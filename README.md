# Recense

Know which machines and containers you have, what software they contain, and which known vulnerabilities affect them.

Recense is a small Go agent that writes structured JSON logs to your existing OpenTelemetry/SigNoz pipeline. It uses Syft for complete software inventory and Grype for vulnerability matching. No database, dashboard, or central Recense server is required.

## Install on a VM

Linux amd64 and arm64, with systemd. Release archives include Recense, Syft, and Grype.

```sh
curl -fsSLO https://github.com/opf/recense/releases/latest/download/install.sh
# Inspect install.sh before running it.
sudo sh install.sh
```

The installer verifies the release archive checksum, installs binaries under `/opt/recense/bin`, and starts `recense.service`. Rerun with a release tag to upgrade or downgrade: `sudo sh install.sh v0.1.0`.

```sh
sudo systemctl status recense
sudo tail -f /var/log/recense/events.jsonl
```

Set `RECENSE_ENVIRONMENT`, `RECENSE_CLUSTER`, and optional `RECENSE_HOST_ID` / `RECENSE_HOST_NAME` in `/etc/recense/environment`, then restart the service. Host IDs default to `/etc/machine-id`; cloned images must receive unique machine IDs. Set labels before collecting production data.

Recense sends a heartbeat every minute and scans immediately, then six hours after each completed cycle. Host and image scans run sequentially. Each Syft/Grype invocation has a 15-minute timeout and a 128 MiB output limit. Scanner failure does not produce a clean result.

For a single run or custom scheduling:

```sh
sudo /opt/recense/bin/recense --once \
  --syft /opt/recense/bin/syft --grype /opt/recense/bin/grype
```

`--once` exits nonzero if a scan, discovery, or supported update check fails. Vulnerabilities themselves do not make collection fail. `--runtime=none` disables container discovery; `--runtime=docker|containerd --socket=/path/to/socket` selects an explicit runtime. Auto mode chooses Docker first, then containerd, at their standard socket locations. It monitors one runtime per process.

## Install on Kubernetes

For EC2-backed EKS or other Linux Kubernetes nodes with containerd and CRI v1:

```sh
helm upgrade --install recense \
  https://github.com/opf/recense/releases/download/v0.1.0/recense-0.1.0.tgz \
  --namespace recense --create-namespace \
  --set clusterName=production-eks \
  --set environment=production
```

The DaemonSet mounts the node filesystem read-only and uses `/run/containerd/containerd.sock`. It writes JSON to stdout for your existing Kubernetes log collector. No Kubernetes API permissions or service account token are required. Set `socketPath` for a nonstandard socket. Docker nodes can use `--set runtime=docker --set socketPath=/var/run/docker.sock`.

The chart starts with a 100m CPU / 256 MiB memory request and a 1 CPU / 2 GiB limit. Allow additional memory for large images and package inventories. Cache and temporary volumes each permit up to 4 GiB of disk usage per node. Set resource reservations based on measured use.

The pod runs as root with `DAC_READ_SEARCH`, without privileged mode, and with a read-only container root filesystem. **Runtime socket access is privileged host access even when the socket mount is read-only.** This workload will not pass restricted Pod Security admission. Host filesystem contents must be trusted; do not expose runtime sockets to application pods. There is no Fargate host-agent support.

The chart assumes unique host machine IDs. On Bottlerocket or other immutable node OSs, validate scanner package coverage before relying on results; supported agent deployment does not imply complete vulnerability coverage.

## Send logs to SigNoz

VMs: merge [deploy/otel/filelog.yaml](deploy/otel/filelog.yaml) into the existing Collector configuration and add `filelog/recense` to its logs pipeline. Ensure the collector can read the log directory and files (the installer defaults to root ownership). The example parses JSON, timestamps, and host/service resource attributes. Configure persistent file offsets in your Collector if you need restart-safe delivery.

Kubernetes: use the existing container log receiver to parse the CRI envelope, then parse the Recense JSON body. Promote `service.name`, `host_id`, and `host_name` to resource attributes as in the VM example. Do not add another receiver for the same pod logs. Parsing JSON is required: writing JSON alone does not make its fields searchable.

Recense never needs a SigNoz token. Your collector retains transport, authentication, retries, and batching.

## Event model

Every record has an RFC3339 UTC `timestamp`, `schema_version=1`, `service.name=recense`, `host_id`, `host_name`, `agent_version`, `environment`, and `k8s_cluster_name`.

| Event | Purpose |
|---|---|
| `agent.heartbeat` | Agent liveness, including while a scan is running |
| `host.inventory` | Distribution, running kernel, architecture, Ubuntu reboot marker |
| `host.updates` | Security updates available to native package tooling, or explicit unsupported/failed status |
| `container.inventory` | Running container → immutable image ID, with Kubernetes pod labels where available |
| `container.discovery_completed` | Complete container snapshot, including an empty snapshot |
| `software.inventory` | One record per discovered package, including packages without vulnerabilities |
| `software.inventory_completed` | Successful software snapshot and package count |
| `vulnerability.finding` | One package/advisory match, severity, known fixes, and source namespace |
| `vulnerability.scan_completed` | Successful scan and counts, or failure without counts |
| `agent.collection_completed` | Result of the whole collection cycle |

Scan events share a random `scan_id`, `target_type` (`host` or `container_image`), and `target_id`. Container discovery events share a `collection_id`. Software and vulnerability records are snapshots, not change events.

For current findings, select the latest **successful** vulnerability scan for each `(host_id, target_type, target_id)`, then select its findings by `scan_id`. Show the age of that scan separately. A newer failure must not erase previous findings or appear healthy. Inventory uses its own successful completion marker. Container presence uses the latest successful discovery snapshot; absent containers/images are no longer active on that host. Historical findings remain in logs until retention expires.

Do not count every finding in a time window as a current vulnerability: repeated scans repeat findings. Empty successful scans explicitly report zero. A terminated process may leave records without a completion marker; these are incomplete snapshots.

## Coverage and limits

- Host scans read the host filesystem; image scans analyze images used by running containers. Duplicate images are scanned once per host cycle. Every cycle rescans against Grype's updated vulnerability database, including unchanged images.
- Host scans exclude `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`, and `/var/lib/recense`. Container storage is handled through image scans. Software under excluded paths is not covered.
- Image scans do not cover container writable-layer changes or mounted application data. Inventoried binaries are installed versions, not proof that a process is running them.
- CRI discovery uses repository digests where available and local tags for images without them. Every image scan verifies Syft’s config digest against the discovered immutable image ID before emitting results, so a moved tag cannot silently scan the wrong image. The containerd namespace defaults to `k8s.io`.
- Ubuntu update checks use `python3-apt` and existing APT metadata. Recense does not refresh APT; keep the host's normal refresh timers enabled. Metadata refresh time is included when the Ubuntu success stamp exists. Missing `python3-apt` is reported as a failed check.
- Amazon Linux 2023 update checks use DNF security advisories with `--refresh --releasever=latest`. They refresh metadata but do not install packages. Counts are distinct offered package-version entries, not CVE counts. Amazon Linux 2 update checks are unsupported.
- In a DaemonSet (`--root=/host`), package-manager update checks are explicitly unsupported. Running APT/DNF in the agent container would inspect the wrong OS. Grype still scans the node packages for vulnerabilities.
- The Ubuntu reboot flag reflects `/var/run/reboot-required`. Other distributions omit it; absence does not mean no reboot is needed. Kernel inventory is the running host kernel, independently of installed kernel packages.
- CVE matching depends on scanner ecosystem support and database freshness. An available fix in Grype is not necessarily installable from the host's repositories. A successful scan does not prove software is vulnerability-free.
- Scanner stderr is intentionally not forwarded to logs because it may contain registry credentials. Errors identify the stage, target, and exit status. For deeper diagnosis, run the bundled scanner manually in a controlled environment.
- No automatic patching, remote command execution, or vulnerability suppression policy is implemented.

## Development

```sh
go test -race ./...
go vet ./...
go build ./cmd/recense
helm lint charts/recense
```

Go dependencies are pinned in `go.mod` / `go.sum`. Scanner versions are pinned in `scripts/package.sh` and `Dockerfile`. The release workflow builds Linux amd64/arm64 archives, a multi-architecture image at `ghcr.io/opf/recense`, and a packaged Helm chart. Keep chart `version`, `appVersion`, and image tag aligned with each release tag.

Before a release, run CI and verify both VM fixture collection and container runtime discovery. Unit tests use fake scanners and local Docker/CRI API servers; they do not inspect the developer's host or containers.

Apache-2.0. Bundled scanners and their licenses are listed in [THIRD_PARTY.md](THIRD_PARTY.md).
