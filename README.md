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

The installer verifies the release archive checksum, installs binaries under `/opt/recense/bin`, and starts `recense.service`. Rerun with a release tag to upgrade or downgrade: `sudo sh install.sh v0.2.0`.

```sh
sudo systemctl status recense
sudo tail -f /var/log/recense/events.jsonl
```

Set `RECENSE_ENVIRONMENT`, `RECENSE_CLUSTER`, and optional `RECENSE_HOST_ID` / `RECENSE_HOST_NAME` in `/etc/recense/environment`, then restart the service. Host IDs default to `/etc/machine-id`; cloned images must receive unique machine IDs. Set labels before collecting production data.

Recense sends a heartbeat every minute. Scans start after a random delay of up to 15 minutes, then repeat 24 hours after completion with another random delay. Set `--interval` and `--jitter` to adjust scheduling; `--once` skips the delay. Host and container scans run sequentially with one scanner worker. Each Syft/Grype invocation has a 45-minute timeout and a 128 MiB output limit. Scanner failure does not produce a clean result.

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
  https://github.com/opf/recense/releases/download/v0.2.0/recense-0.2.0.tgz \
  --namespace recense --create-namespace \
  --set clusterName=production-eks \
  --set environment=production
```

The DaemonSet requests a read-only mount of the node filesystem and uses `/run/containerd/containerd.sock`. It writes JSON to stdout for your existing Kubernetes log collector. No Kubernetes API permissions or service account token are required. Set `socketPath` for a nonstandard socket. Docker nodes can use `--set runtime=docker --set socketPath=/var/run/docker.sock`.

The chart starts with a 100m CPU / 256 MiB memory request and a 250m CPU / 2 GiB limit. Allow additional memory for large images and package inventories. Cache permits up to 8 GiB and temporary files up to 2 GiB per node. The pod requests 4 GiB of ephemeral storage and caps total usage at 11 GiB. Database updates temporarily keep both the old and new databases. Set resource reservations based on measured use.

The pod uses priority -1000 and never preempts other pods. Capacity shortages can leave nodes uncovered.

The pod runs as root with `DAC_READ_SEARCH` and `SYS_PTRACE`, without privileged mode, and with a read-only container root filesystem. Host mount propagation makes new container mounts visible; nested mounts are not guaranteed read-only by the kernel. Scanners must therefore remain trusted and behave read-only. **Runtime socket access is privileged host access even when the socket mount is read-only.** This workload will not pass restricted Pod Security admission. Host filesystem contents must be trusted; do not expose runtime sockets to application pods. There is no Fargate host-agent support.

The chart assumes unique host machine IDs. On Bottlerocket or other immutable node OSs, validate scanner package coverage before relying on results; supported agent deployment does not imply complete vulnerability coverage.

## Resource use and local state

Both deployments cap CPU at 250m and memory at 2 GiB by default. The systemd service also uses nice level 10 and idle I/O priority. Scanner subprocesses use one Go execution thread and a 512 MiB Go heap target. This target is not a process memory limit: mapped databases, page cache, and output buffers also consume memory.

Scans perform disk reads and can compete with workloads. Daily scans and startup jitter reduce fleet-wide bursts; tune limits using a complete scan on representative hosts. A 256 MiB Kubernetes request is a scheduling reservation, not expected peak memory. Heartbeats do not imply successful or fresh scans.

The vulnerability database is cached locally; an observed database used about 3.2 GiB. Kubernetes cache and temporary files are disposable `emptyDir` volumes. A restart can require another download and scan. Recense does not cache live filesystem inventories by image ID, because that would miss writable-layer changes. Logs remain the collector's responsibility; Recense has no durable delivery queue.

## Send logs to SigNoz

VMs: merge [deploy/otel/filelog.yaml](deploy/otel/filelog.yaml) into the existing Collector configuration and add `filelog/recense` to its logs pipeline. Ensure the collector can read the log directory and files (the installer defaults to root ownership). The example parses JSON, timestamps, and host/service resource attributes. Configure persistent file offsets in your Collector if you need restart-safe delivery.

Kubernetes: use the existing container log receiver to parse the CRI envelope, then parse the Recense JSON body. Promote `service.name`, `host_id`, and `host_name` to resource attributes as in the VM example. Do not add another receiver for the same pod logs. Parsing JSON is required: writing JSON alone does not make its fields searchable.

Recense never needs a SigNoz token. Your collector retains transport, authentication, retries, and batching.

## Event model

Every record has an RFC3339 UTC `timestamp`, `schema_version=2`, `service.name=recense`, `host_id`, `host_name`, `agent_version`, `environment`, and `k8s_cluster_name`.

| Event | Purpose |
|---|---|
| `agent.heartbeat` | Agent liveness, including while a scan is running |
| `agent.error` | Collection error details; emitted as JSON even in daemon mode |
| `host.inventory` | Distribution, running kernel, architecture, Ubuntu reboot marker |
| `host.updates` | Security updates available to native package tooling, or explicit unsupported/failed status |
| `container.inventory` | Running container → immutable image ID, with Kubernetes pod labels where available |
| `container.discovery_completed` | Complete container snapshot, including an empty snapshot |
| `software.inventory` | One record per discovered package, including packages without vulnerabilities |
| `software.inventory_completed` | Successful software snapshot and package count |
| `vulnerability.finding` | One package/advisory match, severity, known fixes, and source namespace |
| `vulnerability.scan_completed` | Successful scan and counts, or failure without counts |
| `agent.collection_completed` | Result of the whole collection cycle |

Scan events share a random `scan_id`, `target_type` (`host` or `container`), and `target_id`. Container discovery events share a `collection_id`. Software and vulnerability records are snapshots, not change events.

For current findings, select the latest **successful** vulnerability scan for each `(host_id, target_type, target_id)`, then select its findings by `scan_id`. Show the age of that scan separately. A newer failure must not erase previous findings or appear healthy. Inventory uses its own successful completion marker. Container presence uses the latest successful discovery snapshot; absent containers are no longer active on that host. Historical findings remain in logs until retention expires.

Do not count every finding in a time window as a current vulnerability: repeated scans repeat findings. Empty successful scans explicitly report zero. A terminated process may leave records without a completion marker; these are incomplete snapshots.

## Coverage and limits

- Host scans read the host filesystem. Container scans read each running container's filesystem, including its writable layer. No image download or export is required. Containers sharing an image still need separate scans because their writable layers can differ.
- Scans exclude `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/log`, `/var/cache`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`, and `/var/lib/recense`. Container scans also exclude mounted volumes. Software under excluded paths is not covered.
- Container roots must be visible in the host mount namespace. Recense verifies the root inode and process start time before and after inventory collection. Missing or changed roots fail the scan; they never fall back to another filesystem. A live filesystem is not an atomic snapshot.
- Container scan identity is the container ID. Image IDs are descriptive metadata. Inventoried binaries are installed versions, not proof that a process is running them.
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
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go build ./cmd/recense
helm lint charts/recense
```

Go dependencies are pinned in `go.mod` / `go.sum`. Scanner versions are pinned in `scripts/package.sh` and `Dockerfile`. The release workflow builds Linux amd64/arm64 archives, a multi-architecture image at `ghcr.io/opf/recense`, and a packaged Helm chart. Keep chart `version`, `appVersion`, and image tag aligned with each release tag.

Before a release, run CI and verify both VM fixture collection and container runtime discovery. Unit tests use fake scanners and local Docker/CRI API servers; they do not inspect the developer's host or containers. CI also runs real Syft/Grype scans against a disposable Docker host and writable container filesystems, and the Helm DaemonSet in a disposable kind cluster.

Apache-2.0. Bundled scanners and their licenses are listed in [THIRD_PARTY.md](THIRD_PARTY.md).
