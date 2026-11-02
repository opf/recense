#!/bin/sh
# Run only against a disposable local Docker engine, as in GitHub Actions.
set -eu
fixture=$(mktemp -d)
trap 'docker rm -f recense-smoke-app >/dev/null 2>&1 || true; rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/usr/lib" "$fixture/etc" "$fixture/var/lib/dpkg"
printf 'ID=ubuntu\nNAME=Ubuntu\nVERSION_ID="24.04"\n' > "$fixture/usr/lib/os-release"
printf 'recense-smoke-host\n' > "$fixture/etc/machine-id"
printf 'recense-smoke\n' > "$fixture/etc/hostname"
cat > "$fixture/var/lib/dpkg/status" <<'PACKAGE'
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.13-0ubuntu3
Description: Fixture package

PACKAGE
docker run -d --name recense-smoke-app alpine:3.22 sleep 1800
docker run --rm -v "$fixture:/host:ro" -v /var/run/docker.sock:/runtime.sock \
  recense:test --once --root=/host --runtime=docker --socket=/runtime.sock \
  --scan-timeout=10m > "$fixture/events.jsonl"
python3 - "$fixture/events.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
scans = [r for r in rows if r['event_type'] == 'vulnerability.scan_completed']
assert any(r['target_type'] == 'host' and r['status'] == 'success' for r in scans)
assert any(r['target_type'] == 'container_image' and r['status'] == 'success' for r in scans)
assert any(r['event_type'] == 'container.inventory' and r['container_name'] == 'recense-smoke-app' for r in rows)
assert any(r['event_type'] == 'software.inventory' and r['package_name'] == 'openssl' for r in rows)
assert rows[-1]['event_type'] == 'agent.collection_completed' and rows[-1]['status'] == 'success'
print('Verified real host inventory, Docker discovery, image scans, and completed snapshots')
PY
