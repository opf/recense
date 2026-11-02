#!/bin/sh
# All scanned files and runtime operations stay inside a disposable Docker engine.
set -eu
engine="recense-smoke-$$"
events=$(mktemp)
trap 'docker rm -f "$engine" >/dev/null 2>&1 || true; rm -f "$events"' EXIT HUP INT TERM
docker run --privileged -d --name "$engine" -e DOCKER_TLS_CERTDIR= docker:29-dind >/dev/null
i=0
until docker exec "$engine" docker info >/dev/null 2>&1; do
  i=$((i+1)); test "$i" -lt 60; sleep 1
done
docker exec "$engine" mount --make-rshared /
docker save recense:test | docker exec -i "$engine" docker load >/dev/null
docker exec "$engine" docker run -d --name recense-smoke-app alpine:3.22 sleep 1800 >/dev/null
# A package marker added after container creation proves writable-layer coverage.
docker exec "$engine" docker exec recense-smoke-app sh -c 'mkdir -p /opt/fixture/node_modules/recense-writable-marker; printf "{\"name\":\"recense-writable-marker\",\"version\":\"1.2.3\"}\n" > /opt/fixture/node_modules/recense-writable-marker/package.json'
docker exec "$engine" docker run --rm --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=SYS_PTRACE \
  --mount type=bind,source=/,target=/host,readonly,bind-propagation=rslave \
  -v /var/run/docker.sock:/runtime.sock:ro \
  recense:test --once --root=/host --runtime=docker --socket=/runtime.sock \
  --host-id=recense-smoke-host --scan-timeout=10m > "$events"
python3 - "$events" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
scans = [r for r in rows if r['recense.event.type'] == 'vulnerability.scan_completed']
assert any(r['recense.target.type'] == 'host' and r['recense.status'] == 'success' for r in scans)
app = next(r for r in rows if r['recense.event.type'] == 'container.inventory' and r['recense.target.container.name'] == 'recense-smoke-app')
assert any(r['recense.target.type'] == 'container' and r['recense.target.id'] == app['recense.target.container.id'] and r['recense.status'] == 'success' for r in scans)
assert any(r['recense.event.type'] == 'software.inventory' and r['recense.target.id'] == app['recense.target.container.id'] and r['recense.package.name'] == 'recense-writable-marker' for r in rows)
assert rows[-1]['recense.event.type'] == 'agent.collection_completed' and rows[-1]['recense.status'] == 'success'
print('Verified host inventory, Docker discovery, writable-layer inventory, and completed snapshots')
PY
