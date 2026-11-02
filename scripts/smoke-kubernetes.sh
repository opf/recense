#!/bin/sh
# The CI job provides a disposable kind cluster named recense.
set -eu
kind load docker-image recense:test --name recense
helm upgrade --install recense charts/recense --namespace recense --create-namespace \
  --set image.repository=recense --set image.tag=test --set image.pullPolicy=Never \
  --set clusterName=recense-test --set environment=test \
  --set resources.limits.memory=3Gi --set resources.limits.cpu=2
kubectl rollout status daemonset/recense -n recense --timeout=120s
log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
# Bound the collection to 15 minutes. No production cluster is used.
i=0
while [ "$i" -lt 90 ]; do
  kubectl logs -n recense daemonset/recense > "$log"
  if python3 - "$log" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
raise SystemExit(0 if any(r['event_type'] == 'agent.collection_completed' for r in rows) else 1)
PY
  then break; fi
  sleep 10
  i=$((i + 1))
done
python3 - "$log" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
failures = [r for r in rows if r.get('status') == 'failed']
assert not failures, failures
assert any(r['event_type'] == 'agent.collection_completed' and r['status'] == 'success' for r in rows), 'collection did not finish'
assert any(r['event_type'] == 'container.inventory' and r['container_runtime'] == 'containerd' for r in rows)
assert any(r['event_type'] == 'vulnerability.scan_completed' and r['target_type'] == 'container_image' for r in rows)
assert any(r['event_type'] == 'host.updates' and r['status'] == 'unsupported' for r in rows)
print('Verified real containerd discovery and DaemonSet host/image scanning')
PY
