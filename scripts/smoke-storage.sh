#!/bin/sh
# Real Syft inventory through Recense, with a stub matcher to keep this offline.
set -eu
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/host/etc" "$fixture/host/var/lib/containerd" "$fixture/tools"
printf 'ID=ubuntu\nVERSION_ID=24.04\n' > "$fixture/host/etc/os-release"
printf 'storage-fixture\n' > "$fixture/host/etc/machine-id"
printf 'storage-fixture\n' > "$fixture/host/etc/hostname"
for pair in 'mnt/k8s-disks/0/containerd:recense-storage-containerd' 'mnt/k8s-disks/0/kubelet:recense-storage-kubelet' 'mnt/ordinary:recense-control-mnt'; do
  directory=${pair%:*}
  name=${pair#*:}
  mkdir -p "$fixture/host/$directory/node_modules/$name"
  printf '{"name":"%s","version":"1.0.0"}\n' "$name" > "$fixture/host/$directory/node_modules/$name/package.json"
done
printf '#!/bin/sh\nprintf '\''{"matches":[]}\\n'\''\n' > "$fixture/tools/grype"
chmod 755 "$fixture/tools/grype"
docker run --rm --network=none --memory=512m --cpus=0.25 \
  -v "$fixture/host:/host:ro" \
  -v "$fixture/host/mnt/k8s-disks/0/containerd:/host/var/lib/containerd:ro" \
  -v "$fixture/tools:/test-tools:ro" \
  recense:test --once --root=/host --runtime=none --grype=/test-tools/grype \
  > "$fixture/events.jsonl"
python3 - "$fixture/events.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
names = {r['package_name'] for r in rows if r['event_type'] == 'software.inventory'}
assert 'recense-control-mnt' in names, names
assert not {'recense-storage-containerd', 'recense-storage-kubelet'} & names, names
assert rows[-1]['event_type'] == 'agent.collection_completed' and rows[-1]['status'] == 'success'
print('Verified EKS backing storage is excluded while ordinary /mnt software remains covered')
PY
