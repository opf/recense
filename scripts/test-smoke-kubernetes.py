#!/usr/bin/env python3
"""Exercise smoke-test log retention and truncated-stream failure without a cluster."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("smoke-kubernetes.sh")
script = script.resolve()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for name in ("kind", "helm"):
        path = root / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    sleep = root / "sleep"
    sleep.write_text("#!/bin/sh\nexec python3 -c 'import time; time.sleep(0.02)'\n")
    sleep.chmod(0o755)
    kubectl = root / "kubectl"
    kubectl.write_text('''#!/usr/bin/env python3
import json, os, sys, time
if sys.argv[1] != 'logs':
    sys.exit(0)
rows = [
 {'recense.event.type':'container.inventory','recense.target.container.runtime':'containerd'},
 {'recense.event.type':'host.updates','recense.status':'unsupported'},
 {'recense.event.type':'vulnerability.scan_completed','recense.target.type':'host','recense.status':'success'},
 {'recense.event.type':'vulnerability.scan_completed','recense.target.type':'container','recense.status':'success'},
 {'recense.event.type':'agent.collection_completed','recense.status':'success'},
]
# One-shot requests model kubelet exposing only the current file after rotation.
if '-f' not in sys.argv:
    rows = rows[2:]
if os.environ.get('SMOKE_STREAM') == 'truncated':
    rows = rows[:-1]
for row in rows:
    line = json.dumps(row) + '\\n'
    # A follower can write the final record in several chunks.
    if row['recense.event.type'] == 'agent.collection_completed':
        middle = len(line) // 2
        sys.stdout.write(line[:middle]); sys.stdout.flush()
        time.sleep(0.08)
        sys.stdout.write(line[middle:]); sys.stdout.flush()
    else:
        print(line, end='', flush=True)
''')
    kubectl.chmod(0o755)
    env = os.environ | {"PATH": f"{root}:{os.environ['PATH']}"}
    complete = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert complete.returncode == 0, complete.stdout + complete.stderr
    truncated = subprocess.run(["sh", str(script)], env=env | {"SMOKE_STREAM": "truncated"}, capture_output=True, text=True, timeout=30)
    assert truncated.returncode != 0, "truncated stream was accepted"
    assert "collection did not finish" in truncated.stderr, truncated.stderr
print("Verified discovery retention, split completion records, and truncated-stream rejection")
