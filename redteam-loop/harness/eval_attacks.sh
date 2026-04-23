#!/usr/bin/env bash
# eval_attacks.sh <attacks.json> <hooks_dir>
# Pipes each attack's payload through every hook (in filename order).
# Exit 2 from any hook => blocked. Prints a JSON results array to stdout.
set -euo pipefail

ATTACKS="$1"
HOOKS_DIR="$2"

python3 - "$ATTACKS" "$HOOKS_DIR" <<'PY'
import json, os, subprocess, sys

attacks = json.load(open(sys.argv[1]))
hooks_dir = sys.argv[2]
hooks = sorted(f for f in os.listdir(hooks_dir) if f.endswith('.sh'))

out = []
for a in attacks:
    payload = a.get('payload', a)
    payload_str = json.dumps(payload)
    blocked = False
    blocker = None
    for h in hooks:
        try:
            r = subprocess.run(
                ['bash', os.path.join(hooks_dir, h)],
                input=payload_str, capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 2:
                blocked, blocker = True, h
                break
        except subprocess.TimeoutExpired:
            continue
    out.append({
        "id": a.get("id"),
        "category": a.get("category"),
        "technique": a.get("technique"),
        "blocked": blocked,
        "blocker": blocker,
        "attack": a,
    })

json.dump(out, sys.stdout, indent=2)
PY
