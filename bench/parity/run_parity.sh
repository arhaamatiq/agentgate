#!/usr/bin/env bash
# Rebuild the parity corpus from the Python reference engine, replay it
# through the Go engine, and record the outcome in bench/results/parity.json.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=${PYTHON:-.venv/bin/python}
"$PY" bench/parity/build_corpus.py
log=$(cd gateway && go test ./internal/rules/ -run Parity -count=1 -v 2>&1) || { echo "$log" | tail -40; exit 1; }
"$PY" - "$log" <<'PY'
import json, re, sys
log = sys.argv[1]
m = re.search(r"exact: (\d+) \| go stricter: (\d+) \| same verdict, different reasoning: (\d+) \| go looser or dataset mismatch: (\d+)", log)
total = re.search(r"parity cases: (\d+) (map\[.*?\])", log)
out = {"cases": int(total.group(1)), "by_kind": total.group(2), "exact": int(m.group(1)), "go_stricter": int(m.group(2)),
       "same_verdict_different_reasoning": int(m.group(3)), "go_looser_or_dataset_mismatch": int(m.group(4))}
open("bench/results/parity.json", "w").write(json.dumps(out, indent=2) + "\n")
print(json.dumps(out))
PY
