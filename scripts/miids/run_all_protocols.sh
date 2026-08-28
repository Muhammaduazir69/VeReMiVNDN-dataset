#!/usr/bin/env bash
#
# run_all_protocols.sh - evaluate the three split protocols one after another.
#
# Running them concurrently starves the machine: each holds the full column
# store and torch spawns its own thread pool, so the three together exceed
# both memory and cores. Sequential is slower in principle but finishes
# sooner in practice, and python -u keeps the log readable while it runs.
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LOGDIR="${1:?usage: run_all_protocols.sh <logdir>}"
EPOCHS="${2:-5}"
ROWS="${3:-120000}"

for proto in run-disjoint attacker-disjoint unseen-attack; do
  out="datasets/exe_capture/miids_results_${proto}.json"
  if [ -f "$out" ]; then
    echo "[eval] $proto already done, skipping"
    continue
  fi
  echo "[eval] === $proto ==="
  OMP_NUM_THREADS=8 MKL_NUM_THREADS=8 \
  python3 -u scripts/miids/train_eval_miids.py \
      --protocol "$proto" --epochs "$EPOCHS" --max-train-rows "$ROWS" \
      --robust-sample 12000 --out "$out" 2>&1 | tee "$LOGDIR/eval_${proto}.log"
  echo "[eval] $proto finished with status ${PIPESTATUS[0]}"
done

cp datasets/exe_capture/miids_results_run-disjoint.json \
   datasets/exe_capture/miids_results.json 2>/dev/null
echo "[eval] regenerating tables and figures"
python3 -u scripts/miids/make_paper_results.py
echo "[eval] all done"
