#!/usr/bin/env bash
#
# finalize_results.sh - everything between a finished capture campaign and the
# tables/figures the manuscript needs.
#
#   1. re-run captures that produced nothing usable
#   2. evaluate under all three split protocols
#   3. regenerate the paper's tables and figures from the headline protocol
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "=== 1/3 repairing failed captures ==="
scripts/miids/repair_campaign.sh 300s 1000

echo
echo "=== 2/3 evaluating ==="
for proto in run-disjoint attacker-disjoint unseen-attack; do
  echo "--- $proto ---"
  python3 scripts/miids/train_eval_miids.py \
      --protocol "$proto" \
      --epochs 10 \
      --out "datasets/exe_capture/miids_results_${proto}.json" \
      || echo "[warn] $proto failed"
done

# The headline protocol drives the paper's tables.
cp datasets/exe_capture/miids_results_run-disjoint.json \
   datasets/exe_capture/miids_results.json 2>/dev/null

echo
echo "=== 3/3 regenerating tables and figures ==="
python3 scripts/miids/make_paper_results.py

echo
echo "=== done ==="
