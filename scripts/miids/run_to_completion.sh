#!/usr/bin/env bash
#
# run_to_completion.sh - wait for the capture campaign, then produce results.
#
# Chains the whole back half of the pipeline so it proceeds unattended:
#   wait for campaign -> repair failed captures -> evaluate three protocols
#   -> regenerate tables and figures.
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${1:?usage: run_to_completion.sh <campaign.log>}"

echo "[chain] waiting for capture campaign to finish"
while ! grep -q "campaign] complete" "$LOG" 2>/dev/null; do
  sleep 60
done
echo "[chain] campaign finished with $(grep -c 'done in' "$LOG") runs"

cd "$ROOT"
scripts/miids/finalize_results.sh
echo "[chain] pipeline complete"
