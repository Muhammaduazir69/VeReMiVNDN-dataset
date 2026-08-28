#!/usr/bin/env bash
#
# repair_campaign.sh - re-run capture runs that produced no usable output.
#
# A run can fail for reasons unrelated to the scenario (most commonly a TraCI
# connect race when a previous run has not fully released port 9999). The
# campaign script marks such a run complete so it does not block the queue;
# this script finds them by row count and re-runs them.
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIMLIM="${1:-300s}"
MIN_ROWS="${2:-1000}"
CAPROOT="$ROOT/datasets/exe_capture"

for d in "$CAPROOT"/*_seed*; do
  [ -d "$d" ] || continue
  n=$(cat "$d"/plane_*.csv 2>/dev/null | wc -l)
  [ "$n" -ge "$MIN_ROWS" ] && continue
  base=$(basename "$d"); cfg="${base%_seed*}"; seed="${base##*_seed}"
  echo "[repair] $cfg seed=$seed had $n rows; re-running"
  rm -rf "$d"; mkdir -p "$d"
  rm -f "$ROOT/simulations/configs/planecsv/"*.csv
  sleep 3        # let any previous TraCI socket close before reconnecting
  "$ROOT/scripts/miids/run_one.sh" "$cfg" "$SIMLIM" vremivndn_exe.ini 0 \
      --seed-set="$seed" > "$d/run.log" 2>&1 || true
  mv "$ROOT/simulations/configs/planecsv/"*.csv "$d/" 2>/dev/null
  cp "$ROOT/simulations/configs/results/${cfg}-0.sca" "$d/" 2>/dev/null
  touch "$d/.done"
  echo "[repair] $cfg seed=$seed now $(cat "$d"/plane_*.csv 2>/dev/null | wc -l) rows"
done
echo "[repair] done"
