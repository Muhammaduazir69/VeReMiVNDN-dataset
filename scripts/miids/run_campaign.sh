#!/usr/bin/env bash
#
# run_campaign.sh - VeReMiVNDN-EXE honest measurement campaign
#
# Runs the labelled feature-capture scenarios across several independent seeds.
# Each (scenario, seed) pair writes its per-observer plane CSVs into its own
# directory, which is what makes the run-disjoint evaluation in
# scripts/miids/train_eval_miids.py possible: a split can be taken over whole
# runs, so no window from a training run can leak into the test set.
#
# Usage: scripts/miids/run_campaign.sh [SIM_SECONDS] [SEEDS...]
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIMLIM="${1:-400s}"
shift || true
SEEDS=("${@:-1 2 3 4 5}")
read -r -a SEEDS <<< "${SEEDS[@]}"

CONFIGS=(CAP_Baseline CAP_A1 CAP_A2 CAP_A3 CAP_A4 CAP_A5 CAP_A6 CAP_A7 CAP_A8 CAP_MultiAttack)

# Output root. The online closed-loop evaluation reuses this script with a
# different root and held-out seeds, so that the runs it scores are not the runs
# the deployed detectors were trained on.
CAPROOT="${CAPROOT:-$ROOT/datasets/exe_capture}"
mkdir -p "$CAPROOT"

echo "[campaign] root=$CAPROOT simlim=$SIMLIM seeds=${SEEDS[*]}"
echo "[campaign] $(( ${#CONFIGS[@]} * ${#SEEDS[@]} )) runs queued"

for seed in "${SEEDS[@]}"; do
  for cfg in "${CONFIGS[@]}"; do
    out="$CAPROOT/${cfg}_seed${seed}"
    if [ -f "$out/.done" ]; then
      echo "[campaign] skip $cfg seed=$seed (already complete)"
      continue
    fi
    rm -rf "$out"; mkdir -p "$out"

    # Each worker owns a private plane-CSV and result directory, keyed by the
    # TraCI port, so that seeds can be run concurrently without clobbering one
    # another's output.
    WORKDIR="planecsv_${TRACI_PORT:-9999}"
    RESDIR="results_${TRACI_PORT:-9999}"
    rm -f "$ROOT/simulations/configs/$WORKDIR/"*.csv

    echo "[campaign] === $cfg seed=$seed ==="
    start=$(date +%s)
    if ! PLANECSV_DIR="$WORKDIR" RESULT_DIR="$RESDIR" \
         "$ROOT/scripts/miids/run_one.sh" "$cfg" "$SIMLIM" vremivndn_exe.ini 0 \
            --seed-set="$seed" > "$out/run.log" 2>&1; then
      echo "[campaign] WARNING: $cfg seed=$seed exited non-zero; keeping partial output"
    fi
    end=$(date +%s)

    # Copy results even when the simulator exited non-zero. OMNeT++ writes the
    # scalar file inside finish(), which completes before the object-teardown
    # pass; a heavy scenario can die during that teardown with every result
    # already on disk. Discarding those runs would throw away good data.
    mv "$ROOT/simulations/configs/$WORKDIR/"*.csv "$out/" 2>/dev/null
    cp "$ROOT/simulations/configs/$RESDIR/${cfg}-0.sca" "$out/" 2>/dev/null

    n=$(cat "$out"/*.csv 2>/dev/null | wc -l)
    # Only mark a run complete when it actually produced results. Marking
    # unconditionally makes the resume logic skip runs that died early, which
    # is how a campaign silently ends up with directories full of nothing.
    # A .sca on disk is not proof of completion. OMNeT++ writes scalars module
    # by module as finish() walks the network, so a process killed inside
    # finish() leaves a short but syntactically valid file: one such run held 40
    # of 274 vehicles and produced plausible-looking but wrong aggregates.
    # Require the module count to match the rest of the campaign.
    mods=$(awk '/^scalar/ && $2 ~ /vehicle\[/ && $3=="totalTime" {c++} END{print c+0}' \
             "$out"/*.sca 2>/dev/null | head -1)
    if [ -d "$out" ] && ls "$out"/*.sca >/dev/null 2>&1 && [ "$n" -gt 1 ] \
       && [ "${mods:-0}" -ge 200 ]; then
      echo "[campaign] $cfg seed=$seed done in $((end-start))s, $n feature rows"
      touch "$out/.done"
    else
      echo "[campaign] $cfg seed=$seed FAILED after $((end-start))s ($n rows, ${mods:-0} vehicle modules); will retry on resume"
    fi
  done
done

echo "[campaign] complete"
