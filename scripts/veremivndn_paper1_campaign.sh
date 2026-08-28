#!/usr/bin/env bash
#
# veremivndn_paper1_campaign.sh - generate the dataset for the published
# VeReMiVNDN paper (IEEE Access, April 2026, DOI 10.1109/ACCESS.2026.3681896).
#
# The paper states a dataset of 225 simulation runs spanning three traffic
# density levels, three attacker ratios and independent random seeds, over the
# JubST scenario, for four forwarding-plane attacks plus a benign baseline.
# That grid is reproduced here:
#
#     5 configurations x 3 densities x 3 attacker ratios x 5 seeds = 225 runs
#
# The benign configuration carries no attackers, so its attacker-ratio axis
# yields replicates rather than distinct conditions. The axis is kept so the
# design stays balanced and the run count matches the published figure; the
# released documentation says so plainly rather than implying nine distinct
# benign conditions.
#
# Each run covers 300 s, which spans the attack window the paper defines
# (start 60 s, duration 180 s). Output goes to one directory per run.
#
# Usage: scripts/veremivndn_paper1_campaign.sh [WORKER_INDEX] [NUM_WORKERS]
#   With no arguments a single worker runs the whole grid. To parallelise,
#   launch several workers with different indices; each takes every Nth run.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin:$PATH"

WORKER="${1:-0}"
WORKERS="${2:-1}"
PORT=$((9970 + WORKER))
OUTROOT="$ROOT/datasets/paper1_veremivndn"
SIMTIME=300s
mkdir -p "$OUTROOT" logs

CONFIGS=(BenignTraffic Attack01_InterestFlooding Attack05_NamePrefixHijacking
         Attack12_InterestAggregation Attack18_RoutingInfoFlood)
# Density is set by SUMO demand scaling, not by the ini. *.numVehicles only
# sizes a module vector; SUMO's route file decides how many vehicles actually
# enter, so every run inserted the same 274 regardless of what the ini said.
# These are the counts the calibrated scale factors produce over 300 s.
declare -A DENSITY=( [low]=77 [med]=151 [high]=356 )
# attacker ratio label -> percentage of the fleet
declare -A RATIO=( [r05]=5 [r10]=10 [r20]=20 )
SEEDS=(1 2 3 4 5)

idx=0
for cfg in "${CONFIGS[@]}"; do
  for dlab in low med high; do
    for rlab in r05 r10 r20; do
      for seed in "${SEEDS[@]}"; do
        idx=$((idx + 1))
        [ $(((idx - 1) % WORKERS)) -eq "$WORKER" ] || continue

        nveh=${DENSITY[$dlab]}
        pct=${RATIO[$rlab]}
        nmal=$(( nveh * pct / 100 ))
        [ "$cfg" = "BenignTraffic" ] && nmal=0
        last=$(( nmal - 1 ))

        run="${cfg}_${dlab}_${rlab}_seed${seed}"
        out="$OUTROOT/$run"
        if [ -f "$out/.done" ]; then
          echo "[p1] skip $run (complete)"; continue
        fi
        rm -rf "$out"; mkdir -p "$out/ml"

        WORKDIR="planecsv_p1_$PORT"; RESDIR="results_p1_$PORT"
        # Both worker directories are cleared every run. Leaving them to
        # accumulate filled the disk: OMNeT++ writes a .vec beside every .sca,
        # and across a few dozen runs that reached 14 GB of vector output that
        # nothing in this pipeline reads.
        rm -rf "$ROOT/simulations/configs/$WORKDIR" "$ROOT/simulations/configs/$RESDIR"
        mkdir -p "$ROOT/simulations/configs/$WORKDIR" "$ROOT/simulations/configs/$RESDIR"

        # Each (density, seed) pair has its own SUMO config: scale sets the
        # density band, and the SUMO seed makes the mobility trace differ per
        # seed. The stock config pinned seed 42, so seeds varied traffic only.
        LAUNCHD="../scenarios/sumo/jubst_${dlab}_s${seed}.launchd.xml"
        EXTRA=(--seed-set="$seed" --"*.numVehicles=$nveh"
               --"*.manager.launchConfig=xmldoc(\"$LAUNCHD\")"
               # Vector output is not used by any analysis here and is by far
               # the largest thing a run writes. Scalars are kept.
               --"**.vector-recording=false"
               # Each run gets its own directory for the 69-feature ML export,
               # so runs cannot overwrite one another.
               --"*.vehicle[*].dataCollector.outputDirectory=\"$out/ml\"")
        # Attacker assignment.
        #
        # AttackScenario_Base pins the attacker set to vehicle[0..9], and each
        # attack section repeats that same range for attackType, the module
        # type and the attack parameters. A command-line override cannot
        # displace it: OMNeT++ treats --key=value as a [General] entry, and a
        # named Config section is consulted first. The measured effect was that
        # 5 %, 10 % and 20 % produced exactly ten attackers at every density,
        # so the attacker-ratio axis varied nothing at all.
        #
        # A section that *extends* the target configuration does take
        # precedence. The catch-all false entry after the true range is what
        # stops the inherited vehicle[0..9] pattern from re-enabling vehicles
        # beyond the intended count when the ratio asks for fewer than ten.
        RUNINI=""; RUNCFG="$cfg"
        if [ "$nmal" -gt 0 ]; then
          RUNINI="p1_run_${PORT}.ini"
          RUNCFG=P1
          {
            echo "# Generated per run by veremivndn_paper1_campaign.sh."
            echo "[Config P1]"
            echo "extends = $cfg"
            echo "*.numMaliciousVehicles = $nmal"
            echo "*.vehicle[0..$last].hasAttackModule = true"
            echo "*.vehicle[*].hasAttackModule = false"
            # Re-emit every attacker-scoped setting from the base section and
            # from the attack's own section, widened to the intended range, so
            # the extra attackers are configured exactly like the first ten.
            awk -v want="[Config AttackScenario_Base]" \
                '$0==want{f=1;next} /^\[/{f=0} f' \
                "$ROOT/simulations/configs/omnetpp.ini" \
              | grep '^\*\.vehicle\[0\.\.9\]\.' \
              | grep -v 'hasAttackModule'
            awk -v want="[Config $cfg]" \
                '$0==want{f=1;next} /^\[/{f=0} f' \
                "$ROOT/simulations/configs/omnetpp.ini" \
              | grep '^\*\.vehicle\[0\.\.9\]\.' \
              | grep -v 'hasAttackModule'
          } | sed "s/vehicle\[0\.\.9\]/vehicle[0..$last]/" \
            > "$ROOT/simulations/configs/$RUNINI"
        fi

        echo "[p1] === $run  (vehicles=$nveh attackers=$nmal) ==="
        start=$(date +%s)
        PLANECSV_DIR="$WORKDIR" RESULT_DIR="$RESDIR" TRACI_PORT="$PORT" \
          "$ROOT/scripts/miids/run_one.sh" "$RUNCFG" "$SIMTIME" "$RUNINI" 0 \
          "${EXTRA[@]}" > "$out/run.log" 2>&1
        end=$(date +%s)

        mv "$ROOT/simulations/configs/$WORKDIR/"*.csv "$out/" 2>/dev/null
        cp "$ROOT/simulations/configs/$RESDIR/${RUNCFG}-0.sca" "$out/" 2>/dev/null
        [ -n "$RUNINI" ] && cp "$ROOT/simulations/configs/$RUNINI" "$out/run.ini" 2>/dev/null

        # A .sca alone is not proof of completion: OMNeT++ writes scalars as
        # finish() walks the module tree, so a run killed inside finish()
        # leaves a short but valid file. Require the vehicle count to be there.
        mods=$(awk '/^scalar/ && $2 ~ /mobility/ && $3=="totalTime" {c++} END{print c+0}' \
                 "$out"/*.sca 2>/dev/null | head -1)
        if [ "${mods:-0}" -ge $(( nveh / 2 )) ]; then
          echo "[p1] $run done in $((end-start))s, $mods vehicle records"
          # The console log is 3.5 MB of progress banners per run. On a
          # successful run only the tail is worth keeping.
          tail -40 "$out/run.log" > "$out/run.tail.log" 2>/dev/null
          mv -f "$out/run.tail.log" "$out/run.log" 2>/dev/null
          touch "$out/.done"
        else
          echo "[p1] $run INCOMPLETE (${mods:-0} vehicle records); will retry on resume"
        fi
      done
    done
  done
done
echo "[p1] worker $WORKER finished"
