#!/bin/bash
#
# DP-IDS-VNDN Experiment Runner
# Runs all attack scenarios, baselines, and sensitivity analyses
#
# Usage: ./scripts/run_dpids_experiments.sh [quick|full]
#

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM_DIR="${PROJECT_DIR}/simulations/configs"
BIN="${PROJECT_DIR}/out/gcc-release/src/VeReMiVNDN"
RESULTS_DIR="${SIM_DIR}/results"

# Check if binary exists
if [ ! -f "$BIN" ]; then
    echo "Binary not found. Building..."
    cd "$PROJECT_DIR"
    make MODE=release -j$(nproc)
    BIN="${PROJECT_DIR}/out/gcc-release/src/VeReMiVNDN"
fi

MODE=${1:-quick}
REPEATS=1
SIM_TIME="300s"

if [ "$MODE" == "full" ]; then
    REPEATS=5
    SIM_TIME="500s"
fi

echo "============================================"
echo "DP-IDS-VNDN Experiment Suite"
echo "Mode: $MODE (repeats=$REPEATS, simTime=$SIM_TIME)"
echo "============================================"

mkdir -p "$RESULTS_DIR"

run_config() {
    local config=$1
    local desc=$2
    echo ""
    echo "--- Running: $config ---"
    echo "    Description: $desc"

    cd "$SIM_DIR"
    for r in $(seq 0 $((REPEATS-1))); do
        echo "    Run $((r+1))/$REPEATS..."
        "$BIN" -u Cmdenv -c "$config" \
            --sim-time-limit="$SIM_TIME" \
            -r "$r" \
            --result-dir="$RESULTS_DIR" \
            2>&1 | tail -1
    done
    echo "    Done: $config"
}

echo ""
echo "=== Phase 1: Benign Baseline ==="
run_config "BasicVNDN" "Benign traffic baseline (no attacks)"

echo ""
echo "=== Phase 2: DP-IDS Attack Detection ==="
run_config "DPIDS_CSPoisoning" "CS Poisoning with DP-IDS"
run_config "DPIDS_PITFlooding" "PIT Flooding with DP-IDS"
run_config "DPIDS_FIBHijacking" "FIB Hijacking with DP-IDS"
run_config "DPIDS_Combined" "All 3 FP attacks with DP-IDS"

echo ""
echo "=== Phase 3: Baseline Comparisons (Section 5.3) ==="
run_config "DPIDS_Baseline_B1_BehaviouralOnly" "B1: Behavioural-only IDS"
run_config "DPIDS_Baseline_B2_ForwardingOnly" "B2: Forwarding-only IDS"
run_config "DPIDS_Baseline_B3_NaiveConcatenation" "B3: Naive concatenation"
run_config "DPIDS_Baseline_B4_ClassicalML" "B4: Classical ML ensemble"

if [ "$MODE" == "full" ]; then
    echo ""
    echo "=== Phase 4: Sensitivity Analysis ==="
    run_config "DPIDS_Sensitivity_Threshold" "Belief threshold sweep"
    run_config "DPIDS_Sensitivity_Reliability" "Detector reliability sweep"
    run_config "DPIDS_Sensitivity_Penalization" "Penalisation threshold sweep"
fi

echo ""
echo "============================================"
echo "All experiments complete!"
echo "Results in: $RESULTS_DIR"
echo ""
echo "Scalar files:"
ls -la "$RESULTS_DIR"/*.sca 2>/dev/null | wc -l
echo "Vector files:"
ls -la "$RESULTS_DIR"/*.vec 2>/dev/null | wc -l
echo "============================================"
