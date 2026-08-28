#!/usr/bin/env bash
# run_one.sh - launch a single VeReMiVNDN-EXE simulation end-to-end
#
# Boots SUMO with TraCI on port 9999, then runs the OMNeT++ simulator
# against a chosen Config from omnetpp.ini / vremivndn_exe.ini and waits
# for completion. Any leftover sumo on the port is killed first.
#
# Usage:
#   scripts/miids/run_one.sh <Config> [<sim-time-limit>] [<extra-ini>]
#
# Examples:
#   scripts/miids/run_one.sh BenignTraffic 60s
#   scripts/miids/run_one.sh EXE_MIIDS_MultiAttack 120s vremivndn_exe.ini
#
set -euo pipefail

# LibTorch defaults to one thread per core, which is counter-productive for the
# single-sample forwards MI-IDS issues at every 100 ms tick: the threads spend
# more time synchronising than computing. Pinning to one thread cut the wall
# time of a 30 s run from over ten minutes to 42 s.
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1

CONFIG="${1:-BenignTraffic}"
SIMLIM="${2:-60s}"
EXTRA_INI="${3:-}"
RUN_FILTER="${4:-}"   # optional: pass "0" or "0..2" to limit run count
shift 4 2>/dev/null || shift $# 
EXTRA_ARGS=("$@")   # any further args are forwarded verbatim to the simulator

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/simulations/configs"

OMNETPP_BIN=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin
INET=$ROOT/../inet4.5
VEINS=$ROOT/../veins
VEINS_INET=$ROOT/../veins_inet
SIMU5G=$ROOT/../simu5g

export PATH=$OMNETPP_BIN:$PATH
export LD_LIBRARY_PATH=$OMNETPP_BIN/../lib:$INET/src:$VEINS/src:$VEINS_INET/src:$SIMU5G/src:${LD_LIBRARY_PATH:-}

# TraCI port. Parameterised so that several runs can execute concurrently:
# each worker gets its own port, its own launchd, and its own output paths, and
# no worker may kill another's SUMO. With a single hard-coded port the campaign
# is strictly sequential.
PORT="${TRACI_PORT:-9999}"

# Kill any stale launchd / sumo on this worker's port only.
fuser -k "$PORT"/tcp 2>/dev/null || true
sleep 1

# Boot the Veins-bundled launchd that proxies TraCI between SUMO and OMNeT++.
# This is the path Veins 5.x officially supports and bridges any TraCI API
# version that SUMO ships with on this machine (1.18 reports v20).
LAUNCHD=$ROOT/../veins/bin/veins_launchd
echo "[run_one] starting veins_launchd on port $PORT"
"$LAUNCHD" -d -vv -L /tmp/veins_launchd_$$.log -p "$PORT" &
LAUNCHD_PID=$!
trap "kill $LAUNCHD_PID 2>/dev/null || true; fuser -k $PORT/tcp 2>/dev/null || true" EXIT

for i in $(seq 1 10); do
    if ss -ln "( sport = :$PORT )" 2>/dev/null | grep -q "$PORT"; then break; fi
    sleep 0.5
done

NED_PATH="$ROOT/src:$ROOT/simulations:$INET/src:$VEINS/src/veins:$VEINS_INET/src/veins_inet:$SIMU5G/src"

INI_FILES=(omnetpp.ini)
[ -n "$EXTRA_INI" ] && INI_FILES+=("$EXTRA_INI")

echo "[run_one] launching $CONFIG (sim-time-limit=$SIMLIM, runs=${RUN_FILTER:-all})"
RUN_ARGS=()
[ -n "$RUN_FILTER" ] && RUN_ARGS=(-r "$RUN_FILTER")

# Per-worker output paths, so concurrent runs never write the same file.
RESULT_DIR="${RESULT_DIR:-results}"
PLANECSV_DIR="${PLANECSV_DIR:-planecsv}"
mkdir -p "$RESULT_DIR" "$PLANECSV_DIR"
"$ROOT/VeReMiVNDN" \
    -u Cmdenv \
    -c "$CONFIG" \
    "${RUN_ARGS[@]}" \
    "${EXTRA_ARGS[@]}" \
    --sim-time-limit="$SIMLIM" \
    --result-dir="$RESULT_DIR" \
    --*.manager.port="$PORT" \
    --*.rsu[*].featureExtractor.planeFeatureCsv="\"$PLANECSV_DIR/plane.csv\"" \
    --*.vehicle[*].featureExtractor.planeFeatureCsv="(parentIndex() % 5 == 2) ? \"$PLANECSV_DIR/plane.csv\" : \"\"" \
    -n "$NED_PATH" \
    "${INI_FILES[@]}"

echo "[run_one] done"
