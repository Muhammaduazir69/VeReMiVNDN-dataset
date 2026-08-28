#!/usr/bin/env bash
# run_traci_gui.sh - one-shot launcher for VeReMiVNDN-EXE Qtenv runs.
#
#   * Kills any stale veins_launchd / SUMO on port 9999.
#   * Boots veins_launchd (TraCI proxy) on port 9999.
#   * Launches the OMNeT++ Qtenv GUI for the requested scenario.
#   * SUMO-GUI is started automatically by the launchd as soon as the
#     scenario connects (the launchd reads the <commands><sumo-gui>...
#     line from the .launchd.xml).
#
# Usage:
#   scripts/run_traci_gui.sh <Config> [<sim-time-limit>]
#
# The four master scenarios:
#   scripts/run_traci_gui.sh EXE_S1_Baseline           300s
#   scripts/run_traci_gui.sh EXE_S2_MultiAttackUrban   600s
#   scripts/run_traci_gui.sh EXE_S3_MultiAttackHighway 600s
#   scripts/run_traci_gui.sh EXE_S4_AdversarialRobust  300s
#
# Per-attack scenarios (still available):
#   scripts/run_traci_gui.sh EXE_MIIDS_A1 60s        # Content Poisoning
#   scripts/run_traci_gui.sh EXE_MIIDS_A4 60s        # Sybil Amplification
#   ... etc.
#
# Note: veins_launchd is the TraCI server. SUMO-GUI is launched via launchd
# as the actual TraCI peer, so do NOT try to start sumo-gui manually before
# this script - the script will do it for you.
#
set -euo pipefail

CONFIG="${1:-EXE_S2_MultiAttackUrban}"
SIMLIM="${2:-600s}"
EXTRA_INI="${3:-vremivndn_exe.ini}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/simulations/configs"

OMNETPP_BIN=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin
INET=$ROOT/../inet4.5
VEINS=$ROOT/../veins
VEINS_INET=$ROOT/../veins_inet
SIMU5G=$ROOT/../simu5g

export PATH=$OMNETPP_BIN:$PATH
export LD_LIBRARY_PATH=$OMNETPP_BIN/../lib:$INET/src:$VEINS/src:$VEINS_INET/src:$SIMU5G/src:${LD_LIBRARY_PATH:-}

# 1. Free port 9999
fuser -k 9999/tcp 2>/dev/null || true
sleep 1

# 2. Start veins_launchd (TraCI server). It will fork SUMO-GUI on demand.
LAUNCHD=$VEINS/bin/veins_launchd
LOG=/tmp/veins_launchd_gui_$$.log
echo "[run_traci_gui] starting veins_launchd on port 9999, log=$LOG"
"$LAUNCHD" -d -vv -L "$LOG" -p 9999 &
LAUNCHD_PID=$!
trap "kill $LAUNCHD_PID 2>/dev/null || true; fuser -k 9999/tcp 2>/dev/null || true" EXIT

for i in $(seq 1 10); do
    if ss -ln "( sport = :9999 )" 2>/dev/null | grep -q 9999; then break; fi
    sleep 0.5
done
echo "[run_traci_gui] launchd ready"

NED_PATH="$ROOT/src:$ROOT/simulations:$INET/src:$VEINS/src/veins:$VEINS_INET/src/veins_inet:$SIMU5G/src"

# 3. Launch OMNeT++ Qtenv. SUMO-GUI will appear automatically when the
#    scenario starts - watch your screen for two windows: Qtenv (this app)
#    and SUMO-GUI (the road-network viewer).
echo "[run_traci_gui] launching $CONFIG in Qtenv (sim-time-limit=$SIMLIM)"
echo "[run_traci_gui] press F5 to start the simulation in Qtenv"
"$ROOT/VeReMiVNDN" \
    -u Qtenv \
    -c "$CONFIG" \
    --sim-time-limit="$SIMLIM" \
    -n "$NED_PATH" \
    omnetpp.ini "$EXTRA_INI"

echo "[run_traci_gui] simulation closed; tearing down launchd"
