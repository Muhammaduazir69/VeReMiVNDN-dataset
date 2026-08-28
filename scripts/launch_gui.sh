#!/usr/bin/env bash
# launch_gui.sh - launch a scenario in OMNeT++ Qtenv (and start SUMO-GUI alongside)
# so the user can take paper-quality screenshots.
#
# Usage:
#   scripts/launch_gui.sh <Config>           # default sim-time-limit 600s
#   scripts/launch_gui.sh EXE_MIIDS_A1
#   scripts/launch_gui.sh EXE_MIIDS_MultiAttack
#   scripts/launch_gui.sh EnhancedAljubail
#
# Useful Configs for paper figures:
#   EnhancedAljubail        -> Fig. 14 (baseline scenario)
#   UrbanAttackScenario     -> Fig. 15 (urban attack scenario)
#   HighwayAttackScenario   -> Fig. 16 (highway scenario)
#   EXE_MIIDS_MultiAttack   -> Fig. 17 (multi-attack scenario)
#   EXE_MIIDS_A1..A8        -> per-attack scenarios
#
# After launch:
#   * Wait for SUMO-GUI window to open (it opens automatically via launchd).
#   * In SUMO-GUI: zoom and pan to JubST downtown; use 'Edit -> Take Screenshot'.
#   * In OMNeT++ Qtenv: press F5 to start, F6 to fast-forward; right-click on a
#     module and 'Open Inspector' to expose the IDS belief masses.
#
set -euo pipefail

CONFIG="${1:-EnhancedAljubail}"
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

# Kill stale SUMO/launchd on port 9999
fuser -k 9999/tcp 2>/dev/null || true
sleep 1

LAUNCHD=$ROOT/../veins/bin/veins_launchd
echo "[launch_gui] starting veins_launchd on port 9999"
"$LAUNCHD" -d -vv -L /tmp/veins_launchd_gui_$$.log -p 9999 &
LAUNCHD_PID=$!
trap "kill $LAUNCHD_PID 2>/dev/null || true; fuser -k 9999/tcp 2>/dev/null || true" EXIT

for i in $(seq 1 10); do
    if ss -ln "( sport = :9999 )" 2>/dev/null | grep -q 9999; then break; fi
    sleep 0.5
done

NED_PATH="$ROOT/src:$ROOT/simulations:$INET/src:$VEINS/src/veins:$VEINS_INET/src/veins_inet:$SIMU5G/src"

echo "[launch_gui] launching $CONFIG in Qtenv (sim-time-limit=$SIMLIM)"
echo "[launch_gui] SUMO-GUI will open automatically via launchd"
echo "[launch_gui] use 'Edit -> Take Screenshot' in SUMO-GUI for the SUMO figure"
echo "[launch_gui] use Qtenv 'File -> Save Image' for the OMNeT++ figure"

"$ROOT/VeReMiVNDN" \
    -u Qtenv \
    -c "$CONFIG" \
    --sim-time-limit="$SIMLIM" \
    -n "$NED_PATH" \
    omnetpp.ini "$EXTRA_INI"
