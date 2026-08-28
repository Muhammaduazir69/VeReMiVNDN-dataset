#!/bin/bash
# DP-IDS-VNDN - Run simulation (Cmdenv or Qtenv)
#
# Usage:
#   ./RUN_DPIDS.sh Scenario_A              # Run in Cmdenv
#   ./RUN_DPIDS.sh Scenario_B Qtenv        # Run in Qtenv (GUI)
#   ./RUN_DPIDS.sh Scenario_C              # Runs 4 iterations (DP-IDS vs baselines)
#
# Prerequisites: Start SUMO launchd first:
#   python3 ../../../veins/bin/veins_launchd -vv -p 9999

cd "$(dirname "$0")/../scenarios"

CONFIG=${1:-Scenario_A}
UI=${2:-Cmdenv}
RUN=${3:-0}

source /home/uzair/Desktop/omnet++/omnetpp-6.0.3/setenv

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$(pwd)/../../../veins_inet/out/gcc-release/src:$(pwd)/../../../simu5g/src"

../../out/gcc-release/VeReMiVNDN \
    -r "$RUN" -m -u "$UI" \
    -c "$CONFIG" \
    -n ".:../../src:../../../inet4.5/src:../../../veins/src/veins:../../../veins_inet/src/veins_inet:../../../simu5g/src" \
    --image-path=../../../inet4.5/images:../../../veins/images:../../../simu5g/images \
    -l ../../../inet4.5/src/INET \
    -l ../../../veins/src/veins \
    -l ../../../veins_inet/out/gcc-release/src/veins_inet \
    -l ../../../simu5g/src/simu5g \
    ../configs/dpids_omnetpp.ini
