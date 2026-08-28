#!/bin/bash
# TRIDENT-VNDN - run a scenario arm (Paper 3)
#
# Usage:
#   ./RUN_TRIDENT.sh <ConfigName> [Cmdenv|Qtenv] [runnumber]
# e.g.
#   ./RUN_TRIDENT.sh Urban_Baseline
#   ./RUN_TRIDENT.sh Urban_Trident Qtenv
#
# Prerequisite: start the SUMO launchd proxy first, in another terminal:
#   python3 ../../../veins/bin/veins_launchd -vv -p 9999

cd "$(dirname "$0")/../scenarios"

CONFIG=${1:-Urban_Baseline}
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
    ../configs/trident_omnetpp.ini
