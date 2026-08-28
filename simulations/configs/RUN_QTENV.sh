#!/bin/bash
# DP-IDS-VNDN - Launch Simulation in Qtenv (GUI) with full visualization
#
# This script starts the simulation with:
#   - Veins 802.11p (V2V communication)
#   - Simu5G 5G NR infrastructure (gNodeBs, UPF, core network)
#   - INET integrated visualizer (packet flows, mobility trails, signal propagation)
#   - DP-IDS canvas dashboard overlay
#   - Dynamic vehicle color-coding (TP=red, FP=orange, benign=green)
#
# Prerequisites: Start SUMO launchd first:
#   python3 ../../../veins/bin/veins_launchd -vv -p 9999
#
# Usage: ./RUN_QTENV.sh [CONFIG_NAME]
#   CONFIG_NAME: DPIDS_Benign, DPIDS_CSPoisoning, DPIDS_PITFlooding,
#                DPIDS_FIBHijacking, DPIDS_Combined, etc.

cd "$(dirname "$0")/../scenarios"

CONFIG=${1:-DPIDS_CSPoisoning}

source /home/uzair/Desktop/omnet++/omnetpp-6.0.3/setenv

../../out/gcc-release/VeReMiVNDN \
    -r 0 -m -u Qtenv \
    -c "$CONFIG" \
    -n ".:../../src:../../../inet4.5/src:../../../veins/src/veins:../../../simu5g/src" \
    --image-path=../../../inet4.5/images:../../../veins/images:../../../simu5g/images \
    -l ../../../inet4.5/src/INET \
    -l ../../../veins/src/veins \
    -l ../../../simu5g/src/simu5g \
    ../configs/dpids_omnetpp.ini
