#!/bin/bash
# Run all six TRIDENT arms sequentially on the purpose-built maps, then copy the
# .sca scalars next to the resilience CSVs for the analyzer. Each arm reuses
# run_trident_one.sh (its own launchd lifecycle + pkill), so they cannot collide.
#   bash run_trident_all.sh              # runs the default six
#   bash run_trident_all.sh A B C        # or an explicit list
set -u
CFGDIR=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/simulations/configs
SCEN=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/simulations/scenarios
cd "$CFGDIR"

if [ "$#" -gt 0 ]; then
    CONFIGS="$*"
else
    CONFIGS="Urban_Baseline Urban_Attack Urban_Trident Highway_Baseline Highway_Attack Highway_Trident"
fi

for c in $CONFIGS; do
    echo "############ $(date +%H:%M:%S)  RUN $c ############"
    bash run_trident_one.sh "$c" 0
    echo "############ $(date +%H:%M:%S)  DONE $c (RC=$?) ############"
done

# stage all scalars where analyze_trident.py / make_figs.py expect them
mkdir -p "$SCEN/results"
cp -f "$CFGDIR/results/"*.sca "$SCEN/results/" 2>/dev/null
echo "############ ALL DONE $(date +%H:%M:%S) ############"
ls -la "$SCEN/results/"*.sca "$SCEN/results/"resilience_*.csv 2>/dev/null
