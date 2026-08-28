#!/bin/bash
# Fresh-clean-run driver: runs the remaining 5 TRIDENT configs sequentially
# (Urban_Baseline is run separately), each through the proven per-config wrapper
# so veins_launchd is started and torn down cleanly for every run. Then copies
# the .sca into scenarios/results and rebuilds the summary via analyze_trident.py.
set +u
HERE=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/simulations/configs
CODE=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/VeReMiVNDN-Resilience/code
SCEN=/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/simulations/scenarios
cd "$HERE"

for CFG in Urban_Attack Urban_Trident Highway_Baseline Highway_Attack Highway_Trident; do
  echo "########## $(date +%H:%M:%S)  START $CFG ##########"
  bash run_trident_one.sh "$CFG" 0
  echo "########## $(date +%H:%M:%S)  DONE  $CFG  (rc=$?) ##########"
done

# analyzer reads .sca from scenarios/results by default
cp -f "$HERE"/results/*.sca "$SCEN"/results/ 2>/dev/null
echo "########## running analyzer ##########"
python3 "$CODE"/analyze_trident.py "$SCEN"/results
echo "########## ALL DONE $(date +%H:%M:%S) ##########"
