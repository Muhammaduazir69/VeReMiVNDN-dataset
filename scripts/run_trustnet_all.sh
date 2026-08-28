#!/bin/bash
# Run the six TrustNet OMNeT++/Veins/SUMO configs (benign + 5 position attacks)
# on the LuST scenario and write per-vehicle feature CSVs to results/.
cd /home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN || exit 9
export PATH="/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin:$PATH"
source /home/uzair/Desktop/omnet++/omnetpp-6.0.3/setenv 2>/dev/null
pgrep -f sumo-launchd >/dev/null || (python3 ../veins/sumo-launchd.py -p 9999 >/tmp/sumo_launchd.log 2>&1 &)
sleep 3
mkdir -p results
NEDP="src:simulations:../inet4.5/src:../veins/src/veins:../veins_inet/src/veins_inet:../simu5g/src"
for C in TN_Benign TN_T1 TN_T2 TN_T4 TN_T8 TN_T16; do
  echo "########## $(date +%H:%M:%S) RUN $C ##########"
  timeout 600 out/gcc-release/VeReMiVNDN -u Cmdenv -c "$C" -f simulations/configs/trustnet.ini \
    -n "$NEDP" --image-path=../inet4.5/images:../veins/images --sim-time-limit=150s \
    > /tmp/run_$C.log 2>&1
  echo "   $C exit=$? rows=$(wc -l < results/trustnet_$C.csv 2>/dev/null || echo 0)"
done
echo "########## ALL DONE $(date +%H:%M:%S) ##########"
ls -la results/trustnet_*.csv
