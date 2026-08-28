#!/bin/bash
# Run ONE TrustNet config end-to-end (SUMO + Veins + OMNeT++) and emit the
# per-vehicle feature CSV under simulations/scenarios/results/.
#   bash run_trustnet.sh TN_T8 [sim_time_limit_s]
CONFIG=${1:-TN_Benign}
LIMIT=${2:-150}
ROOT=/home/uzair/Desktop/omnet++/omnetpp-6.0.3
PROJ=$ROOT/VNDN/VeReMiVNDN
source $ROOT/setenv >/dev/null 2>&1
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PROJ/../veins_inet/out/gcc-release/src:$PROJ/../simu5g/src"
pkill -9 -f veins_launchd 2>/dev/null; pkill -9 -f "sumo" 2>/dev/null; sleep 1
python3 $PROJ/../veins/bin/veins_launchd -p 9999 > /tmp/launchd_${CONFIG}.log 2>&1 &
LP=$!
sleep 2
cd $PROJ/simulations/scenarios
mkdir -p results
timeout 1800 $PROJ/out/gcc-release/VeReMiVNDN \
    -r 0 -m -u Cmdenv -c "$CONFIG" --sim-time-limit=${LIMIT}s \
    -n ".:$PROJ/src:$ROOT/VNDN/inet4.5/src:$ROOT/VNDN/veins/src/veins:$ROOT/VNDN/veins_inet/src/veins_inet:$ROOT/VNDN/simu5g/src" \
    --image-path=$ROOT/VNDN/inet4.5/images:$ROOT/VNDN/veins/images:$ROOT/VNDN/simu5g/images \
    -l $ROOT/VNDN/inet4.5/src/INET -l $ROOT/VNDN/veins/src/veins \
    -l $ROOT/VNDN/veins_inet/out/gcc-release/src/veins_inet -l $ROOT/VNDN/simu5g/src/simu5g \
    ../configs/trustnet.ini > /tmp/trustnet_${CONFIG}.log 2>&1
RC=$?
kill $LP 2>/dev/null; pkill -9 -f veins_launchd 2>/dev/null; pkill -9 -f "sumo" 2>/dev/null
echo "RC=$RC"
tail -5 /tmp/trustnet_${CONFIG}.log
