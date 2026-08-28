#!/bin/bash
# Combined harness: start veins_launchd in the background, then run ONE TRIDENT
# config. No sleep is used (the TraCI manager retries the connection for ~17s),
# so the run survives environments that block sleep.
#
#   bash run_trident_one.sh <ConfigName> [runnumber]
CONFIG=${1:-Urban_Baseline}
RUN=${2:-0}
ROOT=/home/uzair/Desktop/omnet++/omnetpp-6.0.3
PROJ=$ROOT/VNDN/VeReMiVNDN

source $ROOT/setenv >/dev/null 2>&1
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PROJ/../veins_inet/out/gcc-release/src:$PROJ/../simu5g/src"

pkill -9 -f veins_launchd 2>/dev/null
pkill -9 -f "bin/sumo" 2>/dev/null

# Start the SUMO launchd proxy in the background; it binds port 9999 immediately.
python3 $PROJ/../veins/bin/veins_launchd -vv -t -p 9999 > /tmp/launchd_$CONFIG.log 2>&1 &
LP=$!
echo ">>> launchd pid=$LP  config=$CONFIG run=$RUN"

cd $PROJ/simulations/scenarios
$PROJ/out/gcc-release/VeReMiVNDN \
    -r "$RUN" -m -u Cmdenv -c "$CONFIG" \
    -n ".:$PROJ/src:$ROOT/VNDN/inet4.5/src:$ROOT/VNDN/veins/src/veins:$ROOT/VNDN/veins_inet/src/veins_inet:$ROOT/VNDN/simu5g/src" \
    --image-path=$ROOT/VNDN/inet4.5/images:$ROOT/VNDN/veins/images:$ROOT/VNDN/simu5g/images \
    -l $ROOT/VNDN/inet4.5/src/INET \
    -l $ROOT/VNDN/veins/src/veins \
    -l $ROOT/VNDN/veins_inet/out/gcc-release/src/veins_inet \
    -l $ROOT/VNDN/simu5g/src/simu5g \
    $PROJ/simulations/configs/trident_omnetpp.ini > $PROJ/simulations/scenarios/results/simout_$CONFIG.log 2>&1
RC=$?
echo ">>> sim RC=$RC"
kill $LP 2>/dev/null
pkill -9 -f veins_launchd 2>/dev/null
pkill -9 -f "bin/sumo" 2>/dev/null
exit $RC
