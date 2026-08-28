#!/bin/bash
# Run ONE config under gdb (batch) and log a backtrace to results/gdb.log.
CONFIG=${1:-Urban_Baseline}
ROOT=/home/uzair/Desktop/omnet++/omnetpp-6.0.3
PROJ=$ROOT/VNDN/VeReMiVNDN
source $ROOT/setenv >/dev/null 2>&1
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PROJ/../veins_inet/out/gcc-release/src:$PROJ/../simu5g/src"
pkill -9 -f veins_launchd 2>/dev/null; pkill -9 -f "sumo -c" 2>/dev/null
python3 $PROJ/../veins/bin/veins_launchd -p 9999 > /tmp/launchd_gdb.log 2>&1 &
LP=$!
cd $PROJ/simulations/scenarios
rm -f results/gdb.log
timeout 90 gdb -batch \
    -ex "set logging file results/gdb.log" \
    -ex "set logging overwrite on" \
    -ex "set logging on" \
    -ex "run" \
    -ex "bt" \
    -ex "quit" \
    --args $PROJ/out/gcc-release/VeReMiVNDN \
    -r 0 -m -u Cmdenv -c "$CONFIG" \
    -n ".:$PROJ/src:$ROOT/VNDN/inet4.5/src:$ROOT/VNDN/veins/src/veins:$ROOT/VNDN/veins_inet/src/veins_inet:$ROOT/VNDN/simu5g/src" \
    --image-path=$ROOT/VNDN/inet4.5/images:$ROOT/VNDN/veins/images:$ROOT/VNDN/simu5g/images \
    -l $ROOT/VNDN/inet4.5/src/INET -l $ROOT/VNDN/veins/src/veins \
    -l $ROOT/VNDN/veins_inet/out/gcc-release/src/veins_inet -l $ROOT/VNDN/simu5g/src/simu5g \
    ../configs/trident_omnetpp.ini > results/gdb_stdout.log 2>&1
kill $LP 2>/dev/null; pkill -9 -f veins_launchd 2>/dev/null; pkill -9 -f "sumo -c" 2>/dev/null
