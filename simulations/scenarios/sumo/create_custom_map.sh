#!/bin/bash
#
# Create Custom SUMO Map from OpenStreetMap
# This script downloads OSM data and converts it to SUMO network
#

set -e

echo "=================================================="
echo "Custom SUMO Map Creator for VeReMiVNDN"
echo "=================================================="

# Set SUMO_HOME if not already set
if [ -z "$SUMO_HOME" ]; then
    export SUMO_HOME="/usr/local/share/sumo"
    echo "Setting SUMO_HOME to: $SUMO_HOME"
fi

# Configuration - Al-Jubail, Saudi Arabia
# Google Maps link: https://maps.app.goo.gl/YAWfJoo5R5vfz4jQ6
# Al-Jubail Industrial City, Saudi Arabia

# Bounding box coordinates (lon_min, lat_min, lon_max, lat_max)
# Al-Jubail city center coordinates
LON_MIN="49.60"    # West
LAT_MIN="27.00"    # South
LON_MAX="49.68"    # East
LAT_MAX="27.05"    # North

MAP_NAME="aljubail_saudi"
OUTPUT_DIR="."

echo ""
echo "Map Configuration:"
echo "  Name: $MAP_NAME"
echo "  Bounds: ($LON_MIN, $LAT_MIN) to ($LON_MAX, $LAT_MAX)"
echo ""

# Step 1: Download OSM data
echo "[Step 1/5] Downloading OSM data from OpenStreetMap..."
echo "  Bounding box: $LON_MIN,$LAT_MIN,$LON_MAX,$LAT_MAX"

# Use wget to download from Overpass API
OVERPASS_QUERY="[bbox:$LAT_MIN,$LON_MIN,$LAT_MAX,$LON_MAX];(way[\"highway\"];node(w););out;"
wget -O "${MAP_NAME}.osm" "https://overpass-api.de/api/interpreter?data=${OVERPASS_QUERY// /%20}"

if [ ! -f "${MAP_NAME}.osm" ] || [ ! -s "${MAP_NAME}.osm" ]; then
    echo "ERROR: Failed to download OSM data or file is empty"
    echo "Please manually download from: https://www.openstreetmap.org/export"
    echo "Select the area and export as .osm file"
    exit 1
fi

echo "  Downloaded: ${MAP_NAME}.osm ($(du -h ${MAP_NAME}.osm | cut -f1))"

# Step 2: Convert OSM to SUMO network
echo ""
echo "[Step 2/5] Converting OSM to SUMO network..."

netconvert \
    --osm-files "${MAP_NAME}.osm" \
    --output-file "${MAP_NAME}.net.xml" \
    --geometry.remove \
    --roundabouts.guess \
    --ramps.guess \
    --junctions.join \
    --tls.guess-signals \
    --tls.discard-simple \
    --tls.join \
    --output.original-names \
    --output.street-names \
    --proj "+proj=utm +zone=38 +datum=WGS84" \
    --no-internal-links \
    --no-turnarounds \
    --verbose

if [ ! -f "${MAP_NAME}.net.xml" ]; then
    echo "ERROR: Failed to create SUMO network"
    exit 1
fi

echo "  Created: ${MAP_NAME}.net.xml"

# Step 3: Generate polygon/background
echo ""
echo "[Step 3/5] Generating polygons for visualization..."

# Check if SUMO type files exist, otherwise skip polygons
if [ -f "$SUMO_HOME/data/typemap/osmPolyconvert.typ.xml" ]; then
    polyconvert \
        --osm-files "${MAP_NAME}.osm" \
        --net-file "${MAP_NAME}.net.xml" \
        --output-file "${MAP_NAME}.poly.xml" \
        --type-file "$SUMO_HOME/data/typemap/osmPolyconvert.typ.xml" \
        --verbose 2>&1 || echo "  Warning: Polygon generation had issues (optional)"
else
    echo "  Skipping polygon generation (type files not found, optional)"
fi

# Ensure poly.xml file exists (create empty one if polyconvert failed)
if [ ! -f "${MAP_NAME}.poly.xml" ]; then
    echo "  Creating empty poly file..."
    cat > "${MAP_NAME}.poly.xml" <<'POLYEOF'
<?xml version="1.0" encoding="UTF-8"?>
<additional xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/additional_file.xsd">
</additional>
POLYEOF
fi

# Step 4: Generate random traffic
echo ""
echo "[Step 4/5] Generating random traffic..."

# Check if SUMO tools exist
if [ -f "$SUMO_HOME/tools/randomTrips.py" ]; then
    python3 "$SUMO_HOME/tools/randomTrips.py" \
        -n "${MAP_NAME}.net.xml" \
        -r "${MAP_NAME}.rou.xml" \
        -e 300 \
        --trip-attributes="departLane=\"best\" departSpeed=\"max\"" \
        --fringe-factor 5 \
        --min-distance 200 \
        --vehicle-class passenger \
        -p 2.0 \
        --validate \
        --verbose
elif [ -f "/usr/local/bin/randomTrips.py" ]; then
    python3 "/usr/local/bin/randomTrips.py" \
        -n "${MAP_NAME}.net.xml" \
        -r "${MAP_NAME}.rou.xml" \
        -e 300 \
        --trip-attributes="departLane=\"best\" departSpeed=\"max\"" \
        --fringe-factor 5 \
        --min-distance 200 \
        --vehicle-class passenger \
        -p 2.0 \
        --validate \
        --verbose
else
    echo "  Warning: randomTrips.py not found, generating simple routes..."
    # Create basic route file
    cat > "${MAP_NAME}.rou.xml" <<'ROUTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<routes xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/routes_file.xsd">
    <vType id="car" accel="2.6" decel="4.5" sigma="0.5" length="5" minGap="2.5" maxSpeed="50" color="1,1,0"/>
    <flow id="flow0" type="car" begin="0" end="300" probability="0.5" departLane="best" departSpeed="max"/>
</routes>
ROUTEOF
fi

if [ ! -f "${MAP_NAME}.rou.xml" ]; then
    echo "ERROR: Failed to generate routes"
    exit 1
fi

echo "  Created: ${MAP_NAME}.rou.xml"

# Step 5: Create SUMO configuration file
echo ""
echo "[Step 5/5] Creating SUMO configuration..."

cat > "${MAP_NAME}.sumo.cfg" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/sumoConfiguration.xsd">
    <input>
        <net-file value="${MAP_NAME}.net.xml"/>
        <route-files value="${MAP_NAME}.rou.xml"/>
        <additional-files value="${MAP_NAME}.poly.xml"/>
    </input>

    <time>
        <begin value="0"/>
        <end value="300"/>
        <step-length value="0.1"/>
    </time>

    <processing>
        <collision.action value="warn"/>
        <collision.check-junctions value="true"/>
        <time-to-teleport value="-1"/>
    </processing>

    <routing>
        <device.rerouting.adaptation-steps value="180"/>
        <device.rerouting.adaptation-interval value="10"/>
    </routing>

    <report>
        <verbose value="true"/>
        <no-step-log value="true"/>
    </report>

    <gui_only>
        <gui-settings-file value="${MAP_NAME}.gui.xml"/>
    </gui_only>
</configuration>
EOF

echo "  Created: ${MAP_NAME}.sumo.cfg"

# Create GUI settings
cat > "${MAP_NAME}.gui.xml" <<EOF
<viewsettings>
    <scheme name="real world"/>
    <delay value="50"/>
    <viewport y="0" x="0" zoom="100"/>
</viewsettings>
EOF

echo "  Created: ${MAP_NAME}.gui.xml"

# Step 6: Create launchd configuration
echo ""
echo "[Step 6/6] Creating VEINS launchd configuration..."

cat > "${MAP_NAME}.launchd.xml" <<EOF
<?xml version="1.0"?>
<launch>
    <basedir path="/home/uzair/Desktop/omnet++/omnetpp-6.0.3/VNDN/VeReMiVNDN/simulations/scenarios/sumo/"/>
    <copy file="${MAP_NAME}.net.xml"/>
    <copy file="${MAP_NAME}.rou.xml"/>
    <copy file="${MAP_NAME}.poly.xml"/>
    <copy file="${MAP_NAME}.gui.xml"/>
    <copy file="${MAP_NAME}.sumo.cfg" type="config"/>
    <commands>
        <sumo-gui>sumo-gui --start</sumo-gui>
        <sumo>sumo</sumo>
    </commands>
</launch>
EOF

echo "  Created: ${MAP_NAME}.launchd.xml"

echo ""
echo "=================================================="
echo "SUCCESS! Custom map created successfully!"
echo "=================================================="
echo ""
echo "Generated files:"
echo "  - ${MAP_NAME}.osm          (OpenStreetMap data)"
echo "  - ${MAP_NAME}.net.xml      (SUMO network)"
echo "  - ${MAP_NAME}.rou.xml      (Traffic routes)"
echo "  - ${MAP_NAME}.poly.xml     (Polygons for visualization)"
echo "  - ${MAP_NAME}.sumo.cfg     (SUMO configuration)"
echo "  - ${MAP_NAME}.gui.xml      (GUI settings)"
echo "  - ${MAP_NAME}.launchd.xml  (VEINS launcher)"
echo ""
echo "To use this map in your simulation:"
echo "1. Update omnetpp.ini:"
echo "   *.manager.launchConfig = xmldoc(\"../scenarios/sumo/${MAP_NAME}.launchd.xml\")"
echo ""
echo "2. Test SUMO visualization:"
echo "   sumo-gui -c ${MAP_NAME}.sumo.cfg"
echo ""
echo "3. Run VeReMiVNDN simulation with new map!"
echo ""
