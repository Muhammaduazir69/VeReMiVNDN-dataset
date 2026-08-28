//
// VeReMiVNDN - Advanced Vehicular Network Scenarios
//
// Comprehensive VNDN network definitions with Veins integration
// for realistic vehicular communications.
//
// Scenarios:
//   1. VndnNetwork        - General purpose (5 RSUs, pentagon coverage)
//   2. UrbanVndnNetwork   - Dense urban (10 RSUs, 4x3 grid at intersections)
//   3. HighwayVndnNetwork - Highway (8 RSUs, linear along corridor)
//   4. MixedVndnNetwork   - Mixed urban-highway (12 RSUs, 6x2 grid)
//
// All scenarios share the Al-Jubail Industrial City playground (15km x 16km)
// but differ in RSU count, placement pattern, communication range, and
// vehicle speed to model distinct deployment environments.
//

package veremivndn.simulations.scenarios;

import veremivndn.vndn.node.VndnVehicle;
import veremivndn.vndn.node.VndnRSU;
import veremivndn.trident.TrustRegistry;
import veremivndn.trident.ResilienceMonitor;

// Veins core modules for VANET simulation
import org.car2x.veins.base.connectionManager.ConnectionManager;
import org.car2x.veins.base.modules.BaseWorldUtility;
import org.car2x.veins.modules.mobility.traci.TraCIScenarioManagerLaunchd;
import org.car2x.veins.modules.obstacle.ObstacleControl;
import org.car2x.veins.modules.world.annotations.AnnotationManager;

// INET visualization (live packet animations, mobility trails, radio rings)
import inet.visualizer.common.IntegratedVisualizer;
import inet.visualizer.contract.IIntegratedVisualizer;

//
// =============================================================================
// BASE VNDN NETWORK (General Purpose)
// =============================================================================
//
// General purpose VNDN network for flexible scenarios.
// 5 RSUs in a coverage-optimized pattern across the 15km x 16km playground:
//   rsu[0]: Southwest (3000, 4000) - covers southern industrial zone
//   rsu[1]: Southeast (11500, 4000) - covers eastern port area
//   rsu[2]: Center    (7250, 8000) - covers central corridor
//   rsu[3]: Northwest (3000, 12000) - covers northern residential zone
//   rsu[4]: Northeast (11500, 12000) - covers NE logistics zone
//
// For specialized scenarios, use UrbanVndnNetwork, HighwayVndnNetwork,
// or MixedVndnNetwork.
//
network VndnNetwork
{
    parameters:
        @display("bgb=17500,18000;bgg=500,2,grey95;bgs=100,m");

        // =====================================================================
        // PLAYGROUND DIMENSIONS
        // =====================================================================
        double playgroundSizeX @unit(m) = default(15000m);
        double playgroundSizeY @unit(m) = default(16000m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY
        // =====================================================================
        int numRSU = default(5);
        // Grid shape used to place the RSUs; numRSU should equal
        // rsuGridCols * rsuGridRows for a fully populated grid.
        int rsuGridCols = default(1);
        int rsuGridRows = default(numRSU);
        int numMaliciousVehicles = default(5);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(500m);
        double interferenceRange @unit(m) = default(1000m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // MOBILITY PARAMETERS
        // =====================================================================
        double vehicleSpeedMean @unit(mps) = default(13.89mps);
        double vehicleSpeedStd @unit(mps) = default(2mps);
        double rsuSpacing @unit(m) = default(500m);

        // =====================================================================
        // NDN PARAMETERS
        // =====================================================================
        int pitSize = default(1000);
        int csSize = default(100);
        double interestLifetime @unit(s) = default(4s);
        double dataFreshness @unit(s) = default(10s);

        // =====================================================================
        // IDS CONFIGURATION
        // =====================================================================
        bool enableIDS = default(true);
        string idsDetectionMethod = default("Hybrid");
        double idsThreshold = default(0.7);
        bool idsLogging = default(true);

        // =====================================================================
        // ATTACK CONFIGURATION
        // =====================================================================
        double attackStartTime @unit(s) = default(50s);
        double attackDuration @unit(s) = default(100s);
        double attackIntensity = default(0.8);

        // =====================================================================
        // STATISTICS
        // =====================================================================
        @signal[networkPacketsSent](type=long);
        @signal[networkPacketsReceived](type=long);
        @signal[totalAttacksDetected](type=long);
        @statistic[networkPacketsSent](source=networkPacketsSent; record=vector,stats);
        @statistic[networkPacketsReceived](source=networkPacketsReceived; record=vector,stats);
        @statistic[totalAttacksDetected](source=totalAttacksDetected; record=vector,stats);

    submodules:
        // =================================================================
        // CONTROL PANEL (left margin, stacked vertically)
        // =================================================================
        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=800,1000;i=block/eye,#33AAFF;is=s");
        }

        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=800,2000;i=abstract/multicast,#4488FF;is=s");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=800,3500;i=misc/globe,#44AAFF;is=s");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=800,5000;i=block/network2,#44AAFF;is=s");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=800,6500;i=block/building,#888888;is=s");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=800,8000;i=block/app,#888888;is=s");
        }

        // =================================================================
        // RSUs - Coverage-optimized pentagon pattern
        // Spread across the full 15km x 16km Al-Jubail playground
        // Positions match DPIDSNetwork RSU locations for consistency
        // =================================================================
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                // Uniform grid over the JubST playground. The published layout
                // pinned five RSUs to fixed pentagon points, which leaves a
                // 15 km x 16 km area with roughly 3 % radio coverage: consumers
                // almost never had a producer in range, so the Interest/Data
                // exchange the caching, data and forwarding planes depend on
                // never took place. A grid of rsuGridCols x rsuGridRows spaces
                // the infrastructure at realistic corridor intervals.
                mobility.x = parent.playgroundSizeX / (parent.rsuGridCols + 1)
                             * ((index % parent.rsuGridCols) + 1);
                mobility.y = parent.playgroundSizeY / (parent.rsuGridRows + 1)
                             * ((index / parent.rsuGridCols) + 1);
                mobility.z = 10;

                nic.phy80211p.transmitPower = 40mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,#FFB800;is=vl;r=500,#FFD70066,2");
        }

        // Vehicle nodes - dynamically created by TraCI/SUMO
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car");
        }
}


//
// =============================================================================
// URBAN VNDN NETWORK
// =============================================================================
//
// Dense urban environment:
//   - 10 RSUs in a 4-column x 3-row grid at major intersections
//   - Reduced communication range (300m) due to building obstacles
//   - Lower vehicle speeds (~40 km/h)
//   - Green RSU icons to distinguish from other scenarios
//
// RSU Grid Layout (4 cols x 3 rows across 15km x 16km):
//   Row 0 (y=2500):  x=2000, 5500, 9000, 12500
//   Row 1 (y=7500):  x=2000, 5500, 9000, 12500
//   Row 2 (y=12500): x=2000, 5500
//
network UrbanVndnNetwork
{
    parameters:
        @display("bgb=1460,1300;bgg=130,1,grey93;bgs=100,m;bgl=2;i=block/routing");

        // =====================================================================
        // PLAYGROUND DIMENSIONS  (purpose-built 1040 m urban grid + 25 m Veins margin)
        // =====================================================================
        double playgroundSizeX @unit(m) = default(1100m);
        double playgroundSizeY @unit(m) = default(1100m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Urban (dense)
        // =====================================================================
        int numRSU = default(10);
        int numMaliciousVehicles = default(10);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Urban (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(300m);
        double interferenceRange @unit(m) = default(600m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // URBAN MOBILITY PARAMETERS
        // =====================================================================
        double vehicleSpeedMean @unit(mps) = default(11.11mps);  // ~40 km/h
        double vehicleSpeedStd @unit(mps) = default(3mps);
        double rsuSpacing @unit(m) = default(250m);

        // =====================================================================
        // NDN PARAMETERS
        // =====================================================================
        int pitSize = default(1000);
        int csSize = default(100);
        double interestLifetime @unit(s) = default(4s);
        double dataFreshness @unit(s) = default(10s);

        // =====================================================================
        // IDS CONFIGURATION
        // =====================================================================
        bool enableIDS = default(true);
        string idsDetectionMethod = default("Hybrid");
        double idsThreshold = default(0.65);
        bool idsLogging = default(true);

        // =====================================================================
        // ATTACK CONFIGURATION
        // =====================================================================
        double attackStartTime @unit(s) = default(50s);
        double attackDuration @unit(s) = default(100s);
        double attackIntensity = default(0.8);

        // =====================================================================
        // STATISTICS
        // =====================================================================
        @signal[networkPacketsSent](type=long);
        @signal[networkPacketsReceived](type=long);
        @signal[totalAttacksDetected](type=long);
        @statistic[networkPacketsSent](source=networkPacketsSent; record=vector,stats);
        @statistic[networkPacketsReceived](source=networkPacketsReceived; record=vector,stats);
        @statistic[totalAttacksDetected](source=totalAttacksDetected; record=vector,stats);

    submodules:
        // =================================================================
        // CONTROL PANEL (left margin)
        // =================================================================
        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=1330,70;i=block/eye,#33AAFF;is=s");
        }

        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1330,175;i=abstract/multicast,#4488FF;is=s");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=1330,280;i=misc/globe,#44AAFF;is=s");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=1330,385;i=block/network2,#44AAFF;is=s");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=1330,490;i=block/building,#888888;is=s");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=1330,595;i=block/app,#888888;is=s");
        }

        // =================================================================
        // TRIDENT-VNDN control-plane singletons (Paper 3)
        // =================================================================
        trustRegistry: TrustRegistry {
            @display("p=1330,700;i=block/table2,#cc8800;is=s");
        }
        resilienceMonitor: ResilienceMonitor {
            @display("p=1330,805;i=block/encrypt,#26A269;is=n");
        }

        // =================================================================
        // Urban RSUs - placed on the purpose-built urban grid (urban_grid.net.xml).
        // The ten roadside units sit at major intersections of the 1040 m grid and
        // are mapped to OMNeT++ canvas coordinates with the Veins traci2omnet
        // transform for this map (ox = sx + 25, oy = 1065 - sy; 25 m margin).
        // Their 300 m cells overlap to blanket the dense, building-shadowed grid.
        // =================================================================
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                dispX = (index == 0 ? 285 : index == 1 ? 805 : index == 2 ? 545 : index == 3 ? 295 : index == 4 ? 805 : index == 5 ? 165 : index == 6 ? 935 : index == 7 ? 545 : index == 8 ? 545 : 935);
                dispY = (index == 0 ? 795 : index == 1 ? 795 : index == 2 ? 545 : index == 3 ? 285 : index == 4 ? 285 : index == 5 ? 545 : index == 6 ? 545 : index == 7 ? 925 : index == 8 ? 155 : 155);
                rsuPosX = dispX * 1m;
                rsuPosY = dispY * 1m;

                nic.phy80211p.transmitPower = 50mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                // Large green roadside antenna with a translucent 300 m coverage disc.
                @display("p=$dispX,$dispY;i=device/antennatower,#00AA44;is=l;r=300,#00CC5522,2");
        }

        // Urban vehicles (created by TraCI/SUMO): small blue cars, each carrying a
        // faint ~150 m V2V signal halo (lower TX power than the RSUs).
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,#2244AA;is=s;r=150,#3388FF1C,1");
        }
}


//
// =============================================================================
// HIGHWAY VNDN NETWORK
// =============================================================================
//
// Highway scenario:
//   - 8 RSUs in a linear chain along the central highway corridor (y=8000)
//   - Extended communication range (500m) for open environment
//   - High vehicle speeds (~100 km/h)
//   - Orange RSU icons to distinguish from other scenarios
//
// RSU Linear Layout (equally spaced along x-axis at y=8000):
//   rsu[0]: x=1500  rsu[1]: x=3500  rsu[2]: x=5500  rsu[3]: x=7500
//   rsu[4]: x=9500  rsu[5]: x=11500 rsu[6]: x=13500 rsu[7]: x=15500 (edge)
//
network HighwayVndnNetwork
{
    parameters:
        @display("bgb=4600,1250;bgg=500,1,grey90;bgs=100,m;bgl=2;i=block/routing");

        // =====================================================================
        // PLAYGROUND DIMENSIONS  (purpose-built 4500 m highway corridor + margin)
        // =====================================================================
        double playgroundSizeX @unit(m) = default(4600m);
        double playgroundSizeY @unit(m) = default(900m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Highway (linear sparse)
        // =====================================================================
        int numRSU = default(8);
        int numMaliciousVehicles = default(15);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Highway (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(500m);
        double interferenceRange @unit(m) = default(1000m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // HIGHWAY MOBILITY PARAMETERS
        // =====================================================================
        double vehicleSpeedMean @unit(mps) = default(27.78mps);  // ~100 km/h
        double vehicleSpeedStd @unit(mps) = default(5mps);
        double rsuSpacing @unit(m) = default(625m);

        // =====================================================================
        // NDN PARAMETERS
        // =====================================================================
        int pitSize = default(1000);
        int csSize = default(100);
        double interestLifetime @unit(s) = default(4s);
        double dataFreshness @unit(s) = default(10s);

        // =====================================================================
        // IDS CONFIGURATION
        // =====================================================================
        bool enableIDS = default(true);
        string idsDetectionMethod = default("Hybrid");
        double idsThreshold = default(0.7);
        bool idsLogging = default(true);

        // =====================================================================
        // ATTACK CONFIGURATION
        // =====================================================================
        double attackStartTime @unit(s) = default(50s);
        double attackDuration @unit(s) = default(100s);
        double attackIntensity = default(0.8);

        // =====================================================================
        // STATISTICS
        // =====================================================================
        @signal[networkPacketsSent](type=long);
        @signal[networkPacketsReceived](type=long);
        @signal[totalAttacksDetected](type=long);
        @statistic[networkPacketsSent](source=networkPacketsSent; record=vector,stats);
        @statistic[networkPacketsReceived](source=networkPacketsReceived; record=vector,stats);
        @statistic[totalAttacksDetected](source=totalAttacksDetected; record=vector,stats);

    submodules:
        // =================================================================
        // CONTROL PANEL (left margin)
        // =================================================================
        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=400,1050;i=block/eye,#33AAFF;is=s");
        }

        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1000,1050;i=abstract/multicast,#4488FF;is=s");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=1600,1050;i=misc/globe,#44AAFF;is=s");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=2200,1050;i=block/network2,#44AAFF;is=s");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=2800,1050;i=block/app,#888888;is=s");
        }

        // =================================================================
        // TRIDENT-VNDN control-plane singletons (Paper 3)
        // =================================================================
        trustRegistry: TrustRegistry {
            @display("p=3400,1050;i=block/table2,#cc8800;is=s");
        }
        resilienceMonitor: ResilienceMonitor {
            @display("p=4000,1050;i=block/encrypt,#00aa88;is=n");
        }

        // =================================================================
        // Highway RSUs - a sparse linear chain along the purpose-built corridor
        // (highway_corridor.net.xml). The eight units are spaced ~550 m apart just
        // north of the carriageway and mapped to OMNeT++ canvas coordinates with
        // the Veins traci2omnet transform for this map (ox = sx + 25, oy = 825 - sy
        // with sy = 480 -> oy = 345; 25 m margin). Wide 500 m cells suit the open,
        // fast, line-of-sight highway radio.
        // =================================================================
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                dispX = (index == 0 ? 325 : index == 1 ? 885 : index == 2 ? 1425 : index == 3 ? 1975 : index == 4 ? 2575 : index == 5 ? 3125 : index == 6 ? 3725 : 4275);
                dispY = 345;
                rsuPosX = dispX * 1m;
                rsuPosY = dispY * 1m;

                nic.phy80211p.transmitPower = 45mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                // Large orange gantry antenna with a translucent 500 m coverage disc.
                @display("p=$dispX,$dispY;i=device/antennatower,#FF8C00;is=l;r=500,#FFA5002A,2");
        }

        // Highway vehicles (created by TraCI/SUMO): small red cars, each with a
        // wider ~250 m V2V signal halo to match the open-road propagation.
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,#CC2200;is=s;r=250,#FF66331C,1");
        }
}


//
// =============================================================================
// MIXED VNDN NETWORK
// =============================================================================
//
// Mixed urban-highway scenario:
//   - 12 RSUs in a 6-column x 2-row grid across the full playground
//   - Balanced communication range (400m)
//   - Moderate vehicle speeds (~70 km/h)
//   - Purple RSU icons to distinguish from other scenarios
//
// RSU Grid Layout (6 cols x 2 rows):
//   Row 0 (y=5000):  x=1500, 3900, 6300, 8700, 11100, 13500
//   Row 1 (y=11000): x=1500, 3900, 6300, 8700, 11100, 13500
//
network MixedVndnNetwork
{
    parameters:
        @display("bgb=17500,18000;bgg=500,2,grey92;bgs=100,m;bgl=2;i=block/users");

        // =====================================================================
        // PLAYGROUND DIMENSIONS
        // =====================================================================
        double playgroundSizeX @unit(m) = default(15000m);
        double playgroundSizeY @unit(m) = default(16000m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Mixed (balanced)
        // =====================================================================
        int numRSU = default(12);
        int numMaliciousVehicles = default(12);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Mixed (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(400m);
        double interferenceRange @unit(m) = default(800m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // MIXED MOBILITY PARAMETERS
        // =====================================================================
        double vehicleSpeedMean @unit(mps) = default(19.44mps);  // ~70 km/h
        double vehicleSpeedStd @unit(mps) = default(4mps);
        double rsuSpacing @unit(m) = default(350m);

        // =====================================================================
        // NDN PARAMETERS
        // =====================================================================
        int pitSize = default(1000);
        int csSize = default(100);
        double interestLifetime @unit(s) = default(4s);
        double dataFreshness @unit(s) = default(10s);

        // =====================================================================
        // IDS CONFIGURATION
        // =====================================================================
        bool enableIDS = default(true);
        string idsDetectionMethod = default("Hybrid");
        double idsThreshold = default(0.68);
        bool idsLogging = default(true);

        // =====================================================================
        // ATTACK CONFIGURATION
        // =====================================================================
        double attackStartTime @unit(s) = default(50s);
        double attackDuration @unit(s) = default(100s);
        double attackIntensity = default(0.8);

        // =====================================================================
        // STATISTICS
        // =====================================================================
        @signal[networkPacketsSent](type=long);
        @signal[networkPacketsReceived](type=long);
        @signal[totalAttacksDetected](type=long);
        @statistic[networkPacketsSent](source=networkPacketsSent; record=vector,stats);
        @statistic[networkPacketsReceived](source=networkPacketsReceived; record=vector,stats);
        @statistic[totalAttacksDetected](source=totalAttacksDetected; record=vector,stats);

    submodules:
        // =================================================================
        // CONTROL PANEL (left margin)
        // =================================================================
        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=1332.296,864.19196;i=block/eye,#33AAFF;is=s");
        }

        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1620.36,2628.584;i=abstract/multicast,#4488FF;is=s");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=10586.352,4428.984;i=misc/globe,#44AAFF;is=s");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=1116.2479,5041.1196;i=block/network2,#44AAFF;is=s");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=1080.24,7345.632;i=block/building,#888888;is=s");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=1332.296,9074.016;i=block/app,#888888;is=s");
        }

        // =================================================================
        // Mixed RSUs - 6-column x 2-row grid
        // Even coverage across the full 15km x 16km playground
        // ~2400m column spacing, ~6000m row spacing
        // =================================================================
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                // 6 columns (x: 1500, 3900, 6300, 8700, 11100, 13500)
                // 2 rows   (y: 5000, 11000)
                mobility.x = ((index % 6) * 2400 + 1500);
                mobility.y = (int(index / 6) * 6000 + 5000);
                mobility.z = 12;

                nic.phy80211p.transmitPower = 45mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,#8800CC,50;is=vl;r=400,#9900FF44,2");
        }

        // Mixed vehicles - dynamically created by TraCI/SUMO
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,#00AACC");
        }
}
