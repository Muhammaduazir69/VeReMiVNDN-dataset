//
// VeReMiVNDN - Advanced Vehicular Network Scenarios
//
// Comprehensive VNDN network with Veins integration for realistic vehicular communications
// Includes attack scenarios, IDS monitoring, and beautiful visualization
//

package veremivndn.simulations.scenarios;

import veremivndn.vndn.node.VndnVehicle;
import veremivndn.vndn.node.VndnRSU;

// Veins core modules for VANET simulation
import org.car2x.veins.base.connectionManager.ConnectionManager;
import org.car2x.veins.base.modules.BaseWorldUtility;
import org.car2x.veins.modules.mobility.traci.TraCIScenarioManagerLaunchd;
import org.car2x.veins.modules.obstacle.ObstacleControl;
import org.car2x.veins.modules.world.annotations.AnnotationManager;

//
// =============================================================================
// BASE VNDN NETWORK (General Purpose)
// =============================================================================
//
// General purpose VNDN network for flexible scenarios.
// This is the base network used by default configurations.
// For specialized scenarios, use UrbanVndnNetwork, HighwayVndnNetwork, or MixedVndnNetwork.
//
network VndnNetwork
{
    parameters:
        @display("bgb=15000,16000;bgg=100,1,grey95;bgs=100,m");

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
        // VEINS Core Components
        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1728.432,1216.304;i=abstract/multicast,gold;is=l");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=4481.12,1152.288;i=misc/globe,gold;is=l");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=7457.864,1120.28;i=block/network2,gold;is=l");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=10754.6875,1120.28;i=block/building,gold;is=l");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=13443.359,1120.28;i=block/app,gold;is=l");
        }

        // RSUs - General deployment pattern
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                mobility.x = (index % 5) * rsuSpacing + 100;
                mobility.y = int(index / 5) * rsuSpacing + 100;
                mobility.z = 10;

                nic.phy80211p.transmitPower = 40mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,gold;is=vl;r=500,#FFD700,1");
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
// Specialized urban environment with:
// - Dense vehicle deployment (dynamically created by SUMO)
// - Building obstacles affecting signal propagation
// - Multiple intersections and traffic lights
// - Lower vehicle speeds (30-60 km/h)
// - Higher RSU density for coverage (10 RSUs in grid pattern)
// - Beautiful city visualization with green RSU icons
//
network UrbanVndnNetwork
{
    parameters:
        @display("bgb=15000,16000;bgg=100,1,grey95;bgs=100,m;bgl=2");

        // =====================================================================
        // PLAYGROUND DIMENSIONS - Urban area (aljubail_saudi network)
        // =====================================================================
        double playgroundSizeX @unit(m) = default(15000m);
        double playgroundSizeY @unit(m) = default(16000m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Urban configuration
        // =====================================================================
        int numRSU = default(10);                // Dense RSU deployment for urban
        int numMaliciousVehicles = default(10);  // Urban attackers
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Urban (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(300m);  // Reduced by obstacles
        double interferenceRange @unit(m) = default(600m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // URBAN MOBILITY PARAMETERS
        // =====================================================================
        double vehicleSpeedMean @unit(mps) = default(11.11mps);  // ~40 km/h urban
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
        double idsThreshold = default(0.65);  // Lower for urban sensitivity
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
        // VEINS Core Components
        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=6849.712,14019.504;i=abstract/multicast,gold;is=l");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=1312.328,9570.392;i=misc/globe,gold;is=l");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=13859.464,9122.28;i=block/network2,gold;is=l");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=13859.464,4961.2397;i=block/building,gold;is=l");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=13891.472,1088.272;i=block/app,gold;is=l");
        }

        // Urban RSUs - Grid placement at intersections
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                mobility.x = ((index % 4) * 3000 + 1500);  // Spread across 15000m
                mobility.y = (int(index / 4) * 4000 + 2000);  // Spread across 16000m
                mobility.z = 15;

                nic.phy80211p.transmitPower = 50mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,green,50;is=vl;r=300,#00FF00,2");
        }

        // Urban vehicles - dynamically created by TraCI/SUMO
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,blue");
        }
}


//
// =============================================================================
// HIGHWAY VNDN NETWORK
// =============================================================================
//
// Highway scenario with:
// - High-speed vehicle deployment (dynamically created by SUMO)
// - Long linear topology (5000m x 1000m)
// - Minimal obstacles (open environment)
// - Sparse RSU deployment along highway (8 RSUs)
// - Extended communication range (500m)
// - Beautiful highway visualization with orange RSU icons
//
network HighwayVndnNetwork
{
    parameters:
        @display("bgb=15000,16000;bgg=50,1,grey90;bgs=100,m;bgl=2");

        // =====================================================================
        // PLAYGROUND DIMENSIONS - Highway (aljubail_saudi network)
        // =====================================================================
        double playgroundSizeX @unit(m) = default(15000m);
        double playgroundSizeY @unit(m) = default(16000m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Highway configuration
        // =====================================================================
        int numRSU = default(8);                // Linear RSU deployment
        int numMaliciousVehicles = default(15); // More vehicles on highway
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Highway (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(500m);  // Extended range
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
        // VEINS Core Components
        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1024.256,14467.616;i=abstract/multicast,gold;is=l");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=13955.487,7969.9917;i=misc/globe,gold;is=l");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=13955.487,14467.616;i=block/network2,gold;is=l");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=13955.487,2240.56;i=block/app,gold;is=l");
        }

        // Highway RSUs - Linear placement along highway center
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                mobility.x = (index * 1875 + 937);  // Linear spacing across 15000m
                mobility.y = 8000;                   // Center of playground
                mobility.z = 12;

                nic.phy80211p.transmitPower = 45mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,orange,50;is=vl;r=500,#FFA500,2");
        }

        // Highway vehicles - dynamically created by TraCI/SUMO
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,red");
        }
}


//
// =============================================================================
// MIXED VNDN NETWORK
// =============================================================================
//
// Mixed urban-highway scenario with:
// - Transitional zones between urban and highway
// - Variable speed limits and topology (3500m x 2000m)
// - Dynamic obstacle density
// - Balanced RSU deployment (12 RSUs)
// - Adaptive communication parameters
// - Beautiful mixed visualization with purple RSU icons
//
network MixedVndnNetwork
{
    parameters:
        @display("bgb=15000,16000;bgg=75,1,grey92;bgs=100,m;bgl=2");

        // =====================================================================
        // PLAYGROUND DIMENSIONS - Mixed terrain (aljubail_saudi network)
        // =====================================================================
        double playgroundSizeX @unit(m) = default(15000m);
        double playgroundSizeY @unit(m) = default(16000m);
        double playgroundSizeZ @unit(m) = default(50m);

        // =====================================================================
        // NETWORK TOPOLOGY - Mixed configuration
        // =====================================================================
        int numRSU = default(12);               // Balanced deployment
        int numMaliciousVehicles = default(12);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // VEHICULAR COMMUNICATION PARAMETERS - Mixed (IEEE 802.11p)
        // =====================================================================
        double communicationRange @unit(m) = default(400m);  // Balanced
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
        // VEINS Core Components
        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=1312.328,1088.272;i=abstract/multicast,gold;is=l");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=4865.216,1056.264;i=misc/globe,gold;is=l");
        }

        manager: TraCIScenarioManagerLaunchd {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnVehicle";
                moduleName = "vehicle";
                @display("p=7777.944,1088.272;i=block/network2,gold;is=l");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=10690.672,1088.272;i=block/building,gold;is=l");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=13955.487,1088.272;i=block/app,gold;is=l");
        }

        // Mixed RSUs - Hybrid grid/linear placement
        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;
                mobility.x = ((index % 6) * 2500 + 1250);  // Spread across 15000m
                mobility.y = (int(index / 6) * 8000 + 4000);  // Spread across 16000m
                mobility.z = 12;

                nic.phy80211p.transmitPower = 45mW;
                nic.phy80211p.sensitivity = -95dBm;

                pitMaxSize = 5000;
                csMaxSize = 500;

                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                @display("i=device/antennatower,purple,50;is=vl;r=400,#9900FF,2");
        }

        // Mixed vehicles - dynamically created by TraCI/SUMO
        vehicle[0]: VndnVehicle {
            @display("i=veins/node/car,cyan");
        }
}
