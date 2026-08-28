//
// DP-IDS-VNDN - Heterogeneous Network Definition
// Dual-Plane IDS for Vehicular Named Data Networking
//
// This network integrates:
//   - Veins 802.11p for V2V DSRC communication
//   - Simu5G 5G NR infrastructure (gNodeBs, UPF, core network)
//   - RSUs equipped with DP-IDS monitoring framework
//   - INET IPv4 routing and visualization
//   - Vehicles capable of launching forwarding-plane attacks
//
// Architecture: Heterogeneous V2X with dual radio access (802.11p + NR)
//
// Node Layout (Al-Jubail Industrial City, Saudi Arabia):
//   - 5 gNodeBs in a coverage-optimized pattern (2 south, 1 center, 2 north)
//   - 5 RSUs co-located near gNodeBs for dual-connectivity coverage
//   - Core network (Server -> Router -> UPF) at the northern edge
//   - Control/utility modules in a panel strip along the left margin
//

package veremivndn.simulations.scenarios;

import veremivndn.vndn.node.VndnNRVehicle;
import veremivndn.vndn.node.VndnRSU;

// Veins-INET bridge (required for VeinsInetMobility + Simu5G)
import org.car2x.veins.subprojects.veins_inet.VeinsInetManager;

// Veins core modules (still needed for RSU 802.11p and obstacles)
import org.car2x.veins.base.connectionManager.ConnectionManager;
import org.car2x.veins.base.modules.BaseWorldUtility;
import org.car2x.veins.modules.obstacle.ObstacleControl;
import org.car2x.veins.modules.world.annotations.AnnotationManager;

// Simu5G 5G NR modules
import simu5g.world.radio.LteChannelControl;
import simu5g.common.binder.Binder;
import simu5g.common.carrierAggregation.CarrierAggregation;
import simu5g.nodes.NR.gNodeB;
import simu5g.nodes.Upf;

// INET core modules
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.ipv4.RoutingTableRecorder;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.ethernet.Eth10G;
import inet.visualizer.common.IntegratedVisualizer;
import inet.visualizer.contract.IIntegratedVisualizer;


//
// =============================================================================
// DP-IDS VNDN HETEROGENEOUS NETWORK
// =============================================================================
//
// Network with DP-IDS-VNDN framework on RSUs for dual-plane intrusion detection.
// RSUs monitor both behavioural signals and NDN forwarding-plane telemetry,
// fuse evidence using Dempster-Shafer Theory, and apply adaptive penalisation.
//
// 5G NR infrastructure provides:
//   - gNodeB base stations for cellular V2N communication
//   - UPF (User Plane Function) for 5G core network
//   - Realistic 3GPP 38.901 channel model
//   - Carrier aggregation with configurable numerology
//
// Methodology Reference: Sections 4.1 - 4.5
//
network DPIDSNetwork
{
    parameters:
        // =====================================================================
        // DISPLAY: Enlarged background with left-margin control panel
        // Background = 17500 x 18000 pixels (playground 15000x16000 + margins)
        // bgg = grid spacing, bgs = scale, bgi = background image (optional)
        // =====================================================================
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
        int numGNodeBs = default(5);
        int numMaliciousVehicles = default(5);
        double maliciousVehicleRatio = default(0.1);

        // =====================================================================
        // IEEE 802.11p COMMUNICATION (V2V DSRC)
        // =====================================================================
        double communicationRange @unit(m) = default(500m);
        double interferenceRange @unit(m) = default(1000m);
        double carrierFrequency @unit(Hz) = default(5.9GHz);
        double transmitPower @unit(mW) = default(20mW);
        double sensitivity @unit(dBm) = default(-89dBm);

        // =====================================================================
        // 5G NR CONFIGURATION
        // =====================================================================
        double nrCarrierFrequency @unit(GHz) = default(3.5GHz);
        int nrNumBands = default(25);
        int nrNumerologyIndex = default(1);  // 30kHz SCS

        // =====================================================================
        // MOBILITY
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
        // IDS CONFIGURATION (legacy behavioural IDS)
        // =====================================================================
        bool enableIDS = default(false);
        string idsDetectionMethod = default("Hybrid");
        double idsThreshold = default(0.7);
        bool idsLogging = default(false);

        // =====================================================================
        // DP-IDS-VNDN CONFIGURATION (Methodology Sections 4.1-4.5)
        // =====================================================================
        bool enableDPIDS = default(true);

        // Orchestration (Section 4.1)
        double dpidsOrchestrationInterval @unit(s) = default(1s);
        double dpidsBeliefThreshold = default(0.65);
        bool dpidsEnablePenalization = default(true);

        // Dempster-Shafer Fusion (Section 4.4)
        double dpidsKMax = default(0.8);
        double dpidsReliabilityBehavioural = default(0.85);
        double dpidsReliabilityForwarding = default(0.90);

        // Adaptive Forwarding Thresholds (Section 4.5)
        double dpidsThetaCS = default(0.5);
        double dpidsThetaPIT = default(0.5);
        double dpidsThetaFIB = default(0.5);

        // =====================================================================
        // ATTACK CONFIGURATION
        // =====================================================================
        double attackStartTime @unit(s) = default(60s);
        double attackDuration @unit(s) = default(180s);
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
        // CONTROL PANEL (left margin, x=600..1600, stacked vertically)
        // These are infrastructure/utility modules, not network nodes.
        // Placed outside the road network area for a clean GUI layout.
        // =================================================================

        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=800,1500;i=block/cogwheel,#44AAFF;is=s");
        }

        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=800,2500;is=s");
        }

        connectionManager: ConnectionManager {
            parameters:
                sendDirect = true;
                maxInterfDist = parent.interferenceRange;
                drawMaxIntfDist = false;
                @display("p=800,3500;i=abstract/multicast,#4488FF;is=s");
        }

        world: BaseWorldUtility {
            parameters:
                playgroundSizeX = parent.playgroundSizeX;
                playgroundSizeY = parent.playgroundSizeY;
                playgroundSizeZ = parent.playgroundSizeZ;
                @display("p=800,4500;i=misc/globe,#44AAFF;is=s");
        }

        manager: VeinsInetManager {
            parameters:
                updateInterval = 0.1s;
                moduleType = "veremivndn.vndn.node.VndnNRVehicle";
                moduleName = "vehicle";
                @display("p=800,5500;i=block/network2,#44AAFF;is=s");
        }

        obstacles: ObstacleControl {
            parameters:
                @display("p=800,6500;i=block/building,#888888;is=s");
        }

        annotations: AnnotationManager {
            parameters:
                @display("p=800,7500;i=block/app,#888888;is=s");
        }

        channelControl: LteChannelControl {
            parameters:
                @display("p=800,8500;i=misc/sun,#FF8800;is=s");
        }

        binder: Binder {
            parameters:
                @display("p=800,9500;i=block/cogwheel,#FF8800;is=s");
        }

        carrierAggregation: CarrierAggregation {
            parameters:
                numComponentCarriers = 1;
                @display("p=800,10500;i=block/control,#FF8800;is=s");
        }

        routingRecorder: RoutingTableRecorder {
            parameters:
                @display("p=800,11500;i=block/table,#888888;is=s");
        }

        // =================================================================
        // 5G CORE NETWORK
        // Logical layout: Server -- Router -- UPF (top-center, north edge)
        // Positioned above the road network for a clean backhaul topology
        // =================================================================

        server: StandardHost {
            parameters:
                @display("p=13500,1200;i=device/server2,#0066CC;is=l");
        }

        router: Router {
            parameters:
                @display("p=10500,1200;i=abstract/router,#0088DD;is=l");
        }

        upf: Upf {
            parameters:
                @display("p=7500,1200;i=abstract/switch,#FF8800;is=l");
        }

        // =================================================================
        // 5G NR gNODEB BASE STATIONS
        // 5 gNodeBs covering Al-Jubail Industrial City:
        //   gnb[0]: Southwest  (3500, 4000)
        //   gnb[1]: Southeast  (11000, 4000)
        //   gnb[2]: Center     (7500, 8000)
        //   gnb[3]: Northwest  (3500, 12000)
        //   gnb[4]: Northeast  (11000, 12000)
        //
        // Positions here match the INI mobility.initialX/Y values.
        // Each gNodeB shows a 2000m cell-radius coverage ring.
        // =================================================================

        gnb[numGNodeBs]: gNodeB {
            parameters:
                @display("i=device/antennatower,#FF6600;is=l;r=2000,#FF880033,2");
        }

        // =================================================================
        // RSUs WITH DP-IDS-VNDN FRAMEWORK
        // 5 RSUs deployed on the Al-Jubail map:
        //   rsu[0]: Southwest  (3361, 3690)
        //   rsu[1]: Southeast  (10083, 3690)
        //   rsu[2]: Center     (6722, 7380)
        //   rsu[3]: Northwest  (3361, 11070)
        //   rsu[4]: Northeast  (10083, 11070)
        //
        // Positions are set via mobility.x/y in the INI file.
        // Each RSU shows a 500m communication-range ring.
        // =================================================================

        rsu[numRSU]: VndnRSU {
            parameters:
                nodeId = index + 1000;

                // NDN tables (larger for RSUs)
                pitMaxSize = 5000;
                csMaxSize = 500;

                // Legacy IDS
                hasIDSModule = parent.enableIDS;
                idsDetectionMethod = parent.idsDetectionMethod;
                idsDetectionThreshold = parent.idsThreshold;
                idsLogging = parent.idsLogging;

                // DP-IDS-VNDN Framework (Section 4)
                hasDPIDSModule = parent.enableDPIDS;
                dpidsOrchestrationInterval = parent.dpidsOrchestrationInterval;
                dpidsBeliefThreshold = parent.dpidsBeliefThreshold;
                dpidsEnablePenalization = parent.dpidsEnablePenalization;
                dpidsKMax = parent.dpidsKMax;
                dpidsReliabilityBehavioural = parent.dpidsReliabilityBehavioural;
                dpidsReliabilityForwarding = parent.dpidsReliabilityForwarding;
                dpidsThetaCS = parent.dpidsThetaCS;
                dpidsThetaPIT = parent.dpidsThetaPIT;
                dpidsThetaFIB = parent.dpidsThetaFIB;

                nic.phy80211p.transmitPower = 40mW;
                nic.phy80211p.sensitivity = -95dBm;

                @display("i=device/antennatower,#CC0000,50;is=l;r=500,#FF444488,2");
        }

        // =================================================================
        // VEHICLES (dynamically created by VeinsInetManager/SUMO)
        // =================================================================
        vehicle[0]: VndnNRVehicle {
            @display("i=veins/node/car");
        }

    connections allowunconnected:
        // =================================================================
        // 5G CORE NETWORK BACKHAUL
        // Server <-> Router <-> UPF <-> gNodeBs
        // =================================================================
        server.pppg++ <--> Eth10G <--> router.pppg++;
        router.pppg++ <--> Eth10G <--> upf.filterGate;
        upf.pppg++ <--> Eth10G <--> gnb[0].ppp;
        upf.pppg++ <--> Eth10G <--> gnb[1].ppp if numGNodeBs > 1;
        upf.pppg++ <--> Eth10G <--> gnb[2].ppp if numGNodeBs > 2;
        upf.pppg++ <--> Eth10G <--> gnb[3].ppp if numGNodeBs > 3;
        upf.pppg++ <--> Eth10G <--> gnb[4].ppp if numGNodeBs > 4;

        // =================================================================
        // X2 INTER-gNODEB CONNECTIONS (handover support)
        // =================================================================
        gnb[0].x2++ <--> Eth10G <--> gnb[1].x2++ if numGNodeBs > 1;
        gnb[1].x2++ <--> Eth10G <--> gnb[2].x2++ if numGNodeBs > 2;
        gnb[2].x2++ <--> Eth10G <--> gnb[3].x2++ if numGNodeBs > 3;
        gnb[3].x2++ <--> Eth10G <--> gnb[4].x2++ if numGNodeBs > 4;
}
