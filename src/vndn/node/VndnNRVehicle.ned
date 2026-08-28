//
// VeReMiVNDN - 5G NR Vehicle with NDN + IDS + Attack
//
// Extends Simu5G's NRCar (NRNicUe + VeinsInetMobility) and adds:
//   - NDN protocol stack (PIT/FIB/CS + NDNProcessor)
//   - Vehicle application controller (Interest generation, content request)
//   - DP-IDS attack module (conditional)
//   - IDS module (conditional)
//
// This provides full dual-stack: 5G NR cellular + NDN overlay
// with SINR, throughput, latency metrics from Simu5G
//

package veremivndn.vndn.node;

// Simu5G NR car (includes NRNicUe + VeinsInetMobility + IPv4 + UDP/TCP)
import simu5g.nodes.cars.NRCar;

// NDN stack
import veremivndn.ndn.core.NdnNode;

// IDS
import veremivndn.ids.detection.IDSModule;
import veremivndn.ids.features.FeatureExtractor;
import veremivndn.ids.logging.DataCollector;

// Attacks
import veremivndn.attacks.IAttackModule;

module VndnNRVehicle extends NRCar
{
    parameters:
        // Mobility is already VeinsInetMobility from NRCar parent
        // cellularNic is already NRNicUe from NRUe parent

        // Node identification
        int nodeId = default(0);
        string vehicleId = default("");

        // VNDN specific
        bool isContentProducer = default(false);
        string producedPrefixes = default("");
        double beaconInterval @unit(s) = default(0.1s);

        // NDN parameters
        int pitMaxSize = default(1000);
        int fibMaxSize = default(500);
        int csMaxSize = default(100);
        string forwardingStrategy = default("BestRoute");
        string cacheReplacementPolicy = default("LRU");
        bool enableCaching = default(true);
        bool enableSignatureVerification = default(true);
        double signatureVerificationDelay @unit(ms) = default(1ms);
        double communicationRange @unit(m) = default(500m);
        double initialTrustScore = default(1.0);
        bool useTrustModel = default(true);

        // IDS parameters
        bool hasIDSModule = default(false);
        string idsDetectionMethod = default("Hybrid");
        double idsDetectionThreshold = default(0.7);
        bool idsLogging = default(true);

        // Attack parameters
        bool hasAttackModule = default(false);
        string attackType = default("");
        string attackModuleType = default("veremivndn.attacks.AttackModule");
        double attackStartTime @unit(s) = default(0s);
        double attackDuration @unit(s) = default(0s);
        double attackIntensity = default(0.5);
        string attackParameters = default("");

        @display("i=veins/node/car;is=vs");

    submodules:
        // Vehicle application controller (Interest generation, beacons)
        controller: VehicleController {
            vehicleId = parent.vehicleId;
            isContentProducer = parent.isContentProducer;
            producedPrefixes = parent.producedPrefixes;
            beaconInterval = parent.beaconInterval;
            @display("p=700,100;i=block/app");
        }

        // NDN protocol stack (PIT/FIB/CS + processor)
        ndnNode: NdnNode {
            nodeId = parent.nodeId;
            nodeType = "Vehicle";
            pitMaxSize = parent.pitMaxSize;
            fibMaxSize = parent.fibMaxSize;
            csMaxSize = parent.csMaxSize;
            enableCaching = parent.enableCaching;
            enableSignatureVerification = parent.enableSignatureVerification;
            signatureVerificationDelay = parent.signatureVerificationDelay;
            hasIDSModule = parent.hasIDSModule;
            @display("p=900,100;i=abstract/router");
        }

        // IDS Module (conditional)
        idsModule: IDSModule if hasIDSModule {
            detectionMethod = parent.idsDetectionMethod;
            detectionThreshold = parent.idsDetectionThreshold;
            loggingEnabled = parent.idsLogging;
            @display("p=1100,100;i=block/control");
        }

        featureExtractor: FeatureExtractor if hasIDSModule {
            @display("p=1100,200;i=block/table");
        }

        dataCollector: DataCollector if hasIDSModule {
            @display("p=1100,300;i=block/table2");
        }

        // Attack Module (conditional, dynamic type)
        attackModule: <attackModuleType> like IAttackModule if hasAttackModule {
            attackType = parent.attackType;
            startTime = parent.attackStartTime;
            duration = parent.attackDuration;
            intensity = parent.attackIntensity;
            attackParams = parent.attackParameters;
            @display("p=700,250;i=status/excl,red");
        }

    connections allowunconnected:
        // Controller to NDN Node with Attack Module if enabled
        controller.ndnOut --> attackModule.ndnIn if hasAttackModule;
        attackModule.ndnOut --> ndnNode.ndnIn++ if hasAttackModule;
        ndnNode.ndnOut++ --> controller.ndnIn if hasAttackModule;

        // Direct connection when no attack module
        controller.ndnOut --> ndnNode.ndnIn++ if !hasAttackModule;
        ndnNode.ndnOut++ --> controller.ndnIn if !hasAttackModule;
}
