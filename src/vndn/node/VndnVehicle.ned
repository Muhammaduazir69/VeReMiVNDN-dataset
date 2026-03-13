//
// VeReMiVNDN - VNDN Vehicle Node
// Compound module with NDN + Vehicle logic + VEINS integration + IDS
//

package veremivndn.vndn.node;

import veremivndn.ndn.core.NdnNode;
import veremivndn.ids.detection.IDSModule;
import veremivndn.ids.features.FeatureExtractor;
import veremivndn.ids.logging.DataCollector;
import veremivndn.attacks.IAttackModule;
import org.car2x.veins.modules.nic.Nic80211p;
import org.car2x.veins.modules.mobility.traci.TraCIMobility;

module VndnVehicle
{
    parameters:
        // Node identification
        int nodeId;
        string vehicleId = default("");

        // VNDN specific
        bool isContentProducer = default(false);
        string producedPrefixes = default("");

        // Communication parameters
        double beaconInterval @unit(s) = default(0.1s);

        // NDN parameters
        int pitMaxSize = default(1000);
        int fibMaxSize = default(500);
        int csMaxSize = default(100);

        // VEINS parameters
        string nicType = default("Nic80211p");
        string mobilityType = default("TraCIMobility");

        // IDS parameters
        bool hasIDSModule = default(false);
        string idsDetectionMethod = default("Hybrid");
        double idsDetectionThreshold = default(0.7);
        bool idsLogging = default(true);

        // Attack parameters
        bool hasAttackModule = default(false);
        string attackType = default("");
        string attackModuleType = default("veremivndn.attacks.AttackModule");  // Dynamic type selection
        double attackStartTime @unit(s) = default(0s);
        double attackDuration @unit(s) = default(0s);
        double attackIntensity = default(0.5);
        string attackParameters = default("");

        @display("i=veins/node/car;is=vs");
        @node;

    gates:
        input veinsRadioIn @directIn;

    submodules:
        // Mobility module (SUMO/TraCI integration)
        mobility: <mobilityType> like org.car2x.veins.base.modules.IMobility {
            @display("p=300,350;i=block/cogwheel");
        }

        // Network Interface Card (802.11p wireless)
        nic: <nicType> like org.car2x.veins.modules.nic.INic80211p {
            @display("p=300,250");
        }

        // Vehicle application controller
        controller: VehicleController {
            vehicleId = parent.vehicleId;
            isContentProducer = parent.isContentProducer;
            producedPrefixes = parent.producedPrefixes;
            beaconInterval = parent.beaconInterval;
            @display("p=150,100");
        }

        // NDN protocol stack
        ndnNode: NdnNode {
            nodeId = parent.nodeId;
            nodeType = "Vehicle";
            pitMaxSize = parent.pitMaxSize;
            fibMaxSize = parent.fibMaxSize;
            csMaxSize = parent.csMaxSize;
            hasIDSModule = parent.hasIDSModule;
            @display("p=450,100");
        }

        // IDS Module (conditional instantiation)
        idsModule: IDSModule if hasIDSModule {
            detectionMethod = parent.idsDetectionMethod;
            detectionThreshold = parent.idsDetectionThreshold;
            loggingEnabled = parent.idsLogging;
            @display("p=600,100;i=block/control");
        }

        // Feature Extractor (conditional instantiation)
        featureExtractor: FeatureExtractor if hasIDSModule {
            @display("p=600,200;i=block/table");
        }

        // Data Collector (conditional instantiation)
        dataCollector: DataCollector if hasIDSModule {
            @display("p=600,300;i=block/table2");
        }

        // Attack Module (conditional instantiation with dynamic type)
        attackModule: <attackModuleType> like IAttackModule if hasAttackModule {
            attackType = parent.attackType;
            startTime = parent.attackStartTime;
            duration = parent.attackDuration;
            intensity = parent.attackIntensity;
            attackParams = parent.attackParameters;
            @display("p=150,200;i=status/excl");
        }

    connections allowunconnected:
        // Radio gate to NIC
        veinsRadioIn --> nic.radioIn;

        // NIC to Controller (application layer)
        nic.upperLayerOut --> controller.lowerLayerIn;
        nic.upperLayerIn <-- controller.lowerLayerOut;
        nic.upperControlOut --> controller.lowerControlIn;
        nic.upperControlIn <-- controller.lowerControlOut;

        // Controller to NDN Node with Attack Module if enabled
        // IDS monitors via signals and timers, not by intercepting packets
        controller.ndnOut --> attackModule.ndnIn if hasAttackModule;
        attackModule.ndnOut --> ndnNode.ndnIn++ if hasAttackModule;
        ndnNode.ndnOut++ --> controller.ndnIn if hasAttackModule;

        // Direct connection when no attack module
        controller.ndnOut --> ndnNode.ndnIn++ if !hasAttackModule;
        ndnNode.ndnOut++ --> controller.ndnIn if !hasAttackModule;
}
