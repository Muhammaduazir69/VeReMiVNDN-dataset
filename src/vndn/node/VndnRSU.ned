//
// VeReMiVNDN - RSU NED Definition
// Compound module with NDN + RSU logic + Network interface + IDS
//

package veremivndn.vndn.node;

import veremivndn.ndn.core.NdnNode;
import veremivndn.ids.detection.IDSModule;
import veremivndn.ids.features.FeatureExtractor;
import veremivndn.ids.logging.DataCollector;
import org.car2x.veins.modules.nic.Nic80211p;

module VndnRSU
{
    parameters:
        // Node identification
        int nodeId;

        // RSU specific
        string producedPrefixes = default("/traffic,/safety,/info");
        double contentUpdateInterval @unit(s) = default(1s);
        double announceInterval @unit(s) = default(5s);

        // NDN parameters (passed to ndnNode)
        int pitMaxSize = default(5000);
        int fibMaxSize = default(2000);
        int csMaxSize = default(1000);

        // Network parameters
        string nicType = default("Nic80211p");

        // IDS parameters
        bool hasIDSModule = default(false);
        string idsDetectionMethod = default("Hybrid");
        double idsDetectionThreshold = default(0.7);
        bool idsLogging = default(true);

        @display("i=device/antennatower;is=vl");
        @node;

    gates:
        input radioIn @directIn;

    submodules:
        // Network Interface Card (802.11p wireless)
        nic: <nicType> like org.car2x.veins.modules.nic.INic80211p {
            @display("p=300,300");
        }

        controller: RSUController {
            producedPrefixes = parent.producedPrefixes;
            contentUpdateInterval = parent.contentUpdateInterval;
            announceInterval = parent.announceInterval;
            @display("p=150,150");
        }

        ndnNode: NdnNode {
            nodeId = parent.nodeId;
            nodeType = "RSU";
            pitMaxSize = parent.pitMaxSize;
            fibMaxSize = parent.fibMaxSize;
            csMaxSize = parent.csMaxSize;
            hasIDSModule = parent.hasIDSModule;
            @display("p=450,150");
        }

        // IDS Module (conditional instantiation)
        idsModule: IDSModule if hasIDSModule {
            detectionMethod = parent.idsDetectionMethod;
            detectionThreshold = parent.idsDetectionThreshold;
            loggingEnabled = parent.idsLogging;
            @display("p=600,150;i=block/control");
        }

        // Feature Extractor (conditional instantiation)
        featureExtractor: FeatureExtractor if hasIDSModule {
            @display("p=600,250;i=block/table");
        }

        // Data Collector (conditional instantiation)
        dataCollector: DataCollector if hasIDSModule {
            @display("p=600,350;i=block/table2");
        }

    connections allowunconnected:
        // Radio gate to NIC
        radioIn --> nic.radioIn;

        // NIC to Controller (application layer)
        nic.upperLayerOut --> controller.lowerLayerIn;
        nic.upperLayerIn <-- controller.lowerLayerOut;
        nic.upperControlOut --> controller.lowerControlIn;
        nic.upperControlIn <-- controller.lowerControlOut;

        // Controller to NDN Node (direct connection - IDS monitors via signals)
        controller.ndnOut --> ndnNode.ndnIn++;
        ndnNode.ndnOut++ --> controller.ndnIn;
}
