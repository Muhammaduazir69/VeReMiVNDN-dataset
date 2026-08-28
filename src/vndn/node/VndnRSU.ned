//
// VeReMiVNDN - RSU NED Definition
// Compound module with NDN + RSU logic + Network interface + IDS
//

package veremivndn.vndn.node;

import veremivndn.ndn.core.NdnNode;
import veremivndn.ids.detection.IDSModule;
import veremivndn.ids.features.FeatureExtractor;
import veremivndn.ids.logging.DataCollector;
import veremivndn.dpids.features.ForwardingPlaneFeatureExtractor;
import veremivndn.dpids.detectors.BehaviouralDetector;
import veremivndn.dpids.detectors.ForwardingPlaneDetector;
import veremivndn.dpids.fusion.DSFusionEngine;
import veremivndn.dpids.strategy.AdaptiveForwardingStrategy;
import veremivndn.dpids.controller.DPIDSController;
import veremivndn.dpids.evaluation.DPIDSMetrics;
import veremivndn.dpids.miids.MIIDSModule;
import veremivndn.trident.TridentController;
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

        // Stationary RSU position (read by the broadcast data plane, since the
        // RSU has no mobility submodule). Set per-instance in the .ini.
        double rsuPosX @unit(m) = default(0m);
        double rsuPosY @unit(m) = default(0m);

        // Canvas position, in playground metres, used only for drawing. The RSU
        // has no mobility submodule to publish a position to the display string,
        // so without these every rsu[i] would be auto-laid-out on top of the next.
        // Unitless on purpose: display strings substitute $dispX/$dispY verbatim.
        double dispX = default(0);
        double dispY = default(0);
        double rsuRange @unit(m) = default(1500m);

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

        // DP-IDS-VNDN parameters (Methodology Section 4)
        bool hasDPIDSModule = default(false);
        double dpidsOrchestrationInterval @unit(s) = default(1s);
        double dpidsBeliefThreshold = default(0.65);
        bool dpidsEnablePenalization = default(true);
        double dpidsKMax = default(0.8);
        double dpidsReliabilityBehavioural = default(0.85);
        double dpidsReliabilityForwarding = default(0.90);
        double dpidsThetaCS = default(0.5);
        double dpidsThetaPIT = default(0.5);
        double dpidsThetaFIB = default(0.5);

        // MI-IDS (VeReMiVNDN-EXE) parameters
        bool hasMIIDSModule = default(false);

        // TRIDENT-VNDN (Paper 3) parameters: closed-loop trust controller. The
        // controller reuses the DP-IDS detectors + DS fusion as its evidence
        // source, so hasDPIDSModule must also be true when hasTridentModule=true.
        bool hasTridentModule = default(false);
        double tridentControlInterval @unit(s) = default(1s);
        double tridentAlpha = default(0.40);
        double tridentBeta = default(0.05);
        double tridentTauQuarantine = default(0.40);
        double tridentTauReinstate = default(0.55);
        double tridentWindowQuarantine @unit(s) = default(10s);
        bool tridentEnableMitigation = default(true);

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

        // DP-IDS-VNDN Modules (conditional on hasDPIDSModule)
        fpFeatureExtractor: ForwardingPlaneFeatureExtractor if hasDPIDSModule {
            @display("p=750,100;i=block/cogwheel");
        }

        behaviouralDetector: BehaviouralDetector if hasDPIDSModule {
            @display("p=750,175;i=block/classifier");
        }

        forwardingDetector: ForwardingPlaneDetector if hasDPIDSModule {
            @display("p=750,250;i=block/classifier2");
        }

        fusionEngine: DSFusionEngine if hasDPIDSModule {
            kMax = parent.dpidsKMax;
            reliabilityBehavioural = parent.dpidsReliabilityBehavioural;
            reliabilityForwarding = parent.dpidsReliabilityForwarding;
            @display("p=750,325;i=block/join");
        }

        adaptiveStrategy: AdaptiveForwardingStrategy if hasDPIDSModule {
            thetaCS = parent.dpidsThetaCS;
            thetaPIT = parent.dpidsThetaPIT;
            thetaFIB = parent.dpidsThetaFIB;
            @display("p=750,400;i=block/control");
        }

        dpidsController: DPIDSController if hasDPIDSModule {
            orchestrationInterval = parent.dpidsOrchestrationInterval;
            beliefThreshold = parent.dpidsBeliefThreshold;
            enablePenalization = parent.dpidsEnablePenalization;
            @display("p=900,250;i=block/control,red");
        }

        dpidsMetrics: DPIDSMetrics if hasDPIDSModule {
            @display("p=900,350;i=block/table");
        }

        // MI-IDS module (VeReMiVNDN-EXE Section V): TorchScript per-plane
        // detectors, DST fusion, trust ODE, optional adversarial inference.
        miids: MIIDSModule if hasMIIDSModule {
            @display("p=1050,250;i=block/control,blue");
        }

        // TRIDENT-VNDN (Paper 3): closed-loop trust controller that turns the
        // belief stream into a continuous trust state and drives the three
        // reversible remediation prongs through adaptiveStrategy + TrustRegistry.
        tridentController: TridentController if hasTridentModule {
            controlInterval = parent.tridentControlInterval;
            alpha = parent.tridentAlpha;
            beta = parent.tridentBeta;
            tauQuarantine = parent.tridentTauQuarantine;
            tauReinstate = parent.tridentTauReinstate;
            windowQuarantine = parent.tridentWindowQuarantine;
            enableMitigation = parent.tridentEnableMitigation;
            @display("p=1050,400;i=block/control,#cc8800");
        }

    connections allowunconnected:
        // Radio gate to NIC
        radioIn --> nic.radioIn;

        // NIC to Controller (application layer)
        nic.upperLayerOut --> controller.lowerLayerIn;
        nic.upperLayerIn <-- controller.lowerLayerOut;
        nic.upperControlOut --> controller.lowerControlIn;
        nic.upperControlIn <-- controller.lowerControlOut;

        // ---- NDN application face (face 0): producer app <-> stack ----
        controller.ndnOut --> ndnNode.ndnIn++;
        ndnNode.ndnOut++ --> controller.ndnIn;

        // ---- NDN wire face (face 1): broadcast-medium side ----
        controller.wireOut --> ndnNode.ndnIn++;
        ndnNode.ndnOut++ --> controller.wireIn;
}
