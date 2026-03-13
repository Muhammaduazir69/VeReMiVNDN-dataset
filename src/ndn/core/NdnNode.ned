//
// VeReMiVNDN - Base NDN Node Definition
// Compound module with NDNProcessor + PIT/FIB/CS
//

package veremivndn.ndn.core;

import veremivndn.ndn.core.NDNProcessor;
import veremivndn.ndn.tables.PIT;
import veremivndn.ndn.tables.FIB;
import veremivndn.ndn.tables.CS;

module NdnNode
{
    parameters:
        // Node identification
        int nodeId;
        string nodeType = default("ndn");

        // NDN configuration
        int pitMaxSize = default(1000);
        int fibMaxSize = default(500);
        int csMaxSize = default(100);
        string forwardingStrategy = default("BestRoute");

        // Cache configuration
        string cacheReplacementPolicy = default("LRU");
        bool enableCaching = default(true);

        // Security configuration
        bool enableSignatureVerification = default(true);
        double signatureVerificationDelay @unit(ms) = default(1ms);

        // IDS integration flag (passed from parent)
        bool hasIDSModule = default(false);

        @display("i=abstract/router;bgb=700,500");

    gates:
        input ndnIn[] @loose;
        output ndnOut[] @loose;

    submodules:
        processor: NDNProcessor {
            nodeId = parent.nodeId;
            nodeType = parent.nodeType;
            enableCaching = parent.enableCaching;
            enableSignatureVerification = parent.enableSignatureVerification;
            signatureVerificationDelay = parent.signatureVerificationDelay;
            forwardingStrategy = parent.forwardingStrategy;
            @display("p=350,250");
        }

        pit: PIT {
            maxSize = parent.pitMaxSize;
            @display("p=200,150");
        }

        fib: FIB {
            maxSize = parent.fibMaxSize;
            @display("p=350,150");
        }

        cs: CS {
            maxSize = parent.csMaxSize;
            enabled = parent.enableCaching;
            replacementPolicy = parent.cacheReplacementPolicy;
            @display("p=500,150");
        }

    connections allowunconnected:
        // Connect processor to PIT/FIB/CS
        processor.pitOut --> pit.processorIn;
        pit.processorOut --> processor.pitIn;

        processor.fibOut --> fib.processorIn;
        fib.processorOut --> processor.fibIn;

        processor.csOut --> cs.processorIn;
        cs.processorOut --> processor.csIn;

        // Connect external gates to processor
        for i=0..sizeof(ndnIn)-1 {
            ndnIn[i] --> processor.ndnIn++;
        }

        for i=0..sizeof(ndnOut)-1 {
            processor.ndnOut++ --> ndnOut[i];
        }
}
