//
// VeReMiVNDN - Intrusion Detection System Module
//

package veremivndn.security.ids;

simple IDS
{
    parameters:
        @class(veremivndn::IDS);
        @display("i=block/control");

        string detectionMethod = default("Hybrid");  // "Signature", "Anomaly", "Hybrid"
        double detectionThreshold = default(0.7);
        bool enableLogging = default(true);
        bool enableTrustModel = default(true);

        // Detection thresholds
        double interestFloodingRate = default(50.0);  // interests/sec
        double trustDecayFactor = default(0.3);
        double trustRecoveryRate = default(0.1);
        double anomalyThreshold = default(0.6);

        // Statistics
        @signal[attackDetected](type=long);
        @statistic[attackDetected](title="Attacks Detected"; source=attackDetected; record=vector,count,sum; interpolationmode=none);

        @signal[trustScore](type=double);
        @statistic[trustScore](title="Node Trust Score"; source=trustScore; record=vector,stats,histogram; interpolationmode=none);

        @signal[anomalyScore](type=double);
        @statistic[anomalyScore](title="Anomaly Score"; source=anomalyScore; record=vector,stats; interpolationmode=none);

    gates:
        input in;
        output out;
}
