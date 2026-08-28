package veremivndn.dpids.detectors;

simple ForwardingPlaneDetector
{
    parameters:
        @class(veremivndn::ForwardingPlaneDetector);
        double detectionInterval @unit(s) = default(1s);
        double csHitDriftThreshold = default(0.3);
        double pitGrowthThreshold = default(0.5);
        double fibDivergenceThreshold = default(0.3);

        // Isolation Forest parameters (Section 4.3.2)
        int numTrees = default(100);
        int sampleSize = default(256);
        string modelPath = default("");  // Path to IF model file

        @signal[forwardingScore](type=double);
        @signal[forwardingDetection](type=long);
        @statistic[forwardingScore](record=vector,stats,histogram);
        @statistic[forwardingDetection](record=count,vector);

        @display("i=block/classifier2");
}
