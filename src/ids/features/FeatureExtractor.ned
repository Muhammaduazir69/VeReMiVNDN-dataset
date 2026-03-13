package veremivndn.ids.features;

simple FeatureExtractor
{
    parameters:
        @class(veremivndn::FeatureExtractor);
        @display("i=block/table");

        // Configuration
        double extractionInterval @unit(s) = default(1s);
        double timeWindowSize @unit(s) = default(10s);
        int maxHistorySize = default(100);
        bool enableRealTimeExtraction = default(true);

        // Signals
        @signal[featureExtraction](type=long);
        @signal[anomalyScore](type=double);

        @statistic[featureExtraction](title="Feature Extractions"; record=count,vector);
        @statistic[anomalyScore](title="Anomaly Score"; record=stats,vector);

    gates:
        input ndnIn @labels(NdnPacket);
        output ndnOut @labels(NdnPacket);
}
