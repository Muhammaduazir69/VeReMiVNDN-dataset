package veremivndn.dpids.features;

simple ForwardingPlaneFeatureExtractor
{
    parameters:
        @class(veremivndn::ForwardingPlaneFeatureExtractor);
        double extractionInterval @unit(s) = default(1s);
        double ewmaAlpha = default(0.1);
        int minSamples = default(5);
        double csHitDriftMax = default(1.0);
        double pitGrowthRateMax = default(100.0);
        double fibDivergenceMax = default(1.0);
        double communicationRange @unit(m) = default(500m);
        double pitThresholdK = default(2.0);  // k for PIT anomaly: P_dot > mean + k*stddev

        @signal[csHitRateDrift](type=double);
        @signal[pitEntryGrowthRate](type=double);
        @signal[fibRouteDivergence](type=double);

        @statistic[csHitRateDrift](record=vector,stats);
        @statistic[pitEntryGrowthRate](record=vector,stats);
        @statistic[fibRouteDivergence](record=vector,stats);

        @display("i=block/cogwheel");
}
