package veremivndn.dpids.fusion;

simple DSFusionEngine
{
    parameters:
        @class(veremivndn::DSFusionEngine);
        double kMax = default(0.8);
        double reliabilityBehavioural = default(0.85);
        double reliabilityForwarding = default(0.90);

        @signal[fusionBeliefMal](type=double);
        @signal[fusionConflict](type=double);
        @signal[extendedMonitoring](type=long);

        @statistic[fusionBeliefMal](record=vector,stats,histogram);
        @statistic[fusionConflict](record=vector,stats);
        @statistic[extendedMonitoring](record=count,vector);

        @display("i=block/join");
}
