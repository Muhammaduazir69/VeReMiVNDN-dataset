package veremivndn.dpids.strategy;

simple AdaptiveForwardingStrategy
{
    parameters:
        @class(veremivndn::AdaptiveForwardingStrategy);
        double penalizationInterval @unit(s) = default(1s);
        double thetaCS = default(0.5);
        double thetaPIT = default(0.5);
        double thetaFIB = default(0.5);

        @signal[csPenalization](type=double);
        @signal[pitPenalization](type=double);
        @signal[fibPenalization](type=double);
        @signal[vehiclePenalized](type=long);

        @statistic[csPenalization](record=vector,stats);
        @statistic[pitPenalization](record=vector,stats);
        @statistic[fibPenalization](record=vector,stats);
        @statistic[vehiclePenalized](record=count,vector);

        @display("i=block/control");
}
