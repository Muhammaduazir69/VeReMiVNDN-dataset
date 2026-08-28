package veremivndn.dpids.evaluation;

simple DPIDSMetrics
{
    parameters:
        @class(veremivndn::DPIDSMetrics);
        double metricsInterval @unit(s) = default(5s);

        @signal[interestSatisfactionRate](type=double);
        @signal[csPoisoningExposureTime](type=double);
        @signal[fibHijackDetectionLatency](type=double);
        @signal[communicationOverhead](type=double);
        @signal[detectionAccuracy](type=double);
        @signal[detectionPrecision](type=double);
        @signal[detectionRecall](type=double);
        @signal[detectionF1](type=double);

        @statistic[interestSatisfactionRate](record=vector,stats);
        @statistic[csPoisoningExposureTime](record=vector,stats);
        @statistic[fibHijackDetectionLatency](record=vector,stats);
        @statistic[communicationOverhead](record=vector,stats);
        @statistic[detectionAccuracy](record=vector,stats);
        @statistic[detectionPrecision](record=vector,stats);
        @statistic[detectionRecall](record=vector,stats);
        @statistic[detectionF1](record=vector,stats);

        @display("i=block/table");
}
