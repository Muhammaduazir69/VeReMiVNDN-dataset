//
// VeReMiVNDN - IDS Module NED
//

package veremivndn.ids.detection;

simple IDSModule
{
    parameters:
        @class(veremivndn::IDSModule);
        string detectionMethod = default("Hybrid");  // Anomaly, Signature, Hybrid
        double detectionThreshold = default(0.7);
        bool loggingEnabled = default(true);
        bool realtimeDetection = default(true);

        double monitoringInterval @unit(s) = default(1s);
        double loggingInterval @unit(s) = default(5s);

        @signal[attackDetected](type=long);
        @signal[falsePositive](type=long);
        @signal[falseNegative](type=long);
        @signal[detectionAccuracy](type=double);
        @signal[confidence](type=double);

        @statistic[attackDetected](record=count,sum,vector);
        @statistic[detectionAccuracy](record=vector,stats);
        @statistic[confidence](record=vector,stats);

        @display("i=block/control");

    gates:
        input trafficIn @loose;
        output trafficOut @loose;
}
