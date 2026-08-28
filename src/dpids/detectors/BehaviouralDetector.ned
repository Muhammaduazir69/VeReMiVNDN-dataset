package veremivndn.dpids.detectors;

simple BehaviouralDetector
{
    parameters:
        @class(veremivndn::BehaviouralDetector);
        double detectionInterval @unit(s) = default(1s);
        double positionDeviationThreshold = default(50.0);   // meters
        double speedDeviationThreshold = default(15.0);      // m/s
        double idrThreshold = default(0.3);
        double communicationRange @unit(m) = default(500m);

        // LSTM model configuration (Section 4.3.1)
        string modelPath = default("");  // Path to LSTM weights directory

        @signal[behaviouralScore](type=double);
        @statistic[behaviouralScore](record=vector,stats,histogram);

        @display("i=block/classifier");
}
