//
// VeReMiVNDN - Core NDN Processor
// Handles Interest/Data packet processing
//

package veremivndn.ndn.core;

simple NDNProcessor
{
    parameters:
        @class(veremivndn::NDNProcessor);

        // Node identification
        int nodeId;
        string nodeType = default("ndn");

        // Configuration
        bool enableCaching = default(true);
        bool enableSignatureVerification = default(true);
        double signatureVerificationDelay @unit(ms) = default(1ms);
        string forwardingStrategy = default("BestRoute");

        // Signals for metrics
        @signal[interestSent](type=long);
        @signal[interestReceived](type=long);
        @signal[dataSent](type=long);
        @signal[dataReceived](type=long);
        @signal[cacheHit](type=long);
        @signal[cacheMiss](type=long);
        @signal[nackSent](type=long);
        @signal[nackReceived](type=long);
        @signal[packetDropped](type=long);
        @signal[forwardingDelay](type=simtime_t);

        // Statistics
        @statistic[interestSent](title="Interest Packets Sent"; source=interestSent; record=count,vector; interpolationmode=none);
        @statistic[interestReceived](title="Interest Packets Received"; source=interestReceived; record=count,vector; interpolationmode=none);
        @statistic[dataSent](title="Data Packets Sent"; source=dataSent; record=count,vector; interpolationmode=none);
        @statistic[dataReceived](title="Data Packets Received"; source=dataReceived; record=count,vector; interpolationmode=none);
        @statistic[cacheHit](title="Cache Hits"; source=cacheHit; record=count,vector; interpolationmode=none);
        @statistic[cacheMiss](title="Cache Misses"; source=cacheMiss; record=count,vector; interpolationmode=none);
        @statistic[nackSent](title="NACK Packets Sent"; source=nackSent; record=count,vector; interpolationmode=none);
        @statistic[nackReceived](title="NACK Packets Received"; source=nackReceived; record=count,vector; interpolationmode=none);
        @statistic[packetDropped](title="Packets Dropped"; source=packetDropped; record=count,vector; interpolationmode=none);
        @statistic[forwardingDelay](title="Forwarding Delay"; source=forwardingDelay; record=stats,histogram,vector; interpolationmode=none);

        @display("i=block/process");

    gates:
        input pitIn;
        output pitOut;
        input fibIn;
        output fibOut;
        input csIn;
        output csOut;
        input ndnIn[];
        output ndnOut[];
}
