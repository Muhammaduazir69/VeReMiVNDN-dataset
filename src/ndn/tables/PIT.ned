//
// VeReMiVNDN - PIT NED Definition
//

package veremivndn.ndn.tables;

simple PIT
{
    parameters:
        @class(veremivndn::PIT);
        int maxSize = default(1000);                    // Maximum PIT entries
        double defaultLifetime @unit(s) = default(4s);  // Default interest lifetime
        bool enableAggregation = default(true);         // Enable interest aggregation
        double cleanupInterval @unit(s) = default(1s);  // Cleanup interval

        // Statistics
        @signal[pitSize](type=long);
        @signal[pitOccupancy](type=double);
        @signal[pitExpired](type=long);
        @signal[pitSatisfied](type=long);

        @statistic[pitSize](record=vector,stats);
        @statistic[pitOccupancy](record=vector,stats);
        @statistic[pitExpired](record=count,sum);
        @statistic[pitSatisfied](record=count,sum);

        @display("i=block/table");

    gates:
        input in @loose;
        output out @loose;
        input processorIn @loose;   // Control messages from NDNProcessor
        output processorOut @loose;  // Responses to NDNProcessor
}
