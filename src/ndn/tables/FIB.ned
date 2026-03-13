//
// VeReMiVNDN - FIB NED Definition
//

package veremivndn.ndn.tables;

simple FIB
{
    parameters:
        @class(veremivndn::FIB);
        int maxSize = default(500);                     // Maximum FIB entries
        bool enableDynamicRouting = default(true);       // Enable dynamic routing
        double entryLifetime @unit(s) = default(0s);     // Entry lifetime (0 = infinite)
        double cleanupInterval @unit(s) = default(5s);   // Cleanup interval

        // Statistics
        @signal[fibSize](type=long);
        @signal[fibLookup](type=long);
        @signal[fibUpdate](type=long);

        @statistic[fibSize](record=vector,stats);
        @statistic[fibLookup](record=count,sum);
        @statistic[fibUpdate](record=count,sum);

        @display("i=block/table2");

    gates:
        input in @loose;
        output out @loose;
        input processorIn @loose;   // Control messages from NDNProcessor
        output processorOut @loose;  // Responses to NDNProcessor
}
