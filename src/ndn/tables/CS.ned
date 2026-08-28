//
// VeReMiVNDN - Content Store NED Definition
//

package veremivndn.ndn.tables;

simple CS
{
    parameters:
        @class(veremivndn::CS);
        int maxSize = default(100);  // MB
        bool enabled = default(true);
        string replacementPolicy = default("LRU");  // LRU, LFU, FIFO
        double cleanupInterval @unit(s) = default(5s);

        @signal[csSize](type=long);
        @signal[csHit](type=long);
        @signal[csMiss](type=long);
        @signal[csHitRatio](type=double);

        @statistic[csSize](record=vector,stats);
        @statistic[csHit](record=count,sum);
        @statistic[csMiss](record=count,sum);
        @statistic[csHitRatio](record=vector,stats);

        // DP-IDS monitoring signals
        @signal[csInsertionEvent](type=long);
        @signal[csEvictionEvent](type=long);

        @statistic[csInsertionEvent](record=count,vector);
        @statistic[csEvictionEvent](record=count,vector);

        @display("i=block/cache");

    gates:
        input in @loose;
        output out @loose;
        input processorIn @loose;   // Control messages from NDNProcessor
        output processorOut @loose;  // Responses to NDNProcessor
}
