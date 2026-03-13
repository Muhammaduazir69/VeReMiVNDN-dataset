//
// VeReMiVNDN - Interest Aggregation Attack NED Definition
//

package veremivndn.attacks.networks;

import veremivndn.attacks.AttackModule;

simple InterestAggregation extends AttackModule
{
    parameters:
        @class(veremivndn::InterestAggregation);
        @display("i=block/network");

        @signal[interestsCrafted](type=long);
        @statistic[interestsCrafted](title="Interests Crafted"; record=vector,count,sum; interpolationmode=none);

        @signal[aggregationPrevented](type=long);
        @statistic[aggregationPrevented](title="Aggregations Prevented"; record=vector,count,sum; interpolationmode=none);

        @signal[pitImbalance](type=long);
        @statistic[pitImbalance](title="PIT Imbalance Events"; record=vector,count,sum; interpolationmode=none);
}
