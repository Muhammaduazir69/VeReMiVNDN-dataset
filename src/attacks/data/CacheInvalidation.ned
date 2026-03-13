//
// VeReMiVNDN - Cache Invalidation Attack NED Definition
//

package veremivndn.attacks.data;

import veremivndn.attacks.AttackModule;

simple CacheInvalidation extends AttackModule
{
    parameters:
        @class(veremivndn::CacheInvalidation);
        @display("i=block/cache");

        @signal[versionsPublished](type=long);
        @statistic[versionsPublished](title="Versions Published"; record=vector,count,sum; interpolationmode=none);

        @signal[invalidationsSent](type=long);
        @statistic[invalidationsSent](title="Invalidations Sent"; record=vector,count,sum; interpolationmode=none);

        @signal[cacheChurn](type=long);
        @statistic[cacheChurn](title="Cache Churn Events"; record=vector,count,sum; interpolationmode=none);
}
