//
// VeReMiVNDN - Cache Partitioning Attack NED Definition
//

package veremivndn.attacks.caching;

import veremivndn.attacks.AttackModule;

simple CachePartitioning extends AttackModule
{
    parameters:
        @class(veremivndn::CachePartitioning);
        @display("i=block/segm");

        @signal[relaysControlled](type=long);
        @statistic[relaysControlled](title="Relays Controlled"; record=vector,count,sum; interpolationmode=none);

        @signal[accessDenials](type=long);
        @statistic[accessDenials](title="Access Denials"; record=vector,count,sum; interpolationmode=none);

        @signal[partitionStrength](type=double);
        @statistic[partitionStrength](title="Partition Strength"; record=vector,mean; interpolationmode=sample-hold);
}
