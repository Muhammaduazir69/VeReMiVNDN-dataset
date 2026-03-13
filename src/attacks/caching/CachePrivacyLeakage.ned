//
// VeReMiVNDN - Cache Privacy Leakage Attack NED Definition
//

package veremivndn.attacks.caching;

import veremivndn.attacks.AttackModule;

simple CachePrivacyLeakage extends AttackModule
{
    parameters:
        @class(veremivndn::CachePrivacyLeakage);
        @display("i=block/table");

        @signal[snapshotsCollected](type=long);
        @statistic[snapshotsCollected](title="Cache Snapshots Collected"; record=vector,count,sum; interpolationmode=none);

        @signal[requestsLeaked](type=long);
        @statistic[requestsLeaked](title="Requests Leaked"; record=vector,count,sum; interpolationmode=none);

        @signal[privacyLeakage](type=long);
        @statistic[privacyLeakage](title="Privacy Leakage Events"; record=vector,count,sum; interpolationmode=none);
}
