//
// VeReMiVNDN - Cache Timing Attack NED
//

package veremivndn.attacks.privacy;

import veremivndn.attacks.AttackModule;

simple CacheTimingAttack extends AttackModule
{
    parameters:
        @class(veremivndn::CacheTimingAttack);
        @display("i=block/tunnel");

        @signal[probesSent](type=long);
        @signal[cacheHitDetected](type=long);
        @signal[privacyViolation](type=long);

        @statistic[probesSent](title="Probes Sent"; record=count,vector);
        @statistic[cacheHitDetected](title="Cache Hits Detected"; record=count,vector);
        @statistic[privacyViolation](title="Privacy Violations"; record=count,vector);
}
