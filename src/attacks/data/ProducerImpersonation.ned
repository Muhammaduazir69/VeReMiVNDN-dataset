//
// VeReMiVNDN - Producer Impersonation Attack NED Definition
//

package veremivndn.attacks.data;

import veremivndn.attacks.AttackModule;

simple ProducerImpersonation extends AttackModule
{
    parameters:
        @class(veremivndn::ProducerImpersonation);
        @display("i=block/source");

        @signal[fakeDataProduced](type=long);
        @statistic[fakeDataProduced](title="Fake Data Produced"; record=vector,count,sum; interpolationmode=none);

        @signal[impersonationSuccess](type=long);
        @statistic[impersonationSuccess](title="Impersonation Success"; record=vector,count,sum; interpolationmode=none);

        @signal[authBypass](type=long);
        @statistic[authBypass](title="Authentication Bypassed"; record=vector,count,sum; interpolationmode=none);
}
