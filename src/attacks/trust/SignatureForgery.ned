//
// VeReMiVNDN - Signature Forgery Attack NED Definition
//

package veremivndn.attacks.trust;

import veremivndn.attacks.AttackModule;

simple SignatureForgery extends AttackModule
{
    parameters:
        @display("i=block/control");
        @class(veremivndn::SignatureForgery);

        // Statistics
        @signal[signaturesForged](type=long);
        @statistic[signaturesForged](title="Signatures Forged"; record=vector,count,sum; interpolationmode=none);

        @signal[verificationFailures](type=long);
        @statistic[verificationFailures](title="Verification Failures"; record=vector,count,sum; interpolationmode=none);

        @signal[fakeAuthenticPackets](type=long);
        @statistic[fakeAuthenticPackets](title="Fake Authentic Packets"; record=vector,count,sum; interpolationmode=none);
}
