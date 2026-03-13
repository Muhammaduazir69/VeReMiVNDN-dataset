//
// VeReMiVNDN - Privacy De-anonymization Attack NED Definition
//

package veremivndn.attacks.privacy;

import veremivndn.attacks.AttackModule;

simple PrivacyDeanonymization extends AttackModule
{
    parameters:
        @class(veremivndn::PrivacyDeanonymization);
        @display("i=block/user");

        @signal[namesCollected](type=long);
        @statistic[namesCollected](title="Names Collected"; record=vector,count,sum; interpolationmode=none);

        @signal[locationsInferred](type=long);
        @statistic[locationsInferred](title="Locations Inferred"; record=vector,count,sum; interpolationmode=none);

        @signal[profilesBuilt](type=long);
        @statistic[profilesBuilt](title="User Profiles Built"; record=vector,count,sum; interpolationmode=none);

        @signal[privacyViolations](type=long);
        @statistic[privacyViolations](title="Privacy Violations"; record=vector,count,sum; interpolationmode=none);
}
