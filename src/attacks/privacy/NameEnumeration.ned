//
// VeReMiVNDN - Name Enumeration Attack NED Definition
//

package veremivndn.attacks.privacy;

import veremivndn.attacks.AttackModule;

simple NameEnumeration extends AttackModule
{
    parameters:
        @class(veremivndn::NameEnumeration);
        @display("i=block/search");

        @signal[namesProbed](type=long);
        @statistic[namesProbed](title="Names Probed"; record=vector,count,sum; interpolationmode=none);

        @signal[namesDiscovered](type=long);
        @statistic[namesDiscovered](title="Names Discovered"; record=vector,count,sum; interpolationmode=none);

        @signal[popularContent](type=long);
        @statistic[popularContent](title="Popular Content Identified"; record=vector,count,sum; interpolationmode=none);

        @signal[privacyCrawl](type=long);
        @statistic[privacyCrawl](title="Privacy Crawl Events"; record=vector,count,sum; interpolationmode=none);
}
