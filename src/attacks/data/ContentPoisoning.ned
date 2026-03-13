//
// VeReMiVNDN - Content Poisoning Attack Module
//

package veremivndn.attacks.data;

import veremivndn.attacks.AttackModule;

simple ContentPoisoning extends AttackModule
{
    parameters:
        @class(veremivndn::ContentPoisoning);
        @display("i=block/error");

        @signal[poisonedContent](type=long);
        @statistic[poisonedContent](title="Poisoned Content"; record=count,vector);
}
