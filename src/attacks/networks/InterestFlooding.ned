//
// VeReMiVNDN - Interest Flooding Attack Module
//

package veremivndn.attacks.networks;

import veremivndn.attacks.AttackModule;

simple InterestFlooding extends AttackModule
{
    parameters:
        @class(veremivndn::InterestFlooding);
        @display("i=block/arrival");

        @signal[floodingRequest](type=long);
        @statistic[floodingRequest](title="Flooding Requests"; record=count,vector);
}
