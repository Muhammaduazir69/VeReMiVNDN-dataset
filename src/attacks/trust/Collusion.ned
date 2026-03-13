//
// VeReMiVNDN - Collusion Attack NED
//

package veremivndn.attacks.trust;

import veremivndn.attacks.AttackModule;

simple Collusion extends AttackModule
{
    parameters:
        @class(veremivndn::Collusion);
        @display("i=block/network2");

        @signal[coordinationMsg](type=long);
        @signal[synchronizedAction](type=long);
        @signal[amplification](type=long);

        @statistic[coordinationMsg](title="Coordination Messages"; record=count,vector);
        @statistic[synchronizedAction](title="Synchronized Actions"; record=count,vector);
        @statistic[amplification](title="Amplification Factor"; record=last,vector);
}
