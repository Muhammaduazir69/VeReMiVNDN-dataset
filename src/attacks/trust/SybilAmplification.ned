//
// VeReMiVNDN - Sybil Amplification Attack Module
//

package veremivndn.attacks.trust;

import veremivndn.attacks.AttackModule;

simple SybilAmplification extends AttackModule
{
    parameters:
        @class(veremivndn::SybilAmplification);
        @display("i=block/segm");
}
