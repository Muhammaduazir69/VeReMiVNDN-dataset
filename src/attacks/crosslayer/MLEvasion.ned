//
// VeReMiVNDN - ML Evasion Attack NED Definition
//

package veremivndn.attacks.crosslayer;

import veremivndn.attacks.AttackModule;

simple MLEvasion extends AttackModule
{
    parameters:
        @class(veremivndn::MLEvasion);
        @display("i=block/cogwheel");

        @signal[adversarialExamples](type=long);
        @statistic[adversarialExamples](title="Adversarial Examples Generated"; record=vector,count,sum; interpolationmode=none);

        @signal[evasionSuccess](type=long);
        @statistic[evasionSuccess](title="Successful Evasions"; record=vector,count,sum; interpolationmode=none);

        @signal[featurePerturbation](type=long);
        @statistic[featurePerturbation](title="Features Perturbated"; record=vector,count,sum; interpolationmode=none);
}
