package veremivndn.attacks.forwarding;

import veremivndn.attacks.AttackModule;

simple PITFloodingAttack extends AttackModule
{
    parameters:
        @class(veremivndn::PITFloodingAttack);

        @signal[unsatisfiableInterests](type=long);
        @statistic[unsatisfiableInterests](record=count,vector);

        @display("i=block/arrival");
}
