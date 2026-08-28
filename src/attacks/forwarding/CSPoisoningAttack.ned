package veremivndn.attacks.forwarding;

import veremivndn.attacks.AttackModule;

simple CSPoisoningAttack extends AttackModule
{
    parameters:
        @class(veremivndn::CSPoisoningAttack);

        @signal[contentReplaced](type=long);
        @statistic[contentReplaced](record=count,vector);

        @display("i=block/decrypt");
}
