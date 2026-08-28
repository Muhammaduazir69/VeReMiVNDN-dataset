package veremivndn.attacks.forwarding;

import veremivndn.attacks.AttackModule;

simple FIBHijackingAttack extends AttackModule
{
    parameters:
        @class(veremivndn::FIBHijackingAttack);

        @signal[routesForged](type=long);
        @signal[trafficDiverted](type=long);
        @statistic[routesForged](record=count,vector);
        @statistic[trafficDiverted](record=count,vector);

        @display("i=block/routing");
}
