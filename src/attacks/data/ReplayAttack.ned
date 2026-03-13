package veremivndn.attacks.data;

import veremivndn.attacks.AttackModule;

simple ReplayAttack extends AttackModule
{
    parameters:
        @class(veremivndn::ReplayAttack);
        @display("i=block/control");

        @signal[packetReplayed](type=long);
        @signal[packetCaptured](type=long);

        @statistic[packetReplayed](title="Packets Replayed"; record=count,vector);
        @statistic[packetCaptured](title="Packets Captured"; record=count,vector);
}
