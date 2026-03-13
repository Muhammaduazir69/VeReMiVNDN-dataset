package veremivndn.attacks.crosslayer;

import veremivndn.attacks.AttackModule;

simple SelectiveForwarding extends AttackModule
{
    parameters:
        @class(veremivndn::SelectiveForwarding);
        @display("i=block/control");

        @signal[packetDropped](type=long);
        @signal[packetDelayed](type=long);
        @signal[grayHoleActive](type=long);

        @statistic[packetDropped](title="Packets Dropped"; record=count,vector);
        @statistic[packetDelayed](title="Packets Delayed"; record=count,vector);
        @statistic[grayHoleActive](title="Gray Hole Active"; record=vector);
}
