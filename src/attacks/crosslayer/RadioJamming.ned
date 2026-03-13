//
// VeReMiVNDN - Radio Jamming Attack NED Definition
//

package veremivndn.attacks.crosslayer;

import veremivndn.attacks.AttackModule;

simple RadioJamming extends AttackModule
{
    parameters:
        @class(veremivndn::RadioJamming);
        @display("i=block/wireless");

        @signal[packetsJammed](type=long);
        @statistic[packetsJammed](title="Packets Jammed"; record=vector,count,sum; interpolationmode=none);

        @signal[jammingPower](type=double);
        @statistic[jammingPower](title="Jamming Power (dBm)"; record=vector,mean,max; interpolationmode=sample-hold);

        @signal[channelOccupancy](type=long);
        @statistic[channelOccupancy](title="Channel Occupancy"; record=vector,mean; interpolationmode=sample-hold);
}
