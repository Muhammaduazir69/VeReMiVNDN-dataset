//
// VeReMiVNDN - Routing Information Flood Attack NED Definition
//

package veremivndn.attacks.networks;

import veremivndn.attacks.AttackModule;

simple RoutingInfoFlood extends AttackModule
{
    parameters:
        @class(veremivndn::RoutingInfoFlood);
        @display("i=block/routing");

        @signal[fibUpdatesFlooded](type=long);
        @statistic[fibUpdatesFlooded](title="FIB Updates Flooded"; record=vector,count,sum; interpolationmode=none);

        @signal[pitEntriesSpoofed](type=long);
        @statistic[pitEntriesSpoofed](title="PIT Entries Spoofed"; record=vector,count,sum; interpolationmode=none);

        @signal[fakeRoutes](type=long);
        @statistic[fakeRoutes](title="Fake Routes Advertised"; record=vector,count,sum; interpolationmode=none);

        @signal[controlOverload](type=long);
        @statistic[controlOverload](title="Control Plane Overload"; record=vector,count,sum; interpolationmode=none);
}
