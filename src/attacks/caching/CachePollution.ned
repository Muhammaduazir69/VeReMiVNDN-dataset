//
// VeReMiVNDN - Cache Pollution Attack Module
//

package veremivndn.attacks.caching;

import veremivndn.attacks.AttackModule;

simple CachePollution extends AttackModule
{
    parameters:
        @class(veremivndn::CachePollution);
        @display("i=block/buffer");

        @signal[pollutionRequest](type=long);
        @statistic[pollutionRequest](title="Pollution Requests"; source=pollutionRequest; record=count,sum,vector; interpolationmode=none);

        @signal[cacheFilled](type=long);
        @statistic[cacheFilled](title="Cache Fill Events"; source=cacheFilled; record=count,vector; interpolationmode=none);
}
