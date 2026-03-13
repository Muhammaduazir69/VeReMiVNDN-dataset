package veremivndn.attacks.networks;

import veremivndn.attacks.AttackModule;

simple NamePrefixHijacking extends AttackModule
{
    parameters:
        @class(veremivndn::NamePrefixHijacking);
        @display("i=block/control");

        @signal[prefixHijacked](type=long);
        @signal[interestIntercepted](type=long);
        @signal[bogusDataSent](type=long);

        @statistic[prefixHijacked](title="Hijacked Prefixes"; record=count,vector);
        @statistic[interestIntercepted](title="Intercepted Interests"; record=count,vector);
        @statistic[bogusDataSent](title="Bogus Data Sent"; record=count,vector);
}
