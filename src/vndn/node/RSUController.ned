//
// VeReMiVNDN - RSU Controller
// Application logic for RSU with network integration
//

package veremivndn.vndn.node;

simple RSUController
{
    parameters:
        @class(veremivndn::RSUController);

        string producedPrefixes;
        double contentUpdateInterval @unit(s);
        double announceInterval @unit(s);

        @display("i=block/app");

    gates:
        // NDN gates
        input ndnIn;
        output ndnOut;

        // VEINS NIC layer gates
        input lowerLayerIn;
        output lowerLayerOut;
        input lowerControlIn;
        output lowerControlOut;
}
