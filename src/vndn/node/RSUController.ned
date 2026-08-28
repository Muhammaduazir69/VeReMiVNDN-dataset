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
        // NDN application face (face 0): controller <-> ndnNode (producer app).
        input ndnIn;
        output ndnOut;

        // NDN wire face (face 1): broadcast-medium side of the forwarder.
        input wireIn;
        output wireOut;

        // VEINS NIC layer gates
        input lowerLayerIn;
        output lowerLayerOut;
        input lowerControlIn;
        output lowerControlOut;

        // Over-the-air broadcast medium: sendDirect frames from neighbours.
        input directIn @directIn;
}
