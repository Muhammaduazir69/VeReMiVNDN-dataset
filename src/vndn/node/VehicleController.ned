//
// VeReMiVNDN - Vehicle Controller
// Application logic for Vehicle with VEINS integration
//

package veremivndn.vndn.node;

simple VehicleController
{
    parameters:
        @class(veremivndn::VehicleController);

        string vehicleId;
        bool isContentProducer;
        string producedPrefixes;
        double beaconInterval @unit(s);

        @display("i=block/app");

        // Signal declarations
        @signal[positionUpdate](type=double);
        @signal[speedChange](type=double);
        @signal[laneChange](type=long);
        @signal[neighborDiscovered](type=long);

        // Statistics
        @statistic[positionUpdate](source=positionUpdate; record=vector,stats);
        @statistic[speedChange](source=speedChange; record=vector,stats);
        @statistic[laneChange](source=laneChange; record=count);
        @statistic[neighborDiscovered](source=neighborDiscovered; record=count);

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
