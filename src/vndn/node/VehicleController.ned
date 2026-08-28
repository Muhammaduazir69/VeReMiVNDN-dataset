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

        // ---- VeReMiVNDN-EXE content model and forwarding role ----
        //
        // The published scenario gave every request a globally unique name and
        // let only producers act on overheard Interests. Both choices make the
        // caching and forwarding planes unobservable: a Content Store can never
        // hit, so cache pollution and cache-timing side channels have nothing to
        // perturb, and a gray hole has nothing to drop. The parameters below
        // restore a realistic content catalogue and an explicit relay role.

        // Vehicles relay overheard Interests for other nodes. Without this, a
        // Selective Forwarding attacker is never on anybody's forwarding path.
        bool isForwarder = default(false);

        // Shared content catalogue. Consumers draw names from a Zipf-popular
        // catalogue so that repeat requests are possible and the Content Store
        // can actually serve them.
        int    catalogSize        = default(200);
        double catalogZipfAlpha   = default(0.9);
        // Fraction of requests that use a globally unique name. These are the
        // safety events that are genuinely one-off, and they keep the Interest
        // Satisfaction Ratio honest by guaranteeing some non-cacheable demand.
        double uniqueNameFraction = default(0.25);
        // Maximum relay hops for an overheard Interest (broadcast-storm guard).
        int    maxRelayHops       = default(3);

        // ---- TrustNet position-falsification (VeReMi taxonomy) ----
        // posAttackType: 0 benign, 1 ConstantPosition, 2 ConstantOffset,
        //                4 RandomPosition, 8 RandomOffset, 16 EventualStop.
        // posAttackerDensity: fraction of vehicles (by index) that become
        //                attackers of posAttackType in this run.
        int posAttackType = default(0);
        double posAttackerDensity = default(0.0);

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
        // NDN application face (face 0): controller <-> ndnNode through attackModule.
        // The consumer app injects Interests here and receives satisfying Data here;
        // a producer/attacker receives Interests here and emits (possibly poisoned)
        // Data here, so the attackModule transforms it at packet level.
        input ndnIn;
        output ndnOut;

        // NDN wire face (face 1): the broadcast-medium side of the stack.
        // wireOut lifts frames received over the air into the local forwarder;
        // wireIn carries frames the forwarder dispatches toward the medium, which
        // the controller then broadcasts to neighbours.
        input wireIn;
        output wireOut;

        // VEINS NIC layer gates (loose for NR-only vehicles)
        input lowerLayerIn @loose;
        output lowerLayerOut @loose;
        input lowerControlIn @loose;
        output lowerControlOut @loose;

        // Over-the-air broadcast medium: sendDirect frames from neighbours.
        input directIn @directIn;
}
