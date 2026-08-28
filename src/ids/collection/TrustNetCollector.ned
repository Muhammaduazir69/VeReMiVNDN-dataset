//
// VeReMiVNDN - TrustNet feature collector (NED)
//
package veremivndn.ids.collection;

simple TrustNetCollector
{
    parameters:
        @class(veremivndn::TrustNetCollector);
        string outputFile = default("results/trustnet.csv");
        int windowSize = default(20);          // W: beacons per sliding window
        int maxWindows = default(60);          // T: windows exported per vehicle
        double beaconInterval @unit(s) = default(0.1s);
        @display("i=block/table2,#1f77b4");
    gates:
}
