//
// TRIDENT-VNDN - Global Trust Registry
//
// A single network-wide blackboard that holds the live trust state T_v(t) and
// the quarantine set produced by the TridentController(s). The data plane reads
// it on every hop: a vehicle drops frames whose stamped senderId belongs to a
// quarantined node (in-network isolation), and forwarders/caches consult the
// continuous trust value for graduated, reversible mitigation.
//
// Exactly one instance per network (named "trustRegistry").
//
package veremivndn.trident;

simple TrustRegistry
{
    parameters:
        @class(veremivndn::TrustRegistry);

        // Trust band thresholds (shared with TridentController for display only;
        // the controller owns the authoritative copies).
        double tauQuarantine = default(0.40);   // tau_T : enter quarantine below this
        double tauReinstate  = default(0.55);   // hysteresis band upper edge

        @signal[activeQuarantines](type=long);
        @statistic[activeQuarantines](record=vector,max,timeavg);

        @display("i=block/table2,#cc8800");
}
