//
// TRIDENT-VNDN - Closed-loop trust controller (sits on each RSU)
//
// Detector-agnostic: it consumes the per-vehicle malicious belief Bel(v) produced
// by whatever evidence pipeline is present (here the DS fusion of the behavioural
// and forwarding-plane detectors) and turns it into a continuous trust state via a
// forward-Euler integration of the trust ODE
//
//     dT_v/dt = -alpha * Bel_v(t) + beta * (1 - T_v(t)),   T_v in [0,1].
//
// A hysteresis state machine (enter quarantine when T_v < tauQuarantine is held
// for windowQuarantine seconds; leave when T_v >= tauReinstate) makes isolation
// GRACEFUL and REVERSIBLE. On each transition it drives three remediation prongs
// through the AdaptiveForwardingStrategy and publishes the verdict to the global
// TrustRegistry, which the data plane honours hop-by-hop.
//
package veremivndn.trident;

simple TridentController
{
    parameters:
        @class(veremivndn::TridentController);

        double controlInterval @unit(s) = default(1s);   // Delta in the Euler step

        // Trust ODE coefficients
        double alpha = default(0.40);   // belief-driven decay gain
        double beta  = default(0.05);   // autonomous recovery gain

        // Hysteresis band (graceful, reversible quarantine)
        double tauQuarantine   = default(0.40);   // tau_T
        double tauReinstate    = default(0.55);   // tau_reinstate (> tau_T)
        double windowQuarantine @unit(s) = default(10s);  // W_quar dwell time

        bool enableMitigation = default(true);    // master switch for the 3 prongs

        @signal[trustMin](type=double);
        @signal[activeQuarantines](type=long);
        @signal[collateralIsolated](type=long);
        @statistic[trustMin](record=vector,min,timeavg);
        @statistic[activeQuarantines](record=vector,max,timeavg);
        @statistic[collateralIsolated](record=vector,max);

        @display("i=block/control,#cc8800");
}
