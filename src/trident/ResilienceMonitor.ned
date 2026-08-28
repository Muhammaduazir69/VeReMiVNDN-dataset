//
// TRIDENT-VNDN - Network resilience monitor
//
// One instance per network. Every sampleInterval it polls the consumer side of
// every vehicle (Interests issued vs. Interests satisfied by VALID data) and
// records the windowed Interest-satisfaction ratio ISR(t). It normalises ISR(t)
// to the pre-attack baseline to obtain the resilience curve Q(t) in [0,1] and, at
// the end of the run, reports the paper's three resilience scores:
//
//   R   = AURC, the time-average of Q(t) over the evaluation window (trapezoid).
//   rho = robustness, the minimum of Q(t) during the attack (drop depth).
//   TTR = time-to-recover, the delay after the attack ends until Q(t) >= thetaRec.
//
// A per-run CSV time series (t, ISR, Q) is also written for the figures.
//
package veremivndn.trident;

simple ResilienceMonitor
{
    parameters:
        @class(veremivndn::ResilienceMonitor);

        double sampleInterval @unit(s) = default(2s);
        double baselineStart  @unit(s) = default(20s);  // start of pre-attack averaging
        double attackStart    @unit(s) = default(60s);  // attack onset (baseline ends here)
        double attackEnd      @unit(s) = default(160s); // attack stops here
        double recoveryThreshold = default(0.90);       // theta_rec for TTR
        string csvFile = default("");                   // empty => results/resilience_<config>_<run>.csv

        @signal[isr](type=double);
        @signal[resilienceQ](type=double);
        @statistic[isr](record=vector,timeavg);
        @statistic[resilienceQ](record=vector,min,timeavg);

        @display("i=block/gauge,#00aa88");
}
