//
// MIIDSModule.ned - Multilayer Intelligent IDS for VeReMiVNDN-EXE.
//
package veremivndn.dpids.miids;

simple MIIDSModule
{
    parameters:
        @class(veremivndn::MIIDSModule);
        @display("i=block/control;bgb=,red");

        // ---- Runtime cadence ----
        double tickInterval     @unit(s) = default(50ms);
        double trustQuarantineWindow @unit(s) = default(10s);

        // ---- DST fusion ----
        // Reject the fused decision when conflict mass K >= kMax
        double kMax                       = default(0.85);
        // Pignistic decision threshold; flag vehicle if BetP(M) > fusionThreshold
        double fusionThreshold            = default(0.55);
        // Reject option: abstain when BetP lies within this margin of the
        // decision threshold, i.e. when the fused evidence does not separate
        // the two hypotheses well enough to commit.
        double decisionMargin             = default(0.02);
        // Spacing of the frames fed to the sequential plane detectors. Set this
        // to the FeatureExtractor export interval used to build the training
        // sequences, not to tickInterval.
        double historyInterval @unit(s)   = default(500ms);
        // Per-plane discounting coefficients beta_k in (0,1]
        double detectorReliabilityData       = default(0.92);
        double detectorReliabilityCache      = default(0.88);
        double detectorReliabilityTrust      = default(0.86);
        double detectorReliabilityForwarding = default(0.90);
        double detectorReliabilityPHY        = default(0.94);

        // ---- Continuous-time trust ODE ----
        // dot{T_n} = -alpha * BetP(M) + beta * (1 - T_n)
        double trustDecayAlpha            = default(0.4);
        double trustRecoveryBeta          = default(0.05);
        double trustQuarantineThreshold   = default(0.4);

        // ---- Adversarial-aware inference ----
        bool   enableAdversarialInference = default(true);
        string adversarialMethod          = default("PGD");   // "PGD" or "FGSM"
        double adversarialEpsilon         = default(0.05);
        int    pgdSteps                   = default(10);

        // ---- TorchScript model paths (relative to working dir) ----
        // Empty string disables LibTorch and uses the analytical fallback.
        string modelPathData       = default("../../models/miids/detector_data.pt");
        string modelPathCache      = default("../../models/miids/detector_cache.pt");
        string modelPathTrust      = default("../../models/miids/detector_trust.pt");
        string modelPathForwarding = default("../../models/miids/detector_forwarding.pt");
        string modelPathPHY        = default("../../models/miids/detector_phy.pt");

        // ---- Fallback / ablation modes ----
        // "dst"      = Dempster-Shafer (default)
        // "linear"   = weighted linear sum (single-vector BiLSTM baseline)
        // "majority" = majority vote across the 5 detectors
        string fusionMode                 = default("dst");
        bool   singleVectorMode           = default(false);

        // ---- Signals ----
        @signal[miidsBetP](type=double);
        @signal[miidsConflict](type=double);
        @signal[miidsTrust](type=double);
        @signal[miidsVerdict](type=long);     // 0 = benign, 1 = malicious
        @signal[miidsQuarantined](type=long); // 1 when vehicle is quarantined

        @statistic[miidsBetP](title="Pignistic BetP(M)"; record=stats,vector);
        @statistic[miidsConflict](title="DST conflict mass K"; record=stats,vector);
        @statistic[miidsTrust](title="Trust score T_n(t)"; record=stats,vector);
        @statistic[miidsVerdict](title="Runtime verdict (0/1)"; record=count,sum,vector);
        @statistic[miidsQuarantined](title="Quarantine indicator"; record=count,sum,vector);
}
