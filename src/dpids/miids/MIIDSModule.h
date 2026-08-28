//
// MIIDSModule.h - Multilayer Intelligent IDS for VeReMiVNDN-EXE
//
// Pipeline: per-plane deep detectors (D1..D5) -> belief masses (Eq.6 of paper)
//           -> Dempster-Shafer fusion (Eq.7) -> pignistic decision
//           -> continuous-time trust ODE (Eq.10).
//
// The deep detectors are intended to be loaded as TorchScript modules at
// runtime via LibTorch (see loadDetectors()). Inference is triggered every
// tickInterval; if LibTorch is not available at build time, the detector
// callbacks fall back to the per-plane anomaly scores S_k(t) emitted by
// FeatureExtractor (Eqs. 1-5 of the manuscript), which keeps the simulator
// runnable on machines without a PyTorch install.
//

#ifndef __VEREMIVNDN_MIIDSMODULE_H
#define __VEREMIVNDN_MIIDSMODULE_H

#include <omnetpp.h>
#include <array>
#include <map>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "../fusion/DSFusionEngine.h"

#ifdef HAVE_LIBTORCH
#  include <torch/script.h>
#endif

using namespace omnetpp;

namespace veremivndn {

enum MIIDSPlane {
    PLANE_DATA = 0,        // Content Poisoning, signatures, payload entropy
    PLANE_CACHE = 1,       // Cache Pollution + Privacy Leakage
    PLANE_TRUST = 2,       // Sybil Amplification, identity graph
    PLANE_FORWARDING = 3,  // Selective Forwarding, drop pattern
    PLANE_PHY = 4,         // Radio Jamming, SINR/CCA/PER
    NUM_PLANES = 5
};

// Calibrated detector output: probability of malicious + confidence interval
struct DetectorOutput {
    double pMal;        // hat{p}_k in [0,1]
    double confidence;  // 1 - epistemic uncertainty
    double latencyMs;   // wall-clock inference latency, for the paper's metrics
};

struct MIIDSState {
    std::array<DetectorOutput, NUM_PLANES> outputs{};
    std::array<MassFunction, NUM_PLANES>   masses{};
    MassFunction fused;
    double conflict     = 0.0;     // K in Eq. 8
    double betPMal      = 0.0;     // BetP(M)
    double trust        = 1.0;     // T_n(t)
    int    quarantined  = 0;       // 1 if currently quarantined
    int    verdict      = 0;       // 0 = benign, 1 = malicious
    bool   abstained    = false;   // reject option fired on the last tick
    simtime_t lastTick;
    simtime_t lowTrustSince;       // start of contiguous T_n < tau_T window
};

class MIIDSModule : public cSimpleModule
{
  public:
    MIIDSModule();
    virtual ~MIIDSModule();

  protected:
    // ---- OMNeT++ lifecycle ----
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // ---- Pipeline stages ----
    void scheduleNextTick();
    void runDetectionTick();

    // Per-subject inference. The feature vector is obtained from the host's
    // FeatureExtractor, which builds it purely from observed traffic; ground
    // truth is never consulted here.
    DetectorOutput queryDetector(MIIDSPlane plane, const std::string &vid);

    // Resolve the host's FeatureExtractor (cached).
    class FeatureExtractor *getObserver();

    // Post-hoc ground truth for the confusion matrix only.
    bool subjectIsAttacker(const std::string &vid);

    // Convert calibrated probability + reliability into a Dempster-Shafer
    // belief mass m_k({M}, {B}, Theta) per Eq. 6 of the manuscript.
    MassFunction buildBelief(const DetectorOutput &out, double reliability);

    // DST fusion + pignistic transform; returns BetP(M) and updates state.
    void fuseAndDecide(MIIDSState &st);

    // Forward-Euler integration of the continuous-time trust ODE (Eq. 10).
    void integrateTrust(MIIDSState &st, double dtSec);

    // Adversarial inference: optionally perturbs the feature vector under
    // an L_inf budget before invoking queryDetector(). FGSM / PGD selectable.
    DetectorOutput adversarialQuery(MIIDSPlane plane, const std::string &vid);

    // Load TorchScript detector models if LibTorch is available; otherwise
    // mark the detectors as analytical fallbacks.
    void loadDetectors();

  private:
    // ---- Configuration ----
    simtime_t tickInterval;
    simtime_t trustQuarantineWindow;
    double kMax;
    double decisionMargin;
    double fusionThreshold;
    std::array<double, NUM_PLANES> reliability;
    double trustDecayAlpha;
    double trustRecoveryBeta;
    double trustQuarantineThreshold;

    bool   enableAdversarialInference;
    std::string adversarialMethod;
    double adversarialEpsilon;
    int    pgdSteps;

    std::string fusionMode;       // "dst" | "linear" | "majority"
    bool   singleVectorMode;

    // ---- Runtime state ----
    cMessage *tickEvent = nullptr;
    DSFusionEngine *dsEngine = nullptr;        // reused if present in network
    std::map<std::string, MIIDSState> states;  // per-vehicle MI-IDS state

    // ---- TorchScript detectors (optional, requires HAVE_LIBTORCH) ----
    std::array<std::string, NUM_PLANES> modelPaths;
    std::array<int, NUM_PLANES> planeDims = {6, 5, 4, 4, 4};
#ifdef HAVE_LIBTORCH
    std::array<torch::jit::script::Module, NUM_PLANES> models;
#endif
    std::array<bool, NUM_PLANES> modelLoaded = {false, false, false, false, false};

    // Detectors for the data, cache and forwarding planes consume a temporal
    // window rather than a single observation. Which planes those are is
    // discovered at load time by probing the checkpoint with both shapes, so
    // the runtime cannot drift out of step with the exported architecture.
    std::array<bool, NUM_PLANES> planeIsSeq = {false, false, false, false, false};
    static const int kSeqLen = 8;

    // Spacing between the frames held in the history ring. This must match the
    // FeatureExtractor export cadence the detectors were trained on, not the
    // decision cadence: the campaign exports every 500 ms while MI-IDS decides
    // every 100 ms, so pushing a frame per tick would give the sequential
    // detectors 0.8 s of look-back online against the 4 s they saw in training.
    simtime_t historyInterval;
    std::array<std::map<std::string, simtime_t>, NUM_PLANES> lastHistoryPush;

    // Per-plane, per-subject ring of the most recent feature frames. Padded at
    // the front with zeros until the subject has been observed kSeqLen times,
    // which matches the zero-padding used when the training sequences were
    // assembled.
    std::array<std::map<std::string, std::deque<std::vector<float>>>,
               NUM_PLANES> history;

    void pushHistory(int plane, const std::string &vid,
                     const std::vector<double> &feat);

    // Score one plane for every eligible subject in a single forward pass.
    // Issuing one forward per subject per plane per tick made the cost grow
    // with the vehicle population and dominated the run: a 400 s run reached
    // only t=88 s in an hour. Batching turns 5*N forwards per tick into 5.
    std::vector<DetectorOutput> scorePlaneBatch(
            int plane, const std::vector<std::string> &vids,
            const std::vector<std::vector<double>> &feats);
#ifdef HAVE_LIBTORCH
    torch::Tensor buildInput(int plane, const std::string &vid,
                             const std::vector<double> &feat);
    torch::Tensor buildBatch(int plane, const std::vector<std::string> &vids,
                             const std::vector<std::vector<double>> &feats);
#endif

    // ---- Signals ----
    simsignal_t betPSig;
    simsignal_t conflictSig;
    simsignal_t trustSig;
    simsignal_t verdictSig;
    simsignal_t quarantinedSig;

    // ---- Ground-truth bookkeeping for confusion matrix ----
    // Confusion-matrix scalars are written via recordScalar() in finish() to
    // mirror IDSModule and let analyze_miids_runs.py aggregate uniformly.
    std::string hostName;
    bool   selfIsAttacker = false;
    double selfAttackIntensity = 0.0;
    long   tpCount = 0, fpCount = 0, tnCount = 0, fnCount = 0;
    double latencySumMs = 0.0;
    long   latencySamples = 0;

    // ---- Observation plumbing ----
    class FeatureExtractor *observer = nullptr;
    bool observerResolved = false;
    std::map<std::string, int> truthCache;      // subject -> 1/0/-1 (unknown)
    long abstainCount = 0;                      // decisions withheld (K >= kMax)
    long unobservedTicks = 0;                   // ticks with no neighbour seen
    long noEvidenceSubjects = 0;                // beacon-only subjects skipped

    // Detection-latency bookkeeping: simulation time between a subject's
    // attack becoming active and MI-IDS first flagging it.
    std::map<std::string, simtime_t> firstAttackSeen;
    std::map<std::string, simtime_t> firstFlagged;
    double detectionDelaySum = 0.0;
    long   detectionDelayCount = 0;
};

} // namespace veremivndn

#endif // __VEREMIVNDN_MIIDSMODULE_H
