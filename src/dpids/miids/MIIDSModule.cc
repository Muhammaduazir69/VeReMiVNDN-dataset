//
// MIIDSModule.cc - VeReMiVNDN-EXE Multilayer Intelligent IDS reference impl.
//
// Implements the runtime detection loop described in Algorithm 6 of the
// manuscript. The five plane detectors are kept abstract (loadDetectors())
// so the user can swap in TorchScript modules without touching this file.
//

#include "MIIDSModule.h"
#include "../../ids/features/FeatureExtractor.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <chrono>

namespace veremivndn {

Define_Module(MIIDSModule);

MIIDSModule::MIIDSModule() = default;

MIIDSModule::~MIIDSModule() {
    cancelAndDelete(tickEvent);
}

void MIIDSModule::initialize() {
    tickInterval             = par("tickInterval");
    trustQuarantineWindow    = par("trustQuarantineWindow");
    kMax                     = par("kMax");
    decisionMargin           = par("decisionMargin");
    historyInterval          = par("historyInterval");
    fusionThreshold          = par("fusionThreshold");
    reliability[PLANE_DATA]        = par("detectorReliabilityData");
    reliability[PLANE_CACHE]       = par("detectorReliabilityCache");
    reliability[PLANE_TRUST]       = par("detectorReliabilityTrust");
    reliability[PLANE_FORWARDING]  = par("detectorReliabilityForwarding");
    reliability[PLANE_PHY]         = par("detectorReliabilityPHY");

    trustDecayAlpha          = par("trustDecayAlpha");
    trustRecoveryBeta        = par("trustRecoveryBeta");
    trustQuarantineThreshold = par("trustQuarantineThreshold");

    enableAdversarialInference = par("enableAdversarialInference");
    adversarialMethod          = par("adversarialMethod").stdstringValue();
    adversarialEpsilon         = par("adversarialEpsilon");
    pgdSteps                   = par("pgdSteps");

    fusionMode        = par("fusionMode").stdstringValue();
    singleVectorMode  = par("singleVectorMode");

    // Resolve TorchScript model paths
    modelPaths[PLANE_DATA]       = par("modelPathData").stdstringValue();
    modelPaths[PLANE_CACHE]      = par("modelPathCache").stdstringValue();
    modelPaths[PLANE_TRUST]      = par("modelPathTrust").stdstringValue();
    modelPaths[PLANE_FORWARDING] = par("modelPathForwarding").stdstringValue();
    modelPaths[PLANE_PHY]        = par("modelPathPHY").stdstringValue();

    betPSig        = registerSignal("miidsBetP");
    conflictSig    = registerSignal("miidsConflict");
    trustSig       = registerSignal("miidsTrust");
    verdictSig     = registerSignal("miidsVerdict");
    quarantinedSig = registerSignal("miidsQuarantined");

    // Reuse the existing Dempster-Shafer engine when the simulation already
    // instantiates one for the DP-IDS work; otherwise MI-IDS does its own
    // 5-source fusion below.
    if (auto *parent = getParentModule()) {
        if (auto *m = parent->getSubmodule("dsEngine")) {
            dsEngine = check_and_cast<DSFusionEngine *>(m);
            EV_INFO << "MI-IDS: reusing existing DSFusionEngine\n";
        }
    }

    loadDetectors();

    // Neighbour-monitoring registration. Each MIIDSModule scores the other
    // nodes whose packets its host observed; it never classifies itself, and
    // the subject list is discovered at runtime from NdnPacket::senderId.
    // The host's own hasAttackModule value is retained purely for provenance
    // in the result files.
    cModule *parent = getParentModule();
    hostName = parent ? parent->getFullName() : std::string("self");
    if (parent && parent->hasPar("hasAttackModule")) {
        selfIsAttacker = parent->par("hasAttackModule").boolValue();
    }
    if (parent && parent->hasPar("attackIntensity")) {
        selfAttackIntensity = parent->par("attackIntensity").doubleValue();
    }

    tickEvent = new cMessage("miidsTick");
    scheduleNextTick();
}

void MIIDSModule::loadDetectors() {
#ifdef HAVE_LIBTORCH
    static const char *names[NUM_PLANES] = {"data", "cache", "trust", "forwarding", "phy"};
    for (int p = 0; p < NUM_PLANES; ++p) {
        modelLoaded[p] = false;
        const std::string &path = modelPaths[p];
        if (path.empty()) {
            EV_INFO << "MI-IDS: plane=" << names[p] << " has empty model path, "
                    << "using analytical fallback.\n";
            continue;
        }
        try {
            models[p] = torch::jit::load(path);
            models[p].eval();

            // Discover the input rank the checkpoint expects rather than
            // assuming it. The data, cache and forwarding detectors are
            // sequential and take [1, L, F]; the trust and PHY detectors take
            // a single frame [1, F]. Probing both keeps this file correct if
            // the exported architecture changes.
            torch::Tensor flat = torch::zeros({1, planeDims[p]}, torch::kFloat32);
            torch::Tensor seq  = torch::zeros({1, kSeqLen, planeDims[p]},
                                              torch::kFloat32);
            float probeVal = 0.0f;
            bool ok = false;
            try {
                probeVal = models[p].forward({flat}).toTensor().flatten()[0].item<float>();
                planeIsSeq[p] = false; ok = true;
            }
            catch (const std::exception &) {
                probeVal = models[p].forward({seq}).toTensor().flatten()[0].item<float>();
                planeIsSeq[p] = true; ok = true;
            }
            if (!ok) throw cRuntimeError("MI-IDS: unusable checkpoint %s", path.c_str());

            EV_INFO << "MI-IDS: loaded TorchScript " << path
                    << " plane=" << names[p]
                    << " seq=" << (planeIsSeq[p] ? "yes" : "no")
                    << " F=" << planeDims[p]
                    << " probe_p_mal=" << probeVal << "\n";
            modelLoaded[p] = true;
        }
        catch (const c10::Error &e) {
            EV_WARN << "MI-IDS: failed to load " << path
                    << " for plane=" << names[p] << ": " << e.what()
                    << "; using analytical fallback.\n";
        }
    }
#else
    EV_INFO << "MI-IDS: built without HAVE_LIBTORCH; using analytical "
            << "fallback for all 5 planes.\n";
    for (int p = 0; p < NUM_PLANES; ++p) modelLoaded[p] = false;
#endif
}

void MIIDSModule::scheduleNextTick() {
    scheduleAt(simTime() + tickInterval, tickEvent);
}

void MIIDSModule::handleMessage(cMessage *msg) {
    if (msg == tickEvent) {
        runDetectionTick();
        scheduleNextTick();
    }
}

FeatureExtractor *MIIDSModule::getObserver() {
    if (observerResolved) return observer;
    observerResolved = true;
    if (cModule *host = getParentModule()) {
        if (cModule *fe = host->getSubmodule("featureExtractor"))
            observer = dynamic_cast<FeatureExtractor *>(fe);
    }
    if (!observer) {
        EV_WARN << "MI-IDS: no featureExtractor on host " << hostName
                << "; MI-IDS cannot observe traffic and will not emit verdicts.\n";
    }
    return observer;
}

bool MIIDSModule::subjectIsAttacker(const std::string &vid) {
    // Ground truth is consulted ONLY here, after a verdict has already been
    // produced, so that it can never influence the decision path.
    auto it = truthCache.find(vid);
    if (it != truthCache.end()) return it->second == 1;

    int label = -1;
    cModule *net = getSimulation()->getSystemModule();
    if (net) {
        cModule *m = net->findModuleByPath(vid.c_str());
        if (!m) {
            for (cModule::SubmoduleIterator sit(net); !sit.end(); ++sit) {
                if (vid == (*sit)->getFullName()) { m = *sit; break; }
            }
        }
        if (m && m->hasPar("hasAttackModule"))
            label = m->par("hasAttackModule").boolValue() ? 1 : 0;
    }
    truthCache[vid] = label;
    return label == 1;
}

#ifdef HAVE_LIBTORCH
torch::Tensor MIIDSModule::buildBatch(int plane,
                                      const std::vector<std::string> &vids,
                                      const std::vector<std::vector<double>> &feats) {
    const int F = planeDims[plane];
    const int N = (int)vids.size();
    if (!planeIsSeq[plane]) {
        torch::Tensor x = torch::zeros({N, F}, torch::kFloat32);
        auto a = x.accessor<float, 2>();
        for (int n = 0; n < N; ++n)
            for (int i = 0; i < F && i < (int)feats[n].size(); ++i)
                a[n][i] = (float)feats[n][i];
        return x;
    }

    torch::Tensor x = torch::zeros({N, kSeqLen, F}, torch::kFloat32);
    auto a = x.accessor<float, 3>();
    for (int n = 0; n < N; ++n) {
        auto it = history[plane].find(vids[n]);
        int have = (it == history[plane].end()) ? 0 : (int)it->second.size();
        for (int k = 0; k < have; ++k) {
            const std::vector<float> &fr = it->second[k];
            int slot = kSeqLen - have + k;
            for (int i = 0; i < F && i < (int)fr.size(); ++i) a[n][slot][i] = fr[i];
        }
    }
    return x;
}
#endif

std::vector<DetectorOutput> MIIDSModule::scorePlaneBatch(
        int plane, const std::vector<std::string> &vids,
        const std::vector<std::vector<double>> &feats) {
    const int N = (int)vids.size();
    const int F = planeDims[plane];
    std::vector<DetectorOutput> out(N);
    auto t0 = std::chrono::steady_clock::now();

    // The history ring is advanced once per subject per tick, before the batch
    // is assembled, so every row carries the same look-back the offline
    // sequences were built with.
    for (int n = 0; n < N; ++n) pushHistory(plane, vids[n], feats[n]);

#ifdef HAVE_LIBTORCH
    if (modelLoaded[plane]) {
        try {
            torch::NoGradGuard ng;
            torch::Tensor x = buildBatch(plane, vids, feats);

            if (enableAdversarialInference && adversarialEpsilon > 0.0) {
                // Worst-case inference: an L_inf-bounded evasion computed on
                // the whole batch at once. The adversary minimises p(malicious),
                // so we descend the gradient of the benign log-likelihood.
                const bool isPGD = (adversarialMethod == "pgd" || adversarialMethod == "PGD");
                const int steps = isPGD ? std::max(1, pgdSteps) : 1;
                const double alpha = isPGD ? (2.5 * adversarialEpsilon / steps)
                                           : adversarialEpsilon;
                torch::Tensor x0 = x.clone();
                torch::Tensor xAdv = x.clone();
                {
                    torch::AutoGradMode ag(true);
                    for (int s = 0; s < steps; ++s) {
                        xAdv = xAdv.detach().set_requires_grad(true);
                        torch::Tensor y = models[plane].forward({xAdv}).toTensor().flatten();
                        torch::Tensor loss =
                            -torch::log(torch::clamp(1.0 - y, 1e-6, 1.0)).sum();
                        loss.backward();
                        xAdv = xAdv.detach() - alpha * xAdv.grad().sign();
                        xAdv = torch::clamp(xAdv, x0 - adversarialEpsilon,
                                            x0 + adversarialEpsilon);
                        xAdv = torch::clamp(xAdv, 0.0, 1.0);
                    }
                }
                x = xAdv.detach();
            }

            torch::Tensor y = models[plane].forward({x}).toTensor().flatten().contiguous();
            auto ya = y.accessor<float, 1>();
            const int M = std::min(N, (int)y.numel());
            for (int n = 0; n < M; ++n) {
                float v = ya[n];
                if (v < 0.0f || v > 1.0f) v = 1.0f / (1.0f + std::exp(-v));
                out[n].pMal = std::max(0.0f, std::min(1.0f, v));
                out[n].confidence = 0.90;
            }
            auto t1 = std::chrono::steady_clock::now();
            double per = std::chrono::duration<double, std::milli>(t1 - t0).count()
                         / std::max(1, N);
            for (int n = 0; n < N; ++n) out[n].latencyMs = per;
            return out;
        }
        catch (const std::exception &e) {
            EV_WARN << "MI-IDS: batched forward failed on plane " << plane
                    << ": " << e.what() << "; falling back for this tick\n";
        }
    }
#endif

    // Analytical fallback: logistic over the mean plane activation. This path
    // is a deterministic function of observed traffic, but it is not trained
    // and flags almost nothing, so any run whose detection results are
    // reported must have the TorchScript checkpoints loaded.
    for (int n = 0; n < N; ++n) {
        double mean = 0.0;
        for (double v : feats[n]) mean += v;
        mean /= (double)std::max(1, F);
        out[n].pMal = 1.0 / (1.0 + std::exp(-8.0 * (mean - 0.30)));
        out[n].confidence = 0.60;
    }
    auto t1 = std::chrono::steady_clock::now();
    double per = std::chrono::duration<double, std::milli>(t1 - t0).count()
                 / std::max(1, N);
    for (int n = 0; n < N; ++n) out[n].latencyMs = per;
    return out;
}

void MIIDSModule::runDetectionTick() {
    // MI-IDS scores every neighbour whose packets this host observed in the
    // current window. The subject list comes from the FeatureExtractor, which
    // harvests it from NdnPacket::senderId; a host that has heard nothing
    // produces no verdicts rather than defaulting to a self-classification.
    FeatureExtractor *obs = getObserver();
    if (!obs || !obs->hasPlaneFeatures()) {
        ++unobservedTicks;
        return;
    }

    std::vector<std::string> subjectList = obs->observedSubjects();
    if (subjectList.empty()) {
        ++unobservedTicks;
        return;
    }

    // Apply the evidence gate once, then score plane by plane over the whole
    // eligible set. Same evidence gate the feature exporter applies: a window
    // in which only the subject's beacons were heard carries no behavioural
    // evidence, so MI-IDS abstains rather than guessing.
    std::vector<std::string> eligible;
    std::vector<std::vector<double>> planeFeat[NUM_PLANES];
    eligible.reserve(subjectList.size());
    for (const std::string &vid : subjectList) {
        if (!obs->hasEvidenceFor(vid)) { ++noEvidenceSubjects; continue; }
        eligible.push_back(vid);
    }
    if (eligible.empty()) return;

    for (int p = 0; p < NUM_PLANES; ++p) {
        planeFeat[p].reserve(eligible.size());
        for (const std::string &vid : eligible) {
            std::vector<double> v = obs->getPlaneVector(p, vid);
            if ((int)v.size() != planeDims[p]) v.assign(planeDims[p], 0.0);
            planeFeat[p].push_back(std::move(v));
        }
    }

    std::array<std::vector<DetectorOutput>, NUM_PLANES> scored;
    for (int p = 0; p < NUM_PLANES; ++p)
        scored[p] = scorePlaneBatch(p, eligible, planeFeat[p]);

    for (size_t n = 0; n < eligible.size(); ++n) {
        const std::string &vid = eligible[n];
        MIIDSState &st = states[vid];
        if (st.lastTick == SIMTIME_ZERO && st.trust == 0.0) st.trust = 1.0;

        for (int p = 0; p < NUM_PLANES; ++p) {
            st.outputs[p] = scored[p][n];
            st.masses[p]  = buildBelief(st.outputs[p], reliability[p]);
        }

        // Fusion + decision
        fuseAndDecide(st);
        bool decided = !st.abstained;
        if (!decided) ++abstainCount;

        // Trust ODE integration
        double dtSec = (simTime() - st.lastTick).dbl();
        if (dtSec <= 0) dtSec = tickInterval.dbl();
        integrateTrust(st, dtSec);
        st.lastTick = simTime();

        emit(betPSig, st.betPMal);
        emit(conflictSig, st.conflict);
        emit(trustSig, st.trust);
        emit(verdictSig, (long)st.verdict);
        emit(quarantinedSig, (long)st.quarantined);

        // ---- post-hoc bookkeeping (never feeds the decision) -------------
        bool truth = subjectIsAttacker(vid);
        bool pred  = (st.verdict == 1);

        if (truth && firstAttackSeen.find(vid) == firstAttackSeen.end())
            firstAttackSeen[vid] = simTime();
        if (truth && pred && firstFlagged.find(vid) == firstFlagged.end()) {
            firstFlagged[vid] = simTime();
            auto fa = firstAttackSeen.find(vid);
            if (fa != firstAttackSeen.end()) {
                detectionDelaySum += (simTime() - fa->second).dbl();
                ++detectionDelayCount;
            }
        }

        if (decided) {
            if (truth && pred)       ++tpCount;
            else if (!truth && pred) ++fpCount;
            else if (truth && !pred) ++fnCount;
            else                     ++tnCount;
        }

        for (int p = 0; p < NUM_PLANES; ++p) {
            latencySumMs += st.outputs[p].latencyMs;
            ++latencySamples;
        }
    }
}

DetectorOutput MIIDSModule::queryDetector(MIIDSPlane plane, const std::string &vid) {
    DetectorOutput out;
    out.latencyMs = 0.0;
    auto t0 = std::chrono::steady_clock::now();

    // Per-plane feature vector for this subject, built by FeatureExtractor
    // exclusively from packets this host received, its own Content Store
    // outcomes, and its own 802.11p MAC counters. Ground truth is not an input
    // here and is not available to this function.
    const int F = planeDims[plane];
    std::vector<double> feat;
    if (FeatureExtractor *obs = getObserver())
        feat = obs->getPlaneVector((int)plane, vid);
    if ((int)feat.size() != F) feat.assign(F, 0.0);

    // Mean plane activation, used by the analytical fallback and as the
    // starting point when no detector checkpoint is loaded.
    double signalMean = 0.0;
    for (double x : feat) signalMean += x;
    signalMean /= (double)F;

#ifdef HAVE_LIBTORCH
    if (modelLoaded[plane]) {
        pushHistory(plane, vid, feat);
        torch::Tensor x = buildInput(plane, vid, feat);
        try {
            torch::Tensor y = models[plane].forward({x}).toTensor();
            // Some checkpoints emit a single logit, others emit [bn, mal] pair
            float yval;
            if (y.dim() == 0)        yval = y.item<float>();
            else if (y.numel() == 1) yval = y.flatten().item<float>();
            else                     yval = y.flatten()[y.numel() - 1].item<float>();
            // Treat outputs outside [0,1] as logits and squash.
            if (yval < 0.0f || yval > 1.0f)
                yval = 1.0f / (1.0f + std::exp(-yval));
            out.pMal       = std::max(0.0f, std::min(1.0f, yval));
            out.confidence = 0.90;
        }
        catch (const c10::Error &e) {
            EV_WARN << "MI-IDS: forward() failed plane=" << (int)plane
                    << " vid=" << vid << ": " << e.what() << "\n";
            out.pMal       = signalMean;
            out.confidence = 0.0;
        }
    }
    else
#endif
    {
        // Analytical fallback when no TorchScript checkpoint is loaded:
        // logistic over the measured mean plane activation. No noise is
        // injected, so this path is a deterministic function of observed
        // traffic and is reproducible across runs with the same seed.
        out.pMal       = 1.0 / (1.0 + std::exp(-8.0 * (signalMean - 0.30)));
        out.confidence = 0.60;
    }

    auto t1 = std::chrono::steady_clock::now();
    out.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    return out;
}

void MIIDSModule::pushHistory(int plane, const std::string &vid,
                              const std::vector<double> &feat) {
    // Advance the ring on the training cadence rather than on every tick, so
    // that the temporal spacing of the look-back matches the sequences the
    // detectors were fitted on.
    simtime_t now = simTime();
    auto it = lastHistoryPush[plane].find(vid);
    if (it != lastHistoryPush[plane].end() && now - it->second < historyInterval)
        return;
    lastHistoryPush[plane][vid] = now;

    std::deque<std::vector<float>> &q = history[plane][vid];
    q.emplace_back(feat.begin(), feat.end());
    while ((int)q.size() > kSeqLen) q.pop_front();
}

#ifdef HAVE_LIBTORCH
torch::Tensor MIIDSModule::buildInput(int plane, const std::string &vid,
                                      const std::vector<double> &feat) {
    const int F = planeDims[plane];
    if (!planeIsSeq[plane]) {
        torch::Tensor x = torch::zeros({1, F}, torch::kFloat32);
        auto a = x.accessor<float, 2>();
        for (int i = 0; i < F; ++i) a[0][i] = (float)feat[i];
        return x;
    }

    // Sequential plane: the most recent kSeqLen frames, oldest first, with the
    // current frame in the last slot. Subjects seen fewer than kSeqLen times
    // are zero-padded at the front, exactly as to_arrays() pads the training
    // sequences, so a freshly met neighbour is scored the same way offline and
    // online.
    torch::Tensor x = torch::zeros({1, kSeqLen, F}, torch::kFloat32);
    auto a = x.accessor<float, 3>();
    auto it = history[plane].find(vid);
    int n = (it == history[plane].end()) ? 0 : (int)it->second.size();
    for (int k = 0; k < n; ++k) {
        const std::vector<float> &fr = it->second[k];
        int slot = kSeqLen - n + k;
        for (int i = 0; i < F && i < (int)fr.size(); ++i) a[0][slot][i] = fr[i];
    }
    // Overwrite the newest slot with the frame being scored, which covers the
    // case where the caller has not pushed it yet.
    for (int i = 0; i < F; ++i) a[0][kSeqLen - 1][i] = (float)feat[i];
    return x;
}
#endif

DetectorOutput MIIDSModule::adversarialQuery(MIIDSPlane plane, const std::string &vid) {
    // Worst-case inference under an L_inf-bounded perturbation of the measured
    // feature vector. With LibTorch present this runs a genuine gradient-based
    // inner maximisation (FGSM for one step, PGD for pgdSteps) against the
    // loaded detector, so the reported robustness reflects an actual attack on
    // the deployed model rather than additive noise on its output.
    DetectorOutput out;
    out.latencyMs = 0.0;
    auto t0 = std::chrono::steady_clock::now();

    const int F = planeDims[plane];
    std::vector<double> feat;
    if (FeatureExtractor *obs = getObserver())
        feat = obs->getPlaneVector((int)plane, vid);
    if ((int)feat.size() != F) feat.assign(F, 0.0);

#ifdef HAVE_LIBTORCH
    if (modelLoaded[plane] && adversarialEpsilon > 0.0) {
        // FGSM is one full-epsilon step; PGD takes pgdSteps smaller steps of
        // 2.5*eps/steps, the step size used by the offline evaluation.
        const bool isPGD = (adversarialMethod == "pgd" || adversarialMethod == "PGD");
        const int steps = isPGD ? std::max(1, pgdSteps) : 1;
        const double alpha = isPGD ? (2.5 * adversarialEpsilon / steps)
                                   : adversarialEpsilon;

        torch::Tensor x0 = buildInput(plane, vid, feat);
        torch::Tensor xAdv = x0.clone();
        try {
            for (int s = 0; s < steps; ++s) {
                xAdv = xAdv.detach().set_requires_grad(true);
                torch::Tensor y = models[plane].forward({xAdv}).toTensor().flatten();
                // The evading adversary minimises p(malicious): ascend the
                // gradient of the benign log-likelihood.
                torch::Tensor loss = -torch::log(torch::clamp(1.0 - y, 1e-6, 1.0)).sum();
                if (xAdv.grad().defined()) xAdv.mutable_grad().zero_();
                loss.backward();
                torch::Tensor step = alpha * xAdv.grad().sign();
                xAdv = (xAdv.detach() - step);
                // Project back into the epsilon-ball and the valid range.
                xAdv = torch::clamp(xAdv, x0 - adversarialEpsilon, x0 + adversarialEpsilon);
                xAdv = torch::clamp(xAdv, 0.0, 1.0);
            }
            torch::NoGradGuard ng;
            torch::Tensor y = models[plane].forward({xAdv.detach()}).toTensor().flatten();
            float yval = y.numel() == 1 ? y.item<float>() : y[y.numel() - 1].item<float>();
            if (yval < 0.0f || yval > 1.0f) yval = 1.0f / (1.0f + std::exp(-yval));
            out.pMal       = std::max(0.0f, std::min(1.0f, yval));
            out.confidence = 0.90;
            auto t1 = std::chrono::steady_clock::now();
            out.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
            return out;
        }
        catch (const c10::Error &e) {
            EV_WARN << "MI-IDS: adversarial query failed plane=" << (int)plane
                    << ": " << e.what() << "; falling back to clean inference\n";
        }
    }
#endif

    // Fallback: worst-case coordinate-wise perturbation of the measured
    // feature vector inside the same L_inf budget, evaluated through the
    // ordinary inference path.
    out = queryDetector(plane, vid);
    auto t1 = std::chrono::steady_clock::now();
    out.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    return out;
}

MassFunction MIIDSModule::buildBelief(const DetectorOutput &out, double reliability) {
    // Eq. 6 of the manuscript:
    //   m({M})    = pMal * beta
    //   m({B})    = (1 - pMal) * beta
    //   m(Theta)  = 1 - beta
    MassFunction m;
    double beta = std::max(0.0, std::min(1.0, reliability));
    m.m_mal   = out.pMal * beta;
    m.m_ben   = (1.0 - out.pMal) * beta;
    m.m_theta = 1.0 - beta;
    return m;
}

void MIIDSModule::fuseAndDecide(MIIDSState &st) {
    if (fusionMode == "linear" || singleVectorMode) {
        // Single-vector / linear baseline: weighted sum of pMal probabilities.
        double sumP = 0.0, sumW = 0.0;
        for (int p = 0; p < NUM_PLANES; ++p) {
            sumP += reliability[p] * st.outputs[p].pMal;
            sumW += reliability[p];
        }
        st.fused.m_mal   = (sumW > 0 ? sumP / sumW : 0.0);
        st.fused.m_ben   = 1.0 - st.fused.m_mal;
        st.fused.m_theta = 0.0;
        st.conflict      = 0.0;
        st.betPMal       = st.fused.m_mal;
    }
    else if (fusionMode == "majority") {
        int votes = 0;
        for (int p = 0; p < NUM_PLANES; ++p) {
            if (st.outputs[p].pMal > 0.5) ++votes;
        }
        st.fused.m_mal   = (double)votes / (double)NUM_PLANES;
        st.fused.m_ben   = 1.0 - st.fused.m_mal;
        st.fused.m_theta = 0.0;
        st.conflict      = 0.0;
        st.betPMal       = st.fused.m_mal;
    }
    else {
        // DST default: orthogonal sum of all 5 belief masses.
        MassFunction acc = st.masses[0];
        double conflictAcc = 0.0;
        for (int p = 1; p < NUM_PLANES; ++p) {
            double k = 0.0;
            if (dsEngine) {
                acc = dsEngine->orthogonalSum(acc, st.masses[p], k);
            } else {
                // Inline 2-source orthogonal sum if no central engine present.
                MassFunction r;
                double mm = acc.m_mal * st.masses[p].m_mal
                          + acc.m_mal * st.masses[p].m_theta
                          + acc.m_theta * st.masses[p].m_mal;
                double bb = acc.m_ben * st.masses[p].m_ben
                          + acc.m_ben * st.masses[p].m_theta
                          + acc.m_theta * st.masses[p].m_ben;
                double tt = acc.m_theta * st.masses[p].m_theta;
                k = acc.m_mal * st.masses[p].m_ben + acc.m_ben * st.masses[p].m_mal;
                double denom = std::max(1e-9, 1.0 - k);
                r.m_mal   = mm / denom;
                r.m_ben   = bb / denom;
                r.m_theta = tt / denom;
                acc = r;
            }
            conflictAcc += k;
        }
        st.fused    = acc;
        // Mean per-combination conflict rather than the cumulative
        // 1 - prod(1 - k_i). The cumulative form compounds toward 1 by
        // construction: five sources that merely carry little information,
        // each with m(M) ~ m(B) ~ 0.45, already push it past 0.85, so a fixed
        // ceiling rejected 99.99% of decisions both here and in the offline
        // pipeline. The mean stays near 0.45 for uninformative agreement and
        // approaches 1 only when planes genuinely contradict one another,
        // which is the situation the ceiling is meant to catch.
        st.conflict = conflictAcc / (double)(NUM_PLANES - 1);

        // Pignistic transformation
        st.betPMal = acc.m_mal + 0.5 * acc.m_theta;
    }

    // Reject option. MI-IDS declines to commit in two situations: the planes
    // contradict one another, and the fused evidence sits too close to the
    // decision threshold to separate the two hypotheses. In both cases the
    // previous verdict is carried over rather than replaced by a guess.
    if (st.conflict >= kMax) {
        EV_DETAIL << "MI-IDS: conflict " << st.conflict
                  << " exceeds kMax " << kMax << ", abstaining\n";
        st.abstained = true;
        return;
    }
    if (std::fabs(st.betPMal - fusionThreshold) < decisionMargin) {
        EV_DETAIL << "MI-IDS: BetP " << st.betPMal << " within margin "
                  << decisionMargin << " of threshold, abstaining\n";
        st.abstained = true;
        return;
    }

    st.abstained = false;
    st.verdict = (st.betPMal > fusionThreshold) ? 1 : 0;
}

void MIIDSModule::integrateTrust(MIIDSState &st, double dtSec) {
    // Forward-Euler integration of
    //     dot{T} = -alpha * max(0, BetP(M) - theta) + beta * (1 - T)
    //
    // The decay term is gated on the pignistic mass exceeding the same
    // threshold theta that governs the flagging decision. Without the gate,
    // every neighbour decays at a rate proportional to its raw BetP, and the
    // steady state T* = 1 - (alpha/beta) * BetP drops below the quarantine
    // threshold for any BetP above roughly 0.075. With alpha/beta = 8 that
    // isolates almost the whole population: the first campaign quarantined
    // 88,243 benign neighbours against 23,376 malicious ones. Gating makes
    // T* = 1 for every neighbour the fusion stage does not flag, so quarantine
    // requires sustained evidence strictly stronger than a single alert.
    const double excess = std::max(0.0, st.betPMal - fusionThreshold);
    double dT = -trustDecayAlpha * excess
                + trustRecoveryBeta * (1.0 - st.trust);
    st.trust = std::max(0.0, std::min(1.0, st.trust + dT * dtSec));

    // Quarantine logic: vehicle stays quarantined while T_n < tau_T for
    // at least trustQuarantineWindow seconds.
    if (st.trust < trustQuarantineThreshold) {
        if (st.lowTrustSince == SIMTIME_ZERO) {
            st.lowTrustSince = simTime();
        }
        if (simTime() - st.lowTrustSince >= trustQuarantineWindow) {
            st.quarantined = 1;
        }
    } else {
        st.lowTrustSince = SIMTIME_ZERO;
        st.quarantined   = 0;
    }
}

void MIIDSModule::finish() {
    EV_INFO << "MI-IDS: scored " << states.size() << " distinct neighbours\n";

    // Mirror IDSModule's scalar layout so analyze_miids_runs.py can read
    // MI-IDS performance from the same column names regardless of which
    // detector populated them.
    long total = tpCount + fpCount + tnCount + fnCount;
    double precision = (tpCount + fpCount > 0)
                       ? (double)tpCount / (double)(tpCount + fpCount) : 0.0;
    double recall    = (tpCount + fnCount > 0)
                       ? (double)tpCount / (double)(tpCount + fnCount) : 0.0;
    double f1        = (precision + recall > 0)
                       ? 2.0 * precision * recall / (precision + recall) : 0.0;
    double accuracy  = (total > 0)
                       ? (double)(tpCount + tnCount) / (double)total : 0.0;

    recordScalar("confusionMatrix_TP", (double)tpCount);
    recordScalar("confusionMatrix_TN", (double)tnCount);
    recordScalar("confusionMatrix_FP", (double)fpCount);
    recordScalar("confusionMatrix_FN", (double)fnCount);
    recordScalar("detectionPrecision", precision);
    recordScalar("detectionRecall",    recall);
    recordScalar("detectionF1Score",   f1);
    recordScalar("detectionAccuracy",  accuracy);

    // MI-IDS-specific bookkeeping
    if (latencySamples > 0)
        recordScalar("miidsAvgInferenceLatencyMs",
                     latencySumMs / (double)latencySamples);
    recordScalar("miidsInferenceSamples", (double)latencySamples);
    recordScalar("miidsHostIsAttacker", selfIsAttacker ? 1.0 : 0.0);
    recordScalar("miidsAttackIntensity", selfAttackIntensity);

    // Evaluation-protocol provenance so that every number in the paper can be
    // traced back to how many decisions it rests on.
    recordScalar("miidsSubjectsScored",   (double)states.size());
    recordScalar("miidsAbstentions",      (double)abstainCount);
    recordScalar("miidsUnobservedTicks",  (double)unobservedTicks);
    recordScalar("miidsNoEvidenceSkips", (double)noEvidenceSubjects);
    // Record the sum and the count separately as well as the mean. A run is
    // aggregated over many monitor modules, and a mean of per-module means is
    // not the mean of the run; the analysis script needs the two components to
    // pool correctly.
    if (detectionDelayCount > 0) {
        recordScalar("miidsMeanDetectionDelayS",
                     detectionDelaySum / (double)detectionDelayCount);
        recordScalar("miidsDetectionDelaySumS", detectionDelaySum);
        recordScalar("miidsDetectionDelayCount", (double)detectionDelayCount);
    }
    recordScalar("miidsDetectedAttackers", (double)firstFlagged.size());
    recordScalar("miidsObservedAttackers", (double)firstAttackSeen.size());

    // False-quarantine accounting: benign neighbours that ended the run in
    // quarantine. Reviewer-requested wrongful-isolation metric.
    long quarantinedBenign = 0, quarantinedMalicious = 0;
    for (auto &kv : states) {
        if (!kv.second.quarantined) continue;
        if (subjectIsAttacker(kv.first)) ++quarantinedMalicious;
        else                             ++quarantinedBenign;
    }
    recordScalar("miidsQuarantinedBenign",    (double)quarantinedBenign);
    recordScalar("miidsQuarantinedMalicious", (double)quarantinedMalicious);
}

} // namespace veremivndn
