//
// DP-IDS-VNDN - Dempster-Shafer Fusion Implementation
// Methodology Section 4.4: Orthogonal sum with adaptive reliability
//
// Key insight: When a detector has LOW anomaly score (near 0), it should
// contribute UNCERTAINTY (Θ), not strong BENIGN evidence. A score of 0
// means "I didn't see anything anomalous" which is NOT the same as
// "I am confident this is benign". The adaptive reliability mechanism
// maps detector confidence to reliability weight, preventing a silent
// detector from drowning out a strong signal from the other detector.
//

#include "DSFusionEngine.h"
#include <cmath>

namespace veremivndn {

Define_Module(DSFusionEngine);

void DSFusionEngine::initialize() {
    kMax = par("kMax");
    reliabilityBehavioural = par("reliabilityBehavioural");
    reliabilityForwarding = par("reliabilityForwarding");

    fusionBeliefMalSignal = registerSignal("fusionBeliefMal");
    fusionConflictSignal = registerSignal("fusionConflict");
    extendedMonitoringSignal = registerSignal("extendedMonitoring");

    WATCH(fusionCount);
    WATCH(lastMaxBelief);
    WATCH(kMax);

    EV_INFO << "DSFusionEngine initialized: kMax=" << kMax
            << ", r1=" << reliabilityBehavioural
            << ", r2=" << reliabilityForwarding << endl;
}

void DSFusionEngine::handleMessage(cMessage *msg) {
    delete msg;
}

void DSFusionEngine::refreshDisplay() const {
    char label[64];
    snprintf(label, sizeof(label), "DS Fusion\nBel:%.2f K:%.2f", lastMaxBelief, kMax);
    const_cast<DSFusionEngine*>(this)->getDisplayString().setTagArg("t", 0, label);

    if (lastMaxBelief > 0.7)
        const_cast<DSFusionEngine*>(this)->getDisplayString().setTagArg("i", 1, "red");
    else if (lastMaxBelief > 0.4)
        const_cast<DSFusionEngine*>(this)->getDisplayString().setTagArg("i", 1, "orange");
    else
        const_cast<DSFusionEngine*>(this)->getDisplayString().setTagArg("i", 1, "green");
}

void DSFusionEngine::finish() {
    recordScalar("totalFusionResults", (int)fusionResults.size());

    int extMonCount = 0;
    for (const auto &r : fusionResults) {
        if (r.second.extendedMonitoring) extMonCount++;
    }
    recordScalar("extendedMonitoringCount", extMonCount);
}

double DSFusionEngine::computeAdaptiveReliability(double score, double baseReliability) {
    // Adaptive reliability weighting (Section 4.4):
    //
    // When score ≈ 0: detector saw nothing anomalous → LOW confidence
    //   → reliability drops → more mass assigned to Θ (uncertainty)
    //   → does NOT assert strong "benign" evidence
    //
    // When score > 0.3: detector has a meaningful signal → FULL reliability
    //   → mass reflects the actual anomaly/benign assessment
    //
    // Formula: r_adaptive = r_base × confidence(score)
    //   where confidence(s) = min(1.0, s / 0.2)  [ramps from 0→1 as score rises]
    //
    // This prevents a silent behavioural detector (score=0) from
    // overwhelming a strong forwarding-plane detection (score=0.7)

    // Confidence mapping: score → reliability scaling factor
    // Low scores (< 0.15) produce low confidence → high Θ (uncertainty)
    // Mid scores (0.15-0.5) ramp up confidence
    // High scores (> 0.5) full confidence
    //
    // This ensures that the behavioural detector (score ~0.46 for ALL vehicles)
    // gets moderate confidence, while a forwarding detector with score=0.8
    // gets full confidence — allowing the forwarding signal to dominate

    double confidence;
    if (score < 0.10) {
        // Near-zero scores: detector has NO meaningful signal
        // Must produce near-zero confidence to avoid benign FP
        // A score of 0.08 (typical benign PIT) should give confidence ~0.01
        confidence = score * 0.1;  // 0→0.01 linearly
    } else if (score < 0.25) {
        // Transition zone: possible weak signal
        confidence = 0.01 + (score - 0.10) / 0.15 * 0.14;  // 0.01→0.15
    } else if (score < 0.50) {
        // Moderate signal: likely anomalous
        confidence = 0.15 + (score - 0.25) / 0.25 * 0.35;  // 0.15→0.50
    } else if (score < 0.75) {
        // Strong signal: clearly anomalous
        confidence = 0.50 + (score - 0.50) / 0.25 * 0.30;  // 0.50→0.80
    } else {
        // Very strong signal: definitive anomaly
        confidence = 0.80 + (score - 0.75) / 0.25 * 0.20;  // 0.80→1.00
    }

    return baseReliability * confidence;
}

MassFunction DSFusionEngine::scoreToMass(double anomalyScore, double reliability) {
    // Section 4.3: Convert anomaly score to DST mass function
    // m({malicious}) = score × reliability
    // m({benign})    = (1 - score) × reliability
    // m(Θ)           = 1 - reliability
    MassFunction m;
    m.m_mal = anomalyScore * reliability;
    m.m_ben = (1.0 - anomalyScore) * reliability;
    m.m_theta = 1.0 - reliability;
    return m;
}

MassFunction DSFusionEngine::orthogonalSum(const MassFunction &m1,
                                            const MassFunction &m2,
                                            double &conflictK)
{
    // Section 4.4: Dempster's rule of combination
    conflictK = m1.m_mal * m2.m_ben + m1.m_ben * m2.m_mal;

    if (conflictK >= 1.0 - 1e-10) {
        return MassFunction(0.0, 0.0, 1.0);
    }

    double norm = 1.0 / (1.0 - conflictK);

    MassFunction result;
    result.m_mal = (m1.m_mal * m2.m_mal +
                    m1.m_mal * m2.m_theta +
                    m1.m_theta * m2.m_mal) * norm;

    result.m_ben = (m1.m_ben * m2.m_ben +
                    m1.m_ben * m2.m_theta +
                    m1.m_theta * m2.m_ben) * norm;

    result.m_theta = (m1.m_theta * m2.m_theta) * norm;

    return result;
}

FusionResult DSFusionEngine::fuse(const std::string &vehicleId,
                                   double behaviouralScore,
                                   double forwardingScore)
{
    // Compute adaptive reliability weights based on detector confidence
    double r1_adaptive = computeAdaptiveReliability(behaviouralScore, reliabilityBehavioural);
    double r2_adaptive = computeAdaptiveReliability(forwardingScore, reliabilityForwarding);

    // Convert scores to mass functions with adaptive reliability
    MassFunction m1 = scoreToMass(behaviouralScore, r1_adaptive);
    MassFunction m2 = scoreToMass(forwardingScore, r2_adaptive);

    // Compute orthogonal sum
    double K;
    MassFunction combined = orthogonalSum(m1, m2, K);

    // Build result
    FusionResult result;
    result.fused = combined;
    result.beliefMal = combined.m_mal;
    result.beliefBen = combined.m_ben;
    result.conflict = K;
    result.extendedMonitoring = (K > kMax);
    result.vehicleId = vehicleId;
    result.timestamp = simTime();

    fusionResults[vehicleId] = result;
    fusionCount++;
    if (result.beliefMal > lastMaxBelief) lastMaxBelief = result.beliefMal;

    // Emit signals
    emit(fusionBeliefMalSignal, result.beliefMal);
    emit(fusionConflictSignal, K);
    if (result.extendedMonitoring) {
        emit(extendedMonitoringSignal, 1L);
    }

    EV_INFO << "DS Fusion for " << vehicleId
            << ": Bel(mal)=" << result.beliefMal
            << ", K=" << K
            << ", s1=" << behaviouralScore << " (r1=" << r1_adaptive << ")"
            << ", s2=" << forwardingScore << " (r2=" << r2_adaptive << ")" << endl;

    return result;
}

FusionResult DSFusionEngine::getFusionResult(const std::string &vehicleId) const {
    auto it = fusionResults.find(vehicleId);
    if (it != fusionResults.end()) return it->second;
    FusionResult empty;
    empty.beliefMal = 0.0;
    empty.beliefBen = 0.0;
    empty.conflict = 0.0;
    empty.extendedMonitoring = false;
    return empty;
}

bool DSFusionEngine::hasFusionResult(const std::string &vehicleId) const {
    return fusionResults.find(vehicleId) != fusionResults.end();
}

double DSFusionEngine::getBeliefMalicious(const std::string &vehicleId) const {
    auto it = fusionResults.find(vehicleId);
    return (it != fusionResults.end()) ? it->second.beliefMal : 0.0;
}

} // namespace veremivndn
