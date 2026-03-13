//
// VeReMiVNDN - Intrusion Detection System Implementation
//

#include "IDS.h"
#include <algorithm>

namespace veremivndn {

Define_Module(IDS);

IDS::IDS() : totalPacketsAnalyzed(0), attacksDetected(0),
             falsePositives(0), falseNegatives(0) {}

IDS::~IDS() {}

void IDS::initialize() {
    detectionMethod = par("detectionMethod").stdstringValue();
    detectionThreshold = par("detectionThreshold");
    enableLogging = par("enableLogging");
    enableTrustModel = par("enableTrustModel");

    // Detection thresholds
    interestFloodingRate = par("interestFloodingRate").doubleValue();
    trustDecayFactor = par("trustDecayFactor").doubleValue();
    trustRecoveryRate = par("trustRecoveryRate").doubleValue();
    anomalyThreshold = par("anomalyThreshold").doubleValue();

    // Register signals
    attackDetectedSignal = registerSignal("attackDetected");
    trustScoreSignal = registerSignal("trustScore");
    anomalyScoreSignal = registerSignal("anomalyScore");

    EV_INFO << "IDS initialized: method=" << detectionMethod
            << ", threshold=" << detectionThreshold << endl;
}

void IDS::handleMessage(cMessage *msg) {
    // IDS processes packets sent to it for analysis
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(msg)) {
        // Use forwardingHint as source identifier (set by Sybil attacks) or default
        std::string sourceId = interest->getForwardingHint();
        if (sourceId.empty()) {
            sourceId = "Node_Unknown";
        }

        DetectionResult result = analyzeInterest(interest, sourceId);
        updateTrustScore(sourceId, result);

        if (result == MALICIOUS) {
            emitDetection(ATTACK_INTEREST_FLOODING);
        }

        totalPacketsAnalyzed++;
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(msg)) {
        std::string sourceId = data->getSignerId();
        if (sourceId.empty()) {
            sourceId = "Unknown";
        }

        DetectionResult result = analyzeData(data, sourceId);
        updateTrustScore(sourceId, result);

        if (result == MALICIOUS) {
            emitDetection(ATTACK_CONTENT_POISONING);
        }

        totalPacketsAnalyzed++;
    }

    // Forward packet to output (IDS is passive)
    send(msg, "out");
}

void IDS::finish() {
    recordScalar("totalPacketsAnalyzed", totalPacketsAnalyzed);
    recordScalar("attacksDetected", attacksDetected);
    recordScalar("falsePositives", falsePositives);
    recordScalar("falseNegatives", falseNegatives);

    double detectionRate = totalPacketsAnalyzed > 0 ?
        (double)attacksDetected / totalPacketsAnalyzed : 0;
    recordScalar("detectionRate", detectionRate);

    // Record final trust scores
    for (auto &pair : nodeProfiles) {
        std::string statName = "finalTrustScore_" + pair.first;
        recordScalar(statName.c_str(), pair.second.trustScore);
    }

    EV_INFO << "IDS finishing: " << attacksDetected << " attacks detected from "
            << totalPacketsAnalyzed << " packets" << endl;
}

DetectionResult IDS::analyzeInterest(InterestPacket *interest, const std::string &sourceId) {
    NodeProfile &profile = getOrCreateProfile(sourceId);
    profile.interestsSent++;
    profile.lastActivity = simTime();
    profile.requestTimestamps.push_back(simTime());

    // Keep only recent timestamps (last 10 seconds)
    while (!profile.requestTimestamps.empty() &&
           simTime() - profile.requestTimestamps.front() > 10.0) {
        profile.requestTimestamps.pop_front();
    }

    // Check for Interest Flooding
    if (detectInterestFlooding(sourceId)) {
        if (enableLogging) {
            EV_WARN << "IDS: Interest Flooding detected from " << sourceId << endl;
        }
        return MALICIOUS;
    }

    // Check for Sybil attack
    if (detectSybilAttack(sourceId)) {
        if (enableLogging) {
            EV_WARN << "IDS: Sybil attack detected: " << sourceId << endl;
        }
        return MALICIOUS;
    }

    // Anomaly detection
    if (detectionMethod == "Anomaly" || detectionMethod == "Hybrid") {
        double anomalyScore = computeAnomalyScore(profile);
        emit(anomalyScoreSignal, anomalyScore);

        if (anomalyScore > anomalyThreshold) {
            return SUSPICIOUS;
        }
    }

    return BENIGN;
}

DetectionResult IDS::analyzeData(DataPacket *data, const std::string &sourceId) {
    NodeProfile &profile = getOrCreateProfile(sourceId);
    profile.dataSent++;
    profile.lastActivity = simTime();

    // Check signature validity
    if (data->isSigned()) {
        std::string sig = data->getSignature();
        if (sig.empty() || sig == "INVALID") {
            profile.signatureFailures++;
            return MALICIOUS;
        }
    }

    // Check for Content Poisoning
    if (detectContentPoisoning(data)) {
        if (enableLogging) {
            EV_WARN << "IDS: Content Poisoning detected from " << sourceId << endl;
        }
        return MALICIOUS;
    }

    // Check trust score
    if (enableTrustModel && profile.trustScore < 0.3) {
        return SUSPICIOUS;
    }

    return BENIGN;
}

bool IDS::detectInterestFlooding(const std::string &sourceId) {
    NodeProfile &profile = getOrCreateProfile(sourceId);

    // Calculate current request rate
    if (profile.requestTimestamps.size() < 2) {
        return false;
    }

    simtime_t timeWindow = simTime() - profile.requestTimestamps.front();
    if (timeWindow < 0.1) return false;  // Too short to evaluate

    double requestRate = profile.requestTimestamps.size() / timeWindow.dbl();

    return requestRate > interestFloodingRate;
}

bool IDS::detectContentPoisoning(DataPacket *data) {
    std::string content = data->getContent();

    // Simple heuristic: check for suspicious content patterns
    if (content.find("FAKE_DATA") != std::string::npos ||
        content.find("POISON") != std::string::npos ||
        content.find("MALICIOUS") != std::string::npos) {
        return true;
    }

    // Check trust score of signer
    if (data->getTrustScore() < 0.3) {
        return true;
    }

    return false;
}

bool IDS::detectSybilAttack(const std::string &sourceId) {
    // Detect Sybil by checking for suspicious ID patterns
    if (sourceId.find("SYBIL_") != std::string::npos) {
        return true;
    }

    // Check for multiple IDs from same source (would need additional context)
    NodeProfile &profile = getOrCreateProfile(sourceId);

    // Rapid identity creation pattern
    if (profile.interestsSent > 100 &&
        (simTime() - profile.lastActivity) < 1.0) {
        return true;
    }

    return false;
}

bool IDS::detectReplayAttack(cPacket *pkt) {
    // Would need to maintain packet history
    // Simplified version checks timestamp
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(pkt)) {
        simtime_t pktTime = interest->getTimestamp();
        if (simTime() - pktTime > 30.0) {  // Packet too old
            return true;
        }
    }
    return false;
}

void IDS::updateTrustScore(const std::string &nodeId, DetectionResult result) {
    if (!enableTrustModel) return;

    NodeProfile &profile = getOrCreateProfile(nodeId);

    switch (result) {
        case BENIGN:
            // Gradually recover trust
            profile.trustScore = std::min(1.0,
                profile.trustScore + trustRecoveryRate * 0.01);
            break;

        case SUSPICIOUS:
            // Small penalty
            profile.trustScore *= (1.0 - trustDecayFactor * 0.1);
            break;

        case MALICIOUS:
            // Large penalty
            profile.trustScore *= (1.0 - trustDecayFactor);
            profile.malformedPackets++;
            break;
    }

    // Emit trust score
    emit(trustScoreSignal, profile.trustScore);

    if (enableLogging && result != BENIGN) {
        EV_INFO << "Trust score for " << nodeId << ": "
                << profile.trustScore << endl;
    }
}

double IDS::getTrustScore(const std::string &nodeId) {
    return getOrCreateProfile(nodeId).trustScore;
}

NodeProfile& IDS::getOrCreateProfile(const std::string &nodeId) {
    auto it = nodeProfiles.find(nodeId);
    if (it == nodeProfiles.end()) {
        NodeProfile profile;
        profile.nodeId = nodeId;
        profile.trustScore = 1.0;  // Start with full trust
        profile.interestsSent = 0;
        profile.dataSent = 0;
        profile.nacksSent = 0;
        profile.duplicateInterests = 0;
        profile.malformedPackets = 0;
        profile.signatureFailures = 0;
        profile.lastActivity = simTime();
        nodeProfiles[nodeId] = profile;
        return nodeProfiles[nodeId];
    }
    return it->second;
}

double IDS::computeAnomalyScore(const NodeProfile &profile) {
    // Compute anomaly score based on multiple factors
    double score = 0.0;

    // Factor 1: Request rate anomaly
    if (!profile.requestTimestamps.empty()) {
        simtime_t timeWindow = simTime() - profile.requestTimestamps.front();
        if (timeWindow > 0) {
            double rate = profile.requestTimestamps.size() / timeWindow.dbl();
            if (rate > interestFloodingRate * 0.5) {
                score += 0.3;
            }
        }
    }

    // Factor 2: Signature failures
    if (profile.signatureFailures > 0) {
        score += 0.3;
    }

    // Factor 3: Low trust score
    if (profile.trustScore < 0.5) {
        score += 0.2;
    }

    // Factor 4: Malformed packets
    if (profile.malformedPackets > 5) {
        score += 0.2;
    }

    return std::min(1.0, score);
}

void IDS::logDetection(const std::string &nodeId, AttackType attackType) {
    std::string attackName;
    switch (attackType) {
        case ATTACK_INTEREST_FLOODING: attackName = "Interest Flooding"; break;
        case ATTACK_CONTENT_POISONING: attackName = "Content Poisoning"; break;
        case ATTACK_CACHE_POLLUTION: attackName = "Cache Pollution"; break;
        case ATTACK_SYBIL: attackName = "Sybil Attack"; break;
        case ATTACK_REPLAY: attackName = "Replay Attack"; break;
        default: attackName = "Unknown Attack"; break;
    }

    EV_WARN << "IDS DETECTION: " << attackName << " from " << nodeId
            << " at " << simTime() << endl;

    if (enableLogging) {
        // Could write to file for dataset generation
    }
}

void IDS::emitDetection(AttackType attackType) {
    attacksDetected++;
    emit(attackDetectedSignal, (long)attackType);
}

DetectionResult IDS::checkPacket(cPacket *pkt, const std::string &sourceId) {
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(pkt)) {
        return analyzeInterest(interest, sourceId);
    } else if (DataPacket *data = dynamic_cast<DataPacket*>(pkt)) {
        return analyzeData(data, sourceId);
    }
    return BENIGN;
}

double IDS::getNodeTrustScore(const std::string &nodeId) {
    return getTrustScore(nodeId);
}

} // namespace veremivndn
