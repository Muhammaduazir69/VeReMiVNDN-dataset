//
// VeReMiVNDN - Intrusion Detection System Header
// Detects malicious behavior and maintains trust scores
//

#ifndef __VEREMIVNDN_IDS_H
#define __VEREMIVNDN_IDS_H

#include <omnetpp.h>
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <vector>
#include <string>
#include <deque>

using namespace omnetpp;

namespace veremivndn {

// Detection result
enum DetectionResult {
    BENIGN,
    SUSPICIOUS,
    MALICIOUS
};

// Attack types
enum AttackType {
    ATTACK_INTEREST_FLOODING,
    ATTACK_CONTENT_POISONING,
    ATTACK_CACHE_POLLUTION,
    ATTACK_SYBIL,
    ATTACK_REPLAY,
    ATTACK_UNKNOWN
};

// Node behavior profile
struct NodeProfile {
    std::string nodeId;
    double trustScore;
    int interestsSent;
    int dataSent;
    int nacksSent;
    int duplicateInterests;
    int malformedPackets;
    int signatureFailures;
    simtime_t lastActivity;
    std::deque<simtime_t> requestTimestamps;  // For rate detection
};

class IDS : public cSimpleModule {
protected:
    // Configuration
    std::string detectionMethod;  // "Signature", "Anomaly", "Hybrid"
    double detectionThreshold;
    bool enableLogging;
    bool enableTrustModel;

    // Node profiles for trust scoring
    std::map<std::string, NodeProfile> nodeProfiles;

    // Detection thresholds
    double interestFloodingRate;  // interests/sec threshold
    double trustDecayFactor;
    double trustRecoveryRate;
    double anomalyThreshold;

    // Statistics
    int totalPacketsAnalyzed;
    int attacksDetected;
    int falsePositives;
    int falseNegatives;

    // Signals
    simsignal_t attackDetectedSignal;
    simsignal_t trustScoreSignal;
    simsignal_t anomalyScoreSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Detection methods
    virtual DetectionResult analyzeInterest(InterestPacket *interest, const std::string &sourceId);
    virtual DetectionResult analyzeData(DataPacket *data, const std::string &sourceId);
    virtual bool detectInterestFlooding(const std::string &sourceId);
    virtual bool detectContentPoisoning(DataPacket *data);
    virtual bool detectSybilAttack(const std::string &sourceId);
    virtual bool detectReplayAttack(cPacket *pkt);

    // Trust management
    virtual void updateTrustScore(const std::string &nodeId, DetectionResult result);
    virtual double getTrustScore(const std::string &nodeId);
    virtual NodeProfile& getOrCreateProfile(const std::string &nodeId);

    // Anomaly detection
    virtual double computeAnomalyScore(const NodeProfile &profile);

    // Helpers
    virtual void logDetection(const std::string &nodeId, AttackType attackType);
    virtual void emitDetection(AttackType attackType);

public:
    IDS();
    virtual ~IDS();

    // Public interface
    DetectionResult checkPacket(cPacket *pkt, const std::string &sourceId);
    double getNodeTrustScore(const std::string &nodeId);
};

Define_Module(IDS);

} // namespace veremivndn

#endif
