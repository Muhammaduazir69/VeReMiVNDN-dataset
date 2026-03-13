//
// VeReMiVNDN - IDS Feature Extractor Module
//
// Extracts comprehensive features from VNDN traffic for ML-based detection
//

#ifndef __VEREMIVNDN_FEATUREEXTRACTOR_H
#define __VEREMIVNDN_FEATUREEXTRACTOR_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <vector>
#include <deque>
#include <string>

using namespace omnetpp;

namespace veremivndn {

/**
 * Feature Vector - Contains all extracted features
 */
struct FeatureVector {
    // Timestamp
    simtime_t timestamp;
    int nodeId;

    // Network Features (10 features)
    double interestRate;              // Interests per second
    double dataRate;                  // Data packets per second
    double avgInterestSize;           // Average Interest packet size
    double avgDataSize;               // Average Data packet size
    double packetDropRate;            // Packet drop rate
    double avgHopCount;               // Average hop count
    double interestDataRatio;         // Interest/Data ratio
    double nackRate;                  // NACK rate
    double avgRTT;                    // Average round-trip time
    double jitter;                    // Packet jitter

    // NDN-Specific Features (15 features)
    double pitOccupancy;              // PIT occupancy ratio (0-1)
    uint32_t pitSize;                 // Current PIT size
    double avgPitLifetime;            // Average PIT entry lifetime
    double pitSatisfactionRate;       // PIT satisfaction ratio
    double fibSize;                   // FIB size
    double avgFibEntryHopCount;       // Average FIB entry cost
    double csOccupancy;               // CS occupancy ratio (0-1)
    uint32_t csSize;                  // Current cache size
    double cacheHitRatio;             // Cache hit ratio
    double cacheMissRatio;            // Cache miss ratio
    double avgCacheEntryAge;          // Average cache entry age
    double contentStoreDiversity;     // Unique content in CS
    double pendingInterestDiversity;  // Unique interests in PIT
    double faceUtilization;           // Average face utilization
    double avgForwardingDelay;        // Average forwarding delay

    // Trust & Security Features (8 features)
    double avgTrustScore;             // Average trust score
    double minTrustScore;             // Minimum trust score
    double maxTrustScore;             // Maximum trust score
    double trustVariance;             // Trust score variance
    double signatureVerificationRate; // Signature verification rate
    double signatureFailureRate;      // Signature failure rate
    double unsignedDataRatio;         // Ratio of unsigned data
    double lowTrustPacketRatio;       // Ratio of low-trust packets

    // Temporal Features (10 features)
    double interestRateVariance;      // Variance in interest rate
    double burstiness;                // Traffic burstiness
    double periodicity;               // Traffic periodicity
    double trendSlope;                // Traffic trend (increasing/decreasing)
    double interArrivalTimeMean;      // Mean inter-arrival time
    double interArrivalTimeStdDev;    // Std dev of inter-arrival time
    double windowInterestCount;       // Interests in time window
    double windowDataCount;           // Data in time window
    double shortTermInterestRate;     // Recent interest rate
    double longTermInterestRate;      // Historical interest rate

    // Privacy Features (5 features)
    double nameEntropy;               // Entropy of content names
    double uniqueNamesRatio;          // Unique names ratio
    double repeatedNonceRatio;        // Repeated nonce ratio
    double locationExposureRisk;      // Location exposure metric
    double anonymityScore;            // Anonymity metric

    // Mobility Features (6 features)
    double speed;                     // Node speed (m/s)
    double acceleration;              // Node acceleration
    double direction;                 // Movement direction (degrees)
    double positionX;                 // X coordinate
    double positionY;                 // Y coordinate
    double neighborCount;             // Number of neighbors

    // Attack-Specific Indicators (10 features)
    double interestFloodingScore;     // Flooding indicator
    double poisoningScore;            // Content poisoning indicator
    double cachePollutionScore;       // Cache pollution indicator
    double timingAttackScore;         // Timing attack indicator
    double replayScore;               // Replay attack indicator
    double sybilScore;                // Sybil attack indicator
    double collusionScore;            // Collusion indicator
    double hijackingScore;            // Prefix hijacking indicator
    double grayHoleScore;             // Gray hole indicator
    double jammingScore;              // Jamming indicator

    // Statistical Aggregates (5 features)
    double totalPackets;              // Total packets in window
    double totalBytes;                // Total bytes in window
    double avgPacketSize;             // Average packet size
    double packetSizeVariance;        // Packet size variance
    double trafficEntropy;            // Overall traffic entropy
};

/**
 * Time Window Statistics
 */
struct WindowStatistics {
    simtime_t windowStart;
    simtime_t windowEnd;
    uint64_t interestCount;
    uint64_t dataCount;
    uint64_t nackCount;
    double totalInterestSize;
    double totalDataSize;
    std::vector<simtime_t> timestamps;
    std::vector<std::string> contentNames;
    std::vector<int> nonces;
};

/**
 * FeatureExtractor
 *
 * Extracts comprehensive feature vectors from VNDN traffic for:
 * - Anomaly detection
 * - ML-based attack classification
 * - Dataset generation
 * - Behavioral analysis
 */
class FeatureExtractor : public cSimpleModule
{
private:
    // Configuration
    double extractionInterval;        // Feature extraction interval
    double timeWindowSize;            // Time window for temporal features
    int maxHistorySize;               // Max history entries to keep
    bool enableRealTimeExtraction;    // Real-time vs batch extraction

    // Node information
    int nodeId;
    std::string nodeIdentifier;

    // Traffic history
    std::deque<WindowStatistics> windowHistory;
    WindowStatistics currentWindow;

    // Packet tracking
    std::map<std::string, simtime_t> pendingInterests;  // For RTT calculation
    std::map<std::string, int> nameFrequency;
    std::map<int, int> nonceFrequency;

    // Statistics accumulation
    uint64_t totalInterests;
    uint64_t totalData;
    uint64_t totalNacks;
    uint64_t totalDrops;
    double totalBytes;

    // Timers
    cMessage *extractionTimer;

    // Signals
    simsignal_t featureExtractionSignal;
    simsignal_t anomalyScoreSignal;

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Feature extraction pipeline
    FeatureVector extractAllFeatures();
    void updateWindowStatistics(cMessage *packet);
    void finalizeWindow();
    void slideWindow();

    // Network features
    void extractNetworkFeatures(FeatureVector &fv);
    double calculateInterestRate();
    double calculateDataRate();
    double calculatePacketDropRate();
    double calculateAverageRTT();
    double calculateJitter();

    // NDN features
    void extractNDNFeatures(FeatureVector &fv);
    double queryPITOccupancy();
    uint32_t queryPITSize();
    double queryCacheHitRatio();
    double queryFIBSize();
    double calculateAverageForwardingDelay();

    // Trust features
    void extractTrustFeatures(FeatureVector &fv);
    double calculateAverageTrustScore();
    double calculateSignatureVerificationRate();
    double calculateUnsignedDataRatio();

    // Temporal features
    void extractTemporalFeatures(FeatureVector &fv);
    double calculateBurstiness();
    double calculatePeriodicity();
    double calculateTrendSlope();
    double calculateInterArrivalTimeStats();
    double calculateRateVariance();

    // Privacy features
    void extractPrivacyFeatures(FeatureVector &fv);
    double calculateNameEntropy();
    double calculateUniqueNamesRatio();
    double calculateRepeatedNonceRatio();
    double calculateLocationExposureRisk();

    // Mobility features
    void extractMobilityFeatures(FeatureVector &fv);
    double getNodeSpeed();
    double getNodeAcceleration();
    int getNeighborCount();

    // Attack-specific indicators
    void extractAttackIndicators(FeatureVector &fv);
    double calculateInterestFloodingScore();
    double calculatePoisoningScore();
    double calculateCachePollutionScore();
    double calculateTimingAttackScore();
    double calculateReplayScore();
    double calculateSybilScore();
    double calculateCollusionScore();
    double calculateHijackingScore();
    double calculateGrayHoleScore();
    double calculateJammingScore();

    // Statistical aggregates
    void extractStatisticalFeatures(FeatureVector &fv);
    double calculateTrafficEntropy();
    double calculatePacketSizeVariance();

    // Helper methods
    std::map<std::string, double> featureVectorToMap(const FeatureVector &fv);
    void normalizeFeatures(FeatureVector &fv);

public:
    FeatureExtractor();
    virtual ~FeatureExtractor();

    // Public interface
    FeatureVector getCurrentFeatures();
    void notifyPacket(cMessage *packet);
    void setExtractionInterval(double interval);
};

} // namespace veremivndn

#endif // __VEREMIVNDN_FEATUREEXTRACTOR_H
