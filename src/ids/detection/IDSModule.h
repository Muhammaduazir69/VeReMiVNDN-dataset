//
// VeReMiVNDN - Intrusion Detection System Module
//
// Main IDS module for detecting attacks and collecting data for ML training
//

#ifndef __VEREMIVNDN_IDSMODULE_H
#define __VEREMIVNDN_IDSMODULE_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../../ndn/packets/NdnPackets_m.h"
// #include "../features/FeatureExtractor.h"  // TODO: Implement FeatureExtractor
// #include "../logging/DataCollector.h"      // TODO: Implement DataCollector
#include <map>
#include <vector>
#include <deque>
#include <fstream>

using namespace omnetpp;

namespace veremivndn {

/**
 * Detection Method Types
 */
enum class DetectionMethod {
    ANOMALY,        // Anomaly-based detection
    SIGNATURE,      // Signature-based detection
    HYBRID,         // Combination of both
    ML_BASED        // Machine learning-based
};

/**
 * Detection Result
 */
struct DetectionResult {
    bool isAttack;
    std::string attackType;
    double confidenceScore;
    simtime_t detectionTime;
    std::string evidence;
};

/**
 * Traffic Statistics for Anomaly Detection
 */
struct TrafficStatistics {
    // Interest statistics
    double interestRate;
    double avgInterestSize;
    uint64_t totalInterests;

    // Data statistics
    double dataRate;
    double avgDataSize;
    uint64_t totalData;

    // PIT statistics
    uint32_t pitSize;
    double pitOccupancy;
    double avgPitLifetime;

    // Cache statistics
    double cacheHitRatio;
    uint32_t cacheSize;
    double cacheOccupancy;

    // Trust metrics
    double avgTrustScore;
    uint32_t lowTrustCount;

    // Timing metrics
    double avgResponseTime;
    double maxResponseTime;

    // Update timestamp
    simtime_t lastUpdate;
};

/**
 * IDSModule
 *
 * Main Intrusion Detection System module that:
 * 1. Monitors all NDN traffic
 * 2. Extracts features for detection
 * 3. Performs attack detection
 * 4. Logs data for ML training
 * 5. Generates ground truth labels
 * 6. Receives signals from all 20 attack modules
 */
class IDSModule : public cSimpleModule, public cListener
{
private:
    // Configuration
    DetectionMethod detectionMethod;
    double detectionThreshold;
    bool loggingEnabled;
    bool realtimeDetection;

    // Node information
    int nodeId;
    std::string nodeIdentifier;

    // Feature extraction
    // FeatureExtractor *featureExtractor;  // TODO: Implement

    // Data collection and logging
    // DataCollector *dataCollector;  // TODO: Implement
    static std::ofstream csvLog;
    static std::ofstream jsonLog;
    static bool filesInitialized;
    static int activeInstances;

    // Traffic monitoring
    TrafficStatistics currentStats;
    TrafficStatistics baselineStats;
    std::deque<TrafficStatistics> statisticsHistory;
    const int HISTORY_SIZE = 100;

    // Detection state
    uint32_t detectionCount;
    std::map<std::string, uint32_t> detectedAttacks;
    std::vector<DetectionResult> detectionHistory;

    // Attack-specific counters (tracking signals from all 20 attacks)
    struct AttackCounters {
        // Attack #1-9 (existing)
        uint64_t interestFloodingDetected = 0;
        uint64_t contentPoisoningDetected = 0;
        uint64_t cachePollutionDetected = 0;
        uint64_t timingAttackDetected = 0;
        uint64_t sybilAttackDetected = 0;
        uint64_t collusionAttackDetected = 0;
        uint64_t privacyAttackDetected = 0;
        uint64_t trustAttackDetected = 0;
        uint64_t selectiveForwardingDetected = 0;

        // Attack #10-20 (new attacks)
        uint64_t signatureForgeryDetected = 0;
        uint64_t privacyDeanonymizationDetected = 0;
        uint64_t interestAggregationDetected = 0;
        uint64_t cacheInvalidationDetected = 0;
        uint64_t radioJammingDetected = 0;
        uint64_t cachePrivacyLeakageDetected = 0;
        uint64_t producerImpersonationDetected = 0;
        uint64_t cachePartitioningDetected = 0;
        uint64_t routingInfoFloodDetected = 0;
        uint64_t nameEnumerationDetected = 0;
        uint64_t mlEvasionDetected = 0;

        // Activity indicators
        uint64_t totalPacketsModified = 0;
        uint64_t totalPacketsDropped = 0;
        uint64_t totalMaliciousPackets = 0;
    } attackCounters;

    // Thresholds and parameters
    struct DetectionThresholds {
        double interestRateThreshold;
        double pitOccupancyThreshold;
        double cacheHitRatioThreshold;
        double trustScoreThreshold;
        double responseTimeThreshold;
    } thresholds;

    // Timers
    cMessage *monitoringTimer;
    cMessage *loggingTimer;
    simtime_t monitoringInterval;
    simtime_t loggingInterval;

    // Statistics signals
    simsignal_t attackDetectedSignal;
    simsignal_t falsePositiveSignal;
    simsignal_t falseNegativeSignal;
    simsignal_t detectionAccuracySignal;
    simsignal_t confidenceSignal;

    // Confusion matrix for evaluation
    struct ConfusionMatrix {
        uint32_t truePositive = 0;
        uint32_t trueNegative = 0;
        uint32_t falsePositive = 0;
        uint32_t falseNegative = 0;
    } confusionMatrix;

protected:
    /**
     * OMNeT++ lifecycle
     */
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    /**
     * Traffic monitoring
     */
    void monitorTraffic();
    void updateStatistics(cMessage *packet);
    void updateBaseline();
    bool isAnomalous(const TrafficStatistics &stats);

    /**
     * Detection methods
     */
    DetectionResult detectAnomaly();
    DetectionResult detectBySignature();
    DetectionResult detectHybrid();
    DetectionResult detectByML();

    /**
     * Signal subscription and handling
     */
    void subscribeToAttackSignals();
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, long value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details) override;
    void processAttackSignal(cComponent *source, simsignal_t signalID, long value);

    /**
     * Specific attack detectors for all 20 attacks
     */
    // Existing attacks (1-9)
    bool detectInterestFlooding();
    bool detectContentPoisoning();
    bool detectCachePollution();
    bool detectTimingAttack();
    bool detectSybilAttack();
    bool detectCollusionAttack();

    // New attacks (10-20)
    bool detectSignatureForgery();
    bool detectPrivacyDeanonymization();
    bool detectInterestAggregation();
    bool detectCacheInvalidation();
    bool detectRadioJamming();
    bool detectCachePrivacyLeakage();
    bool detectProducerImpersonation();
    bool detectCachePartitioning();
    bool detectRoutingInfoFlood();
    bool detectNameEnumeration();
    bool detectMLEvasion();

    /**
     * Feature extraction for ML
     */
    std::map<std::string, double> extractAllFeatures();
    std::map<std::string, double> extractNetworkFeatures();
    std::map<std::string, double> extractNDNFeatures();
    std::map<std::string, double> extractTemporalFeatures();
    std::map<std::string, double> extractTrustFeatures();
    std::map<std::string, double> extractMobilityFeatures();

    /**
     * Data logging for dataset generation
     */
    void logDetectionEvent(const DetectionResult &result);
    void logFeatures(const std::map<std::string, double> &features);
    void logGroundTruth();

    /**
     * Output format generation
     */
    void writeCSVHeader();
    void writeCSVRow(const std::map<std::string, double> &features, const std::string &label);
    void writeJSONEntry(const std::map<std::string, double> &features, const DetectionResult &result);

    /**
     * Threshold calculation
     */
    void calculateDynamicThresholds();
    void updateThresholdsFromHistory();

    /**
     * Evaluation metrics
     */
    void updateConfusionMatrix(bool actualAttack, bool detectedAttack);
    double calculateAccuracy() const;
    double calculatePrecision() const;
    double calculateRecall() const;
    double calculateF1Score() const;

public:
    IDSModule();
    virtual ~IDSModule();

    // Public interface
    bool checkPacket(cMessage *packet);
    void reportAttack(const std::string &attackType, double confidence);
    const TrafficStatistics& getCurrentStatistics() const { return currentStats; }
};

} // namespace veremivndn

#endif // __VEREMIVNDN_IDSMODULE_H
