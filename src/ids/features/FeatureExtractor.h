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
#include <set>
#include <vector>
#include <deque>
#include <string>

using namespace omnetpp;

namespace veremivndn {

// ---------------------------------------------------------------------------
// VeReMiVNDN-EXE plane-specific feature subsystem.
//
// The five MI-IDS planes are fed by *observed* traffic only. Every quantity
// below is derived from packets this node actually received, from its own
// Content Store outcomes, or from its own 802.11p MAC counters. Ground truth
// (hasAttackModule) is never an input; it is attached to the exported CSV as a
// label column only, so that offline training and the runtime detector see
// exactly the same information.
//
// Classification is per (observer, subject) pair: the observer scores each
// neighbour whose packets it has seen, identified by NdnPacket::senderId.
// ---------------------------------------------------------------------------

enum ExePlane {
    EXE_PLANE_DATA = 0,
    EXE_PLANE_CACHE,
    EXE_PLANE_TRUST,
    EXE_PLANE_FORWARDING,
    EXE_PLANE_PHY,
    EXE_NUM_PLANES
};

// Per-plane feature-vector widths (must match MIIDSModule::planeDims and the
// input dimensions of the TorchScript detectors).
extern const int EXE_PLANE_DIMS[EXE_NUM_PLANES];

/**
 * Rolling per-subject observation record.
 *
 * All deques hold (timestamp, value) pairs and are pruned to the configured
 * plane window on every access, so each statistic is a genuine sliding-window
 * estimate rather than a run-cumulative one.
 */
struct SubjectObservation {
    // --- arrival streams -------------------------------------------------
    // Every frame heard from this subject, whatever its type. A jammer keeps
    // transmitting while its victims' frames are being destroyed, so its share
    // of the frames an observer still receives rises during a jamming burst.
    // That share is what makes a jammer attributable at all: the loss itself is
    // an environmental effect and is identical for every neighbour.
    std::deque<simtime_t> rxTimes;
    std::deque<simtime_t> interestTimes;
    std::deque<simtime_t> dataTimes;
    std::deque<simtime_t> nackTimes;
    std::deque<simtime_t> dropTimes;

    // --- data plane ------------------------------------------------------
    std::deque<std::pair<simtime_t, double>> payloadEntropy;   // bits/byte / 8
    std::deque<std::pair<simtime_t, double>> sigFailFlag;      // 1 = bad/absent sig
    std::deque<std::pair<simtime_t, double>> freshnessDev;     // seconds past freshness
    std::deque<std::pair<simtime_t, double>> staleFlag;        // 1 = received stale
    std::deque<std::pair<simtime_t, double>> nonceCollideFlag; // 1 = (name,nonce) repeat
    std::deque<std::pair<simtime_t, std::string>> signerIds;

    // --- cache plane -----------------------------------------------------
    std::deque<std::pair<simtime_t, double>> csHitFlag;        // 1 = CS hit for its Interest
    std::deque<std::pair<simtime_t, double>> respTimeHit;      // seconds
    std::deque<std::pair<simtime_t, double>> respTimeMiss;     // seconds

    // --- trust plane -----------------------------------------------------
    std::deque<std::pair<simtime_t, std::string>> requestedNames;
    std::deque<std::pair<simtime_t, double>> posX;
    std::deque<std::pair<simtime_t, double>> posY;

    // --- forwarding plane ------------------------------------------------
    std::deque<std::pair<simtime_t, double>> forwardDelay;     // seconds
    std::deque<std::pair<simtime_t, double>> satisfiedFlag;    // 1 = Interest satisfied

    simtime_t lastSeen;
};

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
class FeatureExtractor : public cSimpleModule, public cListener
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

    // ---- EXE plane-feature subsystem -----------------------------------
    bool   exePlaneFeaturesEnabled = false;
    double planeWindow = 2.0;          // sliding window for plane statistics (s)
    double positionEpsilon = 25.0;     // co-location radius for Sybil clustering (m)
    std::string planeCsvPath;          // per-tick labelled export ("" = disabled)

    std::map<std::string, SubjectObservation> subjects;

    // Observer-local co-request index: name -> senders that asked for it.
    std::deque<std::pair<simtime_t, std::pair<std::string, std::string>>> coRequestLog;

    // Observer-local 802.11p MAC counters (real Veins signals).
    double phyBusyAccum = 0.0;         // accumulated channel-busy time in window
    std::deque<std::pair<simtime_t, double>> phyBusyLog;
    std::deque<simtime_t> phyCollisionLog;
    std::deque<simtime_t> phyRetryExceededLog;
    std::deque<simtime_t> phyRxLog;
    std::deque<simtime_t> phyLossLog;
    double phyRxBaseline = 0.0;        // EWMA of received frames per window
    simtime_t phyBusySince = SIMTIME_ZERO - 1;  // <0 = channel currently idle

    // Nonce/name replay bookkeeping (observer-wide, pruned to window).
    std::map<std::string, simtime_t> seenNameNonce;

    // Outstanding Interests the observer has overheard, so that it can tell
    // whether each neighbour's requests are eventually answered. A gray hole
    // shows up here as a growing unanswered fraction with no NACK.
    struct PendingRequest { simtime_t at; std::string subject; };
    std::map<std::string, PendingRequest> outstanding;
    double interestTimeout = 4.0;   // seconds; NDN default Interest lifetime

    simsignal_t planeScoreSignals[EXE_NUM_PLANES];
    std::FILE *planeCsv = nullptr;
    long planeCsvRows = 0;
    long beaconOnlyWindows = 0;
    long evidenceWindows = 0;

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // cListener sinks for the Veins 802.11p MAC counters (PHY plane).
    virtual void receiveSignal(cComponent *src, simsignal_t id, double value,
                               cObject *details) override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, bool value,
                               cObject *details) override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, long value,
                               cObject *details) override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, cObject *value,
                               cObject *details) override;

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
    // Mobility is read from the host's Veins mobility submodule. The module
    // pointer is resolved once and cached; prevSpeed/prevSpeedTime back the
    // acceleration estimate, which is a finite difference of speed.
    // Snapshot of the last fully accumulated window.
    //
    // The extraction timer and the DataCollector's collection timer both run at
    // 1 s, so they fire at the same simulation instants. The extractor slides
    // its window as the last step of its own tick, which zeroes the counters
    // before the collector reads them; every rate and volume feature in the
    // exported dataset was therefore identically zero. Serving the collector
    // the vector computed just before the slide removes the dependence on which
    // module's self-message happens to be scheduled first.
    FeatureVector lastFeatures;
    bool haveLastFeatures = false;

    cModule *mobilityModule = nullptr;
    bool mobilityResolved = false;
    double prevSpeed = 0.0;
    simtime_t prevSpeedTime = SIMTIME_ZERO;
    cModule *resolveMobility();

    // The NDN tables live under the host's ndnNode submodule. Several table
    // features were fixed constants (a 30 % cache hit ratio, a FIB of 50
    // entries, a 2 ms forwarding delay) rather than reads of the real tables.
    cModule *csModule = nullptr;
    cModule *fibModule = nullptr;
    cModule *pitModule = nullptr;
    bool tablesResolved = false;
    void resolveTables();

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

    // ---- EXE plane-feature helpers -------------------------------------
    void initPlaneFeatures();
    void exportPlaneFeatures();
    int  resolveSubjectLabel(const std::string &subject) const;
    void pruneSubject(SubjectObservation &s, simtime_t now);
    void pruneObserverLogs(simtime_t now);
    static double shannonEntropyPerByte(const char *buf);
    static double normalizedEntropy(const std::map<std::string, int> &hist);
    void writePlaneCsvRow(const std::string &subject,
                          const std::vector<double> &v, int label);

public:
    FeatureExtractor();
    virtual ~FeatureExtractor();

    // Public interface
    FeatureVector getCurrentFeatures();
    void notifyPacket(cMessage *packet);
    void setExtractionInterval(double interval);

    // ---- EXE plane-feature public interface ----------------------------
    // Called by NDNProcessor on every observed packet / CS outcome.
    void observeInterest(InterestPacket *interest);
    void observeData(DataPacket *data);
    void observeNack(NackPacket *nack);
    // Beacons are the one transmission every neighbour makes unconditionally,
    // so they are what lets a monitor enumerate its neighbourhood at all.
    void observeBeacon(BeaconPacket *beacon);
    void observeDrop(const std::string &subject);
    void observeCsOutcome(const std::string &subject, bool hit, double responseSeconds);
    void observeForwardDelay(const std::string &subject, double seconds);

    // Veins MAC signal sink (channel busy / collision / retries).
    void observePhyBusy(double busySeconds);
    void observePhyCollision();
    void observePhyRetryExceeded();
    void observePhyRx();
    void observePhyLoss();   // frame destroyed on reception (jamming)

    // MI-IDS query interface. Returns EXE_PLANE_DIMS[plane] values in [0,1]
    // computed purely from observed traffic. Empty vector if subject unknown.
    std::vector<double> getPlaneVector(int plane, const std::string &subject);
    std::vector<std::string> observedSubjects() const;
    bool hasPlaneFeatures() const { return exePlaneFeaturesEnabled; }
    // True when the observer heard NDN traffic (not just beacons) from the
    // subject inside the current window.
    bool hasEvidenceFor(const std::string &subject) const {
        auto it = subjects.find(subject);
        if (it == subjects.end()) return false;
        const SubjectObservation &s = it->second;
        return !s.interestTimes.empty() || !s.dataTimes.empty()
            || !s.nackTimes.empty();
    }
};

} // namespace veremivndn

#endif // __VEREMIVNDN_FEATUREEXTRACTOR_H
