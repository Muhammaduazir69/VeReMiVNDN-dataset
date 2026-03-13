//
// VeReMiVNDN - Cache Timing Attack Implementation
//
// Attack #4: Cache Privacy/Timing Attack
// Layer: Caching / Privacy
// Description: Adversary probes cache to infer which content other users accessed
//              by measuring response time differences (cache hit vs miss)
// Impact: Privacy breach → user behavior tracking, location inference
//

#ifndef __VEREMIVNDN_CACHETIMINGATTACK_H
#define __VEREMIVNDN_CACHETIMINGATTACK_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <vector>
#include <string>

namespace veremivndn {

/**
 * Cache Timing Attack Modes
 */
enum class CacheProbeMode {
    TIMING_ANALYSIS,    // Measure response times to detect cache hits
    CONTENT_DISCOVERY,  // Discover what content is cached
    USER_TRACKING,      // Track user access patterns
    LOCATION_INFERENCE  // Infer user location from cached content
};

/**
 * CacheTimingAttack
 *
 * Exploits timing side-channels in NDN caching to infer:
 * - Which content is cached (and thus recently accessed)
 * - User access patterns and interests
 * - Potential location information
 * - Network topology through cache distribution
 *
 * Attack Parameters (JSON):
 * - probeInterval: double - Time between probe requests (default: 0.05s)
 * - targetContent: string - Specific content to probe (default: "/traffic")
 * - probeCount: int - Number of probes per target (default: 10)
 * - mode: string - Attack mode (default: "timing")
 * - measurePrecision: bool - Use high-precision timing (default: true)
 */
class CacheTimingAttack : public AttackBase
{
private:
    // Attack parameters
    std::string targetContent;
    double probeInterval;
    int probeCount;
    CacheProbeMode mode;
    bool measurePrecision;

    // Probing state
    std::vector<std::string> probeTargets;
    std::map<std::string, std::vector<simtime_t>> responseTimes;
    std::map<std::string, bool> cacheStatus;  // Inferred cache status
    std::map<std::string, int> probesSent;

    cMessage *probeTimer;
    int currentProbeIndex;

    // Statistics
    uint64_t totalProbes;
    uint64_t cacheHitsDetected;
    uint64_t cacheMissesDetected;
    uint64_t privacyViolations;  // Successful inferences

    // Timing thresholds
    simtime_t cacheHitThreshold;
    simtime_t cacheMissThreshold;

    // Signals
    simsignal_t probesSentSignal;
    simsignal_t cacheHitDetectedSignal;
    simsignal_t privacyViolationSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Probing operations
    InterestPacket* generateProbeInterest();
    void processProbeResponse(DataPacket *data);
    void analyzeResponseTime(const std::string &name, simtime_t responseTime);

    // Target generation
    void generateProbeTargets();
    std::string selectNextProbeTarget();
    std::vector<std::string> generateContentNames();
    std::vector<std::string> generateLocationBasedNames();

    // Timing analysis
    bool isCacheHit(simtime_t responseTime);
    bool isCacheMiss(simtime_t responseTime);
    void calibrateTimingThresholds();
    double calculateTimingVariance(const std::vector<simtime_t> &times);

    // Privacy inference
    void inferUserBehavior();
    void inferLocationFromCache();
    std::string inferUserInterests();
    void detectAccessPatterns();

    // Results analysis
    void analyzeResults();
    void logPrivacyViolation(const std::string &contentName, const std::string &inference);

public:
    CacheTimingAttack();
    virtual ~CacheTimingAttack();

    // Getters for statistics
    uint64_t getCacheHitsDetected() const { return cacheHitsDetected; }
    uint64_t getPrivacyViolations() const { return privacyViolations; }
};

Define_Module(CacheTimingAttack);

} // namespace veremivndn

#endif // __VEREMIVNDN_CACHETIMINGATTACK_H
