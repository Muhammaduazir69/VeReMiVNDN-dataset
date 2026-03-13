//
// VeReMiVNDN - Cache Invalidation Attack Implementation
//
// Attack #13: Cache Invalidation / Poisoned Cache Invalidation
// Layer: Data / Control
// Description: Attacker triggers frequent cache invalidation (e.g., by publishing rapid fresh versions)
//              causing excessive cache churn and reduced utility
// Impact: Reduced cache effectiveness, increased backhaul traffic, higher latency, resource waste
//

#ifndef __VEREMIVNDN_CACHEINVALIDATION_H
#define __VEREMIVNDN_CACHEINVALIDATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>

namespace veremivndn {

/**
 * Invalidation Attack Modes
 */
enum class InvalidationMode {
    RAPID_VERSIONS,         // Publish rapid version updates
    FAKE_INVALIDATION,      // Send fake invalidation messages
    SHORT_FRESHNESS,        // Use very short freshness periods
    FORCED_EVICTION         // Force cache eviction through control messages
};

/**
 * CacheInvalidation
 *
 * Implements Cache Invalidation attack that triggers excessive
 * cache invalidation through rapid content updates or fake
 * invalidation messages.
 *
 * Attack Parameters (JSON):
 * - rapidVersions: bool - Publish rapid version updates (default: true)
 * - invalidationRate: int - Invalidations per second (default: 10)
 * - forceCacheEviction: bool - Force cache eviction (default: true)
 * - targetPrefix: string - Content prefix to invalidate (default: "/traffic")
 * - versionIncrement: double - Time between versions in seconds (default: 0.1)
 */
class CacheInvalidation : public AttackBase
{
private:
    // Attack parameters
    bool rapidVersions;
    int invalidationRate;
    bool forceCacheEviction;
    std::string targetPrefix;
    double versionIncrement;
    InvalidationMode mode;

    // Attack state
    uint64_t versionsPublished;
    uint64_t invalidationsSent;
    uint64_t cacheEvictionsForced;
    std::map<std::string, int> versionMap;  // content -> current version
    std::set<std::string> invalidatedContent;

    // Version tracking
    int currentVersion;
    simtime_t lastVersionTime;

    // Statistics
    simsignal_t versionsPublishedSignal;
    simsignal_t invalidationsSentSignal;
    simsignal_t cacheChurnSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Version manipulation
    DataPacket* publishNewVersion();
    void incrementVersion(const std::string &contentName);
    std::string getVersionedName(const std::string &baseName, int version);

    // Invalidation methods
    void sendInvalidationMessage(const std::string &contentName);
    void forceEviction(const std::string &contentName);
    DataPacket* createShortFreshnessData();

    // Monitoring
    void monitorCacheChurn();
    double calculateChurnRate();

public:
    CacheInvalidation();
    virtual ~CacheInvalidation();

    // Attack-specific getters
    uint64_t getVersionsPublished() const { return versionsPublished; }
    uint64_t getInvalidationsSent() const { return invalidationsSent; }
    int getCurrentVersion() const { return currentVersion; }
};

Define_Module(CacheInvalidation);

} // namespace veremivndn

#endif // __VEREMIVNDN_CACHEINVALIDATION_H
