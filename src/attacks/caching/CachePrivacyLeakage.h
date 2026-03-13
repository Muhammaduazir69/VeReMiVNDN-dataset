//
// VeReMiVNDN - Content Privacy Leakage via Cache Sharing Attack
//
// Attack #15: Content Privacy Leakage via Cache Sharing
// Layer: Application / Data
// Description: Vehicles share cache snapshots or cooperative caches, inadvertently leaking
//              information about other vehicles' content requests
// Impact: Mass privacy exposure, request history leakage, inter-vehicle profiling, privacy breach across network
//

#ifndef __VEREMIVNDN_CACHEPRIVACYLEAKAGE_H
#define __VEREMIVNDN_CACHEPRIVACYLEAKAGE_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Cache Information Structure
 */
struct CacheSnapshot {
    std::string vehicleId;
    simtime_t timestamp;
    std::vector<std::string> cachedContent;
    std::map<std::string, int> requestCounts;
};

/**
 * CachePrivacyLeakage
 *
 * Implements Cache Privacy Leakage attack that exploits cooperative
 * caching to extract privacy-sensitive information about other vehicles'
 * content requests and interests.
 *
 * Attack Parameters (JSON):
 * - shareCache: bool - Request cache sharing (default: true)
 * - leakRequests: bool - Leak request information (default: true)
 * - collectHistory: bool - Collect cache history (default: true)
 * - probeInterval: double - Interval to probe caches in seconds (default: 2.0)
 * - targetVehicles: string - Specific vehicles to target (default: "all")
 */
class CachePrivacyLeakage : public AttackBase
{
private:
    // Attack parameters
    bool shareCache;
    bool leakRequests;
    bool collectHistory;
    double probeInterval;
    std::string targetVehicles;

    // Collected data
    std::map<std::string, CacheSnapshot> collectedSnapshots;
    std::map<std::string, std::set<std::string>> vehicleProfiles;  // vehicle -> content interests
    std::vector<std::string> leakedInformation;

    // Attack state
    uint64_t snapshotsCollected;
    uint64_t requestsLeaked;
    uint64_t profilesBuilt;
    uint64_t privacyViolations;

    // Probing timer
    cMessage *probeTimer;

    // Statistics
    simsignal_t snapshotsCollectedSignal;
    simsignal_t requestsLeakedSignal;
    simsignal_t privacyLeakageSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Cache probing
    void probeCaches();
    void requestCacheSnapshot(const std::string &vehicleId);
    CacheSnapshot extractCacheInformation();

    // Information leakage
    void leakCacheInformation(const CacheSnapshot &snapshot);
    void analyzeCachePatterns();
    void correlateVehicleInterests();

    // Privacy extraction
    std::set<std::string> extractPrivacyInfo(const CacheSnapshot &snapshot);
    void buildPrivacyProfile(const std::string &vehicleId, const std::set<std::string> &interests);

public:
    CachePrivacyLeakage();
    virtual ~CachePrivacyLeakage();

    // Attack-specific getters
    uint64_t getSnapshotsCollected() const { return snapshotsCollected; }
    uint64_t getRequestsLeaked() const { return requestsLeaked; }
    uint64_t getPrivacyViolations() const { return privacyViolations; }
};

Define_Module(CachePrivacyLeakage);

} // namespace veremivndn

#endif // __VEREMIVNDN_CACHEPRIVACYLEAKAGE_H
