//
// VeReMiVNDN - Content Availability Manipulation (Cache Partitioning) Attack
//
// Attack #17: Content Availability Manipulation (Cache Partitioning)
// Layer: Caching / Network
// Description: Attackers partition caches (by controlling relay nodes) to make content
//              available only in attacker-controlled zones
// Impact: Localized content denial, targeted misinformation, network segmentation, availability manipulation
//

#ifndef __VEREMIVNDN_CACHEPARTITIONING_H
#define __VEREMIVNDN_CACHEPARTITIONING_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Partition Zones
 */
enum class PartitionZone {
    NORTH,
    SOUTH,
    EAST,
    WEST,
    CENTER
};

/**
 * CachePartitioning
 *
 * Implements Cache Partitioning attack that creates network
 * segmentation by controlling relay nodes and cache distribution
 * to limit content availability to specific zones.
 *
 * Attack Parameters (JSON):
 * - partitionZone: string - Zone to create partition (default: "east")
 * - limitAccess: bool - Limit access to controlled zone (default: true)
 * - controlRelays: bool - Control relay nodes (default: true)
 * - targetPrefix: string - Content prefix to partition (default: "/traffic")
 * - isolationLevel: double - Level of isolation 0.0-1.0 (default: 0.8)
 */
class CachePartitioning : public AttackBase
{
private:
    // Attack parameters
    std::string partitionZoneStr;
    PartitionZone partitionZone;
    bool limitAccess;
    bool controlRelays;
    std::string targetPrefix;
    double isolationLevel;

    // Attack state
    uint64_t relaysControlled;
    uint64_t accessDenials;
    uint64_t partitionsBoundariesCreated;
    std::set<std::string> controlledNodes;
    std::map<std::string, bool> contentAvailability;  // content -> available in zone

    // Statistics
    simsignal_t relaysControlledSignal;
    simsignal_t accessDenialsSignal;
    simsignal_t partitionStrengthSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Partitioning methods
    void createPartition();
    void controlRelayNode(const std::string &nodeId);
    void denyAccessToContent(const std::string &contentName);
    bool isInControlledZone(const std::string &nodeId);

    // Zone management
    PartitionZone parseZone(const std::string &zoneStr);
    void isolateZone(PartitionZone zone);
    void restrictContentAvailability(const std::string &content);

public:
    CachePartitioning();
    virtual ~CachePartitioning();

    // Attack-specific getters
    uint64_t getRelaysControlled() const { return relaysControlled; }
    uint64_t getAccessDenials() const { return accessDenials; }
    double getIsolationLevel() const { return isolationLevel; }
};

Define_Module(CachePartitioning);

} // namespace veremivndn

#endif // __VEREMIVNDN_CACHEPARTITIONING_H
