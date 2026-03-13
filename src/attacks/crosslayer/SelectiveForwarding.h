//
// VeReMiVNDN - Selective Forwarding Attack Implementation
//
// Attack #8: Selective Forwarding (Gray Hole)
// Layer: Forwarding / Link
// Description: Intermediate node selectively drops or delays Interest/Data packets,
//              particularly targeting safety messages, causing partial denial of service
// Impact: Partial DoS, targeted disruption of safety apps, degraded reliability, increased latency
//

#ifndef __VEREMIVNDN_SELECTIVEFORWARDING_H
#define __VEREMIVNDN_SELECTIVEFORWARDING_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <set>
#include <deque>
#include <map>

namespace veremivndn {

/**
 * Selective Forwarding Mode
 */
enum class SelectionCriteria {
    BY_PREFIX,          // Drop based on name prefix
    BY_TYPE,            // Drop specific packet types (Interest/Data)
    BY_PROBABILITY,     // Random probabilistic dropping
    BY_TRUST,           // Drop low-trust packets
    BY_TIME            // Drop during specific time periods
};

/**
 * SelectiveForwarding
 *
 * Implements Selective Forwarding (Gray Hole) attack by selectively
 * dropping or delaying specific packets based on configured criteria.
 *
 * Attack Parameters (JSON):
 * - dropProbability: double - Probability to drop (default: 0.7)
 * - targetType: string - "safety", "interest", "data", or "all"
 * - selectiveDelay: bool - Delay instead of drop (default: false)
 * - delayAmount: double - Delay in seconds (default: 0.5)
 * - targetPrefix: string - Prefix to target (default: "/safety")
 * - dropInterest: bool - Drop interests (default: true)
 * - dropData: bool - Drop data (default: true)
 */
class SelectiveForwarding : public AttackBase
{
private:
    // Attack parameters
    double dropProbability;
    std::string targetType;
    bool selectiveDelay;
    double delayAmount;
    std::string targetPrefix;
    bool dropInterest;
    bool dropData;
    SelectionCriteria criteria;

    // Attack state
    uint64_t packetsDropped;
    uint64_t packetsDelayed;
    uint64_t packetsForwarded;
    std::set<std::string> droppedNames;
    std::map<std::string, uint32_t> dropCountByPrefix;

    // Delayed packets queue
    struct DelayedPacket {
        cMessage *packet;
        simtime_t releaseTime;
    };
    std::deque<DelayedPacket> delayedPackets;
    cMessage *delayTimer;

    // Statistics
    simsignal_t packetDroppedSignal;
    simsignal_t packetDelayedSignal;
    simsignal_t grayHoleActiveSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Selective forwarding logic
    bool shouldDropPacket(cMessage *packet);
    bool shouldDelayPacket(cMessage *packet);
    bool matchesSelectionCriteria(cMessage *packet);

    // Packet handling
    void dropPacket(cMessage *packet);
    void delayPacket(cMessage *packet);
    void processDelayedPackets();
    void forwardPacket(cMessage *packet);

    // Selection criteria evaluators
    bool matchesPrefix(cMessage *packet);
    bool matchesType(cMessage *packet);
    bool matchesTrust(cMessage *packet);

    // Overrides from AttackBase
    virtual bool shouldAttackPacket(cMessage *msg) override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual cMessage* generateMaliciousPacket() override;

    // Configuration
    virtual void parseParameters(const std::string &params) override;

public:
    SelectiveForwarding();
    virtual ~SelectiveForwarding();

    // Attack-specific getters
    uint64_t getPacketsDropped() const { return packetsDropped; }
    uint64_t getPacketsDelayed() const { return packetsDelayed; }
    double getDropRatio() const;
};

Define_Module(SelectiveForwarding);

} // namespace veremivndn

#endif // __VEREMIVNDN_SELECTIVEFORWARDING_H
