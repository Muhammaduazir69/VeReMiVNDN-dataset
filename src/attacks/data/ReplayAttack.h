//
// VeReMiVNDN - Replay Attack Implementation
//
// Attack #7: Interest/Content Replay
// Layer: Application / Data
// Description: Old Interest or Data packets are replayed to confuse consumers
//              or fill caches with stale content, causing false situational awareness
// Impact: Stale information delivery, false awareness, cache poisoning, outdated decisions
//

#ifndef __VEREMIVNDN_REPLAYATTACK_H
#define __VEREMIVNDN_REPLAYATTACK_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <deque>

namespace veremivndn {

/**
 * Replay Target Type
 */
enum class ReplayTarget {
    INTEREST,           // Replay Interest packets
    DATA,               // Replay Data packets
    BOTH                // Replay both types
};

/**
 * Captured Packet Record
 */
struct CapturedPacket {
    cMessage *packet;
    simtime_t captureTime;
    std::string name;
    int nonce;
};

/**
 * ReplayAttack
 *
 * Implements Replay Attack by capturing and replaying old packets
 * to cause stale information delivery and confusion.
 *
 * Attack Parameters (JSON):
 * - replayDelay: double - Delay before replay in seconds (default: 30)
 * - targetPrefix: string - Prefix to target (default: "/safety")
 * - ignoreTimestamp: bool - Replay despite old timestamp (default: true)
 * - replayCount: int - Times to replay each packet (default: 3)
 * - target: string - "interest", "data", or "both" (default: "both")
 */
class ReplayAttack : public AttackBase
{
private:
    // Attack parameters
    double replayDelay;
    std::string targetPrefix;
    bool ignoreTimestamp;
    int replayCount;
    ReplayTarget target;
    int maxCapturedPackets;

    // Captured packets storage
    std::deque<CapturedPacket> capturedInterests;
    std::deque<CapturedPacket> capturedData;
    std::map<std::string, int> replayCountMap;

    // Attack state
    uint64_t packetsReplayed;
    uint64_t packetsCaptured;

    // Timers
    cMessage *replayTimer;
    cMessage *captureTimer;

    // Statistics
    simsignal_t packetReplayedSignal;
    simsignal_t packetCapturedSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Packet capture
    void capturePacket(cMessage *packet);
    bool shouldCapturePacket(cMessage *packet);
    void storeCapturedPacket(cMessage *packet);

    // Packet replay
    void replayOldPackets();
    void replayInterest(const CapturedPacket &captured);
    void replayData(const CapturedPacket &captured);
    bool canReplayPacket(const CapturedPacket &captured);

    // Overrides from AttackBase
    virtual bool shouldAttackPacket(cMessage *msg) override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual cMessage* generateMaliciousPacket() override;

    // Configuration
    virtual void parseParameters(const std::string &params) override;

public:
    ReplayAttack();
    virtual ~ReplayAttack();

    // Attack-specific getters
    uint64_t getPacketsReplayed() const { return packetsReplayed; }
    uint64_t getPacketsCaptured() const { return packetsCaptured; }
};

Define_Module(ReplayAttack);

} // namespace veremivndn

#endif // __VEREMIVNDN_REPLAYATTACK_H
