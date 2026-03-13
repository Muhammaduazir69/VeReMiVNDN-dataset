//
// VeReMiVNDN - Interest Flooding Attack Implementation
//
// Attack #1: Interest Flooding (IF)
// Layer: Forwarding / Network (PIT)
// Description: Adversary floods Interests for non-existent or unpopular names,
//              exhausting the Pending Interest Table (PIT)
// Impact: PIT exhaustion → dropped legitimate Interests, DoS
//

#ifndef __VEREMIVNDN_INTERESTFLOODING_H
#define __VEREMIVNDN_INTERESTFLOODING_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <set>
#include <random>

namespace veremivndn {

/**
 * Interest Flooding Attack Modes
 */
enum class FloodingMode {
    NON_EXISTENT,       // Flood with non-existent content names
    UNPOPULAR,          // Flood with unpopular content names
    RANDOM,             // Random name flooding
    TARGETED            // Target specific prefix
};

/**
 * InterestFlooding
 *
 * Implements Interest Flooding attack that exhausts the PIT
 * by sending massive amounts of Interest packets for non-existent
 * or unpopular content.
 *
 * Attack Parameters (JSON):
 * - targetPrefix: string - Name prefix to flood (default: "/attack")
 * - floodRate: int - Interests per second (default: 100)
 * - nonExistent: bool - Use non-existent names (default: true)
 * - useRandomNonce: bool - Randomize nonce (default: true)
 * - spoofSource: bool - Spoof source address (default: false)
 */
class InterestFlooding : public AttackBase
{
private:
    // Attack parameters
    std::string targetPrefix;
    int floodRate;  // Interests per second
    bool nonExistent;
    bool useRandomNonce;
    bool spoofSource;
    FloodingMode mode;

    // Attack state
    uint64_t interestsGenerated;
    std::set<std::string> generatedNames;
    cMessage *floodingTimer;

    // Random generation
    std::mt19937 rng;
    std::uniform_int_distribution<int> nonceDistribution;

    // Statistics
    simsignal_t interestsFloodedSignal;
    simsignal_t pitOccupancySignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Interest generation
    InterestPacket* generateFloodInterest();
    std::string generateRandomName();
    std::string generateNonExistentName();
    std::string generateUnpopularName();
    int generateNonce();

    // Attack optimization
    void adjustFloodRate();
    void selectOptimalPrefix();

public:
    InterestFlooding();
    virtual ~InterestFlooding();

    // Attack-specific getters
    int getFloodRate() const { return floodRate; }
    uint64_t getInterestsGenerated() const { return interestsGenerated; }
};

Define_Module(InterestFlooding);

} // namespace veremivndn

#endif // __VEREMIVNDN_INTERESTFLOODING_H
