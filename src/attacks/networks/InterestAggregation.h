//
// VeReMiVNDN - Interest Aggregation Attack Implementation
//
// Attack #12: Interest Aggregation Attack
// Layer: Network / Forwarding
// Description: Malicious nodes craft Interests that deliberately aggregate in PIT
//              to cause resource imbalance or prevent other Interests from proper aggregation
// Impact: PIT resource exhaustion, unfair resource allocation, aggregation bypass, routing inefficiency
//

#ifndef __VEREMIVNDN_INTERESTAGGREGATION_H
#define __VEREMIVNDN_INTERESTAGGREGATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <random>

namespace veremivndn {

/**
 * Aggregation Attack Modes
 */
enum class AggregationMode {
    PREVENT_AGGREGATION,    // Prevent legitimate Interests from aggregating
    FORCE_AGGREGATION,      // Force malicious Interests to aggregate excessively
    IMBALANCED_LOAD,        // Create resource imbalance through aggregation
    TIMING_MANIPULATION     // Manipulate timing to affect aggregation
};

/**
 * InterestAggregation
 *
 * Implements Interest Aggregation attack that manipulates the PIT
 * aggregation mechanism to cause resource exhaustion or prevent
 * legitimate Interest aggregation.
 *
 * Attack Parameters (JSON):
 * - craftedAggregation: bool - Craft Interests for malicious aggregation (default: true)
 * - resourceImbalance: bool - Create resource imbalance (default: true)
 * - preventMapping: bool - Prevent proper PIT aggregation (default: false)
 * - targetPrefix: string - Target content prefix (default: "/traffic")
 * - aggregationRate: int - Rate of crafted Interests (default: 50)
 */
class InterestAggregation : public AttackBase
{
private:
    // Attack parameters
    bool craftedAggregation;
    bool resourceImbalance;
    bool preventMapping;
    std::string targetPrefix;
    int aggregationRate;
    AggregationMode mode;

    // Attack state
    uint64_t interestsCrafted;
    uint64_t aggregationsPrevented;
    uint64_t pitEntriesExhausted;
    std::map<std::string, int> aggregationMap;  // prefix -> count
    std::set<int> usedNonces;

    // Random generation
    std::mt19937 rng;

    // Statistics
    simsignal_t interestsCraftedSignal;
    simsignal_t aggregationPreventedSignal;
    simsignal_t pitImbalanceSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Interest crafting
    InterestPacket* craftAggregationInterest();
    InterestPacket* craftNonAggregatingInterest();
    InterestPacket* craftImbalancedInterest();

    // Aggregation manipulation
    int generateUniqueNonce();
    void manipulateInterestTiming();
    void createPitImbalance();

    // Monitoring
    void monitorPitAggregation();
    double calculateAggregationRatio();

public:
    InterestAggregation();
    virtual ~InterestAggregation();

    // Attack-specific getters
    uint64_t getInterestsCrafted() const { return interestsCrafted; }
    uint64_t getAggregationsPrevented() const { return aggregationsPrevented; }
};

Define_Module(InterestAggregation);

} // namespace veremivndn

#endif // __VEREMIVNDN_INTERESTAGGREGATION_H
