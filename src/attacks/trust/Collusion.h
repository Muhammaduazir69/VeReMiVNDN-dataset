//
// VeReMiVNDN - Collusion Attack Implementation
//
// Attack #9: Collusion (Cooperative Misbehavior)
// Layer: Trust / Multi-node
// Description: Multiple malicious nodes coordinate to amplify attack effectiveness
//              by sharing information, resources, and synchronized actions
// Impact: Amplified damage, evade detection, overwhelm trust systems
//

#ifndef __VEREMIVNDN_COLLUSION_H
#define __VEREMIVNDN_COLLUSION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>
#include <string>

namespace veremivndn {

/**
 * Collusion Strategies
 */
enum class CollusionStrategy {
    COORDINATED_FLOODING,    // Synchronized Interest flooding
    TRUST_MANIPULATION,      // Cooperate to manipulate trust scores
    CONTENT_POISONING_COOP,  // Coordinate fake content distribution
    ROUTING_MANIPULATION,    // Cooperate on route hijacking
    DISTRIBUTED_DOS          // Distributed denial of service
};

/**
 * Collusion Message Types
 */
struct CollusionMessage {
    std::string senderId;
    std::string messageType;  // "COORDINATION", "STATUS", "ATTACK_TRIGGER"
    simtime_t timestamp;
    std::map<std::string, std::string> data;
};

/**
 * Collusion
 *
 * Implements coordinated attack where multiple malicious nodes:
 * - Share attack targets and timing
 * - Synchronize attack actions
 * - Amplify attack effectiveness
 * - Evade individual detection through distributed behavior
 * - Manipulate trust and reputation systems
 *
 * Attack Parameters (JSON):
 * - collusionGroup: string - Group ID for coordination (default: "group1")
 * - coordinatedAttack: string - Type of attack to coordinate (default: "ContentPoisoning")
 * - synchronize: bool - Synchronized vs independent timing (default: true)
 * - shareTargets: bool - Share attack targets (default: true)
 * - trustBoost: bool - Mutually boost trust scores (default: true)
 */
class Collusion : public AttackBase
{
private:
    // Collusion parameters
    std::string collusionGroup;
    std::string coordinatedAttackType;
    CollusionStrategy strategy;
    bool synchronize;
    bool shareTargets;
    bool trustBoost;

    // Collusion state
    std::set<std::string> groupMembers;  // Other colluding nodes
    std::map<std::string, simtime_t> memberLastSeen;
    std::map<std::string, double> memberTrustLevels;

    // Coordination
    std::vector<std::string> sharedTargets;
    simtime_t nextCoordinatedAction;
    bool isCoordinator;  // One node acts as coordinator
    std::string coordinatorId;

    // Attack synchronization
    cMessage *coordinationTimer;
    cMessage *syncTimer;
    double coordinationInterval;

    // Statistics
    uint64_t coordinationMessages;
    uint64_t synchronizedActions;
    uint64_t trustManipulations;
    uint64_t amplificationFactor;  // How much more effective vs solo

    // Signals
    simsignal_t coordinationMsgSignal;
    simsignal_t synchronizedActionSignal;
    simsignal_t amplificationSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Collusion coordination
    void initializeCollusion();
    void discoverGroupMembers();
    void electCoordinator();
    void sendCoordinationMessage(const std::string &msgType,
                                 const std::map<std::string, std::string> &data);
    void processCoordinationMessage(CollusionMessage *msg);

    // Synchronized attacks
    void executeCoordinatedFlooding();
    void executeCoordinatedPoisoning();
    void executeCoordinatedRoutingManipulation();
    void executeDistributedDoS();

    // Trust manipulation
    void boostGroupTrust();
    void degradeTargetTrust(const std::string &targetNode);
    void sharePositiveFeedback();

    // Target coordination
    void shareAttackTargets();
    void receiveSharedTargets(const std::vector<std::string> &targets);
    std::string selectCoordinatedTarget();

    // Synchronization
    void synchronizeActions();
    void waitForGroupSync();
    bool isGroupSynchronized();

    // Evasion tactics
    void distributeAttackLoad();  // Spread attack across members
    void rotateMaliciousBehavior();  // Take turns being obvious
    void maintainPlausibleBehavior();  // Keep some normal traffic

    // Amplification analysis
    void calculateAmplification();
    double getMemberContribution(const std::string &memberId);

public:
    Collusion();
    virtual ~Collusion();

    // Getters
    uint64_t getCoordinationMessages() const { return coordinationMessages; }
    uint64_t getAmplificationFactor() const { return amplificationFactor; }
    bool isPartOfGroup(const std::string &nodeId) const;
};

Define_Module(Collusion);

} // namespace veremivndn

#endif // __VEREMIVNDN_COLLUSION_H
