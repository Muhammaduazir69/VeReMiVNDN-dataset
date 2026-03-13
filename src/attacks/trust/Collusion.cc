//
// VeReMiVNDN - Collusion Attack Implementation
//

#include "Collusion.h"
#include <algorithm>

namespace veremivndn {

Define_Module(Collusion);

Collusion::Collusion()
    : coordinationTimer(nullptr),
      syncTimer(nullptr),
      coordinationInterval(5.0),
      isCoordinator(false),
      coordinationMessages(0),
      synchronizedActions(0),
      trustManipulations(0),
      amplificationFactor(1)
{
}

Collusion::~Collusion()
{
    cancelAndDelete(coordinationTimer);
    cancelAndDelete(syncTimer);
}

void Collusion::initialize(int stage)
{
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse collusion-specific parameters
        if (parameters.count("collusionGroup")) {
            collusionGroup = parameters["collusionGroup"];
        } else {
            collusionGroup = "group1";
        }

        if (parameters.count("coordinatedAttack")) {
            coordinatedAttackType = parameters["coordinatedAttack"];
        } else {
            coordinatedAttackType = "ContentPoisoning";
        }

        synchronize = parameters.count("synchronize") ?
                     (parameters["synchronize"] == "true") : true;

        shareTargets = parameters.count("shareTargets") ?
                      (parameters["shareTargets"] == "true") : true;

        trustBoost = parameters.count("trustBoost") ?
                    (parameters["trustBoost"] == "true") : true;

        // Determine strategy from coordinated attack type
        if (coordinatedAttackType == "InterestFlooding") {
            strategy = CollusionStrategy::COORDINATED_FLOODING;
        } else if (coordinatedAttackType == "ContentPoisoning") {
            strategy = CollusionStrategy::CONTENT_POISONING_COOP;
        } else if (coordinatedAttackType == "NamePrefixHijacking") {
            strategy = CollusionStrategy::ROUTING_MANIPULATION;
        } else {
            strategy = CollusionStrategy::DISTRIBUTED_DOS;
        }

        // Register signals
        coordinationMsgSignal = registerSignal("coordinationMsg");
        synchronizedActionSignal = registerSignal("synchronizedAction");
        amplificationSignal = registerSignal("amplification");

        coordinationTimer = new cMessage("coordinationTimer");
        syncTimer = new cMessage("syncTimer");

        EV_INFO << "Collusion initialized: group=" << collusionGroup
                << ", attack=" << coordinatedAttackType
                << ", node=" << nodeIdentifier << endl;
    }
}

void Collusion::handleMessage(cMessage *msg)
{
    if (msg == coordinationTimer) {
        sendCoordinationMessage("STATUS", {{"status", "active"}});
        scheduleAt(simTime() + coordinationInterval, coordinationTimer);
    }
    else if (msg == syncTimer) {
        if (isGroupSynchronized()) {
            executeAttack();
        }
    }
    else if (msg->isSelfMessage()) {
        delete msg;
    }
    else {
        // Handle coordination messages from other colluding nodes
        delete msg;
    }
}

void Collusion::startAttack()
{
    AttackBase::startAttack();

    EV_WARN << "[COLLUSION ATTACK] Node " << nodeIdentifier
            << " joining group: " << collusionGroup << endl;

    // Initialize collusion mechanisms
    initializeCollusion();

    // Start coordination
    scheduleAt(simTime() + 0.1, coordinationTimer);

    if (synchronize) {
        scheduleAt(simTime() + 1.0, syncTimer);
    }
}

void Collusion::stopAttack()
{
    AttackBase::stopAttack();

    cancelEvent(coordinationTimer);
    cancelEvent(syncTimer);

    // Calculate final amplification
    calculateAmplification();

    EV_INFO << "[COLLUSION] Attack stopped. Coordination messages: "
            << coordinationMessages << ", Amplification: "
            << amplificationFactor << "x" << endl;
}

void Collusion::executeAttack()
{
    if (!attackActive) return;

    // Execute coordinated attack based on strategy
    switch (strategy) {
        case CollusionStrategy::COORDINATED_FLOODING:
            executeCoordinatedFlooding();
            break;

        case CollusionStrategy::CONTENT_POISONING_COOP:
            executeCoordinatedPoisoning();
            break;

        case CollusionStrategy::ROUTING_MANIPULATION:
            executeCoordinatedRoutingManipulation();
            break;

        case CollusionStrategy::DISTRIBUTED_DOS:
            executeDistributedDoS();
            break;

        default:
            executeCoordinatedPoisoning();
            break;
    }

    synchronizedActions++;
    emit(synchronizedActionSignal, 1L);

    // Trust manipulation
    if (trustBoost) {
        boostGroupTrust();
    }

    // Schedule next action
    if (synchronize && attackActive) {
        scheduleAt(simTime() + 2.0, syncTimer);
    }
}

void Collusion::initializeCollusion()
{
    // Discover other group members (simplified - in real implementation
    // would use network discovery)
    discoverGroupMembers();

    // Elect coordinator
    electCoordinator();

    // Share initial targets
    if (shareTargets && isCoordinator) {
        shareAttackTargets();
    }

    EV_INFO << "Collusion initialized with " << groupMembers.size()
            << " members. Coordinator: " << (isCoordinator ? "YES" : "NO") << endl;
}

void Collusion::discoverGroupMembers()
{
    // In simulation, we know group members from configuration
    // In real scenario, would use covert channel or pre-shared knowledge

    // Add this node
    groupMembers.insert(nodeIdentifier);

    // Simulate discovering other members
    // This would be coordinated outside the simulation
    EV_INFO << "Discovered " << groupMembers.size() << " group members" << endl;
}

void Collusion::electCoordinator()
{
    // Simple election: node with lowest ID becomes coordinator
    if (groupMembers.empty()) {
        isCoordinator = true;
        coordinatorId = nodeIdentifier;
        return;
    }

    auto minElement = std::min_element(groupMembers.begin(), groupMembers.end());
    coordinatorId = *minElement;
    isCoordinator = (coordinatorId == nodeIdentifier);

    EV_INFO << "Coordinator elected: " << coordinatorId << endl;
}

void Collusion::sendCoordinationMessage(const std::string &msgType,
                                       const std::map<std::string, std::string> &data)
{
    coordinationMessages++;
    emit(coordinationMsgSignal, 1L);

    // In real implementation, would send covert message to group members
    // For simulation, we log the coordination

    EV_DETAIL << "[COORDINATION] Sent " << msgType << " message to group" << endl;
}

void Collusion::executeCoordinatedFlooding()
{
    // All group members flood simultaneously
    EV_WARN << "[COORDINATED FLOODING] Executing synchronized flood attack" << endl;

    // Generate multiple flood interests
    for (int i = 0; i < 10; i++) {
        std::string target = "/attack/flood/" + std::to_string(intrand(10000));

        // Create flood interest (simplified)
        stats.packetsGenerated++;
    }
}

void Collusion::executeCoordinatedPoisoning()
{
    // Group members inject consistent false content
    EV_WARN << "[COORDINATED POISONING] Injecting coordinated false content" << endl;

    std::string target = selectCoordinatedTarget();
    if (!target.empty()) {
        // Generate poisoned content (simplified)
        stats.packetsGenerated++;
        stats.packetsModified++;
    }
}

void Collusion::executeCoordinatedRoutingManipulation()
{
    // Group members advertise fake routes together
    EV_WARN << "[ROUTING MANIPULATION] Coordinated route hijacking" << endl;

    stats.packetsGenerated++;
}

void Collusion::executeDistributedDoS()
{
    // Distributed denial of service across group
    EV_WARN << "[DISTRIBUTED DOS] Executing coordinated DoS" << endl;

    distributeAttackLoad();
    stats.packetsGenerated++;
}

void Collusion::boostGroupTrust()
{
    // Group members give each other positive recommendations
    for (const auto &member : groupMembers) {
        if (member != nodeIdentifier) {
            trustManipulations++;
            EV_DETAIL << "Boosting trust for: " << member << endl;
        }
    }
}

void Collusion::shareAttackTargets()
{
    // Coordinator shares targets with group
    sharedTargets.clear();
    sharedTargets.push_back("/target/content1");
    sharedTargets.push_back("/target/content2");
    sharedTargets.push_back("/target/content3");

    sendCoordinationMessage("TARGETS", {{"count", std::to_string(sharedTargets.size())}});

    EV_INFO << "Shared " << sharedTargets.size() << " attack targets with group" << endl;
}

std::string Collusion::selectCoordinatedTarget()
{
    if (sharedTargets.empty()) {
        return "/attack/default";
    }

    int index = intrand(sharedTargets.size());
    return sharedTargets[index];
}

void Collusion::synchronizeActions()
{
    // Wait for all group members to be ready
    EV_DETAIL << "Synchronizing with group..." << endl;
}

bool Collusion::isGroupSynchronized()
{
    // In real implementation, would check all members' status
    // For simulation, return true after delay
    return true;
}

void Collusion::distributeAttackLoad()
{
    // Each member handles portion of attack
    // This makes individual behavior look less suspicious

    uint32_t myPortion = groupMembers.size() > 0 ?
                        100 / groupMembers.size() : 100;

    EV_DETAIL << "My attack portion: " << myPortion << "%" << endl;
}

void Collusion::calculateAmplification()
{
    // Calculate how much more effective attack is with collusion
    amplificationFactor = groupMembers.size() * 2;  // Simplified calculation

    emit(amplificationSignal, amplificationFactor);

    EV_INFO << "Amplification factor: " << amplificationFactor << "x" << endl;
}

bool Collusion::isPartOfGroup(const std::string &nodeId) const
{
    return groupMembers.find(nodeId) != groupMembers.end();
}

void Collusion::finish()
{
    AttackBase::finish();

    recordScalar("coordinationMessages", coordinationMessages);
    recordScalar("synchronizedActions", synchronizedActions);
    recordScalar("trustManipulations", trustManipulations);
    recordScalar("amplificationFactor", amplificationFactor);
    recordScalar("groupSize", (long)groupMembers.size());
}

} // namespace veremivndn
