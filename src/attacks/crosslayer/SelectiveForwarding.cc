//
// VeReMiVNDN - Selective Forwarding Attack Implementation
//

#include "SelectiveForwarding.h"
#include "../../common/SimpleJSON.h"

namespace veremivndn {

Define_Module(SelectiveForwarding);

SelectiveForwarding::SelectiveForwarding()
    : delayTimer(nullptr),
      packetsDropped(0),
      packetsDelayed(0),
      packetsForwarded(0)
{
}

SelectiveForwarding::~SelectiveForwarding()
{
    cancelAndDelete(delayTimer);

    // Clean up delayed packets
    for (auto &delayed : delayedPackets) {
        delete delayed.packet;
    }
}

void SelectiveForwarding::initialize(int stage)
{
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Default parameters
        dropProbability = 0.7;
        targetType = "safety";
        selectiveDelay = false;
        delayAmount = 0.5;
        targetPrefix = "/safety";
        dropInterest = true;
        dropData = true;
        criteria = SelectionCriteria::BY_PREFIX;

        attackType = "SelectiveForwarding";

        // Create timer
        delayTimer = new cMessage("delayTimer");

        // Register signals
        packetDroppedSignal = registerSignal("packetDropped");
        packetDelayedSignal = registerSignal("packetDelayed");
        grayHoleActiveSignal = registerSignal("grayHoleActive");
    }
}

void SelectiveForwarding::handleMessage(cMessage *msg)
{
    if (msg == delayTimer) {
        processDelayedPackets();
    }
    else if (msg == startAttackMsg) {
        startAttack();
    }
    else if (msg == stopAttackMsg) {
        stopAttack();
    }
    else if (attackActive && shouldAttackPacket(msg)) {
        // Apply selective forwarding
        if (shouldDropPacket(msg)) {
            dropPacket(msg);
        }
        else if (selectiveDelay && shouldDelayPacket(msg)) {
            delayPacket(msg);
        }
        else {
            forwardPacket(msg);
        }
    }
    else {
        // Forward normally if attack not active or doesn't match criteria
        send(msg, "ndnOut");
    }
}

void SelectiveForwarding::startAttack()
{
    EV_WARN << "Starting Selective Forwarding (Gray Hole) attack: "
            << "dropProb=" << dropProbability
            << " target=" << targetPrefix << endl;

    attackActive = true;
    packetsDropped = 0;
    packetsDelayed = 0;
    packetsForwarded = 0;

    droppedNames.clear();
    dropCountByPrefix.clear();
    delayedPackets.clear();

    emit(attackActiveSignal, 1L);
    emit(grayHoleActiveSignal, 1L);
}

void SelectiveForwarding::stopAttack()
{
    attackActive = false;
    cancelEvent(delayTimer);

    EV_INFO << "Selective Forwarding attack stopped. Dropped "
            << packetsDropped << " packets, delayed "
            << packetsDelayed << " packets" << endl;

    emit(attackActiveSignal, 0L);
    emit(grayHoleActiveSignal, 0L);
}

void SelectiveForwarding::executeAttack()
{
    // This attack is passive - it acts on passing traffic
    // No active generation needed
}

bool SelectiveForwarding::shouldAttackPacket(cMessage *msg)
{
    return matchesSelectionCriteria(msg);
}

bool SelectiveForwarding::matchesSelectionCriteria(cMessage *packet)
{
    switch (criteria) {
        case SelectionCriteria::BY_PREFIX:
            return matchesPrefix(packet);

        case SelectionCriteria::BY_TYPE:
            return matchesType(packet);

        case SelectionCriteria::BY_PROBABILITY:
            return uniform(0.0, 1.0) < dropProbability;

        case SelectionCriteria::BY_TRUST:
            return matchesTrust(packet);

        case SelectionCriteria::BY_TIME:
            // Drop during specific time windows
            return true;

        default:
            return false;
    }
}

bool SelectiveForwarding::matchesPrefix(cMessage *packet)
{
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(packet)) {
        if (!dropInterest) return false;
        std::string name = interest->getName();
        return name.find(targetPrefix) == 0;
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        if (!dropData) return false;
        std::string name = data->getName();
        return name.find(targetPrefix) == 0;
    }
    return false;
}

bool SelectiveForwarding::matchesType(cMessage *packet)
{
    if (targetType == "interest") {
        return dynamic_cast<InterestPacket*>(packet) != nullptr && dropInterest;
    }
    else if (targetType == "data") {
        return dynamic_cast<DataPacket*>(packet) != nullptr && dropData;
    }
    else if (targetType == "safety") {
        return matchesPrefix(packet);
    }
    else if (targetType == "all") {
        return true;
    }
    return false;
}

bool SelectiveForwarding::matchesTrust(cMessage *packet)
{
    if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        return data->getTrustScore() < 0.5;  // Drop low-trust content
    }
    return false;
}

bool SelectiveForwarding::shouldDropPacket(cMessage *packet)
{
    // Probabilistic dropping
    return uniform(0.0, 1.0) < dropProbability;
}

bool SelectiveForwarding::shouldDelayPacket(cMessage *packet)
{
    // Delay with some probability
    return uniform(0.0, 1.0) < (dropProbability / 2.0);
}

void SelectiveForwarding::dropPacket(cMessage *packet)
{
    packetsDropped++;
    stats.packetsDropped++;

    // Track dropped content
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(packet)) {
        std::string name = interest->getName();
        droppedNames.insert(name);
        dropCountByPrefix[targetPrefix]++;

        EV_WARN << "DROPPING Interest: " << name << endl;
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        std::string name = data->getName();
        droppedNames.insert(name);
        dropCountByPrefix[targetPrefix]++;

        EV_WARN << "DROPPING Data: " << name << endl;
    }

    emit(packetDroppedSignal, 1L);

    // Delete the packet
    delete packet;
}

void SelectiveForwarding::delayPacket(cMessage *packet)
{
    packetsDelayed++;
    stats.packetsModified++;

    DelayedPacket delayed;
    delayed.packet = packet;
    delayed.releaseTime = simTime() + exponential(delayAmount);

    delayedPackets.push_back(delayed);

    EV_DETAIL << "DELAYING packet: " << packet->getName()
              << " until t=" << delayed.releaseTime << endl;

    emit(packetDelayedSignal, 1L);

    // Schedule processing of delayed packets
    if (!delayTimer->isScheduled()) {
        scheduleAt(delayed.releaseTime, delayTimer);
    }
}

void SelectiveForwarding::processDelayedPackets()
{
    simtime_t now = simTime();
    simtime_t nextRelease = -1;

    auto it = delayedPackets.begin();
    while (it != delayedPackets.end()) {
        if (it->releaseTime <= now) {
            // Release this packet
            send(it->packet, "ndnOut");
            packetsForwarded++;

            EV_DETAIL << "RELEASING delayed packet: "
                      << it->packet->getName() << endl;

            it = delayedPackets.erase(it);
        }
        else {
            // Update next release time
            if (nextRelease < 0 || it->releaseTime < nextRelease) {
                nextRelease = it->releaseTime;
            }
            ++it;
        }
    }

    // Schedule next processing
    if (nextRelease > 0 && !delayedPackets.empty()) {
        scheduleAt(nextRelease, delayTimer);
    }
}

void SelectiveForwarding::forwardPacket(cMessage *packet)
{
    packetsForwarded++;
    send(packet, "ndnOut");
}

cMessage* SelectiveForwarding::manipulatePacket(cMessage *msg)
{
    // Selective forwarding doesn't modify packets, just drops/delays them
    return msg;
}

cMessage* SelectiveForwarding::generateMaliciousPacket()
{
    // This attack doesn't generate packets
    return nullptr;
}

double SelectiveForwarding::getDropRatio() const
{
    uint64_t total = packetsDropped + packetsForwarded;
    if (total == 0) return 0.0;
    return (double)packetsDropped / (double)total;
}

void SelectiveForwarding::parseParameters(const std::string &params)
{
    try {
        auto json = nlohmann::json::parse(params);

        if (json.contains("dropProbability")) {
            dropProbability = std::stod(std::string(json["dropProbability"]));
        }
        if (json.contains("targetType")) {
            targetType = std::string(json["targetType"]);
        }
        if (json.contains("selectiveDelay")) {
            std::string val = json["selectiveDelay"];
            selectiveDelay = (val == "true" || val == "1");
        }
        if (json.contains("delayAmount")) {
            delayAmount = std::stod(std::string(json["delayAmount"]));
        }
        if (json.contains("targetPrefix")) {
            targetPrefix = std::string(json["targetPrefix"]);
        }
        if (json.contains("dropInterest")) {
            std::string val = json["dropInterest"];
            dropInterest = (val == "true" || val == "1");
        }
        if (json.contains("dropData")) {
            std::string val = json["dropData"];
            dropData = (val == "true" || val == "1");
        }
        if (json.contains("criteria")) {
            std::string criteriaStr = json["criteria"];
            if (criteriaStr == "prefix") criteria = SelectionCriteria::BY_PREFIX;
            else if (criteriaStr == "type") criteria = SelectionCriteria::BY_TYPE;
            else if (criteriaStr == "probability") criteria = SelectionCriteria::BY_PROBABILITY;
            else if (criteriaStr == "trust") criteria = SelectionCriteria::BY_TRUST;
            else if (criteriaStr == "time") criteria = SelectionCriteria::BY_TIME;
        }
    }
    catch (const std::exception &e) {
        EV_WARN << "Failed to parse attack parameters: " << e.what() << endl;
    }
}

void SelectiveForwarding::finish()
{
    AttackBase::finish();

    recordScalar("packetsDropped", packetsDropped);
    recordScalar("packetsDelayed", packetsDelayed);
    recordScalar("packetsForwarded", packetsForwarded);
    recordScalar("dropRatio", getDropRatio());
    recordScalar("uniqueDroppedNames", (long)droppedNames.size());
}

} // namespace veremivndn
