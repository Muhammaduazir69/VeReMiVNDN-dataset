//
// VeReMiVNDN - Cache Partitioning Attack Implementation
//

#include "CachePartitioning.h"
#include <sstream>

namespace veremivndn {

Define_Module(CachePartitioning);

CachePartitioning::CachePartitioning()
    : limitAccess(true), controlRelays(true), isolationLevel(0.8),
      relaysControlled(0), accessDenials(0), partitionsBoundariesCreated(0),
      partitionZone(PartitionZone::EAST) {
}

CachePartitioning::~CachePartitioning() {
}

void CachePartitioning::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        partitionZoneStr = getParameter("partitionZone", "east");
        limitAccess = getParameterBool("limitAccess", true);
        controlRelays = getParameterBool("controlRelays", true);
        targetPrefix = getParameter("targetPrefix", "/traffic");
        isolationLevel = getParameterDouble("isolationLevel", 0.8);

        // Parse zone
        partitionZone = parseZone(partitionZoneStr);

        // Register signals
        relaysControlledSignal = registerSignal("relaysControlled");
        accessDenialsSignal = registerSignal("accessDenials");
        partitionStrengthSignal = registerSignal("partitionStrength");

        relaysControlled = 0;
        accessDenials = 0;
        partitionsBoundariesCreated = 0;

        EV_INFO << "CachePartitioning attack initialized at node " << nodeIdentifier
                << " creating partition in zone: " << partitionZoneStr
                << ", isolation level: " << isolationLevel << endl;
    }
}

void CachePartitioning::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void CachePartitioning::finish() {
    AttackBase::finish();
    recordScalar("relaysControlled", relaysControlled);
    recordScalar("accessDenials", accessDenials);
    recordScalar("partitionsBoundariesCreated", partitionsBoundariesCreated);
    recordScalar("isolationLevel", isolationLevel);
}

void CachePartitioning::startAttack() {
    EV_INFO << "Starting Cache Partitioning attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Creating partition in zone: " + partitionZoneStr);

    // Create initial partition
    createPartition();

    // Control relay nodes if enabled
    if (controlRelays) {
        // Control multiple relay nodes
        for (int i = 0; i < 5; i++) {
            std::string relayId = "relay[" + std::to_string(intuniform(0, 20)) + "]";
            controlRelayNode(relayId);
        }
    }
}

void CachePartitioning::stopAttack() {
    EV_INFO << "Stopping Cache Partitioning attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Relays controlled: " + std::to_string(relaysControlled));

    controlledNodes.clear();
    contentAvailability.clear();
}

void CachePartitioning::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Isolate the partition zone
    isolateZone(partitionZone);

    // Restrict content availability
    if (uniform(0, 1) < 0.2) {  // 20% chance each tick
        std::string content = targetPrefix + "/content" + std::to_string(intuniform(1, 100));
        restrictContentAvailability(content);
    }

    // Deny access to content outside controlled zone
    if (limitAccess && uniform(0, 1) < isolationLevel) {
        std::string content = targetPrefix + "/blocked/" + std::to_string(simTime().dbl());
        denyAccessToContent(content);
    }

    // Periodically emit partition strength
    emit(partitionStrengthSignal, isolationLevel);
}

void CachePartitioning::createPartition() {
    EV_WARN << "PARTITION CREATED in zone: " << partitionZoneStr
            << " with isolation level: " << isolationLevel << endl;

    partitionsBoundariesCreated++;
    stats.packetsModified++;

    logAttackEvent("PARTITION", "Created partition boundary in " + partitionZoneStr);
}

void CachePartitioning::controlRelayNode(const std::string &nodeId) {
    if (controlledNodes.find(nodeId) != controlledNodes.end()) {
        return;  // Already controlled
    }

    controlledNodes.insert(nodeId);
    relaysControlled++;
    emit(relaysControlledSignal, 1L);

    EV_WARN << "RELAY CONTROL: Took control of relay node: " << nodeId << endl;

    logAttackEvent("CONTROL", "Controlled relay: " + nodeId);
}

void CachePartitioning::denyAccessToContent(const std::string &contentName) {
    contentAvailability[contentName] = false;
    accessDenials++;
    emit(accessDenialsSignal, 1L);
    stats.packetsDropped++;

    EV_WARN << "ACCESS DENIED: Blocked access to content: " << contentName
            << " outside controlled zone" << endl;
}

bool CachePartitioning::isInControlledZone(const std::string &nodeId) {
    // Simplified zone checking
    // In real implementation would check actual node geographic positions
    return controlledNodes.find(nodeId) != controlledNodes.end();
}

PartitionZone CachePartitioning::parseZone(const std::string &zoneStr) {
    if (zoneStr == "north") return PartitionZone::NORTH;
    if (zoneStr == "south") return PartitionZone::SOUTH;
    if (zoneStr == "east") return PartitionZone::EAST;
    if (zoneStr == "west") return PartitionZone::WEST;
    if (zoneStr == "center") return PartitionZone::CENTER;
    return PartitionZone::EAST;  // default
}

void CachePartitioning::isolateZone(PartitionZone zone) {
    // Create network segmentation for the specified zone
    EV_DEBUG << "Isolating zone: " << (int)zone
             << " with " << controlledNodes.size() << " controlled relays" << endl;

    // Simulate blocking inter-zone communication
    if (uniform(0, 1) < isolationLevel) {
        stats.packetsDropped++;
    }
}

void CachePartitioning::restrictContentAvailability(const std::string &content) {
    // Restrict content to be available only in controlled zone
    contentAvailability[content] = true;  // Available ONLY in controlled zone

    EV_WARN << "CONTENT RESTRICTED: " << content
            << " available only in zone: " << partitionZoneStr << endl;

    stats.packetsModified++;
}

cMessage* CachePartitioning::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept packets to create cache partitions and isolate zones

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    DataPacket *data = dynamic_cast<DataPacket*>(msg);

    if (!interest && !data) {
        return msg;  // Unknown packet type
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    std::string name;
    if (interest) {
        name = interest->getName();

        // Drop Interests for content that should be isolated
        if (contentAvailability.find(name) != contentAvailability.end()) {
            // Content is restricted - drop Interest to create partition
            EV_WARN << "PARTITION: Dropped Interest '" << name
                    << "' to isolate zone" << endl;

            delete interest;
            accessDenials++;
            emit(accessDenialsSignal, 1L);
            stats.packetsDropped++;
            return nullptr;  // Dropped
        }

        // Selectively drop Interests to partition zones
        if (uniform(0, 1) < isolationLevel) {
            EV_WARN << "PARTITION: Randomly dropped Interest '" << name
                    << "' to create isolation" << endl;

            delete interest;
            accessDenials++;
            stats.packetsDropped++;
            return nullptr;
        }
    }
    else if (data) {
        name = data->getName();

        // Control Data packet distribution to create partitions
        if (controlRelays) {
            // Mark as non-cacheable to force relay through controlled node
            data->setIsCacheable(false);
            relaysControlled++;
            emit(relaysControlledSignal, 1L);
            stats.packetsModified++;

            EV_WARN << "PARTITION: Data '" << name
                    << "' marked non-cacheable to control relay" << endl;
        }
        else if (limitAccess) {
            // Drop Data to deny access to specific zones
            if (uniform(0, 1) < 0.4) {  // 40% drop rate
                EV_WARN << "PARTITION: Dropped Data '" << name
                        << "' to deny zone access" << endl;

                delete data;
                accessDenials++;
                emit(accessDenialsSignal, 1L);
                stats.packetsDropped++;
                return nullptr;
            }
        }
    }

    return msg;
}

} // namespace veremivndn
