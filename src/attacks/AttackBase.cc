//
// VeReMiVNDN - AttackBase Implementation
//

#include "AttackBase.h"
#include <sstream>
#include <cstdlib>

namespace veremivndn {

Define_Module(AttackBase);

AttackBase::AttackBase() : attackActive(false), attackStarted(0), attackEnded(0),
                           nodeId(0), startAttackMsg(nullptr), stopAttackMsg(nullptr),
                           attackTickMsg(nullptr) {}

AttackBase::~AttackBase() {
    cancelAndDelete(startAttackMsg);
    cancelAndDelete(stopAttackMsg);
    cancelAndDelete(attackTickMsg);
}

void AttackBase::initialize(int stage) {
    if (stage == 0) {
        attackType = par("attackType").stdstringValue();
        startTime = par("startTime");
        duration = par("duration");
        intensity = par("intensity");

        std::string paramStr = par("attackParams").stdstringValue();
        parseParameters(paramStr);

        // Get parent module (VndnVehicle)
        cModule *parent = getParentModule();
        nodeId = parent->par("nodeId");

        // Try to get vehicleId if it exists (for vehicles)
        if (parent->hasPar("vehicleId")) {
            nodeIdentifier = parent->par("vehicleId").stdstringValue();
            if (nodeIdentifier.empty()) {
                nodeIdentifier = "Node_" + std::to_string(nodeId);
            }
        } else {
            nodeIdentifier = "Node_" + std::to_string(nodeId);
        }

        attackActiveSignal = registerSignal("attackActive");
        attackIntensitySignal = registerSignal("attackIntensity");
        packetsGeneratedSignal = registerSignal("packetsGenerated");
        packetsModifiedSignal = registerSignal("packetsModified");

        attackActive = false;
        stats = AttackStatistics();

        EV_INFO << "Attack module initialized: " << attackType << " at node " << nodeIdentifier << endl;
    }
    else if (stage == 2) {
        if (startTime > 0) {
            startAttackMsg = new cMessage("startAttack");
            scheduleAt(startTime, startAttackMsg);
        }

        if (duration > 0 && startTime > 0) {
            stopAttackMsg = new cMessage("stopAttack");
            scheduleAt(startTime + duration, stopAttackMsg);
        }
    }
}

void AttackBase::handleMessage(cMessage *msg) {
    // ========================================================================
    // ATTACK LIFECYCLE CONTROL
    // ========================================================================
    if (msg == startAttackMsg) {
        // Attack start time reached
        attackActive = true;
        attackStarted = simTime();
        startAttack();  // Call derived class implementation
        emit(attackActiveSignal, 1L);

        // Schedule periodic attack execution (every 100ms)
        attackTickMsg = new cMessage("attackTick");
        scheduleAt(simTime() + 0.1, attackTickMsg);

        EV_WARN << "[ATTACK START] " << attackType << " activated at t=" << simTime() << endl;
    }
    else if (msg == stopAttackMsg) {
        // Attack duration ended
        attackActive = false;
        attackEnded = simTime();
        stopAttack();  // Call derived class implementation
        emit(attackActiveSignal, 0L);

        cancelAndDelete(attackTickMsg);
        attackTickMsg = nullptr;

        EV_WARN << "[ATTACK STOP] " << attackType << " deactivated at t=" << simTime() << endl;
    }
    // ========================================================================
    // ACTIVE ATTACK EXECUTION (called every 100ms when attack is active)
    // ========================================================================
    else if (msg == attackTickMsg) {
        if (attackActive) {
            // Call derived class to generate/send malicious packets
            executeAttack();

            // Schedule next execution
            scheduleAt(simTime() + 0.1, attackTickMsg);
        }
    }
    // ========================================================================
    // PACKET INTERCEPTION - This is where attacks affect actual network traffic
    // ========================================================================
    else if (msg->arrivedOn("ndnIn")) {
        // Every packet flowing through the network passes through here
        // This is CRITICAL for attacks to produce measurable effects

        if (attackActive && shouldAttackPacket(msg)) {
            // Attack is active and this packet should be attacked
            // Call derived class to manipulate, drop, or modify the packet
            cMessage *result = manipulatePacket(msg);

            if (result != nullptr) {
                // Packet was modified or passed through
                send(result, "ndnOut");
            }
            // else: packet was DROPPED by attack (manipulatePacket returned nullptr)
            //       This is how jamming, gray hole, and DoS attacks work

            EV_DETAIL << "[ATTACK] " << attackType << " processed packet: "
                      << msg->getName() << (result ? " (forwarded)" : " (DROPPED)") << endl;
        } else {
            // Not attacking or intensity check failed - forward normally
            send(msg, "ndnOut");
        }
    }
    // ========================================================================
    // UNKNOWN MESSAGES - Forward to maintain network operation
    // ========================================================================
    else {
        send(msg, "ndnOut");
    }
}

void AttackBase::finish() {
    recordScalar("attackPacketsGenerated", stats.packetsGenerated);
    recordScalar("attackPacketsModified", stats.packetsModified);
    recordScalar("attackPacketsDropped", stats.packetsDropped);
    recordScalar("totalAttackDuration", stats.totalAttackDuration.dbl());
    recordScalar("avgIntensity", stats.avgIntensity);

    EV_INFO << "Attack " << attackType << " statistics: "
            << "generated=" << stats.packetsGenerated
            << ", modified=" << stats.packetsModified << endl;
}

void AttackBase::parseParameters(const std::string &paramStr) {
    if (paramStr.empty() || paramStr == "{}") return;

    std::string clean = paramStr;
    if (clean.front() == '{') clean = clean.substr(1);
    if (clean.back() == '}') clean = clean.substr(0, clean.length()-1);

    std::stringstream ss(clean);
    std::string token;

    while (std::getline(ss, token, ',')) {
        size_t colonPos = token.find(':');
        if (colonPos != std::string::npos) {
            std::string key = token.substr(0, colonPos);
            std::string value = token.substr(colonPos + 1);

            key.erase(0, key.find_first_not_of(" \t\""));
            key.erase(key.find_last_not_of(" \t\"") + 1);
            value.erase(0, value.find_first_not_of(" \t\""));
            value.erase(value.find_last_not_of(" \t\"") + 1);

            parameters[key] = value;
        }
    }
}

std::string AttackBase::getParameter(const std::string &key, const std::string &defaultValue) const {
    auto it = parameters.find(key);
    return (it != parameters.end()) ? it->second : defaultValue;
}

int AttackBase::getParameterInt(const std::string &key, int defaultValue) const {
    std::string value = getParameter(key, "");
    return value.empty() ? defaultValue : std::atoi(value.c_str());
}

double AttackBase::getParameterDouble(const std::string &key, double defaultValue) const {
    std::string value = getParameter(key, "");
    return value.empty() ? defaultValue : std::atof(value.c_str());
}

bool AttackBase::getParameterBool(const std::string &key, bool defaultValue) const {
    std::string value = getParameter(key, "");
    if (value.empty()) return defaultValue;
    return (value == "true" || value == "1" || value == "True");
}

bool AttackBase::shouldExecuteBasedOnIntensity() const {
    return uniform(0, 1) < intensity;
}

void AttackBase::logAttackEvent(const std::string &event, const std::string &details) {
    EV_INFO << "[ATTACK] " << attackType << " @ " << simTime()
            << ": " << event << " - " << details << endl;
}

void AttackBase::updateStatistics() {
    stats.totalAttackDuration = simTime() - attackStarted;
    stats.avgIntensity = intensity;
}

bool AttackBase::shouldAttackPacket(cMessage *msg) {
    // Default implementation: attack based on intensity probability
    // Derived classes can override to check:
    // - Packet type (Interest vs Data)
    // - Packet name/prefix
    // - Trust score
    // - Time of day
    // - Source/destination
    return attackActive && shouldExecuteBasedOnIntensity();
}

cMessage* AttackBase::manipulatePacket(cMessage *msg) {
    // Default implementation: just passes packet through unchanged
    //
    // IMPORTANT: Derived classes MUST override this to produce measurable effects!
    //
    // Examples:
    //   RadioJamming:  return dropPacket(msg, "jammed");  // Returns nullptr
    //   Poisoning:     data->setTrustScore(0.1); return data;
    //   SelectiveFwd:  if (shouldDrop) return dropPacket(msg); else return msg;
    //
    // The return value is CRITICAL:
    //   - Return modified/original packet to forward it
    //   - Return nullptr to DROP the packet (stops propagation)

    stats.packetsModified++;
    emit(packetsModifiedSignal, 1L);
    return msg;  // Default: forward unchanged
}

cMessage* AttackBase::generateMaliciousPacket() {
    // Default implementation: returns nullptr (no packet generated)
    //
    // IMPORTANT: Derived classes override this to create attack packets
    //
    // Examples:
    //   InterestFlooding:  return createInterestPacket("/nonexistent/flood/...");
    //   ContentPoisoning:  return createDataPacket("/traffic/fake", "POISONED");
    //   SignatureForgery:  DataPacket *d = ...; d->setSignature("FORGED"); return d;
    //
    // This is typically called by executeAttack() in a loop to generate bursts

    stats.packetsGenerated++;
    emit(packetsGeneratedSignal, 1L);
    return nullptr;  // Default: no packet
}

void AttackBase::startAttack() {
    EV_INFO << "AttackBase::startAttack() - Default implementation (no-op)" << endl;
}

void AttackBase::stopAttack() {
    EV_INFO << "AttackBase::stopAttack() - Default implementation (no-op)" << endl;
}

void AttackBase::executeAttack() {
    // Default implementation - does nothing
    // Specific attack types should override this

    // IMPORTANT: Derived classes MUST override this method to:
    // 1. Generate malicious packets (flooding attacks)
    // 2. Send fake data (poisoning attacks)
    // 3. Perform active probing (timing attacks)
    // 4. Update attack state
}

// ============================================================================
// HELPER METHODS - Make attack implementation easier and more consistent
// ============================================================================

bool AttackBase::isInterestPacket(cMessage *msg) {
    return dynamic_cast<InterestPacket*>(msg) != nullptr;
}

bool AttackBase::isDataPacket(cMessage *msg) {
    return dynamic_cast<DataPacket*>(msg) != nullptr;
}

InterestPacket* AttackBase::castToInterest(cMessage *msg) {
    return dynamic_cast<InterestPacket*>(msg);
}

DataPacket* AttackBase::castToData(cMessage *msg) {
    return dynamic_cast<DataPacket*>(msg);
}

InterestPacket* AttackBase::createInterestPacket(const std::string &name, double lifetime) {
    InterestPacket *interest = new InterestPacket("MaliciousInterest");
    interest->setName(name.c_str());
    interest->setNonce(intuniform(1, 2000000000));
    interest->setHopCount(0);
    interest->setInterestLifetime(lifetime);
    interest->setTimestamp(simTime());
    interest->setPriority(1);

    return interest;
}

DataPacket* AttackBase::createDataPacket(const std::string &name, const std::string &content) {
    DataPacket *data = new DataPacket("MaliciousData");
    data->setName(name.c_str());
    data->setContent(content.c_str());
    data->setContentLength(content.length());
    data->setTimestamp(simTime());
    data->setIsCacheable(true);
    data->setTrustScore(0.1);  // Low trust for malicious data
    data->setFreshnessPeriod(10.0);
    data->setIsSigned(false);

    return data;
}

cMessage* AttackBase::dropPacket(cMessage *msg, const std::string &reason) {
    // Log the drop if reason provided
    if (!reason.empty()) {
        EV_WARN << "[ATTACK DROP] " << attackType << " dropping packet: "
                << msg->getName() << " - Reason: " << reason << endl;
    }

    // Update statistics
    stats.packetsDropped++;

    // Delete the packet
    delete msg;

    // Return nullptr to signal packet was dropped
    return nullptr;
}

} // namespace veremivndn
