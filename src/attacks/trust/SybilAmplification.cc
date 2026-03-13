//
// VeReMiVNDN - Sybil Amplification Attack Implementation
//

#include "SybilAmplification.h"
#include <sstream>

namespace veremivndn {

Define_Module(SybilAmplification);

SybilAmplification::SybilAmplification()
    : requestTimer(nullptr), requestsGenerated(0), currentIdentityIndex(0),
      rng(std::random_device{}()), identityDist(0, 0) {}

SybilAmplification::~SybilAmplification() {
    cancelAndDelete(requestTimer);
}

void SybilAmplification::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack parameters
        numSybilIds = getParameterInt("numSybilIds", 10);
        coordinatedRequests = getParameterBool("coordinatedRequests", true);
        spoofLocation = getParameterBool("spoofLocation", false);
        targetContent = getParameter("targetContent", "/traffic");

        // Register signals
        sybilRequestSignal = registerSignal("sybilRequest");
        identitySwitchSignal = registerSignal("identitySwitch");

        // Update identity distribution
        identityDist = std::uniform_int_distribution<int>(0, numSybilIds - 1);

        EV_INFO << "Sybil Amplification initialized: " << numSybilIds
                << " identities, coordinated=" << coordinatedRequests << endl;
    }
}

void SybilAmplification::handleMessage(cMessage *msg) {
    if (msg == requestTimer) {
        if (attackActive && shouldExecuteBasedOnIntensity()) {
            if (coordinatedRequests) {
                generateCoordinatedRequests();
            } else {
                SybilIdentity &identity = selectNextIdentity();
                sendSybilInterest(identity);
            }
        }
        scheduleAt(simTime() + exponential(0.5), requestTimer);
    } else {
        AttackBase::handleMessage(msg);
    }
}

void SybilAmplification::finish() {
    AttackBase::finish();
    recordScalar("totalSybilRequests", requestsGenerated);
    recordScalar("numSybilIdentities", numSybilIds);
    recordScalar("coordinatedRequests", coordinatedRequests ? 1 : 0);
}

void SybilAmplification::startAttack() {
    EV_WARN << "[ATTACK START] Sybil Amplification with " << numSybilIds
            << " fake identities targeting " << targetContent << endl;

    logAttackEvent("START", "Sybil Amplification attack initiated");

    // Create fake identities
    createSybilIdentities();

    // Start request generation timer
    requestTimer = new cMessage("sybilRequestTimer");
    scheduleAt(simTime() + exponential(1.0), requestTimer);

    stats.attacksLaunched++;
}

void SybilAmplification::stopAttack() {
    EV_WARN << "[ATTACK STOP] Sybil Amplification stopped. Generated "
            << requestsGenerated << " requests from " << sybilIdentities.size()
            << " fake identities" << endl;

    logAttackEvent("STOP", "Sybil Amplification attack terminated");

    cancelAndDelete(requestTimer);
    requestTimer = nullptr;

    sybilIdentities.clear();
}

void SybilAmplification::executeAttack() {
    // Main execution happens in handleMessage
}

void SybilAmplification::createSybilIdentities() {
    sybilIdentities.clear();

    for (int i = 0; i < numSybilIds; i++) {
        SybilIdentity identity;
        identity.id = "SYBIL_" + nodeIdentifier + "_" + std::to_string(i);
        identity.nodeId = 10000 + nodeId * 100 + i;  // Fake node IDs

        if (spoofLocation) {
            identity.x = uniform(0, 15000);
            identity.y = uniform(0, 16000);
        } else {
            identity.x = 0;
            identity.y = 0;
        }

        identity.lastActive = simTime();
        sybilIdentities.push_back(identity);

        EV_INFO << "Created Sybil identity: " << identity.id
                << " (nodeId=" << identity.nodeId << ")" << endl;
    }
}

void SybilAmplification::generateCoordinatedRequests() {
    // All Sybil identities request the same content simultaneously
    std::string targetName = generateTargetName();

    for (auto &identity : sybilIdentities) {
        InterestPacket *interest = new InterestPacket();
        interest->setName(targetName.c_str());
        interest->setNonce(intrand(INT_MAX));
        interest->setInterestLifetime(4.0);
        interest->setTimestamp(simTime());
        interest->setHopCount(0);
        interest->setPriority(1);

        // Set source as Sybil identity using forwardingHint field
        interest->setForwardingHint(identity.id.c_str());

        send(interest, "ndnOut");

        identity.lastActive = simTime();
        requestsGenerated++;
        emit(sybilRequestSignal, 1L);
    }

    EV_WARN << "Coordinated Sybil attack: " << sybilIdentities.size()
            << " requests for " << targetName << endl;
}

void SybilAmplification::sendSybilInterest(const SybilIdentity &identity) {
    std::string targetName = generateTargetName();

    InterestPacket *interest = new InterestPacket();
    interest->setName(targetName.c_str());
    interest->setNonce(intrand(INT_MAX));
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    interest->setPriority(1);

    // Set source as Sybil identity using forwardingHint field
    interest->setForwardingHint(identity.id.c_str());

    send(interest, "ndnOut");

    requestsGenerated++;
    emit(sybilRequestSignal, 1L);

    EV_INFO << "Sybil request from " << identity.id << ": " << targetName << endl;
}

SybilAmplification::SybilIdentity& SybilAmplification::selectNextIdentity() {
    // Round-robin or random selection
    if (coordinatedRequests) {
        currentIdentityIndex = (currentIdentityIndex + 1) % sybilIdentities.size();
    } else {
        currentIdentityIndex = identityDist(rng);
    }

    emit(identitySwitchSignal, currentIdentityIndex);
    return sybilIdentities[currentIdentityIndex];
}

std::string SybilAmplification::generateTargetName() {
    std::stringstream ss;
    ss << targetContent << "/data/" << intrand(1000);
    return ss.str();
}

} // namespace veremivndn
