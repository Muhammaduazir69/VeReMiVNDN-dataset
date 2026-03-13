//
// VeReMiVNDN - Interest Flooding Attack Implementation
//

#include "../networks/InterestFlooding.h"

#include <sstream>

namespace veremivndn {

Define_Module(InterestFlooding);

InterestFlooding::InterestFlooding() : floodingTimer(nullptr), interestsGenerated(0),
                                       rng(std::random_device{}()),
                                       nonceDistribution(0, INT_MAX) {}

InterestFlooding::~InterestFlooding() {
    cancelAndDelete(floodingTimer);
}

void InterestFlooding::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        targetPrefix = getParameter("targetPrefix", "/safety");
        floodRate = getParameterInt("floodRate", 100);
        nonExistent = getParameterBool("nonExistent", true);
        useRandomNonce = getParameterBool("useRandomNonce", true);
        spoofSource = getParameterBool("spoofSource", false);

        mode = nonExistent ? FloodingMode::NON_EXISTENT : FloodingMode::RANDOM;

        interestsFloodedSignal = registerSignal("interestsFlooded");
        pitOccupancySignal = registerSignal("pitOccupancy");

        EV_INFO << "Interest Flooding initialized: rate=" << floodRate
                << ", prefix=" << targetPrefix << endl;
    }
}

void InterestFlooding::handleMessage(cMessage *msg) {
    if (msg == floodingTimer) {
        for (int i = 0; i < floodRate / 10; i++) {
            if (shouldExecuteBasedOnIntensity()) {
                InterestPacket *maliciousInterest = generateFloodInterest();
                send(maliciousInterest, "ndnOut");
                interestsGenerated++;
                emit(interestsFloodedSignal, 1L);
            }
        }
        scheduleAt(simTime() + 0.1, floodingTimer);
    } else {
        AttackBase::handleMessage(msg);
    }
}

void InterestFlooding::finish() {
    AttackBase::finish();
    recordScalar("totalInterestsFlooded", interestsGenerated);
    recordScalar("floodRate", floodRate);
}

void InterestFlooding::startAttack() {
    EV_WARN << "[ATTACK START] Interest Flooding from " << nodeIdentifier
            << " targeting " << targetPrefix << " at rate " << floodRate << "/s" << endl;

    logAttackEvent("START", "Interest Flooding attack initiated");

    floodingTimer = new cMessage("floodingTick");
    scheduleAt(simTime(), floodingTimer);

    stats.attacksLaunched++;
}

void InterestFlooding::stopAttack() {
    EV_WARN << "[ATTACK STOP] Interest Flooding stopped. Generated "
            << interestsGenerated << " malicious interests" << endl;

    logAttackEvent("STOP", "Interest Flooding attack terminated");

    cancelAndDelete(floodingTimer);
    floodingTimer = nullptr;
}

void InterestFlooding::executeAttack() {
    // Main attack execution happens in handleMessage with floodingTimer
}

InterestPacket* InterestFlooding::generateFloodInterest() {
    InterestPacket *interest = new InterestPacket();

    std::string name;
    switch (mode) {
        case FloodingMode::NON_EXISTENT:
            name = generateNonExistentName();
            break;
        case FloodingMode::UNPOPULAR:
            name = generateUnpopularName();
            break;
        case FloodingMode::RANDOM:
        default:
            name = generateRandomName();
            break;
    }

    interest->setName(name.c_str());
    interest->setNonce(generateNonce());
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    interest->setPriority(2);  // High priority to waste resources

    generatedNames.insert(name);

    return interest;
}

std::string InterestFlooding::generateRandomName() {
    std::stringstream ss;
    ss << targetPrefix << "/flood/" << interestsGenerated << "/" << intrand(1000000);
    return ss.str();
}

std::string InterestFlooding::generateNonExistentName() {
    std::stringstream ss;
    ss << targetPrefix << "/nonexistent/attack/" << simTime().dbl() << "/" << intrand(999999);
    return ss.str();
}

std::string InterestFlooding::generateUnpopularName() {
    std::stringstream ss;
    ss << targetPrefix << "/unpopular/data" << intrand(10000);
    return ss.str();
}

int InterestFlooding::generateNonce() {
    if (useRandomNonce) {
        return nonceDistribution(rng);
    } else {
        return interestsGenerated;
    }
}

void InterestFlooding::adjustFloodRate() {
    // Dynamic rate adjustment based on attack success
    if (interestsGenerated % 1000 == 0) {
        floodRate = (int)(floodRate * (1.0 + uniform(-0.1, 0.1)));
        floodRate = std::max(10, std::min(500, floodRate));
    }
}

void InterestFlooding::selectOptimalPrefix() {
    // Could implement smart prefix selection
}

} // namespace veremivndn
