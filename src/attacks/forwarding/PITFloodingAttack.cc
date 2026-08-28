//
// DP-IDS-VNDN - PIT Flooding Attack Implementation
// Generates interests for content names that will never be satisfied
// Uses moderate rate and realistic names for stealth
//

#include "PITFloodingAttack.h"

namespace veremivndn {

Define_Module(PITFloodingAttack);

void PITFloodingAttack::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        targetPrefix = getParameter("targetPrefix", "/traffic");
        floodRate = getParameterInt("floodRate", 30);
        maintainBehaviouralProfile = getParameterBool("maintainBehaviouralProfile", true);
        unsatisfiableCount = 0;
        nameCounter = 0;

        // Validate parameters
        if (floodRate < 1) floodRate = 1;
        if (floodRate > 1000) floodRate = 1000;

        rng.seed(getId() + (unsigned)simTime().raw());

        unsatisfiableInterestsSignal = registerSignal("unsatisfiableInterests");

        EV_INFO << "PITFloodingAttack: targetPrefix=" << targetPrefix
                << ", floodRate=" << floodRate << "/s" << endl;
    }
}

void PITFloodingAttack::startAttack() {
    EV_WARN << "PITFloodingAttack STARTED on node " << nodeIdentifier << endl;
}

void PITFloodingAttack::stopAttack() {
    EV_WARN << "PITFloodingAttack STOPPED: " << unsatisfiableCount
            << " unsatisfiable interests generated" << endl;
}

void PITFloodingAttack::executeAttack() {
    // Generate floodRate/10 interests per tick (100ms ticks)
    // When maintainBehaviouralProfile=true, limit rate to avoid behavioural detection
    int effectiveRate = maintainBehaviouralProfile ? std::min(floodRate, 50) : floodRate;
    int perTick = std::max(1, effectiveRate / 10);

    for (int i = 0; i < perTick; i++) {
        if (!shouldExecuteBasedOnIntensity()) continue;

        std::string name = generateRealisticName();
        InterestPacket *interest = createInterestPacket(name);
        interest->setInterestLifetime(4.0);
        interest->setPriority(0);  // Normal priority (stealth)

        send(interest, "ndnOut");

        unsatisfiableCount++;
        stats.packetsGenerated++;
    }

    emit(unsatisfiableInterestsSignal, (long)unsatisfiableCount);
}

std::string PITFloodingAttack::generateRealisticName() {
    // Generate realistic-looking names that no producer serves
    // Use fully randomised components to avoid sequential detection patterns
    std::uniform_int_distribution<int> segDist(1000, 99999);
    std::uniform_int_distribution<int> verDist(1, 1000);
    std::uniform_int_distribution<int> seqDist(1, 999999);

    return targetPrefix + "/segment/" + std::to_string(segDist(rng))
           + "/version/" + std::to_string(verDist(rng))
           + "/seq/" + std::to_string(seqDist(rng));
}

bool PITFloodingAttack::shouldAttackPacket(cMessage *msg) {
    return false; // No packet manipulation - only generates
}

cMessage* PITFloodingAttack::manipulatePacket(cMessage *msg) {
    return msg; // Pass through unchanged (stealth)
}

} // namespace veremivndn
