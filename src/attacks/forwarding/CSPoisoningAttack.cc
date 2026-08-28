//
// DP-IDS-VNDN - CS Poisoning Attack Implementation
//
// This attack operates in TWO modes:
// 1. ACTIVE: Generates poisoned Data packets that will be cached by neighbors
// 2. PASSIVE: Also modifies Data packets passing through (if any)
//
// The ACTIVE mode is essential because in VNDN, Data packets may not
// naturally flow through an attacker's ndnIn gate unless it is on the path.
// Active injection ensures the attack always produces observable effects.
//

#include "CSPoisoningAttack.h"
#include <cmath>

namespace veremivndn {

Define_Module(CSPoisoningAttack);

void CSPoisoningAttack::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        targetPrefix = getParameter("targetPrefix", "/traffic");
        replaceProbability = getParameterDouble("replaceProbability", 0.8);
        poisonContent = getParameter("poisonContent", "FABRICATED_DATA");
        maintainBehaviouralProfile = getParameterBool("maintainBehaviouralProfile", true);
        contentReplacedCount = 0;
        poisonCounter = 0;

        // Validate parameters
        if (replaceProbability < 0.0 || replaceProbability > 1.0) {
            EV_ERROR << "CSPoisoningAttack: replaceProbability must be [0,1], got "
                     << replaceProbability << ", clamping" << endl;
            replaceProbability = std::max(0.0, std::min(1.0, replaceProbability));
        }

        contentReplacedSignal = registerSignal("contentReplaced");

        EV_INFO << "CSPoisoningAttack: targetPrefix=" << targetPrefix
                << ", replaceProbability=" << replaceProbability << endl;
    }
}

void CSPoisoningAttack::startAttack() {
    EV_WARN << "CSPoisoningAttack STARTED on node " << nodeIdentifier << endl;
}

void CSPoisoningAttack::stopAttack() {
    EV_WARN << "CSPoisoningAttack STOPPED: " << contentReplacedCount
            << " packets poisoned" << endl;
}

void CSPoisoningAttack::executeAttack() {
    // ACTIVE MODE: Generate poisoned Data packets that neighbors will cache
    // This ensures attack is observable even if no Data naturally flows through
    if (!shouldExecuteBasedOnIntensity()) return;

    // Generate 1-2 poisoned data packets per tick (stealth: low rate)
    int numPackets = maintainBehaviouralProfile ? 1 : 3;

    for (int i = 0; i < numPackets; i++) {
        poisonCounter++;

        // Create data packet with targeted prefix (will be cached by neighbors)
        std::string fakeName = targetPrefix + "/data/item" + std::to_string(poisonCounter % 100);
        DataPacket *poisonedData = createDataPacket(fakeName, poisonContent);

        // Make it look legitimate to evade detection
        poisonedData->setTrustScore(0.95);
        poisonedData->setIsSigned(true);
        poisonedData->setSignature("VALID_LOOKING_SIG");
        poisonedData->setSignerId(nodeIdentifier.c_str());
        poisonedData->setIsCacheable(true);
        poisonedData->setFreshnessPeriod(SimTime(10.0));
        poisonedData->setContentLength(256);

        send(poisonedData, "ndnOut");

        contentReplacedCount++;
        stats.packetsGenerated++;
    }

    emit(contentReplacedSignal, (long)contentReplacedCount);
}

bool CSPoisoningAttack::shouldAttackPacket(cMessage *msg) {
    // PASSIVE MODE: Also modify Data packets if they pass through
    if (!attackActive) return false;

    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) return false;

    std::string name = data->getName();
    if (name.find(targetPrefix) != 0) return false;

    return (uniform(0, 1) < replaceProbability);
}

cMessage* CSPoisoningAttack::manipulatePacket(cMessage *msg) {
    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) return msg;

    // Replace content with fabricated data
    data->setContent(poisonContent.c_str());
    data->setContentLength(poisonContent.length());
    data->setTrustScore(0.95);  // Fake high trust

    contentReplacedCount++;
    stats.packetsModified++;
    emit(contentReplacedSignal, (long)contentReplacedCount);

    EV_INFO << "CSPoisoning: Poisoned data packet " << data->getName() << endl;
    return msg;
}

} // namespace veremivndn
