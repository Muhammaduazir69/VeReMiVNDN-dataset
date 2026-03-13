//
// VeReMiVNDN - Routing Information Flood Attack Implementation
//

#include "RoutingInfoFlood.h"
#include <sstream>

namespace veremivndn {

Define_Module(RoutingInfoFlood);

RoutingInfoFlood::RoutingInfoFlood()
    : fibUpdateRate(100), spoofEntries(true), fakeRoutes(true),
      floodIntensity(0.9), attackType(RoutingAttackType::FIB_FLOOD),
      fibUpdatesFlooded(0), pitEntriesSpoofed(0), fakeRoutesAdvertised(0),
      controlMessagesFlooded(0) {
}

RoutingInfoFlood::~RoutingInfoFlood() {
}

void RoutingInfoFlood::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        fibUpdateRate = getParameterInt("fibUpdateRate", 100);
        spoofEntries = getParameterBool("spoofEntries", true);
        fakeRoutes = getParameterBool("fakeRoutes", true);
        targetRouter = getParameter("targetRouter", "all");
        floodIntensity = getParameterDouble("floodIntensity", 0.9);

        // Determine attack type
        if (spoofEntries) {
            attackType = RoutingAttackType::PIT_SPOOF;
        } else if (fakeRoutes) {
            attackType = RoutingAttackType::FIB_FLOOD;
        } else {
            attackType = RoutingAttackType::CONTROL_OVERLOAD;
        }

        // Register signals
        fibUpdatesFloodedSignal = registerSignal("fibUpdatesFlooded");
        pitEntriesSpoofedSignal = registerSignal("pitEntriesSpoofed");
        fakeRoutesSignal = registerSignal("fakeRoutes");
        controlOverloadSignal = registerSignal("controlOverload");

        fibUpdatesFlooded = 0;
        pitEntriesSpoofed = 0;
        fakeRoutesAdvertised = 0;
        controlMessagesFlooded = 0;

        EV_INFO << "RoutingInfoFlood attack initialized at node " << nodeIdentifier
                << ", FIB update rate: " << fibUpdateRate
                << ", attack type: " << (int)attackType << endl;
    }
}

void RoutingInfoFlood::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void RoutingInfoFlood::finish() {
    AttackBase::finish();
    recordScalar("fibUpdatesFlooded", fibUpdatesFlooded);
    recordScalar("pitEntriesSpoofed", pitEntriesSpoofed);
    recordScalar("fakeRoutesAdvertised", fakeRoutesAdvertised);
    recordScalar("controlMessagesFlooded", controlMessagesFlooded);
}

void RoutingInfoFlood::startAttack() {
    EV_INFO << "Starting Routing Information Flood attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Routing flood attack initiated");
}

void RoutingInfoFlood::stopAttack() {
    EV_INFO << "Stopping Routing Information Flood attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "FIB updates flooded: " + std::to_string(fibUpdatesFlooded));

    poisonedPrefixes.clear();
    routeAdvertisementCount.clear();
}

void RoutingInfoFlood::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Execute attack based on type
    switch (attackType) {
        case RoutingAttackType::FIB_FLOOD:
            floodFibUpdates();
            break;

        case RoutingAttackType::PIT_SPOOF:
            if (uniform(0, 1) < 0.3) {  // 30% chance
                std::string contentName = "/spoofed/" + std::to_string(simTime().dbl());
                spoofPitEntry(contentName);
            }
            break;

        case RoutingAttackType::ROUTE_POISON:
            if (uniform(0, 1) < 0.2) {  // 20% chance
                std::string prefix = "/poisoned/" + std::to_string(intuniform(1, 20));
                poisonRouteInformation(prefix);
            }
            break;

        case RoutingAttackType::CONTROL_OVERLOAD:
            overloadControlPlane();
            break;
    }
}

void RoutingInfoFlood::floodFibUpdates() {
    // Flood FIB with excessive route advertisements
    double intervalSeconds = 1.0 / fibUpdateRate;

    if (uniform(0, 1) < intervalSeconds * 10) {  // Approximate rate control
        // Generate fake prefix to advertise
        std::stringstream ss;
        ss << "/flooded/" << intuniform(1, 1000) << "/" << simTime().dbl();
        std::string fakePrefix = ss.str();

        advertiseFakeRoute(fakePrefix);

        fibUpdatesFlooded++;
        emit(fibUpdatesFloodedSignal, 1L);
        emit(controlOverloadSignal, 1L);
        stats.packetsGenerated++;

        EV_WARN << "FIB FLOOD: Advertised fake route for prefix: " << fakePrefix << endl;
    }
}

void RoutingInfoFlood::advertiseFakeRoute(const std::string &prefix) {
    // Advertise a fake route for the given prefix
    fakeRoutesAdvertised++;
    emit(fakeRoutesSignal, 1L);

    routeAdvertisementCount[prefix]++;

    EV_WARN << "FAKE ROUTE: Advertising route for prefix: " << prefix
            << " (count: " << routeAdvertisementCount[prefix] << ")" << endl;

    logAttackEvent("FAKE_ROUTE", "Advertised: " + prefix);
}

void RoutingInfoFlood::poisonRouteInformation(const std::string &prefix) {
    // Poison routing information for legitimate prefix
    poisonedPrefixes.insert(prefix);

    EV_WARN << "ROUTE POISON: Poisoned routing information for: " << prefix << endl;

    // Advertise incorrect routing information
    advertiseFakeRoute(prefix);

    stats.packetsModified++;
}

void RoutingInfoFlood::spoofPitEntry(const std::string &contentName) {
    // Create fake PIT entry
    pitEntriesSpoofed++;
    emit(pitEntriesSpoofedSignal, 1L);
    stats.packetsGenerated++;

    EV_WARN << "PIT SPOOF: Created fake PIT entry for: " << contentName << endl;

    createFakePitEntry();
}

void RoutingInfoFlood::createFakePitEntry() {
    // Generate fake PIT entry (simulated)
    // In real implementation would inject into actual PIT

    controlMessagesFlooded++;
    emit(controlOverloadSignal, 1L);

    EV_DEBUG << "Fake PIT entry created" << endl;
}

void RoutingInfoFlood::overloadControlPlane() {
    // Overload control plane with excessive control messages
    int burstSize = intuniform(5, 20);

    for (int i = 0; i < burstSize; i++) {
        generateControlTraffic();
    }

    emit(controlOverloadSignal, (long)burstSize);

    EV_WARN << "CONTROL OVERLOAD: Generated " << burstSize << " control messages" << endl;
}

void RoutingInfoFlood::generateControlTraffic() {
    // Generate control plane traffic (route updates, PIT management, etc.)
    controlMessagesFlooded++;
    stats.packetsGenerated++;

    // Alternate between FIB and PIT attacks
    if (uniform(0, 1) < 0.5) {
        fibUpdatesFlooded++;
        emit(fibUpdatesFloodedSignal, 1L);
    } else {
        pitEntriesSpoofed++;
        emit(pitEntriesSpoofedSignal, 1L);
    }

    EV_DEBUG << "Control traffic generated" << endl;
}

cMessage* RoutingInfoFlood::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Interest packets and manipulate routing tables (FIB/PIT)

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    if (!interest) {
        // Not an Interest packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    std::string name = interest->getName();

    if (attackType == RoutingAttackType::FIB_FLOOD) {
        // Modify Interest to flood FIB with fake routing entries
        // Create unique prefix to exhaust FIB capacity
        std::stringstream ss;
        ss << "/fake/route/" << fibUpdatesFlooded << "/" << nodeId << "/" << name;
        interest->setName(ss.str().c_str());

        // Set high priority to get processed
        interest->setPriority(5);

        fibUpdatesFlooded++;
        emit(fibUpdatesFloodedSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "FIB_FLOOD: Interest modified to inject fake route: "
                << ss.str() << endl;
    }
    else if (attackType == RoutingAttackType::PIT_SPOOF) {
        // Spoof PIT entries with fake nonces
        interest->setNonce(intuniform(1, 100));  // Low nonce values collide

        // Extend lifetime to exhaust PIT resources
        interest->setInterestLifetime(30.0);  // Very long

        pitEntriesSpoofed++;
        emit(pitEntriesSpoofedSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "PIT_SPOOF: Interest spoofed with fake nonce and extended lifetime" << endl;
    }
    else if (attackType == RoutingAttackType::ROUTE_POISON) {
        // Poison routing by redirecting to non-existent prefixes
        std::string poisonedName = "/poisoned/nonexistent/" + name;
        interest->setName(poisonedName.c_str());

        fakeRoutesAdvertised++;
        emit(fakeRoutesSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "ROUTE_POISON: Interest redirected to non-existent prefix" << endl;
    }
    else if (attackType == RoutingAttackType::CONTROL_OVERLOAD) {
        // Duplicate Interest to overload control plane
        InterestPacket *duplicate = interest->dup();

        // Send duplicate immediately
        send(duplicate, "ndnOut");

        controlMessagesFlooded++;
        emit(controlOverloadSignal, 1L);
        stats.packetsGenerated++;

        EV_WARN << "CONTROL_OVERLOAD: Interest duplicated to overload control plane" << endl;
    }

    return interest;
}

} // namespace veremivndn
