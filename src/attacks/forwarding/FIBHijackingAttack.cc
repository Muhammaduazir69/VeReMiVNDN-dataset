//
// DP-IDS-VNDN - FIB Hijacking Attack Implementation
// Periodically advertises forged routes and intercepts matching traffic
//

#include "FIBHijackingAttack.h"
#include "../../ndn/packets/NdnPackets_m.h"

namespace veremivndn {

Define_Module(FIBHijackingAttack);

void FIBHijackingAttack::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        hijackedPrefix = getParameter("hijackedPrefix", "/safety");
        forgedFaceId = getParameterInt("forgedFaceId", 99);
        announcementInterval = getParameterDouble("announcementInterval", 5.0);
        maintainBehaviouralProfile = getParameterBool("maintainBehaviouralProfile", true);
        routesForgedCount = 0;
        trafficDivertedCount = 0;
        tickCounter = 0;

        routesForgedSignal = registerSignal("routesForged");
        trafficDivertedSignal = registerSignal("trafficDiverted");

        EV_INFO << "FIBHijackingAttack: hijackedPrefix=" << hijackedPrefix
                << ", forgedFaceId=" << forgedFaceId << endl;
    }
}

void FIBHijackingAttack::startAttack() {
    EV_WARN << "FIBHijackingAttack STARTED on node " << nodeIdentifier << endl;
}

void FIBHijackingAttack::stopAttack() {
    EV_WARN << "FIBHijackingAttack STOPPED: " << routesForgedCount
            << " forged routes, " << trafficDivertedCount << " diverted" << endl;
}

void FIBHijackingAttack::executeAttack() {
    tickCounter++;

    // Send forged route advertisement at announcementInterval
    int ticksPerAnnouncement = (int)(announcementInterval / 0.1);
    if (ticksPerAnnouncement < 1) ticksPerAnnouncement = 1;

    if (tickCounter % ticksPerAnnouncement == 0) {
        sendForgedRouteAdvertisement();
    }
}

void FIBHijackingAttack::sendForgedRouteAdvertisement() {
    // Create a beacon with forged prefix information
    BeaconPacket *beacon = new BeaconPacket("ForgedBeacon");
    beacon->setPacketType(NDN_DATA);
    beacon->setName(hijackedPrefix.c_str());
    beacon->setVehicleId(nodeIdentifier.c_str());
    beacon->setIsProducer(true);
    beacon->setTimestamp(simTime());

    beacon->setProducedPrefixesArraySize(1);
    beacon->setProducedPrefixes(0, hijackedPrefix.c_str());

    beacon->setTrustScore(1.0); // Fake high trust

    send(beacon, "ndnOut");

    routesForgedCount++;
    stats.packetsGenerated++;
    emit(routesForgedSignal, (long)routesForgedCount);

    EV_INFO << "FIBHijacking: Advertised forged route for " << hijackedPrefix << endl;
}

bool FIBHijackingAttack::shouldAttackPacket(cMessage *msg) {
    if (!attackActive) return false;

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    if (!interest) return false;

    std::string name = interest->getName();
    return (name.find(hijackedPrefix) == 0);
}

cMessage* FIBHijackingAttack::manipulatePacket(cMessage *msg) {
    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    if (!interest) return msg;

    // Intercept and create bogus data response
    DataPacket *bogusData = createDataPacket(interest->getName(),
        "HIJACKED_CONTENT_FROM_ATTACKER");
    bogusData->setTrustScore(0.0);
    bogusData->setIsSigned(true);
    bogusData->setSignature("FORGED_SIGNATURE");
    bogusData->setSignerId(nodeIdentifier.c_str());

    send(bogusData, "ndnOut");

    trafficDivertedCount++;
    stats.packetsModified++;
    emit(trafficDivertedSignal, (long)trafficDivertedCount);

    // Drop the original interest
    return dropPacket(msg, "FIB hijacking - diverted");
}

} // namespace veremivndn
