//
// VeReMiVNDN - RSU Controller Implementation
// Complete RSU functionality: content generation, prefix announcement, network integration
//

#include "RSUController.h"
#include "../../attacks/crosslayer/JammingMedium.h"
#include "NeighborIndex.h"
#include "../../ids/features/FeatureExtractor.h"
#include "VehicleController.h"

namespace veremivndn {

// Resolve a node's current position. Display-string coordinates are only
// maintained when a GUI canvas is active, so Cmdenv runs must read the
// mobility module directly; RSUs expose static x/y parameters instead.
static bool nodePositionOf(cModule *host, double &x, double &y) {
    if (!host) return false;
    cModule *mob = host->getSubmodule("mobility");
    if (!mob) return false;
    if (auto *bm = dynamic_cast<veins::BaseMobility *>(mob)) {
        veins::Coord c = bm->getPositionAt(simTime());
        x = c.x; y = c.y;
        return true;
    }
    if (mob->hasPar("x") && mob->hasPar("y")) {
        x = mob->par("x").doubleValue();
        y = mob->par("y").doubleValue();
        return true;
    }
    return false;
}


Define_Module(RSUController);

RSUController::RSUController()
    : contentTimer(nullptr), announceTimer(nullptr),
      contentCounter(0), packetsSent(0), packetsReceived(0), rsuIndex(0) {}

RSUController::~RSUController() {
    cancelAndDelete(contentTimer);
    cancelAndDelete(announceTimer);
}

void RSUController::initialize() {
    // Get gate IDs
    ndnInGate = findGate("ndnIn");
    ndnOutGate = findGate("ndnOut");
    wireInGate = findGate("wireIn");
    wireOutGate = findGate("wireOut");
    lowerLayerInGate = findGate("lowerLayerIn");
    lowerLayerOutGate = findGate("lowerLayerOut");
    lowerControlInGate = findGate("lowerControlIn");
    lowerControlOutGate = findGate("lowerControlOut");
    directInGate = findGate("directIn");

    // Get parent module (VndnRSU) parameters
    cModule *parent = getParentModule();
    rsuIndex = parent->getIndex();
    rsuId = "RSU_" + std::to_string(rsuIndex);

    contentInterval = par("contentUpdateInterval");
    announceInterval = par("announceInterval");

    // Parse produced prefixes
    std::string prefixStr = par("producedPrefixes").stdstringValue();
    size_t pos = 0;
    while ((pos = prefixStr.find(',')) != std::string::npos) {
        std::string prefix = prefixStr.substr(0, pos);
        prefix.erase(0, prefix.find_first_not_of(" \t"));
        prefix.erase(prefix.find_last_not_of(" \t") + 1);
        if (!prefix.empty()) {
            producedPrefixes.push_back(prefix);
        }
        prefixStr.erase(0, pos + 1);
    }
    if (!prefixStr.empty()) {
        prefixStr.erase(0, prefixStr.find_first_not_of(" \t"));
        prefixStr.erase(prefixStr.find_last_not_of(" \t") + 1);
        producedPrefixes.push_back(prefixStr);
    }

    // Schedule timers
    contentTimer = new cMessage("rsuContentTimer");
    scheduleAt(simTime() + contentInterval, contentTimer);

    announceTimer = new cMessage("rsuAnnounceTimer");
    scheduleAt(simTime() + announceInterval, announceTimer);

    WATCH(packetsSent);
    WATCH(packetsReceived);
    WATCH(contentCounter);

        {
        double rx = 0.0, ry = 0.0;
        nodePositionOf(getParentModule(), rx, ry);
        NeighborIndex::instance().upsert(getParentModule(), rx, ry,
                                         true, true, true);
    }

    EV_INFO << "RSU Controller initialized: " << rsuId << " with " << producedPrefixes.size() << " prefixes" << endl;
}

void RSUController::handleMessage(cMessage *msg) {
  try {
    // Self messages (timers)
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    // Frames delivered UP from the forwarder on the application face (face 0):
    // the producer app must answer Interests with (signed) Data.
    else if (msg->getArrivalGateId() == ndnInGate) {
        handleNDNMessage(msg);
    }
    // Frames the forwarder dispatched toward the wire face (face 1): broadcast.
    else if (msg->getArrivalGateId() == wireInGate) {
        cPacket *pkt = dynamic_cast<cPacket*>(msg);
        if (pkt) deliverToNeighbors(pkt, 0.005);   // 5 ms producer/backhaul latency
        else delete msg;
    }
    // Frames received over the air, or from the NIC: lift into the forwarder.
    else if (msg->getArrivalGateId() == lowerLayerInGate ||
             msg->getArrivalGateId() == directInGate) {
        handleLowerLayerMessage(msg);
    }
    // Control messages from lower layer
    else if (msg->getArrivalGateId() == lowerControlInGate) {
        handleLowerControlMessage(msg);
    }
    else {
        EV_WARN << "Unknown message arrival gate" << endl;
        delete msg;
    }
  } catch (std::exception &e) {
    FILE *dbg = fopen("results/trident_crash.log", "a");
    if (dbg) { fprintf(dbg, "t=%s %s: %s\n", simTime().str().c_str(),
                       rsuId.c_str(), e.what()); fclose(dbg); }
    throw;
  }
}

void RSUController::handleSelfMessage(cMessage *msg) {
    if (msg == contentTimer) {
        generateContent();
        scheduleAt(simTime() + contentInterval, contentTimer);
    }
    else if (msg == announceTimer) {
        announcePrefix();
        scheduleAt(simTime() + announceInterval, announceTimer);
    }
    else {
        EV_WARN << "Unknown self message" << endl;
        delete msg;
    }
}

void RSUController::handleNDNMessage(cMessage *msg) {
    cPacket *pkt = dynamic_cast<cPacket*>(msg);
    if (pkt) {
        processNDNPacket(pkt);
    } else {
        delete msg;
    }
}

void RSUController::handleLowerLayerMessage(cMessage *msg) {
    cPacket *pkt = dynamic_cast<cPacket*>(msg);
    if (pkt) {
        processWirelessPacket(pkt);
        packetsReceived++;
    } else {
        delete msg;
    }
}

void RSUController::handleLowerControlMessage(cMessage *msg) {
    // Handle control messages from NIC
    EV_DEBUG << "Received control message from lower layer" << endl;
    delete msg;
}

void RSUController::processNDNPacket(cPacket *pkt) {
    // Frames delivered UP from the forwarder on the application face (face 0).
    // The forwarder hands the RSU producer app an Interest it heard off the
    // wire (FIB routes the served prefix to the app face). The producer answers
    // with a freshly signed Data on the same face; the forwarder then satisfies
    // the pending (wire-face) PIT entry and dispatches the Data toward the wire
    // face, where handleMessage() broadcasts it. CS is populated en route, so
    // repeat requests are served from cache. Everything stays at packet level.
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(pkt)) {
        EV_INFO << "RSU producer app answering Interest: " << interest->getName() << endl;

        DataPacket *data = new DataPacket();
        data->setName(interest->getName());
        data->setContent(("RSU_Content_" + rsuId).c_str());
        data->setContentLength(256);
        data->setTimestamp(simTime());
        data->setFreshnessPeriod(10.0);
        data->setIsSigned(true);
        data->setSignerId(rsuId.c_str());
        data->setSignature(("SIG_" + rsuId).c_str());
        data->setTrustScore(1.0);
        data->setIsCacheable(true);

        sendToNDN(data);          // app face -> forwarder -> satisfies PIT -> wire
        delete interest;
    }
    else {
        // The RSU is a producer, not a consumer; any Data/Beacon arriving on the
        // app face has nothing to satisfy here.
        delete pkt;
    }
}

void RSUController::deliverToNeighbors(cPacket *pkt, double delaySec) {
    // The RSU is backhaul-connected infrastructure: its answer is delivered to
    // every vehicle (coordinate-free infra plane) on the dedicated directIn gate.
    // A small delaySec models the producer/backhaul latency, so that a co-located
    // attacker's (zero-delay) poisoned reply wins the PIT race in the undefended
    // case; TRIDENT's isolation drops the poison, letting this valid reply win.
    cModule *parent = getParentModule();
    if (NdnPacket *ndnPkt = dynamic_cast<NdnPacket*>(pkt))
        ndnPkt->setSenderId(parent->getFullName());

    int delivered = 0;

    double rx = 0.0, ry = 0.0;
    nodePositionOf(getParentModule(), rx, ry);
    const double R = 800.0;   // RSU coverage radius (m)

    std::vector<const NeighborIndex::Entry *> near;
    near.reserve(64);
    NeighborIndex::instance().query(rx, ry, R, getParentModule(), near);

    for (const NeighborIndex::Entry *e : near) {
        cModule *peer = e->host;
        if (!peer || e->isRsu) continue;      // RSUs serve vehicles

        if (JammingMedium::instance().anyActive()) {
            if (uniform(0.0, 1.0) <
                JammingMedium::instance().lossProbabilityAt(e->x, e->y)) {
                if (cModule *fe = peer->getSubmodule("featureExtractor"))
                    if (auto *obs = dynamic_cast<FeatureExtractor *>(fe))
                        obs->observePhyLoss();
                continue;
            }
        }

        cModule *peerCtrl = peer->getSubmodule("controller");
        if (!peerCtrl) continue;
        cGate *inGate = peerCtrl->gate("directIn");
        if (!inGate) continue;

        sendDirect(pkt->dup(), delaySec, 0, peerCtrl, inGate->getId());
        ++delivered;
    }
    packetsSent += delivered;
    delete pkt;
    EV_DETAIL << "RSU delivered NDN packet to " << delivered << " vehicles" << endl;
}

void RSUController::processWirelessPacket(cPacket *pkt) {
    // Frames received over the air. The RSU is infrastructure: it lifts overheard
    // Interests into its forwarder on the WIRE face, where the real PIT/FIB/CS
    // run and (for served prefixes) the Interest is routed up to the producer
    // app. Data heard off the air is of no use to a producer, so it is dropped.
    EV_INFO << "RSU heard wireless packet: " << pkt->getName() << endl;

    if (BeaconPacket *bp = dynamic_cast<BeaconPacket*>(pkt)) {
        if (cModule *fe = getParentModule()->getSubmodule("featureExtractor"))
            if (auto *obs = dynamic_cast<FeatureExtractor *>(fe))
                obs->observeBeacon(bp);
        delete pkt;                 // presence beacon; static FIB needs no learning
        return;
    }
    if (dynamic_cast<InterestPacket*>(pkt)) {
        send(pkt, wireOutGate);     // lift into forwarder on the wire face
        return;
    }
    // DataPacket / other: a producer does not consume Data.
    delete pkt;
}

void RSUController::refreshDisplay() const {
    // Show RSU activity on the controller submodule
    char label[64];
    snprintf(label, sizeof(label), "Tx:%d Rx:%d Content:%d",
             packetsSent, packetsReceived, contentCounter);
    const_cast<RSUController*>(this)->getDisplayString().setTagArg("t", 0, label);
    const_cast<RSUController*>(this)->getDisplayString().setTagArg("t", 2, "#003366");
}

void RSUController::finish() {
    recordScalar("totalContentGenerated", contentCounter);
    recordScalar("packetsSent", packetsSent);
    recordScalar("packetsReceived", packetsReceived);
    EV_INFO << "RSU Controller finishing. Generated " << contentCounter << " content items" << endl;
}

void RSUController::generateContent() {
    if (producedPrefixes.empty()) return;

    for (const std::string &prefix : producedPrefixes) {
        std::string name = prefix + "/data/" + std::to_string(contentCounter++);
        
        DataPacket *data = new DataPacket();
        data->setName(name.c_str());
        data->setContent(("Content_" + rsuId).c_str());
        data->setContentLength(256);
        data->setTimestamp(simTime());
        data->setIsSigned(true);
        data->setSignerId(rsuId.c_str());
        data->setSignature(("SIG_" + rsuId).c_str());
        data->setIsCacheable(true);

        sendToNDN(data);
        EV_INFO << "RSU generated content: " << name << endl;
    }
}

void RSUController::announcePrefix() {
    BeaconPacket *beacon = new BeaconPacket();
    beacon->setVehicleId(rsuId.c_str());
    beacon->setIsProducer(true);
    beacon->setProducedPrefixesArraySize(producedPrefixes.size());

    for (size_t i = 0; i < producedPrefixes.size(); i++) {
        beacon->setProducedPrefixes(i, producedPrefixes[i].c_str());
    }

    // Send prefix announcement to NDN layer
    sendToNDN(beacon);

    EV_INFO << "RSU announced prefixes: " << rsuId << endl;
}

void RSUController::sendToNDN(cPacket *pkt) {
    send(pkt, ndnOutGate);
}

void RSUController::sendToLowerLayer(cPacket *pkt) {
    send(pkt, lowerLayerOutGate);
    packetsSent++;
}

} // namespace veremivndn
