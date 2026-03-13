//
// VeReMiVNDN - RSU Controller Implementation
// Complete RSU functionality: content generation, prefix announcement, network integration
//

#include "RSUController.h"

namespace veremivndn {

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
    lowerLayerInGate = findGate("lowerLayerIn");
    lowerLayerOutGate = findGate("lowerLayerOut");
    lowerControlInGate = findGate("lowerControlIn");
    lowerControlOutGate = findGate("lowerControlOut");

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

    EV_INFO << "RSU Controller initialized: " << rsuId << " with " << producedPrefixes.size() << " prefixes" << endl;
}

void RSUController::handleMessage(cMessage *msg) {
    // Self messages (timers)
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    // Messages from NDN layer
    else if (msg->getArrivalGateId() == ndnInGate) {
        handleNDNMessage(msg);
    }
    // Messages from lower layer (wireless)
    else if (msg->getArrivalGateId() == lowerLayerInGate) {
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
    // Process packets coming from NDN layer (Interests that need data)
    if (dynamic_cast<InterestPacket*>(pkt)) {
        InterestPacket *interest = check_and_cast<InterestPacket*>(pkt);
        EV_INFO << "RSU received Interest from NDN: " << interest->getName() << endl;

        // Generate matching data
        DataPacket *data = new DataPacket();
        data->setName(interest->getName());
        data->setContent(("RSU_Content_" + rsuId).c_str());
        data->setContentLength(256);
        data->setTimestamp(simTime());
        data->setIsSigned(true);
        data->setSignerId(rsuId.c_str());
        data->setSignature(("SIG_" + rsuId).c_str());
        data->setIsCacheable(true);

        sendToNDN(data);
        delete interest;
    }
    else {
        delete pkt;
    }
}

void RSUController::processWirelessPacket(cPacket *pkt) {
    // Process packets received from wireless (vehicles/other RSUs)
    EV_INFO << "RSU received wireless packet: " << pkt->getName() << endl;

    // Check if it's a beacon (RSUs can also learn routes from other RSUs)
    if (BeaconPacket *beacon = dynamic_cast<BeaconPacket*>(pkt)) {
        if (beacon->isProducer() && beacon->getProducedPrefixesArraySize() > 0) {
            // Update FIB with routes from other producers
            cModule *parent = getParentModule();
            cModule *ndnNode = parent->getSubmodule("ndnNode");

            for (unsigned int i = 0; i < beacon->getProducedPrefixesArraySize(); i++) {
                std::string prefix = beacon->getProducedPrefixes(i);

                // Create FIB add route request
                FIBAddRouteRequest *fibReq = new FIBAddRouteRequest();
                fibReq->setPrefix(prefix.c_str());
                fibReq->setNextHop(0);  // Face 0 connects to network
                fibReq->setCost(1);
                fibReq->setTransactionId(intuniform(1, 1000000));

                send(fibReq, ndnOutGate);

                EV_INFO << "RSU learned route from beacon: " << prefix
                        << " from " << beacon->getVehicleId() << endl;
            }
        }
        delete beacon;
        return;
    }

    // Forward other packets to NDN layer for processing
    send(pkt, ndnOutGate);
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
