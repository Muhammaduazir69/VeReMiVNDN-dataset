//
// VeReMiVNDN - NDN Processor Implementation
// Complete NDN Interest/Data forwarding logic with PIT/FIB/CS integration
//

#include "NDNProcessor.h"
#include "NdnControlMessages_m.h"

namespace veremivndn {

Define_Module(NDNProcessor);

NDNProcessor::NDNProcessor() : nextFaceId(0), nextTransactionId(1) {}

NDNProcessor::~NDNProcessor() {
    // Clear pending transactions
    for (auto &pair : pendingTransactions) {
        if (pair.second.packet) {
            delete pair.second.packet;
        }
    }
    pendingTransactions.clear();
}

void NDNProcessor::initialize() {
    nodeId = par("nodeId");
    nodeIdentifier = par("nodeType").stdstringValue() + std::to_string(nodeId);
    enableCaching = par("enableCaching");
    enableSignatureVerification = par("enableSignatureVerification");
    signatureVerificationDelay = par("signatureVerificationDelay");
    forwardingStrategy = par("forwardingStrategy").stdstringValue();

    // Register signals
    interestSentSignal = registerSignal("interestSent");
    interestReceivedSignal = registerSignal("interestReceived");
    dataSentSignal = registerSignal("dataSent");
    dataReceivedSignal = registerSignal("dataReceived");
    cacheHitSignal = registerSignal("cacheHit");
    cacheMissSignal = registerSignal("cacheMiss");
    nackSentSignal = registerSignal("nackSent");
    nackReceivedSignal = registerSignal("nackReceived");
    packetDroppedSignal = registerSignal("packetDropped");
    forwardingDelaySignal = registerSignal("forwardingDelay");

    nextFaceId = 0;
    nextTransactionId = 1;

    EV_INFO << "NDNProcessor initialized: " << nodeIdentifier << endl;

    // DEBUG: Log all gate connections to understand face mapping
    EV_WARN << "=== NDNProcessor Gate Configuration ===" << endl;
    EV_WARN << "Node: " << nodeIdentifier << endl;
    EV_WARN << "Total ndnOut gates: " << gateSize("ndnOut") << endl;
    for (int i = 0; i < gateSize("ndnOut"); i++) {
        cGate *gate = this->gate("ndnOut", i);
        if (gate->isConnected()) {
            cGate *nextGate = gate->getNextGate();
            cModule *dest = nextGate->getOwnerModule();
            EV_WARN << "  ndnOut[" << i << "] --> " << dest->getFullPath()
                    << " (gate: " << nextGate->getName() << ")" << endl;
        } else {
            EV_WARN << "  ndnOut[" << i << "] --> NOT CONNECTED" << endl;
        }
    }
    EV_WARN << "=======================================" << endl;
}

void NDNProcessor::handleMessage(cMessage *msg) {
    // Handle messages from different sources
    if (msg->arrivedOn("ndnIn")) {
        // Network packet from application/network layer
        handleNetworkPacket(msg);
    }
    else if (msg->arrivedOn("pitIn")) {
        // Response from PIT module
        handlePITResponse(msg);
    }
    else if (msg->arrivedOn("fibIn")) {
        // Response from FIB module
        handleFIBResponse(msg);
    }
    else if (msg->arrivedOn("csIn")) {
        // Response from CS module
        handleCSResponse(msg);
    }
    else {
        EV_WARN << "Message from unknown gate" << endl;
        delete msg;
    }
}

void NDNProcessor::handleNetworkPacket(cMessage *msg) {
    int gateIndex = msg->getArrivalGate()->getIndex();
    int inFace = getFaceForGate(gateIndex);

    if (inFace == -1) {
        inFace = registerFace(gateIndex);
    }

    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(msg)) {
        processInterest(interest, inFace);
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(msg)) {
        processData(data, inFace);
    }
    else if (NackPacket *nack = dynamic_cast<NackPacket*>(msg)) {
        processNack(nack, inFace);
    }
    else {
        EV_WARN << "Unknown packet type" << endl;
        emit(packetDroppedSignal, 1L);
        delete msg;
    }
}

void NDNProcessor::finish() {
    EV_INFO << "NDNProcessor " << nodeIdentifier << " finishing" << endl;
    recordScalar("pendingTransactions", (long)pendingTransactions.size());
}

void NDNProcessor::processInterest(InterestPacket *interest, int inFace) {
    emit(interestReceivedSignal, 1L);

    std::string name = interest->getName();
    EV_INFO << "Processing Interest: " << name << " from face " << inFace << endl;

    // Step 1: Query Content Store for cached data
    int transactionId = nextTransactionId++;
    CSLookupRequest *csReq = new CSLookupRequest();
    csReq->setName(name.c_str());
    csReq->setTransactionId(transactionId);

    // Store context for this transaction
    PendingTransaction trans;
    trans.transactionId = transactionId;
    trans.type = TRANS_CS_LOOKUP;
    trans.packet = interest;  // Keep interest for later use
    trans.inFace = inFace;
    trans.timestamp = simTime();
    pendingTransactions[transactionId] = trans;

    send(csReq, "csOut");
}

void NDNProcessor::handleCSResponse(cMessage *msg) {
    CSLookupResponse *response = dynamic_cast<CSLookupResponse*>(msg);
    if (!response) {
        delete msg;
        return;
    }

    int transactionId = response->getTransactionId();
    auto it = pendingTransactions.find(transactionId);
    if (it == pendingTransactions.end()) {
        EV_WARN << "CS response for unknown transaction " << transactionId << endl;
        delete msg;
        return;
    }

    PendingTransaction &trans = it->second;
    InterestPacket *interest = dynamic_cast<InterestPacket*>(trans.packet);

    if (response->getFound()) {
        // Cache hit!
        emit(cacheHitSignal, 1L);
        EV_INFO << "Cache HIT for " << response->getName() << endl;

        DataPacket *cachedData = const_cast<DataPacket*>(dynamic_cast<const DataPacket*>(response->getData()));
        if (cachedData) {
            // Send cached data back to requesting face
            forwardData(cachedData->dup(), trans.inFace);
        }

        // Clean up
        delete interest;
        delete response;
        pendingTransactions.erase(it);
    }
    else {
        // Cache miss - proceed to PIT
        emit(cacheMissSignal, 1L);
        EV_INFO << "Cache MISS for " << response->getName() << endl;

        delete response;

        // Query PIT
        queryPIT(interest, trans.inFace, transactionId);
    }
}

void NDNProcessor::queryPIT(InterestPacket *interest, int inFace, int transactionId) {
    PITInsertRequest *pitReq = new PITInsertRequest();
    pitReq->setName(interest->getName());
    pitReq->setTransactionId(transactionId);
    pitReq->setInFace(inFace);
    pitReq->setNonce(interest->getNonce());
    pitReq->setInterestLifetime(interest->getInterestLifetime().dbl());

    // Update transaction type
    pendingTransactions[transactionId].type = TRANS_PIT_INSERT;

    send(pitReq, "pitOut");
}

void NDNProcessor::handlePITResponse(cMessage *msg) {
    if (PITInsertResponse *response = dynamic_cast<PITInsertResponse*>(msg)) {
        handlePITInsertResponse(response);
    }
    else if (PITSatisfyResponse *response = dynamic_cast<PITSatisfyResponse*>(msg)) {
        handlePITSatisfyResponse(response);
    }
    else {
        delete msg;
    }
}

void NDNProcessor::handlePITInsertResponse(PITInsertResponse *response) {
    int transactionId = response->getTransactionId();
    auto it = pendingTransactions.find(transactionId);
    if (it == pendingTransactions.end()) {
        delete response;
        return;
    }

    PendingTransaction &trans = it->second;
    InterestPacket *interest = dynamic_cast<InterestPacket*>(trans.packet);

    if (!response->getSuccess()) {
        EV_WARN << "PIT insert failed for " << response->getName() << endl;
        emit(packetDroppedSignal, 1L);
        delete interest;
        delete response;
        pendingTransactions.erase(it);
        return;
    }

    if (response->getAggregated()) {
        // Interest aggregated - no need to forward
        EV_INFO << "Interest aggregated for " << response->getName() << endl;
        delete interest;
        delete response;
        pendingTransactions.erase(it);
        return;
    }

    // Need to forward - query FIB
    delete response;
    queryFIB(interest, trans.inFace, transactionId);
}

void NDNProcessor::queryFIB(InterestPacket *interest, int inFace, int transactionId) {
    FIBLookupRequest *fibReq = new FIBLookupRequest();
    fibReq->setName(interest->getName());
    fibReq->setTransactionId(transactionId);
    fibReq->setInFace(inFace);

    // Update transaction type
    pendingTransactions[transactionId].type = TRANS_FIB_LOOKUP;

    send(fibReq, "fibOut");
}

void NDNProcessor::handleFIBResponse(cMessage *msg) {
    FIBLookupResponse *response = dynamic_cast<FIBLookupResponse*>(msg);
    if (!response) {
        delete msg;
        return;
    }

    int transactionId = response->getTransactionId();
    auto it = pendingTransactions.find(transactionId);
    if (it == pendingTransactions.end()) {
        delete response;
        return;
    }

    PendingTransaction &trans = it->second;
    InterestPacket *interest = dynamic_cast<InterestPacket*>(trans.packet);

    if (!response->getFound() || response->getNextHopsArraySize() == 0) {
        // No route - send NACK back
        EV_WARN << "No route for " << response->getName() << endl;
        sendNack(interest->dup(), trans.inFace, NACK_NO_ROUTE);
        delete interest;
        delete response;
        pendingTransactions.erase(it);
        return;
    }

    // Forward interest to next hops
    interest->setHopCount(interest->getHopCount() + 1);

    simtime_t forwardDelay = simTime() - trans.timestamp;
    emit(forwardingDelaySignal, forwardDelay);

    for (unsigned int i = 0; i < response->getNextHopsArraySize(); i++) {
        int nextHop = response->getNextHops(i);
        if (nextHop != trans.inFace) {  // Don't send back to incoming face
            forwardInterest(interest->dup(), nextHop);
        }
    }

    delete interest;
    delete response;
    pendingTransactions.erase(it);
}

void NDNProcessor::processData(DataPacket *data, int inFace) {
    emit(dataReceivedSignal, 1L);

    std::string name = data->getName();
    EV_INFO << "Processing Data: " << name << " from face " << inFace << endl;

    // Verify signature if enabled
    if (enableSignatureVerification && data->isSigned()) {
        if (!verifySignature(data)) {
            EV_WARN << "Signature verification failed for: " << name << endl;
            emit(packetDroppedSignal, 1L);
            delete data;
            return;
        }
    }

    // Cache data if enabled and cacheable
    if (enableCaching && shouldCacheData(data)) {
        CSInsertRequest *csReq = new CSInsertRequest();
        csReq->setName(name.c_str());
        csReq->setData(dynamic_cast<cMessage*>(data->dup()));
        csReq->setTransactionId(nextTransactionId++);
        send(csReq, "csOut");
    }

    // Query PIT to find requesting faces
    int transactionId = nextTransactionId++;
    PITSatisfyRequest *pitReq = new PITSatisfyRequest();
    pitReq->setName(name.c_str());
    pitReq->setTransactionId(transactionId);
    pitReq->setInFace(inFace);

    // Store data for forwarding
    PendingTransaction trans;
    trans.transactionId = transactionId;
    trans.type = TRANS_PIT_SATISFY;
    trans.packet = data;
    trans.inFace = inFace;
    trans.timestamp = simTime();
    pendingTransactions[transactionId] = trans;

    send(pitReq, "pitOut");
}

void NDNProcessor::handlePITSatisfyResponse(PITSatisfyResponse *response) {
    int transactionId = response->getTransactionId();
    auto it = pendingTransactions.find(transactionId);
    if (it == pendingTransactions.end()) {
        delete response;
        return;
    }

    PendingTransaction &trans = it->second;
    DataPacket *data = dynamic_cast<DataPacket*>(trans.packet);

    if (!response->getFound()) {
        // No matching PIT entry - unsolicited data
        EV_WARN << "Unsolicited data: " << response->getName() << endl;
        emit(packetDroppedSignal, 1L);
        delete data;
        delete response;
        pendingTransactions.erase(it);
        return;
    }

    // Forward data to all requesting faces
    for (unsigned int i = 0; i < response->getOutFacesArraySize(); i++) {
        int outFace = response->getOutFaces(i);
        forwardData(data->dup(), outFace);
    }

    delete data;
    delete response;
    pendingTransactions.erase(it);
}

void NDNProcessor::processNack(NackPacket *nack, int inFace) {
    emit(nackReceivedSignal, 1L);

    std::string name = nack->getName();
    EV_INFO << "Processing NACK: " << name << " reason=" << nack->getReason() << endl;

    // In a full implementation, would update PIT/FIB based on NACK
    // For now, just log and discard
    delete nack;
}

void NDNProcessor::forwardInterest(InterestPacket *interest, int outFace) {
    emit(interestSentSignal, 1L);

    int gateIndex = getGateForFace(outFace);
    if (gateIndex == -1 || gateIndex >= gateSize("ndnOut")) {
        EV_WARN << "Invalid face: " << outFace << endl;
        delete interest;
        return;
    }

    EV_INFO << "Forwarding Interest: " << interest->getName() << " to face " << outFace << endl;
    send(interest, "ndnOut", gateIndex);
}

void NDNProcessor::forwardData(DataPacket *data, int outFace) {
    emit(dataSentSignal, 1L);

    int gateIndex = getGateForFace(outFace);
    if (gateIndex == -1 || gateIndex >= gateSize("ndnOut")) {
        EV_WARN << "Invalid face: " << outFace << endl;
        delete data;
        return;
    }

    EV_INFO << "Forwarding Data: " << data->getName() << " to face " << outFace << endl;
    send(data, "ndnOut", gateIndex);
}

void NDNProcessor::sendNack(InterestPacket *interest, int outFace, NackReason reason) {
    emit(nackSentSignal, 1L);

    NackPacket *nack = new NackPacket();
    nack->setName(interest->getName());
    nack->setNonce(interest->getNonce());
    nack->setReason(reason);

    std::string reasonText;
    switch(reason) {
        case NACK_CONGESTION: reasonText = "Congestion"; break;
        case NACK_DUPLICATE: reasonText = "Duplicate"; break;
        case NACK_NO_ROUTE: reasonText = "NoRoute"; break;
        default: reasonText = "Unknown"; break;
    }
    nack->setReasonText(reasonText.c_str());

    int gateIndex = getGateForFace(outFace);
    if (gateIndex != -1 && gateIndex < gateSize("ndnOut")) {
        send(nack, "ndnOut", gateIndex);
    } else {
        delete nack;
    }
}

int NDNProcessor::registerFace(int gateIndex) {
    int faceId = nextFaceId++;
    faceToGate[faceId] = gateIndex;
    gateToFace[gateIndex] = faceId;

    // DEBUG: Log face registration with gate destination
    cGate *gate = this->gate("ndnOut", gateIndex);
    std::string destination = "UNKNOWN";
    if (gate->isConnected()) {
        cModule *dest = gate->getNextGate()->getOwnerModule();
        destination = dest->getFullPath();
    }

    EV_WARN << "*** REGISTERED FACE " << faceId << " for gate " << gateIndex
            << " --> " << destination << " ***" << endl;

    return faceId;
}

int NDNProcessor::getFaceForGate(int gateIndex) {
    auto it = gateToFace.find(gateIndex);
    return (it != gateToFace.end()) ? it->second : -1;
}

int NDNProcessor::getGateForFace(int faceId) {
    auto it = faceToGate.find(faceId);
    return (it != faceToGate.end()) ? it->second : -1;
}

bool NDNProcessor::shouldCacheData(DataPacket *data) {
    return enableCaching && data->isCacheable();
}

bool NDNProcessor::verifySignature(DataPacket *data) {
    // Simplified signature verification
    std::string sig = data->getSignature();
    return data->isSigned() && !sig.empty();
}

InterestPacket* NDNProcessor::createInterest(const std::string &name) {
    InterestPacket *interest = new InterestPacket();
    interest->setName(name.c_str());
    interest->setNonce(intuniform(0, INT_MAX));
    interest->setInterestLifetime(SimTime(4.0));
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    // mustBeFresh is set via selectors
    InterestSelector selectors;
    selectors.mustBeFresh = true;
    interest->setSelectors(selectors);
    interest->setPriority(0);  // Normal priority
    return interest;
}

DataPacket* NDNProcessor::createData(const std::string &name, const std::string &content) {
    DataPacket *data = new DataPacket();
    data->setName(name.c_str());
    data->setContent(content.c_str());
    data->setContentLength(content.length());
    data->setTimestamp(simTime());
    data->setFreshnessPeriod(10.0);  // 10 seconds freshness
    data->setIsCacheable(true);
    data->setIsSigned(true);
    std::string sig = "SIG_" + std::to_string(nodeId) + "_" + std::to_string(simTime().inUnit(SIMTIME_MS));
    data->setSignature(sig.c_str());
    data->setSignerId(nodeIdentifier.c_str());
    data->setSignatureTime(simTime());
    data->setTrustScore(1.0);  // Default trust score
    return data;
}

} // namespace veremivndn
