//
// VeReMiVNDN - PIT Implementation
//

#include "PIT.h"
#include "../core/NdnControlMessages_m.h"

namespace veremivndn {

Define_Module(PIT);

PIT::PIT() : cleanupTimer(nullptr), currentSize(0), totalInsertions(0),
             totalRemovals(0), totalExpirations(0), totalSatisfied(0),
             totalAggregated(0) {}

PIT::~PIT() {
    cancelAndDelete(cleanupTimer);
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
}

void PIT::initialize() {
    // Read parameters
    maxSize = par("maxSize");
    defaultLifetime = par("defaultLifetime");
    enableAggregation = par("enableAggregation");
    cleanupInterval = par("cleanupInterval");

    // Initialize statistics
    currentSize = 0;
    totalInsertions = 0;
    totalRemovals = 0;
    totalExpirations = 0;
    totalSatisfied = 0;
    totalAggregated = 0;

    // Register signals
    pitSizeSignal = registerSignal("pitSize");
    pitOccupancySignal = registerSignal("pitOccupancy");
    pitExpiredSignal = registerSignal("pitExpired");
    pitSatisfiedSignal = registerSignal("pitSatisfied");

    // Schedule cleanup timer
    cleanupTimer = new cMessage("cleanupTimer");
    scheduleAt(simTime() + cleanupInterval, cleanupTimer);

    EV_INFO << "PIT initialized: maxSize=" << maxSize << ", defaultLifetime=" << defaultLifetime << endl;
}

void PIT::handleMessage(cMessage *msg) {
    if (msg == cleanupTimer) {
        cleanupExpiredEntries();
        scheduleAt(simTime() + cleanupInterval, cleanupTimer);
    }
    else if (PITInsertRequest *req = dynamic_cast<PITInsertRequest*>(msg)) {
        handleInsertRequest(req);
    }
    else if (PITSatisfyRequest *req = dynamic_cast<PITSatisfyRequest*>(msg)) {
        handleSatisfyRequest(req);
    }
    else {
        delete msg;
    }
}

void PIT::handleInsertRequest(PITInsertRequest *request) {
    PITInsertResponse *response = new PITInsertResponse();
    response->setName(request->getName());
    response->setTransactionId(request->getTransactionId());

    std::string name = request->getName();
    int inFace = request->getInFace();
    int nonce = request->getNonce();

    // Check if entry already exists
    PITEntry *entry = findEntry(name);

    if (entry != nullptr) {
        // Entry exists - check for aggregation
        if (enableAggregation) {
            // Check for duplicate nonce
            if (entry->nonces.find(nonce) != entry->nonces.end()) {
                EV_WARN << "Duplicate nonce detected for " << name << endl;
                response->setSuccess(false);
                response->setAggregated(false);
                send(response, "processorOut");
                delete request;
                return;
            }

            // Aggregate: add incoming face
            entry->incomingFaces.insert(inFace);
            entry->nonces.insert(nonce);
            totalAggregated++;

            response->setSuccess(true);
            response->setAggregated(true);  // Don't forward, already pending

            EV_INFO << "Aggregated interest for " << name << " from face " << inFace << endl;
        } else {
            response->setSuccess(false);
            response->setAggregated(false);
        }

        send(response, "processorOut");
        delete request;
        return;
    }

    // New entry - check if PIT is full
    if (isFull()) {
        EV_WARN << "PIT full, evicting oldest entry" << endl;
        evictOldestEntry();
    }

    // Create new entry
    simtime_t lifetime = request->getInterestLifetime();
    if (lifetime <= 0) {
        lifetime = defaultLifetime;
    }

    entry = createEntry(name, lifetime);
    entry->incomingFaces.insert(inFace);
    entry->nonces.insert(nonce);

    currentSize++;
    totalInsertions++;

    emit(pitSizeSignal, (long)currentSize);
    emit(pitOccupancySignal, getOccupancy());

    response->setSuccess(true);
    response->setAggregated(false);  // New entry, need to forward

    EV_INFO << "Inserted new PIT entry for " << name << " from face " << inFace << endl;

    send(response, "processorOut");
    delete request;
}

void PIT::handleSatisfyRequest(PITSatisfyRequest *request) {
    PITSatisfyResponse *response = new PITSatisfyResponse();
    response->setName(request->getName());
    response->setTransactionId(request->getTransactionId());

    std::string name = request->getName();
    PITEntry *entry = findEntry(name);

    if (entry != nullptr) {
        response->setFound(true);

        // Get all incoming faces (these requested the data)
        std::set<int> &inFaces = entry->incomingFaces;
        response->setOutFacesArraySize(inFaces.size());

        int i = 0;
        for (int face : inFaces) {
            response->setOutFaces(i++, face);
        }

        // Mark as satisfied and remove entry
        totalSatisfied++;
        emit(pitSatisfiedSignal, 1L);

        EV_INFO << "Satisfied PIT entry for " << name << ", forwarding to "
                << inFaces.size() << " faces" << endl;

        removeEntry(name);
        currentSize--;
        emit(pitSizeSignal, (long)currentSize);
        emit(pitOccupancySignal, getOccupancy());
    } else {
        response->setFound(false);
        EV_WARN << "No PIT entry found for data: " << name << endl;
    }

    send(response, "processorOut");
    delete request;
}

void PIT::finish() {
    // Cleanup
    cleanupExpiredEntries();

    // Record final statistics
    recordScalar("finalPITSize", currentSize);
    recordScalar("totalInsertions", totalInsertions);
    recordScalar("totalRemovals", totalRemovals);
    recordScalar("totalExpirations", totalExpirations);
    recordScalar("totalSatisfied", totalSatisfied);
    recordScalar("totalAggregated", totalAggregated);
    recordScalar("satisfactionRatio", totalInsertions > 0 ? (double)totalSatisfied / totalInsertions : 0);

    EV_INFO << "PIT statistics: "
            << "insertions=" << totalInsertions
            << ", satisfied=" << totalSatisfied
            << ", expired=" << totalExpirations
            << ", aggregated=" << totalAggregated << endl;
}

bool PIT::insert(InterestPacket *interest, int inFace) {
    std::string name = interest->getName();

    // Check if entry already exists (aggregation)
    PITEntry *existing = findEntry(name);
    if (existing != nullptr) {
        if (enableAggregation) {
            return aggregate(interest, inFace);
        } else {
            // Check for duplicate nonce
            if (existing->hasNonce(interest->getNonce())) {
                EV_WARN << "Duplicate nonce detected for " << name << endl;
                return false;
            }
        }
    }

    // Check if PIT is full
    if (isFull()) {
        EV_WARN << "PIT is full, evicting oldest entry" << endl;
        evictOldestEntry();
    }

    // Create new entry
    simtime_t lifetime = interest->getInterestLifetime();
    if (lifetime == 0) {
        lifetime = defaultLifetime;
    }

    PITEntry *entry = createEntry(name, lifetime);
    entry->incomingFaces.insert(inFace);
    entry->nonces.insert(interest->getNonce());
    entry->hopCount = interest->getHopCount();
    entry->forwardingHint = interest->getForwardingHint();
    entry->producerTrust = interest->getProducerTrust();
    entry->priority = interest->getPriority();

    entries[name] = entry;
    currentSize++;
    totalInsertions++;

    // Emit signals
    emit(pitSizeSignal, currentSize);
    emit(pitOccupancySignal, getOccupancy());

    EV_INFO << "Inserted interest in PIT: " << name << " (size=" << currentSize << ")" << endl;
    return true;
}

PITEntry* PIT::lookup(const std::string &name) {
    return findEntry(name);
}

bool PIT::satisfy(DataPacket *data, std::vector<int> &outFaces) {
    std::string name = data->getName();
    PITEntry *entry = findEntry(name);

    if (entry == nullptr) {
        EV_INFO << "No PIT entry found for Data: " << name << endl;
        return false;
    }

    // Get all incoming faces (where to send the data)
    outFaces.clear();
    for (int face : entry->incomingFaces) {
        outFaces.push_back(face);
    }

    // Mark as satisfied
    entry->isSatisfied = true;
    totalSatisfied++;

    // Remove entry
    removeEntry(name);

    emit(pitSatisfiedSignal, 1L);

    EV_INFO << "Satisfied PIT entry: " << name << " (faces=" << outFaces.size() << ")" << endl;
    return true;
}

bool PIT::aggregate(InterestPacket *interest, int inFace) {
    std::string name = interest->getName();
    PITEntry *entry = findEntry(name);

    if (entry == nullptr) {
        return false;
    }

    // Add incoming face
    entry->incomingFaces.insert(inFace);
    entry->nonces.insert(interest->getNonce());
    totalAggregated++;

    EV_INFO << "Aggregated interest: " << name << " (faces=" << entry->incomingFaces.size() << ")" << endl;
    return true;
}

bool PIT::hasEntry(const std::string &name) const {
    return entries.find(name) != entries.end();
}

void PIT::updateFace(const std::string &name, int face, bool isOutgoing) {
    PITEntry *entry = findEntry(name);
    if (entry != nullptr) {
        if (isOutgoing) {
            entry->outgoingFaces.insert(face);
        } else {
            entry->incomingFaces.insert(face);
        }
    }
}

std::vector<std::string> PIT::getAllEntries() const {
    std::vector<std::string> names;
    for (const auto &entry : entries) {
        names.push_back(entry.first);
    }
    return names;
}

void PIT::clear() {
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
    currentSize = 0;
}

PITEntry* PIT::findEntry(const std::string &name) {
    auto it = entries.find(name);
    if (it != entries.end()) {
        // Check if expired
        if (it->second->isExpired(simTime())) {
            expireEntry(name);
            return nullptr;
        }
        return it->second;
    }
    return nullptr;
}

PITEntry* PIT::createEntry(const std::string &name, simtime_t lifetime) {
    PITEntry *entry = new PITEntry();
    entry->name = name;
    entry->arrivalTime = simTime();
    entry->expiryTime = simTime() + lifetime;
    return entry;
}

void PIT::removeEntry(const std::string &name) {
    auto it = entries.find(name);
    if (it != entries.end()) {
        delete it->second;
        entries.erase(it);
        currentSize--;
        totalRemovals++;

        emit(pitSizeSignal, currentSize);
        emit(pitOccupancySignal, getOccupancy());
    }
}

void PIT::expireEntry(const std::string &name) {
    EV_INFO << "PIT entry expired: " << name << endl;
    removeEntry(name);
    totalExpirations++;
    emit(pitExpiredSignal, 1L);
}

void PIT::cleanupExpiredEntries() {
    std::vector<std::string> expiredNames;
    simtime_t now = simTime();

    // Find expired entries
    for (const auto &entry : entries) {
        if (entry.second->isExpired(now)) {
            expiredNames.push_back(entry.first);
        }
    }

    // Remove expired entries
    for (const std::string &name : expiredNames) {
        expireEntry(name);
    }

    if (!expiredNames.empty()) {
        EV_INFO << "Cleaned up " << expiredNames.size() << " expired PIT entries" << endl;
    }
}

void PIT::evictOldestEntry() {
    if (entries.empty()) {
        return;
    }

    // Find oldest entry
    auto oldest = entries.begin();
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->second->arrivalTime < oldest->second->arrivalTime) {
            oldest = it;
        }
    }

    EV_WARN << "Evicting oldest PIT entry: " << oldest->first << endl;
    removeEntry(oldest->first);
}

} // namespace veremivndn
