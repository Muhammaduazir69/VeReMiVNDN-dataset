//
// VeReMiVNDN - Content Store Implementation
//

#include "CS.h"
#include "../core/NdnControlMessages_m.h"

namespace veremivndn {

Define_Module(CS);

CS::CS() : cleanupTimer(nullptr), currentSize(0), currentSizeBytes(0),
           totalInsertions(0), totalHits(0), totalMisses(0),
           totalEvictions(0), totalExpired(0) {}

CS::~CS() {
    cancelAndDelete(cleanupTimer);
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
}

void CS::initialize() {
    maxSize = par("maxSize");
    maxSizeBytes = maxSize * 1024 * 1024;  // Convert MB to bytes
    enabled = par("enabled");

    std::string policyStr = par("replacementPolicy").stdstringValue();
    if (policyStr == "LRU") policy = ReplacementPolicy::LRU;
    else if (policyStr == "LFU") policy = ReplacementPolicy::LFU;
    else if (policyStr == "FIFO") policy = ReplacementPolicy::FIFO;
    else policy = ReplacementPolicy::LRU;

    cleanupInterval = par("cleanupInterval");

    // Register signals
    csSizeSignal = registerSignal("csSize");
    csHitSignal = registerSignal("csHit");
    csMissSignal = registerSignal("csMiss");
    csHitRatioSignal = registerSignal("csHitRatio");

    // Schedule cleanup
    cleanupTimer = new cMessage("csCleanup");
    scheduleAt(simTime() + cleanupInterval, cleanupTimer);

    EV_INFO << "CS initialized: maxSize=" << maxSize << "MB, policy=" << policyStr << endl;
}

void CS::handleMessage(cMessage *msg) {
    if (msg == cleanupTimer) {
        cleanupExpiredEntries();
        scheduleAt(simTime() + cleanupInterval, cleanupTimer);
    }
    else if (CSLookupRequest *req = dynamic_cast<CSLookupRequest*>(msg)) {
        handleLookupRequest(req);
    }
    else if (CSInsertRequest *req = dynamic_cast<CSInsertRequest*>(msg)) {
        handleInsertRequest(req);
    }
    else {
        delete msg;
    }
}

void CS::finish() {
    recordScalar("finalCSSize", currentSize);
    recordScalar("totalInsertions", totalInsertions);
    recordScalar("totalHits", totalHits);
    recordScalar("totalMisses", totalMisses);
    recordScalar("totalEvictions", totalEvictions);
    recordScalar("hitRatio", getHitRatio());

    EV_INFO << "CS statistics: hits=" << totalHits
            << ", misses=" << totalMisses
            << ", hitRatio=" << getHitRatio() << endl;
}

bool CS::insert(DataPacket *data) {
    if (!enabled || !data) {
        return false;
    }

    std::string name = data->getName();
    int dataSize = data->getContentLength();

    // Check if already cached
    if (contains(name)) {
        CSEntry *existing = findEntry(name);
        if (existing && existing->isFresh()) {
            return false;  // Already cached and fresh
        }
        removeEntry(name);  // Remove stale entry
    }

    // Check space
    while (!hasSpace(dataSize) && currentSize > 0) {
        evictEntry();
    }

    if (!hasSpace(dataSize)) {
        return false;  // Still no space
    }

    // Create copy and insert
    DataPacket *dataCopy = data->dup();
    insertEntry(name, dataCopy);

    totalInsertions++;
    emit(csSizeSignal, currentSize);

    EV_INFO << "Cached: " << name << " (size=" << currentSize << ")" << endl;
    return true;
}

DataPacket* CS::lookup(const std::string &name) {
    if (!enabled) {
        totalMisses++;
        return nullptr;
    }

    CSEntry *entry = findEntry(name);

    if (entry == nullptr || entry->isExpired()) {
        totalMisses++;
        emit(csMissSignal, 1L);
        emit(csHitRatioSignal, getHitRatio());

        if (entry && entry->isExpired()) {
            removeEntry(name);
            totalExpired++;
        }

        return nullptr;
    }

    // Cache hit
    entry->accessCount++;
    entry->lastAccess = simTime();
    updateLRU(name);

    totalHits++;
    emit(csHitSignal, 1L);
    emit(csHitRatioSignal, getHitRatio());

    EV_INFO << "Cache HIT: " << name << endl;
    return entry->data->dup();
}

bool CS::contains(const std::string &name) {
    CSEntry *entry = findEntry(name);
    return entry != nullptr && entry->isFresh();
}

void CS::clear() {
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
    lruList.clear();
    currentSize = 0;
    currentSizeBytes = 0;
}

CSEntry* CS::findEntry(const std::string &name) {
    auto it = entries.find(name);
    return (it != entries.end()) ? it->second : nullptr;
}

void CS::insertEntry(const std::string &name, DataPacket *data) {
    CSEntry *entry = new CSEntry(name, data);
    entries[name] = entry;
    lruList.push_front(name);

    currentSize++;
    currentSizeBytes += entry->size;
}

void CS::removeEntry(const std::string &name) {
    auto it = entries.find(name);
    if (it != entries.end()) {
        currentSizeBytes -= it->second->size;
        delete it->second;
        entries.erase(it);
        lruList.remove(name);
        currentSize--;
    }
}

void CS::evictEntry() {
    switch (policy) {
        case ReplacementPolicy::LRU:
            evictLRU();
            break;
        case ReplacementPolicy::LFU:
            evictLFU();
            break;
        case ReplacementPolicy::FIFO:
            evictFIFO();
            break;
    }
}

void CS::evictLRU() {
    if (lruList.empty()) return;

    std::string name = lruList.back();
    EV_INFO << "Evicting (LRU): " << name << endl;
    removeEntry(name);
    totalEvictions++;
}

void CS::evictLFU() {
    if (entries.empty()) return;

    auto lfu = entries.begin();
    int minAccess = lfu->second->accessCount;

    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->second->accessCount < minAccess) {
            minAccess = it->second->accessCount;
            lfu = it;
        }
    }

    EV_INFO << "Evicting (LFU): " << lfu->first << endl;
    removeEntry(lfu->first);
    totalEvictions++;
}

void CS::evictFIFO() {
    if (entries.empty()) return;

    auto oldest = entries.begin();
    simtime_t oldestTime = oldest->second->insertionTime;

    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->second->insertionTime < oldestTime) {
            oldestTime = it->second->insertionTime;
            oldest = it;
        }
    }

    EV_INFO << "Evicting (FIFO): " << oldest->first << endl;
    removeEntry(oldest->first);
    totalEvictions++;
}

void CS::updateLRU(const std::string &name) {
    lruList.remove(name);
    lruList.push_front(name);
}

void CS::cleanupExpiredEntries() {
    std::vector<std::string> expiredNames;

    for (const auto &entry : entries) {
        if (entry.second->isExpired()) {
            expiredNames.push_back(entry.first);
        }
    }

    for (const std::string &name : expiredNames) {
        removeEntry(name);
        totalExpired++;
    }

    if (!expiredNames.empty()) {
        EV_INFO << "Cleaned " << expiredNames.size() << " expired entries" << endl;
    }
}

bool CS::isFull(int dataSize) const {
    return currentSizeBytes + dataSize > maxSizeBytes;
}

bool CS::hasSpace(int dataSize) const {
    return currentSizeBytes + dataSize <= maxSizeBytes;
}

void CS::handleLookupRequest(CSLookupRequest *request) {
    CSLookupResponse *response = new CSLookupResponse();
    response->setName(request->getName());
    response->setTransactionId(request->getTransactionId());

    if (!enabled) {
        response->setFound(false);
        totalMisses++;
        emit(csMissSignal, 1L);
        emit(csHitRatioSignal, getHitRatio());
        send(response, "processorOut");
        delete request;
        return;
    }

    std::string name = request->getName();
    CSEntry *entry = findEntry(name);

    if (entry == nullptr || entry->isExpired()) {
        // Cache miss
        totalMisses++;
        emit(csMissSignal, 1L);
        emit(csHitRatioSignal, getHitRatio());

        if (entry && entry->isExpired()) {
            removeEntry(name);
            totalExpired++;
            EV_INFO << "Cache entry expired: " << name << endl;
        }

        response->setFound(false);
        EV_INFO << "Cache MISS: " << name << endl;
    } else {
        // Cache hit - return cached data
        entry->accessCount++;
        entry->lastAccess = simTime();
        updateLRU(name);

        totalHits++;
        emit(csHitSignal, 1L);
        emit(csHitRatioSignal, getHitRatio());

        response->setFound(true);
        response->setData(dynamic_cast<cMessage*>(entry->data->dup()));

        EV_INFO << "Cache HIT: " << name << " (hits=" << totalHits
                << ", misses=" << totalMisses
                << ", ratio=" << getHitRatio() << ")" << endl;
    }

    send(response, "processorOut");
    delete request;
}

void CS::handleInsertRequest(CSInsertRequest *request) {
    CSInsertResponse *response = new CSInsertResponse();
    response->setName(request->getName());
    response->setTransactionId(request->getTransactionId());

    if (!enabled) {
        response->setSuccess(false);
        send(response, "processorOut");
        delete request;
        return;
    }

    std::string name = request->getName();
    DataPacket *data = const_cast<DataPacket*>(dynamic_cast<const DataPacket*>(request->getData()));

    if (!data) {
        response->setSuccess(false);
        send(response, "processorOut");
        delete request;
        return;
    }

    int dataSize = data->getContentLength();

    // Check if already cached
    if (contains(name)) {
        CSEntry *existing = findEntry(name);
        if (existing && existing->isFresh()) {
            // Already cached and fresh, no need to insert
            response->setSuccess(false);
            EV_INFO << "Data already cached and fresh: " << name << endl;
            send(response, "processorOut");
            delete request;
            return;
        }
        // Remove stale entry
        removeEntry(name);
    }

    // Check space and evict if necessary
    while (!hasSpace(dataSize) && currentSize > 0) {
        evictEntry();
    }

    if (!hasSpace(dataSize)) {
        // Still no space after eviction
        response->setSuccess(false);
        EV_WARN << "CS full, cannot cache: " << name << endl;
        send(response, "processorOut");
        delete request;
        return;
    }

    // Create copy and insert
    DataPacket *dataCopy = data->dup();
    insertEntry(name, dataCopy);

    totalInsertions++;
    emit(csSizeSignal, currentSize);

    response->setSuccess(true);

    EV_INFO << "Cached data: " << name
            << " (size=" << currentSize
            << "/" << maxSize
            << ", bytes=" << currentSizeBytes
            << "/" << maxSizeBytes << ")" << endl;

    send(response, "processorOut");
    delete request;
}

} // namespace veremivndn
