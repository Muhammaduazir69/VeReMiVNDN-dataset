//
// VeReMiVNDN - FIB Implementation
//

#include "FIB.h"
#include "../core/NdnControlMessages_m.h"

namespace veremivndn {

Define_Module(FIB);

FIB::FIB() : cleanupTimer(nullptr), currentSize(0), totalInsertions(0),
             totalRemovals(0), totalLookups(0), totalUpdates(0) {}

FIB::~FIB() {
    cancelAndDelete(cleanupTimer);
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
}

void FIB::initialize() {
    // Read parameters
    maxSize = par("maxSize");
    enableDynamicRouting = par("enableDynamicRouting");
    entryLifetime = par("entryLifetime");
    cleanupInterval = par("cleanupInterval");

    // Initialize statistics
    currentSize = 0;
    totalInsertions = 0;
    totalRemovals = 0;
    totalLookups = 0;
    totalUpdates = 0;

    // Register signals
    fibSizeSignal = registerSignal("fibSize");
    fibLookupSignal = registerSignal("fibLookup");
    fibUpdateSignal = registerSignal("fibUpdate");
    fibRouteAddEventSignal = registerSignal("fibRouteAddEvent");
    fibRouteRemoveEventSignal = registerSignal("fibRouteRemoveEvent");

    // Schedule cleanup timer
    cleanupTimer = new cMessage("fibCleanupTimer");
    scheduleAt(simTime() + cleanupInterval, cleanupTimer);

    EV_INFO << "FIB initialized: maxSize=" << maxSize << endl;

    // ---- Two-face static routing (no new params; role read from existing ones) ----
    // The NDN node exposes two faces (wired in the parent NED, in order):
    //   face 0 = APPLICATION face  (controller <-> stack, through attackModule)
    //   face 1 = WIRE face         (broadcast-medium side of the forwarder)
    // A PRODUCER (RSU, or a vehicle with isContentProducer=true such as an
    // attacker) routes its served prefixes to the app face, so Interests heard
    // off the wire are delivered up to the producer app (which answers).
    // A pure CONSUMER routes the same prefixes to the wire face, so the
    // Interests it originates on the app face are dispatched onto the medium.
    cModule *ndnNode = getParentModule();              // NdnNode
    cModule *parentNode = ndnNode->getParentModule();  // Vehicle or RSU
    std::string parentTypeName = parentNode->getComponentType()->getName();

    bool isProducer = false;
    if (parentTypeName.find("RSU") != std::string::npos)
        isProducer = true;                              // RSUs are always producers
    else if (parentNode->hasPar("isContentProducer"))
        isProducer = parentNode->par("isContentProducer").boolValue();

    const int APP_FACE = 0, WIRE_FACE = 1;
    int face = isProducer ? APP_FACE : WIRE_FACE;
    addRoute("/safety", face, 1);
    addRoute("/traffic", face, 1);
    addRoute("/emergency", face, 1);
    addRoute("/location", face, 1);
    addRoute("/info", face, 1);
    // /content is the namespace the Cache Pollution attacker floods; without a
    // route its Interests are NACKed at the first hop and never reach a Content
    // Store, so the attack cannot affect cache state.
    addRoute("/content", face, 1);

    EV_INFO << "FIB routes installed for " << parentNode->getFullName()
            << (isProducer ? " (producer -> app face)" : " (consumer -> wire face)") << endl;
}

void FIB::handleMessage(cMessage *msg) {
    if (msg == cleanupTimer) {
        cleanupStaleEntries();
        scheduleAt(simTime() + cleanupInterval, cleanupTimer);
    }
    else if (FIBLookupRequest *req = dynamic_cast<FIBLookupRequest*>(msg)) {
        handleLookupRequest(req);
    }
    else if (FIBAddRouteRequest *req = dynamic_cast<FIBAddRouteRequest*>(msg)) {
        handleAddRouteRequest(req);
    }
    else {
        delete msg;
    }
}

void FIB::handleLookupRequest(FIBLookupRequest *request) {
    FIBLookupResponse *response = new FIBLookupResponse();
    response->setName(request->getName());
    response->setTransactionId(request->getTransactionId());

    std::string name = request->getName();
    int inFace = request->getInFace();

    // Perform longest prefix match
    FIBEntry *entry = findLongestPrefixMatch(name);

    if (entry != nullptr && !entry->nextHops.empty()) {
        // Filter out incoming face
        std::vector<int> validNextHops;
        std::vector<int> validCosts;

        for (int nextHop : entry->nextHops) {
            if (nextHop != inFace) {  // Don't send back to incoming face
                validNextHops.push_back(nextHop);
                auto costIt = entry->costs.find(nextHop);
                int cost = (costIt != entry->costs.end()) ? costIt->second : 1;
                validCosts.push_back(cost);
            }
        }

        if (!validNextHops.empty()) {
            response->setFound(true);
            response->setNextHopsArraySize(validNextHops.size());
            response->setCostsArraySize(validCosts.size());

            for (size_t i = 0; i < validNextHops.size(); i++) {
                response->setNextHops(i, validNextHops[i]);
                response->setCosts(i, validCosts[i]);
            }

            response->setTrustScore(entry->trustScore);

            EV_INFO << "FIB lookup for " << name << " matched prefix " << entry->prefix
                    << " with " << validNextHops.size() << " next hops" << endl;
        } else {
            response->setFound(false);
            EV_WARN << "FIB lookup for " << name << " - all next hops filtered (incoming face)" << endl;
        }
    } else {
        response->setFound(false);
        EV_WARN << "No FIB entry found for " << name << endl;
    }

    totalLookups++;
    emit(fibLookupSignal, 1L);

    send(response, "processorOut");
    delete request;
}

void FIB::handleAddRouteRequest(FIBAddRouteRequest *request) {
    FIBAddRouteResponse *response = new FIBAddRouteResponse();
    response->setTransactionId(request->getTransactionId());

    bool success = addRoute(request->getPrefix(), request->getNextHop(), request->getCost());
    response->setSuccess(success);

    if (success) {
        EV_INFO << "Added FIB route: " << request->getPrefix()
                << " -> face " << request->getNextHop()
                << " (cost=" << request->getCost() << ")" << endl;
    } else {
        EV_WARN << "Failed to add FIB route for " << request->getPrefix() << endl;
    }

    send(response, "processorOut");
    delete request;
}

void FIB::finish() {
    // Record final statistics
    recordScalar("finalFIBSize", currentSize);
    recordScalar("totalInsertions", totalInsertions);
    recordScalar("totalRemovals", totalRemovals);
    recordScalar("totalLookups", totalLookups);
    recordScalar("totalUpdates", totalUpdates);

    EV_INFO << "FIB statistics: "
            << "size=" << currentSize
            << ", lookups=" << totalLookups
            << ", updates=" << totalUpdates << endl;
}

bool FIB::addRoute(const std::string &prefix, int face, int cost) {
    FIBEntry *entry = findEntry(prefix);

    if (entry == nullptr) {
        // Create new entry
        if (isFull()) {
            EV_WARN << "FIB is full, evicting entry" << endl;
            evictEntry();
        }

        entry = createEntry(prefix);
        entries[prefix] = entry;
        currentSize++;
        totalInsertions++;
    }

    // Add next hop
    entry->addNextHop(face, cost);
    entry->timestamp = simTime();
    totalUpdates++;

    emit(fibSizeSignal, currentSize);
    emit(fibUpdateSignal, 1L);
    emit(fibRouteAddEventSignal, 1L);

    EV_INFO << "Added route: prefix=" << prefix << ", face=" << face << ", cost=" << cost << endl;
    return true;
}

bool FIB::removeRoute(const std::string &prefix, int face) {
    FIBEntry *entry = findEntry(prefix);

    if (entry == nullptr) {
        return false;
    }

    entry->removeNextHop(face);

    // Remove entry if no next hops left
    if (entry->nextHops.empty()) {
        removeEntry(prefix);
    }

    EV_INFO << "Removed route: prefix=" << prefix << ", face=" << face << endl;
    return true;
}

bool FIB::updateRoute(const std::string &prefix, int face, int cost) {
    FIBEntry *entry = findEntry(prefix);

    if (entry == nullptr) {
        return addRoute(prefix, face, cost);
    }

    entry->costs[face] = cost;
    entry->timestamp = simTime();
    totalUpdates++;

    emit(fibUpdateSignal, 1L);

    EV_INFO << "Updated route: prefix=" << prefix << ", face=" << face << ", cost=" << cost << endl;
    return true;
}

FIBEntry* FIB::lookup(const std::string &name) {
    totalLookups++;
    emit(fibLookupSignal, 1L);

    FIBEntry *entry = findLongestPrefixMatch(name);

    if (entry != nullptr) {
        entry->forwardCount++;
        entry->lastUsed = simTime();
        EV_DETAIL << "FIB lookup for " << name << " -> " << entry->prefix << endl;
    } else {
        EV_DETAIL << "FIB lookup for " << name << " -> no match" << endl;
    }

    return entry;
}

int FIB::getNextHop(const std::string &name) {
    FIBEntry *entry = lookup(name);

    if (entry == nullptr || entry->nextHops.empty()) {
        return -1;
    }

    return entry->getBestFace();
}

std::vector<int> FIB::getAllNextHops(const std::string &name) {
    std::vector<int> hops;
    FIBEntry *entry = lookup(name);

    if (entry != nullptr) {
        hops.assign(entry->nextHops.begin(), entry->nextHops.end());
    }

    return hops;
}

bool FIB::hasEntry(const std::string &prefix) const {
    return entries.find(prefix) != entries.end();
}

void FIB::updateTrust(const std::string &prefix, double trust) {
    FIBEntry *entry = findEntry(prefix);
    if (entry != nullptr) {
        entry->trustScore = trust;
    }
}

void FIB::updateLinkQuality(const std::string &prefix, double quality) {
    FIBEntry *entry = findEntry(prefix);
    if (entry != nullptr) {
        entry->linkQuality = quality;
    }
}

std::vector<std::string> FIB::getAllPrefixes() const {
    std::vector<std::string> prefixes;
    for (const auto &entry : entries) {
        prefixes.push_back(entry.first);
    }
    return prefixes;
}

void FIB::clear() {
    for (auto &entry : entries) {
        delete entry.second;
    }
    entries.clear();
    currentSize = 0;
}

FIBEntry* FIB::findEntry(const std::string &prefix) {
    auto it = entries.find(prefix);
    return (it != entries.end()) ? it->second : nullptr;
}

FIBEntry* FIB::findLongestPrefixMatch(const std::string &name) {
    FIBEntry *bestMatch = nullptr;
    size_t longestMatch = 0;

    for (auto &pair : entries) {
        const std::string &prefix = pair.first;
        if (isPrefix(prefix, name)) {
            if (prefix.length() > longestMatch) {
                longestMatch = prefix.length();
                bestMatch = pair.second;
            }
        }
    }

    return bestMatch;
}

FIBEntry* FIB::createEntry(const std::string &prefix) {
    FIBEntry *entry = new FIBEntry();
    entry->prefix = prefix;
    entry->timestamp = simTime();
    return entry;
}

void FIB::removeEntry(const std::string &prefix) {
    auto it = entries.find(prefix);
    if (it != entries.end()) {
        delete it->second;
        entries.erase(it);
        currentSize--;
        totalRemovals++;

        emit(fibSizeSignal, currentSize);
        emit(fibRouteRemoveEventSignal, 1L);
    }
}

bool FIB::isPrefix(const std::string &prefix, const std::string &name) const {
    // Check if 'prefix' is a prefix of 'name'
    if (name.length() < prefix.length()) {
        return false;
    }

    return name.compare(0, prefix.length(), prefix) == 0;
}

std::string FIB::getLongestMatchingPrefix(const std::string &name) const {
    std::string bestPrefix;
    size_t longestMatch = 0;

    for (const auto &pair : entries) {
        const std::string &prefix = pair.first;
        if (isPrefix(prefix, name)) {
            if (prefix.length() > longestMatch) {
                longestMatch = prefix.length();
                bestPrefix = prefix;
            }
        }
    }

    return bestPrefix;
}

void FIB::cleanupStaleEntries() {
    if (entryLifetime <= 0) {
        return;  // No lifetime limit
    }

    std::vector<std::string> staleEntries;
    simtime_t now = simTime();

    for (const auto &pair : entries) {
        if (now - pair.second->timestamp > entryLifetime) {
            staleEntries.push_back(pair.first);
        }
    }

    for (const std::string &prefix : staleEntries) {
        EV_INFO << "Removing stale FIB entry: " << prefix << endl;
        removeEntry(prefix);
    }
}

void FIB::evictEntry() {
    if (entries.empty()) {
        return;
    }

    // Evict least recently used entry
    auto lru = entries.begin();
    simtime_t oldestTime = lru->second->lastUsed;

    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->second->lastUsed < oldestTime) {
            oldestTime = it->second->lastUsed;
            lru = it;
        }
    }

    EV_WARN << "Evicting FIB entry: " << lru->first << endl;
    removeEntry(lru->first);
}

void FIB::penalizeRoute(const std::string &prefix, int face, double costMultiplier) {
    FIBEntry *entry = findEntry(prefix);
    if (entry != nullptr) {
        auto costIt = entry->costs.find(face);
        if (costIt != entry->costs.end()) {
            // Clamp multiplier to prevent overflow (max cost 10000)
            double rawCost = costIt->second * std::min(costMultiplier, 1000.0);
            int newCost = (int)std::min(rawCost, 10000.0);
            if (newCost < 1) newCost = 1;
            costIt->second = newCost;
            EV_INFO << "DP-IDS: Penalized route " << prefix << " face " << face
                    << " cost multiplied by " << costMultiplier
                    << " -> " << newCost << endl;
        }
    }
}

void FIB::restoreRoutes() {
    // TRIDENT reinstatement: reset every face cost on this table back to the base
    // routing cost, undoing prior trust-aware penalisation so a reinstated node's
    // routes regain normal priority. This is what makes the quarantine reversible.
    for (auto &e : entries) {
        for (auto &c : e.second->costs)
            c.second = 1;
    }
    EV_INFO << "TRIDENT: restored all FIB route costs to base" << endl;
}

} // namespace veremivndn
