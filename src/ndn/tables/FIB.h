//
// VeReMiVNDN - Forwarding Information Base (FIB)
// Stores forwarding information for name prefixes
//

#ifndef __VEREMIVNDN_FIB_H
#define __VEREMIVNDN_FIB_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../core/NdnControlMessages_m.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include <algorithm>

using namespace omnetpp;

namespace veremivndn {

/**
 * FIB Entry
 * Represents a forwarding entry for a name prefix
 */
class FIBEntry {
public:
    std::string prefix;                         // Name prefix
    std::set<int> nextHops;                     // Next hop face IDs
    std::map<int, int> costs;                   // Cost for each face
    simtime_t timestamp;                        // Last update time
    int hopCount;                               // Distance to prefix
    std::string producer;                       // Producer ID

    // Statistics
    int forwardCount;
    simtime_t lastUsed;

    // VNDN specific
    double trustScore;                          // Trust in this route
    bool isLocal;                               // Local producer
    double linkQuality;                         // Link quality metric

    FIBEntry() : timestamp(0), hopCount(0), forwardCount(0),
                 lastUsed(0), trustScore(1.0), isLocal(false), linkQuality(1.0) {}

    void addNextHop(int face, int cost = 1) {
        nextHops.insert(face);
        costs[face] = cost;
    }

    void removeNextHop(int face) {
        nextHops.erase(face);
        costs.erase(face);
    }

    int getBestFace() const {
        if (nextHops.empty()) return -1;

        int bestFace = *nextHops.begin();
        int bestCost = costs.at(bestFace);

        for (int face : nextHops) {
            int cost = costs.at(face);
            if (cost < bestCost) {
                bestCost = cost;
                bestFace = face;
            }
        }
        return bestFace;
    }
};

/**
 * FIB (Forwarding Information Base)
 * Main routing table for NDN
 */
class FIB : public cSimpleModule {
private:
    // FIB storage: prefix -> entry
    std::map<std::string, FIBEntry*> entries;

    // Configuration
    int maxSize;
    bool enableDynamicRouting;
    simtime_t entryLifetime;

    // Statistics
    int currentSize;
    int totalInsertions;
    int totalRemovals;
    int totalLookups;
    int totalUpdates;

    // Cleanup timer
    cMessage *cleanupTimer;
    simtime_t cleanupInterval;

    // Signals
    simsignal_t fibSizeSignal;
    simsignal_t fibLookupSignal;
    simsignal_t fibUpdateSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Entry management
    FIBEntry* findEntry(const std::string &name);
    FIBEntry* findLongestPrefixMatch(const std::string &name);
    FIBEntry* createEntry(const std::string &prefix);
    void removeEntry(const std::string &prefix);

    // Prefix matching
    bool isPrefix(const std::string &prefix, const std::string &name) const;
    std::string getLongestMatchingPrefix(const std::string &name) const;

    // Cleanup
    void cleanupStaleEntries();
    bool isFull() const { return currentSize >= maxSize; }
    void evictEntry();

    // Control message handlers
    virtual void handleLookupRequest(FIBLookupRequest *request);
    virtual void handleAddRouteRequest(FIBAddRouteRequest *request);

public:
    FIB();
    virtual ~FIB();

    // FIB operations
    bool addRoute(const std::string &prefix, int face, int cost = 1);
    bool removeRoute(const std::string &prefix, int face);
    bool updateRoute(const std::string &prefix, int face, int cost);

    // Lookup operations
    FIBEntry* lookup(const std::string &name);
    int getNextHop(const std::string &name);
    std::vector<int> getAllNextHops(const std::string &name);

    // Query operations
    bool hasEntry(const std::string &prefix) const;
    int getSize() const { return currentSize; }

    // Statistics
    int getTotalLookups() const { return totalLookups; }

    // Advanced operations
    void updateTrust(const std::string &prefix, double trust);
    void updateLinkQuality(const std::string &prefix, double quality);
    std::vector<std::string> getAllPrefixes() const;
    void clear();
};

} // namespace veremivndn

#endif // __VEREMIVNDN_FIB_H
