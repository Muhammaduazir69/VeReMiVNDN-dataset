//
// VeReMiVNDN - Content Store (Cache)
//

#ifndef __VEREMIVNDN_CS_H
#define __VEREMIVNDN_CS_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../packets/NdnPackets_m.h"
#include "../core/NdnControlMessages_m.h"
#include <map>
#include <list>
#include <string>

using namespace omnetpp;

namespace veremivndn {

enum class ReplacementPolicy {
    LRU,    // Least Recently Used
    LFU,    // Least Frequently Used
    FIFO    // First In First Out
};

class CSEntry {
public:
    std::string name;
    DataPacket *data;
    simtime_t insertionTime;
    simtime_t expiryTime;
    int accessCount;
    simtime_t lastAccess;
    int size;  // bytes

    CSEntry(const std::string &n, DataPacket *d) :
        name(n), data(d), insertionTime(simTime()),
        expiryTime(0), accessCount(0), lastAccess(simTime()), size(0) {
        if (d) {
            size = d->getContentLength();
            if (d->getFreshnessPeriod() > 0) {
                expiryTime = simTime() + d->getFreshnessPeriod();
            }
        }
    }

    ~CSEntry() {
        if (data) delete data;
    }

    bool isExpired() const {
        return (expiryTime > 0 && simTime() >= expiryTime);
    }

    bool isFresh() const {
        return !isExpired();
    }
};

class CS : public cSimpleModule {
private:
    // Cache storage
    std::map<std::string, CSEntry*> entries;
    std::list<std::string> lruList;  // For LRU policy

    // Configuration
    int maxSize;  // MB
    int maxSizeBytes;
    ReplacementPolicy policy;
    bool enabled;

    // Statistics
    int currentSize;
    int currentSizeBytes;
    int totalInsertions;
    int totalHits;
    int totalMisses;
    int totalEvictions;
    int totalExpired;

    // Cleanup
    cMessage *cleanupTimer;
    simtime_t cleanupInterval;

    // Signals
    simsignal_t csSizeSignal;
    simsignal_t csHitSignal;
    simsignal_t csMissSignal;
    simsignal_t csHitRatioSignal;
    simsignal_t csInsertionEventSignal;
    simsignal_t csEvictionEventSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Entry management
    CSEntry* findEntry(const std::string &name);
    void insertEntry(const std::string &name, DataPacket *data);
    void removeEntry(const std::string &name);
    void evictEntry();
    void cleanupExpiredEntries();

    // Replacement policies
    void evictLRU();
    void evictLFU();
    void evictFIFO();
    void updateLRU(const std::string &name);

    // Size management
    bool isFull(int dataSize) const;
    bool hasSpace(int dataSize) const;

    // Control message handlers
    virtual void handleLookupRequest(CSLookupRequest *request);
    virtual void handleInsertRequest(CSInsertRequest *request);

public:
    CS();
    virtual ~CS();

    // Cache operations
    bool insert(DataPacket *data);
    DataPacket* lookup(const std::string &name);
    bool contains(const std::string &name);
    void clear();

    // Statistics
    int getSize() const { return currentSize; }
    int getCurrentSizeEntries() const { return currentSize; }
    int getTotalHits() const { return totalHits; }
    int getTotalMisses() const { return totalMisses; }
    int getTotalInsertions() const { return totalInsertions; }
    int getMaxSizeValue() const { return maxSize; }
    double getHitRatio() const {
        int total = totalHits + totalMisses;
        return total > 0 ? (double)totalHits / total : 0.0;
    }

    // DP-IDS Penalisation API (Section 4.5)
    void reduceFreshness(const std::string &name, double factor);
    void bypassVehicleEntries(const std::string &vehicleId);

    // Access to entries for divergence analysis
    const std::map<std::string, CSEntry*>& getEntries() const { return entries; }
};

} // namespace veremivndn

#endif
