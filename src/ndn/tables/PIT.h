//
// VeReMiVNDN - Pending Interest Table (PIT)
// Stores pending interests awaiting data responses
//

#ifndef __VEREMIVNDN_PIT_H
#define __VEREMIVNDN_PIT_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../packets/NdnPackets_m.h"
#include "../core/NdnControlMessages_m.h"
#include <map>
#include <set>
#include <vector>
#include <string>

using namespace omnetpp;

namespace veremivndn {

/**
 * PIT Entry
 * Represents a pending interest in the PIT
 */
class PITEntry {
public:
    std::string name;                           // Content name
    simtime_t arrivalTime;                      // When interest arrived
    simtime_t expiryTime;                       // When entry expires
    std::set<int> incomingFaces;                // Incoming interface IDs
    std::set<int> outgoingFaces;                // Outgoing interface IDs
    std::set<int> nonces;                       // Nonces seen for this interest
    int hopCount;                               // Number of hops
    std::string forwardingHint;                 // Forwarding hint
    bool isSatisfied;                           // Whether data received

    // Statistics
    int retransmissionCount;
    simtime_t lastRetransmission;

    // VNDN specific
    double producerTrust;                       // Trust in producer
    int priority;                               // Interest priority

    PITEntry() : arrivalTime(0), expiryTime(0), hopCount(0),
                 isSatisfied(false), retransmissionCount(0),
                 lastRetransmission(0), producerTrust(1.0), priority(0) {}

    bool isExpired(simtime_t now) const {
        return now >= expiryTime;
    }

    bool hasNonce(int nonce) const {
        return nonces.find(nonce) != nonces.end();
    }
};

/**
 * PIT (Pending Interest Table)
 * Main data structure for tracking pending interests
 */
class PIT : public cSimpleModule {
private:
    // PIT storage: name -> entry
    std::map<std::string, PITEntry*> entries;

    // Configuration
    int maxSize;
    simtime_t defaultLifetime;
    bool enableAggregation;

    // Statistics
    int currentSize;
    int totalInsertions;
    int totalRemovals;
    int totalExpirations;
    int totalSatisfied;
    int totalAggregated;

    // Cleanup timer
    cMessage *cleanupTimer;
    simtime_t cleanupInterval;

    // Signals
    simsignal_t pitSizeSignal;
    simsignal_t pitOccupancySignal;
    simsignal_t pitExpiredSignal;
    simsignal_t pitSatisfiedSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Entry management
    PITEntry* findEntry(const std::string &name);
    PITEntry* createEntry(const std::string &name, simtime_t lifetime);
    void removeEntry(const std::string &name);
    void expireEntry(const std::string &name);

    // Cleanup
    void cleanupExpiredEntries();
    bool isFull() const { return currentSize >= maxSize; }
    void evictOldestEntry();

    // Control message handlers
    virtual void handleInsertRequest(PITInsertRequest *request);
    virtual void handleSatisfyRequest(PITSatisfyRequest *request);

public:
    PIT();
    virtual ~PIT();

    // PIT operations
    bool insert(InterestPacket *interest, int inFace);
    PITEntry* lookup(const std::string &name);
    bool satisfy(DataPacket *data, std::vector<int> &outFaces);
    bool aggregate(InterestPacket *interest, int inFace);

    // Query operations
    bool hasEntry(const std::string &name) const;
    int getSize() const { return currentSize; }
    double getOccupancy() const { return (double)currentSize / maxSize; }

    // Statistics
    int getTotalInsertions() const { return totalInsertions; }
    int getTotalSatisfied() const { return totalSatisfied; }
    int getTotalAggregated() const { return totalAggregated; }

    // Advanced operations
    void updateFace(const std::string &name, int face, bool isOutgoing);
    std::vector<std::string> getAllEntries() const;
    void clear();
};

} // namespace veremivndn

#endif // __VEREMIVNDN_PIT_H
