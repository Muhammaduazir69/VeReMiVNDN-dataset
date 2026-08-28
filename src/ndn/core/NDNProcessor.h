//
// VeReMiVNDN - NDN Processor Header
//

#ifndef __VEREMIVNDN_NDNPROCESSOR_H
#define __VEREMIVNDN_NDNPROCESSOR_H

#include <omnetpp.h>
#include "../packets/NdnPackets_m.h"
#include "../tables/PIT.h"
#include "../tables/FIB.h"
#include "../tables/CS.h"
#include <map>
#include <vector>
#include <string>

using namespace omnetpp;

namespace veremivndn {

// Transaction types for tracking pending requests
enum TransactionType {
    TRANS_CS_LOOKUP,
    TRANS_PIT_INSERT,
    TRANS_PIT_SATISFY,
    TRANS_FIB_LOOKUP
};

// Structure to track pending transactions with PIT/FIB/CS
struct PendingTransaction {
    int transactionId;
    TransactionType type;
    cMessage *packet;
    int inFace;
    simtime_t timestamp;
};

class NDNProcessor : public cSimpleModule {
protected:
    // Node info
    int nodeId;
    std::string nodeIdentifier;

    // Configuration
    bool enableCaching;
    bool enableSignatureVerification;
    bool enableTridentAdmission = false;   // TRIDENT prong 2: cache admission
    simtime_t signatureVerificationDelay;
    std::string forwardingStrategy;

    // Face management
    std::map<int, int> faceToGate;  // faceId -> gateIndex
    std::map<int, int> gateToFace;  // gateIndex -> faceId
    int nextFaceId;

    // Transaction management for async operations
    std::map<int, PendingTransaction> pendingTransactions;
    int nextTransactionId;

    // Statistics signals
    simsignal_t interestSentSignal;
    simsignal_t interestReceivedSignal;
    simsignal_t dataSentSignal;
    simsignal_t dataReceivedSignal;
    simsignal_t cacheHitSignal;
    simsignal_t cacheMissSignal;
    simsignal_t nackSentSignal;
    simsignal_t nackReceivedSignal;
    simsignal_t packetDroppedSignal;
    simsignal_t forwardingDelaySignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    // Counters for visualization
    int interestsSent = 0, interestsReceived = 0;
    int dataSent = 0, dataReceived = 0;
    int cacheHits = 0, cacheMisses = 0;

    // Message handlers
    virtual void handleNetworkPacket(cMessage *msg);
    virtual void handlePITResponse(cMessage *msg);
    virtual void handleFIBResponse(cMessage *msg);
    virtual void handleCSResponse(cMessage *msg);

    // NDN operations
    virtual void processInterest(InterestPacket *interest, int inFace);
    virtual void processData(DataPacket *data, int inFace);
    virtual void processNack(NackPacket *nack, int inFace);

    // Module communication handlers
    virtual void handlePITInsertResponse(class PITInsertResponse *response);
    virtual void handlePITSatisfyResponse(class PITSatisfyResponse *response);
    virtual void queryPIT(InterestPacket *interest, int inFace, int transactionId);
    virtual void queryFIB(InterestPacket *interest, int inFace, int transactionId);

    // Forwarding
    virtual void forwardInterest(InterestPacket *interest, int outFace);
    virtual void forwardData(DataPacket *data, int outFace);
    virtual void sendNack(InterestPacket *interest, int outFace, NackReason reason);

    // Face management
    virtual int registerFace(int gateIndex);
    virtual int getFaceForGate(int gateIndex);
    virtual int getGateForFace(int faceId);

    // Helpers
    virtual bool shouldCacheData(DataPacket *data);
    virtual bool verifySignature(DataPacket *data);

    // VeReMiVNDN-EXE: hand every observed packet / CS outcome to the host's
    // FeatureExtractor so the MI-IDS plane vectors are built from traffic the
    // node actually saw. Resolved lazily and cached; null when the host has no
    // IDS instance, in which case observation is a no-op.
    class FeatureExtractor *exeObserver = nullptr;
    bool exeObserverResolved = false;
    class FeatureExtractor *getExeObserver();

public:
    NDNProcessor();
    virtual ~NDNProcessor();

    // Helper functions for creating packets
    InterestPacket* createInterest(const std::string &name);
    DataPacket* createData(const std::string &name, const std::string &content);

    // Read-only counter accessors so the IDS module can sample live
    // traffic statistics without going through cParameter.
    int getInterestsSent()    const { return interestsSent; }
    int getInterestsReceived()const { return interestsReceived; }
    int getDataSent()         const { return dataSent; }
    int getDataReceived()     const { return dataReceived; }
    int getCacheHits()        const { return cacheHits; }
    int getCacheMisses()      const { return cacheMisses; }
};

Define_Module(NDNProcessor);

} // namespace veremivndn

#endif
