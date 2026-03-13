//
// VeReMiVNDN - RSU Controller Header
// Controls RSU behavior, content generation, and announcements with network integration
//

#ifndef __VEREMIVNDN_RSUCONTROLLER_H
#define __VEREMIVNDN_RSUCONTROLLER_H

#include <omnetpp.h>
#include "../../ndn/packets/NdnPackets_m.h"
#include "../../ndn/core/NdnControlMessages_m.h"
#include <vector>
#include <string>

using namespace omnetpp;

namespace veremivndn {

class RSUController : public cSimpleModule {
protected:
    // RSU identity
    std::string rsuId;
    int rsuIndex;
    std::vector<std::string> producedPrefixes;

    // Timers
    cMessage *contentTimer;
    simtime_t contentInterval;
    cMessage *announceTimer;
    simtime_t announceInterval;

    // Counters
    int contentCounter;
    int packetsSent;
    int packetsReceived;

    // Gate IDs
    int ndnInGate;
    int ndnOutGate;
    int lowerLayerInGate;
    int lowerLayerOutGate;
    int lowerControlInGate;
    int lowerControlOutGate;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Message handlers
    virtual void handleSelfMessage(cMessage *msg);
    virtual void handleNDNMessage(cMessage *msg);
    virtual void handleLowerLayerMessage(cMessage *msg);
    virtual void handleLowerControlMessage(cMessage *msg);

    // RSU operations
    virtual void generateContent();
    virtual void announcePrefix();
    virtual void sendToNDN(cPacket *pkt);
    virtual void processNDNPacket(cPacket *pkt);

    // Network operations
    virtual void sendToLowerLayer(cPacket *pkt);
    virtual void processWirelessPacket(cPacket *pkt);

public:
    RSUController();
    virtual ~RSUController();
};

Define_Module(RSUController);

} // namespace veremivndn

#endif
