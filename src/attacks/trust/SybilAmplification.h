//
// VeReMiVNDN - Sybil Amplification Attack Header
// Creates multiple fake identities to amplify content requests
//

#ifndef __VEREMIVNDN_SYBIL_AMPLIFICATION_H
#define __VEREMIVNDN_SYBIL_AMPLIFICATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <vector>
#include <string>
#include <random>

namespace veremivndn {

class SybilAmplification : public AttackBase {
protected:
    // Attack parameters
    int numSybilIds;
    bool coordinatedRequests;
    bool spoofLocation;
    std::string targetContent;

    // Sybil identities
    struct SybilIdentity {
        std::string id;
        int nodeId;
        double x, y;  // fake position
        simtime_t lastActive;
    };

    std::vector<SybilIdentity> sybilIdentities;

    // Attack statistics
    int requestsGenerated;
    int currentIdentityIndex;

    // Timers
    cMessage *requestTimer;

    // Signals
    simsignal_t sybilRequestSignal;
    simsignal_t identitySwitchSignal;

    // Random number generation
    std::mt19937 rng;
    std::uniform_int_distribution<int> identityDist;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Sybil-specific methods
    virtual void createSybilIdentities();
    virtual void generateCoordinatedRequests();
    virtual void sendSybilInterest(const SybilIdentity &identity);
    virtual SybilIdentity &selectNextIdentity();
    virtual std::string generateTargetName();

public:
    SybilAmplification();
    virtual ~SybilAmplification();
};

Define_Module(SybilAmplification);

} // namespace veremivndn

#endif
