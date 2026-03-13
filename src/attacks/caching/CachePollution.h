//
// VeReMiVNDN - Cache Pollution Attack
// Attack #3: Fills cache with unpopular content
//

#ifndef __VEREMIVNDN_CACHE_POLLUTION_H
#define __VEREMIVNDN_CACHE_POLLUTION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <vector>
#include <set>

namespace veremivndn {

class CachePollution : public AttackBase {
protected:
    // Attack parameters
    bool unpopularContent;
    int requestRate;
    int contentPoolSize;
    std::string targetPrefix;

    // Tracking
    std::vector<std::string> unpopularNames;
    std::set<std::string> requestedContent;
    cMessage *pollutionTimer;
    int pollutionCount;
    int uniqueContentRequested;

    // Signals
    simsignal_t pollutionRequestSignal;
    simsignal_t cacheFilledSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    virtual bool shouldAttackPacket(cMessage *msg) override;
    virtual cMessage* generateMaliciousPacket() override;

    // Cache pollution specific
    void generateUnpopularNames();
    InterestPacket* generatePollutionInterest();
    std::string selectUnpopularContent();

public:
    CachePollution();
    virtual ~CachePollution();
};

} // namespace veremivndn

#endif
