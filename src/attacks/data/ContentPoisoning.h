//
// VeReMiVNDN - Content Poisoning Attack
//

#ifndef __VEREMIVNDN_CONTENTPOISONING_H
#define __VEREMIVNDN_CONTENTPOISONING_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"

namespace veremivndn {

class ContentPoisoning : public AttackBase {
private:
    std::string targetPrefix;
    double poisonProbability;
    bool modifyContent;
    bool keepSignature;

    uint64_t poisonedPackets;

    simsignal_t contentPoisonedSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    DataPacket* poisonData(DataPacket *original);
    std::string generateFakeContent();

public:
    ContentPoisoning();
    virtual ~ContentPoisoning();
};

Define_Module(ContentPoisoning);

} // namespace veremivndn

#endif
