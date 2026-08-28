//
// DP-IDS-VNDN - CS Poisoning Attack (Methodology Section 5.2)
// Replaces cached content with fabricated data while maintaining normal behavioural profile
//

#ifndef __VEREMIVNDN_CSPOISONINGATTACK_H
#define __VEREMIVNDN_CSPOISONINGATTACK_H

#include "../AttackBase.h"

namespace veremivndn {

class CSPoisoningAttack : public AttackBase
{
private:
    std::string targetPrefix;
    double replaceProbability;
    std::string poisonContent;
    bool maintainBehaviouralProfile;  // Section 5.2: evade behavioural IDS
    uint64_t contentReplacedCount;
    int poisonCounter;  // For generating unique poisoned content names

    simsignal_t contentReplacedSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual bool shouldAttackPacket(cMessage *msg) override;

public:
    CSPoisoningAttack() : contentReplacedCount(0), poisonCounter(0) {}
};

} // namespace veremivndn
#endif
