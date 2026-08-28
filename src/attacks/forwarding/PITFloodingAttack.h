//
// DP-IDS-VNDN - PIT Flooding Attack (Methodology Section 5.2)
// Generates unsatisfiable interests to exhaust PIT at victim nodes
//

#ifndef __VEREMIVNDN_PITFLOODINGATTACK_H
#define __VEREMIVNDN_PITFLOODINGATTACK_H

#include "../AttackBase.h"
#include <random>

namespace veremivndn {

class PITFloodingAttack : public AttackBase
{
private:
    std::string targetPrefix;
    int floodRate;          // interests per second (moderate for stealth)
    bool maintainBehaviouralProfile;  // Section 5.2: evade behavioural IDS
    uint64_t unsatisfiableCount;
    int nameCounter;

    std::mt19937 rng;

    simsignal_t unsatisfiableInterestsSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual bool shouldAttackPacket(cMessage *msg) override;

    std::string generateRealisticName();

public:
    PITFloodingAttack() : unsatisfiableCount(0), nameCounter(0) {}
};

} // namespace veremivndn
#endif
