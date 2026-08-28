//
// DP-IDS-VNDN - FIB Hijacking Attack (Methodology Section 5.2)
// Installs forged name-prefix routing entries pointing toward attacker
//

#ifndef __VEREMIVNDN_FIBHIJACKINGATTACK_H
#define __VEREMIVNDN_FIBHIJACKINGATTACK_H

#include "../AttackBase.h"

namespace veremivndn {

class FIBHijackingAttack : public AttackBase
{
private:
    std::string hijackedPrefix;
    int forgedFaceId;
    double announcementInterval;
    bool maintainBehaviouralProfile;  // Section 5.2: evade behavioural IDS
    uint64_t routesForgedCount;
    uint64_t trafficDivertedCount;
    int tickCounter;

    simsignal_t routesForgedSignal;
    simsignal_t trafficDivertedSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual bool shouldAttackPacket(cMessage *msg) override;

    void sendForgedRouteAdvertisement();

public:
    FIBHijackingAttack() : routesForgedCount(0), trafficDivertedCount(0), tickCounter(0) {}
};

} // namespace veremivndn
#endif
