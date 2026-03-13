//
// VeReMiVNDN - Routing Information Flood (FIB/PIT Spoof) Attack
//
// Attack #18: Routing Information Flood (FIB/PIT Spoof)
// Layer: Control / Forwarding
// Description: Malicious advertisements cause excessive FIB updates or spoof PIT entries,
//              leading to router instability and resource exhaustion
// Impact: Router instability, resource exhaustion, routing table pollution, control plane overload
//

#ifndef __VEREMIVNDN_ROUTINGINFOFLOOD_H
#define __VEREMIVNDN_ROUTINGINFOFLOOD_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Routing Attack Types
 */
enum class RoutingAttackType {
    FIB_FLOOD,              // Flood FIB with fake route advertisements
    PIT_SPOOF,              // Spoof PIT entries
    ROUTE_POISON,           // Poison routing information
    CONTROL_OVERLOAD        // Overload control plane
};

/**
 * RoutingInfoFlood
 *
 * Implements Routing Information Flood attack that overwhelms
 * routers with excessive FIB updates or spoofed PIT entries,
 * causing instability and resource exhaustion.
 *
 * Attack Parameters (JSON):
 * - fibUpdateRate: int - FIB updates per second (default: 100)
 * - spoofEntries: bool - Spoof PIT/FIB entries (default: true)
 * - fakeRoutes: bool - Advertise fake routes (default: true)
 * - targetRouter: string - Specific router to target (default: "all")
 * - floodIntensity: double - Flooding intensity 0.0-1.0 (default: 0.9)
 */
class RoutingInfoFlood : public AttackBase
{
private:
    // Attack parameters
    int fibUpdateRate;
    bool spoofEntries;
    bool fakeRoutes;
    std::string targetRouter;
    double floodIntensity;
    RoutingAttackType attackType;

    // Attack state
    uint64_t fibUpdatesFlooded;
    uint64_t pitEntriesSpoofed;
    uint64_t fakeRoutesAdvertised;
    uint64_t controlMessagesFlooded;
    std::set<std::string> poisonedPrefixes;
    std::map<std::string, int> routeAdvertisementCount;

    // Statistics
    simsignal_t fibUpdatesFloodedSignal;
    simsignal_t pitEntriesSpoofedSignal;
    simsignal_t fakeRoutesSignal;
    simsignal_t controlOverloadSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // FIB flooding
    void floodFibUpdates();
    void advertiseFakeRoute(const std::string &prefix);
    void poisonRouteInformation(const std::string &prefix);

    // PIT spoofing
    void spoofPitEntry(const std::string &contentName);
    void createFakePitEntry();

    // Control plane overload
    void overloadControlPlane();
    void generateControlTraffic();

public:
    RoutingInfoFlood();
    virtual ~RoutingInfoFlood();

    // Attack-specific getters
    uint64_t getFibUpdatesFlooded() const { return fibUpdatesFlooded; }
    uint64_t getPitEntriesSpoofed() const { return pitEntriesSpoofed; }
    uint64_t getFakeRoutesAdvertised() const { return fakeRoutesAdvertised; }
};

Define_Module(RoutingInfoFlood);

} // namespace veremivndn

#endif // __VEREMIVNDN_ROUTINGINFOFLOOD_H
