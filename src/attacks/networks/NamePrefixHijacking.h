//
// VeReMiVNDN - Name Prefix Hijacking Attack Implementation
//
// Attack #5: Name Prefix Hijacking / Route Hijack
// Layer: Routing / Forwarding (FIB)
// Description: Malicious node advertises ownership of name prefixes it doesn't serve,
//              attracting Interest packets and enabling interception or bogus data delivery
// Impact: Interest interception, data delivery failure, routing pollution, MITM attacks
//

#ifndef __VEREMIVNDN_NAMEPREFIXHIJACKING_H
#define __VEREMIVNDN_NAMEPREFIXHIJACKING_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Hijacking Mode
 */
enum class HijackingMode {
    ADVERTISE_ONLY,     // Only advertise fake routes
    INTERCEPT,          // Intercept and drop traffic
    MITM,               // Man-in-the-middle (forward modified)
    BLACK_HOLE          // Drop all intercepted traffic
};

/**
 * NamePrefixHijacking
 *
 * Implements Name Prefix Hijacking attack by advertising fake ownership
 * of name prefixes to attract Interest packets.
 *
 * Attack Parameters (JSON):
 * - hijackedPrefix: string - Prefix to hijack (default: "/safety")
 * - advertiseFake: bool - Advertise fake routes (default: true)
 * - interceptTraffic: bool - Intercept traffic (default: true)
 * - mode: string - Attack mode: "advertise", "intercept", "mitm", "blackhole"
 * - advertisementRate: int - Route advertisements per second (default: 10)
 * - hopCountLie: int - Advertise false hop count (default: 1)
 */
class NamePrefixHijacking : public AttackBase
{
private:
    // Attack parameters
    std::string hijackedPrefix;
    bool advertiseFake;
    bool interceptTraffic;
    HijackingMode mode;
    int advertisementRate;
    int hopCountLie;  // Advertise lower hop count to attract traffic
    bool injectBogusData;

    // Attack state
    std::set<std::string> hijackedPrefixes;
    uint64_t interceptedInterests;
    uint64_t forgedAdvertisements;
    uint64_t bogusDataSent;
    std::vector<InterestPacket*> interceptedPackets;

    // Timers
    cMessage *advertisementTimer;

    // Statistics
    simsignal_t prefixHijackedSignal;
    simsignal_t interestInterceptedSignal;
    simsignal_t bogusDataSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Route advertisement
    void advertiseHijackedPrefix();
    void sendFakeRouteAdvertisement(const std::string &prefix);
    void polluteFIBEntries();

    // Traffic interception
    bool shouldInterceptPacket(cMessage *msg);
    void handleInterceptedInterest(InterestPacket *interest);
    void handleInterceptedData(DataPacket *data);

    // MITM operations
    DataPacket* createBogusData(InterestPacket *interest);
    InterestPacket* modifyInterest(InterestPacket *interest);
    DataPacket* modifyData(DataPacket *data);

    // Overrides from AttackBase
    virtual bool shouldAttackPacket(cMessage *msg) override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;
    virtual cMessage* generateMaliciousPacket() override;

    // Configuration
    virtual void parseParameters(const std::string &params) override;

public:
    NamePrefixHijacking();
    virtual ~NamePrefixHijacking();

    // Attack-specific getters
    uint64_t getInterceptedInterests() const { return interceptedInterests; }
    uint64_t getForgedAdvertisements() const { return forgedAdvertisements; }
    const std::set<std::string>& getHijackedPrefixes() const { return hijackedPrefixes; }
};

Define_Module(NamePrefixHijacking);

} // namespace veremivndn

#endif // __VEREMIVNDN_NAMEPREFIXHIJACKING_H
