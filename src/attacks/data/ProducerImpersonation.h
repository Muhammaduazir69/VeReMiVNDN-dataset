//
// VeReMiVNDN - Producer Impersonation / Fake Producers Attack
//
// Attack #16: Producer Impersonation / Fake Producers
// Layer: Trust / Application
// Description: Malicious node advertises content names as if produced by legitimate producer
//              (without owning keys), delivering fake content
// Impact: Fake content delivery, producer identity theft, trust undermining, authentication bypass
//

#ifndef __VEREMIVNDN_PRODUCERIMPERSONATION_H
#define __VEREMIVNDN_PRODUCERIMPERSONATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <string>

namespace veremivndn {

/**
 * Impersonation Modes
 */
enum class ImpersonationMode {
    FAKE_PRODUCER,          // Create entirely fake producer identity
    IMPERSONATE_KNOWN,      // Impersonate a known legitimate producer
    HIJACK_PREFIX,          // Hijack producer's namespace prefix
    MITM                    // Man-in-the-middle producer
};

/**
 * ProducerImpersonation
 *
 * Implements Producer Impersonation attack where a malicious node
 * pretends to be a legitimate content producer, serving fake
 * content under stolen or fake producer identities.
 *
 * Attack Parameters (JSON):
 * - impersonateId: string - ID of producer to impersonate (default: "rsu[0]")
 * - fakePrefix: string - Content prefix to produce (default: "/traffic")
 * - bypassAuth: bool - Attempt to bypass authentication (default: true)
 * - productionRate: int - Fake Data packets per second (default: 30)
 * - advertiseFake: bool - Advertise as fake producer (default: true)
 */
class ProducerImpersonation : public AttackBase
{
private:
    // Attack parameters
    std::string impersonatedId;
    std::string fakePrefix;
    bool bypassAuth;
    int productionRate;
    bool advertiseFake;
    ImpersonationMode mode;

    // Attack state
    uint64_t fakeDataProduced;
    uint64_t authenticationBypassed;
    uint64_t prefixesHijacked;
    std::set<std::string> impersonatedProducers;
    std::map<std::string, int> fakeContentMap;  // content -> production count

    // Statistics
    simsignal_t fakeDataProducedSignal;
    simsignal_t impersonationSuccessSignal;
    simsignal_t authBypassSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Impersonation methods
    DataPacket* produceFakeData();
    void advertiseAsProducer();
    void hijackProducerPrefix(const std::string &producerId);
    bool attemptAuthBypass();

    // Identity manipulation
    std::string createFakeProducerId();
    void stealProducerIdentity(const std::string &producerId);

public:
    ProducerImpersonation();
    virtual ~ProducerImpersonation();

    // Attack-specific getters
    uint64_t getFakeDataProduced() const { return fakeDataProduced; }
    uint64_t getAuthenticationBypassed() const { return authenticationBypassed; }
    const std::set<std::string>& getImpersonatedProducers() const { return impersonatedProducers; }
};

Define_Module(ProducerImpersonation);

} // namespace veremivndn

#endif // __VEREMIVNDN_PRODUCERIMPERSONATION_H
