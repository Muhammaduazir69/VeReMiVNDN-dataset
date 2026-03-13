//
// VeReMiVNDN - Signature Forgery / Key Compromise Attack Implementation
//
// Attack #10: Signature Forgery / Key Compromise
// Layer: Security / Trust
// Description: Attacker forges data signatures or uses compromised signing keys,
//              enabling data poisoning that appears cryptographically authentic
// Impact: Authenticated fake content, trust model breakdown, widespread misinformation
//

#ifndef __VEREMIVNDN_SIGNATUREFORGERY_H
#define __VEREMIVNDN_SIGNATUREFORGERY_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <random>

namespace veremivndn {

/**
 * Signature Forgery Modes
 */
enum class ForgeryMode {
    FORGE_SIGNATURE,        // Generate fake signatures
    COMPROMISED_KEY,        // Use compromised private keys
    REPLAY_SIGNATURE,       // Replay valid signatures on fake data
    NO_SIGNATURE,           // Remove signatures entirely
    WEAK_SIGNATURE          // Use weak/broken crypto
};

/**
 * SignatureForgery
 *
 * Implements Signature Forgery attack that creates fake Data packets
 * with forged or compromised signatures, appearing legitimate
 * to signature verification systems.
 *
 * Attack Parameters (JSON):
 * - forgeSignatures: bool - Generate fake signatures (default: true)
 * - compromisedKeys: string - ID of compromised producer (default: "producer1")
 * - validSignature: bool - Make signature appear valid (default: false)
 * - targetPrefix: string - Content prefix to poison (default: "/traffic")
 * - forgeryRate: int - Forged packets per second (default: 20)
 */
class SignatureForgery : public AttackBase
{
private:
    // Attack parameters
    bool forgeSignatures;
    std::string compromisedProducerId;
    bool validSignature;
    std::string targetPrefix;
    int forgeryRate;
    ForgeryMode mode;

    // Attack state
    uint64_t signaturesForged;
    uint64_t keysCompromised;
    std::set<std::string> compromisedKeys;
    std::map<std::string, std::string> fakeSignatureMap;  // content -> fake signature

    // Statistics
    simsignal_t signaturesForgedSignal;
    simsignal_t verificationFailuresSignal;
    simsignal_t fakeAuthenticPacketsSignal;

    // Random generation
    std::mt19937 rng;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Forgery methods
    DataPacket* createForgedDataPacket();
    std::string generateFakeSignature();
    std::string compromiseKey(const std::string &producerId);
    void replayValidSignature(DataPacket *data);

    // Validation bypass
    bool bypassSignatureValidation();
    void weakenCryptography();

public:
    SignatureForgery();
    virtual ~SignatureForgery();

    // Attack-specific getters
    uint64_t getSignaturesForged() const { return signaturesForged; }
    uint64_t getKeysCompromised() const { return keysCompromised; }
    bool isKeyCompromised(const std::string &key) const;
};

Define_Module(SignatureForgery);

} // namespace veremivndn

#endif // __VEREMIVNDN_SIGNATUREFORGERY_H
