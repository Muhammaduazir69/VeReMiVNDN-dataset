//
// VeReMiVNDN - Signature Forgery Attack Implementation
//

#include "SignatureForgery.h"
#include <sstream>
#include <iomanip>

namespace veremivndn {

Define_Module(SignatureForgery);

SignatureForgery::SignatureForgery()
    : forgeSignatures(true), validSignature(false), forgeryRate(20),
      signaturesForged(0), keysCompromised(0), mode(ForgeryMode::FORGE_SIGNATURE) {
    rng.seed(std::random_device{}());
}

SignatureForgery::~SignatureForgery() {
}

void SignatureForgery::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        forgeSignatures = getParameterBool("forgeSignatures", true);
        compromisedProducerId = getParameter("compromisedKeys", "producer1");
        validSignature = getParameterBool("validSignature", false);
        targetPrefix = getParameter("targetPrefix", "/traffic");
        forgeryRate = getParameterInt("forgeryRate", 20);

        // Determine forgery mode
        if (validSignature) {
            mode = ForgeryMode::COMPROMISED_KEY;
        } else if (forgeSignatures) {
            mode = ForgeryMode::FORGE_SIGNATURE;
        } else {
            mode = ForgeryMode::NO_SIGNATURE;
        }

        // Register signals
        signaturesForgedSignal = registerSignal("signaturesForged");
        verificationFailuresSignal = registerSignal("verificationFailures");
        fakeAuthenticPacketsSignal = registerSignal("fakeAuthenticPackets");

        signaturesForged = 0;
        keysCompromised = 0;

        EV_INFO << "SignatureForgery attack initialized at node " << nodeIdentifier
                << " targeting prefix: " << targetPrefix
                << ", mode: " << (int)mode << endl;
    }
}

void SignatureForgery::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void SignatureForgery::finish() {
    AttackBase::finish();
    recordScalar("signaturesForged", signaturesForged);
    recordScalar("keysCompromised", keysCompromised);
    recordScalar("forgeryRate", forgeryRate);
}

void SignatureForgery::startAttack() {
    EV_INFO << "Starting Signature Forgery attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Signature forgery attack initiated");

    // Compromise initial keys
    if (mode == ForgeryMode::COMPROMISED_KEY) {
        std::string key = compromiseKey(compromisedProducerId);
        compromisedKeys.insert(key);
        keysCompromised++;
    }
}

void SignatureForgery::stopAttack() {
    EV_INFO << "Stopping Signature Forgery attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Signatures forged: " + std::to_string(signaturesForged));

    // Clear compromised keys
    compromisedKeys.clear();
}

void SignatureForgery::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Generate forged Data packets at specified rate
    double intervalSeconds = 1.0 / forgeryRate;
    if (uniform(0, 1) < intervalSeconds * 10) {  // Approximate rate control
        DataPacket *forgedData = createForgedDataPacket();

        if (forgedData) {
            // Send forged data to NDN forwarder
            send(forgedData, "ndnOut");

            signaturesForged++;
            emit(signaturesForgedSignal, 1L);

            if (validSignature) {
                emit(fakeAuthenticPacketsSignal, 1L);
            } else {
                emit(verificationFailuresSignal, 1L);
            }

            stats.packetsGenerated++;

            EV_DEBUG << "Forged Data packet sent with "
                     << (validSignature ? "valid" : "invalid")
                     << " signature for prefix: " << targetPrefix << endl;
        }
    }
}

DataPacket* SignatureForgery::createForgedDataPacket() {
    DataPacket *data = new DataPacket("ForgedData");

    // Create fake content name
    std::stringstream ss;
    ss << targetPrefix << "/forged/" << simTime().dbl() << "/" << nodeId;
    data->setName(ss.str().c_str());

    // Set fake content
    std::string fakeContent = "FORGED_CONTENT_" + std::to_string(signaturesForged);
    data->setContent(fakeContent.c_str());
    data->setContentLength(fakeContent.length());

    // Generate or apply signature based on mode
    std::string signature;
    switch (mode) {
        case ForgeryMode::FORGE_SIGNATURE:
            signature = generateFakeSignature();
            data->setSignature(signature.c_str());
            data->setIsSigned(false);
            break;

        case ForgeryMode::COMPROMISED_KEY:
            signature = "COMPROMISED_KEY_SIG_" + compromisedProducerId;
            data->setSignature(signature.c_str());
            data->setIsSigned(true);  // Appears valid!
            break;

        case ForgeryMode::NO_SIGNATURE:
            data->setSignature("");
            data->setIsSigned(false);
            break;

        case ForgeryMode::REPLAY_SIGNATURE:
            // Replay a previously captured valid signature
            signature = "REPLAYED_SIG_" + std::to_string(signaturesForged % 100);
            data->setSignature(signature.c_str());
            data->setIsSigned(false);
            break;

        case ForgeryMode::WEAK_SIGNATURE:
            signature = "WEAK_" + generateFakeSignature().substr(0, 16);
            data->setSignature(signature.c_str());
            data->setIsSigned(false);
            break;
    }

    // Set producer ID
    data->setSignerId(nodeIdentifier.c_str());

    // Set timestamp
    data->setTimestamp(simTime());

    // Set freshness period
    data->setFreshnessPeriod(10.0);  // 10 seconds

    return data;
}

std::string SignatureForgery::generateFakeSignature() {
    // Generate a fake signature that looks plausible
    std::stringstream ss;
    ss << "SIG_";

    // Generate random hex string to mimic signature
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << (intuniform(0, 255));
    }

    return ss.str();
}

std::string SignatureForgery::compromiseKey(const std::string &producerId) {
    EV_WARN << "Compromising key for producer: " << producerId << endl;

    // Simulate key compromise
    std::string key = "COMPROMISED_KEY_" + producerId + "_" + std::to_string(simTime().dbl());

    logAttackEvent("KEY_COMPROMISE", "Compromised key for: " + producerId);

    return key;
}

void SignatureForgery::replayValidSignature(DataPacket *data) {
    // Store and replay valid signatures on different content
    std::string originalContent = data->getName();
    std::string signature = data->getSignature();

    if (data->isSigned() && !signature.empty()) {
        fakeSignatureMap[originalContent] = signature;
        EV_DEBUG << "Captured valid signature for replay attack" << endl;
    }
}

bool SignatureForgery::bypassSignatureValidation() {
    // Attempt to bypass signature validation through various means
    return validSignature && (mode == ForgeryMode::COMPROMISED_KEY);
}

void SignatureForgery::weakenCryptography() {
    // Simulate using weak cryptographic algorithms
    mode = ForgeryMode::WEAK_SIGNATURE;
    EV_WARN << "Weakened cryptography mode enabled" << endl;
}

bool SignatureForgery::isKeyCompromised(const std::string &key) const {
    return compromisedKeys.find(key) != compromisedKeys.end();
}

cMessage* SignatureForgery::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Data packets and forge their signatures

    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) {
        // Not a Data packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    // Forge the signature based on forgery mode
    switch (mode) {
        case ForgeryMode::FORGE_SIGNATURE: {
            // Replace with fake signature
            std::string fakeSign = generateFakeSignature();
            data->setSignature(fakeSign.c_str());
            data->setIsSigned(true);
            data->setTrustScore(0.3);  // Low trust but not zero

            signaturesForged++;
            emit(signaturesForgedSignal, 1L);
            stats.packetsModified++;

            EV_WARN << "FORGED: Data packet '" << data->getName()
                    << "' signature replaced with fake" << endl;
            break;
        }

        case ForgeryMode::COMPROMISED_KEY: {
            // Use compromised key to create "valid" signature
            std::string compromisedSig = "VALID_BUT_COMPROMISED_" + std::to_string(keysCompromised);
            data->setSignature(compromisedSig.c_str());
            data->setIsSigned(true);
            data->setTrustScore(0.8);  // High trust - looks legitimate!

            keysCompromised++;
            emit(fakeAuthenticPacketsSignal, 1L);
            stats.packetsModified++;

            EV_WARN << "COMPROMISED: Data packet '" << data->getName()
                    << "' signed with compromised key (appears valid)" << endl;
            break;
        }

        case ForgeryMode::REPLAY_SIGNATURE: {
            // Capture signature for replay
            if (data->isSigned()) {
                replayValidSignature(data);
                emit(fakeAuthenticPacketsSignal, 1L);
            }

            // Modify content but keep signature (signature becomes invalid)
            std::string modified = std::string(data->getContent()) + "_MODIFIED";
            data->setContent(modified.c_str());
            data->setTrustScore(0.2);
            stats.packetsModified++;

            EV_WARN << "REPLAY: Data packet '" << data->getName()
                    << "' content modified with replayed signature" << endl;
            break;
        }

        case ForgeryMode::WEAK_SIGNATURE: {
            // Use weak cryptographic signature
            data->setSignature("WEAK_SIG_MD5_BROKEN");
            data->setIsSigned(true);
            data->setTrustScore(0.4);
            stats.packetsModified++;

            EV_WARN << "WEAK: Data packet '" << data->getName()
                    << "' signed with weak algorithm" << endl;
            break;
        }

        case ForgeryMode::NO_SIGNATURE: {
            // Remove signature entirely
            data->setIsSigned(false);
            data->setSignature("");
            data->setTrustScore(0.1);
            stats.packetsModified++;

            EV_WARN << "NO_SIG: Data packet '" << data->getName()
                    << "' signature removed" << endl;
            break;
        }
    }

    return data;
}

} // namespace veremivndn
