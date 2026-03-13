//
// VeReMiVNDN - Producer Impersonation Attack Implementation
//

#include "ProducerImpersonation.h"
#include <sstream>

namespace veremivndn {

Define_Module(ProducerImpersonation);

ProducerImpersonation::ProducerImpersonation()
    : bypassAuth(true), productionRate(30), advertiseFake(true),
      mode(ImpersonationMode::IMPERSONATE_KNOWN), fakeDataProduced(0),
      authenticationBypassed(0), prefixesHijacked(0) {
}

ProducerImpersonation::~ProducerImpersonation() {
}

void ProducerImpersonation::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        impersonatedId = getParameter("impersonateId", "rsu[0]");
        fakePrefix = getParameter("fakePrefix", "/traffic");
        bypassAuth = getParameterBool("bypassAuth", true);
        productionRate = getParameterInt("productionRate", 30);
        advertiseFake = getParameterBool("advertiseFake", true);

        // Determine impersonation mode
        if (impersonatedId == "fake") {
            mode = ImpersonationMode::FAKE_PRODUCER;
        } else {
            mode = ImpersonationMode::IMPERSONATE_KNOWN;
        }

        // Register signals
        fakeDataProducedSignal = registerSignal("fakeDataProduced");
        impersonationSuccessSignal = registerSignal("impersonationSuccess");
        authBypassSignal = registerSignal("authBypass");

        fakeDataProduced = 0;
        authenticationBypassed = 0;
        prefixesHijacked = 0;

        EV_INFO << "ProducerImpersonation attack initialized at node " << nodeIdentifier
                << " impersonating: " << impersonatedId
                << ", prefix: " << fakePrefix << endl;
    }
}

void ProducerImpersonation::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void ProducerImpersonation::finish() {
    AttackBase::finish();
    recordScalar("fakeDataProduced", fakeDataProduced);
    recordScalar("authenticationBypassed", authenticationBypassed);
    recordScalar("prefixesHijacked", prefixesHijacked);
}

void ProducerImpersonation::startAttack() {
    EV_INFO << "Starting Producer Impersonation attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Impersonating producer: " + impersonatedId);

    // Advertise as fake producer
    if (advertiseFake) {
        advertiseAsProducer();
    }

    // Hijack producer prefix
    if (mode == ImpersonationMode::HIJACK_PREFIX) {
        hijackProducerPrefix(impersonatedId);
    }

    // Store impersonated producer
    impersonatedProducers.insert(impersonatedId);
}

void ProducerImpersonation::stopAttack() {
    EV_INFO << "Stopping Producer Impersonation attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Fake data produced: " + std::to_string(fakeDataProduced));

    impersonatedProducers.clear();
    fakeContentMap.clear();
}

void ProducerImpersonation::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Produce fake Data packets at specified rate
    double intervalSeconds = 1.0 / productionRate;
    if (uniform(0, 1) < intervalSeconds * 10) {  // Approximate rate control
        DataPacket *fakeData = produceFakeData();

        if (fakeData) {
            // Send fake data to NDN forwarder
            send(fakeData, "ndnOut");

            fakeDataProduced++;
            emit(fakeDataProducedSignal, 1L);
            emit(impersonationSuccessSignal, 1L);
            stats.packetsGenerated++;

            // Track fake content
            std::string name = fakeData->getName();
            fakeContentMap[name]++;

            EV_WARN << "IMPERSONATION: Fake Data produced as " << impersonatedId
                    << " for name: " << name << endl;
        }
    }

    // Periodically attempt authentication bypass
    if ((int)simTime().dbl() % 5 == 0 && bypassAuth) {
        if (attemptAuthBypass()) {
            authenticationBypassed++;
            emit(authBypassSignal, 1L);
        }
    }
}

DataPacket* ProducerImpersonation::produceFakeData() {
    DataPacket *data = new DataPacket("FakeProducedData");

    // Create fake content name using impersonated producer's prefix
    std::stringstream ss;
    ss << fakePrefix << "/fake/" << simTime().dbl() << "/" << fakeDataProduced;
    data->setName(ss.str().c_str());

    // Set fake content
    std::string fakeContent = "FAKE_PRODUCER_CONTENT_" + std::to_string(fakeDataProduced);
    data->setContent(fakeContent.c_str());
    data->setContentLength(fakeContent.length());

    // Impersonate producer ID
    data->setSignerId(impersonatedId.c_str());  // IMPERSONATION!

    // Set timestamp
    data->setTimestamp(simTime());

    // Set freshness period
    data->setFreshnessPeriod(10.0);

    // Attempt to create fake signature
    std::string fakeSignature = "FAKE_SIG_" + impersonatedId + "_" +
                               std::to_string(fakeDataProduced);
    data->setSignature(fakeSignature.c_str());

    // Set signature validity based on bypass attempt
    if (bypassAuth && attemptAuthBypass()) {
        data->setIsSigned(true);  // Bypass authentication!
        EV_WARN << "AUTHENTICATION BYPASSED for fake Data" << endl;
    } else {
        data->setIsSigned(false);
    }

    return data;
}

void ProducerImpersonation::advertiseAsProducer() {
    // Advertise self as a content producer for the fake prefix
    EV_WARN << "IMPERSONATION: Advertising as producer '" << impersonatedId
            << "' for prefix: " << fakePrefix << endl;

    // In real implementation, would send FIB update announcements
    prefixesHijacked++;
}

void ProducerImpersonation::hijackProducerPrefix(const std::string &producerId) {
    EV_WARN << "PREFIX HIJACKING: Hijacking prefix for producer: " << producerId << endl;

    mode = ImpersonationMode::HIJACK_PREFIX;
    prefixesHijacked++;

    logAttackEvent("HIJACK", "Hijacked prefix from: " + producerId);
}

bool ProducerImpersonation::attemptAuthBypass() {
    // Attempt to bypass authentication mechanisms
    // Simplified simulation - in reality would try various bypass techniques

    if (bypassAuth && uniform(0, 1) < intensity) {
        EV_DEBUG << "Authentication bypass attempt successful" << endl;
        return true;
    }

    return false;
}

std::string ProducerImpersonation::createFakeProducerId() {
    // Create a fake producer ID that looks legitimate
    std::stringstream ss;
    ss << "producer_" << intuniform(1, 100);
    return ss.str();
}

void ProducerImpersonation::stealProducerIdentity(const std::string &producerId) {
    // Steal and use legitimate producer's identity
    EV_WARN << "IDENTITY THEFT: Stealing identity of producer: " << producerId << endl;

    impersonatedId = producerId;
    impersonatedProducers.insert(producerId);

    logAttackEvent("IDENTITY_THEFT", "Stole identity: " + producerId);
}

cMessage* ProducerImpersonation::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Data packets and replace with fake data from impersonated producer

    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) {
        // Not a Data packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    // Impersonate producer - replace content with fake data
    std::string name = data->getName();

    // Replace content with fake data
    std::string fakeContent = "FAKE_DATA_FROM_IMPERSONATOR_" + nodeIdentifier;
    data->setContent(fakeContent.c_str());
    data->setContentLength(fakeContent.length());
    data->setTrustScore(0.5);  // Medium trust
    data->setIsSigned(false);

    fakeDataProduced++;
    emit(fakeDataProducedSignal, 1L);
    stats.packetsModified++;

    EV_WARN << "IMPERSONATE: Data '" << name << "' content replaced with fake" << endl;

    return data;
}

} // namespace veremivndn
