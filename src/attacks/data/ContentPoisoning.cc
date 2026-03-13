//
// VeReMiVNDN - Content Poisoning Implementation
//

#include "ContentPoisoning.h"

namespace veremivndn {

Define_Module(ContentPoisoning);

ContentPoisoning::ContentPoisoning() : poisonedPackets(0) {}

ContentPoisoning::~ContentPoisoning() {}

void ContentPoisoning::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        targetPrefix = getParameter("targetPrefix", "/traffic");
        poisonProbability = getParameterDouble("poisonProbability", 0.8);
        modifyContent = getParameterBool("modifyContent", true);
        keepSignature = getParameterBool("keepSignature", false);

        contentPoisonedSignal = registerSignal("contentPoisoned");
    }
}

void ContentPoisoning::handleMessage(cMessage *msg) {
    if (DataPacket *data = dynamic_cast<DataPacket*>(msg)) {
        if (attackActive && shouldAttackPacket(msg)) {
            std::string name = data->getName();
            if (name.find(targetPrefix) == 0 && uniform(0,1) < poisonProbability) {
                DataPacket *poisoned = poisonData(data);
                send(poisoned, "ndnOut");
                delete data;
                return;
            }
        }
    }
    AttackBase::handleMessage(msg);
}

void ContentPoisoning::finish() {
    AttackBase::finish();
    recordScalar("totalPoisonedContent", poisonedPackets);
}

void ContentPoisoning::startAttack() {
    EV_WARN << "[ATTACK START] Content Poisoning targeting " << targetPrefix << endl;
    logAttackEvent("START", "Content Poisoning attack initiated");
}

void ContentPoisoning::stopAttack() {
    EV_WARN << "[ATTACK STOP] Content Poisoning. Poisoned " << poisonedPackets << " packets" << endl;
    logAttackEvent("STOP", "Content Poisoning attack terminated");
}

void ContentPoisoning::executeAttack() {
    // Attack executes when intercepting data packets
}

DataPacket* ContentPoisoning::poisonData(DataPacket *original) {
    DataPacket *poisoned = original->dup();

    if (modifyContent) {
        std::string fakeContent = generateFakeContent();
        poisoned->setContent(fakeContent.c_str());
        poisoned->setContentLength(fakeContent.length());
    }

    if (!keepSignature) {
        poisoned->setIsSigned(false);
        poisoned->setSignature("");
    }

    poisonedPackets++;
    emit(contentPoisonedSignal, 1L);

    EV_WARN << "Poisoned content: " << original->getName() << endl;
    return poisoned;
}

std::string ContentPoisoning::generateFakeContent() {
    return "FAKE_DATA_FROM_ATTACKER_" + std::to_string(simTime().dbl());
}

} // namespace veremivndn
