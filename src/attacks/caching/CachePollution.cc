//
// VeReMiVNDN - Cache Pollution Attack Implementation
//

#include "CachePollution.h"

namespace veremivndn {

Define_Module(CachePollution);

CachePollution::CachePollution() : pollutionTimer(nullptr), pollutionCount(0), uniqueContentRequested(0) {}

CachePollution::~CachePollution() {
    cancelAndDelete(pollutionTimer);
}

void CachePollution::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        unpopularContent = getParameterBool("unpopularContent", true);
        requestRate = getParameterInt("requestRate", 50);
        contentPoolSize = getParameterInt("contentPoolSize", 1000);
        targetPrefix = getParameter("targetPrefix", "/unpopular");

        pollutionRequestSignal = registerSignal("pollutionRequest");
        cacheFilledSignal = registerSignal("cacheFilled");

        EV_INFO << "Cache Pollution initialized: rate=" << requestRate
                << ", poolSize=" << contentPoolSize << endl;
    }
}

void CachePollution::handleMessage(cMessage *msg) {
    if (msg == pollutionTimer) {
        if (attackActive && shouldExecuteBasedOnIntensity()) {
            for (int i = 0; i < requestRate / 10; i++) {
                InterestPacket *pollutionInterest = generatePollutionInterest();
                send(pollutionInterest, "ndnOut");
                pollutionCount++;
                emit(pollutionRequestSignal, 1L);
            }
        }
        scheduleAt(simTime() + 0.1, pollutionTimer);
    } else {
        AttackBase::handleMessage(msg);
    }
}

void CachePollution::finish() {
    AttackBase::finish();
    recordScalar("totalPollutionRequests", pollutionCount);
    recordScalar("uniqueContentRequested", uniqueContentRequested);
    recordScalar("cacheUtilization", (double)uniqueContentRequested / contentPoolSize);
}

void CachePollution::startAttack() {
    EV_WARN << "[ATTACK START] Cache Pollution: filling cache with unpopular content" << endl;
    logAttackEvent("START", "Cache Pollution attack initiated");

    generateUnpopularNames();
    requestedContent.clear();
    pollutionCount = 0;
    uniqueContentRequested = 0;

    pollutionTimer = new cMessage("pollutionTimer");
    scheduleAt(simTime(), pollutionTimer);

    stats.attacksLaunched++;
}

void CachePollution::stopAttack() {
    EV_WARN << "[ATTACK STOP] Cache Pollution: " << pollutionCount
            << " requests for " << uniqueContentRequested << " unique items" << endl;
    logAttackEvent("STOP", "Cache Pollution attack terminated");

    cancelAndDelete(pollutionTimer);
    pollutionTimer = nullptr;
}

void CachePollution::executeAttack() {
    // Main execution in handleMessage
}

void CachePollution::generateUnpopularNames() {
    unpopularNames.clear();
    for (int i = 0; i < contentPoolSize; i++) {
        std::string name = targetPrefix + "/item/" + std::to_string(i + 10000);
        unpopularNames.push_back(name);
    }
    EV_INFO << "Generated " << unpopularNames.size() << " unpopular content names" << endl;
}

InterestPacket* CachePollution::generatePollutionInterest() {
    std::string name = selectUnpopularContent();

    InterestPacket *interest = new InterestPacket();
    interest->setName(name.c_str());
    interest->setNonce(intrand(INT_MAX));
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    interest->setPriority(0);  // Normal priority
    // interest->setMustBeFresh(false);  // Accept cached content - method may not exist

    requestedContent.insert(name);
    uniqueContentRequested = requestedContent.size();

    return interest;
}

std::string CachePollution::selectUnpopularContent() {
    if (unpopularNames.empty()) {
        generateUnpopularNames();
    }

    // Select random unpopular content
    int index = intrand(unpopularNames.size());
    return unpopularNames[index];
}

bool CachePollution::shouldAttackPacket(cMessage *msg) {
    return attackActive;
}

cMessage* CachePollution::generateMaliciousPacket() {
    return generatePollutionInterest();
}

} // namespace veremivndn
