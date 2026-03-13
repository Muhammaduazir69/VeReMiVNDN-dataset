//
// VeReMiVNDN - Replay Attack Implementation
//

#include "ReplayAttack.h"
#include "../../common/SimpleJSON.h"

namespace veremivndn {

Define_Module(ReplayAttack);

ReplayAttack::ReplayAttack()
    : replayTimer(nullptr),
      captureTimer(nullptr),
      packetsReplayed(0),
      packetsCaptured(0)
{
}

ReplayAttack::~ReplayAttack()
{
    cancelAndDelete(replayTimer);
    cancelAndDelete(captureTimer);

    // Clean up captured packets
    for (auto &captured : capturedInterests) {
        delete captured.packet;
    }
    for (auto &captured : capturedData) {
        delete captured.packet;
    }
}

void ReplayAttack::initialize(int stage)
{
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Default parameters
        replayDelay = 30.0;  // 30 seconds
        targetPrefix = "/safety";
        ignoreTimestamp = true;
        replayCount = 3;
        target = ReplayTarget::BOTH;
        maxCapturedPackets = 100;

        attackType = "ReplayAttack";

        // Create timers
        replayTimer = new cMessage("replayTimer");
        captureTimer = new cMessage("captureTimer");

        // Register signals
        packetReplayedSignal = registerSignal("packetReplayed");
        packetCapturedSignal = registerSignal("packetCaptured");
    }
}

void ReplayAttack::handleMessage(cMessage *msg)
{
    if (msg == replayTimer) {
        executeAttack();
    }
    else if (msg == captureTimer) {
        // Periodic check for replay opportunities
        scheduleAt(simTime() + 1.0, captureTimer);
    }
    else if (msg == startAttackMsg) {
        startAttack();
    }
    else if (msg == stopAttackMsg) {
        stopAttack();
    }
    else if (attackActive) {
        // Capture passing traffic
        if (shouldCapturePacket(msg)) {
            capturePacket(msg);
        }

        // Forward original packet
        send(msg, "ndnOut");
    }
    else {
        send(msg, "ndnOut");
    }
}

void ReplayAttack::startAttack()
{
    EV_WARN << "Starting Replay Attack: prefix=" << targetPrefix
            << " replayDelay=" << replayDelay << "s" << endl;

    attackActive = true;
    packetsReplayed = 0;
    packetsCaptured = 0;

    capturedInterests.clear();
    capturedData.clear();
    replayCountMap.clear();

    // Start capture and replay timers
    scheduleAt(simTime() + 1.0, captureTimer);
    scheduleAt(simTime() + replayDelay, replayTimer);

    emit(attackActiveSignal, 1L);
}

void ReplayAttack::stopAttack()
{
    attackActive = false;
    cancelEvent(replayTimer);
    cancelEvent(captureTimer);

    EV_INFO << "Replay Attack stopped. Replayed " << packetsReplayed
            << " packets, captured " << packetsCaptured << " packets" << endl;

    emit(attackActiveSignal, 0L);
}

void ReplayAttack::executeAttack()
{
    if (!attackActive) return;

    // Replay old packets
    replayOldPackets();

    // Schedule next replay
    scheduleAt(simTime() + exponential(replayDelay / 2.0), replayTimer);
}

bool ReplayAttack::shouldCapturePacket(cMessage *packet)
{
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(packet)) {
        if (target == ReplayTarget::DATA) return false;

        std::string name = interest->getName();
        return name.find(targetPrefix) == 0;
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        if (target == ReplayTarget::INTEREST) return false;

        std::string name = data->getName();
        return name.find(targetPrefix) == 0;
    }

    return false;
}

void ReplayAttack::capturePacket(cMessage *packet)
{
    storeCapturedPacket(packet);

    packetsCaptured++;
    emit(packetCapturedSignal, 1L);

    EV_DETAIL << "Captured packet for replay: " << packet->getName() << endl;
}

void ReplayAttack::storeCapturedPacket(cMessage *packet)
{
    CapturedPacket captured;
    captured.packet = packet->dup();
    captured.captureTime = simTime();

    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(packet)) {
        captured.name = interest->getName();
        captured.nonce = interest->getNonce();

        capturedInterests.push_back(captured);

        // Limit storage
        if (capturedInterests.size() > maxCapturedPackets) {
            delete capturedInterests.front().packet;
            capturedInterests.pop_front();
        }
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        captured.name = data->getName();
        captured.nonce = 0;

        capturedData.push_back(captured);

        // Limit storage
        if (capturedData.size() > maxCapturedPackets) {
            delete capturedData.front().packet;
            capturedData.pop_front();
        }
    }
}

void ReplayAttack::replayOldPackets()
{
    int replaysThisRound = 0;
    int maxReplaysPerRound = 10;

    // Replay captured interests
    if (target != ReplayTarget::DATA) {
        for (const auto &captured : capturedInterests) {
            if (replaysThisRound >= maxReplaysPerRound) break;

            if (canReplayPacket(captured)) {
                replayInterest(captured);
                replaysThisRound++;
            }
        }
    }

    // Replay captured data
    if (target != ReplayTarget::INTEREST) {
        for (const auto &captured : capturedData) {
            if (replaysThisRound >= maxReplaysPerRound) break;

            if (canReplayPacket(captured)) {
                replayData(captured);
                replaysThisRound++;
            }
        }
    }
}

bool ReplayAttack::canReplayPacket(const CapturedPacket &captured)
{
    // Check if packet is old enough
    simtime_t age = simTime() - captured.captureTime;
    if (age < replayDelay) {
        return false;
    }

    // Check replay count limit
    std::string key = captured.name + "_" + std::to_string(captured.captureTime.dbl());
    if (replayCountMap[key] >= replayCount) {
        return false;
    }

    return true;
}

void ReplayAttack::replayInterest(const CapturedPacket &captured)
{
    InterestPacket *replay = check_and_cast<InterestPacket*>(captured.packet->dup());

    // Optionally modify timestamp (make it look fresh)
    if (!ignoreTimestamp) {
        replay->setTimestamp(simTime());
    }

    send(replay, "ndnOut");

    packetsReplayed++;
    stats.packetsGenerated++;

    std::string key = captured.name + "_" + std::to_string(captured.captureTime.dbl());
    replayCountMap[key]++;

    emit(packetReplayedSignal, 1L);
    emit(packetsGeneratedSignal, 1L);

    EV_WARN << "Replayed Interest: " << replay->getName()
            << " (original from t=" << captured.captureTime << ")" << endl;
}

void ReplayAttack::replayData(const CapturedPacket &captured)
{
    DataPacket *replay = check_and_cast<DataPacket*>(captured.packet->dup());

    // Don't update timestamp - keep it stale
    if (!ignoreTimestamp) {
        // Keep old timestamp to show staleness
    }

    send(replay, "ndnOut");

    packetsReplayed++;
    stats.packetsGenerated++;

    std::string key = captured.name + "_" + std::to_string(captured.captureTime.dbl());
    replayCountMap[key]++;

    emit(packetReplayedSignal, 1L);
    emit(packetsGeneratedSignal, 1L);

    EV_WARN << "Replayed Data: " << replay->getName()
            << " (stale, original from t=" << captured.captureTime << ")" << endl;
}

bool ReplayAttack::shouldAttackPacket(cMessage *msg)
{
    return shouldCapturePacket(msg);
}

cMessage* ReplayAttack::manipulatePacket(cMessage *msg)
{
    // Capture for replay, but don't modify
    if (shouldCapturePacket(msg)) {
        capturePacket(msg);
    }
    return msg;
}

cMessage* ReplayAttack::generateMaliciousPacket()
{
    // Replay a random captured packet
    if (!capturedInterests.empty() && uniform(0, 1) < 0.5) {
        int idx = intrand(capturedInterests.size());
        return capturedInterests[idx].packet->dup();
    }
    else if (!capturedData.empty()) {
        int idx = intrand(capturedData.size());
        return capturedData[idx].packet->dup();
    }

    return nullptr;
}

void ReplayAttack::parseParameters(const std::string &params)
{
    try {
        auto json = nlohmann::json::parse(params);

        if (json.contains("replayDelay")) {
            replayDelay = std::stod(std::string(json["replayDelay"]));
        }
        if (json.contains("targetPrefix")) {
            targetPrefix = json["targetPrefix"];
        }
        if (json.contains("ignoreTimestamp")) {
            std::string val = json["ignoreTimestamp"]; ignoreTimestamp = (val == "true" || val == "1");
        }
        if (json.contains("replayCount")) {
            replayCount = std::stoi(std::string(json["replayCount"]));
        }
        if (json.contains("target")) {
            std::string targetStr = json["target"];
            if (targetStr == "interest") target = ReplayTarget::INTEREST;
            else if (targetStr == "data") target = ReplayTarget::DATA;
            else if (targetStr == "both") target = ReplayTarget::BOTH;
        }
        if (json.contains("maxCapturedPackets")) {
            maxCapturedPackets = std::stoi(std::string(json["maxCapturedPackets"]));
        }
    }
    catch (const std::exception &e) {
        EV_WARN << "Failed to parse attack parameters: " << e.what() << endl;
    }
}

void ReplayAttack::finish()
{
    AttackBase::finish();

    recordScalar("packetsReplayed", packetsReplayed);
    recordScalar("packetsCaptured", packetsCaptured);
    recordScalar("capturedInterestsCount", (long)capturedInterests.size());
    recordScalar("capturedDataCount", (long)capturedData.size());
}

} // namespace veremivndn
