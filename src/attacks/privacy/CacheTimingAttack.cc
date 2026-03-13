//
// VeReMiVNDN - Cache Timing Attack Implementation
//

#include "CacheTimingAttack.h"
#include <algorithm>
#include <cmath>

namespace veremivndn {

Define_Module(CacheTimingAttack);

CacheTimingAttack::CacheTimingAttack()
    : probeTimer(nullptr),
      currentProbeIndex(0),
      totalProbes(0),
      cacheHitsDetected(0),
      cacheMissesDetected(0),
      privacyViolations(0),
      cacheHitThreshold(0.001),  // 1ms threshold
      cacheMissThreshold(0.050)  // 50ms threshold
{
}

CacheTimingAttack::~CacheTimingAttack()
{
    cancelAndDelete(probeTimer);
}

void CacheTimingAttack::initialize(int stage)
{
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        if (parameters.count("probeInterval")) {
            probeInterval = std::stod(parameters["probeInterval"]);
        } else {
            probeInterval = 0.05;  // 50ms default
        }

        if (parameters.count("targetContent")) {
            targetContent = parameters["targetContent"];
        } else {
            targetContent = "/traffic";
        }

        if (parameters.count("probeCount")) {
            probeCount = std::stoi(parameters["probeCount"]);
        } else {
            probeCount = 10;
        }

        std::string modeStr = parameters.count("mode") ?
                             parameters["mode"] : "timing";
        if (modeStr == "discovery") {
            mode = CacheProbeMode::CONTENT_DISCOVERY;
        } else if (modeStr == "tracking") {
            mode = CacheProbeMode::USER_TRACKING;
        } else if (modeStr == "location") {
            mode = CacheProbeMode::LOCATION_INFERENCE;
        } else {
            mode = CacheProbeMode::TIMING_ANALYSIS;
        }

        measurePrecision = parameters.count("measurePrecision") ?
                          (parameters["measurePrecision"] == "true") : true;

        // Register signals
        probesSentSignal = registerSignal("probesSent");
        cacheHitDetectedSignal = registerSignal("cacheHitDetected");
        privacyViolationSignal = registerSignal("privacyViolation");

        probeTimer = new cMessage("probeTimer");

        EV_INFO << "CacheTimingAttack initialized: mode=" << modeStr
                << ", probeInterval=" << probeInterval
                << ", target=" << targetContent << endl;
    }
}

void CacheTimingAttack::handleMessage(cMessage *msg)
{
    if (msg == probeTimer) {
        executeAttack();
    }
    else if (msg->isSelfMessage()) {
        delete msg;
    }
    else {
        // Handle probe responses
        if (DataPacket *data = dynamic_cast<DataPacket*>(msg)) {
            processProbeResponse(data);
        }
        delete msg;
    }
}

void CacheTimingAttack::startAttack()
{
    AttackBase::startAttack();

    EV_WARN << "[CACHE TIMING ATTACK] Starting privacy attack at node "
            << nodeIdentifier << endl;

    // Generate probe targets
    generateProbeTargets();

    // Calibrate timing thresholds
    calibrateTimingThresholds();

    // Start probing
    currentProbeIndex = 0;
    scheduleAt(simTime() + probeInterval, probeTimer);
}

void CacheTimingAttack::stopAttack()
{
    AttackBase::stopAttack();

    cancelEvent(probeTimer);

    // Analyze results
    analyzeResults();

    EV_INFO << "[CACHE TIMING ATTACK] Stopped. Total probes: " << totalProbes
            << ", Cache hits detected: " << cacheHitsDetected
            << ", Privacy violations: " << privacyViolations << endl;
}

void CacheTimingAttack::executeAttack()
{
    if (!attackActive) return;

    // Select next target to probe
    std::string target = selectNextProbeTarget();
    if (target.empty()) {
        // All targets probed, analyze and restart
        analyzeResults();
        currentProbeIndex = 0;
        target = selectNextProbeTarget();
    }

    // Generate and send probe
    InterestPacket *probe = generateProbeInterest();
    if (probe) {
        totalProbes++;
        probesSent[target]++;
        emit(probesSentSignal, 1L);

        // Record send time for RTT measurement
        probe->setTimestamp(simTime());

        send(probe, "ndnOut");

        EV_DETAIL << "[PROBE] Sent probe for: " << target << endl;
    }

    // Schedule next probe
    if (attackActive) {
        scheduleAt(simTime() + probeInterval, probeTimer);
    }
}

InterestPacket* CacheTimingAttack::generateProbeInterest()
{
    std::string target = selectNextProbeTarget();
    if (target.empty()) return nullptr;

    InterestPacket *interest = new InterestPacket();
    interest->setName(target.c_str());
    interest->setNonce(intrand(INT_MAX));
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    // interest->setMustBeFresh(false);  // We want cached content - method not available

    return interest;
}

void CacheTimingAttack::processProbeResponse(DataPacket *data)
{
    std::string name = data->getName();
    simtime_t sendTime = data->getTimestamp();
    simtime_t receiveTime = simTime();
    simtime_t rtt = receiveTime - sendTime;

    // Record response time
    responseTimes[name].push_back(rtt);

    // Analyze timing
    analyzeResponseTime(name, rtt);

    EV_DETAIL << "[RESPONSE] " << name << " RTT: " << rtt << "s" << endl;
}

void CacheTimingAttack::analyzeResponseTime(const std::string &name, simtime_t responseTime)
{
    if (isCacheHit(responseTime)) {
        cacheHitsDetected++;
        cacheStatus[name] = true;
        emit(cacheHitDetectedSignal, 1L);

        // This indicates someone recently accessed this content
        std::string inference = "Content '" + name + "' is cached - recent access detected";
        logPrivacyViolation(name, inference);

        EV_WARN << "[PRIVACY BREACH] Cache hit detected for: " << name
                << " (RTT: " << responseTime << "s)" << endl;
    }
    else if (isCacheMiss(responseTime)) {
        cacheMissesDetected++;
        cacheStatus[name] = false;

        EV_DETAIL << "[CACHE MISS] " << name << " (RTT: " << responseTime << "s)" << endl;
    }
}

void CacheTimingAttack::generateProbeTargets()
{
    probeTargets.clear();

    switch (mode) {
        case CacheProbeMode::CONTENT_DISCOVERY:
            probeTargets = generateContentNames();
            break;

        case CacheProbeMode::LOCATION_INFERENCE:
            probeTargets = generateLocationBasedNames();
            break;

        case CacheProbeMode::USER_TRACKING:
        case CacheProbeMode::TIMING_ANALYSIS:
        default:
            // Generate popular content names to probe
            probeTargets.push_back(targetContent + "/emergency");
            probeTargets.push_back(targetContent + "/accident");
            probeTargets.push_back(targetContent + "/congestion");
            probeTargets.push_back(targetContent + "/weather");
            probeTargets.push_back(targetContent + "/parking");
            probeTargets.push_back("/safety/alert");
            probeTargets.push_back("/location/nearby");
            probeTargets.push_back("/video/traffic");
            break;
    }

    EV_INFO << "Generated " << probeTargets.size() << " probe targets" << endl;
}

std::string CacheTimingAttack::selectNextProbeTarget()
{
    if (probeTargets.empty() || currentProbeIndex >= probeTargets.size()) {
        return "";
    }

    std::string target = probeTargets[currentProbeIndex];

    // Move to next target if we've probed enough times
    if (probesSent[target] >= probeCount) {
        currentProbeIndex++;
        return selectNextProbeTarget();
    }

    return target;
}

std::vector<std::string> CacheTimingAttack::generateContentNames()
{
    std::vector<std::string> names;
    std::string prefixes[] = {"/traffic", "/safety", "/emergency", "/parking", "/weather"};

    for (const auto &prefix : prefixes) {
        for (int i = 0; i < 5; i++) {
            names.push_back(prefix + "/data" + std::to_string(i));
        }
    }

    return names;
}

std::vector<std::string> CacheTimingAttack::generateLocationBasedNames()
{
    std::vector<std::string> names;

    // Geographic-specific content that reveals location
    names.push_back("/location/downtown");
    names.push_back("/location/highway101");
    names.push_back("/location/intersection5th");
    names.push_back("/poi/restaurant");
    names.push_back("/poi/gasstation");
    names.push_back("/map/area1");

    return names;
}

bool CacheTimingAttack::isCacheHit(simtime_t responseTime)
{
    return responseTime < cacheHitThreshold;
}

bool CacheTimingAttack::isCacheMiss(simtime_t responseTime)
{
    return responseTime > cacheMissThreshold;
}

void CacheTimingAttack::calibrateTimingThresholds()
{
    // In real implementation, would measure baseline times
    // For simulation, use reasonable defaults
    cacheHitThreshold = 0.002;   // 2ms for cache hit
    cacheMissThreshold = 0.020;  // 20ms for cache miss

    EV_INFO << "Calibrated thresholds: hit=" << cacheHitThreshold
            << "s, miss=" << cacheMissThreshold << "s" << endl;
}

void CacheTimingAttack::analyzeResults()
{
    inferUserBehavior();

    if (mode == CacheProbeMode::LOCATION_INFERENCE) {
        inferLocationFromCache();
    }

    EV_INFO << "Analysis complete: " << cacheHitsDetected << " cache hits, "
            << privacyViolations << " privacy violations detected" << endl;
}

void CacheTimingAttack::inferUserBehavior()
{
    for (const auto &entry : cacheStatus) {
        if (entry.second) {  // Cache hit detected
            std::string inference = "User recently accessed: " + entry.first;
            privacyViolations++;
            emit(privacyViolationSignal, 1L);

            EV_WARN << "[PRIVACY INFERENCE] " << inference << endl;
        }
    }
}

void CacheTimingAttack::inferLocationFromCache()
{
    // Infer user location from cached location-based content
    for (const auto &entry : cacheStatus) {
        if (entry.second && entry.first.find("/location/") != std::string::npos) {
            std::string location = entry.first.substr(entry.first.find("/location/") + 10);
            EV_WARN << "[LOCATION INFERENCE] User likely near: " << location << endl;
            privacyViolations++;
        }
    }
}

void CacheTimingAttack::logPrivacyViolation(const std::string &contentName,
                                            const std::string &inference)
{
    EV_WARN << "[PRIVACY VIOLATION] " << inference << endl;
    stats.packetsGenerated++;  // Count as successful attack action
}

void CacheTimingAttack::finish()
{
    AttackBase::finish();

    recordScalar("totalProbes", totalProbes);
    recordScalar("cacheHitsDetected", cacheHitsDetected);
    recordScalar("cacheMissesDetected", cacheMissesDetected);
    recordScalar("privacyViolations", privacyViolations);

    double hitRate = (totalProbes > 0) ?
                     (double)cacheHitsDetected / totalProbes : 0.0;
    recordScalar("cacheHitRate", hitRate);
}

} // namespace veremivndn
