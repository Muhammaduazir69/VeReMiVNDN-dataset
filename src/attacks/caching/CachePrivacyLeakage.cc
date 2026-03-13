//
// VeReMiVNDN - Cache Privacy Leakage Attack Implementation
//

#include "CachePrivacyLeakage.h"
#include <sstream>

namespace veremivndn {

Define_Module(CachePrivacyLeakage);

CachePrivacyLeakage::CachePrivacyLeakage()
    : shareCache(true), leakRequests(true), collectHistory(true),
      probeInterval(2.0), snapshotsCollected(0), requestsLeaked(0),
      profilesBuilt(0), privacyViolations(0), probeTimer(nullptr) {
}

CachePrivacyLeakage::~CachePrivacyLeakage() {
    cancelAndDelete(probeTimer);
}

void CachePrivacyLeakage::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        shareCache = getParameterBool("shareCache", true);
        leakRequests = getParameterBool("leakRequests", true);
        collectHistory = getParameterBool("collectHistory", true);
        probeInterval = getParameterDouble("probeInterval", 2.0);
        targetVehicles = getParameter("targetVehicles", "all");

        // Register signals
        snapshotsCollectedSignal = registerSignal("snapshotsCollected");
        requestsLeakedSignal = registerSignal("requestsLeaked");
        privacyLeakageSignal = registerSignal("privacyLeakage");

        snapshotsCollected = 0;
        requestsLeaked = 0;
        profilesBuilt = 0;
        privacyViolations = 0;

        EV_INFO << "CachePrivacyLeakage attack initialized at node " << nodeIdentifier << endl;
    }
}

void CachePrivacyLeakage::handleMessage(cMessage *msg) {
    if (msg == probeTimer) {
        probeCaches();
        scheduleAt(simTime() + probeInterval, probeTimer);
    } else {
        AttackBase::handleMessage(msg);
    }
}

void CachePrivacyLeakage::finish() {
    AttackBase::finish();
    recordScalar("snapshotsCollected", snapshotsCollected);
    recordScalar("requestsLeaked", requestsLeaked);
    recordScalar("profilesBuilt", profilesBuilt);
    recordScalar("privacyViolations", privacyViolations);
}

void CachePrivacyLeakage::startAttack() {
    EV_INFO << "Starting Cache Privacy Leakage attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Cache privacy leakage attack initiated");

    // Start periodic cache probing
    probeTimer = new cMessage("probeTimer");
    scheduleAt(simTime() + probeInterval, probeTimer);
}

void CachePrivacyLeakage::stopAttack() {
    EV_INFO << "Stopping Cache Privacy Leakage attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Snapshots collected: " + std::to_string(snapshotsCollected) +
                           ", Privacy violations: " + std::to_string(privacyViolations));

    cancelAndDelete(probeTimer);
    probeTimer = nullptr;
}

void CachePrivacyLeakage::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Analyze collected cache information
    if (snapshotsCollected > 0) {
        analyzeCachePatterns();
    }

    // Correlate vehicle interests
    if (snapshotsCollected > 5) {
        correlateVehicleInterests();
    }
}

void CachePrivacyLeakage::probeCaches() {
    EV_DEBUG << "Probing caches for privacy information" << endl;

    // Simulate requesting cache snapshots from nearby vehicles
    int numVehiclesToProbe = intuniform(3, 10);

    for (int i = 0; i < numVehiclesToProbe; i++) {
        std::string vehicleId = "vehicle[" + std::to_string(intuniform(0, 99)) + "]";

        if (targetVehicles != "all" && vehicleId.find(targetVehicles) == std::string::npos) {
            continue;  // Skip non-target vehicles
        }

        requestCacheSnapshot(vehicleId);
    }
}

void CachePrivacyLeakage::requestCacheSnapshot(const std::string &vehicleId) {
    // Simulate requesting cache snapshot from a vehicle
    EV_DEBUG << "Requesting cache snapshot from " << vehicleId << endl;

    // Extract cache information (simulated)
    CacheSnapshot snapshot = extractCacheInformation();
    snapshot.vehicleId = vehicleId;
    snapshot.timestamp = simTime();

    // Store snapshot
    collectedSnapshots[vehicleId] = snapshot;

    snapshotsCollected++;
    emit(snapshotsCollectedSignal, 1L);
    stats.packetsModified++;

    // Leak information if enabled
    if (leakRequests) {
        leakCacheInformation(snapshot);
    }

    // Extract privacy info
    std::set<std::string> privacyInfo = extractPrivacyInfo(snapshot);
    if (!privacyInfo.empty()) {
        buildPrivacyProfile(vehicleId, privacyInfo);
    }

    EV_WARN << "PRIVACY VIOLATION: Collected cache snapshot from " << vehicleId
            << " with " << snapshot.cachedContent.size() << " cached items" << endl;
}

CacheSnapshot CachePrivacyLeakage::extractCacheInformation() {
    CacheSnapshot snapshot;

    // Simulate extracting cache content (typical VNDN content names)
    std::vector<std::string> sampleContent = {
        "/safety/accident/lat/42.36/long/-71.09",
        "/traffic/congestion/highway/I95",
        "/location/update/vehicle/ABC123",
        "/video/entertainment/movie1",
        "/map/tiles/boston/downtown",
        "/emergency/alert/fire/location",
        "/weather/current/boston",
        "/parking/availability/lot5"
    };

    // Randomly select cached content
    int numCached = intuniform(3, 8);
    for (int i = 0; i < numCached; i++) {
        int idx = intuniform(0, sampleContent.size() - 1);
        snapshot.cachedContent.push_back(sampleContent[idx]);
        snapshot.requestCounts[sampleContent[idx]] = intuniform(1, 10);
    }

    return snapshot;
}

void CachePrivacyLeakage::leakCacheInformation(const CacheSnapshot &snapshot) {
    // Leak cache information (e.g., broadcast or share with other malicious nodes)

    for (const auto &content : snapshot.cachedContent) {
        std::string leakInfo = "LEAK: " + snapshot.vehicleId + " requested " + content;
        leakedInformation.push_back(leakInfo);

        requestsLeaked++;
        emit(requestsLeakedSignal, 1L);
        emit(privacyLeakageSignal, 1L);
        privacyViolations++;

        EV_WARN << "PRIVACY LEAK: " << leakInfo << endl;
    }

    stats.packetsGenerated++;
}

void CachePrivacyLeakage::analyzeCachePatterns() {
    // Analyze patterns across collected cache snapshots

    std::map<std::string, int> contentPopularity;

    for (const auto &entry : collectedSnapshots) {
        const CacheSnapshot &snapshot = entry.second;

        for (const auto &content : snapshot.cachedContent) {
            contentPopularity[content]++;
        }
    }

    EV_DEBUG << "Cache pattern analysis: " << contentPopularity.size()
             << " unique content items across " << collectedSnapshots.size()
             << " vehicles" << endl;

    // Identify privacy-sensitive patterns
    for (const auto &entry : contentPopularity) {
        if (entry.first.find("location") != std::string::npos ||
            entry.first.find("vehicle") != std::string::npos) {
            privacyViolations++;
            emit(privacyLeakageSignal, 1L);
        }
    }
}

void CachePrivacyLeakage::correlateVehicleInterests() {
    // Correlate interests across multiple vehicles to build profiles

    for (const auto &entry : collectedSnapshots) {
        const std::string &vehicleId = entry.first;
        const CacheSnapshot &snapshot = entry.second;

        for (const auto &content : snapshot.cachedContent) {
            vehicleProfiles[vehicleId].insert(content);
        }
    }

    EV_WARN << "Correlated interests for " << vehicleProfiles.size()
            << " vehicles - PRIVACY VIOLATION" << endl;
}

std::set<std::string> CachePrivacyLeakage::extractPrivacyInfo(const CacheSnapshot &snapshot) {
    std::set<std::string> privacyInfo;

    for (const auto &content : snapshot.cachedContent) {
        // Extract privacy-sensitive information from content names
        if (content.find("location") != std::string::npos) {
            privacyInfo.insert("LOCATION_INFO: " + content);
        }
        if (content.find("vehicle") != std::string::npos) {
            privacyInfo.insert("VEHICLE_ID: " + content);
        }
        if (content.find("lat") != std::string::npos ||
            content.find("long") != std::string::npos) {
            privacyInfo.insert("GPS_COORDINATES: " + content);
        }
        if (content.find("emergency") != std::string::npos ||
            content.find("accident") != std::string::npos) {
            privacyInfo.insert("EMERGENCY_INFO: " + content);
        }
    }

    return privacyInfo;
}

void CachePrivacyLeakage::buildPrivacyProfile(const std::string &vehicleId,
                                                const std::set<std::string> &interests) {
    if (interests.empty()) return;

    profilesBuilt++;
    privacyViolations += interests.size();

    EV_WARN << "PRIVACY VIOLATION: Built profile for " << vehicleId
            << " with " << interests.size() << " privacy-sensitive items:" << endl;

    for (const auto &interest : interests) {
        EV_WARN << "  - " << interest << endl;
        emit(privacyLeakageSignal, 1L);
    }
}

cMessage* CachePrivacyLeakage::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept packets to extract cache privacy information
    // This is a passive attack that monitors cache access patterns

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    DataPacket *data = dynamic_cast<DataPacket*>(msg);

    if (!interest && !data) {
        return msg;  // Unknown packet type
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    std::string name;
    if (interest) {
        name = interest->getName();

        // Collect Interest names to infer cache access patterns
        privacyViolations++;
        emit(privacyLeakageSignal, 1L);
        snapshotsCollected++;

        requestsLeaked++;
        emit(requestsLeakedSignal, 1L);

        EV_WARN << "CACHE_PRIVACY: Captured Interest '" << name << "' for analysis" << endl;
    }
    else if (data) {
        name = data->getName();

        // Data packets reveal what's cached
        if (data->isCacheable()) {
            privacyViolations++;
            emit(privacyLeakageSignal, 1L);

            EV_WARN << "CACHE_PRIVACY: Leaked cached content '" << name << "'" << endl;
        }
    }

    // Passive attack - don't modify packets
    stats.packetsModified++;  // "Modified" means "analyzed"
    return msg;
}

} // namespace veremivndn
