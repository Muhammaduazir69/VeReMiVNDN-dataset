//
// VeReMiVNDN - Cache Invalidation Attack Implementation
//

#include "CacheInvalidation.h"
#include <sstream>

namespace veremivndn {

Define_Module(CacheInvalidation);

CacheInvalidation::CacheInvalidation()
    : rapidVersions(true), invalidationRate(10), forceCacheEviction(true),
      versionIncrement(0.1), versionsPublished(0), invalidationsSent(0),
      cacheEvictionsForced(0), currentVersion(0), mode(InvalidationMode::RAPID_VERSIONS) {
}

CacheInvalidation::~CacheInvalidation() {
}

void CacheInvalidation::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        rapidVersions = getParameterBool("rapidVersions", true);
        invalidationRate = getParameterInt("invalidationRate", 10);
        forceCacheEviction = getParameterBool("forceCacheEviction", true);
        targetPrefix = getParameter("targetPrefix", "/traffic");
        versionIncrement = getParameterDouble("versionIncrement", 0.1);

        // Determine attack mode
        if (rapidVersions) {
            mode = InvalidationMode::RAPID_VERSIONS;
        } else if (forceCacheEviction) {
            mode = InvalidationMode::FORCED_EVICTION;
        } else {
            mode = InvalidationMode::SHORT_FRESHNESS;
        }

        // Register signals
        versionsPublishedSignal = registerSignal("versionsPublished");
        invalidationsSentSignal = registerSignal("invalidationsSent");
        cacheChurnSignal = registerSignal("cacheChurn");

        versionsPublished = 0;
        invalidationsSent = 0;
        cacheEvictionsForced = 0;
        currentVersion = 0;
        lastVersionTime = 0;

        EV_INFO << "CacheInvalidation attack initialized at node " << nodeIdentifier
                << " targeting prefix: " << targetPrefix
                << ", mode: " << (int)mode << endl;
    }
}

void CacheInvalidation::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void CacheInvalidation::finish() {
    AttackBase::finish();
    recordScalar("versionsPublished", versionsPublished);
    recordScalar("invalidationsSent", invalidationsSent);
    recordScalar("cacheEvictionsForced", cacheEvictionsForced);
    recordScalar("churnRate", calculateChurnRate());
}

void CacheInvalidation::startAttack() {
    EV_INFO << "Starting Cache Invalidation attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Cache invalidation attack initiated");

    currentVersion = 0;
    lastVersionTime = simTime();
}

void CacheInvalidation::stopAttack() {
    EV_INFO << "Stopping Cache Invalidation attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Versions published: " + std::to_string(versionsPublished));

    versionMap.clear();
    invalidatedContent.clear();
}

void CacheInvalidation::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Execute attack based on mode
    switch (mode) {
        case InvalidationMode::RAPID_VERSIONS: {
            // Publish new versions at high rate
            if (simTime() - lastVersionTime >= versionIncrement) {
                DataPacket *newVersion = publishNewVersion();
                if (newVersion) {
                    send(newVersion, "ndnOut");
                    lastVersionTime = simTime();
                }
            }
            break;
        }

        case InvalidationMode::FAKE_INVALIDATION: {
            // Send fake invalidation messages
            double intervalSeconds = 1.0 / invalidationRate;
            if (uniform(0, 1) < intervalSeconds * 10) {
                std::string contentName = targetPrefix + "/content" +
                                         std::to_string(intuniform(1, 100));
                sendInvalidationMessage(contentName);
            }
            break;
        }

        case InvalidationMode::SHORT_FRESHNESS: {
            // Publish data with very short freshness periods
            if (uniform(0, 1) < 0.1) {
                DataPacket *shortFresh = createShortFreshnessData();
                if (shortFresh) {
                    send(shortFresh, "ndnOut");
                }
            }
            break;
        }

        case InvalidationMode::FORCED_EVICTION: {
            // Force cache eviction through control messages
            double intervalSeconds = 1.0 / invalidationRate;
            if (uniform(0, 1) < intervalSeconds * 10) {
                std::string contentName = targetPrefix + "/evict" +
                                         std::to_string(intuniform(1, 50));
                forceEviction(contentName);
            }
            break;
        }
    }

    // Periodically monitor cache churn
    if ((int)simTime().dbl() % 10 == 0) {
        monitorCacheChurn();
    }
}

DataPacket* CacheInvalidation::publishNewVersion() {
    DataPacket *data = new DataPacket("NewVersion");

    // Increment version
    currentVersion++;

    // Create versioned name
    std::string versionedName = getVersionedName(targetPrefix, currentVersion);
    data->setName(versionedName.c_str());

    // Set content with version info
    std::stringstream content;
    content << "VERSION_" << currentVersion << "_TIME_" << simTime().dbl();
    data->setContent(content.str().c_str());
    data->setContentLength(content.str().length());

    // Set short freshness period to force frequent invalidation
    data->setFreshnessPeriod(versionIncrement * 2);  // Expire quickly

    // Set signature (simplified)
    std::string sig = "SIG_VERSION_" + std::to_string(currentVersion);
    data->setSignature(sig.c_str());
    data->setIsSigned(true);

    data->setSignerId(nodeIdentifier.c_str());
    data->setTimestamp(simTime());

    versionsPublished++;
    emit(versionsPublishedSignal, 1L);
    emit(cacheChurnSignal, 1L);
    stats.packetsGenerated++;

    EV_DEBUG << "Published new version " << currentVersion
             << " for prefix: " << targetPrefix << endl;

    // Track version
    versionMap[targetPrefix] = currentVersion;

    return data;
}

void CacheInvalidation::incrementVersion(const std::string &contentName) {
    versionMap[contentName]++;
    EV_DEBUG << "Incremented version for " << contentName
             << " to " << versionMap[contentName] << endl;
}

std::string CacheInvalidation::getVersionedName(const std::string &baseName, int version) {
    std::stringstream ss;
    ss << baseName << "/v" << version;
    return ss.str();
}

void CacheInvalidation::sendInvalidationMessage(const std::string &contentName) {
    // Send fake cache invalidation message
    // In real NDN, this would be a control packet

    invalidationsSent++;
    emit(invalidationsSentSignal, 1L);
    emit(cacheChurnSignal, 1L);

    invalidatedContent.insert(contentName);

    EV_WARN << "Sent invalidation message for: " << contentName << endl;
}

void CacheInvalidation::forceEviction(const std::string &contentName) {
    // Force cache eviction by publishing content with no-cache directive
    DataPacket *data = new DataPacket("ForceEviction");

    std::stringstream ss;
    ss << contentName << "/nocache/" << simTime().dbl();
    data->setName(ss.str().c_str());

    // Set zero freshness to prevent caching
    data->setFreshnessPeriod(0.0);

    std::string content = "NO_CACHE_CONTENT";
    data->setContent(content.c_str());
    data->setContentLength(content.length());

    data->setSignature("EVICTION_SIG");
    data->setIsSigned(true);
    data->setSignerId(nodeIdentifier.c_str());
    data->setTimestamp(simTime());

    send(data, "ndnOut");

    cacheEvictionsForced++;
    emit(cacheChurnSignal, 1L);
    stats.packetsGenerated++;

    EV_DEBUG << "Forced cache eviction for: " << contentName << endl;
}

DataPacket* CacheInvalidation::createShortFreshnessData() {
    DataPacket *data = new DataPacket("ShortFreshness");

    std::stringstream ss;
    ss << targetPrefix << "/short/" << simTime().dbl();
    data->setName(ss.str().c_str());

    // Very short freshness period (0.1 seconds)
    data->setFreshnessPeriod(0.1);

    std::string content = "SHORT_LIVED_CONTENT_" + std::to_string(versionsPublished);
    data->setContent(content.c_str());
    data->setContentLength(content.length());

    data->setSignature("SHORT_SIG");
    data->setIsSigned(true);
    data->setSignerId(nodeIdentifier.c_str());
    data->setTimestamp(simTime());

    versionsPublished++;
    emit(versionsPublishedSignal, 1L);
    emit(cacheChurnSignal, 1L);
    stats.packetsGenerated++;

    EV_DEBUG << "Created short freshness Data packet" << endl;

    return data;
}

void CacheInvalidation::monitorCacheChurn() {
    double churnRate = calculateChurnRate();

    EV_DEBUG << "Cache churn monitoring: rate=" << churnRate
             << ", versions=" << versionsPublished
             << ", invalidations=" << invalidationsSent << endl;
}

double CacheInvalidation::calculateChurnRate() {
    // Calculate cache churn rate (invalidations + versions per second)
    double elapsed = (simTime() - attackStarted).dbl();
    if (elapsed <= 0) return 0.0;

    double totalChurn = versionsPublished + invalidationsSent + cacheEvictionsForced;
    return totalChurn / elapsed;
}

cMessage* CacheInvalidation::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Data packets and manipulate cache behavior

    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) {
        // Not a Data packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    // Manipulate Data packet to cause cache invalidation/churn
    std::string name = data->getName();

    if (mode == InvalidationMode::RAPID_VERSIONS) {
        // Append version number to force cache updates
        std::stringstream ss;
        ss << name << "/v" << versionsPublished;
        data->setName(ss.str().c_str());

        // Set short freshness to force rapid re-validation
        data->setFreshnessPeriod(0.5);  // 0.5 seconds only
        data->setIsCacheable(true);

        versionsPublished++;
        emit(versionsPublishedSignal, 1L);
        emit(cacheChurnSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "CACHE_CHURN: Data '" << name << "' versioned to v"
                << versionsPublished << " with short freshness" << endl;
    }
    else if (mode == InvalidationMode::SHORT_FRESHNESS) {
        // Set very short freshness period
        data->setFreshnessPeriod(0.1);  // 0.1 seconds only
        data->setIsCacheable(true);

        invalidationsSent++;
        emit(invalidationsSentSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "SHORT_FRESH: Data '" << name << "' freshness reduced to 0.1s" << endl;
    }
    else if (mode == InvalidationMode::FORCED_EVICTION) {
        // Set very long content that exhausts cache space
        std::string bloatedContent(5000, 'X');  // 5KB of junk
        data->setContent(bloatedContent.c_str());
        data->setContentLength(bloatedContent.length());
        data->setIsCacheable(true);

        cacheEvictionsForced++;
        emit(cacheChurnSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "CACHE_EVICT: Data '" << name << "' bloated to force evictions" << endl;
    }
    else if (mode == InvalidationMode::FAKE_INVALIDATION) {
        // Mark as non-cacheable to simulate invalidation
        data->setIsCacheable(false);
        data->setFreshnessPeriod(0.0);

        invalidationsSent++;
        emit(invalidationsSentSignal, 1L);
        stats.packetsDropped++;

        EV_WARN << "FAKE_INVAL: Data '" << name << "' marked non-cacheable" << endl;
    }

    return data;
}

} // namespace veremivndn
