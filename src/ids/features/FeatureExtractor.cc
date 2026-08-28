//
// VeReMiVNDN - IDS Feature Extractor Implementation
//

#include "FeatureExtractor.h"
#include "veins/modules/mobility/traci/TraCIMobility.h"
#include "../../ndn/tables/CS.h"
#include "../../ndn/tables/FIB.h"
#include "../../ndn/tables/PIT.h"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <numeric>

namespace veremivndn {

Define_Module(FeatureExtractor);

FeatureExtractor::FeatureExtractor()
    : extractionTimer(nullptr),
      totalInterests(0),
      totalData(0),
      totalNacks(0),
      totalDrops(0),
      totalBytes(0.0)
{
}

FeatureExtractor::~FeatureExtractor()
{
    cancelAndDelete(extractionTimer);
}

void FeatureExtractor::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0) {
        // Configuration
        extractionInterval = par("extractionInterval").doubleValue();
        timeWindowSize = par("timeWindowSize").doubleValue();
        maxHistorySize = par("maxHistorySize").intValue();
        enableRealTimeExtraction = par("enableRealTimeExtraction").boolValue();

        nodeId = getParentModule()->par("nodeId").intValue();
        nodeIdentifier = getParentModule()->getFullName();
        // NDN features (15)
        // Initialize window
        currentWindow.windowStart = simTime();
        currentWindow.windowEnd = simTime() + timeWindowSize;
        currentWindow.interestCount = 0;
        currentWindow.dataCount = 0;
        currentWindow.nackCount = 0;
        currentWindow.totalInterestSize = 0;
        currentWindow.totalDataSize = 0;

        // Create timer
        extractionTimer = new cMessage("extractionTimer");

        // Register signals
        featureExtractionSignal = registerSignal("featureExtraction");
        anomalyScoreSignal = registerSignal("anomalyScore");

        // VeReMiVNDN-EXE: per-plane observation subsystem.
        initPlaneFeatures();

        // Schedule first extraction
        if (enableRealTimeExtraction) {
            scheduleAt(simTime() + extractionInterval, extractionTimer);
        }
    }
}

void FeatureExtractor::handleMessage(cMessage *msg)
{
    if (msg == extractionTimer) {
        // Extract features
        FeatureVector fv = extractAllFeatures();

        // Publish the completed window before it is cleared below.
        lastFeatures = fv;
        haveLastFeatures = true;

        // Emit signal with feature data
        emit(featureExtractionSignal, 1L);

        // VeReMiVNDN-EXE: emit and (optionally) export the five per-plane
        // vectors for every neighbour observed in the current window.
        exportPlaneFeatures();

        // Slide window, retaining the closed one in history so the temporal
        // features that read windowHistory see every window rather than only
        // those closed by an arriving packet.
        finalizeWindow();
        slideWindow();

        // Schedule next extraction
        scheduleAt(simTime() + extractionInterval, extractionTimer);
    }
    else if (msg->arrivedOn("ndnIn")) {
        // Update statistics from incoming packet
        updateWindowStatistics(msg);

        // Forward packet
        send(msg, "ndnOut");
    }
    else {
        send(msg, "ndnOut");
    }
}

void FeatureExtractor::notifyPacket(cMessage *packet)
{
    updateWindowStatistics(packet);
}

void FeatureExtractor::updateWindowStatistics(cMessage *packet)
{
    simtime_t now = simTime();

    // Check if window needs to slide
    if (now >= currentWindow.windowEnd) {
        finalizeWindow();
        slideWindow();
    }

    // Update current window
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(packet)) {
        currentWindow.interestCount++;
        currentWindow.totalInterestSize += interest->getByteLength();
        currentWindow.timestamps.push_back(now);
        currentWindow.contentNames.push_back(interest->getName());
        currentWindow.nonces.push_back(interest->getNonce());

        totalInterests++;
        totalBytes += interest->getByteLength();

        // Track for RTT calculation
        std::string name = interest->getName();
        pendingInterests[name] = now;

        // Track name frequency
        nameFrequency[name]++;

        // Track nonce frequency
        nonceFrequency[interest->getNonce()]++;
    }
    else if (DataPacket *data = dynamic_cast<DataPacket*>(packet)) {
        currentWindow.dataCount++;
        currentWindow.totalDataSize += data->getByteLength();
        currentWindow.timestamps.push_back(now);
        currentWindow.contentNames.push_back(data->getName());

        totalData++;
        totalBytes += data->getByteLength();

        // Calculate RTT if interest was pending
        std::string name = data->getName();
        if (pendingInterests.find(name) != pendingInterests.end()) {
            // RTT calculation happens here
            pendingInterests.erase(name);
        }
    }
}

void FeatureExtractor::finalizeWindow()
{
    // Store window in history
    windowHistory.push_back(currentWindow);

    // Limit history size
    if (windowHistory.size() > maxHistorySize) {
        windowHistory.pop_front();
    }
}

void FeatureExtractor::slideWindow()
{
    // Reset current window
    currentWindow.windowStart = simTime();
    currentWindow.windowEnd = simTime() + timeWindowSize;
    currentWindow.interestCount = 0;
    currentWindow.dataCount = 0;
    currentWindow.nackCount = 0;
    currentWindow.totalInterestSize = 0;
    currentWindow.totalDataSize = 0;
    currentWindow.timestamps.clear();
    currentWindow.contentNames.clear();
    currentWindow.nonces.clear();
}

FeatureVector FeatureExtractor::extractAllFeatures()
{
    FeatureVector fv = {};

    // Set metadata
    fv.timestamp = simTime();
    fv.nodeId = nodeId;

    // Extract all feature categories
    extractNetworkFeatures(fv);
    extractNDNFeatures(fv);
    extractTrustFeatures(fv);
    extractTemporalFeatures(fv);
    extractPrivacyFeatures(fv);
    extractMobilityFeatures(fv);
    extractAttackIndicators(fv);
    extractStatisticalFeatures(fv);

    // Normalize features (optional)
    // normalizeFeatures(fv);

    return fv;
}

FeatureVector FeatureExtractor::getCurrentFeatures()
{
    // Prefer the snapshot of the last completed window; see lastFeatures.
    // Before the first extraction tick there is nothing to serve, so fall back
    // to extracting from the live window.
    return haveLastFeatures ? lastFeatures : extractAllFeatures();
}

// ============================================================================
// NETWORK FEATURES
// ============================================================================

void FeatureExtractor::extractNetworkFeatures(FeatureVector &fv)
{
    fv.interestRate = calculateInterestRate();
    fv.dataRate = calculateDataRate();
    fv.avgInterestSize = currentWindow.interestCount > 0 ?
                         currentWindow.totalInterestSize / currentWindow.interestCount : 0;
    fv.avgDataSize = currentWindow.dataCount > 0 ?
                     currentWindow.totalDataSize / currentWindow.dataCount : 0;
    fv.packetDropRate = calculatePacketDropRate();
    fv.avgHopCount = 0.0;  // TODO: Track hop counts
    fv.interestDataRatio = fv.dataRate > 0 ? fv.interestRate / fv.dataRate : 0;
    fv.nackRate = 0.0;  // TODO: Track NACKs
    fv.avgRTT = calculateAverageRTT();
    fv.jitter = calculateJitter();
}

double FeatureExtractor::calculateInterestRate()
{
    if (currentWindow.timestamps.empty()) return 0.0;

    double windowDuration = (currentWindow.windowEnd - currentWindow.windowStart).dbl();
    return windowDuration > 0 ? currentWindow.interestCount / windowDuration : 0.0;
}

double FeatureExtractor::calculateDataRate()
{
    double windowDuration = (currentWindow.windowEnd - currentWindow.windowStart).dbl();
    return windowDuration > 0 ? currentWindow.dataCount / windowDuration : 0.0;
}

double FeatureExtractor::calculatePacketDropRate()
{
    uint64_t totalPackets = totalInterests + totalData;
    return totalPackets > 0 ? (double)totalDrops / (double)totalPackets : 0.0;
}

double FeatureExtractor::calculateAverageRTT()
{
    // Simplified RTT calculation
    // In full implementation, track Interest-Data RTT
    return 0.010;  // Placeholder: 10ms average
}

double FeatureExtractor::calculateJitter()
{
    if (currentWindow.timestamps.size() < 2) return 0.0;

    std::vector<double> interArrivals;
    for (size_t i = 1; i < currentWindow.timestamps.size(); i++) {
        double delta = (currentWindow.timestamps[i] - currentWindow.timestamps[i-1]).dbl();
        interArrivals.push_back(delta);
    }

    if (interArrivals.empty()) return 0.0;

    double mean = std::accumulate(interArrivals.begin(), interArrivals.end(), 0.0) / interArrivals.size();

    double variance = 0.0;
    for (double val : interArrivals) {
        variance += (val - mean) * (val - mean);
    }
    variance /= interArrivals.size();

    return std::sqrt(variance);  // Standard deviation = jitter
}

// ============================================================================
// NDN FEATURES
// ============================================================================

void FeatureExtractor::extractNDNFeatures(FeatureVector &fv)
{
    // The PIT, FIB and Content Store are read from the host's own tables under
    // ndnNode. Several of these were fixed constants, and csOccupancy was set
    // to the cache hit ratio, which is a different quantity entirely.
    resolveTables();

    fv.pitOccupancy = queryPITOccupancy();
    fv.pitSize = queryPITSize();
    if (auto *pit = dynamic_cast<PIT *>(pitModule)) {
        fv.pitSize = pit->getSize();
        // Occupancy is expressed against the nominal 1000-entry table the
        // placeholder assumed, so the column keeps the 0 to 1 scale it had.
        fv.pitOccupancy = pit->getSize() / 1000.0;
    }
    fv.avgPitLifetime = 4.0;  // Not exposed by the PIT module.
    fv.pitSatisfactionRate = fv.dataRate / (fv.interestRate + 1e-9);
    fv.fibSize = queryFIBSize();
    fv.avgFibEntryHopCount = 3.0;  // Not exposed by the FIB module.
    if (auto *cs = dynamic_cast<CS *>(csModule)) {
        fv.csSize = cs->getSize();
        int hits = cs->getTotalHits(), misses = cs->getTotalMisses();
        int look = hits + misses;
        // Occupancy is the store's fill against its configured capacity, not
        // the hit ratio that used to stand in for it.
        int cap = cs->getMaxSizeValue();
        fv.csOccupancy = cap > 0 ? (double)cs->getSize() / (double)cap : 0.0;
        (void)look;
    }
    else {
        fv.csSize = 0;
        fv.csOccupancy = 0.0;
    }
    fv.cacheHitRatio = queryCacheHitRatio();
    fv.cacheMissRatio = 1.0 - fv.cacheHitRatio;
    fv.avgCacheEntryAge = 10.0;  // Not exposed by the CS module.
    fv.contentStoreDiversity = nameFrequency.size();
    fv.pendingInterestDiversity = pendingInterests.size();
    fv.faceUtilization = 0.5;  // Per-face statistics are not tracked.
    fv.avgForwardingDelay = calculateAverageForwardingDelay();
}

double FeatureExtractor::queryPITOccupancy()
{
    // Query PIT module for occupancy
    // Placeholder: simulate some occupancy
    return pendingInterests.size() / 1000.0;  // Assuming max 1000
}

uint32_t FeatureExtractor::queryPITSize()
{
    return pendingInterests.size();
}

void FeatureExtractor::resolveTables()
{
    if (tablesResolved) return;
    tablesResolved = true;
    cModule *host = getParentModule();
    cModule *ndnNode = host ? host->getSubmodule("ndnNode") : nullptr;
    if (!ndnNode) return;
    csModule  = ndnNode->getSubmodule("cs");
    fibModule = ndnNode->getSubmodule("fib");
    pitModule = ndnNode->getSubmodule("pit");
}

double FeatureExtractor::queryCacheHitRatio()
{
    resolveTables();
    if (auto *cs = dynamic_cast<CS *>(csModule))
        return cs->getHitRatio();
    return 0.0;
}

double FeatureExtractor::queryFIBSize()
{
    resolveTables();
    if (auto *fib = dynamic_cast<FIB *>(fibModule))
        return (double)fib->getSize();
    return 0.0;
}

double FeatureExtractor::calculateAverageForwardingDelay()
{
    // TODO: Track forwarding delays
    return 0.002;  // Placeholder: 2ms
}

// ============================================================================
// TRUST FEATURES
// ============================================================================

void FeatureExtractor::extractTrustFeatures(FeatureVector &fv)
{
    fv.avgTrustScore = calculateAverageTrustScore();
    fv.minTrustScore = 0.0;  // TODO: Track min trust
    fv.maxTrustScore = 1.0;  // TODO: Track max trust
    fv.trustVariance = 0.1;  // TODO: Calculate variance
    fv.signatureVerificationRate = calculateSignatureVerificationRate();
    fv.signatureFailureRate = 1.0 - fv.signatureVerificationRate;
    fv.unsignedDataRatio = calculateUnsignedDataRatio();
    fv.lowTrustPacketRatio = 0.1;  // TODO: Track low-trust packets
}

double FeatureExtractor::calculateAverageTrustScore()
{
    // TODO: Query trust module for average trust scores
    return 0.8;  // Placeholder: 80% trust
}

double FeatureExtractor::calculateSignatureVerificationRate()
{
    // TODO: Track signature verifications
    return 0.95;  // Placeholder: 95% valid signatures
}

double FeatureExtractor::calculateUnsignedDataRatio()
{
    // TODO: Track unsigned data packets
    return 0.05;  // Placeholder: 5% unsigned
}

// ============================================================================
// TEMPORAL FEATURES
// ============================================================================

void FeatureExtractor::extractTemporalFeatures(FeatureVector &fv)
{
    fv.interestRateVariance = calculateRateVariance();
    fv.burstiness = calculateBurstiness();
    fv.periodicity = calculatePeriodicity();
    fv.trendSlope = calculateTrendSlope();
    fv.interArrivalTimeMean = calculateInterArrivalTimeStats();
    fv.interArrivalTimeStdDev = calculateJitter();  // Reuse jitter calculation
    fv.windowInterestCount = currentWindow.interestCount;
    fv.windowDataCount = currentWindow.dataCount;
    fv.shortTermInterestRate = calculateInterestRate();
    fv.longTermInterestRate = totalInterests / (simTime().dbl() + 1e-9);
}

double FeatureExtractor::calculateRateVariance()
{
    if (windowHistory.size() < 2) return 0.0;

    std::vector<double> rates;
    for (const auto &window : windowHistory) {
        double duration = (window.windowEnd - window.windowStart).dbl();
        double rate = duration > 0 ? window.interestCount / duration : 0;
        rates.push_back(rate);
    }

    double mean = std::accumulate(rates.begin(), rates.end(), 0.0) / rates.size();

    double variance = 0.0;
    for (double rate : rates) {
        variance += (rate - mean) * (rate - mean);
    }
    return variance / rates.size();
}

double FeatureExtractor::calculateBurstiness()
{
    // Burstiness = coefficient of variation of inter-arrival times
    if (currentWindow.timestamps.size() < 2) return 0.0;

    std::vector<double> interArrivals;
    for (size_t i = 1; i < currentWindow.timestamps.size(); i++) {
        double delta = (currentWindow.timestamps[i] - currentWindow.timestamps[i-1]).dbl();
        interArrivals.push_back(delta);
    }

    if (interArrivals.empty()) return 0.0;

    double mean = std::accumulate(interArrivals.begin(), interArrivals.end(), 0.0) / interArrivals.size();
    if (mean == 0) return 0.0;

    double variance = 0.0;
    for (double val : interArrivals) {
        variance += (val - mean) * (val - mean);
    }
    double stddev = std::sqrt(variance / interArrivals.size());

    return stddev / mean;  // Coefficient of variation
}

double FeatureExtractor::calculatePeriodicity()
{
    // Simplified periodicity detection
    // TODO: Implement FFT or autocorrelation analysis
    return 0.0;
}

double FeatureExtractor::calculateTrendSlope()
{
    if (windowHistory.size() < 3) return 0.0;

    // Simple linear regression on interest counts
    std::vector<double> counts;
    for (const auto &window : windowHistory) {
        counts.push_back(window.interestCount);
    }

    // Calculate slope (simplified)
    double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
    int n = counts.size();
    for (int i = 0; i < n; i++) {
        sumX += i;
        sumY += counts[i];
        sumXY += i * counts[i];
        sumX2 += i * i;
    }

    double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX + 1e-9);
    return slope;
}

double FeatureExtractor::calculateInterArrivalTimeStats()
{
    if (currentWindow.timestamps.size() < 2) return 0.0;

    double sum = 0.0;
    int count = 0;
    for (size_t i = 1; i < currentWindow.timestamps.size(); i++) {
        sum += (currentWindow.timestamps[i] - currentWindow.timestamps[i-1]).dbl();
        count++;
    }

    return count > 0 ? sum / count : 0.0;
}

// ============================================================================
// PRIVACY FEATURES
// ============================================================================

void FeatureExtractor::extractPrivacyFeatures(FeatureVector &fv)
{
    fv.nameEntropy = calculateNameEntropy();
    fv.uniqueNamesRatio = calculateUniqueNamesRatio();
    fv.repeatedNonceRatio = calculateRepeatedNonceRatio();
    fv.locationExposureRisk = calculateLocationExposureRisk();
    fv.anonymityScore = 1.0 - fv.locationExposureRisk;  // Inverse of exposure
}

double FeatureExtractor::calculateNameEntropy()
{
    if (nameFrequency.empty()) return 0.0;

    uint64_t total = 0;
    for (const auto &entry : nameFrequency) {
        total += entry.second;
    }

    double entropy = 0.0;
    for (const auto &entry : nameFrequency) {
        double p = (double)entry.second / (double)total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

double FeatureExtractor::calculateUniqueNamesRatio()
{
    uint64_t totalRequests = currentWindow.interestCount + currentWindow.dataCount;
    return totalRequests > 0 ? (double)nameFrequency.size() / (double)totalRequests : 0.0;
}

double FeatureExtractor::calculateRepeatedNonceRatio()
{
    int repeatedCount = 0;
    for (const auto &entry : nonceFrequency) {
        if (entry.second > 1) {
            repeatedCount += entry.second - 1;
        }
    }

    return currentWindow.interestCount > 0 ?
           (double)repeatedCount / (double)currentWindow.interestCount : 0.0;
}

double FeatureExtractor::calculateLocationExposureRisk()
{
    // Check if names contain location information
    int exposedNames = 0;
    for (const auto &name : currentWindow.contentNames) {
        // Simple heuristic: check for coordinate-like patterns
        if (name.find("/lat/") != std::string::npos ||
            name.find("/lon/") != std::string::npos ||
            name.find("/pos/") != std::string::npos) {
            exposedNames++;
        }
    }

    return currentWindow.contentNames.size() > 0 ?
           (double)exposedNames / (double)currentWindow.contentNames.size() : 0.0;
}

// ============================================================================
// MOBILITY FEATURES
// ============================================================================

void FeatureExtractor::extractMobilityFeatures(FeatureVector &fv)
{
    fv.speed = getNodeSpeed();
    fv.acceleration = getNodeAcceleration();
    // Position and heading come from the host's mobility module. These three
    // were fixed at zero and the speed at a constant 15 m/s, so every mobility
    // column in the exported dataset was the same value in every row of every
    // run, whatever the vehicle was actually doing.
    if (cModule *mob = resolveMobility()) {
        if (auto *tm = dynamic_cast<veins::TraCIMobility *>(mob)) {
            veins::Coord p = tm->getPositionAt(simTime());
            fv.positionX = p.x;
            fv.positionY = p.y;
            try {
                fv.direction = tm->getHeading().getRad();
            }
            catch (const cRuntimeError &) {
                // Heading is unset until the first TraCI update arrives.
                fv.direction = 0.0;
            }
        }
    }
    fv.neighborCount = getNeighborCount();
}

cModule *FeatureExtractor::resolveMobility()
{
    if (mobilityResolved) return mobilityModule;
    mobilityResolved = true;
    if (cModule *host = getParentModule())
        mobilityModule = host->getSubmodule("mobility");
    return mobilityModule;
}

double FeatureExtractor::getNodeSpeed()
{
    if (cModule *mob = resolveMobility()) {
        if (auto *tm = dynamic_cast<veins::TraCIMobility *>(mob))
            return tm->getSpeed();
    }
    return 0.0;
}

double FeatureExtractor::getNodeAcceleration()
{
    // Veins exposes speed but not acceleration, so this is a finite difference
    // between consecutive samples. It is zero on the first sample of a node,
    // and its resolution is the collection interval rather than the SUMO step.
    double now = getNodeSpeed();
    simtime_t t = simTime();
    double dt = (t - prevSpeedTime).dbl();
    double a = (prevSpeedTime > SIMTIME_ZERO && dt > 0) ? (now - prevSpeed) / dt
                                                        : 0.0;
    prevSpeed = now;
    prevSpeedTime = t;
    return a;
}

int FeatureExtractor::getNeighborCount()
{
    // Neighbors are the distinct senders this node has heard from recently.
    // There is no separate neighbor-discovery module to query, but the
    // per-subject observation map already records who was heard and when, so
    // the count is measured rather than assumed.
    const simtime_t horizon = simTime() - planeWindow;
    int n = 0;
    for (const auto &kv : subjects)
        if (kv.second.lastSeen >= horizon) ++n;
    return n;
}

// ============================================================================
// ATTACK INDICATORS
// ============================================================================

void FeatureExtractor::extractAttackIndicators(FeatureVector &fv)
{
    fv.interestFloodingScore = calculateInterestFloodingScore();
    fv.poisoningScore = calculatePoisoningScore();
    fv.cachePollutionScore = calculateCachePollutionScore();
    fv.timingAttackScore = calculateTimingAttackScore();
    fv.replayScore = calculateReplayScore();
    fv.sybilScore = calculateSybilScore();
    fv.collusionScore = calculateCollusionScore();
    fv.hijackingScore = calculateHijackingScore();
    fv.grayHoleScore = calculateGrayHoleScore();
    fv.jammingScore = calculateJammingScore();
}

double FeatureExtractor::calculateInterestFloodingScore()
{
    // High interest rate + high PIT occupancy + low satisfaction rate
    double rateScore = std::min(1.0, calculateInterestRate() / 100.0);  // Normalize to 0-1
    double pitScore = queryPITOccupancy();
    double satScore = 1.0 - (calculateDataRate() / (calculateInterestRate() + 1e-9));

    return (rateScore + pitScore + satScore) / 3.0;
}

double FeatureExtractor::calculatePoisoningScore()
{
    // Low trust + high signature failure rate
    double trustScore = 1.0 - calculateAverageTrustScore();
    double sigFailScore = 1.0 - calculateSignatureVerificationRate();

    return (trustScore + sigFailScore) / 2.0;
}

double FeatureExtractor::calculateCachePollutionScore()
{
    // High cache occupancy + low hit ratio + high diversity
    double occupancy = queryCacheHitRatio();  // Using as proxy
    double hitRatio = queryCacheHitRatio();
    double diversity = std::min(1.0, nameFrequency.size() / 100.0);

    return (occupancy + (1.0 - hitRatio) + diversity) / 3.0;
}

double FeatureExtractor::calculateTimingAttackScore()
{
    // High periodicity + specific access patterns
    return calculatePeriodicity();
}

double FeatureExtractor::calculateReplayScore()
{
    // High repeated nonce ratio + old timestamps
    return calculateRepeatedNonceRatio();
}

double FeatureExtractor::calculateSybilScore()
{
    // Multiple identities with similar behavior
    return 0.0;  // TODO: Cross-node correlation needed
}

double FeatureExtractor::calculateCollusionScore()
{
    // Coordinated behavior across nodes
    return 0.0;  // TODO: Multi-node analysis needed
}

double FeatureExtractor::calculateHijackingScore()
{
    // Unusual FIB updates + traffic redirection
    return 0.0;  // TODO: FIB monitoring needed
}

double FeatureExtractor::calculateGrayHoleScore()
{
    // High drop rate + selective dropping
    return calculatePacketDropRate();
}

double FeatureExtractor::calculateJammingScore()
{
    // Low packet delivery rate + high interference
    return 0.0;  // TODO: PHY-layer metrics needed
}

// ============================================================================
// STATISTICAL FEATURES
// ============================================================================

void FeatureExtractor::extractStatisticalFeatures(FeatureVector &fv)
{
    fv.totalPackets = currentWindow.interestCount + currentWindow.dataCount;
    fv.totalBytes = currentWindow.totalInterestSize + currentWindow.totalDataSize;
    fv.avgPacketSize = fv.totalPackets > 0 ? fv.totalBytes / fv.totalPackets : 0;
    fv.packetSizeVariance = 0.0;  // TODO: Calculate variance
    fv.trafficEntropy = calculateTrafficEntropy();
}

double FeatureExtractor::calculateTrafficEntropy()
{
    // Entropy of traffic types
    uint64_t total = currentWindow.interestCount + currentWindow.dataCount + currentWindow.nackCount;
    if (total == 0) return 0.0;

    double pInterest = (double)currentWindow.interestCount / (double)total;
    double pData = (double)currentWindow.dataCount / (double)total;
    double pNack = (double)currentWindow.nackCount / (double)total;

    double entropy = 0.0;
    if (pInterest > 0) entropy -= pInterest * std::log2(pInterest);
    if (pData > 0) entropy -= pData * std::log2(pData);
    if (pNack > 0) entropy -= pNack * std::log2(pNack);

    return entropy;
}

// ============================================================================
// HELPER METHODS
// ============================================================================

std::map<std::string, double> FeatureExtractor::featureVectorToMap(const FeatureVector &fv)
{
    std::map<std::string, double> features;

    // Network features
    features["interestRate"] = fv.interestRate;
    features["dataRate"] = fv.dataRate;
    features["avgInterestSize"] = fv.avgInterestSize;
    features["avgDataSize"] = fv.avgDataSize;
    features["packetDropRate"] = fv.packetDropRate;
    features["avgHopCount"] = fv.avgHopCount;
    features["interestDataRatio"] = fv.interestDataRatio;
    features["nackRate"] = fv.nackRate;
    features["avgRTT"] = fv.avgRTT;
    features["jitter"] = fv.jitter;

    // NDN features
    features["pitOccupancy"] = fv.pitOccupancy;
    features["cacheHitRatio"] = fv.cacheHitRatio;

    // Trust features
    features["avgTrustScore"] = fv.avgTrustScore;
    features["signatureVerificationRate"] = fv.signatureVerificationRate;

    // Temporal features
    features["burstiness"] = fv.burstiness;
    features["trendSlope"] = fv.trendSlope;

    // Privacy features
    features["nameEntropy"] = fv.nameEntropy;
    features["uniqueNamesRatio"] = fv.uniqueNamesRatio;

    // Mobility features
    features["speed"] = fv.speed;
    features["neighborCount"] = fv.neighborCount;

    // Attack indicators
    features["interestFloodingScore"] = fv.interestFloodingScore;
    features["poisoningScore"] = fv.poisoningScore;
    features["cachePollutionScore"] = fv.cachePollutionScore;
    features["grayHoleScore"] = fv.grayHoleScore;

    return features;
}

void FeatureExtractor::normalizeFeatures(FeatureVector &fv)
{
    // TODO: Implement feature normalization (z-score or min-max)
}

void FeatureExtractor::finish()
{
    cSimpleModule::finish();

    // Record final statistics
    recordScalar("totalInterests", totalInterests);
    recordScalar("totalData", totalData);
    recordScalar("totalBytes", totalBytes);
    recordScalar("uniqueNames", (long)nameFrequency.size());

    recordScalar("exeSubjectsObserved", (double)subjects.size());
    recordScalar("exeBeaconOnlyWindows", (double)beaconOnlyWindows);
    recordScalar("exeEvidenceWindows", (double)evidenceWindows);
    if (planeCsv) {
        std::fclose(planeCsv);
        planeCsv = nullptr;
    }
}

// ===========================================================================
// VeReMiVNDN-EXE plane-specific feature subsystem
// ===========================================================================

const int EXE_PLANE_DIMS[EXE_NUM_PLANES] = {6, 5, 4, 4, 4};

namespace {

// Prune a (timestamp, value) deque to the trailing `window` seconds.
template <typename T>
inline void prunePairs(std::deque<std::pair<simtime_t, T>> &d,
                       simtime_t now, double window)
{
    while (!d.empty() && (now - d.front().first).dbl() > window) d.pop_front();
}

inline void pruneTimes(std::deque<simtime_t> &d, simtime_t now, double window)
{
    while (!d.empty() && (now - d.front()).dbl() > window) d.pop_front();
}

// Mean of the value component of a (timestamp, double) deque.
inline double meanOf(const std::deque<std::pair<simtime_t, double>> &d)
{
    if (d.empty()) return 0.0;
    double s = 0.0;
    for (const auto &p : d) s += p.second;
    return s / (double)d.size();
}

// Sample variance of the value component.
inline double varianceOf(const std::deque<std::pair<simtime_t, double>> &d)
{
    if (d.size() < 2) return 0.0;
    double m = meanOf(d), v = 0.0;
    for (const auto &p : d) v += (p.second - m) * (p.second - m);
    return v / (double)(d.size() - 1);
}

// Squash an unbounded non-negative rate into [0,1] with a soft knee at `scale`.
inline double squash(double x, double scale)
{
    if (scale <= 0.0) return 0.0;
    double t = x / scale;
    return t / (1.0 + t);
}

} // anonymous namespace

double FeatureExtractor::shannonEntropyPerByte(const char *buf)
{
    if (!buf || !*buf) return 0.0;
    int hist[256] = {0};
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)buf; *p; ++p) {
        hist[*p]++;
        ++n;
    }
    if (n == 0) return 0.0;
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        double p = (double)hist[i] / (double)n;
        h -= p * std::log2(p);
    }
    return h / 8.0;   // normalize to [0,1]
}

double FeatureExtractor::normalizedEntropy(const std::map<std::string, int> &hist)
{
    if (hist.size() < 2) return 0.0;
    int total = 0;
    for (const auto &kv : hist) total += kv.second;
    if (total <= 0) return 0.0;
    double h = 0.0;
    for (const auto &kv : hist) {
        double p = (double)kv.second / (double)total;
        if (p > 0.0) h -= p * std::log2(p);
    }
    return h / std::log2((double)hist.size());
}

void FeatureExtractor::initPlaneFeatures()
{
    exePlaneFeaturesEnabled = par("enableExePlaneFeatures").boolValue();
    if (!exePlaneFeaturesEnabled) return;

    planeWindow     = par("interactionGraphWindow").doubleValue();
    if (planeWindow <= 0.0) planeWindow = 2.0;
    positionEpsilon = par("sybilPositionEpsilon").doubleValue();
    planeCsvPath    = par("planeFeatureCsv").stdstringValue();

    static const char *sigNames[EXE_NUM_PLANES] = {
        "planeScoreData", "planeScoreCache", "planeScoreTrust",
        "planeScoreForwarding", "planeScorePhy"
    };
    for (int p = 0; p < EXE_NUM_PLANES; ++p)
        planeScoreSignals[p] = registerSignal(sigNames[p]);

    // Subscribe to the host NIC's real 802.11p MAC counters. These are Veins
    // signals, so the PHY plane is fed by measured channel state rather than
    // by anything derived from attacker identity.
    cModule *host = getParentModule();
    if (host) {
        for (const char *s : {"org_car2x_veins_modules_mac_sigChannelBusy",
                              "org_car2x_veins_modules_mac_sigCollision",
                              "org_car2x_veins_modules_mac_sigRetriesExceeded"}) {
            try {
                host->subscribe(s, this);
            }
            catch (const cRuntimeError &) {
                EV_DETAIL << "FeatureExtractor: MAC signal " << s
                          << " unavailable on this host\n";
            }
        }
    }

    if (!planeCsvPath.empty()) {
        // One file per module instance keeps parallel runs from interleaving.
        std::string path = planeCsvPath;
        std::string tag  = nodeIdentifier;
        for (char &c : tag) if (c == '.' || c == '[' || c == ']') c = '_';
        size_t dot = path.rfind('.');
        if (dot == std::string::npos) path += "_" + tag + ".csv";
        else path = path.substr(0, dot) + "_" + tag + path.substr(dot);

        planeCsv = std::fopen(path.c_str(), "w");
        if (planeCsv) {
            std::fprintf(planeCsv,
                "t,observer,subject,"
                "d_sigfail,d_entropy,d_freshdev,d_stale,d_noncecollide,d_signerent,"
                "c_hitrate,c_missrate,c_timinggap,c_evictrate,c_proberegularity,"
                "t_corequest,t_idswitch,t_posoverlap,t_reqrate,"
                "f_dropratio,f_deltaisr,f_droppatternent,f_delayvar,"
                "p_lossfrac,p_rxshare,p_rxdeficit,p_shareunderloss,"
                "label\n");
        }
        else {
            EV_WARN << "FeatureExtractor: cannot open plane CSV " << path << "\n";
        }
    }
}

// Veins emits sigChannelBusy as a bool edge (true on busy, false on idle),
// sigCollision as bool true, and sigRetriesExceeded with the offending packet
// as a cObject. All three overloads are therefore required; the busy fraction
// is integrated from the edges rather than read off a single value.
void FeatureExtractor::receiveSignal(cComponent *, simsignal_t id,
                                     bool value, cObject *)
{
    if (!exePlaneFeaturesEnabled) return;
    const char *name = cComponent::getSignalName(id);
    if (!name) return;

    if (std::strstr(name, "sigChannelBusy")) {
        if (value) {
            if (phyBusySince < SIMTIME_ZERO) phyBusySince = simTime();
        }
        else if (phyBusySince >= SIMTIME_ZERO) {
            observePhyBusy((simTime() - phyBusySince).dbl());
            phyBusySince = SIMTIME_ZERO - 1;
        }
    }
    else if (std::strstr(name, "sigCollision")) {
        if (value) observePhyCollision();
    }
}

void FeatureExtractor::receiveSignal(cComponent *, simsignal_t id,
                                     double value, cObject *)
{
    if (!exePlaneFeaturesEnabled) return;
    const char *name = cComponent::getSignalName(id);
    if (!name) return;
    if (std::strstr(name, "sigChannelBusy")) observePhyBusy(value);
}

void FeatureExtractor::receiveSignal(cComponent *, simsignal_t id,
                                     long value, cObject *)
{
    if (!exePlaneFeaturesEnabled) return;
    const char *name = cComponent::getSignalName(id);
    if (!name) return;
    if (std::strstr(name, "sigCollision"))            observePhyCollision();
    else if (std::strstr(name, "sigRetriesExceeded")) observePhyRetryExceeded();
}

void FeatureExtractor::receiveSignal(cComponent *, simsignal_t id,
                                     cObject *, cObject *)
{
    if (!exePlaneFeaturesEnabled) return;
    const char *name = cComponent::getSignalName(id);
    if (!name) return;
    if (std::strstr(name, "sigRetriesExceeded")) observePhyRetryExceeded();
}

void FeatureExtractor::pruneSubject(SubjectObservation &s, simtime_t now)
{
    pruneTimes(s.rxTimes,       now, planeWindow);
    pruneTimes(s.interestTimes, now, planeWindow);
    pruneTimes(s.dataTimes,     now, planeWindow);
    pruneTimes(s.nackTimes,     now, planeWindow);
    pruneTimes(s.dropTimes,     now, planeWindow);

    prunePairs(s.payloadEntropy,   now, planeWindow);
    prunePairs(s.sigFailFlag,      now, planeWindow);
    prunePairs(s.freshnessDev,     now, planeWindow);
    prunePairs(s.staleFlag,        now, planeWindow);
    prunePairs(s.nonceCollideFlag, now, planeWindow);
    prunePairs(s.signerIds,        now, planeWindow);

    prunePairs(s.csHitFlag,   now, planeWindow);
    prunePairs(s.respTimeHit, now, planeWindow);
    prunePairs(s.respTimeMiss,now, planeWindow);

    prunePairs(s.requestedNames, now, planeWindow);
    prunePairs(s.posX,           now, planeWindow);
    prunePairs(s.posY,           now, planeWindow);

    prunePairs(s.forwardDelay,   now, planeWindow);
    prunePairs(s.satisfiedFlag,  now, planeWindow);
}

void FeatureExtractor::pruneObserverLogs(simtime_t now)
{
    while (!coRequestLog.empty() &&
           (now - coRequestLog.front().first).dbl() > planeWindow)
        coRequestLog.pop_front();

    prunePairs(phyBusyLog, now, planeWindow);
    pruneTimes(phyCollisionLog,      now, planeWindow);
    pruneTimes(phyRetryExceededLog,  now, planeWindow);
    pruneTimes(phyRxLog,             now, planeWindow);
    pruneTimes(phyLossLog,           now, planeWindow);

    for (auto it = seenNameNonce.begin(); it != seenNameNonce.end(); ) {
        if ((now - it->second).dbl() > 4.0 * planeWindow) it = seenNameNonce.erase(it);
        else ++it;
    }

    // Requests that outlived the Interest lifetime were never answered: score
    // them against the neighbour that issued them.
    for (auto it = outstanding.begin(); it != outstanding.end(); ) {
        if ((now - it->second.at).dbl() > interestTimeout) {
            subjects[it->second.subject].satisfiedFlag.emplace_back(now, 0.0);
            it = outstanding.erase(it);
        }
        else ++it;
    }
}

// ---------------------------------------------------------------------------
// Observation hooks (called from NDNProcessor)
// ---------------------------------------------------------------------------

void FeatureExtractor::observeInterest(InterestPacket *interest)
{
    if (!exePlaneFeaturesEnabled || !interest) return;
    std::string subject = interest->getSenderId();
    if (subject.empty() || subject == nodeIdentifier) return;

    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.lastSeen = now;
    s.rxTimes.push_back(now);
    s.interestTimes.push_back(now);
    s.requestedNames.emplace_back(now, std::string(interest->getName()));
    s.posX.emplace_back(now, interest->getLatitude());
    s.posY.emplace_back(now, interest->getLongitude());

    coRequestLog.emplace_back(now,
        std::make_pair(std::string(interest->getName()), subject));

    // Track the request so its fate can be scored when the Data (or nothing)
    // comes back. Only the first requester of a name is charged, which matches
    // NDN Interest aggregation.
    std::string name = interest->getName();
    if (outstanding.find(name) == outstanding.end())
        outstanding[name] = PendingRequest{now, subject};

    pruneSubject(s, now);
    pruneObserverLogs(now);
    observePhyRx();
}

void FeatureExtractor::observeData(DataPacket *data)
{
    if (!exePlaneFeaturesEnabled || !data) return;
    std::string subject = data->getSenderId();
    if (subject.empty() || subject == nodeIdentifier) return;

    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.lastSeen = now;
    s.rxTimes.push_back(now);
    s.dataTimes.push_back(now);

    // Signature evidence: unsigned Data, or a signature string that does not
    // match the claimed signer, counts as a verification failure. This is the
    // same check the NDN forwarder performs before admitting Data to the CS.
    std::string sig    = data->getSignature();
    std::string signer = data->getSignerId();
    bool sigFail = (!data->isSigned()) || sig.empty() ||
                   (!signer.empty() && sig.find(signer) == std::string::npos);
    s.sigFailFlag.emplace_back(now, sigFail ? 1.0 : 0.0);
    if (!signer.empty()) s.signerIds.emplace_back(now, signer);

    s.payloadEntropy.emplace_back(now, shannonEntropyPerByte(data->getContent()));

    // Freshness evidence: how far past its declared freshness period the Data
    // arrived. Replayed content shows a positive, growing deviation.
    double age    = (now - data->getTimestamp()).dbl();
    double fresh  = data->getFreshnessPeriod().dbl();
    double dev    = (fresh > 0.0) ? std::max(0.0, age - fresh) : std::max(0.0, age);
    s.freshnessDev.emplace_back(now, dev);
    s.staleFlag.emplace_back(now, dev > 0.0 ? 1.0 : 0.0);

    // Nonce/name replay evidence.
    std::string key = std::string(data->getName()) + "#" +
                      std::to_string((long)data->getHopCount());
    auto it = seenNameNonce.find(key);
    bool collide = (it != seenNameNonce.end());
    seenNameNonce[key] = now;
    s.nonceCollideFlag.emplace_back(now, collide ? 1.0 : 0.0);

    // This Data answers an outstanding request: credit the requester.
    auto po = outstanding.find(std::string(data->getName()));
    if (po != outstanding.end()) {
        subjects[po->second.subject].satisfiedFlag.emplace_back(now, 1.0);
        outstanding.erase(po);
    }

    pruneSubject(s, now);
    pruneObserverLogs(now);
    observePhyRx();
}

void FeatureExtractor::observeNack(NackPacket *nack)
{
    if (!exePlaneFeaturesEnabled || !nack) return;
    std::string subject = nack->getSenderId();
    if (subject.empty() || subject == nodeIdentifier) return;
    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.lastSeen = now;
    s.rxTimes.push_back(now);
    s.nackTimes.push_back(now);
    pruneSubject(s, now);
    observePhyRx();
}

void FeatureExtractor::observeBeacon(BeaconPacket *beacon)
{
    if (!exePlaneFeaturesEnabled || !beacon) return;
    std::string subject = beacon->getSenderId();
    if (subject.empty()) subject = beacon->getVehicleId();
    if (subject.empty() || subject == nodeIdentifier) return;

    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.lastSeen = now;
    // Position and identity evidence for the trust plane. A Sybil attacker
    // announces several identities from the same point, which is exactly what
    // the co-location statistic in getPlaneVector() measures.
    s.rxTimes.push_back(now);
    s.posX.emplace_back(now, beacon->getLatitude());
    s.posY.emplace_back(now, beacon->getLongitude());
    pruneSubject(s, now);
    observePhyRx();
}

void FeatureExtractor::observeDrop(const std::string &subject)
{
    if (!exePlaneFeaturesEnabled || subject.empty()) return;
    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.dropTimes.push_back(now);
    pruneSubject(s, now);
}

void FeatureExtractor::observeCsOutcome(const std::string &subject, bool hit,
                                        double responseSeconds)
{
    if (!exePlaneFeaturesEnabled || subject.empty()) return;
    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.csHitFlag.emplace_back(now, hit ? 1.0 : 0.0);
    if (hit) s.respTimeHit.emplace_back(now, responseSeconds);
    else     s.respTimeMiss.emplace_back(now, responseSeconds);
    pruneSubject(s, now);
}

void FeatureExtractor::observeForwardDelay(const std::string &subject, double seconds)
{
    if (!exePlaneFeaturesEnabled || subject.empty()) return;
    simtime_t now = simTime();
    SubjectObservation &s = subjects[subject];
    s.forwardDelay.emplace_back(now, seconds);
    pruneSubject(s, now);
}

void FeatureExtractor::observePhyBusy(double busySeconds)
{
    if (!exePlaneFeaturesEnabled) return;
    phyBusyLog.emplace_back(simTime(), std::max(0.0, busySeconds));
}

void FeatureExtractor::observePhyCollision()
{
    if (!exePlaneFeaturesEnabled) return;
    phyCollisionLog.push_back(simTime());
}

void FeatureExtractor::observePhyRetryExceeded()
{
    if (!exePlaneFeaturesEnabled) return;
    phyRetryExceededLog.push_back(simTime());
}

void FeatureExtractor::observePhyRx()
{
    if (!exePlaneFeaturesEnabled) return;
    phyRxLog.push_back(simTime());
}

void FeatureExtractor::observePhyLoss()
{
    if (!exePlaneFeaturesEnabled) return;
    phyLossLog.push_back(simTime());
}

// ---------------------------------------------------------------------------
// Plane vector construction
// ---------------------------------------------------------------------------

std::vector<std::string> FeatureExtractor::observedSubjects() const
{
    std::vector<std::string> out;
    out.reserve(subjects.size());
    for (const auto &kv : subjects) out.push_back(kv.first);
    return out;
}

std::vector<double> FeatureExtractor::getPlaneVector(int plane,
                                                     const std::string &subject)
{
    if (!exePlaneFeaturesEnabled) return {};
    auto it = subjects.find(subject);
    if (it == subjects.end()) return {};

    simtime_t now = simTime();
    SubjectObservation &s = it->second;
    pruneSubject(s, now);
    pruneObserverLogs(now);

    const double W = planeWindow;

    switch (plane) {

    // -- Data plane: signature, payload, freshness, replay -----------------
    case EXE_PLANE_DATA: {
        std::map<std::string, int> signerHist;
        for (const auto &p : s.signerIds) signerHist[p.second]++;
        return {
            meanOf(s.sigFailFlag),
            meanOf(s.payloadEntropy),
            squash(meanOf(s.freshnessDev), 5.0),
            meanOf(s.staleFlag),
            meanOf(s.nonceCollideFlag),
            normalizedEntropy(signerHist)
        };
    }

    // -- Caching plane: hit/miss skew, timing side-channel, eviction -------
    case EXE_PLANE_CACHE: {
        double hit  = meanOf(s.csHitFlag);
        double tHit = meanOf(s.respTimeHit);
        double tMis = meanOf(s.respTimeMiss);
        double gap  = squash(std::max(0.0, tMis - tHit), 0.010);

        // Eviction pressure this subject's Interests generate: misses per
        // second, which is what a pollution attacker drives up.
        double missRate = 0.0;
        for (const auto &p : s.csHitFlag) if (p.second < 0.5) missRate += 1.0;
        missRate = (W > 0.0) ? missRate / W : 0.0;

        // Probe regularity: a side-channel prober emits near-periodic
        // Interests, so the coefficient of variation of its inter-arrival
        // times collapses towards zero.
        double regularity = 0.0;
        if (s.interestTimes.size() >= 3) {
            std::vector<double> ia;
            for (size_t i = 1; i < s.interestTimes.size(); ++i)
                ia.push_back((s.interestTimes[i] - s.interestTimes[i-1]).dbl());
            double m = std::accumulate(ia.begin(), ia.end(), 0.0) / ia.size();
            if (m > 1e-9) {
                double v = 0.0;
                for (double x : ia) v += (x - m) * (x - m);
                double cv = std::sqrt(v / ia.size()) / m;
                regularity = 1.0 / (1.0 + cv);
            }
        }
        return { hit, 1.0 - hit, gap, squash(missRate, 20.0), regularity };
    }

    // -- Trust plane: identity graph around the subject --------------------
    case EXE_PLANE_TRUST: {
        // Co-request cluster: how many distinct identities asked for the same
        // names as this subject inside the window.
        std::set<std::string> subjectNames;
        for (const auto &p : s.requestedNames) subjectNames.insert(p.second);
        std::set<std::string> coSenders;
        for (const auto &e : coRequestLog) {
            if (subjectNames.count(e.second.first) && e.second.second != subject)
                coSenders.insert(e.second.second);
        }

        // Identity-switch rate: distinct identities transmitting from within
        // positionEpsilon of this subject, the geometric Sybil signature.
        double sx = s.posX.empty() ? 0.0 : s.posX.back().second;
        double sy = s.posY.empty() ? 0.0 : s.posY.back().second;
        std::set<std::string> colocated;
        for (const auto &kv : subjects) {
            if (kv.first == subject) continue;
            const SubjectObservation &o = kv.second;
            if (o.posX.empty() || o.posY.empty()) continue;
            double dx = o.posX.back().second - sx;
            double dy = o.posY.back().second - sy;
            if (std::sqrt(dx*dx + dy*dy) <= positionEpsilon) colocated.insert(kv.first);
        }

        double overlap = subjectNames.empty()
            ? 0.0 : std::min(1.0, (double)coSenders.size() / (double)subjectNames.size());
        double reqRate = (W > 0.0) ? (double)s.interestTimes.size() / W : 0.0;

        return {
            squash((double)coSenders.size(), 8.0),
            squash((double)colocated.size(), 8.0),
            overlap,
            squash(reqRate, 50.0)
        };
    }

    // -- Forwarding-behaviour plane: drops, ISR deficit, drop pattern ------
    case EXE_PLANE_FORWARDING: {
        double sent = (double)(s.interestTimes.size() + s.dataTimes.size());
        double drops = (double)s.dropTimes.size();
        double dropRatio = (sent + drops > 0.0) ? drops / (sent + drops) : 0.0;

        // Interest Satisfaction Ratio deficit for this subject's flows.
        double isr = meanOf(s.satisfiedFlag);
        double deltaISR = std::max(0.0, 1.0 - isr);

        // Drop-pattern entropy separates selective (structured) dropping from
        // congestion (memoryless) dropping: bucket the inter-drop gaps and
        // measure how far the distribution is from uniform.
        double patternEntropy = 0.0;
        if (s.dropTimes.size() >= 3) {
            std::map<std::string, int> bins;
            for (size_t i = 1; i < s.dropTimes.size(); ++i) {
                double g = (s.dropTimes[i] - s.dropTimes[i-1]).dbl();
                int b = (int)std::min(7.0, std::floor(g / (W / 8.0)));
                bins[std::to_string(b)]++;
            }
            patternEntropy = normalizedEntropy(bins);
        }

        return {
            dropRatio,
            deltaISR,
            patternEntropy,
            squash(std::sqrt(varianceOf(s.forwardDelay)), 0.050)
        };
    }

    // -- Physical plane: measured 802.11p channel state --------------------
    case EXE_PLANE_PHY: {
        double busy = 0.0;
        for (const auto &p : phyBusyLog) busy += p.second;
        double busyFrac = (W > 0.0) ? std::min(1.0, busy / W) : 0.0;

        // Frames this receiver failed to receive because the channel was being
        // jammed, and how bursty those failures are. Both are observable at the
        // radio without any knowledge of who the jammer is.
        double lossRate = (W > 0.0) ? (double)phyLossLog.size() / W : 0.0;
        double rxCount  = (double)phyRxLog.size();
        double lossFrac = (rxCount + (double)phyLossLog.size() > 0.0)
            ? (double)phyLossLog.size() / (rxCount + (double)phyLossLog.size()) : 0.0;

        // Share of the frames this observer still received that came from this
        // subject. Under jamming the denominator collapses while a jammer's own
        // contribution does not, so the share rises sharply for the jammer and
        // falls for everybody else.
        double share = (rxCount > 0.0) ? (double)s.rxTimes.size() / rxCount : 0.0;

        // The same share weighted by how much loss the observer is suffering:
        // a high share is only suspicious while the channel is being degraded.
        double shareUnderLoss = share * lossFrac;
        (void)busyFrac; (void)lossRate;

        // Reception deficit relative to this observer's own rolling baseline.
        double rxNow = (W > 0.0) ? (double)phyRxLog.size() / W : 0.0;
        phyRxBaseline = (phyRxBaseline <= 0.0) ? rxNow
                                               : 0.95 * phyRxBaseline + 0.05 * rxNow;
        double deficit = (phyRxBaseline > 1e-9)
            ? std::max(0.0, std::min(1.0, 1.0 - rxNow / phyRxBaseline)) : 0.0;

        return { lossFrac, share, deficit, shareUnderLoss };
    }

    default:
        return {};
    }
}

int FeatureExtractor::resolveSubjectLabel(const std::string &subject) const
{
    // Post-hoc ground truth for the exported CSV only. This value is never
    // returned to MI-IDS and never enters getPlaneVector().
    cModule *net = getSimulation()->getSystemModule();
    if (!net) return -1;
    cModule *m = net->findModuleByPath(subject.c_str());
    if (!m) {
        for (cModule::SubmoduleIterator it(net); !it.end(); ++it) {
            if (subject == (*it)->getFullName()) { m = *it; break; }
        }
    }
    if (!m || !m->hasPar("hasAttackModule")) return -1;
    return m->par("hasAttackModule").boolValue() ? 1 : 0;
}

void FeatureExtractor::exportPlaneFeatures()
{
    if (!exePlaneFeaturesEnabled) return;

    simtime_t now = simTime();
    pruneObserverLogs(now);

    // Drop neighbours we have not heard from for several windows so the
    // subject map tracks the current neighbourhood rather than the whole run.
    for (auto it = subjects.begin(); it != subjects.end(); ) {
        if ((now - it->second.lastSeen).dbl() > 5.0 * planeWindow)
            it = subjects.erase(it);
        else ++it;
    }

    double planeMean[EXE_NUM_PLANES] = {0.0, 0.0, 0.0, 0.0, 0.0};
    int    nSubjects = 0;

    for (const auto &kv : subjects) {
        const std::string &subject = kv.first;
        const SubjectObservation &so = kv.second;

        // Evidence gate: the observer must have heard at least one Interest,
        // Data or NACK from this subject inside the window. Beacon-only
        // windows tell us the neighbour exists, not how it behaves.
        const size_t evidence = so.interestTimes.size() + so.dataTimes.size()
                              + so.nackTimes.size();
        if (evidence == 0) { ++beaconOnlyWindows; continue; }

        std::vector<double> row;
        row.reserve(23);

        for (int p = 0; p < EXE_NUM_PLANES; ++p) {
            std::vector<double> v = getPlaneVector(p, subject);
            if ((int)v.size() != EXE_PLANE_DIMS[p]) v.assign(EXE_PLANE_DIMS[p], 0.0);
            // Plane score = mean activation of that plane's features; used as
            // an observability signal, not as the detector input.
            double m = 0.0;
            for (double x : v) m += x;
            planeMean[p] += m / (double)EXE_PLANE_DIMS[p];
            row.insert(row.end(), v.begin(), v.end());
        }
        ++nSubjects;
        ++evidenceWindows;
        writePlaneCsvRow(subject, row, resolveSubjectLabel(subject));
    }

    if (nSubjects > 0) {
        for (int p = 0; p < EXE_NUM_PLANES; ++p)
            emit(planeScoreSignals[p], planeMean[p] / (double)nSubjects);
    }
}

void FeatureExtractor::writePlaneCsvRow(const std::string &subject,
                                        const std::vector<double> &v, int label)
{
    if (!planeCsv) return;
    std::fprintf(planeCsv, "%.4f,%s,%s", simTime().dbl(),
                 nodeIdentifier.c_str(), subject.c_str());
    for (double x : v) std::fprintf(planeCsv, ",%.6f", x);
    std::fprintf(planeCsv, ",%d\n", label);
    // Vehicle-hosted monitors are destroyed by TraCI when their vehicle leaves
    // the scenario, and OMNeT++ does not call finish() on deleted modules, so
    // anything still buffered would be lost. Flushing on every row is far too
    // slow at this scale, so flush periodically: at most a few hundred rows can
    // be lost per departing vehicle, out of millions written per run.
    if (++planeCsvRows % 256 == 0) std::fflush(planeCsv);
}

} // namespace veremivndn
