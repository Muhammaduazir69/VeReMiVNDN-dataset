//
// VeReMiVNDN - IDS Feature Extractor Implementation
//

#include "FeatureExtractor.h"
#include <cmath>
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

        // Emit signal with feature data
        emit(featureExtractionSignal, 1L);

        // Slide window
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
    return extractAllFeatures();
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
    fv.pitOccupancy = queryPITOccupancy();
    fv.pitSize = queryPITSize();
    fv.avgPitLifetime = 4.0;  // TODO: Query from PIT module
    fv.pitSatisfactionRate = fv.dataRate / (fv.interestRate + 1e-9);
    fv.fibSize = queryFIBSize();
    fv.avgFibEntryHopCount = 3.0;  // TODO: Query from FIB
    fv.csOccupancy = queryCacheHitRatio();  // Approximation
    fv.csSize = 0;  // TODO: Query from CS module
    fv.cacheHitRatio = queryCacheHitRatio();
    fv.cacheMissRatio = 1.0 - fv.cacheHitRatio;
    fv.avgCacheEntryAge = 10.0;  // TODO: Query from CS
    fv.contentStoreDiversity = nameFrequency.size();
    fv.pendingInterestDiversity = pendingInterests.size();
    fv.faceUtilization = 0.5;  // TODO: Track face stats
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

double FeatureExtractor::queryCacheHitRatio()
{
    // TODO: Query CS module for actual cache hit ratio
    return 0.3;  // Placeholder: 30% hit ratio
}

double FeatureExtractor::queryFIBSize()
{
    // TODO: Query FIB module
    return 50.0;  // Placeholder
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
    fv.direction = 0.0;  // TODO: Get from mobility module
    fv.positionX = 0.0;  // TODO: Get from mobility module
    fv.positionY = 0.0;  // TODO: Get from mobility module
    fv.neighborCount = getNeighborCount();
}

double FeatureExtractor::getNodeSpeed()
{
    // TODO: Query mobility module
    return 15.0;  // Placeholder: 15 m/s (54 km/h)
}

double FeatureExtractor::getNodeAcceleration()
{
    // TODO: Query mobility module
    return 0.0;  // Placeholder
}

int FeatureExtractor::getNeighborCount()
{
    // TODO: Query neighbor discovery module
    return 5;  // Placeholder
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
}

} // namespace veremivndn
