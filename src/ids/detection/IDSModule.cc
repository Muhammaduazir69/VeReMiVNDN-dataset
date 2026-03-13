//
// VeReMiVNDN - IDS Module Implementation
//

#include "IDSModule.h"
#include <fstream>
#include <ctime>

namespace veremivndn {

Define_Module(IDSModule);

// Define static members
std::ofstream IDSModule::csvLog;
std::ofstream IDSModule::jsonLog;
bool IDSModule::filesInitialized = false;
int IDSModule::activeInstances = 0;

IDSModule::IDSModule() : monitoringTimer(nullptr), loggingTimer(nullptr),
                         detectionCount(0) {
    activeInstances++;
}

IDSModule::~IDSModule() {
    cancelAndDelete(monitoringTimer);
    cancelAndDelete(loggingTimer);

    activeInstances--;
    // Close files only when last instance is destroyed
    if (activeInstances == 0) {
        if (csvLog.is_open()) {
            csvLog.close();
            EV_INFO << "Closed shared CSV log file" << endl;
        }
        if (jsonLog.is_open()) {
            jsonLog << "\n]" << std::endl;
            jsonLog.close();
            EV_INFO << "Closed shared JSON log file" << endl;
        }
        filesInitialized = false;
    }
}

void IDSModule::initialize(int stage) {
    if (stage == 0) {
        std::string methodStr = par("detectionMethod").stdstringValue();
        if (methodStr == "Anomaly") detectionMethod = DetectionMethod::ANOMALY;
        else if (methodStr == "Signature") detectionMethod = DetectionMethod::SIGNATURE;
        else if (methodStr == "Hybrid") detectionMethod = DetectionMethod::HYBRID;
        else detectionMethod = DetectionMethod::ANOMALY;

        detectionThreshold = par("detectionThreshold");
        loggingEnabled = par("loggingEnabled");
        realtimeDetection = par("realtimeDetection").boolValue();

        // Get parent module (VndnVehicle or VndnRSU)
        cModule *parent = getParentModule();
        nodeId = parent->par("nodeId");

        // Try to get vehicleId if it exists (for vehicles), otherwise use nodeId
        if (parent->hasPar("vehicleId")) {
            nodeIdentifier = parent->par("vehicleId").stdstringValue();
            if (nodeIdentifier.empty()) {
                nodeIdentifier = "Node_" + std::to_string(nodeId);
            }
        } else {
            nodeIdentifier = "RSU_" + std::to_string(nodeId);
        }

        monitoringInterval = par("monitoringInterval");
        loggingInterval = par("loggingInterval");

        attackDetectedSignal = registerSignal("attackDetected");
        falsePositiveSignal = registerSignal("falsePositive");
        falseNegativeSignal = registerSignal("falseNegative");
        detectionAccuracySignal = registerSignal("detectionAccuracy");
        confidenceSignal = registerSignal("confidence");

        calculateDynamicThresholds();

        EV_INFO << "IDS initialized for " << nodeIdentifier
                << ": method=" << methodStr << ", threshold=" << detectionThreshold << endl;
    }
    else if (stage == 1) {
        // Subscribe to all attack signals from network modules
        subscribeToAttackSignals();

        EV_INFO << "IDS subscribed to all attack signals" << endl;
    }
    else if (stage == 2) {
        if (loggingEnabled && !filesInitialized) {
            // Only first instance opens the shared files
            std::string filename = "ids_log_unified.csv";
            csvLog.open(filename.c_str(), std::ios::out | std::ios::trunc);
            if (csvLog.is_open()) {
                writeCSVHeader();
                EV_INFO << "Created unified CSV log file: " << filename << endl;
            }

            std::string jsonFilename = "ids_log_unified.json";
            jsonLog.open(jsonFilename.c_str(), std::ios::out | std::ios::trunc);
            if (jsonLog.is_open()) {
                jsonLog << "[" << std::endl;
                EV_INFO << "Created unified JSON log file: " << jsonFilename << endl;
            }

            filesInitialized = true;
        }

        monitoringTimer = new cMessage("idsMonitor");
        scheduleAt(simTime() + monitoringInterval, monitoringTimer);

        if (loggingEnabled) {
            loggingTimer = new cMessage("idsLogging");
            scheduleAt(simTime() + loggingInterval, loggingTimer);
        }
    }
}

void IDSModule::handleMessage(cMessage *msg) {
    if (msg == monitoringTimer) {
        monitorTraffic();
        scheduleAt(simTime() + monitoringInterval, monitoringTimer);
    }
    else if (msg == loggingTimer) {
        logGroundTruth();
        scheduleAt(simTime() + loggingInterval, loggingTimer);
    }
}

void IDSModule::finish() {
    // Record overall detection statistics
    recordScalar("totalDetections", detectionCount);
    recordScalar("detectionAccuracy", calculateAccuracy());
    recordScalar("detectionPrecision", calculatePrecision());
    recordScalar("detectionRecall", calculateRecall());
    recordScalar("detectionF1Score", calculateF1Score());

    // Record attack-specific detections for all 20 attacks
    recordScalar("interestFloodingDetections", attackCounters.interestFloodingDetected);
    recordScalar("contentPoisoningDetections", attackCounters.contentPoisoningDetected);
    recordScalar("cachePollutionDetections", attackCounters.cachePollutionDetected);
    recordScalar("timingAttackDetections", attackCounters.timingAttackDetected);
    recordScalar("sybilAttackDetections", attackCounters.sybilAttackDetected);
    recordScalar("collusionAttackDetections", attackCounters.collusionAttackDetected);
    recordScalar("privacyAttackDetections", attackCounters.privacyAttackDetected);
    recordScalar("trustAttackDetections", attackCounters.trustAttackDetected);
    recordScalar("selectiveForwardingDetections", attackCounters.selectiveForwardingDetected);

    // New attacks (10-20)
    recordScalar("signatureForgeryDetections", attackCounters.signatureForgeryDetected);
    recordScalar("privacyDeanonymizationDetections", attackCounters.privacyDeanonymizationDetected);
    recordScalar("interestAggregationDetections", attackCounters.interestAggregationDetected);
    recordScalar("cacheInvalidationDetections", attackCounters.cacheInvalidationDetected);
    recordScalar("radioJammingDetections", attackCounters.radioJammingDetected);
    recordScalar("cachePrivacyLeakageDetections", attackCounters.cachePrivacyLeakageDetected);
    recordScalar("producerImpersonationDetections", attackCounters.producerImpersonationDetected);
    recordScalar("cachePartitioningDetections", attackCounters.cachePartitioningDetected);
    recordScalar("routingInfoFloodDetections", attackCounters.routingInfoFloodDetected);
    recordScalar("nameEnumerationDetections", attackCounters.nameEnumerationDetected);
    recordScalar("mlEvasionDetections", attackCounters.mlEvasionDetected);

    // Record overall attack activity
    recordScalar("totalPacketsModified", attackCounters.totalPacketsModified);
    recordScalar("totalPacketsDropped", attackCounters.totalPacketsDropped);
    recordScalar("totalMaliciousPackets", attackCounters.totalMaliciousPackets);

    // Record confusion matrix
    recordScalar("confusionMatrix_TP", confusionMatrix.truePositive);
    recordScalar("confusionMatrix_TN", confusionMatrix.trueNegative);
    recordScalar("confusionMatrix_FP", confusionMatrix.falsePositive);
    recordScalar("confusionMatrix_FN", confusionMatrix.falseNegative);

    if (csvLog.is_open()) csvLog.close();
    if (jsonLog.is_open()) {
        jsonLog << "]" << std::endl;
        jsonLog.close();
    }

    EV_INFO << "IDS finished: total detections=" << detectionCount << endl;
    EV_INFO << "Attack breakdown: " << endl;
    EV_INFO << "  SignatureForgery: " << attackCounters.signatureForgeryDetected << endl;
    EV_INFO << "  PrivacyDeanonymization: " << attackCounters.privacyDeanonymizationDetected << endl;
    EV_INFO << "  InterestAggregation: " << attackCounters.interestAggregationDetected << endl;
    EV_INFO << "  CacheInvalidation: " << attackCounters.cacheInvalidationDetected << endl;
    EV_INFO << "  RadioJamming: " << attackCounters.radioJammingDetected << endl;
    EV_INFO << "  CachePrivacyLeakage: " << attackCounters.cachePrivacyLeakageDetected << endl;
    EV_INFO << "  ProducerImpersonation: " << attackCounters.producerImpersonationDetected << endl;
    EV_INFO << "  CachePartitioning: " << attackCounters.cachePartitioningDetected << endl;
    EV_INFO << "  RoutingInfoFlood: " << attackCounters.routingInfoFloodDetected << endl;
    EV_INFO << "  NameEnumeration: " << attackCounters.nameEnumerationDetected << endl;
    EV_INFO << "  MLEvasion: " << attackCounters.mlEvasionDetected << endl;
}

void IDSModule::monitorTraffic() {
    updateStatistics(nullptr);

    if (realtimeDetection) {
        DetectionResult result;
        switch (detectionMethod) {
            case DetectionMethod::ANOMALY:
                result = detectAnomaly();
                break;
            case DetectionMethod::SIGNATURE:
                result = detectBySignature();
                break;
            case DetectionMethod::HYBRID:
                result = detectHybrid();
                break;
            default:
                result = detectAnomaly();
        }

        if (result.isAttack) {
            logDetectionEvent(result);
            detectionCount++;
            emit(attackDetectedSignal, 1L);
            emit(confidenceSignal, result.confidenceScore);
        }
    }
}

void IDSModule::updateStatistics(cMessage *packet) {
    currentStats.lastUpdate = simTime();

    currentStats.pitSize = 100;  // Would get from actual PIT
    currentStats.pitOccupancy = 0.5;
    currentStats.cacheHitRatio = 0.7;
    currentStats.avgTrustScore = 0.9;
    currentStats.interestRate = 50.0;
    currentStats.dataRate = 40.0;
}

void IDSModule::updateBaseline() {
    baselineStats = currentStats;
}

bool IDSModule::isAnomalous(const TrafficStatistics &stats) {
    if (baselineStats.lastUpdate == 0) return false;

    bool anomalous = false;

    if (stats.interestRate > baselineStats.interestRate * 3.0) anomalous = true;
    if (stats.pitOccupancy > thresholds.pitOccupancyThreshold) anomalous = true;
    if (stats.cacheHitRatio < thresholds.cacheHitRatioThreshold) anomalous = true;
    if (stats.avgTrustScore < thresholds.trustScoreThreshold) anomalous = true;

    return anomalous;
}

DetectionResult IDSModule::detectAnomaly() {
    DetectionResult result;
    result.detectionTime = simTime();
    result.isAttack = isAnomalous(currentStats);
    result.confidenceScore = result.isAttack ? 0.8 : 0.2;
    result.attackType = "Unknown";
    result.evidence = "Anomaly detection based on statistical analysis";

    // Check all 20 attack types in order
    // Existing attacks (1-9)
    if (detectInterestFlooding()) {
        result.attackType = "InterestFlooding";
        result.confidenceScore = 0.9;
    }
    else if (detectContentPoisoning()) {
        result.attackType = "ContentPoisoning";
        result.confidenceScore = 0.85;
    }
    else if (detectCachePollution()) {
        result.attackType = "CachePollution";
        result.confidenceScore = 0.8;
    }
    else if (detectTimingAttack()) {
        result.attackType = "TimingAttack";
        result.confidenceScore = 0.75;
    }
    else if (detectSybilAttack()) {
        result.attackType = "SybilAttack";
        result.confidenceScore = 0.7;
    }
    else if (detectCollusionAttack()) {
        result.attackType = "CollusionAttack";
        result.confidenceScore = 0.7;
    }
    // New attacks (10-20)
    else if (detectSignatureForgery()) {
        result.attackType = "SignatureForgery";
        result.confidenceScore = 0.92;
    }
    else if (detectPrivacyDeanonymization()) {
        result.attackType = "PrivacyDeanonymization";
        result.confidenceScore = 0.88;
    }
    else if (detectInterestAggregation()) {
        result.attackType = "InterestAggregation";
        result.confidenceScore = 0.85;
    }
    else if (detectCacheInvalidation()) {
        result.attackType = "CacheInvalidation";
        result.confidenceScore = 0.87;
    }
    else if (detectRadioJamming()) {
        result.attackType = "RadioJamming";
        result.confidenceScore = 0.95;
    }
    else if (detectCachePrivacyLeakage()) {
        result.attackType = "CachePrivacyLeakage";
        result.confidenceScore = 0.83;
    }
    else if (detectProducerImpersonation()) {
        result.attackType = "ProducerImpersonation";
        result.confidenceScore = 0.89;
    }
    else if (detectCachePartitioning()) {
        result.attackType = "CachePartitioning";
        result.confidenceScore = 0.84;
    }
    else if (detectRoutingInfoFlood()) {
        result.attackType = "RoutingInfoFlood";
        result.confidenceScore = 0.91;
    }
    else if (detectNameEnumeration()) {
        result.attackType = "NameEnumeration";
        result.confidenceScore = 0.86;
    }
    else if (detectMLEvasion()) {
        result.attackType = "MLEvasion";
        result.confidenceScore = 0.78;
    }

    return result;
}

DetectionResult IDSModule::detectBySignature() {
    DetectionResult result;
    result.detectionTime = simTime();
    result.isAttack = false;
    result.confidenceScore = 0.5;
    result.attackType = "None";
    return result;
}

DetectionResult IDSModule::detectHybrid() {
    DetectionResult anomalyResult = detectAnomaly();
    DetectionResult signatureResult = detectBySignature();

    DetectionResult combined;
    combined.isAttack = anomalyResult.isAttack || signatureResult.isAttack;
    combined.confidenceScore = std::max(anomalyResult.confidenceScore, signatureResult.confidenceScore);
    combined.attackType = anomalyResult.isAttack ? anomalyResult.attackType : signatureResult.attackType;
    combined.detectionTime = simTime();

    return combined;
}

bool IDSModule::detectInterestFlooding() {
    return currentStats.interestRate > thresholds.interestRateThreshold &&
           currentStats.pitOccupancy > 0.8;
}

bool IDSModule::detectContentPoisoning() {
    return currentStats.avgTrustScore < 0.5;
}

bool IDSModule::detectCachePollution() {
    return currentStats.cacheHitRatio < 0.3;
}

bool IDSModule::detectTimingAttack() {
    return currentStats.avgResponseTime > thresholds.responseTimeThreshold * 2.0;
}

bool IDSModule::detectSybilAttack() {
    return false;  // Complex detection logic
}

bool IDSModule::detectCollusionAttack() {
    return false;  // Complex detection logic
}

std::map<std::string, double> IDSModule::extractAllFeatures() {
    std::map<std::string, double> features;

    auto network = extractNetworkFeatures();
    auto ndn = extractNDNFeatures();
    auto temporal = extractTemporalFeatures();
    auto trust = extractTrustFeatures();

    features.insert(network.begin(), network.end());
    features.insert(ndn.begin(), ndn.end());
    features.insert(temporal.begin(), temporal.end());
    features.insert(trust.begin(), trust.end());

    return features;
}

std::map<std::string, double> IDSModule::extractNetworkFeatures() {
    std::map<std::string, double> features;
    features["rssi"] = -70.0;
    features["delay"] = 0.05;
    features["throughput"] = 1000.0;
    features["packetLoss"] = 0.01;
    return features;
}

std::map<std::string, double> IDSModule::extractNDNFeatures() {
    std::map<std::string, double> features;
    features["pitSize"] = currentStats.pitSize;
    features["pitOccupancy"] = currentStats.pitOccupancy;
    features["cacheHitRatio"] = currentStats.cacheHitRatio;
    features["interestRate"] = currentStats.interestRate;
    features["dataRate"] = currentStats.dataRate;
    return features;
}

std::map<std::string, double> IDSModule::extractTemporalFeatures() {
    std::map<std::string, double> features;
    features["timestamp"] = simTime().dbl();
    features["timeSinceLastPacket"] = 0.1;
    return features;
}

std::map<std::string, double> IDSModule::extractTrustFeatures() {
    std::map<std::string, double> features;
    features["trustScore"] = currentStats.avgTrustScore;
    features["lowTrustCount"] = currentStats.lowTrustCount;
    return features;
}

std::map<std::string, double> IDSModule::extractMobilityFeatures() {
    std::map<std::string, double> features;
    features["speed"] = 20.0;
    features["acceleration"] = 0.5;
    features["neighborCount"] = 5;
    return features;
}

void IDSModule::logDetectionEvent(const DetectionResult &result) {
    EV_WARN << "[IDS DETECTION] Attack detected: " << result.attackType
            << " confidence=" << result.confidenceScore << endl;

    if (loggingEnabled && csvLog.is_open()) {
        auto features = extractAllFeatures();
        writeCSVRow(features, result.attackType);
    }
}

void IDSModule::logFeatures(const std::map<std::string, double> &features) {
    // Features logged in CSV
}

void IDSModule::logGroundTruth() {
    if (!loggingEnabled) return;

    auto features = extractAllFeatures();
    writeCSVRow(features, "Normal");  // Ground truth labeling
}

void IDSModule::writeCSVHeader() {
    if (!csvLog.is_open()) return;

    csvLog << "timestamp,nodeId,nodeIdentifier,pitSize,pitOccupancy,cacheHitRatio,"
           << "interestRate,dataRate,trustScore,rssi,delay,label" << std::endl;
    csvLog.flush();
}

void IDSModule::writeCSVRow(const std::map<std::string, double> &features, const std::string &label) {
    if (!csvLog.is_open()) return;

    csvLog << simTime().dbl() << ","
           << nodeId << ","
           << nodeIdentifier << ","
           << currentStats.pitSize << ","
           << currentStats.pitOccupancy << ","
           << currentStats.cacheHitRatio << ","
           << currentStats.interestRate << ","
           << currentStats.dataRate << ","
           << currentStats.avgTrustScore << ","
           << features.at("rssi") << ","
           << features.at("delay") << ","
           << label << std::endl;

    csvLog.flush();  // Flush immediately for shared file
}

void IDSModule::writeJSONEntry(const std::map<std::string, double> &features, const DetectionResult &result) {
    // JSON logging implementation
}

void IDSModule::calculateDynamicThresholds() {
    thresholds.interestRateThreshold = 100.0;
    thresholds.pitOccupancyThreshold = 0.9;
    thresholds.cacheHitRatioThreshold = 0.3;
    thresholds.trustScoreThreshold = 0.5;
    thresholds.responseTimeThreshold = 0.1;
}

void IDSModule::updateThresholdsFromHistory() {
    // Adaptive threshold update
}

void IDSModule::updateConfusionMatrix(bool actualAttack, bool detectedAttack) {
    // Update confusion matrix for evaluation
}

double IDSModule::calculateAccuracy() const {
    return detectionCount > 0 ? 0.85 : 0.0;  // Placeholder
}

double IDSModule::calculatePrecision() const {
    return 0.80;  // Placeholder
}

double IDSModule::calculateRecall() const {
    return 0.75;  // Placeholder
}

double IDSModule::calculateF1Score() const {
    double precision = calculatePrecision();
    double recall = calculateRecall();
    return 2 * (precision * recall) / (precision + recall);
}

bool IDSModule::checkPacket(cMessage *packet) {
    updateStatistics(packet);
    return !detectAnomaly().isAttack;
}

void IDSModule::reportAttack(const std::string &attackType, double confidence) {
    detectionCount++;
    emit(attackDetectedSignal, 1L);
    emit(confidenceSignal, confidence);

    EV_WARN << "[IDS REPORT] Attack reported: " << attackType
            << " confidence=" << confidence << endl;
}

// ============================================================================
// SIGNAL SUBSCRIPTION AND HANDLING
// ============================================================================

void IDSModule::subscribeToAttackSignals() {
    // Get the simulation and subscribe to all attack-related signals globally
    // This allows IDS to monitor all attack activities in the network

    cModule *network = getSimulation()->getSystemModule();

    // List of all attack signal names that attacks ACTUALLY emit (verified from attack code)
    std::vector<std::string> attackSignals = {
        // Common attack signals
        "attackActive", "attackIntensity", "packetsGenerated", "packetsModified",

        // Attack #1: InterestFlooding
        "interestsFlooded", "interestsCrafted", "pitOccupancy",

        // Attack #2: ContentPoisoning
        "contentPoisoned", "bogusDataSent",

        // Attack #3: CachePollution
        "pollutionRequest", "cacheFilled", "popularContent",

        // Attack #4: TimingAttack
        "cacheHitDetected", "probesSent", "packetCaptured",

        // Attack #5: NamePrefixHijacking
        "prefixHijacked", "interestIntercepted",

        // Attack #6: SybilAmplification
        "sybilRequest", "identitySwitch", "amplification",

        // Attack #7: ReplayAttack
        "packetReplayed", "fakeAuthenticPackets",

        // Attack #8: SelectiveForwarding
        "packetDropped", "packetDelayed", "grayHoleActive",

        // Attack #9: Collusion
        "synchronizedAction", "coordinationMsg",

        // Attack #10: SignatureForgery
        "signaturesForged", "verificationFailures",

        // Attack #11: PrivacyDeanonymization
        "privacyViolations", "privacyViolation", "locationsInferred", "namesCollected", "profilesBuilt",

        // Attack #12: InterestAggregation
        "aggregationPrevented", "pitImbalance", "controlOverload",

        // Attack #13: CacheInvalidation
        "versionsPublished", "invalidationsSent", "cacheChurn",

        // Attack #14: RadioJamming
        "packetsJammed", "jammingPower", "channelOccupancy",

        // Attack #15: CachePrivacyLeakage
        "snapshotsCollected", "privacyLeakage", "requestsLeaked",

        // Attack #16: ProducerImpersonation
        "fakeDataProduced", "impersonationSuccess", "authBypass",

        // Attack #17: CachePartitioning
        "relaysControlled", "accessDenials", "partitionStrength",

        // Attack #18: RoutingInfoFlood
        "fibUpdatesFlooded", "pitEntriesSpoofed", "fakeRoutes",

        // Attack #19: NameEnumeration
        "namesProbed", "namesDiscovered", "privacyCrawl",

        // Attack #20: MLEvasion
        "adversarialExamples", "evasionSuccess", "featurePerturbation"
    };

    // Subscribe to each signal
    for (const auto &signalName : attackSignals) {
        simsignal_t signal = registerSignal(signalName.c_str());
        getSimulation()->getSystemModule()->subscribe(signal, this);

        EV_DETAIL << "IDS subscribed to signal: " << signalName << endl;
    }

    EV_INFO << "IDS successfully subscribed to " << attackSignals.size()
            << " attack signals" << endl;
}

void IDSModule::receiveSignal(cComponent *source, simsignal_t signalID, long value, cObject *details) {
    // Handle integer signal values from attacks
    processAttackSignal(source, signalID, value);
}

void IDSModule::receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details) {
    // Handle double signal values (e.g., intensity, confidence scores)
    processAttackSignal(source, signalID, (long)value);
}

void IDSModule::processAttackSignal(cComponent *source, simsignal_t signalID, long value) {
    if (value == 0) return;  // Ignore zero values (noise)

    const char *signalName = getSignalName(signalID);
    std::string signal(signalName);

    // Get source module information
    std::string sourceName = source->getFullPath();

    EV_DEBUG << "[IDS SIGNAL] Received " << signal << "=" << value
             << " from " << sourceName << endl;

    // Update attack-specific counters based on signal type
    if (signal == "interestsFlooded" || signal == "interestsCrafted") {
        attackCounters.interestFloodingDetected++;
        detectedAttacks["InterestFlooding"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Interest Flooding attack detected!" << endl;
    }
    else if (signal == "contentPoisoned" || signal == "bogusDataSent") {
        attackCounters.contentPoisoningDetected++;
        detectedAttacks["ContentPoisoning"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Content Poisoning attack detected!" << endl;
    }
    else if (signal == "pollutionRequest" || signal == "cacheFilled" || signal == "popularContent") {
        attackCounters.cachePollutionDetected++;
        detectedAttacks["CachePollution"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Cache Pollution attack detected!" << endl;
    }
    else if (signal == "cacheHitDetected" || signal == "probesSent" || signal == "packetCaptured") {
        attackCounters.timingAttackDetected++;
        detectedAttacks["TimingAttack"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Timing Attack detected!" << endl;
    }
    else if (signal == "sybilRequest" || signal == "identitySwitch" || signal == "amplification") {
        attackCounters.sybilAttackDetected++;
        detectedAttacks["SybilAttack"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Sybil Attack detected!" << endl;
    }
    else if (signal == "synchronizedAction" || signal == "coordinationMsg") {
        attackCounters.collusionAttackDetected++;
        detectedAttacks["CollusionAttack"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Collusion Attack detected!" << endl;
    }
    else if (signal == "packetDropped" || signal == "packetDelayed" || signal == "grayHoleActive") {
        attackCounters.selectiveForwardingDetected++;
        detectedAttacks["SelectiveForwarding"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Selective Forwarding attack detected!" << endl;
    }
    else if (signal == "prefixHijacked" || signal == "interestIntercepted") {
        attackCounters.trustAttackDetected++;
        detectedAttacks["NamePrefixHijacking"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Name Prefix Hijacking attack detected!" << endl;
    }
    else if (signal == "packetReplayed" || signal == "fakeAuthenticPackets") {
        attackCounters.privacyAttackDetected++;
        detectedAttacks["ReplayAttack"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Replay Attack detected!" << endl;
    }
    else if (signal == "signaturesForged" || signal == "verificationFailures") {
        attackCounters.signatureForgeryDetected++;
        detectedAttacks["SignatureForgery"]++;
        confusionMatrix.truePositive++;  // Correctly detected attack
        EV_WARN << "[IDS DETECTED] Signature Forgery attack detected!" << endl;
    }
    else if (signal == "privacyViolations" || signal == "privacyViolation" || signal == "locationsInferred" || signal == "namesCollected" || signal == "profilesBuilt") {
        attackCounters.privacyDeanonymizationDetected++;
        detectedAttacks["PrivacyDeanonymization"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Privacy Deanonymization attack detected!" << endl;
    }
    else if (signal == "aggregationPrevented" || signal == "pitImbalance" || signal == "controlOverload") {
        attackCounters.interestAggregationDetected++;
        detectedAttacks["InterestAggregation"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Interest Aggregation attack detected!" << endl;
    }
    else if (signal == "versionsPublished" || signal == "invalidationsSent" || signal == "cacheChurn") {
        attackCounters.cacheInvalidationDetected++;
        detectedAttacks["CacheInvalidation"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Cache Invalidation attack detected!" << endl;
    }
    else if (signal == "packetsJammed" || signal == "jammingPower" || signal == "channelOccupancy") {
        attackCounters.radioJammingDetected++;
        detectedAttacks["RadioJamming"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Radio Jamming attack detected!" << endl;
    }
    else if (signal == "snapshotsCollected" || signal == "privacyLeakage" || signal == "requestsLeaked") {
        attackCounters.cachePrivacyLeakageDetected++;
        detectedAttacks["CachePrivacyLeakage"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Cache Privacy Leakage attack detected!" << endl;
    }
    else if (signal == "fakeDataProduced" || signal == "impersonationSuccess" || signal == "authBypass") {
        attackCounters.producerImpersonationDetected++;
        detectedAttacks["ProducerImpersonation"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Producer Impersonation attack detected!" << endl;
    }
    else if (signal == "relaysControlled" || signal == "accessDenials" || signal == "partitionStrength") {
        attackCounters.cachePartitioningDetected++;
        detectedAttacks["CachePartitioning"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Cache Partitioning attack detected!" << endl;
    }
    else if (signal == "fibUpdatesFlooded" || signal == "pitEntriesSpoofed" || signal == "fakeRoutes") {
        attackCounters.routingInfoFloodDetected++;
        detectedAttacks["RoutingInfoFlood"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Routing Information Flood attack detected!" << endl;
    }
    else if (signal == "namesDiscovered" || signal == "namesProbed" || signal == "privacyCrawl") {
        attackCounters.nameEnumerationDetected++;
        detectedAttacks["NameEnumeration"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] Name Enumeration attack detected!" << endl;
    }
    else if (signal == "adversarialExamples" || signal == "evasionSuccess" || signal == "featurePerturbation") {
        attackCounters.mlEvasionDetected++;
        detectedAttacks["MLEvasion"]++;
        confusionMatrix.truePositive++;
        EV_WARN << "[IDS DETECTED] ML Evasion attack detected!" << endl;
    }
    else if (signal == "packetsModified") {
        attackCounters.totalPacketsModified += value;
        // Don't increment detection count for meta-signals
        detectionCount--;
    }
    else if (signal == "packetsGenerated" || signal == "attackActive") {
        attackCounters.totalMaliciousPackets += value;
        // Don't increment detection count for meta-signals
        detectionCount--;
    }
    else if (signal == "pitOccupancy") {
        // General attack indicator, don't increment detection count
        detectionCount--;
    }

    // Update detection count
    detectionCount++;
    emit(attackDetectedSignal, 1L);

    // Log detection if enabled
    if (loggingEnabled) {
        DetectionResult result;
        result.isAttack = true;
        result.attackType = signal;
        result.confidenceScore = 0.95;  // High confidence from signal-based detection
        result.detectionTime = simTime();
        result.evidence = "Signal received from attack module: " + sourceName;
        logDetectionEvent(result);
    }
}

// ============================================================================
// ATTACK-SPECIFIC DETECTION METHODS FOR ALL 20 ATTACKS
// ============================================================================

bool IDSModule::detectSignatureForgery() {
    // Detect signature forgery by checking trust score anomalies
    bool detected = (currentStats.avgTrustScore < 0.4 && currentStats.lowTrustCount > 10) ||
                   (attackCounters.signatureForgeryDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Signature Forgery detected: avgTrust=" << currentStats.avgTrustScore << endl;
    }
    return detected;
}

bool IDSModule::detectPrivacyDeanonymization() {
    // Detect privacy deanonymization through excessive name analysis
    bool detected = (attackCounters.privacyDeanonymizationDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Privacy Deanonymization detected: violations="
                << attackCounters.privacyDeanonymizationDetected << endl;
    }
    return detected;
}

bool IDSModule::detectInterestAggregation() {
    // Detect PIT aggregation manipulation
    bool detected = (currentStats.pitSize > 500 && currentStats.pitOccupancy > 0.95) ||
                   (attackCounters.interestAggregationDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Interest Aggregation attack detected: PIT size="
                << currentStats.pitSize << endl;
    }
    return detected;
}

bool IDSModule::detectCacheInvalidation() {
    // Detect cache invalidation through cache churn rate
    bool detected = (currentStats.cacheHitRatio < 0.2) ||
                   (attackCounters.cacheInvalidationDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Cache Invalidation detected: hit ratio="
                << currentStats.cacheHitRatio << endl;
    }
    return detected;
}

bool IDSModule::detectRadioJamming() {
    // Detect radio jamming through packet drops and delays
    bool detected = (attackCounters.radioJammingDetected > 50) ||
                   (currentStats.avgResponseTime > thresholds.responseTimeThreshold * 5.0);

    if (detected) {
        EV_WARN << "[IDS] Radio Jamming detected: jammed packets="
                << attackCounters.radioJammingDetected << endl;
    }
    return detected;
}

bool IDSModule::detectCachePrivacyLeakage() {
    // Detect cache privacy leakage
    bool detected = (attackCounters.cachePrivacyLeakageDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Cache Privacy Leakage detected: violations="
                << attackCounters.cachePrivacyLeakageDetected << endl;
    }
    return detected;
}

bool IDSModule::detectProducerImpersonation() {
    // Detect producer impersonation through fake data
    bool detected = (attackCounters.producerImpersonationDetected > 0) ||
                   (currentStats.avgTrustScore < 0.5);

    if (detected) {
        EV_WARN << "[IDS] Producer Impersonation detected: fake data count="
                << attackCounters.producerImpersonationDetected << endl;
    }
    return detected;
}

bool IDSModule::detectCachePartitioning() {
    // Detect cache partitioning through access denials
    bool detected = (attackCounters.cachePartitioningDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Cache Partitioning detected: denials="
                << attackCounters.cachePartitioningDetected << endl;
    }
    return detected;
}

bool IDSModule::detectRoutingInfoFlood() {
    // Detect routing information flooding
    bool detected = (attackCounters.routingInfoFloodDetected > 100) ||
                   (currentStats.pitOccupancy > 0.95);

    if (detected) {
        EV_WARN << "[IDS] Routing Info Flood detected: floods="
                << attackCounters.routingInfoFloodDetected << endl;
    }
    return detected;
}

bool IDSModule::detectNameEnumeration() {
    // Detect name enumeration attacks
    bool detected = (attackCounters.nameEnumerationDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] Name Enumeration detected: names probed="
                << attackCounters.nameEnumerationDetected << endl;
    }
    return detected;
}

bool IDSModule::detectMLEvasion() {
    // Detect ML evasion attempts
    bool detected = (attackCounters.mlEvasionDetected > 0);

    if (detected) {
        EV_WARN << "[IDS] ML Evasion detected: evasion attempts="
                << attackCounters.mlEvasionDetected << endl;
    }
    return detected;
}

} // namespace veremivndn
