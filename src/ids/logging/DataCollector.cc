//
// VeReMiVNDN - IDS Data Collector Implementation
//

#include "DataCollector.h"
#include <sstream>
#include <iomanip>
#include <ctime>

namespace veremivndn {

Define_Module(DataCollector);

DataCollector::DataCollector()
    : collectionTimer(nullptr),
      exportTimer(nullptr),
      featureExtractor(nullptr),
      recordsCollected(0),
      recordsExported(0)
{
}

DataCollector::~DataCollector()
{
    cancelAndDelete(collectionTimer);
    cancelAndDelete(exportTimer);

    // Close all file handles
    if (csvFile.is_open()) csvFile.close();
    if (jsonFile.is_open()) jsonFile.close();
    if (arffFile.is_open()) arffFile.close();
    if (metadataFile.is_open()) metadataFile.close();
}

void DataCollector::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0) {
        // Configuration
        std::string formatStr = par("outputFormat").stringValue();
        if (formatStr == "csv") outputFormat = DatasetFormat::CSV;
        else if (formatStr == "json") outputFormat = DatasetFormat::JSON;
        else if (formatStr == "arff") outputFormat = DatasetFormat::ARFF;
        else outputFormat = DatasetFormat::CSV;

        outputDirectory = par("outputDirectory").stringValue();
        datasetName = par("datasetName").stringValue();
        realtimeExport = par("realtimeExport").boolValue();
        bufferSize = par("bufferSize").intValue();
        includeHeader = par("includeHeader").boolValue();
        normalizeFeatures = par("normalizeFeatures").boolValue();

        collectionInterval = par("collectionInterval").doubleValue();
        exportInterval = par("exportInterval").doubleValue();

        // Initialize feature names
        initializeFeatureNames();

        // Create timers
        collectionTimer = new cMessage("collectionTimer");
        exportTimer = new cMessage("exportTimer");

        // Register signals
        dataCollectedSignal = registerSignal("dataCollected");
        dataExportedSignal = registerSignal("dataExported");

        // Open output files
        std::stringstream filename;
        filename << outputDirectory << "/" << datasetName;

        if (outputFormat == DatasetFormat::CSV) {
            filename << ".csv";
            csvFile.open(filename.str(), std::ios::out);
            if (csvFile.is_open() && includeHeader) {
                writeCSVHeader(csvFile);
            }
        }
        else if (outputFormat == DatasetFormat::JSON) {
            filename << ".json";
            jsonFile.open(filename.str(), std::ios::out);
            if (jsonFile.is_open()) {
                jsonFile << "[\n";  // Start JSON array
            }
        }
        else if (outputFormat == DatasetFormat::ARFF) {
            filename << ".arff";
            arffFile.open(filename.str(), std::ios::out);
            if (arffFile.is_open()) {
                writeARFFHeader(arffFile);
            }
        }

        // Open metadata file
        std::string metaFilename = outputDirectory + "/" + datasetName + "_metadata.txt";
        metadataFile.open(metaFilename, std::ios::out);

        // Schedule collection
        scheduleAt(simTime() + collectionInterval, collectionTimer);
        if (!realtimeExport) {
            scheduleAt(simTime() + exportInterval, exportTimer);
        }

        EV_INFO << "DataCollector initialized: format=" << formatStr
                << " output=" << filename.str() << endl;
    }
    else if (stage == 2) {
        // Find FeatureExtractor module
        cModule *parent = getParentModule();
        featureExtractor = dynamic_cast<FeatureExtractor*>(
            parent->getSubmodule("featureExtractor"));

        if (!featureExtractor) {
            EV_WARN << "FeatureExtractor module not found!" << endl;
        }
    }
}

void DataCollector::handleMessage(cMessage *msg)
{
    if (msg == collectionTimer) {
        collectData();
        scheduleAt(simTime() + collectionInterval, collectionTimer);
    }
    else if (msg == exportTimer) {
        exportBuffer();
        scheduleAt(simTime() + exportInterval, exportTimer);
    }
}

void DataCollector::collectData()
{
    if (!featureExtractor) {
        EV_WARN << "Cannot collect data: FeatureExtractor not available" << endl;
        return;
    }

    // Create record
    DatasetRecord record = createRecord();

    // Validate record
    if (!isValidRecord(record)) {
        EV_WARN << "Invalid record, skipping..." << endl;
        return;
    }

    // Add to buffer or export immediately
    if (realtimeExport) {
        // Export immediately
        if (outputFormat == DatasetFormat::CSV && csvFile.is_open()) {
            writeCSVRow(csvFile, record);
            csvFile.flush();
        }
        else if (outputFormat == DatasetFormat::JSON && jsonFile.is_open()) {
            if (recordsCollected > 0) jsonFile << ",\n";
            writeJSONRecord(jsonFile, record);
            jsonFile.flush();
        }

        recordsExported++;
    }
    else {
        // Buffer for later export
        dataBuffer.push_back(record);

        // Export if buffer is full
        if (dataBuffer.size() >= bufferSize) {
            exportBuffer();
        }
    }

    recordsCollected++;
    emit(dataCollectedSignal, 1L);

    // Update attack counts
    attackCounts[record.label.attackType]++;

    EV_DETAIL << "Collected record #" << recordsCollected
              << " label=" << record.label.attackType << endl;
}

DatasetRecord DataCollector::createRecord()
{
    DatasetRecord record;

    // Get feature vector
    record.features = featureExtractor->getCurrentFeatures();

    // Get ground truth label
    record.label = getCurrentLabel(record.features.nodeId);

    return record;
}

GroundTruthLabel DataCollector::getCurrentLabel(int nodeId)
{
    // Check if we have a current label for this node
    if (currentLabels.find(nodeId) != currentLabels.end()) {
        return currentLabels[nodeId];
    }

    // Default: benign traffic
    GroundTruthLabel label;
    label.timestamp = simTime();
    label.nodeId = nodeId;
    label.attackType = "Benign";
    label.isAttack = false;
    label.attackIntensity = 0.0;
    label.severity = 0.0;
    label.attackLayer = "None";

    return label;
}

void DataCollector::setGroundTruth(int nodeId, const std::string &attackType, double intensity)
{
    GroundTruthLabel label;
    label.timestamp = simTime();
    label.nodeId = nodeId;
    label.attackType = attackType;
    label.isAttack = (attackType != "Benign");
    label.attackIntensity = intensity;

    // Determine severity based on attack type
    if (attackType == "InterestFlooding" || attackType == "RadioJamming") {
        label.severity = 0.9;  // High
        label.attackLayer = "Network";
    }
    else if (attackType == "ContentPoisoning" || attackType == "SignatureForgery") {
        label.severity = 0.95;  // Critical
        label.attackLayer = "Data";
    }
    else if (attackType == "CachePollution" || attackType == "CacheTimingAttack") {
        label.severity = 0.6;  // Medium
        label.attackLayer = "Caching";
    }
    else if (attackType == "NamePrefixHijacking" || attackType == "RoutingInfoFlood") {
        label.severity = 0.8;  // High
        label.attackLayer = "Network";
    }
    else if (attackType == "SybilAmplification" || attackType == "Collusion") {
        label.severity = 0.85;  // High
        label.attackLayer = "Trust";
    }
    else if (attackType == "SelectiveForwarding") {
        label.severity = 0.7;  // Medium-High
        label.attackLayer = "CrossLayer";
    }
    else if (attackType == "PrivacyDeanonymization" || attackType == "NameEnumeration") {
        label.severity = 0.75;  // Medium-High
        label.attackLayer = "Privacy";
    }
    else if (attackType == "InterestAggregation" || attackType == "CacheInvalidation") {
        label.severity = 0.65;  // Medium
        label.attackLayer = "Network";
    }
    else if (attackType == "CachePrivacyLeakage" || attackType == "CachePartitioning") {
        label.severity = 0.7;  // Medium-High
        label.attackLayer = "Caching";
    }
    else if (attackType == "ProducerImpersonation") {
        label.severity = 0.9;  // High
        label.attackLayer = "Data";
    }
    else if (attackType == "MLEvasion") {
        label.severity = 0.95;  // Critical
        label.attackLayer = "CrossLayer";
    }
    else if (attackType == "ReplayAttack") {
        label.severity = 0.8;  // High
        label.attackLayer = "Data";
    }
    else {
        label.severity = 0.5;  // Medium
        label.attackLayer = "Other";
    }

    currentLabels[nodeId] = label;

    EV_DETAIL << "Updated ground truth for node " << nodeId
              << ": " << attackType << " (intensity=" << intensity << ")" << endl;
}

void DataCollector::updateGroundTruth(int nodeId, const std::string &attackType, double intensity)
{
    setGroundTruth(nodeId, attackType, intensity);
}

void DataCollector::addRecord(const FeatureVector &features, const GroundTruthLabel &label)
{
    DatasetRecord record;
    record.features = features;
    record.label = label;

    if (isValidRecord(record)) {
        dataBuffer.push_back(record);
        recordsCollected++;
        emit(dataCollectedSignal, 1L);
    }
}

// ============================================================================
// CSV EXPORT
// ============================================================================

void DataCollector::writeCSVHeader(std::ofstream &file)
{
    // Write feature names
    for (size_t i = 0; i < featureNames.size(); i++) {
        file << featureNames[i];
        if (i < featureNames.size() - 1) file << ",";
    }

    // Write label columns
    file << ",timestamp,nodeId,attackType,isAttack,attackIntensity,severity,attackLayer\n";
}

void DataCollector::writeCSVRow(std::ofstream &file, const DatasetRecord &record)
{
    // Write features
    file << featureVectorToCSV(record.features);

    // Write label
    file << "," << labelToCSV(record.label) << "\n";
}

std::string DataCollector::featureVectorToCSV(const FeatureVector &fv)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6);

    // Network features
    oss << fv.interestRate << "," << fv.dataRate << ","
        << fv.avgInterestSize << "," << fv.avgDataSize << ","
        << fv.packetDropRate << "," << fv.avgHopCount << ","
        << fv.interestDataRatio << "," << fv.nackRate << ","
        << fv.avgRTT << "," << fv.jitter << ",";

    // NDN features
    oss << fv.pitOccupancy << "," << fv.pitSize << ","
        << fv.avgPitLifetime << "," << fv.pitSatisfactionRate << ","
        << fv.fibSize << "," << fv.avgFibEntryHopCount << ","
        << fv.csOccupancy << "," << fv.csSize << ","
        << fv.cacheHitRatio << "," << fv.cacheMissRatio << ","
        << fv.avgCacheEntryAge << "," << fv.contentStoreDiversity << ","
        << fv.pendingInterestDiversity << "," << fv.faceUtilization << ","
        << fv.avgForwardingDelay << ",";

    // Trust features
    oss << fv.avgTrustScore << "," << fv.minTrustScore << ","
        << fv.maxTrustScore << "," << fv.trustVariance << ","
        << fv.signatureVerificationRate << "," << fv.signatureFailureRate << ","
        << fv.unsignedDataRatio << "," << fv.lowTrustPacketRatio << ",";

    // Temporal features
    oss << fv.interestRateVariance << "," << fv.burstiness << ","
        << fv.periodicity << "," << fv.trendSlope << ","
        << fv.interArrivalTimeMean << "," << fv.interArrivalTimeStdDev << ","
        << fv.windowInterestCount << "," << fv.windowDataCount << ","
        << fv.shortTermInterestRate << "," << fv.longTermInterestRate << ",";

    // Privacy features
    oss << fv.nameEntropy << "," << fv.uniqueNamesRatio << ","
        << fv.repeatedNonceRatio << "," << fv.locationExposureRisk << ","
        << fv.anonymityScore << ",";

    // Mobility features
    oss << fv.speed << "," << fv.acceleration << ","
        << fv.direction << "," << fv.positionX << ","
        << fv.positionY << "," << fv.neighborCount << ",";

    // Attack indicators
    oss << fv.interestFloodingScore << "," << fv.poisoningScore << ","
        << fv.cachePollutionScore << "," << fv.timingAttackScore << ","
        << fv.replayScore << "," << fv.sybilScore << ","
        << fv.collusionScore << "," << fv.hijackingScore << ","
        << fv.grayHoleScore << "," << fv.jammingScore << ",";

    // Statistical features
    oss << fv.totalPackets << "," << fv.totalBytes << ","
        << fv.avgPacketSize << "," << fv.packetSizeVariance << ","
        << fv.trafficEntropy;

    return oss.str();
}

std::string DataCollector::labelToCSV(const GroundTruthLabel &label)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6);

    oss << label.timestamp.dbl() << ","
        << label.nodeId << ","
        << label.attackType << ","
        << (label.isAttack ? 1 : 0) << ","
        << label.attackIntensity << ","
        << label.severity << ","
        << label.attackLayer;

    return oss.str();
}

// ============================================================================
// JSON EXPORT
// ============================================================================

void DataCollector::writeJSONRecord(std::ofstream &file, const DatasetRecord &record)
{
    file << "{\n";
    file << "  \"features\": " << featureVectorToJSON(record.features) << ",\n";
    file << "  \"label\": " << labelToJSON(record.label) << "\n";
    file << "}";
}

std::string DataCollector::featureVectorToJSON(const FeatureVector &fv)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6);

    oss << "{\n";
    oss << "    \"interestRate\": " << fv.interestRate << ",\n";
    oss << "    \"dataRate\": " << fv.dataRate << ",\n";
    oss << "    \"pitOccupancy\": " << fv.pitOccupancy << ",\n";
    oss << "    \"cacheHitRatio\": " << fv.cacheHitRatio << ",\n";
    oss << "    \"avgTrustScore\": " << fv.avgTrustScore << ",\n";
    oss << "    \"burstiness\": " << fv.burstiness << ",\n";
    oss << "    \"interestFloodingScore\": " << fv.interestFloodingScore << ",\n";
    oss << "    \"poisoningScore\": " << fv.poisoningScore << ",\n";
    oss << "    \"grayHoleScore\": " << fv.grayHoleScore << "\n";
    oss << "  }";

    return oss.str();
}

std::string DataCollector::labelToJSON(const GroundTruthLabel &label)
{
    std::ostringstream oss;

    oss << "{\n";
    oss << "    \"timestamp\": " << label.timestamp.dbl() << ",\n";
    oss << "    \"nodeId\": " << label.nodeId << ",\n";
    oss << "    \"attackType\": \"" << label.attackType << "\",\n";
    oss << "    \"isAttack\": " << (label.isAttack ? "true" : "false") << ",\n";
    oss << "    \"attackIntensity\": " << label.attackIntensity << ",\n";
    oss << "    \"severity\": " << label.severity << ",\n";
    oss << "    \"attackLayer\": \"" << label.attackLayer << "\"\n";
    oss << "  }";

    return oss.str();
}

// ============================================================================
// ARFF EXPORT
// ============================================================================

void DataCollector::writeARFFHeader(std::ofstream &file)
{
    file << "@RELATION vndn_attack_detection\n\n";

    // Write feature attributes
    for (const auto &name : featureNames) {
        file << "@ATTRIBUTE " << name << " NUMERIC\n";
    }

    // Write label attributes
    file << "@ATTRIBUTE timestamp NUMERIC\n";
    file << "@ATTRIBUTE nodeId NUMERIC\n";
    file << "@ATTRIBUTE attackType {Benign,InterestFlooding,ContentPoisoning,CachePollution,"
         << "CacheTimingAttack,NamePrefixHijacking,SybilAmplification,ReplayAttack,"
         << "SelectiveForwarding,Collusion,SignatureForgery,NameDeanonymization,"
         << "InterestAggregation,CacheInvalidation,RadioJamming,ContentPrivacyLeakage,"
         << "ProducerImpersonation,CachePartitioning,RoutingInfoFlood,NameEnumeration,"
         << "MLEvasion}\n";
    file << "@ATTRIBUTE isAttack {0,1}\n";

    file << "\n@DATA\n";
}

void DataCollector::writeARFFData(std::ofstream &file, const DatasetRecord &record)
{
    file << featureVectorToCSV(record.features) << ","
         << labelToCSV(record.label) << "\n";
}

// ============================================================================
// HELPER METHODS
// ============================================================================

void DataCollector::initializeFeatureNames()
{
    // Network features (10)
    featureNames.push_back("interestRate");
    featureNames.push_back("dataRate");
    featureNames.push_back("avgInterestSize");
    featureNames.push_back("avgDataSize");
    featureNames.push_back("packetDropRate");
    featureNames.push_back("avgHopCount");
    featureNames.push_back("interestDataRatio");
    featureNames.push_back("nackRate");
    featureNames.push_back("avgRTT");
    featureNames.push_back("jitter");

    // NDN features (15)
    featureNames.push_back("pitOccupancy");
    featureNames.push_back("pitSize");
    featureNames.push_back("avgPitLifetime");
    featureNames.push_back("pitSatisfactionRate");
    featureNames.push_back("fibSize");
    featureNames.push_back("avgFibEntryHopCount");
    featureNames.push_back("csOccupancy");
    featureNames.push_back("csSize");
    featureNames.push_back("cacheHitRatio");
    featureNames.push_back("cacheMissRatio");
    featureNames.push_back("avgCacheEntryAge");
    featureNames.push_back("contentStoreDiversity");
    featureNames.push_back("pendingInterestDiversity");
    featureNames.push_back("faceUtilization");
    featureNames.push_back("avgForwardingDelay");

    // Trust features (8)
    featureNames.push_back("avgTrustScore");
    featureNames.push_back("minTrustScore");
    featureNames.push_back("maxTrustScore");
    featureNames.push_back("trustVariance");
    featureNames.push_back("signatureVerificationRate");
    featureNames.push_back("signatureFailureRate");
    featureNames.push_back("unsignedDataRatio");
    featureNames.push_back("lowTrustPacketRatio");

    // Temporal features (10)
    featureNames.push_back("interestRateVariance");
    featureNames.push_back("burstiness");
    featureNames.push_back("periodicity");
    featureNames.push_back("trendSlope");
    featureNames.push_back("interArrivalTimeMean");
    featureNames.push_back("interArrivalTimeStdDev");
    featureNames.push_back("windowInterestCount");
    featureNames.push_back("windowDataCount");
    featureNames.push_back("shortTermInterestRate");
    featureNames.push_back("longTermInterestRate");

    // Privacy features (5)
    featureNames.push_back("nameEntropy");
    featureNames.push_back("uniqueNamesRatio");
    featureNames.push_back("repeatedNonceRatio");
    featureNames.push_back("locationExposureRisk");
    featureNames.push_back("anonymityScore");

    // Mobility features (6)
    featureNames.push_back("speed");
    featureNames.push_back("acceleration");
    featureNames.push_back("direction");
    featureNames.push_back("positionX");
    featureNames.push_back("positionY");
    featureNames.push_back("neighborCount");

    // Attack indicators (10)
    featureNames.push_back("interestFloodingScore");
    featureNames.push_back("poisoningScore");
    featureNames.push_back("cachePollutionScore");
    featureNames.push_back("timingAttackScore");
    featureNames.push_back("replayScore");
    featureNames.push_back("sybilScore");
    featureNames.push_back("collusionScore");
    featureNames.push_back("hijackingScore");
    featureNames.push_back("grayHoleScore");
    featureNames.push_back("jammingScore");

    // Statistical features (5)
    featureNames.push_back("totalPackets");
    featureNames.push_back("totalBytes");
    featureNames.push_back("avgPacketSize");
    featureNames.push_back("packetSizeVariance");
    featureNames.push_back("trafficEntropy");
}

bool DataCollector::isValidRecord(const DatasetRecord &record)
{
    // Check for NaN or infinite values
    if (std::isnan(record.features.interestRate) || std::isinf(record.features.interestRate)) {
        return false;
    }

    // Check timestamp validity
    if (record.label.timestamp < 0) {
        return false;
    }

    return true;
}

void DataCollector::exportBuffer()
{
    if (dataBuffer.empty()) return;

    EV_INFO << "Exporting " << dataBuffer.size() << " records..." << endl;

    for (const auto &record : dataBuffer) {
        if (outputFormat == DatasetFormat::CSV && csvFile.is_open()) {
            writeCSVRow(csvFile, record);
        }
        else if (outputFormat == DatasetFormat::JSON && jsonFile.is_open()) {
            if (recordsExported > 0) jsonFile << ",\n";
            writeJSONRecord(jsonFile, record);
        }
        else if (outputFormat == DatasetFormat::ARFF && arffFile.is_open()) {
            writeARFFData(arffFile, record);
        }

        recordsExported++;
    }

    dataBuffer.clear();

    emit(dataExportedSignal, (long)recordsExported);
}

void DataCollector::exportDataset()
{
    exportBuffer();

    // Write metadata
    writeMetadata();
}

void DataCollector::writeMetadata()
{
    if (!metadataFile.is_open()) return;

    metadataFile << "VeReMiVNDN Attack Detection Dataset\n";
    metadataFile << "===================================\n\n";
    metadataFile << "Generated: " << simTime() << "\n";
    metadataFile << "Records Collected: " << recordsCollected << "\n";
    metadataFile << "Records Exported: " << recordsExported << "\n";
    metadataFile << "Features: " << featureNames.size() << "\n\n";

    metadataFile << "Attack Type Distribution:\n";
    for (const auto &entry : attackCounts) {
        metadataFile << "  " << entry.first << ": " << entry.second << "\n";
    }

    metadataFile.flush();
}

void DataCollector::finish()
{
    cSimpleModule::finish();

    // Export remaining buffer
    exportBuffer();

    // Finalize files
    if (jsonFile.is_open()) {
        jsonFile << "\n]\n";
        jsonFile.close();
    }

    if (csvFile.is_open()) {
        csvFile.close();
    }

    if (arffFile.is_open()) {
        arffFile.close();
    }

    // Write final metadata
    writeMetadata();
    if (metadataFile.is_open()) {
        metadataFile.close();
    }

    // Record statistics
    recordScalar("recordsCollected", recordsCollected);
    recordScalar("recordsExported", recordsExported);
    recordScalar("uniqueAttackTypes", (long)attackCounts.size());

    EV_INFO << "DataCollector finished: "
            << recordsCollected << " records collected, "
            << recordsExported << " records exported" << endl;
}

} // namespace veremivndn
