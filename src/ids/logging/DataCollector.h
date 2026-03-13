//
// VeReMiVNDN - IDS Data Collector Module
//
// Collects features and ground truth labels for ML dataset generation
//

#ifndef __VEREMIVNDN_DATACOLLECTOR_H
#define __VEREMIVNDN_DATACOLLECTOR_H

#include <omnetpp.h>
// #include "inet/common/INETDefs.h"  // Removed INET dependency
#include "../features/FeatureExtractor.h"
#include <fstream>
#include <string>
#include <vector>
#include <map>

using namespace omnetpp;

namespace veremivndn {

/**
 * Dataset Format
 */
enum class DatasetFormat {
    CSV,            // Comma-separated values
    JSON,           // JSON format
    ARFF,           // WEKA ARFF format
    LIBSVM,         // LibSVM format
    NUMPY           // NumPy binary format
};

/**
 * Ground Truth Label
 */
struct GroundTruthLabel {
    simtime_t timestamp;
    int nodeId;
    std::string attackType;      // "Benign" or attack name
    bool isAttack;
    double attackIntensity;
    double severity;             // 0.0 - 1.0
    std::string attackLayer;     // Network, Data, Caching, etc.
};

/**
 * Dataset Record - Feature vector + label
 */
struct DatasetRecord {
    FeatureVector features;
    GroundTruthLabel label;
};

/**
 * DataCollector
 *
 * Responsible for:
 * - Collecting feature vectors from FeatureExtractor
 * - Obtaining ground truth labels from attack modules
 * - Formatting and exporting ML-ready datasets
 * - Managing data buffering and periodic export
 * - Ensuring dataset quality and consistency
 */
class DataCollector : public cSimpleModule
{
private:
    // Configuration
    DatasetFormat outputFormat;
    std::string outputDirectory;
    std::string datasetName;
    bool realtimeExport;
    int bufferSize;
    bool includeHeader;
    bool normalizeFeatures;

    // File handles
    std::ofstream csvFile;
    std::ofstream jsonFile;
    std::ofstream arffFile;
    std::ofstream metadataFile;

    // Data buffer
    std::vector<DatasetRecord> dataBuffer;
    uint64_t recordsCollected;
    uint64_t recordsExported;

    // Feature extractor reference
    FeatureExtractor *featureExtractor;

    // Ground truth tracking
    std::map<int, GroundTruthLabel> currentLabels;  // nodeId -> label
    std::map<std::string, uint64_t> attackCounts;   // Attack type counts

    // Timers
    cMessage *collectionTimer;
    cMessage *exportTimer;
    simtime_t collectionInterval;
    simtime_t exportInterval;

    // Statistics
    simsignal_t dataCollectedSignal;
    simsignal_t dataExportedSignal;

    // Feature names (for CSV header)
    std::vector<std::string> featureNames;

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Data collection
    void collectData();
    void collectFeatureVector();
    void collectGroundTruthLabel();
    DatasetRecord createRecord();

    // Ground truth management
    void updateGroundTruth(int nodeId, const std::string &attackType, double intensity);
    GroundTruthLabel getCurrentLabel(int nodeId);
    void queryAttackModules();

    // Export functions
    void exportBuffer();
    void exportToCSV();
    void exportToJSON();
    void exportToARFF();
    void flushBuffer();

    // CSV operations
    void writeCSVHeader(std::ofstream &file);
    void writeCSVRow(std::ofstream &file, const DatasetRecord &record);
    std::string featureVectorToCSV(const FeatureVector &fv);
    std::string labelToCSV(const GroundTruthLabel &label);

    // JSON operations
    void writeJSONRecord(std::ofstream &file, const DatasetRecord &record);
    std::string featureVectorToJSON(const FeatureVector &fv);
    std::string labelToJSON(const GroundTruthLabel &label);

    // ARFF operations
    void writeARFFHeader(std::ofstream &file);
    void writeARFFData(std::ofstream &file, const DatasetRecord &record);

    // Feature name initialization
    void initializeFeatureNames();

    // Data quality checks
    bool isValidRecord(const DatasetRecord &record);
    void validateDataset();

    // Metadata generation
    void writeMetadata();
    void writeDatasetStatistics();

public:
    DataCollector();
    virtual ~DataCollector();

    // Public interface
    void addRecord(const FeatureVector &features, const GroundTruthLabel &label);
    void setGroundTruth(int nodeId, const std::string &attackType, double intensity);
    void exportDataset();
    uint64_t getRecordCount() const { return recordsCollected; }
};

} // namespace veremivndn

#endif // __VEREMIVNDN_DATACOLLECTOR_H
