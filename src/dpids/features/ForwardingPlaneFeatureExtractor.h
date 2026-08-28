//
// DP-IDS-VNDN - Forwarding-Plane Feature Extraction (Methodology Section 4.2)
// Computes: CS Hit-Rate Drift, PIT Entry Growth Rate, FIB Route Divergence
//

#ifndef __VEREMIVNDN_FORWARDINGPLANEFEATUREEXTRACTOR_H
#define __VEREMIVNDN_FORWARDINGPLANEFEATUREEXTRACTOR_H

#include <omnetpp.h>
#include <map>
#include <deque>
#include <string>
#include <vector>

using namespace omnetpp;

namespace veremivndn {

class CS;
class PIT;
class FIB;

struct ForwardingFeatureVector {
    double csHitRateDrift;      // Delta_CS(v,t) normalised [0,1]
    double pitEntryGrowthRate;  // P_dot(v,t) normalised [0,1]
    double fibRouteDivergence;  // D_FIB(v,t) normalised [0,1]
    bool pitAnomalyFlag;        // P_dot > mean + k*stddev (Section 4.2.2)
    simtime_t timestamp;
    std::string vehicleId;
};

class ForwardingPlaneFeatureExtractor : public cSimpleModule
{
private:
    double extractionInterval;
    double ewmaAlpha;
    int minSamples;
    double csHitDriftMax;
    double pitGrowthRateMax;
    double fibDivergenceMax;
    double communicationRange;
    double pitThresholdK;  // k for PIT anomaly threshold (default 2.0)

    cMessage *extractionTimer;

    // Per-vehicle CS insertion tracking
    std::map<std::string, double> csHitRateBaseline;  // EWMA of insertion rate
    std::map<std::string, int> csHitRateSampleCount;
    std::map<std::string, int> csInsertionBaseline;   // Previous insertion count
    std::map<std::string, simtime_t> csInsertionTimestamp;

    // Per-vehicle PIT size history for finite difference
    std::map<std::string, int> previousPitSize;
    std::map<std::string, simtime_t> previousPitTimestamp;

    // Per-vehicle PIT growth rate history for anomaly flag (mean + k*stddev)
    std::map<std::string, std::deque<double>> pitGrowthHistory;
    static const int MAX_GROWTH_HISTORY = 50;

    // Results
    std::map<std::string, ForwardingFeatureVector> latestFeatures;

    // Signals
    simsignal_t csHitRateDriftSignal;
    simsignal_t pitEntryGrowthRateSignal;
    simsignal_t fibRouteDivergenceSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void extractFeatures();
    double computeCSAnomaly(const std::string &vehicleId, CS *cs);
    double computePITOccupancy(const std::string &vehicleId, PIT *pit);
    double computeDropScore(const std::string &vehicleId, cModule *vehicleMod);
    double computeCSHitRateDrift(const std::string &vehicleId, CS *cs);
    double computePITGrowthRate(const std::string &vehicleId, PIT *pit);
    double computeFIBDivergence(const std::string &vehicleId, FIB *vehicleFib);
    double normalizeMinMax(double value, double maxVal);

    CS* getCSForVehicle(cModule *vehicleMod);
    PIT* getPITForVehicle(cModule *vehicleMod);
    FIB* getFIBForVehicle(cModule *vehicleMod);
    std::vector<cModule*> getVehiclesInRange();

public:
    ForwardingPlaneFeatureExtractor() : extractionTimer(nullptr) {}
    virtual ~ForwardingPlaneFeatureExtractor();

    ForwardingFeatureVector getFeatures(const std::string &vehicleId) const;
    bool hasFeatures(const std::string &vehicleId) const;
    const std::map<std::string, ForwardingFeatureVector>& getAllFeatures() const { return latestFeatures; }
};

} // namespace veremivndn
#endif
