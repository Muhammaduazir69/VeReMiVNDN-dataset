//
// DP-IDS-VNDN - Forwarding-Plane Detector (Methodology Section 4.3.2)
// Isolation Forest scoring on phi(v,t) = [Delta_CS, P_dot, D_FIB]
// Uses SimplifiedIsolationForest for pure C++ inference
//

#ifndef __VEREMIVNDN_FORWARDINGPLANEDETECTOR_H
#define __VEREMIVNDN_FORWARDINGPLANEDETECTOR_H

#include <omnetpp.h>
#include <map>
#include <string>
#include "../features/ForwardingPlaneFeatureExtractor.h"
#include "SimplifiedIsolationForest.h"

using namespace omnetpp;

namespace veremivndn {

class ForwardingPlaneDetector : public cSimpleModule
{
private:
    double detectionInterval;
    double csHitDriftThreshold;
    double pitGrowthThreshold;
    double fibDivergenceThreshold;

    // Isolation Forest model (Section 4.3.2)
    SimplifiedIsolationForest iforest;
    int numTrees;
    int sampleSize;
    std::string modelPath;
    bool useIsolationForest;  // true if IF initialized successfully

    cMessage *detectionTimer;
    simsignal_t forwardingScoreSignal;
    simsignal_t forwardingDetectionSignal;

    std::map<std::string, double> scores;
    ForwardingPlaneFeatureExtractor *featureExtractor;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void detectAnomalies();
    double computeIsolationScore(const ForwardingFeatureVector &fv);
    double computeThresholdScore(const ForwardingFeatureVector &fv);

public:
    ForwardingPlaneDetector() : detectionTimer(nullptr), featureExtractor(nullptr),
        useIsolationForest(false), numTrees(100), sampleSize(256) {}
    virtual ~ForwardingPlaneDetector();

    double getScore(const std::string &vehicleId) const;
    bool hasScore(const std::string &vehicleId) const;
};

} // namespace veremivndn
#endif
