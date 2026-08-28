//
// DP-IDS-VNDN - Behavioural Plane Detector (Methodology Section 4.3.1)
// 4-layer LSTM on VeReMi 6-feature set: pos-x, pos-y, spd-x, spd-y, IDR, TTL
// Uses SimplifiedLSTM for pure C++ inference (no LibTorch required)
// Subscribes to NDNProcessor signals for IDR/TTL tracking
//

#ifndef __VEREMIVNDN_BEHAVIOURALDETECTOR_H
#define __VEREMIVNDN_BEHAVIOURALDETECTOR_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <deque>
#include <string>
#include <vector>
#include "SimplifiedLSTM.h"

using namespace omnetpp;

namespace veremivndn {

class BehaviouralDetector : public cSimpleModule, public cListener
{
private:
    double detectionInterval;
    double posDeviationThreshold;
    double speedDeviationThreshold;
    double idrThreshold;
    double communicationRange;

    // LSTM model (Section 4.3.1: 4-layer LSTM)
    SimplifiedLSTM lstmModel;
    int lstmInputDim;     // 6 features
    int lstmHiddenDim;    // 64 units
    int lstmNumLayers;    // 4 layers
    int lstmSeqLength;    // temporal window
    std::string modelPath;
    bool useLSTM;         // true if LSTM loaded successfully

    cMessage *detectionTimer;
    simsignal_t behaviouralScoreSignal;

    // Per-vehicle behavioural profile (VeReMi 6-feature tracking)
    struct VehicleProfile {
        // Position tracking
        double avgPosX = 0.0, avgPosY = 0.0;
        double lastPosX = 0.0, lastPosY = 0.0;
        // Speed component tracking (spd-x, spd-y separately per VeReMi)
        double avgSpdX = 0.0, avgSpdY = 0.0;
        double lastSpdX = 0.0, lastSpdY = 0.0;
        // IDR tracking (Interest-to-Data Ratio)
        int interestCount = 0;
        int dataCount = 0;
        double avgIDR = 1.0;
        // TTL variability tracking
        std::deque<int> ttlHistory;
        double avgTTL = 0.0;
        double ttlVariance = 0.0;
        // LSTM temporal sequence buffer
        std::deque<std::vector<double>> featureSequence;
        // General
        int sampleCount = 0;
        simtime_t lastUpdate = 0;
    };
    std::map<std::string, VehicleProfile> profiles;
    std::map<std::string, double> scores;
    std::set<int> subscribedVehicles;  // Track which vehicle indices we've subscribed to

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // cListener interface for NDNProcessor signal subscription
    virtual void receiveSignal(cComponent *source, simsignal_t signalID,
                               cObject *obj, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID,
                               long value, cObject *details) override;

    void detectAnomalies();
    double computeScore(const std::string &vehicleId, cModule *vehicleMod);
    double computeScoreLSTM(const std::string &vehicleId, VehicleProfile &profile);
    double computeScoreThreshold(const std::string &vehicleId, VehicleProfile &profile,
                                  double posX, double posY, double dt);
    double computeIDR(VehicleProfile &profile);
    double computeTTLVariability(VehicleProfile &profile);
    std::vector<cModule*> getVehiclesInRange();
    void subscribeToNDNSignals();

public:
    BehaviouralDetector() : detectionTimer(nullptr), useLSTM(false) {}
    virtual ~BehaviouralDetector();

    double getScore(const std::string &vehicleId) const;
    bool hasScore(const std::string &vehicleId) const;

    // External API for feeding IDR/TTL observations
    void recordInterest(const std::string &vehicleId);
    void recordData(const std::string &vehicleId);
    void recordTTL(const std::string &vehicleId, int ttl);
};

} // namespace veremivndn
#endif
