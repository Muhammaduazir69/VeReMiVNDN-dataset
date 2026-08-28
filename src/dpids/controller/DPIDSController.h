//
// DP-IDS-VNDN - Main Controller (Methodology Section 4.1)
// Orchestrates: telemetry -> detection -> fusion -> penalisation -> metrics
//

#ifndef __VEREMIVNDN_DPIDSCONTROLLER_H
#define __VEREMIVNDN_DPIDSCONTROLLER_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <vector>
#include <string>

using namespace omnetpp;

namespace veremivndn {

class ForwardingPlaneFeatureExtractor;
class BehaviouralDetector;
class ForwardingPlaneDetector;
class DSFusionEngine;
class AdaptiveForwardingStrategy;
class DPIDSMetrics;

class DPIDSController : public cSimpleModule
{
private:
    double orchestrationInterval;
    double beliefThreshold;
    bool enablePenalization;
    bool enableExtendedMonitoring;
    double extendedMonitoringDuration;

    cMessage *orchestrationTimer;

    // Sibling submodule references
    ForwardingPlaneFeatureExtractor *featureExtractor;
    BehaviouralDetector *behaviouralDetector;
    ForwardingPlaneDetector *forwardingDetector;
    DSFusionEngine *fusionEngine;
    AdaptiveForwardingStrategy *strategy;
    DPIDSMetrics *metrics;

    // Extended monitoring state
    std::map<std::string, simtime_t> extendedMonitoringExpiry;

    // Ground truth tracking
    std::set<std::string> knownAttackers;       // Vehicles with CURRENTLY active attacks
    std::set<std::string> everAttacked;         // Vehicles that EVER had an active attack
    std::set<std::string> detectedVehicles;     // Currently flagged as malicious
    std::map<std::string, double> vehicleBeliefs; // Latest belief per vehicle (for ROC)

    // Statistics
    int totalDetections;
    int totalPenalizations;
    int currentMonitored;
    int currentDetected;
    double maxBeliefThisCycle;

    simsignal_t vehiclesMonitoredSignal;
    simsignal_t vehiclesDetectedSignal;
    simsignal_t vehiclesPenalizedSignal;

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    void orchestrate();
    void collectGroundTruth();
    void updateVehicleVisuals();
    void initCanvasDashboard();
    void updateCanvasDashboard();
    void drawPacketFlowLines();

    // Canvas dashboard figures
    // Canvas anchor of the dashboard panel, in playground units. Configurable so
    // the panel can be parked in free space instead of covering an RSU icon.
    double dashX = 50;
    double dashY = 50;
    cRectangleFigure *dashPanel = nullptr;
    cTextFigure *dashTitle = nullptr;
    cTextFigure *dashStats = nullptr;
    cRectangleFigure *threatBar = nullptr;
    cRectangleFigure *threatBarBg = nullptr;
    cTextFigure *threatLabel = nullptr;
    // DS belief pie chart
    cPieSliceFigure *beliefSlice = nullptr;
    cPieSliceFigure *disbeliefSlice = nullptr;
    cPieSliceFigure *uncertaintySlice = nullptr;
    cTextFigure *pieLabel = nullptr;
    // Packet flow lines (reused each cycle)
    std::vector<cLineFigure*> flowLines;
    std::vector<cLineFigure*> attackLines;

public:
    DPIDSController() : orchestrationTimer(nullptr), featureExtractor(nullptr),
        behaviouralDetector(nullptr), forwardingDetector(nullptr),
        fusionEngine(nullptr), strategy(nullptr), metrics(nullptr),
        enableExtendedMonitoring(true), extendedMonitoringDuration(10.0),
        totalDetections(0), totalPenalizations(0),
        currentMonitored(0), currentDetected(0), maxBeliefThisCycle(0.0) {}
    virtual ~DPIDSController();
};

} // namespace veremivndn
#endif
