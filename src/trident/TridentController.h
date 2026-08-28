//
// TRIDENT-VNDN - Closed-loop trust controller (header)
//
#ifndef __VEREMIVNDN_TRIDENTCONTROLLER_H
#define __VEREMIVNDN_TRIDENTCONTROLLER_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <string>

using namespace omnetpp;

namespace veremivndn {

class ForwardingPlaneFeatureExtractor;
class BehaviouralDetector;
class ForwardingPlaneDetector;
class DSFusionEngine;
class AdaptiveForwardingStrategy;
class TrustRegistry;

// Per-vehicle trust state owned by this controller.
struct TrustState {
    double    trust        = 1.0;   // T_v(t)
    double    belief       = 0.0;   // last Bel_v(t)
    bool      quarantined  = false;
    simtime_t lowTrustSince = -1;   // start of contiguous T_v < tauQuarantine window
    bool      everQuarantined = false;
    long      quarantineCount = 0;
    long      reinstateCount  = 0;
    simtime_t firstQuarantineAt = -1;
};

class TridentController : public cSimpleModule
{
  public:
    TridentController() {}
    virtual ~TridentController();

  protected:
    virtual void initialize(int stage) override;
    virtual int  numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    void controlStep();              // one Euler tick over all monitored vehicles
    void collectGroundTruth();       // mark which vehicles currently run an attack
    double readBelief(const std::string &vid, cModule *vehMod);
    void applyMitigation(cModule *vehMod, const std::string &vid, const TrustState &st);
    void restoreMitigation(cModule *vehMod, const std::string &vid);
    void updateVehicleVisual(cModule *vehMod, const std::string &vid, const TrustState &st);

  private:
    // Config
    simtime_t controlInterval;
    double alpha, beta;
    double tauQuarantine, tauReinstate;
    simtime_t windowQuarantine;
    bool enableMitigation;

    // Wiring (resolved in stage 2)
    ForwardingPlaneFeatureExtractor *featureExtractor = nullptr;
    BehaviouralDetector             *behaviouralDetector = nullptr;
    ForwardingPlaneDetector         *forwardingDetector = nullptr;
    DSFusionEngine                  *fusionEngine = nullptr;
    AdaptiveForwardingStrategy      *strategy = nullptr;
    TrustRegistry                   *registry = nullptr;

    cMessage *controlTimer = nullptr;

    // State
    std::map<std::string, TrustState> states;
    std::set<std::string> knownAttackers;   // ground truth this cycle
    std::set<std::string> everAttacked;     // persistent ground truth

    // Aggregate counters (for live display + paper metrics)
    int currentQuarantined = 0;
    double minTrustThisCycle = 1.0;
    int collateralIsolated = 0;   // benign nodes currently quarantined (false isolation)

    // Signals
    simsignal_t trustMinSig = -1;
    simsignal_t activeQuarantinesSig = -1;
    simsignal_t collateralIsolatedSig = -1;
};

} // namespace veremivndn

#endif
