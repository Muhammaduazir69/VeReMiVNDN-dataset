//
// DP-IDS-VNDN - Security-Aware Adaptive Forwarding Strategy (Section 4.5)
// Proportional penalisation of CS freshness, PIT timeout, FIB weight
//

#ifndef __VEREMIVNDN_ADAPTIVEFORWARDINGSTRATEGY_H
#define __VEREMIVNDN_ADAPTIVEFORWARDINGSTRATEGY_H

#include <omnetpp.h>
#include <map>
#include <string>

using namespace omnetpp;

namespace veremivndn {

class CS;
class PIT;
class FIB;
class DSFusionEngine;

class AdaptiveForwardingStrategy : public cSimpleModule
{
private:
    double thetaCS;
    double thetaPIT;
    double thetaFIB;

    simsignal_t csPenalizationSignal;
    simsignal_t pitPenalizationSignal;
    simsignal_t fibPenalizationSignal;
    simsignal_t vehiclePenalizedSignal;

    int totalCSPenalizations;
    int totalPITPenalizations;
    int totalFIBPenalizations;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

public:
    AdaptiveForwardingStrategy()
        : totalCSPenalizations(0), totalPITPenalizations(0), totalFIBPenalizations(0) {}

    void applyPenalization(cModule *vehicleMod, const std::string &vehicleId,
                           double beliefMal);

    // ---- TRIDENT: graduated + reversible mitigation driven by trust T_v ----
    // Lower trust => stronger CS/PIT/FIB penalties (severity = 1 - T_v). Applied
    // unconditionally (the quarantine decision is taken by the TridentController).
    void applyTrustMitigation(cModule *vehicleMod, const std::string &vehicleId,
                              double trust);
    // Undo the FIB penalisation on reinstatement (graceful, reversible).
    void restorePenalization(cModule *vehicleMod, const std::string &vehicleId);

private:
    void penalizeCS(cModule *vehicleMod, const std::string &vehicleId, double bel);
    void penalizePIT(cModule *vehicleMod, const std::string &vehicleId, double bel);
    void penalizeFIB(cModule *vehicleMod, const std::string &vehicleId, double bel);
};

} // namespace veremivndn
#endif
