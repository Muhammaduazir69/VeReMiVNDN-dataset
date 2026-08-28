//
// DP-IDS-VNDN - Dempster-Shafer Evidence Fusion (Methodology Section 4.4)
// Combines behavioural and forwarding-plane detector evidence via orthogonal sum
//

#ifndef __VEREMIVNDN_DSFUSIONENGINE_H
#define __VEREMIVNDN_DSFUSIONENGINE_H

#include <omnetpp.h>
#include <map>
#include <string>
#include <algorithm>
#include <cmath>

using namespace omnetpp;

namespace veremivndn {

struct MassFunction {
    double m_mal;
    double m_ben;
    double m_theta;

    MassFunction() : m_mal(0.0), m_ben(0.0), m_theta(1.0) {}
    MassFunction(double mal, double ben, double theta)
        : m_mal(mal), m_ben(ben), m_theta(theta) {}

    bool isValid() const {
        double sum = m_mal + m_ben + m_theta;
        return (sum > 0.999 && sum < 1.001) && m_mal >= 0 && m_ben >= 0 && m_theta >= 0;
    }
};

struct FusionResult {
    MassFunction fused;
    double beliefMal;
    double beliefBen;
    double conflict;
    bool extendedMonitoring;
    std::string vehicleId;
    simtime_t timestamp;
};

class DSFusionEngine : public cSimpleModule
{
private:
    double kMax;
    double reliabilityBehavioural;
    double reliabilityForwarding;

    std::map<std::string, FusionResult> fusionResults;

    simsignal_t fusionBeliefMalSignal;
    simsignal_t fusionConflictSignal;
    simsignal_t extendedMonitoringSignal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    int fusionCount = 0;
    double lastMaxBelief = 0.0;

public:
    DSFusionEngine() {}
    virtual ~DSFusionEngine() {}

    // Core DS operations
    double computeAdaptiveReliability(double score, double baseReliability);
    MassFunction scoreToMass(double anomalyScore, double reliability);
    MassFunction orthogonalSum(const MassFunction &m1, const MassFunction &m2,
                               double &conflictK);
    FusionResult fuse(const std::string &vehicleId,
                      double behaviouralScore, double forwardingScore);

    // Access
    FusionResult getFusionResult(const std::string &vehicleId) const;
    bool hasFusionResult(const std::string &vehicleId) const;
    double getBeliefMalicious(const std::string &vehicleId) const;
    const std::map<std::string, FusionResult>& getAllResults() const { return fusionResults; }
};

} // namespace veremivndn
#endif
