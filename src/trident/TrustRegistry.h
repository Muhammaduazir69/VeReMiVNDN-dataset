//
// TRIDENT-VNDN - Global Trust Registry (header)
//
#ifndef __VEREMIVNDN_TRUSTREGISTRY_H
#define __VEREMIVNDN_TRUSTREGISTRY_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <string>

using namespace omnetpp;

namespace veremivndn {

//
// Network-wide trust blackboard. Keys are vehicle module full names
// (e.g. "vehicle[5]") so that the control plane (TridentController, which
// iterates submodules) and the data plane (VehicleController, which stamps the
// sender module name onto every broadcast frame) agree on identity.
//
class TrustRegistry : public cSimpleModule
{
  public:
    TrustRegistry() {}
    virtual ~TrustRegistry() {}

    // Convenience locator: returns the single network instance, or nullptr.
    static TrustRegistry *get(cModule *anyModule);

    // --- Reads (data plane, must be cheap and const-correct) ---
    double getTrust(const std::string &vid) const;     // default 1.0 (fully trusted)
    bool   isQuarantined(const std::string &vid) const;
    int    numQuarantined() const { return (int)quarantined.size(); }

    // --- Writes (control plane) ---
    void setTrust(const std::string &vid, double t);
    void setQuarantined(const std::string &vid, bool q);

    // Aggregate bookkeeping for the paper's collateral-isolation metric.
    long getTotalQuarantineEvents() const { return quarantineEvents; }
    long getTotalReinstateEvents() const { return reinstateEvents; }

    // --- Detector-agnostic evidence: observed content-integrity anomalies ---
    // Honest nodes serve signed Data; an attacker serves poisoned (invalid) Data.
    // Consumers report each Data they receive; the malicious-belief Bel(v) is the
    // observed fraction of invalid replies attributed to sender v.
    void recordObservation(const std::string &vid, bool poison);
    double observedBelief(const std::string &vid) const;

  protected:
    virtual void initialize() override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

  private:
    double tauQuarantine = 0.40;
    double tauReinstate  = 0.55;

    std::map<std::string, double> trust;   // vid -> T_v(t)
    std::set<std::string>         quarantined;
    std::map<std::string, long>   obsTotal;   // replies attributed to vid
    std::map<std::string, long>   obsPoison;  // of which, invalid (poisoned)

    long quarantineEvents = 0;   // total ACTIVE -> QUARANTINED transitions
    long reinstateEvents  = 0;   // total QUARANTINED -> ACTIVE transitions

    simsignal_t activeQuarantinesSig = -1;
};

} // namespace veremivndn

#endif
