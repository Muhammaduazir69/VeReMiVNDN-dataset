//
// TRIDENT-VNDN - Global Trust Registry (implementation)
//
#include "TrustRegistry.h"

namespace veremivndn {

Define_Module(TrustRegistry);

TrustRegistry *TrustRegistry::get(cModule *anyModule)
{
    if (!anyModule) return nullptr;
    cModule *sys = anyModule->getSimulation()->getSystemModule();
    if (!sys) return nullptr;
    cModule *reg = sys->getSubmodule("trustRegistry");
    return dynamic_cast<TrustRegistry *>(reg);
}

void TrustRegistry::initialize()
{
    tauQuarantine = par("tauQuarantine");
    tauReinstate  = par("tauReinstate");
    activeQuarantinesSig = registerSignal("activeQuarantines");
    WATCH(quarantineEvents);
    WATCH(reinstateEvents);
    EV_INFO << "TrustRegistry online (tauQ=" << tauQuarantine
            << ", tauR=" << tauReinstate << ")" << endl;
}

double TrustRegistry::getTrust(const std::string &vid) const
{
    auto it = trust.find(vid);
    return (it == trust.end()) ? 1.0 : it->second;
}

bool TrustRegistry::isQuarantined(const std::string &vid) const
{
    return quarantined.find(vid) != quarantined.end();
}

void TrustRegistry::setTrust(const std::string &vid, double t)
{
    if (t < 0.0) t = 0.0;
    if (t > 1.0) t = 1.0;
    trust[vid] = t;
}

void TrustRegistry::setQuarantined(const std::string &vid, bool q)
{
    bool was = isQuarantined(vid);
    if (q && !was) {
        quarantined.insert(vid);
        quarantineEvents++;
        emit(activeQuarantinesSig, (long)quarantined.size());
        EV_WARN << "TRIDENT: QUARANTINE " << vid
                << " (T=" << getTrust(vid) << ")" << endl;
    }
    else if (!q && was) {
        quarantined.erase(vid);
        reinstateEvents++;
        emit(activeQuarantinesSig, (long)quarantined.size());
        EV_WARN << "TRIDENT: REINSTATE  " << vid
                << " (T=" << getTrust(vid) << ")" << endl;
    }
}

void TrustRegistry::recordObservation(const std::string &vid, bool poison)
{
    if (vid.empty()) return;
    obsTotal[vid]++;
    if (poison) obsPoison[vid]++;
}

double TrustRegistry::observedBelief(const std::string &vid) const
{
    auto it = obsTotal.find(vid);
    if (it == obsTotal.end() || it->second < 3) return 0.0;  // need a few samples
    auto pit = obsPoison.find(vid);
    long poison = (pit == obsPoison.end()) ? 0 : pit->second;
    return (double)poison / (double)it->second;
}

void TrustRegistry::refreshDisplay() const
{
    char buf[96];
    snprintf(buf, sizeof(buf), "TrustRegistry\nquarantined: %d\nevents Q/R: %ld/%ld",
             (int)quarantined.size(), quarantineEvents, reinstateEvents);
    getDisplayString().setTagArg("tt", 0, buf);
    char t[48];
    snprintf(t, sizeof(t), "Q:%d", (int)quarantined.size());
    getDisplayString().setTagArg("t", 0, t);
}

void TrustRegistry::finish()
{
    recordScalar("totalQuarantineEvents", quarantineEvents);
    recordScalar("totalReinstateEvents",  reinstateEvents);
    recordScalar("quarantinedAtEnd",      (long)quarantined.size());
}

} // namespace veremivndn
