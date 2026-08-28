//
// TRIDENT-VNDN - Closed-loop trust controller (implementation)
//
#include "TridentController.h"
#include "TrustRegistry.h"
#include "../dpids/features/ForwardingPlaneFeatureExtractor.h"
#include "../dpids/detectors/BehaviouralDetector.h"
#include "../dpids/detectors/ForwardingPlaneDetector.h"
#include "../dpids/fusion/DSFusionEngine.h"
#include "../dpids/strategy/AdaptiveForwardingStrategy.h"
#include "../attacks/AttackBase.h"
#include <algorithm>

namespace veremivndn {

Define_Module(TridentController);

TridentController::~TridentController()
{
    cancelAndDelete(controlTimer);
}

void TridentController::initialize(int stage)
{
    if (stage == 0) {
        controlInterval   = par("controlInterval");
        alpha             = par("alpha");
        beta              = par("beta");
        tauQuarantine     = par("tauQuarantine");
        tauReinstate      = par("tauReinstate");
        windowQuarantine  = par("windowQuarantine");
        enableMitigation  = par("enableMitigation");

        trustMinSig           = registerSignal("trustMin");
        activeQuarantinesSig  = registerSignal("activeQuarantines");
        collateralIsolatedSig = registerSignal("collateralIsolated");

        WATCH(currentQuarantined);
        WATCH(minTrustThisCycle);
        WATCH(collateralIsolated);
    }
    else if (stage == 2) {
        cModule *parent = getParentModule();
        featureExtractor   = dynamic_cast<ForwardingPlaneFeatureExtractor*>(parent->getSubmodule("fpFeatureExtractor"));
        behaviouralDetector= dynamic_cast<BehaviouralDetector*>(parent->getSubmodule("behaviouralDetector"));
        forwardingDetector = dynamic_cast<ForwardingPlaneDetector*>(parent->getSubmodule("forwardingDetector"));
        fusionEngine       = dynamic_cast<DSFusionEngine*>(parent->getSubmodule("fusionEngine"));
        strategy           = dynamic_cast<AdaptiveForwardingStrategy*>(parent->getSubmodule("adaptiveStrategy"));
        registry           = TrustRegistry::get(this);

        if (!fusionEngine)
            EV_WARN << "TridentController: DSFusionEngine not found (need hasDPIDSModule=true)" << endl;
        if (!registry)
            EV_WARN << "TridentController: TrustRegistry not found in network!" << endl;

        controlTimer = new cMessage("tridentControl");
        scheduleAt(simTime() + controlInterval, controlTimer);

        EV_INFO << "TridentController online: alpha=" << alpha << " beta=" << beta
                << " tauQ=" << tauQuarantine << " tauR=" << tauReinstate
                << " Wq=" << windowQuarantine << " mitigation=" << enableMitigation << endl;
    }
}

void TridentController::handleMessage(cMessage *msg)
{
    if (msg == controlTimer) {
        controlStep();
        scheduleAt(simTime() + controlInterval, controlTimer);
    } else {
        delete msg;
    }
}

void TridentController::collectGroundTruth()
{
    knownAttackers.clear();
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;
        cModule *attackMod = mod->getSubmodule("attackModule");
        if (attackMod) {
            AttackBase *attack = dynamic_cast<AttackBase*>(attackMod);
            if (attack && attack->isAttackActive()) {
                std::string name = mod->getFullName();
                knownAttackers.insert(name);
                everAttacked.insert(name);
            }
        }
    }
}

double TridentController::readBelief(const std::string &vid, cModule * /*vehMod*/)
{
    // Detector-agnostic: TRIDENT consumes whatever malicious-belief stream is
    // available. Here the primary evidence is the observed content-integrity
    // anomaly rate (fraction of poisoned replies attributed to vid), fused with
    // the DP-IDS behavioural/forwarding detector scores when present.
    // The primary, ground-truthed evidence is the observed content-integrity
    // anomaly rate per sender (fraction of invalid Data attributed to vid),
    // which is zero for honest consumers (they never serve Data) and ~1 for an
    // active poisoner. The DP-IDS behavioural/forwarding detectors are consulted
    // ONLY as a weak secondary signal once vid has actually served content, so
    // an uncalibrated detector cannot quarantine a benign node that has emitted
    // no Data at all (which previously caused ~94% collateral isolation).
    double obs = registry ? registry->observedBelief(vid) : 0.0;
    if (obs <= 0.0)
        return 0.0;   // no observed malicious content from vid -> fully trusted
    double s1 = behaviouralDetector ? behaviouralDetector->getScore(vid) : 0.0;
    double s2 = forwardingDetector  ? forwardingDetector->getScore(vid)  : 0.0;
    double det = 0.0;
    if (fusionEngine) det = fusionEngine->fuse(vid, s1, s2).beliefMal;
    else det = std::max(s1, s2);
    return std::max(obs, det);
}

void TridentController::controlStep()
{
    collectGroundTruth();

    // Build vehicle module cache (indices are non-contiguous under SUMO churn).
    std::map<std::string, cModule*> vehicleCache;
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;
        vehicleCache[mod->getFullName()] = mod;
    }

    const double dt = controlInterval.dbl();
    minTrustThisCycle = 1.0;
    currentQuarantined = 0;
    collateralIsolated = 0;

    for (const auto &pair : vehicleCache) {
        const std::string &vid = pair.first;
        cModule *vehMod = pair.second;

        TrustState &st = states[vid];   // default trust 1.0 on first sight
        st.belief = readBelief(vid, vehMod);

        // ---- Forward-Euler trust ODE: dT = (-alpha*Bel + beta*(1-T)) dt ----
        double dT = (-alpha * st.belief + beta * (1.0 - st.trust)) * dt;
        st.trust += dT;
        if (st.trust < 0.0) st.trust = 0.0;
        if (st.trust > 1.0) st.trust = 1.0;

        // ---- Hysteresis quarantine state machine (reversible) ----
        if (st.trust < tauQuarantine) {
            if (st.lowTrustSince < SimTime::ZERO) st.lowTrustSince = simTime();
        } else {
            st.lowTrustSince = -1;   // trust recovered above the floor, reset dwell
        }

        if (!st.quarantined) {
            bool dwellMet = (st.lowTrustSince >= SimTime::ZERO) &&
                            (simTime() - st.lowTrustSince >= windowQuarantine);
            if (dwellMet) {
                st.quarantined = true;
                st.everQuarantined = true;
                st.quarantineCount++;
                if (st.firstQuarantineAt < SimTime::ZERO) st.firstQuarantineAt = simTime();
                if (registry) registry->setQuarantined(vid, true);
                if (vehMod) applyMitigation(vehMod, vid, st);
            }
        }
        else {
            // Already quarantined: leave only when trust climbs past the upper edge.
            if (st.trust >= tauReinstate) {
                st.quarantined = false;
                st.reinstateCount++;
                st.lowTrustSince = -1;
                if (registry) registry->setQuarantined(vid, false);
                if (vehMod) restoreMitigation(vehMod, vid);
            } else if (vehMod) {
                applyMitigation(vehMod, vid, st);   // keep graduated prongs fresh
            }
        }

        // Publish continuous trust to the data-plane blackboard every tick.
        if (registry) registry->setTrust(vid, st.trust);

        if (st.quarantined) {
            currentQuarantined++;
            if (everAttacked.find(vid) == everAttacked.end())
                collateralIsolated++;   // benign node currently isolated => collateral
        }
        if (st.trust < minTrustThisCycle) minTrustThisCycle = st.trust;

        if (vehMod) updateVehicleVisual(vehMod, vid, st);
    }

    emit(trustMinSig, minTrustThisCycle);
    emit(activeQuarantinesSig, (long)currentQuarantined);
    emit(collateralIsolatedSig, (long)collateralIsolated);
}

void TridentController::applyMitigation(cModule *vehMod, const std::string &vid,
                                        const TrustState &st)
{
    if (!enableMitigation || !strategy) return;
    // Graduated, reversible: lower trust => stronger CS/PIT/FIB penalties.
    strategy->applyTrustMitigation(vehMod, vid, st.trust);
}

void TridentController::restoreMitigation(cModule *vehMod, const std::string &vid)
{
    if (!strategy) return;
    strategy->restorePenalization(vehMod, vid);
}

void TridentController::updateVehicleVisual(cModule *vehMod, const std::string &vid,
                                            const TrustState &st)
{
    auto &ds = vehMod->getDisplayString();
    bool attacker = (everAttacked.find(vid) != everAttacked.end());
    if (st.quarantined) {
        ds.setTagArg("i", 1, attacker ? "red" : "orange");
        ds.setTagArg("t", 0, attacker ? "QUARANTINED" : "ISO(FP)");
        ds.setTagArg("t", 2, attacker ? "red" : "orange");
    } else if (st.trust < tauReinstate) {
        ds.setTagArg("i", 1, "#cccc00");   // amber: under suspicion / recovering
        ds.setTagArg("t", 0, "");
    } else {
        ds.setTagArg("i", 1, "green");
        ds.setTagArg("t", 0, "");
    }
    char tt[200];
    snprintf(tt, sizeof(tt), "%s\nT=%.3f Bel=%.3f\n%s%s",
             vid.c_str(), st.trust, st.belief,
             st.quarantined ? "QUARANTINED" : "active",
             attacker ? " [attacker]" : "");
    ds.setTagArg("tt", 0, tt);
}

void TridentController::refreshDisplay() const
{
    cModule *rsu = getParentModule();
    if (!rsu) return;
    char label[96];
    snprintf(label, sizeof(label), "TRIDENT Q:%d minT:%.2f", currentQuarantined, minTrustThisCycle);
    rsu->getDisplayString().setTagArg("t", 0, label);
    rsu->getDisplayString().setTagArg("t", 2, currentQuarantined > 0 ? "#cc6600" : "#006600");
}

void TridentController::finish()
{
    long totalQ = 0, totalR = 0, attackersQ = 0, benignQ = 0;
    int attackers = 0, benign = 0;
    double sumAttackerTrust = 0, sumBenignTrust = 0;
    simtime_t sumIsoLatency = 0; int isoLatencySamples = 0;

    for (const auto &kv : states) {
        const std::string &vid = kv.first;
        const TrustState &st = kv.second;
        bool attacker = (everAttacked.find(vid) != everAttacked.end());
        totalQ += st.quarantineCount;
        totalR += st.reinstateCount;
        if (attacker) {
            attackers++;
            sumAttackerTrust += st.trust;
            if (st.everQuarantined) {
                attackersQ++;
                if (st.firstQuarantineAt >= SimTime::ZERO)
                    { sumIsoLatency += st.firstQuarantineAt; isoLatencySamples++; }
            }
        } else {
            benign++;
            sumBenignTrust += st.trust;
            if (st.everQuarantined) benignQ++;
        }
    }

    recordScalar("totalQuarantineEvents", totalQ);
    recordScalar("totalReinstateEvents",  totalR);
    recordScalar("attackersMonitored",    attackers);
    recordScalar("benignMonitored",       benign);
    recordScalar("attackersEverQuarantined", attackersQ);
    recordScalar("benignEverQuarantined",    benignQ);
    // Collateral isolation rate = benign nodes that were ever quarantined / benign.
    recordScalar("collateralIsolationRate", benign > 0 ? (double)benignQ / benign : 0.0);
    recordScalar("attackerContainmentRate", attackers > 0 ? (double)attackersQ / attackers : 0.0);
    recordScalar("avgAttackerTrustFinal", attackers > 0 ? sumAttackerTrust / attackers : 0.0);
    recordScalar("avgBenignTrustFinal",   benign > 0 ? sumBenignTrust / benign : 0.0);
}

} // namespace veremivndn
