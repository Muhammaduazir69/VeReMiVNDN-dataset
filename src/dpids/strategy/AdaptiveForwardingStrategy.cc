//
// DP-IDS-VNDN - Adaptive Forwarding Strategy Implementation
// Section 4.5: CS freshness reduction, PIT timeout acceleration, FIB weight reduction
//

#include "AdaptiveForwardingStrategy.h"
#include "../../ndn/tables/CS.h"
#include "../../ndn/tables/PIT.h"
#include "../../ndn/tables/FIB.h"
#include <string>

namespace veremivndn {

Define_Module(AdaptiveForwardingStrategy);

void AdaptiveForwardingStrategy::initialize() {
    thetaCS = par("thetaCS");
    thetaPIT = par("thetaPIT");
    thetaFIB = par("thetaFIB");

    csPenalizationSignal = registerSignal("csPenalization");
    pitPenalizationSignal = registerSignal("pitPenalization");
    fibPenalizationSignal = registerSignal("fibPenalization");
    vehiclePenalizedSignal = registerSignal("vehiclePenalized");

    EV_INFO << "AdaptiveForwardingStrategy initialized: thetaCS=" << thetaCS
            << ", thetaPIT=" << thetaPIT << ", thetaFIB=" << thetaFIB << endl;
}

void AdaptiveForwardingStrategy::handleMessage(cMessage *msg) {
    delete msg;
}

void AdaptiveForwardingStrategy::finish() {
    recordScalar("totalCSPenalizations", totalCSPenalizations);
    recordScalar("totalPITPenalizations", totalPITPenalizations);
    recordScalar("totalFIBPenalizations", totalFIBPenalizations);
}

void AdaptiveForwardingStrategy::applyPenalization(
    cModule *vehicleMod, const std::string &vehicleId, double beliefMal)
{
    bool penalized = false;

    if (beliefMal > thetaCS) {
        penalizeCS(vehicleMod, vehicleId, beliefMal);
        penalized = true;
    }

    if (beliefMal > thetaPIT) {
        penalizePIT(vehicleMod, vehicleId, beliefMal);
        penalized = true;
    }

    if (beliefMal > thetaFIB) {
        penalizeFIB(vehicleMod, vehicleId, beliefMal);
        penalized = true;
    }

    if (penalized) {
        emit(vehiclePenalizedSignal, 1L);
        EV_WARN << "DP-IDS: Penalized vehicle " << vehicleId
                << " (Bel(mal)=" << beliefMal << ")" << endl;
    }
}

void AdaptiveForwardingStrategy::applyTrustMitigation(
    cModule *vehicleMod, const std::string &vehicleId, double trust)
{
    // Severity grows as trust falls. Unlike applyPenalization (which gates on the
    // static thetaCS/thetaPIT/thetaFIB thresholds), this is applied continuously
    // by the closed-loop TridentController, so the strength tracks T_v(t).
    double bel = 1.0 - trust;
    if (bel < 0.0) bel = 0.0;
    if (bel > 1.0) bel = 1.0;

    penalizeCS(vehicleMod, vehicleId, bel);
    penalizePIT(vehicleMod, vehicleId, bel);
    penalizeFIB(vehicleMod, vehicleId, bel);

    emit(vehiclePenalizedSignal, 1L);
    EV_INFO << "TRIDENT: graduated mitigation on " << vehicleId
            << " (T=" << trust << ", severity=" << bel << ")" << endl;
}

void AdaptiveForwardingStrategy::restorePenalization(
    cModule *vehicleMod, const std::string &vehicleId)
{
    cModule *ndnNode = vehicleMod->getSubmodule("ndnNode");
    if (!ndnNode) return;
    FIB *fib = dynamic_cast<FIB*>(ndnNode->getSubmodule("fib"));
    if (fib) fib->restoreRoutes();
    EV_INFO << "TRIDENT: restored forwarding for reinstated " << vehicleId << endl;
}

void AdaptiveForwardingStrategy::penalizeCS(
    cModule *vehicleMod, const std::string &vehicleId, double bel)
{
    cModule *ndnNode = vehicleMod->getSubmodule("ndnNode");
    if (!ndnNode) return;

    CS *cs = dynamic_cast<CS*>(ndnNode->getSubmodule("cs"));
    if (!cs) return;

    if (bel >= 0.99) {
        // At Bel = 1: bypass all CS entries from this vehicle
        cs->bypassVehicleEntries(vehicleId);
    } else {
        // Reduce freshness inversely proportional to belief
        double factor = 1.0 - bel;
        const auto &entries = cs->getEntries();
        for (const auto &e : entries) {
            if (e.second->data && std::string(e.second->data->getSignerId()) == vehicleId) {
                cs->reduceFreshness(e.first, factor);
            }
        }
    }

    totalCSPenalizations++;
    emit(csPenalizationSignal, bel);
}

void AdaptiveForwardingStrategy::penalizePIT(
    cModule *vehicleMod, const std::string &vehicleId, double bel)
{
    cModule *ndnNode = vehicleMod->getSubmodule("ndnNode");
    if (!ndnNode) return;

    PIT *pit = dynamic_cast<PIT*>(ndnNode->getSubmodule("pit"));
    if (!pit) return;

    // Accelerate timeout: multiply remaining time by (1 - bel)
    double factor = 1.0 - bel;
    std::vector<std::string> pitEntries = pit->getAllEntries();
    for (const std::string &name : pitEntries) {
        pit->accelerateTimeout(name, factor);
    }

    totalPITPenalizations++;
    emit(pitPenalizationSignal, bel);
}

void AdaptiveForwardingStrategy::penalizeFIB(
    cModule *vehicleMod, const std::string &vehicleId, double bel)
{
    cModule *ndnNode = vehicleMod->getSubmodule("ndnNode");
    if (!ndnNode) return;

    FIB *fib = dynamic_cast<FIB*>(ndnNode->getSubmodule("fib"));
    if (!fib) return;

    // Increase cost (reduce priority): multiply by 1/(1-bel)
    double costMultiplier = (bel < 0.99) ? 1.0 / (1.0 - bel) : 100.0;
    const auto &entries = fib->getEntries();
    for (const auto &e : entries) {
        for (int face : e.second->nextHops) {
            fib->penalizeRoute(e.first, face, costMultiplier);
        }
    }

    totalFIBPenalizations++;
    emit(fibPenalizationSignal, bel);
}

} // namespace veremivndn
