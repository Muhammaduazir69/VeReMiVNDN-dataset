//
// TRIDENT-VNDN - Network resilience monitor (implementation)
//
#include "ResilienceMonitor.h"
#include "../vndn/node/VehicleController.h"
#include <algorithm>
#include <cmath>

namespace veremivndn {

Define_Module(ResilienceMonitor);

ResilienceMonitor::~ResilienceMonitor()
{
    cancelAndDelete(sampleTimer);
    if (csv) { fclose(csv); csv = nullptr; }
}

void ResilienceMonitor::initialize()
{
    sampleInterval    = par("sampleInterval");
    baselineStart     = par("baselineStart");
    attackStart       = par("attackStart");
    attackEnd         = par("attackEnd");
    recoveryThreshold = par("recoveryThreshold");
    csvFile           = par("csvFile").stdstringValue();

    isrSig = registerSignal("isr");
    qSig   = registerSignal("resilienceQ");

    // Resolve CSV path: results/resilience_<config>_<run>.csv unless overridden.
    if (csvFile.empty()) {
        std::string cfg = "run", run = "0";
        try {
            cfg = getEnvir()->getConfigEx()->getVariable("configname");
            run = getEnvir()->getConfigEx()->getVariable("runnumber");
        } catch (...) {}
        csvFile = "results/resilience_" + cfg + "_" + run + ".csv";
    }
    csv = fopen(csvFile.c_str(), "w");
    if (!csv) {
        // Fall back to current directory if results/ is missing.
        std::string base = csvFile.substr(csvFile.find_last_of('/') + 1);
        csv = fopen(base.c_str(), "w");
    }
    if (csv) fprintf(csv, "time,isr,Q\n");

    sampleTimer = new cMessage("resilienceSample");
    scheduleAt(simTime() + sampleInterval, sampleTimer);

    EV_INFO << "ResilienceMonitor online: window=" << sampleInterval
            << " baseline[" << baselineStart << "," << attackStart << ") attack["
            << attackStart << "," << attackEnd << "] -> " << csvFile << endl;
}

void ResilienceMonitor::handleMessage(cMessage *msg)
{
    if (msg == sampleTimer) {
        sample();
        scheduleAt(simTime() + sampleInterval, sampleTimer);
    } else {
        delete msg;
    }
}

void ResilienceMonitor::pollConsumers(long &issued, long &satisfied)
{
    issued = 0; satisfied = 0;
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;
        cModule *ctrlMod = mod->getSubmodule("controller");
        VehicleController *vc = dynamic_cast<VehicleController*>(ctrlMod);
        if (!vc) continue;
        issued    += vc->getInterestsIssued();
        satisfied += vc->getInterestsSatisfied();
    }
}

void ResilienceMonitor::sample()
{
    long issued = 0, satisfied = 0;
    pollConsumers(issued, satisfied);

    long dIssued    = issued - prevIssued;
    long dSatisfied = satisfied - prevSatisfied;
    prevIssued = issued;
    prevSatisfied = satisfied;

    double isr = (dIssued > 0) ? (double)dSatisfied / (double)dIssued : lastISR;
    if (isr < 0.0) isr = 0.0;
    if (isr > 1.0) isr = 1.0;
    lastISR = isr;

    double now = simTime().dbl();
    ts.push_back(now);
    isrs.push_back(isr);
    emit(isrSig, isr);

    // Incremental pre-attack baseline.
    if (simTime() >= baselineStart && simTime() < attackStart) {
        baseSum += isr; baseCnt++;
    }
    if (baselineISR <= 0.0 && simTime() >= attackStart && baseCnt > 0) {
        baselineISR = baseSum / baseCnt;
    }

    double q = 1.0;
    if (baselineISR > 0.0) {
        q = isr / baselineISR;
        if (q < 0.0) q = 0.0;
        if (q > 1.0) q = 1.0;
    }
    qs.push_back(q);
    emit(qSig, q);

    if (csv) { fprintf(csv, "%.3f,%.5f,%.5f\n", now, isr, q); fflush(csv); }
}

void ResilienceMonitor::refreshDisplay() const
{
    char buf[96];
    snprintf(buf, sizeof(buf), "ISR:%.2f Q:%.2f%s", lastISR,
             baselineISR > 0 ? std::min(1.0, lastISR / baselineISR) : 1.0,
             baselineISR > 0 ? "" : " (base)");
    getDisplayString().setTagArg("t", 0, buf);
}

void ResilienceMonitor::finish()
{
    if (csv) { fclose(csv); csv = nullptr; }

    // Recompute baseline if the run never reached attackStart sampling.
    if (baselineISR <= 0.0) {
        double s = 0; int c = 0;
        for (size_t i = 0; i < ts.size(); i++)
            if (ts[i] >= baselineStart.dbl() && ts[i] < attackStart.dbl()) { s += isrs[i]; c++; }
        if (c > 0) baselineISR = s / c;
    }

    // R = AURC : trapezoidal time-average of Q over [attackStart, end].
    double area = 0.0, span = 0.0, rho = 1.0;
    double aS = attackStart.dbl(), aE = attackEnd.dbl();
    double ttr = -1.0;
    for (size_t i = 0; i + 1 < ts.size(); i++) {
        if (ts[i] < aS) continue;
        double dtSeg = ts[i+1] - ts[i];
        double qAvg = 0.5 * (qs[i] + qs[i+1]);
        area += qAvg * dtSeg;
        span += dtSeg;
    }
    double R = (span > 0) ? area / span : 1.0;

    // rho = robustness : min Q during the attack window.
    for (size_t i = 0; i < ts.size(); i++)
        if (ts[i] >= aS && ts[i] <= aE) rho = std::min(rho, qs[i]);

    // TTR : first time after attackEnd that Q recovers to recoveryThreshold.
    for (size_t i = 0; i < ts.size(); i++) {
        if (ts[i] >= aE && qs[i] >= recoveryThreshold) { ttr = ts[i] - aE; break; }
    }

    recordScalar("baselineISR", baselineISR);
    recordScalar("finalISR", lastISR);
    recordScalar("resilienceAURC", R);          // R in [0,1], higher is better
    recordScalar("robustness", rho);            // drop depth, higher is better
    recordScalar("timeToRecover", ttr);         // seconds; -1 = never recovered
    recordScalar("samples", (long)ts.size());

    EV_INFO << "TRIDENT resilience: baselineISR=" << baselineISR
            << " R(AURC)=" << R << " rho=" << rho << " TTR=" << ttr << "s" << endl;
}

} // namespace veremivndn
