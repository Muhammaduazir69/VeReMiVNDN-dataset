//
// VeReMiVNDN - TrustNet feature collector (implementation)
//
#include "TrustNetCollector.h"
#include "../../vndn/node/VehicleController.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <cmath>

namespace veremivndn {

Define_Module(TrustNetCollector);

TrustNetCollector::~TrustNetCollector() {
    cancelAndDelete(tick);
    if (fp) fclose(fp);
}

void TrustNetCollector::initialize() {
    outputFile = par("outputFile").stdstringValue();
    windowSize = par("windowSize");
    maxWindows = par("maxWindows");
    beaconInterval = par("beaconInterval").doubleValue();

    fp = fopen(outputFile.c_str(), "w");
    if (!fp)
        throw cRuntimeError("TrustNetCollector: cannot open output file '%s'", outputFile.c_str());
    fprintf(fp, "scenario,vehicle,window,f1,f2,f3,f4,f5,is_attacker,attack_type\n");
    fflush(fp);

    // register + subscribe to the NDNProcessor signals network-wide
    sigInterestSent     = registerSignal("interestSent");
    sigDataSent         = registerSignal("dataSent");
    sigPacketDropped    = registerSignal("packetDropped");
    sigInterestReceived = registerSignal("interestReceived");
    cModule *sys = getSimulation()->getSystemModule();
    sys->subscribe(sigInterestSent, this);
    sys->subscribe(sigDataSent, this);
    sys->subscribe(sigPacketDropped, this);
    sys->subscribe(sigInterestReceived, this);

    tick = new cMessage("trustnetTick");
    scheduleAt(simTime() + beaconInterval, tick);
    EV_INFO << "TrustNetCollector active -> " << outputFile << endl;
}

// Walk up from the signal source to the enclosing vehicle[] host.
std::string TrustNetCollector::hostOf(cComponent *source) {
    cModule *m = dynamic_cast<cModule*>(source);
    while (m && m != getSimulation()->getSystemModule()) {
        if (strcmp(m->getName(), "vehicle") == 0) return m->getFullName();
        m = m->getParentModule();
    }
    return "";
}

void TrustNetCollector::receiveSignal(cComponent *src, simsignal_t id, long, cObject *) {
    std::string h = hostOf(src);
    if (h.empty()) return;
    Acc &a = acc[h];
    if (id == sigInterestSent)      { a.cumInterest++; a.cumTotal++; }
    else if (id == sigDataSent)     { a.cumData++;     a.cumTotal++; }
    else if (id == sigPacketDropped){ a.cumDropped++;  a.cumTotal++; }
    else if (id == sigInterestReceived) { a.cumTotal++; }
}

void TrustNetCollector::receiveSignal(cComponent *src, simsignal_t id, unsigned long v, cObject *d) {
    receiveSignal(src, id, (long)v, d);
}

void TrustNetCollector::receiveSignal(cComponent *src, simsignal_t id, cObject *obj, cObject *) {
    std::string h = hostOf(src);
    if (h.empty()) return;
    Acc &a = acc[h];
    if (id == sigInterestSent)      { a.cumInterest++; a.cumTotal++; }
    else if (id == sigDataSent)     { a.cumData++;     a.cumTotal++; }
    else if (id == sigPacketDropped){ a.cumDropped++;  a.cumTotal++; }
    else if (id == sigInterestReceived) { a.cumTotal++; }
    // opportunistically capture hopCount for the TTL-variability feature
    if (NdnPacket *p = dynamic_cast<NdnPacket*>(obj)) {
        a.hcSum += p->getHopCount();
        a.hcSumSq += (double)p->getHopCount() * p->getHopCount();
        a.hcN++;
    }
}

void TrustNetCollector::handleMessage(cMessage *msg) {
    if (msg == tick) {
        sampleWindowTick();
        scheduleAt(simTime() + beaconInterval, tick);
    } else {
        delete msg;
    }
}

void TrustNetCollector::sampleWindowTick() {
    cModule *sys = getSimulation()->getSystemModule();
    for (cModule::SubmoduleIterator it(sys); !it.end(); ++it) {
        cModule *veh = *it;
        if (strcmp(veh->getName(), "vehicle") != 0) continue;
        cModule *cm = veh->getSubmodule("controller");
        VehicleController *ctrl = dynamic_cast<VehicleController*>(cm);
        if (!ctrl || !ctrl->hasReportedPos()) continue;
        std::string h = veh->getFullName();
        Acc &a = acc[h];
        if (a.windowsEmitted >= maxWindows) continue;
        a.active = true;
        a.rx.push_back(ctrl->getLastReportedX());
        a.ry.push_back(ctrl->getLastReportedY());
        if ((int)a.rx.size() >= windowSize)
            emitWindow(h, ctrl);
    }
}

void TrustNetCollector::emitWindow(const std::string &veh, VehicleController *ctrl) {
    Acc &a = acc[veh];
    int n = a.rx.size();

    // f4: mean constant-velocity (Kalman) residual over the reported track
    double f4 = 0.0; int cnt = 0;
    for (int i = 2; i < n; i++) {
        double predx = a.rx[i-1] + (a.rx[i-1] - a.rx[i-2]);
        double predy = a.ry[i-1] + (a.ry[i-1] - a.ry[i-2]);
        double r = std::sqrt((a.rx[i]-predx)*(a.rx[i]-predx) +
                             (a.ry[i]-predy)*(a.ry[i]-predy));
        f4 += 1.0 - 1.0/(1.0 + std::exp(-r/12.0));
        cnt++;
    }
    f4 = (cnt > 0) ? f4/cnt : 0.0;

    // window deltas of the NDN counters
    long dI = a.cumInterest - a.sIat;
    long dD = a.cumData     - a.sDat;
    long dDrop = a.cumDropped - a.sDrop;
    long dTot = a.cumTotal  - a.sTot;
    double winDur = windowSize * beaconInterval;

    // f1: hopCount/TTL variability (0 if hopCount is constant in this sim)
    double f1 = 0.0;
    if (a.hcN > 1) {
        double mean = a.hcSum / a.hcN;
        double var = a.hcSumSq / a.hcN - mean*mean;
        f1 = std::min(1.0, std::max(0.0, var) / 10.0);
    }
    // f2: Interest fraction of this vehicle's NDN traffic
    double f2 = (dI + dD > 0) ? (double)dI / (double)(dI + dD) : 0.0;
    // f3: packet-drop rate over the window
    double f3 = (dTot > 0) ? (double)dDrop / (double)dTot : 0.0;
    // f5: Interest forwarding rate (interests/s), normalised by 20/s
    double f5 = std::min(1.0, (dI / std::max(1e-6, winDur)) / 20.0);

    int atk = ctrl->getEffectivePosAttackType();
    int isAtk = ctrl->getIsPosAttacker() ? 1 : 0;
    const char *scn = getSimulation()->getActiveEnvir()->getConfigEx()->getActiveConfigName();
    fprintf(fp, "%s,%s,%d,%.5f,%.5f,%.5f,%.5f,%.5f,%d,%d\n",
            scn ? scn : "NA", veh.c_str(), a.windowsEmitted,
            f1, f2, f3, f4, f5, isAtk, atk);
    fflush(fp);

    // reset window: keep last 2 reported points for residual continuity
    while ((int)a.rx.size() > 2) { a.rx.pop_front(); a.ry.pop_front(); }
    a.sIat = a.cumInterest; a.sDat = a.cumData; a.sDrop = a.cumDropped; a.sTot = a.cumTotal;
    a.hcN = 0; a.hcSum = a.hcSumSq = 0;
    a.windowsEmitted++;
}

void TrustNetCollector::finish() {
    if (fp) { fflush(fp); fclose(fp); fp = nullptr; }
}

} // namespace veremivndn
