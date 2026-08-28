//
// VeReMiVNDN - TrustNet feature collector
//
// Global instrumentation module for the TrustNet-VNDN paper. It exports, per
// vehicle and per sliding window, the five behavioural features the TrustNet
// detector consumes (f1 TTL/hopCount variability, f2 Interest-to-Data ratio,
// f3 packet-drop rate, f4 position plausibility = Kalman residual on the
// REPORTED beacon track, f5 Interest forwarding rate) together with a benign/
// attacker label and the VeReMi attack type. The reported beacon track is the
// one the VehicleController stamps into its beacons (true+GPS-noise for benign
// vehicles, falsified for attackers), so f4 is computed from what an observer
// would actually see on the wire.
//
#ifndef __VEREMIVNDN_TRUSTNETCOLLECTOR_H
#define __VEREMIVNDN_TRUSTNETCOLLECTOR_H

#include <omnetpp.h>
#include <map>
#include <deque>
#include <string>
#include <cstdio>

using namespace omnetpp;

namespace veremivndn {

class TrustNetCollector : public cSimpleModule, public cListener
{
  private:
    // config
    std::string outputFile;
    int windowSize;        // W: beacons per window
    int maxWindows;        // T: windows per vehicle to export
    double beaconInterval; // sampling period
    cMessage *tick = nullptr;
    FILE *fp = nullptr;

    // subscribed signals
    simsignal_t sigInterestSent, sigDataSent, sigPacketDropped, sigInterestReceived;

    // per-vehicle accumulators
    struct Acc {
        // cumulative NDN counters (updated by signal handlers)
        long cumInterest = 0, cumData = 0, cumDropped = 0, cumTotal = 0;
        // hopCount stats within the current window
        long hcN = 0; double hcSum = 0, hcSumSq = 0;
        // snapshot of cumulative counters at window start
        long sIat = 0, sDat = 0, sDrop = 0, sTot = 0;
        // reported-position sample buffer for the current window
        std::deque<double> rx, ry;
        int windowsEmitted = 0;
        bool active = false;
    };
    std::map<std::string, Acc> acc;

    std::string hostOf(cComponent *source);

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, long v, cObject *d) override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, unsigned long v, cObject *d) override;
    virtual void receiveSignal(cComponent *src, simsignal_t id, cObject *obj, cObject *d) override;

    void sampleWindowTick();
    void emitWindow(const std::string &veh, class VehicleController *ctrl);

  public:
    virtual ~TrustNetCollector();
};

} // namespace veremivndn
#endif
