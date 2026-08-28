//
// TRIDENT-VNDN - Network resilience monitor (header)
//
#ifndef __VEREMIVNDN_RESILIENCEMONITOR_H
#define __VEREMIVNDN_RESILIENCEMONITOR_H

#include <omnetpp.h>
#include <vector>
#include <string>
#include <cstdio>

using namespace omnetpp;

namespace veremivndn {

class ResilienceMonitor : public cSimpleModule
{
  public:
    ResilienceMonitor() {}
    virtual ~ResilienceMonitor();

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    void sample();   // one ISR sample over the elapsed window

  private:
    // Config
    simtime_t sampleInterval;
    simtime_t baselineStart, attackStart, attackEnd;
    double recoveryThreshold;
    std::string csvFile;

    cMessage *sampleTimer = nullptr;

    // Cumulative consumer counters captured at the previous sample.
    long prevIssued = 0;
    long prevSatisfied = 0;

    // Time series.
    std::vector<double> ts;     // sample time (s)
    std::vector<double> isrs;   // windowed ISR
    std::vector<double> qs;     // normalised resilience Q (filled at finish)

    double lastISR = 0.0;
    double baselineISR = 0.0;   // computed at finish from pre-attack samples
    double baseSum = 0.0;       // running pre-attack ISR accumulator
    int    baseCnt = 0;

    simsignal_t isrSig = -1;
    simsignal_t qSig   = -1;

    FILE *csv = nullptr;

    // Helper: sum consumer (issued, satisfied) across all live vehicles.
    void pollConsumers(long &issued, long &satisfied);
};

} // namespace veremivndn

#endif
