//
// DP-IDS-VNDN - Evaluation Metrics (Methodology Section 5.3)
//

#ifndef __VEREMIVNDN_DPIDSMETRICS_H
#define __VEREMIVNDN_DPIDSMETRICS_H

#include <omnetpp.h>
#include <map>
#include <string>
#include <vector>

using namespace omnetpp;

namespace veremivndn {

class DPIDSMetrics : public cSimpleModule
{
private:
    double metricsInterval;
    cMessage *metricsTimer;

    // ISR tracking
    int totalInterestsIssued;
    int interestsSatisfiedLegitimate;

    // Poisoning exposure
    std::map<std::string, simtime_t> poisonStartTimes;
    std::vector<double> poisonExposureDurations;

    // Hijack latency
    std::map<std::string, simtime_t> hijackInstallTimes;
    std::vector<double> hijackDetectionLatencies;

    // Communication overhead
    long totalTrafficBytes;
    long dpidsBytes;

    // Confusion matrix
    int truePositives;
    int trueNegatives;
    int falsePositives;
    int falseNegatives;

    // Signals
    simsignal_t isrSignal;
    simsignal_t poisonExposureSignal;
    simsignal_t hijackLatencySignal;
    simsignal_t overheadSignal;
    simsignal_t accuracySignal;
    simsignal_t precisionSignal;
    simsignal_t recallSignal;
    simsignal_t f1Signal;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void computeMetrics();

public:
    DPIDSMetrics() : metricsTimer(nullptr), totalInterestsIssued(0),
        interestsSatisfiedLegitimate(0), totalTrafficBytes(0), dpidsBytes(0),
        truePositives(0), trueNegatives(0), falsePositives(0), falseNegatives(0) {}

    // Convenience: increment traffic counters from external modules
    void addInterestIssued(int count = 1) { totalInterestsIssued += count; }
    void addInterestSatisfied(int count = 1) { interestsSatisfiedLegitimate += count; }
    void addTraffic(long bytes) { totalTrafficBytes += bytes; }
    void addDPIDSOverhead(long bytes) { dpidsBytes += bytes; totalTrafficBytes += bytes; }
    virtual ~DPIDSMetrics();

    // Registration API
    void recordInterestIssued() { totalInterestsIssued++; }
    void recordInterestSatisfied(bool legitimate) {
        if (legitimate) interestsSatisfiedLegitimate++;
    }
    void recordPoisonStart(const std::string &name) {
        poisonStartTimes[name] = simTime();
    }
    void recordPoisonDetected(const std::string &name) {
        auto it = poisonStartTimes.find(name);
        if (it != poisonStartTimes.end()) {
            poisonExposureDurations.push_back((simTime() - it->second).dbl());
            poisonStartTimes.erase(it);
        }
    }
    void recordHijackInstall(const std::string &prefix) {
        hijackInstallTimes[prefix] = simTime();
    }
    void recordHijackDetected(const std::string &prefix) {
        auto it = hijackInstallTimes.find(prefix);
        if (it != hijackInstallTimes.end()) {
            hijackDetectionLatencies.push_back((simTime() - it->second).dbl());
            hijackInstallTimes.erase(it);
        }
    }
    void recordDetection(bool actualMalicious, bool detectedMalicious) {
        if (actualMalicious && detectedMalicious) truePositives++;
        else if (!actualMalicious && !detectedMalicious) trueNegatives++;
        else if (!actualMalicious && detectedMalicious) falsePositives++;
        else falseNegatives++;
    }
    void recordTraffic(long bytes, bool isDPIDS) {
        totalTrafficBytes += bytes;
        if (isDPIDS) dpidsBytes += bytes;
    }
};

} // namespace veremivndn
#endif
