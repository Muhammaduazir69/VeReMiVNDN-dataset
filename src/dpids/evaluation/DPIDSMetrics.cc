//
// DP-IDS-VNDN - Evaluation Metrics Implementation
// Publication-quality metric recording for confusion matrix,
// ISR, detection latency, and communication overhead
//

#include "DPIDSMetrics.h"

namespace veremivndn {

Define_Module(DPIDSMetrics);

DPIDSMetrics::~DPIDSMetrics() {
    cancelAndDelete(metricsTimer);
}

void DPIDSMetrics::initialize() {
    metricsInterval = par("metricsInterval").doubleValue();

    isrSignal = registerSignal("interestSatisfactionRate");
    poisonExposureSignal = registerSignal("csPoisoningExposureTime");
    hijackLatencySignal = registerSignal("fibHijackDetectionLatency");
    overheadSignal = registerSignal("communicationOverhead");
    accuracySignal = registerSignal("detectionAccuracy");
    precisionSignal = registerSignal("detectionPrecision");
    recallSignal = registerSignal("detectionRecall");
    f1Signal = registerSignal("detectionF1");

    // WATCH for Qtenv inspector
    WATCH(truePositives);
    WATCH(trueNegatives);
    WATCH(falsePositives);
    WATCH(falseNegatives);
    WATCH(totalInterestsIssued);
    WATCH(interestsSatisfiedLegitimate);

    metricsTimer = new cMessage("dpidsMetrics");
    scheduleAt(simTime() + metricsInterval, metricsTimer);
}

void DPIDSMetrics::handleMessage(cMessage *msg) {
    if (msg == metricsTimer) {
        computeMetrics();
        scheduleAt(simTime() + metricsInterval, metricsTimer);
    } else {
        delete msg;
    }
}

void DPIDSMetrics::computeMetrics() {
    // ISR
    double isr = (totalInterestsIssued > 0) ?
        (double)interestsSatisfiedLegitimate / totalInterestsIssued : 1.0;
    emit(isrSignal, isr);

    // Mean CS Poisoning Exposure Time
    if (!poisonExposureDurations.empty()) {
        double sum = 0;
        for (double d : poisonExposureDurations) sum += d;
        double mean = sum / poisonExposureDurations.size();
        emit(poisonExposureSignal, mean);
    }

    // Mean FIB Hijacking Detection Latency
    if (!hijackDetectionLatencies.empty()) {
        double sum = 0;
        for (double d : hijackDetectionLatencies) sum += d;
        double mean = sum / hijackDetectionLatencies.size();
        emit(hijackLatencySignal, mean);
    }

    // Communication Overhead
    double overhead = (totalTrafficBytes > 0) ?
        (double)dpidsBytes / totalTrafficBytes : 0.0;
    emit(overheadSignal, overhead);

    // Confusion matrix metrics
    int total = truePositives + trueNegatives + falsePositives + falseNegatives;
    if (total > 0) {
        double accuracy = (double)(truePositives + trueNegatives) / total;
        emit(accuracySignal, accuracy);

        double precision = (truePositives + falsePositives > 0) ?
            (double)truePositives / (truePositives + falsePositives) : 0.0;
        emit(precisionSignal, precision);

        double recall = (truePositives + falseNegatives > 0) ?
            (double)truePositives / (truePositives + falseNegatives) : 0.0;
        emit(recallSignal, recall);

        double f1 = (precision + recall > 0) ?
            2.0 * precision * recall / (precision + recall) : 0.0;
        emit(f1Signal, f1);
    }
}

void DPIDSMetrics::finish() {
    // ====================================================================
    // CONFUSION MATRIX (raw counts)
    // ====================================================================
    recordScalar("truePositives", truePositives);
    recordScalar("trueNegatives", trueNegatives);
    recordScalar("falsePositives", falsePositives);
    recordScalar("falseNegatives", falseNegatives);

    int total = truePositives + trueNegatives + falsePositives + falseNegatives;

    // ====================================================================
    // DETECTION PERFORMANCE METRICS
    // ====================================================================
    double precision = (truePositives + falsePositives > 0) ?
        (double)truePositives / (truePositives + falsePositives) : 0.0;
    double recall = (truePositives + falseNegatives > 0) ?
        (double)truePositives / (truePositives + falseNegatives) : 0.0;
    double f1 = (precision + recall > 0) ?
        2.0 * precision * recall / (precision + recall) : 0.0;
    double accuracy = (total > 0) ?
        (double)(truePositives + trueNegatives) / total : 0.0;
    double fpr = (falsePositives + trueNegatives > 0) ?
        (double)falsePositives / (falsePositives + trueNegatives) : 0.0;
    double fnr = (falseNegatives + truePositives > 0) ?
        (double)falseNegatives / (falseNegatives + truePositives) : 0.0;
    double specificity = (trueNegatives + falsePositives > 0) ?
        (double)trueNegatives / (trueNegatives + falsePositives) : 0.0;

    // Matthews Correlation Coefficient
    double mcc_num = (double)truePositives * trueNegatives - (double)falsePositives * falseNegatives;
    double mcc_den = std::sqrt(
        (double)(truePositives + falsePositives) * (truePositives + falseNegatives) *
        (trueNegatives + falsePositives) * (trueNegatives + falseNegatives));
    double mcc = (mcc_den > 0) ? mcc_num / mcc_den : 0.0;

    recordScalar("finalPrecision", precision);
    recordScalar("finalRecall", recall);
    recordScalar("finalF1", f1);
    recordScalar("finalAccuracy", accuracy);
    recordScalar("finalFPR", fpr);
    recordScalar("finalFNR", fnr);
    recordScalar("finalSpecificity", specificity);
    recordScalar("finalMCC", mcc);
    recordScalar("totalDecisions", total);

    // ====================================================================
    // QoS METRICS
    // ====================================================================
    double finalISR = (totalInterestsIssued > 0) ?
        (double)interestsSatisfiedLegitimate / totalInterestsIssued : 1.0;
    recordScalar("finalISR", finalISR);
    recordScalar("totalInterestsIssued", totalInterestsIssued);
    recordScalar("interestsSatisfiedLegit", interestsSatisfiedLegitimate);

    // Communication overhead
    recordScalar("totalTrafficBytes", totalTrafficBytes);
    recordScalar("dpidsOverheadBytes", dpidsBytes);
    double overheadRatio = (totalTrafficBytes > 0) ?
        (double)dpidsBytes / totalTrafficBytes : 0.0;
    recordScalar("overheadRatio", overheadRatio);

    // Attack-specific metrics
    recordScalar("poisonExposureEvents", (int)poisonExposureDurations.size());
    recordScalar("hijackDetectionEvents", (int)hijackDetectionLatencies.size());

    if (!poisonExposureDurations.empty()) {
        double sum = 0;
        for (double d : poisonExposureDurations) sum += d;
        recordScalar("avgPoisonExposureTime", sum / poisonExposureDurations.size());
    }

    if (!hijackDetectionLatencies.empty()) {
        double sum = 0;
        for (double d : hijackDetectionLatencies) sum += d;
        recordScalar("avgHijackDetectionLatency", sum / hijackDetectionLatencies.size());
    }
}

} // namespace veremivndn
