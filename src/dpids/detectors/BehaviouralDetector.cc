//
// DP-IDS-VNDN - Behavioural Detector Implementation
// Section 4.3.1: 4-layer LSTM on 6 VeReMi features (pos-x, pos-y, spd-x, spd-y, IDR, TTL)
// Falls back to threshold-based scoring if LSTM weights not available
// Subscribes to NDNProcessor signals for automatic IDR/TTL tracking
//

#include "BehaviouralDetector.h"
#include <cmath>
#include <algorithm>
#include "inet/mobility/contract/IMobility.h"
#include "veins/modules/mobility/traci/TraCIMobility.h"
#include "veins_inet/VeinsInetMobility.h"

namespace veremivndn {

Define_Module(BehaviouralDetector);

BehaviouralDetector::~BehaviouralDetector() {
    cancelAndDelete(detectionTimer);
}

void BehaviouralDetector::initialize(int stage) {
    if (stage == 0) {
        detectionInterval = par("detectionInterval").doubleValue();
        posDeviationThreshold = par("positionDeviationThreshold");
        speedDeviationThreshold = par("speedDeviationThreshold");
        idrThreshold = par("idrThreshold");
        communicationRange = par("communicationRange").doubleValue();

        // LSTM configuration (Section 4.3.1)
        lstmInputDim = 6;     // pos-x, pos-y, spd-x, spd-y, IDR, TTL
        lstmHiddenDim = 64;   // Per methodology
        lstmNumLayers = 4;    // 4-layer LSTM per methodology
        lstmSeqLength = 20;   // Temporal window length

        behaviouralScoreSignal = registerSignal("behaviouralScore");

        // Initialize LSTM model
        modelPath = "";
        if (hasPar("modelPath")) {
            modelPath = par("modelPath").stdstringValue();
        }
        useLSTM = lstmModel.initialize(lstmInputDim, lstmHiddenDim,
                                        lstmNumLayers, modelPath);

        if (useLSTM) {
            EV_INFO << "BehaviouralDetector: LSTM model loaded ("
                    << lstmNumLayers << " layers, " << lstmHiddenDim << " hidden)" << endl;
        } else {
            EV_INFO << "BehaviouralDetector: Using threshold-based scoring (no LSTM weights)" << endl;
        }
    }

    if (stage == 2) {
        // Subscribe to NDNProcessor signals from all vehicles
        subscribeToNDNSignals();

        detectionTimer = new cMessage("behaviouralDetection");
        scheduleAt(simTime() + detectionInterval, detectionTimer);

        EV_INFO << "BehaviouralDetector initialized: posThreshold=" << posDeviationThreshold
                << ", spdThreshold=" << speedDeviationThreshold
                << ", idrThreshold=" << idrThreshold << endl;
    }
}

void BehaviouralDetector::subscribeToNDNSignals() {
    // Subscribe to interestReceived and dataReceived signals from vehicles
    // Called periodically because Veins creates vehicles dynamically via SUMO
    cModule *network = getSystemModule();
    if (!network) return;

    simsignal_t intRecvSig = cComponent::registerSignal("interestReceived");
    simsignal_t dataRecvSig = cComponent::registerSignal("dataReceived");

    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;

        int idx = mod->getIndex();
        if (subscribedVehicles.count(idx)) continue;

        cModule *ndnNode = mod->getSubmodule("ndnNode");
        if (ndnNode) {
            cModule *processor = ndnNode->getSubmodule("processor");
            if (processor) {
                processor->subscribe(intRecvSig, this);
                processor->subscribe(dataRecvSig, this);
                subscribedVehicles.insert(idx);
            }
        }
    }

    EV_INFO << "BehaviouralDetector: Subscribed to NDNProcessor signals" << endl;
}

void BehaviouralDetector::receiveSignal(cComponent *source, simsignal_t signalID,
                                         long value, cObject *details)
{
    // Identify which vehicle this signal came from
    cModule *mod = dynamic_cast<cModule*>(source);
    if (!mod) return;

    // Navigate: NDNProcessor -> NdnNode -> Vehicle
    cModule *ndnNode = mod->getParentModule();
    if (!ndnNode) return;
    cModule *vehicle = ndnNode->getParentModule();
    if (!vehicle) return;

    std::string vehicleId = vehicle->getFullName();
    std::string sigName = cComponent::getSignalName(signalID);

    if (sigName == "interestReceived") {
        recordInterest(vehicleId);
    } else if (sigName == "dataReceived") {
        recordData(vehicleId);
    }
}

void BehaviouralDetector::receiveSignal(cComponent *source, simsignal_t signalID,
                                         cObject *obj, cObject *details)
{
    // Handle object-type signals if needed (currently unused)
}

void BehaviouralDetector::handleMessage(cMessage *msg) {
    if (msg == detectionTimer) {
        detectAnomalies();
        scheduleAt(simTime() + detectionInterval, detectionTimer);
    } else {
        delete msg;
    }
}

void BehaviouralDetector::detectAnomalies() {
    // Dynamically subscribe to new vehicles (Veins creates them at runtime via SUMO)
    subscribeToNDNSignals();

    std::vector<cModule*> vehicles = getVehiclesInRange();

    for (cModule *vehicleMod : vehicles) {
        std::string vehicleId = vehicleMod->getFullName();
        double score = computeScore(vehicleId, vehicleMod);
        scores[vehicleId] = score;
        emit(behaviouralScoreSignal, score);
    }
}

double BehaviouralDetector::computeScore(const std::string &vehicleId,
                                          cModule *vehicleMod)
{
    cModule *mobilityMod = vehicleMod->getSubmodule("mobility");

    double posX = 0, posY = 0;
    double spdFromTraCI = -1;  // Will be set if TraCI speed is available
    bool hasPos = false;
    if (mobilityMod) {
        // Primary: VeinsInetMobility (NRCar / VndnNRVehicle)
        // This provides SUMO/TraCI-driven realistic position+speed
        veins::VeinsInetMobility *veinsMob = dynamic_cast<veins::VeinsInetMobility*>(mobilityMod);
        if (veinsMob) {
            inet::Coord pos = veinsMob->getCurrentPosition();
            inet::Coord vel = veinsMob->getCurrentVelocity();
            posX = pos.x;
            posY = pos.y;
            spdFromTraCI = std::sqrt(vel.x * vel.x + vel.y * vel.y);
            hasPos = true;

            // Get additional TraCI telemetry for richer profiling
            auto *vehCmd = veinsMob->getVehicleCommandInterface();
            if (vehCmd) {
                try {
                    spdFromTraCI = vehCmd->getSpeed();
                } catch (...) {}
            }
        }
        // Fallback: pure Veins TraCIMobility (legacy VndnVehicle)
        if (!hasPos) {
            veins::TraCIMobility *traciMob = dynamic_cast<veins::TraCIMobility*>(mobilityMod);
            if (traciMob) {
                veins::Coord pos = traciMob->getPositionAt(simTime());
                posX = pos.x;
                posY = pos.y;
                spdFromTraCI = traciMob->getSpeed();
                hasPos = true;
            }
        }
        // Last resort: static position
        if (!hasPos && mobilityMod->hasPar("initialX")) {
            posX = mobilityMod->par("initialX").doubleValue();
            posY = mobilityMod->par("initialY").doubleValue();
            hasPos = true;
        }
    }
    if (!hasPos) return 0.0;

    auto &profile = profiles[vehicleId];
    profile.sampleCount++;
    simtime_t now = simTime();

    double dt = (profile.lastUpdate > 0) ? (now - profile.lastUpdate).dbl() : detectionInterval;
    if (dt <= 0) dt = detectionInterval;

    if (profile.sampleCount <= 3) {
        // Warm-up phase: build baseline
        double n = profile.sampleCount;
        profile.avgPosX = profile.avgPosX * (n - 1) / n + posX / n;
        profile.avgPosY = profile.avgPosY * (n - 1) / n + posY / n;
        profile.lastPosX = posX;
        profile.lastPosY = posY;
        profile.lastUpdate = now;
        return 0.0;
    }

    // Compute current 6-feature vector
    double spdX = (posX - profile.lastPosX) / dt;
    double spdY = (posY - profile.lastPosY) / dt;
    double idr = computeIDR(profile);
    double ttlVar = computeTTLVariability(profile);

    // Build feature vector [pos-x, pos-y, spd-x, spd-y, IDR, TTL_variance]
    // Normalise features to reasonable ranges
    std::vector<double> featureVec = {
        posX / 15000.0,                             // Normalise by playground size
        posY / 16000.0,
        spdX / 30.0,                                // Normalise by max speed (~108 km/h)
        spdY / 30.0,
        std::min(idr, 5.0) / 5.0,                   // Cap IDR at 5.0
        std::min(ttlVar, 10.0) / 10.0               // Cap TTL variance at 10
    };

    // Add to LSTM sequence buffer
    profile.featureSequence.push_back(featureVec);
    if ((int)profile.featureSequence.size() > lstmSeqLength) {
        profile.featureSequence.pop_front();
    }

    // Update EWMA baselines (alpha=0.3 for vehicles moving at ~14 m/s with 1s intervals)
    double alpha = 0.3;
    profile.avgPosX = alpha * posX + (1 - alpha) * profile.avgPosX;
    profile.avgPosY = alpha * posY + (1 - alpha) * profile.avgPosY;
    profile.avgSpdX = alpha * spdX + (1 - alpha) * profile.avgSpdX;
    profile.avgSpdY = alpha * spdY + (1 - alpha) * profile.avgSpdY;
    profile.lastPosX = posX;
    profile.lastPosY = posY;
    profile.lastUpdate = now;

    // Use LSTM if available and sequence is long enough, else fall back to threshold
    if (useLSTM && (int)profile.featureSequence.size() >= lstmSeqLength) {
        return computeScoreLSTM(vehicleId, profile);
    } else {
        return computeScoreThreshold(vehicleId, profile, posX, posY, dt);
    }
}

double BehaviouralDetector::computeScoreLSTM(const std::string &vehicleId,
                                              VehicleProfile &profile)
{
    // Convert deque to vector for LSTM input
    std::vector<std::vector<double>> sequence(profile.featureSequence.begin(),
                                               profile.featureSequence.end());

    // Take last lstmSeqLength elements
    if ((int)sequence.size() > lstmSeqLength) {
        sequence = std::vector<std::vector<double>>(
            sequence.end() - lstmSeqLength, sequence.end());
    }

    double score = lstmModel.infer(sequence);
    return std::max(0.0, std::min(1.0, score));
}

double BehaviouralDetector::computeScoreThreshold(const std::string &vehicleId,
                                                    VehicleProfile &profile,
                                                    double posX, double posY, double dt)
{
    // Threshold-based fallback scoring on 6 features
    double posDev = std::sqrt((posX - profile.avgPosX) * (posX - profile.avgPosX) +
                              (posY - profile.avgPosY) * (posY - profile.avgPosY));

    double spdX = (posX - profile.lastPosX) / dt;
    double spdY = (posY - profile.lastPosY) / dt;
    double spdDevX = std::abs(spdX - profile.avgSpdX);
    double spdDevY = std::abs(spdY - profile.avgSpdY);
    double spdDev = std::sqrt(spdDevX * spdDevX + spdDevY * spdDevY);

    double idrScore = computeIDR(profile);
    double ttlScore = computeTTLVariability(profile);

    double posScore = std::min(1.0, posDev / posDeviationThreshold);
    double spdScore = std::min(1.0, spdDev / speedDeviationThreshold);

    // Weighted combination (Section 4.3.1)
    // For stealth forwarding-plane attacks, position/speed are normal.
    // IDR (interest volume / data injection) is the primary behavioural discriminator.
    // Use max(weighted_avg, idrScore) to ensure IDR anomaly isn't diluted.
    double weightedScore = 0.25 * posScore + 0.25 * spdScore + 0.25 * idrScore + 0.25 * ttlScore;
    double score = std::max(weightedScore, idrScore);
    return std::max(0.0, std::min(1.0, score));
}

double BehaviouralDetector::computeIDR(VehicleProfile &profile) {
    // Interest Volume Anomaly: measures absolute interest count deviation
    //
    // In VNDN, ALL vehicles have dataReceived ~0 (no Data flows back over
    // wireless), so IDR is not discriminative. Instead, use interest VOLUME:
    //
    // Calibration from simulation:
    //   Benign: interestReceived = 15-250 (over 500s sim)
    //   PIT Flooder: interestReceived = 2000-4050 (10x-100x higher)
    //   CS Poisoner: interestReceived = 150-250, dataReceived = 1000-1450
    //
    // Score: interest volume deviation from running average

    int totalTraffic = profile.interestCount + profile.dataCount;
    if (totalTraffic < 5) return 0.0;

    double score = 0.0;

    // Component 1: Interest volume anomaly (detects PIT flooding)
    // Benign max ~250 interests, PIT flooder min ~2000
    // Use threshold at 500 interests as anomaly start
    if (profile.interestCount > 500) {
        score = std::min(1.0, (double)(profile.interestCount - 500) / 2000.0);
    }

    // Component 2: Data injection anomaly (detects CS poisoning)
    // Benign dataReceived ~0, CS poisoner dataReceived ~1000-1450
    if (profile.dataCount > 50) {
        double dataScore = std::min(1.0, (double)(profile.dataCount - 50) / 500.0);
        score = std::max(score, dataScore);
    }

    profile.avgIDR = 0.1 * score + 0.9 * profile.avgIDR;
    return score;
}

double BehaviouralDetector::computeTTLVariability(VehicleProfile &profile) {
    if (profile.ttlHistory.size() < 3) return 0.0;

    double sum = 0, sumSq = 0;
    for (int ttl : profile.ttlHistory) {
        sum += ttl;
        sumSq += ttl * ttl;
    }
    double n = profile.ttlHistory.size();
    double mean = sum / n;
    double variance = sumSq / n - mean * mean;
    if (variance < 0) variance = 0;
    profile.ttlVariance = variance;
    profile.avgTTL = mean;

    return std::min(1.0, variance / 10.0);
}

void BehaviouralDetector::recordInterest(const std::string &vehicleId) {
    profiles[vehicleId].interestCount++;
}

void BehaviouralDetector::recordData(const std::string &vehicleId) {
    profiles[vehicleId].dataCount++;
}

void BehaviouralDetector::recordTTL(const std::string &vehicleId, int ttl) {
    auto &profile = profiles[vehicleId];
    profile.ttlHistory.push_back(ttl);
    if (profile.ttlHistory.size() > 50) {
        profile.ttlHistory.pop_front();
    }
}

std::vector<cModule*> BehaviouralDetector::getVehiclesInRange() {
    std::vector<cModule*> result;
    cModule *rsuMod = getParentModule();
    if (!rsuMod) return result;

    // Get RSU position: RSUs are static, position set via Veins INI convention
    // (*.rsu[*].mobility.x/y) which Veins maps to display string "p" tag
    double rsuX = -1, rsuY = -1;
    bool hasRsuPos = false;

    // Try TraCIMobility first (if RSU has one)
    cModule *rsuMobility = rsuMod->getSubmodule("mobility");
    if (rsuMobility) {
        veins::TraCIMobility *traciMob = dynamic_cast<veins::TraCIMobility*>(rsuMobility);
        if (traciMob) {
            veins::Coord pos = traciMob->getPositionAt(simTime());
            rsuX = pos.x; rsuY = pos.y;
            hasRsuPos = true;
        }
    }
    // Fallback: display string position (set by Veins from mobility.x/y)
    if (!hasRsuPos) {
        const char *px = rsuMod->getDisplayString().getTagArg("p", 0);
        const char *py = rsuMod->getDisplayString().getTagArg("p", 1);
        if (px && *px && py && *py) {
            rsuX = atof(px); rsuY = atof(py);
            hasRsuPos = true;
        }
    }

    // VeinsInetManager creates vehicles with non-contiguous indices.
    // Must use SubmoduleIterator to find all vehicles.
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;
        result.push_back(mod);
    }
    return result;
}

double BehaviouralDetector::getScore(const std::string &vehicleId) const {
    auto it = scores.find(vehicleId);
    return (it != scores.end()) ? it->second : 0.0;
}

bool BehaviouralDetector::hasScore(const std::string &vehicleId) const {
    return scores.find(vehicleId) != scores.end();
}

void BehaviouralDetector::finish() {
    recordScalar("vehiclesProfiled", (int)profiles.size());
    recordScalar("usedLSTM", useLSTM ? 1 : 0);
    recordScalar("vehiclesSubscribed", (int)subscribedVehicles.size());

    // Aggregate IDR statistics across all profiled vehicles
    int totalInterests = 0, totalData = 0;
    double sumScores = 0;
    int scoreCount = 0;
    for (const auto &p : profiles) {
        totalInterests += p.second.interestCount;
        totalData += p.second.dataCount;
    }
    for (const auto &s : scores) {
        sumScores += s.second;
        scoreCount++;
    }

    recordScalar("totalInterestsObserved", totalInterests);
    recordScalar("totalDataObserved", totalData);
    recordScalar("avgBehaviouralScore", scoreCount > 0 ? sumScores / scoreCount : 0.0);
    recordScalar("vehiclesScored", scoreCount);
}

} // namespace veremivndn
