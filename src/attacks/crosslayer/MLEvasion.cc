//
// VeReMiVNDN - ML Evasion Attack Implementation
//

#include "MLEvasion.h"
#include <sstream>
#include <cmath>

namespace veremivndn {

Define_Module(MLEvasion);

MLEvasion::MLEvasion()
    : adversarialPattern(true), technique(EvasionTechnique::GRADIENT_BASED),
      targetModel(TargetModel::RANDOM_FOREST), perturbationLevel(0.3),
      mimicBenign(true), adversarialExamplesGenerated(0), featuresPerturbated(0),
      evasionAttempts(0), successfulEvasions(0) {
}

MLEvasion::~MLEvasion() {
}

void MLEvasion::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        adversarialPattern = getParameterBool("adversarialPattern", true);
        perturbationLevel = getParameterDouble("perturbationLevel", 0.3);
        mimicBenign = getParameterBool("mimicBenign", true);

        // Parse evasion technique
        std::string techniqueStr = getParameter("evasionTechnique", "gradient-based");
        if (techniqueStr == "feature-manipulation") {
            technique = EvasionTechnique::FEATURE_MANIPULATION;
        } else if (techniqueStr == "pattern-obfuscation") {
            technique = EvasionTechnique::PATTERN_OBFUSCATION;
        } else if (techniqueStr == "mimicry") {
            technique = EvasionTechnique::MIMICRY;
        } else if (techniqueStr == "timing") {
            technique = EvasionTechnique::TIMING_MANIPULATION;
        } else {
            technique = EvasionTechnique::GRADIENT_BASED;
        }

        // Parse target model
        std::string modelStr = getParameter("targetModel", "RandomForest");
        if (modelStr == "NeuralNetwork") {
            targetModel = TargetModel::NEURAL_NETWORK;
        } else if (modelStr == "SVM") {
            targetModel = TargetModel::SVM;
        } else if (modelStr == "DecisionTree") {
            targetModel = TargetModel::DECISION_TREE;
        } else if (modelStr == "Ensemble") {
            targetModel = TargetModel::ENSEMBLE;
        } else {
            targetModel = TargetModel::RANDOM_FOREST;
        }

        // Register signals
        adversarialExamplesSignal = registerSignal("adversarialExamples");
        evasionSuccessSignal = registerSignal("evasionSuccess");
        featurePerturbationSignal = registerSignal("featurePerturbation");

        adversarialExamplesGenerated = 0;
        featuresPerturbated = 0;
        evasionAttempts = 0;
        successfulEvasions = 0;

        EV_INFO << "MLEvasion attack initialized at node " << nodeIdentifier
                << ", technique: " << (int)technique
                << ", target model: " << (int)targetModel
                << ", perturbation level: " << perturbationLevel << endl;
    }
}

void MLEvasion::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void MLEvasion::finish() {
    AttackBase::finish();
    recordScalar("adversarialExamplesGenerated", adversarialExamplesGenerated);
    recordScalar("featuresPerturbated", featuresPerturbated);
    recordScalar("evasionAttempts", evasionAttempts);
    recordScalar("successfulEvasions", successfulEvasions);
    recordScalar("evasionRate", getEvasionRate());
}

void MLEvasion::startAttack() {
    EV_INFO << "Starting ML Evasion attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "ML evasion attack initiated against " +
                           std::to_string((int)targetModel) + " model");
}

void MLEvasion::stopAttack() {
    EV_INFO << "Stopping ML Evasion attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Adversarial examples: " + std::to_string(adversarialExamplesGenerated) +
                           ", Evasion rate: " + std::to_string(getEvasionRate()));

    featureValues.clear();
    perturbations.clear();
}

void MLEvasion::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Apply evasion technique
    switch (technique) {
        case EvasionTechnique::GRADIENT_BASED:
            applyGradientBasedPerturbation();
            break;

        case EvasionTechnique::FEATURE_MANIPULATION:
            manipulateFeatures();
            break;

        case EvasionTechnique::PATTERN_OBFUSCATION:
            obfuscatePatterns();
            break;

        case EvasionTechnique::MIMICRY:
            mimicBenignBehavior();
            break;

        case EvasionTechnique::TIMING_MANIPULATION:
            manipulateTiming();
            break;
    }

    // Generate adversarial example
    if (uniform(0, 1) < 0.3) {  // 30% chance
        cMessage *adversarial = generateAdversarialExample();
        if (adversarial) {
            send(adversarial, "ndnOut");
        }
    }

    // Periodically optimize evasion
    if ((int)simTime().dbl() % 5 == 0) {
        optimizeEvasion();
    }
}

cMessage* MLEvasion::generateAdversarialExample() {
    // Generate adversarial packet that evades ML detection
    InterestPacket *adversarial = new InterestPacket("AdversarialInterest");

    // Craft name with perturbations
    std::stringstream ss;
    ss << "/adversarial/" << adversarialExamplesGenerated
       << "/perturb/" << perturbationLevel;
    adversarial->setName(ss.str().c_str());

    adversarial->setNonce(intuniform(1, 2000000000));
    adversarial->setHopCount(0);
    adversarial->setInterestLifetime(4.0);
    adversarial->setTimestamp(simTime());

    adversarialExamplesGenerated++;
    emit(adversarialExamplesSignal, 1L);
    stats.packetsGenerated++;

    // Check if evasion successful (simulated)
    evasionAttempts++;
    if (uniform(0, 1) < (1.0 - perturbationLevel)) {  // Lower perturbation = higher success
        successfulEvasions++;
        emit(evasionSuccessSignal, 1L);
        EV_WARN << "ML EVASION SUCCESS: Adversarial example evaded detection" << endl;
    }

    EV_DEBUG << "Generated adversarial example: " << adversarialExamplesGenerated << endl;

    return adversarial;
}

void MLEvasion::applyGradientBasedPerturbation() {
    // Apply gradient-based perturbations to features
    // Simulates FGSM (Fast Gradient Sign Method) or similar

    std::vector<std::string> features = {
        "packetRate", "pitOccupancy", "interestRate", "dataRate", "cacheHitRatio"
    };

    for (const auto &feature : features) {
        double perturbation = calculatePerturbation(feature);
        perturbateFeature(feature, perturbation);
    }

    EV_DEBUG << "Applied gradient-based perturbations to " << features.size() << " features" << endl;
}

void MLEvasion::manipulateFeatures() {
    // Directly manipulate specific features to evade detection

    // Manipulate packet rate to appear benign
    perturbateFeature("packetRate", -perturbationLevel * 50);

    // Manipulate PIT occupancy
    perturbateFeature("pitOccupancy", perturbationLevel * 10);

    // Add noise to timing features
    perturbateFeature("interArrivalTime", uniform(-perturbationLevel, perturbationLevel));

    featuresPerturbated += 3;
    emit(featurePerturbationSignal, 3L);

    EV_DEBUG << "Manipulated features for evasion" << endl;
}

void MLEvasion::obfuscatePatterns() {
    // Obfuscate attack patterns by adding randomness

    // Vary attack intensity
    double obfuscatedIntensity = intensity + uniform(-0.2, 0.2);
    obfuscatedIntensity = std::max(0.1, std::min(1.0, obfuscatedIntensity));

    // Add random delays
    double randomDelay = uniform(0, perturbationLevel);

    EV_DEBUG << "Obfuscated attack pattern with intensity: " << obfuscatedIntensity
             << ", delay: " << randomDelay << endl;

    stats.packetsModified++;
}

void MLEvasion::mimicBenignBehavior() {
    // Mimic benign traffic patterns to evade detection

    if (!mimicBenign) return;

    // Reduce attack rate to match benign traffic
    double benignRate = 10.0;  // Normal benign packet rate
    double mimicProbability = benignRate / (benignRate + intensity * 100);

    if (uniform(0, 1) < mimicProbability) {
        // Act benign this cycle
        EV_DEBUG << "Mimicking benign behavior" << endl;
        return;
    }

    // Mix malicious packets with benign-looking ones
    if (uniform(0, 1) < 0.5) {
        stats.packetsGenerated++;
        EV_DEBUG << "Generated benign-looking packet for mimicry" << endl;
    }
}

void MLEvasion::manipulateTiming() {
    // Manipulate timing characteristics to evade temporal features

    // Add jitter to timing
    double jitter = uniform(0, perturbationLevel * 0.1);

    // Vary inter-arrival times
    perturbateFeature("interArrivalTime", jitter);

    EV_DEBUG << "Manipulated timing with jitter: " << jitter << endl;
}

void MLEvasion::perturbateFeature(const std::string &featureName, double delta) {
    // Apply perturbation to specific feature
    featureValues[featureName] += delta;
    perturbations.push_back(delta);

    featuresPerturbated++;
    emit(featurePerturbationSignal, 1L);

    EV_TRACE << "Perturbated feature '" << featureName << "' by " << delta << endl;
}

double MLEvasion::calculatePerturbation(const std::string &featureName) {
    // Calculate optimal perturbation for the feature
    // Simplified - in reality would use gradient information

    double epsilon = perturbationLevel;
    double sign = (uniform(0, 1) < 0.5) ? -1.0 : 1.0;

    return sign * epsilon * uniform(0.5, 1.5);
}

bool MLEvasion::isDetectable(const std::map<std::string, double> &features) {
    // Simplified detectability check
    // In reality would query actual ML model

    double anomalyScore = 0.0;

    for (const auto &entry : features) {
        anomalyScore += std::abs(entry.second);
    }

    double threshold = 100.0 * (1.0 - perturbationLevel);
    return (anomalyScore > threshold);
}

void MLEvasion::optimizeEvasion() {
    // Optimize evasion strategy based on success rate
    double currentEvasionRate = getEvasionRate();

    EV_DEBUG << "Optimizing evasion strategy. Current rate: " << currentEvasionRate << endl;

    // Adjust perturbation level based on success
    if (currentEvasionRate < 0.5) {
        // Need more evasion - increase perturbation
        perturbationLevel = std::min(1.0, perturbationLevel * 1.1);
    } else if (currentEvasionRate > 0.8) {
        // Very successful - can reduce perturbation
        perturbationLevel = std::max(0.1, perturbationLevel * 0.9);
    }

    EV_DEBUG << "Adjusted perturbation level to: " << perturbationLevel << endl;
}

double MLEvasion::calculateEvasionScore() {
    // Calculate overall evasion effectiveness score
    if (evasionAttempts == 0) return 0.0;

    double successRate = (double)successfulEvasions / evasionAttempts;
    double coverageScore = std::min(1.0, adversarialExamplesGenerated / 100.0);

    return (successRate * 0.7) + (coverageScore * 0.3);
}

double MLEvasion::getEvasionRate() const {
    if (evasionAttempts == 0) return 0.0;
    return (double)successfulEvasions / evasionAttempts;
}

cMessage* MLEvasion::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept packets and apply adversarial perturbations to evade ML-based IDS

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    DataPacket *data = dynamic_cast<DataPacket*>(msg);

    if (!interest && !data) {
        return msg;  // Unknown packet type
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    evasionAttempts++;

    // Apply ML evasion perturbations to packets
    if (interest) {
        std::string name = interest->getName();

        // Apply small adversarial perturbations to Interest features
        // Modify timing slightly
        double timingPerturbation = uniform(-0.01, 0.01);
        interest->setTimestamp(interest->getTimestamp() + timingPerturbation);

        // Modify priority slightly to evade detection patterns
        int currentPriority = interest->getPriority();
        interest->setPriority(std::max(0, std::min(10, currentPriority + intuniform(-1, 1))));

        // Modify interest lifetime slightly
        simtime_t lifetime = interest->getInterestLifetime();
        interest->setInterestLifetime(lifetime.dbl() * (1.0 + uniform(-0.05, 0.05)));

        adversarialExamplesGenerated++;
        emit(adversarialExamplesSignal, 1L);
        stats.packetsModified++;

        EV_WARN << "ML_EVASION: Applied adversarial perturbations to Interest '" << name << "'" << endl;
    }
    else if (data) {
        std::string name = data->getName();

        // Apply adversarial perturbations to Data features
        // Perturb trust score slightly
        double trust = data->getTrustScore();
        data->setTrustScore(std::max(0.0, std::min(1.0, trust + uniform(-0.05, 0.05))));

        // Perturb freshness slightly
        simtime_t freshness = data->getFreshnessPeriod();
        data->setFreshnessPeriod(freshness.dbl() * (1.0 + uniform(-0.1, 0.1)));

        adversarialExamplesGenerated++;
        stats.packetsModified++;

        EV_WARN << "ML_EVASION: Applied adversarial perturbations to Data '" << name << "'" << endl;
    }

    // Track evasion success
    if (uniform(0, 1) < 0.6) {  // 60% evasion success rate
        successfulEvasions++;
        emit(evasionSuccessSignal, 1L);
    }

    return msg;
}

} // namespace veremivndn
