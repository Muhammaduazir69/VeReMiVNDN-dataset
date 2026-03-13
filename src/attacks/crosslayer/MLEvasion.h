//
// VeReMiVNDN - Machine Learning Evasion (Adversarial Content) Attack
//
// Attack #20: Machine Learning Evasion (Adversarial Content)
// Layer: Cross-layer / Application
// Description: Generates content or request patterns that evade ML-based IDS through
//              adversarial examples, reducing detector effectiveness
// Impact: IDS evasion, reduced detection rates, false negatives, security degradation
//

#ifndef __VEREMIVNDN_MLEVASION_H
#define __VEREMIVNDN_MLEVASION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Evasion Techniques
 */
enum class EvasionTechnique {
    GRADIENT_BASED,         // Use gradient-based adversarial examples
    FEATURE_MANIPULATION,   // Manipulate specific features
    PATTERN_OBFUSCATION,    // Obfuscate attack patterns
    MIMICRY,                // Mimic benign behavior
    TIMING_MANIPULATION     // Manipulate timing to evade detection
};

/**
 * Target ML Models
 */
enum class TargetModel {
    RANDOM_FOREST,
    NEURAL_NETWORK,
    SVM,
    DECISION_TREE,
    ENSEMBLE
};

/**
 * MLEvasion
 *
 * Implements Machine Learning Evasion attack that crafts
 * adversarial examples and behavioral patterns specifically
 * designed to evade ML-based intrusion detection systems.
 *
 * Attack Parameters (JSON):
 * - adversarialPattern: bool - Use adversarial patterns (default: true)
 * - evasionTechnique: string - Evasion technique (default: "gradient-based")
 * - targetModel: string - Target ML model (default: "RandomForest")
 * - perturbationLevel: double - Feature perturbation level 0.0-1.0 (default: 0.3)
 * - mimicBenign: bool - Mimic benign behavior (default: true)
 */
class MLEvasion : public AttackBase
{
private:
    // Attack parameters
    bool adversarialPattern;
    EvasionTechnique technique;
    TargetModel targetModel;
    double perturbationLevel;
    bool mimicBenign;

    // Attack state
    uint64_t adversarialExamplesGenerated;
    uint64_t featuresPerturbated;
    uint64_t evasionAttempts;
    uint64_t successfulEvasions;
    std::map<std::string, double> featureValues;
    std::vector<double> perturbations;

    // Statistics
    simsignal_t adversarialExamplesSignal;
    simsignal_t evasionSuccessSignal;
    simsignal_t featurePerturbationSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Adversarial generation
    cMessage* generateAdversarialExample();
    void applyGradientBasedPerturbation();
    void manipulateFeatures();
    void obfuscatePatterns();
    void mimicBenignBehavior();
    void manipulateTiming();

    // Feature manipulation
    void perturbateFeature(const std::string &featureName, double delta);
    double calculatePerturbation(const std::string &featureName);
    bool isDetectable(const std::map<std::string, double> &features);

    // Evasion optimization
    void optimizeEvasion();
    double calculateEvasionScore();

public:
    MLEvasion();
    virtual ~MLEvasion();

    // Attack-specific getters
    uint64_t getAdversarialExamplesGenerated() const { return adversarialExamplesGenerated; }
    uint64_t getSuccessfulEvasions() const { return successfulEvasions; }
    double getEvasionRate() const;
};

Define_Module(MLEvasion);

} // namespace veremivndn

#endif // __VEREMIVNDN_MLEVASION_H
