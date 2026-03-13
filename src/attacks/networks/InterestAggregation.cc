//
// VeReMiVNDN - Interest Aggregation Attack Implementation
//

#include "InterestAggregation.h"
#include <sstream>

namespace veremivndn {

Define_Module(InterestAggregation);

InterestAggregation::InterestAggregation()
    : craftedAggregation(true), resourceImbalance(true), preventMapping(false),
      aggregationRate(50), interestsCrafted(0), aggregationsPrevented(0),
      pitEntriesExhausted(0), mode(AggregationMode::PREVENT_AGGREGATION) {
    rng.seed(std::random_device{}());
}

InterestAggregation::~InterestAggregation() {
}

void InterestAggregation::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        craftedAggregation = getParameterBool("craftedAggregation", true);
        resourceImbalance = getParameterBool("resourceImbalance", true);
        preventMapping = getParameterBool("preventMapping", false);
        targetPrefix = getParameter("targetPrefix", "/traffic");
        aggregationRate = getParameterInt("aggregationRate", 50);

        // Determine attack mode
        if (preventMapping) {
            mode = AggregationMode::PREVENT_AGGREGATION;
        } else if (resourceImbalance) {
            mode = AggregationMode::IMBALANCED_LOAD;
        } else {
            mode = AggregationMode::FORCE_AGGREGATION;
        }

        // Register signals
        interestsCraftedSignal = registerSignal("interestsCrafted");
        aggregationPreventedSignal = registerSignal("aggregationPrevented");
        pitImbalanceSignal = registerSignal("pitImbalance");

        interestsCrafted = 0;
        aggregationsPrevented = 0;
        pitEntriesExhausted = 0;

        EV_INFO << "InterestAggregation attack initialized at node " << nodeIdentifier
                << " targeting prefix: " << targetPrefix
                << ", mode: " << (int)mode << endl;
    }
}

void InterestAggregation::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void InterestAggregation::finish() {
    AttackBase::finish();
    recordScalar("interestsCrafted", interestsCrafted);
    recordScalar("aggregationsPrevented", aggregationsPrevented);
    recordScalar("pitEntriesExhausted", pitEntriesExhausted);
    recordScalar("aggregationRatio", calculateAggregationRatio());
}

void InterestAggregation::startAttack() {
    EV_INFO << "Starting Interest Aggregation attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Interest aggregation manipulation initiated");
}

void InterestAggregation::stopAttack() {
    EV_INFO << "Stopping Interest Aggregation attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Interests crafted: " + std::to_string(interestsCrafted));

    aggregationMap.clear();
    usedNonces.clear();
}

void InterestAggregation::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Generate crafted Interests at specified rate
    double intervalSeconds = 1.0 / aggregationRate;
    if (uniform(0, 1) < intervalSeconds * 10) {  // Approximate rate control

        InterestPacket *interest = nullptr;

        switch (mode) {
            case AggregationMode::PREVENT_AGGREGATION:
                interest = craftNonAggregatingInterest();
                aggregationsPrevented++;
                emit(aggregationPreventedSignal, 1L);
                break;

            case AggregationMode::FORCE_AGGREGATION:
                interest = craftAggregationInterest();
                break;

            case AggregationMode::IMBALANCED_LOAD:
                interest = craftImbalancedInterest();
                emit(pitImbalanceSignal, 1L);
                break;

            case AggregationMode::TIMING_MANIPULATION:
                manipulateInterestTiming();
                interest = craftAggregationInterest();
                break;
        }

        if (interest) {
            // Send crafted Interest to NDN forwarder
            send(interest, "ndnOut");

            interestsCrafted++;
            emit(interestsCraftedSignal, 1L);
            stats.packetsGenerated++;

            // Track aggregation
            std::string name = interest->getName();
            aggregationMap[name]++;

            EV_DEBUG << "Crafted Interest sent: " << name
                     << ", mode: " << (int)mode << endl;
        }
    }

    // Periodically monitor PIT aggregation
    if ((int)simTime().dbl() % 5 == 0) {
        monitorPitAggregation();
    }
}

InterestPacket* InterestAggregation::craftAggregationInterest() {
    // Craft Interest that will force aggregation with many similar Interests
    InterestPacket *interest = new InterestPacket("CraftedInterest");

    // Use same name to force aggregation
    std::stringstream ss;
    ss << targetPrefix << "/aggregation/" << (int)simTime().dbl() / 10;
    interest->setName(ss.str().c_str());

    // Use SAME nonce to force aggregation (violating NDN semantics)
    interest->setNonce(12345);  // Fixed nonce

    interest->setHopCount(0);
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());

    return interest;
}

InterestPacket* InterestAggregation::craftNonAggregatingInterest() {
    // Craft Interest that prevents proper aggregation by using unique nonces/names
    InterestPacket *interest = new InterestPacket("NonAggregatingInterest");

    // Use slightly different names to prevent aggregation
    std::stringstream ss;
    ss << targetPrefix << "/nonagg/" << simTime().dbl()
       << "/" << nodeId << "/" << interestsCrafted;
    interest->setName(ss.str().c_str());

    // Generate UNIQUE nonce for each Interest
    interest->setNonce(generateUniqueNonce());

    interest->setHopCount(0);
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());

    EV_DEBUG << "Non-aggregating Interest crafted with unique nonce: "
             << interest->getNonce() << endl;

    return interest;
}

InterestPacket* InterestAggregation::craftImbalancedInterest() {
    // Craft Interest that creates resource imbalance in PIT
    InterestPacket *interest = new InterestPacket("ImbalancedInterest");

    // Target specific prefixes to create imbalance
    std::stringstream ss;
    int bucket = intuniform(0, 4);  // Create 5 heavily loaded buckets
    ss << targetPrefix << "/imbalance/bucket" << bucket
       << "/seq/" << interestsCrafted;
    interest->setName(ss.str().c_str());

    interest->setNonce(generateUniqueNonce());
    interest->setHopCount(0);
    interest->setInterestLifetime(10.0);  // Longer lifetime to exhaust PIT
    interest->setTimestamp(simTime());

    pitEntriesExhausted++;

    return interest;
}

int InterestAggregation::generateUniqueNonce() {
    int nonce;
    do {
        nonce = intuniform(1, 2000000000);
    } while (usedNonces.find(nonce) != usedNonces.end());

    usedNonces.insert(nonce);

    // Clear old nonces periodically to prevent memory buildup
    if (usedNonces.size() > 10000) {
        usedNonces.clear();
    }

    return nonce;
}

void InterestAggregation::manipulateInterestTiming() {
    // Manipulate timing to affect aggregation behavior
    // Slight delay to de-synchronize with legitimate Interests
    simtime_t delay = uniform(0.001, 0.01);
    EV_DEBUG << "Timing manipulation: delay=" << delay << "s" << endl;
}

void InterestAggregation::createPitImbalance() {
    // Create imbalance by flooding specific PIT partitions
    EV_DEBUG << "Creating PIT imbalance across " << aggregationMap.size()
             << " prefixes" << endl;
}

void InterestAggregation::monitorPitAggregation() {
    // Monitor PIT aggregation effectiveness
    double ratio = calculateAggregationRatio();

    EV_DEBUG << "PIT Aggregation monitoring: ratio=" << ratio
             << ", entries=" << aggregationMap.size()
             << ", interests=" << interestsCrafted << endl;
}

double InterestAggregation::calculateAggregationRatio() {
    if (interestsCrafted == 0) return 0.0;

    // Calculate ratio of unique PIT entries to total Interests
    // Low ratio = high aggregation, High ratio = low aggregation
    double ratio = (double)aggregationMap.size() / interestsCrafted;

    return ratio;
}

cMessage* InterestAggregation::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Interest packets and manipulate aggregation behavior

    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    if (!interest) {
        // Not an Interest packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    // Manipulate Interest to prevent PIT aggregation
    // Change nonce to make it unique (prevents aggregation)
    int newNonce = generateUniqueNonce();
    interest->setNonce(newNonce);

    // Also append unique suffix to name
    std::string originalName = interest->getName();
    std::stringstream ss;
    ss << originalName << "/noagg/" << interestsCrafted;
    interest->setName(ss.str().c_str());

    aggregationsPrevented++;
    emit(aggregationPreventedSignal, 1L);
    stats.packetsModified++;

    EV_WARN << "PREVENT_AGG: Interest '" << originalName
            << "' modified with unique nonce " << newNonce << endl;

    return interest;
}

} // namespace veremivndn
