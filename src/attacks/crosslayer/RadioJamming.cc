//
// VeReMiVNDN - Radio Jamming Attack Implementation
//

#include "RadioJamming.h"
#include <cmath>

namespace veremivndn {

Define_Module(RadioJamming);

RadioJamming::RadioJamming()
    : jammingPower(30.0), dutyCycle(0.8), targetChannel(178),
      jammingType(JammingType::CONSTANT), jammingRange(200.0),
      jammingActive(false), packetsJammed(0), transmissionsPrevented(0),
      totalJammingTime(0), jammingToggleMsg(nullptr), sweepMsg(nullptr) {
    rng.seed(std::random_device{}());
}

RadioJamming::~RadioJamming() {
    cancelAndDelete(jammingToggleMsg);
    cancelAndDelete(sweepMsg);
}

void RadioJamming::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        jammingPower = getParameterDouble("jammingPower", 30.0);
        dutyCycle = getParameterDouble("dutyCycle", 0.8);
        targetChannel = getParameterInt("targetChannel", 178);
        jammingRange = getParameterDouble("range", 200.0);

        std::string typeStr = getParameter("jammingType", "CONSTANT");
        if (typeStr == "REACTIVE") {
            jammingType = JammingType::REACTIVE;
        } else if (typeStr == "DECEPTIVE") {
            jammingType = JammingType::DECEPTIVE;
        } else if (typeStr == "RANDOM") {
            jammingType = JammingType::RANDOM;
        } else if (typeStr == "SWEEP") {
            jammingType = JammingType::SWEEP;
        } else {
            jammingType = JammingType::CONSTANT;
        }

        // Register signals
        packetsJammedSignal = registerSignal("packetsJammed");
        jammingPowerSignal = registerSignal("jammingPower");
        channelOccupancySignal = registerSignal("channelOccupancy");

        packetsJammed = 0;
        transmissionsPrevented = 0;
        totalJammingTime = 0;
        jammingActive = false;
        lastJammingToggle = 0;

        EV_INFO << "RadioJamming attack initialized at node " << nodeIdentifier
                << ", power: " << jammingPower << " dBm"
                << ", duty cycle: " << dutyCycle
                << ", channel: " << targetChannel
                << ", type: " << (int)jammingType << endl;
    }
}

void RadioJamming::handleMessage(cMessage *msg) {
    if (msg == jammingToggleMsg) {
        toggleJamming();
    } else if (msg == sweepMsg) {
        performSweepJamming();
        if (attackActive) {
            scheduleAt(simTime() + 0.01, sweepMsg);  // Sweep every 10ms
        }
    } else {
        AttackBase::handleMessage(msg);
    }
}

void RadioJamming::finish() {
    AttackBase::finish();
    recordScalar("packetsJammed", packetsJammed);
    recordScalar("transmissionsPrevented", transmissionsPrevented);
    recordScalar("totalJammingTime", totalJammingTime.dbl());
    recordScalar("jammingDutyCycle", dutyCycle);
    recordScalar("jammingPower", jammingPower);
}

void RadioJamming::startAttack() {
    EV_INFO << "Starting Radio Jamming attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Radio jamming initiated on channel " + std::to_string(targetChannel));

    // Enable jamming based on type
    if (jammingType == JammingType::CONSTANT) {
        enableJamming();
    } else if (jammingType == JammingType::RANDOM) {
        // Schedule random toggling
        jammingToggleMsg = new cMessage("jammingToggle");
        scheduleAt(simTime() + uniform(0.1, 1.0), jammingToggleMsg);
    } else if (jammingType == JammingType::SWEEP) {
        enableJamming();
        sweepMsg = new cMessage("sweep");
        scheduleAt(simTime() + 0.01, sweepMsg);
    } else {
        enableJamming();
    }
}

void RadioJamming::stopAttack() {
    EV_INFO << "Stopping Radio Jamming attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Packets jammed: " + std::to_string(packetsJammed));

    disableJamming();
    cancelAndDelete(jammingToggleMsg);
    jammingToggleMsg = nullptr;
    cancelAndDelete(sweepMsg);
    sweepMsg = nullptr;
}

void RadioJamming::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Execute jamming based on type
    switch (jammingType) {
        case JammingType::CONSTANT:
            performConstantJamming();
            break;

        case JammingType::REACTIVE:
            performReactiveJamming();
            break;

        case JammingType::DECEPTIVE:
            performDeceptiveJamming();
            break;

        case JammingType::RANDOM:
            performRandomJamming();
            break;

        case JammingType::SWEEP:
            // Handled by sweep message
            break;
    }
}

void RadioJamming::enableJamming() {
    jammingActive = true;
    lastJammingToggle = simTime();

    emit(jammingPowerSignal, jammingPower);
    emit(channelOccupancySignal, 1L);

    EV_WARN << "JAMMING ENABLED: Power=" << jammingPower
            << " dBm, Channel=" << targetChannel << endl;
}

void RadioJamming::disableJamming() {
    if (jammingActive) {
        totalJammingTime += simTime() - lastJammingToggle;
    }

    jammingActive = false;

    emit(jammingPowerSignal, 0.0);
    emit(channelOccupancySignal, 0L);

    EV_DEBUG << "Jamming disabled" << endl;
}

void RadioJamming::toggleJamming() {
    if (jammingActive) {
        disableJamming();
        // Schedule next enable based on duty cycle
        double offTime = (1.0 - dutyCycle) / dutyCycle * uniform(0.1, 0.5);
        scheduleAt(simTime() + offTime, jammingToggleMsg);
    } else {
        enableJamming();
        // Schedule next disable based on duty cycle
        double onTime = dutyCycle * uniform(0.1, 0.5);
        scheduleAt(simTime() + onTime, jammingToggleMsg);
    }
}

void RadioJamming::performConstantJamming() {
    // Continuous interference generation
    if (jammingActive && uniform(0, 1) < dutyCycle) {
        generateInterference();

        packetsJammed++;
        emit(packetsJammedSignal, 1L);
        stats.packetsGenerated++;

        EV_DEBUG << "Constant jamming: packets jammed=" << packetsJammed << endl;
    }
}

void RadioJamming::performReactiveJamming() {
    // React to detected transmissions (simplified simulation)
    // In real implementation, would detect carrier sense

    if (uniform(0, 1) < 0.3) {  // 30% chance of detecting transmission
        enableJamming();
        generateInterference();

        packetsJammed++;
        transmissionsPrevented++;
        emit(packetsJammedSignal, 1L);
        stats.packetsGenerated++;

        EV_WARN << "Reactive jamming triggered: blocked transmission" << endl;

        // Disable after short burst
        disableJamming();
    }
}

void RadioJamming::performDeceptiveJamming() {
    // Send fake packets to confuse receivers
    if (uniform(0, 1) < dutyCycle) {
        generateInterference();  // Simulate fake packet transmission

        packetsJammed++;
        emit(packetsJammedSignal, 1L);
        stats.packetsGenerated++;

        EV_DEBUG << "Deceptive jamming: fake packet sent" << endl;
    }
}

void RadioJamming::performRandomJamming() {
    // Random intermittent jamming (handled by toggle message)
    if (jammingActive) {
        generateInterference();

        packetsJammed++;
        emit(packetsJammedSignal, 1L);
        stats.packetsGenerated++;
    }
}

void RadioJamming::performSweepJamming() {
    // Sweep across frequency channels
    static int currentSweepChannel = targetChannel - 2;

    currentSweepChannel++;
    if (currentSweepChannel > targetChannel + 2) {
        currentSweepChannel = targetChannel - 2;
    }

    generateInterference();

    packetsJammed++;
    emit(packetsJammedSignal, 1L);
    stats.packetsGenerated++;

    EV_DEBUG << "Sweep jamming: channel=" << currentSweepChannel << endl;
}

void RadioJamming::generateInterference() {
    // Generate interference signal
    // In real implementation, this would interface with PHY layer

    emit(jammingPowerSignal, jammingPower);
    emit(channelOccupancySignal, 1L);

    EV_TRACE << "Interference generated: power=" << jammingPower
             << " dBm, channel=" << targetChannel << endl;
}

cMessage* RadioJamming::manipulatePacket(cMessage *msg) {
    // CRITICAL: This is what actually affects packets flowing through!
    // Without this, jamming only generates interference signals but doesn't block traffic

    if (!jammingActive) {
        // Jamming not active, forward normally
        return AttackBase::manipulatePacket(msg);
    }

    // Decision: DROP or DELAY based on jamming type and duty cycle
    double dropProbability = dutyCycle * 0.75;  // 60-80% drop rate for high duty cycle

    if (uniform(0, 1) < dropProbability) {
        // DROP the packet - simulate complete interference
        EV_WARN << "JAMMED: Dropping packet " << msg->getName()
                << " due to radio interference" << endl;

        delete msg;
        packetsJammed++;
        transmissionsPrevented++;
        stats.packetsDropped++;
        emit(packetsJammedSignal, 1L);

        return nullptr;  // Packet dropped
    }
    else if (uniform(0, 1) < 0.4) {
        // DELAY the packet - simulate degraded channel
        double delayAmount = uniform(0.2, 0.5);  // 200-500ms delay

        EV_WARN << "JAMMED: Delaying packet " << msg->getName()
                << " by " << delayAmount << "s due to interference" << endl;

        packetsJammed++;
        stats.packetsModified++;
        emit(packetsJammedSignal, 1L);

        // Send delayed via separate gate handling
        sendDelayed(msg, delayAmount, "ndnOut");
        return nullptr;  // Already handled
    }

    // Otherwise forward normally (survived jamming)
    return msg;
}

bool RadioJamming::isInJammingRange(double distance) {
    return distance <= jammingRange;
}

double RadioJamming::calculateInterferencePower(double distance) {
    // Calculate received interference power using free-space path loss
    // P_rx = P_tx - PathLoss
    // PathLoss = 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c)

    if (distance <= 0) return jammingPower;

    // Simplified path loss calculation
    double pathLoss = 20.0 * log10(distance) + 20.0 * log10(5.9e9) - 147.55;
    double receivedPower = jammingPower - pathLoss;

    return receivedPower;
}

} // namespace veremivndn
