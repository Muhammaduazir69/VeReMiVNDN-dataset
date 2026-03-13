//
// VeReMiVNDN - Cross-Layer Jamming / Radio Interference Attack
//
// Attack #14: Cross-Layer Jamming / Radio Interference
// Layer: PHY / Link
// Description: Traditional radio jamming targeting DSRC/C-V2X to block VNDN traffic
//              at the physical layer, affecting both Interest and Data delivery
// Impact: Wide-area DoS, complete communication loss, safety message blocking, network partition
//

#ifndef __VEREMIVNDN_RADIOJAMMING_H
#define __VEREMIVNDN_RADIOJAMMING_H

#include "../AttackBase.h"
#include <random>

namespace veremivndn {

/**
 * Jamming Attack Types
 */
enum class JammingType {
    CONSTANT,           // Continuous jamming
    REACTIVE,           // Jam when detecting transmissions
    DECEPTIVE,          // Send fake packets to confuse receivers
    RANDOM,             // Random intermittent jamming
    SWEEP               // Frequency sweeping jamming
};

/**
 * RadioJamming
 *
 * Implements Cross-Layer Radio Jamming attack that interferes
 * with wireless communications at the physical layer, blocking
 * NDN Interest and Data packet transmission.
 *
 * Attack Parameters (JSON):
 * - jammingPower: double - Jamming power in dBm (default: 30.0)
 * - dutyCycle: double - Duty cycle 0.0-1.0 (default: 0.8)
 * - targetChannel: int - Target channel frequency (default: 178 for DSRC)
 * - jammingType: string - Type of jamming (default: "CONSTANT")
 * - range: double - Jamming range in meters (default: 200.0)
 */
class RadioJamming : public AttackBase
{
private:
    // Attack parameters
    double jammingPower;      // dBm
    double dutyCycle;         // 0.0 to 1.0
    int targetChannel;        // Channel frequency
    JammingType jammingType;
    double jammingRange;      // meters

    // Attack state
    bool jammingActive;
    uint64_t packetsJammed;
    uint64_t transmissionsPrevented;
    simtime_t totalJammingTime;
    simtime_t lastJammingToggle;

    // Jamming control
    cMessage *jammingToggleMsg;
    cMessage *sweepMsg;

    // Random generation
    std::mt19937 rng;

    // Statistics
    simsignal_t packetsJammedSignal;
    simsignal_t jammingPowerSignal;
    simsignal_t channelOccupancySignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;

    // Packet manipulation - CRITICAL for actually affecting traffic
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Jamming methods
    void enableJamming();
    void disableJamming();
    void toggleJamming();
    void performConstantJamming();
    void performReactiveJamming();
    void performDeceptiveJamming();
    void performRandomJamming();
    void performSweepJamming();

    // Interference simulation
    void generateInterference();
    bool isInJammingRange(double distance);
    double calculateInterferencePower(double distance);

public:
    RadioJamming();
    virtual ~RadioJamming();

    // Attack-specific getters
    uint64_t getPacketsJammed() const { return packetsJammed; }
    double getJammingPower() const { return jammingPower; }
    bool isJammingActive() const { return jammingActive; }
};

Define_Module(RadioJamming);

} // namespace veremivndn

#endif // __VEREMIVNDN_RADIOJAMMING_H
