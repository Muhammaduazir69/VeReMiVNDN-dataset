//
// VeReMiVNDN - Base Attack Module Header
//
// Base class for all attack implementations
//

#ifndef __VEREMIVNDN_ATTACKBASE_H
#define __VEREMIVNDN_ATTACKBASE_H

#include <omnetpp.h>
#include "../ndn/packets/NdnPackets_m.h"
#include <string>
#include <map>
#include <vector>

using namespace omnetpp;

namespace veremivndn {

/**
 * Attack Severity Levels
 */
enum class AttackSeverity {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

/**
 * Attack Layer Classification
 */
enum class AttackLayer {
    PHYSICAL,
    LINK,
    NETWORK,
    TRANSPORT,
    APPLICATION,
    DATA,
    CACHING,
    PRIVACY,
    TRUST,
    CROSSLAYER
};

/**
 * Attack Statistics Structure
 */
struct AttackStatistics {
    uint64_t packetsGenerated = 0;
    uint64_t packetsModified = 0;
    uint64_t packetsDropped = 0;
    uint64_t attacksLaunched = 0;
    simtime_t totalAttackDuration = 0;
    double avgIntensity = 0.0;
};

/**
 * AttackBase
 *
 * Abstract base class for all attack modules.
 * Provides common functionality for attack lifecycle, logging, and statistics.
 */
class AttackBase : public cSimpleModule
{
protected:
    // Attack configuration
    std::string attackType;
    simtime_t startTime;
    simtime_t duration;
    double intensity;  // 0.0 to 1.0
    std::map<std::string, std::string> parameters;

    // Attack state
    bool attackActive;
    simtime_t attackStarted;
    simtime_t attackEnded;

    // Node information
    int nodeId;
    std::string nodeIdentifier;

    // Statistics
    AttackStatistics stats;
    simsignal_t attackActiveSignal;
    simsignal_t attackIntensitySignal;
    simsignal_t packetsGeneratedSignal;
    simsignal_t packetsModifiedSignal;

    // Self-messages for attack control
    cMessage *startAttackMsg;
    cMessage *stopAttackMsg;
    cMessage *attackTickMsg;

protected:
    /**
     * OMNeT++ lifecycle methods
     */
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 3; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    /**
     * Attack lifecycle methods (to be implemented by derived classes)
     */
    virtual void startAttack();
    virtual void stopAttack();
    virtual void executeAttack();

    /**
     * Packet manipulation methods
     *
     * CRITICAL: Derived classes MUST override these methods to produce measurable effects:
     *
     * 1. executeAttack() - Called every 100ms (0.1s) when attack is active
     *    - Use this to GENERATE malicious packets (flooding, fake data, etc.)
     *    - Example: for (int i=0; i<burstSize; i++) { send(generateMaliciousPacket(), "ndnOut"); }
     *
     * 2. manipulatePacket(msg) - Called for EVERY packet passing through ndnIn gate
     *    - Return modified packet to forward it
     *    - Return nullptr to DROP the packet (critical for jamming, gray hole, etc.)
     *    - Example: delete msg; stats.packetsDropped++; return nullptr;
     *
     * 3. shouldAttackPacket(msg) - Determine if packet should be attacked
     *    - Check packet type, prefix, trust score, etc.
     *    - Return true to apply attack to this packet
     *
     * 4. generateMaliciousPacket() - Create a single malicious packet
     *    - Used by executeAttack() to generate flooding/poisoning packets
     *    - Return InterestPacket* or DataPacket* as appropriate
     */
    virtual bool shouldAttackPacket(cMessage *msg);
    virtual cMessage* manipulatePacket(cMessage *msg);
    virtual cMessage* generateMaliciousPacket();

    /**
     * Helper methods for packet inspection and creation
     */
    bool isInterestPacket(cMessage *msg);
    bool isDataPacket(cMessage *msg);
    InterestPacket* castToInterest(cMessage *msg);
    DataPacket* castToData(cMessage *msg);

    /**
     * Helper methods for common packet operations
     */
    InterestPacket* createInterestPacket(const std::string &name, double lifetime = 4.0);
    DataPacket* createDataPacket(const std::string &name, const std::string &content);

    /**
     * Packet dropping helper - use this in manipulatePacket() to drop packets
     */
    cMessage* dropPacket(cMessage *msg, const std::string &reason = "");

    /**
     * Configuration parsing
     */
    virtual void parseParameters(const std::string &paramStr);
    std::string getParameter(const std::string &key, const std::string &defaultValue = "") const;
    int getParameterInt(const std::string &key, int defaultValue = 0) const;
    double getParameterDouble(const std::string &key, double defaultValue = 0.0) const;
    bool getParameterBool(const std::string &key, bool defaultValue = false) const;

    /**
     * Logging and monitoring
     */
    void logAttackEvent(const std::string &event, const std::string &details = "");
    void updateStatistics();

    /**
     * Attack intensity control
     */
    bool shouldExecuteBasedOnIntensity() const;

    /**
     * Helper methods
     */
    std::string getAttackDescription() const;
    AttackSeverity calculateSeverity() const;
    AttackLayer getAttackLayer() const;

public:
    AttackBase();
    virtual ~AttackBase();

    // Getters
    bool isAttackActive() const { return attackActive; }
    double getIntensity() const { return intensity; }
    const AttackStatistics& getStatistics() const { return stats; }
    std::string getAttackType() const { return attackType; }
};

/**
 * Factory function for creating attack modules
 */
AttackBase* createAttack(const std::string &attackType);

} // namespace veremivndn

#endif // __VEREMIVNDN_ATTACKBASE_H
