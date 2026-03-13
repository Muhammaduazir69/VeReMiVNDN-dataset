//
// VeReMiVNDN - Privacy De-anonymization via Name Semantics Attack
//
// Attack #11: Privacy De-anonymization via Name Semantics
// Layer: Application / Privacy
// Description: Named content reveals sensitive information (e.g., "/accident/lat/long/time/vehicleID"),
//              enabling identity and location tracking through name analysis
// Impact: Direct privacy leaks, identity linkage, location tracking, profile building
//

#ifndef __VEREMIVNDN_PRIVACYDEANONYMIZATION_H
#define __VEREMIVNDN_PRIVACYDEANONYMIZATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Privacy Information Types
 */
enum class PrivacyInfoType {
    LOCATION,           // Geographic location
    IDENTITY,           // Vehicle/user identity
    TIMESTAMP,          // Time-based information
    CONTENT_TYPE,       // Type of content requested
    BEHAVIORAL          // Behavioral patterns
};

/**
 * User Profile Structure
 */
struct UserProfile {
    std::string userId;
    std::vector<std::string> locations;
    std::vector<std::string> requestedContent;
    std::map<simtime_t, std::string> timeline;
    int requestCount;
    std::set<std::string> interests;
};

/**
 * PrivacyDeanonymization
 *
 * Implements Privacy De-anonymization attack that extracts sensitive
 * information from NDN content names to track users, their locations,
 * and behavioral patterns.
 *
 * Attack Parameters (JSON):
 * - collectNames: bool - Collect and analyze content names (default: true)
 * - inferLocation: bool - Infer location from names (default: true)
 * - buildProfiles: bool - Build user profiles (default: true)
 * - analysisInterval: double - How often to analyze data in seconds (default: 5.0)
 * - targetVehicles: string - Specific vehicles to target (default: "all")
 */
class PrivacyDeanonymization : public AttackBase
{
private:
    // Attack parameters
    bool collectNames;
    bool inferLocation;
    bool buildProfiles;
    double analysisInterval;
    std::string targetVehicles;

    // Collected data
    std::map<std::string, UserProfile> userProfiles;
    std::vector<std::string> collectedNames;
    std::map<std::string, std::vector<std::string>> locationMap;  // userId -> locations
    std::map<std::string, std::set<std::string>> identityGraph;   // Identity correlations

    // Attack state
    uint64_t namesCollected;
    uint64_t locationsInferred;
    uint64_t identitiesCorrelated;
    uint64_t profilesBuilt;

    // Analysis timer
    cMessage *analysisTimer;

    // Statistics
    simsignal_t namesCollectedSignal;
    simsignal_t locationsInferredSignal;
    simsignal_t profilesBuiltSignal;
    simsignal_t privacyViolationsSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Privacy analysis methods
    void analyzeContentNames();
    void extractLocationFromName(const std::string &name);
    void extractIdentityFromName(const std::string &name);
    void extractTimingFromName(const std::string &name);
    void correlateIdentities();

    // Profile building
    void buildUserProfile(const std::string &userId, const std::string &name);
    void updateProfile(UserProfile &profile, const std::string &name);
    PrivacyInfoType classifyPrivacyInfo(const std::string &nameComponent);

    // Name parsing
    std::vector<std::string> parseNameComponents(const std::string &name);
    bool containsLocationInfo(const std::string &component);
    bool containsIdentityInfo(const std::string &component);
    bool containsTimestampInfo(const std::string &component);

    // Attack optimization
    void selectHighValueTargets();
    double calculatePrivacyScore(const UserProfile &profile);

public:
    PrivacyDeanonymization();
    virtual ~PrivacyDeanonymization();

    // Attack-specific getters
    uint64_t getNamesCollected() const { return namesCollected; }
    uint64_t getLocationsInferred() const { return locationsInferred; }
    uint64_t getProfilesBuilt() const { return profilesBuilt; }
    const std::map<std::string, UserProfile>& getUserProfiles() const { return userProfiles; }
};

Define_Module(PrivacyDeanonymization);

} // namespace veremivndn

#endif // __VEREMIVNDN_PRIVACYDEANONYMIZATION_H
