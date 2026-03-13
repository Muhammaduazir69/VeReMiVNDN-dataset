//
// VeReMiVNDN - Privacy De-anonymization Attack Implementation
//

#include "PrivacyDeanonymization.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace veremivndn {

Define_Module(PrivacyDeanonymization);

PrivacyDeanonymization::PrivacyDeanonymization()
    : collectNames(true), inferLocation(true), buildProfiles(true),
      analysisInterval(5.0), namesCollected(0), locationsInferred(0),
      identitiesCorrelated(0), profilesBuilt(0), analysisTimer(nullptr) {
}

PrivacyDeanonymization::~PrivacyDeanonymization() {
    cancelAndDelete(analysisTimer);
}

void PrivacyDeanonymization::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        collectNames = getParameterBool("collectNames", true);
        inferLocation = getParameterBool("inferLocation", true);
        buildProfiles = getParameterBool("buildProfiles", true);
        analysisInterval = getParameterDouble("analysisInterval", 5.0);
        targetVehicles = getParameter("targetVehicles", "all");

        // Register signals
        namesCollectedSignal = registerSignal("namesCollected");
        locationsInferredSignal = registerSignal("locationsInferred");
        profilesBuiltSignal = registerSignal("profilesBuilt");
        privacyViolationsSignal = registerSignal("privacyViolations");

        namesCollected = 0;
        locationsInferred = 0;
        identitiesCorrelated = 0;
        profilesBuilt = 0;

        EV_INFO << "PrivacyDeanonymization attack initialized at node " << nodeIdentifier << endl;
    }
}

void PrivacyDeanonymization::handleMessage(cMessage *msg) {
    if (msg == analysisTimer) {
        analyzeContentNames();
        scheduleAt(simTime() + analysisInterval, analysisTimer);
    } else {
        AttackBase::handleMessage(msg);
    }
}

void PrivacyDeanonymization::finish() {
    AttackBase::finish();
    recordScalar("namesCollected", namesCollected);
    recordScalar("locationsInferred", locationsInferred);
    recordScalar("identitiesCorrelated", identitiesCorrelated);
    recordScalar("profilesBuilt", profilesBuilt);
    recordScalar("privacyViolations", namesCollected + locationsInferred + identitiesCorrelated);
}

void PrivacyDeanonymization::startAttack() {
    EV_INFO << "Starting Privacy De-anonymization attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Privacy de-anonymization attack initiated");

    // Start periodic analysis
    analysisTimer = new cMessage("analysisTimer");
    scheduleAt(simTime() + analysisInterval, analysisTimer);
}

void PrivacyDeanonymization::stopAttack() {
    EV_INFO << "Stopping Privacy De-anonymization attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Names collected: " + std::to_string(namesCollected) +
                           ", Profiles built: " + std::to_string(profilesBuilt));

    cancelAndDelete(analysisTimer);
    analysisTimer = nullptr;
}

void PrivacyDeanonymization::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Simulate intercepting Interest/Data packets to collect names
    // In real implementation, this would hook into the NDN forwarder

    // Generate sample content names to analyze
    std::vector<std::string> sampleNames = {
        "/safety/accident/lat/42.3601/long/-71.0942/time/" + std::to_string((int)simTime().dbl()) + "/vehicle/" + nodeIdentifier,
        "/traffic/congestion/zone/downtown/vehicle/" + nodeIdentifier,
        "/location/update/" + nodeIdentifier + "/timestamp/" + std::to_string((int)simTime().dbl()),
        "/content/video/user/" + nodeIdentifier + "/time/" + std::to_string((int)simTime().dbl())
    };

    for (const auto &name : sampleNames) {
        if (uniform(0, 1) < 0.3) {  // 30% chance to collect each name
            collectedNames.push_back(name);
            namesCollected++;
            emit(namesCollectedSignal, 1L);

            // Extract information from name
            if (inferLocation) {
                extractLocationFromName(name);
            }

            extractIdentityFromName(name);

            // Build profile if enabled
            if (buildProfiles) {
                std::vector<std::string> components = parseNameComponents(name);
                for (const auto &comp : components) {
                    if (containsIdentityInfo(comp)) {
                        buildUserProfile(comp, name);
                        break;
                    }
                }
            }

            stats.packetsModified++;
        }
    }
}

void PrivacyDeanonymization::analyzeContentNames() {
    EV_DEBUG << "Analyzing collected content names: " << collectedNames.size() << " names" << endl;

    // Correlate identities across different content names
    if (collectedNames.size() > 10) {
        correlateIdentities();
    }

    // Clear old names to prevent memory buildup (keep last 1000)
    if (collectedNames.size() > 1000) {
        collectedNames.erase(collectedNames.begin(), collectedNames.begin() + 500);
    }
}

void PrivacyDeanonymization::extractLocationFromName(const std::string &name) {
    std::vector<std::string> components = parseNameComponents(name);

    std::string lat, lon;
    for (size_t i = 0; i < components.size(); i++) {
        if (components[i] == "lat" && i + 1 < components.size()) {
            lat = components[i + 1];
        } else if (components[i] == "long" && i + 1 < components.size()) {
            lon = components[i + 1];
        } else if (components[i] == "zone" && i + 1 < components.size()) {
            // Geographic zone information
            locationsInferred++;
            emit(locationsInferredSignal, 1L);
            EV_DEBUG << "Location inferred from name: zone=" << components[i + 1] << endl;
        }
    }

    if (!lat.empty() && !lon.empty()) {
        locationsInferred++;
        emit(locationsInferredSignal, 1L);
        emit(privacyViolationsSignal, 1L);

        EV_WARN << "PRIVACY VIOLATION: Location extracted from name: "
                << "lat=" << lat << ", lon=" << lon << endl;
    }
}

void PrivacyDeanonymization::extractIdentityFromName(const std::string &name) {
    std::vector<std::string> components = parseNameComponents(name);

    for (size_t i = 0; i < components.size(); i++) {
        if ((components[i] == "vehicle" || components[i] == "user" ||
             components[i] == "vehicleID") && i + 1 < components.size()) {

            std::string identity = components[i + 1];
            identitiesCorrelated++;

            emit(privacyViolationsSignal, 1L);

            EV_WARN << "PRIVACY VIOLATION: Identity extracted from name: " << identity << endl;
        }
    }
}

void PrivacyDeanonymization::extractTimingFromName(const std::string &name) {
    std::vector<std::string> components = parseNameComponents(name);

    for (size_t i = 0; i < components.size(); i++) {
        if ((components[i] == "time" || components[i] == "timestamp") &&
            i + 1 < components.size()) {
            EV_DEBUG << "Timestamp extracted: " << components[i + 1] << endl;
        }
    }
}

void PrivacyDeanonymization::correlateIdentities() {
    // Correlate identities across multiple content names
    for (const auto &name : collectedNames) {
        std::vector<std::string> components = parseNameComponents(name);
        std::string identity;

        for (const auto &comp : components) {
            if (containsIdentityInfo(comp)) {
                identity = comp;
                break;
            }
        }

        if (!identity.empty()) {
            // Build identity correlation graph
            identityGraph[identity].insert(name);
        }
    }

    EV_DEBUG << "Identity correlation: " << identityGraph.size() << " unique identities" << endl;
}

void PrivacyDeanonymization::buildUserProfile(const std::string &userId, const std::string &name) {
    if (userProfiles.find(userId) == userProfiles.end()) {
        // Create new profile
        UserProfile profile;
        profile.userId = userId;
        profile.requestCount = 0;
        userProfiles[userId] = profile;
        profilesBuilt++;
        emit(profilesBuiltSignal, 1L);

        EV_WARN << "PRIVACY VIOLATION: New user profile created for: " << userId << endl;
    }

    updateProfile(userProfiles[userId], name);
}

void PrivacyDeanonymization::updateProfile(UserProfile &profile, const std::string &name) {
    profile.requestCount++;
    profile.requestedContent.push_back(name);
    profile.timeline[simTime()] = name;

    // Extract interests from name
    std::vector<std::string> components = parseNameComponents(name);
    if (components.size() > 0) {
        profile.interests.insert(components[0]);  // Top-level category
    }

    EV_DEBUG << "Updated profile for " << profile.userId
             << ", total requests: " << profile.requestCount << endl;
}

std::vector<std::string> PrivacyDeanonymization::parseNameComponents(const std::string &name) {
    std::vector<std::string> components;
    std::stringstream ss(name);
    std::string component;

    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            components.push_back(component);
        }
    }

    return components;
}

bool PrivacyDeanonymization::containsLocationInfo(const std::string &component) {
    return (component == "lat" || component == "long" || component == "lon" ||
            component == "location" || component == "zone" || component == "area");
}

bool PrivacyDeanonymization::containsIdentityInfo(const std::string &component) {
    return (component.find("vehicle") != std::string::npos ||
            component.find("user") != std::string::npos ||
            component.find("node") != std::string::npos ||
            component.find("id") != std::string::npos);
}

bool PrivacyDeanonymization::containsTimestampInfo(const std::string &component) {
    return (component == "time" || component == "timestamp" || component == "date");
}

PrivacyInfoType PrivacyDeanonymization::classifyPrivacyInfo(const std::string &nameComponent) {
    if (containsLocationInfo(nameComponent)) {
        return PrivacyInfoType::LOCATION;
    } else if (containsIdentityInfo(nameComponent)) {
        return PrivacyInfoType::IDENTITY;
    } else if (containsTimestampInfo(nameComponent)) {
        return PrivacyInfoType::TIMESTAMP;
    } else {
        return PrivacyInfoType::CONTENT_TYPE;
    }
}

void PrivacyDeanonymization::selectHighValueTargets() {
    // Select targets with high privacy information exposure
    for (const auto &entry : userProfiles) {
        double privacyScore = calculatePrivacyScore(entry.second);
        if (privacyScore > 0.7) {
            EV_INFO << "High-value privacy target: " << entry.first
                    << ", score: " << privacyScore << endl;
        }
    }
}

double PrivacyDeanonymization::calculatePrivacyScore(const UserProfile &profile) {
    // Calculate privacy exposure score (0.0 to 1.0)
    double score = 0.0;

    // Factor in number of requests
    score += std::min(profile.requestCount / 100.0, 0.3);

    // Factor in location diversity
    score += std::min(profile.locations.size() / 10.0, 0.3);

    // Factor in interest diversity
    score += std::min(profile.interests.size() / 5.0, 0.2);

    // Factor in timeline coverage
    score += std::min(profile.timeline.size() / 50.0, 0.2);

    return std::min(score, 1.0);
}

cMessage* PrivacyDeanonymization::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept ALL packets to extract privacy information
    // This attack is passive - it doesn't modify packets, just analyzes them

    // Try both Interest and Data packets
    InterestPacket *interest = dynamic_cast<InterestPacket*>(msg);
    DataPacket *data = dynamic_cast<DataPacket*>(msg);

    if (!interest && !data) {
        return msg;  // Unknown packet type
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    std::string name;
    if (interest) {
        name = interest->getName();
    } else if (data) {
        name = data->getName();
    }

    // Collect the name for analysis
    collectedNames.push_back(name);
    namesCollected++;

    // Extract privacy information from the name
    extractLocationFromName(name);
    extractIdentityFromName(name);
    extractTimingFromName(name);

    // Try to identify user/vehicle from name components
    std::vector<std::string> components = parseNameComponents(name);
    for (const auto &comp : components) {
        if (containsIdentityInfo(comp)) {
            buildUserProfile(comp, name);
            break;
        }
    }

    // Correlate identities periodically
    if (collectedNames.size() % 10 == 0) {
        correlateIdentities();
    }

    // Privacy attacks typically don't modify packets (passive monitoring)
    // But we track statistics to show the attack is working
    stats.packetsModified++;  // "Modified" means "analyzed for privacy"

    EV_DEBUG << "PRIVACY: Analyzed packet '" << name
             << "', total names collected: " << collectedNames.size() << endl;

    // Forward packet unchanged (passive attack)
    return msg;
}

} // namespace veremivndn
