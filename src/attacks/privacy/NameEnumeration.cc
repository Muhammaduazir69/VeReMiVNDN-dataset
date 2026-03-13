//
// VeReMiVNDN - Name Enumeration Attack Implementation
//

#include "NameEnumeration.h"
#include <sstream>

namespace veremivndn {

Define_Module(NameEnumeration);

NameEnumeration::NameEnumeration()
    : probeNames(true), discoverPopular(true), buildDirectory(true),
      probeRate(50), strategy(EnumerationStrategy::DICTIONARY),
      namesProbed(0), namesDiscovered(0), popularContentIdentified(0),
      currentProbeIndex(0) {
}

NameEnumeration::~NameEnumeration() {
}

void NameEnumeration::initialize(int stage) {
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Parse attack-specific parameters
        probeNames = getParameterBool("probeNames", true);
        discoverPopular = getParameterBool("discoverPopular", true);
        buildDirectory = getParameterBool("buildDirectory", true);
        probeRate = getParameterInt("probeRate", 50);
        targetNamespace = getParameter("targetNamespace", "/");

        // Determine strategy
        std::string strategyStr = getParameter("strategy", "dictionary");
        if (strategyStr == "sequential") {
            strategy = EnumerationStrategy::SEQUENTIAL;
        } else if (strategyStr == "random") {
            strategy = EnumerationStrategy::RANDOM;
        } else if (strategyStr == "targeted") {
            strategy = EnumerationStrategy::TARGETED;
        } else {
            strategy = EnumerationStrategy::DICTIONARY;
        }

        // Register signals
        namesProbedSignal = registerSignal("namesProbed");
        namesDiscoveredSignal = registerSignal("namesDiscovered");
        popularContentSignal = registerSignal("popularContent");
        privacyCrawlSignal = registerSignal("privacyCrawl");

        namesProbed = 0;
        namesDiscovered = 0;
        popularContentIdentified = 0;
        currentProbeIndex = 0;

        EV_INFO << "NameEnumeration attack initialized at node " << nodeIdentifier
                << ", target namespace: " << targetNamespace
                << ", strategy: " << (int)strategy << endl;
    }
}

void NameEnumeration::handleMessage(cMessage *msg) {
    AttackBase::handleMessage(msg);
}

void NameEnumeration::finish() {
    AttackBase::finish();
    recordScalar("namesProbed", namesProbed);
    recordScalar("namesDiscovered", namesDiscovered);
    recordScalar("popularContentIdentified", popularContentIdentified);
    recordScalar("directorySize", contentDirectory.size());
}

void NameEnumeration::startAttack() {
    EV_INFO << "Starting Name Enumeration attack at node " << nodeIdentifier << endl;
    logAttackEvent("START", "Name enumeration/privacy crawling initiated");
}

void NameEnumeration::stopAttack() {
    EV_INFO << "Stopping Name Enumeration attack at node " << nodeIdentifier << endl;
    logAttackEvent("STOP", "Names discovered: " + std::to_string(namesDiscovered));

    EV_INFO << "Content directory built with " << contentDirectory.size() << " entries" << endl;
}

void NameEnumeration::executeAttack() {
    if (!shouldExecuteBasedOnIntensity()) {
        return;
    }

    // Execute enumeration based on strategy
    switch (strategy) {
        case EnumerationStrategy::SEQUENTIAL:
            enumerateSequential();
            break;

        case EnumerationStrategy::DICTIONARY:
            enumerateDictionary();
            break;

        case EnumerationStrategy::RANDOM:
            enumerateRandom();
            break;

        case EnumerationStrategy::TARGETED:
            enumerateTargeted();
            break;
    }

    // Periodically analyze discovered content
    if ((int)simTime().dbl() % 10 == 0 && namesDiscovered > 10) {
        identifyPopularContent();
    }
}

void NameEnumeration::probeContentName(const std::string &name) {
    // Send probe Interest
    InterestPacket *probe = createProbeInterest(name);
    send(probe, "ndnOut");

    namesProbed++;
    emit(namesProbedSignal, 1L);
    emit(privacyCrawlSignal, 1L);
    stats.packetsGenerated++;

    EV_DEBUG << "PROBE: Sent probe for name: " << name << endl;

    // Simulate response analysis (in real implementation would check actual response)
    bool found = (uniform(0, 1) < 0.4);  // 40% discovery rate
    analyzeProbeResponse(name, found);
}

InterestPacket* NameEnumeration::createProbeInterest(const std::string &name) {
    InterestPacket *interest = new InterestPacket("ProbeInterest");

    interest->setName(name.c_str());
    interest->setNonce(intuniform(1, 2000000000));
    interest->setHopCount(0);
    interest->setInterestLifetime(2.0);  // Short lifetime for probing
    interest->setTimestamp(simTime());

    return interest;
}

void NameEnumeration::analyzeProbeResponse(const std::string &name, bool found) {
    if (found) {
        // Name exists - add to discovered set
        if (discoveredNames.find(name) == discoveredNames.end()) {
            discoveredNames.insert(name);
            namesDiscovered++;
            emit(namesDiscoveredSignal, 1L);

            EV_WARN << "PRIVACY CRAWL: Discovered content: " << name << endl;

            // Add to directory
            if (buildDirectory) {
                addToDirectory(name);
                buildNamespaceTree(name);
            }

            // Track popularity
            popularityMap[name]++;
        }
    }
}

void NameEnumeration::enumerateSequential() {
    // Sequential enumeration of content names
    double intervalSeconds = 1.0 / probeRate;

    if (uniform(0, 1) < intervalSeconds * 10) {
        std::stringstream ss;
        ss << targetNamespace << "/content/" << currentProbeIndex;
        currentProbeIndex++;

        probeContentName(ss.str());
    }
}

void NameEnumeration::enumerateDictionary() {
    // Dictionary-based enumeration using common content names
    static const std::vector<std::string> dictionary = {
        "safety", "traffic", "accident", "emergency", "weather",
        "parking", "video", "map", "location", "congestion",
        "alert", "warning", "route", "status", "update"
    };

    double intervalSeconds = 1.0 / probeRate;

    if (uniform(0, 1) < intervalSeconds * 10) {
        int dictIndex = intuniform(0, dictionary.size() - 1);
        std::stringstream ss;
        ss << targetNamespace << "/" << dictionary[dictIndex] << "/" << intuniform(1, 100);

        probeContentName(ss.str());
    }
}

void NameEnumeration::enumerateRandom() {
    // Random name enumeration
    double intervalSeconds = 1.0 / probeRate;

    if (uniform(0, 1) < intervalSeconds * 10) {
        std::stringstream ss;
        ss << targetNamespace << "/random/" << intuniform(1, 10000)
           << "/" << simTime().dbl();

        probeContentName(ss.str());
    }
}

void NameEnumeration::enumerateTargeted() {
    // Targeted enumeration of specific patterns
    double intervalSeconds = 1.0 / probeRate;

    if (uniform(0, 1) < intervalSeconds * 10) {
        // Target privacy-sensitive content
        static const std::vector<std::string> targets = {
            "/location/vehicle/", "/safety/accident/lat/", "/emergency/alert/",
            "/traffic/congestion/zone/", "/video/camera/"
        };

        int targetIdx = intuniform(0, targets.size() - 1);
        std::stringstream ss;
        ss << targets[targetIdx] << intuniform(1, 100);

        probeContentName(ss.str());
    }
}

void NameEnumeration::addToDirectory(const std::string &name) {
    contentDirectory.push_back(name);

    EV_DEBUG << "Added to directory: " << name
             << " (total: " << contentDirectory.size() << ")" << endl;
}

void NameEnumeration::buildNamespaceTree(const std::string &name) {
    // Parse name components and build tree structure
    std::stringstream ss(name);
    std::string component;
    std::string currentPath = "";

    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            namespaceTree[currentPath].insert(component);
            currentPath += "/" + component;
        }
    }

    EV_DEBUG << "Namespace tree updated for: " << name << endl;
}

void NameEnumeration::identifyPopularContent() {
    // Identify popular content based on discovery frequency
    for (const auto &entry : popularityMap) {
        if (entry.second >= 3) {  // Threshold for "popular"
            popularContentIdentified++;
            emit(popularContentSignal, 1L);

            EV_WARN << "POPULAR CONTENT: " << entry.first
                    << " (popularity: " << entry.second << ")" << endl;
        }
    }

    EV_DEBUG << "Popular content analysis: " << popularContentIdentified
             << " popular items identified" << endl;
}

cMessage* NameEnumeration::manipulatePacket(cMessage *msg) {
    // CRITICAL: Intercept Data packets (responses) to learn which names exist
    // This is primarily a passive attack but actively generates probe Interests via executeAttack()

    DataPacket *data = dynamic_cast<DataPacket*>(msg);
    if (!data) {
        // Not a Data packet, forward unchanged
        return msg;
    }

    // Attack based on probability (intensity)
    if (!shouldExecuteBasedOnIntensity()) {
        return msg;
    }

    // Learn from Data packet responses
    std::string name = data->getName();

    // Record discovered name
    discoveredNames.insert(name);

    // Build namespace structure
    buildNamespaceTree(name);

    // Add to directory
    addToDirectory(name);

    // Update popularity map
    popularityMap[name]++;

    // Track discovery
    namesDiscovered++;
    emit(namesDiscoveredSignal, 1L);

    // Check if name contains privacy-sensitive information
    if (containsSensitiveInfo(name)) {
        emit(privacyCrawlSignal, 1L);

        EV_WARN << "ENUM_PRIVACY: Discovered sensitive name: " << name << endl;
    }

    // Mark that enumeration is working
    stats.packetsModified++;  // "Modified" means "analyzed"

    EV_DEBUG << "ENUM: Learned name '" << name
             << "', total discovered: " << discoveredNames.size() << endl;

    // Passive attack - don't modify the packet
    return data;
}

bool NameEnumeration::containsSensitiveInfo(const std::string &name) {
    // Check if name contains privacy-sensitive keywords
    return (name.find("user") != std::string::npos ||
            name.find("vehicle") != std::string::npos ||
            name.find("location") != std::string::npos ||
            name.find("private") != std::string::npos ||
            name.find("id") != std::string::npos);
}

} // namespace veremivndn
