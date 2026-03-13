//
// VeReMiVNDN - Name Enumeration / Privacy Crawling Attack
//
// Attack #19: Name Enumeration / Privacy Crawling
// Layer: Application / Privacy
// Description: Attacker probes names to discover what content is popular or available,
//              creating privacy risk through user profiling
// Impact: User profiling, content discovery abuse, targeted attacks, privacy invasion
//

#ifndef __VEREMIVNDN_NAMEENUMERATION_H
#define __VEREMIVNDN_NAMEENUMERATION_H

#include "../AttackBase.h"
#include "../../ndn/packets/NdnPackets_m.h"
#include <map>
#include <set>
#include <vector>

namespace veremivndn {

/**
 * Enumeration Strategies
 */
enum class EnumerationStrategy {
    SEQUENTIAL,         // Enumerate names sequentially
    DICTIONARY,         // Use dictionary-based probing
    RANDOM,             // Random name probing
    TARGETED            // Target specific patterns
};

/**
 * NameEnumeration
 *
 * Implements Name Enumeration attack that systematically probes
 * content names to discover popular content, user interests,
 * and network structure for privacy profiling.
 *
 * Attack Parameters (JSON):
 * - probeNames: bool - Probe content names (default: true)
 * - discoverPopular: bool - Discover popular content (default: true)
 * - buildDirectory: bool - Build content directory (default: true)
 * - probeRate: int - Probes per second (default: 50)
 * - targetNamespace: string - Namespace to enumerate (default: "/")
 */
class NameEnumeration : public AttackBase
{
private:
    // Attack parameters
    bool probeNames;
    bool discoverPopular;
    bool buildDirectory;
    int probeRate;
    std::string targetNamespace;
    EnumerationStrategy strategy;

    // Discovered information
    std::set<std::string> discoveredNames;
    std::map<std::string, int> popularityMap;  // name -> popularity score
    std::vector<std::string> contentDirectory;
    std::map<std::string, std::set<std::string>> namespaceTree;

    // Attack state
    uint64_t namesProbed;
    uint64_t namesDiscovered;
    uint64_t popularContentIdentified;
    int currentProbeIndex;

    // Statistics
    simsignal_t namesProbedSignal;
    simsignal_t namesDiscoveredSignal;
    simsignal_t popularContentSignal;
    simsignal_t privacyCrawlSignal;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Attack lifecycle
    virtual void startAttack() override;
    virtual void stopAttack() override;
    virtual void executeAttack() override;
    virtual cMessage* manipulatePacket(cMessage *msg) override;

    // Name probing
    void probeContentName(const std::string &name);
    InterestPacket* createProbeInterest(const std::string &name);
    void analyzeProbeResponse(const std::string &name, bool found);

    // Discovery methods
    void enumerateSequential();
    void enumerateDictionary();
    void enumerateRandom();
    void enumerateTargeted();

    // Directory building
    void addToDirectory(const std::string &name);
    void buildNamespaceTree(const std::string &name);
    void identifyPopularContent();

    // Helper methods
    bool containsSensitiveInfo(const std::string &name);

public:
    NameEnumeration();
    virtual ~NameEnumeration();

    // Attack-specific getters
    uint64_t getNamesProbed() const { return namesProbed; }
    uint64_t getNamesDiscovered() const { return namesDiscovered; }
    const std::set<std::string>& getDiscoveredNames() const { return discoveredNames; }
};

Define_Module(NameEnumeration);

} // namespace veremivndn

#endif // __VEREMIVNDN_NAMEENUMERATION_H
