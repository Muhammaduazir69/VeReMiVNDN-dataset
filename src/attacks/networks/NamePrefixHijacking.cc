//
// VeReMiVNDN - Name Prefix Hijacking Attack Implementation
//

#include "../networks/NamePrefixHijacking.h"

#include "../../common/SimpleJSON.h"

namespace veremivndn {

Define_Module(NamePrefixHijacking);

NamePrefixHijacking::NamePrefixHijacking()
    : advertisementTimer(nullptr),
      interceptedInterests(0),
      forgedAdvertisements(0),
      bogusDataSent(0)
{
}

NamePrefixHijacking::~NamePrefixHijacking()
{
    cancelAndDelete(advertisementTimer);

    // Clean up intercepted packets
    for (auto pkt : interceptedPackets) {
        delete pkt;
    }
    interceptedPackets.clear();
}

void NamePrefixHijacking::initialize(int stage)
{
    AttackBase::initialize(stage);

    if (stage == 0) {
        // Default parameters
        hijackedPrefix = "/safety";
        advertiseFake = true;
        interceptTraffic = true;
        mode = HijackingMode::INTERCEPT;
        advertisementRate = 10;
        hopCountLie = 1;
        injectBogusData = false;

        attackType = "NamePrefixHijacking";

        // Create timers
        advertisementTimer = new cMessage("advertisementTimer");

        // Register signals
        prefixHijackedSignal = registerSignal("prefixHijacked");
        interestInterceptedSignal = registerSignal("interestIntercepted");
        bogusDataSignal = registerSignal("bogusDataSent");
    }
}

void NamePrefixHijacking::handleMessage(cMessage *msg)
{
    if (msg == advertisementTimer) {
        executeAttack();
    }
    else if (msg == startAttackMsg) {
        startAttack();
    }
    else if (msg == stopAttackMsg) {
        stopAttack();
    }
    else if (attackActive) {
        // Intercept passing traffic if enabled
        if (interceptTraffic && shouldAttackPacket(msg)) {
            if (InterestPacket *interest = dynamic_cast<InterestPacket*>(msg)) {
                handleInterceptedInterest(interest);
                return;  // Don't forward original
            }
            else if (DataPacket *data = dynamic_cast<DataPacket*>(msg)) {
                handleInterceptedData(data);
                return;  // Don't forward original
            }
        }

        // Forward non-targeted traffic
        send(msg, "ndnOut");
    }
    else {
        send(msg, "ndnOut");
    }
}

void NamePrefixHijacking::startAttack()
{
    EV_WARN << "Starting Name Prefix Hijacking attack: prefix=" << hijackedPrefix
            << " mode=" << (int)mode << endl;

    attackActive = true;
    interceptedInterests = 0;
    forgedAdvertisements = 0;
    bogusDataSent = 0;

    hijackedPrefixes.clear();
    hijackedPrefixes.insert(hijackedPrefix);

    // Start advertising hijacked prefixes
    if (advertiseFake) {
        scheduleAt(simTime() + uniform(0.1, 0.5), advertisementTimer);
    }

    emit(attackActiveSignal, 1L);
}

void NamePrefixHijacking::stopAttack()
{
    attackActive = false;
    cancelEvent(advertisementTimer);

    EV_INFO << "Name Prefix Hijacking attack stopped. Intercepted "
            << interceptedInterests << " interests, sent "
            << forgedAdvertisements << " fake advertisements" << endl;

    emit(attackActiveSignal, 0L);
}

void NamePrefixHijacking::executeAttack()
{
    if (!attackActive) return;

    // Advertise hijacked prefix
    advertiseHijackedPrefix();

    // Schedule next advertisement
    double interval = 1.0 / advertisementRate;
    scheduleAt(simTime() + exponential(interval), advertisementTimer);
}

void NamePrefixHijacking::advertiseHijackedPrefix()
{
    for (const auto &prefix : hijackedPrefixes) {
        sendFakeRouteAdvertisement(prefix);
    }
}

void NamePrefixHijacking::sendFakeRouteAdvertisement(const std::string &prefix)
{
    // Create a fake route advertisement message
    // In NDN, this would be a FIB update or routing protocol message

    // For simulation purposes, we create a control message
    cMessage *advertisement = new cMessage("FIB_ADVERTISEMENT");
    advertisement->addPar("prefix") = prefix.c_str();
    advertisement->addPar("cost") = hopCountLie;  // Lie about distance
    advertisement->addPar("nodeId") = nodeId;
    advertisement->addPar("isMalicious") = true;

    // Broadcast to neighbors
    send(advertisement, "ndnOut");

    forgedAdvertisements++;
    stats.packetsGenerated++;

    emit(prefixHijackedSignal, 1L);
    emit(packetsGeneratedSignal, 1L);

    EV_DETAIL << "Advertised hijacked prefix: " << prefix
              << " with cost=" << hopCountLie << endl;
}

bool NamePrefixHijacking::shouldInterceptPacket(cMessage *msg)
{
    if (!interceptTraffic) return false;

    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(msg)) {
        std::string name = interest->getName();

        // Check if interest matches hijacked prefix
        for (const auto &prefix : hijackedPrefixes) {
            if (name.find(prefix) == 0) {  // Starts with prefix
                return true;
            }
        }
    }

    return false;
}

void NamePrefixHijacking::handleInterceptedInterest(InterestPacket *interest)
{
    interceptedInterests++;
    stats.packetsModified++;

    emit(interestInterceptedSignal, 1L);

    EV_WARN << "Intercepted Interest: " << interest->getName() << endl;

    switch(mode) {
        case HijackingMode::ADVERTISE_ONLY:
            // Just forward normally
            send(interest, "ndnOut");
            break;

        case HijackingMode::INTERCEPT:
            // Store and analyze, then forward
            interceptedPackets.push_back(interest->dup());
            send(interest, "ndnOut");
            break;

        case HijackingMode::BLACK_HOLE:
            // Drop the packet
            stats.packetsDropped++;
            delete interest;
            break;

        case HijackingMode::MITM:
            // Send bogus data in response
            if (injectBogusData) {
                DataPacket *bogusData = createBogusData(interest);
                if (bogusData) {
                    send(bogusData, "ndnOut");
                    bogusDataSent++;
                    emit(bogusDataSignal, 1L);
                }
            }
            // Drop original interest
            delete interest;
            break;
    }
}

void NamePrefixHijacking::handleInterceptedData(DataPacket *data)
{
    std::string name = data->getName();

    // Check if data matches hijacked prefix
    bool shouldIntercept = false;
    for (const auto &prefix : hijackedPrefixes) {
        if (name.find(prefix) == 0) {
            shouldIntercept = true;
            break;
        }
    }

    if (!shouldIntercept) {
        send(data, "ndnOut");
        return;
    }

    EV_WARN << "Intercepted Data: " << name << endl;

    switch(mode) {
        case HijackingMode::MITM:
            // Modify and forward
            {
                DataPacket *modified = modifyData(data);
                delete data;
                send(modified, "ndnOut");
                stats.packetsModified++;
            }
            break;

        case HijackingMode::BLACK_HOLE:
            // Drop
            stats.packetsDropped++;
            delete data;
            break;

        default:
            // Forward normally
            send(data, "ndnOut");
            break;
    }
}

DataPacket* NamePrefixHijacking::createBogusData(InterestPacket *interest)
{
    DataPacket *data = new DataPacket();
    data->setName(interest->getName());

    // Create fake content
    std::string bogusContent = "HIJACKED CONTENT - FAKE DATA FROM ATTACKER";
    data->setContent(bogusContent.c_str());
    data->setContentLength(bogusContent.length());

    // Fake signature
    data->setIsSigned(true);
    data->setSignature("FORGED_SIGNATURE_BY_ATTACKER");
    data->setSignerId("ATTACKER");
    data->setSignatureTime(simTime());

    data->setTimestamp(simTime());
    data->setIsCacheable(true);
    data->setTrustScore(0.0);  // Low trust
    data->setFreshnessPeriod(10.0);

    return data;
}

DataPacket* NamePrefixHijacking::modifyData(DataPacket *original)
{
    DataPacket *modified = original->dup();

    // Modify content
    std::string newContent = "MODIFIED: " + std::string(original->getContent());
    modified->setContent(newContent.c_str());
    modified->setContentLength(newContent.length());

    // Invalidate signature
    modified->setSignature("MODIFIED_BY_ATTACKER");
    modified->setTrustScore(0.0);

    return modified;
}

bool NamePrefixHijacking::shouldAttackPacket(cMessage *msg)
{
    return shouldInterceptPacket(msg);
}

cMessage* NamePrefixHijacking::manipulatePacket(cMessage *msg)
{
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(msg)) {
        // Store for analysis
        interceptedPackets.push_back(interest->dup());
    }
    return msg;
}

cMessage* NamePrefixHijacking::generateMaliciousPacket()
{
    // Generate fake route advertisement
    cMessage *advertisement = new cMessage("FAKE_ROUTE_ADV");
    advertisement->addPar("prefix") = hijackedPrefix.c_str();
    advertisement->addPar("cost") = hopCountLie;
    return advertisement;
}

void NamePrefixHijacking::parseParameters(const std::string &params)
{
    try {
        auto json = nlohmann::json::parse(params);

        if (json.contains("hijackedPrefix")) {
            hijackedPrefix = json["hijackedPrefix"];
        }
        if (json.contains("advertiseFake")) {
            std::string val = json["advertiseFake"];
            advertiseFake = (val == "true" || val == "1");
        }
        if (json.contains("interceptTraffic")) {
            std::string val = json["interceptTraffic"];
            interceptTraffic = (val == "true" || val == "1");
        }
        if (json.contains("mode")) {
            std::string modeStr = json["mode"];
            if (modeStr == "advertise") mode = HijackingMode::ADVERTISE_ONLY;
            else if (modeStr == "intercept") mode = HijackingMode::INTERCEPT;
            else if (modeStr == "mitm") mode = HijackingMode::MITM;
            else if (modeStr == "blackhole") mode = HijackingMode::BLACK_HOLE;
        }
        if (json.contains("advertisementRate")) {
            advertisementRate = std::stoi(std::string(json["advertisementRate"]));
        }
        if (json.contains("hopCountLie")) {
            hopCountLie = std::stoi(std::string(json["hopCountLie"]));
        }
        if (json.contains("injectBogusData")) {
            std::string val = json["injectBogusData"];
            injectBogusData = (val == "true" || val == "1");
        }
    }
    catch (const std::exception &e) {
        EV_WARN << "Failed to parse attack parameters: " << e.what() << endl;
    }
}

void NamePrefixHijacking::finish()
{
    AttackBase::finish();

    recordScalar("interceptedInterests", interceptedInterests);
    recordScalar("forgedAdvertisements", forgedAdvertisements);
    recordScalar("bogusDataSent", bogusDataSent);
    recordScalar("hijackedPrefixCount", (long)hijackedPrefixes.size());
}

} // namespace veremivndn
