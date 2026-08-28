//
// VeReMiVNDN - Vehicle Controller Implementation
// Handles vehicle application logic with VEINS and NDN integration
//

#include "VehicleController.h"
#include "../../attacks/crosslayer/JammingMedium.h"
#include "NeighborIndex.h"
#include "../../ids/features/FeatureExtractor.h"
#include "../../trident/TrustRegistry.h"
#include "../../attacks/AttackBase.h"

namespace veremivndn {

// Resolve a node's current position. Display-string coordinates are only
// maintained when a GUI canvas is active, so Cmdenv runs must read the
// mobility module directly; RSUs expose static x/y parameters instead.
static bool nodePositionOf(cModule *host, double &x, double &y) {
    if (!host) return false;
    cModule *mob = host->getSubmodule("mobility");
    if (!mob) return false;
    if (auto *bm = dynamic_cast<veins::BaseMobility *>(mob)) {
        veins::Coord c = bm->getPositionAt(simTime());
        x = c.x; y = c.y;
        return true;
    }
    if (mob->hasPar("x") && mob->hasPar("y")) {
        x = mob->par("x").doubleValue();
        y = mob->par("y").doubleValue();
        return true;
    }
    return false;
}

Define_Module(VehicleController);

VehicleController::VehicleController()
    : beaconTimer(nullptr), requestTimer(nullptr), mobilityUpdateTimer(nullptr),
      requestCounter(0), packetsSent(0), packetsReceived(0),
      isContentProducer(false), mobility(nullptr), traci(nullptr),
      traciVehicle(nullptr), currentSpeed(0.0), currentHeading(0.0),
      currentLaneIndex(0), communicationRange(500.0),
      trustReg(nullptr), tridentIsolation(false), selfAttack(nullptr),
      interestsIssued(0), interestsSatisfied(0), interestsExpired(0),
      framesDroppedQuarantine(0), pendingSweepTimer(nullptr) {}

VehicleController::~VehicleController() {
    NeighborIndex::instance().remove(getParentModule());
    cancelAndDelete(beaconTimer);
    cancelAndDelete(requestTimer);
    cancelAndDelete(mobilityUpdateTimer);
    cancelAndDelete(pendingSweepTimer);
}

void VehicleController::initialize() {
    // Get gate IDs
    ndnInGate = findGate("ndnIn");
    ndnOutGate = findGate("ndnOut");
    wireInGate = findGate("wireIn");
    wireOutGate = findGate("wireOut");
    lowerLayerInGate = findGate("lowerLayerIn");
    lowerLayerOutGate = findGate("lowerLayerOut");
    lowerControlInGate = findGate("lowerControlIn");
    lowerControlOutGate = findGate("lowerControlOut");
    directInGate = findGate("directIn");

    // Configuration
    vehicleId = par("vehicleId").stdstringValue();
    if (vehicleId.empty()) {
        vehicleId = "V_" + std::to_string(getParentModule()->getIndex());
    }

    isContentProducer = par("isContentProducer");
    isForwarder        = par("isForwarder");
    catalogSize        = par("catalogSize");
    catalogZipfAlpha   = par("catalogZipfAlpha");
    uniqueNameFraction = par("uniqueNameFraction");
    maxRelayHops       = par("maxRelayHops");
    buildZipfCdf();
    beaconInterval = par("beaconInterval");

    // Parse produced prefixes
    if (isContentProducer) {
        std::string prefixStr = par("producedPrefixes").stdstringValue();
        size_t pos = 0;
        while ((pos = prefixStr.find(',')) != std::string::npos) {
            std::string prefix = prefixStr.substr(0, pos);
            prefix.erase(0, prefix.find_first_not_of(" \t"));
            prefix.erase(prefix.find_last_not_of(" \t") + 1);
            if (!prefix.empty()) producedPrefixes.push_back(prefix);
            prefixStr.erase(0, pos + 1);
        }
        if (!prefixStr.empty()) {
            prefixStr.erase(0, prefixStr.find_first_not_of(" \t"));
            prefixStr.erase(prefixStr.find_last_not_of(" \t") + 1);
            producedPrefixes.push_back(prefixStr);
        }
    }

    // Schedule timers
    beaconTimer = new cMessage("vehicleBeaconTimer");
    scheduleAt(simTime() + beaconInterval, beaconTimer);

    // Every vehicle is a consumer. The published model made content producers
    // pure servers that never issued a request, which is unrealistic (a vehicle
    // both publishes what it senses and asks for what it needs) and, more
    // importantly for evaluation, left producer-role attackers almost invisible
    // to neighbouring monitors: a node that only answers Interests routed to it
    // transmits far less often than one that also requests.
    requestTimer = new cMessage("vehicleRequestTimer");
    scheduleAt(simTime() + uniform(1.0, 3.0), requestTimer);

    // Register signals FIRST (before calling initializeMobility which may emit signals)
    positionUpdateSignal = registerSignal("positionUpdate");
    speedChangeSignal = registerSignal("speedChange");
    laneChangeSignal = registerSignal("laneChange");
    neighborDiscoveredSignal = registerSignal("neighborDiscovered");

    // Initialize VEINS mobility (may emit signals during updateMobilityState)
    initializeMobility();

    // Schedule mobility update timer
    mobilityUpdateTimer = new cMessage("mobilityUpdateTimer");
    scheduleAt(simTime() + 0.1, mobilityUpdateTimer);

    // ---- TRIDENT-VNDN data-plane wiring ----
    myNodeName = getParentModule()->getFullName();   // e.g. "vehicle[5]"
    trustReg = TrustRegistry::get(this);             // null if registry absent
    tridentIsolation = (trustReg != nullptr);        // isolate only when present
    selfAttack = dynamic_cast<AttackBase*>(getParentModule()->getSubmodule("attackModule"));
    attackTargetPrefix = "/safety";                  // prefix attackers serve/poison

    // Adversary activity window, read straight from the parent's attack params
    // (deterministic; does not depend on the attack module pointer).
    cModule *par = getParentModule();
    nodeIsAttacker = par->hasPar("hasAttackModule") && par->par("hasAttackModule").boolValue();
    attackWinStart = par->hasPar("attackStartTime") ? par->par("attackStartTime").doubleValue() : 0.0;
    double dur     = par->hasPar("attackDuration")  ? par->par("attackDuration").doubleValue()  : 0.0;
    attackWinEnd   = attackWinStart + dur;

    pendingSweepTimer = new cMessage("tridentPendingSweep");
    scheduleAt(simTime() + 1.0, pendingSweepTimer);

    // ---- TrustNet position-falsification setup (VeReMi taxonomy) ----
    posAttackType = hasPar("posAttackType") ? (int)this->par("posAttackType").intValue() : 0;
    posAttackerDensity = hasPar("posAttackerDensity") ? this->par("posAttackerDensity").doubleValue() : 0.0;
    // Randomized attacker selection (avoids any index/spawn-order artifact):
    // each vehicle independently becomes an attacker with probability = density.
    isPosAttacker = (posAttackType != 0) && (uniform(0.0, 1.0) < posAttackerDensity);
    // Stealth: ~40% of attackers falsify at half strength (boundary cases), so the
    // dataset contains hard-to-detect attackers, as in real misbehavior traces.
    posStealth = (isPosAttacker && uniform(0.0, 1.0) < 0.40) ? 0.5 : 1.0;
    hasReported = false;
    lastReportedX = lastReportedY = lastReportedSpeed = 0.0;
    fixedReportX = fixedReportY = 0.0;
    // constant-offset bias chosen once (20..55 m, random sign per axis)
    offsetReportX = uniform(20.0, 55.0) * (intuniform(0,1) ? 1.0 : -1.0);
    offsetReportY = uniform(20.0, 55.0) * (intuniform(0,1) ? 1.0 : -1.0);
    // eventual-stop instant: 25..70% of the sim horizon
    {
        double horizon = 200.0;
        try {
            const char *lim = getEnvir()->getConfig()->getConfigValue("sim-time-limit");
            if (lim && *lim) { double h = SimTime::parse(lim).dbl(); if (h > 0) horizon = h; }
        } catch (...) {}
        stopReportTime = uniform(0.25, 0.70) * horizon;
    }
    stopFrozen = false; stopFrozenX = stopFrozenY = 0.0;

    EV_INFO << "Vehicle Controller initialized: " << vehicleId << " with advanced mobility"
            << (tridentIsolation ? " [TRIDENT isolation ON]" : "") << endl;
}

void VehicleController::handleMessage(cMessage *msg) {
  try {
    // Self messages (timers)
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    // Frames delivered UP from the forwarder on the application face (face 0):
    // satisfying Data for this consumer, or (for a producer/attacker) an Interest
    // to answer.
    else if (msg->getArrivalGateId() == ndnInGate) {
        handleNDNMessage(msg);
    }
    // Frames the forwarder dispatched toward the wire face (face 1): broadcast
    // them onto the medium. A small medium latency lets an attacker's reply win
    // the PIT race against the slower RSU reply in the undefended case.
    else if (msg->getArrivalGateId() == wireInGate) {
        cPacket *pkt = dynamic_cast<cPacket*>(msg);
        if (pkt) deliverToNeighbors(pkt, 0.001);   // 1 ms medium latency
        else delete msg;
    }
    // Frames received over the air, or from the NIC: lift into the forwarder.
    else if (msg->getArrivalGateId() == lowerLayerInGate ||
             msg->getArrivalGateId() == directInGate) {
        handleLowerLayerMessage(msg);
    }
    // Control messages from lower layer
    else if (msg->getArrivalGateId() == lowerControlInGate) {
        handleLowerControlMessage(msg);
    }
    else {
        EV_WARN << "Unknown message arrival gate" << endl;
        delete msg;
    }
  } catch (std::exception &e) {
    FILE *dbg = fopen("results/trident_crash.log", "a");
    if (dbg) { fprintf(dbg, "t=%s %s: %s\n", simTime().str().c_str(),
                       myNodeName.c_str(), e.what()); fclose(dbg); }
    throw;
  }
}

void VehicleController::handleSelfMessage(cMessage *msg) {
    if (msg == beaconTimer) {
        sendBeacon();
        scheduleAt(simTime() + beaconInterval, beaconTimer);
    }
    else if (msg == requestTimer) {
        sendRequest();
        scheduleAt(simTime() + exponential(2.0), requestTimer);
    }
    else if (msg == mobilityUpdateTimer) {
        updateMobilityState();
        NeighborIndex::instance().setCellSize(communicationRange);
        NeighborIndex::instance().upsert(getParentModule(),
                                         currentPosition.x, currentPosition.y,
                                         false, isContentProducer, isForwarder);
        discoverNeighbors();
        cleanupStaleNeighbors();
        scheduleAt(simTime() + 0.1, mobilityUpdateTimer);
    }
    else if (!strcmp(msg->getName(), "relayTimer")) {
        fireRelay(msg);
    }
    else if (msg == pendingSweepTimer) {
        sweepPendingInterests();
        scheduleAt(simTime() + 1.0, pendingSweepTimer);
    }
    else {
        EV_WARN << "Unknown self message" << endl;
        delete msg;
    }
}

void VehicleController::handleNDNMessage(cMessage *msg) {
    cPacket *pkt = dynamic_cast<cPacket*>(msg);
    if (pkt) {
        processNDNPacket(pkt);
    } else {
        delete msg;
    }
}

void VehicleController::handleLowerLayerMessage(cMessage *msg) {
    cPacket *pkt = dynamic_cast<cPacket*>(msg);
    if (pkt) {
        processWirelessPacket(pkt);
        packetsReceived++;
    } else {
        delete msg;
    }
}

void VehicleController::handleLowerControlMessage(cMessage *msg) {
    // Handle control messages from NIC (e.g., channel busy, transmission status)
    EV_DEBUG << "Received control message from lower layer" << endl;
    delete msg;
}

void VehicleController::processNDNPacket(cPacket *pkt) {
    // Frames delivered UP from the forwarder on the APPLICATION face (face 0).
    //
    //  * Data here = the forwarder satisfied a PIT entry whose incoming face is
    //    this local consumer app. It is the answer to an Interest WE issued.
    //    The first matching Data consumed the PIT (genuine NDN), so we judge it:
    //    a valid (signed, trusted) reply counts as a satisfaction; a poisoned one
    //    means the request failed. This is the real, packet-level ISR.
    //
    //  * Interest here = the forwarder routed an overheard Interest up to the
    //    local PRODUCER app (FIB maps a served prefix to the app face). We answer
    //    with a signed Data on the same face; if this node carries an attackModule
    //    that Data is transformed (poisoned) on its way back into the stack.
    if (DataPacket *d = dynamic_cast<DataPacket*>(pkt)) {
        std::string dname = d->getName();
        auto pit = pendingInterests.find(dname);
        if (pit != pendingInterests.end()) {
            if (isValidData(d)) interestsSatisfied++;
            pendingInterests.erase(pit);            // consumer request resolved
        }
        delete pkt;
        return;
    }
    if (InterestPacket *interest = dynamic_cast<InterestPacket*>(pkt)) {
        // Local producer app answers from its served prefix. An adversarial
        // producer only injects content while its attack window is open
        // (attackStartTime .. +attackDuration); outside that window it stays
        // dormant so the pre/post-attack ISR is governed solely by honest RSUs.
        if (nodeIsAttacker) {
            double now = simTime().dbl();
            if (now < attackWinStart || now > attackWinEnd) { delete interest; return; }
        }
        producerAnswers++;
        DataPacket *data = new DataPacket();
        data->setName(interest->getName());
        data->setContent(("Content_" + myNodeName).c_str());
        data->setContentLength(256);
        data->setTimestamp(simTime());
        data->setFreshnessPeriod(10.0);
        data->setIsSigned(true);
        data->setSignerId(myNodeName.c_str());
        data->setSignature(("SIG_" + myNodeName).c_str());
        data->setTrustScore(1.0);
        data->setIsCacheable(true);
        sendToNDN(data);          // app face -> [attackModule] -> forwarder -> wire
        delete interest;
        return;
    }
    delete pkt;                   // Beacons/NACKs need no wire egress here
}

void VehicleController::deliverToNeighbors(cPacket *pkt, double delaySec) {
    // Broadcast a frame over the shared medium (a single collision-domain
    // abstraction standing in for 802.11p, which is not configured to carry raw
    // NDN cPackets in this build). sendDirect drops the frame on each peer's
    // directIn, where it is lifted into that peer's real forwarder.
    //
    //   * An INTEREST reaches the content-resolution plane: every RSU plus every
    //     vehicle that is a content producer (e.g. an attacker serving /safety).
    //     Pure consumers ignore overheard Interests, so they are skipped here,
    //     which also bounds fan-out and prevents re-broadcast storms.
    //   * A DATA reply reaches every vehicle, so the requesting consumer hears it.
    //
    // The transmitter identity is stamped so receivers can attribute content
    // integrity (belief) and honour TRIDENT quarantine at ingress.
    if (NdnPacket *ndnPkt = dynamic_cast<NdnPacket*>(pkt))
        ndnPkt->setSenderId(myNodeName.c_str());

    bool isBeacon   = (dynamic_cast<BeaconPacket*>(pkt) != nullptr);
    bool isInterest = (dynamic_cast<InterestPacket*>(pkt) != nullptr);
    int delivered = 0;

    // Spatial query instead of a full-network scan: only nodes in the nine grid
    // cells around this transmitter can be within radio range.
    std::vector<const NeighborIndex::Entry *> near;
    near.reserve(32);
    NeighborIndex::instance().query(currentPosition.x, currentPosition.y,
                                    communicationRange, getParentModule(), near);

    for (const NeighborIndex::Entry *e : near) {
        cModule *peer = e->host;
        if (!peer) continue;

        if (isBeacon) {
            // Presence beacons reach every node in range, infrastructure included.
        }
        else if (isInterest) {
            // Interests reach the resolution plane: producers answer them,
            // designated forwarders relay them.
            if (!e->isRsu && !e->isProducer && !e->isForwarder) continue;
        }
        else {
            // Data replies go to consumers, not back to infrastructure.
            if (e->isRsu) continue;
        }

        // Physical-plane effect: an active jammer covering this receiver
        // destroys the frame before it is delivered.
        if (JammingMedium::instance().anyActive()) {
            if (uniform(0.0, 1.0) <
                JammingMedium::instance().lossProbabilityAt(e->x, e->y)) {
                if (cModule *fe = peer->getSubmodule("featureExtractor"))
                    if (auto *obs = dynamic_cast<FeatureExtractor *>(fe))
                        obs->observePhyLoss();
                continue;
            }
        }

        cModule *peerCtrl = peer->getSubmodule("controller");
        if (!peerCtrl) continue;
        cGate *inGate = peerCtrl->gate("directIn");
        if (!inGate) continue;

        sendDirect(pkt->dup(), delaySec, 0, peerCtrl, inGate->getId());
        ++delivered;
    }

    packetsSent += delivered;
    delete pkt;
    EV_DETAIL << "Broadcast NDN frame to " << delivered << " peers" << endl;
}

void VehicleController::processWirelessPacket(cPacket *pkt) {
    // Process packets received from wireless (other vehicles/RSUs)
    EV_INFO << "Received wireless packet: " << pkt->getName() << endl;

    // ---- Detector-agnostic evidence: report every Data reply we hear (even
    // from a quarantined sender, so its belief stays high) to the registry. ----
    if (DataPacket *od = dynamic_cast<DataPacket*>(pkt)) {
        if (trustReg) {
            std::string s = od->getSenderId();
            if (!s.empty()) trustReg->recordObservation(s, !isValidData(od));
        }
    }

    // ---- TRIDENT prong 1: in-network isolation of quarantined neighbours ----
    // An honest node refuses to accept/relay any frame whose stamped sender is
    // currently quarantined by the trust controller. This is what makes the
    // mitigation reversible: the moment the sender is reinstated, its frames
    // flow again. Reads are O(log n) against the global blackboard.
    if (tridentIsolation) {
        if (NdnPacket *ndnPkt = dynamic_cast<NdnPacket*>(pkt)) {
            std::string sender = ndnPkt->getSenderId();
            if (!sender.empty() && trustReg && trustReg->isQuarantined(sender)) {
                framesDroppedQuarantine++;
                EV_DETAIL << myNodeName << " dropped frame from quarantined "
                          << sender << endl;
                delete pkt;
                return;
            }
        }
    }

    // ---- Lift the frame into the real forwarder on the WIRE face (face 1) ----
    // Everything below is genuine NDN: the processor runs PIT/CS/FIB and decides
    // what to do. We only gate WHICH frames are worth lifting so that pure
    // consumers do not act as forwarders (which would re-broadcast and storm).
    if (BeaconPacket *bp = dynamic_cast<BeaconPacket*>(pkt)) {
        // Hand the beacon to the local monitor before discarding it: this is
        // how MI-IDS learns which neighbours exist and where they claim to be.
        if (cModule *fe = getParentModule()->getSubmodule("featureExtractor"))
            if (auto *obs = dynamic_cast<FeatureExtractor *>(fe))
                obs->observeBeacon(bp);
        delete pkt;                 // presence beacon; the FIB is static per role
        return;
    }
    if (InterestPacket *oi = dynamic_cast<InterestPacket*>(pkt)) {
        // A producer answers overheard Interests. A designated forwarder also
        // lifts them, so that it sits on somebody's forwarding path and a
        // Selective Forwarding attacker has traffic it can choose to drop; the
        // hop-count ceiling is the broadcast-storm guard that the previous
        // producer-only rule provided implicitly.
        if (isContentProducer) {
            send(pkt, wireOutGate);
            return;
        }
        if (isForwarder && oi->getHopCount() < maxRelayHops) {
            std::string key = std::string(oi->getName()) + "#" +
                              std::to_string(oi->getNonce());
            simtime_t now = simTime();
            for (auto it = relaySeen.begin(); it != relaySeen.end(); ) {
                if ((now - it->second).dbl() > 4.0) it = relaySeen.erase(it);
                else ++it;
            }
            if (relaySeen.count(key)) {
                // Somebody else already put this Interest on the air; abandon
                // our own pending relay rather than adding a duplicate.
                cancelRelay(key);
                ++relaySuppressed;
                delete pkt;
                return;
            }
            relaySeen[key] = now;
            scheduleRelay(oi, key);
            return;      // ownership passed to the deferred relay
        }
        delete pkt;
        return;
    }
    if (dynamic_cast<DataPacket*>(pkt)) {
        // A reply is lifted into the forwarder so that it can satisfy this
        // node's PIT entry and be admitted to the Content Store. Every vehicle
        // issues requests, including those that also produce content, so a
        // producer must process replies as well. Discarding them at producers,
        // as the earlier model did, meant a producer could never satisfy its
        // own Interests and the Interest Satisfaction Ratio was unmeasurable
        // for that share of the fleet.
        send(pkt, wireOutGate);
        return;
    }
    delete pkt;
}

void VehicleController::finish() {
    recordScalar("totalRequests", requestCounter);
    recordScalar("packetsSent", packetsSent);
    recordScalar("packetsReceived", packetsReceived);

    // TRIDENT consumer-side resilience accounting.
    recordScalar("interestsIssued", interestsIssued);
    recordScalar("interestsSatisfied", interestsSatisfied);
    recordScalar("interestsExpired", interestsExpired);
    recordScalar("framesDroppedQuarantine", framesDroppedQuarantine);
    recordScalar("producerAnswers", producerAnswers);   // Data replies this node served
    double isr = (interestsIssued > 0) ? (double)interestsSatisfied / interestsIssued : 0.0;
    recordScalar("interestSatisfactionRatio", isr);

    EV_INFO << "Vehicle Controller finishing (ISR=" << isr << ")" << endl;
}

// An Interest is satisfied only by Data that is signed, carries a non-empty
// signature, and reports a usable trust score. Poisoned / forged Data (which the
// attack modules emit with a blanked signature) therefore never counts as a
// satisfaction, so the resilience curve reflects GENUINE content delivery.
bool VehicleController::isValidData(DataPacket *d) const {
    if (!d) return false;
    if (!d->isSigned()) return false;
    std::string sig = d->getSignature();
    std::string signer = d->getSignerId();
    if (sig.empty()) return false;
    if (d->getTrustScore() < 0.5) return false;
    // Content authenticity: a legitimate /safety reply is signed by an RSU
    // producer with that RSU's key (signature == "SIG_<signerId>"). A poisoner
    // either self-signs (signerId is a vehicle), blanks/forges the signature
    // (ContentPoisoning, SignatureForgery), or impersonates an RSU without the
    // matching key (ProducerImpersonation): all fail one of these checks, so
    // bogus content never counts as a satisfaction.
    if (signer.rfind("RSU", 0) != 0) return false;          // must be an RSU producer
    if (sig != std::string("SIG_") + signer) return false;  // authentic RSU signature
    return true;
}

// Expire Interests that were never satisfied within their lifetime.
void VehicleController::sweepPendingInterests() {
    simtime_t now = simTime();
    auto it = pendingInterests.begin();
    while (it != pendingInterests.end()) {
        if (now >= it->second.expiry) {
            interestsExpired++;
            it = pendingInterests.erase(it);
        } else {
            ++it;
        }
    }
}

void VehicleController::sendBeacon() {
    BeaconPacket *beacon = new BeaconPacket();
    beacon->setVehicleId(vehicleId.c_str());
    beacon->setIsProducer(isContentProducer);
    beacon->setTimestamp(simTime());

    // ---- TrustNet: stamp the REPORTED position into the beacon ----
    // True kinematics come from SUMO via the mobility module (currentPosition is
    // refreshed every 0.1 s by updateMobilityState()).
    double trueX = currentPosition.x;
    double trueY = currentPosition.y;
    double trueSpd = currentSpeed;
    double repX = trueX, repY = trueY;

    if (!isPosAttacker) {
        // Benign: report the true position with small GPS noise (~N(0, 0.5 m)).
        repX = trueX + normal(0.0, 0.5);
        repY = trueY + normal(0.0, 0.5);
    } else {
        // posStealth in {1.0 full, 0.5 stealthy} scales the falsification so the
        // dataset contains hard, half-strength attackers as well as blatant ones.
        double s = posStealth;
        switch (posAttackType) {
            case 1: // Constant Position: report a fixed point (blended for stealth)
                if (!hasReported) { fixedReportX = trueX; fixedReportY = trueY; }
                repX = s * fixedReportX + (1.0 - s) * trueX;
                repY = s * fixedReportY + (1.0 - s) * trueY;
                break;
            case 2: // Constant Offset: true position shifted by a fixed bias
                repX = trueX + s * offsetReportX; repY = trueY + s * offsetReportY;
                break;
            case 4: // Random Position: uniform ghost within a ~1.8 km box
                repX = trueX + s * uniform(-900.0, 900.0);
                repY = trueY + s * uniform(-900.0, 900.0);
                break;
            case 8: // Random Offset: per-beacon jitter in [-12,12] m
                repX = trueX + s * uniform(-12.0, 12.0);
                repY = trueY + s * uniform(-12.0, 12.0);
                break;
            case 16: // Eventual Stop: truthful until stopReportTime, then freeze
                if (!stopFrozen && simTime().dbl() >= stopReportTime) {
                    stopFrozen = true; stopFrozenX = trueX; stopFrozenY = trueY;
                }
                if (stopFrozen) {
                    repX = s * stopFrozenX + (1.0 - s) * trueX;
                    repY = s * stopFrozenY + (1.0 - s) * trueY;
                } else { repX = trueX; repY = trueY; }
                break;
            default:
                repX = trueX; repY = trueY; break;
        }
    }

    beacon->setLatitude(repX);
    beacon->setLongitude(repY);
    beacon->setSpeed(trueSpd);
    beacon->setHeading(currentHeading);

    lastReportedX = repX; lastReportedY = repY; lastReportedSpeed = trueSpd;
    hasReported = true;

    // Broadcast the beacon to neighbours in range. Sending it into the local
    // forwarder instead (as the published code did) made it hit the "unknown
    // packet type" branch of NDNProcessor and be dropped, so beacons never
    // reached anyone and no node could enumerate its neighbourhood.
    deliverToNeighbors(beacon, 0.0);
}

void VehicleController::buildZipfCdf() {
    // Zipf popularity over the shared catalogue. Precomputed once per node so
    // that drawing a name is O(log N) rather than O(N).
    zipfCdf.clear();
    if (catalogSize <= 0) return;
    zipfCdf.reserve(catalogSize);
    double norm = 0.0;
    for (int k = 1; k <= catalogSize; ++k) norm += 1.0 / std::pow((double)k, catalogZipfAlpha);
    double acc = 0.0;
    for (int k = 1; k <= catalogSize; ++k) {
        acc += (1.0 / std::pow((double)k, catalogZipfAlpha)) / norm;
        zipfCdf.push_back(acc);
    }
}

int VehicleController::drawCatalogItem() {
    if (zipfCdf.empty()) return 0;
    double u = uniform(0.0, 1.0);
    auto it = std::lower_bound(zipfCdf.begin(), zipfCdf.end(), u);
    int idx = (int)std::distance(zipfCdf.begin(), it);
    return std::min(idx, catalogSize - 1);
}

void VehicleController::sendRequest() {
    // Two kinds of demand coexist, which is what makes the caching plane
    // measurable. Most requests target a shared, Zipf-popular catalogue, so
    // repeat interest in the same names is common and a Content Store can serve
    // them; the remainder are genuinely one-off safety events with globally
    // unique names, which keep the Interest Satisfaction Ratio honest because
    // they can never be answered from cache.
    std::string name;
    if (uniform(0.0, 1.0) < uniqueNameFraction || zipfCdf.empty()) {
        name = "/safety/accident/" + myNodeName + "/" +
               std::to_string(requestCounter);
    }
    else {
        static const char *prefixes[3] = {"/traffic", "/info", "/content"};
        int item = drawCatalogItem();
        name = std::string(prefixes[item % 3]) + "/item/" + std::to_string(item);
    }

    InterestPacket *interest = new InterestPacket();
    interest->setName(name.c_str());
    interest->setNonce(intuniform(0, INT_MAX));
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    
    requestCounter++;

    // Consumer accounting: register the outstanding request so its eventual
    // (valid) satisfaction can be measured. Satisfaction is decided by the
    // forwarder delivering Data up to this app face (see processNDNPacket).
    PendingInterest pi;
    pi.issued = simTime();
    pi.expiry = simTime() + 4.0;   // matches interestLifetime
    pendingInterests[name] = pi;
    interestsIssued++;

    // Inject the Interest into the local forwarder on the APPLICATION face.
    // The forwarder records the PIT entry (incoming face = app) and, because a
    // consumer's FIB routes /safety to the WIRE face, dispatches it onto the
    // medium via wireIn -> deliverToNeighbors(). No hand-rolled broadcast.
    sendToNDN(interest);

    EV_INFO << "Vehicle consumer issued Interest: " << name << endl;
}


void VehicleController::scheduleRelay(InterestPacket *oi, const std::string &key) {
    cMessage *t = new cMessage("relayTimer");
    t->setContextPointer(new std::string(key));
    DeferredRelay dr{t, oi};
    pendingRelays[key] = dr;
    scheduleAt(simTime() + uniform(relayDeferMin, relayDeferMax), t);
}

void VehicleController::cancelRelay(const std::string &key) {
    auto it = pendingRelays.find(key);
    if (it == pendingRelays.end()) return;
    cancelAndDelete(it->second.timer);
    delete it->second.pkt;
    pendingRelays.erase(it);
    ++relayCancelled;
}

void VehicleController::fireRelay(cMessage *timer) {
    auto *keyp = static_cast<std::string *>(timer->getContextPointer());
    std::string key = keyp ? *keyp : std::string();
    delete keyp;
    auto it = pendingRelays.find(key);
    if (it == pendingRelays.end()) { delete timer; return; }
    InterestPacket *pkt = it->second.pkt;
    pendingRelays.erase(it);
    delete timer;
    ++relayedInterests;
    send(pkt, wireOutGate);
}

void VehicleController::sendToNDN(cPacket *pkt) {
    send(pkt, ndnOutGate);
}

void VehicleController::sendToLowerLayer(cPacket *pkt) {
    send(pkt, lowerLayerOutGate);
    packetsSent++;
}

} // namespace veremivndn
//
// VeReMiVNDN - Enhanced VEINS Mobility Functions Implementation
// Advanced mobility integration for VehicleController
//
// NOTE: This file should be appended to VehicleController.cc or included
//

#include "VehicleController.h"
#include <cmath>

namespace veremivndn {

// ========================================
// MOBILITY INITIALIZATION AND STATE UPDATE
// ========================================

void VehicleController::initializeMobility() {
    // Get mobility module from parent — support both TraCIMobility (VndnVehicle)
    // and VeinsInetMobility (VndnNRVehicle)
    cModule *parent = getParentModule();
    cModule *mobilityMod = parent->getSubmodule("mobility");
    if (!mobilityMod) {
        EV_WARN << "Mobility module not found!" << endl;
        return;
    }

    mobility = dynamic_cast<TraCIMobility*>(mobilityMod);

    if (mobility) {
        // Full TraCIMobility — get TraCI command interface
        traci = mobility->getCommandInterface();
        traciVehicle = mobility->getVehicleCommandInterface();
        updateMobilityState();
        EV_INFO << "VEINS TraCIMobility initialized for " << vehicleId << endl;
    } else {
        // VeinsInetMobility or other INET mobility — no TraCI command interface
        // Position updates still work via IMobility interface
        EV_INFO << "INET mobility initialized for " << vehicleId
                << " (TraCI commands not available)" << endl;
    }
}

void VehicleController::updateMobilityState() {
    if (!mobility) return;

    // Live position straight from the mobility module (TraCI does not update the
    // NED x/y params, and getPositionAt() can read back the origin). This is the
    // authoritative coordinate used by the broadcast data plane.
    currentPosition = mobility->getPositionAt(simTime());
    currentSpeed = mobility->getSpeed();
    currentHeading = mobility->getHeading().getRad();
    currentRoadId = mobility->getRoadId();

    // Lane info needs the TraCI command interface (may be absent for INET mobility).
    if (traciVehicle) {
        currentLaneId = traciVehicle->getLaneId();
        currentLaneIndex = traciVehicle->getLaneIndex();
    }

    emit(positionUpdateSignal, currentSpeed);
}

// ========================================
// POSITION AND MOVEMENT
// ========================================

Coord VehicleController::getPosition() {
    if (mobility) {
        return mobility->getPositionAt(simTime());
    }
    return Coord(0, 0, 0);
}

double VehicleController::getSpeed() {
    if (mobility) {
        return mobility->getSpeed();
    }
    return 0.0;
}

double VehicleController::getHeading() {
    if (mobility) {
        return mobility->getHeading().getRad();
    }
    return 0.0;
}

double VehicleController::getAcceleration() {
    if (traciVehicle) {
        return traciVehicle->getAcceleration();
    }
    return 0.0;
}

void VehicleController::setSpeed(double speed) {
    if (traciVehicle) {
        traciVehicle->setSpeed(speed);
        emit(speedChangeSignal, speed);
        EV_DEBUG << vehicleId << " speed set to " << speed << " m/s" << endl;
    }
}

void VehicleController::setMaxSpeed(double maxSpeed) {
    if (traciVehicle) {
        traciVehicle->setMaxSpeed(maxSpeed);
        EV_DEBUG << vehicleId << " max speed set to " << maxSpeed << " m/s" << endl;
    }
}

// ========================================
// ROAD AND LANE INFORMATION
// ========================================

std::string VehicleController::getRoadId() {
    if (mobility) {
        return mobility->getRoadId();
    }
    return "";
}

std::string VehicleController::getLaneId() {
    if (traciVehicle) {
        return traciVehicle->getLaneId();
    }
    return "";
}

int VehicleController::getLaneIndex() {
    if (traciVehicle) {
        return traciVehicle->getLaneIndex();
    }
    return 0;
}

int VehicleController::getNumberOfLanes() {
    if (traciVehicle) {
        std::string edgeId = mobility->getRoadId();
        // Query SUMO for number of lanes on this edge
        return 2; // Default - would query TraCI in full implementation
    }
    return 1;
}

double VehicleController::getLanePosition() {
    if (traciVehicle) {
        return traciVehicle->getLanePosition();
    }
    return 0.0;
}

// ========================================
// LANE CHANGE OPERATIONS
// ========================================

void VehicleController::changeLane(int direction) {
    if (!traciVehicle) return;

    int currentLane = getLaneIndex();
    int targetLane = currentLane + direction;

    if (targetLane >= 0 && targetLane < getNumberOfLanes()) {
        // TODO: changeLane() method not available in current Veins version
        // traciVehicle->changeLane(targetLane, 3.0); // Duration: 3 seconds
        emit(laneChangeSignal, (long)targetLane);
        EV_WARN << vehicleId << " lane change requested but API not available in current Veins version" << endl;
    }
}

bool VehicleController::canChangeLaneRight() {
    int currentLane = getLaneIndex();
    return currentLane > 0;
}

bool VehicleController::canChangeLaneLeft() {
    int currentLane = getLaneIndex();
    return currentLane < (getNumberOfLanes() - 1);
}

void VehicleController::setLaneChangeMode(int mode) {
    if (traciVehicle) {
        // TODO: setLaneChangeMode() method not available in current Veins version
        // traciVehicle->setLaneChangeMode(mode);
        EV_WARN << vehicleId << " setLaneChangeMode requested but API not available in current Veins version" << endl;
    }
}

// ========================================
// ROUTE MANIPULATION
// ========================================

std::list<std::string> VehicleController::getPlannedRoute() {
    if (traciVehicle) {
        return traciVehicle->getPlannedRoadIds();
    }
    return std::list<std::string>();
}

void VehicleController::changeRoute(const std::list<std::string> &edges) {
    if (traciVehicle && edges.size() > 0) {
        // Current Veins API only supports single road changeRoute
        // Convert list to single road (use first edge)
        std::string firstEdge = *edges.begin();
        traciVehicle->changeRoute(firstEdge, simTime());
        EV_INFO << vehicleId << " changed route to edge: " << firstEdge << endl;
    }
}

void VehicleController::rerouteToDestination(const std::string &dest) {
    if (traciVehicle) {
        // Get current edge
        std::string currentEdge = getRoadId();
        // Request rerouting from TraCI
        traciVehicle->changeTarget(dest);
        EV_INFO << vehicleId << " rerouting to " << dest << endl;
    }
}

std::string VehicleController::getRouteId() {
    if (mobility) {
        return mobility->getExternalId(); // Vehicle ID can be used as route identifier
    }
    return "";
}

// ========================================
// TRAFFIC LIGHT INTERACTION
// ========================================

std::string VehicleController::getNextTrafficLight() {
    if (traciVehicle) {
        // Query next traffic light from TraCI (returns vector of tuples)
        auto tlsList = traciVehicle->getNextTls();
        if (!tlsList.empty()) {
            // Extract first traffic light ID from tuple<string, int, double, char>
            return std::get<0>(tlsList.front());
        }
    }
    return "";
}

double VehicleController::getDistanceToTrafficLight() {
    if (traciVehicle) {
        // TODO: getNextTLSInfo() not available in current Veins version
        // Return a default value for now
        return 100.0; // Default distance
    }
    return -1.0;
}

std::string VehicleController::getTrafficLightState() {
    std::string tlId = getNextTrafficLight();
    if (!tlId.empty() && traci) {
        // Query traffic light state
        // return traci->trafficlight(tlId).getState();
        return "green"; // Placeholder
    }
    return "unknown";
}

void VehicleController::requestTrafficLightPriority() {
    // Emergency vehicle priority request
    std::string tlId = getNextTrafficLight();
    if (!tlId.empty()) {
        EV_INFO << vehicleId << " requesting priority at TL " << tlId << endl;
        // Would send priority request via TraCI
    }
}

// ========================================
// VEHICLE CONTROL
// ========================================

void VehicleController::slowDown(double speed, double duration) {
    if (traciVehicle) {
        traciVehicle->slowDown(speed, (int)(duration * 1000)); // Convert to ms
        EV_INFO << vehicleId << " slowing down to " << speed
                << " m/s for " << duration << " seconds" << endl;
    }
}

void VehicleController::changeTarget(const std::string &edge) {
    if (traciVehicle) {
        traciVehicle->changeTarget(edge);
        EV_INFO << vehicleId << " changing target to edge " << edge << endl;
    }
}

void VehicleController::stopVehicle() {
    if (traciVehicle) {
        setSpeed(0.0);
        EV_INFO << vehicleId << " stopped" << endl;
    }
}

void VehicleController::resumeVehicle() {
    if (traciVehicle) {
        double maxSpeed = traciVehicle->getMaxSpeed();
        setSpeed(maxSpeed);
        EV_INFO << vehicleId << " resumed" << endl;
    }
}

// ========================================
// ENVIRONMENT SENSING
// ========================================

double VehicleController::getDistanceToRoadEnd() {
    if (traciVehicle) {
        std::string roadId = getRoadId();
        double lanePos = getLanePosition();
        // Calculate distance to end of current road
        // Would query road length from TraCI
        return 1000.0; // Placeholder
    }
    return -1.0;
}

std::string VehicleController::getNextEdge() {
    auto route = getPlannedRoute();
    if (route.size() > 1) {
        auto it = route.begin();
        it++; // Move to next edge
        return *it;
    }
    return "";
}

std::list<std::string> VehicleController::getAdjacentVehicles() {
    // Query adjacent vehicles from SUMO
    // This would use TraCI to get vehicles on adjacent lanes
    std::list<std::string> adjacent;
    // Placeholder
    return adjacent;
}

// ========================================
// NEIGHBOR DISCOVERY AND MANAGEMENT
// ========================================

void VehicleController::discoverNeighbors() {
    // This would be called when receiving beacons from other vehicles
    // The actual discovery happens through beacon exchange
    // Here we just maintain the neighbor list
}

void VehicleController::updateNeighborInfo(const std::string &neighId, const Coord &pos,
                                          double speed, double heading, bool isProvider) {
    NeighborInfo &info = neighbors[neighId];
    info.vehicleId = neighId;
    info.position = pos;
    info.speed = speed;
    info.heading = heading;
    info.lastUpdate = simTime();
    info.distance = distanceToPosition(pos);
    info.isContentProvider = isProvider;

    emit(neighborDiscoveredSignal, 1L);

    EV_DEBUG << vehicleId << " updated neighbor " << neighId
             << " at distance " << info.distance << " m" << endl;
}

std::vector<std::string> VehicleController::getNearbyVehicles(double range) {
    std::vector<std::string> nearby;

    for (const auto &pair : neighbors) {
        if (pair.second.distance <= range) {
            nearby.push_back(pair.first);
        }
    }

    return nearby;
}

NeighborInfo* VehicleController::getClosestNeighbor() {
    NeighborInfo *closest = nullptr;
    double minDist = std::numeric_limits<double>::max();

    for (auto &pair : neighbors) {
        if (pair.second.distance < minDist) {
            minDist = pair.second.distance;
            closest = &pair.second;
        }
    }

    return closest;
}

void VehicleController::cleanupStaleNeighbors() {
    simtime_t now = simTime();
    double timeout = 5.0; // 5 seconds timeout

    auto it = neighbors.begin();
    while (it != neighbors.end()) {
        if ((now - it->second.lastUpdate).dbl() > timeout) {
            EV_DEBUG << vehicleId << " removing stale neighbor " << it->first << endl;
            it = neighbors.erase(it);
        } else {
            ++it;
        }
    }
}

// ========================================
// MOBILITY-AWARE NDN OPERATIONS
// ========================================

void VehicleController::forwardToNearestNeighbor(cPacket *pkt) {
    NeighborInfo *nearest = getClosestNeighbor();

    if (nearest) {
        EV_INFO << vehicleId << " forwarding to nearest neighbor "
                << nearest->vehicleId << " at " << nearest->distance << " m" << endl;
        sendToLowerLayer(pkt);
    } else {
        EV_WARN << vehicleId << " no neighbors available for forwarding" << endl;
        delete pkt;
    }
}

void VehicleController::geographicForwarding(cPacket *pkt, const Coord &destination) {
    // Geographic forwarding: select neighbor closest to destination

    double myDist = distanceToPosition(destination);
    std::string bestNeighbor = "";
    double bestDist = myDist;

    for (const auto &pair : neighbors) {
        Coord neighPos = pair.second.position;
        double neighDist = destination.distance(neighPos);

        if (neighDist < bestDist) {
            bestDist = neighDist;
            bestNeighbor = pair.first;
        }
    }

    if (!bestNeighbor.empty()) {
        EV_INFO << vehicleId << " geographic forwarding to " << bestNeighbor
                << " (dist to dest: " << bestDist << " m)" << endl;
        sendToLowerLayer(pkt);
    } else {
        EV_INFO << vehicleId << " is closest to destination, delivering locally" << endl;
        sendToNDN(pkt);
    }
}

std::string VehicleController::selectNextHopByMobility(const std::string &targetName) {
    // Select next hop based on mobility metrics:
    // - Moving in same direction
    // - Higher relative speed (for catching up)
    // - Stable connection (low relative velocity)

    std::string bestHop = "";
    double bestScore = -1.0;

    for (const auto &pair : neighbors) {
        double score = 0.0;

        // Factor 1: Distance (closer is better)
        double distScore = 1.0 / (1.0 + pair.second.distance / 100.0);
        score += distScore * 0.3;

        // Factor 2: Heading similarity (same direction is better)
        double headingDiff = std::abs(pair.second.heading - currentHeading);
        double headingScore = 1.0 - (headingDiff / M_PI);
        score += headingScore * 0.3;

        // Factor 3: Relative speed (moderate relative speed is better)
        double relSpeed = std::abs(pair.second.speed - currentSpeed);
        double speedScore = 1.0 / (1.0 + relSpeed / 10.0);
        score += speedScore * 0.2;

        // Factor 4: Content provider preference
        if (pair.second.isContentProvider) {
            score += 0.2;
        }

        if (score > bestScore) {
            bestScore = score;
            bestHop = pair.first;
        }
    }

    return bestHop;
}

// ========================================
// DISTANCE CALCULATIONS
// ========================================

double VehicleController::distanceToVehicle(const std::string &vehicleId) {
    auto it = neighbors.find(vehicleId);
    if (it != neighbors.end()) {
        return it->second.distance;
    }
    return -1.0;
}

double VehicleController::distanceToPosition(const Coord &pos) {
    return currentPosition.distance(pos);
}

bool VehicleController::isWithinRange(const Coord &pos, double range) {
    return distanceToPosition(pos) <= range;
}

} // namespace veremivndn
