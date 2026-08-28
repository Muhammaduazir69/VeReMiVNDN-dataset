//
// VeReMiVNDN - Enhanced Vehicle Controller Header
// Handles vehicle application logic with advanced VEINS and NDN integration
//

#ifndef __VEREMIVNDN_VEHICLECONTROLLER_H
#define __VEREMIVNDN_VEHICLECONTROLLER_H

#include <omnetpp.h>
#include "../../ndn/packets/NdnPackets_m.h"
#include "../../ndn/core/NdnControlMessages_m.h"
#include <vector>
#include <string>
#include <map>
#include <set>

// VEINS includes for advanced mobility functions
#include "veins/modules/mobility/traci/TraCIMobility.h"
#include "veins/modules/mobility/traci/TraCICommandInterface.h"
#include "veins/modules/mobility/traci/TraCIScenarioManager.h"
#include "veins/base/utils/Coord.h"

using namespace omnetpp;
using namespace veins;

namespace veremivndn {

// Neighbor vehicle information
struct NeighborInfo {
    std::string vehicleId;
    Coord position;
    double speed;
    double heading;
    simtime_t lastUpdate;
    double distance;
    bool isContentProvider;
};

class VehicleController : public cSimpleModule {
protected:
    // Configuration
    std::string vehicleId;
    bool isContentProducer;

    // ---- VeReMiVNDN-EXE content model / forwarding role ----
    bool   isForwarder = false;
    int    catalogSize = 200;
    double catalogZipfAlpha = 0.9;
    double uniqueNameFraction = 0.25;
    int    maxRelayHops = 3;
    std::vector<double> zipfCdf;      // cached popularity CDF over the catalogue
    void   buildZipfCdf();
    int    drawCatalogItem();
    long   relayedInterests = 0;
    // Duplicate suppression for relayed Interests. Without it, every forwarder
    // rebroadcasts every Interest it overhears to every other forwarder, and
    // the fan-out compounds into a broadcast storm within a few simulated
    // seconds. Standard NDN suppresses on the (name, nonce) pair.
    std::map<std::string, simtime_t> relaySeen;
    long   relaySuppressed = 0;

    // Deferred rebroadcast with overhear-and-cancel. Flooding an Interest to
    // every in-range forwarder makes the number of copies grow with the
    // neighbourhood size at every hop. The standard mitigation is to wait a
    // short random interval before relaying and to abandon the relay if the
    // same Interest is heard from somebody else meanwhile, so that only the
    // nodes that actually extend coverage retransmit.
    struct DeferredRelay { cMessage *timer; InterestPacket *pkt; };
    std::map<std::string, DeferredRelay> pendingRelays;
    double relayDeferMin = 0.005;
    double relayDeferMax = 0.030;
    long   relayCancelled = 0;
    void scheduleRelay(InterestPacket *oi, const std::string &key);
    void cancelRelay(const std::string &key);
    void fireRelay(cMessage *timer);
    std::vector<std::string> producedPrefixes;

    // Timers
    cMessage *beaconTimer;
    simtime_t beaconInterval;
    cMessage *requestTimer;
    cMessage *mobilityUpdateTimer;

    // Counters
    int requestCounter;
    int packetsSent;
    int packetsReceived;

    // Gate IDs
    int ndnInGate;
    int ndnOutGate;
    int wireInGate;
    int wireOutGate;
    int lowerLayerInGate;
    int lowerLayerOutGate;
    int lowerControlInGate;
    int lowerControlOutGate;
    int directInGate;

    // VEINS/TraCI Integration (Enhanced)
    TraCIMobility *mobility;
    TraCICommandInterface *traci;
    TraCICommandInterface::Vehicle *traciVehicle;

    // Mobility state
    Coord currentPosition;
    double currentSpeed;
    double currentHeading;
    std::string currentRoadId;
    std::string currentLaneId;
    int currentLaneIndex;

    // Neighbor management
    std::map<std::string, NeighborInfo> neighbors;
    double communicationRange;

    // ========================================
    // TRIDENT-VNDN data-plane state
    // ========================================
    std::string myNodeName;          // this vehicle's module full name (= senderId)
    class TrustRegistry *trustReg;    // global blackboard (resolved lazily)
    bool tridentIsolation;           // honour quarantine drops if true
    class AttackBase *selfAttack;     // own attack module (nullptr if benign)
    std::string attackTargetPrefix;   // prefix this attacker poisons (default /safety)
    bool   nodeIsAttacker;           // this node carries an attack module
    double attackWinStart;           // s; adversary injects only within [start,end]
    double attackWinEnd;
    long   producerAnswers = 0;      // diagnostic: producer-app Data replies built

    // Consumer-side Interest-satisfaction accounting (honest ISR):
    // an Interest counts as satisfied only when a VALID Data (signed, trusted,
    // from a non-quarantined sender) for its name arrives within its lifetime.
    struct PendingInterest { simtime_t issued; simtime_t expiry; };
    std::map<std::string, PendingInterest> pendingInterests;
    std::set<std::string> validCache;  // names this node holds a valid copy of (V2V caching)
    long interestsIssued;            // total Interests this consumer launched
    long interestsSatisfied;         // satisfied by valid Data
    long interestsExpired;           // timed out (unsatisfied)
    long framesDroppedQuarantine;    // frames discarded due to quarantined sender
    cMessage *pendingSweepTimer;

    // ========================================
    // TrustNet position-falsification state (VeReMi taxonomy)
    // ========================================
    int posAttackType;               // 0 benign else 1/2/4/8/16
    double posAttackerDensity;       // fraction of vehicles selected as attackers
    bool isPosAttacker;              // this vehicle falsifies its beacon position
    double posStealth;               // 1.0 full-strength, 0.5 stealthy (boundary)
    // last position this vehicle REPORTED in its beacon (true+noise if benign,
    // falsified if attacker). Read by the TrustNetCollector from the wire-equivalent.
    double lastReportedX, lastReportedY, lastReportedSpeed;
    bool   hasReported;
    // per-type falsification memory
    double fixedReportX, fixedReportY;   // type 1 (constant position)
    double offsetReportX, offsetReportY; // type 2 (constant offset bias)
    double stopReportTime;               // type 16 (eventual stop instant)
    bool   stopFrozen;                   // type 16 latched
    double stopFrozenX, stopFrozenY;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Message handlers
    virtual void handleSelfMessage(cMessage *msg);
    virtual void handleNDNMessage(cMessage *msg);
    virtual void handleLowerLayerMessage(cMessage *msg);
    virtual void handleLowerControlMessage(cMessage *msg);

    // NDN operations
    virtual void sendBeacon();
    virtual void sendRequest();
    virtual void sendToNDN(cPacket *pkt);
    virtual void processNDNPacket(cPacket *pkt);

    // Network operations
    virtual void sendToLowerLayer(cPacket *pkt);
    virtual void processWirelessPacket(cPacket *pkt);
    virtual void deliverToNeighbors(cPacket *pkt, double delaySec = 0.0);

    // ========================================
    // ENHANCED VEINS MOBILITY FUNCTIONS
    // ========================================

    // Initialization
    virtual void initializeMobility();
    virtual void updateMobilityState();

    // Position and movement
    virtual Coord getPosition();
    virtual double getSpeed();
    virtual double getHeading();
    virtual double getAcceleration();
    virtual void setSpeed(double speed);
    virtual void setMaxSpeed(double maxSpeed);

    // Road and lane information
    virtual std::string getRoadId();
    virtual std::string getLaneId();
    virtual int getLaneIndex();
    virtual int getNumberOfLanes();
    virtual double getLanePosition();

    // Lane change operations
    virtual void changeLane(int direction); // -1: right, 1: left
    virtual bool canChangeLaneRight();
    virtual bool canChangeLaneLeft();
    virtual void setLaneChangeMode(int mode);

    // Route manipulation
    virtual std::list<std::string> getPlannedRoute();
    virtual void changeRoute(const std::list<std::string> &edges);
    virtual void rerouteToDestination(const std::string &dest);
    virtual std::string getRouteId();

    // Traffic light interaction
    virtual std::string getNextTrafficLight();
    virtual double getDistanceToTrafficLight();
    virtual std::string getTrafficLightState();
    virtual void requestTrafficLightPriority();

    // Vehicle control
    virtual void slowDown(double speed, double duration);
    virtual void changeTarget(const std::string &edge);
    virtual void stopVehicle();
    virtual void resumeVehicle();

    // Environment sensing
    virtual double getDistanceToRoadEnd();
    virtual std::string getNextEdge();
    virtual std::list<std::string> getAdjacentVehicles();

    // Neighbor discovery and management
    virtual void discoverNeighbors();
    virtual void updateNeighborInfo(const std::string &neighId, const Coord &pos,
                                   double speed, double heading, bool isProvider);
    virtual std::vector<std::string> getNearbyVehicles(double range);
    virtual NeighborInfo* getClosestNeighbor();
    virtual void cleanupStaleNeighbors();

    // Mobility-aware NDN operations
    virtual void forwardToNearestNeighbor(cPacket *pkt);
    virtual void geographicForwarding(cPacket *pkt, const Coord &destination);
    virtual std::string selectNextHopByMobility(const std::string &targetName);

    // Distance calculations
    virtual double distanceToVehicle(const std::string &vehicleId);
    virtual double distanceToPosition(const Coord &pos);
    virtual bool isWithinRange(const Coord &pos, double range);

    // Signals (for statistics and events)
    simsignal_t positionUpdateSignal;
    simsignal_t speedChangeSignal;
    simsignal_t laneChangeSignal;
    simsignal_t neighborDiscoveredSignal;

public:
    VehicleController();
    virtual ~VehicleController();

    // Public interface for other modules
    TraCIMobility* getMobility() { return mobility; }
    const Coord& getCurrentPosition() const { return currentPosition; }
    double getCurrentSpeed() const { return currentSpeed; }
    const std::map<std::string, NeighborInfo>& getNeighbors() const { return neighbors; }

    // TrustNet: read by TrustNetCollector to build the per-vehicle feature set.
    int  getEffectivePosAttackType() const { return isPosAttacker ? posAttackType : 0; }
    bool getIsPosAttacker() const { return isPosAttacker; }
    bool hasReportedPos() const { return hasReported; }
    double getLastReportedX() const { return lastReportedX; }
    double getLastReportedY() const { return lastReportedY; }
    double getLastReportedSpeed() const { return lastReportedSpeed; }

    // TRIDENT: consumer-side resilience counters read by ResilienceMonitor.
    long getInterestsIssued() const { return interestsIssued; }
    long getInterestsSatisfied() const { return interestsSatisfied; }
    long getInterestsExpired() const { return interestsExpired; }
    long getFramesDroppedQuarantine() const { return framesDroppedQuarantine; }

protected:
    // TRIDENT helpers
    void sweepPendingInterests();    // expire timed-out pending Interests
    bool isValidData(class DataPacket *d) const;  // signed + trusted + sender ok
};

} // namespace veremivndn

#endif
