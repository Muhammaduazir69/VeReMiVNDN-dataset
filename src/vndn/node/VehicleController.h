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
    int lowerLayerInGate;
    int lowerLayerOutGate;
    int lowerControlInGate;
    int lowerControlOutGate;

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
};

Define_Module(VehicleController);

} // namespace veremivndn

#endif
