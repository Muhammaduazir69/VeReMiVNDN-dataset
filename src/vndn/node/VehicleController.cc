//
// VeReMiVNDN - Vehicle Controller Implementation
// Handles vehicle application logic with VEINS and NDN integration
//

#include "VehicleController.h"

namespace veremivndn {

Define_Module(VehicleController);

VehicleController::VehicleController()
    : beaconTimer(nullptr), requestTimer(nullptr), mobilityUpdateTimer(nullptr),
      requestCounter(0), packetsSent(0), packetsReceived(0),
      isContentProducer(false), mobility(nullptr), traci(nullptr),
      traciVehicle(nullptr), currentSpeed(0.0), currentHeading(0.0),
      currentLaneIndex(0), communicationRange(500.0) {}

VehicleController::~VehicleController() {
    cancelAndDelete(beaconTimer);
    cancelAndDelete(requestTimer);
    cancelAndDelete(mobilityUpdateTimer);
}

void VehicleController::initialize() {
    // Get gate IDs
    ndnInGate = findGate("ndnIn");
    ndnOutGate = findGate("ndnOut");
    lowerLayerInGate = findGate("lowerLayerIn");
    lowerLayerOutGate = findGate("lowerLayerOut");
    lowerControlInGate = findGate("lowerControlIn");
    lowerControlOutGate = findGate("lowerControlOut");

    // Configuration
    vehicleId = par("vehicleId").stdstringValue();
    if (vehicleId.empty()) {
        vehicleId = "V_" + std::to_string(getParentModule()->getIndex());
    }

    isContentProducer = par("isContentProducer");
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

    if (!isContentProducer) {
        requestTimer = new cMessage("vehicleRequestTimer");
        scheduleAt(simTime() + uniform(1.0, 3.0), requestTimer);
    }

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

    EV_INFO << "Vehicle Controller initialized: " << vehicleId << " with advanced mobility" << endl;
}

void VehicleController::handleMessage(cMessage *msg) {
    // Self messages (timers)
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    // Messages from NDN layer
    else if (msg->getArrivalGateId() == ndnInGate) {
        handleNDNMessage(msg);
    }
    // Messages from lower layer (wireless)
    else if (msg->getArrivalGateId() == lowerLayerInGate) {
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
        discoverNeighbors();
        cleanupStaleNeighbors();
        scheduleAt(simTime() + 0.1, mobilityUpdateTimer);
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
    // Process packets coming back from NDN layer
    if (dynamic_cast<DataPacket*>(pkt)) {
        DataPacket *data = check_and_cast<DataPacket*>(pkt);
        EV_INFO << "Vehicle received Data from NDN: " << data->getName() << endl;

        // Could forward to other vehicles via wireless
        // For now, just process locally
        delete data;
    }
    else {
        delete pkt;
    }
}

void VehicleController::processWirelessPacket(cPacket *pkt) {
    // Process packets received from wireless (other vehicles/RSUs)
    EV_INFO << "Received wireless packet: " << pkt->getName() << endl;

    // Check if it's a beacon with route advertisements
    if (BeaconPacket *beacon = dynamic_cast<BeaconPacket*>(pkt)) {
        if (beacon->isProducer() && beacon->getProducedPrefixesArraySize() > 0) {
            // Update FIB with announced prefixes from producer
            cModule *parent = getParentModule();
            cModule *ndnNode = parent->getSubmodule("ndnNode");

            for (unsigned int i = 0; i < beacon->getProducedPrefixesArraySize(); i++) {
                std::string prefix = beacon->getProducedPrefixes(i);

                // Create FIB add route request
                FIBAddRouteRequest *fibReq = new FIBAddRouteRequest();
                fibReq->setPrefix(prefix.c_str());
                fibReq->setNextHop(0);  // Face 0 connects to network
                fibReq->setCost(1);     // Base cost
                fibReq->setTransactionId(intuniform(1, 1000000));

                send(fibReq, ndnOutGate);

                EV_INFO << "Learned route from beacon: " << prefix
                        << " from " << beacon->getVehicleId() << endl;
            }
        }
        delete beacon;
        return;
    }

    // Forward other packets to NDN layer for processing
    send(pkt, ndnOutGate);
}

void VehicleController::finish() {
    recordScalar("totalRequests", requestCounter);
    recordScalar("packetsSent", packetsSent);
    recordScalar("packetsReceived", packetsReceived);
    EV_INFO << "Vehicle Controller finishing" << endl;
}

void VehicleController::sendBeacon() {
    BeaconPacket *beacon = new BeaconPacket();
    beacon->setVehicleId(vehicleId.c_str());
    beacon->setIsProducer(isContentProducer);
    beacon->setTimestamp(simTime());

    // Send beacon to NDN layer for processing
    sendToNDN(beacon);
}

void VehicleController::sendRequest() {
    std::string name = "/safety/accident/" + std::to_string(intuniform(1, 100));
    
    InterestPacket *interest = new InterestPacket();
    interest->setName(name.c_str());
    interest->setNonce(intuniform(0, INT_MAX));
    interest->setInterestLifetime(4.0);
    interest->setTimestamp(simTime());
    interest->setHopCount(0);
    
    sendToNDN(interest);
    requestCounter++;
    
    EV_INFO << "Vehicle sent Interest: " << name << endl;
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
    // Get mobility module from parent
    cModule *parent = getParentModule();
    mobility = check_and_cast<TraCIMobility*>(parent->getSubmodule("mobility"));

    if (mobility) {
        // Get TraCI command interface
        traci = mobility->getCommandInterface();
        traciVehicle = mobility->getVehicleCommandInterface();

        // Initialize mobility state
        updateMobilityState();

        EV_INFO << "VEINS mobility initialized for " << vehicleId << endl;
    } else {
        EV_WARN << "Mobility module not found!" << endl;
    }
}

void VehicleController::updateMobilityState() {
    if (!mobility || !traciVehicle) return;

    // Update position
    currentPosition = mobility->getPositionAt(simTime());

    // Update speed and heading
    currentSpeed = mobility->getSpeed();
    currentHeading = mobility->getHeading().getRad();

    // Update road/lane information
    currentRoadId = mobility->getRoadId();
    currentLaneId = traciVehicle->getLaneId();
    currentLaneIndex = traciVehicle->getLaneIndex();

    // Emit position update signal
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
