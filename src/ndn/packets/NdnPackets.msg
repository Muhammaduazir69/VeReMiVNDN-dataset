//
// VeReMiVNDN - NDN Packet Definitions
// Message definitions for NDN protocol packets
//
// This file defines all NDN packet types used in the simulation:
// - Interest packets
// - Data packets
// - NACK packets
//

// Removed INET dependency - using plain OMNeT++ packets
// cplusplus {{
// #include "inet/common/packet/chunk/Chunk.h"
// }}

namespace veremivndn;

// NDN Packet Types
enum NdnPacketType {
    NDN_INTEREST = 0;
    NDN_DATA = 1;
    NDN_NACK = 2;
}

// Interest Packet Selector
struct InterestSelector {
    int minSuffixComponents = -1;
    int maxSuffixComponents = -1;
    bool mustBeFresh = false;
}

// NACK Reason Codes
enum NackReason {
    NACK_NONE = 0;
    NACK_CONGESTION = 50;
    NACK_DUPLICATE = 100;
    NACK_NO_ROUTE = 150;
}

//
// Base NDN Packet
//
packet NdnPacket {
    int packetType @enum(NdnPacketType);
    string name;                    // NDN name (e.g., /vehicle/traffic/info/highway1)
    simtime_t timestamp;            // Packet creation timestamp
    int hopCount = 0;               // Number of hops traversed
    string forwardingHint = "";     // Forwarding hint for routing
}

//
// Interest Packet
// Represents a request for content in NDN
//
packet InterestPacket extends NdnPacket {
    packetType = NDN_INTEREST;

    // Interest parameters
    int nonce;                      // Random nonce for loop detection
    simtime_t interestLifetime = 4.0; // Interest lifetime (default 4 seconds)

    // Selectors
    InterestSelector selectors;

    // VNDN specific fields
    double latitude = 0.0;          // Geographic location (for geo-routing)
    double longitude = 0.0;
    double speed = 0.0;             // Vehicle speed
    string contentType = "";        // Content type (safety, traffic, infotainment)
    int priority = 0;               // Priority (0=normal, 1=high, 2=safety)

    // Security
    bool mustBeVerified = false;    // Requires signature verification

    // Trust
    double producerTrust = 1.0;     // Trust in producer (-1 = unknown)
}

//
// Data Packet
// Represents content/data in NDN
//
packet DataPacket extends NdnPacket {
    packetType = NDN_DATA;

    // Data parameters
    string content;                 // Actual content/payload
    int contentLength;              // Content size in bytes
    simtime_t freshnessPeriod = 0.0; // How long data is fresh (0 = always stale)

    // MetaInfo
    int finalBlockId = -1;          // Last segment ID (for segmentation)
    string contentType = "";        // Content MIME type

    // Security
    bool isSigned = false;          // Has digital signature
    string signature = "";          // Digital signature
    string signerId = "";           // Signer identity
    simtime_t signatureTime;        // Signature timestamp

    // VNDN specific
    double producerLatitude = 0.0;  // Producer location
    double producerLongitude = 0.0;
    simtime_t dataAge;              // Age of data
    int producerSpeed = 0;          // Producer speed at creation

    // Cache control
    bool isCacheable = true;        // Can be cached
    int cacheHits = 0;              // Number of cache hits (for tracking)

    // Trust
    double trustScore = 1.0;        // Content trust score
}

//
// NACK Packet
// Negative acknowledgment in NDN
//
packet NackPacket extends InterestPacket {
    packetType = NDN_NACK;
    int reason @enum(NackReason);   // Reason for NACK
    string reasonText = "";         // Human-readable reason
}

//
// Beacon Packet (VNDN-specific)
// Periodic announcement packet for neighbor discovery
//
packet BeaconPacket extends NdnPacket {
    string vehicleId;               // Vehicle identifier
    double latitude;                // Current position
    double longitude;
    double speed;                   // Current speed
    double heading;                 // Direction (degrees)
    int neighborCount;              // Number of known neighbors

    // Capabilities
    bool isProducer = false;        // Can produce content
    string producedPrefixes[];      // Name prefixes this node produces
    int cacheSize;                  // Cache capacity

    // Trust
    double trustScore = 1.0;        // Node trust score
}

//
// Control Message (for attack coordination)
//
packet ControlMessage {
    int commandType;                // Command type
    string targetNode = "";         // Target node ID
    string attackType = "";         // Attack to execute
    double attackIntensity = 0.5;   // Attack intensity (0-1)
    simtime_t duration = 0.0;       // Attack duration
    string parameters = "";         // JSON-encoded parameters
}
