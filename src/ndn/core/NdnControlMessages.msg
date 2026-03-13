//
// VeReMiVNDN - NDN Control Messages for Module Communication
// Messages for NDNProcessor <-> PIT/FIB/CS communication
//

cplusplus {{
#include "../packets/NdnPackets_m.h"
}}

namespace veremivndn;

//
// Message types for module communication
//
enum NDNControlMessageType {
    // PIT operations
    PIT_INSERT_REQUEST = 1;
    PIT_INSERT_RESPONSE = 2;
    PIT_LOOKUP_REQUEST = 3;
    PIT_LOOKUP_RESPONSE = 4;
    PIT_SATISFY_REQUEST = 5;
    PIT_SATISFY_RESPONSE = 6;

    // FIB operations
    FIB_LOOKUP_REQUEST = 10;
    FIB_LOOKUP_RESPONSE = 11;
    FIB_ADD_ROUTE_REQUEST = 12;
    FIB_ADD_ROUTE_RESPONSE = 13;

    // CS operations
    CS_LOOKUP_REQUEST = 20;
    CS_LOOKUP_RESPONSE = 21;
    CS_INSERT_REQUEST = 22;
    CS_INSERT_RESPONSE = 23;
}

//
// Base control message
//
packet NDNControlMessage {
    int messageType @enum(NDNControlMessageType);
    string name;  // Content name
    int transactionId = 0;  // For matching requests/responses
}

//
// PIT Control Messages
//
packet PITInsertRequest extends NDNControlMessage {
    messageType = PIT_INSERT_REQUEST;
    int inFace;
    int nonce;
    double interestLifetime;
}

packet PITInsertResponse extends NDNControlMessage {
    messageType = PIT_INSERT_RESPONSE;
    bool success;
    bool aggregated;  // True if interest was aggregated with existing entry
    int outFaces[];   // Faces to forward to (from FIB)
}

packet PITLookupRequest extends NDNControlMessage {
    messageType = PIT_LOOKUP_REQUEST;
}

packet PITLookupResponse extends NDNControlMessage {
    messageType = PIT_LOOKUP_RESPONSE;
    bool found;
    int inFaces[];    // Requesting faces
    int outFaces[];   // Forwarding faces
}

packet PITSatisfyRequest extends NDNControlMessage {
    messageType = PIT_SATISFY_REQUEST;
    int inFace;  // Face where data arrived
}

packet PITSatisfyResponse extends NDNControlMessage {
    messageType = PIT_SATISFY_RESPONSE;
    bool found;
    int outFaces[];  // Faces to send data to
}

//
// FIB Control Messages
//
packet FIBLookupRequest extends NDNControlMessage {
    messageType = FIB_LOOKUP_REQUEST;
    int inFace;  // Exclude this face from results
}

packet FIBLookupResponse extends NDNControlMessage {
    messageType = FIB_LOOKUP_RESPONSE;
    bool found;
    int nextHops[];   // Next hop faces
    int costs[];      // Costs for each next hop
    double trustScore = 1.0;
}

packet FIBAddRouteRequest extends NDNControlMessage {
    messageType = FIB_ADD_ROUTE_REQUEST;
    string prefix;
    int nextHop;
    int cost = 1;
    double trustScore = 1.0;
}

packet FIBAddRouteResponse extends NDNControlMessage {
    messageType = FIB_ADD_ROUTE_RESPONSE;
    bool success;
}

//
// CS Control Messages
//
packet CSLookupRequest extends NDNControlMessage {
    messageType = CS_LOOKUP_REQUEST;
}

packet CSLookupResponse extends NDNControlMessage {
    messageType = CS_LOOKUP_RESPONSE;
    bool found;
    cMessage *data = nullptr;  // The cached data packet (if found) - cast to DataPacket* in C++
}

packet CSInsertRequest extends NDNControlMessage {
    messageType = CS_INSERT_REQUEST;
    cMessage *data = nullptr;  // Data to cache - cast to DataPacket* in C++
}

packet CSInsertResponse extends NDNControlMessage {
    messageType = CS_INSERT_RESPONSE;
    bool success;
}
