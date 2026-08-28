//
// JammingMedium.h - shared jamming state for VeReMiVNDN-EXE
//
// The vehicular medium in this model is abstracted at the frame-delivery level:
// VehicleController/RSUController hand each outgoing NDN frame to the peers in
// communication range rather than pushing it through the 802.11p PHY. The
// original RadioJamming module only emitted statistics signals ("in a real
// implementation this would interface with the PHY layer"), so a jammer had no
// effect whatsoever on any other node and the physical plane carried no signal
// that any detector could have used.
//
// This registry closes that gap at the same level of abstraction as the rest of
// the medium: active jammers publish their position, transmit power and radius,
// and frame delivery consults the registry to decide whether a given receiver
// is knocked out. The loss probability grows with received jamming power and is
// gated by the jammer's duty cycle, which reproduces the observable consequence
// of jamming (a reception deficit and a busy channel at victims near the
// jammer) without claiming a PHY-accurate interference computation.
//

#ifndef __VEREMIVNDN_JAMMINGMEDIUM_H
#define __VEREMIVNDN_JAMMINGMEDIUM_H

#include <omnetpp.h>
#include "veins/base/modules/BaseMobility.h"
#include <cmath>
#include <map>
#include <string>

using namespace omnetpp;

namespace veremivndn {

// Resolve a node's current position from its mobility module. Display-string
// coordinates only exist when a GUI canvas is running, so a Cmdenv batch run
// must read the mobility model directly.
inline bool jammingNodePosition(omnetpp::cModule *host, double &x, double &y) {
    if (!host) return false;
    omnetpp::cModule *mob = host->getSubmodule("mobility");
    if (!mob) return false;
    if (auto *bm = dynamic_cast<veins::BaseMobility *>(mob)) {
        veins::Coord c = bm->getPositionAt(omnetpp::simTime());
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

struct JammerState {
    double x = 0.0;
    double y = 0.0;
    double range = 250.0;      // metres
    double powerDbm = 28.0;
    bool   active = false;
};

class JammingMedium {
  public:
    static JammingMedium &instance() {
        static JammingMedium inst;
        return inst;
    }

    void update(const std::string &jammer, const JammerState &st) {
        jammers[jammer] = st;
    }

    void clear(const std::string &jammer) {
        jammers.erase(jammer);
    }

    bool anyActive() const {
        for (const auto &kv : jammers) if (kv.second.active) return true;
        return false;
    }

    // Probability that a frame arriving at (rx, ry) is destroyed by jamming.
    // Zero outside every active jammer's radius; inside, it rises with the
    // inverse-square attenuated jamming power, saturating at maxLoss.
    double lossProbabilityAt(double rx, double ry) const {
        double keep = 1.0;
        for (const auto &kv : jammers) {
            const JammerState &j = kv.second;
            if (!j.active) continue;
            double dx = rx - j.x, dy = ry - j.y;
            double d = std::sqrt(dx * dx + dy * dy);
            if (d > j.range) continue;
            // Normalised proximity, 1 at the jammer and 0 at the edge.
            double prox = 1.0 - (d / std::max(1.0, j.range));
            double gain = std::min(1.0, std::max(0.0, (j.powerDbm - 10.0) / 25.0));
            double p = maxLoss * gain * prox * prox;
            keep *= (1.0 - std::min(1.0, std::max(0.0, p)));
        }
        return 1.0 - keep;
    }

    // Fraction of the local neighbourhood currently covered by an active
    // jammer, used as the measured channel-busy proxy at a receiver.
    double occupancyAt(double rx, double ry) const {
        double best = 0.0;
        for (const auto &kv : jammers) {
            const JammerState &j = kv.second;
            if (!j.active) continue;
            double dx = rx - j.x, dy = ry - j.y;
            double d = std::sqrt(dx * dx + dy * dy);
            if (d > j.range) continue;
            best = std::max(best, 1.0 - (d / std::max(1.0, j.range)));
        }
        return best;
    }

  private:
    JammingMedium() = default;
    std::map<std::string, JammerState> jammers;
    static constexpr double maxLoss = 0.85;
};

} // namespace veremivndn

#endif // __VEREMIVNDN_JAMMINGMEDIUM_H
