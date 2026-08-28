//
// NeighborIndex.h - uniform-grid spatial index over VNDN nodes
//
// Frame delivery previously walked every submodule of the network for every
// transmission. With a few hundred vehicles each beaconing at 10 Hz that is
// several hundred thousand module comparisons per simulated second, and it
// dominates run time long before the protocol logic does.
//
// This index keeps every node's last known position in a uniform grid whose
// cell size is the communication range, so a delivery only has to examine the
// nine cells around the transmitter. Positions are refreshed from the mobility
// update each node already performs, so the index adds no new timers.
//

#ifndef __VEREMIVNDN_NEIGHBORINDEX_H
#define __VEREMIVNDN_NEIGHBORINDEX_H

#include <omnetpp.h>
#include <cmath>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace omnetpp;

namespace veremivndn {

class NeighborIndex {
  public:
    struct Entry {
        cModule *host = nullptr;
        double x = 0.0, y = 0.0;
        bool isRsu = false;
        bool isProducer = false;
        bool isForwarder = false;
        long cell = -1;
    };

    static NeighborIndex &instance() {
        static NeighborIndex inst;
        return inst;
    }

    void setCellSize(double m) {
        if (m > 1.0 && std::fabs(m - cellSize) > 1.0) {
            cellSize = m;
            rebuild();
        }
    }

    void upsert(cModule *host, double x, double y, bool isRsu,
                bool isProducer, bool isForwarder) {
        if (!host) return;
        Entry &e = entries[host->getId()];
        if (e.host && e.cell >= 0) cells[e.cell].erase(host->getId());
        e.host = host; e.x = x; e.y = y;
        e.isRsu = isRsu; e.isProducer = isProducer; e.isForwarder = isForwarder;
        e.cell = cellOf(x, y);
        cells[e.cell].insert(host->getId());
    }

    void remove(cModule *host) {
        if (!host) return;
        auto it = entries.find(host->getId());
        if (it == entries.end()) return;
        if (it->second.cell >= 0) cells[it->second.cell].erase(host->getId());
        entries.erase(it);
    }

    // Append every indexed node within `range` metres of (x, y), excluding
    // `self`. Returns the number appended.
    int query(double x, double y, double range, cModule *self,
              std::vector<const Entry *> &out) const {
        const double r2 = range * range;
        const int cx = (int)std::floor(x / cellSize);
        const int cy = (int)std::floor(y / cellSize);
        int n = 0;
        for (int dx = -1; dx <= 1; ++dx) {
            for (int dy = -1; dy <= 1; ++dy) {
                auto cit = cells.find(key(cx + dx, cy + dy));
                if (cit == cells.end()) continue;
                for (int id : cit->second) {
                    auto eit = entries.find(id);
                    if (eit == entries.end()) continue;
                    const Entry &e = eit->second;
                    if (e.host == self) continue;
                    const double ddx = e.x - x, ddy = e.y - y;
                    if (ddx * ddx + ddy * ddy > r2) continue;
                    out.push_back(&e);
                    ++n;
                }
            }
        }
        return n;
    }

    size_t size() const { return entries.size(); }

  private:
    NeighborIndex() = default;

    static long key(int cx, int cy) {
        // Pack two 32-bit cell coordinates into one 64-bit key.
        return ((long)(cx + (1 << 20)) << 24) ^ (long)(cy + (1 << 20));
    }
    long cellOf(double x, double y) const {
        return key((int)std::floor(x / cellSize), (int)std::floor(y / cellSize));
    }
    void rebuild() {
        cells.clear();
        for (auto &kv : entries) {
            kv.second.cell = cellOf(kv.second.x, kv.second.y);
            cells[kv.second.cell].insert(kv.first);
        }
    }

    double cellSize = 500.0;
    std::unordered_map<int, Entry> entries;              // module id -> entry
    std::unordered_map<long, std::unordered_set<int>> cells;
};

} // namespace veremivndn

#endif // __VEREMIVNDN_NEIGHBORINDEX_H
