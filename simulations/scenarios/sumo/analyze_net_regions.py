#!/usr/bin/env python3
"""Analyse aljubail_saudi.net.xml and emit randomTrips weight files that put the
URBAN and HIGHWAY TRIDENT scenarios in genuinely different parts of the map.

URBAN  = central downtown box, low-speed streets (<= ~14 m/s = 50 km/h).
HIGHWAY = fast arterials / corridor (>= ~19.4 m/s = 70 km/h), map-wide.

Writes:  urban.src.xml  urban.dst.xml  highway.src.xml  highway.dst.xml
(randomTrips --weights-prefix reads <name>.src.xml / <name>.dst.xml).
"""
import os, sys
sys.path.append(os.path.join(os.environ["SUMO_HOME"], "tools"))
import sumolib  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NET = os.path.join(HERE, "aljubail_saudi.net.xml")

net = sumolib.net.readNet(NET)
xmin, ymin, xmax, ymax = net.getBoundary()
print(f"boundary: x[{xmin:.0f},{xmax:.0f}] y[{ymin:.0f},{ymax:.0f}]  "
      f"({(xmax-xmin)/1000:.1f}km x {(ymax-ymin)/1000:.1f}km)")

# Central downtown box: middle 45% of the map in each axis.
cx, cy = (xmin + xmax) / 2.0, (ymin + ymax) / 2.0
half_w = 0.225 * (xmax - xmin)
half_h = 0.225 * (ymax - ymin)
ubox = (cx - half_w, cy - half_h, cx + half_w, cy + half_h)
print(f"urban downtown box: x[{ubox[0]:.0f},{ubox[2]:.0f}] y[{ubox[1]:.0f},{ubox[3]:.0f}]")

URBAN_VMAX = 14.0     # <= 50 km/h streets
HIGHWAY_VMIN = 19.4   # >= 70 km/h arterials

urban, highway = {}, {}
speeds = []
for e in net.getEdges():
    if e.isSpecial():            # skip internal / connector edges
        continue
    if not e.allows("passenger"):
        continue
    spd = e.getSpeed()
    speeds.append(spd)
    # edge mid-point
    x, y = e.getFromNode().getCoord()
    x2, y2 = e.getToNode().getCoord()
    mx, my = (x + x2) / 2.0, (y + y2) / 2.0
    inbox = ubox[0] <= mx <= ubox[2] and ubox[1] <= my <= ubox[3]

    if spd <= URBAN_VMAX and inbox:
        # weight short central edges by length so trips meander downtown
        urban[e.getID()] = max(e.getLength(), 5.0)
    if spd >= HIGHWAY_VMIN:
        # weight fast edges by speed so long-haul flows prefer the fastest roads
        highway[e.getID()] = spd * spd

speeds.sort()
if speeds:
    q = lambda p: speeds[int(p * (len(speeds) - 1))]
    print(f"speed quartiles m/s: min={speeds[0]:.1f} q25={q(.25):.1f} "
          f"med={q(.5):.1f} q75={q(.75):.1f} max={speeds[-1]:.1f}")
print(f"urban edges: {len(urban)}   highway edges: {len(highway)}")

def write_weights(name, weights):
    for kind in ("src", "dst"):
        path = os.path.join(HERE, f"{name}.{kind}.xml")
        with open(path, "w") as f:
            f.write('<edgedata>\n  <interval begin="0" end="100000">\n')
            for eid, w in weights.items():
                f.write(f'    <edge id="{eid}" value="{w:.2f}"/>\n')
            f.write('  </interval>\n</edgedata>\n')
        print("wrote", os.path.basename(path), f"({len(weights)} edges)")

if not urban:
    print("WARNING: no urban edges matched; relax the box or speed cap")
if not highway:
    print("WARNING: no highway edges matched; relax the speed floor")
write_weights("urban", urban)
write_weights("highway", highway)
