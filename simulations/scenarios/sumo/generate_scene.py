#!/usr/bin/env python3
"""Generate the realistic scene props for the two purpose-built TRIDENT maps:
building-block polygons, RSU antenna POIs, and traffic-sign / speed-limit POIs.

Outputs (one additional-file per scenario, holding polys + POIs):
    urban_grid.poly.xml
    highway_corridor.poly.xml
and the RSU SUMO coordinates (consumed later to set the OMNeT++ rsu positions):
    rsu_coords_urban.txt
    rsu_coords_highway.txt
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# deterministic per-index building tints (sandy / concrete city palette)
BLDG_COLORS = ["198,180,150", "180,168,150", "205,195,178", "170,160,148",
               "190,176,156", "210,200,185", "165,155,140", "200,188,165"]


def poly(fid, ftype, color, shape, fill=1, layer=-2.0, lineWidth=None):
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in shape)
    lw = f' lineWidth="{lineWidth}"' if lineWidth is not None else ""
    return (f'    <poly id="{fid}" type="{ftype}" color="{color}" '
            f'fill="{fill}" layer="{layer}"{lw} shape="{pts}"/>')


def rect(x0, y0, x1, y1):
    return [(x0, y0), (x1, y0), (x1, y1), (x0, y1), (x0, y0)]


def poi(pid, x, y, color, ptype, width=8.0, height=8.0, layer=10.0, img=""):
    extra = f' imgFile="{img}"' if img else ""
    return (f'    <poi id="{pid}" type="{ptype}" color="{color}" '
            f'x="{x:.1f}" y="{y:.1f}" width="{width}" height="{height}" '
            f'layer="{layer}"{extra}/>')


def circle(cid, cx, cy, r, color, ftype="rsu_range", layer=8.0, n=48, lw=4.0):
    import math
    pts = [(cx + r * math.cos(2 * math.pi * k / n),
            cy + r * math.sin(2 * math.pi * k / n)) for k in range(n + 1)]
    # fill=0 -> coverage shown as a clean outline ring (no overlapping discs)
    return poly(cid, ftype, color, pts, fill=0, layer=layer, lineWidth=lw)


def rsu_markers(rsu_xy, radius, ring_rgb, marker, msize, lw=4.0, prefix="RSU"):
    """Outlined coverage ring + bold marker (clean, non-overlapping VNDN look)."""
    out = []
    for i, (x, y) in enumerate(rsu_xy):
        out.append(circle(f"{prefix}_range_{i}", x, y, radius, ring_rgb, lw=lw))
    for i, (x, y) in enumerate(rsu_xy):
        out.append(poi(f"{prefix}_{i}", x, y, marker, "rsu",
                       width=msize, height=msize))
    return out


# ----------------------------------------------------------------------------
# URBAN GRID: 9x9 lattice at 130 m (0..1040). Buildings = 2x2 sub-blocks/cell.
# ----------------------------------------------------------------------------
def urban():
    L, N, INSET, ALLEY = 130.0, 9, 26.0, 8.0
    items = []
    bi = 0
    for ci in range(N - 1):
        for cj in range(N - 1):
            x0, y0 = ci * L + INSET, cj * L + INSET
            x1, y1 = (ci + 1) * L - INSET, (cj + 1) * L - INSET
            mx, my = (x0 + x1) / 2, (y0 + y1) / 2
            # 2x2 sub-buildings with an interior alley
            for (ax0, ay0, ax1, ay1) in [
                (x0, y0, mx - ALLEY / 2, my - ALLEY / 2),
                (mx + ALLEY / 2, y0, x1, my - ALLEY / 2),
                (x0, my + ALLEY / 2, mx - ALLEY / 2, y1),
                (mx + ALLEY / 2, my + ALLEY / 2, x1, y1)]:
                col = BLDG_COLORS[bi % len(BLDG_COLORS)]
                items.append(poly(f"bldg_u{bi}", "building", col,
                                  rect(ax0, ay0, ax1, ay1)))
                bi += 1
    # RSUs: 10 roadside units spread over intersections (slightly off-centre).
    # Coverage drawn as a clean 150 m outline ring; bold red square marker.
    rsu_xy = [(260, 270), (780, 270), (520, 520), (270, 780), (780, 780),
              (140, 520), (910, 520), (520, 140), (520, 910), (910, 910)]
    rsu_lines = rsu_markers(rsu_xy, 120, "30,90,220", "220,20,20", msize=26, lw=3.0)

    # traffic-sign POIs (speed limit 50 + a few stop signs at the fringe)
    signs = []
    sx = [(70, 130, "SL50", "255,80,80"), (970, 910, "SL50", "255,80,80"),
          (130, 650, "STOP", "220,30,30"), (650, 130, "STOP", "220,30,30"),
          (910, 390, "SL50", "255,80,80")]
    for k, (x, y, lbl, c) in enumerate(sx):
        signs.append(poi(f"sign_u{k}_{lbl}", x, y, c, "trafficSign", 6, 6))

    with open(os.path.join(HERE, "rsu_coords_urban.txt"), "w") as f:
        for x, y in rsu_xy:
            f.write(f"{x} {y}\n")
    return items + rsu_lines + signs, len(rsu_xy), bi


# ----------------------------------------------------------------------------
# HIGHWAY CORRIDOR: 4500 x 800, highway band at y=400. Industrial blocks
# above (y 560..800) and below (y 0..240) the carriageway.
# ----------------------------------------------------------------------------
def highway():
    items = []
    bi = 0
    # cross-road x positions to leave clear: 1100, 2250, 3400 (+/- 90 m)
    clear = [(1010, 1190), (2160, 2340), (3310, 3490)]

    def blocked(x0, x1):
        return any(not (x1 < c0 or x0 > c1) for c0, c1 in clear)

    bw, gap = 150.0, 30.0   # building width + gap
    for band_y0, band_y1 in [(20, 230), (570, 780)]:
        x = 60.0
        while x + bw < 4480:
            if not blocked(x, x + bw):
                col = BLDG_COLORS[bi % len(BLDG_COLORS)]
                # vary depth a little for an industrial-park look
                depth = (band_y1 - band_y0) * (0.7 if bi % 3 else 1.0)
                yy0 = band_y0
                items.append(poly(f"bldg_h{bi}", "industrial", col,
                                  rect(x, yy0, x + bw, yy0 + depth)))
                bi += 1
            x += bw + gap

    # 8 RSUs in a linear chain just north of the highway; 300 m outline rings.
    rsu_x = [300, 860, 1400, 1950, 2550, 3100, 3700, 4250]
    rsu_xy = [(x, 480) for x in rsu_x]
    rsu_lines = rsu_markers(rsu_xy, 255, "30,90,220", "220,20,20", msize=55, lw=6.0)

    # highway speed-limit signs (120) + interchange signs
    signs = []
    for k, x in enumerate([500, 1600, 2900, 4100]):
        signs.append(poi(f"sign_h{k}_SL120", x, 320, "255,80,80",
                         "trafficSign", 10, 10))

    with open(os.path.join(HERE, "rsu_coords_highway.txt"), "w") as f:
        for x, y in rsu_xy:
            f.write(f"{x} {y}\n")
    return items + rsu_lines + signs, len(rsu_xy), bi


def write(name, items):
    path = os.path.join(HERE, f"{name}.poly.xml")
    with open(path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<!-- TRIDENT scene props: buildings, RSU POIs, traffic signs. '
                'Auto-generated by generate_scene.py. -->\n')
        f.write('<additional>\n')
        f.write("\n".join(items) + "\n")
        f.write('</additional>\n')
    print(f"wrote {os.path.basename(path)} ({len(items)} props)")


u_items, u_rsu, u_b = urban()
h_items, h_rsu, h_b = highway()
write("urban_grid", u_items)
write("highway_corridor", h_items)
print(f"urban:   {u_b} buildings, {u_rsu} RSUs")
print(f"highway: {h_b} buildings, {h_rsu} RSUs")
