#!/usr/bin/env python3
"""Consolidate the paper-1 campaign into one file per run.

The campaign writes one CSV per monitoring node, which for 225 runs is tens of
thousands of small files and loses track of which run a row came from. This
rewrites them as one gzipped CSV per run, prepending the columns that identify
the run so the density, attacker-ratio and seed axes can be recovered from the
released files alone.

Two products come out of each run directory:

  ml/      the 69-feature records with the attack label, which is the dataset
           the paper describes and the one most users want
  plane/   the 23-feature per-neighbor records used by the extension work,
           kept because they are already produced and cost little

Usage: scripts/consolidate_paper1.py --root datasets/paper1_veremivndn --out release/data
"""
import argparse
import csv
import gzip
import os
import re
import sys

RUN_RE = re.compile(r"^(?P<cfg>.+?)_(?P<density>low|med|high)_(?P<ratio>r\d+)_seed(?P<seed>\d+)$")

# The configuration names carry the attack identity; map them to the names the
# paper uses so a reader does not have to consult the ini file.
ATTACK = {
    "BenignTraffic": "None",
    "Attack01_InterestFlooding": "InterestFlooding",
    "Attack05_NamePrefixHijacking": "NamePrefixHijacking",
    "Attack12_InterestAggregation": "InterestAggregation",
    "Attack18_RoutingInfoFlood": "RoutingInfoFlood",
}
VEHICLES = {"low": 77, "med": 151, "high": 356}


def consolidate(run_dir, files, out_path, meta):
    """Write one gzipped CSV, prefixing every row with the run's identity."""
    header = None
    rows = 0
    with gzip.open(out_path, "wt", newline="") as fh:
        w = csv.writer(fh)
        for f in sorted(files):
            try:
                with open(f, newline="") as src:
                    r = csv.reader(src)
                    try:
                        h = next(r)
                    except StopIteration:
                        continue
                    if header is None:
                        header = h
                        w.writerow(list(meta.keys()) + header)
                    elif h != header:
                        # A node writing a different schema would silently
                        # misalign every column, so skip it loudly instead.
                        print(f"  !! schema mismatch, skipping {f}", file=sys.stderr)
                        continue
                    mv = list(meta.values())
                    for row in r:
                        if not row or len(row) != len(header):
                            continue
                        w.writerow(mv + row)
                        rows += 1
            except OSError as e:
                print(f"  !! {f}: {e}", file=sys.stderr)
    if rows == 0:
        os.unlink(out_path)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ml_dir = os.path.join(args.out, "ml")
    pl_dir = os.path.join(args.out, "plane")
    os.makedirs(ml_dir, exist_ok=True)
    os.makedirs(pl_dir, exist_ok=True)

    total_ml = total_pl = done = skipped = 0
    for run in sorted(os.listdir(args.root)):
        d = os.path.join(args.root, run)
        if not os.path.isdir(d):
            continue
        if not os.path.exists(os.path.join(d, ".done")):
            skipped += 1
            continue
        m = RUN_RE.match(run)
        if not m:
            print(f"  !! unparseable run name: {run}", file=sys.stderr)
            skipped += 1
            continue
        g = m.groupdict()
        meta = {
            "run": run,
            "config": g["cfg"],
            "attack": ATTACK.get(g["cfg"], "Unknown"),
            "density": g["density"],
            "vehicles": VEHICLES.get(g["density"], ""),
            "attacker_ratio_pct": g["ratio"].lstrip("r").lstrip("0") or "0",
            "seed": g["seed"],
        }
        # BenignTraffic has no attackers, so its ratio label is a replicate
        # index rather than a distinct condition. Say so in the data.
        if g["cfg"] == "BenignTraffic":
            meta["attacker_ratio_pct"] = "0"

        ml = [os.path.join(d, "ml", f) for f in os.listdir(os.path.join(d, "ml"))
              if f.endswith(".csv")] if os.path.isdir(os.path.join(d, "ml")) else []
        pl = [os.path.join(d, f) for f in os.listdir(d) if f.startswith("plane_")
              and f.endswith(".csv")]

        if ml:
            total_ml += consolidate(d, ml, os.path.join(ml_dir, run + ".csv.gz"), meta)
        if pl:
            total_pl += consolidate(d, pl, os.path.join(pl_dir, run + ".csv.gz"), meta)
        done += 1

    print(f"consolidated {done} runs ({skipped} skipped as incomplete)")
    print(f"  ml rows    : {total_ml:,}")
    print(f"  plane rows : {total_pl:,}")


if __name__ == "__main__":
    main()
