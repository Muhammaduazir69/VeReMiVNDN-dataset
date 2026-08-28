"""
consolidate_features.py - one gzipped CSV per run, for release.

The campaign writes one CSV per monitoring node, which comes to 4,250 small
files across the 50 capture runs. That layout is awkward to consume and, worse,
loses the run identity once the files are separated from their directories. The
run-disjoint and attacker-disjoint protocols both partition by run, so a
released file that cannot say which run a row came from cannot reproduce them.

This writes one file per run with two columns prepended, `scenario` and `seed`,
so every row carries its own provenance. Rows are emitted in the order the
monitors wrote them; no filtering, deduplication or rounding is applied, and the
row count is asserted against the inputs.

Usage:
    python3 scripts/miids/consolidate_features.py \\
        --root datasets/exe_capture --out OUTDIR --tag capture
"""

from __future__ import annotations

import argparse
import glob
import gzip
import os


def consolidate(run_dir, out_path, scenario, seed):
    """Merge one run's per-monitor CSVs. Returns (rows written, header)."""
    files = sorted(glob.glob(os.path.join(run_dir, "plane_*.csv")))
    header, rows = None, 0
    with gzip.open(out_path, "wt", newline="", compresslevel=6) as out:
        for f in files:
            with open(f, newline="") as fh:
                head = fh.readline().rstrip("\n")
                if not head:
                    continue                      # monitor exported nothing
                if header is None:
                    header = head
                    out.write("scenario,seed," + header + "\n")
                elif head != header:
                    raise SystemExit(f"header mismatch in {f}")
                for line in fh:
                    line = line.rstrip("\n")
                    if line:
                        out.write(f"{scenario},{seed},{line}\n")
                        rows += 1
    return rows, header


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", default="capture")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    total, n_runs, hdr = 0, 0, None
    for d in sorted(glob.glob(os.path.join(args.root, "*_seed*"))):
        if not os.path.isdir(d):
            continue
        base = os.path.basename(d)
        scenario, seed = base.rsplit("_seed", 1)
        out_path = os.path.join(args.out, f"{base}.csv.gz")
        rows, header = consolidate(d, out_path, scenario, seed)
        if header is None:
            os.remove(out_path)
            print(f"  {base}: no feature rows, skipped")
            continue
        hdr = hdr or header
        total += rows
        n_runs += 1
        print(f"  {base}: {rows:,} rows")

    # The released row count must match what the campaign actually produced.
    src = 0
    for f in glob.glob(os.path.join(args.root, "*_seed*", "plane_*.csv")):
        with open(f) as fh:
            src += max(0, sum(1 for _ in fh) - 1)
    status = "OK" if src == total else "MISMATCH"
    print(f"[{args.tag}] {n_runs} runs, {total:,} rows "
          f"(source {src:,}) {status}")
    if status == "MISMATCH":
        raise SystemExit("row count does not match the source files")


if __name__ == "__main__":
    main()
