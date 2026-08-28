#!/usr/bin/env python3
"""Compute the figures quoted in the VeReMiVNDN documentation.

Every number in the README, the project page and the data dictionary comes from
here rather than from a hand count, so the documentation cannot drift from the
release. Emits JSON on stdout.

Constant columns are detected by streaming min and max per column across the
whole release, so the claim that a column never varies is measured rather than
assumed from reading the source.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

import pandas as pd


def human(n):
    return f"{n:,}"


def short(n):
    for lim, suf in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if n >= lim:
            v = n / lim
            return f"{v:.1f}{suf}".replace(".0", "")
    return str(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True)
    ap.add_argument("--campaign", required=True)
    args = ap.parse_args()

    ml_files = sorted(glob.glob(os.path.join(args.release, "data/ml/*.csv.gz")))
    pl_files = sorted(glob.glob(os.path.join(args.release, "data/plane/*.csv.gz")))

    ml_rows = attack_rows = 0
    lo, hi = {}, {}
    attack_counts, density_counts = {}, {}

    for f in ml_files:
        df = pd.read_csv(f, low_memory=False)
        ml_rows += len(df)
        if "isAttack" in df:
            attack_rows += int(pd.to_numeric(df.isAttack, errors="coerce")
                               .fillna(0).astype(int).sum())
        if "attackType" in df:
            for k, v in df.attackType.value_counts().items():
                attack_counts[k] = attack_counts.get(k, 0) + int(v)
        if "density" in df and len(df):
            d = df.density.iloc[0]
            density_counts[d] = density_counts.get(d, 0) + 1

        num = df.select_dtypes("number")
        mn, mx = num.min(), num.max()
        for c in num.columns:
            lo[c] = mn[c] if c not in lo else min(lo[c], mn[c])
            hi[c] = mx[c] if c not in hi else max(hi[c], mx[c])

    pl_rows = 0
    for f in pl_files:
        # Counting lines is enough here and avoids parsing the whole frame.
        with pd.read_csv(f, chunksize=200_000) as it:
            for ch in it:
                pl_rows += len(ch)

    ignore = {"seed", "vehicles", "attacker_ratio_pct", "nodeId", "timestamp"}
    constant = sorted(c for c in lo
                      if c not in ignore and pd.notna(lo[c]) and lo[c] == hi[c])

    n_runs = len(ml_files)
    sim_seconds = n_runs * 300
    size = subprocess.run(["du", "-sh", os.path.join(args.release, "data")],
                          capture_output=True, text=True).stdout.split()
    rel_size = size[0] if size else "unknown"

    pct = (100.0 * attack_rows / ml_rows) if ml_rows else 0.0

    if constant:
        const_md = ("In this release the following columns are constant:\n\n"
                    + "\n".join(f"- `{c}`" for c in constant) + "\n")
    else:
        const_md = "In this release no feature column is constant.\n"

    out = {
        "runs": n_runs,
        "ml_rows": ml_rows,
        "plane_rows": pl_rows,
        "attack_rows": attack_rows,
        "attack_pct": round(pct, 2),
        "attack_type_counts": attack_counts,
        "runs_per_density": density_counts,
        "constant_columns": constant,
        "subs": {
            "N_RUNS": human(n_runs),
            "ML_ROWS": human(ml_rows),
            "ML_ROWS_SHORT": short(ml_rows),
            "PLANE_ROWS": human(pl_rows),
            "ATTACK_ROWS": human(attack_rows),
            "ATTACK_PCT": f"{pct:.1f} %",
            "SIM_SECONDS": f"{human(sim_seconds)} s",
            "REL_SIZE": rel_size,
            "CONSTANT_COLUMNS": const_md,
        },
    }
    json.dump(out, sys.stdout, indent=2)
    print(file=sys.stderr)
    print(f"runs={n_runs} ml_rows={ml_rows:,} attack_rows={attack_rows:,} "
          f"({pct:.1f}%) plane_rows={pl_rows:,} constant={len(constant)}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
