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
    # Per-attack running sums, so observability can be measured rather than
    # assumed. An attack that executes in the simulator but leaves no trace in
    # the feature set is still labeled in the data, and a user who does not
    # know that will read chance performance as a modelling failure.
    sep = {}

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

        if "attack" in df and "isAttack" in df and len(df):
            atk = str(df.attack.iloc[0])
            if atk != "None":
                feats = df.select_dtypes("number").drop(
                    columns=[c for c in ("isAttack", "attackIntensity", "severity",
                                         "nodeId", "timestamp", "seed", "vehicles",
                                         "attacker_ratio_pct") if c in df],
                    errors="ignore")
                m = df.isAttack.astype(float) > 0
                if m.any() and (~m).any():
                    # Accumulate count, sum and sum of squares per group so the
                    # effect size is computed once over the pooled rows for the
                    # attack. Taking the largest per-run value instead would let
                    # a single favourable run stand in for all forty-five, which
                    # reports an attack as separable when it is not.
                    d = sep.setdefault(atk, {})
                    for grp, mask in (("a", m), ("b", ~m)):
                        sub = feats[mask]
                        g = d.setdefault(grp, {"n": 0, "s": None, "q": None})
                        g["n"] += len(sub)
                        ssum, sq = sub.sum(), (sub ** 2).sum()
                        g["s"] = ssum if g["s"] is None else g["s"].add(ssum, fill_value=0)
                        g["q"] = sq if g["q"] is None else g["q"].add(sq, fill_value=0)

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

    # Render the observability table. Cohen's d is the standardized mean
    # difference between attacker and benign rows for the single most separating
    # feature; below about 0.2 the two populations are effectively identical.
    rows = []
    sep_out = {}
    for atk in sorted(sep):
        d = sep[atk]
        if "a" not in d or "b" not in d or d["a"]["n"] == 0 or d["b"]["n"] == 0:
            continue
        A, B = d["a"], d["b"]
        ma, mb = A["s"] / A["n"], B["s"] / B["n"]
        va = (A["q"] / A["n"] - ma ** 2).clip(lower=0)
        vb = (B["q"] / B["n"] - mb ** 2).clip(lower=0)
        sd = ((va + vb) / 2.0) ** 0.5
        eff = ((ma - mb).abs() / sd.replace(0, float("nan"))).dropna()
        if not len(eff):
            continue
        best, col = float(eff.max()), str(eff.idxmax())
        verdict = ("clearly separable" if best >= 0.8 else
                   "weakly separable" if best >= 0.2 else
                   "not separable in this feature set")
        sep_out[atk] = {"attacker_rows": A["n"], "cohens_d": round(best, 3),
                        "feature": col, "verdict": verdict}
        rows.append(f"| `{atk}` | {A['n']:,} | {best:.2f} | `{col}` | {verdict} |")
    sep_md = ("| Attack | Attacker rows | Best Cohen's d | Feature | Verdict |\n"
              "|---|---|---|---|---|\n" + "\n".join(rows) + "\n") if rows else ""

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
        "separability": sep_out,
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
            "ATTACK_SEPARABILITY": sep_md,
        },
    }
    json.dump(out, sys.stdout, indent=2)
    print(file=sys.stderr)
    print(f"runs={n_runs} ml_rows={ml_rows:,} attack_rows={attack_rows:,} "
          f"({pct:.1f}%) plane_rows={pl_rows:,} constant={len(constant)}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
