"""
extract_network_metrics.py - network-level metrics for the manuscript, taken
straight from the OMNeT++ scalar files of the capture campaign.

These are the system-level numbers the paper quotes alongside the detection
results: Interest Satisfaction Ratio, cache hit ratio, NACK ratio, drop ratio,
per-run attack activity, and the size of the released dataset. They come from
the simulator's own counters rather than from the detection pipeline, so they
are available independently of the machine-learning evaluation.

Two caveats, both discovered by auditing the scalar files rather than assumed.

Departed vehicles do NOT undercount. Veins calls finish() on a vehicle module
immediately before deleting it, so every one of the 274 vehicles a run inserts
writes its scalars even though the mean dwell is 139 s. What does vary is
exposure, so a per-node rate must be normalized by that node's own lifetime
rather than by the run length.

Ratios here are computed over the vehicles, not the RSUs. RSUs in this build
receive no Interests and serve no Content Store lookups, so every RSU-side
ratio is undefined rather than zero.

Usage:
    python3 scripts/miids/extract_network_metrics.py
    python3 scripts/miids/extract_network_metrics.py --latex
"""

from __future__ import annotations

import argparse
import collections
import csv
import glob
import math
import os
import re
import statistics

# Scalars are keyed by (module suffix, name) where the module matters, because
# several names are written by more than one module with different meanings:
# totalInsertions exists on the CS, the PIT and the FIB, and the detection
# scalars exist on both the legacy idsModule and the MI-IDS module.
PIT_SCALARS = ("totalInsertions", "totalSatisfied", "totalExpirations",
               "totalAggregated")
CS_SCALARS = ("totalInsertions", "totalHits", "totalMisses", "finalCSSize")

SCALARS = ("interestSent", "interestReceived", "dataSent", "dataReceived",
           "cacheHit", "cacheMiss", "csHit", "csMiss", "nackSent",
           "nackReceived", "packetDropped", "csEvictionEvent",
           "csInsertionEvent", "collisions", "channelBusy",
           "contentPoisoned", "packetsJammed", "totalSybilRequests",
           "attackPacketsGenerated", "attackPacketsModified",
           "attackPacketsDropped", "producerAnswers",
           "interestsIssued", "interestsSatisfied", "interestsExpired",
           "exeSubjectsObserved", "exeEvidenceWindows",
           "exeBeaconOnlyWindows", "miidsSubjectsScored")


def read_sca(path, rsu_only=False):
    """Sum the scalars of interest over the modules of one run."""
    tot = collections.Counter()
    with open(path, errors="replace") as fh:
        for line in fh:
            if not line.startswith("scalar "):
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            module, name, value = parts[1], parts[2], parts[3].strip()
            if rsu_only and ".rsu[" not in module:
                continue
            base = name.split(":")[0]
            if base not in SCALARS:
                continue
            if ":" in name and not name.endswith((":count", ":sum")):
                continue
            try:
                tot[base] += float(value)
            except ValueError:
                pass
    return tot


def safe_ratio(num, den):
    return (num / den) if den else float("nan")


def per_run_metrics(d):
    sca = glob.glob(os.path.join(d, "*.sca"))
    if not sca:
        return None
    t = read_sca(sca[0])

    cs_lookups = t["csHit"] + t["csMiss"]
    interests = t["interestReceived"]
    m = {
        "interest_received": t["interestReceived"],
        "interest_sent": t["interestSent"],
        "data_received": t["dataReceived"],
        "data_sent": t["dataSent"],
        "cache_hit_ratio": safe_ratio(t["csHit"], cs_lookups),
        "nack_ratio": safe_ratio(t["nackSent"], interests),
        "drop_ratio": safe_ratio(t["packetDropped"],
                                 t["interestReceived"] + t["dataReceived"]),
        "eviction_per_insertion": safe_ratio(t["csEvictionEvent"],
                                             t["csInsertionEvent"]),
        "isr": safe_ratio(t["interestsSatisfied"], t["interestsIssued"]),
        "producer_answers": t["producerAnswers"],
        "attack_events": (t["attackPacketsGenerated"] + t["attackPacketsModified"]
                          + t["contentPoisoned"] + t["packetsJammed"]
                          + t["totalSybilRequests"]),
        "subjects_observed": t["exeSubjectsObserved"],
        "evidence_windows": t["exeEvidenceWindows"],
        "beacon_only_windows": t["exeBeaconOnlyWindows"],
    }
    return m


def dataset_stats(d):
    """Row and label counts from the exported feature files."""
    rows = mal = 0
    subs, obs = set(), set()
    for f in glob.glob(os.path.join(d, "plane_*.csv")):
        with open(f, newline="") as fh:
            rdr = csv.reader(fh)
            header = next(rdr, None)
            if not header:
                continue
            pos = {n: i for i, n in enumerate(header)}
            try:
                i_lab, i_sub, i_obs = pos["label"], pos["subject"], pos["observer"]
            except KeyError:
                continue
            for r in rdr:
                if len(r) <= i_lab:
                    continue
                rows += 1
                if r[i_lab] == "1":
                    mal += 1
                subs.add(r[i_sub]); obs.add(r[i_obs])
    return {"rows": rows, "malicious": mal,
            "subjects": len(subs), "observers": len(obs)}


def mean_ci(values):
    vals = [v for v in values if v == v]          # drop NaN
    if not vals:
        return float("nan"), 0.0
    if len(vals) < 2:
        return vals[0], 0.0
    return (statistics.mean(vals),
            1.96 * statistics.stdev(vals) / math.sqrt(len(vals)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/exe_capture")
    ap.add_argument("--latex", action="store_true")
    args = ap.parse_args()

    by_cfg = collections.defaultdict(list)
    ds_by_cfg = collections.defaultdict(list)
    for d in sorted(glob.glob(os.path.join(args.root, "*_seed*"))):
        cfg = os.path.basename(d).rsplit("_seed", 1)[0]
        m = per_run_metrics(d)
        if m:
            by_cfg[cfg].append(m)
        ds_by_cfg[cfg].append(dataset_stats(d))

    print(f"{'scenario':<18}{'runs':>5}{'rows':>12}{'malicious':>11}"
          f"{'subjects':>10}{'cacheHit':>10}{'ISR':>8}{'drops':>8}")
    grand_rows = grand_mal = 0
    for cfg in sorted(ds_by_cfg):
        ds = ds_by_cfg[cfg]
        rows = sum(x["rows"] for x in ds)
        mal = sum(x["malicious"] for x in ds)
        subs = max(x["subjects"] for x in ds)
        grand_rows += rows; grand_mal += mal
        ms = by_cfg.get(cfg, [])
        ch, _ = mean_ci([m["cache_hit_ratio"] for m in ms])
        isr, _ = mean_ci([m["isr"] for m in ms])
        dr, _ = mean_ci([m["drop_ratio"] for m in ms])
        print(f"{cfg:<18}{len(ds):>5}{rows:>12,}{mal:>11,}{subs:>10}"
              f"{ch:>10.3f}{isr:>8.3f}{dr:>8.3f}")
    print(f"{'TOTAL':<18}{sum(len(v) for v in ds_by_cfg.values()):>5}"
          f"{grand_rows:>12,}{grand_mal:>11,}")

    # Campaign-wide aggregates, reported with confidence intervals.
    allm = [m for ms in by_cfg.values() for m in ms]
    print("\ncampaign aggregates (mean +/- 95% CI over 50 runs)")
    for key, label in (("cache_hit_ratio", "Cache hit ratio"),
                       ("isr", "Interest Satisfaction Ratio"),
                       ("nack_ratio", "NACK ratio"),
                       ("drop_ratio", "Packet drop ratio"),
                       ("eviction_per_insertion", "CS evictions per insertion"),
                       ("subjects_observed", "Neighbors observed per monitor"),
                       ("attack_events", "Attack events per run")):
        mu, ci = mean_ci([m[key] for m in allm])
        print(f"  {label:<34} {mu:>12.4f}  +/- {ci:.4f}")

    if args.latex:
        out = ("VeReMiVNDN-Extension/Preparation_of_Papers_for_IEEE_ACCESS_"
               "extension/generated/tab_dataset_stats.tex")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        lines = [
            r"\begin{table}[t]", r"\centering",
            r"\caption{Released dataset, measured over the 50-run campaign. "
            r"Rows are labeled observation windows; a window is exported only "
            r"when the monitor received NDN traffic from the subject, so "
            r"beacon-only windows are excluded.}",
            r"\label{tab:dataset-stats}",
            r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
            r"\begin{tabular}{p{2.7cm}p{0.9cm}p{1.6cm}p{1.4cm}}", r"\hline",
            r"\textbf{Scenario} & \textbf{Runs} & \textbf{Windows} & "
            r"\textbf{Attacker} \\ \hline",
        ]
        pretty = {"CAP_Baseline": "Baseline", "CAP_A1": "Content Poisoning",
                  "CAP_A2": "Cache Pollution", "CAP_A3": "Cache Privacy Leakage",
                  "CAP_A4": "Sybil Amplification", "CAP_A5": "Selective Forwarding",
                  "CAP_A6": "Radio Jamming", "CAP_A7": "Replay Attack",
                  "CAP_A8": "ML Evasion", "CAP_MultiAttack": "MultiAttack"}
        for cfg in sorted(ds_by_cfg):
            ds = ds_by_cfg[cfg]
            lines.append(f"{pretty.get(cfg, cfg)} & {len(ds)} & "
                         f"{sum(x['rows'] for x in ds):,} & "
                         f"{sum(x['malicious'] for x in ds):,} " + r"\\ \hline")
        lines += [r"\textbf{Total} & \textbf{" + str(sum(len(v) for v in ds_by_cfg.values()))
                  + r"} & \textbf{" + f"{grand_rows:,}" + r"} & \textbf{"
                  + f"{grand_mal:,}" + r"} \\ \hline",
                  r"\end{tabular}", r"\end{table}", ""]
        open(out, "w").write("\n".join(lines))
        print(f"\nwrote {out}")

        # ---- network-level metrics table --------------------------------
        out2 = out.replace("tab_dataset_stats", "tab_network_metrics")
        rows_spec = [
            ("cache_hit_ratio", "Content Store hit ratio", 3),
            ("nack_ratio", "NACK ratio (NACKs per Interest)", 3),
            ("drop_ratio", "Packet drop ratio", 3),
            ("interest_received", "Interests processed per run", 0),
            ("data_received", "Data packets processed per run", 0),
            ("producer_answers", "Producer replies per run", 0),
            ("attack_events", "Attack events per run", 0),
        ]
        L = [
            r"\begin{table}[t]", r"\centering",
            r"\caption{Network-level behavior of the campaign, measured from the "
            r"simulator counters over all 50 runs and reported as mean with a "
            r"95\% confidence interval. Counters are summed over the modules "
            r"that report them. Values are vehicle-side: RSUs in this build "
            r"receive no Interests, so RSU-side ratios are undefined rather than "
            r"zero. Every vehicle writes its scalars, including those TraCI "
            r"removes mid-run, so these are totals rather than lower bounds.}",
            r"\label{tab:network-metrics}",
            r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
            r"\begin{tabular}{p{4.6cm}p{2.6cm}}", r"\hline",
            r"\textbf{Quantity} & \textbf{Value} \\ \hline",
        ]
        for key, label, dg in rows_spec:
            mu, ci = mean_ci([m[key] for m in allm])
            if dg == 0:
                L.append(f"{label} & {mu:,.0f} $\\pm$ {ci:,.0f} " + r"\\ \hline")
            else:
                L.append(f"{label} & {mu:.{dg}f} $\\pm$ {ci:.{dg}f} " + r"\\ \hline")
        L += [r"\end{tabular}", r"\end{table}", ""]
        open(out2, "w").write("\n".join(L))
        print(f"wrote {out2}")


if __name__ == "__main__":
    main()
