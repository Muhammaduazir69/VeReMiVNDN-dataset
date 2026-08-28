"""
extract_online_results.py - closed-loop MI-IDS behavior from the online campaign.

The offline evaluation in train_eval_miids.py measures the detectors on exported
feature windows. This script measures the other half of the system: what MI-IDS
did while the simulation was running, with the trained TorchScript detectors
loaded, on runs generated from seeds that were held out of training.

Everything here comes from the OMNeT++ scalar files, so it reflects the decisions
the deployed module actually made rather than a re-scoring of the trace:

  * confusion matrix accumulated over every committed verdict,
  * reject-option rate, split into evidence-gate skips and fusion abstentions,
  * quarantine outcomes, separated into benign and malicious subjects,
  * detection delay between a subject's first attacking window and its first flag,
  * per-window inference latency of the deployed detectors.

Usage:
    python3 scripts/miids/extract_online_results.py
    python3 scripts/miids/extract_online_results.py --latex
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import math
import os
import statistics

# Scalars MI-IDS writes in finish(). Anything absent is treated as zero, so a
# run that ended early still contributes what it did record.
WANTED = (
    "confusionMatrix_TP", "confusionMatrix_FP",
    "confusionMatrix_FN", "confusionMatrix_TN",
    "miidsAbstentions", "miidsNoEvidenceSkips", "miidsUnobservedTicks",
    "miidsInferenceSamples", "miidsAvgInferenceLatencyMs",
    "miidsQuarantinedBenign", "miidsQuarantinedMalicious",
    "miidsSubjectsScored", "miidsObservedAttackers", "miidsDetectedAttackers",
    "miidsDetectionDelaySumS", "miidsDetectionDelayCount",
)

PRETTY = {
    "CAP_Baseline": "Baseline", "CAP_A1": "Content Poisoning",
    "CAP_A2": "Cache Pollution", "CAP_A3": "Cache Privacy Leakage",
    "CAP_A4": "Sybil Amplification", "CAP_A5": "Selective Forwarding",
    "CAP_A6": "Radio Jamming", "CAP_A7": "Replay Attack",
    "CAP_A8": "ML Evasion", "CAP_MultiAttack": "MultiAttack",
}


def read_sca(path):
    """Sum MI-IDS scalars over the MI-IDS modules of one run.

    The module filter is essential rather than cosmetic. The legacy IDSModule
    writes scalars under the same confusionMatrix_* names, and its counters are
    not comparable: on an attacker-free baseline it reports a TP count larger
    than the total number of verdicts MI-IDS issued. Summing both modules
    produced an apparent F1 of 0.999 on a run containing no attackers.

    Latency is a per-module mean, so summing it would be meaningless; it is
    collected separately and averaged over the modules that reported it.
    """
    tot = collections.Counter()
    latencies = []
    with open(path, errors="replace") as fh:
        for line in fh:
            if not line.startswith("scalar "):
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            module, name, value = parts[1], parts[2], parts[3].strip()
            if not module.endswith(".miids"):
                continue
            base = name.split(":")[0]
            if base not in WANTED:
                continue
            try:
                v = float(value)
            except ValueError:
                continue
            if base == "miidsAvgInferenceLatencyMs":
                if v > 0:
                    latencies.append(v)
            else:
                tot[base] += v
    return tot, latencies


def prf(tp, fp, fn, tn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / max(1.0, tp + tn + fp + fn)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(precision=prec, recall=rec, f1=f1, accuracy=acc, fpr=fpr)


def ci95(vals):
    vals = [v for v in vals if v == v]
    if not vals:
        return float("nan"), 0.0
    if len(vals) < 2:
        return vals[0], 0.0
    return statistics.mean(vals), 1.96 * statistics.stdev(vals) / math.sqrt(len(vals))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/exe_online")
    ap.add_argument("--out", default="datasets/exe_online/online_results.json")
    ap.add_argument("--latex", action="store_true")
    ap.add_argument("--out-dir",
                    default="VeReMiVNDN-Extension/Preparation_of_Papers_for_"
                            "IEEE_ACCESS_extension/generated")
    args = ap.parse_args()

    runs = []
    for d in sorted(glob.glob(os.path.join(args.root, "*_seed*"))):
        sca = glob.glob(os.path.join(d, "*.sca"))
        if not sca:
            continue
        tot, lat = read_sca(sca[0])
        cfg = os.path.basename(d).rsplit("_seed", 1)[0]
        seed = os.path.basename(d).rsplit("_seed", 1)[1]
        tp, fp = tot["confusionMatrix_TP"], tot["confusionMatrix_FP"]
        fn, tn = tot["confusionMatrix_FN"], tot["confusionMatrix_TN"]
        committed = tp + fp + fn + tn
        # Windows MI-IDS looked at but declined to rule on, over everything it
        # looked at. The evidence gate is counted separately because it fires
        # before any detector runs.
        declined = tot["miidsAbstentions"]
        scored = committed + declined
        runs.append({
            "config": cfg, "seed": seed,
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            **prf(tp, fp, fn, tn),
            "abstention_rate": (declined / scored) if scored else float("nan"),
            "evidence_gate_skips": tot["miidsNoEvidenceSkips"],
            "quarantined_benign": tot["miidsQuarantinedBenign"],
            "quarantined_malicious": tot["miidsQuarantinedMalicious"],
            "observed_attackers": tot["miidsObservedAttackers"],
            "detected_attackers": tot["miidsDetectedAttackers"],
            "mean_detection_delay_s": (
                tot["miidsDetectionDelaySumS"] / tot["miidsDetectionDelayCount"]
                if tot["miidsDetectionDelayCount"] else float("nan")),
            "inference_ms": (statistics.mean(lat) if lat else float("nan")),
        })

    if not runs:
        print(f"no runs found under {args.root}")
        return

    by_cfg = collections.defaultdict(list)
    for r in runs:
        by_cfg[r["config"]].append(r)

    print(f"{'scenario':<22}{'runs':>5}{'F1':>8}{'prec':>8}{'rec':>8}"
          f"{'FPR':>8}{'abst':>8}{'delay_s':>9}")
    per_cfg = {}
    for cfg in sorted(by_cfg):
        rs = by_cfg[cfg]
        agg = {k: ci95([r[k] for r in rs])
               for k in ("f1", "precision", "recall", "fpr", "abstention_rate",
                         "mean_detection_delay_s", "inference_ms")}
        agg["n_runs"] = len(rs)
        agg["quarantined_benign"] = sum(r["quarantined_benign"] for r in rs)
        agg["quarantined_malicious"] = sum(r["quarantined_malicious"] for r in rs)
        per_cfg[cfg] = agg
        print(f"{PRETTY.get(cfg, cfg):<22}{len(rs):>5}{agg['f1'][0]:>8.3f}"
              f"{agg['precision'][0]:>8.3f}{agg['recall'][0]:>8.3f}"
              f"{agg['fpr'][0]:>8.3f}{agg['abstention_rate'][0]:>8.3f}"
              f"{agg['mean_detection_delay_s'][0]:>9.2f}")

    # Campaign-wide totals, pooled over every committed verdict rather than
    # averaged over per-run rates, so scenarios with more traffic weigh more.
    #
    # The baseline scenario is pooled separately. It contains no attackers, so
    # it can only ever contribute false positives and true negatives; folding it
    # into an F1 would depress the figure for a reason that has nothing to do
    # with detection quality. Its value is as a false-alarm measurement on a
    # clean network, which is reported on its own.
    atk_runs = [r for r in runs if r["config"] != "CAP_Baseline"]
    base_runs = [r for r in runs if r["config"] == "CAP_Baseline"]
    TP = sum(r["TP"] for r in atk_runs); FP = sum(r["FP"] for r in atk_runs)
    FN = sum(r["FN"] for r in atk_runs); TN = sum(r["TN"] for r in atk_runs)
    overall = prf(TP, FP, FN, TN)
    bFP = sum(r["FP"] for r in base_runs); bTN = sum(r["TN"] for r in base_runs)
    baseline_fpr = bFP / (bFP + bTN) if (bFP + bTN) else float("nan")
    baseline_quarantined = sum(r["quarantined_benign"] for r in base_runs)
    baseline_subjects = sum(r["observed_attackers"] + 0 for r in base_runs)
    qb = sum(r["quarantined_benign"] for r in runs)
    qm = sum(r["quarantined_malicious"] for r in runs)
    delays = [r["mean_detection_delay_s"] for r in runs]
    print(f"\npooled over {len(atk_runs)} attack runs: F1={overall['f1']:.3f} "
          f"P={overall['precision']:.3f} R={overall['recall']:.3f} "
          f"FPR={overall['fpr']:.3f}")
    print(f"attacker-free baseline ({len(base_runs)} runs): "
          f"false-alarm rate={baseline_fpr:.3f}, "
          f"{baseline_quarantined:,.0f} benign quarantines")
    print(f"quarantined: {qm:,.0f} malicious vs {qb:,.0f} benign")

    payload = {"per_config": per_cfg, "overall": overall,
               "baseline_fpr": baseline_fpr,
               "baseline_quarantined_benign": baseline_quarantined,
               "n_attack_runs": len(atk_runs), "n_baseline_runs": len(base_runs),
               "pooled_confusion": {"TP": TP, "FP": FP, "FN": FN, "TN": TN},
               "quarantined_benign": qb, "quarantined_malicious": qm,
               "detection_delay_samples": [d for d in delays if d == d],
               "runs": runs}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"wrote {args.out}")

    qm_all = sum(r["quarantined_malicious"] for r in atk_runs)
    qb_all = sum(r["quarantined_benign"] for r in atk_runs)

    if args.latex:
        os.makedirs(args.out_dir, exist_ok=True)
        out = os.path.join(args.out_dir, "tab_online_results.tex")
        L = [
            r"\begin{table*}[t]", r"\centering",
            r"\caption{Closed-loop MI-IDS behavior on the online campaign. The "
            r"deployed TorchScript detectors run inside the simulator on runs "
            r"generated from seeds held out of training. Values are the mean "
            r"over the runs of each scenario with a 95\% confidence "
            r"interval; the delay column is the time from a subject's first "
            r"attacking window to the first window in which it was flagged.}",
            r"\label{tab:online-results}",
            r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
            r"\begin{tabular}{p{3.4cm}p{2.4cm}p{2.4cm}p{2.3cm}p{2.3cm}p{2.3cm}}",
            r"\hline",
            r"\textbf{Scenario} & \textbf{F1} & \textbf{Rec.} & \textbf{FPR} & "
            r"\textbf{Delay (s)} & \textbf{Quar. M:B} \\ \hline",
        ]

        def f(pair, digits=3):
            m, h = pair
            if m != m:
                return "--"
            return f"{m:.{digits}f} $\\pm$ {h:.{digits}f}"

        for cfg in sorted(per_cfg):
            a = per_cfg[cfg]
            qm, qb = a["quarantined_malicious"], a["quarantined_benign"]
            quar = f"{qm:,.0f}:{qb:,.0f}"
            L.append(f"{PRETTY.get(cfg, cfg)} & {f(a['f1'])} & "
                     f"{f(a['recall'])} & {f(a['fpr'])} & "
                     f"{f(a['mean_detection_delay_s'], 2)} & {quar} "
                     + r"\\ \hline")
        L += [
            r"\textbf{Pooled (attacks)} & \textbf{" + f"{overall['f1']:.3f}"
            + r"} & \textbf{" + f"{overall['recall']:.3f}" + r"} & \textbf{"
            + f"{overall['fpr']:.3f}" + r"} & -- & \textbf{"
            + f"{qm_all:,.0f}:{qb_all:,.0f}" + r"} \\ \hline",
            r"\end{tabular}",
            r"\vspace{2pt}",
            r"\parbox{\textwidth}{\footnotesize The Baseline scenario contains "
            r"no attackers, so F1 and recall are undefined there and its row "
            r"reports the false-alarm rate on a clean network; it is excluded "
            r"from the pooled figure for that reason. The last column counts "
            r"neighbors that ended a run in quarantine, malicious to benign, "
            r"resolved against ground truth after the fact.}",
            r"\end{table*}", "",
        ]
        open(out, "w").write("\n".join(L))
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
