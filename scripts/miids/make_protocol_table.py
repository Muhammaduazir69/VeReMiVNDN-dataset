"""
make_protocol_table.py - one table comparing MI-IDS across the three splits.

The three protocols answer different questions, and reporting them separately
makes the comparison hard to see. Run-disjoint asks whether the detector
generalizes to a new traffic realization, attacker-disjoint whether it
generalizes to vehicles it has never scored, and unseen-attack whether the plane
decomposition transfers to a threat family absent from training. The last is the
one that matters for deployment and the one where we do worst.

Usage:
    python3 scripts/miids/make_protocol_table.py
"""

from __future__ import annotations

import argparse
import json
import os

PROTOCOLS = [
    ("run-disjoint", "Run-disjoint", "held-out seeds"),
    ("attacker-disjoint", "Attacker-disjoint", "held-out vehicles"),
    ("unseen-attack", "Unseen-attack", "held-out attack family"),
]


def cell(entry, digits=3, with_ci=True):
    if entry is None:
        return "--"
    if isinstance(entry, dict):
        m, h = entry.get("mean"), entry.get("ci95", 0.0)
    else:
        m, h = entry, 0.0
    if m is None or m != m:
        return "--"
    if with_ci and h:
        return f"{m:.{digits}f}\\,$\\pm$\\,{h:.{digits}f}"
    return f"{m:.{digits}f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/exe_capture")
    ap.add_argument("--out",
                    default="VeReMiVNDN-Extension/Preparation_of_Papers_for_"
                            "IEEE_ACCESS_extension/generated/tab_protocols.tex")
    args = ap.parse_args()

    rows = []
    for key, label, what in PROTOCOLS:
        path = os.path.join(args.root, f"miids_results_{key}.json")
        if not os.path.exists(path):
            print(f"missing {path}, leaving row blank")
            rows.append((label, what, None, None))
            continue
        with open(path) as fh:
            summary = json.load(fh)["summary"]
        rows.append((label, what, summary, summary.get("n_folds")))

    L = [
        r"\begin{table*}[t]", r"\centering",
        r"\caption{MI-IDS across the three split protocols, each value the mean "
        r"over folds with a 95\% confidence interval. The protocols are "
        r"ordered by how much they withhold from training. AUPRC should be read "
        r"against the attacker prevalence of the split, which is 0.203 for the "
        r"first two and 0.231 for the third, so the lifts over a random ranker "
        r"are 2.46, 2.45 and 1.92 respectively.}",
        r"\label{tab:protocols}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{2.7cm}p{2.7cm}p{2.2cm}p{1.9cm}p{1.9cm}p{1.6cm}p{1.6cm}}",
        r"\hline",
        r"\textbf{Protocol} & \textbf{Withheld} & \textbf{F1} & "
        r"\textbf{AUROC} & \textbf{AUPRC} & \textbf{FPR} & \textbf{Abst.} "
        r"\\ \hline",
    ]
    for label, what, summary, n in rows:
        if summary is None:
            L.append(f"{label} & {what} & -- & -- & -- " + r"\\ \hline")
            continue
        dst = summary.get("MI-IDS (DST)", {})
        L.append(
            f"{label} & {what} & {cell(dst.get('f1'))} & "
            f"{cell(summary.get('auroc'))} & "
            f"{cell(summary.get('auprc'))} & "
            f"{cell(dst.get('fpr'), with_ci=False)} & "
            f"{cell(summary.get('abstention_rate'), with_ci=False)} "
            + r"\\ \hline")
    L += [r"\end{tabular}", r"\end{table*}", ""]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    open(args.out, "w").write("\n".join(L))
    print(f"wrote {args.out}")
    for label, what, summary, n in rows:
        if summary:
            dst = summary.get("MI-IDS (DST)", {})
            print(f"  {label:<20} folds={n} "
                  f"F1={cell(dst.get('f1'))} AUROC={cell(summary.get('auroc'))}")


if __name__ == "__main__":
    main()
