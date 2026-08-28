"""
make_scenario_metrics.py - per-scenario network behavior from the capture campaign.

This answers a question the detection tables cannot: does each attack actually
perturb the network in the way its threat model claims? A detector scoring well
on a family that leaves no trace in the forwarding state would be evidence of
leakage rather than of detection, so these numbers are the sanity check that
sits underneath the detection results.

Every quantity is read from the OMNeT++ scalar files and is attributed to the
module that wrote it. That attribution is not optional. Three scalar names in
this model are written by more than one module with unrelated meanings:
totalInsertions exists on the Content Store, the PIT and the FIB, and the
detection scalars exist on both the legacy IDSModule and the MI-IDS module,
where the legacy counters are not comparable.

Metrics deliberately excluded, with reasons, because each looks available but is
not measurable in this build:

  * Interest Satisfaction Ratio at the consumer. interestsSatisfied is
    identically zero in all 50 runs: isValidData() accepts only RSU-signed Data,
    RSUs never receive Interests, so no RSU-signed Data ever reaches the wire.
    The PIT satisfaction ratio is reported instead and named as such.
  * End-to-end and forwarding delay. forwardingDelay is computed across a
    zero-delay send() to a directly connected submodule, so its sum is exactly
    zero over 2.8 million samples.
  * PIT occupancy. handleSatisfyRequest() decrements currentSize twice, which
    drives finalPITSize negative.
  * Content Store evictions. The 100 MB store never fills at 256-byte content,
    so the zero eviction count is a sizing artifact, not a caching result.
  * Collisions, channel-busy fraction, MAC retransmissions. NDN traffic is
    delivered by a spatial-index emulation rather than through the 802.11p NIC,
    so every MAC and PHY counter is identically zero.

Usage:
    python3 scripts/miids/make_scenario_metrics.py
    python3 scripts/miids/make_scenario_metrics.py --latex
"""

from __future__ import annotations

import argparse
import collections
import glob
import math
import os
import statistics

PRETTY = {
    "CAP_Baseline": "Baseline", "CAP_A1": "Content Poisoning",
    "CAP_A2": "Cache Pollution", "CAP_A3": "Cache Privacy Leakage",
    "CAP_A4": "Sybil Amplification", "CAP_A5": "Selective Forwarding",
    "CAP_A6": "Radio Jamming", "CAP_A7": "Replay Attack",
    "CAP_A8": "ML Evasion", "CAP_MultiAttack": "MultiAttack",
}
ORDER = ["CAP_Baseline", "CAP_A1", "CAP_A2", "CAP_A3", "CAP_A4", "CAP_A5",
         "CAP_A6", "CAP_A7", "CAP_A8", "CAP_MultiAttack"]


def read_run(path):
    """Totals for one run, keyed by (module role, scalar name)."""
    t = collections.Counter()
    with open(path, errors="replace") as fh:
        for line in fh:
            if not line.startswith("scalar "):
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            module, name, value = parts[1], parts[2], parts[3].strip()
            if ".vehicle[" not in module:
                continue
            try:
                v = float(value)
            except ValueError:
                continue
            base = name.split(":")[0]
            if module.endswith(".ndnNode.pit"):
                if base in ("totalInsertions", "totalSatisfied",
                            "totalExpirations", "totalAggregated"):
                    t["pit_" + base] += v
            elif module.endswith(".ndnNode.cs"):
                if base in ("totalHits", "totalMisses", "totalInsertions"):
                    t["cs_" + base] += v
            elif module.endswith(".ndnNode.processor"):
                if base in ("interestReceived", "interestSent", "dataReceived",
                            "dataSent", "nackSent", "packetDropped"):
                    if name.endswith(":count"):
                        t["proc_" + base] += v
            elif module.endswith(".controller"):
                if base in ("interestsIssued", "interestsExpired",
                            "producerAnswers"):
                    t["ctl_" + base] += v
            elif module.endswith(".featureExtractor"):
                if base in ("exeSubjectsObserved", "exeEvidenceWindows",
                            "exeBeaconOnlyWindows"):
                    t["fe_" + base] += v
                    if base == "exeSubjectsObserved":
                        t["fe_monitors"] += 1
    return t


def ratio(a, b):
    return (a / b) if b else float("nan")


def derive(t):
    pit_ins = t["pit_totalInsertions"]
    return {
        "pit_sat": ratio(t["pit_totalSatisfied"], pit_ins),
        "pit_exp": ratio(t["pit_totalExpirations"], pit_ins),
        "aggregation": ratio(t["pit_totalAggregated"],
                             t["pit_totalAggregated"] + pit_ins),
        "cs_hit": ratio(t["cs_totalHits"],
                        t["cs_totalHits"] + t["cs_totalMisses"]),
        "nack": ratio(t["proc_nackSent"], t["proc_interestReceived"]),
        "fwd_ratio": ratio(t["proc_interestSent"], t["proc_interestReceived"]),
        "unsolicited": ratio(t["proc_packetDropped"], t["proc_dataReceived"]),
        "consumer_exp": ratio(t["ctl_interestsExpired"], t["ctl_interestsIssued"]),
        "interests_recv": t["proc_interestReceived"],
        "interests_issued": t["ctl_interestsIssued"],
        "neighbors": ratio(t["fe_exeSubjectsObserved"], t["fe_monitors"]),
        "evidence_share": ratio(t["fe_exeEvidenceWindows"],
                                t["fe_exeEvidenceWindows"] + t["fe_exeBeaconOnlyWindows"]),
    }


def ci95(vals):
    vals = [v for v in vals if v == v]
    if not vals:
        return float("nan"), 0.0
    if len(vals) < 2:
        return vals[0], 0.0
    return statistics.mean(vals), 1.96 * statistics.stdev(vals) / math.sqrt(len(vals))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datasets/exe_capture")
    ap.add_argument("--latex", action="store_true")
    ap.add_argument("--out",
                    default="VeReMiVNDN-Extension/Preparation_of_Papers_for_"
                            "IEEE_ACCESS_extension/generated/tab_scenario_metrics.tex")
    args = ap.parse_args()

    by_cfg = collections.defaultdict(list)
    for d in sorted(glob.glob(os.path.join(args.root, "*_seed*"))):
        sca = glob.glob(os.path.join(d, "[!.]*.sca"))
        if not sca:
            continue
        cfg = os.path.basename(d).rsplit("_seed", 1)[0]
        by_cfg[cfg].append(derive(read_run(sca[0])))

    if not by_cfg:
        print(f"no runs under {args.root}")
        return

    keys = ["pit_sat", "pit_exp", "aggregation", "cs_hit", "nack", "fwd_ratio",
            "interests_recv", "neighbors", "evidence_share"]
    agg = {c: {k: ci95([r[k] for r in rs]) for k in keys}
           for c, rs in by_cfg.items()}

    hdr = f"{'scenario':<22}" + "".join(f"{k:>13}" for k in keys[:6])
    print(hdr)
    for c in ORDER:
        if c not in agg:
            continue
        a = agg[c]
        print(f"{PRETTY.get(c,c):<22}" +
              "".join(f"{a[k][0]:>13.4f}" for k in keys[:6]))

    print()
    for c in ORDER:
        if c not in agg:
            continue
        a = agg[c]
        print(f"{PRETTY.get(c,c):<22} interests_recv={a['interests_recv'][0]:>10,.0f} "
              f"neighbors/monitor={a['neighbors'][0]:.1f} "
              f"evidence_share={a['evidence_share'][0]:.3f}")

    # Campaign-wide values, for the aggregate network table.
    allr = [r for rs in by_cfg.values() for r in rs]
    print("\ncampaign-wide (mean +/- 95% CI over 50 runs)")
    for k, label in (("pit_sat", "PIT satisfaction ratio"),
                     ("pit_exp", "PIT expiry ratio"),
                     ("cs_hit", "Content Store hit ratio"),
                     ("nack", "NACK ratio"),
                     ("fwd_ratio", "Interests forwarded per Interest received"),
                     ("unsolicited", "Unsolicited-Data discard ratio"),
                     ("consumer_exp", "Consumer Interest expiry ratio"),
                     ("interests_issued", "Consumer Interests issued per run"),
                     ("neighbors", "Distinct neighbors per monitor"),
                     ("evidence_share", "Windows carrying behavioral evidence")):
        m, h = ci95([r[k] for r in allr])
        print(f"  {label:<44} {m:>12.4f} +/- {h:.4f}")

    if args.latex:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        L = [
            r"\begin{table*}[t]", r"\centering",
            r"\caption{Network-level effect of each attack, measured from the "
            r"simulator counters over the five seeds of each scenario and "
            r"reported as mean with a 95\% confidence interval. These are "
            r"the traces the detectors are asked to find. Quantities are "
            r"vehicle-side: RSUs in this build receive no Interests, so RSU "
            r"ratios are undefined rather than zero.}",
            r"\label{tab:scenario-metrics}",
            r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
            r"\begin{tabular}{p{3.0cm}p{2.1cm}p{2.1cm}p{2.1cm}p{2.1cm}p{2.1cm}}",
            r"\hline",
            r"\textbf{Scenario} & \textbf{PIT satisf.} & \textbf{PIT expiry} & "
            r"\textbf{Aggregation} & \textbf{CS hit} & \textbf{NACK ratio} "
            r"\\ \hline",
        ]
        for c in ORDER:
            if c not in agg:
                continue
            a = agg[c]
            cells = " & ".join(
                f"{a[k][0]:.3f} $\\pm$ {a[k][1]:.3f}"
                for k in ("pit_sat", "pit_exp", "aggregation", "cs_hit", "nack"))
            L.append(f"{PRETTY.get(c,c)} & {cells} " + r"\\ \hline")
        L += [r"\end{tabular}", r"\end{table*}", ""]
        open(args.out, "w").write("\n".join(L))
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
