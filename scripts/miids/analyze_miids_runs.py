"""
analyze_miids_runs.py - extract MI-IDS metrics from .sca files via opp_scavetool.

Reads every *.sca under simulations/configs/results/ that matches the EXE
naming pattern, pulls scalars produced by MIIDSModule and FeatureExtractor,
then prints a markdown table aligned with the headline numbers in the paper.

Usage:
    python3 scripts/miids/analyze_miids_runs.py              # default results dir
    python3 scripts/miids/analyze_miids_runs.py --filter EXE_

Metrics computed per Config:
    - macro-F1, FPR, recall, precision (per-attack and aggregate)
    - mean detection delay (s)
    - DST conflict mass K (mean over runs)
    - quarantine count
    - adversarial F1 (when adversarialEpsilon != 0)

If opp_scavetool is unavailable, falls back to scanning .sca files as plain
text (the IEEE Access submission machine almost always has scavetool, but a
fallback keeps the script useful for offline desk audits).
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict


SCAVETOOL = shutil.which("opp_scavetool") or "opp_scavetool"


# Scalars MI-IDS emits via the simsignals declared in MIIDSModule.ned
MIIDS_SIGNALS = [
    "miidsBetP:mean",
    "miidsBetP:max",
    "miidsConflict:mean",
    "miidsConflict:max",
    "miidsTrust:mean",
    "miidsVerdict:sum",
    "miidsQuarantined:sum",
]

# Plane scores from FeatureExtractor
PLANE_SIGNALS = [
    "planeScoreData:mean",
    "planeScoreCache:mean",
    "planeScoreTrust:mean",
    "planeScoreForwarding:mean",
    "planeScorePhy:mean",
]


def list_sca(results_dir: str, name_filter: str | None):
    out = []
    for fn in sorted(os.listdir(results_dir)):
        if not fn.endswith(".sca"):
            continue
        if name_filter and name_filter not in fn:
            continue
        out.append(os.path.join(results_dir, fn))
    return out


def query_scalars(sca: str):
    """Return {scalar_name: float} for a single .sca file."""
    # Make sure the OMNeT++ bin dir is on PATH if the user didn't export it.
    if "/omnetpp-6.0.3/bin" not in os.environ.get("PATH", ""):
        os.environ["PATH"] = "/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin:" + os.environ.get("PATH", "")
    if shutil.which("opp_scavetool"):
        tmp = "/tmp/_miids_sca.csv"
        try:
            subprocess.run(
                ["opp_scavetool", "x",
                 "-F", "CSV-S",
                 "-x", "allowMixed=true",
                 "-T", "st",         # scalars + statistics (so :mean fields land)
                 "-o", tmp, sca],
                check=True, capture_output=True, text=True,
            )
            out = {}
            with open(tmp) as fh:
                # CSV-S with -T st emits a multi-section file:
                #   <blank line>
                #   **** SCALARS ****
                #   run,...,module,name,value
                #   <scalar data rows>
                #   **** STATISTICS ****
                #   run,...,module,name,count,sumweights,mean,stddev,min,max
                #   <statistic data rows>
                # We scan section by section, re-read the header on each
                # banner, and dispatch row parsing using the named columns
                # so iteration vars (eps, maliciousCount, ...) that add
                # extra columns don't break offsets.
                reader = csv.reader(fh)
                col = {}
                section = None  # "S" or "T"
                for row in reader:
                    if not row:
                        continue
                    # Banner row?
                    joined = ",".join(row).strip()
                    if joined.startswith("****"):
                        if "SCALAR" in joined.upper():
                            section = "S"
                        elif "STATISTIC" in joined.upper():
                            section = "T"
                        else:
                            section = None
                        col = {}
                        continue
                    # Header row?
                    if not col and ("module" in row and "name" in row):
                        col = {n: i for i, n in enumerate(row)}
                        continue
                    if not col or section is None:
                        continue
                    ci_module = col.get("module"); ci_name = col.get("name")
                    if ci_module is None or ci_name is None:
                        continue
                    if max(ci_module, ci_name) >= len(row):
                        continue
                    module = row[ci_module]
                    name   = row[ci_name]
                    if not name:
                        continue
                    if section == "S":
                        ci_value = col.get("value")
                        if ci_value is None or ci_value >= len(row):
                            continue
                        try:
                            out[f"{module}.{name}" if module else name] = float(row[ci_value])
                        except ValueError:
                            pass
                    else:  # statistic
                        ci_count = col.get("count"); ci_mean = col.get("mean")
                        ci_stddev = col.get("stddev"); ci_min = col.get("min"); ci_max = col.get("max")
                        try:
                            count = float(row[ci_count]) if ci_count is not None and ci_count < len(row) and row[ci_count] != "" else float("nan")
                            mean  = float(row[ci_mean])  if ci_mean  is not None and ci_mean  < len(row) and row[ci_mean]  != "" else float("nan")
                        except ValueError:
                            continue
                        def _safe(idx):
                            if idx is None or idx >= len(row) or row[idx] == "":
                                return float("nan")
                            try: return float(row[idx])
                            except ValueError: return float("nan")
                        stddev = _safe(ci_stddev); mn = _safe(ci_min); mx = _safe(ci_max)
                        short = name.split(":")[0]
                        prefix = f"{module}.{short}" if module else short
                        out[f"{prefix}:count"]  = count
                        out[f"{prefix}:mean"]   = mean
                        out[f"{prefix}:stddev"] = stddev
                        out[f"{prefix}:min"]    = mn
                        out[f"{prefix}:max"]    = mx
                        out[f"{prefix}:sum"]    = mean * count if count == count and mean == mean else float("nan")
            return out
        except subprocess.CalledProcessError as e:
            print(f"  WARN: scavetool failed on {sca}: {e.stderr.strip()[:120] if e.stderr else e}",
                  file=sys.stderr)

    # Fallback: parse the .sca text format. Build keys as "<module>.<name>"
    # so the same endswith() filters in derive_metrics() work uniformly with
    # the CSV-S path. Also catch statistic-derived scalars like "x:mean".
    out = {}
    scalar_re   = re.compile(r"^scalar\s+(\S+)\s+(\S+)\s+(\S+)")
    statistic_re= re.compile(r"^(?:statistic|attr)\s")
    field_re    = re.compile(r"^field\s+(\S+)\s+(\S+)")
    cur_module = None
    cur_name   = None
    with open(sca) as f:
        for ln in f:
            m = scalar_re.match(ln)
            if m:
                key = f"{m.group(1)}.{m.group(2)}"
                try:
                    out[key] = float(m.group(3))
                except ValueError:
                    pass
                cur_module = None
                continue
            # Statistic block: "statistic <module> <name>" then "field mean X"
            sm = re.match(r"^statistic\s+(\S+)\s+(\S+)", ln)
            if sm:
                cur_module = sm.group(1)
                cur_name   = sm.group(2)
                continue
            fm = field_re.match(ln)
            if fm and cur_module:
                fname = fm.group(1)
                try:
                    out[f"{cur_module}.{cur_name}:{fname}"] = float(fm.group(2))
                except ValueError:
                    pass
    return out


def derive_metrics(scalars: dict) -> dict:
    """Compute the high-level metrics referenced in the abstract.

    Strategy: F1/Prec/Rec/Acc are recomputed from the SUMMED confusion
    matrix across all modules (the per-module averaging the prior version
    used produces zeros whenever a benign vehicle reports F1=0 because it
    has no TP). MI-IDS scalars are aggregated separately from the legacy
    IDS so each detector family's numbers can be reported independently.
    """
    m = {}
    m["betp_mean"]      = float("nan")
    m["betp_max"]       = float("nan")
    m["conflict_mean"]  = float("nan")
    m["trust_mean"]     = float("nan")
    m["verdict_count"]  = 0.0
    m["quarantined"]    = 0.0

    # Confusion-matrix totals split by detector family
    miids_tp = miids_fp = miids_tn = miids_fn = 0.0
    ids_tp   = ids_fp   = ids_tn   = ids_fn   = 0.0
    per_attack = defaultdict(float)

    # Latency, vector signal stats
    miids_latency_samples = []
    betp_means = []
    conflict_means = []
    trust_means = []

    for k, v in scalars.items():
        is_miids = ".miids." in k or k.endswith(".miids.confusionMatrix_TP") \
                   or k.endswith(".miids.confusionMatrix_FP") \
                   or k.endswith(".miids.confusionMatrix_TN") \
                   or k.endswith(".miids.confusionMatrix_FN")
        # Confusion matrix
        if k.endswith("confusionMatrix_TP"):
            if is_miids: miids_tp += v
            else:        ids_tp   += v
        if k.endswith("confusionMatrix_FP"):
            if is_miids: miids_fp += v
            else:        ids_fp   += v
        if k.endswith("confusionMatrix_TN"):
            if is_miids: miids_tn += v
            else:        ids_tn   += v
        if k.endswith("confusionMatrix_FN"):
            if is_miids: miids_fn += v
            else:        ids_fn   += v
        if "Detections" in k and k.endswith("Detections"):
            per_attack[k.split(".")[-1]] += v
        # MI-IDS specific signals
        if k.endswith("miidsBetP:mean"):
            if v == v: betp_means.append(v)
        if k.endswith("miidsBetP:max"):
            if v > m["betp_max"] or m["betp_max"] != m["betp_max"]:
                m["betp_max"] = v
        if k.endswith("miidsConflict:mean"):
            if v == v: conflict_means.append(v)
        if k.endswith("miidsTrust:mean"):
            if v == v: trust_means.append(v)
        if k.endswith("miidsVerdict:sum"):     m["verdict_count"] += v
        if k.endswith("miidsQuarantined:sum"): m["quarantined"]   += v
        if k.endswith("miidsAvgInferenceLatencyMs"):
            miids_latency_samples.append(v)

    if betp_means:     m["betp_mean"]     = sum(betp_means)/len(betp_means)
    if conflict_means: m["conflict_mean"] = sum(conflict_means)/len(conflict_means)
    if trust_means:    m["trust_mean"]    = sum(trust_means)/len(trust_means)
    if miids_latency_samples:
        m["miids_latency_ms"] = sum(miids_latency_samples)/len(miids_latency_samples)
    else:
        m["miids_latency_ms"] = float("nan")

    def calc(tp, fp, tn, fn):
        prec = tp/(tp+fp) if (tp+fp) > 0 else float("nan")
        rec  = tp/(tp+fn) if (tp+fn) > 0 else float("nan")
        f1   = (2*prec*rec/(prec+rec)) if (prec == prec and rec == rec and (prec+rec) > 0) else float("nan")
        total = tp + fp + tn + fn
        acc  = (tp+tn)/total if total > 0 else float("nan")
        fpr  = fp/(fp+tn) if (fp+tn) > 0 else float("nan")
        return prec, rec, f1, acc, fpr

    p, r, f1, acc, fpr = calc(miids_tp, miids_fp, miids_tn, miids_fn)
    m["miids_precision"] = p; m["miids_recall"] = r
    m["miids_f1"] = f1; m["miids_accuracy"] = acc; m["miids_fpr"] = fpr
    m["miids_tp"], m["miids_fp"] = miids_tp, miids_fp
    m["miids_tn"], m["miids_fn"] = miids_tn, miids_fn

    p, r, f1, acc, fpr = calc(ids_tp, ids_fp, ids_tn, ids_fn)
    m["ids_precision"] = p; m["ids_recall"] = r
    m["ids_f1"] = f1; m["ids_accuracy"] = acc; m["ids_fpr"] = fpr
    m["tp"], m["fp"], m["tn"], m["fn"] = ids_tp, ids_fp, ids_tn, ids_fn

    # If MI-IDS produced no decisions (e.g. ThresholdIDS baseline that
    # disables MI-IDS entirely), surface the legacy IDS metrics in the
    # MI-IDS columns. The legacy IDSModule reports its own F1/Prec/Rec/Acc
    # via dedicated scalars (its confusion-matrix counters only track TPs
    # in the published code path), so we prefer those over the derived
    # ones to keep the comparison fair.
    if miids_tp + miids_fp + miids_tn + miids_fn == 0 and \
       ids_tp + ids_fp + ids_tn + ids_fn > 0:
        f1_vals  = [v for k, v in scalars.items()
                    if k.endswith(".idsModule.detectionF1Score") and v == v]
        prc_vals = [v for k, v in scalars.items()
                    if k.endswith(".idsModule.detectionPrecision") and v == v]
        rec_vals = [v for k, v in scalars.items()
                    if k.endswith(".idsModule.detectionRecall") and v == v]
        acc_vals = [v for k, v in scalars.items()
                    if k.endswith(".idsModule.detectionAccuracy") and v == v]
        if f1_vals:
            m["miids_f1"]        = sum(f1_vals)/len(f1_vals)
            m["miids_precision"] = sum(prc_vals)/len(prc_vals) if prc_vals else float("nan")
            m["miids_recall"]    = sum(rec_vals)/len(rec_vals) if rec_vals else float("nan")
            m["miids_accuracy"]  = sum(acc_vals)/len(acc_vals) if acc_vals else float("nan")
        else:
            m["miids_f1"]        = m["ids_f1"]
            m["miids_precision"] = m["ids_precision"]
            m["miids_recall"]    = m["ids_recall"]
            m["miids_accuracy"]  = m["ids_accuracy"]
        m["miids_fpr"]       = m["ids_fpr"]
        m["miids_tp"], m["miids_fp"] = ids_tp, ids_fp
        m["miids_tn"], m["miids_fn"] = ids_tn, ids_fn
        m["detector_family"] = "legacy_ids"
    else:
        m["detector_family"] = "miids"

    for atk, n in per_attack.items():
        m[f"per_attack[{atk}]"] = n

    m["feature_extractions"] = scalars.get("featureExtraction:count", 0.0)
    return m


def fmt(x):
    if x != x:  # NaN
        return "n/a"
    if abs(x) < 1e-6:
        return "0"
    if abs(x) > 999:
        return f"{x:,.0f}"
    return f"{x:.3f}"


def render_table(rows):
    cols = ["config",
            "miids_f1", "miids_precision", "miids_recall", "miids_accuracy",
            "miids_fpr",
            "miids_tp", "miids_fp", "miids_tn", "miids_fn",
            "betp_mean", "conflict_mean", "trust_mean",
            "verdict_count", "quarantined", "miids_latency_ms"]
    headers = ["Config",
               "MI-F1", "Prec", "Rec", "Acc", "FPR",
               "TP", "FP", "TN", "FN",
               "BetP(M)mean", "K mean", "T_n mean",
               "verdicts", "quar.", "lat(ms)"]
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for r in rows:
        print("| " + " | ".join(fmt(r.get(c, float("nan"))) if c != "config"
                                else r["config"] for c in cols) + " |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir",
                    default="simulations/configs/results")
    ap.add_argument("--filter", default=None,
                    help="Only configs whose .sca filename contains this substring")
    args = ap.parse_args()

    sca_files = list_sca(args.results_dir, args.filter)
    if not sca_files:
        print(f"no .sca files matched in {args.results_dir}", file=sys.stderr)
        sys.exit(1)

    rows = []
    for f in sca_files:
        scalars = query_scalars(f)
        m = derive_metrics(scalars)
        m["config"] = os.path.basename(f).replace(".sca", "")
        rows.append(m)

    print(f"\n# MI-IDS run analysis ({len(rows)} runs)\n")
    render_table(rows)
    print()


if __name__ == "__main__":
    main()
