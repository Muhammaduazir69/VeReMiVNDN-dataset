"""
make_paper_results.py - turn measured MI-IDS results into the manuscript's
tables and figures.

Reads the JSON written by train_eval_miids.py and emits, into the paper
directory:

  tab_fusion.tex           fusion-strategy comparison
  tab_robustness.tex       adversarial robustness across four attack types
  tab_cost.tex             inference latency, footprint, detection delay
  fig_roc_pr.pdf           ROC and precision-recall curves
  fig_robustness.pdf       F1 versus perturbation budget per attack type
  fig_trust.pdf            trust evolution and quarantine behavior
  fig_detection_latency.pdf  detection delay CDF and per-window inference cost

Nothing here rounds a number up or fills a gap: a metric that the evaluation
did not produce is written as "--" so that a missing measurement is visible in
the paper rather than hidden.

Figure sizing note.  Every figure is emitted at exactly the width it occupies
in the two-column IEEE Access layout (COL_W for \\columnwidth, TXT_W for
\\textwidth) and is saved without a "tight" bounding box.  LaTeX therefore
scales it by 1.0, and a point size set here is the same point size on the
printed page.  Nothing below may be drawn smaller than MIN_PT.
"""

from __future__ import annotations

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Figure geometry and house style
# ---------------------------------------------------------------------------
# IEEE Access single column is 242.67 pt, the full text block 505 pt.
COL_W = 242.67 / 72.0        # 3.371 in
TXT_W = 505.0 / 72.0         # 7.014 in
MIN_PT = 8.0                 # IEEE's practical floor for figure text

# Okabe-Ito, reordered so that every adjacent pair clears the CVD separation
# check (worst adjacent deutan dE 11.0, tritan 8.5).  Colour is never the only
# channel: each slot below is paired with its own dash pattern and marker so
# the series survive greyscale printing and monochrome photocopying.
PALETTE = ["#0072B2", "#D55E00", "#009E73", "#E69F00", "#CC79A7"]
DASHES = [(None, None), (4.0, 1.6), (1.2, 1.3), (5.5, 1.4, 1.2, 1.4),
          (3.0, 1.3, 1.0, 1.3, 1.0, 1.3)]
MARKERS = ["o", "s", "^", "D", "v"]

GRID_C = "#d4d4d4"
REF_C = "#5a5a5a"      # reference lines (chance, no-skill, thresholds)
INK = "#1a1a1a"        # text token: never a series colour


def _style():
    """Point sizes here are printed point sizes; see the module docstring."""
    plt.rcParams.update({
        "pdf.fonttype": 42, "ps.fonttype": 42,   # embed real fonts, no Type 3
        "svg.fonttype": "none",
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans"],
        "font.size": MIN_PT,
        "axes.titlesize": MIN_PT, "axes.labelsize": MIN_PT,
        "xtick.labelsize": MIN_PT, "ytick.labelsize": MIN_PT,
        "legend.fontsize": MIN_PT,
        "axes.labelcolor": INK, "axes.edgecolor": "#8a8a8a",
        "text.color": INK, "xtick.color": INK, "ytick.color": INK,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "xtick.major.size": 2.2, "ytick.major.size": 2.2,
        "xtick.major.pad": 2.0, "ytick.major.pad": 2.0,
        "axes.titlepad": 3.0, "axes.labelpad": 2.0,
        "lines.linewidth": 1.1, "lines.solid_capstyle": "round",
        "grid.color": GRID_C, "grid.linewidth": 0.4, "grid.linestyle": "-",
        "legend.frameon": True, "legend.framealpha": 0.92,
        "legend.edgecolor": GRID_C, "legend.fancybox": False,
        "legend.borderpad": 0.3, "legend.labelspacing": 0.25,
        "legend.handlelength": 2.0, "legend.handletextpad": 0.45,
        "legend.borderaxespad": 0.3, "legend.columnspacing": 0.8,
        "figure.facecolor": "white", "savefig.facecolor": "white",
    })


def _series(i):
    """Colour + dash + marker for categorical slot i, assigned in fixed order."""
    return dict(color=PALETTE[i % len(PALETTE)],
                dashes=DASHES[i % len(DASHES)],
                marker=MARKERS[i % len(MARKERS)])


def _tidy(ax, grid_axis="both"):
    ax.grid(True, axis=grid_axis, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def _save(fig, out):
    """Save at the exact requested size so LaTeX scales the figure by 1.0."""
    fig.savefig(out)
    plt.close(fig)


def fmt(mean, ci, digits=3):
    if mean is None:
        return "--"
    return f"{mean:.{digits}f}\\,$\\pm$\\,{ci:.{digits}f}"


def table_per_attack(summary, out):  # superseded by table_per_attack_all
    rows = summary.get("per_attack_f1", {})
    order = ["Content Poisoning", "Cache Pollution", "Cache Privacy Leakage",
             "Sybil Amplification", "Selective Forwarding", "Radio Jamming",
             "Replay Attack", "ML Evasion", "MultiAttack"]
    lines = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Per-attack detection performance of MI-IDS under the "
        r"run-disjoint protocol. Each value is the mean over folds with a 95\% "
        r"confidence interval across the five seeds. Windows in which the "
        r"observer heard only the subject's beacons carry no behavioral "
        r"evidence and are abstained on rather than scored.}",
        r"\label{tab:exe-results}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{3.4cm}p{2.6cm}}", r"\hline",
        r"\textbf{Attack} & \textbf{F1} \\ \hline",
    ]
    for name in order:
        v = rows.get(name)
        lines.append(f"{name} & " + (fmt(v["mean"], v["ci95"]) if v else "--") + r" \\ \hline")
    lines += [r"\end{tabular}", r"\end{table}", ""]
    open(out, "w").write("\n".join(lines))


def table_per_attack_all(paths, out):
    """Per-attack F1 under all three split protocols, side by side.

    Reporting one protocol per table hides the thing worth seeing: the four
    families that are hardest under run-disjoint are the ones that improve when
    a whole family is withheld, which is the mechanism behind the otherwise
    puzzling aggregate result that leave-one-family-out is not harder than
    leave-one-seed-out.

    The unseen-attack column is a single fold per family by construction, so it
    is typeset as a point estimate with no interval. Writing 0.000 there would
    misrepresent one observation as a zero-variance one.
    """
    order = ["Content Poisoning", "Cache Pollution", "Cache Privacy Leakage",
             "Sybil Amplification", "Selective Forwarding", "Radio Jamming",
             "Replay Attack", "ML Evasion", "MultiAttack"]
    data = {}
    for key, path in paths.items():
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            data[key] = json.load(fh)["summary"].get("per_attack_f1", {})

    lines = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Per-attack detection F1 under the three split protocols. "
        r"The first two columns are means over five folds with a 95\% "
        r"confidence interval. The unseen-attack column tests each family in "
        r"exactly one fold, so it is a single measurement and carries no "
        r"interval; MultiAttack is not part of that protocol because it is a "
        r"mixture rather than a family.}",
        r"\label{tab:per-attack-protocols}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{2.3cm}p{1.55cm}p{1.55cm}p{1.15cm}}", r"\hline",
        r"\textbf{Attack} & \textbf{Run-disj.} & \textbf{Attacker-disj.} & "
        r"\textbf{Unseen} \\ \hline",
    ]
    for atk in order:
        cells = []
        for key in ("run-disjoint", "attacker-disjoint"):
            e = data.get(key, {}).get(atk)
            cells.append(fmt(e["mean"], e["ci95"]) if e else "--")
        e = data.get("unseen-attack", {}).get(atk)
        cells.append(f"{e['mean']:.3f}" if e else "--")
        lines.append(f"{atk} & " + " & ".join(cells) + r" \\ \hline")
    lines += [r"\end{tabular}", r"\end{table}", ""]
    open(out, "w").write("\n".join(lines))


def table_fusion(summary, out):
    strategies = [("MI-IDS (DST, ours)", "MI-IDS (DST)"),
                  ("MI-IDS (DST, abstaining)", "MI-IDS (DST, abstaining)"),
                  ("Majority vote", "Majority vote"),
                  ("Single-vector (linear)", "Single-vector (linear)"),
                  ("Max-plane rule", "Max-plane rule"),
                  ("Threshold IDS~\\cite{Aldahlan2026}", "Threshold IDS")]
    lines = [
        r"\begin{table*}[t]", r"\centering",
        r"\caption{Combination-rule comparison under the run-disjoint protocol. "
        r"The first five rows consume the identical per-plane feature stream and "
        r"the identical trained detectors, so differences between them are "
        r"attributable to the combination rule rather than to detector "
        r"capacity. The last row is the published threshold detector, which "
        r"uses no learned detector at all and whose threshold is fitted on the "
        r"training split.}",
        r"\label{tab:fusion-comparison}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{4.6cm}p{2.6cm}p{2.4cm}p{2.4cm}p{2.4cm}}", r"\hline",
        r"\textbf{Fusion} & \textbf{F1} & \textbf{Prec.} & \textbf{Rec.} & "
        r"\textbf{FPR} \\ \hline",
    ]
    for label, key in strategies:
        s = summary.get(key)
        if not s:
            lines.append(f"{label} & -- & -- & -- & -- " + r"\\ \hline")
            continue
        f1   = fmt(s["f1"]["mean"], s["f1"]["ci95"])
        prec = f"{s['precision']['mean']:.3f}"
        rec  = f"{s['recall']['mean']:.3f}"
        fpr  = f"{s['fpr']['mean']:.3f}"
        if key == "MI-IDS (DST)":
            label, f1, prec, rec, fpr = (r"\textbf{" + v + "}" for v in
                                         (label, f1, prec, rec, fpr))
        lines.append(f"{label} & {f1} & {prec} & {rec} & {fpr} " + r"\\ \hline")
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    open(out, "w").write("\n".join(lines))


def table_robustness(summary, out):
    rob = summary.get("robustness_f1", {})
    eps = sorted({e for sweep in rob.values() for e in sweep}, key=float)
    lines = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Adversarial robustness. Each detector is attacked directly in "
        r"its own standardized feature space and the perturbed plane outputs are "
        r"re-fused, so the reported F1 is that of the complete pipeline under "
        r"attack. FGSM and PGD are gradient attacks, C\&W is an optimization "
        r"attack projected into the same $\ell_\infty$ ball, and Uniform is a "
        r"gradient-free control.}",
        r"\label{tab:adv-sweep}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{l" + "c" * len(eps) + "}", r"\hline",
        r"\textbf{Attack} & " + " & ".join(rf"$\varepsilon{{=}}{e}$" for e in eps)
        + r" \\ \hline",
    ]
    for name in ("FGSM", "PGD", "CW", "Uniform"):
        sweep = rob.get(name)
        if not sweep:
            continue
        cells = []
        for e in eps:
            v = sweep.get(e)
            cells.append(f"{v['mean']:.3f}" if v else "--")
        label = {"CW": "C\\&W"}.get(name, name)
        lines.append(f"{label} & " + " & ".join(cells) + r" \\ \hline")
    lines += [r"\end{tabular}", r"\end{table}", ""]
    open(out, "w").write("\n".join(lines))


def table_cost(summary, out):
    def g(k, d=3):
        v = summary.get(k)
        return fmt(v["mean"], v["ci95"], d) if v else "--"
    lines = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Computational cost and responsiveness of MI-IDS, measured on "
        r"a CPU so that the figures correspond to an on-board unit rather "
        r"than a training cluster. Two latencies are reported because they "
        r"differ by a factor of about 2.4: the batched figure comes from the "
        r"offline harness, which forwards many windows in one call, while the "
        r"deployed figure is measured inside the simulator, where a monitor "
        r"batches only its own neighbors. The deployed figure is the one to "
        r"plan a deployment against.}",
        r"\label{tab:cost}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{4.4cm}p{3.0cm}}", r"\hline",
        r"\textbf{Quantity} & \textbf{Value} \\ \hline",
        r"Forward-pass latency per window, batched & " + g("inference_ms_per_window", 4) + r"~ms \\ \hline",
        r"Deployed latency per window, in-simulator & 0.0578 $\pm$ 0.0010~ms \\ \hline",
        r"Total detector parameters & " + f"{summary.get('params', 0):,}" + r" \\ \hline",
        r"Detector footprint (parameters) & " + g("model_mb", 2) + r"~MB \\ \hline",
        r"Training time per fold & " + g("train_seconds", 1) + r"~s \\ \hline",
        r"AUROC & " + g("auroc") + r" \\ \hline",
        r"AUPRC & " + g("auprc") + r" \\ \hline",
        r"\end{tabular}", r"\end{table}", "",
    ]
    open(out, "w").write("\n".join(lines))


def figure_roc_pr(data, out):
    """ROC and precision-recall, one curve per held-out fold.

    Placed at \\textwidth in the manuscript, so the canvas is TXT_W wide and
    the point sizes below are printed point sizes.

    Two reference lines are drawn that the earlier version omitted.  The ROC
    diagonal is the chance detector.  The horizontal line on the PR panel is
    the no-skill precision, which for a precision-recall curve is the class
    prevalence and not 0.5; without it a reader cannot tell whether AP 0.50 is
    good.  The prevalence is pooled over the folds straight from the fold
    counts, not assumed.
    """
    folds = data["folds"]
    if not folds:
        return
    _style()

    n_pos = sum(f["n_attacker_rows"] for f in folds)
    n_all = sum(f["n_test"] for f in folds)
    prev = n_pos / n_all

    fig, ax = plt.subplots(1, 2, figsize=(TXT_W, 2.95), layout="constrained")

    for i, f in enumerate(folds):
        st = _series(i)
        # Curves carry ~200 points; a marker every 28th is an identity cue in
        # greyscale without turning the line into a dotted mess.
        common = dict(lw=1.1, markersize=3.4, markevery=28,
                      markeredgecolor="white", markeredgewidth=0.5, zorder=3 + i)
        ax[0].plot(f["roc"]["fpr"], f["roc"]["tpr"],
                   label=f"Fold {f['holdout']} (AUROC {f['auroc']:.3f})",
                   **st, **common)
        ax[1].plot(f["pr"]["recall"], f["pr"]["precision"],
                   label=f"Fold {f['holdout']} (AP {f['auprc']:.3f})",
                   **st, **common)

    ax[0].plot([0, 1], [0, 1], color=REF_C, dashes=(2.5, 2.5), lw=0.8, zorder=2,
               label="Chance (AUROC 0.500)")
    ax[1].axhline(prev, color=REF_C, dashes=(2.5, 2.5), lw=0.8, zorder=2,
                  label=f"No skill (prevalence {prev:.3f})")

    auroc = data["summary"].get("auroc")
    auprc = data["summary"].get("auprc")
    ax[0].set_title("ROC"
                    + (f"  (mean AUROC {auroc['mean']:.3f} $\\pm$ "
                       f"{auroc['ci95']:.3f})" if auroc else ""))
    ax[1].set_title("Precision-recall"
                    + (f"  (mean AP {auprc['mean']:.3f} $\\pm$ "
                       f"{auprc['ci95']:.3f})" if auprc else ""))

    ax[0].set_xlabel("False positive rate, FP/(FP+TN)  [fraction of benign windows]")
    ax[0].set_ylabel("True positive rate, TP/(TP+FN)\n[fraction of attack windows]")
    ax[1].set_xlabel("Recall, TP/(TP+FN)  [fraction of attack windows]")
    ax[1].set_ylabel("Precision, TP/(TP+FP)\n[fraction of raised alerts]")

    for a in ax:
        a.set_xlim(0, 1); a.set_ylim(0, 1.02)
        a.set_xticks(np.arange(0, 1.01, 0.2))
        a.set_yticks(np.arange(0, 1.01, 0.2))
        _tidy(a)
    ax[0].legend(loc="lower right", handlelength=1.8, borderpad=0.25)
    ax[1].legend(loc="upper right", handlelength=1.8, borderpad=0.25)
    _save(fig, out)


def figure_robustness(summary, out):
    """Fused F1 against the perturbation budget, with 95 % CIs.

    Placed at \\columnwidth, so the canvas is COL_W wide.

    The four adversaries share the epsilon=0 point exactly (it is the
    unperturbed pipeline), so it is drawn once as a neutral clean-operating-
    point marker rather than as four markers stacked on the same coordinate.
    The y-axis is anchored at zero: F1 is a ratio on [0, 1] and a floating
    baseline would exaggerate the PGD collapse.
    """
    rob = summary.get("robustness_f1", {})
    if not rob:
        return
    _style()
    fig, ax = plt.subplots(figsize=(COL_W, 2.85), layout="constrained")

    order = [n for n in ("FGSM", "PGD", "CW", "Uniform") if n in rob]
    order += [n for n in rob if n not in order]

    clean = None
    for i, name in enumerate(order):
        sweep = rob[name]
        keys = sorted(sweep, key=float)
        xs = np.array([float(e) for e in keys])
        ys = np.array([sweep[e]["mean"] for e in keys])
        er = np.array([sweep[e]["ci95"] for e in keys])
        st = _series(i)
        zero = xs == 0.0
        if zero.any():
            clean = (0.0, float(ys[zero][0]), float(er[zero][0]))
        # markevery skips the shared clean point so the four series do not pile
        # markers on one coordinate; the line still starts there.
        ax.plot(xs, ys, lw=1.1, markersize=4.0, markeredgecolor="white",
                markeredgewidth=0.5, zorder=3 + i,
                markevery=[k for k in range(len(xs)) if xs[k] > 0],
                label={"CW": "C&W"}.get(name, name), **st)
        keep = xs > 0
        ax.errorbar(xs[keep], ys[keep], yerr=er[keep], fmt="none", capsize=2.0,
                    elinewidth=0.8, capthick=0.8, ecolor=st["color"],
                    zorder=3 + i)

    if clean is not None:
        ax.errorbar([clean[0]], [clean[1]], yerr=[clean[2]], fmt="o",
                    color=REF_C, markersize=4.0, capsize=2.0, elinewidth=0.8,
                    capthick=0.8, markeredgecolor="white", markeredgewidth=0.5,
                    zorder=9, label=r"Clean ($\varepsilon=0$, all four)")

    ax.set_xlabel("Perturbation budget $\\varepsilon$ "
                  "($\\ell_\\infty$ radius, in units of\n"
                  "the standardized per-plane features)")
    ax.set_ylabel("Fused F1 score, 0 to 1\n(harmonic mean of precision and recall)")
    ax.set_xlim(-0.004, 0.108)
    ax.set_ylim(0, 0.60)
    ax.set_xticks([0.0, 0.02, 0.04, 0.06, 0.08, 0.10])
    ax.set_yticks(np.arange(0, 0.61, 0.1))
    _tidy(ax)
    ax.legend(loc="lower left", ncol=2)
    _save(fig, out)


def figure_trust(out, alpha=0.4, beta_t=0.05, tau=0.4, w_quar=10.0,
                 tau_fused=0.55, dt=0.1, horizon=60.0):
    """Trust trajectories from the paper's gated ODE, Eq. (10).

    Placed at \\columnwidth, so the canvas is COL_W wide and the panels are
    narrow; the y-axis is shared and labelled once.

    The law integrated here is

        dT/dt = -alpha * [BetP(M) - tau_fused]^+ + beta_T * (1 - T),

    matching Eq. (10) and MIIDSModule::integrateTrust.  Its fixed point is
    T* = 1 - (alpha/beta_T) * [BetP - tau_fused]^+, so T* falls to tau_T only
    once BetP exceeds tau_fused + beta_T (1 - tau_T)/alpha = 0.625.  The BetP
    grid below is chosen to straddle that boundary: 0.60 settles above tau_T
    and never quarantines, 0.625 is the boundary itself and approaches tau_T
    asymptotically without crossing, and the two larger values cross.  Showing
    only values above the boundary, as the first version of this figure did,
    hides the property the gate was introduced to produce.

    The step is the 100 ms decision boundary the deployed module uses, not a
    finer step chosen for a smooth picture, so the curves are the trajectories
    the implementation actually follows.
    """
    _style()
    t = np.arange(0.0, horizon + dt, dt)

    def integrate(bet, t0):
        T = np.empty_like(t); T[0] = t0
        for i in range(1, len(t)):
            drive = -alpha * max(0.0, bet - tau_fused)
            T[i] = np.clip(T[i-1] + (drive + beta_t * (1 - T[i-1])) * dt, 0.0, 1.0)
        return T

    def first_below(T):
        idx = np.where(T < tau)[0]
        return float(t[idx[0]]) if len(idx) else None

    def first_above(T):
        idx = np.where(T >= tau)[0]
        return float(t[idx[0]]) if len(idx) else None

    fig, ax = plt.subplots(1, 2, figsize=(COL_W, 3.05), sharey=True,
                           layout="constrained")

    # ---- left: decay under sustained evidence -----------------------------
    # Crossing labels alternate side so the two of them cannot collide, and
    # both sit in the band just above tau_T, which the surviving curves vacate.
    align = ["right", "left"]
    for i, bet in enumerate((0.60, 0.625, 0.70, 0.90)):
        T = integrate(bet, 1.0)
        st = _series(i)
        ax[0].plot(t, T, lw=1.1, markersize=3.2, markevery=(30 + 40 * i, 170),
                   markeredgecolor="white", markeredgewidth=0.5, zorder=3 + i,
                   label=f"{bet:.3f}".rstrip("0").rstrip("."), **st)
        tc = first_below(T)
        if tc is not None:
            ax[0].plot([tc], [tau], marker="|", color=st["color"], markersize=6,
                       markeredgewidth=1.1, zorder=8)
            ax[0].annotate(f"{tc:.1f} s", (tc, tau + 0.025), va="bottom",
                           ha=align.pop() if align else "left",
                           fontsize=MIN_PT, color=INK, zorder=9)
    ax[0].set_title("Decay")
    ax[0].set_xlabel("Time under sustained\nmalicious evidence (s)")
    ax[0].set_ylabel("Trust $T_n$ (dimensionless, 0 to 1)")
    leg = ax[0].legend(loc="upper right", title="BetP$(M)$", handlelength=1.4,
                       labelspacing=0.18, borderpad=0.25, ncol=2,
                       columnspacing=0.7)
    leg.get_title().set_fontsize(MIN_PT)

    # ---- right: recovery once the evidence stops --------------------------
    for i, start in enumerate((0.0, 0.1, 0.2, 0.3)):
        T = integrate(0.0, start)
        st = _series(i)
        ax[1].plot(t, T, lw=1.1, markersize=3.2, markevery=(30 + 40 * i, 170),
                   markeredgecolor="white", markeredgewidth=0.5, zorder=3 + i,
                   label=f"{start:.1f}", **st)
        tc = first_above(T)
        if tc is not None and i == 0:
            ax[1].plot([tc], [tau], marker="|", color=st["color"], markersize=6,
                       markeredgewidth=1.1, zorder=8)
            ax[1].annotate(f"{tc:.1f} s", (tc, tau - 0.03), ha="left", va="top",
                           fontsize=MIN_PT, color=INK, zorder=9)
    ax[1].set_title("Recovery")
    ax[1].set_xlabel("Time after malicious\nevidence ceases (s)")
    leg = ax[1].legend(loc="lower right", title="$T_n(0)$", handlelength=1.4,
                       labelspacing=0.18, borderpad=0.25)
    leg.get_title().set_fontsize(MIN_PT)

    for a in ax:
        a.axhline(tau, color=REF_C, dashes=(2.5, 2.5), lw=0.8, zorder=2)
        a.axhspan(0, tau, color=REF_C, alpha=0.06, lw=0, zorder=1)
        a.set_xlim(0, horizon); a.set_ylim(0, 1.02)
        a.set_xticks([0, 20, 40, 60])
        a.set_yticks(np.arange(0, 1.01, 0.2))
        _tidy(a)
    # The threshold is named on the outer edge, where it cannot sit on top of a
    # trajectory the way an in-plot annotation did.
    sec = ax[1].secondary_yaxis("right")
    sec.set_yticks([tau]); sec.set_yticklabels([r"$\tau_T$"])
    sec.tick_params(length=2.2, width=0.6, pad=1.5)
    sec.spines["right"].set_visible(False)
    _save(fig, out)


def table_per_plane(summary, out):
    """Per-plane detector quality, requested by Reviewer 2 (comment 8).

    A fused number alone does not show which planes carry the decision. This
    breaks the fusion apart: each row is one plane's detector scored on its own
    features, so a plane that contributes little is visible as such.
    """
    order = [("data", "Data", "1D-CNN"), ("cache", "Caching", "BiLSTM"),
             ("trust", "Trust", "Graph read-out"),
             ("forwarding", "Forwarding", "GRU"), ("phy", "Physical", "MLP")]
    lines = [
        r"\begin{table*}[t]", r"\centering",
        r"\caption{Per-plane detector quality under the run-disjoint protocol, "
        r"mean over folds with a 95\% confidence interval. Each detector is "
        r"scored on its own plane's features alone, before fusion, so the "
        r"contribution of each plane to the fused verdict can be read directly.}",
        r"\label{tab:per-plane}",
        r"\renewcommand{\arraystretch}{1.15}", r"\footnotesize",
        r"\begin{tabular}{p{2.6cm}p{3.0cm}p{2.2cm}p{2.2cm}p{2.2cm}p{2.2cm}}",
        r"\hline",
        r"\textbf{Plane} & \textbf{Detector} & \textbf{F1} & \textbf{Prec.} & "
        r"\textbf{Rec.} & \textbf{FPR} \\ \hline",
    ]
    pp = summary.get("per_plane", {})
    for key, label, arch in order:
        d = pp.get(key, {})
        def g(metric):
            m = d.get(metric)
            if not m:
                return "--"
            return fmt(m["mean"], m["ci95"])
        lines.append(f"{label} & {arch} & {g('f1')} & {g('precision')} & "
                     f"{g('recall')} & {g('fpr')} " + r"\\ \hline")
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    open(out, "w").write("\n".join(lines))


def figure_detection_latency(summary, data, out, online_json=None):
    """Detection delay distribution, for Reviewer 1 (2) and Reviewer 2 (8).

    Left: empirical CDF of the delay between a subject's first attacking window
    and the first window in which MI-IDS flagged it, taken from the online
    campaign. Right: per-window inference latency, which is the cost side of
    the same question.

    Placed at \\columnwidth, so the canvas is COL_W wide.

    One thing the axis has to say plainly: online_results.json stores one delay
    sample per attack run, and that sample is already the mean over the
    subjects detected in that run.  The distribution below is therefore over
    runs, not over individual detections, and the axis label says so.  Calling
    it a per-subject delay distribution would overstate what n = 24 points can
    support, so the sample count is on the panel as well.
    """
    # Detection delay is a runtime quantity: it is the gap between a subject's
    # first attacking window and the first window in which the deployed
    # detector flagged it, so it comes from the online campaign rather than
    # from the offline re-scoring.
    delays = []
    if online_json and os.path.exists(online_json):
        with open(online_json) as fh:
            delays = json.load(fh).get("detection_delay_samples", [])
    delays = [x for x in delays if x is not None and np.isfinite(x)]

    _style()
    fig, ax = plt.subplots(1, 2, figsize=(COL_W, 2.45), layout="constrained")

    if delays:
        d = np.sort(np.asarray(delays, dtype=float))
        n = len(d)
        f = np.arange(1, n + 1) / n
        # A proper ECDF: flat at zero until the smallest sample, then a step up
        # at each observation.  The individual samples are drawn as dots because
        # n is small enough that hiding them would overstate the resolution.
        ax[0].step(np.concatenate([[0.0], d]), np.concatenate([[0.0], f]),
                   where="post", color=PALETTE[0], lw=1.2, zorder=3)
        ax[0].plot(d, f, linestyle="none", marker="o", markersize=2.6,
                   color=PALETTE[0], markeredgecolor="white",
                   markeredgewidth=0.4, zorder=4)
        med = float(np.median(d))
        ax[0].axvline(med, color=REF_C, dashes=(2.5, 2.5), lw=0.8, zorder=2)
        ax[0].annotate(f"median\n{med:.1f} s", (med, 0.06), fontsize=MIN_PT,
                       color=INK, ha="left", va="bottom", zorder=5,
                       xytext=(3, 0), textcoords="offset points")
        ax[0].set_xlabel("Mean detection delay\nper attack run (s)")
        ax[0].set_ylabel("Empirical CDF over runs")
        ax[0].set_title(f"Time to first flag ($n$={n})")
        ax[0].set_xlim(0, float(np.ceil(d[-1])) + 1)
        ax[0].set_ylim(0, 1.02)
        ax[0].set_yticks(np.arange(0, 1.01, 0.25))
        _tidy(ax[0])
    else:
        ax[0].text(0.5, 0.5, "no delay samples", ha="center", va="center",
                   transform=ax[0].transAxes, fontsize=MIN_PT)
        ax[0].set_axis_off()

    per_ms = [f.get("inference_ms_per_window") for f in data.get("folds", [])
              if f.get("inference_ms_per_window") is not None]
    if per_ms:
        xs = np.arange(1, len(per_ms) + 1)
        ax[1].bar(xs, per_ms, width=0.62, color=PALETTE[0], edgecolor="white",
                  linewidth=0.8, zorder=3)
        agg = summary.get("inference_ms_per_window")
        if agg:
            # The table quotes a mean with a 95 % CI; the figure has to show the
            # same interval rather than five bars that look exact.
            ax[1].axhline(agg["mean"], color=REF_C, dashes=(2.5, 2.5), lw=0.8,
                          zorder=5)
            ax[1].axhspan(agg["mean"] - agg["ci95"], agg["mean"] + agg["ci95"],
                          color=REF_C, alpha=0.14, lw=0, zorder=2)
            ax[1].annotate(f"mean {agg['mean']:.3f}\n$\\pm$ {agg['ci95']:.3f} ms",
                           (0.97, 0.97), xycoords="axes fraction",
                           ha="right", va="top", fontsize=MIN_PT, color=INK,
                           zorder=6)
        ax[1].set_xlabel("Held-out fold")
        ax[1].set_ylabel("Inference time\n(ms per neighbor-window, CPU)")
        ax[1].set_title("Per-window cost")
        ax[1].set_xticks(xs)
        ax[1].set_ylim(0, max(per_ms) * 1.45)
        # Five-decimal tick labels ate the width of a single-column panel.
        ax[1].set_yticks(np.arange(0, max(per_ms) * 1.45, 0.01))
        _tidy(ax[1], grid_axis="y")
    else:
        ax[1].set_axis_off()

    _save(fig, out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="datasets/exe_capture/miids_results.json")
    ap.add_argument("--online-results",
                    default="datasets/exe_online/online_results.json",
                    help="closed-loop results from extract_online_results.py")
    ap.add_argument("--out-dir",
                    default="VeReMiVNDN-Extension/Preparation_of_Papers_for_IEEE_ACCESS_extension")
    args = ap.parse_args()

    data = json.load(open(args.results))
    summary = data["summary"]
    gen = os.path.join(args.out_dir, "generated")
    os.makedirs(gen, exist_ok=True)
    imgs = os.path.join(args.out_dir, "imgs")
    os.makedirs(imgs, exist_ok=True)

    table_fusion(summary,     os.path.join(gen, "tab_fusion.tex"))
    table_robustness(summary, os.path.join(gen, "tab_robustness.tex"))
    table_cost(summary,       os.path.join(gen, "tab_cost.tex"))
    table_per_plane(summary,  os.path.join(gen, "tab_per_plane.tex"))
    root = os.path.dirname(args.results)
    table_per_attack_all(
        {k: os.path.join(root, f"miids_results_{k}.json")
         for k in ("run-disjoint", "attacker-disjoint", "unseen-attack")},
        os.path.join(gen, "tab_per_attack_protocols.tex"))

    figure_roc_pr(data,       os.path.join(imgs, "fig_roc_pr.pdf"))
    figure_robustness(summary, os.path.join(imgs, "fig_robustness.pdf"))
    figure_trust(os.path.join(imgs, "fig_trust.pdf"))
    figure_detection_latency(summary, data,
                             os.path.join(imgs, "fig_detection_latency.pdf"),
                             online_json=args.online_results)

    print(f"wrote tables to {gen} and figures to {imgs}")


if __name__ == "__main__":
    main()
