"""
train_eval_miids.py - run-disjoint training and evaluation of MI-IDS.

This replaces the earlier training script, which fitted the five plane
detectors on synthetic Gaussian draws and therefore never touched the
simulator output at all. Here every feature comes from
datasets/exe_capture/<CONFIG>_seed<N>/plane_*.csv, which the OMNeT++
FeatureExtractor writes from observed traffic only; the label column is
post-hoc ground truth and is used for supervision and scoring, never as an
input feature.

Evaluation protocol (addresses the reviewers' leakage concern directly):

  * Run-disjoint splits. A "run" is one (scenario, seed) pair. Whole runs go
    to train, validation or test, so no window from a training run can appear
    in the test set. Reported as the headline protocol.
  * Attacker-disjoint splits. The subject identifiers that appear in the test
    set are held out entirely from training, so the detectors cannot memorise
    individual vehicles.
  * Unseen-attack generalisation. Leave-one-attack-family-out: train on seven
    families, test on the eighth.
  * Confidence intervals. Every headline number is reported as mean +/- 95%
    CI over the seeds.

Usage:
    python3 scripts/miids/train_eval_miids.py --capture-root datasets/exe_capture
    python3 scripts/miids/train_eval_miids.py --protocol attacker-disjoint
    python3 scripts/miids/train_eval_miids.py --protocol unseen-attack
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
import resource
import statistics
import sys
import time
from collections import defaultdict

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

# ---------------------------------------------------------------------------
# Feature layout. Must match FeatureExtractor::getPlaneVector and the column
# order written by FeatureExtractor::writePlaneCsvRow.
# ---------------------------------------------------------------------------
PLANE_COLUMNS = {
    "data":       ["d_sigfail", "d_entropy", "d_freshdev", "d_stale",
                   "d_noncecollide", "d_signerent"],
    "cache":      ["c_hitrate", "c_missrate", "c_timinggap", "c_evictrate",
                   "c_proberegularity"],
    "trust":      ["t_corequest", "t_idswitch", "t_posoverlap", "t_reqrate"],
    "forwarding": ["f_dropratio", "f_deltaisr", "f_droppatternent", "f_delayvar"],
    "phy":        ["p_lossfrac", "p_rxshare", "p_rxdeficit", "p_shareunderloss"],
}
PLANES = list(PLANE_COLUMNS)
# Planes whose detector consumes a temporal sequence rather than one window.
SEQ_PLANE = {"data": True, "cache": True, "trust": False,
             "forwarding": True, "phy": False}

ATTACK_OF_CONFIG = {
    "CAP_A1": "Content Poisoning",
    "CAP_A2": "Cache Pollution",
    "CAP_A3": "Cache Privacy Leakage",
    "CAP_A4": "Sybil Amplification",
    "CAP_A5": "Selective Forwarding",
    "CAP_A6": "Radio Jamming",
    "CAP_A7": "Replay Attack",
    "CAP_A8": "ML Evasion",
    "CAP_MultiAttack": "MultiAttack",
    "CAP_Baseline": "Benign",
}


# ---------------------------------------------------------------------------
# Data loading
#
# The campaign produces roughly four million labeled windows. Holding those as
# one Python dict per row costs on the order of ten gigabytes and will not fit
# alongside training; everything is therefore kept in typed numpy arrays, with
# the string columns replaced by integer codes and lookup tables.
# ---------------------------------------------------------------------------
ALL_COLUMNS = [c for cs in PLANE_COLUMNS.values() for c in cs]
COL_INDEX = {c: i for i, c in enumerate(ALL_COLUMNS)}
PLANE_SLICE = {p: [COL_INDEX[c] for c in cs] for p, cs in PLANE_COLUMNS.items()}


class Capture:
    """Column store for the captured windows."""

    def __init__(self, X, y, run, cfg, subj, seed, t, run_names, cfg_names,
                 subj_names):
        self.X, self.y = X, y
        self.run, self.cfg, self.subj, self.seed, self.t = run, cfg, subj, seed, t
        self.run_names, self.cfg_names, self.subj_names = \
            run_names, cfg_names, subj_names

    def __len__(self):
        return len(self.y)


def _capture_files(root: str):
    out = []
    for d in sorted(glob.glob(os.path.join(root, "*"))):
        if not os.path.isdir(d):
            continue
        base = os.path.basename(d)
        if "_seed" not in base:
            continue
        config, seed = base.rsplit("_seed", 1)
        for path in sorted(glob.glob(os.path.join(d, "plane_*.csv"))):
            out.append((base, config, int(seed), path))
    return out


def load_capture(root: str, drop_unlabelled: bool = True) -> Capture:
    """Two-pass load: count rows, preallocate, then fill.

    Accumulating rows in Python lists and converting at the end costs about
    twenty times the size of the final array, which at four million windows is
    the difference between fitting in memory and not.
    """
    files = _capture_files(root)
    if not files:
        sys.exit(f"no capture directories under {root}; "
                 f"run scripts/miids/run_campaign.sh first")

    # ---- pass 1: how many usable rows are there? -----------------------
    total = 0
    usable = []
    for base, config, seed, path in files:
        with open(path, newline="") as fh:
            rdr = csv.reader(fh)
            header = next(rdr, None)
            if not header:
                continue
            pos = {name: i for i, name in enumerate(header)}
            try:
                fcols = [pos[c] for c in ALL_COLUMNS]
                meta = (pos["t"], pos["subject"], pos["label"])
            except KeyError:
                continue        # column set from an older capture
            n = sum(1 for row in rdr
                    if len(row) > meta[2] and
                    (not drop_unlabelled or int(row[meta[2]]) >= 0))
        if n:
            usable.append((base, config, seed, path, fcols, meta))
            total += n

    nf = len(ALL_COLUMNS)
    X = np.empty((total, nf), dtype=np.float32)
    y = np.empty(total, dtype=np.float32)
    run = np.empty(total, dtype=np.int32)
    cfg = np.empty(total, dtype=np.int32)
    subj = np.empty(total, dtype=np.int32)
    seed_a = np.empty(total, dtype=np.int16)
    t_a = np.empty(total, dtype=np.float32)

    run_names, cfg_names, subj_names = [], [], []
    run_code, cfg_code, subj_code = {}, {}, {}

    def code(table, names, key):
        c = table.get(key)
        if c is None:
            c = table[key] = len(names)
            names.append(key)
        return c

    # ---- pass 2: fill ---------------------------------------------------
    i = 0
    for base, config, seed, path, fcols, (i_t, i_sub, i_lab) in usable:
        rc = code(run_code, run_names, base)
        cc = code(cfg_code, cfg_names, config)
        with open(path, newline="") as fh:
            rdr = csv.reader(fh)
            next(rdr, None)
            for row in rdr:
                if len(row) <= i_lab:
                    continue
                lab = int(row[i_lab])
                if lab < 0:
                    if drop_unlabelled:
                        continue
                    lab = 0
                for j, ci in enumerate(fcols):
                    X[i, j] = row[ci]
                y[i] = lab
                run[i] = rc; cfg[i] = cc; seed_a[i] = seed
                subj[i] = code(subj_code, subj_names, row[i_sub])
                t_a[i] = row[i_t]
                i += 1

    if i < total:       # a file changed between passes
        X, y = X[:i], y[:i]
        run, cfg, subj, seed_a, t_a = (run[:i], cfg[:i], subj[:i],
                                       seed_a[:i], t_a[:i])

    return Capture(X, y, run, cfg, subj, seed_a, t_a,
                   run_names, cfg_names, subj_names)


SEQ_LEN = 8      # windows of temporal context for the sequential detectors


def to_arrays(cap: Capture, idx: np.ndarray, plane: str, seq: bool = False):
    """Feature matrix for a plane over the given row indices.

    With seq=False the result is [N, F], one row per window. With seq=True it is
    [N, L, F]: the L most recent windows of the same (run, subject) track,
    zero-padded at the start. Broadcasting one window L times, as an earlier
    version did, cost L times the compute and carried no temporal information.
    """
    cols = PLANE_SLICE[plane]
    X = cap.X[np.ix_(idx, cols)]
    y = cap.y[idx]
    if not seq:
        return X, y

    # Order rows by track, then by time, so history is a contiguous look-back.
    key = cap.run[idx].astype(np.int64) * 1000003 + cap.subj[idx]
    order = np.lexsort((cap.t[idx], key))
    L, F = SEQ_LEN, X.shape[1]
    Xs = np.zeros((len(idx), L, F), dtype=np.float32)

    sorted_key = key[order]
    start = 0
    for end in np.flatnonzero(np.diff(sorted_key)) .tolist() + [len(order) - 1]:
        track = order[start:end + 1]
        for pos in range(len(track)):
            lo = max(0, pos - L + 1)
            hist = track[lo:pos + 1]
            Xs[track[pos], L - len(hist):, :] = X[hist]
        start = end + 1
    return Xs, y


# ---------------------------------------------------------------------------
# Detector architectures (unchanged from the manuscript description)
# ---------------------------------------------------------------------------
class CNN1D(nn.Module):
    def __init__(self, f, seq=16):
        super().__init__()
        self.seq = seq
        self.c1 = nn.Conv1d(f, 32, 5, padding=2)
        self.c2 = nn.Conv1d(32, 64, 5, padding=2)
        self.c3 = nn.Conv1d(64, 64, 3, padding=1)
        self.fc = nn.Linear(64, 1)

    def forward(self, x):
        x = x.transpose(1, 2)                       # [B, F, L]
        x = F.gelu(self.c1(x)); x = F.gelu(self.c2(x)); x = F.gelu(self.c3(x))
        return torch.sigmoid(self.fc(x.mean(dim=2)))


class BiLSTM(nn.Module):
    def __init__(self, f, hidden=96, seq=32):
        super().__init__()
        self.seq = seq
        self.lstm = nn.LSTM(f, hidden, num_layers=2, dropout=0.2,
                            bidirectional=True, batch_first=True)
        self.fc = nn.Linear(hidden * 2, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return torch.sigmoid(self.fc(out[:, -1, :]))


class GraphMLP(nn.Module):
    """Window-aggregated graph statistics; stands in for the GAT read-out."""
    def __init__(self, f):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(f, 32), nn.GELU(),
                                 nn.Linear(32, 16), nn.GELU(),
                                 nn.Linear(16, 1), nn.Sigmoid())

    def forward(self, x):
        return self.net(x)


class GRUDet(nn.Module):
    def __init__(self, f, hidden=64, seq=24):
        super().__init__()
        self.seq = seq
        self.gru = nn.GRU(f, hidden, num_layers=2, dropout=0.1, batch_first=True)
        self.fc = nn.Linear(hidden, 1)

    def forward(self, x):
        out, _ = self.gru(x)
        return torch.sigmoid(self.fc(out[:, -1, :]))


class PhyMLP(nn.Module):
    def __init__(self, f):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(f, 64), nn.GELU(),
                                 nn.Linear(64, 32), nn.GELU(),
                                 nn.Linear(32, 1), nn.Sigmoid())

    def forward(self, x):
        return self.net(x)


def build(plane, f):
    return {"data": CNN1D, "cache": BiLSTM, "trust": GraphMLP,
            "forwarding": GRUDet, "phy": PhyMLP}[plane](f)


# ---------------------------------------------------------------------------
# Adversarial attacks used for the robustness evaluation
# ---------------------------------------------------------------------------
def fgsm(model, x, y, eps):
    x = x.clone().detach().requires_grad_(True)
    loss = F.binary_cross_entropy(model(x).squeeze(1), y)
    g = torch.autograd.grad(loss, x)[0]
    return torch.clamp(x + eps * g.sign(), 0.0, 1.0).detach()


def pgd(model, x, y, eps, steps=10):
    x0 = x.clone().detach()
    xa = x0.clone()
    alpha = 2.5 * eps / steps
    for _ in range(steps):
        xa.requires_grad_(True)
        loss = F.binary_cross_entropy(model(xa).squeeze(1), y)
        g = torch.autograd.grad(loss, xa)[0]
        xa = xa.detach() + alpha * g.sign()
        xa = torch.min(torch.max(xa, x0 - eps), x0 + eps).clamp(0.0, 1.0)
    return xa.detach()


def carlini_wagner(model, x, y, eps, steps=30, lr=0.02, c=1.0):
    """L2 Carlini-Wagner style attack, projected into the same eps ball so the
    perturbation budget is comparable with FGSM and PGD."""
    x0 = x.clone().detach()
    w = torch.zeros_like(x0, requires_grad=True)
    opt = torch.optim.Adam([w], lr=lr)
    for _ in range(steps):
        xa = torch.clamp(x0 + w, 0.0, 1.0)
        p = model(xa).squeeze(1)
        # Push the prediction towards the wrong class, penalised by L2 size.
        f_loss = torch.where(y > 0.5, p, 1.0 - p)
        l2 = w.pow(2).flatten(1).sum(dim=1)
        loss = (l2 + c * f_loss).mean()
        opt.zero_grad(); loss.backward(); opt.step()
    xa = torch.clamp(x0 + w.detach(), 0.0, 1.0)
    return torch.min(torch.max(xa, x0 - eps), x0 + eps).detach()


def boundary_noise(model, x, y, eps):
    """Decision-based baseline: uniform noise in the eps ball, no gradients."""
    n = (torch.rand_like(x) * 2 - 1) * eps
    return torch.clamp(x + n, 0.0, 1.0).detach()


ATTACKS = {"FGSM": fgsm, "PGD": pgd, "CW": carlini_wagner, "Uniform": boundary_noise}


# ---------------------------------------------------------------------------
# Dempster-Shafer fusion
# ---------------------------------------------------------------------------
def predict_batched(model, X, bs=8192, device="cpu"):
    """Forward a whole array through a detector in slices.

    Running the full test split in one call materialises every intermediate
    activation at once. For the convolutional and recurrent planes that reached
    17 GB on an 800k-row split and got the process OOM-killed, which is not a
    limit of the method but of how the evaluation was written.
    """
    out = np.empty(len(X), dtype=np.float32)
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.tensor(X[i:i + bs], device=device)
            out[i:i + bs] = model(xb).squeeze(1).cpu().numpy()
    return out


def dst_fuse(probs, betas):
    """probs: [N, K] calibrated malicious probabilities. Returns BetP(M), K."""
    n, k = probs.shape
    m_mal = probs * betas
    m_ben = (1.0 - probs) * betas
    m_th = 1.0 - betas

    acc_m = m_mal[:, 0].copy(); acc_b = m_ben[:, 0].copy(); acc_t = np.full(n, m_th[0])
    conflict = np.zeros(n)
    for i in range(1, k):
        bm, bb, bt = m_mal[:, i], m_ben[:, i], np.full(n, m_th[i])
        mm = acc_m * bm + acc_m * bt + acc_t * bm
        bbv = acc_b * bb + acc_b * bt + acc_t * bb
        tt = acc_t * bt
        kk = acc_m * bb + acc_b * bm
        den = np.maximum(1e-9, 1.0 - kk)
        acc_m, acc_b, acc_t = mm / den, bbv / den, tt / den
        conflict = conflict + kk
    # Mean per-combination conflict. The cumulative form 1 - prod(1 - k_i)
    # compounds toward 1 by construction, so five sources that are merely
    # uninformative already exceed any useful ceiling; with kmax=0.85 it
    # rejected 99.99% of windows. The mean stays near 0.45 for uninformative
    # agreement and approaches 1 only on genuine contradiction between planes.
    return acc_m + 0.5 * acc_t, conflict / max(1, k - 1)


def metrics(y, pred):
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / max(1, tp + tn + fp + fn)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=prec, recall=rec,
                f1=f1, accuracy=acc, fpr=fpr)


def roc_pr(y, score, n=200):
    """Return (fpr, tpr, auroc) and (recall, precision, auprc)."""
    order = np.argsort(-score)
    ys = y[order]
    P = max(1, int(ys.sum())); N = max(1, len(ys) - int(ys.sum()))
    tp = np.cumsum(ys); fp = np.cumsum(1 - ys)
    tpr = tp / P; fpr = fp / N
    prec = tp / np.maximum(1, tp + fp); rec = tpr
    auroc = float(np.trapezoid(tpr, fpr))
    # Average precision, computed as the recall-weighted sum of precisions.
    # Integrating the PR curve with trapezoid over a reversed axis produced a
    # negative area, which is not a meaningful quantity.
    drec = np.diff(np.concatenate(([0.0], rec)))
    auprc = float(np.sum(prec * drec))
    idx = np.linspace(0, len(ys) - 1, min(n, len(ys))).astype(int)
    return (fpr[idx], tpr[idx], auroc), (rec[idx], prec[idx], auprc)


def ci95(vals):
    vals = [v for v in vals if v == v]
    if len(vals) < 2:
        return (statistics.mean(vals) if vals else 0.0), 0.0
    m = statistics.mean(vals)
    return m, 1.96 * statistics.stdev(vals) / math.sqrt(len(vals))


# ---------------------------------------------------------------------------
# Deployment export
# ---------------------------------------------------------------------------
class Calibrated(nn.Module):
    """Base detector plus the temperature fitted on the validation split.

    The offline pipeline calibrates every plane before fusing, so an exported
    checkpoint that skips the step would put the runtime on a different
    operating point than the one the paper reports. Folding the temperature
    into the traced graph keeps the two identical without the C++ side having
    to parse any side-car metadata.
    """

    def __init__(self, base, temperature):
        super().__init__()
        self.base = base
        self.register_buffer("T", torch.tensor(float(temperature)))

    def forward(self, x):
        p = self.base(x).clamp(1e-6, 1 - 1e-6)
        return torch.sigmoid(torch.log(p / (1 - p)) / self.T)


def export_models(cap, args, device, outdir):
    """Train one detector per plane on the whole capture and serialize it.

    The runtime MI-IDS module loads these TorchScript files, so the detector
    that runs inside the simulator is the same architecture, trained the same
    way, as the one measured offline. Without this step the module silently
    falls back to an untrained logistic and reports no detections at all.

    The C++ FeatureExtractor already emits features on a bounded scale, so no
    scaler has to be carried across the boundary; the only side-channel is the
    temperature and the per-plane reliability weight, written to meta.json.
    """
    os.makedirs(outdir, exist_ok=True)
    rng = np.random.default_rng(0)
    idx = np.arange(len(cap))
    idx = subsample_tracks(cap, idx, args.max_train_rows, rng)
    rng.shuffle(idx)
    cut = int(0.85 * len(idx))
    tr, va = idx[:cut], idx[cut:]
    meta = {"seq_len": SEQ_LEN, "planes": {}}

    for plane in PLANES:
        sq = SEQ_PLANE[plane]
        Xtr, ytr = to_arrays(cap, tr, plane, sq)
        Xva, yva = to_arrays(cap, va, plane, sq)
        model, T = train_plane(plane, Xtr, ytr, Xva, yva,
                               args.epochs, args.adv_eps, device)
        model.eval().cpu()
        model = Calibrated(model, T).eval()

        # Trace with the exact shape the runtime feeds: [1, L, F] for the
        # sequential planes and [1, F] for the rest.
        F_ = Xtr.shape[-1]
        example = (torch.zeros(1, SEQ_LEN, F_) if sq else torch.zeros(1, F_))
        with torch.no_grad():
            ts = torch.jit.trace(model, example)
            ts = torch.jit.freeze(ts)
            probe = float(ts(example).flatten()[0])
        path = os.path.join(outdir, f"{plane}.pt")
        ts.save(path)
        meta["planes"][plane] = {
            "features": F_, "sequence": bool(sq), "temperature": float(T),
            "reliability": float(getattr(args, "beta_" + plane.replace("-", "_"))),
            "zero_input_output": probe,
        }
        print(f"  exported {path}  F={F_} seq={sq} T={T:.3f} "
              f"p(0)={probe:.4f}")

    with open(os.path.join(outdir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"wrote {outdir}/meta.json")


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_plane(plane, Xtr, ytr, Xva, yva, epochs, adv_eps, device):
    model = build(plane, Xtr.shape[-1]).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    Xtr_t = torch.tensor(Xtr, device=device); ytr_t = torch.tensor(ytr, device=device)

    # Class weighting: attackers are a minority of the observed subjects.
    pos = float(ytr.sum()); neg = float(len(ytr) - pos)
    pw = (neg / pos) if pos > 0 else 1.0

    n = len(ytr_t); bs = 512
    for ep in range(epochs):
        perm = torch.randperm(n, device=device)
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            xb, yb = Xtr_t[idx], ytr_t[idx]
            # FGSM warm-start for the first epochs, PGD inner max afterwards.
            if adv_eps > 0 and ep >= 3:
                model.eval()
                xb = (fgsm(model, xb, yb, adv_eps) if ep < 8
                      else pgd(model, xb, yb, adv_eps, steps=5))
                model.train()
            opt.zero_grad()
            p = model(xb).squeeze(1).clamp(1e-6, 1 - 1e-6)
            w = torch.where(yb > 0.5, torch.full_like(yb, pw), torch.ones_like(yb))
            loss = (F.binary_cross_entropy(p, yb, reduction="none") * w).mean()
            loss.backward(); opt.step()

    # Temperature scaling on the held-out validation split.
    model.eval()
    pv = predict_batched(model, Xva, device=device)
    T = fit_temperature(pv, yva)
    return model, T


def fit_temperature(p, y):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    logit = np.log(p / (1 - p))
    best, bestT = 1e9, 1.0
    for T in np.linspace(0.25, 4.0, 60):
        q = 1.0 / (1.0 + np.exp(-logit / T))
        nll = -np.mean(y * np.log(np.clip(q, 1e-9, 1)) +
                       (1 - y) * np.log(np.clip(1 - q, 1e-9, 1)))
        if nll < best:
            best, bestT = nll, T
    return float(bestT)


def apply_T(p, T):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return 1.0 / (1.0 + np.exp(-np.log(p / (1 - p)) / T))


# ---------------------------------------------------------------------------
# Split construction. All splits return index arrays into the column store, so
# nothing is copied until a plane's features are actually needed.
# ---------------------------------------------------------------------------
def split_indices(cap: Capture, protocol: str, holdout):
    n = len(cap)
    if protocol == "run-disjoint":
        test_mask = cap.seed == holdout
    elif protocol == "attacker-disjoint":
        subs = np.unique(cap.subj)
        held = set(subs[holdout % 5::5].tolist())
        test_mask = np.fromiter((s in held for s in cap.subj), bool, n)
    elif protocol == "unseen-attack":
        cfg_i = cap.cfg_names.index(holdout)
        multi = (cap.cfg_names.index("CAP_MultiAttack")
                 if "CAP_MultiAttack" in cap.cfg_names else -1)
        test_mask = cap.cfg == cfg_i
        train_mask = (cap.cfg != cfg_i) & (cap.cfg != multi)
        tr_all = np.flatnonzero(train_mask)
        te = np.flatnonzero(test_mask)
        return _carve_validation(cap, tr_all, te)
    else:
        sys.exit(f"unknown protocol {protocol}")

    te = np.flatnonzero(test_mask)
    tr_all = np.flatnonzero(~test_mask)
    return _carve_validation(cap, tr_all, te)


def _carve_validation(cap: Capture, tr_all: np.ndarray, te: np.ndarray):
    """Hold out whole runs for validation, never individual rows."""
    runs = np.unique(cap.run[tr_all])
    val_runs = set(runs[::4].tolist())
    is_val = np.fromiter((r in val_runs for r in cap.run[tr_all]), bool,
                         len(tr_all))
    return tr_all[~is_val], tr_all[is_val], te


def subsample_tracks(cap: Capture, idx: np.ndarray, cap_rows: int, rng):
    """Cap the training set by dropping whole tracks.

    Sampling whole (run, subject) tracks rather than individual windows keeps
    the temporal context each sequence needs and preserves run-disjointness.
    """
    if not cap_rows or len(idx) <= cap_rows:
        return idx
    key = cap.run[idx].astype(np.int64) * 1000003 + cap.subj[idx]
    uniq = np.unique(key)
    rng.shuffle(uniq)
    keep, total = set(), 0
    counts = dict(zip(*np.unique(key, return_counts=True)))
    for k in uniq.tolist():
        if total >= cap_rows:
            break
        keep.add(k); total += int(counts[k])
    sel = np.fromiter((k in keep for k in key), bool, len(idx))
    return idx[sel]


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------
def evaluate(cap: Capture, args, device):
    betas = np.array([args.beta_data, args.beta_cache, args.beta_trust,
                      args.beta_forwarding, args.beta_phy], dtype=np.float64)
    rng = np.random.default_rng(0)

    if args.protocol == "run-disjoint":
        holdouts = sorted(set(cap.seed.tolist()))
    elif args.protocol == "unseen-attack":
        holdouts = [c for c in sorted(cap.cfg_names) if c.startswith("CAP_A")]
    else:
        holdouts = list(range(5))

    folds = []
    for ho in holdouts:
        tr, va, te = split_indices(cap, args.protocol, ho)
        if len(tr) == 0 or len(te) == 0 or cap.y[te].sum() == 0:
            print(f"  [skip] holdout={ho}: empty or attacker-free test split")
            continue

        n_before = len(tr)
        tr = subsample_tracks(cap, tr, args.max_train_rows, rng)
        if len(tr) < n_before:
            print(f"  [subsample] training rows {n_before:,} -> {len(tr):,}")
        if len(va) == 0:
            va = tr

        models, temps, probs_te, Xte_all = {}, {}, {}, {}
        t_train0 = time.time()
        for plane in PLANES:
            sq = SEQ_PLANE[plane]
            Xtr, ytr = to_arrays(cap, tr, plane, sq)
            Xva, yva = to_arrays(cap, va, plane, sq)
            m, T = train_plane(plane, Xtr, ytr, Xva, yva, args.epochs,
                               args.adv_eps, device)
            models[plane], temps[plane] = m, T
            del Xtr, Xva
        train_s = time.time() - t_train0

        yte = cap.y[te]
        for plane in PLANES:
            Xte, _ = to_arrays(cap, te, plane, SEQ_PLANE[plane])
            Xte_all[plane] = Xte
            p = predict_batched(models[plane], Xte, device=device)
            probs_te[plane] = apply_T(p, temps[plane])

        P = np.stack([probs_te[p] for p in PLANES], axis=1)

        # --- inference cost, measured on the test split --------------------
        n_params = sum(sum(q.numel() for q in models[p].parameters())
                       for p in PLANES)
        probe = min(1000, len(yte))
        t0 = time.time()
        with torch.no_grad():
            for plane in PLANES:
                models[plane](torch.tensor(Xte_all[plane][:probe]))
        infer_ms = (time.time() - t0) * 1000.0 / max(1, probe)
        model_mb = n_params * 4.0 / (1024.0 * 1024.0)
        rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

        # --- fusion strategies ---------------------------------------------
        betp, conflict = dst_fuse(P, betas)
        # Reject option, identical to the runtime rule in MIIDSModule: decline
        # when the planes contradict each other, and when the fused evidence
        # sits too close to the threshold to separate the hypotheses.
        decided = (conflict < args.kmax) & (np.abs(betp - args.tau) >= args.margin)
        dst_pred = (betp > args.tau).astype(int)
        lin = (P * betas).sum(1) / betas.sum()
        maj = (P > 0.5).sum(1) / len(PLANES)

        # Max-plane rule: flag when any single plane is confident. This shares
        # MI-IDS's trained detectors and only replaces the combination rule, so
        # it is an ablation of the fusion stage, not an external baseline.
        maxrule = P.max(1)

        # Threshold IDS, in the spirit of the detector published with the
        # original benchmark: a linear combination of per-plane anomaly scores
        # compared against a fixed threshold, with no learned detector at all.
        # The anomaly score of a plane is the mean activation of its features,
        # which is the analogue of the per-attack score used there. The
        # threshold is selected on the training split, never on the test split.
        def plane_anomaly(idx):
            cols = [PLANE_SLICE[pl] for pl in PLANES]
            return np.stack([cap.X[np.ix_(idx, c)].mean(axis=1) for c in cols], 1)

        thr_tr = plane_anomaly(tr).mean(axis=1)
        thr_te = plane_anomaly(te).mean(axis=1)
        best_t, best_f1 = 0.5, -1.0
        for cand in np.quantile(thr_tr, np.linspace(0.05, 0.95, 37)):
            m = metrics(cap.y[tr], (thr_tr > cand).astype(int))
            if m["f1"] > best_f1:
                best_f1, best_t = m["f1"], float(cand)
        thr = thr_te
        thr_cut = best_t

        fold = {
            "holdout": str(ho),
            "n_test": int(len(yte)),
            "n_attacker_rows": int(yte.sum()),
            "n_train": int(len(tr)),
            "abstentions": int((~decided).sum()),
            "abstention_rate": float((~decided).mean()),
            "train_seconds": train_s,
            "params": int(n_params),
            "inference_ms_per_window": infer_ms,
            "model_mb": model_mb,
            "peak_rss_mb": rss_mb,
            "fusion": {
                "MI-IDS (DST)": metrics(yte, dst_pred),
                "MI-IDS (DST, abstaining)": metrics(yte[decided],
                                                    dst_pred[decided]),
                "Single-vector (linear)": metrics(yte, (lin > args.tau).astype(int)),
                "Majority vote": metrics(yte, (maj > 0.5).astype(int)),
                "Max-plane rule": metrics(yte, (maxrule > 0.7).astype(int)),
                "Threshold IDS": metrics(yte, (thr > thr_cut).astype(int)),
            },
            "per_plane": {p: metrics(yte, (probs_te[p] > 0.5).astype(int))
                          for p in PLANES},
        }
        (fpr, tpr, auroc), (rec, prec, auprc) = roc_pr(yte, betp)
        fold["auroc"], fold["auprc"] = auroc, auprc
        fold["roc"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
        fold["pr"] = {"recall": rec.tolist(), "precision": prec.tolist()}

        # --- per-attack breakdown ------------------------------------------
        fold["per_attack"] = {}
        for ci, cname in enumerate(cap.cfg_names):
            sel = np.flatnonzero(cap.cfg[te] == ci)
            if len(sel) == 0:
                continue
            fold["per_attack"][ATTACK_OF_CONFIG.get(cname, cname)] = metrics(
                yte[sel], dst_pred[sel])

        # --- adversarial robustness ----------------------------------------
        rob_n = min(len(yte), args.robust_sample) if args.robust_sample else len(yte)
        rob_idx = (np.random.default_rng(1).choice(len(yte), rob_n, replace=False)
                   if rob_n < len(yte) else np.arange(len(yte)))
        y_rob = yte[rob_idx]
        fold["robustness_sample"] = int(rob_n)
        fold["robustness"] = {}
        for aname, afn in ATTACKS.items():
            for eps in args.eps_sweep:
                padv = []
                for plane in PLANES:
                    xb = torch.tensor(Xte_all[plane][rob_idx])
                    yb = torch.tensor(y_rob)
                    xa = afn(models[plane], xb, yb, eps)
                    with torch.no_grad():
                        pa = models[plane](xa).squeeze(1).cpu().numpy()
                    padv.append(apply_T(pa, temps[plane]))
                Pa = np.stack(padv, axis=1)
                ba, _ = dst_fuse(Pa, betas)
                fold["robustness"].setdefault(aname, {})[f"{eps:.2f}"] = \
                    metrics(y_rob, (ba > args.tau).astype(int))

        del Xte_all
        folds.append(fold)
        m = fold["fusion"]["MI-IDS (DST)"]
        print(f"  holdout={ho}: train={len(tr):,} test={len(yte):,} "
              f"atk={int(yte.sum()):,} F1={m['f1']:.3f} P={m['precision']:.3f} "
              f"R={m['recall']:.3f} FPR={m['fpr']:.3f} AUROC={auroc:.3f}")
    return folds


def summarise(folds):
    out = {"n_folds": len(folds)}
    if not folds:
        return out
    for strategy in folds[0]["fusion"]:
        for metric in ("f1", "precision", "recall", "accuracy", "fpr"):
            m, h = ci95([f["fusion"][strategy][metric] for f in folds])
            out.setdefault(strategy, {})[metric] = {"mean": m, "ci95": h}
    for key in ("auroc", "auprc", "inference_ms_per_window", "model_mb",
                "peak_rss_mb", "train_seconds", "abstention_rate"):
        m, h = ci95([f[key] for f in folds])
        out[key] = {"mean": m, "ci95": h}
    out["params"] = folds[0]["params"]

    per_attack = defaultdict(list)
    for f in folds:
        for atk, mm in f["per_attack"].items():
            per_attack[atk].append(mm["f1"])
    out["per_attack_f1"] = {a: dict(zip(("mean", "ci95"), ci95(v)))
                            for a, v in per_attack.items()}

    # Per-plane quality, aggregated the same way as the fused numbers. The
    # reviewers asked which planes actually carry the decision, and that cannot
    # be read off a fused F1.
    per_plane = defaultdict(lambda: defaultdict(list))
    for f in folds:
        for plane, mm in f.get("per_plane", {}).items():
            for metric in ("f1", "precision", "recall", "fpr"):
                per_plane[plane][metric].append(mm[metric])
    out["per_plane"] = {
        pl: {mt: dict(zip(("mean", "ci95"), ci95(v))) for mt, v in d.items()}
        for pl, d in per_plane.items()
    }

    rob = defaultdict(lambda: defaultdict(list))
    for f in folds:
        for a, sweep in f["robustness"].items():
            for eps, mm in sweep.items():
                rob[a][eps].append(mm["f1"])
    out["robustness_f1"] = {a: {e: dict(zip(("mean", "ci95"), ci95(v)))
                                for e, v in sweep.items()}
                            for a, sweep in rob.items()}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture-root", default="datasets/exe_capture")
    ap.add_argument("--protocol", default="run-disjoint",
                    choices=["run-disjoint", "attacker-disjoint", "unseen-attack"])
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--adv-eps", type=float, default=0.03)
    ap.add_argument("--tau", type=float, default=0.55)
    ap.add_argument("--kmax", type=float, default=0.85)
    ap.add_argument("--margin", type=float, default=0.02,
                    help="reject option: abstain when |BetP - tau| is below this")
    ap.add_argument("--beta-data", type=float, default=0.92)
    ap.add_argument("--beta-cache", type=float, default=0.88)
    ap.add_argument("--beta-trust", type=float, default=0.86)
    ap.add_argument("--beta-forwarding", type=float, default=0.90)
    ap.add_argument("--beta-phy", type=float, default=0.94)
    ap.add_argument("--eps-sweep", type=float, nargs="*",
                    default=[0.0, 0.01, 0.03, 0.05, 0.10])
    ap.add_argument("--out", default="datasets/exe_capture/miids_results.json")
    ap.add_argument("--robust-sample", type=int, default=20000,
                    help="test windows used for the adversarial sweep (0 = all)")
    ap.add_argument("--max-train-rows", type=int, default=250000,
                    help="cap on training windows per fold (0 = no cap)")
    ap.add_argument("--keep-unlabelled", action="store_true")
    ap.add_argument("--export-models", metavar="DIR",
                    help="train one detector per plane on the full capture, "
                         "serialize to TorchScript for the runtime, and exit")
    args = ap.parse_args()

    torch.manual_seed(0); np.random.seed(0)
    device = "cpu"     # per-window inference cost is reported for a CPU OBU

    cap = load_capture(args.capture_root,
                       drop_unlabelled=not args.keep_unlabelled)
    print(f"loaded {len(cap):,} labeled windows from {len(cap.run_names)} runs "
          f"({int(cap.y.sum()):,} attacker windows, "
          f"{len(cap.subj_names):,} distinct subjects)")
    print(f"protocol: {args.protocol}")

    if args.export_models:
        print(f"exporting deployment detectors to {args.export_models}")
        export_models(cap, args, device, args.export_models)
        return

    folds = evaluate(cap, args, device)
    summary = summarise(folds)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"args": vars(args), "folds": folds, "summary": summary}, fh, indent=2)
    print(f"\nwrote {args.out}")

    if summary.get("n_folds"):
        print("\n=== summary (mean +/- 95% CI over folds) ===")
        for strat in ("MI-IDS (DST)", "MI-IDS (DST, abstaining)", "Majority vote",
                      "Single-vector (linear)", "Max-plane rule",
                      "Threshold IDS"):
            if strat not in summary:
                continue
            s = summary[strat]
            print(f"{strat:26s} F1={s['f1']['mean']:.3f}+/-{s['f1']['ci95']:.3f}  "
                  f"P={s['precision']['mean']:.3f}  R={s['recall']['mean']:.3f}  "
                  f"FPR={s['fpr']['mean']:.3f}")
        print(f"AUROC={summary['auroc']['mean']:.3f}+/-{summary['auroc']['ci95']:.3f}  "
              f"AUPRC={summary['auprc']['mean']:.3f}")
        print(f"inference={summary['inference_ms_per_window']['mean']:.4f} ms/window, "
              f"params={summary['params']:,}, "
              f"detector footprint={summary['model_mb']['mean']:.2f} MB")


if __name__ == "__main__":
    main()
