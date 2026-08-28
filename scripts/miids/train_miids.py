"""
Train and export the five plane-specific MI-IDS detectors as TorchScript
files consumable by MIIDSModule via LibTorch.

Outputs (under models/miids/):
    detector_data.pt         (1D-CNN, 6 features, Content Poisoning)
    detector_cache.pt        (BiLSTM, 5 features, Cache Pollution + Privacy)
    detector_trust.pt        (MLP over graph stats, 4 features, Sybil)
    detector_forwarding.pt   (GRU, 4 features, Selective Forwarding)
    detector_phy.pt          (MLP, 4 features, Radio Jamming)

Each detector takes a 1D feature vector of plane-specific size and returns
a single scalar log-probability of malicious. Inference contract used by
the C++ MIIDSModule:

    inputs:  torch::Tensor of shape [1, F_k] (float32)
    outputs: torch::Tensor of shape [1, 1]   (float32, sigmoid output)

This synthetic training run generates plausible benign vs. malicious
distributions per plane and fits each detector for 30 epochs. The aim is
not to ship deployment-grade weights, but to provide *valid* TorchScript
artefacts so that the MI-IDS runtime path can be exercised end-to-end. Real
deployment reuses the same architecture but replaces the synthetic data
with the .csv stream produced by FeatureExtractor over the 270 EXE runs.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset


# -------------------------------------------------------------------------
# Per-plane feature dimensions (must match FeatureExtractor.ned)
# -------------------------------------------------------------------------
PLANE_DIMS = {
    "data":        6,   # sig.\ failure rate, payload entropy, freshness dev., trust drop, signer entropy, name entropy
    "cache":       5,   # T_hit, T_miss, dT, eviction rate, probe IAT
    "trust":       4,   # co-request cluster size, identity-switch rate, position overlap, GAT score
    "forwarding":  4,   # per-flow drop ratio, dISR, drop-pattern entropy, delay variance
    "phy":         4,   # SINR, CCA busy, PER, RSSI variance
}

PLANE_SEQLEN = {
    "data":       16,
    "cache":      32,
    "trust":      1,    # graph stats are window-aggregated, not sequential
    "forwarding": 24,
    "phy":        1,    # SINR/CCA/PER/RSSI rolled up into one window vector
}


# -------------------------------------------------------------------------
# Detector architectures
# -------------------------------------------------------------------------
class CNN1D(nn.Module):
    """1D-CNN over a sliding window of per-tick feature vectors."""

    def __init__(self, in_features: int, seq_len: int):
        super().__init__()
        self.conv1 = nn.Conv1d(in_features, 32, kernel_size=5, padding=2)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(64, 64, kernel_size=3, padding=1)
        self.fc    = nn.Linear(64, 1)

    def forward(self, x):
        # x: [B, seq_len, F] for the training path; [B, F] flat at inference.
        if x.dim() == 2:
            # Inference shortcut: pretend a length-1 sequence and broadcast.
            x = x.unsqueeze(1).expand(-1, PLANE_SEQLEN["data"], -1)
        x = x.transpose(1, 2)            # [B, F, seq_len]
        x = F.gelu(self.conv1(x))
        x = F.gelu(self.conv2(x))
        x = F.gelu(self.conv3(x))
        x = x.mean(dim=2)                # global average pool
        return torch.sigmoid(self.fc(x))


class BiLSTM(nn.Module):
    def __init__(self, in_features: int, hidden: int = 96):
        super().__init__()
        self.lstm = nn.LSTM(in_features, hidden, num_layers=2,
                            dropout=0.2, bidirectional=True, batch_first=True)
        self.fc   = nn.Linear(hidden * 2, 1)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1).expand(-1, PLANE_SEQLEN["cache"], -1)
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        return torch.sigmoid(self.fc(out))


class GraphMLP(nn.Module):
    """Lightweight stand-in for GAT: takes window-aggregated graph stats."""

    def __init__(self, in_features: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_features, 32), nn.GELU(),
            nn.Linear(32, 16), nn.GELU(),
            nn.Linear(16, 1), nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


class GRUDetector(nn.Module):
    def __init__(self, in_features: int, hidden: int = 64):
        super().__init__()
        self.gru = nn.GRU(in_features, hidden, num_layers=2,
                          dropout=0.1, batch_first=True)
        self.fc  = nn.Linear(hidden, 1)

    def forward(self, x):
        if x.dim() == 2:
            x = x.unsqueeze(1).expand(-1, PLANE_SEQLEN["forwarding"], -1)
        out, _ = self.gru(x)
        return torch.sigmoid(self.fc(out[:, -1, :]))


class PhyMLP(nn.Module):
    def __init__(self, in_features: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_features, 64), nn.GELU(),
            nn.Linear(64, 32), nn.GELU(),
            nn.Linear(32, 1), nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


# -------------------------------------------------------------------------
# Synthetic data generators (replace with FeatureExtractor CSV ingest)
# -------------------------------------------------------------------------
def synth_data(plane: str, n: int, seed: int = 0):
    """Generate (X_benign, X_malicious) tensors for a plane.

    The malicious distribution is shifted/scaled in a plane-specific way so
    that a small detector can learn the boundary in one or two epochs. This
    keeps the total training time below a minute while producing valid
    TorchScript artefacts. When real CSVs are available, swap this routine
    for a pandas read + windowing step.
    """
    g = torch.Generator().manual_seed(seed)
    F = PLANE_DIMS[plane]
    L = PLANE_SEQLEN[plane]

    # Benign: standard normal around plane-typical operating point.
    if L > 1:
        Xb = torch.randn(n, L, F, generator=g) * 0.3
    else:
        Xb = torch.randn(n, F, generator=g) * 0.3

    # Malicious: per-plane signature.
    if plane == "data":
        # surge in sig.\ failure rate (feat 0) and payload entropy (feat 1)
        Xm = torch.randn(n, L, F, generator=g) * 0.3
        Xm[..., 0] += 1.6
        Xm[..., 1] += 1.0
    elif plane == "cache":
        # widen T_miss - T_hit gap (feat 2) and increase eviction rate (feat 3)
        Xm = torch.randn(n, L, F, generator=g) * 0.3
        Xm[..., 2] += 1.4
        Xm[..., 3] += 1.1
    elif plane == "trust":
        # large co-request cluster (feat 0) and identity-switch rate (feat 1)
        Xm = torch.randn(n, F, generator=g) * 0.3
        Xm[..., 0] += 1.8
        Xm[..., 1] += 1.2
    elif plane == "forwarding":
        # high per-flow drop ratio (feat 0) and dISR (feat 1)
        Xm = torch.randn(n, L, F, generator=g) * 0.3
        Xm[..., 0] += 1.5
        Xm[..., 1] += 1.3
    elif plane == "phy":
        # SINR drop (feat 0 negative shift) and CCA busy spike (feat 1)
        Xm = torch.randn(n, F, generator=g) * 0.3
        Xm[..., 0] -= 1.4
        Xm[..., 1] += 1.6
    else:
        raise ValueError(plane)

    return Xb, Xm


def make_loader(plane: str, n_per_class: int, batch: int = 128):
    Xb, Xm = synth_data(plane, n_per_class)
    yb = torch.zeros(n_per_class, 1)
    ym = torch.ones(n_per_class, 1)
    X = torch.cat([Xb, Xm])
    y = torch.cat([yb, ym])
    perm = torch.randperm(X.size(0))
    return DataLoader(TensorDataset(X[perm], y[perm]),
                      batch_size=batch, shuffle=True)


def build_detector(plane: str):
    F = PLANE_DIMS[plane]
    if plane == "data":        return CNN1D(F, PLANE_SEQLEN["data"])
    if plane == "cache":       return BiLSTM(F)
    if plane == "trust":       return GraphMLP(F)
    if plane == "forwarding":  return GRUDetector(F)
    if plane == "phy":         return PhyMLP(F)
    raise ValueError(plane)


# -------------------------------------------------------------------------
# Adversarial training (FGSM warm-up + PGD inner max)
# -------------------------------------------------------------------------
def pgd_attack(model, x, y, eps: float, steps: int = 5, alpha: float | None = None):
    if alpha is None:
        alpha = eps / 4.0
    x_adv = x.clone().detach().requires_grad_(True)
    for _ in range(steps):
        out = model(x_adv)
        loss = F.binary_cross_entropy(out, y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv.detach() + alpha * grad.sign()
        x_adv = torch.clamp(x_adv, x - eps, x + eps)
        x_adv.requires_grad_(True)
    return x_adv.detach()


def train_one(plane: str, epochs: int, eps: float, out_dir: str):
    print(f"\n=== training plane={plane} ===")
    model = build_detector(plane)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    loader = make_loader(plane, n_per_class=4000)

    for ep in range(epochs):
        loss_sum = 0.0
        correct = 0
        total = 0
        for xb, yb in loader:
            opt.zero_grad()
            # 25% of batches use PGD-perturbed inputs
            if eps > 0 and (ep > 5) and (random.random() < 0.25):
                model.eval()
                x_adv = pgd_attack(model, xb, yb, eps=eps, steps=5)
                model.train()
                out = model(x_adv)
            else:
                out = model(xb)
            loss = F.binary_cross_entropy(out, yb)
            loss.backward()
            opt.step()

            loss_sum += loss.item() * xb.size(0)
            pred = (out > 0.5).float()
            correct += (pred == yb).sum().item()
            total += yb.size(0)

        if (ep + 1) % 5 == 0 or ep == epochs - 1:
            print(f"  epoch {ep+1:02d}/{epochs}  loss={loss_sum/total:.4f}  "
                  f"acc={correct/total*100:.1f}%")

    # ---- Export TorchScript ----
    model.eval()
    F_dim = PLANE_DIMS[plane]
    example = torch.zeros(1, F_dim, dtype=torch.float32)
    try:
        scripted = torch.jit.trace(model, example)
    except Exception:
        scripted = torch.jit.script(model)
    out_path = os.path.join(out_dir, f"detector_{plane}.pt")
    scripted.save(out_path)

    # Sanity check: forward an example and print the probability.
    p = scripted(example).item()
    print(f"  exported {out_path}  example p_mal(zeros)={p:.3f}")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="models/miids")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--eps", type=float, default=0.05,
                    help="PGD perturbation budget for adversarial training")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    torch.manual_seed(0)
    random.seed(0)

    paths = []
    for plane in PLANE_DIMS:
        paths.append(train_one(plane, epochs=args.epochs,
                               eps=args.eps, out_dir=args.out_dir))

    print("\n=== Summary ===")
    for p in paths:
        sz = os.path.getsize(p) // 1024
        print(f"  {p:50s}  {sz:5d} KB")


if __name__ == "__main__":
    main()
