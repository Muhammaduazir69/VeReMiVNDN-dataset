#!/usr/bin/env python3
"""
DP-IDS-VNDN LSTM Behavioural Detector Training Script
Methodology Section 4.3.1

Trains 4-layer LSTM on VeReMi dataset features.
Exports weights as CSV files for SimplifiedLSTM C++ inference.

Features: pos-x, pos-y, spd-x, spd-y, IDR, TTL_variance
Labels: 0 (benign), 1 (malicious)
Loss: Binary cross-entropy with class-weighted sampling

Usage: python3 train_lstm_behavioural.py --data veremi_data.csv --output models/lstm_weights/
"""

import argparse
import os
import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    print("PyTorch not available. Generating random weights for simulation testing.")


class BehaviouralLSTM(nn.Module):
    """4-layer LSTM for behavioural anomaly detection (Section 4.3.1)"""

    def __init__(self, input_dim=6, hidden_dim=64, num_layers=4, dropout=0.3):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers,
                           batch_first=True, dropout=dropout)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        lstm_out, (h_n, c_n) = self.lstm(x)
        out = self.fc(h_n[-1])
        return out.squeeze(-1)


def export_weights_csv(model, output_dir, input_dim=6, hidden_dim=64, num_layers=4):
    """Export LSTM weights to CSV files for C++ SimplifiedLSTM loader."""
    os.makedirs(output_dir, exist_ok=True)

    state = model.state_dict() if HAS_TORCH else None

    for l in range(num_layers):
        layer_input = input_dim if l == 0 else hidden_dim

        if state:
            # Extract PyTorch LSTM weights (concatenated as [i,f,c,o])
            w_ih = state[f'lstm.weight_ih_l{l}'].numpy()  # [4*hidden, input]
            w_hh = state[f'lstm.weight_hh_l{l}'].numpy()  # [4*hidden, hidden]
            b_ih = state[f'lstm.bias_ih_l{l}'].numpy()    # [4*hidden]
            b_hh = state[f'lstm.bias_hh_l{l}'].numpy()    # [4*hidden]

            # Split into i, f, c, o gates
            Wi = w_ih[0:hidden_dim]
            Wf = w_ih[hidden_dim:2*hidden_dim]
            Wc = w_ih[2*hidden_dim:3*hidden_dim]
            Wo = w_ih[3*hidden_dim:4*hidden_dim]

            Ui = w_hh[0:hidden_dim]
            Uf = w_hh[hidden_dim:2*hidden_dim]
            Uc = w_hh[2*hidden_dim:3*hidden_dim]
            Uo = w_hh[3*hidden_dim:4*hidden_dim]

            bi = b_ih[0:hidden_dim] + b_hh[0:hidden_dim]
            bf = b_ih[hidden_dim:2*hidden_dim] + b_hh[hidden_dim:2*hidden_dim]
            bc = b_ih[2*hidden_dim:3*hidden_dim] + b_hh[2*hidden_dim:3*hidden_dim]
            bo = b_ih[3*hidden_dim:4*hidden_dim] + b_hh[3*hidden_dim:4*hidden_dim]
        else:
            # Random Xavier initialization
            limit_i = np.sqrt(6.0 / (hidden_dim + layer_input))
            limit_h = np.sqrt(6.0 / (hidden_dim + hidden_dim))
            Wi = np.random.uniform(-limit_i, limit_i, (hidden_dim, layer_input))
            Wf = np.random.uniform(-limit_i, limit_i, (hidden_dim, layer_input))
            Wc = np.random.uniform(-limit_i, limit_i, (hidden_dim, layer_input))
            Wo = np.random.uniform(-limit_i, limit_i, (hidden_dim, layer_input))
            Ui = np.random.uniform(-limit_h, limit_h, (hidden_dim, hidden_dim))
            Uf = np.random.uniform(-limit_h, limit_h, (hidden_dim, hidden_dim))
            Uc = np.random.uniform(-limit_h, limit_h, (hidden_dim, hidden_dim))
            Uo = np.random.uniform(-limit_h, limit_h, (hidden_dim, hidden_dim))
            bi = np.zeros(hidden_dim)
            bf = np.ones(hidden_dim)  # Forget gate bias = 1
            bc = np.zeros(hidden_dim)
            bo = np.zeros(hidden_dim)

        prefix = f"{output_dir}/layer{l}_"
        np.savetxt(f"{prefix}Wi.csv", Wi, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Wf.csv", Wf, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Wc.csv", Wc, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Wo.csv", Wo, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Ui.csv", Ui, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Uf.csv", Uf, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Uc.csv", Uc, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}Uo.csv", Uo, delimiter=',', fmt='%.8f')
        np.savetxt(f"{prefix}bi.csv", bi, fmt='%.8f')
        np.savetxt(f"{prefix}bf.csv", bf, fmt='%.8f')
        np.savetxt(f"{prefix}bc.csv", bc, fmt='%.8f')
        np.savetxt(f"{prefix}bo.csv", bo, fmt='%.8f')

    # FC layer weights
    if state:
        # Simple FC: hidden -> 32 -> 1 (take first FC layer)
        fc_w = state['fc.0.weight'].numpy()  # [32, hidden]
        fc_b = state['fc.0.bias'].numpy()    # [32]
        # For simplified: just use first row as approximation
        # Or flatten the full FC to single hidden->1 mapping
        fc_final_w = state['fc.3.weight'].numpy()  # [1, 32]
        fc_final_b = state['fc.3.bias'].numpy()     # [1]
        # Combine: effective_w = fc_final_w @ fc_w = [1, hidden]
        effective_w = (fc_final_w @ fc_w).flatten()
        effective_b = float(fc_final_b[0] + fc_final_w @ fc_b)
    else:
        effective_w = np.random.uniform(-0.1, 0.1, hidden_dim)
        effective_b = 0.0

    np.savetxt(f"{output_dir}/fc_weights.csv", effective_w, fmt='%.8f')
    np.savetxt(f"{output_dir}/fc_bias.csv", [effective_b], fmt='%.8f')

    print(f"Weights exported to {output_dir}/")
    print(f"  {num_layers} LSTM layers x 12 weight files = {num_layers * 12} files")
    print(f"  + 2 FC weight files")
    print(f"  Total: {num_layers * 12 + 2} CSV files")


def main():
    parser = argparse.ArgumentParser(description='Train LSTM Behavioural Detector')
    parser.add_argument('--data', type=str, default='', help='Training data CSV path')
    parser.add_argument('--output', type=str, default='models/lstm_weights',
                        help='Output directory for weights')
    parser.add_argument('--epochs', type=int, default=100, help='Training epochs')
    parser.add_argument('--hidden', type=int, default=64, help='LSTM hidden dim')
    parser.add_argument('--layers', type=int, default=4, help='LSTM layers')
    parser.add_argument('--seq-length', type=int, default=20, help='Sequence length')
    parser.add_argument('--lr', type=float, default=1e-3, help='Learning rate')
    args = parser.parse_args()

    input_dim = 6
    hidden_dim = args.hidden
    num_layers = args.layers

    if HAS_TORCH and args.data and os.path.exists(args.data):
        print(f"Training LSTM on {args.data}...")
        model = BehaviouralLSTM(input_dim, hidden_dim, num_layers)

        # Load and prepare data
        data = np.loadtxt(args.data, delimiter=',', skiprows=1)
        # Expected columns: pos-x, pos-y, spd-x, spd-y, IDR, TTL, label
        features = data[:, :6]
        labels = data[:, 6]

        # Create sequences
        X, y = [], []
        for i in range(len(features) - args.seq_length):
            X.append(features[i:i+args.seq_length])
            y.append(labels[i+args.seq_length-1])

        X = torch.FloatTensor(np.array(X))
        y = torch.FloatTensor(np.array(y))

        # Class-weighted sampling (Section 4.3.1)
        class_counts = [int((y == 0).sum()), int((y == 1).sum())]
        weights = [1.0/c if c > 0 else 0 for c in class_counts]
        sample_weights = [weights[int(label)] for label in y]
        sampler = WeightedRandomSampler(sample_weights, len(sample_weights))

        dataset = TensorDataset(X, y)
        loader = DataLoader(dataset, batch_size=64, sampler=sampler)

        # Train
        optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
        criterion = nn.BCELoss()

        for epoch in range(args.epochs):
            model.train()
            total_loss = 0
            for batch_X, batch_y in loader:
                optimizer.zero_grad()
                pred = model(batch_X)
                loss = criterion(pred, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0:
                print(f"  Epoch {epoch+1}/{args.epochs}, Loss: {total_loss/len(loader):.4f}")

        model.eval()
        export_weights_csv(model, args.output, input_dim, hidden_dim, num_layers)
    else:
        print("No training data provided. Generating random weights for simulation testing...")
        model = BehaviouralLSTM(input_dim, hidden_dim, num_layers) if HAS_TORCH else None
        export_weights_csv(model, args.output, input_dim, hidden_dim, num_layers)

    print("Done!")


if __name__ == '__main__':
    main()
