#!/usr/bin/env python3
"""
DP-IDS-VNDN Results Analysis Script
Parses .sca files and generates comparison tables for the paper.

Usage: python3 scripts/analyze_dpids_results.py [results_dir]
"""

import os
import sys
import re
from collections import defaultdict

def parse_sca_file(filepath):
    """Parse an OMNeT++ scalar file and extract key metrics."""
    metrics = {}
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('scalar'):
                parts = line.split('\t')
                if len(parts) >= 3:
                    module = parts[0].replace('scalar ', '')
                    name = parts[1] if len(parts) > 1 else ''
                    value = parts[2] if len(parts) > 2 else '0'
                    # Try space-separated format
                    parts2 = line.split()
                    if len(parts2) >= 4:
                        module = parts2[1]
                        name = parts2[2]
                        value = parts2[3]
                    try:
                        metrics[f"{module}.{name}"] = float(value)
                    except ValueError:
                        pass
    return metrics

def extract_dpids_metrics(metrics):
    """Extract DP-IDS specific metrics from parsed scalar data."""
    result = {
        'totalDetections': 0,
        'totalPenalizations': 0,
        'truePositives': 0,
        'trueNegatives': 0,
        'falsePositives': 0,
        'falseNegatives': 0,
        'finalISR': 0,
        'accuracy': 0,
        'precision': 0,
        'recall': 0,
        'f1': 0,
    }

    for key, value in metrics.items():
        for metric_name in result:
            if metric_name in key:
                result[metric_name] = value

    # Compute derived metrics
    tp = result['truePositives']
    tn = result['trueNegatives']
    fp = result['falsePositives']
    fn = result['falseNegatives']
    total = tp + tn + fp + fn

    if total > 0:
        result['accuracy'] = (tp + tn) / total
    if tp + fp > 0:
        result['precision'] = tp / (tp + fp)
    if tp + fn > 0:
        result['recall'] = tp / (tp + fn)
    if result['precision'] + result['recall'] > 0:
        result['f1'] = 2 * result['precision'] * result['recall'] / (result['precision'] + result['recall'])

    return result

def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else 'simulations/configs/results'

    if not os.path.exists(results_dir):
        print(f"Results directory not found: {results_dir}")
        sys.exit(1)

    # Find all .sca files grouped by config
    configs = defaultdict(list)
    for filename in sorted(os.listdir(results_dir)):
        if filename.endswith('.sca'):
            config_name = filename.rsplit('-', 1)[0]
            configs[config_name].append(os.path.join(results_dir, filename))

    print("=" * 80)
    print("DP-IDS-VNDN Results Analysis")
    print("=" * 80)
    print()

    # Table 1: Detection Performance Comparison
    print("Table 1: Detection Performance (Section 5.3)")
    print("-" * 70)
    print(f"{'Config':<35} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-" * 70)

    for config_name, files in sorted(configs.items()):
        if 'DPIDS' not in config_name:
            continue

        all_metrics = []
        for f in files:
            m = parse_sca_file(f)
            dm = extract_dpids_metrics(m)
            all_metrics.append(dm)

        if all_metrics:
            avg = {k: sum(m[k] for m in all_metrics) / len(all_metrics)
                   for k in all_metrics[0]}
            print(f"{config_name:<35} {avg['accuracy']:>7.4f} {avg['precision']:>7.4f} "
                  f"{avg['recall']:>7.4f} {avg['f1']:>7.4f}")

    print("-" * 70)
    print()

    # Table 2: Forwarding Quality Metrics
    print("Table 2: Forwarding Quality Metrics (Section 5.3)")
    print("-" * 70)
    print(f"{'Config':<35} {'ISR':>7} {'Detect':>7} {'Penal':>7}")
    print("-" * 70)

    for config_name, files in sorted(configs.items()):
        if 'DPIDS' not in config_name:
            continue

        all_metrics = []
        for f in files:
            m = parse_sca_file(f)
            dm = extract_dpids_metrics(m)
            all_metrics.append(dm)

        if all_metrics:
            avg = {k: sum(m[k] for m in all_metrics) / len(all_metrics)
                   for k in all_metrics[0]}
            print(f"{config_name:<35} {avg['finalISR']:>7.4f} "
                  f"{avg['totalDetections']:>7.0f} {avg['totalPenalizations']:>7.0f}")

    print("-" * 70)
    print()
    print("Analysis complete.")

if __name__ == '__main__':
    main()
