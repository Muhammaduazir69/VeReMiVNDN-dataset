# VeReMiVNDN: Vehicular Named Data Network IDS Dataset

[![OMNeT++](https://img.shields.io/badge/OMNeT++-6.0.3-blue)](https://omnetpp.org/)
[![VEINS](https://img.shields.io/badge/VEINS-5.3-green)](https://veins.car2x.org/)
[![INET](https://img.shields.io/badge/INET-4.5-orange)](https://inet.omnetpp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

**VeReMiVNDN** is a comprehensive simulation framework and dataset generator for Intrusion Detection Systems (IDS) in Vehicular Named Data Networks (VNDN). This project implements 20 different multi-layer attacks and provides rich feature extraction for machine learning-based security research.

> Dataset and simulation results are available in the [GitHub Releases](https://github.com/Muhammaduazir69/VNDN-Security/releases) section.

## Key Features

- **Complete NDN Protocol Stack** for vehicular networks
- **20 Attack Types** across all network layers
- **Rich Feature Set**: Trust, Privacy, Temporal, Mobility, Cache, Network metrics
- **ML-Ready Datasets**: CSV, JSON formats with ground truth labels
- **Multi-Layer Detection**: Network, Data, Caching, Privacy, Trust, Cross-layer
- **Realistic Scenarios**: Integration with SUMO, VEINS, INET 4.5, Simu5G

## Attack Types Implemented

### Network Layer (PIT/FIB)
1. **Interest Flooding** - PIT exhaustion attack
2. **Name Prefix Hijacking** - Route hijacking
3. **Interest Aggregation Attack** - Resource imbalance
4. **Routing Information Flood** - FIB/PIT spoofing

### Data/Content Layer
5. **Content Poisoning** - Fake data injection
6. **Interest/Content Replay** - Stale content attacks
7. **Cache Invalidation** - Malicious cache churn
8. **Producer Impersonation** - Fake producer attacks

### Caching Layer
9. **Cache Pollution** - Unpopular content flooding
10. **Cache Partitioning** - Availability manipulation
11. **Content Privacy Leakage** - Cache sharing attacks

### Privacy Layer
12. **Cache Timing Attacks** - Timing-based inference
13. **Privacy De-anonymization** - Name semantics exploitation
14. **Name Enumeration** - Privacy crawling

### Trust/Identity Layer
15. **Sybil Content Amplification** - Multiple fake identities
16. **Collusion** - Coordinated misbehavior
17. **Signature Forgery** - Key compromise attacks

### Cross-Layer Attacks
18. **Selective Forwarding** - Gray hole attacks
19. **Radio Jamming** - PHY layer interference
20. **Machine Learning Evasion** - Adversarial examples

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SUMO Traffic Simulator                  │
│                  (Realistic Vehicle Mobility)               │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              VEINS (Vehicle Communication)                  │
│           INET 4.5 + Simu5G (Network Stack)                 │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                   VNDN Protocol Layer                       │
│  ┌──────────────┬──────────────┬────────────────────────┐  │
│  │   Interest   │    Data      │        NACK            │  │
│  └──────────────┴──────────────┴────────────────────────┘  │
│  ┌──────────────┬──────────────┬────────────────────────┐  │
│  │     PIT      │     FIB      │    Content Store (CS)  │  │
│  └──────────────┴──────────────┴────────────────────────┘  │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              Attack Modules (20 Types)                      │
│   Network │ Data │ Cache │ Privacy │ Trust │ Cross-Layer   │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│           IDS Detection & Data Collection                   │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Feature Extraction: Network, Temporal, Trust,     │    │
│  │  Cache, Mobility, Privacy Metrics                  │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Logging: CSV, JSON + Ground Truth Labels          │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              VeReMiVNDN Dataset                             │
│     Train / Test / Validation Sets with Labels             │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- OMNeT++ 6.0.3
- VEINS 5.3
- INET 4.5
- Simu5G
- SUMO (latest version)
- Python 3.8+ (for data processing)

### Build Instructions

```bash
git clone https://github.com/Muhammaduazir69/VNDN-Security.git
cd VNDN-Security

# Build the project
make makefiles
make -j$(nproc)
```

## Quick Start

### 1. Run a Basic Simulation

```bash
cd simulations
opp_run -u Cmdenv -c BasicVNDN -n ..:../src omnetpp.ini
```

### 2. Run Attack Scenario (Interest Flooding)

```bash
opp_run -u Cmdenv -c AttackScenario_IF -n ..:../src omnetpp.ini
```

### 3. Generate Dataset

```bash
python3 utils/parsers/parse_omnet_results.py --input simulations/results --output datasets/processed
```

## Dataset

The full simulation dataset (results, frames, and OMNeT++ logs) is available in the **[Releases](https://github.com/Muhammaduazir69/VNDN-Security/releases)** section:

| File | Description |
|------|-------------|
| `VeReMiVNDN-OmNetpp-Dataset.zip` | Raw OMNeT++ simulation dataset |
| `VeReMiVNDN-Dataset-Results.zip` | Processed simulation results |
| `VeReMiVNDN-Frames.zip` | Simulation frame captures |

### Features Collected

- **Network**: RSSI, delay, throughput, packet loss, jitter
- **NDN**: PIT size, cache hit ratio, interest satisfaction rate, hop count
- **Trust & Security**: node trust score, content trust score, anomaly score
- **Temporal**: inter-packet arrival time, burst patterns, attack duration
- **Mobility**: speed, acceleration, position, direction, RSU distance
- **Privacy**: name entropy, cache access patterns, timing variance

### Label Format

```csv
timestamp,node_id,attack_type,attack_active,severity,layer
1.234,vehicle[5],InterestFlooding,1,0.85,Network
2.456,vehicle[12],Benign,0,0.0,None
```

## Configuration

Main config: `simulations/configs/omnetpp.ini`

```ini
[General]
network = VndnNetwork
sim-time-limit = 300s
*.numVehicles = 100
*.numRSU = 5
*.numMalicious = 10
*.vehicle[*].attackType = "InterestFlooding"
*.**.ids.enabled = true
```

## Comparison with Existing Datasets

| Feature | VeReMi | F2MD | MisbehaviorX | **VeReMiVNDN** |
|---------|--------|------|--------------|------------|
| Protocol | VANET | VANET | V2X | **VNDN** |
| Attack Types | 5 | 8 | 68 | **20 (VNDN-specific)** |
| Trust Scores | ✗ | ✗ | ✗ | **✓** |
| Privacy Features | ✗ | ✗ | ✗ | **✓** |
| Cache Metrics | ✗ | ✗ | ✗ | **✓** |
| Multi-Layer | ✗ | ✗ | Limited | **✓** |
| NDN Support | ✗ | ✗ | ✗ | **✓** |

## Citation

If you use this framework or dataset in your research, please cite:

```bibtex
@misc{veremivndn2025,
  title={VeReMiVNDN: A Comprehensive Dataset for Intrusion Detection in Vehicular Named Data Networks},
  author={Muhammad Uzair},
  year={2025},
  publisher={GitHub},
  howpublished={\url{https://github.com/Muhammaduazir69/VNDN-Security}}
}
```

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- VeReMi Dataset project
- F2MD Framework
- OMNeT++ Community
- VEINS and INET Development Teams

## Contact

- GitHub Issues: [https://github.com/Muhammaduazir69/VNDN-Security/issues](https://github.com/Muhammaduazir69/VNDN-Security/issues)

---

**Version:** 1.0.0 | **Status:** Active
