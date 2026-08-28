# VeReMiVNDN

A labeled dataset and simulation framework for misbehavior detection in
Vehicular Named Data Networking (VNDN), built on the JubST (Al-Jubail) SUMO
scenario.

This repository accompanies the IEEE Access article:

> B. G. Aldahlan and M. Uzair, "VeReMiVNDN: A Dataset for Misbehavior Detection
> in Vehicular Named Data Networking Using the JubST SUMO Scenario,"
> *IEEE Access*, 2026. doi:[10.1109/ACCESS.2026.3681896](https://doi.org/10.1109/ACCESS.2026.3681896)

---

## Download the dataset

The data is published as **[GitHub Releases]({{RELEASE_URL}})**, not as files in
this repository. Git is a poor fit for a few GB of compressed CSV, so the
release assets carry the data and this repository carries the code that
produced it.

The main archive is uploaded in 48 MB parts. A single large asset has no
resume, and this release was produced over a slow uplink, so a stalled transfer
would otherwise mean starting the whole file again. Fetch the parts and join
them with `cat`; the order is guaranteed by the shell glob.

```bash
# the labeled machine-learning dataset, one gzipped CSV per run
for i in 00 01 02 03 04 05 06 07; do
  curl -LO {{RELEASE_URL_DL}}/veremivndn_ml.tar.gz.part$i
done
cat veremivndn_ml.tar.gz.part* > veremivndn_ml.tar.gz
tar xzf veremivndn_ml.tar.gz
```

The per-neighbor view is small enough to come as one file:

```bash
curl -LO {{RELEASE_URL_DL}}/veremivndn_plane.tar.gz
```

Verify what you downloaded. `CHECKSUMS.sha256` covers both the individual parts
and the reassembled archives, so it will catch a truncated part and a bad join.

```bash
curl -LO {{RELEASE_URL_DL}}/CHECKSUMS.sha256
sha256sum -c CHECKSUMS.sha256
```

## Load it

Every file is a gzipped CSV with a header, so pandas reads it directly.

```python
import glob
import pandas as pd

df = pd.concat(
    [pd.read_csv(f) for f in glob.glob("data/ml/*.csv.gz")],
    ignore_index=True,
)

print(len(df), "rows")
print(df.attack.value_counts())
```

Each row already carries the columns that identify which run it came from, so
the experimental grid can be rebuilt from the released files alone without
consulting any side-car index.

---

## The label schema

This is the part most people ask about, so it is stated explicitly.

| Column | Meaning |
|---|---|
| `attack` | The attack configured for the run: `None`, `InterestFlooding`, `NamePrefixHijacking`, `InterestAggregation` or `RoutingInfoFlood`. Constant within a run. |
| `attackType` | **The ground truth for the row.** The attack the recording node was executing at that instant, or `Benign`. |
| `isAttack` | `1` when `attackType` is not `Benign`, `0` otherwise. This is the binary training target. |
| `attackIntensity` | Configured intensity of the active attack, `0.0` when benign. |
| `severity`, `attackLayer` | Severity class and protocol layer of the active attack. |
| `nodeId`, `timestamp` | Recording node and simulation time. |

Two distinctions matter and are easy to get wrong:

**`attack` is not `attackType`.** `attack` describes the run; `attackType`
describes the row. In an attack run, a malicious vehicle is labeled `Benign`
before its attack window opens and again after it closes, and every benign
vehicle in that run is labeled `Benign` throughout. Training on `attack` rather
than `attackType` labels the majority of an attack run's rows as malicious and
will produce misleadingly high scores.

**Ground truth is not an input feature.** The 69 feature columns are traffic
and table statistics observed at the recording node. The label columns are
resolved from the simulator's own configuration and are supervision only. Drop
them before fitting:

```python
LABELS = ["timestamp", "nodeId", "attackType", "isAttack",
          "attackIntensity", "severity", "attackLayer"]
IDS = ["run", "config", "attack", "density", "vehicles",
       "attacker_ratio_pct", "seed"]

X = df.drop(columns=LABELS + IDS)
y = df.isAttack
```

---

## What is in a release

| Asset | Contents |
|---|---|
| `veremivndn_ml.tar.gz.part00` .. `part07` | The main dataset, in 48 MB parts. One gzipped CSV per run, 69 features plus labels. Join with `cat`. |
| `veremivndn_plane.tar.gz` | A second view: 23 per-neighbor features, one row per monitor and observed neighbor. |
| `veremivndn_scalars.tar.gz.part00` .. `part03` | The OMNeT++ scalar file for every run, holding the network-level measurements. Join with `cat`. |
| `CHECKSUMS.sha256` | SHA-256 of every part and of the reassembled archives. |

Documentation lives in [`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md),
which defines every column, and [`docs/INSTRUCTIONS.md`](docs/INSTRUCTIONS.md),
which covers loading, splitting and the limitations to read first.

## The four attacks

The paper evaluates four forwarding-layer attacks, each with its own run
configuration.

| Configuration | Attack | What the attacker does |
|---|---|---|
| `Attack01_InterestFlooding` | Interest Flooding | Emits Interests for names that cannot be satisfied, so PIT entries accumulate and expire. |
| `Attack05_NamePrefixHijacking` | Name Prefix Hijacking | Advertises prefixes it does not serve, drawing Interests away from legitimate producers. |
| `Attack12_InterestAggregation` | Interest Aggregation Exploitation | Abuses PIT aggregation so that one Interest suppresses the forwarding of others. |
| `Attack18_RoutingInfoFlood` | Routing Information Flood | Floods routing updates to destabilize the FIB. |
| `BenignTraffic` | None | Attacker-free control. |

The simulator in `src/attacks/` implements a wider set of attacks across the
caching, privacy, trust and cross-layer planes. Those are **not** part of this
dataset and are not evaluated in the paper. Only the five configurations above
were run.

## The experimental grid

225 runs of 300 simulated seconds each:

```
5 configurations x 3 densities x 3 attacker ratios x 5 seeds = 225
```

| Axis | Levels |
|---|---|
| Density | `low` ~77 vehicles, `med` ~151, `high` ~356 |
| Attacker ratio | 5 %, 10 %, 20 % of the fleet |
| Seed | 1 to 5, varying both mobility and application traffic |

Density is set through SUMO demand scaling, calibrated against the JubST route
file over a 300 s horizon. Attackers occupy the low vehicle indices. The attack
window opens at t = 60 s and runs for 180 s, so every run contains benign
traffic before, during and after the attack.

`BenignTraffic` has no attackers, so its three ratio levels are replicates
rather than distinct conditions. The axis is kept so the design stays balanced
and the run count matches the published figure; the released rows record an
attacker ratio of 0 for all of them.

## Dataset at a glance

| Property | Value |
|---|---|
| Runs | {{N_RUNS}} |
| Rows, machine-learning view | {{ML_ROWS}} |
| Rows, per-neighbor view | {{PLANE_ROWS}} |
| Feature columns | 69 |
| Attack rows (`isAttack = 1`) | {{ATTACK_ROWS}} ({{ATTACK_PCT}}) |
| Simulated time | {{SIM_SECONDS}} |
| Compressed size | {{REL_SIZE}} |

## Which attacks are observable, and through what

An attack that runs in the simulator is not automatically visible in the
features. Each attack below executes and is labeled, and this table is measured
from the released files rather than asserted: Cohen's d is the standardized mean
difference between attacker and benign rows for the single most separating
feature, pooled over all forty-five runs of that attack.

{{ATTACK_SEPARABILITY}}

All four are separable, but not in the same way, and the difference matters for
how you model them.

Interest Flooding and Interest Aggregation change the short-term picture: the
attacker's burstiness and PIT occupancy move sharply, so a detector reading a
single observation window can find them.

The two routing-plane attacks do not. Name Prefix Hijacking and Routing
Information Flood leave every short-window statistic untouched, to three decimal
places: `interestRate`, `burstiness` and `windowInterestCount` are the same for
attacker and benign rows. They show up only in `longTermInterestRate`, which
accumulates over a longer horizon, where the hijacker sits at about 0.46 against
0.22 for a benign node. The forged advertisements and routing updates are real,
and the scalar files record them in the tens of thousands, but they register as
a slow rise in accumulated volume rather than as a burst.

The practical consequence is that a model given only single-window features will
find the first two attacks and miss the last two. If you care about the routing
attacks, keep the long-horizon features, or build sequences over consecutive
windows.

There is no purpose-built routing feature: the set has no advertisement or FIB
churn column, and `hijackingScore` is an unimplemented stub. Adding one is the
most useful extension available here, and the ground truth for that work is
already in `data/scalars/` as `forgedAdvertisements`, `hijackedPrefixCount` and
`interceptedInterests`.

---

## Build and run it yourself

See [INSTALL.md](INSTALL.md) for the full toolchain. In short:

```bash
make                                     # build the simulator
scripts/veremivndn_paper1_campaign.sh    # regenerate all 225 runs
scripts/consolidate_paper1.py --root datasets/paper1_veremivndn --out release/data
```

A single run:

```bash
scripts/miids/run_one.sh Attack01_InterestFlooding 300s "" 0 \
  --seed-set=1 \
  --'*.manager.launchConfig=xmldoc("../scenarios/sumo/jubst_low_s1.launchd.xml")'
```

## Notes on the data

Read these before drawing conclusions.

- **The dataset was regenerated after publication.** Five defects in the
  export path were repaired first, so the released files are not a
  byte-for-byte reproduction of the tables in the article. Two of them were
  severe enough that the original pipeline could not have produced a usable
  dataset at all: the routine that fills the feature window had no caller, so
  every one of the 69 features held its default value, and no attack module
  ever reported itself, so every row was labeled benign whatever the
  configuration. The others were that all recording nodes wrote to one filename
  and truncated it, that the collector read the window after the extractor had
  cleared it, and that the mobility features were hard-coded placeholders.
  `RELEASE_NOTES.md` lists each one. Numbers computed from this release will
  differ from the published tables, and the release is the version to trust.
- **Some columns are still constant**, either because the quantity is not
  instrumented in this build or because the feature is an unimplemented stub.
  The data dictionary lists exactly which, measured from the released files
  rather than assumed.
- **One map, one vehicle class.** All runs use the JubST road network. Results
  should not be assumed to transfer to another topology without re-measuring.
- **Attackers are static.** Each attacker holds a fixed rate and strategy for
  its whole window and does not react to detection. A detector scored only on
  this data will look better than it would against an adaptive adversary.
- **Class imbalance is real and intended.** Attack rows are a minority. Use
  stratified splits and report precision and recall, not accuracy.

## Repository layout

```
src/           simulator sources (NDN forwarding, attacks, IDS, logging)
simulations/   OMNeT++ configurations and the JubST SUMO scenario
scripts/       campaign, consolidation and release tooling
docs/          data dictionary, instructions and the project page
```

## License

The dataset and documentation are released under
[CC BY 4.0](LICENSE). The simulator source is released under the
[MIT license](LICENSE-CODE).

## Citation

See [CITATION.cff](CITATION.cff), or cite the article directly:

```bibtex
@article{aldahlan2026veremivndn,
  author  = {Aldahlan, Bassma G. and Uzair, Muhammad},
  title   = {{VeReMiVNDN}: A Dataset for Misbehavior Detection in Vehicular
             Named Data Networking Using the {JubST} {SUMO} Scenario},
  journal = {IEEE Access},
  year    = {2026},
  doi     = {10.1109/ACCESS.2026.3681896}
}
```

## Contact

Questions about the data are best raised as a
[GitHub issue](https://github.com/Muhammaduazir69/VeReMiVNDN-dataset/issues).

Muhammad Uzair, COMSATS University Islamabad, muhammaduzairr69@gmail.com
