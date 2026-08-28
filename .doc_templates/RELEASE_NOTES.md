# VeReMiVNDN dataset, v1.0.0

The dataset for the IEEE Access article
[VeReMiVNDN: A Dataset for Misbehavior Detection in Vehicular Named Data
Networking Using the JubST SUMO Scenario](https://doi.org/10.1109/ACCESS.2026.3681896).

This is the first release that carries actual data. The repository previously
pointed to this page while no release existed.

## Contents

| Asset | Contents |
|---|---|
| `veremivndn_ml.tar.gz` | The main dataset. One gzipped CSV per run, 69 features plus labels. |
| `veremivndn_plane.tar.gz` | Per-neighbor view, 23 features per monitor and observed neighbor. |
| `veremivndn_scalars.tar.gz` | OMNeT++ scalar output for every run. |
| `DATA_DICTIONARY.md`, `INSTRUCTIONS.md` | Column definitions, loading, splitting, limitations. |
| `CHECKSUMS.sha256` | SHA-256 of every asset. |

| Property | Value |
|---|---|
| Runs | {{N_RUNS}} |
| Labeled rows | {{ML_ROWS}} |
| Attack rows | {{ATTACK_ROWS}} ({{ATTACK_PCT}}) |
| Features | 69 |
| Simulated time | {{SIM_SECONDS}} |

## Quick start

```bash
curl -LO https://github.com/Muhammaduazir69/VeReMiVNDN-dataset/releases/download/v1.0.0/veremivndn_ml.tar.gz
tar xzf veremivndn_ml.tar.gz
sha256sum -c CHECKSUMS.sha256
```

```python
import glob, pandas as pd
df = pd.concat([pd.read_csv(f) for f in glob.glob("data/ml/*.csv.gz")],
               ignore_index=True)
```

Train on `isAttack` (binary) or `attackType` (multi-class). Do **not** train on
`attack`, which labels the run rather than the row.

## The data was regenerated for this release

Five defects were repaired before generating it. Anyone reproducing numbers from
the article should know what changed. The first two meant the published dataset
could not have contained usable features or usable labels.

1. **Every recording node wrote to the same file and truncated it.** The output
   path was built from the output directory and dataset name only, with no node
   identifier, and opened with `ios::out`. Each node erased what the previous
   ones had written, so a whole campaign exported a few hundred rows. Output is
   now qualified by the host module name, one file per node.

2. **No attack module ever reported itself.** `setGroundTruth` existed but
   nothing called it, so every row fell through to the `Benign` default and the
   dataset could not represent an attack under any configuration. The label is
   now read from the recording node's own attack module at sample time, which
   also means a malicious vehicle is correctly labeled benign outside its attack
   window.

3. **The feature window was never filled.** `notifyPacket()`, which
   accumulates the sliding window every one of the 69 features is computed
   from, had no caller anywhere in the source tree. The NDN forwarding path
   notified the extractor for the per-neighbor plane statistics but never for
   this window, so every traffic, table and timing feature held its default
   value in every row. It is now called from the Interest, Data and NACK paths.

4. **The collector read the window after it had been cleared.** The extractor
   slides its window as the last step of its own 1 s tick, and the collector
   samples on an identical 1 s timer, so the counters were zeroed before they
   were read. The collector is now served a snapshot of the last fully
   accumulated window, which does not depend on which module's self-message is
   scheduled first.

5. **Mobility features were placeholders.** `speed` returned a hard-coded
   15 m/s, `positionX`, `positionY` and `direction` returned zero, and
   `neighborCount` returned a constant 5. All five are now read from the host's
   Veins mobility module, except `neighborCount`, which counts the distinct
   senders heard within the observation window.

6. **The attacker-ratio axis varied nothing.** The attacker set was pinned to
   `vehicle[0..9]` in the base configuration, and a command-line override cannot
   displace a Config section, so 5 %, 10 % and 20 % all produced exactly ten
   attackers at every density. Each run now generates a derived config section
   that sets the intended range and disables the rest.

Two further changes improve the design rather than fix a defect. Traffic density
is now set through SUMO demand scaling, since the `numVehicles` parameter only
sized a module vector and every run inserted the same 274 vehicles whatever it
said. And each seed now selects its own SUMO random seed, so seeds vary mobility
as well as application traffic; the stock configuration pinned seed 42 for
reproducible screenshots.

Because of all this, figures computed from this release will not match the
tables in the published article. This release is the version to trust.

## The four attacks are not visible in the same way

All four execute, are labeled, and are separable, but through different
features. Interest Flooding and Interest Aggregation move short-window
statistics sharply: burstiness and PIT occupancy respond within a single
observation window.

Name Prefix Hijacking and Routing Information Flood do not. Every short-window
statistic is identical between attacker and benign rows to three decimal places.
They appear only in `longTermInterestRate`, which accumulates over a longer
horizon, where an attacker sits near 0.46 against 0.22 for a benign node. The
forged advertisements and routing updates are real and the scalar files record
them in the tens of thousands, but they register as a slow rise in accumulated
volume rather than as a burst.

A model given only single-window features will therefore find the first two
attacks and miss the last two. The README carries the measured table, with
Cohen's d per attack pooled over all forty-five runs.

There is no purpose-built routing feature: no advertisement or FIB churn column
exists and `hijackingScore` is an unimplemented stub. Adding one is the most
useful extension available here, and the counters needed as ground truth are
already in `data/scalars/`.

## Known limitations

- One road network (JubST) and one vehicle class.
- Attackers hold a fixed rate and strategy for their whole window and do not
  react to detection.
- Attackers occupy the low vehicle indices rather than being placed at random.
- Four of the ten heuristic `*Score` columns are unimplemented stubs returning a
  constant, including `hijackingScore`, even though Name Prefix Hijacking is one
  of the four attacks. See the data dictionary.

## License

Data and documentation under CC BY 4.0; simulator source under MIT.
