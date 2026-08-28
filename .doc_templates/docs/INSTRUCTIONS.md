# Instructions

## Loading

Every released file is a gzipped CSV with a header, so no decompression step is
needed.

```python
import glob
import pandas as pd

df = pd.concat(
    [pd.read_csv(f) for f in sorted(glob.glob("data/ml/*.csv.gz"))],
    ignore_index=True,
)
print(len(df), "rows;", int(df.isAttack.sum()), "attack rows")
```

The full machine-learning view is a few GB in memory. If that is too much, read
one run at a time, or read only the columns you need with `usecols`.

## Setting up a supervised problem

```python
LABELS = ["timestamp", "nodeId", "attackType", "isAttack",
          "attackIntensity", "severity", "attackLayer"]
IDS    = ["run", "config", "attack", "density", "vehicles",
          "attacker_ratio_pct", "seed"]
SCORES = [c for c in df.columns if c.endswith("Score")]

X = df.drop(columns=LABELS + IDS + SCORES)   # see the data dictionary on SCORES
y = df.isAttack
```

For multi-class work use `df.attackType` instead, which names the attack rather
than only flagging it.

## Splitting

Do not use a random split. Rows from one run are highly correlated, so a random
split puts near-duplicate rows on both sides and reports a score that will not
survive contact with a new run. Split on one of the identification columns
instead.

**By seed.** The usual choice. Trains and tests on the same conditions with
different randomness.

```python
test  = df[df.seed == 5]
train = df[df.seed != 5]
```

**By attack, to measure generalization to an unseen attack.** Train on three
attacks plus the benign control, test on the fourth.

```python
held  = "NamePrefixHijacking"
test  = df[df.attack == held]
train = df[(df.attack != held)]
```

This is the harder and more informative protocol. Expect a clear drop against
the seed split. If you do not see one, check that the score columns were
dropped.

**By density, to measure transfer across traffic load.**

```python
test  = df[df.density == "high"]
train = df[df.density != "high"]
```

## Class imbalance

Attack rows are a minority, by construction: only a fraction of vehicles are
malicious, and each is malicious only during its 180 s window. Accuracy is
therefore not a useful measure. Report precision, recall, F1 and the area under
the precision-recall curve, and stratify your splits.

```python
from sklearn.metrics import classification_report, average_precision_score
print(classification_report(y_test, pred, digits=3))
print("AP:", average_precision_score(y_test, proba))
```

## A worked baseline

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

tr, te = df[df.seed != 5], df[df.seed == 5]
Xtr = tr.drop(columns=LABELS + IDS + SCORES); ytr = tr.isAttack
Xte = te.drop(columns=LABELS + IDS + SCORES); yte = te.isAttack

clf = RandomForestClassifier(
    n_estimators=300, class_weight="balanced_subsample", n_jobs=-1, random_state=0
).fit(Xtr, ytr)

print(classification_report(yte, clf.predict(Xte), digits=3))
```

Treat the result as a starting point, not as a target. It is a per-node,
per-window classifier with no temporal context; the features support sequence
models, and the `plane` view supports per-neighbor attribution.

## Reassembling and verifying the download

The two large archives ship as 48 MB parts. Join them before use:

```bash
cat veremivndn_ml.tar.gz.part*      > veremivndn_ml.tar.gz
cat veremivndn_scalars.tar.gz.part* > veremivndn_scalars.tar.gz
tar xzf veremivndn_ml.tar.gz
```

`CHECKSUMS.sha256` lists both the parts and the joined archives, so it catches a
truncated part as well as a bad join:

```bash
sha256sum -c CHECKSUMS.sha256
```

## Limitations

Read these before drawing conclusions.

- **The release was regenerated after publication.** Defects in the export path
  were repaired first, so numbers computed here will not match the published
  tables exactly. The README explains what changed. This release is the version
  to trust.
- **One road network.** All runs use JubST. Nothing here establishes transfer to
  a different topology.
- **Attackers are static.** Fixed rate and strategy for the whole window, with
  no reaction to detection. Scores against an adaptive adversary will be lower.
- **Four of the ten heuristic score columns are unimplemented stubs** that
  return a constant. See the data dictionary.
- **Attackers occupy the low vehicle indices.** They are not randomly placed in
  the fleet, so any spatial conclusion should be checked against that.
