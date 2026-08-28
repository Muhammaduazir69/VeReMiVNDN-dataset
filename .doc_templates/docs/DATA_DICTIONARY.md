# Data dictionary

## Files

`data/ml/<CONFIG>_<density>_<ratio>_seed<N>.csv.gz`

One gzipped CSV per run. Each row is one observation window written by one
monitoring node. This is the dataset the paper describes and the one most users
want.

`data/plane/<CONFIG>_<density>_<ratio>_seed<N>.csv.gz`

A second view of the same runs, carrying 23 features that describe one
*neighbor* as seen by one monitor, rather than the monitor's own totals. Use it
if you want per-neighbor attribution instead of per-node classification.

`data/scalars/<run>.sca.gz`

The OMNeT++ scalar output for the run, holding network-level totals.

---

## Sampling

Each node samples once per simulated second, over a 10 s feature window, for the
300 s of the run. A node contributes rows only while it is in the scenario, so
the per-run row count tracks how many vehicles SUMO had inserted and not yet
removed rather than the nominal fleet size.

The article describes sampling at 100 ms across 39 monitoring nodes and quotes
780,000 samples, in one place per run and in another for the dataset as a whole,
against a temporal coverage given as both 300 s and 2000 s. Those figures are
not consistent with each other and are not what this release contains. The
counts in the README are measured from the released files.

## Identification columns

Present on every row of both views. They are prepended during consolidation so
the experimental grid can be recovered from the files alone.

| Column | Type | Meaning |
|---|---|---|
| `run` | string | Full run name, unique across the release. |
| `config` | string | OMNeT++ configuration, for example `Attack01_InterestFlooding`. |
| `attack` | string | Attack configured for the run. Constant within a run. |
| `density` | string | `low`, `med` or `high`. |
| `vehicles` | integer | Vehicles inserted: 77, 151 or 356. |
| `attacker_ratio_pct` | integer | 5, 10 or 20. Always 0 for `BenignTraffic`. |
| `seed` | integer | 1 to 5. Varies both mobility and application traffic. |

## Label columns

| Column | Values | Meaning |
|---|---|---|
| `attackType` | `Benign`, `InterestFlooding`, `NamePrefixHijacking`, `InterestAggregation`, `RoutingInfoFlood` | **Ground truth for this row.** The attack the recording node was executing at that instant. |
| `isAttack` | 0 or 1 | 1 when `attackType` is not `Benign`. The binary target. |
| `attackIntensity` | 0.0 to 1.0 | Configured intensity of the active attack, 0.0 when benign. |
| `severity` | 0.0 to 1.0 | Severity class of the active attack. |
| `attackLayer` | string | Protocol layer, or `None`. |
| `nodeId` | integer | Recording node. |
| `timestamp` | float, seconds | Simulation time of the sample. |

`attackType` is resolved from the recording node's own attack module at the
moment the sample is taken, so it is 1 only while the attack window is open. A
malicious vehicle is labeled `Benign` before t = 60 s and after t = 240 s. This
is deliberate: it is what lets you separate attack onset from steady state, and
it is why `attack` and `attackType` must not be used interchangeably.

---

## Feature columns, 69 total

All features are computed from what the recording node observed. None is
derived from the label.

### Traffic volume and timing, 10

`interestRate`, `dataRate`, `avgInterestSize`, `avgDataSize`,
`packetDropRate`, `avgHopCount`, `interestDataRatio`, `nackRate`, `avgRTT`,
`jitter`

### NDN table state, 15

`pitOccupancy`, `pitSize`, `avgPitLifetime`, `pitSatisfactionRate`, `fibSize`,
`avgFibEntryHopCount`, `csOccupancy`, `csSize`, `cacheHitRatio`,
`cacheMissRatio`, `avgCacheEntryAge`, `contentStoreDiversity`,
`pendingInterestDiversity`, `faceUtilization`, `avgForwardingDelay`

The PIT counters are the ones that respond most directly to the four
forwarding-layer attacks in this dataset, and `pitSize` and `pitOccupancy` are
read from the node's real PIT.

The Content Store columns (`csSize`, `csOccupancy`, `cacheHitRatio`,
`cacheMissRatio`, `avgCacheEntryAge`, `contentStoreDiversity`) are near zero
throughout. The store is never populated in this build, so there is nothing to
hit and nothing to evict. They are reported as measured rather than dropped, but
they carry no signal here and no caching attack is part of this dataset. An
earlier version of the extractor returned a fixed 0.3 hit ratio, which looked
like data and was not.

`avgPitLifetime`, `avgFibEntryHopCount`, `avgCacheEntryAge`, `faceUtilization`
and `avgForwardingDelay` are constants: the corresponding modules do not expose
the quantity in this build.

### Trust and signatures, 8

`avgTrustScore`, `minTrustScore`, `maxTrustScore`, `trustVariance`,
`signatureVerificationRate`, `signatureFailureRate`, `unsignedDataRatio`,
`lowTrustPacketRatio`

### Temporal behavior, 10

`interestRateVariance`, `burstiness`, `periodicity`, `trendSlope`,
`interArrivalTimeMean`, `interArrivalTimeStdDev`, `windowInterestCount`,
`windowDataCount`, `shortTermInterestRate`, `longTermInterestRate`

### Naming and content, 3

`nameEntropy`, `uniqueNamesRatio`, `repeatedNonceRatio`

### Privacy, 2

`locationExposureRisk`, `anonymityScore`

### Mobility, 6

`speed`, `acceleration`, `direction`, `positionX`, `positionY`,
`neighborCount`

### Aggregate traffic, 5

`totalPackets`, `totalBytes`, `avgPacketSize`, `packetSizeVariance`,
`trafficEntropy`

### Heuristic attack scores, 10

`interestFloodingScore`, `poisoningScore`, `cachePollutionScore`,
`timingAttackScore`, `replayScore`, `sybilScore`, `collusionScore`,
`hijackingScore`, `grayHoleScore`, `jammingScore`

**Read this group carefully before using it.**

These are not independent measurements. They are the simulator's own rule based
detector outputs, each a fixed arithmetic combination of features that already
appear elsewhere in the same row. For example `interestFloodingScore` is the
mean of a normalized Interest rate, PIT occupancy and one minus the
satisfaction ratio, all three of which are separate columns. They add no
information a model cannot derive itself, and including them makes a learned
model partly an evaluation of a hand written heuristic rather than of the
traffic.

They do **not** leak the label. Each is computed from observed traffic, not from
the ground truth.

Four of them are unimplemented and return a constant 0.0 in every row:

| Column | Status |
|---|---|
| `sybilScore` | Stub. Requires cross-node correlation that is not implemented. |
| `collusionScore` | Stub. Requires multi-node analysis that is not implemented. |
| `hijackingScore` | Stub. Requires FIB monitoring that is not implemented. |
| `jammingScore` | Stub. Requires physical-layer metrics this build does not expose. |

`hijackingScore` being a stub matters for this dataset in particular, because
Name Prefix Hijacking is one of the four attacks evaluated. There is no
purpose-built feature for it; a detector has to find it in the general traffic
and table statistics.

A safe default is to drop the whole group:

```python
SCORES = [c for c in df.columns if c.endswith("Score")]
X = df.drop(columns=SCORES + LABELS + IDS)
```

### Observability of each attack

{{ATTACK_SEPARABILITY}}

Measured from the released files. A low value means the feature set does not
capture that attack, not that the attack failed to run; see the README.

### Columns that are constant in this release

Some columns never vary, either because they are the stubs above or because the
quantity is not instrumented in this build. Constant columns carry no
information and most feature selectors will drop them anyway, but it is faster
to know in advance. Check for yourself:

```python
constant = [c for c in X.columns if X[c].nunique(dropna=False) <= 1]
```

{{CONSTANT_COLUMNS}}

---

## Scalar files

`data/scalars/<run>.sca.gz` is standard OMNeT++ scalar output, in
`scalar <module> <name> <value>` lines.

**Filter by module before aggregating.** Several scalar names are written by
more than one module with unrelated meanings; `totalInsertions`, for instance,
exists on the Content Store, the PIT and the FIB. Aggregating by name alone
silently sums quantities that are not comparable.

Useful attack-side counters include `totalInterestsFlooded`,
`totalMaliciousPackets` and `totalPacketsGenerated`, written by the attack
modules of malicious vehicles.
