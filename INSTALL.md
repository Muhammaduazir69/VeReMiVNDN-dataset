# Installation

Two things live in this repository, and they have very different requirements.

**If you only want the data**, you do not need any of this. Download a release
asset and read it with pandas; see the [README](README.md). Nothing below is
required.

**If you want to regenerate the data or modify the simulator**, you need the
OMNeT++ toolchain described here.

---

## Toolchain

The versions the dataset was produced with. Nearby versions generally work, but
these are the ones that are tested.

| Component | Version | Purpose |
|---|---|---|
| OMNeT++ | 6.0.3 | Discrete event simulation kernel |
| SUMO | 1.18 | Road traffic and mobility |
| Veins | 5.2 | Couples OMNeT++ to SUMO over TraCI |
| INET | 4.5 | Network stack and mobility base classes |
| GCC | 9 or newer | C++17 |
| Python | 3.8 or newer | Consolidation and analysis scripts |

## 1. System packages

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential clang lld gdb bison flex perl \
     python3 python3-pip qtbase5-dev qtchooser qt5-qmake \
     qtbase5-dev-tools libqt5opengl5-dev libxml2-dev zlib1g-dev \
     doxygen graphviz sumo sumo-tools sumo-doc
```

Confirm SUMO is on the path and new enough:

```bash
sumo --version | head -1
```

## 2. OMNeT++

```bash
wget https://github.com/omnetpp/omnetpp/releases/download/omnetpp-6.0.3/omnetpp-6.0.3-linux-x86_64.tgz
tar xzf omnetpp-6.0.3-linux-x86_64.tgz
cd omnetpp-6.0.3
source setenv
./configure
make -j$(nproc)
```

`source setenv` sets the path for the current shell only. Add it to your shell
profile, or run it in every new terminal before building anything below.

## 3. INET and Veins

Both must sit beside this repository, because the makefile refers to them by
relative path.

```
<parent>/
├── inet4.5/
├── veins/
├── veins_inet/
└── VeReMiVNDN/        <- this repository
```

```bash
cd <parent>
git clone -b v4.5.0 https://github.com/inet-framework/inet.git inet4.5
cd inet4.5 && make makefiles && make -j$(nproc) && cd ..

git clone -b veins-5.2 https://github.com/sommer/veins.git
cd veins && ./configure && make -j$(nproc) && cd ..
```

If your layout differs, edit the `INET`, `VEINS` and `VEINS_INET` paths near the
top of `scripts/miids/run_one.sh`.

## 4. Build the simulator

```bash
cd VeReMiVNDN
make -j$(nproc)
```

This produces the `VeReMiVNDN` binary in the repository root. It is a build
product and is deliberately not tracked in git.

## 5. Verify with one run

```bash
scripts/miids/run_one.sh Attack01_InterestFlooding 300s "" 0 \
  --seed-set=1 \
  --'*.manager.launchConfig=xmldoc("../scenarios/sumo/jubst_low_s1.launchd.xml")'
```

A healthy run finishes in one to three minutes and writes a scalar file under
`simulations/configs/results/`. Check that the attack actually fired:

```bash
awk '$3=="totalInterestsFlooded"{s+=$4} END{print "flooded:", s}' \
  simulations/configs/results/*.sca
```

A count in the tens of thousands is normal for a 300 s run. Zero means the
attack window never opened, which usually means the run was shorter than the
attack start time of 60 s.

## 6. Regenerate the full dataset

```bash
scripts/veremivndn_paper1_campaign.sh          # single worker, all 225 runs
```

To use several cores, run one worker per core with different indices. Each
worker takes every Nth run and gets its own TraCI port and output directories:

```bash
for w in 0 1 2 3; do
  scripts/veremivndn_paper1_campaign.sh $w 4 > logs/w$w.log 2>&1 &
done
```

The campaign is resumable. A run is marked complete only after its scalar file
is checked for a plausible vehicle count, so a run interrupted partway through
is repeated rather than silently kept. Re-running the script skips whatever is
already finished.

Then consolidate the per-node CSVs into one file per run:

```bash
scripts/consolidate_paper1.py \
  --root datasets/paper1_veremivndn --out release/data
```

## Notes

**Disk.** A full campaign writes a few GB. OMNeT++ vector recording is disabled
in the campaign because it produces far more output than everything else
combined and nothing in this pipeline reads it. If you turn it back on, budget
tens of GB.

**Parallelism.** Each worker starts its own SUMO on its own TraCI port. Running
more workers than physical cores slows everything down, because each simulation
is single threaded and they contend for memory bandwidth.

**Reproducibility.** Each `(density, seed)` pair has its own SUMO configuration
under `simulations/scenarios/sumo/jubst_<density>_s<seed>.sumo.cfg`, which fixes
both the demand scale and the SUMO random seed. Given the same toolchain
versions, a run reproduces exactly.
