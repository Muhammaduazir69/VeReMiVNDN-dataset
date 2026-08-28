#!/usr/bin/env bash
#
# make_dataport_package.sh - assemble the IEEE DataPort submission for
# VeReMiVNDN-EXE.
#
# IEEE DataPort's submit form has these required fields: Dataset Authors,
# Title, Category, Abstract, Documentation, Instructions, and the dataset
# files themselves. Optional fields are Keywords, Data Format, Related
# Dataset, Links, Dataset Image, and Scripts. This script produces a file for
# each of those, so the form can be filled by copying text rather than by
# rewriting it.
#
# Two decisions about what NOT to ship:
#
#   * The simulator console logs are 13.3 GB of OMNeT++ teardown warnings and
#     carry no research content. They are excluded.
#   * The per-monitor CSVs are consolidated to one file per run. The campaign
#     writes 4,250 small files, one per monitoring node, which is awkward to
#     consume and hides which run a row came from. Each row gains scenario and
#     seed columns so the run-disjoint split can still be reproduced exactly.
#
# Usage: scripts/miids/make_dataport_package.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="$ROOT/VeReMiVNDN-Extension/dataport_VeReMiVNDN-EXE"

echo "[dataport] building package at $OUT"
rm -rf "$OUT"
mkdir -p "$OUT"/{data/features,data/features_online,data/scalars,data/results,models,code}

# ---------------------------------------------------------------------------
# 1. Feature files, one gzipped CSV per run
# ---------------------------------------------------------------------------
echo "[dataport] consolidating feature files"
python3 "$ROOT/scripts/miids/consolidate_features.py" \
  --root datasets/exe_capture --out "$OUT/data/features" --tag capture
python3 "$ROOT/scripts/miids/consolidate_features.py" \
  --root datasets/exe_online --out "$OUT/data/features_online" --tag online

# ---------------------------------------------------------------------------
# 2. OMNeT++ scalar files, the network-level measurements
# ---------------------------------------------------------------------------
echo "[dataport] compressing scalar files"
for d in datasets/exe_capture/*_seed*/ datasets/exe_online/*_seed*/; do
  [ -d "$d" ] || continue
  run=$(basename "$d")
  set -- "$d"/*.sca
  [ -e "$1" ] || continue
  camp=capture; case "$d" in *exe_online*) camp=online ;; esac
  gzip -c "$1" > "$OUT/data/scalars/${camp}_${run}.sca.gz"
done

# ---------------------------------------------------------------------------
# 3. Evaluation results and trained detectors
# ---------------------------------------------------------------------------
echo "[dataport] copying results and models"
cp datasets/exe_capture/miids_results_*.json "$OUT/data/results/" 2>/dev/null || true
cp datasets/exe_online/online_results.json "$OUT/data/results/" 2>/dev/null || true
cp models/miids/{data,cache,trust,forwarding,phy}.pt "$OUT/models/" 2>/dev/null || true
cp models/miids/meta.json "$OUT/models/" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Code needed to regenerate the dataset and the paper's numbers
# ---------------------------------------------------------------------------
echo "[dataport] copying source and scripts"
mkdir -p "$OUT/code"/{src,simulations/configs,simulations/scenarios/sumo,scripts}
cp -r src/* "$OUT/code/src/" 2>/dev/null || true
cp simulations/configs/*.ini "$OUT/code/simulations/configs/" 2>/dev/null || true
cp simulations/scenarios/*.ned "$OUT/code/simulations/scenarios/" 2>/dev/null || true
cp scripts/miids/*.py scripts/miids/*.sh "$OUT/code/scripts/" 2>/dev/null || true
cp Makefile "$OUT/code/" 2>/dev/null || true

# Only the JubST inputs the campaign reads. The tree also holds the LuST
# scenario and a set of SUMO output files (emissions, tripinfo, vehroutes,
# statistics, summary), which are 100 MB of material this campaign neither
# reads nor produced. Shipping them would misrepresent what generated the data.
for f in aljubail_saudi.net.xml aljubail_saudi.rou.xml aljubail_saudi.poly.xml \
         aljubail_saudi.sumo.cfg aljubail_saudi.launchd.xml \
         aljubail_saudi.gui.xml; do
  [ -f "simulations/scenarios/sumo/$f" ] \
    && cp "simulations/scenarios/sumo/$f" "$OUT/code/simulations/scenarios/sumo/"
done

# Build products and stale logs are not source.
find "$OUT/code" -type d \( -name results -o -name 'results_*' -o -name 'planecsv*' \
     -o -name out -o -name __pycache__ \) -exec rm -rf {} + 2>/dev/null || true
find "$OUT/code" \( -name '*.log' -o -name '*.o' -o -name '*.d' -o -name '*.bak' \) \
  -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Documentation. IEEE DataPort requires a Documentation and an Instructions
#    input; these files are what gets uploaded or pasted into them.
# ---------------------------------------------------------------------------
echo "[dataport] copying documentation"
DOCS="$ROOT/VeReMiVNDN-Extension/dataport_docs"
for f in README.md DATA_DICTIONARY.md INSTRUCTIONS.md LICENSE.txt CITATION.txt; do
  [ -f "$DOCS/$f" ] && cp "$DOCS/$f" "$OUT/"
done
# The listing image reuses the paper's graphical abstract, which is already
# sized for a wide thumbnail.
GA="$ROOT/VeReMiVNDN-Extension/Preparation_of_Papers_for_IEEE_ACCESS_extension/imgs/graphical_abstract.jpg"
[ -f "$GA" ] && cp "$GA" "$OUT/dataport_image.jpg"
# SUBMIT_FORM_FIELDS.md is for the submitter, not the downloader, so it stays
# beside the package rather than inside it.

# ---------------------------------------------------------------------------
# 6. Checksums, so a downloader can verify the transfer
# ---------------------------------------------------------------------------
echo "[dataport] computing checksums"
( cd "$OUT" && find data models -type f -print0 \
    | sort -z | xargs -0 sha256sum > CHECKSUMS.sha256 )

# ---------------------------------------------------------------------------
# 7. Manifest and upload archives
# ---------------------------------------------------------------------------
echo "[dataport] writing manifest"
{
  echo "VeReMiVNDN-EXE, IEEE DataPort upload manifest"
  echo "generated $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo
  printf "%-34s %8s  %s\n" "PATH" "FILES" "SIZE"
  for d in data/features data/features_online data/scalars data/results models code; do
    [ -d "$OUT/$d" ] || continue
    printf "%-34s %8s  %s\n" "$d" \
      "$(find "$OUT/$d" -type f | wc -l)" "$(du -sh "$OUT/$d" | cut -f1)"
  done
  echo
  echo "total $(du -sh "$OUT" | cut -f1) across $(find "$OUT" -type f | wc -l) files"
} > "$OUT/MANIFEST.txt"

# DataPort takes many files, but a few archives upload far more reliably than
# hundreds of small ones over a browser session.
echo "[dataport] building upload archives"
ARC="$ROOT/VeReMiVNDN-Extension/dataport_upload"
rm -rf "$ARC"; mkdir -p "$ARC"
( cd "$OUT" && zip -qr "$ARC/VeReMiVNDN-EXE_features_capture.zip" data/features )
( cd "$OUT" && zip -qr "$ARC/VeReMiVNDN-EXE_features_online.zip" data/features_online )
( cd "$OUT" && zip -qr "$ARC/VeReMiVNDN-EXE_scalars.zip" data/scalars )
( cd "$OUT" && zip -qr "$ARC/VeReMiVNDN-EXE_models_and_results.zip" models data/results )
( cd "$OUT" && zip -qr "$ARC/VeReMiVNDN-EXE_code.zip" code )
( cd "$OUT" && zip -q "$ARC/VeReMiVNDN-EXE_documentation.zip" \
    README.md DATA_DICTIONARY.md INSTRUCTIONS.md LICENSE.txt CITATION.txt \
    MANIFEST.txt CHECKSUMS.sha256 dataport_image.jpg 2>/dev/null )
echo "[dataport] archives:"
ls -la "$ARC" | tail -n +4 | awk '{printf "  %-46s %8.1f MB\n", $9, $5/1048576}'

echo
echo "[dataport] contents:"
du -sh "$OUT"/* 2>/dev/null | sed 's/^/  /'
echo
echo "[dataport] total: $(du -sh "$OUT" | cut -f1)"
echo "[dataport] files: $(find "$OUT" -type f | wc -l)"
