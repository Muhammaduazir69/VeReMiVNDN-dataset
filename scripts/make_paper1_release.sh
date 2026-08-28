#!/usr/bin/env bash
#
# make_paper1_release.sh - assemble the public release for the VeReMiVNDN
# dataset and fill in every documented figure from the data itself.
#
# The documentation carries {{PLACEHOLDER}} tokens rather than hand written
# counts, so a number in the README can never drift from what the release
# actually contains. This script computes them and substitutes them.
#
# Usage: scripts/make_paper1_release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CAMPAIGN="datasets/paper1_veremivndn"
REL="release"
REPO="https://github.com/Muhammaduazir69/VeReMiVNDN-dataset"
TAG="v1.0.0"

echo "[rel] consolidating per-node CSVs into one file per run"
rm -rf "$REL"; mkdir -p "$REL/data/scalars"
python3 scripts/consolidate_paper1.py --root "$CAMPAIGN" --out "$REL/data"

echo "[rel] compressing scalar files"
for d in "$CAMPAIGN"/*/; do
  run=$(basename "$d")
  [ -f "$d/.done" ] || continue
  set -- "$d"/*.sca
  [ -e "$1" ] || continue
  gzip -c "$1" > "$REL/data/scalars/${run}.sca.gz"
done

echo "[rel] computing release statistics"
python3 scripts/paper1_stats.py --release "$REL" --campaign "$CAMPAIGN" \
  > "$REL/stats.json"

# The documentation files in the working tree are generated from templates
# that still carry their {{PLACEHOLDER}} tokens. Restoring them first makes this
# script safe to re-run: a second pass substitutes into fresh templates rather
# than into already substituted text.
echo "[rel] restoring documentation templates"
cp .doc_templates/README.md README.md
cp .doc_templates/docs/index.html docs/index.html
cp .doc_templates/docs/DATA_DICTIONARY.md docs/DATA_DICTIONARY.md
cp .doc_templates/docs/INSTRUCTIONS.md docs/INSTRUCTIONS.md
cp .doc_templates/RELEASE_NOTES.md RELEASE_NOTES.md

echo "[rel] filling documentation placeholders"
python3 - "$REL/stats.json" "$REPO" "$TAG" <<'PY'
import json, re, sys, pathlib
stats = json.load(open(sys.argv[1]))
repo, tag = sys.argv[2], sys.argv[3]

subs = dict(stats["subs"])
subs["RELEASE_URL"]    = f"{repo}/releases/latest"
subs["RELEASE_URL_DL"] = f"{repo}/releases/download/{tag}"

for f in ["README.md", "docs/index.html", "docs/DATA_DICTIONARY.md",
          "docs/INSTRUCTIONS.md", "RELEASE_NOTES.md"]:
    p = pathlib.Path(f)
    if not p.exists():
        continue
    t = p.read_text()
    for k, v in subs.items():
        t = t.replace("{{%s}}" % k, str(v))
    p.write_text(t)
    # Match only our own token shape. A bare "{{" also occurs in the BibTeX
    # entry these files carry, so testing for that alone reports every file
    # as unfilled.
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", t)))
    print(f"  {f}: {'UNFILLED ' + ' '.join(left) if left else 'ok'}")
PY

echo "[rel] building archives"
mkdir -p "$REL/dist"
tar czf "$REL/dist/veremivndn_ml.tar.gz"      -C "$REL" data/ml
tar czf "$REL/dist/veremivndn_plane.tar.gz"   -C "$REL" data/plane
tar czf "$REL/dist/veremivndn_scalars.tar.gz" -C "$REL" data/scalars
cp docs/DATA_DICTIONARY.md docs/INSTRUCTIONS.md LICENSE CITATION.cff "$REL/dist/" 2>/dev/null || true

echo "[rel] checksums"
( cd "$REL/dist" && sha256sum ./* > CHECKSUMS.sha256 2>/dev/null || true )

echo
echo "[rel] release assets:"
ls -la "$REL/dist" | tail -n +4 | awk '{printf "  %-40s %8.1f MB\n", $9, $5/1048576}'
echo "[rel] total: $(du -sh "$REL/dist" | cut -f1)"
