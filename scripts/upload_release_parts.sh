#!/usr/bin/env bash
#
# upload_release_parts.sh - upload the release assets one part at a time.
#
# A single 350 MB asset over a sub-1 Mbit/s uplink has no resume: gh streams the
# whole body, and if the connection stalls the entire transfer is lost. It did
# stall once, after roughly fifty minutes. The archives are therefore split into
# 48 MB parts, so a stall costs one part rather than the whole file, and each
# attempt runs under `timeout` so a hung socket is retried instead of hanging
# forever.
#
# Parts are reassembled by the downloader with:
#   cat veremivndn_ml.tar.gz.part* > veremivndn_ml.tar.gz
set -uo pipefail

REPO=Muhammaduazir69/VeReMiVNDN-dataset
TAG=v1.0.0
PARTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/release/parts"
ATTEMPT_TIMEOUT=1200     # 20 min per part; a 48 MB part needs ~10 at 0.09 MB/s
MAX_TRIES=6

uploaded() {
  gh release view "$TAG" -R "$REPO" --json assets \
    -q '.assets[].name' 2>/dev/null
}

have=$(uploaded)
for f in "$PARTS"/*; do
  name=$(basename "$f")
  if grep -qxF "$name" <<<"$have"; then
    echo "[up] skip $name (already uploaded)"
    continue
  fi
  ok=0
  for try in $(seq 1 $MAX_TRIES); do
    echo "[up] $name attempt $try/$MAX_TRIES ($(du -h "$f" | cut -f1))"
    if timeout "$ATTEMPT_TIMEOUT" gh release upload "$TAG" "$f" \
         -R "$REPO" --clobber 2>&1 | tail -2; then
      # Confirm against the API rather than trusting the exit status.
      if uploaded | grep -qxF "$name"; then
        echo "[up] $name OK"; ok=1; break
      fi
      echo "[up] $name reported success but is not listed; retrying"
    else
      echo "[up] $name failed or timed out; retrying"
    fi
    sleep 15
  done
  [ "$ok" -eq 1 ] || echo "[up] GIVING UP on $name"
  have=$(uploaded)
done

echo
echo "[up] final asset list:"
gh release view "$TAG" -R "$REPO" --json assets \
  -q '.assets[] | "  " + .name + "  " + ((.size/1048576)|floor|tostring) + " MB"' 2>/dev/null
