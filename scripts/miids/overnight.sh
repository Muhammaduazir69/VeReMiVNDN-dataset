#!/usr/bin/env bash
#
# overnight.sh - drive the remaining VeReMiVNDN-EXE compute to completion
# unattended.
#
# Three stages, each resumable. Every stage records a marker file under
# logs/stage_*.done, so re-running the script after a crash, a reboot, or a
# manual kill picks up where it stopped rather than repeating hours of work.
#
#   1. Offline evaluation of the three split protocols, run concurrently.
#   2. Online campaign on held-out seeds 11-13, three workers in parallel,
#      each with its own TraCI port and output directories.
#   3. Result extraction: detection tables, network metrics, per-plane
#      breakdown, and the detection-latency data behind the figures.
#
# Usage: nohup scripts/miids/overnight.sh > logs/overnight.log 2>&1 &

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
mkdir -p logs

# run_one.sh exports its own PATH and LD_LIBRARY_PATH for the simulator, so
# the OMNeT++ setenv script is not needed here. Sourcing it from a detached
# session blocks, which silently stalled the first attempt at this run.
export PATH="/home/uzair/Desktop/omnet++/omnetpp-6.0.3/bin:$PATH"

log() { echo "[overnight $(date +%H:%M:%S)] $*"; }

# True while a real evaluation process is alive. This walks the process table
# and only considers python interpreters, because a pgrep on the script name
# also matches any interactive shell whose command line happens to mention it,
# and that made the wait loop below spin forever.
eval_running() {
  local p c
  for p in /proc/[0-9]*; do
    [ -r "$p/comm" ] || continue
    read -r c < "$p/comm" 2>/dev/null || continue
    case "$c" in python3*|python*) ;; *) continue ;; esac
    if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q "train_eval_miids"; then
      return 0
    fi
  done
  return 1
}

# True while an evaluation of the named protocol is alive.
eval_running_protocol() {
  local p c line
  for p in /proc/[0-9]*; do
    [ -r "$p/comm" ] || continue
    read -r c < "$p/comm" 2>/dev/null || continue
    case "$c" in python3*|python*) ;; *) continue ;; esac
    line=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$line" in *train_eval_miids*"--protocol $1"*) return 0 ;; esac
  done
  return 1
}

# ---------------------------------------------------------------------------
# Stage 1: offline evaluation, three protocols concurrently
# ---------------------------------------------------------------------------
stage_offline() {
  if [ -f logs/stage_offline.done ]; then log "stage 1 already done"; return 0; fi
  log "stage 1: offline evaluation"

  for P in run-disjoint attacker-disjoint unseen-attack; do
    OUT="datasets/exe_capture/miids_results_$P.json"
    # A results file that postdates the training script is already current.
    if [ -f "$OUT" ] && [ "$OUT" -nt scripts/miids/train_eval_miids.py ]; then
      log "  $P: up to date, skipping"; continue
    fi
    if eval_running_protocol "$P"; then
      log "  $P: already running"; continue
    fi
    # Run the protocols one at a time. Three concurrent evaluations peaked at
    # 17 GB each and the kernel OOM-killed one of them; the machine has 30 GB.
    log "  $P: running"
    python3 -u scripts/miids/train_eval_miids.py --protocol "$P" \
      --epochs 5 --max-train-rows 120000 --robust-sample 12000 \
      --out "$OUT" > "logs/eval_$P.log" 2>&1
    log "  $P: exited $?"
  done

  local ok=1
  for P in run-disjoint attacker-disjoint unseen-attack; do
    if [ -s "datasets/exe_capture/miids_results_$P.json" ]; then
      log "  $P: complete"
    else
      log "  $P: MISSING - see logs/eval_$P.log"; ok=0
    fi
  done
  [ "$ok" = 1 ] && touch logs/stage_offline.done
  log "stage 1 finished (ok=$ok)"
}

# ---------------------------------------------------------------------------
# Stage 2: online campaign on held-out seeds
# ---------------------------------------------------------------------------
stage_online() {
  if [ -f logs/stage_online.done ]; then log "stage 2 already done"; return 0; fi
  log "stage 2: online campaign, seeds 11-13"

  local i=0
  for SEED in 11 12 13; do
    local PORT=$((9990 + i)); i=$((i + 1))
    if pgrep -f "run_campaign.sh 300s $SEED" >/dev/null; then
      log "  seed $SEED: already running"; continue
    fi
    log "  seed $SEED: launching on port $PORT"
    CAPROOT="$ROOT/datasets/exe_online" TRACI_PORT=$PORT \
      setsid nohup ./scripts/miids/run_campaign.sh 300s "$SEED" \
        > "logs/online_seed${SEED}.log" 2>&1 &
    sleep 8
  done

  while pgrep -f "run_campaign.sh 300s" >/dev/null; do sleep 60; done

  local n
  n=$(find datasets/exe_online -name .done 2>/dev/null | wc -l)
  log "stage 2 finished: $n/30 runs complete"
  # Accept the stage when every run produced output; a partial campaign is
  # left un-marked so a later invocation retries the missing runs.
  [ "$n" -ge 30 ] && touch logs/stage_online.done
}

# ---------------------------------------------------------------------------
# Stage 3: extract everything the manuscript needs
# ---------------------------------------------------------------------------
stage_results() {
  log "stage 3: result extraction"

  python3 scripts/miids/extract_network_metrics.py --root datasets/exe_capture \
    --latex > logs/network_metrics.txt 2>&1 \
    && log "  network metrics written" || log "  network metrics FAILED"

  if [ -d datasets/exe_online ]; then
    python3 scripts/miids/extract_network_metrics.py --root datasets/exe_online \
      > logs/network_metrics_online.txt 2>&1 \
      && log "  online network metrics written" || log "  online metrics FAILED"
  fi

  python3 scripts/miids/make_scenario_metrics.py --latex \
    > logs/scenario_metrics.txt 2>&1 \
    && log "  per-scenario network metrics written" || log "  scenario metrics FAILED"

  python3 scripts/miids/extract_online_results.py --root datasets/exe_online \
    --latex > logs/online_detection.txt 2>&1 \
    && log "  online closed-loop results written" || log "  online results FAILED"

  for P in run-disjoint attacker-disjoint unseen-attack; do
    python3 scripts/miids/make_paper_results.py \
      --results "datasets/exe_capture/miids_results_$P.json" \
      --out-dir "VeReMiVNDN-Extension/Preparation_of_Papers_for_IEEE_ACCESS_extension/generated/$P" \
      >> logs/paper_results.txt 2>&1 || log "  tables FAILED for $P"
  done
  python3 scripts/miids/make_protocol_table.py >> logs/paper_results.txt 2>&1 \
    && log "  protocol table written" || log "  protocol table FAILED"

  python3 scripts/miids/make_paper_results.py \
    --results datasets/exe_capture/miids_results_run-disjoint.json \
    >> logs/paper_results.txt 2>&1 \
    && log "  paper tables written" || log "  paper tables FAILED"

  touch logs/stage_results.done
  log "stage 3 finished"
}

# An evaluation left over from a previous invocation still holds ~17 GB, so
# wait for it rather than starting a second one alongside it.
while eval_running; do
  log "waiting for an evaluation left running from a previous invocation"
  sleep 120
done

log "=== overnight run starting ==="
stage_offline
stage_online
stage_results
log "=== overnight run complete ==="
