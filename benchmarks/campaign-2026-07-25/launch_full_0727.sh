#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The 2026-07-27 full sweep: same budgets and same corpus as launch_full.sh, but
# written to its own results dir so the 07-26 baseline in results/ survives to be
# compared against. Fast lanes are NOT reordered here — the wave is the whole
# corpus in corpus.tsv order, so a partial capture is still a fair per-lane
# sample of every lane that has finished.
cd "$(dirname "$0")" || exit 1
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz-0727head}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
mkdir -p results-0727
nohup python3 -u run_sweep.py \
    --wave FULL \
    --per-lane 60 \
    --corpus-only \
    --jobs 6 \
    --campaign-time 90 \
    --per-target-time 3 \
    --max-attempts 10 \
    --max-repair-rounds 4 \
    --auto-slack 420 \
    --results-dir results-0727 \
    --rerun \
    > /tmp/full-0727.log 2>&1 &
echo "launched pid $!"
