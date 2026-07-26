#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Launch the full pinned-500 sweep in the background with the campaign budgets.
cd "$(dirname "$0")" || exit 1
# Pin the binary: rebuilding mid-sweep would silently mix tool versions
# across the corpus and make the aggregate numbers unattributable.
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
rm -f results/*.json
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
    --rerun \
    > /tmp/full.log 2>&1 &
echo "launched pid $!"
