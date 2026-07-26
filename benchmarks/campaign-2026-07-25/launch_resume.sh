#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Resume the pinned-500 sweep: keeps every result row already written and only
# runs the projects that have none, so tuning concurrency mid-campaign costs
# nothing. Same pinned binary, so the numbers stay comparable.
cd "$(dirname "$0")" || exit 1
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
nohup python3 -u run_sweep.py \
    --wave FULL \
    --per-lane 60 \
    --corpus-only \
    --jobs "${JOBS:-6}" \
    --campaign-time 180 \
    --per-target-time 4 \
    --max-attempts 20 \
    --max-repair-rounds 6 \
    --auto-slack 600 \
    >> /tmp/full.log 2>&1 &
echo "resumed pid $!"
