#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run the sweep for a subset of lanes, resuming (never wiping) results.
#
# The lane order matters for a long campaign: C and C++ are the slowest lanes by
# an order of magnitude, so running them first leaves fourteen languages
# unmeasured for hours. Running the fast lanes first gives breadth early; the
# budget and the pinned binary are identical either way, so the rows are
# comparable no matter what order they were produced in.
#
#   LANES=rust,go,python sh launch_lanes.sh
cd "$(dirname "$0")" || exit 1
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
nohup python3 -u run_sweep.py \
    --wave FULL \
    --per-lane 60 \
    --corpus-only \
    --only "${LANES:?set LANES=a,b,c}" \
    --jobs "${JOBS:-6}" \
    --campaign-time 90 \
    --per-target-time 3 \
    --max-attempts 10 \
    --max-repair-rounds 4 \
    --auto-slack 420 \
    >> /tmp/full.log 2>&1 &
echo "launched lanes=${LANES} pid $!"
