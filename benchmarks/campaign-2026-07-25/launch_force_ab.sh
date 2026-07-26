#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Measure what `--force` actually buys.
#
# The sweep's own blocker table says the largest REAL govfuzz limit (as opposed
# to uninstalled dependencies) is parameters whose types the project never
# defines — 80 in C, 58 in Go, 47 in Rust, 38 in C++, plus 34 unconstructible C#
# receivers. `--force` exists precisely to drive those anyway, and the sweep
# never once passed it, so the size of that lever was documented but unmeasured.
#
# This wave re-measures the five lanes that carry those blockers with --force on,
# writing to a SEPARATE results dir so the baseline it will be compared against
# is not overwritten:
#
#   aggregate.py --results results --compare results-force
#
# Same corpus, same budgets, same pinned binary as the baseline — the only
# variable is the flag. What --force produces is recorded as stub-only when it
# fuzzes blind stubs rather than the project's own code, so the comparison shows
# both what it recovers and what that recovery is worth.
cd "$(dirname "$0")" || exit 1
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
mkdir -p results-force
nohup python3 -u run_sweep.py \
    --wave FORCE \
    --per-lane 60 \
    --only c,cpp,rust,go,csharp \
    --corpus-only \
    --results-dir results-force \
    --auto-force \
    --surfaces fuzz \
    --jobs 6 \
    --campaign-time 90 \
    --per-target-time 3 \
    --max-attempts 10 \
    --max-repair-rounds 4 \
    --auto-slack 420 \
    --rerun \
    > /tmp/force-ab.log 2>&1 &
echo "launched pid $!"
