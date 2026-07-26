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
#   aggregate.py --results results --compare results-force2
#
# Same corpus, same budgets, same pinned binary as the baseline — the only
# variable is the flag. What --force produces is recorded as stub-only when it
# fuzzes blind stubs rather than the project's own code, so the comparison shows
# both what it recovers and what that recovery is worth.
# The force arm MUST run the SAME binary that produced the baseline. Re-pinning
# first would fold unrelated code changes into the delta and make it
# unattributable — the same mistake as rebuilding mid-sweep.
cd "$(dirname "$0")" || exit 1
GOVFUZZ_BIN="${GOVFUZZ_BIN:-/home/ubuntu/govfuzz-sweep-bin/govfuzz-twophase}"
export GOVFUZZ_BIN
"$GOVFUZZ_BIN" --version >/dev/null 2>&1 || { echo "pinned binary missing: $GOVFUZZ_BIN"; exit 1; }
echo "force arm binary: $("$GOVFUZZ_BIN" --version)"
mkdir -p results-force2
# `--repos force-repos.tsv`: only the 126 projects whose baseline had at least one
# `unsupported_params` target. On the other 100 in these lanes --force is a no-op
# by construction, so measuring them would only add wall-clock and dilute the
# delta. `--corpus-only` is deliberately absent: the filter already pins the exact
# set, so the pool cannot pad it, and two of the 126 are pool replacements.
# `--surfaces fuzz`: sloc/static/sbom do not depend on the flag.
nohup python3 -u run_sweep.py \
    --wave FORCE \
    --per-lane 60 \
    --only c,cpp,rust,go,csharp \
    --repos force-repos.tsv \
    --results-dir results-force2 \
    --auto-force \
    --surfaces fuzz \
    --jobs 6 \
    --campaign-time 90 \
    --per-target-time 3 \
    --max-attempts 10 \
    --max-repair-rounds 4 \
    --auto-slack 420 \
    --rerun \
    > /tmp/force-ab2.log 2>&1 &
echo "launched pid $!"
