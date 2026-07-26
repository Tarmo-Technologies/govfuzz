#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Close out the campaign once the sweep is done:
#   1. pin the final binary (all fixes in)
#   2. re-measure the rows removed because the pinned binary predated the
#      discovery stack-overflow fix — the same projects, the fixed tool
#   3. refresh the SLOC surface for every project, merging into existing rows
#   4. aggregate, chart, publish
# Each step waits for the previous runner to exit, so this is safe to start
# while the sweep is still finishing.
set -e
cd "$(dirname "$0")"

# Match on the process NAME plus its arguments, never on a bare cmdline
# pattern: `pgrep -f run_sweep` also matches any shell whose command line
# mentions it, including this script's own waiters, so the wait never ended.
wait_for_runner() {
    while [ "$(ps -eo comm,args | awk '$1=="python3" && /run_sweep/' | wc -l)" -gt 0 ]; do
        sleep 30
    done
    sleep 5
}

echo "== waiting for the sweep to finish"
wait_for_runner

echo "== pinning the final binary"
cp ../../target/release/govfuzz /home/ubuntu/govfuzz-sweep-bin/govfuzz
/home/ubuntu/govfuzz-sweep-bin/govfuzz --version

echo "== re-measuring the rows that aborted under the older binary"
GOVFUZZ_BIN=/home/ubuntu/govfuzz-sweep-bin/govfuzz python3 -u run_sweep.py \
    --wave FIXED --per-lane 60 --corpus-only --jobs 6 \
    --campaign-time 90 --per-target-time 3 --max-attempts 10 \
    --max-repair-rounds 4 --auto-slack 420 >> /tmp/full.log 2>&1 || true
wait_for_runner

echo "== refreshing the SLOC surface across the corpus"
GOVFUZZ_BIN=/home/ubuntu/govfuzz-sweep-bin/govfuzz python3 -u run_sweep.py \
    --wave SLOC --per-lane 60 --corpus-only --surfaces sloc --merge --rerun \
    --jobs 6 > /tmp/sloc-refresh.log 2>&1 || true
wait_for_runner

echo "== aggregating"
python3 aggregate.py --blockers 20 --json rollup.json | tail -30
python3 charts.py
python3 publish.py
echo "== campaign closed out"
