#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Stop the sweep and every govfuzz it started. Kept as a script so the pattern
# never appears in an interactive command line, where pkill would match the
# shell running it.
for pid in $(pgrep -f 'run_sweep'); do kill "$pid" 2>/dev/null; done
sleep 2
for pid in $(pgrep -f 'sweep-bin'); do kill "$pid" 2>/dev/null; done
sleep 2
for pid in $(pgrep -f 'sweep-bin'); do kill -9 "$pid" 2>/dev/null; done
sleep 1
echo "remaining: $(pgrep -cf 'sweep-bin' 2>/dev/null || echo 0)"
