#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rust head-to-head: govfuzz (builtin Rust lane, zero harness) vs cargo-fuzz
# (libFuzzer, 5-line fuzz_target! harness). Planted magic-gated index panic.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../target/debug/govfuzz"
BUDGET="${BUDGET:-20}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/rust.tsv"
echo -e "tool\tharness_loc\tcrash\tttfc_s\texecs" > "$RES"
now() { date +%s.%N; }
elapsed() { echo "$(now) - $1" | bc -l; }

# --- govfuzz: only the library crate (NO fuzz/ harness dir) ---
mkdir -p "$SCRATCH/gf"
cp "$ROOT/targets/rust/Cargo.toml" "$SCRATCH/gf/"; cp -r "$ROOT/targets/rust/src" "$SCRATCH/gf/"
s=$(now)
"$GF" auto --per-target-time "$BUDGET" --work-dir "$SCRATCH/gf/gw" "$SCRATCH/gf" >"$SCRATCH/gf.log" 2>&1 &
pid=$!; ttfc="-"; crash=0
while kill -0 "$pid" 2>/dev/null; do
  if [ "$crash" = 0 ] && compgen -G "$SCRATCH/gf/gw/findings/*" >/dev/null 2>&1; then ttfc=$(elapsed "$s"); crash=1; fi
  sleep 0.2
done
wait "$pid" 2>/dev/null
execs=$(python3 - "$SCRATCH/gf/gw/auto/run.json" <<'PY' 2>/dev/null
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
ex=0
for t in d.get("targets",[]):
    for p in t["outcome"].get("passes",[]): ex+=p.get("executions",0)
print(ex)
PY
)
echo -e "govfuzz(builtin)\t0\t$crash\t$ttfc\t${execs:-0}" >> "$RES"
echo "govfuzz rust: crash=$crash ttfc=$ttfc"; grep -iE "built\+fuzzed|finding|failed" "$SCRATCH/gf.log" | head -3

# --- cargo-fuzz: build (untimed) then run (timed) ---
cp -r "$ROOT/targets/rust" "$SCRATCH/cf"
( cd "$SCRATCH/cf" && cargo +nightly fuzz build target >"$SCRATCH/cf_build.log" 2>&1 )
if [ $? -ne 0 ]; then echo -e "cargo-fuzz\t5\tBUILD_FAIL\t-\t-" >> "$RES"; tail -5 "$SCRATCH/cf_build.log"; else
  s=$(now)
  ( cd "$SCRATCH/cf" && timeout $((BUDGET+30)) cargo +nightly fuzz run target -- -max_total_time="$BUDGET" -use_value_profile=1 -seed=1 >"$SCRATCH/cf_run.log" 2>&1 ); rc=$?
  ttfc=$(elapsed "$s"); crash=0
  if compgen -G "$SCRATCH/cf/fuzz/artifacts/target/crash-*" >/dev/null 2>&1 || { [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; }; then crash=1; else ttfc="-"; fi
  execs=$(grep -oE "stat::number_of_executed_units: *[0-9]+" "$SCRATCH/cf_run.log" | grep -oE "[0-9]+" | tail -1)
  echo -e "cargo-fuzz\t5\t$crash\t$ttfc\t${execs:-0}" >> "$RES"
  echo "cargo-fuzz: crash=$crash ttfc=$ttfc"
fi
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
