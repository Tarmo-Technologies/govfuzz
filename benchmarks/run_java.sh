#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Java head-to-head: govfuzz (auto-harnessed, drives Jazzer, zero harness) vs
# Jazzer (hand-written 5-line fuzzerTestOneInput harness). Same engine (Jazzer);
# the difference is who writes the harness. Planted magic-gated AIOOBE.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../target/debug/govfuzz"
BUDGET="${BUDGET:-20}"
JAZZER="${JAZZER:-/opt/jazzer/jazzer}"
JAZZER_JAR="${JAZZER_JAR:-/opt/jazzer/jazzer_standalone.jar}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/java.tsv"
echo -e "tool\tharness_loc\tcrash\tttfc_s\texecs" > "$RES"
now() { date +%s.%N; }
elapsed() { echo "$(now) - $1" | bc -l; }

# --- govfuzz: the Maven project, NO hand-written Jazzer harness ---
cp -r "$ROOT/targets/java" "$SCRATCH/gf"
s=$(now)
"$GF" auto --per-target-time "$BUDGET" --work-dir "$SCRATCH/gf/gw" "$SCRATCH/gf" >"$SCRATCH/gf.log" 2>&1 &
pid=$!; ttfc="-"; crash=0
while kill -0 "$pid" 2>/dev/null; do
  if [ "$crash" = 0 ] && compgen -G "$SCRATCH/gf/gw/findings/*" >/dev/null 2>&1; then ttfc=$(elapsed "$s"); crash=1; fi
  sleep 0.2
done
wait "$pid" 2>/dev/null
echo -e "govfuzz(jazzer)\t0\t$crash\t$ttfc\t-" >> "$RES"
echo "govfuzz java: crash=$crash ttfc=$ttfc"; grep -iE "built\+fuzzed|finding|failed|jazzer" "$SCRATCH/gf.log" | head -3

# --- Jazzer: compile the target + the hand-written harness, then fuzz ---
mkdir -p "$SCRATCH/jz/classes"
if javac -cp "$JAZZER_JAR" -d "$SCRATCH/jz/classes" \
      "$ROOT/targets/java/src/com/acme/FrameParser.java" "$ROOT/harnesses/TargetFuzzer.java" 2>"$SCRATCH/jz_build.log"; then
  s=$(now)
  ( cd "$SCRATCH/jz" && timeout $((BUDGET+15)) "$JAZZER" --cp=classes --target_class=TargetFuzzer \
       -max_total_time="$BUDGET" -seed=1 >run.log 2>&1 ); rc=$?
  ttfc=$(elapsed "$s"); crash=0
  if compgen -G "$SCRATCH/jz/crash-*" >/dev/null 2>&1 || grep -qiE "Java Exception|SEVERE: |ArrayIndexOutOfBounds" "$SCRATCH/jz/run.log" || { [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; }; then crash=1; else ttfc="-"; fi
  execs=$(grep -oE "stat::number_of_executed_units: *[0-9]+|^#[0-9]+" "$SCRATCH/jz/run.log" | grep -oE "[0-9]+" | tail -1)
  echo -e "Jazzer\t5\t$crash\t$ttfc\t${execs:-?}" >> "$RES"
  echo "jazzer: crash=$crash ttfc=$ttfc"
else
  echo -e "Jazzer\t5\tBUILD_FAIL\t-\t-" >> "$RES"; tail -5 "$SCRATCH/jz_build.log"
fi
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
