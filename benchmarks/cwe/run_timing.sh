#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# First-run (cold) vs second-run (warm/reuse) time-to-first-finding for govfuzz,
# versus the competitor's fuzz-only time. Run in ISOLATION for accurate timing.
#   - memory bug (CWE-121): both tools find it -> the fair head-to-head.
#   - behavioral bug (CWE-22): only govfuzz finds it -> competitor = "not found".
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../../target/debug/govfuzz"
GCCLIB="$(dirname "$(ls -1 /usr/lib/gcc/x86_64-linux-gnu/*/libstdc++.so 2>/dev/null | sort -V | tail -1)")"
BUDGET=20
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/timing.tsv"
echo -e "bug\tgovfuzz_run1_cold_s\tgovfuzz_run2_warm_s\tlibFuzzer_s\tnote" > "$RES"

gf_ttfc() {  # $1=src-dir(contains one .c) $2=workdir : echo seconds to first finding (no build on warm if WD exists)
  local src="$1" wd="$2"; rm -rf "$wd/findings"
  local s=$(date +%s.%N)
  "$GF" auto --per-target-time "$BUDGET" --reuse-discovery --work-dir "$wd" "$src" >/dev/null 2>&1 &
  local pid=$!; local t="NF"
  while kill -0 "$pid" 2>/dev/null; do compgen -G "$wd/findings/*" >/dev/null 2>&1 && { t=$(echo "$(date +%s.%N) - $s"|bc -l); break; }; sleep 0.02; done
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; echo "$t"
}
lf_ttfc() {  # $1=function : echo seconds to crash, or NF
  local fn="$1"; local d="$SCRATCH/lf_$fn"; mkdir -p "$d"
  clang -g -O1 -fsanitize=fuzzer,address -DFN="$fn" "-L$GCCLIB" "$ROOT/harnesses/libfuzzer.c" "$ROOT/targets/c/libcwe.c" -o "$d/t" 2>/dev/null || { echo "BUILD?"; return; }
  local s=$(date +%s.%N)
  ( cd "$d" && timeout $((BUDGET+5)) ./t -max_total_time="$BUDGET" -use_value_profile=1 -seed=1 >log 2>&1 )
  if compgen -G "$d/crash-*" >/dev/null 2>&1; then echo "$(echo "$(date +%s.%N) - $s"|bc -l)"; else echo "NF"; fi
}

# CWE-121 memory: extract just parse_header into its own dir so govfuzz fuzzes one target.
mkdir -p "$SCRATCH/mem"; awk '/CWE-121/{p=1} p&&/^int parse_header/{f=1} f{print} f&&/^}/{exit}' "$ROOT/targets/c/libcwe.c" > "$SCRATCH/mem/m.c"
printf '#include <stddef.h>\n#include <string.h>\n%s\n' "$(cat "$SCRATCH/mem/m.c")" > "$SCRATCH/mem/m.c.tmp" && mv "$SCRATCH/mem/m.c.tmp" "$SCRATCH/mem/m.c"
WDm="$SCRATCH/wd_mem"
m1=$(gf_ttfc "$SCRATCH/mem" "$WDm"); m2=$(gf_ttfc "$SCRATCH/mem" "$WDm"); mlf=$(lf_ttfc parse_header)
echo -e "CWE-121 (memory, both find)\t$m1\t$m2\t$mlf\tfair head-to-head; libFuzzer pre-built harness" >> "$RES"

# CWE-22 path-control: only govfuzz finds; libFuzzer reports nothing (no crash).
mkdir -p "$SCRATCH/beh"; awk '/CWE-22:/{p=1} p&&/^int load_resource/{f=1} f{print} f&&/^}/{exit}' "$ROOT/targets/c/libcwe.c" > "$SCRATCH/beh/b.c"
printf '#include <stddef.h>\n#include <string.h>\n#include <fcntl.h>\n#include <unistd.h>\n%s\n' "$(cat "$SCRATCH/beh/b.c")" > "$SCRATCH/beh/b.c.tmp" && mv "$SCRATCH/beh/b.c.tmp" "$SCRATCH/beh/b.c"
WDb="$SCRATCH/wd_beh"
b1=$(gf_ttfc "$SCRATCH/beh" "$WDb"); b2=$(gf_ttfc "$SCRATCH/beh" "$WDb"); blf=$(lf_ttfc load_resource)
echo -e "CWE-22 (path-control, govfuzz only)\t$b1\t$b2\t$blf\tlibFuzzer cannot detect (no crash)" >> "$RES"

echo "=== TIMING (seconds to first finding) ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
