#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CWE-coverage head-to-head (C). govfuzz auto-harnesses the whole library and
# reports memory AND behavioral CWEs; libFuzzer/AFL++ are handed a harness for
# EACH vulnerable function yet only catch the crash-detectable ones.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../../target/debug/govfuzz"
LIB="$ROOT/targets/c/libcwe.c"
GCCLIB="$(dirname "$(ls -1 /usr/lib/gcc/x86_64-linux-gnu/*/libstdc++.so 2>/dev/null | sort -V | tail -1)")"
BUDGET="${BUDGET:-12}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/c_cwe.tsv"
echo -e "cwe\tfunction\tgovfuzz\tlibFuzzer\tAFL++" > "$RES"

# function -> CWE map (each function carries one CWE)
declare -A CWE=( [parse_header]=CWE-121 [set_level]=CWE-617 [load_resource]=CWE-22 \
                 [write_temp]=CWE-377 [read_secret]=CWE-522 )
# oracle/rule -> CWE map for govfuzz findings
gf_cwes() { python3 - "$1" <<'PY'
import json,os,sys
root=sys.argv[1]; m={
 "path-controlled-open-runtime":"CWE-22","toctou-runtime":"CWE-367",
 "insecure-temp-file-runtime":"CWE-377","sensitive-env-ada":"CWE-522",
 "native-assertion-contract":"CWE-617"}
found=set()
if os.path.isdir(root):
  for fn in os.listdir(root):
    fj=os.path.join(root,fn,"finding.json")
    if not os.path.isfile(fj): continue
    f=json.load(open(fj)); o=f.get("oracle"); o=o.get("name") if isinstance(o,dict) else o
    cls=f.get("classification","");
    if o in m: found.add(m[o])
    elif cls=="unhandled" or "crash" in str(cls): found.add("CWE-121")
print(" ".join(sorted(found)))
PY
}

echo ">> govfuzz: run 1 (cold) on the whole library"
WD="$SCRATCH/gw"; mkdir -p "$SCRATCH/src"; cp "$LIB" "$SCRATCH/src/"
s=$(date +%s.%N)
"$GF" auto --per-target-time "$BUDGET" --reuse-discovery --work-dir "$WD" "$SCRATCH/src" >"$SCRATCH/gf1.log" 2>&1
R1=$(echo "$(date +%s.%N) - $s"|bc -l)
GF_CWES="$(gf_cwes "$WD/findings")"
echo "   govfuzz run1 wall=${R1}s  CWEs=[$GF_CWES]"
echo ">> govfuzz: run 2 (warm, reuse harnesses)"
s=$(date +%s.%N)
"$GF" auto --per-target-time "$BUDGET" --reuse-discovery --work-dir "$WD" "$SCRATCH/src" >"$SCRATCH/gf2.log" 2>&1
R2=$(echo "$(date +%s.%N) - $s"|bc -l)
echo "   govfuzz run2 wall=${R2}s  (rebuilt harnesses: $(grep -c 'generating harness' "$SCRATCH/gf2.log"))"

# Competitors: one harness per function.
lf_finds() {  # $1=function -> echo 1 if a crash is found
  local fn="$1" d="$SCRATCH/lf_$fn"; mkdir -p "$d"
  clang -g -O1 -fsanitize=fuzzer,address -DFN="$fn" "-L$GCCLIB" "$ROOT/harnesses/libfuzzer.c" "$LIB" -o "$d/t" 2>/dev/null || { echo "BUILD?"; return; }
  ( cd "$d" && timeout $((BUDGET+8)) ./t -max_total_time="$BUDGET" -use_value_profile=1 -seed=1 >log 2>&1 )
  { compgen -G "$d/crash-*" >/dev/null 2>&1; } && echo 1 || echo 0
}
afl_finds() {
  local fn="$1" d="$SCRATCH/afl_$fn"; mkdir -p "$d/seeds" "$d/out"; cp "$ROOT/seed" "$d/seeds/"
  AFL_QUIET=1 afl-clang-fast -g -O1 -fsanitize=address -DFN="$fn" "$ROOT/harnesses/afl_persistent.c" "$LIB" -o "$d/t" 2>/dev/null || { echo "BUILD?"; return; }
  ( cd "$d" && AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 \
      timeout $((BUDGET+8)) afl-fuzz -i seeds -o out -V "$BUDGET" -- ./t >log 2>&1 )
  local sc; sc=$(grep -oE "saved_crashes *: *[0-9]+" "$d/out/default/fuzzer_stats" 2>/dev/null | grep -oE "[0-9]+$")
  [ "${sc:-0}" -gt 0 ] && echo 1 || echo 0
}

for fn in parse_header set_level load_resource write_temp read_secret; do
  cwe="${CWE[$fn]}"
  gf=$([[ " $GF_CWES " == *" $cwe "* ]] && echo 1 || echo 0)
  echo ">> competitor on $fn ($cwe)"
  lf=$(lf_finds "$fn"); afl=$(afl_finds "$fn")
  echo -e "$cwe\t$fn\t$gf\t$lf\t$afl" >> "$RES"
done

# timings row
echo -e "TIMING\tgovfuzz_run1_wall=${R1}s\tgovfuzz_run2_wall=${R2}s\t-\t-" >> "$RES"
echo "=== CWE COVERAGE (1=found) ==="
column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
