#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# C head-to-head: libFuzzer vs AFL++ vs govfuzz(builtin) vs govfuzz(afl++) on
# planted-bug targets with a UNIFORM entry `target_one_input`. Measures, per tool:
# crash-found, wall time-to-first-crash (TTFC), executions, exec/s. govfuzz needs
# ZERO hand-written harness; the others need the harnesses under harnesses/.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../target/debug/govfuzz"
BUDGET="${BUDGET:-25}"
SCRATCH="$(mktemp -d)"
RES="$ROOT/results/c.tsv"
echo -e "target\ttool\tharness_loc\tcrash\tttfc_s\texecs\texecs_per_s" > "$RES"

now() { date +%s.%N; }
elapsed() { echo "$(now) - $1" | bc -l; }

# clang's libFuzzer runtime is C++ and pulls -lstdc++, but the gcc version dir
# isn't on clang's default linker search path here — add it.
GCCLIB="$(dirname "$(ls -1 /usr/lib/gcc/x86_64-linux-gnu/*/libstdc++.so 2>/dev/null | sort -V | tail -1)")"
LSTDCXX="${GCCLIB:+-L$GCCLIB}"

run_libfuzzer() {
  local tgt="$1" name="$2" dir="$SCRATCH/$name/lf"; mkdir -p "$dir"
  clang -g -O1 -fsanitize=fuzzer,address $LSTDCXX "$ROOT/harnesses/libfuzzer.c" "$tgt" -o "$dir/t" 2>"$dir/build.log" || { echo -e "$name\tlibFuzzer\t6\tBUILD_FAIL\t-\t-\t-" >>"$RES"; return; }
  local s; s=$(now); local rc
  # libFuzzer at its best: value-profile on (its cmplog-equivalent).
  ( cd "$dir" && timeout $((BUDGET+10)) ./t -max_total_time="$BUDGET" -use_value_profile=1 -print_final_stats=1 -seed=1 >log 2>&1 ); rc=$?
  local t; t=$(elapsed "$s")
  local crash execs eps
  # libFuzzer exits immediately on a crash (rc != 0, != 124-timeout) and writes a
  # crash-* artifact; either signal => crash, and the wall time is the TTFC.
  if compgen -G "$dir/crash-*" >/dev/null 2>&1 || { [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; }; then crash=1; else crash=0; t="-"; fi
  execs=$(grep -oE "stat::number_of_executed_units: *[0-9]+" "$dir/log" | grep -oE "[0-9]+" | tail -1)
  [ -z "$execs" ] && execs=$(grep -oE "^#[0-9]+" "$dir/log" | tr -d '#' | tail -1)
  eps=$(grep -oE "exec/s: *[0-9]+" "$dir/log" | grep -oE "[0-9]+" | tail -1)
  # libFuzzer averages exec/s to 0 when it crashes in under a second; derive it.
  if { [ -z "$eps" ] || [ "$eps" = 0 ]; } && [ "$crash" = 1 ] && [ -n "$execs" ]; then
    eps=$(printf '%.0f' "$(echo "$execs / $t" | bc -l)" 2>/dev/null)
  fi
  echo -e "$name\tlibFuzzer\t6\t$crash\t${t:-?}\t${execs:-0}\t${eps:-0}" >>"$RES"
}

run_afl() {
  local tgt="$1" name="$2" dir="$SCRATCH/$name/afl"; mkdir -p "$dir/seeds" "$dir/out"
  cp "$ROOT/seeds/seed" "$dir/seeds/"
  AFL_QUIET=1 afl-clang-fast -g -O1 -fsanitize=address "$ROOT/harnesses/afl_persistent.c" "$tgt" -o "$dir/t" 2>/dev/null || { echo -e "$name\tAFL++\t13\tBUILD_FAIL\t-\t-\t-" >>"$RES"; return; }
  # AFL++ at its best: a CMPLOG (input-to-state / RedQueen) instrumented binary
  # passed with `-c`, so the comparison isn't against a hobbled config.
  AFL_QUIET=1 AFL_LLVM_CMPLOG=1 afl-clang-fast -g -O1 -fsanitize=address "$ROOT/harnesses/afl_persistent.c" "$tgt" -o "$dir/t.cmplog" 2>/dev/null
  ( cd "$dir" && AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 \
      timeout $((BUDGET+10)) afl-fuzz -i seeds -o out -V "$BUDGET" -c ./t.cmplog -- ./t >log 2>&1 )
  local fs="$dir/out/default/fuzzer_stats" crash=0 ttfc="-" execs=0 eps=0
  if [ -f "$fs" ]; then
    local sc; sc=$(grep -oE "saved_crashes *: *[0-9]+" "$fs" | grep -oE "[0-9]+$")
    [ "${sc:-0}" -gt 0 ] && crash=1
    execs=$(grep -oE "execs_done *: *[0-9]+" "$fs" | grep -oE "[0-9]+$")
    eps=$(grep -oE "execs_per_sec *: *[0-9.]+" "$fs" | grep -oE "[0-9.]+$")
    if [ "$crash" = 1 ]; then
      local lc st; lc=$(grep -oE "last_crash *: *[0-9]+" "$fs" | grep -oE "[0-9]+$"); st=$(grep -oE "start_time *: *[0-9]+" "$fs" | grep -oE "[0-9]+$")
      [ -n "$lc" ] && [ -n "$st" ] && ttfc=$((lc - st))
    fi
  fi
  echo -e "$name\tAFL++\t13\t$crash\t$ttfc\t${execs:-0}\t${eps:-0}" >>"$RES"
}

run_govfuzz() {
  local tgt="$1" name="$2" engine="$3"
  local dir="$SCRATCH/$name/gf_${engine}"; mkdir -p "$dir/src"
  cp "$tgt" "$dir/src/"
  local s; s=$(now)
  "$GF" auto --engine "$engine" --per-target-time "$BUDGET" --work-dir "$dir/gw" "$dir/src" >"$dir/log" 2>&1 &
  local pid=$!
  local ttfc="-" crash=0
  # Record end-to-end TTFC (source -> first crash, incl. auto-build) when the
  # first finding appears, but let govfuzz finish so run.json finalizes (execs).
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$crash" = 0 ] && compgen -G "$dir/gw/findings/*" >/dev/null 2>&1; then ttfc=$(elapsed "$s"); crash=1; fi
    sleep 0.2
  done
  wait "$pid" 2>/dev/null
  # If it finished without us catching the finding, read run.json.
  local rj="$dir/gw/auto/run.json" execs=0 eps=0
  if [ -f "$rj" ]; then
    read -r crash2 execs eps < <(python3 - "$rj" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
f=0;ex=0;el=0.0
for t in d.get("targets",[]):
    for p in t["outcome"].get("passes",[]):
        f+=len(p.get("findings",[])); ex+=p.get("executions",0); el+=p.get("elapsed_secs",0) or 0
eps=int(ex/el) if el>0 else 0
print(1 if f>0 else 0, ex, eps)
PY
)
    [ "${crash2:-0}" = 1 ] && crash=1
  fi
  echo -e "$name\tgovfuzz($engine)\t0\t$crash\t$ttfc\t${execs:-0}\t${eps:-0}" >>"$RES"
}

for tgt in "$ROOT"/targets/c/*.c; do
  name="$(basename "$tgt" .c)"
  echo ">> $name"
  run_libfuzzer "$tgt" "$name"
  run_afl "$tgt" "$name"
  run_govfuzz "$tgt" "$name" builtin
  run_govfuzz "$tgt" "$name" afl++
done
echo "=== RESULTS ($RES) ==="
column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
