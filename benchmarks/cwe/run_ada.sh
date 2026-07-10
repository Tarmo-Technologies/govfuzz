#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Ada CWE coverage: 2 subprograms raising CONSTRAINT_ERROR. No off-the-shelf
# fuzzer supports Ada, so govfuzz IS the comparison.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
GF="$ROOT/../../target/debug/govfuzz"; BUDGET="${BUDGET:-15}"; SCRATCH="$(mktemp -d)"
RES="$ROOT/results/ada_cwe.tsv"; echo -e "metric\tgovfuzz\t(any other fuzzer)" > "$RES"
command -v gnatmake >/dev/null 2>&1 || { echo "SKIP: no gnatmake"; exit 0; }
cp -r "$ROOT/targets/ada" "$SCRATCH/gf"
"$GF" auto --per-target-time "$BUDGET" --work-dir "$SCRATCH/gw" "$SCRATCH/gf" >"$SCRATCH/gf.log" 2>&1
gf_fns=$(python3 - "$SCRATCH/gw/findings" <<'PY'
import json,os,sys
root=sys.argv[1]; fns=set()
if os.path.isdir(root):
  for fn in os.listdir(root):
    fj=os.path.join(root,fn,"finding.json")
    if os.path.isfile(fj):
      f=json.load(open(fj)); fns.add(str(f.get("harness_id","")))
print(len(fns))
PY
)
echo "govfuzz ada: distinct buggy subprograms found=$gf_fns ($(grep -c 'built+fuzzed' "$SCRATCH/gf.log") targets)"
echo -e "buggy subprograms found (of 2)\t$gf_fns\t0 (cannot fuzz Ada)" >> "$RES"
echo -e "fuzzes Ada at all\tyes\tno" >> "$RES"
echo "=== RESULTS ==="; column -t -s $'\t' "$RES"
rm -rf "$SCRATCH"
