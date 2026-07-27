#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Targeted A/B for the configure-style `#error` guard recovery.
#
# `residual_errors.py` named the class and the two corpus projects that carry it:
# WindTerm (libssh's `#error "no strtoull function found"` /
# `"Your system must provide a __func__ macro"`) and ImageMagick (`#error "you
# should set MAGICKCORE_QUANTUM_DEPTH"`). A whole-corpus A/B is the wrong
# instrument for a class this specific — it would spend an hour to move a number
# by the size of its own noise floor. Run the two projects that exhibit it, with
# the SAME flags, under two PINNED binaries, and compare directly.
#
#   BEFORE=/home/ubuntu/govfuzz-sweep-bin/govfuzz-force3 \
#   AFTER=/home/ubuntu/govfuzz-sweep-bin/govfuzz-0.2.21 sh config_guard_ab.sh
#
# Distinguish the binaries by md5sum, never by `--version` — it is identical
# across rebuilds.
set -e
cd "$(dirname "$0")"

BEFORE="${BEFORE:-/home/ubuntu/govfuzz-sweep-bin/govfuzz-force3}"
AFTER="${AFTER:-/home/ubuntu/govfuzz-sweep-bin/govfuzz-0.2.21}"
OUT="${OUT:-/tmp/config-guard-ab}"
CORPUS=/home/ubuntu/govfuzz-corpus-500/c

md5sum "$BEFORE" "$AFTER"
mkdir -p "$OUT"

for repo in kingToolbox__WindTerm ImageMagick__ImageMagick; do
    url=$(awk -F'\t' -v r="$(echo "$repo" | sed 's/__/\//')" '$2 == r {print $3}' corpus.tsv pool.tsv | head -1)
    [ -d "$CORPUS/$repo" ] || git clone --depth 1 --quiet --no-tags "$url" "$CORPUS/$repo"
    for arm in before after; do
        bin=$BEFORE
        [ "$arm" = after ] && bin=$AFTER
        work="$OUT/$repo.$arm"
        rm -rf "$work"
        echo "== $repo $arm =="
        "$bin" auto "$CORPUS/$repo" --work-dir "$work" \
            --campaign-time 90 --per-target-time 3 \
            --max-attempts 10 --max-repair-rounds 4 --jobs 2 \
            --profile external-tools --force >"$OUT/$repo.$arm.log" 2>&1 || true
        python3 - "$work/auto/run.json" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except OSError:
    print("   no run.json"); raise SystemExit
s = data["summary"]
print(f"   attempted={s['discovered']} built_and_fuzzed={s['built_and_fuzzed']} "
      f"built={s['built']} report_only={s.get('report_only', 0)}")
guards = [r for t in data.get("targets", [])
          for r in (t["outcome"].get("repairs") or [])
          if r.get("kind") == "config_guard_define"]
if guards:
    print("   config-guard defines: "
          + ", ".join(sorted({f"{g['name']}={g['value']}" for g in guards})))
PY
    done
done
