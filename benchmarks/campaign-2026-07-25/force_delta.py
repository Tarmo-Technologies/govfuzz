#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Report what `--force` bought, separating real reach from stub-only reach.

`--force` drives a parameter govfuzz could not construct — an opaque handle, a
type the project never defines — by fabricating a value for it. That can move a
target from `unsupported_params` to `built_and_fuzzed`, which looks like pure
gain, but a harness whose parameters are fabricated may exercise only govfuzz's
own stubs and never the project's code. govfuzz records that case separately
(`fuzzed_stub_only`), and a comparison that folds the two together would report
the lever as bigger than it is.

So this prints three things per lane, over only the projects present in BOTH
arms:
  - real reach:  built_and_fuzzed that is NOT stub-only
  - stub-only:   built_and_fuzzed whose harness fuzzed blind stubs
  - findings:    whether forcing actually surfaced anything

Usage:
  force_delta.py [--baseline results] [--forced results-force]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

STATUSES = [
    "built_and_fuzzed",
    "fuzzed_stub_only",
    "failed_build",
    "unsupported_params",
    "report_only",
    "unrecoverable_link",
    "unrecoverable_runtime",
    "skipped",
]


def load(results: Path) -> dict[str, dict]:
    """Row per repo that actually carries a fuzz measurement."""
    rows: dict[str, dict] = {}
    for path in sorted(results.glob("*.json")):
        try:
            row = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        auto = (row.get("surfaces") or {}).get("auto") or {}
        if auto.get("summary"):
            rows[row["repo"]] = row
    return rows


def tally(row: dict) -> dict:
    """Per-project counts, splitting fuzzed reach into real vs stub-only."""
    auto = (row.get("surfaces") or {}).get("auto") or {}
    summary = auto.get("summary") or {}
    out = {key: summary.get(key, 0) or 0 for key in STATUSES}
    out["findings"] = summary.get("findings", 0) or 0
    out["attempted"] = sum(out[key] for key in STATUSES)
    # `stub_only` is per TARGET, so read the target rows rather than trusting a
    # summary field: a project can have both kinds at once.
    stub_only = 0
    for target in auto.get("targets") or []:
        if not isinstance(target, dict):
            continue
        if target.get("outcome") == "built_and_fuzzed" and target.get("stub_only"):
            stub_only += 1
    out["stub_only_targets"] = stub_only
    out["real_fuzzed"] = max(0, out["built_and_fuzzed"] - stub_only)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=Path, default=HERE / "results")
    ap.add_argument("--forced", type=Path, default=HERE / "results-force")
    args = ap.parse_args()

    base, forced = load(args.baseline), load(args.forced)
    shared = sorted(set(base) & set(forced))
    if not shared:
        print("no project measured in both arms yet")
        return

    per_lane: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for repo in shared:
        lane = base[repo]["lane"]
        b, f = tally(base[repo]), tally(forced[repo])
        bucket = per_lane[lane]
        bucket["projects"] += 1
        for key in ("attempted", "built_and_fuzzed", "real_fuzzed", "stub_only_targets", "findings"):
            bucket[f"b_{key}"] += b[key]
            bucket[f"f_{key}"] += f[key]

    print(f"--force A/B over {len(shared)} project(s) measured in both arms")
    print(f"  baseline: {args.baseline}")
    print(f"  forced:   {args.forced}\n")
    header = (
        f"{'lane':8s} {'proj':>4s} {'attempted':>19s} {'REAL fuzzed':>19s} "
        f"{'stub-only':>15s} {'findings':>13s}"
    )
    print(header)
    print("-" * len(header))
    totals: dict[str, int] = defaultdict(int)
    for lane in sorted(per_lane):
        bucket = per_lane[lane]
        for key, value in bucket.items():
            totals[key] += value
        print(
            f"{lane:8s} {bucket['projects']:4d} "
            f"{bucket['b_attempted']:8d} -> {bucket['f_attempted']:<7d} "
            f"{bucket['b_real_fuzzed']:8d} -> {bucket['f_real_fuzzed']:<7d} "
            f"{bucket['b_stub_only_targets']:6d} -> {bucket['f_stub_only_targets']:<6d} "
            f"{bucket['b_findings']:5d} -> {bucket['f_findings']:<5d}"
        )
    print("-" * len(header))
    print(
        f"{'ALL':8s} {totals['projects']:4d} "
        f"{totals['b_attempted']:8d} -> {totals['f_attempted']:<7d} "
        f"{totals['b_real_fuzzed']:8d} -> {totals['f_real_fuzzed']:<7d} "
        f"{totals['b_stub_only_targets']:6d} -> {totals['f_stub_only_targets']:<6d} "
        f"{totals['b_findings']:5d} -> {totals['f_findings']:<5d}"
    )

    real_gain = totals["f_real_fuzzed"] - totals["b_real_fuzzed"]
    stub_gain = totals["f_stub_only_targets"] - totals["b_stub_only_targets"]
    find_gain = totals["f_findings"] - totals["b_findings"]
    print(
        f"\n--force moved {real_gain:+d} target(s) into REAL fuzzing and "
        f"{stub_gain:+d} into stub-only, for {find_gain:+d} finding(s)."
    )
    if real_gain <= 0 and stub_gain > 0:
        print(
            "Read that as a cost, not a gain: the extra reach exercised govfuzz's "
            "own fabricated values, not the project's code."
        )


if __name__ == "__main__":
    main()
