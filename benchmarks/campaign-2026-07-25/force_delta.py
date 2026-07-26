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
    out["attempted"] = sum(out[key] for key in STATUSES)
    # `summary.findings` counts report-only STATIC findings alongside runtime
    # crashes, and forcing pushes targets into `report_only` — statically
    # analyzed, never fuzzed. Reporting the total would have read as "--force
    # found 76 more bugs" when what it found was static findings on targets it
    # still could not fuzz. The finding id carries the provenance: `F-RO-*` is
    # report-only, `F-STATIC-*` is the whole-tree scan, anything else is runtime.
    fuzz_findings = static_findings = 0
    for finding in auto.get("findings_detail") or []:
        if not isinstance(finding, dict):
            continue
        fid = finding.get("id") or ""
        if fid.startswith(("F-RO-", "F-STATIC-")):
            static_findings += 1
        else:
            fuzz_findings += 1
    out["fuzz_findings"] = fuzz_findings
    out["static_findings"] = static_findings
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
        for key in (
            "attempted",
            "built_and_fuzzed",
            "real_fuzzed",
            "stub_only_targets",
            "report_only",
            "unsupported_params",
            "failed_build",
            "fuzz_findings",
            "static_findings",
        ):
            bucket[f"b_{key}"] += b[key]
            bucket[f"f_{key}"] += f[key]

    print(f"--force A/B over {len(shared)} project(s) measured in both arms")
    print(f"  baseline: {args.baseline}")
    print(f"  forced:   {args.forced}\n")
    columns = [
        ("REAL fuzzed", "real_fuzzed"),
        ("stub-only", "stub_only_targets"),
        ("undrivable", "unsupported_params"),
        ("failed build", "failed_build"),
        ("report-only", "report_only"),
        ("FUZZ finds", "fuzz_findings"),
        ("static finds", "static_findings"),
    ]
    header = f"{'lane':7s} {'proj':>4s} " + " ".join(f"{label:>16s}" for label, _ in columns)
    print(header)
    print("-" * len(header))
    totals: dict[str, int] = defaultdict(int)

    def render(name: str, bucket: dict) -> str:
        cells = " ".join(
            f"{bucket['b_' + key]:6d}->{bucket['f_' + key]:<9d}" for _, key in columns
        )
        return f"{name:7s} {bucket['projects']:4d} {cells}"

    for lane in sorted(per_lane):
        bucket = per_lane[lane]
        for key, value in bucket.items():
            totals[key] += value
        print(render(lane, bucket))
    print("-" * len(header))
    print(render("ALL", totals))

    def delta(key: str) -> int:
        return totals[f"f_{key}"] - totals[f"b_{key}"]

    real, stub = delta("real_fuzzed"), delta("stub_only_targets")
    fuzz_finds, static_finds = delta("fuzz_findings"), delta("static_findings")
    print(
        f"\n--force, over the targets it could act on: {real:+d} into REAL fuzzing, "
        f"{stub:+d} into stub-only, {delta('report_only'):+d} into report-only "
        f"(analyzed, NOT fuzzed).\nFindings: {fuzz_finds:+d} from fuzzing, "
        f"{static_finds:+d} from static analysis of what it still could not fuzz."
    )
    if real <= 0:
        print(
            "So --force did NOT buy fuzz reach here. Any headline that counts its\n"
            "static findings as fuzzing results is measuring the wrong thing."
        )


if __name__ == "__main__":
    main()
