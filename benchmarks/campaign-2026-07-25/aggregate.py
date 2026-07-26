#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Roll the per-project result rows up into the numbers the campaign reports.

Answers three questions:
  1. Per language, what fraction of attempted targets reach built_and_fuzzed,
     and in how many projects is that a majority?
  2. What is blocking the rest, ranked -- the next lever to build.
  3. Did any surface panic, hang, or fail, and where.

Usage:
  aggregate.py                 # summary tables
  aggregate.py --blockers 40   # deeper blocker ranking
  aggregate.py --json out.json # machine-readable rollup
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

STATUSES = [
    "built_and_fuzzed",
    "fuzzed_stub_only",
    "failed_build",
    "unsupported_params",
    "unrecoverable_link",
    "unrecoverable_runtime",
    "skipped",
    "report_only",
]


def load() -> list[dict]:
    rows = []
    for path in sorted(RESULTS.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            print(f"unreadable result: {path}")
    return rows


def auto_of(row: dict) -> dict:
    return (row.get("surfaces") or {}).get("auto") or {}


def summarize(rows: list[dict]) -> dict:
    per_lane: dict[str, dict] = defaultdict(
        lambda: {
            "projects": 0,
            "measured": 0,
            "no_targets": 0,
            "majority_built": 0,
            "discovered_total": 0,
            "attempted": 0,
            "findings": 0,
            "wall_s": 0.0,
            **{s: 0 for s in STATUSES},
        }
    )
    problems: list[dict] = []
    blockers: Counter = Counter()
    blocker_lang: dict[tuple, str] = {}

    for row in rows:
        lane = row.get("lane", "?")
        bucket = per_lane[lane]
        bucket["projects"] += 1
        status = row.get("status")
        if status != "done":
            problems.append(
                {"repo": row.get("repo"), "lane": lane, "status": status,
                 "why": (row.get("error") or row.get("lane_check") or "")[:120]}
            )
            continue

        for name, surface in (row.get("surfaces") or {}).items():
            if not isinstance(surface, dict):
                continue
            if surface.get("panic"):
                problems.append(
                    {"repo": row.get("repo"), "lane": lane, "status": f"PANIC:{name}",
                     "why": (surface.get("panic_excerpt") or "")[:200]}
                )
            elif surface.get("timed_out"):
                problems.append(
                    {"repo": row.get("repo"), "lane": lane, "status": f"timeout:{name}",
                     "why": f"{surface.get('wall_s')}s"}
                )
            elif surface.get("exit") not in (0, 1, 2, None):
                problems.append(
                    {"repo": row.get("repo"), "lane": lane, "status": f"exit:{name}",
                     "why": f"exit={surface.get('exit')} {(surface.get('stderr_tail') or '')[:150]}"}
                )

        auto = auto_of(row)
        summary = auto.get("summary") or {}
        if not summary:
            continue
        bucket["measured"] += 1
        bucket["wall_s"] += auto.get("wall_s") or 0
        bucket["discovered_total"] += summary.get("discovered_total", 0)
        bucket["findings"] += summary.get("findings", 0)
        attempted = 0
        for s in STATUSES:
            n = summary.get(s, 0) or 0
            bucket[s] += n
            attempted += n
        bucket["attempted"] += attempted
        if attempted == 0:
            bucket["no_targets"] += 1
        elif summary.get("built_and_fuzzed", 0) * 2 > attempted:
            bucket["majority_built"] += 1

        for entry in auto.get("blockers") or []:
            key = (
                entry.get("language", "?"),
                entry.get("category", "?"),
                (entry.get("detail") or "")[:110],
            )
            blockers[key] += entry.get("count", 0)
            blocker_lang[key] = entry.get("language", "?")

    return {
        "per_lane": dict(per_lane),
        "problems": problems,
        "blockers": blockers,
    }


def render(agg: dict, top_blockers: int) -> None:
    per_lane = agg["per_lane"]
    print(
        f"{'lane':9s} {'proj':>4s} {'meas':>4s} {'disc':>7s} {'attm':>5s} "
        f"{'B&F':>5s} {'ratio':>6s} {'maj':>4s} {'0tgt':>4s} {'fail':>5s} "
        f"{'unsup':>5s} {'stub':>5s} {'find':>5s}"
    )
    tot = Counter()
    for lane in sorted(per_lane):
        b = per_lane[lane]
        att = b["attempted"]
        ratio = (b["built_and_fuzzed"] / att * 100) if att else 0.0
        print(
            f"{lane:9s} {b['projects']:4d} {b['measured']:4d} {b['discovered_total']:7d} "
            f"{att:5d} {b['built_and_fuzzed']:5d} {ratio:5.1f}% "
            f"{b['majority_built']:4d} {b['no_targets']:4d} {b['failed_build']:5d} "
            f"{b['unsupported_params']:5d} {b['fuzzed_stub_only']:5d} {b['findings']:5d}"
        )
        for k in ("projects", "measured", "discovered_total", "attempted",
                  "majority_built", "no_targets", "findings", *STATUSES):
            tot[k] += b[k]
    att = tot["attempted"]
    ratio = (tot["built_and_fuzzed"] / att * 100) if att else 0.0
    print(
        f"{'TOTAL':9s} {tot['projects']:4d} {tot['measured']:4d} {tot['discovered_total']:7d} "
        f"{att:5d} {tot['built_and_fuzzed']:5d} {ratio:5.1f}% "
        f"{tot['majority_built']:4d} {tot['no_targets']:4d} {tot['failed_build']:5d} "
        f"{tot['unsupported_params']:5d} {tot['fuzzed_stub_only']:5d} {tot['findings']:5d}"
    )
    measured = tot["measured"]
    if measured:
        print(
            f"\nprojects where a majority of attempted targets fuzzed: "
            f"{tot['majority_built']}/{measured} "
            f"({tot['majority_built'] / measured * 100:.0f}%)"
        )

    problems = agg["problems"]
    print(f"\n--- problems ({len(problems)}) ---")
    by_kind = Counter(p["status"].split(":")[0] for p in problems)
    for kind, n in by_kind.most_common():
        print(f"  {kind:16s} {n}")
    for p in problems[:25]:
        print(f"  {p['lane']:8s} {p['repo'][:40]:40s} {p['status']:18s} {p['why'][:90]}")

    print(f"\n--- top {top_blockers} residual blockers ---")
    for (lang, cat, detail), n in agg["blockers"].most_common(top_blockers):
        print(f"  {n:5d}  {lang:8s} {cat:22s} {detail[:96]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--blockers", type=int, default=25)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    rows = load()
    agg = summarize(rows)
    render(agg, args.blockers)
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "per_lane": agg["per_lane"],
                    "problems": agg["problems"],
                    "blockers": [
                        {"language": k[0], "category": k[1], "detail": k[2], "count": v}
                        for k, v in agg["blockers"].most_common()
                    ],
                },
                indent=1,
            )
        )
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
