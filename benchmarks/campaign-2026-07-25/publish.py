#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fill the results section of docs/site/sweep-500.md from the sweep rows.

Keeping this a script rather than hand-edited prose means the published
numbers cannot drift from `results/`: re-run the sweep, re-run this, and the
page is current.

Usage:
  publish.py [--results results] [--page ../../docs/site/sweep-500.md]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "## Results"
NEXT_SECTION = "## Honest limits"

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

LANE_NAMES = {
    "c": "C", "cpp": "C++", "rust": "Rust", "go": "Go", "python": "Python",
    "java": "Java", "js": "JavaScript", "ts": "TypeScript", "csharp": "C#",
    "php": "PHP", "ruby": "Ruby", "perl": "Perl", "ada": "Ada", "lua": "Lua",
    "fortran": "Fortran", "cobol": "COBOL",
}


def load(results: Path) -> list[dict]:
    rows = []
    for path in sorted(results.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    return rows


def summarize(rows: list[dict]) -> tuple[dict, dict]:
    per_lane: dict[str, dict] = defaultdict(
        lambda: {
            "projects": 0, "measured": 0, "discovered": 0, "attempted": 0,
            "findings": 0, "sloc": 0, "no_targets": 0, "majority": 0,
            **{s: 0 for s in STATUSES},
        }
    )
    totals = Counter()
    for row in rows:
        lane = row.get("lane", "?")
        bucket = per_lane[lane]
        bucket["projects"] += 1
        surfaces = row.get("surfaces") or {}
        sloc = (surfaces.get("sloc") or {}).get("sloc_total") or 0
        bucket["sloc"] += sloc
        summary = (surfaces.get("auto") or {}).get("summary") or {}
        if not summary:
            continue
        bucket["measured"] += 1
        bucket["discovered"] += summary.get("discovered_total", 0)
        bucket["findings"] += summary.get("findings", 0)
        attempted = 0
        for status in STATUSES:
            n = summary.get(status, 0) or 0
            bucket[status] += n
            attempted += n
        bucket["attempted"] += attempted
        if attempted == 0:
            bucket["no_targets"] += 1
        elif summary.get("built_and_fuzzed", 0) * 2 > attempted:
            bucket["majority"] += 1
    for bucket in per_lane.values():
        for key, value in bucket.items():
            totals[key] += value
    return dict(per_lane), dict(totals)


def render(per_lane: dict, totals: dict, rows: list[dict]) -> str:
    lines = [
        "",
        f"{totals['projects']} projects measured, "
        f"{totals['sloc']:,} lines of code, "
        f"{totals['discovered']:,} fuzzable targets discovered, "
        f"**zero harnesses written by hand**.",
        "",
        "| Language | Projects | SLOC | Targets found | Attempted | Fuzzed | Rate | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for lane in sorted(per_lane, key=lambda k: -per_lane[k]["discovered"]):
        b = per_lane[lane]
        rate = f"{b['built_and_fuzzed'] / b['attempted'] * 100:.0f}%" if b["attempted"] else "—"
        lines.append(
            f"| {LANE_NAMES.get(lane, lane)} | {b['projects']} | {b['sloc']:,} | "
            f"{b['discovered']:,} | {b['attempted']} | {b['built_and_fuzzed']} | "
            f"{rate} | {b['findings']} |"
        )
    rate = (
        f"{totals['built_and_fuzzed'] / totals['attempted'] * 100:.0f}%"
        if totals["attempted"]
        else "—"
    )
    lines.append(
        f"| **All 16** | **{totals['projects']}** | **{totals['sloc']:,}** | "
        f"**{totals['discovered']:,}** | **{totals['attempted']}** | "
        f"**{totals['built_and_fuzzed']}** | **{rate}** | **{totals['findings']}** |"
    )

    panics = sum(
        1
        for row in rows
        for surface in (row.get("surfaces") or {}).values()
        if isinstance(surface, dict) and surface.get("panic")
    )
    timeouts = sum(
        1
        for row in rows
        for surface in (row.get("surfaces") or {}).values()
        if isinstance(surface, dict) and surface.get("timed_out")
    )
    lines += [
        "",
        "### Robustness",
        "",
        f"Across {totals['projects']} projects and "
        f"{totals['projects'] * 6} surface invocations: **{panics} panics**, "
        f"**{timeouts} timeouts**. A tool that is run unattended over an estate has "
        "to survive every tree in it, including the malformed ones.",
        "",
        "### What blocked the rest",
        "",
    ]
    blockers: Counter = Counter()
    for row in rows:
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for entry in auto.get("blockers") or []:
            blockers[(entry.get("language", "?"), (entry.get("detail") or "")[:70])] += entry.get(
                "count", 0
            )
    lines += ["| Targets | Language | Cause |", "|---:|---|---|"]
    for (lang, detail), count in blockers.most_common(12):
        lines.append(f"| {count} | {lang} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--page", type=Path, default=HERE.parent.parent / "docs/site/sweep-500.md")
    args = ap.parse_args()

    rows = load(args.results)
    if not rows:
        print("no results yet")
        return
    per_lane, totals = summarize(rows)
    section = render(per_lane, totals, rows)

    text = args.page.read_text()
    start = text.index(MARKER) + len(MARKER)
    end = text.index(NEXT_SECTION)
    args.page.write_text(text[:start] + "\n" + section + "\n" + text[end:])
    print(f"filled {args.page} from {len(rows)} project(s)")


if __name__ == "__main__":
    main()
