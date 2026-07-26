#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the campaign's figures from the sweep results.

Four figures, each answering one question the campaign set out to answer:

  reach.png        per language, what fraction of attempted targets fuzzed
  blockers.png     what stops the rest, ranked
  findings.png     findings per language, split crash-visible vs behavioural
  before_after.png the same projects before and after the fix rounds

Usage:
  charts.py [--results results] [--baseline baseline-w0] [--out charts]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent

# A calm, colour-blind-safe set: one accent for govfuzz, greys for context.
ACCENT = "#2563eb"
ACCENT_2 = "#059669"
MUTED = "#94a3b8"
WARN = "#dc2626"
TEXT = "#1f2937"

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


def load(results: Path) -> list[dict]:
    rows = []
    for path in sorted(results.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            continue
    return rows


def summarize(rows: list[dict]) -> dict[str, dict]:
    per_lane: dict[str, dict] = defaultdict(
        lambda: {"attempted": 0, "findings": 0, "projects": 0, **{s: 0 for s in STATUSES}}
    )
    for row in rows:
        auto = (row.get("surfaces") or {}).get("auto") or {}
        summary = auto.get("summary") or {}
        if not summary:
            continue
        bucket = per_lane[row.get("lane", "?")]
        bucket["projects"] += 1
        bucket["findings"] += summary.get("findings", 0)
        for status in STATUSES:
            n = summary.get(status, 0) or 0
            bucket[status] += n
            bucket["attempted"] += n
    return dict(per_lane)


def style(ax, title: str, xlabel: str = "", ylabel: str = "") -> None:
    ax.set_title(title, color=TEXT, fontsize=13, pad=12, loc="left")
    ax.set_xlabel(xlabel, color=TEXT, fontsize=10)
    ax.set_ylabel(ylabel, color=TEXT, fontsize=10)
    ax.tick_params(colors=TEXT, labelsize=9)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.set_axisbelow(True)


def chart_reach(per_lane: dict[str, dict], out: Path) -> None:
    lanes = sorted(per_lane, key=lambda k: -(per_lane[k]["built_and_fuzzed"]))
    lanes = [k for k in lanes if per_lane[k]["attempted"]]
    ratios = [
        per_lane[k]["built_and_fuzzed"] / per_lane[k]["attempted"] * 100 for k in lanes
    ]
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(lanes) + 1.8))
    bars = ax.barh(lanes, ratios, color=ACCENT, height=0.62)
    for bar, lane, ratio in zip(bars, lanes, ratios):
        n = per_lane[lane]
        ax.text(
            ratio + 1,
            bar.get_y() + bar.get_height() / 2,
            f"{ratio:.0f}%  ({n['built_and_fuzzed']}/{n['attempted']})",
            va="center",
            fontsize=8.5,
            color=TEXT,
        )
    ax.set_xlim(0, 108)
    ax.invert_yaxis()
    style(ax, "Targets fuzzed, per language", "% of attempted targets reaching built+fuzzed")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def chart_blockers(rows: list[dict], out: Path, top: int = 14) -> None:
    counter: Counter = Counter()
    for row in rows:
        auto = (row.get("surfaces") or {}).get("auto") or {}
        for entry in auto.get("blockers") or []:
            label = f"{entry.get('language', '?')}: {(entry.get('detail') or '')[:58]}"
            counter[label] += entry.get("count", 0)
    items = counter.most_common(top)
    if not items:
        return
    labels = [k for k, _ in reversed(items)]
    values = [v for _, v in reversed(items)]
    fig, ax = plt.subplots(figsize=(11, 0.42 * len(labels) + 1.8))
    ax.barh(labels, values, color=WARN, height=0.62)
    for index, value in enumerate(values):
        ax.text(value + max(values) * 0.01, index, str(value), va="center", fontsize=8.5, color=TEXT)
    style(ax, "What stopped the rest, ranked", "targets blocked")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def chart_findings(per_lane: dict[str, dict], out: Path) -> None:
    lanes = [k for k in sorted(per_lane) if per_lane[k]["findings"]]
    if not lanes:
        return
    values = [per_lane[k]["findings"] for k in lanes]
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(lanes) + 1.8))
    ax.barh(lanes, values, color=ACCENT_2, height=0.62)
    for index, value in enumerate(values):
        ax.text(value + max(values) * 0.01, index, str(value), va="center", fontsize=8.5, color=TEXT)
    ax.invert_yaxis()
    style(ax, "Findings per language", "findings")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def chart_before_after(results: Path, baseline: Path, out: Path) -> None:
    if not baseline.is_dir():
        return
    before = summarize(load(baseline))
    after = summarize(load(results))
    lanes = sorted(set(before) & set(after))
    lanes = [k for k in lanes if before[k]["attempted"] or after[k]["attempted"]]
    if not lanes:
        return

    def ratio(bucket: dict) -> float:
        return bucket["built_and_fuzzed"] / bucket["attempted"] * 100 if bucket["attempted"] else 0.0

    fig, ax = plt.subplots(figsize=(10, 0.5 * len(lanes) + 2))
    positions = range(len(lanes))
    ax.barh([p + 0.2 for p in positions], [ratio(before[k]) for k in lanes],
            height=0.36, color=MUTED, label="before the fix rounds")
    ax.barh([p - 0.2 for p in positions], [ratio(after[k]) for k in lanes],
            height=0.36, color=ACCENT, label="after")
    ax.set_yticks(list(positions))
    ax.set_yticklabels(lanes)
    ax.invert_yaxis()
    ax.legend(frameon=False, fontsize=9)
    style(ax, "Targets fuzzed before and after the fix rounds", "% of attempted targets")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--baseline", type=Path, default=HERE / "baseline-w0")
    ap.add_argument("--out", type=Path, default=HERE / "charts")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    rows = load(args.results)
    per_lane = summarize(rows)
    chart_reach(per_lane, args.out / "reach.png")
    chart_blockers(rows, args.out / "blockers.png")
    chart_findings(per_lane, args.out / "findings.png")
    chart_before_after(args.results, args.baseline, args.out / "before_after.png")
    print(f"wrote figures to {args.out} from {len(rows)} project result(s)")


if __name__ == "__main__":
    main()
