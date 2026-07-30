#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Gate a `static-scan` change on producing IDENTICAL findings.

The static scanner's precision is the product, so an optimisation there is only
acceptable if it changes nothing about what is reported. Speed is easy to measure
and easy to fool yourself about; "did I silently stop exploring something" is
not, because losing a finding looks exactly like a faster scan.

This harness makes that difference visible. `capture` scans a tree and records a
normalised digest alongside the wall time and peak RSS; `compare` diffs two
digests and fails on any change to what was found.

Findings are compared as a MULTISET of `rule:path:line:slug` fingerprints —
several findings legitimately share one site, so set semantics would hide a
change in how many. Rule, severity and CWE totals are compared too, so a
same-count-different-kind swap cannot slip through.

`analysis_gaps` are compared just as strictly, and that is the part that catches
a taint change pretending to be an optimisation: when the engine gives up on a
call or truncates a function's state it records a gap, so exploring less shows up
as MORE gaps even when the finding count happens to hold.

Usage:
    finding-parity.py capture <tree> <digest.json> [--govfuzz PATH] [--jobs N]
    finding-parity.py compare <baseline.json> <candidate.json>
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import resource
import shutil
import subprocess
import sys
import tempfile
import time


def digest_of_report(report: dict) -> dict:
    """Everything about a scan that must not change, in a comparable form."""
    findings = report.get("findings") or []
    gaps = report.get("analysis_gaps") or []
    return {
        "finding_count": len(findings),
        # Multiset: several findings can share a site, so the COUNT per
        # fingerprint matters, not just its presence.
        "fingerprints": dict(
            collections.Counter(f.get("fingerprint", "") for f in findings)
        ),
        "by_rule": dict(collections.Counter(f.get("rule_id", "") for f in findings)),
        "by_severity": dict(
            collections.Counter(f.get("severity", "") for f in findings)
        ),
        "by_cwe": dict(collections.Counter(str(f.get("cwe", "")) for f in findings)),
        # Gaps are where the engine admits it stopped. More gaps = less
        # exploration, which is the failure mode an "optimisation" can hide.
        "gap_count": len(gaps),
        "gaps_by_reason": dict(collections.Counter(g.get("reason", "") for g in gaps)),
    }


def capture(tree: pathlib.Path, out: pathlib.Path, govfuzz: str, jobs: int) -> int:
    scan_out = pathlib.Path(tempfile.mkdtemp(prefix="parity-scan-"))
    command = [
        govfuzz,
        "static-scan",
        str(tree),
        "--out",
        str(scan_out),
        "--jobs",
        str(jobs),
    ]
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.monotonic()
    completed = subprocess.run(command, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    peak_kb = max(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss - before, 0)
    if completed.returncode not in (0, 1):
        # 0 = clean, 1 = findings present. Anything else is a real failure.
        sys.stderr.write(
            f"scan failed (exit {completed.returncode}):\n{completed.stderr[-2000:]}\n"
        )
        shutil.rmtree(scan_out, ignore_errors=True)
        return 2

    report_path = scan_out / "static-report.json"
    if not report_path.is_file():
        sys.stderr.write(f"no static-report.json under {scan_out}\n")
        shutil.rmtree(scan_out, ignore_errors=True)
        return 2
    report = json.loads(report_path.read_text())
    digest = digest_of_report(report)
    digest["tree"] = str(tree)
    # Timing lives beside the digest so one run answers both questions: did it get
    # faster, and did it stay correct.
    digest["wall_seconds"] = round(elapsed, 2)
    digest["peak_rss_mib"] = peak_kb // 1024
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(digest, indent=2, sort_keys=True))
    shutil.rmtree(scan_out, ignore_errors=True)
    print(
        f"{tree}: {digest['finding_count']} finding(s), {digest['gap_count']} gap(s), "
        f"{digest['wall_seconds']}s, {digest['peak_rss_mib']} MiB -> {out}"
    )
    return 0


def diff_counters(
    label: str, before: dict, after: dict, limit: int = 15
) -> list[str]:
    problems: list[str] = []
    keys = set(before) | set(after)
    changed = [(k, before.get(k, 0), after.get(k, 0)) for k in sorted(keys)]
    changed = [row for row in changed if row[1] != row[2]]
    if changed:
        problems.append(f"{label}: {len(changed)} entr(ies) changed")
        for key, was, now in changed[:limit]:
            problems.append(f"    {key or '<empty>'}: {was} -> {now}")
        if len(changed) > limit:
            problems.append(f"    ... {len(changed) - limit} more")
    return problems


def compare(baseline: pathlib.Path, candidate: pathlib.Path) -> int:
    was = json.loads(baseline.read_text())
    now = json.loads(candidate.read_text())

    problems: list[str] = []
    for label in ("fingerprints", "by_rule", "by_severity", "by_cwe", "gaps_by_reason"):
        problems += diff_counters(label, was.get(label, {}), now.get(label, {}))
    for label in ("finding_count", "gap_count"):
        if was.get(label) != now.get(label):
            problems.append(f"{label}: {was.get(label)} -> {now.get(label)}")

    speed = ""
    if was.get("wall_seconds") and now.get("wall_seconds"):
        factor = was["wall_seconds"] / max(now["wall_seconds"], 0.01)
        speed = (
            f"  {was['wall_seconds']}s -> {now['wall_seconds']}s ({factor:.2f}x), "
            f"{was.get('peak_rss_mib')} -> {now.get('peak_rss_mib')} MiB"
        )

    if problems:
        print("FINDING PARITY FAILED — the scan's output changed:")
        for line in problems:
            print(f"  {line}")
        if speed:
            print(f"\ntiming (irrelevant while parity fails):{speed}")
        return 1

    print(f"finding parity OK — {now.get('finding_count')} finding(s), "
          f"{now.get('gap_count')} gap(s), identical.")
    if speed:
        print(f"timing:{speed}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    cap = sub.add_parser("capture", help="scan a tree and record its digest")
    cap.add_argument("tree", type=pathlib.Path)
    cap.add_argument("out", type=pathlib.Path)
    cap.add_argument("--govfuzz", default="./target/release/govfuzz")
    cap.add_argument("--jobs", type=int, default=2)

    cmp_ = sub.add_parser("compare", help="fail if two digests differ")
    cmp_.add_argument("baseline", type=pathlib.Path)
    cmp_.add_argument("candidate", type=pathlib.Path)

    args = parser.parse_args()
    if args.mode == "capture":
        return capture(args.tree, args.out, args.govfuzz, args.jobs)
    return compare(args.baseline, args.candidate)


if __name__ == "__main__":
    sys.exit(main())
