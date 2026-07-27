#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enumerate what `--force` could NOT build, by reading the compilers.

The forced arm ends 297 targets on `unbuildable after N repair round(s)`. That
string is a *class*, not a diagnosis: it is whatever the repair loop could not
fix. The blocker histogram groups those targets but says nothing about why, and
the answer only exists in each harness's `repairs/*_build_output.log`.

This walks the same corpus the force A/B walks, forced, and harvests the actual
`error:` lines out of every harness that did not reach built_and_fuzzed. Clone
and work dir are deleted straight after harvesting, so peak disk stays at one
project no matter how many are swept.

  residual_errors.py --lanes c,cpp --limit 20 --out residual-c-cpp.jsonl
  residual_errors.py --report residual-c-cpp.jsonl        # histogram only

The histogram is the worklist: fix the largest class, re-measure, repeat.
Normalisation exists purely for grouping — always open an exemplar's raw log
(printed with each class) before believing a class is one bug.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_corpus as bc  # noqa: E402

HERE = Path(__file__).resolve().parent
WORK_ROOT = Path("/home/ubuntu/govfuzz-sweep-work")
GOVFUZZ = Path(os.environ.get("GOVFUZZ_BIN", "/home/ubuntu/github/tarmo/govfuzz/target/release/govfuzz"))

# Everything that varies between two runs of the same defect: absolute paths,
# temporary object names, line/column numbers, and the identifier the error is
# about. Identifiers are folded LAST so a message keeps its shape.
QUOTED = re.compile(r"'[^']*'")
NUMBERS = re.compile(r"\b\d+\b")
PATHS = re.compile(r"\S*/\S*")


def normalise(message: str) -> str:
    text = PATHS.sub("<path>", message.strip())
    text = QUOTED.sub("'<id>'", text)
    text = NUMBERS.sub("N", text)
    return text[:200]


# Outcomes that mean GovFuzz gave up on the target. Anything else — above all
# `built_and_fuzzed` — must NOT be harvested: the repair loop reaches the link
# stage with symbols still undefined on the way to fixing them, so a SUCCESSFUL
# C harness routinely leaves `undefined reference to …` in its last build log.
# Harvesting those made "undefined reference" the largest class in the histogram
# when it was really the loop working as designed.
TERMINAL_OUTCOMES = {
    "report_only",
    "failed_build",
    "unrecoverable_link",
    "unrecoverable_runtime",
    "built_not_entered",
}


def harvest(work: Path) -> list[dict]:
    """One record per harness GovFuzz GAVE UP on, with its compiler errors."""
    out = []
    harnesses = work / "harnesses"
    if not harnesses.is_dir():
        return out
    for hdir in sorted(harnesses.iterdir()):
        result = hdir / "result.json"
        status = None
        if result.is_file():
            try:
                # The outcome is an internally-tagged enum: {"outcome": {"outcome": ...}}.
                status = (json.loads(result.read_text()).get("outcome") or {}).get("outcome")
            except (json.JSONDecodeError, OSError, AttributeError):
                pass
        # No result.json at all means the attempt never finished — the campaign
        # clock stopped it, which is budget, not a defect. Skip those too.
        if status not in TERMINAL_OUTCOMES:
            continue
        errors: list[str] = []
        raw: list[str] = []
        for log in sorted((hdir / "repairs").glob("*build_output.log")):
            try:
                text = log.read_text(errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                if ": error:" in line or line.startswith("error:"):
                    message = line.split("error:", 1)[1].strip()
                    errors.append(normalise(message))
                    raw.append(line.strip()[:400])
                elif "undefined reference to" in line:
                    errors.append("undefined reference to '<id>'")
                    raw.append(line.strip()[:400])
        if errors:
            out.append(
                {
                    "harness": hdir.name,
                    "status": status,
                    "errors": errors,
                    "raw": raw[:6],
                }
            )
    return out


def sweep_one(row: dict, args: argparse.Namespace) -> list[dict]:
    lane, repo = row["lane"], row["repo"]
    slug = f"{lane}__{repo.replace('/', '__')}"
    work = WORK_ROOT / slug
    scratch = WORK_ROOT / f"{slug}.cwd"
    tree = None
    records: list[dict] = []
    try:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            tree, _ = bc.clone_repo(lane, repo, row["url"])
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"  {slug}: clone failed: {exc}", flush=True)
            return records
        cmd = [
            str(GOVFUZZ), "auto", str(tree),
            "--work-dir", str(work),
            "--campaign-time", str(args.campaign_time),
            "--per-target-time", str(args.per_target_time),
            "--max-attempts", str(args.max_attempts),
            "--max-repair-rounds", str(args.max_repair_rounds),
            "--jobs", str(args.inner_jobs),
            "--profile", "external-tools",
            "--force",
        ]  # fmt: skip
        t0 = time.monotonic()
        try:
            subprocess.run(
                cmd,
                cwd=scratch,
                capture_output=True,
                text=True,
                timeout=args.campaign_time + args.slack,
            )
        except subprocess.TimeoutExpired:
            pass
        for record in harvest(work):
            record["lane"] = lane
            record["repo"] = repo
            records.append(record)
        print(
            f"  {slug}: {len(records)} unbuilt harness(es) in {time.monotonic() - t0:.0f}s",
            flush=True,
        )
        return records
    finally:
        if tree is not None and not args.keep_clone:
            shutil.rmtree(tree, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def report(path: Path, top: int) -> None:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    by_class: Counter = Counter()
    lanes: dict[str, Counter] = defaultdict(Counter)
    exemplar: dict[str, str] = {}
    for record in records:
        # One vote per harness per distinct error class: a header that fails to
        # be found 40 times in one TU is one defect, not forty.
        for message in sorted(set(record["errors"])):
            by_class[message] += 1
            lanes[message][record["lane"]] += 1
            exemplar.setdefault(message, f"{record['repo']} {record['harness']}")
    harnesses = len(records)
    print(f"{harnesses} unbuilt harnesses over {len({r['repo'] for r in records})} projects")
    print(f"{len(by_class)} distinct error classes\n")
    for message, count in by_class.most_common(top):
        spread = " ".join(f"{lane}:{n}" for lane, n in lanes[message].most_common())
        print(f"{count:5d}  [{spread}]  {message}")
        print(f"         e.g. {exemplar[message]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=Path, default=HERE / "force-repos.tsv")
    ap.add_argument("--lanes", default="c,cpp")
    ap.add_argument("--limit", type=int, default=20, help="projects per lane")
    ap.add_argument("--out", type=Path, default=HERE / "residual-errors.jsonl")
    ap.add_argument("--report", type=Path, help="histogram an existing jsonl and exit")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--inner-jobs", type=int, default=2)
    ap.add_argument("--campaign-time", type=int, default=90)
    ap.add_argument("--per-target-time", type=int, default=3)
    ap.add_argument("--max-attempts", type=int, default=10)
    ap.add_argument("--max-repair-rounds", type=int, default=4)
    ap.add_argument("--slack", type=int, default=420)
    ap.add_argument("--keep-clone", action="store_true")
    args = ap.parse_args()

    if args.report:
        report(args.report, args.top)
        return 0

    if not GOVFUZZ.is_file():
        print(f"no govfuzz binary at {GOVFUZZ}", file=sys.stderr)
        return 1

    urls = {(r["lane"], r["repo"]): r["url"] for r in bc.read_tsv(bc.CORPUS_TSV)}
    urls.update({(r["lane"], r["repo"]): r["url"] for r in bc.read_tsv(bc.POOL_TSV)})

    wanted = args.lanes.split(",")
    picked: list[dict] = []
    per_lane: Counter = Counter()
    for line in args.repos.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        lane, repo = line.split("\t")[:2]
        if lane not in wanted or per_lane[lane] >= args.limit:
            continue
        url = urls.get((lane, repo))
        if url is None:
            continue
        per_lane[lane] += 1
        picked.append({"lane": lane, "repo": repo, "url": url})

    print(f"{len(picked)} projects: {dict(per_lane)}", flush=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as handle, ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for records in pool.map(lambda row: sweep_one(row, args), picked):
            for record in records:
                handle.write(json.dumps(record) + "\n")
            handle.flush()
    print(f"\nwrote {args.out}\n", flush=True)
    report(args.out, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
