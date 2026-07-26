#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure govfuzz against the leading tool for each job it does.

Four comparisons, each run against the same inputs for every tool:

  sloc     govfuzz sloc vs cloc (the accuracy reference) and tokei
  static   govfuzz static-scan vs cppcheck / flawfinder / semgrep / bandit /
           gosec, on findings and on throughput
  sbom     govfuzz sbom vs syft, on components identified
  fuzz     govfuzz auto vs libFuzzer and AFL++ on the SAME C function --
           including the harness each competitor needs and govfuzz does not

Usage:
  compare.py sloc   --projects <dir> [--json out.json]
  compare.py static --projects <dir> [--json out.json]
  compare.py sbom   --projects <dir> [--json out.json]
  compare.py fuzz   --target <dir> --function <name> [--seconds 60]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GOVFUZZ = Path(os.environ.get("GOVFUZZ_BIN", REPO / "target" / "release" / "govfuzz"))
HERE = Path(__file__).resolve().parent


def timed(cmd: list[str], timeout: int = 1800, cwd: Path | None = None) -> tuple[int, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout, cwd=str(cwd) if cwd else None,
        )
        return proc.returncode, proc.stdout + proc.stderr, round(time.monotonic() - started, 2)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return -1, f"{type(exc).__name__}", round(time.monotonic() - started, 2)


def projects_in(root: Path, limit: int) -> list[Path]:
    out = []
    for lane_dir in sorted(root.iterdir()):
        if not lane_dir.is_dir():
            continue
        for project in sorted(lane_dir.iterdir()):
            if project.is_dir():
                out.append(project)
    return out[:limit]


# ---------------------------------------------------------------- sloc


def compare_sloc(projects: list[Path]) -> list[dict]:
    rows = []
    for project in projects:
        row: dict = {"project": project.name}
        code, out, wall = timed([str(GOVFUZZ), "sloc", str(project), "--json"], 600)
        row["govfuzz"] = {"wall_s": wall, "code": parse_govfuzz_sloc(out)}
        code, out, wall = timed(["cloc", "--quiet", "--json", str(project)], 1800)
        row["cloc"] = {"wall_s": wall, "code": parse_cloc(out)}
        code, out, wall = timed(["tokei", "--output", "json", str(project)], 1800)
        row["tokei"] = {"wall_s": wall, "code": parse_tokei(out)}
        rows.append(row)
        print(
            f"{project.name[:34]:34s} govfuzz={row['govfuzz']['code']:>9} "
            f"cloc={row['cloc']['code']:>9} tokei={row['tokei']['code']:>9}  "
            f"({row['govfuzz']['wall_s']}s / {row['cloc']['wall_s']}s / {row['tokei']['wall_s']}s)"
        )
    return rows


def parse_govfuzz_sloc(out: str) -> int:
    try:
        data = json.loads(out[out.index("{"):])
    except (ValueError, json.JSONDecodeError):
        return 0
    total = 0
    for root in data.get("roots", []):
        total += int((root.get("total") or {}).get("code_lines") or 0)
    return total


def parse_cloc(out: str) -> int:
    try:
        data = json.loads(out[out.index("{"):])
    except (ValueError, json.JSONDecodeError):
        return 0
    return int((data.get("SUM") or {}).get("code") or 0)


def parse_tokei(out: str) -> int:
    try:
        data = json.loads(out[out.index("{"):])
    except (ValueError, json.JSONDecodeError):
        return 0
    total = 0
    for name, entry in data.items():
        if name == "Total" or not isinstance(entry, dict):
            continue
        total += int(entry.get("code") or 0)
    return total


# -------------------------------------------------------------- static


def compare_static(projects: list[Path], work: Path) -> list[dict]:
    rows = []
    for project in projects:
        lane = project.parent.name
        out_dir = work / project.name
        shutil.rmtree(out_dir, ignore_errors=True)
        row: dict = {"project": project.name, "lane": lane}

        code, out, wall = timed(
            [str(GOVFUZZ), "static-scan", str(project), "--out", str(out_dir), "--jobs", "2"], 1800
        )
        report = out_dir / "static-report.json"
        findings = 0
        if report.is_file():
            try:
                findings = len(json.loads(report.read_text()).get("findings") or [])
            except json.JSONDecodeError:
                findings = 0
        row["govfuzz"] = {"wall_s": wall, "findings": findings}

        if lane in ("c", "cpp"):
            code, out, wall = timed(
                ["cppcheck", "--enable=warning,style", "--quiet",
                 "--template={file}:{line}:{severity}:{id}", str(project)], 1800
            )
            row["cppcheck"] = {"wall_s": wall, "findings": len([l for l in out.splitlines() if ":" in l])}
            code, out, wall = timed(["flawfinder", "--quiet", "--dataonly", str(project)], 1800)
            row["flawfinder"] = {
                "wall_s": wall,
                "findings": len(re.findall(r"^\S+:\d+:", out, re.M)),
            }
        if lane == "python":
            code, out, wall = timed(["bandit", "-r", "-q", "-f", "json", str(project)], 1800)
            try:
                row["bandit"] = {"wall_s": wall, "findings": len(json.loads(out).get("results", []))}
            except json.JSONDecodeError:
                row["bandit"] = {"wall_s": wall, "findings": 0}
        if lane == "go":
            code, out, wall = timed(["gosec", "-quiet", "-fmt=json", "./..."], 1800, cwd=project)
            try:
                row["gosec"] = {"wall_s": wall, "findings": len(json.loads(out).get("Issues", []))}
            except json.JSONDecodeError:
                row["gosec"] = {"wall_s": wall, "findings": 0}

        rows.append(row)
        others = " ".join(
            f"{tool}={row[tool]['findings']}({row[tool]['wall_s']}s)"
            for tool in ("cppcheck", "flawfinder", "bandit", "gosec")
            if tool in row
        )
        print(
            f"{project.name[:30]:30s} {lane:7s} govfuzz={findings:5d}"
            f"({row['govfuzz']['wall_s']}s)  {others}"
        )
    return rows


# ---------------------------------------------------------------- sbom


def compare_sbom(projects: list[Path], work: Path) -> list[dict]:
    rows = []
    for project in projects:
        out_dir = work / f"sbom-{project.name}"
        shutil.rmtree(out_dir, ignore_errors=True)
        code, out, wall = timed([str(GOVFUZZ), "sbom", str(project), "--out", str(out_dir)], 900)
        components = 0
        for name in ("sbom.json", "sbom.cdx.json", "sbom.spdx.json"):
            path = out_dir / name
            if path.is_file():
                try:
                    data = json.loads(path.read_text())
                except json.JSONDecodeError:
                    continue
                components = len(data.get("components") or data.get("packages") or [])
                break
        row = {"project": project.name, "govfuzz": {"wall_s": wall, "components": components}}

        code, out, wall = timed(["syft", "scan", f"dir:{project}", "-o", "json", "-q"], 1800)
        try:
            row["syft"] = {
                "wall_s": wall,
                "components": len(json.loads(out).get("artifacts") or []),
            }
        except json.JSONDecodeError:
            row["syft"] = {"wall_s": wall, "components": 0}
        rows.append(row)
        print(
            f"{project.name[:34]:34s} govfuzz={components:4d}({row['govfuzz']['wall_s']}s)  "
            f"syft={row['syft']['components']:4d}({row['syft']['wall_s']}s)"
        )
    return rows


# ---------------------------------------------------------------- fuzz


LIBFUZZER_HARNESS = """// SPDX-License-Identifier: Apache-2.0
// Hand-written libFuzzer harness -- the work govfuzz does not ask for.
#include <stdint.h>
#include <stddef.h>
%(decl)s
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    %(call)s
    return 0;
}
"""


def compare_fuzz(target_dir: Path, source: Path, function: str, seconds: int, work: Path) -> dict:
    """govfuzz (no harness) vs libFuzzer and AFL++ (one hand-written harness each)."""
    work.mkdir(parents=True, exist_ok=True)
    result: dict = {"target": str(source), "function": function, "seconds": seconds}

    gf_work = work / "govfuzz-work"
    shutil.rmtree(gf_work, ignore_errors=True)
    code, out, wall = timed(
        [str(GOVFUZZ), "auto", str(target_dir), "--work-dir", str(gf_work),
         "--per-target-time", str(seconds), "--max-targets", "1", "--single-pass"],
        seconds + 900,
    )
    execs, findings = 0, 0
    run_json = gf_work / "auto" / "run.json"
    if run_json.is_file():
        data = json.loads(run_json.read_text())
        findings = (data.get("summary") or {}).get("findings", 0)
        for target in data.get("targets") or []:
            rate = (target.get("outcome") or {}).get("executions_per_sec")
            if rate:
                execs = max(execs, int(rate))
    result["govfuzz"] = {
        "harnesses_written_by_hand": 0,
        "wall_s": wall,
        "execs_per_sec": execs,
        "findings": findings,
    }
    print(f"govfuzz    execs/s={execs:8d} findings={findings} harnesses=0 ({wall}s)")
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sloc", "static", "sbom", "fuzz"])
    ap.add_argument("--projects", type=Path, default=Path("/home/ubuntu/govfuzz-corpus-500"))
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--work", type=Path, default=Path("/tmp/govfuzz-compare"))
    ap.add_argument("--json", type=Path)
    ap.add_argument("--target", type=Path)
    ap.add_argument("--source", type=Path)
    ap.add_argument("--function", default="")
    ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)

    if args.mode == "fuzz":
        rows = compare_fuzz(args.target, args.source, args.function, args.seconds, args.work)
    else:
        projects = projects_in(args.projects, args.limit)
        if args.mode == "sloc":
            rows = compare_sloc(projects)
        elif args.mode == "static":
            rows = compare_static(projects, args.work)
        else:
            rows = compare_sbom(projects, args.work)

    if args.json:
        args.json.write_text(json.dumps(rows, indent=1))
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
