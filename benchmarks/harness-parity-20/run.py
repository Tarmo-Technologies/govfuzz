#!/usr/bin/env python3
"""Run the pinned, blind auto-vs-expert harness comparison."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ARGS = {
    # The canonical SQLite repository is a generated-source tree: its checked-in
    # configure script must run before sqlite3.h/Makefile/compile commands exist.
    "sqlite": ["--unsafe-search-and-run-build-commands"],
}


def load_projects() -> list[dict[str, str]]:
    with (HERE / "projects.tsv").open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def command(argv: list[str], *, cwd: Path | None = None, env=None, log=None) -> int:
    with (log.open("wb") if log else open(os.devnull, "wb")) as output:
        return subprocess.run(argv, cwd=cwd, env=env, stdout=output,
                              stderr=subprocess.STDOUT, check=False).returncode


def ensure_source(project: dict[str, str], sources: Path, logs: Path) -> tuple[Path, str | None]:
    root = sources / project["project"]
    log = logs / f"{project['project']}-clone.log"
    if not (root / ".git").is_dir():
        root.parent.mkdir(parents=True, exist_ok=True)
        rc = command(["git", "clone", "--filter=blob:none", "--no-checkout",
                      project["url"], str(root)], log=log)
        if rc:
            return root, f"clone exited {rc}"
    if command(["git", "fetch", "--depth", "1", "origin", project["commit"]],
               cwd=root, log=log):
        return root, "fetch failed"
    if command(["git", "checkout", "--detach", project["commit"]], cwd=root, log=log):
        return root, "checkout failed"
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    return root, None if actual == project["commit"] else f"revision mismatch: {actual}"


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def run_one(project: dict[str, str], args, sources: Path, work_root: Path,
            logs: Path) -> dict[str, object]:
    name = project["project"]
    source, source_error = ensure_source(project, sources, logs)
    row: dict[str, object] = {"project": name, "commit": project["commit"],
                              "target": project["target"]}
    if source_error:
        row.update(status="source_error", diagnostic=source_error)
        return row
    work = work_root / name
    expert = (HERE / project["expert"]).resolve()
    env = os.environ.copy()
    env["GOVFUZZ_BLIND_EXPERT_HARNESSES"] = "1"
    env["GOVFUZZ_EXPERT_HARNESS"] = str(expert)
    argv = [str(args.govfuzz), "auto", str(source), "--work-dir", str(work),
            "--target", project["target"], "--target-file", project["target_file"],
            "--max-targets", "1", "--max-attempts", "1", "--single-pass",
            "--per-target-time", str(args.seconds), "--jobs", "1", "--probe-build",
            "--comparison-progress", "--sanitizers", "none"]
    argv.extend(PROJECT_ARGS.get(name, []))
    argv.append("--resume" if args.resume else "--fresh-discovery")
    rc = command(argv, env=env, log=logs / f"{name}.log")
    results = [value for path in work.glob("harnesses/*/result.json")
               if (value := read_json(path)) and value.get("name") == project["target"]]
    if not results:
        row.update(status="no_result", exit_code=rc,
                   diagnostic="target was not discovered or no attempt result was written")
        return row
    result = results[0]
    harness = next(path.parent for path in work.glob("harnesses/*/result.json")
                   if read_json(path) == result)
    oracle = read_json(harness / "expert-oracle.json")
    feedback = read_json(harness / "portfolio-feedback.json")
    outcome = result.get("outcome") or {}
    outcome_diagnostic = outcome.get("reason")
    if not outcome_diagnostic and outcome.get("last_errors"):
        outcome_diagnostic = json.dumps(outcome["last_errors"], separators=(",", ":"))
    row.update(status=outcome.get("outcome", "unknown"), exit_code=rc,
               harness_id=result.get("harness_id", harness.name),
               diagnostic=outcome_diagnostic or result.get("reason") or
               result.get("diagnostic") or "-",
               portfolio_lanes=len((feedback or {}).get("lanes", [])))
    if oracle:
        row.update(verdict=oracle.get("verdict", ""),
                   generated_lines=oracle.get("generated_covered_lines", 0),
                   expert_lines=oracle.get("expert_covered_lines", 0),
                   overlap_lines=oracle.get("overlap_lines", 0),
                   expert_only_lines=oracle.get("expert_only_lines", 0),
                   generated_only_lines=oracle.get("generated_only_lines", 0),
                   ratio=oracle.get("generated_to_expert_ratio"),
                   common_files=oracle.get("common_instrumented_files", 0))
    else:
        row.update(verdict="not_measured", diagnostic=(row["diagnostic"] or
                   "generated coverage or expert build/replay unavailable"))
    return row


def write_results(rows: list[dict[str, object]], output: Path) -> None:
    fields = ["project", "commit", "target", "status", "verdict", "generated_lines",
              "expert_lines", "overlap_lines", "expert_only_lines", "generated_only_lines",
              "ratio", "common_files", "portfolio_lanes", "exit_code", "diagnostic"]
    with (output / "results.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    measured = [r for r in rows if r.get("verdict") not in (None, "", "not_measured",
                                                             "expert_build_unavailable")]
    parity = [r for r in measured if r.get("verdict") in
              ("expert_parity", "generated_exceeds_expert")]
    ratios = [float(r["ratio"]) for r in measured if r.get("ratio") is not None]
    lines = ["# Blind harness parity results", "",
             f"- Projects attempted: {len(rows)}",
             f"- Comparable auto/expert measurements: {len(measured)}",
             f"- Expert parity or better: {len(parity)}/{len(measured) or 0}",
             f"- Mean generated/expert covered-line ratio: " +
             (f"{sum(ratios)/len(ratios):.3f}" if ratios else "n/a"), "",
             "| Project | Result | Auto | Expert | Ratio | Expert-only |", "|---|---:|---:|---:|---:|---:|"]
    for row in rows:
        ratio = row.get("ratio")
        lines.append(f"| {row['project']} | {row.get('verdict', row.get('status'))} | "
                     f"{row.get('generated_lines', '—')} | {row.get('expert_lines', '—')} | "
                     f"{float(ratio):.3f}" if ratio is not None else
                     f"| {row['project']} | {row.get('verdict', row.get('status'))} | — | — | —")
        lines[-1] += f" | {row.get('expert_only_lines', '—')} |"
    (output / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--govfuzz", type=Path, default=HERE.parents[1] / "target/release/govfuzz")
    parser.add_argument("--output", type=Path, default=Path("/tmp/govfuzz-harness-parity-20"))
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()
    args.govfuzz = args.govfuzz.resolve()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    sources = (args.sources or output / "sources").resolve()
    work = output / "work"; logs = output / "logs"
    sources.mkdir(parents=True, exist_ok=True); work.mkdir(exist_ok=True); logs.mkdir(exist_ok=True)
    projects = [p for p in load_projects() if not args.only or p["project"] in args.only]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, p, args, sources, work, logs): p for p in projects}
        rows = []
        for future in as_completed(futures):
            row = future.result(); rows.append(row)
            print(f"{row['project']}: {row.get('verdict', row.get('status'))}", flush=True)
    rows.sort(key=lambda row: row["project"])
    write_results(rows, output)
    print(output / "summary.md")


if __name__ == "__main__":
    main()
