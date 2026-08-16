#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the broad auto-harness half of the pinned 200-project parity audit."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import signal
import shutil
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


HERE = Path(__file__).resolve().parent
LANGUAGE_ARG = {"js": "javascript", "ts": "typescript"}
# These lanes write GOVFUZZ_TARGET_ENTRY_SHM immediately before the selected
# endpoint. A false value is therefore a real miss, not an inference from
# launcher execution.
ENTRY_INSTRUMENTED = {
    "ada",
    "c",
    "cpp",
    "cobol",
    "csharp",
    "fortran",
    "go",
    "java",
    "js",
    "lua",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "ts",
}


def project_key(project: dict[str, str]) -> str:
    return f"{project['language']}__{project['repo'].replace('/', '__')}"


def load_projects(args) -> list[dict[str, str]]:
    with (HERE / "projects.tsv").open(newline="") as stream:
        projects = list(csv.DictReader(stream, delimiter="\t"))
    if args.only_language:
        projects = [row for row in projects if row["language"] in args.only_language]
    if args.only:
        projects = [
            row
            for row in projects
            if row["repo"] in args.only or project_key(row) in args.only
        ]
    if args.limit_per_language:
        counts: Counter[str] = Counter()
        limited = []
        for row in projects:
            if counts[row["language"]] >= args.limit_per_language:
                continue
            counts[row["language"]] += 1
            limited.append(row)
        projects = limited
    return projects


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    log: Path,
    timeout: int,
) -> tuple[int | None, bool]:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as output:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=os.name == "posix",
        )
        try:
            return process.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            # GovFuzz/build tools spawn compiler and linker grandchildren. Killing
            # only the direct process leaves those children orphaned and consuming
            # cores indefinitely (a GNAT child from one timed-out project survived
            # the earlier audit for more than an hour). Each command owns a fresh
            # session, so terminate exactly that process group, escalate after a
            # short grace period, and reap the leader before returning a durable row.
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
            output.write(f"\nAUDIT TIMEOUT after {timeout}s\n".encode())
            return None, True


def ensure_source(
    project: dict[str, str], sources: Path, logs: Path, timeout: int
) -> tuple[Path, str | None]:
    key = project_key(project)
    root = sources / key
    clone_log = logs / f"{key}-clone.log"
    if not (root / ".git").is_dir():
        if root.exists():
            shutil.rmtree(root)
        root.parent.mkdir(parents=True, exist_ok=True)
        rc, timed_out = run_command(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--no-tags",
                project["url"],
                str(root),
            ],
            log=clone_log,
            timeout=timeout,
        )
        if timed_out:
            return root, "clone timed out"
        if rc:
            return root, f"clone exited {rc}"
    rc, timed_out = run_command(
        ["git", "fetch", "--depth", "1", "origin", project["commit"]],
        cwd=root,
        log=clone_log,
        timeout=timeout,
    )
    if timed_out:
        return root, "fetch timed out"
    if rc:
        return root, f"fetch exited {rc}"
    rc, timed_out = run_command(
        ["git", "checkout", "--detach", "--force", project["commit"]],
        cwd=root,
        log=clone_log,
        timeout=timeout,
    )
    if timed_out:
        return root, "checkout timed out"
    if rc:
        return root, f"checkout exited {rc}"
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    if actual != project["commit"]:
        return root, f"revision mismatch: expected {project['commit']}, got {actual}"
    return root, None


def outcome_of(result: dict) -> tuple[str, str]:
    outcome = result.get("outcome") or {}
    if isinstance(outcome, str):
        return outcome, "-"
    diagnostic = outcome.get("reason")
    if not diagnostic and outcome.get("last_errors"):
        diagnostic = json.dumps(outcome["last_errors"], separators=(",", ":"))
    return outcome.get("outcome", "unknown"), diagnostic or "-"


def covered_line_count(harness: Path) -> int | None:
    path = harness / "covered-lines.txt"
    try:
        lines = {
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip().rsplit(":", 1)[-1].isdigit()
        }
    except OSError:
        return None
    return len(lines) or None


def target_entry_observed(result: dict, language: str) -> bool | None:
    """Return checkpoint proof, keeping unavailable distinct from a miss."""
    outcome = result.get("outcome") or {}
    passes = outcome.get("passes", []) if isinstance(outcome, dict) else []
    if any(run.get("target_entry_observed") is True for run in passes):
        return True
    if language in ENTRY_INSTRUMENTED:
        return False
    return None


def dynamic_coverage_edges(result: dict) -> int:
    """Return the strongest cumulative project-coverage signal from any pass."""
    outcome = result.get("outcome") or {}
    passes = outcome.get("passes", []) if isinstance(outcome, dict) else []
    return max((int(run.get("coverage_edges") or 0) for run in passes), default=0)


def result_rank(item: tuple[Path, dict], language: str) -> tuple[int, int, int, str]:
    """Prefer the strongest result when normal backfill attempted many targets."""
    path, result = item
    status, _ = outcome_of(result)
    trace = result.get("attempt_trace") or {}
    stage_rank = {
        "discover": 0,
        "generate": 1,
        "build": 2,
        "smoke": 3,
        "fuzz": 4,
    }.get(trace.get("terminal_stage"), -1)
    entered = target_entry_observed(result, language) is True
    return entered, status == "built_and_fuzzed", stage_rank, path.name


def run_one(project: dict[str, str], args, output: Path) -> dict[str, object]:
    key = project_key(project)
    row_path = output / "rows" / f"{key}.json"
    if args.resume and row_path.is_file():
        cached = read_json(row_path)
        # A signal-terminated child can race with an interrupted outer runner and
        # leave a syntactically valid `no_result` row (`returncode == -SIGINT`).
        # That is not a completed audit boundary; retry it just like a missing row.
        exit_code = cached.get("exit_code") if isinstance(cached, dict) else None
        if cached and not (isinstance(exit_code, int) and exit_code < 0):
            return cached
    sources = output / "sources"
    logs = output / "logs"
    source, source_error = ensure_source(project, sources, logs, args.clone_timeout)
    row: dict[str, object] = {
        "key": key,
        "language": project["language"],
        "repo": project["repo"],
        "commit": project["commit"],
        "prior_status": project["prior_status"],
        "govfuzz_version": args.govfuzz_version,
        "govfuzz_sha256": args.govfuzz_sha256,
    }
    if source_error:
        row.update(status="source_error", diagnostic=source_error)
    else:
        work = output / "work" / key
        # A durable row is the resume boundary and returned above. If there is no
        # row, any existing work directory is necessarily partial (for example a
        # process-group timeout or interrupted run) and must not leak generated
        # artifacts/results into the retry.
        if work.exists():
            shutil.rmtree(work)
        env = os.environ.copy()
        env["GOVFUZZ_BLIND_EXPERT_HARNESSES"] = "1"
        language = LANGUAGE_ARG.get(project["language"], project["language"])
        argv = [
            str(args.govfuzz),
            "auto",
            str(source),
            "--languages",
            language,
            "--work-dir",
            str(work),
            "--max-targets",
            "1",
            "--max-attempts",
            str(args.max_attempts),
            "--single-pass",
            "--per-target-time",
            str(args.seconds),
            "--jobs",
            "1",
            "--probe-build",
            "--comparison-progress",
            "--sanitizers",
            "none",
            "--profile",
            "external-tools",
            "--fresh-discovery",
        ]
        rc, timed_out = run_command(
            argv,
            env=env,
            log=logs / f"{key}.log",
            timeout=args.project_timeout,
        )
        row.update(exit_code=rc, timed_out=timed_out)
        results = []
        for path in work.glob("harnesses/*/result.json"):
            if value := read_json(path):
                results.append((path.parent, value))
        if not results:
            summary = read_json(work / "run-summary.json") or {}
            row.update(
                status="timeout" if timed_out else "no_result",
                diagnostic=summary.get("reason")
                or "no target attempt result was written",
                discovered=summary.get("discovered"),
            )
        else:
            harness, result = max(
                results, key=lambda item: result_rank(item, project["language"])
            )
            status, diagnostic = outcome_of(result)
            trace = result.get("attempt_trace") or {}
            target_entry = target_entry_observed(result, project["language"])
            coverage_edges = dynamic_coverage_edges(result)
            row.update(
                status=status,
                diagnostic=diagnostic,
                target=result.get("name"),
                source_path=result.get("source_path"),
                harness_id=result.get("harness_id", harness.name),
                launcher_fuzzed=status == "built_and_fuzzed",
                target_entry=target_entry,
                target_entry_evidence=(
                    "checkpoint"
                    if target_entry is True
                    else "checkpoint_miss"
                    if target_entry is False
                    else "not_instrumented"
                ),
                dynamic_coverage_edges=coverage_edges,
                target_body_reached=(coverage_edges > 0 if status == "built_and_fuzzed" else False),
                attempt_count=len(results),
                terminal_stage=trace.get("terminal_stage"),
                fallback_chain=trace.get("fallback_chain", []),
                repair_count=trace.get("repair_count", 0),
                generated_covered_lines=covered_line_count(harness),
            )
    row_path.parent.mkdir(parents=True, exist_ok=True)
    row_path.write_text(json.dumps(row, indent=2) + "\n")
    if not args.keep_sources and source.exists():
        shutil.rmtree(source)
    return row


def write_results(rows: list[dict[str, object]], output: Path) -> None:
    rows.sort(key=lambda row: (str(row["language"]), str(row["repo"])))
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    fields = [
        "language",
        "repo",
        "commit",
        "prior_status",
        "govfuzz_version",
        "govfuzz_sha256",
        "status",
        "launcher_fuzzed",
        "target_entry",
        "target_entry_evidence",
        "target_body_reached",
        "dynamic_coverage_edges",
        "attempt_count",
        "target",
        "source_path",
        "generated_covered_lines",
        "terminal_stage",
        "repair_count",
        "timed_out",
        "exit_code",
        "diagnostic",
    ]
    with (output / "results.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    by_language: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_language[str(row["language"])].append(row)
    lines = [
        "# 200-project multilingual parity audit — auto baseline",
        "",
        f"- GovFuzz versions: {', '.join(sorted({str(row.get('govfuzz_version', 'unknown')) for row in rows}))}",
        f"- GovFuzz binary SHA-256 values: {', '.join(sorted({str(row.get('govfuzz_sha256', 'unknown')) for row in rows}))}",
        f"- Projects attempted: {len(rows)}",
        f"- Launchers fuzzed: {sum(row.get('launcher_fuzzed') is True for row in rows)}",
        f"- Targets entered with checkpoint proof: {sum(row.get('target_entry') is True for row in rows)}",
        f"- Fuzzed targets with dynamic project coverage: "
        f"{sum(row.get('target_body_reached') is True for row in rows)}",
        f"- Fuzzed targets without entry instrumentation: "
        f"{sum(row.get('launcher_fuzzed') is True and row.get('target_entry') is None for row in rows)}",
        f"- Projects with generated line evidence: {sum(row.get('generated_covered_lines') is not None for row in rows)}",
        f"- Timed out: {sum(bool(row.get('timed_out')) for row in rows)}",
        "",
        "| Language | Projects | Launcher fuzzed | Entry proven | Body covered | Entry unavailable | Line evidence | Top residual outcomes |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for language, language_rows in sorted(by_language.items()):
        outcomes = Counter(str(row.get("status", "unknown")) for row in language_rows)
        residual = ", ".join(
            f"{name}={count}"
            for name, count in outcomes.most_common()
            if name != "built_and_fuzzed"
        ) or "none"
        lines.append(
            f"| {language} | {len(language_rows)} | "
            f"{sum(row.get('launcher_fuzzed') is True for row in language_rows)} | "
            f"{sum(row.get('target_entry') is True for row in language_rows)} | "
            f"{sum(row.get('target_body_reached') is True for row in language_rows)} | "
            f"{sum(row.get('launcher_fuzzed') is True and row.get('target_entry') is None for row in language_rows)} | "
            f"{sum(row.get('generated_covered_lines') is not None for row in language_rows)} | "
            f"{residual} |"
        )
    (output / "summary.md").write_text("\n".join(lines) + "\n")


def merge_existing_rows(
    rows: list[dict[str, object]], output: Path
) -> list[dict[str, object]]:
    """Merge a partial rerun with durable rows already present in the output.

    Newly executed rows always win. This is deliberately opt-in: a small pilot
    should normally summarize only the projects it ran, while a language repair
    pass over a completed 200-project output should preserve the other 15 lanes.
    """
    merged: dict[str, dict[str, object]] = {}
    for path in sorted((output / "rows").glob("*.json")):
        value = read_json(path)
        if isinstance(value, dict) and isinstance(value.get("key"), str):
            merged[str(value["key"])] = value
    for row in rows:
        if isinstance(row.get("key"), str):
            merged[str(row["key"])] = row
    return list(merged.values())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--govfuzz", type=Path, default=HERE.parents[1] / "target/release/govfuzz"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("/tmp/govfuzz-harness-parity-200")
    )
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--max-attempts", type=int, default=10)
    parser.add_argument("--project-timeout", type=int, default=240)
    parser.add_argument("--clone-timeout", type=int, default=300)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--include-existing",
        action="store_true",
        help="include durable rows from other projects in the final summary",
    )
    parser.add_argument("--keep-sources", action="store_true")
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--only-language", action="append", default=[])
    parser.add_argument("--limit-per-language", type=int)
    args = parser.parse_args()
    args.govfuzz = args.govfuzz.resolve()
    args.govfuzz_sha256 = hashlib.sha256(args.govfuzz.read_bytes()).hexdigest()
    try:
        args.govfuzz_version = subprocess.check_output(
            [str(args.govfuzz), "--version"], text=True, timeout=10
        ).strip()
    except (OSError, subprocess.SubprocessError):
        args.govfuzz_version = "unknown"
    output = args.output.resolve()
    for directory in [output, output / "sources", output / "work", output / "logs", output / "rows"]:
        directory.mkdir(parents=True, exist_ok=True)
    projects = load_projects(args)
    rows = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, row, args, output): row for row in projects}
        for future in as_completed(futures):
            project = futures[future]
            try:
                row = future.result()
            except Exception as error:  # one repository must not abort 199 peers
                row = {
                    "key": project_key(project),
                    "language": project["language"],
                    "repo": project["repo"],
                    "commit": project["commit"],
                    "prior_status": project["prior_status"],
                    "govfuzz_version": args.govfuzz_version,
                    "govfuzz_sha256": args.govfuzz_sha256,
                    "status": "runner_error",
                    "diagnostic": repr(error),
                }
            rows.append(row)
            print(
                f"{row['language']} {row['repo']}: {row.get('status')} "
                f"target={row.get('target', '-')} entry={row.get('target_entry', False)}",
                flush=True,
            )
    if args.include_existing:
        rows = merge_existing_rows(rows, output)
    write_results(rows, output)
    print(output / "summary.md")


if __name__ == "__main__":
    main()
