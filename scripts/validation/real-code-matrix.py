#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "tests/fixtures/real_code_validation/manifest.toml"
DEFAULT_WORKSPACE = Path(os.environ.get("GOVFUZZ_REAL_CODE_WORKSPACE", "/tmp/govfuzz-real-code-validation"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run GovFuzz against pinned real codebases.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--offline", action="store_true", help="Do not fetch missing or wrong-rev repositories.")
    parser.add_argument("--dry-run", action="store_true", help="Print the matrix without cloning or running commands.")
    parser.add_argument("--json", action="store_true", help="Print JSON results to stdout.")
    parser.add_argument("--json-out", type=Path, help="Write JSON results to this path.")
    parser.add_argument("--markdown-out", type=Path, help="Write a Markdown evidence report to this path.")
    parser.add_argument("--repo", action="append", default=[], help="Limit execution to one repository id. Repeatable.")
    return parser.parse_args()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


SCHEMA_VERSION = "govfuzz.real_code_matrix.v1"


def matrix_repos(manifest: dict[str, Any], selected: set[str] | None = None) -> list[dict[str, Any]]:
    return [r for r in manifest.get("repositories", []) if not selected or r["id"] in selected]


def matrix_summary(manifest: dict[str, Any], selected: set[str] | None = None) -> dict[str, Any]:
    repos = matrix_repos(manifest, selected)
    summary: dict[str, Any] = {
        "repositories": len(repos),
        "checks": sum(len(r.get("checks", [])) for r in repos),
        "scenarios": sum(len(r.get("scenarios", [])) for r in repos),
        "language_coverage": {},
        "checks_by_kind": {},
        "scenarios_by_kind": {},
        "broken_build_by_language": {},
        "known_gaps_by_language": {},
        "toolchain_gaps_by_language": {},
        "expected_outcomes": {
            "target_discovery": 0,
            "harness_build": 0,
            "instrumentation": 0,
            "broken_build_recovery": 0,
            "known_gaps": 0,
            "toolchain_gaps": 0,
        },
    }
    for repo in repos:
        language = repo["language"]
        language_bucket = summary["language_coverage"].setdefault(
            language, {"repositories": 0, "checks": 0, "scenarios": 0}
        )
        language_bucket["repositories"] += 1
        language_bucket["checks"] += len(repo.get("checks", []))
        language_bucket["scenarios"] += len(repo.get("scenarios", []))
        summary["broken_build_by_language"].setdefault(language, False)
        summary["known_gaps_by_language"].setdefault(language, 0)
        summary["toolchain_gaps_by_language"].setdefault(language, 0)

        for check in repo.get("checks", []):
            kind = check["kind"]
            summary["checks_by_kind"][kind] = summary["checks_by_kind"].get(kind, 0) + 1
            outcome = check_expected_outcome(kind)
            if outcome:
                summary["expected_outcomes"][outcome] += 1
            if check.get("expect_status") == "known_gap":
                summary["known_gaps_by_language"][language] += 1
                summary["expected_outcomes"]["known_gaps"] += 1
            elif check.get("expect_status") == "toolchain_gap":
                summary["toolchain_gaps_by_language"][language] += 1
                summary["expected_outcomes"]["toolchain_gaps"] += 1

        for scenario in repo.get("scenarios", []):
            kind = scenario["kind"]
            summary["scenarios_by_kind"][kind] = summary["scenarios_by_kind"].get(kind, 0) + 1
            if kind in {"auto_missing_file", "known_gap", "toolchain_gap"}:
                summary["broken_build_by_language"][language] = True
            outcome = scenario_expected_outcome(kind)
            if outcome:
                summary["expected_outcomes"][outcome] += 1
            if kind == "known_gap":
                summary["known_gaps_by_language"][language] += 1
                summary["expected_outcomes"]["known_gaps"] += 1
            elif kind == "toolchain_gap":
                summary["toolchain_gaps_by_language"][language] += 1
                summary["expected_outcomes"]["toolchain_gaps"] += 1

    for language in ("ada", "c", "cpp"):
        summary["language_coverage"].setdefault(
            language, {"repositories": 0, "checks": 0, "scenarios": 0}
        )
        summary["broken_build_by_language"].setdefault(language, False)
        summary["known_gaps_by_language"].setdefault(language, 0)
        summary["toolchain_gaps_by_language"].setdefault(language, 0)

    return summary


def check_expected_outcome(kind: str) -> str | None:
    if kind in {"list_targets", "scan"}:
        return "target_discovery"
    if kind in {"generate_harness_build", "generate_harness_gpr"}:
        return "harness_build"
    if kind == "instrument":
        return "instrumentation"
    return None


def scenario_expected_outcome(kind: str) -> str | None:
    if kind in {"auto_missing_file", "toolchain_gap"}:
        return "broken_build_recovery"
    return None


def bounded_subset_metadata(manifest: dict[str, Any], selected: set[str] | None = None) -> dict[str, Any]:
    configured = list(manifest.get("settings", {}).get("bounded_subset", []))
    if selected:
        configured = [repo_id for repo_id in configured if repo_id in selected]
    available_ids = {repo["id"] for repo in matrix_repos(manifest, selected)}
    runnable = [repo_id for repo_id in configured if repo_id in available_ids]
    return {
        "ci_ready": bool(runnable),
        "repositories": runnable,
        "requires_network": False,
        "mode": "bounded_offline_after_materialization",
    }


def result_envelope(manifest: dict[str, Any], selected: set[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "offline": {
            "mode": "rerunnable_after_materialization",
            "workspace": str(DEFAULT_WORKSPACE),
            "network_required_for_first_materialization": True,
        },
        "bounded_subset": bounded_subset_metadata(manifest, selected),
        "evidence_claim": {
            "claim": "offline government legacy software fuzzer readiness",
            "scope": "Ada / C / C++ source, broken-build recovery, and binary/enterprise evidence when companion reports are supplied",
            "limitations": [
                "Dry-run validates the matrix contract but does not clone or execute repositories.",
                "Full execution requires first materialization unless --offline points at an already populated workspace.",
                "Toolchain gaps are reported separately from GovFuzz defects.",
            ],
        },
    }


def add_readiness_gate(result: dict[str, Any]) -> None:
    summary = result.get("summary", {})
    languages = ["ada", "c", "cpp"]
    reasons: list[str] = []
    for language in languages:
        repos = summary.get("language_coverage", {}).get(language, {}).get("repositories", 0)
        if repos < 1:
            reasons.append(f"missing {language} repository evidence")
        if not summary.get("broken_build_by_language", {}).get(language, False):
            reasons.append(f"missing {language} broken-build evidence")
    if summary.get("checks", 0) < 6:
        reasons.append("matrix has fewer than six checks")
    if summary.get("scenarios", 0) < 3:
        reasons.append("matrix has fewer than three breakage scenarios")
    if not result.get("bounded_subset", {}).get("ci_ready", False):
        reasons.append("bounded offline subset is not configured")
    if summary.get("failed", 0):
        reasons.append("one or more executed matrix entries failed")

    result["readiness_gate"] = {
        "status": "pass" if not reasons else "fail",
        "failed_reasons": reasons,
        "thresholds": {
            "languages": languages,
            "minimum_checks": 6,
            "minimum_scenarios": 3,
            "requires_broken_build_by_language": True,
            "requires_bounded_subset": True,
        },
    }


def dry_run(manifest: dict[str, Any], selected: set[str] | None = None) -> dict[str, Any]:
    repos = []
    for repo in matrix_repos(manifest, selected):
        repos.append(
            {
                "id": repo["id"],
                "language": repo["language"],
                "rev": repo["rev"],
                "checks": [check["kind"] for check in repo.get("checks", [])],
                "scenarios": [
                    {
                        "id": scenario["id"],
                        "kind": scenario["kind"],
                        "status": scenario.get("kind", "planned"),
                    }
                    for scenario in repo.get("scenarios", [])
                ],
            }
        )
    result = result_envelope(manifest, selected)
    result.update({"summary": matrix_summary(manifest, selected), "repositories": repos})
    add_readiness_gate(result)
    return result


def run(cmd: list[str], *, cwd: Path | None = None, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not allow_failure and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def govfuzz_cmd(args: list[str]) -> list[str]:
    override = os.environ.get("GOVFUZZ_BIN")
    if override:
        return [override, *args]
    return ["cargo", "run", "--quiet", "-p", "govfuzz", "--", *args]


def ensure_repo(repo: dict[str, Any], workspace: Path, offline: bool) -> Path:
    repo_dir = workspace / "repos" / repo["id"]
    if repo_dir.exists():
        current = run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"]).stdout.strip()
        if current == repo["rev"]:
            return repo_dir
        if offline:
            raise RuntimeError(f"{repo['id']}: expected {repo['rev']} but workspace has {current}")
        run(["git", "-C", str(repo_dir), "fetch", "--quiet", "origin", repo["rev"]])
        run(["git", "-C", str(repo_dir), "checkout", "--quiet", repo["rev"]])
        return repo_dir

    if offline:
        raise RuntimeError(f"{repo['id']}: missing {repo_dir} and --offline was requested")
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--quiet", repo["url"], str(repo_dir)])
    run(["git", "-C", str(repo_dir), "checkout", "--quiet", repo["rev"]])
    return repo_dir


def prepare_repo(repo: dict[str, Any], repo_dir: Path) -> list[dict[str, Any]]:
    results = []
    for step in repo.get("prepare", []):
        if step["kind"] != "cmake":
            raise RuntimeError(f"{repo['id']}: unsupported prepare kind {step['kind']}")
        build_dir = repo_dir / step.get("build_dir", "build")
        cmd = ["cmake", "-S", str(repo_dir), "-B", str(build_dir), *step.get("args", [])]
        proc = run(cmd)
        results.append({"kind": "cmake", "status": "passed", "build_dir": str(build_dir), "stdout": proc.stdout[-2000:]})
    return results


def check_list_targets(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any]) -> dict[str, Any]:
    target_path = repo_dir / check.get("path", ".")
    top = str(check.get("top", 20))
    proc = run(govfuzz_cmd(["list-targets", str(target_path), "--format", "json", "--top", top]))
    targets = json.loads(proc.stdout)
    min_targets = int(check.get("min_targets", 1))
    if len(targets) < min_targets:
        raise RuntimeError(f"{repo['id']}: list-targets returned {len(targets)} targets, expected >= {min_targets}")
    return {"kind": "list_targets", "status": "passed", "targets": len(targets)}


def check_scan(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any], workspace: Path) -> dict[str, Any]:
    work_dir = workspace / "results" / repo["id"] / "scan"
    if work_dir.exists():
        shutil.rmtree(work_dir)
    target_path = repo_dir / check.get("path", ".")
    run(govfuzz_cmd(["scan", str(target_path), "--work-dir", str(work_dir)]))
    scan_json = json.loads((work_dir / "scan_index.json").read_text())
    total_targets = int(scan_json.get("total_targets", 0))
    min_targets = int(check.get("min_targets", 1))
    if total_targets < min_targets:
        raise RuntimeError(f"{repo['id']}: scan found {total_targets} targets, expected >= {min_targets}")
    return {"kind": "scan", "status": "passed", "total_targets": total_targets}


def check_generate_harness_build(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any], workspace: Path) -> dict[str, Any]:
    work_dir = workspace / "results" / repo["id"] / check["harness_id"]
    if work_dir.exists():
        shutil.rmtree(work_dir)
    output_dir = work_dir / "generated_harnesses"
    run(
        govfuzz_cmd(
            [
                "generate-harness",
                str(repo_dir / check["source"]),
                "--target",
                check["target"],
                "--id",
                check["harness_id"],
                "--output",
                str(output_dir),
            ]
        )
    )
    makefile = output_dir / check["harness_id"] / "Makefile"
    text = makefile.read_text()
    for needle in check.get("expect_makefile_contains", []):
        if needle not in text:
            raise RuntimeError(f"{repo['id']}: {makefile} did not contain {needle!r}")
    run(govfuzz_cmd(["build", str(work_dir), "--harness", check["harness_id"]]))
    return {"kind": "generate_harness_build", "status": "passed", "harness_id": check["harness_id"]}


def check_instrument(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any], workspace: Path) -> dict[str, Any]:
    out_dir = workspace / "results" / repo["id"] / "instrument"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    run(govfuzz_cmd(["instrument", str(repo_dir / check["source"]), "--output", str(out_dir)]))
    if not (out_dir / "breadcrumbs.json").is_file():
        raise RuntimeError(f"{repo['id']}: instrumentation did not write breadcrumbs.json")
    return {"kind": "instrument", "status": "passed", "source": check["source"]}


def check_generate_harness_gpr(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any], workspace: Path) -> dict[str, Any]:
    work_dir = workspace / "results" / repo["id"] / check["harness_id"]
    if work_dir.exists():
        shutil.rmtree(work_dir)
    output_dir = work_dir / "generated_harnesses"
    cmd = [
        "generate-harness",
        str(repo_dir / check["source"]),
        "--target",
        check["target"],
        "--id",
        check["harness_id"],
        "--source-tree",
        str(repo_dir / check["source_tree"]),
        "--output",
        str(output_dir),
    ]
    if "project" in check:
        cmd.extend(["--project", str(repo_dir / check["project"])])
    run(govfuzz_cmd(cmd))
    gpr = output_dir / check["harness_id"] / f"{check['harness_id'].replace('-', '_')}.gpr"
    proc = run(["gprbuild", "-P", str(gpr)], allow_failure=True)
    expected = check.get("expect_status", "passed")
    if expected == "known_gap":
        needle = check.get("expect_stderr_contains", "")
        haystack = proc.stdout + proc.stderr
        if proc.returncode == 0 or needle not in haystack:
            raise RuntimeError(f"{repo['id']}: expected known gprbuild gap containing {needle!r}")
        return {"kind": "generate_harness_gpr", "status": "known_gap", "detail": needle}
    if expected == "toolchain_gap":
        needle = check.get("expect_stderr_contains", "")
        haystack = proc.stdout + proc.stderr
        if proc.returncode == 0 or needle not in haystack:
            raise RuntimeError(f"{repo['id']}: expected toolchain gap containing {needle!r}")
        return {"kind": "generate_harness_gpr", "status": "toolchain_gap", "detail": needle}
    if proc.returncode != 0:
        raise RuntimeError(f"{repo['id']}: gprbuild failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return {"kind": "generate_harness_gpr", "status": "passed"}


def run_check(repo: dict[str, Any], repo_dir: Path, check: dict[str, Any], workspace: Path) -> dict[str, Any]:
    kind = check["kind"]
    if kind == "list_targets":
        return check_list_targets(repo, repo_dir, check)
    if kind == "scan":
        return check_scan(repo, repo_dir, check, workspace)
    if kind == "generate_harness_build":
        return check_generate_harness_build(repo, repo_dir, check, workspace)
    if kind == "instrument":
        return check_instrument(repo, repo_dir, check, workspace)
    if kind == "generate_harness_gpr":
        return check_generate_harness_gpr(repo, repo_dir, check, workspace)
    raise RuntimeError(f"{repo['id']}: unsupported check kind {kind}")


def copy_repo_for_scenario(repo_dir: Path, scenario_dir: Path) -> None:
    if scenario_dir.exists():
        shutil.rmtree(scenario_dir)
    shutil.copytree(repo_dir, scenario_dir, ignore=shutil.ignore_patterns(".git"))


def scenario_auto_missing_file(repo: dict[str, Any], repo_dir: Path, scenario: dict[str, Any], workspace: Path, default_time: int) -> dict[str, Any]:
    scenario_dir = workspace / "scenarios" / repo["id"] / scenario["id"]
    copy_repo_for_scenario(repo_dir, scenario_dir)
    for rel in scenario.get("remove_files", []):
        path = scenario_dir / rel
        if not path.is_file():
            raise RuntimeError(f"{repo['id']}:{scenario['id']}: missing removal target {rel}")
        path.unlink()
    work_dir = scenario_dir / "govfuzz_work"
    cmd = [
        "auto",
        str(scenario_dir),
        "--work-dir",
        str(work_dir),
        "--per-target-time",
        str(scenario.get("per_target_time", default_time)),
    ]
    for target in scenario.get("targets", []):
        cmd.extend(["--target", target])
    run(govfuzz_cmd(cmd), allow_failure=True)
    run_json = json.loads((work_dir / "auto" / "run.json").read_text())
    needed = run_json.get("needed_for_build", {})
    for expected in scenario.get("expect_needed", []):
        bucket = expected["bucket"]
        locator = expected["locator"]
        entries = needed.get(bucket, [])
        if not any(entry.get("name") == locator for entry in entries):
            raise RuntimeError(f"{repo['id']}:{scenario['id']}: expected {locator!r} in needed_for_build.{bucket}")
    return {
        "id": scenario["id"],
        "kind": "auto_missing_file",
        "status": "passed",
        "summary": run_json.get("summary", {}),
    }


def run_scenario(repo: dict[str, Any], repo_dir: Path, scenario: dict[str, Any], workspace: Path, default_time: int) -> dict[str, Any]:
    kind = scenario["kind"]
    if kind == "auto_missing_file":
        return scenario_auto_missing_file(repo, repo_dir, scenario, workspace, default_time)
    if kind == "known_gap":
        return {"id": scenario["id"], "kind": "known_gap", "status": "known_gap", "detail": scenario.get("description", "")}
    if kind == "toolchain_gap":
        return {"id": scenario["id"], "kind": "toolchain_gap", "status": "toolchain_gap", "detail": scenario.get("description", "")}
    raise RuntimeError(f"{repo['id']}:{scenario['id']}: unsupported scenario kind {kind}")


def execute(manifest: dict[str, Any], workspace: Path, offline: bool, selected: set[str] | None) -> dict[str, Any]:
    workspace.mkdir(parents=True, exist_ok=True)
    default_time = int(manifest.get("settings", {}).get("per_target_time", 2))
    result: dict[str, Any] = result_envelope(manifest, selected)
    result.update({
        "summary": {"repositories": 0, "checks": 0, "scenarios": 0, "passed": 0, "failed": 0, "known_gaps": 0, "toolchain_gaps": 0},
        "repositories": [],
    })
    for key, value in matrix_summary(manifest, selected).items():
        if key not in {"repositories", "checks", "scenarios"}:
            result["summary"][key] = value
    for repo in matrix_repos(manifest, selected):
        repo_result: dict[str, Any] = {"id": repo["id"], "language": repo["language"], "checks": [], "scenarios": []}
        result["summary"]["repositories"] += 1
        try:
            repo_dir = ensure_repo(repo, workspace, offline)
            repo_result["path"] = str(repo_dir)
            repo_result["prepare"] = prepare_repo(repo, repo_dir)
            for check in repo.get("checks", []):
                check_result = run_check(repo, repo_dir, check, workspace)
                repo_result["checks"].append(check_result)
                result["summary"]["checks"] += 1
                if check_result["status"] == "known_gap":
                    result["summary"]["known_gaps"] += 1
                elif check_result["status"] == "toolchain_gap":
                    result["summary"]["toolchain_gaps"] += 1
                else:
                    result["summary"]["passed"] += 1
            for scenario in repo.get("scenarios", []):
                scenario_result = run_scenario(repo, repo_dir, scenario, workspace, default_time)
                repo_result["scenarios"].append(scenario_result)
                result["summary"]["scenarios"] += 1
                if scenario_result["status"] == "known_gap":
                    result["summary"]["known_gaps"] += 1
                elif scenario_result["status"] == "toolchain_gap":
                    result["summary"]["toolchain_gaps"] += 1
                else:
                    result["summary"]["passed"] += 1
        except Exception as exc:  # noqa: BLE001 - script reports all validation failures as JSON.
            repo_result["status"] = "failed"
            repo_result["error"] = str(exc)
            result["summary"]["failed"] += 1
        else:
            repo_result["status"] = "passed"
        result["repositories"].append(repo_result)
    add_readiness_gate(result)
    return result


def render_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    gate = result.get("readiness_gate", {})
    language_coverage = summary.get("language_coverage", {})
    expected = summary.get("expected_outcomes", {})
    lines = [
        "# Real-Code Evidence Matrix",
        "",
        f"- Readiness gate: {gate.get('status', 'unknown')}",
        f"- Repositories: {summary.get('repositories', 0)}",
        f"- Checks: {summary.get('checks', 0)}",
        f"- Scenarios: {summary.get('scenarios', 0)}",
        "- Scope: Ada / C / C++ real-code validation with deliberate broken-build scenarios",
        "",
        "## Language Coverage",
        "",
    ]
    for language in ["ada", "c", "cpp"]:
        bucket = language_coverage.get(language, {})
        broken = summary.get("broken_build_by_language", {}).get(language, False)
        lines.append(
            f"- {language}: {bucket.get('repositories', 0)} repo(s), "
            f"{bucket.get('checks', 0)} check(s), {bucket.get('scenarios', 0)} scenario(s), "
            f"broken-build evidence: {str(broken).lower()}"
        )
    lines.extend([
        "",
        "## Expected Outcomes",
        "",
    ])
    for key in sorted(expected):
        lines.append(f"- {key}: {expected[key]}")
    if gate.get("failed_reasons"):
        lines.extend(["", "## Gate Failures", ""])
        for reason in gate["failed_reasons"]:
            lines.append(f"- {reason}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    manifest = load_manifest(args.manifest)
    selected = set(args.repo) if args.repo else None
    result = dry_run(manifest, selected) if args.dry_run else execute(manifest, args.workspace, args.offline, selected)
    encoded = json.dumps(result, indent=2, sort_keys=True)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded + "\n")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(result))
    if args.json or args.dry_run or not args.json_out:
        print(encoded)
    if not args.dry_run and result["summary"].get("failed", 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
