#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import math
import os
import signal
import shutil
import subprocess
import threading
import time
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    REPO_ROOT / "tests/fixtures/legacy_breakage_validation/manifest.toml"
)
DEFAULT_WORKSPACE = Path(
    os.environ.get(
        "GOVFUZZ_LEGACY_BREAKAGE_WORKSPACE", "/tmp/govfuzz-legacy-breakage"
    )
)
SCHEMA_VERSION = "govfuzz.legacy_breakage_matrix.v2"
ADA_LOCK = threading.Lock()
CAP_CANDIDATES = (1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Delete required artifacts from pinned legacy projects and require "
            "GovFuzz to build and fuzz the surviving real target."
        )
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument(
        "--materialized-root",
        type=Path,
        help=(
            "Root containing the already-cloned repositories at each scenario's "
            "materialized_path. Avoids all network access."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Fail instead of cloning when a pinned repository is unavailable.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="Run only the named scenario. Repeatable.",
    )
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and print the matrix without copying or executing projects.",
    )
    return parser.parse_args()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def selected_scenarios(
    manifest: dict[str, Any], selected: set[str]
) -> list[dict[str, Any]]:
    scenarios = list(manifest.get("scenarios", []))
    if selected:
        scenarios = [scenario for scenario in scenarios if scenario["id"] in selected]
        missing = selected - {scenario["id"] for scenario in scenarios}
        if missing:
            raise RuntimeError(f"unknown scenario(s): {', '.join(sorted(missing))}")
    return scenarios


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd or REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        # Auto's post-campaign analyzers can launch harness and symbolizer
        # descendants. Kill the whole session so none retain these capture pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            command, timeout, output=stdout, stderr=stderr
        ) from error
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def govfuzz_binary() -> Path:
    override = os.environ.get("GOVFUZZ_BIN")
    binary = Path(override) if override else REPO_ROOT / "target/release/govfuzz"
    if not binary.is_file():
        raise RuntimeError(
            f"GovFuzz binary not found at {binary}; run cargo build --release -p govfuzz"
        )
    return binary.resolve()


def repository_path(
    scenario: dict[str, Any],
    workspace: Path,
    materialized_root: Path | None,
    offline: bool,
) -> Path:
    if materialized_root is not None:
        candidate = materialized_root / scenario["materialized_path"]
        if candidate.joinpath(".git").is_dir():
            verify_revision(candidate, scenario)
            return candidate
        if offline:
            raise RuntimeError(f"materialized repository missing: {candidate}")

    candidate = workspace / "repositories" / scenario["repository_id"]
    if candidate.joinpath(".git").is_dir():
        verify_revision(candidate, scenario)
        return candidate
    if offline:
        raise RuntimeError(
            f"{scenario['id']}: repository is not materialized and --offline was requested"
        )

    candidate.parent.mkdir(parents=True, exist_ok=True)
    clone = run(["git", "clone", "--quiet", scenario["url"], str(candidate)])
    if clone.returncode != 0:
        raise RuntimeError(f"git clone failed: {clone.stderr.strip()}")
    checkout = run(
        ["git", "-C", str(candidate), "checkout", "--quiet", scenario["rev"]]
    )
    if checkout.returncode != 0:
        raise RuntimeError(f"git checkout failed: {checkout.stderr.strip()}")
    verify_revision(candidate, scenario)
    return candidate


def verify_revision(repo: Path, scenario: dict[str, Any]) -> None:
    revision = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    actual = revision.stdout.strip()
    if revision.returncode != 0 or actual != scenario["rev"]:
        raise RuntimeError(
            f"{scenario['id']}: expected {scenario['rev']}, found {actual or 'unknown'}"
        )


def verified_relative_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"constraint evidence path is not confined: {relative}")
    return root / candidate


def verify_external_constraint(
    scenario: dict[str, Any], scenario_root: Path
) -> dict[str, Any] | None:
    constraint = scenario.get("external_constraint")
    if constraint is None:
        return None
    kind = str(constraint.get("kind", "")).strip()
    proof = str(constraint.get("proof", "")).strip()
    probes = list(constraint.get("probes", []))
    absent_paths = list(constraint.get("absent_paths", []))
    control_failure_contains = [
        str(value) for value in constraint.get("control_failure_contains", [])
    ]
    if not kind or not proof:
        raise RuntimeError(
            f"{scenario['id']}: external constraint requires non-empty kind and proof"
        )
    if not probes and not absent_paths:
        raise RuntimeError(
            f"{scenario['id']}: external constraint has no machine-checkable evidence"
        )
    if not control_failure_contains or any(
        not value for value in control_failure_contains
    ):
        raise RuntimeError(
            f"{scenario['id']}: external constraint requires non-empty "
            "control_failure_contains evidence"
        )

    verified_probes: list[dict[str, Any]] = []
    for probe in probes:
        relative = str(probe.get("path", ""))
        required = str(probe.get("contains", ""))
        if not relative or not required:
            raise RuntimeError(
                f"{scenario['id']}: constraint probe requires path and contains"
            )
        path = verified_relative_path(scenario_root, relative)
        if not path.is_file():
            raise RuntimeError(
                f"{scenario['id']}: constraint evidence file is missing: {relative}"
            )
        text = path.read_text(encoding="utf-8", errors="replace")
        if required not in text:
            raise RuntimeError(
                f"{scenario['id']}: constraint evidence {relative} does not contain "
                f"{required!r}"
            )
        verified_probes.append({"path": relative, "contains": required})

    verified_absent: list[str] = []
    for relative_value in absent_paths:
        relative = str(relative_value)
        path = verified_relative_path(scenario_root, relative)
        if path.exists() or path.is_symlink():
            raise RuntimeError(
                f"{scenario['id']}: expected external/generated path is present: {relative}"
            )
        verified_absent.append(relative)

    return {
        "kind": kind,
        "proof": proof,
        "verified": True,
        "probes": verified_probes,
        "absent_paths": verified_absent,
        "control_failure_contains": control_failure_contains,
    }


def verify_external_control_failure(
    constraint: dict[str, Any], control: dict[str, Any]
) -> dict[str, Any]:
    expected = list(constraint["control_failure_contains"])
    log_path = Path(str(control.get("log", "")))
    log_text = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file()
        else ""
    )
    matched = [value for value in expected if value in log_text]
    return {
        "verified": control.get("status") == "failed" and matched == expected,
        "expected": expected,
        "matched": matched,
        "log": str(log_path),
    }


def export_clean_tree(
    repo: Path, destination: Path, revision: str, preserve_vcs_history: bool
) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    if preserve_vcs_history:
        clone = run(
            [
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(repo),
                str(destination),
            ]
        )
        if clone.returncode != 0:
            raise RuntimeError(f"local shared clone failed: {clone.stderr.strip()}")
        checkout = run(
            ["git", "-C", str(destination), "checkout", "--quiet", "--detach", revision]
        )
        if checkout.returncode != 0:
            raise RuntimeError(
                f"local shared clone checkout failed: {checkout.stderr.strip()}"
            )
        return
    destination.mkdir(parents=True)
    archive = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert archive.stdout is not None
    extract = subprocess.run(
        ["tar", "-xf", "-", "-C", str(destination)],
        stdin=archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        check=False,
    )
    archive.stdout.close()
    archive_stderr = archive.stderr.read().decode(errors="replace") if archive.stderr else ""
    archive_rc = archive.wait()
    if archive_rc != 0 or extract.returncode != 0:
        raise RuntimeError(
            "clean tree export failed: "
            + archive_stderr
            + extract.stderr.decode(errors="replace")
        )


def apply_and_verify_mutation(
    scenario: dict[str, Any], scenario_root: Path
) -> dict[str, Any]:
    target_file = scenario_root / scenario["target_file"]
    probe_file = scenario_root / scenario.get("probe_file", scenario["target_file"])
    if not target_file.is_file():
        raise RuntimeError(f"target implementation is missing: {scenario['target_file']}")
    if not probe_file.is_file():
        raise RuntimeError(f"breakage probe is missing: {probe_file}")

    probe_text = probe_file.read_text(encoding="utf-8", errors="replace")
    required = scenario["probe_contains"]
    if required not in probe_text:
        raise RuntimeError(
            f"{scenario['id']}: probe does not contain required reference {required!r}"
        )

    removed_contains = scenario.get("removed_contains")
    removed: list[str] = []
    for relative in scenario["remove_files"]:
        path = scenario_root / relative
        if removed_contains is not None:
            if not path.is_file():
                raise RuntimeError(
                    f"cannot verify removed artifact content for non-file: {relative}"
                )
            removed_text = path.read_text(encoding="utf-8", errors="replace")
            contains_removed_symbol = (
                removed_contains.lower() in removed_text.lower()
                if scenario.get("language") == "ada"
                else removed_contains in removed_text
            )
            if not contains_removed_symbol:
                raise RuntimeError(
                    f"{scenario['id']}: removed artifact does not define/reference "
                    f"{removed_contains!r}"
                )
        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            raise RuntimeError(f"removal artifact does not exist: {relative}")
        removed.append(relative)

    if not target_file.is_file():
        raise RuntimeError("mutation removed the target implementation")
    return {
        "target_file": scenario["target_file"],
        "probe_file": str(probe_file.relative_to(scenario_root)),
        "probe_contains": required,
        "removed": removed,
        "removed_contains": removed_contains,
        "proof": scenario.get(
            "proof",
            "surviving target closure references a symbol or unit supplied by the "
            "removed artifact",
        ),
    }


def scenario_command(
    scenario: dict[str, Any],
    scenario_root: Path,
    work_dir: Path,
    settings: dict[str, Any],
    *,
    control: bool = False,
) -> list[str]:
    iterations_key = "control_iterations" if control else "iterations"
    time_key = "control_per_target_time" if control else "per_target_time"
    return [
        str(govfuzz_binary()),
        "auto",
        str(scenario_root),
        "--work-dir",
        str(work_dir),
        "--profile",
        "external-tools",
        "--target",
        scenario["target_name"],
        "--target-file",
        str(scenario_root / scenario["target_file"]),
        "--iterations",
        str(settings.get(iterations_key, 1 if control else 8)),
        "--passes",
        "fuzz",
        "--per-target-time",
        str(settings.get(time_key, 3 if control else 10)),
        "--max-repair-rounds",
        str(settings.get("max_repair_rounds", 16)),
        "--sanitizers",
        "none",
        "--no-discovery-cache",
        "-v",
    ]


def assess_run(
    scenario: dict[str, Any],
    run_json: dict[str, Any],
    *,
    require_repair: bool = True,
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []
    summary = run_json.get("summary", {})
    target_path = scenario["target_file"].replace("\\", "/")
    targets = [
        target
        for target in run_json.get("targets", [])
        if str(target.get("source", "")).replace("\\", "/").endswith(target_path)
        and str(target.get("name", "")).lower() == scenario["target_name"].lower()
        and (
            "target_line" not in scenario
            or int(target.get("line", -1)) == int(scenario["target_line"])
        )
    ]
    if len(targets) != 1:
        reasons.append(f"expected one selected target, found {len(targets)}")
        return False, reasons, {"summary": summary}

    target = targets[0]
    outcome = target.get("outcome", {})
    repairs = list(outcome.get("repairs", []))
    passes = list(outcome.get("passes", []))
    executions = sum(int(item.get("executions", 0)) for item in passes)
    coverage_edges = max(
        (int(item.get("coverage_edges", 0)) for item in passes), default=0
    )
    target_symbol = scenario.get(
        "target_symbol",
        scenario["target_name"].rsplit("::", 1)[-1].split("(", 1)[0],
    ).lower()
    target_stubbed = any(
        repair.get("kind") in {"stub_blind", "stub_declared"}
        and str(repair.get("symbol", "")).lower().rsplit("::", 1)[-1]
        == target_symbol
        for repair in repairs
    )

    if outcome.get("outcome") != "built_and_fuzzed":
        reasons.append(f"outcome is {outcome.get('outcome', 'missing')}")
    if int(summary.get("built_and_fuzzed", 0)) < 1:
        reasons.append("run summary has no built_and_fuzzed target")
    if int(summary.get("fuzzed_stub_only", 0)) != 0:
        reasons.append("run was downgraded to fuzzed_stub_only")
    if executions < 1:
        reasons.append("fuzz pass executed no inputs")
    if coverage_edges < 1:
        reasons.append("fuzz pass recorded no coverage edges")
    if require_repair and len(repairs) < int(scenario.get("min_repairs", 1)):
        reasons.append("mutation triggered no recorded build repair")
    if target_stubbed:
        reasons.append("the selected target itself was stubbed")

    evidence = {
        "summary": summary,
        "outcome": outcome.get("outcome"),
        "repairs": len(repairs),
        "repair_rounds": int(outcome.get("retries", 0)),
        "build_attempts": int(outcome.get("retries", 0)) + 1,
        "repairs_per_round": (
            len(repairs) / int(outcome.get("retries", 0))
            if int(outcome.get("retries", 0)) > 0
            else 0.0
        ),
        "repair_kinds": sorted({str(repair.get("kind")) for repair in repairs}),
        "vcs_recovery_repairs": sum(
            "vcs_recovery" in json.dumps(repair, sort_keys=True) for repair in repairs
        ),
        "executions": executions,
        "coverage_edges": coverage_edges,
        "target_stubbed": target_stubbed,
    }
    return not reasons, reasons, evidence


def execute_scenario_run(
    scenario: dict[str, Any],
    scenario_root: Path,
    work_dir: Path,
    log: Path,
    settings: dict[str, Any],
    *,
    control: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    command = scenario_command(
        scenario, scenario_root, work_dir, settings, control=control
    )
    timeout = int(settings.get("scenario_timeout", 300))
    try:
        # Fuzzed targets may create databases, logs, sockets, or arbitrary paths
        # relative to their process cwd. Keep those side effects inside the
        # disposable scenario export instead of leaking them into the GovFuzz
        # checkout that launched this validation runner.
        proc = run(command, cwd=scenario_root, timeout=timeout)
        log.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        run_path = work_dir / "auto" / "run.json"
        if not run_path.is_file():
            raise RuntimeError("GovFuzz did not write auto/run.json")
        run_json = json.loads(run_path.read_text(encoding="utf-8"))
        passed, reasons, evidence = assess_run(
            scenario, run_json, require_repair=not control
        )
        return {
            "command": command,
            "returncode": proc.returncode,
            "log": str(log),
            "evidence": evidence,
            "status": "passed" if passed else "failed",
            "failed_reasons": reasons,
            "elapsed_secs": time.monotonic() - started,
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "log": str(log),
            "status": "failed",
            "failed_reasons": ["scenario timed out"],
            "elapsed_secs": time.monotonic() - started,
        }
    except Exception as error:  # noqa: BLE001 - evidence runner reports failures.
        return {
            "command": command,
            "log": str(log),
            "status": "failed",
            "failed_reasons": [str(error)],
            "elapsed_secs": time.monotonic() - started,
        }


def run_scenario(
    scenario: dict[str, Any],
    settings: dict[str, Any],
    workspace: Path,
    materialized_root: Path | None,
    offline: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "id": scenario["id"],
        "repository_id": scenario["repository_id"],
        "language": scenario["language"],
        "mutation_class": scenario["mutation_class"],
        "severity": scenario.get("severity", "single_artifact"),
    }
    try:
        repo = repository_path(scenario, workspace, materialized_root, offline)
        scenario_root = workspace / "scenarios" / scenario["id"] / "source"
        preserve_vcs_history = bool(settings.get("preserve_vcs_history", False))
        export_clean_tree(
            repo,
            scenario_root,
            scenario["rev"],
            preserve_vcs_history,
        )
        result["vcs_history_available"] = preserve_vcs_history
        constraint = verify_external_constraint(scenario, scenario_root)
        if constraint is not None:
            result["external_constraint"] = constraint
        lock = (
            ADA_LOCK
            if scenario["language"] == "ada"
            else contextlib.nullcontext()
        )
        with lock:
            if settings.get("control_first", False):
                control_work = workspace / "scenarios" / scenario["id"] / "control-work"
                control_log = workspace / "scenarios" / scenario["id"] / "control.log"
                result["control"] = execute_scenario_run(
                    scenario,
                    scenario_root,
                    control_work,
                    control_log,
                    settings,
                    control=True,
                )
                if constraint is not None:
                    constraint["control_failure"] = verify_external_control_failure(
                        constraint, result["control"]
                    )

            result["mutation"] = apply_and_verify_mutation(scenario, scenario_root)
            work_dir = workspace / "scenarios" / scenario["id"] / "work"
            log = workspace / "scenarios" / scenario["id"] / "govfuzz.log"
            mutated = execute_scenario_run(
                scenario,
                scenario_root,
                work_dir,
                log,
                settings,
                control=False,
            )
            result.update(mutated)
    except Exception as error:  # noqa: BLE001 - evidence runner reports failures.
        result["status"] = "failed"
        result["failed_reasons"] = [str(error)]
    result["elapsed_secs"] = time.monotonic() - started
    return result


def nearest_rank(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def convergence_metrics(
    scenarios: list[dict[str, Any]], configured_cap: int
) -> dict[str, Any]:
    successful = [
        scenario["evidence"]
        for scenario in scenarios
        if scenario.get("status") == "passed" and "evidence" in scenario
    ]
    rounds = [int(evidence.get("repair_rounds", 0)) for evidence in successful]
    repair_actions = [int(evidence.get("repairs", 0)) for evidence in successful]
    cap_curve = []
    for cap in CAP_CANDIDATES:
        covered = sum(value <= cap for value in rounds)
        cap_curve.append(
            {
                "cap": cap,
                "covered": covered,
                "total_successes": len(rounds),
                "coverage": covered / len(rounds) if rounds else 0.0,
            }
        )
    cap_exhausted = sum(
        scenario.get("evidence", {}).get("outcome") == "failed_build"
        and int(scenario.get("evidence", {}).get("repair_rounds", -1)) >= configured_cap
        for scenario in scenarios
    )
    return {
        "configured_cap": configured_cap,
        "successful_samples": len(rounds),
        "repair_rounds": {
            "min": min(rounds) if rounds else None,
            "mean": sum(rounds) / len(rounds) if rounds else None,
            "p50": nearest_rank(rounds, 0.50),
            "p90": nearest_rank(rounds, 0.90),
            "p95": nearest_rank(rounds, 0.95),
            "p99": nearest_rank(rounds, 0.99),
            "max": max(rounds) if rounds else None,
        },
        "repair_actions": {
            "min": min(repair_actions) if repair_actions else None,
            "mean": (
                sum(repair_actions) / len(repair_actions) if repair_actions else None
            ),
            "p50": nearest_rank(repair_actions, 0.50),
            "p90": nearest_rank(repair_actions, 0.90),
            "p95": nearest_rank(repair_actions, 0.95),
            "p99": nearest_rank(repair_actions, 0.99),
            "max": max(repair_actions) if repair_actions else None,
        },
        "cap_coverage": cap_curve,
        "cap_exhausted_failures": cap_exhausted,
        "failed_build_before_cap": sum(
            scenario.get("evidence", {}).get("outcome") == "failed_build"
            and int(scenario.get("evidence", {}).get("repair_rounds", -1))
            < configured_cap
            for scenario in scenarios
        ),
    }


def outcome_breakdown(runs: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for run_result in runs:
        outcome = str(run_result.get("evidence", {}).get("outcome") or "no_result")
        counts[outcome] = counts.get(outcome, 0) + 1
    return dict(sorted(counts.items()))


def summarize(
    scenarios: list[dict[str, Any]], threshold: float, configured_cap: int
) -> dict[str, Any]:
    passed = sum(scenario["status"] == "passed" for scenario in scenarios)
    total = len(scenarios)
    rate = passed / total if total else 0.0
    controls = [
        scenario["control"]
        for scenario in scenarios
        if isinstance(scenario.get("control"), dict)
    ]
    controls_passed = sum(control.get("status") == "passed" for control in controls)
    confirmed_external = [
        scenario
        for scenario in scenarios
        if scenario.get("external_constraint", {}).get("verified") is True
        and scenario.get("external_constraint", {})
        .get("control_failure", {})
        .get("verified")
        is True
    ]
    confirmed_external_ids = {scenario["id"] for scenario in confirmed_external}
    in_scope = [
        scenario for scenario in scenarios if scenario["id"] not in confirmed_external_ids
    ]
    in_scope_controls_passed = sum(
        scenario.get("control", {}).get("status") == "passed"
        for scenario in in_scope
    )
    in_scope_recovery_passed = sum(
        scenario.get("status") == "passed" for scenario in in_scope
    )
    in_scope_control_rate = (
        in_scope_controls_passed / len(in_scope) if in_scope else 0.0
    )
    in_scope_recovery_rate = (
        in_scope_recovery_passed / len(in_scope) if in_scope else 0.0
    )
    eligible = [
        scenario
        for scenario in scenarios
        if scenario.get("control", {}).get("status") == "passed"
    ]
    eligible_passed = sum(scenario["status"] == "passed" for scenario in eligible)
    by_language: dict[str, dict[str, Any]] = {}
    by_mutation: dict[str, dict[str, Any]] = {}
    for scenario in scenarios:
        bucket = by_language.setdefault(
            scenario["language"], {"total": 0, "passed": 0, "success_rate": 0.0}
        )
        bucket["total"] += 1
        bucket["passed"] += scenario["status"] == "passed"
        mutation_bucket = by_mutation.setdefault(
            scenario["mutation_class"],
            {"total": 0, "passed": 0, "success_rate": 0.0},
        )
        mutation_bucket["total"] += 1
        mutation_bucket["passed"] += scenario["status"] == "passed"
    for bucket in by_language.values():
        bucket["success_rate"] = bucket["passed"] / bucket["total"]
    for bucket in by_mutation.values():
        bucket["success_rate"] = bucket["passed"] / bucket["total"]
    return {
        "repositories": len({scenario["repository_id"] for scenario in scenarios}),
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "success_rate": rate,
        "controls": {
            "attempted": len(controls),
            "passed": controls_passed,
            "success_rate": controls_passed / len(controls) if controls else None,
            "outcomes": outcome_breakdown(controls),
            "convergence": convergence_metrics(controls, configured_cap),
        },
        "external_constraints": {
            "confirmed": len(confirmed_external),
            "scenario_ids": sorted(confirmed_external_ids),
            "by_kind": dict(
                sorted(
                    {
                        kind: sum(
                            scenario.get("external_constraint", {}).get("kind") == kind
                            for scenario in confirmed_external
                        )
                        for kind in {
                            str(scenario.get("external_constraint", {}).get("kind"))
                            for scenario in confirmed_external
                        }
                    }.items()
                )
            ),
        },
        "in_scope": {
            "total": len(in_scope),
            "controls_passed": in_scope_controls_passed,
            "control_success_rate": in_scope_control_rate,
            "recovery_passed": in_scope_recovery_passed,
            "recovery_success_rate": in_scope_recovery_rate,
        },
        "eligible_recovery": {
            "total": len(eligible),
            "passed": eligible_passed,
            "success_rate": eligible_passed / len(eligible) if eligible else None,
        },
        "required_success_rate": threshold,
        "by_language": by_language,
        "by_mutation": by_mutation,
        "outcomes": outcome_breakdown(scenarios),
        "convergence": convergence_metrics(scenarios, configured_cap),
        "combined_convergence": convergence_metrics(controls + scenarios, configured_cap),
        "gate": (
            "pass"
            if in_scope
            and in_scope_control_rate >= threshold
            and in_scope_recovery_rate >= threshold
            else "fail"
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Legacy Broken-Project Fuzz Matrix",
        "",
        f"- Gate: **{summary['gate']}**",
        f"- Repositories: {summary['repositories']}",
        f"- Raw damaged-project recovery: {summary['passed']} / {summary['total']} "
        f"({summary['success_rate']:.1%})",
        f"- Required: {summary['required_success_rate']:.1%}",
        (
            f"- Raw unmodified controls: {summary['controls']['passed']} / "
            f"{summary['controls']['attempted']} "
            f"({summary['controls']['success_rate']:.1%})"
            if summary["controls"]["attempted"]
            else "- Raw unmodified controls: not run"
        ),
        (
            f"- Verified external/toolchain constraints: "
            f"{summary['external_constraints']['confirmed']}"
        ),
        (
            f"- In-scope clean discovery-to-fuzz: "
            f"{summary['in_scope']['controls_passed']} / "
            f"{summary['in_scope']['total']} "
            f"({summary['in_scope']['control_success_rate']:.1%})"
        ),
        (
            f"- In-scope damaged-project recovery: "
            f"{summary['in_scope']['recovery_passed']} / "
            f"{summary['in_scope']['total']} "
            f"({summary['in_scope']['recovery_success_rate']:.1%})"
        ),
        (
            "- Successful repair rounds: "
            f"p50={summary['convergence']['repair_rounds']['p50']}, "
            f"p95={summary['convergence']['repair_rounds']['p95']}, "
            f"p99={summary['convergence']['repair_rounds']['p99']}, "
            f"max={summary['convergence']['repair_rounds']['max']} "
            f"(configured cap {summary['convergence']['configured_cap']})"
        ),
        "",
        "| Scenario | Scope | Language | Mutation | Outcome | Rounds | Repairs | VCS | Executions | Edges |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    external_ids = set(summary["external_constraints"]["scenario_ids"])
    for scenario in result["scenarios"]:
        evidence = scenario.get("evidence", {})
        scope = "external" if scenario["id"] in external_ids else "in-scope"
        lines.append(
            "| {id} | {scope} | {language} | {mutation_class} | {status} | {repair_rounds} | {repairs} | {vcs_recovery_repairs} | "
            "{executions} | {coverage_edges} |".format(
                scope=scope,
                repair_rounds=evidence.get("repair_rounds", 0),
                repairs=evidence.get("repairs", 0),
                vcs_recovery_repairs=evidence.get("vcs_recovery_repairs", 0),
                executions=evidence.get("executions", 0),
                coverage_edges=evidence.get("coverage_edges", 0),
                **scenario,
            )
        )
        for reason in scenario.get("failed_reasons", []):
            lines.append(f"|  |  |  |  | Failure: {reason} |  |  |  |  |  |")
    if external_ids:
        lines.extend(["", "## Verified External Constraints", ""])
        for scenario in result["scenarios"]:
            if scenario["id"] not in external_ids:
                continue
            constraint = scenario["external_constraint"]
            lines.append(
                f"- `{scenario['id']}` ({constraint['kind']}): {constraint['proof']}"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    manifest = load_manifest(args.manifest)
    scenarios = selected_scenarios(manifest, set(args.scenario))
    threshold = float(manifest.get("settings", {}).get("minimum_success_rate", 0.9))

    if args.dry_run:
        dry = {
            "schema_version": SCHEMA_VERSION,
            "summary": {
                "total": len(scenarios),
                "repositories": len(
                    {scenario["repository_id"] for scenario in scenarios}
                ),
                "required_success_rate": threshold,
                "languages": sorted({scenario["language"] for scenario in scenarios}),
            },
            "scenarios": scenarios,
        }
        print(json.dumps(dry, indent=2))
        return 0

    args.workspace.mkdir(parents=True, exist_ok=True)
    settings = manifest.get("settings", {})
    configured_cap = int(settings.get("max_repair_rounds", 16))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.jobs)
    ) as executor:
        futures = [
            executor.submit(
                run_scenario,
                scenario,
                settings,
                args.workspace,
                args.materialized_root,
                args.offline,
            )
            for scenario in scenarios
        ]
        results = [future.result() for future in futures]
    results.sort(key=lambda item: item["id"])
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "manifest": str(args.manifest),
        "offline": args.offline,
        "summary": summarize(results, threshold, configured_cap),
        "scenarios": results,
    }
    rendered = json.dumps(envelope, indent=2)
    if args.json:
        print(rendered)
    else:
        print(render_markdown(envelope), end="")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(envelope), encoding="utf-8")
    return 0 if envelope["summary"]["gate"] == "pass" else 1


if __name__ == "__main__":
    sys_exit = main()
    raise SystemExit(sys_exit)
