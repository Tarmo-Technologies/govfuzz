# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("legacy-breakage-matrix.py")
SPEC = importlib.util.spec_from_file_location("legacy_breakage_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def scenario(status: str, rounds: int, repairs: int) -> dict:
    return {
        "id": f"case-{rounds}-{repairs}",
        "repository_id": f"repo-{rounds}-{repairs}",
        "language": "c",
        "mutation_class": "missing_direct_header",
        "status": status,
        "evidence": {
            "outcome": "built_and_fuzzed" if status == "passed" else "failed_build",
            "repair_rounds": rounds,
            "repairs": repairs,
        },
    }


class ConvergenceMetricsTests(unittest.TestCase):
    def test_nearest_rank_and_cap_curve_measure_rounds_not_repair_actions(self) -> None:
        cases = [
            scenario("passed", 1, 2),
            scenario("passed", 2, 24),
            scenario("passed", 6, 17),
            scenario("failed", 48, 90),
        ]
        metrics = matrix.convergence_metrics(cases, 48)

        self.assertEqual(metrics["successful_samples"], 3)
        self.assertEqual(metrics["repair_rounds"]["p50"], 2)
        self.assertEqual(metrics["repair_rounds"]["p95"], 6)
        self.assertEqual(metrics["repair_actions"]["max"], 24)
        self.assertEqual(metrics["cap_exhausted_failures"], 1)
        by_cap = {item["cap"]: item for item in metrics["cap_coverage"]}
        self.assertEqual(by_cap[2]["covered"], 2)
        self.assertEqual(by_cap[6]["coverage"], 1.0)
        self.assertEqual(metrics["failed_build_before_cap"], 0)

    def test_outcome_breakdown_includes_runs_without_evidence(self) -> None:
        runs = [
            {"evidence": {"outcome": "built_and_fuzzed"}},
            {"evidence": {"outcome": "failed_build"}},
            {"failed_reasons": ["timed out"]},
        ]

        self.assertEqual(
            matrix.outcome_breakdown(runs),
            {"built_and_fuzzed": 1, "failed_build": 1, "no_result": 1},
        )

    def test_control_can_build_without_a_mutation_repair(self) -> None:
        selected = {
            "target_file": "parse.c",
            "target_name": "parse",
            "min_repairs": 1,
        }
        run = {
            "summary": {
                "built_and_fuzzed": 1,
                "fuzzed_stub_only": 0,
            },
            "targets": [
                {
                    "source": "/src/parse.c",
                    "name": "parse",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "retries": 0,
                        "repairs": [],
                        "passes": [{"executions": 1, "coverage_edges": 3}],
                    },
                }
            ],
        }

        control_passed, _, evidence = matrix.assess_run(
            selected, run, require_repair=False
        )
        mutation_passed, reasons, _ = matrix.assess_run(
            selected, run, require_repair=True
        )
        self.assertTrue(control_passed)
        self.assertEqual(evidence["build_attempts"], 1)
        self.assertFalse(mutation_passed)
        self.assertIn("mutation triggered no recorded build repair", reasons)

    def test_fuzz_success_requires_coverage(self) -> None:
        selected = {"target_file": "parse.c", "target_name": "parse"}
        run = {
            "summary": {"built_and_fuzzed": 1, "fuzzed_stub_only": 0},
            "targets": [
                {
                    "source": "/src/parse.c",
                    "name": "parse",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "retries": 0,
                        "repairs": [],
                        "passes": [{"executions": 4, "coverage_edges": 0}],
                    },
                }
            ],
        }

        passed, reasons, evidence = matrix.assess_run(
            selected, run, require_repair=False
        )

        self.assertFalse(passed)
        self.assertEqual(evidence["executions"], 4)
        self.assertIn("fuzz pass recorded no coverage edges", reasons)

    def test_file_mutation_deletes_dependency_and_preserves_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.c"
            dependency = root / "dependency.h"
            target.write_text('#include "dependency.h"\nint target(void) {}\n')
            dependency.write_text("int dependency(void);\n")
            scenario_data = {
                "id": "file-removal",
                "target_file": "target.c",
                "probe_contains": '#include "dependency.h"',
                "remove_files": ["dependency.h"],
            }

            evidence = matrix.apply_and_verify_mutation(scenario_data, root)

            self.assertTrue(target.is_file())
            self.assertFalse(dependency.exists())
            self.assertEqual(evidence["removed"], ["dependency.h"])

    def test_ada_removed_symbol_proof_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.adb"
            dependency = root / "dependency.adb"
            target.write_text("with Dependency;\nprocedure Target is begin null; end;\n")
            dependency.write_text("package body dependency is\nend dependency;\n")
            scenario_data = {
                "id": "ada-body-removal",
                "language": "ada",
                "target_file": "target.adb",
                "probe_contains": "with Dependency;",
                "removed_contains": "Dependency",
                "remove_files": ["dependency.adb"],
            }

            evidence = matrix.apply_and_verify_mutation(scenario_data, root)

            self.assertEqual(evidence["removed_contains"], "Dependency")
            self.assertFalse(dependency.exists())

    def test_scenario_executes_from_disposable_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            work = root / "work"
            source.mkdir()
            (work / "auto").mkdir(parents=True)
            (work / "auto" / "run.json").write_text(
                '{"summary":{"built_and_fuzzed":1,"fuzzed_stub_only":0},'
                '"targets":[{"source":"/src/parse.c","name":"parse",'
                '"outcome":{"outcome":"built_and_fuzzed","retries":0,'
                '"repairs":[],"passes":[{"executions":1,"coverage_edges":3}]}}]}'
            )
            selected = {"target_file": "parse.c", "target_name": "parse"}
            completed = subprocess.CompletedProcess(["govfuzz"], 0, "", "")

            with mock.patch.object(matrix, "scenario_command", return_value=["govfuzz"]), mock.patch.object(
                matrix, "run", return_value=completed
            ) as run_mock:
                result = matrix.execute_scenario_run(
                    selected,
                    source,
                    work,
                    root / "run.log",
                    {},
                    control=True,
                )

            self.assertEqual(result["status"], "passed")
            self.assertEqual(run_mock.call_args.kwargs["cwd"], source)

    def test_external_constraint_requires_static_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README").write_text("requires arm-none-eabi toolchain\n")
            selected = {
                "id": "cross-only",
                "external_constraint": {
                    "kind": "cross_toolchain",
                    "proof": "pinned project is ARM-only",
                    "probes": [
                        {
                            "path": "README",
                            "contains": "arm-none-eabi toolchain",
                        }
                    ],
                    "absent_paths": ["host-runtime.gpr"],
                    "control_failure_contains": ["matching GNAT cross toolchain"],
                },
            }

            evidence = matrix.verify_external_constraint(selected, root)

            self.assertTrue(evidence["verified"])
            self.assertEqual(evidence["kind"], "cross_toolchain")
            self.assertEqual(evidence["absent_paths"], ["host-runtime.gpr"])

    def test_external_constraint_requires_matching_clean_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "control.log"
            log.write_text("matching GNAT cross toolchain is unavailable\n")
            constraint = {
                "control_failure_contains": ["matching GNAT cross toolchain"]
            }

            matched = matrix.verify_external_control_failure(
                constraint, {"status": "failed", "log": str(log)}
            )
            unrelated = matrix.verify_external_control_failure(
                {"control_failure_contains": ["generated binding is missing"]},
                {"status": "failed", "log": str(log)},
            )

            self.assertTrue(matched["verified"])
            self.assertFalse(unrelated["verified"])

    def test_gate_uses_all_non_external_projects_for_both_rates(self) -> None:
        passed = scenario("passed", 1, 1)
        passed["control"] = {"status": "passed", "evidence": {}}
        clean_failure = scenario("failed", 0, 0)
        clean_failure["id"] = "unclassified-clean-failure"
        clean_failure["control"] = {"status": "failed", "evidence": {}}
        external = scenario("failed", 0, 0)
        external["id"] = "proven-cross-only"
        external["control"] = {"status": "failed", "evidence": {}}
        external["external_constraint"] = {
            "kind": "cross_toolchain",
            "proof": "verified fixture",
            "verified": True,
            "control_failure": {"verified": True},
        }

        summary = matrix.summarize([passed, clean_failure, external], 0.9, 16)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["external_constraints"]["confirmed"], 1)
        self.assertEqual(summary["in_scope"]["total"], 2)
        self.assertEqual(summary["in_scope"]["controls_passed"], 1)
        self.assertEqual(summary["in_scope"]["recovery_passed"], 1)
        self.assertEqual(summary["gate"], "fail")


if __name__ == "__main__":
    unittest.main()
