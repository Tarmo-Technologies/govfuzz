# SPDX-License-Identifier: Apache-2.0

import io
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from govfuzz_gnatstudio_core import (
    GovfuzzConfig,
    action_name,
    build_minimize_args,
    build_replay_args,
    diagnostic_records,
    encode_frame,
    finding_action_specs,
    read_frame,
    resolve_reproducer_path,
)


FINDING = {
    "id": "F-0001-alpha",
    "severity": "high",
    "classification": "swallowed_predefined",
    "signature": "aabbccdd",
    "exception": {
        "handler": {
            "file": "src/pkg.adb",
            "line": 5,
            "col": 7,
        },
        "last_breadcrumb": {
            "file": "src/pkg.adb",
            "line": 3,
            "col": 2,
        },
    },
    "generated_repro_ada": "F-0001-alpha/repro.adb",
    "replay": {
        "command": "govfuzz replay --finding F-0001-alpha",
    },
}


class CoreTests(unittest.TestCase):
    def test_frame_round_trip(self):
        frame = encode_frame({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

        self.assertTrue(frame.startswith(b"Content-Length: "))
        self.assertEqual(
            read_frame(io.BytesIO(frame)),
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        )

    def test_diagnostic_records_map_finding_to_gnatstudio_message(self):
        records = diagnostic_records([FINDING], "/work/project")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].finding_id, "F-0001-alpha")
        self.assertEqual(records[0].file, os.path.normpath("/work/project/src/pkg.adb"))
        self.assertEqual(records[0].line, 5)
        self.assertEqual(records[0].column, 7)
        self.assertEqual(records[0].importance, "HIGH")
        self.assertIn("swallowed_predefined", records[0].text)
        self.assertIn("aabbccdd", records[0].text)

    def test_diagnostic_records_prefer_actionability_fix_location(self):
        finding = {
            **FINDING,
            "actionability": {
                "verdict": "real_reachable",
                "confidence": "high",
                "fix_location": {
                    "path": "src/fix.adb",
                    "line": 42,
                    "col": 4,
                    "reason": "explicit_raise_site",
                },
            },
        }

        records = diagnostic_records([finding], "/work/project")

        self.assertEqual(records[0].file, os.path.normpath("/work/project/src/fix.adb"))
        self.assertEqual(records[0].line, 42)
        self.assertEqual(records[0].column, 4)
        self.assertIn("real_reachable", records[0].text)
        self.assertIn("high", records[0].text)

    def test_diagnostic_records_fall_back_to_last_breadcrumb(self):
        finding = {
            **FINDING,
            "exception": {
                "last_breadcrumb": {
                    "file": "src/pkg.adb",
                    "line": 3,
                    "col": 2,
                },
            },
        }

        records = diagnostic_records([finding], "/work/project")

        self.assertEqual(records[0].line, 3)
        self.assertEqual(records[0].column, 2)

    def test_build_replay_args_use_harness_override_when_configured(self):
        config = GovfuzzConfig(
            cli_path="govfuzz",
            daemon_path="govfuzz-daemon",
            findings_dir="findings",
            harness_path="build/H 1/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_replay_args(FINDING, config),
            [
                "govfuzz",
                "replay",
                "--finding",
                os.path.normpath("/work/project/findings/F-0001-alpha"),
                "--harness",
                "build/H 1/main",
            ],
        )

    def test_build_replay_args_use_configured_findings_dir_with_harness_override(self):
        config = GovfuzzConfig(
            cli_path="govfuzz",
            daemon_path="govfuzz-daemon",
            findings_dir="custom/findings",
            harness_path="build/H 1/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_replay_args(FINDING, config),
            [
                "govfuzz",
                "replay",
                "--finding",
                os.path.normpath("/work/project/custom/findings/F-0001-alpha"),
                "--harness",
                "build/H 1/main",
            ],
        )

    def test_build_replay_args_use_finding_command_without_harness_override(self):
        config = GovfuzzConfig(workspace_root="/work/project")

        self.assertEqual(
            build_replay_args(FINDING, config),
            ["govfuzz", "replay", "--finding", "F-0001-alpha"],
        )

    def test_build_minimize_args_include_strategy_and_harness(self):
        config = GovfuzzConfig(
            harness_path="build/main",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_minimize_args(FINDING, config),
            [
                "govfuzz",
                "minimize",
                "--finding",
                os.path.normpath("/work/project/findings/F-0001-alpha"),
                "--harness",
                "build/main",
                "--strategy",
                "typed",
            ],
        )

    def test_build_minimize_args_use_configured_findings_dir(self):
        config = GovfuzzConfig(
            findings_dir="/tmp/govfuzz-findings",
            harness_path="",
            minimize_strategy="typed",
            workspace_root="/work/project",
        )

        self.assertEqual(
            build_minimize_args(FINDING, config),
            [
                "govfuzz",
                "minimize",
                "--finding",
                os.path.normpath("/tmp/govfuzz-findings/F-0001-alpha"),
                "--strategy",
                "typed",
            ],
        )

    def test_resolve_reproducer_path_uses_findings_root(self):
        config = GovfuzzConfig(
            findings_dir="findings",
            workspace_root="/work/project",
        )

        self.assertEqual(
            resolve_reproducer_path(FINDING, config),
            os.path.normpath("/work/project/findings/F-0001-alpha/repro.adb"),
        )

    def test_action_name_is_deterministic_and_safe(self):
        self.assertEqual(
            action_name("replay", "F/0001 alpha"),
            "GovFuzz replay F_0001_alpha",
        )

    def test_finding_action_specs_match_available_workflows(self):
        self.assertEqual(
            [spec.action for spec in finding_action_specs(FINDING)],
            ["replay", "minimize", "open-repro"],
        )

        finding_without_repro = {
            key: value for key, value in FINDING.items() if key != "generated_repro_ada"
        }
        self.assertEqual(
            [spec.action for spec in finding_action_specs(finding_without_repro)],
            ["replay", "minimize"],
        )


if __name__ == "__main__":
    unittest.main()
