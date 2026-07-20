# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("synthesize-legacy-breakage-manifest.py")
SPEC = importlib.util.spec_from_file_location("synthesize_legacy_breakage_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
synthesis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(synthesis)


class AutoTargetParsingTests(unittest.TestCase):
    def test_parses_only_supported_fuzz_eligible_rows(self) -> None:
        output = """\
# govfuzz auto: 3 ranked target(s) under /src (highest score first; no build)
rank   score  lang  reachability        target                            file:line
   1      65  C++   unproven            parser::read(string, size_t)       src/parser.cc:272
   2      40  Ada   -                   parse_next                        ada/parse.adb:133
   3      30  Rust  -                   decode                            src/lib.rs:20
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = synthesis.parse_auto_targets(output, root)

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["target"]["name"], "parser::read(string, size_t)")
        self.assertEqual(targets[0]["target"]["language"], "cpp")
        self.assertEqual(targets[0]["target"]["line"], 272)
        self.assertEqual(targets[1]["target"]["language"], "ada")

    def test_scenario_language_comes_from_selected_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "target.c"
            header = root / "dependency.h"
            source.write_text('#include "dependency.h"\nint target(void) { return 0; }\n')
            header.write_text("int dependency(void);\n")
            repository = {
                "id": "mixed",
                "url": "https://example.invalid/mixed.git",
                "rev": "0" * 40,
                "materialized_path": "mixed",
                "language": "unknown",
            }
            targets = [
                {
                    "file": str(source),
                    "target": {
                        "language": "c",
                        "line": 2,
                        "name": "target",
                        "score": 1,
                    },
                }
            ]

            scenario = synthesis.c_header_scenario(repository, root, targets)

        self.assertIsNotNone(scenario)
        self.assertEqual(scenario["language"], "c")

    def test_dependency_implementation_mutation_preserves_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.c"
            header = root / "dependency.h"
            implementation = root / "dependency.c"
            target.write_text(
                '/* Copyright (C) Example { */\n'
                '#include "dependency.h"\nint target(void) { return dependency(1); }\n'
            )
            header.write_text(
                "/* Copyright (C) Example { */\nint dependency(int value);\n"
            )
            implementation.write_text(
                '/* Copyright (C) Example { */\n'
                '#include "dependency.h"\nint dependency(int value) { return value; }\n'
            )
            repository = {
                "id": "linked",
                "url": "https://example.invalid/linked.git",
                "rev": "0" * 40,
                "materialized_path": "linked",
                "language": "c",
            }
            targets = [
                {
                    "file": str(target),
                    "target": {
                        "language": "c",
                        "line": 2,
                        "name": "target",
                        "score": 1,
                    },
                }
            ]

            scenario = synthesis.dependency_implementation_scenario(
                repository, root, targets
            )

        self.assertIsNotNone(scenario)
        self.assertEqual(scenario["remove_files"], ["dependency.c"])
        self.assertEqual(scenario["removed_contains"], "dependency")
        self.assertEqual(
            scenario["mutation_class"], "missing_dependency_implementation"
        )

    def test_dependency_implementation_rejects_platform_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unix").mkdir()
            (root / "windows").mkdir()
            target = root / "target.c"
            header = root / "dependency.h"
            target.write_text(
                '#include "dependency.h"\nint target(void) { return dependency(1); }\n'
            )
            header.write_text("int dependency(int value);\n")
            for platform in ("unix", "windows"):
                (root / platform / "dependency.c").write_text(
                    "int dependency(int value) { return value; }\n"
                )
            repository = {
                "id": "ambiguous",
                "url": "https://example.invalid/ambiguous.git",
                "rev": "0" * 40,
                "materialized_path": "ambiguous",
                "language": "c",
            }
            targets = [
                {
                    "file": str(target),
                    "target": {
                        "language": "c",
                        "line": 2,
                        "name": "target",
                        "score": 1,
                    },
                }
            ]

            scenario = synthesis.dependency_implementation_scenario(
                repository, root, targets
            )

        self.assertIsNone(scenario)


if __name__ == "__main__":
    unittest.main()
