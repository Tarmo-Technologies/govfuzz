#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize truthful successes and residual gap classes from an audit output."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


SUCCESS = "entered_and_covered"


def read_rows(output: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted((output / "rows").glob("*.json")):
        try:
            value = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def gap_class(row: dict[str, object]) -> str:
    if row.get("target_entry") is True and row.get("target_body_reached") is True:
        return SUCCESS
    status = str(row.get("status", "unknown")).lower()
    diagnostic = str(row.get("diagnostic", "")).lower()
    text = f"{status} {diagnostic}"
    if status in {"source_error"}:
        return "source_acquisition"
    if bool(row.get("timed_out")) or status == "timeout":
        return "timeout"
    if "not_entered" in status or (
        row.get("launcher_fuzzed") is True and row.get("target_entry") is False
    ):
        return "target_entry_miss"
    if "unsupported_params" in status or any(
        term in text
        for term in [
            "unsupported parameter",
            "unsupported return",
            "not fuzzable",
            "cannot synthesize",
            "not nameable",
        ]
    ):
        return "unsupported_signature"
    if any(
        term in text
        for term in [
            "default constructor",
            "parameterless constructor",
            "receiver",
            "instantiate",
            "instance method",
        ]
    ):
        return "receiver_or_object_state"
    if any(
        term in text
        for term in [
            "no module named",
            "cannot find module",
            "class not found",
            "could not load file or assembly",
            "package not found",
            "autoload",
            "missing dependency",
            "cannot load such file",
        ]
    ):
        return "missing_project_dependency"
    if any(
        term in text
        for term in [
            "requires go ",
            "unsupported target framework",
            "sdk does not support targeting",
            "language version",
            "preview feature",
            "edition 2024",
            "toolchain",
        ]
    ):
        return "toolchain_or_language_version"
    if "unrecoverable_link" in status or any(
        term in text
        for term in [
            "undefined reference",
            "unresolved external",
            "symbol not found",
            "cannot find -l",
            "duplicate symbol",
        ]
    ):
        return "link_or_source_closure"
    if any(
        term in text
        for term in [
            "__dev__",
            "undefined global",
            "host global",
            "window is not defined",
            "document is not defined",
            "vim is nil",
            "android.",
        ]
    ):
        return "framework_host_environment"
    if "failed_build" in status or "compile" in text or "build" in text:
        return "compile_or_build_context"
    if status in {"no_result", "unsupported", "not_attempted"}:
        return "discovery_or_no_attempt"
    if row.get("target_entry") is True:
        return "entered_without_dynamic_body_coverage"
    return "other"


def write_gap_rows(rows: list[dict[str, object]], destination: Path) -> None:
    fields = [
        "language",
        "repo",
        "prior_status",
        "gap_class",
        "status",
        "launcher_fuzzed",
        "target_entry",
        "target_body_reached",
        "target",
        "source_path",
        "diagnostic",
    ]
    with destination.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (str(item["language"]), str(item["repo"]))):
            enriched = dict(row)
            enriched["gap_class"] = gap_class(row)
            writer.writerow(enriched)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=Path("/tmp/govfuzz-harness-parity-200")
    )
    args = parser.parse_args()
    output = args.output.resolve()
    rows = read_rows(output)
    if not rows:
        raise SystemExit(f"no durable rows found under {output / 'rows'}")
    write_gap_rows(rows, output / "gaps.tsv")

    by_language: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_language[str(row.get("language", "unknown"))].append(row)
    classes = Counter(gap_class(row) for row in rows)
    previous_regressions = [
        row
        for row in rows
        if row.get("prior_status") == "fuzzed" and gap_class(row) != SUCCESS
    ]
    previous_recoveries = [
        row
        for row in rows
        if row.get("prior_status") == "gap" and gap_class(row) == SUCCESS
    ]
    false_successes = [
        row
        for row in rows
        if row.get("launcher_fuzzed") is True and row.get("target_entry") is not True
    ]

    lines = [
        "# 200-project expert-parity gap analysis",
        "",
        f"- Durable projects analyzed: {len(rows)}",
        f"- Selected targets entered and dynamically covered: {classes[SUCCESS]}",
        f"- Launcher-only successes rejected by entry proof: {len(false_successes)}",
        f"- Previously reached projects now exposing a gap: {len(previous_regressions)}",
        f"- Previously missed projects now entered and covered: {len(previous_recoveries)}",
        "",
        "## Evidence by language",
        "",
        "| Language | Projects | Entered + body covered | Entry misses | Other gaps |",
        "|---|---:|---:|---:|---:|",
    ]
    for language, language_rows in sorted(by_language.items()):
        counts = Counter(gap_class(row) for row in language_rows)
        lines.append(
            f"| {language} | {len(language_rows)} | {counts[SUCCESS]} | "
            f"{counts['target_entry_miss']} | "
            f"{len(language_rows) - counts[SUCCESS] - counts['target_entry_miss']} |"
        )
    lines.extend(
        [
            "",
            "## Residual gap classes",
            "",
            "| Gap class | Projects |",
            "|---|---:|",
        ]
    )
    for name, count in classes.most_common():
        lines.append(f"| {name} | {count} |")
    lines.extend(
        [
            "",
            "Classifications are deterministic triage labels derived from the durable",
            "status and diagnostic fields. They prioritize investigation; they do not",
            "replace source review or the nested expert-harness measurements.",
        ]
    )
    (output / "gap-report.md").write_text("\n".join(lines) + "\n")
    print(output / "gap-report.md")


if __name__ == "__main__":
    main()
