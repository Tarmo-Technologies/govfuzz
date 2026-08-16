#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the broad auto audit with one independent expert driver per lane."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


SUPPORTED = {
    "ada", "c", "cpp", "rust", "java", "python", "perl", "go", "cobol",
    "fortran", "csharp", "js", "ts", "ruby", "lua", "php",
}


def read_experts(root: Path) -> list[dict[str, str]]:
    with (root / "expert-projects.tsv").open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    languages = {row["language"] for row in rows}
    if len(rows) != 16 or languages != SUPPORTED:
        raise SystemExit(
            f"expert matrix must contain exactly one row for all 16 lanes; got {len(rows)} {sorted(languages)}"
        )
    return rows


def read_auto_rows(output: Path) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for path in sorted((output / "rows").glob("*.json")):
        try:
            row = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(row, dict) and isinstance(row.get("repo"), str):
            rows[str(row["repo"]).lower()] = row
    return rows


def surface_leaf(value: str) -> str:
    value = re.sub(r"\([^)]*\)$", "", value.strip())
    parts = [part for part in re.split(r"::|#|[.\\]", value) if part]
    return re.sub(r"[^a-z0-9]", "", (parts[-1] if parts else value).lower())


def surface_match(expert: str, actual: str) -> bool:
    expert_leaf = surface_leaf(expert)
    actual_leaf = surface_leaf(actual)
    # Qualification and signature spelling differ between manifests and result
    # rows, but the callable leaf must be identical. Suffix matching over-credits
    # unrelated APIs (`parse` versus `sparse`, `load` versus `download`).
    return bool(expert_leaf and actual_leaf) and expert_leaf == actual_leaf


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=Path("/tmp/govfuzz-harness-parity-200")
    )
    parser.add_argument(
        "--destination",
        type=Path,
        help="report path (default: OUTPUT/expert-parity-report.md)",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = args.output.resolve()
    destination = args.destination or output / "expert-parity-report.md"
    experts = read_experts(root)
    auto_rows = read_auto_rows(output)

    compared: list[dict[str, object]] = []
    for expert in experts:
        harness = root / expert["expert_harness"]
        if not harness.is_file():
            raise SystemExit(f"missing expert harness: {harness}")
        content = harness.read_bytes()
        auto = auto_rows.get(expert["repo"].lower(), {})
        actual_commit = str(auto.get("commit", ""))
        if actual_commit and actual_commit != expert["commit"]:
            raise SystemExit(
                f"commit mismatch for {expert['repo']}: expert={expert['commit']} auto={actual_commit}"
            )
        actual = str(auto.get("target", "-"))
        compared.append(
            {
                **expert,
                "auto_surface_actual": actual,
                "same_surface": surface_match(expert["expert_surface"], actual),
                "entry_proven": auto.get("target_entry") is True,
                "body_covered": auto.get("target_body_reached") is True,
                "auto_status": str(auto.get("status", "not audited")),
                "dynamic_edges": auto.get("dynamic_coverage_edges"),
                "expert_lines": content.count(b"\n") + (not content.endswith(b"\n")),
                "expert_sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    present = sum(row["auto_status"] != "not audited" for row in compared)
    entered = sum(bool(row["entry_proven"]) for row in compared)
    covered = sum(bool(row["body_covered"]) for row in compared)
    same = sum(bool(row["same_surface"]) for row in compared)
    total_lines = sum(int(row["expert_lines"]) for row in compared)
    lines = [
        "# Cross-language expert-harness comparison",
        "",
        f"- Supported-language expert drivers: {len(compared)}/16",
        f"- Independent expert harness code: {total_lines} lines",
        f"- Expert projects present in the broad audit: {present}/16",
        f"- Auto-selected target entry proven: {entered}/16",
        f"- Auto-selected target body dynamically covered: {covered}/16",
        f"- Auto selected the expert entrypoint: {same}/16",
        "",
        "The target-entry and body columns are dynamic measurements from the durable",
        "audit rows. Target parity compares independently selected entrypoints. It does",
        "not claim full harness parity: the last column records the deliberate setup in",
        "the expert reference. A matching target shows selection parity, while the audit",
        "findings determine whether auto-harnessing also reproduced that lever.",
        "",
        "| Lane | Project | Expert surface | Auto surface | Entry | Body | Same target | Expert reference lever |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for row in compared:
        lines.append(
            "| {language} | {repo} | `{expert_surface}` | `{auto_surface_actual}` | "
            "{entry} | {body} | {same} | {expert_lever} |".format(
                **row,
                entry="yes" if row["entry_proven"] else "no",
                body="yes" if row["body_covered"] else "no",
                same="yes" if row["same_surface"] else "no",
            )
        )
    lines.extend(
        [
            "",
            "Every expert file is content-addressed while generating this report;",
            "missing files, duplicate lanes, or incomplete language coverage are fatal.",
            "The SHA-256 inventory is written to `expert-harnesses.tsv` beside the report.",
        ]
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n")

    fields = [
        "language", "repo", "commit", "expert_harness", "expert_surface",
        "auto_surface_actual", "same_surface", "entry_proven", "body_covered",
        "auto_status", "dynamic_edges", "expert_lines", "expert_sha256", "expert_lever",
    ]
    with (destination.parent / "expert-harnesses.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(compared)
    print(destination)


if __name__ == "__main__":
    main()
