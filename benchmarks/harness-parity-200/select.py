#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select a balanced, pinned 200-project parity audit from the 500-project sweep."""

from __future__ import annotations

import csv
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
SWEEP = HERE.parent / "campaign-2026-07-25"
RESULTS = SWEEP / "results-0727"
CORE_13 = {"c", "cpp", "rust", "java", "python", "go", "js", "ts"}
LANGUAGES = [
    "ada",
    "c",
    "cpp",
    "rust",
    "java",
    "python",
    "perl",
    "go",
    "cobol",
    "fortran",
    "csharp",
    "js",
    "ts",
    "ruby",
    "lua",
    "php",
]


def load_corpus() -> list[dict[str, str]]:
    with (SWEEP / "corpus.tsv").open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    for row in rows:
        row["language"] = row.pop("# lane")
    return rows


def load_results() -> dict[tuple[str, str], dict]:
    results = {}
    for path in sorted(RESULTS.glob("*.json")):
        try:
            row = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        results[(row.get("lane", ""), row.get("repo", ""))] = row
    return results


def was_fuzzed(result: dict) -> bool:
    summary = result.get("surfaces", {}).get("auto", {}).get("summary", {})
    return int(summary.get("built_and_fuzzed", 0) or 0) > 0


def select() -> list[dict[str, str]]:
    corpus = load_corpus()
    results = load_results()
    selected = []
    for language in LANGUAGES:
        quota = 13 if language in CORE_13 else 12
        success_quota = quota - 4
        candidates = []
        for rank, project in enumerate(
            row for row in corpus if row["language"] == language
        ):
            result = results.get((language, project["repo"]))
            if not result or not result.get("sha"):
                continue
            summary = result.get("surfaces", {}).get("auto", {}).get("summary", {})
            candidates.append(
                {
                    "language": language,
                    "repo": project["repo"],
                    "url": project["clone_url"],
                    "commit": result["sha"],
                    "stars": project["stars"],
                    "size_kb": project["size_kb"],
                    "prior_status": "fuzzed" if was_fuzzed(result) else "gap",
                    "prior_fuzzed_targets": str(summary.get("built_and_fuzzed", 0) or 0),
                    "_rank": rank,
                }
            )

        # Preserve the star-ranked sampling frame within two explicit strata:
        # projects where the prior binary reached code and projects where it did
        # not. Prefer repositories below 50 MiB inside each stratum so a 200-row
        # audit remains repeatable on one workstation, but never replace a
        # missing outcome class with a hand-picked easy project.
        def order(row: dict[str, str]) -> tuple[bool, int]:
            return (int(row["size_kb"]) > 50_000, int(row["_rank"]))

        successes = sorted(
            (row for row in candidates if row["prior_status"] == "fuzzed"), key=order
        )
        gaps = sorted(
            (row for row in candidates if row["prior_status"] == "gap"), key=order
        )
        picked = successes[:success_quota] + gaps[: quota - success_quota]
        if len(picked) < quota:
            picked_repos = {row["repo"] for row in picked}
            remaining = sorted(
                (row for row in candidates if row["repo"] not in picked_repos),
                key=order,
            )
            picked.extend(remaining[: quota - len(picked)])
        if len(picked) != quota:
            raise RuntimeError(
                f"{language}: wanted {quota} projects but selected {len(picked)}"
            )
        picked.sort(key=lambda row: int(row["_rank"]))
        for row in picked:
            row.pop("_rank")
        selected.extend(picked)

    if len(selected) != 200:
        raise RuntimeError(f"selection must contain exactly 200 projects, got {len(selected)}")
    return selected


def main() -> None:
    rows = select()
    fields = [
        "language",
        "repo",
        "url",
        "commit",
        "stars",
        "size_kb",
        "prior_status",
        "prior_fuzzed_targets",
    ]
    with (HERE / "projects.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
    counts = {language: 0 for language in LANGUAGES}
    for row in rows:
        counts[row["language"]] += 1
    print(f"wrote {len(rows)} pinned projects to {HERE / 'projects.tsv'}")
    print(" ".join(f"{language}={count}" for language, count in counts.items()))


if __name__ == "__main__":
    main()
