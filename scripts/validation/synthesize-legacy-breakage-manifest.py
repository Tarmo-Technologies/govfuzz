#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = REPO_ROOT / "tests/fixtures/legacy_breakage_validation/catalog.toml"
DEFAULT_OUTPUT = (
    REPO_ROOT / "tests/fixtures/legacy_breakage_validation/expanded-manifest.toml"
)
EXCLUDED_PARTS = {
    "bench",
    "benchmark",
    "benchmarks",
    "ct",
    "doc",
    "docs",
    "example",
    "examples",
    "fuzz",
    "fuzzing",
    "test",
    "tests",
    "testsuite",
    "tool",
    "tools",
}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
IMPLEMENTATION_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
SOURCE_SUFFIXES = HEADER_SUFFIXES | {".c", ".cc", ".cpp", ".cxx", ".ads", ".adb"}
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
C_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
ADA_WITH_RE = re.compile(
    r"(?im)^\s*(?:limited\s+|private\s+)?with\s+([a-z][a-z0-9_.]*)\s*;"
)
AUTO_TARGET_RE = re.compile(
    r"^\s*\d+\s+(?P<score>-?\d+)\s+(?P<language>\S+)\s+\S+\s+"
    r"(?P<name>.*?)\s{2,}(?P<file>.+):(?P<line>\d+)\s*$"
)
AUTO_LANGUAGES = {"Ada": "ada", "C": "c", "C++": "cpp"}
NON_CALL_NAMES = {
    "alignas",
    "alignof",
    "defined",
    "for",
    "if",
    "return",
    "sizeof",
    "static_assert",
    "switch",
    "while",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Select a ranked target and a real directly referenced dependency in "
            "each pinned repository, then emit destructive matrix scenarios."
        )
    )
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--materialized-root", type=Path, required=True)
    parser.add_argument(
        "--discover-catalog",
        action="store_true",
        help="Derive repository pins from all two-level Git checkouts under the root.",
    )
    parser.add_argument(
        "--write-catalog",
        type=Path,
        help="Write the discovered pinned repository catalog as TOML.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--top", type=int, default=200)
    return parser.parse_args()


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def govfuzz_binary() -> Path:
    binary = REPO_ROOT / "target/release/govfuzz"
    if not binary.is_file():
        raise RuntimeError("target/release/govfuzz is missing; build it first")
    return binary


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def strip_c_comments(source: str) -> str:
    return C_COMMENT_RE.sub("", source)


def source_index(repo: Path) -> dict[str, list[Path]]:
    by_name: dict[str, list[Path]] = defaultdict(list)
    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(repo)
        if ".git" in relative.parts or "build" in relative.parts:
            continue
        by_name[path.name.lower()].append(path)
    return by_name


def resolve_include(
    repo: Path, source: Path, include: str, by_name: dict[str, list[Path]]
) -> Path | None:
    direct = [
        source.parent / include,
        repo / include,
        repo / "include" / include,
        repo / "src" / include,
        repo / "lib" / include,
    ]
    for candidate in direct:
        if candidate.is_file() and candidate.resolve().is_relative_to(repo.resolve()):
            return candidate.resolve()
    matches = by_name.get(Path(include).name.lower(), [])
    suffix_matches = [
        path
        for path in matches
        if path.as_posix().lower().endswith(include.replace("\\", "/").lower())
    ]
    candidates = suffix_matches or matches
    return candidates[0].resolve() if len(candidates) == 1 else None


def excluded_target(relative: Path) -> bool:
    return any(part.lower() in EXCLUDED_PARTS for part in relative.parts[:-1])


def discover_targets(repo: Path, top: int) -> tuple[list[dict[str, Any]], str | None]:
    with tempfile.TemporaryDirectory(prefix="govfuzz-auto-discovery-") as work_dir:
        command = [
            str(govfuzz_binary()),
            "auto",
            str(repo),
            "--work-dir",
            work_dir,
            "--profile",
            "external-tools",
            "--list-targets",
            "--no-discovery-cache",
        ]
        result = run(command)
    if result.returncode != 0:
        return [], result.stderr.strip() or f"auto --list-targets exited {result.returncode}"
    return parse_auto_targets(result.stdout, repo)[:top], None


def parse_auto_targets(output: str, repo: Path) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = AUTO_TARGET_RE.match(line)
        if match is None:
            continue
        language = AUTO_LANGUAGES.get(match.group("language"))
        if language is None:
            continue
        source = repo / match.group("file")
        targets.append(
            {
                "file": str(source.resolve()),
                "target": {
                    "language": language,
                    "line": int(match.group("line")),
                    "name": match.group("name").strip(),
                    "score": int(match.group("score")),
                },
            }
        )
    return targets


def discover_repository_catalog(root: Path) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = []
    for repo in sorted(path.parent for path in root.glob("*/*/.git")):
        relative = repo.relative_to(root).as_posix()
        revision = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
        remote = run(["git", "-C", str(repo), "remote", "get-url", "origin"])
        if revision.returncode != 0 or remote.returncode != 0:
            continue
        targets, _ = discover_targets(repo, 20)
        language = next(
            (
                str(item.get("target", {}).get("language"))
                for item in targets
                if item.get("target", {}).get("language") in {"ada", "c", "cpp"}
            ),
            "unknown",
        )
        repositories.append(
            {
                "id": safe_id(repo.name),
                "url": remote.stdout.strip(),
                "rev": revision.stdout.strip(),
                "materialized_path": relative,
                "language": language,
            }
        )
    return repositories


def render_catalog(repositories: list[dict[str, Any]]) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Exact repository pins for the broad destructive legacy campaign.",
        "",
    ]
    for repository in repositories:
        lines.append("[[repositories]]")
        for key in ["id", "url", "rev", "materialized_path", "language"]:
            lines.append(f"{key} = {quoted(str(repository[key]))}")
        lines.append("")
    return "\n".join(lines)


def c_header_scenario(
    repository: dict[str, Any], repo: Path, targets: list[dict[str, Any]]
) -> dict[str, Any] | None:
    by_name = source_index(repo)
    for item in targets:
        source = Path(item["file"]).resolve()
        try:
            relative_source = source.relative_to(repo.resolve())
        except ValueError:
            continue
        if excluded_target(relative_source) or not source.is_file():
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        for match in INCLUDE_RE.finditer(text):
            include = match.group(1)
            dependency = resolve_include(repo, source, include, by_name)
            if dependency is None or dependency == source:
                continue
            if dependency.suffix.lower() not in HEADER_SUFFIXES:
                continue
            relative_dependency = dependency.relative_to(repo.resolve())
            if dependency.stat().st_size == 0:
                continue
            target = item["target"]
            probe = match.group(0).strip()
            return {
                **repository,
                "id": f"{safe_id(repository['id'])}_missing_direct_header",
                "repository_id": repository["id"],
                "language": target["language"],
                "mutation_class": "missing_direct_header",
                "severity": "single_direct_dependency",
                "target_name": target["name"],
                "target_line": int(target["line"]),
                "target_file": relative_source.as_posix(),
                "probe_file": relative_source.as_posix(),
                "probe_contains": probe,
                "remove_files": [relative_dependency.as_posix()],
                "proof": (
                    f"selected target source directly includes {include}; the resolved "
                    "in-tree header is deleted"
                ),
            }
    return None


def sibling_implementations(
    repo: Path, dependency: Path, by_name: dict[str, list[Path]]
) -> list[Path]:
    candidates: set[Path] = set()
    for suffix in IMPLEMENTATION_SUFFIXES:
        candidate = dependency.with_suffix(suffix)
        if candidate.is_file():
            candidates.add(candidate.resolve())
        for match in by_name.get(f"{dependency.stem}{suffix}".lower(), []):
            candidates.add(match.resolve())
    return sorted(
        path
        for path in candidates
        if path.is_relative_to(repo.resolve()) and not excluded_target(path.relative_to(repo))
    )


def dependency_implementation_scenario(
    repository: dict[str, Any], repo: Path, targets: list[dict[str, Any]]
) -> dict[str, Any] | None:
    by_name = source_index(repo)
    implementation_code: dict[Path, str] = {}

    def code_for(path: Path) -> str:
        if path not in implementation_code:
            implementation_code[path] = strip_c_comments(
                path.read_text(encoding="utf-8", errors="replace")
            )
        return implementation_code[path]

    for item in targets:
        source = Path(item["file"]).resolve()
        try:
            relative_source = source.relative_to(repo.resolve())
        except ValueError:
            continue
        if excluded_target(relative_source) or not source.is_file():
            continue
        source_text = source.read_text(encoding="utf-8", errors="replace")
        code = strip_c_comments(source_text)
        for include_match in INCLUDE_RE.finditer(source_text):
            include = include_match.group(1)
            dependency = resolve_include(repo, source, include, by_name)
            if dependency is None or dependency.suffix.lower() not in HEADER_SUFFIXES:
                continue
            header_text = strip_c_comments(
                dependency.read_text(encoding="utf-8", errors="replace")
            )
            names = sorted(set(CALL_NAME_RE.findall(header_text)) - NON_CALL_NAMES)
            implementations = sibling_implementations(repo, dependency, by_name)
            for implementation in implementations:
                if implementation == source:
                    continue
                implementation_text = code_for(implementation)
                for name in names:
                    call = re.compile(rf"\b{re.escape(name)}\s*\(")
                    definition = re.compile(
                        rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", re.DOTALL
                    )
                    if call.search(code) is None or definition.search(
                        implementation_text
                    ) is None:
                        continue
                    definitions = [
                        path
                        for path in implementations
                        if definition.search(code_for(path)) is not None
                    ]
                    if definitions != [implementation]:
                        continue
                    target = item["target"]
                    relative_implementation = implementation.relative_to(repo.resolve())
                    return {
                        **repository,
                        "id": f"{safe_id(repository['id'])}_missing_dependency_impl",
                        "repository_id": repository["id"],
                        "language": target["language"],
                        "mutation_class": "missing_dependency_implementation",
                        "severity": "single_link_dependency",
                        "target_name": target["name"],
                        "target_line": int(target["line"]),
                        "target_file": relative_source.as_posix(),
                        "probe_file": relative_source.as_posix(),
                        "probe_contains": call.search(code).group(0),
                        "removed_contains": name,
                        "remove_files": [relative_implementation.as_posix()],
                        "proof": (
                            f"selected target source calls {name}, declared by directly "
                            f"included {include}; the sibling implementation defining "
                            "that symbol is deleted"
                        ),
                    }
    return None


def ada_spec_scenario(
    repository: dict[str, Any], repo: Path, targets: list[dict[str, Any]]
) -> dict[str, Any] | None:
    by_name = source_index(repo)
    for item in targets:
        source = Path(item["file"]).resolve()
        try:
            relative_source = source.relative_to(repo.resolve())
        except ValueError:
            continue
        if excluded_target(relative_source) or not source.is_file():
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        for match in ADA_WITH_RE.finditer(text):
            unit = match.group(1)
            basename = unit.lower().replace(".", "-") + ".ads"
            candidates = by_name.get(basename, [])
            if len(candidates) != 1:
                continue
            dependency = candidates[0].resolve()
            if dependency == source or dependency.stat().st_size == 0:
                continue
            target = item["target"]
            return {
                **repository,
                "id": f"{safe_id(repository['id'])}_missing_ada_spec",
                "repository_id": repository["id"],
                "language": target["language"],
                "mutation_class": "missing_ada_spec",
                "severity": "single_direct_dependency",
                "target_name": target["name"],
                "target_line": int(target["line"]),
                "target_file": relative_source.as_posix(),
                "probe_file": relative_source.as_posix(),
                "probe_contains": match.group(0).strip(),
                "remove_files": [dependency.relative_to(repo.resolve()).as_posix()],
                "proof": (
                    f"selected target source directly WITHs {unit}; the unique "
                    "in-tree package specification is deleted"
                ),
            }
    return None


def ada_body_scenario(
    repository: dict[str, Any], repo: Path, targets: list[dict[str, Any]]
) -> dict[str, Any] | None:
    by_name = source_index(repo)
    for item in targets:
        source = Path(item["file"]).resolve()
        try:
            relative_source = source.relative_to(repo.resolve())
        except ValueError:
            continue
        if excluded_target(relative_source) or not source.is_file():
            continue
        source_text = source.read_text(encoding="utf-8", errors="replace")
        for with_match in ADA_WITH_RE.finditer(source_text):
            unit = with_match.group(1)
            body_name = unit.lower().replace(".", "-") + ".adb"
            bodies = by_name.get(body_name, [])
            if len(bodies) != 1:
                continue
            body = bodies[0].resolve()
            if body == source or body.stat().st_size == 0:
                continue
            call = re.search(
                rf"(?i)\b{re.escape(unit)}\s*\.\s*([a-z][a-z0-9_]*)\s*\(",
                source_text,
            )
            if call is None:
                continue
            symbol = call.group(1)
            body_text = body.read_text(encoding="utf-8", errors="replace")
            if re.search(
                rf"(?i)\b(?:procedure|function)\s+{re.escape(symbol)}\b", body_text
            ) is None:
                continue
            target = item["target"]
            return {
                **repository,
                "id": f"{safe_id(repository['id'])}_missing_ada_body",
                "repository_id": repository["id"],
                "language": target["language"],
                "mutation_class": "missing_ada_body",
                "severity": "single_link_dependency",
                "target_name": target["name"],
                "target_line": int(target["line"]),
                "target_file": relative_source.as_posix(),
                "probe_file": relative_source.as_posix(),
                "probe_contains": call.group(0),
                "removed_contains": symbol,
                "remove_files": [body.relative_to(repo.resolve()).as_posix()],
                "proof": (
                    f"selected target source calls {unit}.{symbol}; the unique package "
                    "body implementing that dependency is deleted while its spec remains"
                ),
            }
    return None


def synthesize(repository: dict[str, Any], root: Path, top: int) -> dict[str, Any]:
    repo = root / repository["materialized_path"]
    result: dict[str, Any] = {
        "repository_id": repository["id"],
        "path": str(repo),
        "status": "rejected",
    }
    if not repo.joinpath(".git").is_dir():
        result["reason"] = "materialized repository is missing"
        return result
    revision = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    actual = revision.stdout.strip()
    if revision.returncode != 0 or actual != repository["rev"]:
        result["reason"] = f"revision mismatch: expected {repository['rev']}, got {actual}"
        return result
    targets, error = discover_targets(repo, top)
    if error:
        result["reason"] = error
        return result
    result["discovered_targets"] = len(targets)
    languages = {str(item.get("target", {}).get("language", "")) for item in targets}
    scenario = None
    if "ada" in languages or repository.get("language") == "ada":
        scenario = ada_body_scenario(repository, repo, targets)
    if scenario is None and ("ada" in languages or repository.get("language") == "ada"):
        scenario = ada_spec_scenario(repository, repo, targets)
    if scenario is None:
        scenario = dependency_implementation_scenario(repository, repo, targets)
    if scenario is None:
        scenario = c_header_scenario(repository, repo, targets)
    if scenario is None:
        result["reason"] = "no ranked non-test target with a resolvable direct dependency"
        return result
    result["status"] = "selected"
    result["scenario"] = scenario
    return result


def render_manifest(scenarios: list[dict[str, Any]]) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Generated by scripts/validation/synthesize-legacy-breakage-manifest.py",
        "",
        "[settings]",
        "minimum_success_rate = 0.90",
        "iterations = 4",
        "per_target_time = 8",
        "control_first = true",
        "control_iterations = 1",
        "control_per_target_time = 3",
        "max_repair_rounds = 16",
        "scenario_timeout = 300",
        "",
    ]
    ordered_keys = [
        "id",
        "repository_id",
        "url",
        "rev",
        "materialized_path",
        "language",
        "mutation_class",
        "severity",
        "target_name",
        "target_line",
        "target_file",
        "probe_file",
        "probe_contains",
        "removed_contains",
        "proof",
        "remove_files",
    ]
    for scenario in sorted(scenarios, key=lambda item: item["id"]):
        lines.append("[[scenarios]]")
        for key in ordered_keys:
            if key not in scenario:
                continue
            value = scenario[key]
            if isinstance(value, str):
                lines.append(f"{key} = {quoted(value)}")
            elif isinstance(value, int):
                lines.append(f"{key} = {value}")
            elif isinstance(value, list):
                rendered = ", ".join(quoted(str(item)) for item in value)
                lines.append(f"{key} = [{rendered}]")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.discover_catalog:
        repositories = discover_repository_catalog(args.materialized_root)
        if args.write_catalog:
            args.write_catalog.parent.mkdir(parents=True, exist_ok=True)
            args.write_catalog.write_text(render_catalog(repositories), encoding="utf-8")
    else:
        with args.catalog.open("rb") as handle:
            catalog = tomllib.load(handle)
        repositories = list(catalog.get("repositories", []))
    selected_ids = set(args.repository)
    if selected_ids:
        repositories = [repo for repo in repositories if repo["id"] in selected_ids]
    if args.limit is not None:
        repositories = repositories[: args.limit]

    results = [
        synthesize(repository, args.materialized_root, args.top)
        for repository in repositories
    ]
    scenarios = [result["scenario"] for result in results if result["status"] == "selected"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_manifest(scenarios), encoding="utf-8")
    report = {
        "repositories": len(repositories),
        "selected": len(scenarios),
        "rejected": len(repositories) - len(scenarios),
        "results": results,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if scenarios else 1


if __name__ == "__main__":
    raise SystemExit(main())
