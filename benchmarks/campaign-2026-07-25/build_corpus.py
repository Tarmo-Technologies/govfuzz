#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the 500-project sweep corpus, and manage clones without hoarding disk.

Queries GitHub for the per-language quotas, filters out repositories that would
poison the measurements (fuzzing corpora, awesome-lists, doc-only trees, huge
monorepos), and records a ranked backup pool so a rejected pick can be swapped
out.

GitHub's primary-language attribution is unreliable -- JavaScript wrappers get
tagged COBOL, C projects tagged Perl, editor-config trees tagged Lua -- so a
clone counts for a lane only if the tree really is mostly that lane's source.

Clones are streamed by the sweep runner: clone, measure, delete. Nothing here
keeps 500 working trees on disk.

Usage:
  build_corpus.py select              # write corpus.tsv + pool.tsv
  build_corpus.py clone <lane> <repo> # clone one repo, print its path + sha
  build_corpus.py check <dir> <lane>  # validate a clone against its lane
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_TSV = HERE / "corpus.tsv"
POOL_TSV = HERE / "pool.tsv"
CORPUS_ROOT = Path("/home/ubuntu/govfuzz-corpus-500")

# GitHub's primary-language name -> (quota, minimum stars to consider)
QUOTAS: dict[str, tuple[int, int]] = {
    "C": (60, 400),
    "C++": (55, 400),
    "Rust": (40, 300),
    "Go": (40, 400),
    "Python": (40, 400),
    "Java": (38, 300),
    "JavaScript": (30, 400),
    "TypeScript": (25, 400),
    "C#": (25, 200),
    "PHP": (22, 200),
    "Ruby": (22, 200),
    "Perl": (20, 40),
    "Ada": (25, 3),
    "Lua": (20, 100),
    "Fortran": (20, 20),
    "COBOL": (18, 2),
}

# govfuzz's own lane name for each GitHub language.
LANE = {
    "C": "c",
    "C++": "cpp",
    "Rust": "rust",
    "Go": "go",
    "Python": "python",
    "Java": "java",
    "JavaScript": "js",
    "TypeScript": "ts",
    "C#": "csharp",
    "PHP": "php",
    "Ruby": "ruby",
    "Perl": "perl",
    "Ada": "ada",
    "Lua": "lua",
    "Fortran": "fortran",
    "COBOL": "cobol",
}

# Source extensions that identify each lane. Headers shared between C and C++
# are deliberately left out: they cannot discriminate the two.
LANE_EXTS: dict[str, tuple[str, ...]] = {
    "c": (".c",),
    "cpp": (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hxx"),
    "rust": (".rs",),
    "go": (".go",),
    "python": (".py",),
    "java": (".java",),
    "js": (".js", ".mjs", ".cjs", ".jsx"),
    "ts": (".ts", ".tsx"),
    "csharp": (".cs",),
    "php": (".php", ".phtml"),
    "ruby": (".rb",),
    "perl": (".pl", ".pm", ".t"),
    "ada": (".adb", ".ads"),
    "lua": (".lua",),
    "fortran": (".f", ".f77", ".f90", ".f95", ".f03", ".f08", ".for", ".ftn"),
    "cobol": (".cob", ".cbl", ".cpy", ".ccp", ".cobol"),
}
EXT_TO_LANE = {ext: lane for lane, exts in LANE_EXTS.items() for ext in exts}

# Directories that are never the project's own source.
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "external",
    "externals",
    "deps",
    "dependencies",
    "target",
    "build",
    "dist",
    "out",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "bower_components",
}

# A repo whose name or description matches these is documentation, a course, a
# fuzzer, or a deliberately-vulnerable corpus: all of them distort the results.
NAME_REJECT = re.compile(
    r"(?:^|[-_.])(?:awesome|book|books|tutorial|tutorials|course|courses|guide|guides"
    r"|cheatsheet|cheatsheets|interview|interviews|roadmap|roadmaps|handbook|notes"
    r"|docs|documentation|wiki|blog|resume|cv|dotfiles|dotfile|config|configs|conf"
    r"|theme|themes|icons|wallpapers|fonts|papers|slides|talks|examples|example"
    r"|samples|sample|demo|demos|playground|exercises|katas|challenges|writeups|ctf"
    r"|fuzz|fuzzer|fuzzing|afl|libfuzzer|honggfuzz|radamsa|vulnerable|vulnhub"
    r"|juliet|testsuite|benchmark|benchmarks|pdf|learn|learning)(?:$|[-_.])",
    re.I,
)
DESC_REJECT = re.compile(
    r"\b(?:awesome list|curated list|collection of links|learning resources"
    r"|free programming books|deliberately vulnerable|intentionally vulnerable"
    r"|fuzzing (?:engine|harness|corpus)|fuzz target[s]?|oss-fuzz"
    r"|my (?:neovim|nvim|vim|emacs) (?:config|configuration|setup|dotfiles))\b",
    re.I,
)
EXACT_REJECT = {
    "torvalds/linux",  # 37M SLOC; measured separately in the static-scan bench
    "llvm/llvm-project",
    "chromium/chromium",
    "microsoft/vscode",
    "flutter/flutter",
    "tensorflow/tensorflow",
    "pytorch/pytorch",
    "google/oss-fuzz",
    "AFLplusplus/AFLplusplus",
    "x0rz/EQGRP",  # leaked binaries, not a buildable project
}
MAX_KB = 400_000  # 400 MB working tree
POOL_DEPTH = 4  # keep quota * this many ranked candidates as backups


def gh_search(language: str, min_stars: int, pages: int) -> list[dict]:
    """Star-ranked repository search for one language."""
    out: list[dict] = []
    for page in range(1, pages + 1):
        query = f"language:{language} stars:>={min_stars} size:<{MAX_KB} archived:false"
        cmd = [
            "gh", "api", "-X", "GET", "search/repositories",
            "-f", f"q={query}", "-f", "sort=stars", "-f", "order=desc",
            "-f", "per_page=100", "-f", f"page={page}",
        ]  # fmt: skip
        for attempt in range(3):
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                break
            print(f"  retry {language} p{page}: {proc.stderr.strip()[:120]}")
        else:
            break
        items = json.loads(proc.stdout).get("items", [])
        out.extend(items)
        if len(items) < 100:
            break
    return out


def acceptable(repo: dict) -> bool:
    if repo["full_name"] in EXACT_REJECT:
        return False
    if NAME_REJECT.search(repo["name"]):
        return False
    if DESC_REJECT.search(repo.get("description") or ""):
        return False
    if repo.get("size", 0) >= MAX_KB:
        return False
    return not repo.get("fork", False)


def _row(lane: str, repo: dict) -> str:
    return "\t".join(
        (
            lane,
            repo["full_name"],
            repo["clone_url"],
            str(repo.get("stargazers_count", 0)),
            str(repo.get("size", 0)),
            (repo.get("description") or "").replace("\t", " ")[:160],
        )
    )


def select() -> None:
    header = "# lane\trepo\tclone_url\tstars\tsize_kb\tdescription\n"
    chosen_rows: list[str] = []
    pool_rows: list[str] = []
    for language, (quota, min_stars) in QUOTAS.items():
        pages = max(2, min(6, (quota * POOL_DEPTH) // 100 + 2))
        found = gh_search(language, min_stars, pages)
        kept = [r for r in found if acceptable(r)]
        lane = LANE[language]
        chosen_rows += [_row(lane, r) for r in kept[:quota]]
        pool_rows += [_row(lane, r) for r in kept[quota : quota * POOL_DEPTH]]
        short = quota - len(kept[:quota])
        print(
            f"{language:12s} searched={len(found):4d} kept={len(kept):4d} "
            f"chosen={min(quota, len(kept)):3d} pool={len(kept[quota:quota * POOL_DEPTH]):4d}"
            + (f"  SHORT by {short}" if short > 0 else "")
        )
    CORPUS_TSV.write_text(header + "\n".join(chosen_rows) + "\n")
    POOL_TSV.write_text(header + "\n".join(pool_rows) + "\n")
    print(f"\nwrote {len(chosen_rows)} picks to {CORPUS_TSV}")
    print(f"wrote {len(pool_rows)} backups to {POOL_TSV}")


def read_tsv(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        p = line.split("\t")
        rows.append(
            {
                "lane": p[0],
                "repo": p[1],
                "url": p[2],
                "stars": int(p[3]),
                "size_kb": int(p[4]),
            }
        )
    return rows


def clone_path(lane: str, repo: str) -> Path:
    return CORPUS_ROOT / lane / repo.replace("/", "__")


def clone_repo(lane: str, repo: str, url: str, timeout: int = 1200) -> tuple[Path, str]:
    """Shallow-clone one repo. Returns (path, sha) or raises RuntimeError."""
    dest = clone_path(lane, repo)
    if not (dest / ".git").exists():
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", "--no-tags", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return dest, sha


def lane_profile(root: Path, cap_files: int = 60_000) -> tuple[Counter, Counter]:
    """Count source files and non-blank lines per lane under root."""
    files: Counter = Counter()
    lines: Counter = Counter()
    seen = 0
    for path in root.rglob("*"):
        if seen >= cap_files:
            break
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        lane = EXT_TO_LANE.get(path.suffix.lower())
        if lane is None:
            continue
        seen += 1
        files[lane] += 1
        try:
            with path.open("rb") as fh:
                lines[lane] += sum(1 for ln in fh if ln.strip())
        except OSError:
            continue
    return files, lines


def check_lane(root: Path, lane: str) -> tuple[bool, str]:
    """Is this tree really mostly `lane` source, with enough of it to fuzz?"""
    files, lines = lane_profile(root)
    if not files:
        return False, "no recognised source files"
    top_lane, top_lines = lines.most_common(1)[0]
    n_files, n_lines = files[lane], lines[lane]
    detail = f"{lane}: {n_files} files / {n_lines} lines; top={top_lane}({top_lines})"
    if n_files < 3:
        return False, f"too few {lane} files ({detail})"
    if n_lines < 300:
        return False, f"too little {lane} code ({detail})"
    # C and C++ interleave constantly; either winning is fine for both lanes.
    kin = {"c": {"c", "cpp"}, "cpp": {"c", "cpp"}, "js": {"js", "ts"}, "ts": {"js", "ts"}}
    if top_lane != lane and top_lane not in kin.get(lane, {lane}):
        # Accept a strong minority lane (a real Lua/Perl core inside a polyglot
        # repo is still a valid target), reject a token wrapper.
        if n_lines < max(2_000, top_lines * 0.25):
            return False, f"mislabelled by GitHub ({detail})"
    return True, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("select")
    c = sub.add_parser("clone")
    c.add_argument("lane")
    c.add_argument("repo")
    c.add_argument("url")
    k = sub.add_parser("check")
    k.add_argument("dir")
    k.add_argument("lane")
    args = ap.parse_args()

    if args.action == "select":
        select()
    elif args.action == "clone":
        path, sha = clone_repo(args.lane, args.repo, args.url)
        print(f"{path}\t{sha}")
    else:
        ok, why = check_lane(Path(args.dir), args.lane)
        print(f"{'OK' if ok else 'REJECT'}\t{why}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
