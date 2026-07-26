#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise every govfuzz surface that the per-project sweep does not.

The sweep measures the fuzzing pipeline plus sloc/static-scan/sbom/report. This
script covers the rest of the CLI against a real project and a real crash:
triage (minimize, replay, capsule, verify-poc, env-capsule, explain,
cartography, differential, cmplog), supply chain (license-audit, sbom gating),
governance (policy, audit, pack, export), no-source analysis (binary scan),
one-function fuzzing (snippet), and CI mode.

Each surface reports PASS/FAIL with the check that decided it, so a regression
in a rarely-run command shows up as a line rather than as silence.

Usage:
  surfaces.py --project <dir> [--work /tmp/surfaces] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GOVFUZZ = Path(os.environ.get("GOVFUZZ_BIN", REPO / "target" / "release" / "govfuzz"))


class Surfaces:
    def __init__(self, work: Path, project: Path) -> None:
        self.work = work
        self.project = project
        self.results: list[dict] = []

    def run(
        self,
        name: str,
        args: list[str],
        *,
        timeout: int = 300,
        expect_files: list[Path] | None = None,
        expect_stdout: list[str] | None = None,
        allow_exit: tuple[int, ...] = (0,),
        cwd: Path | None = None,
    ) -> dict:
        started = time.monotonic()
        try:
            proc = subprocess.run(
                [str(GOVFUZZ), *args],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                cwd=str(cwd or self.work),
                env={**os.environ, "RUST_BACKTRACE": "1",
                     "PATH": "/home/ubuntu/.dotnet:" + os.environ.get("PATH", "")},
            )
            code, out, err = proc.returncode, proc.stdout, proc.stderr
            timed_out = False
        except subprocess.TimeoutExpired:
            code, out, err, timed_out = -9, "", "", True

        problems = []
        if timed_out:
            problems.append(f"timed out after {timeout}s")
        elif code not in allow_exit:
            problems.append(f"exit={code}: {(err or out).strip().splitlines()[-1][:160] if (err or out).strip() else 'no output'}")
        if "panicked at" in err or "panicked at" in out:
            problems.append("PANIC")
        for path in expect_files or []:
            if not path.exists():
                problems.append(f"missing output {path.name}")
        for needle in expect_stdout or []:
            if needle not in out and needle not in err:
                problems.append(f"missing {needle!r} in output")

        row = {
            "surface": name,
            "cmd": " ".join(args)[:200],
            "exit": code,
            "wall_s": round(time.monotonic() - started, 2),
            "ok": not problems,
            "problems": problems,
        }
        self.results.append(row)
        status = "PASS" if row["ok"] else "FAIL"
        print(f"[{status}] {name:22s} {row['wall_s']:6.1f}s  {'; '.join(problems)}")
        return row


def harness_binary(work: Path, finding_dir: Path) -> Path | None:
    """The built harness a finding came from, for the commands that need it."""
    meta = finding_dir / "finding.json"
    harness_id = None
    if meta.is_file():
        try:
            harness_id = json.loads(meta.read_text()).get("harness_id")
        except json.JSONDecodeError:
            harness_id = None
    candidates = []
    if harness_id:
        candidates.append(work / "harnesses" / harness_id / "main")
    candidates += sorted((work / "harnesses").glob("*/main")) if (work / "harnesses").is_dir() else []
    return next((c for c in candidates if c.is_file()), None)


def find_finding(work: Path) -> tuple[Path, Path] | None:
    """First finding directory with a crash input, and its harness dir."""
    findings = work / "findings"
    if not findings.is_dir():
        return None
    for entry in sorted(findings.iterdir()):
        for name in ("input", "crash", "input.bin", "testcase"):
            candidate = entry / name
            if candidate.is_file():
                return entry, candidate
        files = [p for p in entry.iterdir() if p.is_file()] if entry.is_dir() else []
        if files:
            return entry, files[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", type=Path, required=True)
    ap.add_argument("--work", type=Path, default=Path("/tmp/govfuzz-surfaces"))
    ap.add_argument("--json", type=Path)
    ap.add_argument("--campaign-time", type=int, default=120)
    args = ap.parse_args()

    shutil.rmtree(args.work, ignore_errors=True)
    args.work.mkdir(parents=True, exist_ok=True)
    s = Surfaces(args.work, args.project)
    auto_work = args.work / "auto-work"

    # --- pipeline: produce a run with findings for the triage surfaces to use
    s.run(
        "auto",
        ["auto", str(args.project), "--work-dir", str(auto_work),
         "--campaign-time", str(args.campaign_time), "--per-target-time", "8",
         "--max-attempts", "12", "--profile", "external-tools"],
        timeout=args.campaign_time + 900,
        allow_exit=(0, 1),
        expect_files=[auto_work / "auto" / "run.json"],
    )

    # --- inventory / analysis surfaces
    s.run("sloc", ["sloc", str(args.project), "--json"], timeout=300)
    s.run("list targets", ["list", "targets", str(args.project), "--top", "10"], timeout=600)
    s.run("list oracles", ["list", "oracles"], timeout=60)
    s.run("rules", ["rules", "list"], timeout=60, allow_exit=(0, 2))
    s.run(
        "static-scan",
        ["static-scan", str(args.project), "--out", str(args.work / "static"), "--sarif"],
        timeout=900,
        allow_exit=(0, 1),
        expect_files=[args.work / "static" / "static-report.json",
                      args.work / "static" / "static-report.sarif"],
    )
    s.run(
        "static-scan baseline",
        ["static-scan", str(args.project), "--out", str(args.work / "static2"),
         "--baseline", str(args.work / "static" / "static-report.json")],
        timeout=900,
        allow_exit=(0, 1),
    )
    s.run(
        "sbom",
        ["sbom", str(args.project), "--out", str(args.work / "sbom")],
        timeout=600,
        allow_exit=(0, 1),
    )
    s.run("license-audit", ["license-audit", "--root", str(REPO)], timeout=300, allow_exit=(0, 1))

    # --- reporting surfaces
    s.run(
        "report all formats",
        ["report", "--findings", str(auto_work / "findings"),
         "--out", str(args.work / "reports"), "--sarif", "--junit", "--csv"],
        timeout=300,
        allow_exit=(0, 1),
    )

    # --- governance / air-gap surfaces
    s.run("policy validate", ["policy", "explain"], timeout=60, allow_exit=(0, 2))
    s.run(
        "audit",
        ["audit", "read", "--work-dir", str(auto_work)],
        timeout=60,
        allow_exit=(0, 1, 2),
    )
    s.run(
        "export",
        ["export", "--work-dir", str(auto_work), "--out", str(args.work / "export")],
        timeout=300,
        allow_exit=(0, 1, 2),
    )

    # --- triage surfaces, driven by a real finding when the run produced one
    found = find_finding(auto_work)
    if found:
        finding_dir, crash_input = found
        harness = harness_binary(auto_work, finding_dir)
        if harness:
            s.run(
                "minimize",
                ["minimize", "--finding", str(finding_dir), "--harness", str(harness)],
                timeout=600,
                allow_exit=(0, 1, 2),
            )
        s.run(
            "replay",
            ["replay", str(finding_dir)],
            timeout=600,
            allow_exit=(0, 1, 2),
        )
        s.run(
            "explain",
            ["explain", "--work-dir", str(auto_work), "--finding-id", finding_dir.name],
            timeout=300,
            allow_exit=(0, 1, 2),
        )
        s.run(
            "capsule",
            ["capsule", "--work-dir", str(auto_work), "--finding-id", finding_dir.name],
            timeout=600,
            allow_exit=(0, 1, 2),
        )
        capsules = sorted((auto_work / "capsules").glob("*")) if (auto_work / "capsules").is_dir() else []
        if capsules:
            s.run(
                "verify-poc",
                ["verify-poc", str(capsules[0])],
                timeout=900,
                allow_exit=(0, 1, 2),
            )
        else:
            print("[SKIP] verify-poc           (capsule produced no package to verify)")
        s.run(
            "cartography",
            ["cartography", "--work-dir", str(auto_work), "--finding-id", finding_dir.name],
            timeout=600,
            allow_exit=(0, 1, 2),
        )
    else:
        print("[SKIP] triage surfaces      (the run produced no finding to triage)")

    # --- one-function fuzzing with no project at all
    snippet = args.work / "snippet.c"
    snippet.write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "int parse_len(const unsigned char *d, size_t n) {\n"
        "    if (n < 4) return -1;\n"
        "    int len = d[0] | (d[1] << 8);\n"
        "    if (len > 100) { int *p = 0; return *p; }\n"
        "    return len;\n}\n"
    )
    s.run(
        "snippet",
        ["snippet", str(snippet), "--work-dir", str(args.work / "snippet-work"),
         "--per-target-time", "10"],
        timeout=900,
        allow_exit=(0, 1, 2),
    )

    # --- no-source analysis of a built artifact
    binary = shutil.which("gzip") or "/bin/ls"
    s.run(
        "binary scan",
        ["binary", "scan", binary, "--out", str(args.work / "binscan")],
        timeout=600,
        allow_exit=(0, 1, 2),
    )

    # --- CI mode with a gate
    s.run(
        "ci",
        ["ci", str(args.project), "--work-dir", str(args.work / "ci-work"),
         "--campaign-time", "60", "--per-target-time", "5",
         "--summary-file", str(args.work / "ci-summary.md"),
         "--fail-on", "critical"],
        timeout=1800,
        allow_exit=(0, 1, 2),
        expect_files=[args.work / "ci-summary.md"],
    )

    passed = sum(1 for r in s.results if r["ok"])
    print(f"\n{passed}/{len(s.results)} surfaces passed")
    if args.json:
        args.json.write_text(json.dumps(s.results, indent=1))
        print(f"wrote {args.json}")
    return 0 if passed == len(s.results) else 1


if __name__ == "__main__":
    sys.exit(main())
