#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Drive govfuzz over the sweep corpus, one project at a time, and measure it.

Projects are streamed: clone, run every surface under test, distil the numbers
into results/<lane>__<repo>.json, then delete the clone and the work dir. Peak
disk stays at a few working trees no matter how large the corpus is.

Each project row records the target-status histogram, the residual blockers, the
findings, per-surface exit codes and wall times, and any govfuzz panic --
everything needed to rank the next fix and to prove the fix moved the number.

Usage:
  run_sweep.py --wave W0 --per-lane 1
  run_sweep.py --wave W1 --per-lane 7 --jobs 3
  run_sweep.py --wave W1 --per-lane 7 --only c,cpp,ada --force
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import build_corpus as bc

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GOVFUZZ = Path(os.environ.get("GOVFUZZ_BIN", REPO / "target" / "release" / "govfuzz"))
WORK_ROOT = Path("/home/ubuntu/govfuzz-sweep-work")
RESULTS = HERE / "results"
VALIDATED = HERE / "validated.json"

LANES = list(dict.fromkeys(bc.LANE.values()))

PANIC_RE = re.compile(
    r"(?:thread '[^']*' panicked at|internal error: entered unreachable code"
    r"|attempt to (?:subtract with overflow|add with overflow|divide by zero)"
    r"|index out of bounds|called `(?:Option::unwrap|Result::unwrap)\(\)`)"
)


def sh(
    args: list[str],
    cwd: Path,
    timeout: int,
    env_extra: dict[str, str] | None = None,
    keep_stdout: bool = False,
) -> dict:
    """Run one govfuzz invocation, capturing what the sweep needs to judge it."""
    env = dict(os.environ)
    env.setdefault("GOVFUZZ_PROFILE", "external-tools")
    env["RUST_BACKTRACE"] = "1"
    # A C# shop has a current SDK; the distro one is .NET 8 and most of the
    # corpus now targets 9/10. govfuzz picks the newest it finds on PATH.
    env["DOTNET_ROOT"] = "/home/ubuntu/.dotnet"
    env["PATH"] = "/home/ubuntu/.dotnet:" + env.get("PATH", "")
    if env_extra:
        env.update(env_extra)
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
        )
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = -9
        out = (exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else ""
        err = (exc.stderr or b"").decode("utf-8", "replace") if exc.stderr else ""
    wall = round(time.monotonic() - started, 2)
    panic = PANIC_RE.search(err) or PANIC_RE.search(out)
    row = {
        "cmd": " ".join(args[1:]),
        "exit": code,
        "wall_s": wall,
        "timed_out": timed_out,
        "panic": bool(panic),
    }
    if panic:
        # Keep enough context to fix it without re-running the whole project.
        tail = err[-4000:] if err else out[-4000:]
        row["panic_excerpt"] = tail
    elif code not in (0, 1, 2) and not timed_out:
        row["stderr_tail"] = (err or out)[-2000:]
    if keep_stdout:
        # Caller pops this: the parsed numbers are kept, the raw JSON is not.
        row["stdout_json"] = out
    return row


def read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def distil_run(work: Path) -> dict:
    """Pull the target histogram, blockers, and per-target outcomes out of a run."""
    out: dict = {}
    run = read_json(work / "auto" / "run.json")
    if isinstance(run, dict):
        out["summary"] = run.get("summary", {})
        out["mode"] = run.get("mode")
        out["partial"] = run.get("partial")
        needed = run.get("needed_for_build") or {}
        out["needed_for_build"] = {
            k: (len(v) if isinstance(v, list) else v) for k, v in needed.items()
        }
        targets = []
        for t in run.get("targets") or []:
            outcome = t.get("outcome") or {}
            stub = t.get("stub_execution") or {}
            targets.append(
                {
                    "name": t.get("name"),
                    "source": t.get("source", "").split("/")[-1],
                    "outcome": outcome.get("outcome"),
                    "retries": outcome.get("retries"),
                    "repairs": len(outcome.get("repairs") or []),
                    "execs_per_sec": outcome.get("executions_per_sec"),
                    "reason": outcome.get("reason") or outcome.get("detail"),
                    "stub_only": stub.get("stub_only"),
                    "blind_stub_fraction": stub.get("blind_stub_fraction"),
                }
            )
        out["targets"] = targets
    blockers = read_json(work / "auto" / "blockers.json")
    if blockers is not None:
        out["blockers"] = blockers
    findings = []
    findings_dir = work / "findings"
    if findings_dir.is_dir():
        for entry in sorted(findings_dir.iterdir())[:200]:
            meta = read_json(entry / "finding.json") or read_json(entry / "meta.json")
            if isinstance(meta, dict):
                # The CWE, severity and confidence live under `actionability`;
                # reading them off the top level silently produced null for every
                # finding in the corpus.
                act = meta.get("actionability") or {}
                cwe = act.get("cwe") or meta.get("cwe")
                findings.append(
                    {
                        "id": entry.name,
                        "rule": meta.get("rule_id") or meta.get("rule"),
                        "cwe": cwe if isinstance(cwe, list) else ([cwe] if cwe else []),
                        "cwe_name": act.get("cwe_name"),
                        "kind": meta.get("kind"),
                        "severity": act.get("severity") or meta.get("severity"),
                        "confidence": act.get("confidence"),
                        "tier": meta.get("finding_tier") or meta.get("tier"),
                        "harness": meta.get("harness_id"),
                    }
                )
            else:
                findings.append({"id": entry.name})
    out["findings_detail"] = findings
    return out


def distil_static(out_dir: Path) -> dict:
    report = read_json(out_dir / "static-report.json")
    res: dict = {"sarif": (out_dir / "static-report.sarif").exists()}
    if isinstance(report, dict):
        fs = report.get("findings") or []
        res["count"] = len(fs)
        by_rule: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in fs:
            rule = str(f.get("rule_id") or f.get("rule") or "?")
            by_rule[rule] = by_rule.get(rule, 0) + 1
            sev = str(f.get("severity") or "?")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        res["by_severity"] = by_sev
        res["top_rules"] = dict(sorted(by_rule.items(), key=lambda kv: -kv[1])[:15])
        res["gaps"] = len(report.get("analysis_gaps") or [])
    return res


def run_project(row: dict, args: argparse.Namespace) -> dict:
    lane, repo = row["lane"], row["repo"]
    slug = f"{lane}__{repo.replace('/', '__')}"
    result: dict = {
        "lane": lane,
        "repo": repo,
        "stars": row.get("stars"),
        "wave": args.wave,
        "surfaces": {},
    }
    work = WORK_ROOT / slug
    scratch = WORK_ROOT / f"{slug}.cwd"
    tree: Path | None = None
    try:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)

        t0 = time.monotonic()
        try:
            tree, sha = bc.clone_repo(lane, repo, row["url"])
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            result["status"] = "clone_failed"
            result["error"] = str(exc)[:300]
            return result
        result["sha"] = sha
        result["clone_s"] = round(time.monotonic() - t0, 1)

        ok, why = bc.check_lane(tree, lane)
        result["lane_check"] = why
        if not ok:
            result["status"] = "rejected_lane"
            return result

        surfaces = set(args.surfaces.split(","))

        if "sloc" in surfaces:
            r = sh(
                [str(GOVFUZZ), "sloc", str(tree), "--json", "--out", str(scratch / "sloc.json")],
                scratch,
                300,
            )
            data = read_json(scratch / "sloc.json")
            roots = (data or {}).get("roots") if isinstance(data, dict) else None
            if roots:
                langs = roots[0].get("languages") or []
                r["languages"] = len(langs)
                r["sloc_total"] = int((roots[0].get("total") or {}).get("code_lines") or 0)
                r["sloc_by_lang"] = {
                    str(x.get("language")): int(x.get("code_lines") or 0)
                    for x in langs
                    if isinstance(x, dict)
                }
            result["surfaces"]["sloc"] = r

        if "list" in surfaces:
            r = sh(
                [
                    str(GOVFUZZ), "list", "targets", str(tree),
                    "--format", "json", "--top", "100000",
                ],  # fmt: skip
                scratch,
                900,
                keep_stdout=True,
            )
            try:
                listed = json.loads(r.pop("stdout_json", "") or "[]")
            except json.JSONDecodeError:
                listed = []
            if isinstance(listed, list):
                r["count"] = len(listed)
                per_lang: dict[str, int] = {}
                for item in listed:
                    lang = str(((item or {}).get("target") or {}).get("language") or "?")
                    per_lang[lang] = per_lang.get(lang, 0) + 1
                r["by_language"] = per_lang
            result["surfaces"]["list_targets"] = r

        if "static" in surfaces:
            static_out = work / "static"
            r = sh(
                [
                    str(GOVFUZZ), "static-scan", str(tree),
                    "--out", str(static_out), "--sarif",
                    "--sloc", "sloc-breakdown.json",
                    "--jobs", "2", "--max-memory-mb", "2500",
                ],  # fmt: skip
                scratch,
                1200,
            )
            r.update(distil_static(static_out))
            result["surfaces"]["static_scan"] = r

        if "sbom" in surfaces:
            sbom_out = work / "sbom"
            r = sh(
                [str(GOVFUZZ), "sbom", str(tree), "--out", str(sbom_out)],
                scratch,
                600,
            )
            for name in ("sbom.json", "sbom.cdx.json", "sbom.spdx.json"):
                data = read_json(sbom_out / name)
                if isinstance(data, dict):
                    comps = data.get("components") or data.get("packages") or []
                    r["components"] = len(comps)
                    break
            result["surfaces"]["sbom"] = r

        if "fuzz" in surfaces:
            cmd = [
                str(GOVFUZZ), "auto", str(tree),
                "--work-dir", str(work),
                "--campaign-time", str(args.campaign_time),
                "--per-target-time", str(args.per_target_time),
                "--max-attempts", str(args.max_attempts),
                "--max-repair-rounds", str(args.max_repair_rounds),
                "--jobs", str(args.inner_jobs),
                "--profile", "external-tools",
            ]  # fmt: skip
            if args.max_targets:
                # Success-seeking mode: attempt ranked candidates until N of them
                # FUZZ, backfilling past the nonviable ones. Answers "can govfuzz
                # find N fuzzable targets here?", where the attempt cap answers
                # "of the top N candidates, how many fuzz?".
                cmd += ["--max-targets", str(args.max_targets)]
            if args.single_pass:
                cmd.append("--single-pass")
            if args.force:
                cmd.append("--force")
            r = sh(cmd, scratch, args.campaign_time + args.auto_slack)
            r.update(distil_run(work))
            result["surfaces"]["auto"] = r

        if "report" in surfaces and (work / "findings").is_dir():
            r = sh(
                [
                    str(GOVFUZZ), "report",
                    "--findings", str(work / "findings"),
                    "--out", str(work / "reports"),
                    "--sarif", "--junit", "--csv",
                ],  # fmt: skip
                scratch,
                300,
            )
            reports = work / "reports"
            r["emitted"] = sorted(p.suffix for p in reports.glob("*")) if reports.is_dir() else []
            result["surfaces"]["report"] = r

        result["status"] = "done"
        return result
    finally:
        if not args.keep_clone and tree is not None:
            shutil.rmtree(tree, ignore_errors=True)
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def pick_wave(args: argparse.Namespace) -> list[dict]:
    """Choose `--per-lane` projects per lane, skipping known lane rejects."""
    corpus = bc.read_tsv(bc.CORPUS_TSV)
    pool = bc.read_tsv(bc.POOL_TSV) if bc.POOL_TSV.exists() else []
    verdicts = read_json(VALIDATED) or {}
    lanes = args.only.split(",") if args.only else LANES
    done = set()
    if not args.rerun:
        for path in args.results_dir.glob("*.json"):
            row = read_json(path)
            if isinstance(row, dict) and row.get("status") in ("done", "rejected_lane"):
                done.add(row.get("repo"))
    wave: list[dict] = []
    for lane in lanes:
        lane_corpus = [r for r in corpus if r["lane"] == lane]
        # The corpus is the pinned 500. The pool exists to REPLACE a pick that
        # turns out not to be the lane it was labelled, not to pad a lane past
        # what was selected.
        lane_pool = [r for r in pool if r["lane"] == lane]
        want = min(args.per_lane, len(lane_corpus)) if args.corpus_only else args.per_lane
        picked = 0
        skip = args.skip
        for row in lane_corpus + lane_pool:
            if picked >= want:
                break
            if verdicts.get(row["repo"]) == "rejected_lane":
                continue
            if row["repo"] in done:
                picked += 1  # already measured this wave slot
                continue
            if skip > 0:
                skip -= 1
                continue
            wave.append(row)
            picked += 1
    return wave


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wave", default="W0")
    ap.add_argument("--per-lane", type=int, default=1)
    ap.add_argument("--corpus-only", action="store_true",
                    help="never pad a lane from the backup pool")
    ap.add_argument("--skip", type=int, default=0, help="skip the first N per lane")
    ap.add_argument("--only", default="", help="comma-separated lanes")
    ap.add_argument("--jobs", type=int, default=3, help="concurrent projects")
    ap.add_argument("--inner-jobs", type=int, default=1, help="govfuzz auto --jobs")
    ap.add_argument("--campaign-time", type=int, default=240)
    ap.add_argument("--per-target-time", type=int, default=6)
    ap.add_argument("--max-attempts", type=int, default=60)
    ap.add_argument("--max-repair-rounds", type=int, default=16)
    ap.add_argument("--max-targets", type=int, default=0,
                    help="seek N successful fuzzes per project (0 = off)")
    ap.add_argument("--auto-slack", type=int, default=900, help="grace over campaign-time")
    ap.add_argument("--single-pass", action="store_true", default=True)
    ap.add_argument("--all-passes", dest="single_pass", action="store_false")
    ap.add_argument("--auto-force", dest="force", action="store_true",
                    help="pass --force to auto (drive opaque/unbuildable targets)")
    ap.add_argument("--results-dir", type=Path, default=RESULTS,
                    help="where rows are written; a separate dir keeps an A/B "
                         "wave (e.g. --auto-force) from overwriting the baseline")
    ap.add_argument("--surfaces", default="sloc,list,static,sbom,fuzz,report")
    ap.add_argument("--keep-clone", action="store_true")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument("--merge", action="store_true",
                    help="update only the surfaces measured, keeping the rest of the row")
    ap.add_argument("--rerun", action="store_true",
                    help="re-measure projects that already have a result row")
    args = ap.parse_args()

    if not GOVFUZZ.exists():
        print(f"missing binary: {GOVFUZZ}", file=sys.stderr)
        return 2
    args.results_dir.mkdir(parents=True, exist_ok=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    wave = pick_wave(args)
    print(f"wave {args.wave}: {len(wave)} projects, {args.jobs} concurrent")
    verdicts = read_json(VALIDATED) or {}
    completed = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_project, row, args): row for row in wave}
        for fut in as_completed(futures):
            row = futures[fut]
            slug = f"{row['lane']}__{row['repo'].replace('/', '__')}"
            try:
                result = fut.result()
            except Exception as exc:  # noqa: BLE001 - runner must never die
                result = {
                    "lane": row["lane"],
                    "repo": row["repo"],
                    "wave": args.wave,
                    "status": "runner_error",
                    "error": repr(exc)[:500],
                }
            out_path = args.results_dir / f"{slug}.json"
            if args.merge:
                # Re-measuring ONE surface must not discard the others: a
                # sloc-only pass over the corpus is minutes, a full re-run is
                # hours, and the fuzz rows are the expensive part.
                previous = read_json(out_path)
                if isinstance(previous, dict):
                    merged = dict(previous)
                    merged.setdefault("surfaces", {})
                    merged["surfaces"].update(result.get("surfaces") or {})
                    for key, value in result.items():
                        if key != "surfaces":
                            merged[key] = value
                    result = merged
            out_path.write_text(json.dumps(result, indent=1))
            if result.get("status") in ("rejected_lane",):
                verdicts[row["repo"]] = "rejected_lane"
            completed += 1
            summary = (result.get("surfaces", {}).get("auto", {}) or {}).get("summary", {})
            built = summary.get("built_and_fuzzed", "-")
            disc = summary.get("discovered_total", summary.get("discovered", "-"))
            panics = [
                name
                for name, s in (result.get("surfaces") or {}).items()
                if isinstance(s, dict) and s.get("panic")
            ]
            print(
                f"[{completed}/{len(wave)}] {row['lane']:8s} {row['repo'][:44]:44s} "
                f"{result.get('status'):14s} built={built}/{disc}"
                + (f"  PANIC:{','.join(panics)}" if panics else "")
            )
            VALIDATED.write_text(json.dumps(verdicts, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
