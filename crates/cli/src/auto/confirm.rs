// SPDX-License-Identifier: Apache-2.0

//! M23 #484 — fuzz-confirmation join.
//!
//! Static analysis flags *possible* weaknesses; fuzzing proves *reachable* ones.
//! This module ties the two together: after the attempt loop has written its
//! runtime findings (fuzz crashes + oracle hits) and the `--static` / report-only
//! passes have written their static findings, it matches each static finding's
//! flagged source site (file + line) against the sink site of every runtime
//! finding. When they coincide — govfuzz observed an input actually reach the
//! exact line the static rule flagged — the static finding is upgraded in place to
//! `confirmation: "fuzz_confirmed"` with high confidence and a `likely_reachable`
//! verdict, and records which runtime finding(s) confirmed it. This is govfuzz's
//! differentiator: a confirmed static finding is not a maybe, it is a defect a
//! fuzzer walked into.
//!
//! The join never downgrades on SILENCE — a static finding with no matching
//! runtime hit stays `static`, because the fuzzer not reaching a site does not
//! prove it unreachable, and downgrading on no-hit would manufacture false
//! negatives. The one honest downgrade ([`downgrade_unreachable_static_findings`],
//! #486 Phase 2) fires only on POSITIVE evidence: a still-`static` finding inside
//! a function fuzzing PROVED is not attacker-reachable (its candidate's
//! `input_reachability` is `reachability_unproven`/`output_serializer`) is demoted
//! to `lab_only` — triaged down, not hidden.

use actionability::{ActionabilityConfidence, ActionabilityRecord, RunMode, Verdict};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Outcome of the join, folded into the run summary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmStats {
    /// Static findings upgraded to `fuzz_confirmed`.
    pub confirmed: usize,
}

/// One runtime crash/oracle site that can confirm a static finding.
struct RuntimeSite {
    /// The sink's source path (for the canonical-path collision guard).
    path: String,
    /// The confirming runtime finding's id.
    id: String,
    /// Its root-cause cluster, so the confirmed static finding can join the same
    /// issue row instead of rendering a lonely second row (#484).
    cluster_key_full: Option<String>,
    /// Whether the fuzzed entry that reached this site is attacker-controlled:
    /// `Some(true)` reachable, `Some(false)` proven NOT attacker-reachable (an
    /// internal helper / serializer), `None` not assessed. Drives the confirmed
    /// finding's verdict — a site the fuzzer only reached through a non-attacker
    /// entry is confirmed-but-`lab_only`, not `likely_reachable`.
    attacker_reachable: Option<bool>,
}

/// Join the static findings under `work/findings/` against the run's runtime
/// findings and upgrade every static finding whose flagged site coincides with a
/// runtime sink. Returns how many were upgraded. Best-effort: unreadable or
/// mis-shaped sidecars are skipped, never fatal.
pub fn confirm_static_findings(work: &Path, mode: RunMode) -> ConfirmStats {
    let findings_dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return ConfirmStats::default();
    };

    // (basename_lowercase, line) -> runtime sites at that source location.
    let mut runtime: BTreeMap<(String, u64), Vec<RuntimeSite>> = BTreeMap::new();
    let mut statics: Vec<PathBuf> = Vec::new();

    for entry in entries.flatten() {
        let finding_json = entry.path().join("finding.json");
        let Some(raw) = read_json(&finding_json) else {
            continue;
        };
        if is_static_finding(&raw) {
            statics.push(finding_json);
            continue;
        }
        // Runtime finding (fuzz crash or oracle hit): index its sink site.
        let record =
            actionability::existing_actionability_or_backfill(mode, &raw, Some(&finding_json));
        if let Some((file, line)) = sink_site(&record) {
            let id = raw
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let cluster_key_full = raw
                .get("cluster_key_full")
                .and_then(Value::as_str)
                .filter(|k| !k.trim().is_empty())
                .map(ToOwned::to_owned);
            runtime
                .entry(site_key(&file, line))
                .or_default()
                .push(RuntimeSite {
                    path: file,
                    id,
                    cluster_key_full,
                    attacker_reachable: attacker_reachable_of(&raw),
                });
        }
    }

    if runtime.is_empty() || statics.is_empty() {
        return ConfirmStats::default();
    }

    let mut stats = ConfirmStats::default();
    for finding_json in statics {
        let Some(mut raw) = read_json(&finding_json) else {
            continue;
        };
        if raw.get("confirmation").and_then(Value::as_str) == Some("fuzz_confirmed") {
            continue; // idempotent: a re-run does not double-count.
        }
        let record =
            actionability::existing_actionability_or_backfill(mode, &raw, Some(&finding_json));
        let Some((file, line)) = sink_site(&record) else {
            continue;
        };
        let Some(sites) = runtime.get(&site_key(&file, line)) else {
            continue;
        };
        // Guard basename collisions: when both paths resolve on disk, require the
        // canonical paths to agree so `src/a/x.c:8` is not confirmed by a crash in
        // `src/b/x.c:8`.
        let confirming: Vec<&RuntimeSite> = sites
            .iter()
            .filter(|s| paths_compatible(&s.path, &file))
            .collect();
        if confirming.is_empty() {
            continue;
        }

        upgrade_to_confirmed(&mut raw, &confirming, &record);
        if let Ok(bytes) = serde_json::to_vec_pretty(&raw) {
            if std::fs::write(&finding_json, bytes).is_ok() {
                stats.confirmed += 1;
            }
        }
    }
    stats
}

/// Count static findings already marked `fuzz_confirmed` on disk (used by the
/// report to fold a `fuzz_confirmed` tally into the run summary without threading
/// the join's return value through the whole report path — so `--resume` reloads
/// see the same number).
pub fn count_fuzz_confirmed(work: &Path) -> usize {
    let findings_dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| read_json(&entry.path().join("finding.json")))
        .filter(|raw| raw.get("confirmation").and_then(Value::as_str) == Some("fuzz_confirmed"))
        .count()
}

/// A fuzzed candidate's source site + whether its input channel is attacker-
/// reachable, keyed by basename + the function's start line. Built from the
/// attempt results by the CLI (which owns the candidates' reachability signal).
pub struct ReachabilitySite {
    /// Lowercased basename of the candidate's source file.
    pub basename: String,
    /// The candidate function's start line.
    pub start_line: u64,
    /// `true` when fuzzing PROVED the fuzzed entry is not attacker-controlled
    /// (`reachability_unproven` / `output_serializer`); `false` when it is
    /// attacker-reachable. Sites with an unassessed signal are simply not passed.
    pub non_attacker_reachable: bool,
}

/// Reachability-based DOWNGRADE (#484 / #486 Phase 2 — the mirror of the upgrade
/// join). A static finding a fuzz hit reached is upgraded; one that sits inside a
/// function fuzzing PROVED is not attacker-reachable is demoted to `lab_only`. For
/// each still-`static` finding, find its enclosing fuzzed candidate (nearest
/// function start ≤ the finding's line, same file); if that candidate is proven
/// non-attacker-reachable, stamp `input_reachability` and write a `lab_only`
/// verdict so the report deprioritizes it (the finding is not hidden — it is
/// triaged). Returns how many were demoted.
///
/// Conservative: only demotes when there IS positive non-reachability evidence for
/// the enclosing function. Absence of a fuzzed candidate leaves the finding as-is.
pub fn downgrade_unreachable_static_findings(
    work: &Path,
    sites: &[ReachabilitySite],
    mode: RunMode,
) -> usize {
    if sites.is_empty() {
        return 0;
    }
    let findings_dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut demoted = 0usize;
    for entry in entries.flatten() {
        let finding_json = entry.path().join("finding.json");
        let Some(mut raw) = read_json(&finding_json) else {
            continue;
        };
        // Only un-confirmed static findings are candidates for a downgrade (a
        // fuzz-confirmed one already carries a reachability-aware verdict).
        if !is_static_finding(&raw)
            || raw.get("confirmation").and_then(Value::as_str) != Some("static")
        {
            continue;
        }
        let Some((basename, line)) = static_finding_site(&raw) else {
            continue;
        };
        // Nearest enclosing fuzzed candidate in the same file (max start ≤ line).
        let enclosing = sites
            .iter()
            .filter(|s| s.basename == basename && s.start_line <= line)
            .max_by_key(|s| s.start_line);
        let Some(site) = enclosing else {
            continue;
        };
        if !site.non_attacker_reachable {
            continue;
        }
        if downgrade_to_lab_only(&mut raw, &finding_json, mode) {
            demoted += 1;
        }
    }
    demoted
}

/// Negative fuzz-confirmation (the symmetric half of the join): mark a still-`static`
/// finding as `fuzz_exercised` when the fuzzer PROVABLY executed its exact line
/// (recorded in a `covered-lines.txt` sidecar by the interpreted-lane tracers) yet
/// the whole campaign produced no crash / oracle hit there. This is POSITIVE evidence
/// — the line was run, not merely un-hit — so it is honest triage signal (weak
/// evidence of a false positive), distinct from the silence the join never downgrades
/// on. Confidence is lowered to `low`; the finding is NOT hidden or proven-safe.
/// Only fires where a covered-lines sidecar exists (Python/Perl today).
pub fn mark_fuzz_exercised_findings(work: &Path, mode: RunMode) -> usize {
    let covered = load_covered_lines(work);
    if covered.is_empty() {
        return 0;
    }
    let findings_dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut marked = 0usize;
    for entry in entries.flatten() {
        let finding_json = entry.path().join("finding.json");
        let Some(mut raw) = read_json(&finding_json) else {
            continue;
        };
        if !is_static_finding(&raw)
            || raw.get("confirmation").and_then(Value::as_str) != Some("static")
        {
            continue;
        }
        let Some((basename, line)) = static_finding_site(&raw) else {
            continue;
        };
        if !covered.contains(&(basename, line)) {
            continue;
        }
        if mark_exercised(&mut raw, &finding_json, mode) {
            marked += 1;
        }
    }
    marked
}

/// Union of every `<work>/harnesses/*/covered-lines.txt` sidecar into a set of
/// (lowercased basename, line) the fuzzer executed. Each line is `<path>:<line>`.
fn load_covered_lines(work: &Path) -> std::collections::BTreeSet<(String, u64)> {
    let mut out = std::collections::BTreeSet::new();
    let Ok(harnesses) = std::fs::read_dir(work.join("harnesses")) else {
        return out;
    };
    for harness in harnesses.flatten() {
        let Ok(text) = std::fs::read_to_string(harness.path().join("covered-lines.txt")) else {
            continue;
        };
        for entry in text.lines() {
            let Some((path, line)) = entry.rsplit_once(':') else {
                continue;
            };
            let Ok(line) = line.trim().parse::<u64>() else {
                continue;
            };
            if let Some(basename) = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_ascii_lowercase())
            {
                out.insert((basename, line));
            }
        }
    }
    out
}

/// Stamp a static finding as `fuzz_exercised` (executed, survived) with low
/// confidence — honest triage signal, kept as a finding.
fn mark_exercised(raw: &mut Value, finding_json: &Path, mode: RunMode) -> bool {
    let mut record =
        actionability::existing_actionability_or_backfill(mode, raw, Some(finding_json));
    record.confidence = ActionabilityConfidence::Low;
    let Some(obj) = raw.as_object_mut() else {
        return false;
    };
    obj.insert("confirmation".to_owned(), json!("fuzz_exercised"));
    obj.insert(
        "fuzz_exercised_note".to_owned(),
        json!("the fuzzer executed this line without a crash or oracle hit"),
    );
    if let Ok(value) = serde_json::to_value(&record) {
        obj.insert("actionability".to_owned(), value);
    }
    match serde_json::to_vec_pretty(raw) {
        Ok(bytes) => std::fs::write(finding_json, bytes).is_ok(),
        Err(_) => false,
    }
}

/// The set of lowercased basenames of source files that carry a static finding —
/// the target files for directed fuzzing (fuzz these candidates first so, under a
/// time/campaign cap, a flagged sink gets fuzzed and fuzz-confirmed before the
/// budget runs out). Read from the `F-STATIC-*` finding sidecars on disk.
pub fn static_finding_files(work: &Path) -> std::collections::BTreeSet<String> {
    let mut files = std::collections::BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(work.join("findings")) else {
        return files;
    };
    for entry in entries.flatten() {
        let Some(raw) = read_json(&entry.path().join("finding.json")) else {
            continue;
        };
        if !is_static_finding(&raw) {
            continue;
        }
        if let Some((basename, _line)) = static_finding_site(&raw) {
            files.insert(basename);
        }
    }
    files
}

/// The (lowercased basename, line) a static finding flags, from its
/// `target.source_path` + `target.line`.
fn static_finding_site(raw: &Value) -> Option<(String, u64)> {
    let target = raw.get("target")?;
    let path = target.get("source_path").and_then(Value::as_str)?;
    let line = target.get("line").and_then(Value::as_u64)?;
    let basename = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())?
        .to_ascii_lowercase();
    Some((basename, line))
}

/// Stamp `input_reachability` and persist a `lab_only` verdict on a static finding
/// (full valid record, like the upgrade path, so the demotion survives the loader).
fn downgrade_to_lab_only(raw: &mut Value, finding_json: &Path, mode: RunMode) -> bool {
    let record = actionability::existing_actionability_or_backfill(mode, raw, Some(finding_json));
    let Some(obj) = raw.as_object_mut() else {
        return false;
    };
    obj.insert(
        "input_reachability".to_owned(),
        json!("reachability_unproven"),
    );
    let mut demoted = record;
    demoted.verdict = Verdict::LabOnly;
    if let Ok(value) = serde_json::to_value(&demoted) {
        obj.insert("actionability".to_owned(), value);
    }
    match serde_json::to_vec_pretty(raw) {
        Ok(bytes) => std::fs::write(finding_json, bytes).is_ok(),
        Err(_) => false,
    }
}

/// In-place upgrade of a matched static finding:
/// * `confirmation: "fuzz_confirmed"` + the confirming runtime finding ids;
/// * CLUSTER it with the confirming runtime finding (adopt its `cluster_key_full`)
///   so the report collapses the two into ONE issue row, not a lonely static row
///   beside the crash that proves it;
/// * boost confidence to `high`, and set the verdict from reachability — a site
///   the fuzzer reached ONLY through proven non-attacker-reachable entries is
///   `lab_only` (confirmed in the lab, attacker-reachability unproven), otherwise
///   `likely_reachable`.
///
/// Writing the FULL backfilled record (not a partial patch) is deliberate — a
/// static finding's on-disk `actionability` block is a stub that fails to
/// deserialize, so the boost only survives the report loader if we persist a
/// complete, valid record here.
fn upgrade_to_confirmed(
    raw: &mut Value,
    confirming: &[&RuntimeSite],
    record: &ActionabilityRecord,
) {
    let Some(obj) = raw.as_object_mut() else {
        return;
    };
    let ids: Vec<&str> = confirming
        .iter()
        .map(|s| s.id.as_str())
        .filter(|id| !id.is_empty())
        .collect();
    obj.insert("confirmation".to_owned(), json!("fuzz_confirmed"));
    obj.insert("confirmed_by".to_owned(), json!(ids));

    // Adopt the confirming crash's cluster so the two collapse to one issue row.
    if let Some(cluster) = confirming.iter().find_map(|s| s.cluster_key_full.clone()) {
        obj.insert("cluster_key_full".to_owned(), json!(cluster.clone()));
        obj.insert("cluster_key".to_owned(), json!(cluster));
    }

    // Honest downgrade: only `likely_reachable` when at least one confirming entry
    // is attacker-reachable or unassessed. If EVERY confirming entry proved the
    // fuzzed channel is not attacker-controlled, the defect is real but lab-only.
    let attacker_reachable = confirming
        .iter()
        .any(|s| s.attacker_reachable != Some(false));
    let mut boosted = record.clone();
    boosted.verdict = if attacker_reachable {
        Verdict::LikelyReachable
    } else {
        Verdict::LabOnly
    };
    boosted.confidence = ActionabilityConfidence::High;
    if let Ok(value) = serde_json::to_value(&boosted) {
        obj.insert("actionability".to_owned(), value);
    }
}

/// A static-scan / report-only finding carries `classification: "static_scan"`.
fn is_static_finding(raw: &Value) -> bool {
    raw.get("classification").and_then(Value::as_str) == Some("static_scan")
}

/// Whether the fuzzed entry that produced a runtime finding is attacker-reachable,
/// read from the `input_reachability` label the auto pipeline stamps: `Some(true)`
/// attacker-reachable, `Some(false)` proven not (internal helper / serializer),
/// `None` not assessed (Ada / legacy — never downgraded on this alone).
fn attacker_reachable_of(raw: &Value) -> Option<bool> {
    let label = raw
        .get("input_reachability")
        .and_then(Value::as_str)
        .or_else(|| {
            raw.pointer("/target/input_reachability")
                .and_then(Value::as_str)
        })?;
    match label {
        "attacker_reachable" => Some(true),
        "reachability_unproven" | "output_serializer" => Some(false),
        _ => None,
    }
}

/// The (file, line) a finding's sink resolves to, when both are present.
fn sink_site(record: &ActionabilityRecord) -> Option<(String, u64)> {
    let sink = record.sink.as_ref()?;
    Some((sink.file.clone()?, sink.line?))
}

/// Join key: lowercased basename + line. Basename (not full path) so a relative
/// static path and an absolute runtime path still meet; the canonical-path guard
/// in the caller rejects genuine collisions.
fn site_key(file: &str, line: u64) -> (String, u64) {
    let base = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file)
        .to_ascii_lowercase();
    (base, line)
}

/// Whether two path strings are compatible: identical once canonicalized, or —
/// when either cannot be resolved on disk — accepted (the basename already
/// matched, and we prefer a confirmation over a miss for a relocated tree).
fn paths_compatible(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => true,
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_finding(dir: &Path, id: &str, body: Value) {
        let d = dir.join("findings").join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("finding.json"),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    fn read_finding(dir: &Path, id: &str) -> Value {
        let p = dir.join("findings").join(id).join("finding.json");
        serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("gf-confirm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Negative confirmation: a static finding whose exact line a covered-lines
    /// sidecar proves the fuzzer executed is marked `fuzz_exercised`; one on an
    /// un-covered line stays `static`.
    #[test]
    fn covered_line_is_marked_fuzz_exercised_uncovered_stays_static() {
        let work = tmp("exercised");
        let harness = work.join("harnesses").join("H-P0001");
        std::fs::create_dir_all(&harness).unwrap();
        // The tracer executed mod.py:7 (the finding's line) but not line 99.
        std::fs::write(
            harness.join("covered-lines.txt"),
            "/proj/mod.py:4\n/proj/mod.py:7\n",
        )
        .unwrap();
        write_finding(
            &work,
            "F-STATIC-0000",
            json!({
                "id": "F-STATIC-0000", "rule_id": "GF-422", "confirmation": "static",
                "classification": "static_scan", "report_only": true,
                "target": { "source_path": "/proj/mod.py", "line": 7 }
            }),
        );
        write_finding(
            &work,
            "F-STATIC-0001",
            json!({
                "id": "F-STATIC-0001", "rule_id": "GF-422", "confirmation": "static",
                "classification": "static_scan", "report_only": true,
                "target": { "source_path": "/proj/mod.py", "line": 99 }
            }),
        );

        let n = mark_fuzz_exercised_findings(&work, RunMode::Reporting);
        assert_eq!(n, 1, "only the covered-line finding is marked");
        assert_eq!(
            read_finding(&work, "F-STATIC-0000")["confirmation"],
            "fuzz_exercised"
        );
        assert_eq!(
            read_finding(&work, "F-STATIC-0001")["confirmation"],
            "static",
            "an un-covered line is never downgraded (no silence penalty)"
        );
    }

    /// A static finding whose flagged line matches a fuzz crash sink is upgraded
    /// to `fuzz_confirmed`; a static finding at an unreached line stays `static`.
    #[test]
    fn matching_site_is_confirmed_unmatched_stays_static() {
        let work = tmp("match");
        // Runtime fuzz crash whose sink resolves to cmd.c:8.
        write_finding(
            &work,
            "F-0000-0",
            json!({
                "id": "F-0000-0",
                "classification": "unhandled",
                "exception": { "name": "SIGSEGV", "stack": [
                    { "function": "handle_request", "file": "/proj/src/cmd.c", "line": 8 }
                ]},
            }),
        );
        // Static finding at the SAME site -> should confirm.
        write_finding(
            &work,
            "F-STATIC-0000",
            static_json("F-STATIC-0000", "/proj/src/cmd.c", 8),
        );
        // Static finding at a DIFFERENT line -> should stay static.
        write_finding(
            &work,
            "F-STATIC-0001",
            static_json("F-STATIC-0001", "/proj/src/cmd.c", 42),
        );

        let stats = confirm_static_findings(&work, RunMode::Reporting);
        assert_eq!(stats.confirmed, 1);

        let hit = read_finding(&work, "F-STATIC-0000");
        assert_eq!(hit["confirmation"], "fuzz_confirmed");
        assert_eq!(hit["confirmed_by"][0], "F-0000-0");
        assert_eq!(hit["actionability"]["confidence"], "high");
        assert_eq!(hit["actionability"]["verdict"], "likely_reachable");

        let miss = read_finding(&work, "F-STATIC-0001");
        assert_eq!(miss["confirmation"], "static");
        assert_eq!(count_fuzz_confirmed(&work), 1);
    }

    /// Oracle findings (crash-free, source-evidence sink) also confirm.
    #[test]
    fn oracle_hit_confirms_matching_static() {
        let work = tmp("oracle");
        write_finding(
            &work,
            "F-0000-1",
            json!({
                "id": "F-0000-1",
                "classification": "oracle",
                "oracle": { "evidence": [
                    { "key": "source", "value": "/proj/src/exec.c:15:run" }
                ]},
            }),
        );
        write_finding(
            &work,
            "F-STATIC-0100",
            static_json("F-STATIC-0100", "/proj/src/exec.c", 15),
        );
        let stats = confirm_static_findings(&work, RunMode::Reporting);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(
            read_finding(&work, "F-STATIC-0100")["confirmation"],
            "fuzz_confirmed"
        );
    }

    /// Re-running the join does not re-confirm (idempotent) — the count reflects
    /// only newly-upgraded findings.
    #[test]
    fn confirmation_is_idempotent() {
        let work = tmp("idem");
        write_finding(
            &work,
            "F-0000-2",
            json!({
                "id": "F-0000-2",
                "classification": "unhandled",
                "exception": { "name": "SIGABRT", "stack": [
                    { "function": "parse", "file": "/p/x.c", "line": 3 }
                ]},
            }),
        );
        write_finding(
            &work,
            "F-STATIC-0200",
            static_json("F-STATIC-0200", "/p/x.c", 3),
        );
        assert_eq!(
            confirm_static_findings(&work, RunMode::Reporting).confirmed,
            1
        );
        assert_eq!(
            confirm_static_findings(&work, RunMode::Reporting).confirmed,
            0
        );
        assert_eq!(count_fuzz_confirmed(&work), 1);
    }

    /// No runtime findings at all -> nothing to confirm, static findings untouched.
    #[test]
    fn no_runtime_findings_is_noop() {
        let work = tmp("noop");
        write_finding(
            &work,
            "F-STATIC-0300",
            static_json("F-STATIC-0300", "/p/y.c", 9),
        );
        assert_eq!(
            confirm_static_findings(&work, RunMode::Reporting).confirmed,
            0
        );
        assert_eq!(
            read_finding(&work, "F-STATIC-0300")["confirmation"],
            "static"
        );
    }

    /// Reachability downgrade: a static finding inside a function fuzzing proved is
    /// NOT attacker-reachable is demoted to `lab_only`; one in an attacker-reachable
    /// function is left alone.
    #[test]
    fn unreachable_static_finding_is_demoted_to_lab_only() {
        let work = tmp("downgrade");
        // Finding at parse.c:20, enclosed by a function starting at line 15.
        write_finding(
            &work,
            "F-STATIC-0600",
            static_json("F-STATIC-0600", "/proj/parse.c", 20),
        );
        // Finding at parse.c:60, enclosed by an attacker-reachable function at 55.
        write_finding(
            &work,
            "F-STATIC-0601",
            static_json("F-STATIC-0601", "/proj/parse.c", 60),
        );

        let sites = vec![
            ReachabilitySite {
                basename: "parse.c".to_owned(),
                start_line: 15,
                non_attacker_reachable: true,
            },
            ReachabilitySite {
                basename: "parse.c".to_owned(),
                start_line: 55,
                non_attacker_reachable: false,
            },
        ];
        let demoted = downgrade_unreachable_static_findings(&work, &sites, RunMode::Reporting);
        assert_eq!(demoted, 1);

        let unreachable = read_finding(&work, "F-STATIC-0600");
        assert_eq!(unreachable["input_reachability"], "reachability_unproven");
        assert_eq!(unreachable["actionability"]["verdict"], "lab_only");

        // The attacker-reachable one keeps its default verdict, no stamp.
        let reachable = read_finding(&work, "F-STATIC-0601");
        assert!(reachable.get("input_reachability").is_none());
        assert_ne!(reachable["actionability"]["verdict"], "lab_only");
    }

    /// A confirmed static finding adopts the confirming crash's cluster so the
    /// two collapse to ONE issue row instead of a lonely static row.
    #[test]
    fn confirmed_static_adopts_runtime_cluster() {
        let work = tmp("cluster");
        write_finding(
            &work,
            "F-0000-3",
            json!({
                "id": "F-0000-3",
                "classification": "unhandled",
                "cluster_key_full": "deadbeefcluster",
                "exception": { "name": "SIGSEGV", "stack": [
                    { "function": "copy", "file": "/p/z.c", "line": 5 }
                ]},
            }),
        );
        write_finding(
            &work,
            "F-STATIC-0400",
            static_json("F-STATIC-0400", "/p/z.c", 5),
        );
        assert_eq!(
            confirm_static_findings(&work, RunMode::Reporting).confirmed,
            1
        );
        let hit = read_finding(&work, "F-STATIC-0400");
        assert_eq!(hit["cluster_key_full"], "deadbeefcluster");
        assert_eq!(hit["cluster_key"], "deadbeefcluster");
    }

    /// A site the fuzzer reached ONLY through a proven non-attacker-reachable entry
    /// is confirmed but capped to `lab_only`, not `likely_reachable` — an honest
    /// downgrade (the defect is real in the lab, attacker-reachability unproven).
    #[test]
    fn confirmed_but_non_attacker_reachable_is_lab_only() {
        let work = tmp("labonly");
        write_finding(
            &work,
            "F-0000-4",
            json!({
                "id": "F-0000-4",
                "classification": "unhandled",
                "input_reachability": "output_serializer",
                "exception": { "name": "SIGSEGV", "stack": [
                    { "function": "dump", "file": "/p/w.c", "line": 11 }
                ]},
            }),
        );
        write_finding(
            &work,
            "F-STATIC-0500",
            static_json("F-STATIC-0500", "/p/w.c", 11),
        );
        assert_eq!(
            confirm_static_findings(&work, RunMode::Reporting).confirmed,
            1
        );
        let hit = read_finding(&work, "F-STATIC-0500");
        assert_eq!(hit["confirmation"], "fuzz_confirmed");
        assert_eq!(hit["actionability"]["verdict"], "lab_only");
    }

    /// The static-finding record shape emitted by `report_only::static_finding_record`.
    fn static_json(id: &str, path: &str, line: u64) -> Value {
        json!({
            "id": id,
            "rule_id": "GF-420",
            "classification": "static_scan",
            "severity": "high",
            "report_only": true,
            "confirmation": "static",
            "harness_id": "static-scan",
            "target": {
                "name": "x",
                "source_path": path,
                "line": line,
                "location": { "path": path, "line": line },
            },
            "oracle": { "evidence": [ { "key": "source", "value": format!("{path}:{line}") } ] },
            "exception": { "message": "dynamic code execution" },
            "actionability": { "cwe": ["CWE-94"], "verdict": "static_only", "confidence": "medium" },
        })
    }
}
