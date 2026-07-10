// SPDX-License-Identifier: Apache-2.0

//! Build-recovery provenance — is a crash a REAL defect or a STUB ARTIFACT?
//!
//! When `auto` fuzzes a tree with no working build, it stitches one together by
//! injecting weak stubs for every undefined dependency (see `auto/repair.rs` →
//! `auto_stubs.c`). Those stubs fabricate return values — `NULL`, `0` — that the
//! real dependency would not. A crash the campaign found might therefore be an
//! ARTIFACT of a fabricated value (a NULL the target dereferenced only because the
//! stub returned NULL) rather than a genuine defect in the target code.
//!
//! This module distinguishes the two, and it is a govfuzz differentiator: no other
//! fuzzer stitches builds this way, so none has to — or can — attribute a crash to
//! its own scaffolding. For each C harness that (a) injected ≥1 value-returning
//! stub and (b) produced a reproducible crash, it rebuilds a *poisoned* variant in
//! which every value stub records its name and `_Exit`s the instant it is called
//! (`make prov`, driven by `$(AUTO_PROV_SOURCES)`), then replays the crash's
//! minimized input through it:
//!
//! * a poisoned stub fired before the crash  ⇒ the crash needed a fabricated value
//!   ⇒ **stub_artifact** — demoted to `lab_only` (confirm against the real
//!   dependency), naming the stub(s) responsible;
//! * the original sanitizer crash reproduced with NO stub on its path ⇒ the crash
//!   is provably independent of the scaffolding ⇒ **real_defect** — confidence
//!   raised to `high`.
//!
//! The asymmetry is deliberate and honest: `real_defect` is a strong, false-
//! positive-free certificate (no stub ran before the fault), while `stub_artifact`
//! is the conservative, safe direction (a stitched-build crash that runs through
//! fabricated code is flagged for confirmation, never silently trusted). Only
//! value-returning stubs are poisoned; a `void` stub cannot fabricate crash data,
//! so its presence never demotes a downstream real crash.
//!
//! Best-effort and non-fatal: a harness with no stubs, a poison build that fails to
//! link (e.g. the real build also linked sibling TUs this reconstruction lacks), or
//! a min input that no longer reproduces all skip cleanly, leaving the finding as-is.

use actionability::{ActionabilityConfidence, RunMode, Verdict};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

/// Outcome of the provenance pass, folded into the run summary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceStats {
    /// Crashes proven independent of every injected stub (confidence raised).
    pub real_defects: usize,
    /// Crashes attributed to a fabricated stub value (demoted to `lab_only`).
    pub stub_artifacts: usize,
}

impl ProvenanceStats {
    pub fn total(&self) -> usize {
        self.real_defects + self.stub_artifacts
    }
}

/// The distinct exit code a poisoned stub uses so the replay can tell "a stub
/// fired" apart from the original sanitizer crash (which prints a report and dies
/// by signal / the sanitizer's own exit code).
const STUB_FIRED_EXIT: i32 = 111;

/// Run the provenance pass over every C harness in `work_dir`. Returns the tally of
/// reclassified findings.
pub fn run_stub_provenance(work_dir: &Path, mode: RunMode) -> ProvenanceStats {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return ProvenanceStats::default();
    };
    let mut stats = ProvenanceStats::default();
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        stats = stats.add(provenance_one(work_dir, &hdir, harness_id, mode));
    }
    stats
}

impl ProvenanceStats {
    fn add(self, other: ProvenanceStats) -> ProvenanceStats {
        ProvenanceStats {
            real_defects: self.real_defects + other.real_defects,
            stub_artifacts: self.stub_artifacts + other.stub_artifacts,
        }
    }
}

/// The verdict of replaying one crash through the poisoned build.
#[derive(Debug, PartialEq, Eq)]
enum Provenance {
    /// A value stub fired before the crash — the crash needs a fabricated value.
    StubArtifact(Vec<String>),
    /// The original sanitizer crash reproduced with no stub on its path.
    RealDefect,
    /// Neither (min input no longer reproduces on the poison build) — leave as-is.
    Inconclusive,
}

fn provenance_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    mode: RunMode,
) -> ProvenanceStats {
    let mut stats = ProvenanceStats::default();
    if !hdir.join("Makefile").is_file() {
        return stats;
    }
    // Only the C lane's weak-stub file is handled today (C++ stub poisoning is a
    // follow-up). No stub file -> nothing was fabricated -> nothing to attribute.
    let stub_src = hdir.join("repairs").join("auto_stubs.c");
    let Ok(stub_text) = std::fs::read_to_string(&stub_src) else {
        return stats;
    };
    let Some((poisoned, poisoned_names)) = poison_stub_source(&stub_text) else {
        return stats; // only void stubs (or none) -> no value to fabricate.
    };

    // Which findings belong to this harness AND carry a reproducible min input?
    let findings = harness_findings_with_input(work_dir, harness_id);
    if findings.is_empty() {
        return stats;
    }

    // Materialize the poisoned stub and build the provenance variant.
    let prov_src = hdir.join("repairs").join("auto_stubs_prov.c");
    if std::fs::write(&prov_src, poisoned).is_err() {
        return stats;
    }
    if !build_prov(hdir, &prov_src) {
        return stats; // couldn't reconstruct the build -> stay honest, skip.
    }
    let prov_bin = hdir.join("main_prov");
    let real_bin = hdir.join("main");
    if !prov_bin.is_file() || !real_bin.is_file() {
        return stats;
    }

    for (finding_json, input) in findings {
        // Require the crash to still reproduce on the real ASan build (a fresh
        // process — the fork server can mask per-process crashes, #416). If it does
        // not, provenance is meaningless; skip.
        if !reproduces_crash(&real_bin, &input) {
            continue;
        }
        let prov = classify(&prov_bin, &input, &poisoned_names);
        match prov {
            Provenance::StubArtifact(stubs) => {
                if reclassify(&finding_json, mode, Verdict::LabOnly, &stubs) {
                    stats.stub_artifacts += 1;
                }
            }
            Provenance::RealDefect => {
                if certify_real(&finding_json, mode) {
                    stats.real_defects += 1;
                }
            }
            Provenance::Inconclusive => {}
        }
    }
    stats
}

/// Replay `input` through the poisoned binary and read out the provenance verdict.
fn classify(prov_bin: &Path, input: &Path, poisoned_names: &[String]) -> Provenance {
    let trace = prov_bin.with_file_name(format!(
        "stub_trace_{}",
        input.file_name().and_then(|n| n.to_str()).unwrap_or("x")
    ));
    let _ = std::fs::remove_file(&trace);
    let Ok(out) = replay_command(prov_bin)
        .arg(input)
        .env("GOVFUZZ_STUB_TRACE", &trace)
        // A poisoned stub records + exits cleanly; keep the sanitizer aborting so a
        // genuine crash is still an unambiguous sanitizer report on stderr.
        // `symbolize=0` avoids the coverage-instrumented binary hanging in the ASan
        // crash symbolizer during this post-hoc replay.
        .env("ASAN_OPTIONS", "abort_on_error=1:symbolize=0")
        .output()
    else {
        return Provenance::Inconclusive;
    };
    let fired = read_fired_stubs(&trace, poisoned_names);
    let _ = std::fs::remove_file(&trace);
    if !fired.is_empty() || out.status.code() == Some(STUB_FIRED_EXIT) {
        return Provenance::StubArtifact(fired);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if is_sanitizer_crash(&stderr, &out.status) {
        return Provenance::RealDefect;
    }
    Provenance::Inconclusive
}

/// Read the poisoned stubs that fired, from the trace sidecar (one name per line),
/// keeping only names we actually poisoned (defensive against a stray file).
fn read_fired_stubs(trace: &Path, poisoned_names: &[String]) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(trace) else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let name = line.trim();
        if !name.is_empty() && poisoned_names.iter().any(|n| n == name) {
            seen.insert(name.to_owned());
        }
    }
    seen.into_iter().collect()
}

/// Whether a replay's stderr/exit shows an original sanitizer crash (not the
/// poisoned-stub clean exit).
fn is_sanitizer_crash(stderr: &str, status: &std::process::ExitStatus) -> bool {
    let sanitizer = stderr.contains("AddressSanitizer")
        || stderr.contains("UndefinedBehaviorSanitizer")
        || stderr.contains("runtime error:")
        || stderr.contains("SUMMARY: ");
    // A crash also shows up as death-by-signal or the sanitizer's non-zero exit.
    let died = !status.success() && status.code() != Some(STUB_FIRED_EXIT);
    sanitizer || (died && status.code().is_none())
}

/// Does the real ASan build crash on this input in a fresh process?
fn reproduces_crash(bin: &Path, input: &Path) -> bool {
    let Ok(out) = replay_command(bin)
        .arg(input)
        .env("ASAN_OPTIONS", "abort_on_error=1:symbolize=0")
        .output()
    else {
        return false;
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    is_sanitizer_crash(&stderr, &out.status)
}

/// Build a replay command wrapped in `timeout` when available so a pathological
/// input can never wedge the provenance pass.
fn replay_command(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut cmd = Command::new("timeout");
        cmd.arg("-s").arg("KILL").arg("10").arg(bin);
        cmd
    } else {
        Command::new(bin)
    }
}

/// Build the `main_prov` provenance variant: `make prov` with the poisoned stub as
/// the sole extra source. A link failure (the real build linked sibling TUs this
/// reconstruction lacks) returns false and the harness is skipped.
fn build_prov(hdir: &Path, prov_src: &Path) -> bool {
    // Match the auto build's default C/C++ compiler when the caller's env doesn't
    // already pin one (the generated Makefile's CC default is plain `clang`, which
    // is correct here — the ASan flags are baked into CFLAGS).
    let mut cmd = Command::new("make");
    cmd.arg("prov").current_dir(hdir);
    cmd.env("AUTO_PROV_SOURCES", prov_src);
    if std::env::var_os("CC").is_none() {
        cmd.env("CC", "clang");
    }
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

/// The `(finding.json, min-input)` pairs for a harness's reproducible crash
/// findings — runtime (`unhandled`) findings that carry a `testcase.bin`.
fn harness_findings_with_input(
    work_dir: &Path,
    harness_id: &str,
) -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work_dir.join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let finding_json = dir.join("finding.json");
        let Some(raw) = read_json(&finding_json) else {
            continue;
        };
        if raw.get("classification").and_then(Value::as_str) != Some("unhandled") {
            continue; // provenance is about runtime crashes, not static/oracle rows.
        }
        if raw.get("harness_id").and_then(Value::as_str) != Some(harness_id) {
            continue;
        }
        // Idempotent: a re-run does not re-attribute a finding already labeled.
        if raw.get("provenance").is_some() {
            continue;
        }
        let input = dir.join("testcase.bin");
        if input.is_file() {
            out.push((finding_json, input));
        }
    }
    out
}

/// Rewrite a runtime crash finding as a `stub_artifact`: demote the verdict (to
/// `lab_only`), lower confidence, and record which fabricated stub(s) it needed.
fn reclassify(finding_json: &Path, mode: RunMode, verdict: Verdict, stubs: &[String]) -> bool {
    let Some(mut raw) = read_json(finding_json) else {
        return false;
    };
    let mut record =
        actionability::existing_actionability_or_backfill(mode, &raw, Some(finding_json));
    record.verdict = verdict;
    record.confidence = ActionabilityConfidence::Low;
    let Some(obj) = raw.as_object_mut() else {
        return false;
    };
    obj.insert("provenance".to_owned(), json!("stub_artifact"));
    obj.insert(
        "stub_provenance".to_owned(),
        json!({
            "fired_stubs": stubs,
            "note": "the crash required a value fabricated by an injected build-recovery \
                     stub; confirm against the real dependency before treating it as a defect",
        }),
    );
    if let Ok(value) = serde_json::to_value(&record) {
        obj.insert("actionability".to_owned(), value);
    }
    write_json(finding_json, &raw)
}

/// Rewrite a runtime crash finding as a `real_defect`: raise confidence to `high`
/// (the crash reproduced with every value stub poisoned — none on its path).
fn certify_real(finding_json: &Path, mode: RunMode) -> bool {
    let Some(mut raw) = read_json(finding_json) else {
        return false;
    };
    let mut record =
        actionability::existing_actionability_or_backfill(mode, &raw, Some(finding_json));
    record.confidence = ActionabilityConfidence::High;
    let Some(obj) = raw.as_object_mut() else {
        return false;
    };
    obj.insert("provenance".to_owned(), json!("real_defect"));
    obj.insert(
        "stub_provenance".to_owned(),
        json!({
            "fired_stubs": Vec::<String>::new(),
            "note": "the crash reproduced with every injected value stub poisoned to abort on \
                     call — none was on the crash path, so it is independent of the recovered \
                     build's scaffolding",
        }),
    );
    if let Ok(value) = serde_json::to_value(&record) {
        obj.insert("actionability".to_owned(), value);
    }
    write_json(finding_json, &raw)
}

/// Produce a poisoned copy of a C weak-stub source: every VALUE-returning weak stub
/// gets a `govfuzz__stub_fired("<name>")` call injected as its first statement (the
/// helper records the name and `_Exit`s). `void` stubs are copied unchanged — they
/// fabricate no value, so poisoning them would falsely demote a downstream real
/// crash. Returns `(poisoned_source, poisoned_stub_names)`, or `None` when there is
/// no value stub to poison.
pub fn poison_stub_source(src: &str) -> Option<(String, Vec<String>)> {
    let mut out = String::new();
    let mut poisoned = Vec::new();
    for line in src.lines() {
        if let Some((rt, name)) = parse_weak_stub_open(line) {
            if !is_void_return(&rt) {
                // Inject the marker as the first statement, right after the `{`.
                // The stub's own body follows (unreachable after _Exit, but valid).
                if let Some(idx) = line.rfind('{') {
                    let (head, tail) = line.split_at(idx + 1);
                    out.push_str(head);
                    out.push_str(&format!(" govfuzz__stub_fired(\"{name}\");"));
                    out.push_str(tail);
                    out.push('\n');
                    poisoned.push(name);
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if poisoned.is_empty() {
        return None;
    }
    let prologue = "\
/* govfuzz build-recovery provenance: injected marker for value-returning stubs. */
#include <stdio.h>
#include <stdlib.h>
static void govfuzz__stub_fired(const char *name) {
    const char *p = getenv(\"GOVFUZZ_STUB_TRACE\");
    if (p) { FILE *f = fopen(p, \"a\"); if (f) { fputs(name, f); fputc('\\n', f); fclose(f); } }
    _Exit(111);
}
";
    Some((format!("{prologue}{out}"), poisoned))
}

/// Parse a weak-stub opening line `__attribute__((weak)) <rt> <name>(<params>) {`
/// into `(return_type, name)`. Returns `None` for any other line.
fn parse_weak_stub_open(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("__attribute__((weak))")?;
    if !line.trim_end().ends_with('{') {
        return None;
    }
    let paren = rest.find('(')?;
    let before = rest[..paren].trim(); // "<rt...> <name>"
                                       // The name is the last identifier token before `(`; strip a leading `*` that
                                       // binds to the pointer return type (`char * name` -> rt "char *", name "name").
    let name_start = before.rfind(|c: char| c.is_whitespace() || c == '*')? + 1;
    let name = &before[name_start..];
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let rt = before[..name_start].trim();
    Some((rt.to_owned(), name.to_owned()))
}

/// Whether a return type is exactly `void` (a value-less stub). `void *` is a
/// value.
fn is_void_return(rt: &str) -> bool {
    rt.trim() == "void"
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_json(path: &Path, value: &Value) -> bool {
    match serde_json::to_vec_pretty(value) {
        Ok(bytes) => std::fs::write(path, bytes).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUBS: &str = "\
#include <stdbool.h>
#include \"auto_types.h\"

__attribute__((weak)) void audit_log(const char * _gf_p0) {
    return;
}
__attribute__((weak)) char * acquire_scratch(void) {
    return NULL;
}
__attribute__((weak)) int compute_len(const char * _gf_p0) {
    return 0;
}
";

    #[test]
    fn parses_weak_stub_openings() {
        assert_eq!(
            parse_weak_stub_open("__attribute__((weak)) void audit_log(const char * _gf_p0) {"),
            Some(("void".to_owned(), "audit_log".to_owned()))
        );
        assert_eq!(
            parse_weak_stub_open("__attribute__((weak)) char * acquire_scratch(void) {"),
            Some(("char *".to_owned(), "acquire_scratch".to_owned()))
        );
        assert_eq!(
            parse_weak_stub_open("__attribute__((weak)) int compute_len(const char * _gf_p0) {"),
            Some(("int".to_owned(), "compute_len".to_owned()))
        );
        assert_eq!(parse_weak_stub_open("    return NULL;"), None);
        assert_eq!(parse_weak_stub_open("#include <stdbool.h>"), None);
    }

    #[test]
    fn poisons_only_value_stubs() {
        let (poisoned, names) = poison_stub_source(STUBS).unwrap();
        // Value stubs get the marker; the void stub does not.
        assert!(names.contains(&"acquire_scratch".to_owned()));
        assert!(names.contains(&"compute_len".to_owned()));
        assert!(!names.contains(&"audit_log".to_owned()));
        assert!(poisoned.contains("govfuzz__stub_fired(\"acquire_scratch\");"));
        assert!(poisoned.contains("govfuzz__stub_fired(\"compute_len\");"));
        // The void stub's body is untouched (no marker on its line).
        let audit_line = poisoned.lines().find(|l| l.contains("audit_log(")).unwrap();
        assert!(!audit_line.contains("govfuzz__stub_fired"));
        // Helper + headers are prepended, and the original bodies survive.
        assert!(poisoned.contains("static void govfuzz__stub_fired"));
        assert!(poisoned.contains("return NULL;"));
    }

    #[test]
    fn no_value_stub_yields_none() {
        let void_only = "__attribute__((weak)) void f(void) {\n    return;\n}\n";
        assert!(poison_stub_source(void_only).is_none());
    }

    #[test]
    fn void_star_is_a_value() {
        assert!(!is_void_return("void *"));
        assert!(is_void_return("void"));
        assert!(is_void_return(" void "));
    }

    #[test]
    fn stub_artifact_reclassify_demotes_and_names_stub() {
        let dir = std::env::temp_dir().join(format!("gf-prov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fj = dir.join("finding.json");
        write_json(
            &fj,
            &json!({
                "id": "F-0000-x",
                "classification": "unhandled",
                "harness_id": "H-C0001",
                "actionability": { "cwe": ["CWE-476"], "verdict": "likely_reachable", "confidence": "medium" },
            }),
        );
        assert!(reclassify(
            &fj,
            RunMode::Reporting,
            Verdict::LabOnly,
            &["acquire_scratch".to_owned()]
        ));
        let raw = read_json(&fj).unwrap();
        assert_eq!(raw["provenance"], "stub_artifact");
        assert_eq!(raw["stub_provenance"]["fired_stubs"][0], "acquire_scratch");
        assert_eq!(raw["actionability"]["verdict"], "lab_only");
        assert_eq!(raw["actionability"]["confidence"], "low");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_defect_certify_raises_confidence() {
        let dir = std::env::temp_dir().join(format!("gf-prov-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fj = dir.join("finding.json");
        write_json(
            &fj,
            &json!({
                "id": "F-0000-y",
                "classification": "unhandled",
                "harness_id": "H-C0002",
                "actionability": { "cwe": ["CWE-121"], "verdict": "likely_reachable", "confidence": "medium" },
            }),
        );
        assert!(certify_real(&fj, RunMode::Reporting));
        let raw = read_json(&fj).unwrap();
        assert_eq!(raw["provenance"], "real_defect");
        assert_eq!(raw["actionability"]["confidence"], "high");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
