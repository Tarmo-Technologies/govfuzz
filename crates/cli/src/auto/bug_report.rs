// SPDX-License-Identifier: Apache-2.0

//! Self-diagnostics: capture govfuzz's OWN internal failures (panics, codegen
//! defects) while scanning an untrusted tree, and boil them down to a
//! `bug-report.{json,md}` a maintainer can act on.
//!
//! Two guarantees:
//!  1. **Resilience** — a panic while parsing/attempting ONE file is caught at
//!     the per-file / per-target boundary ([`catch`]) so the whole `auto` run no
//!     longer dies on a single malformed input; the target is recorded and the
//!     sweep continues.
//!  2. **Actionable reports** — every caught panic (plus the codegen-artifact
//!     ledger the report already computes) is aggregated, deduplicated, and
//!     written as `<work>/auto/bug-report.json` + `.md`, stamped with the govfuzz
//!     version/commit. `--debug` sets `RUST_BACKTRACE` and captures a backtrace
//!     per panic so the report has enough to fix the bug offline.
//!
//! This is DISTINCT from the dependency manifest (`missing-deps.*`, the user's
//! missing environment) and from findings (bugs in the *scanned* target): the
//! bug report is exclusively govfuzz's OWN defects.

use std::any::Any;
use std::backtrace::Backtrace;
use std::cell::RefCell;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static DEBUG: AtomicBool = AtomicBool::new(false);
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static ISSUES: Mutex<Vec<InternalIssue>> = Mutex::new(Vec::new());
/// The run's `<work>/auto` dir, set once the auto sweep knows it, so an UNCAUGHT
/// panic (one that escaped every per-target/per-file `catch`) can still flush the
/// bug report there before the process aborts — write_reports never runs on abort.
static OUTPUT_DIR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

thread_local! {
    /// The hook writes the panic's location/backtrace here on the panicking
    /// thread; [`catch`] takes it right after `catch_unwind` returns `Err` (same
    /// thread), so it correlates cleanly even under the parallel sweep.
    static LAST_PANIC: RefCell<Option<PanicCapture>> = const { RefCell::new(None) };
}

/// Whether `--debug` was passed (enables backtrace capture + verbose internal
/// logging). Read by other auto modules to gate extra diagnostics.
pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// Record the run's `<work>/auto` dir so the panic hook / a top-level catch can
/// flush a bug report there even if an uncaught panic aborts the run.
pub fn set_output_dir(auto_dir: std::path::PathBuf) {
    *OUTPUT_DIR.lock().unwrap_or_else(|e| e.into_inner()) = Some(auto_dir);
}

/// Flush the current issues to the recorded output dir (best-effort, forcing a
/// write even with zero issues). Returns the `bug-report.md` path if a dir was
/// known. Called from the panic hook when an uncaught panic is aborting the run.
fn flush_report() -> Option<std::path::PathBuf> {
    let dir = OUTPUT_DIR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()?;
    write(&dir, &now_rfc3339(), &[], true);
    Some(dir.join("bug-report.md"))
}

/// Flush the bug report after a top-level `catch_unwind` intercepted an escaping
/// panic (idempotent with the hook's flush). Returns the issue count, or 0 when
/// no output dir was known.
pub fn flush_after_panic() -> usize {
    // Bind the clone to a local so the OUTPUT_DIR guard drops here, before write()
    // takes the ISSUES lock (keeps the two locks strictly non-overlapping).
    let dir = OUTPUT_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match dir {
        Some(dir) => write(&dir, &now_rfc3339(), &[], true),
        None => 0,
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Install the diagnostics panic hook (once) and record `--debug`. Under
/// `--debug` we also set `RUST_BACKTRACE=full` if the user hasn't, so a panic
/// that escapes the per-target boundary still prints a full trace.
pub fn init(debug: bool) {
    DEBUG.store(debug, Ordering::Relaxed);
    if debug && std::env::var_os("RUST_BACKTRACE").is_none() {
        // SAFETY: single-threaded startup, before any worker threads spawn.
        unsafe { std::env::set_var("RUST_BACKTRACE", "full") };
    }
    if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = panic_message(info.payload());
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let backtrace = if DEBUG.load(Ordering::Relaxed) {
            Some(Backtrace::force_capture().to_string())
        } else {
            None
        };
        // Concise live line: the full/default trace is noisy mid-sweep, and the
        // detail lands in the bug report. If a panic ESCAPES the catch boundary
        // (a genuine govfuzz bug outside per-target work), fall back to the
        // default hook so nothing is lost.
        if THREAD_IN_CATCH.with(|c| c.get()) {
            // Caught at a per-target/per-file boundary: hand off to `catch` via the
            // thread-local, and print a concise line (detail goes to the report).
            eprintln!(
                "govfuzz: internal panic{}: {message} (recorded in bug-report.json{})",
                location
                    .as_ref()
                    .map(|l| format!(" at {l}"))
                    .unwrap_or_default(),
                if backtrace.is_some() {
                    ""
                } else {
                    "; rerun with --debug for a backtrace"
                },
            );
            LAST_PANIC.with(|c| {
                *c.borrow_mut() = Some(PanicCapture {
                    message,
                    location,
                    backtrace,
                });
            });
        } else {
            // UNCAUGHT: this panic escaped every catch and is about to abort the
            // run. Record it and FLUSH the bug report to disk NOW (write_reports
            // won't get to run), so `--debug` still yields a file, then let the
            // default hook print the stacktrace.
            record(InternalIssue {
                category: IssueCategory::InternalPanic,
                summary: format!("panic: {message}"),
                context: IssueContext {
                    phase: "uncaught".to_owned(),
                    ..Default::default()
                },
                detail: location,
                backtrace,
                occurrences: 1,
            });
            if let Some(path) = flush_report() {
                eprintln!(
                    "govfuzz: internal panic — bug report written to {}",
                    path.display()
                );
            }
            default_hook(info);
        }
    }));
}

thread_local! {
    static THREAD_IN_CATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f`, catching a panic at this boundary. On success returns `Ok(value)`.
/// On panic, records a deduplicated [`InternalIssue`] tagged with `context` and
/// returns `Err(reason)` — a one-line reason the caller can surface as the
/// target's outcome so the sweep continues instead of aborting.
pub fn catch<T>(context: IssueContext, f: impl FnOnce() -> T) -> Result<T, String> {
    // Save/restore (not just set true/false) so a nested catch can't leave the
    // outer scope marked "not in catch" and mis-route a later panic to the
    // uncaught flush. No nesting occurs today, but this is cheap insurance.
    let prev_in_catch = THREAD_IN_CATCH.with(|c| c.replace(true));
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(f));
    THREAD_IN_CATCH.with(|c| c.set(prev_in_catch));
    match outcome {
        Ok(value) => Ok(value),
        Err(_payload) => {
            let cap = LAST_PANIC
                .with(|c| c.borrow_mut().take())
                .unwrap_or_else(|| PanicCapture {
                    message: "<panic payload not captured>".to_owned(),
                    location: None,
                    backtrace: None,
                });
            let reason = format!(
                "govfuzz internal error (see bug-report.json): {}{}",
                cap.message,
                cap.location
                    .as_ref()
                    .map(|l| format!(" at {l}"))
                    .unwrap_or_default(),
            );
            record(InternalIssue {
                category: IssueCategory::InternalPanic,
                summary: format!("panic: {}", cap.message),
                context,
                detail: cap.location,
                backtrace: cap.backtrace,
                occurrences: 1,
            });
            Err(reason)
        }
    }
}

/// Record an internal issue. Deduplicated by (category, summary) — the
/// TYPE/reason, NOT the file — so one row covers every file that hit it.
pub fn record(issue: InternalIssue) {
    let mut issues = ISSUES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = issues
        .iter_mut()
        .find(|e| e.category == issue.category && e.summary == issue.summary)
    {
        existing.occurrences = existing
            .occurrences
            .saturating_add(issue.occurrences.max(1));
        return;
    }
    issues.push(issue);
}

/// Snapshot of all issues recorded so far (panics + directly-recorded defects).
pub fn snapshot() -> Vec<InternalIssue> {
    ISSUES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}

struct PanicCapture {
    message: String,
    location: Option<String>,
    backtrace: Option<String>,
}

/// Where a govfuzz-internal issue happened, so the maintainer can reproduce it.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IssueContext {
    /// Pipeline phase (`discovery-parse`, `attempt`, …).
    pub phase: String,
    /// Source file being processed (relative to the scan root when known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Target subprogram/function name, when in the per-target phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Source language of the file/target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueCategory {
    /// govfuzz itself panicked while processing an input (highest priority — a bug).
    InternalPanic,
    /// A codegen/parser recovery artifact (a type govfuzz's own emitter left
    /// unresolved) — a defect in govfuzz's harness generation (a bug).
    CodegenDefect,
    /// govfuzz could not build a harness for a target — an unsupported parameter
    /// or return type (a feature gap: a type spelling the decoder can't handle).
    UnsupportedType,
    /// A generated harness would not COMPILE (undefined-in-tree types, link
    /// errors). May be a govfuzz gap or a missing dependency (see missing-deps.txt).
    FailedBuild,
    /// govfuzz could not fuzz the target and fell back to a source-only static
    /// scan (e.g. types from an external SDK/framework not in the tree). The reason
    /// names what was missing.
    ReportOnly,
}

/// One boiled-down govfuzz defect, deduplicated across the run.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InternalIssue {
    pub category: IssueCategory,
    /// One-line human summary (the thing to fix).
    pub summary: String,
    pub context: IssueContext,
    /// Extra diagnostic detail (panic location, compiler tail, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Captured backtrace (only under `--debug`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace: Option<String>,
    /// How many times this same issue was hit (targets/files affected).
    pub occurrences: usize,
}

/// The serialized bug report (`bug-report.json`).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BugReport {
    pub schema_version: u32,
    pub govfuzz_version: String,
    pub govfuzz_commit: String,
    pub generated_at: String,
    /// True iff `--debug` was on (backtraces present).
    pub debug: bool,
    pub issue_count: usize,
    pub issues: Vec<InternalIssue>,
}

/// govfuzz version (git tag/describe) + short commit, stamped at build time
/// (see `build.rs`); the same string `govfuzz --version` prints.
pub fn version() -> &'static str {
    option_env!("GOVFUZZ_VERSION_FULL").unwrap_or(env!("CARGO_PKG_VERSION"))
}
pub fn commit() -> &'static str {
    option_env!("GOVFUZZ_GIT_COMMIT").unwrap_or("unknown")
}

/// Build the bug report from the recorded panics plus `extra` (codegen defects
/// and the per-target outcomes govfuzz couldn't fully fuzz), then write
/// `bug-report.json` + `bug-report.md` under `auto_dir`. When `always` is false a
/// clean run (no issues) writes nothing; when `always` is true (`--debug`) the
/// report is written even with zero issues, as a version-stamped confirmation.
/// Returns the number of distinct issues.
pub fn write(auto_dir: &Path, generated_at: &str, extra: &[InternalIssue], always: bool) -> usize {
    let mut issues = snapshot();
    for issue in extra {
        record_into(&mut issues, issue.clone());
    }
    if issues.is_empty() && !always {
        return 0;
    }
    // Bugs first (panics, then codegen), then feature gaps, then descending
    // occurrences so the most-common issue leads each category.
    issues.sort_by(|a, b| {
        issue_rank(a)
            .cmp(&issue_rank(b))
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.summary.cmp(&b.summary))
    });
    let report = BugReport {
        schema_version: 1,
        govfuzz_version: version().to_owned(),
        govfuzz_commit: commit().to_owned(),
        generated_at: generated_at.to_owned(),
        debug: debug_enabled(),
        issue_count: issues.len(),
        issues,
    };
    let _ = std::fs::create_dir_all(auto_dir);
    if let Ok(json) = serde_json::to_vec_pretty(&report) {
        let _ = std::fs::write(auto_dir.join("bug-report.json"), json);
    }
    let _ = std::fs::write(auto_dir.join("bug-report.md"), render_md(&report));
    report.issue_count
}

fn issue_rank(issue: &InternalIssue) -> u8 {
    match issue.category {
        IssueCategory::InternalPanic => 0,
        IssueCategory::CodegenDefect => 1,
        IssueCategory::UnsupportedType => 2,
        IssueCategory::FailedBuild => 3,
        IssueCategory::ReportOnly => 4,
    }
}

/// Human label + whether it's a govfuzz bug (vs a limitation/gap), per category.
fn category_label(category: IssueCategory) -> &'static str {
    match category {
        IssueCategory::InternalPanic => "PANIC",
        IssueCategory::CodegenDefect => "codegen-bug",
        IssueCategory::UnsupportedType => "unsupported-type",
        IssueCategory::FailedBuild => "failed-build",
        IssueCategory::ReportOnly => "static-only",
    }
}

/// Whether an `unsupported-type` row is a KNOWN, working-as-intended boundary
/// rather than something to report — and, if so, the short parenthetical that
/// explains why. These are the cases where govfuzz correctly SKIPS a parameter
/// (and keeps going): an opaque-handle type whose construction needs runtime
/// lifecycle support (roadmap "Phase C"), and a class the harness can't build
/// because the user's own source exposes no public constructor/factory. Both are
/// expected gaps the user can't file as govfuzz bugs; the second is fixable in
/// the user's own tree (the message says how). Returns `None` for an unsupported
/// type that is NOT a recognized boundary — genuinely worth a report.
fn unsupported_type_boundary_note(summary: &str) -> Option<&'static str> {
    let s = summary.to_ascii_lowercase();
    if s.contains("phase c") || s.contains("needs lifecycle support") {
        return Some(
            "working as intended: an opaque handle/pointer type whose construction needs \
             runtime lifecycle support (roadmap Phase C) — govfuzz skips this parameter and \
             keeps going; not a bug, no need to report",
        );
    }
    if s.contains("no public default constructor")
        || s.contains("no supported public constructor")
        || s.contains("no factory method")
    {
        return Some(
            "working as intended: the class has no public constructor/factory the harness can \
             call — fixable in YOUR source (add a wrapper/factory, as the message says); not a \
             govfuzz bug",
        );
    }
    None
}

/// Dedup a directly-built issue into an existing in-memory list. Deduplicated by
/// (category, summary) — i.e. by the TYPE/reason, NOT by file — so the same
/// unsupported type or panic across many files collapses to ONE row (with an
/// occurrence count), keeping the report short enough to re-type by hand.
fn record_into(issues: &mut Vec<InternalIssue>, issue: InternalIssue) {
    if let Some(existing) = issues
        .iter_mut()
        .find(|e| e.category == issue.category && e.summary == issue.summary)
    {
        existing.occurrences = existing
            .occurrences
            .saturating_add(issue.occurrences.max(1));
        return;
    }
    issues.push(issue);
}

fn render_md(report: &BugReport) -> String {
    let mut out = String::new();
    out.push_str("# govfuzz bug report\n\n");
    out.push_str(&format!(
        "govfuzz {} ({}) — generated {}\n\n",
        report.govfuzz_version, report.govfuzz_commit, report.generated_at
    ));
    out.push_str(
        "What govfuzz could NOT fully handle on your tree — its own bugs (`PANIC`, \
         `codegen-bug`) plus targets it couldn't fuzz (`unsupported-type`, `failed-build`, \
         `static-only`). Deduplicated BY TYPE (one row per unique type/reason, not per \
         file) so it's short enough to re-type. NOT findings in your target, and NOT missing \
         dependencies (see `missing-deps.txt`). Send a row to the maintainer.\n\n",
    );
    if report.issue_count == 0 {
        out.push_str(
            "**No issues: govfuzz built and fuzzed every discovered target cleanly.** \
             (This file was written because `--debug` was set; it confirms the running \
             build.)\n\n",
        );
        return out;
    }
    if !report.debug {
        out.push_str(
            "> Tip: re-run with `--debug` to add a backtrace per panic (pins the exact \
             source line).\n\n",
        );
    }
    let count_of = |c: IssueCategory| report.issues.iter().filter(|i| i.category == c).count();
    out.push_str(&format!(
        "**{} issue(s): {} panic(s), {} codegen-bug(s), {} unsupported-type(s), {} \
         failed-build(s), {} static-only.**\n\n",
        report.issue_count,
        count_of(IssueCategory::InternalPanic),
        count_of(IssueCategory::CodegenDefect),
        count_of(IssueCategory::UnsupportedType),
        count_of(IssueCategory::FailedBuild),
        count_of(IssueCategory::ReportOnly),
    ));
    out.push_str("`xN` = number of targets/files that hit the same type/reason.\n\n");
    // If any row is a recognized working-as-intended boundary, explain the marker
    // ONCE up front so the reader doesn't file those as bugs.
    if report
        .issues
        .iter()
        .any(|i| unsupported_type_boundary_note(&i.summary).is_some())
    {
        out.push_str(
            "> Rows marked **(working as intended)** are KNOWN limitations, not govfuzz bugs — \
             govfuzz skipped that parameter/target on purpose and kept going. You do NOT need to \
             report them.\n\n",
        );
    }
    for (n, issue) in report.issues.iter().enumerate() {
        let kind = category_label(issue.category);
        let occ = if issue.occurrences > 1 {
            format!(" x{}", issue.occurrences)
        } else {
            String::new()
        };
        // One compact line per issue — the type/reason is the actionable bit; the
        // per-file context is dropped (issues are deduped by type, not file).
        out.push_str(&format!("{}. [{kind}{occ}] {}\n", n + 1, issue.summary));
        // Tag a recognized working-as-intended boundary so it isn't mistaken for a
        // bug worth reporting (only `unsupported-type` rows carry these reasons).
        if let Some(note) = unsupported_type_boundary_note(&issue.summary) {
            out.push_str(&format!("   ↳ **(working as intended)** {note}\n"));
        }
        // A panic also carries WHERE in govfuzz it fired (the pin) plus the full
        // backtrace tucked away — you don't need to re-type the backtrace.
        if issue.category == IssueCategory::InternalPanic {
            if let Some(bt) = &issue.backtrace {
                let frames = govfuzz_frames(bt, 3);
                if !frames.is_empty() {
                    out.push_str(&format!("   govfuzz: {}\n", frames.join(" <- ")));
                }
                out.push_str(
                    "\n   <details><summary>full backtrace (no need to re-type)</summary>\n\n```\n",
                );
                out.push_str(bt);
                out.push_str("\n```\n   </details>\n");
            } else if let Some(detail) = &issue.detail {
                out.push_str(&format!(
                    "   panicked at {detail} — rerun with `--debug` for the govfuzz frame\n"
                ));
            }
        }
        out.push('\n');
    }
    out
}

/// The first few GOVFUZZ source frames from a captured backtrace (skipping std,
/// core, and the bug_report hook machinery), so a panic row names WHERE in
/// govfuzz it fired without the user re-typing the whole trace.
fn govfuzz_frames(backtrace: &str, max: usize) -> Vec<String> {
    let mut frames = Vec::new();
    for line in backtrace.lines() {
        if let Some(at) = line.trim().strip_prefix("at ") {
            let path = at.trim_start_matches("./");
            if path.contains("crates/") && !path.contains("bug_report.rs") {
                frames.push(path.to_owned());
                if frames.len() >= max {
                    break;
                }
            }
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that read/clear the process-global issue list so they
    /// don't observe each other's (or `catch()`'s) recorded panics.
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_issues() {
        ISSUES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    #[test]
    fn catch_records_a_panic_and_returns_err_reason() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_issues();
        init(false);
        let ctx = IssueContext {
            phase: "attempt".to_owned(),
            file: Some("weird.adb".to_owned()),
            target: Some("Boom".to_owned()),
            language: Some("ada".to_owned()),
        };
        let result: Result<i32, String> =
            catch(ctx, || panic!("byte index 4 is not a char boundary"));
        let reason = result.expect_err("panicking closure must yield Err(reason)");
        assert!(reason.contains("govfuzz internal error"), "{reason}");
        assert!(reason.contains("char boundary"), "{reason}");
        let issues = snapshot();
        let hit = issues
            .iter()
            .find(|i| {
                i.category == IssueCategory::InternalPanic && i.summary.contains("char boundary")
            })
            .expect("panic must be recorded as an internal issue");
        assert_eq!(hit.context.target.as_deref(), Some("Boom"));
        assert_eq!(hit.context.file.as_deref(), Some("weird.adb"));
    }

    #[test]
    fn catch_passes_through_a_non_panicking_value() {
        init(false);
        let ctx = IssueContext {
            phase: "attempt".to_owned(),
            ..Default::default()
        };
        assert_eq!(catch(ctx, || 7 + 5), Ok(12));
    }

    #[test]
    fn write_skips_clean_run_but_debug_writes_confirmation() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_issues();
        let dir = std::env::temp_dir().join(format!("gf-bugreport-a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Clean run, no --debug -> nothing written.
        init(false);
        assert_eq!(write(&dir, "2026-07-02T00:00:00Z", &[], false), 0);
        assert!(!dir.join("bug-report.json").exists());
        // Clean run WITH --debug -> a 0-issue version-stamped confirmation.
        init(true);
        assert_eq!(write(&dir, "2026-07-02T00:00:00Z", &[], true), 0);
        assert!(dir.join("bug-report.json").is_file());
        assert!(std::fs::read_to_string(dir.join("bug-report.md"))
            .unwrap()
            .contains("No issues"));
        init(false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_emits_categorized_and_deduped_issues() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_issues();
        init(false);
        let dir = std::env::temp_dir().join(format!("gf-bugreport-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cstring = |file: &str| InternalIssue {
            category: IssueCategory::UnsupportedType,
            summary: "unsupported parameter type 'const CString &'".to_owned(),
            context: IssueContext {
                phase: "harness-gen".to_owned(),
                file: Some(file.to_owned()),
                ..Default::default()
            },
            detail: None,
            backtrace: None,
            occurrences: 1,
        };
        let extra = vec![
            InternalIssue {
                category: IssueCategory::CodegenDefect,
                summary: "codegen: unresolved 'utf8_iterator' (parser recovery artifact)"
                    .to_owned(),
                context: IssueContext {
                    phase: "harness-codegen".to_owned(),
                    ..Default::default()
                },
                detail: None,
                backtrace: None,
                occurrences: 2,
            },
            cstring("dlg1.cpp"),
            cstring("dlg2.cpp"), // SAME type, DIFFERENT file -> still one row (dedup by type)
        ];
        let n = write(&dir, "2026-07-02T00:00:00Z", &extra, false);
        assert_eq!(
            n, 2,
            "codegen + one type-deduped unsupported-type (across 2 files)"
        );
        let md = std::fs::read_to_string(dir.join("bug-report.md")).unwrap();
        assert!(md.contains("utf8_iterator"), "{md}");
        assert!(md.contains("const CString &"), "{md}");
        // Type-based dedup: one compact row tagged with the count, not per-file rows.
        assert!(md.contains("[unsupported-type x2]"), "{md}");
        assert!(
            !md.contains("dlg1.cpp") && !md.contains("dlg2.cpp"),
            "per-file noise dropped: {md}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_boundary_unsupported_types_are_tagged_working_as_intended() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_issues();
        init(false);
        let dir = std::env::temp_dir().join(format!("gf-bugreport-wai-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let issue = |summary: &str| InternalIssue {
            category: IssueCategory::UnsupportedType,
            summary: summary.to_owned(),
            context: IssueContext {
                phase: "harness-gen".to_owned(),
                ..Default::default()
            },
            detail: None,
            backtrace: None,
            occurrences: 1,
        };
        let extra = vec![
            // Phase-C opaque-lifecycle skip (groups 1-4 of the dogfood report).
            issue("opque type 'XPRSprob' for parameter 'prob' needs lifecycle support (Phase C)"),
            // No-ctor class the harness can't construct (group 5).
            issue(
                "cannot construct C++ class 'CAboutInfoAdaptor' to harness 'FromXML': it has no \
                 public default constructor, no supported public constructor, and no factory \
                 method or free function returning 'CAboutInfoAdaptor' was found.",
            ),
            // A genuinely-unrecognized unsupported type: must NOT be tagged.
            issue("unsupported parameter type 'WCHAR'"),
        ];
        write(&dir, "2026-07-07T00:00:00Z", &extra, false);
        let md = std::fs::read_to_string(dir.join("bug-report.md")).unwrap();
        // The up-front explanation of the marker appears once.
        assert!(
            md.contains("Rows marked **(working as intended)**"),
            "missing marker legend: {md}"
        );
        // Both known boundaries are annotated.
        assert_eq!(
            md.matches("**(working as intended)**").count(),
            3, // legend + the two tagged rows
            "expected the legend plus two tagged rows: {md}"
        );
        assert!(md.contains("roadmap Phase C"), "phase-c note: {md}");
        assert!(
            md.contains("no public constructor/factory"),
            "no-ctor note: {md}"
        );
        // The unrecognized type is left untagged (still worth reporting).
        let wchar_line = md
            .lines()
            .find(|l| l.contains("'WCHAR'"))
            .expect("WCHAR row present");
        assert!(
            !wchar_line.contains("working as intended"),
            "an unrecognized unsupported type must NOT be tagged: {wchar_line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_type_boundary_note_classifies_reasons() {
        assert!(unsupported_type_boundary_note("needs lifecycle support (Phase C)").is_some());
        assert!(
            unsupported_type_boundary_note("it has no public default constructor, ...").is_some()
        );
        assert!(unsupported_type_boundary_note("no factory method or free function").is_some());
        // Not a recognized boundary — should stay reportable.
        assert!(unsupported_type_boundary_note("unsupported parameter type 'WCHAR'").is_none());
    }
}
