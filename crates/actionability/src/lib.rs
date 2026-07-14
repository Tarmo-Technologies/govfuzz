// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    #[default]
    Reporting,
    Attacking,
}

impl RunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reporting => "reporting",
            Self::Attacking => "attacking",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RunMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "reporting" => Ok(Self::Reporting),
            "attacking" => Ok(Self::Attacking),
            _ => Err("mode must be reporting or attacking".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    RealReachable,
    LikelyReachable,
    LabOnly,
    Blocked,
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RealReachable => "real_reachable",
            Self::LikelyReachable => "likely_reachable",
            Self::LabOnly => "lab_only",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Critical,
    High,
    Medium,
    Low,
    /// Informational: not a defect (e.g. the target rejecting malformed input
    /// via its own declared exception). Shown for coverage/visibility, distinct
    /// from `Low` (a minor real defect) and `Unknown` (undetermined).
    Info,
    Unknown,
}

impl Impact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionabilityConfidence {
    High,
    Medium,
    Low,
}

impl ActionabilityConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Parse a persisted confidence label back into the enum. `None` for an
    /// unknown/empty string so callers can fall back to a recomputed value.
    pub fn from_label(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPath {
    pub kind: String,
    pub source: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Whether the fuzzed entry's parameters are a proven attacker-controlled
    /// input channel:
    /// * `Some(true)`  — attacker-reachable (a read-only untrusted-input buffer);
    ///   a crash here is a candidate vulnerability.
    /// * `Some(false)` — the govfuzz harness drove this function directly but the
    ///   fuzzed parameters are NOT attacker input (internal helper / output
    ///   serializer); public-API reachability is UNPROVEN.
    /// * `None`        — reachability was not assessed for this entry (Ada targets,
    ///   which are ranked structurally, or legacy findings). Treated as the prior
    ///   behavior, never downgraded on this signal alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attacker_reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixLocation {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u64>,
    pub reason: String,
}

/// Where attacker input enters the program: the fuzzed entry point (the harness
/// target subprogram / entry path) plus the reproducer that drives it. Distinct
/// from `fix_location` (where a developer changes code) and from `Sink` (where
/// the fault actually surfaces).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// How the input enters, e.g. `harness` for a fuzz target.
    pub kind: String,
    /// The fuzzed entry point the input drives (target subprogram or harness id).
    pub entry: String,
    /// The reproducer file carrying the triggering bytes (e.g. `testcase.bin`).
    pub testcase: String,
}

/// Where execution goes wrong: the top resolved project frame from the crash
/// stack. Carries the source `file`/`line` when the frame resolved to one, plus
/// the faulting `function`. Distinct from `fix_location`, which may point
/// elsewhere (a caller, an allocation site, or a remapped source line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEvidence {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProstheticItem {
    pub kind: String,
    pub name: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prosthetics {
    pub used: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ProstheticItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchHint {
    pub rule_id: String,
    pub title: String,
    pub guidance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionabilityRecord {
    pub mode: RunMode,
    pub verdict: Verdict,
    pub impact: Impact,
    pub confidence: ActionabilityConfidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_path: Option<EntryPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_location: Option<FixLocation>,
    /// Where attacker input enters (fuzzed entry point + reproducer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Where execution goes wrong (top resolved project frame).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<Sink>,
    /// Plain-English, jargon-free description of the bug, the input that
    /// triggers it, and its lay impact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// CWE identifier(s) for the finding's bug class, primary first
    /// (e.g. `["CWE-416"]` or `["CWE-122", "CWE-787"]`). Empty when the bug
    /// class is unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    /// Human-readable name of the primary CWE (e.g. `"Use After Free"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayEvidence>,
    pub prosthetics: Prosthetics,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patch_hints: Vec<PatchHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ActionabilityCounts {
    pub by_actionability_verdict: BTreeMap<String, usize>,
    pub by_impact: BTreeMap<String, usize>,
}

pub fn backfill_actionability(
    mode: RunMode,
    raw: &Value,
    finding_json_path: Option<&str>,
) -> ActionabilityRecord {
    let prosthetics = prosthetics_from(raw);
    let fix_location = select_fix_location(raw, finding_json_path);
    let entry_path = entry_path_from(raw);
    let sink = sink_from(raw);
    let source = source_from(raw, entry_path.as_ref());
    let explanation = explanation_for(raw, sink.as_ref(), &source);
    let (cwe, cwe_name) = cwe_for_finding(raw);
    let replay = replay_from(raw);
    let impact = impact_from(raw);
    let confidence = confidence_from(
        raw,
        replay.as_ref(),
        fix_location.as_ref(),
        entry_path.as_ref(),
    );
    let verdict = classify_verdict(
        raw,
        entry_path.as_ref(),
        fix_location.as_ref(),
        replay.as_ref(),
        &prosthetics,
    );
    let patch_hints = patch_hints_for_finding(raw);
    let mut next_steps = next_steps_for(verdict, fix_location.as_ref(), &prosthetics);
    if let Some(note) = tier_next_step(raw) {
        next_steps.insert(0, note);
    }

    ActionabilityRecord {
        mode,
        verdict,
        impact,
        confidence,
        entry_path,
        fix_location,
        source,
        sink,
        explanation,
        cwe,
        cwe_name,
        replay,
        prosthetics,
        patch_hints,
        next_steps,
    }
}

pub fn classify_verdict(
    raw: &Value,
    entry_path: Option<&EntryPath>,
    fix_location: Option<&FixLocation>,
    replay: Option<&ReplayEvidence>,
    prosthetics: &Prosthetics,
) -> Verdict {
    if prosthetics.used {
        return Verdict::LabOnly;
    }
    if has_blocking_resource_evidence(raw) {
        return Verdict::Blocked;
    }
    // Harness-quality false-positive classes: a LeakSanitizer report with no
    // target frame (G5), a relational `assert!` contract panic the auto-harness
    // can't satisfy (G6), or a fixed-width read of a too-short fuzzed slice
    // (byteorder-style documented length precondition, #467). Reproducible in the
    // lab but not an attacker-reachable bug — demote so they don't read as real
    // findings (still surfaced, not dropped).
    if is_rust_alloc_only_leak(raw)
        || is_relational_contract_panic(raw)
        || is_fixed_width_slice_read_panic(raw)
        || is_harness_cleanup_artifact(raw)
        || is_go_must_panic(raw)
        || is_native_assertion_enum_domain_precondition(raw)
    {
        return Verdict::LabOnly;
    }
    let has_failure = string_at(raw, &["rule_id"]).is_some()
        || string_at(raw, &["signature"]).is_some()
        || raw.get("exception").is_some()
        || raw.get("handler").is_some();
    let reproduced = replay.is_some_and(|r| r.status == "reproduced");
    let has_source_fix = fix_location.is_some_and(is_source_fix_location);
    if entry_path.is_some() && has_failure {
        // Positive evidence the fuzzed entry is NOT an attacker-controlled input
        // channel (an internal helper / output serializer the harness drove
        // directly): the crash is reproducible in the lab but public-API
        // reachability is unproven, so it must not read as attacker-reachable.
        // Unknown reachability (`None`, e.g. Ada / legacy findings) keeps the
        // prior behavior — we only downgrade on a definite unproven signal.
        if entry_path.is_some_and(|entry| entry.attacker_reachable == Some(false)) {
            return Verdict::LabOnly;
        }
        if reproduced && has_source_fix {
            return Verdict::RealReachable;
        }
        return Verdict::LikelyReachable;
    }
    Verdict::Unknown
}

pub fn select_fix_location(raw: &Value, finding_json_path: Option<&str>) -> Option<FixLocation> {
    if let Some(location) =
        location_at(raw, &["oracle", "sink", "location"], "oracle_sink_location")
    {
        return Some(location);
    }
    if let Some(location) = location_at(raw, &["sink", "location"], "oracle_sink_location") {
        return Some(location);
    }
    if let Some(location) = sanitizer_stack_location(raw) {
        return Some(location);
    }
    if let Some(location) = explicit_raise_location(raw) {
        return Some(location);
    }
    // The exact source site of the escaped exception, recovered by remapping the
    // instrumented-copy `<file>:<line>` in the runtime message back to the
    // original source (`exception.source_file`/`source_line`). This is the line
    // a developer fixes for an unhandled language-runtime check
    // (CONSTRAINT_ERROR etc.), so it outranks the generic handler-site fallback.
    if let Some(location) = exception_source_location(raw) {
        return Some(location);
    }
    if let Some(location) = location_at(raw, &["exception", "handler"], "handler_site")
        .or_else(|| handler_location(raw))
    {
        return Some(location);
    }
    if let Some(location) = location_at(raw, &["exception", "last_breadcrumb"], "last_breadcrumb") {
        return Some(location);
    }
    if let Some(location) = location_at(raw, &["target", "location"], "target_entry") {
        return Some(location);
    }
    // No project source frame resolved. Point at the sink frame's function (the
    // top meaningful non-runtime / non-harness stack frame) even when it carries
    // no source file, so the fix location names the faulting routine instead of
    // the generated `finding.json` path. When the stack has nothing meaningful at
    // all, return `None` — never emit the finding.json path as a fix location.
    //
    // `finding_json_path` is retained in the signature for API compatibility but
    // is no longer used as a fallback target.
    let _ = finding_json_path;
    sink_frame_fix_location(raw)
}

/// A last-resort fix location built from the sink frame's function when no frame
/// resolved to a source file. Reason `sink_frame_no_source` so consumers can
/// surface it as "function only, no source line" rather than a confirmed source
/// fix site.
fn sink_frame_fix_location(raw: &Value) -> Option<FixLocation> {
    let sink = sink_from(raw)?;
    let (path, reason) = match &sink.file {
        Some(file) => (file.clone(), "sanitizer_top_non_runtime_frame".to_owned()),
        None => (sink.function.clone(), "sink_frame_no_source".to_owned()),
    };
    Some(FixLocation {
        path,
        line: sink.line,
        col: None,
        reason,
    })
}

pub fn patch_hints_for_finding(raw: &Value) -> Vec<PatchHint> {
    let rule_id = string_at(raw, &["rule_id"]).unwrap_or_default();
    let oracle_name = string_at(raw, &["oracle", "name"]).unwrap_or_default();
    let rule_hint = match rule_id.as_str() {
        "GF-302" => Some(PatchHint {
            rule_id: rule_id.clone(),
            title: "Use SQL parameter binding".to_owned(),
            guidance: "Replace string-concatenated SQL with prepared statements and bound parameters for every attacker-controlled value.".to_owned(),
            diff: None,
        }),
        "GF-304" => Some(PatchHint {
            rule_id: rule_id.clone(),
            title: "Avoid shell command strings".to_owned(),
            guidance: "Pass an argv array or a validated enum command instead of building a shell string from input bytes.".to_owned(),
            diff: None,
        }),
        "GF-205" => Some(PatchHint {
            rule_id: rule_id.clone(),
            title: "Check bounds before arithmetic or narrowing".to_owned(),
            guidance: "Validate upper and lower bounds before arithmetic, allocation-size calculation, indexing, or narrowing conversion.".to_owned(),
            diff: None,
        }),
        _ if oracle_name.contains("path-traversal") => Some(PatchHint {
            rule_id: rule_id.clone(),
            title: "Constrain paths under an allowed root".to_owned(),
            guidance: "Normalize the requested path, reject parent-directory traversal, and verify the canonical path remains under the configured root.".to_owned(),
            diff: None,
        }),
        _ => None,
    };
    if let Some(hint) = rule_hint {
        return vec![hint];
    }
    // No rule/oracle-specific guidance: derive a bug-class-specific hint from the
    // sanitizer / exception type and the sink frame.
    sanitizer_patch_hint(raw).into_iter().collect()
}

/// Bug-class-specific, advisory fix guidance keyed off the sanitizer / exception
/// type plus the resolved sink frame. References the sink location; never
/// fabricates a diff.
fn sanitizer_patch_hint(raw: &Value) -> Option<PatchHint> {
    let class = classify_bug(raw);
    if matches!(class, BugClass::Unknown) {
        return None;
    }
    let at = sink_from(raw)
        .map(|sink| sink_location_phrase(&sink))
        .unwrap_or_else(|| "the faulting location".to_owned());
    // Keep the hint tied to the finding's rule when it has one, else label it by
    // bug class so consumers still get a stable, meaningful id.
    let rule_id = string_at(raw, &["rule_id"]).unwrap_or_else(|| class.slug().to_owned());
    let (title, guidance) = match class {
        BugClass::HeapBufferOverflow
        | BugClass::StackBufferOverflow
        | BugClass::GlobalBufferOverflow => (
            "Bounds-check before the access",
            format!(
                "Bounds-check the index/length before the access at {at}: validate it against the buffer size before reading or writing."
            ),
        ),
        BugClass::UseAfterFree => (
            "Do not use freed memory",
            format!(
                "Do not use the object after it is freed at {at}: reorder the free, take ownership of the lifetime, or null the pointer and re-check before use."
            ),
        ),
        BugClass::StaleStackPointerUse => (
            "Do not use a stack pointer past its object's lifetime",
            format!(
                "Stop the address from outliving its stack object near {at}: do not return or store a pointer/reference to a local, and do not keep a pointer to a variable past the block it was declared in. Copy the value out, or give the object longer-lived (heap or caller-provided) storage."
            ),
        ),
        BugClass::DoubleFree => (
            "Free exactly once",
            format!(
                "Ensure the allocation is freed exactly once near {at}: null the pointer after freeing and guard against a second free on every path."
            ),
        ),
        BugClass::MemoryLeak => (
            "Free the allocation on every exit path",
            format!(
                "Free the allocation from {at} on every exit path, including error and early-return paths."
            ),
        ),
        BugClass::NullDeref => (
            "Guard the pointer for null",
            format!(
                "Guard the pointer for null before the dereference at {at}, or ensure the producer never returns null."
            ),
        ),
        BugClass::WildSegv => (
            "Validate the pointer and offset",
            format!(
                "Validate the pointer and any offset/length before the access at {at}; reject inputs that drive it out of range."
            ),
        ),
        BugClass::UndefinedBehavior => (
            "Check before the arithmetic / shift",
            format!(
                "Check for overflow before the arithmetic at {at} (or use a wider / unsigned type), and validate shift amounts and conversions against their type's range."
            ),
        ),
        BugClass::Timeout => (
            "Bound the work per input",
            format!(
                "Bound the work near {at}: cap iteration counts and recursion depth, and reject inputs that would cause excessive processing."
            ),
        ),
        BugClass::OutOfMemory => (
            "Cap allocation size",
            format!(
                "Validate and cap allocation sizes near {at} against a sane maximum before allocating; reject oversized or self-amplifying inputs."
            ),
        ),
        BugClass::ReachableAssertion => (
            "Validate input instead of asserting",
            format!(
                "Replace the reachable assertion / abort near {at} with input validation that returns a recoverable error: reject the malformed input gracefully rather than aborting the process."
            ),
        ),
        BugClass::DivideByZero => (
            "Guard the divisor against zero",
            format!(
                "Check the divisor for zero before the division at {at}, and reject or special-case inputs that drive it to zero."
            ),
        ),
        BugClass::StackExhaustion => (
            "Bound the recursion depth",
            format!(
                "Cap the recursion depth near {at} (or convert it to an explicit, bounded iterative loop), and reject inputs that would drive unbounded nesting."
            ),
        ),
        BugClass::UncaughtException => (
            "Handle the exception at the boundary",
            format!(
                "Catch and handle the escaping exception at {at} (or validate the precondition before it can raise), so malformed input yields a recoverable error instead of terminating the runtime."
            ),
        ),
        BugClass::IndexOutOfBounds => (
            "Bounds-check the index/range before the access",
            format!(
                "Validate the index or slice range against the slice length before the access at {at} (use `get`/`get_mut`, `split_at_checked`, or an explicit length check); reject inputs that drive it out of bounds rather than indexing unchecked."
            ),
        ),
        BugClass::Unknown => return None,
    };
    Some(PatchHint {
        rule_id,
        title: title.to_owned(),
        guidance,
        diff: None,
    })
}

/// A compact, human-readable reference to the sink location for hint / next-step
/// prose: `` `file:line` (`function`) `` when a source line resolved, else the
/// bare `` `function` ``.
fn sink_location_phrase(sink: &Sink) -> String {
    match (&sink.file, sink.line) {
        (Some(file), Some(line)) => format!("`{file}:{line}` (`{}`)", sink.function),
        (Some(file), None) => format!("`{file}` (`{}`)", sink.function),
        (None, _) => format!("`{}`", sink.function),
    }
}

pub fn aggregate_counts<'a>(
    records: impl IntoIterator<Item = &'a ActionabilityRecord>,
) -> ActionabilityCounts {
    let mut counts = ActionabilityCounts::default();
    for record in records {
        *counts
            .by_actionability_verdict
            .entry(record.verdict.as_str().to_owned())
            .or_insert(0) += 1;
        *counts
            .by_impact
            .entry(record.impact.as_str().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

pub fn finding_sort_key(record: &ActionabilityRecord) -> (u8, u8, u8) {
    (
        verdict_rank(record.verdict),
        impact_rank(record.impact),
        confidence_rank(record.confidence),
    )
}

pub fn attacking_target_score(base_score: i32, source_text: &str, target_name: &str) -> i64 {
    let mut score = i64::from(base_score);
    let lower_name = target_name.to_ascii_lowercase();
    if [
        "parse", "decode", "read", "open", "connect", "spawn", "query", "sql", "load",
    ]
    .iter()
    .any(|needle| lower_name.contains(needle))
    {
        score += 50;
    }
    for oracle in finding_rules::oracle_manifest::ORACLE_MANIFEST {
        if oracle.dangerous_apis.iter().any(|api| {
            source_text.contains(api.rsplit('.').next().unwrap_or(api)) || source_text.contains(api)
        }) {
            score += 100;
        }
    }
    score
}

pub fn existing_actionability_or_backfill(
    mode: RunMode,
    raw: &Value,
    finding_json_path: Option<&Path>,
) -> ActionabilityRecord {
    if let Some(existing) = raw.get("actionability") {
        if let Ok(mut record) = serde_json::from_value::<ActionabilityRecord>(existing.clone()) {
            // Backfill fields added after some on-disk records were written, so a
            // report over an older finding still surfaces source / sink / the
            // plain-English explanation / fix guidance.
            if record.sink.is_none() {
                record.sink = sink_from(raw);
            }
            if record.source.is_none() {
                record.source = source_from(raw, record.entry_path.as_ref());
            }
            if record.explanation.is_none() {
                record.explanation = explanation_for(raw, record.sink.as_ref(), &record.source);
            }
            if record.cwe.is_empty() {
                let (cwe, cwe_name) = cwe_for_finding(raw);
                record.cwe = cwe;
                if record.cwe_name.is_none() {
                    record.cwe_name = cwe_name;
                }
            }
            if record.patch_hints.is_empty() {
                record.patch_hints = patch_hints_for_finding(raw);
            }
            let raw_prosthetics = prosthetics_from(raw);
            if raw_prosthetics.used || record.prosthetics.used {
                if raw_prosthetics.used {
                    record.prosthetics = raw_prosthetics;
                }
                record.verdict = Verdict::LabOnly;
                record.next_steps = next_steps_for(
                    record.verdict,
                    record.fix_location.as_ref(),
                    &record.prosthetics,
                );
            }
            return record;
        }
    }
    let path = finding_json_path.map(|path| path.to_string_lossy().into_owned());
    backfill_actionability(mode, raw, path.as_deref())
}

pub fn value_for_finding(mode: RunMode, raw: &Value, finding_json_path: Option<&Path>) -> Value {
    serde_json::to_value(existing_actionability_or_backfill(
        mode,
        raw,
        finding_json_path,
    ))
    .unwrap_or_else(|_| json!({ "mode": mode.as_str(), "verdict": "unknown" }))
}

fn entry_path_from(raw: &Value) -> Option<EntryPath> {
    let signal = attacker_reachable_signal(raw);
    if let Some(entry) = raw
        .get("actionability")
        .and_then(|value| value.get("entry_path"))
    {
        let kind = string_at(entry, &["kind"]).unwrap_or_else(|| "harness".to_owned());
        let source = string_at(entry, &["source"]).unwrap_or_else(|| "testcase.bin".to_owned());
        let target = string_at(entry, &["target"]).unwrap_or_else(|| target_name(raw));
        // A persisted record's own flag wins; otherwise fall back to the raw
        // reachability signal stamped by the auto pipeline.
        let attacker_reachable = entry
            .get("attacker_reachable")
            .and_then(Value::as_bool)
            .map(Some)
            .unwrap_or(signal);
        return Some(EntryPath {
            kind,
            source,
            target,
            evidence: string_array_at(entry, &["evidence"]),
            attacker_reachable,
        });
    }
    let target = target_name(raw);
    if target != "unknown" {
        return Some(EntryPath {
            kind: "harness".to_owned(),
            source: "testcase.bin".to_owned(),
            target,
            evidence: Vec::new(),
            attacker_reachable: signal,
        });
    }
    None
}

/// The fuzzed entry's attacker-reachability, stamped into the finding as a raw
/// `input_reachability` label by the auto pipeline (the candidate's
/// `target_rank::InputReachability`). `attacker_reachable` → `Some(true)`;
/// `reachability_unproven` / `output_serializer` → `Some(false)`; absent or
/// anything else (Ada / legacy findings) → `None` (not assessed).
fn attacker_reachable_signal(raw: &Value) -> Option<bool> {
    let label = string_at(raw, &["input_reachability"])
        .or_else(|| string_at(raw, &["target", "input_reachability"]))?;
    match label.as_str() {
        "attacker_reachable" => Some(true),
        "reachability_unproven" | "output_serializer" => Some(false),
        // Input-reachable via a virtualized IPC channel (shm / mq / MMIO): the
        // crash IS driven by input, so it must NOT be downgraded to lab_only like
        // `reachability_unproven` — but attacker-control depends on the channel's
        // trust boundary, so we don't assert Some(true) either. None lets the
        // verdict land on likely_reachable (a real, input-driven failure).
        "ipc_channel_reachable" => None,
        _ => None,
    }
}

fn replay_from(raw: &Value) -> Option<ReplayEvidence> {
    let replay = raw.get("replay")?;
    let status = string_at(replay, &["status"])
        .or_else(|| string_at(replay, &["command"]).map(|_| "available".to_owned()))?;
    Some(ReplayEvidence { status })
}

fn prosthetics_from(raw: &Value) -> Prosthetics {
    let mut items = Vec::new();
    for name in string_array_at(raw, &["build", "deps", "stubbed"]) {
        items.push(ProstheticItem {
            kind: "stubbed_dependency".to_owned(),
            name,
            evidence: "build.deps.stubbed".to_owned(),
        });
    }
    for name in string_array_at(raw, &["build", "deps", "fake_corba"]) {
        items.push(ProstheticItem {
            kind: "fake_resource".to_owned(),
            name,
            evidence: "build.deps.fake_corba".to_owned(),
        });
    }
    if let Some(obj) = raw
        .pointer("/runtime_mode/env_injected")
        .and_then(Value::as_object)
    {
        for name in obj.keys() {
            items.push(ProstheticItem {
                kind: "missing_env_shim".to_owned(),
                name: name.clone(),
                evidence: "runtime_mode.env_injected".to_owned(),
            });
        }
    }
    for symbol in raw
        .get("mocks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) =
            string_at(symbol, &["symbol"]).or_else(|| symbol.as_str().map(ToOwned::to_owned))
        {
            items.push(ProstheticItem {
                kind: "mock".to_owned(),
                name,
                evidence: "mocks".to_owned(),
            });
        }
    }
    Prosthetics {
        used: !items.is_empty(),
        items,
    }
}

fn has_blocking_resource_evidence(raw: &Value) -> bool {
    raw.get("runtrace_events")
        .and_then(Value::as_array)
        .is_some_and(|events| {
            events
                .iter()
                .filter_map(|event| string_at(event, &["kind"]))
                .any(|kind| is_blocking_resource_kind(&kind))
        })
        || raw
            .get("blocked_resources")
            .and_then(Value::as_array)
            .is_some_and(|events| !events.is_empty())
}

fn impact_from(raw: &Value) -> Impact {
    // A finding's triage tier governs impact for Ada exception findings: a
    // genuine uncaught fault is loud; an exception the target caught itself is
    // quiet regardless of the underlying rule's inherent severity. This is what
    // stops a swallowed Constraint_Error (GF-102, inherently "high") from
    // masquerading as a confirmed high-impact vulnerability.
    match tier_at(raw) {
        Some("real_fault") => return Impact::High,
        // A swallowed predefined check may be a masked real defect — minor, but
        // worth review. The target rejecting input via its own declared
        // exception is not a defect at all — informational only.
        Some("swallowed_check") => return Impact::Low,
        Some("intended_rejection") => return Impact::Info,
        _ => {}
    }
    if let Some(severity) = string_at(raw, &["severity"]) {
        return impact_from_severity(&severity);
    }
    if let Some(rule_id) = string_at(raw, &["rule_id"]) {
        if let Some(rule) = finding_rules::by_id(&rule_id) {
            return impact_from_severity(rule.default_severity.as_str());
        }
    }
    Impact::Unknown
}

/// The `tier` field set by the corpus finding emitter (`real_fault`,
/// `swallowed_check`, `intended_rejection`), if present.
fn tier_at(raw: &Value) -> Option<&str> {
    raw.get("tier").and_then(Value::as_str)
}

/// A leading triage instruction reflecting the finding's tier, so a reviewer
/// can tell a real crash from a swallowed check worth auditing from the
/// target's own intended input rejection.
fn tier_next_step(raw: &Value) -> Option<String> {
    Some(match tier_at(raw)? {
        "real_fault" => "Uncaught exception escaped the target to the harness top level: triage as a real fault (crash / DoS).".to_owned(),
        "swallowed_check" => "Predefined runtime check caught inside the target: potential masked memory-safety / DoS bug. Review whether it is exploitable with runtime checks suppressed or in a C/C++ port.".to_owned(),
        "intended_rejection" => "Target rejected malformed input via its own declared exception: intended handling, not a finding.".to_owned(),
        _ => return None,
    })
}

fn confidence_from(
    raw: &Value,
    replay: Option<&ReplayEvidence>,
    fix_location: Option<&FixLocation>,
    entry_path: Option<&EntryPath>,
) -> ActionabilityConfidence {
    // Exceptions the target caught itself are low-confidence as vulnerabilities:
    // Ada contained them. They stay visible (especially swallowed checks, which
    // may mask a real bug) but must not read as confirmed.
    match tier_at(raw) {
        Some("swallowed_check") | Some("intended_rejection") => {
            return ActionabilityConfidence::Low
        }
        _ => {}
    }
    let base = if let Some(value) =
        string_at(raw, &["confidence"]).or_else(|| string_at(raw, &["confidence", "label"]))
    {
        match value.as_str() {
            "high" => ActionabilityConfidence::High,
            "medium" => ActionabilityConfidence::Medium,
            _ => ActionabilityConfidence::Low,
        }
    } else {
        let has_source_fix = fix_location.is_some_and(is_source_fix_location);
        if replay.is_some_and(|r| r.status == "reproduced") && has_source_fix {
            ActionabilityConfidence::High
        } else if has_source_fix {
            ActionabilityConfidence::Medium
        } else {
            ActionabilityConfidence::Low
        }
    };
    // An entry the harness drove directly with unproven public-API reachability
    // cannot read as high-confidence — cap it at `medium`.
    if matches!(base, ActionabilityConfidence::High)
        && entry_path.is_some_and(|entry| entry.attacker_reachable == Some(false))
    {
        return ActionabilityConfidence::Medium;
    }
    base
}

fn location_at(raw: &Value, path: &[&str], reason: &str) -> Option<FixLocation> {
    let location = path
        .iter()
        .try_fold(raw, |current, component| current.get(*component))?;
    let path_value = string_at(location, &["path"]).or_else(|| string_at(location, &["file"]))?;
    Some(FixLocation {
        path: path_value,
        line: location.get("line").and_then(Value::as_u64),
        col: location.get("col").and_then(Value::as_u64),
        reason: reason.to_owned(),
    })
}

fn sanitizer_stack_location(raw: &Value) -> Option<FixLocation> {
    let frames = raw.pointer("/exception/stack").and_then(Value::as_array)?;
    for frame in frames {
        let function = string_at(frame, &["function"]).unwrap_or_default();
        if is_runtime_frame(&function) || is_allocator_frame(&function) {
            continue;
        }
        let Some(file) = string_at(frame, &["file"]) else {
            continue;
        };
        if file.starts_with('(') {
            continue;
        }
        // A glibc-internal source file (libio/iofread.c, sysdeps/.../memmove.S)
        // is never the developer's fix site — the project caller above it is.
        if is_libc_source_file(Some(&file)) {
            continue;
        }
        // A Rust toolchain stdlib frame (core::ptr::copy_nonoverlapping at
        // library/core) is never the fix site either — the first in-project Rust
        // frame above it is (#32).
        if is_rust_stdlib_frame(&function, Some(&file)) {
            continue;
        }
        // Never resolve the fix to govfuzz's own generated harness (the
        // `govfuzz_run_one`/`main` frames in `<work>/auto/<id>/main.c`): that
        // frame is the harness freeing/decoding the fabricated inputs it built,
        // not a target site. Skip it so the location names real target code, or
        // resolves to `None` for a harness-only stack (then the harness-artifact
        // verdict demotion classifies it). Mirrors `sink_from`.
        if is_harness_frame(&function, Some(&file)) {
            continue;
        }
        return Some(FixLocation {
            path: file,
            line: frame.get("line").and_then(Value::as_u64),
            col: None,
            reason: "sanitizer_top_non_runtime_frame".to_owned(),
        });
    }
    None
}

/// The original-source fault site of an escaped exception, populated by the
/// finding emitter after remapping the instrumented-copy line back to the
/// developer's source. Absent for findings without a line map (C/sanitizer).
fn exception_source_location(raw: &Value) -> Option<FixLocation> {
    let path = string_at(raw, &["exception", "source_file"])?;
    let line = raw
        .get("exception")
        .and_then(|exception| exception.get("source_line"))
        .and_then(Value::as_u64);
    Some(FixLocation {
        path,
        line,
        col: None,
        reason: "exception_source".to_owned(),
    })
}

fn explicit_raise_location(raw: &Value) -> Option<FixLocation> {
    if let Some(location) =
        location_at(raw, &["exception", "explicit_raise"], "explicit_raise_site")
    {
        return Some(location);
    }
    if string_at(raw, &["classification"]).as_deref() != Some("explicit_raise") {
        return None;
    }
    let handler_seq = raw
        .pointer("/handler/sequence_index")
        .and_then(Value::as_u64);
    let handler_exception = string_at(raw, &["handler", "exception_name"]);
    let raises = raw.get("raises").and_then(Value::as_array)?;
    raises
        .iter()
        .filter(|raise| {
            handler_seq.is_none_or(|seq| {
                raise
                    .get("sequence_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX)
                    < seq
            }) && handler_exception.as_deref().is_none_or(|name| {
                string_at(raise, &["exception_name"])
                    .is_none_or(|raise_name| raise_name.eq_ignore_ascii_case(name))
            })
        })
        .filter_map(|raise| {
            let path = string_at(raise, &["file"])?;
            Some((
                raise.get("sequence_index").and_then(Value::as_u64),
                FixLocation {
                    path,
                    line: raise.get("line").and_then(Value::as_u64),
                    col: None,
                    reason: "explicit_raise_site".to_owned(),
                },
            ))
        })
        .max_by_key(|(sequence_index, _location)| *sequence_index)
        .map(|(_sequence_index, location)| location)
}

fn is_source_fix_location(location: &FixLocation) -> bool {
    // A function-only sink frame (`sink_frame_no_source`) names the faulting
    // routine but resolves no source line, so it is not strong enough to count
    // as a real source-fix site for verdict / confidence purposes. The legacy
    // `finding_json_path` reason (older on-disk records) likewise does not count.
    !matches!(
        location.reason.as_str(),
        "finding_json_path" | "sink_frame_no_source"
    )
}

fn is_blocking_resource_kind(kind: &str) -> bool {
    matches!(
        kind,
        "network_unreachable" | "file_missing" | "env_var_missing" | "dlopen_failed"
    )
}

fn handler_location(raw: &Value) -> Option<FixLocation> {
    let handler = raw.get("handler")?;
    let path = string_at(handler, &["handler_file"])?;
    Some(FixLocation {
        path,
        line: handler.get("handler_line").and_then(Value::as_u64),
        col: None,
        reason: "handler_site".to_owned(),
    })
}

fn next_steps_for(
    verdict: Verdict,
    fix_location: Option<&FixLocation>,
    prosthetics: &Prosthetics,
) -> Vec<String> {
    match verdict {
        Verdict::LabOnly => prosthetics
            .items
            .iter()
            .map(|item| {
                format!(
                    "Replace {} '{}' with the real dependency before claiming attacker reachability.",
                    item.kind, item.name
                )
            })
            .collect(),
        Verdict::Blocked => vec![
            "Provide the missing real resource and rerun in attacking mode to test the path without substitutions."
                .to_owned(),
        ],
        Verdict::Unknown => vec![
            "Replay the testcase and collect source-location evidence before using this as a security gate."
                .to_owned(),
        ],
        Verdict::RealReachable | Verdict::LikelyReachable => fix_location
            .map(|location| vec![format!("Inspect {} as the primary fix location.", location.path)])
            .unwrap_or_default(),
    }
}

fn target_name(raw: &Value) -> String {
    string_at(raw, &["target", "subprogram"])
        .or_else(|| string_at(raw, &["target", "harness_id"]))
        .or_else(|| string_at(raw, &["harness_id"]))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn impact_from_severity(severity: &str) -> Impact {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Impact::Critical,
        "high" => Impact::High,
        "medium" => Impact::Medium,
        "low" => Impact::Low,
        "info" | "informational" => Impact::Info,
        _ => Impact::Unknown,
    }
}

fn is_runtime_frame(function: &str) -> bool {
    let normalized = function.to_ascii_lowercase();
    if normalized.starts_with("__asan")
        || normalized.starts_with("__ubsan")
        || normalized.starts_with("llvm")
        || normalized.contains("sanitizer")
        || normalized.contains("libc_start")
        || normalized == "main"
        // The CRT entry stub: a harness-only / CRT-only stack must not resolve its
        // sink or fix location to `_start` (aligns with cluster.rs NOISE_EXACT) (#38).
        || normalized == "_start"
    {
        return true;
    }
    is_libc_runtime_function(&function_head(function))
}

/// libc / system primitives that surface as a stack frame but are never the
/// project's sink — the real call site is the project frame ABOVE them. Covers
/// glibc stdio internals (`_IO_fread`, `_IO_file_xsgetn`), the `__GI_` /
/// `__libc_` aliases, and the mem/str builtins a sanitizer flags an overrun
/// inside (`memcpy`, `strlen`). Allocator primitives are handled separately by
/// [`is_allocator_frame`].
fn is_libc_runtime_function(head: &str) -> bool {
    let f = head.to_ascii_lowercase();
    if f.starts_with("_io_") || f.starts_with("__gi_") || f.starts_with("__libc_") {
        return true;
    }
    matches!(
        f.as_str(),
        "fread"
            | "fwrite"
            | "fgets"
            | "fputs"
            | "fputc"
            | "fgetc"
            | "getc"
            | "putc"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "strlen"
            | "strnlen"
            | "strcmp"
            | "strncmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strdup"
            | "strndup"
    )
}

/// A glibc-internal *source file* (not a target source). glibc builds with
/// component-relative paths (`libio/iofread.c`, `../sysdeps/.../memmove.S`), so
/// a frame whose file begins with one of those component dirs (after stripping
/// leading `../`/`./`) is libc, never the project sink. Anchored at the path
/// start so a real target path like `/home/u/proj/string/parse.c` does NOT
/// match.
fn is_libc_source_file(file: Option<&str>) -> bool {
    let Some(file) = file else {
        return false;
    };
    let mut rest = file;
    loop {
        rest = match rest.strip_prefix("../").or_else(|| rest.strip_prefix("./")) {
            Some(stripped) => stripped,
            None => break,
        };
    }
    const DIRS: &[&str] = &[
        "libio/",
        "sysdeps/",
        "string/",
        "malloc/",
        "stdio-common/",
        "stdlib/",
        "wcsmbs/",
        "time/",
    ];
    DIRS.iter().any(|dir| rest.starts_with(dir))
}

/// The bare callable name with any argument list / trailing `()` stripped, so
/// `nsvg__createParser()` becomes `nsvg__createParser` and
/// `govfuzz_run_one(unsigned char const*, unsigned long)` becomes
/// `govfuzz_run_one`. The literal `(anonymous namespace)` scope token is NOT an
/// argument list, so `pugi::impl::(anonymous namespace)::strlength_wide(const
/// wchar_t*)` keeps its full qualified name up to the real argument paren.
fn function_head(function: &str) -> String {
    match arg_list_paren_index(function) {
        Some(idx) => function[..idx].trim().to_owned(),
        None => function.trim().to_owned(),
    }
}

/// Byte index of the `(` that opens the trailing argument list, skipping the
/// `(anonymous namespace)` scope token (a non-argument parenthetical embedded
/// in a qualified C++ name) and ignoring `(` nested inside template `<...>`.
/// `None` when the name carries no argument list.
fn arg_list_paren_index(s: &str) -> Option<usize> {
    const ANON: &str = "(anonymous namespace)";
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut angle = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' if angle > 0 => angle -= 1,
            b'(' if angle <= 0 => {
                if s[i..].starts_with(ANON) {
                    i += ANON.len();
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Allocator / deallocator primitives that are never the project sink — the real
/// project allocation/free site is the caller above them.
fn is_allocator_frame(function: &str) -> bool {
    let normalized = function_head(function).to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "malloc"
            | "calloc"
            | "realloc"
            | "reallocarray"
            | "free"
            | "cfree"
            | "aligned_alloc"
            | "posix_memalign"
            | "memalign"
            | "valloc"
            | "pvalloc"
    ) || normalized.starts_with("operator new")
        || normalized.starts_with("operator delete")
        || normalized.starts_with("_znw")
        || normalized.starts_with("_zna")
        || normalized.starts_with("_zdl")
        || normalized.starts_with("_zda")
}

/// A Rust standard-library allocation/plumbing frame (`alloc::raw_vec::RawVecInner
/// ::with_capacity_in`, `alloc::alloc::realloc_nonnull`, `__rust_alloc`, …). These
/// are never the project's leak site — a LeakSanitizer report whose entire stack
/// is such frames is a `Vec`/arena allocation the one-shot harness drops, not a
/// real leak (G5).
fn is_rust_std_alloc_frame(function: &str) -> bool {
    let f = function_head(function).to_ascii_lowercase();
    f.contains("alloc::")
        || f.contains("rawvec")
        || f.contains("with_capacity")
        || f.contains("realloc_nonnull")
        || f.starts_with("__rust_alloc")
        || f.starts_with("__rust_realloc")
        || f.starts_with("__rust_dealloc")
        || f.contains("__rdl_")
}

/// A Rust toolchain standard-library frame (`core::ptr::copy_nonoverlapping`,
/// `alloc::vec::Vec::<T>::push`, `std::io::...`) — by function head (`core::`,
/// `alloc::`, `std::`, incl. the trait-impl `<core::...>` form) or by source path
/// (the rustc-shipped `.../library/{core,alloc,std}/...`,
/// `.../rustlib/src/rust/library/...`, `/rustc/<hash>/library/...`). Such a frame
/// is the Rust stdlib, never the project's sink: the real fault site is the first
/// IN-PROJECT frame above it (e.g. `json::short::Short::from_slice`, not
/// `core::ptr::copy_nonoverlapping`). Mirrors `is_libc_source_file`/`is_libc_runtime_function`
/// for the native Rust lane (#32).
fn is_rust_stdlib_frame(function: &str, file: Option<&str>) -> bool {
    let head = function_head(function);
    if head.starts_with("core::")
        || head.starts_with("alloc::")
        || head.starts_with("std::")
        || head.starts_with("<core::")
        || head.starts_with("<alloc::")
        || head.starts_with("<std::")
    {
        return true;
    }
    file.is_some_and(|file| {
        let lower = file.to_ascii_lowercase();
        lower.contains("/rustlib/src/rust/library/")
            || lower.contains("/library/core/")
            || lower.contains("/library/alloc/")
            || lower.contains("/library/std/")
            || (lower.contains("/rustc/") && lower.contains("/library/"))
    })
}

/// A LeakSanitizer finding whose stack has NO target-crate frame — every frame is
/// allocator / sanitizer-runtime / harness / Rust-std-alloc plumbing, or the stack
/// is empty (unattributable). Such a leak is the `Document`/`Vec` arena the
/// auto-harness allocates and drops in one shot, flagged because LSan never sees
/// the free — noise, not an exploitable bug. Demoted to lab-only (G5).
fn is_rust_alloc_only_leak(raw: &Value) -> bool {
    if classify_bug(raw) != BugClass::MemoryLeak {
        return false;
    }
    match raw.pointer("/exception/stack").and_then(Value::as_array) {
        None => false, // no stack recorded — leave normal verdict logic alone
        Some(frames) if frames.is_empty() => true, // leak with no attributable frame
        Some(frames) => frames.iter().all(|frame| {
            let func = string_at(frame, &["function"]).unwrap_or_default();
            let file = string_at(frame, &["file"]);
            func.is_empty()
                || is_runtime_frame(&func)
                || is_allocator_frame(&func)
                || is_rust_std_alloc_frame(&func)
                || is_harness_frame(&func, file.as_deref())
                || is_libc_source_file(file.as_deref())
        }),
    }
}

/// A native memory-corruption crash whose FAULTING operation is the generated
/// harness itself, not the target: the crash carries a stack, the top meaningful
/// (non-runtime, non-allocator) frame is a govfuzz harness frame, and no target
/// frame resolves at all (`sink_from` is `None`). This is the auto-harness
/// freeing the pointer fields it fabricated for a by-pointer struct parameter —
/// e.g. fuzzing a tomlc99 `eat_token(context_t*, …)` internal, where the harness
/// builds the `context_t` with malloc'd `start`/`stop`/`tok.ptr` buffers, the
/// target reassigns or frees one of them, and the harness's own cleanup then
/// double-/invalid-frees. govfuzz manufactured the fault, so it is NOT an
/// attacker-reachable target vulnerability. Demoted to lab-only — still surfaced,
/// never reported as likely/real-reachable critical.
///
/// Conservative by construction: gated to the native memory-corruption classes
/// (managed-runtime exceptions and oracle findings don't use this stack shape),
/// requires a POSITIVE harness frame (a merely symbol-less stack is left alone),
/// and bails the instant any frame resolves to target code (`sink_from`).
fn is_harness_cleanup_artifact(raw: &Value) -> bool {
    match classify_bug(raw) {
        BugClass::DoubleFree
        | BugClass::UseAfterFree
        | BugClass::HeapBufferOverflow
        | BugClass::StackBufferOverflow
        | BugClass::GlobalBufferOverflow
        | BugClass::NullDeref
        | BugClass::WildSegv
        | BugClass::UndefinedBehavior => {}
        _ => return false,
    }
    let Some(frames) = raw.pointer("/exception/stack").and_then(Value::as_array) else {
        return false;
    };
    if frames.is_empty() {
        return false;
    }
    // A target frame resolved → genuine site, never demote.
    if sink_from(raw).is_some() {
        return false;
    }
    // The fault is positively in the generated harness (not just an
    // unattributable symbol-less stack).
    frames.iter().any(|frame| {
        let func = string_at(frame, &["function"]).unwrap_or_default();
        let file = string_at(frame, &["file"]);
        !func.is_empty() && is_harness_frame(&func, file.as_deref())
    })
}

/// A recovered Go panic raised BY a `Must*` function. By Go convention a `MustX`
/// function is a panic-on-error wrapper around an `X` that returns an error
/// (fastjson `MustParse`, regexp `MustCompile`, template `Must`): panicking on
/// invalid input is its DOCUMENTED contract, not a defect — and the non-panic
/// variant `X` is the meaningful fuzz target, discovered and fuzzed separately.
/// Demoted to lab-only so the by-design panic doesn't read as a real finding.
///
/// Conservative: fires only for a recovered Go panic whose PANICKING frame (the
/// top non-runtime frame, i.e. the function that called `panic`) is itself the
/// `Must*` function. A genuine runtime panic (nil deref / index OOB) raised
/// deeper inside the callee surfaces a non-`Must*` top frame and is left alone.
fn is_go_must_panic(raw: &Value) -> bool {
    let name = string_at(raw, &["exception", "name"]).unwrap_or_default();
    let message = string_at(raw, &["exception", "message"]).unwrap_or_default();
    let is_go_panic = name.eq_ignore_ascii_case("ASAN_GO_PANIC")
        || name.eq_ignore_ascii_case("go-panic")
        || message.starts_with("Go panic");
    if !is_go_panic {
        return false;
    }
    let Some(frames) = raw.pointer("/exception/stack").and_then(Value::as_array) else {
        return false;
    };
    frames
        .iter()
        .find_map(|frame| {
            let func = string_at(frame, &["function"])?;
            (!func.is_empty() && !is_runtime_frame(&func)).then_some(func)
        })
        .is_some_and(|func| is_go_must_function(&func))
}

/// Whether a (possibly package-qualified) Go function name follows the `MustX`
/// panic-wrapper convention: `Must` immediately followed by an upper-case letter
/// (or nothing). `github.com/x/y.MustParse` and `(*T).MustCompile` match;
/// `Mustang` / `must_lower` do not.
fn is_go_must_function(qualified: &str) -> bool {
    let simple = qualified.rsplit('.').next().unwrap_or(qualified);
    let simple = simple.trim_matches(|c| matches!(c, '(' | ')' | '*' | ' '));
    simple
        .strip_prefix("Must")
        .is_some_and(|rest| rest.chars().next().is_none_or(|c| c.is_ascii_uppercase()))
}

/// A native C/C++ assertion (GF-415) whose failed expression is an ENUM-DOMAIN
/// PRECONDITION over a single discriminator — `x == A || x == B || x == C`, every
/// clause comparing the SAME identifier for equality against a NAMED constant (an
/// enum member, not a numeric/null literal). This is the "the discriminator must
/// be one of these enum values" contract (tinycbor `cbor_encode_floating_point`'s
/// `cbor_assert(fpType == CborHalfFloatType || fpType == CborFloatType || fpType
/// == CborDoubleType)`): the auto-harness fuzzes the discriminator parameter out
/// of its declared domain, so any out-of-range byte trips it — a harness-supplied
/// precondition, not a target defect. Demoted to lab-only (still surfaced), never
/// deleted.
///
/// Tightly gated so a GENUINE assertion still surfaces: requires (a) a native
/// assertion oracle, (b) at least TWO `IDENT == CONST` alternatives joined by
/// `||`, (c) the SAME left-hand identifier in every clause, and (d) every
/// right-hand side a named constant carrying an upper-case letter. A relational
/// invariant (`len < cap`, `i < count`, `ptr != NULL`) has no `==`-disjunction
/// shape and keeps its normal verdict.
fn is_native_assertion_enum_domain_precondition(raw: &Value) -> bool {
    let is_native_assert = string_at(raw, &["oracle", "name"]).as_deref()
        == Some("native-assertion-contract")
        || string_at(raw, &["rule_id"]).as_deref() == Some("GF-415");
    if !is_native_assert {
        return false;
    }
    let Some(expr) = oracle_evidence_value(raw, "expression") else {
        return false;
    };
    is_enum_domain_membership_expr(&expr)
}

fn is_enum_domain_membership_expr(expr: &str) -> bool {
    let clauses: Vec<&str> = expr.split("||").collect();
    if clauses.len() < 2 {
        return false;
    }
    let mut lhs_ident: Option<String> = None;
    for clause in clauses {
        let c = clause.trim_matches(|ch: char| ch.is_whitespace() || ch == '(' || ch == ')');
        let Some((lhs, rhs)) = c.split_once("==") else {
            return false;
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        if !is_simple_c_identifier(lhs) || !is_named_enum_constant(rhs) {
            return false;
        }
        match &lhs_ident {
            None => lhs_ident = Some(lhs.to_owned()),
            Some(prev) if prev != lhs => return false,
            _ => {}
        }
    }
    lhs_ident.is_some()
}

/// A single unqualified C identifier (the discriminator parameter): a letter/`_`
/// head then alnum/`_`. A field access (`e->type`) or compound expression is NOT
/// simple and is left alone (conservative).
fn is_simple_c_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A NAMED enum constant on the RHS of a domain check: an identifier (optionally
/// `::`/`.`-qualified) carrying at least one upper-case letter (`CborHalfFloatType`,
/// `CBOR_HALF`). Excludes numeric / `null` / lowercase-local operands so the
/// demotion only fires on a true enum-membership contract.
fn is_named_enum_constant(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.')
        && s.chars().any(|c| c.is_ascii_uppercase())
}

/// A Rust `assert!`-style RELATIONAL contract panic: the panic message ties two
/// caller-supplied operands together in a containment/ordering precondition
/// (`bytes::Bytes::slice_ref`: "subset is out of bounds: self = …, subset = …";
/// "subset pointer (…) is smaller than self pointer (…)"). The auto-harness builds
/// the receiver and the argument INDEPENDENTLY, so any input trips the contract —
/// a relational-precondition false positive (G6). Conservative: only fires when
/// the bug is NOT a memory-corruption sanitizer class (those classify away from
/// `Unknown`) and the message is NOT a standard-library bounds panic (which can be
/// a genuine OOB). Demoted to lab-only, never deleted.
fn is_relational_contract_panic(raw: &Value) -> bool {
    if classify_bug(raw) != BugClass::Unknown {
        return false;
    }
    let msg = string_at(raw, &["exception", "message"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    if msg.is_empty() {
        return false;
    }
    // Standard-library bounds panics can be real OOB bugs — never demote them.
    if msg.contains("the len is")
        || msg.contains("out of range for slice")
        || msg.contains("but the index is")
        || msg.contains("slice index starts at")
    {
        return false;
    }
    (msg.contains("subset")
        && (msg.contains("out of bounds")
            || msg.contains("smaller than")
            || msg.contains("contained")
            || msg.contains("self")))
        || msg.contains("must be contained")
        || msg.contains("is not contained")
        || msg.contains("must point into")
        || msg.contains("does not point into")
}

/// A fixed-width read of a too-short fuzzed slice — byteorder's documented length
/// precondition (#467). `ByteOrder::read_u32/u64/u128(buf: &[u8])` read a FIXED
/// `&buf[..N]` prefix and panic ("range end index N out of range for slice of
/// length M") when the fuzzed `buf` is shorter than one primitive unit. The
/// language's bounds check caught it safely; it is the same noise as any
/// byte-reader fed a too-short slice, not a memory-safety bug.
///
/// Gated tightly so a genuine over-read is never masked:
///   - the `range end index N` form is a CONSTANT-range slice read (`&buf[..N]`);
///     a real over-index produces the `the len is X but the index is Y` form,
///     which is explicitly left untouched ([`is_relational_contract_panic`] and
///     `stdlib_index_oob_panic_is_not_demoted` both preserve it), and
///   - `N` must be a primitive integer byte-width {1,2,4,8,16}: a parser that
///     reads a length field then over-indexes lands on an arbitrary `N`, never
///     exactly a primitive width, so its findings keep their normal verdict.
fn is_fixed_width_slice_read_panic(raw: &Value) -> bool {
    let msg = string_at(raw, &["exception", "message"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    // "...range end index {n} out of range for slice of length {m}"
    let Some((_, after)) = msg.split_once("range end index ") else {
        return false;
    };
    let Some((n_str, tail)) = after.split_once(" out of range for slice of length ") else {
        return false;
    };
    let Ok(n) = n_str.trim().parse::<u64>() else {
        return false;
    };
    let Some(m) = tail
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return false;
    };
    matches!(n, 1 | 2 | 4 | 8 | 16) && m < n
}

/// The govfuzz harness scaffolding (entry shims + the generated `main`), which
/// drives the input but is not where the target's bug lives. Shared with the
/// report writeup so the rendered crash Stack can trim these synthetic-driver
/// frames using the SAME predicate the sink computation relies on, instead of
/// duplicating the frame-name knowledge.
pub fn is_harness_frame(function: &str, file: Option<&str>) -> bool {
    let head = function_head(function);
    if head.starts_with("govfuzz_")
        // The generated decode helpers (`gf_c_string`, `gf_take_*`, ...) live in
        // the copied-in runtime header `govfuzz_decode.h`; a leak/crash whose top
        // frame is one of them is govfuzz scaffolding, not a target site.
        || head.starts_with("gf_")
        || head == "LLVMFuzzerTestOneInput"
        || head == "LLVMFuzzerRunDriver"
    {
        return true;
    }
    file.is_some_and(|file| {
        let lower = file.to_ascii_lowercase();
        (lower.contains("/auto/")
            && (lower.ends_with("main.cpp")
                || lower.ends_with("main.cc")
                || lower.ends_with("main.c")))
            // The copied-in decode/runtime headers (`govfuzz_decode.h`,
            // `govfuzz_cov.*`) and any `*_runtime/` tree (`c_runtime/`,
            // `rust_runtime/`, `java_runtime/`, ...) are govfuzz's own code.
            || lower.contains("govfuzz_decode")
            || lower.contains("govfuzz_cov")
            || lower.contains("_runtime/")
    })
}

/// Where execution goes wrong: the top project frame on the crash stack. Skips
/// sanitizer-runtime frames, allocator primitives, and the govfuzz harness.
/// Prefers the topmost frame that resolved to a source file (`Sink.file`/`line`
/// populated); falls back to the topmost meaningful frame even when it carries
/// only a function name.
fn sink_from(raw: &Value) -> Option<Sink> {
    let Some(frames) = raw.pointer("/exception/stack").and_then(Value::as_array) else {
        // No crash stack (an oracle hit) — derive the sink from the oracle's
        // declared source location when it carries one.
        return oracle_sink(raw);
    };
    let mut fallback: Option<Sink> = None;
    for frame in frames {
        let function = string_at(frame, &["function"]).unwrap_or_default();
        if function.is_empty() || is_runtime_frame(&function) || is_allocator_frame(&function) {
            continue;
        }
        let file = string_at(frame, &["file"]).filter(|file| !file.starts_with('('));
        if is_harness_frame(&function, file.as_deref())
            || is_libc_source_file(file.as_deref())
            || is_rust_stdlib_frame(&function, file.as_deref())
        {
            continue;
        }
        let sink = Sink {
            file: file.clone(),
            line: frame.get("line").and_then(Value::as_u64),
            function: function_head(&function),
        };
        if sink.file.is_some() {
            return Some(sink);
        }
        if fallback.is_none() {
            fallback = Some(sink);
        }
    }
    fallback.or_else(|| oracle_sink(raw))
}

/// Derive a [`Sink`] for an oracle hit from its declared `source` evidence —
/// the site-stable `file:line:function` location a native-assertion oracle
/// (GF-415) records — so oracle findings populate the report's sink columns
/// instead of leaving them blank. `None` for oracles that carry no source
/// location (their defect is behavioral; the evidence, not a sink, is the signal).
fn oracle_sink(raw: &Value) -> Option<Sink> {
    let source = oracle_evidence_value(raw, "source")?;
    parse_source_location(&source)
}

/// Read an oracle hit's `evidence[].value` for `key` from `oracle.evidence`.
fn oracle_evidence_value(raw: &Value, key: &str) -> Option<String> {
    raw.get("oracle")?
        .get("evidence")?
        .as_array()?
        .iter()
        .find(|item| item.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|item| item.get("value").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// Parse a `file:line:function` (or `file:line`, or bare `file`) assertion
/// source location into a [`Sink`]. The first purely-numeric `:`-delimited
/// component is the line; everything before it is the file, everything after is
/// the function.
fn parse_source_location(source: &str) -> Option<Sink> {
    let source = source.trim();
    if source.is_empty() {
        return None;
    }
    let parts: Vec<&str> = source.split(':').collect();
    let line_idx = parts
        .iter()
        .position(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    match line_idx {
        Some(idx) => {
            let file = parts[..idx].join(":");
            let function = parts[idx + 1..].join(":");
            Some(Sink {
                file: (!file.trim().is_empty()).then_some(file),
                line: parts[idx].parse::<u64>().ok(),
                // A bare `file:line` source carries no function. Leave it BLANK
                // rather than inventing the file basename as the function name — a
                // filename in a `sink_function` column is misleading (the static
                // emitter now supplies the real enclosing function as a third
                // `:function` segment when it knows it).
                function: function.trim().to_owned(),
            })
        }
        // No line component: treat the whole token as a function name.
        None => Some(Sink {
            file: None,
            line: None,
            function: source.to_owned(),
        }),
    }
}

/// Where attacker input enters: the fuzzed entry point (from `entry_path`) plus
/// the reproducer file that drives it.
fn source_from(raw: &Value, entry_path: Option<&EntryPath>) -> Option<Source> {
    let entry = entry_path?;
    let testcase = string_at(raw, &["paths", "testcase"])
        .or_else(|| Some(entry.source.clone()).filter(|source| !source.trim().is_empty()))
        .unwrap_or_else(|| "testcase.bin".to_owned());
    Some(Source {
        kind: entry.kind.clone(),
        entry: entry.target.clone(),
        testcase,
    })
}

/// Coarse memory-safety / fault classification derived from the sanitizer name,
/// exception name, and message. Drives the plain-English explanation and the
/// bug-class fix hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BugClass {
    HeapBufferOverflow,
    StackBufferOverflow,
    GlobalBufferOverflow,
    UseAfterFree,
    DoubleFree,
    MemoryLeak,
    NullDeref,
    WildSegv,
    UndefinedBehavior,
    Timeout,
    OutOfMemory,
    /// Reachable assertion / `abort()` / `SIGABRT` with no memory-safety class.
    ReachableAssertion,
    /// Integer or floating-point divide-by-zero (`SIGFPE`).
    DivideByZero,
    /// Stack exhaustion from uncontrolled / unbounded recursion (distinct from a
    /// stack-buffer-overflow, which corrupts a fixed on-stack buffer).
    StackExhaustion,
    /// An uncaught / unhandled exception escaping a managed runtime (e.g. a JVM
    /// `Throwable`), terminating the process.
    UncaughtException,
    /// A Rust bounds-checked panic — an array/slice index or slice-range that ran
    /// past the bounds (`ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS`, "index out of
    /// bounds", "range end index N out of range for slice of length M", "slice
    /// index starts at"). The language caught a DETECTED out-of-bounds access
    /// safely; the underlying defect is still an out-of-bounds read/write.
    IndexOutOfBounds,
    /// A TEMPORAL stack error — a stale/expired stack pointer used after its
    /// frame returned (`stack-use-after-return`, CWE-562) or its lexical scope
    /// ended (`stack-use-after-scope`, CWE-825). Distinct from the SPATIAL
    /// [`BugClass::StackBufferOverflow`] (CWE-121): the storage was reused, not
    /// overrun, so the fix is lifetime, not bounds.
    StaleStackPointerUse,
    Unknown,
}

impl BugClass {
    fn slug(self) -> &'static str {
        match self {
            Self::StaleStackPointerUse => "stale-stack-pointer-use",
            Self::HeapBufferOverflow => "heap-buffer-overflow",
            Self::StackBufferOverflow => "stack-buffer-overflow",
            Self::GlobalBufferOverflow => "global-buffer-overflow",
            Self::UseAfterFree => "use-after-free",
            Self::DoubleFree => "double-free",
            Self::MemoryLeak => "memory-leak",
            Self::NullDeref => "null-deref",
            Self::WildSegv => "segv",
            Self::UndefinedBehavior => "undefined-behavior",
            Self::Timeout => "timeout",
            Self::OutOfMemory => "out-of-memory",
            Self::ReachableAssertion => "reachable-assertion",
            Self::DivideByZero => "divide-by-zero",
            Self::StackExhaustion => "stack-exhaustion",
            Self::UncaughtException => "uncaught-exception",
            Self::IndexOutOfBounds => "index-out-of-bounds",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether a SEGV report's faulting address is in the first memory page
/// (`< 0x1000`). ASan prints `SEGV on unknown address 0x000000000010 (pc ...)`;
/// `hay` is the lower-cased name+message. A sub-page fault is a near-null
/// dereference (a null base pointer plus a small field/element offset), the
/// CWE-476 class — not a wild pointer (#30).
fn segv_sub_page_fault(hay: &str) -> bool {
    let Some(idx) = hay.find("address 0x") else {
        return false;
    };
    let hex: String = hay[idx + "address 0x".len()..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    if hex.is_empty() {
        return false;
    }
    u64::from_str_radix(&hex, 16).is_ok_and(|addr| addr < 0x1000)
}

fn classify_bug(raw: &Value) -> BugClass {
    let name = string_at(raw, &["exception", "name"]).unwrap_or_default();
    let sanitizer = string_at(raw, &["exception", "sanitizer"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let message = string_at(raw, &["exception", "message"]).unwrap_or_default();
    // Normalize `_`/`-` so `HEAP_BUFFER_OVERFLOW` and `heap-buffer-overflow`
    // both match the same needles.
    let hay = format!("{name} {message}")
        .to_ascii_lowercase()
        .replace('_', "-");
    let has = |needle: &str| hay.contains(needle);

    if has("use-after-free") {
        return BugClass::UseAfterFree;
    }
    if has("double-free") {
        return BugClass::DoubleFree;
    }
    // Temporal stack errors (stale/expired stack pointer) are a DISTINCT weakness
    // (CWE-825/562) from a spatial stack-buffer-overflow (CWE-121). Catch them
    // before the stack-overflow needles below so they don't fall through to
    // StackBufferOverflow (#29).
    if has("stack-use-after-return") || has("stack-use-after-scope") {
        return BugClass::StaleStackPointerUse;
    }
    if has("heap-buffer-overflow") {
        return BugClass::HeapBufferOverflow;
    }
    // Stack exhaustion from uncontrolled recursion is a distinct weakness
    // (CWE-674) from a fixed-buffer stack overflow (CWE-121). Catch the
    // recursion-driven forms (incl. Java `StackOverflowError`) BEFORE the
    // stack-buffer-overflow needles so `stack-overflow-recursion` is not
    // miscategorised as a buffer overflow. A bare `stack-overflow` with no
    // recursion signal stays a stack-buffer-overflow.
    if has("stack-exhaustion")
        || has("stackoverflowerror")
        || has("uncontrolled-recursion")
        || has("infinite-recursion")
        || has("infinite recursion")
        || has("deep-recursion")
        || has("deep recursion")
        || has("recursion-limit")
        || has("recursion limit")
        || has("recursion-depth")
        || has("recursion depth")
        || has("stack-overflow-recursion")
    {
        return BugClass::StackExhaustion;
    }
    if has("stack-buffer-overflow") || has("dynamic-stack-buffer-overflow") || has("stack-overflow")
    {
        return BugClass::StackBufferOverflow;
    }
    if has("global-buffer-overflow") {
        return BugClass::GlobalBufferOverflow;
    }
    if sanitizer == "lsan" || has("memory-leak") || has("detected memory leaks") {
        return BugClass::MemoryLeak;
    }
    if has("out-of-memory")
        || has("out of memory")
        || has("allocation-size-too-big")
        || has("requested allocation size")
        || has("rss-limit")
        || has("rss limit")
        || has("oom")
    {
        return BugClass::OutOfMemory;
    }
    if has("timeout") || has("timed out") {
        return BugClass::Timeout;
    }
    // Divide-by-zero is its own weakness (CWE-369), not generic UB. Catch it
    // BEFORE the `sanitizer == "ubsan"` clause below — UBSan reports integer
    // division by zero, but the most defensible leaf is CWE-369.
    if has("sigfpe")
        || has("divide-by-zero")
        || has("division-by-zero")
        || has("division by zero")
        || has("floating-point-exception")
        || has("floating point exception")
        // Ruby's native ZeroDivisionError message reads "divided by 0", not
        // "division by zero"; match the exception class name too.
        || has("zerodivision")
        || has("divided by 0")
    {
        return BugClass::DivideByZero;
    }
    if sanitizer == "ubsan"
        || has("undefined-behavior")
        || has("signed-integer-overflow")
        || has("integer-overflow")
        || has("shift-exponent")
        || has("invalid-shift")
        || has("float-cast-overflow")
        || has("misaligned-address")
    {
        return BugClass::UndefinedBehavior;
    }
    // An uncaught/unhandled exception escaping a managed runtime (Jazzer-style
    // JVM throwable, etc.) terminates the process — CWE-248.
    if has("uncaught exception")
        || has("uncaught-exception")
        || has("unhandled exception")
        || has("unhandled-exception")
        || has("uncaught throwable")
        || has("uncaught-throwable")
        || has("exception in thread")
    {
        return BugClass::UncaughtException;
    }
    if has("segv") || has("sigsegv") || has("segmentation") || has("access-violation") {
        // A near-null fault — a null base pointer plus a small struct-field /
        // array-element offset — lands at a SUB-PAGE address, not exactly zero. The
        // old `0x000000000000` (12-zero) needle missed those; treat any sub-page
        // fault address as a NULL deref (CWE-476) rather than a wild SEGV (#30).
        if has("0x000000000000") || has("null") || segv_sub_page_fault(&hay) {
            return BugClass::NullDeref;
        }
        return BugClass::WildSegv;
    }
    // A Rust bounds-checked panic — an array/slice index or slice-range past the
    // bounds (`ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS`; "index out of bounds"; "range
    // end index N out of range for slice of length M"; "slice index starts at").
    // The language DETECTED the out-of-bounds access and aborted safely, so the
    // underlying defect is an out-of-bounds read/write (CWE-125/787), not a generic
    // reachable assertion. Checked AFTER the sanitizer memory-corruption classes (a
    // real ASan heap/stack/global overflow names itself and returns above) and
    // BEFORE the SIGABRT/abort clause (an aborting panic) so the specific class wins.
    if has("index out of bounds")
        || has("index-out-of-bounds")
        || has("out of range for slice")
        || has("slice index starts at")
    {
        return BugClass::IndexOutOfBounds;
    }
    // Reachable assertion / `abort()` (`SIGABRT`) with no more-specific class —
    // a fuzzer-reachable, deliberately-fatal check (CWE-617). Kept LAST so any
    // sanitizer class above wins (sanitizers also call `abort()` after
    // reporting), and so it never shadows the memory-safety needles.
    if has("sigabrt")
        || has("abort")
        || has("assertion failed")
        || has("assertion `")
        || has("assert(")
        || has("__assert")
    {
        return BugClass::ReachableAssertion;
    }
    BugClass::Unknown
}

/// Map the finding's bug class to its CWE identifier(s) — primary first, with a
/// secondary id where the class spans more than one CWE — plus the primary CWE's
/// human-readable name. Returns `(vec![], None)` for an unknown bug class.
fn cwe_for_finding(raw: &Value) -> (Vec<String>, Option<String>) {
    let class = classify_bug(raw);
    // Read vs write disambiguates the overflow CWEs; the UB subtype distinguishes
    // signed-overflow (CWE-190) from other undefined behavior (CWE-682).
    let hay = format!(
        "{} {}",
        string_at(raw, &["exception", "name"]).unwrap_or_default(),
        string_at(raw, &["exception", "message"]).unwrap_or_default()
    )
    .to_ascii_lowercase()
    .replace('_', "-");
    let is_read = hay.contains("read");
    let is_write = hay.contains("write");

    let (primary, secondary): (&str, Option<&str>) = match class {
        BugClass::HeapBufferOverflow => (
            "CWE-122",
            if is_write {
                Some("CWE-787")
            } else if is_read {
                Some("CWE-125")
            } else {
                None
            },
        ),
        BugClass::StackBufferOverflow => ("CWE-121", None),
        // A temporal stack error: stack-use-after-return is "Return of Stack
        // Variable Address" (CWE-562); stack-use-after-scope is the broader
        // "Expired Pointer Dereference" (CWE-825). Pick the matching primary and
        // carry the other as secondary (#29).
        BugClass::StaleStackPointerUse => {
            if hay.contains("use-after-return") {
                ("CWE-562", Some("CWE-825"))
            } else {
                ("CWE-825", Some("CWE-562"))
            }
        }
        // A global-buffer-overflow is an out-of-bounds access; pick the
        // read/write CWE that matches the sanitizer report (write by default).
        BugClass::GlobalBufferOverflow => {
            if is_read {
                ("CWE-125", None)
            } else {
                ("CWE-787", None)
            }
        }
        BugClass::UseAfterFree => ("CWE-416", None),
        BugClass::DoubleFree => ("CWE-415", None),
        BugClass::MemoryLeak => ("CWE-401", None),
        BugClass::NullDeref => ("CWE-476", None),
        // A wild (non-null) bad access — model as an out-of-bounds access,
        // matching the read/write direction when the report records one.
        BugClass::WildSegv => {
            if is_read {
                ("CWE-125", None)
            } else {
                ("CWE-787", None)
            }
        }
        BugClass::UndefinedBehavior => {
            if hay.contains("signed-integer-overflow") || hay.contains("integer-overflow") {
                ("CWE-190", None)
            } else {
                ("CWE-682", None)
            }
        }
        BugClass::Timeout => ("CWE-834", Some("CWE-400")),
        BugClass::OutOfMemory => ("CWE-789", Some("CWE-400")),
        BugClass::ReachableAssertion => ("CWE-617", None),
        BugClass::DivideByZero => ("CWE-369", None),
        BugClass::StackExhaustion => ("CWE-674", None),
        BugClass::UncaughtException => ("CWE-248", None),
        // A bounds-checked panic is a DETECTED out-of-bounds access; direction is
        // usually unstated, so default to CWE-125 (read) with CWE-787 (write)
        // secondary, and flip when the message names a write (`copy_from_slice`,
        // `copy_within`, `clone_from_slice`, or an explicit "write").
        BugClass::IndexOutOfBounds => {
            let is_oob_write = is_write
                || hay.contains("copy-from-slice")
                || hay.contains("copy-within")
                || hay.contains("clone-from-slice");
            if is_oob_write {
                ("CWE-787", Some("CWE-125"))
            } else {
                ("CWE-125", Some("CWE-787"))
            }
        }
        // No bug-class CWE (e.g. an ORACLE_* behavioral/assertion finding). Fall
        // back to the matched rule's CWE so the "every finding carries a CWE in
        // every report format" contract holds on the auto path too (campaign fix:
        // GF-415 oracle hits used to emit a blank CWE in findings.csv). Mirrors
        // report::ensure_finding_cwe's rule_id step.
        BugClass::Unknown => return cwe_from_rule_id(raw),
    };

    let mut ids = vec![primary.to_owned()];
    if let Some(secondary) = secondary {
        ids.push(secondary.to_owned());
    }
    (ids, Some(cwe_name(primary).to_owned()))
}

/// Resolve a finding's CWE from its `rule_id` via the rule catalog, or empty.
fn cwe_from_rule_id(raw: &Value) -> (Vec<String>, Option<String>) {
    let Some(rule) = string_at(raw, &["rule_id"]).and_then(|id| finding_rules::by_id(&id)) else {
        return (Vec::new(), None);
    };
    (vec![rule.cwe.to_owned()], Some(rule.name.to_owned()))
}

/// Canonical short name for a CWE id used by the bug-class mapping.
fn cwe_name(id: &str) -> &'static str {
    match id {
        "CWE-121" => "Stack-based Buffer Overflow",
        "CWE-122" => "Heap-based Buffer Overflow",
        "CWE-125" => "Out-of-bounds Read",
        "CWE-787" => "Out-of-bounds Write",
        "CWE-190" => "Integer Overflow or Wraparound",
        "CWE-401" => "Missing Release of Memory after Effective Lifetime",
        "CWE-415" => "Double Free",
        "CWE-416" => "Use After Free",
        "CWE-476" => "NULL Pointer Dereference",
        "CWE-682" => "Incorrect Calculation",
        "CWE-789" => "Memory Allocation with Excessive Size Value",
        "CWE-834" => "Excessive Iteration",
        "CWE-248" => "Uncaught Exception",
        "CWE-369" => "Divide By Zero",
        "CWE-617" => "Reachable Assertion",
        "CWE-674" => "Uncontrolled Recursion",
        "CWE-562" => "Return of Stack Variable Address",
        "CWE-825" => "Expired Pointer Dereference",
        _ => "Uncategorized Weakness",
    }
}

/// Plain-English, jargon-free description of the bug: what it is, where it
/// surfaced (the sink function), the impact in lay terms, and that a fuzzed
/// reproducer triggers it.
fn explanation_for(raw: &Value, sink: Option<&Sink>, source: &Option<Source>) -> Option<String> {
    let class = classify_bug(raw);
    let fn_ref = sink
        .map(|sink| format!("`{}`", sink.function))
        .unwrap_or_else(|| "the affected code".to_owned());
    let testcase = source
        .as_ref()
        .map(|source| source.testcase.clone())
        .or_else(|| string_at(raw, &["paths", "testcase"]))
        .unwrap_or_else(|| "testcase.bin".to_owned());
    let trigger = format!("Triggered by the attached test input (`{testcase}`).");
    let body = match class {
        BugClass::MemoryLeak => format!(
            "This is a memory leak: while processing a crafted input, the code allocated memory in {fn_ref} and never freed it. An attacker who can supply input to this code can exhaust memory by repeating it, which can crash the program or starve the machine."
        ),
        BugClass::HeapBufferOverflow | BugClass::GlobalBufferOverflow => format!(
            "This is a buffer overflow: while processing a crafted input, {fn_ref} read or wrote past the end of a memory buffer. Out-of-bounds access can corrupt memory, leak data, crash the program, and in some cases be steered into running attacker code."
        ),
        BugClass::StackBufferOverflow => format!(
            "This is a stack buffer overflow: while processing a crafted input, {fn_ref} wrote past the end of a buffer on the call stack. Overwriting the stack can crash the program and is a classic path to running attacker-controlled code."
        ),
        BugClass::StaleStackPointerUse => format!(
            "This is a stale stack-pointer use: while processing a crafted input, {fn_ref} used a pointer to a local (stack) variable after that variable's lifetime had ended — its function returned or its block closed — so the memory had already been reused for something else. Reading or writing through such a stale pointer corrupts unrelated data, can crash the program, and is exploitable."
        ),
        BugClass::UseAfterFree => format!(
            "This is a use-after-free: while processing a crafted input, {fn_ref} used memory that had already been freed. Reusing freed memory can corrupt data, crash the program, and is often exploitable for code execution."
        ),
        BugClass::DoubleFree => format!(
            "This is a double free: while processing a crafted input, {fn_ref} freed the same memory twice. That corrupts the memory allocator's bookkeeping and can crash the program or be exploited."
        ),
        BugClass::NullDeref => format!(
            "This is a null-pointer dereference: while processing a crafted input, {fn_ref} followed a pointer that was empty (null), so the program tried to use address zero and crashed. An attacker who can supply this input can reliably crash the program (denial of service)."
        ),
        BugClass::WildSegv => format!(
            "This is an invalid-memory access (segmentation fault): while processing a crafted input, {fn_ref} touched a memory address it should not have, and the program crashed. An attacker who can supply this input can crash the program, and such faults sometimes lead to worse."
        ),
        BugClass::UndefinedBehavior => format!(
            "This is undefined behavior: while processing a crafted input, {fn_ref} performed an operation the language leaves undefined (for example arithmetic that overflows or an out-of-range shift). The result is unpredictable and can produce wrong answers or crashes."
        ),
        BugClass::Timeout => format!(
            "This input makes the code run far too long: while processing a crafted input, {fn_ref} got stuck doing excessive work (a hang or near-endless loop). An attacker who can supply this input can make the program unresponsive (denial of service)."
        ),
        BugClass::OutOfMemory => format!(
            "This input makes the code use far too much memory: while processing a crafted input, the program around {fn_ref} requested or held more memory than was available and ran out. An attacker who can supply this input can crash the program or starve the machine (denial of service)."
        ),
        BugClass::ReachableAssertion => format!(
            "This is a reachable assertion / abort: while processing a crafted input, {fn_ref} hit an internal consistency check (an assertion or `abort()`) and the program deliberately killed itself. An attacker who can supply this input can reliably crash the program (denial of service); the check also marks an input the code did not expect to be reachable."
        ),
        BugClass::DivideByZero => format!(
            "This is a divide-by-zero: while processing a crafted input, {fn_ref} divided by zero (or took a remainder by zero), raising a fatal arithmetic exception. An attacker who can supply this input can crash the program (denial of service)."
        ),
        BugClass::StackExhaustion => format!(
            "This is stack exhaustion from runaway recursion: while processing a crafted input, {fn_ref} recursed without an effective depth bound until the call stack was exhausted and the program crashed. An attacker who can supply this input can crash the program (denial of service)."
        ),
        BugClass::UncaughtException => format!(
            "This is an uncaught exception: while processing a crafted input, {fn_ref} raised an exception that nothing handled, so the managed runtime terminated. An attacker who can supply this input can crash the program (denial of service); the missing handler should be reviewed."
        ),
        BugClass::IndexOutOfBounds => format!(
            "This is an out-of-bounds index: while processing a crafted input, {fn_ref} tried to read or write past the end of an array or slice. The language's bounds check caught it and stopped the program (denial of service); in a language without that check the same defect would be an out-of-bounds memory access, so the missing length validation should be fixed."
        ),
        BugClass::Unknown => format!(
            "While processing a crafted input, the program hit a fault in {fn_ref} and stopped. At minimum this lets an attacker who can supply this input crash the program; the underlying defect should be reviewed."
        ),
    };
    Some(format!("{body} {trigger}"))
}

fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::RealReachable => 0,
        Verdict::LikelyReachable => 1,
        Verdict::LabOnly => 2,
        Verdict::Blocked => 3,
        Verdict::Unknown => 4,
    }
}

fn impact_rank(impact: Impact) -> u8 {
    match impact {
        Impact::Critical => 0,
        Impact::High => 1,
        Impact::Medium => 2,
        Impact::Low => 3,
        Impact::Info => 4,
        Impact::Unknown => 5,
    }
}

fn confidence_rank(confidence: ActionabilityConfidence) -> u8 {
    match confidence {
        ActionabilityConfidence::High => 0,
        ActionabilityConfidence::Medium => 1,
        ActionabilityConfidence::Low => 2,
    }
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let current = path
        .iter()
        .try_fold(value, |current, component| current.get(*component))?;
    current
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    let Some(value) = path
        .iter()
        .try_fold(value, |current, component| current.get(*component))
    else {
        return Vec::new();
    };
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str().filter(|text| !text.trim().is_empty()))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
