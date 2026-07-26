// SPDX-License-Identifier: Apache-2.0

//! Per-language histogram of what actually stopped a target from being fuzzed.
//!
//! A sweep already reports how many targets landed in `unsupported_params` or
//! `report_only`. It does not report WHY, and recovering that meant hand-reading
//! per-target logs. Every lever that moved spat's built count came out of doing
//! exactly that by hand — histogramming the first error line of each failing
//! target, fixing the most common class, and re-measuring. The levers that were
//! adopted because they seemed obviously right, and never measured, are the ones
//! that turned out to be wrong.
//!
//! This module makes that loop a first-class output, for every language rather
//! than the one someone happened to be debugging. It is purely diagnostic: it
//! reads finished [`AttemptResult`]s and never influences an outcome.

use std::collections::BTreeMap;

use crate::auto::attempt::{AttemptResult, Outcome};
use crate::auto::candidate::Lang;

/// One row: a language, the outcome bucket, and the normalized proximate cause.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BlockerKey {
    pub(crate) language: String,
    pub(crate) category: String,
    pub(crate) detail: String,
}

/// Collapse a diagnostic into something that GROUPS. Raw compiler text names the
/// specific type, unit, or symbol at fault, so a hundred instances of one class
/// of failure look like a hundred distinct problems and the histogram says
/// nothing. Quoted and backticked spans become `X` and bare integers become `N`,
/// which is what the hand-rolled `sed 's/"[^"]*"/"X"/g'` pipeline did.
pub(crate) fn normalize_detail(raw: &str) -> String {
    // Usually the first line carries the proximate cause; GNAT and clang both
    // continue with context lines that vary per instance. Some build tools lead
    // with a banner instead — MSBuild prints "Build FAILED." and only then the
    // `error NETSDK1045: ...` that says what to fix — so a banner is skipped in
    // favour of the first line that names an error. Without this, every C#
    // failure in a sweep collapsed into one uninformative row.
    let first = first_informative_line(raw);
    // Drop a leading `path/file.ext:12:34:` location prefix — the location is
    // per-instance, the message after it is the class.
    let without_location = strip_location_prefix(first);
    let mut out = String::with_capacity(without_location.len());
    let mut chars = without_location.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' | '`' | '\'' => {
                // Consume through the closing delimiter. An unterminated quote
                // (truncated compiler tail) just ends the span at end of line.
                //
                // A backtick closes with EITHER a backtick or an apostrophe:
                // GNAT and GCC write `foo', while rustc, cargo and every
                // interpreted lane write `foo`. Accepting only the apostrophe
                // made a backtick pair run past its real end to the next
                // apostrophe on the line, so the quoted identifier leaked into
                // the key and each distinct name became its own histogram row —
                // the exact grouping this function exists to produce.
                let closes = |c: char| {
                    if ch == '`' {
                        c == '`' || c == '\''
                    } else {
                        c == ch
                    }
                };
                for inner in chars.by_ref() {
                    if closes(inner) {
                        break;
                    }
                }
                out.push_str("\"X\"");
            }
            c if c.is_ascii_digit() => {
                // A digit run glued to the end of a word is part of an
                // identifier, not a per-instance number: diagnostic codes
                // (`NETSDK1045`, `CS0618`, `C2065`, `E0308`) are exactly what an
                // operator searches for, and collapsing them to `N` erased the
                // one token that names the problem. Only free-standing numbers
                // — line numbers, counts, offsets — collapse.
                let glued_to_word = out
                    .chars()
                    .last()
                    .is_some_and(|p| p.is_ascii_alphanumeric());
                if glued_to_word {
                    out.push(c);
                    while let Some(next) = chars.peek() {
                        if next.is_ascii_digit() {
                            out.push(*next);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                } else {
                    while chars.peek().is_some_and(char::is_ascii_digit) {
                        chars.next();
                    }
                    out.push('N');
                }
            }
            c => out.push(c),
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    // Long `Other` tails are whole compiler transcripts; keep the head, which is
    // where the proximate cause sits.
    if collapsed.chars().count() > 160 {
        collapsed.chars().take(160).collect::<String>() + "…"
    } else {
        collapsed
    }
}

/// Lines that announce a failure without describing it. Keying the histogram on
/// one of these merges every distinct cause into a single row.
fn is_banner_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let lower = lower.trim().trim_end_matches('.');
    // A `note:` is context the compiler attaches to a diagnostic — "X has been
    // explicitly marked deprecated here" — never the diagnosis. Keying on one
    // names a line of the project's source instead of what stopped the build.
    if lower.starts_with("note:") || lower.contains(": note:") {
        return true;
    }
    // Likewise an "In file included from ..." chain header.
    if lower.starts_with("in file included from") || lower.starts_with("in function") {
        return true;
    }
    matches!(
        lower,
        "build failed"
            | "build failed:"
            | "compilation failed"
            | "error"
            | "make: *** [all] error 1"
            | "gprbuild: *** compilation phase failed"
            | "failed"
    ) || lower.starts_with("error: could not compile")
        || lower.starts_with("error: build failed")
}

/// The first line that actually describes the failure, skipping banners.
fn first_informative_line(raw: &str) -> &str {
    let mut fallback = "";
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if fallback.is_empty() {
            fallback = trimmed;
        }
        if is_banner_line(trimmed) {
            continue;
        }
        return trimmed;
    }
    fallback
}

/// Strip a `file:line:col:` / `file:line:` prefix. Deliberately conservative: it
/// only fires when the segments after the first colon are numeric, so a message
/// that merely contains a colon is left alone.
fn strip_location_prefix(line: &str) -> &str {
    let mut rest = line;
    loop {
        let Some((head, tail)) = rest.split_once(':') else {
            return rest;
        };
        let head = head.trim();
        // A path segment (first hop) or a number (line/column).
        let is_location_segment = !head.is_empty()
            && (head.chars().all(|c| c.is_ascii_digit())
                || head.contains('/')
                || head.contains('.'));
        if !is_location_segment {
            return rest;
        }
        rest = tail.trim_start();
        // Once past the numeric segments the remainder is the message. Detect
        // that by peeking: if the next segment is not numeric, stop here.
        let next_is_number = rest
            .split_once(':')
            .is_some_and(|(h, _)| !h.is_empty() && h.trim().chars().all(|c| c.is_ascii_digit()));
        if !next_is_number {
            // `error: ...` / `warning: ...` still carries a severity segment.
            if let Some(stripped) = rest.strip_prefix("error:") {
                return stripped.trim_start();
            }
            return rest;
        }
    }
}

/// The proximate blocker for a target that did NOT reach `built_and_fuzzed`, or
/// `None` when it did (nothing to explain).
pub(crate) fn blocker_for(result: &AttemptResult) -> Option<BlockerKey> {
    let language = lang_tag(result.candidate.lang).to_owned();
    let (category, detail) = match &result.outcome {
        Outcome::BuiltAndFuzzed { .. } => return None,
        Outcome::UnsupportedParams { reason } => ("unsupported_params", normalize_detail(reason)),
        Outcome::ReportOnly {
            reason, dialect, ..
        } => {
            let detail = match dialect {
                Some(dialect) => format!("[{dialect}] {}", normalize_detail(reason)),
                None => normalize_detail(reason),
            };
            ("report_only", detail)
        }
        Outcome::FailedBuild { last_errors, .. } => (
            "failed_build",
            last_errors
                .first()
                .map_or_else(|| "no classified error".to_owned(), build_error_detail),
        ),
        // The symbols are per-target; the class is what groups.
        Outcome::UnrecoverableLink { missing, .. } => (
            "unrecoverable_link",
            format!("{} undefined symbol(s) after repair", missing.len().min(1)),
        ),
        Outcome::UnrecoverableRuntime { reason, .. } => {
            ("unrecoverable_runtime", normalize_detail(reason))
        }
        // `entry_miss` is already a stable sub-category, so it groups as-is.
        Outcome::BuiltNotEntered { entry_miss, .. } => ("built_not_entered", entry_miss.clone()),
        Outcome::Built { .. } => ("built_not_fuzzed", "built, no fuzz pass ran".to_owned()),
    };
    Some(BlockerKey {
        language,
        category: category.to_owned(),
        detail,
    })
}

/// A classified build error rendered as its CLASS, not its instance. `Other` is
/// the interesting bucket — the classifier did not recognise it, which is
/// exactly where an unimplemented lever hides — so its raw tail is normalized
/// and kept.
fn build_error_detail(error: &build_classifier::BuildErrorKind) -> String {
    use build_classifier::BuildErrorKind as E;
    match error {
        E::MissingHeader { .. } => "missing header".to_owned(),
        E::MissingType { .. } => "missing type".to_owned(),
        E::IncompleteType { .. } => "incomplete type".to_owned(),
        E::MissingMacro { .. } => "missing macro".to_owned(),
        E::UndefinedSymbol { .. } => "undefined symbol".to_owned(),
        E::UndeclaredFunction { .. } => "undeclared function".to_owned(),
        E::MissingSharedLib { .. } => "missing shared library".to_owned(),
        E::MissingAdaWith { .. } => "missing Ada unit".to_owned(),
        E::MissingAdaSymbol { .. } => "missing Ada symbol".to_owned(),
        E::MissingAdaPackageBody { .. } => "missing Ada package body".to_owned(),
        E::UncompilableAdaBody { .. } => "uncompilable Ada body".to_owned(),
        E::MissingGprImport { .. } => "missing GPR import".to_owned(),
        E::MalformedFunctionDecl { .. } => "malformed function declaration".to_owned(),
        E::Other { tail } => normalize_detail(tail),
    }
}

fn lang_tag(l: Lang) -> &'static str {
    match l {
        Lang::Ada => "ada",
        Lang::C => "c",
        Lang::Cpp => "cpp",
        Lang::Rust => "rust",
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Perl => "perl",
        Lang::Go => "go",
        Lang::Cobol => "cobol",
        Lang::Fortran => "fortran",
        Lang::CSharp => "csharp",
        Lang::Js => "javascript",
        Lang::Ts => "typescript",
        Lang::Ruby => "ruby",
        Lang::Lua => "lua",
        Lang::Php => "php",
    }
}

/// Counted blockers, ordered most-common-first within each language.
#[derive(Debug, Default)]
pub(crate) struct BlockerHistogram {
    counts: BTreeMap<BlockerKey, usize>,
    fuzzed: BTreeMap<String, usize>,
}

impl BlockerHistogram {
    pub(crate) fn from_results(results: &[AttemptResult]) -> Self {
        let mut histogram = Self::default();
        for result in results {
            let language = lang_tag(result.candidate.lang).to_owned();
            match blocker_for(result) {
                Some(key) => *histogram.counts.entry(key).or_default() += 1,
                None => *histogram.fuzzed.entry(language).or_default() += 1,
            }
        }
        histogram
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Rows sorted by language, then by descending count — the order the manual
    /// `sort -rn` produced, which is the order you work the list in.
    pub(crate) fn rows(&self) -> Vec<(&BlockerKey, usize)> {
        let mut rows: Vec<(&BlockerKey, usize)> = self
            .counts
            .iter()
            .map(|(key, count)| (key, *count))
            .collect();
        rows.sort_by(|(left_key, left_count), (right_key, right_count)| {
            left_key
                .language
                .cmp(&right_key.language)
                .then(right_count.cmp(left_count))
                .then(left_key.category.cmp(&right_key.category))
                .then(left_key.detail.cmp(&right_key.detail))
        });
        rows
    }

    pub(crate) fn render(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "\ngovfuzz auto: residual blockers (targets that did NOT reach built_and_fuzzed)\n",
        );
        let mut current_language = String::new();
        for (key, count) in self.rows() {
            if key.language != current_language {
                current_language = key.language.clone();
                let fuzzed = self.fuzzed.get(&current_language).copied().unwrap_or(0);
                let blocked: usize = self
                    .counts
                    .iter()
                    .filter(|(k, _)| k.language == current_language)
                    .map(|(_, c)| *c)
                    .sum();
                out.push_str(&format!(
                    "  {current_language}: {fuzzed} fuzzed, {blocked} blocked\n"
                ));
            }
            out.push_str(&format!(
                "    {count:>5}  {:<20} {}\n",
                key.category, key.detail
            ));
        }
        out
    }

    /// Machine-readable form for `run.json` consumers and for diffing one sweep
    /// against another, which is how a lever gets judged.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.rows()
                .into_iter()
                .map(|(key, count)| {
                    serde_json::json!({
                        "language": key.language,
                        "category": key.category,
                        "detail": key.detail,
                        "count": count,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backtick pair must be redacted as one span. Closing only on an
    /// apostrophe made the span run past its end to the next apostrophe on the
    /// line, so the name leaked out and every distinct package or symbol became
    /// its own histogram row instead of grouping.
    #[test]
    fn a_backtick_pair_redacts_as_one_span_whichever_way_it_closes() {
        let modern = normalize_detail(
            "target `flask.cli` is not loadable: missing module `werkzeug` (not installed) \
             — ModuleNotFoundError: No module named 'werkzeug'",
        );
        assert!(
            !modern.contains("werkzeug"),
            "the package name must not leak into the key: {modern}"
        );
        assert!(
            modern.contains("missing module \"X\""),
            "the marker must survive redaction so the row is readable: {modern}"
        );

        // Two different packages must produce the SAME key — that is the point.
        let other = normalize_detail(
            "target `django.apps` is not loadable: missing module `asgiref` (not installed) \
             — ModuleNotFoundError: No module named 'asgiref'",
        );
        assert_eq!(modern, other, "distinct packages must group into one row");

        // GNAT/GCC's `foo' form still redacts as one span.
        let gnat = normalize_detail("error: `Foo' is undefined here");
        assert_eq!(gnat, "error: \"X\" is undefined here");

        // rustc's backtick pairs group across identifiers too.
        assert_eq!(
            normalize_detail("error[E0425]: cannot find value `alpha` in this scope"),
            normalize_detail("error[E0425]: cannot find value `beta` in this scope"),
        );
    }

    #[test]
    fn a_build_banner_never_becomes_the_histogram_key() {
        // MSBuild's real diagnostic is two lines below its banner. Keying on the
        // banner collapsed every C# failure in a 500-project sweep into one row
        // that said nothing about what to fix.
        let msbuild = "Build FAILED.\n\n/usr/lib/dotnet/sdk/8.0.129/Sdks/Microsoft.NET.Sdk/\
                       targets/Microsoft.NET.TargetFrameworkInference.targets(166,5): error \
                       NETSDK1045: The current .NET SDK does not support targeting .NET 10.0.";
        let detail = normalize_detail(msbuild);
        assert!(
            detail.contains("NETSDK1045"),
            "the actionable diagnostic must survive, code intact: {detail}"
        );
        assert!(!detail.starts_with("Build FAILED"), "{detail}");
        // A per-instance number still collapses so instances group.
        assert!(
            !detail.contains("166"),
            "line numbers still collapse: {detail}"
        );

        // A transcript that is nothing BUT a banner still yields that banner
        // rather than an empty key.
        assert_eq!(normalize_detail("Build FAILED.\n"), "Build FAILED.");

        // A first line that is already informative is still preferred.
        let gnat = "spat.adb:31:07: error: \"Foo\" is undefined\ncompilation failed";
        assert!(normalize_detail(gnat).contains("is undefined"));

        // A compiler NOTE is context, not a cause: keying on one reported
        // "note: X has been explicitly marked deprecated here" as the blocker.
        let with_note = "/p/h.h:9:1: note: 'old_api' has been explicitly marked \
                         deprecated here\n/p/a.c:4:5: error: use of undeclared \
                         identifier 'ctx'";
        let detail = normalize_detail(with_note);
        assert!(detail.contains("undeclared identifier"), "{detail}");
        assert!(!detail.contains("deprecated"), "{detail}");

        // An include-chain header is not a cause either.
        let chain = "In file included from /p/a.c:1:\n/p/b.h:3:9: error: missing type";
        assert!(normalize_detail(chain).contains("missing type"));
    }

    #[test]
    fn quoted_spans_and_numbers_collapse_so_instances_group() {
        let a = normalize_detail("expected type \"Spat.Subject_Name\" found type \"Duration\"");
        let b = normalize_detail("expected type \"Foo.Bar\" found type \"Integer\"");
        assert_eq!(a, b, "two instances of one class must share a key");
        assert_eq!(a, "expected type \"X\" found type \"X\"");
    }

    #[test]
    fn a_source_location_prefix_is_stripped() {
        assert_eq!(
            normalize_detail("main.adb:31:04: error: \"GNATCOLL\" is not visible"),
            "\"X\" is not visible"
        );
    }

    #[test]
    fn a_message_containing_a_colon_is_not_mistaken_for_a_location() {
        assert_eq!(
            normalize_detail("note: candidate function not viable"),
            "note: candidate function not viable"
        );
    }

    #[test]
    fn only_the_first_nonempty_line_is_used() {
        assert_eq!(
            normalize_detail("\n  first thing failed\nsecond line\nthird line"),
            "first thing failed"
        );
    }

    #[test]
    fn an_unterminated_quote_does_not_swallow_the_rest_silently() {
        // Truncated compiler tails are common; the span just ends at the line end.
        assert_eq!(
            normalize_detail("cannot find \"widget"),
            "cannot find \"X\""
        );
    }

    #[test]
    fn an_unrecognised_build_error_keeps_its_normalized_tail() {
        let detail = build_error_detail(&build_classifier::BuildErrorKind::Other {
            tail: "x.adb:9:1: error: operator for type \"P\" not directly visible".to_owned(),
        });
        assert_eq!(detail, "operator for type \"X\" not directly visible");
    }

    #[test]
    fn a_recognised_build_error_reports_its_class_not_its_instance() {
        let detail = build_error_detail(&build_classifier::BuildErrorKind::MissingHeader {
            path: "zlib.h".to_owned(),
        });
        assert_eq!(detail, "missing header");
    }

    #[test]
    fn a_built_and_fuzzed_target_has_no_blocker() {
        let result = fuzzed_result(Lang::Ada);
        assert!(blocker_for(&result).is_none());
    }

    #[test]
    fn rows_are_ordered_by_descending_count_within_a_language() {
        let results = vec![
            unsupported_result(Lang::Ada, "cannot drive param of type \"A\""),
            unsupported_result(Lang::Ada, "cannot drive param of type \"B\""),
            report_only_result(Lang::Ada, "legacy dialect"),
        ];
        let histogram = BlockerHistogram::from_results(&results);
        let rows = histogram.rows();
        assert_eq!(rows[0].1, 2, "the two-instance class must come first");
        assert_eq!(rows[0].0.category, "unsupported_params");
        assert_eq!(rows[1].1, 1);
    }

    #[test]
    fn languages_are_counted_separately() {
        let results = vec![
            unsupported_result(Lang::Ada, "cannot drive param of type \"A\""),
            unsupported_result(Lang::C, "cannot drive param of type \"B\""),
        ];
        let histogram = BlockerHistogram::from_results(&results);
        let rows = histogram.rows();
        assert_eq!(rows.len(), 2, "one row per language, not a merged row");
        assert_eq!(rows[0].0.language, "ada");
        assert_eq!(rows[1].0.language, "c");
    }

    #[test]
    fn the_render_names_the_fuzzed_and_blocked_split_per_language() {
        let results = vec![
            fuzzed_result(Lang::Ada),
            unsupported_result(Lang::Ada, "cannot drive param of type \"A\""),
        ];
        let rendered = BlockerHistogram::from_results(&results).render();
        assert!(rendered.contains("ada: 1 fuzzed, 1 blocked"), "{rendered}");
    }

    fn candidate(lang: Lang) -> crate::auto::candidate::Candidate {
        crate::auto::candidate::Candidate {
            harness_id: "H-TEST".to_owned(),
            lang,
            source_path: std::path::PathBuf::from("src/thing.rs"),
            line: 1,
            name: "thing".to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    fn result(lang: Lang, outcome: Outcome) -> AttemptResult {
        AttemptResult {
            candidate: candidate(lang),
            outcome,
            harness_dir: std::path::PathBuf::from("/nonexistent"),
        }
    }

    fn fuzzed_result(lang: Lang) -> AttemptResult {
        result(
            lang,
            Outcome::BuiltAndFuzzed {
                repairs: Vec::new(),
                retries: 0,
                passes: Vec::new(),
                per_pass_budget_secs: 0,
                total_wall_budget_secs: 0,
                executions_per_sec: 0.0,
                runtrace_events: Vec::new(),
            },
        )
    }

    fn unsupported_result(lang: Lang, reason: &str) -> AttemptResult {
        result(
            lang,
            Outcome::UnsupportedParams {
                reason: reason.to_owned(),
            },
        )
    }

    fn report_only_result(lang: Lang, reason: &str) -> AttemptResult {
        result(
            lang,
            Outcome::ReportOnly {
                reason: reason.to_owned(),
                dialect: None,
                static_findings: 0,
                finding_ids: Vec::new(),
            },
        )
    }
}
