// SPDX-License-Identifier: Apache-2.0

//! COBOL crash attribution (M3.4) — turn a generic COBOL SIGSEGV crash into a
//! COBOL-semantic finding.
//!
//! A COBOL harness crash (via the glue's exit-interposition) is recorded as a
//! generic `GF-210` reachable-crash. But libcob printed a precise diagnostic to
//! stderr just before exiting — `libcob: <file>.cob:<line>: error: <what>` — which
//! names the COBOL source site and the violated runtime check. This post-pass
//! replays each COBOL crash's input, captures that message, and enriches the
//! finding with the COBOL source location, a human message, and the mapped CWE
//! (out-of-bounds reference-modification/subscript → CWE-125, zero divide →
//! CWE-369, SIZE overflow → CWE-190, ...). Non-COBOL findings are left untouched.

use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// Replay every COBOL (`H-B*`) crash finding to recover libcob's diagnostic and
/// enrich the finding record. Returns the number of findings enriched.
pub fn run_cobol_attribution(work_dir: &Path) -> usize {
    let findings_dir = work_dir.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut enriched = 0usize;
    for entry in entries.flatten() {
        let dir = entry.path();
        let finding_json = dir.join("finding.json");
        let testcase = dir.join("testcase.bin");
        if !finding_json.is_file() || !testcase.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read(&finding_json) else {
            continue;
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        let harness_id = value
            .get("harness_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // COBOL harness ids are `H-B*` (see Candidate::id_prefix).
        if !harness_id.starts_with("H-B") {
            continue;
        }
        let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
        if !main_bin.is_file() {
            continue;
        }
        let Some(diag) = replay_capture_libcob(&main_bin, &testcase) else {
            continue;
        };
        // A failed dynamic CALL to a sibling program that isn't linked into this
        // single-program harness ("module 'X' not found") is an environment
        // artifact, not a target defect — drop the finding so it is never
        // reported as a false positive.
        if is_harness_artifact(&diag.what) {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        if enrich(&mut value, &diag) {
            if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
                if std::fs::write(&finding_json, bytes).is_ok() {
                    enriched += 1;
                }
            }
        }
    }
    enriched
}

/// Run the harness on `input` and return the first `libcob: ...: error: ...`
/// diagnostic line from its stderr, if any.
fn replay_capture_libcob(bin: &Path, input: &Path) -> Option<LibcobDiag> {
    let out = crate::command_output::output_with_timeout(
        std::process::Command::new(bin).arg(input),
        Duration::from_secs(15),
    )
    .ok()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr.lines() {
        if let Some(diag) = parse_libcob_line(line) {
            return Some(diag);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibcobDiag {
    file: String,
    line: u32,
    what: String,
}

/// Parse `libcob: <file>:<line>: error: <what>` (the `<file>:<line>:` part is
/// optional in some libcob messages).
fn parse_libcob_line(line: &str) -> Option<LibcobDiag> {
    let rest = line.trim().strip_prefix("libcob:")?.trim();
    // Split the message off at "error:" (libcob also emits "warning:"—ignore those).
    let (loc, what) = rest.split_once("error:")?;
    let what = what.trim().to_owned();
    // loc is either "<file>:<line>: " or empty.
    let loc = loc.trim().trim_end_matches(':');
    let (file, line_no) = match loc.rsplit_once(':') {
        Some((f, n)) => (f.to_owned(), n.trim().parse::<u32>().unwrap_or(0)),
        None => (String::new(), 0),
    };
    if what.is_empty() {
        return None;
    }
    Some(LibcobDiag {
        file,
        line: line_no,
        what,
    })
}

/// Whether a libcob diagnostic is a harness/environment artifact rather than a
/// target defect: a failed dynamic CALL to a sibling program not linked into
/// this single-program harness. Such a crash reproduces on any input (often the
/// empty one) and must never be reported as a finding.
fn is_harness_artifact(what: &str) -> bool {
    let w = what.to_ascii_lowercase();
    (w.contains("module") && w.contains("not found"))
        || w.contains("cannot find module")
        || w.contains("cobol runtime cannot resolve")
}

/// Map a libcob error description to (CWE, short kind) for the finding.
fn classify(what: &str) -> (&'static str, &'static str) {
    let w = what.to_ascii_lowercase();
    if w.contains("out of bounds") || w.contains("subscript") || w.contains("ref mod") {
        // Out-of-range reference-modification / OCCURS subscript.
        (
            "CWE-125",
            "COBOL out-of-bounds reference-modification / subscript",
        )
    } else if w.contains("zero") && w.contains("divide") || w.contains("division by zero") {
        ("CWE-369", "COBOL divide by zero")
    } else if w.contains("size") || w.contains("overflow") {
        ("CWE-190", "COBOL numeric size overflow")
    } else if w.contains("not numeric") || w.contains("incompatible") || w.contains("invalid data")
    {
        ("CWE-704", "COBOL invalid numeric data / conversion")
    } else if w.contains("linkage") || w.contains("parameter") {
        ("CWE-457", "COBOL missing/uninitialized LINKAGE argument")
    } else {
        ("CWE-20", "COBOL runtime exception")
    }
}

/// Rewrite the finding's exception message + CWE + source location in place.
/// Returns true when the finding was changed.
fn enrich(value: &mut Value, diag: &LibcobDiag) -> bool {
    let (cwe, kind) = classify(&diag.what);
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let location = if diag.line > 0 && !diag.file.is_empty() {
        format!("{}:{}", diag.file, diag.line)
    } else {
        diag.file.clone()
    };
    let message = if location.is_empty() {
        format!("{kind}: {}", diag.what)
    } else {
        format!("{kind} at {location}: {}", diag.what)
    };
    // Exception name + message.
    let exception = obj
        .entry("exception")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(exc) = exception.as_object_mut() {
        exc.insert("name".to_owned(), Value::from("COBOL_RUNTIME_ERROR"));
        exc.insert("message".to_owned(), Value::from(message));
        exc.insert(
            "libcob_diagnostic".to_owned(),
            Value::from(diag.what.clone()),
        );
    }
    // CWE onto actionability (mirrors the msan/sink oracles).
    let actionability = obj
        .entry("actionability")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(act) = actionability.as_object_mut() {
        act.insert("cwe".to_owned(), serde_json::json!([cwe]));
    }
    // Record the COBOL source site if we recovered one.
    if diag.line > 0 && !diag.file.is_empty() {
        obj.insert(
            "cobol_source".to_owned(),
            serde_json::json!({ "file": diag.file, "line": diag.line }),
        );
    }
    obj.insert(
        "analysis".to_owned(),
        serde_json::json!({ "engine": "govfuzz.cobol.attribution" }),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ref_mod_out_of_bounds() {
        let d = parse_libcob_line(
            "libcob: parseit.cob:11: error: offset of 'BUF' out of bounds: 200, maximum: 8",
        )
        .unwrap();
        assert_eq!(d.file, "parseit.cob");
        assert_eq!(d.line, 11);
        assert!(d.what.contains("out of bounds"));
        assert_eq!(classify(&d.what).0, "CWE-125");
    }

    #[test]
    fn parses_subscript_and_zero_divide() {
        let sub = parse_libcob_line("libcob: p.cob:5: error: subscript of 'T' out of bounds: 101")
            .unwrap();
        assert_eq!(classify(&sub.what).0, "CWE-125");
        let zd = parse_libcob_line("libcob: p.cob:9: error: division by zero").unwrap();
        assert_eq!(classify(&zd.what).0, "CWE-369");
    }

    #[test]
    fn suppresses_call_resolution_artifacts_only() {
        assert!(is_harness_artifact(
            "module 'JsonParse-ObjectStart' not found"
        ));
        assert!(is_harness_artifact("cannot find module FOO"));
        assert!(!is_harness_artifact("offset of 'BUF' out of bounds: 200"));
        assert!(!is_harness_artifact("division by zero"));
    }

    #[test]
    fn ignores_non_error_lines() {
        assert!(parse_libcob_line("some unrelated output").is_none());
        assert!(parse_libcob_line("libcob: warning: something").is_none());
    }

    #[test]
    fn enrich_sets_cwe_message_and_source() {
        let mut v = serde_json::json!({
            "rule_id": "GF-210",
            "exception": { "name": "ASAN_FATAL_SIGNAL", "message": "SIGSEGV" },
            "actionability": {}
        });
        let diag = LibcobDiag {
            file: "parseit.cob".to_owned(),
            line: 11,
            what: "offset of 'BUF' out of bounds: 200, maximum: 8".to_owned(),
        };
        assert!(enrich(&mut v, &diag));
        assert_eq!(v["exception"]["name"], "COBOL_RUNTIME_ERROR");
        assert_eq!(v["actionability"]["cwe"][0], "CWE-125");
        assert_eq!(v["cobol_source"]["line"], 11);
        assert!(v["exception"]["message"]
            .as_str()
            .unwrap()
            .contains("parseit.cob:11"));
    }
}
