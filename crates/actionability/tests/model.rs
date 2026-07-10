// SPDX-License-Identifier: Apache-2.0

use actionability::{
    backfill_actionability, ActionabilityConfidence, ActionabilityRecord, EntryPath, FixLocation,
    Impact, Prosthetics, ReplayEvidence, RunMode, Verdict,
};
use serde_json::json;

#[test]
fn oracle_finding_backfills_cwe_from_rule_id() {
    // M22 campaign fix: an ORACLE_* behavioral/assertion finding has no bug-class
    // CWE, so it used to emit a blank CWE in auto/findings.csv. The actionability
    // backfill must fall back to the matched rule's CWE (GF-415 -> CWE-617) so the
    // "every finding carries a CWE in every format" contract holds on the auto path.
    let raw = json!({
        "rule_id": "GF-415",
        "classification": "ORACLE_NATIVE_ASSERT",
        "exception": { "name": "oracle", "message": "native assertion contract violated" }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-617".to_string()]);
    assert!(rec.cwe_name.is_some());
}

#[test]
fn temporal_stack_use_after_return_maps_to_cwe_562_not_121() {
    // #29: a stack-use-after-return is a TEMPORAL stale-pointer bug (CWE-562 with
    // CWE-825 secondary), NOT the spatial stack-buffer-overflow CWE-121 that the
    // old GF-203 rule fallback produced.
    let raw = json!({
        "rule_id": "GF-211",
        "exception": {
            "name": "ASAN_STACK_USE_AFTER_RETURN",
            "sanitizer": "asan",
            "message": "AddressSanitizer: stack-use-after-return on address 0x7f"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-562".to_string(), "CWE-825".to_string()]);
    assert!(!rec.cwe.contains(&"CWE-121".to_string()));
    assert!(
        !rec.patch_hints.is_empty(),
        "temporal stack needs a patch hint"
    );
    assert!(rec
        .explanation
        .unwrap()
        .to_lowercase()
        .contains("stale stack"));
}

#[test]
fn temporal_stack_use_after_scope_maps_to_cwe_825() {
    let raw = json!({
        "rule_id": "GF-211",
        "exception": {
            "name": "ASAN_STACK_USE_AFTER_SCOPE",
            "sanitizer": "asan",
            "message": "AddressSanitizer: stack-use-after-scope on address 0x7f"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-825".to_string(), "CWE-562".to_string()]);
}

#[test]
fn segv_near_null_subpage_address_is_cwe_476_null_deref() {
    // #30: a near-null deref (null base + small field offset) faults at a sub-page
    // address, not exactly zero; classify it as a NULL deref (CWE-476), not a wild
    // SEGV (CWE-787/125).
    let raw = json!({
        "rule_id": "GF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x000000000010 (READ memory access)"
        }
    });
    let rec = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(rec.cwe, vec!["CWE-476".to_string()]);
}

#[test]
fn segv_wild_read_with_direction_is_cwe_125_not_787() {
    // #30: a non-null wild SEGV whose captured direction is a READ is an
    // out-of-bounds READ (CWE-125), not the default OOB WRITE (CWE-787).
    let read = json!({
        "rule_id": "GF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x00007f1200001234 (READ memory access)"
        }
    });
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &read, None).cwe,
        vec!["CWE-125".to_string()]
    );
    let write = json!({
        "rule_id": "GF-206",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "message": "AddressSanitizer: SEGV on unknown address 0x00007f1200001234 (WRITE memory access)"
        }
    });
    assert_eq!(
        backfill_actionability(RunMode::Reporting, &write, None).cwe,
        vec!["CWE-787".to_string()]
    );
}

#[test]
fn serializes_actionability_record_in_spec_shape() {
    let record = ActionabilityRecord {
        mode: RunMode::Attacking,
        verdict: Verdict::RealReachable,
        impact: Impact::High,
        confidence: ActionabilityConfidence::High,
        entry_path: Some(EntryPath {
            kind: "cli".to_owned(),
            source: "stdin".to_owned(),
            target: "Pkg.Parse".to_owned(),
            evidence: Vec::new(),
            attacker_reachable: None,
        }),
        fix_location: Some(FixLocation {
            path: "src/pkg.adb".to_owned(),
            line: Some(42),
            col: None,
            reason: "explicit_raise_site".to_owned(),
        }),
        source: None,
        sink: None,
        explanation: None,
        cwe: Vec::new(),
        cwe_name: None,
        replay: Some(ReplayEvidence {
            status: "reproduced".to_owned(),
        }),
        prosthetics: Prosthetics::default(),
        patch_hints: Vec::new(),
        next_steps: Vec::new(),
    };

    let value = serde_json::to_value(record).unwrap();

    assert_eq!(value["mode"], "attacking");
    assert_eq!(value["verdict"], "real_reachable");
    assert_eq!(value["impact"], "high");
    assert_eq!(value["confidence"], "high");
    assert_eq!(value["entry_path"]["source"], "stdin");
    assert_eq!(value["fix_location"]["path"], "src/pkg.adb");
    assert_eq!(value["fix_location"]["reason"], "explicit_raise_site");
    assert_eq!(value["prosthetics"]["used"], false);
}

#[test]
fn lsan_leak_maps_to_cwe_401() {
    // A LeakSanitizer finding (nanosvg-style) maps to CWE-401.
    let raw = json!({
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "sanitizer": "lsan",
            "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(record.cwe, vec!["CWE-401".to_owned()]);
    assert_eq!(
        record.cwe_name.as_deref(),
        Some("Missing Release of Memory after Effective Lifetime")
    );

    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(value["cwe"][0], "CWE-401");
    assert_eq!(
        value["cwe_name"],
        "Missing Release of Memory after Effective Lifetime"
    );
}

#[test]
fn cwe_mapping_covers_core_bug_classes() {
    let case = |name: &str, msg: &str, sanitizer: &str| {
        backfill_actionability(
            RunMode::Reporting,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": sanitizer }
            }),
            None,
        )
        .cwe
    };

    // heap-buffer-overflow READ -> CWE-122 primary + CWE-125 secondary.
    assert_eq!(
        case("heap-buffer-overflow", "READ of size 4", "asan"),
        vec!["CWE-122".to_owned(), "CWE-125".to_owned()]
    );
    // heap-buffer-overflow WRITE -> CWE-122 + CWE-787.
    assert_eq!(
        case("heap-buffer-overflow", "WRITE of size 8", "asan"),
        vec!["CWE-122".to_owned(), "CWE-787".to_owned()]
    );
    assert_eq!(
        case("stack-buffer-overflow", "WRITE of size 1", "asan"),
        vec!["CWE-121".to_owned()]
    );
    assert_eq!(
        case("heap-use-after-free", "READ of size 4", "asan"),
        vec!["CWE-416".to_owned()]
    );
    assert_eq!(case("double-free", "", "asan"), vec!["CWE-415".to_owned()]);
    assert_eq!(
        case("SEGV", "SEGV on unknown address 0x000000000000", "asan"),
        vec!["CWE-476".to_owned()]
    );
    assert_eq!(
        case("signed-integer-overflow", "", "ubsan"),
        vec!["CWE-190".to_owned()]
    );
    assert_eq!(
        case("shift-exponent", "shift exponent too large", "ubsan"),
        vec!["CWE-682".to_owned()]
    );
    assert_eq!(
        case("timeout", "timeout after 60s", ""),
        vec!["CWE-834".to_owned(), "CWE-400".to_owned()]
    );
    assert_eq!(
        case(
            "out-of-memory",
            "out-of-memory: requested allocation size",
            ""
        ),
        vec!["CWE-789".to_owned(), "CWE-400".to_owned()]
    );
    // Unknown / non-memory-safety: no CWE.
    assert!(case("Constraint_Error", "range check failed", "").is_empty());
}

#[test]
fn cwe_mapping_covers_non_memory_fault_classes() {
    let record = |name: &str, msg: &str, sanitizer: &str| {
        backfill_actionability(
            RunMode::Reporting,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": sanitizer }
            }),
            None,
        )
    };

    // SIGABRT / assert -> Reachable Assertion (CWE-617).
    let abort = record("SIGABRT", "Assertion failed: idx < len", "");
    assert_eq!(abort.cwe, vec!["CWE-617".to_owned()]);
    assert_eq!(abort.cwe_name.as_deref(), Some("Reachable Assertion"));

    // SIGFPE / divide-by-zero -> CWE-369 (NOT generic UB), even under UBSan.
    let fpe = record("SIGFPE", "division by zero", "ubsan");
    assert_eq!(fpe.cwe, vec!["CWE-369".to_owned()]);
    assert_eq!(fpe.cwe_name.as_deref(), Some("Divide By Zero"));

    // Stack exhaustion from recursion -> CWE-674 (NOT stack-buffer-overflow).
    let recursion = record(
        "stack-exhaustion",
        "uncontrolled recursion depth exceeded",
        "",
    );
    assert_eq!(recursion.cwe, vec!["CWE-674".to_owned()]);
    assert_eq!(
        recursion.cwe_name.as_deref(),
        Some("Uncontrolled Recursion")
    );

    // Uncaught managed-runtime exception -> CWE-248.
    let uncaught = record(
        "jvm-uncaught-throwable",
        "Uncaught exception: java.lang.IllegalStateException",
        "",
    );
    assert_eq!(uncaught.cwe, vec!["CWE-248".to_owned()]);
    assert_eq!(uncaught.cwe_name.as_deref(), Some("Uncaught Exception"));
}

#[test]
fn rust_index_out_of_bounds_panic_maps_to_oob_cwe() {
    // A Rust bounds-checked panic must carry a memory-safety CWE (it was empty/None
    // before) — a DETECTED out-of-bounds access. Read direction defaults to CWE-125
    // (Out-of-bounds Read); a write context flips it to CWE-787 (Out-of-bounds Write).
    let record = |name: &str, msg: &str| {
        backfill_actionability(
            RunMode::Attacking,
            &json!({
                "exception": { "name": name, "message": msg, "sanitizer": "asan" }
            }),
            None,
        )
    };

    // The byteorder campaign shape: name + slice-range message, no read/write word.
    let bo = record(
        "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
        "Rust panic: range end index 8 out of range for slice of length 0",
    );
    assert!(
        !bo.cwe.is_empty(),
        "a Rust index-out-of-bounds panic must carry a CWE, got none"
    );
    assert_eq!(bo.cwe[0], "CWE-125");
    assert_eq!(bo.cwe_name.as_deref(), Some("Out-of-bounds Read"));

    // The classic indexing form also classifies (was Unknown -> no CWE before).
    let idx = record(
        "panic",
        "index out of bounds: the len is 3 but the index is 5",
    );
    assert_eq!(idx.cwe[0], "CWE-125");

    // A write context (`copy_from_slice` into the buffer) makes it CWE-787 primary.
    let write = record(
        "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
        "Rust panic: range end index 16 out of range for slice of length 0 in copy_from_slice",
    );
    assert_eq!(write.cwe[0], "CWE-787");
    assert_eq!(write.cwe_name.as_deref(), Some("Out-of-bounds Write"));
}
