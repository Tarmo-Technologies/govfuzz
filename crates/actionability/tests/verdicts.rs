// SPDX-License-Identifier: Apache-2.0

use actionability::{
    backfill_actionability, existing_actionability_or_backfill, ActionabilityConfidence, RunMode,
    Verdict,
};
use serde_json::json;

#[test]
fn real_reachable_requires_entry_failure_fix_and_no_prosthetics() {
    let raw = json!({
        "id": "F-real",
        "rule_id": "GF-201",
        "harness_id": "H-real",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
    assert!(!record.prosthetics.used);
}

#[test]
fn rust_std_alloc_only_leak_is_lab_only() {
    // G5: a LeakSanitizer report whose entire stack is Rust std alloc plumbing
    // (no target-crate frame) is the harness-dropped Vec/arena — lab-only noise.
    let raw = json!({
        "id": "F-leak", "rule_id": "GF-208", "harness_id": "H-r",
        "exception": {
            "sanitizer": "lsan", "name": "memory-leak",
            "stack": [
                { "function": "malloc" },
                { "function": "<alloc::raw_vec::RawVecInner>::with_capacity_in" },
                { "function": "<alloc::vec::Vec<u8>>::with_capacity_in" }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-leak/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn leak_with_a_target_frame_is_not_demoted() {
    // A leak WITH a real target-crate frame (parson process_string) is a genuine
    // finding and must keep its normal verdict — G5 must not over-suppress.
    let raw = json!({
        "id": "F-realleak", "rule_id": "GF-208", "harness_id": "H-p",
        "exception": {
            "sanitizer": "lsan", "name": "memory-leak",
            "stack": [
                { "function": "malloc" },
                { "function": "process_string", "file": "parson.c", "line": 898 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-realleak/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn harness_cleanup_double_free_is_lab_only() {
    // A double-free whose ENTIRE fault stack is the generated harness's own
    // cleanup (govfuzz_run_one freeing the pointer fields it fabricated for a
    // by-pointer struct param, e.g. a tomlc99 `eat_token(context_t*, …)`
    // internal) plus libc — no target frame. govfuzz manufactured the crash, so
    // even though the fuzzed entry is flagged attacker-reachable it must NOT read
    // as a real/likely-reachable critical vulnerability. Surfaced as lab-only.
    let raw = json!({
        "id": "F-art", "rule_id": "GF-201", "harness_id": "H-C0",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_ATTEMPTING",
            "message": "ERROR: AddressSanitizer: attempting double-free on 0x502000000070 in thread T0:",
            "stack": [
                { "function": "free", "file": null, "line": null },
                { "function": "govfuzz_run_one", "file": "/w/auto/H-C0/main.c", "line": 64 },
                { "function": "govfuzz_run_file", "file": "/w/auto/H-C0/main.c", "line": 479 },
                { "function": "main", "file": "/w/auto/H-C0/main.c", "line": 545 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-art/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn double_free_with_a_target_frame_is_not_demoted() {
    // The contrast: a double-free whose top fault frame is TARGET code (the
    // target itself frees twice) is a genuine ownership bug — it must keep its
    // normal reachable verdict. The harness-artifact demotion must not swallow it.
    let raw = json!({
        "id": "F-real-df", "rule_id": "GF-201", "harness_id": "H-C1",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_ATTEMPTING",
            "message": "ERROR: AddressSanitizer: attempting double-free on 0x502 in thread T0:",
            "stack": [
                { "function": "free", "file": null, "line": null },
                { "function": "toml_free_table", "file": "toml.c", "line": 1421 },
                { "function": "govfuzz_run_one", "file": "/w/auto/H-C1/main.c", "line": 64 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real-df/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn go_must_function_panic_is_lab_only() {
    // A recovered Go panic whose panicking frame is a `Must*` function
    // (fastjson `MustParse`): by Go convention `MustX` is a panic-on-error
    // wrapper around `X`, so panicking on bad input is its documented contract,
    // not a bug — and `X` (which returns an error) is fuzzed separately. Demote.
    let raw = json!({
        "id": "F-must", "rule_id": "GF-210", "harness_id": "H-G0",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_GO_PANIC",
            "message": "Go panic: cannot parse JSON: cannot parse empty string",
            "stack": [
                { "function": "github.com/valyala/fastjson.MustParse", "file": "parser.go", "line": 60 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-must/finding.json"),
    );
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn go_panic_in_non_must_function_is_not_demoted() {
    // The contrast: a Go panic whose top frame is an ordinary (`Parse`) function
    // is a genuine finding — the Must* demotion must be precise.
    let raw = json!({
        "id": "F-parse", "rule_id": "GF-210", "harness_id": "H-G1",
        "input_reachability": "attacker_reachable",
        "exception": {
            "name": "ASAN_GO_PANIC",
            "message": "Go panic: runtime error: index out of range [3] with length 2",
            "stack": [
                { "function": "github.com/x/y.Parse", "file": "parse.go", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-parse/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn relational_contract_assert_panic_is_lab_only() {
    // G6: bytes::Bytes::slice_ref asserts subset is contained in self; the
    // auto-harness builds them independently so any input trips the contract.
    let raw = json!({
        "id": "F-sr", "rule_id": "GF-201", "harness_id": "H-b",
        "exception": {
            "name": "panic",
            "message": "subset is out of bounds: self = (0x1, 10), subset = (0x2, 3)",
            "stack": [ { "function": "slice_ref", "file": "src/bytes.rs", "line": 432 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record =
        backfill_actionability(RunMode::Attacking, &raw, Some("findings/F-sr/finding.json"));
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn stdlib_index_oob_panic_is_not_demoted() {
    // A genuine standard-library bounds panic must NOT be demoted by G6 — it can
    // be a real OOB in target code.
    let raw = json!({
        "id": "F-oob", "rule_id": "GF-201", "harness_id": "H-x",
        "exception": {
            "name": "panic",
            "message": "index out of bounds: the len is 3 but the index is 5",
            "stack": [ { "function": "parse", "file": "src/parse.rs", "line": 12 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-oob/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn byteorder_fixed_width_slice_read_panic_is_lab_only() {
    // #467: ByteOrder::read_u128(buf: &[u8]) reads a fixed `&buf[..16]` prefix and
    // panics when the fuzzed slice is shorter — a documented length precondition
    // ("Panics if buf.len() < 16"), not a memory-safety bug. The `range end index
    // {primitive-width}` form (NOT the computed `the index is Y` form) marks it.
    for (n, m) in [(16u32, 0u32), (4, 0), (8, 3), (2, 1)] {
        let raw = json!({
            "id": "F-bo", "rule_id": "GF-201", "harness_id": "H-bo",
            "exception": {
                "sanitizer": "asan",
                "name": "ASAN_RUST_PANIC_INDEX_OUT_OF_BOUNDS",
                "message": format!("Rust panic: range end index {n} out of range for slice of length {m}"),
                "stack": [ { "function": "<rust panic>", "file": "src/lib.rs", "line": 1908 } ]
            },
            "replay": { "status": "reproduced" }
        });
        let record =
            backfill_actionability(RunMode::Attacking, &raw, Some("findings/F-bo/finding.json"));
        assert_eq!(
            record.verdict,
            Verdict::LabOnly,
            "fixed-width read of a too-short slice (end {n}, len {m}) is lab-only"
        );
    }
}

#[test]
fn variable_length_slice_read_panic_is_not_demoted() {
    // A parser that reads a length field then over-indexes lands on an ARBITRARY
    // end index (here 257), never a primitive integer width — that can be a real
    // OOB and must NOT be masked by the #467 byteorder carve-out.
    let raw = json!({
        "id": "F-var", "rule_id": "GF-201", "harness_id": "H-var",
        "exception": {
            "name": "panic",
            "message": "range end index 257 out of range for slice of length 12",
            "stack": [ { "function": "parse_record", "file": "src/parse.rs", "line": 88 } ]
        },
        "replay": { "status": "reproduced" }
    });
    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-var/finding.json"),
    );
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn prosthetic_evidence_disqualifies_real_reachable() {
    let raw = json!({
        "id": "F-lab",
        "rule_id": "GF-201",
        "harness_id": "H-lab",
        "build": { "deps": { "stubbed": ["Missing.Driver"] } },
        "exception": {
            "stack": [
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-lab/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert!(record.prosthetics.used);
    assert_eq!(record.prosthetics.items[0].kind, "stubbed_dependency");
}

#[test]
fn existing_real_actionability_is_downgraded_when_raw_prosthetics_are_present() {
    let raw = json!({
        "id": "F-stale-real",
        "rule_id": "GF-201",
        "harness_id": "H-lab",
        "build": { "deps": { "stubbed": ["Missing.Driver"] } },
        "exception": {
            "stack": [
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" },
        "actionability": {
            "mode": "attacking",
            "verdict": "real_reachable",
            "impact": "high",
            "confidence": "high",
            "entry_path": {
                "kind": "harness",
                "source": "testcase.bin",
                "target": "H-lab"
            },
            "fix_location": {
                "path": "src/parse.c",
                "line": 12,
                "reason": "sanitizer_stack_frame"
            },
            "replay": { "status": "reproduced" },
            "prosthetics": { "used": false, "items": [] }
        }
    });

    let record = existing_actionability_or_backfill(
        RunMode::Attacking,
        &raw,
        Some(std::path::Path::new("findings/F-stale-real/finding.json")),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert!(record.prosthetics.used);
    assert_eq!(record.prosthetics.items[0].kind, "stubbed_dependency");
}

#[test]
fn blocked_resource_evidence_yields_blocked_when_no_prosthetic_was_used() {
    let raw = json!({
        "id": "F-blocked",
        "rule_id": "GF-304",
        "harness_id": "H-blocked",
        "runtrace_events": [
            { "kind": "network_unreachable", "address": "10.0.0.5:443" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-blocked/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Blocked);
}

#[test]
fn explicit_blocked_resources_yield_blocked_when_no_prosthetic_was_used() {
    let raw = json!({
        "id": "F-blocked-resource",
        "rule_id": "GF-304",
        "harness_id": "H-blocked",
        "blocked_resources": [
            { "kind": "file_missing", "path": "/etc/app/config" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-blocked-resource/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Blocked);
}

#[test]
fn fallback_finding_json_location_does_not_make_reproduced_finding_real() {
    let raw = json!({
        "id": "F-metadata-only",
        "rule_id": "GF-201",
        "harness_id": "H-metadata",
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-metadata-only/finding.json"),
    );

    assert_ne!(record.verdict, Verdict::RealReachable);
    assert_eq!(record.confidence, ActionabilityConfidence::Low);
    // With no stack to resolve, there is no fix location at all — and never the
    // generated finding.json path.
    assert!(record.fix_location.is_none());
}

#[test]
fn unknown_runtrace_event_does_not_block_reproduced_real_finding() {
    let raw = json!({
        "id": "F-real-runtrace",
        "rule_id": "GF-201",
        "harness_id": "H-real",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" },
        "runtrace_events": [
            { "kind": "unknown", "raw": "resource probe did something unclassified" }
        ]
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-real-runtrace/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
}

#[test]
fn strong_static_evidence_without_replay_is_likely_reachable() {
    let raw = json!({
        "id": "F-likely",
        "rule_id": "GF-205",
        "harness_id": "H-likely",
        "exception": {
            "stack": [
                { "function": "size_calc", "file": "src/parse.c", "line": 30 }
            ]
        }
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-likely/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn insufficient_evidence_is_unknown() {
    let raw = json!({ "id": "F-unknown" });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-unknown/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::Unknown);
}

#[test]
fn unproven_reachability_entry_is_lab_only_even_when_reproduced() {
    // The harness drove an internal function directly (e.g. a write_* serializer
    // whose buffer is caller-controlled): a clean reproduce does not make it
    // attacker-reachable, so the verdict is lab_only and the confidence cannot
    // read as high.
    let raw = json!({
        "id": "F-internal",
        "rule_id": "GF-201",
        "harness_id": "H-internal",
        "input_reachability": "reachability_unproven",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "write_uint24", "file": "src/enc.c", "line": 20 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-internal/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(false)
    );
    assert_ne!(record.confidence, ActionabilityConfidence::High);
}

#[test]
fn output_serializer_reachability_is_also_lab_only() {
    let raw = json!({
        "id": "F-serializer",
        "rule_id": "GF-201",
        "harness_id": "H-serializer",
        "input_reachability": "output_serializer",
        "exception": {
            "stack": [
                { "function": "encode_frame", "file": "src/enc.c", "line": 8 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-serializer/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LabOnly);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(false)
    );
}

#[test]
fn attacker_reachable_entry_stays_real_reachable() {
    let raw = json!({
        "id": "F-public",
        "rule_id": "GF-201",
        "harness_id": "H-public",
        "input_reachability": "attacker_reachable",
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        },
        "replay": { "status": "reproduced" }
    });

    let record = backfill_actionability(
        RunMode::Attacking,
        &raw,
        Some("findings/F-public/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::RealReachable);
    assert_eq!(
        record.entry_path.as_ref().unwrap().attacker_reachable,
        Some(true)
    );
    assert_eq!(record.confidence, ActionabilityConfidence::High);
}

#[test]
fn attacker_reachable_static_only_is_likely_reachable() {
    let raw = json!({
        "id": "F-public-static",
        "rule_id": "GF-205",
        "harness_id": "H-public-static",
        "input_reachability": "attacker_reachable",
        "exception": {
            "stack": [
                { "function": "size_calc", "file": "src/parse.c", "line": 30 }
            ]
        }
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-public-static/finding.json"),
    );

    assert_eq!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn empty_harness_id_does_not_create_entry_path_evidence() {
    let raw = json!({
        "id": "F-empty-harness",
        "rule_id": "GF-201",
        "harness_id": "   "
    });

    let record = backfill_actionability(
        RunMode::Reporting,
        &raw,
        Some("findings/F-empty-harness/finding.json"),
    );

    assert!(record.entry_path.is_none());
    assert_ne!(record.verdict, Verdict::LikelyReachable);
}

#[test]
fn native_assertion_enum_domain_precondition_is_lab_only() {
    // #39: tinycbor cbor_encode_floating_point asserts its fpType discriminator is
    // one of the Half/Float/Double enum members. The auto-harness fuzzes fpType out
    // of domain, so the assert trips on a harness-supplied parameter — demote to
    // lab-only (still surfaced), not a real CWE-617 finding.
    let raw = json!({
        "id": "F-fp",
        "rule_id": "GF-415",
        "harness_id": "H-tinycbor",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [
                { "key": "expression", "value": "fpType == CborHalfFloatType || fpType == CborFloatType || fpType == CborDoubleType" }
            ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn genuine_relational_assertion_still_surfaces_not_demoted() {
    // #39 guard: a genuine relational invariant (`len < cap`) is NOT a discriminator
    // domain precondition — it must keep its normal (non-lab-only) verdict so a real
    // reachable assertion is never hidden.
    let raw = json!({
        "id": "F-real-assert",
        "rule_id": "GF-415",
        "harness_id": "H-x",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [ { "key": "expression", "value": "len < cap" } ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_ne!(record.verdict, Verdict::LabOnly);
}

#[test]
fn single_value_enum_assertion_is_not_demoted() {
    // #39 guard: a single `state == ACTIVE` precondition (one allowed value) is not
    // a multi-member domain check — keep it (too tight to demote safely).
    let raw = json!({
        "id": "F-one",
        "rule_id": "GF-415",
        "harness_id": "H-y",
        "classification": "oracle_hit",
        "oracle": {
            "name": "native-assertion-contract",
            "api": "__assert_fail",
            "evidence": [ { "key": "expression", "value": "state == ACTIVE" } ]
        },
        "exception": { "name": "oracle", "message": "native assertion contract failed" }
    });
    let record = backfill_actionability(RunMode::Attacking, &raw, None);
    assert_ne!(record.verdict, Verdict::LabOnly);
}
