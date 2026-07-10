// SPDX-License-Identifier: Apache-2.0

use actionability::select_fix_location;
use serde_json::json;

#[test]
fn fix_location_prefers_oracle_sink_over_stack() {
    let raw = json!({
        "oracle": {
            "sink": {
                "location": { "path": "src/sink.adb", "line": 8, "col": 3 }
            }
        },
        "exception": {
            "stack": [
                { "function": "parse", "file": "src/parse.c", "line": 12 }
            ]
        }
    });

    let location = select_fix_location(&raw, Some("findings/F/finding.json")).unwrap();

    assert_eq!(location.path, "src/sink.adb");
    assert_eq!(location.reason, "oracle_sink_location");
}

#[test]
fn fix_location_skips_generated_harness_frame() {
    // A double-free whose top non-runtime frame is the generated harness's own
    // cleanup (govfuzz_run_one in <work>/auto/<id>/main.c) must NOT resolve the
    // fix location to govfuzz's own code — that frame is the harness freeing
    // fabricated inputs, not a target site. With no target frame, the location
    // is None (the harness-artifact verdict demotion handles classification).
    let raw = json!({
        "exception": {
            "name": "ASAN_ATTEMPTING",
            "message": "AddressSanitizer: attempting double-free",
            "stack": [
                { "function": "free", "file": null, "line": null },
                { "function": "govfuzz_run_one", "file": "/w/auto/H-C0/main.c", "line": 64 },
                { "function": "main", "file": "/w/auto/H-C0/main.c", "line": 545 }
            ]
        }
    });
    assert!(
        select_fix_location(&raw, Some("findings/F/finding.json")).is_none(),
        "fix location must never point at the generated harness main.c"
    );
}

#[test]
fn fix_location_uses_target_frame_below_harness_frame() {
    // A harness frame on top of a real target frame: skip the harness, resolve
    // the fix to the target source line.
    let raw = json!({
        "exception": {
            "stack": [
                { "function": "govfuzz_run_one", "file": "/w/auto/H/main.c", "line": 64 },
                { "function": "toml_parse", "file": "toml.c", "line": 880 }
            ]
        }
    });
    let location = select_fix_location(&raw, None).unwrap();
    assert_eq!(location.path, "toml.c");
    assert_eq!(location.line, Some(880));
}

#[test]
fn fix_location_uses_top_non_runtime_sanitizer_frame() {
    let raw = json!({
        "exception": {
            "stack": [
                { "function": "__asan_memcpy", "file": null, "line": null },
                { "function": "parse_packet", "file": "src/packet.c", "line": 27 }
            ]
        }
    });

    let location = select_fix_location(&raw, Some("findings/F/finding.json")).unwrap();

    assert_eq!(location.path, "src/packet.c");
    assert_eq!(location.line, Some(27));
    assert_eq!(location.reason, "sanitizer_top_non_runtime_frame");
}

#[test]
fn fix_location_uses_explicit_raise_before_handler() {
    let raw = json!({
        "classification": "explicit_raise",
        "handler": { "sequence_index": 4, "exception_name": "Bad", "handler_file": "src/pkg.adb", "handler_line": 20 },
        "raises": [
            { "sequence_index": 2, "exception_name": "Bad", "file": "src/pkg.adb", "line": 12 }
        ]
    });

    let location = select_fix_location(&raw, Some("findings/F/finding.json")).unwrap();

    assert_eq!(location.path, "src/pkg.adb");
    assert_eq!(location.line, Some(12));
    assert_eq!(location.reason, "explicit_raise_site");
}

#[test]
fn fix_location_uses_closest_matching_explicit_raise_before_handler() {
    let raw = json!({
        "classification": "explicit_raise",
        "handler": { "sequence_index": 4, "exception_name": "Bad", "handler_file": "src/pkg.adb", "handler_line": 20 },
        "raises": [
            { "sequence_index": 1, "exception_name": "Bad", "file": "src/pkg.adb", "line": 10 },
            { "sequence_index": 3, "exception_name": "Bad", "file": "src/pkg.adb", "line": 12 }
        ]
    });

    let location = select_fix_location(&raw, Some("findings/F/finding.json")).unwrap();

    assert_eq!(location.path, "src/pkg.adb");
    assert_eq!(location.line, Some(12));
    assert_eq!(location.reason, "explicit_raise_site");
}

#[test]
fn fix_location_uses_remapped_exception_source_over_handler_site() {
    // An unhandled CONSTRAINT_ERROR whose instrumented line was remapped to the
    // original source: fix_location must point there, not at <unhandled>.
    let raw = json!({
        "classification": "unhandled",
        "handler": { "sequence_index": 0, "exception_name": "CONSTRAINT_ERROR", "handler_file": "<unhandled>", "handler_line": 0 },
        "exception": {
            "name": "CONSTRAINT_ERROR",
            "message": "bzip2-decoding.adb:518 index check failed",
            "source_file": "/src/bzip2-decoding.adb",
            "source_line": 518
        }
    });

    let location = select_fix_location(&raw, Some("findings/F/finding.json")).unwrap();

    assert_eq!(location.path, "/src/bzip2-decoding.adb");
    assert_eq!(location.line, Some(518));
    assert_eq!(location.reason, "exception_source");
}

#[test]
fn fix_location_is_none_when_nothing_resolves_instead_of_finding_json_path() {
    // No stack, no oracle/handler/raise: there is genuinely nothing to point at.
    // The fix location must be absent rather than the generated finding.json path.
    let raw = json!({ "id": "F-fallback" });

    assert!(select_fix_location(&raw, Some("findings/F-fallback/finding.json")).is_none());
}

#[test]
fn fix_location_falls_back_to_sink_frame_function_without_source() {
    // The only meaningful frame resolves no source file: the fix location names
    // the sink function (reason `sink_frame_no_source`), never finding.json.
    let raw = json!({
        "exception": {
            "stack": [
                { "function": "__asan_report_load4", "file": null, "line": null },
                { "function": "parse_header", "file": null, "line": null }
            ]
        }
    });

    let location = select_fix_location(&raw, Some("findings/F-sink/finding.json")).unwrap();

    assert_eq!(location.path, "parse_header");
    assert_eq!(location.reason, "sink_frame_no_source");
    assert!(location.line.is_none());
}
