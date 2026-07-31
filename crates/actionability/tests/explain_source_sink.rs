// SPDX-License-Identifier: Apache-2.0
//
// Source / sink / plain-English explanation + bug-class patch hints derived from
// a sanitizer crash's stack. Modeled on a real C LeakSanitizer finding (nanosvg)
// whose stack is malloc -> nsvg__createParser -> nsvgParse -> govfuzz harness.

use actionability::{backfill_actionability, patch_hints_for_finding, RunMode, Verdict};
use serde_json::json;

#[test]
fn runtime_message_source_prefix_backfills_sink_and_fix_location() {
    let raw = json!({
        "rule_id": "GF-205",
        "target": { "name": "decode_index" },
        "exception": {
            "name": "UBSAN_ARRAY_INDEX_OUT_OF_BOUNDS",
            "message": "/project/src/decode.c:41:17: runtime error: index -2 out of bounds for type 'char[6]'"
        }
    });

    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("message source should become the sink");
    assert_eq!(sink.file.as_deref(), Some("/project/src/decode.c"));
    assert_eq!(sink.line, Some(41));
    assert_eq!(sink.function, "decode_index");

    let fix = record
        .fix_location
        .expect("message source should be fixable");
    assert_eq!(fix.path, "/project/src/decode.c");
    assert_eq!(fix.line, Some(41));
    assert_eq!(fix.col, Some(17));
    assert_eq!(fix.reason, "exception_message_source");
}

#[test]
fn sink_skips_rust_stdlib_frame_and_resolves_in_project_frame() {
    // #32: a Rust-lane crash's top frame is the toolchain stdlib
    // (core::ptr::copy_nonoverlapping at library/core); the sink / fix_location
    // must resolve to the first IN-PROJECT frame, not the stdlib.
    let raw = json!({
        "rule_id": "GF-203",
        "harness_id": "H-rust",
        "paths": { "testcase": "crash.bin" },
        "exception": {
            "name": "ASAN_RUST_PANIC",
            "sanitizer": "asan",
            "stack": [
                { "function": "core::ptr::copy_nonoverlapping::<u8>", "file": "/rustc/abc123/library/core/src/intrinsics.rs", "line": 3140 },
                { "function": "json::short::Short::from_slice", "file": "/proj/src/short.rs", "line": 60 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(sink.function, "json::short::Short::from_slice");
    assert_eq!(sink.file.as_deref(), Some("/proj/src/short.rs"));
    let fix = record.fix_location.expect("fix location");
    assert!(
        fix.path.contains("short.rs"),
        "fix must point at the in-project frame, got {}",
        fix.path
    );
    assert!(
        !fix.path.contains("library/core"),
        "fix must not point into the Rust stdlib: {}",
        fix.path
    );
}

#[test]
fn sink_skips_crt_start_stub_so_harness_only_stack_has_no_sink() {
    // #38: `_start` (the CRT entry stub) must be filtered like other runtime
    // frames; a harness + CRT-only stack must NOT resolve fix_location to `_start`.
    let raw = json!({
        "rule_id": "GF-206",
        "harness_id": "H-crt",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "stack": [
                { "function": "_start", "file": null, "line": null },
                { "function": "govfuzz_run_one", "file": "/w/auto/H/main.c", "line": 12 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert!(
        record.sink.is_none(),
        "harness+CRT-only stack has no target sink"
    );
    assert!(
        record.fix_location.is_none(),
        "fix_location must never be `_start`: {:?}",
        record.fix_location
    );
}

#[test]
fn sink_keeps_start_named_target_function_when_it_resolves_to_source() {
    // Guard: only the bare CRT `_start` stub is filtered — a real target function
    // (with a source line) below it still resolves as the sink.
    let raw = json!({
        "rule_id": "GF-201",
        "harness_id": "H-ok",
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "_start", "file": null, "line": null },
                { "function": "real_parse", "file": "/src/p.c", "line": 9 }
            ]
        }
    });
    let sink = backfill_actionability(RunMode::Reporting, &raw, None)
        .sink
        .expect("real target frame below _start is the sink");
    assert_eq!(sink.function, "real_parse");
}

#[test]
fn sink_skips_libc_internal_frames_and_resolves_project_frame() {
    // A glibc stdio internal (_IO_fread) is never the sink — the project caller
    // above it is. Previously the fix/sink pointed at libio internals.
    let raw = json!({
        "rule_id": "GF-201",
        "harness_id": "H-io",
        "paths": { "testcase": "crash.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "_IO_fread", "file": "libio/iofread.c", "line": 38 },
                { "function": "real_parse", "file": "/src/p.c", "line": 42 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(sink.function, "real_parse");
    assert_eq!(sink.file.as_deref(), Some("/src/p.c"));
    assert_eq!(sink.line, Some(42));
}

#[test]
fn leak_in_govfuzz_decode_helper_is_demoted_to_lab_only() {
    // A LeakSanitizer report whose whole stack is allocator + the generated
    // `gf_c_string` decode helper (c_runtime/govfuzz_decode.h) is govfuzz
    // scaffolding the one-shot harness drops, not a target leak.
    let raw = json!({
        "rule_id": "GF-208",
        "harness_id": "H-leak",
        "paths": { "testcase": "t.bin" },
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
            "sanitizer": "lsan",
            "stack": [
                { "function": "malloc" },
                { "function": "gf_c_string", "file": "/work/auto/H/govfuzz_decode.h", "line": 88 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn sink_keeps_anonymous_namespace_in_function_name() {
    // The "(anonymous namespace)" scope token is not an argument list, so the
    // top frame name must survive intact into the sink function.
    let raw = json!({
        "rule_id": "GF-201",
        "harness_id": "H-pugi",
        "paths": { "testcase": "c.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                {
                    "function": "pugi::impl::(anonymous namespace)::strlength_wide(wchar_t const*)",
                    "file": "/src/pugixml.cpp",
                    "line": 220
                }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(
        sink.function,
        "pugi::impl::(anonymous namespace)::strlength_wide"
    );
}

fn nanosvg_leak() -> serde_json::Value {
    json!({
        "id": "F-0000-1028b5d3",
        "rule_id": "GF-208",
        "harness_id": "H-X0C65-56DA8C32",
        "dialect": "unknown",
        "paths": { "testcase": "testcase.bin" },
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "message": "==2306327==ERROR: LeakSanitizer: detected memory leaks",
            "sanitizer": "lsan",
            "stack": [
                { "function": "malloc" },
                { "function": "nsvg__createParser()", "file": "/src/nanosvg.h", "line": 646 },
                { "function": "nsvgParse", "file": "/src/nanosvg.h", "line": 3178 },
                { "function": "govfuzz_run_one(unsigned char const*, unsigned long)", "file": "/work/auto/H/main.cpp", "line": 39 }
            ]
        }
    })
}

#[test]
fn sink_is_top_project_frame_skipping_allocator_and_harness() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let sink = record.sink.expect("sink");
    // malloc (allocator) is skipped; the project allocation site is the sink.
    assert_eq!(sink.function, "nsvg__createParser");
    assert_eq!(sink.file.as_deref(), Some("/src/nanosvg.h"));
    assert_eq!(sink.line, Some(646));
}

#[test]
fn source_is_harness_entry_plus_reproducer() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let source = record.source.expect("source");
    assert_eq!(source.kind, "harness");
    assert_eq!(source.entry, "H-X0C65-56DA8C32");
    assert_eq!(source.testcase, "testcase.bin");
}

#[test]
fn explanation_is_plain_english_leak_naming_sink_and_reproducer() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("memory leak"), "{explanation}");
    assert!(explanation.contains("nsvg__createParser"), "{explanation}");
    assert!(explanation.contains("testcase.bin"), "{explanation}");
    // No jargon like the sanitizer's internal label.
    assert!(!explanation.contains("LSAN"), "{explanation}");
}

#[test]
fn leak_patch_hint_advises_freeing_on_every_exit_path_and_references_sink() {
    let hints = patch_hints_for_finding(&nanosvg_leak());
    assert_eq!(hints.len(), 1);
    let hint = &hints[0];
    assert!(
        hint.guidance.to_ascii_lowercase().contains("free"),
        "{}",
        hint.guidance
    );
    assert!(hint.guidance.contains("exit path"), "{}", hint.guidance);
    assert!(
        hint.guidance.contains("nsvg__createParser"),
        "{}",
        hint.guidance
    );
    // Advisory only — no fabricated diff.
    assert!(hint.diff.is_none());
}

#[test]
fn heap_overflow_explanation_and_hint_are_bug_class_specific() {
    let raw = json!({
        "rule_id": "GF-777",
        "harness_id": "H-ovf",
        "paths": { "testcase": "crash-abc.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "__asan_memcpy" },
                { "function": "copy_chunk", "file": "src/io.c", "line": 88 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("buffer overflow"), "{explanation}");
    assert!(explanation.contains("copy_chunk"), "{explanation}");
    assert!(explanation.contains("crash-abc.bin"), "{explanation}");

    let hints = patch_hints_for_finding(&raw);
    assert_eq!(hints.len(), 1);
    assert!(
        hints[0].guidance.to_ascii_lowercase().contains("bounds"),
        "{}",
        hints[0].guidance
    );
    assert!(
        hints[0].guidance.contains("src/io.c:88"),
        "{}",
        hints[0].guidance
    );
}

#[test]
fn null_deref_explanation_classifies_as_crash() {
    let raw = json!({
        "harness_id": "H-null",
        "exception": {
            "name": "SEGV",
            "message": "SEGV on unknown address 0x000000000000",
            "stack": [
                { "function": "deref_it", "file": "src/x.c", "line": 5 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("null-pointer"), "{explanation}");
    let hints = patch_hints_for_finding(&raw);
    assert!(
        hints[0].guidance.to_ascii_lowercase().contains("null"),
        "{}",
        hints[0].guidance
    );
}
