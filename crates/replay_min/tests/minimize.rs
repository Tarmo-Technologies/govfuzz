// SPDX-License-Identifier: Apache-2.0

use corpus::{compute_signature, Signature};
use event_log::{HandlerEvent, Testcase};
use replay_min::{
    load_decoded_typed_spans, minimize_finding_bytes, minimize_finding_typed_values, MinimizeError,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn minimize_finding_bytes_uses_signature_match_predicate() {
    let finding_dir = write_finding(b"prefix-crash-suffix", canonical_signature());

    let result = minimize_finding_bytes(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result.minimized, b"crash");
    assert_eq!(result.original_len, b"prefix-crash-suffix".len());
    assert!(result.predicate_runs > 0);
}

#[test]
fn minimize_finding_bytes_treats_candidate_replay_failures_as_non_reproducing() {
    let finding_dir = write_finding(b"boom-crash-tail", canonical_signature());

    let result = minimize_finding_bytes(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result.minimized, b"crash");
}

#[test]
fn minimize_finding_bytes_rejects_non_reproducing_original() {
    let finding_dir = write_finding(b"does-not-reproduce", canonical_signature());

    let error = minimize_finding_bytes(&finding_dir, fake_harness()).unwrap_err();

    assert!(matches!(error, MinimizeError::OriginalMismatch { .. }));
}

#[test]
fn minimize_finding_typed_values_collapses_decoded_spans() {
    let finding_dir = write_finding(b"AAAAcrashBBBB", canonical_signature());
    write_decoded_spans(
        &finding_dir,
        &[
            serde_json::json!({ "start": 0, "end": 4, "kind": "string" }),
            serde_json::json!({ "start": 9, "end": 13, "kind": "bytes" }),
        ],
    );

    let result = minimize_finding_typed_values(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result.minimized, b"crash");
    assert_eq!(result.attempted_replacements, 2);
    assert_eq!(result.accepted_replacements, 2);
}

#[test]
fn minimize_finding_typed_values_without_decoded_spans_is_noop() {
    let finding_dir = write_finding(b"AAAAcrashBBBB", canonical_signature());

    let result = minimize_finding_typed_values(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result.minimized, b"AAAAcrashBBBB");
    assert_eq!(result.attempted_replacements, 0);
    assert_eq!(result.accepted_replacements, 0);
}

#[test]
fn load_decoded_typed_spans_rejects_unknown_kind() {
    let finding_dir = write_finding(b"AAAAcrashBBBB", canonical_signature());
    write_decoded_spans(
        &finding_dir,
        &[serde_json::json!({ "start": 0, "end": 4, "kind": "record" })],
    );

    let error = load_decoded_typed_spans(&finding_dir).unwrap_err();

    assert!(matches!(
        error,
        MinimizeError::InvalidDecodedMetadata { .. }
    ));
}

#[test]
fn load_decoded_typed_spans_rejects_overlapping_spans() {
    let finding_dir = write_finding(b"AAAAcrashBBBB", canonical_signature());
    write_decoded_spans(
        &finding_dir,
        &[
            serde_json::json!({ "start": 0, "end": 6, "kind": "string" }),
            serde_json::json!({ "start": 4, "end": 9, "kind": "bytes" }),
        ],
    );

    let error = load_decoded_typed_spans(&finding_dir).unwrap_err();

    assert!(matches!(
        error,
        MinimizeError::InvalidDecodedMetadata { .. }
    ));
}

fn canonical_signature() -> Signature {
    let testcase = testcase_with_handler_line(9);
    compute_signature(&testcase, &testcase.handlers[0])
}

fn testcase_with_handler_line(handler_line: u32) -> Testcase {
    Testcase {
        testcase_id: 1,
        target_id: 0x42,
        target_entered: false,
        crumbs: vec![1],
        handlers: vec![HandlerEvent {
            sequence_index: 3,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "bad input".to_owned(),
            handler_file: "pkg.adb".to_owned(),
            handler_line,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        }],
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    }
}

fn write_finding(input: &[u8], signature: Signature) -> PathBuf {
    let finding_dir = temp_dir("minimize").join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec(&serde_json::json!({ "signature": signature })).unwrap(),
    )
    .unwrap();
    finding_dir
}

fn write_decoded_spans(finding_dir: &Path, spans: &[serde_json::Value]) {
    fs::write(
        finding_dir.join("decoded.json"),
        serde_json::to_vec(&serde_json::json!({ "typed_spans": spans })).unwrap(),
    )
    .unwrap();
}

fn fake_harness() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_fake_harness"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-minimize-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
