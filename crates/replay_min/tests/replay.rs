// SPDX-License-Identifier: Apache-2.0

use corpus::{compute_signature, Signature};
use event_log::{HandlerEvent, Testcase};
use replay_min::{replay, ReplayError, ReplayResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn replay_match_when_harness_emits_recorded_signature_events() {
    let finding_dir = write_finding("match", canonical_signature());

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_mismatch_when_harness_emits_different_signature() {
    let finding_dir = write_finding("mismatch", canonical_signature());

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert!(matches!(
        result,
        ReplayResult::Mismatch {
            recorded,
            actual: Some(_)
        } if recorded == canonical_signature()
    ));
}

#[test]
fn replay_matches_recorded_signature_at_second_handler_index() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let recorded = compute_signature(&testcase, &testcase.handlers[1]);
    let finding_dir = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_returns_mismatch_when_recorded_signature_absent_from_all_handlers() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let actual = compute_signature(&testcase, &testcase.handlers[0]);
    let unrelated = testcase_with_handler_lines(&[13]);
    let recorded = compute_signature(&unrelated, &unrelated.handlers[0]);
    let finding_dir = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(
        result,
        ReplayResult::Mismatch {
            recorded,
            actual: Some(actual)
        }
    );
}

#[test]
fn replay_returns_match_when_recorded_signature_at_first_handler_index() {
    let testcase = testcase_with_handler_lines(&[5, 9]);
    let recorded = compute_signature(&testcase, &testcase.handlers[0]);
    let finding_dir = write_finding("multi-handler", recorded);

    let result = replay(&finding_dir, fake_harness()).unwrap();

    assert_eq!(result, ReplayResult::Match);
}

#[test]
fn replay_returns_error_when_finding_missing() {
    let missing = temp_dir("missing").join("F-0000-missing");

    let error = replay(&missing, fake_harness()).unwrap_err();

    assert!(matches!(error, ReplayError::MissingFinding { .. }));
}

#[test]
fn replay_returns_error_when_harness_binary_missing() {
    let finding_dir = write_finding("match", canonical_signature());
    let missing_harness = temp_dir("missing-harness").join("missing-harness");

    let error = replay(&finding_dir, &missing_harness).unwrap_err();

    assert!(matches!(error, ReplayError::HarnessFailedToStart { .. }));
}

fn canonical_signature() -> Signature {
    let testcase = testcase_with_handler_lines(&[9]);
    compute_signature(&testcase, &testcase.handlers[0])
}

fn testcase_with_handler_lines(handler_lines: &[u32]) -> Testcase {
    Testcase {
        testcase_id: 1,
        target_id: 0x42,
        crumbs: vec![1],
        handlers: handler_lines
            .iter()
            .enumerate()
            .map(|(index, handler_line)| HandlerEvent {
                sequence_index: 3 + index,
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: *handler_line,
                last_breadcrumb: 1,
                target_id: 0x42,
                testcase_id: 1,
            })
            .collect(),
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    }
}

fn write_finding(input: &str, signature: Signature) -> PathBuf {
    let finding_dir = temp_dir(input).join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec(&serde_json::json!({ "signature": signature })).unwrap(),
    )
    .unwrap();
    finding_dir
}

fn fake_harness() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_fake_harness"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-replay-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
