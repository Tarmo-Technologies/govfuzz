// SPDX-License-Identifier: Apache-2.0

use corpus::{
    classify, compute_signature, Classification, CorpusManager, FindingEmitter, SignatureClass,
};
use event_log::{group_into_testcases, Event, EventReader, EventTag};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const EXPECTED_SIGNATURE: &str = "20b41fb2a2ceeabc9f0403546af14199d4ccacc54e55f6fcb5855015b5eb63bd";

#[test]
fn e2e_swallowed_ce_synthetic_stream_produces_finding_ada95() {
    run_dialect("ada95");
}

#[test]
fn e2e_swallowed_ce_synthetic_stream_produces_finding_ada2005() {
    run_dialect("ada2005");
}

#[test]
fn e2e_swallowed_ce_synthetic_stream_produces_finding_ada2012() {
    run_dialect("ada2012");
}

#[test]
fn e2e_swallowed_ce_synthetic_stream_produces_finding_ada2022() {
    run_dialect("ada2022");
}

#[test]
fn e2e_duplicate_signature_returns_duplicate_class() {
    let root = temp_dir("duplicates");
    let mut manager = CorpusManager::new(root);
    let events = parse_events(swallowed_ce_stream(1));

    let first = manager
        .record("m5_swallowed_ce_ada95", b"bad", &events)
        .unwrap();
    let duplicate = manager
        .record("m5_swallowed_ce_ada95", b"bad", &events)
        .unwrap();
    let changed = manager
        .record(
            "m5_swallowed_ce_ada95",
            b"bad",
            &parse_events(swallowed_ce_stream(2)),
        )
        .unwrap();

    assert_eq!(first[0].class, SignatureClass::New);
    assert_eq!(duplicate[0].class, SignatureClass::Duplicate);
    assert_eq!(changed[0].class, SignatureClass::New);
}

fn run_dialect(dialect: &str) {
    let root = temp_dir(dialect);
    let harness_id = format!("m5_swallowed_ce_{dialect}");
    let input = b"not-an-integer";
    let stream = swallowed_ce_stream(1);
    let events = parse_events(stream.clone());
    let testcases =
        group_into_testcases(EventReader::new(Cursor::new(stream))).expect("group testcases");

    assert_eq!(testcases.len(), 1);
    assert_eq!(
        classify(&testcases[0]),
        vec![(0, Classification::SwallowedPredefined)]
    );
    assert_eq!(
        compute_signature(&testcases[0], &testcases[0].handlers[0]).hex(),
        EXPECTED_SIGNATURE
    );

    let mut manager = CorpusManager::new(root.clone());
    let records = manager.record(&harness_id, input, &events).unwrap();
    assert_eq!(records[0].class, SignatureClass::New);

    let emitter = FindingEmitter::with_metadata(
        root.clone(),
        harness_id.clone(),
        dialect.to_owned(),
        "examples/swallowed_constraint_error/pkg.adb".to_owned(),
    );
    let id = emitter.emit(input, &testcases[0], 0).unwrap();
    let finding_dir = root.join("findings").join(id.0);
    let finding_json = fs::read_to_string(finding_dir.join("finding.json")).unwrap();
    let finding: serde_json::Value = serde_json::from_str(&finding_json).unwrap();

    assert!(finding_dir.is_dir());
    assert_eq!(finding["signature"], EXPECTED_SIGNATURE);
    assert_eq!(finding["classification"], "swallowed_predefined");
    assert_eq!(finding["handler"]["handler_line"], 9);
    assert_eq!(finding["last_breadcrumb"], 1);
    assert_eq!(finding["harness_id"], harness_id);
    assert_eq!(finding["dialect"], dialect);
}

fn parse_events(stream: Vec<u8>) -> Vec<Event> {
    EventReader::new(Cursor::new(stream))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn swallowed_ce_stream(last_breadcrumb: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_begin(&mut bytes, 1);
    push_target(&mut bytes, 0x42);
    push_crumb(&mut bytes, last_breadcrumb);
    push_handler(
        &mut bytes,
        "CONSTRAINT_ERROR",
        "bad input",
        "pkg.adb",
        9,
        last_breadcrumb,
        0x42,
        1,
    );
    push_end(&mut bytes, 0);
    bytes
}

fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {
    bytes.push(EventTag::Begin as u8);
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}

fn push_end(bytes: &mut Vec<u8>, result_class: u8) {
    bytes.push(EventTag::End as u8);
    bytes.push(result_class);
}

fn push_crumb(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(EventTag::Crumb as u8);
    bytes.extend_from_slice(&id.to_le_bytes());
}

fn push_target(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(EventTag::Target as u8);
    bytes.extend_from_slice(&id.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn push_handler(
    bytes: &mut Vec<u8>,
    exception_name: &str,
    exception_message: &str,
    handler_file: &str,
    handler_line: u32,
    last_breadcrumb: u32,
    target_id: u32,
    testcase_id: u64,
) {
    bytes.push(EventTag::Handler as u8);
    push_string(bytes, exception_name);
    push_string(bytes, exception_message);
    push_string(bytes, handler_file);
    bytes.extend_from_slice(&handler_line.to_le_bytes());
    bytes.extend_from_slice(&last_breadcrumb.to_le_bytes());
    bytes.extend_from_slice(&target_id.to_le_bytes());
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-e2e-swallowed-ce-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
