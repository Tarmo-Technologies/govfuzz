// SPDX-License-Identifier: Apache-2.0

//! End-to-end: emit findings against two synthetic stacks via the
//! C/C++ sanitizer path, then run `report::build_report` and assert
//! two clusters with correct membership counts.

use corpus::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
use corpus::FindingEmitter;
use report::{build_report, ReportOptions};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn tempdir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("govfuzz-cluster-e2e-{prefix}-{nonce}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn report_for(target_fn: &str) -> SanitizerReport {
    SanitizerReport {
        sanitizer: Sanitizer::AddressSanitizer,
        kind: "heap-buffer-overflow".to_owned(),
        rule_id: "GF-201",
        stack: vec![
            StackFrame {
                function: "__asan_memcpy".to_owned(),
                file: None,
                line: None,
            },
            StackFrame {
                function: target_fn.to_owned(),
                file: Some("/src/x.c".to_owned()),
                line: Some(9),
            },
            StackFrame {
                function: "LLVMFuzzerTestOneInput".to_owned(),
                file: None,
                line: None,
            },
        ],
        message: format!("ERROR: AddressSanitizer: heap-buffer-overflow in {target_fn}"),
    }
}

#[test]
fn three_findings_across_two_target_frames_produce_two_clusters() {
    let root = tempdir("two-clusters");
    let emitter = FindingEmitter::new(root.clone());

    emitter
        .emit_sanitizer_crash(b"a-1", &report_for("parse_a"))
        .unwrap();
    emitter
        .emit_sanitizer_crash(b"a-2", &report_for("parse_a"))
        .unwrap();
    emitter
        .emit_sanitizer_crash(b"b-1", &report_for("parse_b"))
        .unwrap();

    let out_dir = tempdir("two-clusters-out");
    let document = build_report(&ReportOptions::new(root.join("findings"), out_dir)).unwrap();

    assert_eq!(document.findings.len(), 3);
    assert_eq!(document.clusters.len(), 2);
    let by_size: Vec<usize> = document.clusters.iter().map(|c| c.member_count).collect();
    assert_eq!(by_size, vec![2, 1], "sorted descending by member_count");
    let by_frame: std::collections::BTreeMap<&str, usize> = document
        .clusters
        .iter()
        .map(|c| (c.top_frames[0].as_str(), c.member_count))
        .collect();
    assert_eq!(by_frame["parse_a"], 2);
    assert_eq!(by_frame["parse_b"], 1);
}
