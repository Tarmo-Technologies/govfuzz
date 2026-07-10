// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn model_train_writes_warm_model_file() {
    let root = temp_dir("train");
    let labels = root.join("labels.json");
    let model_path = root.join("models/tenant-model.bin");
    write_path_based_labels(&root, &labels, 100);

    let exit = cli::run_from([
        "govfuzz",
        "model",
        "train",
        "--labels",
        labels.to_str().unwrap(),
        "--out",
        model_path.to_str().unwrap(),
    ]);

    assert_eq!(exit, 0);
    let model: serde_json::Value = serde_json::from_slice(&fs::read(model_path).unwrap()).unwrap();
    assert_eq!(model["schema_version"], "govfuzz.confidence_model.v1");
    assert_eq!(model["label_count"], 100);
    assert!(model["model_id"]
        .as_str()
        .unwrap()
        .starts_with("govfuzz.learned.v1."));
    assert!(model["weights"].as_array().unwrap().len() > 1);
    assert_eq!(model["training"]["cold_start_min_labels"], 100);
}

#[test]
fn report_subcommand_uses_requested_confidence_model() {
    let root = temp_dir("report-model");
    let labels = root.join("labels.json");
    let model_path = root.join("tenant-model.bin");
    let findings = root.join("findings");
    let out = root.join("reports");
    write_inline_labels(&labels, 100);

    let train_exit = cli::run_from([
        "govfuzz",
        "model",
        "train",
        "--labels",
        labels.to_str().unwrap(),
        "--out",
        model_path.to_str().unwrap(),
    ]);
    assert_eq!(train_exit, 0);

    write_finding(
        &findings.join("F-0001-confidence"),
        true_positive_finding("F-0001-confidence"),
    );
    let report_exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
        "--model",
        model_path.to_str().unwrap(),
    ]);

    assert_eq!(report_exit, 0);
    let model: serde_json::Value = serde_json::from_slice(&fs::read(model_path).unwrap()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("run-ci.json")).unwrap()).unwrap();
    let confidence = &report["findings"][0]["confidence"];
    assert_eq!(confidence["model_id"], model["model_id"]);
    assert!(confidence["learned"].is_f64());
    assert!(confidence["blend"].is_f64());
}

fn write_path_based_labels(root: &Path, labels_path: &Path, count: usize) {
    let fixtures = root.join("label-fixtures");
    fs::create_dir_all(&fixtures).unwrap();
    fs::write(
        fixtures.join("true.json"),
        serde_json::to_vec_pretty(&true_positive_finding("training-true")).unwrap(),
    )
    .unwrap();
    fs::write(
        fixtures.join("false.json"),
        serde_json::to_vec_pretty(&false_positive_finding()).unwrap(),
    )
    .unwrap();
    let labels = (0..count)
        .map(|index| {
            if index % 2 == 0 {
                json!({ "label": "true_positive", "finding_path": "label-fixtures/true.json" })
            } else {
                json!({ "label": "false_positive", "finding_path": "label-fixtures/false.json" })
            }
        })
        .collect::<Vec<_>>();
    fs::write(
        labels_path,
        serde_json::to_vec_pretty(&json!({ "labels": labels })).unwrap(),
    )
    .unwrap();
}

fn write_inline_labels(labels_path: &Path, count: usize) {
    let labels = (0..count)
        .map(|index| {
            if index % 2 == 0 {
                json!({ "label": "true_positive", "finding": true_positive_finding("training-true") })
            } else {
                json!({ "label": "false_positive", "finding": false_positive_finding() })
            }
        })
        .collect::<Vec<_>>();
    fs::write(
        labels_path,
        serde_json::to_vec_pretty(&json!({ "labels": labels })).unwrap(),
    )
    .unwrap();
}

fn write_finding(finding_dir: &Path, finding: serde_json::Value) {
    fs::create_dir_all(finding_dir).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&finding).unwrap(),
    )
    .unwrap();
}

fn true_positive_finding(id: &str) -> serde_json::Value {
    json!({
        "id": id,
        "classification": "explicit_raise",
        "return_class": "failure",
        "breadcrumbs": [1, 2, 3],
        "raises": [{}],
        "signature_age": 1,
        "target": { "score": 95.0, "param_shape_complexity": 1 },
        "build": { "deps": { "stubbed": [], "fake_corba": [] } }
    })
}

fn false_positive_finding() -> serde_json::Value {
    json!({
        "id": "training-false",
        "classification": "unknown",
        "return_class": "normal",
        "signature_age": 80,
        "target": { "score": 5.0, "param_shape_complexity": 14 },
        "build": {
            "deps": {
                "stubbed": ["external.ads", "external.adb"],
                "stubbed_call_depth": 5,
                "calls_through_stub": 5,
                "fake_corba": ["corba.ads"]
            }
        }
    })
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-model-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
