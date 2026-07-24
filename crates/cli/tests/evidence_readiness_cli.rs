// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn real_code_matrix_reports_language_coverage_and_offline_subset_metadata() {
    let root = repo_root();
    let script = root.join("scripts/validation/real-code-matrix.py");
    let manifest = root.join("tests/fixtures/real_code_validation/manifest.toml");
    let output = Command::new("python3")
        .arg(&script)
        .arg("--manifest")
        .arg(&manifest)
        .arg("--dry-run")
        .arg("--json")
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", script.display()));

    assert!(
        output.status.success(),
        "dry-run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("parse dry-run JSON: {error}"));

    assert_eq!(value["schema_version"], "govfuzz.real_code_matrix.v1");
    assert_eq!(value["offline"]["mode"], "rerunnable_after_materialization");
    assert_eq!(value["bounded_subset"]["ci_ready"], true);
    assert_eq!(
        value["summary"]["language_coverage"]["ada"]["repositories"],
        3
    );
    assert_eq!(
        value["summary"]["language_coverage"]["c"]["repositories"],
        1
    );
    assert_eq!(
        value["summary"]["language_coverage"]["cpp"]["repositories"],
        1
    );
    assert!(
        value["summary"]["checks_by_kind"]["list_targets"]
            .as_u64()
            .unwrap_or(0)
            >= 4
    );
    assert!(
        value["summary"]["checks_by_kind"]["generate_harness_gpr"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );
    assert_eq!(value["summary"]["broken_build_by_language"]["ada"], true);
    assert_eq!(value["summary"]["broken_build_by_language"]["c"], true);
    assert_eq!(value["summary"]["broken_build_by_language"]["cpp"], true);
    assert!(
        value["summary"]["toolchain_gaps_by_language"]["ada"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    let subset = value["bounded_subset"]["repositories"]
        .as_array()
        .expect("bounded subset repositories")
        .iter()
        .map(|item| item.as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    assert!(subset.contains("cjson"));
    assert!(subset.contains("tinyxml2"));
    // #104: the bounded offline subset uses the hermetic ada_local endpoint (real
    // Ada target entry provable without Alire), not the network-only adayaml repo.
    assert!(subset.contains("ada_local"));
}

#[test]
fn seeded_benchmark_tracks_recall_precision_and_fails_on_missed_expected_findings() {
    let root = temp_dir("seeded-benchmark");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("unsafe.c"),
        "#include <string.h>\nvoid copy(char *dst, const char *src) { strcpy(dst, src); }\n",
    )
    .unwrap();
    fs::write(
        src.join("clean.c"),
        "#include <string.h>\nvoid copy(char *dst, const char *src) { memcpy(dst, src, 4); }\n",
    )
    .unwrap();
    fs::write(
        src.join("service.cpp"),
        "#include <cstdio>\nvoid log_user(char *input) { std::printf(input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("tasking.adb"),
        "procedure Tasking is\n   task type Worker;\n   task body Worker is begin null; end Worker;\nbegin\n   null;\nend Tasking;\n",
    )
    .unwrap();
    let manifest = root.join("seeded-suite.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.seeded_benchmark.v1",
            "suite_id": "seeded-government-legacy-smoke",
            "root": "src",
            "limitations": ["Fixture-sized proxy suite; not a population precision estimate."],
            "cases": [
                {
                    "id": "c-unsafe-copy",
                    "finding_kind": "static",
                    "source": "unsafe.c",
                    "expected_findings": [{ "rule_id": "GF-401", "path": "unsafe.c" }]
                },
                {
                    "id": "cpp-nonliteral-format",
                    "finding_kind": "static",
                    "source": "service.cpp",
                    "expected_findings": [{ "rule_id": "GF-408", "path": "service.cpp" }]
                },
                {
                    "id": "ada-tasking",
                    "finding_kind": "static",
                    "source": "tasking.adb",
                    "expected_findings": [{ "rule_id": "GF-411", "path": "tasking.adb" }]
                },
                {
                    "id": "clean-c",
                    "finding_kind": "static",
                    "source": "clean.c",
                    "expected_non_findings": [{ "rule_id": "GF-401", "path": "clean.c" }]
                },
                {
                    "id": "dynamic-crash-triage",
                    "finding_kind": "dynamic",
                    "observed_findings": [{ "rule_id": "GF-101", "path": "replay/run-last.json" }],
                    "expected_findings": [{ "rule_id": "GF-101", "path": "replay/run-last.json" }]
                },
                {
                    "id": "binary-crash",
                    "finding_kind": "binary",
                    "observed_findings": [{ "rule_id": "GF-501", "path": "bin/legacyd" }],
                    "expected_findings": [{ "rule_id": "GF-501", "path": "bin/legacyd" }]
                },
                {
                    "id": "sca-cve",
                    "finding_kind": "sca",
                    "observed_findings": [{ "rule_id": "CVE-2026-0001", "path": "sbom/sbom.json" }],
                    "expected_findings": [{ "rule_id": "CVE-2026-0001", "path": "sbom/sbom.json" }]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let metrics = root.join("metrics.json");
    let markdown = root.join("metrics.md");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "benchmark",
                "seeded",
                "--manifest",
                manifest.to_str().unwrap(),
                "--out",
                metrics.to_str().unwrap(),
                "--markdown",
                markdown.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let value = read_json(&metrics);
    assert_eq!(
        value["schema_version"],
        "govfuzz.seeded_benchmark.metrics.v1"
    );
    assert_eq!(value["suite_id"], "seeded-government-legacy-smoke");
    assert_eq!(value["metrics"]["expected_findings"], 6);
    assert_eq!(value["metrics"]["true_positives"], 6);
    assert_eq!(value["metrics"]["false_negatives"], 0);
    assert_eq!(value["metrics"]["false_positives"], 0);
    assert_eq!(value["metrics"]["recall"], 1.0);
    assert_eq!(value["metrics"]["precision_proxy"], 1.0);
    assert_eq!(value["metrics"]["by_kind"]["static"]["expected"], 3);
    assert_eq!(value["metrics"]["by_kind"]["dynamic"]["expected"], 1);
    assert_eq!(value["metrics"]["by_kind"]["binary"]["expected"], 1);
    assert_eq!(value["metrics"]["by_kind"]["sca"]["expected"], 1);
    assert_eq!(value["metrics"]["by_rule"]["GF-401"]["true_positives"], 1);
    assert!(markdown.read_text().contains("Seeded Benchmark Metrics"));

    let missed = root.join("missed-suite.json");
    fs::write(
        &missed,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.seeded_benchmark.v1",
            "suite_id": "missed",
            "root": "src",
            "cases": [{
                "id": "expected-miss",
                "finding_kind": "static",
                "source": "clean.c",
                "expected_findings": [{ "rule_id": "GF-999", "path": "clean.c" }]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let missed_metrics = root.join("missed-metrics.json");
    let output = Command::new(govfuzz_bin())
        .args([
            "benchmark",
            "seeded",
            "--manifest",
            missed.to_str().unwrap(),
            "--out",
            missed_metrics.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "missed expected finding should fail\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let missed_value = read_json(&missed_metrics);
    assert_eq!(missed_value["metrics"]["false_negatives"], 1);
    assert_eq!(
        missed_value["false_negatives"][0]["case_id"],
        "expected-miss"
    );
}

#[test]
fn government_legacy_pattern_corpus_reports_required_track_coverage() {
    let root = repo_root();
    let manifest = root.join("tests/fixtures/government_legacy_patterns/manifest.json");
    let manifest_json = read_json(&manifest);
    assert_eq!(
        manifest_json["schema_version"],
        "govfuzz.legacy_patterns.v1"
    );

    let required = [
        "ada95_idioms",
        "gpr_variants",
        "corba_idl",
        "c_parser",
        "cpp_service_class",
        "protocol_tlv",
        "embedded_runtime_dependency",
        "stripped_binary",
    ];
    let tracks = manifest_json["patterns"]
        .as_array()
        .expect("patterns array")
        .iter()
        .map(|pattern| pattern["track"].as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    for track in required {
        assert!(
            tracks.contains(track),
            "missing required pattern track {track}"
        );
    }
    for pattern in manifest_json["patterns"].as_array().unwrap() {
        let path = pattern["path"].as_str().expect("pattern path");
        assert!(
            root.join("tests/fixtures/government_legacy_patterns")
                .join(path)
                .is_file(),
            "pattern fixture {path} must exist"
        );
        assert!(
            !pattern["expected_behavior"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "pattern {} must document expected behavior",
            pattern["id"]
        );
    }

    let temp = temp_dir("pattern-coverage");
    let out = temp.join("patterns.json");
    let markdown = temp.join("patterns.md");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "benchmark",
                "patterns",
                "--manifest",
                manifest.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--markdown",
                markdown.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let coverage = read_json(&out);
    assert_eq!(
        coverage["schema_version"],
        "govfuzz.legacy_patterns.coverage.v1"
    );
    assert_eq!(coverage["counts"]["tracks"], 8);
    assert_eq!(coverage["counts"]["patterns"], 8);
    assert!(
        coverage["counts"]["breakage_patterns"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );
    assert_eq!(coverage["by_track"]["cpp_service_class"]["patterns"], 1);
    assert!(markdown
        .read_text()
        .contains("Government Legacy Pattern Coverage"));
}

#[test]
fn readiness_scorecard_uses_evidence_and_blocks_unsupported_enterprise_scanner_claims() {
    let root = temp_dir("readiness-scorecard");
    let validation = root.join("real-code.json");
    fs::write(
        &validation,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.real_code_matrix.v1",
            "summary": {
                "repositories": 4,
                "checks": 8,
                "scenarios": 3,
                "failed": 0,
                "known_gaps": 0,
                "toolchain_gaps": 1,
                "language_coverage": {
                    "ada": { "repositories": 2, "checks": 4, "scenarios": 1 },
                    "c": { "repositories": 1, "checks": 2, "scenarios": 1 },
                    "cpp": { "repositories": 1, "checks": 2, "scenarios": 1 }
                },
                "broken_build_by_language": { "ada": true, "c": true, "cpp": true }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let metrics = root.join("metrics.json");
    fs::write(
        &metrics,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.seeded_benchmark.metrics.v1",
            "metrics": {
                "recall": 1.0,
                "precision_proxy": 1.0,
                "false_negatives": 0,
                "false_positives": 0,
                "by_kind": {
                    "static": { "expected": 3 },
                    "dynamic": { "expected": 1 },
                    "binary": { "expected": 1 },
                    "sca": { "expected": 1 }
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let patterns = root.join("patterns.json");
    fs::write(
        &patterns,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.legacy_patterns.coverage.v1",
            "counts": { "tracks": 8, "patterns": 8, "breakage_patterns": 2 },
            "by_track": {
                "ada95_idioms": { "patterns": 1 },
                "gpr_variants": { "patterns": 1 },
                "corba_idl": { "patterns": 1 },
                "c_parser": { "patterns": 1 },
                "cpp_service_class": { "patterns": 1 },
                "protocol_tlv": { "patterns": 1 },
                "embedded_runtime_dependency": { "patterns": 1 },
                "stripped_binary": { "patterns": 1 }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let claim_root = root.join("docs");
    fs::create_dir_all(&claim_root).unwrap();
    fs::write(
        claim_root.join("index.md"),
        "GovFuzz is a government legacy software fuzzer for Ada, C, C++, binaries, and enterprise offline workflows.\n",
    )
    .unwrap();
    fs::write(
        claim_root.join("bad.md"),
        "GovFuzz is a complete enterprise scanner with exhaustive vulnerability detection.\n",
    )
    .unwrap();

    let out = root.join("readiness.json");
    let markdown = root.join("readiness.md");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "readiness",
                "scorecard",
                "--validation",
                validation.to_str().unwrap(),
                "--benchmark",
                metrics.to_str().unwrap(),
                "--patterns",
                patterns.to_str().unwrap(),
                "--claim-root",
                claim_root.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--markdown",
                markdown.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let scorecard = read_json(&out);
    assert_eq!(scorecard["schema_version"], "govfuzz.readiness.v1");
    for category in [
        "static_scanning",
        "binary_scanning",
        "ada_depth",
        "cpp_depth",
        "enterprise_operations",
        "evidence",
    ] {
        assert!(
            scorecard["categories"].get(category).is_some(),
            "missing readiness category {category}"
        );
        assert!(
            scorecard["categories"][category]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|capability| capability["status"] == "implemented"),
            "{category} must include implemented capability evidence"
        );
    }
    assert!(
        scorecard["categories"]["cpp_depth"]["score"]
            .as_u64()
            .unwrap_or(0)
            >= scorecard["categories"]["ada_depth"]["score"]
                .as_u64()
                .unwrap_or(0),
        "C++ depth should be at least as mature as Ada depth for the parity goal"
    );
    assert_eq!(
        scorecard["claim_gate"]["unsupported_claims"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        scorecard["claim_gate"]["unsupported_claims"][0]["phrase"],
        "complete enterprise scanner"
    );
    assert!(markdown.read_text().contains("Readiness Scorecard"));
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("govfuzz-{name}-{unique}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    }))
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

trait ReadText {
    fn read_text(&self) -> String;
}

impl ReadText for PathBuf {
    fn read_text(&self) -> String {
        fs::read_to_string(self).unwrap_or_else(|error| panic!("read {}: {error}", self.display()))
    }
}
