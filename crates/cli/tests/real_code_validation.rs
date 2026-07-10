// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/cli")
        .to_path_buf()
}

#[derive(Debug, Deserialize)]
struct Manifest {
    repositories: Vec<Repository>,
}

#[derive(Debug, Deserialize)]
struct Repository {
    id: String,
    url: String,
    rev: String,
    language: String,
    license: String,
    #[serde(default)]
    checks: Vec<Check>,
    #[serde(default)]
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Check {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    kind: String,
    #[serde(default)]
    expect_needed: Vec<ExpectedNeeded>,
}

#[derive(Debug, Deserialize)]
struct ExpectedNeeded {
    bucket: String,
    locator: String,
}

#[test]
fn real_code_validation_manifest_covers_language_parity_and_breakage() {
    let root = repo_root();
    let manifest_path = root.join("tests/fixtures/real_code_validation/manifest.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let manifest: Manifest = toml::from_str(&manifest_text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));

    let languages: BTreeSet<_> = manifest
        .repositories
        .iter()
        .map(|repo| repo.language.as_str())
        .collect();
    assert!(languages.contains("ada"), "manifest must include real Ada");
    assert!(languages.contains("c"), "manifest must include real C");
    assert!(languages.contains("cpp"), "manifest must include real C++");

    let mut strict_broken_c = false;
    let mut strict_broken_cpp = false;
    let mut ada_gpr_build = false;
    let mut ada_toolchain_gap = false;
    for repo in &manifest.repositories {
        assert!(!repo.id.trim().is_empty(), "repo id must be present");
        assert!(
            repo.url.starts_with("https://github.com/") && repo.url.ends_with(".git"),
            "{}: repo url must be a GitHub clone URL ending in .git",
            repo.id
        );
        assert_eq!(
            repo.rev.len(),
            40,
            "{}: repo rev must be a pinned 40-character commit",
            repo.id
        );
        assert!(
            repo.rev.chars().all(|ch| ch.is_ascii_hexdigit()),
            "{}: repo rev must be hexadecimal",
            repo.id
        );
        assert!(
            !repo.license.trim().is_empty(),
            "{}: license required",
            repo.id
        );
        assert!(
            !repo.checks.is_empty(),
            "{}: at least one check required",
            repo.id
        );
        assert!(
            repo.checks.iter().any(|check| check.kind == "list_targets"),
            "{}: each real repo must at least exercise list-targets",
            repo.id
        );
        for scenario in &repo.scenarios {
            assert!(
                !scenario.id.trim().is_empty(),
                "{}: scenario id required",
                repo.id
            );
            if repo.language == "c" && scenario.kind == "auto_missing_file" {
                strict_broken_c = true;
            }
            if repo.language == "cpp" && scenario.kind == "auto_missing_file" {
                strict_broken_cpp = true;
            }
            if repo.language == "ada" && scenario.kind == "toolchain_gap" {
                ada_toolchain_gap = true;
            }
            for expected in &scenario.expect_needed {
                assert!(
                    !expected.bucket.trim().is_empty() && !expected.locator.trim().is_empty(),
                    "{}:{} expected needed_for_build bucket and locator must be non-empty",
                    repo.id,
                    scenario.id
                );
            }
        }
        if repo.language == "ada"
            && repo
                .checks
                .iter()
                .any(|check| check.kind == "generate_harness_gpr")
        {
            ada_gpr_build = true;
        }
    }

    assert!(strict_broken_c, "manifest must break a real C codebase");
    assert!(strict_broken_cpp, "manifest must break a real C++ codebase");
    assert!(ada_gpr_build, "manifest must build a real Ada harness GPR");
    assert!(
        ada_toolchain_gap,
        "manifest must record host-toolchain incompatibilities separately from GovFuzz gaps"
    );
}

#[test]
fn real_code_validation_runner_dry_run_lists_matrix() {
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
    assert_eq!(value["summary"]["repositories"].as_u64(), Some(4));
    assert!(
        value["summary"]["checks"].as_u64().unwrap_or(0) >= 6,
        "expected at least six real-code checks: {value:#}"
    );
    assert!(
        value["summary"]["scenarios"].as_u64().unwrap_or(0) >= 3,
        "expected strict C/C++ breakage plus Ada toolchain-gap scenarios: {value:#}"
    );
    let ids = value["repositories"]
        .as_array()
        .expect("repositories array")
        .iter()
        .map(|repo| repo["id"].as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    assert!(ids.contains("cjson"));
    assert!(ids.contains("tinyxml2"));
    assert!(ids.contains("adayaml"));
    assert!(ids.contains("ada_util"));
}

#[test]
fn real_code_validation_runner_writes_evidence_report_and_readiness_gate() {
    let temp = std::env::temp_dir().join(format!(
        "govfuzz-real-code-evidence-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp).unwrap();
    let root = repo_root();
    let script = root.join("scripts/validation/real-code-matrix.py");
    let manifest = root.join("tests/fixtures/real_code_validation/manifest.toml");
    let json_out = temp.join("matrix.json");
    let markdown_out = temp.join("matrix.md");
    let output = Command::new("python3")
        .arg(&script)
        .arg("--manifest")
        .arg(&manifest)
        .arg("--dry-run")
        .arg("--json-out")
        .arg(&json_out)
        .arg("--markdown-out")
        .arg(&markdown_out)
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", script.display()));

    assert!(
        output.status.success(),
        "dry-run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&json_out).unwrap())
        .unwrap_or_else(|error| panic!("parse {}: {error}", json_out.display()));
    assert_eq!(value["readiness_gate"]["status"], "pass");
    assert_eq!(
        value["readiness_gate"]["thresholds"]["languages"],
        serde_json::json!(["ada", "c", "cpp"])
    );
    assert!(
        value["summary"]["expected_outcomes"]["target_discovery"]
            .as_u64()
            .unwrap_or(0)
            >= 4
    );
    assert!(
        value["summary"]["expected_outcomes"]["harness_build"]
            .as_u64()
            .unwrap_or(0)
            >= 4
    );
    assert!(
        value["summary"]["expected_outcomes"]["broken_build_recovery"]
            .as_u64()
            .unwrap_or(0)
            >= 3
    );
    assert_eq!(
        value["evidence_claim"]["claim"],
        "offline government legacy software fuzzer readiness"
    );

    let markdown = std::fs::read_to_string(&markdown_out)
        .unwrap_or_else(|error| panic!("read {}: {error}", markdown_out.display()));
    assert!(markdown.contains("Real-Code Evidence Matrix"));
    assert!(markdown.contains("Readiness gate: pass"));
    assert!(markdown.contains("Ada / C / C++"));
}
