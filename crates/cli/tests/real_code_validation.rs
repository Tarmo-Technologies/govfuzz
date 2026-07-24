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

fn manifest_path() -> PathBuf {
    repo_root().join("tests/fixtures/real_code_validation/manifest.toml")
}

#[derive(Debug, Deserialize)]
struct Manifest {
    repositories: Vec<Repository>,
}

#[derive(Debug, Deserialize)]
struct Repository {
    id: String,
    // Network repos pin a GitHub clone URL + commit; hermetic repos check their
    // source into the tree via `local_path` and carry neither.
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    rev: Option<String>,
    #[serde(default)]
    local_path: Option<String>,
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
    #[serde(default)]
    target: Option<String>,
    // A managed/GPR harness may pin an explicit project; an Ada target-entry
    // control deliberately omits it to exercise automatic governing-GPR selection.
    #[serde(default)]
    project: Option<String>,
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

fn load_manifest() -> Manifest {
    let path = manifest_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    toml::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn real_code_validation_manifest_covers_language_parity_and_breakage() {
    let manifest = load_manifest();
    let manifest_dir = manifest_path()
        .parent()
        .expect("manifest has a parent dir")
        .to_path_buf();

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
    let mut strict_broken_ada = false;
    let mut ada_gpr_build = false;
    let mut ada_toolchain_gap = false;
    // #104: an end-to-end auto that BUILDS and ENTERS the target endpoint is the
    // authoritative proof; the matrix must exercise one per language.
    let mut entry_languages: BTreeSet<&str> = BTreeSet::new();
    // #104: at least one hermetic, dependency-free repo checked into the tree so
    // real target entry can be proven offline in normal CI (no network, no Alire).
    let mut hermetic_ada_local = false;
    for repo in &manifest.repositories {
        assert!(!repo.id.trim().is_empty(), "repo id must be present");
        match &repo.local_path {
            None => {
                let url = repo
                    .url
                    .as_deref()
                    .unwrap_or_else(|| panic!("{}: network repo must set url", repo.id));
                let rev = repo
                    .rev
                    .as_deref()
                    .unwrap_or_else(|| panic!("{}: network repo must set rev", repo.id));
                assert!(
                    url.starts_with("https://github.com/") && url.ends_with(".git"),
                    "{}: repo url must be a GitHub clone URL ending in .git",
                    repo.id
                );
                assert_eq!(
                    rev.len(),
                    40,
                    "{}: repo rev must be a pinned 40-character commit",
                    repo.id
                );
                assert!(
                    rev.chars().all(|ch| ch.is_ascii_hexdigit()),
                    "{}: repo rev must be hexadecimal",
                    repo.id
                );
            }
            Some(local) => {
                assert!(
                    repo.url.is_none() && repo.rev.is_none(),
                    "{}: a local_path repo must not also pin url/rev",
                    repo.id
                );
                let dir = manifest_dir.join(local);
                assert!(
                    dir.is_dir(),
                    "{}: local_path {} must be a checked-in directory",
                    repo.id,
                    dir.display()
                );
                let has_gpr = std::fs::read_dir(&dir)
                    .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("gpr"))
                    });
                assert!(
                    has_gpr,
                    "{}: hermetic Ada repo {} must ship a .gpr project",
                    repo.id,
                    dir.display()
                );
                if repo.language == "ada" {
                    hermetic_ada_local = true;
                }
            }
        }
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
        for check in &repo.checks {
            if check.kind == "auto_target_entry" {
                assert!(
                    check
                        .target
                        .as_deref()
                        .is_some_and(|t| !t.trim().is_empty()),
                    "{}: auto_target_entry check must name a target",
                    repo.id
                );
                entry_languages.insert(repo.language.as_str());
                if repo.language == "ada" {
                    assert!(
                        check.project.is_none(),
                        "{}: Ada target-entry control must omit `project` so it \
                         exercises automatic governing-GPR selection",
                        repo.id
                    );
                }
            }
        }
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
            if repo.language == "ada" && scenario.kind == "auto_missing_file" {
                strict_broken_ada = true;
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
    assert!(
        strict_broken_ada,
        "manifest must break a real Ada build (missing dependency) and categorize it"
    );
    assert!(ada_gpr_build, "manifest must build a real Ada harness GPR");
    assert!(
        ada_toolchain_gap,
        "manifest must record host-toolchain incompatibilities separately from GovFuzz gaps"
    );
    for language in ["ada", "c", "cpp"] {
        assert!(
            entry_languages.contains(language),
            "manifest must prove end-to-end target ENTRY for {language} \
             (an auto_target_entry check)"
        );
    }
    assert!(
        hermetic_ada_local,
        "manifest must ship a hermetic local Ada repo so Ada target entry is provable offline"
    );
}

#[test]
fn real_code_validation_runner_dry_run_lists_matrix() {
    let root = repo_root();
    let script = root.join("scripts/validation/real-code-matrix.py");
    let manifest = manifest_path();
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
    assert_eq!(value["summary"]["repositories"].as_u64(), Some(5));
    assert!(
        value["summary"]["checks"].as_u64().unwrap_or(0) >= 6,
        "expected at least six real-code checks: {value:#}"
    );
    assert!(
        value["summary"]["scenarios"].as_u64().unwrap_or(0) >= 3,
        "expected strict C/C++/Ada breakage plus Ada toolchain-gap scenarios: {value:#}"
    );
    // #104: the executed matrix proves target entry per language; the contract dry-run
    // enumerates one auto_target_entry check for each of Ada, C, and C++.
    assert!(
        value["summary"]["expected_outcomes"]["target_entry"]
            .as_u64()
            .unwrap_or(0)
            >= 3,
        "expected an end-to-end target-entry check per language: {value:#}"
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
    assert!(
        ids.contains("ada_local"),
        "manifest must ship the hermetic ada_local endpoint"
    );
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
    let manifest = manifest_path();
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

/// #104: run the matrix end-to-end against the hermetic `ada_local` repo — no
/// network, no Alire — and prove a real Ada target ENTRY plus broken-build
/// categorization offline. This is the always-on gate that a plain `cargo test`
/// can enforce (the network repos are the scheduled companion job).
#[test]
fn real_code_validation_ada_local_proves_offline_target_entry() {
    if which::which("gnatmake").is_err() {
        eprintln!("SKIP: gnatmake not on PATH");
        return;
    }
    if which::which("python3").is_err() {
        eprintln!("SKIP: python3 not on PATH");
        return;
    }
    let root = repo_root();
    let script = root.join("scripts/validation/real-code-matrix.py");
    let manifest = manifest_path();
    let workspace = std::env::temp_dir().join(format!(
        "govfuzz-ada-local-entry-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new("python3")
        .arg(&script)
        .arg("--manifest")
        .arg(&manifest)
        .arg("--repo")
        .arg("ada_local")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--json")
        .env("GOVFUZZ_BIN", env!("CARGO_BIN_EXE_govfuzz"))
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", script.display()));

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse matrix JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });

    // The overall readiness gate intentionally fails here (only Ada is selected),
    // but the Ada evidence itself must be real: entry observed + all checks pass.
    assert_eq!(
        value["summary"]["target_entry_by_language"]["ada"], true,
        "hermetic ada_local run must observe a real Ada target entry: {value:#}"
    );
    let repos = value["repositories"]
        .as_array()
        .expect("repositories array");
    let ada_local = repos
        .iter()
        .find(|repo| repo["id"] == "ada_local")
        .expect("ada_local repository result");
    assert_eq!(
        ada_local["status"], "passed",
        "ada_local checks must all pass: {ada_local:#}"
    );
    let entry_check = ada_local["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["kind"] == "auto_target_entry")
        .expect("auto_target_entry check result");
    assert_eq!(entry_check["target_entry_observed"], true);
    let scenario = ada_local["scenarios"]
        .as_array()
        .expect("scenarios array")
        .iter()
        .find(|scenario| scenario["id"] == "ada_local_missing_dependency")
        .expect("ada broken-build scenario result");
    assert_eq!(
        scenario["status"], "passed",
        "the Ada missing-dependency scenario must be categorized, not crash: {scenario:#}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
