// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn policy_validate_writes_governance_summary() {
    let root = temp_dir("policy");
    let policy = root.join("govfuzz-policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "acme-strict",
            "languages": ["ada", "c", "cpp"],
            "rules": { "enabled": ["GF-401", "GF-402"], "disabled": [] },
            "runners": { "allowed": ["host", "qemu-aarch64"], "require_sandbox": true },
            "ci": { "fail_on_severity": "high", "fail_on_actionability": "likely" },
            "update_packs": { "allowed_kinds": ["rules", "cve", "corpus"] }
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("policy-summary.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "policy",
                "validate",
                policy.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let summary: serde_json::Value = read_json(&out);
    assert_eq!(summary["schema_version"], "govfuzz.policy.validation.v1");
    assert_eq!(summary["valid"], true);
    assert_eq!(summary["policy_id"], "acme-strict");
    assert_eq!(summary["rules"]["enabled"], 2);
    assert_eq!(summary["runners"]["require_sandbox"], true);
    assert_eq!(summary["ci"]["fail_on_severity"], "high");
}

#[test]
fn runners_validate_writes_capability_summary() {
    let root = temp_dir("runners");
    let manifest = root.join("runners.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.v1",
            "runners": [
                {
                    "id": "host",
                    "kind": "host",
                    "languages": ["ada", "c", "cpp"],
                    "engines": ["builtin", "libfuzzer"],
                    "sandbox": "firejail"
                },
                {
                    "id": "qemu-aarch64",
                    "kind": "qemu-user",
                    "languages": ["c", "cpp"],
                    "engines": ["builtin"],
                    "target": "aarch64-linux-gnu"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("runner-summary.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "validate",
                manifest.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let summary: serde_json::Value = read_json(&out);
    assert_eq!(summary["schema_version"], "govfuzz.runners.validation.v1");
    assert_eq!(summary["valid"], true);
    assert_eq!(summary["counts"]["runners"], 2);
    assert_eq!(summary["runners"][0]["id"], "host");
    assert_eq!(summary["runners"][1]["target"], "aarch64-linux-gnu");
}

#[test]
fn runners_plan_assigns_queue_with_policy_and_capacity_evidence() {
    let root = temp_dir("runner-plan");
    let manifest = root.join("runners.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.v1",
            "runners": [
                {
                    "id": "sandbox-host",
                    "kind": "sandboxed",
                    "languages": ["ada", "c", "cpp"],
                    "engines": ["builtin", "libfuzzer"],
                    "capabilities": ["sandbox", "local"],
                    "sandbox": { "required": true, "technology": "firejail" },
                    "capacity": { "max_jobs": 1, "max_seconds": 120 }
                },
                {
                    "id": "qemu-aarch64",
                    "kind": "qemu-user",
                    "languages": ["c", "cpp"],
                    "engines": ["builtin"],
                    "capabilities": ["cross", "sandbox"],
                    "target": "aarch64-linux-gnu",
                    "capacity": { "max_jobs": 2, "max_seconds": 180 }
                },
                {
                    "id": "research-adapter",
                    "kind": "binary",
                    "languages": ["binary"],
                    "engines": ["builtin"],
                    "capabilities": ["external_tool:ghidra"],
                    "capacity": { "max_jobs": 1, "max_seconds": 60 }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let queue = root.join("queue.json");
    fs::write(
        &queue,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runner_queue.v1",
            "jobs": [
                {
                    "id": "ada-stateful",
                    "language": "ada",
                    "engine": "libfuzzer",
                    "priority": "high",
                    "estimated_seconds": 90,
                    "required_capabilities": ["sandbox"]
                },
                {
                    "id": "cpp-cross",
                    "language": "cpp",
                    "engine": "builtin",
                    "priority": "medium",
                    "target": "aarch64-linux-gnu",
                    "estimated_seconds": 75,
                    "required_capabilities": ["cross"]
                },
                {
                    "id": "binary-ghidra",
                    "language": "binary",
                    "engine": "builtin",
                    "priority": "low",
                    "estimated_seconds": 30,
                    "required_tools": ["ghidra"],
                    "required_capabilities": ["external_tool:ghidra"]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "runner-plan-policy",
            "runners": {
                "allowed": ["sandbox-host", "qemu-aarch64"],
                "require_sandbox": true
            },
            "external_tools": { "denied": ["ghidra"] }
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("runner-plan.json");
    let planned = Command::new(govfuzz_bin())
        .args([
            "runners",
            "plan",
            manifest.to_str().unwrap(),
            "--queue",
            queue.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(1));

    let plan = read_json(&out);
    assert_eq!(plan["schema_version"], "govfuzz.runners.plan.v1");
    assert_eq!(plan["valid"], false);
    assert_eq!(plan["counts"]["jobs"], 3);
    assert_eq!(plan["counts"]["assigned"], 2);
    assert_eq!(plan["counts"]["unassigned"], 1);
    assert_eq!(
        assignment(&plan, "ada-stateful")["runner_id"],
        "sandbox-host"
    );
    assert_eq!(assignment(&plan, "cpp-cross")["runner_id"], "qemu-aarch64");
    assert_eq!(
        assignment(&plan, "ada-stateful")["lease_hint"],
        "sandbox-host-job-0001"
    );
    assert_eq!(
        unassigned(&plan, "binary-ghidra")["reason"],
        "denied_external_tool"
    );
    assert_eq!(
        plan["runners"]
            .as_array()
            .unwrap()
            .iter()
            .find(|runner| runner["id"] == "sandbox-host")
            .unwrap()["remaining_capacity"]["jobs"],
        0
    );
    assert_eq!(plan["policy"]["policy_id"], "runner-plan-policy");
    assert_eq!(plan["policy"]["require_sandbox"], true);
}

#[test]
fn pack_verify_checks_air_gapped_item_hashes() {
    let root = temp_dir("pack");
    let rules_dir = root.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    let rules_path = rules_dir.join("static.json");
    fs::write(&rules_path, b"{\"rules\":[\"GF-401\"]}\n").unwrap();

    let manifest = root.join("pack.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.update_pack.v1",
            "pack_id": "rules-2026-06-08",
            "version": "2026.06.08",
            "items": [{
                "kind": "rules",
                "path": "rules/static.json",
                "sha256": sha256_hex(&fs::read(&rules_path).unwrap()),
                "license": "Apache-2.0"
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("pack-verify.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "verify",
                manifest.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let summary: serde_json::Value = read_json(&out);
    assert_eq!(
        summary["schema_version"],
        "govfuzz.update_pack.verification.v1"
    );
    assert_eq!(summary["valid"], true);
    assert_eq!(summary["items"][0]["status"], "verified");
}

#[test]
fn pack_create_builds_deterministic_signed_update_pack_manifest() {
    let root = temp_dir("pack-create");
    fs::create_dir_all(root.join("rules")).unwrap();
    fs::create_dir_all(root.join("cve")).unwrap();
    fs::write(
        root.join("rules/static.json"),
        b"{\"rules\":[\"GF-401\"]}\n",
    )
    .unwrap();
    fs::write(root.join("cve/cve-db.json"), b"{\"vulnerabilities\":[]}\n").unwrap();

    let out = root.join("pack.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "create",
                "--root",
                root.to_str().unwrap(),
                "--pack-id",
                "offline-2026-06",
                "--version",
                "2026.06",
                "--item",
                "rules:rules/static.json",
                "--item",
                "cve:cve/cve-db.json",
                "--license",
                "Apache-2.0",
                "--sign-key",
                "offline-root",
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let manifest = read_json(&out);
    assert_eq!(manifest["schema_version"], "govfuzz.update_pack.v1");
    assert_eq!(manifest["pack_id"], "offline-2026-06");
    assert_eq!(manifest["items"].as_array().unwrap().len(), 2);
    assert_eq!(manifest["items"][0]["kind"], "cve");
    assert_eq!(manifest["items"][1]["kind"], "rules");
    assert_eq!(manifest["items"][0]["license"], "Apache-2.0");
    assert_eq!(manifest["signature"]["algorithm"], "sha256-items-v1");
    assert_eq!(manifest["signature"]["key_id"], "offline-root");
    assert_eq!(
        manifest["signature"]["digest"],
        pack_items_signature(manifest["items"].as_array().unwrap())
    );

    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "pack-create-policy",
            "update_packs": {
                "allowed_kinds": ["rules", "cve"],
                "require_signature": true,
                "trusted_keys": ["offline-root"]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let verify = root.join("verify.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "verify",
                out.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--out",
                verify.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(read_json(&verify)["signature"]["status"], "verified");
}

#[test]
fn export_bundle_writes_manifest_for_reports_static_policy_and_pack() {
    let root = temp_dir("export");
    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("reports")).unwrap();
    fs::create_dir_all(work.join("static")).unwrap();
    fs::create_dir_all(work.join("sbom")).unwrap();
    fs::write(work.join("reports/run-last.json"), b"{\"run\":\"last\"}\n").unwrap();
    fs::write(
        work.join("static/static-report.json"),
        b"{\"schema_version\":\"govfuzz.static.v1\"}\n",
    )
    .unwrap();
    fs::write(
        work.join("sbom/sbom.json"),
        b"{\"schema_version\":\"govfuzz.sbom.v1\"}\n",
    )
    .unwrap();
    fs::write(
        work.join("sbom/cyclonedx.json"),
        b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}\n",
    )
    .unwrap();
    fs::write(
        work.join("sbom/vulnerabilities.json"),
        b"{\"schema_version\":\"govfuzz.vulnerabilities.v1\"}\n",
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(&policy, b"{\"schema_version\":\"govfuzz.policy.v1\"}\n").unwrap();
    let pack = root.join("pack.json");
    fs::write(&pack, b"{\"schema_version\":\"govfuzz.update_pack.v1\"}\n").unwrap();

    let out = root.join("bundle-manifest.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "export",
                "--work-dir",
                work.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--update-pack",
                pack.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let manifest: serde_json::Value = read_json(&out);
    assert_eq!(manifest["schema_version"], "govfuzz.export.v1");
    assert_eq!(manifest["counts"]["artifacts"], 7);
    assert!(artifact(&manifest, "report_json", "reports/run-last.json").is_some());
    assert!(artifact(&manifest, "static_report", "static/static-report.json").is_some());
    assert!(artifact(&manifest, "sbom", "sbom/sbom.json").is_some());
    assert!(artifact(&manifest, "cyclonedx_sbom", "sbom/cyclonedx.json").is_some());
    assert!(artifact(
        &manifest,
        "vulnerability_report",
        "sbom/vulnerabilities.json"
    )
    .is_some());
    assert!(artifact(&manifest, "policy", "policy.json").is_some());
    assert!(artifact(&manifest, "update_pack", "pack.json").is_some());
}

#[test]
fn export_bundle_materializes_artifacts_for_air_gapped_handoff() {
    let root = temp_dir("export-materialized");
    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("reports")).unwrap();
    fs::create_dir_all(work.join("findings/F-1")).unwrap();
    fs::write(work.join("reports/run-last.json"), b"{\"run\":\"last\"}\n").unwrap();
    fs::write(work.join("findings/F-1/testcase.bin"), b"replay").unwrap();
    let policy = root.join("policy.json");
    fs::write(&policy, b"{\"schema_version\":\"govfuzz.policy.v1\"}\n").unwrap();

    let out = root.join("bundle-manifest.json");
    let bundle_dir = root.join("bundle");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "export",
                "--work-dir",
                work.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--bundle-dir",
                bundle_dir.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );

    let manifest = read_json(&out);
    assert_eq!(manifest["bundle"]["materialized"], true);
    assert_eq!(
        manifest["bundle"]["path"].as_str().unwrap(),
        bundle_dir.to_string_lossy()
    );
    let report = artifact(&manifest, "report_json", "reports/run-last.json").unwrap();
    let replay = artifact(&manifest, "replay_input", "findings/F-1/testcase.bin").unwrap();
    let policy_artifact = artifact(&manifest, "policy", "policy.json").unwrap();
    for copied in [report, replay, policy_artifact] {
        let bundle_path = copied["bundle_path"].as_str().unwrap();
        let copied_path = bundle_dir.join(bundle_path);
        assert!(
            copied_path.is_file(),
            "missing copied artifact {bundle_path}"
        );
        assert_eq!(
            sha256_hex(&fs::read(copied_path).unwrap()),
            copied["sha256"]
        );
    }
    let bundled_manifest = read_json(&bundle_dir.join("export-manifest.json"));
    assert_eq!(bundled_manifest["counts"]["artifacts"], 3);
}

#[test]
fn ci_and_export_include_runner_plan_governance_evidence() {
    let root = temp_dir("runner-plan-governance");
    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("reports")).unwrap();
    fs::write(
        work.join("reports/run-last.sarif"),
        b"{\"version\":\"2.1.0\"}\n",
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "ci-runner-plan",
            "ci": { "fail_on_severity": "high" }
        }))
        .unwrap(),
    )
    .unwrap();
    let runner_plan = root.join("runner-plan.json");
    fs::write(
        &runner_plan,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.plan.v1",
            "valid": false,
            "counts": { "jobs": 3, "assigned": 2, "unassigned": 1 },
            "assignments": [
                { "job_id": "ada-stateful", "runner_id": "sandbox-host" },
                { "job_id": "cpp-cross", "runner_id": "qemu-aarch64" }
            ],
            "unassigned": [
                { "job_id": "binary-ghidra", "reason": "denied_external_tool" }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let dashboard = root.join("ci-dashboard.json");
    let ci = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--runner-plan",
            runner_plan.to_str().unwrap(),
            "--dashboard-out",
            dashboard.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        ci.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    let dashboard_json = read_json(&dashboard);
    assert_eq!(dashboard_json["budget"]["allocated_targets"], 2);
    assert_eq!(dashboard_json["budget"]["runner_plan"]["assigned"], 2);
    assert_eq!(dashboard_json["budget"]["runner_plan"]["unassigned"], 1);

    let export = root.join("export.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "export",
                "--work-dir",
                work.to_str().unwrap(),
                "--out",
                export.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--runner-plan",
                runner_plan.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let exported = read_json(&export);
    assert!(artifact(&exported, "runner_plan", "runner-plan.json").is_some());
    assert_eq!(exported["governance"]["runner_plan"]["assigned"], 2);
}

#[test]
fn ci_policy_requires_runner_plan_and_full_assignment() {
    let root = temp_dir("ci-runner-plan-policy");
    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("reports")).unwrap();
    fs::write(
        work.join("reports/run-last.sarif"),
        b"{\"version\":\"2.1.0\"}\n",
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "runner-plan-required",
            "ci": {
                "fail_on_severity": "high",
                "require_runner_plan": true,
                "require_full_runner_assignment": true
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let missing_dashboard = root.join("ci-missing-runner-plan.json");
    let missing = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--dashboard-out",
            missing_dashboard.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        missing.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&missing.stdout),
        String::from_utf8_lossy(&missing.stderr)
    );
    let missing_json = read_json(&missing_dashboard);
    assert_eq!(missing_json["gate"]["failed"], true);
    assert!(missing_json["gate"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "missing_runner_plan"));
    assert_eq!(
        missing_json["decisions"]["runner_plan"]["status"],
        "missing"
    );

    let incomplete_plan = root.join("incomplete-runner-plan.json");
    fs::write(
        &incomplete_plan,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.plan.v1",
            "valid": false,
            "counts": { "jobs": 2, "assigned": 1, "unassigned": 1 },
            "assignments": [
                { "job_id": "ada-stateful", "runner_id": "sandbox-host" }
            ],
            "unassigned": [
                { "job_id": "binary-ghidra", "reason": "denied_external_tool" }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let incomplete_dashboard = root.join("ci-incomplete-runner-plan.json");
    let incomplete = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--runner-plan",
            incomplete_plan.to_str().unwrap(),
            "--dashboard-out",
            incomplete_dashboard.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        incomplete.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&incomplete.stdout),
        String::from_utf8_lossy(&incomplete.stderr)
    );
    let incomplete_json = read_json(&incomplete_dashboard);
    assert_eq!(incomplete_json["gate"]["failed"], true);
    assert!(incomplete_json["gate"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "runner_plan_unassigned"));
    assert_eq!(
        incomplete_json["decisions"]["runner_plan"]["status"],
        "incomplete"
    );
    assert_eq!(
        incomplete_json["decisions"]["runner_plan"]["summary"]["assigned"],
        1
    );
    assert_eq!(
        incomplete_json["decisions"]["runner_plan"]["summary"]["unassigned"],
        1
    );

    let complete_plan = root.join("complete-runner-plan.json");
    fs::write(
        &complete_plan,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.plan.v1",
            "valid": true,
            "counts": { "jobs": 2, "assigned": 2, "unassigned": 0 },
            "assignments": [
                { "job_id": "ada-stateful", "runner_id": "sandbox-host" },
                { "job_id": "cpp-cross", "runner_id": "qemu-aarch64" }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let complete_dashboard = root.join("ci-complete-runner-plan.json");
    let complete = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--runner-plan",
            complete_plan.to_str().unwrap(),
            "--dashboard-out",
            complete_dashboard.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        complete.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&complete.stdout),
        String::from_utf8_lossy(&complete.stderr)
    );
    let complete_json = read_json(&complete_dashboard);
    assert_eq!(complete_json["gate"]["failed"], false);
    assert_eq!(
        complete_json["decisions"]["runner_plan"]["status"],
        "complete"
    );
}

#[test]
fn sbom_generates_components_matches_offline_cves_and_gates_ci() {
    let root = temp_dir("sbom");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    let auto_dir = root.join("auto");
    fs::create_dir_all(&auto_dir).unwrap();
    fs::write(
        auto_dir.join("run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.auto.v1",
            "needed_for_build": {
                "dlopen_failures": [{
                    "name": "libssl.so.1.1",
                    "referenced_by_targets": ["H-C-LEGACY"]
                }]
            },
            "targets": [{
                "harness_id": "H-C-LEGACY",
                "source_path": "Cargo.toml",
                "name": "parse_legacy",
                "outcome": {
                    "outcome": "built_and_fuzzed",
                    "passes": [
                        { "pass": "rng", "executions": 128, "findings": [] }
                    ]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let vendor = root.join("vendor/ambiguous-lib-1.0.0");
    fs::create_dir_all(&vendor).unwrap();
    fs::write(vendor.join("VERSION"), "1.0.0\n").unwrap();
    let binary_inventory = root.join("binary-inventory.json");
    fs::write(
        &binary_inventory,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.binary.v1",
            "binaries": [{
                "path": "build/legacyd",
                "format": "elf",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let vuln_db = root.join("cve-db.json");
    fs::write(
        &vuln_db,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.cve_db.v1",
            "vulnerabilities": [
                {
                    "id": "CVE-2026-0001",
                    "severity": "critical",
                    "summary": "legacy-lib critical parser issue",
                    "package": { "ecosystem": "cargo", "name": "legacy-lib" },
                    "affected_versions": ["1.2.3"],
                    "kev": {
                        "known_exploited": true,
                        "date_added": "2026-01-15",
                        "due_date": "2026-02-01",
                        "required_action": "Apply vendor update"
                    }
                },
                {
                    "id": "CVE-2026-0002",
                    "severity": "medium",
                    "summary": "ambiguous vendored component",
                    "package": { "ecosystem": "generic", "name": "ambiguous-lib" },
                    "affected_versions": ["1.0.0"]
                },
                {
                    "id": "CVE-2026-0003",
                    "severity": "high",
                    "summary": "runtime OpenSSL fixture",
                    "package": { "ecosystem": "runtime-dlopen", "name": "libssl" },
                    "affected_versions": ["1.1"]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "sbom-policy",
            "ci": { "fail_on_vulnerability_severity": "high" }
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("govfuzz_work/sbom");
    let output = Command::new(govfuzz_bin())
        .args([
            "sbom",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--vuln-db",
            vuln_db.to_str().unwrap(),
            "--binary-inventory",
            binary_inventory.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let sbom: serde_json::Value = read_json(&out.join("sbom.json"));
    assert_eq!(sbom["schema_version"], "govfuzz.sbom.v1");
    assert_eq!(
        component(&sbom, "legacy-lib")["identity_confidence"],
        "high"
    );
    assert_eq!(
        component(&sbom, "ambiguous-lib")["identity_confidence"],
        "low"
    );
    assert_eq!(
        component(&sbom, "build/legacyd")["matching_method"],
        "binary_inventory"
    );
    assert_eq!(
        component(&sbom, "libssl")["matching_method"],
        "runtime_dlopen"
    );
    assert_eq!(
        component(&sbom, "libssl")["runtime_harnesses"][0],
        "H-C-LEGACY"
    );
    let cyclonedx: serde_json::Value = read_json(&out.join("cyclonedx.json"));
    assert_eq!(cyclonedx["bomFormat"], "CycloneDX");
    assert_eq!(cyclonedx["specVersion"], "1.6");
    assert_eq!(
        cyclonedx["metadata"]["tools"]["components"][0]["name"],
        "govfuzz"
    );
    assert_eq!(
        cyclonedx_component(&cyclonedx, "legacy-lib")["version"],
        "1.2.3"
    );
    assert_eq!(
        cyclonedx_component(&cyclonedx, "legacy-lib")["purl"],
        "pkg:cargo/legacy-lib@1.2.3"
    );
    assert_eq!(
        cyclonedx_component(&cyclonedx, "build/legacyd")["hashes"][0]["alg"],
        "SHA-256"
    );
    assert!(cyclonedx_component(&cyclonedx, "libssl")["properties"]
        .as_array()
        .unwrap()
        .iter()
        .any(|property| property["name"] == "govfuzz:matching_method"
            && property["value"] == "runtime_dlopen"));

    let vulns: serde_json::Value = read_json(&out.join("vulnerabilities.json"));
    assert_eq!(vulns["schema_version"], "govfuzz.vulnerabilities.v1");
    assert_eq!(vulns["counts"]["matches"], 3);
    assert_eq!(vulns["counts"]["kev_matches"], 1);
    assert_eq!(vulns["counts"]["reached_matches"], 2);
    assert_eq!(vulns["gate"]["failed"], true);
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0001")["match_confidence"],
        "high"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0001")["reachability"]["status"],
        "reached_by_fuzz"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0001")["reachability"]["harnesses"][0]["harness_id"],
        "H-C-LEGACY"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0001")["kev"]["known_exploited"],
        true
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0001")["kev"]["due_date"],
        "2026-02-01"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0002")["match_confidence"],
        "low"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0003")["reachability"]["status"],
        "reached_by_fuzz"
    );
    assert_eq!(
        vulnerability(&vulns, "CVE-2026-0003")["reachability"]["harnesses"][0]["harness_id"],
        "H-C-LEGACY"
    );
}

#[test]
fn enterprise_ops_support_runners_packs_policy_ci_audit_and_dashboard() {
    let root = temp_dir("enterprise-complete");
    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("findings/F-1")).unwrap();
    fs::create_dir_all(work.join("reports")).unwrap();
    fs::create_dir_all(work.join("evidence/real-code")).unwrap();
    fs::write(
        work.join("findings/F-1/finding.json"),
        serde_json::to_vec_pretty(&json!({
            "id": "F-1",
            "rule_id": "GF-401",
            "severity": "high",
            "actionability": { "verdict": "likely_reachable", "confidence": "high" },
            "runner": { "profile_id": "sandbox-host", "capabilities": ["libfuzzer", "sandbox"] },
            "flaky": false
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(work.join("findings/F-1/testcase.bin"), b"replay").unwrap();
    fs::write(
        work.join("reports/run-last.sarif"),
        b"{\"version\":\"2.1.0\"}\n",
    )
    .unwrap();
    fs::write(
        work.join("evidence/real-code/tinyxml2.json"),
        b"{\"repo\":\"tinyxml2\"}\n",
    )
    .unwrap();

    let runners = root.join("runners.json");
    fs::write(
        &runners,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.v1",
            "runners": [
                {
                    "id": "host",
                    "kind": "host",
                    "languages": ["ada", "c", "cpp"],
                    "engines": ["builtin", "libfuzzer"],
                    "capabilities": ["local"]
                },
                {
                    "id": "sandbox-host",
                    "kind": "sandboxed",
                    "languages": ["ada", "c", "cpp"],
                    "engines": ["libfuzzer"],
                    "capabilities": ["sandbox", "local"],
                    "sandbox": { "required": true, "technology": "firejail" },
                    "resource_limits": { "timeout_seconds": 120, "memory_mb": 2048 }
                },
                {
                    "id": "qemu-aarch64",
                    "kind": "qemu-user",
                    "languages": ["c", "cpp"],
                    "engines": ["builtin"],
                    "capabilities": ["cross"],
                    "target": "aarch64-linux-gnu"
                },
                {
                    "id": "handoff",
                    "kind": "distributed",
                    "languages": ["ada", "c", "cpp"],
                    "engines": ["libfuzzer", "afl"],
                    "capabilities": ["offline_handoff"]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let runner_list = root.join("runner-list.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "list",
                runners.to_str().unwrap(),
                "--out",
                runner_list.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let runner_list_json = read_json(&runner_list);
    assert_eq!(runner_list_json["counts"]["by_kind"]["qemu-user"], 1);
    assert_eq!(runner_list_json["counts"]["by_kind"]["distributed"], 1);

    let selected_runner = root.join("selected-runner.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "select",
                runners.to_str().unwrap(),
                "--runner",
                "sandbox-host",
                "--out",
                selected_runner.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let selected = read_json(&selected_runner);
    assert_eq!(selected["runner"]["id"], "sandbox-host");
    assert_eq!(selected["capability_evidence"]["sandbox_required"], true);

    let handoff = root.join("handoff.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "handoff",
                runners.to_str().unwrap(),
                "--runner",
                "handoff",
                "--work-dir",
                work.to_str().unwrap(),
                "--out",
                handoff.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let handoff_json = read_json(&handoff);
    assert_eq!(handoff_json["selected_runner"]["id"], "handoff");
    assert!(handoff_json["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| {
            artifact["kind"] == "finding" && artifact["path"].as_str().unwrap().contains("F-1")
        }));

    let lease = root.join("runner-lease.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "lease",
                handoff.to_str().unwrap(),
                "--runner",
                "handoff",
                "--lease-id",
                "lease-001",
                "--out",
                lease.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let lease_json = read_json(&lease);
    assert_eq!(lease_json["schema_version"], "govfuzz.runners.lease.v1");
    assert_eq!(lease_json["valid"], true);
    assert_eq!(lease_json["runner"]["id"], "handoff");
    assert_eq!(lease_json["lease"]["id"], "lease-001");
    assert!(lease_json["jobs"].as_array().unwrap().iter().any(|job| {
        job["artifact"]["kind"] == "finding"
            && job["artifact"]["path"].as_str().unwrap().contains("F-1")
    }));

    let runner_result = root.join("runner-result.json");
    fs::write(&runner_result, b"{\"result\":\"completed\"}\n").unwrap();
    let completion = root.join("runner-completion.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "runners",
                "complete",
                lease.to_str().unwrap(),
                "--artifact",
                runner_result.to_str().unwrap(),
                "--out",
                completion.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let completion_json = read_json(&completion);
    assert_eq!(
        completion_json["schema_version"],
        "govfuzz.runners.completion.v1"
    );
    assert_eq!(completion_json["status"], "completed");
    assert_eq!(completion_json["lease"]["id"], "lease-001");
    assert_eq!(completion_json["artifacts"][0]["kind"], "runner_result");

    let bad_runners = root.join("bad-runners.json");
    fs::write(
        &bad_runners,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.runners.v1",
            "runners": [{ "kind": "remote" }]
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_out = root.join("bad-runners-summary.json");
    let bad = Command::new(govfuzz_bin())
        .args([
            "runners",
            "validate",
            bad_runners.to_str().unwrap(),
            "--out",
            bad_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(read_json(&bad_out)["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("missing id"));

    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "strict-enterprise",
            "version": "2026.06",
            "rules": { "disabled": ["GF-999"] },
            "external_tools": { "denied": ["ghidra"] },
            "runners": { "allowed": ["sandbox-host", "handoff"], "require_sandbox": true },
            "update_packs": {
                "allowed_kinds": ["rules", "cve", "corpus"],
                "denied_licenses": ["GPL-3.0-only"],
                "denied_required_tools": ["ghidra"],
                "require_signature": true,
                "trusted_keys": ["offline-root"]
            },
            "ci": {
                "fail_on_severity": "high",
                "fail_on_actionability": "likely",
                "require_artifacts": ["sarif", "replay_input", "junit"],
                "waivers": [{
                    "id": "W-F-1",
                    "finding_id": "F-1",
                    "reason": "accepted enterprise risk for regression coverage",
                    "expires": "2027-01-01"
                }]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let policy_explain = root.join("policy-explain.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "policy",
                "explain",
                policy.to_str().unwrap(),
                "--out",
                policy_explain.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(
        read_json(&policy_explain)["policy_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    let dry_run = root.join("policy-dry-run.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "policy",
                "dry-run",
                policy.to_str().unwrap(),
                "--finding",
                work.join("findings/F-1/finding.json").to_str().unwrap(),
                "--out",
                dry_run.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let dry = read_json(&dry_run);
    assert_eq!(dry["decisions"]["ci_gate"], "pass");
    assert_eq!(dry["decisions"]["waived"], true);
    assert_eq!(dry["decisions"]["waiver_id"], "W-F-1");
    assert_eq!(dry["decisions"]["runner_allowed"], true);
    assert_eq!(dry["policy"]["policy_id"], "strict-enterprise");

    let pack_root = root.join("pack-root");
    fs::create_dir_all(pack_root.join("rules")).unwrap();
    let rules_path = pack_root.join("rules/static.json");
    fs::write(&rules_path, b"{\"rules\":[\"GF-777\"]}\n").unwrap();
    let rules_sha = sha256_hex(&fs::read(&rules_path).unwrap());
    let pack_items = vec![json!({
        "kind": "rules",
        "path": "rules/static.json",
        "sha256": rules_sha,
        "license": "Apache-2.0",
        "required_tools": []
    })];
    let pack_signature = pack_items_signature(&pack_items);
    let pack = pack_root.join("pack.json");
    fs::write(
        &pack,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.update_pack.v1",
            "pack_id": "offline-rules",
            "version": "2026.06",
            "items": pack_items,
            "signature": {
                "algorithm": "sha256-items-v1",
                "key_id": "offline-root",
                "digest": pack_signature
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let pack_inspect = root.join("pack-inspect.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "inspect",
                pack.to_str().unwrap(),
                "--out",
                pack_inspect.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(read_json(&pack_inspect)["counts"]["items"], 1);

    let pack_verify = root.join("pack-verify.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "verify",
                pack.to_str().unwrap(),
                "--root",
                pack_root.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--out",
                pack_verify.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let pack_verify_json = read_json(&pack_verify);
    assert_eq!(pack_verify_json["signature"]["status"], "verified");
    assert_eq!(pack_verify_json["signature"]["key_id"], "offline-root");

    let installed = root.join("installed-packs");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "pack",
                "install",
                pack.to_str().unwrap(),
                "--root",
                pack_root.to_str().unwrap(),
                "--install-dir",
                installed.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert!(installed.join("offline-rules/pack.json").is_file());
    assert!(installed.join("offline-rules/rules/static.json").is_file());

    let denied_pack = pack_root.join("denied-pack.json");
    fs::write(
        &denied_pack,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.update_pack.v1",
            "pack_id": "denied-adapter",
            "items": [{
                "kind": "adapter",
                "path": "rules/static.json",
                "sha256": sha256_hex(&fs::read(&rules_path).unwrap()),
                "license": "GPL-3.0-only",
                "required_tools": ["ghidra"]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let denied = Command::new(govfuzz_bin())
        .args([
            "pack",
            "verify",
            denied_pack.to_str().unwrap(),
            "--root",
            pack_root.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(1));

    let audit_log = root.join("audit.jsonl");
    let audit_event = root.join("audit-event.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "audit",
                "append",
                "--log",
                audit_log.to_str().unwrap(),
                "--event",
                "scan_started",
                "--actor",
                "alice",
                "--role",
                "operator",
                "--project",
                "legacy",
                "--out",
                audit_event.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(read_json(&audit_event)["event"], "scan_started");

    let audit_summary = root.join("audit-summary.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "audit",
                "read",
                "--log",
                audit_log.to_str().unwrap(),
                "--out",
                audit_summary.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(read_json(&audit_summary)["counts"]["events"], 1);

    let ci_dashboard = root.join("ci-dashboard.json");
    let ci = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--dashboard-out",
            ci_dashboard.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(ci.status.code(), Some(1));
    let ci_json = read_json(&ci_dashboard);
    assert_eq!(ci_json["schema_version"], "govfuzz.ci.dashboard.v1");
    assert_eq!(ci_json["policy"]["policy_id"], "strict-enterprise");
    assert_eq!(ci_json["gate"]["failed"], true);
    assert_eq!(ci_json["gate"]["reason"], "missing_required_artifacts");
    assert!(ci_json["decisions"]["missing_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|kind| kind == "junit"));
    assert_eq!(
        ci_json["decisions"]["waived_findings"][0]["finding_id"],
        "F-1"
    );
    assert_eq!(ci_json["budget"]["strategy"], "deterministic-risk");

    fs::write(
        work.join("reports/run-last.junit.xml"),
        b"<?xml version=\"1.0\"?><testsuite tests=\"1\" failures=\"0\"/>\n",
    )
    .unwrap();
    let ci_dashboard_after_evidence = root.join("ci-dashboard-after-evidence.json");
    let ci_after_evidence = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--no-stubs",
            "--policy",
            policy.to_str().unwrap(),
            "--dashboard-out",
            ci_dashboard_after_evidence.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        ci_after_evidence.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&ci_after_evidence.stdout),
        String::from_utf8_lossy(&ci_after_evidence.stderr)
    );
    let ci_after_json = read_json(&ci_dashboard_after_evidence);
    assert_eq!(ci_after_json["gate"]["failed"], false);
    assert_eq!(
        ci_after_json["decisions"]["missing_evidence"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let dashboard = root.join("dashboard.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "dashboard",
                "--work-dir",
                work.to_str().unwrap(),
                "--audit-log",
                audit_log.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--runner-manifest",
                runners.to_str().unwrap(),
                "--out",
                dashboard.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let dashboard_json = read_json(&dashboard);
    assert_eq!(dashboard_json["schema_version"], "govfuzz.dashboard.v1");
    assert_eq!(dashboard_json["rbac"]["roles"][0], "reader");
    assert_eq!(dashboard_json["counts"]["audit_events"], 1);

    let export = root.join("bundle-manifest.json");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "export",
                "--work-dir",
                work.to_str().unwrap(),
                "--out",
                export.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--update-pack",
                pack.to_str().unwrap(),
                "--audit-log",
                audit_log.to_str().unwrap(),
                "--runner-manifest",
                runners.to_str().unwrap(),
                "--require-artifact",
                "sarif",
                "--require-artifact",
                "replay_input",
                "--require-artifact",
                "junit",
            ])
            .output()
            .unwrap(),
    );
    let exported = read_json(&export);
    assert_eq!(exported["schema_version"], "govfuzz.export.v1");
    assert!(artifact(&exported, "replay_input", "findings/F-1/testcase.bin").is_some());
    assert_eq!(
        exported["governance"]["policy_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        exported["governance"]["update_packs"][0]["signature"]["status"],
        "verified"
    );
    assert_eq!(
        exported["required_artifacts"]["missing"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

fn artifact<'a>(
    manifest: &'a serde_json::Value,
    kind: &str,
    path_suffix: &str,
) -> Option<&'a serde_json::Value> {
    manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| {
            artifact["kind"] == kind
                && artifact["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(path_suffix))
        })
}

fn component<'a>(sbom: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == name)
        .unwrap()
}

fn cyclonedx_component<'a>(sbom: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == name)
        .unwrap()
}

fn vulnerability<'a>(report: &'a serde_json::Value, cve: &str) -> &'a serde_json::Value {
    report["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == cve)
        .unwrap()
}

fn assignment<'a>(plan: &'a serde_json::Value, job_id: &str) -> &'a serde_json::Value {
    plan["assignments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|assignment| assignment["job_id"] == job_id)
        .unwrap()
}

fn unassigned<'a>(plan: &'a serde_json::Value, job_id: &str) -> &'a serde_json::Value {
    plan["unassigned"]
        .as_array()
        .unwrap()
        .iter()
        .find(|assignment| assignment["job_id"] == job_id)
        .unwrap()
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn pack_items_signature(items: &[serde_json::Value]) -> String {
    let mut hasher = Sha256::new();
    for item in items {
        for key in ["kind", "path", "sha256"] {
            hasher.update(item[key].as_str().unwrap_or("").as_bytes());
            hasher.update(b"\t");
        }
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-enterprise-ops-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
