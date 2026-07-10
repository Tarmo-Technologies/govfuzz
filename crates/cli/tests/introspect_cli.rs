// SPDX-License-Identifier: Apache-2.0

use cli::auto::discovery;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn tempdir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-introspect-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_two_target_project(root: &Path) {
    fs::write(
        root.join("parse.c"),
        r#"
int parse_packet(const unsigned char *data, unsigned long len) {
  if (parse_header(data, len)) return 2;
  if (parse_body(data, len)) return 3;
  if (len > 3 && data[0] == 'G' && data[1] == 'F') return 1;
  return 0;
}

int parse_header(const unsigned char *data, unsigned long len) {
  if (parse_magic(data, len)) return 2;
  if (len > 0 && data[0] == 0x42) return 1;
  return 0;
}

int parse_magic(const unsigned char *data, unsigned long len) {
  if (len >= 5 && data[0] == 'M' && data[1] == 'A') return 1;
  return 0;
}

int parse_orphan(const unsigned char *data, unsigned long len) {
  if (len >= 2 && data[0] == 'O' && data[1] == 'R') return 1;
  return 0;
}
"#,
    )
    .unwrap();
}

fn write_ada_parameterless_helper_project(root: &Path) {
    fs::write(
        root.join("helper.adb"),
        r#"
procedure Helper is
begin
   null;
end Helper;
"#,
    )
    .unwrap();
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Helper;
   if Input'Length > 0 then
      null;
   end if;
end Parse;
"#,
    )
    .unwrap();
}

fn write_ada_package_qualified_helper_project(root: &Path) {
    fs::write(
        root.join("helpers.ads"),
        r#"
package Helpers is
   procedure Helper;
end Helpers;
"#,
    )
    .unwrap();
    fs::write(
        root.join("helpers.adb"),
        r#"
package body Helpers is
   procedure Helper is
   begin
      null;
   end Helper;
end Helpers;
"#,
    )
    .unwrap();
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Helpers.Helper;
   if Input'Length > 0 then
      null;
   end if;
end Parse;
"#,
    )
    .unwrap();
}

fn write_ada_missing_parameterless_call_project(root: &Path) {
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Missing_Helper;
   if Input'Length > 0 then
      null;
   end if;
end Parse;
"#,
    )
    .unwrap();
}

fn write_ada_argument_arity_mismatch_project(root: &Path) {
    fs::write(
        root.join("helper.adb"),
        r#"
procedure Helper is
begin
   null;
end Helper;
"#,
    )
    .unwrap();
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Helper (Input);
end Parse;
"#,
    )
    .unwrap();
}

fn write_ada_grouped_formal_helper_project(root: &Path) {
    fs::write(
        root.join("helper.adb"),
        r#"
procedure Helper (Left, Right : in String) is
begin
   null;
end Helper;
"#,
    )
    .unwrap();
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Helper (Input, Input);
end Parse;
"#,
    )
    .unwrap();
}

fn write_ada_defaulted_formal_helper_project(root: &Path) {
    fs::write(
        root.join("helper.adb"),
        r#"
procedure Helper (Required : in String; Optional : in String := "fallback") is
begin
   null;
end Helper;
"#,
    )
    .unwrap();
    fs::write(
        root.join("parse.adb"),
        r#"
procedure Parse (Input : in String) is
begin
   Helper (Input);
end Parse;
"#,
    )
    .unwrap();
}

#[test]
fn introspect_json_marks_targets_absent_from_prior_auto_run() {
    let root = tempdir("json");
    write_two_target_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    assert!(
        candidates.len() >= 2,
        "fixture should expose at least two targets: {candidates:?}"
    );
    let already_run = candidates
        .iter()
        .find(|candidate| candidate.name == "parse_packet")
        .expect("parse_packet candidate");

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": already_run.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let cmplog_path = work.join("cmplog.jsonl");
    fs::write(
        &cmplog_path,
        b"{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"4141\",\"b\":\"4d41474943\"}\n",
    )
    .unwrap();
    fs::create_dir_all(work.join("fuzz_runs")).unwrap();
    fs::write(
        work.join("fuzz_runs")
            .join(format!("{}-latest.json", already_run.harness_id)),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "harness_id": already_run.harness_id,
            "cmplog": {
                "enabled": true,
                "status": "loaded",
                "log_path": cmplog_path,
                "entries": 1,
                "dictionary_tokens": 2,
                "seed_splice_candidates": 0
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["prior_run"]["present"], true);
    assert!(
        value["discovered"]["total"].as_u64().unwrap() >= 2,
        "discovered count should include both fixture targets: {value:#}"
    );

    let targets = value["targets"].as_array().expect("targets array");
    let packet = targets
        .iter()
        .find(|target| target["name"] == "parse_packet")
        .expect("parse_packet row");
    assert_eq!(packet["prior_outcome"], "built_and_fuzzed");
    assert_eq!(packet["blocker_kind"], "already_fuzzed");
    let direct_callees = packet["static_reachability"]["direct_callees"]
        .as_array()
        .expect("direct callees");
    assert!(
        direct_callees
            .iter()
            .any(|callee| callee["name"] == "parse_header"),
        "parse_packet should statically reach parse_header: {packet:#}"
    );
    let uncovered_callees = packet["static_reachability"]["uncovered_direct_callees"]
        .as_array()
        .expect("uncovered direct callees");
    assert!(
        uncovered_callees
            .iter()
            .any(|callee| callee["name"] == "parse_header"
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "parse_header should be reported as an uncovered direct callee: {packet:#}"
    );
    let reachable_callees = packet["static_reachability"]["uncovered_reachable_callees"]
        .as_array()
        .expect("uncovered reachable callees");
    assert!(
        reachable_callees
            .iter()
            .any(|callee| callee["name"] == "parse_magic"
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "parse_magic should be reported as an uncovered transitive callee: {packet:#}"
    );
    let unresolved_calls = packet["static_reachability"]["unresolved_calls"]
        .as_array()
        .expect("unresolved calls");
    assert!(
        unresolved_calls
            .iter()
            .any(|call| call["call"] == "parse_body"),
        "parse_packet should report the unresolved parse_body call: {packet:#}"
    );

    let header = targets
        .iter()
        .find(|target| target["name"] == "parse_header")
        .expect("parse_header row");
    assert_eq!(header["prior_outcome"], "not_seen_in_prior_run");
    assert_eq!(header["blocker_kind"], "not_run");
    assert!(header["recommendation"]
        .as_str()
        .unwrap()
        .contains("add or run a harness"));
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    let top_blocker = blockers.first().expect("top coverage blocker");
    assert_eq!(
        top_blocker["kind"], "static_reachability_gap",
        "coverage blockers should be ranked by actionable static reachability first: {value:#}"
    );
    assert_eq!(
        top_blocker["blocked_target"]["name"], "parse_header",
        "direct static callee gaps should rank ahead of transitive/dynamic/orphan blockers: {value:#}"
    );
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["name"] == "parse_packet"
                && blocker["blocked_target"]["name"] == "parse_header"
        }),
        "expected static reachability blocker for parse_packet -> parse_header: {value:#}"
    );
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["name"] == "parse_packet"
                && blocker["blocked_target"]["name"] == "parse_magic"
                && blocker["evidence"]
                    .as_array()
                    .expect("transitive evidence")
                    .iter()
                    .any(|evidence| evidence["key"] == "depth" && evidence["value"] == "2")
                && blocker["evidence"]
                    .as_array()
                    .expect("transitive evidence")
                    .iter()
                    .any(|evidence| evidence["key"] == "call_chain"
                        && evidence["value"] == "parse_packet -> parse_header -> parse_magic")
        }),
        "expected transitive static reachability blocker for parse_packet -> parse_magic: {value:#}"
    );
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "unresolved_static_call"
                && blocker["source_target"]["name"] == "parse_packet"
                && blocker["evidence"]
                    .as_array()
                    .expect("unresolved evidence")
                    .iter()
                    .any(|evidence| evidence["key"] == "call" && evidence["value"] == "parse_body")
        }),
        "expected unresolved static call blocker for parse_body: {value:#}"
    );
    let cmplog = &packet["dynamic_coverage"]["cmplog"];
    assert_eq!(
        cmplog["enabled"], true,
        "packet row should include cmplog dynamic coverage: {packet:#}\nfull output: {value:#}"
    );
    assert_eq!(cmplog["entries"], 1);
    assert_eq!(cmplog["seed_splice_candidates"], 0);
    assert!(
        cmplog["suggested_dictionary_tokens"]
            .as_array()
            .expect("suggested cmplog tokens")
            .iter()
            .any(|token| token["hex"] == "4d41474943"),
        "cmplog should expose magic operand suggestions: {packet:#}"
    );
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "comparison_gate"
                && blocker["source_target"]["name"] == "parse_packet"
                && blocker["evidence"][0]["key"] == "token_hex"
                && blocker["evidence"][0]["value"] == "4141"
        }),
        "expected comparison-gate blocker from cmplog evidence: {value:#}"
    );
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "unreached_public_target"
                && blocker["source_target"]["name"] == "parse_orphan"
                && blocker.get("blocked_target").is_none()
                && blocker["recommendation"]
                    .as_str()
                    .is_some_and(|recommendation| recommendation.contains("add or run a harness"))
        }),
        "expected per-tree blocker for orphan not-run target: {value:#}"
    );
    assert!(
        !blockers.iter().any(|blocker| {
            blocker["kind"] == "unreached_public_target"
                && (blocker["source_target"]["name"] == "parse_header"
                    || blocker["source_target"]["name"] == "parse_magic")
        }),
        "static-reachability gaps should not be duplicated as orphan blockers: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_static_reachability_gap() {
    let root = tempdir("ada-json");
    write_ada_parameterless_helper_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case("helper")),
        "fixture should expose Helper as an Ada candidate: {candidates:?}"
    );

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert_eq!(parse_row["language"], "ada");
    assert_eq!(parse_row["prior_outcome"], "built_and_fuzzed");
    assert!(
        parse_row["static_reachability"]["uncovered_direct_callees"]
            .as_array()
            .expect("uncovered direct callees")
            .iter()
            .any(|callee| callee["language"] == "ada"
                && callee["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "Parse should report Helper as an uncovered Ada direct callee: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["blocked_target"]["language"] == "ada"
                && blocker["blocked_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
        }),
        "expected Ada static reachability blocker for Parse -> Helper: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_package_qualified_reachability_gap() {
    let root = tempdir("ada-qualified-json");
    write_ada_package_qualified_helper_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");
    assert!(
        candidates.iter().any(|candidate| {
            candidate.name.eq_ignore_ascii_case("helper")
                || candidate.name.eq_ignore_ascii_case("helpers.helper")
        }),
        "fixture should expose Helpers.Helper as an Ada candidate: {candidates:?}"
    );

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert!(
        parse_row["static_reachability"]["uncovered_direct_callees"]
            .as_array()
            .expect("uncovered direct callees")
            .iter()
            .any(|callee| callee["language"] == "ada"
                && callee["name"].as_str().is_some_and(|name| {
                    name.eq_ignore_ascii_case("helper")
                        || name.eq_ignore_ascii_case("helpers.helper")
                })
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "Parse should report Helpers.Helper as an uncovered Ada direct callee: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["blocked_target"]["language"] == "ada"
                && blocker["blocked_target"]["name"]
                    .as_str()
                    .is_some_and(|name| {
                        name.eq_ignore_ascii_case("helper")
                            || name.eq_ignore_ascii_case("helpers.helper")
                    })
        }),
        "expected Ada static reachability blocker for Parse -> Helpers.Helper: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_unresolved_parameterless_call_blocker() {
    let root = tempdir("ada-unresolved-json");
    write_ada_missing_parameterless_call_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert!(
        parse_row["static_reachability"]["unresolved_calls"]
            .as_array()
            .expect("unresolved calls")
            .iter()
            .any(|call| call["call"] == "Missing_Helper" && call["line"] == 4),
        "Parse should report Missing_Helper as an unresolved Ada call: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "unresolved_static_call"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["evidence"]
                    .as_array()
                    .expect("unresolved evidence")
                    .iter()
                    .any(|evidence| {
                        evidence["key"] == "call" && evidence["value"] == "Missing_Helper"
                    })
        }),
        "expected unresolved Ada static-call blocker for Missing_Helper: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_argument_arity_mismatch_as_unresolved_call() {
    let root = tempdir("ada-arity-mismatch-json");
    write_ada_argument_arity_mismatch_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case("helper")),
        "fixture should expose parameterless Helper as an Ada candidate: {candidates:?}"
    );

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert!(
        parse_row["static_reachability"]["unresolved_calls"]
            .as_array()
            .expect("unresolved calls")
            .iter()
            .any(|call| call["call"] == "Helper" && call["line"] == 4),
        "Parse should report Helper(Input) as unresolved when only Helper exists: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "unresolved_static_call"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["evidence"]
                    .as_array()
                    .expect("unresolved evidence")
                    .iter()
                    .any(|evidence| evidence["key"] == "call" && evidence["value"] == "Helper")
        }),
        "expected unresolved Ada static-call blocker for Helper(Input): {value:#}"
    );
    assert!(
        !blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["blocked_target"]["language"] == "ada"
                && blocker["blocked_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
        }),
        "Helper(Input) must not be reported as a reachability gap for parameterless Helper: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_grouped_formal_reachability_gap() {
    let root = tempdir("ada-grouped-formal-json");
    write_ada_grouped_formal_helper_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case("helper")),
        "fixture should expose grouped-formal Helper as an Ada candidate: {candidates:?}"
    );

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert!(
        parse_row["static_reachability"]["uncovered_direct_callees"]
            .as_array()
            .expect("uncovered direct callees")
            .iter()
            .any(|callee| callee["language"] == "ada"
                && callee["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "Parse should report grouped-formal Helper as an uncovered Ada direct callee: {parse_row:#}"
    );
    assert!(
        !parse_row["static_reachability"]["unresolved_calls"]
            .as_array()
            .expect("unresolved calls")
            .iter()
            .any(|call| call["call"] == "helper"),
        "Parse should not report grouped-formal Helper(Input, Input) as unresolved: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["blocked_target"]["language"] == "ada"
                && blocker["blocked_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
        }),
        "expected Ada static reachability blocker for Parse -> grouped-formal Helper: {value:#}"
    );
}

#[test]
fn introspect_json_reports_ada_defaulted_formal_reachability_gap() {
    let root = tempdir("ada-defaulted-formal-json");
    write_ada_defaulted_formal_helper_project(&root);

    let candidates = discovery::discover(&root).expect("discover candidates");
    let parse = candidates
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case("parse"))
        .expect("Parse candidate");
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case("helper")),
        "fixture should expose defaulted-formal Helper as an Ada candidate: {candidates:?}"
    );

    let work = root.join("govfuzz_work");
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(
        work.join("auto/run.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "summary": {
                "discovered": 1,
                "built": 1,
                "built_and_fuzzed": 1,
                "findings": 0
            },
            "targets": [
                {
                    "harness_id": parse.harness_id,
                    "outcome": { "outcome": "built_and_fuzzed" }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("introspect json output");
    let targets = value["targets"].as_array().expect("targets array");
    let parse_row = targets
        .iter()
        .find(|target| {
            target["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
        })
        .expect("Parse row");
    assert!(
        parse_row["static_reachability"]["uncovered_direct_callees"]
            .as_array()
            .expect("uncovered direct callees")
            .iter()
            .any(|callee| callee["language"] == "ada"
                && callee["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
                && callee["prior_outcome"] == "not_seen_in_prior_run"),
        "Parse should report defaulted-formal Helper as an uncovered Ada direct callee: {parse_row:#}"
    );
    assert!(
        !parse_row["static_reachability"]["unresolved_calls"]
            .as_array()
            .expect("unresolved calls")
            .iter()
            .any(|call| call["call"] == "helper"),
        "Parse should not report Helper(Input) as unresolved when omitted formals have defaults: {parse_row:#}"
    );
    let blockers = value["coverage_blockers"]
        .as_array()
        .expect("coverage blockers");
    assert!(
        blockers.iter().any(|blocker| {
            blocker["kind"] == "static_reachability_gap"
                && blocker["source_target"]["language"] == "ada"
                && blocker["source_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("parse"))
                && blocker["blocked_target"]["language"] == "ada"
                && blocker["blocked_target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("helper"))
        }),
        "expected Ada static reachability blocker for Parse -> defaulted-formal Helper: {value:#}"
    );
}

#[test]
fn introspect_markdown_guides_first_run_when_no_auto_report_exists() {
    let root = tempdir("markdown");
    write_two_target_project(&root);

    // Pin an isolated (nonexistent) work dir so "no prior run" is genuine. Without
    // this the default `govfuzz_work` resolves against the process CWD, and a stray
    // `govfuzz_work/auto/run.json` left in the crate dir by any earlier `govfuzz auto`
    // makes the prior-run probe fire — every other introspect test already isolates.
    let work = root.join("gw");
    let out = Command::new(govfuzz_bin())
        .args([
            "introspect",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("spawn govfuzz introspect");
    assert!(
        out.status.success(),
        "introspect exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("# GovFuzz Introspection"));
    assert!(stdout.contains("Prior auto run: not found"));
    assert!(stdout.contains("govfuzz auto"));
    assert!(stdout.contains("parse_packet"));
}
