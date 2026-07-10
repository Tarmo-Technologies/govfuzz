// SPDX-License-Identifier: Apache-2.0

use cli::run_from;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn fuzz_builtin_writes_replayable_finding() {
    let temp = temp_dir("builtin-replay");
    let work_dir = temp.join("govfuzz_work");
    let harness_id = "H-TEST";
    let harness = install_fake_harness(&work_dir, harness_id);

    let fuzz_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--seed-input"),
        OsString::from("crash"),
    ]);

    assert_eq!(fuzz_exit, 0);
    assert!(work_dir.join("corpus/H-TEST/queue").is_dir());
    let run_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-TEST-latest.json")).unwrap())
            .unwrap();
    assert_eq!(run_summary["sandbox"]["mode"], "none");
    let finding_dir = only_finding_dir(&work_dir);
    let finding_json: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding_json["sandbox"]["mode"], "none");
    assert_eq!(finding_json["build"]["sandbox"]["mode"], "none");
    assert_eq!(
        fs::read(finding_dir.join("testcase.bin")).expect("testcase is readable"),
        b"crash"
    );

    let replay_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("replay"),
        OsString::from("--finding"),
        finding_dir.into_os_string(),
        OsString::from("--harness"),
        harness.into_os_string(),
    ]);

    assert_eq!(replay_exit, 0);
}

#[test]
fn fuzz_builtin_returns_three_when_harness_executable_missing() {
    let temp = temp_dir("missing-harness");
    let work_dir = temp.join("govfuzz_work");
    fs::create_dir_all(work_dir.join("build/H-MISSING")).expect("build directory is created");

    let exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.into_os_string(),
        OsString::from("--harness"),
        OsString::from("H-MISSING"),
        OsString::from("--iterations"),
        OsString::from("1"),
    ]);

    assert_eq!(exit, 3);
}

#[test]
fn fuzz_builtin_uses_symbolic_seed_source_for_first_execution() {
    let temp = temp_dir("symbolic-seed");
    let work_dir = temp.join("govfuzz_work");
    let harness_id = "H-TEST";
    let _harness = install_fake_harness(&work_dir, harness_id);
    let source_path = temp.join("guarded.adb");
    fs::write(
        &source_path,
        r#"
procedure Guarded (Input : String) is
begin
   if Input = "match" then
      raise Constraint_Error;
   end if;
end Guarded;
"#,
    )
    .expect("guarded source is written");

    let fuzz_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--symbolic-seed-source"),
        source_path.into_os_string(),
    ]);

    assert_eq!(fuzz_exit, 0);
    let finding_dir = only_finding_dir(&work_dir);
    assert_eq!(
        fs::read(finding_dir.join("testcase.bin")).expect("testcase is readable"),
        b"match"
    );
}

#[test]
fn fuzz_builtin_summary_records_cmplog_sanitizer_and_execution_metadata() {
    let temp = temp_dir("summary-metadata");
    let work_dir = temp.join("govfuzz_work");
    let harness_id = "H-TEST";
    let _harness = install_fake_harness(&work_dir, harness_id);
    let cmplog_path = temp.join("cmplog.jsonl");
    fs::write(
        &cmplog_path,
        b"{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"6372617368\",\"b\":\"4d41474943\"}\n",
    )
    .expect("cmplog fixture is written");

    let fuzz_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--seed-input"),
        OsString::from("crash"),
        OsString::from("--cmplog-log"),
        cmplog_path.into_os_string(),
        OsString::from("--sanitizers"),
        OsString::from("asan"),
    ]);

    assert_eq!(fuzz_exit, 0);
    let run_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-TEST-latest.json")).unwrap())
            .unwrap();
    assert_eq!(
        run_summary["execution"]["harness_protocol"],
        "stdin_event_log"
    );
    assert_eq!(run_summary["execution"]["forkserver"], false);
    assert_eq!(run_summary["execution"]["persistent"], false);
    assert_eq!(run_summary["cmplog"]["enabled"], true);
    assert_eq!(run_summary["cmplog"]["entries"], 1);
    assert_eq!(run_summary["cmplog"]["dictionary_tokens"], 2);
    assert_eq!(run_summary["cmplog"]["seed_splice_candidates"], 1);
    assert_eq!(run_summary["sanitizers"]["requested"][0], "asan");
    assert_eq!(
        run_summary["sanitizers"]["active_env"][0]["key"],
        "ASAN_OPTIONS"
    );
    // #405: fuzz_runs/<hid>-*.json carries measured wall + throughput, and the
    // throughput is internally consistent with executions / elapsed_secs.
    let elapsed = run_summary["elapsed_secs"]
        .as_f64()
        .expect("elapsed_secs present");
    let eps = run_summary["executions_per_sec"]
        .as_f64()
        .expect("executions_per_sec present");
    assert!(elapsed >= 0.0, "elapsed_secs {elapsed}");
    assert!(eps >= 0.0, "executions_per_sec {eps}");
    if elapsed > 0.0 {
        let execs = run_summary["executions"].as_f64().unwrap();
        assert!(
            (eps - execs / elapsed).abs() < 1.0,
            "exec/s {eps} should equal executions {execs} / elapsed {elapsed}"
        );
    }
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_cli_writes_campaign_summary() {
    use std::os::unix::fs::PermissionsExt;

    let temp = temp_dir("multicore-cli");
    let work_dir = temp.join("govfuzz_work");
    fs::create_dir_all(work_dir.join("build/H-MULTI")).expect("build directory is created");
    fs::create_dir_all(work_dir.join("corpus/H-MULTI/queue")).expect("queue is created");
    fs::write(work_dir.join("corpus/H-MULTI/queue/base.bin"), b"base").unwrap();
    let script = temp.join("fake-govfuzz.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
worker_dir="$2"
harness=""
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) harness="$2"; shift 2 ;;
    *) shift ;;
  esac
done
test -f "$GOVFUZZ_SHARED_CORPUS_DIR/base.bin"
mkdir -p "$worker_dir/corpus/$harness/queue"
printf "cli-worker-%s" "$GOVFUZZ_WORKER_ID" > "$worker_dir/corpus/$harness/queue/cli-worker-$GOVFUZZ_WORKER_ID.bin"
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let fuzz_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from("H-MULTI"),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--workers"),
        OsString::from("2"),
        OsString::from("--sanitizers"),
        OsString::from("asan,ubsan"),
        OsString::from("--govfuzz-bin"),
        script.into_os_string(),
    ]);

    assert_eq!(fuzz_exit, 0);
    let campaign_summary_path = work_dir.join("fuzz_campaigns/H-MULTI-latest.json");
    assert!(campaign_summary_path.is_file());
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(campaign_summary_path).unwrap()).unwrap();
    assert_eq!(summary["workers_started"], 2);
    assert_eq!(summary["workers_completed"], 2);
    assert_eq!(summary["sync"]["seed_inputs_loaded"], 1);
    assert_eq!(summary["sync"]["imported_inputs"], 2);
    assert_eq!(summary["per_worker"][0]["env_keys"][0], "ASAN_OPTIONS");
    assert_eq!(summary["per_worker"][1]["env_keys"][0], "UBSAN_OPTIONS");
}

fn install_fake_harness(work_dir: &Path, harness_id: &str) -> PathBuf {
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let target = work_dir
        .join("build")
        .join(harness_id)
        .join("obj")
        .join("main");
    fs::create_dir_all(target.parent().expect("target has parent"))
        .expect("harness build directory is created");
    fs::copy(&harness, &target).expect("fake harness is copied");
    make_executable(&target);
    target
}

fn only_finding_dir(work_dir: &Path) -> PathBuf {
    let findings_root = work_dir.join("findings");
    let findings = fs::read_dir(&findings_root)
        .expect("findings directory is readable")
        .map(|entry| entry.expect("finding entry is readable").path())
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    findings.into_iter().next().expect("one finding exists")
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-fuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .expect("metadata is readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("permissions are updated");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
