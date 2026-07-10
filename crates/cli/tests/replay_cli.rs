// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CANONICAL_SIGNATURE: &str =
    "20b41fb2a2ceeabc9f0403546af14199d4ccacc54e55f6fcb5855015b5eb63bd";

#[test]
fn replay_subcommand_match_returns_zero() {
    let finding_dir = write_finding("match");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_accepts_finding_flag() {
    let finding_dir = write_finding("match");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            "--finding",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_resolves_bare_finding_id_under_findings_root() {
    let root = temp_dir("bare-id");
    let finding_id = "F-0000-test";
    write_finding_at(&root.join("findings").join(finding_id), "match");

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .current_dir(&root)
        .args([
            "replay",
            "--finding",
            finding_id,
            "--harness",
            fake_harness().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn replay_subcommand_qemu_user_wraps_harness() {
    let root = temp_dir("qemu-user");
    let qemu_path = root.join("fake-qemu-aarch64");
    let qemu_log = root.join("qemu-argv.txt");
    write_fake_qemu_user(&qemu_path);
    let finding_dir = write_finding("match");

    let exit = cli::run_from([
        "govfuzz",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--qemu-user",
        qemu_path.to_str().unwrap(),
        "--qemu-arg=-L",
        "--qemu-arg=/opt/aarch64-sysroot",
    ]);

    assert_eq!(exit, 0);
    assert_eq!(
        fs::read_to_string(qemu_log).unwrap(),
        format!("-L\n/opt/aarch64-sysroot\n{}\n", fake_harness().display())
    );
}

#[cfg(unix)]
#[test]
fn replay_subcommand_firejail_sandbox_wraps_harness() {
    let root = temp_dir("firejail-sandbox");
    let sandbox_path = root.join("fake-firejail");
    let sandbox_log = root.join("sandbox-argv.txt");
    write_fake_sandbox(&sandbox_path);
    let finding_dir = write_finding("match");

    let exit = cli::run_from([
        "govfuzz",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--sandbox",
        "firejail",
        "--sandbox-tool",
        sandbox_path.to_str().unwrap(),
    ]);

    assert_eq!(exit, 0);
    let sandbox_argv = fs::read_to_string(sandbox_log).unwrap();
    assert!(sandbox_argv.contains("--net=none\n"));
    assert!(sandbox_argv.contains("--\n"));
    assert!(sandbox_argv.contains(&format!("{}\n", fake_harness().display())));
}

#[test]
fn replay_subcommand_strict_missing_sandbox_returns_one() {
    let root = temp_dir("strict-missing-sandbox");
    let finding_dir = write_finding("match");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--sandbox",
            "firejail",
            "--sandbox-tool",
            root.join("missing-firejail").to_str().unwrap(),
            "--sandbox-strict",
        ]),
        1
    );
}

#[test]
fn replay_subcommand_mismatch_returns_three() {
    let finding_dir = write_finding("mismatch");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        3
    );
}

#[test]
fn replay_subcommand_auto_resolves_harness_from_fixture_path() {
    // No --harness: the finding records `fixture_path`, so replay resolves the
    // built harness itself and still reproduces (MATCH -> exit 0).
    let finding_dir = write_finding_with_fixture("match", fake_harness());

    assert_eq!(
        cli::run_from(["govfuzz", "replay", finding_dir.to_str().unwrap(),]),
        0
    );
}

#[test]
fn replay_subcommand_auto_resolves_harness_from_harness_id_layout() {
    // No --harness, no fixture_path: resolve `<work>/harnesses/<harness_id>/main`
    // relative to the finding dir (`<work>/findings/<F-...>/`).
    let root = temp_dir("auto-harness-id");
    let work = root.join("work");
    let finding_dir = work.join("findings/F-0000-auto");
    let harness_id = "H-AUTO-1234";
    let auto_dir = work.join("harnesses").join(harness_id);
    fs::create_dir_all(&auto_dir).unwrap();
    copy_executable(fake_harness(), &auto_dir.join("main"));
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), b"match").unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!("{{\"signature\":\"{CANONICAL_SIGNATURE}\",\"harness_id\":\"{harness_id}\"}}"),
    )
    .unwrap();

    assert_eq!(
        cli::run_from(["govfuzz", "replay", finding_dir.to_str().unwrap()]),
        0
    );
}

#[test]
fn replay_subcommand_explicit_harness_overrides_auto_resolution() {
    // An explicit --harness wins even when the finding records a (here bogus)
    // fixture_path that does not exist.
    let finding_dir =
        write_finding_with_fixture("match", Path::new("/nonexistent/govfuzz/harness"));

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_unresolvable_harness_returns_one() {
    // No --harness and nothing resolvable: clear error, exit 1.
    let finding_dir = write_finding("match");

    assert_eq!(
        cli::run_from(["govfuzz", "replay", finding_dir.to_str().unwrap()]),
        1
    );
}

#[test]
fn replay_subcommand_missing_finding_returns_one() {
    let missing = temp_dir("missing").join("findings/F-0000-missing");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "replay",
            missing.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        1
    );
}

#[test]
fn minimize_subcommand_writes_min_testcase_and_updates_finding_record() {
    let input = format!("{}crash{}", "A".repeat(32), "B".repeat(32));
    let finding_dir = write_finding(&input);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "minimize",
            "--finding",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["paths"]["minimized"], "min_testcase.bin");
    assert_eq!(finding["minimal_reproducer"], "min_testcase.bin");
    assert_eq!(finding["minimization"]["strategy"], "bytes");
    assert_eq!(finding["minimization"]["reduced"], true);
    assert_eq!(
        finding["minimization"]["original_len"].as_u64(),
        Some(input.len() as u64)
    );
    assert_eq!(finding["minimization"]["minimized_len"].as_u64(), Some(5));
    assert!(5 * 10 < input.len());
}

#[cfg(unix)]
#[test]
fn minimize_subcommand_qemu_user_wraps_harness() {
    let root = temp_dir("qemu-user-minimize");
    let qemu_path = root.join("fake-qemu-aarch64");
    let qemu_log = root.join("qemu-argv.txt");
    write_fake_qemu_user(&qemu_path);
    let finding_dir = write_finding("AAAAcrashBBBB");

    let exit = cli::run_from([
        "govfuzz",
        "minimize",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--qemu-user",
        qemu_path.to_str().unwrap(),
        "--qemu-arg=--sysroot",
        "--qemu-arg=/opt/aarch64-sysroot",
    ]);

    assert_eq!(exit, 0);
    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    assert!(fs::read_to_string(qemu_log)
        .unwrap()
        .contains(&fake_harness().display().to_string()));
}

#[test]
fn minimize_subcommand_typed_strategy_uses_decoded_spans() {
    let finding_dir = write_finding("AAAAcrashBBBB");
    write_decoded_spans(
        &finding_dir,
        &[
            serde_json::json!({ "start": 0, "end": 4, "kind": "string" }),
            serde_json::json!({ "start": 9, "end": 13, "kind": "bytes" }),
        ],
    );

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--strategy",
            "typed",
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["minimization"]["strategy"], "typed");
    assert_eq!(
        finding["minimization"]["attempted_replacements"].as_u64(),
        Some(2)
    );
    assert_eq!(
        finding["minimization"]["accepted_replacements"].as_u64(),
        Some(2)
    );
}

#[test]
fn minimize_subcommand_typed_strategy_without_spans_records_no_reduction() {
    let finding_dir = write_finding("AAAAcrashBBBB");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--strategy",
            "typed",
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"AAAAcrashBBBB"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["minimization"]["strategy"], "typed");
    assert_eq!(finding["minimization"]["reduced"], false);
    assert_eq!(
        finding["minimization"]["attempted_replacements"].as_u64(),
        Some(0)
    );
    assert_eq!(
        finding["minimization"]["accepted_replacements"].as_u64(),
        Some(0)
    );
}

#[test]
fn minimize_subcommand_rejects_non_reproducing_original() {
    let finding_dir = write_finding("does-not-reproduce");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        1
    );
    assert!(!finding_dir.join("min_testcase.bin").exists());
}

fn write_finding(input: &str) -> PathBuf {
    let finding_dir = temp_dir(input).join("findings/F-0000-test");
    write_finding_at(&finding_dir, input);
    finding_dir
}

fn write_finding_at(finding_dir: &Path, input: &str) {
    fs::create_dir_all(finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!("{{\"signature\":\"{CANONICAL_SIGNATURE}\"}}"),
    )
    .unwrap();
}

fn write_finding_with_fixture(input: &str, fixture: &Path) -> PathBuf {
    let finding_dir = temp_dir(&format!("{input}-fixture")).join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!(
            "{{\"signature\":\"{CANONICAL_SIGNATURE}\",\"fixture_path\":\"{}\"}}",
            fixture.display()
        ),
    )
    .unwrap();
    finding_dir
}

fn copy_executable(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(to).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(to, permissions).unwrap();
    }
}

fn write_decoded_spans(finding_dir: &Path, spans: &[serde_json::Value]) {
    fs::write(
        finding_dir.join("decoded.json"),
        serde_json::to_vec(&serde_json::json!({ "typed_spans": spans })).unwrap(),
    )
    .unwrap();
}

fn read_finding_json(finding_dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap()
}

fn fake_harness() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cli_fake_harness"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-replay-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn write_fake_qemu_user(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        path,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$(dirname "$0")/qemu-argv.txt"
last=''
for arg in "$@"; do
  last="$arg"
done
exec "$last"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn write_fake_sandbox(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        path,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$(dirname "$0")/sandbox-argv.txt"
found_separator=0
shifted=''
for arg in "$@"; do
  if [ "$found_separator" = 1 ]; then
    shifted="${shifted}${arg}
"
  elif [ "$arg" = "--" ]; then
    found_separator=1
  fi
done
if [ "$found_separator" != 1 ]; then
  exit 125
fi
set -- $shifted
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}
