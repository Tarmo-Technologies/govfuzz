// SPDX-License-Identifier: Apache-2.0

//! The fork-server execution mode (`GOVFUZZ_FORK_SERVER=1`) must find the same
//! faults as the per-spawn path, with correct per-input attribution. This is
//! the regression guard for the persistent-process protocol (framed stdin +
//! sync byte + event-log delta). Gnat-gated; skips cleanly without a compiler.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The exception name + remapped source line of every finding under `work_dir`.
fn finding_signatures(work_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let findings = work_dir.join("findings");
    let Ok(entries) = fs::read_dir(&findings) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Ok(bytes) = fs::read(&path) else { continue };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let name = value["exception"]["name"].as_str().unwrap_or("").to_owned();
        let line = value["exception"]["source_line"].to_string();
        out.push((name, line));
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn fork_server_finds_the_same_fault_as_per_spawn() {
    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping: no Ada compiler on PATH");
        return;
    }

    let root = temp_dir("forkserver");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("bug.ads"),
        "package Bug is\n   procedure Hit (N : Natural; R : out Integer);\nend Bug;\n",
    )
    .unwrap();
    // An index check that fails for ~half the decoded inputs -> a finding the
    // builtin engine surfaces quickly in either mode.
    fs::write(
        src.join("bug.adb"),
        "package body Bug is\n\
         \x20  procedure Hit (N : Natural; R : out Integer) is\n\
         \x20     Tab : array (0 .. 9) of Integer := (others => 0);\n\
         \x20  begin\n\
         \x20     R := Tab (N mod 20);\n\
         \x20  end Hit;\n\
         end Bug;\n",
    )
    .unwrap();

    let work = root.join("govfuzz_work");
    // `auto` builds (and fuzzes once) the harness.
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "auto",
            "--per-target-time",
            "1",
            "--target",
            "hit",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ]),
        0
    );
    let harness_id = fs::read_dir(work.join("build"))
        .unwrap()
        .flatten()
        .find_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with("H-").then_some(name)
        })
        .expect("a harness was built");

    let fuzz = |mode_flag: &str| -> Vec<(String, String)> {
        let _ = fs::remove_dir_all(work.join("findings"));
        let _ = fs::remove_dir_all(work.join("corpus"));
        let mut argv = vec![
            "govfuzz",
            "fuzz",
            "--harness",
            &harness_id,
            work.to_str().unwrap(),
            "--engine",
            "builtin",
            "--iterations",
            "400",
        ];
        if !mode_flag.is_empty() {
            argv.push(mode_flag);
        }
        assert_eq!(cli::run_from(argv), 0);
        finding_signatures(&work)
    };

    // `--no-fork-server` is the fresh-process path; the bare run is the
    // fork-server default. Both must find the same replay-valid fault(s).
    let per_spawn = fuzz("--no-fork-server");
    let fork_server_default = fuzz("");
    let fork_server_forced = fuzz("--fork-server");

    assert!(
        !per_spawn.is_empty(),
        "per-spawn must find the planted fault"
    );
    assert_eq!(
        per_spawn, fork_server_default,
        "fork-server (the default) must find the same fault(s) as per-spawn"
    );
    assert_eq!(
        per_spawn, fork_server_forced,
        "an explicit --fork-server must match per-spawn too"
    );
}
