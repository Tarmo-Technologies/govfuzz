// SPDX-License-Identifier: Apache-2.0
//! End-to-end: `govfuzz ci --changed-since` scopes a run to a PR's diff.
//!
//! Two cases, both driving a real `git` repo:
//!   1. A diff that touches only non-source files short-circuits to
//!      "nothing to do" and passes (exit 0) — needs only `git`.
//!   2. A diff that changes one C file scopes the sweep to exactly that file
//!      (`scoped_files == 1`) — gated on a C toolchain, skipped otherwise.

use std::path::Path;
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        // Deterministic identity + no signing/hooks so CI-less boxes work.
        .args([
            "-c",
            "user.email=test@govfuzz.local",
            "-c",
            "user.name=govfuzz-test",
        ])
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn tempdir(name: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-ci-e2e-{name}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

#[test]
fn ci_changed_since_nothing_to_do_when_only_docs_change() {
    if !have("git") {
        eprintln!("skip: git not installed");
        return;
    }
    let repo = tempdir("nothing");
    git(&repo, &["init", "-q"]);
    write(&repo.join("src/a.c"), "int a(void){return 0;}\n");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    let base = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();

    // A commit that touches only a doc file — nothing fuzzable changed.
    write(&repo.join("docs/readme.md"), "# hi\n");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "docs only"]);

    let work = tempdir("nothing-work");
    let ci_json = work.join("ci.json");
    let out = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .current_dir(&repo)
        .args(["ci", "."])
        .args(["--changed-since", &base])
        .arg("--work-dir")
        .arg(&work)
        .arg("--ci-json")
        .arg(&ci_json)
        .output()
        .expect("spawn govfuzz");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\n{stdout}",
        out.status
    );
    assert!(
        stdout.contains("no changed fuzzable files in scope"),
        "expected the nothing-to-do message, got:\n{stdout}"
    );
    let ci: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ci_json).expect("ci.json written")).unwrap();
    assert_eq!(ci["nothing_to_do"], true);
    assert_eq!(ci["scoped_files"], 0);
    assert_eq!(ci["exit_code"], 0);
}

#[test]
fn ci_changed_since_scopes_to_the_changed_c_file() {
    if !have("git") || !have("clang") {
        eprintln!("skip: needs git + clang");
        return;
    }
    let repo = tempdir("scoped");
    git(&repo, &["init", "-q"]);
    // Two fuzzable C files at the base.
    write(
        &repo.join("src/a.c"),
        "#include <stddef.h>\nint a_parse(const unsigned char*d,size_t n){return n&&d[0]=='A';}\n",
    );
    write(
        &repo.join("src/b.c"),
        "#include <stddef.h>\nint b_parse(const unsigned char*d,size_t n){return n&&d[0]=='B';}\n",
    );
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    let base = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();

    // Change only b.c.
    write(
        &repo.join("src/b.c"),
        "#include <stddef.h>\nint b_parse(const unsigned char*d,size_t n){return n>1&&d[0]=='B'&&d[1]=='!';}\n",
    );
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "touch b"]);

    let work = tempdir("scoped-work");
    let ci_json = work.join("ci.json");
    let out = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .current_dir(&repo)
        .args(["ci", "."])
        .args(["--changed-since", &base])
        .args(["--languages", "c"])
        .args(["--campaign-time", "2"])
        .args(["--per-target-time", "2"])
        .arg("--work-dir")
        .arg(&work)
        .arg("--ci-json")
        .arg(&ci_json)
        .output()
        .expect("spawn govfuzz");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("no changed fuzzable files in scope"),
        "a changed C file must NOT short-circuit; got:\n{stdout}"
    );
    let ci: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ci_json).expect("ci.json written")).unwrap();
    // Exactly one changed fuzzable source file (b.c) was in scope.
    assert_eq!(ci["scoped_files"], 1, "scoped to the single changed file");
    assert_ne!(ci["nothing_to_do"], true);
}
