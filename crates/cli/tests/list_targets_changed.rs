// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that `govfuzz list-targets --changed-since`
//! filters by git diff.

use std::fs;
use std::path::PathBuf;
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
    let dir = std::env::temp_dir().join(format!("govfuzz-list-changed-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git command spawn")
}

fn assert_git_success(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn changed_since_keeps_only_modified_files() {
    let repo = tempdir("filter");
    assert_git_success(&git(&["init", "-q"], &repo), "git init");
    assert_git_success(
        &git(&["config", "user.email", "test@example.com"], &repo),
        "git config email",
    );
    assert_git_success(
        &git(&["config", "user.name", "Test"], &repo),
        "git config name",
    );
    assert_git_success(
        &git(&["config", "commit.gpgsign", "false"], &repo),
        "git config gpgsign",
    );

    let a_ada = r#"
procedure Untouched (Input : String) is
begin
   if Input = "x" then
      raise Constraint_Error;
   end if;
end Untouched;
"#;
    let b_ada = r#"
procedure Modified (Input : String) is
begin
   if Input = "y" then
      raise Constraint_Error;
   end if;
end Modified;
"#;

    fs::write(repo.join("untouched.adb"), a_ada).unwrap();
    fs::write(repo.join("modified.adb"), b_ada).unwrap();
    assert_git_success(&git(&["add", "."], &repo), "git add 1");
    assert_git_success(
        &git(&["commit", "-q", "-m", "initial"], &repo),
        "git commit 1",
    );

    fs::write(repo.join("modified.adb"), format!("{b_ada}\n-- touched\n")).unwrap();
    assert_git_success(&git(&["add", "."], &repo), "git add 2");
    assert_git_success(
        &git(&["commit", "-q", "-m", "modify"], &repo),
        "git commit 2",
    );

    let out = Command::new(govfuzz_bin())
        .args([
            "list-targets",
            repo.to_str().unwrap(),
            "--format",
            "json",
            "--changed-since",
            "HEAD~1",
        ])
        .current_dir(&repo)
        .output()
        .expect("spawn govfuzz list-targets");
    assert!(
        out.status.success(),
        "list-targets exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json output");
    let arr = value.as_array().expect("array");
    for row in arr {
        let file = row["file"].as_str().unwrap();
        assert!(
            file.ends_with("modified.adb"),
            "untouched file leaked through filter: {file}"
        );
    }
    assert!(
        !arr.is_empty(),
        "expected at least one target from modified.adb"
    );
}

#[test]
fn changed_since_empty_diff_yields_no_targets() {
    let repo = tempdir("empty");
    assert_git_success(&git(&["init", "-q"], &repo), "git init");
    assert_git_success(
        &git(&["config", "user.email", "test@example.com"], &repo),
        "git config email",
    );
    assert_git_success(&git(&["config", "user.name", "Test"], &repo), "git config");
    assert_git_success(
        &git(&["config", "commit.gpgsign", "false"], &repo),
        "git config gpgsign",
    );

    fs::write(
        repo.join("only.adb"),
        "procedure Only is\nbegin\n   null;\nend Only;\n",
    )
    .unwrap();
    assert_git_success(&git(&["add", "."], &repo), "git add");
    assert_git_success(
        &git(&["commit", "-q", "-m", "initial"], &repo),
        "git commit",
    );

    let out = Command::new(govfuzz_bin())
        .args([
            "list-targets",
            repo.to_str().unwrap(),
            "--format",
            "json",
            "--changed-since",
            "HEAD",
        ])
        .current_dir(&repo)
        .output()
        .expect("spawn govfuzz list-targets");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 0);
}
