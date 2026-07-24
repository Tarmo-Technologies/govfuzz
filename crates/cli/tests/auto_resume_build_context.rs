// SPDX-License-Identifier: Apache-2.0

//! #101: `--resume` reuses completed-target results only when BOTH the source
//! identity (discovery cache) AND the build context (compile databases, GPRs,
//! IDLs, harness-affecting options) are unchanged. A build-context change
//! re-attempts affected targets even when the source is unchanged; a docs change
//! does not.

use std::path::Path;
use std::process::{Command, Output};

fn run_auto(root: &Path, work: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    command
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass");
    command.args(extra);
    command.output().expect("spawn govfuzz auto")
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-resume-bctx-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have_c_compiler() -> bool {
    which::which("clang").is_ok() || which::which("cc").is_ok()
}

#[test]
fn resume_reuses_on_unchanged_context_but_reattempts_on_build_context_change() {
    if !have_c_compiler() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let root = tmpdir("src");
    std::fs::write(
        root.join("lib.c"),
        "#include <stddef.h>\n#include <stdint.h>\nint decode(const uint8_t*d,size_t n){return n&&d[0]=='Z';}\n",
    )
    .unwrap();
    let work = tmpdir("work");

    // First run establishes the checkpoint + writes the build-context fingerprint.
    let first = run_auto(&root, &work, &[]);
    assert!(
        work.join("auto/build-context.fingerprint").is_file(),
        "first run must record the build-context fingerprint; stderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // A docs-only change must NOT invalidate: --resume reloads the completed target.
    std::fs::write(root.join("NOTES.md"), "docs only\n").unwrap();
    let resumed = run_auto(&root, &work, &["--resume"]);
    let resumed_err = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        resumed_err.contains("reloaded") || resumed_err.contains("no completed targets"),
        "a docs-only change must allow resume, not re-attempt on a build-context change; stderr:\n{resumed_err}"
    );
    assert!(
        !resumed_err.contains("build context changed"),
        "docs change must not report a build-context change; stderr:\n{resumed_err}"
    );

    // Adding a compile database changes the build context (source is unchanged), so
    // --resume must re-attempt rather than trust the prior results.
    std::fs::write(root.join("compile_commands.json"), "[]\n").unwrap();
    let changed = run_auto(&root, &work, &["--resume"]);
    let changed_err = String::from_utf8_lossy(&changed.stderr);
    assert!(
        changed_err.contains("build context changed"),
        "adding compile_commands.json must invalidate the build context; stderr:\n{changed_err}"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
