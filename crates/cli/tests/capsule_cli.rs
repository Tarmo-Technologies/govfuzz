// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `govfuzz capsule` + `govfuzz verify-poc`: a crash found
//! on a stub-stitched (un-buildable) tree is packaged into a portable capsule that
//! rebuilds and reproduces OFFLINE with only clang + a shell — no govfuzz, no
//! original work dir. Exercises both a self-contained crash and a stub-dependent
//! one (the recovered stubs must ship in the capsule).

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn govfuzz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_govfuzz"))
}

/// Self-contained stack overflow.
const OVERFLOW_C: &str = "\
#include <string.h>
int parse_header(const char *data, unsigned int len) {
    char buf[16];
    memcpy(buf, data, len);
    return buf[0];
}
";

/// NULL deref via a stubbed (undefined) external — the capsule must ship the stub.
const STUB_DEP_C: &str = "\
#include <string.h>
extern char *acquire_scratch(void);
int process(const char *data, unsigned int len) {
    char *dst = acquire_scratch();
    memcpy(dst, data, len);
    return dst[0];
}
";

fn snippet_into(src: &str, work: &Path) {
    let tmp = work.with_extension("src.c");
    std::fs::write(&tmp, src).unwrap();
    let out = govfuzz()
        .arg("snippet")
        .arg(&tmp)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("6")
        .arg("--work-dir")
        .arg(work)
        .output()
        .expect("run govfuzz snippet");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        work.join("findings").is_dir(),
        "snippet produced no findings: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn build_capsule(work: &Path, tar: bool) -> String {
    let mut cmd = govfuzz();
    cmd.arg("capsule")
        .arg("--work-dir")
        .arg(work)
        .arg("--verbose");
    if tar {
        cmd.arg("--tar");
    }
    let out = cmd.output().expect("run govfuzz capsule");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Verify a capsule from a PRISTINE location — no govfuzz work dir nearby.
fn verify_from_scratch(capsule_src: &Path, tag: &str) -> (bool, String) {
    let scratch = std::env::temp_dir().join(format!("gf-cap-scratch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let dest = scratch.join(capsule_src.file_name().unwrap());
    // Copy the capsule tree into the scratch area (cp -r).
    let ok = Command::new("cp")
        .arg("-r")
        .arg(capsule_src)
        .arg(&dest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "failed to stage capsule copy");
    let out = govfuzz()
        .arg("verify-poc")
        .arg(&dest)
        .output()
        .expect("run govfuzz verify-poc");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let pass = out.status.success() && stdout.contains("PASS");
    let _ = std::fs::remove_dir_all(&scratch);
    (pass, stdout)
}

fn only_capsule(work: &Path) -> std::path::PathBuf {
    let caps = work.join("capsules");
    std::fs::read_dir(&caps)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("capsule_")
        })
        .expect("a capsule dir")
}

#[test]
fn self_contained_crash_capsule_reproduces_offline() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-cap-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    snippet_into(OVERFLOW_C, &work);
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    // The capsule ships a build.sh + input + harness + manifest.
    for f in [
        "build.sh",
        "manifest.json",
        "input/testcase.bin",
        "harness/main.c",
    ] {
        assert!(cap.join(f).is_file(), "capsule missing {f}");
    }
    let (pass, out) = verify_from_scratch(&cap, "plain");
    assert!(pass, "verify-poc should PASS offline; got:\n{out}");
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn stub_dependent_crash_capsule_ships_stubs_and_reproduces() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-cap-stub-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    snippet_into(STUB_DEP_C, &work);
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    // The recovered stub for the undefined external must be packaged, and the
    // provenance-poisoned copy must NOT be.
    assert!(
        cap.join("stubs/auto_stubs.c").is_file(),
        "capsule must ship the stub"
    );
    assert!(
        !cap.join("stubs/auto_stubs_prov.c").exists(),
        "the provenance-poisoned stub is internal and must not ship"
    );
    let (pass, out) = verify_from_scratch(&cap, "stub");
    assert!(
        pass,
        "stub-dependent capsule should reproduce offline; got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&work);
}
