// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for build-recovery provenance (stub_artifact vs
//! real_defect). Both fixtures crash on a stub-stitched build (each references an
//! undefined external govfuzz stubs), but only one crash CAUSALLY needs the
//! fabricated stub value:
//!   - `stub_dep.c`  — dereferences a NULL fabricated by `acquire_scratch()` ⇒
//!     the crash is a stub artifact ⇒ demoted to `lab_only`, naming the stub.
//!   - `real_def.c`  — a stack overflow that fires BEFORE the (value) stub is ever
//!     called ⇒ the crash is independent of the scaffolding ⇒ `real_defect`,
//!     confidence raised to `high`.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn govfuzz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_govfuzz"))
}

/// Crash is an ARTIFACT of the NULL the stub fabricates.
const STUB_ARTIFACT_C: &str = "\
#include <string.h>
extern char *acquire_scratch(void);
extern void audit_log(const char *);
int process(const char *data, unsigned int len) {
    audit_log(\"start\");
    char *dst = acquire_scratch();
    memcpy(dst, data, len);
    return dst[0];
}
";

/// Crash is a REAL overflow that fires before the value stub is reached.
const REAL_DEFECT_C: &str = "\
#include <string.h>
extern int compute_checksum(const char *, unsigned int);
int parse_record(const char *data, unsigned int len) {
    char buf[8];
    memcpy(buf, data, len);
    int c = compute_checksum(data, len);
    return buf[0] ^ c;
}
";

fn run_snippet(src: &str, work: &Path) -> String {
    let tmp = work.with_extension("src.c");
    std::fs::write(&tmp, src).unwrap();
    let out = govfuzz()
        .arg("snippet")
        .arg(&tmp)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(work)
        .output()
        .expect("run govfuzz snippet");
    let _ = std::fs::remove_file(&tmp);
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Read every finding's `provenance` label for a work dir.
fn provenances(work: &Path) -> Vec<String> {
    let dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        if let Ok(bytes) = std::fs::read(e.path().join("finding.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(p) = v.get("provenance").and_then(|p| p.as_str()) {
                    let verdict = v
                        .pointer("/actionability/verdict")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_owned();
                    out.push(format!("{p}:{verdict}"));
                }
            }
        }
    }
    out
}

#[test]
fn stub_fabricated_crash_is_demoted_to_lab_only() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-prov-artifact-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let stderr = run_snippet(STUB_ARTIFACT_C, &work);
    let provs = provenances(&work);
    assert!(
        !provs.is_empty(),
        "expected a crash + provenance label; stderr:\n{stderr}"
    );
    assert!(
        provs.iter().all(|p| p == "stub_artifact:lab_only"),
        "every NULL-stub crash must be a stub_artifact demoted to lab_only, got {provs:?}\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn stub_independent_crash_is_certified_real_defect() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-prov-real-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let stderr = run_snippet(REAL_DEFECT_C, &work);
    let provs = provenances(&work);
    assert!(
        !provs.is_empty(),
        "expected the overflow crash + provenance label; stderr:\n{stderr}"
    );
    assert!(
        provs.iter().any(|p| p == "real_defect:likely_reachable"),
        "the stub-independent overflow must be certified real_defect, got {provs:?}\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&work);
}
