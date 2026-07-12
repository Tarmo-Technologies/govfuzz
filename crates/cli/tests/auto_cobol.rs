// SPDX-License-Identifier: Apache-2.0
//! End-to-end: `govfuzz auto` fuzzes a COBOL program and catches a runtime bug.
//!
//! The fixture is a subprogram with a `LINKAGE` `PIC X(8)` buffer whose
//! reference-modification offset goes out of bounds when the input starts with
//! `Z` — a libcob `EC-BOUND-REF-MOD` failure the harness surfaces as a crash. The
//! trigger byte is seeded so the run is fast + deterministic. Gated on
//! cobc + clang + make; skipped otherwise.

use std::path::Path;
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tempdir(name: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cobol-e2e-{name}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_findings(work: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work.join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Ok(bytes) = std::fs::read(entry.path().join("finding.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                out.push(v);
            }
        }
    }
    out
}

#[test]
fn auto_cobol_discovers_and_crashes_on_ref_mod_oob() {
    if !have("cobc") || !have("clang") || !have("make") {
        eprintln!("skip: needs cobc (GnuCOBOL) + clang + make");
        return;
    }
    let src = tempdir("src");
    std::fs::write(
        src.join("parseit.cob"),
        "       IDENTIFICATION DIVISION.\n\
         \x20      PROGRAM-ID. PARSEIT.\n\
         \x20      DATA DIVISION.\n\
         \x20      WORKING-STORAGE SECTION.\n\
         \x20      01 IDX PIC 9(4).\n\
         \x20      LINKAGE SECTION.\n\
         \x20      01 BUF PIC X(8).\n\
         \x20      PROCEDURE DIVISION USING BUF.\n\
         \x20          IF BUF(1:1) = \"Z\"\n\
         \x20              MOVE 200 TO IDX\n\
         \x20              DISPLAY BUF(IDX:1)\n\
         \x20          END-IF\n\
         \x20          GOBACK.\n",
    )
    .unwrap();

    let seed = tempdir("seed");
    std::fs::write(seed.join("z.bin"), b"Z").unwrap();

    let work = tempdir("work");
    let out = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args(["auto", src.to_str().unwrap()])
        .args(["--languages", "cobol"])
        .args(["--per-target-time", "10"])
        .arg("--no-discovery-cache")
        .arg("--seed-dir")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("spawn govfuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The COBOL program was discovered and built+fuzzed via the C harness path.
    assert!(
        stdout.contains("PARSEIT") || stderr.contains("PARSEIT"),
        "expected COBOL PROGRAM-ID PARSEIT to be discovered.\n{stdout}\n{stderr}"
    );
    // The out-of-bounds reference-modification is caught as a crash finding.
    let findings = read_findings(&work);
    assert!(
        findings.iter().any(|f| f["rule_id"] == "GF-210"),
        "expected a GF-210 reachable-crash finding from the ref-mod OOB.\n{stdout}\n{stderr}"
    );
}
