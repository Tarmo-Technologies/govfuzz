// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `govfuzz cartography`: after fuzzing an OOB read whose
//! offset a single input byte controls, the perturbation analysis must identify
//! that byte as controlling the offset and classify the exploit primitive as a
//! controlled relative read (CWE-125) — deterministically and offline.

use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

/// byte 0 controls an OOB read offset that lands in the 16-byte heap redzone, so
/// ANY input reliably crashes and byte 0 is the offset control.
const BYTE_CONTROLLED_OOB_C: &str = "\
#include <string.h>
#include <stdlib.h>
int idx_read(const char *data, unsigned int len) {
    if (len < 2) return 0;
    char *buf = malloc(16);
    memset(buf, 0, 16);
    unsigned idx = 16 + ((unsigned char)data[0] % 8);
    char r = buf[idx];
    free(buf);
    return r;
}
";

#[test]
fn cartography_maps_byte_to_controlled_read_offset() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-cart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let src = work.with_extension("src.c");
    std::fs::write(&src, BYTE_CONTROLLED_OOB_C).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("6")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run snippet");
    let _ = std::fs::remove_file(&src);
    assert!(
        find_finding(&work).is_some(),
        "snippet produced no crash: {}",
        String::from_utf8_lossy(&snip.stderr)
    );

    let carto = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("cartography")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run cartography");
    let stdout = String::from_utf8_lossy(&carto.stdout);
    assert!(
        stdout.contains("controls offset/index") || stdout.contains("controlled_relative_read"),
        "cartography should map an offset-controlling byte; got:\n{stdout}"
    );

    // The machine-readable card must carry the primitive + the controlling byte.
    let fdir = find_finding(&work).unwrap();
    let card: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("byte-control.json")).unwrap()).unwrap();
    assert_eq!(card["primitive"]["kind"], "controlled_relative_read");
    assert_eq!(card["primitive"]["cwe"], "CWE-125");
    let ctrl = card["primitive"]["controlling_bytes"].as_array().unwrap();
    assert!(
        ctrl.iter().any(|b| b.as_u64() == Some(0)),
        "byte 0 must be flagged as controlling the offset; card: {card}"
    );

    // The finding itself is enriched with the primitive.
    let finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding["primitive"]["kind"], "controlled_relative_read");
    let _ = std::fs::remove_dir_all(&work);
}

fn find_finding(work: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(work.join("findings"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("F-0000"))
                && p.join("testcase.bin").is_file()
        })
}
