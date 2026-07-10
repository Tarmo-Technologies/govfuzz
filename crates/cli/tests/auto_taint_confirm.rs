// SPDX-License-Identifier: Apache-2.0

//! End-to-end (#422): dynamic byte-origin taint graduates the static
//! `path-controlled-file-open` candidate (GF-405) to a runtime-confirmed
//! oracle finding when a fuzz-controlled path reaches `open` unsanitized,
//! and reports nothing for a sanitized variant that opens a fixed path.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-taint-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// Recursively collect every `finding.json` body under `root`.
fn finding_jsons(root: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "finding.json") {
                if let Ok(bytes) = fs::read(&path) {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        out.push(value);
                    }
                }
            }
        }
    }
    out
}

fn run_auto(root: &Path) {
    let status = support::govfuzz_cargo_command()
        .current_dir(root)
        .args(["auto", root.to_str().unwrap(), "--per-target-time", "3"])
        .status()
        .expect("run govfuzz auto");
    // auto exits 1 when it surfaces findings; both are acceptable here.
    assert!(status.success() || status.code() == Some(1));
}

#[test]
fn auto_confirms_path_controlled_open_gf405() {
    if !support::libfuzzer_toolchain_available("taint-open") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("controlled");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // The target opens its raw fuzz bytes as a filesystem path: any input
    // is fuzz-controlled, so the open path is tainted and GF-405 confirms.
    fs::write(
        src.join("opener.c"),
        "#include <fcntl.h>\n\
         #include <unistd.h>\n\
         #include <string.h>\n\
         int parse_path(const unsigned char *d, unsigned long n) {\n\
             char path[256];\n\
             if (n == 0 || n >= sizeof(path)) return 0;\n\
             memcpy(path, d, n);\n\
             path[n] = 0;\n\
             int fd = open(path, 0);\n\
             if (fd >= 0) close(fd);\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    run_auto(&root);

    let findings = finding_jsons(&root.join("govfuzz_work"));
    let gf405: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-405")
        .collect();
    assert!(
        !gf405.is_empty(),
        "expected a runtime-confirmed GF-405 finding; findings: {:#?}",
        findings
    );
    let confirmed = gf405.iter().find(|f| f["confirmation"] == "runtime");
    let confirmed = confirmed.expect("GF-405 finding must be runtime-confirmed (#422)");
    let evidence = &confirmed["oracle"]["evidence"];
    let taint_path = evidence
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|e| e["key"] == "taint_path")
                .and_then(|e| e["value"].as_str())
        })
        .unwrap_or_default();
    assert!(
        taint_path.contains("open(path)"),
        "GF-405 finding must carry a source→sink taint path, got: {taint_path:?}"
    );
}

#[test]
fn auto_sanitized_open_reports_no_gf405() {
    if !support::libfuzzer_toolchain_available("taint-sanitized") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("sanitized");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // Sanitized: the path is a fixed literal, never derived from the fuzz
    // input. The byte-origin match is severed, so no GF-405 confirmation.
    fs::write(
        src.join("opener.c"),
        "#include <fcntl.h>\n\
         #include <unistd.h>\n\
         int parse_path(const unsigned char *d, unsigned long n) {\n\
             (void)d;\n\
             int fd = open(\"/etc/govfuzz-sanitized-fixed.conf\", 0);\n\
             if (fd >= 0) close(fd);\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    run_auto(&root);

    let findings = finding_jsons(&root.join("govfuzz_work"));
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-405"),
        "sanitized fixed-path open must not produce a GF-405 finding; findings: {:#?}",
        findings
    );
}
