// SPDX-License-Identifier: Apache-2.0

//! End-to-end (#422): dynamic byte-origin taint confirms a fuzz-controlled
//! program/argv reaching an `execv` process-execution API as OS command
//! injection (GF-431, the process-exec sink class), and reports nothing for a
//! hardcoded exec.
//!
//! Safety: the fixture builds the program path under a `/nonexistent/` prefix,
//! so `execv` always fails with ENOENT and never runs an attacker-chosen
//! binary — while the program/argv the shim audits stays fuzz-controlled.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-exectaint-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

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
    assert!(status.success() || status.code() == Some(1));
}

#[test]
fn auto_confirms_exec_program_controlled_gf431() {
    if !support::libfuzzer_toolchain_available("exectaint-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("controlled");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("runner.c"),
        "#include <unistd.h>\n\
         #include <stdio.h>\n\
         #include <string.h>\n\
         int run_exec(const unsigned char *d, unsigned long n) {\n\
             char prog[200];\n\
             char full[256];\n\
             unsigned long i;\n\
             if (n < 4 || n >= sizeof(prog)) return 0;\n\
             for (i = 0; i < n; i++) {\n\
                 if (d[i] < 0x20 || d[i] > 0x7e || d[i] == '/') return 0;\n\
             }\n\
             memcpy(prog, d, n);\n\
             prog[n] = 0;\n\
             snprintf(full, sizeof(full), \"/nonexistent/%s\", prog);\n\
             char *const argv[] = { full, (char *)0 };\n\
             execv(full, argv);\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    run_auto(&root);

    let findings = finding_jsons(&root.join("govfuzz_work"));
    let gf431: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "GF-431")
        .collect();
    assert!(
        !gf431.is_empty(),
        "expected a runtime-confirmed GF-431 finding for exec; findings: {:#?}",
        findings
    );
    let confirmed = gf431
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-431 exec finding must be runtime-confirmed (#422)");
    let taint_path = confirmed["oracle"]["evidence"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|e| e["key"] == "taint_path")
                .and_then(|e| e["value"].as_str())
        })
        .unwrap_or_default();
    assert!(
        taint_path.contains("execv(command)"),
        "GF-431 exec finding must carry an execv source→sink taint path, got: {taint_path:?}"
    );
}

#[test]
fn auto_hardcoded_exec_reports_no_gf431() {
    if !support::libfuzzer_toolchain_available("exectaint-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("hardcoded");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("runner.c"),
        "#include <unistd.h>\n\
         int run_exec(const unsigned char *d, unsigned long n) {\n\
             (void)d;\n\
             char *const argv[] = { (char *)\"/nonexistent/govfuzz-fixed\", (char *)0 };\n\
             execv(\"/nonexistent/govfuzz-fixed\", argv);\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    run_auto(&root);

    let findings = finding_jsons(&root.join("govfuzz_work"));
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-431"),
        "hardcoded exec must not produce a GF-431 finding; findings: {:#?}",
        findings
    );
}
