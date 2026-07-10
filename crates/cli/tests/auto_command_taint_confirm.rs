// SPDX-License-Identifier: Apache-2.0

//! End-to-end (#422): dynamic byte-origin taint confirms a fuzz-controlled
//! command reaching `system`/`popen` as an OS command-injection finding
//! (GF-431), and reports nothing for a hardcoded command that merely contains
//! shell metacharacters.
//!
//! Safety: the shim forwards `system()` to the real libc, so the fixtures embed
//! the fuzz-derived span inside single quotes and reject quote/control bytes —
//! the executed command is inert (`echo '...' > /dev/null`) while its string
//! stays fuzz-controlled, which is what the taint oracle keys on.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-cmdtaint-{prefix}-{n}"));
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
fn auto_confirms_command_controlled_gf431() {
    if !support::libfuzzer_toolchain_available("cmdtaint-controlled") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("controlled");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // The target embeds its raw fuzz bytes verbatim inside a shell command and
    // runs it: the command string is fuzz-controlled, so a contiguous run of it
    // carries byte-origin taint and GF-431 confirms. The single-quote wrap plus
    // the quote/control-byte reject keep the executed command inert.
    fs::write(
        src.join("runner.c"),
        "#include <stdlib.h>\n\
         #include <stdio.h>\n\
         #include <string.h>\n\
         int run_cmd(const unsigned char *d, unsigned long n) {\n\
             char arg[256];\n\
             char cmd[512];\n\
             unsigned long i;\n\
             if (n < 4 || n >= sizeof(arg)) return 0;\n\
             for (i = 0; i < n; i++) {\n\
                 if (d[i] == '\\'' || d[i] < 0x20 || d[i] > 0x7e) return 0;\n\
             }\n\
             memcpy(arg, d, n);\n\
             arg[n] = 0;\n\
             snprintf(cmd, sizeof(cmd), \"echo 'govfuzz_%s' > /dev/null\", arg);\n\
             system(cmd);\n\
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
        "expected a runtime-confirmed GF-431 finding; findings: {:#?}",
        findings
    );
    let confirmed = gf431
        .iter()
        .find(|f| f["confirmation"] == "runtime")
        .expect("GF-431 finding must be runtime-confirmed (#422)");
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
        taint_path.contains("system(command)") || taint_path.contains("popen(command)"),
        "GF-431 finding must carry a source→sink taint path, got: {taint_path:?}"
    );
}

#[test]
fn auto_hardcoded_command_reports_no_gf431() {
    if !support::libfuzzer_toolchain_available("cmdtaint-hardcoded") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("hardcoded");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // The command is a fixed literal with shell metacharacters, never derived
    // from the fuzz input. The byte-origin match is severed (and the constant is
    // run on every input, so any dictionary echo is suppressed) — no GF-431.
    fs::write(
        src.join("runner.c"),
        "#include <stdlib.h>\n\
         int run_cmd(const unsigned char *d, unsigned long n) {\n\
             (void)d;\n\
             system(\"echo govfuzz-fixed | grep govfuzz > /dev/null\");\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    run_auto(&root);

    let findings = finding_jsons(&root.join("govfuzz_work"));
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "GF-431"),
        "hardcoded command must not produce a GF-431 finding; findings: {:#?}",
        findings
    );
}
