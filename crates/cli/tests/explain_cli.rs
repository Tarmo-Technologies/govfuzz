// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `govfuzz explain`: after fuzzing a crash that is gated
//! behind a magic value AND reads an env var (faked by the shim), the offline,
//! deterministic explanation must join every evidence source — the sink + CWE, the
//! minimized input, the recovered gate constants the engine solved (input-to-state),
//! the virtualized environment, and the reproduce commands — with no LLM.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn govfuzz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_govfuzz"))
}

/// Overflow gated behind the magic bytes "BOOM"; also reads env var APP_MODE.
const GATED_C: &str = "\
#include <string.h>
#include <stdlib.h>
int handle(const char *data, unsigned int len) {
    if (len < 4) return 0;
    if (data[0]=='B' && data[1]=='O' && data[2]=='O' && data[3]=='M') {
        char *cfg = getenv(\"APP_MODE\");
        char buf[8];
        memcpy(buf, data, len);
        return buf[0] + (cfg ? cfg[0] : 0);
    }
    return 1;
}
";

#[test]
fn explain_joins_input_gates_faked_env_and_dataflow() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-explain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let src = work.with_extension("src.c");
    std::fs::write(&src, GATED_C).unwrap();
    let out = govfuzz()
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("10")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run govfuzz snippet");
    let _ = std::fs::remove_file(&src);
    assert!(
        finding_dir_nonempty(&work),
        "snippet produced no crash: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let explain = govfuzz()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run govfuzz explain");
    let text = String::from_utf8_lossy(&explain.stdout);

    // The narrative must be deterministic and self-contained.
    assert!(text.contains("WHAT HAPPENED"), "missing section:\n{text}");
    assert!(
        text.contains("CWE-121") || text.contains("Buffer Overflow"),
        "missing CWE/class:\n{text}"
    );
    assert!(
        text.contains("THE INPUT THAT TRIGGERS IT"),
        "missing input section:\n{text}"
    );
    // Input-to-state: the engine solved the "BOOM" gate — at least one gate byte
    // must be surfaced from the recovered dictionary.
    assert!(
        text.contains("Input-to-state") && text.contains("matched recovered constant"),
        "missing gate-constant reasoning:\n{text}"
    );
    // The faked environment: the shim served getenv APP_MODE.
    assert!(
        text.contains("FAKED ENVIRONMENT") && text.contains("APP_MODE"),
        "missing faked-env timeline:\n{text}"
    );
    // Reproduce hooks wire into the capsule feature.
    assert!(
        text.contains("govfuzz verify-poc"),
        "missing reproduce commands:\n{text}"
    );

    // Determinism: a second run yields identical text.
    let explain2 = govfuzz()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run govfuzz explain again");
    assert_eq!(
        text,
        String::from_utf8_lossy(&explain2.stdout),
        "explain must be deterministic across runs"
    );
    let _ = std::fs::remove_dir_all(&work);
}

fn finding_dir_nonempty(work: &Path) -> bool {
    std::fs::read_dir(work.join("findings"))
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}
