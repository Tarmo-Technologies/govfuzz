// SPDX-License-Identifier: Apache-2.0
//
// Campaign regression (byteorder write_* empty-buffer FP). The native Rust lane
// harnesses `pub trait` STATIC methods that take an OUTPUT buffer `buf: &mut [u8]`
// plus a value (`Pack::write_u64(buf, n)`). The buffer must be backed by an
// adequately-sized, mutable scratch buffer — NOT the raw fuzz slice, which is
// empty/short for most inputs and makes the fixed-width `buf[..N].copy_from_slice`
// panic on EVERY input ("range end index N out of range for slice of length 0").
// This test builds+fuzzes the real fixture and asserts the panic storm is gone:
// the write_* harnesses execute cleanly with ZERO findings, and the generated
// harness backs the `&mut [u8]` with a sized buffer. Self-skips without a `cargo
// +nightly` toolchain (the native lane needs it for `-Zsanitizer`).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize fixture {name}: {e}"))
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn has_cargo_nightly() -> bool {
    Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_auto(fixture_dir: &Path, work: &Path) -> (String, serde_json::Value) {
    let output = Command::new(govfuzz_bin())
        .args([
            "auto",
            fixture_dir.to_str().unwrap(),
            "--per-target-time",
            "3",
            "--max-targets",
            "4",
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run_json = work.join("auto").join("run.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&run_json).expect("read run.json"))
            .expect("parse run.json");
    (combined, json)
}

fn attempts(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json.get("targets")
        .or_else(|| json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array")
}

/// Total findings across an attempt's passes, or `None` if it did not build+fuzz.
fn attempt_findings(attempt: &serde_json::Value) -> Option<usize> {
    let passes = attempt
        .get("outcome")
        .and_then(|o| o.get("passes"))
        .and_then(|p| p.as_array())?;
    Some(
        passes
            .iter()
            .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
            .map(|f| f.len())
            .sum(),
    )
}

#[test]
fn write_output_buffer_method_builds_fuzzes_without_empty_slice_panic_storm() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-outbuf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (combined, json) = run_auto(&fixture("rust_output_buffer"), &tmp);

    // A write_* method built+fuzzed through the UFCS static-method lane.
    assert!(
        combined.contains("built+fuzzed"),
        "a write_* output-buffer method must build+fuzz; got:\n{combined}"
    );
    // The empty-buffer panic must be GONE: no input should produce the fixed-width
    // slice-range panic now that the buffer is adequately sized.
    assert!(
        !combined.contains("out of range for slice of length 0"),
        "the empty-buffer write panic storm must be gone; got:\n{combined}"
    );

    // Find the write_* attempts that built+fuzzed; each must produce ZERO findings
    // (the write path now runs cleanly) and back the `&mut [u8]` with a sized buffer.
    let mut built_writes = 0usize;
    for attempt in attempts(&json) {
        let name = attempt
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        if !name.starts_with("write_") {
            continue;
        }
        let Some(findings) = attempt_findings(attempt) else {
            continue; // did not build+fuzz on this run
        };
        built_writes += 1;
        assert_eq!(
            findings, 0,
            "write_* output-buffer harness `{name}` must produce ZERO findings \
             (no empty-buffer panic); output:\n{combined}"
        );
        // The generated harness backs the output buffer with a sized, zero-padded
        // scratch buffer rather than the raw fuzz slice.
        let harness_id = attempt
            .get("harness_id")
            .and_then(|h| h.as_str())
            .unwrap_or_else(|| panic!("`{name}` has a harness_id"));
        let harness_rs = tmp
            .join("harnesses")
            .join(harness_id)
            .join("rust_harness/src/lib.rs");
        if let Ok(text) = std::fs::read_to_string(&harness_rs) {
            assert!(
                text.contains("_gf_buf.resize(64, 0u8)"),
                "`{name}` harness must back the &mut [u8] with a sized buffer:\n{text}"
            );
            assert!(
                !text.contains("let mut a0 = c.bytes("),
                "`{name}` output buffer must not be the raw fuzz slice:\n{text}"
            );
        }
    }
    assert!(
        built_writes > 0,
        "at least one write_* output-buffer method must build+fuzz; output:\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
