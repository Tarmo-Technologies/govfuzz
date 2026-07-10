// SPDX-License-Identifier: Apache-2.0

//! Windows-native cross-fuzzing (mingw + wine) end-to-end fixture.
//!
//! Proves govfuzz can BUILD a fuzz harness as a real Windows PE with the
//! `x86_64-w64-mingw32` cross toolchain and RUN it under wine — the
//! higher-fidelity path for Windows-platform-guarded targets that the attempt
//! loop FUTURE note (attempt.rs) calls for. Each test is gated on the cross
//! toolchain + wine being present, mirroring `m17_aarch64_cross_fixture.rs`, so
//! it is a no-op skip on a host without the toolchain and a real check here.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The cross toolchain + wine govfuzz drives for a real Windows-PE harness.
struct WindowsTools {
    wine: PathBuf,
}

impl WindowsTools {
    fn discover() -> Option<Self> {
        which::which("x86_64-w64-mingw32-gcc").ok()?;
        let wine = which::which("wine").ok()?;
        Some(Self { wine })
    }
}

/// A `govfuzz_run_one` that faults on an input beginning with `CRASH` and is
/// otherwise a no-op. The faulting address is derived from the input so the
/// compiler cannot const-fold the dereference away as UB.
const RUN_ONE_CRASH_ON_PREFIX: &str =
    "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\
     int govfuzz_run_one(const uint8_t *d, size_t n) {\n\
     \x20 if (n >= 5 && memcmp(d, \"CRASH\", 5) == 0) {\n\
     \x20   volatile char *p = (volatile char *)(uintptr_t)d[0];\n\
     \x20   *p = (char)0x41;\n\
     \x20 }\n\
     \x20 return 0;\n\
     }\n";

/// A C++ source whose parser is guarded by `_WIN32` — exercises the cpp.tera
/// driver template's Windows port (cross-compiled with mingw g++, fuzzed under
/// wine). Same input-triggered wild write as the C fixture.
const WIN_PARSER_CPP_FIXTURE: &str = "#include <cstddef>\n#include <cstdint>\n\
     #ifdef _WIN32\n\
     #include <windows.h>\n\
     int cpp_parse(const uint8_t *data, std::size_t len) {\n\
     \x20 if (len >= 1 && data[0] != 0) {\n\
     \x20   volatile char *p = reinterpret_cast<volatile char *>(static_cast<std::uintptr_t>(data[0]));\n\
     \x20   *p = static_cast<char>(0x41);\n\
     \x20 }\n\
     \x20 return static_cast<int>(len);\n\
     }\n\
     #endif\n";

/// A C source whose parser is guarded by `_WIN32`, so discovery tags it with a
/// `foreign_guard` and the attempt loop must cross-compile it to a PE and fuzz it
/// under wine. The parser does a wild write to a low (unmapped) address derived
/// from the input, so almost any non-empty input faults — caught by the driver's
/// vectored exception handler as a crash. Models a Windows-only code path.
const WIN_PARSER_FIXTURE: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     #ifdef _WIN32\n\
     #include <windows.h>\n\
     int parse_record(const uint8_t *data, size_t len) {\n\
     \x20 if (len >= 1 && data[0] != 0) {\n\
     \x20   volatile char *p = (volatile char *)(uintptr_t)((unsigned)data[0]);\n\
     \x20   *p = (char)0x41; /* wild write -> access violation */\n\
     \x20 }\n\
     \x20 return (int)len;\n\
     }\n\
     #endif\n";

/// A `govfuzz_run_one` that exercises several input-dependent edges, so the
/// trace-pc coverage runtime sets bits in the bitmap.
const RUN_ONE_EXERCISE: &str = "#include <stdint.h>\n#include <stddef.h>\n\
     int govfuzz_run_one(const uint8_t *d, size_t n) {\n\
     \x20 volatile int acc = 0;\n\
     \x20 for (size_t i = 0; i < n; i++) {\n\
     \x20   if (d[i] & 1) acc += d[i]; else acc -= d[i];\n\
     \x20 }\n\
     \x20 return acc & 1;\n\
     }\n";

/// Cross-build the govfuzz driver + a `govfuzz_run_one` TU into a Windows PE
/// with the mingw coverage/cmplog flags, returning the `.exe` path.
fn build_windows_harness(dir: &Path, run_one_src: &str) -> PathBuf {
    let driver = repo_root().join("c_runtime/govfuzz_driver.c");
    let run_one = dir.join("run_one.c");
    std::fs::write(&run_one, run_one_src).expect("run_one source is written");
    let exe = dir.join("main.exe");
    let output = Command::new("x86_64-w64-mingw32-gcc")
        .args(["-fsanitize-coverage=trace-pc,trace-cmp", "-O1", "-g"])
        .arg(&driver)
        .arg(&run_one)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("mingw cc runs");
    assert!(
        output.status.success(),
        "windows harness builds; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

/// Write one framed `{u32 LE length, bytes}` record to the harness stdin.
fn write_frame(w: &mut impl Write, bytes: &[u8]) {
    w.write_all(&(bytes.len() as u32).to_le_bytes())
        .expect("frame length is written");
    w.write_all(bytes).expect("frame body is written");
    w.flush().expect("frame is flushed");
}

/// The mingw C cross compiler govfuzz drives for a Windows target, if present.
fn mingw_cc() -> Option<&'static str> {
    let cc = "x86_64-w64-mingw32-gcc";
    which::which(cc).ok().map(|_| cc)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-windows-{name}-{nonce}"));
    std::fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}

/// Write a trivial `govfuzz_run_one` translation unit beside the driver so the
/// driver links into a standalone PE without pulling a real target in.
fn write_trivial_run_one(dir: &Path) -> PathBuf {
    let run_one = dir.join("run_one.c");
    std::fs::write(
        &run_one,
        b"#include <stdint.h>\n#include <stddef.h>\n\
          int govfuzz_run_one(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n",
    )
    .expect("run_one source is written");
    run_one
}

#[test]
fn govfuzz_driver_compiles_under_mingw_with_trace_pc_coverage() {
    let Some(cc) = mingw_cc() else {
        eprintln!("skipping: no x86_64-w64-mingw32-gcc on PATH");
        return;
    };

    let driver = repo_root().join("c_runtime/govfuzz_driver.c");
    assert!(driver.is_file(), "driver source is present at {driver:?}");

    let dir = temp_dir("driver-compile");
    let run_one = write_trivial_run_one(&dir);
    let exe = dir.join("main.exe");

    // mingw-w64 gcc rejects `trace-pc-guard` (clang-only here) but accepts
    // `trace-pc` + `trace-cmp` — the coverage/cmplog flags the Windows build
    // uses. The driver must compile cleanly under them.
    let output = Command::new(cc)
        .args(["-fsanitize-coverage=trace-pc,trace-cmp", "-O1", "-g"])
        .arg(&driver)
        .arg(&run_one)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("mingw cc runs");

    assert!(
        output.status.success(),
        "govfuzz_driver.c must cross-compile under mingw; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(exe.is_file(), "a Windows PE is produced at {exe:?}");
}

#[test]
fn windows_harness_runs_clean_input_under_wine_via_framed_protocol() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("framed-clean");
    let exe = build_windows_harness(&dir, RUN_ONE_CRASH_ON_PREFIX);

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("GOVFUZZ_FRAMED", "1")
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");
    assert_eq!(byte[0], 1, "ready byte is 1");

    write_frame(&mut stdin, b"hello");
    stdout
        .read_exact(&mut byte)
        .expect("harness writes a sync byte after a clean exec");
    assert_eq!(byte[0], 1, "sync byte is 1");

    drop(stdin); // EOF ends the persistent loop
    let status = child.wait().expect("harness exits");
    assert!(
        status.success(),
        "a clean framed run under wine exits 0, got {status}"
    );
}

#[test]
fn windows_harness_crash_is_detected_under_wine() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("framed-crash");
    let exe = build_windows_harness(&dir, RUN_ONE_CRASH_ON_PREFIX);

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("GOVFUZZ_FRAMED", "1")
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");

    // A crashing input faults inside run_one; the vectored exception handler
    // converts it into an immediate process exit, so no sync byte arrives and
    // the process exits with the crash sentinel rather than hanging.
    write_frame(&mut stdin, b"CRASH");
    let got = stdout.read(&mut byte).expect("read after crash");
    assert_eq!(got, 0, "no sync byte after a crash (pipe closes at EOF)");

    drop(stdin);
    let status = child.wait().expect("harness exits");
    assert!(
        !status.success(),
        "a crash under wine yields a nonzero exit, got {status}"
    );
    if let Some(code) = status.code() {
        assert_eq!(
            code, 0x39,
            "crash exit is the driver's vectored-handler sentinel"
        );
    }
}

#[test]
fn windows_harness_coverage_shm_is_visible_to_host_after_wine_run() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("cov-shm");
    let exe = build_windows_harness(&dir, RUN_ONE_EXERCISE);
    let cov = dir.join("cov.bin");
    // Pre-create the backing file zeroed so "host sees nothing" is unambiguous:
    // the driver must write coverage THROUGH to this same host file.
    std::fs::write(&cov, vec![0u8; 1 << 16]).expect("cov backing file is created");

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("GOVFUZZ_FRAMED", "1")
        .env("GOVFUZZ_COV_SHM", &cov)
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");
    write_frame(&mut stdin, b"the quick brown fox");
    stdout
        .read_exact(&mut byte)
        .expect("harness writes a sync byte");
    drop(stdin);
    child.wait().expect("harness exits");

    let bytes = std::fs::read(&cov).expect("cov backing file is readable");
    let nonzero = bytes.iter().filter(|b| **b != 0).count();
    assert!(
        nonzero > 0,
        "coverage written under wine must be visible in the host's backing file \
         (got {nonzero} nonzero bytes of {})",
        bytes.len()
    );
}

#[test]
fn govfuzz_auto_cross_builds_and_fuzzes_a_windows_guarded_target_under_wine() {
    let Some(_tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("auto-win");
    std::fs::write(dir.join("win_parser.c"), WIN_PARSER_FIXTURE).expect("fixture written");
    let work = dir.join("work");

    // `govfuzz auto` must DISCOVER parse_record (tagged `_WIN32` foreign-guard),
    // pick the Cross(mingw+wine) strategy, build a real PE, and fuzz it under wine.
    let rc = cli::run_from([
        "govfuzz",
        "auto",
        dir.to_str().unwrap(),
        "--per-target-time",
        "10",
        "--max-targets",
        "4",
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    assert_eq!(
        rc, 0,
        "govfuzz auto exits 0 (findings are data, not an error)"
    );

    let run_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let attempts = run_json
        .get("targets")
        .or_else(|| run_json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array");
    let pr = attempts
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("parse_record"))
        .unwrap_or_else(|| panic!("parse_record was attempted; run.json:\n{run_json:#}"));

    let outcome = pr.get("outcome").expect("parse_record has an outcome");
    let passes = outcome
        .get("passes")
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| {
            panic!("parse_record must build+fuzz via the Cross mingw+wine path, not skip/stub; outcome:\n{outcome:#}")
        });

    let edges: u64 = passes
        .iter()
        .filter_map(|p| p.get("coverage_edges").and_then(|e| e.as_u64()))
        .max()
        .unwrap_or(0);
    let execs: u64 = passes
        .iter()
        .filter_map(|p| p.get("executions").and_then(|e| e.as_u64()))
        .sum();
    let findings: usize = passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum();

    assert!(execs > 0, "real executions under wine, got {execs}");
    assert!(
        edges > 0,
        "real coverage edges under wine via trace-pc, got {edges}"
    );
    assert!(
        findings > 0,
        "the wild-write crash must be found under wine (0 findings over {execs} execs, {edges} edges)"
    );
}

#[test]
fn govfuzz_auto_cross_builds_and_fuzzes_a_windows_guarded_cpp_target_under_wine() {
    if which::which("x86_64-w64-mingw32-g++").is_err() || which::which("wine").is_err() {
        eprintln!("skipping: requires x86_64-w64-mingw32-g++ and wine");
        return;
    }

    let dir = temp_dir("auto-win-cpp");
    std::fs::write(dir.join("win_parser.cpp"), WIN_PARSER_CPP_FIXTURE).expect("fixture written");
    let work = dir.join("work");

    let rc = cli::run_from([
        "govfuzz",
        "auto",
        dir.to_str().unwrap(),
        "--per-target-time",
        "10",
        "--max-targets",
        "4",
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0, "govfuzz auto exits 0");

    let run_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let attempts = run_json
        .get("targets")
        .or_else(|| run_json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array");
    let pr = attempts
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("cpp_parse"))
        .unwrap_or_else(|| panic!("cpp_parse was attempted; run.json:\n{run_json:#}"));
    let passes = pr
        .get("outcome")
        .and_then(|o| o.get("passes"))
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| panic!("cpp_parse must build+fuzz via Cross mingw+wine; got:\n{pr:#}"));
    let execs: u64 = passes
        .iter()
        .filter_map(|p| p.get("executions").and_then(|e| e.as_u64()))
        .sum();
    let findings: usize = passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum();
    assert!(execs > 0, "real C++ executions under wine, got {execs}");
    assert!(
        findings > 0,
        "the wild-write crash in the C++ target must be found under wine ({execs} execs)"
    );
}
