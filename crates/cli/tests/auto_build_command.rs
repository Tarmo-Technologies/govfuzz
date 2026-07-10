// SPDX-License-Identifier: Apache-2.0

//! End-to-end: `govfuzz auto --build-command "<cmd>"` — the universal escape
//! hatch for build systems govfuzz doesn't natively probe (a bare `build.sh`,
//! Bazel, SCons, Waf, a vendor RTOS build). The fixture is a project whose ONLY
//! way to learn the compile wiring is to run its custom build script: the target
//! needs an `-I` include dir and a `-D` define that exist nowhere except inside
//! `build.sh`. govfuzz runs that script under a front-of-PATH compiler shim,
//! recovers the flags into a `compile_commands.json`, and the harness then
//! builds and fuzzes with them. Without interception the harness build can't
//! find the config header and fails.
//!
//! Shells the built `govfuzz` binary. Gated on clang so a toolchain-less CI lane
//! skips cleanly.

use std::path::Path;
use std::process::Command;

fn toolchain_available() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_build_command: clang not on PATH");
        return false;
    }
    // The shim execs `cc`; require a host C compiler the build script can call.
    if which::which("cc").is_err() && which::which("gcc").is_err() {
        eprintln!("skipping auto_build_command: no cc/gcc on PATH");
        return false;
    }
    true
}

fn write_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("inc")).unwrap();
    // The define + value the parser depends on live ONLY in the include dir the
    // custom build adds — recoverable solely by intercepting the build.
    std::fs::write(root.join("inc/site_cfg.h"), "#define FRAME_BIAS 11\n").unwrap();
    std::fs::write(
        root.join("sensor.c"),
        "#include \"site_cfg.h\"\n\
         int decode_frame(const unsigned char *d, unsigned n)\n\
         {\n\
         \x20   unsigned acc = FRAME_BIAS;\n\
         \x20   for (unsigned i = 0; i < n; i++) acc += d[i];\n\
         \x20   return (int)(acc & 0xffff);\n\
         }\n",
    )
    .unwrap();
    // A custom build script that invokes the compiler BY NAME with the project's
    // real flags (`-Iinc`). Named arbitrarily — the user points govfuzz at it.
    std::fs::write(
        root.join("build.sh"),
        "#!/bin/sh\ncc -Iinc -DBUILT_BY_SCRIPT=1 -c sensor.c -o sensor.o\n",
    )
    .unwrap();
}

#[test]
fn build_command_interception_recovers_flags_and_fuzzes() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-build-command-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--build-command")
        .arg("sh build.sh")
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn govfuzz auto");

    // The interception must have produced a compile database with the recovered
    // include dir + define.
    let db_path = root.join(".govfuzz-build/compile_commands.json");
    let db = std::fs::read_to_string(&db_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; govfuzz auto exit={:?}\nstderr:\n{}",
            db_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert!(
        db.contains("-Iinc"),
        "recovered DB must capture -Iinc:\n{db}"
    );
    assert!(
        db.contains("sensor.c"),
        "recovered DB must name the TU:\n{db}"
    );

    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).expect("run.json"))
            .expect("parse run.json");
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);
    assert!(
        built_and_fuzzed >= 1,
        "harness must build+fuzz using the intercepted flags; summary={}\nstderr:\n{}",
        run["summary"],
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn build_command_intercepts_an_absolute_path_compiler() {
    if !toolchain_available() {
        return;
    }
    // Catching a compiler invoked by ABSOLUTE path is the LD_PRELOAD exec-shim's
    // job (the PATH shim cannot shadow it). Skip if the shim wasn't built next to
    // the binary (e.g. a non-workspace `-p govfuzz` build).
    let so = Path::new(env!("CARGO_BIN_EXE_govfuzz"))
        .parent()
        .unwrap()
        .join("libgovfuzz_cc_intercept.so");
    if !so.is_file() {
        eprintln!(
            "skipping: {} not built (workspace build needed)",
            so.display()
        );
        return;
    }
    let cc = which::which("cc")
        .or_else(|_| which::which("gcc"))
        .expect("cc/gcc present");

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-abs-cc-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("inc")).unwrap();
    std::fs::write(root.join("inc/cfg.h"), "#define ABS_BIAS 5\n").unwrap();
    std::fs::write(
        root.join("scan.c"),
        "#include \"cfg.h\"\n\
         int scan(const unsigned char *d, unsigned n)\n\
         { int s = ABS_BIAS; for (unsigned i = 0; i < n; i++) s += d[i]; return s; }\n",
    )
    .unwrap();
    // The build invokes the compiler by ABSOLUTE path.
    std::fs::write(
        root.join("build.sh"),
        format!(
            "#!/bin/sh\n{} -Iinc -DVIA_ABS_PATH=1 -c scan.c -o scan.o\n",
            cc.display()
        ),
    )
    .unwrap();
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--build-command")
        .arg("sh build.sh")
        .arg("--work-dir")
        .arg(&work)
        .arg("--deps-only")
        .output()
        .expect("spawn govfuzz auto");

    let db_path = root.join(".govfuzz-build/compile_commands.json");
    let db: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&db_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}; exit={:?}\nstderr:\n{}",
                db_path.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }))
        .expect("parse compile_commands.json");

    let entries = db.as_array().expect("DB is an array");
    // Flags from the abs-path compile were recovered (only LD_PRELOAD could).
    let blob = db.to_string();
    assert!(
        blob.contains("-Iinc") && blob.contains("VIA_ABS_PATH"),
        "abs-path compile flags must be recovered via LD_PRELOAD:\n{blob}"
    );
    // Dedup: exactly one entry for scan.c despite PATH-shim + LD_PRELOAD both on.
    let scan_entries = entries
        .iter()
        .filter(|e| e["file"].as_str().is_some_and(|f| f.ends_with("scan.c")))
        .count();
    assert_eq!(
        scan_entries, 1,
        "scan.c must appear exactly once; db={blob}"
    );
}
