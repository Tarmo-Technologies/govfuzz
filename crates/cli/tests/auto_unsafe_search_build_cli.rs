// SPDX-License-Identifier: Apache-2.0
//
// `govfuzz auto --unsafe-search-and-run-build-commands`: the explicit opt-in to
// searching the tree for its own build and EXECUTING it to recover compile flags. The
// fixture's target only compiles with -DGOVFUZZ_NEEDS_THIS, a define ONLY its build.sh
// sets — so without the flag it fails to build, and with it govfuzz finds+runs build.sh
// under the compiler-intercepting shim, recovers the define, and builds+fuzzes.
// Skips cleanly without a C toolchain + make.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_toolchain() -> bool {
    (Command::new("cc").arg("--version").output().is_ok()
        || Command::new("clang").arg("--version").output().is_ok())
        && Command::new("make").arg("--version").output().is_ok()
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn has_built_and_fuzzed(work: &Path) -> bool {
    let Ok(bytes) = std::fs::read(work.join("auto/run.json")) else {
        return false;
    };
    let Ok(run): Result<serde_json::Value, _> = serde_json::from_slice(&bytes) else {
        return false;
    };
    run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .any(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        })
        .unwrap_or(false)
}

#[test]
fn unsafe_search_and_run_recovers_flags_from_build_sh() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }
    if !have_toolchain() {
        eprintln!("skip: no C toolchain / make");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-unsafe-search-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();
    // The target only compiles when the define its build.sh sets is present, with
    // the VALUE build.sh gives it. A bare `#ifndef X / #error` would no longer be a
    // negative control: GovFuzz repairs that shape by defining what the guard tests
    // (see `auto_config_guard.rs`). A compound condition names no single macro whose
    // definition decides it, so GovFuzz refuses to guess and only the real flag —
    // recovered from build.sh — satisfies it.
    std::fs::write(
        src.join("gt.c"),
        "#if !defined(GOVFUZZ_NEEDS_THIS) || GOVFUZZ_NEEDS_THIS != 7\n\
         #error \"needs -DGOVFUZZ_NEEDS_THIS=7, set only by build.sh\"\n\
         #endif\n\
         int process(const char *data, unsigned long len) {\n\
         \x20   if (len >= 4 && data[0] == 'Q') return 1;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let build_sh = src.join("build.sh");
    std::fs::write(
        &build_sh,
        "#!/bin/sh\ncc -DGOVFUZZ_NEEDS_THIS=7 -c gt.c -o gt.o\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&build_sh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let run = |work: &Path, extra: &[&str]| -> bool {
        let mut args = vec![
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "3",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let _ = Command::new(&bin).args(args).output().expect("run auto");
        has_built_and_fuzzed(work)
    };

    // Without the flag: the missing define makes the harness build fail.
    assert!(
        !run(&tmp.join("w_off"), &[]),
        "without the flag the target must NOT build (missing -DGOVFUZZ_NEEDS_THIS)"
    );
    // With the flag: build.sh is found + executed, the define is recovered, it builds.
    assert!(
        run(&tmp.join("w_on"), &["--unsafe-search-and-run-build-commands"]),
        "--unsafe-search-and-run-build-commands should recover the flag from build.sh and build+fuzz"
    );

    let _ = std::fs::remove_dir_all(Path::new(&tmp));
}
