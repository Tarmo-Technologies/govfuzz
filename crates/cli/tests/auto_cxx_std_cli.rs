// SPDX-License-Identifier: Apache-2.0
//
// `govfuzz auto` legacy-C++ dialect ladder. The fixture uses `register` — a storage
// class removed in C++17 — so it fails to compile under the modern default (gnu++20)
// and only builds under an older standard. Without `--cxx-std`, auto must retry the
// ladder and reach built_and_fuzzed (choosing gnu++14), rather than failed_build.
// An explicit `--cxx-std gnu++14` also builds; a bogus value fails the run fast.
// Skips cleanly without clang/make.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_clang() -> bool {
    Command::new("clang++").arg("--version").output().is_ok()
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

fn write_fixture(dir: &Path) {
    std::fs::write(
        dir.join("gt.cpp"),
        "int process(const char *data, unsigned long len) {\n\
         \x20   register int y = (int)len;  /* 'register' removed in C++17 */\n\
         \x20   if (len >= 4 && data[0] == 'Z') return y;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
}

/// Whether run.json records at least one built_and_fuzzed target.
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

fn run_auto(bin: &Path, src: &Path, work: &Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "auto",
        src.to_str().unwrap(),
        "--per-target-time",
        "6",
        "--max-targets",
        "1",
        "--work-dir",
        work.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    Command::new(bin)
        .args(args)
        .output()
        .expect("run govfuzz auto")
}

#[test]
fn auto_cxx_std_ladder_builds_legacy_cpp_and_rejects_bogus() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }
    if !have_clang() {
        eprintln!("skip: clang++/make unavailable");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-cxxstd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src);

    // 1) No --cxx-std: the ladder must retry an older standard and build+fuzz.
    let work_ladder = tmp.join("work_ladder");
    let out = run_auto(&bin, &src, &work_ladder, &[]);
    assert!(
        has_built_and_fuzzed(&work_ladder),
        "the dialect ladder should build+fuzz legacy C++ (register); output:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The ladder recorded the older standard it settled on (gnu++20/17 reject register).
    let chosen = std::fs::read_to_string(work_ladder.join("cxx_dialect.txt")).unwrap_or_default();
    assert!(
        chosen.trim() == "gnu++14" || chosen.trim() == "gnu++11" || chosen.trim() == "gnu++03",
        "ladder should settle on a pre-C++17 standard, got {chosen:?}"
    );

    // 2) A bogus --cxx-std fails the run fast.
    let bad = run_auto(
        &bin,
        &src,
        &tmp.join("work_bad"),
        &["--cxx-std", "seventeen"],
    );
    assert!(!bad.status.success(), "a bogus --cxx-std should fail");
    assert!(
        String::from_utf8_lossy(&bad.stderr)
            .to_lowercase()
            .contains("cxx-std"),
        "the error should name --cxx-std:\n{}",
        String::from_utf8_lossy(&bad.stderr)
    );

    let _ = std::fs::remove_dir_all(Path::new(&tmp));
}
