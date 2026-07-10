// SPDX-License-Identifier: Apache-2.0

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-toolchain-support-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/cli")
        .to_path_buf()
}

#[test]
fn libstdcxx_search_path_from_dirs_returns_first_existing_runtime_dir() {
    let root = tmpdir("libstdcxx");
    let missing = root.join("gcc/missing");
    let found = root.join("gcc/13");
    fs::create_dir_all(&found).unwrap();
    fs::write(found.join("libstdc++.so"), "").unwrap();

    let selected = support::libstdcxx_search_path_from_dirs([missing.as_path(), found.as_path()]);

    assert_eq!(selected.as_deref(), Some(found.as_path()));
}

#[test]
fn libfuzzer_probe_args_thread_libstdcxx_fallback() {
    let bin = Path::new("/tmp/govfuzz-probe-bin");
    let src = Path::new("/tmp/govfuzz-probe.c");
    let libstdcxx = Path::new("/usr/lib/gcc/x86_64-linux-gnu/13");

    let args = support::libfuzzer_probe_args(bin, src, Some(libstdcxx));
    let rendered = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(rendered.contains(&"-fsanitize=fuzzer,address,undefined".to_owned()));
    assert!(rendered.contains(&format!("-L{}", libstdcxx.display())));
}

#[test]
fn libfuzzer_toolchain_probe_returns_false_for_missing_compiler() {
    assert!(!support::libfuzzer_toolchain_available_with(
        "definitely-not-a-govfuzz-compiler",
        "missing-compiler"
    ));
}

#[test]
fn libfuzzer_toolchain_probe_entrypoint_is_callable() {
    let _ = support::libfuzzer_toolchain_available("entrypoint");
}

#[test]
fn govfuzz_cargo_command_uses_manifest_path() {
    let cmd = support::govfuzz_cargo_command();
    let rendered = cmd
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(rendered.contains(&"--manifest-path".to_owned()));
    assert!(rendered.iter().any(|arg| arg.ends_with("Cargo.toml")));
    assert!(rendered.contains(&"--".to_owned()));
}

#[test]
fn c_runtime_decoder_compiles_under_c89_project_flags() {
    if which::which("clang").is_err() {
        eprintln!("skipping c89 runtime probe: clang not on PATH");
        return;
    }

    let root = workspace_root();
    let c_runtime = root.join("c_runtime");
    let src = c_runtime.join("govfuzz_decode_test.c");
    let out_dir = tmpdir("c89-runtime");
    let bin = out_dir.join("govfuzz_decode_test");
    let output = Command::new("clang")
        .arg("-std=c89")
        .arg("-I")
        .arg(&c_runtime)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .output()
        .expect("spawn clang c89 runtime probe");

    assert!(
        output.status.success(),
        "govfuzz_decode.h must compile when real C compile databases carry -std=c89\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new(&bin)
        .output()
        .expect("run c89 runtime probe binary");
    assert!(
        run.status.success(),
        "c89 runtime probe binary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
