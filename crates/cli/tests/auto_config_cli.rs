// SPDX-License-Identifier: Apache-2.0
//
// `govfuzz auto` project config file. A `.govfuzz.toml` in the scanned tree is
// auto-loaded, but — because that tree is untrusted — its build-EXECUTING keys
// (build-command / run-untrusted / unsafe-search-and-run…) are ignored unless the
// config is passed explicitly with `--config`. Safe knobs apply either way. Uses
// `--dry-run` so the test is fast and never actually builds.

use std::path::{Path, PathBuf};
use std::process::Command;

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

#[test]
fn auto_loaded_config_ignores_build_executing_keys_but_explicit_config_honors_them() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("a.c"),
        "int process(const char *d, unsigned long n){ return n>0?d[0]:0; }\n",
    )
    .unwrap();
    // A safe knob plus a build-EXECUTING key.
    let cfg = src.join(".govfuzz.toml");
    std::fs::write(&cfg, "per-target-time = 1\nbuild-command = \"./x.sh\"\n").unwrap();

    let stderr = |extra: &[&str]| -> String {
        let mut args = vec!["auto", src.to_str().unwrap(), "--dry-run"];
        args.extend_from_slice(extra);
        let out = Command::new(&bin).args(args).output().expect("run auto");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // Auto-loaded: config is loaded, but the build-command key is ignored (untrusted).
    let auto = stderr(&[]);
    assert!(
        auto.contains("loaded config from"),
        "config should load:\n{auto}"
    );
    assert!(
        auto.contains("ignoring build-executing keys"),
        "auto-loaded build-command must be ignored:\n{auto}"
    );

    // Explicit --config: the same file is trusted, so the key is honored (no warning).
    let explicit = stderr(&["--config", cfg.to_str().unwrap()]);
    assert!(
        explicit.contains("loaded config from"),
        "config should load:\n{explicit}"
    );
    assert!(
        !explicit.contains("ignoring build-executing keys"),
        "an explicit --config must honor build-command:\n{explicit}"
    );

    let _ = std::fs::remove_dir_all(Path::new(&tmp));
}
