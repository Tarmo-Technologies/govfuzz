// SPDX-License-Identifier: Apache-2.0

//! Copy libgovfuzz_runtrace_shim.so next to the govfuzz binary
//! as libgovfuzz_runtrace.so so the auto loop can find it via
//! std::env::current_exe() + sibling lookup at runtime.

use std::env;
use std::path::PathBuf;

fn main() {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned());
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap())
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is target/<profile>/build/<crate>-<hash>/out")
        .to_path_buf();

    let shim_src = target_dir.join("libgovfuzz_runtrace_shim.so");
    let shim_dst = target_dir.join("libgovfuzz_runtrace.so");

    // The shim is a workspace member, so cargo builds it before us
    // when cli is built as part of a workspace `cargo build`. Single-
    // crate builds (`cargo build -p govfuzz`) may NOT build the shim.
    // If the canonical cargo artifact exists but this copy step does
    // not run, the runtime locator can still load libgovfuzz_runtrace_shim.so.

    println!("cargo:rerun-if-changed={}", shim_src.display());
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=GOVFUZZ_RELEASE_VERSION");
    let _ = profile;

    // Stamp the short git commit so `bug_report` can identify exactly which
    // govfuzz build produced a self-diagnostics report. Best-effort: an offline
    // unpacked source tarball with no git leaves GOVFUZZ_GIT_COMMIT unset and the
    // report shows "unknown".
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    // Refresh the version/commit stamp when the commit OR tags move. A build
    // script that emits ANY `rerun-if-changed` (the shim, above) otherwise reruns
    // ONLY for those inputs — so `git describe` / the commit would go stale across
    // a re-tag (this made a freshly-tagged release ship a previous version's
    // stamp). Watching the ref files/dirs forces a re-stamp. Absent in a no-git
    // source tarball; the `.exists()` guard keeps cargo from warning then.
    for rel in [
        "../../.git/HEAD",
        "../../.git/packed-refs",
        "../../.git/refs/tags",
    ] {
        if std::path::Path::new(&manifest_dir).join(rel).exists() {
            println!("cargo:rerun-if-changed={rel}");
        }
    }
    let git = |args: &[&str]| -> Option<String> {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&manifest_dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    if let Some(commit) = git(&["rev-parse", "--short", "HEAD"]) {
        println!("cargo:rustc-env=GOVFUZZ_GIT_COMMIT={commit}");
    }
    // A human version for `govfuzz --version`: the git tag/describe (e.g.
    // `v0.2.3` on a tag, or `v0.2.2-3-gc307502` between tags), falling back to the
    // Cargo package version for an unpacked source tarball with no git. ALWAYS
    // emitted so `env!("GOVFUZZ_VERSION_FULL")` compiles.
    let package_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_owned());
    let version_full = if env::var_os("GOVFUZZ_RELEASE_VERSION").is_some() {
        format!("v{package_version}")
    } else {
        git(&["describe", "--tags", "--always", "--dirty"]).unwrap_or(package_version)
    };
    println!("cargo:rustc-env=GOVFUZZ_VERSION_FULL={version_full}");

    if shim_src.is_file() {
        // Copy only if mtime changed.
        let needs_copy = match (shim_src.metadata(), shim_dst.metadata()) {
            (Ok(src), Ok(dst)) => src.modified().ok() != dst.modified().ok(),
            (Ok(_), Err(_)) => true,
            _ => false,
        };
        if needs_copy {
            if let Err(e) = std::fs::copy(&shim_src, &shim_dst) {
                println!("cargo:warning=copy shim: {e}");
            }
        }
    }
}
