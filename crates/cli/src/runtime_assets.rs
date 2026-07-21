// SPDX-License-Identifier: Apache-2.0

//! Locates the language harness runtimes shipped with govfuzz.
//!
//! Release archives carry these directories beside the executable. Installers,
//! however, install only the executable, so every tracked runtime source is also
//! embedded in the CLI and materialized into a private temporary directory on
//! first use. This keeps generated harnesses independent of the build machine's
//! source checkout.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

type EmbeddedFile = (&'static str, &'static [u8]);

static EMBEDDED_ROOT: OnceLock<Result<tempfile::TempDir, String>> = OnceLock::new();

const EMBEDDED_FILES: &[EmbeddedFile] = &[
    (
        "ada_runtime/adafuzz-decode.adb",
        include_bytes!("../../../ada_runtime/adafuzz-decode.adb"),
    ),
    (
        "ada_runtime/adafuzz-decode.ads",
        include_bytes!("../../../ada_runtime/adafuzz-decode.ads"),
    ),
    (
        "ada_runtime/adafuzz-input.adb",
        include_bytes!("../../../ada_runtime/adafuzz-input.adb"),
    ),
    (
        "ada_runtime/adafuzz-input.ads",
        include_bytes!("../../../ada_runtime/adafuzz-input.ads"),
    ),
    (
        "ada_runtime/adafuzz-probe-gnat_actions.ads",
        include_bytes!("../../../ada_runtime/adafuzz-probe-gnat_actions.ads"),
    ),
    (
        "ada_runtime/adafuzz-probe-memory_buffer.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-memory_buffer.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe-semihosting.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-semihosting.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe-stub.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-stub.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe.ads",
        include_bytes!("../../../ada_runtime/adafuzz-probe.ads"),
    ),
    (
        "ada_runtime/adafuzz.ads",
        include_bytes!("../../../ada_runtime/adafuzz.ads"),
    ),
    (
        "ada_runtime/adafuzz.gpr",
        include_bytes!("../../../ada_runtime/adafuzz.gpr"),
    ),
    (
        "ada_runtime/adafuzz_cov.c",
        include_bytes!("../../../ada_runtime/adafuzz_cov.c"),
    ),
    (
        "c_runtime/govfuzz_asan.h",
        include_bytes!("../../../c_runtime/govfuzz_asan.h"),
    ),
    (
        "c_runtime/govfuzz_asan_fiber.h",
        include_bytes!("../../../c_runtime/govfuzz_asan_fiber.h"),
    ),
    (
        "c_runtime/govfuzz_decode.h",
        include_bytes!("../../../c_runtime/govfuzz_decode.h"),
    ),
    (
        "c_runtime/govfuzz_decode_test.c",
        include_bytes!("../../../c_runtime/govfuzz_decode_test.c"),
    ),
    (
        "c_runtime/govfuzz_driver.c",
        include_bytes!("../../../c_runtime/govfuzz_driver.c"),
    ),
    (
        "csharp_runtime/Driver.cs",
        include_bytes!("../../../csharp_runtime/Driver.cs"),
    ),
    (
        "java_runtime/build-agent.sh",
        include_bytes!("../../../java_runtime/build-agent.sh"),
    ),
    (
        "java_runtime/src/com/govfuzz/Cmplog.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/Cmplog.java"),
    ),
    (
        "java_runtime/src/com/govfuzz/Coverage.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/Coverage.java"),
    ),
    (
        "java_runtime/src/com/govfuzz/CoverageAgent.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/CoverageAgent.java"),
    ),
    (
        "java_runtime/src/com/govfuzz/Driver.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/Driver.java"),
    ),
    (
        "java_runtime/src/com/govfuzz/GovfuzzData.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/GovfuzzData.java"),
    ),
    (
        "java_runtime/src/com/govfuzz/Sink.java",
        include_bytes!("../../../java_runtime/src/com/govfuzz/Sink.java"),
    ),
    (
        "js_runtime/govfuzz_driver.js",
        include_bytes!("../../../js_runtime/govfuzz_driver.js"),
    ),
    (
        "lua_runtime/govfuzz_driver.lua",
        include_bytes!("../../../lua_runtime/govfuzz_driver.lua"),
    ),
    (
        "perl_runtime/Devel/GovfuzzCov.pm",
        include_bytes!("../../../perl_runtime/Devel/GovfuzzCov.pm"),
    ),
    (
        "perl_runtime/govfuzz_driver.pl",
        include_bytes!("../../../perl_runtime/govfuzz_driver.pl"),
    ),
    (
        "php_runtime/govfuzz_driver.php",
        include_bytes!("../../../php_runtime/govfuzz_driver.php"),
    ),
    (
        "python_runtime/govfuzz_cov.py",
        include_bytes!("../../../python_runtime/govfuzz_cov.py"),
    ),
    (
        "python_runtime/govfuzz_decode.py",
        include_bytes!("../../../python_runtime/govfuzz_decode.py"),
    ),
    (
        "python_runtime/govfuzz_driver.py",
        include_bytes!("../../../python_runtime/govfuzz_driver.py"),
    ),
    (
        "ruby_runtime/govfuzz_driver.rb",
        include_bytes!("../../../ruby_runtime/govfuzz_driver.rb"),
    ),
    (
        "rust_runtime/Cargo.toml",
        include_bytes!("../../rust_runtime/Cargo.toml"),
    ),
    (
        "rust_runtime/src/lib.rs",
        include_bytes!("../../rust_runtime/src/lib.rs"),
    ),
];

/// Locate a runtime directory in an extracted release, a development checkout,
/// or the embedded installer fallback.
pub(crate) fn locate(runtime_dir: &str, marker: &str) -> Option<PathBuf> {
    let force_embedded = std::env::var_os("GOVFUZZ_FORCE_EMBEDDED_RUNTIMES").is_some();
    if !force_embedded {
        if let Ok(exe) = std::env::current_exe() {
            for dir in exe.ancestors().skip(1) {
                let candidate = dir.join(runtime_dir);
                if candidate.join(marker).is_file() {
                    return Some(candidate);
                }

                // Older source-tree layouts keep the Rust runtime under `crates/`.
                let nested_candidate = dir.join("crates").join(runtime_dir);
                if nested_candidate.join(marker).is_file() {
                    return Some(nested_candidate);
                }
            }
        }

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for candidate in [
            source_root.join(runtime_dir),
            source_root.join("crates").join(runtime_dir),
        ] {
            if candidate.join(marker).is_file() {
                return Some(candidate);
            }
        }
    }

    let root = embedded_root()?;
    let candidate = root.join(runtime_dir);
    candidate.join(marker).is_file().then_some(candidate)
}

fn embedded_root() -> Option<&'static Path> {
    EMBEDDED_ROOT
        .get_or_init(stage_embedded)
        .as_ref()
        .ok()
        .map(|dir| dir.path())
}

fn stage_embedded() -> Result<tempfile::TempDir, String> {
    let dir = tempfile::Builder::new()
        .prefix("govfuzz-runtime-")
        .tempdir()
        .map_err(|error| format!("create embedded runtime directory: {error}"))?;

    for (relative, bytes) in EMBEDDED_FILES {
        let destination = dir.path().join(relative);
        let parent = destination
            .parent()
            .ok_or_else(|| format!("embedded runtime path has no parent: {relative}"))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create '{}': {error}", parent.display()))?;
        fs::write(&destination, bytes)
            .map_err(|error| format!("write '{}': {error}", destination.display()))?;
    }

    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_fallback_contains_every_runtime_lane() {
        let staged = stage_embedded().expect("stage embedded runtimes");
        for marker in [
            "ada_runtime/adafuzz.ads",
            "c_runtime/govfuzz_driver.c",
            "csharp_runtime/Driver.cs",
            "java_runtime/build-agent.sh",
            "java_runtime/src/com/govfuzz/CoverageAgent.java",
            "js_runtime/govfuzz_driver.js",
            "lua_runtime/govfuzz_driver.lua",
            "perl_runtime/Devel/GovfuzzCov.pm",
            "php_runtime/govfuzz_driver.php",
            "python_runtime/govfuzz_driver.py",
            "ruby_runtime/govfuzz_driver.rb",
            "rust_runtime/Cargo.toml",
            "rust_runtime/src/lib.rs",
        ] {
            assert!(staged.path().join(marker).is_file(), "missing {marker}");
        }
    }

    #[test]
    fn embedded_files_match_the_compiled_assets() {
        let staged = stage_embedded().expect("stage embedded runtimes");
        for (relative, expected) in EMBEDDED_FILES {
            assert_eq!(
                fs::read(staged.path().join(relative)).expect("read staged runtime"),
                *expected,
                "staged bytes differ for {relative}"
            );
        }
    }
}
