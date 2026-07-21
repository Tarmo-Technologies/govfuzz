// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProbeBackend {
    #[value(name = "host_file")]
    HostFile,
    #[value(name = "memory_buffer")]
    MemoryBuffer,
    #[value(name = "semihosting")]
    Semihosting,
    #[value(name = "stub")]
    Stub,
}

impl ProbeBackend {
    fn probe_body_source(self) -> &'static str {
        match self {
            Self::HostFile => "adafuzz-probe.adb",
            Self::MemoryBuffer => "adafuzz-probe-memory_buffer.adb",
            Self::Semihosting => "adafuzz-probe-semihosting.adb",
            Self::Stub => "adafuzz-probe-stub.adb",
        }
    }
}

pub(crate) fn materialize_runtime_sources(
    destination: &Path,
    backend: ProbeBackend,
) -> Result<PathBuf, String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "create runtime source directory '{}': {error}",
            destination.display()
        )
    })?;

    let runtime_source_dir = runtime_source_dir();
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz.ads",
        "adafuzz.ads",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz-probe.ads",
        "adafuzz-probe.ads",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        backend.probe_body_source(),
        "adafuzz-probe.adb",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz-input.ads",
        "adafuzz-input.ads",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz-input.adb",
        "adafuzz-input.adb",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz-decode.ads",
        "adafuzz-decode.ads",
    )?;
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz-decode.adb",
        "adafuzz-decode.adb",
    )?;
    // The trace-pc edge-coverage callback (#412). Built by the runtime gpr at
    // `-g` (uninstrumented) and linked into the static archive; the instrumented
    // Ada + binder objects pull it in via the unresolved `__sanitizer_cov_trace_pc`.
    copy_runtime_file(
        &runtime_source_dir,
        destination,
        "adafuzz_cov.c",
        "adafuzz_cov.c",
    )?;

    Ok(destination.to_path_buf())
}

fn copy_runtime_file(
    source_root: &Path,
    destination_root: &Path,
    source_name: &str,
    destination_name: &str,
) -> Result<(), String> {
    let source = source_root.join(source_name);
    let destination = destination_root.join(destination_name);
    fs::copy(&source, &destination).map_err(|error| {
        format!(
            "copy runtime source '{}' to '{}': {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn runtime_source_dir() -> PathBuf {
    crate::runtime_assets::locate("ada_runtime", "adafuzz.ads").unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("ada_runtime")
    })
}
