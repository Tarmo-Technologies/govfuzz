// SPDX-License-Identifier: Apache-2.0

//! `libgovfuzz_runtrace.so` — LD_PRELOAD shim loaded by `govfuzz auto`
//! into each fuzz target binary. Intercepts a fixed list of libc and
//! libdl entry points (open / getenv / connect / dlopen / ...), calls
//! the real implementation via dlsym(RTLD_NEXT, ...), and appends
//! one-line JSONL runtime events to the file path given in
//! `GOVFUZZ_RUNTRACE_LOG`.
//!
//! Allocation discipline: every hook formats its event into a stack
//! buffer and writes it via libc::write directly. We must NOT call
//! malloc / free / Box::new / String / Vec from inside a hook because
//! the hooked process may already be inside its own allocator on the
//! path we're being called from.

#[cfg(target_os = "linux")]
pub mod dlsym;
#[cfg(target_os = "linux")]
pub mod fakes;
#[cfg(target_os = "linux")]
pub mod hooks;
#[cfg(target_os = "linux")]
pub mod jsonl;
#[cfg(target_os = "linux")]
pub mod policy;
#[cfg(target_os = "linux")]
pub mod reentrancy;
#[cfg(target_os = "linux")]
pub mod registry;
pub mod sdk;

/// Re-export the manifest types so the existing test/code paths
/// continue to work while the data itself lives in the cli-safe
/// `runtrace_manifest` crate.
pub mod manifest {
    pub use runtrace_manifest::{ManifestEntry, MANIFEST};
}

#[cfg(not(target_os = "linux"))]
mod stub {
    // Empty cdylib on macOS / Windows. The auto loop's
    // shim_path::locate() will probably still find the .so/.dylib,
    // but none of the symbols override anything, so the audit is
    // a no-op.
}
