// SPDX-License-Identifier: Apache-2.0

//! Identity plugin: when `GOVFUZZ_FAKE_IDENTITY=1` is set,
//! `getpid` / `getuid` / `getgid` / `getppid` return deterministic
//! constants so consecutive runs of the same harness produce
//! identical traces. Useful for differential fuzzing (issue #306)
//! and reproducible replay.
//!
//! Allocation discipline: same as the other hook modules — no
//! malloc / Box / Vec / String from inside the hooks. The env gate
//! is read once via a libc::getenv comparison against b"1\0".

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

pub const FAKE_PID: libc::pid_t = 4242;
pub const FAKE_UID: libc::uid_t = 1000;
pub const FAKE_GID: libc::gid_t = 1000;
pub const FAKE_PPID: libc::pid_t = 1;

const ENV_VAR: &[u8] = b"GOVFUZZ_FAKE_IDENTITY\0";

/// Reads `GOVFUZZ_FAKE_IDENTITY` once via libc::getenv. Returns
/// true iff the value is exactly "1". Cached for the process
/// lifetime so repeated hook calls don't re-enter libc.
pub fn env_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = if value.is_null() {
        false
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(value) };
        s.to_bytes() == b"1"
    };
    CACHED.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    enabled
}

pub struct Identity;

impl FakeResource for Identity {
    fn name(&self) -> &'static str {
        "identity"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"getpid\0", b"getuid\0", b"getgid\0", b"getppid\0"]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "fake POSIX identity calls for deterministic replay"
    }
}

static REAL_GETPID: ResolvedFn = ResolvedFn::new(b"getpid\0");
static REAL_GETUID: ResolvedFn = ResolvedFn::new(b"getuid\0");
static REAL_GETGID: ResolvedFn = ResolvedFn::new(b"getgid\0");
static REAL_GETPPID: ResolvedFn = ResolvedFn::new(b"getppid\0");

unsafe fn call_real_pid(
    resolved: &ResolvedFn,
    hook: *const (),
    default: libc::pid_t,
) -> libc::pid_t {
    call_pid_ptr_or_default(resolved.ptr() as *const (), hook, default)
}

unsafe fn call_real_uid(
    resolved: &ResolvedFn,
    hook: *const (),
    default: libc::uid_t,
) -> libc::uid_t {
    call_uid_ptr_or_default(resolved.ptr() as *const (), hook, default)
}

unsafe fn call_pid_ptr_or_default(
    real: *const (),
    hook: *const (),
    default: libc::pid_t,
) -> libc::pid_t {
    if real.is_null() || real == hook {
        return default;
    }
    let real: unsafe extern "C" fn() -> libc::pid_t = std::mem::transmute(real);
    real()
}

unsafe fn call_uid_ptr_or_default(
    real: *const (),
    hook: *const (),
    default: libc::uid_t,
) -> libc::uid_t {
    if real.is_null() || real == hook {
        return default;
    }
    let real: unsafe extern "C" fn() -> libc::uid_t = std::mem::transmute(real);
    real()
}

fn emit_identity_audit(symbol: &[u8], value: i64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"identity");
        b.field_str(b"f", symbol);
        b.field_i64(b"v", value);
        b.emit();
    }
}

#[no_mangle]
pub unsafe extern "C" fn getpid() -> libc::pid_t {
    if env_enabled() {
        emit_identity_audit(b"getpid", FAKE_PID as i64);
        return FAKE_PID;
    }
    // Never call libc::getpid() here — it resolves to *this* function
    // under LD_PRELOAD and recurses until stack overflow. Use the raw
    // syscall as the fallback when dlsym hasn't resolved the real
    // libc symbol yet.
    call_real_pid(
        &REAL_GETPID,
        getpid as *const (),
        libc::syscall(libc::SYS_getpid) as libc::pid_t,
    )
}

#[no_mangle]
pub unsafe extern "C" fn getuid() -> libc::uid_t {
    if env_enabled() {
        emit_identity_audit(b"getuid", FAKE_UID as i64);
        return FAKE_UID;
    }
    call_real_uid(
        &REAL_GETUID,
        getuid as *const (),
        libc::syscall(libc::SYS_getuid) as libc::uid_t,
    )
}

#[no_mangle]
pub unsafe extern "C" fn getgid() -> libc::gid_t {
    if env_enabled() {
        emit_identity_audit(b"getgid", FAKE_GID as i64);
        return FAKE_GID;
    }
    call_real_uid(
        &REAL_GETGID,
        getgid as *const (),
        libc::syscall(libc::SYS_getgid) as libc::gid_t,
    )
}

#[no_mangle]
pub unsafe extern "C" fn getppid() -> libc::pid_t {
    if env_enabled() {
        emit_identity_audit(b"getppid", FAKE_PPID as i64);
        return FAKE_PPID;
    }
    call_real_pid(
        &REAL_GETPPID,
        getppid as *const (),
        libc::syscall(libc::SYS_getppid) as libc::pid_t,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::FakeResource;

    #[test]
    fn identity_plugin_metadata_matches_manifest() {
        let plugin = Identity;
        assert_eq!(plugin.name(), "identity");
        assert_eq!(
            plugin.intercepts(),
            &[b"getpid\0" as &[u8], b"getuid\0", b"getgid\0", b"getppid\0"]
        );
        assert_eq!(
            plugin.describe(),
            "fake POSIX identity calls for deterministic replay"
        );
    }

    #[test]
    fn pid_fallback_rejects_resolved_hook_pointer() {
        unsafe extern "C" fn recursive_hook() -> libc::pid_t {
            -99
        }

        let value = unsafe {
            call_pid_ptr_or_default(
                recursive_hook as *const (),
                recursive_hook as *const (),
                1234,
            )
        };

        assert_eq!(value, 1234);
    }

    #[test]
    fn uid_fallback_rejects_resolved_hook_pointer() {
        unsafe extern "C" fn recursive_hook() -> libc::uid_t {
            99
        }

        let value = unsafe {
            call_uid_ptr_or_default(
                recursive_hook as *const (),
                recursive_hook as *const (),
                4321,
            )
        };

        assert_eq!(value, 4321);
    }
}
