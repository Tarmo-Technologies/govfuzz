// SPDX-License-Identifier: Apache-2.0

//! getenv-style interceptors. Log every NULL return so the auto loop
//! knows which env vars the target tried to read but found unset.
//! The auto loop's between-pass injector reads the log and
//! setenv()-injects values into the real environment so pass 2
//! sees them. The shim never fakes getenv directly — we'd risk
//! breaking secure_getenv / threading / glibc internals.
//!
//! Safety: the #[no_mangle] extern "C" fn here is invoked by the
//! dynamic linker as a libc symbol. Caller must satisfy libc's
//! getenv-style contract — we forward the pointer to the real impl.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_GETENV: ResolvedFn = ResolvedFn::new(b"getenv\0");
static REAL_SECURE_GETENV: ResolvedFn = ResolvedFn::new(b"secure_getenv\0");

fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

const SUPPRESSED_VARS: &[&[u8]] = &[
    b"GOVFUZZ_",
    b"GOVFUZZ_RUNTRACE_LOG",
    b"LD_PRELOAD",
    b"LD_LIBRARY_PATH",
    // Anything starting with AFL_ or ASAN_ is fuzz-runtime noise.
    b"AFL_",
    b"ASAN_",
    b"UBSAN_",
    b"LSAN_",
    b"MSAN_",
    // Defense-in-depth for the ASan crash symbolizer: on a crash the statically
    // linked sanitizer spawns llvm-symbolizer/addr2line, which inherit our
    // LD_PRELOAD + GOVFUZZ_RUNTRACE_LOG and probe these config families. The
    // symbolizer process is already silenced wholesale at log-open time (see
    // `jsonl::process_is_symbolizer`); these entries also stop the same families
    // from being misattributed as a TARGET dependency if a target itself reads
    // them. None is ever the fuzzed program's own attack surface.
    b"LLVM_",
    b"DEBUGINFOD_",
    b"OPENSSL_",
    b"GNUTLS_",
    b"NETTLE_",
    b"P11_KIT_",
    b"GLIBCXX_TUNABLES",
];

fn should_log(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    for prefix in SUPPRESSED_VARS {
        if name == *prefix {
            return false;
        }
        if name.starts_with(prefix) && prefix.ends_with(b"_") {
            return false;
        }
    }
    true
}

unsafe fn log_env_read(event_name: &[u8], name: *const libc::c_char, result: *mut libc::c_char) {
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        if !name.is_null() {
            let name_bytes = CStr::from_ptr(name).to_bytes();
            if should_log(name_bytes) {
                let mut b = Builder::new(event_name);
                b.field_str(b"n", name_bytes);
                if result.is_null() {
                    b.field_null(b"r");
                } else {
                    b.field_i64(b"r", 1);
                }
                b.emit();
            }
        }
    }
    restore_errno(saved_errno);
}

#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const libc::c_char) -> *mut libc::c_char {
    let real = REAL_GETENV.ptr() as *const ();
    if real.is_null() {
        return libc::getenv(name);
    }
    let real: unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char =
        std::mem::transmute(real);
    let result = real(name);
    log_env_read(b"getenv", name, result);
    result
}

#[no_mangle]
pub unsafe extern "C" fn secure_getenv(name: *const libc::c_char) -> *mut libc::c_char {
    let real = REAL_SECURE_GETENV.ptr() as *const ();
    let result = if real.is_null() {
        std::ptr::null_mut()
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char =
            std::mem::transmute(real);
        real(name)
    };
    log_env_read(b"secure_getenv", name, result);
    result
}

pub struct Env;

impl crate::sdk::FakeResource for Env {
    fn name(&self) -> &'static str {
        "env"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"getenv\0", b"secure_getenv\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log target reads of unset environment variables for between-pass injection"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ld_preload_is_suppressed() {
        assert!(!should_log(b"LD_PRELOAD"));
        assert!(!should_log(b"GOVFUZZ_RUNTRACE_LOG"));
        assert!(!should_log(b"AFL_FUZZ_DIR"));
        assert!(!should_log(b"ASAN_OPTIONS"));
    }

    #[test]
    fn govfuzz_internal_env_vars_are_suppressed() {
        assert!(!should_log(b"GOVFUZZ_FAKE_IDENTITY"));
        assert!(!should_log(b"GOVFUZZ_CMPLOG"));
        assert!(!should_log(b"GOVFUZZ_FUZZ_INPUT_FD"));
        assert!(!should_log(b"GOVFUZZ_RUNTRACE_MODE"));
    }

    #[test]
    fn application_env_vars_logged() {
        assert!(should_log(b"ACME_CONFIG_DIR"));
        assert!(should_log(b"HOME"));
        assert!(should_log(b"PATH"));
    }

    #[test]
    fn symbolizer_and_tls_config_families_are_suppressed() {
        // The ASan crash symbolizer (llvm-symbolizer / debuginfod) and the
        // TLS-config families it probes must never be logged as target deps.
        assert!(!should_log(b"OPENSSL_CONF"));
        assert!(!should_log(b"GNUTLS_SYSTEM_PRIORITY_FILE"));
        assert!(!should_log(b"NETTLE_FOO"));
        assert!(!should_log(b"P11_KIT_DEBUG"));
        assert!(!should_log(b"LLVM_SYMBOLIZER_PATH"));
        assert!(!should_log(b"DEBUGINFOD_URLS"));
        assert!(!should_log(b"GLIBCXX_TUNABLES"));
    }

    #[test]
    fn empty_name_not_logged() {
        assert!(!should_log(b""));
    }

    #[test]
    fn env_plugin_lists_secure_getenv_intercept() {
        use crate::sdk::FakeResource;

        let plugin = Env;
        assert!(plugin
            .intercepts()
            .iter()
            .any(|symbol| *symbol == b"getenv\0"));
        assert!(plugin
            .intercepts()
            .iter()
            .any(|symbol| *symbol == b"secure_getenv\0"));
    }
}
