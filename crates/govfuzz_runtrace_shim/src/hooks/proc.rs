// SPDX-License-Identifier: Apache-2.0

//! Process-execution audit hooks. These record command strings passed
//! to shell-style APIs so executable oracles can promote suspicious
//! runtime commands into findings.
//!
//! Safety: the #[no_mangle] extern "C" fns here are invoked by the
//! dynamic linker as libc symbols. Caller-supplied pointers must
//! satisfy the matching libc function contract; we forward them
//! unchanged to the real implementation after auditing.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_SYSTEM: ResolvedFn = ResolvedFn::new(b"system\0");
static REAL_POPEN: ResolvedFn = ResolvedFn::new(b"popen\0");
static REAL_EXECV: ResolvedFn = ResolvedFn::new(b"execv\0");
static REAL_EXECVP: ResolvedFn = ResolvedFn::new(b"execvp\0");
static REAL_EXECVPE: ResolvedFn = ResolvedFn::new(b"execvpe\0");
static REAL_EXECVE: ResolvedFn = ResolvedFn::new(b"execve\0");
static REAL_FEXECVE: ResolvedFn = ResolvedFn::new(b"fexecve\0");
static REAL_POSIX_SPAWN: ResolvedFn = ResolvedFn::new(b"posix_spawn\0");
static REAL_POSIX_SPAWNP: ResolvedFn = ResolvedFn::new(b"posix_spawnp\0");

type Argv = *const *const libc::c_char;

fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

unsafe fn bytes_from_ptr(p: *const libc::c_char) -> &'static [u8] {
    if p.is_null() {
        return &[];
    }
    let cstr = CStr::from_ptr(p);
    let slice: &[u8] = cstr.to_bytes();
    std::mem::transmute::<&[u8], &'static [u8]>(slice)
}

/// Minimum run of fuzz-input-derived bytes a command must contain before it
/// is treated as taint (#422). Matches the floor the filesystem-path hooks
/// use for byte-origin taint; short runs match almost any input by chance.
const TAINT_MIN_LEN: usize = 4;

/// Append byte-origin taint fields to a command event when a contiguous run
/// of the command was derived from the current fuzz input: `u`=1 (controlled)
/// and `o`=the input offset the controlled run originates from. Mirrors the
/// filesystem-path hooks' taint flag so the CLI can confirm a fuzz-controlled
/// command reaching `system`/`popen` (GF-431) with a source→sink path.
fn append_command_taint(b: &mut Builder, command: &[u8]) {
    if let Some((offset, _len)) =
        crate::fakes::fuzz_input::input_derived_run(command, TAINT_MIN_LEN)
    {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
}

fn log_command(event: &[u8], command: &[u8]) {
    if command.is_empty() {
        return;
    }
    let mut b = Builder::new(event);
    b.field_str(b"c", command);
    append_command_taint(&mut b, command);
    b.emit();
}

/// Append a NUL-terminated C string's bytes into `buf` at offset `n`, returning
/// the new offset. Truncates at the buffer end. No heap allocation.
unsafe fn append_cstr(buf: &mut [u8; 1024], mut n: usize, p: *const libc::c_char) -> usize {
    if p.is_null() {
        return n;
    }
    let mut i = 0isize;
    loop {
        let c = *p.offset(i) as u8;
        if c == 0 || n >= buf.len() {
            break;
        }
        buf[n] = c;
        n += 1;
        i += 1;
    }
    n
}

/// Build `program argv...` into a stack buffer and emit an `exec` event (with
/// byte-origin taint) so the CLI's process-exec sink oracle (GF-431) can confirm
/// a fuzz-controlled program or argument reaching an `exec*` / `posix_spawn`
/// API. Emitted on every call (tainted or not) so a constant command is
/// suppressed by the cross-execution correlator. Signal-safe: a fixed 1 KiB
/// stack buffer, at most 64 argv entries, no heap.
unsafe fn log_exec(api: &[u8], path: *const libc::c_char, argv: Argv) {
    let mut buf = [0u8; 1024];
    let mut n = append_cstr(&mut buf, 0, path);
    if !argv.is_null() {
        let mut i = 0isize;
        while i < 64 {
            let a = *argv.offset(i);
            if a.is_null() {
                break;
            }
            if n < buf.len() {
                buf[n] = b' ';
                n += 1;
            }
            n = append_cstr(&mut buf, n, a);
            i += 1;
        }
    }
    if n == 0 {
        return;
    }
    let mut b = Builder::new(b"exec");
    b.field_str(b"a", api);
    b.field_str(b"p", &buf[..n]);
    append_command_taint(&mut b, &buf[..n]);
    b.emit();
}

/// Shared body for the argv-array `exec*` interposers: audit the program + argv
/// for taint, then forward to the real libc function (which replaces the process
/// image on success, so the audit must happen first).
unsafe fn exec_forward(
    real_fn: &ResolvedFn,
    api: &[u8],
    path: *const libc::c_char,
    argv: Argv,
    envp: Argv,
    has_envp: bool,
) -> libc::c_int {
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        log_exec(api, path, argv);
    }
    restore_errno(saved_errno);
    let real = real_fn.ptr() as *const ();
    if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        return -1;
    }
    if has_envp {
        let real: unsafe extern "C" fn(*const libc::c_char, Argv, Argv) -> libc::c_int =
            std::mem::transmute(real);
        real(path, argv, envp)
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, Argv) -> libc::c_int =
            std::mem::transmute(real);
        real(path, argv)
    }
}

#[no_mangle]
pub unsafe extern "C" fn execv(path: *const libc::c_char, argv: Argv) -> libc::c_int {
    exec_forward(&REAL_EXECV, b"execv", path, argv, std::ptr::null(), false)
}

#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const libc::c_char, argv: Argv) -> libc::c_int {
    exec_forward(&REAL_EXECVP, b"execvp", file, argv, std::ptr::null(), false)
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(file: *const libc::c_char, argv: Argv, envp: Argv) -> libc::c_int {
    exec_forward(&REAL_EXECVPE, b"execvpe", file, argv, envp, true)
}

#[no_mangle]
pub unsafe extern "C" fn execve(path: *const libc::c_char, argv: Argv, envp: Argv) -> libc::c_int {
    exec_forward(&REAL_EXECVE, b"execve", path, argv, envp, true)
}

#[no_mangle]
pub unsafe extern "C" fn fexecve(fd: libc::c_int, argv: Argv, envp: Argv) -> libc::c_int {
    // No program path (the program is an fd) — the argv still carries controlled
    // arguments, so audit it before forwarding.
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        log_exec(b"fexecve", std::ptr::null(), argv);
    }
    restore_errno(saved_errno);
    let real = REAL_FEXECVE.ptr() as *const ();
    if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        return -1;
    }
    let real: unsafe extern "C" fn(libc::c_int, Argv, Argv) -> libc::c_int =
        std::mem::transmute(real);
    real(fd, argv, envp)
}

/// Shared body for `posix_spawn`/`posix_spawnp`. These return an errno-style int
/// (0 on success) and do NOT replace the caller, but we still audit before
/// forwarding for consistency.
#[allow(clippy::too_many_arguments)]
unsafe fn posix_spawn_forward(
    real_fn: &ResolvedFn,
    api: &[u8],
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: Argv,
    envp: Argv,
) -> libc::c_int {
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        log_exec(api, path, argv);
    }
    restore_errno(saved_errno);
    let real = real_fn.ptr() as *const ();
    if real.is_null() {
        return libc::ENOSYS;
    }
    let real: unsafe extern "C" fn(
        *mut libc::pid_t,
        *const libc::c_char,
        *const libc::c_void,
        *const libc::c_void,
        Argv,
        Argv,
    ) -> libc::c_int = std::mem::transmute(real);
    real(pid, path, file_actions, attrp, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: Argv,
    envp: Argv,
) -> libc::c_int {
    posix_spawn_forward(
        &REAL_POSIX_SPAWN,
        b"posix_spawn",
        pid,
        path,
        file_actions,
        attrp,
        argv,
        envp,
    )
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: Argv,
    envp: Argv,
) -> libc::c_int {
    posix_spawn_forward(
        &REAL_POSIX_SPAWNP,
        b"posix_spawnp",
        pid,
        file,
        file_actions,
        attrp,
        argv,
        envp,
    )
}

#[no_mangle]
pub unsafe extern "C" fn system(command: *const libc::c_char) -> libc::c_int {
    let command_bytes = bytes_from_ptr(command);
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        log_command(b"system", command_bytes);
    }
    restore_errno(saved_errno);

    let real = REAL_SYSTEM.ptr() as *const ();
    if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        return -1;
    }
    let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int = std::mem::transmute(real);
    real(command)
}

#[no_mangle]
pub unsafe extern "C" fn popen(
    command: *const libc::c_char,
    mode: *const libc::c_char,
) -> *mut libc::FILE {
    let command_bytes = bytes_from_ptr(command);
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        log_command(b"popen", command_bytes);
    }
    restore_errno(saved_errno);

    let real = REAL_POPEN.ptr() as *const ();
    if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        return std::ptr::null_mut();
    }
    let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::FILE =
        std::mem::transmute(real);
    real(command, mode)
}

pub struct Proc;

impl crate::sdk::FakeResource for Proc {
    fn name(&self) -> &'static str {
        "proc"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"system\0",
            b"popen\0",
            b"execv\0",
            b"execvp\0",
            b"execvpe\0",
            b"execve\0",
            b"fexecve\0",
            b"posix_spawn\0",
            b"posix_spawnp\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log command strings and program/argv passed to process-execution APIs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_cstr_concatenates_and_truncates() {
        let a = b"/nonexistent/AAAA\0";
        let b = b"--flag\0";
        let mut buf = [0u8; 1024];
        let n = unsafe {
            let n = append_cstr(&mut buf, 0, a.as_ptr() as *const libc::c_char);
            buf[n] = b' ';
            append_cstr(&mut buf, n + 1, b.as_ptr() as *const libc::c_char)
        };
        assert_eq!(&buf[..n], b"/nonexistent/AAAA --flag");
    }

    #[test]
    fn append_cstr_null_pointer_is_noop() {
        let mut buf = [0u8; 1024];
        let n = unsafe { append_cstr(&mut buf, 3, std::ptr::null()) };
        assert_eq!(n, 3, "a null program pointer must not advance the offset");
    }
}
