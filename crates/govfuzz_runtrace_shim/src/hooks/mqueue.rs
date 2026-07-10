// SPDX-License-Identifier: Apache-2.0

//! POSIX message-queue virtualization (#440).
//!
//! Partitioned / message-driven systems on POSIX — cFS's Software Bus, DDS, and
//! most RTOS-on-Linux IPC — move data between tasks/partitions over POSIX message
//! queues (`mq_*`) and shared memory (the latter handled in #438). A message-loop
//! target normally blocks in `mq_receive` waiting for another partition to send;
//! under fuzzing there is no other partition, so the loop never advances and the
//! handler the fuzzer wants to reach never runs.
//!
//! During a fuzz pass this module DELIVERS the current fuzz input as a message:
//! `mq_open` returns a private fake descriptor, `mq_receive`/`mq_timedreceive`
//! fill the caller's buffer with mode-driven bytes (Empty → no message, Rng →
//! pseudo-random, FuzzDriven → the live fuzz input), and `mq_send` is swallowed.
//! `mq_getattr` reports a sane message size so a caller can size its receive
//! buffer. This feeds a partition's message handler its input through the real
//! IPC API without the rest of the deployment. The vendor message-bus structs
//! (cFE `CFE_SB_*`, ARINC 653 APEX) sit ABOVE this and are generated against the
//! target's own headers by stub-gen; here we virtualize the POSIX primitive they
//! are built on.
//!
//! Delivery is bounded ([`MQ_DELIVERY_CAP`]) so a `while (1) mq_receive(...)` loop
//! terminates instead of spinning on the wrapping fuzz-input cursor.
//!
//! Audit mode passes every call through to the real implementation.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::sync::atomic::{AtomicUsize, Ordering};

static REAL_MQ_OPEN: ResolvedFn = ResolvedFn::new(b"mq_open\0");
static REAL_MQ_RECEIVE: ResolvedFn = ResolvedFn::new(b"mq_receive\0");
static REAL_MQ_TIMEDRECEIVE: ResolvedFn = ResolvedFn::new(b"mq_timedreceive\0");

/// Max fuzz-driven messages delivered per process before `mq_receive` reports
/// "empty" (EAGAIN). Generous enough for multi-message protocols, bounded so a
/// receive loop cannot spin forever on the wrapping fuzz-input cursor.
const MQ_DELIVERY_CAP: usize = 256;
static MQ_DELIVERED: AtomicUsize = AtomicUsize::new(0);

fn set_errno(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

fn log_mq(event: &[u8], detail: i64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(event);
        b.field_i64(b"r", detail);
        b.field_i64(b"v", 1);
        b.emit();
    }
}

/// Create a private fake message-queue descriptor (a memfd, so it is a real fd
/// that `mq_close`/`close` accept). Returns -1 on failure.
unsafe fn fake_mqd() -> libc::mqd_t {
    let name = b"govfuzz_fake_mq\0";
    libc::syscall(
        libc::SYS_memfd_create,
        name.as_ptr() as *const libc::c_char,
        libc::MFD_CLOEXEC as libc::c_uint,
    ) as libc::mqd_t
}

// mq_open is variadic in C (`mq_open(name, oflag, [mode, attr])`). As with the
// fs `open` hook, a fixed 4-arg signature works: the trailing args are only read
// by the real implementation when O_CREAT is set, and we ignore them when faking.
#[no_mangle]
pub unsafe extern "C" fn mq_open(
    name: *const libc::c_char,
    oflag: libc::c_int,
    mode: libc::mode_t,
    attr: *mut libc::mq_attr,
) -> libc::mqd_t {
    if crate::fakes::mode::current().is_faking() {
        let fd = fake_mqd();
        if fd >= 0 {
            log_mq(b"mq_open", fd as i64);
            return fd;
        }
    }
    let real = REAL_MQ_OPEN.ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(
        *const libc::c_char,
        libc::c_int,
        libc::mode_t,
        *mut libc::mq_attr,
    ) -> libc::mqd_t = std::mem::transmute(real);
    real(name, oflag, mode, attr)
}

unsafe fn deliver_message(
    msg_ptr: *mut libc::c_char,
    msg_len: libc::size_t,
    msg_prio: *mut libc::c_uint,
    timed: bool,
) -> libc::ssize_t {
    let mode = crate::fakes::mode::current();
    // Empty pass: the external world is absent — no message available.
    if mode == crate::fakes::mode::Mode::Empty {
        set_errno(if timed { libc::ETIMEDOUT } else { libc::EAGAIN });
        return -1;
    }
    // Bound the number of delivered messages so a receive loop terminates.
    if MQ_DELIVERED.fetch_add(1, Ordering::Relaxed) >= MQ_DELIVERY_CAP {
        set_errno(if timed { libc::ETIMEDOUT } else { libc::EAGAIN });
        return -1;
    }
    if msg_ptr.is_null() || msg_len == 0 {
        return 0;
    }
    let buf = std::slice::from_raw_parts_mut(msg_ptr as *mut u8, msg_len);
    let n = crate::fakes::data::fill_bytes(b"mqueue", buf);
    if !msg_prio.is_null() {
        *msg_prio = 0;
    }
    log_mq(b"mq_receive", n as i64);
    n as libc::ssize_t
}

#[no_mangle]
pub unsafe extern "C" fn mq_receive(
    mqdes: libc::mqd_t,
    msg_ptr: *mut libc::c_char,
    msg_len: libc::size_t,
    msg_prio: *mut libc::c_uint,
) -> libc::ssize_t {
    if crate::fakes::mode::current().is_faking() {
        return deliver_message(msg_ptr, msg_len, msg_prio, false);
    }
    let real = REAL_MQ_RECEIVE.ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::mqd_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::c_uint,
    ) -> libc::ssize_t = std::mem::transmute(real);
    real(mqdes, msg_ptr, msg_len, msg_prio)
}

#[no_mangle]
pub unsafe extern "C" fn mq_timedreceive(
    mqdes: libc::mqd_t,
    msg_ptr: *mut libc::c_char,
    msg_len: libc::size_t,
    msg_prio: *mut libc::c_uint,
    abs_timeout: *const libc::timespec,
) -> libc::ssize_t {
    if crate::fakes::mode::current().is_faking() {
        return deliver_message(msg_ptr, msg_len, msg_prio, true);
    }
    let real = REAL_MQ_TIMEDRECEIVE.ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::mqd_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::c_uint,
        *const libc::timespec,
    ) -> libc::ssize_t = std::mem::transmute(real);
    real(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)
}

#[no_mangle]
pub unsafe extern "C" fn mq_send(
    _mqdes: libc::mqd_t,
    _msg_ptr: *const libc::c_char,
    _msg_len: libc::size_t,
    _msg_prio: libc::c_uint,
) -> libc::c_int {
    // Faking: swallow the send (no peer partition); audit: best-effort success.
    log_mq(b"mq_send", 0);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mq_getattr(_mqdes: libc::mqd_t, attr: *mut libc::mq_attr) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        if !attr.is_null() {
            std::ptr::write_bytes(attr, 0, 1);
            (*attr).mq_maxmsg = 10;
            (*attr).mq_msgsize = 8192;
            (*attr).mq_curmsgs = 1;
        }
        return 0;
    }
    let real = ResolvedFn::new(b"mq_getattr\0").ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(libc::mqd_t, *mut libc::mq_attr) -> libc::c_int =
        std::mem::transmute(real);
    real(_mqdes, attr)
}

#[no_mangle]
pub unsafe extern "C" fn mq_close(mqdes: libc::mqd_t) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        // Our descriptor is a memfd — close it directly.
        libc::close(mqdes);
        return 0;
    }
    let real = ResolvedFn::new(b"mq_close\0").ptr() as *const ();
    if real.is_null() {
        return libc::close(mqdes);
    }
    let real: unsafe extern "C" fn(libc::mqd_t) -> libc::c_int = std::mem::transmute(real);
    real(mqdes)
}

#[no_mangle]
pub unsafe extern "C" fn mq_unlink(name: *const libc::c_char) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        return 0;
    }
    let real = ResolvedFn::new(b"mq_unlink\0").ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int = std::mem::transmute(real);
    real(name)
}

/// `--list-fakes` plugin entry for the message-queue virtualization hooks.
pub struct Mqueue;

impl crate::sdk::FakeResource for Mqueue {
    fn name(&self) -> &'static str {
        "mqueue"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"mq_open\0",
            b"mq_receive\0",
            b"mq_timedreceive\0",
            b"mq_send\0",
            b"mq_getattr\0",
            b"mq_close\0",
            b"mq_unlink\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "deliver fuzz input as POSIX message-queue messages (mq_receive) to a partition's handler"
    }
}
