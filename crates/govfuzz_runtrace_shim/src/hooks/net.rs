// SPDX-License-Identifier: Apache-2.0

//! connect / getaddrinfo audit hooks. Records every ECONNREFUSED
//! / EAI_NONAME / EAI_AGAIN that points at an off-loopback
//! address. The Slice-C runtime will later substitute these with
//! socketpair() peers; for now we just observe.
//!
//! Safety: every #[no_mangle] extern "C" fn here is invoked by the
//! dynamic linker as a libc symbol. Caller-supplied pointers must
//! satisfy the matching libc function's contract — we forward them
//! to the real implementation unchanged.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::needless_range_loop)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::policy::should_audit_endpoint;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_CONNECT: ResolvedFn = ResolvedFn::new(b"connect\0");
static REAL_GETADDRINFO: ResolvedFn = ResolvedFn::new(b"getaddrinfo\0");

fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

/// Minimum run of fuzz-input-derived bytes a destination must contain before it
/// is treated as taint (#422). Matches the floor the other sink hooks use.
const TAINT_MIN_LEN: usize = 4;

/// Emit a `net_egress` sink event for a network destination reached during a
/// fuzz execution, tagged with byte-origin taint when a contiguous run of the
/// destination came from the current fuzz input. Emitted on every egress to a
/// real endpoint (tainted or not) so the CLI's SSRF sink oracle (GF-433) can
/// confirm a fuzz-controlled destination and suppress a constant one the
/// auto-dictionary merely echoed into an input.
fn emit_egress(api: &[u8], dest: &[u8]) {
    if dest.is_empty() {
        return;
    }
    let mut b = Builder::new(b"net_egress");
    b.field_str(b"a", api);
    b.field_str(b"d", dest);
    if let Some((offset, _len)) = crate::fakes::fuzz_input::input_derived_run(dest, TAINT_MIN_LEN) {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
    b.emit();
}

/// Render an unsigned integer into `out[n..]` as decimal ASCII.
/// Returns the new write offset. Width-limited to `max_digits`.
/// No heap allocations.
fn write_uint(out: &mut [u8; 128], mut n: usize, mut v: u32, max_digits: usize) -> usize {
    let mut digits = [0u8; 5];
    let mut count = 0usize;
    if v == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while v > 0 && count < max_digits {
            digits[max_digits - 1 - count] = b'0' + (v % 10) as u8;
            v /= 10;
            count += 1;
        }
        // Shift digits to start of array.
        for j in 0..count {
            digits[j] = digits[max_digits - count + j];
        }
    }
    for j in 0..count {
        if n < out.len() {
            out[n] = digits[j];
            n += 1;
        }
    }
    n
}

/// Render a sockaddr to a short printable form so the report can
/// list it. Falls back to "?" on unknown families. No heap allocs.
unsafe fn render_sockaddr(
    addr: *const libc::sockaddr,
    _len: libc::socklen_t,
    out: &mut [u8; 128],
) -> (i32, usize) {
    if addr.is_null() {
        return (0, 0);
    }
    let family = (*addr).sa_family as i32;
    match family {
        f if f == libc::AF_UNIX => {
            // sa_data starts at offset 2. Path is up to 108 bytes.
            let sun = addr as *const libc::sockaddr_un;
            let path_ptr = (*sun).sun_path.as_ptr() as *const u8;
            let path_max = 108_usize.min(out.len());
            let mut n = 0;
            while n < path_max {
                let c = *path_ptr.add(n);
                if c == 0 {
                    break;
                }
                out[n] = c;
                n += 1;
            }
            (f, n)
        }
        f if f == libc::AF_INET => {
            let sin = addr as *const libc::sockaddr_in;
            let s_addr = u32::from_be((*sin).sin_addr.s_addr);
            let port = u16::from_be((*sin).sin_port);
            let octets = [
                ((s_addr >> 24) & 0xff) as u8,
                ((s_addr >> 16) & 0xff) as u8,
                ((s_addr >> 8) & 0xff) as u8,
                (s_addr & 0xff) as u8,
            ];
            let mut n = 0;
            for (i, oct) in octets.iter().enumerate() {
                if i > 0 && n < out.len() {
                    out[n] = b'.';
                    n += 1;
                }
                n = write_uint(out, n, *oct as u32, 3);
            }
            if n < out.len() {
                out[n] = b':';
                n += 1;
            }
            n = write_uint(out, n, port as u32, 5);
            (f, n)
        }
        _ => (family, 0),
    }
}

#[no_mangle]
pub unsafe extern "C" fn connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    let real = REAL_CONNECT.ptr() as *const ();
    if real.is_null() {
        return libc::connect(sockfd, addr, addrlen);
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::sockaddr,
        libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(sockfd, addr, addrlen);
    let saved_errno = save_errno();
    // #422: emit the SSRF sink event for every egress to a real endpoint
    // (regardless of success), so a fuzz-controlled destination is confirmed and
    // a constant one is suppressed by the cross-execution correlator (GF-433).
    if let Some(_g) = HookGuard::acquire() {
        let mut buf = [0u8; 128];
        let (family, n) = render_sockaddr(addr, addrlen, &mut buf);
        if should_audit_endpoint(family, &buf[..n]) {
            emit_egress(b"connect", &buf[..n]);
        }
    }
    if result < 0 && (saved_errno == libc::ECONNREFUSED || saved_errno == libc::ENOENT) {
        if let Some(_g) = HookGuard::acquire() {
            let mut buf = [0u8; 128];
            let (family, n) = render_sockaddr(addr, addrlen, &mut buf);
            let addr_slice: &'static [u8] = std::mem::transmute(&buf[..n] as &[u8]);
            if should_audit_endpoint(family, addr_slice) {
                let mut b = Builder::new(b"connect");
                b.field_i64(b"f", family as i64);
                b.field_str(b"a", addr_slice);
                b.field_i64(b"r", result as i64);
                b.field_i64(b"n", saved_errno as i64);
                b.emit();
            }
        }
        if crate::fakes::mode::current().is_faking() {
            let mut name_buf = [0u8; 128];
            let (family, name_len) = render_sockaddr(addr, addrlen, &mut name_buf);
            let resource_name: &[u8] = &name_buf[..name_len];
            if crate::policy::should_audit_endpoint(family, resource_name) {
                let (local_fd, peer_fd) =
                    crate::fakes::peer::create_fake_socket_peer(resource_name);
                if local_fd >= 0 {
                    if libc::dup2(local_fd, sockfd) >= 0 {
                        let _ = libc::close(local_fd);
                        let _ = libc::close(peer_fd);
                        *libc::__errno_location() = 0;
                        return 0;
                    }
                    let _ = libc::close(local_fd);
                    let _ = libc::close(peer_fd);
                }
            }
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let real = REAL_GETADDRINFO.ptr() as *const ();
    if real.is_null() {
        return libc::getaddrinfo(node, service, hints, res);
    }
    let real: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::addrinfo,
        *mut *mut libc::addrinfo,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(node, service, hints, res);
    let saved_errno = save_errno();
    // #422: the hostname is the classic SSRF-controllable value — emit the SSRF
    // sink event for every off-localhost resolution (regardless of success) so a
    // fuzz-controlled hostname is confirmed and a constant one is suppressed
    // (GF-433).
    if let Some(_g) = HookGuard::acquire() {
        if !node.is_null() {
            let name = CStr::from_ptr(node).to_bytes();
            if !name.starts_with(b"localhost") && name != b"::1" && !name.starts_with(b"127.") {
                emit_egress(b"getaddrinfo", name);
            }
        }
    }
    // getaddrinfo returns EAI_* codes (not errno); EAI_NONAME = -2.
    if result != 0 {
        if let Some(_g) = HookGuard::acquire() {
            if !node.is_null() {
                let name: &'static [u8] = std::mem::transmute(CStr::from_ptr(node).to_bytes());
                if !name.starts_with(b"localhost") && name != b"::1" && !name.starts_with(b"127.") {
                    let mut b = Builder::new(b"getaddrinfo");
                    b.field_str(b"n", name);
                    b.field_i64(b"r", result as i64);
                    b.emit();
                }
            }
        }
    }
    restore_errno(saved_errno);
    result
}

pub struct Net;

impl crate::sdk::FakeResource for Net {
    fn name(&self) -> &'static str {
        "net"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"connect\0", b"getaddrinfo\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log connect/getaddrinfo failures and substitute fake socket peers"
    }
}
