// SPDX-License-Identifier: Apache-2.0

//! Build a socketpair, pre-fill the peer end with fake bytes for
//! the target to read, and return the local end's fd. The connect
//! hook calls this on ECONNREFUSED in faking mode and uses dup2()
//! to swap the target's existing socket fd in place.

use crate::fakes::data::fill_bytes;

const FAKE_PEER_CAPACITY: usize = 16 * 1024;

/// Returns (local_fd, peer_fd_to_close_after_dup2). Caller dup2()s
/// `local_fd` over the target's socket fd, then closes both
/// returned fds. The peer end has already been pre-filled with up
/// to FAKE_PEER_CAPACITY bytes; subsequent read()s by the target
/// see those bytes, then EOF.
///
/// Returns (-1, -1) on failure.
///
/// # Safety
///
/// Invokes libc syscalls directly (socketpair, write, shutdown).
/// The caller is responsible for closing both returned fds when
/// they're no longer needed.
pub unsafe fn create_fake_socket_peer(resource_name: &[u8]) -> (i32, i32) {
    let mut sv = [0i32; 2];
    let rc = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
    if rc < 0 {
        return (-1, -1);
    }
    let (local, peer) = (sv[0], sv[1]);
    // Pre-fill the peer with bytes for the target to read on `local`.
    let mut buf = [0u8; FAKE_PEER_CAPACITY];
    let n = fill_bytes(resource_name, &mut buf);
    if n > 0 {
        let mut written = 0;
        while written < n {
            let w = libc::write(
                peer,
                buf[written..n].as_ptr() as *const libc::c_void,
                n - written,
            );
            if w <= 0 {
                break;
            }
            written += w as usize;
        }
    }
    // Half-close the peer side so the target sees EOF after the
    // pre-filled bytes are exhausted. Shut down write only — the
    // local side can still write to the peer (which we discard).
    let _ = libc::shutdown(peer, libc::SHUT_WR);
    (local, peer)
}
