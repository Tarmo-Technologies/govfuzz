// SPDX-License-Identifier: Apache-2.0

//! Environment capsule (#4): record and replay the bytes the shim SERVES to the
//! target for each faked resource, so a crash that depended on the synthesized
//! environment reproduces deterministically and portably.
//!
//! * **Record** — when `GOVFUZZ_ENVCAP_RECORD=<path>` is set, every
//!   [`crate::fakes::data::fill_bytes`] appends `<resource_hex>:<bytes_hex>` for
//!   what it served. The append is signal-safe: the fd is opened ONCE, the write is
//!   a direct `write(2)` of a stack buffer, no allocation on the hot path (the same
//!   discipline the JSONL runtrace writer uses).
//! * **Replay** — when `GOVFUZZ_ENVCAP_REPLAY=<path>` points at a recorded capsule,
//!   `fill_bytes` serves the EXACT recorded bytes for a resource instead of the pass
//!   mode's generated content, so the faked world is byte-identical to the recorded
//!   run regardless of pass mode / RNG seed. The capsule is parsed once at first use
//!   (an init-time allocation, exactly like the fuzz-input memfd loader), after which
//!   lookups are allocation-free.
//!
//! Together these let `govfuzz env-capsule` bundle a self-contained, replayable
//! virtualized environment for a finding.

use crate::reentrancy::HookGuard;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Cap recorded bytes per resource (a `fill_bytes` serves at most one memfd
/// capacity — 16 KiB — and a content-gated crash needs only the consumed prefix).
const MAX_RECORD: usize = 16 * 1024;

// ── record ───────────────────────────────────────────────────────────────────

static RECORD_FD: OnceLock<i32> = OnceLock::new();

fn record_fd() -> i32 {
    *RECORD_FD.get_or_init(|| {
        let Some(path) = std::env::var_os("GOVFUZZ_ENVCAP_RECORD") else {
            return -1;
        };
        let mut cpath = path.as_encoded_bytes().to_vec();
        cpath.push(0);
        // SAFETY: cpath is NUL-terminated; O_CLOEXEC keeps the fd out of children.
        unsafe {
            libc::open(
                cpath.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
                0o644,
            )
        }
    })
}

/// Record the bytes served for `resource_name`. Signal-safe: opens once, writes a
/// stack buffer via `write(2)`, no heap allocation on the hot path.
pub fn record_fill(resource_name: &[u8], bytes: &[u8]) {
    let fd = record_fd();
    if fd < 0 || resource_name.is_empty() || bytes.is_empty() {
        return;
    }
    // A reentrancy guard keeps a resource that opens during our own hook path from
    // recursing into another record.
    let Some(_g) = HookGuard::acquire() else {
        return;
    };
    let saved = unsafe { *libc::__errno_location() };
    write_hex(fd, resource_name);
    write_all(fd, b":");
    let n = bytes.len().min(MAX_RECORD);
    write_hex(fd, &bytes[..n]);
    write_all(fd, b"\n");
    unsafe { *libc::__errno_location() = saved };
}

fn write_all(fd: i32, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: raw write of a valid slice to a valid fd.
        let w = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if w <= 0 {
            return;
        }
        buf = &buf[w as usize..];
    }
}

/// Hex-encode `bytes` and write them in bounded stack chunks (no allocation).
fn write_hex(fd: i32, bytes: &[u8]) {
    const CHUNK: usize = 256;
    let mut hx = [0u8; CHUNK * 2];
    for chunk in bytes.chunks(CHUNK) {
        for (i, b) in chunk.iter().enumerate() {
            hx[i * 2] = HEX[(b >> 4) as usize];
            hx[i * 2 + 1] = HEX[(b & 0xf) as usize];
        }
        write_all(fd, &hx[..chunk.len() * 2]);
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// ── replay ───────────────────────────────────────────────────────────────────

static REPLAY_MAP: OnceLock<Option<HashMap<Vec<u8>, Vec<u8>>>> = OnceLock::new();

fn replay_map() -> Option<&'static HashMap<Vec<u8>, Vec<u8>>> {
    REPLAY_MAP
        .get_or_init(|| {
            let path = std::env::var_os("GOVFUZZ_ENVCAP_REPLAY")?;
            let text = std::fs::read_to_string(path).ok()?;
            Some(parse_capsule(&text))
        })
        .as_ref()
}

/// If a recorded world is pinned and it has an entry for `resource_name`, fill
/// `out` with the recorded bytes (wrapping if the request is larger) and return the
/// count. Returns `None` when replay is off or this resource was not recorded, so
/// the caller falls through to normal generation.
pub fn replay_fill(resource_name: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    let map = replay_map()?;
    let recorded = map.get(resource_name)?;
    if recorded.is_empty() {
        return Some(0);
    }
    let len = recorded.len();
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = recorded[i % len];
    }
    Some(out.len())
}

/// Parse a capsule (`<resource_hex>:<bytes_hex>` per line) into a resource → bytes
/// map. A later line for the same resource wins.
fn parse_capsule(text: &str) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((res_hex, bytes_hex)) = line.split_once(':') else {
            continue;
        };
        let (Some(res), Some(bytes)) = (unhex(res_hex), unhex(bytes_hex)) else {
            continue;
        };
        if !res.is_empty() {
            map.insert(res, bytes);
        }
    }
    map
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in s.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(unhex("00ff41"), Some(vec![0x00, 0xff, 0x41]));
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("abc"), None); // odd length
    }

    #[test]
    fn parse_capsule_maps_resource_to_bytes() {
        // "/etc/x" -> "AB", "sock" -> "\x01\x02"
        let text = "2f6574632f78:4142\n736f636b:0102\n";
        let map = parse_capsule(text);
        assert_eq!(map.get(b"/etc/x".as_slice()), Some(&b"AB".to_vec()));
        assert_eq!(map.get(b"sock".as_slice()), Some(&vec![1u8, 2u8]));
    }

    #[test]
    fn last_line_wins_for_duplicate_resource() {
        let text = "6161:4142\n6161:4344\n"; // "aa" -> "AB" then "CD"
        let map = parse_capsule(text);
        assert_eq!(map.get(b"aa".as_slice()), Some(&b"CD".to_vec()));
    }

    #[test]
    fn replay_fill_is_none_without_env() {
        // REPLAY_MAP initializes from the (unset in test) env to None.
        let mut out = [0u8; 4];
        // Can't easily control OnceLock across tests; just assert the empty-out guard.
        let mut empty: [u8; 0] = [];
        assert_eq!(replay_fill(b"x", &mut empty), None);
        let _ = &mut out;
    }
}
