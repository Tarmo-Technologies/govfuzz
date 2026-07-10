// SPDX-License-Identifier: Apache-2.0
//
// Fixture library for the M1.1 Rust discovery lane. Exercises every ranking
// signal: byte-channel parse entries (high rank), a getter (penalized), a
// private helper (skipped), and an `unsafe`/raw-pointer surface (promoted).

/// High rank: parser name + `&[u8]` byte channel -> AttackerReachable.
pub fn parse_header(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// High rank: `decode`/`&str` byte channel.
pub fn decode_record(text: &str) -> usize {
    text.split(',').count()
}

/// High rank: an `unsafe` raw-pointer surface (deepSURF severity thesis).
///
/// # Safety
/// `ptr` must point to at least `len` readable bytes.
pub unsafe fn parse_raw(ptr: *const u8, len: usize) -> u8 {
    if len == 0 {
        return 0;
    }
    *ptr
}

/// Low rank: a getter (no attacker byte channel, getter-name penalty).
pub fn get_version() -> u32 {
    1
}

/// Skipped: module-private, not externally callable.
fn secret_helper(data: &[u8]) -> bool {
    data.first() == Some(&0xFF)
}

/// A reader type with an associated parse fn and a `&self` method.
pub struct Reader;

impl Reader {
    /// Associated fn (no `self`) -> is_static; parser name + byte channel.
    pub fn from_bytes(data: &[u8]) -> Reader {
        let _ = secret_helper(data);
        Reader
    }

    /// `&self` method -> not static; getter penalty.
    pub fn get_len(&self) -> usize {
        0
    }
}
