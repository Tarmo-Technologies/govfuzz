// SPDX-License-Identifier: Apache-2.0
//! Robust source reading for untrusted legacy trees.
//!
//! Government legacy Ada/C/C++ is frequently stored in Latin-1 / Windows-1252
//! (accented author names and copyright glyphs in header comments, degree signs
//! in radar/units documentation) rather than UTF-8. `fs::read_to_string`
//! rejects those bytes with `ErrorKind::InvalidData`, which previously caused
//! whole files — including real fuzzable subprograms — to be silently dropped
//! from discovery.
//!
//! We instead decode UTF-8 when the bytes are valid and otherwise fall back to
//! ISO-8859-1 (Latin-1), which maps every one of the 256 byte values to a
//! Unicode code point and therefore can never fail. ASCII (and thus all code
//! structure, newlines, and identifiers) is preserved byte-for-byte; high bytes
//! only ever appear inside comments and string literals, so the structural
//! parse of subprograms is unaffected. This keeps the decode dependency-free,
//! which the strict-permissive license policy requires.

use std::path::Path;

/// Default ceiling for one source file parsed by the auto/discovery/build-recovery
/// pipeline. Tree-sitter and the structural parsers can require several times the
/// input size while a parse is live, so accepting an arbitrarily large generated
/// translation unit lets one file OOM an otherwise bounded whole-tree run.
///
/// The fallback is 64 MiB on platforms where available memory cannot be queried.
/// On Linux the normal default is 1/32 of currently available host/cgroup memory,
/// clamped to 64 MiB..1 GiB. Build recovery routinely encounters amalgamated
/// C/C++ sources, so a larger machine should not inherit a workstation-sized
/// limit. `GOVFUZZ_MAX_SOURCE_FILE_BYTES` always overrides the derived value.
const FALLBACK_MAX_SOURCE_FILE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn max_source_file_bytes() -> u64 {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_SOURCE_FILE_BYTES",
        32,
        64 * crate::resource_limits::MIB,
        FALLBACK_MAX_SOURCE_FILE_BYTES,
        1024 * crate::resource_limits::MIB,
    ) as u64
}

/// Read a source file as text, transcoding non-UTF-8 bytes from Latin-1 rather
/// than failing. Only genuine I/O errors (missing file, permission denied)
/// propagate; an encoding mismatch never does.
pub(crate) fn read_source_text(path: &Path) -> std::io::Result<String> {
    read_source_text_capped(path, max_source_file_bytes())
}

fn read_source_text_capped(path: &Path, limit: u64) -> std::io::Result<String> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "source file is {len} bytes, above the {limit}-byte safety limit; \
                 raise GOVFUZZ_MAX_SOURCE_FILE_BYTES to parse it"
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(len.min(limit).min(64 * 1024) as usize);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "source file grew above the {limit}-byte safety limit while being read; \
                 raise GOVFUZZ_MAX_SOURCE_FILE_BYTES to parse it"
            ),
        ));
    }
    Ok(decode_source_bytes(bytes))
}

/// Decode raw source bytes to a `String`: UTF-8 when valid, otherwise Latin-1.
pub(crate) fn decode_source_bytes(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        // Latin-1: every byte 0x00..=0xFF is the matching Unicode scalar value.
        Err(err) => err.into_bytes().iter().map(|&b| b as char).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn valid_utf8_passes_through_unchanged() {
        let text = "procedure Décodé is begin null; end;\n";
        let decoded = decode_source_bytes(text.as_bytes().to_vec());
        assert_eq!(decoded, text);
    }

    #[test]
    fn latin1_high_bytes_decode_without_dropping_content() {
        // 0xE9 is 'é' in Latin-1 and an invalid lone byte in UTF-8.
        let mut bytes = b"-- Auteur: Fr".to_vec();
        bytes.push(0xE9); // é
        bytes.extend_from_slice(b"d\nprocedure Track is begin null; end Track;\n");
        let decoded = decode_source_bytes(bytes);
        // ASCII code structure is preserved verbatim...
        assert!(decoded.contains("procedure Track is begin null; end Track;"));
        // ...and the high byte became the expected Latin-1 code point, not a drop.
        assert!(decoded.contains('é'));
        // Newlines (and therefore line numbering) survive the transcode.
        assert_eq!(decoded.lines().count(), 2);
    }

    #[test]
    fn read_source_text_transcodes_latin1_file() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("govfuzz-latin1-{nonce}.ads"));
        let mut bytes = b"-- Copyright ".to_vec();
        bytes.push(0xA9); // (c) sign in Latin-1
        bytes.extend_from_slice(b"\nprocedure Demod is begin null; end Demod;\n");
        std::fs::write(&path, &bytes).unwrap();
        let text = read_source_text(&path).expect("latin-1 file should decode, not error");
        assert!(text.contains("procedure Demod"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_source_text_propagates_missing_file() {
        let path = std::env::temp_dir().join("govfuzz-does-not-exist-zzz.ads");
        assert!(read_source_text(&path).is_err());
    }

    #[test]
    fn oversized_source_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("generated.c");
        std::fs::write(&path, b"12345").unwrap();
        let error = read_source_text_capped(&path, 4).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("5 bytes"));
    }
}
