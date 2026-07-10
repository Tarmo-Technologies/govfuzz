// SPDX-License-Identifier: Apache-2.0

//! Cross-fuzzer corpus bridge. Reads flat directories of input
//! files from AFL/libFuzzer/Honggfuzz/govfuzz, deduplicates by
//! SHA-256 of content, and writes them out under the target format's
//! naming convention.
//!
//! All four supported formats are flat directories of raw input
//! bytes — only the file-naming convention differs. Sidecar metadata
//! (AFL plot data, libFuzzer stats, etc.) is ignored.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Supported corpus directory formats. See module docs for the
/// per-format naming convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Govfuzz,
    Libfuzzer,
    Afl,
    Honggfuzz,
    /// Source directory whose format could not be auto-detected.
    /// Treated as a flat directory of raw input bytes — every
    /// regular file is imported regardless of name.
    Unknown,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Govfuzz => "govfuzz",
            Format::Libfuzzer => "libfuzzer",
            Format::Afl => "afl",
            Format::Honggfuzz => "honggfuzz",
            Format::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "govfuzz" => Some(Format::Govfuzz),
            "libfuzzer" => Some(Format::Libfuzzer),
            "afl" => Some(Format::Afl),
            "honggfuzz" => Some(Format::Honggfuzz),
            "auto" | "unknown" => Some(Format::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub unique: usize,
    pub duplicates: usize,
    pub source_format: Format,
    pub target_format: Format,
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("source directory does not exist or is not a directory: {0}")]
    SourceMissing(PathBuf),
}

/// Inspect filenames in `dir` and guess the source format. Only the
/// names of top-level regular files are consulted; contents are not
/// read.
pub fn detect_format(dir: &Path) -> Result<Format, BridgeError> {
    if !dir.is_dir() {
        return Err(BridgeError::SourceMissing(dir.to_path_buf()));
    }
    let mut afl = 0usize;
    let mut libfuzzer = 0usize;
    let mut honggfuzz = 0usize;
    let mut govfuzz = 0usize;
    let mut total = 0usize;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        total += 1;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("id:") {
            afl += 1;
        } else if name.ends_with(".fuzz") {
            honggfuzz += 1;
        } else if name.ends_with(".bin") {
            govfuzz += 1;
        } else if is_sha1_hex(name) {
            libfuzzer += 1;
        }
    }
    if total == 0 {
        return Ok(Format::Unknown);
    }
    // Pick the format with strict majority (>= 50%); fall back to
    // Unknown if no single format wins.
    let half = total / 2;
    if afl > half {
        Ok(Format::Afl)
    } else if libfuzzer > half {
        Ok(Format::Libfuzzer)
    } else if honggfuzz > half {
        Ok(Format::Honggfuzz)
    } else if govfuzz > half {
        Ok(Format::Govfuzz)
    } else {
        Ok(Format::Unknown)
    }
}

fn is_sha1_hex(s: &str) -> bool {
    s.len() == 40
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Copy raw inputs from `src` (flat dir) into `dst` using
/// govfuzz naming, deduped by content hash. `source_format` is
/// recorded in the summary but does not change the import logic
/// (all formats are flat dirs of bytes).
pub fn import_dir(
    src: &Path,
    dst: &Path,
    source_format: Format,
) -> Result<ImportSummary, BridgeError> {
    copy_with_dedup(src, dst, source_format, Format::Govfuzz)
}

/// Copy raw inputs from `src` into `dst` using `target_format` for
/// the output file names, deduped by content hash.
pub fn export_dir(
    src: &Path,
    dst: &Path,
    target_format: Format,
) -> Result<ImportSummary, BridgeError> {
    let source_format = detect_format(src)?;
    copy_with_dedup(src, dst, source_format, target_format)
}

/// Merge N input dirs into `dst` deduped by content hash. The
/// `source_format` field in the summary reflects what was detected
/// in the first input dir; for mixed merges callers should inspect
/// per-dir detection separately if it matters.
pub fn merge_dirs(srcs: &[PathBuf], dst: &Path) -> Result<ImportSummary, BridgeError> {
    fs::create_dir_all(dst)?;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut unique = 0usize;
    let mut duplicates = 0usize;
    let mut first_format = Format::Unknown;
    let mut ord = next_afl_ordinal(dst, Format::Govfuzz);
    for (i, src) in srcs.iter().enumerate() {
        let detected = detect_format(src)?;
        if i == 0 {
            first_format = detected;
        }
        for (bytes, hash) in iter_files(src)? {
            if !seen.insert(hash) {
                duplicates += 1;
                continue;
            }
            let name = output_name(Format::Govfuzz, &hash, &mut ord);
            fs::write(dst.join(name), &bytes)?;
            unique += 1;
        }
    }
    Ok(ImportSummary {
        unique,
        duplicates,
        source_format: first_format,
        target_format: Format::Govfuzz,
    })
}

fn copy_with_dedup(
    src: &Path,
    dst: &Path,
    source_format: Format,
    target_format: Format,
) -> Result<ImportSummary, BridgeError> {
    if !src.is_dir() {
        return Err(BridgeError::SourceMissing(src.to_path_buf()));
    }
    fs::create_dir_all(dst)?;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut unique = 0usize;
    let mut duplicates = 0usize;
    let mut ord = next_afl_ordinal(dst, target_format);
    for (bytes, hash) in iter_files(src)? {
        if !seen.insert(hash) {
            duplicates += 1;
            continue;
        }
        let name = output_name(target_format, &hash, &mut ord);
        fs::write(dst.join(name), &bytes)?;
        unique += 1;
    }
    Ok(ImportSummary {
        unique,
        duplicates,
        source_format,
        target_format,
    })
}

type FileWithHash = (Vec<u8>, [u8; 32]);

fn iter_files(dir: &Path) -> Result<Vec<FileWithHash>, BridgeError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        out.push((bytes, hash));
    }
    // Deterministic order — sort by hash so output naming is stable
    // for the AFL ordinal allocator across runs.
    out.sort_by_key(|(_, hash)| *hash);
    Ok(out)
}

fn output_name(format: Format, hash: &[u8; 32], next_afl_ord: &mut u32) -> String {
    let hex = hex_lower(hash);
    match format {
        Format::Govfuzz | Format::Unknown => format!("{}.bin", &hex[..16]),
        Format::Honggfuzz => format!("{}.fuzz", &hex[..16]),
        Format::Libfuzzer => {
            // libFuzzer corpus convention is SHA-1 of contents. We
            // use the first 40 hex chars of SHA-256 — semantically
            // unique, libFuzzer doesn't actually check the hash.
            hex[..40].to_owned()
        }
        Format::Afl => {
            let n = *next_afl_ord;
            *next_afl_ord = n.saturating_add(1);
            format!("id:{n:06},sig:{}", &hex[..16])
        }
    }
}

fn next_afl_ordinal(dst: &Path, target_format: Format) -> u32 {
    if !matches!(target_format, Format::Afl) {
        return 0;
    }
    let Ok(entries) = fs::read_dir(dst) else {
        return 0;
    };
    let mut max = -1i64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(rest) = name.strip_prefix("id:") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<i64>() {
                if n > max {
                    max = n;
                }
            }
        }
    }
    (max + 1).max(0) as u32
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-bridge-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str, contents: &[u8]) {
        fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn detect_format_recognises_afl_queue() {
        let dir = temp_dir("detect-afl");
        write_file(&dir, "id:000000,orig:seed1", b"input-a");
        write_file(&dir, "id:000001,orig:seed2", b"input-b");
        assert_eq!(detect_format(&dir).unwrap(), Format::Afl);
    }

    #[test]
    fn detect_format_recognises_libfuzzer_sha1_names() {
        let dir = temp_dir("detect-libfuzzer");
        write_file(&dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b"a");
        write_file(&dir, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", b"b");
        assert_eq!(detect_format(&dir).unwrap(), Format::Libfuzzer);
    }

    #[test]
    fn detect_format_recognises_honggfuzz_fuzz_suffix() {
        let dir = temp_dir("detect-honggfuzz");
        write_file(&dir, "seed1.fuzz", b"a");
        write_file(&dir, "seed2.fuzz", b"b");
        assert_eq!(detect_format(&dir).unwrap(), Format::Honggfuzz);
    }

    #[test]
    fn detect_format_returns_unknown_for_arbitrary_names() {
        let dir = temp_dir("detect-unknown");
        write_file(&dir, "alpha", b"a");
        write_file(&dir, "beta", b"b");
        assert_eq!(detect_format(&dir).unwrap(), Format::Unknown);
    }

    #[test]
    fn import_dir_copies_unique_files() {
        let src = temp_dir("import-unique-src");
        let dst = temp_dir("import-unique-dst");
        write_file(&src, "id:000000,orig:a", b"aaa");
        write_file(&src, "id:000001,orig:b", b"bbb");
        write_file(&src, "id:000002,orig:c", b"ccc");
        let summary = import_dir(&src, &dst, Format::Afl).unwrap();
        assert_eq!(summary.unique, 3);
        assert_eq!(summary.duplicates, 0);
        assert_eq!(summary.source_format, Format::Afl);
        assert_eq!(summary.target_format, Format::Govfuzz);
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 3);
    }

    #[test]
    fn import_dir_deduplicates_by_content_hash() {
        let src = temp_dir("import-dedup-src");
        let dst = temp_dir("import-dedup-dst");
        write_file(&src, "id:000000,orig:a", b"aaa");
        write_file(&src, "id:000001,orig:b", b"aaa"); // duplicate content
        write_file(&src, "id:000002,orig:c", b"ccc");
        let summary = import_dir(&src, &dst, Format::Afl).unwrap();
        assert_eq!(summary.unique, 2);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 2);
    }

    #[test]
    fn export_dir_writes_libfuzzer_40_char_hex_names() {
        let src = temp_dir("export-libfuzzer-src");
        let dst = temp_dir("export-libfuzzer-dst");
        write_file(&src, "input1.bin", b"aaa");
        write_file(&src, "input2.bin", b"bbb");
        let summary = export_dir(&src, &dst, Format::Libfuzzer).unwrap();
        assert_eq!(summary.unique, 2);
        for entry in fs::read_dir(&dst).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert_eq!(name.len(), 40, "libfuzzer name should be 40 hex chars");
            assert!(name.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn export_dir_writes_afl_sequential_ordinals() {
        let src = temp_dir("export-afl-src");
        let dst = temp_dir("export-afl-dst");
        write_file(&src, "input1.bin", b"aaa");
        write_file(&src, "input2.bin", b"bbb");
        write_file(&src, "input3.bin", b"ccc");
        export_dir(&src, &dst, Format::Afl).unwrap();
        let mut ordinals: Vec<u32> = Vec::new();
        for entry in fs::read_dir(&dst).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(name.starts_with("id:"));
            let digits: String = name[3..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            ordinals.push(digits.parse().unwrap());
        }
        ordinals.sort();
        assert_eq!(ordinals, vec![0, 1, 2]);
    }

    #[test]
    fn merge_dirs_deduplicates_across_inputs() {
        let src1 = temp_dir("merge-src1");
        let src2 = temp_dir("merge-src2");
        let dst = temp_dir("merge-dst");
        write_file(&src1, "input1.bin", b"aaa");
        write_file(&src1, "input2.bin", b"bbb");
        write_file(&src2, "input3.bin", b"aaa"); // duplicate of src1
        write_file(&src2, "input4.bin", b"ccc");
        let summary = merge_dirs(&[src1, src2], &dst).unwrap();
        assert_eq!(summary.unique, 3);
        assert_eq!(summary.duplicates, 1);
    }

    #[test]
    fn merge_dirs_reports_first_input_format() {
        let src1 = temp_dir("merge-fmt-src1");
        let src2 = temp_dir("merge-fmt-src2");
        let dst = temp_dir("merge-fmt-dst");
        write_file(&src1, "id:000000,orig:a", b"a");
        write_file(&src2, "input1.bin", b"b");
        let summary = merge_dirs(&[src1, src2], &dst).unwrap();
        assert_eq!(summary.source_format, Format::Afl);
        assert_eq!(summary.target_format, Format::Govfuzz);
    }
}
