// SPDX-License-Identifier: Apache-2.0

//! CmpLog / RedQueen-style magic-byte extraction scaffold.
//!
//! Tracks issue #294. v0.1 ships the data model + entry-point fn
//! signatures; the real instrumentation pass (LD_PRELOAD-style
//! intercepts of memcmp/strcmp/Ada.Strings.Equals plus an
//! offset-matching splicer) lands behind the `cmplog-runtime`
//! feature in a follow-up.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmpEntry {
    /// Identifier of the comparison site (PC value or AST node id).
    pub site_id: u64,
    pub operand_a: Vec<u8>,
    pub operand_b: Vec<u8>,
    pub kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    /// `memcmp` / `Ada.Strings.Equals` etc. — full-buffer equality.
    BufferEquality,
    /// `strcmp` — NUL-terminated equality.
    CStringEquality,
    /// Integer comparison via `cmp` instruction.
    IntegerCompare,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmpLog {
    pub entries: Vec<CmpEntry>,
}

impl CmpLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: CmpEntry) {
        self.entries.push(entry);
    }

    /// Return every unique operand byte sequence observed across
    /// the recorded cmp entries. Useful for feeding the fuzz
    /// engine's `Dictionary::from_tokens` — every magic-byte
    /// comparison the target performed becomes a candidate
    /// dictionary insertion. Empty operands and exact duplicates
    /// are filtered.
    pub fn dictionary_tokens(&self) -> Vec<Vec<u8>> {
        use std::collections::HashSet;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        for entry in &self.entries {
            for operand in [&entry.operand_a, &entry.operand_b] {
                if operand.is_empty() {
                    continue;
                }
                if seen.insert(operand.clone()) {
                    out.push(operand.clone());
                }
            }
        }
        out
    }

    /// Extract candidate splices: for each entry, if `input`
    /// contains `operand_a` at some offset, yield a candidate
    /// mutation replacing that occurrence with `operand_b` (and
    /// vice versa). Used by the builtin engine's mutator to
    /// learn magic-byte expectations from runtime evidence.
    pub fn splice_candidates(&self, input: &[u8]) -> Vec<SpliceCandidate> {
        let mut out = Vec::new();
        for entry in &self.entries {
            for (src, dst) in [
                (&entry.operand_a, &entry.operand_b),
                (&entry.operand_b, &entry.operand_a),
            ] {
                if src.is_empty() {
                    continue;
                }
                let mut search_from = 0usize;
                while let Some(pos) = find_subslice(&input[search_from..], src) {
                    let absolute = search_from + pos;
                    out.push(SpliceCandidate {
                        site_id: entry.site_id,
                        offset: absolute,
                        replacement: dst.clone(),
                        original_len: src.len(),
                    });
                    search_from = absolute + 1;
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceCandidate {
    pub site_id: u64,
    pub offset: usize,
    pub replacement: Vec<u8>,
    pub original_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CmpLogError {
    #[error("I/O error reading cmplog log: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid hex in cmplog operand")]
    BadHex,
}

/// Ingest a CmpLog from the JSONL audit log produced by the
/// runtrace_shim's `cmplog` hook. Each `{"e":"cmplog","k":...,
/// "a":"<hex>","b":"<hex>"}` event becomes one `CmpEntry`. The shim
/// keys every audit event by `"e"` (see
/// `govfuzz_runtrace_shim::jsonl::Builder`), so cmplog records are
/// matched on `"e" == "cmplog"`. Lines that aren't valid JSON or
/// don't carry the cmplog category are silently skipped.
pub fn ingest_from_jsonl_log(path: &std::path::Path) -> Result<CmpLog, CmpLogError> {
    let bytes = std::fs::read(path)?;
    let mut log = CmpLog::new();
    for (line_no, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(category) = value.get("e").and_then(|v| v.as_str()) else {
            continue;
        };
        if category != "cmplog" {
            continue;
        }
        let kind = match value.get("k").and_then(|v| v.as_str()).unwrap_or("") {
            "strcmp" | "strncmp" => CmpKind::CStringEquality,
            _ => CmpKind::BufferEquality,
        };
        let a_hex = value.get("a").and_then(|v| v.as_str()).unwrap_or("");
        let b_hex = value.get("b").and_then(|v| v.as_str()).unwrap_or("");
        let operand_a = hex_decode(a_hex).ok_or(CmpLogError::BadHex)?;
        let operand_b = hex_decode(b_hex).ok_or(CmpLogError::BadHex)?;
        log.record(CmpEntry {
            site_id: line_no as u64,
            operand_a,
            operand_b,
            kind,
        });
    }
    Ok(log)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmplog_records_entries() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn splice_candidates_finds_operand_in_input() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        let candidates = log.splice_candidates(b"xxabcdyy");
        assert!(!candidates.is_empty());
        let first = &candidates[0];
        assert_eq!(first.offset, 2);
        assert_eq!(first.replacement, b"MAGIC");
        assert_eq!(first.original_len, 4);
    }

    #[test]
    fn splice_candidates_handles_bidirectional() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"in".to_vec(),
            operand_b: b"out".to_vec(),
            kind: CmpKind::CStringEquality,
        });
        let candidates = log.splice_candidates(b"out-of-bounds");
        assert!(candidates.iter().any(|c| c.replacement == b"in"));
    }

    #[test]
    fn ingest_from_jsonl_log_parses_cmplog_events() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cmplog-ingest-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        // Real audit-log format: the runtrace shim emits every event (incl.
        // cmplog) keyed by "e" (see govfuzz_runtrace_shim::jsonl::Builder),
        // NOT "c". Ingest must match what the shim actually produces.
        let jsonl = b"\
{\"e\":\"getenv\",\"n\":\"FOO\"}\n\
{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"6162\",\"b\":\"4d41\"}\n\
not-json-just-noise\n\
{\"e\":\"cmplog\",\"k\":\"strcmp\",\"a\":\"68656c6c6f\",\"b\":\"776f726c64\"}\n\
";
        std::fs::write(&log_path, jsonl).unwrap();
        let log = ingest_from_jsonl_log(&log_path).unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].operand_a, b"ab");
        assert_eq!(log.entries[0].operand_b, b"MA");
        assert_eq!(log.entries[0].kind, CmpKind::BufferEquality);
        assert_eq!(log.entries[1].operand_a, b"hello");
        assert_eq!(log.entries[1].operand_b, b"world");
        assert_eq!(log.entries[1].kind, CmpKind::CStringEquality);
    }

    #[test]
    fn dictionary_tokens_deduplicates_operands() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"MAGIC".to_vec(),
            operand_b: b"hello".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        log.record(CmpEntry {
            site_id: 2,
            operand_a: b"MAGIC".to_vec(), // duplicate
            operand_b: b"world".to_vec(),
            kind: CmpKind::CStringEquality,
        });
        log.record(CmpEntry {
            site_id: 3,
            operand_a: b"".to_vec(), // empty skipped
            operand_b: b"hello".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        let tokens = log.dictionary_tokens();
        assert_eq!(tokens.len(), 3); // MAGIC, hello, world
        assert!(tokens.iter().any(|t| t.as_slice() == b"MAGIC"));
        assert!(tokens.iter().any(|t| t.as_slice() == b"hello"));
        assert!(tokens.iter().any(|t| t.as_slice() == b"world"));
        assert!(!tokens.iter().any(|t| t.is_empty()));
    }

    #[test]
    fn ingest_skips_unrelated_categories() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cmplog-other-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        std::fs::write(
            &log_path,
            b"{\"c\":\"getenv\",\"n\":\"X\"}\n{\"c\":\"connect\",\"e\":\"x\"}\n",
        )
        .unwrap();
        let log = ingest_from_jsonl_log(&log_path).unwrap();
        assert!(log.entries.is_empty());
    }
}
