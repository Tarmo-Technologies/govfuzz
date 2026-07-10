// SPDX-License-Identifier: Apache-2.0

//! Rewrites instrumented-copy line numbers in runtime exception messages back
//! to the developer's original source lines.
//!
//! govfuzz instruments Ada sources by inserting breadcrumb calls, which shifts
//! line numbers. GNAT embeds the *instrumented* file's line in runtime
//! exception messages (`bzip2-decoding.adb:646 index check failed`). The
//! instrumenter writes a `<file>.govfuzz-lines.json` sidecar next to each
//! instrumented unit recording `(instrumented_line, original_line)` anchors and
//! the original source path; this module loads those sidecars and uses them to
//! show the line a developer actually wrote.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

const SIDECAR_SUFFIX: &str = ".govfuzz-lines.json";

#[derive(Debug, Clone, Default)]
pub struct SourceLineMaps {
    /// Instrumented file basename (lowercased) -> (original source path, sorted
    /// `(instrumented_line, original_line)` anchors).
    maps: HashMap<String, (String, Vec<(u32, u32)>)>,
}

#[derive(Deserialize)]
struct SidecarFile {
    source_path: String,
    anchors: Vec<(u32, u32)>,
}

/// One remapped `<file>:<line>` reference resolved to the original source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLocation {
    pub source_path: String,
    pub original_line: u32,
}

impl SourceLineMaps {
    /// Load every `*.govfuzz-lines.json` sidecar in `dir`. Missing dir / bad
    /// sidecars are skipped silently — remapping is best-effort enrichment.
    pub fn load(dir: &Path) -> Self {
        let mut maps = HashMap::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self { maps };
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let Some(basename) = file_name.strip_suffix(SIDECAR_SUFFIX) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(mut sidecar) = serde_json::from_str::<SidecarFile>(&text) else {
                continue;
            };
            sidecar.anchors.sort_unstable_by_key(|&(instr, _)| instr);
            maps.insert(
                basename.to_ascii_lowercase(),
                (sidecar.source_path, sidecar.anchors),
            );
        }
        Self { maps }
    }

    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    fn to_original(anchors: &[(u32, u32)], instr_line: u32) -> u32 {
        match anchors.binary_search_by_key(&instr_line, |&(instr, _)| instr) {
            Ok(idx) => anchors[idx].1,
            Err(0) => instr_line,
            Err(idx) => {
                let (anchor_instr, anchor_orig) = anchors[idx - 1];
                anchor_orig.saturating_add(instr_line.saturating_sub(anchor_instr))
            }
        }
    }

    /// Rewrite every `<file>.adb:<line>` / `.ads:<line>` reference whose unit we
    /// have a map for, returning the rewritten message plus the first resolved
    /// location (for structured `source_file`/`source_line` fields).
    pub fn remap_message(&self, message: &str) -> (String, Option<ResolvedLocation>) {
        if self.maps.is_empty() || message.is_empty() {
            return (message.to_owned(), None);
        }
        let bytes = message.as_bytes();
        let mut out = String::with_capacity(message.len());
        let mut resolved: Option<ResolvedLocation> = None;
        let mut i = 0usize;
        while i < bytes.len() {
            if let Some((basename, line, after)) = self.match_file_line(message, i) {
                if let Some((source_path, anchors)) = self.maps.get(&basename.to_ascii_lowercase())
                {
                    let original = Self::to_original(anchors, line);
                    out.push_str(&basename);
                    out.push(':');
                    out.push_str(&original.to_string());
                    if resolved.is_none() {
                        resolved = Some(ResolvedLocation {
                            source_path: source_path.clone(),
                            original_line: original,
                        });
                    }
                    i = after;
                    continue;
                }
            }
            // Not a remappable reference: copy this CHARACTER through. `message`
            // is valid UTF-8, so copy the whole char at `i` and advance by its
            // UTF-8 length — `bytes[i] as char` would Latin-1-decode each byte and
            // mojibake any multibyte content (a `㎲`/`µ` in an Ada exception
            // message became `ã²`). Non-ASCII bytes never start a file:line match
            // (those begin on ASCII stem bytes), so this only affects passthrough.
            let ch = message[i..]
                .chars()
                .next()
                .expect("byte index i is on a char boundary within valid UTF-8");
            out.push(ch);
            i += ch.len_utf8();
        }
        (out, resolved)
    }

    /// If a `<stem>.ad[bs]:<digits>` reference starts at or spans byte `i` as the
    /// `.` of the extension, return `(basename, instr_line, end_index)`. We probe
    /// only when `i` is the start of the filename stem, so the caller advances
    /// one byte at a time and we test each candidate stem start.
    fn match_file_line(&self, message: &str, i: usize) -> Option<(String, u32, usize)> {
        let bytes = message.as_bytes();
        // The stem must start here and not be a continuation of an identifier
        // run (so `foo.adb` inside `xfoo.adb` is not double-counted).
        if i > 0 && is_stem_byte(bytes[i - 1]) {
            return None;
        }
        let mut j = i;
        while j < bytes.len() && is_stem_byte(bytes[j]) {
            j += 1;
        }
        // Need `.adb:` or `.ads:` immediately after the stem.
        let ext = message.get(j..j + 4)?;
        if !ext.eq_ignore_ascii_case(".adb") && !ext.eq_ignore_ascii_case(".ads") {
            return None;
        }
        if bytes.get(j + 4) != Some(&b':') {
            return None;
        }
        if j == i {
            return None; // empty stem
        }
        let mut k = j + 5;
        let digits_start = k;
        while k < bytes.len() && bytes[k].is_ascii_digit() {
            k += 1;
        }
        if k == digits_start {
            return None; // no line number
        }
        let line: u32 = message.get(digits_start..k)?.parse().ok()?;
        let basename = message.get(i..j + 4)?.to_owned();
        Some((basename, line, k))
    }
}

/// Bytes allowed in a source filename stem (before the `.adb`/`.ads`). Ada unit
/// files use letters, digits, `_`, and `-` (child-unit separator).
fn is_stem_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn maps_with(basename: &str, source_path: &str, anchors: &[(u32, u32)]) -> SourceLineMaps {
        let mut maps = HashMap::new();
        maps.insert(
            basename.to_ascii_lowercase(),
            (source_path.to_owned(), anchors.to_vec()),
        );
        SourceLineMaps { maps }
    }

    #[test]
    fn remaps_a_known_file_line_reference() {
        let maps = maps_with(
            "bzip2-decoding.adb",
            "/src/bzip2-decoding.adb",
            &[(1, 1), (62, 56)],
        );
        let (out, resolved) = maps.remap_message("bzip2-decoding.adb:646 index check failed");
        // 646 falls after anchor (62,56): 56 + (646-62) = 640.
        assert_eq!(out, "bzip2-decoding.adb:640 index check failed");
        let resolved = resolved.unwrap();
        assert_eq!(resolved.source_path, "/src/bzip2-decoding.adb");
        assert_eq!(resolved.original_line, 640);
    }

    #[test]
    fn leaves_unknown_files_untouched() {
        let maps = maps_with("known.adb", "/src/known.adb", &[(1, 1)]);
        let (out, resolved) = maps.remap_message("other.adb:99 boom");
        assert_eq!(out, "other.adb:99 boom");
        assert!(resolved.is_none());
    }

    #[test]
    fn multibyte_message_passes_through_intact() {
        // An Ada exception message with a non-ASCII unit label (`㎲`, 3 bytes)
        // must pass through byte-exact, not Latin-1-mojibake. Regression for the
        // `bytes[i] as char` passthrough. The file:line ref is still remapped.
        let maps = maps_with("timer.adb", "/src/timer.adb", &[(1, 1), (10, 4)]);
        let (out, resolved) = maps.remap_message("timer.adb:12 elapsed ㎲s= 16705");
        assert_eq!(out, "timer.adb:6 elapsed ㎲s= 16705");
        assert!(out.contains('㎲'), "multibyte glyph must survive: {out:?}");
        assert_eq!(resolved.unwrap().original_line, 6);
    }

    #[test]
    fn remaps_embedded_reference_in_instantiation_message() {
        let maps = maps_with(
            "lzma-decoding.adb",
            "/src/lzma-decoding.adb",
            &[(1, 1), (10, 5)],
        );
        let (out, _) = maps.remap_message("raised at lzma-decoding.adb:40 instantiated elsewhere");
        // 40 after (10,5): 5 + (40-10) = 35.
        assert_eq!(out, "raised at lzma-decoding.adb:35 instantiated elsewhere");
    }

    #[test]
    fn does_not_match_filename_substring() {
        let maps = maps_with("a.adb", "/src/a.adb", &[(1, 1)]);
        // `xa.adb:5` must not be treated as `a.adb:5`.
        let (out, resolved) = maps.remap_message("xa.adb:5 nope");
        assert_eq!(out, "xa.adb:5 nope");
        assert!(resolved.is_none());
    }

    #[test]
    fn empty_maps_is_identity() {
        let maps = SourceLineMaps::default();
        let (out, resolved) = maps.remap_message("bzip2-decoding.adb:646 boom");
        assert_eq!(out, "bzip2-decoding.adb:646 boom");
        assert!(resolved.is_none());
    }

    #[test]
    fn load_parses_sidecars_from_dir() {
        let dir = std::env::temp_dir().join(format!("govfuzz-linemap-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(
            dir.join("p.adb.govfuzz-lines.json"),
            r#"{"source_path":"/src/p.adb","anchors":[[1,1],[5,3]]}"#,
        )
        .unwrap();
        let maps = SourceLineMaps::load(&dir);
        assert!(!maps.is_empty());
        let (out, _) = maps.remap_message("p.adb:8 oops");
        // 8 after (5,3): 3 + 3 = 6.
        assert_eq!(out, "p.adb:6 oops");
        let _ = fs::remove_dir_all(&dir);
    }
}
