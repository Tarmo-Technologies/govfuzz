// SPDX-License-Identifier: Apache-2.0

//! Lightweight literal scanner shared by the hand-rolled C-family lanes (C#, JS)
//! to mine an AFL fuzzing dictionary from a target's string and integer literals.
//!
//! The managed/interpreted drivers (SharpFuzz IL coverage, V8 block coverage) carry
//! **no CmpLog/RedQueen channel**, so a single multi-byte comparison gate
//! (`if (s == "OPENSESAME")`) is all-or-nothing for coverage — the engine cannot
//! guess the constant byte-by-byte the way it can for a chain of single-byte
//! compares. Feeding the source's own string/number literals into the dictionary is
//! what lets the engine splice past such gates (the same lever libFuzzer's autodict
//! and Jazzer's value profile provide, and that govfuzz already mines for
//! Rust/Go/Java/Python/Perl).

/// Cap on distinct tokens mined from one source (bounds a huge generated file).
const MAX_TOKENS: usize = 4096;

/// Scan `source` for string and integer literals, returning cleaned, de-duplicated
/// dictionary tokens (unquoted string contents and numeric literal text). Comments
/// are skipped. `backtick` enables JS template literals as a third string quote.
pub fn scan_literal_tokens(source: &str, backtick: bool) -> Vec<String> {
    let b = source.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut i = 0usize;
    let n = b.len();
    while i < n && out.len() < MAX_TOKENS {
        let c = b[i];
        // Line comment.
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        // String literal (", ', and optionally `).
        if c == b'"' || c == b'\'' || (backtick && c == b'`') {
            let quote = c;
            let start = i + 1;
            let mut j = start;
            while j < n {
                if b[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if b[j] == quote {
                    break;
                }
                j += 1;
            }
            if j <= n {
                if let Ok(raw) = std::str::from_utf8(&b[start..j.min(n)]) {
                    if let Some(tok) = clean_string(raw) {
                        push_unique(&mut out, &mut seen, tok);
                    }
                }
            }
            i = j + 1;
            continue;
        }
        // Integer / hex literal, when not part of an identifier.
        if c.is_ascii_digit() && (i == 0 || !is_ident_byte(b[i - 1])) {
            let start = i;
            let mut j = i;
            if b[j] == b'0' && j + 1 < n && (b[j + 1] | 0x20) == b'x' {
                j += 2;
                while j < n && (b[j].is_ascii_hexdigit() || b[j] == b'_') {
                    j += 1;
                }
            } else {
                while j < n && (b[j].is_ascii_digit() || b[j] == b'_') {
                    j += 1;
                }
            }
            // Reject a float / identifier continuation (`1.5`, `0x1p`, `3f`).
            let next = b.get(j).copied().unwrap_or(b' ');
            if next != b'.' && !is_ident_byte(next) {
                if let Ok(txt) = std::str::from_utf8(&b[start..j]) {
                    if let Some(tok) = clean_number(txt) {
                        push_unique(&mut out, &mut seen, tok);
                    }
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn push_unique(out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>, tok: String) {
    if seen.insert(tok.clone()) {
        out.push(tok);
    }
}

/// Unescape the common C-family escapes in a string literal and keep it only if it
/// is a plausible magic value: 1..=64 bytes, at least one non-space, and not a
/// format-only string (a bare `%s`/`{0}` placeholder carries no gate constant).
fn clean_string(raw: &str) -> Option<String> {
    let mut s = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let e = bytes[i + 1];
            s.push(match e {
                b'n' => '\n',
                b't' => '\t',
                b'r' => '\r',
                b'0' => '\0',
                b'\\' => '\\',
                b'"' => '"',
                b'\'' => '\'',
                // \xNN, \uNNNN, etc. — drop the escape body rather than mis-decode.
                b'x' | b'u' | b'U' => {
                    i += 2;
                    continue;
                }
                other => other as char,
            });
            i += 2;
            continue;
        }
        s.push(bytes[i] as char);
        i += 1;
    }
    let trimmed = s.trim();
    if trimmed.is_empty() || s.len() > 64 {
        return None;
    }
    // A pure format placeholder is noise, not a comparison constant.
    if matches!(trimmed, "%s" | "%d" | "%x" | "{}" | "{0}" | "{1}") {
        return None;
    }
    Some(s)
}

/// Keep an integer literal's text (underscores stripped) if it parses; drop the
/// trivial 0/1 which flood the dictionary without gating anything.
fn clean_number(txt: &str) -> Option<String> {
    let t: String = txt.chars().filter(|c| *c != '_').collect();
    let val = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        t.parse::<u64>().ok()?
    };
    if val <= 1 {
        return None;
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_strings_and_numbers() {
        let src = r#"
            // a comment "not mined"
            function f(s) {
              if (s === "OPENSESAME") return 1;
              if (s.length === 4919 || s.charCodeAt(0) === 0x1337) return 2;
              return "%s"; // format placeholder dropped
            }
        "#;
        let toks = scan_literal_tokens(src, true);
        assert!(toks.contains(&"OPENSESAME".to_owned()));
        assert!(toks.contains(&"4919".to_owned()));
        assert!(toks.contains(&"0x1337".to_owned()));
        assert!(!toks.iter().any(|t| t == "not mined")); // comment skipped
        assert!(!toks.iter().any(|t| t == "%s")); // placeholder dropped
    }

    #[test]
    fn skips_trivial_numbers_and_empty_strings() {
        let src = "let a = 0; let b = 1; let c = \"\"; let d = 42;";
        let toks = scan_literal_tokens(src, false);
        assert!(!toks.iter().any(|t| t == "0" || t == "1"));
        assert!(toks.contains(&"42".to_owned()));
    }

    #[test]
    fn number_in_identifier_not_mined() {
        let src = "let sha256 = f(); let x = md5hash;";
        let toks = scan_literal_tokens(src, false);
        assert!(toks.is_empty()); // 256 is part of `sha256`, not a literal
    }

    #[test]
    fn csharp_verbatim_and_escapes() {
        let src = r#"if (name == "Content-Type" && code == 0xDEAD) {}"#;
        let toks = scan_literal_tokens(src, false);
        assert!(toks.contains(&"Content-Type".to_owned()));
        assert!(toks.contains(&"0xDEAD".to_owned()));
    }
}
