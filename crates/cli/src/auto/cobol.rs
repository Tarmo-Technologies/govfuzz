// SPDX-License-Identifier: Apache-2.0

//! COBOL fuzzing lane (M3.4).
//!
//! Strategy: reuse govfuzz's mature C engine. A COBOL subprogram
//! (`PROGRAM-ID` with a `LINKAGE SECTION` driven `PROCEDURE DIVISION USING`) is
//! translated to C with `cobc -C` (GnuCOBOL, GPLv3 → subprocess only; its
//! `libcob` runtime is LGPLv3 and links into the user's harness like the GNAT
//! runtime). The generated C exposes `int <PROGRAM-ID>(cob_u8_t *buf)`; a tiny
//! generated glue defines `LLVMFuzzerTestOneInput`, which fills a `PIC X(N)`
//! buffer from the fuzz bytes (space-padded, truncated past N — COBOL semantics)
//! and calls the entry. The existing passthrough C fork-server driver (with its
//! coverage and cmplog runtime) then drives it unchanged. Compiling the COBOL
//! under `cobc -fec=all` turns COBOL-semantic violations (out-of-range
//! reference-modification, subscript, SIZE overflow, zero divide) into hard
//! libcob failures the fuzzer catches — a second oracle on top of ASan.
//!
//! This module owns the lightweight source scan (discovery) shared by the
//! discovery pass and the build step; the build step lives in
//! [`crate::auto::cobol_build`].

/// A discovered COBOL program: the callable entry and its fuzzable input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CobolProgram {
    /// `PROGRAM-ID` as written (used for the candidate name / display).
    pub program_id: String,
    /// 1-based line of the `PROGRAM-ID` clause.
    pub line: u32,
    /// The primary fuzzable `LINKAGE` buffer named first in `PROCEDURE DIVISION
    /// USING`, with its `PIC X(N)` byte length. `None` when the program takes no
    /// USING buffer (not directly fuzzable via LINKAGE).
    pub linkage_buf: Option<LinkageBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkageBuf {
    pub name: String,
    /// Byte length from `PIC X(N)` / `PIC X...X`.
    pub len: usize,
}

/// Normalize a raw source line for scanning: drop the fixed-format sequence area
/// (cols 1-6) and indicator column (col 7) when the line looks fixed-format, drop
/// an inline `*>` free-format comment, uppercase, and collapse whitespace. A `*`
/// or `/` in the indicator column (col 7) marks a full-line comment → empty.
fn norm_line(raw: &str) -> String {
    // A tab-free line ≥7 cols with a non-space indicator col is fixed-format.
    let chars: Vec<char> = raw.chars().collect();
    let mut body = raw;
    if chars.len() > 6 && !raw.starts_with('\t') {
        let indicator = chars[6];
        if indicator == '*' || indicator == '/' || indicator == '$' {
            return String::new(); // comment / directive line
        }
        // Only treat cols 1-6 as a sequence area when they're blank or digits
        // (real fixed-format); otherwise it's free-format and we keep the line.
        let seq: String = chars[..6].iter().collect();
        if seq.chars().all(|c| c == ' ' || c.is_ascii_digit()) {
            body = &raw[raw.char_indices().nth(7).map(|(i, _)| i).unwrap_or(0)..];
        }
    }
    let body = body.split("*>").next().unwrap_or(body);
    let upper = body.to_ascii_uppercase();
    upper.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse the `PIC X(n)` / `PIC XX...` length out of a normalized data line.
fn pic_x_len(line: &str) -> Option<usize> {
    // Find "PIC" or "PICTURE" then the picture string.
    let after = line
        .split_once(" PICTURE ")
        .or_else(|| line.split_once(" PIC "))
        .map(|(_, rest)| rest)?;
    let token = after.split_whitespace().next()?;
    // Only alphanumeric X pictures are treated as raw byte buffers.
    if let Some(rest) = token.strip_prefix('X') {
        if let Some(inner) = rest.strip_prefix('(') {
            let num: String = inner.chars().take_while(|c| c.is_ascii_digit()).collect();
            return num.parse().ok();
        }
        // `XX...` — count leading X's (including the one we stripped).
        let xs = 1 + rest.chars().take_while(|&c| c == 'X').count();
        if xs >= 1 {
            return Some(xs);
        }
    }
    None
}

/// Scan COBOL source for fuzzable subprograms. Handles fixed- and free-format
/// leniently. One [`CobolProgram`] per `PROGRAM-ID`; its `linkage_buf` is the
/// first `USING` operand resolved to a `LINKAGE` `01 ... PIC X(N)` item.
pub fn parse_cobol(source: &str) -> Vec<CobolProgram> {
    let mut programs: Vec<CobolProgram> = Vec::new();
    // Per current program: collected LINKAGE 01 buffers and the USING order.
    let mut in_linkage = false;
    let mut linkage_bufs: Vec<LinkageBuf> = Vec::new();
    let mut using: Vec<String> = Vec::new();
    let mut cur: Option<usize> = None; // index into programs of the current program

    let finish = |programs: &mut Vec<CobolProgram>,
                  cur: Option<usize>,
                  linkage_bufs: &[LinkageBuf],
                  using: &[String]| {
        if let Some(idx) = cur {
            // Primary buffer = first USING operand that resolves to a LINKAGE X buffer;
            // fall back to the first LINKAGE buffer if USING wasn't parsed.
            let buf = using
                .iter()
                .find_map(|u| linkage_bufs.iter().find(|b| &b.name == u))
                .or_else(|| linkage_bufs.first())
                .cloned();
            programs[idx].linkage_buf = buf;
        }
    };

    for (i, raw) in source.lines().enumerate() {
        let line = norm_line(raw);
        if line.is_empty() {
            continue;
        }
        // New program unit.
        if let Some(rest) = line.strip_prefix("PROGRAM-ID.") {
            finish(&mut programs, cur, &linkage_bufs, &using);
            in_linkage = false;
            linkage_bufs.clear();
            using.clear();
            let id = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_owned();
            if !id.is_empty() {
                programs.push(CobolProgram {
                    program_id: id,
                    line: (i + 1) as u32,
                    linkage_buf: None,
                });
                cur = Some(programs.len() - 1);
            } else {
                cur = None;
            }
            continue;
        }
        if line.starts_with("LINKAGE SECTION") {
            in_linkage = true;
            continue;
        }
        if line.starts_with("WORKING-STORAGE SECTION")
            || line.starts_with("LOCAL-STORAGE SECTION")
            || line.starts_with("FILE SECTION")
        {
            in_linkage = false;
            continue;
        }
        // PROCEDURE DIVISION [USING a b c].
        if line.starts_with("PROCEDURE DIVISION") {
            in_linkage = false;
            if let Some((_, rest)) = line.split_once(" USING ") {
                for tok in rest.trim_end_matches('.').split_whitespace() {
                    let name = tok.trim_end_matches('.');
                    if name != "BY" && name != "REFERENCE" && name != "CONTENT" && name != "VALUE" {
                        using.push(name.to_owned());
                    }
                }
            }
            continue;
        }
        // A LINKAGE 01-level X buffer.
        if in_linkage && (line.starts_with("01 ") || line.starts_with("1 ")) {
            let mut toks = line.split_whitespace();
            let _level = toks.next();
            if let Some(name) = toks.next() {
                if let Some(len) = pic_x_len(&line) {
                    linkage_bufs.push(LinkageBuf {
                        name: name.trim_end_matches('.').to_owned(),
                        len,
                    });
                }
            }
        }
    }
    finish(&mut programs, cur, &linkage_bufs, &using);
    programs
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "\
       IDENTIFICATION DIVISION.
       PROGRAM-ID. PARSEIT.
       DATA DIVISION.
       LINKAGE SECTION.
       01 BUF PIC X(32).
       PROCEDURE DIVISION USING BUF.
           IF BUF(1:1) = \"Z\"
               MOVE 1 TO RETURN-CODE
           END-IF.
           GOBACK.
";

    #[test]
    fn parses_program_id_and_linkage_buffer() {
        let progs = parse_cobol(SUB);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].program_id, "PARSEIT");
        assert_eq!(progs[0].line, 2);
        assert_eq!(
            progs[0].linkage_buf,
            Some(LinkageBuf {
                name: "BUF".to_owned(),
                len: 32
            })
        );
    }

    #[test]
    fn pic_x_forms() {
        assert_eq!(pic_x_len("01 B PIC X(64)."), Some(64));
        assert_eq!(pic_x_len("01 B PICTURE X(8)."), Some(8));
        assert_eq!(pic_x_len("01 B PIC XXXX."), Some(4));
        assert_eq!(pic_x_len("01 N PIC 9(4)."), None); // numeric, not a byte buffer
    }

    #[test]
    fn skips_fixed_format_comment_and_sequence_area() {
        // Col 7 '*' is a comment; sequence area digits are ignored.
        let src = "000100 PROGRAM-ID. FOO.\n000200* this is a comment PROGRAM-ID. BAR.\n";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].program_id, "FOO");
    }

    #[test]
    fn using_order_picks_first_resolvable_buffer() {
        let src = "\
       PROGRAM-ID. P.
       LINKAGE SECTION.
       01 A PIC X(4).
       01 B PIC X(8).
       PROCEDURE DIVISION USING B A.
           GOBACK.
";
        let progs = parse_cobol(src);
        assert_eq!(progs[0].linkage_buf.as_ref().unwrap().name, "B");
        assert_eq!(progs[0].linkage_buf.as_ref().unwrap().len, 8);
    }

    #[test]
    fn program_with_no_linkage_has_none() {
        let src = "       PROGRAM-ID. MAINP.\n       PROCEDURE DIVISION.\n           GOBACK.\n";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].linkage_buf, None);
    }
}
