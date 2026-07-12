// SPDX-License-Identifier: Apache-2.0

//! COBOL fuzzing lane (M3.4).
//!
//! Strategy: reuse govfuzz's mature C engine. A COBOL subprogram
//! (`PROGRAM-ID` with a `LINKAGE SECTION` driven `PROCEDURE DIVISION USING`) is
//! translated to C with `cobc -C` (GnuCOBOL, GPLv3 -> subprocess only; its
//! `libcob` runtime is LGPLv3 and links into the user's harness like the GNAT
//! runtime). The generated C exposes `int <PROGRAM-ID>(cob_u8_t *p0, ...)`, one
//! pointer per `USING` operand; a generated glue defines `LLVMFuzzerTestOneInput`,
//! which fills the primary `PIC X` buffer from the fuzz bytes, sets a length
//! operand to the byte count, zeroes the rest, and calls the entry. The existing
//! passthrough C fork-server driver + coverage/cmplog runtime then drive it
//! unchanged. Compiling the COBOL under `cobc -fec=all` turns COBOL-semantic
//! violations (out-of-range reference-modification, subscript, SIZE overflow,
//! zero divide) into hard libcob failures the fuzzer catches — a second oracle
//! on top of ASan.
//!
//! This module owns the lightweight source scan (discovery) shared by the
//! discovery pass and the build step; the build step lives in
//! [`crate::auto::cobol_build`].

/// A discovered COBOL program: the callable entry and its `PROCEDURE DIVISION
/// USING` parameter list (resolved to LINKAGE types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CobolProgram {
    /// `PROGRAM-ID` as written (used for the candidate name / display).
    pub program_id: String,
    /// 1-based line of the `PROGRAM-ID` clause.
    pub line: u32,
    /// The `USING` operands, in order, each resolved to its LINKAGE type. Empty
    /// when the program takes no USING arguments (not directly fuzzable).
    pub params: Vec<CobolParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CobolParam {
    pub name: String,
    pub kind: CobolParamKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CobolParamKind {
    /// `PIC X(N)` fixed buffer, or `PIC X ... ANY LENGTH` (`len == None`) — the
    /// fuzzable byte surface.
    Bytes { len: Option<usize> },
    /// A numeric item (`BINARY-*`, `PIC 9(n)`, `COMP`) — a length/count/status.
    /// `width` is the byte width used to encode a length operand.
    Numeric { width: usize },
    /// A group or item we don't model — passed as a zeroed scratch buffer.
    Other,
}

impl CobolProgram {
    /// A program is fuzzable when at least one `USING` operand is a byte buffer.
    pub fn is_fuzzable(&self) -> bool {
        self.params
            .iter()
            .any(|p| matches!(p.kind, CobolParamKind::Bytes { .. }))
    }

    /// Index of the primary (first) byte-buffer operand.
    pub fn primary_buffer_index(&self) -> Option<usize> {
        self.params
            .iter()
            .position(|p| matches!(p.kind, CobolParamKind::Bytes { .. }))
    }
}

/// Normalize a raw source line for scanning: drop the fixed-format sequence area
/// (cols 1-6) and indicator column (col 7) when the line looks fixed-format, drop
/// an inline `*>` free-format comment, uppercase, and collapse whitespace. A `*`
/// or `/` in the indicator column (col 7) marks a full-line comment -> empty.
fn norm_line(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut body = raw;
    if chars.len() > 6 && !raw.starts_with('\t') {
        let indicator = chars[6];
        if indicator == '*' || indicator == '/' || indicator == '$' {
            return String::new();
        }
        let seq: String = chars[..6].iter().collect();
        if seq.chars().all(|c| c == ' ' || c.is_ascii_digit()) {
            body = &raw[raw.char_indices().nth(7).map(|(i, _)| i).unwrap_or(0)..];
        }
    }
    let body = body.split("*>").next().unwrap_or(body);
    let upper = body.to_ascii_uppercase();
    upper.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse the `PIC X(n)` / `PIC XX...` byte length out of a normalized data line.
fn pic_x_len(line: &str) -> Option<usize> {
    let after = line
        .split_once(" PICTURE ")
        .or_else(|| line.split_once(" PIC "))
        .map(|(_, rest)| rest)?;
    let token = after.split_whitespace().next()?;
    if let Some(rest) = token.strip_prefix('X') {
        if let Some(inner) = rest.strip_prefix('(') {
            let num: String = inner.chars().take_while(|c| c.is_ascii_digit()).collect();
            return num.parse().ok();
        }
        let xs = 1 + rest.chars().take_while(|&c| c == 'X').count();
        return Some(xs);
    }
    None
}

/// Classify a normalized LINKAGE `01`-level line into a parameter kind.
fn linkage_kind(line: &str) -> CobolParamKind {
    // ANY LENGTH first: a bare `PIC X ANY LENGTH` would otherwise parse as X(1).
    if line.contains("ANY LENGTH") && (line.contains("PIC X") || line.contains("PICTURE X")) {
        return CobolParamKind::Bytes { len: None };
    }
    if let Some(len) = pic_x_len(line) {
        return CobolParamKind::Bytes { len: Some(len) };
    }
    // Numeric widths (GnuCOBOL BINARY-* and common COMP forms).
    if line.contains("BINARY-DOUBLE") || line.contains("COMP-2") {
        return CobolParamKind::Numeric { width: 8 };
    }
    if line.contains("BINARY-LONG") || line.contains("BINARY-INT") {
        return CobolParamKind::Numeric { width: 4 };
    }
    if line.contains("BINARY-SHORT") {
        return CobolParamKind::Numeric { width: 2 };
    }
    if line.contains("BINARY-CHAR") {
        return CobolParamKind::Numeric { width: 1 };
    }
    if line.contains("PIC 9") || line.contains("PICTURE 9") || line.contains("COMP") {
        return CobolParamKind::Numeric { width: 4 };
    }
    CobolParamKind::Other
}

/// Scan COBOL source for fuzzable subprograms. Handles fixed- and free-format
/// leniently. One [`CobolProgram`] per `PROGRAM-ID`; its `params` are the
/// `USING` operands resolved to their LINKAGE `01`-level types.
pub fn parse_cobol(source: &str) -> Vec<CobolProgram> {
    let mut programs: Vec<CobolProgram> = Vec::new();
    let mut in_linkage = false;
    // name -> kind for the current program's LINKAGE 01 items.
    let mut linkage: Vec<(String, CobolParamKind)> = Vec::new();
    let mut using: Vec<String> = Vec::new();
    let mut cur: Option<usize> = None;

    let finish = |programs: &mut Vec<CobolProgram>,
                  cur: Option<usize>,
                  linkage: &[(String, CobolParamKind)],
                  using: &[String]| {
        if let Some(idx) = cur {
            let params: Vec<CobolParam> = using
                .iter()
                .map(|u| {
                    let kind = linkage
                        .iter()
                        .find(|(n, _)| n == u)
                        .map(|(_, k)| *k)
                        .unwrap_or(CobolParamKind::Other);
                    CobolParam {
                        name: u.clone(),
                        kind,
                    }
                })
                .collect();
            programs[idx].params = params;
        }
    };

    for (i, raw) in source.lines().enumerate() {
        let line = norm_line(raw);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("PROGRAM-ID.") {
            finish(&mut programs, cur, &linkage, &using);
            in_linkage = false;
            linkage.clear();
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
                    params: Vec::new(),
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
        if line.starts_with("PROCEDURE DIVISION") {
            in_linkage = false;
            if let Some((_, rest)) = line.split_once(" USING ") {
                for tok in rest.trim_end_matches('.').split_whitespace() {
                    let name = tok.trim_end_matches('.');
                    if !matches!(name, "BY" | "REFERENCE" | "CONTENT" | "VALUE") {
                        using.push(name.to_owned());
                    }
                }
            }
            continue;
        }
        if in_linkage && (line.starts_with("01 ") || line.starts_with("1 ")) {
            let mut toks = line.split_whitespace();
            let _level = toks.next();
            if let Some(name) = toks.next() {
                linkage.push((name.trim_end_matches('.').to_owned(), linkage_kind(&line)));
            }
        }
    }
    finish(&mut programs, cur, &linkage, &using);
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
           GOBACK.
";

    #[test]
    fn parses_program_id_and_single_buffer() {
        let progs = parse_cobol(SUB);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].program_id, "PARSEIT");
        assert_eq!(progs[0].line, 2);
        assert!(progs[0].is_fuzzable());
        assert_eq!(
            progs[0].params,
            vec![CobolParam {
                name: "BUF".to_owned(),
                kind: CobolParamKind::Bytes { len: Some(32) }
            }]
        );
    }

    #[test]
    fn parses_multi_param_json_parser() {
        // A real-world shape: a variable-length buffer + a length + a status.
        let src = "\
       PROGRAM-ID. JSON-PARSE.
       LINKAGE SECTION.
       01 LK-JSON PIC X ANY LENGTH.
       01 LK-JSON-LEN BINARY-LONG UNSIGNED.
       01 LK-FAILURE BINARY-CHAR UNSIGNED.
       PROCEDURE DIVISION USING LK-JSON LK-JSON-LEN LK-FAILURE.
           GOBACK.
";
        let p = &parse_cobol(src)[0];
        assert!(p.is_fuzzable());
        assert_eq!(p.params.len(), 3);
        assert_eq!(p.params[0].kind, CobolParamKind::Bytes { len: None });
        assert_eq!(p.params[1].kind, CobolParamKind::Numeric { width: 4 });
        assert_eq!(p.params[2].kind, CobolParamKind::Numeric { width: 1 });
        assert_eq!(p.primary_buffer_index(), Some(0));
    }

    #[test]
    fn pic_x_forms_and_kinds() {
        assert_eq!(pic_x_len("01 B PIC X(64)."), Some(64));
        assert_eq!(pic_x_len("01 B PICTURE X(8)."), Some(8));
        assert_eq!(pic_x_len("01 B PIC XXXX."), Some(4));
        assert_eq!(pic_x_len("01 N PIC 9(4)."), None);
        assert_eq!(
            linkage_kind("01 B PIC X(64)."),
            CobolParamKind::Bytes { len: Some(64) }
        );
        assert_eq!(
            linkage_kind("01 J PIC X ANY LENGTH."),
            CobolParamKind::Bytes { len: None }
        );
        assert_eq!(
            linkage_kind("01 N BINARY-LONG UNSIGNED."),
            CobolParamKind::Numeric { width: 4 }
        );
        assert_eq!(linkage_kind("01 G."), CobolParamKind::Other);
    }

    #[test]
    fn skips_fixed_format_comment_and_sequence_area() {
        let src = "000100 PROGRAM-ID. FOO.\n000200* comment PROGRAM-ID. BAR.\n";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].program_id, "FOO");
    }

    #[test]
    fn program_with_no_using_is_not_fuzzable() {
        let src = "       PROGRAM-ID. MAINP.\n       PROCEDURE DIVISION.\n           GOBACK.\n";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 1);
        assert!(!progs[0].is_fuzzable());
    }
}
