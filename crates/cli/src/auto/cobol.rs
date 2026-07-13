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
    /// A NUMERIC `USING` operand is used as a POSITION in the body — a table
    /// subscript (`COMMAND-NODE-PARSER(LK-NODE-INDEX)`, `BLOCK-ENTRY-*(LK-BLOCK)`)
    /// or a reference-modification OFFSET (`LK-JSON(LK-OFFSET:len)`). Such an
    /// operand is a caller-built handle/cursor into a shared structure, not attacker
    /// data: a synthesized garbage/zero position indexes out of bounds (COBOL is
    /// 1-based; a standalone run has no caller-built table/cursor) — a CWE-787 FALSE
    /// POSITIVE. This is the precise signal that a program is an internal parse step
    /// / table method needing caller context, whether or not it is nested. A pure
    /// parser whose numerics are only LENGTHS/STATUS (compared, or the length half
    /// of a ref-mod — set correctly by the harness) is unaffected (`Blocks-Parse`,
    /// `getquery`). Discovery skips a positional-operand program.
    pub positional_operand: bool,
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
    /// A program is fuzzable when it has at least one `USING` byte buffer AND no
    /// numeric operand used as a caller-managed position (see
    /// [`CobolProgram::positional_operand`]) — the latter can't be synthesized
    /// without driving an out-of-bounds false positive.
    pub fn is_fuzzable(&self) -> bool {
        !self.positional_operand
            && self
                .params
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

/// Whether a COBOL source is FREE format (code may begin in column 1) rather than
/// FIXED format (cols 1-6 sequence area, col 7 indicator, Area A at col 8). A
/// division / `PROGRAM-ID` / section header at column 0 can only occur in free
/// format — in fixed format those live in Area A (col 8+). Detecting this per-file
/// is essential: a free-format `    01 LK-JSON` (4-space indent) otherwise has its
/// `01` LEVEL number mistaken for a fixed-format sequence area and stripped, so the
/// LINKAGE buffer is silently lost and the program looks non-fuzzable (CobolCraft
/// `Blocks-Parse`). The check is intentionally strict so a genuinely fixed-format
/// file keeps its sequence-area handling.
fn is_free_format(source: &str) -> bool {
    source.lines().any(|l| {
        l.starts_with(">>SOURCE FORMAT FREE")
            || l.starts_with(">> SOURCE FORMAT FREE")
            || l.starts_with("IDENTIFICATION DIVISION")
            || l.starts_with("ID DIVISION")
            || l.starts_with("ENVIRONMENT DIVISION")
            || l.starts_with("DATA DIVISION")
            || l.starts_with("PROCEDURE DIVISION")
            || l.starts_with("PROGRAM-ID")
    })
}

/// Whether a normalized procedure `body` uses `name` as a POSITION — a table
/// subscript (`IDENT(NAME)` / `IDENT(I, NAME)`) or the OFFSET of a reference
/// modification (`BUF(NAME:len)`). The body is whitespace-collapsed and uppercased.
/// Matched on whole-token boundaries so `LK-BLOCK` does not match `LK-BLOCK-STATE`.
/// The LENGTH half of a ref-mod (`BUF(1:NAME)`) is deliberately NOT matched — a
/// length operand is set correctly by the harness and is safe.
fn body_uses_as_position(body: &str, name: &str) -> bool {
    [
        format!("({name})"),  // sole subscript
        format!("({name},"),  // first of several subscripts
        format!("({name} "),  // first of several (space-separated)
        format!(",{name})"),  // last subscript
        format!(", {name})"), // last subscript (spaced)
        format!(" {name})"),  // last subscript (spaced)
        format!("({name}:"),  // reference-modification offset
    ]
    .iter()
    .any(|pat| body.contains(pat.as_str()))
}

/// Whether any NUMERIC `USING` operand is used as a caller-managed position
/// (subscript or ref-mod offset) in `body` (see
/// [`CobolProgram::positional_operand`]).
fn uses_numeric_operand_as_position(
    body: &str,
    linkage: &[(String, CobolParamKind)],
    using: &[String],
) -> bool {
    using.iter().any(|u| {
        linkage
            .iter()
            .any(|(n, k)| n == u && matches!(k, CobolParamKind::Numeric { .. }))
            && body_uses_as_position(body, u)
    })
}

/// Normalize a raw source line for scanning: drop the fixed-format sequence area
/// (cols 1-6) and indicator column (col 7) when the line looks fixed-format, drop
/// an inline `*>` free-format comment, uppercase, and collapse whitespace. A `*`
/// or `/` in the indicator column (col 7) marks a full-line comment -> empty. When
/// `free_format`, the sequence-area handling is skipped entirely — the whole line
/// is code (only an indicator-column full-line comment is NOT possible in free
/// format; `*>` inline comments are still stripped below).
fn norm_line(raw: &str, free_format: bool) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut body = raw;
    if !free_format && chars.len() > 6 && !raw.starts_with('\t') {
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
    // Normalized PROCEDURE-body text of the current program, used to detect a
    // numeric operand used as a caller-managed position (subscript / ref-mod
    // offset), which makes the program un-fuzzable standalone (a FALSE POSITIVE).
    let mut body = String::new();
    // Detect fixed vs free source format ONCE (see [`is_free_format`]); a
    // free-format line must not have its indentation mistaken for a sequence area.
    let free_format = is_free_format(source);

    let finish = |programs: &mut Vec<CobolProgram>,
                  cur: Option<usize>,
                  linkage: &[(String, CobolParamKind)],
                  using: &[String],
                  body: &str| {
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
            programs[idx].positional_operand =
                uses_numeric_operand_as_position(body, linkage, using);
        }
    };

    for (i, raw) in source.lines().enumerate() {
        let line = norm_line(raw, free_format);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("PROGRAM-ID.") {
            finish(&mut programs, cur, &linkage, &using, &body);
            in_linkage = false;
            linkage.clear();
            using.clear();
            body.clear();
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
                    positional_operand: false,
                });
                cur = Some(programs.len() - 1);
            } else {
                cur = None;
            }
            continue;
        }
        if line.starts_with("END PROGRAM") {
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
            continue;
        }
        // Any remaining line is PROCEDURE-body text; accumulate it (normalized) so a
        // numeric operand used as a table subscript can be detected at `finish`.
        body.push(' ');
        body.push_str(&line);
    }
    finish(&mut programs, cur, &linkage, &using, &body);
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
    fn numeric_operand_used_as_position_is_not_fuzzable() {
        // CobolCraft shapes. A numeric operand used as a table SUBSCRIPT
        // (`TABLE(LK-BLOCK)`, `COMMAND-NODE-PARSER(LK-NODE-INDEX)`) or a ref-mod
        // OFFSET (`LK-JSON(LK-OFFSET:len)`) is a caller-built handle/cursor — a
        // synthesized garbage/zero position indexes out of bounds (CWE-787 FP),
        // whether the program is nested or top-level. A pure parser whose numerics
        // are only LENGTH/STATUS (compared, or the length half of a ref-mod) is kept
        // — including a nested single-buffer helper, which is safely fuzzable.
        let src = "\
IDENTIFICATION DIVISION.
PROGRAM-ID. BLOCKS-PARSE.
LINKAGE SECTION.
    01 LK-JSON PIC X ANY LENGTH.
    01 LK-JSON-LEN BINARY-LONG UNSIGNED.
    01 LK-FAILURE BINARY-CHAR UNSIGNED.
PROCEDURE DIVISION USING LK-JSON LK-JSON-LEN LK-FAILURE.
    IF LK-JSON-LEN > 0
        MOVE 0 TO LK-FAILURE
    END-IF
    GOBACK.
    PROGRAM-ID. BLOCKS-PARSE-BLOCK.
    LINKAGE SECTION.
        01 LK-JSON PIC X ANY LENGTH.
        01 LK-OFFSET BINARY-LONG UNSIGNED.
        01 LK-BLOCK BINARY-LONG UNSIGNED.
    PROCEDURE DIVISION USING LK-JSON LK-OFFSET LK-BLOCK.
        MOVE 0 TO BLOCK-ENTRY-PROPERTY-COUNT(LK-BLOCK)
        MOVE LK-JSON(LK-OFFSET:1) TO WS-CHAR
        GOBACK.
    END PROGRAM BLOCKS-PARSE-BLOCK.
    PROGRAM-ID. GETQUERY.
    LINKAGE SECTION.
        01 THE-QUERY PIC X(1600).
    PROCEDURE DIVISION USING THE-QUERY.
        GOBACK.
    END PROGRAM GETQUERY.
END PROGRAM BLOCKS-PARSE.
PROGRAM-ID. ADDCOMMANDARGUMENT.
LINKAGE SECTION.
    01 LK-NODE-NAME PIC X ANY LENGTH.
    01 LK-NODE-INDEX BINARY-LONG UNSIGNED.
PROCEDURE DIVISION USING LK-NODE-NAME LK-NODE-INDEX.
    MOVE 1 TO COMMAND-NODE-PARSER(LK-NODE-INDEX)
    GOBACK.
END PROGRAM ADDCOMMANDARGUMENT.
";
        let progs = parse_cobol(src);
        let by = |name: &str| progs.iter().find(|p| p.program_id == name).unwrap();

        // Pure top-level parser (numerics are length + status) -> fuzzable.
        assert!(!by("BLOCKS-PARSE").positional_operand);
        assert!(by("BLOCKS-PARSE").is_fuzzable());

        // Nested parse step with a subscript AND a ref-mod cursor -> skipped.
        assert!(by("BLOCKS-PARSE-BLOCK").positional_operand);
        assert!(!by("BLOCKS-PARSE-BLOCK").is_fuzzable());

        // A NESTED single-buffer helper (no positional numeric) is still fuzzable —
        // nesting alone must NOT exclude it (the cow.cbl getquery coverage case).
        assert!(!by("GETQUERY").positional_operand);
        assert!(by("GETQUERY").is_fuzzable());

        // Top-level table method with a subscripted numeric operand -> skipped.
        assert!(by("ADDCOMMANDARGUMENT").positional_operand);
        assert!(!by("ADDCOMMANDARGUMENT").is_fuzzable());
    }

    #[test]
    fn free_format_four_space_indented_linkage_buffer_is_detected() {
        // CobolCraft is FREE format (divisions at column 0) with 4-space-indented
        // data items. `    01 LK-JSON` must NOT have its `01` level mistaken for a
        // fixed-format sequence area and stripped — else the LINKAGE buffer is lost
        // and the top-level parser looks non-fuzzable (regression that forced the
        // nested-subprogram FP).
        let src = "\
IDENTIFICATION DIVISION.
PROGRAM-ID. Blocks-Parse.
DATA DIVISION.
WORKING-STORAGE SECTION.
    01 SCRATCH BINARY-LONG.
LINKAGE SECTION.
    01 LK-JSON                  PIC X ANY LENGTH.
    01 LK-JSON-LEN              BINARY-LONG UNSIGNED.
    01 LK-FAILURE               BINARY-CHAR UNSIGNED.
PROCEDURE DIVISION USING LK-JSON LK-JSON-LEN LK-FAILURE.
    GOBACK.
END PROGRAM Blocks-Parse.
";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 1);
        let p = &progs[0];
        assert_eq!(p.program_id, "BLOCKS-PARSE");
        assert_eq!(
            p.params[0].kind,
            CobolParamKind::Bytes { len: None },
            "free-format 4-space-indented PIC X ANY LENGTH buffer must be detected"
        );
        assert!(
            p.is_fuzzable(),
            "the top-level free-format parser must be a fuzz target"
        );
    }

    #[test]
    fn multiple_single_buffer_programs_are_all_fuzzable() {
        // Several separate single-buffer parsers in one file — none use a numeric
        // operand as a position, so all are fuzz targets.
        let src = "\
       PROGRAM-ID. FIRSTP.
       LINKAGE SECTION.
       01 BUF PIC X(8).
       PROCEDURE DIVISION USING BUF.
           GOBACK.
       PROGRAM-ID. SECONDP.
       LINKAGE SECTION.
       01 BUF PIC X(8).
       PROCEDURE DIVISION USING BUF.
           GOBACK.
";
        let progs = parse_cobol(src);
        assert_eq!(progs.len(), 2);
        assert!(progs.iter().all(|p| !p.positional_operand));
        assert!(progs.iter().all(|p| p.is_fuzzable()));
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
