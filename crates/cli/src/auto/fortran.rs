// SPDX-License-Identifier: Apache-2.0

//! Fortran fuzzing lane (M3.5).
//!
//! Strategy (like the COBOL lane): reuse govfuzz's C engine. A Fortran
//! `subroutine`/`function` with a `character` (byte-buffer) argument is the
//! fuzzable unit. It is compiled with `gfortran -fsanitize=address
//! -fsanitize-coverage=trace-pc,trace-cmp` (ASan catches memory corruption
//! directly with the exact `.f90:line`; trace-pc/trace-cmp feed the govfuzz
//! driver's coverage + cmplog runtime), and a generated `LLVMFuzzerTestOneInput`
//! glue calls the routine via the gfortran C ABI (`name_`, arguments by
//! reference, a hidden `size_t` length appended per character argument), with the
//! primary buffer heap-allocated to the input size so a real out-of-bounds access
//! lands in ASan's redzone. The passthrough C fork-server driver drives it unchanged.
//!
//! Unlike COBOL, no `exit()` interposition is needed: gfortran/ASan report a bad
//! access as a genuine ASan crash the engine already classifies correctly.

/// A discovered Fortran procedure and its dummy-argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortranProc {
    pub name: String,
    pub line: u32,
    pub args: Vec<FortranArg>,
    /// The enclosing `MODULE` name when the procedure is module-contained (in a
    /// `module … contains` block), else `None` for a top-level external procedure.
    /// Drives the gfortran C-ABI symbol (`__module_MOD_name` vs `name_`).
    pub module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortranArg {
    pub name: String,
    pub kind: FortranArgKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FortranArgKind {
    /// `character(len=K)` (possibly an array) — the fuzzable byte buffer. `len`
    /// is the per-element character length (`0` = assumed `len=*`).
    CharBuffer { len: usize },
    /// `integer` scalar — a length/count operand.
    Integer,
    /// Anything else (real, logical, arrays, derived types) — zeroed scratch.
    Other,
}

impl FortranProc {
    pub fn is_fuzzable(&self) -> bool {
        self.args
            .iter()
            .any(|a| matches!(a.kind, FortranArgKind::CharBuffer { .. }))
    }

    pub fn primary_buffer_index(&self) -> Option<usize> {
        self.args
            .iter()
            .position(|a| matches!(a.kind, FortranArgKind::CharBuffer { .. }))
    }

    /// Count of `character` arguments (each contributes a hidden length in the ABI).
    pub fn char_arg_count(&self) -> usize {
        self.args
            .iter()
            .filter(|a| matches!(a.kind, FortranArgKind::CharBuffer { .. }))
            .count()
    }
}

/// Strip a Fortran comment (`!` to end of line, outside a string) and trailing
/// whitespace; uppercase for keyword matching.
fn norm(line: &str) -> String {
    let mut out = String::new();
    let mut in_str: Option<char> = None;
    for c in line.chars() {
        match in_str {
            Some(q) => {
                out.push(c);
                if c == q {
                    in_str = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    in_str = Some(c);
                    out.push(c);
                } else if c == '!' {
                    break;
                } else {
                    out.push(c);
                }
            }
        }
    }
    out.trim().to_ascii_uppercase()
}

/// Parse the `character` length from a type spec: `CHARACTER(LEN=K)`,
/// `CHARACTER(K)`, `CHARACTER*K`, `CHARACTER(LEN=*)` (assumed -> 0), bare
/// `CHARACTER` -> 1.
fn char_len(spec: &str) -> Option<usize> {
    let s = spec.trim();
    let rest = s.strip_prefix("CHARACTER")?;
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with("::") || rest.starts_with(|c: char| c.is_alphabetic()) {
        return Some(1); // bare CHARACTER
    }
    if let Some(star) = rest.strip_prefix('*') {
        let n: String = star
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        return Some(n.parse().unwrap_or(1));
    }
    if let Some(paren) = rest.strip_prefix('(') {
        let inner = paren.split(')').next().unwrap_or("");
        let inner = inner.trim();
        let val = inner
            .strip_prefix("LEN")
            .map(|v| v.trim_start().trim_start_matches('=').trim())
            .unwrap_or(inner);
        if val.starts_with('*') {
            return Some(0); // assumed length
        }
        let n: String = val.chars().take_while(|c| c.is_ascii_digit()).collect();
        return Some(n.parse().unwrap_or(1));
    }
    Some(1)
}

/// Classify a declaration's type spec into an argument kind.
fn decl_kind(spec: &str) -> FortranArgKind {
    let s = spec.trim();
    if s.starts_with("CHARACTER") {
        return FortranArgKind::CharBuffer {
            len: char_len(s).unwrap_or(1),
        };
    }
    if s.starts_with("INTEGER") {
        return FortranArgKind::Integer;
    }
    FortranArgKind::Other
}

/// The names declared by a Fortran declaration line, i.e. the part after `::`
/// (or after the type spec when there's no `::`). Array specs `a(n)` and initial
/// values are stripped to the bare name.
fn declared_names(line: &str, spec_end: usize) -> Vec<String> {
    let after = if let Some(pos) = line.find("::") {
        &line[pos + 2..]
    } else {
        &line[spec_end..]
    };
    let mut names = Vec::new();
    for part in after.split(',') {
        let name: String = part
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Scan Fortran source for fuzzable `subroutine`/`function` procedures.
pub fn parse_fortran(source: &str) -> Vec<FortranProc> {
    let mut procs: Vec<FortranProc> = Vec::new();
    // Join free-form continuation lines (`&` at end).
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut pending = String::new();
    let mut pending_line = 0usize;
    for (i, raw) in source.lines().enumerate() {
        let n = norm(raw);
        if n.is_empty() {
            continue;
        }
        if pending.is_empty() {
            pending_line = i + 1;
        }
        if let Some(head) = n.strip_suffix('&') {
            pending.push_str(head.trim_end());
            pending.push(' ');
        } else {
            pending.push_str(&n);
            logical.push((pending_line, std::mem::take(&mut pending)));
        }
    }
    if !pending.is_empty() {
        logical.push((pending_line, pending));
    }

    let mut cur: Option<usize> = None;
    // Track the enclosing MODULE so a module-contained procedure gets the right ABI
    // symbol. `MODULE name` opens it; `END MODULE`/`END` at module level closes it.
    let mut current_module: Option<String> = None;
    for (line_no, line) in &logical {
        let l = line.trim_start();
        // `MODULE name` (a module definition, not `MODULE PROCEDURE`/`END MODULE`)
        // opens a module scope; procedures inside it are module-contained.
        if let Some(rest) = l.strip_prefix("MODULE ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && name != "PROCEDURE" {
                current_module = Some(name.to_owned());
                continue;
            }
        }
        if l.starts_with("END MODULE") || (l == "END" && cur.is_none() && current_module.is_some())
        {
            current_module = None;
            continue;
        }
        // Procedure header: [prefix] SUBROUTINE/FUNCTION name(args)
        if let Some(hdr) = proc_header(l) {
            let args: Vec<FortranArg> = hdr
                .1
                .iter()
                .map(|a| FortranArg {
                    name: a.clone(),
                    kind: FortranArgKind::Other,
                })
                .collect();
            procs.push(FortranProc {
                name: hdr.0,
                line: *line_no as u32,
                args,
                module: current_module.clone(),
            });
            cur = Some(procs.len() - 1);
            continue;
        }
        if l.starts_with("END SUBROUTINE") || l.starts_with("END FUNCTION") || l == "END" {
            cur = None;
            continue;
        }
        // A type declaration inside the current procedure: refine arg kinds.
        if let Some(idx) = cur {
            if let Some(spec_end) = type_spec_end(l) {
                let kind = decl_kind(l);
                if !matches!(kind, FortranArgKind::Other) {
                    let names = declared_names(l, spec_end);
                    for n in names {
                        if let Some(arg) = procs[idx].args.iter_mut().find(|a| a.name == n) {
                            arg.kind = kind;
                        }
                    }
                }
            }
        }
    }
    procs
}

/// If `l` starts a `SUBROUTINE`/`FUNCTION` (optionally after a prefix like
/// `PURE`/`RECURSIVE`/a `FUNCTION` result type), return (name, arg names).
fn proc_header(l: &str) -> Option<(String, Vec<String>)> {
    let kw_pos = l
        .find("SUBROUTINE ")
        .map(|p| (p, "SUBROUTINE "))
        .or_else(|| l.find("FUNCTION ").map(|p| (p, "FUNCTION ")))?;
    // Reject a reference inside a larger word (e.g. END SUBROUTINE handled elsewhere,
    // CALL ... FUNCTION-like). Require the keyword at start or after a prefix word.
    let before = l[..kw_pos.0].trim();
    if !before.is_empty()
        && !before
            .split_whitespace()
            .all(|w| matches!(w, "PURE" | "RECURSIVE" | "ELEMENTAL" | "MODULE" | "IMPURE"))
        && !before.ends_with("REAL")
        && !before.ends_with("INTEGER")
        && !before.ends_with("LOGICAL")
        && !before.contains("CHARACTER")
    {
        return None;
    }
    let rest = &l[kw_pos.0 + kw_pos.1.len()..];
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    // A Fortran identifier must start with a letter — this rejects preprocessor
    // template stubs like `_TEMPLATE_ROUTINE_NAME_CHARSTRING` (include fragments
    // that are not standalone-compilable) that would otherwise be false candidates.
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    let args = match rest.split_once('(') {
        Some((_, a)) => a
            .split(')')
            .next()
            .unwrap_or("")
            .split(',')
            .filter_map(|s| {
                let n: String = s
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!n.is_empty()).then_some(n)
            })
            .collect(),
        None => Vec::new(),
    };
    Some((name, args))
}

/// If `l` begins with a type spec (`CHARACTER`, `INTEGER`, `REAL`, ...) return the
/// byte offset just past the type spec token, else `None`.
fn type_spec_end(l: &str) -> Option<usize> {
    for kw in [
        "CHARACTER",
        "INTEGER",
        "REAL",
        "LOGICAL",
        "COMPLEX",
        "DOUBLE PRECISION",
        "TYPE",
    ] {
        if l.starts_with(kw) {
            return Some(kw.len());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_char_buffer_and_integer_args() {
        let src = "\
subroutine scan(buf, n)
  implicit none
  integer, intent(in) :: n
  character(len=1), intent(inout) :: buf(n)
  buf(1) = 'x'
end subroutine scan
";
        let p = &parse_fortran(src)[0];
        assert_eq!(p.name, "SCAN");
        assert!(p.is_fuzzable());
        assert_eq!(p.args.len(), 2);
        assert_eq!(p.args[0].name, "BUF");
        assert_eq!(p.args[0].kind, FortranArgKind::CharBuffer { len: 1 });
        assert_eq!(p.args[1].kind, FortranArgKind::Integer);
        assert_eq!(p.primary_buffer_index(), Some(0));
        assert_eq!(p.char_arg_count(), 1);
    }

    #[test]
    fn char_len_forms() {
        assert_eq!(char_len("CHARACTER(LEN=32)"), Some(32));
        assert_eq!(char_len("CHARACTER(16)"), Some(16));
        assert_eq!(char_len("CHARACTER*8"), Some(8));
        assert_eq!(char_len("CHARACTER(LEN=*)"), Some(0));
        assert_eq!(char_len("CHARACTER, INTENT(IN)"), Some(1));
    }

    #[test]
    fn continuation_lines_joined() {
        let src = "subroutine f(a, &\n b)\n character(len=4) :: a\n integer :: b\nend subroutine\n";
        let p = &parse_fortran(src)[0];
        assert_eq!(p.args.len(), 2);
        assert_eq!(p.args[0].kind, FortranArgKind::CharBuffer { len: 4 });
    }

    #[test]
    fn non_fuzzable_when_no_char_arg() {
        let src = "subroutine g(x, y)\n integer :: x, y\nend subroutine\n";
        let p = &parse_fortran(src)[0];
        assert!(!p.is_fuzzable());
    }

    #[test]
    fn rejects_template_stub_names() {
        // Preprocessor include-fragment stubs (invalid Fortran identifier) are not
        // standalone-compilable and must not be discovered as candidates.
        let src = "function _TEMPLATE_ROUTINE_NAME ( s ) result ( v )\n character(len=*) :: s\nend function\n";
        assert!(parse_fortran(src).is_empty());
    }

    #[test]
    fn function_header_and_prefixes() {
        let src = "pure integer function count_it(s)\n character(len=*) :: s\nend function\n";
        let p = &parse_fortran(src)[0];
        assert_eq!(p.name, "COUNT_IT");
        assert!(p.is_fuzzable());
        assert_eq!(p.args[0].kind, FortranArgKind::CharBuffer { len: 0 });
    }
}
