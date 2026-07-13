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
    /// Whether the procedure is externally accessible per Fortran module visibility.
    /// A `PRIVATE` module procedure is compiled to a *local* symbol (nm `t`, not `T`)
    /// that the generated glue in a separate object file cannot link against — and it
    /// is an internal helper, not the library's attacker-reachable public API. External
    /// (non-module) procedures are always accessible, so this is `true` for them.
    pub public: bool,
    /// How this procedure returns, which drives the gfortran C-ABI glue. A `character`
    /// result is passed via a *hidden* leading argument the glue must supply — omitting
    /// it puts the fuzz buffer in the result slot and turns the real argument into a
    /// garbage pointer (an out-of-bounds false positive on nearly every input). Two
    /// distinct character-result ABIs (both verified empirically):
    /// see [`FortranResult`]. Ubiquitous in Fortran string libraries.
    pub result: FortranResult,
}

/// How a Fortran procedure returns — selects the gfortran C-ABI calling convention
/// the glue must emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FortranResult {
    /// A subroutine, or a function returning a scalar numeric/logical value (returned
    /// in a register — the `void`-returning glue ignores it, which is correct).
    #[default]
    NonChar,
    /// A function whose result is a fixed/assumed-length `character(len=K)` /
    /// `character(len=*)`. ABI: `void f(char* result, size_t result_len, <args…>)` —
    /// the glue passes a caller-allocated result buffer + its length. `fixed_len` is
    /// the declared constant length (`0` = assumed/unknown), used to size the buffer.
    ValueChar { fixed_len: usize },
    /// A function whose result is a deferred-length `character(len=:), allocatable`
    /// (or `pointer`) — the *modern* Fortran string-return idiom. ABI:
    /// `void f(char** data, size_t* len, <args…>)` — the callee `malloc`s the result
    /// and stores the pointer+length; the glue frees it. No expansion-overflow risk
    /// (the callee sizes its own buffer), unlike [`FortranResult::ValueChar`].
    AllocChar,
    /// A character result the glue can't synthesize: an ARRAY of characters
    /// (`character(len=1), allocatable :: arr(:)`, `character :: a(len(s))`), which is
    /// returned via a full gfortran array descriptor rather than either scalar hidden
    /// form. Driving it with a scalar-result ABI corrupts memory (a false positive), so
    /// the procedure is skipped — the Fortran analog of an unsynthesizable receiver.
    Unsupported,
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
    /// A `type(...)` / `class(...)` derived-type argument — a caller-built object
    /// (a json-fortran `json_value` pointer, an OO method's `class` receiver). The
    /// harness can only pass a zeroed (NULL) object, so a procedure that
    /// dereferences it faults — an unsynthesizable operand, the Fortran analog of a
    /// C++ receiver / COBOL handle. A procedure taking one is not fuzzable.
    Derived,
    /// Anything else (real, logical, arrays) — zeroed scratch.
    Other,
}

impl FortranProc {
    pub fn is_fuzzable(&self) -> bool {
        // A `PRIVATE` module procedure is a local symbol the glue can't link and is an
        // internal helper, not the public API — skip it (else a confusing failed_build
        // and a false attacker-reachability claim on a non-exported routine).
        self.public
            // A character-ARRAY result uses a gfortran descriptor ABI the glue can't
            // synthesize — skip (else a scalar-result ABI corrupts memory, a false positive).
            && !matches!(self.result, FortranResult::Unsupported)
            // A derived-type / polymorphic argument is a caller-built object the harness
            // can only pass as NULL, so any procedure taking one faults on deref (a
            // false positive) — exclude it and keep the pure string/numeric parsers.
            && !self
                .args
                .iter()
                .any(|a| matches!(a.kind, FortranArgKind::Derived))
            && self
                .args
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
    // An ALLOCATABLE / POINTER dummy is passed as a gfortran descriptor, not a raw
    // buffer — the harness can't synthesize one, so a `character(len=:),allocatable`
    // output (json-fortran's string utilities) corrupts memory / SEGVs when handed a
    // plain buffer. Treat as unsynthesizable (skip the procedure), like a derived type.
    if s.contains("ALLOCATABLE") || s.contains(",POINTER") || s.contains(", POINTER") {
        return FortranArgKind::Derived;
    }
    if s.starts_with("CHARACTER") {
        return FortranArgKind::CharBuffer {
            len: char_len(s).unwrap_or(1),
        };
    }
    if s.starts_with("INTEGER") {
        return FortranArgKind::Integer;
    }
    // A derived-type / polymorphic argument (`TYPE(json_value)`, `CLASS(json_core)`)
    // is a caller-built object the harness can't synthesize.
    if s.starts_with("TYPE(")
        || s.starts_with("TYPE (")
        || s.starts_with("CLASS(")
        || s.starts_with("CLASS (")
    {
        return FortranArgKind::Derived;
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
    // Module visibility (Fortran access statements): a bare `PRIVATE` in the module
    // specification section flips the default to private; `PUBLIC ::`/`PRIVATE ::`
    // lists override per name. Reset at each `MODULE`. A bare `PRIVATE`/`PUBLIC`
    // *inside a derived-type definition* sets COMPONENT visibility, not the module
    // default — so ignore access statements while inside a `TYPE … END TYPE` block.
    let mut mod_default_private = false;
    let mut mod_public: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut mod_private: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut in_type_def = false;
    // The result variable name of the FUNCTION currently being scanned (if any), used
    // to detect a `character`-typed result declared on a later line.
    let mut cur_result_name: Option<String> = None;
    for (line_no, line) in &logical {
        let l = line.trim_start();
        // `MODULE name` (a module definition, not `MODULE PROCEDURE`/`END MODULE`)
        // opens a module scope; procedures inside it are module-contained.
        if let Some(rest) = l.strip_prefix("MODULE ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && name != "PROCEDURE" {
                current_module = Some(name.to_owned());
                mod_default_private = false;
                mod_public.clear();
                mod_private.clear();
                in_type_def = false;
                continue;
            }
        }
        if l.starts_with("END MODULE") || (l == "END" && cur.is_none() && current_module.is_some())
        {
            current_module = None;
            mod_default_private = false;
            mod_public.clear();
            mod_private.clear();
            continue;
        }
        // Derived-type definition block: a bare `PRIVATE`/`PUBLIC` here is a component
        // access spec, not the module default — track the block so we skip those.
        if current_module.is_some() && cur.is_none() {
            if is_type_def_open(l) {
                in_type_def = true;
            } else if l.starts_with("END TYPE") || l == "ENDTYPE" {
                in_type_def = false;
            }
        }
        // Module access statements (spec section only: inside a module, outside any
        // procedure and outside a type definition).
        if current_module.is_some() && cur.is_none() && !in_type_def {
            if l == "PRIVATE" {
                mod_default_private = true;
                continue;
            }
            if let Some(rest) = access_stmt_names(l, "PRIVATE") {
                mod_private.extend(rest);
                continue;
            }
            if let Some(rest) = access_stmt_names(l, "PUBLIC") {
                mod_public.extend(rest);
                continue;
            }
        }
        // Procedure header: [prefix] SUBROUTINE/FUNCTION name(args)
        if let Some(hdr) = proc_header(l) {
            let args: Vec<FortranArg> = hdr
                .args
                .iter()
                .map(|a| FortranArg {
                    name: a.clone(),
                    kind: FortranArgKind::Other,
                })
                .collect();
            // External (non-module) procedures are always accessible; inside a module,
            // an explicit `public ::` wins, then an explicit `private ::`, then the
            // module default (`private` statement flips it).
            let public = if current_module.is_none() || mod_public.contains(&hdr.name) {
                true
            } else if mod_private.contains(&hdr.name) {
                false
            } else {
                !mod_default_private
            };
            // The result variable's name (`RESULT(x)`, else the function name itself),
            // so a later `character :: x` declaration marks a character-result function.
            cur_result_name = if hdr.is_function {
                Some(hdr.result_name.clone().unwrap_or_else(|| hdr.name.clone()))
            } else {
                None
            };
            procs.push(FortranProc {
                name: hdr.name,
                line: *line_no as u32,
                args,
                module: current_module.clone(),
                public,
                // A typed prefix (`character(len=*) function …`) is a value-char result
                // immediately; the `result(x)` form is refined when `x` is declared
                // (and may be upgraded to the allocatable-result ABI there).
                result: if hdr.is_function && hdr.char_result_prefix {
                    FortranResult::ValueChar { fixed_len: 0 }
                } else {
                    FortranResult::NonChar
                },
            });
            cur = Some(procs.len() - 1);
            continue;
        }
        if l.starts_with("END SUBROUTINE") || l.starts_with("END FUNCTION") || l == "END" {
            cur = None;
            cur_result_name = None;
            continue;
        }
        // A type declaration inside the current procedure: refine arg kinds, and detect
        // a `character`-typed result variable (character-returning function).
        if let Some(idx) = cur {
            if let Some(spec_end) = type_spec_end(l) {
                let kind = decl_kind(l);
                let names = declared_names(l, spec_end);
                if !matches!(kind, FortranArgKind::Other) {
                    for n in &names {
                        if let Some(arg) = procs[idx].args.iter_mut().find(|a| &a.name == n) {
                            arg.kind = kind;
                        }
                    }
                }
                // The RESULT variable's declaration selects the return ABI. This must
                // run even when `decl_kind` collapsed an allocatable char to `Derived`.
                if let Some(rname) = &cur_result_name {
                    if names.iter().any(|n| n == rname) {
                        procs[idx].result = classify_result_decl(l, rname);
                    }
                }
            }
        }
    }
    procs
}

/// Classify a FUNCTION result from its declaration line `l` (which declares the
/// result variable `rname`) into the return ABI the glue must emit.
///
/// Only a result returned in a register (a scalar numeric/logical, [`NonChar`]) or a
/// scalar character (a hidden result argument, [`ValueChar`]/[`AllocChar`]) can be
/// driven. Anything returned via a gfortran descriptor — an ARRAY, an `allocatable`/
/// `pointer` of any type, a derived type, or `complex` — is [`Unsupported`]: the
/// `void` glue would leave that hidden descriptor slot pointing at a real argument and
/// corrupt memory (a false positive). This is the Fortran analog of an unsynthesizable
/// receiver, and covers e.g. M_strings `s2c` (allocatable char array) and `s2vs`
/// (allocatable `doubleprecision` array).
fn classify_result_decl(l: &str, rname: &str) -> FortranResult {
    if l.starts_with("CHARACTER") {
        if result_is_array(l, rname) {
            FortranResult::Unsupported
        } else if is_deferred_char(l) {
            FortranResult::AllocChar
        } else {
            FortranResult::ValueChar {
                fixed_len: char_len(l).unwrap_or(0),
            }
        }
    } else if l.contains("ALLOCATABLE")
        || l.contains("POINTER")
        || l.contains("DIMENSION")
        || l.starts_with("TYPE")
        || l.starts_with("CLASS")
        || l.starts_with("COMPLEX")
        || result_is_array(l, rname)
    {
        // A non-character result returned via a descriptor — can't be driven.
        FortranResult::Unsupported
    } else {
        // A scalar numeric/logical result is returned in a register; the `void` glue
        // (which ignores the return) is correct.
        FortranResult::NonChar
    }
}

/// Whether a `character` declaration is deferred-length / allocatable / pointer
/// (`character(len=:), allocatable`) — the callee-allocated result ABI.
fn is_deferred_char(l: &str) -> bool {
    l.contains("ALLOCATABLE") || l.contains("POINTER") || l.contains("LEN=:") || l.contains("(:)")
}

/// Whether the `rname` declared on line `l` is an ARRAY — it carries a `DIMENSION`
/// attribute, or the result name is subscripted (`:: arr(:)`, `:: arr(len(s))`). An
/// array-of-characters result uses a gfortran array descriptor, not a scalar hidden
/// result argument.
fn result_is_array(l: &str, rname: &str) -> bool {
    if l.contains("DIMENSION") {
        return true;
    }
    let Some(pos) = l.find("::") else {
        return false;
    };
    for decl in l[pos + 2..].split(',') {
        if let Some(rest) = decl.trim().strip_prefix(rname) {
            // The result name is immediately (modulo spaces) followed by a `(` — a
            // dimension spec — and not part of a longer identifier.
            if rest.trim_start().starts_with('(') {
                return true;
            }
        }
    }
    false
}

/// A parsed procedure header.
struct ProcHeader {
    name: String,
    args: Vec<String>,
    is_function: bool,
    /// The header has a `character` type prefix (`character(len=*) function …`) — a
    /// character result declared inline.
    char_result_prefix: bool,
    /// The `RESULT(x)` name, if given.
    result_name: Option<String>,
}

/// If `l` starts a `SUBROUTINE`/`FUNCTION` (optionally after a prefix like
/// `PURE`/`RECURSIVE`/a `FUNCTION` result type), return its parsed header.
fn proc_header(l: &str) -> Option<ProcHeader> {
    let (kw_pos, is_function) = l
        .find("SUBROUTINE ")
        .map(|p| ((p, "SUBROUTINE "), false))
        .or_else(|| l.find("FUNCTION ").map(|p| ((p, "FUNCTION "), true)))?;
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
    let char_result_prefix = before.contains("CHARACTER");
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
    // `… FUNCTION name(args) RESULT(rname)` — capture the result variable name.
    let result_name = is_function.then(|| result_clause_name(rest)).flatten();
    Some(ProcHeader {
        name,
        args,
        is_function,
        char_result_prefix,
        result_name,
    })
}

/// Extract `x` from a trailing `RESULT ( x )` clause on a function header, if present.
fn result_clause_name(rest: &str) -> Option<String> {
    let pos = rest.find("RESULT")?;
    let after = rest[pos + "RESULT".len()..].trim_start();
    let inner = after.strip_prefix('(')?;
    let name: String = inner
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Whether `l` (normalized/uppercased) opens a derived-type DEFINITION block
/// (`TYPE :: name`, `TYPE, attrs :: name`, `TYPE name`) as opposed to a variable
/// declaration/use (`TYPE(name)`) or a `SELECT TYPE`/`TYPE IS` construct.
fn is_type_def_open(l: &str) -> bool {
    let Some(rest) = l.strip_prefix("TYPE") else {
        return false;
    };
    // `TYPE(...)` / `TYPE (...)` is a declaration or use, never a definition.
    let r = rest.trim_start();
    if r.starts_with('(') {
        return false;
    }
    // `TYPE, attrs :: name` or `TYPE :: name` — an attribute list or `::` means a def.
    if rest.starts_with(',') || r.starts_with("::") {
        return true;
    }
    // `TYPE name` — a name follows; exclude `TYPE IS (...)` (a select-type guard).
    if let Some(after) = rest.strip_prefix(' ') {
        let first = after.trim_start();
        return !first.starts_with("IS")
            && first.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    }
    false
}

/// Parse a Fortran access statement's name list: `PUBLIC :: a, b`, `PRIVATE :: a`,
/// or the older `PUBLIC a, b`. Returns the uppercased names when `l` is that access
/// statement (matching `kw`), else `None` (so a bare `PUBLIC`/`PRIVATE` or an
/// attribute like `INTEGER, PUBLIC :: x` is not treated as a name list).
fn access_stmt_names(l: &str, kw: &str) -> Option<Vec<String>> {
    let rest = l.strip_prefix(kw)?;
    // Must be the access STATEMENT: keyword then `::` or whitespace then names.
    let rest = rest.trim_start();
    let names_part = if let Some(after) = rest.strip_prefix("::") {
        after
    } else if l.len() > kw.len() && l.as_bytes()[kw.len()] == b' ' && !rest.is_empty() {
        rest
    } else {
        return None;
    };
    let names: Vec<String> = names_part
        .split(',')
        .filter_map(|s| {
            let n: String = s
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!n.is_empty()).then_some(n)
        })
        .collect();
    (!names.is_empty()).then_some(names)
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
        // The one-word spelling `doubleprecision` (gfortran accepts it) — so an
        // allocatable/array result of this type is recognized and skipped.
        "DOUBLEPRECISION",
        "TYPE",
        // Polymorphic derived-type declarations (`class(json_core) :: me`) — an OO
        // method's receiver; recognized so its arg is classified `Derived` (skip).
        "CLASS",
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

    #[test]
    fn derived_type_object_argument_is_not_fuzzable() {
        // json-fortran shape: a procedure that mutates a caller-built json_value
        // object (a `type(...)`/`class(...)` pointer) plus a character name. The
        // harness can only pass a zeroed (NULL) object -> NULL-deref SEGV false
        // positive; skip it. A pure string parser (no derived arg) stays fuzzable.
        let mutator = "subroutine json_add_member(json, name)\n \
             type(json_value), pointer :: json\n character(len=*) :: name\nend subroutine\n";
        let p = &parse_fortran(mutator)[0];
        assert_eq!(p.args[0].kind, FortranArgKind::Derived);
        assert!(!p.is_fuzzable(), "a derived-object mutator must be skipped");

        let class_method = "subroutine parse(me, s)\n \
             class(json_core), intent(inout) :: me\n character(len=*) :: s\nend subroutine\n";
        assert!(!parse_fortran(class_method)[0].is_fuzzable());

        let pure = "subroutine escape(s)\n character(len=*) :: s\nend subroutine\n";
        assert!(
            parse_fortran(pure)[0].is_fuzzable(),
            "a pure string parser stays fuzzable"
        );
    }

    #[test]
    fn private_module_procedure_is_not_fuzzable() {
        // fortran-csv-module shape: an encapsulated module (`private` default) exports
        // only a named list. A private helper (`to_real_sp`) compiles to a *local*
        // symbol the glue can't link and is not the public API -> must be skipped; the
        // explicitly `public` helper (`lowercase_string`) stays fuzzable. A bare
        // `private` inside a derived-type definition sets COMPONENT visibility and must
        // NOT be mistaken for the module default.
        let src = "\
module csv_utilities
  private
  type, public :: holder
    private
    integer :: n
  end type holder
  public :: lowercase_string
contains
  pure function lowercase_string(str) result(s)
    character(len=*), intent(in) :: str
    character(len=len(str)) :: s
    s = str
  end function lowercase_string
  pure elemental subroutine to_real_sp(str, val, ok)
    character(len=*), intent(in) :: str
    real, intent(out) :: val
    logical, intent(out) :: ok
    read(str, *) val
  end subroutine to_real_sp
end module csv_utilities
";
        let procs = parse_fortran(src);
        let lower = procs.iter().find(|p| p.name == "LOWERCASE_STRING").unwrap();
        assert!(lower.public);
        assert!(
            lower.is_fuzzable(),
            "an explicitly public helper is fuzzable"
        );
        let to_real = procs.iter().find(|p| p.name == "TO_REAL_SP").unwrap();
        assert!(!to_real.public, "a private module procedure is not public");
        assert!(
            !to_real.is_fuzzable(),
            "a private module procedure (local symbol, internal helper) must be skipped"
        );
    }

    #[test]
    fn character_returning_function_is_detected() {
        // `result(s)` + a fixed/assumed-length `character` declaration -> ValueChar.
        let via_result = "\
pure function lowercase_string(str) result(s_lower)
  character(len=*), intent(in) :: str
  character(len=len(str)) :: s_lower
  s_lower = str
end function lowercase_string
";
        let p = &parse_fortran(via_result)[0];
        assert!(matches!(p.result, FortranResult::ValueChar { .. }));
        assert!(p.is_fuzzable());

        // A typed prefix `character(len=*) function …` is a value-char result at once.
        let via_prefix =
            "character(len=10) function tag(s)\n character(len=*) :: s\nend function\n";
        assert!(matches!(
            parse_fortran(via_prefix)[0].result,
            FortranResult::ValueChar { .. }
        ));

        // A deferred-length `character(len=:), allocatable` result -> AllocChar (the
        // modern idiom; the callee mallocs the result, a different hidden ABI).
        let via_alloc = "\
function upper(str) result(output)
  character(len=*), intent(in) :: str
  character(len=:), allocatable :: output
  output = str
end function upper
";
        let a = &parse_fortran(via_alloc)[0];
        assert_eq!(a.result, FortranResult::AllocChar);
        assert!(a.is_fuzzable());

        // A subroutine and a non-character function have no character result.
        let sub = "subroutine scan(buf)\n character(len=*) :: buf\nend subroutine\n";
        assert_eq!(parse_fortran(sub)[0].result, FortranResult::NonChar);
        let int_fn = "integer function count_it(s)\n character(len=*) :: s\nend function\n";
        assert_eq!(parse_fortran(int_fn)[0].result, FortranResult::NonChar);
    }

    #[test]
    fn character_array_result_is_unsupported_and_skipped() {
        // M_strings `s2c(string) result(array)` returns an ALLOCATABLE character ARRAY
        // (`character(len=1), allocatable :: array(:)`) — a gfortran array-descriptor
        // ABI the scalar-result glue can't synthesize. Must be skipped, not mis-driven.
        let alloc_arr = "\
pure function s2c(string) result(array)
  character(len=*), intent(in) :: string
  character(len=1), allocatable :: array(:)
  array = transfer(string, array)
end function s2c
";
        let p = &parse_fortran(alloc_arr)[0];
        assert_eq!(p.result, FortranResult::Unsupported);
        assert!(!p.is_fuzzable(), "an array-char result must be skipped");

        // A fixed-length character ARRAY result (`character :: a(len(s))`) is likewise
        // an array descriptor -> skipped.
        let fixed_arr = "\
pure function switch(string) result(array)
  character(len=*), intent(in) :: string
  character(len=1) :: array(len(string))
  array = ' '
end function switch
";
        assert!(!parse_fortran(fixed_arr)[0].is_fuzzable());

        // A `dimension`-attribute char array result is also skipped.
        let dim_attr = "\
function chars(s) result(a)
  character(len=*), intent(in) :: s
  character(len=1), dimension(:), allocatable :: a
  a = transfer(s, a)
end function chars
";
        assert_eq!(
            parse_fortran(dim_attr)[0].result,
            FortranResult::Unsupported
        );
    }

    #[test]
    fn non_character_nonscalar_result_is_unsupported() {
        // M_strings `s2vs(string) result(darray)` returns an allocatable
        // `doubleprecision` ARRAY — a descriptor ABI, not a register return. Driving it
        // as a `void` function would leave the hidden descriptor slot pointing at a real
        // argument. Skip it.
        let alloc_dbl = "\
function s2vs(string) result(darray)
  character(len=*), intent(in) :: string
  doubleprecision, allocatable :: darray(:)
  darray = 0
end function s2vs
";
        let p = &parse_fortran(alloc_dbl)[0];
        assert_eq!(p.result, FortranResult::Unsupported);
        assert!(!p.is_fuzzable());

        // A scalar numeric result is returned in a register -> fuzzable (NonChar).
        let scalar = "\
integer function atoi(str) result(n)
  character(len=*), intent(in) :: str
  integer :: n
  read(str, *) n
end function atoi
";
        let s = &parse_fortran(scalar)[0];
        assert_eq!(s.result, FortranResult::NonChar);
        assert!(s.is_fuzzable());
    }

    #[test]
    fn default_public_module_procedure_stays_fuzzable() {
        // A module with no `private` default keeps its procedures public (the common
        // simple-library case) -> no over-skip.
        let src = "\
module m
contains
  subroutine parse(s)
    character(len=*), intent(in) :: s
  end subroutine parse
end module m
";
        let p = &parse_fortran(src)[0];
        assert!(p.public);
        assert!(p.is_fuzzable());
    }
}
