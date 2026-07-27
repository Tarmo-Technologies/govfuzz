// SPDX-License-Identifier: Apache-2.0

use crate::BuildErrorKind;
use regex::Regex;
use std::sync::OnceLock;

pub fn classify_into(stderr: &str, hits: &mut Vec<BuildErrorKind>) {
    let lines = stderr.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        // Some autoconf-era portability headers do not attempt to include the
        // generated config file when it is absent. They emit `#error No
        // config.h ...` instead (libarchive's archive_platform.h), so clang has
        // no ordinary "file not found" diagnostic for the existing config
        // synthesis repair to recognize.
        if line.contains("error:") && line.contains("No config.h") {
            hits.push(BuildErrorKind::MissingHeader {
                path: "config.h".to_owned(),
            });
            continue;
        }
        // A `#error` directive a build-config guard reached. clang renders the
        // directive's text verbatim (`error: "no strtoull function found"`), gcc
        // prefixes it (`error: #error "..."`). Recognized ahead of the generic
        // patterns because the text is arbitrary prose that could otherwise
        // resemble another diagnostic.
        if let Some((file, error_line, message)) = config_guard_error(line) {
            hits.push(BuildErrorKind::ConfigGuardError {
                file,
                line: error_line,
                message,
            });
            continue;
        }
        if let Some(caps) = missing_header().captures(line) {
            hits.push(BuildErrorKind::MissingHeader {
                path: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = incomplete_type().captures(line) {
            // A forward-declared-but-undefined type (pimpl idiom): "incomplete
            // type 'X'", "variable has incomplete type 'X'", or "... with
            // incomplete return type 'X'". Distinct from "unknown type name": the
            // type IS declared, just not defined in the compiled sources, so it
            // must NOT be `void *`-repaired (that redefines the forward decl).
            hits.push(BuildErrorKind::IncompleteType {
                name: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = unknown_type().captures(line) {
            // #96: "unknown type name 'X'" puts X in TYPE position. An ALL_CAPS X is
            // a legacy uppercase TYPEDEF (Expat's `SCANNER`) by default, needing a
            // type/header repair — NOT a `void *` (which corrupts the declaration)
            // and NOT a macro. Only a declaration DECORATOR (jansson's `JSON_INLINE`
            // expanding to `inline`/nothing, `__EXPORT`, `WINAPI`) is defined empty
            // as a macro. Classifying deterministically here also stops the repair
            // kind from oscillating between type and macro across rounds.
            if is_type_position_decorator_macro(&caps[1]) {
                hits.push(BuildErrorKind::MissingMacro {
                    name: caps[1].to_owned(),
                    as_value: false,
                });
            } else {
                hits.push(BuildErrorKind::MissingType {
                    name: caps[1].to_owned(),
                });
            }
            continue;
        }
        if let Some(caps) = undeclared_macro().captures(line) {
            // An ALL-CAPS identifier used but undeclared is overwhelmingly a
            // build-config macro the project's build system would inject
            // (generated config.h / -D). Repair by #defining it to a benign
            // value so the TU compiles. Lower/mixed-case undeclared identifiers
            // are real symbols and fall through to the symbol/Other paths.
            hits.push(BuildErrorKind::MissingMacro {
                name: caps[1].to_owned(),
                as_value: true,
            });
            continue;
        }
        if let Some(caps) = undeclared_identifier().captures(line) {
            // When a deleted project header was the only path to a C++ standard
            // header, Clang diagnoses the qualifier rather than the actual type:
            // `use of undeclared identifier 'std'` followed by `using std::string`.
            // Preserve the qualified member from the source-context line so repair
            // can include the correct standard header.
            if &caps[1] == "std" {
                if let Some(member) = lines
                    .iter()
                    .skip(line_index + 1)
                    .take(3)
                    .find_map(|context| std_qualified_identifier().captures(context))
                {
                    hits.push(BuildErrorKind::MissingType {
                        name: format!("std::{}", &member[1]),
                    });
                    continue;
                }
            }
            // Clang++ reports a missing declaration as "use of undeclared
            // identifier" rather than C's "call to undeclared function". Only
            // promote the curated libc/POSIX function set; arbitrary lowercase
            // identifiers remain Other so variables are never stubbed as calls.
            if is_known_header_function(&caps[1]) {
                hits.push(BuildErrorKind::UndefinedSymbol {
                    name: caps[1].to_owned(),
                });
                continue;
            }
            // Clang++ uses the same diagnostic for an undeclared variable and
            // an undeclared function. Source/caret context disambiguates them:
            // only a following `name (` call expression is repairable. A
            // function-like neutral macro is sufficient for a missing inline
            // dependency helper such as LevelDB's DecodeFixed32.
            if identifier_used_as_call(&lines, line_index, &caps[1]) {
                hits.push(BuildErrorKind::MissingMacro {
                    name: caps[1].to_owned(),
                    as_value: true,
                });
                continue;
            }
            // Mixed-case project constants and typedef aliases lost with a
            // private/public header (cJSON_IsReference, bzip2's True/UChar) do
            // not match the ALL_CAPS fast path. Promote only identifiers that
            // start uppercase or use cJSON's established namespace; the repair
            // planner resolves surviving typedefs and exact duplicate #defines
            // before considering a synthesized value.
            if (caps[1].len() >= 2
                && caps[1]
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase()))
                || caps[1].starts_with("cJSON_")
            {
                hits.push(BuildErrorKind::MissingMacro {
                    name: caps[1].to_owned(),
                    as_value: true,
                });
                continue;
            }
        }
        if let Some(caps) = call_to_undeclared().captures(line) {
            // clang frontend: `call to undeclared function 'foo';
            // ISO C99 and later do not support implicit function
            // declarations`. Keep it distinct from an ld undefined reference:
            // a standalone stub cannot supply the missing call-site declaration.
            let symbol = &caps[1];
            if let Some(lib) = system_lib_for_symbol(symbol) {
                hits.push(BuildErrorKind::MissingSharedLib {
                    name: lib.to_owned(),
                });
            } else if let Some((file, line)) = diagnostic_location(line) {
                hits.push(BuildErrorKind::UndeclaredFunction {
                    name: symbol.to_owned(),
                    file,
                    line,
                });
            } else {
                // Preserve the old fallback for nonstandard compiler output that
                // omits a source location; normal clang/gcc diagnostics take the
                // location-aware arm above.
                hits.push(BuildErrorKind::UndefinedSymbol {
                    name: symbol.to_owned(),
                });
            }
            continue;
        }
        if let Some(caps) = undefined_reference().captures(line) {
            let symbol = &caps[1];
            // System-library symbols (math, pthread, dl, rt) are
            // really "you forgot to link -l<lib>". Classifying these
            // as `UndefinedSymbol` would route them through the C
            // stub-gen path, which would synthesise a fake `sqrt`
            // and silently corrupt fuzz signal. Map to
            // `MissingSharedLib` instead so the upstream maintainer
            // sees "you need -lm" and the repair planner doesn't
            // stub it out.
            if let Some(lib) = system_lib_for_symbol(symbol) {
                hits.push(BuildErrorKind::MissingSharedLib {
                    name: lib.to_owned(),
                });
            } else {
                hits.push(BuildErrorKind::UndefinedSymbol {
                    name: symbol.to_owned(),
                });
            }
            continue;
        }
        if let Some(caps) = ld_cannot_find_lib().captures(line) {
            hits.push(BuildErrorKind::MissingSharedLib {
                name: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = malformed_function_body().captures(line) {
            if let Ok(line_no) = caps[2].parse::<u32>() {
                hits.push(BuildErrorKind::MalformedFunctionDecl {
                    file: caps[1].to_owned(),
                    line: line_no,
                });
                continue;
            }
        }
        if let Some(caps) = type_specifier_missing().captures(line) {
            let column = caps[3].parse::<usize>().ok();
            if let (Some(column), Some(rendered_line)) = (column, lines.get(line_index + 1)) {
                // Clang commonly renders context as `  97 | <source>`. The
                // diagnostic column is relative to `<source>`, not that gutter.
                let source_line = rendered_line
                    .split_once('|')
                    .map(|(_, source)| source.strip_prefix(' ').unwrap_or(source))
                    .unwrap_or(rendered_line);
                if let Some(name) = identifier_at_column(source_line, column) {
                    // #96: a declaration decorator, OR a CALL-LIKE/function-like
                    // macro (the name is immediately followed by `(`, e.g. libyaml's
                    // `SHIM(yaml_char_t **b_end)`), becomes an empty macro. A plain
                    // uppercase TYPEDEF in this position is left for the type/header
                    // repair path (never define-empty'd).
                    let call_like = is_macro_like(name)
                        && source_line
                            .get(column - 1 + name.len()..)
                            .is_some_and(|rest| rest.starts_with('('));
                    if is_type_position_decorator_macro(name) || call_like {
                        hits.push(BuildErrorKind::MissingMacro {
                            name: name.to_owned(),
                            as_value: false,
                        });
                        continue;
                    }
                }
            }
        }
    }
}

fn identifier_at_column(line: &str, one_based_column: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut index = one_based_column.saturating_sub(1).min(bytes.len() - 1);
    while index > 0 && !(bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index -= 1;
    }
    if !(bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        return None;
    }
    let mut start = index;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    let mut end = index + 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end]).ok()
}

fn identifier_used_as_call(lines: &[&str], diagnostic_index: usize, name: &str) -> bool {
    lines.iter().skip(diagnostic_index).take(4).any(|line| {
        line.match_indices(name)
            .any(|(offset, _)| line[offset + name.len()..].trim_start().starts_with('('))
    })
}

fn malformed_function_body() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^(.+?):(\d+):\d+: error: expected function body after function declarator"#)
            .expect("regex")
    })
}

fn type_specifier_missing() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^(.+?):(\d+):(\d+): error: type specifier missing"#).expect("regex")
    })
}

fn missing_header() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?:fatal )?error: ['"](.+?)['"] file not found"#).expect("regex")
    })
}

fn incomplete_type() -> &'static Regex {
    // Matches clang/gcc's several spellings for a forward-declared-but-undefined
    // type, capturing the type name: "incomplete type 'X'", "variable has
    // incomplete type 'X'", "field has incomplete type 'X'", "... with
    // incomplete return type 'X'". A leading `class`/`struct`/`enum` keyword the
    // compiler sometimes prints before the name is stripped.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"error: .*incomplete (?:return )?type '(?:(?:class|struct|enum|union) )?(.+?)'"#,
        )
        .expect("regex")
    })
}

fn unknown_type() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"error: unknown type name '(.+?)'"#).expect("regex"))
}

fn undefined_reference() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"undefined reference to `(.+?)'"#).expect("regex"))
}

fn call_to_undeclared() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"call to undeclared (?:library )?function '(.+?)'"#).expect("regex")
    })
}

/// Recognize a `#error` directive diagnostic and return `(file, line, message)`.
///
/// Two spellings: gcc keeps the directive (`error: #error "text"`), clang prints
/// only the operand (`error: "text"`). The clang form is matched on the operand
/// being a QUOTED string — an ordinary diagnostic starts with a bare word or a
/// single-quoted identifier, never a double quote — so this cannot swallow one.
fn config_guard_error(line: &str) -> Option<(String, u32, String)> {
    let (file, error_line) = diagnostic_location(line)?;
    let message = line.split("error:").nth(1)?.trim();
    let message = match message.strip_prefix("#error") {
        Some(rest) => rest.trim(),
        // Exactly one quoted run, spanning the whole operand. GNAT reports
        // `"To_String" not declared in "Legacy"`, which also starts and ends with a
        // quote — counting them keeps that (and any other prose diagnostic naming
        // two quoted things) out.
        None if message.starts_with('"')
            && message.ends_with('"')
            && message.matches('"').count() == 2 =>
        {
            message
        }
        None => return None,
    };
    let message = message.trim_matches('"').trim();
    (!message.is_empty()).then(|| (file, error_line, message.to_owned()))
}

fn diagnostic_location(line: &str) -> Option<(String, u32)> {
    static R: OnceLock<Regex> = OnceLock::new();
    let captures = R
        .get_or_init(|| Regex::new(r#"^(.+):(\d+):\d+: (?:fatal )?error:"#).expect("regex"))
        .captures(line)?;
    Some((captures[1].to_owned(), captures[2].parse().ok()?))
}

/// True when a name has the shape of a preprocessor macro: only ALL-CAPS
/// letters, digits and underscores, at least two chars, with at least one
/// uppercase letter. Leading underscores are allowed — reserved-identifier
/// linkage/visibility macros (`__EXPORT`, `__BEGIN_DECLS`, `__WEAK`) are
/// pervasive in embedded C/C++ (PX4, NuttX, HALs) and, in type position, must be
/// defined-empty rather than typedef'd to `void *`. A lowercase letter anywhere
/// (`widget_t`, `_MyType`) means it's a real type, not a macro.
fn is_macro_like(name: &str) -> bool {
    name.len() >= 2
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && name.chars().any(|c| c.is_ascii_uppercase())
}

/// #96: within a TYPE-position diagnostic ("unknown type name 'X'" / "type
/// specifier missing"), decide whether an ALL_CAPS `X` is a declaration DECORATOR
/// macro (`JSON_INLINE`, `__EXPORT`, `WINAPI` — it expands to a qualifier and must
/// be defined EMPTY) versus a legacy uppercase TYPEDEF (Expat's `SCANNER`,
/// `XML_Bool` — a real type needing a type/header repair).
///
/// The compiler already told us `X` is in TYPE position, so an unknown `X` there is
/// a typedef by DEFAULT; blindly calling every ALL_CAPS type-position name a macro
/// corrupts the declaration and oscillates the repair kind across rounds (a
/// type-header repair one round, a macro the next). Only decorator-SHAPED names —
/// reserved-identifier macros (leading `_`) or names carrying a decl-spec /
/// calling-convention / attribute word — route to a macro here.
fn is_type_position_decorator_macro(name: &str) -> bool {
    if !is_macro_like(name) {
        // A lower/mixed-case name in type position (`widget_t`, `_MyType`) is a
        // real type, never a macro.
        return false;
    }
    // Reserved-identifier macros (`__EXPORT`, `__BEGIN_DECLS`, `__WEAK`) are
    // pervasive linkage/visibility decorators in embedded C/C++ HALs (PX4/NuttX).
    if name.starts_with('_') {
        return true;
    }
    // A decl-spec / calling-convention / attribute word anywhere in the name marks
    // it as a decorator that expands to a qualifier, not the type itself.
    const DECORATOR_WORDS: &[&str] = &[
        "INLINE",
        "FORCEINLINE",
        "NOINLINE",
        "EXPORT",
        "IMPORT",
        "EXTERN",
        "DLLEXPORT",
        "DLLIMPORT",
        "DECLSPEC",
        "VISIBILITY",
        "CDECL",
        "STDCALL",
        "FASTCALL",
        "THISCALL",
        "WINAPI",
        "APIENTRY",
        "CALLBACK",
        "PASCAL",
        "ATTRIBUTE",
        "DEPRECATED",
        "NORETURN",
        "NODISCARD",
        "NOEXCEPT",
        "NOTHROW",
        "RESTRICT",
        "DECLS",
    ];
    name.split('_').any(|word| DECORATOR_WORDS.contains(&word))
}

fn undeclared_macro() -> &'static Regex {
    // Only ALL-CAPS identifiers (>= 2 chars, leading letter) — the shape of a
    // preprocessor constant — so real undeclared functions/variables are left
    // to the symbol/Other classifiers.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"error: use of undeclared identifier '([A-Z][A-Z0-9_]+)'"#).expect("regex")
    })
}

fn undeclared_identifier() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"error: use of undeclared identifier '([A-Za-z_][A-Za-z0-9_]*)'"#)
            .expect("regex")
    })
}

fn std_qualified_identifier() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"\bstd::([A-Za-z_][A-Za-z0-9_]*)"#).expect("regex"))
}

fn is_known_header_function(name: &str) -> bool {
    matches!(
        name,
        "htons"
            | "htonl"
            | "ntohs"
            | "ntohl"
            | "stricmp"
            | "strcmpi"
            | "strnicmp"
            | "strncmpi"
            | "wcslen"
            | "true"
            | "false"
    )
}

fn ld_cannot_find_lib() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"cannot find -l([^\s:]+)").expect("regex"))
}

/// Map a libc/system symbol back to the `-l<name>` that defines it.
/// Only covers the system libraries gcc/clang ship in a default
/// Linux toolchain — anything else stays an `UndefinedSymbol`.
fn system_lib_for_symbol(symbol: &str) -> Option<&'static str> {
    // libm (-lm). Includes the bsd-style suffixed forms gcc emits
    // for IEEE 754 variants.
    const MATH: &[&str] = &[
        "acos",
        "acosf",
        "acosh",
        "acoshf",
        "asin",
        "asinf",
        "asinh",
        "asinhf",
        "atan",
        "atanf",
        "atan2",
        "atan2f",
        "atanh",
        "atanhf",
        "cbrt",
        "cbrtf",
        "ceil",
        "ceilf",
        "copysign",
        "copysignf",
        "cos",
        "cosf",
        "cosh",
        "coshf",
        "erf",
        "erfc",
        "exp",
        "expf",
        "exp2",
        "exp2f",
        "expm1",
        "expm1f",
        "fabs",
        "fabsf",
        "floor",
        "floorf",
        "fmod",
        "fmodf",
        "frexp",
        "hypot",
        "hypotf",
        "ldexp",
        "lgamma",
        "log",
        "logf",
        "log10",
        "log10f",
        "log1p",
        "log2",
        "log2f",
        "modf",
        "pow",
        "powf",
        "round",
        "roundf",
        "scalbn",
        "sin",
        "sinf",
        "sinh",
        "sinhf",
        "sqrt",
        "sqrtf",
        "tan",
        "tanf",
        "tanh",
        "tanhf",
        "tgamma",
        "trunc",
        "truncf",
    ];
    const PTHREAD: &[&str] = &[
        "pthread_create",
        "pthread_join",
        "pthread_detach",
        "pthread_cancel",
        "pthread_mutex_init",
        "pthread_mutex_destroy",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_mutex_trylock",
        "pthread_cond_init",
        "pthread_cond_destroy",
        "pthread_cond_wait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
        "pthread_rwlock_init",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock",
        "pthread_rwlock_unlock",
        "pthread_key_create",
        "pthread_getspecific",
        "pthread_setspecific",
        "pthread_once",
        "pthread_barrier_init",
        "pthread_barrier_wait",
        "pthread_barrier_destroy",
    ];
    const DL: &[&str] = &["dlopen", "dlsym", "dlclose", "dlerror", "dladdr", "dlmopen"];
    const RT: &[&str] = &[
        "clock_gettime",
        "clock_settime",
        "clock_getres",
        "clock_nanosleep",
        "shm_open",
        "shm_unlink",
        "mq_open",
        "mq_close",
        "mq_unlink",
        "mq_send",
        "mq_receive",
        "timer_create",
        "timer_delete",
        "timer_settime",
        "timer_gettime",
        "aio_read",
        "aio_write",
        "aio_error",
        "aio_return",
    ];
    if MATH.contains(&symbol) {
        Some("m")
    } else if PTHREAD.contains(&symbol) {
        Some("pthread")
    } else if DL.contains(&symbol) {
        Some("dl")
    } else if RT.contains(&symbol) {
        Some("rt")
    } else {
        None
    }
}
