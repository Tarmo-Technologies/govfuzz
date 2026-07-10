// SPDX-License-Identifier: Apache-2.0

use crate::BuildErrorKind;
use regex::Regex;
use std::sync::OnceLock;

pub fn classify_into(stderr: &str, hits: &mut Vec<BuildErrorKind>) {
    for line in stderr.lines() {
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
            // An ALL-CAPS name in type position is not a real type — it's a
            // build-config qualifier macro (inline/export/api decorator like
            // jansson's `JSON_INLINE`, expanding to `inline` or nothing). A
            // `void *` typedef would corrupt the declaration; define it empty.
            if is_macro_like(&caps[1]) {
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
        if let Some(caps) = call_to_undeclared().captures(line) {
            // clang frontend: `call to undeclared function 'foo';
            // ISO C99 and later do not support implicit function
            // declarations`. Routes to UndefinedSymbol so the repair
            // planner stubs the symbol the same way it would for an
            // ld undefined-reference error.
            let symbol = &caps[1];
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
    }
}

fn malformed_function_body() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^(.+?):(\d+):\d+: error: expected function body after function declarator"#)
            .expect("regex")
    })
}

fn missing_header() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"fatal error: ['"](.+?)['"] file not found"#).expect("regex"))
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
    R.get_or_init(|| Regex::new(r#"call to undeclared function '(.+?)'"#).expect("regex"))
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

fn undeclared_macro() -> &'static Regex {
    // Only ALL-CAPS identifiers (>= 2 chars, leading letter) — the shape of a
    // preprocessor constant — so real undeclared functions/variables are left
    // to the symbol/Other classifiers.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"error: use of undeclared identifier '([A-Z][A-Z0-9_]+)'"#).expect("regex")
    })
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
