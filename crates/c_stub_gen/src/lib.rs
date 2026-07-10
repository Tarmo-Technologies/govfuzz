// SPDX-License-Identifier: Apache-2.0

//! Synthesise C/C++ stubs for symbols the auto-mode build couldn't resolve.

/// Map a (cleaned) C return-type spelling to the body of a no-op stub.
/// Returns `None` for struct/union by value — the caller marks the
/// containing target `failed_build` because we have no safe default.
pub fn stub_body_for_return_type(return_type: &str) -> Option<&'static str> {
    let trimmed = return_type.trim();
    if trimmed.is_empty() || trimmed == "void" {
        return Some("return;");
    }
    if trimmed.contains('*') {
        return Some("return NULL;");
    }
    if is_integral(trimmed) {
        return Some("return 0;");
    }
    if matches!(trimmed, "float" | "double" | "long double") {
        return Some("return 0.0;");
    }
    None
}

fn is_integral(t: &str) -> bool {
    let canonical = t.trim_start_matches("const ").trim();
    if matches!(
        canonical,
        "int"
            | "unsigned"
            | "unsigned int"
            | "short"
            | "unsigned short"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "char"
            | "signed char"
            | "unsigned char"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "off_t"
            | "time_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            // miniz's typedef for `unsigned long`. Without this the
            // declared-stub path bails on functions like
            // `mz_uncompress` and the symbol falls through to the
            // blind-stub bucket.
            | "mz_ulong"
            | "intptr_t"
            | "uintptr_t"
            | "bool"
            | "_Bool"
    ) {
        return true;
    }
    if canonical.starts_with("enum ") {
        return true;
    }
    // Heuristic: vendor-typedef'd scalars (`foo_ulong`, `bar_uint`,
    // `baz_t` etc.) that the strict list doesn't know. Returning 0 is
    // a safe default for any unsigned integer — and if the type turns
    // out to be a pointer typedef the compiler will reject `return 0`
    // and the candidate will land in unrecoverable_runtime anyway.
    canonical.ends_with("_ulong")
        || canonical.ends_with("_uint")
        || canonical.ends_with("_uint8")
        || canonical.ends_with("_uint16")
        || canonical.ends_with("_uint32")
        || canonical.ends_with("_uint64")
        || canonical.ends_with("_int")
        || canonical.ends_with("_long")
}

/// Whether `t` is a bare (by-value, non-pointer) `enum TAG` spelling, optionally
/// `const`-qualified. Such a type is INCOMPLETE in the isolated weak-stub TU
/// (which includes only `auto_types.h`, never the real header that lists the
/// enumerators), so it may appear neither as a function RESULT type nor as a
/// by-value PARAMETER of a definition — C11 6.7.6.3p4 / 6.9.1p7 require complete
/// parameter types, and a definition with an incomplete result type is likewise
/// rejected. A pointer (`enum TAG *`) points to an incomplete type, which is
/// legal, so it is excluded.
fn is_bare_incomplete_enum(t: &str) -> bool {
    let t = t.trim();
    let bare = t.strip_prefix("const ").map(str::trim).unwrap_or(t);
    bare.starts_with("enum ") && !bare.contains('*')
}

/// The return type to EMIT for a weak stub. A bare `enum TAG` value return is
/// incomplete in the isolated stub TU (which includes only `auto_types.h`, never
/// the real header), and clang rejects a function defined with an incomplete
/// result type. A weak fallback symbol has no cross-TU return-type linkage check,
/// the real definition overrides it when linked, and the `return 0;` body is
/// ABI-identical to the enum's zero — so emit `int` instead. Only a *value*
/// return is affected: `enum TAG *` is a pointer to an incomplete type, which is
/// legal, so it (and every other shape) is returned untouched.
fn stub_return_type(rt: &str) -> String {
    let t = rt.trim();
    if is_bare_incomplete_enum(t) {
        return "int".to_owned();
    }
    t.to_owned()
}

/// Minimal view of a declared C function. Both `c_parser::CDeclaration`
/// and `cpp_parser::CppDeclaration` will implement this so `c_stub_gen`
/// stays parser-agnostic.
pub trait DeclarationView {
    fn name(&self) -> &str;
    fn return_type(&self) -> &str;
    /// Parameter type spellings in order, exactly as written in the
    /// declaration. Empty list means a `(void)` declaration; the caller
    /// is responsible for telling those apart from K&R-style empty
    /// parens.
    fn param_types(&self) -> &[String];
}

/// Unwrap a function-like export-macro return type to its inner type:
/// `CJSON_PUBLIC(void *)` -> `void *`, `ZEXTERN(int)` -> `int`. Symbol-export
/// macros (`CJSON_PUBLIC`, `__declspec`-style API wrappers) are UPPER_CASE by
/// convention; a lowercase leading token (a real type like `void`) or a
/// non-wrapping shape (`const char *`, `void (*)(int)`) is left untouched. Copying
/// the macro INVOCATION as a return type produced a malformed declarator clang
/// rejects. Applied repeatedly in case a macro wraps another.
pub fn unwrap_export_macro(return_type: &str) -> String {
    let mut t = return_type.trim().to_owned();
    loop {
        let chars: Vec<char> = t.chars().collect();
        let ident_end = chars
            .iter()
            .position(|c| !(c.is_alphanumeric() || *c == '_'))
            .unwrap_or(chars.len());
        let ident: String = chars[..ident_end].iter().collect();
        let is_macro_name = !ident.is_empty()
            && ident
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && ident.chars().any(|c| c.is_ascii_uppercase());
        if !is_macro_name {
            return t;
        }
        let rest: String = chars[ident_end..].iter().collect();
        let rest = rest.trim_start();
        if !rest.starts_with('(') {
            return t;
        }
        // Find the `(` matching close, requiring it to span to the end.
        let rb: Vec<char> = rest.chars().collect();
        let mut depth = 0i32;
        let mut close = None;
        for (i, c) in rb.iter().enumerate() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        match close {
            Some(i) if rb[i + 1..].iter().all(|c| c.is_whitespace()) => {
                t = rb[1..i].iter().collect::<String>().trim().to_owned();
            }
            _ => return t,
        }
    }
}

/// Render an abstract parameter-type list as a NAMED list for a definition: a
/// C function DEFINITION may not omit parameter names (`foo(size_t) {...}` is a
/// malformed declarator), so each type gets a synthetic `_gf_pN`. Empty / a sole
/// `void` stays `void`.
fn named_param_list(param_types: &[String]) -> String {
    if param_types.is_empty() || (param_types.len() == 1 && param_types[0].trim() == "void") {
        return "void".to_owned();
    }
    param_types
        .iter()
        .enumerate()
        .map(|(i, ty)| {
            // A by-value `enum TAG` parameter is incomplete in the isolated stub
            // TU (no enumerator list), and a function DEFINITION may not declare a
            // parameter of incomplete type (clang: "variable has incomplete type
            // 'enum TAG'") — jansson's `jsonp_error_set(..., enum json_error_code
            // code, ...)`. Demote it to `int` exactly as `stub_return_type` does
            // for an incomplete-enum result: the body ignores every parameter and
            // the weak symbol is overridden by the real definition at link, so the
            // rewrite is ABI-immaterial. A pointer (`enum TAG *`) points to an
            // incomplete type, which is legal, so it is left untouched.
            let emitted = if is_bare_incomplete_enum(ty) {
                "int"
            } else {
                ty.trim()
            };
            format!("{emitted} _gf_p{i}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render a C source-level stub function definition matching the given
/// declaration. Returns `None` when the return type isn't safely
/// stubbable (struct/union by value).
pub fn synth_c_stub<D: DeclarationView>(decl: &D) -> Option<String> {
    // Unwrap an export-macro return type (`CJSON_PUBLIC(void *)` -> `void *`) so
    // both the body choice and the emitted return type are valid C.
    let rt_unwrapped = unwrap_export_macro(decl.return_type());
    let body = stub_body_for_return_type(&rt_unwrapped)?;
    let rt = if rt_unwrapped.trim().is_empty() {
        "void".to_owned()
    } else {
        stub_return_type(rt_unwrapped.trim())
    };
    let params = named_param_list(decl.param_types());
    Some(format!(
        "__attribute__((weak)) {rt} {name}({params}) {{\n    {body}\n}}\n",
        rt = rt,
        name = decl.name(),
        params = params,
        body = body,
    ))
}

/// Synthesise an empty header file body. The header path is recorded
/// in a leading comment so the repair manifest can show the user
/// exactly what was replaced.
pub fn synth_placeholder_header(virtual_path: &str) -> String {
    format!(
        "/* auto-synthesised placeholder for {virtual_path}\n\
         * govfuzz auto could not find this header on the include path.\n\
         * The original may have defined types or function prototypes - if\n\
         * the build still fails after stub synthesis, supply the real\n\
         * header via --extra-include and re-run.\n\
         */\n\
         #pragma once\n"
    )
}

/// Derive the interface "base" name from a CORBA/IDL stub header path: the
/// leaf stem with its trailing `C`/`S` (client-stub / server-skeleton) marker
/// and extension stripped (`src/idl/MessageC.h` -> `Message`, `bankS.hpp` ->
/// `bank`). Falls back to the bare stem when no recognised marker is present.
fn idl_base_name(virtual_path: &str) -> String {
    let leaf = virtual_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(virtual_path);
    let stem = leaf.split('.').next().unwrap_or(leaf);
    let base = stem
        .strip_suffix('C')
        .or_else(|| stem.strip_suffix('S'))
        .filter(|b| !b.is_empty())
        .unwrap_or(stem);
    base.to_owned()
}

/// Synthesise a placeholder header for an absent CORBA/IDL-generated stub
/// (`<base>C.h` / `<base>S.h`). Unlike [`synth_placeholder_header`]'s empty
/// `#pragma once`, this emits a small curated set of CORBA scaffolding typedefs
/// (`CORBA_Object`, `CORBA_long`, ...) plus an opaque typedef for the
/// interface's own base name, so the dependent TU's IDL-typed declarations parse
/// rather than cascading into "unknown type" errors. Any caller-supplied `decls`
/// (e.g. recovered from the `.idl`, when available) are appended verbatim. These
/// are deliberately fuzz-oriented placeholders: an opaque object handle and
/// platform-default integer widths, mirroring [`c_config_type_alias`]'s style —
/// sound enough to compile and decode, not an ABI-faithful CORBA mapping.
pub fn synth_idl_placeholder_header(virtual_path: &str, decls: &[String]) -> String {
    let base = idl_base_name(virtual_path);
    let mut out = format!(
        "/* auto-synthesised CORBA/IDL placeholder for {virtual_path}\n\
         * govfuzz auto could not find this IDL-generated stub header (the source\n\
         * `.idl` and its compiled C/S output aren't in the tree). The curated\n\
         * CORBA scaffolding typedefs below let IDL-typed declarations parse so the\n\
         * dependent target still builds and fuzzes. Supply the real generated\n\
         * header (tao_idl / `govfuzz fake-corba`) for faithful CORBA semantics.\n\
         */\n\
         #pragma once\n\
         /* curated CORBA/IDL scaffolding stub types */\n\
         typedef struct {{ void *_p; }} CORBA_Object;\n\
         typedef long CORBA_long;\n\
         typedef unsigned long CORBA_unsigned_long;\n\
         typedef short CORBA_short;\n\
         typedef unsigned short CORBA_unsigned_short;\n\
         typedef unsigned char CORBA_octet;\n\
         typedef unsigned char CORBA_boolean;\n\
         typedef char CORBA_char;\n\
         typedef double CORBA_double;\n\
         typedef float CORBA_float;\n\
         typedef char *CORBA_string;\n\
         typedef struct {{ void *_p; }} CORBA_Environment;\n",
    );
    // Opaque typedef for the interface's own base name (`Message` from
    // `MessageC.h`): IDL interfaces map to object references, so an opaque
    // pointer-bearing struct is a safe stand-in for the parser.
    out.push_str(&format!(
        "/* opaque placeholder for IDL interface `{base}` */\n\
         typedef struct {{ void *_p; }} {base};\n"
    ));
    for decl in decls {
        out.push_str(decl);
        out.push('\n');
    }
    out
}

/// Map a C++ standard-library type spelling (bare or `std::`-qualified) to
/// the standard header that defines it. Returns None for non-stdlib names,
/// which fall back to the `void *` placeholder. The legacy `<strstream>`
/// family is included because the government C++ targets that motivate this
/// (old CORBA glue, zlib `contrib/iostream` wrappers) predate `<sstream>`.
pub fn cpp_stdlib_header(type_name: &str) -> Option<&'static str> {
    let bare = type_name.strip_prefix("std::").unwrap_or(type_name);
    Some(match bare {
        "ostrstream" | "istrstream" | "strstream" | "strstreambuf" => "strstream",
        "streampos" | "streamoff" | "streamsize" | "ios" | "ios_base" => "ios",
        "ostream" | "istream" | "iostream" | "wostream" | "wistream" | "wiostream" => "iostream",
        "ofstream" | "ifstream" | "fstream" | "filebuf" => "fstream",
        "ostringstream" | "istringstream" | "stringstream" | "stringbuf" => "sstream",
        "string" | "wstring" => "string",
        "vector" => "vector",
        _ => return None,
    })
}

/// Resolve a recognised C++ standard-library type by pulling in its real
/// definition: a `#include <header>` (and a `using` re-publishing the
/// unqualified spelling) rather than a `void *` alias, which would silently
/// corrupt value semantics. Returns None for non-stdlib names.
///
/// The emitted block is guarded by `__cplusplus` and consists only of header
/// `#include`s + `using` declarations, both idempotent — so unlike a `void *`
/// `typedef`, this is safe to *force-include* into every translation unit of
/// the build (including the real target/library sources that define these
/// types), where a placeholder typedef would clash with the genuine
/// definition.
/// Map a C standard fixed-width / size type spelling to the header that
/// defines it. These are real types (so a `void *` placeholder corrupts
/// arithmetic) but standard, so the fix is to `#include` the header rather
/// than stub. Returns None for non-standard names.
pub fn c_std_header(type_name: &str) -> Option<&'static str> {
    let bare = type_name
        .trim_start_matches("const ")
        .trim_start_matches("unsigned ")
        .trim();
    match bare {
        "int8_t" | "int16_t" | "int32_t" | "int64_t" | "uint8_t" | "uint16_t" | "uint32_t"
        | "uint64_t" | "int_least8_t" | "int_least16_t" | "int_least32_t" | "int_least64_t"
        | "uint_least8_t" | "uint_least16_t" | "uint_least32_t" | "uint_least64_t"
        | "int_fast8_t" | "int_fast16_t" | "int_fast32_t" | "int_fast64_t" | "uint_fast8_t"
        | "uint_fast16_t" | "uint_fast32_t" | "uint_fast64_t" | "intmax_t" | "uintmax_t"
        | "intptr_t" | "uintptr_t" => Some("stdint.h"),
        "size_t" | "ptrdiff_t" | "wchar_t" => Some("stddef.h"),
        // `va_list` and its glibc / compiler-builtin spellings come from
        // <stdarg.h> (which on glibc also defines `__gnuc_va_list`). Aliasing them
        // to `void *` collides with the real typedef <stdio.h> pulls in
        // ("typedef redefinition with different types '__gnuc_va_list' vs 'void *'")
        // — a systematic FAILED BUILD on any variadic API that takes a va_list
        // (jansson's `json_vpack_ex(..., va_list ap)`). Force-include the header.
        "va_list" | "__gnuc_va_list" | "__builtin_va_list" | "__va_list" => Some("stdarg.h"),
        // `FILE` is provided by <stdio.h>; a `void *` alias clashes with the real
        // opaque struct typedef. (FILE* parameters are decoded via fmemopen
        // elsewhere; this is for a FILE type that surfaces as missing.)
        "FILE" => Some("stdio.h"),
        // `bool`/`true`/`false` are macros from <stdbool.h> in C. When a
        // project header that would have pulled them in (e.g. cFE's
        // common_types.h) is placeholdered away, `bool` surfaces as a missing
        // type; resolving it to <stdbool.h> is sound and force-include-safe,
        // whereas the generic `typedef void *bool;` corrupts every predicate.
        "bool" | "_Bool" => Some("stdbool.h"),
        _ => None,
    }
}

/// `#include` the standard header for a recognised C standard type. Unguarded
/// (`<stdint.h>`/`<stddef.h>` are valid in C and C++) and idempotent, so it is
/// safe to force-include into every TU — unlike a `void *` placeholder.
pub fn synth_c_std_include(type_name: &str) -> Option<String> {
    let header = c_std_header(type_name)?;
    Some(format!(
        "/* auto-synthesised: C standard type `{type_name}` -> <{header}> */\n\
         #include <{header}>\n"
    ))
}

/// A minimal autoconf-style `config.h` for a C project that ships only a
/// `config.h.in` template (no configured build), so a source guarded by
/// `#ifdef HAVE_CONFIG_H` / the standard `HAVE_*_H` feature macros still
/// compiles on a glibc host. Only standard headers that genuinely exist on the
/// host are claimed; nothing feature-specific is asserted.
pub fn synth_minimal_config_h() -> String {
    let mut out = String::from(
        "/* auto-synthesised minimal config.h (project ships only config.h.in) */\n\
         #ifndef GOVFUZZ_AUTO_CONFIG_H\n#define GOVFUZZ_AUTO_CONFIG_H 1\n\
         #define HAVE_CONFIG_H 1\n#define STDC_HEADERS 1\n",
    );
    for h in [
        "STDIO_H",
        "STDLIB_H",
        "STRING_H",
        "STRINGS_H",
        "STDINT_H",
        "INTTYPES_H",
        "STDDEF_H",
        "STDARG_H",
        "STDBOOL_H",
        "LIMITS_H",
        "CTYPE_H",
        "ERRNO_H",
        "ASSERT_H",
        "MEMORY_H",
        "UNISTD_H",
        "FCNTL_H",
        "SYS_TYPES_H",
        "SYS_STAT_H",
        "SYS_TIME_H",
        "TIME_H",
        "WCHAR_H",
        "WCTYPE_H",
        "DIRENT_H",
        "SIGNAL_H",
        "DLFCN_H",
    ] {
        out.push_str(&format!("#define HAVE_{h} 1\n"));
    }
    out.push_str(
        "#ifndef PACKAGE\n#define PACKAGE \"\"\n#endif\n\
         #ifndef VERSION\n#define VERSION \"0\"\n#endif\n\
         #ifndef PACKAGE_VERSION\n#define PACKAGE_VERSION \"0\"\n#endif\n\
         #endif /* GOVFUZZ_AUTO_CONFIG_H */\n",
    );
    out
}

/// Whether `path` (a missing-header `#include` spelling) is an autoconf/cmake
/// `config.h` the project would have generated from a `config.h.in` template.
pub fn is_config_header(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    matches!(base, "config.h" | "config_h.h" | "auto_config.h")
}

/// Whether `name` is a standard C / POSIX library FUNCTION that the C runtime
/// always provides at link time. Such a symbol must never be blind-stubbed (a
/// bogus `void name(void)` mismatches the real signature and breaks the link / is
/// a redefinition) — leaving it unstubbed lets it resolve from libc. Curated, not
/// heuristic, so a project's own `read`/`write`-named function is not suppressed
/// only when it is genuinely one of these (the linker still prefers a real
/// in-tree definition, which `AddSource` adds first).
pub fn is_standard_libc_symbol(name: &str) -> bool {
    matches!(
        name,
        // <stdio.h>
        "printf" | "fprintf" | "sprintf" | "snprintf" | "vprintf" | "vfprintf" | "vsnprintf"
        | "scanf" | "sscanf" | "fscanf" | "puts" | "fputs" | "fputc" | "putc" | "putchar"
        | "getchar" | "fgetc" | "getc" | "fgets" | "fopen" | "fdopen" | "freopen" | "fclose"
        | "fread" | "fwrite" | "fseek" | "ftell" | "rewind" | "fflush" | "feof" | "ferror"
        | "clearerr" | "setvbuf" | "setbuf" | "perror" | "remove" | "rename" | "tmpfile"
        | "fileno" | "fmemopen"
        // <stdlib.h>
        | "malloc" | "calloc" | "realloc" | "free" | "aligned_alloc" | "posix_memalign"
        | "abort" | "exit" | "_exit" | "atexit" | "getenv" | "setenv" | "unsetenv" | "putenv"
        | "system" | "atoi" | "atol" | "atoll" | "atof" | "strtol" | "strtoul" | "strtoll"
        | "strtoull" | "strtod" | "qsort" | "bsearch" | "rand" | "srand" | "abs" | "labs"
        // <string.h> / <strings.h>
        | "memcpy" | "memmove" | "memset" | "memcmp" | "memchr" | "strcmp" | "strncmp"
        | "strcpy" | "strncpy" | "strcat" | "strncat" | "strlen" | "strnlen" | "strchr"
        | "strrchr" | "strstr" | "strdup" | "strndup" | "strtok" | "strtok_r" | "strerror"
        | "strerror_r" | "strcasecmp" | "strncasecmp" | "bcopy" | "bzero" | "ffs"
        // <ctype.h>
        | "isalpha" | "isdigit" | "isalnum" | "isspace" | "isupper" | "islower" | "isprint"
        | "ispunct" | "iscntrl" | "isxdigit" | "tolower" | "toupper"
        // <unistd.h> / <fcntl.h> / file ops
        | "open" | "close" | "read" | "write" | "lseek" | "pread" | "pwrite" | "dup" | "dup2"
        | "pipe" | "fcntl" | "ioctl" | "access" | "unlink" | "link" | "symlink" | "readlink"
        | "stat" | "fstat" | "lstat" | "chmod" | "chown" | "mkdir" | "rmdir" | "getcwd"
        | "chdir" | "opendir" | "readdir" | "closedir" | "isatty" | "sysconf"
        // process / signal / time
        | "fork" | "execv" | "execvp" | "execve" | "waitpid" | "wait" | "kill" | "signal"
        | "sigaction" | "getpid" | "getppid" | "sleep" | "usleep" | "nanosleep"
        | "gettimeofday" | "clock_gettime" | "time" | "clock" | "localtime" | "gmtime"
        | "mktime" | "strftime"
        // wide / misc
        | "wctomb" | "mbtowc" | "wcslen" | "setlocale"
        // math (libm, linked alongside)
        | "sqrt" | "pow" | "fabs" | "floor" | "ceil" | "round" | "log" | "log2" | "log10"
        | "exp" | "sin" | "cos" | "tan" | "fmod" | "fmin" | "fmax"
    )
}

/// Map a standard symbol that is a *macro* (or needs a header to be declared,
/// not merely linked) to the standard header that provides it (`assert` ->
/// `<assert.h>`). When such a symbol is reported undefined the fix is to
/// force-include the header, not to stub the symbol. Returns `None` for ordinary
/// libc functions (handled by [`is_standard_libc_symbol`], which link from libc).
pub fn c_std_symbol_header(name: &str) -> Option<&'static str> {
    match name {
        "assert" | "static_assert" | "__assert_fail" => Some("assert.h"),
        "errno" => Some("errno.h"),
        "offsetof" => Some("stddef.h"),
        "va_start" | "va_end" | "va_arg" | "va_copy" => Some("stdarg.h"),
        // POSIX functions whose DECLARATION a project gates behind a feature `-D`
        // it expects its build system to pass (zip's `<unistd.h>` sits under a
        // CMake-only `ZIP_HAVE_SYMLINK`). They link from libc fine — the failure is
        // "call to undeclared function" — so the fix is to force-include the
        // declaring header, never to blind-stub the symbol (a `void *f(void)` stub
        // both mismatches the real signature and leaves the call site undeclared).
        "ftruncate" | "truncate" | "fsync" | "fdatasync" | "getpagesize" | "gethostname"
        | "getentropy" | "pread" | "pwrite" => Some("unistd.h"),
        "ftello" | "fseeko" | "getline" | "getdelim" => Some("stdio.h"),
        _ => None,
    }
}

/// Map a common embedded / legacy fixed-width integer type *alias* spelling to
/// the `<stdint.h>` type it conventionally denotes. Unlike [`c_std_header`]'s
/// standard `(u)intN_t` names, these are project aliases — the OSAL / cFE /
/// classic-flight-software / VxWorks-style `int32`, `uint16`, ... family — that
/// resolve to a real integer type. Aliasing them to `void *` (the generic
/// placeholder) corrupts arithmetic and pointer width and cascades build
/// failures across every header that uses them (e.g. cFE's `common_types.h`
/// chain), so they get a sound typedef instead. Returns None for names outside
/// this well-known family.
pub fn c_integer_alias(type_name: &str) -> Option<&'static str> {
    let bare = type_name.trim_start_matches("const ").trim();
    Some(match bare {
        "int8" => "int8_t",
        "int16" => "int16_t",
        "int32" => "int32_t",
        "int64" => "int64_t",
        "uint8" => "uint8_t",
        "uint16" => "uint16_t",
        "uint32" => "uint32_t",
        "uint64" => "uint64_t",
        _ => return None,
    })
}

/// Synthesise a sound typedef for a recognised integer alias (see
/// [`c_integer_alias`]): `typedef int32_t int32;` preceded by `#include
/// <stdint.h>`. Safe to *force-include* — the typedef only materialises when
/// the alias is otherwise missing from the build (so no real definition is
/// present to clash with), and an identical typedef redefinition is permitted
/// (C11 6.7p3) anyway. This is the integer-family analogue of
/// [`synth_c_std_include`]; preferring it over [`synth_typedef_placeholder`]
/// keeps `int32`-style aliases from becoming `void *`. Returns None for
/// unknown names.
pub fn synth_c_integer_alias_typedef(type_name: &str) -> Option<String> {
    let canonical = c_integer_alias(type_name)?;
    let bare = type_name.trim_start_matches("const ").trim();
    Some(format!(
        "/* auto-synthesised: integer alias `{bare}` -> {canonical} (<stdint.h>) */\n\
         #include <stdint.h>\n\
         typedef {canonical} {bare};\n"
    ))
}

/// Map a known framework *config* type alias to its concrete fixed-width scalar
/// spelling. These are the F´ (fprime) `Fw*Type` family: scalar typedefs whose
/// real definition lives in `config/*TypeAliasAc.h` headers that the FPP
/// autocoder emits during the build and are therefore ABSENT from a fresh
/// checkout. The parser TU references them as scalars (IDs, sizes, indices), so
/// the generic `void *` placeholder cannot stand in — it corrupts arithmetic and
/// won't compile where the value is used in `<`, `[]`, `+`. Unlike a width
/// *guess*, every entry below is the upstream default resolved from the shipped
/// `default/config/FpConfig.fpp` + the unix `PlatformTypes.fpp`, with exact
/// signedness preserved (guessing signedness flips comparison semantics and
/// manufactures/masks findings). The unix defaults match the x86_64 host the
/// harness builds for. A non-default deployment can override these widths, so a
/// synthesised alias is LOWER-CONFIDENCE (see [`synth_c_config_type_alias_typedef`]).
/// Returns None for any name outside the curated family — an unknown stays a
/// `void *` placeholder, never a guessed scalar.
pub fn c_config_type_alias(type_name: &str) -> Option<&'static str> {
    let bare = type_name.trim_start_matches("const ").trim();
    Some(match bare {
        // ID family -> U32 (FwIdType and the aliases that default through it).
        "FwIdType" | "FwChanIdType" | "FwDpIdType" | "FwDpPriorityType" | "FwEventIdType"
        | "FwOpcodeType" | "FwPrmIdType" | "FwTraceIdType" | "FwSignalType" => "uint32_t",
        // Sizes default through Platform{,Signed}SizeType -> 64-bit on the LP64 host.
        "FwSizeType" => "uint64_t",
        "FwSignedSizeType" => "int64_t",
        // Index is SIGNED (I16); assert-arg and task-id are SIGNED (I32).
        "FwIndexType" => "int16_t",
        "FwAssertArgType" | "FwTaskIdType" => "int32_t",
        // Priorities -> U8.
        "FwTaskPriorityType" | "FwQueuePriorityType" => "uint8_t",
        // Narrow store / packet / time fields -> U16 (keep them narrow so a
        // 16-bit wrap stays reachable instead of being over-widened away).
        "FwSizeStoreType"
        | "FwBuffSizeType"
        | "FwTlmPacketizeIdType"
        | "FwTimeBaseStoreType"
        | "FwPacketDescriptorType" => "uint16_t",
        "FwTimeContextStoreType" => "uint8_t",
        // Enum store is SIGNED (I32) — a signed/unsigned flip here changes
        // `enum < count` semantics and would invent or mask a finding.
        "FwEnumStoreType" => "int32_t",
        _ => return None,
    })
}

/// Synthesise a sound typedef for a recognised framework config-type alias (see
/// [`c_config_type_alias`]): `typedef uint32_t FwChanIdType;` preceded by
/// `#include <stdint.h>`, carrying a LOWER-CONFIDENCE provenance comment. Safe to
/// force-include only when no real definition is reachable (the caller applies
/// the same source/tree guards as the `void *` arm); an identical typedef
/// redefinition is permitted (C11 6.7p3) if the real header later arrives at the
/// same width. Returns None for names outside the curated family.
pub fn synth_c_config_type_alias_typedef(type_name: &str) -> Option<String> {
    let underlying = c_config_type_alias(type_name)?;
    let bare = type_name.trim_start_matches("const ").trim();
    Some(format!(
        "/* auto-synthesised config-type alias `{bare}` -> {underlying} (<stdint.h>).\n\
         \x20  LOWER-CONFIDENCE: the real width is set by the project's absent config\n\
         \x20  codegen; this is the upstream default and a non-default deployment may\n\
         \x20  override it. Findings touching this type stay path-validated, not\n\
         \x20  runtime-confirmed. */\n\
         #include <stdint.h>\n\
         typedef {underlying} {bare};\n"
    ))
}

/// Derive the curated config-type alias backing a missing F´ autocoder header.
/// The FPP autocoder names each per-type header `<Type>AliasAc.h` (e.g.
/// `config/FwTraceIdTypeAliasAc.h` carries `FwTraceIdType`); when that header is
/// absent codegen, stubbing it EMPTY leaves the type undefined and the build
/// burns a repair round per header before the type even surfaces. Recognising
/// the header lets the repair write the real typedef straight into the stub, so
/// one round resolves both the `#include` and the type. Returns
/// `(type_name, underlying)` for a curated config alias, else None.
pub fn config_type_alias_from_header(header_path: &str) -> Option<(String, &'static str)> {
    let base = header_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(header_path);
    let stem = base
        .strip_suffix(".h")
        .or_else(|| base.strip_suffix(".hpp"))?;
    let type_name = stem.strip_suffix("AliasAc")?;
    let underlying = c_config_type_alias(type_name)?;
    Some((type_name.to_owned(), underlying))
}

pub fn synth_cpp_stdlib_include(type_name: &str) -> Option<String> {
    let header = cpp_stdlib_header(type_name)?;
    let bare = type_name.strip_prefix("std::").unwrap_or(type_name);
    Some(if bare == type_name {
        format!(
            "/* auto-synthesised: C++ stdlib type `{type_name}` -> <{header}> */\n\
             #ifdef __cplusplus\n\
             #include <{header}>\n\
             using std::{bare};\n\
             #endif\n"
        )
    } else {
        format!(
            "/* auto-synthesised: C++ stdlib type `{type_name}` -> <{header}> */\n\
             #ifdef __cplusplus\n\
             #include <{header}>\n\
             #endif\n"
        )
    })
}

/// Synthesise a typedef alias to `void *` for a missing type name.
/// Unsound for value-types but unblocks parsing in cases where the
/// missing header just provided a struct-pointer alias. Only reaches the
/// compile via `auto_stubs.c` (never force-included) precisely because a
/// `void *` typedef would collide with a real definition if it landed in a
/// TU that defines the type for real — prefer [`synth_cpp_stdlib_include`]
/// for recognised C++ stdlib names.
pub fn synth_typedef_placeholder(type_name: &str) -> String {
    format!(
        "/* auto-synthesised: unknown type `{type_name}` aliased to void* */\n\
         typedef void *{type_name};\n"
    )
}

/// One observed field-access chain on a value of a missing type — mirrors
/// `c_parser::FieldAccessPath`, redeclared here so `c_stub_gen` stays
/// dependency-free (the caller converts).
#[derive(Debug, Clone)]
pub struct FieldPath {
    pub components: Vec<String>,
    pub leaf_indexed: bool,
    pub max_index: usize,
}

#[derive(Default)]
struct FieldNode {
    children: std::collections::BTreeMap<String, FieldNode>,
    leaf_array: bool,
    array_len: usize,
}

/// Synthesise a real `struct` for a missing type the target dereferences by
/// field, from the observed access chains. A `void *` placeholder (see
/// [`synth_typedef_placeholder`]) can never compile when the body does
/// `x->a.b.c[i]`; this emits a nested struct whose members are inferred from
/// usage: a member with sub-members becomes a nested `struct`, an indexed leaf
/// becomes `unsigned char name[N]` (N from the largest index seen), and a plain
/// leaf becomes a wide `unsigned long`. Returns None when there are no chains.
///
/// Sound to force-include for the same reason as the void* placeholder: it only
/// materialises when the type is otherwise missing from the build.
pub fn synth_struct_from_field_paths(type_name: &str, paths: &[FieldPath]) -> Option<String> {
    let root = build_field_tree(paths)?;
    let body = emit_struct_members(&root, 1);
    Some(format!(
        "/* auto-synthesised: struct for field-accessed type `{type_name}` \
         (members inferred from usage) */\n\
         typedef struct {{\n{body}}} {type_name};\n"
    ))
}

/// As [`synth_struct_from_field_paths`], but *completes a named struct/union
/// tag* (`struct <tag> {{ .. }};`) rather than introducing a fresh typedef. Used
/// when a real header already does `typedef struct <tag> <Name>;` to an
/// incomplete tag (cFE's generated `CFE_MSG_Message_t` -> `struct
/// CFE_MSG_Message`): completing the tag satisfies the field accesses without
/// the "typedef redefinition" clash a second typedef would cause.
pub fn synth_struct_tag_from_field_paths(
    tag: &str,
    is_union: bool,
    type_name: &str,
    paths: &[FieldPath],
) -> Option<String> {
    let root = build_field_tree(paths)?;
    let body = emit_struct_members(&root, 1);
    let keyword = if is_union { "union" } else { "struct" };
    // Complete the tag, then re-declare the typedef. The typedef is byte-identical
    // to the real header's (we derived `tag` from that header's `typedef
    // <keyword> <tag> <type_name>;`), so it is a legal identical redefinition
    // (C11 6.7p3) whether or not the real header is also reached.
    Some(format!(
        "/* auto-synthesised: completion of `{keyword} {tag}` for the field-accessed \
         incomplete type `{type_name}` (members inferred from usage) */\n\
         {keyword} {tag} {{\n{body}}};\n\
         typedef {keyword} {tag} {type_name};\n"
    ))
}

fn build_field_tree(paths: &[FieldPath]) -> Option<FieldNode> {
    let mut root = FieldNode::default();
    for path in paths {
        if path.components.is_empty() {
            continue;
        }
        let last = path.components.len() - 1;
        let mut node = &mut root;
        for (i, comp) in path.components.iter().enumerate() {
            node = node.children.entry(comp.clone()).or_default();
            if i == last && path.leaf_indexed {
                node.leaf_array = true;
                node.array_len = node.array_len.max(path.max_index.saturating_add(1));
            }
        }
    }
    if root.children.is_empty() {
        None
    } else {
        Some(root)
    }
}

fn emit_struct_members(node: &FieldNode, depth: usize) -> String {
    let indent = "    ".repeat(depth);
    let mut out = String::new();
    for (name, child) in &node.children {
        if !child.children.is_empty() {
            // A member with sub-members is a nested struct (this wins over any
            // scalar use of the same member at a shallower site).
            let inner = emit_struct_members(child, depth + 1);
            out.push_str(&format!("{indent}struct {{\n{inner}{indent}}} {name};\n"));
        } else if child.leaf_array {
            let len = child.array_len.clamp(1, 4096);
            out.push_str(&format!("{indent}unsigned char {name}[{len}];\n"));
        } else {
            out.push_str(&format!("{indent}unsigned long {name};\n"));
        }
    }
    out
}

/// Last-resort stub when no declaration of `name` can be found in
/// the source tree. Emits `void name(void) {{ return; }}`. Call sites
/// that pass arguments will themselves fail to compile - that's
/// usually fine because those call sites live in a .c file we already
/// gave up resolving. If the call site IS our generated harness,
/// the attempt loop marks the target unrecoverable.
pub fn synth_blind_stub(name: &str) -> String {
    // A captured undefined symbol sometimes carries its parameter signature
    // (`crc8_dvb_s2(unsigned char, unsigned char)`), not just the bare name. The
    // function identifier is everything up to the first `(`; using the whole
    // string as the name emits
    // `void crc8_dvb_s2(unsigned char, unsigned char)(void)` -- a function
    // returning a function type, which does not compile and fails the entire
    // stub translation unit. Strip to the identifier and give the stub a single
    // no-prototype-free definition that still provides the symbol at link.
    let ident = name.split('(').next().map(str::trim).unwrap_or(name);
    let ident = if ident.is_empty() { name } else { ident };
    // Return a NULL pointer rather than `void`, so the integer return register
    // (RAX / x0) is deterministically zeroed. With no in-tree declaration we
    // don't know the real signature, but the harness calls the symbol through its
    // OWN prototype (from an out-of-tree header), and for the dominant
    // pointer-/integer-returning case a `void` stub leaves the return register
    // holding garbage -- a `cJSON *j = cJSON_Parse(...)` then sees a non-NULL
    // junk pointer and `free`s it, the phantom #388 crash. Zeroing the register
    // makes that read NULL/0, so the harness's `if (ptr)` guard short-circuits.
    // C has no return-type mangling, so the symbol still satisfies the link; only
    // the register value changes (struct-by-value/float returns are unchanged --
    // no worse than the old `void` stub, and those don't cause the free(garbage)
    // class). The stub is compiled standalone in auto_stubs.c and never
    // force-included, so the prototype mismatch is invisible.
    format!(
        "/* auto-synthesised blind stub: declaration of `{name}` not found in tree */\n\
         __attribute__((weak)) void *{ident}(void) {{\n    return (void *)0;\n}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        c_config_type_alias, c_std_symbol_header, config_type_alias_from_header, is_config_header,
        is_standard_libc_symbol, stub_body_for_return_type, synth_blind_stub,
        synth_c_config_type_alias_typedef, synth_minimal_config_h,
    };

    #[test]
    fn minimal_config_h_defines_have_config_h_and_is_config_header_matches() {
        let cfg = synth_minimal_config_h();
        assert!(cfg.contains("#define HAVE_CONFIG_H 1"));
        assert!(cfg.contains("#define HAVE_STDINT_H 1"));
        assert!(is_config_header("config.h"));
        assert!(is_config_header("build/cmake/config.h"));
        assert!(!is_config_header("archive.h"));
    }

    #[test]
    fn standard_libc_functions_are_recognized() {
        for f in [
            "open", "strcmp", "waitpid", "wctomb", "malloc", "printf", "memcpy",
        ] {
            assert!(is_standard_libc_symbol(f), "{f} should be a libc symbol");
        }
        for project in ["ngtcp2_conn_read", "my_decode", "lzma_encode"] {
            assert!(!is_standard_libc_symbol(project), "{project} is not libc");
        }
    }

    #[test]
    fn standard_macro_symbols_map_to_their_header() {
        assert_eq!(c_std_symbol_header("assert"), Some("assert.h"));
        assert_eq!(c_std_symbol_header("offsetof"), Some("stddef.h"));
        // POSIX file/IO functions a project gates behind a feature `-D` (zip's
        // ftruncate under a CMake-only ZIP_HAVE_SYMLINK) → force-include the
        // declaring header, not a blind stub.
        assert_eq!(c_std_symbol_header("ftruncate"), Some("unistd.h"));
        assert_eq!(c_std_symbol_header("truncate"), Some("unistd.h"));
        assert_eq!(c_std_symbol_header("getline"), Some("stdio.h"));
        // An ordinary libc function is NOT a header-injection case (it links).
        assert_eq!(c_std_symbol_header("open"), None);
        assert_eq!(c_std_symbol_header("my_func"), None);
    }

    #[test]
    fn config_alias_derived_from_autocoder_header_name() {
        assert_eq!(
            config_type_alias_from_header("config/FwTraceIdTypeAliasAc.h"),
            Some(("FwTraceIdType".to_owned(), "uint32_t"))
        );
        assert_eq!(
            config_type_alias_from_header("FwEnumStoreTypeAliasAc.h"),
            Some(("FwEnumStoreType".to_owned(), "int32_t"))
        );
        // Not an autocoder alias header.
        assert_eq!(
            config_type_alias_from_header("config/SomethingElse.h"),
            None
        );
        assert_eq!(config_type_alias_from_header("FpConfig.h"), None);
        // Autocoder-shaped name but not a curated type -> None (stays placeholder).
        assert_eq!(config_type_alias_from_header("FwBogusTypeAliasAc.h"), None);
    }

    #[test]
    fn config_alias_widths_match_fprime_defaults_with_exact_signedness() {
        // Exact upstream widths — over/under-widening shifts struct layout and
        // decoder byte consumption; a signedness flip changes comparison
        // semantics. Pin both.
        assert_eq!(c_config_type_alias("FwChanIdType"), Some("uint32_t"));
        assert_eq!(c_config_type_alias("FwOpcodeType"), Some("uint32_t"));
        assert_eq!(c_config_type_alias("FwTraceIdType"), Some("uint32_t"));
        assert_eq!(c_config_type_alias("FwSizeType"), Some("uint64_t"));
        assert_eq!(c_config_type_alias("FwSignedSizeType"), Some("int64_t"));
        assert_eq!(c_config_type_alias("FwIndexType"), Some("int16_t")); // SIGNED
        assert_eq!(c_config_type_alias("FwEnumStoreType"), Some("int32_t")); // SIGNED
        assert_eq!(c_config_type_alias("FwAssertArgType"), Some("int32_t")); // SIGNED
        assert_eq!(c_config_type_alias("FwTaskPriorityType"), Some("uint8_t"));
        assert_eq!(
            c_config_type_alias("FwPacketDescriptorType"),
            Some("uint16_t")
        );
        assert_eq!(
            c_config_type_alias("FwTimeContextStoreType"),
            Some("uint8_t")
        );
    }

    #[test]
    fn config_alias_strips_const_qualifier() {
        assert_eq!(c_config_type_alias("const FwOpcodeType"), Some("uint32_t"));
    }

    #[test]
    fn config_alias_misses_safely_on_unknown_and_typo() {
        // A typo of a known alias must MISS (-> None -> stays void*), never be
        // fuzzily matched to a guessed scalar.
        assert_eq!(c_config_type_alias("FwChanIdTyp"), None);
        assert_eq!(c_config_type_alias("FwBogusType"), None);
        // word_t is resolved tree-wide via TypeAlias; it is deliberately NOT in
        // the curated table (a stale entry would be wrong-width when absent).
        assert_eq!(c_config_type_alias("word_t"), None);
        // An arbitrary unknown scalar-named type is not synthesised.
        assert_eq!(c_config_type_alias("SomeRandomThing"), None);
    }

    #[test]
    fn config_alias_emitter_is_sound_and_flagged_low_confidence() {
        let s = synth_c_config_type_alias_typedef("FwEnumStoreType").unwrap();
        assert!(s.contains("#include <stdint.h>"));
        assert!(s.contains("typedef int32_t FwEnumStoreType;"));
        assert!(s.contains("LOWER-CONFIDENCE"));
        assert!(synth_c_config_type_alias_typedef("NotAConfigType").is_none());
    }

    #[test]
    fn blind_stub_for_bare_name_is_valid() {
        let s = synth_blind_stub("rc_decode_buf");
        // Pointer return zeroes RAX so a caller treating it as a pointer sees NULL
        // (the #388 free(garbage) guard) — see synth_blind_stub.
        assert!(s.contains("void *rc_decode_buf(void) {"));
        assert!(s.contains("return (void *)0;"));
        assert!(!s.contains(")(void)"));
    }

    #[test]
    fn blind_stub_strips_embedded_signature() {
        // A symbol captured with its parameter list must not become a function
        // returning a function type (`void f(args)(void)`), which won't compile.
        let s = synth_blind_stub("crc8_dvb_s2(unsigned char, unsigned char)");
        assert!(
            s.contains("void *crc8_dvb_s2(void) {"),
            "expected bare-identifier stub, got: {s}"
        );
        assert!(
            !s.contains(")(void)"),
            "must not emit function-returning-function: {s}"
        );
    }

    #[test]
    fn void_returns_bare_return() {
        assert_eq!(stub_body_for_return_type("void"), Some("return;"));
    }

    #[test]
    fn empty_return_type_treated_as_void() {
        assert_eq!(stub_body_for_return_type(""), Some("return;"));
    }

    #[test]
    fn pointer_returns_null() {
        assert_eq!(stub_body_for_return_type("char *"), Some("return NULL;"));
        assert_eq!(
            stub_body_for_return_type("struct foo *"),
            Some("return NULL;")
        );
        assert_eq!(stub_body_for_return_type("void **"), Some("return NULL;"));
    }

    #[test]
    fn integral_returns_zero() {
        for t in ["int", "size_t", "uint64_t", "bool", "unsigned int"] {
            assert_eq!(stub_body_for_return_type(t), Some("return 0;"), "{t}");
        }
    }

    #[test]
    fn floating_returns_zero_point_zero() {
        assert_eq!(stub_body_for_return_type("float"), Some("return 0.0;"));
        assert_eq!(stub_body_for_return_type("double"), Some("return 0.0;"));
    }

    #[test]
    fn struct_by_value_unsupported() {
        assert_eq!(stub_body_for_return_type("struct widget"), None);
        assert_eq!(stub_body_for_return_type("my_struct_t"), None);
    }

    #[test]
    fn enum_returns_zero() {
        assert_eq!(stub_body_for_return_type("enum Color"), Some("return 0;"));
        assert_eq!(
            stub_body_for_return_type("const enum Mode"),
            Some("return 0;")
        );
    }

    #[test]
    fn types_ending_in_enum_are_not_treated_as_integral() {
        // Catches the previous (buggy) `ends_with("enum")` heuristic.
        assert_eq!(stub_body_for_return_type("my_enum"), None);
    }

    #[test]
    fn miniz_ulong_returns_zero() {
        // Concrete regression: govfuzz auto failed to stub
        // `mz_uncompress` because `mz_ulong` wasn't on the known
        // int-typedef list, so the symbol fell through to the blind
        // path and surfaced as stubbed_symbols_blind.
        assert_eq!(stub_body_for_return_type("mz_ulong"), Some("return 0;"));
        assert_eq!(
            stub_body_for_return_type("const mz_ulong"),
            Some("return 0;")
        );
    }

    #[test]
    fn vendor_ulong_uint_heuristic_returns_zero() {
        for t in [
            "foo_ulong",
            "bar_uint",
            "baz_uint32",
            "quux_uint64",
            "vendor_int",
            "thing_long",
        ] {
            assert_eq!(stub_body_for_return_type(t), Some("return 0;"), "{t}");
        }
    }

    #[test]
    fn vendor_t_suffix_still_treated_as_struct_by_value() {
        // Don't widen the `_t` suffix to integers — `point_t` is a
        // struct-by-value in plenty of real code. The existing
        // `struct_by_value_unsupported` test pins this, but the
        // bonus heuristic in is_integral could regress it; this
        // assertion is a belt-and-braces guard.
        assert_eq!(stub_body_for_return_type("widget_t"), None);
    }
}

#[cfg(test)]
mod synth_tests {
    use super::*;

    struct FakeDecl {
        name: &'static str,
        return_type: &'static str,
        params: Vec<String>,
    }
    impl DeclarationView for FakeDecl {
        fn name(&self) -> &str {
            self.name
        }
        fn return_type(&self) -> &str {
            self.return_type
        }
        fn param_types(&self) -> &[String] {
            &self.params
        }
    }

    #[test]
    fn synthesises_pointer_returning_stub() {
        let decl = FakeDecl {
            name: "decoder_create",
            return_type: "decoder_t *",
            params: vec!["void".to_owned()],
        };
        let stub = synth_c_stub(&decl).expect("supported");
        assert_eq!(
            stub.trim(),
            "__attribute__((weak)) decoder_t * decoder_create(void) {\n    return NULL;\n}"
        );
    }

    #[test]
    fn synthesises_void_param_stub() {
        let decl = FakeDecl {
            name: "vendor_log_init",
            return_type: "void",
            params: vec![],
        };
        let stub = synth_c_stub(&decl).expect("supported");
        assert_eq!(
            stub.trim(),
            "__attribute__((weak)) void vendor_log_init(void) {\n    return;\n}"
        );
    }

    #[test]
    fn renders_real_param_list() {
        let decl = FakeDecl {
            name: "decoder_feed",
            return_type: "int",
            params: vec![
                "decoder_t *".to_owned(),
                "const uint8_t *".to_owned(),
                "size_t".to_owned(),
            ],
        };
        let stub = synth_c_stub(&decl).expect("supported");
        // A DEFINITION must name its params (`(size_t)` is a malformed declarator).
        assert!(
            stub.contains(
                "int decoder_feed(decoder_t * _gf_p0, const uint8_t * _gf_p1, size_t _gf_p2)"
            ),
            "stub: {stub}"
        );
        assert!(stub.contains("return 0;"));
    }

    #[test]
    fn unwraps_export_macro_return_type_and_names_params() {
        // cJSON: `CJSON_PUBLIC(void *) cJSON_malloc(size_t)` — the macro-wrapped
        // return type and the abstract param both made the definition malformed.
        let decl = FakeDecl {
            name: "cJSON_malloc",
            return_type: "CJSON_PUBLIC(void *)",
            params: vec!["size_t".to_owned()],
        };
        let stub = synth_c_stub(&decl).expect("pointer return is stubbable");
        assert_eq!(
            stub.trim(),
            "__attribute__((weak)) void * cJSON_malloc(size_t _gf_p0) {\n    return NULL;\n}",
            "stub: {stub}"
        );
    }

    #[test]
    fn unwrap_export_macro_leaves_real_types_untouched() {
        // Lowercase leading token (a real type) / non-wrapping shapes are unchanged.
        assert_eq!(unwrap_export_macro("const char *"), "const char *");
        assert_eq!(unwrap_export_macro("void (*)(int)"), "void (*)(int)");
        assert_eq!(unwrap_export_macro("CJSON_PUBLIC(cJSON *)"), "cJSON *");
        assert_eq!(unwrap_export_macro("ZEXTERN(int)"), "int");
        // A function-call-shaped lowercase name is NOT an export macro.
        assert_eq!(unwrap_export_macro("foo(int)"), "foo(int)");
    }

    #[test]
    fn bare_enum_tag_return_is_emitted_as_int_to_avoid_incomplete_type() {
        // tinycbor: `enum CborError cbor_parser_init(...)`. The weak stub TU
        // includes only auto_types.h, not the real header, so `enum CborError` is
        // an INCOMPLETE type there — clang rejects a function defined with an
        // incomplete result type. A weak fallback symbol has no cross-TU return-type
        // check (C has no return-type-based linkage), the real definition overrides
        // it when linked, and `int 0` is ABI-identical to the enum's `0`. So emit
        // `int`, not `enum CborError`.
        let decl = FakeDecl {
            name: "cbor_parser_init",
            return_type: "enum CborError",
            params: vec!["const uint8_t *".to_owned(), "size_t".to_owned()],
        };
        let stub = synth_c_stub(&decl).expect("enum return is stubbable");
        assert!(
            stub.contains("__attribute__((weak)) int cbor_parser_init("),
            "bare enum tag rewritten to int: {stub}"
        );
        assert!(
            !stub.contains("enum CborError"),
            "no incomplete enum: {stub}"
        );
        assert!(stub.contains("return 0;"), "{stub}");
        // A POINTER to an incomplete enum is fine (incomplete pointee allowed) —
        // leave `enum X *` untouched so the NULL-returning stub keeps its real type.
        let pdecl = FakeDecl {
            name: "cbor_last_error",
            return_type: "enum CborError *",
            params: vec!["void".to_owned()],
        };
        let pstub = synth_c_stub(&pdecl).expect("pointer return is stubbable");
        assert!(
            pstub.contains("enum CborError * cbor_last_error("),
            "enum pointer return untouched: {pstub}"
        );
    }

    /// Compile `stub` as a standalone C TU that mirrors the isolated weak-stub TU:
    /// the referenced aggregate and enum tags are only FORWARD-declared
    /// (incomplete), so any by-value use of an incomplete type fails exactly as in
    /// the auto build. No-ops when clang is unavailable (toolchain-less CI) rather
    /// than failing the suite.
    fn compile_stub_tu_or_skip(stub: &str) {
        use std::process::Command;
        use std::sync::atomic::{AtomicUsize, Ordering};
        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("clang unavailable; skipping stub-TU compile check");
            return;
        }
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gf_stub_tu_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let src = dir.join("stub_tu.c");
        // `enum json_error_code;` is forward-declared (INCOMPLETE) and the
        // aggregate is an incomplete struct — the same view the real stub TU has.
        let tu = format!(
            "#include <stddef.h>\n\
             typedef struct json_error_s json_error_t;\n\
             enum json_error_code;\n\
             {stub}"
        );
        std::fs::write(&src, &tu).expect("write TU");
        let out = Command::new("clang")
            .args(["-fsyntax-only", "-Wall"])
            .arg(&src)
            .output()
            .expect("clang invocation");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.status.success(),
            "emitted stub TU must compile (no incomplete-type by value); clang said:\n{stderr}\n--- TU ---\n{tu}"
        );
    }

    #[test]
    fn incomplete_enum_value_param_demoted_to_int_and_compiles() {
        // jansson: `void jsonp_error_set(json_error_t *, int, int, size_t,
        // enum json_error_code, const char *, ...)`. The weak stub TU sees only an
        // INCOMPLETE `enum json_error_code` (auto_types.h, never the real header),
        // and a function DEFINITION may not declare a by-value parameter of
        // incomplete type — clang: "variable has incomplete type
        // 'enum json_error_code'" (the actual auto_stubs.c:10 failure on jansson).
        // The by-value enum param must be demoted to `int`, exactly as the return
        // type is: the body ignores it and the weak symbol is overridden at link.
        let decl = FakeDecl {
            name: "jsonp_error_set",
            return_type: "void",
            params: vec![
                "json_error_t *".to_owned(),
                "int".to_owned(),
                "int".to_owned(),
                "size_t".to_owned(),
                "enum json_error_code".to_owned(),
                "const char *".to_owned(),
            ],
        };
        let stub = synth_c_stub(&decl).expect("void return is stubbable");
        // The incomplete-enum value param is rewritten to `int`; the genuine `int`
        // params and the pointer params are unaffected.
        assert!(
            stub.contains("size_t _gf_p3, int _gf_p4, const char * _gf_p5"),
            "incomplete enum value param demoted to int: {stub}"
        );
        assert!(
            !stub.contains("enum json_error_code"),
            "no incomplete enum value param survives: {stub}"
        );
        // And it actually compiles against a forward-declared (incomplete) enum.
        compile_stub_tu_or_skip(&stub);
    }

    #[test]
    fn incomplete_enum_param_variants_handled() {
        // `const enum TAG` by value is demoted; `enum TAG *` (pointer to an
        // incomplete type, which is legal) is left untouched.
        let decl = FakeDecl {
            name: "vendor_set",
            return_type: "void",
            params: vec![
                "const enum json_error_code".to_owned(),
                "enum json_error_code *".to_owned(),
            ],
        };
        let stub = synth_c_stub(&decl).expect("void return is stubbable");
        assert!(
            stub.contains("int _gf_p0, enum json_error_code * _gf_p1"),
            "const enum value demoted, enum pointer kept: {stub}"
        );
        compile_stub_tu_or_skip(&stub);
    }

    #[test]
    fn declared_stubs_are_weak_so_real_sources_can_override_them() {
        let decl = FakeDecl {
            name: "decoder_feed",
            return_type: "int",
            params: vec!["const uint8_t *".to_owned(), "size_t".to_owned()],
        };
        let stub = synth_c_stub(&decl).expect("supported");
        assert!(
            stub.contains("__attribute__((weak)) int decoder_feed("),
            "declared stub should be weak: {stub}",
        );
    }

    #[test]
    fn struct_by_value_return_bails() {
        let decl = FakeDecl {
            name: "make_point",
            return_type: "point_t",
            params: vec!["int".to_owned(), "int".to_owned()],
        };
        assert!(synth_c_stub(&decl).is_none());
    }

    #[test]
    fn synth_c_stub_handles_mz_ulong_return_type() {
        // Regression for `mz_uncompress`: c_stub_gen used to return
        // None for the `mz_ulong` return type, so auto fell through
        // to the blind-stub path and the symbol surfaced as
        // stubbed_symbols_blind. Today the declared path emits a
        // stub that returns 0.
        let decl = FakeDecl {
            name: "mz_uncompress",
            return_type: "mz_ulong",
            params: vec![
                "unsigned char *".to_owned(),
                "mz_ulong *".to_owned(),
                "const unsigned char *".to_owned(),
                "mz_ulong".to_owned(),
            ],
        };
        let stub = synth_c_stub(&decl).expect("supported");
        assert!(
            stub.contains("mz_ulong mz_uncompress("),
            "stub signature: {stub}"
        );
        assert!(stub.contains("return 0;"), "stub body: {stub}");
    }

    #[test]
    fn empty_return_type_renders_as_void() {
        struct EmptyRt;
        impl DeclarationView for EmptyRt {
            fn name(&self) -> &str {
                "init"
            }
            fn return_type(&self) -> &str {
                ""
            }
            fn param_types(&self) -> &[String] {
                &[]
            }
        }
        let stub = synth_c_stub(&EmptyRt).expect("supported");
        assert!(
            stub.starts_with("__attribute__((weak)) void init(void)"),
            "stub should treat empty return as void: {stub}"
        );
    }
}

#[cfg(test)]
mod aux_tests {
    use super::*;

    #[test]
    fn placeholder_header_is_pragma_once_only() {
        let h = synth_placeholder_header("internal/proprietary_alloc.h");
        assert!(h.contains("#pragma once"));
        assert!(h.contains("internal/proprietary_alloc.h"));
        assert!(h.contains("auto-synthesised"));
    }

    #[test]
    fn synth_idl_placeholder_header_emits_stub_decls() {
        // A CORBA/IDL-generated stub header (MessageC.h) that's absent codegen:
        // an EMPTY #pragma-once placeholder leaves every IDL-defined type and the
        // CORBA scaffolding types undefined, so the dependent TU cascades into
        // "unknown type" errors. The IDL placeholder must instead carry curated
        // CORBA stub typedefs + an opaque typedef for the interface's own base.
        let h = synth_idl_placeholder_header("src/idl/MessageC.h", &[]);
        // Still a real header.
        assert!(h.contains("#pragma once"), "{h}");
        assert!(h.contains("auto-synthesised"), "{h}");
        assert!(h.contains("src/idl/MessageC.h"), "{h}");
        // ...but NOT empty: it carries CORBA scaffolding typedefs.
        assert!(
            h.contains("typedef"),
            "IDL placeholder must emit a typedef: {h}"
        );
        assert!(h.contains("CORBA_Object"), "{h}");
        assert!(h.contains("CORBA_long"), "{h}");
        // ...and an opaque typedef keyed off the interface base name.
        assert!(h.contains("Message"), "opaque base typedef: {h}");
        // Caller-supplied decls land verbatim.
        let h2 = synth_idl_placeholder_header("bankC.h", &["typedef long Account;".to_owned()]);
        assert!(h2.contains("typedef long Account;"), "{h2}");
        // The empty placeholder is untouched: still pragma-once only, no typedef.
        let empty = synth_placeholder_header("internal/proprietary_alloc.h");
        assert!(!empty.contains("typedef"), "{empty}");
    }

    #[test]
    fn typedef_placeholder_uses_void_pointer_alias() {
        let t = synth_typedef_placeholder("Widget");
        assert!(t.contains("typedef void *Widget;"));
        assert!(t.contains("auto-synthesised"));
    }

    #[test]
    fn cpp_stdlib_header_maps_known_families() {
        assert_eq!(cpp_stdlib_header("ostrstream"), Some("strstream"));
        assert_eq!(cpp_stdlib_header("streamoff"), Some("ios"));
        assert_eq!(cpp_stdlib_header("std::streampos"), Some("ios"));
        assert_eq!(cpp_stdlib_header("ofstream"), Some("fstream"));
        assert_eq!(cpp_stdlib_header("Widget"), None);
        assert_eq!(cpp_stdlib_header("mz_ulong"), None);
    }

    #[test]
    fn typedef_placeholder_is_always_void_alias_even_for_stdlib_names() {
        // The void* path must never emit a stdlib include: it is force-include
        // unsafe (would collide with real definitions). The stdlib include
        // lives in synth_cpp_stdlib_include instead.
        let t = synth_typedef_placeholder("ostrstream");
        assert!(t.contains("typedef void *ostrstream;"), "{t}");
        assert!(!t.contains("#include"), "{t}");
    }

    #[test]
    fn cpp_stdlib_include_uses_real_header_for_bare_type() {
        let t = synth_cpp_stdlib_include("ostrstream").expect("stdlib type");
        // Real definition, not a void* alias that would corrupt semantics.
        assert!(t.contains("#include <strstream>"), "{t}");
        assert!(t.contains("using std::ostrstream;"), "{t}");
        assert!(t.contains("#ifdef __cplusplus"), "{t}");
        assert!(!t.contains("typedef void *"), "{t}");
    }

    #[test]
    fn cpp_stdlib_include_skips_using_for_qualified_type() {
        // Already namespace-qualified: the include alone resolves it; a
        // `using std::std::streamoff` would be malformed.
        let t = synth_cpp_stdlib_include("std::streamoff").expect("stdlib type");
        assert!(t.contains("#include <ios>"), "{t}");
        assert!(!t.contains("using std::"), "{t}");
    }

    #[test]
    fn cpp_stdlib_include_is_none_for_non_stdlib_type() {
        assert!(synth_cpp_stdlib_include("Widget").is_none());
        assert!(synth_cpp_stdlib_include("RealT").is_none());
    }

    #[test]
    fn c_std_types_resolve_to_their_header_not_a_void_alias() {
        assert_eq!(c_std_header("uint32_t"), Some("stdint.h"));
        assert_eq!(c_std_header("int8_t"), Some("stdint.h"));
        assert_eq!(c_std_header("size_t"), Some("stddef.h"));
        assert_eq!(c_std_header("ptrdiff_t"), Some("stddef.h"));
        assert_eq!(c_std_header("bool"), Some("stdbool.h"));
        assert_eq!(c_std_header("_Bool"), Some("stdbool.h"));
        assert_eq!(c_std_header("widget_t"), None);
        let inc = synth_c_std_include("uint32_t").expect("stdint type");
        assert!(inc.contains("#include <stdint.h>"), "{inc}");
        // Unguarded (valid in C and C++) and no void* alias.
        assert!(!inc.contains("__cplusplus"), "{inc}");
        assert!(!inc.contains("typedef void"), "{inc}");
    }

    #[test]
    fn integer_alias_maps_known_embedded_families() {
        assert_eq!(c_integer_alias("int8"), Some("int8_t"));
        assert_eq!(c_integer_alias("int16"), Some("int16_t"));
        assert_eq!(c_integer_alias("int32"), Some("int32_t"));
        assert_eq!(c_integer_alias("int64"), Some("int64_t"));
        assert_eq!(c_integer_alias("uint8"), Some("uint8_t"));
        assert_eq!(c_integer_alias("uint16"), Some("uint16_t"));
        assert_eq!(c_integer_alias("uint32"), Some("uint32_t"));
        assert_eq!(c_integer_alias("uint64"), Some("uint64_t"));
        assert_eq!(c_integer_alias("const uint32"), Some("uint32_t"));
        // Standard names already resolve via c_std_header, not here.
        assert_eq!(c_integer_alias("int32_t"), None);
        // Width-ambiguous / unknown aliases must NOT be guessed.
        assert_eq!(c_integer_alias("uint"), None);
        assert_eq!(c_integer_alias("boolean"), None);
        assert_eq!(c_integer_alias("widget_t"), None);
    }

    #[test]
    fn integer_alias_typedef_is_sound_not_void_star() {
        // Regression: cFE/OSAL `int32`,`uint16`,... used to become
        // `typedef void *int32;`, which corrupts every arithmetic/pointer use
        // and cascades the whole common_types.h chain into failed_build.
        let t = synth_c_integer_alias_typedef("uint32").expect("known alias");
        assert!(t.contains("#include <stdint.h>"), "{t}");
        assert!(t.contains("typedef uint32_t uint32;"), "{t}");
        assert!(!t.contains("void *"), "{t}");
        assert!(synth_c_integer_alias_typedef("const int16").is_some());
        assert!(synth_c_integer_alias_typedef("Widget").is_none());
    }

    #[test]
    fn synth_struct_from_field_paths_builds_nested_struct() {
        // cFE CCSDS shape: MsgPtr->CCSDS.Pri.StreamId[0..1] and ...Pri.Sequence.
        let paths = vec![
            FieldPath {
                components: vec!["CCSDS".into(), "Pri".into(), "StreamId".into()],
                leaf_indexed: true,
                max_index: 1,
            },
            FieldPath {
                components: vec!["CCSDS".into(), "Pri".into(), "Sequence".into()],
                leaf_indexed: false,
                max_index: 0,
            },
        ];
        let s = synth_struct_from_field_paths("CFE_MSG_Message_t", &paths).expect("paths present");
        assert!(s.contains("typedef struct {"), "{s}");
        assert!(s.contains("} CFE_MSG_Message_t;"), "{s}");
        assert!(s.contains("struct {"), "{s}"); // nested CCSDS / Pri
        assert!(s.contains("unsigned char StreamId[2];"), "{s}"); // max_index 1 -> [2]
        assert!(s.contains("unsigned long Sequence;"), "{s}"); // scalar leaf
        assert!(!s.contains("void *"), "{s}");
    }

    #[test]
    fn synth_struct_from_field_paths_none_when_empty() {
        assert!(synth_struct_from_field_paths("T", &[]).is_none());
    }

    #[test]
    fn synth_struct_tag_completes_named_tag_without_typedef() {
        // When a real header already does `typedef struct CFE_MSG_Message
        // CFE_MSG_Message_t;`, complete the *tag* to avoid a typedef clash.
        let paths = vec![FieldPath {
            components: vec!["CCSDS".into(), "Pri".into(), "StreamId".into()],
            leaf_indexed: true,
            max_index: 1,
        }];
        let s = synth_struct_tag_from_field_paths(
            "CFE_MSG_Message",
            false,
            "CFE_MSG_Message_t",
            &paths,
        )
        .expect("paths present");
        assert!(s.contains("struct CFE_MSG_Message {"), "{s}");
        // identical redefinition of the real typedef (legal C11), so the typedef
        // name resolves whether or not the real header is reached.
        assert!(
            s.contains("typedef struct CFE_MSG_Message CFE_MSG_Message_t;"),
            "{s}"
        );
        assert!(s.contains("unsigned char StreamId[2];"), "{s}");
        assert!(synth_struct_tag_from_field_paths("U", true, "U_t", &paths)
            .unwrap()
            .contains("union U {"));
    }

    #[test]
    fn blind_stub_returns_null_pointer_to_zero_return_register() {
        // Pointer return zeroes RAX/x0 so a caller treating the result as a
        // pointer reads NULL and its `if (ptr)` guard short-circuits, instead of
        // freeing a garbage register value (#388).
        let s = synth_blind_stub("vendor_log_warn");
        assert!(s.contains("void *vendor_log_warn(void)"), "blind stub: {s}");
        assert!(s.contains("return (void *)0;"));
    }

    #[test]
    fn blind_stubs_are_weak_so_real_sources_can_override_them() {
        let s = synth_blind_stub("vendor_table");
        assert!(
            s.contains("__attribute__((weak)) void *vendor_table(void)"),
            "blind stub should be weak: {s}",
        );
    }

    #[test]
    fn va_list_and_file_resolve_to_system_headers_not_void_placeholders() {
        // A `void *` placeholder for a standard type collides with the real typedef
        // pulled in by a system header (jansson's `va_list` param ->
        // "typedef redefinition '__gnuc_va_list' vs 'void *'"). These must
        // force-include the providing header instead.
        assert_eq!(c_std_header("va_list"), Some("stdarg.h"));
        assert_eq!(c_std_header("__gnuc_va_list"), Some("stdarg.h"));
        assert_eq!(c_std_header("__builtin_va_list"), Some("stdarg.h"));
        assert_eq!(c_std_header("FILE"), Some("stdio.h"));
        // synth_c_std_include (tried before the placeholder) emits the include.
        assert!(synth_c_std_include("va_list")
            .unwrap()
            .contains("#include <stdarg.h>"));
    }
}
