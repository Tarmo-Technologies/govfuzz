// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use type_model::{Field, ScalarKind, TypeRegistry, TypeShape};

/// Default recursion depth for nested struct/union/array field synthesis.
const MAX_DECODE_DEPTH: usize = 4;
/// Default per-array element-decode cap (a larger fixed array fuzzes its fill
/// count `0..cap` instead of decoding every slot — see `emit_array_decode`).
const MAX_ARRAY_ELEMS: usize = 64;
/// Default byte ceiling on a single parameter's synthesised decoder body, past
/// which the parameter is rejected (a runaway struct synthesis would otherwise
/// emit megabytes of init code).
const MAX_DECL_BYTES: usize = 64 * 1024;

/// Tunable caps for the C decoder's struct/array synthesis (§27.11). Defaults
/// reproduce the historical hardcoded constants EXACTLY, so a default-limits run
/// is byte-identical to the pre-§27.11 emission; the CLI flags
/// `--max-decode-depth` / `--max-array-elems` / `--max-decl-bytes` override them
/// per target for tuning a deep/wide legacy aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderLimits {
    /// Max recursion depth for nested struct/union/array field synthesis
    /// (default [`MAX_DECODE_DEPTH`]). Past it a field is left zeroed.
    pub depth: usize,
    /// Max number of array elements decoded per fixed array (default
    /// [`MAX_ARRAY_ELEMS`]); a larger array fuzzes its fill count `0..cap`.
    pub array_elems: usize,
    /// Byte ceiling on a parameter's whole synthesised decoder body (default
    /// [`MAX_DECL_BYTES`]); a larger body rejects the parameter.
    pub decl_bytes: usize,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        DecoderLimits {
            depth: MAX_DECODE_DEPTH,
            array_elems: MAX_ARRAY_ELEMS,
            decl_bytes: MAX_DECL_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CDecoderError {
    reason: String,
}

impl CDecoderError {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for CDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for CDecoderError {}

#[derive(Debug, Clone, Serialize)]
pub struct CParamEmission {
    /// Optional file-scope support code, e.g. callback trampolines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<String>,
    pub decl: String,
    pub arg: String,
    pub c_type: String,
    /// Optional cleanup statement, e.g. `free(s)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free: Option<String>,
}

/// An init / delete pair for an opaque handle type, discovered among the
/// target's sibling functions. When a parameter is a pointer to an opaque
/// struct whose fields cannot be synthesised (e.g. libyaml's `yaml_parser_t`,
/// which must be set up by `yaml_parser_initialize` rather than zero-filled),
/// the decoder stack-allocates the handle, calls `init` before the target
/// call and `delete` after, instead of bailing with "needs lifecycle support".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CHandleLifecycle {
    /// Canonical handle base type, no pointer — e.g. `yaml_parser_t`.
    pub handle_type: String,
    /// Constructor, if found. By default a single-argument in-place initializer
    /// (`void foo_init(T *)`); when [`init_returns_handle`](Self::init_returns_handle)
    /// is set it is instead a returning constructor (`T *foo_new(void)`).
    pub init: Option<String>,
    /// Single-argument (handle pointer only) destructor, if found.
    pub delete: Option<String>,
    /// When true, `init` is a returning constructor (`T *foo_new(void)`) and the
    /// handle is the *return value*, passed by value to the target and freed as
    /// `delete(handle)`. When false (the default), `init` fills a stack handle
    /// in place and the harness passes/free `&handle`.
    pub init_returns_handle: bool,
    /// Neutral argument expressions for a *returning* constructor that takes
    /// parameters (`T *foo_create(const char *opt)` -> `["NULL"]`). The
    /// "use defaults" idiom: pointer config args are passed as `NULL`
    /// (`XML_ParserCreate(NULL)`, `archive_read_new()`). Empty for a zero-arg
    /// constructor. Ignored for in-place initializers, which always receive
    /// `&storage`.
    pub init_args: Vec<String>,
}

/// Canonical comparison key for an opaque-handle type spelling. Collapses a
/// leading elaborated tag (`struct X` / `union X` / `enum X`) to the bare tag
/// name and trims surrounding whitespace, so a handle the parser spells WITH the
/// tag in one position and WITHOUT it in another resolves to ONE key.
///
/// This matters for returning-constructor discovery: a prototype like
/// `struct libdeflate_decompressor *libdeflate_alloc_decompressor(void)` loses
/// its `struct` keyword during return-type normalization (becoming
/// `libdeflate_decompressor *`), while the matching destructor parameter and the
/// target's own parameter keep it (`struct libdeflate_decompressor *`). Without
/// this collapse the constructor and destructor land under two distinct table
/// entries and the lifecycle is never paired, so the opaque handle is skipped as
/// having "no returning-constructor lifecycle".
pub fn normalize_handle_key(raw: &str) -> &str {
    let trimmed = raw.trim();
    for tag in ["struct ", "union ", "enum "] {
        if let Some(rest) = trimmed.strip_prefix(tag) {
            return rest.trim();
        }
    }
    trimmed
}

fn lookup_lifecycle<'a>(
    lifecycle: &'a [CHandleLifecycle],
    handle_type: &str,
) -> Option<&'a CHandleLifecycle> {
    let key = normalize_handle_key(handle_type);
    lifecycle
        .iter()
        .find(|entry| normalize_handle_key(&entry.handle_type) == key)
}

/// Render a libFuzzer-style decoder for the given C type name and parameter
/// name. Returns `None` for unsupported types so the caller can bail with a
/// clear UnsupportedParamType error.
pub fn select_c_decoder(c_type: &str, name: &str) -> Option<CParamEmission> {
    if let Some(underlying) = normalize_win32_typedef(c_type) {
        return select_c_decoder(underlying, name);
    }
    legacy_select_c_decoder(c_type, name)
}

/// Rewrite a standard Win32 POINTER typedef to its underlying C pointer type so
/// the normal byte-buffer / C-string decoders can drive it.
///
/// The Win32 *scalar* typedefs (`BOOL`, `DWORD`, `WORD`, `BYTE`, `UINT`, …) are
/// NOT here: `type_model`'s Win32 scalar table (`WIN32_INTEGER_TYPEDEFS`) already
/// resolves them to a `TypeShape::Scalar` while KEEPING the alias spelling in the
/// emitted decl (`BOOL flag = (BOOL)gf_i32(&Cur)`), which is what compiles once
/// the target's own header / the synthesized `windows.h` defines the alias. This
/// helper only closes the POINTER gap those scalars don't cover — a `PUCHAR data`
/// param would otherwise resolve opaque and skip the target "needs lifecycle
/// support (Phase C)".
///
/// The mapping is reconciled against `WINDOWS_H_STUB` in
/// `crates/cli/src/auto/cross_target.rs` so the driver's decoded type matches the
/// compiled type: `PUCHAR`/`LPBYTE` are `unsigned char *` (byte buffers) and
/// `LPCSTR`/`LPCTSTR`/`LPSTR`/`LPTSTR` are C strings there. Opaque handle pointers
/// (`HANDLE`, `HWND`, `LPVOID`, `HINSTANCE`) are deliberately EXCLUDED — the stub
/// makes them `void *` and the existing pointer-lifecycle path owns them (see the
/// `HANDLE`/`HWND`/`LPVOID` stay-opaque assertions in `type_model`). MFC *class*
/// types like `CString` are also out of scope (constructing a class arg).
fn normalize_win32_typedef(c_type: &str) -> Option<&'static str> {
    Some(match c_type.trim() {
        // Byte-buffer pointers — driven from the fuzz `(Data, Size)` buffer.
        "PUCHAR" | "PBYTE" | "LPBYTE" => "unsigned char *",
        // C-string pointers — driven from a NUL-terminated fuzz C string.
        "LPCSTR" | "LPCTSTR" | "PCSTR" => "const char *",
        "LPSTR" | "LPTSTR" | "PSTR" => "char *",
        _ => return None,
    })
}

pub fn select_c_decoder_with_registry(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_with_lifecycle(c_type, name, registry, &[])
}

/// Like [`select_c_decoder_with_registry`], but emits C++-safe aggregate locals
/// (value-init `T x{};`, no `memset`). The C++ fallback path uses this so a
/// by-value class/struct param compiles even when it has non-trivial members.
pub fn select_c_decoder_with_registry_cpp(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_inner(
        c_type,
        name,
        registry,
        &[],
        true,
        None,
        DecoderLimits::default(),
    )
}

/// Like [`select_c_decoder_with_registry_cpp`] but constructs a pointer to an
/// opaque handle through a discovered init/delete FREE-function lifecycle, instead
/// of bailing "needs lifecycle support". The C++ direct harness uses this for a
/// C-ABI decode entry whose first parameter is an opaque context the fuzzer must
/// build via `new`/`free` (libde265 `de265_decode_data(de265_decoder_context *,
/// const void *, int)` -> `ctx = de265_new_decoder(); …; de265_free_decoder(ctx)`).
/// The construction is plain C, valid in a C++ translation unit.
pub fn select_c_decoder_with_lifecycle_cpp(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_inner(
        c_type,
        name,
        registry,
        lifecycle,
        true,
        None,
        DecoderLimits::default(),
    )
}

/// Like [`select_c_decoder_with_registry`] but, for a pointer to an opaque
/// handle type that has a discovered `init`/`delete` pair, constructs the
/// handle through its lifecycle functions rather than failing.
pub fn select_c_decoder_with_lifecycle(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_with_lifecycle_with_limits(
        c_type,
        name,
        registry,
        lifecycle,
        DecoderLimits::default(),
    )
}

/// Like [`select_c_decoder_with_lifecycle`], but with caller-supplied
/// [`DecoderLimits`] (§27.11) instead of the defaults. Used by the C harness
/// build path so `--max-decode-depth` / `--max-array-elems` / `--max-decl-bytes`
/// actually bound struct/array synthesis.
pub fn select_c_decoder_with_lifecycle_with_limits(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
    limits: DecoderLimits,
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_inner(c_type, name, registry, lifecycle, false, None, limits)
}

/// Like [`select_c_decoder_with_lifecycle`], but additionally enforces that an
/// opaque handle the lifecycle would STACK-ALLOCATE (`{raw} storage; init(&storage)`
/// or the destructor-only `memset` form) is COMPLETE in the harness's included
/// headers. `header_complete` lists the struct/union spellings whose full definition
/// the harness translation unit can see (`struct X {...}` textually present in an
/// included header). When the handle's struct is NOT in that set — its body lives
/// only in a non-included `.c` (tidwall/hashmap.c's `struct hashmap`) — stack
/// allocation would be an illegal "variable has incomplete type" declaration, so the
/// decoder returns a `CDecoderError` and the target is cleanly SKIPPED instead. The
/// returning-constructor lifecycle (`T *foo_new(void)`) needs no complete type and is
/// unaffected. The C path of `govfuzz auto` uses this; the permissive
/// [`select_c_decoder_with_lifecycle`] (no oracle) keeps the legacy behavior.
pub fn select_c_decoder_with_lifecycle_strict(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
    header_complete: &HashSet<String>,
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_with_lifecycle_strict_with_limits(
        c_type,
        name,
        registry,
        lifecycle,
        header_complete,
        DecoderLimits::default(),
    )
}

/// Like [`select_c_decoder_with_lifecycle_strict`], but with caller-supplied
/// [`DecoderLimits`] (§27.11). The C `auto` path threads the CLI-configured
/// limits through here.
pub fn select_c_decoder_with_lifecycle_strict_with_limits(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
    header_complete: &HashSet<String>,
    limits: DecoderLimits,
) -> Result<CParamEmission, CDecoderError> {
    select_c_decoder_inner(
        c_type,
        name,
        registry,
        lifecycle,
        false,
        Some(header_complete),
        limits,
    )
}

fn select_c_decoder_inner(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
    cpp: bool,
    header_complete: Option<&HashSet<String>>,
    limits: DecoderLimits,
) -> Result<CParamEmission, CDecoderError> {
    // #466: a parameter type with unbalanced parentheses is a malformed fragment of
    // an inline function-pointer that an upstream parse split on the funcptr's inner
    // comma (`int (*cb)(int` and the spurious `int)`). Scalar-decoding the fragment
    // emits a broken `gf_i32` harness that fails to BUILD; skip the target cleanly
    // instead. A well-formed funcptr (`int (*)(int, int)`) is balanced and reaches
    // the trampoline path below. (Keeping inline funcptr params intact upstream +
    // synthesising a trampoline is the deeper fix — ROADMAP §27.9.)
    if c_type.matches('(').count() != c_type.matches(')').count() {
        return Err(CDecoderError::new(format!(
            "parameter '{name}' has a malformed (unbalanced-paren) type '{c_type}', likely a \
             split inline function-pointer; not auto-harnessable"
        )));
    }

    // A standard Win32 typedef (`PUCHAR`, `DWORD`, `BOOL`, …) is unknown to the
    // decoder at harness-generation time — the repair loop injects the synthesized
    // `windows.h` defining it only later, at build time — so normalize it to its
    // underlying C type up front and re-dispatch. The underlying types (`int`,
    // `unsigned char *`, …) are not themselves in the map, so this terminates.
    if let Some(underlying) = normalize_win32_typedef(c_type) {
        return select_c_decoder_inner(
            underlying,
            name,
            registry,
            lifecycle,
            cpp,
            header_complete,
            limits,
        );
    }

    if let Some(emission) = ownership_flag_pinned(c_type, name) {
        return Ok(emission);
    }

    if let Some(emission) = control_flag_pinned(c_type, name) {
        return Ok(emission);
    }

    if let Some(emission) = allocator_callbacks_nulled(c_type, name) {
        return Ok(emission);
    }

    // A typedef'd interior/opaque handle (`sds` = `typedef char *sds`) that the
    // tree constructs with a self-returning constructor must be built via that
    // constructor, NOT decoded as a raw string/buffer: the pointer points INTO a
    // malloc'd `{header; data}` block, so feeding raw bytes makes the accessors
    // read the `s[-1]` header out of bounds (a guaranteed GF-201 FP). This runs
    // BEFORE the char*/void* short-circuits below. A bare `char *` carries `*`/
    // whitespace in its spelling and never matches a handle_type, so it is
    // unaffected and stays a string decode input.
    if let Some(emission) = typedef_handle_via_returning_ctor(c_type, name, lifecycle) {
        return Ok(emission);
    }

    if let Some(emission) = legacy_select_c_decoder(c_type, name) {
        return Ok(emission);
    }

    if let Some(signature) = registry.function_pointer_signature(c_type) {
        return callback_trampoline(c_type, name, &signature);
    }

    let shape = registry.resolve(c_type);
    let pointer_base_hint = registry.pointer_base_spelling(c_type);
    let mut ctx = DecodeContext::new(registry, cpp, limits);
    ctx.header_complete = header_complete;
    let decl_type = emit_c_type(c_type);
    let arg = emit_top_level_value(
        &mut ctx,
        &decl_type,
        name,
        &shape,
        pointer_base_hint.as_deref(),
        lifecycle,
    )?;
    let decl = ctx.statements.join("; ");
    if decl.len() > limits.decl_bytes {
        return Err(CDecoderError::new(format!(
            "decoder for parameter '{name}' exceeds {} bytes after struct synthesis",
            limits.decl_bytes
        )));
    }
    // File-scope callback trampolines synthesised for any function-pointer fields.
    let support = (!ctx.support.is_empty()).then(|| ctx.support.join("\n"));
    Ok(CParamEmission {
        support,
        decl,
        arg,
        c_type: decl_type,
        free: ctx.cleanup(),
    })
}

/// Build a single-identifier typedef interior/opaque handle (redis `sds`) via its
/// self-returning constructor recorded in the lifecycle table, instead of letting
/// it decay to the raw-string/buffer decoder (which underflows the handle's
/// negative-offset header). Returns `None` for any spelling that carries a
/// pointer/array/decoration (a bare `char *`, or a `T *` struct handle — the
/// latter is handled by the shape path's lifecycle branch) or that has no
/// returning-constructor lifecycle entry.
fn typedef_handle_via_returning_ctor(
    c_type: &str,
    name: &str,
    lifecycle: &[CHandleLifecycle],
) -> Option<CParamEmission> {
    let bare = c_type
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim();
    if bare.is_empty() || !bare.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let entry = lookup_lifecycle(lifecycle, bare)?;
    if !entry.init_returns_handle {
        return None;
    }
    let init = entry.init.as_ref()?;
    let args = entry.init_args.join(", ");
    Some(CParamEmission {
        support: None,
        decl: format!("{bare} {name} = {init}({args})"),
        arg: name.to_owned(),
        c_type: bare.to_owned(),
        free: entry.delete.as_ref().map(|d| format!("{d}({name})")),
    })
}

/// Build a callback trampoline's file-scope support code (a re-declared typedef +
/// a `static` no-op definition matching the parsed signature) and the trampoline's
/// function name. Shared by the callback PARAMETER path and the struct-field path
/// (#454); `name` seeds the unique trampoline identifier.
fn build_callback_trampoline(
    c_type: &str,
    name: &str,
    signature: &str,
) -> Result<(String, String), CDecoderError> {
    // An inline (anonymous) function-pointer — `void handle(int (*cb)(int, int))`
    // — carries its signature in `c_type` itself (`int (*)(int, int)`) with no
    // project typedef to name, so a `_gf_cb_<name>` is synthesized below. A
    // typedef'd callback references its existing typedef name.
    let inline = c_type.contains("(*");
    // A `restrict`-qualifier macro inside the callback's inner parameters
    // (xxHash's `typedef void (*XXH3_f_accumulate)(xxh_u64* XXH_RESTRICT, ...)`)
    // is, like `restrict`/`__restrict`, a qualifier — not a parameter name. The
    // grammar cannot expand the project macro, so it is mistaken for the (often
    // unnamed) parameter's name and emitted into both the re-declared typedef and
    // the trampoline signature: multiple `XXH_RESTRICT` params then collide
    // (`redefinition of parameter 'XXH_RESTRICT'`). Strip it from the signature
    // once so every downstream use (typedef line, parsed params, `(void)name;`) is
    // clean.
    let signature = strip_restrict_qualifier_macros(signature);
    let signature = signature.as_str();
    let Some(parsed) = parse_callback_signature(signature) else {
        return Err(CDecoderError::new(format!(
            "callback '{name}' has unsupported function-pointer signature '{signature}'"
        )));
    };
    let trampoline = format!("_gf_{}_trampoline", sanitize_ident(name));
    let mut decl_params = Vec::new();
    let mut body = String::new();
    for (index, param) in parsed.params.iter().enumerate() {
        // A variadic `...` (tinycbor's `CborStreamFunction(void *, const char *,
        // ...)`) cannot be named or referenced — `... _gf_arg2` is a syntax error
        // ("expected ')'") and `(void)_gf_arg2;` then fails. Emit the ellipsis
        // verbatim; the no-op trampoline never touches the varargs.
        if param.trim() == "..." {
            decl_params.push("...".to_owned());
            continue;
        }
        // A definition (unlike a declaration) must name every parameter
        // before C23, so unnamed params get a synthesized name.
        match callback_param_name(param) {
            Some(param_name) => {
                decl_params.push(param.clone());
                body.push_str(&format!("    (void){param_name};\n"));
            }
            None => {
                let synthesized = format!("_gf_arg{index}");
                decl_params.push(named_callback_param(param, &synthesized));
                body.push_str(&format!("    (void){synthesized};\n"));
            }
        }
    }
    let params = if decl_params.is_empty() {
        "void".to_owned()
    } else {
        decl_params.join(", ")
    };
    if parsed.return_type.trim() != "void" {
        body.push_str("    return 0;\n");
    }
    // The generated main.c forward-declares the target instead of including
    // project headers, so the typedef behind the callback must be re-declared
    // before the prototype + trampoline that reference it. (C11 permits identical
    // typedef redefinitions should a project header also end up included.) An
    // inline funcptr has no project typedef, so a fresh `_gf_cb_<name>` is
    // synthesized; the parameter path recomputes the same name for the decl type.
    let typedef_name = if inline {
        format!("_gf_cb_{}", sanitize_ident(name))
    } else {
        c_type
            .split_whitespace()
            .filter(|token| !matches!(*token, "const" | "volatile"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let support = format!(
        "typedef {};\nstatic {} {}({}) {{\n{}}}",
        signature.replacen("(*)", &format!("(*{typedef_name})"), 1),
        parsed.return_type,
        trampoline,
        params,
        body
    );
    Ok((support, trampoline))
}

fn callback_trampoline(
    c_type: &str,
    name: &str,
    signature: &str,
) -> Result<CParamEmission, CDecoderError> {
    let (support, trampoline) = build_callback_trampoline(c_type, name, signature)?;
    // An inline funcptr param uses the synthesized `_gf_cb_<name>` typedef as its
    // type (matching the one `build_callback_trampoline` declared); a typedef'd
    // callback uses its existing type.
    let decl_type = if c_type.contains("(*") {
        format!("_gf_cb_{}", sanitize_ident(name))
    } else {
        emit_c_type(c_type)
    };
    Ok(CParamEmission {
        support: Some(support),
        // Cast the trampoline to the callback type. The trampoline's signature is
        // derived from the tree-parsed typedef, which can differ from the header's
        // preprocessor-resolved one (inih's `ini_handler` is 4-param by default,
        // but the tree also has a 5-param `#if INI_HANDLER_LINENO` branch).
        // Assigning the trampoline directly is then an incompatible-function-pointer
        // error under modern clang; the explicit cast assigns cleanly, and the
        // trampoline ignores every argument so the mismatch is harmless at runtime.
        // For an inline funcptr the cast is to the synthesized `_gf_cb_<name>` type
        // the trampoline already has, so it is a harmless no-op there.
        decl: format!("{decl_type} {name} = ({decl_type}){trampoline}"),
        arg: name.to_owned(),
        c_type: decl_type,
        free: None,
    })
}

#[derive(Debug, Clone)]
struct CallbackSignature {
    return_type: String,
    params: Vec<String>,
}

fn parse_callback_signature(signature: &str) -> Option<CallbackSignature> {
    // Function-pointer spelling: `RET (* [name])(params)`. The declarator group
    // is the first parenthesized run whose contents start with `*` — tolerating
    // arbitrary whitespace (`(*)`, `(* )`, `( * )`) and a still-present
    // declarator name (`(*name)`), since the canonical form may blank a typedef
    // name to a space (FreeRTOS `(* PendedFunction_t)` -> `(* )`). The parameter
    // list is the next parenthesized group.
    let decl_open = signature.find('(')?;
    let return_type = signature[..decl_open].trim().to_owned();
    if return_type.is_empty() {
        return None;
    }
    let decl_close_rel = signature[decl_open..].find(')')?;
    let decl_close = decl_open + decl_close_rel;
    if !signature[decl_open + 1..decl_close]
        .trim_start()
        .starts_with('*')
    {
        return None;
    }
    let rest = signature[decl_close + 1..].trim();
    let params = rest.strip_prefix('(')?.strip_suffix(')')?.trim();
    let params = if params.is_empty() || params == "void" {
        Vec::new()
    } else {
        params
            .split(',')
            .map(|param| param.trim().to_owned())
            .filter(|param| !param.is_empty())
            .collect()
    };
    Some(CallbackSignature {
        return_type,
        params,
    })
}

/// Whether `tok` is a `restrict`-style qualifier — the keyword spellings
/// (`restrict`/`__restrict`/`__restrict__`) or a project macro that expands to one
/// (xxHash's `XXH_RESTRICT`, the conventional `RESTRICT`/`_Restrict`). It sits in
/// the QUALIFIER position and must never be treated as a parameter name.
fn is_restrict_qualifier_token(tok: &str) -> bool {
    // Whole-word against the macro convention: any underscore-separated segment is
    // exactly `restrict` (catches `restrict`, `__restrict`, `__restrict__`,
    // `XXH_RESTRICT`, glibc's `__restrict_arr`) while sparing `restrictions`.
    tok.to_ascii_lowercase()
        .split('_')
        .any(|seg| seg == "restrict")
}

/// Remove `restrict`-qualifier macro/keyword tokens from a type or
/// function-pointer signature string, collapsing the whitespace they leave behind
/// (`void (*)(xxh_u64* XXH_RESTRICT, size_t)` -> `void (*)(xxh_u64*, size_t)`).
/// Identifier runs are checked whole-word so `restrictions`/`__restricted` survive.
fn strip_restrict_qualifier_macros(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut ident = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            ident.push(ch);
            continue;
        }
        if !ident.is_empty() {
            if !is_restrict_qualifier_token(&ident) {
                out.push_str(&ident);
            }
            ident.clear();
        }
        out.push(ch);
    }
    if !ident.is_empty() && !is_restrict_qualifier_token(&ident) {
        out.push_str(&ident);
    }
    // Collapse the gaps a removed qualifier leaves: runs of spaces, and a space
    // sitting just before a `,` or `)`.
    let mut cleaned = String::with_capacity(out.len());
    let mut prev_space = false;
    for ch in out.chars() {
        if ch == ' ' {
            if prev_space {
                continue;
            }
            prev_space = true;
            cleaned.push(ch);
        } else {
            if (ch == ',' || ch == ')') && cleaned.ends_with(' ') {
                cleaned.pop();
            }
            prev_space = false;
            cleaned.push(ch);
        }
    }
    cleaned.trim().to_owned()
}

fn callback_param_name(param: &str) -> Option<String> {
    let without_array = param.split('[').next().unwrap_or(param).trim();
    // Split on '*' as well as whitespace so "const void*" yields type
    // tokens, not a bogus "void*" name.
    let tokens: Vec<&str> = without_array
        .split(|c: char| c.is_whitespace() || c == '*')
        .filter(|token| !token.is_empty())
        .collect();
    let last = tokens.last()?;
    if !is_c_identifier(last) || is_likely_type_only_param_name(last) {
        return None;
    }
    // A lone identifier is the type of an unnamed param ("mz_uint"), and
    // an identifier right after struct/union/enum is a tag, not a name.
    if tokens.len() == 1 {
        return None;
    }
    if matches!(tokens[tokens.len() - 2], "struct" | "union" | "enum") {
        return None;
    }
    // "const foo" can only be a qualified unnamed type — a parameter
    // needs a type before its name, and a qualifier alone is not one.
    if tokens.len() == 2 && matches!(tokens[0], "const" | "volatile" | "restrict") {
        return None;
    }
    Some((*last).to_owned())
}

fn is_c_identifier(token: &str) -> bool {
    let mut chars = token.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Attach a synthesized name to an unnamed parameter type, keeping array
/// suffixes after the name ("int [4]" -> "int _gf_arg0[4]").
fn named_callback_param(param: &str, name: &str) -> String {
    match param.find('[') {
        Some(bracket) => {
            let (base, array) = param.split_at(bracket);
            format!("{} {name}{array}", base.trim())
        }
        None => format!("{} {name}", param.trim()),
    }
}

fn is_likely_type_only_param_name(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "unsigned"
            | "signed"
            | "float"
            | "double"
            | "size_t"
            | "ssize_t"
            | "uint8_t"
            | "int8_t"
            | "uint16_t"
            | "int16_t"
            | "uint32_t"
            | "int32_t"
            | "uint64_t"
            | "int64_t"
    )
}

fn legacy_select_c_decoder(c_type: &str, name: &str) -> Option<CParamEmission> {
    let normalized = canonical_c_type_for_decoder(c_type);
    // An image/audio channel- or component-COUNT parameter is a tiny enum (1..4
    // channels), not a free integer. Fuzzing it as a full-range int makes a decode
    // entry reject nearly every input on an invalid component count and never run:
    // jpgd `decompress_jpeg_image_from_memory`'s `req_comps` must be 0/1/3/4, so a
    // full-range `gf_i32` was valid ~0% of the time and coverage stalled at the
    // header-reject path (110 edges). Bound it small so valid counts are hit often
    // and the decoder body is actually exercised.
    if is_channel_count_name(name) {
        if let Some(ty) = small_int_decl_type(normalized.as_str()) {
            return Some(scalar(
                name,
                ty,
                &format!("({ty})gf_bounded_i32(&Cur, 0, 8)"),
            ));
        }
    }
    match normalized.as_str() {
        "_Bool" => Some(scalar(name, "_Bool", "(_Bool)(gf_u8(&Cur) & 1)")),
        "bool" => Some(scalar(name, "bool", "(bool)(gf_u8(&Cur) & 1)")),
        // Floating-point scalars. Without these the registry-LESS gate
        // `cpp_parameter_type_supported` (used to decide whether a C++ lifecycle
        // step is harnessable) rejected a `double` param even though the
        // registry-aware emission path decodes it fine — so e.g.
        // `INIReader::GetReal(..., double default_value)` was silently dropped
        // ("unsupported parameter type 'double'"). Mirror the registry F32/F64
        // emission (gf_i32/gf_i64 reinterpreted to the float type).
        "float" => Some(scalar(name, "float", "(float)gf_i32(&Cur)")),
        "double" => Some(scalar(name, "double", "(double)gf_i64(&Cur)")),
        "long double" => Some(scalar(name, "long double", "(long double)gf_i64(&Cur)")),
        "short" | "signed short" | "short int" => {
            Some(scalar(name, "short", "(short)gf_i32(&Cur)"))
        }
        "unsigned short" | "unsigned short int" => Some(scalar(
            name,
            "unsigned short",
            "(unsigned short)gf_bounded_i32(&Cur, 0, 0xffff)",
        )),
        "int" | "signed int" => Some(scalar(name, "int", "gf_i32(&Cur)")),
        "unsigned" | "unsigned int" => Some(scalar(
            name,
            "unsigned int",
            "(unsigned int)gf_bounded_i32(&Cur, 0, 0x7fffffff)",
        )),
        "long" | "signed long" => Some(scalar(name, "long", "(long)gf_i64(&Cur)")),
        "unsigned long" => Some(scalar(
            name,
            "unsigned long",
            "(unsigned long)gf_bounded_length(&Cur, 0, 0x7fffffff)",
        )),
        "uLong" | "uLongf" => Some(scalar(
            name,
            normalized.as_str(),
            "(uLong)gf_bounded_length(&Cur, 0, 0x7fffffff)",
        )),
        "uInt" => Some(scalar(
            name,
            "uInt",
            "(uInt)gf_bounded_i32(&Cur, 0, 0x7fffffff)",
        )),
        "z_size_t" => Some(scalar(
            name,
            "z_size_t",
            "(z_size_t)gf_bounded_length(&Cur, 0, 65536)",
        )),
        "mz_ulong" => Some(scalar(
            name,
            "mz_ulong",
            "(mz_ulong)gf_bounded_length(&Cur, 0, 0x7fffffff)",
        )),
        "long long" | "signed long long" => Some(scalar(name, "long long", "gf_i64(&Cur)")),
        "size_t" => Some(scalar(name, "size_t", "gf_bounded_length(&Cur, 0, 65536)")),
        "uint8_t" | "unsigned char" => Some(scalar(name, "uint8_t", "gf_u8(&Cur)")),
        "int8_t" | "signed char" | "char" => Some(scalar(name, "int8_t", "(int8_t)gf_u8(&Cur)")),
        "uint16_t" => Some(scalar(
            name,
            "uint16_t",
            "(uint16_t)gf_bounded_i32(&Cur, 0, 0xffff)",
        )),
        "int16_t" => Some(scalar(name, "int16_t", "(int16_t)gf_i32(&Cur)")),
        "int32_t" => Some(scalar(name, "int32_t", "gf_i32(&Cur)")),
        "uint32_t" => Some(scalar(
            name,
            "uint32_t",
            "(uint32_t)gf_bounded_i32(&Cur, 0, 0x7fffffff)",
        )),
        "int64_t" => Some(scalar(name, "int64_t", "gf_i64(&Cur)")),
        "uint64_t" => Some(scalar(name, "uint64_t", "(uint64_t)gf_i64(&Cur)")),
        // MSVC fixed-width integer spellings (`__intN`). A header's
        // `#ifdef _MSC_VER typedef __int64 ssize_t` branch is parsed verbatim
        // (tree-sitter doesn't evaluate the #ifdef), so a typedef can resolve to
        // `__int64` even on a non-MSVC host (utf8proc's `utf8proc_ssize_t`). These
        // are plain integers, not opaque types — decode like their `intN_t` peers.
        "__int64" | "signed __int64" => Some(scalar(name, "__int64", "gf_i64(&Cur)")),
        "unsigned __int64" => Some(scalar(
            name,
            "unsigned __int64",
            "(unsigned __int64)gf_i64(&Cur)",
        )),
        "__int32" | "signed __int32" => Some(scalar(name, "__int32", "gf_i32(&Cur)")),
        "unsigned __int32" => Some(scalar(
            name,
            "unsigned __int32",
            "(unsigned __int32)gf_bounded_i32(&Cur, 0, 0x7fffffff)",
        )),
        "__int16" | "signed __int16" => Some(scalar(name, "__int16", "(__int16)gf_i32(&Cur)")),
        "unsigned __int16" => Some(scalar(
            name,
            "unsigned __int16",
            "(unsigned __int16)gf_bounded_i32(&Cur, 0, 0xffff)",
        )),
        "__int8" | "signed __int8" => Some(scalar(name, "__int8", "(__int8)gf_u8(&Cur)")),
        "unsigned __int8" => Some(scalar(
            name,
            "unsigned __int8",
            "(unsigned __int8)gf_u8(&Cur)",
        )),
        "const char *" | "const char*" | "char const *" if is_file_path_param_name(name) => {
            Some(file_path_param(name, true))
        }
        "char *" | "char*" if is_file_path_param_name(name) => Some(file_path_param(name, false)),
        // A printf-style FORMAT parameter (named fmt/format): feed a NUL-terminated
        // string with `%` neutralised. A variadic logging function takes the format
        // but the harness passes no matching varargs, so a `%s`/`%n` in a fuzzed
        // format makes vfprintf read a garbage vararg and crash — a harness
        // format/argument mismatch FALSE POSITIVE (log.c log_log). %-free is safe.
        "const char *" | "const char*" | "char const *" if is_format_string_param_name(name) => {
            Some(c_format_string_param(name, true))
        }
        "char *" | "char*" if is_format_string_param_name(name) => {
            Some(c_format_string_param(name, false))
        }
        "const char *" | "const char*" | "char const *" => Some(CParamEmission {
            support: None,
            decl: format!("char *{name} = gf_c_string(&Cur, 4096)"),
            arg: name.to_owned(),
            c_type: "const char *".to_owned(),
            free: Some(format!("free({name})")),
        }),
        "char *" | "char*" => Some(CParamEmission {
            support: None,
            decl: format!("char *{name} = gf_c_string(&Cur, 4096)"),
            arg: name.to_owned(),
            c_type: "char *".to_owned(),
            free: Some(format!("free({name})")),
        }),
        // Wide-string parameters (`const wchar_t *path`, pugixml load_file). Decode
        // a NUL-terminated wchar_t buffer; otherwise the param decays to a pointer
        // at a single non-NUL wchar_t and the callee's wcslen walks off the end —
        // a harness false OOB (campaign: pugixml CWE-121 FP).
        "const wchar_t *" | "const wchar_t*" | "wchar_t const *" => Some(CParamEmission {
            support: None,
            decl: format!("wchar_t *{name} = gf_wc_string(&Cur, 2048)"),
            arg: name.to_owned(),
            c_type: "const wchar_t *".to_owned(),
            free: Some(format!("free({name})")),
        }),
        "wchar_t *" | "wchar_t*" => Some(CParamEmission {
            support: None,
            decl: format!("wchar_t *{name} = gf_wc_string(&Cur, 2048)"),
            arg: name.to_owned(),
            c_type: "wchar_t *".to_owned(),
            free: Some(format!("free({name})")),
        }),
        "const void *" | "void const *" => Some(const_void_pointer(name)),
        "void *" => Some(mutable_void_pointer(name)),
        "FILE *" => Some(file_pointer("FILE *", name)),
        "MZ_FILE *" => Some(file_pointer("MZ_FILE *", name)),
        other => match char_double_pointer_constness(other) {
            Some(is_const) => Some(char_double_pointer(is_const, name)),
            None => out_pointer_decoder(other, name),
        },
    }
}

#[derive(Clone)]
struct DecodeContext<'a> {
    statements: Vec<String>,
    cleanups: Vec<String>,
    /// File-scope support code (callback trampolines) emitted before the harness
    /// body. Accumulated as fields/params decode; rolled back with the rest of the
    /// context when a field decode fails (so a half-built trampoline doesn't leak).
    support: Vec<String>,
    /// The type registry, so a struct/union field can resolve a typedef'd
    /// function-pointer signature and emit a callback trampoline at decode time
    /// (#454) instead of being left NULL.
    registry: &'a TypeRegistry,
    /// True when emitting into a C++ harness. A struct/class local is then
    /// value-initialized (`T x{};`) and NOT `memset`-zeroed — memset on a
    /// non-trivial C++ object (members with constructors) is undefined and, for a
    /// class with no default ctor, even the bare `T x;` fails to compile.
    cpp: bool,
    /// The struct/union spellings whose full definition the harness translation
    /// unit can see (`struct X {...}` present in an INCLUDED header). When `Some`,
    /// an opaque-handle lifecycle that would STACK-ALLOCATE a type absent from this
    /// set is skipped (it would be an illegal incomplete-type declaration). `None`
    /// is permissive (legacy callers / the C++ fallback path): stack-allocate by
    /// spelling and trust the compiler to resolve completeness via the includes.
    header_complete: Option<&'a HashSet<String>>,
    /// Configurable struct/array synthesis caps (§27.11); [`DecoderLimits::default`]
    /// reproduces the historical hardcoded behavior byte-for-byte.
    limits: DecoderLimits,
}

impl<'a> DecodeContext<'a> {
    fn new(registry: &'a TypeRegistry, cpp: bool, limits: DecoderLimits) -> Self {
        DecodeContext {
            statements: Vec::new(),
            cleanups: Vec::new(),
            support: Vec::new(),
            registry,
            cpp,
            header_complete: None,
            limits,
        }
    }

    /// Whether an opaque handle of resolved spelling `raw` may be STACK-ALLOCATED
    /// (its full definition is visible to the harness TU). Permissive when no
    /// header-completeness oracle was supplied (`None`).
    fn opaque_stack_allocatable(&self, raw: &str) -> bool {
        match self.header_complete {
            None => true,
            Some(set) => set.contains(raw),
        }
    }

    fn push(&mut self, statement: impl Into<String>) {
        self.statements.push(statement.into());
    }

    /// `{}` value-initializer suffix for an aggregate local in C++, empty in C.
    fn value_init_suffix(&self) -> &'static str {
        if self.cpp {
            "{}"
        } else {
            ""
        }
    }

    fn cleanup(&self) -> Option<String> {
        if self.cleanups.is_empty() {
            None
        } else {
            Some(self.cleanups.join("; "))
        }
    }
}

fn emit_top_level_value(
    ctx: &mut DecodeContext<'_>,
    c_type: &str,
    name: &str,
    shape: &TypeShape,
    pointer_base_hint: Option<&str>,
    lifecycle: &[CHandleLifecycle],
) -> Result<String, CDecoderError> {
    match shape {
        TypeShape::Scalar(kind) => {
            ctx.push(format!("{c_type} {name} = {}", scalar_expr(*kind, c_type)));
            Ok(name.to_owned())
        }
        TypeShape::CString => {
            ctx.push(format!("char *{name} = gf_c_string(&Cur, 4096)"));
            ctx.cleanups.push(format!("free({name})"));
            Ok(name.to_owned())
        }
        TypeShape::Enum { members, .. } => {
            emit_enum_decode(ctx, name, c_type, members, true);
            Ok(name.to_owned())
        }
        TypeShape::Struct { fields, .. } => {
            let storage_type = storage_c_type(c_type);
            ctx.push(format!("{storage_type} {name}{}", ctx.value_init_suffix()));
            emit_struct_init(ctx, name, fields, 0);
            Ok(name.to_owned())
        }
        TypeShape::Union { fields, .. } => {
            let storage_type = storage_c_type(c_type);
            ctx.push(format!("{storage_type} {name}{}", ctx.value_init_suffix()));
            emit_union_init(ctx, name, fields, 0)?;
            Ok(name.to_owned())
        }
        TypeShape::Pointer(inner) => {
            emit_top_level_pointer(ctx, c_type, name, inner, pointer_base_hint, lifecycle)
        }
        TypeShape::Array { elem, len } => {
            let Some(base) = array_base_c_type(c_type) else {
                return Err(CDecoderError::new(format!(
                    "array parameter '{name}' of type '{c_type}' needs declarator support"
                )));
            };
            ctx.push(format!("{base} {name}[{len}]"));
            emit_array_decode(ctx, name, base, elem, *len, 0);
            Ok(name.to_owned())
        }
        TypeShape::FuncPtr => Err(CDecoderError::new(format!(
            "callback parameter '{name}' needs trampoline support (Phase C)"
        ))),
        TypeShape::Opaque(raw) => Err(CDecoderError::new(format!(
            "opaque type '{raw}' for parameter '{name}' needs lifecycle support (Phase C)"
        ))),
    }
}

fn emit_top_level_pointer(
    ctx: &mut DecodeContext<'_>,
    c_type: &str,
    name: &str,
    inner: &TypeShape,
    pointer_base_hint: Option<&str>,
    lifecycle: &[CHandleLifecycle],
) -> Result<String, CDecoderError> {
    match inner {
        TypeShape::Scalar(kind) => {
            if is_const_byte_pointer(c_type, *kind) {
                // A LONE const byte pointer (a `(buffer, length)` pair would have
                // been consumed earlier) is, in practice, a NUL-terminated C-string
                // — a length-less binary buffer isn't drivable. Pass a
                // NUL-terminated heap copy so a `strlen` / parser read can't run
                // past the fuzz input (cJSON detach_path's `const unsigned char
                // *path` -> strlen -> spurious heap-overflow otherwise).
                // Floor the allocation to the max scalar fixed width (8 bytes —
                // uint64/double) so a length-less internal loader that reads N fixed
                // bytes forward with no bounds check (libcbor `_cbor_load_uint16`/
                // `_cbor_load_uint64`) cannot over-read the heap on a short/0-byte
                // input. Zero the whole buffer first so the bytes past `Size` are
                // defined (a fixed-width read sees zeros, not heap garbage), then copy
                // the fuzz bytes and keep the C-string NUL terminator.
                let cap = format!("_gf_cap_{name}");
                ctx.push(format!(
                    "size_t {cap} = (size_t)Size + 1; if ({cap} < 8) {cap} = 8; \
                     {c_type} {name} = ({c_type})malloc({cap}); \
                     if ({name}) {{ memset((void *){name}, 0, {cap}); \
                     if (Size) memcpy((void *){name}, Data, Size); \
                     ((char *){name})[Size] = '\\0'; }}"
                ));
                ctx.cleanups.push(format!("free((void *){name})"));
                return Ok(name.to_owned());
            }
            let storage_type = output_pointer_storage_type(c_type, pointer_base_hint, name)?;
            let storage = format!("_gf_out_{name}");
            ctx.push(format!(
                "{storage_type} {storage} = {}",
                scalar_expr(*kind, &storage_type)
            ));
            ctx.push(format!("{c_type} {name} = &{storage}"));
            Ok(name.to_owned())
        }
        TypeShape::Enum { members, .. } => {
            let storage_type = output_pointer_storage_type(c_type, pointer_base_hint, name)?;
            let storage = format!("_gf_out_{name}");
            emit_enum_decode(ctx, &storage, &storage_type, members, true);
            ctx.push(format!("{c_type} {name} = &{storage}"));
            Ok(name.to_owned())
        }
        TypeShape::Struct { fields, .. } => {
            let base = pointer_base_owned(c_type)
                .or_else(|| pointer_base_hint.map(storage_c_type));
            let Some(base) = base else {
                return Err(CDecoderError::new(format!(
                    "pointer parameter '{name}' of type '{c_type}' needs pointer declarator support"
                )));
            };
            let storage_type = storage_c_type(&base);
            let storage = format!("_gf_value_{name}");
            ctx.push(format!("{storage_type} {storage}{}", ctx.value_init_suffix()));
            emit_struct_init(ctx, &storage, fields, 0);
            ctx.push(format!("{c_type} {name} = &{storage}"));
            Ok(name.to_owned())
        }
        TypeShape::Union { fields, .. } => {
            let base = pointer_base_owned(c_type)
                .or_else(|| pointer_base_hint.map(storage_c_type));
            let Some(base) = base else {
                return Err(CDecoderError::new(format!(
                    "pointer parameter '{name}' of type '{c_type}' needs pointer declarator support"
                )));
            };
            let storage_type = storage_c_type(&base);
            let storage = format!("_gf_value_{name}");
            ctx.push(format!("{storage_type} {storage}{}", ctx.value_init_suffix()));
            emit_union_init(ctx, &storage, fields, 0)?;
            ctx.push(format!("{c_type} {name} = &{storage}"));
            Ok(name.to_owned())
        }
        TypeShape::Pointer(slot_inner) if is_void_pointer_output_slot(c_type, slot_inner) => {
            let storage = format!("_gf_out_{name}");
            ctx.push(format!("void * {storage} = NULL"));
            ctx.push(format!("{c_type} {name} = &{storage}"));
            Ok(name.to_owned())
        }
        TypeShape::Pointer(slot_inner) if is_typed_output_handle_slot(c_type, slot_inner) => {
            // A `T **out` output-handle (the parse-to-out-handle idiom: the callee
            // allocates a `T *` and writes it back through the slot). Provide a NULL
            // slot and pass its address; if the tree exposes a destructor for `T`,
            // free the produced handle after the call — NULL-guarded, since a failed
            // parse leaves the slot NULL.
            let storage_type = pointer_base_owned(c_type)
                .or_else(|| pointer_base_hint.map(storage_c_type))
                .ok_or_else(|| {
                    CDecoderError::new(format!(
                        "output-handle parameter '{name}' of type '{c_type}' needs \
                         pointer declarator support"
                    ))
                })?;
            let storage = format!("_gf_out_{name}");
            ctx.push(format!("{storage_type} {storage} = NULL"));
            ctx.push(format!("{c_type} {name} = &{storage}"));
            // Lifecycle is keyed by the clean base type name (no pointer). The
            // pointee shape carries it directly (`foo_data`); the pointer hint still
            // has a trailing `*` here (two declarator levels), so prefer the shape.
            let mut base_key = output_handle_base_name(slot_inner);
            if base_key.is_empty() {
                base_key = pointer_base_hint
                    .map(|h| h.trim_end_matches(['*', ' ']).trim().to_owned())
                    .unwrap_or_default();
            }
            if let Some(entry) = lookup_lifecycle(lifecycle, &base_key) {
                if let Some(delete) = &entry.delete {
                    ctx.cleanups.push(format!("if ({storage}) {delete}({storage})"));
                }
            }
            Ok(name.to_owned())
        }
        TypeShape::Opaque(raw) => {
            // Opaque struct: fields can't be synthesised (forward-only in this
            // TU, or too complex to value-fill). If the tree provides lifecycle
            // functions for it, stack-allocate by spelling (the compiler
            // resolves completeness via the harness includes even though the
            // type_model registry sees it as opaque) and drive the lifecycle
            // instead of bailing.
            // Look up the lifecycle by the handle's TYPEDEF NAME
            // (`de265_decoder_context`), not the resolved base: an opaque
            // `typedef void <name>` handle (the classic C opaque-handle idiom)
            // resolves to "void", but the lifecycle table is keyed by the typedef.
            // Keying by `raw` ("void") here would never match, and the old
            // `raw != "void"` guard skipped such handles entirely.
            let handle_key = pointer_base_hint
                .filter(|hint| !hint.is_empty())
                .unwrap_or(raw.as_str());
            if let Some(entry) = lookup_lifecycle(lifecycle, handle_key) {
                let storage = format!("_gf_lc_{name}");
                if let (Some(init), true) = (&entry.init, entry.init_returns_handle) {
                    // Returning constructor (`T *foo_new(void)`): the handle is the
                    // return value, passed by value and freed directly
                    // (`foo_free(handle)`), not by address. Needs no complete /
                    // stack-allocatable type, so an opaque `typedef void` handle
                    // (libde265 `de265_decoder_context`) is supported. A constructor
                    // taking pointer config args is called with the neutral "use
                    // defaults" value NULL for each (`XML_ParserCreate(NULL)`).
                    let init_args = entry.init_args.join(", ");
                    ctx.push(format!("{c_type} {name} = {init}({init_args})"));
                    if let Some(delete) = &entry.delete {
                        ctx.cleanups.push(format!("{delete}({name})"));
                    }
                    return Ok(name.to_owned());
                } else if raw != "void" {
                    // The remaining paths stack-allocate `{raw} storage`, which needs
                    // a complete type — impossible for a `void` handle (which only
                    // works via the returning-constructor path above).
                    //
                    // When a header-completeness oracle was supplied (the C `auto`
                    // path) and `{raw}` is NOT fully defined in any header the harness
                    // includes — its body lives only in a non-included `.c`, e.g.
                    // tidwall/hashmap.c's `struct hashmap`, merely forward-declared in
                    // hashmap.h — the stack declaration would be an illegal "variable
                    // has incomplete type 'struct hashmap'". There is no synthesizable
                    // returning-constructor lifecycle (hashmap_new needs caller-supplied
                    // hash/compare function pointers), so SKIP the target cleanly with a
                    // clear reason rather than emit code that cannot compile. (`None`
                    // oracle = permissive: trust the includes, the legacy behavior.)
                    if !ctx.opaque_stack_allocatable(raw) {
                        return Err(CDecoderError::new(format!(
                            "opaque handle '{raw}' for parameter '{name}' is incomplete in \
                             the harness's included headers (its full definition is visible \
                             only in a non-included source) and has no returning-constructor \
                             lifecycle; cannot stack-allocate it — skipping"
                        )));
                    }
                    if let Some(init) = &entry.init {
                        // In-place initializer (`void foo_init(T *)`): set up a
                        // stack handle and pass/free its address.
                        ctx.push(format!("{raw} {storage}"));
                        ctx.push(format!("{init}(&{storage})"));
                        ctx.push(format!("{c_type} {name} = &{storage}"));
                        if let Some(delete) = &entry.delete {
                            ctx.cleanups.push(format!("{delete}(&{storage})"));
                        }
                        return Ok(name.to_owned());
                    } else if let Some(delete) = &entry.delete {
                        // No constructor but a destructor exists: an output /
                        // managed struct the callee fills (e.g. libyaml
                        // yaml_token_t / yaml_event_t / yaml_document_t — written
                        // by yaml_parser_scan/parse/load, released by *_delete).
                        // Zero-initialise, pass its address, and delete after.
                        // A zeroed struct is a safe argument and a safe delete.
                        ctx.push(format!("{raw} {storage}"));
                        ctx.push(format!("memset(&{storage}, 0, sizeof {storage})"));
                        ctx.push(format!("{c_type} {name} = &{storage}"));
                        ctx.cleanups.push(format!("{delete}(&{storage})"));
                        return Ok(name.to_owned());
                    }
                }
            }
            // A read-only pointer to an opaque struct with no lifecycle is the
            // wire-format / packet-parser idiom (cFE `const CFE_MSG_Message_t *`,
            // a CCSDS message; MAVLink/DIS/network headers): back it with the raw
            // fuzz input so the parser runs on fuzzer-controlled bytes instead of
            // being skipped. The const-pointee gate keeps mutable handle pointers
            // — which the callee may write through, and which are not the input —
            // out of this path; a lifecycle pair (checked above) handles those.
            if raw != "void" && is_const_pointee(c_type) {
                ctx.push(format!("{c_type} {name} = ({c_type})Data"));
                return Ok(name.to_owned());
            }
            Err(CDecoderError::new(format!(
                "opaque type '{raw}' for pointer parameter '{name}' needs lifecycle support (Phase C)"
            )))
        }
        TypeShape::FuncPtr => Err(CDecoderError::new(format!(
            "callback parameter '{name}' needs trampoline support (Phase C)"
        ))),
        _ => Err(CDecoderError::new(format!(
            "pointer parameter '{name}' of type '{c_type}' is not safely drivable after struct synthesis"
        ))),
    }
}

fn output_pointer_storage_type(
    c_type: &str,
    pointer_base_hint: Option<&str>,
    name: &str,
) -> Result<String, CDecoderError> {
    pointer_base_owned(c_type)
        .or_else(|| pointer_base_hint.map(storage_c_type))
        .map(|base| storage_c_type(&base))
        .ok_or_else(|| {
            CDecoderError::new(format!(
                "pointer parameter '{name}' of type '{c_type}' needs pointer declarator support"
            ))
        })
}

fn is_void_pointer_output_slot(c_type: &str, inner: &TypeShape) -> bool {
    matches!(inner, TypeShape::Opaque(raw) if raw == "void")
        && canonical_c_type_for_decoder(c_type) == "void * *"
}

/// A typed `T **out` output-handle slot: a pointer to a pointer-to-{struct, union,
/// non-void opaque} (two declarator levels). Distinct from the `void **` slot
/// (handled above) and from a single `T *` (the Struct/Union/Opaque arms fill that
/// by value). The callee allocates the `T *` and writes it back through the slot.
fn is_typed_output_handle_slot(c_type: &str, inner: &TypeShape) -> bool {
    let two_levels = canonical_c_type_for_decoder(c_type).ends_with("* *");
    two_levels
        && match inner {
            TypeShape::Struct { .. } | TypeShape::Union { .. } => true,
            TypeShape::Opaque(raw) => raw != "void",
            _ => false,
        }
}

/// The base type NAME of an output-handle's pointee shape, for lifecycle lookup
/// (`cgltf_data **` -> `cgltf_data`). Empty when the shape carries no name.
fn output_handle_base_name(inner: &TypeShape) -> String {
    match inner {
        TypeShape::Struct { name, .. } | TypeShape::Union { name, .. } => name.clone(),
        TypeShape::Opaque(raw) => raw.clone(),
        _ => String::new(),
    }
}

/// Whether the *pointee* is `const` (a read-only view), i.e. `const` qualifies
/// the type to the left of the last `*` (`const T *`, `T const *`) rather than
/// the pointer itself (`T * const`). Used to gate byte-overlay of an opaque
/// pointer to a read-only data/packet view.
fn is_const_pointee(c_type: &str) -> bool {
    match c_type.rfind('*') {
        Some(star) => c_type[..star]
            .split_whitespace()
            .any(|token| token == "const"),
        None => false,
    }
}

fn is_const_byte_pointer(c_type: &str, kind: ScalarKind) -> bool {
    if !matches!(kind, ScalarKind::U8 | ScalarKind::I8) {
        return false;
    }
    let canonical = canonical_c_type_for_decoder(c_type);
    let Some(base) = canonical.strip_suffix(" *") else {
        return false;
    };
    base.split_whitespace().any(|token| token == "const")
}

fn emit_struct_init(ctx: &mut DecodeContext<'_>, lvalue: &str, fields: &[Field], depth: usize) {
    // In C the object is `memset`-zeroed before the decodable fields are filled;
    // in C++ it was value-initialized at its declaration (`T x{};`) so memset is
    // skipped (memset over a non-trivial member is undefined behaviour).
    if !ctx.cpp {
        ctx.push(format!("memset(&{lvalue}, 0, sizeof {lvalue})"));
    }
    if depth >= ctx.limits.depth {
        ctx.push(format!(
            "/* govfuzz: {lvalue} left zeroed after decoder depth cap */"
        ));
        return;
    }
    for field in fields {
        // Never emit a member access with an empty/invalid name (`{lvalue}. = ...`,
        // which does not compile — `expected identifier`). A function-pointer field
        // whose name was a calling-convention macro (cJSON's `CJSON_CDECL`, empty on
        // Linux) is the canonical source; the parser now strips it, but guard the
        // emission too so any residual nameless field is left zeroed, not emitted.
        if !is_c_identifier(&field.name) {
            ctx.push(format!(
                "/* govfuzz: field {lvalue}.<unnamed> left zeroed: unresolved member name */"
            ));
            continue;
        }
        let field_lvalue = format!("{lvalue}.{}", field.name);
        let before = ctx.clone();
        if let Err(err) =
            emit_lvalue_decode(ctx, &field_lvalue, &field.c_type, &field.shape, depth + 1)
        {
            *ctx = before;
            ctx.push(format!(
                "/* govfuzz: field {field_lvalue} left zeroed: {err} */"
            ));
        }
    }
}

fn emit_union_init(
    ctx: &mut DecodeContext<'_>,
    lvalue: &str,
    fields: &[Field],
    depth: usize,
) -> Result<(), CDecoderError> {
    if !ctx.cpp {
        ctx.push(format!("memset(&{lvalue}, 0, sizeof {lvalue})"));
    }
    if depth >= ctx.limits.depth {
        return Err(CDecoderError::new(format!(
            "union '{lvalue}' exceeds decoder depth cap"
        )));
    }
    for field in fields {
        if !is_c_identifier(&field.name) {
            continue;
        }
        let mut attempt = ctx.clone();
        let field_lvalue = format!("{lvalue}.{}", field.name);
        if emit_lvalue_decode(
            &mut attempt,
            &field_lvalue,
            &field.c_type,
            &field.shape,
            depth + 1,
        )
        .is_ok()
        {
            *ctx = attempt;
            return Ok(());
        }
    }
    // No member is independently decodable (all pointer / callback / opaque). A
    // zeroed union is still a valid value, so leave the memset and proceed rather
    // than rejecting the whole parameter — the function runs with a zeroed union
    // instead of being skipped.
    ctx.push(format!(
        "/* govfuzz: union {lvalue} left zeroed: no decodable member */"
    ));
    Ok(())
}

fn emit_lvalue_decode(
    ctx: &mut DecodeContext<'_>,
    lvalue: &str,
    c_type: &str,
    shape: &TypeShape,
    depth: usize,
) -> Result<(), CDecoderError> {
    if depth > ctx.limits.depth {
        return Err(CDecoderError::new(format!(
            "{lvalue} exceeds decoder depth cap"
        )));
    }
    match shape {
        TypeShape::Scalar(kind) => {
            ctx.push(format!("{lvalue} = {}", scalar_expr(*kind, c_type)));
            Ok(())
        }
        TypeShape::CString => {
            ctx.push(format!("{lvalue} = gf_c_string(&Cur, 256)"));
            // Cast through void* so the cleanup compiles when the field is
            // `const char *` (C++'s free(void *) rejects a const argument).
            ctx.cleanups.push(format!("free((void *){lvalue})"));
            Ok(())
        }
        TypeShape::Enum { members, .. } => {
            emit_enum_decode(ctx, lvalue, c_type, members, false);
            Ok(())
        }
        TypeShape::Struct { fields, .. } => {
            emit_struct_init(ctx, lvalue, fields, depth);
            Ok(())
        }
        TypeShape::Union { fields, .. } => emit_union_init(ctx, lvalue, fields, depth),
        TypeShape::Array { elem, len } => {
            // The field spelling may be an array *typedef* (`nd_uint8_t`, where
            // `typedef unsigned char nd_uint8_t[1]`) which carries no `[...]`; the
            // lvalue is still an indexable array, so fall back to the element's
            // own canonical scalar spelling for the cast.
            let base = match array_base_c_type(c_type) {
                Some(base) => base.to_owned(),
                None => scalar_shape_c_type(elem).ok_or_else(|| {
                    CDecoderError::new(format!(
                        "array field '{lvalue}' of type '{c_type}' needs declarator support"
                    ))
                })?,
            };
            emit_array_decode(ctx, lvalue, &base, elem, *len, depth);
            Ok(())
        }
        TypeShape::Pointer(inner) => match inner.as_ref() {
            TypeShape::Opaque(raw) => Err(CDecoderError::new(format!(
                "opaque type '{raw}' for field '{lvalue}' needs lifecycle support (Phase C)"
            ))),
            TypeShape::FuncPtr => Err(CDecoderError::new(format!(
                "callback field '{lvalue}' needs trampoline support (Phase C)"
            ))),
            // A pointer-to-pointer field (`T **`) is the output-handle idiom, a
            // parameter concern; left zeroed inside a struct.
            TypeShape::Pointer(_) => Err(CDecoderError::new(format!(
                "pointer-to-pointer field '{lvalue}' is left zeroed (output-handle idiom)"
            ))),
            // #451: a pointer to a decodable VALUE (scalar / enum / struct / union)
            // was left NULL, blocking dereference codepaths. Synthesise per-field
            // stack storage, decode the pointee into it, and point the field at it.
            other => emit_pointer_field_storage(ctx, lvalue, c_type, other, depth),
        },
        // #454: a typedef'd function-pointer field gets a callback trampoline (a
        // static no-op matching its signature) assigned to it, instead of being
        // left NULL — so the struct's callback codepath actually runs. An inline /
        // unresolvable signature can't be synthesised, so it stays zeroed.
        TypeShape::FuncPtr => match ctx.registry.function_pointer_signature(c_type) {
            Some(signature) => {
                let (support, trampoline) = build_callback_trampoline(c_type, lvalue, &signature)?;
                ctx.support.push(support);
                ctx.push(format!("{lvalue} = {trampoline}"));
                Ok(())
            }
            None => Err(CDecoderError::new(format!(
                "callback field '{lvalue}' has no resolvable signature; left zeroed"
            ))),
        },
        TypeShape::Opaque(raw) => Err(CDecoderError::new(format!(
            "opaque type '{raw}' for field '{lvalue}'"
        ))),
    }
}

/// #451: a struct field that is a pointer to a decodable VALUE (`int *`,
/// `struct Foo *`, an enum/union pointer) used to be left NULL — blocking the
/// dereference codepaths behind it. Synthesise a per-field stack storage of the
/// pointee type, decode the value into it, and point the field at it
/// (`{T} _gf_pf_<field> = <decoded>; field = &_gf_pf_<field>;`). The storage is a
/// harness-scope local (lives until the call returns), so no free is owed; any
/// heap owned by the pointee's own fields (e.g. an inner C string) is freed via
/// the shared cleanup list. Recursion is bounded by the decoder depth cap, so a
/// self-referential `struct Node *next` terminates with a zeroed tail.
fn emit_pointer_field_storage(
    ctx: &mut DecodeContext<'_>,
    lvalue: &str,
    c_type: &str,
    inner: &TypeShape,
    depth: usize,
) -> Result<(), CDecoderError> {
    let Some(base) = pointer_base_owned(c_type) else {
        return Err(CDecoderError::new(format!(
            "pointer field '{lvalue}' of type '{c_type}' needs pointer declarator support"
        )));
    };
    let storage_type = storage_c_type(&base);
    let storage = format!("_gf_pf_{}", sanitize_ident(lvalue));
    match inner {
        TypeShape::Scalar(kind) => {
            ctx.push(format!(
                "{storage_type} {storage} = {}",
                scalar_expr(*kind, &storage_type)
            ));
        }
        TypeShape::Enum { members, .. } => {
            emit_enum_decode(ctx, &storage, &storage_type, members, true);
        }
        TypeShape::Struct { fields, .. } => {
            ctx.push(format!(
                "{storage_type} {storage}{}",
                ctx.value_init_suffix()
            ));
            emit_struct_init(ctx, &storage, fields, depth);
        }
        TypeShape::Union { fields, .. } => {
            ctx.push(format!(
                "{storage_type} {storage}{}",
                ctx.value_init_suffix()
            ));
            emit_union_init(ctx, &storage, fields, depth)?;
        }
        _ => {
            return Err(CDecoderError::new(format!(
                "pointer field '{lvalue}' to '{base}' needs declarator support"
            )))
        }
    }
    ctx.push(format!("{lvalue} = &{storage}"));
    Ok(())
}

fn emit_array_decode(
    ctx: &mut DecodeContext<'_>,
    lvalue: &str,
    elem_c_type: &str,
    elem: &TypeShape,
    len: usize,
    depth: usize,
) {
    let capped = len.min(ctx.limits.array_elems);
    let idx = format!("_gf_i_{}", sanitize_ident(lvalue));
    ctx.push(format!("size_t {idx} = 0"));
    match elem {
        // A callback ARRAY `RET (*name[N])(...)`: synthesise ONE no-op trampoline
        // matching the element signature and point every slot at it, so the struct's
        // callback table is fully populated and callable instead of left NULL (§27.3).
        // An unresolvable element signature leaves the (memset-zeroed) slots as-is.
        TypeShape::FuncPtr => {
            if let Some(signature) = ctx.registry.function_pointer_signature(elem_c_type) {
                if let Ok((support, trampoline)) =
                    build_callback_trampoline(elem_c_type, lvalue, &signature)
                {
                    ctx.support.push(support);
                    ctx.push(format!(
                        "for ({idx} = 0; {idx} < {capped}; ++{idx}) {{ {lvalue}[{idx}] = ({elem_c_type}){trampoline}; }}"
                    ));
                }
            }
        }
        TypeShape::Scalar(kind) => {
            if len > ctx.limits.array_elems {
                // #464: a large fixed array is truncated at the cap; rather than
                // always filling the same fixed prefix (leaving a 256-tap buffer
                // permanently zeroed past slot 63), fuzz the fill COUNT (0..cap) so
                // different inputs cover different slots. Slots past the chosen
                // count keep their memset-zero. (The cap itself is the per-target
                // tuning knob — `--max-array-elems`, threaded via
                // `DecoderLimits::array_elems`, §27.11.)
                let count = format!("_gf_n_{}", sanitize_ident(lvalue));
                ctx.push(format!(
                    "size_t {count} = (size_t)(gf_u8(&Cur) % {})",
                    capped + 1
                ));
                ctx.push(format!(
                    "for ({idx} = 0; {idx} < {count}; ++{idx}) {{ {lvalue}[{idx}] = {}; }}",
                    scalar_expr(*kind, elem_c_type)
                ));
            } else {
                ctx.push(format!(
                    "for ({idx} = 0; {idx} < {capped}; ++{idx}) {{ {lvalue}[{idx}] = {}; }}",
                    scalar_expr(*kind, elem_c_type)
                ));
            }
        }
        _ => {
            for i in 0..capped {
                let element_lvalue = format!("{lvalue}[{i}]");
                let before = ctx.clone();
                if emit_lvalue_decode(ctx, &element_lvalue, elem_c_type, elem, depth + 1).is_err() {
                    *ctx = before;
                    break;
                }
            }
        }
    }
}

fn emit_enum_decode(
    ctx: &mut DecodeContext<'_>,
    lvalue: &str,
    c_type: &str,
    members: &[String],
    declare: bool,
) {
    // The harness's local is MUTABLE — the switch assigns the chosen variant into
    // it — so a leading `const` on a by-value param type (`const jsmntype_t`, just
    // the callee's promise not to modify its copy) must not propagate to the local
    // declaration, or it fails "cannot assign to const". The casts use the same
    // unqualified type.
    let decl_type = strip_leading_const(c_type);
    if members.is_empty() {
        // No recoverable named variants (e.g. an X-macro-generated body like
        // `enum E { E_MAP(GEN) };` whose enumerators we can't expand). Fuzz it as
        // a bounded integer cast to the enum type rather than pinning it to 0, so
        // out-of-range values are still explored — an enum used as a table index
        // (`http_errno_name(err)`) is exactly where an OOB read would surface.
        let expr = format!("({decl_type})gf_bounded_i32(&Cur, 0, 255)");
        if declare {
            ctx.push(format!("{decl_type} {lvalue} = {expr}"));
        } else {
            ctx.push(format!("{lvalue} = {expr}"));
        }
        return;
    }
    let fallback = members.first().cloned().unwrap_or_else(|| "0".to_owned());
    let max = members.len().saturating_sub(1);
    let sel = format!("_gf_sel_{}", sanitize_ident(lvalue));
    ctx.push(format!("int {sel} = gf_bounded_i32(&Cur, 0, {max})"));
    if declare {
        ctx.push(format!("{decl_type} {lvalue} = ({decl_type}){fallback}"));
    } else {
        ctx.push(format!("{lvalue} = ({decl_type}){fallback}"));
    }
    let mut switch = format!("switch ({sel}) {{");
    for (idx, member) in members.iter().enumerate() {
        switch.push_str(&format!(
            " case {idx}: {lvalue} = ({decl_type}){member}; break;"
        ));
    }
    switch.push_str(" default: break; }");
    ctx.push(switch);
}

/// Strip a leading `const` qualifier from a by-value type so the harness's mutable
/// local can be declared and assigned (`const jsmntype_t` -> `jsmntype_t`). Only a
/// LEADING, whole-word `const` is removed (a type named `const_t` is untouched, and
/// a pointer's const-pointee `const char *` — handled elsewhere — is not a by-value
/// enum/scalar so never reaches here).
fn strip_leading_const(c_type: &str) -> &str {
    let t = c_type.trim();
    match t.strip_prefix("const ") {
        Some(rest) => rest.trim_start(),
        None => t,
    }
}

fn scalar_expr(kind: ScalarKind, c_type: &str) -> String {
    match kind {
        ScalarKind::Bool => format!("({c_type})(gf_u8(&Cur) & 1)"),
        ScalarKind::I8 => {
            if c_type.trim() == "int8_t" {
                "(int8_t)gf_u8(&Cur)".to_owned()
            } else {
                format!("({c_type})gf_u8(&Cur)")
            }
        }
        ScalarKind::U8 => {
            if c_type.trim() == "uint8_t" {
                "gf_u8(&Cur)".to_owned()
            } else {
                format!("({c_type})gf_u8(&Cur)")
            }
        }
        ScalarKind::I16 => format!("({c_type})gf_i32(&Cur)"),
        ScalarKind::U16 => format!("({c_type})gf_bounded_i32(&Cur, 0, 0xffff)"),
        ScalarKind::I32 => {
            if matches!(c_type.trim(), "int" | "signed int" | "int32_t") {
                "gf_i32(&Cur)".to_owned()
            } else {
                format!("({c_type})gf_i32(&Cur)")
            }
        }
        ScalarKind::U32 => format!("({c_type})gf_bounded_i32(&Cur, 0, 0x7fffffff)"),
        ScalarKind::I64 => {
            if matches!(c_type.trim(), "long long" | "int64_t") {
                "gf_i64(&Cur)".to_owned()
            } else {
                format!("({c_type})gf_i64(&Cur)")
            }
        }
        ScalarKind::U64 => format!("({c_type})gf_bounded_length(&Cur, 0, 0x7fffffff)"),
        ScalarKind::F32 => format!("({c_type})gf_i32(&Cur)"),
        ScalarKind::F64 => format!("({c_type})gf_i64(&Cur)"),
    }
}

fn storage_c_type(c_type: &str) -> String {
    c_type
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "restrict" | "register"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn emit_c_type(c_type: &str) -> String {
    c_type
        .replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn pointer_base_owned(c_type: &str) -> Option<String> {
    canonical_c_type_for_decoder(c_type)
        .strip_suffix(" *")
        .map(str::trim)
        .map(storage_c_type)
}

fn array_base_c_type(c_type: &str) -> Option<&str> {
    c_type.find('[').map(|open| c_type[..open].trim())
}

/// Canonical C spelling for a scalar element shape, used to cast array elements
/// when the field type is an array typedef whose `[...]` extent is not present in
/// the field spelling itself.
fn scalar_shape_c_type(shape: &TypeShape) -> Option<String> {
    let TypeShape::Scalar(kind) = shape else {
        return None;
    };
    Some(
        match kind {
            ScalarKind::Bool => "bool",
            ScalarKind::I8 => "int8_t",
            ScalarKind::U8 => "uint8_t",
            ScalarKind::I16 => "int16_t",
            ScalarKind::U16 => "uint16_t",
            ScalarKind::I32 => "int32_t",
            ScalarKind::U32 => "uint32_t",
            ScalarKind::I64 => "int64_t",
            ScalarKind::U64 => "uint64_t",
            ScalarKind::F32 => "float",
            ScalarKind::F64 => "double",
        }
        .to_owned(),
    )
}

/// Strip leading declaration-specifier noise from a type string so it is usable
/// as a result-variable or parameter declaration. C/C++ functions carry storage
/// (`static`/`inline`/`constexpr`), calling-convention (`__vectorcall`), and
/// decoration macros (`SIMDJSON_INLINE`, `HB_UNUSED`, `simdjson_warn_unused`,
/// `CTRE_FORCE_INLINE`) on the return type / parameter types; tree-sitter keeps
/// them in the type string, and they leak into `<type> R = ...` and
/// `<type> arg` declarations as syntax errors. Drop them, keeping the core type
/// (and any trailing `*`/`&`/`const`). Never strips the final token (the core
/// type), so a worst-case mis-parse degrades to today's behaviour, never to an
/// empty type.
pub fn strip_type_decoration(ty: &str) -> String {
    // Unwrap a function-like export macro that wraps the whole type, e.g. cJSON's
    // `CJSON_PUBLIC(cJSON *)` (`#define CJSON_PUBLIC(type) __declspec(dllexport)
    // type`). On Windows it expands to a linkage decoration the harness then
    // illegally applies to a local result variable; the bare inner type is what
    // we want. Then remove `__attribute__((...))` / `__declspec(...)` runs.
    let unwrapped = unwrap_type_macro(ty);
    let cleaned = remove_attr_runs(&unwrapped);
    let toks: Vec<&str> = cleaned.split_whitespace().collect();
    if toks.len() <= 1 {
        return cleaned.trim().to_owned();
    }
    let mut i = 0;
    while i + 1 < toks.len() && is_leading_decl_noise(toks[i]) {
        i += 1;
    }
    toks[i..].join(" ")
}

/// Unwrap a function-like export macro that wraps the *entire* type, e.g.
/// `CJSON_PUBLIC(cJSON *)` -> `cJSON *`, `MYLIB_API(int)` -> `int`. Such macros
/// (an ALL-CAPS identifier taking the type as its argument) expand to a linkage
/// decoration plus the type; the space-separated `is_leading_decl_noise` path
/// can't see them because there is no whitespace before `(`. Conservative: only
/// unwraps when an ALL-CAPS macro name is immediately followed by a parenthesised
/// run that spans the whole trimmed string, so ordinary types and
/// function-pointer spellings (`void (*)(int)`) are left untouched.
fn unwrap_type_macro(ty: &str) -> String {
    let t = ty.trim();
    let name_end = t
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(t.len());
    let name = &t[..name_end];
    let rest = t[name_end..].trim_start();
    // Macro names are conventionally ALL-CAPS (digits/underscores allowed) with at
    // least one letter — never a real C type, which uses lowercase keywords.
    let looks_macro = name.len() >= 2
        && name.chars().any(|c| c.is_ascii_uppercase())
        && !name.chars().any(|c| c.is_ascii_lowercase());
    if !looks_macro || !rest.starts_with('(') || !rest.ends_with(')') {
        return ty.to_owned();
    }
    let inner = &rest[1..rest.len() - 1];
    // The first '(' must match the final ')' (inner balanced), else this is not a
    // single whole-type wrapper (e.g. `MACRO(a)(b)`).
    let mut depth = 0i32;
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return ty.to_owned();
                }
            }
            _ => {}
        }
    }
    if depth != 0 || inner.trim().is_empty() {
        return ty.to_owned();
    }
    inner.trim().to_owned()
}

/// Remove `__attribute__((...))` and `__declspec(...)` runs (balanced parens).
fn remove_attr_runs(ty: &str) -> String {
    let mut out = String::with_capacity(ty.len());
    let mut rest = ty;
    while let Some(pos) = rest
        .find("__attribute__")
        .or_else(|| rest.find("__declspec"))
    {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        // Skip the keyword, then a balanced parenthesised run.
        if let Some(open) = after.find('(') {
            let mut depth = 0i32;
            let mut end = None;
            for (idx, ch) in after[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(open + idx + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            match end {
                Some(e) => rest = &after[e..],
                None => {
                    rest = "";
                    break;
                }
            }
        } else {
            // No parens after the keyword: drop just the keyword token.
            rest = &after["__attribute__".len().min(after.len())..];
        }
    }
    out.push_str(rest);
    out
}

/// Whether a leading type token is a declaration specifier / calling-convention /
/// decoration macro to drop (not a type-building keyword like `unsigned`/`const`/
/// `struct`).
fn is_leading_decl_noise(tok: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "static",
        "inline",
        "constexpr",
        "consteval",
        "virtual",
        "explicit",
        "friend",
        "extern",
        "register",
        "mutable",
        "__inline",
        "__inline__",
        "__forceinline",
        "_Noreturn",
        "noreturn",
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
        "WINAPI",
        "APIENTRY",
        "CALLBACK",
        "restrict",
        "__restrict",
        "__restrict__",
    ];
    if KEYWORDS.contains(&tok) {
        return true;
    }
    // A decoration macro: an identifier carrying a decoration word. High-
    // precision markers only (avoid substrings like "hot"/"cold" that collide
    // with real names). Matches SIMDJSON_INLINE / HB_UNUSED / CTRE_FORCE_INLINE /
    // simdjson_warn_unused, but not a real type like `simdjson_result`.
    const MARKERS: &[&str] = &[
        "inline",
        "unused",
        "nodiscard",
        "deprecated",
        "warn_unused",
        "force_inline",
        "dllexport",
        "dllimport",
        "visibility",
        "noreturn",
        "noescape",
    ];
    if !tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let lower = tok.to_ascii_lowercase();
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // API-definition / visibility macros follow a naming convention: an ALL-CAPS
    // token like `TSFDEF`, `WREN_API`, `DRFLAC_API`, `STBIDEF`, `JSON_DECL` that
    // expands to a storage/linkage specifier (extern/static) or nothing. As a
    // LEADING token before the real return type it is always decoration; leaving
    // it makes `<type> R = call()` illegal ("declaration of block scope identifier
    // with linkage cannot have an initializer"). is_leading_decl_noise is consulted
    // only for LEADING tokens that have a following type token, so a single-token
    // type that merely ends this way is never stripped.
    tok.len() >= 4
        && tok
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && [
            "DEF", "_API", "_DECL", "_EXTERN", "_EXPORT", "_IMPORT", "_PUBLIC", "_CALL",
        ]
        .iter()
        .any(|s| tok.ends_with(s))
}

fn canonical_c_type_for_decoder(c_type: &str) -> String {
    c_type
        .replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalise a parameter name to a bare identifier. The parser occasionally
/// mis-splits a top-level pointer cv-qualifier (`const uint8_t * const src`)
/// so the trailing `const`/`volatile` lands on the name side (`"const src"`).
/// Such qualifiers are meaningless on a by-value local and produce illegal call
/// arguments (`func(const src)`), so drop any run of leading cv-qualifier tokens
/// and keep the final identifier. A lone qualifier with no following identifier
/// is returned unchanged (degrade-safe — never empties a non-empty name).
pub fn sanitize_param_name(name: &str) -> String {
    let toks: Vec<&str> = name.split_whitespace().collect();
    let mut i = 0;
    while i + 1 < toks.len()
        && matches!(
            toks[i],
            "const" | "volatile" | "restrict" | "__restrict" | "__restrict__"
        )
    {
        i += 1;
    }
    // The identifier is the first non-qualifier token; any trailing tokens are
    // attribute macros (`HB_UNUSED`) that follow the declarator and are dropped.
    toks.get(i).copied().unwrap_or("").to_owned()
}

/// [`sanitize_param_name`], but a parameter that has no usable identifier (an
/// unnamed formal, common in C++ operator/overload declarations) gets a
/// synthesized positional name so the decoder never emits a nameless local
/// (`Type ;`) or `memset(&, 0, sizeof )` with empty operands.
pub fn sanitize_or_synthesize_param_name(name: &str, index: usize) -> String {
    let cleaned = sanitize_param_name(name);
    if cleaned.is_empty() {
        format!("_gf_arg{index}")
    } else {
        cleaned
    }
}

/// Recover a function-pointer parameter whose declarator leaked into the NAME.
///
/// Some C parses model `RET (*name)(args)` as `c_type = "RET"`, `name =
/// "(*name)(args)"` — the funcptr declarator collapses into the name and the type
/// drops to the bare return type (classically a pointer-returning funcptr like
/// json.h's `void *(*alloc_func_ptr)(void *, size_t)`). Decoding that as an
/// ordinary pointer splices a `= calloc(...)` initializer into the MIDDLE of the
/// declarator and emits uncompilable C. When the name has this shape, rebuild the
/// canonical model `(bare_name, "RET (*)(args)")` so the parameter routes through
/// the callback-trampoline path instead. Returns `None` for an ordinary
/// identifier name (the common case) so callers fall through unchanged.
///
/// The c_parser now models this directly (see `funcptr_declarator`), so this is a
/// defensive net for any residual parse that still leaks the declarator.
pub(crate) fn recover_leaked_funcptr_param(name: &str, c_type: &str) -> Option<(String, String)> {
    // The name must be a funcptr declarator: `(* IDENT )( PARAMS )`.
    let rest = name.trim().strip_prefix('(')?;
    let rest = rest.trim_start().strip_prefix('*')?;
    let close = rest.find(')')?;
    let ident = rest[..close].trim();
    if ident.is_empty() || !is_c_identifier(ident) {
        return None;
    }
    // The parameter list follows the declarator group.
    let params = rest[close + 1..]
        .trim_start()
        .strip_prefix('(')?
        .strip_suffix(')')?
        .trim();
    let canonical = format!("{} (*)({})", c_type.trim(), params);
    Some((ident.to_owned(), canonical))
}

fn sanitize_ident(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// Recognise pointer-to-scalar parameters (e.g. `unsigned int *destLen`)
/// commonly used as in/out length / status returns. Synthesize a local
/// variable seeded from the cursor and pass its address. The harness owns
/// the storage so there's nothing to free.
/// If `c_type` is a `char **` / `const char **` (a pointer to a C-string pointer),
/// return `Some(is_const)`; else `None`. Distinguishes a string in-out cursor
/// (`parson parse_value(const char **string)`) / output slot
/// (`cJSON_ParseWithLengthOpts(..., const char **return_parse_end)`) from other
/// double pointers, which still fall through to the unsupported path.
pub(crate) fn char_double_pointer_constness(c_type: &str) -> Option<bool> {
    let norm = c_type
        .replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let parts: Vec<&str> = norm.split_whitespace().collect();
    if parts.iter().filter(|t| **t == "*").count() != 2 {
        return None;
    }
    let non_star: Vec<&str> = parts.iter().copied().filter(|t| *t != "*").collect();
    let only_char_or_const = non_star.iter().all(|t| *t == "char" || *t == "const");
    // `char **`, `const char **`, and `const char *const *` (inner const, common
    // for string arrays) — exactly one `char` plus any number of `const` tokens.
    if non_star.iter().filter(|t| **t == "char").count() == 1 && only_char_or_const {
        Some(non_star.contains(&"const"))
    } else {
        None
    }
}

/// Decode a `char **` / `const char **` parameter. A name reading like an OUTPUT
/// slot (`end`/`parse_end`/`offset`/`position`) gets a scratch `NULL` pointer the
/// callee writes the final position to; otherwise it is treated as an in-out
/// CURSOR pointing at a NUL-terminated heap string the parser advances (the parson
/// recursive-descent core: `parse_value`/`parse_array_value`/`parse_object_value`).
fn char_double_pointer(is_const: bool, name: &str) -> CParamEmission {
    let elem = if is_const { "const char" } else { "char" };
    let lower = name.to_ascii_lowercase();
    let is_out = ["end", "offset", "position", "rest", "remainder"]
        .iter()
        .any(|m| lower.contains(m))
        || lower == "pos";
    if is_out {
        CParamEmission {
            support: None,
            decl: format!("{elem} *_gf_end_{name} = 0; {elem} **{name} = &_gf_end_{name}"),
            arg: name.to_owned(),
            c_type: format!("{elem} **"),
            free: None,
        }
    } else {
        CParamEmission {
            support: None,
            decl: format!(
                "char *_gf_buf_{name} = gf_c_string(&Cur, 4096); \
                 {elem} *_gf_p_{name} = _gf_buf_{name}; \
                 {elem} **{name} = &_gf_p_{name}"
            ),
            arg: name.to_owned(),
            c_type: format!("{elem} **"),
            free: Some(format!("free(_gf_buf_{name})")),
        }
    }
}

fn out_pointer_decoder(c_type: &str, name: &str) -> Option<CParamEmission> {
    let trimmed = c_type
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("*", " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.last().copied() != Some("*") {
        return None;
    }
    let base = parts[..parts.len() - 1].join(" ");
    // Skip pointer-to-pointer for now (would need a slot table).
    if base.contains('*') {
        return None;
    }
    let (decoder_expr, storage_init) = match base.as_str() {
        "int" | "signed int" => ("gf_i32(&Cur)", "0"),
        "unsigned" | "unsigned int" => ("(unsigned int)gf_bounded_i32(&Cur, 0, 0x7fffffff)", "0"),
        "long" | "signed long" => ("(long)gf_i64(&Cur)", "0"),
        "unsigned long" => ("(unsigned long)gf_bounded_length(&Cur, 0, 0x7fffffff)", "0"),
        "uLong" | "uLongf" => ("(uLong)gf_bounded_length(&Cur, 0, 0x7fffffff)", "0"),
        "uInt" => ("(uInt)gf_bounded_i32(&Cur, 0, 0x7fffffff)", "0"),
        "z_size_t" => ("(z_size_t)gf_bounded_length(&Cur, 0, 65536)", "0"),
        "mz_ulong" => ("(mz_ulong)gf_bounded_length(&Cur, 0, 0x7fffffff)", "0"),
        "long long" | "signed long long" => ("gf_i64(&Cur)", "0"),
        "size_t" => ("gf_bounded_length(&Cur, 0, 65536)", "0"),
        "uint8_t" | "unsigned char" => ("gf_u8(&Cur)", "0"),
        "int8_t" | "signed char" | "char" => ("(int8_t)gf_u8(&Cur)", "0"),
        "int32_t" => ("gf_i32(&Cur)", "0"),
        "uint32_t" => ("(uint32_t)gf_bounded_i32(&Cur, 0, 0x7fffffff)", "0"),
        "int64_t" => ("gf_i64(&Cur)", "0"),
        "uint64_t" => ("(uint64_t)gf_i64(&Cur)", "0"),
        _ => return None,
    };
    let storage_name = format!("_gf_out_{name}");
    let _ = storage_init;
    let decl =
        format!("{base} {storage_name} = ({base}){decoder_expr}; {base} *{name} = &{storage_name}");
    Some(CParamEmission {
        support: None,
        decl,
        arg: name.to_owned(),
        c_type: format!("{base} *"),
        free: None,
    })
}

/// A `const char *`/`char *` parameter whose NAME marks it as a FILE PATH (an API
/// that opens the path and reads it), not an in-band string. Conservative — only
/// unambiguous file-path names — so a string param named e.g. `path` to a JSON
/// pointer API is left as the normal `gf_c_string` decoder. Recognises the common
/// spellings (`filename`/`filepath`/`file_name`/`pathname`/`infile`/…) and the
/// `*_path`/`*_file`/`*filename`/`*filepath` suffix conventions.
pub(crate) fn is_file_path_param_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "filename"
            | "filepath"
            | "file_name"
            | "file_path"
            | "fname"
            | "fpath"
            | "pathname"
            | "infile"
            | "in_file"
            | "input_file"
            | "inputfile"
            | "inputpath"
            | "input_path"
            | "outfile"
            | "out_file"
            | "output_file"
    ) || n.ends_with("_path")
        || n.ends_with("_file")
        || n.ends_with("filename")
        || n.ends_with("filepath")
}

/// True when the ENCLOSING function opens a filesystem PATH and reads/parses it
/// (pugixml `load_file`, `*_read_file`/`*_parse_file`/`*_open_file`/`*_from_file`),
/// so an otherwise-ambiguous `path`/`source`/`uri` string parameter is a FILE PATH
/// whose CONTENT should be the fuzz input (a tempfile), not an in-band string (#25).
/// Without this a fuzzed `gf_c_string` path ENOENTs and the parser never runs — a
/// hollow false-clean. Matches the bare leaf so a C++-qualified name works too.
pub(crate) fn is_file_io_function_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let leaf = lower.rsplit("::").next().unwrap_or(&lower);
    [
        "load_file",
        "read_file",
        "parse_file",
        "open_file",
        "from_file",
        "loadfile",
        "readfile",
        "parsefile",
        "openfile",
        "fromfile",
    ]
    .iter()
    .any(|kw| leaf.contains(kw))
}

/// File-path-ish parameter names that are ambiguous in isolation (a JSON-pointer
/// `path`) but ARE a filesystem path when the enclosing function is a file LOADER
/// (#25): bare `path`/`path_`/`source`/`uri`, plus everything
/// [`is_file_path_param_name`] already recognizes unconditionally. Gated by the
/// caller on [`is_file_io_function_name`].
pub(crate) fn is_loader_file_path_param_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(n.as_str(), "path" | "path_" | "source" | "uri") || is_file_path_param_name(name)
}

/// True when a `char *` parameter names a printf-style FORMAT string (fmt /
/// format / …). Such a parameter is fed a `%`-neutralised string so a variadic
/// formatter (log.c's `log_log`) — which the harness calls with NO matching
/// variadic arguments — cannot read a garbage vararg through a `%s`/`%n` and
/// crash. That crash is a harness format/argument mismatch, not a target bug.
pub(crate) fn is_format_string_param_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "fmt" | "format" | "fmtstr" | "fmt_str" | "format_str" | "format_string" | "formatstr"
    )
}

/// Whether `c_type` is a plain (possibly `const`) `char *` — the spellings the
/// string decoders handle. Used to recognise the format parameter of a variadic
/// function (the last fixed `char *` before the `...`).
pub(crate) fn is_plain_char_ptr_type(c_type: &str) -> bool {
    matches!(
        c_type.trim(),
        "const char *" | "const char*" | "char const *" | "char *" | "char*"
    )
}

/// Emit a printf-style FORMAT parameter: a NUL-terminated heap string with every
/// `%` neutralised (`gf_c_format_string`) rather than the plain `gf_c_string`. A
/// variadic logging/format function (log.c's `log_log`) takes the format but the
/// harness passes NO matching varargs, so a `%s`/`%n` in a fuzzed format makes
/// vfprintf read a garbage vararg and crash — a harness format/argument mismatch
/// FALSE POSITIVE, not a target bug (a %-free format calls the function
/// correctly). Used both for parameters NAMED fmt/format and for the last fixed
/// `char *` of a variadic function.
pub(crate) fn c_format_string_param(name: &str, is_const: bool) -> CParamEmission {
    CParamEmission {
        support: None,
        decl: format!("char *{name} = gf_c_format_string(&Cur, 4096)"),
        arg: name.to_owned(),
        c_type: if is_const { "const char *" } else { "char *" }.to_owned(),
        free: Some(format!("free({name})")),
    }
}

/// Drive a file-PATH parameter: write the fuzz input to a temp file (its CONTENT
/// is the fuzz input) and pass the path. The auto-harnessing analogue of
/// `fmemopen` for `FILE*` — it lets `auto` fuzz format parsers whose only entry is
/// a path-taking `load`/`read`/`parse`/`open` API (e.g. libE57Format's reader),
/// which would otherwise be un-harnessable. The temp file is unlinked after.
pub(crate) fn file_path_param(name: &str, is_const: bool) -> CParamEmission {
    let cty = if is_const { "const char *" } else { "char *" };
    // Emitted in the function body (where Data/Size live), like `file_pointer` —
    // NOT in `support`, which is top-level scope. The trailing param decl is last
    // so the template's appended `;` completes it.
    CParamEmission {
        support: None,
        decl: format!(
            "char {name}_path[gf_tempfile_path_len]; \
             const char *{name}_made = gf_make_tempfile(Data, Size, {name}_path); \
             {cty} {name} = {name}_made ? {name}_path : \"\""
        ),
        arg: name.to_owned(),
        c_type: cty.to_owned(),
        free: Some(format!("if ({name}_made) unlink({name}_path)")),
    }
}

fn file_pointer(c_type: &str, name: &str) -> CParamEmission {
    let decl = if c_type == "FILE *" {
        format!(r#"FILE * {name} = fmemopen((void *)Data, Size, "rb")"#)
    } else {
        format!(r#"{c_type} {name} = ({c_type})fmemopen((void *)Data, Size, "rb")"#)
    };
    CParamEmission {
        support: None,
        decl,
        arg: name.to_owned(),
        c_type: c_type.to_owned(),
        free: Some(format!("if ({name}) fclose({name})")),
    }
}

fn const_void_pointer(name: &str) -> CParamEmission {
    CParamEmission {
        support: None,
        decl: format!("const void * {name} = (const void *)Data"),
        arg: name.to_owned(),
        c_type: "const void *".to_owned(),
        free: None,
    }
}

fn mutable_void_pointer(name: &str) -> CParamEmission {
    CParamEmission {
        support: None,
        decl: format!(
            "void * {name} = calloc(Size ? Size : 1, 1); if ({name} && Size) memcpy({name}, Data, Size)"
        ),
        arg: name.to_owned(),
        c_type: "void *".to_owned(),
        free: Some(format!("free({name})")),
    }
}

/// Best-effort decoder for a parameter the normal type-directed selectors
/// REJECT — used only under `auto --force` (force-fuzz). The goal is a driver
/// that COMPILES for an opaque/vendor/function-pointer/aggregate parameter, so a
/// target that would otherwise be skipped `unsupported_params` still gets built
/// and fuzzed. Value correctness is explicitly NOT a goal: force mode accepts
/// false positives, so a plausibly-typed zero/buffer/NULL is acceptable.
///
/// Strictly additive: every non-force path is unchanged; this is never reached
/// unless the caller opts in via the `force` flag at a rejection site.
///
/// - Function pointer (`ret (*)(args)`, detected by a `(*` declarator): pass a
///   NULL of the exact type — `(<c_type>)0`. A callee that dereferences it may
///   crash, which force mode reports as a finding.
/// - Any pointer type (`T *`, `T **`, …): a heap byte buffer filled from the
///   fuzz `(Data, Size)` input, cast to the parameter type. For an opaque /
///   incomplete pointee this is a zeroed (or input-filled) region — enough to
///   pass, and the callee decides what to read.
/// - Non-pointer unknown / aggregate: a zero-initialized stack object of the
///   type, passed by value. Compiles for any complete type; an incomplete value
///   type is not representable by value in C, so those still can't appear here.
pub fn best_effort_param_emission(c_type: &str, name: &str) -> CParamEmission {
    let trimmed = c_type.trim();
    // Function pointer: a `(*` declarator (`void (*)(int)`, `int (*cb)(void)`).
    if trimmed.contains("(*") {
        return CParamEmission {
            support: None,
            decl: format!("{trimmed} {name} = ({trimmed})0"),
            arg: name.to_owned(),
            c_type: trimmed.to_owned(),
            free: None,
        };
    }
    // Any pointer type: a heap byte buffer from the fuzz input, cast to the
    // parameter type. `calloc(Size ? Size : 1, 1)` guarantees a non-NULL,
    // zeroed region even for empty input; the cast reaches any pointee spelling
    // (opaque struct, vendor typedef, `T **`).
    if trimmed.ends_with('*') {
        let buf = format!("_gf_force_{name}");
        return CParamEmission {
            support: None,
            decl: format!(
                "void * {buf} = calloc(Size ? Size : 1, 1); \
                 if ({buf} && Size) memcpy({buf}, Data, Size); \
                 {trimmed} {name} = ({trimmed}){buf}"
            ),
            arg: name.to_owned(),
            c_type: trimmed.to_owned(),
            free: Some(format!("free({buf})")),
        };
    }
    // Non-pointer unknown / aggregate value: a zero-initialized stack object.
    // `{0}` zero-initializes a struct/union/array; a scalar it does not reach
    // here (scalars are handled by the normal decoders and never rejected).
    CParamEmission {
        support: None,
        decl: format!("{trimmed} {name} = ({trimmed}){{0}}"),
        arg: name.to_owned(),
        c_type: trimmed.to_owned(),
        free: None,
    }
}

/// Image/audio channel- or component-count parameter names — a tiny enum (1..4),
/// bounded small rather than fuzzed as a free integer (see legacy_select_c_decoder).
/// Conservative: only count/component words, never generic ints like `count`/`n`.
fn is_channel_count_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "channels"
            | "num_channels"
            | "n_channels"
            | "nchannels"
            | "nchan"
            | "num_chan"
            | "channel_count"
            | "components"
            | "num_components"
            | "n_components"
            | "ncomp"
            | "ncomps"
            | "comps"
            | "num_comps"
            | "component_count"
            | "req_comps"
            | "req_comp"
            | "req_channels"
            | "desired_channels"
            | "desired_comps"
            | "out_channels"
            | "in_channels"
    ) || n.ends_with("_channels")
        || n.ends_with("_components")
        || n.ends_with("_comps")
}

/// The canonical decl type for a small integer suitable for a bounded enum value,
/// or None for non-small-int types (so a `channels`-named pointer/float/64-bit int
/// is left to the normal type-based decoder).
fn small_int_decl_type(normalized: &str) -> Option<&'static str> {
    match normalized {
        "int" | "signed int" => Some("int"),
        "unsigned" | "unsigned int" => Some("unsigned int"),
        "int32_t" => Some("int32_t"),
        "uint32_t" => Some("uint32_t"),
        "int16_t" => Some("int16_t"),
        "uint16_t" => Some("uint16_t"),
        "short" | "signed short" => Some("short"),
        "unsigned short" => Some("unsigned short"),
        _ => None,
    }
}

fn scalar(name: &str, c_type: &str, decoder: &str) -> CParamEmission {
    CParamEmission {
        support: None,
        decl: format!("{c_type} {name} = {decoder}"),
        arg: name.to_owned(),
        c_type: c_type.to_owned(),
        free: None,
    }
}

/// True when a parameter name denotes an ownership-transfer flag — it tells the
/// callee to take ownership of (and later `free`) a buffer the harness passed
/// in. `plm_create_with_memory(bytes, length, free_when_done)`,
/// `stbi_load_from_callbacks(..., int free_data)`, `..., int take_ownership`.
fn is_ownership_transfer_flag_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Distinctive ownership phrases only — never a bare "free"/"own" token, so a
    // normal flag like `free_slots` or `unknown` can't match.
    const NEEDLES: &[&str] = &[
        "free_when",
        "free_on_",
        "free_data",
        "free_buffer",
        "free_memory",
        "free_input",
        "free_src",
        "should_free",
        "do_free",
        "take_ownership",
        "takes_ownership",
        "transfer_ownership",
        "owns_data",
        "owns_buffer",
        "owns_memory",
        "own_data",
    ];
    NEEDLES.iter().any(|needle| lower.contains(needle)) || lower == "free_when_done"
}

/// Pass an allocation-callbacks / allocator pointer as NULL instead of a
/// fabricated zeroed struct. Such a pointer is optional by convention across the
/// C ecosystem (dr_libs, miniaudio, …): NULL means "use the library's default
/// malloc/free". A zeroed-but-non-NULL struct has NULL function pointers, which
/// libraries that validate the callbacks reject — so the call bails before doing
/// any real work and the target bounces off an early return (drwav_init_memory
/// fuzzed at 14 edges, never reaching the WAV parser). Passing NULL lets the
/// default allocator kick in so the parser actually runs.
fn allocator_callbacks_nulled(c_type: &str, name: &str) -> Option<CParamEmission> {
    // Only meaningful for a pointer parameter.
    if !c_type.contains('*') {
        return None;
    }
    let lower_type = c_type.to_ascii_lowercase();
    let lower_name = name.to_ascii_lowercase();
    let is_allocator = lower_type.contains("allocation_callbacks")
        || lower_type.contains("alloc_callbacks")
        || lower_type.contains("allocator")
        || lower_name.contains("allocationcallbacks")
        || lower_name.contains("allocation_callbacks")
        || lower_name.contains("allocator");
    if !is_allocator {
        return None;
    }
    Some(scalar(name, c_type, "NULL"))
}

/// Pin an ownership-transfer flag parameter to 0 instead of decoding it from the
/// fuzz cursor. Fuzzing it to non-zero makes the callee free the harness's own
/// input buffer, which the harness then frees again — a double-free ASan reports
/// as a finding with no bug in the target (observed on pl_mpeg's
/// `plm_create_with_memory(..., free_when_done)`). Only plain integer/bool
/// scalars qualify; anything else falls through to the normal decoders.
fn ownership_flag_pinned(c_type: &str, name: &str) -> Option<CParamEmission> {
    if !is_ownership_transfer_flag_name(name) {
        return None;
    }
    let normalized = c_type
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "restrict" | "register"))
        .collect::<Vec<_>>()
        .join(" ");
    let is_integer_or_bool = matches!(
        normalized.as_str(),
        "int"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "_Bool"
            | "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "short int"
            | "unsigned short"
            | "long"
            | "long int"
            | "unsigned long"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
    );
    if !is_integer_or_bool {
        return None;
    }
    Some(scalar(name, &normalized, "0"))
}

/// True when a parameter NAME denotes a control flag / mode / options bitmask that
/// DISCRIMINATES a tagged union or selects an internal dispatch path — `flags`,
/// `mode`, `options`. Conservative: only the canonical discriminator words (exact
/// or a `_flags`/`_mode`/`_options` suffix), never a generic int, so a real
/// numeric parameter (`width`, `level`, `count`) is left fuzzable.
fn is_control_flag_param_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "flags" | "flag" | "mode" | "modes" | "options" | "option" | "opts"
    ) || n.ends_with("_flags")
        || n.ends_with("_flag")
        || n.ends_with("_mode")
        || n.ends_with("_options")
        || n.ends_with("_opts")
}

/// Pin a control-flag / mode / options DISCRIMINATOR integer to 0 (the default
/// mode) instead of fuzzing it. Such a parameter selects a tagged-union variant or
/// an internal dispatch (tinycbor `cbor_parser_init`'s `uint32_t flags` has an
/// ExternalSource bit that makes the callee deref `source.ops`; `cbor_encoder_init`'s
/// `int flags` has a WriterFunction bit that calls the buffer pointer as a
/// function). Fuzzing the discriminator full-range trips a reserved/invalid bit and
/// produces an OOB deref or a wild jump — a harness artifact, since the real caller
/// passes a documented (usually 0) flag value. Only plain integer scalars qualify.
fn control_flag_pinned(c_type: &str, name: &str) -> Option<CParamEmission> {
    if !is_control_flag_param_name(name) {
        return None;
    }
    let normalized = c_type
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "restrict" | "register"))
        .collect::<Vec<_>>()
        .join(" ");
    let is_integer = matches!(
        normalized.as_str(),
        "int"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "short"
            | "short int"
            | "unsigned short"
            | "long"
            | "long int"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "size_t"
    );
    if !is_integer {
        return None;
    }
    Some(scalar(name, &normalized, "0"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use type_model::TypeRegistry;

    fn registry(source: &str) -> TypeRegistry {
        let defs = c_parser::parse_c_type_defs(source).expect("type defs parse");
        TypeRegistry::from_defs([&defs])
    }

    #[test]
    fn control_flag_discriminator_is_pinned_to_zero() {
        // Campaign #11: tinycbor `cbor_parser_init`'s `uint32_t flags` (ExternalSource
        // bit -> source.ops deref OOB) and `cbor_encoder_init`'s `int flags`
        // (WriterFunction bit -> buffer ptr called as a function = wild jump)
        // discriminate a tagged union. Fuzzing them full-range trips a reserved bit
        // -> a harness-artifact crash. Pin a flags/mode/options discriminator to 0.
        let f =
            select_c_decoder_with_registry("uint32_t", "flags", &registry("")).expect("supported");
        assert_eq!(f.decl, "uint32_t flags = 0");
        let m = select_c_decoder_with_registry("int", "mode", &registry("")).expect("supported");
        assert_eq!(m.decl, "int mode = 0");
        let o = select_c_decoder_with_registry("int", "options", &registry("")).expect("supported");
        assert_eq!(o.decl, "int options = 0");
        let suffixed = select_c_decoder_with_registry("uint32_t", "parse_flags", &registry(""))
            .expect("supported");
        assert_eq!(suffixed.decl, "uint32_t parse_flags = 0");
        // control_flag_pinned itself only matches discriminator names + integer types.
        assert!(control_flag_pinned("int", "width").is_none());
        assert!(control_flag_pinned("int", "level").is_none());
        // A `char *` named `mode` (an fopen-style mode string) is NOT an integer
        // discriminator, so it stays a string decode.
        assert!(control_flag_pinned("char *", "mode").is_none());
        // A real numeric param is still fuzzed end-to-end.
        let w = select_c_decoder_with_registry("int", "width", &registry("")).expect("supported");
        assert!(w.decl.contains("gf_i32(&Cur)"), "{}", w.decl);
    }

    #[test]
    fn ownership_transfer_flag_is_pinned_to_zero_not_fuzzed() {
        // `free_when_done`/`take_ownership` tell the callee to free the buffer
        // the harness passed in; fuzzing the flag non-zero makes the library
        // free the harness's own input, which the harness frees again — a
        // double-free ASan reports with no bug in the target (pl_mpeg's
        // plm_create_with_memory). Pin such flags to 0.
        let pinned = ownership_flag_pinned("int", "free_when_done").expect("pinned");
        assert_eq!(pinned.decl, "int free_when_done = 0");
        assert_eq!(pinned.arg, "free_when_done");
        assert!(ownership_flag_pinned("int", "take_ownership").is_some());
        assert!(ownership_flag_pinned("_Bool", "should_free").is_some());
        assert!(ownership_flag_pinned("unsigned char", "owns_data").is_some());
        // const is stripped for the type check but a sane spelling is emitted.
        assert_eq!(
            ownership_flag_pinned("const int", "free_buffer")
                .unwrap()
                .decl,
            "int free_buffer = 0"
        );
        // A normal flag/dimension is NOT pinned (still fuzzed).
        assert!(ownership_flag_pinned("int", "flags").is_none());
        assert!(ownership_flag_pinned("int", "width").is_none());
        assert!(ownership_flag_pinned("int", "num_free_slots").is_none());
        // Only integer/bool scalars qualify; a pointer named like a flag is not.
        assert!(ownership_flag_pinned("void *", "free_data").is_none());
    }

    #[test]
    fn allocation_callbacks_pointer_is_passed_as_null() {
        // An allocator-callbacks pointer is optional (NULL => library defaults);
        // a fabricated zeroed struct has NULL fn-pointers that drwav rejects,
        // bailing before the parse. Match on the type or the parameter name.
        let by_type = allocator_callbacks_nulled(
            "const drwav_allocation_callbacks *",
            "pAllocationCallbacks",
        )
        .expect("nulled");
        assert_eq!(
            by_type.decl,
            "const drwav_allocation_callbacks * pAllocationCallbacks = NULL"
        );
        assert_eq!(by_type.arg, "pAllocationCallbacks");
        assert!(allocator_callbacks_nulled("ma_allocator *", "p").is_some());
        assert!(allocator_callbacks_nulled("struct foo *", "allocator").is_some());
        // Not an allocator, or not a pointer -> left to the normal decoders.
        assert!(allocator_callbacks_nulled("const wav_fmt *", "fmt").is_none());
        assert!(allocator_callbacks_nulled("int", "allocatorId").is_none());
    }

    #[test]
    fn strip_type_decoration_drops_specifiers_attrs_and_decoration_macros() {
        // Decoration macros leak from the return type into `<type> R = ...`.
        assert_eq!(
            strip_type_decoration("simdjson_inline simdjson_result<T>"),
            "simdjson_result<T>"
        );
        assert_eq!(strip_type_decoration("SIMDJSON_WARN_UNUSED bool"), "bool");
        assert_eq!(strip_type_decoration("CTRE_FORCE_INLINE auto"), "auto");
        assert_eq!(strip_type_decoration("HB_UNUSED int"), "int");
        // API-definition / visibility macros (TSFDEF, WREN_API, DRFLAC_API, STBIDEF,
        // JSON_DECL) expand to extern/static and must be stripped from the return
        // type, else `<type> R = call()` is an illegal block-scope linked decl.
        assert_eq!(strip_type_decoration("TSFDEF tsf *"), "tsf *");
        assert_eq!(strip_type_decoration("WREN_API WrenVM *"), "WrenVM *");
        assert_eq!(strip_type_decoration("DRFLAC_API drflac *"), "drflac *");
        assert_eq!(
            strip_type_decoration("STBIDEF unsigned char *"),
            "unsigned char *"
        );
        assert_eq!(strip_type_decoration("JSON_DECL int"), "int");
        // Function-like export macros that take the type as an argument (cJSON's
        // `CJSON_PUBLIC(cJSON *)`, `MYLIB_API(int)`) wrap the whole type and must
        // be unwrapped to the bare inner type — on Windows they expand to
        // `__declspec(dllexport) <type>`, illegal on a local result variable.
        assert_eq!(strip_type_decoration("CJSON_PUBLIC(cJSON *)"), "cJSON *");
        assert_eq!(strip_type_decoration("MYLIB_API(int)"), "int");
        assert_eq!(
            strip_type_decoration("CJSON_PUBLIC(const char *)"),
            "const char *"
        );
        // But a single-token type that merely ends this way is NOT stripped.
        assert_eq!(strip_type_decoration("MYDEF"), "MYDEF");
        assert_eq!(strip_type_decoration("config_t"), "config_t");
        // Lowercase `name(...)` is not a macro wrapper, and a function-pointer
        // spelling must survive (the leading token is a real type keyword).
        assert_eq!(strip_type_decoration("foo_t(int)"), "foo_t(int)");
        assert_eq!(strip_type_decoration("void (*)(int)"), "void (*)(int)");
        // Calling-convention / storage keywords.
        assert_eq!(strip_type_decoration("__vectorcall __m128i"), "__m128i");
        assert_eq!(strip_type_decoration("static inline size_t"), "size_t");
        // __attribute__ runs.
        assert_eq!(
            strip_type_decoration("__attribute__((warn_unused_result)) int"),
            "int"
        );
        // Type-building keywords and real types are preserved.
        assert_eq!(strip_type_decoration("unsigned long"), "unsigned long");
        assert_eq!(strip_type_decoration("const char *"), "const char *");
        assert_eq!(
            strip_type_decoration("simdjson_result<T>"),
            "simdjson_result<T>"
        );
        assert_eq!(
            strip_type_decoration("struct archive *"),
            "struct archive *"
        );
        // Parameter-attribute macros that expand to __attribute__((noescape))
        // (xxHash's XXH_NOESCAPE) are dropped so they don't pollute the type.
        assert_eq!(
            strip_type_decoration("XXH_NOESCAPE XXH3_state_t *"),
            "XXH3_state_t *"
        );
        // Never empties: a lone decoration-looking token is kept (degrade safe).
        assert_eq!(strip_type_decoration("HB_UNUSED"), "HB_UNUSED");
    }

    #[test]
    fn sanitize_param_name_drops_misparsed_leading_qualifiers() {
        // A top-level pointer `const` (`const uint8_t * const src`) is sometimes
        // mis-split by the parser so the trailing `const` lands on the NAME side
        // (`name = "const src"`). The call argument must be the bare identifier,
        // never `const src` — `func(const src)` is not a valid expression.
        assert_eq!(sanitize_param_name("const src"), "src");
        assert_eq!(sanitize_param_name("volatile buf"), "buf");
        assert_eq!(sanitize_param_name("const volatile p"), "p");
        // `restrict`/`__restrict` leak the same way (harfbuzz's `__restrict row_buf`
        // became the local name `_gf_out___restrict row_buf`).
        assert_eq!(sanitize_param_name("__restrict row_buf"), "row_buf");
        assert_eq!(sanitize_param_name("restrict area"), "area");
        // Trailing attribute macros after the declarator (`const void * data HB_UNUSED`,
        // parsed name = "data HB_UNUSED") must be dropped too — keep the identifier.
        assert_eq!(sanitize_param_name("data HB_UNUSED"), "data");
        // A well-formed bare identifier is left untouched.
        assert_eq!(sanitize_param_name("src"), "src");
        assert_eq!(sanitize_param_name(""), "");
        // `const` as a genuine (if unusual) identifier survives if it is the
        // sole token — we only drop it as a leading qualifier before a real name.
        assert_eq!(sanitize_param_name("const"), "const");
        // An unnamed parameter gets a synthesized positional name so the decoder
        // never emits a nameless local / `memset(&, 0, sizeof )`.
        assert_eq!(sanitize_or_synthesize_param_name("", 2), "_gf_arg2");
        assert_eq!(sanitize_or_synthesize_param_name("buf", 0), "buf");
        assert_eq!(sanitize_or_synthesize_param_name("const x", 1), "x");
    }

    #[test]
    fn const_char_field_cleanup_casts_through_void_pointer() {
        // harfbuzz's hb_sanitize_context_t has `const char *start, *end;`. The
        // synthesized field decode strdup's the bytes and frees them on cleanup,
        // but C++'s free(void *) rejects a `const char *` argument — the cast must
        // launder the const (`free((void *)x.start)`).
        let reg = registry("struct ctx { const char *start; const char *end; };");
        let e = select_c_decoder_with_registry("struct ctx", "x", &reg)
            .expect("a by-value struct with const char* fields should decode");
        let free = e.free.unwrap_or_default();
        assert!(
            free.contains("free((void *)x.start)") && free.contains("free((void *)x.end)"),
            "const char* field frees must cast through void*, got: {free}"
        );
    }

    #[test]
    fn array_typedef_struct_field_is_decoded_elementwise() {
        // tcpdump declares header fields with array typedefs
        // (`typedef unsigned char nd_uint8_t[1];`). The field type spelling
        // carries no `[...]`, but the resolved shape is an array — the decoder
        // must index into it (`x.ip6_vfc[0] = ...`), never assign a scalar to an
        // array lvalue and never leave it zeroed.
        let reg = registry(
            "typedef unsigned char nd_uint8_t[1]; typedef unsigned char nd_uint16_t[2]; \
             struct ip6_hdr { nd_uint8_t ip6_vfc; nd_uint16_t ip6_plen; };",
        );
        let e = select_c_decoder_with_registry("struct ip6_hdr", "x", &reg)
            .expect("a by-value struct with array-typedef fields should decode");
        assert!(
            e.decl.contains("x.ip6_vfc[") && e.decl.contains("x.ip6_plen["),
            "array-typedef fields must be indexed and decoded, got: {}",
            e.decl
        );
        assert!(
            !e.decl.contains("ip6_vfc left zeroed") && !e.decl.contains("ip6_plen left zeroed"),
            "array-typedef fields must not be skipped/zeroed, got: {}",
            e.decl
        );
    }

    #[test]
    fn const_pointer_to_opaque_struct_overlays_fuzz_input() {
        // A read-only pointer to an opaque packet/message type (cFE's
        // `const CFE_MSG_Message_t *`) is the canonical wire-format fuzz target:
        // back it with the raw fuzz input rather than skipping the target.
        let reg = registry("struct unrelated { int x; };");
        let e = select_c_decoder_with_registry("const widget_t *", "msg", &reg)
            .expect("const opaque pointer should overlay the fuzz input");
        assert!(
            e.decl.contains("(const widget_t *)Data"),
            "expected byte overlay of the input, got: {}",
            e.decl
        );
    }

    #[test]
    fn format_string_param_uses_neutralised_decoder() {
        // A printf-style format param (named fmt/format) must be decoded with
        // gf_c_format_string (which strips `%`), NOT gf_c_string: a variadic
        // formatter (log.c log_log) is called with no matching varargs, so a `%s`
        // in a fuzzed format makes vfprintf read a garbage vararg and crash — a
        // harness format/argument mismatch FALSE POSITIVE.
        let fmt = select_c_decoder("const char *", "fmt").expect("fmt is supported");
        assert!(
            fmt.decl.contains("gf_c_format_string(&Cur"),
            "fmt param must use the %-neutralising decoder: {}",
            fmt.decl
        );
        let format = select_c_decoder("char *", "format").expect("format is supported");
        assert!(
            format.decl.contains("gf_c_format_string(&Cur"),
            "{}",
            format.decl
        );
        // A NON-format char* stays on the plain NUL-terminating decoder.
        let msg = select_c_decoder("const char *", "name").expect("name is supported");
        assert!(
            msg.decl.contains("gf_c_string(&Cur") && !msg.decl.contains("gf_c_format_string"),
            "a non-format char* must stay on gf_c_string: {}",
            msg.decl
        );
    }

    #[test]
    fn nonconst_pointer_to_opaque_struct_still_skips() {
        // A mutable opaque pointer may be a handle the callee writes through;
        // overlaying the read-only fuzz input would be unsafe, so it stays an
        // honest skip (a lifecycle pair, if present, drives it instead).
        let reg = registry("struct unrelated { int x; };");
        assert!(select_c_decoder_with_registry("widget_t *", "handle", &reg).is_err());
    }

    #[test]
    fn select_c_decoder_handles_int() {
        let e = select_c_decoder("int", "x").expect("int is supported");
        assert!(e.decl.contains("int x = gf_i32(&Cur)"));
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_handles_win32_bool_and_dword_scalars() {
        // Offline MFC/Win32 dogfood: <windows.h> is NOT in the scanned tree, so
        // BOOL/DWORD have no typedef to chase. They must still decode as their
        // underlying integer (keeping the alias spelling so they compile once the
        // target's own headers/stub define them) rather than skip the whole target
        // as opaque "needs lifecycle support (Phase C)".
        let reg = TypeRegistry::default();
        let b = select_c_decoder_with_registry("BOOL", "flag", &reg).expect("BOOL is a scalar");
        assert!(
            b.decl.contains("BOOL flag = (BOOL)gf_i32(&Cur)"),
            "{}",
            b.decl
        );
        assert!(b.free.is_none());
        let d = select_c_decoder_with_registry("DWORD", "count", &reg).expect("DWORD is a scalar");
        assert!(
            d.decl
                .contains("DWORD count = (DWORD)gf_bounded_i32(&Cur, 0, 0x7fffffff)"),
            "{}",
            d.decl
        );
    }

    #[test]
    fn select_c_decoder_handles_const_char_ptr_with_free() {
        let e = select_c_decoder("const char *", "name").expect("const char* is supported");
        assert!(e.decl.contains("gf_c_string"));
        assert_eq!(e.free.as_deref(), Some("free(name)"));
    }

    #[test]
    fn select_c_decoder_drives_const_char_double_pointer_cursor() {
        // parson `parse_value(const char **string)` — an in-out cursor: point it at
        // a NUL-terminated heap string the parser advances.
        let e = select_c_decoder("const char **", "string").expect("char** cursor supported");
        assert!(e.decl.contains("gf_c_string"), "{}", e.decl);
        assert!(
            e.decl.contains("const char **string = &_gf_p_string"),
            "{}",
            e.decl
        );
        assert_eq!(e.free.as_deref(), Some("free(_gf_buf_string)"));
    }

    #[test]
    fn select_c_decoder_drives_const_char_double_pointer_out_param() {
        // cJSON `cJSON_ParseWithLengthOpts(..., const char **return_parse_end)` — an
        // OUTPUT slot: pass a scratch NULL pointer, no fuzz input consumed, no free.
        let e = select_c_decoder("const char **", "return_parse_end")
            .expect("char** out-param supported");
        assert!(
            e.decl.contains("const char *_gf_end_return_parse_end = 0"),
            "{}",
            e.decl
        );
        assert!(!e.decl.contains("gf_c_string"), "{}", e.decl);
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_handles_size_t_with_bound() {
        let e = select_c_decoder("size_t", "len").expect("size_t is supported");
        assert!(e.decl.contains("gf_bounded_length"));
    }

    #[test]
    fn select_c_decoder_handles_bool_and_16bit_scalars() {
        let flag = select_c_decoder("bool", "flag").expect("bool is supported");
        assert!(flag.decl.contains("bool flag = (bool)(gf_u8(&Cur) & 1)"));
        assert_eq!(flag.c_type, "bool");

        let wide = select_c_decoder("uint16_t", "wide").expect("uint16_t is supported");
        assert!(wide
            .decl
            .contains("uint16_t wide = (uint16_t)gf_bounded_i32(&Cur, 0, 0xffff)"));
        assert_eq!(wide.c_type, "uint16_t");

        let signed = select_c_decoder("int16_t", "signed_value").expect("int16_t is supported");
        assert!(signed
            .decl
            .contains("int16_t signed_value = (int16_t)gf_i32(&Cur)"));
        assert_eq!(signed.c_type, "int16_t");
    }

    #[test]
    fn select_c_decoder_handles_float_double_and_short_scalars() {
        // The registry-LESS decoder must accept these so the C++ lifecycle gate
        // (`cpp_parameter_type_supported`, which probes this path) agrees with the
        // registry-aware emission path — otherwise a `double` param silently drops
        // the lifecycle step (INIReader::GetReal).
        let d = select_c_decoder("double", "v").expect("double is supported");
        assert!(
            d.decl.contains("double v = (double)gf_i64(&Cur)"),
            "{}",
            d.decl
        );
        let f = select_c_decoder("float", "f").expect("float is supported");
        assert!(
            f.decl.contains("float f = (float)gf_i32(&Cur)"),
            "{}",
            f.decl
        );
        let s = select_c_decoder("short", "s").expect("short is supported");
        assert!(
            s.decl.contains("short s = (short)gf_i32(&Cur)"),
            "{}",
            s.decl
        );
        let us = select_c_decoder("unsigned short", "u").expect("unsigned short is supported");
        assert!(
            us.decl
                .contains("unsigned short u = (unsigned short)gf_bounded_i32(&Cur, 0, 0xffff)"),
            "{}",
            us.decl
        );
    }

    #[test]
    fn channel_count_int_params_are_bounded_small_not_full_range() {
        // A channel/component-count param must be a tiny bounded enum so a decode
        // entry actually runs (jpgd req_comps must be 0/1/3/4): a full-range gf_i32
        // never lands on a valid count and the decoder body is never exercised.
        for n in [
            "req_comps",
            "channels",
            "num_channels",
            "components",
            "desired_channels",
        ] {
            let e = select_c_decoder("int", n).unwrap_or_else(|| panic!("int {n} supported"));
            assert!(
                e.decl.contains("gf_bounded_i32(&Cur, 0, 8)"),
                "channel-count '{n}' must be bounded small, got: {}",
                e.decl
            );
        }
        // Other-typed channel counts are bounded too.
        let u = select_c_decoder("unsigned int", "num_components").expect("supported");
        assert!(
            u.decl.contains("gf_bounded_i32(&Cur, 0, 8)"),
            "got: {}",
            u.decl
        );
        // Guard: a generic int param is NOT bounded by this rule (still full-range).
        let generic = select_c_decoder("int", "count").expect("int supported");
        assert!(
            generic.decl.contains("int count = gf_i32(&Cur)"),
            "generic int must stay full-range, got: {}",
            generic.decl
        );
        // Guard: width/height (not a channel count) stay full-range.
        let w = select_c_decoder("int", "width").expect("int supported");
        assert!(
            w.decl.contains("int width = gf_i32(&Cur)"),
            "got: {}",
            w.decl
        );
    }

    #[test]
    fn select_c_decoder_handles_zlib_length_aliases() {
        let u_long = select_c_decoder("uLong", "sourceLen").expect("uLong is supported");
        assert!(u_long.decl.contains("uLong sourceLen"));
        assert!(u_long.decl.contains("gf_bounded_length"));

        let u_int = select_c_decoder("uInt", "len").expect("uInt is supported");
        assert!(u_int.decl.contains("uInt len"));
        assert!(u_int.decl.contains("gf_bounded_i32"));

        let z_size = select_c_decoder("z_size_t", "size").expect("z_size_t is supported");
        assert!(z_size.decl.contains("z_size_t size"));
        assert!(z_size.decl.contains("gf_bounded_length"));
    }

    #[test]
    fn select_c_decoder_handles_zlib_length_output_pointer_alias() {
        let e = select_c_decoder("uLongf *", "destLen").expect("uLongf* is supported");
        assert!(e.decl.contains("uLongf _gf_out_destLen"));
        assert!(e.decl.contains("uLongf *destLen = &_gf_out_destLen"));
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_handles_file_pointer_with_fmemopen() {
        let e = select_c_decoder("FILE *", "stream").expect("FILE* is supported");

        assert!(e.decl.contains("FILE * stream = fmemopen("));
        assert!(e.decl.contains("(void *)Data"));
        assert!(e.decl.contains("Size"));
        assert_eq!(e.arg, "stream");
        assert_eq!(e.c_type, "FILE *");
        assert_eq!(e.free.as_deref(), Some("if (stream) fclose(stream)"));
    }

    #[test]
    fn select_c_decoder_drives_file_path_param_with_tempfile() {
        // A path-named `const char *` opens the path -> write the fuzz bytes to a
        // temp file and pass its path (the file CONTENT is the fuzz input), so a
        // path-only `load`/`read`/`parse` API becomes auto-harnessable.
        for n in [
            "filename",
            "filePath",
            "input_file",
            "e57_path",
            "scene_file",
        ] {
            let e = select_c_decoder("const char *", n)
                .unwrap_or_else(|| panic!("file-path param {n} supported"));
            assert!(
                e.decl.contains("gf_make_tempfile(Data, Size"),
                "{n}: must write fuzz bytes to a temp file: {}",
                e.decl
            );
            assert!(
                e.decl.contains(&format!("{n} = {n}_made ? {n}_path")),
                "got: {}",
                e.decl
            );
            // body-scope decoder (references Data/Size) — never emitted at top level.
            assert!(
                e.support.is_none(),
                "file-path decoder must not use top-level support"
            );
            assert_eq!(
                e.free.as_deref(),
                Some(format!("if ({n}_made) unlink({n}_path)").as_str())
            );
        }
        // A plain string param is UNCHANGED — still the gf_c_string decoder, so we
        // don't regress ordinary `const char *` inputs.
        let s = select_c_decoder("const char *", "name").expect("string supported");
        assert!(
            s.decl.contains("gf_c_string(&Cur"),
            "plain string param must stay gf_c_string"
        );
        assert!(s.support.is_none());
    }

    #[test]
    fn select_c_decoder_handles_miniz_file_macro_pointer_with_fmemopen() {
        let e = select_c_decoder("MZ_FILE *", "stream").expect("MZ_FILE* is supported");

        assert!(e.decl.contains("MZ_FILE * stream = (MZ_FILE *)fmemopen("));
        assert!(e.decl.contains("(void *)Data"));
        assert!(e.decl.contains("Size"));
        assert_eq!(e.arg, "stream");
        assert_eq!(e.c_type, "MZ_FILE *");
        assert_eq!(e.free.as_deref(), Some("if (stream) fclose(stream)"));
    }

    #[test]
    fn win32_pointer_typedefs_are_drivable() {
        // Win32 pointer typedefs must now select a decoder: PUCHAR/LPBYTE decode as
        // a byte buffer, LPCSTR/LPSTR as a C string. (The Win32 *scalar* typedefs —
        // BOOL/DWORD/BYTE — are already driven by type_model's WIN32_INTEGER_TYPEDEFS
        // through the registry path, keeping their alias spelling; see
        // `select_c_decoder_handles_win32_bool_and_dword_scalars`.)
        let data = select_c_decoder("PUCHAR", "data").expect("PUCHAR is a byte buffer");
        assert_eq!(data.c_type, "unsigned char *");
        assert!(select_c_decoder("LPBYTE", "buf").is_some());
        let name = select_c_decoder("LPCSTR", "name").expect("LPCSTR is a C string");
        assert!(name.decl.contains("gf_c_string"));
        assert!(select_c_decoder("LPSTR", "out").is_some());
        // sanity: an unknown opaque type (and opaque Win32 handles) still return None.
        assert!(select_c_decoder("CString", "name").is_none());
        assert!(select_c_decoder("HANDLE", "h").is_none());
    }

    #[test]
    fn win32_pointer_typedef_drives_via_registry_path() {
        // The auto C/C++ path resolves through the registry-aware entry; PUCHAR must
        // build a byte buffer there too rather than skip "needs lifecycle support".
        let reg = TypeRegistry::default();
        let data =
            select_c_decoder_with_registry("PUCHAR", "data", &reg).expect("PUCHAR is drivable");
        assert_eq!(data.c_type, "unsigned char *");
    }

    #[test]
    fn select_c_decoder_handles_const_void_pointer_as_data_view() {
        let e = select_c_decoder("const void *", "blob").expect("const void* is supported");

        assert_eq!(e.decl, "const void * blob = (const void *)Data");
        assert_eq!(e.arg, "blob");
        assert_eq!(e.c_type, "const void *");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_handles_mutable_void_pointer_as_heap_copy() {
        let e = select_c_decoder("void *", "opaque").expect("void* is supported");

        assert!(e
            .decl
            .contains("void * opaque = calloc(Size ? Size : 1, 1)"));
        assert!(e
            .decl
            .contains("if (opaque && Size) memcpy(opaque, Data, Size)"));
        assert_eq!(e.arg, "opaque");
        assert_eq!(e.c_type, "void *");
        assert_eq!(e.free.as_deref(), Some("free(opaque)"));
    }

    #[test]
    fn select_c_decoder_returns_none_for_unsupported() {
        assert!(select_c_decoder("struct foo *", "p").is_none());
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_enum() {
        let reg = registry("enum mode { MODE_A, MODE_B };");
        let e =
            select_c_decoder_with_registry("enum mode", "mode", &reg).expect("enum is supported");

        assert!(e
            .decl
            .contains("int _gf_sel_mode = gf_bounded_i32(&Cur, 0, 1)"));
        assert!(e.decl.contains("enum mode mode = (enum mode)MODE_A"));
        assert!(e.decl.contains("case 1: mode = (enum mode)MODE_B; break"));
        assert_eq!(e.arg, "mode");
        assert!(e.free.is_none());
    }

    #[test]
    fn x_macro_enum_decodes_as_bounded_int_not_phantom_member() {
        // http_parser.h `enum http_errno { HTTP_ERRNO_MAP(HTTP_ERRNO_GEN) };`:
        // no recoverable named variants, so decode a bounded int cast to the enum
        // (which still explores out-of-range table indices) rather than emitting
        // the un-compilable `(enum http_errno)HTTP_ERRNO_MAP`.
        let reg = registry(
            "#define HTTP_ERRNO_MAP(XX) XX(0, OK, \"ok\")\n\
             enum http_errno { HTTP_ERRNO_MAP(HTTP_ERRNO_GEN) };",
        );
        let e = select_c_decoder_with_registry("enum http_errno", "err", &reg)
            .expect("variantless enum is still supported");
        assert!(
            e.decl
                .contains("enum http_errno err = (enum http_errno)gf_bounded_i32(&Cur, 0, 255)"),
            "{}",
            e.decl
        );
        assert!(
            !e.decl.contains("HTTP_ERRNO_MAP"),
            "must not reference the X-macro name as a constant: {}",
            e.decl
        );
        assert_eq!(e.arg, "err");
    }

    #[test]
    fn select_c_decoder_strips_const_from_by_value_enum_local() {
        // jsmn `jsmn_fill_token(.., const jsmntype_t type, ..)`: the harness local
        // is mutable (the switch assigns into it), so a by-value `const` enum param
        // must declare a NON-const local — else "cannot assign to const".
        let reg = registry("typedef enum { JSMN_UNDEFINED, JSMN_OBJECT } jsmntype_t;");
        let e = select_c_decoder_with_registry("const jsmntype_t", "type", &reg)
            .expect("const enum is supported");
        assert!(
            e.decl
                .contains("jsmntype_t type = (jsmntype_t)JSMN_UNDEFINED"),
            "{}",
            e.decl
        );
        assert!(
            !e.decl.contains("const jsmntype_t type"),
            "the harness local must NOT be const: {}",
            e.decl
        );
        assert!(e
            .decl
            .contains("case 1: type = (jsmntype_t)JSMN_OBJECT; break"));
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_struct_by_value() {
        let reg = registry(
            r#"
            enum mode { MODE_A, MODE_B };
            struct config {
                int count;
                const char *name;
                enum mode mode;
                char tag[4];
            };
            "#,
        );

        let e = select_c_decoder_with_registry("struct config", "cfg", &reg)
            .expect("struct is supported");

        assert!(e.decl.contains("struct config cfg"));
        assert!(e.decl.contains("memset(&cfg, 0, sizeof cfg)"));
        assert!(e.decl.contains("cfg.count = gf_i32(&Cur)"));
        assert!(e.decl.contains("cfg.name = gf_c_string(&Cur, 256)"));
        assert!(e.decl.contains("cfg.mode = (enum mode)MODE_A"));
        assert!(e.decl.contains("size_t _gf_i_cfg_tag = 0"));
        assert!(e
            .decl
            .contains("cfg.tag[_gf_i_cfg_tag] = (char)gf_u8(&Cur)"));
        assert_eq!(e.free.as_deref(), Some("free((void *)cfg.name)"));
    }

    #[test]
    fn select_c_decoder_fuzzes_fill_count_for_over_cap_scalar_array() {
        // #464: a large fixed array (256 > cap 64) fuzzes its fill count (0..cap)
        // instead of always filling a fixed prefix, so inputs cover different slots.
        let reg = registry("struct taps { int t[256]; };");
        let e =
            select_c_decoder_with_registry("struct taps", "s", &reg).expect("struct is supported");
        assert!(
            e.decl
                .contains("size_t _gf_n_s_t = (size_t)(gf_u8(&Cur) % 65)"),
            "{}",
            e.decl
        );
        assert!(e.decl.contains("_gf_i_s_t < _gf_n_s_t"), "{}", e.decl);
        assert!(
            e.decl.contains("s.t[_gf_i_s_t] = gf_i32(&Cur)"),
            "{}",
            e.decl
        );
    }

    #[test]
    fn select_c_decoder_with_registry_uses_typedef_enum_field_type() {
        let reg = registry(
            r#"
            typedef enum { MODE_A, MODE_B } mode_t;
            struct config { mode_t mode; };
            "#,
        );

        let e = select_c_decoder_with_registry("struct config", "cfg", &reg)
            .expect("struct is supported");

        assert!(e.decl.contains("cfg.mode = (mode_t)MODE_A"));
        assert!(e.decl.contains("case 1: cfg.mode = (mode_t)MODE_B; break"));
        assert!(
            !e.decl.contains("enum mode_t"),
            "anonymous enum typedef must be emitted through the alias type: {}",
            e.decl
        );
    }

    #[test]
    fn select_c_decoder_with_registry_trampolines_typedef_callback_fields() {
        // #454: a typedef'd function-pointer field gets a callback trampoline
        // assigned to it (was left NULL), so the struct's callback codepath runs.
        let reg = registry(
            r#"
            typedef int (*callback_t)(void *opaque);
            struct hooks { callback_t cb; int count; };
            "#,
        );

        let e = select_c_decoder_with_registry("struct hooks", "hooks", &reg)
            .expect("struct with a callback field is supported");

        assert!(e.decl.contains("struct hooks hooks"));
        // The callback field is wired to a generated trampoline (not zeroed).
        assert!(
            e.decl.contains("hooks.cb = _gf_hooks_cb_trampoline"),
            "{}",
            e.decl
        );
        let support = e.support.as_deref().expect("trampoline support code");
        assert!(
            support.contains("static int _gf_hooks_cb_trampoline(void *opaque)"),
            "{support}"
        );
        assert!(support.contains("(void)opaque;"), "{support}");
        assert!(support.contains("return 0;"), "{support}");
        // The plain scalar field still decodes.
        assert!(e.decl.contains("hooks.count = gf_i32(&Cur)"), "{}", e.decl);
        assert!(
            !e.decl.contains("cb left zeroed"),
            "callback field must not be zeroed: {}",
            e.decl
        );
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_pointer_to_scalar_field() {
        // #451: a `int *count` field (pointer to a decodable scalar) used to be left
        // NULL; now it points at decoded stack storage so dereferences run.
        let reg = registry(
            r#"
            struct view { int *count; unsigned long len; };
            "#,
        );

        let e = select_c_decoder_with_registry("struct view", "v", &reg)
            .expect("struct with a pointer-to-scalar field is supported");

        assert!(e.decl.contains("struct view v"), "{}", e.decl);
        assert!(
            e.decl.contains("int _gf_pf_v_count = gf_i32(&Cur)"),
            "{}",
            e.decl
        );
        assert!(e.decl.contains("v.count = &_gf_pf_v_count"), "{}", e.decl);
        assert!(e.decl.contains("v.len ="), "{}", e.decl);
        assert!(
            !e.decl.contains("count left zeroed"),
            "pointer-to-scalar field must not be zeroed: {}",
            e.decl
        );
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_pointer_to_struct_field() {
        // A `struct point *origin` field points at a decoded struct storage, so the
        // nested value is reachable through the field.
        let reg = registry(
            r#"
            struct point { int x; int y; };
            struct shape { struct point *origin; };
            "#,
        );

        let e = select_c_decoder_with_registry("struct shape", "s", &reg)
            .expect("struct with a pointer-to-struct field is supported");

        assert!(
            e.decl.contains("struct point _gf_pf_s_origin"),
            "{}",
            e.decl
        );
        assert!(e.decl.contains("_gf_pf_s_origin.x ="), "{}", e.decl);
        assert!(e.decl.contains("s.origin = &_gf_pf_s_origin"), "{}", e.decl);
    }

    #[test]
    fn select_c_decoder_skips_malformed_split_funcptr_fragment() {
        // #466: a parser that split `int (*cb)(int, int)` on the inner comma yields
        // the malformed fragment `int (*cb)(int` and a spurious `int)`. Both are
        // unbalanced-paren -> clean skip, not a broken `gf_i32` scalar harness that
        // fails to build.
        let reg = registry("");
        assert!(select_c_decoder_with_registry("int (*cb)(int", "cb", &reg).is_err());
        assert!(select_c_decoder_with_registry("int)", "x", &reg).is_err());
        // A balanced scalar type is unaffected.
        assert!(select_c_decoder_with_registry("int", "n", &reg).is_ok());
    }

    #[test]
    fn select_c_decoder_with_registry_emits_callback_trampoline_for_typedef_param() {
        let reg = registry(
            r#"
            typedef int (*visit_cb)(void *opaque, const char *name);
            "#,
        );

        let e = select_c_decoder_with_registry("visit_cb", "cb", &reg)
            .expect("function pointer typedef params get a trampoline");

        let support = e.support.as_deref().expect("callback support code");
        assert!(support.contains("static int _gf_cb_trampoline(void *opaque, const char *name)"));
        assert!(support.contains("(void)opaque;"));
        assert!(support.contains("(void)name;"));
        assert!(support.contains("return 0;"));
        // Cast to the callback type so a header-vs-tree signature mismatch still
        // assigns cleanly (the trampoline ignores its args).
        assert_eq!(e.decl, "visit_cb cb = (visit_cb)_gf_cb_trampoline");
        assert_eq!(e.arg, "cb");
        assert_eq!(e.c_type, "visit_cb");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_emits_trampoline_for_inline_function_pointer_param() {
        // An inline (anonymous) funcptr param `int (*)(int, int)` has no project
        // typedef — synthesize `_gf_cb_<name>` and use it as the parameter's type.
        let reg = registry("");
        let e = select_c_decoder_with_registry("int (*)(int, int)", "callback", &reg)
            .expect("inline function pointer params get a synthesized typedef + trampoline");
        let support = e.support.as_deref().expect("callback support code");
        assert!(
            support.contains("typedef int (*_gf_cb_callback)(int, int);"),
            "{support}"
        );
        assert!(support.contains("static int _gf_callback_trampoline("));
        // The trampoline is cast to the (here synthesized, no-op) callback type.
        assert_eq!(
            e.decl,
            "_gf_cb_callback callback = (_gf_cb_callback)_gf_callback_trampoline"
        );
        assert_eq!(e.c_type, "_gf_cb_callback");
        assert_eq!(e.arg, "callback");
    }

    #[test]
    fn callback_trampoline_uses_exact_header_signature_no_guess() {
        // inih's `ini_handler` is a 4-arg callback. The trampoline + its
        // re-declared typedef must mirror the *parsed* signature exactly (4
        // params), never a guessed/defaulted arity (e.g. a 5th `lineno`). The
        // re-declared typedef being identical is what lets it coexist with the
        // project header's own typedef under C11.
        let reg = registry(
            r#"
            typedef int (*ini_handler)(void* user, const char* section, const char* name, const char* value);
            "#,
        );

        let e = select_c_decoder_with_registry("ini_handler", "handler", &reg)
            .expect("4-arg callback typedef gets a trampoline");
        let support = e.support.as_deref().expect("callback support code");

        assert!(
            support.contains(
                "static int _gf_handler_trampoline(void* user, const char* section, const char* name, const char* value)"
            ),
            "trampoline must use the exact 4-arg header signature, got: {support}"
        );
        assert!(
            support.contains(
                "typedef int (*ini_handler)(void* user, const char* section, const char* name, const char* value);"
            ),
            "re-declared typedef must match the header exactly (identical redefinition), got: {support}"
        );
        // No invented extra parameter (the historical 5-arg `lineno` guess).
        assert!(
            !support.contains("_gf_arg4") && !support.to_lowercase().contains("lineno"),
            "must not invent a 5th parameter, got: {support}"
        );
    }

    #[test]
    fn callback_trampoline_synthesizes_names_for_unnamed_params() {
        let reg = registry(
            r#"
            typedef int (*compare_cb)(const void *, const void*);
            "#,
        );

        let e = select_c_decoder_with_registry("compare_cb", "cmp", &reg)
            .expect("unnamed-param callback typedef gets a trampoline");

        let support = e.support.as_deref().expect("callback support code");
        // Unnamed parameters are invalid in a C function definition before
        // C23, and `(void)void*;` never compiles — every parameter must get
        // a synthesized name.
        assert!(
            support.contains("(void)_gf_arg0;") && support.contains("(void)_gf_arg1;"),
            "trampoline body must reference synthesized names, got: {support}"
        );
        assert!(
            !support.contains("(void)void"),
            "type token must not be mistaken for a parameter name, got: {support}"
        );
        assert!(
            support.contains("_gf_arg0,") && support.contains("_gf_arg1)"),
            "trampoline definition must name every parameter, got: {support}"
        );
    }

    #[test]
    fn strip_restrict_qualifier_macros_drops_qualifier_tokens() {
        assert_eq!(
            strip_restrict_qualifier_macros(
                "void (*)(xxh_u64* XXH_RESTRICT, const xxh_u8* XXH_RESTRICT, size_t)"
            ),
            "void (*)(xxh_u64*, const xxh_u8*, size_t)"
        );
        assert_eq!(
            strip_restrict_qualifier_macros("void (*)(int* __restrict a, int* restrict b)"),
            "void (*)(int* a, int* b)"
        );
        // Whole-word only: a real identifier that merely contains the substring
        // must survive.
        assert_eq!(
            strip_restrict_qualifier_macros("void (*)(int restrictions)"),
            "void (*)(int restrictions)"
        );
    }

    #[test]
    fn callback_trampoline_strips_restrict_qualifier_macro_from_inner_params() {
        // xxHash's `XXH3_f_accumulate` is a funcptr typedef whose UNNAMED inner
        // params carry the `XXH_RESTRICT` qualifier macro. Taken as the (repeated)
        // parameter name it yields `redefinition of parameter 'XXH_RESTRICT'`. The
        // macro must be stripped so each param is unnamed and gets a synthesized
        // positional name.
        let reg = registry(
            "typedef void (*XXH3_f_accumulate)(unsigned long* XXH_RESTRICT, \
             const unsigned char* XXH_RESTRICT, const unsigned char* XXH_RESTRICT, unsigned long);",
        );
        let e = select_c_decoder_with_registry("XXH3_f_accumulate", "acc", &reg)
            .expect("restrict-macro callback typedef gets a trampoline");
        let support = e.support.as_deref().expect("callback support code");
        assert!(
            !support.contains("XXH_RESTRICT"),
            "the qualifier macro must never appear in the trampoline support, got: {support}"
        );
        assert!(
            support.contains("(void)_gf_arg0;") && support.contains("(void)_gf_arg1;"),
            "stripped params must get synthesized positional names, got: {support}"
        );
    }

    #[test]
    fn variadic_callback_trampoline_keeps_ellipsis_unnamed() {
        // tinycbor's `CborStreamFunction` is variadic:
        // `CborError (*)(void *token, const char *fmt, ...)`. A `...` cannot be
        // named — emitting `... _gf_arg2` is a syntax error ("expected ')'") and
        // `(void)_gf_arg2;` then fails. The trampoline must keep a bare ellipsis.
        let reg = registry("typedef int (*CborStreamFunction)(void *token, const char *fmt, ...);");
        let e = select_c_decoder_with_registry("CborStreamFunction", "stream", &reg)
            .expect("variadic callback typedef gets a trampoline");
        let support = e.support.as_deref().expect("callback support code");
        assert!(
            support.contains("const char *fmt, ...)"),
            "the ellipsis must be emitted bare (no name), got: {support}"
        );
        assert!(
            !support.contains("..._gf") && !support.contains("... _gf"),
            "the ellipsis must not be given a synthesized name, got: {support}"
        );
        assert!(
            !support.contains("(void)_gf_arg2;"),
            "the variadic args must not be referenced in the body, got: {support}"
        );
    }

    #[test]
    fn parse_callback_signature_tolerates_blanked_name_and_whitespace() {
        // A typedef written `void (* PendedFunction_t)(void *, uint32_t)`
        // canonicalizes with the name blanked to a space -> `void (* )( ... )`.
        // The marker match must tolerate the whitespace (and a still-present
        // declarator name), or FreeRTOS's PendedFunction_t /
        // StreamBufferCallbackFunction_t callbacks are rejected as "unsupported
        // function-pointer signature".
        let sig = parse_callback_signature("void (* )( void * arg1, uint32_t arg2 )")
            .expect("spaced func-ptr marker must parse");
        assert_eq!(sig.return_type, "void");
        assert_eq!(
            sig.params,
            vec!["void * arg1".to_owned(), "uint32_t arg2".to_owned()]
        );

        // A named declarator is equally acceptable.
        let named = parse_callback_signature("int (*cb)(const char *s)")
            .expect("named func-ptr declarator must parse");
        assert_eq!(named.return_type, "int");
        assert_eq!(named.params, vec!["const char *s".to_owned()]);
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_struct_pointer() {
        let reg = registry(
            r#"
            struct config { int count; };
            typedef struct config *config_ptr;
            "#,
        );

        let e = select_c_decoder_with_registry("struct config *", "out", &reg)
            .expect("struct pointer is supported");

        assert!(e.decl.contains("struct config _gf_value_out"));
        assert!(e
            .decl
            .contains("memset(&_gf_value_out, 0, sizeof _gf_value_out)"));
        assert!(e.decl.contains("_gf_value_out.count = gf_i32(&Cur)"));
        assert!(e.decl.contains("struct config * out = &_gf_value_out"));
        assert_eq!(e.arg, "out");

        let alias = select_c_decoder_with_registry("config_ptr", "alias", &reg)
            .expect("struct pointer typedef is supported");
        assert!(alias.decl.contains("struct config _gf_value_alias"));
        assert!(alias.decl.contains("_gf_value_alias.count = gf_i32(&Cur)"));
        assert!(alias.decl.contains("config_ptr alias = &_gf_value_alias"));
        assert_eq!(alias.arg, "alias");
    }

    #[test]
    fn select_c_decoder_decodes_typed_output_handle_double_pointer() {
        // `parse(..., foo_data **out)` — the callee allocates a `foo_data *` and
        // writes it back. The harness provides a NULL slot, passes its address, and
        // frees the produced handle via a discovered destructor (NULL-guarded).
        let reg = registry("typedef struct foo_data { int n; } foo_data;");
        let lifecycle = vec![CHandleLifecycle {
            handle_type: "foo_data".to_owned(),
            init: None,
            delete: Some("foo_free".to_owned()),
            init_returns_handle: false,
            init_args: Vec::new(),
        }];
        let e = select_c_decoder_with_lifecycle("foo_data **", "out", &reg, &lifecycle)
            .expect("typed output-handle double pointer is supported");
        assert!(e.decl.contains("_gf_out_out = NULL"), "{}", e.decl);
        assert!(e.decl.contains("out = &_gf_out_out"), "{}", e.decl);
        assert_eq!(e.arg, "out");
        assert_eq!(
            e.free.as_deref(),
            Some("if (_gf_out_out) foo_free(_gf_out_out)")
        );

        // Without a discovered destructor the slot still works — just no free.
        let e2 = select_c_decoder_with_registry("foo_data **", "out", &reg)
            .expect("output-handle slot works without a lifecycle");
        assert!(e2.decl.contains("_gf_out_out = NULL"));
        assert!(e2.free.is_none());
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_scalar_output_pointer_alias() {
        let reg = registry("typedef unsigned int mz_uint32;");

        let e = select_c_decoder_with_registry("mz_uint32 *", "pIndex", &reg)
            .expect("scalar output pointer typedef is supported");

        assert!(e
            .decl
            .contains("mz_uint32 _gf_out_pIndex = (mz_uint32)gf_bounded_i32"));
        assert!(e.decl.contains("mz_uint32 * pIndex = &_gf_out_pIndex"));
        assert_eq!(e.arg, "pIndex");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_enum_output_pointer_alias() {
        let reg = registry(
            r#"
            typedef enum {
                MZ_ZIP_NO_ERROR,
                MZ_ZIP_INVALID_PARAMETER
            } mz_zip_error;
            "#,
        );

        let e = select_c_decoder_with_registry("mz_zip_error *", "pErr", &reg)
            .expect("enum output pointer typedef is supported");

        assert!(e
            .decl
            .contains("mz_zip_error _gf_out_pErr = (mz_zip_error)MZ_ZIP_NO_ERROR"));
        assert!(e
            .decl
            .contains("case 1: _gf_out_pErr = (mz_zip_error)MZ_ZIP_INVALID_PARAMETER; break"));
        assert!(e.decl.contains("mz_zip_error * pErr = &_gf_out_pErr"));
        assert_eq!(e.arg, "pErr");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_const_miniz_time_pointer_alias() {
        let reg = registry("");

        let e = select_c_decoder_with_registry("const MZ_TIME_T *", "pFile_time", &reg)
            .expect("const MZ_TIME_T pointer is supported");

        assert!(e
            .decl
            .contains("MZ_TIME_T _gf_out_pFile_time = (MZ_TIME_T)gf_i64"));
        assert!(e
            .decl
            .contains("const MZ_TIME_T * pFile_time = &_gf_out_pFile_time"));
        assert_eq!(e.arg, "pFile_time");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_void_pointer_output_slot() {
        let reg = registry("");

        let e = select_c_decoder_with_registry("void **", "ppBuf", &reg)
            .expect("void pointer output slots are supported");

        assert!(e.decl.contains("void * _gf_out_ppBuf = NULL"));
        assert!(e.decl.contains("void * * ppBuf = &_gf_out_ppBuf"));
        assert_eq!(e.arg, "ppBuf");
        assert_eq!(e.c_type, "void * *");
        assert!(e.free.is_none());
    }

    #[test]
    fn select_c_decoder_nul_terminates_lone_const_byte_pointer_typedef() {
        let reg = registry("typedef unsigned char mz_uint8;");

        let e = select_c_decoder_with_registry("const mz_uint8 *", "ptr", &reg)
            .expect("const byte pointer typedef is supported");

        // A LONE const byte pointer (no length sibling) is a NUL-terminated
        // C-string copy, not the raw non-terminated Data span (so a strlen can't
        // run past the input). A genuine (buffer,length) pair is handled earlier.
        assert!(e.decl.contains("(const mz_uint8 *)malloc"), "{}", e.decl);
        assert!(e.decl.contains("((char *)ptr)[Size] = '\\0'"), "{}", e.decl);
        assert_eq!(e.arg, "ptr");
        assert_eq!(e.c_type, "const mz_uint8 *");
        assert_eq!(e.free.as_deref(), Some("free((void *)ptr)"));
    }

    #[test]
    fn select_c_decoder_floors_lone_const_byte_pointer_to_max_scalar_width() {
        // Campaign #8: libcbor's internal fixed-width loaders take a LONE
        // `const unsigned char *source` with NO length param and read N fixed bytes
        // forward (_cbor_load_uint16 reads 2, _cbor_load_uint64 reads 8). A Size+1
        // malloc over-reads the heap on short/0-byte input. Floor the buffer to the
        // max scalar fixed width (8) and zero the tail so a fixed-width forward read
        // stays in-bounds and observes defined zero bytes.
        let e = select_c_decoder_with_registry("const unsigned char *", "source", &registry(""))
            .expect("const byte pointer is supported");
        assert!(
            e.decl
                .contains("if (_gf_cap_source < 8) _gf_cap_source = 8"),
            "{}",
            e.decl
        );
        assert!(
            e.decl.contains("memset((void *)source, 0, _gf_cap_source)"),
            "{}",
            e.decl
        );
        // NUL-termination for the C-string case is preserved.
        assert!(
            e.decl.contains("((char *)source)[Size] = '\\0'"),
            "{}",
            e.decl
        );
    }

    #[test]
    fn select_c_decoder_routes_wide_string_pointer_to_gf_wc_string() {
        // Campaign fix: a `const wchar_t *` param must decode a NUL-terminated
        // wchar_t buffer, not a pointer to a single non-NUL stack unit (pugixml
        // load_file: the callee's wcslen otherwise walks off the end — a false
        // ASan stack-buffer-overflow).
        let reg = registry("");
        let e = select_c_decoder_with_registry("const wchar_t *", "path", &reg)
            .expect("wide string pointer is supported");
        assert!(e.decl.contains("gf_wc_string(&Cur"), "{}", e.decl);
        assert!(e.decl.starts_with("wchar_t *path ="), "{}", e.decl);
        assert_eq!(e.free.as_deref(), Some("free(path)"));

        let m = select_c_decoder_with_registry("wchar_t *", "buf", &reg)
            .expect("mutable wide string pointer is supported");
        assert!(m.decl.contains("gf_wc_string(&Cur"), "{}", m.decl);
    }

    #[test]
    fn select_c_decoder_nul_terminates_lone_const_unsigned_char_pointer() {
        // cJSON detach_path's `const unsigned char *path` is strlen'd; the lone
        // pointer must be NUL-terminated so the read can't run off the input.
        let e = select_c_decoder_with_registry("const unsigned char *", "path", &registry(""))
            .expect("const unsigned char* is supported");
        assert!(
            e.decl.contains("(const unsigned char *)malloc"),
            "{}",
            e.decl
        );
        assert!(
            e.decl.contains("((char *)path)[Size] = '\\0'"),
            "{}",
            e.decl
        );
        assert_eq!(e.free.as_deref(), Some("free((void *)path)"));
    }

    #[test]
    fn select_c_decoder_with_registry_decodes_union_first_decodable_member() {
        let reg = registry("union payload { int code; const char *name; };");

        let e = select_c_decoder_with_registry("union payload", "payload", &reg)
            .expect("union is supported");

        assert!(e.decl.contains("union payload payload"));
        assert!(e.decl.contains("memset(&payload, 0, sizeof payload)"));
        assert!(e.decl.contains("payload.code = gf_i32(&Cur)"));
        assert!(!e.decl.contains("payload.name = gf_c_string"));
    }

    #[test]
    fn select_c_decoder_with_registry_zeroes_union_with_no_decodable_member() {
        // A union whose every member is an opaque pointer has no independently
        // decodable member — a zeroed union is still a valid value, so it decodes
        // (memset + comment) rather than rejecting the whole parameter.
        let reg = registry(
            "struct opaque_a; struct opaque_b; \
             union only_ptrs { struct opaque_a *a; struct opaque_b *b; void *raw; };",
        );
        let e = select_c_decoder_with_registry("union only_ptrs", "v", &reg)
            .expect("a union with no decodable member is zeroed, not rejected");
        assert!(e.decl.contains("memset(&v, 0, sizeof v)"));
        assert!(e.decl.contains("no decodable member"), "{}", e.decl);
        assert_eq!(e.arg, "v");
    }

    #[test]
    fn select_c_decoder_with_registry_rejects_opaque_pointer() {
        let reg = registry("struct opaque;");

        let err = select_c_decoder_with_registry("struct opaque *", "p", &reg)
            .expect_err("opaque pointers need Phase C lifecycle support");

        assert!(err.to_string().contains("opaque type"));
        assert!(err.to_string().contains("struct opaque"));
        assert!(err.to_string().contains("Phase C"));
    }

    #[test]
    fn lifecycle_constructs_opaque_handle_via_init_and_delete() {
        // `widget_t` is unknown to the registry (opaque), but an init/delete
        // pair is available: construct it through the lifecycle instead of
        // bailing. The base type is declared by spelling; the compiler
        // resolves completeness via the harness includes.
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "widget_t".to_owned(),
            init: Some("widget_initialize".to_owned()),
            delete: Some("widget_delete".to_owned()),
            init_returns_handle: false,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect("opaque handle with init/delete is constructible");

        assert!(e.decl.contains("widget_t _gf_lc_w"), "{}", e.decl);
        assert!(
            e.decl.contains("widget_initialize(&_gf_lc_w)"),
            "{}",
            e.decl
        );
        assert!(e.decl.contains("widget_t * w = &_gf_lc_w"), "{}", e.decl);
        assert_eq!(e.arg, "w");
        assert_eq!(e.free.as_deref(), Some("widget_delete(&_gf_lc_w)"));
    }

    #[test]
    fn strict_lifecycle_skips_opaque_handle_incomplete_in_headers() {
        // GAP #6 (tidwall/hashmap.c): `struct hashmap` is only FORWARD-declared in
        // the harness's headers (its body lives in hashmap.c, which a non-static
        // target does NOT include). A destructor-only lifecycle (hashmap_free) would
        // stack-allocate `struct hashmap _gf_lc_map;` + memset — an illegal "variable
        // has incomplete type" declaration that fails to BUILD. With a header-
        // completeness oracle that does NOT list the struct, the strict decoder must
        // SKIP (CDecoderError), so the target is cleanly reported UnsupportedParams.
        let reg = registry("struct hashmap;"); // forward-decl only -> opaque
        let lifecycle = [CHandleLifecycle {
            handle_type: "struct hashmap".to_owned(),
            init: None,
            delete: Some("hashmap_free".to_owned()),
            init_returns_handle: false,
            init_args: vec![],
        }];
        let header_complete: HashSet<String> = HashSet::new(); // not defined in any header
        let err = select_c_decoder_with_lifecycle_strict(
            "struct hashmap *",
            "map",
            &reg,
            &lifecycle,
            &header_complete,
        )
        .expect_err("incomplete-in-headers opaque handle must be skipped");
        assert!(
            err.to_string().contains("incomplete in the harness"),
            "skip reason should name the incomplete-type cause: {err}"
        );
    }

    #[test]
    fn strict_lifecycle_constructs_opaque_handle_complete_in_headers() {
        // Regression guard for GAP #6: when the handle's struct IS fully defined in a
        // header the harness includes (listed in the oracle), the strict path STILL
        // stack-allocates + drives the destructor-only lifecycle — exactly the libyaml
        // `yaml_token_t` / managed-output-struct idiom — so it is NOT over-skipped.
        let reg = registry("struct yaml_token_s;"); // registry sees a forward-decl -> opaque
        let lifecycle = [CHandleLifecycle {
            handle_type: "struct yaml_token_s".to_owned(),
            init: None,
            delete: Some("yaml_token_delete".to_owned()),
            init_returns_handle: false,
            init_args: vec![],
        }];
        let header_complete: HashSet<String> =
            ["struct yaml_token_s".to_owned()].into_iter().collect();
        let e = select_c_decoder_with_lifecycle_strict(
            "struct yaml_token_s *",
            "tok",
            &reg,
            &lifecycle,
            &header_complete,
        )
        .expect("complete-in-headers opaque handle is still constructible");
        assert!(
            e.decl.contains("struct yaml_token_s _gf_lc_tok"),
            "{}",
            e.decl
        );
        assert!(
            e.decl.contains("memset(&_gf_lc_tok, 0, sizeof _gf_lc_tok)"),
            "{}",
            e.decl
        );
        assert_eq!(e.free.as_deref(), Some("yaml_token_delete(&_gf_lc_tok)"));
    }

    #[test]
    fn strict_lifecycle_allows_returning_constructor_for_incomplete_handle() {
        // A returning constructor (`T *foo_new(void)`) needs NO complete type: the
        // handle is the return value, passed/freed by value. So even with an empty
        // header-completeness oracle, an incomplete opaque handle that has one must
        // STILL be constructed (libde265-style), not skipped.
        let reg = registry("struct decoder;");
        let lifecycle = [CHandleLifecycle {
            handle_type: "struct decoder".to_owned(),
            init: Some("decoder_new".to_owned()),
            delete: Some("decoder_free".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];
        let header_complete: HashSet<String> = HashSet::new();
        let e = select_c_decoder_with_lifecycle_strict(
            "struct decoder *",
            "d",
            &reg,
            &lifecycle,
            &header_complete,
        )
        .expect("returning constructor needs no complete type");
        assert!(e.decl.contains("d = decoder_new()"), "{}", e.decl);
        assert_eq!(e.free.as_deref(), Some("decoder_free(d)"));
    }

    #[test]
    fn lifecycle_returning_constructor_uses_return_value() {
        // `widget_t *widget_new(void)` returns the handle: pass it by value and
        // free it directly (`widget_free(w)`), with no stack storage / &-pass.
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "widget_t".to_owned(),
            init: Some("widget_new".to_owned()),
            delete: Some("widget_free".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect("returning constructor is constructible");

        assert!(e.decl.contains("w = widget_new()"), "{}", e.decl);
        assert!(!e.decl.contains("_gf_lc_w"), "no stack storage: {}", e.decl);
        assert!(!e.decl.contains("&w"), "handle passed by value: {}", e.decl);
        assert_eq!(e.arg, "w");
        assert_eq!(e.free.as_deref(), Some("widget_free(w)"));
    }

    #[test]
    fn interior_pointer_typedef_handle_built_via_returning_constructor_not_raw_string() {
        // redis `sds` = `typedef char *sds`: the pointer points INTO a malloc'd
        // header+data block, so accessors read `s[-1]`. It must be built via its
        // self-returning constructor (sdsempty/sdsnew), NOT decoded as a raw
        // gf_c_string buffer (which underflows the header -> GF-201 FP).
        let reg = registry("typedef char *sds;");
        let lifecycle = [CHandleLifecycle {
            handle_type: "sds".to_owned(),
            init: Some("sdsempty".to_owned()),
            delete: Some("sdsfree".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("sds", "s", &reg, &lifecycle)
            .expect("sds handle is constructible via its returning constructor");

        assert!(e.decl.contains("s = sdsempty()"), "{}", e.decl);
        assert!(
            !e.decl.contains("gf_c_string"),
            "must NOT decode as a raw string: {}",
            e.decl
        );
        assert_eq!(e.free.as_deref(), Some("sdsfree(s)"));
    }

    #[test]
    fn bare_char_pointer_is_not_treated_as_a_handle() {
        // Guard: a BARE `char *` (no typedef handle entry) must still decode as a
        // string input even when a typedef handle lifecycle is present in the same
        // table (cJSON_CreateString(const char *) must not be hijacked).
        let reg = registry("typedef char *sds;");
        let lifecycle = [CHandleLifecycle {
            handle_type: "sds".to_owned(),
            init: Some("sdsempty".to_owned()),
            delete: Some("sdsfree".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("const char *", "name", &reg, &lifecycle)
            .expect("a bare char* is a string input");
        assert!(e.decl.contains("gf_c_string"), "{}", e.decl);
        assert!(!e.decl.contains("sdsempty"), "{}", e.decl);
    }

    #[test]
    fn lifecycle_lookup_is_insensitive_to_struct_tag_spelling() {
        // Campaign reproduction (libdeflate): the lifecycle table stores the
        // tag-free key `libdeflate_decompressor` (the constructor's return type
        // lost its `struct` keyword during parsing), but the TARGET parameter is
        // spelled `struct libdeflate_decompressor *`. The decoder's lookup must
        // collapse the elaborated tag and still find the returning constructor.
        let reg = registry("struct libdeflate_decompressor;"); // forward-declared / incomplete
        let lifecycle = [CHandleLifecycle {
            handle_type: "libdeflate_decompressor".to_owned(), // tag-free table key
            init: Some("libdeflate_alloc_decompressor".to_owned()),
            delete: Some("libdeflate_free_decompressor".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle(
            "struct libdeflate_decompressor *",
            "d",
            &reg,
            &lifecycle,
        )
        .expect("tag-spelling mismatch must still resolve the returning constructor");

        assert!(
            e.decl.contains("d = libdeflate_alloc_decompressor()"),
            "{}",
            e.decl
        );
        assert!(
            !e.decl.contains("struct libdeflate_decompressor _gf_lc"),
            "must not stack-allocate the incomplete struct: {}",
            e.decl
        );
        assert_eq!(e.arg, "d");
        assert_eq!(e.free.as_deref(), Some("libdeflate_free_decompressor(d)"));
    }

    #[test]
    fn normalize_handle_key_collapses_elaborated_tags() {
        assert_eq!(super::normalize_handle_key("struct foo"), "foo");
        assert_eq!(super::normalize_handle_key("union foo"), "foo");
        assert_eq!(super::normalize_handle_key("enum foo"), "foo");
        assert_eq!(super::normalize_handle_key("  struct  foo  "), "foo");
        // A bare typedef name (no tag) is unchanged.
        assert_eq!(super::normalize_handle_key("widget_t"), "widget_t");
        // `struct`-prefixed identifiers that aren't a tag boundary stay intact.
        assert_eq!(super::normalize_handle_key("structure_t"), "structure_t");
    }

    #[test]
    fn lifecycle_constructs_void_typedef_opaque_handle_via_returning_constructor() {
        // `typedef void de265_decoder_context;` — the classic C opaque-handle idiom
        // — resolves to opaque `void`, but the lifecycle is keyed by the TYPEDEF
        // name. The returning constructor must still build it (libde265
        // `de265_decode_data(de265_decoder_context *, ...)`):
        // `ctx = de265_new_decoder(); …; de265_free_decoder(ctx);`. Before the fix
        // the `raw != "void"` guard skipped void-typedef handles entirely and the
        // lookup keyed by "void" never matched the lifecycle.
        let reg = registry("typedef void de265_decoder_context;");
        let lifecycle = [CHandleLifecycle {
            handle_type: "de265_decoder_context".to_owned(),
            init: Some("de265_new_decoder".to_owned()),
            delete: Some("de265_free_decoder".to_owned()),
            init_returns_handle: true,
            init_args: vec![],
        }];

        let e =
            select_c_decoder_with_lifecycle_cpp("de265_decoder_context *", "ctx", &reg, &lifecycle)
                .expect("void-typedef opaque handle with a returning constructor is constructible");

        assert!(e.decl.contains("ctx = de265_new_decoder()"), "{}", e.decl);
        assert_eq!(e.arg, "ctx");
        assert_eq!(e.free.as_deref(), Some("de265_free_decoder(ctx)"));
    }

    #[test]
    fn lifecycle_returning_constructor_passes_neutral_args() {
        // `widget_t *widget_create(const char *opt)` is a returning constructor
        // that takes a pointer config arg. The harness calls it with the neutral
        // "use defaults" value NULL (XML_ParserCreate(NULL), archive_read_new()).
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "widget_t".to_owned(),
            init: Some("widget_create".to_owned()),
            delete: Some("widget_free".to_owned()),
            init_returns_handle: true,
            init_args: vec!["NULL".to_owned()],
        }];

        let e = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect("returning constructor with neutral args is constructible");

        assert!(e.decl.contains("w = widget_create(NULL)"), "{}", e.decl);
        assert_eq!(e.free.as_deref(), Some("widget_free(w)"));
    }

    #[test]
    fn lifecycle_without_delete_still_constructs_with_no_cleanup() {
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "widget_t".to_owned(),
            init: Some("widget_create".to_owned()),
            delete: None,
            init_returns_handle: false,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect("init alone is enough to construct");

        assert!(e.decl.contains("widget_create(&_gf_lc_w)"), "{}", e.decl);
        assert!(e.free.is_none(), "no delete => no cleanup");
    }

    #[test]
    fn lifecycle_delete_only_zero_inits_output_struct() {
        // No constructor but a destructor exists: an output / managed struct
        // the callee fills (libyaml yaml_token_t etc.). Zero-init, pass, delete
        // — rather than rejecting.
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "widget_t".to_owned(),
            init: None,
            delete: Some("widget_delete".to_owned()),
            init_returns_handle: false,
            init_args: vec![],
        }];

        let e = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect("delete-only output struct is zero-init + delete");
        assert!(e.decl.contains("widget_t _gf_lc_w"), "{}", e.decl);
        assert!(
            e.decl.contains("memset(&_gf_lc_w, 0, sizeof _gf_lc_w)"),
            "{}",
            e.decl
        );
        assert!(e.decl.contains("widget_t * w = &_gf_lc_w"), "{}", e.decl);
        assert_eq!(e.free.as_deref(), Some("widget_delete(&_gf_lc_w)"));
    }

    #[test]
    fn lifecycle_table_miss_leaves_opaque_pointer_rejected() {
        let reg = registry("");
        let lifecycle = [CHandleLifecycle {
            handle_type: "other_t".to_owned(),
            init: Some("other_init".to_owned()),
            delete: None,
            init_returns_handle: false,
            init_args: vec![],
        }];

        let err = select_c_decoder_with_lifecycle("widget_t *", "w", &reg, &lifecycle)
            .expect_err("no matching handle => unsupported");
        assert!(err.to_string().contains("needs lifecycle support"));
    }

    // ----- §27.11: configurable decoder limits -----

    /// Default-limits emission must be byte-identical to the historical
    /// (preserved) public path — the regression-safety guarantee for §27.11.
    #[test]
    fn decoder_limits_default_is_byte_identical_to_legacy_path() {
        let reg = registry("typedef struct { unsigned char data[128]; int n; } Blob;");
        let legacy = select_c_decoder_with_lifecycle("Blob", "b", &reg, &[])
            .expect("struct by-value is decodable");
        let with_default = select_c_decoder_with_lifecycle_with_limits(
            "Blob",
            "b",
            &reg,
            &[],
            DecoderLimits::default(),
        )
        .expect("struct by-value is decodable");
        assert_eq!(
            legacy.decl, with_default.decl,
            "DecoderLimits::default() must reproduce the legacy emission byte-for-byte"
        );
        // Sanity: the default array-elem cap (64) leaves the 128-element field
        // fuzzing its fill count modulo cap+1 = 65 — the pre-§27.11 behavior.
        assert!(
            with_default.decl.contains("% 65"),
            "default array cap 64 -> fill count `% 65`: {}",
            with_default.decl
        );
    }

    /// A tighter `--max-array-elems` shrinks the emitted per-array fill cap.
    #[test]
    fn decoder_limits_custom_array_cap_shrinks_emitted_decode() {
        let reg = registry("typedef struct { unsigned char data[128]; } Blob;");
        let limits = DecoderLimits {
            array_elems: 4,
            ..DecoderLimits::default()
        };
        let e = select_c_decoder_with_lifecycle_with_limits("Blob", "b", &reg, &[], limits)
            .expect("struct decodable");
        // 128 still > cap, so the fuzzed fill count is now modulo cap+1 = 5.
        assert!(
            e.decl.contains("% 5"),
            "custom array cap 4 -> fill count `% 5`: {}",
            e.decl
        );
        assert!(
            !e.decl.contains("% 65"),
            "the historical 64 cap must be gone: {}",
            e.decl
        );
    }

    /// A shallower `--max-decode-depth` leaves a deeper nested field zeroed.
    #[test]
    fn decoder_limits_custom_depth_cap_zeroes_deeper_fields() {
        let reg = registry(
            "typedef struct { int leaf; } Inner; \
             typedef struct { Inner mid; } Outer; \
             typedef struct { Outer top; } Root;",
        );
        // Depth 1: only the first level of nesting is synthesised; `top` is left
        // zeroed after the depth cap.
        let shallow = DecoderLimits {
            depth: 1,
            ..DecoderLimits::default()
        };
        let e = select_c_decoder_with_lifecycle_with_limits("Root", "r", &reg, &[], shallow)
            .expect("struct decodable");
        assert!(
            e.decl.contains("left zeroed after decoder depth cap"),
            "a depth-1 cap must zero the nested aggregate: {}",
            e.decl
        );
        // The default depth (4) reaches the innermost scalar.
        let deep = select_c_decoder_with_lifecycle_with_limits(
            "Root",
            "r",
            &reg,
            &[],
            DecoderLimits::default(),
        )
        .expect("struct decodable");
        assert!(
            deep.decl.contains("leaf"),
            "the default depth must reach the innermost scalar: {}",
            deep.decl
        );
    }

    /// A tiny `--max-decl-bytes` rejects a parameter whose synthesised body is
    /// larger than the configured ceiling.
    #[test]
    fn decoder_limits_custom_decl_bytes_rejects_large_synthesis() {
        let reg = registry("typedef struct { unsigned char data[128]; int a; int b; } Blob;");
        let tiny = DecoderLimits {
            decl_bytes: 16,
            ..DecoderLimits::default()
        };
        let err = select_c_decoder_with_lifecycle_with_limits("Blob", "b", &reg, &[], tiny)
            .expect_err("a 16-byte decl ceiling must reject this struct");
        assert!(
            err.to_string().contains("exceeds 16 bytes"),
            "the error must name the configured ceiling: {err}"
        );
        // The default ceiling (64 KiB) accepts it.
        assert!(select_c_decoder_with_lifecycle_with_limits(
            "Blob",
            "b",
            &reg,
            &[],
            DecoderLimits::default()
        )
        .is_ok());
    }

    #[test]
    fn best_effort_param_emission_drives_opaque_pointer() {
        let e = best_effort_param_emission("struct Opaque *", "handle");
        assert!(!e.decl.is_empty());
        assert!(e.decl.contains("(struct Opaque *)"));
        assert!(e.decl.contains("calloc"));
        assert_eq!(e.arg, "handle");
        assert!(e.free.is_some(), "the heap buffer must be freed");
    }

    #[test]
    fn best_effort_param_emission_nulls_function_pointer() {
        let e = best_effort_param_emission("void (*)(int)", "cb");
        assert!(!e.decl.is_empty());
        assert!(
            e.decl.contains("(void (*)(int))0"),
            "a function pointer is a NULL cast: {}",
            e.decl
        );
        assert!(e.free.is_none());
    }

    #[test]
    fn best_effort_param_emission_zero_inits_unknown_value() {
        let e = best_effort_param_emission("vendor_config_t", "cfg");
        assert!(!e.decl.is_empty());
        assert!(
            e.decl.contains("{0}"),
            "an unknown value type is zero-initialized: {}",
            e.decl
        );
    }
}
