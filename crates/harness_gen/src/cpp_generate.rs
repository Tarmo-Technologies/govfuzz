// SPDX-License-Identifier: Apache-2.0

use crate::c_decoders::CParamEmission;
pub use crate::cpp_decoders::CppDecoderLimits;
use crate::cpp_decoders::{select_cpp_decoder, select_cpp_decoder_with_registry_limited};
// `select_cpp_decoder` (the default-limits probe at `cpp_parameter_type_supported`)
// is intentionally still used; the limits-aware variant drives actual emission.
use crate::templates;
use crate::HarnessGenError;
use cpp_parser::CppFunction;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use type_model::TypeRegistry;

const BUILD_CONTEXT_PROVENANCE_PREFIX: &str = "@govfuzz-build-context-provenance=";
const BUILD_CONTEXT_CONFIDENCE_PREFIX: &str = "@govfuzz-build-context-confidence=";
const BUILD_CONTEXT_RECOVERY_PREFIX: &str = "@govfuzz-build-context-recovery=";
const BUILD_CONTEXT_LDFLAG_PREFIX: &str = "@govfuzz-build-context-ldflag=";

#[derive(Debug, Clone)]
pub struct CppParameter {
    pub name: String,
    pub cpp_type: String,
}

/// Factory construction plan: the receiver is obtained by calling a factory
/// method on an owner object (or a free function) rather than by direct construction.
/// The owner is stack-allocated and kept alive for the entire method call so the
/// receiver's lifetime (which may be owned by the factory owner) is safe.
#[derive(Debug, Clone)]
pub struct CppFactoryPlan {
    /// The qualified type of the factory owner (e.g., `"tinyxml2::XMLDocument"`),
    /// or `None` when the factory is a free function (no owner needed).
    pub owner_type: Option<String>,
    /// The factory method name (instance method) or free-function name.
    pub factory_method: String,
    /// Parameters to pass to the factory call (decoded from fuzz input).
    pub factory_params: Vec<CppParameter>,
    /// Whether the factory returns a pointer (`C*`, `unique_ptr<C>`, `shared_ptr<C>`)
    /// requiring `->` access and a null guard; `false` for value or reference returns.
    pub receiver_is_pointer: bool,
}

#[derive(Debug, Clone)]
pub struct GenerateCppDirectArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CppFunction,
    pub params: Vec<CppParameter>,
    pub return_type: String,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub c_runtime_include: PathBuf,
    /// Namespaces to inject as `using namespace X;` before the harness body
    /// so unqualified class names from the project header resolve.
    /// Populated by CLI auto-detection (scan included headers for top-level
    /// `namespace X { ... }` blocks).
    pub using_namespaces: Vec<String>,
    /// User-supplied cleanup expression to emit after the target call.
    /// `R` is bound to the target's return value. Mirrors the C-side
    /// `result_cleanup` so callers fuzzing C++ libraries with leaky
    /// factories can pass `--cleanup "delete R"` etc.
    pub result_cleanup: Option<String>,
    pub constructor_params: Vec<CppParameter>,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// C++ classes the caller determined are default-constructible, so a
    /// class-typed constructor argument can be default-constructed and passed
    /// rather than skipping the whole constructor (#353).
    pub default_constructible_classes: Vec<String>,
    /// When the method's declaring class is ABSTRACT, the concrete subclass to
    /// build the receiver from instead (`MemoryReader` for an abstract `Reader`),
    /// so `<override> _gf_receiver; _gf_receiver.method(..)` calls the virtual
    /// method polymorphically. `None` keeps the declaring class (#456).
    pub receiver_class_override: Option<String>,
    /// Factory construction plan when the declaring class has no usable public
    /// constructor but can be obtained via a factory method or free function.
    /// Overrides `constructor_params` / `receiver_class_override` when present.
    pub factory_plan: Option<CppFactoryPlan>,
    /// Configurable container/bitset/array decoder caps (§27.11). `Default`
    /// reproduces the historical hardcoded behavior; the CLI threads
    /// `--container-size-max` / `--bitset-max-size` / `--array-max-size` here.
    pub decoder_limits: CppDecoderLimits,
    /// Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    /// decoders reject is given a best-effort compiling driver
    /// ([`crate::c_decoders::best_effort_param_emission`]) instead of failing the
    /// whole target. Default `false` leaves the emission byte-for-byte unchanged.
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct CppLifecycleStep {
    pub name: String,
    pub params: Vec<CppParameter>,
    pub return_type: String,
}

#[derive(Debug, Clone)]
pub struct GenerateCppSequenceArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CppFunction,
    pub params: Vec<CppParameter>,
    pub return_type: String,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub c_runtime_include: PathBuf,
    pub using_namespaces: Vec<String>,
    pub result_cleanup: Option<String>,
    pub constructor_params: Vec<CppParameter>,
    pub lifecycle_steps: Vec<CppLifecycleStep>,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// See `GenerateCppDirectArgs::default_constructible_classes` (#353).
    pub default_constructible_classes: Vec<String>,
    /// See `GenerateCppDirectArgs::receiver_class_override` (#456).
    pub receiver_class_override: Option<String>,
    /// See `GenerateCppDirectArgs::factory_plan`.
    pub factory_plan: Option<CppFactoryPlan>,
    /// See `GenerateCppDirectArgs::decoder_limits` (§27.11).
    pub decoder_limits: CppDecoderLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedCppFiles {
    pub main_cpp: PathBuf,
    pub makefile: PathBuf,
    pub harness_id: String,
}

/// On Windows, prepend the MSVC STL version-mismatch escape hatch to the C++
/// harness compile flags. The Microsoft STL shipped with Visual Studio hard-errors
/// (`STL1000: Unexpected compiler version`) when the compiler predates the
/// clang/MSVC version it was tested against — and clang routinely lags the latest
/// VS STL by a release (e.g. clang 18 vs an STL demanding clang 19), so every C++
/// harness fails to compile against a recent VS STL. `_ALLOW_COMPILER_AND_STL_
/// VERSION_MISMATCH` is Microsoft's supported opt-out. No-op off Windows (libstdc++
/// / libc++ ignore it). Pure (platform passed in) so it is unit-testable off-Windows.
fn cpp_compile_flags_with_stl_compat(mut flags: Vec<String>, windows: bool) -> Vec<String> {
    const STL_COMPAT: &str = "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH";
    if windows && !flags.iter().any(|f| f == STL_COMPAT) {
        flags.insert(0, STL_COMPAT.to_owned());
    }
    flags
}

pub fn generate_cpp_direct_harness(
    args: GenerateCppDirectArgs,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_context(&args, &[])?;
    render_cpp_harness(&args.output_dir, &args.harness_id, &context)
}

/// Like [`generate_cpp_direct_harness`] but constructs opaque-handle parameters
/// through the given init/delete FREE-function lifecycles (the CLI discovers them
/// from sibling functions). Lets a C-ABI decode entry whose first parameter is an
/// opaque context — libde265 `de265_decode_data(de265_decoder_context *, const
/// void *, int)` — be auto-harnessed: `ctx = de265_new_decoder(); decode(ctx,
/// Data, Size); de265_free_decoder(ctx);`.
pub fn generate_cpp_direct_harness_with_lifecycle(
    args: GenerateCppDirectArgs,
    handle_lifecycle: &[crate::c_decoders::CHandleLifecycle],
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_context(&args, handle_lifecycle)?;
    render_cpp_harness(&args.output_dir, &args.harness_id, &context)
}

pub fn generate_cpp_sequence_harness(
    args: GenerateCppSequenceArgs,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_sequence_context(&args)?;
    render_cpp_harness(&args.output_dir, &args.harness_id, &context)
}

pub fn cpp_parameter_type_supported(cpp_type: &str) -> bool {
    select_cpp_decoder(cpp_type, "_gf_probe").is_some()
}

/// Whether `name` is something we can legally write after `receiver.` as a member
/// call — a plain member identifier or an `operatorX` overload. Robustness gate for
/// the sequence/method emitter (campaign: tinyobjloader): even after attribution is
/// fixed in the parser, a residual tree-sitter error-recovery artifact must never
/// reach codegen as `receiver.<garbage>(...)`. A `~Dtor`, a qualified `A::b`, a
/// templated `f<...>` spelling, or any non-identifier text is rejected here and the
/// step/target is dropped or the harness skipped cleanly instead of emitting a
/// non-compiling call.
pub fn cpp_callable_member_name(name: &str) -> bool {
    let name = name.trim();
    if let Some(op) = name.strip_prefix("operator") {
        // `operator==`, `operator()`, `operator[]`, `operator new` …: accept any
        // non-empty operator spelling; reject a bare `operator`.
        return !op.is_empty();
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Reserved keywords that can NEVER stand alone as a return type. A
/// `function_definition` tree-sitter recovered from a mis-parsed `namespace X {`
/// surfaces with return type exactly `namespace` (tinyobjloader's `detail_fp`),
/// which the emitter would otherwise render as the un-compilable
/// `namespace R = receiver.detail_fp();`. (`struct`/`class`/`enum`/`union` are NOT
/// listed: as a *single* leading token before a tag name — `struct Foo` — they are
/// a legal elaborated-type-specifier, so a lone one is the artifact while two
/// tokens are fine.)
const CPP_NON_TYPE_RETURN_KEYWORDS: &[&str] = &[
    "namespace",
    "template",
    "typedef",
    "using",
    "friend",
    "public",
    "private",
    "protected",
    "return",
];

/// Whether `return_type` is a usable type the emitter can write as `<ret> R = …`.
/// Rejects the empty string only implicitly (callers treat empty as `void`); the
/// real job is vetoing a lone reserved keyword that is a parse artifact rather than
/// a type. See [`CPP_NON_TYPE_RETURN_KEYWORDS`].
pub fn cpp_return_type_emittable(return_type: &str) -> bool {
    let toks: Vec<&str> = return_type.split_whitespace().collect();
    if let [only] = toks.as_slice() {
        if CPP_NON_TYPE_RETURN_KEYWORDS.contains(only) {
            return false;
        }
    }
    true
}

fn render_cpp_harness(
    output_dir: &PathBuf,
    harness_id: &str,
    context: &CppTemplateContext,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let tera = templates::build_tera()?;
    let main_cpp = tera.render(
        "direct_harness_cpp",
        &tera::Context::from_serialize(context)?,
    )?;
    let makefile = tera.render(
        "harness_makefile_cpp",
        &tera::Context::from_serialize(context)?,
    )?;

    fs::create_dir_all(output_dir)?;
    let main_path = output_dir.join("main.cpp");
    let makefile_path = output_dir.join("Makefile");
    fs::write(&main_path, main_cpp)?;
    fs::write(&makefile_path, makefile)?;

    Ok(GeneratedCppFiles {
        main_cpp: main_path,
        makefile: makefile_path,
        harness_id: harness_id.to_owned(),
    })
}

#[derive(Debug, Serialize)]
struct CppTemplateContext {
    harness_id: String,
    qualified_target_name: String,
    /// Turbofish type-argument suffix for an instantiated template target —
    /// `"<int>"`, `"<std::string, double>"`, or empty for a non-template
    /// (#455 / §27.5). Appended directly after `qualified_target_name` in the
    /// emitted call so the right specialization is selected.
    target_template_suffix: String,
    target_name: String,
    forward_namespace: String,
    target_includes: Vec<String>,
    target_includes_dirs: Vec<String>,
    target_sources: Vec<String>,
    compile_flags: Vec<String>,
    link_flags: Vec<String>,
    build_context_provenance: String,
    build_context_confidence: String,
    build_context_recovery: String,
    c_runtime_include: String,
    params: Vec<CParamEmission>,
    return_type: String,
    return_type_present: bool,
    constructor_params: Vec<CParamEmission>,
    /// Class name (heuristically detected) when the target is a member
    /// function and we should emit a stack instance + method call instead
    /// of a free-function forward decl.
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_class: Option<String>,
    /// True when the target itself is a constructor: emit direct-initialization
    /// `Class _gf_receiver(args);` rather than a member call `_gf_receiver.Class(args)`
    /// (naming a constructor as a member function is illegal C++).
    target_is_constructor: bool,
    /// Static methods have no receiver object, but they are still class members
    /// and cannot be forward-declared as namespace-level free functions.
    target_is_method: bool,
    /// True when at least one header in `target_includes` brings the target
    /// declaration into scope, so the forward declaration block is
    /// redundant (and would conflict for class members).
    has_target_header: bool,
    using_namespaces: Vec<String>,
    uses_array: bool,
    uses_bitset: bool,
    uses_chrono: bool,
    uses_deque: bool,
    uses_filesystem: bool,
    uses_forward_list: bool,
    uses_functional: bool,
    uses_list: bool,
    uses_map: bool,
    uses_memory: bool,
    uses_optional: bool,
    uses_set: bool,
    uses_span: bool,
    uses_tuple: bool,
    uses_unordered_map: bool,
    uses_unordered_set: bool,
    uses_utility: bool,
    uses_variant: bool,
    cxx_standard: String,
    passthrough_libfuzzer_entrypoint: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_cleanup: Option<String>,
    lifecycle_steps: Vec<CppLifecycleStepEmission>,
    lifecycle_step_count: usize,
    /// True for a free-function byte-stream decoder (`decode(uint8_t byte, ...)`,
    /// PX4 st24_decode/sumd_decode): feed the whole fuzz input through the target
    /// one byte at a time so the stateful protocol machine is driven. `params`
    /// then holds only parameters 2..N (the byte is the loop variable).
    byte_stream: bool,
    /// Factory-based receiver construction, set when the receiver class has no
    /// usable public constructor and is instead built via a factory method or
    /// free function. When present, the template emits owner construction +
    /// factory call + null-guarded method call instead of the normal receiver path.
    #[serde(skip_serializing_if = "Option::is_none")]
    factory: Option<CppTemplateFactoryContext>,
}

#[derive(Debug, Serialize)]
struct CppLifecycleStepEmission {
    name: String,
    params: Vec<CParamEmission>,
    return_type: String,
    return_type_present: bool,
    result_name: String,
}

/// Template-level factory context: serialised into the Tera template so the
/// harness emits owner construction + factory call + null-guarded method call.
#[derive(Debug, Serialize)]
struct CppTemplateFactoryContext {
    /// Qualified owner type for an instance-method factory (e.g.,
    /// `"tinyxml2::XMLDocument"`); empty string for a free-function factory.
    owner_type: String,
    method: String,
    params: Vec<CParamEmission>,
    receiver_is_pointer: bool,
}

/// Detect adjacent (raw-buffer, length) pairs in a C++ parameter list and
/// emit a Data+Size view, falling back to the per-parameter C++ decoder
/// for everything else. Mirrors the C-side `build_param_decoders` so a
/// `void Parse(const char *xml, size_t nBytes)`-shaped C++ API stops
/// receiving random mismatched length+heap-string and starts receiving
/// coherent libFuzzer input.
fn build_cpp_param_decoders(
    params: &[CppParameter],
    registry: &TypeRegistry,
    handle_lifecycle: &[crate::c_decoders::CHandleLifecycle],
    limits: &CppDecoderLimits,
    // Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    // decoders reject gets a best-effort compiling driver instead of failing the
    // whole target. Default-path callers pass `false` (emission unchanged).
    force: bool,
    // The target is a user-defined-literal operator (`operator"" _x`). By
    // [lex.ext], its `(charT const *, size_t)` parameters are the literal and its
    // EXACT length — intrinsically paired. The length must therefore be bound to
    // the buffer's own char count (`Size`), never an independent fuzzed value: a
    // decoupled `n` up to 65536 made `std::string(s, n)` read past a `Size`-byte
    // buffer (nlohmann `operator"" _json_pointer` → ASan heap-overflow FALSE
    // POSITIVE). Default-path callers pass `false`.
    literal_operator: bool,
) -> Result<Vec<CParamEmission>, HarnessGenError> {
    // Strip leading declaration-specifier / attribute / decoration-macro noise
    // from every parameter type up front (`__restrict`, `HB_UNUSED`, etc.) so the
    // generated `<type> arg` declarations and decoders never see it.
    let params: Vec<CppParameter> = params
        .iter()
        .enumerate()
        .map(|(i, p)| CppParameter {
            // Synthesize a name for an unnamed parameter so the decoder never
            // emits `Type ;` / `memset(&, 0, sizeof )` with empty operands.
            name: crate::c_decoders::sanitize_or_synthesize_param_name(&p.name, i),
            cpp_type: crate::c_decoders::strip_type_decoration(&p.cpp_type),
        })
        .collect();
    let params = &params[..];
    let mut out = Vec::with_capacity(params.len());
    let mut i = 0;
    let mut pair_consumed = false;
    while i < params.len() {
        // User-defined-literal string operator: `operator"" _x(charT const *s,
        // size_t n)`. By [lex.ext] `n` is the literal's exact length, so it must
        // track the buffer — bind `s` via the standalone char decoder (a
        // NUL-terminated `Size`-byte copy, safe for both `string(s, n)` and a
        // C-string `string(s)`) and `n = Size`. Without this, `n` was an
        // independent fuzzed length that overran `s` (heap-overflow FALSE POSITIVE).
        if literal_operator
            && i == 0
            && params.len() == 2
            && is_cpp_char_pointer_param(&params[0].cpp_type)
            && is_length_cpp_param(&params[1].cpp_type)
        {
            if let Ok(s_emission) = select_cpp_decoder_with_registry_limited(
                &params[0].cpp_type,
                &params[0].name,
                registry,
                limits,
            ) {
                out.push(s_emission);
                let len_type = params[1]
                    .cpp_type
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push(CParamEmission {
                    support: None,
                    decl: format!("{len_type} {} = ({len_type})Size", params[1].name),
                    arg: params[1].name.clone(),
                    c_type: len_type,
                    free: None,
                });
                break;
            }
        }
        if i + 1 < params.len()
            && is_output_buffer_cpp_param(&params[i].cpp_type)
            && is_length_pointer_cpp_param(&params[i + 1].cpp_type)
            && looks_like_cpp_output_capacity_pair(&params[i], &params[i + 1])
        {
            let (buf_decl, len_decl) = pair_cpp_output_buffer_length(&params[i], &params[i + 1]);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        if i + 1 < params.len()
            && is_output_buffer_cpp_param(&params[i].cpp_type)
            && is_length_cpp_param(&params[i + 1].cpp_type)
            && looks_like_cpp_output_capacity_pair(&params[i], &params[i + 1])
        {
            let (buf_decl, len_decl) = pair_cpp_output_buffer_capacity(&params[i], &params[i + 1]);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        if !pair_consumed
            && i + 1 < params.len()
            && is_raw_buffer_cpp_param(&params[i].cpp_type)
            && is_length_cpp_param(&params[i + 1].cpp_type)
            // Require NAME evidence before binding (buffer, Size), mirroring the C
            // lane: `pugi::xml_document::load_file(const char *path_, unsigned int
            // options)` was mis-read as a (buffer, length) pair — binding `path_`
            // to the raw, non-NUL-terminated Data span (a file path the parser then
            // ran off the end of: a heap-buffer-overflow FALSE POSITIVE). Neither
            // `path_` nor `options` is buffer- or length-shaped, so they fall
            // through to the standalone decoders (path_ -> a tempfile path).
            && (crate::c_generate::looks_like_count_name(&params[i + 1].name)
                || crate::c_generate::looks_like_buffer_name(&params[i].name))
        {
            let buf = &params[i];
            let len = &params[i + 1];
            let buf_type = normalize_cpp_pointer(&buf.cpp_type);
            let len_type = len
                .cpp_type
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let buf_decl = format!("{buf_type} {} = ({buf_type})Data", buf.name);
            let len_decl = format!("{len_type} {} = ({len_type})Size", len.name);
            out.push(CParamEmission {
                support: None,
                decl: buf_decl,
                arg: buf.name.clone(),
                c_type: buf_type.clone(),
                free: None,
            });
            out.push(CParamEmission {
                support: None,
                decl: len_decl,
                arg: len.name.clone(),
                c_type: len_type,
                free: None,
            });
            i += 2;
            pair_consumed = true;
            continue;
        }
        let emission = match select_cpp_decoder_with_registry_limited(
            &params[i].cpp_type,
            &params[i].name,
            registry,
            limits,
        ) {
            Ok(emission) => emission,
            // The C++ decoder bails on an opaque-handle pointer (an opaque
            // `void`-typedef the fuzzer can't synthesize). If the CLI discovered a
            // FREE-function lifecycle for it (libde265's `de265_decoder_context *`
            // via `de265_new_decoder`/`de265_free_decoder`), construct it through
            // that lifecycle instead of failing. Fall back to the original error
            // if no lifecycle applies, so a genuinely un-drivable param still fails.
            Err(cpp_err) => {
                let via_lifecycle = (!handle_lifecycle.is_empty())
                    .then(|| {
                        crate::c_decoders::select_c_decoder_with_lifecycle_cpp(
                            &params[i].cpp_type,
                            &params[i].name,
                            registry,
                            handle_lifecycle,
                        )
                        .ok()
                    })
                    .flatten();
                match via_lifecycle {
                    Some(emission) => emission,
                    None if force => crate::c_decoders::best_effort_param_emission(
                        &params[i].cpp_type,
                        &params[i].name,
                    ),
                    None => {
                        return Err(HarnessGenError::UnsupportedParamType(format!(
                            "C++ parameter '{}' of type '{}' has no byte-buffer decoder \
                     (auto-harness drives scalar, string, and visible aggregate params): {cpp_err}",
                            params[i].name, params[i].cpp_type
                        )));
                    }
                }
            }
        };
        out.push(emission);
        i += 1;
    }
    Ok(out)
}

fn normalize_cpp_pointer(c_type: &str) -> String {
    c_type
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("char*", "char *")
        .replace("uint8_t*", "uint8_t *")
        .replace("std::uint8_t*", "std::uint8_t *")
        .replace("int8_t*", "int8_t *")
        .replace("std::byte*", "std::byte *")
        .replace("unsigned char*", "unsigned char *")
        .replace("void*", "void *")
}

fn is_raw_buffer_cpp_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    let without_const = normalized.trim_start_matches("const ").trim();
    cpp_pointer_base(without_const).is_some_and(is_cpp_byte_buffer_base)
}

/// Whether a target name is a user-defined-literal operator (`operator"" _x` /
/// `operator""_x`). The spelling varies by dialect (a space after `""` before the
/// suffix in C++11, none in C++17), so normalize whitespace before matching.
fn is_cpp_literal_operator(name: &str) -> bool {
    name.split_whitespace()
        .collect::<String>()
        .contains("operator\"\"")
}

/// A pointer to any character element — the first parameter of a user-defined
/// string-literal operator. Broader than [`is_raw_buffer_cpp_param`]: it also
/// accepts the wide/Unicode literal element types (`char8_t`/`char16_t`/
/// `char32_t`/`wchar_t`) that a UDL literal can carry but that are not byte
/// buffers for the generic (buffer, length) pairing.
fn is_cpp_char_pointer_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    let without_const = normalized.trim_start_matches("const ").trim();
    cpp_pointer_base(without_const).is_some_and(|base| {
        matches!(
            base,
            "char"
                | "unsigned char"
                | "signed char"
                | "char8_t"
                | "std::char8_t"
                | "char16_t"
                | "std::char16_t"
                | "char32_t"
                | "std::char32_t"
                | "wchar_t"
                | "uint8_t"
                | "std::uint8_t"
                | "int8_t"
                | "std::byte"
        )
    })
}

fn is_output_buffer_cpp_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    if is_const_cpp_pointer_type(&normalized) {
        return false;
    }
    cpp_pointer_base(&normalized).is_some_and(is_cpp_byte_buffer_base)
}

fn cpp_pointer_base(cpp_type: &str) -> Option<&str> {
    cpp_type
        .trim()
        .strip_suffix(" *")
        .map(str::trim)
        .filter(|base| !base.contains('*'))
}

fn is_const_cpp_pointer_type(cpp_type: &str) -> bool {
    cpp_pointer_base(cpp_type)
        .is_some_and(|base| base.split_whitespace().any(|token| token == "const"))
}

fn is_cpp_byte_buffer_base(base: &str) -> bool {
    matches!(
        base,
        "char" | "uint8_t" | "std::uint8_t" | "std::byte" | "unsigned char" | "void" | "int8_t"
    )
}

fn is_length_cpp_param(cpp_type: &str) -> bool {
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    let canonical = normalized.trim_start_matches("const ").trim();
    is_cpp_length_scalar_base(canonical)
}

fn is_length_pointer_cpp_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    if is_const_cpp_pointer_type(&normalized) {
        return false;
    }
    cpp_pointer_base(&normalized).is_some_and(is_cpp_length_scalar_base)
}

fn is_cpp_length_scalar_base(base: &str) -> bool {
    matches!(
        base,
        "size_t"
            | "std::size_t"
            | "ssize_t"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
    )
}

fn pair_cpp_output_buffer_length(
    buffer: &CppParameter,
    length: &CppParameter,
) -> (CParamEmission, CParamEmission) {
    let buf_type = normalize_cpp_pointer(&buffer.cpp_type);
    let len_type = normalize_cpp_pointer(&length.cpp_type);
    let len_base = cpp_pointer_base(&len_type)
        .expect("caller checked length pointer")
        .to_owned();
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_gf_cap_{buf_name}");
    let len_storage = format!("_gf_out_{len_name}");

    let buf_decl = format!(
        "size_t {cap_name} = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_decl =
        format!("{len_base} {len_storage} = ({len_base}){cap_name}; {len_base} *{len_name} = &{len_storage}");
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

fn pair_cpp_output_buffer_capacity(
    buffer: &CppParameter,
    length: &CppParameter,
) -> (CParamEmission, CParamEmission) {
    let buf_type = normalize_cpp_pointer(&buffer.cpp_type);
    let len_type = length
        .cpp_type
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_gf_cap_{buf_name}");

    let buf_decl = format!(
        "size_t {cap_name} = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_decl = format!("{len_type} {len_name} = ({len_type}){cap_name}");
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

fn looks_like_cpp_output_capacity_pair(buffer: &CppParameter, length: &CppParameter) -> bool {
    looks_cpp_outputish(&buffer.name) || looks_cpp_outputish(&length.name)
}

fn looks_cpp_outputish(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("out")
        || lower.contains("output")
        || lower.contains("dest")
        || lower.contains("dst")
}

fn build_cpp_context<'a>(
    args: &'a GenerateCppDirectArgs,
    handle_lifecycle: &'a [crate::c_decoders::CHandleLifecycle],
) -> Result<CppTemplateContext, HarnessGenError> {
    build_cpp_context_common(CppContextInput {
        harness_id: &args.harness_id,
        source_path: &args.source_path,
        target: &args.target,
        params: &args.params,
        return_type: &args.return_type,
        target_includes: &args.target_includes,
        target_includes_dirs: &args.target_includes_dirs,
        target_sources: &args.target_sources,
        compile_flags: &args.compile_flags,
        c_runtime_include: &args.c_runtime_include,
        using_namespaces: &args.using_namespaces,
        result_cleanup: args.result_cleanup.as_deref(),
        constructor_params: &args.constructor_params,
        type_defs: &args.type_defs,
        default_constructible_classes: &args.default_constructible_classes,
        receiver_class_override: args.receiver_class_override.as_deref(),
        lifecycle_steps: Vec::new(),
        handle_lifecycle,
        factory_plan: args.factory_plan.as_ref(),
        decoder_limits: args.decoder_limits,
        force: args.force,
    })
}

fn build_cpp_sequence_context(
    args: &GenerateCppSequenceArgs,
) -> Result<CppTemplateContext, HarnessGenError> {
    let registry = TypeRegistry::from_defs(args.type_defs.iter());
    let lifecycle_steps =
        build_lifecycle_step_emissions(&args.lifecycle_steps, &registry, args.decoder_limits)?;
    build_cpp_context_common(CppContextInput {
        harness_id: &args.harness_id,
        source_path: &args.source_path,
        target: &args.target,
        params: &args.params,
        return_type: &args.return_type,
        target_includes: &args.target_includes,
        target_includes_dirs: &args.target_includes_dirs,
        target_sources: &args.target_sources,
        compile_flags: &args.compile_flags,
        c_runtime_include: &args.c_runtime_include,
        using_namespaces: &args.using_namespaces,
        result_cleanup: args.result_cleanup.as_deref(),
        constructor_params: &args.constructor_params,
        type_defs: &args.type_defs,
        default_constructible_classes: &args.default_constructible_classes,
        receiver_class_override: args.receiver_class_override.as_deref(),
        lifecycle_steps,
        handle_lifecycle: &[],
        factory_plan: args.factory_plan.as_ref(),
        decoder_limits: args.decoder_limits,
        // The C++ sequence path is not part of the force-fuzz direct flow.
        force: false,
    })
}

struct CppContextInput<'a> {
    harness_id: &'a str,
    source_path: &'a PathBuf,
    target: &'a CppFunction,
    params: &'a [CppParameter],
    return_type: &'a str,
    target_includes: &'a [String],
    target_includes_dirs: &'a [PathBuf],
    target_sources: &'a [PathBuf],
    compile_flags: &'a [String],
    c_runtime_include: &'a PathBuf,
    using_namespaces: &'a [String],
    result_cleanup: Option<&'a str>,
    constructor_params: &'a [CppParameter],
    type_defs: &'a [c_parser::CTypeDefs],
    default_constructible_classes: &'a [String],
    receiver_class_override: Option<&'a str>,
    lifecycle_steps: Vec<CppLifecycleStepEmission>,
    /// Init/delete FREE-function lifecycles for opaque-handle parameters (an
    /// opaque `void`-typedef pointer the fuzzer can't synthesize, built via a
    /// `new`/`free` pair instead). Empty for harnesses without such a param.
    handle_lifecycle: &'a [crate::c_decoders::CHandleLifecycle],
    /// Factory plan for receiver construction (see `CppFactoryPlan`).
    factory_plan: Option<&'a CppFactoryPlan>,
    /// Configurable container/bitset/array decoder caps (§27.11).
    decoder_limits: CppDecoderLimits,
    /// Force-fuzz mode (`auto --force`). When true, a rejected parameter gets a
    /// best-effort compiling driver instead of failing the target. Default
    /// `false` (sequence path, unit tests) keeps the emission unchanged.
    force: bool,
}

/// C++ counterpart of `validate_c_build_inputs`: refuse untrusted
/// flags/paths/include dirs that could inject commands into the
/// generated Makefile recipe.
fn validate_cpp_build_inputs(input: &CppContextInput<'_>) -> Result<(), HarnessGenError> {
    use crate::build_safety::{ensure_all_build_inputs_safe, ensure_build_input_safe};
    ensure_all_build_inputs_safe(
        "compile flag",
        input.compile_flags.iter().map(String::as_str),
    )?;
    ensure_all_build_inputs_safe(
        "include name",
        input.target_includes.iter().map(String::as_str),
    )?;
    for dir in input.target_includes_dirs {
        ensure_build_input_safe("include dir", &dir.display().to_string())?;
    }
    for src in input.target_sources {
        ensure_build_input_safe("source path", &src.display().to_string())?;
    }
    ensure_build_input_safe(
        "runtime include",
        &input.c_runtime_include.display().to_string(),
    )?;
    // Robustness gate (campaign: tinyobjloader): refuse to emit a harness whose
    // TARGET call would not compile because the parser handed us a non-identifier
    // leaf name or a parse-artifact return type (a mis-recovered `namespace X {`
    // arrives as a "function" named `X` with return type `namespace`). A clean
    // skip with an actionable reason beats an emitted `namespace R = X(...);`. Skip
    // the check for the libFuzzer passthrough entrypoint, which is emitted as a
    // definition rather than a call.
    if input.target.name != "LLVMFuzzerTestOneInput" {
        if !cpp_callable_member_name(&input.target.name) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "C++ target '{}' is not a valid callable name (likely a parse-recovery \
                 artifact, e.g. a namespace mis-parsed as a function); skipping rather \
                 than emitting an uncompilable harness",
                input.target.name
            )));
        }
        if !cpp_return_type_emittable(input.return_type) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "C++ target '{}' has a malformed return type '{}' (likely a parse-recovery \
                 artifact); skipping rather than emitting an uncompilable harness",
                input.target.name, input.return_type
            )));
        }
    }
    Ok(())
}

/// Strip leading declaration-specifier tokens that are illegal on a runtime-
/// initialized local result variable (`<ret> R = <call>;`).
///
/// `strip_type_decoration` already removes the bare keyword spellings
/// (`constexpr`/`consteval`/`static`/`inline`), but a macro that *expands* to such
/// a specifier reaches codegen unexpanded — the harness does not preprocess the
/// target header. utf8.h declares `utf8_constexpr14_impl int utf8cmp(...)` where
/// the macro expands to `constexpr` under C++14, so the literal token
/// `utf8_constexpr14_impl` survives into the return type and emitting
/// `utf8_constexpr14_impl int R = <runtime call>;` is rejected ("constexpr
/// variable 'R' must be initialized by a constant expression").
///
/// Drop a leading bare storage/constant-evaluation keyword, or a leading
/// identifier-shaped macro token whose lowercased form names a constant-evaluation
/// specifier (`constexpr`/`consteval`/`constinit`), but only while a real type
/// token still follows. cv-qualifiers (`const`/`volatile`) are deliberately NOT
/// stripped: `const char * R = call();` is legal and the `const` belongs to the
/// pointee, so removing it would corrupt the type (and reject assigning a
/// `const char *` return into a `char *` local).
fn strip_runtime_illegal_result_specifiers(return_type: &str) -> String {
    let toks: Vec<&str> = return_type.split_whitespace().collect();
    let mut i = 0;
    while i + 1 < toks.len() && is_runtime_illegal_result_specifier(toks[i]) {
        i += 1;
    }
    toks[i..].join(" ")
}

/// Whether a leading return-type token is a declaration specifier that is illegal
/// on (or, for a constexpr family, makes ill-formed) a runtime-initialized local.
/// See [`strip_runtime_illegal_result_specifiers`].
fn is_runtime_illegal_result_specifier(tok: &str) -> bool {
    if matches!(
        tok,
        "constexpr" | "consteval" | "constinit" | "static" | "inline"
    ) {
        return true;
    }
    // Match a macro that expands to a constant-evaluation specifier: an
    // identifier-shaped token whose lowercased form contains a constexpr/consteval/
    // constinit marker (utf8.h's `utf8_constexpr14_impl`, a `FOO_CONSTEXPR`, ...).
    // Restrict to identifier characters so punctuated type spellings (`char *`,
    // `std::string`) are never matched.
    if !tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let lower = tok.to_ascii_lowercase();
    ["constexpr", "consteval", "constinit"]
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Whether any token in `return_type` is an unexpanded all-caps decoration macro
/// — uppercase/digits/underscores, ≥3 chars, at least one letter, and CONTAINING
/// an underscore (the multi-segment shape of library macros: `TOML_CALLCONV`,
/// `FOO_EXTERNAL_LINKAGE`). Requiring the underscore keeps single-word real
/// all-caps typedefs (`DWORD`, `BYTE`, `HANDLE`, `BOOL`) — which compile fine as an
/// explicit result type — from being needlessly demoted to `auto`. Splits on the
/// punctuation that separates type tokens (`*`, `&`, `<`, `>`, `,`, `::`, `()`) so a
/// macro buried in a qualified/templated spelling is still caught.
fn return_type_has_macro_shaped_token(return_type: &str) -> bool {
    return_type
        .split(|c: char| {
            c.is_whitespace() || matches!(c, '*' | '&' | '<' | '>' | ',' | ':' | '(' | ')')
        })
        .any(|tok| {
            tok.len() >= 3
                && tok.contains('_')
                && tok.bytes().any(|b| b.is_ascii_uppercase())
                && tok
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn build_cpp_context_common(
    input: CppContextInput<'_>,
) -> Result<CppTemplateContext, HarnessGenError> {
    validate_cpp_build_inputs(&input)?;
    let input_references_type_defs = cpp_params_reference_type_defs(&input);
    let registry = TypeRegistry::from_defs(input.type_defs.iter())
        .with_default_constructible_classes(input.default_constructible_classes.iter().cloned());
    // Template-function instantiation (#455 / §27.5): when the target carries a
    // resolved specialization, substitute its concrete type arguments into the
    // parameter / return types BEFORE decoding (so `const std::vector<T> &`
    // decodes as `const std::vector<int> &`) and remember the turbofish suffix
    // for the call. A non-template target has no args and is untouched.
    let template_subst: Vec<(String, String)> = input
        .target
        .template_type_params
        .iter()
        .cloned()
        .zip(input.target.instantiation_args.iter().cloned())
        .collect();
    let substituted_params_storage: Vec<CppParameter>;
    let effective_params: &[CppParameter] = if template_subst.is_empty() {
        input.params
    } else {
        substituted_params_storage = input
            .params
            .iter()
            .map(|p| CppParameter {
                name: p.name.clone(),
                cpp_type: substitute_template_type_params(&p.cpp_type, &template_subst),
            })
            .collect();
        &substituted_params_storage
    };
    let target_template_suffix = if input.target.instantiation_args.is_empty() {
        String::new()
    } else {
        format!("<{}>", input.target.instantiation_args.join(", "))
    };
    // A free-function byte-stream decoder is driven one byte at a time: the first
    // parameter is the untrusted byte (the loop variable), only params 2..N are
    // decoded/backed.
    let byte_stream = !input.target.api.is_method
        && input.constructor_params.is_empty()
        && input.lifecycle_steps.is_empty()
        && is_cpp_byte_stream_decoder(&input.target.name, effective_params);
    let literal_operator = is_cpp_literal_operator(&input.target.name);
    let params = if byte_stream {
        build_cpp_param_decoders(
            effective_params.get(1..).unwrap_or(&[]),
            &registry,
            input.handle_lifecycle,
            &input.decoder_limits,
            input.force,
            literal_operator,
        )?
    } else {
        build_cpp_param_decoders(
            effective_params,
            &registry,
            input.handle_lifecycle,
            &input.decoder_limits,
            input.force,
            literal_operator,
        )?
    };
    let constructor_params = build_constructor_param_emissions(
        input.constructor_params,
        &registry,
        &input.decoder_limits,
    )?;
    let factory = if let Some(plan) = input.factory_plan {
        let factory_params = build_constructor_param_emissions(
            &plan.factory_params,
            &registry,
            &input.decoder_limits,
        )?;
        Some(CppTemplateFactoryContext {
            owner_type: plan.owner_type.clone().unwrap_or_default(),
            method: plan.factory_method.clone(),
            params: factory_params,
            receiver_is_pointer: plan.receiver_is_pointer,
        })
    } else {
        None
    };
    let build_context = split_cpp_build_context_flags(input.compile_flags);
    let lifecycle_steps = input.lifecycle_steps;
    let factory_param_emissions: Vec<&CParamEmission> = factory
        .as_ref()
        .map(|f| f.params.iter().collect())
        .unwrap_or_default();
    let all_param_emissions = params
        .iter()
        .chain(constructor_params.iter())
        .chain(factory_param_emissions.iter().copied())
        .chain(lifecycle_steps.iter().flat_map(|step| step.params.iter()));
    let mut uses_array = false;
    let mut uses_bitset = false;
    let mut uses_chrono = false;
    let mut uses_deque = false;
    let mut uses_filesystem = false;
    let mut uses_forward_list = false;
    let mut uses_functional = false;
    let mut uses_list = false;
    let mut uses_map = false;
    let mut uses_memory = false;
    let mut uses_optional = false;
    let mut uses_set = false;
    let mut uses_span = false;
    let mut uses_tuple = false;
    let mut uses_unordered_map = false;
    let mut uses_unordered_set = false;
    let mut uses_utility = false;
    let mut uses_variant = false;
    for param in all_param_emissions {
        uses_array |= param.c_type.contains("std::array<");
        uses_bitset |= param.c_type.contains("std::bitset<");
        uses_chrono |= param.c_type.contains("std::chrono::");
        uses_deque |= param.c_type.contains("std::deque<");
        uses_filesystem |= param.c_type.contains("std::filesystem::");
        uses_forward_list |= param.c_type.contains("std::forward_list<");
        uses_functional |= param.c_type.contains("std::function<");
        uses_list |= param.c_type.contains("std::list<");
        uses_map |= param.c_type.contains("std::map<");
        uses_memory |=
            param.c_type.contains("std::unique_ptr<") || param.c_type.contains("std::shared_ptr<");
        uses_optional |= param.c_type.contains("std::optional<");
        uses_set |= param.c_type.contains("std::set<");
        uses_span |= param.c_type.contains("std::span<");
        uses_tuple |= param.c_type.contains("std::tuple<");
        uses_unordered_map |= param.c_type.contains("std::unordered_map<");
        uses_unordered_set |= param.c_type.contains("std::unordered_set<");
        uses_utility |= param.c_type.contains("std::pair<") || param.arg.contains("std::move(");
        uses_variant |=
            param.c_type.contains("std::variant<") || param.c_type.contains("std::monostate");
    }
    // Use the GNU dialect, not strict ISO. Real systems/embedded C++ codebases
    // (PX4, cFE, the kernel headers they pull in, zeek) pervasively use GNU
    // extensions -- `typeof`, statement expressions, `__attribute__`, anonymous
    // structs -- in headers the target transitively includes (PX4's drv_hrt.h
    // uses bare `typeof`). Strict `-std=c++NN` rejects those and the harness
    // fails to build through no fault of the parser under test; the GNU dialect
    // is a superset that accepts them and matches how these projects actually
    // compile. No downside for fuzzing the project's own translation units.
    // Default to gnu++20: modern C++ projects increasingly require C++20 features
    // (char8_t, concepts, three-way comparison — libheif, capnproto, ctre all
    // failed under gnu++17), and gnu++20 is a near-superset that still compiles
    // C++11/14/17 translation units, so it's the safer floor. `uses_span` is kept
    // for the <span> include but no longer gates the standard.
    let _ = uses_span;
    // The baked default is gnu++20; `--cxx-std` (published by `auto` as
    // GOVFUZZ_CXX_STD) overrides it, and even without an override the Makefile's
    // CXX_STD is overridable at build time by the dialect ladder.
    let cxx_standard = std::env::var("GOVFUZZ_CXX_STD")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "gnu++20".to_owned());

    // Qualify unqualified std names in the result type too (the harness lacks
    // the target's `using std::map;` etc.): `R = obj.foo()` declared as
    // `map<string, Json>` -> "no template named 'map'". A template result type
    // (`T`) is first specialised to the chosen instantiation (#455 / §27.5) so
    // `T R = convert<int>(..)` becomes `int R = convert<int>(..)`.
    let substituted_return = if template_subst.is_empty() {
        input.return_type.trim().to_owned()
    } else {
        substitute_template_type_params(input.return_type.trim(), &template_subst)
    };
    let return_type =
        crate::cpp_decoders::qualify_std_type_names(&strip_runtime_illegal_result_specifiers(
            &crate::c_decoders::strip_type_decoration(substituted_return.trim()),
        ));
    // Robust fallback: if the cleaned return type STILL carries an unexpanded
    // decoration macro (e.g. an export/linkage/calling-convention macro the parser
    // didn't recognise — `TOML_EXTERNAL_LINKAGE`, `FOO_CALLCONV`), writing
    // `<ret> R = call();` won't compile because the header `#undef`s that token. We
    // can't preprocess the header, but `auto R = call();` deduces the real type and
    // always compiles when the call does. See [`return_type_has_macro_shaped_token`].
    let return_type = if return_type_has_macro_shaped_token(&return_type) {
        "auto".to_owned()
    } else {
        return_type
    };
    let return_type_present = !return_type.is_empty() && return_type != "void";

    let qualified_target_name = if input.target.qualifier_path.is_empty() {
        input.target.name.clone()
    } else {
        format!(
            "{}::{}",
            input.target.qualifier_path.join("::"),
            input.target.name
        )
    };

    // A receiver instance is needed only for an actual member function, and
    // its type is the full qualifier path (namespace(s) + (nested) class),
    // e.g. `Json::Value`, `acme::v2::XmlReader`. `is_method` is the
    // authoritative signal — inferring "is this a class" from the
    // capitalization of the last qualifier segment wrongly treats a free
    // function in a Capitalized namespace (jsoncpp's `Json::releaseStringValue`)
    // as a method of class `Json`, synthesising a bogus `Json _gf_receiver`.
    let receiver_class = if input.target.api.is_method
        && !input.target.is_static
        && !input.target.qualifier_path.is_empty()
    {
        // #456: an abstract declaring class is replaced by a concrete subclass the
        // caller resolved, so the receiver is constructible and the virtual method
        // dispatches to the subclass's implementation.
        Some(
            input
                .receiver_class_override
                .map(str::to_owned)
                .unwrap_or_else(|| input.target.qualifier_path.join("::")),
        )
    } else {
        None
    };
    let target_is_constructor = receiver_class.is_some() && input.target.api.is_constructor;
    let include_source_for_receiver = receiver_class.is_some()
        && input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path);
    let include_source_for_type_defs = input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path)
        && input_references_type_defs;
    // A same-file template instantiation needs the template's DEFINITION (its
    // body), not just a declaration — a `convert<int>(..)` call can only be
    // instantiated where the template body is visible, and the linked `.cpp`
    // never exports an `int convert(..)` symbol. So include the source `.cpp`
    // itself (and drop it from the separately-compiled sources), exactly like the
    // receiver case (#455 / §27.5). When the template lives in an included header
    // this is moot — `has_target_header` already suppresses the forward decl.
    let include_source_for_template = !input.target.instantiation_args.is_empty()
        && input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path);
    // A header-less `.cpp` free function whose signature carries a REFERENCE or an
    // STL container needs its exact declaration in scope: the synthesized forward
    // declaration renders the decode-friendly by-value type (`std::vector<uint8_t>`)
    // for a `const std::vector<unsigned char>&` parameter, and the two mangle
    // differently — the harness then fails to link with `undefined symbol`.
    // Including the source `.cpp` (and dropping it from the separately-linked
    // sources, below) brings the real signature into scope, so no forward
    // declaration is emitted and the call binds to the true definition.
    let include_source_for_reference_param = input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path)
        && input
            .target
            .params
            .iter()
            .any(|param| param.cpp_type.contains('&') || param.cpp_type.contains("std::"));
    let include_source = include_source_for_receiver
        || include_source_for_type_defs
        || include_source_for_template
        || include_source_for_reference_param;
    let mut target_includes = input.target_includes.to_vec();
    let mut target_sources = input.target_sources.to_vec();
    if include_source {
        if let Some(file_name) = input.source_path.file_name().and_then(|name| name.to_str()) {
            target_includes.push(file_name.to_owned());
        }
        target_sources.retain(|source| source != input.source_path);
    }
    let has_target_header = !target_includes.is_empty();
    let mut using_namespaces = input.using_namespaces.to_vec();
    if include_source {
        push_cpp_target_namespace(
            &mut using_namespaces,
            input.target,
            receiver_class.is_some(),
        );
    }
    // Dedup the `using namespace X;` directives, preserving first-seen order: the
    // input list plus the pushed target namespace can repeat the same namespace,
    // emitting duplicate `using namespace simdjson;` lines (harmless but noisy,
    // and a duplicate that imports the same name from two scopes can make a call
    // ambiguous). One per namespace.
    {
        let mut seen = std::collections::HashSet::new();
        using_namespaces.retain(|ns| seen.insert(ns.clone()));
    }
    let passthrough_libfuzzer_entrypoint = input.target.name == "LLVMFuzzerTestOneInput";
    let lifecycle_step_count = lifecycle_steps.len();

    Ok(CppTemplateContext {
        harness_id: input.harness_id.to_owned(),
        qualified_target_name,
        target_template_suffix,
        target_name: input.target.name.clone(),
        forward_namespace: input.target.qualifier_path.join("::"),
        target_includes,
        target_includes_dirs: input
            .target_includes_dirs
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        target_sources: target_sources
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        compile_flags: cpp_compile_flags_with_stl_compat(
            build_context.compile_flags,
            cfg!(windows),
        ),
        link_flags: build_context.link_flags,
        build_context_provenance: build_context.provenance,
        build_context_confidence: build_context.confidence,
        build_context_recovery: build_context.recovery,
        c_runtime_include: crate::build_safety::make_path(input.c_runtime_include),
        params,
        return_type: if return_type_present {
            return_type
        } else {
            "void".to_owned()
        },
        return_type_present,
        constructor_params,
        receiver_class,
        target_is_constructor,
        target_is_method: input.target.api.is_method,
        has_target_header,
        using_namespaces,
        uses_array,
        uses_bitset,
        uses_chrono,
        uses_deque,
        uses_filesystem,
        uses_forward_list,
        uses_functional,
        uses_list,
        uses_map,
        uses_memory,
        uses_optional,
        uses_set,
        uses_span,
        uses_tuple,
        uses_unordered_map,
        uses_unordered_set,
        uses_utility,
        uses_variant,
        cxx_standard,
        passthrough_libfuzzer_entrypoint,
        result_cleanup: input.result_cleanup.map(str::to_owned),
        lifecycle_steps,
        lifecycle_step_count,
        byte_stream,
        factory,
    })
}

/// A free-function byte-stream decoder: a `parse`/`decode`-named function whose
/// first parameter is a single untrusted byte scalar the driver feeds one byte at
/// a time (PX4 st24_decode/sumd_decode). Mirrors the C-side detection.
fn is_cpp_byte_stream_decoder(name: &str, params: &[CppParameter]) -> bool {
    let Some(first) = params.first() else {
        return false;
    };
    let t = first
        .cpp_type
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if t.contains('*') || t.contains('&') {
        return false;
    }
    let t = t.trim_start_matches("const ").trim();
    let is_byte = matches!(
        t,
        "uint8_t" | "int8_t" | "unsigned char" | "signed char" | "char" | "u8" | "std::uint8_t"
    );
    let lower = name.to_ascii_lowercase();
    let parser = [
        "parse",
        "decode",
        "consume",
        "feed",
        "push_byte",
        "rx",
        "scan",
    ]
    .iter()
    .any(|kw| lower.contains(kw));
    is_byte && parser
}

fn push_cpp_target_namespace(
    using_namespaces: &mut Vec<String>,
    target: &CppFunction,
    has_receiver_class: bool,
) {
    let namespace = if !target.api.namespace_path.is_empty() {
        target.api.namespace_path.join("::")
    } else if has_receiver_class {
        target
            .qualifier_path
            .split_last()
            .map(|(_, ns)| ns.join("::"))
            .unwrap_or_default()
    } else {
        target.qualifier_path.join("::")
    };
    if !namespace.is_empty() && !using_namespaces.iter().any(|ns| ns == &namespace) {
        using_namespaces.push(namespace);
    }
}

fn build_constructor_param_emissions(
    params: &[CppParameter],
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Result<Vec<CParamEmission>, HarnessGenError> {
    let renamed_params = params
        .iter()
        .enumerate()
        .map(|(param_index, param)| CppParameter {
            name: constructor_param_name(param_index, &param.name),
            cpp_type: param.cpp_type.clone(),
        })
        .collect::<Vec<_>>();
    build_cpp_param_decoders(&renamed_params, registry, &[], limits, false, false)
}

struct CppBuildContextRender {
    compile_flags: Vec<String>,
    link_flags: Vec<String>,
    provenance: String,
    confidence: String,
    recovery: String,
}

/// Escape a build flag for verbatim interpolation into a Makefile recipe. A flag
/// may legitimately carry a quoted string-macro value (`-DREVISION_ID="lib-1.2.3"`,
/// from CMake / compile_commands.json); written raw into `$(CXX) ... -DX="v" ...`,
/// the shell strips the inner quotes and the macro expands UNQUOTED — a bare token,
/// not a string literal — breaking compilation. Backslash-escaping the quotes makes
/// the shell pass them through literally so the macro stays a string.
pub(crate) fn escape_makefile_recipe_flag(flag: &str) -> String {
    if flag.contains('"') {
        flag.replace('"', "\\\"")
    } else {
        flag.to_owned()
    }
}

fn split_cpp_build_context_flags(flags: &[String]) -> CppBuildContextRender {
    let mut compile_flags = Vec::new();
    let mut link_flags = Vec::new();
    let mut provenance = "none".to_owned();
    let mut confidence = "none".to_owned();
    let mut recovery = "none".to_owned();

    for flag in flags {
        if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_PROVENANCE_PREFIX) {
            provenance = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_CONFIDENCE_PREFIX) {
            confidence = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_RECOVERY_PREFIX) {
            recovery = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_LDFLAG_PREFIX) {
            link_flags.push(escape_makefile_recipe_flag(value));
        } else {
            compile_flags.push(escape_makefile_recipe_flag(flag));
        }
    }

    CppBuildContextRender {
        compile_flags,
        link_flags,
        provenance,
        confidence,
        recovery,
    }
}

fn build_lifecycle_step_emissions(
    steps: &[CppLifecycleStep],
    registry: &TypeRegistry,
    limits: CppDecoderLimits,
) -> Result<Vec<CppLifecycleStepEmission>, HarnessGenError> {
    // Robustness gate (campaign: tinyobjloader): never emit a `receiver.<step>(...)`
    // call the parser handed us with a non-identifier name or a parse-artifact
    // return type (a mis-recovered `namespace detail_fp {` arrives as a "method"
    // named `detail_fp` with return type `namespace`). Drop such steps — re-indexed
    // contiguously so `_gf_step{n}` names and the emitted switch cases stay dense —
    // rather than producing an un-compilable harness. The parser reconciliation
    // normally removes these upstream; this is the belt-and-suspenders net.
    let steps: Vec<&CppLifecycleStep> = steps
        .iter()
        .filter(|step| {
            cpp_callable_member_name(&step.name) && cpp_return_type_emittable(&step.return_type)
        })
        .collect();
    steps
        .iter()
        .enumerate()
        .map(|(step_index, step)| {
            let renamed_params = step
                .params
                .iter()
                .enumerate()
                .map(|(param_index, param)| CppParameter {
                    name: lifecycle_param_name(step_index, param_index, &param.name),
                    cpp_type: param.cpp_type.clone(),
                })
                .collect::<Vec<_>>();
            let params =
                build_cpp_param_decoders(&renamed_params, registry, &[], &limits, false, false)?;
            let return_type = step.return_type.trim().to_owned();
            let return_type_present = !return_type.is_empty() && return_type != "void";
            Ok(CppLifecycleStepEmission {
                name: step.name.clone(),
                params,
                return_type: if return_type_present {
                    return_type
                } else {
                    "void".to_owned()
                },
                return_type_present,
                result_name: format!("_gf_step{step_index}_result"),
            })
        })
        .collect()
}

fn lifecycle_param_name(step_index: usize, param_index: usize, raw: &str) -> String {
    scoped_param_name("_gf_step", Some(step_index), param_index, raw)
}

fn constructor_param_name(param_index: usize, raw: &str) -> String {
    scoped_param_name("_gf_ctor", None, param_index, raw)
}

fn scoped_param_name(
    prefix: &str,
    step_index: Option<usize>,
    param_index: usize,
    raw: &str,
) -> String {
    let mut out = String::from("_gf_step");
    if prefix != "_gf_step" {
        out = prefix.to_owned();
    }
    if let Some(step_index) = step_index {
        out.push_str(&step_index.to_string());
    }
    out.push('_');
    let mut saw_any = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            saw_any = true;
        } else {
            out.push('_');
        }
    }
    if !saw_any {
        out.push('p');
        out.push_str(&param_index.to_string());
    }
    out
}

fn is_cpp_implementation_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension == "C"
                || matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "cc" | "cpp" | "cxx"
                )
        })
}

fn cpp_params_reference_type_defs(input: &CppContextInput<'_>) -> bool {
    let mut names = Vec::new();
    for defs in input.type_defs {
        names.extend(defs.structs.iter().map(|def| def.name.as_str()));
        names.extend(defs.enums.iter().map(|def| def.name.as_str()));
        names.extend(defs.typedefs.iter().map(|def| def.name.as_str()));
    }
    if names.is_empty() {
        return false;
    }

    input
        .params
        .iter()
        .chain(input.constructor_params.iter())
        .any(|param| cpp_type_mentions_any_name(&param.cpp_type, &names))
}

fn cpp_type_mentions_any_name(cpp_type: &str, names: &[&str]) -> bool {
    cpp_type
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| names.contains(&token))
}

/// Substitute template type-parameter names with their concrete instantiation
/// arguments in a type spelling (#455 / §27.5): `const std::vector<T> &` with
/// `T -> int` becomes `const std::vector<int> &`. Replacement is WHOLE-IDENTIFIER
/// (a `T` token is replaced, the `T` inside `Tree` is not), so it never corrupts a
/// surrounding type name. Punctuation, `<`, `>`, `*`, `&`, `::`, and whitespace are
/// preserved verbatim. `subst` is positionally aligned (`template_type_params`
/// zipped with `instantiation_args`); an empty list returns the input unchanged.
fn substitute_template_type_params(cpp_type: &str, subst: &[(String, String)]) -> String {
    if subst.is_empty() {
        return cpp_type.to_owned();
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(cpp_type.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.is_empty() {
            return;
        }
        let replacement = subst
            .iter()
            .find(|(param, _)| param == token)
            .map(|(_, arg)| arg.as_str())
            .unwrap_or(token.as_str());
        out.push_str(replacement);
        token.clear();
    };
    for ch in cpp_type.chars() {
        if is_ident(ch) {
            token.push(ch);
        } else {
            flush(&mut token, &mut out);
            out.push(ch);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn stl_compat_define_added_on_windows_only() {
        let base = vec!["-DFOO".to_owned(), "-I/x".to_owned()];
        // Off Windows: flags are untouched.
        assert_eq!(cpp_compile_flags_with_stl_compat(base.clone(), false), base);
        // On Windows: the MSVC STL escape hatch is prepended.
        let win = cpp_compile_flags_with_stl_compat(base.clone(), true);
        assert_eq!(win[0], "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH");
        assert!(win.contains(&"-DFOO".to_owned()));
        // Idempotent: not duplicated if already present.
        let again = cpp_compile_flags_with_stl_compat(win.clone(), true);
        assert_eq!(
            again
                .iter()
                .filter(|f| f.as_str() == "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")
                .count(),
            1
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cppgen-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cppfunction(name: &str) -> CppFunction {
        CppFunction {
            name: name.to_owned(),
            line: 1,
            return_type: String::new(),
            params: Vec::new(),
            qualifier_path: Vec::new(),
            api: cpp_parser::CppApiMetadata::default(),
            ..Default::default()
        }
    }

    fn runtime_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap()
    }

    fn clangxx_compile_flags(prefix: &str) -> Option<Vec<String>> {
        if clangxx_probe(prefix, &[]) {
            return Some(Vec::new());
        }
        for dir in [
            "/usr/lib/gcc/x86_64-linux-gnu/14",
            "/usr/lib/gcc/x86_64-linux-gnu/13",
            "/usr/lib/gcc/x86_64-linux-gnu/12",
            "/usr/lib/gcc/x86_64-linux-gnu/11",
        ] {
            let flag = format!("--gcc-install-dir={dir}");
            if clangxx_probe(prefix, std::slice::from_ref(&flag)) {
                return Some(vec![flag]);
            }
        }
        None
    }

    fn clangxx_probe(prefix: &str, extra_flags: &[String]) -> bool {
        let dir = temp_dir(&format!("{prefix}-clangxx-probe"));
        let src = dir.join("p.cpp");
        let obj = dir.join("p.o");
        let wrote = fs::write(
            &src,
            "#include <cstdint>\n#include <cstddef>\nint f(const uint8_t *d, size_t n) { return d && n ? d[0] : 0; }\n",
        )
        .is_ok();
        let ok = wrote
            && Command::new("clang++")
                .args(extra_flags)
                .args(["-std=c++17", "-c"])
                .arg(&src)
                .arg("-o")
                .arg(&obj)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);
        let _ = fs::remove_dir_all(&dir);
        ok
    }

    #[test]
    fn generate_cpp_direct_harness_emits_main_and_makefile() {
        let out = temp_dir("cpp-emit");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("LLVMFuzzerTestOneInput"));
        // A forward declaration must precede the entrypoint definition so the
        // harness compiles under projects that promote -Wmissing-prototypes to an
        // error (harfbuzz's hb.hh does exactly this).
        assert!(
            main.contains("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);"),
            "missing -Wmissing-prototypes forward declaration:\n{main}"
        );
        assert!(main.contains("std::string input"));
        assert!(main.contains("int R = demo::parse(input);"));
        // #408: the C++ driver must carry the same govfuzz coverage runtime +
        // persistent framed fork-server main the C driver has, so the engine
        // sees non-zero coverage on C++ amalgamations (was coverage_edges=0).
        assert!(
            main.contains("__sanitizer_cov_trace_pc_guard"),
            "C++ driver missing edge-coverage runtime:\n{main}"
        );
        assert!(
            main.contains("GOVFUZZ_COV_SHM") && main.contains("GOVFUZZ_FRAMED"),
            "C++ driver missing coverage SHM / framed fork-server main:\n{main}"
        );
        assert!(
            main.find("#include \"demo.h\"") < main.find("#undef getenv")
                && main.find("#undef getenv") < main.find("getenv(\"GOVFUZZ_COV_SHM\")"),
            "target-header getenv redirects must be cleared before the coverage runtime:\n{main}"
        );
        // The sanitizer callbacks must have C linkage or name-mangling hides them
        // from the sanitizer runtime.
        assert!(
            main.contains("extern \"C\" {"),
            "C++ sanitizer runtime must be wrapped in extern \"C\":\n{main}"
        );

        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(mk.contains("ifeq ($(origin CXX), default)"));
        assert!(mk.contains("CXX = clang++"));
        assert!(mk.contains("CXX_STD ?= gnu++20"));
        assert!(mk.contains("-Wno-reserved-user-defined-literal"));
        // #408: instrument with trace-pc-guard,trace-cmp (like the C makefile) and
        // do NOT link libFuzzer's own main on the default recipe — mixing it in
        // mis-drove the binary and fabricated empty-testcase findings.
        assert!(
            mk.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"),
            "C++ default recipe missing coverage instrumentation:\n{mk}"
        );
        assert!(
            !mk.contains("-fsanitize=fuzzer,address,undefined"),
            "C++ default recipe must not link libFuzzer's main:\n{mk}"
        );
        // The FP-prone UBSan checks are subtracted so callback/vptr-heavy C++
        // libraries fuzz instead of aborting on every input under halt_on_error.
        assert!(
            mk.contains("-fsanitize=address,undefined -fno-sanitize=function,vptr,alignment"),
            "C++ default recipe must subtract FP-prone UBSan checks:\n{mk}"
        );
    }

    #[test]
    fn static_member_uses_qualified_call_without_receiver() {
        let out = temp_dir("cpp-static-member");
        let mut target = cppfunction("Parse");
        target.qualifier_path = vec!["demo".to_owned(), "Regexp".to_owned()];
        target.api.namespace_path = vec!["demo".to_owned()];
        target.api.class_name = Some("Regexp".to_owned());
        target.api.is_method = true;
        target.is_static = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STATIC".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/parse.cc"),
            target,
            params: vec![CppParameter {
                name: "text".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["regexp.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/parse.cc")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("demo::Regexp::Parse(text)"), "{main}");
        assert!(!main.contains("_gf_receiver"), "{main}");
        assert!(
            !main.contains("namespace demo::Regexp"),
            "a static method must not be redeclared as a namespace free function:\n{main}"
        );
    }

    #[test]
    fn user_defined_literal_operator_binds_length_to_buffer_size() {
        // nlohmann `operator"" _json_pointer(const char8_t *s, std::size_t n)`: by
        // [lex.ext] `n` is the literal's exact length, so it MUST bind to the
        // buffer's own char count (`Size`), not an independent fuzzed length — a
        // decoupled `n` up to 65536 made `std::string(s, n)` read past the
        // `Size`-byte `s` (ASan heap-buffer-overflow FALSE POSITIVE).
        let out = temp_dir("cpp-udl");
        let target = cppfunction("operator\"\"_json_pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UDL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/json.cpp"),
            target,
            params: vec![
                CppParameter {
                    name: "s".to_owned(),
                    cpp_type: "const char8_t *".to_owned(),
                },
                CppParameter {
                    name: "n".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/json.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // The length param tracks the buffer, never an independent fuzzed length.
        assert!(
            main.contains("std::size_t n = (std::size_t)Size"),
            "UDL length must bind to Size, not a decoupled fuzzed length:\n{main}"
        );
        assert!(
            !main.contains("gf_bounded_length(&Cur, 0, 65536)"),
            "UDL length must NOT be an independent bounded fuzz length:\n{main}"
        );
        // `s` is still a NUL-terminated copy of the input (safe for both
        // `string(s, n)` and a C-string `string(s)`).
        assert!(
            main.contains("char8_t * s = (const char8_t *)malloc")
                || main.contains("char8_t * s = (char8_t *)malloc"),
            "UDL char buffer must be a NUL-terminated heap copy:\n{main}"
        );
    }

    #[test]
    fn qualified_namespace_free_function_emits_forward_declaration() {
        // A free function in a C++ namespace, discovered from a header-less `.cpp`
        // (no project header declares it), must get a namespace-qualified forward
        // declaration so the qualified call resolves the identifier. Regression for
        // the `use of undeclared identifier 'UtilitiesLib'` codegen bug.
        let out = temp_dir("cpp-qual-ns");
        let mut target = cppfunction("Extract_Minutes");
        target.qualifier_path = vec!["UtilitiesLib".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-QNS001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/util.cpp"),
            target,
            params: vec![
                CppParameter {
                    name: "g".to_owned(),
                    cpp_type: "char *".to_owned(),
                },
                CppParameter {
                    name: "s".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "l".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "e".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "m".to_owned(),
                    cpp_type: "double *".to_owned(),
                },
            ],
            return_type: "long".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/util.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            src.contains("namespace UtilitiesLib"),
            "expected ns forward decl:\n{src}"
        );
        assert!(
            src.contains("Extract_Minutes("),
            "forward decl names the fn:\n{src}"
        );
        assert!(
            src.contains("UtilitiesLib::Extract_Minutes("),
            "still calls the qualified name:\n{src}"
        );
    }

    #[test]
    fn qualified_namespace_free_function_with_header_still_emits_forward_declaration() {
        // A namespace-qualified free function gets its forward declaration EVEN
        // when a project header is in scope: the auto-included header (e.g. an MFC
        // `StdAfx.h`) frequently does not declare THIS symbol, and without the decl
        // the qualified call is `use of undeclared identifier` (the reported
        // `UtilitiesLib` bug). A namespace-scoped redeclaration matching the real
        // one is legal C++, so the redundant decl is harmless when the header does
        // declare it.
        let out = temp_dir("cpp-qual-ns-hdr");
        let mut target = cppfunction("Extract_Minutes");
        target.qualifier_path = vec!["UtilitiesLib".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-QNS002".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/util.cpp"),
            target,
            params: vec![CppParameter {
                name: "s".to_owned(),
                cpp_type: "long".to_owned(),
            }],
            return_type: "long".to_owned(),
            target_includes: vec!["util.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/util.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            src.contains("namespace UtilitiesLib {"),
            "a namespaced free fn must get a forward decl even with a header in scope:\n{src}"
        );
        assert!(
            src.contains("UtilitiesLib::Extract_Minutes("),
            "still calls the qualified name:\n{src}"
        );
    }

    #[test]
    fn cpp_parameter_type_supported_accepts_floating_point_scalars() {
        // §26.6: by-value `float`/`double` are decodable scalars — the C++
        // lifecycle-step gate (`cpp_parameter_type_supported`) used to reject them,
        // so tinyxml2's `DoubleAttribute(double)`/`FloatAttribute(float)` were
        // skipped "unsupported parameter type 'double'/'float'". They must now be
        // accepted like every other scalar. (By-reference scalars are a separate,
        // pre-existing limitation shared with `const int &`, out of scope here.)
        for ty in ["float", "double", "long double"] {
            assert!(
                cpp_parameter_type_supported(ty),
                "C++ float/double param '{ty}' must be supported (§26.6)"
            );
        }
    }

    #[test]
    fn cpp_parameter_type_supported_accepts_const_qualified_by_value_scalars() {
        // Campaign: taocpp-json skipped lifecycle steps whose params were
        // `const bool`/`const double`/`const int`/... — a top-level const on a
        // BY-VALUE scalar is irrelevant to the caller and must decode like the
        // bare type. The lifecycle-step / direct gate (`cpp_parameter_type_
        // supported`) must now accept them. (Const-references like `const int &`
        // are a separate, pre-existing limitation, out of scope.)
        for ty in [
            "const bool",
            "const double",
            "const float",
            "const int",
            "const unsigned",
            "const long",
            "const std::size_t",
            "const std::uint32_t",
            "bool const",
            "volatile int",
        ] {
            assert!(
                cpp_parameter_type_supported(ty),
                "C++ const-qualified by-value scalar '{ty}' must be supported"
            );
        }
    }

    #[test]
    fn substitute_template_type_params_replaces_whole_identifiers_only() {
        let subst = vec![("T".to_owned(), "int".to_owned())];
        assert_eq!(substitute_template_type_params("T", &subst), "int");
        assert_eq!(
            substitute_template_type_params("const std::vector<T> &", &subst),
            "const std::vector<int> &"
        );
        // `T` inside another identifier (`Tree`, `myT`) must NOT be replaced.
        assert_eq!(substitute_template_type_params("Tree", &subst), "Tree");
        assert_eq!(
            substitute_template_type_params("std::pair<T, T>", &subst),
            "std::pair<int, int>"
        );
        // Multiple params.
        let multi = vec![
            ("K".to_owned(), "std::string".to_owned()),
            ("V".to_owned(), "double".to_owned()),
        ];
        assert_eq!(
            substitute_template_type_params("std::map<K, V>", &multi),
            "std::map<std::string, double>"
        );
        // Empty subst is a no-op.
        assert_eq!(substitute_template_type_params("T", &[]), "T");
    }

    #[test]
    fn generate_cpp_direct_harness_instantiates_template_with_turbofish() {
        // #455 / §27.5: a templated free function with a resolved specialization
        // emits a turbofish call and substitutes the type arg into the decoded
        // parameter / result types.
        let out = temp_dir("cpp-template");
        let mut target = cppfunction("convert");
        target.api.is_template = true;
        target.api.api_kind = "template_function".to_owned();
        target.template_type_params = vec!["T".to_owned()];
        target.instantiation_args = vec!["int".to_owned()];
        target.return_type = "T".to_owned();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPTPL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/convert.hpp"),
            target,
            params: vec![CppParameter {
                name: "data".to_owned(),
                cpp_type: "const std::vector<T> &".to_owned(),
            }],
            return_type: "T".to_owned(),
            target_includes: vec!["convert.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("convert<int>(data)"),
            "expected a turbofish call:\n{main}"
        );
        // The result variable's `T` is specialised to `int`.
        assert!(
            main.contains("int R = convert<int>(data)"),
            "expected substituted result type:\n{main}"
        );
        // The decoded parameter's `T` is specialised to `int`.
        assert!(
            main.contains("std::vector<int>"),
            "expected substituted parameter type:\n{main}"
        );
    }

    #[test]
    fn return_type_macro_shaped_token_detection() {
        // Multi-segment all-caps decoration macros are detected (so the emitter can
        // fall back to `auto`); single-word real all-caps types and ordinary
        // lower/mixed-case types are NOT, and so keep their explicit result type.
        assert!(return_type_has_macro_shaped_token(
            "FOO_EXTERNAL_LINKAGE parse_result"
        ));
        assert!(return_type_has_macro_shaped_token(
            "parse_result FOO_CALLCONV"
        ));
        assert!(return_type_has_macro_shaped_token("TOML_CALLCONV"));
        assert!(!return_type_has_macro_shaped_token("parse_result"));
        assert!(!return_type_has_macro_shaped_token("int"));
        assert!(!return_type_has_macro_shaped_token("const char *"));
        assert!(!return_type_has_macro_shaped_token("std::string"));
        assert!(!return_type_has_macro_shaped_token("uint32_t"));
        // Single-word real all-caps types have no underscore, so they are kept.
        assert!(!return_type_has_macro_shaped_token("DWORD"));
        assert!(!return_type_has_macro_shaped_token("BYTE"));
    }

    #[test]
    fn cpp_result_var_falls_back_to_auto_for_unexpanded_decoration_macro() {
        // A library decoration macro the parser + c-decoration strippers both miss
        // (toml++ wraps results in `..._EXTERNAL_LINKAGE` / `..._CALLCONV`) would
        // otherwise leak into the result-variable TYPE — and the header `#undef`s it,
        // so `<ret> R = call();` won't compile. The emitter falls back to
        // `auto R = call();`, which deduces the real type and always compiles.
        let out = temp_dir("cpp-auto-fallback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPAUTO".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/toml.hpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "doc".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "FOO_EXTERNAL_LINKAGE parse_result".to_owned(),
            target_includes: vec!["toml.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("auto R = parse("),
            "expected `auto` result-var fallback:\n{main}"
        );
        assert!(
            !main.contains("EXTERNAL_LINKAGE"),
            "the unexpanded decoration macro must not leak into the result var:\n{main}"
        );
    }

    #[test]
    fn cpp_result_var_strips_constexpr_macro_return_qualifier() {
        // utf8.h declares `utf8_constexpr14_impl int utf8cmp(...)` where the macro
        // expands to `constexpr` under C++14. The harness does not preprocess the
        // header, so the literal token `utf8_constexpr14_impl` reaches codegen as a
        // leading return-type qualifier. Emitting `utf8_constexpr14_impl int R =
        // <runtime call>;` is rejected ("constexpr variable 'R' must be initialized
        // by a constant expression"). The qualifier must be stripped from the
        // result-variable type, leaving the bare `int`.
        let out = temp_dir("cpp-constexpr-macro");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPCE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/utf8.h"),
            target: cppfunction("utf8cmp"),
            params: vec![CppParameter {
                name: "src1".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "utf8_constexpr14_impl int".to_owned(),
            target_includes: vec!["utf8.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("int R = utf8cmp("),
            "result var must declare the bare `int` type:\n{main}"
        );
        assert!(
            !main.contains("constexpr"),
            "constexpr-expanding macro qualifier must be stripped from result var:\n{main}"
        );
    }

    #[test]
    fn cpp_result_var_keeps_const_pointee_return_type() {
        // Regression guard: `const char *` is a const *pointee*, not an illegal
        // local-var specifier. `const char * R = call();` is perfectly legal and the
        // const must NOT be stripped (doing so would make assigning a `const char *`
        // return into a `char *` local ill-formed).
        let out = temp_dir("cpp-const-pointee");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPCP".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("name_of"),
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "const char *".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("const char * R = name_of(") || main.contains("const char *R = name_of("),
            "const pointee return type must be preserved verbatim:\n{main}"
        );
    }

    #[test]
    fn cpp_project_include_dirs_use_iquote_so_system_headers_win() {
        // #366 (C++ mirror): project include dirs must be -iquote (not -I or
        // -isystem) so a vendored header (capnproto's C++ endian.h) cannot
        // shadow a system header of the same name pulled in via angle include.
        let out = temp_dir("cpp-iquote");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPISYS".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/proj/inc")],
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/rt"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(
            mk.contains("-iquote /proj/inc"),
            "project include dirs must be passed as -iquote: {mk}"
        );
        assert!(
            mk.contains("-idirafter /proj/inc"),
            "project include dirs must ALSO be -idirafter so angled self-includes resolve: {mk}"
        );
        assert!(
            !mk.contains("-I /proj/inc"),
            "project include dirs must NOT be passed as -I: {mk}"
        );
        assert!(
            !mk.contains("-isystem /proj/inc"),
            "-isystem does not prevent shadowing; must be -iquote: {mk}"
        );
        assert!(mk.contains("-I ."), "harness cwd must stay -I .: {mk}");
        assert!(
            mk.contains("-I /rt"),
            "c_runtime include must stay -I: {mk}"
        );
    }

    #[test]
    fn constructor_target_is_direct_initialized_not_called_as_a_method() {
        // A constructor target (capnp `Text::Reader::Reader`) must be emitted as
        // direct-initialization `Text::Reader _gf_receiver(args);`, NOT as a member
        // call `_gf_receiver.Reader(args)` — naming a constructor as a member is
        // illegal C++ ("invalid use of 'capnp::Text::Reader::Reader'").
        let out = temp_dir("cpp-ctor-target");
        let mut target = cppfunction("Reader");
        target.qualifier_path = vec!["capnp".to_owned(), "Text".to_owned(), "Reader".to_owned()];
        target.api.is_method = true;
        target.api.is_constructor = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CTOR01".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/text.h"),
            target,
            params: vec![CppParameter {
                name: "n".to_owned(),
                cpp_type: "std::uint32_t".to_owned(),
            }],
            return_type: String::new(),
            target_includes: vec!["capnp/text.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("capnp::Text::Reader _gf_receiver(n);"),
            "constructor target must be direct-initialized:\n{main}"
        );
        assert!(
            !main.contains("_gf_receiver.Reader("),
            "constructor must not be called as a member function:\n{main}"
        );
    }

    #[test]
    fn generate_cpp_sequence_harness_constructs_receiver_from_decoded_constructor_params() {
        let out = temp_dir("cpp-sequence-ctor");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["gov".to_owned(), "Parser".to_owned()];
        target.api.class_name = Some("Parser".to_owned());
        target.api.namespace_path = vec!["gov".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-CTOR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/parser.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "std::string_view".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/parser.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: vec![CppParameter {
                name: "seed".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            lifecycle_steps: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        assert!(main.contains("std::string _gf_ctor_seed"));
        assert!(main.contains("gov::Parser _gf_receiver(_gf_ctor_seed);"));
        assert!(main.contains("_gf_receiver.parse(input);"));
    }

    #[test]
    fn generate_cpp_direct_harness_substitutes_abstract_receiver_with_subclass() {
        // #456: an abstract declaring class is replaced by the caller-resolved
        // concrete subclass for the receiver, so the virtual method dispatches
        // polymorphically (`MemoryReader::read`).
        let out = temp_dir("cpp-abstract-subclass");
        let mut target = cppfunction("read");
        target.qualifier_path = vec!["e57".to_owned(), "Reader".to_owned()];
        target.api.class_name = Some("Reader".to_owned());
        target.api.namespace_path = vec!["e57".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-ABS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/reader.cpp"),
            target,
            params: vec![CppParameter {
                name: "n".to_owned(),
                cpp_type: "int".to_owned(),
            }],
            return_type: "void".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/reader.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: Some("e57::MemoryReader".to_owned()),
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // The receiver is the concrete subclass, not the abstract base.
        assert!(main.contains("e57::MemoryReader _gf_receiver"), "{main}");
        assert!(!main.contains("e57::Reader _gf_receiver"), "{main}");
        // The virtual method is still called on the receiver.
        assert!(main.contains("_gf_receiver.read("), "{main}");
    }

    #[test]
    fn generate_cpp_direct_harness_makefile_includes_afl_target() {
        let out = temp_dir("cpp-emit-afl");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-AFL".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        assert!(main.contains("static int govfuzz_run_one"));
        assert!(main.contains("#if defined(GOVFUZZ_AFL)"));
        assert!(main.contains("__AFL_LOOP(10000)"));
        assert!(main.contains("#else"));
        assert!(main.contains("int LLVMFuzzerTestOneInput"));
        assert!(makefile.contains("ifeq ($(origin CXX), default)"));
        assert!(makefile.contains("CXX = clang++"));
        assert!(makefile.contains(".PHONY: all afl diff clean"));
        assert!(makefile.contains("AFLPP_CXX ?= afl-clang-fast++"));
        assert!(makefile.contains("afl: main_afl"));
        // The two-compiler differential build target.
        assert!(makefile.contains("diff: main_diff"));
        assert!(makefile.contains("DIFF_CXX ?= clang++"));
        // The afl target is declared; target sources live in the recipe, not the
        // prerequisites (an absolute Windows source path carries a drive-letter
        // colon that GNU make would parse as a target:prereq separator).
        assert!(makefile.contains("main_afl: main.cpp"));
        // …and the afl recipe still compiles the target source alongside main.cpp.
        assert!(makefile.contains("-o $@ main.cpp /tmp/source.cpp"));
        assert!(makefile.contains("$(AFLPP_CXX) $(AFLPP_CXXFLAGS)"));
        assert!(makefile.contains("-DGOVFUZZ_AFL"));
        assert!(
            makefile.contains("SECTION_FLAGS ?= -ffunction-sections -fdata-sections")
                && makefile.contains("SECTION_LDFLAGS ?= -Wl,--gc-sections"),
            "C++ harnesses must discard unreachable dependency sections:\n{makefile}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_uint8() {
        let out = temp_dir("cpp-emit-vec");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP002".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("decode"),
            params: vec![CppParameter {
                name: "buf".to_owned(),
                cpp_type: "const std::vector<uint8_t> &".to_owned(),
            }],
            return_type: "void".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<uint8_t> buf(Data, Data + Size)"));
        assert!(
            !main.contains("R = decode"),
            "void return should not bind R"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_string() {
        let out = temp_dir("cpp-emit-vector-string");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP010".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse_args"),
            params: vec![CppParameter {
                name: "tokens".to_owned(),
                cpp_type: "const std::vector<std::string> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<std::string> tokens;"));
        assert!(main.contains("parse_args(tokens);"));
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_of_supported_values() {
        let out = temp_dir("cpp-emit-vector-scalar");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VECTOR-SCALAR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::vector<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<std::uint32_t> items;"));
        assert!(main.contains("items.emplace_back(_gf_vector_items_elt)"));
        assert!(main.contains("parse(items);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_deque_and_list() {
        let out = temp_dir("cpp-emit-sequence-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SEQUENCE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "items".to_owned(),
                    cpp_type: "const std::deque<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "views".to_owned(),
                    cpp_type: "const std::list<std::string_view> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <deque>"));
        assert!(main.contains("#include <list>"));
        assert!(main.contains("std::deque<std::uint32_t> items;"));
        assert!(main.contains("std::list<std::string_view> views;"));
        assert!(main.contains("parse(items, views);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_forward_list() {
        let out = temp_dir("cpp-emit-forward-list");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FORWARD-LIST".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::forward_list<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <forward_list>"));
        assert!(main.contains("std::forward_list<std::uint32_t> items;"));
        assert!(main.contains("items.emplace_front(_gf_forward_list_items_elt)"));
        assert!(main.contains("parse(items);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_set_and_map() {
        let out = temp_dir("cpp-emit-associative-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ASSOCIATIVE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "ids".to_owned(),
                    cpp_type: "const std::set<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "lookup".to_owned(),
                    cpp_type: "const std::map<std::string_view, std::uint32_t> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <map>"));
        assert!(main.contains("#include <set>"));
        assert!(main.contains("std::set<std::uint32_t> ids;"));
        assert!(main.contains("std::map<std::string_view, std::uint32_t> lookup;"));
        assert!(main.contains("lookup.emplace(_gf_map_lookup_key, _gf_map_lookup_value)"));
        assert!(main.contains("parse(ids, lookup);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_unordered_set_and_map() {
        let out = temp_dir("cpp-emit-unordered-associative-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UNORDERED-ASSOCIATIVE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "ids".to_owned(),
                    cpp_type: "const std::unordered_set<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "lookup".to_owned(),
                    cpp_type: "const std::unordered_map<std::string_view, std::uint32_t> &"
                        .to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <unordered_map>"));
        assert!(main.contains("#include <unordered_set>"));
        assert!(main.contains("std::unordered_set<std::uint32_t> ids;"));
        assert!(main.contains("std::unordered_map<std::string_view, std::uint32_t> lookup;"));
        assert!(main.contains(
            "lookup.emplace(_gf_unordered_map_lookup_key, _gf_unordered_map_lookup_value)"
        ));
        assert!(main.contains("parse(ids, lookup);"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_cpp_struct_by_value_with_registry() {
        let out = temp_dir("cpp-emit-struct-by-value");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STRUCT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("consume"),
            params: vec![CppParameter {
                name: "cfg".to_owned(),
                cpp_type: "Config".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["api.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![
                        c_parser::CParamDescriptor {
                            name: "mode".to_owned(),
                            c_type: "int".to_owned(),
                        },
                        c_parser::CParamDescriptor {
                            name: "enabled".to_owned(),
                            c_type: "bool".to_owned(),
                        },
                        c_parser::CParamDescriptor {
                            name: "code".to_owned(),
                            c_type: "std::uint16_t".to_owned(),
                        },
                    ],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // C++ value-initializes the aggregate (`Config cfg{};`) rather than
        // declaring + memset-zeroing it — memset on a non-trivial class is UB.
        assert!(main.contains("Config cfg{}"));
        assert!(
            !main.contains("memset(&cfg"),
            "C++ struct must be value-initialized, not memset:\n{main}"
        );
        assert!(main.contains("cfg.mode = gf_i32(&Cur)"));
        assert!(main.contains("cfg.enabled = (bool)(gf_u8(&Cur) & 1)"));
        assert!(main.contains("cfg.code = (std::uint16_t)gf_bounded_i32(&Cur, 0, 0xffff)"));
        assert!(main.contains("consume(cfg);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_source_for_source_only_aggregate_reference() {
        let out = temp_dir("cpp-emit-struct-ref");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STRUCT-REF".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("consume"),
            params: vec![CppParameter {
                name: "cfg".to_owned(),
                cpp_type: "const Config &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include \"x.cpp\""));
        assert!(!main.contains("int consume("));
        assert!(main.contains("Config cfg"));
        assert!(main.contains("cfg.mode = gf_i32(&Cur)"));
        assert!(main.contains("consume(cfg);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_drives_file_pointer_with_fmemopen() {
        let work = temp_dir("cpp-emit-file-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FILE".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse_stream"),
            params: vec![CppParameter {
                name: "stream".to_owned(),
                cpp_type: "FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <stdio.h>"));
        assert!(main.contains("fmemopen(_gf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("Size ? fmemopen"));
        assert!(main.contains(": tmpfile()"));
        assert!(main.contains("int R = parse_stream(stream);"));
        assert!(main.contains("if (stream) fclose(stream); free(_gf_file_buf_stream);"));

        let Some(cxx_flags) = clangxx_compile_flags("cppgen-file-pointer") else {
            eprintln!(
                "skipping generated C++ FILE* harness compile: clang++ C++ headers unavailable"
            );
            return;
        };
        let obj = work.join("file_main.o");
        let output = Command::new("clang++")
            .args(&cxx_flags)
            .arg("-std=c++17")
            .arg("-I")
            .arg(runtime_dir())
            .arg("-c")
            .arg(&result.main_cpp)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang++");
        assert!(
            output.status.success(),
            "clang++ failed\nstdout:\n{}\nstderr:\n{}\nmain.cpp:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn generate_cpp_direct_harness_drives_std_file_pointer_with_fmemopen() {
        let work = temp_dir("cpp-emit-std-file-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STD-FILE".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse_stream"),
            params: vec![CppParameter {
                name: "stream".to_owned(),
                cpp_type: "std::FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("fmemopen(_gf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("parse_stream(stream);"));
        assert!(main.contains("if (stream) fclose(stream); free(_gf_file_buf_stream);"));
    }

    #[test]
    fn generate_cpp_direct_harness_emits_callback_trampoline_for_typedef() {
        let out = temp_dir("cpp-emit-callback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-CB".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("visit"),
            params: vec![CppParameter {
                name: "cb".to_owned(),
                cpp_type: "visit_cb".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["api.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                typedefs: vec![c_parser::CTypedefDef {
                    name: "visit_cb".to_owned(),
                    underlying: "int (*)(void *opaque, const char *name)".to_owned(),
                    line: 1,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("static int _gf_cb_trampoline(void *opaque, const char *name)"));
        assert!(main.contains("visit_cb cb = (visit_cb)_gf_cb_trampoline;"));
        assert!(main.contains("int R = visit(cb);"));
    }

    #[test]
    fn generate_cpp_direct_harness_emits_std_function_callback() {
        let out = temp_dir("cpp-emit-std-function-callback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STDFUNC".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("walk"),
            params: vec![CppParameter {
                name: "cb".to_owned(),
                cpp_type: "const std::function<int(std::string_view)> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <functional>"));
        assert!(main.contains(
            "std::function<int(std::string_view)> cb = [](std::string_view _gf_cb_arg0) -> int"
        ));
        assert!(main.contains("(void)_gf_cb_arg0;"));
        assert!(main.contains("return {};"));
        assert!(main.contains("int R = walk(cb);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_array_for_fixed_array() {
        let out = temp_dir("cpp-emit-array");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP009".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "key".to_owned(),
                cpp_type: "const std::array<std::byte, 16> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("std::array<std::byte, 16> key{}"));
        assert!(main.contains("parse(key);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_array_for_supported_values() {
        let out = temp_dir("cpp-emit-array-values");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ARRAY-VALUES".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "values".to_owned(),
                cpp_type: "const std::array<std::uint32_t, 4> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("std::array<std::uint32_t, 4> values{}"));
        assert!(main.contains("values[_gf_i_values] = _gf_array_values_elt"));
        assert!(main.contains("parse(values);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_bitset_for_bitset() {
        let out = temp_dir("cpp-emit-bitset");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-BITSET".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "flags".to_owned(),
                cpp_type: "const std::bitset<32> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <bitset>"));
        assert!(main.contains("std::bitset<32> flags"));
        assert!(main.contains("flags.set(_gf_i_flags"));
        assert!(main.contains("parse(flags);"));
    }

    #[test]
    fn cpp_buffer_pairing_requires_name_evidence() {
        let reg = type_model::TypeRegistry::default();
        let decls = |params: &[(&str, &str)]| -> String {
            let p: Vec<CppParameter> = params
                .iter()
                .map(|(n, t)| CppParameter {
                    name: (*n).to_owned(),
                    cpp_type: (*t).to_owned(),
                })
                .collect();
            build_cpp_param_decoders(&p, &reg, &[], &CppDecoderLimits::default(), false, false)
                .unwrap()
                .iter()
                .map(|e| e.decl.clone())
                .collect::<Vec<_>>()
                .join(" ; ")
        };
        // pugixml load_file(const char *path_, unsigned int options): neither name
        // is buffer- nor length-shaped, so it must NOT pair (binding path_ to the
        // raw non-NUL Data span was a heap-buffer-overflow FALSE POSITIVE).
        let nogate = decls(&[("path_", "const char *"), ("options", "unsigned int")]);
        assert!(
            !nogate.contains("path_ = (const char *)Data"),
            "path_/options must not be mis-paired as (buffer, length): {nogate}"
        );
        // A genuine (const char *data, size_t len) pair still binds to (Data, Size).
        let paired = decls(&[("data", "const char *"), ("len", "size_t")]);
        assert!(
            paired.contains(")Data") && paired.contains(")Size"),
            "data/len must still pair to (Data, Size): {paired}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_pairs_standard_byte_pointer_and_length() {
        for (name, cpp_type, expected_decl) in [
            (
                "std-uint8",
                "const std::uint8_t *",
                "const std::uint8_t * data = (const std::uint8_t *)Data",
            ),
            (
                "std-byte",
                "const std::byte *",
                "const std::byte * data = (const std::byte *)Data",
            ),
        ] {
            let out = temp_dir(name);
            let args = GenerateCppDirectArgs {
                decoder_limits: Default::default(),
                force: false,
                harness_id: "H-CPP004".to_owned(),
                output_dir: out,
                source_path: PathBuf::from("/tmp/x.cpp"),
                target: cppfunction("parse"),
                params: vec![
                    CppParameter {
                        name: "data".to_owned(),
                        cpp_type: cpp_type.to_owned(),
                    },
                    CppParameter {
                        name: "len".to_owned(),
                        cpp_type: "std::size_t".to_owned(),
                    },
                ],
                return_type: "int".to_owned(),
                target_includes: Vec::new(),
                target_includes_dirs: Vec::new(),
                target_sources: Vec::new(),
                compile_flags: Vec::new(),
                c_runtime_include: PathBuf::from("/tmp/c_runtime"),
                using_namespaces: Vec::new(),
                result_cleanup: None,
                constructor_params: Vec::new(),
                type_defs: Vec::new(),
                default_constructible_classes: Vec::new(),
                receiver_class_override: None,
                factory_plan: None,
            };

            let result = generate_cpp_direct_harness(args).unwrap();
            let main = fs::read_to_string(&result.main_cpp).unwrap();
            assert!(
                main.contains(expected_decl),
                "expected {cpp_type} pointer to borrow Data, got:\n{main}"
            );
            assert!(
                main.contains("std::size_t len = (std::size_t)Size"),
                "expected std::size_t length to mirror Size, got:\n{main}"
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_output_capacity_does_not_consume_input_pair() {
        let out = temp_dir("cpp-emit-output-capacity");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OUT-CAP".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("compress_mem_to_mem"),
            params: vec![
                CppParameter {
                    name: "pOut_buf".to_owned(),
                    cpp_type: "void *".to_owned(),
                },
                CppParameter {
                    name: "out_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
                CppParameter {
                    name: "pSrc_buf".to_owned(),
                    cpp_type: "const void *".to_owned(),
                },
                CppParameter {
                    name: "src_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "std::size_t".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("void * pOut_buf = (void *)malloc"));
        assert!(main.contains("std::size_t out_buf_len = (std::size_t)_gf_cap_pOut_buf"));
        assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
        assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
        assert!(
            !main.contains("src_buf_len = gf_bounded_length"),
            "input length must stay coherent with Data:\n{main}"
        );
        assert!(main.contains("free(pOut_buf)"));
    }

    #[test]
    fn generate_cpp_direct_harness_output_length_pointer_does_not_consume_input_pair() {
        let out = temp_dir("cpp-emit-output-length-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OUT-LEN".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("compress_mem_to_heap"),
            params: vec![
                CppParameter {
                    name: "pOut_buf".to_owned(),
                    cpp_type: "void *".to_owned(),
                },
                CppParameter {
                    name: "pOut_len".to_owned(),
                    cpp_type: "std::size_t *".to_owned(),
                },
                CppParameter {
                    name: "pSrc_buf".to_owned(),
                    cpp_type: "const void *".to_owned(),
                },
                CppParameter {
                    name: "src_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "bool".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("void * pOut_buf = (void *)malloc"));
        assert!(main.contains("std::size_t _gf_out_pOut_len = (std::size_t)_gf_cap_pOut_buf"));
        assert!(main.contains("std::size_t *pOut_len = &_gf_out_pOut_len"));
        assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
        assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
        assert!(
            !main.contains("src_buf_len = gf_bounded_length"),
            "input length must stay coherent with Data:\n{main}"
        );
        assert!(main.contains("free(pOut_buf)"));
    }

    #[test]
    fn generate_cpp_direct_harness_uses_cpp20_for_span_params() {
        let out = temp_dir("cpp-emit-span");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP005".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "bytes".to_owned(),
                cpp_type: "std::span<const std::byte>".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("std::span<const std::byte> bytes("));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_uses_cpp20_for_mutable_span_params() {
        let out = temp_dir("cpp-emit-mutable-span");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP008".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "bytes".to_owned(),
                cpp_type: "std::span<std::byte>".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("std::vector<std::byte> _gf_span_storage_bytes("));
        assert!(main.contains("std::span<std::byte> bytes(_gf_span_storage_bytes.data(), _gf_span_storage_bytes.size())"));
        assert!(main.contains("parse(bytes);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_optional_for_optional_string() {
        let out = temp_dir("cpp-emit-optional-string");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP006".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe".to_owned(),
                cpp_type: "const std::optional<std::string> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("std::optional<std::string> maybe"));
        assert!(main.contains("parse(maybe);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_optional_for_optional_scalar() {
        let out = temp_dir("cpp-emit-optional-scalar");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OPT-SCALAR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe_count".to_owned(),
                cpp_type: "const std::optional<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("std::optional<std::uint32_t> maybe_count"));
        assert!(main.contains("maybe_count.emplace(_gf_optional_maybe_count)"));
        assert!(main.contains("parse(maybe_count);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_optional_visible_aggregate() {
        let out = temp_dir("cpp-emit-optional-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OPT-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe".to_owned(),
                cpp_type: "const std::optional<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::optional<Config> maybe"));
        assert!(main.contains("_gf_optional_maybe.mode = gf_i32(&Cur)"));
        assert!(main.contains("parse(maybe);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_vector_visible_aggregate() {
        let out = temp_dir("cpp-emit-vector-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VEC-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::vector<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <vector>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::vector<Config> items;"));
        assert!(main.contains("_gf_vector_items_elt.mode = gf_i32(&Cur)"));
        assert!(main.contains("items.emplace_back(_gf_vector_items_elt)"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_array_visible_aggregate() {
        let out = temp_dir("cpp-emit-array-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ARRAY-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::array<Config, 2> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::array<Config, 2> items{}"));
        assert!(main.contains("_gf_array_items_elt.mode = gf_i32(&Cur)"));
        assert!(main.contains("items[_gf_i_items] = _gf_array_items_elt"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_forward_list_visible_aggregate() {
        let out = temp_dir("cpp-emit-forward-list-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FLIST-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::forward_list<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <forward_list>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::forward_list<Config> items;"));
        assert!(main.contains("_gf_forward_list_items_elt.mode = gf_i32(&Cur)"));
        assert!(main.contains("items.emplace_front(_gf_forward_list_items_elt)"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_variant_visible_aggregate() {
        let out = temp_dir("cpp-emit-variant-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<Config, std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::variant<Config, std::uint32_t> choice"));
        assert!(main.contains("_gf_variant_choice_0.mode = gf_i32(&Cur)"));
        assert!(main.contains(
            "std::variant<Config, std::uint32_t>(std::in_place_index<0>, _gf_variant_choice_0)"
        ));
        assert!(main.contains("parse(choice);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_unordered_map_visible_aggregate_value() {
        let out = temp_dir("cpp-emit-unordered-map-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UMAP-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "lookup".to_owned(),
                cpp_type: "const std::unordered_map<std::string, Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <unordered_map>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::unordered_map<std::string, Config> lookup;"));
        assert!(main.contains("_gf_unordered_map_lookup_value.mode = gf_i32(&Cur)"));
        assert!(main.contains(
            "lookup.emplace(_gf_unordered_map_lookup_key, _gf_unordered_map_lookup_value)"
        ));
        assert!(main.contains("parse(lookup);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_span_visible_aggregate() {
        let out = temp_dir("cpp-emit-span-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SPAN-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::span<const Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::vector<Config> _gf_span_storage_items;"));
        assert!(main.contains("_gf_span_items_elt.mode = gf_i32(&Cur)"));
        assert!(main.contains(
            "std::span<const Config> items(_gf_span_storage_items.data(), _gf_span_storage_items.size())"
        ));
        assert!(main.contains("parse(items);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_memory_for_smart_pointers() {
        let out = temp_dir("cpp-emit-smart-pointers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SMART-PTR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "owned".to_owned(),
                    cpp_type: "std::unique_ptr<std::uint32_t>".to_owned(),
                },
                CppParameter {
                    name: "shared".to_owned(),
                    cpp_type: "const std::shared_ptr<std::string> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <memory>"));
        assert!(main.contains("#include <utility>"));
        assert!(main.contains("std::unique_ptr<std::uint32_t> owned = std::make_unique"));
        assert!(main.contains("std::shared_ptr<std::string> shared = std::make_shared"));
        assert!(main.contains("parse(std::move(owned), shared);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_utility_for_pair() {
        let out = temp_dir("cpp-emit-pair");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-PAIR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "entry".to_owned(),
                cpp_type: "const std::pair<std::uint32_t, std::string_view> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <utility>"));
        assert!(main.contains("std::pair<std::uint32_t, std::string_view> entry"));
        assert!(main.contains("parse(entry);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_tuple_for_tuple() {
        let out = temp_dir("cpp-emit-tuple");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-TUPLE".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "entry".to_owned(),
                cpp_type: "const std::tuple<std::uint32_t, std::string_view, bool> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <tuple>"));
        assert!(main.contains("std::tuple<std::uint32_t, std::string_view, bool> entry"));
        assert!(main.contains("parse(entry);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_variant_for_variant() {
        let out = temp_dir("cpp-emit-variant");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<std::uint32_t, std::string_view, bool> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("std::variant<std::uint32_t, std::string_view, bool> choice"));
        assert!(main.contains("std::in_place_index<1>"));
        assert!(main.contains("parse(choice);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_variant_monostate_alternative() {
        let out = temp_dir("cpp-emit-variant-monostate");
        let runtime = runtime_dir();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT-MONOSTATE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<std::monostate, std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("std::variant<std::monostate, std::uint32_t> choice"));
        assert!(main.contains("std::monostate _gf_variant_choice_0{}"));
        assert!(main.contains("std::in_place_index<0>"));
        assert!(main.contains("parse(choice);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-variant-monostate") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_enum_class_param() {
        let out = temp_dir("cpp-emit-enum-class");
        let runtime = runtime_dir();
        let header_text = r#"
            enum class Mode { Fast, Safe };
            int parse(Mode mode);
        "#;
        fs::write(out.join("mode.hpp"), header_text).unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("mode.hpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["mode.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(header_text).unwrap()],
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("Mode mode = (Mode)Mode::Fast"));
        assert!(main.contains("case 1: mode = (Mode)Mode::Safe; break"));
        assert!(main.contains("parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_source_only_namespaced_enum_class_param() {
        let out = temp_dir("cpp-emit-namespaced-enum-class");
        let runtime = runtime_dir();
        let source_text = r#"
            namespace gov {
            enum class Mode { Fast, Safe };
            int parse(Mode mode) { return mode == Mode::Fast ? 1 : 0; }
            }
        "#;
        fs::write(out.join("parser.cpp"), source_text).unwrap();
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["gov".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-NS-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("parser.cpp"),
            target,
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(source_text).unwrap()],
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("using namespace gov;"));
        assert!(main.contains("Mode mode = (Mode)Mode::Fast"));
        assert!(main.contains("gov::parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-ns-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_qualified_namespaced_enum_class_param() {
        let out = temp_dir("cpp-emit-qualified-enum-class");
        let runtime = runtime_dir();
        let source_text = r#"
            namespace gov {
            enum class Mode { Fast, Safe };
            }
            int parse(gov::Mode mode) { return mode == gov::Mode::Fast ? 1 : 0; }
        "#;
        fs::write(out.join("parser.cpp"), source_text).unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-QUAL-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("parser.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "gov::Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(source_text).unwrap()],
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("gov::Mode mode = (gov::Mode)gov::Mode::Fast"));
        assert!(main.contains("case 1: mode = (gov::Mode)gov::Mode::Safe; break"));
        assert!(main.contains("parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-qualified-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_includes_filesystem_for_path() {
        let out = temp_dir("cpp-emit-filesystem-path");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP007".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("load"),
            params: vec![CppParameter {
                name: "path".to_owned(),
                cpp_type: "const std::filesystem::path &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <filesystem>"));
        assert!(main.contains("std::filesystem::path path(_tmp_path)"));
        assert!(main.contains("load(path);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_chrono_for_duration() {
        let out = temp_dir("cpp-emit-chrono-duration");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-CHRONO".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "timeout".to_owned(),
                cpp_type: "const std::chrono::milliseconds &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <chrono>"));
        assert!(main.contains("std::chrono::milliseconds timeout(gf_bounded_i32"));
        assert!(main.contains("parse(timeout);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));

        let Some(cxx_flags) = clangxx_compile_flags("cppgen-chrono-duration") else {
            eprintln!(
                "skipping generated C++ chrono harness compile: clang++ C++ headers unavailable"
            );
            return;
        };
        let obj = result.main_cpp.with_extension("o");
        let output = Command::new("clang++")
            .args(&cxx_flags)
            .arg("-std=c++17")
            .arg("-I")
            .arg(runtime_dir())
            .arg("-c")
            .arg(&result.main_cpp)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang++");
        assert!(
            output.status.success(),
            "clang++ failed\nstdout:\n{}\nstderr:\n{}\nmain.cpp:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn existing_libfuzzer_entrypoint_is_not_wrapped_recursively() {
        let out = temp_dir("cpp-existing-libfuzzer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP003".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/fuzz.cc"),
            target: cppfunction("LLVMFuzzerTestOneInput"),
            params: vec![
                CppParameter {
                    name: "data".to_owned(),
                    cpp_type: "const uint8_t *".to_owned(),
                },
                CppParameter {
                    name: "size".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/fuzz.cc")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        // #408: a passthrough C++ target must now get the govfuzz driver (the
        // edge-coverage runtime + persistent framed fork-server main), NOT the
        // old no-op that left libFuzzer's own main to mis-drive the binary —
        // which produced zero coverage and empty-testcase false positives.
        assert!(
            main.contains("__sanitizer_cov_trace_pc_guard") && main.contains("GOVFUZZ_FRAMED"),
            "passthrough C++ must emit the govfuzz coverage/framed driver: {main}"
        );
        // The project supplies the entrypoint body; the driver only DECLARES it
        // (forward declaration, ends with ';') and calls it once through the
        // wrapper. It must NEVER be redefined here (ODR clash with the project's
        // definition) nor call itself (infinite recursion).
        assert!(
            main.contains(
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);"
            ),
            "passthrough must forward-declare the project entrypoint: {main}"
        );
        assert!(
            !main.contains("LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {"),
            "existing libFuzzer target must not be redefined: {main}"
        );
        assert!(
            main.contains("govfuzz_run_one_bytes")
                && main.contains("LLVMFuzzerTestOneInput(data, size)"),
            "driver should call the project entrypoint through the wrapper: {main}"
        );
        // Makefile: coverage on, libFuzzer's main off (so the govfuzz main is
        // the only entrypoint).
        assert!(
            makefile.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"),
            "passthrough makefile must instrument coverage: {makefile}"
        );
        assert!(
            !makefile.contains("-fsanitize=fuzzer,address,undefined"),
            "passthrough makefile must drop libFuzzer's main: {makefile}"
        );
        assert!(
            makefile.contains("-fsanitize=address,undefined -fno-sanitize=function,vptr,alignment"),
            "passthrough makefile must subtract FP-prone UBSan checks: {makefile}"
        );
        assert!(
            makefile.contains("main.cpp /tmp/fuzz.cc"),
            "project fuzz source should still be linked: {makefile}"
        );
    }

    // ── Factory-receiver emission tests ────────────────────────────────────

    /// A factory plan with an instance-method factory returning a pointer must
    /// emit: owner default-construction, `auto _gf_receiver = _gf_owner.Factory(args)`,
    /// a null guard `if (_gf_receiver) { _gf_receiver->method(...); }`, and the
    /// owner declaration must precede the receiver so it outlives the call.
    #[test]
    fn generate_cpp_factory_pointer_receiver_emits_owner_and_null_guard() {
        let out = temp_dir("cpp-factory-pointer");
        let mut target = cppfunction("IntAttribute");
        target.qualifier_path = vec!["tinyxml2".to_owned(), "XMLElement".to_owned()];
        target.api.class_name = Some("XMLElement".to_owned());
        target.api.namespace_path = vec!["tinyxml2".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-PTR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/tinyxml2.cpp"),
            target,
            params: vec![CppParameter {
                name: "name".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["tinyxml2.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: Some("tinyxml2::XMLDocument".to_owned()),
                factory_method: "NewElement".to_owned(),
                factory_params: vec![CppParameter {
                    name: "name".to_owned(),
                    cpp_type: "const char *".to_owned(),
                }],
                receiver_is_pointer: true,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // Owner must be declared and kept in scope.
        assert!(
            main.contains("tinyxml2::XMLDocument _gf_owner;"),
            "owner must be stack-allocated: {main}"
        );
        // Receiver must be obtained from the factory call (using auto).
        assert!(
            main.contains("auto _gf_receiver = _gf_owner.NewElement("),
            "factory call must use _gf_owner: {main}"
        );
        // Null guard: pointer receivers may be null.
        assert!(
            main.contains("if (_gf_receiver)"),
            "pointer factory receiver must be null-guarded: {main}"
        );
        // Method call must use -> access.
        assert!(
            main.contains("_gf_receiver->IntAttribute("),
            "method on pointer receiver must use -> access: {main}"
        );
        // R must be declared before the if-guard so (void)R compiles outside it.
        let r_decl_pos = main.find("int R{}").or_else(|| main.find("int R ="));
        let if_guard_pos = main.find("if (_gf_receiver)");
        assert!(
            r_decl_pos.is_some() && if_guard_pos.is_some() && r_decl_pos < if_guard_pos,
            "R must be declared before the null guard: {main}"
        );
        // Owner declaration must precede the receiver (LIFETIME: owner must outlive call).
        let owner_pos = main.find("tinyxml2::XMLDocument _gf_owner;");
        let receiver_pos = main.find("auto _gf_receiver = _gf_owner.NewElement(");
        assert!(
            owner_pos.is_some() && receiver_pos.is_some() && owner_pos < receiver_pos,
            "owner must be declared before receiver: {main}"
        );
        // Normal receiver construction path must NOT be emitted.
        assert!(
            !main.contains("tinyxml2::XMLElement _gf_receiver"),
            "factory path must not also emit direct receiver construction: {main}"
        );
    }

    /// A factory plan with a VALUE (non-pointer) return must use `.` access and
    /// must NOT emit a null guard.
    #[test]
    fn generate_cpp_factory_value_receiver_uses_dot_access_without_null_guard() {
        let out = temp_dir("cpp-factory-value");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["acme".to_owned(), "Token".to_owned()];
        target.api.class_name = Some("Token".to_owned());
        target.api.namespace_path = vec!["acme".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-VAL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/acme.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["acme.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: Some("acme::Lexer".to_owned()),
                factory_method: "MakeToken".to_owned(),
                factory_params: Vec::new(),
                receiver_is_pointer: false,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        assert!(
            main.contains("acme::Lexer _gf_owner;"),
            "owner must be emitted: {main}"
        );
        assert!(
            main.contains("auto _gf_receiver = _gf_owner.MakeToken()"),
            "value factory call must be emitted: {main}"
        );
        // Value receiver uses `.` not `->`.
        assert!(
            main.contains("_gf_receiver.parse("),
            "value receiver must use . access: {main}"
        );
        // No null guard for a value return.
        assert!(
            !main.contains("if (_gf_receiver)"),
            "value factory receiver must NOT be null-guarded: {main}"
        );
    }

    /// A factory plan with NO owner (free-function factory) must omit the owner
    /// declaration and call the factory function directly.
    #[test]
    fn generate_cpp_free_function_factory_receiver_omits_owner() {
        let out = temp_dir("cpp-factory-free-fn");
        let mut target = cppfunction("encode");
        target.qualifier_path = vec!["codec".to_owned(), "Frame".to_owned()];
        target.api.class_name = Some("Frame".to_owned());
        target.api.namespace_path = vec!["codec".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-FREE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/codec.cpp"),
            target,
            params: vec![CppParameter {
                name: "buf".to_owned(),
                cpp_type: "const uint8_t *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["codec.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: None, // free-function factory
                factory_method: "codec::create_frame".to_owned(),
                factory_params: Vec::new(),
                receiver_is_pointer: true,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // No owner declaration.
        assert!(
            !main.contains("_gf_owner"),
            "free-function factory must not emit an owner: {main}"
        );
        // Direct free-function call.
        assert!(
            main.contains("auto _gf_receiver = codec::create_frame()"),
            "free-function factory call must be emitted: {main}"
        );
        assert!(
            main.contains("if (_gf_receiver)"),
            "pointer result from free-function factory must be null-guarded: {main}"
        );
        assert!(
            main.contains("_gf_receiver->encode("),
            "method on pointer receiver must use -> access: {main}"
        );
    }

    /// When `factory_plan` is `None` and the class has a normal public default
    /// constructor, the harness must use direct construction — the factory path
    /// must not activate.
    #[test]
    fn generate_cpp_no_factory_plan_uses_direct_receiver_construction() {
        let out = temp_dir("cpp-factory-absent");
        let mut target = cppfunction("value");
        target.qualifier_path = vec!["acme".to_owned(), "Item".to_owned()];
        target.api.class_name = Some("Item".to_owned());
        target.api.namespace_path = vec!["acme".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-NOFACTORY".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/acme.cpp"),
            target,
            params: Vec::new(),
            return_type: "int".to_owned(),
            target_includes: vec!["acme.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // No factory emission when factory_plan is None.
        assert!(
            !main.contains("_gf_owner"),
            "no factory_plan must not emit an owner: {main}"
        );
        assert!(
            !main.contains("auto _gf_receiver"),
            "no factory_plan must not emit auto factory receiver: {main}"
        );
        // Normal receiver path (declaring class name) must be used.
        assert!(
            main.contains("acme::Item _gf_receiver"),
            "direct receiver construction must be used: {main}"
        );
        assert!(
            main.contains("_gf_receiver.value("),
            "normal . access must be used: {main}"
        );
    }

    #[test]
    fn callable_member_name_accepts_identifiers_and_operators_only() {
        assert!(cpp_callable_member_name("open"));
        assert!(cpp_callable_member_name("_private0"));
        assert!(cpp_callable_member_name("operator=="));
        assert!(cpp_callable_member_name("operator()"));
        // Parse-recovery artifacts the emitter must never call as `receiver.X(...)`.
        assert!(!cpp_callable_member_name("~MappedFile"));
        assert!(!cpp_callable_member_name("A::b"));
        assert!(!cpp_callable_member_name("bad<int>"));
        assert!(!cpp_callable_member_name("operator"));
        assert!(!cpp_callable_member_name(""));
        assert!(!cpp_callable_member_name("9start"));
    }

    #[test]
    fn return_type_emittable_rejects_bare_keyword_artifacts() {
        assert!(cpp_return_type_emittable("int"));
        assert!(cpp_return_type_emittable("std::string"));
        assert!(cpp_return_type_emittable("const char *"));
        // A legal elaborated-type-specifier is two tokens and stays allowed.
        assert!(cpp_return_type_emittable("struct Foo"));
        // `namespace detail_fp {` mis-recovered as a function surfaces here.
        assert!(!cpp_return_type_emittable("namespace"));
        assert!(!cpp_return_type_emittable("template"));
        assert!(!cpp_return_type_emittable("using"));
    }

    /// ROBUSTNESS (campaign: tinyobjloader): a lifecycle harness must DROP a step
    /// the parser mis-attributed as a member whose call would not compile — a
    /// non-identifier name or a `namespace`-typed parse artifact — while still
    /// emitting the genuine member, rather than producing an un-compilable harness.
    #[test]
    fn sequence_harness_drops_uncompilable_lifecycle_steps() {
        let out = temp_dir("cpp-sequence-drop-artifacts");
        let mut target = cppfunction("open");
        target.qualifier_path = vec!["ns".to_owned(), "MappedFile".to_owned()];
        target.api.class_name = Some("MappedFile".to_owned());
        target.api.namespace_path = vec!["ns".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-DROP".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/mapped.cpp"),
            target,
            params: vec![CppParameter {
                name: "path".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "bool".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/mapped.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            lifecycle_steps: vec![
                // genuine member: must be emitted
                CppLifecycleStep {
                    name: "close".to_owned(),
                    params: Vec::new(),
                    return_type: "void".to_owned(),
                },
                // `namespace detail_fp {` mis-parsed as a method: must be dropped
                CppLifecycleStep {
                    name: "detail_fp".to_owned(),
                    params: Vec::new(),
                    return_type: "namespace".to_owned(),
                },
                // non-identifier name: must be dropped
                CppLifecycleStep {
                    name: "bad<int>".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                },
            ],
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        assert!(
            main.contains("_gf_receiver.close("),
            "genuine member step must be emitted: {main}"
        );
        assert!(
            !main.contains("detail_fp"),
            "namespace artifact step must be dropped: {main}"
        );
        assert!(
            !main.contains("bad<int>"),
            "non-identifier step must be dropped: {main}"
        );
        assert!(
            !main.contains("namespace _gf_step"),
            "no step may emit a `namespace`-typed result: {main}"
        );
    }

    /// ROBUSTNESS: a TARGET the parser handed us with a parse-artifact return type
    /// must SKIP cleanly (an `Err` the CLI surfaces as a skip reason) instead of
    /// emitting `namespace R = receiver.detail_fp();`.
    #[test]
    fn sequence_harness_skips_malformed_target_cleanly() {
        let out = temp_dir("cpp-sequence-bad-target");
        let mut target = cppfunction("detail_fp");
        target.qualifier_path = vec!["ns".to_owned(), "MappedFile".to_owned()];
        target.api.class_name = Some("MappedFile".to_owned());
        target.api.namespace_path = vec!["ns".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-BADTGT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/mapped.cpp"),
            target,
            params: Vec::new(),
            return_type: "namespace".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/mapped.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            lifecycle_steps: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let err = generate_cpp_sequence_harness(args).unwrap_err();
        assert!(
            matches!(err, HarnessGenError::UnsupportedParamType(_)),
            "malformed target must skip cleanly, got: {err:?}"
        );
    }
}
