// SPDX-License-Identifier: Apache-2.0
//
// Lightweight heuristic ranker for C and C++ targets.
//
// Govfuzz's Ada ranker reasons over the full structural AST (visibility,
// handlers, raises, etc.). For C/C++ we have only a function signature and
// the function name, so the scoring is shape-based:
//
// - Parameter shape: byte buffers (`char *`, `const char *`,
//   `uint8_t *`, `unsigned char *`, `void *`, `std::string`,
//   `std::string_view`, byte vectors, fixed byte arrays, filesystem paths) are highly fuzz-worthy.
// - Length param: a `size_t` / `int` adjacent to a buffer is a strong
//   signal.
// - Return type: `int` looks like an error-code return, so the function
//   is likely a validator/parser worth fuzzing.
// - Name keywords: `parse`, `decode`, `read`, `load`, `process` move the
//   target up; `getter`/`setter`/`*_helper` push it down.
// - Arity: 1–4 params is a sweet spot.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CTarget {
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: CScoreBreakdown,
    /// Whether the function's fuzzed parameters constitute an attacker-controlled
    /// input channel. Drives both ranking (down-rank functions with no untrusted
    /// input) and honest reporting (a crash on a non-`AttackerReachable` target is
    /// not demonstrably reachable from attacker input as fuzzed).
    pub input_reachability: InputReachability,
}

/// Verdict on whether fuzzing a function's parameters exercises an
/// attacker-controlled input channel, derived from parameter shape + name.
///
/// govfuzz fuzzes a target by driving its *parameters* with the fuzz input. That
/// only models a real attack when a parameter is something an attacker actually
/// controls — a read-only byte buffer (`const uint8_t *`, `std::string_view`,
/// `const std::vector<uint8_t>&`, a filesystem path). A non-`const` output buffer
/// (`uint8_t *buf` a serializer writes into), an in/out cursor (`int &offset`), or
/// a capacity/count scalar (`max_channels`) is *caller/firmware-controlled*:
/// fuzzing it overruns the harness's own buffer, but the real caller never passes
/// attacker-derived values, so the crash is a harness artifact, not a
/// vulnerability. (Concretely: PX4 `write_uint24_t(uint8_t *buf, int &offset, int
/// value)` "crashes" under fuzzing but is unreachable; `crsf_parse(const uint8_t
/// *frame, unsigned len, ...)` is the real attacker surface.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputReachability {
    /// Has a read-only untrusted-input buffer parameter (the attacker source).
    /// Crashes are candidate vulnerabilities worth triaging.
    AttackerReachable,
    /// A serializer/writer (`write_*`/`send_*`/`encode_*`) whose buffer + offset
    /// are caller-controlled, with no untrusted-input buffer. Crashes here are
    /// harness artifacts (the caller never feeds attacker bytes to these args).
    OutputSerializer,
    /// No untrusted-input buffer at all — the fuzzed parameters are scalars,
    /// handles, output pointers, or cursors the caller controls. Reachability from
    /// attacker input is unproven; a crash must not be reported as a vulnerability
    /// without a separate proof that attacker data reaches these parameters.
    #[default]
    ReachabilityUnproven,
    /// The function takes no untrusted-input buffer parameter, BUT the run showed
    /// it reading fuzz-driven data from a virtualized IPC channel (POSIX/System V
    /// shared memory, a POSIX message queue, or MMIO). The crash IS reachable from
    /// that channel's data — assigned dynamically from the runtrace, never at rank
    /// time. Whether the channel is attacker-controlled depends on the deployment's
    /// trust boundary, so this sits between `AttackerReachable` and
    /// `ReachabilityUnproven`.
    IpcChannelReachable,
}

impl InputReachability {
    /// One-line honest label for the report.
    pub fn report_note(self) -> &'static str {
        match self {
            InputReachability::AttackerReachable => {
                "attacker-reachable input channel (read-only untrusted buffer parameter)"
            }
            InputReachability::OutputSerializer => {
                "REACHABILITY UNPROVEN: output/serializer function — its buffer and offset are \
                 caller-controlled, not attacker input; a fuzz crash here is a harness artifact \
                 unless attacker control of these arguments is separately proven"
            }
            InputReachability::ReachabilityUnproven => {
                "REACHABILITY UNPROVEN: no untrusted-input buffer parameter — the fuzzed arguments \
                 (scalars/handles/output/cursor) are caller-controlled; a fuzz crash here is not \
                 demonstrably reachable from attacker input without a separate proof"
            }
            InputReachability::IpcChannelReachable => {
                "INPUT-REACHABLE VIA IPC CHANNEL: no buffer parameter, but the run drove this crash \
                 with fuzz data read from a virtualized IPC channel (shared memory / message queue \
                 / MMIO) — it IS reachable from that channel's data, and attacker-controlled if the \
                 channel crosses a trust boundary (a less-trusted partition, a network-fed bus, or \
                 an untrusted peripheral)"
            }
        }
    }

    pub fn is_attacker_reachable(self) -> bool {
        matches!(self, InputReachability::AttackerReachable)
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct CScoreBreakdown {
    pub buffer_param: i32,
    pub length_param_with_buffer: i32,
    pub error_code_return: i32,
    pub parse_decode_name: i32,
    pub helper_or_static_name: i32,
    pub arity_in_sweet_spot: i32,
    /// Penalty when the function has no attacker-controlled input channel — a
    /// serializer/writer or a function whose fuzzed parameters are all
    /// caller-controlled. Keeps wrong-layer targets (PX4 `write_*`,
    /// `crsf_parse_buffer`) from out-ranking the real parsers.
    pub no_attacker_input: i32,
    /// Penalty when the function needs a PRE-BUILT typed input context alongside
    /// its byte buffer (a token array, an AST node list) that the fuzzer cannot
    /// synthesize from raw bytes. Keeps an internal mid-layer parser
    /// (`cgltf_parse_json_material(jsmntok_t const* tokens, ...)`) from
    /// out-ranking the clean raw-byte entry (`cgltf_parse(const void*, size)`).
    /// Large enough to dominate the call-graph fan-out boost (which would
    /// otherwise re-lift such a deep, high-fan-out node).
    pub needs_prebuilt_context: i32,
    /// Penalty for a COMPRESSION-direction codec function (`compress`, `deflate`):
    /// it serializes the caller's own (trusted) data into bytes, so it is not the
    /// attack surface — the attacker-facing side of a codec is DEcompression
    /// (`uncompress`/`inflate`/`decompress`). Keeps `LZ4_compress_*` /
    /// `deflate*` from out-ranking `LZ4_decompress_safe` / `inflate`.
    pub compressor_name: i32,
    pub total: i32,
}

pub fn rank_c_targets(functions: &[c_parser::CFunction]) -> Vec<CTarget> {
    let mut targets: Vec<CTarget> = functions
        .iter()
        .filter(|f| !is_allocator_free_primitive(&f.name))
        .map(|f| {
            let (breakdown, input_reachability) = score_c_function(f);
            CTarget {
                name: f.name.clone(),
                line: f.line,
                score: breakdown.total,
                breakdown,
                input_reachability,
            }
        })
        .collect();
    sort_targets(&mut targets);
    targets
}

pub fn rank_cpp_targets(functions: &[cpp_parser::CppFunction]) -> Vec<CTarget> {
    let mut targets: Vec<CTarget> = functions
        .iter()
        .filter(|f| !cpp_api_is_unsupported_target(f))
        .map(|f| {
            let (breakdown, input_reachability) = score_cpp_function(f);
            CTarget {
                name: cpp_target_name(f),
                line: f.line,
                score: breakdown.total,
                breakdown,
                input_reachability,
            }
        })
        .collect();
    sort_targets(&mut targets);
    targets
}

fn sort_targets(targets: &mut [CTarget]) {
    targets.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.line.cmp(&right.line))
    });
}

fn score_c_function(f: &c_parser::CFunction) -> (CScoreBreakdown, InputReachability) {
    let params: Vec<(&str, &str)> = f
        .params
        .iter()
        .map(|p| (p.name.as_str(), p.c_type.as_str()))
        .collect();
    let (mut b, reach) = score_from_signature(&f.name, &f.return_type, &params);
    // Internal-linkage (`static`) functions are not the library's attack surface:
    // they are helpers reached THROUGH the public API, and fuzzing one in isolation
    // forces the harness to fabricate its typed inputs (e.g. cJSON's static
    // `create_patches`/`get_item_from_pointer`, fed zeroed stack structs), which
    // yields low-value findings — borrowed-pointer aliasing, output-accumulator
    // leaks. Soft-demote so a public entry point out-ranks them (same magnitude as
    // the name-based helper marker; a static helper still beats an output serializer).
    // Only when the name heuristic hasn't already applied the penalty (no double-hit).
    if f.is_static && b.helper_or_static_name == 0 {
        b.helper_or_static_name = -20;
        b.total -= 20;
    }
    // Campaign fix: a STATIC function with an opaque `void *` context/stream
    // parameter is a callback / internal reader (inih ini_reader_string
    // `char*(char*,int,void*)`, microtar file_read `int(mtar_t*,void*,unsigned)`)
    // reached only through a function-pointer cast with a caller-built context —
    // never an attacker-controlled entry point. The harness can only fabricate
    // that opaque context from raw bytes, so the callee casts+derefs garbage and
    // reports a false critical crash in the LIBRARY. Heavily demote it (still
    // discoverable via --target) so real public entry points always outrank it.
    //
    // Campaign #5: the static gate alone misses yyjson's `unsafe_yyjson_get_*`
    // inline accessors — the `*_api_inline` export macro hides their static-inline
    // storage from the non-preprocessing parser, so `is_static` is false. Extend
    // the demotion to a NON-static function whose opaque `void *` stands ALONE
    // (no length/size param), i.e. an opaque handle/cursor — but NEVER a
    // `(const void *data, size)` raw-byte data channel (cgltf_parse), where the
    // paired length proves it's a real attacker input buffer.
    if params.iter().any(|(_, ty)| is_opaque_void_pointer(ty)) {
        let has_length = params
            .iter()
            .any(|(n, t)| is_length_param(t) || is_length_name(n));
        if f.is_static || !has_length {
            b.helper_or_static_name -= 100;
            b.total -= 100;
        }
    }
    (b, reach)
}

/// Whether `ty` is a bare `void *` (an opaque context/userdata/stream pointer),
/// not a typed pointer. `const void *` data buffers are included — a static
/// callback's context is opaque regardless of constness.
fn is_opaque_void_pointer(ty: &str) -> bool {
    let t = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        t.as_str(),
        "void *" | "void*" | "const void *" | "void const *"
    )
}

/// A memory-(re)allocation primitive whose pointer operand must be a *live*
/// allocation owned by that same allocator — `Realloc`/`Free`/`Deallocate` and
/// friends. Its pointer cannot be synthesized from fuzz bytes: binding it to a
/// `(void *)Data` view (or a fresh mismatched allocation) makes the callee
/// `std::realloc`/`std::free` an invalid pointer, which ASan reports as an
/// invalid-free / double-free FALSE POSITIVE (rapidjson `CrtAllocator::Realloc`,
/// `MemoryPoolAllocator::Free`). These are allocator plumbing reached THROUGH a
/// parser, never an attacker-controlled entry point, so they are not fuzzable.
/// Matched on the unqualified leaf name — a member (`Allocator::Free`), a free
/// function (`Free`), and the generic `Realloc(A &, T *, ...)` (whose pointer the
/// parser may drop) are all caught, while a project helper like `free_node` (a
/// distinct name) is not. No non-allocator parser is named exactly `free`/`realloc`.
fn is_allocator_free_primitive(name: &str) -> bool {
    let leaf = name.rsplit("::").next().unwrap_or(name);
    matches!(
        leaf.to_ascii_lowercase().as_str(),
        "free" | "realloc" | "reallocate" | "deallocate" | "dealloc"
    )
}

fn score_cpp_function(f: &cpp_parser::CppFunction) -> (CScoreBreakdown, InputReachability) {
    let params: Vec<(&str, &str)> = f
        .params
        .iter()
        .map(|p| (p.name.as_str(), p.cpp_type.as_str()))
        .collect();
    let name = if f.qualifier_path.is_empty() {
        f.name.clone()
    } else {
        format!("{}::{}", f.qualifier_path.join("::"), f.name)
    };
    score_from_signature(&name, &f.return_type, &params)
}

fn cpp_api_is_unsupported_target(f: &cpp_parser::CppFunction) -> bool {
    f.api.is_constructor
        || f.api.is_destructor
        || is_allocator_free_primitive(&cpp_target_name(f))
        // A templated free function is harnessable ONCE a concrete specialization
        // is resolved (#455 / §27.5): a call-site instantiation (`parse<int>(..)`)
        // or the `--template-instantiate` flag fills `instantiation_args`, and
        // codegen then emits a turbofish call with the type args substituted into
        // the parameter types. Still filter a template with no resolved args — its
        // parameters can't be decoded.
        || (f.api.is_template && f.instantiation_args.is_empty())
        || f.api
            .member_access
            .as_deref()
            .is_some_and(|access| access != "public")
}

fn cpp_target_name(f: &cpp_parser::CppFunction) -> String {
    let qualified = if f.qualifier_path.is_empty() {
        f.name.clone()
    } else {
        format!("{}::{}", f.qualifier_path.join("::"), f.name)
    };
    if f.api.unsupported.iter().any(|item| item == "overload_set") {
        format!(
            "{}({})",
            qualified,
            f.params
                .iter()
                .map(|param| param.cpp_type.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        qualified
    }
}

fn score_from_signature(
    name: &str,
    return_type: &str,
    params: &[(&str, &str)],
) -> (CScoreBreakdown, InputReachability) {
    let mut b = CScoreBreakdown::default();
    let reachability = classify_input_reachability(name, params);

    // Only a read-only *untrusted-input* buffer earns the buffer bonus. A
    // non-`const` output buffer (a serializer's destination) is NOT an attacker
    // input channel, so it must not make the function look fuzz-worthy.
    let untrusted_buffer_count = params
        .iter()
        .filter(|(_, t)| is_untrusted_input_buffer(t))
        .count();
    // A length param is recognised by TYPE (size_t, uLong, …) OR by NAME
    // (`len`, `sourceLen`, `nbytes`) so a typedef'd length on undocumented code
    // still earns the buffer+length bonus.
    let length_param_count = params
        .iter()
        .filter(|(n, t)| is_length_param(t) || is_length_name(n))
        .count();
    // The classic C parser idiom takes a NON-const byte pointer it tokenizes in
    // place (`toml_parse(char *toml, ...)`, `json_parse(char *)`). The const-only
    // rule above misses it, leaving the real public entry point scoring near zero
    // while internal `const char *` helpers out-rank it. Count a mutable byte
    // pointer as an input buffer ONLY once `classify_input_reachability` has
    // already proved the function attacker-driven (it required a length + a
    // parser/decoder name), so a genuine serializer's destination still scores as
    // output, not input.
    let mutable_input_buffer = reachability.is_attacker_reachable()
        && params
            .iter()
            .any(|(_, t)| is_byte_pointer(&normalize_type(t)));
    let has_input_buffer = untrusted_buffer_count > 0 || mutable_input_buffer;
    if has_input_buffer {
        b.buffer_param = 30;
    }
    // A self-describing buffer (std::string, string_view, span, byte vector,
    // filesystem::path) carries its own length, so it earns the buffer+length
    // bonus on its own: the `const std::string &` of `ObjReader::ParseFromString`
    // is a complete (bytes, length) channel — equivalent to a `(const char *,
    // size_t)` pair — and must not score below an internal helper that merely
    // spells the pair out.
    let has_self_describing_buffer = params
        .iter()
        .any(|(_, t)| is_untrusted_input_buffer(t) && !is_byte_pointer(&normalize_type(t)));
    if has_input_buffer && (length_param_count > 0 || has_self_describing_buffer) {
        b.length_param_with_buffer = 15;
    }
    if is_error_code_return(return_type) {
        b.error_code_return = 10;
    }

    let lower_name = name.to_ascii_lowercase();
    if name_has_parser_keyword(&lower_name) {
        b.parse_decode_name = 15;
    }
    if name_has_helper_marker(&lower_name) {
        b.helper_or_static_name = -20;
    }
    // #26: a fixed-width SCALAR value accessor (mpack `mpack_load_u16`/
    // `mpack_load_double`) is a header-only inline getter that loads N fixed bytes
    // and returns a scalar — NOT an attacker-parser entry. The `load`/`read` keyword
    // bonus mis-promotes it to the top, where its `(void)R` harness is dead-code-
    // eliminated at -O1 (a hollow "built+fuzzed cov=N/0f"). Drop the parser bonus
    // and demote it like a trivial getter so real parsers out-rank it.
    if is_fixed_width_value_accessor(&lower_name) {
        b.parse_decode_name = 0;
        if b.helper_or_static_name == 0 {
            b.helper_or_static_name = -20;
        }
    }

    let arity = params.len();
    if (1..=4).contains(&arity) {
        b.arity_in_sweet_spot = 5;
    }

    // Down-rank a function with no attacker-controlled input channel so the real
    // parsers out-rank the wrong-layer targets (serializers, internal helpers
    // whose fuzzed args the caller controls). A serializer is penalised hardest.
    b.no_attacker_input = match reachability {
        InputReachability::AttackerReachable => 0,
        InputReachability::OutputSerializer => -40,
        // IpcChannelReachable is assigned dynamically from the runtrace AFTER a
        // run, never by static ranking, so it cannot reach this match; treat it
        // like a no-buffer-param function for the (unreachable) exhaustive arm.
        InputReachability::ReachabilityUnproven | InputReachability::IpcChannelReachable => -20,
    };

    // Demote a mid-layer parser that consumes raw bytes BUT also requires a
    // pre-built typed input context (a token array, an AST node list) the fuzzer
    // can't construct from raw bytes. Such a function looks like a parser (byte
    // buffer + parse name + high fan-out) yet isn't hands-off harnessable, so it
    // must rank below the clean raw-byte entry point. The penalty is sized to
    // dominate the call-graph fan-out boost (applied later in discovery), which
    // would otherwise re-lift these deep, high-fan-out internal nodes.
    if has_input_buffer && params.iter().any(|(n, t)| is_prebuilt_input_context(n, t)) {
        b.needs_prebuilt_context = -60;
    }

    // A compressor processes the caller's own data (an output serializer); the
    // attacker-facing codec surface is decompression. Demote so the decompress
    // entry out-ranks the compressor that shares the same buffer+length shape.
    if name_is_compressor(&lower_name) {
        b.compressor_name = -25;
    }

    b.total = b.buffer_param
        + b.length_param_with_buffer
        + b.error_code_return
        + b.parse_decode_name
        + b.helper_or_static_name
        + b.arity_in_sweet_spot
        + b.no_attacker_input
        + b.needs_prebuilt_context
        + b.compressor_name;
    (b, reachability)
}

/// A COMPRESSION-direction codec name. Compression turns the caller's own
/// (trusted) data into bytes, so it is an output serializer, not an attack
/// surface — the attacker-facing side is DEcompression. The `compress` test is
/// guarded against the `decompress`/`uncompress` substrings so the decompressor
/// is never mistaken for a compressor; `deflate` (compress) is distinct from
/// `inflate` (decompress) and safe to match directly.
fn name_is_compressor(name: &str) -> bool {
    (name.contains("compress") && !name.contains("decompress") && !name.contains("uncompress"))
        || name.contains("deflate")
}

/// A parameter that hands the function a PRE-BUILT typed input structure the
/// fuzzer cannot synthesize from raw bytes (a parsed token array, an AST node
/// list, a populated parser state) — the tell of a mid-layer parser rather than
/// a top-level entry point. Conservative on purpose so it never demotes a real
/// entry point:
/// - only a `const` SINGLE pointer (a read-only input; a double pointer is an
///   out-param, a non-`const` pointer is an in/out the harness can zero-init);
/// - the pointee is a TYPED aggregate, not a byte/opaque blob (`char`/`uint8_t`/
///   `void`/`byte`) — those are the attacker buffer — nor a `FILE` (govfuzz
///   `fmemopen`s a stream) nor a length scalar;
/// - the name is NOT a synthesizable context/output/allocator/callback (those
///   are zero-init or harness-owned), e.g. `options`, `ctx`, `allocator`,
///   `pAllocationCallbacks`, `out_*`.
///
/// A bare scalar base type (so a `T &` / `T *` of it is an out-param or count, not
/// a prebuilt context object). `real_t` is tinyobjloader's float typedef; the rest
/// are the standard integer/float/bool spellings.
fn is_scalar_base(base: &str) -> bool {
    matches!(
        base,
        "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "long long"
            | "short"
            | "float"
            | "double"
            | "bool"
            | "size_t"
            | "ssize_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "real_t"
    )
}

fn is_prebuilt_input_context(name: &str, raw: &str) -> bool {
    let t = normalize_type(raw);
    // Two prebuilt-context shapes the fuzzer cannot synthesize from raw bytes:
    //   - a read-only single pointer (`const T *`), and
    //   - a reference to a non-buffer object (`StreamReader &`) — the C++ idiom for
    //     a caller-populated reader/tokenizer/parse-state. A reference to a
    //     SYNTHESIZABLE buffer (`const std::string &`, `span`, byte vector) is
    //     fuzzable INPUT, not context, so it is excluded here.
    let is_const_ptr = t.matches('*').count() == 1 && t.contains("const");
    let is_context_ref =
        t.matches('*').count() == 0 && t.contains('&') && !is_untrusted_input_buffer(&t);
    if !is_const_ptr && !is_context_ref {
        return false;
    }
    // Pointee/referent base = type with `const`/`*`/`&` stripped.
    let base = t
        .replace(['*', '&'], " ")
        .split_whitespace()
        .filter(|tok| *tok != "const")
        .collect::<Vec<_>>()
        .join(" ");
    if base.is_empty()
        || base.contains("char")
        || base.contains("uint8")
        || base.contains("int8")
        || base.contains("void")
        || base.contains("byte")
        || base == "file"
        || is_length_param(&base)
        // A reference/pointer to a bare scalar is an out-param or a count, never a
        // prebuilt context OBJECT (`int &out`, `real_t &`).
        || is_scalar_base(&base)
        // A config/option/context/settings TYPE is default-constructible (govfuzz
        // builds it), not a prebuilt input the fuzzer lacks (`const ObjReaderConfig &`).
        || ["config", "option", "setting", "context"]
            .iter()
            .any(|k| base.contains(k))
    {
        return false;
    }
    // Synthesizable context / output / allocator / callback params are fine.
    let n = name.trim().trim_matches('_').to_ascii_lowercase();
    const CTX_CONTAINS: &[&str] = &[
        "option", "config", "context", "setting", "alloc", "callback", "userdata", "logger",
        "output", "result", "buffer",
    ];
    if CTX_CONTAINS.iter().any(|k| n.contains(k)) {
        return false;
    }
    const CTX_EXACT: &[&str] = &[
        "opt", "opts", "cfg", "conf", "ctx", "cx", "uc", "env", "cb", "cbs", "ud", "mem", "pool",
        "arena", "state", "st", "self", "this", "out", "dst", "dest", "sink", "res", "err", "diag",
        "hint", "hints", "user",
    ];
    if CTX_EXACT.contains(&n.as_str()) {
        return false;
    }
    true
}

/// Classify whether fuzzing this signature exercises an attacker-controlled input
/// channel. See [`InputReachability`]. Order matters: a present read-only
/// untrusted buffer wins; otherwise a serializer name marks an output function;
/// otherwise there is no proven attacker input.
pub fn classify_input_reachability(name: &str, params: &[(&str, &str)]) -> InputReachability {
    let has_untrusted_buffer = params.iter().any(|(_, t)| is_untrusted_input_buffer(t));
    if has_untrusted_buffer {
        return InputReachability::AttackerReachable;
    }
    let lower_name = name.to_ascii_lowercase();
    // A non-`const` byte buffer paired with a length under a parser/decoder name
    // is the C idiom for an in-place / mutable input buffer (some decoders write
    // back into the frame they parse) — treat as attacker-reachable.
    let has_output_buffer = params.iter().any(|(_, t)| is_output_buffer(t));
    let has_length = params
        .iter()
        .any(|(n, t)| is_length_param(t) || is_length_name(n));
    if has_output_buffer
        && has_length
        && name_has_parser_keyword(&lower_name)
        && !name_has_serializer_keyword(&lower_name)
    {
        return InputReachability::AttackerReachable;
    }
    // Byte-stream decoder idiom: a `parse`/`decode` function fed one untrusted
    // byte at a time (`decode(uint8_t byte, ...out params...)`), the input being
    // a single byte scalar driven in a loop by the driver. The attacker controls
    // that byte (radio/UART stream), so it IS attacker-reachable — but a
    // single-call harness can't drive the state machine; it needs a byte-stream
    // harness that feeds the whole fuzz input one byte per call. (PX4 st24_decode,
    // sumd_decode.)
    if name_has_parser_keyword(&lower_name)
        && !name_has_serializer_keyword(&lower_name)
        && params.first().is_some_and(|(_, t)| is_byte_scalar(t))
    {
        return InputReachability::AttackerReachable;
    }
    if name_has_serializer_keyword(&lower_name) {
        return InputReachability::OutputSerializer;
    }
    InputReachability::ReachabilityUnproven
}

/// A single-byte scalar (`uint8_t`/`unsigned char`/`char`/`u8`) — the per-call
/// unit of a byte-stream decoder. NOT a pointer (that's a buffer).
fn is_byte_scalar(raw: &str) -> bool {
    let t = normalize_type(raw);
    if t.contains('*') || t.contains('&') {
        return false;
    }
    let t = t.trim_start_matches("const ").trim();
    matches!(
        t,
        "uint8_t" | "int8_t" | "unsigned char" | "signed char" | "char" | "u8" | "std::uint8_t"
    )
}

fn normalize_type(raw: &str) -> String {
    raw.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A pointer to a byte-ish base (`char`, `uint8_t`, `unsigned char`, `void`,
/// `std::byte`). `t` must be normalized (lowercase, single-spaced).
fn is_byte_pointer(t: &str) -> bool {
    t.contains('*')
        && (t.contains("char")
            || t.contains("uint8_t")
            || t.contains("int8_t")
            || t.contains("void")
            || t.contains("byte"))
}

/// A `std::vector`/`std::array` of bytes. `t` must be normalized.
fn is_byte_container(t: &str) -> bool {
    t.contains("vector<uint8_t")
        || t.contains("vector<std::uint8_t")
        || t.contains("vector<unsigned char")
        || t.contains("vector<char")
        || t.contains("vector<std::byte")
        || t.contains("array<uint8_t")
        || t.contains("array<std::uint8_t")
        || t.contains("array<unsigned char")
        || t.contains("array<char")
        || t.contains("array<std::byte")
}

/// A read-only / untrusted-input byte buffer — the attacker source. A `const`
/// byte pointer, or a read-only byte container/view (by-value or const-ref
/// `std::string`/vector/array, `string_view`, `span<const ...>`, a path).
fn is_untrusted_input_buffer(raw: &str) -> bool {
    let t = normalize_type(raw);
    if is_byte_pointer(&t) {
        // A read-only input buffer is `const`-qualified (`const uint8_t *`).
        return t.contains("const");
    }
    if t.contains("string_view") || t.contains("filesystem::path") {
        return true;
    }
    if t.contains("span<") {
        // A read-only view is `span<const ...>`; a mutable span is an output.
        return t.contains("span<const") || t.contains("span< const");
    }
    if t.contains("std::string") {
        // By-value / const-ref string is input; a mutable `std::string &` is output.
        return !t.contains('&') || t.contains("const");
    }
    if is_byte_container(&t) {
        // By-value / const-ref byte container is input; a mutable ref is output.
        return !t.contains('&') || t.contains("const");
    }
    false
}

/// A mutable byte buffer the function writes into — caller/firmware-controlled
/// output (a serializer's destination), NOT an attacker source.
fn is_output_buffer(raw: &str) -> bool {
    let t = normalize_type(raw);
    if is_byte_pointer(&t) {
        return !t.contains("const");
    }
    if t.contains("span<") {
        return !(t.contains("span<const") || t.contains("span< const"));
    }
    if t.contains("std::string") || is_byte_container(&t) {
        return t.contains('&') && !t.contains("const");
    }
    false
}

fn name_has_serializer_keyword(name: &str) -> bool {
    [
        "write",
        "send",
        "serialize",
        "serialise",
        "encode",
        "marshal",
        "pack",
        "emit",
        "format",
        "to_buf",
        "to_bytes",
        "to_byte",
        "put_",
        "_put",
        "dump",
    ]
    .iter()
    .any(|kw| name.contains(kw))
}

fn is_length_param(raw: &str) -> bool {
    let t = normalize_type(raw);
    let strip = t.trim_start_matches("const ").trim().to_owned();
    matches!(
        strip.as_str(),
        "size_t"
            | "std::size_t"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "ssize_t"
            | "uint32_t"
            | "uint64_t"
            | "int32_t"
            | "int64_t"
            // Common length/size typedefs from widely-used C libraries (zlib's
            // uLong/uLongf/uInt, BSD u_long/u_int, stdint-ish) so a typedef'd
            // length still earns the buffer+length bonus on undocumented code.
            | "ulong"
            | "ulongf"
            | "uint"
            | "uintf"
            | "ushort"
            | "u_long"
            | "u_int"
            | "uintptr_t"
            | "intptr_t"
            | "ptrdiff_t"
            | "usize"
            | "off_t"
            | "off64_t"
            | "uintmax_t"
            | "intmax_t"
    )
}

/// A parameter whose NAME marks it as a length/size/count regardless of its
/// (possibly typedef'd) type — `len`, `size`, `count`, `n`, `sourceLen`,
/// `nbytes`, `data_len`. Documentation-independent: it catches the length a
/// library's own integer typedef hides from [`is_length_param`] (zlib's
/// `uLong sourceLen`, a project's bespoke `mylen_t`). Only ever ADDS the
/// buffer+length bonus, and that bonus is gated on an input buffer also being
/// present, so a loosely-named scalar can't promote a non-parser function.
fn is_length_name(raw: &str) -> bool {
    let n = raw.trim().trim_matches('_').to_ascii_lowercase();
    if matches!(
        n.as_str(),
        "len"
            | "length"
            | "size"
            | "sz"
            | "count"
            | "cnt"
            | "n"
            | "num"
            | "nbytes"
            | "nbyte"
            | "nmemb"
            | "bytes"
            | "datalen"
            | "buflen"
            | "bufsize"
    ) {
        return true;
    }
    n.ends_with("len")
        || n.ends_with("size")
        || n.ends_with("count")
        || n.ends_with("_n")
        || n.ends_with("_bytes")
        || n.starts_with("num")
        || n.starts_with("n_")
}

fn is_error_code_return(raw: &str) -> bool {
    let t = normalize_type(raw);
    let strip = t.trim_start_matches("const ").trim().to_owned();
    matches!(
        strip.as_str(),
        "int" | "signed int" | "int32_t" | "long" | "ssize_t" | "ptrdiff_t"
    )
}

/// True when `name` (lowercased) is a FIXED-WIDTH SCALAR value accessor —
/// `mpack_load_u16` / `mpack_load_double` / `*_get_u32` / `*_read_i64`: a
/// header-only inline getter that loads N fixed bytes from a pointer and returns a
/// scalar. It is not an attacker-parser entry; the `load`/`read` keyword bonus
/// mis-promotes it, and its `(void)R` harness is dead-code-eliminated at -O1 (#26).
fn is_fixed_width_value_accessor(name: &str) -> bool {
    let leaf = name.rsplit("::").next().unwrap_or(name);
    for verb in ["load_", "get_", "read_"] {
        if let Some(idx) = leaf.rfind(verb) {
            if is_fixed_width_scalar_suffix(&leaf[idx + verb.len()..]) {
                return true;
            }
        }
    }
    false
}

fn is_fixed_width_scalar_suffix(s: &str) -> bool {
    matches!(
        s,
        "u8" | "u16"
            | "u24"
            | "u32"
            | "u64"
            | "i8"
            | "i16"
            | "i24"
            | "i32"
            | "i64"
            | "f32"
            | "f64"
            | "float"
            | "double"
            | "bool"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
    )
}

fn name_has_parser_keyword(name: &str) -> bool {
    [
        "parse",
        "decode",
        "read",
        "load",
        "process",
        "deserialize",
        "unmarshal",
        "consume",
        "scan",
        // Decompression / container entry points consume untrusted bytes just like
        // a parser (`uncompress`, `inflate`, `unpack`, `extract` an archive/blob).
        // Without these, codec libraries' real entry (zlib's `uncompress`) ranked
        // far below internal `read_*` helpers whose names already matched.
        "decompress",
        "uncompress",
        "inflate",
        "unpack",
        "extract",
        "demux",
    ]
    .iter()
    .any(|kw| name.contains(kw))
}

/// A name carrying an explicit "not the public attack surface" marker — an
/// implementation worker (`*_internal` / `*Internal`), a CLI/argv parser, a config
/// setter, or `main`. Demoted in scoring, and (via `discovery`) excluded from the
/// entry-point fan-out boost so a deep internal worker cannot be re-lifted above
/// the public wrapper that delegates to it.
pub fn name_has_helper_marker(name: &str) -> bool {
    let nl = name.to_ascii_lowercase();
    // The bare leaf (drop any C++ qualifier path) so the reserved-/internal-name
    // conventions below match a NAMESPACED helper too (`ns::_impl_foo`).
    let leaf = nl.rsplit("::").next().unwrap_or(&nl);
    // Reserved / library-internal naming conventions (§26.3). A C identifier that
    // begins with an underscore, or contains a double underscore anywhere, is
    // reserved by the C standard for the implementation and is the conventional
    // marker for a library's own internals — stb's `stb__threadq_*` queue
    // internals, a `_impl`/`_internal` worker. Such a symbol is reached THROUGH
    // the public API, not directly attacker-facing, and is frequently `static` or
    // declared in no public header, so a separately compiled harness either can't
    // link it or fuzzes it at the wrong layer. Demote (never drop) so a real
    // public entry point out-ranks it.
    if leaf.starts_with('_') || leaf.contains("__") || nl.ends_with("_impl") {
        return true;
    }
    // `unsafe_`-prefixed accessors (yyjson `unsafe_yyjson_get_len`/`unsafe_yyjson_get_str`,
    // exposed inline behind a `*_api_inline` export macro the non-preprocessing parser
    // can't mark `static`) are the author's explicit "internal, precondition-laden, NOT
    // the public attack surface" marker — they take a pre-validated opaque handle and
    // skip the bounds checks the safe wrappers perform. Fuzzing one feeds raw bytes as
    // the opaque handle and reports a false OOB. Demote (never drop — still --target-able).
    if leaf.starts_with("unsafe_") {
        return true;
    }
    name.ends_with("_helper")
        || name.starts_with("static_")
        || name.contains("_internal_")
        // `*_internal` / `*Internal` methods and an `internal` namespace segment are
        // the author's explicit "not the public API" marker — an implementation
        // worker reached THROUGH a public wrapper (tinyobjloader's
        // `ObjReader::ParseFromString` -> `LoadObj` -> `LoadObjInternal`, and the
        // `tinyobj::opt_internal::*` / `*_internal` opt loaders). Fuzzing it directly
        // is wrong-layer and often un-harnessable (needs a prebuilt receiver), so it
        // must rank below the public entry that delegates to it.
        || nl.ends_with("_internal")
        || name.ends_with("Internal")
        || nl.contains("internal::")
        // A program `main` (and namespace-qualified `foo::main`) is a program entry
        // point, not a library API. Discovery drops it entirely (the generated harness
        // defines its own `int main(...)`, causing a duplicate-main link error), but
        // the scorer still demotes it here so any `main` that slips past a custom
        // `--include-dir` can't out-rank the real library API (nghttp2's
        // `h2load::main` ranked #1 over the HPACK decoder). The `::` suffix catches
        // namespace-qualified C++ mains.
        || name == "main"
        || name.ends_with("::main")
        // CLI argument parsers (parse argv, not untrusted file/network input) — a
        // bundled command-line tool, not the library's attack surface.
        || name.contains("cmdline")
        || name.contains("command_line")
        || name.contains("commandline")
        || name.contains("parse_switches")
        || name.contains("parse_argv")
        || name.contains("parse_args")
        // getopt-family CLI parsers consume argv via a fixed option table, never
        // file/network bytes — a vendored libc shim (libde265 `extra/getopt.c`),
        // not the library's attack surface.
        || nl == "getopt"
        || nl.starts_with("getopt")
        // Config / parameter SETTERS take an option-NAME key (matched against a
        // static option table) plus a value — not parsed untrusted input. Fuzzing
        // them in isolation only trips their own "unknown option" contract assert
        // (libde265 `config_parameters::set_int`:421, `en265_set_parameter_int`),
        // an isolation false positive, never an attacker path. Demote (not drop).
        || nl.contains("set_parameter")
        || nl.contains("processcmdline")
        || nl.contains("processcommandline")
        || nl.ends_with("::set_int")
        || nl.ends_with("::set_bool")
        || nl.ends_with("::set_string")
}

#[cfg(test)]
mod tests {
    use super::*;
    use c_parser::{CFunction, CParamDescriptor};
    use cpp_parser::{CppFunction, CppParamDescriptor};

    #[test]
    fn ipc_channel_reachable_note_is_input_reachable_not_unproven() {
        let note = InputReachability::IpcChannelReachable.report_note();
        assert!(
            note.contains("INPUT-REACHABLE VIA IPC CHANNEL"),
            "note must read as input-reachable, not unproven: {note}"
        );
        assert!(
            !note.contains("UNPROVEN"),
            "the IPC note must not carry the misleading UNPROVEN wording: {note}"
        );
        assert!(
            note.contains("trust boundary"),
            "must state the caveat: {note}"
        );
        // It is not a PROVEN attacker-reachable buffer param.
        assert!(!InputReachability::IpcChannelReachable.is_attacker_reachable());
    }

    /// Bare types → (name, type) params, for reachability/score assertions that
    /// only exercise type-based signals (param names left empty on purpose).
    fn tp<'a>(types: &[&'a str]) -> Vec<(&'a str, &'a str)> {
        types.iter().map(|t| ("", *t)).collect()
    }

    fn cf(name: &str, ret: &str, params: &[(&str, &str)]) -> CFunction {
        CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params: params
                .iter()
                .map(|(n, t)| CParamDescriptor {
                    name: (*n).to_owned(),
                    c_type: (*t).to_owned(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn cppf(name: &str, ret: &str, params: &[(&str, &str)]) -> CppFunction {
        CppFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params: params
                .iter()
                .map(|(n, t)| CppParamDescriptor {
                    name: (*n).to_owned(),
                    cpp_type: (*t).to_owned(),
                })
                .collect(),
            qualifier_path: Vec::new(),
            api: cpp_parser::CppApiMetadata::default(),
            ..Default::default()
        }
    }

    fn cpp_method(class_name: &str, name: &str, ret: &str, params: &[(&str, &str)]) -> CppFunction {
        let mut function = cppf(name, ret, params);
        function.qualifier_path = vec!["gov".to_owned(), class_name.to_owned()];
        function.api.class_name = Some(class_name.to_owned());
        function.api.namespace_path = vec!["gov".to_owned()];
        function.api.is_method = true;
        function.api.api_kind = "method".to_owned();
        function.api.overload_key = format!("gov::{class_name}::{name}");
        function
    }

    #[test]
    fn parse_with_buffer_and_length_scores_above_getter() {
        let fns = vec![
            cf("get_count", "int", &[]),
            cf(
                "parse",
                "int",
                &[("input", "const char *"), ("len", "size_t")],
            ),
        ];
        let ranked = rank_c_targets(&fns);
        assert_eq!(ranked[0].name, "parse");
        assert!(ranked[0].score > ranked[1].score);
    }

    #[test]
    fn helper_name_is_penalized() {
        let fns = vec![
            cf("init_helper", "int", &[("data", "const char *")]),
            cf("decode", "int", &[("data", "const char *")]),
        ];
        let ranked = rank_c_targets(&fns);
        assert_eq!(ranked[0].name, "decode");
    }

    #[test]
    fn cpp_string_param_counts_as_buffer() {
        let fns = vec![cppf(
            "parse_request",
            "int",
            &[("body", "const std::string &")],
        )];
        let ranked = rank_cpp_targets(&fns);
        assert!(ranked[0].breakdown.buffer_param > 0);
    }

    #[test]
    fn cpp_ranker_uses_qualified_method_names_and_skips_lifecycle_members() {
        let mut constructor = cpp_method("Parser", "Parser", "", &[("seed", "int")]);
        constructor.api.is_constructor = true;
        constructor.api.api_kind = "constructor".to_owned();
        let mut destructor = cpp_method("Parser", "~Parser", "", &[]);
        destructor.api.is_destructor = true;
        destructor.api.api_kind = "destructor".to_owned();
        let method = cpp_method("Parser", "feed", "int", &[("input", "std::string_view")]);

        let ranked = rank_cpp_targets(&[constructor, destructor, method]);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "gov::Parser::feed");
        assert!(
            ranked[0].breakdown.parse_decode_name > 0,
            "Parser class name should count as parser surface"
        );
    }

    #[test]
    fn cpp_ranker_surfaces_templated_function_with_resolved_instantiation() {
        // #455 / §27.5: a templated free function is filtered while it has no
        // resolved specialization, but surfaces once `instantiation_args` is set
        // (from a call site or the --template-instantiate flag).
        let mut unresolved = cppf("parse_as", "T", &[("s", "const std::string &")]);
        unresolved.api.is_template = true;
        unresolved.api.api_kind = "template_function".to_owned();
        unresolved.template_type_params = vec!["T".to_owned()];

        let mut resolved = unresolved.clone();
        resolved.instantiation_args = vec!["int".to_owned()];

        assert!(
            rank_cpp_targets(std::slice::from_ref(&unresolved)).is_empty(),
            "an unresolved template must stay filtered"
        );
        let ranked = rank_cpp_targets(std::slice::from_ref(&resolved));
        assert_eq!(ranked.len(), 1, "a resolved template must be surfaced");
        assert_eq!(ranked[0].name, "parse_as");
    }

    #[test]
    fn cpp_ranker_skips_known_non_public_methods() {
        let mut private = cpp_method("Parser", "reset", "void", &[]);
        private.api.member_access = Some("private".to_owned());
        let mut public = cpp_method("Parser", "parse", "int", &[("input", "std::string_view")]);
        public.api.member_access = Some("public".to_owned());

        let ranked = rank_cpp_targets(&[private, public]);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "gov::Parser::parse");
    }

    #[test]
    fn cpp_ranker_drops_allocator_realloc_free_primitives() {
        // rapidjson `CrtAllocator::Realloc(void *originalPtr, size_t originalSize,
        // size_t newSize)`: binding `originalPtr` to a `(void *)Data` view makes the
        // callee `std::realloc` an invalid pointer -> ASan double-free FALSE POSITIVE.
        // The allocator method must not be a candidate at all; a real parser in the
        // same class still is.
        let realloc = cpp_method(
            "CrtAllocator",
            "Realloc",
            "void *",
            &[
                ("originalPtr", "void *"),
                ("originalSize", "size_t"),
                ("newSize", "size_t"),
            ],
        );
        let free = cpp_method("MemoryPoolAllocator", "Free", "void", &[("ptr", "void *")]);
        let parse = cpp_method("GenericReader", "Parse", "int", &[("json", "const char *")]);

        let ranked = rank_cpp_targets(&[realloc, free, parse]);

        assert_eq!(ranked.len(), 1, "both allocator primitives must be dropped");
        assert_eq!(ranked[0].name, "gov::GenericReader::Parse");
    }

    #[test]
    fn c_ranker_drops_allocator_realloc_but_keeps_lookalike_helper() {
        // A bare `realloc`/`free` taking a `void *` is allocator plumbing (unfuzzable
        // pointer contract); a project helper with a DISTINCT name (`free_node`) is not.
        let fns = vec![
            cf("realloc", "void *", &[("p", "void *"), ("n", "size_t")]),
            cf("free", "void", &[("p", "void *")]),
            cf("free_node", "void", &[("node", "struct node *")]),
            cf(
                "parse",
                "int",
                &[("data", "const char *"), ("len", "size_t")],
            ),
        ];
        let ranked = rank_c_targets(&fns);
        let names: Vec<&str> = ranked.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"realloc"), "realloc must be dropped");
        assert!(!names.contains(&"free"), "free must be dropped");
        assert!(
            names.contains(&"free_node"),
            "free_node is not an allocator primitive"
        );
        assert!(names.contains(&"parse"));
    }

    #[test]
    fn cpp_ranker_preserves_overload_signatures_in_target_names() {
        let mut string_parse =
            cpp_method("Parser", "parse", "int", &[("input", "std::string_view")]);
        string_parse.api.unsupported.push("overload_set".to_owned());
        let mut raw_parse = cpp_method(
            "Parser",
            "parse",
            "int",
            &[("input", "const char *"), ("len", "size_t")],
        );
        raw_parse.api.unsupported.push("overload_set".to_owned());

        let ranked = rank_cpp_targets(&[string_parse, raw_parse]);
        let names = ranked
            .iter()
            .map(|target| target.name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"gov::Parser::parse(std::string_view)"));
        assert!(names.contains(&"gov::Parser::parse(const char *, size_t)"));
    }

    #[test]
    fn standard_qualified_cpp_byte_vectors_count_as_buffers() {
        for cpp_type in [
            "const std::vector<std::uint8_t> &",
            "const std::vector<std::byte> &",
        ] {
            let ranked = rank_cpp_targets(&[cppf("parse_request", "int", &[("body", cpp_type)])]);
            assert!(
                ranked[0].breakdown.buffer_param > 0,
                "{cpp_type} should count as a buffer"
            );
        }
    }

    #[test]
    fn cpp_fixed_byte_array_counts_as_buffer() {
        let ranked = rank_cpp_targets(&[cppf(
            "parse_key",
            "int",
            &[("key", "const std::array<std::byte, 16> &")],
        )]);
        assert!(ranked[0].breakdown.buffer_param > 0);
    }

    #[test]
    fn std_byte_pointer_counts_as_buffer() {
        let ranked = rank_cpp_targets(&[cppf(
            "parse_request",
            "int",
            &[("body", "const std::byte *"), ("len", "std::size_t")],
        )]);
        assert!(ranked[0].breakdown.buffer_param > 0);
        assert!(ranked[0].breakdown.length_param_with_buffer > 0);
    }

    #[test]
    fn cpp_span_counts_as_buffer() {
        let ranked = rank_cpp_targets(&[cppf(
            "parse_request",
            "int",
            &[("body", "std::span<const std::byte>")],
        )]);
        assert!(ranked[0].breakdown.buffer_param > 0);
    }

    #[test]
    fn cpp_filesystem_path_counts_as_buffer() {
        let ranked = rank_cpp_targets(&[cppf(
            "load_config",
            "int",
            &[("path", "const std::filesystem::path &")],
        )]);
        assert!(ranked[0].breakdown.buffer_param > 0);
    }

    #[test]
    fn arity_zero_loses_sweet_spot_bonus() {
        let fns = vec![cf("noop", "void", &[]), cf("tick", "int", &[("x", "int")])];
        let ranked = rank_c_targets(&fns);
        assert_eq!(ranked[0].name, "tick");
        assert_eq!(ranked[0].breakdown.arity_in_sweet_spot, 5);
    }

    #[test]
    fn const_input_buffer_is_attacker_reachable() {
        // PX4 crsf_parse(now, const uint8_t *frame, unsigned len, ...) — the real
        // attacker surface.
        let r = classify_input_reachability(
            "crsf_parse",
            &tp(&[
                "const uint64_t",
                "const uint8_t *",
                "unsigned",
                "uint16_t *",
                "uint16_t",
            ]),
        );
        assert_eq!(r, InputReachability::AttackerReachable);
    }

    #[test]
    fn non_const_output_buffer_serializer_is_not_attacker_reachable() {
        // PX4 write_uint24_t(uint8_t *buf, int &offset, int value) — a serializer
        // whose buffer+offset are firmware-controlled. Must NOT look fuzz-worthy.
        let r = classify_input_reachability("write_uint24_t", &tp(&["uint8_t *", "int &", "int"]));
        assert_eq!(r, InputReachability::OutputSerializer);
        let (b, _) = score_from_signature(
            "write_uint24_t",
            "void",
            &tp(&["uint8_t *", "int &", "int"]),
        );
        assert_eq!(
            b.buffer_param, 0,
            "an output buffer must not earn the buffer bonus"
        );
        assert!(b.no_attacker_input < 0);
    }

    #[test]
    fn internal_helper_with_caller_controlled_args_is_unproven() {
        // PX4 crsf_parse_buffer(uint16_t *values, uint16_t *num_values, uint16_t
        // max_channels) — no untrusted byte buffer; args are firmware-controlled.
        let r = classify_input_reachability(
            "crsf_parse_buffer",
            &tp(&["uint16_t *", "uint16_t *", "uint16_t"]),
        );
        assert_eq!(r, InputReachability::ReachabilityUnproven);
    }

    #[test]
    fn real_parser_out_ranks_the_write_serializer() {
        let fns = vec![
            cf(
                "write_frame_crc",
                "void",
                &[
                    ("buf", "uint8_t *"),
                    ("offset", "int &"),
                    ("buf_size", "int"),
                ],
            ),
            cf(
                "crsf_parse",
                "bool",
                &[("frame", "const uint8_t *"), ("len", "unsigned")],
            ),
        ];
        let ranked = rank_c_targets(&fns);
        assert_eq!(ranked[0].name, "crsf_parse");
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::AttackerReachable
        );
        assert_eq!(
            ranked[1].input_reachability,
            InputReachability::OutputSerializer
        );
        assert!(
            ranked[0].score > ranked[1].score + 40,
            "real parser must clear the serializer by a wide margin: {} vs {}",
            ranked[0].score,
            ranked[1].score
        );
    }

    #[test]
    fn byte_stream_decoder_is_attacker_reachable() {
        // PX4 st24_decode(uint8_t byte, uint8_t *rssi, uint8_t *lost_count,
        // uint16_t *channel_count, uint16_t *channels, uint16_t max_chan_count):
        // the untrusted input is the single streamed `byte`.
        let r = classify_input_reachability(
            "st24_decode",
            &tp(&[
                "uint8_t",
                "uint8_t *",
                "uint8_t *",
                "uint16_t *",
                "uint16_t *",
                "uint16_t",
            ]),
        );
        assert_eq!(r, InputReachability::AttackerReachable);
        // A non-parser function with a leading byte scalar is NOT auto-promoted.
        assert_eq!(
            classify_input_reachability("set_mode", &tp(&["uint8_t", "int"])),
            InputReachability::ReachabilityUnproven
        );
    }

    #[test]
    fn mutable_input_buffer_under_parser_name_is_reachable() {
        // Some C decoders read+rewrite a mutable buffer: decode(uint8_t *buf,
        // size_t len). Parser name + length + byte buffer -> attacker-reachable.
        let r = classify_input_reachability("dsm_decode", &tp(&["uint8_t *", "size_t"]));
        assert_eq!(r, InputReachability::AttackerReachable);
        // But a bare mutable buffer with no length and a non-parser name is not.
        let r2 = classify_input_reachability("set_buffer", &tp(&["uint8_t *"]));
        assert_eq!(r2, InputReachability::ReachabilityUnproven);
    }

    #[test]
    fn typedef_and_named_length_params_earn_the_length_bonus() {
        // zlib: int uncompress(Bytef *dest, uLongf *destLen,
        //                      const Bytef *source, uLong sourceLen).
        // `source` (Bytef = unsigned char) is the const input buffer; `sourceLen`
        // is a length the type list can't see (uLong) but the typedef list and
        // the param NAME both reveal it — without the bonus zlib's real entry
        // point ranked below internal read_* helpers.
        let (b, reach) = score_from_signature(
            "uncompress",
            "int",
            &[
                ("dest", "Bytef *"),
                ("destLen", "uLongf *"),
                ("source", "const Bytef *"),
                ("sourceLen", "uLong"),
            ],
        );
        assert_eq!(reach, InputReachability::AttackerReachable);
        assert_eq!(
            b.buffer_param, 30,
            "const Bytef* source is the input buffer"
        );
        assert_eq!(
            b.length_param_with_buffer, 15,
            "uLong sourceLen must count as a length (typedef + name)"
        );
        assert_eq!(b.parse_decode_name, 15, "uncompress is a codec entry point");
    }

    #[test]
    fn bespoke_typedef_length_recognised_by_param_name() {
        // A library's OWN length typedef the type list can't know about is still
        // caught by the parameter name — documentation-independent.
        let (b, _) = score_from_signature(
            "img_decode",
            "int",
            &[("data", "const uint8_t *"), ("data_len", "img_size_t")],
        );
        assert_eq!(
            b.length_param_with_buffer, 15,
            "a length recognised only by its name (`data_len`) must still count"
        );
    }

    #[test]
    fn mid_layer_parser_needing_prebuilt_token_context_is_demoted_below_clean_entry() {
        // cgltf: the clean public entry takes raw bytes; the internal json parser
        // also takes a pre-parsed `jsmntok_t const* tokens` array + an index the
        // fuzzer can't synthesize. The clean entry must out-rank the internal one.
        let (clean, reach) = score_from_signature(
            "cgltf_parse",
            "int",
            &[
                ("options", "const cgltf_options *"),
                ("data", "const void *"),
                ("size", "cgltf_size"),
                ("out_data", "cgltf_data **"),
            ],
        );
        assert_eq!(reach, InputReachability::AttackerReachable);
        assert_eq!(
            clean.needs_prebuilt_context, 0,
            "raw-byte entry not demoted"
        );

        let (internal, _) = score_from_signature(
            "cgltf_parse_json_material",
            "int",
            &[
                ("options", "cgltf_options *"),
                ("tokens", "jsmntok_t const *"),
                ("i", "int"),
                ("json_chunk", "const uint8_t *"),
                ("out_material", "cgltf_material *"),
            ],
        );
        assert_eq!(
            internal.needs_prebuilt_context, -60,
            "a parser needing a pre-built token array is demoted"
        );
        assert!(
            clean.total > internal.total,
            "clean raw-byte entry must out-score the token-context parser: {} vs {}",
            clean.total,
            internal.total
        );
    }

    #[test]
    fn allocator_and_context_pointers_do_not_trigger_prebuilt_context_demotion() {
        // drwav: `const drwav_allocation_callbacks* pAllocationCallbacks` is a
        // harness-synthesizable allocator, NOT attacker-supplied context, so the
        // real decode entry must keep its full score.
        let (b, _) = score_from_signature(
            "drwav_open_memory_and_read_pcm_frames_f32",
            "float *",
            &[
                ("data", "const void *"),
                ("dataSize", "size_t"),
                ("channelsOut", "unsigned int *"),
                ("sampleRateOut", "unsigned int *"),
                ("totalFrameCountOut", "drwav_uint64 *"),
                ("pAllocationCallbacks", "const drwav_allocation_callbacks *"),
            ],
        );
        assert_eq!(
            b.needs_prebuilt_context, 0,
            "an allocator/callbacks context param is not pre-built attacker input"
        );
        // And a const options pointer is likewise exempt.
        let (b2, _) = score_from_signature(
            "decode",
            "int",
            &[
                ("opts", "const decode_options *"),
                ("data", "const uint8_t *"),
            ],
        );
        assert_eq!(b2.needs_prebuilt_context, 0, "const options pointer exempt");
    }

    #[test]
    fn stream_reader_reference_is_prebuilt_context_but_string_and_config_refs_are_not() {
        // tinyobjloader `sr_parseInt(StreamReader &, int *, std::string *, const
        // std::string &)`: the `StreamReader &` is a caller-populated reader the
        // fuzzer cannot synthesize, so this mid-layer sub-parser must be demoted
        // below the clean public entry (it ranked above `ParseFromString`).
        let (sub, _) = score_from_signature(
            "sr_parseInt",
            "bool",
            &[
                ("sr", "StreamReader &"),
                ("out", "int *"),
                ("err", "std::string *"),
                ("token", "const std::string &"),
            ],
        );
        assert_eq!(
            sub.needs_prebuilt_context, -60,
            "a StreamReader& prebuilt-context sub-parser must be demoted",
        );
        // The idiomatic public C++ parser entry takes only synthesizable refs: two
        // fuzzable std::strings + a default-constructible config. NOT prebuilt
        // context, so no demotion, and it must out-score the sub-parser.
        let (entry, _) = score_from_signature(
            "tinyobj::ObjReader::ParseFromString",
            "bool",
            &[
                ("obj_text", "const std::string &"),
                ("mtl_text", "const std::string &"),
                ("config", "const ObjReaderConfig &"),
            ],
        );
        assert_eq!(
            entry.needs_prebuilt_context, 0,
            "fuzzable std::string + default-constructible config refs are not context",
        );
        assert!(
            entry.total > sub.total,
            "public string-in entry must out-score the StreamReader& sub-parser: entry={} sub={}",
            entry.total,
            sub.total,
        );
    }

    #[test]
    fn decompressor_out_ranks_compressor_of_the_same_shape() {
        // The attacker-facing codec surface is DEcompression; a compressor
        // serializes the caller's own data. Same buffer+length shape, opposite
        // direction — lz4 ranked `LZ4_compress_*` #1 over `LZ4_decompress_safe`.
        let (comp, _) = score_from_signature(
            "LZ4_compress_default",
            "int",
            &[
                ("src", "const char *"),
                ("dst", "char *"),
                ("srcSize", "int"),
                ("dstCapacity", "int"),
            ],
        );
        let (decomp, _) = score_from_signature(
            "LZ4_decompress_safe",
            "int",
            &[
                ("src", "const char *"),
                ("dst", "char *"),
                ("compressedSize", "int"),
                ("dstCapacity", "int"),
            ],
        );
        assert_eq!(comp.compressor_name, -25, "compressor demoted");
        assert_eq!(decomp.compressor_name, 0, "decompressor not demoted");
        assert!(
            decomp.total > comp.total,
            "decompressor must out-rank compressor: {} vs {}",
            decomp.total,
            comp.total
        );
        // The `deflate`/`inflate` pair must split correctly despite the shared
        // `*flate` shape: deflate is compression, inflate is decompression.
        let (deflate, _) =
            score_from_signature("deflate", "int", &[("strm", "z_streamp"), ("flush", "int")]);
        assert_eq!(deflate.compressor_name, -25, "deflate is compression");
        let (inflate, _) =
            score_from_signature("inflate", "int", &[("strm", "z_streamp"), ("flush", "int")]);
        assert_eq!(inflate.compressor_name, 0, "inflate is decompression");
    }

    #[test]
    fn program_main_and_cli_arg_parsers_are_demoted_not_dropped() {
        // A program `main` is dropped at the discovery layer (the generated harness
        // defines its own `int main(...)`, so including the target's `main` always
        // fails with a duplicate-main link error). The scorer still DEMOTES it so any
        // `main` that reaches the ranker via a custom `--include-dir` can't out-rank
        // the real library API (nghttp2's `h2load::main` ranked #1 over the HPACK
        // decoder). Same demotion for CLI argv parsers (`parse_switches`, mozjpeg's
        // cjpeg). This test verifies the score; the discovery drop is in discovery.rs.
        let (main_b, _) = score_from_signature(
            "h2load::main",
            "int",
            &[("argc", "int"), ("argv", "char **")],
        );
        assert_eq!(main_b.helper_or_static_name, -20, "qualified main demoted");
        let (cli_b, _) = score_from_signature(
            "parse_switches",
            "void",
            &[("ci", "cjpeg_info *"), ("argc", "int"), ("argv", "char **")],
        );
        assert_eq!(cli_b.helper_or_static_name, -20, "CLI arg parser demoted");
        // A real parser keeps its full score.
        let (parse_b, _) = score_from_signature(
            "json_parse",
            "int",
            &[("data", "const char *"), ("len", "size_t")],
        );
        assert_eq!(parse_b.helper_or_static_name, 0, "real parser not demoted");
    }

    #[test]
    fn static_internal_function_is_demoted_below_identical_public_one() {
        // cJSON shape: the public `cJSON_Parse` and the internal `static`
        // `get_item_from_pointer` are both byte-consuming, but the static helper is
        // reached through the API, not directly attacker-facing — fuzzing it in
        // isolation produced borrowed-pointer / accumulator-leak FPs. A static
        // function is soft-demoted by linkage even when its name has no helper marker.
        let public = cf("parse_value", "int", &[("data", "const char *")]);
        let mut internal = cf("parse_value", "int", &[("data", "const char *")]);
        internal.is_static = true;
        let (pub_b, _) = score_c_function(&public);
        let (int_b, _) = score_c_function(&internal);
        assert_eq!(pub_b.helper_or_static_name, 0, "public not demoted");
        assert_eq!(int_b.helper_or_static_name, -20, "static linkage demoted");
        assert_eq!(int_b.total, pub_b.total - 20);

        // The static linkage penalty does not stack on top of a name-based marker.
        let mut static_helper = cf("alloc_buffer_helper", "void *", &[("n", "size_t")]);
        static_helper.is_static = true;
        let (h_b, _) = score_c_function(&static_helper);
        assert_eq!(
            h_b.helper_or_static_name, -20,
            "name marker + static linkage is a single -20, not -40"
        );
    }

    #[test]
    fn reserved_and_internal_naming_conventions_are_demoted() {
        // §26.3: a symbol that follows the C reserved / library-internal naming
        // conventions (leading underscore, an interior double underscore, an
        // `_impl`/`_internal` worker) is reached through the public API, not
        // directly attacker-facing, so it is demoted below a real public parser.
        for internal in [
            "stb__threadq_enqueue", // stb's interior double-underscore internals
            "_readdir_raw",         // leading underscore (reserved)
            "parse_value_impl",     // `_impl` worker
            "json__scan",           // C-reserved double underscore
            "ns::_detail_step",     // namespaced leading-underscore leaf
        ] {
            assert!(
                name_has_helper_marker(internal),
                "{internal} should be marked internal/reserved"
            );
            let (b, _) = score_from_signature(internal, "int", &[("data", "const char *")]);
            assert_eq!(
                b.helper_or_static_name, -20,
                "{internal} must be demoted by the internal-name marker"
            );
        }
        // A genuine public parser keeps its full score (no spurious demotion).
        for public in ["json_parse", "toml_parse", "cJSON_Parse", "read_header"] {
            assert!(
                !name_has_helper_marker(public),
                "{public} must not be mistaken for an internal symbol"
            );
        }
        // And the public entry out-ranks the interior-double-underscore internal
        // of the same byte-buffer shape.
        let ranked = rank_c_targets(&[
            cf(
                "stb__threadq_enqueue",
                "int",
                &[("data", "const char *"), ("len", "size_t")],
            ),
            cf(
                "qoi_decode",
                "int",
                &[("data", "const char *"), ("len", "size_t")],
            ),
        ]);
        assert_eq!(ranked[0].name, "qoi_decode");
    }

    #[test]
    fn static_void_context_callback_ranks_below_public_entry_point() {
        // Campaign fix: a static internal reader/callback with an opaque `void *`
        // context (inih ini_reader_string, microtar file_read) is reached only via
        // a function-pointer cast with a caller-built context, never an
        // attacker-controlled entry point. Harnessing it fabricates the opaque
        // context from raw bytes -> a false critical crash in the library. It must
        // rank below a real public parser of the same byte-buffer shape.
        let reader = CFunction {
            is_static: true,
            ..cf(
                "ini_reader_string",
                "char *",
                &[("str", "char *"), ("num", "int"), ("stream", "void *")],
            )
        };
        let public = cf(
            "ini_parse_string",
            "int",
            &[("data", "const char *"), ("handler", "int")],
        );
        let ranked = rank_c_targets(&[reader, public]);
        assert_eq!(
            ranked[0].name, "ini_parse_string",
            "public entry point must outrank the static void* callback"
        );
        assert!(
            ranked
                .iter()
                .find(|t| t.name == "ini_reader_string")
                .unwrap()
                .score
                < ranked
                    .iter()
                    .find(|t| t.name == "ini_parse_string")
                    .unwrap()
                    .score
        );
    }

    #[test]
    fn fixed_width_value_accessor_is_demoted_below_real_parser() {
        // Campaign #26: mpack's header-only inline value getters (mpack_load_u16/
        // mpack_load_double) are fixed-width scalar reads, not attacker parser
        // entries; the `load` keyword bonus mis-promoted them to the top (where their
        // `(void)R` harness is DCE'd at -O1 -> hollow built+fuzzed). They must rank
        // below a real parser, with the load bonus dropped and a getter demotion.
        let ranked = rank_c_targets(&[
            cf("mpack_load_u16", "uint16_t", &[("p", "const char *")]),
            cf("mpack_load_double", "double", &[("p", "const char *")]),
            cf(
                "mpack_parse",
                "int",
                &[("data", "const char *"), ("len", "size_t")],
            ),
        ]);
        assert_eq!(ranked[0].name, "mpack_parse");
        let acc = ranked.iter().find(|t| t.name == "mpack_load_u16").unwrap();
        assert_eq!(
            acc.breakdown.parse_decode_name, 0,
            "the load keyword bonus must be dropped for a fixed-width accessor"
        );
        assert!(
            acc.breakdown.helper_or_static_name < 0,
            "a fixed-width value accessor must be demoted"
        );
        // A real parser keeps its parser bonus and is not demoted.
        let parser = ranked.iter().find(|t| t.name == "mpack_parse").unwrap();
        assert_eq!(parser.breakdown.parse_decode_name, 15);
    }

    #[test]
    fn unsafe_prefixed_opaque_accessor_ranks_below_public_entry() {
        // Campaign #5: yyjson's `unsafe_`-prefixed inline accessors take an opaque
        // handle as `void *` (the const storage is hidden behind a `*_api_inline`
        // export macro the non-preprocessing parser can't see, so `is_static` is
        // false). Fuzzing one feeds raw bytes as the opaque handle -> false OOB
        // storm. They must rank below a real public byte-buffer parser even when
        // the parser doesn't mark them static.
        let accessor = cf("unsafe_yyjson_get_len", "size_t", &[("val", "void *")]);
        let public = cf(
            "yyjson_read",
            "int",
            &[("dat", "const char *"), ("len", "size_t")],
        );
        let ranked = rank_c_targets(&[accessor, public]);
        assert_eq!(
            ranked[0].name, "yyjson_read",
            "public parser must outrank the unsafe_ opaque accessor"
        );
        let acc = ranked
            .iter()
            .find(|t| t.name == "unsafe_yyjson_get_len")
            .unwrap();
        // Both the helper-marker demotion (-20) and the standalone opaque-void*
        // demotion (-100) must apply even though is_static is false.
        assert_eq!(acc.breakdown.helper_or_static_name, -120);
        assert!(name_has_helper_marker("unsafe_yyjson_get_str"));
    }

    #[test]
    fn opaque_void_with_length_is_not_demoted_as_handle() {
        // Guard: a non-static `(const void *data, size)` raw-byte data channel
        // (cgltf_parse) is a legit attacker entry — the void* is paired with a
        // length-named scalar, so the standalone-opaque-handle demotion must NOT
        // fire for it.
        let f = cf(
            "cgltf_parse",
            "int",
            &[("data", "const void *"), ("size", "cgltf_size")],
        );
        let (b, _) = score_c_function(&f);
        assert_eq!(
            b.helper_or_static_name, 0,
            "a (const void*, size) data channel must not be demoted as an opaque handle"
        );
    }

    #[test]
    fn getopt_and_config_setters_are_demoted_not_dropped() {
        // getopt-family CLI parsers (libde265 `extra/getopt.c`) consume argv via a
        // fixed option table, not attacker file/network bytes — a vendored libc
        // shim. Hands-off auto ranked `getopt_internal` at 60; demote.
        let (go_b, _) = score_from_signature(
            "getopt_internal",
            "int",
            &[
                ("argc", "int"),
                ("argv", "char **"),
                ("shortopts", "const char *"),
            ],
        );
        assert_eq!(go_b.helper_or_static_name, -20, "getopt demoted");
        // Config / parameter setters take an option-NAME key (matched against a
        // static table) + a value, not parsed input. Fuzzing in isolation only
        // trips their own "unknown option" contract assert — an isolation FP, not
        // an attacker path (libde265 `config_parameters::set_int`:421 was the only
        // "finding" of a hands-off libde265 hunt).
        let (set_b, _) = score_from_signature(
            "config_parameters::set_int",
            "bool",
            &[("param", "const char *"), ("value", "int")],
        );
        assert_eq!(set_b.helper_or_static_name, -20, "config setter demoted");
        let (setp_b, _) = score_from_signature(
            "de265_error::en265_set_parameter_int",
            "void",
            &[("name", "const char *"), ("value", "int")],
        );
        assert_eq!(setp_b.helper_or_static_name, -20, "set_parameter demoted");
        // Guard against over-demotion: a real parser taking a char* is NOT a setter.
        let (parse_b, _) = score_from_signature(
            "toml_parse",
            "int",
            &[("conf", "char *"), ("errbuf", "char *"), ("errsz", "int")],
        );
        assert_eq!(
            parse_b.helper_or_static_name, 0,
            "real parser must not be demoted by the setter markers"
        );
    }
}
