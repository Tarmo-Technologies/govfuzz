// SPDX-License-Identifier: Apache-2.0

use crate::c_decoders::{
    select_c_decoder, select_c_decoder_with_registry_cpp, CDecoderError, CParamEmission,
};
use type_model::TypeRegistry;

/// Tunable caps for the C++ decoder's container / bitset / fixed-array synthesis
/// (§27.11). Defaults reproduce the historical hardcoded values EXACTLY, so a
/// default-limits run is byte-identical to the pre-§27.11 emission; the CLI flags
/// `--container-size-max` / `--bitset-max-size` / `--array-max-size` override
/// them per target. The per-parameter OOM byte budget ([`MAX_PARAM_BYTES`]) is
/// always enforced on top of these so a large configured cap can't blow memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CppDecoderLimits {
    /// Upper bound on a dynamic container's fuzzed element COUNT
    /// (`gf_bounded_length(&Cur, 0, N)` for `vector`/`set`/`map`/`span`/…);
    /// default 16. Clamped down further by the byte budget for known-size
    /// elements (see [`container_count_cap`]).
    pub container_size_max: usize,
    /// Largest `std::bitset<N>` whose `N` bits are decoded individually before
    /// the parameter is skipped; default 4096.
    pub bitset_max_size: usize,
    /// Largest `std::array<T, N>` element COUNT accepted when `T`'s byte size is
    /// not known at codegen time; default 4096. Known-size elements are bounded
    /// by [`MAX_PARAM_BYTES`] instead (see [`array_within_budget`]).
    pub array_max_size: usize,
}

impl Default for CppDecoderLimits {
    fn default() -> Self {
        CppDecoderLimits {
            container_size_max: 16,
            bitset_max_size: 4096,
            array_max_size: 4096,
        }
    }
}

/// Render a libFuzzer-style decoder for the given C++ type and parameter name.
/// Falls back to the C decoder for scalar/pointer parameters and adds C++
/// idioms (`std::string`, `std::string_view`, byte vectors, paths).
/// Prefix `std::` onto unqualified standard-library type names. A library that
/// does `using std::string;` / `using namespace std;` spells its parameters as
/// bare `string`, `vector<...>`, `map<...>`, but the generated harness has no
/// such using-directive — so the decoder must both recognise and emit the
/// qualified spelling (json11's internal `const string &` params, etc.). A
/// token already preceded by `::` is left as-is.
pub(crate) fn qualify_std_type_names(s: &str) -> String {
    const STD_NAMES: &[&str] = &[
        "string",
        "wstring",
        "u8string",
        "u16string",
        "u32string",
        "string_view",
        "wstring_view",
        "u8string_view",
        "u16string_view",
        "u32string_view",
        "vector",
        "array",
        "deque",
        "list",
        "forward_list",
        "map",
        "multimap",
        "unordered_map",
        "unordered_multimap",
        "set",
        "multiset",
        "unordered_set",
        "unordered_multiset",
        "pair",
        "tuple",
        "optional",
        "variant",
        "monostate",
    ];
    let bytes = s.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if is_ident(bytes[i]) && (i == 0 || !is_ident(bytes[i - 1])) {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            let token = &s[start..i];
            // Already qualified (`std::string`, `foo::string`) -> leave it.
            let already_qualified = start >= 2 && &bytes[start - 2..start] == b"::";
            if !already_qualified && STD_NAMES.contains(&token) {
                out.push_str("std::");
            }
            out.push_str(token);
        } else {
            // Preserve a complete UTF-8 scalar. Advancing one byte at a time
            // could leave `i` inside a multibyte character; the next ASCII
            // identifier then made the `start - 2..start` string slice panic.
            let ch = s[i..].chars().next().expect("i is within the UTF-8 string");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Strip a top-level `const`/`volatile` cv-qualifier from a BY-VALUE C++
/// parameter type so its base type flows through the normal decoder path.
///
/// A cv-qualifier on a by-value parameter (`const bool`, `const double`,
/// `const std::size_t`, east-const `int const`) is irrelevant to the caller —
/// you still pass a value — but it previously suppressed the scalar/aggregate
/// decoder and the target/step was skipped ("unsupported parameter type 'const
/// bool'"; campaign: taocpp-json). Only BY-VALUE types are stripped: a pointer
/// (`const char *`, a pointer to const DATA) or a reference (`const T &`, bound
/// differently and handled by the existing reference paths) keeps its qualifier.
/// Handles both west-const (`const T`) and east-const (`T const`) spellings, and
/// only TOP-LEVEL tokens — an inner qualifier (`std::vector<const int>`) is left
/// intact because it is part of an unsplittable template token.
fn strip_byvalue_top_level_cv(cpp_type: &str) -> String {
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    // Pointer / reference: the qualifier is meaningful (or handled elsewhere).
    if normalized.contains('*') || normalized.contains('&') {
        return normalized;
    }
    let is_cv = |t: &str| t == "const" || t == "volatile";
    let mut tokens: Vec<&str> = normalized.split(' ').filter(|t| !t.is_empty()).collect();
    // Drop leading/trailing top-level cv tokens, never the final remaining token
    // (degrade-safe: a lone qualifier with no base type is returned unchanged).
    while tokens.len() > 1 && is_cv(tokens[0]) {
        tokens.remove(0);
    }
    while tokens.len() > 1 && is_cv(tokens[tokens.len() - 1]) {
        tokens.pop();
    }
    tokens.join(" ")
}

/// File-PATH C++ parameters: write the fuzz bytes to a temp file and pass the path
/// (the file CONTENT is the fuzz input) — the C++ analogue of the C `file_path_param`
/// decoder. A `const char *`/`char *`, `std::string`, or `std::string_view` is treated
/// as a file path only when its NAME marks it (`filename`/`filepath`/`pathname`/
/// `*_path`/…), so ordinary string params are unchanged. (`std::filesystem::path` is
/// left to its existing string decoder — it is as often parsed as it is opened.)
/// Unlocks path-only format readers (e.g. libE57Format's `Reader(const ustring&)`).
fn select_cpp_file_path_decoder(stripped: &str, name: &str) -> Option<CParamEmission> {
    let charptr = matches!(stripped, "char *" | "char*");
    let stringish = matches!(
        stripped,
        "std::string" | "std::string_view" | "std::u8string" | "std::u8string_view"
    );
    if !(crate::c_decoders::is_file_path_param_name(name) && (charptr || stringish)) {
        return None;
    }
    let make = format!(
        "char {name}_path[gf_tempfile_path_len]; \
         const char *{name}_made = gf_make_tempfile(Data, Size, {name}_path)"
    );
    let p = format!("{name}_made ? {name}_path : \"\"");
    let (decl, c_type) = if charptr {
        (
            format!("{make}; const char * {name} = {p}"),
            "const char *".to_owned(),
        )
    } else if stripped == "std::string_view" {
        // string_view does not own — back it with a std::string local that
        // outlives the call.
        (
            format!("{make}; std::string {name}_s({p}); std::string_view {name}({name}_s)"),
            "std::string_view".to_owned(),
        )
    } else if stripped == "std::u8string_view" {
        // C++20 char8_t path view (tomlplusplus parse_file). Back it with an owned
        // std::u8string built from the temp-file path so the view stays valid.
        (
            format!(
                "{make}; std::u8string {name}_s(reinterpret_cast<const char8_t *>({p})); \
                 std::u8string_view {name}({name}_s)"
            ),
            "std::u8string_view".to_owned(),
        )
    } else if stripped == "std::u8string" {
        (
            format!("{make}; std::u8string {name}(reinterpret_cast<const char8_t *>({p}))"),
            "const std::u8string &".to_owned(),
        )
    } else {
        (
            format!("{make}; std::string {name}({p})"),
            "const std::string &".to_owned(),
        )
    };
    Some(CParamEmission {
        support: None,
        decl,
        arg: name.to_owned(),
        c_type,
        free: Some(format!("if ({name}_made) unlink({name}_path)")),
    })
}

pub fn select_cpp_decoder(cpp_type: &str, name: &str) -> Option<CParamEmission> {
    select_cpp_decoder_limited(cpp_type, name, &CppDecoderLimits::default())
}

/// [`select_cpp_decoder`] with caller-supplied [`CppDecoderLimits`] (§27.11).
pub(crate) fn select_cpp_decoder_limited(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let qualified = qualify_std_type_names(cpp_type);
    // Strip a top-level `const`/`volatile` from a BY-VALUE parameter so `const
    // bool` decodes exactly like `bool` (see [`strip_byvalue_top_level_cv`]).
    // A cv-qualifier on a by-value parameter is meaningless to the caller — you
    // still pass a value — but it previously suppressed the scalar/aggregate
    // decoder, so taocpp-json's `const bool`/`const double` steps were skipped
    // ("unsupported parameter type 'const bool'"). Pointer-to-const (`const char
    // *`) and const-reference (`const T &`) types keep their qualifier and flow
    // through the existing pointer/reference paths unchanged.
    let cpp_type = strip_byvalue_top_level_cv(&qualified);
    let cpp_type = cpp_type.as_str();
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    // Normalize a reference/by-value type to its bare referent so `T const &`
    // (east-const) decodes EXACTLY like `const T &` (west-const). Remove the
    // reference first, then strip a top-level `const`/`volatile` on EITHER end:
    // the old code only did `.trim_start_matches("const ")`, so east-const
    // references (`std::string const &`) survived as `std::string const` and
    // matched no arm — skipped "unsupported parameter type". A pointer keeps its
    // qualifier (pointer-to-const `const char *` is meaningful) and only loses a
    // leading `const`, preserving the existing file-path/`char *` routing.
    let no_ref = normalized.trim_end_matches('&').trim();
    let stripped = if no_ref.contains('*') {
        no_ref.trim_start_matches("const ").trim().to_owned()
    } else {
        strip_byvalue_top_level_cv(no_ref)
    }
    .replace("std::size_t", "size_t");

    // `<cstdio>` is permitted to expose the C stream type as `std::FILE`, while
    // the C decoder (and the generated harness's `<stdio.h>`) use `FILE`. They
    // name the same ABI type, so route the qualified spellings through the
    // existing fmemopen/fclose decoder instead of rejecting an otherwise useful
    // stream parser target (legacy Loki's `FPrintf(std::FILE *, ...)`).
    if matches!(
        stripped.as_str(),
        "std::FILE *" | "std::FILE*" | "::FILE *" | "::FILE*"
    ) {
        return select_c_decoder("FILE *", name);
    }

    if let Some(emission) = select_cpp_file_path_decoder(&stripped, name) {
        return Some(emission);
    }

    if let Some(emission) = select_std_function_decoder(&normalized, &stripped, name) {
        return Some(emission);
    }

    if let Some(emission) = select_fixed_byte_array_decoder(&stripped, name, limits) {
        return Some(emission);
    }
    if let Some(emission) = select_std_array_decoder(&stripped, name, limits) {
        return Some(emission);
    }
    if let Some(emission) = select_std_chrono_duration_decoder(&normalized, &stripped, name) {
        return Some(emission);
    }
    if let Some(emission) = select_std_bitset_decoder(&normalized, &stripped, name, limits) {
        return Some(emission);
    }

    match stripped.as_str() {
        "format_args" | "fmt::format_args" => Some(CParamEmission {
            support: None,
            decl: format!("{stripped} {name}{{}}"),
            arg: name.to_owned(),
            c_type: stripped.clone(),
            free: None,
        }),
        "std::monostate" => Some(CParamEmission {
            support: None,
            decl: format!("std::monostate {name}{{}}; (void){name}"),
            arg: name.to_owned(),
            c_type: if is_cpp_reference(&normalized) {
                normalized.clone()
            } else {
                "std::monostate".to_owned()
            },
            free: None,
        }),
        "std::string" => Some(CParamEmission {
            support: None,
            decl: format!(
                "char *_tmp_{name} = gf_c_string(&Cur, 4096); std::string {name}(_tmp_{name}); free(_tmp_{name})",
            ),
            arg: name.to_owned(),
            c_type: "const std::string &".to_owned(),
            free: None,
        }),
        // MFC/ATL CString: a string-shaped param, driven from a fuzz C string via
        // the govfuzz MFC stub's `CString(const char *)` (see cross_target.rs
        // MFC_STUB). Covers `CString` / `const CString &` / `CStringA`.
        "CString" | "CStringA" | "ATL::CStringA" | "ATL::CString" => Some(CParamEmission {
            support: None,
            decl: format!(
                "char *_tmp_{name} = gf_c_string(&Cur, 4096); CString {name}(_tmp_{name} ? _tmp_{name} : \"\"); free(_tmp_{name})",
            ),
            arg: name.to_owned(),
            c_type: "const CString &".to_owned(),
            free: None,
        }),
        "std::optional<std::string>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::optional<std::string> {name}; if (gf_u8(&Cur) & 1) {{ char *_tmp_{name} = gf_c_string(&Cur, 4096); {name}.emplace(_tmp_{name} ? _tmp_{name} : \"\"); free(_tmp_{name}); }} (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::optional<std::string>".to_owned(),
            free: None,
        }),
        "std::filesystem::path" => Some(CParamEmission {
            support: None,
            decl: format!(
                "char *_tmp_{name} = gf_c_string(&Cur, 4096); std::filesystem::path {name}(_tmp_{name}); free(_tmp_{name})",
            ),
            arg: name.to_owned(),
            c_type: "const std::filesystem::path &".to_owned(),
            free: None,
        }),
        "std::string_view" => Some(CParamEmission {
            support: None,
            decl: format!(
                "const uint8_t *_gf_sv_ptr_{name} = nullptr; size_t _gf_sv_len_{name} = 0; gf_data_slice(&Cur, &_gf_sv_ptr_{name}, &_gf_sv_len_{name}); std::string_view {name}(reinterpret_cast<const char *>(_gf_sv_ptr_{name}), _gf_sv_len_{name})",
            ),
            arg: name.to_owned(),
            c_type: "std::string_view".to_owned(),
            free: None,
        }),
        // C++20 char8_t string types (#46): char8_t is a 1-byte unsigned type, so a
        // u8string / u8string_view decodes directly off the fuzz bytes exactly like
        // std::string_view (tomlplusplus parse_file takes a u8string_view). Without
        // these arms the trivially byte-decodable type is misrouted to the opaque
        // Phase-C path and the whole target is skipped.
        "std::u8string_view" => Some(CParamEmission {
            support: None,
            decl: format!(
                "const uint8_t *_gf_sv_ptr_{name} = nullptr; size_t _gf_sv_len_{name} = 0; gf_data_slice(&Cur, &_gf_sv_ptr_{name}, &_gf_sv_len_{name}); std::u8string_view {name}(reinterpret_cast<const char8_t *>(_gf_sv_ptr_{name}), _gf_sv_len_{name})",
            ),
            arg: name.to_owned(),
            c_type: "std::u8string_view".to_owned(),
            free: None,
        }),
        "std::u8string" => Some(CParamEmission {
            support: None,
            decl: format!(
                "const uint8_t *_gf_u8s_ptr_{name} = nullptr; size_t _gf_u8s_len_{name} = 0; gf_data_slice(&Cur, &_gf_u8s_ptr_{name}, &_gf_u8s_len_{name}); std::u8string {name}(reinterpret_cast<const char8_t *>(_gf_u8s_ptr_{name}), _gf_u8s_len_{name})",
            ),
            arg: name.to_owned(),
            c_type: "std::u8string".to_owned(),
            free: None,
        }),
        // char16_t / char32_t views: reinterpreting the raw fuzz buffer to the wider
        // element would be misaligned UB, so build an owned u16string / u32string
        // element-by-element (little-endian) and bind the view to it.
        "std::u16string_view" => Some(unicode_string_view_emission(
            &normalized,
            "std::u16string",
            "std::u16string_view",
            "char16_t",
            2,
            name,
        )),
        "std::u32string_view" => Some(unicode_string_view_emission(
            &normalized,
            "std::u32string",
            "std::u32string_view",
            "char32_t",
            4,
            name,
        )),
        "std::vector<uint8_t>" | "std::vector<unsigned char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<uint8_t> {name}(Data, Data + Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::vector<uint8_t>".to_owned(),
            free: None,
        }),
        "std::vector<std::uint8_t>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<std::uint8_t> {name}(Data, Data + Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::vector<std::uint8_t>".to_owned(),
            free: None,
        }),
        "std::vector<char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<char> {name}(reinterpret_cast<const char *>(Data), reinterpret_cast<const char *>(Data) + Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::vector<char>".to_owned(),
            free: None,
        }),
        "std::vector<std::byte>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<std::byte> {name}(reinterpret_cast<const std::byte *>(Data), reinterpret_cast<const std::byte *>(Data) + Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::vector<std::byte>".to_owned(),
            free: None,
        }),
        "std::vector<std::string>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<std::string> {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ char *_tmp_{name} = gf_c_string(&Cur, 256); {name}.emplace_back(_tmp_{name} ? _tmp_{name} : \"\"); free(_tmp_{name}); }} (void){name}",
                cap = container_count_cap("std::string", limits.container_size_max),
            ),
            arg: name.to_owned(),
            c_type: "const std::vector<std::string> &".to_owned(),
            free: None,
        }),
        "std::span<uint8_t>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<uint8_t> _gf_span_storage_{name}(Data, Data + Size); std::span<uint8_t> {name}(_gf_span_storage_{name}.data(), _gf_span_storage_{name}.size()); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<uint8_t>".to_owned(),
            free: None,
        }),
        "std::span<std::uint8_t>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<std::uint8_t> _gf_span_storage_{name}(Data, Data + Size); std::span<std::uint8_t> {name}(_gf_span_storage_{name}.data(), _gf_span_storage_{name}.size()); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<std::uint8_t>".to_owned(),
            free: None,
        }),
        "std::span<unsigned char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<unsigned char> _gf_span_storage_{name}(Data, Data + Size); std::span<unsigned char> {name}(_gf_span_storage_{name}.data(), _gf_span_storage_{name}.size()); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<unsigned char>".to_owned(),
            free: None,
        }),
        "std::span<char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<char> _gf_span_storage_{name}(reinterpret_cast<const char *>(Data), reinterpret_cast<const char *>(Data) + Size); std::span<char> {name}(_gf_span_storage_{name}.data(), _gf_span_storage_{name}.size()); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<char>".to_owned(),
            free: None,
        }),
        "std::span<std::byte>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::vector<std::byte> _gf_span_storage_{name}(reinterpret_cast<const std::byte *>(Data), reinterpret_cast<const std::byte *>(Data) + Size); std::span<std::byte> {name}(_gf_span_storage_{name}.data(), _gf_span_storage_{name}.size()); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<std::byte>".to_owned(),
            free: None,
        }),
        "std::span<const uint8_t>" => Some(CParamEmission {
            support: None,
            decl: format!("std::span<const uint8_t> {name}(Data, Size); (void){name}"),
            arg: name.to_owned(),
            c_type: "std::span<const uint8_t>".to_owned(),
            free: None,
        }),
        "std::span<const std::uint8_t>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::span<const std::uint8_t> {name}(reinterpret_cast<const std::uint8_t *>(Data), Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<const std::uint8_t>".to_owned(),
            free: None,
        }),
        "std::span<const unsigned char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::span<const unsigned char> {name}(reinterpret_cast<const unsigned char *>(Data), Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<const unsigned char>".to_owned(),
            free: None,
        }),
        "std::span<const char>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::span<const char> {name}(reinterpret_cast<const char *>(Data), Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<const char>".to_owned(),
            free: None,
        }),
        "std::span<const std::byte>" => Some(CParamEmission {
            support: None,
            decl: format!(
                "std::span<const std::byte> {name}(reinterpret_cast<const std::byte *>(Data), Size); (void){name}",
            ),
            arg: name.to_owned(),
            c_type: "std::span<const std::byte>".to_owned(),
            free: None,
        }),
        _ => select_std_vector_decoder(&stripped, name, limits)
            .or_else(|| {
                select_std_sequence_container_decoder(
                    &stripped,
                    name,
                    "std::deque",
                    "deque",
                    "emplace_back",
                    limits,
                )
            })
            .or_else(|| {
                select_std_sequence_container_decoder(
                    &stripped,
                    name,
                    "std::list",
                    "list",
                    "emplace_back",
                    limits,
                )
            })
            .or_else(|| {
                select_std_sequence_container_decoder(
                    &stripped,
                    name,
                    "std::forward_list",
                    "forward_list",
                    "emplace_front",
                    limits,
                )
            })
            .or_else(|| select_std_set_decoder(&stripped, name, limits))
            .or_else(|| select_std_map_decoder(&stripped, name, limits))
            .or_else(|| select_std_unordered_set_decoder(&stripped, name, limits))
            .or_else(|| select_std_unordered_map_decoder(&stripped, name, limits))
            .or_else(|| select_std_pair_decoder(&stripped, name, limits))
            .or_else(|| select_std_tuple_decoder(&stripped, name, limits))
            .or_else(|| select_std_variant_decoder(&stripped, name, limits))
            .or_else(|| select_std_optional_decoder(&stripped, name, limits))
            .or_else(|| {
                select_std_smart_pointer_decoder(
                    &normalized,
                    &stripped,
                    name,
                    "std::unique_ptr",
                    "unique_ptr",
                    true,
                    limits,
                )
            })
            .or_else(|| {
                select_std_smart_pointer_decoder(
                    &normalized,
                    &stripped,
                    name,
                    "std::shared_ptr",
                    "shared_ptr",
                    false,
                    limits,
                )
            })
            .or_else(|| select_cpp_scalar_alias_decoder(&normalized, name))
            .or_else(|| select_c_decoder(cpp_type, name))
            .or_else(|| select_cpp_ref_scalar_decoder(&stripped, &normalized, name)),
    }
}

/// A plain scalar passed BY (const) REFERENCE — `const bool &`, `const int &`,
/// east-const `bool const &`. The C++ match table has no bare-scalar arms (they
/// live in the C decoder), and the C decoder rejects the `&`-carrying spelling,
/// so these were skipped "unsupported parameter type". Decode the bare value
/// type through the C scalar table (an lvalue local that binds to the const ref)
/// and re-attach the reference spelling to the emitted `c_type`. std scalar
/// aliases (`std::size_t &`) are already handled by
/// [`select_cpp_scalar_alias_decoder`]; a pointer keeps its own paths.
fn select_cpp_ref_scalar_decoder(
    stripped: &str,
    normalized: &str,
    name: &str,
) -> Option<CParamEmission> {
    if !is_cpp_reference(normalized) || stripped.contains('*') {
        return None;
    }
    let mut emission = select_c_decoder(stripped, name)?;
    emission.c_type = normalized.trim().to_owned();
    Some(emission)
}

pub fn select_cpp_decoder_with_registry(
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
) -> Result<CParamEmission, CDecoderError> {
    select_cpp_decoder_with_registry_limited(cpp_type, name, registry, &CppDecoderLimits::default())
}

/// [`select_cpp_decoder_with_registry`] with caller-supplied [`CppDecoderLimits`]
/// (§27.11). The C++ harness build path threads the CLI-configured caps through
/// here so `--container-size-max` / `--bitset-max-size` / `--array-max-size`
/// actually bound the emitted container / bitset / array decoders.
pub fn select_cpp_decoder_with_registry_limited(
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Result<CParamEmission, CDecoderError> {
    // A function-pointer parameter (`utf8_int8_t *(*alloc_func_ptr)(utf8_int8_t *,
    // size_t)`, or a `RetType (*)(...)` / array-pointer `T (*)[N]` declarator)
    // has no scalar/aggregate decoder in the C++ lane; falling through to struct
    // synthesis emits broken code that fails to BUILD. Skip the target cleanly —
    // callback-trampoline synthesis for the C++ lane is a separate effort (the C
    // lane already has it). A member-pointer `Ret (Class::*)(...)` carries `::*`,
    // not `(*`, so it is not caught here.
    if cpp_type.contains("(*") {
        return Err(CDecoderError::new(format!(
            "C++ parameter '{name}' is a function/array pointer ('{cpp_type}'); the C++ lane has \
             no trampoline synthesis for it — skip the target"
        )));
    }
    if let Some(emission) = select_cpp_decoder_limited(cpp_type, name, limits) {
        return Ok(emission);
    }
    let cpp_type = qualify_std_type_names(cpp_type);
    let cpp_type = cpp_type.as_str();
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    // Normalize a reference/by-value type to its bare referent so `T const &`
    // (east-const) decodes EXACTLY like `const T &` (west-const). Remove the
    // reference first, then strip a top-level `const`/`volatile` on EITHER end:
    // the old code only did `.trim_start_matches("const ")`, so east-const
    // references (`std::string const &`) survived as `std::string const` and
    // matched no arm — skipped "unsupported parameter type". A pointer keeps its
    // qualifier (pointer-to-const `const char *` is meaningful) and only loses a
    // leading `const`, preserving the existing file-path/`char *` routing.
    let no_ref = normalized.trim_end_matches('&').trim();
    let stripped = if no_ref.contains('*') {
        no_ref.trim_start_matches("const ").trim().to_owned()
    } else {
        strip_byvalue_top_level_cv(no_ref)
    }
    .replace("std::size_t", "size_t");
    // Resolve a project STRING alias to its real spelling and re-dispatch once, so
    // the string / file-path decoders fire behind it (libE57Format's reader takes
    // `const ustring &`, where `using ustring = std::string;`). Limited to string
    // targets — scalar/struct typedef chains are already handled by `resolve()`
    // below, so we don't disturb them.
    if let Some(target) = registry.alias_target_spelling(&stripped) {
        let t = target.trim();
        if let Some(kind) = classify_string_alias_target(t) {
            if t != stripped {
                match kind {
                    // std::string / char* / std::string_view: rebuild with the
                    // resolved spelling and re-dispatch so the std::string +
                    // file-path arms fire behind the alias (libE57Format's reader
                    // takes `const ustring &`, where `using ustring = std::string;`).
                    StringAliasKind::StdStringLike | StringAliasKind::StdStringView => {
                        let mut rebuilt = String::new();
                        if normalized.starts_with("const ") {
                            rebuilt.push_str("const ");
                        }
                        rebuilt.push_str(t);
                        if normalized.ends_with('&') {
                            rebuilt.push_str(" &");
                        }
                        return select_cpp_decoder_with_registry_limited(
                            &rebuilt, name, registry, limits,
                        );
                    }
                    // A bundled non-std view (csv-parser's `using string_view =
                    // nonstd::string_view;`) can't be re-dispatched, so emit a
                    // slice-backed view typed as the alias's own spelling (#16).
                    StringAliasKind::NonStdStringView => {
                        return Ok(string_view_alias_emission(&normalized, &stripped, name));
                    }
                }
            }
        }
    }
    // Some libraries expose a string-view type directly rather than through a
    // project alias (RE2 uses `absl::string_view`). Check this only after alias
    // resolution so a project `string_view` alias to std::string_view keeps the
    // standard decoder.
    if matches!(
        classify_string_alias_target(&stripped),
        Some(StringAliasKind::NonStdStringView)
    ) {
        return Ok(string_view_alias_emission(&normalized, &stripped, name));
    }
    if let Some(emission) =
        select_std_optional_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_array_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_vector_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) = select_std_sequence_container_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::deque",
        "deque",
        "emplace_back",
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) = select_std_sequence_container_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::list",
        "list",
        "emplace_back",
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) = select_std_sequence_container_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::forward_list",
        "forward_list",
        "emplace_front",
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_pair_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_tuple_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_variant_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) = select_std_associative_map_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::map",
        "map",
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) = select_std_associative_map_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::unordered_map",
        "unordered_map",
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) =
        select_std_span_decoder_with_registry(&normalized, &stripped, name, registry, limits)
    {
        return Ok(emission);
    }
    if let Some(emission) = select_std_smart_pointer_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::unique_ptr",
        "unique_ptr",
        true,
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    if let Some(emission) = select_std_smart_pointer_decoder_with_registry(
        &normalized,
        &stripped,
        name,
        "std::shared_ptr",
        "shared_ptr",
        false,
        registry,
        limits,
    ) {
        return Ok(emission);
    }
    // Prefer a visible aggregate/enum/alias shape over neutral construction: its
    // public fields are genuine fuzz input. Default construction is only the
    // fallback for an otherwise opaque infrastructure class.
    let bare = cpp_registry_decode_type(cpp_type);
    let registry_fallback = select_c_decoder_with_registry_cpp(&bare, name, registry);
    if let Ok(emission) = registry_fallback.as_ref() {
        return Ok(emission.clone());
    }

    // #353: a class-typed argument (value or reference, not pointer) whose
    // class the caller recorded as default-constructible is default-constructed
    // and passed — no fuzz bytes consumed — so a constructor like
    // `FastCdr(const FastBuffer&)` is harnessable instead of skipped.
    // Legacy CORBA C++ mappings append an implementation-owned exception
    // environment to virtually every generated operation:
    // `CORBA::Environment &ACE_TRY_ENV`.  It is call context, not attacker
    // input, and every supported mapping provides a public empty environment.
    // Treat it like other default-constructible infrastructure arguments even
    // when the ORB headers live outside the scanned source tree.
    // #99: canonicalize the class spelling so EVERY equivalent spelling of the same
    // type takes the same decoder path — `CORBA::Environment &`, `const
    // CORBA::Environment&`, `::CORBA::Environment`, `CORBA::Environment const &`,
    // and `class CORBA::Environment` all resolve to `CORBA::Environment`. Without
    // this a leading `::`, an east-const, a `volatile`, or an elaborated keyword
    // wrongly rejected the parameter as opaque.
    let canonical = canonical_class_spelling(&bare);
    if canonical == "CORBA::Environment" {
        return Ok(CParamEmission {
            support: None,
            decl: format!("{canonical} {name};"),
            arg: name.to_owned(),
            c_type: canonical,
            free: None,
        });
    }
    if !canonical.contains('*') && registry.is_default_constructible_class(&canonical) {
        return Ok(CParamEmission {
            support: None,
            decl: format!("{canonical} {name};"),
            arg: name.to_owned(),
            c_type: canonical,
            free: None,
        });
    }
    // #24: a `T *` output-sink whose default-constructible pointee (std::string,
    // std container, default-constructible class) is stack-allocated and passed by
    // address, instead of skipping the target as "opaque … Phase C" (tinyobjloader
    // LoadObj's std::string* warn/err + container outputs).
    if let Some(emission) = select_cpp_output_sink_decoder(&normalized, name, registry) {
        return Ok(emission);
    }
    registry_fallback
}

/// #99: canonicalize a class-type spelling to a stable key so equivalent spellings
/// take the same decoder path. Strips a leading `::`, leading/trailing
/// `const`/`volatile` qualifiers, and an elaborated `class`/`struct`/`enum`/`union`/
/// `typename` keyword. Whitespace is already collapsed by the caller.
pub(crate) fn canonical_class_spelling(bare: &str) -> String {
    let mut s = bare.trim();
    // Elaborated type specifier (`class Foo`, `struct Foo`, `typename Foo`).
    for keyword in ["class ", "struct ", "enum ", "union ", "typename "] {
        if let Some(rest) = s.strip_prefix(keyword) {
            s = rest.trim();
            break;
        }
    }
    // Leading cv-qualifiers (west-const, possibly repeated / with volatile).
    loop {
        let trimmed = s.trim_start();
        if let Some(rest) = trimmed.strip_prefix("const ") {
            s = rest;
        } else if let Some(rest) = trimmed.strip_prefix("volatile ") {
            s = rest;
        } else {
            s = trimmed;
            break;
        }
    }
    // Trailing cv-qualifiers (east-const: `Foo const`).
    let mut owned = s.trim().to_owned();
    loop {
        let trimmed = owned.trim_end();
        if let Some(rest) = trimmed.strip_suffix(" const") {
            owned = rest.to_owned();
        } else if let Some(rest) = trimmed.strip_suffix(" volatile") {
            owned = rest.to_owned();
        } else {
            owned = trimmed.to_owned();
            break;
        }
    }
    // Leading `::` global-namespace qualifier.
    owned.trim_start_matches("::").trim().to_owned()
}

fn cpp_registry_decode_type(cpp_type: &str) -> String {
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.contains('*') {
        return normalized;
    }
    normalized
        .trim_start_matches("const ")
        .trim()
        .trim_end_matches('&')
        .trim()
        .to_owned()
}

fn select_cpp_scalar_alias_decoder(cpp_type: &str, name: &str) -> Option<CParamEmission> {
    let value_type = cpp_type
        .trim_start_matches("const ")
        .trim()
        .trim_end_matches('&')
        .trim();
    if value_type.contains('*') {
        return None;
    }
    let c_type = cpp_scalar_alias_c_type(value_type)?;
    let mut emission = select_c_decoder(c_type, name)?;
    emission.decl = rewrite_cpp_scalar_decl(&emission.decl, c_type, value_type, name)?;
    emission.c_type = if cpp_type.trim_end().ends_with('&') {
        cpp_type.trim().to_owned()
    } else {
        value_type.to_owned()
    };
    Some(emission)
}

fn cpp_scalar_alias_c_type(cpp_type: &str) -> Option<&'static str> {
    match cpp_type {
        "std::size_t" => Some("size_t"),
        "std::uint8_t" => Some("uint8_t"),
        "std::int8_t" => Some("int8_t"),
        "std::uint16_t" => Some("uint16_t"),
        "std::int16_t" => Some("int16_t"),
        "std::uint32_t" => Some("uint32_t"),
        "std::int32_t" => Some("int32_t"),
        "std::uint64_t" => Some("uint64_t"),
        "std::int64_t" => Some("int64_t"),
        _ => cpp_std_nested_scalar_typedef(cpp_type),
    }
}

/// Nested member typedefs of std containers that are GUARANTEED integral aliases:
/// `std::string::size_type` / `std::vector<T>::size_type` are `size_t`, and
/// `::difference_type` is the signed pointer-width integer (`ptrdiff_t`, decoded
/// like `int64_t` since the C scalar table has no `ptrdiff_t` arm). Without this
/// they fall through to the opaque branch and a pure-scalar out-param target —
/// json11's `Json::parse_multi` takes a `std::string::size_type &` parser-position
/// out-param — is needlessly skipped. The emitted local keeps the real C++ type
/// spelling (via `rewrite_cpp_scalar_decl`), so the cast is exact.
fn cpp_std_nested_scalar_typedef(cpp_type: &str) -> Option<&'static str> {
    if !cpp_type.starts_with("std::") {
        return None;
    }
    if cpp_type.ends_with("::size_type") {
        Some("size_t")
    } else if cpp_type.ends_with("::difference_type") {
        Some("int64_t")
    } else {
        None
    }
}

fn rewrite_cpp_scalar_decl(
    c_decl: &str,
    c_type: &str,
    cpp_type: &str,
    name: &str,
) -> Option<String> {
    let prefix = format!("{c_type} {name} = ");
    let expr = c_decl.strip_prefix(&prefix)?;
    let mut expr = expr.replace(c_type, cpp_type);
    let cpp_cast = format!("({cpp_type})");
    if !expr.trim_start().starts_with(&cpp_cast) {
        expr = format!("{cpp_cast}{expr}");
    }
    Some(format!("{cpp_type} {name} = {expr}"))
}

fn select_std_chrono_duration_decoder(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
) -> Option<CParamEmission> {
    let max_value = match cpp_type {
        "std::chrono::nanoseconds" => 2_000_000_000,
        "std::chrono::microseconds" => 2_000_000,
        "std::chrono::milliseconds" => 60_000,
        "std::chrono::seconds" => 3_600,
        "std::chrono::minutes" => 60,
        "std::chrono::hours" => 24,
        _ => return None,
    };
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        cpp_type.to_owned()
    };
    Some(CParamEmission {
        support: None,
        decl: format!("{cpp_type} {name}(gf_bounded_i32(&Cur, 0, {max_value})); (void){name}"),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

/// Per-parameter byte budget (#465): a fixed array decodes when its total size
/// `len * sizeof(element)` is within ~1 MiB, guarding against per-testcase OOM
/// while letting useful large-but-small-element arrays (`std::array<int, 8192>` =
/// 32 KiB) through, instead of the cruder fixed element-count cap.
const MAX_PARAM_BYTES: usize = 1024 * 1024;

/// The byte size of a C++ primitive element type, or `None` for a non-primitive
/// (whose size isn't known at codegen time — keep the conservative element cap).
fn cpp_primitive_size(ty: &str) -> Option<usize> {
    match ty.trim() {
        "bool" | "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t"
        | "std::int8_t" | "std::uint8_t" => Some(1),
        "short" | "short int" | "unsigned short" | "int16_t" | "uint16_t" | "char16_t"
        | "std::int16_t" | "std::uint16_t" => Some(2),
        "int" | "unsigned" | "unsigned int" | "float" | "int32_t" | "uint32_t" | "char32_t"
        | "wchar_t" | "std::int32_t" | "std::uint32_t" => Some(4),
        "long" | "unsigned long" | "long long" | "unsigned long long" | "double" | "int64_t"
        | "uint64_t" | "size_t" | "std::int64_t" | "std::uint64_t" | "std::size_t" => Some(8),
        _ => None,
    }
}

/// Whether a fixed array of `len` elements of `element_type` is within budget:
/// the per-parameter byte budget ([`MAX_PARAM_BYTES`]) for known-size primitives
/// — this is the array OOM guard — else the configurable element-count cap
/// ([`CppDecoderLimits::array_max_size`], default 4096) for unknown-size elements.
fn array_within_budget(element_type: &str, len: usize, limits: &CppDecoderLimits) -> bool {
    match cpp_primitive_size(element_type) {
        Some(size) => len.saturating_mul(size) <= MAX_PARAM_BYTES,
        None => len <= limits.array_max_size,
    }
}

/// OOM guard (§27.11) for a *dynamic* container's element COUNT: clamp the
/// configured [`CppDecoderLimits::container_size_max`] so the worst-case decode
/// (`count * sizeof(element)`) stays within the per-parameter byte budget
/// ([`MAX_PARAM_BYTES`], ~1 MiB). For an element whose byte size is unknown at
/// codegen time the configured count is used as-is (the default 16 is harmless;
/// only a hand-cranked huge `--container-size-max` on an unknown-size element is
/// unguarded). Never returns below 1 so a non-empty container stays reachable.
/// At the default cap of 16 this is a no-op for every element type, preserving
/// byte-identical emission.
fn container_count_cap(element_type: &str, configured: usize) -> usize {
    match cpp_primitive_size(element_type) {
        Some(size) if size > 0 => configured.min((MAX_PARAM_BYTES / size).max(1)),
        _ => configured,
    }
}

fn select_std_bitset_decoder(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let len = cpp_type
        .strip_prefix("std::bitset<")?
        .strip_suffix('>')?
        .trim()
        .parse::<usize>()
        .ok()?;
    if len > limits.bitset_max_size {
        return None;
    }
    let bitset_type = format!("std::bitset<{len}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        bitset_type.clone()
    };

    Some(CParamEmission {
        support: None,
        decl: format!(
            "{bitset_type} {name}; for (size_t _gf_i_{name} = 0; _gf_i_{name} < {name}.size(); ++_gf_i_{name}) {{ {name}.set(_gf_i_{name}, (gf_u8(&Cur) & 1) != 0); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_fixed_byte_array_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type.strip_prefix("std::array<")?.strip_suffix('>')?;
    let (elem, len) = inner.rsplit_once(',')?;
    let elem = elem.trim();
    let len = len.trim().parse::<usize>().ok()?;
    if len > limits.array_max_size || !is_byte_array_element(elem) {
        return None;
    }

    Some(CParamEmission {
        support: None,
        decl: format!(
            "std::array<{elem}, {len}> {name}{{}}; size_t _gf_copy_{name} = Size < {name}.size() ? Size : {name}.size(); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_copy_{name}; ++_gf_i_{name}) {{ {name}[_gf_i_{name}] = static_cast<{elem}>(Data[_gf_i_{name}]); }} (void){name}",
        ),
        arg: name.to_owned(),
        c_type: format!("const std::array<{elem}, {len}> &"),
        free: None,
    })
}

fn select_std_array_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type.strip_prefix("std::array<")?.strip_suffix('>')?;
    let (element_type, len) = inner.rsplit_once(',')?;
    let element_type = element_type.trim();
    let len = len.trim().parse::<usize>().ok()?;
    if !array_within_budget(element_type, len, limits) || element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_array_{name}_elt");
    let element = select_cpp_decoder_limited(element_type, &element_name, limits)?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }

    Some(CParamEmission {
        support,
        decl: format!(
            "std::array<{element_type}, {len}> {name}{{}}; for (size_t _gf_i_{name} = 0; _gf_i_{name} < {name}.size(); ++_gf_i_{name}) {{ {decl}; {name}[_gf_i_{name}] = {arg}; }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("std::array<{element_type}, {len}>"),
        free: None,
    })
}

fn select_std_array_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type.strip_prefix("std::array<")?.strip_suffix('>')?;
    let (element_type, len) = inner.rsplit_once(',')?;
    let element_type = element_type.trim();
    let len = len.trim().parse::<usize>().ok()?;
    if !array_within_budget(element_type, len, limits) || element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_array_{name}_elt");
    let element =
        select_cpp_decoder_with_registry_limited(element_type, &element_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let array_type = format!("std::array<{element_type}, {len}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        array_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!(
            "{array_type} {name}{{}}; for (size_t _gf_i_{name} = 0; _gf_i_{name} < {name}.size(); ++_gf_i_{name}) {{ {decl}; {name}[_gf_i_{name}] = {arg}; }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_optional_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::optional<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let inner_type = args[0].trim();
    if inner_type.contains('&') {
        return None;
    }

    let inner_name = format!("_gf_optional_{name}");
    let inner = select_cpp_decoder_limited(inner_type, &inner_name, limits)?;
    if inner.free.is_some() {
        return None;
    }

    Some(CParamEmission {
        support: inner.support,
        decl: format!(
            "std::optional<{inner_type}> {name}; if (gf_u8(&Cur) & 1) {{ {}; {name}.emplace({}); }} (void){name}",
            inner.decl, inner.arg
        ),
        arg: name.to_owned(),
        c_type: format!("std::optional<{inner_type}>"),
        free: None,
    })
}

fn select_std_optional_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::optional<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let inner_type = args[0].trim();
    if inner_type.contains('&') {
        return None;
    }

    let inner_name = format!("_gf_optional_{name}");
    let inner =
        select_cpp_decoder_with_registry_limited(inner_type, &inner_name, registry, limits).ok()?;
    if inner.free.is_some() {
        return None;
    }
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        format!("std::optional<{inner_type}>")
    };

    Some(CParamEmission {
        support: inner.support,
        decl: format!(
            "std::optional<{inner_type}> {name}; if (gf_u8(&Cur) & 1) {{ {}; {name}.emplace({}); }} (void){name}",
            inner.decl, inner.arg
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_pair_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::pair<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 2 {
        return None;
    }
    let first_type = args[0].trim();
    let second_type = args[1].trim();
    if first_type.contains('&') || second_type.contains('&') {
        return None;
    }

    let first_name = format!("_gf_pair_{name}_first");
    let second_name = format!("_gf_pair_{name}_second");
    let first = select_cpp_decoder_limited(first_type, &first_name, limits)?;
    let second = select_cpp_decoder_limited(second_type, &second_name, limits)?;
    let CParamEmission {
        support: first_support,
        decl: first_decl,
        arg: first_arg,
        free: first_free,
        ..
    } = first;
    let CParamEmission {
        support: second_support,
        decl: second_decl,
        arg: second_arg,
        free: second_free,
        ..
    } = second;
    if first_free.is_some() || second_free.is_some() {
        return None;
    }

    Some(CParamEmission {
        support: combine_support(first_support, second_support),
        decl: format!(
            "{first_decl}; {second_decl}; std::pair<{first_type}, {second_type}> {name}({first_arg}, {second_arg}); (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("std::pair<{first_type}, {second_type}>"),
        free: None,
    })
}

fn select_std_pair_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::pair<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 2 {
        return None;
    }
    let first_type = args[0].trim();
    let second_type = args[1].trim();
    if first_type.contains('&') || second_type.contains('&') {
        return None;
    }

    let first_name = format!("_gf_pair_{name}_first");
    let second_name = format!("_gf_pair_{name}_second");
    let first =
        select_cpp_decoder_with_registry_limited(first_type, &first_name, registry, limits).ok()?;
    let second =
        select_cpp_decoder_with_registry_limited(second_type, &second_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support: first_support,
        decl: first_decl,
        arg: first_arg,
        free: first_free,
        ..
    } = first;
    let CParamEmission {
        support: second_support,
        decl: second_decl,
        arg: second_arg,
        free: second_free,
        ..
    } = second;
    if first_free.is_some() || second_free.is_some() {
        return None;
    }
    let pair_type = format!("std::pair<{first_type}, {second_type}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        pair_type.clone()
    };

    Some(CParamEmission {
        support: combine_support(first_support, second_support),
        decl: format!(
            "{first_decl}; {second_decl}; {pair_type} {name}({first_arg}, {second_arg}); (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_vector_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::vector<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    if element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_vector_{name}_elt");
    let element = select_cpp_decoder_limited(element_type, &element_name, limits)?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(element_type, limits.container_size_max);

    Some(CParamEmission {
        support,
        decl: format!(
            "std::vector<{element_type}> {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {name}.emplace_back({arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("std::vector<{element_type}>"),
        free: None,
    })
}

fn select_std_vector_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::vector<")?
        .strip_suffix('>')?
        .trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    if element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_vector_{name}_elt");
    let element =
        select_cpp_decoder_with_registry_limited(element_type, &element_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(element_type, limits.container_size_max);
    let vector_type = format!("std::vector<{element_type}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        vector_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!(
            "{vector_type} {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {name}.emplace_back({arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_sequence_container_decoder(
    cpp_type: &str,
    name: &str,
    container: &str,
    variable_prefix: &str,
    insertion_method: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{container}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    if element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_{variable_prefix}_{name}_elt");
    let element = select_cpp_decoder_limited(element_type, &element_name, limits)?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(element_type, limits.container_size_max);

    Some(CParamEmission {
        support,
        decl: format!(
            "{container}<{element_type}> {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {name}.{insertion_method}({arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("{container}<{element_type}>"),
        free: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_std_sequence_container_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    container: &str,
    variable_prefix: &str,
    insertion_method: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{container}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    if element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_{variable_prefix}_{name}_elt");
    let element =
        select_cpp_decoder_with_registry_limited(element_type, &element_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(element_type, limits.container_size_max);
    let container_type = format!("{container}<{element_type}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        container_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!(
            "{container_type} {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {name}.{insertion_method}({arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_set_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    select_std_associative_set_decoder(cpp_type, name, "std::set", "set", limits)
}

fn select_std_unordered_set_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    select_std_associative_set_decoder(
        cpp_type,
        name,
        "std::unordered_set",
        "unordered_set",
        limits,
    )
}

fn select_std_associative_set_decoder(
    cpp_type: &str,
    name: &str,
    container: &str,
    variable_prefix: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{container}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    if element_type.contains('&') {
        return None;
    }

    let element_name = format!("_gf_{variable_prefix}_{name}_elt");
    let element = select_cpp_decoder_limited(element_type, &element_name, limits)?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(element_type, limits.container_size_max);

    Some(CParamEmission {
        support,
        decl: format!(
            "{container}<{element_type}> {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {name}.emplace({arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("{container}<{element_type}>"),
        free: None,
    })
}

fn select_std_map_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    select_std_associative_map_decoder(cpp_type, name, "std::map", "map", limits)
}

fn select_std_unordered_map_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    select_std_associative_map_decoder(
        cpp_type,
        name,
        "std::unordered_map",
        "unordered_map",
        limits,
    )
}

fn select_std_associative_map_decoder(
    cpp_type: &str,
    name: &str,
    container: &str,
    variable_prefix: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{container}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 2 {
        return None;
    }
    let key_type = args[0].trim();
    let value_type = args[1].trim();
    if key_type.contains('&') || value_type.contains('&') {
        return None;
    }

    let key_name = format!("_gf_{variable_prefix}_{name}_key");
    let value_name = format!("_gf_{variable_prefix}_{name}_value");
    let key = select_cpp_decoder_limited(key_type, &key_name, limits)?;
    let value = select_cpp_decoder_limited(value_type, &value_name, limits)?;
    let CParamEmission {
        support: key_support,
        decl: key_decl,
        arg: key_arg,
        free: key_free,
        ..
    } = key;
    let CParamEmission {
        support: value_support,
        decl: value_decl,
        arg: value_arg,
        free: value_free,
        ..
    } = value;
    if key_free.is_some() || value_free.is_some() {
        return None;
    }
    let cap = map_count_cap(key_type, value_type, limits.container_size_max);

    Some(CParamEmission {
        support: combine_support(key_support, value_support),
        decl: format!(
            "{container}<{key_type}, {value_type}> {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {key_decl}; {value_decl}; {name}.emplace({key_arg}, {value_arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type: format!("{container}<{key_type}, {value_type}>"),
        free: None,
    })
}

/// OOM cap for an associative map's pair COUNT: clamp by BOTH the key and the
/// value element budgets (a fuzzed map allocates `count` of each), so neither
/// side can blow [`MAX_PARAM_BYTES`]. At the default cap of 16 this is a no-op.
fn map_count_cap(key_type: &str, value_type: &str, configured: usize) -> usize {
    container_count_cap(key_type, configured).min(container_count_cap(value_type, configured))
}

fn select_std_associative_map_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    container: &str,
    variable_prefix: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{container}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 2 {
        return None;
    }
    let key_type = args[0].trim();
    let value_type = args[1].trim();
    if key_type.contains('&') || value_type.contains('&') {
        return None;
    }

    let key_name = format!("_gf_{variable_prefix}_{name}_key");
    let value_name = format!("_gf_{variable_prefix}_{name}_value");
    let key = select_cpp_decoder_limited(key_type, &key_name, limits)?;
    let value =
        select_cpp_decoder_with_registry_limited(value_type, &value_name, registry, limits).ok()?;
    let CParamEmission {
        support: key_support,
        decl: key_decl,
        arg: key_arg,
        free: key_free,
        ..
    } = key;
    let CParamEmission {
        support: value_support,
        decl: value_decl,
        arg: value_arg,
        free: value_free,
        ..
    } = value;
    if key_free.is_some() || value_free.is_some() {
        return None;
    }
    let cap = map_count_cap(key_type, value_type, limits.container_size_max);
    let map_type = format!("{container}<{key_type}, {value_type}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        map_type.clone()
    };

    Some(CParamEmission {
        support: combine_support(key_support, value_support),
        decl: format!(
            "{map_type} {name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {key_decl}; {value_decl}; {name}.emplace({key_arg}, {value_arg}); }} (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_span_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type.strip_prefix("std::span<")?.strip_suffix('>')?;
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let element_type = args[0].trim();
    let storage_type = element_type.trim_start_matches("const ").trim();
    if storage_type.is_empty()
        || storage_type.contains('&')
        || storage_type.contains('*')
        || storage_type
            .split_whitespace()
            .any(|token| token == "volatile")
    {
        return None;
    }

    let element_name = format!("_gf_span_{name}_elt");
    let element =
        select_cpp_decoder_with_registry_limited(storage_type, &element_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = element;
    if free.is_some() {
        return None;
    }
    let cap = container_count_cap(storage_type, limits.container_size_max);
    let span_type = format!("std::span<{element_type}>");
    let storage_name = format!("_gf_span_storage_{name}");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        span_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!(
            "std::vector<{storage_type}> {storage_name}; size_t _gf_count_{name} = gf_bounded_length(&Cur, 0, {cap}); for (size_t _gf_i_{name} = 0; _gf_i_{name} < _gf_count_{name}; ++_gf_i_{name}) {{ {decl}; {storage_name}.emplace_back({arg}); }} {span_type} {name}({storage_name}.data(), {storage_name}.size()); (void){name}"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_tuple_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::tuple<")?
        .strip_suffix('>')?
        .trim();
    let element_types = split_cpp_type_list(inner)?;
    if element_types.is_empty() || element_types.iter().any(|ty| ty.contains('&')) {
        return None;
    }

    let mut supports = Vec::new();
    let mut decls = Vec::with_capacity(element_types.len());
    let mut args = Vec::with_capacity(element_types.len());
    for (index, element_type) in element_types.iter().enumerate() {
        let element_name = format!("_gf_tuple_{name}_{index}");
        let emission = select_cpp_decoder_limited(element_type, &element_name, limits)?;
        let CParamEmission {
            support,
            decl,
            arg,
            free,
            ..
        } = emission;
        if free.is_some() {
            return None;
        }
        if let Some(support) = support {
            supports.push(support);
        }
        decls.push(decl);
        args.push(arg);
    }

    let joined_types = element_types.join(", ");
    Some(CParamEmission {
        support: combine_supports(supports),
        decl: format!(
            "{}; std::tuple<{joined_types}> {name}({}); (void){name}",
            decls.join("; "),
            args.join(", ")
        ),
        arg: name.to_owned(),
        c_type: format!("std::tuple<{joined_types}>"),
        free: None,
    })
}

fn select_std_tuple_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::tuple<")?
        .strip_suffix('>')?
        .trim();
    let element_types = split_cpp_type_list(inner)?;
    if element_types.is_empty() || element_types.iter().any(|ty| ty.contains('&')) {
        return None;
    }

    let mut supports = Vec::new();
    let mut decls = Vec::with_capacity(element_types.len());
    let mut args = Vec::with_capacity(element_types.len());
    for (index, element_type) in element_types.iter().enumerate() {
        let element_name = format!("_gf_tuple_{name}_{index}");
        let emission =
            select_cpp_decoder_with_registry_limited(element_type, &element_name, registry, limits)
                .ok()?;
        let CParamEmission {
            support,
            decl,
            arg,
            free,
            ..
        } = emission;
        if free.is_some() {
            return None;
        }
        if let Some(support) = support {
            supports.push(support);
        }
        decls.push(decl);
        args.push(arg);
    }

    let joined_types = element_types.join(", ");
    let tuple_type = format!("std::tuple<{joined_types}>");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        tuple_type.clone()
    };
    Some(CParamEmission {
        support: combine_supports(supports),
        decl: format!(
            "{}; {tuple_type} {name}({}); (void){name}",
            decls.join("; "),
            args.join(", ")
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_variant_decoder(
    cpp_type: &str,
    name: &str,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::variant<")?
        .strip_suffix('>')?
        .trim();
    let alternative_types = split_cpp_type_list(inner)?;
    if alternative_types.is_empty() || alternative_types.iter().any(|ty| ty.contains('&')) {
        return None;
    }

    let joined_types = alternative_types.join(", ");
    let variant_type = format!("std::variant<{joined_types}>");
    let mut supports = Vec::new();
    let mut cases = Vec::new();
    let mut default_body = None;
    for (index, alternative_type) in alternative_types.iter().enumerate() {
        let alternative_name = format!("_gf_variant_{name}_{index}");
        let emission = select_cpp_decoder_limited(alternative_type, &alternative_name, limits)?;
        let CParamEmission {
            support,
            decl,
            arg,
            free,
            ..
        } = emission;
        if free.is_some() {
            return None;
        }
        if let Some(support) = support {
            supports.push(support);
        }
        let body = format!("{decl}; return {variant_type}(std::in_place_index<{index}>, {arg});");
        if index == 0 {
            default_body = Some(body);
        } else {
            cases.push(format!("case {index}: {{ {body} }}"));
        }
    }
    let default_body = default_body?;

    Some(CParamEmission {
        support: combine_supports(supports),
        decl: format!(
            "{variant_type} {name} = [&]() -> {variant_type} {{ switch (gf_u8(&Cur) % {}) {{ {} default: {{ {default_body} }} }} }}(); (void){name}",
            alternative_types.len(),
            cases.join(" ")
        ),
        arg: name.to_owned(),
        c_type: variant_type,
        free: None,
    })
}

fn select_std_variant_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let inner = cpp_type
        .strip_prefix("std::variant<")?
        .strip_suffix('>')?
        .trim();
    let alternative_types = split_cpp_type_list(inner)?;
    if alternative_types.is_empty() || alternative_types.iter().any(|ty| ty.contains('&')) {
        return None;
    }

    let joined_types = alternative_types.join(", ");
    let variant_type = format!("std::variant<{joined_types}>");
    let mut supports = Vec::new();
    let mut cases = Vec::new();
    let mut default_body = None;
    for (index, alternative_type) in alternative_types.iter().enumerate() {
        let alternative_name = format!("_gf_variant_{name}_{index}");
        let emission = select_cpp_decoder_with_registry_limited(
            alternative_type,
            &alternative_name,
            registry,
            limits,
        )
        .ok()?;
        let CParamEmission {
            support,
            decl,
            arg,
            free,
            ..
        } = emission;
        if free.is_some() {
            return None;
        }
        if let Some(support) = support {
            supports.push(support);
        }
        let body = format!("{decl}; return {variant_type}(std::in_place_index<{index}>, {arg});");
        if index == 0 {
            default_body = Some(body);
        } else {
            cases.push(format!("case {index}: {{ {body} }}"));
        }
    }
    let default_body = default_body?;
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        variant_type.clone()
    };

    Some(CParamEmission {
        support: combine_supports(supports),
        decl: format!(
            "{variant_type} {name} = [&]() -> {variant_type} {{ switch (gf_u8(&Cur) % {}) {{ {} default: {{ {default_body} }} }} }}(); (void){name}",
            alternative_types.len(),
            cases.join(" ")
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn select_std_smart_pointer_decoder(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    pointer_type: &str,
    variable_prefix: &str,
    move_only: bool,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{pointer_type}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let pointee_type = args[0].trim();
    if pointee_type.contains('&') {
        return None;
    }

    let value_name = format!("_gf_{variable_prefix}_{name}_value");
    let value = select_cpp_decoder_limited(pointee_type, &value_name, limits)?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = value;
    if free.is_some() {
        return None;
    }

    let smart_type = format!("{pointer_type}<{pointee_type}>");
    let maker = if move_only {
        "std::make_unique"
    } else {
        "std::make_shared"
    };
    let call_arg = if move_only && !is_cpp_lvalue_reference(raw_type) {
        format!("std::move({name})")
    } else {
        name.to_owned()
    };
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        smart_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!("{decl}; {smart_type} {name} = {maker}<{pointee_type}>({arg}); (void){name}"),
        arg: call_arg,
        c_type,
        free: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_std_smart_pointer_decoder_with_registry(
    raw_type: &str,
    cpp_type: &str,
    name: &str,
    pointer_type: &str,
    variable_prefix: &str,
    move_only: bool,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Option<CParamEmission> {
    let open = format!("{pointer_type}<");
    let inner = cpp_type.strip_prefix(&open)?.strip_suffix('>')?.trim();
    let args = split_cpp_type_list(inner)?;
    if args.len() != 1 {
        return None;
    }
    let pointee_type = args[0].trim();
    if pointee_type.contains('&') {
        return None;
    }

    let value_name = format!("_gf_{variable_prefix}_{name}_value");
    let value =
        select_cpp_decoder_with_registry_limited(pointee_type, &value_name, registry, limits)
            .ok()?;
    let CParamEmission {
        support,
        decl,
        arg,
        free,
        ..
    } = value;
    if free.is_some() {
        return None;
    }

    let smart_type = format!("{pointer_type}<{pointee_type}>");
    let maker = if move_only {
        "std::make_unique"
    } else {
        "std::make_shared"
    };
    let call_arg = if move_only && !is_cpp_lvalue_reference(raw_type) {
        format!("std::move({name})")
    } else {
        name.to_owned()
    };
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        smart_type.clone()
    };

    Some(CParamEmission {
        support,
        decl: format!("{decl}; {smart_type} {name} = {maker}<{pointee_type}>({arg}); (void){name}"),
        arg: call_arg,
        c_type,
        free: None,
    })
}

/// Decode a `char16_t`/`char32_t` string view (#46). Reinterpreting the raw fuzz
/// buffer to the wider element would be misaligned UB, so build an owned
/// `u16string`/`u32string` element-by-element (little-endian) and bind the view to
/// it; the owned local outlives the target call. `width` is the element byte size.
fn unicode_string_view_emission(
    raw_type: &str,
    owned_type: &str,
    view_type: &str,
    char_type: &str,
    width: usize,
    name: &str,
) -> CParamEmission {
    let ptr = format!("_gf_sv_ptr_{name}");
    let len = format!("_gf_sv_len_{name}");
    let buf = format!("_gf_sv_buf_{name}");
    let idx = format!("_gf_sv_i_{name}");
    let combine = (0..width)
        .map(|b| {
            if b == 0 {
                format!("({char_type}){ptr}[{idx}]")
            } else {
                format!("(({char_type}){ptr}[{idx} + {b}] << {})", b * 8)
            }
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        view_type.to_owned()
    };
    CParamEmission {
        support: None,
        decl: format!(
            "const uint8_t *{ptr} = nullptr; size_t {len} = 0; gf_data_slice(&Cur, &{ptr}, &{len}); {owned_type} {buf}; for (size_t {idx} = 0; {idx} + {width} <= {len}; {idx} += {width}) {{ {buf}.push_back(({char_type})({combine})); }} {view_type} {name}({buf})"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    }
}

/// Classification of a project type alias's resolved target (bug #16). Drives the
/// string-alias redirect in [`select_cpp_decoder_with_registry_limited`].
enum StringAliasKind {
    /// `std::string` (or a `char *` family spelling) — re-dispatch so the
    /// std::string + file-path arms fire behind the alias.
    StdStringLike,
    /// Canonical `std::string_view` — re-dispatch (preserves file-path routing).
    StdStringView,
    /// A bundled non-std view (`nonstd::string_view`, string-view-lite, or a
    /// `basic_string_view<char>` spelling). Constructible from `(const char*,
    /// size_t)` but not re-dispatchable, so it is emitted typed as the alias.
    NonStdStringView,
}

/// Classify an alias's RESOLVED target spelling. `std::string_view` is matched
/// exactly BEFORE the leaf-based non-std check so the canonical view does not fall
/// into the non-std bucket (note `"nonstd::string_view".ends_with("std::string_view")`
/// is true, so a loose `ends_with` would misclassify it).
fn classify_string_alias_target(target: &str) -> Option<StringAliasKind> {
    let t = target.trim();
    if matches!(
        t,
        "std::string" | "::std::string" | "char *" | "char*" | "const char *"
    ) {
        return Some(StringAliasKind::StdStringLike);
    }
    if matches!(t, "std::string_view" | "::std::string_view") {
        return Some(StringAliasKind::StdStringView);
    }
    let leaf = t.rsplit("::").next().unwrap_or(t).trim();
    if leaf == "string_view" || leaf == "basic_string_view<char>" {
        return Some(StringAliasKind::NonStdStringView);
    }
    None
}

/// Emit a slice-backed `string_view` decoder TYPED AS THE PARAMETER'S OWN ALIAS
/// (`csv::string_view`), so a bundled `nonstd::string_view` param — constructible
/// from `(const char*, size_t)` — builds instead of misrouting to Phase-C (#16).
fn string_view_alias_emission(raw_type: &str, value_type: &str, name: &str) -> CParamEmission {
    let c_type = if is_cpp_reference(raw_type) {
        raw_type.trim().to_owned()
    } else {
        value_type.to_owned()
    };
    CParamEmission {
        support: None,
        decl: format!(
            "const uint8_t *_gf_sv_ptr_{name} = nullptr; size_t _gf_sv_len_{name} = 0; gf_data_slice(&Cur, &_gf_sv_ptr_{name}, &_gf_sv_len_{name}); {value_type} {name}(reinterpret_cast<const char *>(_gf_sv_ptr_{name}), _gf_sv_len_{name})"
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    }
}

/// A `T *` OUTPUT-SINK parameter (#24) whose non-const, default-constructible
/// pointee is stack-allocated as a scratch and passed by address — the
/// tinyobjloader `LoadObj(attrib_t*, std::vector<shape_t>*, …, std::string* warn,
/// std::string* err, …)` idiom. Without this the target was skipped and mislabelled
/// "opaque … Phase C". Pointer-to-const (`const T *`, an INPUT the callee reads),
/// `T **`, `void *`, and registry aggregates (already field-filled by the existing
/// pointer path) are left to their existing handlers.
fn select_cpp_output_sink_decoder(
    normalized: &str,
    name: &str,
    registry: &TypeRegistry,
) -> Option<CParamEmission> {
    let t = normalized.trim();
    if t.contains('&') {
        return None;
    }
    let pointee = t.strip_suffix('*')?.trim();
    if pointee.is_empty() || pointee.contains('*') || pointee == "void" {
        return None;
    }
    // A pointer to const data is an input, not an output sink.
    if pointee.starts_with("const ") || pointee.ends_with(" const") {
        return None;
    }
    if !cpp_pointee_is_default_constructible(pointee, registry) {
        return None;
    }
    let scratch = format!("_gf_out_{name}");
    Some(CParamEmission {
        support: None,
        decl: format!("{pointee} {scratch}{{}}; {pointee} * {name} = &{scratch}"),
        arg: name.to_owned(),
        c_type: format!("{pointee} *"),
        free: None,
    })
}

/// Whether `pointee` default-constructs so an output-sink scratch (`T scratch{};`)
/// compiles (#24). Limited to std::string / std::string_view, default-constructible
/// std containers, and registry classes recorded as default-constructible — a bare
/// registry aggregate is left to the existing field-filling pointer path.
fn cpp_pointee_is_default_constructible(pointee: &str, registry: &TypeRegistry) -> bool {
    is_default_constructible_std_type(pointee) || registry.is_default_constructible_class(pointee)
}

/// A standard-library type that is default-constructible (to an empty value).
fn is_default_constructible_std_type(ty: &str) -> bool {
    const EXACT: &[&str] = &[
        "std::string",
        "std::wstring",
        "std::u8string",
        "std::u16string",
        "std::u32string",
        "std::string_view",
        "std::wstring_view",
        "std::u8string_view",
        "std::u16string_view",
        "std::u32string_view",
        "std::filesystem::path",
    ];
    const TEMPLATES: &[&str] = &[
        "std::vector<",
        "std::deque<",
        "std::list<",
        "std::forward_list<",
        "std::set<",
        "std::multiset<",
        "std::unordered_set<",
        "std::unordered_multiset<",
        "std::map<",
        "std::multimap<",
        "std::unordered_map<",
        "std::unordered_multimap<",
        "std::optional<",
        "std::array<",
    ];
    EXACT.contains(&ty) || TEMPLATES.iter().any(|p| ty.starts_with(p))
}

fn is_cpp_reference(raw_type: &str) -> bool {
    raw_type.trim_end().ends_with('&')
}

fn is_cpp_lvalue_reference(raw_type: &str) -> bool {
    let trimmed = raw_type.trim_end();
    trimmed.ends_with('&') && !trimmed.ends_with("&&")
}

fn combine_supports(items: Vec<String>) -> Option<String> {
    if items.is_empty() {
        None
    } else {
        Some(items.join("\n"))
    }
}

fn combine_support(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("{left}\n{right}")),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn select_std_function_decoder(
    normalized_type: &str,
    value_type: &str,
    name: &str,
) -> Option<CParamEmission> {
    let signature = value_type
        .strip_prefix("std::function<")?
        .strip_suffix('>')?;
    let open = signature.find('(')?;
    let close = signature.rfind(')')?;
    if close < open {
        return None;
    }
    let return_type = signature[..open].trim();
    if return_type.is_empty() || return_type.contains('&') {
        return None;
    }
    let params = signature[open + 1..close].trim();
    let param_types = if params.is_empty() || params == "void" {
        Vec::new()
    } else {
        split_cpp_type_list(params)?
    };
    let lambda_params = param_types
        .iter()
        .enumerate()
        .map(|(index, param_type)| format!("{} _gf_{name}_arg{index}", param_type.trim()))
        .collect::<Vec<_>>();
    let void_params = (0..param_types.len())
        .map(|index| format!("(void)_gf_{name}_arg{index};"))
        .collect::<Vec<_>>()
        .join(" ");
    let return_stmt = if return_type == "void" {
        String::new()
    } else {
        " return {};".to_owned()
    };
    let body = [void_params, return_stmt]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("");
    let c_type = if normalized_type.trim_end().ends_with('&') {
        normalized_type.trim().to_owned()
    } else {
        value_type.to_owned()
    };

    Some(CParamEmission {
        support: None,
        decl: format!(
            "{value_type} {name} = []({}) -> {return_type} {{ {body} }}",
            lambda_params.join(", ")
        ),
        arg: name.to_owned(),
        c_type,
        free: None,
    })
}

fn split_cpp_type_list(input: &str) -> Option<Vec<String>> {
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0i32;
    let mut paren_depth = 0i32;
    for (index, ch) in input.char_indices() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth -= 1,
            '(' => paren_depth += 1,
            ')' => paren_depth -= 1,
            ',' if angle_depth == 0 && paren_depth == 0 => {
                let item = input[start..index].trim();
                if item.is_empty() {
                    return None;
                }
                items.push(item.to_owned());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
        if angle_depth < 0 || paren_depth < 0 {
            return None;
        }
    }
    let item = input[start..].trim();
    if item.is_empty() || angle_depth != 0 || paren_depth != 0 {
        return None;
    }
    items.push(item.to_owned());
    Some(items)
}

fn is_byte_array_element(elem: &str) -> bool {
    matches!(
        elem,
        "uint8_t" | "std::uint8_t" | "unsigned char" | "char" | "std::byte"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpp_function_pointer_param_is_a_clean_skip_not_garbage() {
        // utf8.h's `utf8dup_ex(const utf8_int8_t *src, utf8_int8_t *(*alloc_func_ptr)
        // (utf8_int8_t *, size_t), void *user_data)` has a function-pointer param.
        // The C++ lane has no trampoline synthesis for it; struct-synthesizing the
        // funcptr emitted broken code that failed to BUILD. It must instead be a
        // clean decoder error so the target is SKIPPED, not a failed build.
        let reg = TypeRegistry::default();
        let err = select_cpp_decoder_with_registry(
            "utf8_int8_t *(*alloc_func_ptr)(utf8_int8_t *, size_t)",
            "alloc_func_ptr",
            &reg,
        );
        assert!(
            err.is_err(),
            "a C++ function-pointer param must be a clean skip, got: {err:?}"
        );
    }

    #[test]
    fn canonical_class_spelling_normalizes_equivalent_spellings() {
        // #99: leading `::`, west/east const, volatile, and elaborated keywords all
        // canonicalize to the same class key.
        for spelling in [
            "CORBA::Environment",
            "const CORBA::Environment",
            "CORBA::Environment const",
            "::CORBA::Environment",
            "class CORBA::Environment",
            "  volatile   CORBA::Environment  ",
            "typename CORBA::Environment",
        ] {
            assert_eq!(
                canonical_class_spelling(spelling),
                "CORBA::Environment",
                "spelling {spelling:?}"
            );
        }
    }

    #[test]
    fn corba_environment_spellings_take_the_same_decoder_path() {
        // #99: every equivalent spelling of the CORBA exception-environment context
        // parameter resolves to the SAME default-constructed emission (it is call
        // context, not fuzz input), instead of a leading `::` / const / elaborated
        // spelling being wrongly rejected as an opaque unsupported param.
        let reg = TypeRegistry::default();
        for spelling in [
            "CORBA::Environment &",
            "const CORBA::Environment &",
            "::CORBA::Environment &",
            "CORBA::Environment const &",
            "class CORBA::Environment &",
        ] {
            let e = select_cpp_decoder_with_registry(spelling, "env", &reg).unwrap_or_else(|err| {
                panic!("CORBA::Environment must decode for {spelling:?}: {err:?}")
            });
            assert_eq!(e.decl, "CORBA::Environment env;", "spelling {spelling:?}");
            assert_eq!(e.c_type, "CORBA::Environment", "spelling {spelling:?}");
        }
    }

    #[test]
    fn select_cpp_decoder_handles_std_string() {
        let e = select_cpp_decoder("const std::string &", "input")
            .expect("const std::string& is supported");
        assert!(e.decl.contains("std::string input(_tmp_input)"));
        assert!(e.decl.contains("gf_c_string"));
        assert!(e.decl.contains("free(_tmp_input)"));
    }

    #[test]
    fn select_cpp_decoder_drives_mfc_cstring_param_from_fuzz_string() {
        // `FromXML(const CString& s)` etc.: a CString param is a string, driven
        // from a fuzz C string via the MFC stub's `CString(const char *)` ctor.
        for ty in ["const CString &", "CString", "CStringA"] {
            let e = select_cpp_decoder(ty, "cmd")
                .unwrap_or_else(|| panic!("CString param must be a string decoder for {ty:?}"));
            assert!(
                e.decl.contains("gf_c_string") && e.decl.contains("CString cmd(_tmp_cmd"),
                "{ty:?} -> {}",
                e.decl
            );
        }
    }

    #[test]
    fn select_cpp_decoder_handles_win32_bool_scalar() {
        // `FromXML(const BOOL bValidateWithSchema)` on an offline lab: BOOL is an
        // int typedef from <windows.h> that isn't in the scanned tree, so it must
        // decode as a scalar rather than skip the whole target as opaque
        // "needs lifecycle support (Phase C)". const is stripped from the local.
        let e = select_cpp_decoder_with_registry(
            "const BOOL",
            "bValidateWithSchema",
            &TypeRegistry::default(),
        )
        .expect("const BOOL is a scalar");
        assert!(
            e.decl
                .contains("BOOL bValidateWithSchema = (BOOL)gf_i32(&Cur)"),
            "{}",
            e.decl
        );
        assert!(e.free.is_none());
    }

    #[test]
    fn select_cpp_decoder_drives_file_path_params_with_tempfile() {
        // A path-named std::string / const char* opens a file -> drive it with a
        // temp file whose CONTENT is the fuzz input (libE57Format's reader takes
        // `const ustring& filePath` / `const char* path`).
        let s = select_cpp_decoder("const std::string &", "filePath").expect("path string");
        assert!(
            s.decl
                .contains("gf_make_tempfile(Data, Size, filePath_path)"),
            "got {}",
            s.decl
        );
        assert!(
            s.decl
                .contains("std::string filePath(filePath_made ? filePath_path"),
            "got {}",
            s.decl
        );
        assert_eq!(
            s.free.as_deref(),
            Some("if (filePath_made) unlink(filePath_path)")
        );

        let c = select_cpp_decoder("const char *", "filename").expect("path char*");
        assert!(
            c.decl
                .contains("gf_make_tempfile(Data, Size, filename_path)"),
            "got {}",
            c.decl
        );
        assert!(
            c.decl.contains("const char * filename = filename_made"),
            "got {}",
            c.decl
        );

        // A non-path-named std::string is UNCHANGED (still gf_c_string).
        let plain = select_cpp_decoder("const std::string &", "input").expect("plain string");
        assert!(
            plain.decl.contains("gf_c_string"),
            "plain string param must stay gf_c_string"
        );
        assert!(!plain.decl.contains("gf_make_tempfile"));
    }

    #[test]
    fn select_cpp_decoder_handles_unqualified_std_string() {
        // json11 does `using std::string;` and spells params `const string &`.
        let e = select_cpp_decoder("const string &", "in")
            .expect("unqualified `string` should resolve to std::string");
        assert!(
            e.decl.contains("std::string in(_tmp_in)"),
            "got: {}",
            e.decl
        );
        // And nested unqualified names get qualified too.
        assert_eq!(
            qualify_std_type_names("const vector<string> &"),
            "const std::vector<std::string> &"
        );
        // Already-qualified names are untouched; user names are left alone.
        assert_eq!(qualify_std_type_names("std::string"), "std::string");
        assert_eq!(qualify_std_type_names("MyString"), "MyString");
    }

    #[test]
    fn qualify_std_type_names_preserves_utf8_before_an_identifier() {
        // Regression for GF-210: fuzzed replacement/non-ASCII characters can
        // put the following ASCII token two bytes after the middle of a
        // multibyte scalar. Qualification must never slice through that scalar.
        assert_eq!(
            qualify_std_type_names("abc\u{fffd}string"),
            "abc\u{fffd}std::string"
        );
        assert_eq!(
            qualify_std_type_names("\u{00e9}vector<string>"),
            "\u{00e9}std::vector<std::string>"
        );
    }

    #[test]
    fn select_cpp_decoder_handles_string_view() {
        let e =
            select_cpp_decoder("std::string_view", "view").expect("std::string_view is supported");
        assert!(e.decl.contains("std::string_view view"));
        assert!(e.decl.contains("gf_data_slice"));
    }

    #[test]
    fn select_cpp_decoder_handles_direct_nonstd_string_view() {
        let e =
            select_cpp_decoder_with_registry("absl::string_view", "view", &TypeRegistry::default())
                .expect("absl::string_view is constructible from a byte slice");
        assert!(e.decl.contains("absl::string_view view("), "{}", e.decl);
        assert!(e.decl.contains("gf_data_slice"), "{}", e.decl);
        assert_eq!(e.c_type, "absl::string_view");
    }

    #[test]
    fn select_cpp_decoder_handles_vector_uint8() {
        let e = select_cpp_decoder("const std::vector<uint8_t> &", "bytes")
            .expect("vector<uint8_t> is supported");
        assert!(e
            .decl
            .contains("std::vector<uint8_t> bytes(Data, Data + Size)"));
    }

    #[test]
    fn select_cpp_decoder_handles_vector_char() {
        let e = select_cpp_decoder("const std::vector<char> &", "bytes")
            .expect("vector<char> is supported");
        assert!(e.decl.contains("std::vector<char> bytes("));
        assert_eq!(e.c_type, "std::vector<char>");
    }

    #[test]
    fn select_cpp_decoder_handles_standard_byte_vectors() {
        let uint8 = select_cpp_decoder("const std::vector<std::uint8_t> &", "bytes")
            .expect("vector<std::uint8_t> is supported");
        assert!(uint8
            .decl
            .contains("std::vector<std::uint8_t> bytes(Data, Data + Size)"));
        assert_eq!(uint8.c_type, "std::vector<std::uint8_t>");

        let byte = select_cpp_decoder("const std::vector<std::byte> &", "raw")
            .expect("vector<std::byte> is supported");
        assert!(byte.decl.contains("std::vector<std::byte> raw("));
        assert!(byte
            .decl
            .contains("reinterpret_cast<const std::byte *>(Data)"));
        assert_eq!(byte.c_type, "std::vector<std::byte>");
    }

    #[test]
    fn select_cpp_decoder_handles_string_vectors() {
        let e = select_cpp_decoder("const std::vector<std::string> &", "tokens")
            .expect("vector<string> is supported");
        assert!(e.decl.contains("std::vector<std::string> tokens;"));
        assert!(e.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(e
            .decl
            .contains("tokens.emplace_back(_tmp_tokens ? _tmp_tokens : \"\")"));
        assert!(e.decl.contains("free(_tmp_tokens)"));
        assert_eq!(e.c_type, "const std::vector<std::string> &");
    }

    #[test]
    fn select_cpp_decoder_handles_vector_of_supported_values() {
        let e = select_cpp_decoder("const std::vector<std::uint32_t> &", "items")
            .expect("vector<uint32_t> is supported");
        assert!(e.decl.contains("std::vector<std::uint32_t> items;"));
        assert!(e.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(e
            .decl
            .contains("std::uint32_t _gf_vector_items_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(e.decl.contains("items.emplace_back(_gf_vector_items_elt)"));
        assert_eq!(e.c_type, "std::vector<std::uint32_t>");
    }

    #[test]
    fn select_cpp_decoder_handles_deque_and_list_of_supported_values() {
        let deque = select_cpp_decoder("const std::deque<std::uint32_t> &", "items")
            .expect("deque<uint32_t> is supported");
        assert!(deque.decl.contains("std::deque<std::uint32_t> items;"));
        assert!(deque.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(deque
            .decl
            .contains("std::uint32_t _gf_deque_items_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(deque
            .decl
            .contains("items.emplace_back(_gf_deque_items_elt)"));
        assert_eq!(deque.c_type, "std::deque<std::uint32_t>");

        let list = select_cpp_decoder("const std::list<std::string_view> &", "views")
            .expect("list<string_view> is supported");
        assert!(list.decl.contains("std::list<std::string_view> views;"));
        assert!(list.decl.contains("std::string_view _gf_list_views_elt("));
        assert!(list.decl.contains("views.emplace_back(_gf_list_views_elt)"));
        assert_eq!(list.c_type, "std::list<std::string_view>");
    }

    #[test]
    fn select_cpp_decoder_handles_forward_list_of_supported_values() {
        let items = select_cpp_decoder("const std::forward_list<std::uint32_t> &", "items")
            .expect("forward_list<uint32_t> is supported");
        assert!(items
            .decl
            .contains("std::forward_list<std::uint32_t> items;"));
        assert!(items.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(items
            .decl
            .contains("std::uint32_t _gf_forward_list_items_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(items
            .decl
            .contains("items.emplace_front(_gf_forward_list_items_elt)"));
        assert_eq!(items.c_type, "std::forward_list<std::uint32_t>");
    }

    #[test]
    fn select_cpp_decoder_handles_set_and_map_of_supported_values() {
        let set = select_cpp_decoder("const std::set<std::uint32_t> &", "ids")
            .expect("set<uint32_t> is supported");
        assert!(set.decl.contains("std::set<std::uint32_t> ids;"));
        assert!(set.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(set
            .decl
            .contains("std::uint32_t _gf_set_ids_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(set.decl.contains("ids.emplace(_gf_set_ids_elt)"));
        assert_eq!(set.c_type, "std::set<std::uint32_t>");

        let map = select_cpp_decoder(
            "const std::map<std::string_view, std::uint32_t> &",
            "lookup",
        )
        .expect("map<string_view, uint32_t> is supported");
        assert!(map
            .decl
            .contains("std::map<std::string_view, std::uint32_t> lookup;"));
        assert!(map.decl.contains("std::string_view _gf_map_lookup_key("));
        assert!(map
            .decl
            .contains("std::uint32_t _gf_map_lookup_value = (std::uint32_t)gf_bounded_i32"));
        assert!(map
            .decl
            .contains("lookup.emplace(_gf_map_lookup_key, _gf_map_lookup_value)"));
        assert_eq!(map.c_type, "std::map<std::string_view, std::uint32_t>");
    }

    #[test]
    fn select_cpp_decoder_handles_unordered_set_and_map_of_supported_values() {
        let set = select_cpp_decoder("const std::unordered_set<std::uint32_t> &", "ids")
            .expect("unordered_set<uint32_t> is supported");
        assert!(set.decl.contains("std::unordered_set<std::uint32_t> ids;"));
        assert!(set.decl.contains("gf_bounded_length(&Cur, 0, 16)"));
        assert!(set
            .decl
            .contains("std::uint32_t _gf_unordered_set_ids_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(set.decl.contains("ids.emplace(_gf_unordered_set_ids_elt)"));
        assert_eq!(set.c_type, "std::unordered_set<std::uint32_t>");

        let map = select_cpp_decoder(
            "const std::unordered_map<std::string_view, std::uint32_t> &",
            "lookup",
        )
        .expect("unordered_map<string_view, uint32_t> is supported");
        assert!(map
            .decl
            .contains("std::unordered_map<std::string_view, std::uint32_t> lookup;"));
        assert!(map
            .decl
            .contains("std::string_view _gf_unordered_map_lookup_key("));
        assert!(map.decl.contains(
            "std::uint32_t _gf_unordered_map_lookup_value = (std::uint32_t)gf_bounded_i32"
        ));
        assert!(map.decl.contains(
            "lookup.emplace(_gf_unordered_map_lookup_key, _gf_unordered_map_lookup_value)"
        ));
        assert_eq!(
            map.c_type,
            "std::unordered_map<std::string_view, std::uint32_t>"
        );
    }

    #[test]
    fn select_cpp_decoder_handles_fixed_byte_arrays() {
        let key = select_cpp_decoder("const std::array<std::byte, 16> &", "key")
            .expect("array<std::byte, 16> is supported");
        assert!(key.decl.contains("std::array<std::byte, 16> key{}"));
        assert!(key
            .decl
            .contains("key[_gf_i_key] = static_cast<std::byte>(Data[_gf_i_key])"));
        assert_eq!(key.c_type, "const std::array<std::byte, 16> &");

        let raw = select_cpp_decoder("std::array<std::uint8_t, 32>", "raw")
            .expect("array<std::uint8_t, 32> is supported");
        assert!(raw.decl.contains("std::array<std::uint8_t, 32> raw{}"));
        assert!(raw
            .decl
            .contains("raw[_gf_i_raw] = static_cast<std::uint8_t>(Data[_gf_i_raw])"));
    }

    #[test]
    fn std_array_byte_budget_decodes_large_primitive_array_skips_huge() {
        // #465: std::array<int, 8192> (32 KiB) is within the ~1 MiB byte budget and
        // now decodes; std::array<int, 1000000> (4 MiB) exceeds it and is skipped.
        assert!(select_cpp_decoder("std::array<int, 8192>", "a").is_some());
        assert!(select_cpp_decoder("std::array<int, 1000000>", "a").is_none());
        // A non-primitive (unknown-size) element keeps the conservative 4096 cap.
        let limits = CppDecoderLimits::default();
        assert!(array_within_budget("int", 8192, &limits));
        assert!(!array_within_budget("int", 1_000_000, &limits));
        assert!(!array_within_budget("Widget", 5000, &limits));
        assert!(array_within_budget("Widget", 4096, &limits));
    }

    #[test]
    fn select_cpp_decoder_handles_array_of_supported_values() {
        let values = select_cpp_decoder("const std::array<std::uint32_t, 4> &", "values")
            .expect("array<uint32_t, 4> is supported");
        assert!(values
            .decl
            .contains("std::array<std::uint32_t, 4> values{}"));
        assert!(values.decl.contains("values.size()"));
        assert!(values
            .decl
            .contains("std::uint32_t _gf_array_values_elt = (std::uint32_t)gf_bounded_i32"));
        assert!(values
            .decl
            .contains("values[_gf_i_values] = _gf_array_values_elt"));
        assert_eq!(values.c_type, "std::array<std::uint32_t, 4>");
    }

    #[test]
    fn select_cpp_decoder_handles_bitset_flags() {
        let flags = select_cpp_decoder("const std::bitset<32> &", "flags")
            .expect("bitset<32> is supported");
        assert!(flags.decl.contains("std::bitset<32> flags"));
        assert!(flags.decl.contains("flags.set(_gf_i_flags"));
        assert!(flags.decl.contains("(gf_u8(&Cur) & 1) != 0"));
        assert_eq!(flags.c_type, "const std::bitset<32> &");
    }

    #[test]
    fn select_cpp_decoder_handles_const_byte_spans() {
        let span = select_cpp_decoder("std::span<const std::byte>", "bytes")
            .expect("span<const std::byte> is supported");
        assert!(span.decl.contains("std::span<const std::byte> bytes("));
        assert!(span
            .decl
            .contains("reinterpret_cast<const std::byte *>(Data)"));
        assert_eq!(span.c_type, "std::span<const std::byte>");

        let u8_span = select_cpp_decoder("std::span<const std::uint8_t>", "raw")
            .expect("span<const std::uint8_t> is supported");
        assert!(u8_span.decl.contains("std::span<const std::uint8_t> raw("));
    }

    #[test]
    fn select_cpp_decoder_handles_mutable_byte_spans() {
        let byte_span = select_cpp_decoder("std::span<std::byte>", "bytes")
            .expect("span<std::byte> is supported");
        assert!(byte_span
            .decl
            .contains("std::vector<std::byte> _gf_span_storage_bytes("));
        assert!(byte_span
            .decl
            .contains("std::span<std::byte> bytes(_gf_span_storage_bytes.data(), _gf_span_storage_bytes.size())"));
        assert_eq!(byte_span.c_type, "std::span<std::byte>");

        let u8_span = select_cpp_decoder("std::span<std::uint8_t>", "raw")
            .expect("span<std::uint8_t> is supported");
        assert!(u8_span
            .decl
            .contains("std::vector<std::uint8_t> _gf_span_storage_raw(Data, Data + Size)"));
        assert!(u8_span.decl.contains(
            "std::span<std::uint8_t> raw(_gf_span_storage_raw.data(), _gf_span_storage_raw.size())"
        ));
    }

    #[test]
    fn select_cpp_decoder_handles_optional_string() {
        let e = select_cpp_decoder("const std::optional<std::string> &", "maybe")
            .expect("optional<string> is supported");
        assert!(e.decl.contains("std::optional<std::string> maybe"));
        assert!(e.decl.contains("gf_u8(&Cur) & 1"));
        assert!(e
            .decl
            .contains("maybe.emplace(_tmp_maybe ? _tmp_maybe : \"\")"));
        assert!(e.decl.contains("free(_tmp_maybe)"));
        assert_eq!(e.c_type, "std::optional<std::string>");
    }

    #[test]
    fn select_cpp_decoder_handles_optional_standard_scalar() {
        let e = select_cpp_decoder("const std::optional<std::uint32_t> &", "maybe_count")
            .expect("optional<uint32_t> is supported");
        assert!(e.decl.contains("std::optional<std::uint32_t> maybe_count"));
        assert!(e.decl.contains("if (gf_u8(&Cur) & 1)"));
        assert!(e
            .decl
            .contains("std::uint32_t _gf_optional_maybe_count = (std::uint32_t)gf_bounded_i32"));
        assert!(e
            .decl
            .contains("maybe_count.emplace(_gf_optional_maybe_count)"));
        assert_eq!(e.c_type, "std::optional<std::uint32_t>");
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_optional_visible_aggregate() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let maybe =
            select_cpp_decoder_with_registry("const std::optional<Config> &", "maybe", &registry)
                .expect("optional<Config> is supported when Config is visible");

        assert!(maybe.decl.contains("std::optional<Config> maybe"));
        assert!(maybe.decl.contains("Config _gf_optional_maybe"));
        assert!(maybe
            .decl
            .contains("_gf_optional_maybe.mode = gf_i32(&Cur)"));
        assert!(maybe.decl.contains("maybe.emplace(_gf_optional_maybe)"));
        assert_eq!(maybe.arg, "maybe");
        assert_eq!(maybe.c_type, "const std::optional<Config> &");
    }

    #[test]
    fn select_cpp_decoder_with_registry_resolves_string_alias_for_file_path() {
        // `using ustring = std::string;` (libE57Format): a path-named
        // `const ustring &` param resolves through the alias so the file-path
        // (temp-file) decoder fires; a non-path-named one stays a plain string.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![c_parser::CTypedefDef {
                name: "ustring".to_owned(),
                underlying: "std::string".to_owned(),
                line: 1,
            }],
            ..Default::default()
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let path = select_cpp_decoder_with_registry("const ustring &", "filePath", &registry)
            .expect("ustring path param resolves to the std::string file-path decoder");
        assert!(
            path.decl
                .contains("gf_make_tempfile(Data, Size, filePath_path)"),
            "got {}",
            path.decl
        );
        assert!(
            path.decl.contains("std::string filePath("),
            "got {}",
            path.decl
        );

        let value = select_cpp_decoder_with_registry("const ustring &", "value", &registry)
            .expect("ustring value param resolves to the std::string decoder");
        assert!(value.decl.contains("gf_c_string"), "got {}", value.decl);
        assert!(!value.decl.contains("gf_make_tempfile"));
    }

    #[test]
    fn select_cpp_decoder_with_registry_default_constructs_known_class_arg() {
        // #353: a class-typed constructor argument whose class is default-
        // constructible gets default-constructed and passed, consuming no fuzz
        // bytes, instead of failing the whole constructor.
        let registry =
            TypeRegistry::default().with_default_constructible_classes(["FastBuffer".to_owned()]);
        let emission = select_cpp_decoder_with_registry("const FastBuffer &", "buffer", &registry)
            .expect("a default-constructible class arg is decodable");
        assert!(
            emission.decl.contains("FastBuffer buffer;"),
            "decl: {}",
            emission.decl
        );
        assert_eq!(emission.arg, "buffer");
        // An unknown class stays an honest skip (no default-construction).
        assert!(
            select_cpp_decoder_with_registry("const Unknown &", "x", &TypeRegistry::default())
                .is_err()
        );
    }

    #[test]
    fn select_cpp_decoder_neutralizes_legacy_corba_environment_reference() {
        let emission = select_cpp_decoder_with_registry(
            "CORBA::Environment &",
            "_env",
            &TypeRegistry::default(),
        )
        .expect("legacy CORBA call context is default-constructible");
        assert_eq!(emission.decl, "CORBA::Environment _env;");
        assert_eq!(emission.arg, "_env");
    }

    #[test]
    fn select_cpp_decoder_default_constructs_fmt_format_args() {
        let emission =
            select_cpp_decoder_with_registry("format_args", "args", &TypeRegistry::default())
                .expect("fmt format_args has a public empty state");
        assert_eq!(emission.decl, "format_args args{}");
        assert_eq!(emission.arg, "args");
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_vector_visible_aggregate() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let items =
            select_cpp_decoder_with_registry("const std::vector<Config> &", "items", &registry)
                .expect("vector<Config> is supported when Config is visible");

        assert!(items.decl.contains("std::vector<Config> items;"));
        assert!(items.decl.contains("Config _gf_vector_items_elt"));
        assert!(items
            .decl
            .contains("_gf_vector_items_elt.mode = gf_i32(&Cur)"));
        assert!(items
            .decl
            .contains("items.emplace_back(_gf_vector_items_elt)"));
        assert_eq!(items.arg, "items");
        assert_eq!(items.c_type, "const std::vector<Config> &");
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_array_visible_aggregate() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let items =
            select_cpp_decoder_with_registry("const std::array<Config, 2> &", "items", &registry)
                .expect("array<Config, 2> is supported when Config is visible");

        assert!(items.decl.contains("std::array<Config, 2> items{}"));
        assert!(items.decl.contains("Config _gf_array_items_elt"));
        assert!(items
            .decl
            .contains("_gf_array_items_elt.mode = gf_i32(&Cur)"));
        assert!(items
            .decl
            .contains("items[_gf_i_items] = _gf_array_items_elt"));
        assert_eq!(items.arg, "items");
        assert_eq!(items.c_type, "const std::array<Config, 2> &");
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_sequence_visible_aggregates() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        for (cpp_type, container, prefix, insertion) in [
            (
                "const std::deque<Config> &",
                "std::deque<Config>",
                "deque",
                "emplace_back",
            ),
            (
                "const std::list<Config> &",
                "std::list<Config>",
                "list",
                "emplace_back",
            ),
            (
                "const std::forward_list<Config> &",
                "std::forward_list<Config>",
                "forward_list",
                "emplace_front",
            ),
        ] {
            let items = select_cpp_decoder_with_registry(cpp_type, "items", &registry)
                .unwrap_or_else(|err| panic!("{cpp_type} should decode visible Config: {err}"));

            assert!(items.decl.contains(&format!("{container} items;")));
            assert!(items
                .decl
                .contains(&format!("Config _gf_{prefix}_items_elt")));
            assert!(items
                .decl
                .contains(&format!("_gf_{prefix}_items_elt.mode = gf_i32(&Cur)")));
            assert!(items
                .decl
                .contains(&format!("items.{insertion}(_gf_{prefix}_items_elt)")));
            assert_eq!(items.arg, "items");
            assert_eq!(items.c_type, cpp_type);
        }
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_composed_visible_aggregates() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let pair = select_cpp_decoder_with_registry(
            "const std::pair<Config, std::uint32_t> &",
            "entry",
            &registry,
        )
        .expect("pair<Config, uint32_t> is supported when Config is visible");
        assert!(pair.decl.contains("Config _gf_pair_entry_first"));
        assert!(pair
            .decl
            .contains("_gf_pair_entry_first.mode = gf_i32(&Cur)"));
        assert!(pair.decl.contains(
            "std::pair<Config, std::uint32_t> entry(_gf_pair_entry_first, _gf_pair_entry_second)"
        ));
        assert_eq!(pair.c_type, "const std::pair<Config, std::uint32_t> &");

        let tuple = select_cpp_decoder_with_registry(
            "const std::tuple<Config, std::uint32_t> &",
            "entry",
            &registry,
        )
        .expect("tuple<Config, uint32_t> is supported when Config is visible");
        assert!(tuple.decl.contains("Config _gf_tuple_entry_0"));
        assert!(tuple.decl.contains("_gf_tuple_entry_0.mode = gf_i32(&Cur)"));
        assert!(tuple.decl.contains(
            "std::tuple<Config, std::uint32_t> entry(_gf_tuple_entry_0, _gf_tuple_entry_1)"
        ));
        assert_eq!(tuple.c_type, "const std::tuple<Config, std::uint32_t> &");

        let variant = select_cpp_decoder_with_registry(
            "const std::variant<Config, std::uint32_t> &",
            "choice",
            &registry,
        )
        .expect("variant<Config, uint32_t> is supported when Config is visible");
        assert!(variant.decl.contains("Config _gf_variant_choice_0"));
        assert!(variant
            .decl
            .contains("_gf_variant_choice_0.mode = gf_i32(&Cur)"));
        assert!(variant.decl.contains(
            "std::variant<Config, std::uint32_t>(std::in_place_index<0>, _gf_variant_choice_0)"
        ));
        assert_eq!(
            variant.c_type,
            "const std::variant<Config, std::uint32_t> &"
        );
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_map_visible_aggregate_values() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let map = select_cpp_decoder_with_registry(
            "const std::map<std::string_view, Config> &",
            "lookup",
            &registry,
        )
        .expect("map<string_view, Config> is supported when Config is visible");
        assert!(map
            .decl
            .contains("std::map<std::string_view, Config> lookup;"));
        assert!(map.decl.contains("std::string_view _gf_map_lookup_key("));
        assert!(map.decl.contains("Config _gf_map_lookup_value"));
        assert!(map
            .decl
            .contains("_gf_map_lookup_value.mode = gf_i32(&Cur)"));
        assert!(map
            .decl
            .contains("lookup.emplace(_gf_map_lookup_key, _gf_map_lookup_value)"));
        assert_eq!(map.c_type, "const std::map<std::string_view, Config> &");

        let unordered = select_cpp_decoder_with_registry(
            "const std::unordered_map<std::string, Config> &",
            "lookup",
            &registry,
        )
        .expect("unordered_map<string, Config> is supported when Config is visible");
        assert!(unordered
            .decl
            .contains("std::unordered_map<std::string, Config> lookup;"));
        assert!(unordered
            .decl
            .contains("std::string _gf_unordered_map_lookup_key"));
        assert!(unordered
            .decl
            .contains("Config _gf_unordered_map_lookup_value"));
        assert!(unordered
            .decl
            .contains("_gf_unordered_map_lookup_value.mode = gf_i32(&Cur)"));
        assert!(unordered.decl.contains(
            "lookup.emplace(_gf_unordered_map_lookup_key, _gf_unordered_map_lookup_value)"
        ));
        assert_eq!(
            unordered.c_type,
            "const std::unordered_map<std::string, Config> &"
        );
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_span_visible_aggregates() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let mutable = select_cpp_decoder_with_registry("std::span<Config>", "items", &registry)
            .expect("span<Config> is supported when Config is visible");
        assert!(mutable
            .decl
            .contains("std::vector<Config> _gf_span_storage_items;"));
        assert!(mutable.decl.contains("Config _gf_span_items_elt"));
        assert!(mutable
            .decl
            .contains("_gf_span_items_elt.mode = gf_i32(&Cur)"));
        assert!(mutable
            .decl
            .contains("_gf_span_storage_items.emplace_back(_gf_span_items_elt)"));
        assert!(mutable.decl.contains(
            "std::span<Config> items(_gf_span_storage_items.data(), _gf_span_storage_items.size())"
        ));
        assert_eq!(mutable.c_type, "std::span<Config>");

        let constant =
            select_cpp_decoder_with_registry("const std::span<const Config> &", "items", &registry)
                .expect("span<const Config> is supported when Config is visible");
        assert!(constant
            .decl
            .contains("std::vector<Config> _gf_span_storage_items;"));
        assert!(constant.decl.contains("Config _gf_span_items_elt"));
        assert!(constant.decl.contains(
            "std::span<const Config> items(_gf_span_storage_items.data(), _gf_span_storage_items.size())"
        ));
        assert_eq!(constant.c_type, "const std::span<const Config> &");
    }

    #[test]
    fn select_cpp_decoder_handles_smart_pointers_to_supported_values() {
        let unique = select_cpp_decoder("std::unique_ptr<std::uint32_t>", "owned")
            .expect("unique_ptr<uint32_t> is supported");
        assert!(unique
            .decl
            .contains("std::uint32_t _gf_unique_ptr_owned_value = (std::uint32_t)gf_bounded_i32"));
        assert!(unique.decl.contains(
            "std::unique_ptr<std::uint32_t> owned = std::make_unique<std::uint32_t>(_gf_unique_ptr_owned_value)"
        ));
        assert_eq!(unique.arg, "std::move(owned)");
        assert_eq!(unique.c_type, "std::unique_ptr<std::uint32_t>");

        let shared = select_cpp_decoder("const std::shared_ptr<std::string> &", "name")
            .expect("shared_ptr<string> is supported");
        assert!(shared
            .decl
            .contains("std::string _gf_shared_ptr_name_value"));
        assert!(shared.decl.contains(
            "std::shared_ptr<std::string> name = std::make_shared<std::string>(_gf_shared_ptr_name_value)"
        ));
        assert_eq!(shared.arg, "name");
        assert_eq!(shared.c_type, "const std::shared_ptr<std::string> &");
    }

    #[test]
    fn select_cpp_decoder_with_registry_handles_smart_pointer_to_visible_aggregate() {
        let defs = c_parser::CTypeDefs {
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
        };
        let registry = TypeRegistry::from_defs([&defs]);

        let owned = select_cpp_decoder_with_registry("std::unique_ptr<Config>", "owned", &registry)
            .expect("unique_ptr<Config> is supported when Config is visible");

        assert!(owned.decl.contains("Config _gf_unique_ptr_owned_value"));
        assert!(owned
            .decl
            .contains("_gf_unique_ptr_owned_value.mode = gf_i32(&Cur)"));
        assert!(owned.decl.contains(
            "std::unique_ptr<Config> owned = std::make_unique<Config>(_gf_unique_ptr_owned_value)"
        ));
        assert_eq!(owned.arg, "std::move(owned)");
        assert_eq!(owned.c_type, "std::unique_ptr<Config>");
    }

    #[test]
    fn select_cpp_decoder_handles_pair_of_supported_values() {
        let e = select_cpp_decoder(
            "const std::pair<std::uint32_t, std::string_view> &",
            "entry",
        )
        .expect("pair<uint32_t, string_view> is supported");
        assert!(e
            .decl
            .contains("std::uint32_t _gf_pair_entry_first = (std::uint32_t)gf_bounded_i32"));
        assert!(e.decl.contains("std::string_view _gf_pair_entry_second("));
        assert!(e.decl.contains(
            "std::pair<std::uint32_t, std::string_view> entry(_gf_pair_entry_first, _gf_pair_entry_second)"
        ));
        assert_eq!(e.c_type, "std::pair<std::uint32_t, std::string_view>");
    }

    #[test]
    fn select_cpp_decoder_handles_tuple_of_supported_values() {
        let e = select_cpp_decoder(
            "const std::tuple<std::uint32_t, std::string_view, bool> &",
            "entry",
        )
        .expect("tuple<uint32_t, string_view, bool> is supported");
        assert!(e
            .decl
            .contains("std::uint32_t _gf_tuple_entry_0 = (std::uint32_t)gf_bounded_i32"));
        assert!(e.decl.contains("std::string_view _gf_tuple_entry_1("));
        assert!(e
            .decl
            .contains("bool _gf_tuple_entry_2 = (bool)(gf_u8(&Cur) & 1)"));
        assert!(e.decl.contains(
            "std::tuple<std::uint32_t, std::string_view, bool> entry(_gf_tuple_entry_0, _gf_tuple_entry_1, _gf_tuple_entry_2)"
        ));
        assert_eq!(
            e.c_type,
            "std::tuple<std::uint32_t, std::string_view, bool>"
        );
    }

    #[test]
    fn select_cpp_decoder_handles_variant_of_supported_values() {
        let e = select_cpp_decoder(
            "const std::variant<std::uint32_t, std::string_view, bool> &",
            "choice",
        )
        .expect("variant<uint32_t, string_view, bool> is supported");
        assert!(e.decl.contains(
            "std::variant<std::uint32_t, std::string_view, bool> choice = [&]() -> std::variant<std::uint32_t, std::string_view, bool>"
        ));
        assert!(e.decl.contains("switch (gf_u8(&Cur) % 3)"));
        assert!(e
            .decl
            .contains("std::uint32_t _gf_variant_choice_0 = (std::uint32_t)gf_bounded_i32"));
        assert!(e.decl.contains("std::string_view _gf_variant_choice_1("));
        assert!(e.decl.contains(
            "return std::variant<std::uint32_t, std::string_view, bool>(std::in_place_index<1>, _gf_variant_choice_1)"
        ));
        assert_eq!(
            e.c_type,
            "std::variant<std::uint32_t, std::string_view, bool>"
        );
    }

    #[test]
    fn select_cpp_decoder_handles_monostate_variant_alternative() {
        let e = select_cpp_decoder(
            "const std::variant<std::monostate, std::uint32_t> &",
            "choice",
        )
        .expect("variant<monostate, uint32_t> is supported");
        assert!(e.decl.contains("std::monostate _gf_variant_choice_0{}"));
        assert!(e.decl.contains(
            "return std::variant<std::monostate, std::uint32_t>(std::in_place_index<0>, _gf_variant_choice_0)"
        ));
        assert!(e
            .decl
            .contains("std::uint32_t _gf_variant_choice_1 = (std::uint32_t)gf_bounded_i32"));
        assert_eq!(e.c_type, "std::variant<std::monostate, std::uint32_t>");
    }

    #[test]
    fn select_cpp_decoder_handles_filesystem_path() {
        let e = select_cpp_decoder("const std::filesystem::path &", "path")
            .expect("filesystem path is supported");
        assert!(e.decl.contains("char *_tmp_path = gf_c_string(&Cur, 4096)"));
        assert!(e.decl.contains("std::filesystem::path path(_tmp_path)"));
        assert!(e.decl.contains("free(_tmp_path)"));
        assert_eq!(e.c_type, "const std::filesystem::path &");
    }

    #[test]
    fn select_cpp_decoder_falls_back_to_c_for_scalars() {
        let e = select_cpp_decoder("int", "n").expect("int falls through to C decoder");
        assert!(e.decl.contains("int n = gf_i32(&Cur)"));
    }

    #[test]
    fn select_cpp_decoder_handles_standard_scalar_aliases() {
        let count =
            select_cpp_decoder("std::size_t", "count").expect("std::size_t scalar is supported");
        assert!(count
            .decl
            .contains("std::size_t count = (std::size_t)gf_bounded_length(&Cur, 0, 65536)"));
        assert_eq!(count.c_type, "std::size_t");

        let flags = select_cpp_decoder("std::uint32_t", "flags")
            .expect("std::uint32_t scalar is supported");
        assert!(flags
            .decl
            .contains("std::uint32_t flags = (std::uint32_t)gf_bounded_i32(&Cur, 0, 0x7fffffff)"));
        assert_eq!(flags.c_type, "std::uint32_t");

        let code =
            select_cpp_decoder("std::uint16_t", "code").expect("std::uint16_t scalar is supported");
        assert!(code
            .decl
            .contains("std::uint16_t code = (std::uint16_t)gf_bounded_i32(&Cur, 0, 0xffff)"));
        assert_eq!(code.c_type, "std::uint16_t");

        let enabled = select_cpp_decoder("bool", "enabled").expect("bool scalar is supported");
        assert!(enabled
            .decl
            .contains("bool enabled = (bool)(gf_u8(&Cur) & 1)"));
        assert_eq!(enabled.c_type, "bool");

        let limit = select_cpp_decoder("const std::size_t &", "limit")
            .expect("const std::size_t& scalar is supported");
        assert!(limit
            .decl
            .contains("std::size_t limit = (std::size_t)gf_bounded_length(&Cur, 0, 65536)"));
        assert_eq!(limit.c_type, "const std::size_t &");
    }

    /// `std::string::size_type` (== size_t) and `std::*::difference_type` (signed
    /// pointer-width) are nested std-container member typedefs. They must decode as
    /// scalars — not fall through to the opaque branch — so a pure-scalar out-param
    /// target like json11's `Json::parse_multi(..., std::string::size_type &)` is
    /// harnessable instead of skipped. The emitted local keeps the real C++ spelling.
    #[test]
    fn select_cpp_decoder_handles_nested_std_container_typedefs() {
        let pos = select_cpp_decoder("std::string::size_type", "parser_stop_pos")
            .expect("std::string::size_type decodes as a scalar");
        assert!(
            pos.decl.contains(
                "std::string::size_type parser_stop_pos = \
                 (std::string::size_type)gf_bounded_length(&Cur, 0, 65536)"
            ),
            "decl: {}",
            pos.decl
        );
        assert_eq!(pos.c_type, "std::string::size_type");

        // Out-param reference form (the json11 parser-position case): a value local
        // is decoded and passed by reference; the recorded c_type keeps the `&`.
        let by_ref = select_cpp_decoder("std::string::size_type &", "pos")
            .expect("reference size_type decodes as a scalar");
        assert!(by_ref
            .decl
            .contains("std::string::size_type pos = (std::string::size_type)"));
        assert_eq!(by_ref.c_type, "std::string::size_type &");

        // A templated container's size_type resolves the same way.
        let vec_pos = select_cpp_decoder("std::vector<int>::size_type", "n")
            .expect("std::vector<int>::size_type decodes as a scalar");
        assert_eq!(vec_pos.c_type, "std::vector<int>::size_type");

        // difference_type (signed pointer-width) decodes too.
        let diff = select_cpp_decoder("std::string::difference_type", "d")
            .expect("std::string::difference_type decodes as a scalar");
        assert!(
            diff.decl
                .contains("std::string::difference_type d = (std::string::difference_type)"),
            "decl: {}",
            diff.decl
        );
        assert_eq!(diff.c_type, "std::string::difference_type");
    }

    /// A top-level `const` (or `volatile`) on a BY-VALUE scalar/aggregate
    /// parameter is irrelevant to the caller and must decode EXACTLY like its
    /// non-const base type (campaign: taocpp-json `const bool`/`const double`
    /// steps were skipped "unsupported parameter type"). West-const, east-const,
    /// and `volatile` all collapse to the same decoder as the bare type.
    #[test]
    fn select_cpp_decoder_strips_top_level_const_on_by_value_params() {
        for (qualified, base) in [
            ("const bool", "bool"),
            ("const double", "double"),
            ("const float", "float"),
            ("const int", "int"),
            ("const unsigned", "unsigned"),
            ("const long", "long"),
            ("const std::size_t", "std::size_t"),
            ("const std::uint32_t", "std::uint32_t"),
            // East-const and volatile spellings resolve identically.
            ("bool const", "bool"),
            ("int const", "int"),
            ("volatile int", "int"),
            ("std::size_t const", "std::size_t"),
        ] {
            let q = select_cpp_decoder(qualified, "v")
                .unwrap_or_else(|| panic!("const-qualified by-value '{qualified}' is supported"));
            let b = select_cpp_decoder(base, "v")
                .unwrap_or_else(|| panic!("base '{base}' is supported"));
            assert_eq!(
                q.decl, b.decl,
                "'{qualified}' must decode like '{base}' (decl)"
            );
            assert_eq!(
                q.c_type, b.c_type,
                "'{qualified}' must decode like '{base}' (c_type)"
            );
        }
    }

    /// The const-stripping is BY-VALUE only: a pointer-to-const (`const char *`)
    /// and a const-reference (`const T &`) keep their qualifier — separate,
    /// pre-existing paths the strip must not disturb.
    #[test]
    fn select_cpp_decoder_keeps_const_on_pointers_and_references() {
        let s = select_cpp_decoder("const char *", "s").expect("const char* is supported");
        assert_eq!(s.c_type, "const char *");
        let limit = select_cpp_decoder("const std::size_t &", "limit")
            .expect("const std::size_t& is supported");
        assert_eq!(limit.c_type, "const std::size_t &");
    }

    /// East-const on a REFERENCE (`std::string const &`) must decode identically
    /// to west-const (`const std::string &`) — the normalizer used to only strip a
    /// leading `const`, so east-const references were skipped "unsupported
    /// parameter type". (Regression: MFC/Windows dogfood, east-const-heavy APIs.)
    #[test]
    fn select_cpp_decoder_handles_east_const_reference() {
        let west = select_cpp_decoder("const std::string &", "s").expect("west-const string");
        let east = select_cpp_decoder("std::string const &", "s").expect("east-const string");
        assert_eq!(
            east.decl, west.decl,
            "east-const `std::string const &` must decode like west-const"
        );
        // East-const on a vector referent too.
        let ev = select_cpp_decoder("std::vector<uint8_t> const &", "b")
            .expect("east-const vector<uint8_t>&");
        assert!(
            ev.decl
                .contains("std::vector<uint8_t> b(Data, Data + Size)"),
            "{}",
            ev.decl
        );
    }

    /// A plain scalar passed by const reference (`const bool &`, `const int &`,
    /// east-const `bool const &`) must be supported: decode the bare value type
    /// and bind the local to the const ref. Previously skipped because no C++ arm
    /// exists for a bare scalar and the C decoder rejected the `&`-spelling.
    #[test]
    fn select_cpp_decoder_handles_const_reference_scalars() {
        for spelling in [
            "const bool &",
            "const int &",
            "bool const &",
            "const double &",
        ] {
            let e = select_cpp_decoder(spelling, "p")
                .unwrap_or_else(|| panic!("const-ref scalar '{spelling}' should be supported"));
            assert!(
                e.c_type.trim_end().ends_with('&'),
                "'{spelling}' must keep its reference spelling, got c_type '{}'",
                e.c_type
            );
        }
        // The decoded local is decoded from bytes (not left uninitialised).
        let b = select_cpp_decoder("const bool &", "flag").expect("const bool&");
        assert!(b.decl.contains("gf_u8"), "{}", b.decl);
    }

    #[test]
    fn strip_byvalue_top_level_cv_only_touches_by_value_top_level() {
        assert_eq!(strip_byvalue_top_level_cv("const bool"), "bool");
        assert_eq!(strip_byvalue_top_level_cv("bool const"), "bool");
        assert_eq!(strip_byvalue_top_level_cv("volatile int"), "int");
        assert_eq!(
            strip_byvalue_top_level_cv("const unsigned int"),
            "unsigned int"
        );
        // Pointer / reference qualifiers are preserved verbatim.
        assert_eq!(strip_byvalue_top_level_cv("const char *"), "const char *");
        assert_eq!(
            strip_byvalue_top_level_cv("const std::size_t &"),
            "const std::size_t &"
        );
        // An inner template qualifier is part of an unsplittable token and stays.
        assert_eq!(
            strip_byvalue_top_level_cv("std::vector<const int>"),
            "std::vector<const int>"
        );
        // A leading const on a by-value template still strips.
        assert_eq!(
            strip_byvalue_top_level_cv("const std::vector<int>"),
            "std::vector<int>"
        );
    }

    // ----- #46: C++20 char8_t / char16_t / char32_t string types -----

    #[test]
    fn select_cpp_decoder_handles_u8_string_types() {
        // tomlplusplus parse_file takes a std::u8string_view; char8_t is a 1-byte
        // unsigned type so it decodes directly off the fuzz bytes like string_view.
        let view =
            select_cpp_decoder("std::u8string_view", "v").expect("u8string_view is supported");
        assert!(
            view.decl
                .contains("std::u8string_view v(reinterpret_cast<const char8_t *>"),
            "{}",
            view.decl
        );
        assert!(view.decl.contains("gf_data_slice"), "{}", view.decl);
        assert_eq!(view.c_type, "std::u8string_view");

        let owned = select_cpp_decoder("std::u8string", "s").expect("u8string is supported");
        assert!(
            owned
                .decl
                .contains("std::u8string s(reinterpret_cast<const char8_t *>"),
            "{}",
            owned.decl
        );
        assert!(owned.decl.contains("gf_data_slice"), "{}", owned.decl);

        // An unqualified `u8string_view` gets std:: prefixed and decodes.
        assert_eq!(
            qualify_std_type_names("u8string_view"),
            "std::u8string_view"
        );
        let bare = select_cpp_decoder("const u8string_view &", "v")
            .expect("bare u8string_view resolves to std::u8string_view");
        assert!(bare.decl.contains("std::u8string_view v("), "{}", bare.decl);
    }

    #[test]
    fn select_cpp_decoder_handles_u16_u32_string_views() {
        // Reinterpreting the raw fuzz buffer as char16_t/char32_t would be
        // misaligned UB, so an owned u16string/u32string is built element-by-element.
        let u16 =
            select_cpp_decoder("std::u16string_view", "v").expect("u16string_view is supported");
        assert!(
            u16.decl.contains("std::u16string _gf_sv_buf_v"),
            "{}",
            u16.decl
        );
        assert!(
            u16.decl.contains("std::u16string_view v(_gf_sv_buf_v)"),
            "{}",
            u16.decl
        );
        assert!(u16.decl.contains("+ 2 <= _gf_sv_len_v"), "{}", u16.decl);
        assert_eq!(u16.c_type, "std::u16string_view");

        let u32 =
            select_cpp_decoder("std::u32string_view", "v").expect("u32string_view is supported");
        assert!(
            u32.decl.contains("std::u32string _gf_sv_buf_v"),
            "{}",
            u32.decl
        );
        assert!(
            u32.decl.contains("std::u32string_view v(_gf_sv_buf_v)"),
            "{}",
            u32.decl
        );
        assert!(u32.decl.contains("+ 4 <= _gf_sv_len_v"), "{}", u32.decl);
    }

    #[test]
    fn select_cpp_decoder_drives_u8_file_path_params_with_tempfile() {
        let p = select_cpp_decoder("std::u8string_view", "filename")
            .expect("path-named u8 view drives a temp file");
        assert!(
            p.decl
                .contains("gf_make_tempfile(Data, Size, filename_path)"),
            "{}",
            p.decl
        );
        assert!(
            p.decl.contains("std::u8string_view filename("),
            "{}",
            p.decl
        );
        assert_eq!(
            p.free.as_deref(),
            Some("if (filename_made) unlink(filename_path)")
        );
    }

    // ----- #16: bundled non-std string_view alias -----

    #[test]
    fn select_cpp_decoder_with_registry_resolves_nonstd_string_view_alias() {
        // csv-parser: `namespace csv { using string_view = nonstd::string_view; }`
        // (string-view-lite). The alias resolves through the bare leaf and the param
        // decodes as a slice-backed view typed as its own alias spelling — which is
        // constructible from (const char*, size_t) — instead of misrouting to Phase-C.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![c_parser::CTypedefDef {
                name: "string_view".to_owned(),
                underlying: "nonstd::string_view".to_owned(),
                line: 1,
            }],
            ..Default::default()
        };
        let reg = TypeRegistry::from_defs([&defs]);
        let e = select_cpp_decoder_with_registry("const csv::string_view &", "src", &reg)
            .expect("bundled nonstd csv::string_view decodes");
        assert!(e.decl.contains("csv::string_view src("), "{}", e.decl);
        assert!(e.decl.contains("gf_data_slice"), "{}", e.decl);
        assert!(
            e.decl.contains("reinterpret_cast<const char *>"),
            "{}",
            e.decl
        );

        // The canonical std alias still RE-DISPATCHES to the std::string_view decoder
        // (no behavior change for the common C++17 csv build).
        let std_defs = c_parser::CTypeDefs {
            typedefs: vec![c_parser::CTypedefDef {
                name: "string_view".to_owned(),
                underlying: "std::string_view".to_owned(),
                line: 1,
            }],
            ..Default::default()
        };
        let std_reg = TypeRegistry::from_defs([&std_defs]);
        let s = select_cpp_decoder_with_registry("csv::string_view", "tok", &std_reg)
            .expect("std::string_view alias decodes");
        assert!(s.decl.contains("std::string_view tok("), "{}", s.decl);
    }

    // ----- #24: pointer-to-default-constructible output sinks -----

    #[test]
    fn select_cpp_decoder_with_registry_stack_allocates_output_sink_pointers() {
        let reg = TypeRegistry::default();
        // std::string* output sink (tinyobjloader's warn/err idiom).
        let warn = select_cpp_decoder_with_registry("std::string *", "warn", &reg)
            .expect("std::string* output sink stack-allocates a scratch");
        assert!(
            warn.decl.contains("std::string _gf_out_warn{}"),
            "{}",
            warn.decl
        );
        assert!(
            warn.decl.contains("std::string * warn = &_gf_out_warn"),
            "{}",
            warn.decl
        );
        assert_eq!(warn.arg, "warn");
        assert!(warn.free.is_none());

        // std::vector<shape_t>* output sink — a container pointee needs no registry.
        let shapes = select_cpp_decoder_with_registry("std::vector<shape_t> *", "shapes", &reg)
            .expect("vector* output sink");
        assert!(
            shapes
                .decl
                .contains("std::vector<shape_t> _gf_out_shapes{}"),
            "{}",
            shapes.decl
        );
        assert!(
            shapes
                .decl
                .contains("std::vector<shape_t> * shapes = &_gf_out_shapes"),
            "{}",
            shapes.decl
        );

        // A default-constructible class pointee (tinyobjloader attrib_t).
        let reg2 =
            TypeRegistry::default().with_default_constructible_classes(["attrib_t".to_owned()]);
        let attrib = select_cpp_decoder_with_registry("attrib_t *", "attrib", &reg2)
            .expect("default-constructible class output sink");
        assert!(
            attrib.decl.contains("attrib_t _gf_out_attrib{}"),
            "{}",
            attrib.decl
        );

        // A pointer to const DATA is an INPUT the callee reads, NOT an output sink:
        // it must not be turned into a scratch (it keeps its existing handling).
        let cp = select_cpp_decoder_with_registry("const Unknown *", "p", &reg)
            .expect("const opaque pointer overlays the fuzz input");
        assert!(
            !cp.decl.contains("_gf_out_p{}"),
            "a const input pointer must not become an output sink: {}",
            cp.decl
        );

        // A non-default-constructible unknown pointee still skips cleanly.
        assert!(
            select_cpp_decoder_with_registry("Unknown *", "p", &reg).is_err(),
            "an opaque non-default-constructible pointee must still skip"
        );
    }

    // ----- §27.11: configurable C++ decoder limits -----

    /// Default-limits emission must be byte-identical to the public (preserved)
    /// path — the regression-safety guarantee for §27.11.
    #[test]
    fn cpp_decoder_limits_default_is_byte_identical() {
        // The historical container cap of 16 is preserved at default.
        let legacy = select_cpp_decoder("const std::vector<std::uint32_t> &", "items")
            .expect("vector<uint32_t> decodable");
        assert!(
            legacy.decl.contains("gf_bounded_length(&Cur, 0, 16)"),
            "default container cap stays 16: {}",
            legacy.decl
        );
        let with_default = select_cpp_decoder_limited(
            "const std::vector<std::uint32_t> &",
            "items",
            &CppDecoderLimits::default(),
        )
        .expect("vector<uint32_t> decodable");
        assert_eq!(
            legacy.decl, with_default.decl,
            "CppDecoderLimits::default() must reproduce the public emission byte-for-byte"
        );
    }

    /// A tighter `--container-size-max` shrinks the emitted element-count bound.
    #[test]
    fn cpp_custom_container_cap_shrinks_emitted_bound() {
        let limits = CppDecoderLimits {
            container_size_max: 4,
            ..CppDecoderLimits::default()
        };
        for ty in [
            "const std::vector<std::uint32_t> &",
            "const std::set<std::uint32_t> &",
            "const std::map<int, int> &",
            "const std::deque<std::uint32_t> &",
        ] {
            let e = select_cpp_decoder_limited(ty, "c", &limits)
                .unwrap_or_else(|| panic!("{ty} decodable"));
            assert!(
                e.decl.contains("gf_bounded_length(&Cur, 0, 4)"),
                "container cap 4 must apply for {ty}: {}",
                e.decl
            );
            assert!(
                !e.decl.contains(", 16)"),
                "the historical 16 cap must be gone for {ty}: {}",
                e.decl
            );
        }
    }

    /// Custom `--bitset-max-size` / `--array-max-size` gate the accepted sizes.
    #[test]
    fn cpp_custom_bitset_and_array_caps_apply() {
        let tight = CppDecoderLimits {
            bitset_max_size: 8,
            array_max_size: 8,
            ..CppDecoderLimits::default()
        };
        assert!(select_cpp_decoder_limited("std::bitset<8>", "b", &tight).is_some());
        assert!(
            select_cpp_decoder_limited("std::bitset<32>", "b", &tight).is_none(),
            "a bitset above the cap is skipped"
        );
        // An unknown-size element array is bound by array_max_size.
        assert!(select_cpp_decoder_limited("std::array<std::string, 8>", "a", &tight).is_some());
        assert!(
            select_cpp_decoder_limited("std::array<std::string, 9>", "a", &tight).is_none(),
            "an array above the element-count cap is skipped"
        );
    }

    /// §27.11 OOM guard: a hand-cranked huge `--container-size-max` is clamped
    /// by the ~1 MiB per-parameter byte budget so a known-size element can't
    /// blow memory; and an over-budget `std::array` is skipped entirely.
    #[test]
    fn cpp_oom_guard_clamps_huge_cap_and_skips_huge_array() {
        let huge = CppDecoderLimits {
            container_size_max: 1_000_000,
            ..CppDecoderLimits::default()
        };
        let e = select_cpp_decoder_limited("const std::vector<int> &", "v", &huge)
            .expect("vector<int> decodable");
        let clamp = MAX_PARAM_BYTES / 4; // sizeof(int) == 4
        assert!(
            e.decl
                .contains(&format!("gf_bounded_length(&Cur, 0, {clamp})")),
            "the count must clamp to the ~1 MiB byte budget ({clamp}), got: {}",
            e.decl
        );
        assert!(
            !e.decl.contains("1000000"),
            "the unclamped huge count must never reach the harness: {}",
            e.decl
        );
        // A fixed std::array whose total size exceeds the budget is skipped.
        assert!(
            select_cpp_decoder("std::array<int, 1000000>", "a").is_none(),
            "a 4 MiB std::array must be skipped by the OOM byte budget"
        );
        // An unknown-size element keeps the configured count unclamped (the
        // default 16 is harmless; documented limitation).
        let e = select_cpp_decoder_limited("const std::vector<std::string> &", "s", &huge)
            .expect("vector<string> decodable");
        assert!(
            e.decl.contains("gf_bounded_length(&Cur, 0, 1000000)"),
            "unknown-size elements are not byte-clamped: {}",
            e.decl
        );
    }
}
