// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppParamDescriptor {
    pub name: String,
    pub cpp_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppFunction {
    pub name: String,
    pub line: u32,
    pub return_type: String,
    pub params: Vec<CppParamDescriptor>,
    /// Qualified namespace path (without the function name itself), e.g.
    /// `["demo", "Reader"]` for `int demo::Reader::Foo()`. Empty for free
    /// functions.
    pub qualifier_path: Vec<String>,
    pub api: CppApiMetadata,
    /// `static` storage class on a free function — internal linkage,
    /// not callable from an external harness translation unit.
    /// (Static *member* functions are linkable; this is only set from
    /// the storage class on the definition itself, so callers should
    /// combine it with `api.is_method`.)
    pub is_static: bool,
    /// Set when the definition sits under a preprocessor conditional
    /// naming a foreign-platform macro. See `c_parser::CFunction`.
    pub foreign_guard: Option<String>,
    /// The declared type-parameter names of the nearest enclosing
    /// `template<...>` clause — `["T"]` for `template<typename T> T parse(...)`,
    /// `["K", "V"]` for `template<class K, class V> ...`. Empty for a
    /// non-templated function. Used by the instantiation lane (#455 / §27.5)
    /// to substitute concrete type arguments into the parameter / return types.
    pub template_type_params: Vec<String>,
    /// Concrete type arguments chosen for ONE instantiation of this template
    /// function — `["int"]` resolved from a `parse<int>(..)` call site, or set
    /// by the `--template-instantiate` flag. Empty unless this is a templated
    /// function with a resolved specialization. Positionally aligned with
    /// `template_type_params`. The presence of args is what lifts the template
    /// out of the ranker's "unsupported" filter and drives a turbofish call.
    pub instantiation_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct CppApiMetadata {
    pub api_kind: String,
    pub namespace_path: Vec<String>,
    pub class_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_access: Option<String>,
    pub is_method: bool,
    pub is_constructor: bool,
    pub is_destructor: bool,
    pub is_template: bool,
    pub overload_key: String,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppDeclaration {
    pub name: String,
    pub return_type: String,
    pub param_types: Vec<String>,
    pub line: u32,
}

impl c_stub_gen::DeclarationView for CppDeclaration {
    fn name(&self) -> &str {
        &self.name
    }
    fn return_type(&self) -> &str {
        &self.return_type
    }
    fn param_types(&self) -> &[String] {
        &self.param_types
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CppParseError {
    #[error("failed to load C++ grammar")]
    Grammar,
    #[error("failed to parse C++ source")]
    Parse,
}

/// Walk the tree-sitter tree counting `ERROR` and `MISSING` nodes.
/// Mirrors `c_parser::count_parse_errors`; used by the CLI to surface
/// parser-confusion warnings when a real-world file yields zero
/// functions.
/// Hard cap on recursive AST-walk depth. tree-sitter parses deep input fine
/// (its parser is iterative), but our recursive walkers use one stack frame
/// per AST level; a pathologically deep source (long else-if/||/&& chains,
/// nested parens) otherwise overflows the stack and aborts the process
/// before the build (#407).
///
/// 250 is still ~4x the C standard's guaranteed 63-level nesting minimum and
/// below clang's default 256-level expression-nesting limit, so it never
/// truncates code a compiler would accept; yet it stays well under the
/// empirical overflow threshold on a 2 MiB worker-thread stack (debug builds,
/// the worst case — the daemon parses untrusted source on such threads, not
/// just the CLI's larger main-thread stack). The C++ walkers carry larger
/// frames than the C ones, so they bound the safe cap; both crates use the
/// same value for one rationale.
const MAX_AST_DEPTH: usize = 250;

thread_local! {
    static AST_WALK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// RAII guard: returns None once the recursion is at MAX_AST_DEPTH (the caller
/// then stops descending), and decrements on drop. A tree is never cyclic, so
/// a depth cap — not a visited-set — is the correct bound.
struct AstDepthGuard;

impl AstDepthGuard {
    fn enter() -> Option<AstDepthGuard> {
        AST_WALK_DEPTH.with(|d| {
            let cur = d.get();
            if cur >= MAX_AST_DEPTH {
                None
            } else {
                d.set(cur + 1);
                Some(AstDepthGuard)
            }
        })
    }
}

impl Drop for AstDepthGuard {
    fn drop(&mut self) {
        AST_WALK_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return 0;
    }
    let Some(tree) = parser.parse(source, None) else {
        return 0;
    };
    let mut count = 0_usize;
    walk_errors(tree.root_node(), &mut count);
    count
}

fn walk_errors(node: tree_sitter::Node<'_>, count: &mut usize) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.is_error() || node.is_missing() {
        *count = count.saturating_add(1);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_errors(child, count);
    }
}

/// Blank an export/visibility macro token sitting between a `class`/`struct`
/// keyword and the type name — `class TINYXML2_LIB Foo`, `class Q_DECL_EXPORT
/// Bar`, `struct GTEST_API_ Baz`. Left in place, the unexpanded macro makes
/// tree-sitter-cpp mis-parse the entire class as a function declaration and
/// detach every member, so the harness generator sees constructors as free
/// functions (`ret="class TINYXML2_LIB"`) and methods with no receiver
/// (`SetAttribute(...)` instead of `obj.SetAttribute(...)`).
///
/// `class IDENT IDENT` (two adjacent identifiers) is only legal C++ when the
/// first is such a macro, so blanking it is safe. The token is overwritten
/// with same-length ASCII spaces, leaving every byte offset — and therefore
/// every reported line/column — unchanged. The trailing `final` contextual
/// keyword (`class FOO final`, where `FOO` is the real name) is excluded.
/// Whether an all-caps token is a known function-decoration macro (export/inline/
/// attribute/calling-convention), by marker substring — the same philosophy as
/// `harness_gen`'s `is_leading_decl_noise`. Precise enough to never match a real
/// all-caps type (`DWORD`, `BYTE`, `HANDLE`, `RESULT_T`).
fn is_decoration_macro_token(tok: &str) -> bool {
    // Calling-convention keywords (MSVC/GCC spellings) sit in the decoration
    // position between the return type and the name, exactly like an export macro
    // (`parse_result TOML_CALLCONV parse(...)`), but they are LOWERCASE so they
    // bypass the all-caps gate below. Left in place they survive into the call-
    // result variable's type and the header `#undef`s them → uncompilable harness.
    if matches!(
        tok,
        "__cdecl"
            | "__stdcall"
            | "__fastcall"
            | "__thiscall"
            | "__vectorcall"
            | "_cdecl"
            | "_stdcall"
            | "_fastcall"
    ) {
        return true;
    }
    if tok.len() < 3
        || !tok
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !tok.bytes().any(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    const MARKERS: &[&str] = &[
        "INLINE",
        "UNUSED",
        "NODISCARD",
        "DEPRECATED",
        "WARN_UNUSED",
        "FORCE_INLINE",
        "DLLEXPORT",
        "DLLIMPORT",
        "VISIBILITY",
        "NORETURN",
        "NOESCAPE",
        "PUBLIC_API",
        "PUREF",
        "WINAPI",
        "APIENTRY",
        "CALLBACK",
        "RESTRICT",
        "HIDDEN",
        // Implementation-function macros (pugixml `PUGI_IMPL_FN` / `..._FN_NO_INLINE`)
        // that prefix every internal definition. No real all-caps type contains
        // `IMPL_FN`, so this is a safe signal.
        "IMPL_FN",
        // Linkage / calling-convention decoration macros. toml++ wraps every
        // free function as `TOML_NODISCARD TOML_EXTERNAL_LINKAGE parse_result
        // TOML_CALLCONV parse(...)`; left in place the `_EXTERNAL_LINKAGE` /
        // `_CALLCONV` tokens land in the call-result variable's TYPE and the
        // header `#undef`s them → the harness fails to compile. `LINKAGE` also
        // covers a bare `*_LINKAGE`; `FREE_FUNCTION` covers `*_FREE_FUNCTION`.
        // No real all-caps type spells any of these, so they are safe signals.
        "LINKAGE",
        "CALLCONV",
        "FREE_FUNCTION",
    ];
    if MARKERS.iter().any(|m| tok.contains(m)) {
        return true;
    }
    // Library export-visibility macros are conventionally `<LIB>_API` / `<LIB>_EXPORT`
    // / `<LIB>_PUBLIC` / `<LIB>_IMPORT` (LIBDE265_API, ZSTDLIB_API, PNG_EXPORT,
    // MY_LIB_PUBLIC). Left in place, the macro makes tree-sitter read the real
    // return type as a class and the function as a phantom method
    // (`de265_error::de265_decode_data`), which then can't resolve its lifecycle. A
    // real return type never ends in these suffixes and the token is already
    // constrained to all-caps, so the suffix is a safe, general signal that catches
    // per-library export macros the hardcoded list can't enumerate.
    const EXPORT_SUFFIXES: &[&str] = &["_API", "_EXPORT", "_PUBLIC", "_IMPORT"];
    EXPORT_SUFFIXES.iter().any(|s| tok.ends_with(s))
}

/// Blank function-decoration macros (`XXH_PUBLIC_API`, `XXH_PUREF`, `WINAPI`, ...)
/// in a function declarator prefix before the structural parse, so tree-sitter
/// sees a clean `<return-type> <name>(...)`. Without this the macros derail the
/// parse: a primitive qualifier is dropped (`unsigned long long` -> `long long`)
/// or the real return type is read as a class and the function as a phantom
/// method (`_gf_receiver.XXH128`). Only KNOWN decoration-macro tokens are blanked,
/// and never the function name (the identifier immediately before `(`), so a
/// genuine all-caps return type (`DWORD GetThing(...)`) is untouched. This is a
/// structural source cleanup, not C preprocessing (no macro expansion, no config).
/// True if the line that ends at byte `nl` (the index of a `\n`) is a
/// preprocessor directive — its first non-whitespace character is `#`. Used by
/// the decoration-macro walk-back to treat a directive line as a hard boundary.
fn preceding_line_is_directive(bytes: &[u8], nl: usize) -> bool {
    let mut line_start = nl;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut k = line_start;
    while k < nl && matches!(bytes[k], b' ' | b'\t' | b'\r') {
        k += 1;
    }
    k < nl && bytes[k] == b'#'
}

fn blank_function_decoration_macros(source: &str) -> String {
    let bytes = source.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut to_blank: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        // Walk back over a run of [identifier | whitespace | '*' | '&'] from '(',
        // collecting identifier spans (right-to-left).
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut j = i;
        loop {
            if j == 0 {
                break;
            }
            let c = bytes[j - 1];
            if c == b'\n' {
                // A preprocessor directive on the preceding line is a hard
                // boundary: a declarator never spans a `#if`/`#ifndef`/… line.
                // Without this the walk-back crosses into the directive, collects
                // its tokens (`#ifndef LIBDE265_DISABLE_DEPRECATED` above
                // `LIBDE265_API de265_error de265_decode_data(...)`), and the
                // boundary check then fails on the `#`, so the real export macro on
                // the next line is never blanked and the return type is mis-read as
                // a class (`de265_error::de265_decode_data`).
                if preceding_line_is_directive(bytes, j - 1) {
                    break;
                }
                j -= 1;
            } else if matches!(c, b' ' | b'\t' | b'\r' | b'*' | b'&') {
                j -= 1;
            } else if is_ident(c) {
                let end = j;
                while j > 0 && is_ident(bytes[j - 1]) {
                    j -= 1;
                }
                spans.push((j, end));
            } else if c == b':' && j >= 2 && bytes[j - 2] == b':' {
                // Cross a `::` scope-resolution operator so a decoration macro before
                // a QUALIFIED definition is still reached and blanked
                // (`PUGI_IMPL_FN xml_parse_result xml_document::load_file(...)`).
                // Without this the walk stops at `::`, the macro is left in place, and
                // the return type is mis-read as part of the qualifier
                // (`xml_parse_result::xml_document::load_file`). The statement-boundary
                // + `is_decoration_macro_token` gates below keep this from touching a
                // `Class::method()` CALL.
                j -= 2;
            } else {
                break;
            }
        }
        spans.reverse();
        // Need at least a type + a name; the declaration must start at a boundary
        // (so we never touch a call expression or a macro-call statement).
        if spans.len() >= 2 {
            let first_start = spans[0].0;
            let mut b = first_start;
            while b > 0 && matches!(bytes[b - 1], b' ' | b'\t' | b'\r') {
                b -= 1;
            }
            let at_boundary = b == 0 || matches!(bytes[b - 1], b';' | b'{' | b'}' | b'\n' | b'>');
            if at_boundary {
                // Blank every decoration-macro token except the name (last span).
                for &(s, e) in &spans[..spans.len() - 1] {
                    if is_decoration_macro_token(&source[s..e]) {
                        to_blank.push((s, e));
                    }
                }
            }
        }
        i += 1;
    }
    if to_blank.is_empty() {
        return source.to_owned();
    }
    let mut out = source.as_bytes().to_vec();
    for (s, e) in to_blank {
        for b in &mut out[s..e] {
            *b = b' ';
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

fn blank_class_modifier_macros(source: &str) -> String {
    let bytes = source.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut to_blank: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let kw_len = if bytes[i..].starts_with(b"class") {
            5
        } else if bytes[i..].starts_with(b"struct") {
            6
        } else {
            0
        };
        if kw_len == 0 {
            i += 1;
            continue;
        }
        // Whole-word keyword: the preceding byte must not be identifier-ish.
        if i > 0 && is_ident(bytes[i - 1]) {
            i += 1;
            continue;
        }
        let after_kw = i + kw_len;
        if after_kw >= bytes.len() || (bytes[after_kw] != b' ' && bytes[after_kw] != b'\t') {
            i = after_kw;
            continue;
        }
        let mut j = after_kw;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        // T1: the modifier candidate.
        let t1_start = j;
        while j < bytes.len() && is_ident(bytes[j]) {
            j += 1;
        }
        let t1 = &source[t1_start..j];
        let macro_like = t1.len() >= 3
            && t1.as_bytes()[0].is_ascii_uppercase()
            && t1
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !macro_like {
            i = j.max(after_kw);
            continue;
        }
        // Require separating whitespace then T2 (the real type name).
        let after_t1 = j;
        let mut k = after_t1;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        if k == after_t1
            || k >= bytes.len()
            || !(bytes[k].is_ascii_alphabetic() || bytes[k] == b'_')
        {
            i = after_t1;
            continue;
        }
        let t2_start = k;
        while k < bytes.len() && is_ident(bytes[k]) {
            k += 1;
        }
        let t2 = &source[t2_start..k];
        if t2 == "final" {
            i = after_t1;
            continue;
        }
        to_blank.push((t1_start, after_t1));
        i = k;
    }
    if to_blank.is_empty() {
        return source.to_owned();
    }
    let mut out = source.as_bytes().to_vec();
    for (start, end) in to_blank {
        for b in &mut out[start..end] {
            *b = b' ';
        }
    }
    // Only ASCII identifier bytes were overwritten with ASCII spaces, so the
    // result is still valid UTF-8; fall back to the original on the impossible
    // error rather than panicking.
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

/// Blank bare namespace-delimiter macro invocations — identifiers ending in
/// `_NAMESPACE_BEGIN` / `_NAMESPACE_END` / `_NS_BEGIN` / `_NS_END`
/// (`NLOHMANN_JSON_NAMESPACE_BEGIN`, `ASIO_NS_BEGIN`, …) that stand in
/// statement/declaration position. They expand to `namespace X { inline namespace … {`
/// (and the matching `}`s) but tree-sitter-cpp sees only an opaque identifier; placed
/// immediately before a `namespace`/`class` they derail ERROR-recovery so the
/// enclosing class's members are mis-attributed as global free functions (nlohmann's
/// protected `detail::exception::name` leaked as a global `name`, dodging the
/// visibility filter and surfacing as a junk fuzz target). The macros carry no literal
/// braces, so blanking them with same-length spaces is brace-neutral and
/// offset-preserving. `#`-directive lines are spared so a macro's own `#define` body
/// (which legitimately contains `namespace X {`) is left intact.
fn blank_namespace_delimiter_macros(source: &str) -> String {
    const SUFFIXES: [&str; 4] = ["_NAMESPACE_BEGIN", "_NAMESPACE_END", "_NS_BEGIN", "_NS_END"];
    let bytes = source.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut to_blank: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    let mut at_line_start = true;
    let mut line_is_directive = false;
    while i < bytes.len() {
        if at_line_start {
            let mut k = i;
            while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
                k += 1;
            }
            line_is_directive = bytes.get(k) == Some(&b'#');
            at_line_start = false;
        }
        if bytes[i] == b'\n' {
            at_line_start = true;
            i += 1;
            continue;
        }
        if !line_is_directive && is_ident(bytes[i]) && (i == 0 || !is_ident(bytes[i - 1])) {
            let start = i;
            let mut j = i;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            let word = &source[start..j];
            if SUFFIXES
                .iter()
                .any(|suffix| word.len() > suffix.len() && word.ends_with(suffix))
            {
                // Also swallow a same-line balanced `(...)` arg list, if any
                // (`SOME_NS_BEGIN(detail)`), so no dangling parens remain.
                let mut end = j;
                let mut p = j;
                while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
                    p += 1;
                }
                if bytes.get(p) == Some(&b'(') {
                    let mut depth = 0i32;
                    let mut q = p;
                    while q < bytes.len() && bytes[q] != b'\n' {
                        match bytes[q] {
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    q += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        q += 1;
                    }
                    if depth == 0 {
                        end = q;
                    }
                }
                to_blank.push((start, end));
            }
            i = j;
            continue;
        }
        i += 1;
    }
    if to_blank.is_empty() {
        return source.to_owned();
    }
    let mut out = bytes.to_vec();
    for (start, end) in to_blank {
        for b in &mut out[start..end] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

/// Run every offset-preserving source pre-pass tree-sitter needs before a parse:
/// blank namespace-delimiter macros, class-modifier macros, then function-decoration
/// macros. Each is brace-neutral and length-preserving, so byte offsets reported by
/// tree-sitter still index the ORIGINAL source.
fn prepare_cpp_source(source: &str) -> String {
    blank_function_decoration_macros(&blank_class_modifier_macros(
        &blank_namespace_delimiter_macros(source),
    ))
}

/// True if `line` is a conditional preprocessor directive (`#if`, `#ifdef`,
/// `#ifndef`, `#elif`, `#else`, `#endif`). `#include` / `#define` / `#pragma`
/// are not conditionals and are deliberately spared.
fn is_conditional_directive_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let d = rest.trim_start();
    d.starts_with("if") || d.starts_with("elif") || d.starts_with("else") || d.starts_with("endif")
}

/// Cheap gate: does the source contain any conditional preprocessor directive?
/// Lets [`parse_cpp_functions`] skip the recovery re-parse when there is nothing
/// for it to recover.
fn source_has_conditional_directive(source: &str) -> bool {
    source.lines().any(is_conditional_directive_line)
}

/// Blank conditional preprocessor directive lines with same-length spaces,
/// preserving every byte offset and newline (mirrors the decoration-macro
/// blankers). tree-sitter-cpp models preprocessor conditionals only in statement
/// / declaration position; a conditional that interrupts an EXPRESSION — e.g.
/// `#if defined(_WIN32)` splitting a constructor's member-initializer list
/// (tinyobjloader's `MappedFile`) — becomes an ERROR node whose recovery cascades
/// and silently drops later definitions. Blanking the directives keeps BOTH
/// branches' tokens, which is valid SYNTAX (a redefinition is a semantic, not a
/// syntactic, error tree-sitter ignores), so the surrounding construct parses.
fn blank_conditional_directives(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        if is_conditional_directive_line(line) {
            for &b in line.as_bytes() {
                out.push(if b == b'\n' { '\n' } else { ' ' });
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Parse already-prepared (decoration-blanked) C++ source and collect functions.
/// Returns the functions plus whether the parse contained any ERROR / MISSING
/// node — the signal [`parse_cpp_functions`] uses to decide whether a
/// conditional-directive recovery re-parse is worthwhile.
fn collect_cpp_functions_raw(source: &str) -> Result<(Vec<CppFunction>, bool), CppParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut error_count = 0_usize;
    walk_errors(tree.root_node(), &mut error_count);
    let mut functions = Vec::new();
    let mut member_access = std::collections::BTreeMap::new();
    collect_member_access_declarations(
        tree.root_node(),
        source.as_bytes(),
        &[],
        &[],
        None,
        &mut member_access,
    );
    collect_functions(
        tree.root_node(),
        source.as_bytes(),
        &[],
        &[],
        None,
        None,
        &member_access,
        false,
        &[],
        false,
        &mut functions,
    );
    Ok((functions, error_count > 0))
}

pub fn parse_cpp_functions(source: &str) -> Result<Vec<CppFunction>, CppParseError> {
    let prepared = prepare_cpp_source(source);
    let (mut functions, had_errors) = collect_cpp_functions_raw(prepared.as_str())?;
    // Recovery re-parse: a preprocessor conditional that interrupts an EXPRESSION
    // (e.g. a platform `#if` inside a constructor's member-initializer list, as in
    // tinyobjloader's `MappedFile`) makes tree-sitter emit an ERROR whose recovery
    // cascades and silently drops later out-of-line definitions — the canonical
    // `ObjReader::ParseFromString` fuzz entry vanished from discovery on the full
    // header. When the native parse errored and the source has conditional
    // directives, re-parse with those directives blanked and UNION in any function
    // the native parse missed. The native result is authoritative and never
    // removed, so the keep-both-branches imprecision of blanking can only ADD
    // recovered definitions, never regress a file that already parsed cleanly.
    if had_errors && source_has_conditional_directive(source) {
        let recovered = prepare_cpp_source(&blank_conditional_directives(source));
        if let Ok((extra, _)) = collect_cpp_functions_raw(recovered.as_str()) {
            reconcile_recovered_scope(&mut functions, extra);
        }
    }
    annotate_overload_sets(&mut functions);
    annotate_template_instantiations(&mut functions, source);
    Ok(functions)
}

/// Reconcile the native parse against a conditional-blanked re-parse (`extra`) to
/// undo class mis-attribution from tree-sitter ERROR-recovery. A preprocessor
/// conditional that splits an EXPRESSION rather than a statement — the platform
/// `#if` inside tinyobjloader's `MappedFile` constructor member-initializer list —
/// derails recovery so the `struct_specifier`'s body never closes: it runs
/// UNBOUNDED and swallows every following sibling (free functions, other classes'
/// methods, even `namespace detail_fp {`) as a bogus public "member" of that
/// struct, and the harness emitter then writes uncompilable `receiver.parseInt(..)`
/// / `namespace R = ...` calls. The conditional-blanked re-parse keeps both
/// branches' tokens, which is valid SYNTAX, so the struct closes correctly — making
/// it an authoritative oracle for which functions REALLY belong to each class.
///
/// Runs only when the native parse already errored (caller-gated), so a cleanly
/// parsed file is never disturbed.
fn reconcile_recovered_scope(functions: &mut Vec<CppFunction>, extra: Vec<CppFunction>) {
    // Per-class member-name sets from the structurally-sound re-parse.
    let mut recovery_members: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    for r in &extra {
        if let Some(class) = r.api.class_name.as_deref() {
            recovery_members
                .entry(class.to_owned())
                .or_default()
                .insert(r.name.clone());
        }
    }
    // (1) Where the re-parse resolves a native "method" at the same (name, line)
    //     under a DIFFERENT receiver (a free function, or a method of another
    //     class), the native receiver is the artifact — adopt the recovered scope.
    //     Only corrects a contradicted receiver; never invents a member where
    //     recovery agrees.
    for native in functions.iter_mut() {
        if !native.api.is_method {
            continue;
        }
        if let Some(recovered) = extra.iter().find(|r| {
            r.name == native.name
                && r.line == native.line
                && r.api.class_name != native.api.class_name
        }) {
            *native = recovered.clone();
        }
    }
    // (2) Evict residual swallow artifacts the per-line pass can't see: a native
    //     method of class C that the re-parse — which DOES know C's real members —
    //     never attributes to C under ANY name (the `MaterialFileReader`/`ObjReader`
    //     constructors recovery placed at their real lines; `namespace detail_fp {`
    //     recovery dropped as a non-function). Gated on a NON-EMPTY recovered member
    //     set for C, so a class the re-parse could not resolve is left fully intact —
    //     this can only remove a member recovery is confident does not exist.
    functions.retain(|native| {
        let Some(class) = native.api.class_name.as_deref() else {
            return true;
        };
        match recovery_members.get(class) {
            Some(members) if !members.is_empty() => members.contains(&native.name),
            _ => true,
        }
    });
    // (3) Union in any definition the native parse missed entirely (incl. the real
    //     definitions of the constructors evicted above). Dedup by (name, line); the
    //     native result is kept for scope except where the reconciliation above
    //     already replaced/removed a swallow artifact.
    for f in extra {
        let already = functions
            .iter()
            .any(|g| g.name == f.name && g.line == f.line);
        if !already {
            functions.push(f);
        }
    }
}

/// Resolve ONE concrete specialization for each free templated function from the
/// call-site instantiations seen in the SAME translation unit (#455 / §27.5
/// Phase 2). A `template<typename T> T parse_as(...)` defined and called as
/// `parse_as<int>(..)` in one file gets `instantiation_args = ["int"]`; the
/// ranker then surfaces it and codegen emits a `parse_as<int>(..)` turbofish call.
///
/// Matching is by leaf name + matching type-argument arity (`==
/// template_type_params.len()`), and only for free functions — member templates
/// (`obj.m<T>()`) are not collected at call sites yet. Cross-file instantiation
/// aggregation (the def in a header, the use in another TU) is a discovery-layer
/// increment; a single self-contained TU resolves here. Deterministic: the
/// instantiation list is sorted/deduped, so the first matching arity wins.
fn annotate_template_instantiations(functions: &mut [CppFunction], source: &str) {
    let has_unresolved_template = functions.iter().any(|f| {
        f.api.is_template
            && !f.api.is_method
            && !f.template_type_params.is_empty()
            && f.instantiation_args.is_empty()
    });
    if !has_unresolved_template {
        return;
    }
    let instantiations = parse_cpp_template_instantiations(source).unwrap_or_default();
    if instantiations.is_empty() {
        return;
    }
    for f in functions.iter_mut() {
        if !f.api.is_template
            || f.api.is_method
            || f.template_type_params.is_empty()
            || !f.instantiation_args.is_empty()
        {
            continue;
        }
        if let Some((_, args)) = instantiations
            .iter()
            .find(|(name, args)| name == &f.name && args.len() == f.template_type_params.len())
        {
            f.instantiation_args = args.clone();
        }
    }
}

pub fn parse_cpp_declarations(source: &str) -> Result<Vec<CppDeclaration>, CppParseError> {
    let source = prepare_cpp_source(source);
    let source = source.as_str();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut decls = Vec::new();
    collect_declarations(tree.root_node(), source.as_bytes(), &mut decls);
    Ok(decls)
}

pub fn parse_cpp_type_defs(source: &str) -> Result<c_parser::CTypeDefs, CppParseError> {
    let source = prepare_cpp_source(source);
    let source = source.as_str();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut defs = c_parser::CTypeDefs::default();
    collect_type_defs(tree.root_node(), source.as_bytes(), &mut defs);

    let mut keep: Vec<c_parser::CStructDef> = Vec::with_capacity(defs.structs.len());
    for d in defs.structs.drain(..) {
        match keep.iter_mut().find(|k| k.name == d.name) {
            Some(existing) => {
                if d.complete && !existing.complete {
                    *existing = d;
                }
            }
            None => keep.push(d),
        }
    }
    defs.structs = keep;
    Ok(defs)
}

/// Return the (leaf) names of classes/structs in `source` that are abstract —
/// i.e. declare at least one pure-virtual member function (`virtual ... = 0;`).
/// An abstract class cannot be instantiated, so a method target whose receiver is
/// abstract must be skipped, never emitted as `Abstract _gf_receiver;`.
pub fn parse_cpp_abstract_classes(
    source: &str,
) -> Result<std::collections::HashSet<String>, CppParseError> {
    let source = prepare_cpp_source(source);
    let source = source.as_str();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut out = std::collections::HashSet::new();
    collect_abstract_classes(tree.root_node(), source.as_bytes(), &mut out);
    Ok(out)
}

/// Map each base class's leaf name to the leaf names of classes/structs that
/// directly derive from it (#456). Used to substitute a concrete subclass as the
/// receiver when a method's declaring class is abstract — `class MemoryReader :
/// public Reader` yields `{"Reader": ["MemoryReader"]}`.
pub fn parse_cpp_subclasses(
    source: &str,
) -> Result<std::collections::HashMap<String, Vec<String>>, CppParseError> {
    let source = prepare_cpp_source(source);
    let source = source.as_str();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut out = std::collections::HashMap::new();
    collect_subclasses(tree.root_node(), source.as_bytes(), &mut out);
    Ok(out)
}

fn collect_subclasses(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    out: &mut std::collections::HashMap<String, Vec<String>>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "base_class_clause" {
                    if let Ok(text) = child.utf8_text(source) {
                        for base in parse_base_leaves(text) {
                            out.entry(base).or_default().push(name.to_owned());
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_subclasses(child, source, out);
    }
}

/// Leaf names of the base classes in a `base_class_clause` text
/// (`: public e57::Reader, private Foo<T>, virtual public Bar` ->
/// `["Reader", "Foo", "Bar"]`), dropping access/virtual keywords, namespace
/// qualification, and template arguments.
fn parse_base_leaves(clause: &str) -> Vec<String> {
    clause
        .trim_start()
        .trim_start_matches(':')
        .split(',')
        .filter_map(|spec| {
            let base: String = spec
                .split_whitespace()
                .filter(|t| !matches!(*t, "public" | "private" | "protected" | "virtual"))
                .collect::<Vec<_>>()
                .join(" ");
            let base = base.split('<').next().unwrap_or(&base).trim();
            let leaf = base.rsplit("::").next().unwrap_or(base).trim();
            leaf.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
                .then(|| leaf.to_owned())
        })
        .collect()
}

/// Concrete template instantiations seen at CALL SITES in `source` (#455 Phase 1):
/// each `func<Type, ...>(args)` call yields `(func_leaf, [type_args])`, e.g.
/// `parse<int>(buf)` -> `("parse", ["int"])`. Deduplicated. This is the foundation
/// for synthesising an instantiated harness per detected specialization — the
/// template-function lane that the ranker currently filters out entirely.
/// Value (non-type) template arguments are ignored; only `type_descriptor` args
/// are recorded. Member-template calls (`obj.m<T>()`) are not yet collected.
pub fn parse_cpp_template_instantiations(
    source: &str,
) -> Result<Vec<(String, Vec<String>)>, CppParseError> {
    let source = prepare_cpp_source(source);
    let source = source.as_str();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut out = Vec::new();
    collect_template_instantiations(tree.root_node(), source.as_bytes(), &mut out);
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_template_instantiations(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    out: &mut Vec<(String, Vec<String>)>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    // A `template_function` node is the `f<T>` callable form (distinct from a
    // `template_type` like `std::vector<int>`). It appears directly as a call's
    // function for `parse<int>(..)` and nested inside a `qualified_identifier` for
    // `ns::convert<..>(..)`, so match it wherever it occurs in the walk.
    if node.kind() == "template_function" {
        if let (Some(name), Some(args)) = (
            node.child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok()),
            node.child_by_field_name("arguments"),
        ) {
            let leaf = name.rsplit("::").next().unwrap_or(name).trim();
            let type_args = collect_template_type_args(args, source);
            if !leaf.is_empty() && !type_args.is_empty() {
                out.push((leaf.to_owned(), type_args));
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_template_instantiations(child, source, out);
    }
}

/// The `type_descriptor` arguments of a `template_argument_list`, whitespace
/// collapsed (`std::string`, `int`). Non-type (value) arguments are skipped.
fn collect_template_type_args(args: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "type_descriptor" {
            if let Ok(text) = child.utf8_text(source) {
                out.push(text.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
    }
    out
}

fn collect_abstract_classes(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    out: &mut std::collections::HashSet<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        if let (Some(name), Some(body)) = (
            node.child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::trim)
                .filter(|s| !s.is_empty()),
            node.child_by_field_name("body"),
        ) {
            if class_body_has_pure_virtual(body, source) {
                out.insert(name.to_owned());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_abstract_classes(child, source, out);
    }
}

/// Whether a class body declares a pure-virtual member. A pure-specifier is a
/// `= 0` that follows the function's closing `)` (after any cv/ref/noexcept/
/// override/final qualifiers) — distinct from a parameter's default `= 0`.
fn class_body_has_pure_virtual(body: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = body.walk();
    for field in body.children(&mut cursor) {
        if field.kind() != "field_declaration" {
            continue;
        }
        let Ok(text) = field.utf8_text(source) else {
            continue;
        };
        if !text.contains("virtual") {
            continue;
        }
        let normalized: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(close) = normalized.rfind(')') {
            let after = normalized[close + 1..].trim_end_matches(';');
            if after.ends_with("=0") {
                return true;
            }
        }
    }
    false
}

pub fn extract_cpp_dictionary_tokens(source: &str) -> Result<Vec<String>, CppParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|_| CppParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(CppParseError::Parse)?;
    let mut tokens = Vec::new();

    for enum_def in parse_cpp_type_defs(source)?.enums {
        for member in enum_def.members {
            push_cpp_enum_dictionary_token(&mut tokens, member);
        }
    }
    collect_cpp_string_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_cpp_case_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_cpp_comparison_dictionary_tokens(tree.root_node(), source.as_bytes(), &mut tokens);
    collect_cpp_define_dictionary_tokens(source, &mut tokens);

    Ok(tokens)
}

/// Mine literal operands of equality/relational comparisons — magic-byte /
/// sentinel / length gates the parser checks (#379). Mirrors the C collector.
fn collect_cpp_comparison_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if let Ok(op) = op.utf8_text(source) {
                if matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=") {
                    for field in ["left", "right"] {
                        if let Some(operand) = node.child_by_field_name(field) {
                            if matches!(
                                operand.kind(),
                                "number_literal" | "char_literal" | "string_literal"
                            ) {
                                if let Ok(text) = operand.utf8_text(source).map(str::trim) {
                                    push_cpp_case_label_dictionary_token(text, tokens);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_cpp_comparison_dictionary_tokens(child, source, tokens);
    }
}

fn collect_cpp_string_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "string_literal" {
        if let Ok(raw) = node.utf8_text(source) {
            if let Some(value) = cpp_string_literal_value(raw) {
                push_dictionary_token(tokens, value);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_cpp_string_dictionary_tokens(child, source, tokens);
    }
}

fn collect_cpp_define_dictionary_tokens(source: &str, tokens: &mut Vec<String>) {
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some((name, value)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        if name.contains('(') {
            continue;
        }
        let value = value
            .split("//")
            .next()
            .unwrap_or("")
            .split("/*")
            .next()
            .unwrap_or("")
            .trim();
        let first = value.split_whitespace().next().unwrap_or("");
        if let Some(value) = cpp_string_literal_value(first) {
            push_dictionary_token(tokens, value);
        } else if is_cpp_integer_literal(first) {
            push_dictionary_token(tokens, first.to_owned());
        }
    }
}

fn collect_cpp_case_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    if node.kind() == "case_statement" {
        if let Some(label) = node.child_by_field_name("value") {
            if let Ok(label) = label.utf8_text(source).map(str::trim) {
                push_cpp_case_label_dictionary_token(label, tokens);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_cpp_case_dictionary_tokens(child, source, tokens);
    }
}

fn push_cpp_case_label_dictionary_token(label: &str, tokens: &mut Vec<String>) {
    if label.is_empty() {
        return;
    }
    if let Some(value) = cpp_string_literal_value(label) {
        push_dictionary_token(tokens, value);
    } else if let Some(value) = cpp_char_literal_value(label) {
        push_dictionary_token(tokens, value);
    } else if is_cpp_integer_literal(label) || is_cpp_identifier(label) {
        push_dictionary_token(tokens, label.to_owned());
    }
}

fn cpp_string_literal_value(raw: &str) -> Option<String> {
    let start = raw.find('"')?;
    let end = raw.rfind('"')?;
    if end <= start {
        return None;
    }
    let mut out = String::new();
    let mut chars = raw[start + 1..end].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => break,
        }
    }
    Some(out)
}

fn cpp_char_literal_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let body = raw.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = body.chars();
    let ch = match chars.next()? {
        '\\' => match chars.next()? {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '0' => '\0',
            '\\' => '\\',
            '\'' => '\'',
            other => other,
        },
        other => other,
    };
    Some(ch.to_string())
}

fn is_cpp_integer_literal(raw: &str) -> bool {
    let trimmed = raw
        .trim_start_matches(['+', '-'])
        .trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    }
    !trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_digit())
}

fn is_cpp_identifier(raw: &str) -> bool {
    let mut chars = raw.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !is_cpp_keyword(raw)
}

fn push_dictionary_token(tokens: &mut Vec<String>, token: String) {
    let token = token.trim().to_owned();
    if token.is_empty() || token.len() > 256 || tokens.contains(&token) {
        return;
    }
    tokens.push(token);
}

fn push_cpp_enum_dictionary_token(tokens: &mut Vec<String>, member: String) {
    if let Some((_, leaf)) = member.rsplit_once("::") {
        push_dictionary_token(tokens, leaf.to_owned());
    }
    push_dictionary_token(tokens, member);
}

fn collect_type_defs(node: tree_sitter::Node<'_>, source: &[u8], defs: &mut c_parser::CTypeDefs) {
    collect_type_defs_scoped(node, source, &[], defs);
}

/// `collect_type_defs`, threading the enclosing struct/class scope so a MEMBER
/// enum is recorded by its fully-qualified tag and enumerators. Sibling structs
/// each declaring `enum value { ... }` (yaml-cpp's `FmtScope` / `GroupType` /
/// `FlowType`) otherwise collide in the bare-name-keyed registry (first wins) and
/// a parameter typed `GroupType::value` resolves to the WRONG members → the
/// harness emits impossible enumerators that don't compile. Only struct/class
/// names enter the scope (namespaces don't): a parameter is spelled with the
/// struct scope it was written under but not its surrounding namespace, so the
/// recorded tag must match that spelling for resolution to hit.
fn collect_type_defs_scoped(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    scope: &[String],
    defs: &mut c_parser::CTypeDefs,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    // We recurse strictly top-down from the root and prune the WHOLE subtree at
    // the first `template_declaration` (returning before visiting its children).
    // So if any ancestor were a template we'd already have stopped there and never
    // reached this node — checking just THIS node's kind is therefore equivalent
    // to the old `has_template_ancestor` ancestor-walk, but O(1) instead of an
    // O(depth) chain of tree-sitter `.parent()` hops. `Node::parent()` is itself
    // O(tree) (it re-descends from the root via `ts_node_child_with_descendant`),
    // so the per-node ancestor walk made `collect_type_defs` O(n^2) in AST size
    // and hung for >8 min on large TUs (e.g. basis_universal's ~40k-line
    // basisu_transcoder.cpp). See the matching `in_template` threading in
    // `collect_functions`.
    if node.kind() == "template_declaration" {
        return;
    }

    let mut nested_scope = None;
    match node.kind() {
        "struct_specifier" | "class_specifier" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            if let Some(name) = name {
                if !is_cpp_keyword(&name) {
                    let body = node.child_by_field_name("body");
                    let default_public = node.kind() == "struct_specifier";
                    defs.structs.push(c_parser::CStructDef {
                        name: name.clone(),
                        fields: body
                            .map(|b| cpp_struct_fields(b, source, default_public))
                            .unwrap_or_default(),
                        line: node.start_position().row as u32 + 1,
                        complete: body.is_some(),
                    });
                    let mut next = scope.to_vec();
                    next.push(name);
                    nested_scope = Some(next);
                }
            }
        }
        "enum_specifier" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            if let (Some(name), Some(body)) = (name, node.child_by_field_name("body")) {
                if !is_cpp_keyword(&name) {
                    let scoped = is_scoped_cpp_enum(node, source);
                    // Prefix the enclosing struct/class scope onto the tag (and, for
                    // an unscoped member enum, its enumerators) so sibling member
                    // enums named the same bare tag stay distinct: `FmtScope::value`
                    // with members `FmtScope::Local`, not `value` with `Local`.
                    let scope_prefix = if scope.is_empty() {
                        String::new()
                    } else {
                        format!("{}::", scope.join("::"))
                    };
                    let qualified_name = format!("{scope_prefix}{name}");
                    let members = enum_members(body, source)
                        .into_iter()
                        .map(|member| {
                            if scoped {
                                // Scoped enumerator is `Tag::Member` (already
                                // scope-prefixed via `qualified_name`).
                                format!("{qualified_name}::{member}")
                            } else {
                                // Unscoped enumerator is injected into the enclosing
                                // scope: `Scope::Member` (bare `Member` at file scope).
                                format!("{scope_prefix}{member}")
                            }
                        })
                        .collect();
                    defs.enums.push(c_parser::CEnumDef {
                        name: qualified_name,
                        members,
                        line: node.start_position().row as u32 + 1,
                    });
                }
            }
        }
        "type_definition" => {
            collect_typedef(node, source, defs);
        }
        "alias_declaration" => {
            collect_alias_declaration(node, source, defs);
        }
        _ => {}
    }

    let active_scope = nested_scope.as_deref().unwrap_or(scope);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_type_defs_scoped(child, source, active_scope, defs);
    }
}

fn cpp_struct_fields(
    body: tree_sitter::Node<'_>,
    source: &[u8],
    default_public: bool,
) -> Vec<c_parser::CParamDescriptor> {
    let mut fields = Vec::new();
    let mut public = default_public;
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "access_specifier" {
            public = child
                .utf8_text(source)
                .is_ok_and(|text| text.trim().trim_end_matches(':') == "public");
            continue;
        }
        if !public {
            continue;
        }
        if child.kind() != "field_declaration" || contains_kind(child, "function_declarator") {
            continue;
        }
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        let base_type = type_node
            .utf8_text(source)
            .map(typedef_underlying_text)
            .unwrap_or_default();
        if base_type.is_empty() {
            continue;
        }
        let mut field_cursor = child.walk();
        for part in child.children(&mut field_cursor) {
            if let Some(descriptor) = cpp_field_descriptor(part, source, &base_type) {
                fields.push(descriptor);
            }
        }
    }
    fields
}

/// C++ `using NAME = UNDERLYING;` alias. Modern C++ uses these instead of
/// `typedef`, so without this the type system can't resolve aliases like
/// jsoncpp's `using UInt = unsigned int;` and bails on parameters of that type.
/// Recorded as a typedef so `type_model` resolves the chain to a scalar/struct.
fn collect_alias_declaration(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    defs: &mut c_parser::CTypeDefs,
) {
    let alias = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok())
        .map(str::trim)
        .filter(|name| !name.is_empty() && !is_cpp_keyword(name));
    let underlying = node
        .child_by_field_name("type")
        .and_then(|n| n.utf8_text(source).ok())
        .map(typedef_underlying_text)
        .filter(|u| !u.is_empty());
    if let (Some(alias), Some(underlying)) = (alias, underlying) {
        defs.typedefs.push(c_parser::CTypedefDef {
            name: alias.to_owned(),
            underlying,
            line: node.start_position().row as u32 + 1,
        });
    }
}

fn collect_typedef(node: tree_sitter::Node<'_>, source: &[u8], defs: &mut c_parser::CTypeDefs) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let declarator_text = declarator
        .utf8_text(source)
        .map(str::trim)
        .unwrap_or_default();
    let alias = if typedef_declarator_is_function_pointer(declarator_text) {
        function_pointer_typedef_alias(declarator_text)
    } else {
        type_identifier_text(declarator, source)
    };
    let Some(alias) = alias else {
        return;
    };
    if is_cpp_keyword(&alias) {
        return;
    }
    let line = node.start_position().row as u32 + 1;

    if typedef_declarator_is_function_pointer(declarator_text) {
        if let Some(underlying) =
            function_pointer_typedef_underlying(type_node, declarator_text, source, &alias)
        {
            defs.typedefs.push(c_parser::CTypedefDef {
                name: alias,
                underlying,
                line,
            });
        }
        return;
    }

    let mut underlying = type_node
        .utf8_text(source)
        .map(typedef_underlying_text)
        .unwrap_or_default();
    if underlying.is_empty() {
        return;
    }
    for _ in 0..typedef_pointer_depth(declarator) {
        underlying.push_str(" *");
    }
    defs.typedefs.push(c_parser::CTypedefDef {
        name: alias,
        underlying,
        line,
    });
}

fn typedef_declarator_is_function_pointer(declarator_text: &str) -> bool {
    declarator_text.contains("(*") && declarator_text.contains(')')
}

fn function_pointer_typedef_alias(declarator_text: &str) -> Option<String> {
    let start = declarator_text.find("(*")? + 2;
    let rest = &declarator_text[start..];
    let end = rest.find(')')?;
    let alias = rest[..end].trim();
    (!alias.is_empty()).then(|| alias.to_owned())
}

fn function_pointer_typedef_underlying(
    type_node: tree_sitter::Node<'_>,
    declarator_text: &str,
    source: &[u8],
    alias: &str,
) -> Option<String> {
    let return_type = type_node
        .utf8_text(source)
        .ok()
        .map(typedef_underlying_text)?;
    if return_type.is_empty() {
        return None;
    }
    let without_alias = declarator_text.replacen(alias, "", 1);
    let signature = normalize_type(&format!("{return_type} {without_alias}"));
    (!signature.is_empty()).then_some(signature)
}

fn typedef_pointer_depth(declarator: tree_sitter::Node<'_>) -> usize {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return 0;
    };
    if declarator.kind() == "pointer_declarator" {
        return 1 + declarator
            .child_by_field_name("declarator")
            .map(typedef_pointer_depth)
            .unwrap_or(0);
    }
    0
}

fn cpp_field_descriptor(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    base_type: &str,
) -> Option<c_parser::CParamDescriptor> {
    let _depth_guard = AstDepthGuard::enter()?;
    match node.kind() {
        "field_identifier" | "identifier" => Some(c_parser::CParamDescriptor {
            name: node.utf8_text(source).ok()?.to_owned(),
            c_type: base_type.to_owned(),
        }),
        "pointer_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let mut descriptor = cpp_field_descriptor(inner, source, base_type)?;
            descriptor.c_type = format!("{} *", descriptor.c_type);
            Some(descriptor)
        }
        "array_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            let descriptor = cpp_field_descriptor(inner, source, base_type)?;
            let size = node
                .child_by_field_name("size")
                .and_then(|s| s.utf8_text(source).ok())
                .unwrap_or("");
            Some(c_parser::CParamDescriptor {
                name: descriptor.name,
                c_type: format!("{}[{}]", descriptor.c_type, size),
            })
        }
        "init_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            cpp_field_descriptor(inner, source, base_type)
        }
        _ => None,
    }
}

fn enum_members(body: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let mut members = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() != "enumerator" {
            continue;
        }
        if let Some(name) = child
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
        {
            members.push(name.to_owned());
        }
    }
    members
}

fn is_scoped_cpp_enum(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    node.utf8_text(source).is_ok_and(|raw| {
        raw.split(|ch: char| ch.is_whitespace() || ch == ':' || ch == '{')
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair == ["enum", "class"] || pair == ["enum", "struct"])
    })
}

fn typedef_underlying_text(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(brace) = trimmed.find('{') {
        trimmed[..brace].trim().to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn type_identifier_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let _depth_guard = AstDepthGuard::enter()?;
    if matches!(node.kind(), "type_identifier" | "identifier") {
        return node.utf8_text(source).ok().map(str::to_owned);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = type_identifier_text(child, source) {
            return Some(found);
        }
    }
    None
}

fn contains_kind(node: tree_sitter::Node<'_>, kind: &str) -> bool {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return false;
    };
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if contains_kind(child, kind) {
            return true;
        }
    }
    false
}

fn collect_declarations(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    decls: &mut Vec<CppDeclaration>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    // If we hit a function_definition with a body, that's a defined function
    // -> parse_cpp_functions handles it. Do not recurse into its body or
    // we'd pick up locally-declared variables as "declarations".
    if node.kind() == "function_definition" && node.child_by_field_name("body").is_some() {
        return;
    }
    let is_decl = matches!(node.kind(), "declaration" | "field_declaration");
    if is_decl {
        if let Some(declarator) = find_function_declarator(node) {
            if let Some(name) = declarator_name_text(declarator, source) {
                if !is_cpp_keyword(&name) {
                    let return_type = declaration_return_type(node, source);
                    let param_types = function_param_types(declarator, source);
                    decls.push(CppDeclaration {
                        name,
                        return_type,
                        param_types,
                        line: node.start_position().row as u32 + 1,
                    });
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_declarations(child, source, decls);
    }
}

fn find_function_declarator<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "function_declarator" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_function_declarator(child) {
            return Some(found);
        }
    }
    None
}

fn declaration_return_type(decl: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(type_node) = decl.child_by_field_name("type") else {
        return String::new();
    };
    let Ok(type_text) = type_node.utf8_text(source) else {
        return String::new();
    };

    // tree-sitter-cpp, like tree-sitter-c, places `type_qualifier` (const,
    // volatile, restrict) as SIBLINGS of the type field, not as part of it.
    // Scan declaration children that appear before the type node and
    // prepend their text so `extern const std::string get_name()` keeps
    // its const in the synthesised stub signature.
    let mut leading_quals = Vec::<String>::new();
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.start_byte() >= type_node.start_byte() {
            break;
        }
        if child.kind() == "type_qualifier" {
            if let Ok(text) = child.utf8_text(source) {
                leading_quals.push(text.trim().to_owned());
            }
        }
    }

    if leading_quals.is_empty() {
        type_text.trim().to_owned()
    } else {
        format!("{} {}", leading_quals.join(" "), type_text.trim())
    }
}

fn function_param_types(declarator: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = declarator.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = params_node.walk();
    for child in params_node.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let span = child
            .utf8_text(source)
            .map(str::trim)
            .unwrap_or("")
            .to_owned();
        if span == "void" || span.is_empty() {
            continue;
        }
        out.push(span);
    }
    out
}

/// Keywords that can never be function names. tree-sitter's error
/// recovery on preprocessor-split control flow (an #ifdef between an
/// `if` and its `else if`) can mangle a statement into a
/// function_definition whose declarator reads `if (cond)`. Exact
/// matches only, so `operator==`-style names stay intact.
const CPP_KEYWORDS: &[&str] = &[
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "return",
    "sizeof",
    "goto",
    "break",
    "continue",
    "typedef",
    "struct",
    "union",
    "enum",
    "static",
    "extern",
    "inline",
    "const",
    "volatile",
    "register",
    "auto",
    "unsigned",
    "signed",
    "int",
    "char",
    "long",
    "short",
    "float",
    "double",
    "void",
    // Builtin types / literals that are never a real namespace/class scope. Listed
    // here so a return type folded into a qualified name by a stray decoration macro
    // (`ada_really_inline bool url::parse_host` -> scope `bool`) is dropped instead
    // of leaking as `ada::bool::parse_host`.
    "bool",
    "wchar_t",
    "char8_t",
    "char16_t",
    "char32_t",
    "true",
    "false",
    "nullptr",
    "namespace",
    "class",
    "template",
    "using",
    "new",
    "delete",
    "try",
    "catch",
    "throw",
    "operator",
    "constexpr",
    "noexcept",
    "public",
    "private",
    "protected",
    "virtual",
    "friend",
    "typename",
    "this",
];

fn is_cpp_keyword(name: &str) -> bool {
    CPP_KEYWORDS.contains(&name)
}

fn has_static_storage(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| {
        c.kind() == "storage_class_specifier" && c.utf8_text(source).is_ok_and(|t| t == "static")
    });
    found
}

// RTOS/vendor platform macros are foreign on ANY host (a Linux/Windows lab box
// can't run a VxWorks/INTEGRITY/QNX image), so they appear in both variants. A
// `#ifdef __vxworks` branch is then tagged + routed to a stub-isolated build.
#[cfg(not(windows))]
const FOREIGN_PLATFORM_MACROS: &[&str] = &[
    "_WIN32",
    "_WIN64",
    "_MSC_VER",
    "__MINGW32__",
    "__MINGW64__",
    "__vxworks",
    "__VXWORKS__",
    "__INTEGRITY",
    "__QNX__",
    "__QNXNTO__",
];
#[cfg(windows)]
const FOREIGN_PLATFORM_MACROS: &[&str] = &[
    "__linux__",
    "__APPLE__",
    "__unix__",
    "__vxworks",
    "__VXWORKS__",
    "__INTEGRITY",
    "__QNX__",
    "__QNXNTO__",
];

/// `#ifdef FOO` → Some("FOO") when FOO is foreign. `#if <expr>` →
/// Some(expr) when the expr mentions a foreign macro and contains no
/// negation (`!`), so `#if !defined(_WIN32)` stays unflagged.
fn foreign_guard_of(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "preproc_ifdef" => {
            let directive = node.child(0)?.utf8_text(source).ok()?;
            if directive != "#ifdef" {
                return None; // #ifndef FOREIGN guards the *portable* branch
            }
            let name = node.child_by_field_name("name")?.utf8_text(source).ok()?;
            FOREIGN_PLATFORM_MACROS
                .contains(&name)
                .then(|| name.to_owned())
        }
        "preproc_if" => {
            let cond = node
                .child_by_field_name("condition")?
                .utf8_text(source)
                .ok()?;
            (!cond.contains('!') && FOREIGN_PLATFORM_MACROS.iter().any(|m| cond.contains(m)))
                .then(|| cond.trim().to_owned())
        }
        _ => None,
    }
}

/// `#if 0` bodies are dead by definition; only the #else/#elif
/// alternatives can be live.
fn is_dead_preproc_if(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    node.kind() == "preproc_if"
        && node
            .child_by_field_name("condition")
            .and_then(|c| c.utf8_text(source).ok())
            .is_some_and(|t| t.trim() == "0")
}

#[allow(clippy::too_many_arguments)]
fn collect_functions(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    namespace_stack: &[String],
    class_stack: &[String],
    guard: Option<&str>,
    member_access: Option<&'static str>,
    member_access_declarations: &std::collections::BTreeMap<String, String>,
    in_template: bool,
    template_params: &[String],
    in_anon_namespace: bool,
    functions: &mut Vec<CppFunction>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    // A free function inside an UNNAMED `namespace { ... }` has internal linkage —
    // it is not callable from the harness's separate translation unit. tree-sitter
    // exposes such a namespace as a `namespace_definition` with no `name` field, so
    // OR that into the flag threaded down the walk (mirrors how `in_template` is
    // accumulated). Combined with `has_static_storage` at the push site, it makes
    // anon-namespace helpers (yaml-cpp `IsValidPlainScalar`, ada-url
    // `ada::try_can_parse_absolute_fast`) get `is_static`, so discovery's
    // `is_static && !is_method` gate skips them instead of emitting an unbuildable
    // cross-TU call.
    let in_anon_namespace = in_anon_namespace
        || (node.kind() == "namespace_definition"
            && node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none());
    // Whether we are anywhere inside a `template_declaration`, threaded DOWN the
    // recursion instead of re-derived per node via `has_template_ancestor` (whose
    // tree-sitter `.parent()` hops are each O(tree), making the walk O(n^2) and
    // hanging on large TUs). Accumulating on the way down is O(1) per node and
    // identical: a `function_definition` is never itself a `template_declaration`,
    // so `in_template` here equals the old ancestor-walk result.
    let in_template = in_template || node.kind() == "template_declaration";
    // Carry the nearest enclosing template's type-parameter names down the walk so
    // a templated `function_definition` records them (#455 / §27.5). A nested
    // template (a member template inside a class template) overrides with its own.
    let own_template_params = (node.kind() == "template_declaration")
        .then(|| template_parameter_names(node, source))
        .filter(|names| !names.is_empty());
    let template_params: &[String] = match own_template_params.as_deref() {
        Some(names) => names,
        None => template_params,
    };
    let guard_outer = guard;
    if is_dead_preproc_if(node, source) {
        if let Some(alt) = node.child_by_field_name("alternative") {
            collect_functions(
                alt,
                source,
                namespace_stack,
                class_stack,
                guard_outer,
                member_access,
                member_access_declarations,
                in_template,
                template_params,
                in_anon_namespace,
                functions,
            );
        }
        return;
    }
    let own_guard = foreign_guard_of(node, source);
    let guard = own_guard.as_deref().or(guard_outer);
    // Track the surrounding namespace(s) so a definition like
    // `int XmlReader::parse(...)` written inside `namespace acme {
    // namespace v2 { ... } }` is captured as
    // qualifier_path = ["acme", "v2", "XmlReader"], not just
    // ["XmlReader"]. Without this, the C++ harness emitter can't
    // generate a fully-qualified receiver-instance type.
    let mut nested = None;
    if node.kind() == "namespace_definition" {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            let mut next = namespace_stack.to_vec();
            // tree-sitter exposes `namespace X::Y { }` as a single
            // `nested_namespace_specifier` name; split on `::` so each
            // segment lands as its own qualifier entry.
            for seg in name.split("::").filter(|s| !s.is_empty()) {
                next.push(seg.to_owned());
            }
            nested = Some(next);
        }
    }
    let active_stack = nested.as_deref().unwrap_or(namespace_stack);
    let mut nested_class = None;
    let mut active_member_access = member_access;
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        {
            let mut next = class_stack.to_vec();
            next.push(name);
            nested_class = Some(next);
            active_member_access = Some(if node.kind() == "struct_specifier" {
                "public"
            } else {
                "private"
            });
        }
    }
    let active_class_stack = nested_class.as_deref().unwrap_or(class_stack);

    if node.kind() == "function_definition" && node.child_by_field_name("body").is_some() {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(name) = declarator_name_text(declarator, source) {
                if !is_cpp_keyword(&name) {
                    let return_type = function_return_type(node, source);
                    let params = function_params(declarator, source);
                    // A `friend` function declared inside a class body is a FREE
                    // function (enclosing-namespace scope, reached via ADL), not a
                    // member — don't attach the class as a receiver.
                    let is_friend = is_friend_function(node, source);
                    let mut qualifier_path = active_stack.to_vec();
                    if !is_friend {
                        for seg in active_class_stack {
                            qualifier_path.push(seg.clone());
                        }
                    }
                    for seg in declarator_qualifier_path(declarator, source) {
                        qualifier_path.push(seg);
                    }
                    qualifier_path.dedup();
                    let mut api =
                        cpp_api_metadata(&name, &qualifier_path, active_stack.len(), in_template);
                    if api.is_method {
                        let param_types = params
                            .iter()
                            .map(|param| param.cpp_type.clone())
                            .collect::<Vec<_>>();
                        api.member_access = active_member_access.map(str::to_owned).or_else(|| {
                            member_access_declarations
                                .get(&member_access_key(&qualifier_path, &name, &param_types))
                                .cloned()
                        });
                        if api
                            .member_access
                            .as_deref()
                            .is_some_and(|access| access != "public")
                            && !api
                                .unsupported
                                .iter()
                                .any(|item| item == "non_public_member")
                        {
                            api.unsupported.push("non_public_member".to_owned());
                        }
                    }
                    functions.push(CppFunction {
                        name,
                        line: node.start_position().row as u32 + 1,
                        return_type,
                        params,
                        qualifier_path,
                        api,
                        is_static: has_static_storage(node, source) || in_anon_namespace,
                        foreign_guard: guard.map(str::to_owned),
                        template_type_params: template_params.to_vec(),
                        instantiation_args: Vec::new(),
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    if node.kind() == "field_declaration_list" && !active_class_stack.is_empty() {
        let mut current_access = active_member_access.unwrap_or("private");
        for child in node.children(&mut cursor) {
            if child.kind() == "access_specifier" {
                if let Some(access) = cpp_access_specifier(child, source) {
                    current_access = access;
                }
                continue;
            }
            let child_guard = if matches!(child.kind(), "preproc_else" | "preproc_elif") {
                guard_outer
            } else {
                guard
            };
            collect_functions(
                child,
                source,
                active_stack,
                active_class_stack,
                child_guard,
                Some(current_access),
                member_access_declarations,
                in_template,
                template_params,
                in_anon_namespace,
                functions,
            );
        }
        return;
    }
    for child in node.children(&mut cursor) {
        // The #else/#elif branch of a foreign-guarded conditional is
        // the *non-foreign* branch — recurse with the outer guard.
        let child_guard = if matches!(child.kind(), "preproc_else" | "preproc_elif") {
            guard_outer
        } else {
            guard
        };
        collect_functions(
            child,
            source,
            active_stack,
            active_class_stack,
            child_guard,
            active_member_access,
            member_access_declarations,
            in_template,
            template_params,
            in_anon_namespace,
            functions,
        );
    }
}

/// Type-parameter NAMES declared by a `template_declaration` node's parameter
/// list — `["T"]` for `template<typename T>`, `["K", "V"]` for
/// `template<class K, class V>`. Only TYPE parameters (`typename`/`class`,
/// including ones with a default like `typename U = int`) are returned; non-type
/// (value) and template-template parameters are skipped, since only type
/// arguments are substituted by the instantiation lane.
fn template_parameter_names(node: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let Some(list) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if matches!(
            child.kind(),
            "type_parameter_declaration" | "optional_type_parameter_declaration"
        ) {
            let mut inner = child.walk();
            for sub in child.children(&mut inner) {
                if sub.kind() == "type_identifier" {
                    if let Ok(name) = sub.utf8_text(source) {
                        let name = name.trim();
                        if !name.is_empty() {
                            out.push(name.to_owned());
                        }
                    }
                }
            }
        }
    }
    out
}

fn collect_member_access_declarations(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    namespace_stack: &[String],
    class_stack: &[String],
    member_access: Option<&'static str>,
    declarations: &mut std::collections::BTreeMap<String, String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut nested = None;
    if node.kind() == "namespace_definition" {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            let mut next = namespace_stack.to_vec();
            for seg in name.split("::").filter(|s| !s.is_empty()) {
                next.push(seg.to_owned());
            }
            nested = Some(next);
        }
    }
    let active_stack = nested.as_deref().unwrap_or(namespace_stack);

    let mut nested_class = None;
    let mut active_member_access = member_access;
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        {
            let mut next = class_stack.to_vec();
            next.push(name);
            nested_class = Some(next);
            active_member_access = Some(if node.kind() == "struct_specifier" {
                "public"
            } else {
                "private"
            });
        }
    }
    let active_class_stack = nested_class.as_deref().unwrap_or(class_stack);

    if !active_class_stack.is_empty() && node.kind() == "field_declaration" {
        if let Some(declarator) = find_function_declarator(node) {
            if let Some(name) = declarator_name_text(declarator, source) {
                if !is_cpp_keyword(&name) {
                    let mut qualifier_path = active_stack.to_vec();
                    qualifier_path.extend(active_class_stack.iter().cloned());
                    let param_types = function_params(declarator, source)
                        .into_iter()
                        .map(|param| param.cpp_type)
                        .collect::<Vec<_>>();
                    declarations.insert(
                        member_access_key(&qualifier_path, &name, &param_types),
                        active_member_access.unwrap_or("private").to_owned(),
                    );
                }
            }
        }
    }

    let mut cursor = node.walk();
    if node.kind() == "field_declaration_list" && !active_class_stack.is_empty() {
        let mut current_access = active_member_access.unwrap_or("private");
        for child in node.children(&mut cursor) {
            if child.kind() == "access_specifier" {
                if let Some(access) = cpp_access_specifier(child, source) {
                    current_access = access;
                }
                continue;
            }
            collect_member_access_declarations(
                child,
                source,
                active_stack,
                active_class_stack,
                Some(current_access),
                declarations,
            );
        }
        return;
    }

    for child in node.children(&mut cursor) {
        collect_member_access_declarations(
            child,
            source,
            active_stack,
            active_class_stack,
            active_member_access,
            declarations,
        );
    }
}

fn cpp_access_specifier(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<&'static str> {
    match node.utf8_text(source).ok()?.trim().trim_end_matches(':') {
        "public" => Some("public"),
        "private" => Some("private"),
        "protected" => Some("protected"),
        _ => None,
    }
}

/// `<class>::<method>` → access (`public`/`private`/`protected`) for every method
/// DECLARED inside a class/struct body in `source`. Built to resolve the access of
/// methods DEFINED out-of-line in a `.cpp` (whose definition carries no access
/// specifier, so [`parse_cpp_functions`] leaves `member_access` = None): parse the
/// class's HEADER with this and fill the gap. Unlike `parse_cpp_functions`, which
/// only collects function *definitions* (nodes with a body), this collects in-class
/// *declarations*. Keyed by class + method only — no namespace or parameter types —
/// because access is a per-declaration property overloads share, and that key is
/// robust to the namespace/param spelling drift between a header declaration and a
/// `.cpp` definition.
pub fn parse_cpp_method_access(source: &str) -> std::collections::BTreeMap<String, String> {
    let source = prepare_cpp_source(source);
    let mut out = std::collections::BTreeMap::new();
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return out;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return out;
    };
    collect_method_access(
        tree.root_node(),
        source.as_bytes(),
        None,
        "private",
        &mut out,
    );
    out
}

fn collect_method_access(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    enclosing_class: Option<&str>,
    // Default access of `enclosing_class`'s body: a `class` body starts private, a
    // `struct` body starts public. Threaded down so the `field_declaration_list`
    // (a child of the class/struct node) knows which default applies before the
    // first explicit `public:`/`private:` specifier.
    default_access: &str,
    out: &mut std::collections::BTreeMap<String, String>,
) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut class_name = enclosing_class.map(str::to_owned);
    let mut child_default = default_access;
    if matches!(node.kind(), "class_specifier" | "struct_specifier") {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            class_name = Some(name.to_owned());
            child_default = if node.kind() == "struct_specifier" {
                "public"
            } else {
                "private"
            };
        }
    }
    if node.kind() == "field_declaration_list" {
        if let Some(cls) = class_name.as_deref() {
            let mut access = default_access;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "access_specifier" {
                    if let Some(a) = cpp_access_specifier(child, source) {
                        access = a;
                    }
                    continue;
                }
                if child.kind() == "field_declaration" {
                    if let Some(declarator) = find_function_declarator(child) {
                        if let Some(name) = declarator_name_text(declarator, source) {
                            if !is_cpp_keyword(&name) {
                                out.entry(format!("{cls}::{name}"))
                                    .or_insert_with(|| access.to_owned());
                            }
                        }
                    }
                }
                // Nested types in the body recurse with their own class scope.
                collect_method_access(child, source, Some(cls), access, out);
            }
            return;
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_method_access(child, source, class_name.as_deref(), child_default, out);
    }
}

fn member_access_key(qualifier_path: &[String], name: &str, param_types: &[String]) -> String {
    let mut path = qualifier_path.to_vec();
    path.push(name.to_owned());
    format!(
        "{}({})",
        path.join("::"),
        param_types
            .iter()
            .map(|param| normalize_type(param))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn cpp_api_metadata(
    name: &str,
    qualifier_path: &[String],
    namespace_depth: usize,
    is_template: bool,
) -> CppApiMetadata {
    // `collect_functions` knows the structural split: the first
    // `namespace_depth` segments are enclosing namespaces, the rest are class
    // qualifiers (from a class body or an out-of-line `Class::` declarator).
    // A function is a method iff it has at least one class qualifier — decided
    // structurally, never from capitalization, so a capitalized namespace
    // (jsoncpp's `Json`) is not mistaken for a class.
    let namespace_depth = namespace_depth.min(qualifier_path.len());
    let namespace_path = qualifier_path[..namespace_depth].to_vec();
    let class_name = qualifier_path[namespace_depth..].last().cloned();
    let is_constructor = class_name
        .as_ref()
        .is_some_and(|class_name| name == class_name);
    let is_destructor = class_name
        .as_ref()
        .is_some_and(|class_name| name == format!("~{class_name}"));
    let is_method = class_name.is_some();
    let api_kind = if is_constructor {
        "constructor"
    } else if is_destructor {
        "destructor"
    } else if is_method {
        "method"
    } else if is_template {
        "template_function"
    } else {
        "function"
    }
    .to_owned();
    let mut overload_key_parts = qualifier_path.to_vec();
    overload_key_parts.push(name.to_owned());
    let overload_key = overload_key_parts.join("::");
    let mut unsupported = Vec::new();
    if is_template {
        unsupported.push("template_definition".to_owned());
    }
    CppApiMetadata {
        api_kind,
        namespace_path,
        class_name,
        member_access: None,
        is_method,
        is_constructor,
        is_destructor,
        is_template,
        overload_key,
        unsupported,
    }
}

fn annotate_overload_sets(functions: &mut [CppFunction]) {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for function in functions.iter() {
        *counts.entry(function.api.overload_key.clone()).or_insert(0) += 1;
    }
    for function in functions {
        if counts
            .get(&function.api.overload_key)
            .is_some_and(|count| *count > 1)
            && !function
                .api
                .unsupported
                .iter()
                .any(|item| item == "overload_set")
        {
            function.api.unsupported.push("overload_set".to_owned());
        }
    }
}

fn function_return_type(def: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(type_node) = def.child_by_field_name("type") else {
        return String::new();
    };
    let declarator = def.child_by_field_name("declarator");
    // The `type` field alone is just the base (`char`), dropping a leading
    // `const`/`volatile` (a sibling type_qualifier) and the pointer `*`/`&`
    // (which lives inside the declarator). Capture the full span from the
    // definition start to the declarator for the qualifiers + base, then pull
    // the declarator's leading pointer run — so `const char* f()` yields
    // `const char *`, not `char`.
    let prefix = match declarator {
        Some(decl) => std::str::from_utf8(&source[def.start_byte()..decl.start_byte()])
            .map(str::trim)
            .unwrap_or_default()
            .to_owned(),
        None => type_node
            .utf8_text(source)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default(),
    };
    // Drop storage/function specifiers that aren't part of the value type.
    let base = prefix
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "static" | "inline" | "virtual" | "explicit" | "constexpr" | "friend" | "extern"
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let stars: String = declarator
        .and_then(|d| d.utf8_text(source).ok())
        .map(|text| {
            text.trim_start()
                .chars()
                .take_while(|c| *c == '*' || *c == '&')
                .collect()
        })
        .unwrap_or_default();
    if stars.is_empty() {
        normalize_type(&base)
    } else {
        normalize_type(&format!("{base} {stars}"))
    }
}

/// Whether `tok` is a `restrict`-style qualifier: the standard keyword spellings
/// (`restrict` / `__restrict` / `__restrict__`) or a project macro that expands to
/// one (xxHash's `XXH_RESTRICT`, the conventional `RESTRICT` / `_Restrict`). Such a
/// token sits in the parameter QUALIFIER position — after the base type and any
/// `*`, immediately before the name — exactly like `const`/`volatile`, and must be
/// stripped, never treated as a type or a name. Matched whole-word against the
/// macro convention (any underscore-separated segment is exactly `restrict`) so an
/// ordinary identifier like `restrictions` or `__restricted` is not stripped.
fn is_restrict_qualifier_macro(tok: &str) -> bool {
    tok.to_ascii_lowercase()
        .split('_')
        .any(|seg| seg == "restrict")
}

/// Whether `tok` is a macro-shaped qualifier decorator — an ALL-CAPS identifier
/// (uppercase, digits, underscores only, with at least one letter). Used solely to
/// disambiguate the first of two adjacent declarator identifiers
/// (`<type> * MACRO name`): in valid C++ the first must be a qualifier macro and
/// the second the real name. Real parameter names are conventionally not ALL-CAPS,
/// so this never strips a genuine lower/mixed-case name.
fn is_macro_shaped_qualifier(tok: &str) -> bool {
    !tok.is_empty()
        && tok.chars().any(|c| c.is_ascii_uppercase())
        && tok
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// First identifier in a subtree (the real parameter name buried in an `ERROR`
/// node, e.g. `acc` from `ERROR [acc]`).
fn first_identifier_descendant(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return String::new();
    };
    if matches!(node.kind(), "identifier" | "field_identifier") {
        return node.utf8_text(source).unwrap_or("").trim().to_owned();
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let found = first_identifier_descendant(child, source);
        if !found.is_empty() {
            return found;
        }
    }
    String::new()
}

/// Recover the real parameter name that tree-sitter stranded in a trailing `ERROR`
/// sibling when an UNKNOWN restrict-qualifier macro sits between the `*` and the
/// name (`const void* XXH_RESTRICT input`). The grammar cannot expand `XXH_RESTRICT`,
/// so it takes the macro as the declarator's identifier and pushes the real `input`
/// into an `ERROR` node following the `parameter_declaration`. Returns the first
/// plain identifier among the sibling tokens up to the next `,` / `)`.
fn trailing_error_param_name(param_decl: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let mut sib = param_decl.next_sibling();
    while let Some(node) = sib {
        if matches!(node.kind(), "," | ")") {
            break;
        }
        let id = first_identifier_descendant(node, source);
        if is_cpp_identifier(&id) {
            return Some(id);
        }
        sib = node.next_sibling();
    }
    None
}

fn function_params(declarator: tree_sitter::Node<'_>, source: &[u8]) -> Vec<CppParamDescriptor> {
    let Some(list) = find_parameter_list(declarator) else {
        return Vec::new();
    };
    let mut params = Vec::new();
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let declarator_node = child.child_by_field_name("declarator");
        let type_text = match declarator_node {
            Some(decl) => {
                let start = child.start_byte();
                let end = decl.start_byte();
                std::str::from_utf8(&source[start..end])
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default()
            }
            None => child
                .child_by_field_name("type")
                .and_then(|n| n.utf8_text(source).ok())
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
        };
        let raw_decl = declarator_node
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        let (mut name, pointer_suffix) = split_declarator(&raw_decl);
        // An unknown restrict-qualifier macro between the `*` and the name
        // (`const void* XXH_RESTRICT input`, xxhash.h, compiled as C++) is
        // mis-modelled by tree-sitter as the declarator's identifier, leaving the
        // macro as the parameter `name` and stranding the real `input` in a
        // trailing ERROR node. The type text before the declarator is already
        // clean (`const void *`); only the name is wrong. Treat the macro as the
        // qualifier it is — drop it and recover the real name — so the harness
        // neither emits nor stubs `XXH_RESTRICT` (emitting it as the decode
        // variable yields `redefinition of 'XXH_RESTRICT'` once the project
        // header that #defines the macro is included).
        if is_restrict_qualifier_macro(&name) || is_macro_shaped_qualifier(&name) {
            match trailing_error_param_name(child, source) {
                Some(real) => name = real,
                None if is_restrict_qualifier_macro(&name) => name.clear(),
                None => {}
            }
        }
        if name.is_empty() && type_text.is_empty() {
            continue;
        }
        if type_text == "void" && name.is_empty() {
            continue;
        }
        let full_type = if pointer_suffix.is_empty() {
            normalize_type(&type_text)
        } else {
            normalize_type(&format!("{type_text} {pointer_suffix}"))
        };
        params.push(CppParamDescriptor {
            name,
            cpp_type: full_type,
        });
    }
    params
}

fn find_parameter_list<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "parameter_list" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(list) = find_parameter_list(child) {
            return Some(list);
        }
    }
    None
}

fn split_declarator(raw: &str) -> (String, String) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (String::new(), String::new());
    }
    let mut pointer = String::new();
    let mut name = trimmed.trim_start();
    // Peel pointer / reference tokens and any cv / restrict qualifier that binds
    // to the pointer (`T * const name`, `T * __restrict name`). `__restrict__`
    // before `__restrict` so the longer GNU spelling strips whole. Without
    // stripping `restrict`/`__restrict`/`__restrict__` the qualifier leaks into
    // the parameter name (`void* __restrict dst` -> name `__restrict dst`,
    // dropping the real `dst`).
    loop {
        if let Some(rest) = name.strip_prefix('*') {
            pointer.push('*');
            name = rest.trim_start();
            continue;
        }
        if let Some(rest) = name.strip_prefix('&') {
            pointer.push('&');
            name = rest.trim_start();
            continue;
        }
        let mut stripped = false;
        for qualifier in [
            "const",
            "volatile",
            "restrict",
            "__restrict__",
            "__restrict",
        ] {
            if let Some(rest) = name.strip_prefix(qualifier) {
                // Only a *whole-word* qualifier, not a prefix of an identifier
                // like `constant` or `restrictions`.
                if rest.is_empty()
                    || rest.starts_with(|c: char| c.is_whitespace() || c == '*' || c == '&')
                {
                    name = rest.trim_start();
                    stripped = true;
                    break;
                }
            }
        }
        if !stripped {
            break;
        }
    }
    (name.trim().to_owned(), pointer)
}

fn normalize_type(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn declarator_qualifier_path(node: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return Vec::new();
    };
    // Walk into nested declarators looking for a `qualified_identifier`. The
    // qualifier path is every name segment before the final `::` separator.
    if node.kind() == "qualified_identifier" {
        return qualified_identifier_scopes(node, source);
    }
    if let Some(inner) = node.child_by_field_name("declarator") {
        return declarator_qualifier_path(inner, source);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let path = declarator_qualifier_path(child, source);
        if !path.is_empty() {
            return path;
        }
    }
    Vec::new()
}

/// Whether a function node is a `friend` declaration/definition (so it is a free
/// function in the enclosing namespace, not a member of the class it sits in).
/// tree-sitter-cpp either wraps it in a `friend_declaration` or carries a leading
/// `friend` token before the declarator.
fn is_friend_function(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    if let Some(parent) = node.parent() {
        if parent.kind() == "friend_declaration" {
            return true;
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Specifiers precede the declarator; stop once we reach it.
        if child.kind().ends_with("declarator") {
            break;
        }
        if child.kind() == "friend" || child.utf8_text(source).map(str::trim) == Ok("friend") {
            return true;
        }
    }
    false
}

/// Collect the scope segments of a `qualified_identifier` in source order,
/// EXCLUDING the final unqualified name. tree-sitter-cpp nests a qualified name
/// right-associatively (`a::(b::(c::f))`), so the qualifier is the top `scope`
/// followed by recursing into a `qualified_identifier` `name`; the recursion
/// stops at the plain-identifier final name. The old one-level walk both
/// reversed the order and dropped middle components.
fn qualified_identifier_scopes(node: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return Vec::new();
    };
    let mut parts = Vec::new();
    if let Some(scope) = node.child_by_field_name("scope") {
        // A left-associative or template scope can itself hold several `::`
        // segments in one node — split defensively so none are merged.
        if let Ok(text) = scope.utf8_text(source) {
            for seg in text.split("::") {
                let seg = seg.trim();
                // A keyword segment (`class`, `new`, ...) is an error-recovery
                // artifact, never a real scope; dropping it stops bogus receivers.
                if !seg.is_empty() && !is_cpp_keyword(seg) {
                    parts.push(seg.to_owned());
                }
            }
        }
    }
    // A stray (lowercase) decoration macro before an out-of-line definition makes
    // tree-sitter read the macro as the return type and fold the real
    // `<return-type> Class::method` into one qualified name: the leaked return type
    // becomes the `scope` (dropped above when it is a builtin type such as `bool`)
    // and the true class is stranded in an `(ERROR (identifier))` sibling between the
    // scope and the name. Recover those so
    // `ada_really_inline bool url::parse_host` yields `["url"]`, not `["bool"]`.
    let name_field = node.child_by_field_name("name");
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "ERROR" && Some(child) != name_field {
            push_error_scopes(child, source, &mut parts);
        }
    }
    if let Some(name) = name_field {
        if name.kind() == "qualified_identifier" {
            parts.extend(qualified_identifier_scopes(name, source));
        }
    }
    parts
}

/// Pull identifier scope segments out of an `(ERROR ...)` recovery node, dropping
/// keyword/builtin-type noise. Used to recover the real class qualifier when a
/// stray decoration macro derails the structural parse of an out-of-line method.
fn push_error_scopes(node: tree_sitter::Node<'_>, source: &[u8], parts: &mut Vec<String>) {
    let Some(_depth_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "namespace_identifier" | "type_identifier" => {
                if let Ok(text) = child.utf8_text(source) {
                    let seg = text.trim();
                    if !seg.is_empty() && !is_cpp_keyword(seg) {
                        parts.push(seg.to_owned());
                    }
                }
            }
            "ERROR" | "qualified_identifier" => push_error_scopes(child, source, parts),
            _ => {}
        }
    }
}

fn declarator_name_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let _depth_guard = AstDepthGuard::enter()?;
    if node.kind() == "destructor_name" {
        return node
            .child_by_field_name("name")
            .or_else(|| node.named_child(0))
            .and_then(|name_node| name_node.utf8_text(source).ok())
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| format!("~{text}"));
    }

    if node.kind() == "operator_cast" {
        return node
            .child_by_field_name("type")
            .and_then(|type_node| type_node.utf8_text(source).ok())
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| format!("operator {text}"));
    }

    if let Some(declarator) = node.child_by_field_name("declarator") {
        return declarator_name_text(declarator, source);
    }

    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "operator_name"
    ) {
        return node
            .utf8_text(source)
            .ok()
            .filter(|text| !text.is_empty())
            .map(str::to_owned);
    }

    let mut cursor = node.walk();
    let mut name = None;
    for child in node.children(&mut cursor) {
        if let Some(child_name) = declarator_name_text(child, source) {
            name = Some(child_name);
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pathologically deep source must not stack-overflow (abort the process)
    /// in our recursive walkers before the build (#407). tree-sitter parses the
    /// deep input fine; the bound lives in our walkers, every one of which
    /// descends into all children — so any deeply-nested AST exercises them.
    /// DEEP is built well past both `MAX_AST_DEPTH` and the no-guard overflow
    /// threshold, so the test also catches a regression that removes the guard.
    /// The constructs (nested blocks / namespaces) are ones tree-sitter-cpp
    /// parses linearly — deeply-nested C++ *expressions* trip the grammar's GLR
    /// ambiguity search and are pathologically slow to parse (unrelated to the
    /// walk bound under test), so they are avoided here.
    #[test]
    fn deep_nesting_does_not_overflow() {
        const DEEP: usize = 2000;
        // A normal shallow function placed ABOVE each deep construct so the
        // walker reaches it before bottoming out in the deep subtree.
        let shallow = "struct Shallow { int field; };\nint top_decl(int);\nint f() { return 0; }\n";

        // ~2000-deep nested compound statements (compound_statement chain).
        let mut nested_blocks = String::from(shallow);
        nested_blocks.push_str("int g(int x) {\n");
        nested_blocks.push_str(&"{\n".repeat(DEEP));
        nested_blocks.push_str("    x = x + 1;\n");
        nested_blocks.push_str(&"}\n".repeat(DEEP));
        nested_blocks.push_str("    return x;\n}\n");

        // ~2000-deep nested namespaces (namespace_definition chain), with a
        // member buried at the bottom so the member-access walker descends too.
        let mut nested_ns = String::from(shallow);
        nested_ns.push_str(&"namespace ns { ".repeat(DEEP));
        nested_ns.push_str("struct Buried { int deep_method(); };");
        nested_ns.push_str(&"}".repeat(DEEP));
        nested_ns.push('\n');

        for src in [&nested_blocks, &nested_ns] {
            // None of these calls may abort the process via stack overflow.
            let funcs = parse_cpp_functions(src).expect("parse functions");
            assert!(
                funcs.iter().any(|fun| fun.name == "f"),
                "shallow function above the deep construct must still be found"
            );
            let decls = parse_cpp_declarations(src).expect("parse declarations");
            assert!(
                decls.iter().any(|d| d.name == "top_decl"),
                "shallow prototype above the deep construct must still be found"
            );
            let defs = parse_cpp_type_defs(src).expect("parse type defs");
            assert!(
                defs.structs.iter().any(|s| s.name == "Shallow"),
                "shallow struct above the deep construct must still be found"
            );
            count_parse_errors(src);
            parse_cpp_abstract_classes(src).expect("abstract classes");
            extract_cpp_dictionary_tokens(src).expect("dictionary tokens");
        }
    }

    /// The depth cap is far above any legitimate nesting: a modest ~50-deep
    /// nested-namespace construct still walks fully, so a function buried at the
    /// bottom is found with its full qualifier path.
    #[test]
    fn normal_nesting_is_unaffected() {
        const DEPTH: usize = 50;
        let mut src = String::new();
        for i in 0..DEPTH {
            src.push_str(&format!("namespace n{i} {{ "));
        }
        src.push_str("void deep_fn() {}");
        src.push_str(&"}".repeat(DEPTH));
        src.push('\n');

        let funcs = parse_cpp_functions(&src).expect("parse functions");
        let deep = funcs
            .iter()
            .find(|f| f.name == "deep_fn")
            .expect("a function nested ~50 namespaces deep must still be discovered");
        assert_eq!(
            deep.qualifier_path.len(),
            DEPTH,
            "the full ~{DEPTH}-deep namespace qualifier path must be recovered (cap must not truncate real code)"
        );
    }

    #[test]
    fn export_macro_between_class_keyword_and_name_does_not_detach_members() {
        // tinyxml2 shape: `class TINYXML2_LIB XMLElement`. The unexpanded export
        // macro must not make tree-sitter read the class as a function and
        // orphan its members — the constructor must be a constructor of the
        // class, and the method must keep its receiver class + access.
        let src = "namespace tinyxml2 {\n\
                   class TINYXML2_LIB XMLElement {\n\
                   public:\n\
                       XMLElement() { x = 0; }\n\
                       void SetAttribute(const char* name, int value) { (void)name; (void)value; }\n\
                   private:\n\
                       void Hidden() {}\n\
                       int x;\n\
                   };\n\
                   }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let ctor = fns
            .iter()
            .find(|f| f.name == "XMLElement")
            .expect("constructor discovered");
        assert_eq!(ctor.api.class_name.as_deref(), Some("XMLElement"));
        assert!(
            ctor.api.is_constructor,
            "XMLElement() must be a constructor"
        );
        assert_ne!(
            ctor.return_type, "class TINYXML2_LIB",
            "export macro leaked into the constructor return type"
        );

        let setter = fns
            .iter()
            .find(|f| f.name == "SetAttribute")
            .expect("method discovered");
        assert_eq!(
            setter.api.class_name.as_deref(),
            Some("XMLElement"),
            "method must keep its receiver class (else it is emitted as a free call)"
        );
        assert_eq!(setter.api.member_access.as_deref(), Some("public"));

        let hidden = fns.iter().find(|f| f.name == "Hidden").expect("hidden");
        assert_eq!(hidden.api.member_access.as_deref(), Some("private"));
    }

    #[test]
    fn class_modifier_blanking_preserves_offsets_and_spares_final() {
        // Byte length is unchanged (same-length space substitution).
        let src = "class FOO_API Bar {};\n";
        let out = blank_class_modifier_macros(src);
        assert_eq!(out.len(), src.len(), "length must be preserved");
        assert!(!out.contains("FOO_API"), "macro should be blanked: {out:?}");
        assert!(out.contains("Bar {};"), "class name must survive: {out:?}");
        assert!(out.trim_start().starts_with("class "), "got: {out:?}");
        // `class IO final` — `IO` is the real name, `final` the keyword; leave it.
        let keep = "class IO final {};\n";
        assert_eq!(blank_class_modifier_macros(keep), keep);
        // Single-token class is untouched.
        let plain = "class Widget {};\n";
        assert_eq!(blank_class_modifier_macros(plain), plain);
    }

    #[test]
    fn blank_conditional_directives_blanks_conditionals_preserves_offsets_spares_include_define() {
        let src = "#include <x>\n#if FOO\nint a;\n#elif BAR\nint c;\n#else\nint b;\n#endif\n#define Y 1\n";
        let out = blank_conditional_directives(src);
        assert_eq!(out.len(), src.len(), "byte offsets must be preserved");
        assert_eq!(
            out.lines().count(),
            src.lines().count(),
            "line count preserved"
        );
        assert!(out.contains("#include <x>"), "#include spared: {out:?}");
        assert!(out.contains("#define Y 1"), "#define spared: {out:?}");
        assert!(
            !out.contains("#if")
                && !out.contains("#elif")
                && !out.contains("#else")
                && !out.contains("#endif"),
            "conditionals must be blanked: {out:?}",
        );
        assert!(
            out.contains("int a;") && out.contains("int b;") && out.contains("int c;"),
            "every branch's code is kept (valid syntax for tree-sitter): {out:?}",
        );
    }

    #[test]
    fn conditional_in_initializer_list_recovers_dropped_definition() {
        // tinyobjloader `MappedFile` shape: a `#if` interrupts the constructor's
        // member-initializer list. tree-sitter-cpp can't parse a conditional inside
        // an expression and emits an ERROR that drops the constructor from
        // discovery (verified: a native parse finds only the methods). The recovery
        // re-parse must restore it WITHOUT losing the methods the native parse
        // already found. This is the minimal proxy for the full-header cascade that
        // dropped the out-of-line `ObjReader::ParseFromString` fuzz entry.
        let src = r#"
struct MappedFile {
  MappedFile() : data(0)
#if defined(_WIN32)
    , hFile(0)
#else
    , mapped_ptr(0)
#endif
  {}
  bool open_file(const char *path) { return path != 0; }
  long read_bytes(char *dst, long n) { return n; }
  const char *data;
};
"#;
        let funcs = parse_cpp_functions(src).unwrap();
        let names: std::collections::HashSet<&str> =
            funcs.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains("MappedFile"),
            "constructor dropped by the #if-in-initializer must be recovered; got {names:?}",
        );
        assert!(
            names.contains("open_file") && names.contains("read_bytes"),
            "native results must be preserved by the union; got {names:?}",
        );
    }

    #[test]
    fn free_function_in_capitalized_namespace_is_not_a_method() {
        // jsoncpp shape: a free function inside `namespace Json`. `Json` is a
        // namespace, not a class — the function must not become a method of a
        // bogus `Json` class (which produced `Json _gf_receiver`).
        let fns = parse_cpp_functions(
            "namespace Json { static inline void releaseStringValue(char* v, unsigned n) { (void)v; (void)n; } }",
        )
        .unwrap();
        let f = fns.iter().find(|f| f.name == "releaseStringValue").unwrap();
        assert!(!f.api.is_method, "free function must not be a method");
        assert_eq!(f.api.class_name, None);
        assert_eq!(f.api.namespace_path, vec!["Json".to_owned()]);

        // A real out-of-line method inside the same namespace still resolves.
        let fns = parse_cpp_functions("namespace Json { int Value::size() const { return 0; } }")
            .unwrap();
        let m = fns.iter().find(|f| f.name == "size").unwrap();
        assert!(m.api.is_method);
        assert_eq!(m.api.class_name, Some("Value".to_owned()));
        assert_eq!(m.api.namespace_path, vec!["Json".to_owned()]);
        assert_eq!(
            m.qualifier_path,
            vec!["Json".to_owned(), "Value".to_owned()]
        );

        // A method inside a class body inside the namespace.
        let fns = parse_cpp_functions(
            "namespace Json { class Value { public: int size() const { return 0; } }; }",
        )
        .unwrap();
        let m = fns.iter().find(|f| f.name == "size").unwrap();
        assert!(m.api.is_method);
        assert_eq!(m.api.class_name, Some("Value".to_owned()));
        assert_eq!(m.api.namespace_path, vec!["Json".to_owned()]);
    }

    #[test]
    fn function_return_type_keeps_const_and_pointer() {
        let rt = |src: &str, name: &str| {
            parse_cpp_functions(src)
                .unwrap()
                .into_iter()
                .find(|f| f.name == name)
                .map(|f| f.return_type)
                .unwrap_or_default()
        };
        // The bug: `const char*` came back as `char`, so the harness emitted
        // `char R = obj.asCString();` ("cannot initialize... with const char *").
        assert_eq!(
            rt(
                "namespace J { const char* V::asCString() const { return 0; } }",
                "asCString"
            ),
            "const char *"
        );
        assert_eq!(
            rt("J::Value& V::get() { return *this; }", "get"),
            "J::Value &"
        );
        assert_eq!(rt("int V::size() const { return 0; }", "size"), "int");
        assert_eq!(rt("void V::clear() {}", "clear"), "void");
        // Storage specifiers are not part of the value type.
        assert_eq!(
            rt("static const char* host() { return 0; }", "host"),
            "const char *"
        );
    }

    #[test]
    fn strips_restrict_qualifier_macro_from_param() {
        // xxHash's `XXH_RESTRICT` is a project macro (`#define XXH_RESTRICT
        // restrict`/`__restrict`/empty); xxhash.h is compiled as C++. The grammar
        // cannot expand it, so it lands in the parameter QUALIFIER position. It
        // must be stripped (never emitted or stubbed): emitting it as a decode
        // variable collides with the macro once the header is included
        // (`redefinition of 'XXH_RESTRICT'`).
        let src = "unsigned mix(void* XXH_RESTRICT acc, const void* XXH_RESTRICT input, \
                   const void* XXH_RESTRICT secret) { return 0; }";
        let f = &parse_cpp_functions(src).unwrap()[0];
        assert_eq!(f.params.len(), 3, "params: {:?}", f.params);
        assert_eq!(f.params[0].name, "acc");
        assert_eq!(f.params[0].cpp_type, "void *");
        assert_eq!(f.params[1].name, "input");
        assert_eq!(f.params[1].cpp_type, "const void *");
        assert_eq!(f.params[2].name, "secret");
        assert_eq!(f.params[2].cpp_type, "const void *");
        assert!(
            f.params
                .iter()
                .all(|p| p.name != "XXH_RESTRICT" && !p.cpp_type.contains("XXH_RESTRICT")),
            "the qualifier macro must never surface as a name or a type: {:?}",
            f.params
        );
    }

    #[test]
    fn strips_gnu_restrict_keyword_from_param() {
        // The standard `__restrict` keyword, recognised by the grammar as a
        // pointer modifier; without stripping it the name became `__restrict dst`.
        let src = "void copy(void* __restrict dst, const void* __restrict src) {}";
        let f = &parse_cpp_functions(src).unwrap()[0];
        assert_eq!(f.params.len(), 2, "params: {:?}", f.params);
        assert_eq!(f.params[0].name, "dst");
        assert_eq!(f.params[0].cpp_type, "void *");
        assert_eq!(f.params[1].name, "src");
        assert_eq!(f.params[1].cpp_type, "const void *");
    }

    #[test]
    fn discovers_cpp_function_definitions() {
        let functions = parse_cpp_functions(
            r#"
            namespace demo { static int helper(int x) { return x + 1; } }
            void process();
            void process() {
                (void)demo::helper(1);
            }
            "#,
        )
        .expect("C++ parses");

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "helper");
        assert_eq!(functions[0].return_type, "int");
        assert_eq!(functions[0].params.len(), 1);
        assert_eq!(functions[0].params[0].cpp_type, "int");
        assert_eq!(functions[1].name, "process");
        assert_eq!(functions[1].return_type, "void");
        assert!(functions[1].params.is_empty());
    }

    #[test]
    fn captures_enclosing_namespaces_in_qualifier_path() {
        // Member function defined inside nested namespaces but with a
        // bare class qualifier in the declarator (the common style).
        // qualifier_path should reflect the surrounding namespace
        // stack so the harness emitter can produce a fully-qualified
        // receiver type.
        let functions = parse_cpp_functions(
            r#"
            namespace acme {
            namespace v2 {

            class XmlReader {
            public:
                int parse(const char *data, size_t size);
            };

            int XmlReader::parse(const char *data, size_t size) {
                (void)data; (void)size;
                return 0;
            }

            } }
            "#,
        )
        .expect("C++ parses");
        let defs: Vec<_> = functions.iter().filter(|f| f.name == "parse").collect();
        assert_eq!(defs.len(), 1, "only the definition has a body");
        assert_eq!(
            defs[0].qualifier_path,
            vec!["acme", "v2", "XmlReader"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merges_namespace_stack_with_explicit_qualifier_in_definition() {
        // Definition inside one namespace, with an explicit second
        // namespace qualifier - tree-sitter exposes the explicit part
        // alone, so we must merge with the surrounding stack.
        let functions = parse_cpp_functions(
            r#"
            namespace outer {
            void inner::run() {}
            }
            "#,
        )
        .expect("C++ parses");
        let run = functions.iter().find(|f| f.name == "run").unwrap();
        assert_eq!(
            run.qualifier_path,
            vec!["outer", "inner"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn cpp_keywords_never_leak_into_qualifier_path() {
        // Macro-split / error-recovery constructs can produce a qualified_identifier
        // whose scope segment is a C++ keyword; such a segment must not become a
        // (bogus) receiver class — it produced candidates like `namespace R = std()`.
        let functions = parse_cpp_functions(
            "struct X { }; int X::class::g() { return 0; }\nint new::foo() { return 0; }\n",
        )
        .expect("C++ parses");
        for f in &functions {
            for seg in &f.qualifier_path {
                assert!(
                    !is_cpp_keyword(seg),
                    "keyword '{seg}' leaked into qualifier_path of {:?}: {:?}",
                    f.name,
                    f.qualifier_path
                );
            }
        }
        let g = functions.iter().find(|f| f.name == "g").unwrap();
        assert_eq!(g.qualifier_path, vec!["X".to_owned()]);
    }

    #[test]
    fn function_leading_decoration_macros_stripped_from_return_type() {
        // xxHash declares `XXH_PUBLIC_API XXH_PUREF XXH128_hash_t XXH128(...)`.
        // The leading decoration macros must not leak into the return type (which
        // made tree-sitter model it as a phantom method `_gf_receiver.XXH128`).
        let functions = parse_cpp_functions(
            "XXH_PUBLIC_API XXH_PUREF unsigned long long XXH128(const void *input, unsigned long len) { return 0; }",
        )
        .expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "XXH128")
            .expect("XXH128 discovered");
        assert_eq!(f.return_type, "unsigned long long");
        assert!(
            !f.api.is_method,
            "free function must not become a method, got path {:?}",
            f.qualifier_path
        );
    }

    #[test]
    fn library_export_api_macro_stripped_so_free_function_is_not_a_phantom_method() {
        // libde265 declares `LIBDE265_API de265_error de265_decode_data(...)`. The
        // per-library `<LIB>_API` export macro is not in the hardcoded marker list;
        // left in place, tree-sitter read `de265_error` (the return type) as a class
        // and `de265_decode_data` as a phantom method `de265_error::de265_decode_data`,
        // whose opaque-handle lifecycle could never resolve ("could not auto-harness").
        // The `_API`/`_EXPORT` suffix heuristic strips it.
        let functions = parse_cpp_functions(
            "LIBDE265_API de265_error de265_decode_data(de265_decoder_context* ctx, const void* data, int len) { return 0; }",
        )
        .expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "de265_decode_data")
            .expect("de265_decode_data discovered");
        assert_eq!(f.return_type, "de265_error");
        assert!(
            !f.api.is_method && f.qualifier_path.is_empty(),
            "an export-macro'd free function must not become a method of its return type, got path {:?}",
            f.qualifier_path,
        );
        // The suffix heuristic recognizes per-library export macros but never a real
        // all-caps type.
        assert!(is_decoration_macro_token("LIBDE265_API"));
        assert!(is_decoration_macro_token("ZSTDLIB_API"));
        assert!(is_decoration_macro_token("PNG_EXPORT"));
        assert!(!is_decoration_macro_token("DWORD"));
        assert!(!is_decoration_macro_token("RESULT_T"));
        assert!(!is_decoration_macro_token("HANDLE"));
    }

    #[test]
    fn impl_fn_macro_before_a_qualified_method_is_stripped() {
        // pugixml defines `PUGI_IMPL_FN xml_parse_result xml_document::load_file(...)`.
        // The walk-back must cross the `::` to reach + blank PUGI_IMPL_FN; otherwise
        // the return type `xml_parse_result` is mis-read as part of the qualifier
        // (`xml_parse_result::xml_document::load_file`) and the method never builds.
        let functions = parse_cpp_functions(
            "namespace pugi {\n\
             PUGI_IMPL_FN xml_parse_result xml_document::load_file(const char* path, unsigned int options) { return xml_parse_result(); }\n\
             }",
        )
        .expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "load_file")
            .expect("load_file discovered");
        assert_eq!(f.return_type, "xml_parse_result");
        assert_eq!(
            f.api.class_name.as_deref(),
            Some("xml_document"),
            "class must be xml_document, not the return type; path {:?}",
            f.qualifier_path
        );
        assert!(is_decoration_macro_token("PUGI_IMPL_FN"));
    }

    #[test]
    fn export_macro_after_a_preprocessor_directive_line_is_still_stripped() {
        // libde265 de265.cc: `#ifndef LIBDE265_DISABLE_DEPRECATED` immediately
        // precedes `LIBDE265_API de265_error de265_decode_data(...)`. The walk-back
        // must treat the directive line as a boundary; otherwise it collects the
        // directive's tokens, the boundary check fails on the `#`, the export macro
        // is never blanked, and the decode entry becomes a phantom method of its
        // return type (`de265_error::de265_decode_data`) — which then can't resolve
        // its opaque-handle lifecycle.
        let src = "#ifndef LIBDE265_DISABLE_DEPRECATED\n\
                   LIBDE265_API de265_error de265_decode_data(de265_decoder_context* ctx, const void* data, int len) { return 0; }\n\
                   #endif\n";
        let functions = parse_cpp_functions(src).expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "de265_decode_data")
            .expect("de265_decode_data discovered");
        assert!(
            !f.api.is_method && f.qualifier_path.is_empty(),
            "a directive-preceded export-macro'd free function must not become a method \
             of its return type, got path {:?}",
            f.qualifier_path,
        );
        assert_eq!(f.return_type, "de265_error");
    }

    #[test]
    fn all_uppercase_macro_return_type_alone_is_preserved() {
        // A genuine all-caps type as the sole return token (`BYTE f()`) must be
        // kept — the leading-strip never removes the final/core type token.
        let functions = parse_cpp_functions("BYTE read_one(void) { return 0; }").expect("parses");
        let f = functions.iter().find(|f| f.name == "read_one").unwrap();
        assert_eq!(f.return_type, "BYTE");
    }

    #[test]
    fn toml_linkage_and_callconv_macros_stripped_from_return_type() {
        // toml++ wraps every free function as `TOML_NODISCARD TOML_EXTERNAL_LINKAGE
        // parse_result TOML_CALLCONV parse(...)`. The linkage + calling-convention
        // decoration macros must not leak into the return type — the header `#undef`s
        // them, so a `TOML_EXTERNAL_LINKAGE ... parse_result TOML_CALLCONV R =
        // toml::parse(...)` declaration would not compile.
        let functions = parse_cpp_functions(
            "namespace toml {\n\
             TOML_NODISCARD TOML_EXTERNAL_LINKAGE parse_result TOML_CALLCONV parse(std::string_view doc) { return parse_result(); }\n\
             }",
        )
        .expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "parse")
            .expect("parse discovered");
        assert_eq!(f.return_type, "parse_result");
        assert!(
            !f.api.is_method,
            "free function must not become a phantom method, got path {:?}",
            f.qualifier_path
        );
        // The macro-shape recognizer covers linkage / calling-convention macros and
        // the lowercase calling-convention keywords, but never a real all-caps type.
        assert!(is_decoration_macro_token("TOML_EXTERNAL_LINKAGE"));
        assert!(is_decoration_macro_token("TOML_CALLCONV"));
        assert!(is_decoration_macro_token("MYLIB_LINKAGE"));
        assert!(is_decoration_macro_token("FOO_FREE_FUNCTION"));
        assert!(is_decoration_macro_token("__cdecl"));
        assert!(is_decoration_macro_token("__stdcall"));
        assert!(is_decoration_macro_token("__fastcall"));
        assert!(!is_decoration_macro_token("BYTE"));
        assert!(!is_decoration_macro_token("HANDLE"));
    }

    #[test]
    fn anonymous_namespace_free_function_is_internal_linkage() {
        // A free function inside an unnamed `namespace { ... }` has internal linkage
        // and is not callable from the harness's separate translation unit (yaml-cpp
        // `IsValidPlainScalar`, ada-url `ada::try_can_parse_absolute_fast`). It must
        // be flagged `is_static` so discovery's `is_static && !is_method` gate skips
        // it instead of emitting an unbuildable cross-TU call.
        let functions = parse_cpp_functions(
            "namespace {\n\
             bool IsValidPlainScalar(int x) { return x > 0; }\n\
             }\n\
             bool PublicHelper(int x) { return x < 0; }\n",
        )
        .expect("C++ parses");
        let internal = functions
            .iter()
            .find(|f| f.name == "IsValidPlainScalar")
            .expect("anon-namespace fn discovered");
        assert!(
            internal.is_static && !internal.api.is_method,
            "anon-namespace free function must be internal-linkage"
        );
        let public = functions
            .iter()
            .find(|f| f.name == "PublicHelper")
            .expect("public fn discovered");
        assert!(
            !public.is_static,
            "an ordinary free function keeps external linkage"
        );

        // Also covers an anon namespace nested inside a named one (ada-url shape).
        let nested = parse_cpp_functions(
            "namespace ada {\n namespace {\n\
             bool try_can_parse_absolute_fast(int x) { return x > 0; }\n\
             }\n }\n",
        )
        .expect("C++ parses");
        let f = nested
            .iter()
            .find(|f| f.name == "try_can_parse_absolute_fast")
            .expect("nested anon fn discovered");
        assert!(
            f.is_static,
            "anon namespace nested in a named namespace is still internal-linkage"
        );
    }

    #[test]
    fn sibling_member_enums_with_same_bare_tag_are_qualified() {
        // yaml-cpp `FmtScope` / `GroupType` / `FlowType` each declare an unscoped
        // `enum value { ... }`. Recorded by the ambiguous bare tag `value`, they
        // collide in the registry (first wins) and a parameter typed `GroupType::value`
        // resolves to the WRONG members. Qualifying the tag + enumerators with the
        // enclosing struct scope keeps them distinct.
        let defs = parse_cpp_type_defs(
            "struct FmtScope { enum value { Local, Global }; };\n\
             struct GroupType { enum value { NoType, Flow }; };\n",
        )
        .expect("C++ parses");
        let fmt = defs
            .enums
            .iter()
            .find(|e| e.name == "FmtScope::value")
            .expect("FmtScope::value recorded by qualified tag");
        assert_eq!(fmt.members, vec!["FmtScope::Local", "FmtScope::Global"]);
        let grp = defs
            .enums
            .iter()
            .find(|e| e.name == "GroupType::value")
            .expect("GroupType::value recorded by qualified tag");
        assert_eq!(grp.members, vec!["GroupType::NoType", "GroupType::Flow"]);
        assert!(
            !defs.enums.iter().any(|e| e.name == "value"),
            "the ambiguous bare tag must not be recorded"
        );
    }

    #[test]
    fn parse_cpp_abstract_classes_detects_pure_virtual_members() {
        let abstract_classes = parse_cpp_abstract_classes(
            r#"
            class ClientHook {
            public:
                virtual bool isBrand(const void *other) = 0;
                virtual void raise() const = 0;
            };
            struct Plain {
                // a default arg `= 0` is NOT a pure-specifier
                virtual int weight(int n = 0) { return n; }
                int count = 0;
            };
            class Concrete {
                virtual void run() {}
            };
            "#,
        )
        .expect("C++ parses");
        assert!(
            abstract_classes.contains("ClientHook"),
            "pure-virtual class must be abstract: {abstract_classes:?}"
        );
        assert!(
            !abstract_classes.contains("Plain"),
            "default-arg `= 0` is not a pure-specifier: {abstract_classes:?}"
        );
        assert!(
            !abstract_classes.contains("Concrete"),
            "a class with only concrete virtuals is not abstract: {abstract_classes:?}"
        );
    }

    #[test]
    fn parse_cpp_subclasses_maps_bases_to_direct_derived_classes() {
        let subs = parse_cpp_subclasses(
            r#"
            class Reader { public: virtual void read() = 0; };
            class MemoryReader : public e57::Reader { public: void read() override {} };
            struct FileReader : Reader, virtual public Other<int> {};
            "#,
        )
        .expect("C++ parses");
        let mut readers = subs.get("Reader").cloned().unwrap_or_default();
        readers.sort();
        assert_eq!(
            readers,
            vec!["FileReader".to_owned(), "MemoryReader".to_owned()],
            "{subs:?}"
        );
        // Access/virtual keywords + template args + namespace qualification stripped.
        assert!(
            subs.get("Other")
                .unwrap()
                .contains(&"FileReader".to_owned()),
            "{subs:?}"
        );
    }

    #[test]
    fn parse_cpp_template_instantiations_records_call_site_type_args() {
        let insts = parse_cpp_template_instantiations(
            "void use(const std::string &buf, int x) {\n\
             \x20 auto a = parse<int>(buf);\n\
             \x20 auto b = ns::convert<std::string, double>(x);\n\
             }\n",
        )
        .expect("C++ parses");
        assert!(
            insts.contains(&("parse".to_owned(), vec!["int".to_owned()])),
            "{insts:?}"
        );
        assert!(
            insts.iter().any(|(n, args)| n == "convert"
                && args == &["std::string".to_owned(), "double".to_owned()]),
            "{insts:?}"
        );
    }

    #[test]
    fn friend_operator_in_class_is_a_free_function_not_a_member() {
        // ctre declares `constexpr friend bool operator!=(const char8_t *, const
        // utf8_iterator &)` inside the class. A friend is a free function, so it
        // must NOT be modeled as a member (which produced a bogus receiver and a
        // 2-arg member call with an empty/duplicated operand).
        let functions = parse_cpp_functions(
            r#"
            class utf8_iterator {
                constexpr friend bool operator!=(const char8_t *lhs, const utf8_iterator &rhs) {
                    (void)lhs; (void)rhs; return false;
                }
            };
            "#,
        )
        .expect("C++ parses");
        let op = functions
            .iter()
            .find(|f| f.name.contains("operator"))
            .expect("the friend operator is discovered");
        assert!(
            !op.api.is_method,
            "friend operator must be a free function, got qualifier_path {:?}",
            op.qualifier_path
        );
        assert!(
            !op.qualifier_path.iter().any(|s| s == "utf8_iterator"),
            "friend operator must not carry the class as a receiver: {:?}",
            op.qualifier_path
        );
    }

    #[test]
    fn fully_qualified_out_of_line_definition_keeps_scope_order() {
        // A `.cpp` out-of-line definition written at file scope carries the
        // entire scope in the declarator (`eprosima::fastcdr::internal::f`).
        // The qualifier path must preserve source order and drop no middle
        // component — the old walker reversed it and dropped `internal`,
        // producing a bogus `fastcdr::eprosima` receiver.
        let functions = parse_cpp_functions(
            "void eprosima::fastcdr::internal::use_char_pointer(const char *p) { (void)p; }",
        )
        .expect("C++ parses");
        let f = functions
            .iter()
            .find(|f| f.name == "use_char_pointer")
            .unwrap();
        assert_eq!(
            f.qualifier_path,
            vec!["eprosima", "fastcdr", "internal"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn fully_qualified_nested_class_constructor_keeps_scope_order() {
        // `FastCdr::state::state(...)` out-of-line: the qualifier path is the
        // nested class path `FastCdr::state`, not the reversed `state::FastCdr`.
        let functions = parse_cpp_functions("FastCdr::state::state(const FastCdr &c) { (void)c; }")
            .expect("C++ parses");
        let f = functions.iter().find(|f| f.name == "state").unwrap();
        assert_eq!(
            f.qualifier_path,
            vec!["FastCdr", "state"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn reports_member_function_name_not_qualifier() {
        let functions = parse_cpp_functions(
            r#"
            int demo::Reader::GetInteger() const {
                return 1;
            }
            "#,
        )
        .expect("C++ parses");

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "GetInteger");
        assert_eq!(functions[0].return_type, "int");
    }

    #[test]
    fn captures_std_string_parameter() {
        let functions = parse_cpp_functions(
            "int parse(const std::string &input, std::size_t max) { return 0; }",
        )
        .expect("C++ parses");

        assert_eq!(functions.len(), 1);
        let f = &functions[0];
        assert_eq!(f.params.len(), 2);
        assert!(
            f.params[0].cpp_type.contains("std::string"),
            "expected std::string in type, got {:?}",
            f.params[0].cpp_type
        );
        assert_eq!(f.params[1].name, "max");
    }

    #[test]
    fn discovers_operator_function_definitions() {
        let functions = parse_cpp_functions(
            r#"
            struct result {
                explicit operator bool() const noexcept { return true; }
                result& operator=(const result&) = delete;
                bool operator==(const result&) const { return true; }
            };
            "#,
        )
        .expect("C++ parses");

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "operator bool");
        assert_eq!(functions[1].name, "operator==");
    }

    #[test]
    fn parse_cpp_declarations_finds_extern_prototypes_and_header_rows() {
        let decls = parse_cpp_declarations(
            "extern int run(const char *cmd);\n\
             class Foo {\n\
             public:\n\
                 int parse(const char *s);\n\
             };\n\
             int run(const char *cmd) { return 0; }\n",
        )
        .expect("parses");
        let names: Vec<_> = decls.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"run"));
        assert!(
            names.contains(&"parse"),
            "in-class declaration must be captured (no body present)"
        );
        // the second `run` has a body -> goes to parse_cpp_functions, not here
        assert_eq!(decls.iter().filter(|d| d.name == "run").count(), 1);
    }

    #[test]
    fn parse_cpp_declarations_records_param_types() {
        let decls = parse_cpp_declarations(
            "extern int decode(const std::string &input, std::size_t max);\n",
        )
        .expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "decode");
        assert_eq!(decls[0].return_type, "int");
        assert!(
            decls[0]
                .param_types
                .iter()
                .any(|p| p.contains("std::string")),
            "param types: {:?}",
            decls[0].param_types
        );
    }

    #[test]
    fn parse_cpp_declarations_preserves_const_return_qualifier() {
        let decls =
            parse_cpp_declarations("extern const std::string get_name();\n").expect("parses");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].return_type, "const std::string");
    }

    #[test]
    fn parse_cpp_type_defs_extracts_struct_and_class_fields() {
        let defs = parse_cpp_type_defs(
            r#"
            #include <cstdint>
            struct Config {
                int mode;
                bool enabled;
                std::uint16_t code;
            };
            class Options {
            public:
                std::size_t limit;
                int retries;
                int helper() const { return retries; }
            private:
                int hidden;
            };
            enum Mode { ModeA, ModeB };
            typedef int (*visit_cb)(void *opaque, const char *name);
            "#,
        )
        .expect("C++ type definitions parse");

        let config = defs
            .structs
            .iter()
            .find(|def| def.name == "Config")
            .expect("Config struct is extracted");
        assert!(config.complete);
        assert_eq!(
            config
                .fields
                .iter()
                .map(|field| (field.name.as_str(), field.c_type.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("mode", "int"),
                ("enabled", "bool"),
                ("code", "std::uint16_t")
            ]
        );

        let options = defs
            .structs
            .iter()
            .find(|def| def.name == "Options")
            .expect("Options class is extracted");
        assert!(options.complete);
        assert_eq!(
            options
                .fields
                .iter()
                .map(|field| (field.name.as_str(), field.c_type.as_str()))
                .collect::<Vec<_>>(),
            vec![("limit", "std::size_t"), ("retries", "int")]
        );

        let mode = defs
            .enums
            .iter()
            .find(|def| def.name == "Mode")
            .expect("Mode enum is extracted");
        assert_eq!(mode.members, vec!["ModeA".to_owned(), "ModeB".to_owned()]);

        let callback = defs
            .typedefs
            .iter()
            .find(|def| def.name == "visit_cb")
            .expect("callback typedef is extracted");
        assert_eq!(
            callback.underlying,
            "int (*)(void *opaque, const char *name)"
        );
    }

    #[test]
    fn parse_cpp_type_defs_extracts_using_aliases() {
        // Modern C++ `using` aliases (jsoncpp-style) must resolve like typedefs.
        let defs = parse_cpp_type_defs(
            "namespace Json {\n\
             using UInt = unsigned int;\n\
             using ArrayIndex = UInt;\n\
             typedef int OldStyle;\n\
             }\n",
        )
        .unwrap();
        let uint = defs
            .typedefs
            .iter()
            .find(|d| d.name == "UInt")
            .expect("using alias UInt extracted");
        assert_eq!(uint.underlying, "unsigned int");
        assert!(
            defs.typedefs.iter().any(|d| d.name == "ArrayIndex"),
            "chained using alias extracted"
        );
        assert!(
            defs.typedefs.iter().any(|d| d.name == "OldStyle"),
            "typedef still works alongside using"
        );
    }

    #[test]
    fn parse_cpp_type_defs_qualifies_enum_class_members() {
        let defs = parse_cpp_type_defs(
            r#"
            enum class Mode { Fast, Safe };
            "#,
        )
        .expect("C++ scoped enum definitions parse");

        let mode = defs
            .enums
            .iter()
            .find(|def| def.name == "Mode")
            .expect("Mode enum class is extracted");
        assert_eq!(
            mode.members,
            vec!["Mode::Fast".to_owned(), "Mode::Safe".to_owned()]
        );
    }

    #[test]
    fn extracts_cpp_dictionary_tokens_from_enums_strings_defines_and_cases() {
        let tokens = extract_cpp_dictionary_tokens(
            r#"
            #define CPP_MAGIC_TEXT "HELLO_CPP"
            #define CPP_MAGIC_NUM 0xC0FFEE
            namespace gov {
            enum class Mode { Fast, Safe };
            int parse(std::string_view input, int tag) {
                switch (tag) { case 0x55: return 1; case 'Q': return 2; default: break; }
                return input == "READY_CPP" ? 1 : 0;
            }
            }
            "#,
        )
        .expect("C++ dictionary tokens parse");

        for expected in [
            "HELLO_CPP",
            "0xC0FFEE",
            "Fast",
            "Mode::Fast",
            "Safe",
            "Mode::Safe",
            "0x55",
            "Q",
            "READY_CPP",
        ] {
            assert!(
                tokens.iter().any(|token| token == expected),
                "missing {expected} from {tokens:?}"
            );
        }
    }

    #[test]
    fn extracts_cpp_dictionary_tokens_from_comparison_operands() {
        // #379: scalar magic-byte / length gates as comparison operands.
        let tokens = extract_cpp_dictionary_tokens(
            r#"
            int parse(const unsigned char *b, int n) {
                if (b[0] == 0x55 && b[1] != 'P') return 1;
                if (n >= 1234) return 2;
                return 0;
            }
            "#,
        )
        .expect("C++ dictionary tokens parse");
        assert!(tokens.contains(&"0x55".to_owned()), "{tokens:?}");
        assert!(tokens.contains(&"P".to_owned()), "{tokens:?}");
        assert!(tokens.contains(&"1234".to_owned()), "{tokens:?}");
    }

    #[test]
    fn annotates_methods_templates_overloads_and_unsupported_cases() {
        let functions = parse_cpp_functions(
            r#"
            namespace gov {
            class Parser {
            public:
                Parser() {}
                ~Parser() {}
                int parse(const std::string &input) { return 0; }
                int parse(const char *input, std::size_t len) { return 0; }
                template <typename T>
                int decode(const T &value) { return 0; }
            };
            }
            "#,
        )
        .expect("C++ parses");

        let parse = functions
            .iter()
            .find(|function| function.name == "parse" && function.params.len() == 1)
            .unwrap();
        assert_eq!(parse.api.api_kind, "method");
        assert_eq!(parse.api.class_name.as_deref(), Some("Parser"));
        assert_eq!(parse.api.namespace_path, vec!["gov".to_owned()]);
        assert!(parse
            .api
            .unsupported
            .iter()
            .any(|item| item == "overload_set"));

        let constructor = functions
            .iter()
            .find(|function| function.name == "Parser")
            .unwrap();
        assert_eq!(constructor.api.api_kind, "constructor");

        let destructor = functions
            .iter()
            .find(|function| function.name == "~Parser")
            .unwrap();
        assert_eq!(destructor.api.api_kind, "destructor");

        let template = functions
            .iter()
            .find(|function| function.name == "decode")
            .unwrap();
        assert!(template.api.is_template);
        assert!(template
            .api
            .unsupported
            .iter()
            .any(|item| item == "template_definition"));
    }

    #[test]
    fn annotates_inline_member_access() {
        let functions = parse_cpp_functions(
            r#"
            namespace gov {
            class Parser {
            public:
                int parse(const char *input) { return input ? 1 : 0; }
            protected:
                void prepare() {}
            private:
                void reset() {}
            };
            }
            "#,
        )
        .expect("C++ parses");

        let parse = functions
            .iter()
            .find(|function| function.name == "parse")
            .unwrap();
        assert_eq!(parse.api.member_access.as_deref(), Some("public"));

        let prepare = functions
            .iter()
            .find(|function| function.name == "prepare")
            .unwrap();
        assert_eq!(prepare.api.member_access.as_deref(), Some("protected"));
        assert!(prepare
            .api
            .unsupported
            .iter()
            .any(|item| item == "non_public_member"));

        let reset = functions
            .iter()
            .find(|function| function.name == "reset")
            .unwrap();
        assert_eq!(reset.api.member_access.as_deref(), Some("private"));
        assert!(reset
            .api
            .unsupported
            .iter()
            .any(|item| item == "non_public_member"));
    }

    #[test]
    fn annotates_out_of_line_member_access_from_class_declarations() {
        let functions = parse_cpp_functions(
            r#"
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                int parse(std::string_view input);
            private:
                void reset();
            };

            void Parser::reset() {}
            int Parser::parse(std::string_view input) { return (int)input.size(); }
            }
            "#,
        )
        .expect("C++ parses");

        let parse = functions
            .iter()
            .find(|function| function.name == "parse")
            .unwrap();
        assert_eq!(parse.api.member_access.as_deref(), Some("public"));

        let reset = functions
            .iter()
            .find(|function| function.name == "reset")
            .unwrap();
        assert_eq!(reset.api.member_access.as_deref(), Some("private"));
        assert!(reset
            .api
            .unsupported
            .iter()
            .any(|item| item == "non_public_member"));
    }

    #[test]
    fn no_keyword_targets_from_preprocessor_split_functions() {
        // Same failure shape as the C parser: an if/else-if chain split
        // by an #ifndef/#else mangles tree-sitter's recovery into a
        // function_definition whose declarator reads `if (cond)`.
        let functions = parse_cpp_functions(
            r#"
        int check_block(void *zip, unsigned long out_ofs, unsigned long want,
                        unsigned int crc_a, unsigned int crc_b)
        {
            int status = 0;
            if (out_ofs != want)
            {
                status = -1;
            }
        #ifndef DISABLE_CRC_CHECKS
            else if (crc_a != crc_b)
            {
                status = -2;
            }
        #endif
            return status;
        }
        "#,
        )
        .expect("C++ parses");
        assert!(
            functions.iter().all(|f| f.name != "if" && f.name != "else"),
            "keyword extracted as function: {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        // Operator overloads must survive the keyword filter (exact-match only).
        let ops = parse_cpp_functions(
            "struct V { int v; };\nbool operator==(V a, V b) { return a.v == b.v; }\n",
        )
        .expect("C++ parses");
        assert!(
            ops.iter().any(|f| f.name == "operator=="),
            "operator== lost: {:?}",
            ops.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_cpp_method_access_reads_in_class_declarations() {
        // A header-style class: methods are DECLARED (no body), with access
        // specifiers — exactly the shape `parse_cpp_functions` (definitions only)
        // can't report. The `.cpp` defines these out-of-line with no specifier.
        let access = parse_cpp_method_access(
            r#"
            namespace ns {
            class Transcoder {
            public:
                bool start_transcoding(const void *p, unsigned size);
                int get_total_images() const;
            protected:
                void prepare();
            private:
                bool validate_header_quick() const;
            };
            struct Bag { void poke(); };   // struct default is public
            }
            "#,
        );
        assert_eq!(
            access
                .get("Transcoder::start_transcoding")
                .map(String::as_str),
            Some("public")
        );
        assert_eq!(
            access
                .get("Transcoder::get_total_images")
                .map(String::as_str),
            Some("public")
        );
        assert_eq!(
            access.get("Transcoder::prepare").map(String::as_str),
            Some("protected")
        );
        assert_eq!(
            access
                .get("Transcoder::validate_header_quick")
                .map(String::as_str),
            Some("private")
        );
        // struct members default to public.
        assert_eq!(access.get("Bag::poke").map(String::as_str), Some("public"));
    }

    /// Regression for the O(n^2) hang in `collect_type_defs` / `collect_functions`:
    /// both used to call `has_template_ancestor`, walking `Node::parent()` to the
    /// root per node. `parent()` is O(tree) in tree-sitter, so on a large TU the
    /// walk went quadratic and hung for minutes (basis_universal's ~40k-line
    /// basisu_transcoder.cpp took >8 min in `govfuzz auto`). The template state is
    /// now threaded top-down, making each node O(1). This test builds a large TU
    /// (thousands of nodes) that the quadratic version could not parse promptly,
    /// and pins the template inclusion/exclusion semantics the rewrite preserves.
    #[test]
    fn large_templated_tu_parses_fast_and_keeps_template_semantics() {
        let mut src = String::from("#include <cstdint>\n");
        // ~1500 ordinary structs + free functions: plenty of nodes, no templates.
        for i in 0..1500 {
            src.push_str(&format!(
                "struct Plain{i} {{ int a; std::uint16_t b; }};\n\
                 int plain_fn{i}(int x) {{ return x + {i}; }}\n"
            ));
        }
        // A big template block: every type/function inside must be EXCLUDED from
        // type defs and flagged templated, exactly as the old ancestor-walk did.
        for i in 0..400 {
            src.push_str(&format!(
                "template <typename T> struct Tmpl{i} {{ T v; int k; }};\n\
                 template <typename T> T tmpl_fn{i}(T x) {{ return x; }}\n"
            ));
        }

        let defs = parse_cpp_type_defs(&src).expect("large TU type defs parse");
        assert!(
            defs.structs.iter().any(|d| d.name == "Plain0")
                && defs.structs.iter().any(|d| d.name == "Plain1499"),
            "ordinary structs must still be collected"
        );
        assert!(
            !defs.structs.iter().any(|d| d.name.starts_with("Tmpl")),
            "template-defined structs must be pruned, found: {:?}",
            defs.structs
                .iter()
                .filter(|d| d.name.starts_with("Tmpl"))
                .map(|d| &d.name)
                .collect::<Vec<_>>()
        );

        let funcs = parse_cpp_functions(&src).expect("large TU functions parse");
        let plain = funcs
            .iter()
            .find(|f| f.name == "plain_fn0")
            .expect("non-template free function collected");
        assert!(!plain.api.is_template, "plain_fn0 must not be templated");
        let tmpl = funcs
            .iter()
            .find(|f| f.name == "tmpl_fn0")
            .expect("templated free function collected");
        assert!(tmpl.api.is_template, "tmpl_fn0 must be flagged templated");
    }

    #[test]
    fn template_function_records_type_params_and_call_site_instantiation() {
        // #455 / §27.5: a free templated function defined AND used (with explicit
        // type args) in one TU records both its declared type-parameter names and
        // the concrete specialization resolved from the call site, so the ranker
        // can surface it and codegen can emit a turbofish call.
        let src = "\
#include <string>
template <typename T> T convert(const std::string &s) { return T(); }
static int sample(const std::string &s) { return convert<int>(s); }
";
        let funcs = parse_cpp_functions(src).expect("parse");
        let convert = funcs
            .iter()
            .find(|f| f.name == "convert")
            .expect("templated convert collected");
        assert!(convert.api.is_template);
        assert_eq!(convert.template_type_params, vec!["T".to_owned()]);
        assert_eq!(convert.instantiation_args, vec!["int".to_owned()]);
    }

    #[test]
    fn template_function_records_multiple_type_params() {
        let src = "\
template <class K, class V> V lookup(const K &k) { return V(); }
";
        let funcs = parse_cpp_functions(src).expect("parse");
        let lookup = funcs
            .iter()
            .find(|f| f.name == "lookup")
            .expect("templated lookup collected");
        assert_eq!(
            lookup.template_type_params,
            vec!["K".to_owned(), "V".to_owned()]
        );
        // No call site -> no instantiation resolved (steering left to the flag).
        assert!(lookup.instantiation_args.is_empty());
    }

    #[test]
    fn template_function_without_call_site_has_no_instantiation() {
        let src = "\
#include <string>
template <typename T> T parse_as(const std::string &s) { return T(); }
";
        let funcs = parse_cpp_functions(src).expect("parse");
        let parse_as = funcs.iter().find(|f| f.name == "parse_as").expect("found");
        assert_eq!(parse_as.template_type_params, vec!["T".to_owned()]);
        assert!(parse_as.instantiation_args.is_empty());
    }

    #[test]
    fn namespace_begin_macro_keeps_class_membership() {
        // A class opened under a `*_NAMESPACE_BEGIN` macro (nlohmann/json's
        // `NLOHMANN_JSON_NAMESPACE_BEGIN`) with a complex body used to derail
        // tree-sitter ERROR-recovery so the class's members were mis-attributed as
        // GLOBAL free functions. A protected static helper (`name`) then leaked past
        // the visibility filter and surfaced as a junk fuzz target called unqualified.
        // `blank_namespace_delimiter_macros` must neutralise the macro so membership
        // and access survive.
        let src = "\
LIB_NAMESPACE_BEGIN
namespace detail
{
class exception : public std::exception
{
  public:
    const char* what() const noexcept override { return m.what(); }
  protected:
    JSON_HEDLEY_NON_NULL(3)
    exception(int id_, const char* w) : id(id_), m(w) {}
    static std::string name(const std::string& ename, int id_)
    {
        return concat(\"[\", ename, '.', std::to_string(id_), \"] \");
    }
    template<typename T> static std::string diagnostics(const T* leaf)
    {
#if LIB_DIAGNOSTICS
        return get_positions(leaf);
#else
        return \"\";
#endif
    }
};
}  // namespace detail
LIB_NAMESPACE_END
";
        let funcs = parse_cpp_functions(src).expect("parse");
        let name = funcs
            .iter()
            .find(|f| f.name == "name")
            .expect("name collected");
        assert_eq!(
            name.api.class_name.as_deref(),
            Some("exception"),
            "protected static `name` must be attributed to class exception, not leaked as a free function: {:?}",
            name.api,
        );
        assert_eq!(
            name.api.member_access.as_deref(),
            Some("protected"),
            "access must be recovered so discovery's visibility filter drops it"
        );
        assert!(name.api.is_method, "static member is still a method");
    }

    // --- F3: return type / attribute / leading-macro qualifiers must never leak
    // into the discovered qualified name. ---

    fn find_fn<'a>(fns: &'a [CppFunction], name: &str) -> &'a CppFunction {
        fns.iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("function {name:?} not found in {fns:?}"))
    }

    /// The reported defect: a lowercase decoration macro before an out-of-line
    /// definition (`ada_really_inline bool url::parse_host(...)`) made tree-sitter
    /// read the macro as the return type and fold `bool url::parse_host` into one
    /// qualified name, so the return type `bool` leaked as the class scope
    /// (`ada::bool::parse_host`) and the real class `url` was lost.
    #[test]
    fn f3_out_of_line_macro_return_type_does_not_leak() {
        let src = "namespace ada {\n\
                   ada_really_inline bool url::parse_host(std::string_view input) { return true; }\n\
                   }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let f = find_fn(&fns, "parse_host");
        assert_eq!(
            f.qualifier_path,
            vec!["ada".to_owned(), "url".to_owned()],
            "return type `bool` must not become a scope and class `url` must be recovered"
        );
        assert_eq!(f.api.namespace_path, vec!["ada".to_owned()]);
        assert_eq!(f.api.class_name.as_deref(), Some("url"));
        assert!(f.api.is_method);
        assert!(
            !f.qualifier_path.iter().any(|s| s == "bool"),
            "no builtin-type segment may appear in the qualifier"
        );
    }

    /// The `[[nodiscard]] <macro> bool parse_host(...)` shape as an inline member
    /// definition: attribute + leading macro must not leak; the class supplies the
    /// scope structurally.
    #[test]
    fn f3_inline_member_with_attribute_and_macro() {
        let src = "namespace ada {\n\
                   class url {\n\
                   public:\n\
                     [[nodiscard]] ada_really_inline bool parse_host(std::string_view input) { return true; }\n\
                   };\n\
                   }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let f = find_fn(&fns, "parse_host");
        assert_eq!(f.qualifier_path, vec!["ada".to_owned(), "url".to_owned()]);
        assert_eq!(f.api.class_name.as_deref(), Some("url"));
    }

    /// A plain `bool foo()` free function must stay `foo`, never `bool::foo`.
    #[test]
    fn f3_plain_bool_free_function() {
        let src = "bool foo() { return true; }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let f = find_fn(&fns, "foo");
        assert!(f.qualifier_path.is_empty(), "free function has no scope");
        assert!(!f.api.is_method);
    }

    /// A namespaced free function stays `ada::g` (namespace, not the return type).
    #[test]
    fn f3_namespaced_free_function() {
        let src = "namespace ada { int g() { return 0; } }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let f = find_fn(&fns, "g");
        assert_eq!(f.qualifier_path, vec!["ada".to_owned()]);
        assert_eq!(f.api.namespace_path, vec!["ada".to_owned()]);
        assert!(!f.api.is_method);
    }

    /// Templated / inline / static return shapes must keep a clean name and not
    /// fold the return type into the scope, including the macro+template case that
    /// previously parsed correctly (guard against regression of the new code path).
    #[test]
    fn f3_templated_inline_static_returns() {
        // template + leading macro + qualified out-of-line def
        let tmpl = "namespace ada {\n\
                    template <typename T> ada_really_inline T url::get(T x) { return x; }\n\
                    }\n";
        let tmpl_fns = parse_cpp_functions(tmpl).expect("parse");
        let f = find_fn(&tmpl_fns, "get");
        assert_eq!(f.qualifier_path, vec!["ada".to_owned(), "url".to_owned()]);

        // static inline free function
        let st = "namespace ada { static inline int g2() { return 0; } }\n";
        let st_fns = parse_cpp_functions(st).expect("parse");
        let f = find_fn(&st_fns, "g2");
        assert_eq!(f.qualifier_path, vec!["ada".to_owned()]);
        assert!(!f.api.is_method);

        // free template function with builtin return type
        let id = "template <typename T> T id(T x) { return x; }\n";
        let id_fns = parse_cpp_functions(id).expect("parse");
        let f = find_fn(&id_fns, "id");
        assert!(f.qualifier_path.is_empty());
    }

    /// Multi-level namespace + multi-segment out-of-line qualifier still resolves
    /// every middle component (right-associative recursion intact).
    #[test]
    fn f3_multi_level_qualifier_preserved() {
        let src = "namespace a { namespace b { int d::e::f() { return 0; } } }\n";
        let fns = parse_cpp_functions(src).expect("parse");
        let f = find_fn(&fns, "f");
        assert_eq!(
            f.qualifier_path,
            vec![
                "a".to_owned(),
                "b".to_owned(),
                "d".to_owned(),
                "e".to_owned()
            ]
        );
    }

    fn test_fn(
        name: &str,
        line: u32,
        return_type: &str,
        qualifier_path: &[&str],
        ns_depth: usize,
    ) -> CppFunction {
        let qp: Vec<String> = qualifier_path.iter().map(|s| (*s).to_owned()).collect();
        let api = cpp_api_metadata(name, &qp, ns_depth, false);
        CppFunction {
            name: name.to_owned(),
            line,
            return_type: return_type.to_owned(),
            params: Vec::new(),
            qualifier_path: qp,
            api,
            is_static: false,
            foreign_guard: None,
            template_type_params: Vec::new(),
            instantiation_args: Vec::new(),
        }
    }

    /// Reconciliation against the conditional-blanked re-parse must undo the
    /// `MappedFile` swallow (campaign: tinyobjloader): sibling free functions,
    /// other classes' constructors, and a `namespace`-mis-parsed-as-function that
    /// tree-sitter ERROR-recovery wrongly homed in a struct body that never closed.
    #[test]
    fn reconcile_undoes_struct_body_swallow() {
        // Native (buggy) parse: `MappedFile`'s body ran unbounded.
        let mut native = vec![
            // a genuine member
            test_fn("open", 10, "bool", &["tinyobj", "MappedFile"], 1),
            // a sibling FREE function swallowed as a member (same line as recovery)
            test_fn("parseInt", 100, "int", &["tinyobj", "MappedFile"], 1),
            // `namespace detail_fp {` mis-parsed as a `MappedFile` "method"
            test_fn("detail_fp", 200, "namespace", &["MappedFile"], 0),
            // another class's constructor swallowed (recovery has it at a DIFFERENT line)
            test_fn("MaterialFileReader", 300, "", &["MappedFile"], 0),
        ];
        // Conditional-blanked re-parse: structurally sound.
        let recovered = vec![
            test_fn("open", 10, "bool", &["tinyobj", "MappedFile"], 1),
            test_fn("parseInt", 100, "int", &["tinyobj"], 1), // genuinely free
            // real constructor of its own class, at its real line
            test_fn(
                "MaterialFileReader",
                305,
                "",
                &["tinyobj", "MaterialFileReader"],
                1,
            ),
            // (recovery sees `namespace detail_fp {` as a namespace, NOT a function)
        ];

        reconcile_recovered_scope(&mut native, recovered);

        let members_of = |class: &str| -> Vec<String> {
            native
                .iter()
                .filter(|f| f.api.class_name.as_deref() == Some(class))
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
        };
        // Only the real member survives on the receiver.
        assert_eq!(members_of("MappedFile"), vec!["open".to_owned()]);
        // The swallowed free function is restored as a free function.
        let parse_int = find_fn(&native, "parseInt");
        assert!(parse_int.api.class_name.is_none() && !parse_int.api.is_method);
        // The namespace-as-function artifact is gone entirely.
        assert!(native.iter().all(|f| f.name != "detail_fp"));
        // The other class's constructor is re-homed to its real class (unioned in).
        let mfr = find_fn(&native, "MaterialFileReader");
        assert_eq!(mfr.api.class_name.as_deref(), Some("MaterialFileReader"));
        assert_eq!(mfr.line, 305);
    }

    /// Reconciliation must NOT disturb a class the re-parse could not resolve: when
    /// the recovered member set for a class is empty, its native methods are kept
    /// verbatim (guards against false eviction of real members).
    #[test]
    fn reconcile_keeps_members_when_recovery_blind_to_class() {
        let mut native = vec![test_fn("doWork", 5, "int", &["ns", "Widget"], 1)];
        // Recovery knows nothing about `Widget` (no member, no contradicting entry).
        let recovered = vec![test_fn("unrelated", 9, "void", &["ns"], 1)];
        reconcile_recovered_scope(&mut native, recovered);
        let widget = find_fn(&native, "doWork");
        assert_eq!(widget.api.class_name.as_deref(), Some("Widget"));
    }
}
