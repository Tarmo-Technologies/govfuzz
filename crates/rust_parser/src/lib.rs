// SPDX-License-Identifier: Apache-2.0

//! Structural parser for the native Rust fuzzing lane (M1.1).
//!
//! Mirrors `c_parser`/`cpp_parser`: a thin tree-sitter walk that extracts the
//! function shapes the ranker (`target_rank::rust_rank`) needs to score
//! discovery candidates — name, line, params, return type, visibility,
//! free-fn-vs-method (`is_static`), a `#[cfg(...)]` foreign guard, and whether
//! the function lives inside an existing `fuzz_target!` harness.
//!
//! Like the C/C++ parsers this reasons over the signature only; it does not
//! resolve types or build a full semantic model.

/// One parameter of a Rust function: the binding name and its type spelling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RustParam {
    pub name: String,
    /// Raw source spelling of the parameter type, e.g. `&[u8]`, `&str`,
    /// `Vec<u8>`, `i32`. Whitespace is collapsed to single spaces.
    pub ty: String,
}

/// Visibility of a Rust item. Only `Pub` items are exported across crate
/// boundaries and thus reachable by a generated harness that depends on the
/// crate by path; `PubCrate` and `Private` items are skipped by the ranker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RustVisibility {
    /// `pub` — reachable from a dependent crate.
    Pub,
    /// `pub(crate)` / `pub(super)` / `pub(in ...)` — crate-internal, NOT reachable
    /// from a separate harness crate; the ranker drops these.
    PubCrate,
    /// No visibility modifier — module-private, not externally callable.
    #[default]
    Private,
}

/// A function (free fn, associated fn, or method) extracted from one Rust
/// source file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RustFn {
    pub name: String,
    /// 1-based line of the `fn` definition.
    pub line: u32,
    /// Raw return-type spelling, or `None` for `()` / no explicit return.
    pub return_type: Option<String>,
    pub params: Vec<RustParam>,
    /// `true` for a free function or an associated function with no `self`
    /// receiver; `false` for a method taking `&self` / `&mut self` / `self`.
    pub is_static: bool,
    /// `true` for an `unsafe fn`, OR a fn whose signature takes/returns a raw
    /// pointer (`*const T` / `*mut T`). The ranker promotes these: real memory
    /// bugs live behind `unsafe`/FFI, per the deepSURF severity thesis.
    pub is_unsafe: bool,
    /// `true` ONLY for the `unsafe fn` MODIFIER (not a raw-pointer FFI signature).
    /// An `unsafe fn` carries a caller-upheld safety precondition the harness cannot
    /// honour (json-rust's `Short::from_slice`, contract len<=30), so feeding it the
    /// full fuzz input fabricates a false GF-203/CWE-121 — the Rust build lane skips
    /// it as a primary target. Distinct from `is_unsafe` so a safe raw-pointer
    /// signature keeps its promotion.
    pub is_unsafe_fn: bool,
    pub visibility: RustVisibility,
    /// The condition text of a `#[cfg(...)]` attribute guarding the definition
    /// (e.g. `target_os = "windows"`), or `None`. Mirrors the C parser's
    /// `foreign_guard`.
    pub foreign_guard: Option<String>,
    /// `true` when this function sits inside a `fuzz_target!` invocation — an
    /// existing libFuzzer harness, the highest-value Rust discovery.
    pub in_fuzz_target: bool,
    /// `true` when a `#[doc(hidden)]` attribute guards the definition. Such items
    /// are explicitly "not public API" (e.g. serde_json's
    /// `Number::from_string_unchecked`); the ranker drops them.
    pub doc_hidden: bool,
    /// `true` when the function declares a generic TYPE parameter (`fn f<T>(...)`),
    /// excluding lifetime-only (`<'a>`) and const (`<const N: usize>`) params. Such
    /// a fn can't be called without naming the type, and is uninferable when the
    /// type appears only in the return (e.g. `from_slice<T: Deserialize>` ->
    /// `Result<T>`), so the Rust lane skips it rather than emitting a failed build.
    pub has_type_generics: bool,
    /// The declared generic TYPE parameters with their (collapsed) trait bounds —
    /// `<T: AsRef<[u8]>>` -> `[{name:"T", bound:"AsRef<[u8]>"}]`. Lifetime and
    /// const params are excluded. The harness generator monomorphizes a param
    /// bounded by a byte/str-slice conversion (`AsRef<[u8]>`) to a concrete
    /// `&[u8]`/`&str`; an unrecognized or return-only bound is still rejected.
    pub type_params: Vec<RustTypeParam>,
    /// For a method defined in a TRAIT impl (`impl Trait for Type { fn m(..) }`),
    /// the trait spelling as written (`ByteOrder`, `byteorder::ByteOrder`); `None`
    /// for a free fn or an inherent-impl method. A trait-impl method carries no
    /// `pub` (it inherits the trait's visibility), so the parser records it as
    /// `Pub` and the harness calls it by UFCS `<Type as Trait>::m(..)` — which
    /// needs no `use` of the trait. Enables crates whose API is trait-impl methods
    /// on marker types (byteorder's `ByteOrder` on `BigEndian`/`LittleEndian`).
    pub impl_trait: Option<String>,
    /// `true` when this is a method DECLARED inside a `pub trait` body — either a
    /// bodyless required signature (`fn read(&mut self) -> u8;`) or a default method
    /// (byteorder's `ReadBytesExt::read_u32<T: ByteOrder>`). Such a method has no
    /// enclosing concrete `impl` type; the Rust lane synthesises a std-reader
    /// receiver (`std::io::Cursor`) for it and imports the trait. For a trait
    /// method, `impl_trait` carries the DECLARING trait's name and `visibility`
    /// is recorded `Pub` (a `pub trait`'s methods are public API).
    pub is_trait_method: bool,
    /// For a trait method, the enclosing `pub trait`'s supertrait bound spelling
    /// (`io::Read` for `pub trait ReadBytesExt: io::Read`), collapsed and with the
    /// leading `:` stripped; `None` for an unbounded trait or a non-trait fn. The
    /// ranker and the Rust build lane key the std-reader receiver synthesis off a
    /// `Read`/`BufRead` supertrait (only then is a `Cursor` receiver constructable).
    pub trait_supertrait: Option<String>,
}

/// A generic TYPE parameter declared by a function, with its trait bound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RustTypeParam {
    /// The parameter name, e.g. `T`.
    pub name: String,
    /// The collapsed trait-bound spelling (`AsRef<[u8]>`, `Deserialize`,
    /// `AsRef<[u8]> + Send`), or empty for an unbounded `<T>`.
    pub bound: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RustParseError {
    #[error("failed to load Rust grammar")]
    Grammar,
    #[error("failed to parse Rust source")]
    Parse,
}

/// Hard cap on recursive AST-walk depth. tree-sitter parses deep input fine
/// (iterative parser), but our recursive walkers use one stack frame per AST
/// level; pathologically deep source otherwise overflows the worker stack.
/// Mirrors `c_parser::MAX_AST_DEPTH`.
const MAX_AST_DEPTH: usize = 250;

thread_local! {
    static AST_WALK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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

/// Parse Rust `source` and return every function definition it declares.
///
/// Methods and associated functions inside `impl` blocks are included (with
/// `is_static` distinguishing free/assoc fns from `&self` methods). Functions
/// textually contained in a `fuzz_target!` macro body are NOT returned as
/// `RustFn`s (a macro body is not a `function_item`); instead, every function
/// in a file that contains a `fuzz_target!` invocation is tagged
/// `in_fuzz_target = true` so the ranker can promote existing-harness files.
pub fn parse_rust_functions(source: &str) -> Result<Vec<RustFn>, RustParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| RustParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(RustParseError::Parse)?;
    let bytes = source.as_bytes();
    let file_has_fuzz_target = file_contains_fuzz_target(tree.root_node(), bytes);
    let mut functions = Vec::new();
    collect_functions(
        tree.root_node(),
        bytes,
        None,
        false,
        file_has_fuzz_target,
        &mut functions,
    );
    Ok(functions)
}

/// The enclosing `pub trait` declaration threaded into its method bodies: the
/// trait's name (so a method records it in `impl_trait`) and its supertrait bound
/// spelling (so the reader-receiver synthesis can detect a `Read`/`BufRead` bound).
#[derive(Clone, Copy)]
struct TraitDecl<'a> {
    name: &'a str,
    supertrait: Option<&'a str>,
}

/// A `pub` enum definition extracted from one source file. Used by the harness
/// generator to decode an enum-typed parameter: pick a variant by a fuzz byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustEnum {
    pub name: String,
    /// Names of the UNIT variants (no tuple/struct payload), in declaration order.
    pub unit_variants: Vec<String>,
    /// True when EVERY variant is a unit variant (so any can be picked with no data).
    pub all_unit: bool,
    /// `pub` visibility (only `pub` enums are reachable from a harness crate).
    pub is_pub: bool,
}

/// Parse the enum definitions in `source`. Only the variant SHAPE is extracted
/// (enough to decode an enum parameter by selecting a unit variant).
pub fn parse_rust_enums(source: &str) -> Vec<RustEnum> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    collect_enums(tree.root_node(), bytes, &mut out);
    out
}

fn collect_enums(node: tree_sitter::Node<'_>, bytes: &[u8], out: &mut Vec<RustEnum>) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "enum_item" {
            if let Some(e) = parse_enum_item(child, bytes) {
                out.push(e);
            }
        }
        collect_enums(child, bytes, out);
    }
}

fn parse_enum_item(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<RustEnum> {
    let name = node
        .child_by_field_name("name")?
        .utf8_text(bytes)
        .ok()?
        .to_owned();
    let is_pub = node
        .children(&mut node.walk())
        .any(|c| c.kind() == "visibility_modifier" && c.utf8_text(bytes) == Ok("pub"));
    let body = node.child_by_field_name("body")?;
    let mut unit_variants = Vec::new();
    let mut all_unit = true;
    let mut total = 0usize;
    let mut cursor = body.walk();
    for variant in body.children(&mut cursor) {
        if variant.kind() != "enum_variant" {
            continue;
        }
        total += 1;
        // A unit variant has a `name` but no tuple/struct payload field.
        let has_payload = variant.children(&mut variant.walk()).any(|c| {
            c.kind() == "ordered_field_declaration_list" || c.kind() == "field_declaration_list"
        });
        if has_payload {
            all_unit = false;
        } else if let Some(vn) = variant.child_by_field_name("name") {
            if let Ok(vn) = vn.utf8_text(bytes) {
                unit_variants.push(vn.to_owned());
            }
        }
    }
    if total == 0 {
        return None;
    }
    Some(RustEnum {
        name,
        unit_variants,
        all_unit,
        is_pub,
    })
}

/// Count `ERROR`/`MISSING` nodes — used by the CLI to warn "parser confused,
/// results may be incomplete" when discovery comes up empty on a real file.
/// Mirrors `c_parser::count_parse_errors`.
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return 0;
    }
    let Some(tree) = parser.parse(source, None) else {
        return 0;
    };
    let mut count = 0usize;
    walk_errors(tree.root_node(), &mut count);
    count
}

fn walk_errors(node: tree_sitter::Node<'_>, count: &mut usize) {
    let Some(_guard) = AstDepthGuard::enter() else {
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

/// Whether the file contains any `fuzz_target!` macro invocation.
fn file_contains_fuzz_target(node: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    let Some(_guard) = AstDepthGuard::enter() else {
        return false;
    };
    if node.kind() == "macro_invocation" {
        if let Some(macro_name) = node.child_by_field_name("macro") {
            if macro_name.utf8_text(bytes) == Ok("fuzz_target") {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if file_contains_fuzz_target(child, bytes) {
            return true;
        }
    }
    false
}

/// Recursive walk: collect every `function_item`, carrying a pending
/// `#[cfg(...)]` guard seen on the immediately-preceding sibling attribute.
fn collect_functions(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    inherited_cfg: Option<String>,
    inherited_doc_hidden: bool,
    file_has_fuzz_target: bool,
    out: &mut Vec<RustFn>,
) {
    collect_functions_in(
        node,
        bytes,
        inherited_cfg,
        inherited_doc_hidden,
        file_has_fuzz_target,
        None,
        None,
        out,
    );
}

/// `collect_functions` plus the enclosing TRAIT-impl trait name (`impl_trait`) and
/// the enclosing `pub trait` declaration (`trait_decl`), threaded so a trait-impl
/// method is recorded `Pub`/tagged with its trait and a `pub trait`'s own methods
/// are collected as public trait methods.
#[allow(clippy::too_many_arguments)]
fn collect_functions_in(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    inherited_cfg: Option<String>,
    inherited_doc_hidden: bool,
    file_has_fuzz_target: bool,
    impl_trait: Option<&str>,
    trait_decl: Option<TraitDecl<'_>>,
    out: &mut Vec<RustFn>,
) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    // Walk children in order so a `#[cfg(...)]` / `#[doc(hidden)]` attribute_item
    // attaches to the function_item that immediately follows it (siblings in a
    // source_file / declaration_list / mod body).
    let mut pending_cfg: Option<String> = None;
    let mut pending_doc_hidden = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "attribute_item" => {
                if let Some(cfg) = cfg_condition(child, bytes) {
                    pending_cfg = Some(cfg);
                }
                if is_doc_hidden_attr(child, bytes) {
                    pending_doc_hidden = true;
                }
                // A non-cfg / non-doc attribute (e.g. `#[inline]`) leaves any
                // pending guard intact: `#[doc(hidden)] #[inline] fn f` still hides.
            }
            // A function with a body. Inside a `pub trait` body it is a default
            // method (byteorder's `ReadBytesExt::read_u8`); elsewhere a free fn /
            // impl method.
            "function_item" => {
                let guard = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                if let Some(func) = parse_function_item(
                    child,
                    bytes,
                    guard,
                    file_has_fuzz_target,
                    doc_hidden,
                    impl_trait,
                    trait_decl,
                ) {
                    out.push(func);
                }
            }
            // A bodyless required trait method (`fn read_u32(&mut self) -> u32;`).
            // Only meaningful inside a `pub trait` body — `trait_decl` is `Some`.
            "function_signature_item" if trait_decl.is_some() => {
                let guard = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                if let Some(func) = parse_function_item(
                    child,
                    bytes,
                    guard,
                    file_has_fuzz_target,
                    doc_hidden,
                    impl_trait,
                    trait_decl,
                ) {
                    out.push(func);
                }
            }
            // `impl Type { ... }` / `impl Trait for Type { ... }` — recurse into the
            // body. A `#[cfg]` / `#[doc(hidden)]` on the impl guards every method;
            // a trait impl's `trait` field tags its methods so they call by UFCS.
            "impl_item" => {
                let impl_cfg = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let impl_doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                let trait_name = child
                    .child_by_field_name("trait")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .map(collapse_ws);
                collect_functions_in(
                    child,
                    bytes,
                    impl_cfg,
                    impl_doc_hidden,
                    file_has_fuzz_target,
                    trait_name.as_deref(),
                    None,
                    out,
                );
            }
            // An impl body, or a trait body — preserve the enclosing trait-impl tag
            // and the enclosing `pub trait` declaration.
            "declaration_list" => {
                let inner_cfg = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let inner_doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                collect_functions_in(
                    child,
                    bytes,
                    inner_cfg,
                    inner_doc_hidden,
                    file_has_fuzz_target,
                    impl_trait,
                    trait_decl,
                    out,
                );
            }
            // `mod m { ... }` (inline modules) open a NEW scope — their functions
            // are not methods of any enclosing trait impl or declaration.
            "mod_item" => {
                let inner_cfg = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let inner_doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                collect_functions_in(
                    child,
                    bytes,
                    inner_cfg,
                    inner_doc_hidden,
                    file_has_fuzz_target,
                    None,
                    None,
                    out,
                );
            }
            // A `pub trait Foo: Read { ... }` declaration. Its methods (default OR
            // bodyless required) are public API on a synthesised receiver, so thread
            // the trait name + supertrait into the body. A non-`pub` trait opens a
            // new scope with no public trait methods (they need a concrete impl to
            // be reachable).
            "trait_item" => {
                let inner_cfg = pending_cfg.take().or_else(|| inherited_cfg.clone());
                let inner_doc_hidden = pending_doc_hidden || inherited_doc_hidden;
                pending_doc_hidden = false;
                let is_pub = child
                    .children(&mut child.walk())
                    .any(|c| c.kind() == "visibility_modifier" && c.utf8_text(bytes) == Ok("pub"));
                // The supertrait bound spelling (`io::Read` for `: io::Read`), with
                // the leading `:` stripped — keyed by the reader-receiver lane.
                let supertrait = child.child_by_field_name("bounds").and_then(|b| {
                    b.utf8_text(bytes)
                        .ok()
                        .map(|t| collapse_ws(t.trim_start_matches(':').trim()))
                });
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok());
                let inner_trait_decl = match (is_pub, name) {
                    (true, Some(name)) => Some(TraitDecl {
                        name,
                        supertrait: supertrait.as_deref(),
                    }),
                    _ => None,
                };
                collect_functions_in(
                    child,
                    bytes,
                    inner_cfg,
                    inner_doc_hidden,
                    file_has_fuzz_target,
                    None,
                    inner_trait_decl,
                    out,
                );
            }
            _ => {
                // Other nodes: clear any pending guard (it only guards a directly
                // following item) and recurse to catch nested functions.
                pending_cfg = None;
                pending_doc_hidden = false;
                collect_functions_in(
                    child,
                    bytes,
                    inherited_cfg.clone(),
                    inherited_doc_hidden,
                    file_has_fuzz_target,
                    impl_trait,
                    trait_decl,
                    out,
                );
            }
        }
    }
}

/// Extract a `RustFn` from a `function_item` or `function_signature_item` node.
/// Both expose the same `name`/`parameters`/`return_type`/`type_parameters` fields;
/// a signature item simply has no body (a bodyless required trait method).
fn parse_function_item(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    foreign_guard: Option<String>,
    file_has_fuzz_target: bool,
    doc_hidden: bool,
    impl_trait: Option<&str>,
    trait_decl: Option<TraitDecl<'_>>,
) -> Option<RustFn> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(bytes).ok()?.to_owned();
    let line = name_node.start_position().row as u32 + 1;

    // A trait-impl method (or a `pub trait`'s own method) has the trait's
    // visibility — it carries no `pub` modifier of its own, so treat it as `Pub`
    // (the trait makes it part of the public API).
    let visibility = if impl_trait.is_some() || trait_decl.is_some() {
        RustVisibility::Pub
    } else {
        node.children(&mut node.walk())
            .find(|c| c.kind() == "visibility_modifier")
            .map(|v| parse_visibility(v, bytes))
            .unwrap_or_default()
    };

    let return_type = node
        .child_by_field_name("return_type")
        .map(|rt| collapse_ws(rt.utf8_text(bytes).unwrap_or("")));

    let (params, has_self) = node
        .child_by_field_name("parameters")
        .map(|p| parse_parameters(p, bytes))
        .unwrap_or_default();

    // `unsafe fn` is marked by a `function_modifiers` child containing `unsafe`.
    let has_unsafe_modifier = node
        .children(&mut node.walk())
        .filter(|c| c.kind() == "function_modifiers")
        .any(|m| m.utf8_text(bytes).map(|t| t.contains("unsafe")) == Ok(true));
    // A raw-pointer parameter or return type is an FFI/unsafe surface even on a
    // safe-signature fn.
    let touches_raw_pointer = params.iter().any(|p| p.ty.contains('*'))
        || return_type.as_deref().is_some_and(|t| t.contains('*'));
    let type_params = parse_type_params(node, bytes);

    Some(RustFn {
        name,
        line,
        return_type,
        params,
        // Free fn / associated fn (no `self` receiver) are static; a method is
        // not. `&self` / `&mut self` / `self` all count as a receiver.
        is_static: !has_self,
        is_unsafe: has_unsafe_modifier || touches_raw_pointer,
        is_unsafe_fn: has_unsafe_modifier,
        visibility,
        foreign_guard,
        in_fuzz_target: file_has_fuzz_target,
        doc_hidden,
        has_type_generics: !type_params.is_empty(),
        type_params,
        // For a `pub trait`'s own method, tag it with the DECLARING trait so the
        // build lane can import that trait for the synthesised receiver call.
        impl_trait: impl_trait
            .map(str::to_owned)
            .or_else(|| trait_decl.map(|t| t.name.to_owned())),
        is_trait_method: trait_decl.is_some(),
        trait_supertrait: trait_decl.and_then(|t| t.supertrait.map(str::to_owned)),
    })
}

fn parse_visibility(node: tree_sitter::Node<'_>, bytes: &[u8]) -> RustVisibility {
    let text = collapse_ws(node.utf8_text(bytes).unwrap_or(""));
    if text == "pub" {
        RustVisibility::Pub
    } else if text.starts_with("pub") {
        // `pub(crate)`, `pub(in path)`, `pub(super)`, `pub(self)` — all
        // crate-internal API surface.
        RustVisibility::PubCrate
    } else {
        RustVisibility::Private
    }
}

/// Returns the parameter list and whether a `self` receiver was present.
fn parse_parameters(node: tree_sitter::Node<'_>, bytes: &[u8]) -> (Vec<RustParam>, bool) {
    let mut params = Vec::new();
    let mut has_self = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "self_parameter" => has_self = true,
            "parameter" => {
                // `pattern : type` — the type is the `type` field; the binding
                // is the `pattern` field (commonly an identifier).
                let ty = child
                    .child_by_field_name("type")
                    .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                let name = child
                    .child_by_field_name("pattern")
                    .map(|p| collapse_ws(p.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                params.push(RustParam { name, ty });
            }
            // A bare `...` variadic in an extern fn, or `_: T` shapes are rare in
            // a fuzzable Rust API; ignore other child kinds.
            _ => {}
        }
    }
    (params, has_self)
}

/// If `attribute_item` is a `#[cfg(...)]`, return the inner condition text
/// (e.g. `target_os = "windows"`). Mirrors the C parser's `foreign_guard`
/// extraction. `#[cfg_attr(...)]` and non-cfg attributes return `None`.
/// True when an `attribute_item` is `#[doc(hidden)]`.
fn is_doc_hidden_attr(node: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute" {
            let is_doc = child
                .child_by_field_name("path")
                .or_else(|| {
                    child
                        .children(&mut child.walk())
                        .find(|c| c.kind() == "identifier")
                })
                .map(|p| p.utf8_text(bytes) == Ok("doc"))
                .unwrap_or(false);
            if !is_doc {
                return false;
            }
            // `doc(hidden)` — the arg token_tree contains the `hidden` ident.
            return child
                .children(&mut child.walk())
                .find(|c| c.kind() == "token_tree")
                .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")).contains("hidden"))
                .unwrap_or(false);
        }
    }
    false
}

/// Extract a `function_item`'s generic TYPE parameters (`<T>` / `<T: Bound>`) with
/// their collapsed trait bounds. Lifetime (`<'a>`) and const (`<const N: usize>`)
/// params are excluded (they don't block calling the fn). The name and bound are
/// split on the first `:` of each parameter's source text, which is robust across
/// tree-sitter field-name differences.
fn parse_type_params(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<RustTypeParam> {
    let Some(tp) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = tp.walk();
    for c in tp.children(&mut cursor) {
        if c.kind() != "type_parameter" && c.kind() != "constrained_type_parameter" {
            continue;
        }
        let text = c.utf8_text(bytes).unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let (name, bound) = match text.split_once(':') {
            Some((n, b)) => (n.trim().to_owned(), collapse_ws(b)),
            None => (text.to_owned(), String::new()),
        };
        if !name.is_empty() {
            out.push(RustTypeParam { name, bound });
        }
    }
    // Merge WHERE-clause bounds (`fn f<T>(..) where T: Deserialize<'a>`). tree-sitter
    // keeps these in a `where_clause`, NOT the `<...>` list, so an otherwise-bare
    // `<T>` would lose its bound — and EVERY serde format crate writes
    // `from_str<T>(..) where T: Deserialize` this way, leaving the parser unable to
    // monomorphize the primary parse entry point.
    let mut where_clause = node.child_by_field_name("where_clause");
    if where_clause.is_none() {
        let mut c = node.walk();
        where_clause = node.children(&mut c).find(|n| n.kind() == "where_clause");
    }
    if let Some(wc) = where_clause {
        let mut wcur = wc.walk();
        for pred in wc.children(&mut wcur) {
            if pred.kind() != "where_predicate" {
                continue;
            }
            let text = pred.utf8_text(bytes).unwrap_or("").trim();
            // A predicate is `<type-or-lifetime> : <bounds>`. Skip lifetime
            // predicates (`'a: 'b`) and only attach to a declared TYPE param.
            if let Some((lhs, b)) = text.split_once(':') {
                let lhs = lhs.trim();
                let bound = collapse_ws(b);
                if bound.is_empty() {
                    continue;
                }
                if let Some(param) = out.iter_mut().find(|p| p.name == lhs) {
                    if param.bound.is_empty() {
                        param.bound = bound;
                    } else {
                        param.bound = format!("{} + {bound}", param.bound);
                    }
                }
            }
        }
    }
    out
}

fn cfg_condition(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute" {
            let ident = child.child_by_field_name("path").or_else(|| {
                child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "identifier")
            })?;
            if ident.utf8_text(bytes) != Ok("cfg") {
                return None;
            }
            // The argument list is a `token_tree`: strip the outer parens.
            let args = child
                .children(&mut child.walk())
                .find(|c| c.kind() == "token_tree")?;
            let raw = args.utf8_text(bytes).ok()?;
            let inner = raw
                .trim()
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(raw);
            return Some(collapse_ws(inner));
        }
    }
    None
}

/// Collapse all runs of ASCII whitespace to single spaces and trim — so type
/// spellings compare stably regardless of source formatting.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Mine string- and number-like source literals into fuzzing-dictionary tokens
/// (magic values that gate `==`/`match` comparisons). Mirrors the C/C++ lanes so
/// the native Rust lane no longer fuzzes "cold". The tree is untrusted, so the
/// walk is depth-capped ([`DICT_MAX_DEPTH`]) to avoid stack overflow.
pub fn extract_rust_dictionary_tokens(source: &str) -> Result<Vec<String>, RustParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| RustParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(RustParseError::Parse)?;
    let mut tokens = Vec::new();
    collect_dictionary_tokens(tree.root_node(), source.as_bytes(), 0, &mut tokens);
    Ok(tokens)
}

/// Recursion cap for the untrusted-tree dictionary walk.
const DICT_MAX_DEPTH: usize = 256;

fn collect_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    depth: usize,
    out: &mut Vec<String>,
) {
    if depth >= DICT_MAX_DEPTH {
        return;
    }
    let kind = node.kind();
    if dict_kind_is_string_like(kind) {
        if let Ok(text) = node.utf8_text(src) {
            if let Some(tok) = clean_dict_string(text) {
                push_unique_token(out, tok);
            }
        }
        return; // a string is a leaf value — never recurse into its content
    }
    if dict_kind_is_number_like(kind) {
        if let Ok(text) = node.utf8_text(src) {
            if let Some(tok) = clean_dict_number(text) {
                push_unique_token(out, tok);
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_dictionary_tokens(child, src, depth + 1, out);
    }
}

fn dict_kind_is_string_like(kind: &str) -> bool {
    kind.contains("string")
        || matches!(
            kind,
            "char_literal"
                | "character_literal"
                | "rune_literal"
                | "interpolated_string_literal"
                | "heredoc_content"
                | "quoted_content"
        )
}

fn dict_kind_is_number_like(kind: &str) -> bool {
    matches!(
        kind,
        "integer_literal"
            | "int_literal"
            | "integer"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "number"
            | "numeric_literal"
            | "float_literal"
    )
}

/// Strip an optional byte/raw/format prefix (`b`, `r`, `f`, `u`, `L`, ...), one
/// matching layer of surrounding quotes, and Rust raw-string `#` hashes from a
/// string-like literal, keeping the inner bytes verbatim (no unescaping). Rejects
/// empty/whitespace and results outside 1..=64 bytes.
fn clean_dict_string(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    let lead = s.bytes().take_while(u8::is_ascii_alphabetic).count();
    if lead > 0
        && s.as_bytes()
            .get(lead)
            .is_some_and(|&c| matches!(c, b'"' | b'\'' | b'`' | b'#'))
    {
        s = &s[lead..];
    }
    let hashes = s.bytes().take_while(|b| *b == b'#').count();
    if hashes > 0 && s.len() >= 2 * hashes {
        s = &s[hashes..s.len() - hashes];
    }
    let b = s.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if matches!(first, b'"' | b'\'' | b'`') && first == last {
            s = &s[1..s.len() - 1];
        }
    }
    if s.trim().is_empty() || s.len() > 64 {
        return None;
    }
    Some(s.to_owned())
}

/// Keep a number-like literal verbatim (trimmed); reject empty / over 32 bytes.
fn clean_dict_number(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    Some(s.to_owned())
}

fn push_unique_token(out: &mut Vec<String>, tok: String) {
    if !out.contains(&tok) {
        out.push(tok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_and_integer_dictionary_tokens() {
        let toks = extract_rust_dictionary_tokens(
            "fn f(n: u32) { let x = \"MAGIC\"; if n == 4919 { let _ = x; } }",
        )
        .expect("parse");
        assert!(toks.contains(&"MAGIC".to_string()), "tokens: {toks:?}");
        assert!(toks.contains(&"4919".to_string()), "tokens: {toks:?}");
    }

    fn parse(src: &str) -> Vec<RustFn> {
        parse_rust_functions(src).expect("parse")
    }

    fn by_name<'a>(fns: &'a [RustFn], name: &str) -> &'a RustFn {
        fns.iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("function {name} not found in {fns:?}"))
    }

    #[test]
    fn parses_free_function_signature() {
        let fns = parse("pub fn parse_thing(data: &[u8]) -> Result<u32, ()> { Ok(0) }");
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "parse_thing");
        assert_eq!(f.line, 1);
        assert_eq!(f.visibility, RustVisibility::Pub);
        assert!(f.is_static, "a free fn has no self receiver");
        assert_eq!(f.return_type.as_deref(), Some("Result<u32, ()>"));
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name, "data");
        assert_eq!(f.params[0].ty, "&[u8]");
        assert!(f.foreign_guard.is_none());
        assert!(!f.in_fuzz_target);
    }

    #[test]
    fn captures_pub_crate_and_private_visibility() {
        let fns = parse(
            "pub(crate) fn helper(s: &str) -> bool { false }\n\
             fn private_one(x: i32) {}",
        );
        assert_eq!(by_name(&fns, "helper").visibility, RustVisibility::PubCrate);
        assert_eq!(
            by_name(&fns, "private_one").visibility,
            RustVisibility::Private
        );
    }

    #[test]
    fn pub_in_path_is_pub_crate() {
        let fns = parse("pub(in crate::a) fn scoped() {}");
        assert_eq!(by_name(&fns, "scoped").visibility, RustVisibility::PubCrate);
    }

    #[test]
    fn parses_unit_enum_variants() {
        let enums = parse_rust_enums(
            "pub enum AdaStandard { Ada95, Ada2005, Ada2012, Ada2022 }\n\
             enum Private { A, B }\n\
             pub enum Mixed { Unit, Tuple(u32), Struct { x: u8 } }",
        );
        let ada = enums.iter().find(|e| e.name == "AdaStandard").unwrap();
        assert!(ada.is_pub && ada.all_unit);
        assert_eq!(
            ada.unit_variants,
            vec!["Ada95", "Ada2005", "Ada2012", "Ada2022"]
        );
        let private = enums.iter().find(|e| e.name == "Private").unwrap();
        assert!(!private.is_pub);
        let mixed = enums.iter().find(|e| e.name == "Mixed").unwrap();
        assert!(!mixed.all_unit, "has tuple/struct variants");
        assert_eq!(
            mixed.unit_variants,
            vec!["Unit"],
            "only the unit variant is listed"
        );
    }

    #[test]
    fn doc_hidden_attribute_is_detected() {
        // `#[doc(hidden)]` items are explicitly "not public API" (serde_json's
        // `Number::from_string_unchecked` is one); the ranker drops them.
        let fns = parse(
            "#[doc(hidden)]\n\
             pub fn from_string_unchecked(s: String) {}\n\
             pub fn real_api(s: &str) {}",
        );
        assert!(by_name(&fns, "from_string_unchecked").doc_hidden);
        assert!(!by_name(&fns, "real_api").doc_hidden);
    }

    #[test]
    fn doc_hidden_survives_intervening_attribute() {
        // `#[doc(hidden)] #[inline] fn f` still hides `f`.
        let fns = parse("#[doc(hidden)]\n#[inline]\npub fn f(s: &str) {}");
        assert!(by_name(&fns, "f").doc_hidden);
    }

    #[test]
    fn fn_level_type_generics_are_detected() {
        // A function generic over a TYPE param (e.g. `from_slice<T: Deserialize>`)
        // can't be called without naming T; uninferable when T is return-only.
        let fns = parse(
            "pub fn from_slice<T>(d: &[u8]) -> Result<T, ()> { unimplemented!() }\n\
             pub fn plain(s: &str) {}\n\
             pub fn lifetime_only<'a>(s: &'a str) {}\n\
             pub fn const_only<const N: usize>(s: &str) {}",
        );
        assert!(by_name(&fns, "from_slice").has_type_generics);
        assert!(!by_name(&fns, "plain").has_type_generics, "no generics");
        assert!(
            !by_name(&fns, "lifetime_only").has_type_generics,
            "lifetime params are not type params and stay harnessable"
        );
        assert!(
            !by_name(&fns, "const_only").has_type_generics,
            "const params are not type params"
        );
    }

    #[test]
    fn type_param_bounds_are_captured() {
        // The bound spelling drives byte-slice monomorphization in harness_gen.
        let fns = parse(
            "pub fn decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> { Vec::new() }\n\
             pub fn unbounded<T>(d: &[u8]) -> Option<T> { None }\n\
             pub fn multi<T: AsRef<[u8]> + Send>(data: T) {}",
        );
        let d = by_name(&fns, "decode");
        assert_eq!(d.type_params.len(), 1);
        assert_eq!(d.type_params[0].name, "T");
        assert_eq!(d.type_params[0].bound, "AsRef<[u8]>");
        assert_eq!(by_name(&fns, "unbounded").type_params[0].bound, "");
        assert_eq!(
            by_name(&fns, "multi").type_params[0].bound,
            "AsRef<[u8]> + Send"
        );
    }

    #[test]
    fn where_clause_bounds_are_merged_into_type_params() {
        // Serde format crates write the Deserialize bound in a WHERE clause, not
        // inline (`from_slice<'a, T>(v: &'a [u8]) -> Result<T> where T: Deserialize`).
        // It must still land on the type param so the harness can monomorphize.
        let fns = parse(
            "pub fn from_slice<'a, T>(v: &'a [u8]) -> Result<T>\n\
             where\n\
                 T: serde::de::Deserialize<'a>,\n\
             { todo!() }",
        );
        let f = by_name(&fns, "from_slice");
        assert_eq!(f.type_params.len(), 1);
        assert_eq!(f.type_params[0].name, "T");
        assert!(
            f.type_params[0].bound.contains("Deserialize"),
            "where-bound merged: {:?}",
            f.type_params[0]
        );
    }

    #[test]
    fn method_with_self_is_not_static_assoc_fn_is() {
        let fns = parse(
            "pub struct R;\n\
             impl R {\n\
                 pub fn new() -> Self { R }\n\
                 pub fn read(&self, data: &[u8]) -> usize { 0 }\n\
                 pub fn from_bytes(data: &[u8]) -> R { R }\n\
                 pub fn mutate(&mut self) {}\n\
             }",
        );
        assert!(by_name(&fns, "new").is_static, "no receiver");
        assert!(by_name(&fns, "from_bytes").is_static, "assoc fn, no self");
        assert!(!by_name(&fns, "read").is_static, "&self method");
        assert!(!by_name(&fns, "mutate").is_static, "&mut self method");
    }

    #[test]
    fn extracts_cfg_foreign_guard() {
        let fns = parse(
            "#[cfg(target_os = \"windows\")]\n\
             pub fn win_only(b: Vec<u8>) {}\n\
             pub fn portable(b: Vec<u8>) {}",
        );
        assert_eq!(
            by_name(&fns, "win_only").foreign_guard.as_deref(),
            Some("target_os = \"windows\"")
        );
        assert!(by_name(&fns, "portable").foreign_guard.is_none());
    }

    #[test]
    fn cfg_on_impl_guards_each_method() {
        let fns = parse(
            "pub struct R;\n\
             #[cfg(unix)]\n\
             impl R {\n\
                 pub fn a(&self) {}\n\
                 pub fn b(&self) {}\n\
             }",
        );
        assert_eq!(by_name(&fns, "a").foreign_guard.as_deref(), Some("unix"));
        assert_eq!(by_name(&fns, "b").foreign_guard.as_deref(), Some("unix"));
    }

    #[test]
    fn non_cfg_attribute_is_not_a_guard() {
        let fns = parse("#[inline]\npub fn fast(x: i32) -> i32 { x }");
        assert!(by_name(&fns, "fast").foreign_guard.is_none());
    }

    #[test]
    fn file_with_fuzz_target_tags_in_fuzz_target() {
        // The `fuzz_target!` body is a macro token tree, so the closure body is
        // not parsed as a function_item. We still mark any sibling fn in the
        // file as in_fuzz_target so an existing harness file ranks top.
        let fns = parse(
            "#![no_main]\n\
             use libfuzzer_sys::fuzz_target;\n\
             fn helper(d: &[u8]) -> bool { false }\n\
             fuzz_target!(|data: &[u8]| { let _ = helper(data); });",
        );
        assert!(
            by_name(&fns, "helper").in_fuzz_target,
            "a file containing fuzz_target! marks its fns in_fuzz_target"
        );
    }

    #[test]
    fn file_without_fuzz_target_does_not_tag() {
        let fns = parse("pub fn plain(d: &[u8]) {}");
        assert!(!by_name(&fns, "plain").in_fuzz_target);
    }

    #[test]
    fn unsafe_fn_and_raw_pointer_signatures_are_flagged_unsafe() {
        let fns = parse(
            "pub unsafe fn explicit(d: &[u8]) {}\n\
             pub fn raw_ptr(p: *const u8, len: usize) -> *mut u8 { p as *mut u8 }\n\
             pub fn safe(d: &[u8]) -> u32 { 0 }",
        );
        assert!(by_name(&fns, "explicit").is_unsafe, "unsafe fn modifier");
        assert!(
            by_name(&fns, "raw_ptr").is_unsafe,
            "raw-pointer signature is an FFI/unsafe surface"
        );
        assert!(!by_name(&fns, "safe").is_unsafe);
        // `is_unsafe_fn` is the MODIFIER only: the raw-pointer fn is NOT an unsafe fn.
        assert!(by_name(&fns, "explicit").is_unsafe_fn, "unsafe fn modifier");
        assert!(
            !by_name(&fns, "raw_ptr").is_unsafe_fn,
            "a safe raw-pointer fn is not an `unsafe fn`"
        );
        assert!(!by_name(&fns, "safe").is_unsafe_fn);
    }

    #[test]
    fn no_return_type_is_none() {
        let fns = parse("pub fn sink(d: &[u8]) {}");
        assert!(by_name(&fns, "sink").return_type.is_none());
    }

    #[test]
    fn multiple_params_and_self_describing_types() {
        let fns = parse("pub fn decode(input: &str, max: usize) -> Option<String> { None }");
        let f = &fns[0];
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].ty, "&str");
        assert_eq!(f.params[1].ty, "usize");
        assert_eq!(f.return_type.as_deref(), Some("Option<String>"));
    }

    #[test]
    fn malformed_source_does_not_panic() {
        // Recovery path: tree-sitter still yields a tree; we must not crash.
        let fns = parse("pub fn broken(d: &[u8] { ");
        let _ = fns; // any result is acceptable; the contract is "no panic".
    }

    #[test]
    fn nested_module_functions_are_found() {
        let fns = parse(
            "pub mod inner {\n\
                 pub fn nested(data: &[u8]) -> u32 { 0 }\n\
             }",
        );
        assert!(fns.iter().any(|f| f.name == "nested"));
    }

    #[test]
    fn count_parse_errors_flags_broken_source() {
        assert_eq!(count_parse_errors("pub fn ok(x: i32) -> i32 { x }"), 0);
        assert!(count_parse_errors("pub fn bad(") > 0);
    }

    #[test]
    fn trait_impl_methods_are_public_and_tagged_with_their_trait() {
        // byteorder shape: a `self`-less method in a trait impl carries no `pub` but
        // is part of the public API — record it `Pub` and tag it with the trait.
        let src = "pub trait Decode { fn decode(buf: &[u8]) -> u32; }\n\
                   pub enum Big {}\n\
                   impl Decode for Big { fn decode(buf: &[u8]) -> u32 { buf.len() as u32 } }\n\
                   pub struct Thing;\n\
                   impl Thing { pub fn inherent(b: &[u8]) -> usize { b.len() } fn private(x: i32) -> i32 { x } }";
        let fns = parse_rust_functions(src).unwrap();
        let decode = fns.iter().find(|f| f.name == "decode").unwrap();
        assert_eq!(decode.visibility, RustVisibility::Pub);
        assert_eq!(decode.impl_trait.as_deref(), Some("Decode"));
        assert!(decode.is_static);
        // An inherent `pub fn` is unaffected (no trait tag).
        let inherent = fns.iter().find(|f| f.name == "inherent").unwrap();
        assert_eq!(inherent.visibility, RustVisibility::Pub);
        assert_eq!(inherent.impl_trait, None);
        // An inherent NON-pub method stays private (only trait-impl methods are
        // promoted, since those genuinely inherit the trait's visibility).
        let private = fns.iter().find(|f| f.name == "private").unwrap();
        assert_eq!(private.visibility, RustVisibility::Private);
        assert_eq!(private.impl_trait, None);
        // The trait DECLARATION's own method is not a trait-impl method.
        // (It has no body; `parse_rust_functions` only collects function_items.)
    }

    #[test]
    fn pub_trait_methods_are_collected_with_supertrait() {
        // byteorder shape: a `pub trait ReadBytesExt: io::Read` with a bodyless
        // required method, a default (with-body) method, and a generic-marker
        // default method. All three are collected as public trait methods tagged
        // with the trait + its `io::Read` supertrait.
        let src = "use std::io;\n\
                   pub trait ReadBytesExt: io::Read {\n\
                       fn read_tag(&mut self) -> io::Result<u8>;\n\
                       fn read_u8(&mut self) -> io::Result<u8> { Ok(0) }\n\
                       fn read_u32<T: ByteOrder>(&mut self) -> io::Result<u32> { Ok(0) }\n\
                   }\n";
        let fns = parse_rust_functions(src).unwrap();
        for name in ["read_tag", "read_u8", "read_u32"] {
            let f = by_name(&fns, name);
            assert!(f.is_trait_method, "{name} is a trait method");
            assert_eq!(f.visibility, RustVisibility::Pub, "{name} is public API");
            assert_eq!(f.impl_trait.as_deref(), Some("ReadBytesExt"), "{name}");
            assert_eq!(
                f.trait_supertrait.as_deref(),
                Some("io::Read"),
                "{name} carries the reader supertrait"
            );
            assert!(!f.is_static, "{name} takes &mut self");
        }
        // The generic-marker method keeps its `T: ByteOrder` type param (the
        // existing marker-turbofish lane resolves it).
        assert!(by_name(&fns, "read_u32").has_type_generics);
    }

    #[test]
    fn private_trait_methods_are_not_collected_as_public() {
        // A non-`pub` trait's bodyless signatures are NOT public API (a concrete
        // impl is needed to reach them); they stay uncollected. A default (with
        // body) method in a private trait stays Private, as before.
        let src = "trait Hidden {\n\
                       fn required(&self) -> u8;\n\
                       fn provided(&self) -> u8 { 0 }\n\
                   }\n";
        let fns = parse_rust_functions(src).unwrap();
        assert!(
            fns.iter().all(|f| f.name != "required"),
            "a bodyless signature in a private trait is not collected: {fns:?}"
        );
        let provided = by_name(&fns, "provided");
        assert!(!provided.is_trait_method, "private-trait method not tagged");
        assert_eq!(provided.visibility, RustVisibility::Private);
    }
}
