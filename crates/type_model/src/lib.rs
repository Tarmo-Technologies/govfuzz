// SPDX-License-Identifier: Apache-2.0
//! Semantic type model for the C lane.
//!
//! Maps raw C type strings (as extracted by `c_parser`) onto
//! decodable shapes. The registry is built per translation unit from
//! `c_parser::CTypeDefs` (the TU's own definitions plus any header
//! definitions the caller stitches in) and resolves typedef chains to
//! a fixed point. Resolution never fails: anything unknown degrades
//! to `TypeShape::Opaque`, and the decoder layer decides what that
//! means (skip, NULL, or a Phase C lifecycle cluster).

use std::collections::{HashMap, HashSet};

pub fn crate_name() -> &'static str {
    "type_model"
}

/// Canonical scalar spellings shared with `harness_gen`'s decoder
/// table so the two never drift. Each entry is (spelling, kind).
pub const SCALAR_SPELLINGS: &[(&str, ScalarKind)] = &[
    ("int", ScalarKind::I32),
    ("signed int", ScalarKind::I32),
    ("signed", ScalarKind::I32),
    ("unsigned", ScalarKind::U32),
    ("unsigned int", ScalarKind::U32),
    ("long", ScalarKind::I64),
    ("signed long", ScalarKind::I64),
    ("long int", ScalarKind::I64),
    ("unsigned long", ScalarKind::U64),
    ("unsigned long int", ScalarKind::U64),
    ("long long", ScalarKind::I64),
    ("signed long long", ScalarKind::I64),
    ("unsigned long long", ScalarKind::U64),
    ("short", ScalarKind::I16),
    ("signed short", ScalarKind::I16),
    ("unsigned short", ScalarKind::U16),
    // BSD/POSIX <sys/types.h> integer aliases (tcpdump, lwIP, most network/
    // systems C). Standardized meanings, so resolve them directly to scalars —
    // otherwise the typedef chases into a libc-internal `__u_int` the tree
    // doesn't define and the type is mis-classified opaque (no decoder) or, worse,
    // struct-synthesized into a definition that collides with <sys/types.h>.
    ("u_char", ScalarKind::U8),
    ("u_short", ScalarKind::U16),
    ("u_int", ScalarKind::U32),
    ("u_long", ScalarKind::U64),
    ("u_quad_t", ScalarKind::U64),
    ("quad_t", ScalarKind::I64),
    ("u_int8_t", ScalarKind::U8),
    ("u_int16_t", ScalarKind::U16),
    ("u_int32_t", ScalarKind::U32),
    ("u_int64_t", ScalarKind::U64),
    ("uchar", ScalarKind::U8),
    ("ushort", ScalarKind::U16),
    ("uint", ScalarKind::U32),
    ("ulong", ScalarKind::U64),
    ("size_t", ScalarKind::U64),
    ("std::size_t", ScalarKind::U64),
    ("ssize_t", ScalarKind::I64),
    ("time_t", ScalarKind::I64),
    ("MZ_TIME_T", ScalarKind::I64),
    ("uint8_t", ScalarKind::U8),
    ("std::uint8_t", ScalarKind::U8),
    ("int8_t", ScalarKind::I8),
    ("std::int8_t", ScalarKind::I8),
    ("unsigned char", ScalarKind::U8),
    ("signed char", ScalarKind::I8),
    ("char", ScalarKind::I8),
    // C++ character types. Without these a `char8_t`/`char16_t`/`char32_t`
    // value param is mis-classified opaque and its target skips ("unsupported
    // parameter type"), and — worse — a header that aliases a string type to one
    // of them under `#if __cplusplus` (utf8.h: `using utf8_int8_t = char8_t;`)
    // makes the whole `utf8_int8_t *` pointer opaque, so the string is cast raw
    // from Data (un-terminated) instead of NUL-terminated — a spurious
    // heap-buffer-overflow when the callee strlen's it. char8_t/char16_t/char32_t
    // are unsigned per the standard; wchar_t is 4-byte signed on Linux/macOS.
    ("char8_t", ScalarKind::U8),
    ("char16_t", ScalarKind::U16),
    ("char32_t", ScalarKind::U32),
    ("wchar_t", ScalarKind::I32),
    ("uint16_t", ScalarKind::U16),
    ("std::uint16_t", ScalarKind::U16),
    ("int16_t", ScalarKind::I16),
    ("std::int16_t", ScalarKind::I16),
    ("uint32_t", ScalarKind::U32),
    ("std::uint32_t", ScalarKind::U32),
    ("int32_t", ScalarKind::I32),
    ("std::int32_t", ScalarKind::I32),
    ("uint64_t", ScalarKind::U64),
    ("std::uint64_t", ScalarKind::U64),
    ("int64_t", ScalarKind::I64),
    ("std::int64_t", ScalarKind::I64),
    // MSVC fixed-width integer spellings. A header's `#ifdef _MSC_VER typedef
    // __int64 ssize_t` branch is parsed verbatim (tree-sitter does not evaluate the
    // `#ifdef`), so a typedef resolves to `__int64` even on a non-MSVC host
    // (utf8proc's `utf8proc_ssize_t`); without these it is mis-classified opaque
    // and the whole candidate skips for "needs lifecycle support".
    ("__int8", ScalarKind::I8),
    ("signed __int8", ScalarKind::I8),
    ("unsigned __int8", ScalarKind::U8),
    ("__int16", ScalarKind::I16),
    ("signed __int16", ScalarKind::I16),
    ("unsigned __int16", ScalarKind::U16),
    ("__int32", ScalarKind::I32),
    ("signed __int32", ScalarKind::I32),
    ("unsigned __int32", ScalarKind::U32),
    ("__int64", ScalarKind::I64),
    ("signed __int64", ScalarKind::I64),
    ("unsigned __int64", ScalarKind::U64),
    // Win32 integer typedefs (windef.h/basetsd.h). MFC/ATL and plain Win32 C++
    // sources use these constantly, but on an offline non-Windows lab <windows.h>
    // is not in the scanned tree, so the typedef chain has nothing to chase and
    // `BOOL`/`DWORD` resolve opaque -> the target is skipped as "needs lifecycle
    // support (Phase C)". Resolve them directly to their underlying integer.
    // Widths are the Win32 (LP64-on-Windows) meanings: LONG/DWORD/ULONG are
    // 32-bit even though Linux `long` is 64-bit — the emitted decl keeps the
    // alias spelling (defined by whatever header the target includes), so only
    // the fuzz byte-count differs, a benign over/under-read, never a build break.
    // POINTER/handle typedefs (HANDLE/HWND/LPVOID/LPCTSTR/…) are deliberately
    // absent: they must stay on the pointer path, not be mis-decoded as ints.
    ("BOOL", ScalarKind::I32),
    ("BOOLEAN", ScalarKind::U8),
    ("INT", ScalarKind::I32),
    ("UINT", ScalarKind::U32),
    ("INT8", ScalarKind::I8),
    ("UINT8", ScalarKind::U8),
    ("INT16", ScalarKind::I16),
    ("UINT16", ScalarKind::U16),
    ("INT32", ScalarKind::I32),
    ("UINT32", ScalarKind::U32),
    ("INT64", ScalarKind::I64),
    ("UINT64", ScalarKind::U64),
    ("LONG", ScalarKind::I32),
    ("ULONG", ScalarKind::U32),
    ("LONG32", ScalarKind::I32),
    ("ULONG32", ScalarKind::U32),
    ("LONG64", ScalarKind::I64),
    ("ULONG64", ScalarKind::U64),
    ("LONGLONG", ScalarKind::I64),
    ("ULONGLONG", ScalarKind::U64),
    ("DWORD", ScalarKind::U32),
    ("DWORD32", ScalarKind::U32),
    ("DWORD64", ScalarKind::U64),
    ("DWORDLONG", ScalarKind::U64),
    ("QWORD", ScalarKind::U64),
    ("WORD", ScalarKind::U16),
    ("SHORT", ScalarKind::I16),
    ("USHORT", ScalarKind::U16),
    ("CHAR", ScalarKind::I8),
    ("UCHAR", ScalarKind::U8),
    ("BYTE", ScalarKind::U8),
    ("float", ScalarKind::F32),
    ("double", ScalarKind::F64),
    ("_Bool", ScalarKind::Bool),
    ("bool", ScalarKind::Bool),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub shape: TypeShape,
    /// The raw C type string for emission (e.g. `unsigned long`,
    /// `struct point`), before pointer/array decoration.
    pub c_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeShape {
    Scalar(ScalarKind),
    /// `const char *` / `char *` — NUL-terminated string.
    CString,
    Enum {
        name: String,
        members: Vec<String>,
    },
    Struct {
        name: String,
        fields: Vec<Field>,
    },
    Union {
        name: String,
        fields: Vec<Field>,
    },
    Pointer(Box<TypeShape>),
    Array {
        elem: Box<TypeShape>,
        len: usize,
    },
    FuncPtr,
    /// Unresolvable: forward-declared struct, unknown typedef,
    /// `void`, or anything else we cannot shape. Carries the
    /// normalized spelling for diagnostics.
    Opaque(String),
}

/// #99: how to construct a live instance of an opaque C++ class parameter that is
/// NOT default-constructible, resolved from the owning header/include closure. The
/// decoder carries these recipes so it can emit a genuine lifecycle construction
/// (`T name = Owner::create();` / `T name(arg0, arg1);`) instead of rejecting the
/// parameter as unsupported. Populated only for the target's direct opaque-class
/// parameters, so a recipe's constructor arguments are always directly decodable —
/// the recursive arg decode terminates without hitting another recipe.
#[derive(Debug, Clone)]
pub enum ClassConstruction {
    /// A self-contained construction expression that yields the class BY VALUE,
    /// e.g. a public static factory `"Owner::create()"`. Emitted as
    /// `T name = <expr>;`.
    Expression(String),
    /// A public parameterized constructor whose argument types are all directly
    /// byte-decodable. Emitted as `T name(<decoded args>);`.
    Constructor { param_types: Vec<String> },
}

/// Per-translation-unit type registry.
#[derive(Debug, Default)]
pub struct TypeRegistry {
    structs: HashMap<String, c_parser::CStructDef>,
    unions: HashMap<String, c_parser::CStructDef>,
    enums: HashMap<String, c_parser::CEnumDef>,
    typedefs: HashMap<String, String>,
    /// C++ lexical scopes, most-specific first (`ns::Class`, then `ns`). Used
    /// only when an unqualified spelling needs to resolve a namespace-qualified
    /// definition; empty for C and for callers without scope context.
    cpp_lookup_scopes: Vec<String>,
    /// C++ class names known to be default-constructible (a public, non-deleted
    /// default constructor; not abstract; not a template). Carried here so the
    /// decoder layer — which only has the type string + this registry — can
    /// emit a default-constructed value for a class-typed argument instead of
    /// failing (#353). Populated by the caller for the C++ path; empty for C.
    default_constructible_classes: HashSet<String>,
    /// C++ class names (canonical spelling) that are NOT default-constructible but
    /// CAN be built via a resolved public factory or parameterized constructor
    /// (#99). Keyed by `canonical_class_spelling`. Empty for C and for targets
    /// whose parameters are all directly decodable.
    class_constructions: HashMap<String, ClassConstruction>,
}

/// Hard cap on typedef-chase hops and struct nesting so resolution is
/// total even on adversarial inputs (`typedef a b; typedef b a;`).
const MAX_RESOLVE_DEPTH: usize = 16;

impl TypeRegistry {
    /// Build from one or more translation units' definitions (the
    /// target TU first, then headers; first definition of a name wins
    /// except that complete struct definitions replace forward ones).
    pub fn from_defs<'a>(all: impl IntoIterator<Item = &'a c_parser::CTypeDefs>) -> Self {
        let mut reg = Self::default();
        for defs in all {
            for s in &defs.structs {
                match reg.structs.get(&s.name) {
                    Some(existing) if existing.complete || !s.complete => {}
                    _ => {
                        reg.structs.insert(s.name.clone(), s.clone());
                    }
                }
            }
            for e in &defs.enums {
                reg.enums.entry(e.name.clone()).or_insert_with(|| e.clone());
            }
            for t in &defs.typedefs {
                reg.typedefs
                    .entry(t.name.clone())
                    .or_insert_with(|| t.underlying.clone());
            }
        }
        reg
    }

    /// Attach the set of default-constructible C++ class names (#353).
    pub fn with_default_constructible_classes(
        mut self,
        names: impl IntoIterator<Item = String>,
    ) -> Self {
        self.default_constructible_classes = names.into_iter().collect();
        self
    }

    pub fn with_cpp_lookup_scopes(mut self, scopes: impl IntoIterator<Item = String>) -> Self {
        self.cpp_lookup_scopes = scopes.into_iter().collect();
        self
    }

    /// Attach declaration-aware construction recipes for opaque C++ class
    /// parameters (#99). Keyed by canonical class spelling.
    pub fn with_class_constructions(
        mut self,
        recipes: impl IntoIterator<Item = (String, ClassConstruction)>,
    ) -> Self {
        self.class_constructions = recipes.into_iter().collect();
        self
    }

    /// The construction recipe for an opaque class parameter, if one was resolved
    /// from the owning header (#99). `name` is a canonical class spelling.
    pub fn class_construction(&self, name: &str) -> Option<&ClassConstruction> {
        self.class_constructions.get(name)
    }

    fn lookup_named<'a, T>(&'a self, map: &'a HashMap<String, T>, name: &str) -> Option<&'a T> {
        if let Some(exact) = map.get(name) {
            return Some(exact);
        }
        if !name.contains("::") {
            for scope in &self.cpp_lookup_scopes {
                if let Some(scoped) = map.get(&format!("{scope}::{name}")) {
                    return Some(scoped);
                }
            }
        }
        let leaf = qualified_leaf(name).unwrap_or(name);
        let mut matches = map
            .iter()
            .filter(|(key, _)| key.rsplit("::").next() == Some(leaf))
            .map(|(_, value)| value);
        let only = matches.next()?;
        matches.next().is_none().then_some(only)
    }

    /// Whether `name` (a bare, unqualified class spelling) was recorded as
    /// default-constructible. Empty set => always false (the C path).
    pub fn is_default_constructible_class(&self, name: &str) -> bool {
        self.default_constructible_classes.contains(name)
    }

    /// Resolve a raw C type string to a shape. Never fails.
    pub fn resolve(&self, raw: &str) -> TypeShape {
        self.resolve_inner(raw, 0)
    }

    /// Return the raw pointee spelling for direct pointers or typedefs to
    /// pointers. Used by codegen to allocate stack storage for pointer aliases
    /// such as `typedef mz_stream *mz_streamp`.
    pub fn pointer_base_spelling(&self, raw: &str) -> Option<String> {
        let mut current = normalize(raw);
        for _ in 0..=MAX_RESOLVE_DEPTH {
            if let Some(base) = current.strip_suffix('*') {
                return Some(base.trim().to_owned());
            }
            let underlying = self.lookup_named(&self.typedefs, &current)?;
            current = normalize(underlying);
        }
        None
    }

    /// Follow a typedef/alias chain to its final underlying spelling, e.g. with
    /// `using ustring = std::string;` in scope, `alias_target_spelling("ustring")`
    /// is `Some("std::string")`. Returns `None` when `raw` is not itself an alias,
    /// so the caller keeps the original spelling. Lets the param decoders see the
    /// real `std::string`/`const char *`/scalar behind a project alias
    /// (libE57Format spells its reader's path parameter `const ustring &`).
    pub fn alias_target_spelling(&self, raw: &str) -> Option<String> {
        let mut current = normalize(raw);
        let mut resolved = None;
        for _ in 0..=MAX_RESOLVE_DEPTH {
            // A namespace-/scope-qualified leaf (`csv::string_view`) falls back to
            // the bare typedef key (`string_view`): a `using string_view = …;` alias
            // declared inside `namespace csv` is recorded under its bare leaf, but
            // parameters spell it `csv::string_view`. Mirrors `resolve_inner`'s leaf
            // fallback so the string-alias redirect and the no-public-constructor
            // gate both see through the qualified spelling (csv-parser, bug #16).
            let underlying = self.lookup_named(&self.typedefs, &current).cloned();
            match underlying {
                Some(underlying) => {
                    current = normalize(&underlying);
                    resolved = Some(current.clone());
                }
                None => break,
            }
        }
        resolved
    }

    /// When `raw` — a function's RESULT or RECEIVER type — resolves BY VALUE
    /// (never through a pointer) to a struct or union whose tag the harness
    /// translation unit knows only as a FORWARD declaration (present in this
    /// registry, but with no complete definition), return that incomplete
    /// `struct X` / `union X` spelling.
    ///
    /// This is the precise oracle for §26.4: declaring a local of such a type
    /// (`<IncompleteType> R = target(...);`) is rejected by the compiler with
    /// "variable has incomplete type", so a target whose result/receiver type is
    /// incomplete in the harness TU must be skipped cleanly rather than emitted as
    /// an uncompilable harness (stb `stb_cfg` aka `struct stb_cfg_st`,
    /// `stb_threadqueue`).
    ///
    /// Deliberately returns `None` — i.e. does NOT skip — for:
    ///   - a pointer (`stb_cfg *`): a pointer to an incomplete type is legal;
    ///   - a scalar / `char *` string / `void` / complete aggregate / enum;
    ///   - a type this registry does not model at all (it may be fully defined in
    ///     a header we never parsed — skipping on mere ignorance would drop real
    ///     targets).
    pub fn resolves_to_incomplete_aggregate(&self, raw: &str) -> Option<String> {
        let mut current = normalize(raw);
        for _ in 0..=MAX_RESOLVE_DEPTH {
            // A pointer / array / function pointer is never an incomplete by-value
            // declaration: a pointer to an incomplete type is legal, an array
            // element is resolved elsewhere, a funcptr is complete.
            if current.contains('*') || current.contains('[') || current.contains("(*") {
                return None;
            }
            if current == "void" || scalar_kind(&current).is_some() {
                return None;
            }
            // Explicit `struct X` / `union X` tags: incomplete only when the tag is
            // present in the registry AND has no complete definition. An unknown tag
            // (not in the registry) is left to the compiler — do not skip on it.
            if let Some(tag) = current.strip_prefix("struct ") {
                let tag = tag.trim();
                return match self.lookup_named(&self.structs, tag) {
                    Some(def) if def.complete => None,
                    Some(_) => Some(format!("struct {tag}")),
                    None => None,
                };
            }
            if let Some(tag) = current.strip_prefix("union ") {
                let tag = tag.trim();
                return match self
                    .lookup_named(&self.unions, tag)
                    .or_else(|| self.lookup_named(&self.structs, tag))
                {
                    Some(def) if def.complete => None,
                    Some(_) => Some(format!("union {tag}")),
                    None => None,
                };
            }
            if current.starts_with("enum ") {
                // An enum spelled with the keyword is a complete scalar by value.
                return None;
            }
            // Bare name: a struct-by-alias, an enum, or a typedef to chase.
            if let Some(def) = self.lookup_named(&self.structs, &current) {
                return if def.complete {
                    None
                } else {
                    Some(format!("struct {}", def.name))
                };
            }
            if self.lookup_named(&self.enums, &current).is_some() {
                return None;
            }
            if let Some(underlying) = self.lookup_named(&self.typedefs, &current) {
                current = normalize(underlying);
                continue;
            }
            // Unmodeled — do not skip on ignorance.
            return None;
        }
        None
    }

    /// Return a function-pointer signature for a raw function-pointer spelling
    /// or a typedef chain that resolves to one. The signature preserves
    /// parameter spelling because C codegen needs it for trampoline prototypes.
    pub fn function_pointer_signature(&self, raw: &str) -> Option<String> {
        if raw.contains("(*") {
            return Some(canonical_function_pointer_signature(raw));
        }
        let mut current = normalize(raw);
        for _ in 0..=MAX_RESOLVE_DEPTH {
            let underlying = self.lookup_named(&self.typedefs, &current)?;
            if underlying.contains("(*") {
                return Some(canonical_function_pointer_signature(underlying));
            }
            current = normalize(underlying);
        }
        None
    }

    fn resolve_inner(&self, raw: &str, depth: usize) -> TypeShape {
        if depth > MAX_RESOLVE_DEPTH {
            return TypeShape::Opaque(raw.trim().to_owned());
        }
        // Function-pointer spellings (`T (*)(...)`, `T (*name)(...)`)
        // checked on the raw text — normalization respaces `*`.
        if raw.contains("(*") {
            // An array of function pointers — `RET (*)(...)[N]` (a callback table
            // struct field, `void (*handlers[N])(int)`) — resolves to an array whose
            // element is a function pointer, so the decoder fills every slot with a
            // trampoline rather than treating the whole field as one funcptr and
            // assigning to a (non-assignable) array lvalue (§27.3). The trailing
            // `[N]` follows the final `)` of the parameter list; a bare funcptr (no
            // such suffix) keeps the FuncPtr shape.
            if let Some(len) = funcptr_array_len(raw) {
                return TypeShape::Array {
                    elem: Box::new(TypeShape::FuncPtr),
                    len,
                };
            }
            return TypeShape::FuncPtr;
        }
        let normalized = normalize(raw);

        // Fixed-size array suffix: `char[16]`.
        if let Some((base, len)) = split_array(&normalized) {
            let elem = self.resolve_inner(base, depth + 1);
            return TypeShape::Array {
                elem: Box::new(elem),
                len,
            };
        }

        // Pointer peeling, one level per recursion.
        if let Some(base) = normalized.strip_suffix('*') {
            let base = base.trim_end();
            // const char * / char * is a string, not Pointer(I8).
            if matches!(base, "char") {
                return TypeShape::CString;
            }
            return TypeShape::Pointer(Box::new(self.resolve_inner(base, depth + 1)));
        }

        if normalized == "void" {
            return TypeShape::Opaque("void".to_owned());
        }

        if let Some(kind) = scalar_kind(&normalized) {
            return TypeShape::Scalar(kind);
        }

        if let Some(tag) = normalized.strip_prefix("struct ") {
            return self.struct_shape(tag.trim(), raw, depth);
        }
        if let Some(tag) = normalized.strip_prefix("union ") {
            return self.union_shape(tag.trim(), raw, depth);
        }
        if let Some(tag) = normalized.strip_prefix("enum ") {
            return self.enum_shape(tag.trim(), raw);
        }

        // Bare name: enum, struct-by-alias, or typedef chain.
        if let Some(def) = self.lookup_named(&self.enums, &normalized) {
            return enum_shape_for_spelling(def, &normalized);
        }
        if self.lookup_named(&self.structs, &normalized).is_some() {
            return self.struct_shape(&normalized, raw, depth);
        }
        if let Some(underlying) = self.lookup_named(&self.typedefs, &normalized) {
            return self.resolve_inner(&underlying.clone(), depth + 1);
        }

        // Only infer a project-prefixed scalar after consulting real tree
        // declarations. A source typedef such as `char8_t utf8_int8_t` is more
        // authoritative than the `_int8_t` spelling heuristic.
        if let Some(kind) = project_prefixed_scalar_kind(&normalized) {
            return TypeShape::Scalar(kind);
        }

        TypeShape::Opaque(normalized)
    }

    fn struct_shape(&self, tag: &str, raw: &str, depth: usize) -> TypeShape {
        match self.lookup_named(&self.structs, tag) {
            Some(def) if def.complete => TypeShape::Struct {
                name: def.name.clone(),
                fields: self.fields_of(def, depth),
            },
            _ => TypeShape::Opaque(normalize(raw)),
        }
    }

    fn union_shape(&self, tag: &str, raw: &str, depth: usize) -> TypeShape {
        match self
            .lookup_named(&self.unions, tag)
            .or_else(|| self.lookup_named(&self.structs, tag))
        {
            Some(def) if def.complete => TypeShape::Union {
                name: def.name.clone(),
                fields: self.fields_of(def, depth),
            },
            _ => TypeShape::Opaque(normalize(raw)),
        }
    }

    fn enum_shape(&self, tag: &str, raw: &str) -> TypeShape {
        match self.lookup_named(&self.enums, tag) {
            Some(def) => enum_shape_for_spelling(def, tag),
            None => TypeShape::Opaque(normalize(raw)),
        }
    }

    fn fields_of(&self, def: &c_parser::CStructDef, depth: usize) -> Vec<Field> {
        def.fields
            .iter()
            .map(|f| Field {
                name: f.name.clone(),
                shape: self.resolve_inner(&f.c_type, depth + 1),
                c_type: f.c_type.clone(),
            })
            .collect()
    }
}

pub fn scalar_kind(normalized: &str) -> Option<ScalarKind> {
    SCALAR_SPELLINGS
        .iter()
        .find(|(spelling, _)| *spelling == normalized)
        .map(|(_, kind)| *kind)
}

fn project_prefixed_scalar_kind(normalized: &str) -> Option<ScalarKind> {
    for (suffix, kind) in [
        ("_bool", ScalarKind::Bool),
        ("_int8_t", ScalarKind::I8),
        ("_uint8_t", ScalarKind::U8),
        ("_int16_t", ScalarKind::I16),
        ("_uint16_t", ScalarKind::U16),
        ("_int32_t", ScalarKind::I32),
        ("_uint32_t", ScalarKind::U32),
        ("_int64_t", ScalarKind::I64),
        ("_uint64_t", ScalarKind::U64),
        ("_ssize_t", ScalarKind::I64),
        ("_size_t", ScalarKind::U64),
        ("_option_t", ScalarKind::I32),
        ("_flags_t", ScalarKind::U32),
    ] {
        if normalized.len() > suffix.len() && normalized.ends_with(suffix) {
            return Some(kind);
        }
    }
    None
}

/// Collapse whitespace and strip qualifiers that don't affect decoding.
fn normalize(raw: &str) -> String {
    let collapsed = raw
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "restrict" | "register"))
        .collect::<Vec<_>>()
        .join(" ")
        .replace('*', " * ");
    collapsed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" * ", " *")
        .trim()
        .to_owned()
}

fn canonical_function_pointer_signature(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned()
}

fn qualified_leaf(normalized: &str) -> Option<&str> {
    normalized.rsplit_once("::").map(|(_, leaf)| leaf.trim())
}

fn enum_shape_for_spelling(def: &c_parser::CEnumDef, spelling: &str) -> TypeShape {
    TypeShape::Enum {
        name: def.name.clone(),
        members: qualify_enum_members_for_spelling(def, spelling),
    }
}

fn qualify_enum_members_for_spelling(def: &c_parser::CEnumDef, spelling: &str) -> Vec<String> {
    // The reference `spelling` may prepend extra namespace/class scope onto the
    // enum's own (possibly already-qualified) name. `def.name` is the authoritative
    // tag — it is bare for a top-level enum (`Mode`) and fully qualified for a
    // member enum (`FmtScope::value`, recorded scope-first by the C++ parser so
    // sibling member enums named the same bare tag stay distinct). The members are
    // recorded relative to that same name, so the ONLY qualification still needed is
    // whatever extra leading scope the spelling adds beyond `def.name`:
    //   spelling "gov::Mode"        def "Mode"            -> prefix "gov::"
    //   spelling "FmtScope::value"  def "FmtScope::value" -> prefix ""  (members as-is)
    //   spelling "YAML::FmtScope::value" def "FmtScope::value" -> prefix "YAML::"
    let Some(extra_scope) = spelling.strip_suffix(&def.name) else {
        return def.members.clone();
    };
    // A genuine prefix ends at a `::` boundary (or is empty); a partial-token match
    // (`GameMode` ending in `Mode`) is not a scope and must be ignored.
    if !extra_scope.is_empty() && !extra_scope.ends_with("::") {
        return def.members.clone();
    }
    if extra_scope.is_empty() {
        return def.members.clone();
    }
    def.members
        .iter()
        .map(|member| format!("{extra_scope}{member}"))
        .collect()
}

/// The element count `N` of an array-of-function-pointers spelling
/// `RET (*)(...)[N]`, or `None` for a bare function pointer. The array dimension
/// is the `[N]` AFTER the final `)` (the close of the parameter list), so a
/// funcptr whose own parameters contain array brackets (`int (*)(char buf[4])`)
/// is not mistaken for an array of funcptrs.
fn funcptr_array_len(raw: &str) -> Option<usize> {
    let last_paren = raw.rfind(')')?;
    let suffix = raw[last_paren + 1..].trim();
    let inner = suffix.strip_prefix('[')?.strip_suffix(']')?.trim();
    inner.parse().ok()
}

fn split_array(normalized: &str) -> Option<(&str, usize)> {
    let open = normalized.find('[')?;
    let close = normalized.rfind(']')?;
    if close <= open {
        return None;
    }
    let len: usize = normalized[open + 1..close].trim().parse().ok()?;
    Some((normalized[..open].trim_end(), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cxx_character_types_resolve_to_integer_scalars() {
        // Without these, a `char8_t`/`char16_t`/`char32_t` param is opaque (its
        // target skips), and a header aliasing a string type to one of them
        // (utf8.h: `using utf8_int8_t = char8_t;`) makes the whole pointer opaque
        // so the string is cast raw from Data (un-terminated) -> spurious OOB.
        let reg = TypeRegistry::default();
        assert_eq!(reg.resolve("char8_t"), TypeShape::Scalar(ScalarKind::U8));
        assert_eq!(reg.resolve("char16_t"), TypeShape::Scalar(ScalarKind::U16));
        assert_eq!(reg.resolve("char32_t"), TypeShape::Scalar(ScalarKind::U32));
        assert_eq!(reg.resolve("wchar_t"), TypeShape::Scalar(ScalarKind::I32));
        // A pointer to a char-typedef whose underlying type is char8_t is a byte
        // pointer (string), not opaque.
        let defs = c_parser::parse_c_type_defs("typedef char8_t utf8_int8_t;").expect("parses");
        let reg = TypeRegistry::from_defs([&defs]);
        assert_eq!(
            reg.resolve("const utf8_int8_t *"),
            TypeShape::Pointer(Box::new(TypeShape::Scalar(ScalarKind::U8)))
        );
    }

    #[test]
    fn project_prefixed_fixed_width_aliases_resolve_without_their_header() {
        let reg = TypeRegistry::default();
        assert_eq!(
            reg.resolve("cJSON_bool"),
            TypeShape::Scalar(ScalarKind::Bool)
        );
        assert_eq!(
            reg.resolve("const utf8proc_uint8_t *"),
            TypeShape::Pointer(Box::new(TypeShape::Scalar(ScalarKind::U8)))
        );
        assert_eq!(
            reg.resolve("vendor_int32_t"),
            TypeShape::Scalar(ScalarKind::I32)
        );
        assert_eq!(
            reg.resolve("utf8proc_ssize_t"),
            TypeShape::Scalar(ScalarKind::I64)
        );
        assert_eq!(
            reg.resolve("utf8proc_option_t"),
            TypeShape::Scalar(ScalarKind::I32)
        );
        assert_eq!(
            reg.resolve("widget_bool_t"),
            TypeShape::Opaque("widget_bool_t".to_owned())
        );
    }

    #[test]
    fn default_constructible_classes_round_trip() {
        let reg = TypeRegistry::default()
            .with_default_constructible_classes(["FastBuffer".to_owned(), "Config".to_owned()]);
        assert!(reg.is_default_constructible_class("FastBuffer"));
        assert!(reg.is_default_constructible_class("Config"));
        assert!(!reg.is_default_constructible_class("Other"));
        // The C path leaves the set empty -> always false.
        assert!(!TypeRegistry::default().is_default_constructible_class("FastBuffer"));
    }

    fn registry() -> TypeRegistry {
        let defs = c_parser::parse_c_type_defs(
            r#"
        typedef unsigned long mz_ulong;
        typedef mz_ulong mz_ulong_alias;
        struct point { int x; int y; };
        typedef struct point point_t;
        typedef struct point *point_ptr;
        typedef struct { point_t origin; char name[16]; mz_ulong flags; } shape;
        enum tinfl_status { TINFL_OK, TINFL_FAILED };
        typedef enum { TDEFL_NO_FLUSH, TDEFL_SYNC_FLUSH } tdefl_flush;
        typedef int (*callback_t)(void *opaque);
        struct callbacks { callback_t cb; };
        struct opaque;
        struct node { int v; struct node *next; };
        typedef b_loop a_loop;
        typedef a_loop b_loop;
        "#,
        )
        .expect("parses");
        TypeRegistry::from_defs([&defs])
    }

    #[test]
    fn resolves_scalar_typedef_chains() {
        let reg = registry();
        assert_eq!(reg.resolve("mz_ulong"), TypeShape::Scalar(ScalarKind::U64));
        assert_eq!(
            reg.resolve("mz_ulong_alias"),
            TypeShape::Scalar(ScalarKind::U64)
        );
        assert_eq!(
            reg.resolve("const mz_ulong"),
            TypeShape::Scalar(ScalarKind::U64),
            "qualifiers are stripped"
        );
    }

    #[test]
    fn resolves_posix_bsd_integer_aliases_to_scalars() {
        // Even when the tree typedefs the alias to a libc-internal opaque base
        // (`typedef __u_char u_char;`), the standardized alias resolves directly
        // to a scalar — not opaque, not struct-synthesized (tcpdump/lwIP).
        let defs = c_parser::parse_c_type_defs(
            "typedef unsigned char __u_char; typedef __u_char u_char;\n",
        )
        .unwrap();
        let reg = TypeRegistry::from_defs([&defs]);
        assert_eq!(reg.resolve("u_char"), TypeShape::Scalar(ScalarKind::U8));
        assert_eq!(reg.resolve("u_int"), TypeShape::Scalar(ScalarKind::U32));
        assert_eq!(reg.resolve("u_short"), TypeShape::Scalar(ScalarKind::U16));
        assert_eq!(reg.resolve("u_long"), TypeShape::Scalar(ScalarKind::U64));
        assert_eq!(
            reg.resolve("const u_int"),
            TypeShape::Scalar(ScalarKind::U32)
        );
    }

    #[test]
    fn resolves_struct_by_tag_alias_and_pointer() {
        let reg = registry();
        let TypeShape::Struct { name, fields } = reg.resolve("struct point") else {
            panic!("expected struct shape");
        };
        assert_eq!(name, "point");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].shape, TypeShape::Scalar(ScalarKind::I32));

        assert!(matches!(reg.resolve("point_t"), TypeShape::Struct { .. }));
        assert!(matches!(
            reg.resolve("point_ptr"),
            TypeShape::Pointer(inner) if matches!(*inner, TypeShape::Struct { .. })
        ));
        assert_eq!(
            reg.pointer_base_spelling("point_ptr").as_deref(),
            Some("struct point")
        );
        let TypeShape::Pointer(inner) = reg.resolve("const struct point *") else {
            panic!("expected pointer shape");
        };
        assert!(matches!(*inner, TypeShape::Struct { .. }));
    }

    #[test]
    fn resolves_nested_struct_array_and_enum_fields() {
        let reg = registry();
        let TypeShape::Struct { fields, .. } = reg.resolve("shape") else {
            panic!("expected struct shape for anonymous typedef");
        };
        assert!(matches!(fields[0].shape, TypeShape::Struct { .. }));
        let TypeShape::Array { ref elem, len } = fields[1].shape else {
            panic!("expected array field, got {:?}", fields[1].shape);
        };
        assert_eq!(len, 16);
        assert_eq!(**elem, TypeShape::Scalar(ScalarKind::I8));
        assert_eq!(fields[2].shape, TypeShape::Scalar(ScalarKind::U64));

        let TypeShape::Enum { members, .. } = reg.resolve("enum tinfl_status") else {
            panic!("expected enum shape");
        };
        assert_eq!(members, vec!["TINFL_OK", "TINFL_FAILED"]);
        assert!(matches!(
            reg.resolve("tinfl_status"),
            TypeShape::Enum { .. }
        ));
        let TypeShape::Enum { members, .. } = reg.resolve("tdefl_flush") else {
            panic!("expected typedef enum shape");
        };
        assert_eq!(members, vec!["TDEFL_NO_FLUSH", "TDEFL_SYNC_FLUSH"]);
        assert_eq!(reg.resolve("callback_t"), TypeShape::FuncPtr);
        let TypeShape::Struct { fields, .. } = reg.resolve("struct callbacks") else {
            panic!("expected callbacks struct");
        };
        assert_eq!(fields[0].shape, TypeShape::FuncPtr);
    }

    #[test]
    fn resolves_callback_array_to_array_of_function_pointers() {
        // §27.3: a callback-array field spelling `RET (*)(...)[N]` must resolve to an
        // array whose element is a function pointer (so the decoder fills every slot
        // with a trampoline), NOT to a single FuncPtr (which would assign to a
        // non-assignable array lvalue). A bare funcptr keeps the FuncPtr shape, and a
        // funcptr whose own params use array brackets is not mistaken for an array.
        let reg = TypeRegistry::default();
        assert_eq!(
            reg.resolve("void (*)(int)[4]"),
            TypeShape::Array {
                elem: Box::new(TypeShape::FuncPtr),
                len: 4,
            }
        );
        assert_eq!(reg.resolve("void (*)(int)"), TypeShape::FuncPtr);
        assert_eq!(reg.resolve("int (*)(char buf[4])"), TypeShape::FuncPtr);
    }

    #[test]
    fn resolves_function_pointer_typedef_signature() {
        let reg = registry();

        assert_eq!(
            reg.function_pointer_signature("callback_t").as_deref(),
            Some("int (*)(void *opaque)")
        );
        assert_eq!(
            reg.function_pointer_signature("int (*)(void)").as_deref(),
            Some("int (*)(void)")
        );
    }

    #[test]
    fn degrades_gracefully() {
        let reg = registry();
        assert!(matches!(
            reg.resolve("struct opaque *"),
            TypeShape::Pointer(inner) if matches!(*inner, TypeShape::Opaque(_))
        ));
        assert_eq!(reg.resolve("WCHAR"), TypeShape::Opaque("WCHAR".into()));
        assert!(matches!(reg.resolve("void *"), TypeShape::Pointer(_)));
        assert_eq!(reg.resolve("int (*)()"), TypeShape::FuncPtr);
        // Self-referential struct terminates.
        let TypeShape::Struct { fields, .. } = reg.resolve("struct node") else {
            panic!("expected struct node");
        };
        assert!(matches!(fields[1].shape, TypeShape::Pointer(_)));
        // Typedef cycle terminates as Opaque instead of recursing.
        assert!(matches!(reg.resolve("a_loop"), TypeShape::Opaque(_)));
    }

    #[test]
    fn cstring_spellings() {
        let reg = registry();
        assert_eq!(reg.resolve("const char *"), TypeShape::CString);
        assert_eq!(reg.resolve("char*"), TypeShape::CString);
        assert!(
            matches!(reg.resolve("unsigned char *"), TypeShape::Pointer(_)),
            "byte pointers are buffers, not strings"
        );
    }

    #[test]
    fn win32_integer_typedefs_resolve_as_scalars() {
        let reg = registry();
        // Win32 integer typedefs must decode as their underlying integer even
        // when <windows.h> is not in the scanned tree (offline dogfood of
        // MFC/Win32 C++ sources). Otherwise a `BOOL`/`DWORD` parameter is
        // mis-classified opaque and its whole target is skipped with
        // "needs lifecycle support (Phase C)". Widths follow Win32 (LP64-on-
        // Windows) semantics; only the fuzz byte-count differs from Linux LP64,
        // which is a benign over/under-read, never a build break.
        assert_eq!(reg.resolve("BOOL"), TypeShape::Scalar(ScalarKind::I32));
        assert_eq!(
            reg.resolve("const BOOL"),
            TypeShape::Scalar(ScalarKind::I32)
        );
        assert_eq!(reg.resolve("INT"), TypeShape::Scalar(ScalarKind::I32));
        assert_eq!(reg.resolve("UINT"), TypeShape::Scalar(ScalarKind::U32));
        assert_eq!(reg.resolve("DWORD"), TypeShape::Scalar(ScalarKind::U32));
        assert_eq!(reg.resolve("LONG"), TypeShape::Scalar(ScalarKind::I32));
        assert_eq!(reg.resolve("ULONG"), TypeShape::Scalar(ScalarKind::U32));
        assert_eq!(reg.resolve("WORD"), TypeShape::Scalar(ScalarKind::U16));
        assert_eq!(reg.resolve("SHORT"), TypeShape::Scalar(ScalarKind::I16));
        assert_eq!(reg.resolve("BYTE"), TypeShape::Scalar(ScalarKind::U8));
        assert_eq!(reg.resolve("LONGLONG"), TypeShape::Scalar(ScalarKind::I64));
        assert_eq!(reg.resolve("ULONGLONG"), TypeShape::Scalar(ScalarKind::U64));
        assert_eq!(reg.resolve("DWORD64"), TypeShape::Scalar(ScalarKind::U64));
        // A `const BOOL *` out-parameter stays a pointer to the scalar.
        assert!(matches!(
            reg.resolve("const BOOL *"),
            TypeShape::Pointer(inner) if matches!(*inner, TypeShape::Scalar(ScalarKind::I32))
        ));
        // Win32 POINTER/handle typedefs must NOT be scalarized — they remain
        // opaque (the pointer-lifecycle path), never mis-decoded as integers.
        assert!(matches!(reg.resolve("HANDLE"), TypeShape::Opaque(_)));
        assert!(matches!(reg.resolve("HWND"), TypeShape::Opaque(_)));
        assert!(matches!(reg.resolve("LPVOID"), TypeShape::Opaque(_)));
    }

    #[test]
    fn miniz_time_macro_alias_resolves_as_scalar() {
        let reg = registry();

        assert_eq!(reg.resolve("MZ_TIME_T"), TypeShape::Scalar(ScalarKind::I64));
        assert!(matches!(
            reg.resolve("const MZ_TIME_T *"),
            TypeShape::Pointer(inner) if matches!(*inner, TypeShape::Scalar(ScalarKind::I64))
        ));
    }

    #[test]
    fn resolves_cpp_qualified_names_by_leaf_identifier() {
        let defs = c_parser::CTypeDefs {
            structs: vec![c_parser::CStructDef {
                name: "Config".to_owned(),
                fields: vec![c_parser::CParamDescriptor {
                    name: "enabled".to_owned(),
                    c_type: "bool".to_owned(),
                }],
                line: 1,
                complete: true,
            }],
            enums: vec![c_parser::CEnumDef {
                name: "Mode".to_owned(),
                members: vec!["Mode::Fast".to_owned(), "Mode::Safe".to_owned()],
                line: 2,
            }],
            typedefs: Vec::new(),
        };
        let reg = TypeRegistry::from_defs([&defs]);

        let TypeShape::Enum { members, .. } = reg.resolve("gov::Mode") else {
            panic!("expected enum shape for qualified C++ enum name");
        };
        assert_eq!(members, vec!["gov::Mode::Fast", "gov::Mode::Safe"]);

        let TypeShape::Struct { fields, .. } = reg.resolve("gov::Config") else {
            panic!("expected struct shape for qualified C++ struct name");
        };
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].shape, TypeShape::Scalar(ScalarKind::Bool));
    }

    #[test]
    fn namespace_colliding_structs_resolve_exactly_or_by_lexical_scope() {
        let defs = c_parser::CTypeDefs {
            structs: vec![
                c_parser::CStructDef {
                    name: "one::Options".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "one_value".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                },
                c_parser::CStructDef {
                    name: "two::Options".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "two_value".to_owned(),
                        c_type: "bool".to_owned(),
                    }],
                    line: 2,
                    complete: true,
                },
            ],
            ..Default::default()
        };
        let unscoped = TypeRegistry::from_defs([&defs]);
        assert!(matches!(unscoped.resolve("Options"), TypeShape::Opaque(_)));

        let one = TypeRegistry::from_defs([&defs]).with_cpp_lookup_scopes(["one".to_owned()]);
        let TypeShape::Struct { fields, .. } = one.resolve("Options") else {
            panic!("lexical scope should resolve one::Options");
        };
        assert_eq!(fields[0].name, "one_value");

        let TypeShape::Struct { fields, .. } = unscoped.resolve("two::Options") else {
            panic!("qualified lookup should resolve exactly");
        };
        assert_eq!(fields[0].name, "two_value");
    }

    #[test]
    fn sibling_member_enums_resolve_to_their_own_members() {
        // yaml-cpp `FmtScope::value` / `GroupType::value`: two member enums with the
        // SAME bare tag. The C++ parser now records each by its fully-qualified tag
        // (scope-first), so they no longer collide in the bare-name-keyed registry
        // and a parameter typed `GroupType::value` resolves to ITS members, not the
        // first-registered enum's.
        let defs = c_parser::CTypeDefs {
            structs: Vec::new(),
            enums: vec![
                c_parser::CEnumDef {
                    name: "FmtScope::value".to_owned(),
                    members: vec!["FmtScope::Local".to_owned(), "FmtScope::Global".to_owned()],
                    line: 1,
                },
                c_parser::CEnumDef {
                    name: "GroupType::value".to_owned(),
                    members: vec!["GroupType::NoType".to_owned(), "GroupType::Flow".to_owned()],
                    line: 2,
                },
            ],
            typedefs: Vec::new(),
        };
        let reg = TypeRegistry::from_defs([&defs]);

        let TypeShape::Enum { members, .. } = reg.resolve("GroupType::value") else {
            panic!("expected enum shape for a member enum");
        };
        assert_eq!(members, vec!["GroupType::NoType", "GroupType::Flow"]);

        let TypeShape::Enum { members, .. } = reg.resolve("FmtScope::value") else {
            panic!("expected enum shape for a member enum");
        };
        assert_eq!(members, vec!["FmtScope::Local", "FmtScope::Global"]);
    }

    #[test]
    fn alias_target_spelling_resolves_namespace_qualified_leaf() {
        // csv-parser: `namespace csv { using string_view = std::string_view; }`. The
        // alias is recorded under the bare leaf `string_view`, but parameters spell
        // it `csv::string_view`. The qualified spelling must fall back to the bare
        // key (bug #16) — otherwise the string-alias redirect never fires and the
        // target is falsely skipped as opaque / no-public-constructor.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![c_parser::CTypedefDef {
                name: "string_view".to_owned(),
                underlying: "std::string_view".to_owned(),
                line: 1,
            }],
            ..Default::default()
        };
        let reg = TypeRegistry::from_defs([&defs]);
        assert_eq!(
            reg.alias_target_spelling("csv::string_view").as_deref(),
            Some("std::string_view")
        );
        // The bare leaf still resolves directly.
        assert_eq!(
            reg.alias_target_spelling("string_view").as_deref(),
            Some("std::string_view")
        );
        // A qualified name with no matching bare typedef does NOT false-resolve.
        assert_eq!(reg.alias_target_spelling("csv::DataType"), None);
        assert_eq!(reg.alias_target_spelling("std::string"), None);

        // Bundled string-view-lite: `using string_view = nonstd::string_view;`.
        let nonstd = c_parser::CTypeDefs {
            typedefs: vec![c_parser::CTypedefDef {
                name: "string_view".to_owned(),
                underlying: "nonstd::string_view".to_owned(),
                line: 1,
            }],
            ..Default::default()
        };
        let reg = TypeRegistry::from_defs([&nonstd]);
        assert_eq!(
            reg.alias_target_spelling("csv::string_view").as_deref(),
            Some("nonstd::string_view")
        );
    }

    #[test]
    fn resolves_to_incomplete_aggregate_flags_forward_declared_by_value_only() {
        // §26.4: stb shape — `stb_cfg` is a typedef whose underlying
        // `struct stb_cfg_st` is only FORWARD-declared (incomplete) in the headers
        // the harness sees. A by-value `stb_cfg R;` declaration is rejected with
        // "variable has incomplete type", so it must be flagged for a clean skip.
        let defs = c_parser::CTypeDefs {
            structs: vec![
                // Forward-declared, no body.
                c_parser::CStructDef {
                    name: "stb_cfg_st".to_owned(),
                    fields: Vec::new(),
                    line: 1,
                    complete: false,
                },
                // A fully-defined POD struct for contrast.
                c_parser::CStructDef {
                    name: "rgba".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "r".to_owned(),
                        c_type: "unsigned char".to_owned(),
                    }],
                    line: 2,
                    complete: true,
                },
            ],
            enums: Vec::new(),
            typedefs: vec![
                c_parser::CTypedefDef {
                    name: "stb_cfg".to_owned(),
                    line: 3,
                    underlying: "struct stb_cfg_st".to_owned(),
                },
                c_parser::CTypedefDef {
                    name: "stb_size".to_owned(),
                    line: 4,
                    underlying: "unsigned long".to_owned(),
                },
            ],
        };
        let reg = TypeRegistry::from_defs([&defs]);

        // By-value incomplete result type (typedef and the bare `struct` spelling).
        assert_eq!(
            reg.resolves_to_incomplete_aggregate("stb_cfg"),
            Some("struct stb_cfg_st".to_owned())
        );
        assert_eq!(
            reg.resolves_to_incomplete_aggregate("struct stb_cfg_st"),
            Some("struct stb_cfg_st".to_owned())
        );
        // A POINTER to the same incomplete type is legal — must NOT be flagged.
        assert_eq!(reg.resolves_to_incomplete_aggregate("stb_cfg *"), None);
        assert_eq!(
            reg.resolves_to_incomplete_aggregate("struct stb_cfg_st *"),
            None
        );
        // A complete struct, a scalar, a scalar typedef, `int`, `void` — all fine.
        assert_eq!(reg.resolves_to_incomplete_aggregate("struct rgba"), None);
        assert_eq!(reg.resolves_to_incomplete_aggregate("stb_size"), None);
        assert_eq!(reg.resolves_to_incomplete_aggregate("int"), None);
        assert_eq!(reg.resolves_to_incomplete_aggregate("void"), None);
        assert_eq!(reg.resolves_to_incomplete_aggregate("const char *"), None);
        // An UNMODELED type (a struct the registry never saw — it may be complete
        // in a header we did not parse) must NOT be flagged: never skip on ignorance.
        assert_eq!(
            reg.resolves_to_incomplete_aggregate("struct elsewhere"),
            None
        );
        assert_eq!(reg.resolves_to_incomplete_aggregate("unknown_t"), None);
    }
}
