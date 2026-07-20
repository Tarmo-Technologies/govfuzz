// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{
    PackageId, StructuralAst, SubprogramKind, SubprogramOwner, TypeKind, TypeRef, Visibility,
};

/// A package's fully-qualified dotted name, built by walking its `parent` chain.
/// The parser records a NESTED package by its leaf name plus a parent link
/// (`Zip_Streams.Calendar` -> name "Calendar", parent Zip_Streams), so using the
/// leaf alone produced an unqualified, not-visible constructor call
/// (`Calendar.Time_Of` instead of `Zip_Streams.Calendar.Time_Of`). Returns "" if
/// the id is unknown (matching the prior `unwrap_or_default`).
fn qualified_package_name(ast: &StructuralAst, package_id: PackageId) -> String {
    let mut parts = Vec::new();
    let mut current = Some(package_id);
    let mut guard = 0;
    while let Some(pid) = current {
        guard += 1;
        if guard > 64 {
            break; // defensive: never loop on a malformed parent cycle
        }
        let Some(pkg) = ast.packages.iter().find(|p| p.id == pid) else {
            break;
        };
        parts.push(pkg.name.clone());
        current = pkg.parent;
    }
    parts.reverse();
    parts.join(".")
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConstructorEntry {
    pub tagged_type_name: String,
    pub constructor_name: String,
    pub qualified_path: String,
    pub param_count: u32,
    /// Type-name path for each formal parameter (joined with '.'), in declaration order.
    /// Empty entries fall back to the legacy "0" neutral.
    #[serde(default)]
    pub param_type_names: Vec<String>,
    /// Whether each formal parameter has a default expression, in declaration
    /// order. Trailing defaulted parameters (e.g. ada-toml's
    /// `Location : Source_Location := No_Location`) are omitted from synthesised
    /// calls so the decoder doesn't pass a wrong-typed neutral (`0`) for them.
    #[serde(default)]
    pub param_has_default: Vec<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConstructorRegistry {
    pub entries: Vec<ConstructorEntry>,
}

impl ConstructorRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn for_tagged_type(&self, type_name: &str) -> Vec<&ConstructorEntry> {
        let mut entries: Vec<&ConstructorEntry> = self
            .entries
            .iter()
            .filter(|entry| type_name_matches(&entry.tagged_type_name, type_name))
            .collect();
        // Parameterless constructors first - they are guaranteed to compile.
        // Within the same param_count, keep declaration order so output is
        // deterministic.
        entries.sort_by_key(|entry| entry.param_count);
        entries
    }
}

pub(crate) fn type_name_matches(entry_name: &str, lookup_name: &str) -> bool {
    if entry_name.eq_ignore_ascii_case(lookup_name) {
        return true;
    }
    // When BOTH names carry package qualification, a shared bare leaf is not
    // enough: `Util.Encoders.Base64.Decoder` and `Util.Streams.Buffered.Decoder`
    // are different types. Require a dotted-suffix relationship (one path is a
    // tail of the other on '.' boundaries) so differently-deep qualifications of
    // the *same* type still match while cross-package collisions do not.
    if entry_name.contains('.') && lookup_name.contains('.') {
        return dotted_suffix_match(entry_name, lookup_name);
    }
    // One side is unqualified (the common `use`-visible case, e.g. a parser that
    // wrote the bare `Decoder`): fall back to the bare last-segment.
    let entry_last = entry_name.rsplit('.').next().unwrap_or(entry_name);
    let lookup_last = lookup_name.rsplit('.').next().unwrap_or(lookup_name);
    entry_last.eq_ignore_ascii_case(lookup_last)
}

/// Case-insensitive dotted-suffix match: true when the shorter dotted path is a
/// tail of the longer on '.' boundaries (`Base64.Decoder` ⊑
/// `Util.Encoders.Base64.Decoder`), and false for a mere shared leaf in a
/// different package (`...Streams.Buffered.Decoder`).
fn dotted_suffix_match(a: &str, b: &str) -> bool {
    let mut matched = false;
    for (x, y) in a.rsplit('.').zip(b.rsplit('.')) {
        if !x.eq_ignore_ascii_case(y) {
            return false;
        }
        matched = true;
    }
    matched
}

fn return_type_is_user_named(return_type: &ada_parser::ast::TypeRef) -> bool {
    if return_type.name_path.is_empty() {
        return false;
    }
    if matches!(&return_type.kind, TypeKind::Scalar(_) | TypeKind::Enum(_)) {
        return false;
    }
    let last = return_type
        .name_path
        .iter()
        .flat_map(|part| part.split('.'))
        .rfind(|part| !part.is_empty());
    let Some(last) = last else {
        return false;
    };
    !matches!(
        last.to_ascii_lowercase().as_str(),
        "integer"
            | "natural"
            | "positive"
            | "boolean"
            | "float"
            | "long_float"
            | "long_long_float"
            | "short_float"
            | "string"
            | "wide_string"
            | "wide_wide_string"
            | "character"
            | "wide_character"
            | "wide_wide_character"
            | "duration"
    )
}

pub fn discover_constructors(ast: &StructuralAst) -> ConstructorRegistry {
    let mut entries = Vec::new();

    for subprogram in &ast.subprograms {
        if subprogram.kind != SubprogramKind::Function {
            continue;
        }

        if subprogram.visibility != Visibility::Public {
            continue;
        }

        let Some(return_type) = &subprogram.return_type else {
            continue;
        };

        if !return_type_is_user_named(return_type) {
            continue;
        }

        // Skip self-referential constructors: any function whose parameters
        // include the same type it returns is a "transition" function that
        // requires an existing instance to make a new one. The decoder cannot
        // bootstrap such a call from scratch, and emitting it leads to
        // type-mismatch compile errors when the neutral substitution falls
        // back to literal 0.
        if subprogram.params.iter().any(|param| {
            type_name_matches(
                &param.type_ref.name_path.join("."),
                &return_type.name_path.join("."),
            )
        }) {
            continue;
        }

        let owner_name = match &subprogram.owner {
            SubprogramOwner::Package(package_id) => qualified_package_name(ast, *package_id),
            SubprogramOwner::LibraryLevel => String::new(),
        };
        let qualified_path = if owner_name.is_empty() {
            subprogram.name.clone()
        } else {
            format!("{}.{}", owner_name, subprogram.name)
        };

        let param_type_names = subprogram
            .params
            .iter()
            .map(|param| {
                if param.type_ref.name_path.is_empty()
                    && matches!(param.type_ref.kind, TypeKind::Access { .. })
                    && !param.type_ref.constraints.0.trim().is_empty()
                {
                    format!("access {}", param.type_ref.constraints.0.trim())
                } else {
                    param.type_ref.name_path.join(".")
                }
            })
            .collect();
        let param_has_default = subprogram
            .params
            .iter()
            .map(|param| param.default.is_some())
            .collect();

        entries.push(ConstructorEntry {
            tagged_type_name: return_type.name_path.join("."),
            constructor_name: subprogram.name.clone(),
            qualified_path,
            param_count: subprogram.params.len() as u32,
            param_type_names,
            param_has_default,
        });
    }

    // A public constant of a user-named type is a parameterless "constructor":
    // for a private type with no synthesisable constructor function (zip-ada
    // `Time`, whose only function `Get_Time` needs a stream), the constant is the
    // sole externally usable value — e.g. `default_time : constant Time;` →
    // `Zip_Streams.default_time`. The same machinery covers the
    // `Null_Unbounded_String`/`No_Element`/`Empty_Map` "null value" idiom.
    for object in &ast.constants {
        if object.visibility != Visibility::Public {
            continue;
        }
        if !type_name_is_user_named(&object.type_name) {
            continue;
        }
        let owner_name = match &object.owner {
            ada_parser::ast::TypeOwner::Package(package_id) => {
                qualified_package_name(ast, *package_id)
            }
            _ => String::new(),
        };
        let qualified_path = if owner_name.is_empty() {
            object.name.clone()
        } else {
            format!("{}.{}", owner_name, object.name)
        };
        entries.push(ConstructorEntry {
            tagged_type_name: object.type_name.clone(),
            constructor_name: object.name.clone(),
            qualified_path,
            param_count: 0,
            param_type_names: Vec::new(),
            param_has_default: Vec::new(),
        });
    }

    ConstructorRegistry { entries }
}

/// Whether a type-mark string names a user-defined type (not a predefined
/// scalar/string with its own decode path). A constant of a builtin type is
/// noise — the scalar decoders already cover it — so it is not registered as a
/// constructor.
fn type_name_is_user_named(type_name: &str) -> bool {
    let last = type_name
        .rsplit('.')
        .map(str::trim)
        .find(|part| !part.is_empty());
    let Some(last) = last else {
        return false;
    };
    !matches!(
        last.to_ascii_lowercase().as_str(),
        "integer"
            | "natural"
            | "positive"
            | "boolean"
            | "float"
            | "long_float"
            | "long_long_float"
            | "short_float"
            | "string"
            | "wide_string"
            | "wide_wide_string"
            | "character"
            | "wide_character"
            | "wide_wide_character"
            | "duration"
    )
}

/// #457: an Ada access-type opaque-handle lifecycle — the Init/Create subprogram
/// that allocates a handle and the Delete/Free subprogram that releases it, keyed
/// by the access type's name. The Ada analog of the C `CHandleLifecycle`; the
/// harness emits `H := Init; target (H, ..); Delete (H);` (a setup/call/cleanup
/// sequence) instead of passing a null access value (the access decoder's prior
/// behaviour).
#[derive(Debug, Clone, PartialEq)]
pub struct AdaAccessLifecycle {
    /// The access type's name as written on the lifecycle subprogram
    /// (`Memory_Zipstream_Access`).
    pub access_type: String,
    /// The designated base type the access points to (`Memory_Zipstream`), parsed
    /// from the access declaration's `access [all|constant] X` text. Lets an Init
    /// keyed on the BASE type pair with a target parameter spelled with a different
    /// access ALIAS to the same base (`Zipstream_Class_Access`). `None` when the
    /// designated mark could not be recovered.
    pub designated_base: Option<String>,
    /// Qualified name of the discovered initializer (`Widgets.Create`), if any.
    pub init: Option<String>,
    /// Whether `init` is a FUNCTION that returns the handle (`function Create
    /// return T_Access`, emitted as `H := Create;`) versus a PROCEDURE that fills
    /// an out-parameter handle (`procedure Init (H : out T_Access)`, emitted as
    /// `Init (H);`).
    pub init_returns_handle: bool,
    /// Formal-parameter count of `init` — used to keep the emission to the
    /// synthesizable shapes (a nullary returning constructor, or a one-parameter
    /// out-handle initializer) rather than guessing config arguments.
    pub init_param_count: usize,
    /// Qualified name of the discovered destructor (`Widgets.Destroy`), if any.
    pub delete: Option<String>,
    /// Formal-parameter count of `delete` (the one-handle `Free (H)` shape is 1).
    pub delete_param_count: usize,
}

#[derive(Clone)]
struct RoleInfo {
    qualified: String,
    designated_base: Option<String>,
    returns_handle: bool,
    param_count: usize,
}

/// Discover access-type init/delete pairs in `ast`: a public subprogram named like
/// an initializer (Init/Create/Allocate/Open/Make) that takes or returns an access
/// type is its constructor; one named like a destructor (Free/Delete/Finalize/
/// Close/Destroy/Release/Deallocate) taking that access type is its destructor.
/// Keyed by the access type's name. The first match of each role per type wins.
pub fn discover_access_lifecycles(ast: &StructuralAst) -> Vec<AdaAccessLifecycle> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut inits: BTreeMap<String, RoleInfo> = BTreeMap::new();
    let mut deletes: BTreeMap<String, RoleInfo> = BTreeMap::new();

    for sub in &ast.subprograms {
        if sub.visibility != Visibility::Public || sub.is_generic {
            continue;
        }
        let Some((access_type, designated_base, returns_handle)) = access_role(ast, sub) else {
            continue;
        };
        let info = RoleInfo {
            qualified: qualified_subprogram_path(ast, sub),
            designated_base,
            returns_handle,
            param_count: sub.params.len(),
        };
        if is_ada_lifecycle_init(&sub.name) {
            inits.entry(access_type).or_insert(info);
        } else if is_ada_lifecycle_delete(&sub.name) {
            deletes.entry(access_type).or_insert(info);
        }
    }

    let mut types: BTreeSet<String> = BTreeSet::new();
    types.extend(inits.keys().cloned());
    types.extend(deletes.keys().cloned());
    types
        .into_iter()
        .map(|access_type| {
            let init = inits.get(&access_type);
            let delete = deletes.get(&access_type);
            // Prefer the init's designated base (the constructor is the load-bearing
            // pairing), falling back to the destructor's when only it carries one.
            let designated_base = init
                .and_then(|i| i.designated_base.clone())
                .or_else(|| delete.and_then(|d| d.designated_base.clone()));
            AdaAccessLifecycle {
                designated_base,
                init: init.map(|i| i.qualified.clone()),
                init_returns_handle: init.map(|i| i.returns_handle).unwrap_or(false),
                init_param_count: init.map(|i| i.param_count).unwrap_or(0),
                delete: delete.map(|d| d.qualified.clone()),
                delete_param_count: delete.map(|d| d.param_count).unwrap_or(0),
                access_type,
            }
        })
        .collect()
}

/// The access type a subprogram operates on, plus its designated base and whether
/// the subprogram RETURNS the handle. A function whose result is an access type
/// (`function Create return T_Access`) is keyed by that return type and reported as
/// returns-handle; otherwise the first access-typed parameter (the common `Free (H
/// : in out T_Access)` / `Init (H : out T_Access)`) is used. `None` when the
/// subprogram neither returns nor takes an access type.
fn access_role(
    ast: &StructuralAst,
    sub: &ada_parser::ast::Subprogram,
) -> Option<(String, Option<String>, bool)> {
    if let Some(r) = sub.return_type.as_ref() {
        if let Some(base) = access_designated_base(ast, r) {
            return Some((r.name_path.join("."), base, true));
        }
    }
    for p in &sub.params {
        if let Some(base) = access_designated_base(ast, &p.type_ref) {
            return Some((p.type_ref.name_path.join("."), base, false));
        }
    }
    None
}

/// When `type_ref` is (or names) an access type, the designated base it points to
/// (`Some(Some("Context"))` / `Some(None)` when the mark is unrecoverable); `None`
/// when it is not an access type at all. A subprogram's return/parameter type is
/// often left as an unresolved named type by the structural parser, so resolve it
/// against the tree's `is access` declarations by leaf name — the same lookup the
/// harness generator's `find_access_type_decl` performs.
fn access_designated_base(ast: &StructuralAst, type_ref: &TypeRef) -> Option<Option<String>> {
    if matches!(type_ref.kind, TypeKind::Access { .. }) {
        return Some(ada_designated_base(&type_ref.constraints.0));
    }
    let leaf = type_ref.name_path.last()?.rsplit('.').next()?.trim();
    if leaf.is_empty() {
        return None;
    }
    let decl = ast.types.iter().find(|t| {
        t.name_path
            .last()
            .is_some_and(|n| n.eq_ignore_ascii_case(leaf))
            && matches!(t.kind, TypeKind::Access { .. })
    })?;
    Some(ada_designated_base(&decl.constraints.0))
}

/// The designated subtype mark of an access declaration, parsed from the parser's
/// constraint text (`access [all|constant|not null] X [(...)]` is stored with the
/// leading `access` removed). Returns the dotted mark (`Memory_Zipstream`) or
/// `None` when there is no recoverable designated name.
fn ada_designated_base(constraints: &str) -> Option<String> {
    let mut rest = constraints.trim();
    for prefix in [
        "all ",
        "constant ",
        "not null ",
        "All ",
        "Constant ",
        "Not null ",
    ] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped.trim();
        }
    }
    let mark = rest
        .split(['(', ' ', '\t', '\n'])
        .next()
        .unwrap_or("")
        .trim();
    if mark.is_empty() || mark.eq_ignore_ascii_case("access") {
        return None;
    }
    Some(mark.to_owned())
}

fn qualified_subprogram_path(ast: &StructuralAst, sub: &ada_parser::ast::Subprogram) -> String {
    let owner = match &sub.owner {
        SubprogramOwner::Package(pid) => qualified_package_name(ast, *pid),
        SubprogramOwner::LibraryLevel => String::new(),
    };
    if owner.is_empty() {
        sub.name.clone()
    } else {
        format!("{owner}.{}", sub.name)
    }
}

/// Lowercase `_`-separated tokens of an Ada identifier (`Memory_Zipstream_Init`
/// -> `["memory","zipstream","init"]`), so lifecycle needles match whole words.
fn ada_name_tokens(name: &str) -> Vec<String> {
    name.split('_')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Whether an Ada subprogram name reads like a handle initializer/constructor.
pub fn is_ada_lifecycle_init(name: &str) -> bool {
    let tokens = ada_name_tokens(name);
    [
        "init",
        "initialize",
        "create",
        "allocate",
        "alloc",
        "open",
        "make",
    ]
    .iter()
    .any(|needle| tokens.iter().any(|t| t == needle))
}

/// Whether an Ada subprogram name reads like a handle destructor/finalizer.
pub fn is_ada_lifecycle_delete(name: &str) -> bool {
    [
        "free",
        "delete",
        "destroy",
        "finalize",
        "close",
        "release",
        "dispose",
        "deallocate",
    ]
    .iter()
    .any(|needle| ada_name_tokens(name).iter().any(|t| t == needle))
}

#[cfg(test)]
mod tests {
    use super::{
        discover_access_lifecycles, discover_constructors, is_ada_lifecycle_delete,
        is_ada_lifecycle_init, ConstructorEntry, ConstructorRegistry,
    };
    use ada_parser::ast::{
        Aspects, ConstantDecl, Constraints, Package, PackageId, ParamMode, Parameter, ScalarKind,
        Span, StructuralAst, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner, TypeId,
        TypeKind, TypeOwner, TypeRef, Visibility,
    };

    fn span() -> Span {
        Span::new(0, 10, 1, 1)
    }

    fn type_ref(name: &str, kind: TypeKind) -> TypeRef {
        TypeRef {
            id: TypeId(1),
            name_path: name.split('.').map(str::to_owned).collect(),
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        }
    }

    fn param(name: &str) -> Parameter {
        Parameter {
            name: name.to_owned(),
            mode: ParamMode::In,
            type_ref: type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer)),
            default: None,
        }
    }

    fn package(id: u32, name: &str) -> Package {
        Package {
            id: PackageId(id),
            name: name.to_owned(),
            parent: None,
            is_generic: false,
            formals: Vec::new(),
            decls: Vec::new(),
            is_private: false,
        }
    }

    fn subprogram(
        id: u32,
        owner: SubprogramOwner,
        name: &str,
        kind: SubprogramKind,
        return_type: Option<TypeRef>,
        params: Vec<Parameter>,
    ) -> Subprogram {
        Subprogram {
            id: SubprogramId(id),
            owner,
            name: name.to_owned(),
            kind,
            params,
            return_type,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: Some(span()),
            decl_span: span(),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        }
    }

    #[test]
    fn discover_access_lifecycles_pairs_init_and_delete() {
        // zip-ada idiom: a Memory_Zipstream_Access handle with Create + Free; a
        // non-lifecycle subprogram on the same access type is ignored.
        let access = || {
            let mut tr = type_ref(
                "Memory_Zipstream_Access",
                TypeKind::Access { target: TypeId(9) },
            );
            tr.constraints = Constraints("all Memory_Zipstream".to_owned());
            tr
        };
        let acc_param = || Parameter {
            name: "H".to_owned(),
            mode: ParamMode::In,
            type_ref: access(),
            default: None,
        };
        let ast = StructuralAst {
            subprograms: vec![
                subprogram(
                    1,
                    SubprogramOwner::LibraryLevel,
                    "Create",
                    SubprogramKind::Function,
                    Some(access()),
                    Vec::new(),
                ),
                subprogram(
                    2,
                    SubprogramOwner::LibraryLevel,
                    "Free",
                    SubprogramKind::Procedure,
                    None,
                    vec![acc_param()],
                ),
                subprogram(
                    3,
                    SubprogramOwner::LibraryLevel,
                    "Process",
                    SubprogramKind::Procedure,
                    None,
                    vec![acc_param()],
                ),
            ],
            ..StructuralAst::new()
        };

        let lcs = discover_access_lifecycles(&ast);
        assert_eq!(lcs.len(), 1, "{lcs:?}");
        assert_eq!(lcs[0].access_type, "Memory_Zipstream_Access");
        assert_eq!(lcs[0].init.as_deref(), Some("Create"));
        assert_eq!(lcs[0].delete.as_deref(), Some("Free"));
        // #457 emission metadata: Create is a nullary returning constructor; Free
        // is a one-handle destructor; the designated base resolves for cross-alias
        // pairing.
        assert!(lcs[0].init_returns_handle);
        assert_eq!(lcs[0].init_param_count, 0);
        assert_eq!(lcs[0].delete_param_count, 1);
        assert_eq!(lcs[0].designated_base.as_deref(), Some("Memory_Zipstream"));
    }

    #[test]
    fn discover_access_lifecycles_records_out_param_initializer_shape() {
        // A procedure initializer (`Init (H : out T_Access)`) is reported as
        // NOT returns-handle with a single formal — the emission then writes
        // `Init (H);` rather than `H := Init;`.
        let access = || {
            let mut tr = type_ref("Handle_Access", TypeKind::Access { target: TypeId(9) });
            tr.constraints = Constraints("Handle_Record".to_owned());
            tr
        };
        let acc_param = || Parameter {
            name: "H".to_owned(),
            mode: ParamMode::Out,
            type_ref: access(),
            default: None,
        };
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Initialize",
                SubprogramKind::Procedure,
                None,
                vec![acc_param()],
            )],
            ..StructuralAst::new()
        };

        let lcs = discover_access_lifecycles(&ast);
        assert_eq!(lcs.len(), 1, "{lcs:?}");
        assert_eq!(lcs[0].init.as_deref(), Some("Initialize"));
        assert!(!lcs[0].init_returns_handle);
        assert_eq!(lcs[0].init_param_count, 1);
        assert_eq!(lcs[0].designated_base.as_deref(), Some("Handle_Record"));
    }

    #[test]
    fn ada_lifecycle_name_patterns_match_whole_tokens() {
        assert!(is_ada_lifecycle_init("Memory_Zipstream_Init"));
        assert!(is_ada_lifecycle_init("Create"));
        assert!(!is_ada_lifecycle_init("Process"));
        assert!(is_ada_lifecycle_delete("Free"));
        assert!(is_ada_lifecycle_delete("Finalize_Stream"));
        assert!(!is_ada_lifecycle_delete("Read"));
    }

    #[test]
    fn discover_constructors_finds_function_returning_tagged_type() {
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Make_Root",
                SubprogramKind::Function,
                Some(type_ref(
                    "Root.Root_Type",
                    TypeKind::Tagged {
                        base: TypeId(0),
                        is_abstract: false,
                    },
                )),
                vec![param("Seed")],
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert_eq!(
            registry.entries,
            vec![ConstructorEntry {
                tagged_type_name: "Root.Root_Type".to_owned(),
                constructor_name: "Make_Root".to_owned(),
                qualified_path: "Make_Root".to_owned(),
                param_count: 1,
                param_type_names: vec!["Integer".to_owned()],
                param_has_default: vec![false],
            }]
        );
    }

    #[test]
    fn discover_constructors_skips_procedures() {
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Make_Root",
                SubprogramKind::Procedure,
                Some(type_ref(
                    "Root_Type",
                    TypeKind::Tagged {
                        base: TypeId(0),
                        is_abstract: false,
                    },
                )),
                Vec::new(),
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert!(registry.entries.is_empty());
    }

    #[test]
    fn discover_constructors_skips_functions_returning_scalar() {
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Make_Int",
                SubprogramKind::Function,
                Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
                Vec::new(),
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert!(registry.entries.is_empty());
    }

    #[test]
    fn discover_constructors_resolves_owner_package_name() {
        let ast = StructuralAst {
            packages: vec![package(7, "Factories")],
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::Package(PackageId(7)),
                "Make_Root",
                SubprogramKind::Function,
                Some(type_ref(
                    "Root_Type",
                    TypeKind::Tagged {
                        base: TypeId(0),
                        is_abstract: false,
                    },
                )),
                Vec::new(),
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert_eq!(registry.entries[0].qualified_path, "Factories.Make_Root");
    }

    #[test]
    fn discover_constructors_handles_library_level_function() {
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Make_Root",
                SubprogramKind::Function,
                Some(type_ref(
                    "Root_Type",
                    TypeKind::Tagged {
                        base: TypeId(0),
                        is_abstract: false,
                    },
                )),
                Vec::new(),
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert_eq!(registry.entries[0].qualified_path, "Make_Root");
    }

    #[test]
    fn constructor_registry_new_starts_empty() {
        let registry = ConstructorRegistry::new();

        assert!(registry.entries.is_empty());
    }

    #[test]
    fn for_tagged_type_filters_by_type_name() {
        let registry = ConstructorRegistry {
            entries: vec![
                ConstructorEntry {
                    tagged_type_name: "Root_Type".to_owned(),
                    constructor_name: "Make_Root".to_owned(),
                    qualified_path: "Make_Root".to_owned(),
                    param_count: 0,
                    param_type_names: Vec::new(),
                    param_has_default: Vec::new(),
                },
                ConstructorEntry {
                    tagged_type_name: "Other_Type".to_owned(),
                    constructor_name: "Make_Other".to_owned(),
                    qualified_path: "Make_Other".to_owned(),
                    param_count: 0,
                    param_type_names: Vec::new(),
                    param_has_default: Vec::new(),
                },
            ],
        };

        let constructors = registry.for_tagged_type("Root_Type");

        assert_eq!(constructors.len(), 1);
        assert_eq!(constructors[0].constructor_name, "Make_Root");
    }

    #[test]
    fn for_tagged_type_matches_case_insensitively_for_parsed_lowercased_names() {
        let registry = ConstructorRegistry {
            entries: vec![ConstructorEntry {
                tagged_type_name: "public_key".to_owned(),
                constructor_name: "Construct".to_owned(),
                qualified_path: "Sparknacl.Cryptobox.Construct".to_owned(),
                param_count: 1,
                param_type_names: vec!["Bytes_32".to_owned()],
                param_has_default: Vec::new(),
            }],
        };

        assert_eq!(registry.for_tagged_type("Public_Key").len(), 1);
        assert_eq!(registry.for_tagged_type("public_key").len(), 1);
        assert_eq!(
            registry
                .for_tagged_type("Sparknacl.Cryptobox.Public_Key")
                .len(),
            1
        );
    }

    #[test]
    fn for_tagged_type_does_not_cross_match_same_leaf_in_different_packages() {
        // ada-util: a setter whose receiver is Util.Streams.Buffered.Decoder must
        // NOT bind Util.Encoders.Base64's Create (which yields a different
        // Decoder). Both types' last segment is "Decoder"; the bare-last-segment
        // fallback over-matched across packages and bound the wrong constructor.
        let registry = ConstructorRegistry {
            entries: vec![ConstructorEntry {
                tagged_type_name: "Util.Encoders.Base64.Decoder".to_owned(),
                constructor_name: "Create".to_owned(),
                qualified_path: "Util.Encoders.Base64.Create".to_owned(),
                param_count: 0,
                param_type_names: Vec::new(),
                param_has_default: Vec::new(),
            }],
        };

        // A different fully-qualified Decoder must not match.
        assert!(registry
            .for_tagged_type("Util.Streams.Buffered.Decoder")
            .is_empty());
        // The same fully-qualified type still matches.
        assert_eq!(
            registry
                .for_tagged_type("Util.Encoders.Base64.Decoder")
                .len(),
            1
        );
        // A partially-qualified suffix (same type, fewer packages) still matches.
        assert_eq!(registry.for_tagged_type("Base64.Decoder").len(), 1);
        // A bare leaf (use-visible, unqualified) still matches.
        assert_eq!(registry.for_tagged_type("Decoder").len(), 1);
    }

    #[test]
    fn discover_constructors_finds_function_returning_private_type() {
        let ast = StructuralAst {
            packages: vec![package(3, "sparknacl.cryptobox")],
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::Package(PackageId(3)),
                "Construct",
                SubprogramKind::Function,
                Some(type_ref("public_key", TypeKind::Private)),
                vec![param("K")],
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].qualified_path,
            "sparknacl.cryptobox.Construct"
        );
        assert_eq!(registry.entries[0].tagged_type_name, "public_key");
    }

    #[test]
    fn discover_constructor_preserves_anonymous_callback_profile() {
        let mut callback = type_ref("", TypeKind::Access { target: TypeId(0) });
        callback.name_path.clear();
        callback.constraints =
            Constraints("procedure (Item : out String; Last : out Natural)".to_owned());
        let ast = StructuralAst {
            packages: vec![package(3, "YAML")],
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::Package(PackageId(3)),
                "Create",
                SubprogramKind::Function,
                Some(type_ref("Parser", TypeKind::Private)),
                vec![Parameter {
                    name: "Input".to_owned(),
                    mode: ParamMode::AccessMode,
                    type_ref: callback,
                    default: None,
                }],
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert_eq!(
            registry.entries[0].param_type_names,
            vec!["access procedure (Item : out String; Last : out Natural)"]
        );
    }

    #[test]
    fn discover_constructors_qualifies_nested_package_name() {
        // zip-ada Zip_Streams.Calendar.Time_Of: a ctor in a NESTED package must be
        // called by its FULL path, not the bare leaf `Calendar.Time_Of` (which is
        // not visible -> "Calendar is not visible" and a failed build).
        let mut calendar = package(2, "Calendar");
        calendar.parent = Some(PackageId(1));
        let ast = StructuralAst {
            packages: vec![package(1, "Zip_Streams"), calendar],
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::Package(PackageId(2)),
                "Time_Of",
                SubprogramKind::Function,
                Some(type_ref("Time", TypeKind::Private)),
                vec![param("Year")],
            )],
            ..StructuralAst::new()
        };
        let registry = discover_constructors(&ast);
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].qualified_path,
            "Zip_Streams.Calendar.Time_Of"
        );
    }

    #[test]
    fn discover_constructors_skips_non_public_visibility() {
        let mut sub = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Make_Root",
            SubprogramKind::Function,
            Some(type_ref(
                "Root_Type",
                TypeKind::Tagged {
                    base: TypeId(0),
                    is_abstract: false,
                },
            )),
            Vec::new(),
        );
        sub.visibility = Visibility::Private;
        let ast = StructuralAst {
            subprograms: vec![sub],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert!(registry.entries.is_empty());
    }

    fn constant(
        name: &str,
        type_name: &str,
        owner: TypeOwner,
        visibility: Visibility,
    ) -> ConstantDecl {
        ConstantDecl {
            name: name.to_owned(),
            type_name: type_name.to_owned(),
            owner,
            visibility,
            span: span(),
        }
    }

    #[test]
    fn discover_constructors_registers_public_constant_as_nullary_constructor() {
        // zip-ada `default_time : constant Time;` in Zip_Streams' public part is
        // the only externally usable way to obtain a Time value: the type is
        // private with no public constructor function whose parameters can be
        // synthesised (Get_Time needs a stream). Register the constant as a
        // parameterless constructor so the private-type decoder can use it.
        let ast = StructuralAst {
            packages: vec![package(2, "Zip_Streams")],
            constants: vec![constant(
                "default_time",
                "Time",
                TypeOwner::Package(PackageId(2)),
                Visibility::Public,
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        let time_ctors = registry.for_tagged_type("Time");
        assert_eq!(time_ctors.len(), 1);
        assert_eq!(time_ctors[0].qualified_path, "Zip_Streams.default_time");
        assert_eq!(time_ctors[0].tagged_type_name, "Time");
        assert_eq!(time_ctors[0].param_count, 0);
        assert!(time_ctors[0].param_type_names.is_empty());
    }

    #[test]
    fn discover_constructors_skips_constant_of_builtin_scalar_type() {
        // `Buffer_Size : constant Integer := 4096;` already has a neutral via the
        // scalar decode path; registering it as a constructor would be noise.
        let ast = StructuralAst {
            packages: vec![package(2, "Config")],
            constants: vec![constant(
                "Buffer_Size",
                "Integer",
                TypeOwner::Package(PackageId(2)),
                Visibility::Public,
            )],
            ..StructuralAst::new()
        };

        assert!(discover_constructors(&ast).entries.is_empty());
    }

    #[test]
    fn discover_constructors_skips_private_part_constant() {
        // A constant declared in the package's private part is not externally
        // visible, so it cannot back a neutral in a generated harness.
        let ast = StructuralAst {
            packages: vec![package(2, "Zip_Streams")],
            constants: vec![constant(
                "internal_default",
                "Time",
                TypeOwner::Package(PackageId(2)),
                Visibility::Private,
            )],
            ..StructuralAst::new()
        };

        assert!(discover_constructors(&ast).entries.is_empty());
    }

    #[test]
    fn discover_constructors_skips_functions_returning_builtin_string() {
        let ast = StructuralAst {
            subprograms: vec![subprogram(
                1,
                SubprogramOwner::LibraryLevel,
                "Serialize",
                SubprogramKind::Function,
                Some(type_ref("String", TypeKind::Unknown)),
                Vec::new(),
            )],
            ..StructuralAst::new()
        };

        let registry = discover_constructors(&ast);

        assert!(registry.entries.is_empty());
    }
}
