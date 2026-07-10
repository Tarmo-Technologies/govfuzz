// SPDX-License-Identifier: Apache-2.0

//! Structural parser for the native Java fuzzing lane (M2.1).
//!
//! Mirrors `rust_parser`/`c_parser`/`cpp_parser`: a thin tree-sitter walk that
//! extracts the method shapes the ranker (`target_rank::java_rank`) needs to
//! score discovery candidates — name, line, params, return type, visibility,
//! static-vs-instance, the enclosing class path + package (for the call FQN),
//! whether the method is abstract (no body → not directly callable), and whether
//! it is an existing Jazzer-style `fuzzerTestOneInput` entry point.
//!
//! Like the other parsers this reasons over the signature only; it does not
//! resolve types or build a full semantic model.

/// One parameter of a Java method: the binding name and its declared type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JavaParam {
    pub name: String,
    /// Source spelling of the parameter type, e.g. `byte[]`, `String`,
    /// `java.nio.ByteBuffer`, `int`. Whitespace collapsed; a varargs `T...`
    /// is normalized to the array form `T[]`.
    pub ty: String,
}

/// Java access level. Only `Public` methods are reachable from a generated
/// harness in another package; `Protected`/`Package`/`Private` are not (the
/// ranker drops them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JavaVisibility {
    /// `public` — reachable from any package.
    Public,
    /// `protected` — subclass/same-package only.
    Protected,
    /// No access modifier — package-private.
    #[default]
    Package,
    /// `private` — declaring class only.
    Private,
}

/// A method (or constructor) extracted from one Java source file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JavaMethod {
    pub name: String,
    /// 1-based line of the method name.
    pub line: u32,
    /// Source spelling of the return type, or `None` for `void` / a constructor.
    pub return_type: Option<String>,
    pub params: Vec<JavaParam>,
    /// `true` for a `static` method — callable as `Class.method(args)` with no
    /// instance. An instance method needs a receiver the harness must construct.
    pub is_static: bool,
    pub visibility: JavaVisibility,
    /// `true` when every enclosing type up to the top level is reachable from
    /// another package (each is `public`, or an interface/annotation member). A
    /// `public` method of a package-private top-level class (jsoup `Re2jRegex`)
    /// has `visibility == Public` but `enclosing_public == false`: it cannot be
    /// referenced by FQN from the generated harness in another package, so
    /// discovery must skip it (#34). The parser still returns it so non-discovery
    /// consumers see the full method set.
    pub enclosing_public: bool,
    /// The file's `package` declaration, e.g. `com.example.parser`, or `None`
    /// for the default package.
    pub package: Option<String>,
    /// Enclosing class names, outer-most first (the last is the immediate
    /// declaring class). Source-level nesting uses `.`; binary names use `$`.
    pub class_path: Vec<String>,
    /// `true` for a constructor (`Foo(...)` with no return type).
    pub is_constructor: bool,
    /// `true` when the method has no body (an `abstract` method or a plain
    /// interface method) — not directly callable without an implementation.
    pub is_abstract: bool,
    /// `true` for a Jazzer-style `public static void fuzzerTestOneInput(...)`
    /// entry point — an existing harness, the highest-value Java discovery.
    pub is_fuzz_entry: bool,
    /// Declared checked exceptions (`throws A, B`). Used by the ranker to temper
    /// expected-exception noise.
    pub throws: Vec<String>,
}

impl JavaMethod {
    /// Fully-qualified source-form class name, e.g. `com.example.Outer.Inner`.
    pub fn fqcn(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(pkg) = &self.package {
            parts.push(pkg.clone());
        }
        parts.extend(self.class_path.iter().cloned());
        parts.join(".")
    }

    /// Binary class name (nested classes joined with `$`), e.g.
    /// `com.example.Outer$Inner` — the form a classloader / `-cp` expects.
    pub fn binary_class(&self) -> String {
        let nested = self.class_path.join("$");
        match &self.package {
            Some(pkg) if !pkg.is_empty() => format!("{pkg}.{nested}"),
            _ => nested,
        }
    }
}

/// A lightweight model of a class/enum type, enough to synthesise a *default*
/// instance for a custom-typed harness parameter (F8: e.g. `CSVParser.parse(String,
/// CSVFormat)` — a `CSVFormat` config object the harness must supply so the real
/// fuzzable `String`/`Reader` input gets driven). Built by
/// [`parse_java_type_models`] from the type's own source file; the harness
/// generator picks a construction strategy from it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JavaTypeModel {
    /// Fully-qualified source-form name, e.g. `org.apache.commons.csv.CSVFormat`.
    pub fqn: String,
    /// True when the type is an `enum` (constructed as a `values()` pick).
    pub is_enum: bool,
    /// Names of public `static final <Self>` fields — the idiomatic immutable
    /// singleton/config pattern (`CSVFormat.DEFAULT`, `EXCEL`, …), in source order.
    pub self_constants: Vec<String>,
    /// True when a public no-arg constructor is reachable: an explicit public
    /// `T()`, or the implicit public default ctor a non-abstract public class gets
    /// when it declares no constructors at all.
    pub has_public_no_arg_ctor: bool,
    /// Names of public static no-arg factory methods returning `<Self>`
    /// (e.g. `create`, `newInstance`, `getDefault`), in source order.
    pub no_arg_self_factories: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum JavaParseError {
    #[error("failed to load Java grammar")]
    Grammar,
    #[error("failed to parse Java source")]
    Parse,
}

/// Hard cap on recursive AST-walk depth (mirrors the other parsers). Guards the
/// worker stack against pathologically deep source.
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

/// Parse Java `source` and return every method/constructor it declares, each
/// carrying its enclosing class path + package so the call FQN is reconstructable.
pub fn parse_java_methods(source: &str) -> Result<Vec<JavaMethod>, JavaParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .map_err(|_| JavaParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(JavaParseError::Parse)?;
    let bytes = source.as_bytes();
    let package = find_package(tree.root_node(), bytes);
    let mut methods = Vec::new();
    collect_methods(
        tree.root_node(),
        bytes,
        &package,
        &[],
        false,
        true,
        &mut methods,
    );
    Ok(methods)
}

/// Fully-qualified names of every `enum` type declared in `source` (package +
/// enclosing class path + enum name, e.g. `com.acme.Color`, `com.acme.Outer.Mode`).
/// The harness generator uses this to recognize an enum-typed parameter and decode
/// it as a `values()` index instead of rejecting it.
pub fn parse_java_enum_types(source: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let package = find_package(tree.root_node(), bytes);
    let mut out = Vec::new();
    // Start in a publicly-accessible, non-interface context (the package level).
    collect_enum_types(
        tree.root_node(),
        bytes,
        &package,
        &[],
        true,
        false,
        &mut out,
    );
    out
}

fn collect_enum_types(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &Option<String>,
    class_path: &[String],
    public_path: bool,
    in_interface: bool,
    out: &mut Vec<String>,
) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .unwrap_or("")
                    .to_owned();
                // A type is reachable from the harness (another package) only if it
                // is `public` and every enclosing type is too. Members of an
                // interface/annotation are implicitly public.
                let mut mods = child.walk();
                let modifiers = child.children(&mut mods).find(|c| c.kind() == "modifiers");
                let (vis, _, _) = parse_modifiers(modifiers);
                let this_public = in_interface || matches!(vis, JavaVisibility::Public);
                let reachable = public_path && this_public;
                if child.kind() == "enum_declaration" && !name.is_empty() && reachable {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(pkg) = package {
                        parts.push(pkg.clone());
                    }
                    parts.extend(class_path.iter().cloned());
                    parts.push(name.clone());
                    out.push(parts.join("."));
                }
                let mut nested = class_path.to_vec();
                if !name.is_empty() {
                    nested.push(name);
                }
                let child_is_interface = matches!(
                    child.kind(),
                    "interface_declaration" | "annotation_type_declaration"
                );
                collect_enum_types(
                    child,
                    bytes,
                    package,
                    &nested,
                    reachable,
                    child_is_interface,
                    out,
                );
            }
            _ => collect_enum_types(
                child,
                bytes,
                package,
                class_path,
                public_path,
                in_interface,
                out,
            ),
        }
    }
}

/// Fully-qualified names of every type declared in `source` that CANNOT be directly
/// instantiated with `new` — an `abstract class`, an `interface`, or an `@interface`
/// annotation type (package + enclosing class path + name, e.g.
/// `org.apache.commons.validator.routines.checkdigit.ModulusCheckDigit`). The Java
/// harness/receiver builders consult this so they never emit
/// `new <AbstractOrInterface>(...)` (javac: "<T> is abstract; cannot be
/// instantiated"); such a target is skipped cleanly instead.
///
/// Enums and records are deliberately excluded: an enum is constructed as a
/// `values()` pick (see [`parse_java_enum_types`]) and a record is a concrete class.
/// Collected regardless of visibility — instantiability is independent of
/// reachability, and callers match by exact FQN.
pub fn parse_java_abstract_types(source: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let package = find_package(tree.root_node(), bytes);
    let mut out = Vec::new();
    collect_abstract_types(tree.root_node(), bytes, &package, &[], &mut out);
    out
}

fn collect_abstract_types(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &Option<String>,
    class_path: &[String],
    out: &mut Vec<String>,
) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .unwrap_or("")
                    .to_owned();
                // An interface / @interface is never `new`-able; a class is only
                // non-instantiable when declared `abstract`.
                let non_instantiable = match child.kind() {
                    "interface_declaration" | "annotation_type_declaration" => true,
                    "class_declaration" => {
                        let modifiers = child
                            .children(&mut child.walk())
                            .find(|c| c.kind() == "modifiers");
                        let (_, _, is_abstract) = parse_modifiers(modifiers);
                        is_abstract
                    }
                    _ => false,
                };
                if non_instantiable && !name.is_empty() {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(pkg) = package {
                        parts.push(pkg.clone());
                    }
                    parts.extend(class_path.iter().cloned());
                    parts.push(name.clone());
                    out.push(parts.join("."));
                }
                let mut nested = class_path.to_vec();
                if !name.is_empty() {
                    nested.push(name);
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_abstract_types(body, bytes, package, &nested, out);
                }
            }
            _ => collect_abstract_types(child, bytes, package, class_path, out),
        }
    }
}

/// Build a [`JavaTypeModel`] for every reachable (public-path) class/enum declared
/// in `source`. The CLI scans the tree for the types that appear as custom-typed
/// harness parameters and hands the matching models to the harness generator so it
/// can synthesise a default instance (F8) instead of skipping the target.
pub fn parse_java_type_models(source: &str) -> Vec<JavaTypeModel> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let package = find_package(tree.root_node(), bytes);
    let mut out = Vec::new();
    collect_type_models(
        tree.root_node(),
        bytes,
        &package,
        &[],
        true,
        false,
        &mut out,
    );
    out
}

fn collect_type_models(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &Option<String>,
    class_path: &[String],
    public_path: bool,
    in_interface: bool,
    out: &mut Vec<JavaTypeModel>,
) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .unwrap_or("")
                    .to_owned();
                let modifiers = child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "modifiers");
                let (vis, _, is_abstract) = parse_modifiers(modifiers);
                let this_public = in_interface || matches!(vis, JavaVisibility::Public);
                let reachable = public_path && this_public;
                let mut parts: Vec<String> = Vec::new();
                if let Some(pkg) = package {
                    parts.push(pkg.clone());
                }
                parts.extend(class_path.iter().cloned());
                if !name.is_empty() {
                    parts.push(name.clone());
                }
                let fqn = parts.join(".");
                let body = child.child_by_field_name("body");
                if reachable && !name.is_empty() {
                    out.push(build_type_model(
                        child.kind(),
                        &fqn,
                        &name,
                        is_abstract,
                        body,
                        bytes,
                    ));
                }
                let mut nested = class_path.to_vec();
                if !name.is_empty() {
                    nested.push(name);
                }
                let child_is_interface = matches!(
                    child.kind(),
                    "interface_declaration" | "annotation_type_declaration"
                );
                if let Some(body) = body {
                    collect_type_models(
                        body,
                        bytes,
                        package,
                        &nested,
                        reachable,
                        child_is_interface,
                        out,
                    );
                }
            }
            _ => collect_type_models(
                child,
                bytes,
                package,
                class_path,
                public_path,
                in_interface,
                out,
            ),
        }
    }
}

/// Build a model from a type declaration's own (non-nested) members. Only the
/// body's direct children are inspected so a nested type's members don't leak into
/// the enclosing model (nested types get their own model via the recursion above).
fn build_type_model(
    kind: &str,
    fqn: &str,
    name_leaf: &str,
    is_abstract: bool,
    body: Option<tree_sitter::Node<'_>>,
    bytes: &[u8],
) -> JavaTypeModel {
    let is_enum = kind == "enum_declaration";
    let mut self_constants = Vec::new();
    let mut no_arg_self_factories = Vec::new();
    let mut declared_ctor = false;
    let mut public_no_arg_ctor = false;
    if let Some(body) = body {
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            match member.kind() {
                "field_declaration" => {
                    let mods = member
                        .children(&mut member.walk())
                        .find(|c| c.kind() == "modifiers");
                    let (vis, is_static, _) = parse_modifiers(mods);
                    let is_final = mods
                        .map(|m| m.children(&mut m.walk()).any(|c| c.kind() == "final"))
                        .unwrap_or(false);
                    if matches!(vis, JavaVisibility::Public) && is_static && is_final {
                        let ty = member
                            .child_by_field_name("type")
                            .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")))
                            .unwrap_or_default();
                        if type_leaf(&ty) == name_leaf {
                            let mut dc = member.walk();
                            for d in member.children(&mut dc) {
                                if d.kind() == "variable_declarator" {
                                    if let Some(n) = d
                                        .child_by_field_name("name")
                                        .and_then(|n| n.utf8_text(bytes).ok())
                                    {
                                        self_constants.push(n.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
                "constructor_declaration" => {
                    declared_ctor = true;
                    let mods = member
                        .children(&mut member.walk())
                        .find(|c| c.kind() == "modifiers");
                    let (vis, _, _) = parse_modifiers(mods);
                    let params = member
                        .child_by_field_name("parameters")
                        .map(|p| parse_parameters(p, bytes))
                        .unwrap_or_default();
                    if matches!(vis, JavaVisibility::Public) && params.is_empty() {
                        public_no_arg_ctor = true;
                    }
                }
                "method_declaration" => {
                    let mods = member
                        .children(&mut member.walk())
                        .find(|c| c.kind() == "modifiers");
                    let (vis, is_static, _) = parse_modifiers(mods);
                    let params = member
                        .child_by_field_name("parameters")
                        .map(|p| parse_parameters(p, bytes))
                        .unwrap_or_default();
                    let rt = member
                        .child_by_field_name("type")
                        .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")))
                        .unwrap_or_default();
                    if matches!(vis, JavaVisibility::Public)
                        && is_static
                        && params.is_empty()
                        && type_leaf(&rt) == name_leaf
                    {
                        if let Some(mname) = member
                            .child_by_field_name("name")
                            .and_then(|n| n.utf8_text(bytes).ok())
                        {
                            no_arg_self_factories.push(mname.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Only a concrete (non-abstract) class is `new`-able. The implicit public
    // default ctor exists only when the class declares no constructors at all.
    let has_public_no_arg_ctor =
        kind == "class_declaration" && !is_abstract && (public_no_arg_ctor || !declared_ctor);
    JavaTypeModel {
        fqn: fqn.to_owned(),
        is_enum,
        self_constants,
        has_public_no_arg_ctor,
        no_arg_self_factories,
    }
}

/// The leaf type name with generics, array brackets, and package/nesting qualifiers
/// stripped (`java.util.List<String>[]` -> `List`).
fn type_leaf(ty: &str) -> &str {
    let t = ty.split('<').next().unwrap_or(ty).trim();
    let t = t.split('[').next().unwrap_or(t).trim();
    t.rsplit('.').next().unwrap_or(t)
}

/// Count `ERROR`/`MISSING` nodes — used by the CLI to warn "parser confused,
/// results may be incomplete". Mirrors `c_parser::count_parse_errors`.
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
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

/// The `package ...;` declaration name, if any.
fn find_package(root: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_declaration" {
            // The name is the scoped_identifier / identifier child.
            let mut inner = child.walk();
            for c in child.children(&mut inner) {
                if c.kind() == "scoped_identifier" || c.kind() == "identifier" {
                    return Some(collapse_ws(c.utf8_text(bytes).unwrap_or("")));
                }
            }
        }
    }
    None
}

/// Recursive walk collecting every method/constructor, tracking the enclosing
/// class path so each method carries its declaring type.
fn collect_methods(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &Option<String>,
    class_path: &[String],
    in_interface: bool,
    // True when every enclosing type up to the top level is reachable from another
    // package (`public`, or an interface/annotation member). A method in a
    // package-private top-level class (e.g. jsoup `class Re2jRegex`) is NOT
    // referenceable by FQN from the generated harness in its own package — javac
    // rejects it — so such methods must not be collected even when they are
    // themselves `public` (#34).
    public_path: bool,
    out: &mut Vec<JavaMethod>,
) {
    let Some(_guard) = AstDepthGuard::enter() else {
        return;
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                // Descend into the type body with the class name pushed. Interface
                // and annotation-type members are implicitly `public`.
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .unwrap_or("")
                    .to_owned();
                let mut nested = class_path.to_vec();
                if !name.is_empty() {
                    nested.push(name);
                }
                let body_is_interface = matches!(
                    child.kind(),
                    "interface_declaration" | "annotation_type_declaration"
                );
                // This type is reachable only if it is `public` (interface members
                // are implicitly public) AND every enclosing type is too.
                let mut mods = child.walk();
                let modifiers = child.children(&mut mods).find(|c| c.kind() == "modifiers");
                let (vis, _, _) = parse_modifiers(modifiers);
                let this_public = in_interface || matches!(vis, JavaVisibility::Public);
                let reachable = public_path && this_public;
                if let Some(body) = child.child_by_field_name("body") {
                    collect_methods(
                        body,
                        bytes,
                        package,
                        &nested,
                        body_is_interface,
                        reachable,
                        out,
                    );
                }
            }
            "method_declaration" | "constructor_declaration" => {
                // The parser returns every method; `enclosing_public` records
                // whether the declaring type chain is reachable so discovery can
                // skip an unreachable (package-private-class) method (#34) without
                // hiding it from non-discovery consumers.
                if let Some(m) =
                    parse_method(child, bytes, package, class_path, in_interface, public_path)
                {
                    out.push(m);
                }
            }
            // enum_body wraps method declarations in an `enum_body_declarations`;
            // class/interface bodies hold them directly. Recurse through any other
            // container to reach nested types + methods, preserving interface scope.
            _ => {
                collect_methods(
                    child,
                    bytes,
                    package,
                    class_path,
                    in_interface,
                    public_path,
                    out,
                );
            }
        }
    }
}

/// Extract a `JavaMethod` from a `method_declaration` / `constructor_declaration`.
fn parse_method(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &Option<String>,
    class_path: &[String],
    in_interface: bool,
    enclosing_public: bool,
) -> Option<JavaMethod> {
    let is_constructor = node.kind() == "constructor_declaration";
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(bytes).ok()?.to_owned();
    let line = name_node.start_position().row as u32 + 1;

    let modifiers = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "modifiers");
    let (mut visibility, is_static, is_abstract_mod) = parse_modifiers(modifiers);
    // Interface (and annotation-type) members are implicitly `public` when no
    // access modifier is written. An explicit `private` (legal since Java 9)
    // stays private.
    if in_interface && matches!(visibility, JavaVisibility::Package) {
        visibility = JavaVisibility::Public;
    }

    let return_type = if is_constructor {
        None
    } else {
        node.child_by_field_name("type").and_then(|t| {
            let txt = collapse_ws(t.utf8_text(bytes).unwrap_or(""));
            if txt == "void" || txt.is_empty() {
                None
            } else {
                Some(txt)
            }
        })
    };

    let params = node
        .child_by_field_name("parameters")
        .map(|p| parse_parameters(p, bytes))
        .unwrap_or_default();

    // No `body` field → an interface method or `abstract` method (not callable).
    // A constructor and a static/concrete method always have a body.
    let has_body = node.child_by_field_name("body").is_some();
    let is_abstract = is_abstract_mod || (!has_body && !is_constructor);

    let throws = parse_throws(node, bytes);

    let is_fuzz_entry =
        name == "fuzzerTestOneInput" && is_static && matches!(visibility, JavaVisibility::Public);

    Some(JavaMethod {
        name,
        line,
        return_type,
        params,
        is_static,
        visibility,
        enclosing_public,
        package: package.clone(),
        class_path: class_path.to_vec(),
        is_constructor,
        is_abstract,
        is_fuzz_entry,
        throws,
    })
}

/// Read access level + `static` + `abstract` out of a `modifiers` node.
fn parse_modifiers(modifiers: Option<tree_sitter::Node<'_>>) -> (JavaVisibility, bool, bool) {
    let Some(modifiers) = modifiers else {
        return (JavaVisibility::Package, false, false);
    };
    let mut visibility = JavaVisibility::Package;
    let mut is_static = false;
    let mut is_abstract = false;
    let mut cursor = modifiers.walk();
    for child in modifiers.children(&mut cursor) {
        match child.kind() {
            "public" => visibility = JavaVisibility::Public,
            "protected" => visibility = JavaVisibility::Protected,
            "private" => visibility = JavaVisibility::Private,
            "static" => is_static = true,
            "abstract" => is_abstract = true,
            _ => {
                // Annotations (`marker_annotation`/`annotation`) and other
                // modifiers (`final`, `synchronized`, …) don't affect ranking.
            }
        }
    }
    (visibility, is_static, is_abstract)
}

/// Parse a `formal_parameters` node into `(name, type)` pairs. A varargs
/// `spread_parameter` (`T... xs`) is normalized to the array type `T[]`.
fn parse_parameters(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<JavaParam> {
    let mut params = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => {
                let ty = child
                    .child_by_field_name("type")
                    .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                let name = child
                    .child_by_field_name("name")
                    .map(|n| collapse_ws(n.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                params.push(JavaParam { name, ty });
            }
            "spread_parameter" => {
                // `T... xs`: the `type` child is `T`; the binding is a
                // variable_declarator. Normalize to `T[]`.
                let ty = child
                    .children(&mut child.walk())
                    .find(|c| {
                        c.kind().ends_with("_type")
                            || c.kind() == "type_identifier"
                            || c.kind() == "scoped_type_identifier"
                            || c.kind() == "generic_type"
                            || c.kind() == "array_type"
                    })
                    .map(|t| collapse_ws(t.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                let name = child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "variable_declarator" || c.kind() == "identifier")
                    .map(|n| collapse_ws(n.utf8_text(bytes).unwrap_or("")))
                    .unwrap_or_default();
                params.push(JavaParam {
                    name,
                    ty: format!("{ty}[]"),
                });
            }
            _ => {}
        }
    }
    params
}

/// Collect the type names in a `throws` clause.
fn parse_throws(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<String> {
    let Some(throws) = node
        .children(&mut node.walk())
        .find(|c| c.kind() == "throws")
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = throws.walk();
    for child in throws.children(&mut cursor) {
        match child.kind() {
            "type_identifier" | "scoped_type_identifier" => {
                out.push(collapse_ws(child.utf8_text(bytes).unwrap_or("")));
            }
            _ => {}
        }
    }
    out
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Mine string- and number-like source literals into fuzzing-dictionary tokens
/// (magic values that gate `==`/`switch` comparisons). Mirrors the C/C++ lanes so
/// the Java lane no longer fuzzes "cold". The tree is untrusted, so the walk is
/// depth-capped ([`DICT_MAX_DEPTH`]) to avoid stack overflow.
pub fn extract_java_dictionary_tokens(source: &str) -> Result<Vec<String>, JavaParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .map_err(|_| JavaParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(JavaParseError::Parse)?;
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
/// matching layer of surrounding quotes, and raw-string `#` hashes from a
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
        let toks = extract_java_dictionary_tokens(
            "class C {\n  String m(int n) {\n    String s = \"MAGIC\";\n    if (n == 4919) { return s; }\n    return s;\n  }\n}\n",
        )
        .expect("parse");
        assert!(toks.contains(&"MAGIC".to_string()), "tokens: {toks:?}");
        assert!(toks.contains(&"4919".to_string()), "tokens: {toks:?}");
    }

    fn parse(src: &str) -> Vec<JavaMethod> {
        parse_java_methods(src).expect("parse")
    }

    fn by_name<'a>(ms: &'a [JavaMethod], name: &str) -> &'a JavaMethod {
        ms.iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("{name} not found: {ms:?}"))
    }

    #[test]
    fn parses_public_static_method_signature() {
        let ms = parse(
            "package com.example.parser;\n\
             public class Json {\n\
             public static Object parse(byte[] data) throws ParseException { return null; }\n\
             }",
        );
        let m = by_name(&ms, "parse");
        assert_eq!(m.line, 3);
        assert_eq!(m.visibility, JavaVisibility::Public);
        assert!(m.is_static);
        assert!(!m.is_abstract);
        assert!(!m.is_constructor);
        assert_eq!(m.return_type.as_deref(), Some("Object"));
        assert_eq!(m.params.len(), 1);
        assert_eq!(m.params[0].name, "data");
        assert_eq!(m.params[0].ty, "byte[]");
        assert_eq!(m.package.as_deref(), Some("com.example.parser"));
        assert_eq!(m.class_path, vec!["Json"]);
        assert_eq!(m.fqcn(), "com.example.parser.Json");
        assert_eq!(m.throws, vec!["ParseException"]);
    }

    #[test]
    fn void_return_is_none_and_visibility_defaults_package() {
        let ms = parse(
            "class C {\n\
             void run(int n) {}\n\
             }",
        );
        let m = by_name(&ms, "run");
        assert_eq!(m.return_type, None);
        assert_eq!(m.visibility, JavaVisibility::Package);
        assert!(!m.is_static);
    }

    #[test]
    fn private_and_protected_visibility() {
        let ms = parse(
            "class C {\n\
             private void secret() {}\n\
             protected int helper() { return 0; }\n\
             }",
        );
        assert_eq!(by_name(&ms, "secret").visibility, JavaVisibility::Private);
        assert_eq!(by_name(&ms, "helper").visibility, JavaVisibility::Protected);
    }

    #[test]
    fn interface_and_abstract_methods_are_abstract() {
        let ms = parse(
            "interface I {\n\
             Object decode(byte[] b);\n\
             }\n\
             abstract class A {\n\
             public abstract void go(String s);\n\
             }",
        );
        assert!(
            by_name(&ms, "decode").is_abstract,
            "no-body interface method"
        );
        assert!(by_name(&ms, "go").is_abstract, "abstract modifier");
    }

    #[test]
    fn interface_members_are_implicitly_public() {
        let ms = parse(
            "interface Codec {\n\
             Object decode(byte[] b);\n\
             default Object decodeOrNull(byte[] b) { return null; }\n\
             static Codec of() { return null; }\n\
             private void helper() {}\n\
             }",
        );
        // No modifier on an interface member -> public.
        assert_eq!(by_name(&ms, "decode").visibility, JavaVisibility::Public);
        assert_eq!(
            by_name(&ms, "decodeOrNull").visibility,
            JavaVisibility::Public
        );
        assert_eq!(by_name(&ms, "of").visibility, JavaVisibility::Public);
        // Explicit `private` interface method (Java 9+) stays private.
        assert_eq!(by_name(&ms, "helper").visibility, JavaVisibility::Private);
        // The default/static methods have bodies -> not abstract; the bare one is.
        assert!(by_name(&ms, "decode").is_abstract);
        assert!(!by_name(&ms, "decodeOrNull").is_abstract);
    }

    #[test]
    fn class_members_without_modifier_are_package_private() {
        // The interface rule must NOT bleed into classes.
        let ms = parse("class C {\nObject f(byte[] b) { return null; }\n}");
        assert_eq!(by_name(&ms, "f").visibility, JavaVisibility::Package);
    }

    #[test]
    fn nested_class_path_is_tracked() {
        let ms = parse(
            "package p;\n\
             public class Outer {\n\
             public static class Inner {\n\
             public static int f(String s) { return 0; }\n\
             }\n\
             }",
        );
        let m = by_name(&ms, "f");
        assert_eq!(m.class_path, vec!["Outer", "Inner"]);
        assert_eq!(m.fqcn(), "p.Outer.Inner");
        assert_eq!(m.binary_class(), "p.Outer$Inner");
    }

    #[test]
    fn constructor_is_flagged_with_no_return() {
        let ms = parse(
            "public class Foo {\n\
             public Foo(byte[] data) {}\n\
             }",
        );
        let m = by_name(&ms, "Foo");
        assert!(m.is_constructor);
        assert_eq!(m.return_type, None);
        assert_eq!(m.params[0].ty, "byte[]");
    }

    #[test]
    fn detects_jazzer_fuzz_entry() {
        let ms = parse(
            "import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n\
             public class Harness {\n\
             public static void fuzzerTestOneInput(byte[] data) {}\n\
             }",
        );
        let m = by_name(&ms, "fuzzerTestOneInput");
        assert!(m.is_fuzz_entry);
        assert!(m.is_static);
    }

    #[test]
    fn varargs_param_is_normalized_to_array() {
        let ms = parse(
            "class C {\n\
             public static void f(String... parts) {}\n\
             }",
        );
        let m = by_name(&ms, "f");
        assert_eq!(m.params.len(), 1);
        assert_eq!(m.params[0].ty, "String[]");
    }

    #[test]
    fn count_parse_errors_flags_broken_source() {
        assert_eq!(count_parse_errors("class C { void f() {} }"), 0);
        assert!(count_parse_errors("class C { void f( {") > 0);
    }

    #[test]
    fn parse_java_enum_types_collects_only_reachable_fqns() {
        let src = "package com.acme;\n\
                   public class Api {\n\
                   public enum Status { OK, FAIL }\n\
                   public static class Inner { public enum Mode { A, B } }\n\
                   enum PkgPrivate { Z }\n\
                   }\n\
                   public enum TopLevel { X }\n";
        let mut got = parse_java_enum_types(src);
        got.sort();
        // PkgPrivate (no modifier) is unreachable from the harness's package -> excluded.
        assert_eq!(
            got,
            vec![
                "com.acme.Api.Inner.Mode".to_owned(),
                "com.acme.Api.Status".to_owned(),
                "com.acme.TopLevel".to_owned(),
            ]
        );
        // A public enum in a package-private enclosing class is NOT reachable.
        assert!(parse_java_enum_types("class Outer { public enum E { A } }").is_empty());
        // No package -> bare name; an interface member is implicitly public.
        assert_eq!(
            parse_java_enum_types("public enum Color { R, G, B }"),
            vec!["Color".to_owned()]
        );
        assert_eq!(
            parse_java_enum_types("public interface I { enum Mode { A } }"),
            vec!["I.Mode".to_owned()]
        );
        // A package-private top-level enum is excluded.
        assert!(parse_java_enum_types("enum Hidden { A, B }").is_empty());
        assert!(parse_java_enum_types("class C { void f() {} }").is_empty());
    }

    #[test]
    fn parse_java_abstract_types_collects_abstract_classes_and_interfaces() {
        // The commons-validator shape: an `abstract class` (must never be `new`'d),
        // alongside a concrete class (instantiable) and an interface (never `new`'d).
        let src = "package org.apache.commons.validator.routines.checkdigit;\n\
                   public abstract class ModulusCheckDigit { public ModulusCheckDigit(int m){} }\n\
                   public class ISBNCheckDigit extends ModulusCheckDigit { public ISBNCheckDigit(){super(11);} }\n\
                   public interface CheckDigit { String calculate(String code); }\n";
        let mut got = parse_java_abstract_types(src);
        got.sort();
        let base = "org.apache.commons.validator.routines.checkdigit";
        assert_eq!(
            got,
            vec![
                format!("{base}.CheckDigit"),
                format!("{base}.ModulusCheckDigit"),
            ]
        );
        // A concrete record and a nested abstract/interface are handled by kind+nesting.
        let nested = "package p;\n\
                      public class Outer {\n\
                      public abstract static class Base {}\n\
                      public @interface Marker {}\n\
                      public record Pt(int x) {}\n\
                      }\n\
                      public interface Top {}\n";
        let mut got = parse_java_abstract_types(nested);
        got.sort();
        assert_eq!(
            got,
            vec![
                "p.Outer.Base".to_owned(),
                "p.Outer.Marker".to_owned(),
                "p.Top".to_owned(),
            ]
        );
        // A purely concrete tree yields nothing.
        assert!(parse_java_abstract_types("public class C { public C(){} }").is_empty());
    }

    fn model<'a>(ms: &'a [JavaTypeModel], leaf: &str) -> &'a JavaTypeModel {
        ms.iter()
            .find(|m| m.fqn.rsplit('.').next() == Some(leaf))
            .unwrap_or_else(|| panic!("{leaf} not found: {ms:?}"))
    }

    #[test]
    fn type_model_static_final_self_constants() {
        // The CSVFormat shape: a final class with `public static final CSVFormat
        // DEFAULT/EXCEL` constants and a private ctor only.
        let src = "package org.apache.commons.csv;\n\
             public final class CSVFormat {\n\
             \x20 public static final CSVFormat DEFAULT = new CSVFormat();\n\
             \x20 public static final CSVFormat EXCEL = DEFAULT;\n\
             \x20 private CSVFormat() {}\n\
             }";
        let ms = parse_java_type_models(src);
        let m = model(&ms, "CSVFormat");
        assert_eq!(m.fqn, "org.apache.commons.csv.CSVFormat");
        assert!(!m.is_enum);
        assert_eq!(m.self_constants, vec!["DEFAULT", "EXCEL"]);
        assert!(!m.has_public_no_arg_ctor, "only a private ctor");
    }

    #[test]
    fn type_model_no_arg_ctor_implicit_and_explicit() {
        // No declared ctor -> implicit public no-arg ctor.
        let ms = parse_java_type_models("public class Cfg { }");
        assert!(model(&ms, "Cfg").has_public_no_arg_ctor);
        // Explicit public no-arg ctor.
        let ms = parse_java_type_models("public class Cfg { public Cfg() {} public Cfg(int x){} }");
        assert!(model(&ms, "Cfg").has_public_no_arg_ctor);
        // Only a parameterised ctor -> not no-arg-constructible.
        let ms = parse_java_type_models("public class Cfg { public Cfg(int x){} }");
        assert!(!model(&ms, "Cfg").has_public_no_arg_ctor);
        // Abstract class is never `new`-able even with no declared ctor.
        let ms = parse_java_type_models("public abstract class Cfg { }");
        assert!(!model(&ms, "Cfg").has_public_no_arg_ctor);
    }

    #[test]
    fn type_model_static_factory_and_enum() {
        let ms = parse_java_type_models(
            "public class Cfg { private Cfg(){} public static Cfg create(){return new Cfg();} \
             public static Cfg of(int x){return null;} }",
        );
        let m = model(&ms, "Cfg");
        // No-arg self factory is recorded; the arg-taking `of` is not.
        assert_eq!(m.no_arg_self_factories, vec!["create"]);
        assert!(!m.has_public_no_arg_ctor);
        // An enum is flagged.
        let ms = parse_java_type_models("public enum Mode { A, B }");
        assert!(model(&ms, "Mode").is_enum);
    }

    #[test]
    fn type_model_skips_non_public_and_nested_members_dont_leak() {
        // A package-private type is not reachable from another package -> no model.
        assert!(parse_java_type_models("class Hidden { }").is_empty());
        // A nested public class's `static final Outer` does not become Outer's
        // constant (members are read per declaring type).
        let ms = parse_java_type_models(
            "public class Outer { public static class Inner { \
             public static final Inner I = new Inner(); } }",
        );
        assert!(model(&ms, "Outer").self_constants.is_empty());
        assert_eq!(model(&ms, "Inner").self_constants, vec!["I"]);
    }

    #[test]
    fn methods_of_package_private_top_level_class_are_not_collected() {
        // #34: a `public` method in a package-private (no `public` modifier)
        // top-level class is NOT referenceable by FQN from the generated harness in
        // another package (javac rejects it), so it must not be collected even
        // though the method itself is public — jsoup `class Re2jRegex` shape.
        // The parser still RETURNS the method (non-discovery consumers see it), but
        // marks enclosing_public=false so the ranker/discovery drops it.
        let hidden = parse_java_methods(
            "package a.b; class Re2jRegex { public static int compile(String s) { return 0; } }",
        )
        .expect("parse");
        let m = hidden
            .iter()
            .find(|m| m.name == "compile")
            .expect("method still parsed");
        assert!(
            !m.enclosing_public,
            "a method of a package-private top-level class must be marked enclosing_public=false"
        );
        // The same method in a PUBLIC class is reachable.
        let visible = parse_java_methods(
            "package a.b; public class Open { public static int compile(String s) { return 0; } }",
        )
        .expect("parse");
        assert!(
            visible
                .iter()
                .find(|m| m.name == "compile")
                .unwrap()
                .enclosing_public
        );
    }
}
