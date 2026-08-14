// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Attribute, Const, ConstValue, Declaration, Enum, Exception, Field, IdlFile, IdlPragma,
    IdlPragmaKind, Interface, InterfaceMember, Module, Operation, Param, ParamDirection,
    PrimitiveType, ScopedName, Struct, TypeRef, Typedef,
};
use crate::literal::decode_idl_literal;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAdaUnit {
    pub package_name: String,
    pub relative_path: PathBuf,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaEmitOutput {
    pub units: Vec<GeneratedAdaUnit>,
    pub warnings: Vec<String>,
}

pub fn emit_ada_packages(idl: &IdlFile) -> AdaEmitOutput {
    let mut emitter = Emitter::default();
    let declarations = merge_reopened_modules(&idl.declarations);
    emitter.root_package = root_package_name(&declarations);
    let declarations = qualify_named_types(&declarations, emitter.root_package.as_deref());
    emitter.warnings.extend(idl.warnings.iter().cloned());
    emitter.version_pragmas = collect_version_pragmas(&declarations);
    emitter.collect_sequences(&declarations);
    emitter.walk_declarations(&declarations, &[], &[], &PragmaState::default());
    emitter.emit_root_package(&declarations, &PragmaState::default());
    emitter.emit_sequence_units();
    emitter.units.sort_by(|left, right| {
        left.package_name
            .cmp(&right.package_name)
            .then_with(|| is_body_unit(left).cmp(&is_body_unit(right)))
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    AdaEmitOutput {
        units: emitter.units,
        warnings: emitter.warnings,
    }
}

fn merge_reopened_modules(declarations: &[Declaration]) -> Vec<Declaration> {
    merge_reopened_modules_in_scope(declarations, None)
}

/// Preferred name for the package holding the IDL global scope.
const ROOT_PACKAGE_NAME: &str = "IDL_Global";

/// Whether a declaration belongs in the global-scope package. Modules and
/// interfaces bring their own packages; everything else is a declaration that
/// needs one.
fn goes_in_root_package(declaration: &Declaration) -> bool {
    !matches!(
        declaration,
        Declaration::Pragma(_) | Declaration::Module(_) | Declaration::Interface(_)
    )
}

/// The package name for the global scope, or `None` when the file declares
/// nothing outside a module. Ada identifiers are case-insensitive, so the name
/// is stepped until it cannot collide with a module or interface package.
fn root_package_name(declarations: &[Declaration]) -> Option<String> {
    if !declarations.iter().any(goes_in_root_package) {
        return None;
    }
    let taken = declarations
        .iter()
        .filter_map(|declaration| match declaration {
            Declaration::Module(module) => Some(ada_identifier(&module.name)),
            Declaration::Interface(interface) => Some(ada_identifier(&interface.name)),
            _ => None,
        })
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut candidate = ROOT_PACKAGE_NAME.to_owned();
    let mut suffix = 2_u32;
    while taken.contains(&candidate.to_ascii_lowercase()) {
        candidate = format!("{ROOT_PACKAGE_NAME}_{suffix}");
        suffix += 1;
    }
    Some(candidate)
}

/// Rewrite every `TypeRef::Named` into its fully qualified form.
///
/// A named type is rendered by joining its parts with `.`, and its `with`
/// clauses come from everything but the last part. A single-part name — the
/// normal way to name a sibling type — therefore rendered as a bare `Reading`
/// with no context clause. That is undefined inside the standalone
/// `Sequence_Of_Reading` package, and inside its own package it collides with a
/// record component of the same name, because Ada identifiers are
/// case-insensitive and `Name name;` is one identifier used twice.
fn qualify_named_types(
    declarations: &[Declaration],
    root_package: Option<&str>,
) -> Vec<Declaration> {
    let mut index = BTreeMap::new();
    index_declared_types(declarations, &[], root_package, &mut index);
    let mut qualified = declarations.to_vec();
    qualify_declarations(&mut qualified, &[], &index);
    qualified
}

fn index_declared_types(
    declarations: &[Declaration],
    scope: &[String],
    root_package: Option<&str>,
    index: &mut BTreeMap<String, Vec<String>>,
) {
    for declaration in declarations {
        let Some(name) = declaration_name(declaration) else {
            continue;
        };
        let mut path = scope.to_vec();
        path.push(name.to_owned());
        if let Declaration::Module(module) = declaration {
            index_declared_types(&module.declarations, &path, root_package, index);
            continue;
        }
        if matches!(declaration, Declaration::Const(_)) {
            continue;
        }
        // A global-scope declaration is emitted inside the root package, so its
        // Ada path carries that prefix even though its IDL path does not.
        let mut ada_path = path.clone();
        if scope.is_empty() && goes_in_root_package(declaration) {
            if let Some(root_package) = root_package {
                ada_path.insert(0, root_package.to_owned());
            }
        }
        index.insert(path.join("::"), ada_path);
    }
}

fn qualify_declarations(
    declarations: &mut [Declaration],
    scope: &[String],
    index: &BTreeMap<String, Vec<String>>,
) {
    for declaration in declarations {
        match declaration {
            Declaration::Module(module) => {
                let mut inner = scope.to_vec();
                inner.push(module.name.clone());
                qualify_declarations(&mut module.declarations, &inner, index);
            }
            Declaration::Interface(interface) => {
                let mut inner = scope.to_vec();
                inner.push(interface.name.clone());
                for member in &mut interface.members {
                    match member {
                        InterfaceMember::Operation(operation) => {
                            qualify_type(&mut operation.return_type, &inner, index);
                            for param in &mut operation.params {
                                qualify_type(&mut param.ty, &inner, index);
                            }
                        }
                        InterfaceMember::Attribute(attribute) => {
                            qualify_type(&mut attribute.ty, &inner, index);
                        }
                    }
                }
            }
            Declaration::Struct(struct_decl) => {
                for field in &mut struct_decl.fields {
                    qualify_type(&mut field.ty, scope, index);
                }
            }
            Declaration::Exception(exception) => {
                for field in &mut exception.fields {
                    qualify_type(&mut field.ty, scope, index);
                }
            }
            Declaration::Union(union_decl) => {
                qualify_type(&mut union_decl.discriminator, scope, index);
                for arm in &mut union_decl.arms {
                    qualify_type(&mut arm.field.ty, scope, index);
                }
            }
            Declaration::Typedef(typedef) => qualify_type(&mut typedef.ty, scope, index),
            Declaration::Const(const_decl) => qualify_type(&mut const_decl.ty, scope, index),
            Declaration::Pragma(_)
            | Declaration::Enum(_)
            | Declaration::ValueType(_)
            | Declaration::EventType(_) => {}
        }
    }
}

fn qualify_type(ty: &mut TypeRef, scope: &[String], index: &BTreeMap<String, Vec<String>>) {
    match ty {
        TypeRef::Named(name) => {
            if let Some(path) = resolve_declared_type(name, scope, index) {
                *name = ScopedName {
                    absolute: false,
                    parts: path,
                };
            }
        }
        TypeRef::Sequence { element, .. } | TypeRef::Array { element, .. } => {
            qualify_type(element, scope, index);
        }
        TypeRef::Map { key, value, .. } => {
            qualify_type(key, scope, index);
            qualify_type(value, scope, index);
        }
        TypeRef::Void | TypeRef::Primitive(_) | TypeRef::String { .. } | TypeRef::Fixed { .. } => {}
    }
}

/// Resolve a type name the way IDL does: innermost enclosing scope outwards.
/// An unresolved name is left alone — it names a type from an `#include` this
/// run could not read, and inventing a scope for it would be worse.
fn resolve_declared_type(
    name: &ScopedName,
    scope: &[String],
    index: &BTreeMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let suffix = name.parts.join("::");
    if name.absolute {
        return index.get(&suffix).cloned();
    }
    for depth in (0..=scope.len()).rev() {
        let mut key = scope[..depth].join("::");
        if !key.is_empty() {
            key.push_str("::");
        }
        key.push_str(&suffix);
        if let Some(path) = index.get(&key) {
            return Some(path.clone());
        }
    }
    None
}

fn merge_reopened_modules_in_scope(
    declarations: &[Declaration],
    initial_prefix: Option<String>,
) -> Vec<Declaration> {
    let mut merged = Vec::new();
    let mut active_prefix = initial_prefix;
    for declaration in declarations {
        match declaration {
            Declaration::Pragma(pragma) => {
                if let IdlPragmaKind::Prefix(prefix) = &pragma.kind {
                    active_prefix = Some(prefix.clone());
                }
                merged.push(declaration.clone());
            }
            Declaration::Module(module) => {
                let mut declarations =
                    merge_reopened_modules_in_scope(&module.declarations, active_prefix.clone());
                if let Some(prefix) = &active_prefix {
                    prepend_prefix_pragma(&mut declarations, prefix);
                }
                let incoming = Module {
                    name: module.name.clone(),
                    declarations,
                };
                if let Some(existing) = find_module_mut(&mut merged, &incoming.name) {
                    existing.declarations.extend(incoming.declarations);
                    existing.declarations =
                        merge_reopened_modules_in_scope(&existing.declarations, None);
                } else {
                    merged.push(Declaration::Module(incoming));
                }
            }
            Declaration::Interface(_)
            | Declaration::Struct(_)
            | Declaration::Enum(_)
            | Declaration::Exception(_)
            | Declaration::Typedef(_)
            | Declaration::Const(_)
            | Declaration::Union(_)
            | Declaration::ValueType(_)
            | Declaration::EventType(_) => {
                merge_named_declaration(&mut merged, declaration.clone())
            }
        }
    }
    merged
}

/// Merge duplicate declarations introduced when several top-level IDLs include
/// the same common file and are then emitted as one aggregate AST. Reopened
/// modules are already combined above; this handles the declarations inside
/// them so an included struct/interface is not rendered twice into one Ada spec.
/// Conflicting same-name declarations keep the first shape and add only distinct
/// compatible members, which is deterministic and avoids last-file-wins erasure.
fn merge_named_declaration(merged: &mut Vec<Declaration>, incoming: Declaration) {
    match incoming {
        Declaration::Interface(mut value) => {
            if let Some(Declaration::Interface(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::Interface(item) if item.name == value.name))
            {
                for inherited in value.inherits.drain(..) {
                    if !existing.inherits.contains(&inherited) {
                        existing.inherits.push(inherited);
                    }
                }
                for member in value.members.drain(..) {
                    if !existing.members.contains(&member) {
                        existing.members.push(member);
                    }
                }
            } else {
                merged.push(Declaration::Interface(value));
            }
        }
        Declaration::Struct(mut value) => {
            if let Some(Declaration::Struct(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::Struct(item) if item.name == value.name))
            {
                for field in value.fields.drain(..) {
                    if !existing.fields.iter().any(|item| item.name == field.name) {
                        existing.fields.push(field);
                    }
                }
            } else {
                merged.push(Declaration::Struct(value));
            }
        }
        Declaration::Exception(mut value) => {
            if let Some(Declaration::Exception(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::Exception(item) if item.name == value.name))
            {
                for field in value.fields.drain(..) {
                    if !existing.fields.iter().any(|item| item.name == field.name) {
                        existing.fields.push(field);
                    }
                }
            } else {
                merged.push(Declaration::Exception(value));
            }
        }
        Declaration::Enum(mut value) => {
            if let Some(Declaration::Enum(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::Enum(item) if item.name == value.name))
            {
                for variant in value.variants.drain(..) {
                    if !existing.variants.contains(&variant) {
                        existing.variants.push(variant);
                    }
                }
            } else {
                merged.push(Declaration::Enum(value));
            }
        }
        Declaration::Union(mut value) => {
            if let Some(Declaration::Union(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::Union(item) if item.name == value.name))
            {
                for arm in value.arms.drain(..) {
                    if !existing
                        .arms
                        .iter()
                        .any(|item| item.field.name == arm.field.name)
                    {
                        existing.arms.push(arm);
                    }
                }
            } else {
                merged.push(Declaration::Union(value));
            }
        }
        Declaration::Typedef(value) => {
            if !merged.iter().any(
                |declaration| matches!(declaration, Declaration::Typedef(item) if item.name == value.name),
            ) {
                merged.push(Declaration::Typedef(value));
            }
        }
        Declaration::Const(value) => {
            if !merged.iter().any(
                |declaration| matches!(declaration, Declaration::Const(item) if item.name == value.name),
            ) {
                merged.push(Declaration::Const(value));
            }
        }
        Declaration::ValueType(mut value) => {
            if let Some(Declaration::ValueType(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::ValueType(item) if item.name == value.name))
            {
                for inherited in value.inherits.drain(..) {
                    if !existing.inherits.contains(&inherited) {
                        existing.inherits.push(inherited);
                    }
                }
                existing.is_abstract |= value.is_abstract;
            } else {
                merged.push(Declaration::ValueType(value));
            }
        }
        Declaration::EventType(mut value) => {
            if let Some(Declaration::EventType(existing)) = merged
                .iter_mut()
                .find(|declaration| matches!(declaration, Declaration::EventType(item) if item.name == value.name))
            {
                for inherited in value.inherits.drain(..) {
                    if !existing.inherits.contains(&inherited) {
                        existing.inherits.push(inherited);
                    }
                }
                existing.is_abstract |= value.is_abstract;
            } else {
                merged.push(Declaration::EventType(value));
            }
        }
        value @ (Declaration::Pragma(_) | Declaration::Module(_)) => merged.push(value),
    }
}

fn prepend_prefix_pragma(declarations: &mut Vec<Declaration>, prefix: &str) {
    if declarations.first().is_some_and(|declaration| {
        matches!(
            declaration,
            Declaration::Pragma(IdlPragma {
                kind: IdlPragmaKind::Prefix(existing),
                ..
            }) if existing == prefix
        )
    }) {
        return;
    }
    declarations.insert(
        0,
        Declaration::Pragma(IdlPragma {
            name: "prefix".to_owned(),
            line: 0,
            kind: IdlPragmaKind::Prefix(prefix.to_owned()),
        }),
    );
}

fn find_module_mut<'a>(declarations: &'a mut [Declaration], name: &str) -> Option<&'a mut Module> {
    declarations
        .iter_mut()
        .find_map(|declaration| match declaration {
            Declaration::Module(module) if module.name == name => Some(module),
            _ => None,
        })
}

pub fn write_generated_ada_units(
    output_dir: &Path,
    units: &[GeneratedAdaUnit],
) -> io::Result<Vec<PathBuf>> {
    let mut written = Vec::with_capacity(units.len());
    for unit in units {
        let path = output_dir.join(&unit.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &unit.contents)?;
        written.push(path);
    }
    Ok(written)
}

#[derive(Default)]
struct Emitter {
    units: Vec<GeneratedAdaUnit>,
    warnings: Vec<String>,
    sequences: BTreeMap<String, SequenceInfo>,
    maps: BTreeMap<String, MapInfo>,
    arrays: BTreeMap<String, ArrayInfo>,
    version_pragmas: BTreeMap<Vec<String>, String>,
    /// Package holding the declarations that sit outside every IDL module, if
    /// the file has any. Ada has no global type scope, so without one those
    /// declarations had nowhere to go and were dropped entirely.
    root_package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SequenceInfo {
    element_type: String,
    dependencies: BTreeSet<String>,
    owner: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArrayInfo {
    element_type: String,
    dimensions: Vec<u64>,
    dependencies: BTreeSet<String>,
    owner: Option<Vec<String>>,
}

/// A sequence / map / array helper type that belongs inside a module package
/// rather than in a unit of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperType {
    Sequence(SequenceInfo),
    Map(MapInfo),
    Array(ArrayInfo),
}

impl HelperType {
    /// The declarations to splice into the owning package, at the point where
    /// the element type is already declared.
    fn render(&self, type_name: &str) -> String {
        match self {
            HelperType::Sequence(info) => format!(
                "   type {type_name}_Elements is array (Positive range <>) of {};\n   type {type_name} is record\n      Length : Natural := 0;\n      Values : {type_name}_Elements (1 .. 1);\n   end record;\n",
                info.element_type
            ),
            HelperType::Map(info) => format!(
                "   type {type_name}_Keys is array (Positive range <>) of {};\n   type {type_name}_Values is array (Positive range <>) of {};\n   type {type_name} is record\n      Length : Natural := 0;\n      Keys : {type_name}_Keys (1 .. 1);\n      Values : {type_name}_Values (1 .. 1);\n   end record;\n",
                info.key_type, info.value_type
            ),
            HelperType::Array(info) => format!(
                "   type {type_name} is array ({}) of {};\n",
                info.dimensions
                    .iter()
                    .map(|dimension| format!("1 .. {dimension}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                info.element_type
            ),
        }
    }
}

/// The package scope that owns the helper type for `ty`, if any.
///
/// A helper whose element type is declared in a module cannot live in a unit of
/// its own: the module needs the helper for its own fields, and the helper needs
/// the module for its element type, which is a circular `with` Ada rejects. Such
/// a helper is declared inside the module instead. Helpers over primitives,
/// strings and unresolved external names have no such cycle and stay standalone.
fn type_owner_scope(ty: &TypeRef) -> Option<Vec<String>> {
    match ty {
        TypeRef::Named(name) if name.parts.len() > 1 => Some(
            name.parts[..name.parts.len() - 1]
                .iter()
                .map(|part| ada_identifier(part))
                .collect(),
        ),
        TypeRef::Sequence { element, .. } | TypeRef::Array { element, .. } => {
            type_owner_scope(element)
        }
        TypeRef::Map { key, value, .. } => {
            type_owner_scope(key).or_else(|| type_owner_scope(value))
        }
        _ => None,
    }
}

/// How a helper type is named at a use site: a type inside its owning package,
/// or the type exported by its standalone package.
fn render_helper_reference(ty: &TypeRef, helper_name: &str, standalone_type: &str) -> String {
    match type_owner_scope(ty) {
        Some(scope) => format!("{}.{helper_name}", scope.join(".")),
        None => format!("{helper_name}.{standalone_type}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapInfo {
    owner: Option<Vec<String>>,
    key_type: String,
    value_type: String,
    dependencies: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PragmaState {
    prefix: Option<String>,
}

impl Emitter {
    fn collect_sequences(&mut self, declarations: &[Declaration]) {
        for declaration in declarations {
            match declaration {
                Declaration::Pragma(_) => {}
                Declaration::Module(module) => self.collect_sequences(&module.declarations),
                Declaration::Interface(interface) => {
                    for member in &interface.members {
                        match member {
                            InterfaceMember::Operation(operation) => {
                                self.collect_type(&operation.return_type);
                                for param in &operation.params {
                                    self.collect_type(&param.ty);
                                }
                            }
                            InterfaceMember::Attribute(attribute) => {
                                self.collect_type(&attribute.ty)
                            }
                        }
                    }
                }
                Declaration::Struct(struct_decl) => {
                    for field in &struct_decl.fields {
                        self.collect_type(&field.ty);
                    }
                }
                Declaration::Exception(exception) => {
                    for field in &exception.fields {
                        self.collect_type(&field.ty);
                    }
                }
                Declaration::Typedef(typedef) => self.collect_type(&typedef.ty),
                Declaration::Const(const_decl) => {
                    self.collect_type(&const_decl.ty);
                    self.warn_on_unrepresentable_literal(const_decl);
                }
                Declaration::Union(union_decl) => {
                    self.collect_type(&union_decl.discriminator);
                    for arm in &union_decl.arms {
                        self.collect_type(&arm.field.ty);
                    }
                    self.warnings.push(format!(
                        "union '{}' emitted as declaration comments",
                        union_decl.name
                    ));
                }
                Declaration::Enum(_) | Declaration::ValueType(_) | Declaration::EventType(_) => {}
            }
        }
    }

    /// The generated `Standard.Character` / `Standard.String` are 8-bit, so a
    /// wide literal naming a higher code point cannot be rendered faithfully.
    /// [`clamp_ada_code_point`] substitutes `?`; say so rather than quietly
    /// changing the constant.
    fn warn_on_unrepresentable_literal(&mut self, const_decl: &Const) {
        let ConstValue::String(literal) = &const_decl.value else {
            return;
        };
        if decode_idl_literal(literal)
            .chars()
            .any(|ch| ch as u32 > MAX_ADA_CHARACTER)
        {
            self.warnings.push(format!(
                "IDL constant '{}' holds characters beyond Latin-1; they are mapped to '?'",
                const_decl.name
            ));
        }
    }

    fn collect_type(&mut self, ty: &TypeRef) {
        // `qualify_named_types` has already run, so a name that is still a
        // single part is one this run never mapped — a type from an `#include`
        // it could not read, or one declared outside any module (which the
        // emitter has no package to put in). Ada will reject the reference, so
        // say which type it was rather than leaving an undefined identifier.
        if let TypeRef::Named(name) = ty {
            if name.parts.len() == 1 {
                let name = name.parts[0].clone();
                let warning = format!("IDL type '{name}' is referenced but not mapped");
                if !self.warnings.contains(&warning) {
                    self.warnings.push(warning);
                }
            }
        }
        match ty {
            TypeRef::Sequence { element, bound } => {
                self.collect_type(element);
                let package_name = sequence_package_name(element, *bound);
                let owner = type_owner_scope(ty);
                self.sequences.entry(package_name).or_insert_with(|| {
                    let mut dependencies = BTreeSet::new();
                    collect_type_dependencies(element, &mut dependencies);
                    SequenceInfo {
                        element_type: render_constrained_type(element),
                        dependencies,
                        owner,
                    }
                });
            }
            TypeRef::Map { key, value, bound } => {
                self.collect_type(key);
                self.collect_type(value);
                let package_name = map_package_name(key, value, *bound);
                let owner = type_owner_scope(ty);
                self.maps.entry(package_name).or_insert_with(|| {
                    let mut dependencies = BTreeSet::new();
                    collect_type_dependencies(key, &mut dependencies);
                    collect_type_dependencies(value, &mut dependencies);
                    MapInfo {
                        key_type: render_constrained_type(key),
                        value_type: render_constrained_type(value),
                        dependencies,
                        owner,
                    }
                });
            }
            TypeRef::Array {
                element,
                dimensions,
            } => {
                self.collect_type(element);
                let package_name = array_package_name(element, dimensions);
                let owner = type_owner_scope(ty);
                self.arrays.entry(package_name).or_insert_with(|| {
                    let mut dependencies = BTreeSet::new();
                    collect_type_dependencies(element, &mut dependencies);
                    ArrayInfo {
                        element_type: render_constrained_type(element),
                        dimensions: dimensions.clone(),
                        dependencies,
                        owner,
                    }
                });
            }
            TypeRef::Fixed { digits, scale } => self.warnings.push(format!(
                "fixed<{digits}, {scale}> mapped to Long_Float placeholder"
            )),
            _ => {}
        }
    }

    fn walk_declarations(
        &mut self,
        declarations: &[Declaration],
        ada_scope: &[String],
        idl_scope: &[String],
        state: &PragmaState,
    ) {
        let mut local_state = state.clone();
        for declaration in declarations {
            match declaration {
                Declaration::Pragma(pragma) => apply_pragma_state(pragma, &mut local_state),
                Declaration::Module(module) => {
                    self.emit_module(module, ada_scope, idl_scope, &local_state)
                }
                Declaration::Interface(interface) => {
                    self.emit_interface(interface, ada_scope, idl_scope, &local_state)
                }
                _ => {}
            }
        }
    }

    /// Emit the package holding everything declared outside a module. Its Ada
    /// scope is the synthetic package, but its IDL scope stays global, so the
    /// repository id of each declaration is still `IDL:<prefix>/<Name>:<ver>`.
    fn emit_root_package(&mut self, declarations: &[Declaration], state: &PragmaState) {
        let Some(package_name) = self.root_package.clone() else {
            return;
        };
        let module = Module {
            name: package_name.clone(),
            declarations: declarations
                .iter()
                .filter(|declaration| {
                    goes_in_root_package(declaration)
                        || matches!(declaration, Declaration::Pragma(_))
                })
                .cloned()
                .collect(),
        };
        let ada_scope = vec![package_name.clone()];
        let owned_helpers = self.helpers_owned_by(&ada_scope);
        self.units.push(generated_unit(
            &package_name,
            render_module_package(
                &package_name,
                &module,
                &[],
                state,
                &self.version_pragmas,
                &owned_helpers,
                false,
            ),
        ));
    }

    fn emit_module(
        &mut self,
        module: &Module,
        ada_scope: &[String],
        idl_scope: &[String],
        state: &PragmaState,
    ) {
        let mut module_ada_scope = ada_scope.to_vec();
        module_ada_scope.push(ada_identifier(&module.name));
        let mut module_idl_scope = idl_scope.to_vec();
        module_idl_scope.push(module.name.clone());
        let package_name = module_ada_scope.join(".");
        let owned_helpers = self.helpers_owned_by(&module_ada_scope);
        self.units.push(generated_unit(
            &package_name,
            render_module_package(
                &package_name,
                module,
                &module_idl_scope,
                state,
                &self.version_pragmas,
                &owned_helpers,
                true,
            ),
        ));
        self.walk_declarations(
            &module.declarations,
            &module_ada_scope,
            &module_idl_scope,
            state,
        );
    }

    fn emit_interface(
        &mut self,
        interface: &Interface,
        ada_scope: &[String],
        idl_scope: &[String],
        state: &PragmaState,
    ) {
        let mut interface_scope = ada_scope.to_vec();
        let interface_name = ada_identifier(&interface.name);
        interface_scope.push(interface_name.clone());
        let mut interface_idl_scope = idl_scope.to_vec();
        interface_idl_scope.push(interface.name.clone());
        let package_name = interface_scope.join(".");
        let repository_id = repository_id_for(&interface_idl_scope, state, &self.version_pragmas);

        self.units.push(generated_unit(
            &package_name,
            render_interface_package(
                &package_name,
                interface,
                ada_scope,
                repository_id.as_deref(),
            ),
        ));
        if interface_has_body(interface) {
            self.units.push(generated_body_unit(
                &package_name,
                render_interface_body(&package_name, interface),
            ));
        }
        self.units.push(generated_unit(
            &format!("{package_name}.Helper"),
            render_helper_package(&package_name, &interface_name, repository_id.as_deref()),
        ));
        self.units.push(generated_body_unit(
            &format!("{package_name}.Helper"),
            render_helper_body(&package_name, &interface_name),
        ));
        self.units.push(generated_unit(
            &format!("{package_name}.Skel"),
            render_skel_package(&package_name),
        ));
        self.units.push(generated_body_unit(
            &format!("{package_name}.Skel"),
            render_skel_body(&package_name),
        ));
        self.units.push(generated_unit(
            &format!("{package_name}.Stub"),
            render_stub_package(&format!("{package_name}.Stub"), interface),
        ));
        self.units.push(generated_body_unit(
            &format!("{package_name}.Stub"),
            render_stub_body(&format!("{package_name}.Stub"), interface),
        ));
    }

    /// Emit the helper packages that stand alone. Helpers owned by a module are
    /// spliced into that module's package by [`Emitter::helpers_owned_by`].
    fn emit_sequence_units(&mut self) {
        for (package_name, info) in &self.sequences {
            if info.owner.is_some() {
                continue;
            }
            self.units.push(generated_unit(
                package_name,
                render_sequence_package(package_name, info),
            ));
        }
        for (package_name, info) in &self.maps {
            if info.owner.is_some() {
                continue;
            }
            self.units.push(generated_unit(
                package_name,
                render_map_package(package_name, info),
            ));
        }
        for (package_name, info) in &self.arrays {
            if info.owner.is_some() {
                continue;
            }
            self.units.push(generated_unit(
                package_name,
                render_array_package(package_name, info),
            ));
        }
    }

    fn helpers_owned_by(&self, scope: &[String]) -> BTreeMap<String, HelperType> {
        let mut owned = BTreeMap::new();
        for (name, info) in &self.sequences {
            if info.owner.as_deref() == Some(scope) {
                owned.insert(name.clone(), HelperType::Sequence(info.clone()));
            }
        }
        for (name, info) in &self.maps {
            if info.owner.as_deref() == Some(scope) {
                owned.insert(name.clone(), HelperType::Map(info.clone()));
            }
        }
        for (name, info) in &self.arrays {
            if info.owner.as_deref() == Some(scope) {
                owned.insert(name.clone(), HelperType::Array(info.clone()));
            }
        }
        owned
    }
}

fn interface_has_body(interface: &Interface) -> bool {
    interface.members.iter().any(|member| match member {
        InterfaceMember::Operation(_) | InterfaceMember::Attribute(_) => true,
    })
}

fn render_module_package(
    package_name: &str,
    module: &Module,
    idl_scope: &[String],
    state: &PragmaState,
    version_pragmas: &BTreeMap<Vec<String>, String>,
    owned_helpers: &BTreeMap<String, HelperType>,
    package_repository_id: bool,
) -> String {
    let mut dependencies = BTreeSet::new();
    for declaration in &module.declarations {
        collect_declaration_dependencies(declaration, &mut dependencies);
    }
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package {package_name} is\n"));
    if package_repository_id {
        if let Some(repository_id) = repository_id_for(idl_scope, state, version_pragmas) {
            push_repository_id_constant(&mut contents, "Repository_Id", &repository_id);
        }
    }
    let mut local_state = state.clone();
    let mut pending_helpers = owned_helpers.clone();
    for declaration in &module.declarations {
        if let Declaration::Pragma(pragma) = declaration {
            apply_pragma_state(pragma, &mut local_state);
            continue;
        }
        // A helper type has to follow the element type it is built from and
        // precede the first declaration that uses it, so it is spliced in here
        // rather than batched at either end of the package.
        for helper_name in declaration_helper_types(declaration) {
            if let Some(helper) = pending_helpers.remove(&helper_name) {
                contents.push_str(&helper.render(&helper_name));
            }
        }
        if let Some(name) = declaration_name(declaration) {
            let mut declaration_scope = idl_scope.to_vec();
            declaration_scope.push(name.to_owned());
            if let Some(repository_id) =
                repository_id_for(&declaration_scope, &local_state, version_pragmas)
            {
                push_repository_id_constant(
                    &mut contents,
                    &format!("Repository_Id_{}", ada_identifier(name)),
                    &repository_id,
                );
            }
        }
        match declaration {
            Declaration::Enum(enum_decl) => push_enum(&mut contents, enum_decl),
            Declaration::Struct(struct_decl) => push_struct(&mut contents, struct_decl),
            Declaration::Exception(exception) => push_exception(&mut contents, exception),
            Declaration::Typedef(typedef) => push_typedef(&mut contents, typedef),
            Declaration::Const(const_decl) => push_const(&mut contents, const_decl),
            Declaration::Union(union_decl) => {
                contents.push_str(&format!(
                    "   --  union {} emitted as a placeholder declaration\n",
                    ada_identifier(&union_decl.name)
                ));
            }
            Declaration::ValueType(value_type) => contents.push_str(&format!(
                "   type {} is tagged null record;\n",
                ada_identifier(&value_type.name)
            )),
            Declaration::EventType(event_type) => contents.push_str(&format!(
                "   type {} is tagged null record;\n",
                ada_identifier(&event_type.name)
            )),
            Declaration::Pragma(_) | Declaration::Module(_) | Declaration::Interface(_) => {}
        }
    }
    // Helpers no declaration in this package used directly — a nested module or
    // an interface child unit reaches them through this parent.
    for (helper_name, helper) in &pending_helpers {
        contents.push_str(&helper.render(helper_name));
    }
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

/// The owned helper types a declaration references, in first-use order.
fn declaration_helper_types(declaration: &Declaration) -> Vec<String> {
    let mut names = Vec::new();
    let push = |ty: &TypeRef, names: &mut Vec<String>| collect_helper_type_names(ty, names);
    match declaration {
        Declaration::Struct(struct_decl) => {
            for field in &struct_decl.fields {
                push(&field.ty, &mut names);
            }
        }
        Declaration::Exception(exception) => {
            for field in &exception.fields {
                push(&field.ty, &mut names);
            }
        }
        Declaration::Typedef(typedef) => push(&typedef.ty, &mut names),
        Declaration::Const(const_decl) => push(&const_decl.ty, &mut names),
        Declaration::Union(union_decl) => {
            push(&union_decl.discriminator, &mut names);
            for arm in &union_decl.arms {
                push(&arm.field.ty, &mut names);
            }
        }
        Declaration::Pragma(_)
        | Declaration::Module(_)
        | Declaration::Interface(_)
        | Declaration::Enum(_)
        | Declaration::ValueType(_)
        | Declaration::EventType(_) => {}
    }
    names
}

fn collect_helper_type_names(ty: &TypeRef, names: &mut Vec<String>) {
    let name = match ty {
        TypeRef::Sequence { element, bound } => {
            collect_helper_type_names(element, names);
            sequence_package_name(element, *bound)
        }
        TypeRef::Array {
            element,
            dimensions,
        } => {
            collect_helper_type_names(element, names);
            array_package_name(element, dimensions)
        }
        TypeRef::Map { key, value, bound } => {
            collect_helper_type_names(key, names);
            collect_helper_type_names(value, names);
            map_package_name(key, value, *bound)
        }
        _ => return,
    };
    if !names.contains(&name) {
        names.push(name);
    }
}

fn render_interface_package(
    package_name: &str,
    interface: &Interface,
    scope: &[String],
    repository_id: Option<&str>,
) -> String {
    let dependencies = collect_interface_dependencies(interface);
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package {package_name} is\n"));
    contents.push_str("   type Ref is tagged null record;\n");
    if let Some(repository_id) = repository_id {
        push_repository_id_constant(&mut contents, "Repository_Id", repository_id);
    }
    for member in &interface.members {
        match member {
            InterfaceMember::Operation(operation) => {
                push_raises_comment(&mut contents, operation, scope);
                contents.push_str("   ");
                contents.push_str(&render_operation_spec(operation, true));
                contents.push('\n');
                contents.push_str("   ");
                contents.push_str(&render_operation_spec(operation, false));
                contents.push('\n');
            }
            InterfaceMember::Attribute(attribute) => {
                push_attribute(&mut contents, attribute);
            }
        }
    }
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn render_interface_body(package_name: &str, interface: &Interface) -> String {
    let dependencies = collect_interface_dependencies(interface);
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package body {package_name} is\n"));
    for member in &interface.members {
        match member {
            InterfaceMember::Operation(operation) => {
                contents.push_str(&render_operation_body(operation, true));
                contents.push_str(&render_operation_body(operation, false));
            }
            InterfaceMember::Attribute(attribute) => {
                contents.push_str(&render_attribute_bodies(attribute));
            }
        }
    }
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn render_helper_package(
    package_name: &str,
    interface_name: &str,
    repository_id: Option<&str>,
) -> String {
    let helper_name = format!("{package_name}.Helper");
    let mut contents = String::new();
    push_header_and_context(
        &mut contents,
        &helper_name,
        BTreeSet::from(["CORBA.Any".to_owned()]),
    );
    contents.push_str(&format!("package {helper_name} is\n"));
    if let Some(repository_id) = repository_id {
        push_repository_id_constant(&mut contents, "Repository_Id", repository_id);
    }
    contents.push_str(&format!(
        "   function From_Any (Value : CORBA.Any.Value) return {package_name}.Ref;\n"
    ));
    contents.push_str(&format!(
        "   function To_Any (Value : {package_name}.Ref) return CORBA.Any.Value;\n"
    ));
    contents.push_str(&format!(
        "   function TC_{interface_name} return CORBA.Any.TypeCode;\n"
    ));
    contents.push_str(&format!("end {helper_name};\n"));
    contents
}

fn render_helper_body(package_name: &str, interface_name: &str) -> String {
    let helper_name = format!("{package_name}.Helper");
    let mut contents = String::new();
    push_header_and_context(
        &mut contents,
        &helper_name,
        BTreeSet::from(["CORBA.Any".to_owned()]),
    );
    contents.push_str(&format!("package body {helper_name} is\n"));
    contents.push_str(&format!(
        "   function From_Any (Value : CORBA.Any.Value) return {package_name}.Ref is\n      pragma Unreferenced (Value);\n      Result : {package_name}.Ref;\n   begin\n      return Result;\n   end From_Any;\n"
    ));
    contents.push_str(&format!(
        "   function To_Any (Value : {package_name}.Ref) return CORBA.Any.Value is\n      pragma Unreferenced (Value);\n   begin\n      return CORBA.Any.Value'(null record);\n   end To_Any;\n"
    ));
    contents.push_str(&format!(
        "   function TC_{interface_name} return CORBA.Any.TypeCode is\n   begin\n      return CORBA.Any.TypeCode'(null record);\n   end TC_{interface_name};\n"
    ));
    contents.push_str(&format!("end {helper_name};\n"));
    contents
}

fn render_skel_package(package_name: &str) -> String {
    let skel_name = format!("{package_name}.Skel");
    format!("--  SPDX-License-Identifier: Apache-2.0\n\npackage {skel_name} is\n   procedure Dispatch (Target : in out {package_name}.Ref);\nend {skel_name};\n")
}

fn render_skel_body(package_name: &str) -> String {
    let skel_name = format!("{package_name}.Skel");
    format!("--  SPDX-License-Identifier: Apache-2.0\n\npackage body {skel_name} is\n   procedure Dispatch (Target : in out {package_name}.Ref) is\n      pragma Unreferenced (Target);\n   begin\n      null;\n   end Dispatch;\nend {skel_name};\n")
}

fn render_stub_package(package_name: &str, interface: &Interface) -> String {
    let dependencies = collect_interface_dependencies(interface);
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package {package_name} is\n"));
    for member in &interface.members {
        if let InterfaceMember::Operation(operation) = member {
            contents.push_str("   ");
            contents.push_str(&render_operation_spec(operation, false));
            contents.push('\n');
        }
    }
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn render_stub_body(package_name: &str, interface: &Interface) -> String {
    let dependencies = collect_interface_dependencies(interface);
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package body {package_name} is\n"));
    for member in &interface.members {
        if let InterfaceMember::Operation(operation) = member {
            contents.push_str(&render_operation_body(operation, false));
        }
    }
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn render_operation_spec(operation: &Operation, include_self: bool) -> String {
    format!("{};", render_operation_profile(operation, include_self))
}

fn render_operation_body(operation: &Operation, include_self: bool) -> String {
    let name = ada_identifier(&operation.name);
    let mut contents = String::new();
    contents.push_str("   ");
    contents.push_str(&render_operation_profile(operation, include_self));
    contents.push_str(" is\n");
    for param in &operation.params {
        contents.push_str(&format!(
            "      pragma Unreferenced ({});\n",
            ada_identifier(&param.name)
        ));
    }
    if include_self {
        contents.push_str("      pragma Unreferenced (Self);\n");
    }
    if operation.return_type == TypeRef::Void {
        contents.push_str("   begin\n");
        contents.push_str("      null;\n");
    } else {
        push_return_stub(&mut contents, &operation.return_type);
    }
    contents.push_str(&format!("   end {name};\n"));
    contents
}

fn render_operation_profile(operation: &Operation, include_self: bool) -> String {
    let name = ada_identifier(&operation.name);
    let mut rendered_params = Vec::new();
    if include_self {
        if operation.return_type == TypeRef::Void {
            rendered_params.push("Self : in out Ref".to_owned());
        } else {
            rendered_params.push("Self : Ref".to_owned());
        }
    }
    rendered_params.extend(
        operation
            .params
            .iter()
            .map(render_param)
            .collect::<Vec<_>>(),
    );
    let params = rendered_params.join("; ");
    let param_list = if params.is_empty() {
        String::new()
    } else {
        format!(" ({params})")
    };
    match &operation.return_type {
        TypeRef::Void => format!("procedure {name}{param_list}"),
        return_type => format!(
            "function {name}{param_list} return {}",
            render_type(return_type)
        ),
    }
}

fn render_attribute_bodies(attribute: &Attribute) -> String {
    let name = ada_identifier(&attribute.name);
    let ty = render_type(&attribute.ty);
    let mut contents = String::new();
    contents.push_str(&format!(
        "   function {name} (Self : Ref) return {ty} is\n      pragma Unreferenced (Self);\n"
    ));
    push_return_stub(&mut contents, &attribute.ty);
    contents.push_str(&format!("   end {name};\n"));
    if !attribute.readonly {
        contents.push_str(&format!(
            "   procedure Set_{name} (Self : in out Ref; Value : {ty}) is\n      pragma Unreferenced (Self);\n      pragma Unreferenced (Value);\n   begin\n      null;\n   end Set_{name};\n"
        ));
    }
    contents
}

fn push_return_stub(contents: &mut String, ty: &TypeRef) {
    if let Some(expression) = dummy_return_expression(ty) {
        contents.push_str("   begin\n");
        contents.push_str(&format!("      return {expression};\n"));
    } else {
        contents.push_str(&format!("      Result : {};\n", render_type(ty)));
        contents.push_str("   begin\n");
        contents.push_str("      return Result;\n");
    }
}

fn dummy_return_expression(ty: &TypeRef) -> Option<String> {
    match ty {
        TypeRef::Void => None,
        TypeRef::Primitive(PrimitiveType::Boolean) => Some("False".to_owned()),
        TypeRef::Primitive(PrimitiveType::Char | PrimitiveType::WChar) => {
            Some("Standard.Character'Val (0)".to_owned())
        }
        TypeRef::Primitive(
            PrimitiveType::Octet
            | PrimitiveType::Short
            | PrimitiveType::UShort
            | PrimitiveType::Long
            | PrimitiveType::ULong
            | PrimitiveType::LongLong
            | PrimitiveType::ULongLong,
        ) => Some("0".to_owned()),
        TypeRef::Primitive(
            PrimitiveType::Float | PrimitiveType::Double | PrimitiveType::LongDouble,
        )
        | TypeRef::Fixed { .. } => Some("0.0".to_owned()),
        TypeRef::Primitive(PrimitiveType::Any) => Some("CORBA.Any.Value'(null record)".to_owned()),
        TypeRef::Primitive(PrimitiveType::Object) => Some("CORBA.Object.Nil".to_owned()),
        TypeRef::String { .. } => Some("\"\"".to_owned()),
        TypeRef::Named(_)
        | TypeRef::Sequence { .. }
        | TypeRef::Map { .. }
        | TypeRef::Array { .. } => None,
    }
}

fn render_param(param: &Param) -> String {
    let name = ada_identifier(&param.name);
    let ty = render_type(&param.ty);
    match param.direction {
        ParamDirection::In => format!("{name} : {ty}"),
        ParamDirection::Out => format!("{name} : out {ty}"),
        ParamDirection::InOut => format!("{name} : in out {ty}"),
    }
}

fn render_type(ty: &TypeRef) -> String {
    match ty {
        TypeRef::Void => "Standard.Boolean".to_owned(),
        TypeRef::Primitive(primitive) => render_primitive_type(primitive).to_owned(),
        TypeRef::Named(name) => name
            .parts
            .iter()
            .map(|part| ada_identifier(part))
            .collect::<Vec<_>>()
            .join("."),
        TypeRef::Sequence { element, bound } => {
            render_helper_reference(ty, &sequence_package_name(element, *bound), "Sequence")
        }
        TypeRef::Map { key, value, bound } => {
            render_helper_reference(ty, &map_package_name(key, value, *bound), "Map")
        }
        TypeRef::Array {
            element,
            dimensions,
        } => render_helper_reference(ty, &array_package_name(element, dimensions), "Value"),
        TypeRef::String { .. } => "Standard.String".to_owned(),
        TypeRef::Fixed { .. } => "Long_Float".to_owned(),
    }
}

/// The type as written where Ada demands a *constrained* subtype: record and
/// array components. `Standard.String` is unconstrained, so `string name;` —
/// about the most ordinary IDL there is — produced "unconstrained subtype in
/// component declaration". A bounded IDL string carries its bound here; an
/// unbounded one gets the same one-element placeholder the sequence packages
/// already use for their payload.
fn render_constrained_type(ty: &TypeRef) -> String {
    match ty {
        TypeRef::String { bound, .. } => {
            format!("Standard.String (1 .. {})", bound.unwrap_or(1))
        }
        _ => render_type(ty),
    }
}

fn render_primitive_type(primitive: &PrimitiveType) -> &'static str {
    match primitive {
        PrimitiveType::Boolean => "Standard.Boolean",
        PrimitiveType::Char | PrimitiveType::WChar => "Standard.Character",
        PrimitiveType::Octet => "CORBA.Octet",
        PrimitiveType::Short | PrimitiveType::UShort | PrimitiveType::Long => "Integer",
        PrimitiveType::ULong => "Natural",
        PrimitiveType::LongLong | PrimitiveType::ULongLong => "Long_Long_Integer",
        PrimitiveType::Float => "Float",
        PrimitiveType::Double | PrimitiveType::LongDouble => "Long_Float",
        PrimitiveType::Any => "CORBA.Any.Value",
        PrimitiveType::Object => "CORBA.Object.Ref",
    }
}

fn sequence_suffix(ty: &TypeRef) -> String {
    type_package_suffix(ty)
}

fn type_package_suffix(ty: &TypeRef) -> String {
    match ty {
        TypeRef::String { wide: false, .. } => "String".to_owned(),
        TypeRef::String { wide: true, .. } => "WString".to_owned(),
        TypeRef::Sequence { element, bound } => sequence_package_name(element, *bound),
        TypeRef::Map { key, value, bound } => map_package_name(key, value, *bound),
        _ => sanitize_type_name(&render_type(ty)),
    }
}

fn sanitize_type_name(name: &str) -> String {
    name.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

fn sequence_package_name(element: &TypeRef, bound: Option<u64>) -> String {
    let mut name = format!("Sequence_Of_{}", sequence_suffix(element));
    if let Some(bound) = bound {
        name.push_str(&format!("_Bound_{bound}"));
    }
    name
}

/// `octet raw[16]` and `long grid[2][257]` get one package each, holding a real
/// constrained Ada array type. Rendering the array as its element type instead
/// silently turned a 16-byte field into a single byte.
fn array_package_name(element: &TypeRef, dimensions: &[u64]) -> String {
    format!(
        "Array_Of_{}_{}",
        type_package_suffix(element),
        dimensions
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("x")
    )
}

fn render_array_package(package_name: &str, info: &ArrayInfo) -> String {
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, info.dependencies.clone());
    contents.push_str(&format!("package {package_name} is\n"));
    let ranges = info
        .dimensions
        .iter()
        .map(|dimension| format!("1 .. {dimension}"))
        .collect::<Vec<_>>()
        .join(", ");
    contents.push_str(&format!(
        "   type Value is array ({ranges}) of {};\n",
        info.element_type
    ));
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn map_package_name(key: &TypeRef, value: &TypeRef, bound: Option<u64>) -> String {
    let mut name = format!(
        "Map_{}_To_{}",
        type_package_suffix(key),
        type_package_suffix(value)
    );
    if let Some(bound) = bound {
        name.push_str(&format!("_Bound_{bound}"));
    }
    name
}

fn render_sequence_package(package_name: &str, info: &SequenceInfo) -> String {
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, info.dependencies.clone());
    contents.push_str(&format!("package {package_name} is\n"));
    contents.push_str(&format!(
        "   type Element_Array is array (Positive range <>) of {};\n",
        info.element_type
    ));
    contents.push_str(
        "   type Sequence is record\n      Length : Natural := 0;\n      Values : Element_Array (1 .. 1);\n   end record;\n",
    );
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn render_map_package(package_name: &str, info: &MapInfo) -> String {
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, info.dependencies.clone());
    contents.push_str(&format!("package {package_name} is\n"));
    contents.push_str(&format!(
        "   type Key_Array is array (Positive range <>) of {};\n",
        info.key_type
    ));
    contents.push_str(&format!(
        "   type Value_Array is array (Positive range <>) of {};\n",
        info.value_type
    ));
    contents.push_str(
        "   type Map is record\n      Length : Natural := 0;\n      Keys : Key_Array (1 .. 1);\n      Values : Value_Array (1 .. 1);\n   end record;\n",
    );
    contents.push_str(&format!("end {package_name};\n"));
    contents
}

fn push_header_and_context(
    contents: &mut String,
    package_name: &str,
    dependencies: BTreeSet<String>,
) {
    contents.push_str("--  SPDX-License-Identifier: Apache-2.0\n\n");
    let dependencies = dependencies
        .into_iter()
        .filter(|dependency| !is_self_or_ancestor_dependency(package_name, dependency))
        .collect::<Vec<_>>();
    for dependency in dependencies {
        contents.push_str(&format!("with {dependency};\n"));
    }
    if !contents.ends_with("\n\n") {
        contents.push('\n');
    }
}

fn is_self_or_ancestor_dependency(package_name: &str, dependency: &str) -> bool {
    package_name == dependency
        || package_name
            .strip_prefix(dependency)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn collect_declaration_dependencies(
    declaration: &Declaration,
    dependencies: &mut BTreeSet<String>,
) {
    match declaration {
        Declaration::Pragma(_) => {}
        Declaration::Struct(struct_decl) => {
            for field in &struct_decl.fields {
                collect_type_dependencies(&field.ty, dependencies);
            }
        }
        Declaration::Exception(exception) => {
            for field in &exception.fields {
                collect_type_dependencies(&field.ty, dependencies);
            }
        }
        Declaration::Typedef(typedef) => collect_type_dependencies(&typedef.ty, dependencies),
        Declaration::Const(const_decl) => collect_type_dependencies(&const_decl.ty, dependencies),
        Declaration::Union(union_decl) => {
            collect_type_dependencies(&union_decl.discriminator, dependencies);
            for arm in &union_decl.arms {
                collect_type_dependencies(&arm.field.ty, dependencies);
            }
        }
        Declaration::Module(_)
        | Declaration::Interface(_)
        | Declaration::Enum(_)
        | Declaration::ValueType(_)
        | Declaration::EventType(_) => {}
    }
}

fn collect_interface_dependencies(interface: &Interface) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    for member in &interface.members {
        match member {
            InterfaceMember::Operation(operation) => {
                collect_type_dependencies(&operation.return_type, &mut dependencies);
                for param in &operation.params {
                    collect_type_dependencies(&param.ty, &mut dependencies);
                }
            }
            InterfaceMember::Attribute(attribute) => {
                collect_type_dependencies(&attribute.ty, &mut dependencies);
            }
        }
    }
    dependencies
}

fn collect_type_dependencies(ty: &TypeRef, dependencies: &mut BTreeSet<String>) {
    match ty {
        TypeRef::Primitive(PrimitiveType::Octet) => {
            dependencies.insert("CORBA".to_owned());
        }
        TypeRef::Primitive(PrimitiveType::Any) => {
            dependencies.insert("CORBA.Any".to_owned());
        }
        TypeRef::Primitive(PrimitiveType::Object) => {
            dependencies.insert("CORBA.Object".to_owned());
        }
        TypeRef::Named(name) if name.parts.len() > 1 => {
            dependencies.insert(
                name.parts[..name.parts.len() - 1]
                    .iter()
                    .map(|part| ada_identifier(part))
                    .collect::<Vec<_>>()
                    .join("."),
            );
        }
        // An owned helper is declared inside its element's package, so the
        // dependency the use site needs is that package — already contributed by
        // the element itself — and never a standalone helper unit.
        TypeRef::Sequence { element, bound } => {
            collect_type_dependencies(element, dependencies);
            if type_owner_scope(ty).is_none() {
                dependencies.insert(sequence_package_name(element, *bound));
            }
        }
        TypeRef::Map { key, value, bound } => {
            collect_type_dependencies(key, dependencies);
            collect_type_dependencies(value, dependencies);
            if type_owner_scope(ty).is_none() {
                dependencies.insert(map_package_name(key, value, *bound));
            }
        }
        TypeRef::Array {
            element,
            dimensions,
        } => {
            collect_type_dependencies(element, dependencies);
            if type_owner_scope(ty).is_none() {
                dependencies.insert(array_package_name(element, dimensions));
            }
        }
        TypeRef::Void
        | TypeRef::Primitive(_)
        | TypeRef::Named(_)
        | TypeRef::String { .. }
        | TypeRef::Fixed { .. } => {}
    }
}

fn push_enum(contents: &mut String, enum_decl: &Enum) {
    let name = ada_identifier(&enum_decl.name);
    let variants = if enum_decl.variants.is_empty() {
        vec![format!("{name}_Value")]
    } else {
        enum_decl
            .variants
            .iter()
            .map(|variant| ada_identifier(variant))
            .collect::<Vec<_>>()
    };
    contents.push_str(&format!("   type {name} is ({});\n", variants.join(", ")));
}

fn push_struct(contents: &mut String, struct_decl: &Struct) {
    let name = ada_identifier(&struct_decl.name);
    if struct_decl.fields.is_empty() {
        contents.push_str(&format!("   type {name} is null record;\n"));
        return;
    }
    contents.push_str(&format!("   type {name} is record\n"));
    for field in &struct_decl.fields {
        push_field(contents, field);
    }
    contents.push_str("   end record;\n");
}

fn push_exception(contents: &mut String, exception: &Exception) {
    let name = ada_identifier(&exception.name);
    contents.push_str(&format!("   {name} : exception;\n"));
    for field in &exception.fields {
        contents.push_str(&format!(
            "   --  exception field {} : {}\n",
            ada_identifier(&field.name),
            render_type(&field.ty)
        ));
    }
}

fn push_typedef(contents: &mut String, typedef: &Typedef) {
    contents.push_str(&format!(
        "   subtype {} is {};\n",
        ada_identifier(&typedef.name),
        render_constrained_type(&typedef.ty)
    ));
}

fn push_const(contents: &mut String, const_decl: &Const) {
    contents.push_str(&format!(
        "   {} : constant {} := {};\n",
        ada_identifier(&const_decl.name),
        render_type(&const_decl.ty),
        render_const_value(&const_decl.value, &const_decl.ty)
    ));
}

fn push_attribute(contents: &mut String, attribute: &Attribute) {
    let name = ada_identifier(&attribute.name);
    let ty = render_type(&attribute.ty);
    contents.push_str(&format!("   function {name} (Self : Ref) return {ty};\n"));
    if !attribute.readonly {
        contents.push_str(&format!(
            "   procedure Set_{name} (Self : in out Ref; Value : {ty});\n"
        ));
    }
}

fn push_field(contents: &mut String, field: &Field) {
    contents.push_str(&format!(
        "      {} : {};\n",
        ada_identifier(&field.name),
        render_constrained_type(&field.ty)
    ));
}

fn push_raises_comment(contents: &mut String, operation: &Operation, scope: &[String]) {
    if operation.raises.is_empty() {
        return;
    }
    let names = operation
        .raises
        .iter()
        .map(|name| render_raise_name(name, scope))
        .collect::<Vec<_>>()
        .join(", ");
    contents.push_str(&format!("   --  raises {names}\n"));
}

fn render_raise_name(name: &ScopedName, scope: &[String]) -> String {
    if name.absolute || name.parts.len() > 1 || scope.is_empty() {
        render_scoped_name(name)
    } else {
        let mut parts = scope.to_vec();
        parts.push(ada_identifier(&name.parts[0]));
        parts.join(".")
    }
}

fn render_scoped_name(name: &ScopedName) -> String {
    name.parts
        .iter()
        .map(|part| ada_identifier(part))
        .collect::<Vec<_>>()
        .join(".")
}

/// Render an IDL constant as an Ada expression of `ty`.
///
/// The AST keeps literals as raw IDL lexemes, which are not Ada: `'\n'`, `.5`,
/// `1.` and `L"wide"` are all rejected by GNAT, and an unescaped `"` inside a
/// string ends the literal early. Everything is translated here, where the
/// target type is known — the same lexeme means a character or a string
/// depending on it.
fn render_const_value(value: &ConstValue, ty: &TypeRef) -> String {
    match value {
        ConstValue::Integer(value) => value.to_string(),
        ConstValue::Float(value) => render_ada_real(value),
        ConstValue::String(value) => {
            let decoded = decode_idl_literal(value);
            if is_character_type(ty) {
                render_ada_character(&decoded)
            } else {
                render_ada_string(&decoded)
            }
        }
        ConstValue::Boolean(true) => "True".to_owned(),
        ConstValue::Boolean(false) => "False".to_owned(),
        ConstValue::ScopedName(name) => render_scoped_name(name),
    }
}

fn is_character_type(ty: &TypeRef) -> bool {
    matches!(
        ty,
        TypeRef::Primitive(PrimitiveType::Char | PrimitiveType::WChar)
    )
}

/// Normalise an IDL floating literal into an Ada real literal. Ada requires a
/// digit on each side of the point (`.5` and `1.` are errors) and has no `d`/`f`
/// fixed-point suffix.
fn render_ada_real(text: &str) -> String {
    let text = text.trim();
    let (sign, magnitude) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text.strip_prefix('+').unwrap_or(text)),
    };
    let magnitude = magnitude.trim_end_matches(['d', 'D', 'f', 'F']);
    let (mantissa, exponent) = match magnitude.find(['e', 'E']) {
        Some(index) => (&magnitude[..index], &magnitude[index..]),
        None => (magnitude, ""),
    };
    let mantissa = match mantissa.split_once('.') {
        Some((whole, fraction)) => format!(
            "{}.{}",
            if whole.is_empty() { "0" } else { whole },
            if fraction.is_empty() { "0" } else { fraction }
        ),
        None if mantissa.is_empty() => "0.0".to_owned(),
        None => format!("{mantissa}.0"),
    };
    format!("{sign}{mantissa}{exponent}")
}

/// The largest code point the generated `Standard.Character` can hold.
const MAX_ADA_CHARACTER: u32 = 255;

/// An Ada character literal, or `Character'Val` for the control characters Ada
/// forbids inside one.
fn render_ada_character(value: &str) -> String {
    let Some(ch) = value.chars().next() else {
        return "Character'Val (0)".to_owned();
    };
    match ch {
        // An apostrophe is spelled as itself between two more apostrophes.
        '\'' => "'''".to_owned(),
        ch if is_ada_graphic(ch) => format!("'{ch}'"),
        ch => format!("Character'Val ({})", clamp_ada_code_point(ch)),
    }
}

/// An Ada string expression. Ada string literals hold graphic characters only,
/// so control characters are concatenated in with `Character'Val`.
fn render_ada_string(value: &str) -> String {
    let mut parts = Vec::new();
    let mut run = String::new();
    for ch in value.chars() {
        if is_ada_graphic(ch) {
            if ch == '"' {
                run.push('"');
            }
            run.push(ch);
            continue;
        }
        if !run.is_empty() {
            parts.push(format!("\"{run}\""));
            run.clear();
        }
        parts.push(format!("Character'Val ({})", clamp_ada_code_point(ch)));
    }
    if !run.is_empty() {
        parts.push(format!("\"{run}\""));
    }
    if parts.is_empty() {
        return "\"\"".to_owned();
    }
    parts.join(" & ")
}

fn is_ada_graphic(ch: char) -> bool {
    matches!(ch, ' '..='~') || matches!(ch, '\u{a0}'..='\u{ff}')
}

/// Wide literals can name code points the 8-bit `Standard.Character` cannot
/// hold; `?` keeps the constant compilable. `collect_wide_literal_warnings`
/// reports every constant this affects.
fn clamp_ada_code_point(ch: char) -> u32 {
    let value = ch as u32;
    if value > MAX_ADA_CHARACTER {
        u32::from(b'?')
    } else {
        value
    }
}

fn collect_version_pragmas(declarations: &[Declaration]) -> BTreeMap<Vec<String>, String> {
    let mut versions = BTreeMap::new();
    collect_version_pragmas_in_scope(declarations, &[], &mut versions);
    versions
}

fn collect_version_pragmas_in_scope(
    declarations: &[Declaration],
    scope: &[String],
    versions: &mut BTreeMap<Vec<String>, String>,
) {
    for declaration in declarations {
        match declaration {
            Declaration::Pragma(pragma) => {
                if let IdlPragmaKind::Version { target, version } = &pragma.kind {
                    versions.insert(scoped_name_key(scope, target), version.clone());
                }
            }
            Declaration::Module(module) => {
                let mut module_scope = scope.to_vec();
                module_scope.push(module.name.clone());
                collect_version_pragmas_in_scope(&module.declarations, &module_scope, versions);
            }
            _ => {}
        }
    }
}

fn apply_pragma_state(pragma: &IdlPragma, state: &mut PragmaState) {
    if let IdlPragmaKind::Prefix(prefix) = &pragma.kind {
        state.prefix = Some(prefix.clone());
    }
}

fn repository_id_for(
    scoped_name: &[String],
    state: &PragmaState,
    version_pragmas: &BTreeMap<Vec<String>, String>,
) -> Option<String> {
    let version = version_pragmas.get(scoped_name);
    if state.prefix.is_none() && version.is_none() {
        return None;
    }
    let version = version.map(String::as_str).unwrap_or("1.0");
    let mut parts = Vec::new();
    if let Some(prefix) = &state.prefix {
        let trimmed = prefix.trim_matches('/');
        if !trimmed.is_empty() {
            parts.push(trimmed.to_owned());
        }
    }
    parts.extend(scoped_name.iter().cloned());
    Some(format!("IDL:{}:{version}", parts.join("/")))
}

fn scoped_name_key(scope: &[String], name: &ScopedName) -> Vec<String> {
    if name.absolute {
        name.parts.clone()
    } else {
        let mut parts = scope.to_vec();
        parts.extend(name.parts.iter().cloned());
        parts
    }
}

fn declaration_name(declaration: &Declaration) -> Option<&str> {
    match declaration {
        Declaration::Module(module) => Some(&module.name),
        Declaration::Interface(interface) => Some(&interface.name),
        Declaration::Struct(struct_decl) => Some(&struct_decl.name),
        Declaration::Enum(enum_decl) => Some(&enum_decl.name),
        Declaration::Exception(exception) => Some(&exception.name),
        Declaration::Typedef(typedef) => Some(&typedef.name),
        Declaration::Const(const_decl) => Some(&const_decl.name),
        Declaration::Union(union_decl) => Some(&union_decl.name),
        Declaration::ValueType(value_type) => Some(&value_type.name),
        Declaration::EventType(event_type) => Some(&event_type.name),
        Declaration::Pragma(_) => None,
    }
}

fn push_repository_id_constant(contents: &mut String, name: &str, repository_id: &str) {
    contents.push_str(&format!(
        "   {name} : constant String := {};\n",
        ada_string_literal(repository_id)
    ));
}

fn ada_string_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn ada_identifier(value: &str) -> String {
    let mut result = String::new();
    for (index, ch) in value.chars().enumerate() {
        if (index == 0 && ch.is_ascii_alphabetic())
            || (index > 0 && (ch.is_ascii_alphanumeric() || ch == '_'))
        {
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    // Ada permits neither two consecutive underlines nor a trailing one, so
    // `a__b` and `value_` — both ordinary IDL names — have to be repaired.
    let mut result = collapse_underscores(&result);
    while result.ends_with('_') {
        result.pop();
    }
    if result.is_empty()
        || !result
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
    {
        result.insert_str(0, "Id");
    }
    if is_ada_reserved_word(&result) {
        result.push_str("_Id");
    }
    result
}

fn collapse_underscores(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '_' && collapsed.ends_with('_') {
            continue;
        }
        collapsed.push(ch);
    }
    collapsed
}

fn is_ada_reserved_word(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "abort"
            | "abs"
            | "abstract"
            | "accept"
            | "access"
            | "aliased"
            | "all"
            | "and"
            | "array"
            | "at"
            | "begin"
            | "body"
            | "case"
            | "constant"
            | "declare"
            | "delay"
            | "delta"
            | "digits"
            | "do"
            | "else"
            | "elsif"
            | "end"
            | "entry"
            | "exception"
            | "exit"
            | "for"
            | "function"
            | "generic"
            | "goto"
            | "if"
            | "in"
            | "interface"
            | "is"
            | "limited"
            | "loop"
            | "mod"
            | "new"
            | "not"
            | "null"
            | "of"
            | "or"
            | "others"
            | "out"
            | "overriding"
            | "package"
            | "parallel"
            | "pragma"
            | "private"
            | "procedure"
            | "protected"
            | "raise"
            | "range"
            | "record"
            | "rem"
            | "renames"
            | "requeue"
            | "return"
            | "reverse"
            | "select"
            | "separate"
            | "some"
            | "subtype"
            | "synchronized"
            | "tagged"
            | "task"
            | "terminate"
            | "then"
            | "type"
            | "until"
            | "use"
            | "when"
            | "while"
            | "with"
            | "xor"
    )
}

fn generated_unit(package_name: &str, contents: String) -> GeneratedAdaUnit {
    GeneratedAdaUnit {
        package_name: package_name.to_owned(),
        relative_path: format!(
            "{}.ads",
            package_name.replace('.', "-").to_ascii_lowercase()
        )
        .into(),
        contents,
    }
}

fn generated_body_unit(package_name: &str, contents: String) -> GeneratedAdaUnit {
    GeneratedAdaUnit {
        package_name: package_name.to_owned(),
        relative_path: format!(
            "{}.adb",
            package_name.replace('.', "-").to_ascii_lowercase()
        )
        .into(),
        contents,
    }
}

fn is_body_unit(unit: &GeneratedAdaUnit) -> bool {
    unit.relative_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("adb"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_interface_helper_skel_and_stub_packages() {
        let ast = crate::parse_idl(
            "module Demo { interface Calculator { long Add(in long Left, in long Right); }; };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let names = output
            .units
            .iter()
            .filter(|unit| !is_body_unit(unit))
            .map(|unit| unit.package_name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "Demo",
                "Demo.Calculator",
                "Demo.Calculator.Helper",
                "Demo.Calculator.Skel",
                "Demo.Calculator.Stub",
            ]
        );
        assert!(unit(&output, "Demo.Calculator")
            .contents
            .contains("function Add (Left : Integer; Right : Integer) return Integer;"));
        assert!(unit(&output, "Demo.Calculator").contents.contains(
            "function Add (Self : Ref; Left : Integer; Right : Integer) return Integer;"
        ));
        assert!(unit(&output, "Demo.Calculator.Helper")
            .contents
            .contains("function From_Any"));
        assert!(unit(&output, "Demo.Calculator.Skel")
            .contents
            .contains("procedure Dispatch"));
        assert!(unit(&output, "Demo.Calculator.Stub")
            .contents
            .contains("function Add"));
        assert!(output
            .units
            .iter()
            .any(|unit| unit.relative_path == Path::new("demo-calculator.adb")));
        assert!(output
            .units
            .iter()
            .any(|unit| unit.relative_path == Path::new("demo-calculator-helper.adb")));
    }

    fn unit<'a>(output: &'a AdaEmitOutput, name: &str) -> &'a GeneratedAdaUnit {
        output
            .units
            .iter()
            .find(|unit| unit.package_name == name)
            .unwrap_or_else(|| panic!("{name} unit is emitted"))
    }

    #[test]
    fn emits_common_idl_declarations_as_parseable_ada() {
        let ast = crate::parse_idl(
            "module Demo {
                enum Color { Red, Green };
                struct Point { long X; string Name; };
                exception BadInput { long Code; };
                typedef sequence<long> Long_List;
                const long Limit = 7;
                interface Calculator {
                    attribute string Name;
                    readonly attribute long Version;
                    void Reset(inout long Count) raises(BadInput);
                };
            };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let demo = &unit(&output, "Demo").contents;
        assert!(demo.contains("type Color is (Red, Green);"));
        assert!(demo.contains("type Point is record"));
        assert!(demo.contains("BadInput : exception;"));
        assert!(demo.contains("subtype Long_List is Sequence_Of_Integer.Sequence;"));
        assert!(demo.contains("Limit : constant Integer := 7;"));

        let iface = &unit(&output, "Demo.Calculator").contents;
        assert!(iface.contains("function Name (Self : Ref) return Standard.String;"));
        assert!(iface.contains("procedure Set_Name (Self : in out Ref; Value : Standard.String);"));
        assert!(iface.contains("function Version (Self : Ref) return Integer;"));
        assert!(!iface.contains("Set_Version"));
        assert!(iface.contains("procedure Reset (Self : in out Ref; Count : in out Integer);"));
        assert!(iface.contains("--  raises Demo.BadInput"));

        assert_generated_units_parse(&output);
    }

    #[test]
    fn escapes_ada_reserved_words_in_generated_identifiers() {
        let ast = crate::parse_idl(
            "module Demo {
                struct String { long type; };
                struct Range { String protected; };
            };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let demo = &unit(&output, "Demo").contents;

        assert!(demo.contains("type String is record"));
        assert!(demo.contains("type_Id : Integer;"));
        assert!(demo.contains("type Range_Id is record"));
        // Constrained: Ada rejects an unconstrained subtype as a component.
        assert!(
            demo.contains("protected_Id : Standard.String (1 .. 1);"),
            "{demo}"
        );
        assert_generated_units_parse(&output);
    }

    #[test]
    fn renders_idl_literals_as_valid_ada_expressions() {
        let ast = crate::parse_idl(
            r#"module Lits {
                 const char   NL = '\n';
                 const char   A  = 'A';
                 const char   Q  = '\'';
                 const string S1 = "say \"hi\"";
                 const string S2 = "C:\\tmp";
                 const wstring W = L"wide";
                 const wchar  WC = L'a';
                 const double D1 = 1.;
                 const double D2 = .5;
                 const double D3 = 1.5d;
                 const double D4 = 3.40023E+16;
               };"#,
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let lits = &unit(&output, "Lits").contents;

        // A control character cannot sit inside an Ada literal.
        assert!(lits.contains("NL : constant Standard.Character := Character'Val (10);"));
        assert!(lits.contains("A : constant Standard.Character := 'A';"));
        assert!(lits.contains("Q : constant Standard.Character := ''';"));
        // Ada doubles an embedded quote and has no backslash escapes.
        assert!(lits.contains(r#"S1 : constant Standard.String := "say ""hi""";"#));
        assert!(lits.contains(r#"S2 : constant Standard.String := "C:\tmp";"#));
        // The wide prefix marks the literal, it is not part of the value.
        assert!(lits.contains(r#"W : constant Standard.String := "wide";"#));
        assert!(lits.contains("WC : constant Standard.Character := 'a';"));
        // Ada needs a digit on both sides of the point and has no `d` suffix.
        assert!(lits.contains("D1 : constant Long_Float := 1.0;"));
        assert!(lits.contains("D2 : constant Long_Float := 0.5;"));
        assert!(lits.contains("D3 : constant Long_Float := 1.5;"));
        assert!(lits.contains("D4 : constant Long_Float := 3.40023E+16;"));
    }

    #[test]
    fn repairs_identifiers_ada_rejects() {
        let ast = crate::parse_idl("module Ids { struct S { long value_; long a__b; }; };")
            .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let ids = &unit(&output, "Ids").contents;

        assert!(ids.contains("value : Integer;"), "{ids}");
        assert!(ids.contains("a_b : Integer;"), "{ids}");
    }

    #[test]
    fn maps_arrays_to_constrained_ada_array_types() {
        let ast = crate::parse_idl(
            "module Pkt { const long N = 3; struct P { octet raw[16]; long grid[2][N]; }; };",
        )
        .expect("IDL parses");
        let output = emit_ada_packages(&ast);

        // An array over a primitive cannot form a `with` cycle, so it keeps a
        // unit of its own and the field names the type it exports.
        let pkt = &unit(&output, "Pkt").contents;
        assert!(
            pkt.contains("raw : Array_Of_CORBA_Octet_16.Value;"),
            "{pkt}"
        );
        assert!(pkt.contains("grid : Array_Of_Integer_2x3.Value;"), "{pkt}");

        let raw = &unit(&output, "Array_Of_CORBA_Octet_16").contents;
        assert!(
            raw.contains("type Value is array (1 .. 16) of CORBA.Octet;"),
            "{raw}"
        );
        let grid = &unit(&output, "Array_Of_Integer_2x3").contents;
        assert!(
            grid.contains("type Value is array (1 .. 2, 1 .. 3) of Integer;"),
            "{grid}"
        );
        assert_generated_units_parse(&output);
    }

    #[test]
    fn declares_helpers_over_module_types_inside_that_module() {
        // A standalone `Sequence_Of_Tel_Reading` would have to `with Tel` while
        // `Tel` withs it back, which Ada rejects as a circular dependency.
        let ast = crate::parse_idl(
            "module Tel {
               struct Reading { long v; };
               typedef sequence<Reading> Readings;
               struct Sample { Readings rs; };
             };",
        )
        .expect("IDL parses");
        let output = emit_ada_packages(&ast);

        assert!(
            !output
                .units
                .iter()
                .any(|item| item.package_name == "Sequence_Of_Tel_Reading"),
            "the helper must not be a unit of its own"
        );
        let tel = &unit(&output, "Tel").contents;
        assert!(!tel.contains("with Sequence_Of_Tel_Reading;"), "{tel}");
        // Declared after its element type and before the typedef that uses it.
        let element = tel.find("type Reading is record").expect("element type");
        let helper = tel
            .find("type Sequence_Of_Tel_Reading is record")
            .expect("helper type");
        let user = tel.find("subtype Readings is").expect("typedef");
        assert!(element < helper && helper < user, "{tel}");
        assert_generated_units_parse(&output);
    }

    #[test]
    fn qualifies_named_types_so_they_survive_a_same_named_component() {
        // Ada identifiers are case-insensitive, so a bare `Name` inside the
        // record resolves to the component being declared, not the type.
        let ast = crate::parse_idl("module Tel { typedef string Name; struct S { Name name; }; };")
            .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let tel = &unit(&output, "Tel").contents;

        assert!(tel.contains("name : Tel.Name;"), "{tel}");
    }

    #[test]
    fn constrains_string_components_and_keeps_their_idl_bound() {
        let ast =
            crate::parse_idl("module Tel { struct S { string free; string<32> bounded; }; };")
                .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let tel = &unit(&output, "Tel").contents;

        assert!(
            tel.contains("bounded : Standard.String (1 .. 32);"),
            "{tel}"
        );
        assert!(tel.contains("free : Standard.String (1 .. 1);"), "{tel}");
    }

    #[test]
    fn emits_declarations_outside_every_module_into_a_root_package() {
        // Ada has no global type scope, so these used to be dropped: the file
        // generated no unit at all, and a sequence over one of them referenced
        // an undefined type.
        let ast = crate::parse_idl(
            "const long LIMIT = 5;
             struct Reading { long v; };
             typedef sequence<Reading> Readings;
             struct Sample { Readings rs; };",
        )
        .expect("IDL parses");
        let output = emit_ada_packages(&ast);

        let root = &unit(&output, "IDL_Global").contents;
        assert!(root.contains("LIMIT : constant Integer := 5;"), "{root}");
        assert!(root.contains("type Reading is record"), "{root}");
        assert!(
            root.contains("subtype Readings is IDL_Global.Sequence_Of_IDL_Global_Reading;"),
            "{root}"
        );
        assert!(root.contains("rs : IDL_Global.Readings;"), "{root}");
        assert!(
            !output
                .warnings
                .iter()
                .any(|warning| warning.contains("referenced but not mapped")),
            "{:?}",
            output.warnings
        );
        assert_generated_units_parse(&output);
    }

    #[test]
    fn root_package_keeps_the_global_idl_scope_in_repository_ids() {
        let ast = crate::parse_idl(
            "#pragma prefix \"acme.example\"\nstruct Top { long t; };\ninterface I { Top get(); };",
        )
        .expect("IDL parses");
        let output = emit_ada_packages(&ast);

        let root = &unit(&output, "IDL_Global").contents;
        // The synthetic package is not an IDL scope, so it names neither the
        // package-level id nor the declaration's.
        assert!(
            root.contains("Repository_Id_Top : constant String := \"IDL:acme.example/Top:1.0\";"),
            "{root}"
        );
        assert!(!root.contains("Repository_Id : constant"), "{root}");
        assert!(
            unit(&output, "I")
                .contents
                .contains("return IDL_Global.Top;"),
            "the interface reaches the root package"
        );
    }

    #[test]
    fn root_package_steps_aside_for_a_module_of_the_same_name() {
        let ast = crate::parse_idl(
            "module IDL_Global { struct A { long a; }; }; struct Top { long t; };",
        )
        .expect("IDL parses");
        let output = emit_ada_packages(&ast);

        assert!(unit(&output, "IDL_Global").contents.contains("type A is"));
        assert!(unit(&output, "IDL_Global_2")
            .contents
            .contains("type Top is"));
    }

    #[test]
    fn no_root_package_when_every_declaration_lives_in_a_module() {
        let ast = crate::parse_idl("module M { struct A { long a; }; };").expect("IDL parses");
        let output = emit_ada_packages(&ast);

        assert!(
            !output
                .units
                .iter()
                .any(|item| item.package_name.starts_with("IDL_Global")),
            "{:?}",
            output
                .units
                .iter()
                .map(|item| &item.package_name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn reports_types_the_mapping_could_not_resolve() {
        let ast =
            crate::parse_idl("module Tel { struct S { External e; }; };").expect("IDL parses");

        let output = emit_ada_packages(&ast);

        assert!(
            output
                .warnings
                .contains(&"IDL type 'External' is referenced but not mapped".to_owned()),
            "{:?}",
            output.warnings
        );
    }

    fn assert_generated_units_parse(output: &AdaEmitOutput) {
        for unit in &output.units {
            ada_parser::reconcile::build_structural_ast(&unit.contents, None, &unit.relative_path)
                .unwrap_or_else(|error| panic!("{} parses: {error}", unit.relative_path.display()));
        }
    }

    #[test]
    fn dedupes_sequence_helper_packages() {
        let ast = crate::parse_idl(
            "module Demo {
                typedef sequence<long> First;
                typedef sequence<long> Second;
                interface I { void Use(in sequence<long> Values); };
            };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let sequence_units = output
            .units
            .iter()
            .filter(|unit| unit.package_name == "Sequence_Of_Integer")
            .count();

        assert_eq!(sequence_units, 1);
        assert!(unit(&output, "Sequence_Of_Integer")
            .contents
            .contains("type Sequence is record"));
    }

    #[test]
    fn emits_map_types_as_parseable_placeholders() {
        let ast = crate::parse_idl(
            "module Demo {
                typedef map<string, long, 8> Counts;
                struct Sample { map<string, sequence<long>> Buckets; };
                interface I { Counts Get_Counts(); };
            };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let demo = &unit(&output, "Demo").contents;

        assert!(demo.contains("subtype Counts is Map_String_To_Integer_Bound_8.Map;"));
        assert!(demo.contains("Buckets : Map_String_To_Sequence_Of_Integer.Map;"));
        assert!(unit(&output, "Map_String_To_Integer_Bound_8")
            .contents
            .contains("type Map is record"));
        assert_generated_units_parse(&output);
    }

    #[test]
    fn emits_context_clauses_for_external_mapping_dependencies() {
        let ast = crate::parse_idl(
            "module Demo {
                typedef sequence<long> Long_List;
                interface Calculator {
                    any Echo(in Object Obj, in sequence<long> Values);
                };
            };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let demo = &unit(&output, "Demo").contents;
        let iface = &unit(&output, "Demo.Calculator").contents;
        let helper = &unit(&output, "Demo.Calculator.Helper").contents;
        let stub = &unit(&output, "Demo.Calculator.Stub").contents;

        assert_with_before_package(demo, "with Sequence_Of_Integer;");
        assert_with_before_package(iface, "with CORBA.Any;");
        assert_with_before_package(iface, "with CORBA.Object;");
        assert_with_before_package(iface, "with Sequence_Of_Integer;");
        assert_with_before_package(helper, "with CORBA.Any;");
        assert_with_before_package(stub, "with CORBA.Any;");
        assert_with_before_package(stub, "with CORBA.Object;");
        assert_with_before_package(stub, "with Sequence_Of_Integer;");
        assert_generated_units_parse(&output);
    }

    #[test]
    fn emits_repository_ids_from_prefix_and_version_pragmas() {
        let ast = crate::parse_idl(
            "#pragma prefix \"acme.example\"\nmodule Demo {\n#pragma version Calculator 2.1\ninterface Calculator {};\nstruct Point { long X; };\n};",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let demo = &unit(&output, "Demo").contents;
        let iface = &unit(&output, "Demo.Calculator").contents;
        let helper = &unit(&output, "Demo.Calculator.Helper").contents;

        assert!(demo.contains(
            "Repository_Id_Point : constant String := \"IDL:acme.example/Demo/Point:1.0\";"
        ));
        assert!(iface.contains(
            "Repository_Id : constant String := \"IDL:acme.example/Demo/Calculator:2.1\";"
        ));
        assert!(helper.contains(
            "Repository_Id : constant String := \"IDL:acme.example/Demo/Calculator:2.1\";"
        ));
        assert_generated_units_parse(&output);
    }

    #[test]
    fn merges_reopened_modules_before_emitting_ada_units() {
        let ast = crate::parse_idl(
            "#pragma prefix \"legacy.example\"
             module Legacy { module Telemetry { struct Reading { long Id; }; }; };
             module Legacy {
                module Telemetry {
                   #pragma version Monitor 2.4
                   interface Monitor { Reading Latest(in Object Source); };
                };
             };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        let telemetry_units = output
            .units
            .iter()
            .filter(|unit| unit.package_name == "Legacy.Telemetry")
            .count();

        assert_eq!(telemetry_units, 1);
        let telemetry = &unit(&output, "Legacy.Telemetry").contents;
        assert!(telemetry.contains("type Reading is record"));
        assert!(telemetry.contains(
            "Repository_Id_Monitor : constant String := \"IDL:legacy.example/Legacy/Telemetry/Monitor:2.4\";"
        ));
        assert_generated_units_parse(&output);
    }

    #[test]
    fn merging_reopened_modules_preserves_intervening_prefix_pragmas() {
        let ast = crate::parse_idl(
            "#pragma prefix \"old.example\"
             module Legacy {
                interface OldIface {};
                module Telemetry { struct Reading { long Id; }; };
             };
             #pragma prefix \"new.example\"
             module Legacy {
                interface NewIface {};
                module Telemetry { interface Monitor {}; };
             };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);

        assert!(unit(&output, "Legacy.OldIface").contents.contains(
            "Repository_Id : constant String := \"IDL:old.example/Legacy/OldIface:1.0\";"
        ));
        assert!(unit(&output, "Legacy.OldIface.Helper").contents.contains(
            "Repository_Id : constant String := \"IDL:old.example/Legacy/OldIface:1.0\";"
        ));
        assert!(unit(&output, "Legacy.NewIface").contents.contains(
            "Repository_Id : constant String := \"IDL:new.example/Legacy/NewIface:1.0\";"
        ));
        assert!(unit(&output, "Legacy.NewIface.Helper").contents.contains(
            "Repository_Id : constant String := \"IDL:new.example/Legacy/NewIface:1.0\";"
        ));
        assert!(unit(&output, "Legacy.Telemetry.Monitor").contents.contains(
            "Repository_Id : constant String := \"IDL:new.example/Legacy/Telemetry/Monitor:1.0\";"
        ));
        assert!(unit(&output, "Legacy.Telemetry")
            .contents
            .contains("Repository_Id_Monitor : constant String := \"IDL:new.example/Legacy/Telemetry/Monitor:1.0\";"));
        assert_generated_units_parse(&output);
    }

    #[test]
    fn emits_ada_2005_safe_function_return_stubs() {
        let ast = crate::parse_idl(
            "module Legacy {
                module Telemetry {
                   struct Reading { long Id; };
                   interface Monitor {
                      attribute string Name;
                      Reading Latest(in Object Source);
                      any Snapshot(in sequence<::Legacy::Telemetry::Reading, 8> Values);
                   };
                };
             };",
        )
        .expect("IDL parses");

        let output = emit_ada_packages(&ast);
        for unit in output.units.iter().filter(|unit| {
            unit.relative_path
                .extension()
                .is_some_and(|ext| ext == "adb")
        }) {
            assert!(
                !unit.contents.contains("return raise Program_Error"),
                "{} must not use Ada 2012 raise expressions",
                unit.relative_path.display()
            );
        }
        let monitor_body = &body_unit(&output, "Legacy.Telemetry.Monitor").contents;
        // Fully qualified: a bare `Reading` is undefined in a standalone
        // sequence package and clashes with any same-named component.
        assert!(
            monitor_body.contains("Result : Legacy.Telemetry.Reading;"),
            "{monitor_body}"
        );
        assert!(monitor_body.contains("return \"\";"));
        assert!(monitor_body.contains("return CORBA.Any.Value'(null record);"));
        assert_generated_units_parse(&output);
    }

    fn body_unit<'a>(output: &'a AdaEmitOutput, name: &str) -> &'a GeneratedAdaUnit {
        output
            .units
            .iter()
            .find(|unit| unit.package_name == name && is_body_unit(unit))
            .unwrap_or_else(|| panic!("{name} body unit is emitted"))
    }

    fn assert_with_before_package(contents: &str, with_clause: &str) {
        let with_index = contents
            .find(with_clause)
            .unwrap_or_else(|| panic!("{with_clause} is emitted"));
        let package_index = contents
            .find("package ")
            .expect("package declaration is emitted");
        assert!(
            with_index < package_index,
            "{with_clause} must appear before package declaration"
        );
    }

    #[test]
    fn write_generated_ada_units_writes_relative_paths() {
        let temp = temp_dir("write-units");
        let units = vec![GeneratedAdaUnit {
            package_name: "Demo.Calculator.Helper".to_owned(),
            relative_path: "demo-calculator-helper.ads".into(),
            contents: "package Demo.Calculator.Helper is end Demo.Calculator.Helper;\n".to_owned(),
        }];

        let written = write_generated_ada_units(&temp, &units).expect("units write");

        assert_eq!(written, vec![temp.join("demo-calculator-helper.ads")]);
        assert!(temp.join("demo-calculator-helper.ads").is_file());
        std::fs::remove_dir_all(temp).expect("temporary dir is removed");
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-idl-ada-emit-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).expect("temporary directory is created");
        dir
    }
}
