// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Attribute, Const, ConstValue, Declaration, Enum, Exception, Field, IdlFile, IdlPragma,
    IdlPragmaKind, Interface, InterfaceMember, Module, Operation, Param, ParamDirection,
    PrimitiveType, ScopedName, Struct, TypeRef, Typedef,
};
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
    emitter.warnings.extend(idl.warnings.iter().cloned());
    emitter.version_pragmas = collect_version_pragmas(&declarations);
    emitter.collect_sequences(&declarations);
    emitter.walk_declarations(&declarations, &[], &[], &PragmaState::default());
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
            | Declaration::EventType(_) => merged.push(declaration.clone()),
        }
    }
    merged
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
    version_pragmas: BTreeMap<Vec<String>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SequenceInfo {
    element_type: String,
    dependencies: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapInfo {
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
                Declaration::Const(const_decl) => self.collect_type(&const_decl.ty),
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

    fn collect_type(&mut self, ty: &TypeRef) {
        match ty {
            TypeRef::Sequence { element, bound } => {
                self.collect_type(element);
                let package_name = sequence_package_name(element, *bound);
                self.sequences.entry(package_name).or_insert_with(|| {
                    let mut dependencies = BTreeSet::new();
                    collect_type_dependencies(element, &mut dependencies);
                    SequenceInfo {
                        element_type: render_type(element),
                        dependencies,
                    }
                });
            }
            TypeRef::Map { key, value, bound } => {
                self.collect_type(key);
                self.collect_type(value);
                let package_name = map_package_name(key, value, *bound);
                self.maps.entry(package_name).or_insert_with(|| {
                    let mut dependencies = BTreeSet::new();
                    collect_type_dependencies(key, &mut dependencies);
                    collect_type_dependencies(value, &mut dependencies);
                    MapInfo {
                        key_type: render_type(key),
                        value_type: render_type(value),
                        dependencies,
                    }
                });
            }
            TypeRef::Array {
                element,
                dimensions,
            } => {
                self.collect_type(element);
                self.warnings.push(format!(
                    "array dimensions [{}] mapped to element type placeholder",
                    dimensions
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
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
        self.units.push(generated_unit(
            &package_name,
            render_module_package(
                &package_name,
                module,
                &module_idl_scope,
                state,
                &self.version_pragmas,
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

    fn emit_sequence_units(&mut self) {
        for (package_name, info) in &self.sequences {
            self.units.push(generated_unit(
                package_name,
                render_sequence_package(package_name, info),
            ));
        }
        for (package_name, info) in &self.maps {
            self.units.push(generated_unit(
                package_name,
                render_map_package(package_name, info),
            ));
        }
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
) -> String {
    let mut dependencies = BTreeSet::new();
    for declaration in &module.declarations {
        collect_declaration_dependencies(declaration, &mut dependencies);
    }
    let mut contents = String::new();
    push_header_and_context(&mut contents, package_name, dependencies);
    contents.push_str(&format!("package {package_name} is\n"));
    if let Some(repository_id) = repository_id_for(idl_scope, state, version_pragmas) {
        push_repository_id_constant(&mut contents, "Repository_Id", &repository_id);
    }
    let mut local_state = state.clone();
    for declaration in &module.declarations {
        if let Declaration::Pragma(pragma) = declaration {
            apply_pragma_state(pragma, &mut local_state);
            continue;
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
    contents.push_str(&format!("end {package_name};\n"));
    contents
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
            format!("{}.Sequence", sequence_package_name(element, *bound))
        }
        TypeRef::Map { key, value, bound } => {
            format!("{}.Map", map_package_name(key, value, *bound))
        }
        TypeRef::Array { element, .. } => render_type(element),
        TypeRef::String { .. } => "Standard.String".to_owned(),
        TypeRef::Fixed { .. } => "Long_Float".to_owned(),
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
        TypeRef::Sequence { element, bound } => {
            collect_type_dependencies(element, dependencies);
            dependencies.insert(sequence_package_name(element, *bound));
        }
        TypeRef::Map { key, value, bound } => {
            collect_type_dependencies(key, dependencies);
            collect_type_dependencies(value, dependencies);
            dependencies.insert(map_package_name(key, value, *bound));
        }
        TypeRef::Array { element, .. } => {
            collect_type_dependencies(element, dependencies);
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
        render_type(&typedef.ty)
    ));
}

fn push_const(contents: &mut String, const_decl: &Const) {
    contents.push_str(&format!(
        "   {} : constant {} := {};\n",
        ada_identifier(&const_decl.name),
        render_type(&const_decl.ty),
        render_const_value(&const_decl.value)
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
        render_type(&field.ty)
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

fn render_const_value(value: &ConstValue) -> String {
    match value {
        ConstValue::Integer(value) => value.to_string(),
        ConstValue::Float(value) | ConstValue::String(value) => value.clone(),
        ConstValue::Boolean(true) => "True".to_owned(),
        ConstValue::Boolean(false) => "False".to_owned(),
        ConstValue::ScopedName(name) => render_scoped_name(name),
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
        assert!(demo.contains("protected_Id : Standard.String;"));
        assert_generated_units_parse(&output);
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
        assert!(monitor_body.contains("Result : Reading;"));
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
