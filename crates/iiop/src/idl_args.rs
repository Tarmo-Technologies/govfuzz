// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use idl_parser::{
    Declaration, IdlFile, IdlPragma, IdlPragmaKind, Interface, InterfaceMember, ParamDirection,
    PrimitiveType, ScopedName, TypeRef,
};

use crate::cdr::{CdrError, CdrReader};
use crate::giop::ParsedRequest12;

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedRequestArguments<'a> {
    pub repository_id: Option<String>,
    pub interface: String,
    pub operation: String,
    pub raw_arguments: &'a [u8],
    pub arguments: Vec<DecodedArgument>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedArgument {
    pub name: String,
    pub direction: ParamDirection,
    pub ty: TypeRef,
    pub span: Range<usize>,
    pub value: DecodedArgumentValue,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedArgumentValue {
    Boolean(bool),
    Char(u8),
    Octet(u8),
    Short(i16),
    UShort(u16),
    Long(i32),
    ULong(u32),
    LongLong(i64),
    ULongLong(u64),
    Float(f32),
    Double(f64),
    String(String),
    Sequence(Vec<DecodedArgumentValue>),
    ObjectReference { type_id: String, profile_count: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdlOperationCatalog {
    operations: Vec<IdlOperationMetadata>,
    interface_scopes: Vec<Vec<String>>,
}

impl IdlOperationCatalog {
    pub fn from_idl_file(file: &IdlFile) -> Self {
        let mut version_pragmas = BTreeMap::new();
        collect_version_pragmas(&file.declarations, &[], &mut version_pragmas);

        let mut catalog = Self {
            operations: Vec::new(),
            interface_scopes: Vec::new(),
        };
        let mut state = PragmaState::default();
        for pragma in &file.pragmas {
            apply_pragma_state(pragma, &mut state);
        }
        collect_operations(
            &file.declarations,
            &[],
            &mut state,
            &version_pragmas,
            &mut catalog,
        );
        catalog
    }

    pub fn lookup_operation(
        &self,
        operation: &str,
    ) -> Result<&IdlOperationMetadata, IdlArgumentDecodeError> {
        let mut matches = self
            .operations
            .iter()
            .filter(|candidate| candidate.operation == operation);
        let Some(first) = matches.next() else {
            return Err(IdlArgumentDecodeError::UnknownOperation {
                operation: operation.to_owned(),
                raw_arguments: Vec::new(),
            });
        };
        if matches.next().is_some() {
            return Err(IdlArgumentDecodeError::AmbiguousOperation {
                operation: operation.to_owned(),
                raw_arguments: Vec::new(),
            });
        }

        Ok(first)
    }

    pub fn lookup_operation_by_repository_id(
        &self,
        repository_id: &str,
        operation: &str,
    ) -> Result<&IdlOperationMetadata, IdlArgumentDecodeError> {
        self.operations
            .iter()
            .find(|candidate| {
                candidate.repository_id.as_deref() == Some(repository_id)
                    && candidate.operation == operation
            })
            .ok_or_else(|| IdlArgumentDecodeError::UnknownOperation {
                operation: operation.to_owned(),
                raw_arguments: Vec::new(),
            })
    }

    pub fn lookup_operation_by_interface(
        &self,
        scoped_interface: &[&str],
        operation: &str,
    ) -> Result<&IdlOperationMetadata, IdlArgumentDecodeError> {
        self.operations
            .iter()
            .find(|candidate| {
                candidate
                    .scoped_interface
                    .iter()
                    .map(String::as_str)
                    .eq(scoped_interface.iter().copied())
                    && candidate.operation == operation
            })
            .ok_or_else(|| IdlArgumentDecodeError::UnknownOperation {
                operation: operation.to_owned(),
                raw_arguments: Vec::new(),
            })
    }

    fn type_is_interface(&self, ty: &TypeRef, operation_scope: &[String]) -> bool {
        let TypeRef::Named(name) = ty else {
            return false;
        };
        let resolved = scoped_name_key(&operation_scope[..operation_scope.len() - 1], name);
        self.interface_scopes
            .iter()
            .any(|scope| scope == &resolved || scope.last() == name.parts.last())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdlOperationMetadata {
    pub repository_id: Option<String>,
    pub interface: String,
    pub scoped_interface: Vec<String>,
    pub operation: String,
    pub params: Vec<IdlParamMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdlParamMetadata {
    pub name: String,
    pub direction: ParamDirection,
    pub ty: TypeRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdlArgumentDecodeError {
    UnknownOperation {
        operation: String,
        raw_arguments: Vec<u8>,
    },
    AmbiguousOperation {
        operation: String,
        raw_arguments: Vec<u8>,
    },
    UnsupportedType {
        operation: String,
        parameter: String,
        ty: TypeRef,
        raw_arguments: Vec<u8>,
    },
    SequenceBoundExceeded {
        operation: String,
        parameter: String,
        bound: u64,
        actual: u32,
        raw_arguments: Vec<u8>,
    },
    Cdr {
        operation: String,
        parameter: String,
        source: CdrError,
        raw_arguments: Vec<u8>,
    },
    TrailingBytes {
        operation: String,
        offset: usize,
        remaining: usize,
        raw_arguments: Vec<u8>,
    },
}

impl fmt::Display for IdlArgumentDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation { operation, .. } => {
                write!(formatter, "no IDL metadata for operation '{operation}'")
            }
            Self::AmbiguousOperation { operation, .. } => write!(
                formatter,
                "IDL operation '{operation}' is ambiguous without interface metadata"
            ),
            Self::UnsupportedType {
                operation,
                parameter,
                ty,
                ..
            } => write!(
                formatter,
                "unsupported IDL type {ty:?} for parameter '{parameter}' on operation '{operation}'"
            ),
            Self::SequenceBoundExceeded {
                operation,
                parameter,
                bound,
                actual,
                ..
            } => write!(
                formatter,
                "sequence parameter '{parameter}' on operation '{operation}' declared {actual} element(s), exceeding bound {bound}"
            ),
            Self::Cdr {
                operation,
                parameter,
                source,
                ..
            } => write!(
                formatter,
                "failed to decode parameter '{parameter}' on operation '{operation}': {source}"
            ),
            Self::TrailingBytes {
                operation,
                offset,
                remaining,
                ..
            } => write!(
                formatter,
                "decoded operation '{operation}' left {remaining} trailing argument byte(s) at offset {offset}"
            ),
        }
    }
}

impl std::error::Error for IdlArgumentDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cdr { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn decode_request_arguments<'a>(
    request: &ParsedRequest12<'a>,
    catalog: &IdlOperationCatalog,
) -> Result<DecodedRequestArguments<'a>, IdlArgumentDecodeError> {
    let operation = catalog
        .lookup_operation(&request.operation)
        .map_err(|error| error.with_raw_arguments(request.arguments))?;
    let mut reader = request.arguments_reader();
    let mut arguments = Vec::new();

    for param in operation
        .params
        .iter()
        .filter(|param| param.direction != ParamDirection::Out)
    {
        let start = reader.position();
        let value = decode_value(
            &param.ty,
            operation,
            param,
            catalog,
            &mut reader,
            request.arguments,
        )?;
        let end = reader.position();
        arguments.push(DecodedArgument {
            name: param.name.clone(),
            direction: param.direction.clone(),
            ty: param.ty.clone(),
            span: start..end,
            value,
        });
    }

    if reader.remaining() != 0 {
        return Err(IdlArgumentDecodeError::TrailingBytes {
            operation: request.operation.clone(),
            offset: reader.position(),
            remaining: reader.remaining(),
            raw_arguments: request.arguments.to_vec(),
        });
    }

    Ok(DecodedRequestArguments {
        repository_id: operation.repository_id.clone(),
        interface: operation.interface.clone(),
        operation: operation.operation.clone(),
        raw_arguments: request.arguments,
        arguments,
    })
}

fn decode_value(
    ty: &TypeRef,
    operation: &IdlOperationMetadata,
    param: &IdlParamMetadata,
    catalog: &IdlOperationCatalog,
    reader: &mut CdrReader<'_>,
    raw_arguments: &[u8],
) -> Result<DecodedArgumentValue, IdlArgumentDecodeError> {
    match ty {
        TypeRef::Primitive(primitive) => {
            decode_primitive(primitive, operation, param, reader, raw_arguments)
        }
        TypeRef::String { wide: false, bound } => {
            let value = reader
                .read_string()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
            if let Some(bound) = bound {
                if value.len() as u64 > *bound {
                    return Err(IdlArgumentDecodeError::SequenceBoundExceeded {
                        operation: operation.operation.clone(),
                        parameter: param.name.clone(),
                        bound: *bound,
                        actual: value.len() as u32,
                        raw_arguments: raw_arguments.to_vec(),
                    });
                }
            }
            Ok(DecodedArgumentValue::String(value))
        }
        TypeRef::Sequence { element, bound } => decode_sequence(
            element,
            *bound,
            operation,
            param,
            catalog,
            reader,
            raw_arguments,
        ),
        TypeRef::Named(_) if catalog.type_is_interface(ty, &operation.scoped_interface) => {
            read_object_reference(operation, param, reader, raw_arguments)
        }
        _ => Err(IdlArgumentDecodeError::UnsupportedType {
            operation: operation.operation.clone(),
            parameter: param.name.clone(),
            ty: ty.clone(),
            raw_arguments: raw_arguments.to_vec(),
        }),
    }
}

fn decode_primitive(
    primitive: &PrimitiveType,
    operation: &IdlOperationMetadata,
    param: &IdlParamMetadata,
    reader: &mut CdrReader<'_>,
    raw_arguments: &[u8],
) -> Result<DecodedArgumentValue, IdlArgumentDecodeError> {
    let result = match primitive {
        PrimitiveType::Boolean => DecodedArgumentValue::Boolean(
            reader
                .read_bool()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Char => DecodedArgumentValue::Char(
            reader
                .read_octet()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Octet => DecodedArgumentValue::Octet(
            reader
                .read_octet()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Short => DecodedArgumentValue::Short(
            reader
                .read_i16()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::UShort => DecodedArgumentValue::UShort(
            reader
                .read_u16()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Long => DecodedArgumentValue::Long(
            reader
                .read_i32()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::ULong => DecodedArgumentValue::ULong(
            reader
                .read_u32()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::LongLong => DecodedArgumentValue::LongLong(
            reader
                .read_i64()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::ULongLong => DecodedArgumentValue::ULongLong(
            reader
                .read_u64()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Float => DecodedArgumentValue::Float(
            reader
                .read_f32()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Double => DecodedArgumentValue::Double(
            reader
                .read_f64()
                .map_err(|source| cdr_error(operation, param, source, raw_arguments))?,
        ),
        PrimitiveType::Object => {
            return read_object_reference(operation, param, reader, raw_arguments);
        }
        PrimitiveType::WChar | PrimitiveType::LongDouble | PrimitiveType::Any => {
            return Err(IdlArgumentDecodeError::UnsupportedType {
                operation: operation.operation.clone(),
                parameter: param.name.clone(),
                ty: TypeRef::Primitive(primitive.clone()),
                raw_arguments: raw_arguments.to_vec(),
            });
        }
    };

    Ok(result)
}

fn decode_sequence(
    element: &TypeRef,
    bound: Option<u64>,
    operation: &IdlOperationMetadata,
    param: &IdlParamMetadata,
    catalog: &IdlOperationCatalog,
    reader: &mut CdrReader<'_>,
    raw_arguments: &[u8],
) -> Result<DecodedArgumentValue, IdlArgumentDecodeError> {
    let count = reader
        .read_u32()
        .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
    if let Some(bound) = bound {
        if u64::from(count) > bound {
            return Err(IdlArgumentDecodeError::SequenceBoundExceeded {
                operation: operation.operation.clone(),
                parameter: param.name.clone(),
                bound,
                actual: count,
                raw_arguments: raw_arguments.to_vec(),
            });
        }
    }

    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(decode_value(
            element,
            operation,
            param,
            catalog,
            reader,
            raw_arguments,
        )?);
    }

    Ok(DecodedArgumentValue::Sequence(values))
}

fn read_object_reference(
    operation: &IdlOperationMetadata,
    param: &IdlParamMetadata,
    reader: &mut CdrReader<'_>,
    raw_arguments: &[u8],
) -> Result<DecodedArgumentValue, IdlArgumentDecodeError> {
    let type_id = reader
        .read_string()
        .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
    let profile_count = reader
        .read_u32()
        .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
    for _ in 0..profile_count {
        reader
            .read_u32()
            .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
        reader
            .read_octet_sequence()
            .map_err(|source| cdr_error(operation, param, source, raw_arguments))?;
    }

    Ok(DecodedArgumentValue::ObjectReference {
        type_id,
        profile_count,
    })
}

fn cdr_error(
    operation: &IdlOperationMetadata,
    param: &IdlParamMetadata,
    source: CdrError,
    raw_arguments: &[u8],
) -> IdlArgumentDecodeError {
    IdlArgumentDecodeError::Cdr {
        operation: operation.operation.clone(),
        parameter: param.name.clone(),
        source,
        raw_arguments: raw_arguments.to_vec(),
    }
}

impl IdlArgumentDecodeError {
    fn with_raw_arguments(self, raw_arguments: &[u8]) -> Self {
        match self {
            Self::UnknownOperation { operation, .. } => Self::UnknownOperation {
                operation,
                raw_arguments: raw_arguments.to_vec(),
            },
            Self::AmbiguousOperation { operation, .. } => Self::AmbiguousOperation {
                operation,
                raw_arguments: raw_arguments.to_vec(),
            },
            other => other,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PragmaState {
    prefix: Option<String>,
}

fn collect_operations(
    declarations: &[Declaration],
    scope: &[String],
    state: &mut PragmaState,
    version_pragmas: &BTreeMap<Vec<String>, String>,
    catalog: &mut IdlOperationCatalog,
) {
    for declaration in declarations {
        match declaration {
            Declaration::Pragma(pragma) => apply_pragma_state(pragma, state),
            Declaration::Module(module) => {
                let mut module_scope = scope.to_vec();
                module_scope.push(module.name.clone());
                let mut module_state = state.clone();
                collect_operations(
                    &module.declarations,
                    &module_scope,
                    &mut module_state,
                    version_pragmas,
                    catalog,
                );
            }
            Declaration::Interface(interface) => {
                collect_interface(interface, scope, state, version_pragmas, catalog);
            }
            _ => {}
        }
    }
}

fn collect_interface(
    interface: &Interface,
    scope: &[String],
    state: &PragmaState,
    version_pragmas: &BTreeMap<Vec<String>, String>,
    catalog: &mut IdlOperationCatalog,
) {
    let mut scoped_interface = scope.to_vec();
    scoped_interface.push(interface.name.clone());
    catalog.interface_scopes.push(scoped_interface.clone());

    let repository_id = repository_id_for(&scoped_interface, state, version_pragmas);
    for member in &interface.members {
        let InterfaceMember::Operation(operation) = member else {
            continue;
        };
        catalog.operations.push(IdlOperationMetadata {
            repository_id: repository_id.clone(),
            interface: interface.name.clone(),
            scoped_interface: scoped_interface.clone(),
            operation: operation.name.clone(),
            params: operation
                .params
                .iter()
                .map(|param| IdlParamMetadata {
                    name: param.name.clone(),
                    direction: param.direction.clone(),
                    ty: param.ty.clone(),
                })
                .collect(),
        });
    }
}

fn collect_version_pragmas(
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
                collect_version_pragmas(&module.declarations, &module_scope, versions);
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
