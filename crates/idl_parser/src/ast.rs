// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdlFile {
    pub declarations: Vec<Declaration>,
    pub pragmas: Vec<IdlPragma>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Declaration {
    Pragma(IdlPragma),
    Module(Module),
    Interface(Interface),
    Struct(Struct),
    Enum(Enum),
    Exception(Exception),
    Typedef(Typedef),
    Const(Const),
    Union(Union),
    ValueType(ValueType),
    EventType(EventType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdlPragma {
    pub name: String,
    pub line: usize,
    pub kind: IdlPragmaKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdlPragmaKind {
    Prefix(String),
    Version { target: ScopedName, version: String },
    Unknown { arguments: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub declarations: Vec<Declaration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub inherits: Vec<ScopedName>,
    pub members: Vec<InterfaceMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceMember {
    Operation(Operation),
    Attribute(Attribute),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub name: String,
    pub return_type: TypeRef,
    pub params: Vec<Param>,
    pub raises: Vec<ScopedName>,
    pub oneway: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: TypeRef,
    pub direction: ParamDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamDirection {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub ty: TypeRef,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enum {
    pub name: String,
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typedef {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Const {
    pub name: String,
    pub ty: TypeRef,
    pub value: ConstValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Union {
    pub name: String,
    pub discriminator: TypeRef,
    pub arms: Vec<UnionArm>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnionArm {
    pub labels: Vec<UnionLabel>,
    pub field: Field,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnionLabel {
    Case(ConstValue),
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueType {
    pub name: String,
    pub inherits: Vec<ScopedName>,
    pub is_abstract: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventType {
    pub name: String,
    pub inherits: Vec<ScopedName>,
    pub is_abstract: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedName {
    pub absolute: bool,
    pub parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef {
    Void,
    Primitive(PrimitiveType),
    Named(ScopedName),
    Sequence {
        element: Box<TypeRef>,
        bound: Option<u64>,
    },
    Map {
        key: Box<TypeRef>,
        value: Box<TypeRef>,
        bound: Option<u64>,
    },
    Array {
        element: Box<TypeRef>,
        dimensions: Vec<u64>,
    },
    String {
        wide: bool,
        bound: Option<u64>,
    },
    Fixed {
        digits: u16,
        scale: i16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveType {
    Boolean,
    Char,
    WChar,
    Octet,
    Short,
    UShort,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Float,
    Double,
    LongDouble,
    Any,
    Object,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstValue {
    Integer(i64),
    Float(String),
    String(String),
    Boolean(bool),
    ScopedName(ScopedName),
}
