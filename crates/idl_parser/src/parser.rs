// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Attribute, Const, ConstValue, Declaration, Enum, EventType, Exception, Field, IdlFile,
    IdlPragma, IdlPragmaKind, Interface, InterfaceMember, Module, Operation, Param, ParamDirection,
    PrimitiveType, ScopedName, Struct, TypeRef, Typedef, Union, UnionArm, UnionLabel, ValueType,
};
use crate::error::{IdlParseError, Span};
use crate::lexer::{lex, Token, TokenKind};
use std::collections::VecDeque;

pub fn parse_source(source: &str) -> Result<IdlFile, IdlParseError> {
    let trimmed = source.trim_start();
    if trimmed.starts_with('#') && !starts_with_pragma_directive(trimmed) {
        return Err(IdlParseError::new(
            "unexpected preprocessor directive after CPP-lite preprocessing",
            Span::start(),
        ));
    }

    let tokens = lex(source)?;
    Parser {
        source,
        tokens,
        pos: 0,
        pragmas: Vec::new(),
        warnings: Vec::new(),
        pending_declarations: VecDeque::new(),
        depth: 0,
    }
    .parse_file()
}

/// Maximum module / constructed-type nesting depth. A crafted `.idl` with
/// thousands of nested `module { … }` or `sequence<sequence<…>>` would otherwise
/// recurse until the parser thread's stack overflows (security review, LOW). The
/// `#include` preprocessor has its own separate `MAX_INCLUDE_DEPTH` cap.
const MAX_NEST_DEPTH: usize = 256;

struct Parser<'a> {
    source: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    pragmas: Vec<IdlPragma>,
    warnings: Vec<String>,
    pending_declarations: VecDeque<Declaration>,
    /// Current recursive-descent nesting depth (modules + constructed types),
    /// bounded by [`MAX_NEST_DEPTH`]. Incremented by [`Parser::enter_nesting`].
    depth: usize,
}

impl Parser<'_> {
    /// Enter one nesting level, rejecting input nested past [`MAX_NEST_DEPTH`].
    /// The caller decrements `self.depth` on its return path; on the error path
    /// the whole parse aborts, so a missed decrement is harmless.
    fn enter_nesting(&mut self) -> Result<(), IdlParseError> {
        self.depth += 1;
        if self.depth > MAX_NEST_DEPTH {
            return Err(self.error_here("IDL nesting exceeds the maximum supported depth"));
        }
        Ok(())
    }

    fn parse_file(&mut self) -> Result<IdlFile, IdlParseError> {
        let mut declarations = Vec::new();
        while !self.at_end() || !self.pending_declarations.is_empty() {
            declarations.push(self.parse_declaration()?);
        }
        Ok(IdlFile {
            declarations,
            pragmas: std::mem::take(&mut self.pragmas),
            warnings: std::mem::take(&mut self.warnings),
        })
    }

    fn parse_declaration(&mut self) -> Result<Declaration, IdlParseError> {
        if let Some(declaration) = self.pending_declarations.pop_front() {
            return Ok(declaration);
        }
        self.skip_square_attributes()?;
        if self.is_annotation_declaration() {
            return self.parse_annotation_declaration();
        }
        self.skip_annotations()?;
        if self.consume_keyword("import") {
            return self.parse_import_declaration();
        }
        if self.consume_keyword("library") {
            return self.parse_library();
        }
        if self.peek().text == "#" {
            return self.parse_pragma();
        }
        if self.consume_keyword("module") {
            return self.parse_module();
        }
        if self.consume_keyword("local") {
            if self.consume_keyword("interface") {
                return self.parse_interface();
            }
            return Err(self.error_here("expected 'interface' after 'local'"));
        }
        if self.consume_keyword("interface") {
            return self.parse_interface();
        }
        if self.consume_keyword("exception") {
            return self.parse_exception();
        }
        if self.consume_keyword("struct") {
            return self.parse_struct();
        }
        if self.consume_keyword("enum") {
            return self.parse_enum();
        }
        if self.consume_keyword("bitmask") {
            return self.parse_bitmask();
        }
        if self.consume_keyword("typedef") {
            return self.parse_typedef();
        }
        if self.consume_keyword("const") {
            return self.parse_const();
        }
        if self.consume_keyword("union") {
            return self.parse_union();
        }
        let is_abstract = self.consume_keyword("abstract");
        if self.consume_keyword("valuetype") {
            return self.parse_valuetype(is_abstract);
        }
        if self.consume_keyword("eventtype") {
            return self.parse_eventtype(is_abstract);
        }
        if !is_abstract && self.consume_keyword("valuetype") {
            return self.parse_valuetype(false);
        }
        if !is_abstract && self.consume_keyword("eventtype") {
            return self.parse_eventtype(false);
        }

        Err(self.error_here(format!(
            "expected declaration, found '{}'",
            self.peek().text
        )))
    }

    fn parse_pragma(&mut self) -> Result<Declaration, IdlParseError> {
        let line = self.peek().span.line;
        self.expect_text("#")?;
        self.expect_keyword("pragma")?;
        let name = self.expect_identifier()?;
        let lower_name = name.to_ascii_lowercase();
        let kind = match lower_name.as_str() {
            "prefix" => {
                let prefix = self.expect_string_literal()?;
                self.expect_end_of_pragma_line(line)?;
                IdlPragmaKind::Prefix(prefix)
            }
            "version" => {
                let target = self.parse_scoped_name()?;
                let version = self.expect_pragma_version()?;
                self.expect_end_of_pragma_line(line)?;
                IdlPragmaKind::Version { target, version }
            }
            "govfuzz_warning" => {
                // govfuzz's OWN recovery breadcrumb: the preprocessor injects
                // `#pragma govfuzz_warning "<message>"` when an `#include` cannot
                // be resolved (see crates/idl_parser/src/preprocessor.rs
                // `warning_pragma`). Surface the message verbatim as a normal IDL
                // warning instead of re-flagging govfuzz's own marker as an
                // "unknown IDL pragma" — the confusing self-diagnostic the user
                // saw as `unknown IDL pragma '#pragma govfuzz_warning "..."'`.
                let arguments = self.collect_pragma_arguments(line);
                let message = arguments
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .map(|inner| inner.replace("\"\"", "\"").replace("\\\\", "\\"))
                    .unwrap_or_else(|| arguments.clone());
                self.warnings.push(message);
                IdlPragmaKind::Unknown { arguments }
            }
            _ => {
                let arguments = self.collect_pragma_arguments(line);
                self.warnings.push(format!(
                    "unknown IDL pragma '#pragma {name}{}{}' recorded",
                    if arguments.is_empty() { "" } else { " " },
                    arguments
                ));
                IdlPragmaKind::Unknown { arguments }
            }
        };
        let pragma = IdlPragma { name, line, kind };
        self.pragmas.push(pragma.clone());
        Ok(Declaration::Pragma(pragma))
    }

    fn parse_module(&mut self) -> Result<Declaration, IdlParseError> {
        self.enter_nesting()?;
        let name = self.expect_identifier()?;
        self.expect_text("{")?;
        let mut declarations = Vec::new();
        loop {
            if let Some(declaration) = self.pending_declarations.pop_front() {
                declarations.push(declaration);
                continue;
            }
            if self.consume_text("}") {
                break;
            }
            declarations.push(self.parse_declaration()?);
        }
        self.expect_text(";")?;
        self.depth -= 1;
        Ok(Declaration::Module(Module { name, declarations }))
    }

    fn parse_import_declaration(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_string_literal()?;
        self.expect_text(";")?;
        Ok(Declaration::ValueType(ValueType {
            name: format!("import:{name}"),
            inherits: Vec::new(),
            is_abstract: false,
        }))
    }

    fn parse_library(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        self.skip_braced_body()?;
        self.expect_text(";")?;
        Ok(Declaration::ValueType(ValueType {
            name,
            inherits: Vec::new(),
            is_abstract: false,
        }))
    }

    fn parse_interface(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let inherits = if self.consume_text(":") {
            self.parse_scoped_name_list()?
        } else {
            Vec::new()
        };
        if self.consume_text(";") {
            return Ok(Declaration::Interface(Interface {
                name,
                inherits,
                members: Vec::new(),
            }));
        }
        self.expect_text("{")?;
        let mut members = Vec::new();
        while !self.consume_text("}") {
            members.push(self.parse_interface_member()?);
        }
        self.expect_text(";")?;
        Ok(Declaration::Interface(Interface {
            name,
            inherits,
            members,
        }))
    }

    fn parse_exception(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        self.expect_text("{")?;
        let mut fields = Vec::new();
        while !self.consume_text("}") {
            fields.extend(self.parse_fields()?);
        }
        self.expect_text(";")?;
        Ok(Declaration::Exception(Exception { name, fields }))
    }

    fn parse_struct(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        if self.consume_text(";") {
            return Ok(Declaration::Struct(Struct {
                name,
                fields: Vec::new(),
            }));
        }
        let _inherits = self.parse_optional_type_inherits()?;
        self.expect_text("{")?;
        let mut fields = Vec::new();
        while !self.consume_text("}") {
            fields.extend(self.parse_fields()?);
        }
        self.expect_text(";")?;
        Ok(Declaration::Struct(Struct { name, fields }))
    }

    fn parse_enum(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let variants = self.parse_enum_variants()?;
        Ok(Declaration::Enum(Enum { name, variants }))
    }

    fn parse_bitmask(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let variants = self.parse_enum_variants()?;
        Ok(Declaration::Enum(Enum { name, variants }))
    }

    fn parse_enum_variants(&mut self) -> Result<Vec<String>, IdlParseError> {
        self.expect_text("{")?;
        let mut variants = Vec::new();
        if !self.consume_text("}") {
            loop {
                self.skip_annotations()?;
                variants.push(self.expect_identifier()?);
                if self.consume_text("}") {
                    break;
                }
                self.expect_text(",")?;
            }
        }
        self.expect_text(";")?;
        Ok(variants)
    }

    fn parse_typedef(&mut self) -> Result<Declaration, IdlParseError> {
        if self.consume_keyword("struct") {
            return self.parse_inline_struct_typedef();
        }
        let base_ty = self.parse_type()?;
        let mut declarations = Vec::new();
        loop {
            let name = self.expect_identifier()?;
            let ty = self.parse_array_suffix(base_ty.clone())?;
            declarations.push(Declaration::Typedef(Typedef { name, ty }));
            if !self.consume_text(",") {
                break;
            }
        }
        self.expect_text(";")?;
        let first = declarations.remove(0);
        self.pending_declarations.extend(declarations);
        Ok(first)
    }

    fn parse_inline_struct_typedef(&mut self) -> Result<Declaration, IdlParseError> {
        let _tag = self.expect_identifier()?;
        self.expect_text("{")?;
        let mut fields = Vec::new();
        while !self.consume_text("}") {
            fields.extend(self.parse_fields()?);
        }
        let name = self.expect_identifier()?;
        let _ty = self.parse_array_suffix(TypeRef::Named(ScopedName {
            absolute: false,
            parts: vec![name.clone()],
        }))?;
        self.expect_text(";")?;
        Ok(Declaration::Struct(Struct { name, fields }))
    }

    fn parse_const(&mut self) -> Result<Declaration, IdlParseError> {
        let ty = self.parse_type()?;
        let name = self.expect_identifier()?;
        self.expect_text("=")?;
        let value = self.parse_const_value()?;
        self.expect_text(";")?;
        Ok(Declaration::Const(Const { name, ty, value }))
    }

    fn parse_union(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        if self.consume_text(";") {
            return Ok(Declaration::Union(Union {
                name,
                discriminator: TypeRef::Void,
                arms: Vec::new(),
            }));
        }
        self.expect_keyword("switch")?;
        self.expect_text("(")?;
        let discriminator = self.parse_type()?;
        self.expect_text(")")?;
        self.expect_text("{")?;
        let mut arms = Vec::new();
        while !self.consume_text("}") {
            let mut labels = Vec::new();
            loop {
                if self.consume_keyword("case") {
                    labels.push(UnionLabel::Case(self.parse_const_value()?));
                    self.expect_text(":")?;
                } else if self.consume_keyword("default") {
                    labels.push(UnionLabel::Default);
                    self.expect_text(":")?;
                } else {
                    break;
                }
            }
            arms.push(UnionArm {
                labels,
                field: self.parse_field()?,
            });
        }
        self.expect_text(";")?;
        Ok(Declaration::Union(Union {
            name,
            discriminator,
            arms,
        }))
    }

    fn parse_valuetype(&mut self, is_abstract: bool) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let inherits = self.parse_optional_type_inherits()?;
        if self.consume_text(";") {
            return Ok(Declaration::ValueType(ValueType {
                name,
                inherits,
                is_abstract,
            }));
        }
        self.skip_braced_body()?;
        self.expect_text(";")?;
        Ok(Declaration::ValueType(ValueType {
            name,
            inherits,
            is_abstract,
        }))
    }

    fn parse_eventtype(&mut self, is_abstract: bool) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let inherits = self.parse_optional_type_inherits()?;
        if self.consume_text(";") {
            return Ok(Declaration::EventType(EventType {
                name,
                inherits,
                is_abstract,
            }));
        }
        self.skip_braced_body()?;
        self.expect_text(";")?;
        Ok(Declaration::EventType(EventType {
            name,
            inherits,
            is_abstract,
        }))
    }

    fn parse_annotation_declaration(&mut self) -> Result<Declaration, IdlParseError> {
        self.expect_text("@")?;
        self.expect_keyword("annotation")?;
        let name = self.expect_identifier()?;
        if !self.consume_text(";") {
            self.skip_braced_body()?;
            self.expect_text(";")?;
        }
        Ok(Declaration::ValueType(ValueType {
            name,
            inherits: Vec::new(),
            is_abstract: false,
        }))
    }

    fn parse_interface_member(&mut self) -> Result<InterfaceMember, IdlParseError> {
        self.skip_square_attributes()?;
        self.skip_annotations()?;
        let readonly = self.consume_keyword("readonly");
        if readonly {
            self.expect_keyword("attribute")?;
        }
        if readonly || self.consume_keyword("attribute") {
            let ty = self.parse_type()?;
            let name = self.expect_identifier()?;
            self.expect_text(";")?;
            return Ok(InterfaceMember::Attribute(Attribute { name, ty, readonly }));
        }

        let oneway = self.consume_keyword("oneway");
        let return_type = if self.consume_keyword("void") {
            TypeRef::Void
        } else {
            self.parse_type()?
        };
        let name = self.expect_identifier()?;
        self.expect_text("(")?;
        let mut params = Vec::new();
        if !self.consume_text(")") {
            loop {
                params.push(self.parse_param()?);
                if self.consume_text(")") {
                    break;
                }
                self.expect_text(",")?;
            }
        }
        let raises = if self.consume_keyword("raises") {
            self.expect_text("(")?;
            let names = self.parse_scoped_name_list()?;
            self.expect_text(")")?;
            names
        } else {
            Vec::new()
        };
        self.expect_text(";")?;

        Ok(InterfaceMember::Operation(Operation {
            name,
            return_type,
            params,
            raises,
            oneway,
        }))
    }

    fn parse_param(&mut self) -> Result<Param, IdlParseError> {
        let attributes = self.skip_square_attributes()?;
        self.skip_annotations()?;
        let direction = if self.consume_keyword("inout") {
            ParamDirection::InOut
        } else if self.consume_keyword("in") {
            ParamDirection::In
        } else if self.consume_keyword("out") {
            ParamDirection::Out
        } else if !attributes.is_empty() {
            param_direction_from_attributes(&attributes)
        } else {
            return Err(self.error_here("expected parameter direction"));
        };
        let base_ty = self.parse_type()?;
        while self.consume_text("*") {}
        let name = self.expect_identifier()?;
        let ty = self.parse_array_suffix(base_ty)?;
        Ok(Param {
            name,
            ty,
            direction,
        })
    }

    fn parse_type(&mut self) -> Result<TypeRef, IdlParseError> {
        // Bound `sequence<sequence<…>>` / `map<…>` nesting. Wraps the body so the
        // decrement runs on every return path (`map<K,V>` recurses twice at one
        // level, so siblings must not accumulate depth).
        self.enter_nesting()?;
        let result = self.parse_type_inner();
        self.depth -= 1;
        result
    }

    fn parse_type_inner(&mut self) -> Result<TypeRef, IdlParseError> {
        self.skip_annotations()?;

        if self.consume_keyword("sequence") {
            self.expect_text("<")?;
            let element = self.parse_type()?;
            let bound = if self.consume_text(",") {
                self.parse_bound()?
            } else {
                None
            };
            self.expect_text(">")?;
            return Ok(TypeRef::Sequence {
                element: Box::new(element),
                bound,
            });
        }
        if self.consume_keyword("map") {
            self.expect_text("<")?;
            let key = self.parse_type()?;
            self.expect_text(",")?;
            let value = self.parse_type()?;
            let bound = if self.consume_text(",") {
                self.parse_bound()?
            } else {
                None
            };
            self.expect_text(">")?;
            return Ok(TypeRef::Map {
                key: Box::new(key),
                value: Box::new(value),
                bound,
            });
        }
        if self.consume_keyword("fixed") {
            self.expect_text("<")?;
            let digits = self.expect_u64()? as u16;
            self.expect_text(",")?;
            let scale = self.expect_i64()? as i16;
            self.expect_text(">")?;
            return Ok(TypeRef::Fixed { digits, scale });
        }
        if self.consume_keyword("string") {
            return Ok(TypeRef::String {
                wide: false,
                bound: self.parse_optional_bound()?,
            });
        }
        if self.consume_keyword("wstring") {
            return Ok(TypeRef::String {
                wide: true,
                bound: self.parse_optional_bound()?,
            });
        }

        let token = self.peek().clone();
        if token.kind == TokenKind::Identifier {
            let lower = token.text.to_ascii_lowercase();
            if lower == "unsigned" {
                self.bump();
                return self.parse_unsigned_type();
            }
            if lower == "long" {
                self.bump();
                if self.consume_keyword("double") {
                    return Ok(TypeRef::Primitive(PrimitiveType::LongDouble));
                }
                if self.consume_keyword("long") {
                    return Ok(TypeRef::Primitive(PrimitiveType::LongLong));
                }
                return Ok(TypeRef::Primitive(PrimitiveType::Long));
            }
            if let Some(primitive) = primitive_type(&lower) {
                self.bump();
                return Ok(TypeRef::Primitive(primitive));
            }
        }

        let name = self.parse_scoped_name()?;
        if self.consume_text("(") {
            self.skip_balanced_tokens("(", ")")?;
        }
        Ok(TypeRef::Named(name))
    }

    fn parse_unsigned_type(&mut self) -> Result<TypeRef, IdlParseError> {
        if self.consume_keyword("short") {
            Ok(TypeRef::Primitive(PrimitiveType::UShort))
        } else if self.consume_keyword("long") {
            if self.consume_keyword("long") {
                Ok(TypeRef::Primitive(PrimitiveType::ULongLong))
            } else {
                Ok(TypeRef::Primitive(PrimitiveType::ULong))
            }
        } else {
            Err(self.error_here("expected 'short' or 'long' after 'unsigned'"))
        }
    }

    fn parse_optional_bound(&mut self) -> Result<Option<u64>, IdlParseError> {
        if !self.consume_text("<") {
            return Ok(None);
        }
        let bound = self.parse_bound()?;
        self.expect_text(">")?;
        Ok(bound)
    }

    fn parse_bound(&mut self) -> Result<Option<u64>, IdlParseError> {
        let token = self.peek().clone();
        if token.kind == TokenKind::Number {
            return self.expect_u64().map(Some);
        }
        let start = self.pos;
        let _ = self.parse_const_value()?;
        let text = self.tokens[start..self.pos]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.warnings.push(format!(
            "nonliteral IDL bound '{text}' treated as unbounded"
        ));
        Ok(None)
    }

    fn parse_scoped_name_list(&mut self) -> Result<Vec<ScopedName>, IdlParseError> {
        let mut names = vec![self.parse_scoped_name()?];
        while self.consume_text(",") {
            names.push(self.parse_scoped_name()?);
        }
        Ok(names)
    }

    fn parse_scoped_name(&mut self) -> Result<ScopedName, IdlParseError> {
        let absolute = self.consume_text("::");
        let mut parts = vec![self.expect_identifier()?];
        while self.consume_text("::") {
            parts.push(self.expect_identifier()?);
        }
        Ok(ScopedName { absolute, parts })
    }

    fn parse_fields(&mut self) -> Result<Vec<Field>, IdlParseError> {
        self.skip_annotations()?;
        let base_ty = self.parse_type()?;
        let mut fields = Vec::new();
        loop {
            let name = self.expect_identifier()?;
            let ty = self.parse_array_suffix(base_ty.clone())?;
            fields.push(Field { name, ty });
            if !self.consume_text(",") {
                break;
            }
        }
        self.expect_text(";")?;
        Ok(fields)
    }

    fn parse_field(&mut self) -> Result<Field, IdlParseError> {
        let fields = self.parse_fields()?;
        fields
            .into_iter()
            .next()
            .ok_or_else(|| self.error_here("expected field"))
    }

    fn parse_array_suffix(&mut self, element: TypeRef) -> Result<TypeRef, IdlParseError> {
        let mut dimensions = Vec::new();
        self.skip_annotations()?;
        while self.consume_text("[") {
            dimensions.push(self.parse_array_dimension()?);
            self.expect_text("]")?;
            self.skip_annotations()?;
        }
        if dimensions.is_empty() {
            Ok(element)
        } else {
            Ok(TypeRef::Array {
                element: Box::new(element),
                dimensions,
            })
        }
    }

    fn parse_array_dimension(&mut self) -> Result<u64, IdlParseError> {
        match self.parse_const_value()? {
            ConstValue::Integer(value) => u64::try_from(value)
                .map_err(|_| self.error_here("expected nonnegative array dimension")),
            _ => {
                self.warnings
                    .push("noninteger IDL array dimension mapped to 0".to_owned());
                Ok(0)
            }
        }
    }

    fn skip_annotations(&mut self) -> Result<(), IdlParseError> {
        while self.consume_text("@") {
            let name = self.parse_scoped_name()?;
            self.warnings.push(format!(
                "ignored IDL annotation '@{}'",
                format_scoped_name(&name)
            ));
            if self.consume_text("(") {
                let mut depth = 1_u32;
                while depth > 0 {
                    if self.at_end() {
                        return Err(self.error_here("expected ')'"));
                    }
                    if self.consume_text("(") {
                        depth += 1;
                    } else if self.consume_text(")") {
                        depth -= 1;
                    } else {
                        self.bump();
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_const_value(&mut self) -> Result<ConstValue, IdlParseError> {
        let expression = self.parse_const_expression(MIN_CONST_PRECEDENCE)?;
        if expression.has_operator {
            if let Some(value) = expression.numeric_value {
                return Ok(ConstValue::Integer(value));
            }
            self.warnings.push(format!(
                "unsupported IDL constant expression '{}' mapped to 0",
                expression.text
            ));
            return Ok(ConstValue::Integer(0));
        }
        Ok(expression.value)
    }

    fn parse_const_expression(
        &mut self,
        min_precedence: u8,
    ) -> Result<ConstExpression, IdlParseError> {
        let mut left = self.parse_const_atom()?;
        loop {
            let Some(operator) = self.peek_const_operator() else {
                break;
            };
            let precedence = const_operator_precedence(operator);
            if precedence < min_precedence {
                break;
            }

            self.consume_const_operator(operator);
            let right = self.parse_const_expression(precedence + 1)?;
            let numeric_value = match (left.numeric_value, right.numeric_value) {
                (Some(left), Some(right)) => eval_integer_operator(operator, left, right),
                _ => None,
            };
            left = ConstExpression {
                value: numeric_value.map_or(ConstValue::Integer(0), ConstValue::Integer),
                numeric_value,
                text: format!("{} {operator} {}", left.text, right.text),
                has_operator: true,
            };
        }
        Ok(left)
    }

    fn parse_const_atom(&mut self) -> Result<ConstExpression, IdlParseError> {
        if self.consume_keyword("true") {
            return Ok(ConstExpression {
                value: ConstValue::Boolean(true),
                numeric_value: Some(1),
                text: "true".to_owned(),
                has_operator: false,
            });
        }
        if self.consume_keyword("false") {
            return Ok(ConstExpression {
                value: ConstValue::Boolean(false),
                numeric_value: Some(0),
                text: "false".to_owned(),
                has_operator: false,
            });
        }
        if self.peek().kind == TokenKind::Identifier
            && self.peek().text.eq_ignore_ascii_case("L")
            && self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|token| token.kind == TokenKind::StringLiteral)
        {
            let prefix = self.peek().text.clone();
            self.bump();
            let literal = self.peek().text.clone();
            self.bump();
            let text = format!("{prefix}{literal}");
            return Ok(ConstExpression {
                value: ConstValue::String(text.clone()),
                numeric_value: None,
                text,
                has_operator: false,
            });
        }
        let negative = self.consume_text("-");
        let token = self.peek().clone();
        if negative && token.kind != TokenKind::Number {
            return Err(self.error_here("expected numeric constant after '-'"));
        }
        match token.kind {
            TokenKind::Number => {
                self.bump();
                if token.text.contains('.') {
                    let value = if negative {
                        format!("-{}", token.text)
                    } else {
                        token.text
                    };
                    Ok(ConstExpression {
                        value: ConstValue::Float(value.clone()),
                        numeric_value: None,
                        text: value,
                        has_operator: false,
                    })
                } else {
                    let value = parse_integer_literal(&token.text).ok_or_else(|| {
                        IdlParseError::new("expected integer literal", token.span)
                    })?;
                    let value = if negative { -value } else { value };
                    Ok(ConstExpression {
                        value: ConstValue::Integer(value),
                        numeric_value: Some(value),
                        text: value.to_string(),
                        has_operator: false,
                    })
                }
            }
            TokenKind::StringLiteral => {
                self.bump();
                Ok(ConstExpression {
                    value: ConstValue::String(token.text.clone()),
                    numeric_value: None,
                    text: token.text,
                    has_operator: false,
                })
            }
            TokenKind::Identifier => {
                let name = self.parse_scoped_name()?;
                let text = format_scoped_name(&name);
                Ok(ConstExpression {
                    value: ConstValue::ScopedName(name),
                    numeric_value: None,
                    text,
                    has_operator: false,
                })
            }
            TokenKind::Punctuation if token.text == "::" => {
                let name = self.parse_scoped_name()?;
                let text = format_scoped_name(&name);
                Ok(ConstExpression {
                    value: ConstValue::ScopedName(name),
                    numeric_value: None,
                    text,
                    has_operator: false,
                })
            }
            _ => Err(self.error_here("expected constant value")),
        }
    }

    fn peek_const_operator(&self) -> Option<&'static str> {
        match self.peek().text.as_str() {
            "<" if self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|token| token.text == "<") =>
            {
                Some("<<")
            }
            ">" if self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|token| token.text == ">") =>
            {
                Some(">>")
            }
            "|" => Some("|"),
            "&" => Some("&"),
            "^" => Some("^"),
            "+" => Some("+"),
            "-" => Some("-"),
            "*" => Some("*"),
            "/" => Some("/"),
            _ => None,
        }
    }

    fn consume_const_operator(&mut self, operator: &str) {
        self.bump();
        if matches!(operator, "<<" | ">>") {
            self.bump();
        }
    }

    fn parse_optional_type_inherits(&mut self) -> Result<Vec<ScopedName>, IdlParseError> {
        if self.consume_text(":") || self.consume_keyword("supports") {
            self.parse_scoped_name_list()
        } else {
            Ok(Vec::new())
        }
    }

    fn skip_braced_body(&mut self) -> Result<(), IdlParseError> {
        self.expect_text("{")?;
        self.skip_balanced_tokens("{", "}")
    }

    fn skip_square_attributes(&mut self) -> Result<Vec<String>, IdlParseError> {
        let mut attributes = Vec::new();
        while self.consume_text("[") {
            let start = self.pos;
            self.skip_balanced_tokens("[", "]")?;
            let text = self.tokens[start..self.pos.saturating_sub(1)]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            attributes.push(text);
        }
        Ok(attributes)
    }

    fn skip_balanced_tokens(&mut self, open: &str, close: &str) -> Result<(), IdlParseError> {
        let mut depth = 1_u32;
        while depth > 0 {
            if self.at_end() {
                return Err(self.error_here(format!("expected '{close}'")));
            }
            if self.consume_text(open) {
                depth += 1;
            } else if self.consume_text(close) {
                depth -= 1;
            } else {
                self.bump();
            }
        }
        Ok(())
    }

    fn expect_identifier(&mut self) -> Result<String, IdlParseError> {
        let token = self.peek().clone();
        if token.kind == TokenKind::Identifier {
            self.bump();
            Ok(token.text)
        } else {
            Err(self.error_here("expected identifier"))
        }
    }

    fn expect_string_literal(&mut self) -> Result<String, IdlParseError> {
        let token = self.peek().clone();
        if token.kind == TokenKind::StringLiteral {
            self.bump();
            decode_string_literal(&token.text)
                .map_err(|message| IdlParseError::new(message, token.span))
        } else {
            Err(self.error_here("expected string literal"))
        }
    }

    fn expect_pragma_version(&mut self) -> Result<String, IdlParseError> {
        let token = self.peek().clone();
        if token.kind == TokenKind::Number && is_major_minor_version(&token.text) {
            self.bump();
            Ok(token.text)
        } else {
            Err(self.error_here("expected pragma version as major.minor"))
        }
    }

    fn expect_end_of_pragma_line(&mut self, line: usize) -> Result<(), IdlParseError> {
        if !self.at_end() && self.peek().span.line == line {
            Err(self.error_here("unexpected trailing tokens in pragma"))
        } else {
            Ok(())
        }
    }

    fn collect_pragma_arguments(&mut self, line: usize) -> String {
        let start = self.peek().span.start;
        let mut end = start;
        while !self.at_end() && self.peek().span.line == line {
            end = self.peek().span.end;
            self.bump();
        }
        self.source[start..end].trim().to_owned()
    }

    fn expect_u64(&mut self) -> Result<u64, IdlParseError> {
        let token = self.peek().clone();
        if token.kind == TokenKind::Number {
            self.bump();
            parse_integer_literal(&token.text)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| IdlParseError::new("expected unsigned integer", token.span))
        } else {
            Err(self.error_here("expected unsigned integer"))
        }
    }

    fn expect_i64(&mut self) -> Result<i64, IdlParseError> {
        let negative = self.consume_text("-");
        let token = self.peek().clone();
        if token.kind == TokenKind::Number {
            self.bump();
            let value = parse_integer_literal(&token.text)
                .ok_or_else(|| IdlParseError::new("expected integer", token.span))?;
            Ok(if negative { -value } else { value })
        } else {
            Err(self.error_here("expected integer"))
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> Result<(), IdlParseError> {
        if self.consume_keyword(keyword) {
            Ok(())
        } else {
            Err(self.error_here(format!("expected '{keyword}'")))
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.peek().kind == TokenKind::Identifier
            && self.peek().text.eq_ignore_ascii_case(keyword)
        {
            self.bump();
            true
        } else {
            false
        }
    }

    fn consume_text(&mut self, text: &str) -> bool {
        if self.peek().text == text {
            self.bump();
            true
        } else {
            false
        }
    }

    fn is_annotation_declaration(&self) -> bool {
        self.peek().text == "@"
            && self.tokens.get(self.pos + 1).is_some_and(|token| {
                token.kind == TokenKind::Identifier && token.text.eq_ignore_ascii_case("annotation")
            })
    }

    fn expect_text(&mut self, text: &str) -> Result<(), IdlParseError> {
        if self.consume_text(text) {
            Ok(())
        } else {
            Err(self.error_here(format!("expected '{text}'")))
        }
    }

    fn at_end(&self) -> bool {
        self.peek().kind == TokenKind::End
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn bump(&mut self) {
        if !self.at_end() {
            self.pos += 1;
        }
    }

    fn error_here(&self, message: impl Into<String>) -> IdlParseError {
        IdlParseError::new(message, self.peek().span)
    }
}

fn format_scoped_name(name: &ScopedName) -> String {
    format!(
        "{}{}",
        if name.absolute { "::" } else { "" },
        name.parts.join("::")
    )
}

fn param_direction_from_attributes(attributes: &[String]) -> ParamDirection {
    let text = attributes.join(" ").to_ascii_lowercase();
    let has_in = text
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| word == "in");
    let has_out = text
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| word == "out");
    match (has_in, has_out) {
        (true, true) => ParamDirection::InOut,
        (false, true) => ParamDirection::Out,
        _ => ParamDirection::In,
    }
}

#[derive(Debug, Clone)]
struct ConstExpression {
    value: ConstValue,
    numeric_value: Option<i64>,
    text: String,
    has_operator: bool,
}

const MIN_CONST_PRECEDENCE: u8 = 1;

fn const_operator_precedence(operator: &str) -> u8 {
    match operator {
        "*" | "/" => 6,
        "+" | "-" => 5,
        "<<" | ">>" => 4,
        "&" => 3,
        "^" => 2,
        "|" => 1,
        _ => 0,
    }
}

fn eval_integer_operator(operator: &str, left: i64, right: i64) -> Option<i64> {
    match operator {
        "<<" => u32::try_from(right)
            .ok()
            .and_then(|shift| left.checked_shl(shift)),
        ">>" => u32::try_from(right)
            .ok()
            .and_then(|shift| left.checked_shr(shift)),
        "|" => Some(left | right),
        "&" => Some(left & right),
        "^" => Some(left ^ right),
        "+" => left.checked_add(right),
        "-" => left.checked_sub(right),
        "*" => left.checked_mul(right),
        "/" => {
            if right == 0 {
                None
            } else {
                left.checked_div(right)
            }
        }
        _ => None,
    }
}

fn parse_integer_literal(text: &str) -> Option<i64> {
    let normalized = text.replace('_', "");
    let (digits, radix) = if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        (hex, 16)
    } else if normalized.len() > 1 && normalized.starts_with('0') {
        (&normalized[1..], 8)
    } else {
        (normalized.as_str(), 10)
    };
    if digits.is_empty() {
        return Some(0);
    }
    i64::from_str_radix(digits, radix).ok()
}

fn primitive_type(name: &str) -> Option<PrimitiveType> {
    match name {
        "boolean" => Some(PrimitiveType::Boolean),
        "char" => Some(PrimitiveType::Char),
        "wchar" => Some(PrimitiveType::WChar),
        "octet" => Some(PrimitiveType::Octet),
        "short" => Some(PrimitiveType::Short),
        "float" => Some(PrimitiveType::Float),
        "double" => Some(PrimitiveType::Double),
        "any" => Some(PrimitiveType::Any),
        "object" => Some(PrimitiveType::Object),
        _ => None,
    }
}

fn starts_with_pragma_directive(trimmed_source: &str) -> bool {
    let Some(rest) = trimmed_source.strip_prefix('#') else {
        return false;
    };
    let rest = rest.trim_start();
    let Some(after_name) = rest.strip_prefix("pragma") else {
        return false;
    };
    after_name.chars().next().is_none_or(char::is_whitespace)
}

fn decode_string_literal(text: &str) -> Result<String, &'static str> {
    let mut chars = text.chars();
    let Some(quote) = chars.next() else {
        return Err("expected string literal");
    };
    if quote != '"' && quote != '\'' {
        return Err("expected string literal");
    }
    if !text.ends_with(quote) || text.len() < 2 {
        return Err("unterminated string literal");
    }
    let body = &text[quote.len_utf8()..text.len() - quote.len_utf8()];
    let mut decoded = String::with_capacity(body.len());
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            decoded.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            decoded.push(ch);
        }
    }
    if escaped {
        decoded.push('\\');
    }
    Ok(decoded)
}

fn is_major_minor_version(text: &str) -> bool {
    let Some((major, minor)) = text.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.chars().all(|ch| ch.is_ascii_digit())
        && minor.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use crate::ast::{
        ConstValue, Declaration, IdlPragmaKind, InterfaceMember, ParamDirection, PrimitiveType,
        TypeRef, UnionLabel,
    };

    // Regression (security review, LOW): a crafted `.idl` nested far past
    // MAX_NEST_DEPTH must return an error, not recurse until the stack overflows.
    #[test]
    fn rejects_pathologically_deep_nesting_without_stack_overflow() {
        let depth = 5000;
        let mut modules = String::new();
        for i in 0..depth {
            modules.push_str(&format!("module M{i} {{ "));
        }
        modules.push_str("interface I { void f(); };");
        for _ in 0..depth {
            modules.push_str(" };");
        }
        let err = crate::parse_idl(&modules).expect_err("deep module nesting must be rejected");
        assert!(
            err.to_string().to_lowercase().contains("nesting"),
            "expected a nesting-depth error, got: {err}"
        );

        // Deeply nested constructed types are bounded the same way.
        let mut seq = String::from("module M { typedef ");
        for _ in 0..depth {
            seq.push_str("sequence<");
        }
        seq.push_str("long");
        for _ in 0..depth {
            seq.push('>');
        }
        seq.push_str(" T; };");
        assert!(
            crate::parse_idl(&seq).is_err(),
            "deep sequence nesting must be rejected"
        );

        // A modestly nested document still parses.
        crate::parse_idl("module A { module B { module C { interface I { void f(); }; }; }; };")
            .expect("moderate nesting parses");
    }

    #[test]
    fn parses_module_interface_operation_and_raises() {
        let ast = crate::parse_idl(
            "module Foo { exception BadInput {}; interface Bar : Baz { long compute(in string s, out long code) raises(BadInput); }; };",
        )
        .expect("IDL parses");
        let Declaration::Module(module) = &ast.declarations[0] else {
            panic!("module expected")
        };
        assert_eq!(module.name, "Foo");
        let Declaration::Interface(interface) = &module.declarations[1] else {
            panic!("interface expected")
        };
        assert_eq!(interface.name, "Bar");
        assert_eq!(interface.inherits[0].parts, vec!["Baz"]);
        let InterfaceMember::Operation(operation) = &interface.members[0] else {
            panic!("operation expected")
        };
        assert_eq!(operation.name, "compute");
        assert_eq!(operation.params.len(), 2);
        assert_eq!(operation.raises[0].parts, vec!["BadInput"]);
    }

    #[test]
    fn parses_local_interface_as_interface() {
        let ast =
            crate::parse_idl("local interface ConfigStore { void reset(); };").expect("IDL parses");

        let Declaration::Interface(interface) = &ast.declarations[0] else {
            panic!("interface expected")
        };
        assert_eq!(interface.name, "ConfigStore");
    }

    #[test]
    fn parses_interface_forward_declaration_as_empty_interface() {
        let ast = crate::parse_idl("local interface Condition;").expect("IDL parses");

        let Declaration::Interface(interface) = &ast.declarations[0] else {
            panic!("interface expected")
        };
        assert_eq!(interface.name, "Condition");
        assert!(interface.members.is_empty());
    }

    #[test]
    fn parses_oneway_void_operation() {
        let ast = crate::parse_idl("interface Ping { oneway void notify(in long code); };")
            .expect("IDL parses");
        let Declaration::Interface(interface) = &ast.declarations[0] else {
            panic!("interface expected")
        };
        let InterfaceMember::Operation(operation) = &interface.members[0] else {
            panic!("operation expected")
        };
        assert!(operation.oneway);
        assert_eq!(operation.return_type, TypeRef::Void);
    }

    #[test]
    fn parses_struct_enum_exception_typedef_const_and_attributes() {
        let source = r#"
            module Foo {
              enum Color { RED, GREEN, BLUE };
              struct Item { long id; string<32> name; };
              exception BadInput { string reason; };
              typedef sequence<Item, 8> ItemSeq;
              const long Limit = 8;
              interface Bar {
                readonly attribute string name;
                attribute Color color;
              };
            };
        "#;
        let ast = crate::parse_idl(source).expect("IDL parses");
        let Declaration::Module(module) = &ast.declarations[0] else {
            panic!("module expected")
        };
        assert!(matches!(module.declarations[0], Declaration::Enum(_)));
        assert!(matches!(module.declarations[1], Declaration::Struct(_)));
        assert!(matches!(module.declarations[2], Declaration::Exception(_)));
        assert!(matches!(module.declarations[3], Declaration::Typedef(_)));
        assert!(matches!(module.declarations[4], Declaration::Const(_)));
        let Declaration::Interface(interface) = &module.declarations[5] else {
            panic!("interface expected")
        };
        assert_eq!(interface.members.len(), 2);
    }

    #[test]
    fn parses_annotations_on_enum_variants() {
        let ast = crate::parse_idl("enum SubmessageKind { @value(0x00) RTPS_HE, PAD };")
            .expect("IDL parses");

        let Declaration::Enum(enum_decl) = &ast.declarations[0] else {
            panic!("enum expected")
        };
        assert_eq!(enum_decl.variants, vec!["RTPS_HE", "PAD"]);
    }

    #[test]
    fn parses_bitmask_as_enum_like_declaration() {
        let ast = crate::parse_idl(
            "@bit_bound(16) bitmask MemberFlag { @position(0) TRY_CONSTRUCT1, IS_KEY };",
        )
        .expect("IDL parses");

        let Declaration::Enum(enum_decl) = &ast.declarations[0] else {
            panic!("enum expected")
        };
        assert_eq!(enum_decl.name, "MemberFlag");
        assert_eq!(enum_decl.variants, vec!["TRY_CONSTRUCT1", "IS_KEY"]);
    }

    #[test]
    fn parses_fixed_union_valuetype_and_eventtype_shells() {
        let source = r#"
            union Choice switch (long) {
              case 1: string name;
              default: fixed<5, 2> amount;
            };
            abstract valuetype V supports Foo {};
            eventtype E : V {};
        "#;
        let ast = crate::parse_idl(source).expect("IDL parses");
        assert!(matches!(ast.declarations[0], Declaration::Union(_)));
        assert!(matches!(ast.declarations[1], Declaration::ValueType(_)));
        assert!(matches!(ast.declarations[2], Declaration::EventType(_)));
    }

    #[test]
    fn parses_forward_valuetype_and_eventtype_declarations() {
        let ast = crate::parse_idl("valuetype TypeDescriptor; eventtype SampleEvent;")
            .expect("IDL parses");

        let Declaration::ValueType(value_type) = &ast.declarations[0] else {
            panic!("valuetype expected")
        };
        assert_eq!(value_type.name, "TypeDescriptor");

        let Declaration::EventType(event_type) = &ast.declarations[1] else {
            panic!("eventtype expected")
        };
        assert_eq!(event_type.name, "SampleEvent");
    }

    #[test]
    fn parses_annotation_declarations() {
        let ast = crate::parse_idl("@annotation RPCRequestType {}; @RPCRequestType struct S {};")
            .expect("IDL parses");

        assert!(matches!(ast.declarations[0], Declaration::ValueType(_)));
        assert!(matches!(ast.declarations[1], Declaration::Struct(_)));
    }

    #[test]
    fn parses_minimal_com_idl_forms() {
        let ast = crate::parse_idl(
            r#"
            import "unknwn.idl";
            [uuid(1234), dual]
            interface I : IDispatch {
              [id(1)] HRESULT Start([in] SAFEARRAY(VARIANT)* Values, [out, retval] long* Result);
            };
            [uuid(5678)] library L { importlib("stdole32.tlb"); interface I; };
            "#,
        )
        .expect("IDL parses");

        let Declaration::Interface(interface) = &ast.declarations[1] else {
            panic!("interface expected")
        };
        let InterfaceMember::Operation(operation) = &interface.members[0] else {
            panic!("operation expected")
        };
        assert_eq!(operation.params.len(), 2);
        assert_eq!(operation.params[1].direction, ParamDirection::Out);
    }

    #[test]
    fn parses_union_forward_declaration_as_empty_union() {
        let ast = crate::parse_idl("union Parameter;").expect("IDL parses");

        let Declaration::Union(union_decl) = &ast.declarations[0] else {
            panic!("union expected")
        };
        assert_eq!(union_decl.name, "Parameter");
        assert!(union_decl.arms.is_empty());
    }

    #[test]
    fn parses_named_and_scoped_const_values() {
        let ast = crate::parse_idl(
            "const Color DefaultColor = RED; const Color RemoteColor = ::Foo::GREEN;",
        )
        .expect("IDL parses");
        assert_eq!(ast.declarations.len(), 2);
    }

    #[test]
    fn ignores_scoped_annotations_on_declarations() {
        let ast = crate::parse_idl(
            "@OpenDDS::internal::special_serialization(\"prop_seq\") typedef sequence<string> PropertySeq;",
        )
        .expect("IDL parses");

        assert_eq!(ast.declarations.len(), 1);
        assert!(ast
            .warnings
            .iter()
            .any(|warning| warning.contains("@OpenDDS::internal::special_serialization")));
    }

    #[test]
    fn review_parses_long_double_field_and_operation_return_type() {
        let ast = crate::parse_idl(
            "struct S { long double value; }; interface I { long double measure(); };",
        )
        .expect("IDL parses");

        let Declaration::Struct(struct_decl) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        assert_eq!(
            struct_decl.fields[0].ty,
            TypeRef::Primitive(PrimitiveType::LongDouble)
        );

        let Declaration::Interface(interface) = &ast.declarations[1] else {
            panic!("interface expected")
        };
        let InterfaceMember::Operation(operation) = &interface.members[0] else {
            panic!("operation expected")
        };
        assert_eq!(
            operation.return_type,
            TypeRef::Primitive(PrimitiveType::LongDouble)
        );
    }

    #[test]
    fn review_parses_negative_integer_constants_and_union_labels() {
        let ast = crate::parse_idl(
            "const long Min = -1; union U switch (long) { case -1: string error; default: long ok; };",
        )
        .expect("IDL parses");

        let Declaration::Const(const_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(const_decl.value, ConstValue::Integer(-1));

        let Declaration::Union(union_decl) = &ast.declarations[1] else {
            panic!("union expected")
        };
        assert_eq!(
            union_decl.arms[0].labels[0],
            UnionLabel::Case(ConstValue::Integer(-1))
        );
    }

    #[test]
    fn parses_hex_and_octal_integer_constants() {
        let ast = crate::parse_idl("const unsigned long Hex = 0x018252d3; const long Oct = 077;")
            .expect("IDL parses");

        let Declaration::Const(hex_decl) = &ast.declarations[0] else {
            panic!("hex const expected")
        };
        assert_eq!(hex_decl.value, ConstValue::Integer(0x018252d3));

        let Declaration::Const(oct_decl) = &ast.declarations[1] else {
            panic!("octal const expected")
        };
        assert_eq!(oct_decl.value, ConstValue::Integer(0o77));
    }

    #[test]
    fn parses_wide_character_and_string_literals() {
        let ast = crate::parse_idl("const wchar Letter = L'a'; const wstring Greeting = L\"hi\";")
            .expect("IDL parses");

        let Declaration::Const(letter_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(letter_decl.value, ConstValue::String("L'a'".to_owned()));

        let Declaration::Const(greeting_decl) = &ast.declarations[1] else {
            panic!("const expected")
        };
        assert_eq!(
            greeting_decl.value,
            ConstValue::String("L\"hi\"".to_owned())
        );
    }

    #[test]
    fn parses_numeric_constant_expressions() {
        let ast = crate::parse_idl(
            "const unsigned long Read = 0x0001 << 3; const unsigned long Mask = 1 | 4;",
        )
        .expect("IDL parses");

        let Declaration::Const(read_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(read_decl.value, ConstValue::Integer(8));

        let Declaration::Const(mask_decl) = &ast.declarations[1] else {
            panic!("const expected")
        };
        assert_eq!(mask_decl.value, ConstValue::Integer(5));
    }

    #[test]
    fn parses_numeric_constant_expressions_with_operator_precedence() {
        let ast =
            crate::parse_idl("const unsigned long Mask = 1 << 1 | 1 << 3;").expect("IDL parses");

        let Declaration::Const(mask_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(mask_decl.value, ConstValue::Integer(10));
    }

    #[test]
    fn consumes_unsupported_named_constant_expressions_with_warning() {
        let ast = crate::parse_idl("const unsigned long Derived = Base + 1;")
            .expect("IDL parses with warning");

        let Declaration::Const(const_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(const_decl.value, ConstValue::Integer(0));
        assert!(ast
            .warnings
            .iter()
            .any(|warning| warning.contains("unsupported IDL constant expression")));
    }

    #[test]
    fn parses_array_declarators_on_typedefs_fields_and_params() {
        let ast = crate::parse_idl(
            "typedef octet OctetArray16[16]; struct S { octet bytes[8]; }; interface I { void set(in octet value[4]); };",
        )
        .expect("IDL parses");

        let Declaration::Typedef(typedef) = &ast.declarations[0] else {
            panic!("typedef expected")
        };
        assert_eq!(
            typedef.ty,
            TypeRef::Array {
                element: Box::new(TypeRef::Primitive(PrimitiveType::Octet)),
                dimensions: vec![16]
            }
        );

        let Declaration::Struct(struct_decl) = &ast.declarations[1] else {
            panic!("struct expected")
        };
        assert!(matches!(
            struct_decl.fields[0].ty,
            TypeRef::Array {
                dimensions: ref dims,
                ..
            } if dims == &[8]
        ));

        let Declaration::Interface(interface) = &ast.declarations[2] else {
            panic!("interface expected")
        };
        let InterfaceMember::Operation(operation) = &interface.members[0] else {
            panic!("operation expected")
        };
        assert!(matches!(
            operation.params[0].ty,
            TypeRef::Array {
                dimensions: ref dims,
                ..
            } if dims == &[4]
        ));
    }

    #[test]
    fn parses_arithmetic_array_dimensions() {
        let ast = crate::parse_idl("struct S { octet digest[8*16]; };").expect("IDL parses");

        let Declaration::Struct(struct_decl) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        assert!(matches!(
            struct_decl.fields[0].ty,
            TypeRef::Array {
                dimensions: ref dims,
                ..
            } if dims == &[128]
        ));
    }

    #[test]
    fn parses_comma_separated_struct_fields() {
        let ast = crate::parse_idl("struct S { long x, y; string a, b, c; };").expect("IDL parses");

        let Declaration::Struct(struct_decl) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        let names = struct_decl
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["x", "y", "a", "b", "c"]);
    }

    #[test]
    fn parses_struct_inheritance() {
        let ast = crate::parse_idl("struct Base { long x; }; struct Child : Base { long y; };")
            .expect("IDL parses");

        assert!(matches!(ast.declarations[1], Declaration::Struct(_)));
    }

    #[test]
    fn parses_forward_struct_declaration() {
        let ast = crate::parse_idl("struct Node; struct Node { sequence<Node> Children; };")
            .expect("IDL parses");

        let Declaration::Struct(forward) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        assert_eq!(forward.name, "Node");
        assert!(forward.fields.is_empty());
    }

    #[test]
    fn skips_annotations_in_type_positions() {
        let ast = crate::parse_idl(
            "struct S { @optional long x; sequence<@try_construct(USE_DEFAULT) string<3>, 2> names; };",
        )
        .expect("IDL parses");

        let Declaration::Struct(struct_decl) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        assert_eq!(struct_decl.fields.len(), 2);
    }

    #[test]
    fn skips_annotations_between_declarators_and_array_suffixes() {
        let ast = crate::parse_idl(
            "typedef string<20> NameArray @try_construct(TRIM)[10]; struct S { NameArray Names @try_construct(USE_DEFAULT)[3]; };",
        )
        .expect("IDL parses");

        let Declaration::Typedef(typedef) = &ast.declarations[0] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            typedef.ty,
            TypeRef::Array {
                dimensions: ref dims,
                ..
            } if dims == &[10]
        ));

        let Declaration::Struct(struct_decl) = &ast.declarations[1] else {
            panic!("struct expected")
        };
        assert!(matches!(
            struct_decl.fields[0].ty,
            TypeRef::Array {
                dimensions: ref dims,
                ..
            } if dims == &[3]
        ));
    }

    #[test]
    fn parses_named_string_and_sequence_bounds_as_unbounded() {
        let ast = crate::parse_idl(
            "const long LIMIT = 32; typedef string<LIMIT> Name; typedef sequence<octet, LIMIT> Bytes;",
        )
        .expect("IDL parses");

        let Declaration::Typedef(name_typedef) = &ast.declarations[1] else {
            panic!("typedef expected")
        };
        assert_eq!(
            name_typedef.ty,
            TypeRef::String {
                wide: false,
                bound: None
            }
        );

        let Declaration::Typedef(bytes_typedef) = &ast.declarations[2] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            bytes_typedef.ty,
            TypeRef::Sequence { bound: None, .. }
        ));
        assert!(ast
            .warnings
            .iter()
            .any(|warning| warning.contains("nonliteral IDL bound")));
    }

    #[test]
    fn parses_map_types_with_optional_bounds() {
        let ast = crate::parse_idl(
            "typedef map<string, long> Counts; typedef map<string, sequence<long>, 8> Buckets;",
        )
        .expect("IDL parses");

        let Declaration::Typedef(counts_typedef) = &ast.declarations[0] else {
            panic!("typedef expected")
        };
        assert_eq!(
            counts_typedef.ty,
            TypeRef::Map {
                key: Box::new(TypeRef::String {
                    wide: false,
                    bound: None,
                }),
                value: Box::new(TypeRef::Primitive(PrimitiveType::Long)),
                bound: None,
            }
        );

        let Declaration::Typedef(buckets_typedef) = &ast.declarations[1] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            &buckets_typedef.ty,
            TypeRef::Map {
                value,
                bound: Some(8),
                ..
            } if matches!(**value, TypeRef::Sequence { .. })
        ));
    }

    #[test]
    fn parses_typedef_declarator_lists() {
        let ast =
            crate::parse_idl("typedef double Latitude, Longitude, Altitude;").expect("IDL parses");

        let names = ast
            .declarations
            .iter()
            .map(|declaration| match declaration {
                Declaration::Typedef(typedef) => typedef.name.as_str(),
                _ => panic!("typedef expected"),
            })
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Latitude", "Longitude", "Altitude"]);
    }

    #[test]
    fn parses_inline_struct_typedefs() {
        let ast = crate::parse_idl("typedef struct XYZ_ { double x; double y; } XYZ;")
            .expect("IDL parses");

        let Declaration::Struct(struct_decl) = &ast.declarations[0] else {
            panic!("struct expected")
        };
        assert_eq!(struct_decl.name, "XYZ");
        assert_eq!(struct_decl.fields.len(), 2);
    }

    #[test]
    fn parses_named_bound_expressions_as_unbounded() {
        let ast = crate::parse_idl("typedef string<LIMIT + 1> Name;").expect("IDL parses");

        let Declaration::Typedef(name_typedef) = &ast.declarations[0] else {
            panic!("typedef expected")
        };
        assert_eq!(
            name_typedef.ty,
            TypeRef::String {
                wide: false,
                bound: None
            }
        );
    }

    #[test]
    fn rejects_negative_scoped_const_value() {
        let error =
            crate::parse_idl("const Color DefaultColor = -RED;").expect_err("IDL is rejected");
        assert!(error.to_string().contains("expected numeric constant"));
    }

    #[test]
    fn parses_prefix_version_and_unknown_pragmas_as_ordered_declarations() {
        let ast = crate::parse_idl(
            "#pragma prefix \"acme.example\"\nmodule Demo {\n#pragma version Calculator 2.1\n#pragma vendor optimize on\ninterface Calculator {};\n};",
        )
        .expect("IDL parses");

        assert_eq!(ast.pragmas.len(), 3);
        assert!(matches!(
            ast.pragmas[0].kind,
            IdlPragmaKind::Prefix(ref prefix) if prefix == "acme.example"
        ));
        assert!(matches!(
            ast.pragmas[1].kind,
            IdlPragmaKind::Version { ref version, .. } if version == "2.1"
        ));
        assert!(matches!(
            ast.pragmas[2].kind,
            IdlPragmaKind::Unknown { ref arguments } if arguments == "optimize on"
        ));
        assert!(ast
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown IDL pragma '#pragma vendor optimize on'")));

        let Declaration::Module(module) = &ast.declarations[1] else {
            panic!("module expected after prefix pragma")
        };
        assert!(matches!(module.declarations[0], Declaration::Pragma(_)));
        assert!(matches!(module.declarations[2], Declaration::Interface(_)));
    }

    #[test]
    fn malformed_interface_reports_expected_token() {
        let error = crate::parse_idl("interface Broken { long compute(in string s) ")
            .expect_err("malformed IDL is rejected");
        assert!(error.to_string().contains("expected ';'"));
        assert!(error.to_string().contains("line 1, column 46"));
    }

    #[test]
    fn unsupported_preprocessor_directive_mentions_cpp_lite() {
        let error = crate::parse_idl("#if VENDOR_FLAG(1)\ninterface I {};\n#endif\n")
            .expect_err("CPP is rejected");
        assert!(error.to_string().contains("unexpected trailing tokens"));
    }
}
