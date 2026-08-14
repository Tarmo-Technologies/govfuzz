// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Attribute, Const, ConstValue, Declaration, Enum, EventType, Exception, Field, IdlFile,
    IdlPragma, IdlPragmaKind, Interface, InterfaceMember, Module, Operation, Param, ParamDirection,
    PrimitiveType, ScopedName, Struct, TypeRef, Typedef, Union, UnionArm, UnionLabel, ValueType,
};
use crate::error::{IdlParseError, Span};
use crate::lexer::{lex, Token, TokenKind};
use crate::literal::{decode_idl_literal_body, literal_body};
use std::collections::{HashMap, VecDeque};

pub fn parse_source(source: &str) -> Result<IdlFile, IdlParseError> {
    let trimmed = source.trim_start_matches('\u{feff}').trim_start();
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
        scope: Vec::new(),
        constants: HashMap::new(),
        type_bracket_depth: 0,
    }
    .parse_file()
}

/// Maximum module / constructed-type nesting depth. A crafted `.idl` with
/// thousands of nested `module { … }` or `sequence<sequence<…>>` would otherwise
/// recurse until the parser thread's stack overflows (security review, LOW). The
/// `#include` preprocessor has its own separate `MAX_INCLUDE_DEPTH` cap.
const MAX_NEST_DEPTH: usize = 256;

/// The largest `fixed<>` precision IDL defines; also the fallback when a
/// `fixed<>` argument names a constant this parser cannot resolve.
const MAX_FIXED_DIGITS: u16 = 31;

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
    /// Enclosing module / interface names, innermost last. Used to qualify the
    /// constants recorded in [`Parser::constants`] and to resolve a relative
    /// scoped name the way IDL does: innermost enclosing scope outwards.
    scope: Vec<String>,
    /// Integer-valued `const` declarations seen so far, keyed by their fully
    /// qualified name (`Mod::Iface::MAX`). Lets a named constant act as a real
    /// `positive_int_const` in a sequence/string bound or an array dimension
    /// instead of degrading to "unbounded" / dimension 0.
    constants: HashMap<String, i128>,
    /// How many `<…>` type brackets enclose the expression being parsed. Inside
    /// one, `>>` closes two nested `sequence<sequence<T, MAX>>` brackets and is
    /// never a right-shift operator.
    type_bracket_depth: usize,
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
        if self.consume_keyword("native") {
            return self.parse_native();
        }
        if self.consume_keyword("typeprefix") {
            return self.parse_type_prefix();
        }
        if self.consume_keyword("bitset") {
            return self.parse_bitset();
        }
        let is_abstract = self.consume_keyword("abstract");
        // `abstract interface` is IDL3; without this the `abstract` was consumed
        // and the `interface` then failed the declaration dispatch entirely.
        if self.consume_keyword("interface") {
            return self.parse_interface();
        }
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
        self.scope.push(name.clone());
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
        self.scope.pop();
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
        self.scope.push(name.clone());
        let mut members = Vec::new();
        while !self.consume_text("}") {
            if self.parse_nested_scope_declaration(&name)? {
                continue;
            }
            members.push(self.parse_interface_member()?);
        }
        self.scope.pop();
        self.expect_text(";")?;
        Ok(Declaration::Interface(Interface {
            name,
            inherits,
            members,
        }))
    }

    /// IDL lets an `interface` (or `valuetype`) body declare its own types and
    /// constants. `Interface` carries only operations and attributes, so a nested
    /// declaration is hoisted to the enclosing scope — the type still reaches the
    /// generated harness instead of the whole `.idl` being skipped. Returns
    /// `false` when the next token does not start a nested declaration.
    fn parse_nested_scope_declaration(&mut self, owner: &str) -> Result<bool, IdlParseError> {
        let token = self.peek().clone();
        if token.kind != TokenKind::Identifier {
            return Ok(false);
        }
        let keyword = token.text.to_ascii_lowercase();
        if !matches!(
            keyword.as_str(),
            "const"
                | "typedef"
                | "struct"
                | "union"
                | "enum"
                | "bitmask"
                | "bitset"
                | "exception"
                | "native"
                | "typeprefix"
        ) {
            return Ok(false);
        }
        // Every name matched above is an IDL reserved word, so it can only start
        // a declaration here — it can never be an operation's return type.
        let keyword_index = self.pos;
        self.bump();
        let start = self.pending_declarations.len();
        let declaration = match keyword.as_str() {
            "const" => self.parse_const()?,
            "typedef" => self.parse_typedef()?,
            "struct" => self.parse_struct()?,
            "union" => self.parse_union()?,
            "enum" => self.parse_enum()?,
            "bitmask" => self.parse_bitmask()?,
            "bitset" => self.parse_bitset()?,
            "exception" => self.parse_exception()?,
            "native" => self.parse_native()?,
            _ => self.parse_type_prefix()?,
        };
        self.warnings.push(self.warning_at(
            keyword_index,
            format!("IDL declaration nested in '{owner}' hoisted to the enclosing scope"),
        ));
        self.pending_declarations.insert(start, declaration);
        Ok(true)
    }

    /// `bitset Header { bitfield<3> flags; };` — IDL4 / DDS-XTypes. The bit
    /// layout has no Ada mapping here, so the body is skipped and the name is
    /// kept as a placeholder rather than failing the whole file.
    fn parse_bitset(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        let _inherits = self.parse_optional_type_inherits()?;
        if !self.consume_text(";") {
            self.skip_braced_body()?;
            self.expect_text(";")?;
        }
        self.warnings.push(format!(
            "IDL bitset '{name}' mapped to an opaque placeholder"
        ));
        Ok(Declaration::ValueType(ValueType {
            name,
            inherits: Vec::new(),
            is_abstract: false,
        }))
    }

    /// `native Cookie;` — an opaque, language-mapped type. Recorded as a named
    /// placeholder so references to it resolve.
    fn parse_native(&mut self) -> Result<Declaration, IdlParseError> {
        let name = self.expect_identifier()?;
        self.expect_text(";")?;
        self.warnings.push(format!(
            "native IDL type '{name}' mapped to an opaque placeholder"
        ));
        Ok(Declaration::ValueType(ValueType {
            name,
            inherits: Vec::new(),
            is_abstract: false,
        }))
    }

    /// `typeprefix Target "prefix";` — the IDL3 spelling of `#pragma prefix`.
    fn parse_type_prefix(&mut self) -> Result<Declaration, IdlParseError> {
        let line = self.peek().span.line;
        let _target = self.parse_scoped_name()?;
        let prefix = self.expect_string_literal()?;
        self.expect_text(";")?;
        let pragma = IdlPragma {
            name: "prefix".to_owned(),
            line,
            kind: IdlPragmaKind::Prefix(prefix),
        };
        self.pragmas.push(pragma.clone());
        Ok(Declaration::Pragma(pragma))
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
        let inherits = self.parse_optional_type_inherits()?;
        for base in &inherits {
            // `Struct` carries no base, so the inherited fields are dropped.
            // Silently emitting a short struct would misreport the wire layout.
            self.warnings.push(format!(
                "IDL struct '{name}' inherits '{}'; the inherited fields are not mapped",
                format_scoped_name(base)
            ));
        }
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
                let variant = self.expect_identifier()?;
                // `RED = 5` is not OMG IDL — IDL4 spells it `@value(5)` — but it
                // is common in vendor and MIDL-flavoured `.idl`, and rejecting it
                // costs the whole file.
                if self.consume_text("=") {
                    let start = self.pos;
                    let (_, numeric) = self.parse_const_value_and_numeric()?;
                    let text = self.source_text_between(start, self.pos);
                    self.warnings.push(self.warning_at(
                        start,
                        format!("explicit IDL enumerator value '{variant} = {text}' ignored"),
                    ));
                    self.register_constant(&variant, numeric);
                }
                self.skip_annotations()?;
                variants.push(variant);
                if self.consume_text("}") {
                    break;
                }
                self.expect_text(",")?;
                // A trailing comma before `}` is accepted by most IDL compilers.
                if self.consume_text("}") {
                    break;
                }
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
        let (value, numeric) = self.parse_const_value_and_numeric()?;
        self.expect_text(";")?;
        self.register_constant(&name, numeric);
        Ok(Declaration::Const(Const { name, ty, value }))
    }

    /// A `fixed<digits, scale>` argument, which IDL allows to be any constant
    /// expression. An unresolvable one falls back to `fallback` with a warning
    /// rather than failing the whole file, because `ada_emit` maps every
    /// `fixed<>` to the same `Long_Float` placeholder anyway.
    fn parse_fixed_argument(&mut self, role: &str, fallback: i64) -> Result<i64, IdlParseError> {
        let start = self.pos;
        let expression = self.parse_bracketed_const_expression()?;
        if let Some(value) = expression
            .numeric_value
            .and_then(|value| i64::try_from(value).ok())
        {
            return Ok(value);
        }
        let text = self.source_text_between(start, self.pos);
        self.warnings.push(self.warning_at(
            start,
            format!("nonliteral IDL fixed<> {role} '{text}' mapped to {fallback}"),
        ));
        Ok(fallback)
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
            if !self.consume_text("<") {
                // Unparameterised `fixed` is the CORBA "any fixed" placeholder.
                return Ok(TypeRef::Fixed {
                    digits: MAX_FIXED_DIGITS,
                    scale: 0,
                });
            }
            let digits = self.parse_fixed_argument("digits", i64::from(MAX_FIXED_DIGITS))?;
            self.expect_text(",")?;
            let scale = self.parse_fixed_argument("scale", 0)?;
            self.expect_text(">")?;
            return Ok(TypeRef::Fixed {
                digits: u16::try_from(digits).unwrap_or(MAX_FIXED_DIGITS),
                scale: i16::try_from(scale).unwrap_or(0),
            });
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
        let start = self.pos;
        let expression = self.parse_bracketed_const_expression()?;
        if let Some(bound) = expression
            .numeric_value
            .and_then(|value| u64::try_from(value).ok())
        {
            return Ok(Some(bound));
        }
        let text = self.source_text_between(start, self.pos);
        self.warnings.push(self.warning_at(
            start,
            format!("nonliteral IDL bound '{text}' treated as unbounded"),
        ));
        Ok(None)
    }

    /// Parse a constant expression that sits between `<` and `>` — a sequence /
    /// string / map bound or a `fixed<>` argument — so `>>` is read as two
    /// closing brackets instead of a right shift.
    fn parse_bracketed_const_expression(&mut self) -> Result<ConstExpression, IdlParseError> {
        self.type_bracket_depth += 1;
        let expression = self.parse_const_expression(MIN_CONST_PRECEDENCE);
        self.type_bracket_depth -= 1;
        expression
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
        let start = self.pos;
        let expression = self.parse_const_expression(MIN_CONST_PRECEDENCE)?;
        match expression.numeric_value {
            Some(value) => u64::try_from(value)
                .map_err(|_| self.error_here("expected nonnegative array dimension")),
            None => {
                let text = self.source_text_between(start, self.pos);
                self.warnings.push(self.warning_at(
                    start,
                    format!("noninteger IDL array dimension '{text}' mapped to 0"),
                ));
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
        Ok(self.parse_const_value_and_numeric()?.0)
    }

    /// Parse a constant expression, returning both the mapped [`ConstValue`] and
    /// the folded integer value when the expression has one. The integer is what
    /// makes a named constant usable as a bound / array dimension and what lets
    /// `const long B = A;` re-export `A`'s value under `B`.
    fn parse_const_value_and_numeric(
        &mut self,
    ) -> Result<(ConstValue, Option<i128>), IdlParseError> {
        let start = self.pos;
        let expression = self.parse_const_expression(MIN_CONST_PRECEDENCE)?;
        if expression.has_operator {
            if let Some(value) = expression.numeric_value {
                let narrowed = self.narrow_const_integer(value, start);
                return Ok((ConstValue::Integer(narrowed), Some(value)));
            }
            // `2.0 * 3.14159`: a floating expression folds to a floating value.
            // Falling through to the integer path would map it to 0.
            if let Some(value) = expression.float_value.filter(|value| value.is_finite()) {
                return Ok((ConstValue::Float(render_float_literal(value)), None));
            }
            let text = self.source_text_between(start, self.pos);
            self.warnings.push(self.warning_at(
                start,
                format!("unsupported IDL constant expression '{text}' mapped to 0"),
            ));
            return Ok((ConstValue::Integer(0), None));
        }
        if let (ConstValue::Integer(_), Some(value)) = (&expression.value, expression.numeric_value)
        {
            let narrowed = self.narrow_const_integer(value, start);
            return Ok((ConstValue::Integer(narrowed), Some(value)));
        }
        Ok((expression.value, expression.numeric_value))
    }

    /// Constants are folded in `i128` so a full-width `unsigned long long` mask
    /// or `1 << 63` can be evaluated at all, but the AST carries `i64`. Values
    /// outside that range keep their bit pattern and say so, instead of failing
    /// the parse (which skipped the whole file) or wrapping in silence.
    fn narrow_const_integer(&mut self, value: i128, index: usize) -> i64 {
        match i64::try_from(value) {
            Ok(value) => value,
            Err(_) => {
                let wrapped = wrap_const_integer(value);
                self.warnings.push(self.warning_at(
                    index,
                    format!(
                        "IDL constant {value} is outside the signed 64-bit range; kept as the {wrapped} bit pattern"
                    ),
                ));
                wrapped
            }
        }
    }

    fn parse_const_expression(
        &mut self,
        min_precedence: u8,
    ) -> Result<ConstExpression, IdlParseError> {
        let mut left = self.parse_const_unary()?;
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
            let float_value = match (numeric_value, left.float_value, right.float_value) {
                (None, Some(left), Some(right)) => eval_float_operator(operator, left, right),
                _ => None,
            };
            left = ConstExpression {
                value: const_expression_value(numeric_value, float_value),
                numeric_value,
                float_value,
                text: format!("{} {operator} {}", left.text, right.text),
                has_operator: true,
            };
        }
        Ok(left)
    }

    /// `const_exp` unary layer: `+`, `-` and `~` bind tighter than every binary
    /// operator and apply to any operand, not just a literal — `-MAX`, `~(1 << N)`
    /// and `+5` are all ordinary IDL constant expressions.
    fn parse_const_unary(&mut self) -> Result<ConstExpression, IdlParseError> {
        let token = self.peek().clone();
        let operator = match token.text.as_str() {
            "-" | "+" | "~" if token.kind == TokenKind::Punctuation => token.text,
            _ => return self.parse_const_atom(),
        };
        self.bump();
        self.enter_nesting()?;
        let operand = self.parse_const_unary();
        self.depth -= 1;
        let operand = operand?;

        // A signed floating literal is still a floating literal: `-1.5` maps to
        // the value -1.5, not to an integer expression the folder can evaluate.
        if let ConstValue::Float(literal) = &operand.value {
            if operator != "~" && !operand.has_operator {
                let text = if operator == "-" {
                    match literal.strip_prefix('-') {
                        Some(positive) => positive.to_owned(),
                        None => format!("-{literal}"),
                    }
                } else {
                    literal.clone()
                };
                return Ok(ConstExpression {
                    value: ConstValue::Float(text.clone()),
                    numeric_value: None,
                    float_value: parse_float_literal(&text),
                    text,
                    has_operator: false,
                });
            }
        }

        let numeric_value = operand
            .numeric_value
            .and_then(|value| match operator.as_str() {
                "-" => value.checked_neg(),
                "+" => Some(value),
                _ => Some(!value),
            });
        let float_value = match (numeric_value, operand.float_value) {
            (None, Some(value)) if operator != "~" => {
                Some(if operator == "-" { -value } else { value })
            }
            _ => None,
        };
        Ok(ConstExpression {
            value: const_expression_value(numeric_value, float_value),
            numeric_value,
            float_value,
            text: format!("{operator}{}", operand.text),
            has_operator: true,
        })
    }

    fn parse_const_atom(&mut self) -> Result<ConstExpression, IdlParseError> {
        if self.peek().kind == TokenKind::Punctuation && self.peek().text == "(" {
            self.bump();
            self.enter_nesting()?;
            // A `>>` inside the parentheses is a shift again, even when the whole
            // expression sits in a `sequence<…>` bound.
            let outer_brackets = std::mem::take(&mut self.type_bracket_depth);
            let inner = self.parse_const_expression(MIN_CONST_PRECEDENCE);
            self.type_bracket_depth = outer_brackets;
            self.depth -= 1;
            let inner = inner?;
            self.expect_text(")")?;
            return Ok(ConstExpression {
                text: format!("({})", inner.text),
                ..inner
            });
        }
        if self.consume_keyword("true") {
            return Ok(ConstExpression {
                value: ConstValue::Boolean(true),
                numeric_value: Some(1),
                float_value: None,
                text: "true".to_owned(),
                has_operator: false,
            });
        }
        if self.consume_keyword("false") {
            return Ok(ConstExpression {
                value: ConstValue::Boolean(false),
                numeric_value: Some(0),
                float_value: None,
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
            // `L"wide"` / `L'a'`: the prefix marks the literal as wide, it is not
            // part of the value. Keeping it made the constant's value literally
            // `L"wide"`, which then reached the generated Ada verbatim.
            self.bump();
            let text = self.parse_string_literal_run();
            return Ok(ConstExpression {
                value: ConstValue::String(text.clone()),
                numeric_value: None,
                float_value: None,
                text,
                has_operator: false,
            });
        }
        let token = self.peek().clone();
        match token.kind {
            TokenKind::Number => {
                self.bump();
                if is_floating_literal(&token.text) {
                    Ok(ConstExpression {
                        value: ConstValue::Float(token.text.clone()),
                        numeric_value: None,
                        float_value: parse_float_literal(&token.text),
                        text: token.text,
                        has_operator: false,
                    })
                } else {
                    let value = parse_integer_literal(&token.text).ok_or_else(|| {
                        IdlParseError::new("expected integer literal", token.span)
                    })?;
                    Ok(ConstExpression {
                        value: ConstValue::Integer(wrap_const_integer(value)),
                        numeric_value: Some(value),
                        float_value: Some(value as f64),
                        text: value.to_string(),
                        has_operator: false,
                    })
                }
            }
            TokenKind::StringLiteral => {
                let text = self.parse_string_literal_run();
                Ok(ConstExpression {
                    value: ConstValue::String(text.clone()),
                    numeric_value: None,
                    float_value: None,
                    text,
                    has_operator: false,
                })
            }
            TokenKind::Identifier => self.parse_scoped_name_atom(),
            TokenKind::Punctuation if token.text == "::" => self.parse_scoped_name_atom(),
            _ => Err(self.error_here("expected constant value")),
        }
    }

    /// Consume a run of adjacent string literals, which IDL concatenates into
    /// one value (`"line one " "line two"`). The mapped value keeps the source
    /// spelling — one pair of quotes around the joined bodies.
    fn parse_string_literal_run(&mut self) -> String {
        let first = self.peek().text.clone();
        self.bump();
        let quote = first.chars().next().unwrap_or('"');
        let mut body = literal_body(&first).to_owned();
        while self.peek().kind == TokenKind::StringLiteral {
            body.push_str(literal_body(&self.peek().text));
            self.bump();
        }
        format!("{quote}{body}{quote}")
    }

    /// A named constant used as a value: resolve it against the constants
    /// recorded so far so it can serve as a real bound or array dimension. The
    /// `ScopedName` is kept as the mapped value either way, so an unresolved
    /// name still round-trips symbolically.
    fn parse_scoped_name_atom(&mut self) -> Result<ConstExpression, IdlParseError> {
        let name = self.parse_scoped_name()?;
        let text = format_scoped_name(&name);
        let numeric_value = self.lookup_constant(&name);
        Ok(ConstExpression {
            value: ConstValue::ScopedName(name),
            numeric_value,
            float_value: numeric_value.map(|value| value as f64),
            text,
            has_operator: false,
        })
    }

    /// Resolve a scoped name against [`Parser::constants`], walking from the
    /// innermost enclosing scope outwards the way IDL name lookup does.
    fn lookup_constant(&self, name: &ScopedName) -> Option<i128> {
        let suffix = name.parts.join("::");
        if name.absolute {
            return self.constants.get(&suffix).copied();
        }
        for depth in (0..=self.scope.len()).rev() {
            let mut key = String::new();
            for part in &self.scope[..depth] {
                key.push_str(part);
                key.push_str("::");
            }
            key.push_str(&suffix);
            if let Some(value) = self.constants.get(&key) {
                return Some(*value);
            }
        }
        None
    }

    /// Record an integer `const` under its fully qualified name so later bounds,
    /// array dimensions and constant expressions can resolve it.
    fn register_constant(&mut self, name: &str, value: Option<i128>) {
        let Some(value) = value else {
            return;
        };
        let mut key = String::new();
        for part in &self.scope {
            key.push_str(part);
            key.push_str("::");
        }
        key.push_str(name);
        self.constants.insert(key, value);
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
            // Inside `sequence<sequence<octet, MAX>>` the `>>` closes both type
            // brackets; only outside a type bracket is it a right shift.
            ">" if self.type_bracket_depth == 0
                && self
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
            "%" => Some("%"),
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

    /// The source text the tokens `[start, end)` were lexed from, whitespace
    /// normalised. Warnings quote this instead of a reconstruction, so the user
    /// sees `M::MAX` and `3.40023E+16` rather than `M :: MAX` and `3.40023E + 16`.
    fn source_text_between(&self, start: usize, end: usize) -> String {
        let Some(first) = self.tokens.get(start) else {
            return String::new();
        };
        let last = end
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index))
            .map_or(first.span.end, |token| token.span.end);
        self.source
            .get(first.span.start..last)
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Append the source location of token `index` to a warning. Without it a
    /// warning like "noninteger IDL array dimension" names no file position at
    /// all, which is unactionable in a run over hundreds of `.idl` files.
    fn warning_at(&self, index: usize, message: String) -> String {
        match self.tokens.get(index) {
            Some(token) => format!(
                "{message} at line {}, column {}",
                token.span.line, token.span.column
            ),
            None => message,
        }
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
    /// The folded integer value, in `i128` so a full-width `unsigned long long`
    /// constant can be evaluated before it is narrowed for the AST.
    numeric_value: Option<i128>,
    /// The folded floating value, so `2.0 * 3.14159` maps to a floating constant
    /// rather than to integer 0.
    float_value: Option<f64>,
    text: String,
    has_operator: bool,
}

/// The [`ConstValue`] a folded expression carries. Integers win over floats so
/// `7 / 2` keeps IDL's integer division semantics.
fn const_expression_value(numeric: Option<i128>, float: Option<f64>) -> ConstValue {
    if let Some(value) = numeric {
        return ConstValue::Integer(wrap_const_integer(value));
    }
    match float.filter(|value| value.is_finite()) {
        Some(value) => ConstValue::Float(render_float_literal(value)),
        None => ConstValue::Integer(0),
    }
}

/// Keep the low 64 bits of an out-of-range constant. Callers that can warn go
/// through [`Parser::narrow_const_integer`] instead.
fn wrap_const_integer(value: i128) -> i64 {
    value as u64 as i64
}

/// Render a folded floating value as a literal that is valid in both IDL and
/// the generated Ada — Ada rejects an exponent with no decimal point (`1e300`).
fn render_float_literal(value: f64) -> String {
    let text = format!("{value:?}");
    match text.find(['e', 'E']) {
        Some(index) if !text[..index].contains('.') => {
            format!("{}.0{}", &text[..index], &text[index..])
        }
        _ => text,
    }
}

fn parse_float_literal(text: &str) -> Option<f64> {
    text.trim_end_matches(['d', 'D', 'f', 'F'])
        .parse::<f64>()
        .ok()
}

const MIN_CONST_PRECEDENCE: u8 = 1;

fn const_operator_precedence(operator: &str) -> u8 {
    match operator {
        "*" | "/" | "%" => 6,
        "+" | "-" => 5,
        "<<" | ">>" => 4,
        "&" => 3,
        "^" => 2,
        "|" => 1,
        _ => 0,
    }
}

fn eval_float_operator(operator: &str, left: f64, right: f64) -> Option<f64> {
    let value = match operator {
        "+" => left + right,
        "-" => left - right,
        "*" => left * right,
        // Bitwise and shift operators have no floating meaning in IDL.
        "/" => left / right,
        _ => return None,
    };
    value.is_finite().then_some(value)
}

fn eval_integer_operator(operator: &str, left: i128, right: i128) -> Option<i128> {
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
        "%" => {
            if right == 0 {
                None
            } else {
                left.checked_rem(right)
            }
        }
        _ => None,
    }
}

/// Whether an IDL numeric literal is a floating (or fixed-point) literal rather
/// than an integer one: it has a fraction part, a decimal exponent, or a `d`/`D`
/// fixed-point suffix. Hexadecimal literals are excluded so `0x1E` stays an
/// integer and its `E` is a digit, not an exponent marker.
fn is_floating_literal(text: &str) -> bool {
    if text.starts_with("0x") || text.starts_with("0X") {
        return false;
    }
    if text.contains('.') {
        return true;
    }
    if text.strip_suffix(['d', 'D']).is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return true;
    }
    text.char_indices().any(|(index, ch)| {
        if index == 0 || !matches!(ch, 'e' | 'E') {
            return false;
        }
        let exponent = &text[index + 1..];
        let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        digits.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    })
}

fn parse_integer_literal(text: &str) -> Option<i128> {
    let normalized = text.replace('_', "");
    // `100UL`, `0xFFu`, `1ll`: the width/signedness suffix carries no value.
    // None of `u`/`U`/`l`/`L` is a decimal or hexadecimal digit, so trimming
    // them can never eat part of the number itself.
    let normalized = normalized.trim_end_matches(['u', 'U', 'l', 'L']).to_owned();
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
    i128::from_str_radix(digits, radix).ok()
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
        // IDL4 / DDS-XTypes explicit-width names. Without these every `int32`
        // field became a reference to an undefined user type. `int8` maps to the
        // 8-bit `octet`: same width and byte layout, only the signedness of the
        // Ada placeholder differs.
        "int8" | "uint8" => Some(PrimitiveType::Octet),
        "int16" => Some(PrimitiveType::Short),
        "uint16" => Some(PrimitiveType::UShort),
        "int32" => Some(PrimitiveType::Long),
        "uint32" => Some(PrimitiveType::ULong),
        "int64" => Some(PrimitiveType::LongLong),
        "uint64" => Some(PrimitiveType::ULongLong),
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
    Ok(decode_idl_literal_body(
        &text[quote.len_utf8()..text.len() - quote.len_utf8()],
    ))
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

        // The `L` marks the literal as wide; the declared type already records
        // that, so it must not end up inside the constant's value.
        let Declaration::Const(letter_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(letter_decl.value, ConstValue::String("'a'".to_owned()));
        assert_eq!(
            letter_decl.ty,
            TypeRef::Primitive(PrimitiveType::WChar),
            "wideness is carried by the type"
        );

        let Declaration::Const(greeting_decl) = &ast.declarations[1] else {
            panic!("const expected")
        };
        assert_eq!(greeting_decl.value, ConstValue::String("\"hi\"".to_owned()));
        assert_eq!(
            greeting_decl.ty,
            TypeRef::String {
                wide: true,
                bound: None
            }
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
    fn resolves_named_string_and_sequence_bounds_to_their_constant() {
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
                bound: Some(32)
            }
        );

        let Declaration::Typedef(bytes_typedef) = &ast.declarations[2] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            bytes_typedef.ty,
            TypeRef::Sequence {
                bound: Some(32),
                ..
            }
        ));
        assert!(
            ast.warnings.is_empty(),
            "a resolvable bound must not warn: {:?}",
            ast.warnings
        );
    }

    #[test]
    fn resolves_bounds_and_dimensions_through_expressions_and_module_scopes() {
        let ast = crate::parse_idl(
            "module M { const long BASE = 4; }; const long EXTRA = 2;
             typedef sequence<octet, M::BASE * EXTRA> Payload;
             struct Grid { long cells[M::BASE + 1][EXTRA]; };",
        )
        .expect("IDL parses");

        let Declaration::Typedef(payload) = &ast.declarations[2] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            payload.ty,
            TypeRef::Sequence { bound: Some(8), .. }
        ));

        let Declaration::Struct(grid) = &ast.declarations[3] else {
            panic!("struct expected")
        };
        assert!(matches!(
            grid.fields[0].ty,
            TypeRef::Array { dimensions: ref dims, .. } if dims == &[5, 2]
        ));
        assert!(ast.warnings.is_empty(), "{:?}", ast.warnings);
    }

    #[test]
    fn reports_unresolvable_bounds_and_dimensions_with_source_locations() {
        let ast = crate::parse_idl(
            "typedef sequence<octet, EXTERNAL_MAX> Bytes;\nstruct S { long cells[OTHER_MAX]; };",
        )
        .expect("IDL parses");

        let Declaration::Typedef(bytes) = &ast.declarations[0] else {
            panic!("typedef expected")
        };
        assert!(matches!(bytes.ty, TypeRef::Sequence { bound: None, .. }));
        assert!(
            ast.warnings.iter().any(|warning| warning
                == "nonliteral IDL bound 'EXTERNAL_MAX' treated as unbounded at line 1, column 25"),
            "{:?}",
            ast.warnings
        );
        assert!(
            ast.warnings.iter().any(|warning| warning
                == "noninteger IDL array dimension 'OTHER_MAX' mapped to 0 at line 2, column 23"),
            "{:?}",
            ast.warnings
        );
    }

    #[test]
    fn parses_nested_sequence_bounded_by_a_named_constant() {
        // The `>>` closing two type brackets must not be read as a right shift.
        let ast =
            crate::parse_idl("const long MAX = 8; typedef sequence<sequence<octet, MAX>> Blobs;")
                .expect("IDL parses");

        let Declaration::Typedef(blobs) = &ast.declarations[1] else {
            panic!("typedef expected")
        };
        let TypeRef::Sequence { element, bound } = &blobs.ty else {
            panic!("sequence expected")
        };
        assert_eq!(*bound, None);
        assert!(matches!(
            **element,
            TypeRef::Sequence { bound: Some(8), .. }
        ));
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
    fn degrades_negated_nonnumeric_const_value_instead_of_skipping_the_file() {
        // `-RED` is not a legal IDL constant expression, but failing the parse
        // would drop every other declaration in the file along with it.
        let ast = crate::parse_idl("const Color DefaultColor = -RED; struct Keep { long a; };")
            .expect("IDL parses with a warning");

        let Declaration::Const(const_decl) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(const_decl.value, ConstValue::Integer(0));
        assert!(matches!(&ast.declarations[1], Declaration::Struct(item) if item.name == "Keep"));
        assert!(
            ast.warnings.iter().any(|warning| warning
                == "unsupported IDL constant expression '-RED' mapped to 0 at line 1, column 28"),
            "{:?}",
            ast.warnings
        );
    }

    #[test]
    fn parses_the_full_const_expression_grammar() {
        let ast = crate::parse_idl(
            "const long Grouped = (1 + 2) * 3;
             const long Complement = ~0;
             const long Positive = +5;
             const long Remainder = 17 % 5;
             const long Suffixed = 100UL;
             const long Hex = 0x1E + 2;
             const double Exponent = 3.40023E+16;
             const double Small = 1.0e-5;
             const double Negative = -1.5;",
        )
        .expect("IDL parses");

        let values = ast
            .declarations
            .iter()
            .map(|declaration| {
                let Declaration::Const(item) = declaration else {
                    panic!("const expected")
                };
                (item.name.as_str(), item.value.clone())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                ("Grouped", ConstValue::Integer(9)),
                ("Complement", ConstValue::Integer(-1)),
                ("Positive", ConstValue::Integer(5)),
                ("Remainder", ConstValue::Integer(2)),
                ("Suffixed", ConstValue::Integer(100)),
                ("Hex", ConstValue::Integer(32)),
                ("Exponent", ConstValue::Float("3.40023E+16".to_owned())),
                ("Small", ConstValue::Float("1.0e-5".to_owned())),
                ("Negative", ConstValue::Float("-1.5".to_owned())),
            ]
        );
        assert!(ast.warnings.is_empty(), "{:?}", ast.warnings);
    }

    #[test]
    fn hoists_declarations_nested_in_an_interface_body() {
        let ast = crate::parse_idl(
            "interface Session {
                 const long MAX_KEYS = 4;
                 typedef sequence<octet, MAX_KEYS> Keys;
                 struct Token { long id; };
                 exception Denied { long code; };
                 native Cookie;
                 Token issue(in Keys keys);
             };",
        )
        .expect("IDL parses");

        let Declaration::Interface(interface) = &ast.declarations[0] else {
            panic!("interface expected")
        };
        assert_eq!(interface.members.len(), 1, "only the operation stays");

        let names = ast
            .declarations
            .iter()
            .map(|declaration| match declaration {
                Declaration::Const(item) => item.name.clone(),
                Declaration::Typedef(item) => item.name.clone(),
                Declaration::Struct(item) => item.name.clone(),
                Declaration::Exception(item) => item.name.clone(),
                Declaration::ValueType(item) => item.name.clone(),
                Declaration::Interface(item) => item.name.clone(),
                other => panic!("unexpected declaration {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["Session", "MAX_KEYS", "Keys", "Token", "Denied", "Cookie"]
        );

        let Declaration::Typedef(keys) = &ast.declarations[2] else {
            panic!("typedef expected")
        };
        assert!(
            matches!(keys.ty, TypeRef::Sequence { bound: Some(4), .. }),
            "an interface-scoped const still resolves: {:?}",
            keys.ty
        );
    }

    #[test]
    fn folds_floating_constant_expressions_into_floating_values() {
        let ast = crate::parse_idl(
            "const double TWO_PI = 2.0 * 3.14159265358979;
             const float  HALF   = 1.0 / 2.0;
             const double SUM    = 1.5 + 2;
             const long   IDIV   = 7 / 2;",
        )
        .expect("IDL parses");

        let values = ast
            .declarations
            .iter()
            .map(|declaration| {
                let Declaration::Const(item) = declaration else {
                    panic!("const expected")
                };
                item.value.clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                ConstValue::Float("6.28318530717958".to_owned()),
                ConstValue::Float("0.5".to_owned()),
                ConstValue::Float("3.5".to_owned()),
                // Integer operands keep IDL's integer division.
                ConstValue::Integer(3),
            ]
        );
        assert!(ast.warnings.is_empty(), "{:?}", ast.warnings);
    }

    #[test]
    fn folds_full_width_integer_constants_and_flags_the_narrowing() {
        let ast = crate::parse_idl(
            "const unsigned long long MASK = 0xFFFFFFFFFFFFFFFF;
             const long long MIN = -9223372036854775808;
             typedef sequence<octet, 0xFFFFFFFF> Huge;",
        )
        .expect("IDL parses");

        let Declaration::Const(mask) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(mask.value, ConstValue::Integer(-1), "bit pattern preserved");
        let Declaration::Const(min) = &ast.declarations[1] else {
            panic!("const expected")
        };
        assert_eq!(min.value, ConstValue::Integer(i64::MIN));
        let Declaration::Typedef(huge) = &ast.declarations[2] else {
            panic!("typedef expected")
        };
        assert!(matches!(
            huge.ty,
            TypeRef::Sequence {
                bound: Some(4294967295),
                ..
            }
        ));

        assert_eq!(ast.warnings.len(), 1, "{:?}", ast.warnings);
        assert!(
            ast.warnings[0].starts_with("IDL constant 18446744073709551615 is outside"),
            "{:?}",
            ast.warnings
        );
    }

    #[test]
    fn concatenates_adjacent_string_literals() {
        let ast = crate::parse_idl("const string BANNER = \"line one \" \"line two\";")
            .expect("IDL parses");

        let Declaration::Const(banner) = &ast.declarations[0] else {
            panic!("const expected")
        };
        assert_eq!(
            banner.value,
            ConstValue::String("\"line one line two\"".to_owned())
        );
    }

    #[test]
    fn accepts_a_utf8_byte_order_mark_at_the_start_of_a_file() {
        let ast = crate::parse_idl("\u{feff}module M { struct S { long a; }; };")
            .expect("a BOM must not skip the file");

        assert!(matches!(&ast.declarations[0], Declaration::Module(item) if item.name == "M"));
    }

    #[test]
    fn parses_idl4_declarations_that_used_to_abort_the_file() {
        let ast = crate::parse_idl(
            "abstract interface Base { long op(); };
             bitset Header { bitfield<3> flags; };
             struct Widths { int8 a; uint8 b; int16 c; uint16 d; int32 e; uint32 f; int64 g; uint64 h; };",
        )
        .expect("IDL parses");

        assert!(
            matches!(&ast.declarations[0], Declaration::Interface(item) if item.name == "Base")
        );
        assert!(
            matches!(&ast.declarations[1], Declaration::ValueType(item) if item.name == "Header")
        );
        let Declaration::Struct(widths) = &ast.declarations[2] else {
            panic!("struct expected")
        };
        assert_eq!(
            widths
                .fields
                .iter()
                .map(|field| field.ty.clone())
                .collect::<Vec<_>>(),
            vec![
                TypeRef::Primitive(PrimitiveType::Octet),
                TypeRef::Primitive(PrimitiveType::Octet),
                TypeRef::Primitive(PrimitiveType::Short),
                TypeRef::Primitive(PrimitiveType::UShort),
                TypeRef::Primitive(PrimitiveType::Long),
                TypeRef::Primitive(PrimitiveType::ULong),
                TypeRef::Primitive(PrimitiveType::LongLong),
                TypeRef::Primitive(PrimitiveType::ULongLong),
            ]
        );
    }

    #[test]
    fn reports_struct_inheritance_instead_of_dropping_the_base_fields_silently() {
        let ast = crate::parse_idl("struct B { long x; }; struct D : B { long y; };")
            .expect("IDL parses");

        let Declaration::Struct(derived) = &ast.declarations[1] else {
            panic!("struct expected")
        };
        assert_eq!(derived.fields.len(), 1);
        assert!(
            ast.warnings.iter().any(|warning| warning
                == "IDL struct 'D' inherits 'B'; the inherited fields are not mapped"),
            "{:?}",
            ast.warnings
        );
    }

    #[test]
    fn parses_fixed_types_with_named_arguments() {
        let ast = crate::parse_idl("const long DIGITS = 9; typedef fixed<DIGITS, 2> Money;")
            .expect("IDL parses");

        let Declaration::Typedef(money) = &ast.declarations[1] else {
            panic!("typedef expected")
        };
        assert_eq!(
            money.ty,
            TypeRef::Fixed {
                digits: 9,
                scale: 2
            }
        );
    }

    #[test]
    fn accepts_explicit_enumerator_values_and_trailing_commas() {
        let ast = crate::parse_idl("enum Color { RED, GREEN = 5, BLUE, };").expect("IDL parses");

        let Declaration::Enum(color) = &ast.declarations[0] else {
            panic!("enum expected")
        };
        assert_eq!(color.variants, vec!["RED", "GREEN", "BLUE"]);
        assert!(
            ast.warnings
                .iter()
                .any(|warning| warning.starts_with("explicit IDL enumerator value 'GREEN = 5'")),
            "{:?}",
            ast.warnings
        );
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
