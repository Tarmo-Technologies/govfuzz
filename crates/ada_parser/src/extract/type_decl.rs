// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    AdaStandard, Aspects, Constraints, Fields, FormalKind, InterfaceKind, ScalarKind, TypeId,
    TypeKind, TypeOwner, TypeRef, Visibility,
};
use crate::extract::{parse_trailing_aspects, ScopeKind, ScopeTree};
use crate::lexer::{Token, TokenKind};
use std::collections::HashMap;
use std::ops::Range;

pub mod composite;
pub mod reference;
pub mod scalar;

pub fn extract_types(
    scope_tree: &ScopeTree,
    source: &str,
    tokens: &[Token],
    dialect: AdaStandard,
) -> Vec<TypeRef> {
    let mut types = Vec::new();
    let owner_index = TypeOwnerIndex::new(scope_tree);

    for (scope_index, scope) in scope_tree.scopes.iter().enumerate() {
        let owner = owner_index.owner_for_scope(scope_index);
        if scope.is_generic {
            if let Some(scope_start) = token_index_at_byte(tokens, scope.decl_span.start_byte) {
                if let Some(generic_start) = tokens[..scope_start]
                    .iter()
                    .rposition(|token| token.effective_kind == TokenKind::KwGeneric)
                {
                    collect_types_in_range(
                        &mut types,
                        source,
                        tokens,
                        generic_start.saturating_add(1)..scope_start,
                        TypeDeclContext {
                            dialect,
                            force_generic_formal: true,
                            visibility: visibility_for_scope_range(scope.kind, false),
                            owner: owner.clone(),
                        },
                    );
                }
            }
        }

        if let Some(span) = scope.declarative_span {
            if let Some((start, end)) = token_range_for_span(tokens, span.start_byte, span.end_byte)
            {
                collect_types_in_range(
                    &mut types,
                    source,
                    tokens,
                    start..end,
                    TypeDeclContext {
                        dialect,
                        force_generic_formal: false,
                        visibility: visibility_for_scope_range(scope.kind, false),
                        owner: owner.clone(),
                    },
                );
            }
        }

        if let Some(span) = scope.private_declarative_span {
            if let Some((start, end)) = token_range_for_span(tokens, span.start_byte, span.end_byte)
            {
                collect_types_in_range(
                    &mut types,
                    source,
                    tokens,
                    start..end,
                    TypeDeclContext {
                        dialect,
                        force_generic_formal: false,
                        visibility: Visibility::Private,
                        owner,
                    },
                );
            }
        }
    }

    types
}

pub(crate) struct TypeOwnerIndex {
    package_scope_ids: Vec<Option<crate::ast::PackageId>>,
    subprogram_scope_ids: Vec<Option<crate::ast::SubprogramId>>,
}

impl TypeOwnerIndex {
    pub(crate) fn new(scope_tree: &ScopeTree) -> Self {
        let mut package_scope_ids = vec![None; scope_tree.scopes.len()];
        let mut subprogram_scope_ids = vec![None; scope_tree.scopes.len()];
        let mut package_by_name = HashMap::new();
        let mut package_count = 0u32;
        let mut subprogram_count = 0u32;

        for (scope_index, scope) in scope_tree.scopes.iter().enumerate() {
            match scope.kind {
                ScopeKind::PackageSpec | ScopeKind::PackageBody => {
                    let id = package_by_name
                        .entry(scope.name.clone())
                        .or_insert_with(|| {
                            let id = crate::ast::PackageId(package_count);
                            package_count = package_count.saturating_add(1);
                            id
                        });
                    package_scope_ids[scope_index] = Some(*id);
                }
                ScopeKind::SubprogramSpec | ScopeKind::SubprogramBody => {
                    let id = crate::ast::SubprogramId(subprogram_count);
                    subprogram_count = subprogram_count.saturating_add(1);
                    subprogram_scope_ids[scope_index] = Some(id);
                }
            }
        }

        Self {
            package_scope_ids,
            subprogram_scope_ids,
        }
    }

    pub(crate) fn owner_for_scope(&self, scope_index: usize) -> TypeOwner {
        if let Some(subprogram_id) = self
            .subprogram_scope_ids
            .get(scope_index)
            .and_then(|id| *id)
        {
            return TypeOwner::Subprogram(subprogram_id);
        }

        if let Some(package_id) = self.package_scope_ids.get(scope_index).and_then(|id| *id) {
            return TypeOwner::Package(package_id);
        }

        TypeOwner::LibraryLevel
    }
}

fn visibility_for_scope_range(scope_kind: ScopeKind, is_private: bool) -> Visibility {
    if is_private {
        return Visibility::Private;
    }

    match scope_kind {
        ScopeKind::PackageSpec => Visibility::Public,
        ScopeKind::PackageBody | ScopeKind::SubprogramBody => Visibility::Local,
        ScopeKind::SubprogramSpec => Visibility::LibraryLevel,
    }
}

struct TypeDeclContext {
    dialect: AdaStandard,
    force_generic_formal: bool,
    visibility: Visibility,
    owner: TypeOwner,
}

fn collect_types_in_range(
    types: &mut Vec<TypeRef>,
    source: &str,
    tokens: &[Token],
    range: Range<usize>,
    context: TypeDeclContext,
) {
    let mut index = range.start;

    while index < range.end {
        if kind_at(tokens, index, &TokenKind::KwSubtype) {
            if let Some((type_ref, next_index)) =
                parse_subtype_decl(source, tokens, index, types.len() as u32, &context)
            {
                types.push(type_ref);
                index = next_index;
            } else {
                index = skip_to_after_semicolon(tokens, index.saturating_add(1), range.end);
            }
            continue;
        }

        if !kind_at(tokens, index, &TokenKind::KwType) {
            index = index.saturating_add(1);
            continue;
        }

        if let Some((type_ref, next_index)) =
            parse_type_decl(source, tokens, index, types.len() as u32, &context)
        {
            types.push(type_ref);
            index = next_index;
        } else {
            index = skip_to_after_semicolon(tokens, index.saturating_add(1), range.end);
        }
    }
}

fn parse_subtype_decl(
    source: &str,
    tokens: &[Token],
    subtype_index: usize,
    id: u32,
    context: &TypeDeclContext,
) -> Option<(TypeRef, usize)> {
    let name = identifier_text(tokens.get(subtype_index.saturating_add(1))?)?;
    let is_index = find_is_for_type_decl(tokens, subtype_index.saturating_add(2))?;
    let terminator = find_type_decl_terminator(tokens, is_index.saturating_add(1))?;
    let aspect_start = find_aspect_with(
        tokens,
        is_index.saturating_add(1),
        terminator,
        context.dialect,
    )
    .unwrap_or(terminator);
    let constraints = source_text(source, tokens, is_index.saturating_add(1), aspect_start)?
        .trim()
        .to_owned();
    if constraints.is_empty() {
        return None;
    }
    let (aspects, next_index) = if aspect_start < terminator {
        parse_trailing_aspects(source, tokens, aspect_start, context.dialect)
    } else {
        (Vec::new(), terminator.saturating_add(1))
    };

    Some((
        TypeRef {
            id: TypeId(id),
            name_path: vec![name],
            visibility: context.visibility.clone(),
            owner: context.owner.clone(),
            kind: TypeKind::Derived { base: TypeId(0) },
            constraints: Constraints(constraints),
            aspects: Aspects(aspects),
        },
        next_index,
    ))
}

fn parse_type_decl(
    source: &str,
    tokens: &[Token],
    type_index: usize,
    id: u32,
    context: &TypeDeclContext,
) -> Option<(TypeRef, usize)> {
    let name = identifier_text(tokens.get(type_index.saturating_add(1))?)?;
    let is_index = find_is_for_type_decl(tokens, type_index.saturating_add(2))?;
    let terminator = find_type_decl_terminator(tokens, is_index.saturating_add(1))?;
    let aspect_start = find_aspect_with(
        tokens,
        is_index.saturating_add(1),
        terminator,
        context.dialect,
    )
    .unwrap_or(terminator);
    let head_start = is_index.saturating_add(1);
    let head_end = aspect_start;
    let (aspects, next_index) = if aspect_start < terminator {
        parse_trailing_aspects(source, tokens, aspect_start, context.dialect)
    } else {
        (Vec::new(), terminator.saturating_add(1))
    };
    let (kind, constraints) = if context.force_generic_formal {
        (
            TypeKind::Generic(FormalKind::Type),
            source_text(source, tokens, head_start, head_end)
                .unwrap_or_default()
                .trim()
                .to_owned(),
        )
    } else {
        parse_type_head(
            source,
            tokens,
            type_index,
            head_start,
            head_end,
            context.dialect,
        )?
    };

    Some((
        TypeRef {
            id: TypeId(id),
            name_path: vec![name],
            visibility: context.visibility.clone(),
            owner: context.owner.clone(),
            kind,
            constraints: Constraints(constraints),
            aspects: Aspects(aspects),
        },
        next_index,
    ))
}

fn parse_type_head(
    source: &str,
    tokens: &[Token],
    type_index: usize,
    start: usize,
    end: usize,
    dialect: AdaStandard,
) -> Option<(TypeKind, String)> {
    parse_scalar_or_enum(source, tokens, start, end)
        .or_else(|| parse_composite_type(source, tokens, type_index, start, end))
        .or_else(|| parse_reference_type(source, tokens, start, end, dialect))
}

fn parse_scalar_or_enum(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    match tokens.get(start).map(|token| &token.effective_kind) {
        Some(TokenKind::KwRange) => {
            let constraints = source_text(source, tokens, start.saturating_add(1), end)?;
            if !valid_range_expr(tokens, start.saturating_add(1), end) {
                return None;
            }
            Some((
                TypeKind::Scalar(ScalarKind::Integer),
                constraints.trim().to_owned(),
            ))
        }
        Some(TokenKind::KwMod) => {
            let constraints = source_text(source, tokens, start.saturating_add(1), end)?;
            if constraints.trim().is_empty() {
                return None;
            }
            Some((
                TypeKind::Scalar(ScalarKind::Modular),
                constraints.trim().to_owned(),
            ))
        }
        Some(TokenKind::KwDigits) => {
            let constraints = source_text(source, tokens, start, end)?;
            Some((
                TypeKind::Scalar(ScalarKind::Float),
                constraints.trim().to_owned(),
            ))
        }
        Some(TokenKind::KwDelta) => {
            let constraints = source_text(source, tokens, start, end)?;
            let kind = if contains_kind(tokens, start, end, &TokenKind::KwDigits) {
                ScalarKind::Decimal
            } else {
                ScalarKind::Fixed
            };
            Some((TypeKind::Scalar(kind), constraints.trim().to_owned()))
        }
        Some(TokenKind::LParen) => parse_enum_literals(source, tokens, start, end)
            .map(|literals| (TypeKind::Enum(literals), String::new())),
        _ => None,
    }
}

fn valid_range_expr(tokens: &[Token], start: usize, end: usize) -> bool {
    if start >= end {
        return false;
    }

    matches!(
        tokens
            .get(end.saturating_sub(1))
            .map(|token| &token.effective_kind),
        Some(
            TokenKind::Identifier(_)
                | TokenKind::IntLiteral(_)
                | TokenKind::RealLiteral(_)
                | TokenKind::BasedLiteral(_)
                | TokenKind::CharLiteral(_)
                | TokenKind::StringLiteral(_)
                | TokenKind::RParen
        )
    )
}

fn parse_enum_literals(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Option<Vec<String>> {
    if !kind_at(tokens, start, &TokenKind::LParen)
        || !kind_at(tokens, end.saturating_sub(1), &TokenKind::RParen)
    {
        return None;
    }

    let mut literals = Vec::new();
    let mut index = start.saturating_add(1);
    while index < end.saturating_sub(1) {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Identifier(name)) => literals.push(name.clone()),
            Some(TokenKind::CharLiteral(_)) => {
                literals.push(source_text(source, tokens, index, index.saturating_add(1))?);
            }
            Some(TokenKind::Comma) => {}
            Some(_) => return None,
            None => return None,
        }
        index = index.saturating_add(1);
    }

    if literals.is_empty() {
        None
    } else {
        Some(literals)
    }
}

fn parse_composite_type(
    source: &str,
    tokens: &[Token],
    type_index: usize,
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    if let Some(discriminated) = parse_discriminated_record(source, tokens, type_index, start, end)
    {
        return Some(discriminated);
    }

    match tokens.get(start).map(|token| &token.effective_kind) {
        Some(TokenKind::KwArray) => parse_array_type(source, tokens, start, end),
        Some(TokenKind::KwRecord) => parse_record_type(source, tokens, start, end, String::new()),
        Some(TokenKind::KwLimited)
            if kind_at(tokens, start.saturating_add(1), &TokenKind::KwRecord) =>
        {
            parse_record_type(
                source,
                tokens,
                start.saturating_add(1),
                end,
                "limited".to_owned(),
            )
        }
        Some(TokenKind::KwNew) => parse_derived_type(source, tokens, start, end),
        Some(TokenKind::KwTagged) => Some((
            TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            },
            String::new(),
        )),
        Some(TokenKind::KwAbstract)
            if kind_at(tokens, start.saturating_add(1), &TokenKind::KwTagged) =>
        {
            Some((
                TypeKind::Tagged {
                    base: TypeId(0),
                    is_abstract: true,
                },
                String::new(),
            ))
        }
        _ => None,
    }
}

fn parse_array_type(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    let open = start.saturating_add(1);
    if !kind_at(tokens, open, &TokenKind::LParen) {
        return None;
    }
    let close = find_matching_rparen(tokens, open, end)?;
    let bounds = source_text(source, tokens, open.saturating_add(1), close)?
        .trim()
        .to_owned();
    let of_index = first_kind_at_or_after(tokens, close.saturating_add(1), end, &TokenKind::KwOf)?;
    let elem_name = array_component_name(tokens, of_index.saturating_add(1), end);

    Some((
        TypeKind::Array {
            idx_types: Vec::new(),
            elem_type: TypeId(0),
            bounds,
            elem_name,
        },
        String::new(),
    ))
}

/// First token index >= `from` (and < `end`) whose kind matches `target`.
fn first_kind_at_or_after(
    tokens: &[Token],
    from: usize,
    end: usize,
    target: &TokenKind,
) -> Option<usize> {
    (from..end.min(tokens.len())).find(|&index| &tokens[index].kind == target)
}

/// Recover the component type name of `array (...) of <component>`, dropping a
/// leading `aliased`/`constant` and any trailing constraint, e.g.
/// `array (..) of aliased Byte` -> `Byte`.
fn array_component_name(tokens: &[Token], start: usize, end: usize) -> String {
    let mut index = start;
    while index < end.min(tokens.len())
        && matches!(
            tokens[index].kind,
            TokenKind::KwAliased | TokenKind::KwConstant
        )
    {
        index = index.saturating_add(1);
    }
    let mut name = String::new();
    while index < end.min(tokens.len()) {
        match &tokens[index].kind {
            TokenKind::Identifier(text) => name.push_str(text),
            TokenKind::Dot => name.push('.'),
            _ => break,
        }
        index = index.saturating_add(1);
    }
    name
}

fn parse_record_type(
    source: &str,
    tokens: &[Token],
    record_index: usize,
    end: usize,
    constraints: String,
) -> Option<(TypeKind, String)> {
    let fields_end = find_end_record(tokens, record_index.saturating_add(1), end)?;
    let fields = split_semicolon_texts(source, tokens, record_index.saturating_add(1), fields_end);
    Some((TypeKind::Record(Fields(fields)), constraints))
}

fn parse_discriminated_record(
    source: &str,
    tokens: &[Token],
    type_index: usize,
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    let discrim_open = type_index.saturating_add(2);
    if !kind_at(tokens, discrim_open, &TokenKind::LParen) {
        return None;
    }
    let discrim_close = find_matching_rparen(tokens, discrim_open, start)?;
    if !kind_at(tokens, start, &TokenKind::KwRecord) {
        return None;
    }
    find_end_record(tokens, start.saturating_add(1), end)?;
    let discriminants = split_semicolon_texts(
        source,
        tokens,
        discrim_open.saturating_add(1),
        discrim_close,
    );

    Some((
        TypeKind::Discriminated {
            base: TypeId(0),
            discriminants: Fields(discriminants),
        },
        String::new(),
    ))
}

fn parse_derived_type(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    let base_end = find_derived_base_end(tokens, start.saturating_add(1), end);
    let base = source_text(source, tokens, start.saturating_add(1), base_end)?
        .trim()
        .to_owned();
    if base.is_empty() {
        return None;
    }

    if contains_kind(tokens, base_end, end, &TokenKind::KwRecord)
        || (kind_at(tokens, base_end, &TokenKind::KwWith)
            && kind_at(tokens, base_end.saturating_add(1), &TokenKind::KwPrivate))
    {
        return Some((
            TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            },
            base,
        ));
    }

    Some((TypeKind::Derived { base: TypeId(0) }, base))
}

fn parse_reference_type(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
    dialect: AdaStandard,
) -> Option<(TypeKind, String)> {
    match tokens.get(start).map(|token| &token.effective_kind) {
        Some(TokenKind::KwAccess) => parse_access_type(source, tokens, start, end),
        Some(TokenKind::KwNot)
            if kind_at(tokens, start.saturating_add(1), &TokenKind::KwNull)
                && kind_at(tokens, start.saturating_add(2), &TokenKind::KwAccess) =>
        {
            if dialect < AdaStandard::Ada2005 {
                return Some((TypeKind::Unknown, String::new()));
            }
            parse_access_type(source, tokens, start, end)
        }
        Some(TokenKind::KwPrivate) => Some((TypeKind::Private, "private".to_owned())),
        Some(TokenKind::KwLimited)
            if kind_at(tokens, start.saturating_add(1), &TokenKind::KwPrivate) =>
        {
            Some((TypeKind::Private, "limited private".to_owned()))
        }
        Some(TokenKind::KwInterface) if dialect >= AdaStandard::Ada2005 => {
            parse_interface_type(source, tokens, start, end, InterfaceKind::Plain)
        }
        Some(TokenKind::KwLimited)
            if dialect >= AdaStandard::Ada2005
                && kind_at(tokens, start.saturating_add(1), &TokenKind::KwInterface) =>
        {
            parse_interface_type(
                source,
                tokens,
                start.saturating_add(1),
                end,
                InterfaceKind::Limited,
            )
        }
        Some(TokenKind::KwSynchronized)
            if dialect >= AdaStandard::Ada2005
                && kind_at(tokens, start.saturating_add(1), &TokenKind::KwInterface) =>
        {
            parse_interface_type(
                source,
                tokens,
                start.saturating_add(1),
                end,
                InterfaceKind::Synchronized,
            )
        }
        Some(TokenKind::KwTask)
            if dialect >= AdaStandard::Ada2005
                && kind_at(tokens, start.saturating_add(1), &TokenKind::KwInterface) =>
        {
            parse_interface_type(
                source,
                tokens,
                start.saturating_add(1),
                end,
                InterfaceKind::Task,
            )
        }
        Some(TokenKind::KwProtected)
            if dialect >= AdaStandard::Ada2005
                && kind_at(tokens, start.saturating_add(1), &TokenKind::KwInterface) =>
        {
            parse_interface_type(
                source,
                tokens,
                start.saturating_add(1),
                end,
                InterfaceKind::Protected,
            )
        }
        _ => None,
    }
}

fn parse_access_type(
    source: &str,
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Option<(TypeKind, String)> {
    let constraint_start = if kind_at(tokens, start, &TokenKind::KwAccess) {
        start.saturating_add(1)
    } else {
        start
    };
    let constraints = source_text(source, tokens, constraint_start, end)?
        .trim()
        .to_owned();
    if constraints.is_empty() {
        return None;
    }

    Some((TypeKind::Access { target: TypeId(0) }, constraints))
}

fn parse_interface_type(
    source: &str,
    tokens: &[Token],
    interface_index: usize,
    end: usize,
    kind: InterfaceKind,
) -> Option<(TypeKind, String)> {
    let mut parents = Vec::new();
    let mut index = interface_index.saturating_add(1);

    while index < end {
        if !kind_at(tokens, index, &TokenKind::KwAnd) {
            index = index.saturating_add(1);
            continue;
        }
        let parent_start = index.saturating_add(1);
        let parent_end = find_parent_name_end(tokens, parent_start, end);
        if let Some(parent) = source_text(source, tokens, parent_start, parent_end) {
            let trimmed = parent.trim();
            if !trimmed.is_empty() {
                parents.push(trimmed.to_owned());
            }
        }
        index = parent_end;
    }

    Some((TypeKind::Interface { parents, kind }, String::new()))
}

fn find_is_for_type_decl(tokens: &[Token], mut index: usize) -> Option<usize> {
    let mut paren_depth = 0u32;
    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::KwIs) if paren_depth == 0 => return Some(index),
            Some(TokenKind::Semicolon | TokenKind::Eof) if paren_depth == 0 => return None,
            Some(_) => {}
            None => return None,
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_type_decl_terminator(tokens: &[Token], mut index: usize) -> Option<usize> {
    let mut paren_depth = 0u32;
    let mut record_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::KwRecord) if paren_depth == 0 => {
                record_depth = record_depth.saturating_add(1);
            }
            Some(TokenKind::KwEnd)
                if paren_depth == 0
                    && record_depth > 0
                    && kind_at(tokens, index.saturating_add(1), &TokenKind::KwRecord) =>
            {
                record_depth = record_depth.saturating_sub(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::Semicolon) if paren_depth == 0 && record_depth == 0 => {
                return Some(index);
            }
            Some(TokenKind::Eof) => return None,
            Some(_) => {}
            None => return None,
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_aspect_with(
    tokens: &[Token],
    mut index: usize,
    end: usize,
    dialect: AdaStandard,
) -> Option<usize> {
    if dialect < AdaStandard::Ada2012 {
        return None;
    }
    let mut paren_depth = 0u32;
    let mut record_depth = 0u32;

    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::KwRecord) if paren_depth == 0 => {
                record_depth = record_depth.saturating_add(1);
            }
            Some(TokenKind::KwEnd)
                if paren_depth == 0
                    && record_depth > 0
                    && kind_at(tokens, index.saturating_add(1), &TokenKind::KwRecord) =>
            {
                record_depth = record_depth.saturating_sub(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::KwWith)
                if paren_depth == 0
                    && record_depth == 0
                    && matches!(
                        tokens
                            .get(index.saturating_add(1))
                            .map(|token| &token.effective_kind),
                        Some(TokenKind::Identifier(_))
                    ) =>
            {
                return Some(index);
            }
            Some(_) => {}
            None => return None,
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_matching_rparen(tokens: &[Token], open: usize, end: usize) -> Option<usize> {
    let mut depth = 0u32;
    let mut index = open;

    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => depth = depth.saturating_add(1),
            Some(TokenKind::RParen) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            Some(_) => {}
            None => return None,
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_end_record(tokens: &[Token], mut index: usize, end: usize) -> Option<usize> {
    while index < end {
        if kind_at(tokens, index, &TokenKind::KwEnd)
            && kind_at(tokens, index.saturating_add(1), &TokenKind::KwRecord)
        {
            return Some(index);
        }
        index = index.saturating_add(1);
    }

    None
}

fn find_derived_base_end(tokens: &[Token], mut index: usize, end: usize) -> usize {
    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwWith) => return index,
            Some(_) => index = index.saturating_add(1),
            None => return end,
        }
    }

    end
}

fn split_semicolon_texts(source: &str, tokens: &[Token], start: usize, end: usize) -> Vec<String> {
    let mut fields = Vec::new();
    let mut entry_start = start;
    let mut index = start;
    let mut paren_depth = 0u32;

    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::Semicolon) if paren_depth == 0 => {
                if let Some(text) = source_text(source, tokens, entry_start, index) {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        fields.push(trimmed.to_owned());
                    }
                }
                entry_start = index.saturating_add(1);
            }
            Some(_) => {}
            None => break,
        }
        index = index.saturating_add(1);
    }

    if entry_start < end {
        if let Some(text) = source_text(source, tokens, entry_start, end) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                fields.push(trimmed.to_owned());
            }
        }
    }

    fields
}

pub(crate) fn token_range_for_span(
    tokens: &[Token],
    start_byte: u32,
    end_byte: u32,
) -> Option<(usize, usize)> {
    let start = tokens
        .iter()
        .position(|token| token.text_span.start >= start_byte)?;
    let end = tokens
        .iter()
        .position(|token| token.text_span.start >= end_byte)
        .unwrap_or(tokens.len());
    Some((start, end))
}

fn token_index_at_byte(tokens: &[Token], byte: u32) -> Option<usize> {
    tokens
        .iter()
        .position(|token| token.text_span.start == byte)
}

fn find_parent_name_end(tokens: &[Token], mut index: usize, end: usize) -> usize {
    while index < end {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwAnd | TokenKind::Semicolon | TokenKind::Eof) => return index,
            Some(_) => index = index.saturating_add(1),
            None => return end,
        }
    }

    end
}

fn skip_to_after_semicolon(tokens: &[Token], mut index: usize, limit: usize) -> usize {
    while index < limit && index < tokens.len() {
        if tokens[index].effective_kind == TokenKind::Semicolon {
            return index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }

    index.saturating_add(1)
}

fn source_text(source: &str, tokens: &[Token], start: usize, end: usize) -> Option<String> {
    let start_byte = tokens.get(start)?.text_span.start as usize;
    let end_byte = if end > start {
        tokens.get(end.saturating_sub(1))?.text_span.end as usize
    } else {
        start_byte
    };

    source.get(start_byte..end_byte).map(str::to_owned)
}

fn identifier_text(token: &Token) -> Option<String> {
    match &token.effective_kind {
        TokenKind::Identifier(name) => Some(name.clone()),
        _ => None,
    }
}

fn contains_kind(tokens: &[Token], start: usize, end: usize, kind: &TokenKind) -> bool {
    tokens
        .get(start..end)
        .is_some_and(|items| items.iter().any(|token| token.effective_kind == *kind))
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}
