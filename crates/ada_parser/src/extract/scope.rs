// SPDX-License-Identifier: Apache-2.0

use crate::ast::Span;
use crate::lexer::{Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub kind: ScopeKind,
    pub name: String,
    pub decl_span: Span,
    pub body_span: Option<Span>,
    pub declarative_span: Option<Span>,
    pub private_declarative_span: Option<Span>,
    pub parent: Option<usize>,
    pub is_generic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    PackageSpec,
    PackageBody,
    SubprogramSpec,
    SubprogramBody,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeTree {
    pub scopes: Vec<Scope>,
}

pub fn build_scope_tree(tokens: &[Token]) -> ScopeTree {
    let mut tree = ScopeTree::default();
    let mut stack: Vec<usize> = Vec::new();
    let mut index = 0usize;
    let mut pending_generic = false;

    while index < tokens.len() {
        match &tokens[index].effective_kind {
            TokenKind::KwGeneric => {
                pending_generic = true;
                index += 1;
            }
            TokenKind::KwEnd => {
                close_matching_scope(tokens, index, &mut stack, &tree);
                index += 1;
            }
            TokenKind::KwPackage if is_package_declaration_start(tokens, index) => {
                let is_generic = pending_generic;
                pending_generic = false;
                if let Some(scope) =
                    parse_package_scope(tokens, index, stack.last().copied(), is_generic)
                {
                    let push_scope =
                        matches!(scope.kind, ScopeKind::PackageSpec | ScopeKind::PackageBody);
                    tree.scopes.push(scope);
                    if push_scope {
                        stack.push(tree.scopes.len() - 1);
                    }
                }
                index += 1;
            }
            TokenKind::KwProcedure | TokenKind::KwFunction | TokenKind::KwEntry
                if is_subprogram_declaration_start(tokens, index) =>
            {
                let is_generic = pending_generic;
                pending_generic = false;
                if let Some(scope) =
                    parse_subprogram_scope(tokens, index, stack.last().copied(), is_generic)
                {
                    // An expression function (`function F (...) return T is (expr);`)
                    // is a body but is closed by `;`, not `end F;`. Pushing it onto
                    // the scope stack would leave it unclosed (nothing pops it), so
                    // every following declaration would be wrongly treated as nested
                    // inside it — flipping public package operations to `Local`
                    // (ada-toml's `Is_Present is (not Value.Is_Null);` orphaned
                    // `Kind`, `Get`, `Load_String`, ...).
                    let push_scope = scope.kind == ScopeKind::SubprogramBody
                        && !subprogram_is_expression_function(tokens, index);
                    tree.scopes.push(scope);
                    if push_scope {
                        stack.push(tree.scopes.len() - 1);
                    }
                }
                index += 1;
            }
            _ => index += 1,
        }
    }

    tree
}

fn is_package_declaration_start(tokens: &[Token], index: usize) -> bool {
    !previous_kind_is(tokens, index, &TokenKind::KwEnd)
        && !previous_kind_is(tokens, index, &TokenKind::KwWith)
        && !is_package_instantiation(tokens, index)
        && !is_package_renaming(tokens, index)
}

fn is_subprogram_declaration_start(tokens: &[Token], index: usize) -> bool {
    !previous_kind_is(tokens, index, &TokenKind::KwEnd)
        && !previous_kind_is(tokens, index, &TokenKind::KwWith)
        && !is_subprogram_instantiation(tokens, index)
}

/// `procedure Free is new Generic (...)` is a generic instantiation, not a
/// subprogram body. It ends at `;` and has no `end Free`; pushing it as a body
/// scope would make every later package operation look local to `Free`.
fn is_subprogram_instantiation(tokens: &[Token], index: usize) -> bool {
    let Some((_, after_name)) = parse_dotted_name(tokens, index.saturating_add(1)) else {
        return false;
    };
    kind_at(tokens, after_name, &TokenKind::KwIs)
        && kind_at(tokens, after_name.saturating_add(1), &TokenKind::KwNew)
}

fn previous_kind_is(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    index
        .checked_sub(1)
        .and_then(|previous| tokens.get(previous))
        .is_some_and(|token| token.effective_kind == *kind)
}

/// `package Local renames Some.Unit;` is a renaming declaration, not a nested
/// package — it has no `end Local;`, so treating it as a scope makes its span
/// run to end-of-file and wrongly adopt every later declaration (e.g. json-ada
/// `package AS renames Ada.Streams;` swallowing `JSON.Streams.From_Text`).
fn is_package_renaming(tokens: &[Token], index: usize) -> bool {
    let Some((_, after_name)) = parse_dotted_name(tokens, index.saturating_add(1)) else {
        return false;
    };
    kind_at(tokens, after_name, &TokenKind::KwRenames)
}

fn is_package_instantiation(tokens: &[Token], index: usize) -> bool {
    let name_index = if kind_at(tokens, index.saturating_add(1), &TokenKind::KwBody) {
        index.saturating_add(2)
    } else {
        index.saturating_add(1)
    };
    let Some((_, after_name)) = parse_dotted_name(tokens, name_index) else {
        return false;
    };
    kind_at(tokens, after_name, &TokenKind::KwIs)
        && kind_at(tokens, after_name.saturating_add(1), &TokenKind::KwNew)
}

fn parse_package_scope(
    tokens: &[Token],
    index: usize,
    parent: Option<usize>,
    is_generic: bool,
) -> Option<Scope> {
    let (kind, name_index) = if kind_at(tokens, index + 1, &TokenKind::KwBody) {
        (ScopeKind::PackageBody, index + 2)
    } else {
        (ScopeKind::PackageSpec, index + 1)
    };
    let (local_name, after_name) = parse_dotted_name(tokens, name_index)?;
    let name = separate_parent_before(tokens, index)
        .map(|parent| format!("{parent}.{local_name}"))
        .unwrap_or_else(|| local_name.clone());
    let end_index =
        find_named_end(tokens, after_name, &local_name).unwrap_or_else(|| last_token_index(tokens));
    let decl_span = span_from_token_range(tokens, index, end_index);
    let body_span = if kind == ScopeKind::PackageBody {
        Some(decl_span)
    } else {
        None
    };
    let declarative_span = package_declarative_span(tokens, kind, after_name, end_index);
    let private_declarative_span =
        package_private_declarative_span(tokens, kind, after_name, end_index);

    Some(Scope {
        kind,
        name,
        decl_span,
        body_span,
        declarative_span,
        private_declarative_span,
        parent,
        is_generic,
    })
}

/// Whether the subprogram starting at `index` is an Ada 2012 expression
/// function (`... is (expr);`). Such a body has no `end`, so it must not be
/// pushed onto the scope stack. Mirrors the `is`-token discovery in
/// `parse_subprogram_scope`.
fn subprogram_is_expression_function(tokens: &[Token], index: usize) -> bool {
    let Some((_, after_name)) = parse_dotted_name(tokens, index + 1) else {
        return false;
    };
    let header_end = find_subprogram_header_end(tokens, after_name);
    let is_index = find_token_before(tokens, after_name, header_end, &TokenKind::KwIs);
    is_index.is_some_and(|position| !is_abstract_spec(tokens, position))
        && is_expression_function(tokens, is_index)
}

fn parse_subprogram_scope(
    tokens: &[Token],
    index: usize,
    parent: Option<usize>,
    is_generic: bool,
) -> Option<Scope> {
    let (local_name, after_name) = parse_dotted_name(tokens, index + 1)?;
    let name = separate_parent_before(tokens, index)
        .map(|parent| format!("{parent}.{local_name}"))
        .unwrap_or_else(|| local_name.clone());
    let header_end = find_subprogram_header_end(tokens, after_name);
    let is_index = find_token_before(tokens, after_name, header_end, &TokenKind::KwIs);
    let is_body = is_index.is_some_and(|position| !is_abstract_spec(tokens, position));
    let end_index = if is_body {
        if is_expression_function(tokens, is_index) {
            find_depth_zero_semicolon(tokens, is_index.unwrap_or(header_end)).unwrap_or(header_end)
        } else {
            find_named_end(tokens, header_end, &local_name).unwrap_or(header_end)
        }
    } else {
        header_end
    };
    let kind = if is_body {
        ScopeKind::SubprogramBody
    } else {
        ScopeKind::SubprogramSpec
    };
    let decl_span = span_from_token_range(tokens, index, end_index);
    let body_span = if is_body { Some(decl_span) } else { None };
    let declarative_span = if is_body {
        subprogram_declarative_span(tokens, after_name, end_index)
    } else {
        None
    };

    Some(Scope {
        kind,
        name,
        decl_span,
        body_span,
        declarative_span,
        private_declarative_span: None,
        parent,
        is_generic,
    })
}

/// The parent named by an Ada subunit's `separate (Parent.Unit)` clause when
/// the declaration at `index` immediately follows that clause. Subunits are
/// compiled as children of the named parent; treating their local leaf as a
/// library-level unit makes generated harnesses emit invalid `with Leaf;` and
/// `Leaf.Operation` references.
fn separate_parent_before(tokens: &[Token], index: usize) -> Option<String> {
    let separate = (0..index)
        .rev()
        .find(|candidate| kind_at(tokens, *candidate, &TokenKind::KwSeparate))?;
    if !kind_at(tokens, separate.saturating_add(1), &TokenKind::LParen) {
        return None;
    }
    let (parent, after_parent) = parse_dotted_name(tokens, separate.saturating_add(2))?;
    if !kind_at(tokens, after_parent, &TokenKind::RParen) || after_parent.saturating_add(1) != index
    {
        return None;
    }
    Some(parent)
}

fn package_declarative_span(
    tokens: &[Token],
    kind: ScopeKind,
    after_name: usize,
    end_index: usize,
) -> Option<Span> {
    let is_index = find_token_before(tokens, after_name, end_index, &TokenKind::KwIs)?;
    let start = is_index.saturating_add(1);
    let stop = match kind {
        ScopeKind::PackageSpec => find_package_spec_declarative_end(tokens, start, end_index),
        ScopeKind::PackageBody => find_body_declarative_end(tokens, start, end_index),
        ScopeKind::SubprogramSpec | ScopeKind::SubprogramBody => None,
    }?;

    span_between_token_boundaries(tokens, start, stop)
}

fn subprogram_declarative_span(
    tokens: &[Token],
    after_name: usize,
    end_index: usize,
) -> Option<Span> {
    let is_index = find_token_before(tokens, after_name, end_index, &TokenKind::KwIs)?;
    find_body_declarative_end(tokens, is_index.saturating_add(1), end_index)
        .and_then(|stop| span_between_token_boundaries(tokens, is_index.saturating_add(1), stop))
}

fn package_private_declarative_span(
    tokens: &[Token],
    kind: ScopeKind,
    after_name: usize,
    end_index: usize,
) -> Option<Span> {
    if kind != ScopeKind::PackageSpec {
        return None;
    }

    let is_index = find_token_before(tokens, after_name, end_index, &TokenKind::KwIs)?;
    let public_stop =
        find_package_spec_declarative_end(tokens, is_index.saturating_add(1), end_index)?;
    if !kind_at(tokens, public_stop, &TokenKind::KwPrivate) {
        return None;
    }

    let start = public_stop.saturating_add(1);
    let stop = find_package_spec_declarative_end(tokens, start, end_index)?;
    span_between_token_boundaries(tokens, start, stop)
}

/// Whether the `end` at `index` closes an embedded construct (`end record`,
/// `end case`, `end loop`, `end if`, `end select`, `end return`) rather than a
/// package/subprogram. These appear inside type declarations (variant records)
/// and must be skipped when scanning for the enclosing unit's `end`.
fn next_is_construct_close(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens
            .get(index.saturating_add(1))
            .map(|token| &token.effective_kind),
        Some(
            TokenKind::KwRecord
                | TokenKind::KwCase
                | TokenKind::KwLoop
                | TokenKind::KwIf
                | TokenKind::KwSelect
                | TokenKind::KwReturn
        )
    )
}

fn find_package_spec_declarative_end(
    tokens: &[Token],
    mut index: usize,
    end_index: usize,
) -> Option<usize> {
    while index <= end_index && index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            // Construct closers (`end record` / `end case` / `end loop` / ...)
            // are NOT the package's `end` — a variant record in a type
            // declaration (`... case D is ... end case; end record;`) embeds
            // them, and stopping at one truncates the declarative span so every
            // later declaration is lost (ada-toml's `Any_Float` dropped
            // `Read_Result` and the whole API after it).
            Some(TokenKind::KwEnd) if next_is_construct_close(tokens, index) => {
                index = index.saturating_add(2);
            }
            Some(TokenKind::KwProtected | TokenKind::KwTask) => {
                if let Some(close) = concurrent_declaration_end(tokens, index, end_index) {
                    index = close.saturating_add(1);
                } else {
                    index = index.saturating_add(1);
                }
            }
            Some(TokenKind::KwPrivate) if !is_private_type_keyword(tokens, index) => {
                return Some(index);
            }
            Some(TokenKind::KwEnd) => return Some(index),
            Some(TokenKind::KwProcedure | TokenKind::KwFunction | TokenKind::KwEntry)
                if is_subprogram_declaration_start(tokens, index) =>
            {
                let Some(scope) = parse_subprogram_scope(tokens, index, None, false) else {
                    index = index.saturating_add(1);
                    continue;
                };
                index = token_index_at_or_after_byte(tokens, scope.decl_span.end_byte)
                    .unwrap_or(index.saturating_add(1));
            }
            Some(TokenKind::KwPackage) if is_package_declaration_start(tokens, index) => {
                let Some(scope) = parse_package_scope(tokens, index, None, false) else {
                    index = index.saturating_add(1);
                    continue;
                };
                index = token_index_at_or_after_byte(tokens, scope.decl_span.end_byte)
                    .unwrap_or(index.saturating_add(1));
            }
            Some(_) => index = index.saturating_add(1),
            None => return None,
        }
    }

    Some(end_index)
}

fn is_private_type_keyword(tokens: &[Token], index: usize) -> bool {
    let mut cursor = index;

    while let Some(previous) = cursor.checked_sub(1) {
        match tokens.get(previous).map(|token| &token.effective_kind) {
            Some(TokenKind::KwType) => return true,
            Some(TokenKind::Semicolon) | None => return false,
            Some(_) => cursor = previous,
        }
    }

    false
}

fn find_body_declarative_end(
    tokens: &[Token],
    mut index: usize,
    end_index: usize,
) -> Option<usize> {
    let mut depth = 0u32;

    while index <= end_index && index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwBegin) if depth == 0 => return Some(index),
            Some(TokenKind::KwBegin) => index = index.saturating_add(1),
            Some(TokenKind::KwEnd) if depth == 0 => return Some(index),
            Some(TokenKind::KwEnd) => {
                if body_construct_closes_at_end(tokens, index) {
                    depth = depth.saturating_sub(1);
                    index = index.saturating_add(body_end_width(tokens, index));
                } else {
                    index = index.saturating_add(1);
                }
            }
            Some(TokenKind::KwProtected | TokenKind::KwTask) => {
                if let Some(close) = concurrent_declaration_end(tokens, index, end_index) {
                    index = close.saturating_add(1);
                } else {
                    index = index.saturating_add(1);
                }
            }
            Some(TokenKind::KwProcedure | TokenKind::KwFunction | TokenKind::KwEntry)
                if is_subprogram_declaration_start(tokens, index) =>
            {
                let Some(header_end) = body_subprogram_header_end(tokens, index) else {
                    index = index.saturating_add(1);
                    continue;
                };
                if kind_at(tokens, header_end, &TokenKind::KwIs) {
                    depth = depth.saturating_add(1);
                }
                index = header_end.saturating_add(1);
            }
            Some(TokenKind::KwPackage) if is_package_declaration_start(tokens, index) => {
                let Some(is_index) = body_package_is_index(tokens, index, end_index) else {
                    index = index.saturating_add(1);
                    continue;
                };
                depth = depth.saturating_add(1);
                index = is_index.saturating_add(1);
            }
            Some(
                TokenKind::KwRecord | TokenKind::KwCase | TokenKind::KwLoop | TokenKind::KwSelect,
            ) => {
                depth = depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::KwDeclare) => {
                depth = depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            Some(_) => index = index.saturating_add(1),
            None => return None,
        }
    }

    Some(end_index)
}

/// End token of a protected/task declaration beginning at `index`, including
/// optional `type` and discriminants. A forward declaration (`task type T;`)
/// has no `is` and therefore no embedded `end` to skip.
fn concurrent_declaration_end(tokens: &[Token], index: usize, limit: usize) -> Option<usize> {
    if !matches!(
        tokens.get(index).map(|token| &token.effective_kind),
        Some(TokenKind::KwProtected | TokenKind::KwTask)
    ) {
        return None;
    }
    let name_index = if kind_at(tokens, index.saturating_add(1), &TokenKind::KwType) {
        index.saturating_add(2)
    } else {
        index.saturating_add(1)
    };
    let (name, after_name) = parse_dotted_name(tokens, name_index)?;
    let mut cursor = after_name;
    let mut paren_depth = 0u32;
    let mut has_body = false;
    while cursor <= limit && cursor < tokens.len() {
        match tokens.get(cursor).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::KwIs) if paren_depth == 0 => {
                has_body = true;
                break;
            }
            Some(TokenKind::Semicolon) if paren_depth == 0 => return None,
            Some(TokenKind::Eof) | None => return None,
            Some(_) => {}
        }
        cursor = cursor.saturating_add(1);
    }
    has_body
        .then(|| find_named_end(tokens, cursor.saturating_add(1), &name))
        .flatten()
}

fn body_subprogram_header_end(tokens: &[Token], start: usize) -> Option<usize> {
    let (_, after_name) = parse_dotted_name(tokens, start.saturating_add(1))?;
    Some(find_subprogram_header_end(tokens, after_name))
}

fn body_package_is_index(tokens: &[Token], start: usize, end_index: usize) -> Option<usize> {
    let name_index = if kind_at(tokens, start.saturating_add(1), &TokenKind::KwBody) {
        start.saturating_add(2)
    } else {
        start.saturating_add(1)
    };
    let (_, after_name) = parse_dotted_name(tokens, name_index)?;
    find_token_before(tokens, after_name, end_index, &TokenKind::KwIs)
}

fn body_construct_closes_at_end(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens
            .get(index.saturating_add(1))
            .map(|token| &token.effective_kind),
        Some(
            TokenKind::KwRecord
                | TokenKind::KwCase
                | TokenKind::KwLoop
                | TokenKind::KwSelect
                | TokenKind::KwProcedure
                | TokenKind::KwFunction
                | TokenKind::KwEntry
                | TokenKind::KwPackage
                | TokenKind::Semicolon
                | TokenKind::Identifier(_)
        )
    )
}

fn body_end_width(tokens: &[Token], index: usize) -> usize {
    if matches!(
        tokens
            .get(index.saturating_add(1))
            .map(|token| &token.effective_kind),
        Some(
            TokenKind::KwRecord
                | TokenKind::KwCase
                | TokenKind::KwLoop
                | TokenKind::KwSelect
                | TokenKind::KwProcedure
                | TokenKind::KwFunction
                | TokenKind::KwEntry
                | TokenKind::KwPackage
        )
    ) {
        2
    } else {
        1
    }
}

fn close_matching_scope(tokens: &[Token], index: usize, stack: &mut Vec<usize>, tree: &ScopeTree) {
    if stack.is_empty() {
        return;
    }

    if let Some(end_name) = parse_end_name(tokens, index) {
        if let Some(position) = stack
            .iter()
            .rposition(|scope_index| scope_name_matches(&tree.scopes[*scope_index].name, &end_name))
        {
            stack.truncate(position);
        }
        return;
    }

    if kind_at(tokens, index + 1, &TokenKind::Semicolon) {
        stack.pop();
    }
}

fn find_subprogram_header_end(tokens: &[Token], mut index: usize) -> usize {
    let mut paren_depth = 0u32;
    while index < tokens.len() {
        match &tokens[index].effective_kind {
            TokenKind::LParen => paren_depth = paren_depth.saturating_add(1),
            TokenKind::RParen => paren_depth = paren_depth.saturating_sub(1),
            TokenKind::Semicolon if paren_depth == 0 => return index,
            TokenKind::KwIs if paren_depth == 0 => {
                if is_expression_function(tokens, Some(index)) {
                    return find_depth_zero_semicolon(tokens, index).unwrap_or(index);
                }
                if is_abstract_spec(tokens, index) {
                    return find_depth_zero_semicolon(tokens, index).unwrap_or(index);
                }
                return index;
            }
            TokenKind::Eof => return index,
            _ => {}
        }
        index += 1;
    }

    last_token_index(tokens)
}

fn find_named_end(tokens: &[Token], mut index: usize, name: &str) -> Option<usize> {
    while index < tokens.len() {
        if tokens[index].effective_kind == TokenKind::KwEnd
            && parse_end_name(tokens, index)
                .as_deref()
                .is_some_and(|end_name| scope_name_matches(name, end_name))
        {
            return Some(find_statement_end(tokens, index));
        }
        index += 1;
    }

    None
}

fn parse_end_name(tokens: &[Token], index: usize) -> Option<String> {
    let mut cursor = index.saturating_add(1);
    if matches!(
        tokens.get(cursor).map(|token| &token.effective_kind),
        Some(
            TokenKind::KwPackage
                | TokenKind::KwProcedure
                | TokenKind::KwFunction
                | TokenKind::KwEntry
        )
    ) {
        cursor = cursor.saturating_add(1);
    }

    parse_dotted_name(tokens, cursor).map(|(name, _)| name)
}

fn scope_name_matches(scope_name: &str, end_name: &str) -> bool {
    scope_name == end_name
        || scope_name
            .rsplit('.')
            .next()
            .is_some_and(|last| last == end_name)
}

fn find_token_before(
    tokens: &[Token],
    mut index: usize,
    stop: usize,
    kind: &TokenKind,
) -> Option<usize> {
    while index <= stop && index < tokens.len() {
        if tokens[index].effective_kind == *kind {
            return Some(index);
        }
        index += 1;
    }

    None
}

fn is_abstract_spec(tokens: &[Token], is_index: usize) -> bool {
    kind_at(tokens, is_index + 1, &TokenKind::KwAbstract)
}

fn is_expression_function(tokens: &[Token], is_index: Option<usize>) -> bool {
    is_index.is_some_and(|index| kind_at(tokens, index + 1, &TokenKind::LParen))
}

fn find_depth_zero_semicolon(tokens: &[Token], mut index: usize) -> Option<usize> {
    let mut paren_depth = 0u32;
    while index < tokens.len() {
        match &tokens[index].effective_kind {
            TokenKind::LParen => paren_depth = paren_depth.saturating_add(1),
            TokenKind::RParen => paren_depth = paren_depth.saturating_sub(1),
            TokenKind::Semicolon if paren_depth == 0 => return Some(index),
            TokenKind::Eof => return Some(index),
            _ => {}
        }
        index += 1;
    }

    None
}

fn find_statement_end(tokens: &[Token], mut index: usize) -> usize {
    while index < tokens.len() {
        if tokens[index].effective_kind == TokenKind::Semicolon {
            return index;
        }
        if tokens[index].effective_kind == TokenKind::Eof {
            return index;
        }
        index += 1;
    }

    last_token_index(tokens)
}

fn parse_dotted_name(tokens: &[Token], mut index: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    parts.push(identifier_text(tokens.get(index)?)?);
    index = index.saturating_add(1);

    while kind_at(tokens, index, &TokenKind::Dot) {
        index = index.saturating_add(1);
        parts.push(identifier_text(tokens.get(index)?)?);
        index = index.saturating_add(1);
    }

    Some((parts.join("."), index))
}

fn identifier_text(token: &Token) -> Option<String> {
    match &token.effective_kind {
        TokenKind::Identifier(name) => Some(name.clone()),
        _ => None,
    }
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

fn span_from_token_range(tokens: &[Token], start: usize, end: usize) -> Span {
    let Some(start_token) = tokens.get(start) else {
        return Span::new(0, 0, 0, 0);
    };
    let end_token = tokens.get(end).unwrap_or(start_token);

    Span::new(
        start_token.text_span.start,
        end_token.text_span.end,
        start_token.line,
        start_token.col,
    )
}

fn span_between_token_boundaries(tokens: &[Token], start: usize, stop: usize) -> Option<Span> {
    let start_token = tokens.get(start)?;
    let end_byte = if stop > start {
        tokens
            .get(stop.saturating_sub(1))
            .map(|token| token.text_span.end)
            .unwrap_or(start_token.text_span.start)
    } else {
        start_token.text_span.start
    };

    Some(Span::new(
        start_token.text_span.start,
        end_byte,
        start_token.line,
        start_token.col,
    ))
}

fn token_index_at_or_after_byte(tokens: &[Token], byte: u32) -> Option<usize> {
    tokens
        .iter()
        .position(|token| token.text_span.start >= byte || token.text_span.end >= byte)
}

fn last_token_index(tokens: &[Token]) -> usize {
    tokens.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::{build_scope_tree, ScopeKind};
    use crate::ast::AdaStandard;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2022)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    #[test]
    fn library_level_package_spec_yields_one_scope() {
        let tree = build_scope_tree(&tokens("package P is end P;"));

        assert_eq!(tree.scopes.len(), 1);
        assert_eq!(tree.scopes[0].kind, ScopeKind::PackageSpec);
        assert_eq!(tree.scopes[0].name, "p");
        assert_eq!(tree.scopes[0].parent, None);
    }

    #[test]
    fn child_package_uses_dotted_name() {
        let tree = build_scope_tree(&tokens("package Parent.Child is end Parent.Child;"));

        assert_eq!(tree.scopes[0].name, "parent.child");
        assert_eq!(tree.scopes[0].kind, ScopeKind::PackageSpec);
    }

    #[test]
    fn separate_package_body_is_qualified_by_parent_unit() {
        let source = "with Dependency; separate (Crypto.Types.Big_Numbers) \
                      package body Utils is procedure Run is begin null; end Run; end Utils;";
        let tree = build_scope_tree(&tokens(source));

        let package = tree
            .scopes
            .iter()
            .find(|scope| scope.kind == ScopeKind::PackageBody)
            .unwrap();
        assert_eq!(package.name, "crypto.types.big_numbers.utils");
        let run = tree
            .scopes
            .iter()
            .find(|scope| scope.kind == ScopeKind::SubprogramBody)
            .unwrap();
        assert_eq!(run.name, "run");
        assert_eq!(
            run.parent,
            tree.scopes.iter().position(|scope| scope == package)
        );
    }

    #[test]
    fn separate_subprogram_is_qualified_by_parent_unit() {
        let source = "separate (Crypto.Types.Big_Numbers) \
                      function Parse (S : String) return Integer is begin return 0; end Parse;";
        let tree = build_scope_tree(&tokens(source));
        let function = tree
            .scopes
            .iter()
            .find(|scope| scope.kind == ScopeKind::SubprogramBody)
            .unwrap();
        assert_eq!(function.name, "crypto.types.big_numbers.parse");
        assert_eq!(function.parent, None);
    }

    #[test]
    fn generic_package_marks_is_generic() {
        let source = "generic type T is private; package P is end P;";
        let tree = build_scope_tree(&tokens(source));

        assert!(tree.scopes[0].is_generic);
        assert_eq!(tree.scopes[0].name, "p");
    }

    #[test]
    fn nested_subprogram_records_parent() {
        let source = "package body P is procedure Inner is begin null; end Inner; end P;";
        let tree = build_scope_tree(&tokens(source));

        let package = tree
            .scopes
            .iter()
            .position(|scope| scope.kind == ScopeKind::PackageBody)
            .unwrap();
        let inner = tree
            .scopes
            .iter()
            .position(|scope| scope.kind == ScopeKind::SubprogramBody)
            .unwrap();

        assert_eq!(tree.scopes[inner].parent, Some(package));
        assert_eq!(tree.scopes[inner].name, "inner");
    }

    #[test]
    fn package_instantiation_does_not_become_enclosing_scope() {
        let source = "package body P is package Local is new Factory (Integer); function F return Integer is begin return 1; end F; end P;";
        let tree = build_scope_tree(&tokens(source));

        assert!(!tree.scopes.iter().any(|scope| scope.name == "local"));

        let package = tree
            .scopes
            .iter()
            .position(|scope| scope.kind == ScopeKind::PackageBody)
            .unwrap();
        let function = tree
            .scopes
            .iter()
            .position(|scope| scope.kind == ScopeKind::SubprogramBody && scope.name == "f")
            .unwrap();

        assert_eq!(tree.scopes[function].parent, Some(package));
    }

    #[test]
    fn package_body_pairs_with_spec_when_both_present() {
        let source = "package P is end P; package body P is end P;";
        let tree = build_scope_tree(&tokens(source));

        assert_eq!(tree.scopes.len(), 2);
        assert_eq!(tree.scopes[0].kind, ScopeKind::PackageSpec);
        assert_eq!(tree.scopes[1].kind, ScopeKind::PackageBody);
        assert_eq!(tree.scopes[0].name, tree.scopes[1].name);
    }

    #[test]
    fn entry_in_protected_or_task_recognised_as_subprogram_spec() {
        let source = "package P is protected T is entry Lock; end T; end P;";
        let tree = build_scope_tree(&tokens(source));

        assert!(tree
            .scopes
            .iter()
            .any(|scope| scope.kind == ScopeKind::SubprogramSpec && scope.name == "lock"));
    }

    #[test]
    fn expression_function_at_2012_recognised_as_subprogram_body() {
        let source = "function F return Integer is (1);";
        let tree = build_scope_tree(&tokens(source));

        assert_eq!(tree.scopes.len(), 1);
        assert_eq!(tree.scopes[0].kind, ScopeKind::SubprogramBody);
        assert!(tree.scopes[0].body_span.is_some());
    }

    #[test]
    fn expression_function_does_not_orphan_following_package_operations() {
        // ada-toml shape: an expression function in a package spec must not be
        // pushed as an unclosed scope and adopt every later operation. `Kind`
        // (and anything after) must stay a direct child of the package.
        let source = "package P is\n\
                      function Is_Present (V : T) return Boolean is (not V.Is_Null);\n\
                      function Kind (V : T) return K;\n\
                      function Load_String (Content : String) return R;\n\
                      end P;";
        let tree = build_scope_tree(&tokens(source));
        let pkg = tree
            .scopes
            .iter()
            .position(|s| s.kind == ScopeKind::PackageSpec)
            .expect("package scope");
        for name in ["kind", "load_string"] {
            let scope = tree
                .scopes
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{name} scope present"));
            assert_eq!(
                scope.parent,
                Some(pkg),
                "{name} must be a direct child of package P, not nested in the expression function"
            );
        }
    }

    #[test]
    fn generic_subprogram_instance_does_not_orphan_following_package_operations() {
        let source = "package P is\n\
                      procedure Free is new Ada.Unchecked_Deallocation (T, T_Access);\n\
                      procedure Read_Bom (S : String);\n\
                      function Write_Bom return String;\n\
                      end P;";
        let tree = build_scope_tree(&tokens(source));
        let pkg = tree
            .scopes
            .iter()
            .position(|scope| scope.kind == ScopeKind::PackageSpec)
            .expect("package scope");
        assert!(tree.scopes.iter().all(|scope| scope.name != "free"));
        for name in ["read_bom", "write_bom"] {
            let scope = tree
                .scopes
                .iter()
                .find(|scope| scope.name == name)
                .unwrap_or_else(|| panic!("{name} scope present"));
            assert_eq!(scope.parent, Some(pkg));
        }
    }

    #[test]
    fn incomplete_package_at_eof_does_not_panic() {
        let tree = build_scope_tree(&tokens("package Broken is procedure P;"));

        assert_eq!(tree.scopes[0].kind, ScopeKind::PackageSpec);
        assert_eq!(tree.scopes[0].name, "broken");
    }

    #[test]
    fn generic_procedure_marks_is_generic() {
        let source = "generic type T is private; procedure P (X : T);";
        let tree = build_scope_tree(&tokens(source));

        assert_eq!(tree.scopes[0].kind, ScopeKind::SubprogramSpec);
        assert!(tree.scopes[0].is_generic);
    }

    #[test]
    fn package_spec_declarative_span_runs_from_is_to_end_or_private() {
        let source = "package P is type T is range 1 .. 10; private type H is private; end P;";
        let tree = build_scope_tree(&tokens(source));
        let span = tree.scopes[0].declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];

        assert_eq!(text.trim(), "type T is range 1 .. 10;");
    }

    #[test]
    fn package_spec_declarative_span_spans_past_variant_record() {
        // A variant record embeds `end case;`/`end record;`. The declarative-end
        // scan must skip those construct closers — otherwise the span stops at
        // the variant's `end case` and every declaration after it is lost
        // (ada-toml's `Any_Float` truncated the API, dropping `Read_Result`).
        let source = "package P is \
                      type R (D : Boolean := True) is record \
                      case D is when True => X : Integer; when False => Y : Integer; end case; \
                      end record; \
                      type After_It is range 1 .. 9; end P;";
        let tree = build_scope_tree(&tokens(source));
        let span = tree.scopes[0].declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];
        assert!(
            text.contains("After_It"),
            "declarative span truncated at the variant record's `end case`: {text:?}"
        );
    }

    #[test]
    fn package_spec_declarative_span_spans_past_protected_type() {
        let source = "package P is\n\
            protected type Object (Size : Positive) is\n\
               procedure Touch;\n\
            private\n\
               Value : Integer := Size;\n\
            end Object;\n\
            type Object_Access is access all Object;\n\
            end P;";
        let tokens = crate::lexer::lex(source, crate::ast::AdaStandard::Ada2012);
        let tree = build_scope_tree(&tokens);
        let span = tree.scopes[0].declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];
        assert!(text.contains("type Object_Access"), "{text}");
    }

    #[test]
    fn package_body_declarative_span_runs_from_is_to_begin() {
        let source = "package body P is X : Integer; begin null; end P;";
        let tree = build_scope_tree(&tokens(source));
        let span = tree.scopes[0].declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];

        assert_eq!(text.trim(), "X : Integer;");
    }

    #[test]
    fn subprogram_body_declarative_span_runs_from_is_to_begin() {
        let source = "procedure P is X : Integer; begin null; end P;";
        let tree = build_scope_tree(&tokens(source));
        let span = tree.scopes[0].declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];

        assert_eq!(text.trim(), "X : Integer;");
    }

    #[test]
    fn subprogram_spec_declarative_span_is_none() {
        let tree = build_scope_tree(&tokens("procedure P;"));

        assert!(tree.scopes[0].declarative_span.is_none());
    }

    #[test]
    fn nested_subprogram_records_its_own_declarative_span() {
        let source = "procedure Outer is procedure Inner is X : Integer; begin null; end Inner; begin null; end Outer;";
        let tree = build_scope_tree(&tokens(source));
        let inner = tree
            .scopes
            .iter()
            .find(|scope| scope.name == "inner")
            .unwrap();
        let span = inner.declarative_span.unwrap();
        let text = &source[span.start_byte as usize..span.end_byte as usize];

        assert_eq!(text.trim(), "X : Integer;");
    }
}
