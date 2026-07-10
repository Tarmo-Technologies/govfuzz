// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    AdaStandard, ExceptionHandler, Expr, RaiseKind, RaiseSite, RaiseSiteId, Span, Subprogram,
};
use crate::extract::scope::{ScopeKind, ScopeTree};
use crate::lexer::{Token, TokenKind};

pub fn extract_raises(
    scope_tree: &ScopeTree,
    subprograms: &[Subprogram],
    handlers: &[ExceptionHandler],
    source: &str,
    tokens: &[Token],
    dialect: AdaStandard,
) -> Vec<RaiseSite> {
    let mut raises = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.effective_kind != TokenKind::KwRaise
            || !inside_raise_scope(scope_tree, subprograms, token)
        {
            continue;
        }

        let site = parse_raise_site(
            RaiseSiteId(raises.len() as u32),
            handlers,
            source,
            tokens,
            index,
            dialect,
        );
        raises.push(site);
    }

    raises
}

fn parse_raise_site(
    id: RaiseSiteId,
    handlers: &[ExceptionHandler],
    source: &str,
    tokens: &[Token],
    raise_index: usize,
    dialect: AdaStandard,
) -> RaiseSite {
    let mut cursor = raise_index.saturating_add(1);
    let in_handler = tokens
        .get(raise_index)
        .is_some_and(|token| inside_handler_body(handlers, token));
    let mut exception = None;
    let mut message = None;

    if !matches!(
        tokens.get(cursor).map(|token| &token.effective_kind),
        Some(TokenKind::Semicolon | TokenKind::RParen | TokenKind::Eof) | None
    ) {
        if let Some((name, next)) = parse_dotted_name(tokens, cursor) {
            exception = Some(name);
            cursor = next;
        }
    }

    if dialect >= AdaStandard::Ada2005 && kind_at(tokens, cursor, &TokenKind::KwWith) {
        let message_start = cursor.saturating_add(1);
        let message_end = find_raise_end(tokens, message_start);
        message = source_text(source, tokens, message_start, message_end).map(Expr);
        cursor = message_end;
    }

    let end_index = find_raise_end(tokens, cursor);
    let kind = if exception.is_none() && in_handler {
        RaiseKind::Reraise
    } else {
        RaiseKind::Explicit
    };

    RaiseSite {
        id,
        kind,
        exception,
        message,
        span: span_from_token_range(tokens, raise_index, end_index.saturating_add(1)),
    }
}

fn inside_raise_scope(scope_tree: &ScopeTree, subprograms: &[Subprogram], token: &Token) -> bool {
    inside_subprogram_body(subprograms, token) || inside_package_body(scope_tree, token)
}

fn inside_subprogram_body(subprograms: &[Subprogram], token: &Token) -> bool {
    subprograms.iter().any(|subprogram| {
        subprogram
            .body_span
            .is_some_and(|span| span_contains_byte(span, token.text_span.start))
    })
}

fn inside_package_body(scope_tree: &ScopeTree, token: &Token) -> bool {
    scope_tree.scopes.iter().any(|scope| {
        scope.kind == ScopeKind::PackageBody
            && scope
                .body_span
                .is_some_and(|span| span_contains_byte(span, token.text_span.start))
    })
}

fn inside_handler_body(handlers: &[ExceptionHandler], token: &Token) -> bool {
    handlers
        .iter()
        .any(|handler| span_contains_byte(handler.body_span, token.text_span.start))
}

fn find_raise_end(tokens: &[Token], mut index: usize) -> usize {
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => {
                if paren_depth == 0 {
                    return index;
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            Some(TokenKind::Semicolon) if paren_depth == 0 => return index,
            Some(TokenKind::Eof) | None => return index,
            Some(_) => {}
        }
        index = index.saturating_add(1);
    }

    index
}

fn parse_dotted_name(tokens: &[Token], mut index: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    parts.push(identifier_text(tokens.get(index))?);
    index = index.saturating_add(1);

    while kind_at(tokens, index, &TokenKind::Dot) {
        index = index.saturating_add(1);
        parts.push(identifier_text(tokens.get(index))?);
        index = index.saturating_add(1);
    }

    Some((parts.join("."), index))
}

fn identifier_text(token: Option<&Token>) -> Option<String> {
    match token.map(|token| &token.effective_kind) {
        Some(TokenKind::Identifier(name)) => Some(name.clone()),
        _ => None,
    }
}

fn source_text(source: &str, tokens: &[Token], start: usize, end: usize) -> Option<String> {
    if start >= end {
        return None;
    }

    let start_byte = tokens.get(start)?.text_span.start as usize;
    let end_byte = tokens.get(end.saturating_sub(1))?.text_span.end as usize;
    source
        .get(start_byte..end_byte)
        .map(|text| text.trim().to_owned())
}

fn span_from_token_range(tokens: &[Token], start: usize, end: usize) -> Span {
    let Some(start_token) = tokens.get(start) else {
        return Span::new(0, 0, 0, 0);
    };
    let end_token = if end > start {
        tokens.get(end.saturating_sub(1)).unwrap_or(start_token)
    } else {
        start_token
    };

    Span::new(
        start_token.text_span.start,
        end_token.text_span.end,
        start_token.line,
        start_token.col,
    )
}

fn span_contains_byte(span: Span, byte: u32) -> bool {
    byte >= span.start_byte && byte < span.end_byte
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

#[cfg(test)]
mod tests {
    use super::extract_raises;
    use crate::ast::{AdaStandard, RaiseKind};
    use crate::extract::{
        build_scope_tree, extract_handlers, extract_packages, extract_subprograms,
    };
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str, dialect: AdaStandard) -> Vec<Token> {
        lex(source, dialect)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn parts(
        source: &str,
        dialect: AdaStandard,
    ) -> (
        crate::extract::ScopeTree,
        Vec<crate::ast::Subprogram>,
        Vec<crate::ast::ExceptionHandler>,
        Vec<Token>,
    ) {
        let tokens = tokens(source, dialect);
        let tree = build_scope_tree(&tokens);
        let packages = extract_packages(&tree, source, &tokens);
        let subprograms = extract_subprograms(&tree, source, &tokens, dialect);
        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);
        (tree, subprograms, handlers, tokens)
    }

    #[test]
    fn bare_raise_outside_handler_is_explicit_with_no_name() {
        let source = "procedure P is begin raise; end P;";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada2012);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada2012,
        );

        assert_eq!(raises.len(), 1);
        assert_eq!(raises[0].kind, RaiseKind::Explicit);
        assert_eq!(raises[0].exception, None);
    }

    #[test]
    fn raise_with_name_captures_dotted_name() {
        let source = "procedure P is begin raise Ada.IO_Exceptions.Name_Error; end P;";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada2012);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada2012,
        );

        assert_eq!(
            raises[0].exception.as_deref(),
            Some("ada.io_exceptions.name_error")
        );
    }

    #[test]
    fn raise_with_message_at_2005_captures_message_text() {
        let source = "procedure P is begin raise Constraint_Error with \"bad length\"; end P;";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada2005);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada2005,
        );

        assert_eq!(
            raises[0].message.as_ref().map(|expr| expr.0.as_str()),
            Some("\"bad length\"")
        );
    }

    #[test]
    fn raise_with_message_at_95_records_no_message_field() {
        let source = "procedure P is begin raise Constraint_Error with \"bad length\"; end P;";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada95);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada95,
        );

        assert_eq!(raises[0].exception.as_deref(), Some("constraint_error"));
        assert_eq!(raises[0].message, None);
    }

    #[test]
    fn bare_raise_inside_handler_is_reraise() {
        let source = "procedure P is begin null; exception when others => raise; end P;";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada2012);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada2012,
        );

        assert_eq!(raises[0].kind, RaiseKind::Reraise);
    }

    #[test]
    fn raise_inside_expression_function_at_2012_is_extracted() {
        let source = "function F return Integer is (raise Constraint_Error);";
        let (tree, subprograms, handlers, tokens) = parts(source, AdaStandard::Ada2012);

        let raises = extract_raises(
            &tree,
            &subprograms,
            &handlers,
            source,
            &tokens,
            AdaStandard::Ada2012,
        );

        assert_eq!(raises.len(), 1);
        assert_eq!(raises[0].exception.as_deref(), Some("constraint_error"));
    }
}
