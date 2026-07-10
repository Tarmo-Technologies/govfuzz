// SPDX-License-Identifier: Apache-2.0

use crate::ast::{
    Choice, ExceptionHandler, HandlerId, HandlerOwner, Package, PackageId, Span, Subprogram,
};
use crate::extract::{Scope, ScopeKind, ScopeTree};
use crate::lexer::{Token, TokenKind};

pub fn extract_handlers(
    scope_tree: &ScopeTree,
    packages: &[Package],
    subprograms: &[Subprogram],
    _source: &str,
    tokens: &[Token],
) -> Vec<ExceptionHandler> {
    let mut handlers = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.effective_kind != TokenKind::KwException {
            continue;
        }

        let Some(owner) = owner_for_exception(scope_tree, packages, subprograms, token) else {
            continue;
        };
        let Some(body_span) = owner_body_span(scope_tree, packages, subprograms, &owner) else {
            continue;
        };
        if top_level_exception_index(scope_tree, tokens, body_span) != Some(index) {
            continue;
        }
        parse_handler_block(tokens, index, &owner, body_span.end_byte, &mut handlers);
    }

    handlers
}

fn owner_for_exception(
    scope_tree: &ScopeTree,
    packages: &[Package],
    subprograms: &[Subprogram],
    token: &Token,
) -> Option<HandlerOwner> {
    let byte = token.text_span.start;
    let subprogram_candidates = subprograms.iter().filter_map(|subprogram| {
        let span = subprogram.body_span?;
        if span_contains_byte(span, byte) {
            Some((
                HandlerOwner::Subprogram(subprogram.id),
                span.end_byte.saturating_sub(span.start_byte),
            ))
        } else {
            None
        }
    });
    let package_body_candidates = scope_tree.scopes.iter().filter_map(|scope| {
        if scope.kind != ScopeKind::PackageBody {
            return None;
        }
        let span = scope.body_span?;
        if span_contains_byte(span, byte) {
            Some((
                HandlerOwner::PackageBody(package_id_for_scope(packages, scope)?),
                span.end_byte.saturating_sub(span.start_byte),
            ))
        } else {
            None
        }
    });

    subprogram_candidates
        .chain(package_body_candidates)
        .min_by_key(|(_, len)| *len)
        .map(|(owner, _)| owner)
}

fn owner_body_span(
    scope_tree: &ScopeTree,
    packages: &[Package],
    subprograms: &[Subprogram],
    owner: &HandlerOwner,
) -> Option<Span> {
    match owner {
        HandlerOwner::Subprogram(id) => subprograms
            .iter()
            .find(|subprogram| subprogram.id == *id)
            .and_then(|subprogram| subprogram.body_span),
        HandlerOwner::PackageBody(id) => {
            let package = packages.iter().find(|package| package.id == *id)?;
            scope_tree
                .scopes
                .iter()
                .find(|scope| scope.kind == ScopeKind::PackageBody && scope.name == package.name)
                .and_then(|scope| scope.body_span)
        }
    }
}

fn package_id_for_scope(packages: &[Package], scope: &Scope) -> Option<PackageId> {
    packages
        .iter()
        .find(|package| package.name == scope.name)
        .map(|package| package.id)
}

fn top_level_exception_index(
    scope_tree: &ScopeTree,
    tokens: &[Token],
    body_span: Span,
) -> Option<usize> {
    let mut index = first_token_at_or_after(tokens, body_span.start_byte);
    let mut saw_begin = false;
    let mut nesting = NestingDepth::default();

    while index < tokens.len() && token_starts_before(tokens, index, body_span.end_byte) {
        if let Some(next) = skip_nested_scope(scope_tree, tokens, body_span, index) {
            index = next;
            continue;
        }

        if !saw_begin {
            if kind_at(tokens, index, &TokenKind::KwBegin) {
                saw_begin = true;
            }
            index = index.saturating_add(1);
            continue;
        }

        if nesting.is_top_level() {
            match tokens.get(index).map(|token| &token.effective_kind) {
                Some(TokenKind::KwException) => return Some(index),
                Some(TokenKind::KwEnd) if is_handler_block_end(tokens, index) => return None,
                Some(_) => {}
                None => return None,
            }
        }

        index = nesting.observe(tokens, index);
    }

    None
}

fn skip_nested_scope(
    scope_tree: &ScopeTree,
    tokens: &[Token],
    body_span: Span,
    index: usize,
) -> Option<usize> {
    let byte = tokens.get(index)?.text_span.start;
    let nested_span = scope_tree
        .scopes
        .iter()
        .map(|scope| scope.decl_span)
        .filter(|span| {
            span.start_byte > body_span.start_byte
                && span.end_byte <= body_span.end_byte
                && span_contains_byte(*span, byte)
        })
        .max_by_key(|span| span.end_byte)?;

    Some(first_token_at_or_after(tokens, nested_span.end_byte))
}

fn parse_handler_block(
    tokens: &[Token],
    exception_index: usize,
    owner: &HandlerOwner,
    limit: u32,
    handlers: &mut Vec<ExceptionHandler>,
) {
    let mut index = exception_index.saturating_add(1);

    while index < tokens.len() && token_starts_before(tokens, index, limit) {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwWhen) => {
                let next = parse_handler_arm(tokens, index, owner, limit, handlers);
                if next <= index {
                    index = index.saturating_add(1);
                } else {
                    index = next;
                }
            }
            Some(TokenKind::KwEnd) if is_handler_block_end(tokens, index) => break,
            Some(_) => index = index.saturating_add(1),
            None => break,
        }
    }
}

fn parse_handler_arm(
    tokens: &[Token],
    when_index: usize,
    owner: &HandlerOwner,
    limit: u32,
    handlers: &mut Vec<ExceptionHandler>,
) -> usize {
    let Some(arrow_index) = find_arrow(tokens, when_index.saturating_add(1), limit) else {
        return find_next_arm_or_end(tokens, when_index.saturating_add(1), limit);
    };
    let (binds, choices) = parse_choices(tokens, when_index.saturating_add(1), arrow_index);
    let body_start = arrow_index.saturating_add(1);
    let body_end = find_next_arm_or_end(tokens, body_start, limit);

    if choices.is_empty() {
        return body_end;
    }

    let span = span_from_token_range(tokens, when_index, body_end.max(body_start));
    let body_span = span_from_token_range(tokens, body_start, body_end);
    handlers.push(ExceptionHandler {
        id: HandlerId(handlers.len() as u32),
        owner: owner.clone(),
        choices,
        binds,
        span,
        body_span,
    });

    body_end
}

fn parse_choices(
    tokens: &[Token],
    mut index: usize,
    arrow_index: usize,
) -> (Option<String>, Vec<Choice>) {
    let binds = if identifier_text(tokens.get(index)).is_some()
        && kind_at(tokens, index.saturating_add(1), &TokenKind::Colon)
    {
        let binding = identifier_text(tokens.get(index));
        index = index.saturating_add(2);
        binding
    } else {
        None
    };

    let mut choices = Vec::new();
    while index < arrow_index {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Identifier(_)) => {
                if let Some((name, next)) = parse_dotted_name(tokens, index) {
                    choices.push(Choice(name));
                    index = next;
                } else {
                    index = index.saturating_add(1);
                }
            }
            Some(TokenKind::KwOthers) => {
                choices.push(Choice("others".to_owned()));
                index = index.saturating_add(1);
            }
            Some(_) => index = index.saturating_add(1),
            None => break,
        }
    }

    (binds, choices)
}

fn find_arrow(tokens: &[Token], mut index: usize, limit: u32) -> Option<usize> {
    while index < tokens.len() && token_starts_before(tokens, index, limit) {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Arrow) => return Some(index),
            Some(TokenKind::KwWhen) | Some(TokenKind::KwEnd) => return None,
            Some(_) => index = index.saturating_add(1),
            None => return None,
        }
    }

    None
}

fn find_next_arm_or_end(tokens: &[Token], mut index: usize, limit: u32) -> usize {
    let mut nesting = NestingDepth::default();

    while index < tokens.len() && token_starts_before(tokens, index, limit) {
        if nesting.is_top_level() {
            match tokens.get(index).map(|token| &token.effective_kind) {
                Some(TokenKind::KwWhen) => return index,
                Some(TokenKind::KwEnd) if is_handler_block_end(tokens, index) => return index,
                Some(_) => {}
                None => return index,
            }
        }
        index = nesting.observe(tokens, index);
    }

    index.min(tokens.len())
}

#[derive(Debug, Default)]
struct NestingDepth {
    case_select: u32,
}

impl NestingDepth {
    fn is_top_level(&self) -> bool {
        self.case_select == 0
    }

    fn observe(&mut self, tokens: &[Token], index: usize) -> usize {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwCase | TokenKind::KwSelect) => {
                self.case_select = self.case_select.saturating_add(1);
                index.saturating_add(1)
            }
            Some(TokenKind::KwEnd)
                if matches!(
                    tokens
                        .get(index.saturating_add(1))
                        .map(|token| &token.effective_kind),
                    Some(TokenKind::KwCase | TokenKind::KwSelect)
                ) =>
            {
                self.case_select = self.case_select.saturating_sub(1);
                index.saturating_add(2)
            }
            Some(_) => index.saturating_add(1),
            None => index,
        }
    }
}

fn is_handler_block_end(tokens: &[Token], index: usize) -> bool {
    !matches!(
        tokens
            .get(index.saturating_add(1))
            .map(|token| &token.effective_kind),
        Some(
            TokenKind::KwIf
                | TokenKind::KwLoop
                | TokenKind::KwCase
                | TokenKind::KwRecord
                | TokenKind::KwSelect
                | TokenKind::KwReturn
                | TokenKind::KwDo
        )
    )
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

fn token_starts_before(tokens: &[Token], index: usize, limit: u32) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.text_span.start < limit)
}

fn first_token_at_or_after(tokens: &[Token], byte: u32) -> usize {
    tokens
        .iter()
        .position(|token| token.text_span.start >= byte)
        .unwrap_or(tokens.len())
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

#[cfg(test)]
mod tests {
    use super::extract_handlers;
    use crate::ast::{AdaStandard, Choice, HandlerOwner};
    use crate::extract::{build_scope_tree, extract_packages, extract_subprograms};
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2012)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn extracted_parts(
        source: &str,
    ) -> (
        crate::extract::ScopeTree,
        Vec<crate::ast::Package>,
        Vec<crate::ast::Subprogram>,
        Vec<Token>,
    ) {
        let tokens = tokens(source);
        let tree = build_scope_tree(&tokens);
        let packages = extract_packages(&tree, source, &tokens);
        let subprograms = extract_subprograms(&tree, source, &tokens, AdaStandard::Ada2012);
        (tree, packages, subprograms, tokens)
    }

    #[test]
    fn single_handler_with_named_choice() {
        let source = "procedure P is begin null; exception when Constraint_Error => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].choices,
            vec![Choice("constraint_error".to_owned())]
        );
        assert_eq!(
            handlers[0].owner,
            HandlerOwner::Subprogram(subprograms[0].id)
        );
    }

    #[test]
    fn multiple_choices_separated_by_pipe() {
        let source = "procedure P is begin null; exception when Constraint_Error | Program_Error => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(
            handlers[0].choices,
            vec![
                Choice("constraint_error".to_owned()),
                Choice("program_error".to_owned())
            ]
        );
    }

    #[test]
    fn others_choice_recognised() {
        let source = "procedure P is begin null; exception when others => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers[0].choices, vec![Choice("others".to_owned())]);
    }

    #[test]
    fn named_binding_captured_in_binds() {
        let source =
            "procedure P is begin null; exception when E : Constraint_Error => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers[0].binds.as_deref(), Some("e"));
    }

    #[test]
    fn nested_subprogram_handler_attaches_to_correct_owner() {
        let source = "procedure Outer is procedure Inner is begin null; exception when others => null; end Inner; begin null; end Outer;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);
        let inner = subprograms
            .iter()
            .find(|subprogram| subprogram.name == "inner")
            .unwrap();

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].owner, HandlerOwner::Subprogram(inner.id));
    }

    #[test]
    fn package_body_initialiser_handler_attaches_to_package_body_owner() {
        let source = "package body P is begin null; exception when others => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert!(subprograms.is_empty());
        assert_eq!(packages.len(), 1);
        assert_eq!(handlers.len(), 1);
        assert!(matches!(
            &handlers[0].owner,
            HandlerOwner::PackageBody(id) if *id == packages[0].id
        ));
    }

    #[test]
    fn nested_case_in_handler_body_does_not_create_extra_handler() {
        let source = r#"
procedure P is
begin
   null;
exception
   when others =>
      case State is
         when Red => null;
      end case;
end P;
"#;
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].choices, vec![Choice("others".to_owned())]);
    }

    #[test]
    fn exception_type_declaration_does_not_open_handler_block() {
        let source = r#"
procedure P is
   E : exception;
begin
   case State is
      when Red => null;
   end case;
end P;
"#;
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert!(handlers.is_empty());
    }

    #[test]
    fn nested_select_in_handler_body_does_not_create_extra_handler() {
        let source = r#"
procedure P is
begin
   null;
exception
   when others =>
      select
         when Ready => null;
      end select;
end P;
"#;
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].choices, vec![Choice("others".to_owned())]);
    }

    #[test]
    fn multiple_handlers_with_nested_case_keep_all_arms_intact() {
        let source = r#"
procedure P is
begin
   null;
exception
   when Constraint_Error =>
      case State is
         when Red => null;
      end case;
   when Program_Error =>
      null;
end P;
"#;
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 2);
        assert_eq!(
            handlers[0].choices,
            vec![Choice("constraint_error".to_owned())]
        );
        assert_eq!(
            handlers[1].choices,
            vec![Choice("program_error".to_owned())]
        );
    }

    #[test]
    fn malformed_handler_arm_skips_to_next_when() {
        let source =
            "procedure P is begin null; exception when => null; when Program_Error => null; end P;";
        let (tree, packages, subprograms, tokens) = extracted_parts(source);

        let handlers = extract_handlers(&tree, &packages, &subprograms, source, &tokens);

        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].choices,
            vec![Choice("program_error".to_owned())]
        );
    }
}
