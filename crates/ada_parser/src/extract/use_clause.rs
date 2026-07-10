// SPDX-License-Identifier: Apache-2.0

use crate::ast::{UseClause, UseKind};
use crate::lexer::{Token, TokenKind};

pub fn extract_use_clauses(_source: &str, tokens: &[Token]) -> Vec<UseClause> {
    let mut clauses = Vec::new();
    let mut index = 0usize;
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => {
                paren_depth = paren_depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::RParen) => {
                paren_depth = paren_depth.saturating_sub(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::KwUse) if paren_depth == 0 => {
                if let Some((clause, next)) = parse_use_clause(tokens, index) {
                    clauses.push(clause);
                    index = next;
                } else {
                    index = skip_to_statement_end(tokens, index).saturating_add(1);
                }
            }
            Some(_) => index = index.saturating_add(1),
            None => break,
        }
    }

    clauses
}

fn parse_use_clause(tokens: &[Token], use_index: usize) -> Option<(UseClause, usize)> {
    let mut index = use_index.saturating_add(1);
    let kind = if kind_at(tokens, index, &TokenKind::KwAll) {
        index = index.saturating_add(1);
        if !kind_at(tokens, index, &TokenKind::KwType) {
            return None;
        }
        index = index.saturating_add(1);
        UseKind::UseAllType
    } else if kind_at(tokens, index, &TokenKind::KwType) {
        index = index.saturating_add(1);
        UseKind::UseType
    } else {
        UseKind::Use
    };

    let mut names = Vec::new();
    loop {
        let (name, next) = parse_name(tokens, index)?;
        names.push(name);
        index = next;

        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Comma) => index = index.saturating_add(1),
            Some(TokenKind::Semicolon) => {
                return Some((UseClause { kind, names }, index.saturating_add(1)));
            }
            _ => return None,
        }
    }
}

fn parse_name(tokens: &[Token], mut index: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    parts.push(identifier_text(tokens.get(index))?);
    index = index.saturating_add(1);

    while matches!(
        tokens.get(index).map(|token| &token.effective_kind),
        Some(TokenKind::Dot | TokenKind::Tick)
    ) {
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

fn skip_to_statement_end(tokens: &[Token], mut index: usize) -> usize {
    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::Semicolon | TokenKind::Eof) | None => return index,
            Some(_) => index = index.saturating_add(1),
        }
    }

    index
}

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

#[cfg(test)]
mod tests {
    use super::extract_use_clauses;
    use crate::ast::{AdaStandard, UseKind};
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2022)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    #[test]
    fn plain_use_clause() {
        let source = "use Ada.Text_IO;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].kind, UseKind::Use);
        assert_eq!(clauses[0].names, vec!["ada.text_io"]);
    }

    #[test]
    fn use_type_clause() {
        let source = "use type Interfaces.Unsigned_32;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert_eq!(clauses[0].kind, UseKind::UseType);
        assert_eq!(clauses[0].names, vec!["interfaces.unsigned_32"]);
    }

    #[test]
    fn use_all_type_clause_at_2012() {
        let source = "use all type Root.T;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert_eq!(clauses[0].kind, UseKind::UseAllType);
        assert_eq!(clauses[0].names, vec!["root.t"]);
    }

    #[test]
    fn comma_separated_use_clause() {
        let source = "use Ada.Text_IO, Ada.Calendar, Foo.Bar;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert_eq!(clauses[0].kind, UseKind::Use);
        assert_eq!(
            clauses[0].names,
            vec!["ada.text_io", "ada.calendar", "foo.bar"]
        );
    }

    #[test]
    fn use_inside_package_body_declarative_part() {
        let source = "package body P is use Ada.Text_IO; begin null; end P;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].names, vec!["ada.text_io"]);
    }

    #[test]
    fn malformed_use_clause_does_not_panic_or_emit_partial_clause() {
        let source = "use ; package P is end P;";

        let clauses = extract_use_clauses(source, &tokens(source));

        assert!(clauses.is_empty());
    }
}
