// SPDX-License-Identifier: Apache-2.0

use crate::lexer::{Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepClause {
    pub target_name: String,
    pub clause_text: String,
    pub byte_offset: u32,
}

pub fn extract_representation_clauses(source: &str, tokens: &[Token]) -> Vec<RepClause> {
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
            Some(TokenKind::KwFor) if paren_depth == 0 => {
                if let Some((clause, next_index)) = parse_clause(source, tokens, index) {
                    clauses.push(clause);
                    index = next_index;
                } else {
                    index = skip_to_after_semicolon(tokens, index.saturating_add(1));
                }
            }
            Some(_) => index = index.saturating_add(1),
            None => break,
        }
    }

    clauses
}

fn parse_clause(source: &str, tokens: &[Token], start_index: usize) -> Option<(RepClause, usize)> {
    let target = identifier_text(tokens.get(start_index.saturating_add(1))?)?;
    let byte_offset = tokens.get(start_index)?.text_span.start;
    let mut index = start_index.saturating_add(2);

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwUse) => break,
            Some(TokenKind::KwIn | TokenKind::KwLoop | TokenKind::Semicolon | TokenKind::Eof) => {
                return None;
            }
            Some(_) => index = index.saturating_add(1),
            None => return None,
        }
    }

    let use_index = index;
    let end_index = if kind_at(tokens, use_index.saturating_add(1), &TokenKind::KwRecord) {
        find_end_record_semicolon(tokens, use_index.saturating_add(2))?
    } else {
        find_depth_zero_semicolon(tokens, use_index.saturating_add(1))?
    };

    let raw = source_text(source, tokens, start_index, end_index.saturating_add(1))?;
    Some((
        RepClause {
            target_name: target,
            clause_text: format!("rep: {}", raw.trim()),
            byte_offset,
        },
        end_index.saturating_add(1),
    ))
}

fn find_end_record_semicolon(tokens: &[Token], mut index: usize) -> Option<usize> {
    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::KwEnd)
                if kind_at(tokens, index.saturating_add(1), &TokenKind::KwRecord)
                    && kind_at(tokens, index.saturating_add(2), &TokenKind::Semicolon) =>
            {
                return Some(index.saturating_add(2));
            }
            Some(TokenKind::Eof) | None => return None,
            Some(_) => index = index.saturating_add(1),
        }
    }

    None
}

fn find_depth_zero_semicolon(tokens: &[Token], mut index: usize) -> Option<usize> {
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
            Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
            Some(TokenKind::Semicolon) if paren_depth == 0 => return Some(index),
            Some(TokenKind::Eof) | None => return None,
            Some(_) => {}
        }
        index = index.saturating_add(1);
    }

    None
}

fn skip_to_after_semicolon(tokens: &[Token], mut index: usize) -> usize {
    while index < tokens.len() {
        if tokens[index].effective_kind == TokenKind::Semicolon {
            return index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }

    index
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

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

#[cfg(test)]
mod tests {
    use super::{extract_representation_clauses, RepClause};
    use crate::ast::AdaStandard;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2012)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    #[test]
    fn for_size_attribute_clause() {
        let source = "for T'Size use 32;";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert_eq!(
            clauses,
            vec![RepClause {
                target_name: "t".to_owned(),
                clause_text: "rep: for T'Size use 32;".to_owned(),
                byte_offset: 0
            }]
        );
    }

    #[test]
    fn for_record_use_clause_with_field_positions() {
        let source = "for R use record at mod 4; F1 at 0 range 0 .. 7; end record;";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].target_name, "r");
        assert_eq!(clauses[0].clause_text, format!("rep: {source}"));
        assert_eq!(clauses[0].byte_offset, 0);
    }

    #[test]
    fn for_enumeration_representation_clause() {
        let source = "for Color use (Red => 1, Green => 2);";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert_eq!(clauses[0].target_name, "color");
        assert_eq!(clauses[0].clause_text, format!("rep: {source}"));
        assert_eq!(clauses[0].byte_offset, 0);
    }

    #[test]
    fn unrelated_for_loop_not_captured() {
        let source = "procedure P is begin for I in 1 .. 10 loop null; end loop; end P;";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert!(clauses.is_empty());
    }

    #[test]
    fn multiple_rep_clauses_for_different_types() {
        let source = "for T'Size use 32; for R'Alignment use 4;";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert_eq!(
            clauses
                .iter()
                .map(|clause| clause.target_name.as_str())
                .collect::<Vec<_>>(),
            vec!["t", "r"]
        );
    }

    #[test]
    fn malformed_rep_clause_skips_without_panic() {
        let source = "for Broken use record F at 0 range 0 .. 7; for T'Size use 32;";
        let clauses = extract_representation_clauses(source, &tokens(source));

        assert_eq!(
            clauses,
            vec![RepClause {
                target_name: "t".to_owned(),
                clause_text: "rep: for T'Size use 32;".to_owned(),
                byte_offset: 43
            }]
        );
    }
}
