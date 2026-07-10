// SPDX-License-Identifier: Apache-2.0

use crate::ast::AdaStandard;
use crate::lexer::{Token, TokenKind};

pub fn parse_trailing_aspects(
    source: &str,
    tokens: &[Token],
    after_decl_idx: usize,
    dialect: AdaStandard,
) -> (Vec<String>, usize) {
    if dialect < AdaStandard::Ada2012 || !kind_at(tokens, after_decl_idx, &TokenKind::KwWith) {
        return (Vec::new(), after_decl_idx);
    }

    let mut aspects = Vec::new();
    let mut index = after_decl_idx.saturating_add(1);

    while index < tokens.len() {
        if matches!(
            tokens.get(index).map(|token| &token.effective_kind),
            Some(TokenKind::Semicolon | TokenKind::Eof) | None
        ) {
            return (aspects, index);
        }

        let entry_start = index;
        let mut entry_end = index;
        let mut paren_depth = 0u32;

        while entry_end < tokens.len() {
            match tokens.get(entry_end).map(|token| &token.effective_kind) {
                Some(TokenKind::LParen) => paren_depth = paren_depth.saturating_add(1),
                Some(TokenKind::RParen) => paren_depth = paren_depth.saturating_sub(1),
                Some(TokenKind::Comma) if paren_depth == 0 => break,
                Some(TokenKind::Semicolon | TokenKind::Eof) if paren_depth == 0 => break,
                Some(_) => {}
                None => break,
            }
            entry_end = entry_end.saturating_add(1);
        }

        if let Some(text) = source_text(source, tokens, entry_start, entry_end) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                aspects.push(trimmed.to_owned());
            }
        }

        match tokens.get(entry_end).map(|token| &token.effective_kind) {
            Some(TokenKind::Comma) => index = entry_end.saturating_add(1),
            Some(TokenKind::Semicolon) => return (aspects, entry_end.saturating_add(1)),
            Some(TokenKind::Eof) | None => return (aspects, entry_end),
            Some(_) => index = entry_end.saturating_add(1),
        }
    }

    (aspects, tokens.len())
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

fn kind_at(tokens: &[Token], index: usize, kind: &TokenKind) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == *kind)
}

#[cfg(test)]
mod tests {
    use super::parse_trailing_aspects;
    use crate::ast::AdaStandard;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2022)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn with_index(tokens: &[Token]) -> usize {
        tokens
            .iter()
            .position(|token| token.effective_kind == TokenKind::KwWith)
            .unwrap()
    }

    #[test]
    fn pre_2012_returns_empty_no_consumption() {
        let source = "with Inline => True;";
        let tokens = tokens(source);
        let start = with_index(&tokens);

        let (aspects, next) = parse_trailing_aspects(source, &tokens, start, AdaStandard::Ada2005);

        assert!(aspects.is_empty());
        assert_eq!(next, start);
    }

    #[test]
    fn single_aspect_with_value() {
        let source = "with Inline => True;";
        let tokens = tokens(source);

        let (aspects, _) =
            parse_trailing_aspects(source, &tokens, with_index(&tokens), AdaStandard::Ada2012);

        assert_eq!(aspects, vec!["Inline => True"]);
    }

    #[test]
    fn single_aspect_no_value() {
        let source = "with Pack;";
        let tokens = tokens(source);

        let (aspects, _) =
            parse_trailing_aspects(source, &tokens, with_index(&tokens), AdaStandard::Ada2012);

        assert_eq!(aspects, vec!["Pack"]);
    }

    #[test]
    fn multiple_aspects_comma_separated() {
        let source = "with Inline => True, Pack, Size => 32;";
        let tokens = tokens(source);

        let (aspects, _) =
            parse_trailing_aspects(source, &tokens, with_index(&tokens), AdaStandard::Ada2012);

        assert_eq!(aspects, vec!["Inline => True", "Pack", "Size => 32"]);
    }

    #[test]
    fn aspect_value_with_parens_preserves_commas_inside() {
        let source = "with Predicate => Check (A, B), Pack;";
        let tokens = tokens(source);

        let (aspects, _) =
            parse_trailing_aspects(source, &tokens, with_index(&tokens), AdaStandard::Ada2012);

        assert_eq!(aspects, vec!["Predicate => Check (A, B)", "Pack"]);
    }

    #[test]
    fn unterminated_aspect_does_not_panic_returns_partial() {
        let source = "with Inline => True, Pack";
        let tokens = tokens(source);

        let (aspects, next) =
            parse_trailing_aspects(source, &tokens, with_index(&tokens), AdaStandard::Ada2012);

        assert_eq!(aspects, vec!["Inline => True", "Pack"]);
        assert_eq!(next, tokens.len().saturating_sub(1));
    }
}
