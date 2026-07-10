// SPDX-License-Identifier: Apache-2.0

use crate::lexer::{Token, TokenKind};

pub struct TokenCursor<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> TokenCursor<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    pub fn peek_kind(&self) -> Option<&'a TokenKind> {
        self.peek().map(|token| &token.effective_kind)
    }

    pub fn peek_at(&self, offset: usize) -> Option<&'a Token> {
        self.tokens.get(self.pos.saturating_add(offset))
    }

    pub fn advance(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.pos)?;
        self.pos = self.pos.saturating_add(1);
        Some(token)
    }

    pub fn matches(&self, kind: &TokenKind) -> bool {
        self.peek()
            .is_some_and(|token| token.effective_kind == *kind)
    }

    pub fn consume(&mut self, kind: &TokenKind) -> bool {
        if !self.matches(kind) {
            return false;
        }

        self.pos = self.pos.saturating_add(1);
        true
    }

    pub fn skip_until_at_depth_zero(&mut self, pred: impl Fn(&TokenKind) -> bool) {
        let mut paren_depth = 0u32;

        while let Some(token) = self.peek() {
            let kind = &token.effective_kind;
            if paren_depth == 0 && pred(kind) {
                break;
            }

            match kind {
                TokenKind::LParen => paren_depth = paren_depth.saturating_add(1),
                TokenKind::RParen => paren_depth = paren_depth.saturating_sub(1),
                _ => {}
            }

            self.pos = self.pos.saturating_add(1);
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos.min(self.tokens.len());
    }
}

#[cfg(test)]
mod tests {
    use super::TokenCursor;
    use crate::ast::AdaStandard;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2012)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    #[test]
    fn peek_after_advance_returns_next_token() {
        let tokens = tokens("procedure P;");
        let mut cursor = TokenCursor::new(&tokens);

        assert!(matches!(cursor.peek_kind(), Some(TokenKind::KwProcedure)));
        assert!(matches!(
            cursor.advance().map(|token| &token.effective_kind),
            Some(TokenKind::KwProcedure)
        ));
        assert!(matches!(
            cursor.peek_kind(),
            Some(TokenKind::Identifier(name)) if name == "p"
        ));
    }

    #[test]
    fn peek_at_reads_without_advancing() {
        let tokens = tokens("procedure P;");
        let cursor = TokenCursor::new(&tokens);

        assert!(matches!(
            cursor.peek_at(1).map(|token| &token.effective_kind),
            Some(TokenKind::Identifier(name)) if name == "p"
        ));
        assert_eq!(cursor.pos(), 0);
    }

    #[test]
    fn skip_until_at_depth_zero_ignores_semicolon_inside_parentheses() {
        let tokens = tokens("P (A; B); Q;");
        let mut cursor = TokenCursor::new(&tokens);

        cursor.skip_until_at_depth_zero(|kind| *kind == TokenKind::Semicolon);

        assert!(matches!(cursor.peek_kind(), Some(TokenKind::Semicolon)));
        assert!(matches!(
            cursor.peek_at(1).map(|token| &token.effective_kind),
            Some(TokenKind::Identifier(name)) if name == "q"
        ));
    }

    #[test]
    fn advance_past_eof_returns_none() {
        let tokens = tokens("");
        let mut cursor = TokenCursor::new(&tokens);

        assert!(cursor.advance().is_some());
        assert!(cursor.advance().is_none());
        assert!(cursor.advance().is_none());
    }

    #[test]
    fn consume_only_advances_on_match() {
        let tokens = tokens("procedure P;");
        let mut cursor = TokenCursor::new(&tokens);

        assert!(!cursor.consume(&TokenKind::KwFunction));
        assert_eq!(cursor.pos(), 0);
        assert!(cursor.consume(&TokenKind::KwProcedure));
        assert_eq!(cursor.pos(), 1);
    }

    #[test]
    fn set_pos_clamps_to_token_len() {
        let tokens = tokens("procedure P;");
        let mut cursor = TokenCursor::new(&tokens);

        cursor.set_pos(usize::MAX);

        assert_eq!(cursor.pos(), tokens.len());
        assert!(cursor.peek().is_none());
    }
}
