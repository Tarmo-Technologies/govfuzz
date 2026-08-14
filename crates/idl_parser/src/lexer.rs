// SPDX-License-Identifier: Apache-2.0

use crate::error::{IdlParseError, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Identifier,
    Number,
    StringLiteral,
    Punctuation,
    End,
}

pub fn lex(source: &str) -> Result<Vec<Token>, IdlParseError> {
    let lexer = Lexer {
        source,
        pos: 0,
        line: 1,
        column: 1,
        tokens: Vec::new(),
    };
    lexer.lex_all()
}

struct Lexer<'a> {
    source: &'a str,
    pos: usize,
    line: usize,
    column: usize,
    tokens: Vec<Token>,
}

impl Lexer<'_> {
    fn lex_all(mut self) -> Result<Vec<Token>, IdlParseError> {
        while let Some(ch) = self.peek() {
            match ch {
                // U+FEFF is Cf, not White_Space, so `is_whitespace` misses the
                // byte-order mark an editor leaves at the head of a UTF-8 `.idl`.
                // Every real IDL compiler tolerates it; rejecting it skipped the
                // entire file on its first character.
                ch if ch.is_whitespace() || ch == '\u{feff}' => {
                    self.bump();
                }
                '/' if self.peek_next() == Some('/') => self.skip_line_comment(),
                '/' if self.peek_next() == Some('*') => self.skip_block_comment()?,
                '"' | '\'' => self.lex_string()?,
                ':' if self.peek_next() == Some(':') => self.push_punctuation(2),
                ch if is_ident_start(ch) => self.lex_identifier(),
                ch if ch.is_ascii_digit() => self.lex_number(),
                '.' if self.peek_next().is_some_and(|ch| ch.is_ascii_digit()) => self.lex_number(),
                ch if is_punctuation(ch) => self.push_punctuation(ch.len_utf8()),
                _ => {
                    let span = self.current_span();
                    return Err(IdlParseError::new(
                        format!("unexpected character '{ch}'"),
                        span,
                    ));
                }
            }
        }

        self.tokens.push(Token {
            kind: TokenKind::End,
            text: String::new(),
            span: self.current_span(),
        });
        Ok(self.tokens)
    }

    fn lex_identifier(&mut self) {
        let start = self.mark();
        while self.peek().is_some_and(is_ident_continue) {
            self.bump();
        }
        self.push_token(TokenKind::Identifier, start);
    }

    fn lex_number(&mut self) {
        let start = self.mark();
        // A hexadecimal literal's `e`/`E` are digits, not exponent markers, so
        // `0x1E+2` stays an addition while `1E+2` is one floating literal.
        let hexadecimal = {
            let rest = &self.source[self.pos..];
            rest.starts_with("0x") || rest.starts_with("0X")
        };
        while let Some(ch) = self.peek() {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.')) {
                break;
            }
            let exponent_marker = !hexadecimal && matches!(ch, 'e' | 'E');
            self.bump();
            // `3.40023E+16`: absorb the signed exponent so the `+` is not lexed
            // as an addition operator that splits the literal in three tokens.
            if exponent_marker
                && matches!(self.peek(), Some('+' | '-'))
                && self.peek_next().is_some_and(|ch| ch.is_ascii_digit())
            {
                self.bump();
            }
        }
        self.push_token(TokenKind::Number, start);
    }

    fn lex_string(&mut self) -> Result<(), IdlParseError> {
        let start = self.mark();
        let quote = self.bump().expect("string quote is present");
        let mut escaped = false;
        while let Some(ch) = self.peek() {
            self.bump();
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                self.push_token(TokenKind::StringLiteral, start);
                return Ok(());
            }
        }
        Err(IdlParseError::new(
            "unterminated string literal",
            start.span(),
        ))
    }

    fn skip_line_comment(&mut self) {
        while let Some(ch) = self.peek() {
            self.bump();
            if ch == '\n' {
                break;
            }
        }
    }

    fn skip_block_comment(&mut self) -> Result<(), IdlParseError> {
        let start = self.mark();
        self.bump();
        self.bump();
        while let Some(ch) = self.peek() {
            if ch == '*' && self.peek_next() == Some('/') {
                self.bump();
                self.bump();
                return Ok(());
            }
            self.bump();
        }
        Err(IdlParseError::new(
            "unterminated block comment",
            start.span(),
        ))
    }

    fn push_punctuation(&mut self, len: usize) {
        let start = self.mark();
        let end = self.pos + len;
        while self.pos < end {
            self.bump();
        }
        self.push_token(TokenKind::Punctuation, start);
    }

    fn push_token(&mut self, kind: TokenKind, start: Mark) {
        self.tokens.push(Token {
            kind,
            text: self.source[start.pos..self.pos].to_owned(),
            span: Span {
                start: start.pos,
                end: self.pos,
                line: start.line,
                column: start.column,
            },
        });
    }

    fn mark(&self) -> Mark {
        Mark {
            pos: self.pos,
            line: self.line,
            column: self.column,
        }
    }

    fn current_span(&self) -> Span {
        Span {
            start: self.pos,
            end: self.pos,
            line: self.line,
            column: self.column,
        }
    }

    fn peek(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    fn peek_next(&self) -> Option<char> {
        let mut chars = self.source[self.pos..].chars();
        chars.next()?;
        chars.next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(ch)
    }
}

#[derive(Debug, Clone, Copy)]
struct Mark {
    pos: usize,
    line: usize,
    column: usize,
}

impl Mark {
    fn span(self) -> Span {
        Span {
            start: self.pos,
            end: self.pos,
            line: self.line,
            column: self.column,
        }
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_punctuation(ch: char) -> bool {
    matches!(
        ch,
        '{' | '}'
            | '('
            | ')'
            | '['
            | ']'
            | '<'
            | '>'
            | ';'
            | ':'
            | ','
            | '='
            | '#'
            | '+'
            | '-'
            | '*'
            | '/'
            | '%'
            | '|'
            | '&'
            | '^'
            | '~'
            | '@'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_skips_line_and_block_comments() {
        let tokens = lex("module Foo { // x\n /* y */ interface Bar {}; };").expect("lexes");
        assert!(tokens.iter().any(|token| token.text == "module"));
        assert!(tokens
            .iter()
            .all(|token| token.text != "x" && token.text != "y"));
    }

    #[test]
    fn lex_preserves_scoped_name_punctuation_and_literals() {
        let tokens = lex("const long X = ::Foo::Bar + 42; string<16> name;").expect("lexes");
        let texts = tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert!(texts.windows(2).any(|window| window == ["::", "Foo"]));
        assert!(texts.contains(&"42"));
        assert!(texts.contains(&"<"));
        assert!(texts.contains(&">"));
    }

    #[test]
    fn lex_accepts_leading_dot_numeric_literals() {
        let tokens = lex("@default(value=.1) @default(value=.3d)").expect("lexes");
        let texts = tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert!(texts.contains(&".1"));
        assert!(texts.contains(&".3d"));
    }

    #[test]
    fn lex_keeps_signed_float_exponents_in_one_number_token() {
        let tokens = lex("const double S = 3.40023E+16; const double T = 1.0e-5;").expect("lexes");
        let texts = tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert!(texts.contains(&"3.40023E+16"), "got {texts:?}");
        assert!(texts.contains(&"1.0e-5"), "got {texts:?}");
        assert!(!texts.contains(&"+"), "exponent sign leaked as an operator");
    }

    #[test]
    fn lex_treats_hexadecimal_e_as_a_digit_not_an_exponent() {
        let tokens = lex("const long X = 0x1E+2;").expect("lexes");
        let texts = tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert!(texts.contains(&"0x1E"), "got {texts:?}");
        assert!(texts.contains(&"+"), "got {texts:?}");
    }

    #[test]
    fn lex_accepts_complement_and_modulo_operators() {
        let tokens = lex("const long M = ~0 % 4;").expect("lexes");
        let texts = tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert!(texts.contains(&"~"), "got {texts:?}");
        assert!(texts.contains(&"%"), "got {texts:?}");
    }

    #[test]
    fn lex_unterminated_block_comment_errors_with_span() {
        let error = lex("module Foo { /* nope").expect_err("unterminated comment is rejected");
        assert!(error.to_string().contains("unterminated block comment"));
    }
}
