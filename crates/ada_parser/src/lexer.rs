// SPDX-License-Identifier: Apache-2.0

use crate::ast::AdaStandard;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub effective_kind: TokenKind,
    pub text_span: ByteRange,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    KwAbort,
    KwAbs,
    KwAccept,
    KwAccess,
    KwAll,
    KwAnd,
    KwArray,
    KwAt,
    KwBegin,
    KwBody,
    KwCase,
    KwConstant,
    KwDeclare,
    KwDelay,
    KwDelta,
    KwDigits,
    KwDo,
    KwElse,
    KwElsif,
    KwEnd,
    KwEntry,
    KwException,
    KwExit,
    KwFor,
    KwFunction,
    KwGeneric,
    KwGoto,
    KwIf,
    KwIn,
    KwIs,
    KwLimited,
    KwLoop,
    KwMod,
    KwNew,
    KwNot,
    KwNull,
    KwOf,
    KwOr,
    KwOthers,
    KwOut,
    KwPackage,
    KwPragma,
    KwPrivate,
    KwProcedure,
    KwProtected,
    KwRaise,
    KwRange,
    KwRecord,
    KwRem,
    KwRenames,
    KwRequeue,
    KwReturn,
    KwReverse,
    KwSelect,
    KwSeparate,
    KwSubtype,
    KwTagged,
    KwTask,
    KwTerminate,
    KwThen,
    KwType,
    KwUntil,
    KwUse,
    KwWhen,
    KwWhile,
    KwWith,
    KwXor,
    KwAbstract,
    KwAliased,
    KwInterface,
    KwOverriding,
    KwSynchronized,
    KwSome,
    KwParallel,
    Identifier(String),
    IntLiteral(String),
    RealLiteral(String),
    BasedLiteral(String),
    CharLiteral(char),
    StringLiteral(String),
    Comment(String),
    LParen,
    RParen,
    Semicolon,
    Comma,
    Colon,
    Assign,
    Arrow,
    DotDot,
    Tick,
    Dot,
    Box,
    Plus,
    Minus,
    Star,
    Slash,
    Ampersand,
    DoubleStar,
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    Error(String),
    Eof,
}

pub fn lex(source: &str, dialect: AdaStandard) -> Vec<Token> {
    Lexer::new(source, dialect).lex()
}

struct Lexer<'source> {
    source: &'source str,
    position: usize,
    line: u32,
    col: u32,
    dialect: AdaStandard,
    tokens: Vec<Token>,
    last_significant: Option<TokenKind>,
}

impl<'source> Lexer<'source> {
    fn new(source: &'source str, dialect: AdaStandard) -> Self {
        Self {
            source,
            position: 0,
            line: 1,
            col: 1,
            dialect,
            tokens: Vec::new(),
            last_significant: None,
        }
    }

    fn lex(mut self) -> Vec<Token> {
        while let Some(ch) = self.peek_char() {
            match ch {
                ch if ch.is_whitespace() => {
                    self.bump();
                }
                '-' if self.peek_next_char() == Some('-') => self.scan_comment(),
                '"' => self.scan_string(),
                '\'' => self.scan_apostrophe(),
                ch if ch.is_ascii_digit() => self.scan_number(),
                ch if is_identifier_start(ch) => self.scan_identifier_or_keyword(),
                _ => self.scan_punctuation_or_error(),
            }
        }

        let offset = self.position as u32;
        self.push_token_at(
            TokenKind::Eof,
            TokenKind::Eof,
            offset,
            offset,
            self.line,
            self.col,
        );
        self.tokens
    }

    fn scan_comment(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;
        self.bump();
        self.bump();
        let content_start = self.position;
        while let Some(ch) = self.peek_char() {
            if ch == '\n' {
                break;
            }
            self.bump();
        }
        let content = self.source[content_start..self.position].to_owned();
        self.push_token(
            TokenKind::Comment(content.clone()),
            TokenKind::Comment(content),
            start,
            line,
            col,
        );
    }

    fn scan_identifier_or_keyword(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;

        self.bump();
        while self.peek_char().is_some_and(is_identifier_continue) {
            self.bump();
        }

        let canonical = self.source[start..self.position].to_ascii_lowercase();
        let kind = keyword_or_identifier(&canonical, self.dialect);
        self.push_token(kind.clone(), kind, start, line, col);
    }

    fn scan_number(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;

        self.consume_decimal_digits();

        if self.peek_char() == Some('#') {
            self.scan_based_literal(start, line, col);
            return;
        }

        let mut is_real = false;
        if self.peek_char() == Some('.')
            && self.peek_next_char() != Some('.')
            && self.peek_next_char().is_some_and(|ch| ch.is_ascii_digit())
        {
            is_real = true;
            self.bump();
            self.consume_decimal_digits();
        }

        if matches!(self.peek_char(), Some('e' | 'E')) {
            let exponent_start = self.position;
            self.bump();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump();
            }
            let digits_start = self.position;
            self.consume_decimal_digits();
            if self.position == digits_start {
                self.position = exponent_start;
            } else {
                is_real = true;
            }
        }

        let text = self.source[start..self.position].to_owned();
        let kind = if is_real {
            TokenKind::RealLiteral(text)
        } else {
            TokenKind::IntLiteral(text)
        };
        self.push_token(kind.clone(), kind, start, line, col);
    }

    fn scan_based_literal(&mut self, start: usize, line: u32, col: u32) {
        let base_text = self.source[start..self.position].replace('_', "");
        let valid_base = base_text
            .parse::<u32>()
            .ok()
            .is_some_and(|base| (2..=16).contains(&base));

        self.bump();
        let mut saw_digit = false;
        while let Some(ch) = self.peek_char() {
            if ch == '#' {
                break;
            }
            if ch.is_whitespace() || is_resync_punctuation(ch) {
                break;
            }
            saw_digit = true;
            self.bump();
        }

        if !valid_base || !saw_digit || self.peek_char() != Some('#') {
            self.resync_wordish();
            self.push_token(
                TokenKind::Error("malformed based literal".to_owned()),
                TokenKind::Error("malformed based literal".to_owned()),
                start,
                line,
                col,
            );
            return;
        }

        self.bump();
        if matches!(self.peek_char(), Some('e' | 'E')) {
            let exponent_start = self.position;
            self.bump();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump();
            }
            let digits_start = self.position;
            self.consume_decimal_digits();
            if self.position == digits_start {
                self.position = exponent_start;
            }
        }

        let text = self.source[start..self.position].to_owned();
        self.push_token(
            TokenKind::BasedLiteral(text.clone()),
            TokenKind::BasedLiteral(text),
            start,
            line,
            col,
        );
    }

    fn scan_string(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;
        let mut content = String::new();

        self.bump();
        while let Some(ch) = self.peek_char() {
            match ch {
                '"' => {
                    self.bump();
                    if self.peek_char() == Some('"') {
                        content.push('"');
                        self.bump();
                    } else {
                        self.push_token(
                            TokenKind::StringLiteral(content.clone()),
                            TokenKind::StringLiteral(content),
                            start,
                            line,
                            col,
                        );
                        return;
                    }
                }
                '\n' => {
                    self.push_token(
                        TokenKind::Error("unterminated string literal".to_owned()),
                        TokenKind::Error("unterminated string literal".to_owned()),
                        start,
                        line,
                        col,
                    );
                    return;
                }
                _ => {
                    content.push(ch);
                    self.bump();
                }
            }
        }

        self.push_token(
            TokenKind::Error("unterminated string literal".to_owned()),
            TokenKind::Error("unterminated string literal".to_owned()),
            start,
            line,
            col,
        );
    }

    fn scan_apostrophe(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;

        if self.apostrophe_is_attribute_marker() {
            self.bump();
            self.push_token(TokenKind::Tick, TokenKind::Tick, start, line, col);
            return;
        }

        let Some((literal, end_position)) = self.character_literal_candidate() else {
            self.bump();
            self.push_token(TokenKind::Tick, TokenKind::Tick, start, line, col);
            return;
        };

        while self.position < end_position {
            self.bump();
        }
        self.push_token(
            TokenKind::CharLiteral(literal),
            TokenKind::CharLiteral(literal),
            start,
            line,
            col,
        );
    }

    fn scan_punctuation_or_error(&mut self) {
        let start = self.position;
        let line = self.line;
        let col = self.col;
        let Some(ch) = self.peek_char() else {
            return;
        };

        let kind = match ch {
            '(' => {
                self.bump();
                TokenKind::LParen
            }
            ')' => {
                self.bump();
                TokenKind::RParen
            }
            ';' => {
                self.bump();
                TokenKind::Semicolon
            }
            ',' => {
                self.bump();
                TokenKind::Comma
            }
            ':' => {
                self.bump();
                if self.peek_char() == Some('=') {
                    self.bump();
                    TokenKind::Assign
                } else {
                    TokenKind::Colon
                }
            }
            '=' => {
                self.bump();
                if self.peek_char() == Some('>') {
                    self.bump();
                    TokenKind::Arrow
                } else {
                    TokenKind::Eq
                }
            }
            '.' => {
                self.bump();
                if self.peek_char() == Some('.') {
                    self.bump();
                    TokenKind::DotDot
                } else {
                    TokenKind::Dot
                }
            }
            '<' => {
                self.bump();
                match self.peek_char() {
                    Some('>') => {
                        self.bump();
                        TokenKind::Box
                    }
                    Some('=') => {
                        self.bump();
                        TokenKind::Le
                    }
                    _ => TokenKind::Lt,
                }
            }
            '>' => {
                self.bump();
                if self.peek_char() == Some('=') {
                    self.bump();
                    TokenKind::Ge
                } else {
                    TokenKind::Gt
                }
            }
            '/' => {
                self.bump();
                if self.peek_char() == Some('=') {
                    self.bump();
                    TokenKind::Neq
                } else {
                    TokenKind::Slash
                }
            }
            '*' => {
                self.bump();
                if self.peek_char() == Some('*') {
                    self.bump();
                    TokenKind::DoubleStar
                } else {
                    TokenKind::Star
                }
            }
            '+' => {
                self.bump();
                TokenKind::Plus
            }
            '-' => {
                self.bump();
                TokenKind::Minus
            }
            '&' => {
                self.bump();
                TokenKind::Ampersand
            }
            _ => {
                self.bump();
                TokenKind::Error(format!("unexpected character '{ch}'"))
            }
        };

        self.push_token(kind.clone(), kind, start, line, col);
    }

    fn character_literal_candidate(&self) -> Option<(char, usize)> {
        let after_open = self.position + '\''.len_utf8();
        let mut chars = self.source.get(after_open..)?.char_indices();
        let (_, literal) = chars.next()?;
        if literal == '\n' || literal == '\'' {
            return None;
        }
        let after_literal = after_open + literal.len_utf8();
        if self.source.get(after_literal..)?.chars().next()? != '\'' {
            return None;
        }
        Some((literal, after_literal + '\''.len_utf8()))
    }

    fn apostrophe_is_attribute_marker(&self) -> bool {
        matches!(
            self.last_significant.as_ref(),
            Some(TokenKind::Identifier(_))
                | Some(TokenKind::RParen)
                | Some(TokenKind::KwAll)
                | Some(TokenKind::Tick)
        )
    }

    fn consume_decimal_digits(&mut self) {
        while self
            .peek_char()
            .is_some_and(|ch| ch.is_ascii_digit() || ch == '_')
        {
            self.bump();
        }
    }

    fn resync_wordish(&mut self) {
        while self
            .peek_char()
            .is_some_and(|ch| !ch.is_whitespace() && !is_resync_punctuation(ch))
        {
            self.bump();
        }
    }

    fn push_token(
        &mut self,
        kind: TokenKind,
        effective_kind: TokenKind,
        start: usize,
        line: u32,
        col: u32,
    ) {
        self.push_token_at(
            kind,
            effective_kind,
            start as u32,
            self.position as u32,
            line,
            col,
        );
    }

    fn push_token_at(
        &mut self,
        kind: TokenKind,
        effective_kind: TokenKind,
        start: u32,
        end: u32,
        line: u32,
        col: u32,
    ) {
        if !matches!(effective_kind, TokenKind::Comment(_) | TokenKind::Eof) {
            self.last_significant = Some(effective_kind.clone());
        }

        self.tokens.push(Token {
            kind,
            effective_kind,
            text_span: ByteRange { start, end },
            line,
            col,
        });
    }

    fn peek_char(&self) -> Option<char> {
        self.source.get(self.position..)?.chars().next()
    }

    fn peek_next_char(&self) -> Option<char> {
        let current = self.peek_char()?;
        self.source
            .get(self.position + current.len_utf8()..)?
            .chars()
            .next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.position += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }
}

fn keyword_or_identifier(word: &str, dialect: AdaStandard) -> TokenKind {
    match word {
        "abort" => TokenKind::KwAbort,
        "abs" => TokenKind::KwAbs,
        "accept" => TokenKind::KwAccept,
        "access" => TokenKind::KwAccess,
        "all" => TokenKind::KwAll,
        "and" => TokenKind::KwAnd,
        "array" => TokenKind::KwArray,
        "at" => TokenKind::KwAt,
        "begin" => TokenKind::KwBegin,
        "body" => TokenKind::KwBody,
        "case" => TokenKind::KwCase,
        "constant" => TokenKind::KwConstant,
        "declare" => TokenKind::KwDeclare,
        "delay" => TokenKind::KwDelay,
        "delta" => TokenKind::KwDelta,
        "digits" => TokenKind::KwDigits,
        "do" => TokenKind::KwDo,
        "else" => TokenKind::KwElse,
        "elsif" => TokenKind::KwElsif,
        "end" => TokenKind::KwEnd,
        "entry" => TokenKind::KwEntry,
        "exception" => TokenKind::KwException,
        "exit" => TokenKind::KwExit,
        "for" => TokenKind::KwFor,
        "function" => TokenKind::KwFunction,
        "generic" => TokenKind::KwGeneric,
        "goto" => TokenKind::KwGoto,
        "if" => TokenKind::KwIf,
        "in" => TokenKind::KwIn,
        "is" => TokenKind::KwIs,
        "limited" => TokenKind::KwLimited,
        "loop" => TokenKind::KwLoop,
        "mod" => TokenKind::KwMod,
        "new" => TokenKind::KwNew,
        "not" => TokenKind::KwNot,
        "null" => TokenKind::KwNull,
        "of" => TokenKind::KwOf,
        "or" => TokenKind::KwOr,
        "others" => TokenKind::KwOthers,
        "out" => TokenKind::KwOut,
        "package" => TokenKind::KwPackage,
        "pragma" => TokenKind::KwPragma,
        "private" => TokenKind::KwPrivate,
        "procedure" => TokenKind::KwProcedure,
        "protected" => TokenKind::KwProtected,
        "raise" => TokenKind::KwRaise,
        "range" => TokenKind::KwRange,
        "record" => TokenKind::KwRecord,
        "rem" => TokenKind::KwRem,
        "renames" => TokenKind::KwRenames,
        "requeue" => TokenKind::KwRequeue,
        "return" => TokenKind::KwReturn,
        "reverse" => TokenKind::KwReverse,
        "select" => TokenKind::KwSelect,
        "separate" => TokenKind::KwSeparate,
        "subtype" => TokenKind::KwSubtype,
        "tagged" => TokenKind::KwTagged,
        "task" => TokenKind::KwTask,
        "terminate" => TokenKind::KwTerminate,
        "then" => TokenKind::KwThen,
        "type" => TokenKind::KwType,
        "until" => TokenKind::KwUntil,
        "use" => TokenKind::KwUse,
        "when" => TokenKind::KwWhen,
        "while" => TokenKind::KwWhile,
        "with" => TokenKind::KwWith,
        "xor" => TokenKind::KwXor,
        "abstract" => TokenKind::KwAbstract,
        "aliased" => TokenKind::KwAliased,
        "interface" if dialect >= AdaStandard::Ada2005 => TokenKind::KwInterface,
        "overriding" if dialect >= AdaStandard::Ada2005 => TokenKind::KwOverriding,
        "synchronized" if dialect >= AdaStandard::Ada2005 => TokenKind::KwSynchronized,
        "some" if dialect >= AdaStandard::Ada2012 => TokenKind::KwSome,
        "parallel" if dialect >= AdaStandard::Ada2022 => TokenKind::KwParallel,
        _ => TokenKind::Identifier(word.to_owned()),
    }
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic()
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_resync_punctuation(ch: char) -> bool {
    matches!(
        ch,
        '(' | ')'
            | ';'
            | ','
            | ':'
            | '='
            | '.'
            | '<'
            | '>'
            | '/'
            | '*'
            | '+'
            | '-'
            | '&'
            | '\''
            | '"'
    )
}

#[cfg(test)]
mod tests {
    use super::{lex, ByteRange, TokenKind};
    use crate::ast::AdaStandard;

    fn non_eof_kinds(source: &str, dialect: AdaStandard) -> Vec<TokenKind> {
        lex(source, dialect)
            .into_iter()
            .filter(|token| token.kind != TokenKind::Eof)
            .map(|token| token.effective_kind)
            .collect()
    }

    #[test]
    fn interface_is_identifier_in_ada95() {
        assert_eq!(
            non_eof_kinds("interface", AdaStandard::Ada95),
            vec![TokenKind::Identifier("interface".to_owned())]
        );
    }

    #[test]
    fn interface_is_keyword_in_ada2005() {
        assert_eq!(
            non_eof_kinds("interface", AdaStandard::Ada2005),
            vec![TokenKind::KwInterface]
        );
    }

    #[test]
    fn overriding_is_identifier_in_ada95() {
        assert_eq!(
            non_eof_kinds("overriding", AdaStandard::Ada95),
            vec![TokenKind::Identifier("overriding".to_owned())]
        );
    }

    #[test]
    fn overriding_is_keyword_in_ada2005() {
        assert_eq!(
            non_eof_kinds("overriding", AdaStandard::Ada2005),
            vec![TokenKind::KwOverriding]
        );
    }

    #[test]
    fn synchronized_is_identifier_in_ada95() {
        assert_eq!(
            non_eof_kinds("synchronized", AdaStandard::Ada95),
            vec![TokenKind::Identifier("synchronized".to_owned())]
        );
    }

    #[test]
    fn synchronized_is_keyword_in_ada2005() {
        assert_eq!(
            non_eof_kinds("synchronized", AdaStandard::Ada2005),
            vec![TokenKind::KwSynchronized]
        );
    }

    #[test]
    fn parallel_is_identifier_below_ada2022() {
        assert_eq!(
            non_eof_kinds("parallel", AdaStandard::Ada2012),
            vec![TokenKind::Identifier("parallel".to_owned())]
        );
    }

    #[test]
    fn parallel_is_keyword_in_ada2022() {
        assert_eq!(
            non_eof_kinds("parallel", AdaStandard::Ada2022),
            vec![TokenKind::KwParallel]
        );
    }

    #[test]
    fn some_is_identifier_in_ada95() {
        assert_eq!(
            non_eof_kinds("some", AdaStandard::Ada95),
            vec![TokenKind::Identifier("some".to_owned())]
        );
    }

    #[test]
    fn some_is_keyword_at_ada2012_and_above() {
        for dialect in [AdaStandard::Ada2012, AdaStandard::Ada2022] {
            assert_eq!(
                non_eof_kinds("some", dialect),
                vec![TokenKind::KwSome],
                "expected KwSome under {dialect:?}"
            );
        }
    }

    #[test]
    fn decimal_integer_literal_is_preserved() {
        assert_eq!(
            non_eof_kinds("42", AdaStandard::Ada2012),
            vec![TokenKind::IntLiteral("42".to_owned())]
        );
    }

    #[test]
    fn decimal_real_literal_is_preserved() {
        assert_eq!(
            non_eof_kinds("42.5", AdaStandard::Ada2012),
            vec![TokenKind::RealLiteral("42.5".to_owned())]
        );
    }

    #[test]
    fn integer_literal_allows_underscores() {
        assert_eq!(
            non_eof_kinds("1_000_000", AdaStandard::Ada2012),
            vec![TokenKind::IntLiteral("1_000_000".to_owned())]
        );
    }

    #[test]
    fn based_literals_are_preserved() {
        assert_eq!(
            non_eof_kinds("16#FF# 2#1010#E2 8#777#", AdaStandard::Ada2012),
            vec![
                TokenKind::BasedLiteral("16#FF#".to_owned()),
                TokenKind::BasedLiteral("2#1010#E2".to_owned()),
                TokenKind::BasedLiteral("8#777#".to_owned())
            ]
        );
    }

    #[test]
    fn malformed_based_literal_emits_error() {
        let tokens = non_eof_kinds("16#FF", AdaStandard::Ada2012);
        assert_eq!(
            tokens,
            vec![TokenKind::Error("malformed based literal".to_owned())]
        );
    }

    #[test]
    fn string_literal_preserves_content() {
        assert_eq!(
            non_eof_kinds("\"hello\"", AdaStandard::Ada2012),
            vec![TokenKind::StringLiteral("hello".to_owned())]
        );
    }

    #[test]
    fn string_literal_unescapes_doubled_quotes() {
        assert_eq!(
            non_eof_kinds("\"with \"\"quote\"\" inside\"", AdaStandard::Ada2012),
            vec![TokenKind::StringLiteral("with \"quote\" inside".to_owned())]
        );
    }

    #[test]
    fn unterminated_string_before_newline_emits_error() {
        assert_eq!(
            non_eof_kinds("\"hello\nNext", AdaStandard::Ada2012)[0],
            TokenKind::Error("unterminated string literal".to_owned())
        );
    }

    #[test]
    fn character_literals_capture_single_character() {
        assert_eq!(
            non_eof_kinds("'A' '9'", AdaStandard::Ada2012),
            vec![TokenKind::CharLiteral('A'), TokenKind::CharLiteral('9')]
        );
    }

    #[test]
    fn identifier_apostrophe_identifier_is_attribute_marker() {
        assert_eq!(
            non_eof_kinds("Foo'Image", AdaStandard::Ada2012),
            vec![
                TokenKind::Identifier("foo".to_owned()),
                TokenKind::Tick,
                TokenKind::Identifier("image".to_owned())
            ]
        );
    }

    #[test]
    fn attribute_name_that_is_reserved_word_stays_reserved_token() {
        assert_eq!(
            non_eof_kinds("Foo'Range(1)", AdaStandard::Ada2012),
            vec![
                TokenKind::Identifier("foo".to_owned()),
                TokenKind::Tick,
                TokenKind::KwRange,
                TokenKind::LParen,
                TokenKind::IntLiteral("1".to_owned()),
                TokenKind::RParen
            ]
        );
    }

    #[test]
    fn multiline_comment_then_identifier_tracks_line_and_column() {
        let tokens = lex("-- comment\nThing", AdaStandard::Ada2012);
        assert_eq!(tokens[0].kind, TokenKind::Comment(" comment".to_owned()));
        assert_eq!(tokens[0].text_span, ByteRange { start: 0, end: 10 });
        assert_eq!(tokens[1].kind, TokenKind::Identifier("thing".to_owned()));
        assert_eq!((tokens[1].line, tokens[1].col), (2, 1));
    }

    #[test]
    fn trailing_whitespace_at_eof_only_emits_one_eof() {
        assert_eq!(
            lex("Name   \n\t", AdaStandard::Ada2012)
                .into_iter()
                .map(|token| token.kind)
                .collect::<Vec<_>>(),
            vec![TokenKind::Identifier("name".to_owned()), TokenKind::Eof]
        );
    }

    #[test]
    fn empty_input_emits_eof_only() {
        assert_eq!(
            lex("", AdaStandard::Ada2012)
                .into_iter()
                .map(|token| token.kind)
                .collect::<Vec<_>>(),
            vec![TokenKind::Eof]
        );
    }

    #[test]
    fn reserved_words_are_case_insensitive() {
        assert_eq!(
            non_eof_kinds("BEGIN Begin begin", AdaStandard::Ada2012),
            vec![TokenKind::KwBegin, TokenKind::KwBegin, TokenKind::KwBegin]
        );
    }
}
