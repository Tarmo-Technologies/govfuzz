// SPDX-License-Identifier: Apache-2.0

//! IDL string and character literal decoding.
//!
//! The lexer keeps literals as raw source text, quotes and backslashes included.
//! Anything that wants the *value* — the Ada emitter, a fuzzing dictionary, a
//! `#pragma prefix` — has to translate the escape sequences of OMG IDL 4.2
//! §7.2.6.2 first. Copying the lexeme through instead produced `n` for `\n` and
//! emitted `'\n'` verbatim into generated Ada, which GNAT rejects.

/// The body of a string / character literal, without its delimiting quotes.
/// Text that is not a quoted literal is returned unchanged.
pub(crate) fn literal_body(text: &str) -> &str {
    let mut chars = text.chars();
    let Some(quote) = chars.next() else {
        return text;
    };
    if (quote != '"' && quote != '\'') || text.len() < 2 || !text.ends_with(quote) {
        return text;
    }
    &text[quote.len_utf8()..text.len() - quote.len_utf8()]
}

/// Decode a quoted IDL literal into the value it denotes.
pub(crate) fn decode_idl_literal(text: &str) -> String {
    decode_idl_literal_body(literal_body(text))
}

/// Decode the escape sequences in an already-unquoted literal body.
pub(crate) fn decode_idl_literal_body(body: &str) -> String {
    let mut decoded = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let Some(escape) = chars.next() else {
            // A trailing backslash is not an escape; keep it verbatim.
            decoded.push('\\');
            break;
        };
        match escape {
            'n' => decoded.push('\n'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{0b}'),
            'b' => decoded.push('\u{08}'),
            'r' => decoded.push('\r'),
            'f' => decoded.push('\u{0c}'),
            'a' => decoded.push('\u{07}'),
            '\\' | '?' | '\'' | '"' => decoded.push(escape),
            'x' => push_radix_escape(&mut decoded, &mut chars, 16, 2, escape),
            'u' => push_radix_escape(&mut decoded, &mut chars, 16, 4, escape),
            '0'..='7' => {
                // Octal escapes are 1-3 digits and include the one just read.
                let mut value = escape.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(8)) else {
                        break;
                    };
                    value = value * 8 + digit;
                    chars.next();
                }
                push_code_point(&mut decoded, value);
            }
            // IDL leaves other escapes undefined; keep the escaped character.
            _ => decoded.push(escape),
        }
    }
    decoded
}

fn push_radix_escape(
    decoded: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max_digits: usize,
    escape: char,
) {
    let mut value = 0_u32;
    let mut digits = 0_usize;
    while digits < max_digits {
        let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(radix)) else {
            break;
        };
        value = value * radix + digit;
        digits += 1;
        chars.next();
    }
    if digits == 0 {
        // `\x` with no hex digit is malformed; keep it readable.
        decoded.push(escape);
        return;
    }
    push_code_point(decoded, value);
}

fn push_code_point(decoded: &mut String, value: u32) {
    match char::from_u32(value) {
        Some(ch) => decoded.push(ch),
        // Lone surrogates have no `char`; keep the value visible as replacement.
        None => decoded.push('\u{fffd}'),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_idl_literal, literal_body};

    #[test]
    fn decodes_the_idl_escape_set() {
        assert_eq!(decode_idl_literal(r#""a\nb""#), "a\nb");
        assert_eq!(decode_idl_literal(r#""a\tb\rc""#), "a\tb\rc");
        assert_eq!(decode_idl_literal(r#""C:\\tmp""#), "C:\\tmp");
        assert_eq!(decode_idl_literal(r#""say \"hi\"""#), "say \"hi\"");
        assert_eq!(decode_idl_literal(r"'\''"), "'");
        assert_eq!(decode_idl_literal(r"'\0'"), "\0");
        assert_eq!(decode_idl_literal(r"'\101'"), "A");
        assert_eq!(decode_idl_literal(r"'\x41'"), "A");
        assert_eq!(decode_idl_literal(r#""\u0041""#), "A");
        assert_eq!(
            decode_idl_literal(r#""\a\b\f\v""#),
            "\u{07}\u{08}\u{0c}\u{0b}"
        );
    }

    #[test]
    fn octal_and_hex_escapes_stop_at_their_digit_limit() {
        // `\1011` is the character 'A' followed by a literal '1'.
        assert_eq!(decode_idl_literal(r"'\1011'"), "A1");
        // `\x41F` is 'A' followed by 'F' — hex escapes take at most two digits.
        assert_eq!(decode_idl_literal(r"'\x41F'"), "AF");
    }

    #[test]
    fn undefined_and_malformed_escapes_keep_the_escaped_character() {
        assert_eq!(decode_idl_literal(r#""a\zb""#), "azb");
        assert_eq!(decode_idl_literal(r#""a\x""#), "ax");
        assert_eq!(decode_idl_literal(r#""a\""#), "a\\");
    }

    #[test]
    fn literal_body_strips_only_matching_quotes() {
        assert_eq!(literal_body("\"abc\""), "abc");
        assert_eq!(literal_body("'a'"), "a");
        assert_eq!(literal_body("abc"), "abc");
        assert_eq!(literal_body("\""), "\"");
    }
}
