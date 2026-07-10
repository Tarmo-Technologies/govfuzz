// SPDX-License-Identifier: Apache-2.0

use crate::ast::Pragma;
use crate::lexer::{Token, TokenKind};

pub fn extract_unit_pragmas(source: &str, tokens: &[Token]) -> Vec<Pragma> {
    let mut pragmas = Vec::new();
    let mut index = 0usize;
    let mut paren_depth = 0u32;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(kind) if paren_depth == 0 && is_compilation_unit_declaration_start(kind) => break,
            Some(TokenKind::LParen) => {
                paren_depth = paren_depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::RParen) => {
                paren_depth = paren_depth.saturating_sub(1);
                index = index.saturating_add(1);
            }
            Some(TokenKind::KwPragma) if paren_depth == 0 => {
                if let Some((pragma, next_index)) = parse_pragma(source, tokens, index) {
                    pragmas.push(pragma);
                    index = next_index;
                } else {
                    index = skip_to_after_semicolon(tokens, index.saturating_add(1));
                }
            }
            Some(_) => index = index.saturating_add(1),
            None => break,
        }
    }

    pragmas
}

fn is_compilation_unit_declaration_start(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::KwPackage
            | TokenKind::KwProcedure
            | TokenKind::KwFunction
            | TokenKind::KwEntry
            | TokenKind::KwTask
            | TokenKind::KwProtected
            | TokenKind::KwGeneric
    )
}

fn parse_pragma(source: &str, tokens: &[Token], index: usize) -> Option<(Pragma, usize)> {
    let name = identifier_text(tokens.get(index.saturating_add(1))?)?;
    let mut cursor = index.saturating_add(2);
    let mut args = String::new();

    if kind_at(tokens, cursor, &TokenKind::LParen) {
        let open = cursor;
        let close = find_matching_rparen_before_semicolon(tokens, open)?;
        args = source_text(source, tokens, open.saturating_add(1), close)
            .unwrap_or_default()
            .trim()
            .to_owned();
        cursor = close.saturating_add(1);
    }

    if !kind_at(tokens, cursor, &TokenKind::Semicolon) {
        return None;
    }

    Some((Pragma { name, args }, cursor.saturating_add(1)))
}

fn find_matching_rparen_before_semicolon(tokens: &[Token], open_index: usize) -> Option<usize> {
    let mut depth = 0u32;
    let mut index = open_index;

    while index < tokens.len() {
        match tokens.get(index).map(|token| &token.effective_kind) {
            Some(TokenKind::LParen) => depth = depth.saturating_add(1),
            Some(TokenKind::RParen) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            Some(TokenKind::Semicolon | TokenKind::Eof) if depth > 0 => return None,
            Some(_) => {}
            None => return None,
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
    use super::extract_unit_pragmas;
    use crate::ast::AdaStandard;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2012)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    #[test]
    fn pragma_pure_no_args() {
        let pragmas = extract_unit_pragmas("pragma Pure;", &tokens("pragma Pure;"));

        assert_eq!(pragmas.len(), 1);
        assert_eq!(pragmas[0].name, "pure");
        assert_eq!(pragmas[0].args, "");
    }

    #[test]
    fn pragma_ada_2012() {
        let source = "pragma Ada_2012;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas[0].name, "ada_2012");
    }

    #[test]
    fn pragma_with_single_arg() {
        let source = "pragma Restrictions (No_Allocators);";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas[0].name, "restrictions");
        assert_eq!(pragmas[0].args, "No_Allocators");
    }

    #[test]
    fn pragma_with_multiple_args() {
        let source = "pragma Suppress (Index_Check, On => X);";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas[0].args, "Index_Check, On => X");
    }

    #[test]
    fn multiple_unit_pragmas() {
        let source = "pragma Pure; pragma Restrictions (No_Allocators); package P is end P;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(
            pragmas.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["pure", "restrictions"]
        );
    }

    #[test]
    fn pragma_inside_parens_ignored() {
        let source = "procedure P(A : Integer with pragma Suppress(Index_Check)); pragma Pure;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert!(pragmas.is_empty());
    }

    #[test]
    fn local_pragmas_inside_subprogram_body_are_not_unit_pragmas() {
        let source = "pragma Pure;\nprocedure P is pragma Suppress (Index_Check); begin pragma Assert (Ready); end P;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas.len(), 1);
        assert_eq!(pragmas[0].name, "pure");
    }

    #[test]
    fn local_pragmas_inside_package_body_are_not_unit_pragmas() {
        let source =
            "pragma Ada_2012;\npackage body P is pragma Suppress (Index_Check); begin null; end P;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas.len(), 1);
        assert_eq!(pragmas[0].name, "ada_2012");
    }

    #[test]
    fn unit_pragmas_before_first_declaration_are_all_captured() {
        let source =
            "pragma Ada_2012; pragma Pure; pragma Restrictions (No_Allocators); package P is end P;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(
            pragmas.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["ada_2012", "pure", "restrictions"]
        );
    }

    #[test]
    fn malformed_pragma_skips_to_next_semicolon() {
        let source = "pragma Broken (No_Close; pragma Pure;";
        let pragmas = extract_unit_pragmas(source, &tokens(source));

        assert_eq!(pragmas.len(), 1);
        assert_eq!(pragmas[0].name, "pure");
    }
}
