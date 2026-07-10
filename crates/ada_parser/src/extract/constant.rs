// SPDX-License-Identifier: Apache-2.0

//! Extract named constant object declarations (`Name : constant Type [:= ...];`)
//! from package specs.
//!
//! The harness generator treats a public constant of a user-named type as a
//! parameterless "constructor": for a private type with no synthesisable
//! constructor function (zip-ada `Time`, whose only function `Get_Time` requires
//! a stream), such a constant — `default_time : constant Time;` — is the only
//! externally usable value of the type. This is the same idiom as
//! `Null_Unbounded_String` / `No_Element` / `Empty_Map`.

use crate::ast::{ConstantDecl, Span, Visibility};
use crate::extract::scope::{ScopeKind, ScopeTree};
use crate::extract::type_decl::{token_range_for_span, TypeOwnerIndex};
use crate::lexer::{Token, TokenKind};

/// Collect public and private named constants declared in package specs. Only
/// `Visibility::Public` constants are externally usable; the private ones are
/// recorded with `Visibility::Private` so consumers can distinguish them.
pub fn extract_constants(
    scope_tree: &ScopeTree,
    source: &str,
    tokens: &[Token],
) -> Vec<ConstantDecl> {
    let mut constants = Vec::new();
    let owner_index = TypeOwnerIndex::new(scope_tree);

    for (scope_index, scope) in scope_tree.scopes.iter().enumerate() {
        // Only a package spec exposes externally-usable constants; constants in a
        // body or subprogram are local and cannot back a generated harness.
        if scope.kind != ScopeKind::PackageSpec {
            continue;
        }
        let owner = owner_index.owner_for_scope(scope_index);

        if let Some(span) = scope.declarative_span {
            collect_constants_in_range(
                &mut constants,
                source,
                tokens,
                span,
                Visibility::Public,
                &owner,
            );
        }
        if let Some(span) = scope.private_declarative_span {
            collect_constants_in_range(
                &mut constants,
                source,
                tokens,
                span,
                Visibility::Private,
                &owner,
            );
        }
    }

    constants
}

fn collect_constants_in_range(
    out: &mut Vec<ConstantDecl>,
    _source: &str,
    tokens: &[Token],
    span: Span,
    visibility: Visibility,
    owner: &crate::ast::TypeOwner,
) {
    let Some((start, end)) = token_range_for_span(tokens, span.start_byte, span.end_byte) else {
        return;
    };

    let mut index = start;
    while index < end {
        if tokens[index].effective_kind != TokenKind::KwConstant {
            index = index.saturating_add(1);
            continue;
        }

        // An object-declaration constant is `Name[, Name]* : [aliased] constant
        // ...`. The `constant` keyword is therefore immediately preceded by the
        // colon (optionally `aliased`). Anything else — `access constant T`,
        // `function ... return access constant T` — is not an object decl.
        if let Some((names, colon_index)) = object_names_before_colon(tokens, index, start) {
            let type_name = type_mark_after_constant(tokens, index, end);
            // Skip named-number constants (`Pi : constant := 3.14;`) and
            // anonymous-array constants — there is no named type to synthesise.
            if !type_name.is_empty() {
                let name_token = &tokens[colon_index.saturating_sub(names.len())];
                let decl_span = Span::new(
                    name_token.text_span.start,
                    tokens[index].text_span.end,
                    name_token.line,
                    name_token.col,
                );
                for name in names {
                    out.push(ConstantDecl {
                        name,
                        type_name: type_name.clone(),
                        owner: owner.clone(),
                        visibility: visibility.clone(),
                        span: decl_span,
                    });
                }
            }
        }
        index = index.saturating_add(1);
    }
}

/// Walk backward from the `constant` keyword to collect the object names that
/// precede the colon. Returns the names in declaration order and the colon's
/// token index, or `None` when the `constant` is not part of an object decl.
fn object_names_before_colon(
    tokens: &[Token],
    constant_index: usize,
    range_start: usize,
) -> Option<(Vec<String>, usize)> {
    let prev = constant_index.checked_sub(1)?;
    let colon_index = match tokens.get(prev)?.effective_kind {
        TokenKind::Colon => prev,
        TokenKind::KwAliased => {
            let candidate = prev.checked_sub(1)?;
            if tokens.get(candidate)?.effective_kind == TokenKind::Colon {
                candidate
            } else {
                return None;
            }
        }
        _ => return None,
    };

    let mut names = Vec::new();
    let mut index = colon_index;
    while index > range_start {
        index -= 1;
        match &tokens[index].effective_kind {
            TokenKind::Identifier(name) => names.push(name.clone()),
            TokenKind::Comma => {}
            _ => break,
        }
    }
    names.reverse();
    if names.is_empty() {
        None
    } else {
        Some((names, colon_index))
    }
}

/// Read the type-mark dotted name following the `constant` keyword. Empty when
/// no type mark is present (named-number or anonymous-array constant).
fn type_mark_after_constant(tokens: &[Token], constant_index: usize, range_end: usize) -> String {
    let mut index = constant_index.saturating_add(1);
    if tokens
        .get(index)
        .is_some_and(|token| token.effective_kind == TokenKind::KwAliased)
    {
        index = index.saturating_add(1);
    }

    let mut parts = Vec::new();
    while index < range_end {
        let Some(TokenKind::Identifier(name)) =
            tokens.get(index).map(|token| &token.effective_kind)
        else {
            break;
        };
        parts.push(name.clone());

        let dot = index.saturating_add(1);
        let after_dot = index.saturating_add(2);
        let dotted = tokens
            .get(dot)
            .is_some_and(|token| token.effective_kind == TokenKind::Dot)
            && matches!(
                tokens.get(after_dot).map(|token| &token.effective_kind),
                Some(TokenKind::Identifier(_))
            );
        if dotted {
            index = after_dot;
        } else {
            break;
        }
    }

    parts.join(".")
}

#[cfg(test)]
mod tests {
    use super::extract_constants;
    use crate::ast::{AdaStandard, Visibility};
    use crate::extract::build_scope_tree;
    use crate::lexer::{lex, Token, TokenKind};

    fn tokens(source: &str) -> Vec<Token> {
        lex(source, AdaStandard::Ada2022)
            .into_iter()
            .filter(|token| !matches!(token.effective_kind, TokenKind::Comment(_)))
            .collect()
    }

    fn run(source: &str) -> Vec<crate::ast::ConstantDecl> {
        let toks = tokens(source);
        let scope_tree = build_scope_tree(&toks);
        extract_constants(&scope_tree, source, &toks)
    }

    #[test]
    fn finds_public_deferred_constant_of_private_type() {
        // zip-ada Zip_Streams: the deferred constant in the visible part is the
        // externally usable Time value.
        let source = "package Zip_Streams is\n\
                      type Time is private;\n\
                      default_time : constant Time;\n\
                      private\n\
                      type Time is new Integer;\n\
                      default_time : constant Time := 16789;\n\
                      end Zip_Streams;";

        let constants = run(source);

        let public: Vec<_> = constants
            .iter()
            .filter(|c| c.visibility == Visibility::Public)
            .collect();
        assert_eq!(public.len(), 1, "constants: {constants:?}");
        assert_eq!(public[0].name, "default_time");
        assert_eq!(public[0].type_name.to_ascii_lowercase(), "time");
    }

    #[test]
    fn private_part_constant_is_marked_private() {
        let source = "package P is\n\
                      type T is private;\n\
                      private\n\
                      Hidden : constant T := 0;\n\
                      end P;";

        let constants = run(source);

        assert!(constants
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case("hidden") && c.visibility == Visibility::Private));
    }

    #[test]
    fn captures_qualified_type_mark() {
        let source = "package Zip is\n\
                      stamp : constant Zip_Streams.Time;\n\
                      end Zip;";

        let constants = run(source);

        assert_eq!(constants.len(), 1);
        assert_eq!(
            constants[0].type_name.to_ascii_lowercase(),
            "zip_streams.time"
        );
    }

    #[test]
    fn ignores_named_number_constant() {
        let source = "package P is\n\
                      Pi : constant := 3.14159;\n\
                      end P;";

        assert!(run(source).is_empty());
    }

    #[test]
    fn ignores_access_to_constant_type_decl() {
        // `access constant T` is not an object declaration.
        let source = "package P is\n\
                      type Handle is access constant Integer;\n\
                      end P;";

        assert!(run(source).is_empty());
    }

    #[test]
    fn captures_multiple_names_in_one_declaration() {
        let source = "package P is\n\
                      type T is private;\n\
                      special_1, special_2 : constant T;\n\
                      private\n\
                      type T is new Integer;\n\
                      end P;";

        let constants = run(source);

        let public: Vec<_> = constants
            .iter()
            .filter(|c| c.visibility == Visibility::Public)
            .map(|c| c.name.to_ascii_lowercase())
            .collect();
        assert_eq!(public, vec!["special_1", "special_2"]);
    }
}
