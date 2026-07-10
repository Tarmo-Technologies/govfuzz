// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use ada_parser::ast::AdaStandard;
use ada_parser::lexer::{lex, Token, TokenKind};

#[derive(Debug, Clone, Copy)]
pub struct SymbolicSeedSource<'a> {
    pub path: &'a str,
    pub contents: &'a str,
}

impl<'a> SymbolicSeedSource<'a> {
    pub fn new(path: &'a str, contents: &'a str) -> Self {
        Self { path, contents }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicSeed {
    pub bytes: Vec<u8>,
    pub kind: SymbolicSeedKind,
    pub provenance: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolicSeedKind {
    GuardedStringLiteral,
}

pub fn generate_symbolic_seeds<'a, I>(sources: I) -> Vec<SymbolicSeed>
where
    I: IntoIterator<Item = SymbolicSeedSource<'a>>,
{
    let mut seen = BTreeSet::<Vec<u8>>::new();
    let mut seeds = Vec::new();

    for source in sources {
        let tokens = lex(source.contents, AdaStandard::Ada2022);
        for token in guarded_string_literals(&tokens) {
            let TokenKind::StringLiteral(value) = &token.kind else {
                continue;
            };
            let bytes = value.as_bytes().to_vec();
            if bytes.is_empty() || !seen.insert(bytes.clone()) {
                continue;
            }

            seeds.push(SymbolicSeed {
                bytes,
                kind: SymbolicSeedKind::GuardedStringLiteral,
                provenance: format!("{}:{}:{}", source.path, token.line, token.col),
            });
        }
    }

    seeds
}

fn guarded_string_literals(tokens: &[Token]) -> Vec<&Token> {
    let mut literals = Vec::new();
    let mut guard_depth = 0_usize;

    for token in tokens {
        match &token.kind {
            TokenKind::KwIf | TokenKind::KwElsif | TokenKind::KwWhen | TokenKind::KwCase => {
                guard_depth = guard_depth.saturating_add(1);
            }
            TokenKind::KwThen | TokenKind::Arrow => {
                guard_depth = guard_depth.saturating_sub(1);
            }
            TokenKind::StringLiteral(_) if guard_depth > 0 => literals.push(token),
            _ => {}
        }
    }

    literals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_string_literal_becomes_seed_bytes() {
        let source = r#"
procedure Guarded (Input : String) is
begin
   if Input = "match" then
      raise Constraint_Error;
   end if;
end Guarded;
"#;

        let seeds = generate_symbolic_seeds([SymbolicSeedSource::new("guarded.adb", source)]);

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].bytes, b"match");
        assert_eq!(seeds[0].kind, SymbolicSeedKind::GuardedStringLiteral);
        assert!(seeds[0].provenance.contains("guarded.adb"));
    }

    #[test]
    fn duplicate_guard_literals_are_deduplicated_stably() {
        let source = r#"
procedure Guarded (Input : String) is
begin
   if Input = "match" then null; end if;
   if Input = "match" then null; end if;
   if Input = "mismatch" then null; end if;
end Guarded;
"#;

        let seeds = generate_symbolic_seeds([SymbolicSeedSource::new("guarded.adb", source)]);

        assert_eq!(
            seeds
                .iter()
                .map(|seed| seed.bytes.as_slice())
                .collect::<Vec<_>>(),
            vec![b"match".as_slice(), b"mismatch".as_slice()]
        );
    }
}
