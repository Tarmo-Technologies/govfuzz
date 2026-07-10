// SPDX-License-Identifier: Apache-2.0

//! User-supplied context-free grammar for structure-aware generation — a
//! Nautilus/Grammarinator-style grammar mutator for the built-in engine.
//!
//! The 14 built-in structured mutators cover common text/binary shapes heuristically,
//! but a bespoke legacy format (a mil-STD binary message, a domain-specific config,
//! a custom wire protocol) has structure no fixed mutator knows. A grammar lets the
//! operator describe that structure once and have the engine synthesize deeply-valid
//! inputs — reaching parser code past the surface checks that reject random bytes.
//!
//! Format: a JSON object mapping each non-terminal name to a list of production
//! strings. In a production, `{NAME}` references another non-terminal and everything
//! else is literal text. The start symbol is `START` if present, else the first rule.
//! The CLI parses the JSON (this crate has no serde dependency) and hands the rules to
//! [`Grammar::from_rules`].

use std::collections::HashMap;

use crate::rng::MutationRng;

/// Hard recursion cap: expansion stops past this depth, so a self-recursive grammar
/// (`"A": ["{A}"]`) terminates with bounded stack rather than looping forever.
const MAX_DEPTH: usize = 48;
/// Near the cap, prefer productions with the fewest non-terminals so the derivation
/// collapses to terminals and yields useful output instead of being cut mid-expansion.
const COLLAPSE_MARGIN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Symbol {
    Literal(Vec<u8>),
    NonTerminal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    rules: HashMap<String, Vec<Vec<Symbol>>>,
    start: String,
}

impl Grammar {
    /// Build a grammar from `(name, productions)` rules, each production a string in
    /// the `{NAME}`-reference format. `start` selects the start symbol (defaults to
    /// `START` if present, else the first rule). Returns an error for an empty
    /// grammar, an empty rule, or a reference to an undefined non-terminal.
    pub fn from_rules(
        rules: &[(String, Vec<String>)],
        start: Option<&str>,
    ) -> Result<Self, String> {
        if rules.is_empty() {
            return Err("grammar has no rules".to_owned());
        }
        let mut parsed: HashMap<String, Vec<Vec<Symbol>>> = HashMap::new();
        for (name, productions) in rules {
            if productions.is_empty() {
                return Err(format!("grammar rule {name:?} has no productions"));
            }
            let alts = productions.iter().map(|p| parse_production(p)).collect();
            parsed.insert(name.clone(), alts);
        }
        for (name, alts) in &parsed {
            for alt in alts {
                for symbol in alt {
                    if let Symbol::NonTerminal(nt) = symbol {
                        if !parsed.contains_key(nt) {
                            return Err(format!(
                                "grammar rule {name:?} references undefined non-terminal {{{nt}}}"
                            ));
                        }
                    }
                }
            }
        }
        let start = match start {
            Some(s) if parsed.contains_key(s) => s.to_owned(),
            Some(s) => return Err(format!("start symbol {s:?} is not a defined rule")),
            None if parsed.contains_key("START") => "START".to_owned(),
            None => rules[0].0.clone(),
        };
        Ok(Self {
            rules: parsed,
            start,
        })
    }

    /// Synthesize one derivation from the start symbol into bytes, bounded by
    /// `max_len` and the recursion cap. Returns `None` if the derivation is empty
    /// (e.g. a degenerate grammar that only recurses).
    pub fn generate(&self, max_len: usize, rng: &mut MutationRng) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.expand(&self.start, 0, max_len, rng, &mut out);
        if out.is_empty() {
            return None;
        }
        out.truncate(max_len);
        Some(out)
    }

    fn expand(
        &self,
        nt: &str,
        depth: usize,
        max_len: usize,
        rng: &mut MutationRng,
        out: &mut Vec<u8>,
    ) {
        if out.len() >= max_len || depth >= MAX_DEPTH {
            return;
        }
        let Some(alts) = self.rules.get(nt) else {
            return;
        };
        // Near the depth cap, force the derivation toward terminals; otherwise pick a
        // production uniformly at random.
        let chosen = if depth + COLLAPSE_MARGIN >= MAX_DEPTH {
            alts.iter().min_by_key(|alt| nonterminal_count(alt))
        } else {
            rng.choose_index(alts.len()).and_then(|i| alts.get(i))
        };
        let Some(alt) = chosen else {
            return;
        };
        for symbol in alt {
            if out.len() >= max_len {
                return;
            }
            match symbol {
                Symbol::Literal(bytes) => out.extend_from_slice(bytes),
                Symbol::NonTerminal(child) => self.expand(child, depth + 1, max_len, rng, out),
            }
        }
    }
}

fn nonterminal_count(alt: &[Symbol]) -> usize {
    alt.iter()
        .filter(|s| matches!(s, Symbol::NonTerminal(_)))
        .count()
}

/// Split a production string into literal runs and `{NAME}` non-terminal references.
/// A `{` that does not open a valid `{IDENT}` reference is treated as a literal byte,
/// so ordinary braces in the target format survive.
fn parse_production(s: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut literal: Vec<u8> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = s[i + 1..].find('}') {
                let name = &s[i + 1..i + 1 + rel];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    if !literal.is_empty() {
                        symbols.push(Symbol::Literal(std::mem::take(&mut literal)));
                    }
                    symbols.push(Symbol::NonTerminal(name.to_owned()));
                    i += 1 + rel + 1;
                    continue;
                }
            }
        }
        literal.push(bytes[i]);
        i += 1;
    }
    if !literal.is_empty() {
        symbols.push(Symbol::Literal(literal));
    }
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(name, prods)| {
                (
                    (*name).to_owned(),
                    prods.iter().map(|p| (*p).to_owned()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn parse_production_splits_literals_and_references() {
        assert_eq!(
            parse_production("( {EXPR} )"),
            vec![
                Symbol::Literal(b"( ".to_vec()),
                Symbol::NonTerminal("EXPR".to_owned()),
                Symbol::Literal(b" )".to_vec()),
            ]
        );
        // A brace that is not a valid reference stays literal.
        assert_eq!(
            parse_production("{ raw }"),
            vec![Symbol::Literal(b"{ raw }".to_vec())]
        );
    }

    #[test]
    fn undefined_nonterminal_is_rejected() {
        let err = Grammar::from_rules(&rules(&[("START", &["{MISSING}"])]), None).unwrap_err();
        assert!(err.contains("MISSING"), "got: {err}");
    }

    #[test]
    fn generate_only_emits_grammar_terminals() {
        // A tiny arithmetic grammar: every byte produced must be one the grammar can
        // emit, so a parser for this language accepts the output.
        let g = Grammar::from_rules(
            &rules(&[
                ("START", &["{EXPR}"]),
                ("EXPR", &["{EXPR}+{TERM}", "{TERM}"]),
                ("TERM", &["1", "2", "({EXPR})"]),
            ]),
            None,
        )
        .unwrap();
        let mut rng = MutationRng::new(0xC0FFEE);
        let mut produced_nonempty = false;
        for _ in 0..64 {
            if let Some(out) = g.generate(256, &mut rng) {
                produced_nonempty = true;
                assert!(out.len() <= 256);
                assert!(
                    out.iter()
                        .all(|b| matches!(b, b'1' | b'2' | b'+' | b'(' | b')')),
                    "unexpected byte in {out:?}"
                );
            }
        }
        assert!(
            produced_nonempty,
            "grammar generated nothing across 64 draws"
        );
    }

    #[test]
    fn self_recursive_grammar_terminates() {
        // A grammar that can only recurse must not loop forever; it just yields empty.
        let g = Grammar::from_rules(&rules(&[("START", &["{START}"])]), None).unwrap();
        let mut rng = MutationRng::new(1);
        assert_eq!(g.generate(64, &mut rng), None);
    }
}
