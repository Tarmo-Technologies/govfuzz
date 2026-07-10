// SPDX-License-Identifier: Apache-2.0

//! Ranking for the native Perl fuzzing lane (M3.2).
//!
//! Perl subs have no declared parameter types (they unpack `@_`), so every public
//! sub is a potential string sink. Ranking leans entirely on the sub NAME
//! (parse/decode/load) and structure: private (`_name`) and special subs
//! (`new`/`BEGIN`/`AUTOLOAD`/...) are dropped; function-style subs outrank OO
//! methods (which need a blessed receiver the build module constructs via `new`).

use crate::InputReachability;
use perl_parser::PerlSub;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerlTarget {
    /// Fully-qualified `Package::sub`.
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: PerlScoreBreakdown,
    pub input_reachability: InputReachability,
    /// Function-style sub (not an OO method) — callable without a receiver.
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct PerlScoreBreakdown {
    /// Name marks a parse/decode/read/load/deserialize entry point.
    pub parser_name: i32,
    /// Base: every public sub takes string `@_` — a potential input sink.
    pub string_sink: i32,
    /// Function-style sub (no `$self`) — no receiver to construct.
    pub callable_without_receiver: i32,
    /// Penalty: an OO method needing a blessed receiver.
    pub needs_receiver: i32,
    /// Penalty for a getter / writer / accessor name.
    pub getter_or_writer_name: i32,
    pub total: i32,
}

/// Subs that are never useful direct fuzz targets (constructors, lifecycle hooks,
/// magic methods) regardless of name.
fn is_special(name: &str) -> bool {
    matches!(
        name,
        "new"
            | "BEGIN"
            | "END"
            | "INIT"
            | "CHECK"
            | "DESTROY"
            | "AUTOLOAD"
            | "import"
            | "unimport"
            | "clone"
    )
}

/// Rank public subs, dropping private/special. Sorted by score desc, then name/line.
pub fn rank_perl_targets(subs: &[PerlSub]) -> Vec<PerlTarget> {
    let mut targets: Vec<PerlTarget> = subs
        .iter()
        .filter(|s| !s.is_private && !is_special(&s.name))
        .map(|s| {
            let breakdown = score(s);
            PerlTarget {
                name: s.qualified(),
                line: s.line,
                score: breakdown.total,
                breakdown,
                // Perl subs take string args — an attacker-controlled channel.
                input_reachability: InputReachability::AttackerReachable,
                is_static: !s.is_method,
            }
        })
        .collect();
    targets.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.line.cmp(&b.line))
    });
    targets
}

fn name_is_parser(lower: &str) -> bool {
    const KW: &[&str] = &[
        "parse",
        "decode",
        "read",
        "load",
        "deserialize",
        "unmarshal",
        "from_",
        "scan",
        "lex",
        "tokenize",
        "unpack",
        "process",
        "handle",
        "convert",
        "expand",
        "split",
        "extract",
    ];
    KW.iter().any(|k| lower.contains(k))
}

fn name_is_getter_or_writer(lower: &str) -> bool {
    lower.starts_with("get_")
        || lower.starts_with("set_")
        || lower.starts_with("is_")
        || lower.starts_with("to_")
        || lower.starts_with("write")
        || lower.starts_with("print")
        || lower.starts_with("encode")
        || lower.starts_with("dump")
}

fn score(s: &PerlSub) -> PerlScoreBreakdown {
    let mut b = PerlScoreBreakdown::default();
    let lower = s.name.to_ascii_lowercase();
    b.string_sink = 10;
    if name_is_parser(&lower) {
        b.parser_name = 25;
    }
    if s.is_method {
        b.needs_receiver = -10;
    } else {
        b.callable_without_receiver = 8;
    }
    if name_is_getter_or_writer(&lower) {
        b.getter_or_writer_name = -20;
    }
    b.total = b.parser_name
        + b.string_sink
        + b.callable_without_receiver
        + b.needs_receiver
        + b.getter_or_writer_name;
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use perl_parser::parse_perl_subs;

    fn rank(src: &str) -> Vec<PerlTarget> {
        rank_perl_targets(&parse_perl_subs(src).unwrap())
    }

    #[test]
    fn parser_named_function_outranks_method_and_drops_private_and_new() {
        let t = rank(
            "package P;\nsub new { my $class = shift; bless {}, $class }\nsub parse_doc { my $s = shift; $s }\nsub get_thing { my ($self)=@_; 1 }\nsub _helper { 1 }\n1;\n",
        );
        let names: Vec<&str> = t.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"P::parse_doc"));
        assert!(!names.iter().any(|n| n.ends_with("::new")), "new dropped");
        assert!(
            !names.iter().any(|n| n.ends_with("_helper")),
            "private dropped"
        );
        // parse_doc (function, parser name) outranks get_thing (method, getter).
        assert_eq!(t[0].name, "P::parse_doc");
        assert!(t[0].is_static);
        assert_eq!(
            t[0].input_reachability,
            InputReachability::AttackerReachable
        );
    }
}
