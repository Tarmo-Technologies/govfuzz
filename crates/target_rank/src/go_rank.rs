// SPDX-License-Identifier: Apache-2.0

//! Ranking for the native Go fuzzing lane (M3.3).
//!
//! Go is statically typed, so (like C/Rust) ranking leans on the parameter TYPE:
//! a `[]byte`/`string` byte channel is the attack surface. Unexported functions
//! (lowercase) are dropped (not callable from a separate harness package);
//! exported free functions outrank methods (which need a receiver value).

use crate::InputReachability;
use go_parser::GoFunc;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GoTarget {
    /// The function name (the package is recovered by the build module from go.mod).
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: GoScoreBreakdown,
    pub input_reachability: InputReachability,
    /// Free function (not a method) — callable without a receiver value.
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct GoScoreBreakdown {
    /// A `[]byte`/`string` parameter — the byte channel.
    pub byte_channel_param: i32,
    /// Name marks a parse/decode/read/unmarshal entry point.
    pub parser_name: i32,
    /// 1..=3 params is the harnessable sweet spot.
    pub arity_in_sweet_spot: i32,
    /// Free function — no receiver to construct.
    pub free_function: i32,
    /// Penalty: a method needing a receiver value.
    pub needs_receiver: i32,
    /// Penalty for a getter / writer / String() name.
    pub getter_or_writer_name: i32,
    /// Penalty when there is no byte channel at all.
    pub no_byte_channel: i32,
    pub total: i32,
}

pub fn rank_go_targets(functions: &[GoFunc]) -> Vec<GoTarget> {
    let mut targets: Vec<GoTarget> = functions
        .iter()
        .filter(|f| f.is_exported)
        .map(|f| {
            let (breakdown, reach) = score(f);
            GoTarget {
                name: f.name.clone(),
                line: f.line,
                score: breakdown.total,
                breakdown,
                input_reachability: reach,
                is_static: !f.is_method,
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

fn is_byte_channel(ty: &str) -> bool {
    let t = ty.trim();
    t == "[]byte" || t == "string" || t == "[]rune" || t == "io.Reader" || t == "io.ReadCloser"
}

fn name_is_parser(lower: &str) -> bool {
    const KW: &[&str] = &[
        "parse",
        "decode",
        "unmarshal",
        "read",
        "load",
        "scan",
        "lex",
        "tokenize",
        "unpack",
        "from",
        "deserialize",
    ];
    KW.iter().any(|k| lower.contains(k))
}

fn name_is_getter_or_writer(lower: &str) -> bool {
    lower.starts_with("get")
        || lower.starts_with("set")
        || lower.starts_with("write")
        || lower.starts_with("marshal")
        || lower.starts_with("encode")
        || lower == "string"
}

fn score(f: &GoFunc) -> (GoScoreBreakdown, InputReachability) {
    let mut b = GoScoreBreakdown::default();
    let lower = f.name.to_ascii_lowercase();
    let has_channel = f.params.iter().any(|p| is_byte_channel(&p.ty));
    if has_channel {
        b.byte_channel_param = 30;
    } else {
        b.no_byte_channel = -25;
    }
    if name_is_parser(&lower) {
        b.parser_name = 25;
    }
    if (1..=3).contains(&f.params.len()) {
        b.arity_in_sweet_spot = 10;
    }
    if f.is_method {
        b.needs_receiver = -10;
    } else {
        b.free_function = 8;
    }
    if name_is_getter_or_writer(&lower) {
        b.getter_or_writer_name = -20;
    }
    b.total = b.byte_channel_param
        + b.parser_name
        + b.arity_in_sweet_spot
        + b.free_function
        + b.needs_receiver
        + b.getter_or_writer_name
        + b.no_byte_channel;
    let reach = if has_channel {
        InputReachability::AttackerReachable
    } else {
        InputReachability::ReachabilityUnproven
    };
    (b, reach)
}

#[cfg(test)]
mod tests {
    use super::*;
    use go_parser::parse_go_functions;

    fn rank(src: &str) -> Vec<GoTarget> {
        rank_go_targets(&parse_go_functions(src).unwrap())
    }

    #[test]
    fn byte_parser_outranks_and_drops_unexported() {
        let t = rank(
            "package p\nfunc ParseDoc(data []byte) error { return nil }\nfunc Compute(n int) int { return n }\nfunc internal(s string) {}\n",
        );
        let names: Vec<&str> = t.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"ParseDoc"));
        assert!(!names.contains(&"internal"), "unexported dropped");
        assert_eq!(t[0].name, "ParseDoc");
        assert_eq!(
            t[0].input_reachability,
            InputReachability::AttackerReachable
        );
        assert!(t[0].is_static);
    }

    #[test]
    fn free_function_outranks_method() {
        let t = rank("package p\nfunc Parse(data []byte) {}\nfunc (d *D) Parse(data []byte) {}\n");
        let free = t.iter().find(|x| x.name == "Parse" && x.is_static).unwrap();
        let method = t
            .iter()
            .find(|x| x.name == "Parse" && !x.is_static)
            .unwrap();
        assert!(free.score > method.score);
    }
}
