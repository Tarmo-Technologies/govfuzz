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
    /// Penalty for registry mutators and callback/opaque inputs. These are easy to
    /// call but rarely exercise the parser/state machine an expert would target.
    pub registry_or_opaque_surface: i32,
    /// Penalty when there is no byte channel at all.
    pub no_byte_channel: i32,
    /// Bonus for a zero-argument state-machine terminal with a sibling public
    /// feeder (`SetArgs([]string)`, `SetInput([]byte)`, `Feed(string)`) on the
    /// same receiver. An expert drives the feeder from fuzz bytes and then calls
    /// the terminal; scoring the terminal in isolation otherwise hides it.
    pub stateful_byte_feeder: i32,
    pub total: i32,
}

pub fn rank_go_targets(functions: &[GoFunc]) -> Vec<GoTarget> {
    let mut targets: Vec<GoTarget> = functions
        .iter()
        .filter(|f| f.is_exported)
        .map(|f| {
            let stateful = find_stateful_byte_feeder(f, functions).is_some();
            let (breakdown, reach) = score(f, stateful);
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
    t == "[]byte"
        || t == "[]string"
        || t == "string"
        || t == "[]rune"
        || t == "io.Reader"
        || t == "io.ReadCloser"
}

fn receiver_base(func: &GoFunc) -> Option<&str> {
    func.receiver_type
        .as_deref()
        .map(str::trim)
        .map(|receiver| receiver.trim_start_matches('*').trim())
        .filter(|receiver| !receiver.is_empty())
}

/// Find the public byte-input method that prepares a zero-argument stateful
/// target on the same receiver. Kept deliberately narrow: the target must be a
/// terminal operation and the feeder must have exactly one raw-input parameter.
/// This captures command/parser state machines without guessing arbitrary method
/// sequences or fabricating callbacks.
pub fn find_stateful_byte_feeder<'a>(
    target: &GoFunc,
    functions: &'a [GoFunc],
) -> Option<&'a GoFunc> {
    if !target.is_method || !target.params.is_empty() {
        return None;
    }
    let target_name = target.name.to_ascii_lowercase();
    if ![
        "execute", "executec", "run", "process", "parse", "decode", "load",
    ]
    .contains(&target_name.as_str())
    {
        return None;
    }
    let receiver = receiver_base(target)?;
    functions.iter().find(|candidate| {
        let feeder_name = candidate.name.to_ascii_lowercase();
        candidate.is_method
            && candidate.is_exported
            && receiver_base(candidate) == Some(receiver)
            && candidate.params.len() == 1
            && is_byte_channel(&candidate.params[0].ty)
            && (feeder_name.starts_with("set")
                || feeder_name.starts_with("feed")
                || feeder_name.starts_with("input")
                || feeder_name.starts_with("push"))
    })
}

fn name_is_parser(name: &str) -> bool {
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
    crate::name_semantics::has_action_stem(name, KW)
}

fn name_is_getter_or_writer(lower: &str) -> bool {
    lower.starts_with("get")
        || lower.starts_with("set")
        || lower.starts_with("write")
        || lower.starts_with("marshal")
        || lower.starts_with("encode")
        || lower == "string"
}

fn is_registry_mutator(lower: &str) -> bool {
    lower.starts_with("add")
        || lower.starts_with("register")
        || lower.starts_with("mark")
        || lower.starts_with("bind")
        || lower.starts_with("use")
}

fn is_opaque_or_callback(ty: &str) -> bool {
    let t = ty.trim();
    t == "interface{}" || t == "any" || t.starts_with("func(") || t.starts_with("func (")
}

fn score(f: &GoFunc, stateful: bool) -> (GoScoreBreakdown, InputReachability) {
    let mut b = GoScoreBreakdown::default();
    let lower = f.name.to_ascii_lowercase();
    let has_channel = f.params.iter().any(|p| is_byte_channel(&p.ty));
    if has_channel {
        b.byte_channel_param = 30;
    } else {
        b.no_byte_channel = -25;
    }
    if name_is_parser(&f.name) {
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
    if is_registry_mutator(&lower) || f.params.iter().any(|p| is_opaque_or_callback(&p.ty)) {
        b.registry_or_opaque_surface = -25;
    }
    if stateful {
        b.stateful_byte_feeder = 105;
    }
    b.total = b.byte_channel_param
        + b.parser_name
        + b.arity_in_sweet_spot
        + b.free_function
        + b.needs_receiver
        + b.getter_or_writer_name
        + b.registry_or_opaque_surface
        + b.no_byte_channel
        + b.stateful_byte_feeder;
    let reach = if has_channel || stateful {
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

    #[test]
    fn parser_outranks_registry_setter_with_opaque_value() {
        let t = rank(
            "package p\n\
             func AddTemplateFunc(name string, tmpl interface{}) {}\n\
             func ParseCommand(line string) {}\n",
        );
        assert_eq!(t[0].name, "ParseCommand");
        let setter = t.iter().find(|x| x.name == "AddTemplateFunc").unwrap();
        assert!(t[0].score > setter.score);
        assert!(setter.breakdown.registry_or_opaque_surface < 0);
    }

    #[test]
    fn download_is_not_scored_as_a_load_parser() {
        let t = rank(
            "package p\n\
             func DownloadAudio(url string) {}\n\
             func ParseAudio(data []byte) {}\n",
        );
        assert_eq!(t[0].name, "ParseAudio");
        assert_eq!(
            t.iter()
                .find(|target| target.name == "DownloadAudio")
                .unwrap()
                .breakdown
                .parser_name,
            0
        );
    }

    #[test]
    fn stateful_execute_outranks_its_argument_feeder_and_registry_helpers() {
        let t = rank(
            "package p\n\
             type Command struct{}\n\
             func (c *Command) SetArgs(args []string) {}\n\
             func (c *Command) Execute() error { return nil }\n\
             func AddTemplateFunc(name string, value interface{}) {}\n",
        );
        assert_eq!(t[0].name, "Execute");
        assert_eq!(
            t[0].input_reachability,
            InputReachability::AttackerReachable
        );
        assert!(t[0].breakdown.stateful_byte_feeder > 0);
    }
}
