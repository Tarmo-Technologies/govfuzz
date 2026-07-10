// SPDX-License-Identifier: Apache-2.0

//! Ranking for the native Python fuzzing lane (M3.1).
//!
//! Python is dynamically typed, so (like the C ranker leaning on `const char *`
//! and naming) this scores on parameter *names* and optional annotations
//! (`bytes`/`str`/`data`/`buf`/`payload`) plus the classic parse/decode/load name
//! signal. Private (`_name`), dunder, and `@property` functions are dropped;
//! module-level `def`s and `@staticmethod`s outrank instance methods (which need a
//! constructible receiver the harness resolves later).

use crate::InputReachability;
use python_parser::PyFunction;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PythonTarget {
    /// Qualified within the module: `Class.method` or `func`.
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: PythonScoreBreakdown,
    pub input_reachability: InputReachability,
    /// Callable without constructing a receiver (module-level `def`,
    /// `@staticmethod`, or `@classmethod`). Carried so discovery can prefer these.
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct PythonScoreBreakdown {
    /// A `bytes`/`bytearray`/`memoryview`/`str` annotation, or a param NAME that
    /// reads like an input channel (`data`/`buf`/`payload`/`input`/`text`/`raw`).
    pub byte_channel_param: i32,
    /// Name marks a parse/decode/read/load(s)/deserialize/from_*/unmarshal entry.
    pub parser_name: i32,
    /// 1..=3 decodable params is the harnessable sweet spot.
    pub arity_in_sweet_spot: i32,
    /// Module-level `def` / `@staticmethod` / `@classmethod` — no receiver to build.
    pub callable_without_receiver: i32,
    /// Penalty: an instance method needing a constructed receiver.
    pub needs_receiver: i32,
    /// Penalty for a getter / `__repr__` / writer / setter name.
    pub getter_or_writer_name: i32,
    /// Penalty when there is no attacker-controlled channel at all.
    pub no_byte_channel: i32,
    pub total: i32,
}

/// Rank the public functions in `functions`, dropping private/dunder/property.
/// Sorted by score desc, ties by name then line.
pub fn rank_python_targets(functions: &[PyFunction]) -> Vec<PythonTarget> {
    let mut targets: Vec<PythonTarget> = functions
        .iter()
        .filter(|f| is_rankable(f))
        .map(|f| {
            let (breakdown, reach) = score(f);
            PythonTarget {
                name: f.qualified(),
                line: f.line,
                score: breakdown.total,
                breakdown,
                input_reachability: reach,
                is_static: callable_without_receiver(f),
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

/// A function is rankable if it is part of the callable public API:
/// not private (`_x`), not a dunder, not a `@property` accessor. A module-level
/// `__init__` would already be filtered as dunder; class constructors are reached
/// via the receiver-resolution path in the build module, not ranked directly.
fn is_rankable(f: &PyFunction) -> bool {
    !f.is_private && !f.is_dunder && !f.is_property
}

fn callable_without_receiver(f: &PyFunction) -> bool {
    !f.is_method || f.is_staticmethod || f.is_classmethod
}

/// Decodable params = positional, non-varargs params (the harness fills these from
/// fuzz bytes). A `@classmethod`'s `cls` is already dropped by the parser.
fn decodable_params(f: &PyFunction) -> usize {
    f.params.iter().filter(|p| !p.is_varargs).count()
}

const BYTE_ANNOTATIONS: &[&str] = &[
    "bytes",
    "bytearray",
    "memoryview",
    "str",
    "bytes | None",
    "Optional[bytes]",
    "io.BytesIO",
    "BytesIO",
];

const INPUT_NAMES: &[&str] = &[
    "data", "buf", "buffer", "payload", "input", "inp", "text", "content", "raw", "blob", "body",
    "src", "source", "stream", "s", "b", "string", "msg", "message", "bytes_", "value", "val",
    "line", "chunk", "token",
];

fn is_byte_channel(p: &python_parser::PyParam) -> bool {
    if let Some(ann) = &p.annotation {
        let a = ann.trim();
        if BYTE_ANNOTATIONS.iter().any(|t| a == *t || a.starts_with(t)) {
            return true;
        }
    }
    let n = p.name.to_ascii_lowercase();
    INPUT_NAMES.contains(&n.as_str())
}

fn name_is_parser(lower: &str) -> bool {
    const KW: &[&str] = &[
        "parse",
        "decode",
        "loads",
        "load",
        "read",
        "deserialize",
        "unmarshal",
        "from_",
        "scan",
        "tokenize",
        "lex",
        "unpack",
        "feed",
        "consume",
        "ingest",
        "process",
        "handle",
        "deserialise",
        "fromstring",
        "frombytes",
        "parse_",
    ];
    KW.iter().any(|k| lower.contains(k))
}

fn name_is_getter_or_writer(lower: &str) -> bool {
    lower.starts_with("get_")
        || lower.starts_with("is_")
        || lower.starts_with("set_")
        || lower.starts_with("to_")
        || lower.starts_with("write")
        || lower.starts_with("dump")
        || lower == "repr"
        || lower == "str"
        || lower.ends_with("_setter")
}

fn score(f: &PyFunction) -> (PythonScoreBreakdown, InputReachability) {
    let mut b = PythonScoreBreakdown::default();
    let lower = f.name.to_ascii_lowercase();

    let has_channel = f.params.iter().any(is_byte_channel);
    if has_channel {
        b.byte_channel_param = 30;
    } else {
        b.no_byte_channel = -25;
    }

    if name_is_parser(&lower) {
        b.parser_name = 25;
    }

    let arity = decodable_params(f);
    if (1..=3).contains(&arity) {
        b.arity_in_sweet_spot = 10;
    } else if arity == 0 {
        // No params to fuzz at all (a no-arg method) — not a byte sink.
        b.no_byte_channel = b.no_byte_channel.min(-25);
    }

    if callable_without_receiver(f) {
        b.callable_without_receiver = 8;
    } else {
        // Instance method: needs a receiver the build module must construct.
        b.needs_receiver = -10;
    }

    if name_is_getter_or_writer(&lower) {
        b.getter_or_writer_name = -20;
    }

    b.total = b.byte_channel_param
        + b.parser_name
        + b.arity_in_sweet_spot
        + b.callable_without_receiver
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
    use python_parser::parse_python_functions;

    fn rank(src: &str) -> Vec<PythonTarget> {
        rank_python_targets(&parse_python_functions(src).unwrap())
    }

    #[test]
    fn byte_parser_outranks_plain() {
        let t = rank("def parse(data: bytes): pass\ndef compute(n: int): pass\n");
        assert_eq!(t[0].name, "parse");
        assert!(t[0].score > t[1].score);
        assert_eq!(
            t[0].input_reachability,
            InputReachability::AttackerReachable
        );
    }

    #[test]
    fn drops_private_dunder_property() {
        let t = rank(
            "def _helper(data: bytes): pass\nclass C:\n    @property\n    def p(self): return 1\n    def __eq__(self, o): return False\n",
        );
        assert!(t.iter().all(|x| x.name != "_helper"));
        assert!(t.iter().all(|x| !x.name.ends_with(".p")));
        assert!(t.iter().all(|x| !x.name.contains("__eq__")));
    }

    #[test]
    fn module_def_outranks_instance_method_same_signature() {
        let t = rank(
            "def parse(data: bytes): pass\nclass P:\n    def parse(self, data: bytes): pass\n",
        );
        let free = t.iter().find(|x| x.name == "parse").unwrap();
        let method = t.iter().find(|x| x.name == "P.parse").unwrap();
        assert!(free.score > method.score, "free fn should outrank method");
        assert!(free.is_static && !method.is_static);
    }

    #[test]
    fn name_channel_without_annotation_counts() {
        let t = rank("def handle(payload): pass\n");
        assert_eq!(
            t[0].input_reachability,
            InputReachability::AttackerReachable
        );
    }

    #[test]
    fn staticmethod_is_callable_without_receiver() {
        let t = rank("class C:\n    @staticmethod\n    def decode(data: bytes): pass\n");
        assert!(t[0].is_static);
        assert_eq!(t[0].name, "C.decode");
    }
}
