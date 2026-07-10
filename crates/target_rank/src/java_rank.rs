// SPDX-License-Identifier: Apache-2.0
//
// Heuristic ranker for Java discovery targets (M2.1).
//
// Like the C/C++/Rust rankers this reasons over the method signature and name
// only. The Java threat model shifts the emphasis: the highest-value Java
// vulnerabilities are *logical sinks* — unsafe deserialization (`readObject`,
// `readValue`, `unmarshal`), XML external entities (`parse`/`newDocumentBuilder`),
// expression/script evaluation (`eval`, `compile`), and reflective loading
// (`Class.forName`, `loadClass`) — fed attacker bytes/strings. So beyond the
// generic byte-channel + parser-name signals, a **security-sink** name earns a
// strong bonus. Per the strategy reference §3a:
//
// - An existing `fuzzerTestOneInput` (Jazzer) entry ranks TOP — already a harness.
// - A `byte[]` / `String` / `ByteBuffer` / `InputStream` / `Reader` parameter is
//   an attacker byte channel -> `InputReachability::AttackerReachable` + a bonus.
// - A security-sink name (deserialize/readObject/unmarshal/eval/exec/load/parse)
//   earns the dominant non-harness bonus — this is the Java attack surface.
// - parse/read/decode/load/from* names -> parser bonus.
// - A `static` method is preferred (callable as `Class.method(..)` with no
//   receiver); a constructor is callable via `new`. Instance methods rank lower
//   (they need a constructed receiver — deferred to the harness lane).
// - getter / `toString` / writer names are penalized.
// - Only `public` methods are ranked; `protected`/package/`private` are dropped
//   (a harness in another package can't reach them). `abstract` methods are
//   dropped (no body — not callable without an implementation).

use crate::InputReachability;
use java_parser::{JavaMethod, JavaVisibility};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JavaTarget {
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: JavaScoreBreakdown,
    /// Whether the fuzzed parameters constitute an attacker-controlled input
    /// channel — drives honest reporting, same as the other lanes.
    pub input_reachability: InputReachability,
    /// `static` carried through so discovery can populate the `Candidate` (and the
    /// harness lane knows it can call `Class.method(..)` without a receiver).
    pub is_static: bool,
    /// A constructor (callable via `new Class(..)`).
    pub is_constructor: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct JavaScoreBreakdown {
    /// Top bonus: an existing Jazzer `fuzzerTestOneInput` entry point.
    pub existing_fuzz_entry: i32,
    /// A `byte[]` / `String` / `ByteBuffer` / `InputStream` / `Reader` byte-channel
    /// parameter (the attacker source).
    pub byte_channel_param: i32,
    /// Name marks a security sink (deserialize/readObject/unmarshal/eval/exec/load).
    pub security_sink_name: i32,
    /// Name marks a parse/decode/read/load/from entry point.
    pub parser_name: i32,
    /// A byte-channel target that DECLARES a checked exception (`throws`) — the
    /// Java idiom for "validates/parses input and rejects bad input", so a
    /// `JSONObject(String) throws JSONException` outranks a same-shape config ctor.
    pub throwing_parser: i32,
    /// `static` (no receiver) or a constructor — directly callable.
    pub directly_callable: i32,
    /// Penalty for a getter / `toString` / writer name (not the attack surface).
    pub getter_or_writer_name: i32,
    /// Penalty when there is no attacker-controlled byte channel at all.
    pub no_byte_channel: i32,
    /// 1..=4 params is the harnessable sweet spot.
    pub arity_in_sweet_spot: i32,
    /// Penalty for constructing a Throwable subclass (`*Exception` / `*Error` ctor,
    /// e.g. commons-codec `new DecoderException(String)`): an exception type has no
    /// fuzzable processing, so it shouldn't consume a `--max-targets` slot.
    pub exception_type_ctor: i32,
    pub total: i32,
}

/// Rank the `public`, non-`abstract` methods/constructors in `methods`, dropping
/// the rest. Returns targets sorted by score descending, ties broken by name then
/// line.
pub fn rank_java_targets(methods: &[JavaMethod]) -> Vec<JavaTarget> {
    let mut targets: Vec<JavaTarget> = methods
        .iter()
        .filter(|m| is_rankable(m))
        .map(|m| {
            let (breakdown, input_reachability) = score_java_method(m);
            JavaTarget {
                name: m.name.clone(),
                line: m.line,
                score: breakdown.total,
                breakdown,
                input_reachability,
                is_static: m.is_static,
                is_constructor: m.is_constructor,
            }
        })
        .collect();
    sort_targets(&mut targets);
    targets
}

/// Only `public`, concrete (non-`abstract`) methods/constructors whose ENCLOSING
/// type chain is also reachable are callable from a generated harness in another
/// package. A `public` method of a package-private top-level class (jsoup
/// `Re2jRegex`) is referenced by FQN from the harness's own package and javac
/// rejects it — `enclosing_public` gates that out (#34).
fn is_rankable(m: &JavaMethod) -> bool {
    matches!(m.visibility, JavaVisibility::Public) && !m.is_abstract && m.enclosing_public
}

fn sort_targets(targets: &mut [JavaTarget]) {
    targets.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.line.cmp(&right.line))
    });
}

fn score_java_method(m: &JavaMethod) -> (JavaScoreBreakdown, InputReachability) {
    let mut b = JavaScoreBreakdown::default();
    let lower = m.name.to_ascii_lowercase();

    // An existing fuzzerTestOneInput harness is the highest-value discovery.
    if m.is_fuzz_entry {
        b.existing_fuzz_entry = 100;
    }

    let has_byte_channel = m.params.iter().any(|p| is_byte_channel_type(&p.ty));
    if has_byte_channel {
        b.byte_channel_param = 30;
    }

    if name_is_security_sink(&lower) {
        b.security_sink_name = 25;
    }

    if name_has_parser_keyword(&lower) {
        b.parser_name = 15;
    }

    if m.is_static || m.is_constructor {
        b.directly_callable = 10;
    }

    // A byte-channel target that declares a checked exception parses/validates its
    // input (the Java contract: throw on malformed input). This surfaces real
    // parser entry points whose NAME isn't a keyword — `JSONObject(String) throws
    // JSONException`, `Foo(byte[]) throws IOException` — above same-shape configs.
    if has_byte_channel && !m.throws.is_empty() {
        b.throwing_parser = 8;
    }

    if name_is_getter_or_writer(&lower) {
        b.getter_or_writer_name = -20;
    }

    let reachability = classify_java_reachability(m, has_byte_channel);
    if !has_byte_channel && !m.is_fuzz_entry {
        b.no_byte_channel = -20;
    }

    let arity = m.params.len();
    if (1..=4).contains(&arity) {
        b.arity_in_sweet_spot = 5;
    }

    // Constructing a Throwable subclass exercises no library logic — demote so an
    // exception type's ctor (`new DecoderException(String)`) doesn't consume a
    // budget slot ahead of real decoders. A ctor's name is its class name.
    if m.is_constructor && name_is_throwable_type(&m.name) {
        b.exception_type_ctor = -40;
    }

    b.total = b.existing_fuzz_entry
        + b.byte_channel_param
        + b.security_sink_name
        + b.parser_name
        + b.throwing_parser
        + b.directly_callable
        + b.getter_or_writer_name
        + b.no_byte_channel
        + b.arity_in_sweet_spot
        + b.exception_type_ctor;
    (b, reachability)
}

/// True when a type name reads like a Throwable subclass (`*Exception`, `*Error`,
/// or `Throwable` itself) — constructing one has no fuzzable processing.
fn name_is_throwable_type(name: &str) -> bool {
    name.ends_with("Exception") || name.ends_with("Error") || name == "Throwable"
}

/// Verdict on whether fuzzing this method exercises an attacker-controlled channel.
fn classify_java_reachability(m: &JavaMethod, has_byte_channel: bool) -> InputReachability {
    if m.is_fuzz_entry || has_byte_channel {
        return InputReachability::AttackerReachable;
    }
    let lower = m.name.to_ascii_lowercase();
    if name_is_writer(&lower) {
        return InputReachability::OutputSerializer;
    }
    InputReachability::ReachabilityUnproven
}

/// A parameter type that hands the method attacker-controlled bytes: a byte array
/// (`byte[]`), a `String`/`CharSequence`, an NIO `ByteBuffer`, a stream
/// (`InputStream`), or a character `Reader`. `ty` is the collapsed type spelling
/// (possibly package-qualified, e.g. `java.io.InputStream`).
fn is_byte_channel_type(ty: &str) -> bool {
    let t = ty.replace(' ', "");
    // The simple binary channel.
    if t == "byte[]" {
        return true;
    }
    // Strings / char sequences (take the last `.`-segment so package-qualified
    // names like `java.lang.String` match).
    let leaf = t.rsplit('.').next().unwrap_or(&t);
    matches!(
        leaf,
        "String"
            | "CharSequence"
            | "ByteBuffer"
            | "InputStream"
            | "DataInputStream"
            | "Reader"
            | "InputStreamReader"
            | "BufferedReader"
            | "byte[]"
    )
}

fn name_has_parser_keyword(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "parse",
        "decode",
        "read",
        "load",
        "deserialize",
        "frombytes",
        "fromstring",
        "fromjson",
        "fromxml",
        "decompress",
        "inflate",
        "unpack",
        "scan",
        "lex",
        "tokenize",
    ];
    KEYWORDS.iter().any(|kw| name.contains(kw)) || name.starts_with("from")
}

/// A Java security sink: the method name marks a classic injection/deserialization
/// surface. These earn the dominant non-harness bonus because a crash or unexpected
/// behaviour here maps to a real Java CWE (CWE-502 deserialization, CWE-611 XXE,
/// CWE-94 expression injection, CWE-470 reflective load).
fn name_is_security_sink(name: &str) -> bool {
    const SINKS: &[&str] = &[
        "deserialize",
        "readobject",
        "readvalue",
        "readexternal",
        "unmarshal",
        "fromxml",
        "parsexml",
        "eval",
        "compile",
        "execute",
        "exec",
        "invoke",
        "forname",
        "loadclass",
        "newinstance",
        "expand",
        "interpolate",
        "render",
        "template",
    ];
    SINKS.iter().any(|kw| name.contains(kw))
}

/// A getter / `toString`-ish / writer name: emits the program's own data, not the
/// attack surface.
fn name_is_getter_or_writer(name: &str) -> bool {
    name_is_writer(name)
        || name.starts_with("get")
        || name.starts_with("is")
        || name.starts_with("has")
        || name == "tostring"
        || name == "hashcode"
        || name == "equals"
        || name == "compareto"
        || name == "clone"
        || name.starts_with("set")
        || name == "size"
        || name == "length"
        || name == "name"
}

fn name_is_writer(name: &str) -> bool {
    name.starts_with("write")
        || name.starts_with("serialize")
        || name.starts_with("encode")
        || name.starts_with("emit")
        || name.starts_with("dump")
        || name.starts_with("print")
        || name.starts_with("send")
        || name.starts_with("format")
        || name.starts_with("marshal")
}

#[cfg(test)]
mod tests {
    use super::*;
    use java_parser::JavaParam;

    fn jm(name: &str, params: &[(&str, &str)]) -> JavaMethod {
        JavaMethod {
            name: name.to_owned(),
            line: 1,
            return_type: Some("Object".to_owned()),
            params: params
                .iter()
                .map(|(n, t)| JavaParam {
                    name: (*n).to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
            is_static: true,
            visibility: JavaVisibility::Public,
            enclosing_public: true,
            package: Some("com.example".to_owned()),
            class_path: vec!["C".to_owned()],
            is_constructor: false,
            is_abstract: false,
            is_fuzz_entry: false,
            throws: Vec::new(),
        }
    }

    fn by_name<'a>(t: &'a [JavaTarget], name: &str) -> &'a JavaTarget {
        t.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("{name} not ranked: {t:?}"))
    }

    #[test]
    fn exception_type_constructor_is_demoted_below_a_real_decoder() {
        // commons-codec: `new DecoderException(String)` has no fuzzable logic and
        // should rank below a real decoder taking the same byte channel.
        let mut exc = jm("DecoderException", &[("msg", "String")]);
        exc.is_constructor = true;
        let decoder = jm("decodeHex", &[("data", "byte[]")]);
        let ranked = rank_java_targets(&[exc, decoder]);
        assert_eq!(ranked[0].name, "decodeHex", "{ranked:?}");
        assert_eq!(
            by_name(&ranked, "DecoderException")
                .breakdown
                .exception_type_ctor,
            -40
        );
        // A non-constructor method merely NAMED like an exception is not demoted.
        assert_eq!(
            by_name(&ranked, "decodeHex").breakdown.exception_type_ctor,
            0
        );
    }

    #[test]
    fn non_public_and_abstract_are_dropped() {
        let mut priv_m = jm("parseSecret", &[("d", "byte[]")]);
        priv_m.visibility = JavaVisibility::Private;
        let mut prot = jm("parseProt", &[("d", "byte[]")]);
        prot.visibility = JavaVisibility::Protected;
        let mut pkg = jm("parsePkg", &[("d", "byte[]")]);
        pkg.visibility = JavaVisibility::Package;
        let mut abstr = jm("parseAbstract", &[("d", "byte[]")]);
        abstr.is_abstract = true;
        let public = jm("parsePublic", &[("d", "byte[]")]);
        let ranked = rank_java_targets(&[priv_m, prot, pkg, abstr, public]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "parsePublic");
    }

    #[test]
    fn fuzz_entry_ranks_top() {
        let mut entry = jm("fuzzerTestOneInput", &[("d", "byte[]")]);
        entry.is_fuzz_entry = true;
        let parser = jm("parse", &[("d", "byte[]")]);
        let ranked = rank_java_targets(&[parser, entry]);
        assert_eq!(ranked[0].name, "fuzzerTestOneInput");
        assert!(ranked[0].breakdown.existing_fuzz_entry > 0);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::AttackerReachable
        );
    }

    #[test]
    fn byte_array_is_attacker_reachable_and_bonused() {
        let ranked = rank_java_targets(&[jm("handle", &[("d", "byte[]")])]);
        let t = by_name(&ranked, "handle");
        assert_eq!(t.input_reachability, InputReachability::AttackerReachable);
        assert!(t.breakdown.byte_channel_param > 0);
    }

    #[test]
    fn string_and_qualified_inputstream_are_byte_channels() {
        assert!(is_byte_channel_type("String"));
        assert!(is_byte_channel_type("java.lang.String"));
        assert!(is_byte_channel_type("java.io.InputStream"));
        assert!(is_byte_channel_type("ByteBuffer"));
        assert!(!is_byte_channel_type("int"));
        assert!(!is_byte_channel_type("Foo"));
    }

    #[test]
    fn security_sink_outranks_plain_parser() {
        // A deserialization sink should rank above a same-shape plain helper.
        let sink = jm("readObject", &[("in", "java.io.InputStream")]);
        let plain = jm("process", &[("in", "java.io.InputStream")]);
        let ranked = rank_java_targets(&[plain, sink]);
        assert_eq!(ranked[0].name, "readObject");
        assert!(by_name(&ranked, "readObject").breakdown.security_sink_name > 0);
    }

    #[test]
    fn throwing_byte_channel_parser_outranks_plain_config_ctor() {
        // `JSONObject(String) throws JSONException` should outrank a same-shape
        // config constructor with no declared exception.
        let mut parser = jm("JSONObject", &[("s", "String")]);
        parser.is_static = false;
        parser.is_constructor = true;
        parser.throws = vec!["JSONException".to_owned()];
        // A config-style ctor with no declared exception (and no parser keyword in
        // its name, which would itself boost it).
        let mut config = jm("JsonConfig", &[("s", "String")]);
        config.is_static = false;
        config.is_constructor = true;
        let ranked = rank_java_targets(&[config, parser]);
        assert_eq!(ranked[0].name, "JSONObject");
        assert!(by_name(&ranked, "JSONObject").breakdown.throwing_parser > 0);
        assert_eq!(by_name(&ranked, "JsonConfig").breakdown.throwing_parser, 0);
    }

    #[test]
    fn getter_is_penalized() {
        let ranked = rank_java_targets(&[jm("getName", &[])]);
        assert!(by_name(&ranked, "getName").breakdown.getter_or_writer_name < 0);
    }

    #[test]
    fn static_and_constructor_are_directly_callable_bonused() {
        let st = jm("parse", &[("d", "byte[]")]); // static by default in jm
        let mut ctor = jm("C", &[("d", "byte[]")]);
        ctor.is_static = false;
        ctor.is_constructor = true;
        let mut instance = jm("decode", &[("d", "byte[]")]);
        instance.is_static = false;
        let ranked = rank_java_targets(&[st, ctor, instance]);
        assert!(by_name(&ranked, "parse").breakdown.directly_callable > 0);
        assert!(by_name(&ranked, "C").breakdown.directly_callable > 0);
        assert_eq!(by_name(&ranked, "decode").breakdown.directly_callable, 0);
    }
}
