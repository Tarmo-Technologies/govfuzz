// SPDX-License-Identifier: Apache-2.0
//
// Heuristic ranker for Rust discovery targets (M1.1).
//
// Like the C/C++ ranker (`c_rank`), this reasons over the function signature
// and name only — Rust's type system gives us a cleaner byte-channel signal
// than C, but the philosophy is identical: rank the real attack surface (a
// parser taking attacker-controlled bytes) above getters, writers, and
// private helpers. Per the strategy reference §2a:
//
// - An existing `fuzz_target!` harness ranks TOP — it already compiles and
//   already declares fuzzing intent.
// - A `&[u8]` / `&str` / `Vec<u8>` / `String` parameter is an attacker byte
//   channel -> `InputReachability::AttackerReachable` + a buffer bonus.
// - `parse`/`read`/`load`/`decode`/`deserialize`/`from_*` name -> parser bonus.
// - `unsafe`/raw-pointer-reachable fns rank higher (real memory bugs live
//   behind `unsafe`/FFI — the deepSURF severity thesis).
// - getter / `Display` / `write`-style names are penalized.
// - Only `pub` fns are ranked; `pub(crate)`/`pub(super)` and private fns are
//   skipped (the harness is a separate crate and can only call `pub` items).

use crate::InputReachability;
use rust_parser::{RustFn, RustVisibility};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RustTarget {
    pub name: String,
    pub line: u32,
    pub score: i32,
    pub breakdown: RustScoreBreakdown,
    /// Whether the fuzzed parameters constitute an attacker-controlled input
    /// channel — drives honest reporting, same as the C/C++ lane.
    pub input_reachability: InputReachability,
    /// `is_static` (free/assoc fn) carried through so discovery can populate the
    /// `Candidate` without re-parsing.
    pub is_static: bool,
    /// `#[cfg(...)]` guard carried through for the `Candidate`.
    pub foreign_guard: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct RustScoreBreakdown {
    /// Top bonus: the fn lives inside an existing `fuzz_target!` harness.
    pub existing_fuzz_target: i32,
    /// A `&[u8]` / `&str` / `Vec<u8>` / `String` / `&[u8; N]` byte-channel param.
    pub byte_channel_param: i32,
    /// Name marks a parse/decode/read/load/deserialize/from_* entry point.
    pub parser_name: i32,
    /// `unsafe fn` or a raw-pointer (FFI) signature — memory-bug surface.
    pub unsafe_reachable: i32,
    /// Penalty for a getter / `Display` / writer name (not the attack surface).
    pub getter_or_writer_name: i32,
    /// Penalty when there is no attacker-controlled byte channel at all.
    pub no_byte_channel: i32,
    /// 1..=4 params is the harnessable sweet spot.
    pub arity_in_sweet_spot: i32,
    /// A free / associated function (no `self` receiver) is ALWAYS auto-harnessable;
    /// a `&self`/`&mut self` method may not be (it needs a constructible receiver).
    /// A modest bonus prefers free functions when scores are otherwise tied, so a
    /// crate's free parser entry points (`memchr::memchr`, `memmem::find`) out-rank
    /// same-scored methods (`Finder::count`) instead of losing the budget to them.
    pub static_free_function: i32,
    /// Penalty for a `pub trait` method whose receiver the Rust lane cannot
    /// construct: a static (associated) trait method, or an instance method whose
    /// trait is NOT a `Read`/`BufRead` reader trait (only a reader trait gets a
    /// synthesised `std::io::Cursor` receiver). Demoted so these never waste budget
    /// over a real target they would only `failed_build` against (#458/#462).
    pub unconstructable_trait_method: i32,
    pub total: i32,
}

/// Rank the `pub`/`pub(crate)` functions in `functions`, dropping private fns.
/// Returns targets sorted by score descending, ties broken by name then line.
pub fn rank_rust_targets(functions: &[RustFn]) -> Vec<RustTarget> {
    let mut targets: Vec<RustTarget> = functions
        .iter()
        .filter(|f| {
            // RC9: drop `#[cfg(test)]` fns — test helpers, not the public API, and
            // they don't exist in a normal build (they'd crowd out real targets).
            is_rankable_visibility(f.visibility) && !f.doc_hidden && !is_cfg_test(&f.foreign_guard)
        })
        .map(|f| {
            let (breakdown, input_reachability) = score_rust_function(f);
            RustTarget {
                name: f.name.clone(),
                line: f.line,
                score: breakdown.total,
                breakdown,
                input_reachability,
                is_static: f.is_static,
                foreign_guard: f.foreign_guard.clone(),
            }
        })
        .collect();
    sort_targets(&mut targets);
    targets
}

/// Only externally-reachable API is rankable. The generated harness is a SEPARATE
/// crate that path-depends on the target, so it can call ONLY `pub` items —
/// `pub(crate)` / `pub(super)` / `pub(in ...)` are crate-internal and would only
/// yield a `failed_build` ("associated function is private" / "module is private").
fn is_rankable_visibility(v: RustVisibility) -> bool {
    matches!(v, RustVisibility::Pub)
}

/// True when a `#[cfg(...)]` guard is TEST-EXCLUSIVE — the item exists ONLY under
/// `cfg(test)` and never in a normal build, so it is a test helper, not public API.
///
/// This is a structural evaluation, not a substring match: an item is test-only iff
/// `test` is REQUIRED for the cfg to hold. A bare `test` and `all(test, ...)` require
/// it; `any(feature = "alloc", test)` does NOT (the `alloc` feature satisfies it in a
/// normal build — base64's `Engine::decode`/`encode` live behind exactly this and were
/// being blacked out), nor does `not(test)` (a non-test config), nor a feature named
/// `"test"` (which earlier substring matching wrongly tripped on).
fn is_cfg_test(guard: &Option<String>) -> bool {
    let Some(cond) = guard else {
        return false;
    };
    cfg_requires_test(cond)
}

/// True when `cond` (a `#[cfg(...)]` condition spelling) can hold ONLY when `test`
/// is enabled — i.e. every satisfying configuration has `test` set.
///
/// - bare `test` -> required.
/// - `all(c1, c2, ...)` -> required if ANY conjunct requires it (all must hold).
/// - `any(c1, c2, ...)` -> required only if EVERY alternative requires it (any one
///   that does not requires gives a non-test way to satisfy the cfg).
/// - `not(...)` -> never forces `test` true (a negation can't require it).
/// - any other predicate (`feature = "x"`, `unix`, `feature = "test"`) -> not required.
fn cfg_requires_test(cond: &str) -> bool {
    let c = cond.trim();
    if let Some(inner) = cfg_combinator_inner(c, "all") {
        return cfg_split_top_level(inner)
            .iter()
            .any(|p| cfg_requires_test(p));
    }
    if let Some(inner) = cfg_combinator_inner(c, "any") {
        let parts = cfg_split_top_level(inner);
        return !parts.is_empty() && parts.iter().all(|p| cfg_requires_test(p));
    }
    if cfg_combinator_inner(c, "not").is_some() {
        return false;
    }
    c == "test"
}

/// If `c` is `kw(...)` (optionally `kw (...)`), return the inner argument text.
fn cfg_combinator_inner<'a>(c: &'a str, kw: &str) -> Option<&'a str> {
    let rest = c.strip_prefix(kw)?.trim_start();
    let inner = rest.strip_prefix('(')?.strip_suffix(')')?;
    Some(inner)
}

/// Split a cfg argument list on TOP-LEVEL commas (not inside nested `(...)`).
fn cfg_split_top_level(inner: &str) -> Vec<&str> {
    let bytes = inner.as_bytes();
    let mut depth = 0i32;
    let mut parts = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

/// True for a STATIC trait-IMPL method that the Rust build lane cannot harness — a
/// std conversion/collection trait (`From`/`Into`/`TryFrom`/`TryInto`/`FromIterator`/
/// `IntoIterator`) whose `impl` is callable only by UFCS with the trait in scope, and
/// for which there is no in-crate or prelude UFCS path. Excludes the UFCS-reachable
/// `TryFrom<&[u8]>/<&str>::try_from` (and `FromStr::from_str`, which is not in the
/// set), mirroring `rust_build::std_ufcs_trait_path`. In-crate domain traits
/// (byteorder's `ByteOrder`) are NOT in the set, so their statics keep harnessing.
fn is_demotable_std_conversion_static(f: &RustFn) -> bool {
    if !f.is_static {
        return false;
    }
    let Some(spelling) = f.impl_trait.as_deref() else {
        return false;
    };
    let leaf = spelling.rsplit("::").next().unwrap_or(spelling).trim();
    let base = leaf.split('<').next().unwrap_or(leaf).trim();
    const STD_CONVERSION_TRAITS: &[&str] = &[
        "From",
        "Into",
        "TryFrom",
        "TryInto",
        "FromIterator",
        "IntoIterator",
    ];
    if !STD_CONVERSION_TRAITS.contains(&base) {
        return false;
    }
    // `TryFrom<&[u8]>/<&str>::try_from(arg)` IS UFCS-reachable via core — keep it.
    if base == "TryFrom" && f.name == "try_from" && f.params.len() == 1 {
        let p = f.params[0].ty.replace(' ', "");
        let p = erase_lifetime(&p);
        if p == "&[u8]" || p == "&str" {
            return false;
        }
    }
    true
}

/// Lifetime-erased, whitespace-stripped borrowed-type spelling: `&'a[u8]` -> `&[u8]`.
fn erase_lifetime(compact: &str) -> String {
    if let Some(after) = compact.strip_prefix("&'") {
        // Drop the lifetime identifier after `&'` up to the next non-ident char.
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        format!("&{}", &after[end..])
    } else {
        compact.to_owned()
    }
}

/// An internal implementation-detail name (a SIMD/specialized variant like
/// `match_uri_vectored`, `*_sse`, `*_avx2`, `*_neon`, `*_simd`). These are `pub`
/// but not the API surface a user drives — they crowd out the real scalar
/// parse/entry fns, so demote them (RC9).
fn name_is_internal_impl(name: &str) -> bool {
    name.contains("_vectored")
        || name.contains("_simd")
        || name.contains("_sse")
        || name.contains("_avx")
        || name.contains("_neon")
        || name.ends_with("_fallback")
        || name.ends_with("_generic")
}

fn sort_targets(targets: &mut [RustTarget]) {
    targets.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.line.cmp(&right.line))
    });
}

fn score_rust_function(f: &RustFn) -> (RustScoreBreakdown, InputReachability) {
    let mut b = RustScoreBreakdown::default();
    let lower = f.name.to_ascii_lowercase();

    // An existing fuzz_target! harness is the highest-value discovery: it
    // compiles and declares intent. Dominant bonus so it always ranks top.
    if f.in_fuzz_target {
        b.existing_fuzz_target = 100;
    }

    // A `pub trait` method (byteorder's `ReadBytesExt::read_u32`) has no value
    // byte-channel param — its bytes flow through the SYNTHESISED reader receiver
    // (`std::io::Cursor::new(fuzz_bytes)`). Only an INSTANCE method on a reader
    // trait (`: Read`/`BufRead`) gets that receiver, so only it is harnessable.
    let reader_trait_method =
        f.is_trait_method && !f.is_static && trait_supertrait_is_reader(&f.trait_supertrait);

    let has_byte_channel =
        f.params.iter().any(|p| is_byte_channel_type(&p.ty)) || reader_trait_method;
    if has_byte_channel {
        b.byte_channel_param = 30;
    }

    // An un-constructable trait method (static, or instance without a reader
    // receiver) only ever `failed_build`s; demote it hard so it sorts below every
    // real target and never spends budget. This catches BOTH a trait-DECL method
    // (`is_trait_method`) AND a static std-conversion trait-IMPL method (`From`/
    // `Into`/`TryFrom`/... — `impl_trait` set, `is_trait_method` false) that the
    // build lane skips because it is callable only by UFCS with no reachable path.
    if (f.is_trait_method && !reader_trait_method) || is_demotable_std_conversion_static(f) {
        b.unconstructable_trait_method = -60;
    }

    if name_has_parser_keyword(&lower) {
        b.parser_name = 15;
    }

    if f.is_unsafe {
        b.unsafe_reachable = 15;
    }

    if name_is_getter_or_writer(&lower) || name_is_internal_impl(&lower) {
        b.getter_or_writer_name = -20;
    }

    // Down-rank a fn with no attacker byte channel so real parsers out-rank
    // getters/setters/scalar-only helpers. An existing fuzz_target! is exempt —
    // it declares intent regardless of its visible signature (the bytes flow in
    // through the macro, not a named param).
    let reachability = classify_rust_reachability(f, has_byte_channel);
    if !has_byte_channel && !f.in_fuzz_target {
        b.no_byte_channel = -20;
    }

    let arity = f.params.len();
    if (1..=4).contains(&arity) {
        b.arity_in_sweet_spot = 5;
    }

    // Prefer free/associated functions (always harnessable) over `&self`/`&mut
    // self` methods (which need a constructible receiver). Modest, so it only
    // breaks ties — a high-value parser method still out-ranks a free getter.
    if f.is_static {
        b.static_free_function = 8;
    }

    b.total = b.existing_fuzz_target
        + b.byte_channel_param
        + b.parser_name
        + b.unsafe_reachable
        + b.getter_or_writer_name
        + b.no_byte_channel
        + b.arity_in_sweet_spot
        + b.static_free_function
        + b.unconstructable_trait_method;
    (b, reachability)
}

/// True when a trait's supertrait bound names a `std::io::Read` / `BufRead`
/// reader (so a `pub trait`'s instance method has a constructable `std::io::Cursor`
/// receiver). Matches the bound's leaf segment, tolerating `io::Read`,
/// `std::io::Read`, a bare `Read`, and a sum bound (`Read + Seek`).
fn trait_supertrait_is_reader(supertrait: &Option<String>) -> bool {
    let Some(bound) = supertrait else {
        return false;
    };
    bound.split('+').any(|clause| {
        let leaf = clause
            .trim()
            .split('<')
            .next()
            .unwrap_or("")
            .rsplit("::")
            .next()
            .unwrap_or("")
            .trim();
        matches!(leaf, "Read" | "BufRead")
    })
}

/// Verdict on whether fuzzing this fn exercises an attacker-controlled channel.
fn classify_rust_reachability(f: &RustFn, has_byte_channel: bool) -> InputReachability {
    // An existing fuzz_target! consumes raw fuzz bytes by construction.
    if f.in_fuzz_target || has_byte_channel {
        return InputReachability::AttackerReachable;
    }
    let lower = f.name.to_ascii_lowercase();
    if name_is_writer(&lower) {
        return InputReachability::OutputSerializer;
    }
    InputReachability::ReachabilityUnproven
}

/// A parameter type that hands the function attacker-controlled bytes: a byte
/// slice / vec / array, a string slice / `String`. `ty` is the collapsed type
/// spelling from `rust_parser`.
fn is_byte_channel_type(ty: &str) -> bool {
    let t = ty.replace(' ', "");
    // Byte slices and references to them: `&[u8]`, `&mut [u8]`, `[u8]`, and a
    // fixed array `&[u8; N]`.
    if t.contains("[u8]") || t.contains("[u8;") {
        return true;
    }
    // String channels: `&str`, `String`, `&String`.
    if t == "&str" || t == "str" || t.ends_with("String") || t == "&String" {
        return true;
    }
    // Owned/borrowed byte vectors and the `bytes` crate's `Bytes`/`BytesMut`.
    if t.contains("Vec<u8>") || t.ends_with("Bytes") || t.ends_with("BytesMut") {
        return true;
    }
    // A `std::io::Read` / `impl Read` / `Cursor<&[u8]>` reader is a byte stream.
    if t.contains("Cursor<") || t.contains("implRead") || t.contains("dynRead") {
        return true;
    }
    false
}

fn name_has_parser_keyword(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "parse",
        "decode",
        "read",
        "load",
        "deserialize",
        "from_bytes",
        "from_slice",
        "from_str",
        "from_reader",
        "from_utf8",
        "from_json",
        "decompress",
        "inflate",
        "unpack",
        "scan",
        "lex",
    ];
    // `from_*` constructors are common parse entry points; catch the generic
    // shape too (`from_xml`, `from_der`).
    KEYWORDS.iter().any(|kw| name.contains(kw)) || name.starts_with("from_")
}

/// A getter / `Display`-ish / writer name: emits the program's own data, not the
/// attack surface. Mirrors the C `OutputSerializer` / getter penalty.
fn name_is_getter_or_writer(name: &str) -> bool {
    name_is_writer(name)
        || name.starts_with("get_")
        || name == "get"
        || name.starts_with("is_")
        || name.starts_with("as_")
        || name.starts_with("to_")
        || name == "fmt"
        || name == "display"
        || name.starts_with("len")
        || name == "name"
        || name == "id"
}

fn name_is_writer(name: &str) -> bool {
    name.starts_with("write")
        || name.starts_with("serialize")
        || name.starts_with("encode")
        || name.starts_with("emit")
        || name.starts_with("dump")
        || name.starts_with("print")
        || name.starts_with("send")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_parser::{RustParam, RustVisibility};

    fn rf(name: &str, params: &[(&str, &str)]) -> RustFn {
        RustFn {
            name: name.to_owned(),
            line: 1,
            return_type: None,
            params: params
                .iter()
                .map(|(n, t)| RustParam {
                    name: (*n).to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
            is_static: true,
            is_unsafe: false,
            is_unsafe_fn: false,
            visibility: RustVisibility::Pub,
            foreign_guard: None,
            in_fuzz_target: false,
            doc_hidden: false,
            has_type_generics: false,
            type_params: Vec::new(),
            impl_trait: None,
            is_trait_method: false,
            trait_supertrait: None,
        }
    }

    fn by_name<'a>(t: &'a [RustTarget], name: &str) -> &'a RustTarget {
        t.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("{name} not ranked: {t:?}"))
    }

    #[test]
    fn free_function_outranks_equal_scored_method() {
        // memchr shape: a free fn `find(&[u8])` vs a `&self` method `count(&[u8])`.
        // Both have a byte channel and score equally otherwise, but "count" sorts
        // before "find" alphabetically — without the static bonus the methods would
        // crowd out the free entry points. The free function must rank first.
        let free = rf("find", &[("haystack", "&[u8]")]);
        let mut method = rf("count", &[("haystack", "&[u8]")]);
        method.is_static = false;
        let ranked = rank_rust_targets(&[method, free]);
        assert_eq!(
            ranked[0].name, "find",
            "free function should rank first: {ranked:?}"
        );
        assert!(by_name(&ranked, "find").breakdown.static_free_function > 0);
        assert_eq!(by_name(&ranked, "count").breakdown.static_free_function, 0);
    }

    #[test]
    fn private_functions_are_dropped() {
        let mut private = rf("parse_secret", &[("d", "&[u8]")]);
        private.visibility = RustVisibility::Private;
        let public = rf("parse_public", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[private, public]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "parse_public");
    }

    #[test]
    fn pub_crate_is_dropped() {
        // The generated harness is a SEPARATE crate that path-depends on the
        // target; it can only call `pub` items. `pub(crate)` (and `pub(super)` /
        // `pub(in ...)`) are crate-internal and unreachable, so ranking one only
        // produces a guaranteed `failed_build` (e.g. semver's
        // `pub(crate) unsafe fn Identifier::new_unchecked`). Drop them.
        let mut internal = rf("new_unchecked", &[("d", "&str")]);
        internal.visibility = RustVisibility::PubCrate;
        let public = rf("parse_public", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[internal, public]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "parse_public");
    }

    #[test]
    fn cfg_test_functions_are_dropped() {
        let mut t = rf("qc_roundtrip", &[("d", "&[u8]")]);
        t.foreign_guard = Some("test".to_owned());
        let public = rf("parse_real", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[t, public]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "parse_real");
    }

    #[test]
    fn cfg_with_test_and_a_satisfiable_feature_is_not_dropped() {
        // base64 shape: `#[cfg(any(feature = "alloc", test))]` guards the canonical
        // `Engine::decode`/`encode`. The cfg holds in a normal build whenever the
        // `alloc` feature is on, so it is NOT test-only — dropping it blacks out the
        // crate's real API. Only a cfg where `test` is REQUIRED is test-only.
        let mut prod = rf("decode", &[("d", "&[u8]")]);
        prod.foreign_guard = Some("any(feature = \"alloc\", test)".to_owned());
        let other = rf("encode", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[prod, other]);
        assert_eq!(ranked.len(), 2, "neither fn is test-only: {ranked:?}");
        assert!(ranked.iter().any(|t| t.name == "decode"));

        // `all(test, ...)` and bare `test` ARE test-only (test is required).
        let mut all_test = rf("helper", &[("d", "&[u8]")]);
        all_test.foreign_guard = Some("all(test, feature = \"x\")".to_owned());
        assert_eq!(
            rank_rust_targets(&[all_test]).len(),
            0,
            "all(test, ..) requires test -> test-only"
        );

        // `not(test)` is a NON-test config (it only exists OUT of test) — keep it.
        let mut not_test = rf("prod_only", &[("d", "&[u8]")]);
        not_test.foreign_guard = Some("not(test)".to_owned());
        assert_eq!(rank_rust_targets(&[not_test]).len(), 1);

        // A feature literally NAMED "test" must not trip the test detector.
        let mut feat_named_test = rf("via_feature", &[("d", "&[u8]")]);
        feat_named_test.foreign_guard = Some("feature = \"test\"".to_owned());
        assert_eq!(rank_rust_targets(&[feat_named_test]).len(), 1);
    }

    #[test]
    fn static_std_conversion_trait_impl_methods_are_demoted() {
        // rust-rgb shape: `impl From<[T; 3]> for Rgb<T> { fn from(..) -> Self }` is a
        // STATIC trait-IMPL conversion. It is callable only by UFCS with a non-std
        // trait in scope, so the build lane skips it — but `is_trait_method` is false
        // (it's an impl, not a trait DECL), so the existing demotion missed it and the
        // unharnessable conversion out-ranked the real parser (vacuous exit-1).
        let mut from_impl = rf("from", &[("v", "[u8; 3]")]);
        from_impl.is_static = true;
        from_impl.impl_trait = Some("From<[u8; 3]>".to_owned());

        let mut from_iter = rf("from_iter", &[("it", "Vec<u8>")]);
        from_iter.is_static = true;
        from_iter.impl_trait = Some("FromIterator<u8>".to_owned());

        let real = rf("parse", &[("data", "&[u8]")]);
        let ranked = rank_rust_targets(&[from_impl, from_iter, real]);
        assert_eq!(
            ranked[0].name, "parse",
            "real target ranks first: {ranked:?}"
        );
        assert!(
            by_name(&ranked, "from")
                .breakdown
                .unconstructable_trait_method
                < 0
        );
        assert!(
            by_name(&ranked, "from_iter")
                .breakdown
                .unconstructable_trait_method
                < 0
        );
        assert!(by_name(&ranked, "from").score < by_name(&ranked, "parse").score);
    }

    #[test]
    fn ufcs_reachable_conversion_statics_are_not_demoted() {
        // `FromStr::from_str(&str)` and `TryFrom<&[u8]>/<&str>::try_from` ARE
        // UFCS-reachable from a dependent crate (std traits in the prelude / core),
        // so the build lane harnesses them — they must NOT be demoted.
        let mut from_str = rf("from_str", &[("s", "&str")]);
        from_str.is_static = true;
        from_str.impl_trait = Some("FromStr".to_owned());

        let mut try_from_bytes = rf("try_from", &[("b", "&[u8]")]);
        try_from_bytes.is_static = true;
        try_from_bytes.impl_trait = Some("TryFrom<&'a [u8]>".to_owned());

        let ranked = rank_rust_targets(&[from_str, try_from_bytes]);
        assert_eq!(
            by_name(&ranked, "from_str")
                .breakdown
                .unconstructable_trait_method,
            0,
            "FromStr::from_str is UFCS-reachable"
        );
        assert_eq!(
            by_name(&ranked, "try_from")
                .breakdown
                .unconstructable_trait_method,
            0,
            "TryFrom<&[u8]>::try_from is UFCS-reachable"
        );
    }

    #[test]
    fn internal_simd_impl_names_rank_below_public_parsers() {
        let simd = rf("match_uri_vectored", &[("d", "&[u8]")]);
        let public = rf("parse_uri", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[simd, public]);
        // The public scalar parser out-ranks the SIMD impl detail.
        assert_eq!(ranked[0].name, "parse_uri");
        assert!(
            by_name(&ranked, "match_uri_vectored")
                .breakdown
                .getter_or_writer_name
                < 0
        );
    }

    #[test]
    fn doc_hidden_functions_are_dropped() {
        // `#[doc(hidden)]` items are not public API (serde_json's
        // `from_string_unchecked`); ranking one is a wasted/failed build.
        let mut hidden = rf("from_string_unchecked", &[("s", "&str")]);
        hidden.doc_hidden = true;
        let public = rf("parse_public", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[hidden, public]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "parse_public");
    }

    #[test]
    fn existing_fuzz_target_ranks_top() {
        let mut harness = rf("run", &[]);
        harness.in_fuzz_target = true;
        let parser = rf("parse_thing", &[("d", "&[u8]")]);
        let ranked = rank_rust_targets(&[parser, harness]);
        assert_eq!(ranked[0].name, "run");
        assert!(ranked[0].breakdown.existing_fuzz_target > 0);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::AttackerReachable
        );
    }

    #[test]
    fn byte_slice_param_is_attacker_reachable_and_bonused() {
        let ranked = rank_rust_targets(&[rf("handle", &[("data", "&[u8]")])]);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::AttackerReachable
        );
        assert_eq!(ranked[0].breakdown.byte_channel_param, 30);
    }

    #[test]
    fn str_and_vec_and_fixed_array_count_as_byte_channels() {
        for ty in ["&str", "String", "Vec<u8>", "&[u8; 16]", "&mut [u8]"] {
            let ranked = rank_rust_targets(&[rf("f", &[("x", ty)])]);
            assert_eq!(
                ranked[0].breakdown.byte_channel_param, 30,
                "{ty} should be a byte channel"
            );
        }
    }

    #[test]
    fn parse_name_out_ranks_getter() {
        let ranked = rank_rust_targets(&[
            rf("get_count", &[("idx", "usize")]),
            rf("parse", &[("data", "&[u8]")]),
        ]);
        assert_eq!(ranked[0].name, "parse");
        assert!(ranked[0].score > ranked[1].score);
        assert!(by_name(&ranked, "parse").breakdown.parser_name > 0);
        assert!(
            by_name(&ranked, "get_count")
                .breakdown
                .getter_or_writer_name
                < 0
        );
    }

    #[test]
    fn writer_is_output_serializer_not_attacker_reachable() {
        let ranked = rank_rust_targets(&[rf("write_header", &[("n", "u32")])]);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::OutputSerializer
        );
        assert!(ranked[0].breakdown.getter_or_writer_name < 0);
    }

    #[test]
    fn unsafe_signature_is_promoted() {
        let mut unsafe_fn = rf("decode", &[("data", "&[u8]")]);
        unsafe_fn.is_unsafe = true;
        let safe_fn = rf("decode2", &[("data", "&[u8]")]);
        let ranked = rank_rust_targets(&[safe_fn, unsafe_fn]);
        assert_eq!(ranked[0].name, "decode", "unsafe variant ranks first");
        assert!(by_name(&ranked, "decode").breakdown.unsafe_reachable > 0);
    }

    #[test]
    fn scalar_only_fn_is_unproven_and_penalized() {
        let ranked = rank_rust_targets(&[rf("set_mode", &[("mode", "u8")])]);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::ReachabilityUnproven
        );
        assert_eq!(ranked[0].breakdown.no_byte_channel, -20);
    }

    #[test]
    fn from_bytes_constructor_gets_parser_bonus() {
        let ranked = rank_rust_targets(&[rf("from_bytes", &[("data", "&[u8]")])]);
        assert!(ranked[0].breakdown.parser_name > 0);
    }

    #[test]
    fn reader_trait_method_is_attacker_reachable_not_demoted() {
        // byteorder shape: `pub trait ReadBytesExt: io::Read { fn read_u32(&mut self) }`.
        // No value byte-channel param, but its bytes flow through the synthesised
        // Cursor receiver — so it counts as a byte channel and is NOT demoted.
        let mut reader = rf("read_u32", &[]);
        reader.is_static = false;
        reader.is_trait_method = true;
        reader.trait_supertrait = Some("io::Read".to_owned());
        let ranked = rank_rust_targets(&[reader]);
        assert_eq!(
            ranked[0].input_reachability,
            InputReachability::AttackerReachable,
            "the reader receiver IS the attacker channel"
        );
        assert_eq!(ranked[0].breakdown.byte_channel_param, 30);
        assert_eq!(ranked[0].breakdown.unconstructable_trait_method, 0);
        assert_eq!(ranked[0].breakdown.no_byte_channel, 0);
    }

    #[test]
    fn unconstructable_trait_methods_are_demoted_below_real_targets() {
        // A static trait method (`fn make(buf: &[u8]) -> Self` in a trait) and an
        // instance trait method on a NON-reader trait can't get a synthesised
        // receiver — demote both below a normal parser so they never waste budget.
        let mut static_tm = rf("from_trait", &[("buf", "&[u8]")]);
        static_tm.is_static = true;
        static_tm.is_trait_method = true;
        static_tm.trait_supertrait = None;

        let mut non_reader = rf("process", &[("data", "&[u8]")]);
        non_reader.is_static = false;
        non_reader.is_trait_method = true;
        non_reader.trait_supertrait = Some("Clone".to_owned());

        let real = rf("parse", &[("data", "&[u8]")]);
        let ranked = rank_rust_targets(&[static_tm, non_reader, real]);
        assert_eq!(
            ranked[0].name, "parse",
            "the real target ranks first: {ranked:?}"
        );
        assert!(
            by_name(&ranked, "from_trait")
                .breakdown
                .unconstructable_trait_method
                < 0
        );
        assert!(
            by_name(&ranked, "process")
                .breakdown
                .unconstructable_trait_method
                < 0
        );
        assert!(by_name(&ranked, "from_trait").score < by_name(&ranked, "parse").score);
        assert!(by_name(&ranked, "process").score < by_name(&ranked, "parse").score);
    }

    #[test]
    fn carries_static_and_guard_through() {
        let mut f = rf("parse", &[("d", "&[u8]")]);
        f.is_static = false;
        f.foreign_guard = Some("unix".to_owned());
        let ranked = rank_rust_targets(&[f]);
        assert!(!ranked[0].is_static);
        assert_eq!(ranked[0].foreign_guard.as_deref(), Some("unix"));
    }
}
