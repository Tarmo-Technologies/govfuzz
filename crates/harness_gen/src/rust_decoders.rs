// SPDX-License-Identifier: Apache-2.0

//! Map a Rust parameter type (`RustParam.ty`, the collapsed spelling from
//! `rust_parser`) to a govfuzz-native decode: a `rust_runtime::Cursor` call plus
//! the argument expression handed to the target. The Rust analog of
//! `c_decoders::select_c_decoder`.
//!
//! ## Strategy
//!
//! Each parameter becomes a `let <bind> = <cursor-expr>;` statement and an
//! argument expression. Fixed-width scalars (`u8`..`u64`, `bool`, `f32/f64`,
//! `char`) read a fixed number of bytes; a length-bounded variable field
//! (`Vec<u8>`, `String`) reads a 16-bit length prefix then bytes so later
//! parameters still see input.
//!
//! The single highest-value channel — a borrowed `&[u8]` / `&str` — is backed by
//! the **rest of the input** so the bulk of the fuzz bytes reach the primary
//! parser. To keep that sound when more than one parameter wants the rest, the
//! generator (`rust_generate`) decodes the LAST rest-eligible parameter with
//! `rest_*` and any earlier ones with the length-bounded form; this module just
//! reports, per parameter, whether it is "rest-eligible" so the generator can
//! pick exactly one.
//!
//! A type with no native decoder (a project struct, a generic, a trait object)
//! is rejected with [`RustDecodeError`] so the candidate is skipped cleanly
//! rather than emitting an uncompilable harness.

/// One decoded Rust parameter: the `let` binding text and the argument
/// expression passed at the call site. `rest_eligible` is true for a borrowed
/// byte/str slice that can consume the rest of the input (the generator backs at
/// most one such parameter with `rest_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustParamEmission {
    /// The cursor expression in length-bounded form (consumes a prefix, not the
    /// rest) — used for every parameter except the chosen rest channel.
    pub bounded_expr: String,
    /// The cursor expression in rest-consuming form, or `None` when this type is
    /// not rest-eligible. Used for the single chosen rest channel.
    pub rest_expr: Option<String>,
    /// Whether the argument must be passed by reference (`&bind`) — a borrowed
    /// slice/str binding is already a reference, an owned value is moved.
    pub by_ref: ArgPass,
    /// True when the type is a borrowed byte/str slice eligible to consume the
    /// rest of the input as the primary channel.
    pub rest_eligible: bool,
}

/// How the bound local is handed to the target at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgPass {
    /// Pass the binding directly (`bind`).
    Move,
    /// Borrow it (`&bind`).
    Ref,
    /// Borrow it mutably (`&mut bind`).
    RefMut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDecodeError {
    pub ty: String,
}

impl std::fmt::Display for RustDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rust parameter type '{}' has no govfuzz-native byte decoder",
            self.ty
        )
    }
}

/// Default maximum length for a bounded `Vec<u8>` / `String` parameter.
pub const RUST_BOUNDED_MAX: usize = 4096;

/// Backing length for a synthesized `&mut [u8]` OUTPUT / in-out buffer. A method
/// like `ByteOrder::write_u64(buf: &mut [u8], n)` writes a FIXED-width prefix
/// (`buf[..8].copy_from_slice(..)`); handed an empty or short fuzz slice it panics
/// on EVERY input ("range end index 8 out of range for slice of length 0") — a
/// harness-quality false positive, not a target bug. 64 (>= 16) covers the widest
/// fixed-width primitive write (`u128` = 16 bytes) with headroom.
pub const RUST_OUTPUT_BUF_LEN: usize = 64;

/// Normalise a type spelling: collapse whitespace and drop a leading lifetime on
/// a reference (`&'a [u8]` -> `&[u8]`). Mirrors how `rust_parser` already
/// collapses whitespace; we additionally erase named lifetimes which don't
/// affect the decode.
fn normalize(ty: &str) -> String {
    let collapsed = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    // Erase a `'name ` lifetime token wherever it appears (`&'a str`,
    // `& 'a [u8]`). A bare `&` reference keeps its meaning.
    let mut out = String::with_capacity(collapsed.len());
    let mut chars = collapsed.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch == '\'' {
            // Skip the lifetime identifier (letters/digits/underscore).
            while let Some(&(_, c)) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
            // Drop a single following space so `&'a str` -> `&str`.
            if let Some(&(_, ' ')) = chars.peek() {
                chars.next();
            }
        } else {
            out.push(ch);
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    drop_empty_generic_args(&collapsed)
}

/// Remove a generic-argument list left empty by lifetime erasure: `Request<'a, 'b>`
/// normalises to `Request<, >` (dangling commas) which then renders in a skip
/// message as `&mut Request<, >`. Erase any `<...>` whose content is solely commas
/// and whitespace so it reads `Request`. Legitimate args (`Vec<u8>`, `Cow<str>`)
/// are untouched, so decoder matching is unaffected.
fn drop_empty_generic_args(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '<' {
            // Find the matching '>' (depth-aware).
            let mut depth = 1i32;
            let mut j = i + 1;
            while j < chars.len() {
                match chars[j] {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if depth == 0 && j < chars.len() {
                let inner: String = chars[i + 1..j].iter().collect();
                if inner.chars().all(|c| c == ',' || c.is_whitespace()) {
                    i = j + 1; // skip the whole empty `<...>`
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// The type-correct zero literal for a fixed-width POD scalar element type, used to
/// fill a `&mut [T]` output-scratch `Vec<T>`. `None` for any non-POD-scalar element
/// (a project struct / generic / nested slice) so such a slice rejects cleanly.
fn scalar_zero_literal(elem: &str) -> Option<&'static str> {
    match elem.trim() {
        "u8" => Some("0u8"),
        "i8" => Some("0i8"),
        "u16" => Some("0u16"),
        "i16" => Some("0i16"),
        "u32" => Some("0u32"),
        "i32" => Some("0i32"),
        "u64" => Some("0u64"),
        "i64" => Some("0i64"),
        "u128" => Some("0u128"),
        "i128" => Some("0i128"),
        "usize" => Some("0usize"),
        "isize" => Some("0isize"),
        "f32" => Some("0.0f32"),
        "f64" => Some("0.0f64"),
        "bool" => Some("false"),
        "char" => Some("'\\0'"),
        _ => None,
    }
}

/// Decode one parameter type. Returns the emission or a [`RustDecodeError`].
pub fn select_rust_decoder(ty: &str) -> Result<RustParamEmission, RustDecodeError> {
    let n = normalize(ty);
    let compact = n.replace(' ', "");

    // --- fixed-width scalar integers / bool / float / char ---
    let scalar = match compact.as_str() {
        "u8" => Some("c.u8()"),
        "i8" => Some("c.i8()"),
        "u16" => Some("c.u16()"),
        "i16" => Some("c.i16()"),
        "u32" => Some("c.u32()"),
        "i32" => Some("c.i32()"),
        "u64" => Some("c.u64()"),
        "i64" => Some("c.i64()"),
        "usize" => Some("c.usize()"),
        "isize" => Some("c.isize()"),
        "bool" => Some("c.bool()"),
        "f32" => Some("c.f32()"),
        "f64" => Some("c.f64()"),
        "char" => Some("c.char()"),
        _ => None,
    };
    if let Some(expr) = scalar {
        return Ok(RustParamEmission {
            bounded_expr: expr.to_owned(),
            rest_expr: None,
            by_ref: ArgPass::Move,
            rest_eligible: false,
        });
    }

    // --- `&'static` byte/str references (RC2): `normalize` strips the lifetime, so
    // a `&'static [u8]` / `&'static str` would otherwise be fed a local borrow and
    // fail E0597. LEAK the decoded buffer to obtain a genuine `'static` reference
    // (one-shot per fuzz input; bounded by the per-input size). Passed by value
    // (the leaked reference IS the argument). ---
    if ty.contains("'static") {
        if compact == "&[u8]" || compact == "&mut[u8]" {
            return Ok(RustParamEmission {
                bounded_expr: format!("Box::leak(c.bytes({RUST_BOUNDED_MAX}).into_boxed_slice())"),
                rest_expr: Some("Box::leak(c.rest_bytes().into_boxed_slice())".to_owned()),
                by_ref: ArgPass::Move,
                rest_eligible: true,
            });
        }
        if compact == "&str" {
            return Ok(RustParamEmission {
                bounded_expr: format!("Box::leak(c.string({RUST_BOUNDED_MAX}).into_boxed_str())"),
                rest_expr: Some("Box::leak(c.rest_string().into_boxed_str())".to_owned()),
                by_ref: ArgPass::Move,
                rest_eligible: true,
            });
        }
    }

    // --- borrowed byte slice: `&[u8]` / `&mut [u8]` — the primary channel. The
    // binding owns a Vec; the call site borrows it (`&v` / `&mut v`). Rest-
    // eligible so the generator can feed it the whole input. ---
    if compact == "&[u8]" {
        return Ok(RustParamEmission {
            bounded_expr: format!("c.bytes({RUST_BOUNDED_MAX})"),
            rest_expr: Some("c.rest_bytes()".to_owned()),
            by_ref: ArgPass::Ref,
            rest_eligible: true,
        });
    }
    if compact == "&mut[u8]" {
        // An OUTPUT / in-out byte buffer (`ByteOrder::write_u64(buf: &mut [u8], n)`):
        // back it with an ADEQUATELY-SIZED, mutable buffer — fuzz bytes zero-padded
        // to `RUST_OUTPUT_BUF_LEN` — instead of the raw fuzz slice. An empty/short
        // slice makes every fixed-width write panic ("range end index N out of range
        // for slice of length 0") on EVERY input, a false positive rather than a
        // target bug. NOT rest-eligible: a fixed-size scratch buffer consumes no
        // primary input channel, so a sibling `&[u8]` keeps the rest.
        return Ok(RustParamEmission {
            bounded_expr: format!(
                "{{ let mut _gf_buf = c.bytes({RUST_OUTPUT_BUF_LEN}); \
                 _gf_buf.resize({RUST_OUTPUT_BUF_LEN}, 0u8); _gf_buf }}"
            ),
            rest_expr: None,
            by_ref: ArgPass::RefMut,
            rest_eligible: false,
        });
    }

    // --- output / in-out POD-scalar slice: `&mut [T]` for any fixed-width scalar
    // (`usize`/`u*`/`i*`/`f*`/`bool`/`char`), e.g. csv-core's `ends: &mut [usize]`.
    // Back it with a zero-init, adequately-sized `Vec<T>` scratch passed by `&mut`
    // (deref-coerces to `&mut [T]`). Without this, only `&mut [u8]` was handled and
    // every other element type hit the terminal decode error and skipped the target.
    // NOT rest-eligible (a fixed scratch consumes no primary input channel). ---
    if let Some(elem) = compact
        .strip_prefix("&mut[")
        .and_then(|s| s.strip_suffix(']'))
    {
        if let Some(zero) = scalar_zero_literal(elem) {
            return Ok(RustParamEmission {
                bounded_expr: format!(
                    "{{ let mut _gf_buf = vec![{zero}; {RUST_OUTPUT_BUF_LEN}]; _gf_buf }}"
                ),
                rest_expr: None,
                by_ref: ArgPass::RefMut,
                rest_eligible: false,
            });
        }
    }

    // --- output sink by mutable ref: `&mut String` / `&mut Vec<u8>` — arises from
    // monomorphizing a `&mut W` writer param (`W: fmt::Write`/`io::Write`). The
    // function WRITES into it, so back it with a FRESH EMPTY growable sink passed by
    // `&mut`; the result is discarded. NOT rest-eligible. ---
    if compact == "&mutString" {
        return Ok(RustParamEmission {
            bounded_expr: "String::new()".to_owned(),
            rest_expr: None,
            by_ref: ArgPass::RefMut,
            rest_eligible: false,
        });
    }
    if compact == "&mutVec<u8>" {
        return Ok(RustParamEmission {
            bounded_expr: "Vec::<u8>::new()".to_owned(),
            rest_expr: None,
            by_ref: ArgPass::RefMut,
            rest_eligible: false,
        });
    }

    // --- borrowed str: `&str`. Binding owns a String, call borrows it. ---
    if compact == "&str" {
        return Ok(RustParamEmission {
            bounded_expr: format!("c.string({RUST_BOUNDED_MAX})"),
            rest_expr: Some("c.rest_string()".to_owned()),
            by_ref: ArgPass::Ref,
            rest_eligible: true,
        });
    }

    // --- owned Vec<u8> / String: moved into the call. Rest-eligible. ---
    if compact == "Vec<u8>" {
        return Ok(RustParamEmission {
            bounded_expr: format!("c.bytes({RUST_BOUNDED_MAX})"),
            rest_expr: Some("c.rest_bytes()".to_owned()),
            by_ref: ArgPass::Move,
            rest_eligible: true,
        });
    }
    if compact == "String" {
        return Ok(RustParamEmission {
            bounded_expr: format!("c.string({RUST_BOUNDED_MAX})"),
            rest_expr: Some("c.rest_string()".to_owned()),
            by_ref: ArgPass::Move,
            rest_eligible: true,
        });
    }

    // --- `&&[u8]`: a reference to a byte slice. Arises from monomorphizing a
    // `needle: &N` param where `N: ?Sized + AsRef<[u8]>` is resolved to `N = &[u8]`
    // (e.g. memchr's `find_iter<N: AsRef<[u8]>>(haystack, needle: &N)`). Bind a
    // `&[u8]` value so the call site's `&` yields exactly `&&[u8]`; the binding leaks
    // a boxed slice (one-shot, bounded by the input size — the same idiom as the
    // `&'static` arm). NOT rest-eligible: a needle should stay small so a sibling
    // `&[u8]` haystack keeps the bulk of the input. ---
    if compact == "&&[u8]" {
        return Ok(RustParamEmission {
            bounded_expr: format!("&*c.bytes({RUST_BOUNDED_MAX}).leak()"),
            rest_expr: None,
            by_ref: ArgPass::Ref,
            rest_eligible: false,
        });
    }

    // --- &String -> bind a String, borrow it. ---
    if compact == "&String" {
        return Ok(RustParamEmission {
            bounded_expr: format!("c.string({RUST_BOUNDED_MAX})"),
            rest_expr: Some("c.rest_string()".to_owned()),
            by_ref: ArgPass::Ref,
            rest_eligible: true,
        });
    }

    // --- composite OWNED types: tuples and single-/nested-level
    // `Vec<U>`/`Box<U>`/`Rc<U>`/`Arc<U>`/`Cow<U>` over decodable elements. These
    // build a self-contained owned value (moved into the call) — e.g. `(u8, u32)`,
    // `Vec<u32>`, `Box<u64>`, `Cow<[u8]>`. Handled last so the dedicated `Vec<u8>` /
    // `String` arms keep their rest-eligibility. A composite whose element has no
    // owned decoder (a project struct, a borrow, `dyn Trait`) falls through to the
    // reject below. ---
    if let Some(expr) = decode_owned_expr(&compact, OWNED_DECODE_MAX_DEPTH) {
        return Ok(RustParamEmission {
            bounded_expr: expr,
            rest_expr: None,
            by_ref: ArgPass::Move,
            rest_eligible: false,
        });
    }

    Err(RustDecodeError { ty: n })
}

/// Nesting cap for [`decode_owned_expr`] — bounds generated-code size and recursion
/// on a pathological type like `Vec<Vec<Vec<...>>>`.
const OWNED_DECODE_MAX_DEPTH: u8 = 4;

/// Build a single self-contained expression that decodes an OWNED, move-able value
/// of compacted type `c` from the cursor `c` (the harness's `rust_runtime::Cursor`),
/// or `None` when no owned decoder applies. Recurses for tuples and the
/// `Vec`/`Box`/`Rc`/`Arc`/`Cow` wrappers; only owned leaves (scalars, `Vec<u8>`,
/// `String`) bottom out — a borrow (`&[u8]`) or project type yields `None` so the
/// caller rejects the parameter rather than emitting an uncompilable harness.
fn decode_owned_expr(c: &str, depth: u8) -> Option<String> {
    if depth == 0 {
        return None;
    }
    // Owned leaves.
    match c {
        "u8" => return Some("c.u8()".to_owned()),
        "i8" => return Some("c.i8()".to_owned()),
        "u16" => return Some("c.u16()".to_owned()),
        "i16" => return Some("c.i16()".to_owned()),
        "u32" => return Some("c.u32()".to_owned()),
        "i32" => return Some("c.i32()".to_owned()),
        "u64" => return Some("c.u64()".to_owned()),
        "i64" => return Some("c.i64()".to_owned()),
        "usize" => return Some("c.usize()".to_owned()),
        "isize" => return Some("c.isize()".to_owned()),
        "bool" => return Some("c.bool()".to_owned()),
        "f32" => return Some("c.f32()".to_owned()),
        "f64" => return Some("c.f64()".to_owned()),
        "char" => return Some("c.char()".to_owned()),
        "Vec<u8>" => return Some(format!("c.bytes({RUST_BOUNDED_MAX})")),
        "String" => return Some(format!("c.string({RUST_BOUNDED_MAX})")),
        _ => {}
    }
    // Tuple `(A, B, ...)` (and the unit `()`), depth-aware element split.
    if let Some(inner) = c.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        if inner.is_empty() {
            return Some("()".to_owned());
        }
        let parts = split_top_level(inner);
        // A 1-tuple is spelled `(T,)`; the trailing empty part must be preserved.
        let one_tuple = parts.len() == 2 && parts[1].is_empty();
        let elems: Option<Vec<String>> = parts
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| decode_owned_expr(p, depth - 1))
            .collect();
        let elems = elems?;
        if elems.is_empty() {
            return None;
        }
        if one_tuple {
            return Some(format!("({},)", elems[0]));
        }
        return Some(format!("({})", elems.join(", ")));
    }
    // `Cow<[u8]>` / `Cow<str>` decode to an owned `Vec<u8>` / `String`. `Cow` is
    // `Cow<'a, B>`, so after lifetime erasure the arg list may carry a leading empty
    // slot (`Cow<, [u8]>`); take the last non-empty arg as the `B` type.
    if let Some(inner) = generic_inner(c, "Cow") {
        let owned = split_top_level(inner)
            .into_iter()
            .rfind(|p| !p.is_empty())?;
        if owned == "[u8]" {
            return Some(format!(
                "std::borrow::Cow::<[u8]>::Owned(c.bytes({RUST_BOUNDED_MAX}))"
            ));
        }
        if owned == "str" {
            return Some(format!(
                "std::borrow::Cow::<str>::Owned(c.string({RUST_BOUNDED_MAX}))"
            ));
        }
        // `Cow<T>` over an owned, `ToOwned`-able element.
        let e = decode_owned_expr(owned, depth - 1)?;
        return Some(format!("std::borrow::Cow::Owned({e})"));
    }
    // `Vec<U>` over an owned element: bounded count then a push loop.
    if let Some(inner) = generic_inner(c, "Vec") {
        let e = decode_owned_expr(inner, depth - 1)?;
        return Some(format!(
            "{{ let _gf_n = c.bounded_len(256); \
             let mut _gf_v = Vec::with_capacity(_gf_n); \
             for _ in 0.._gf_n {{ _gf_v.push({e}); }} _gf_v }}"
        ));
    }
    // Smart-pointer wrappers around an owned element.
    for (wrapper, ctor) in [
        ("Box", "Box::new"),
        ("Rc", "std::rc::Rc::new"),
        ("Arc", "std::sync::Arc::new"),
    ] {
        if let Some(inner) = generic_inner(c, wrapper) {
            let e = decode_owned_expr(inner, depth - 1)?;
            return Some(format!("{ctor}({e})"));
        }
    }
    None
}

/// If `c` is `Name<...>` (with an optional `path::` prefix, so `std::borrow::Cow<..>`
/// and `alloc::vec::Vec<..>` match `Cow`/`Vec`), return the inner argument list
/// verbatim; else `None`. Last-path-segment match only — `MyVec<u8>` does not match
/// `Vec`.
fn generic_inner<'a>(c: &'a str, name: &str) -> Option<&'a str> {
    let lt = c.find('<')?;
    let head = &c[..lt];
    let last = head.rsplit("::").next().unwrap_or(head);
    if last != name {
        return None;
    }
    let inner = c[lt + 1..].strip_suffix('>')?;
    Some(inner.trim())
}

/// Split a generic/tuple argument list on TOP-LEVEL commas only (so `Vec<u8>` and
/// `(u8, u16)` inside an element stay intact). Trailing empty parts are kept (a
/// `(T,)` 1-tuple split yields `["T", ""]`).
fn split_top_level(inner: &str) -> Vec<&str> {
    let bytes = inner.as_bytes();
    let mut depth = 0i32;
    let mut parts = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(inner[start..].trim());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_erases_lifetime_only_generic_args() {
        // Lifetime erasure used to leave dangling commas (`Request<'a, 'b>` ->
        // `Request<, >`); the whole empty generic list must vanish.
        assert_eq!(normalize("Request<'a, 'b>"), "Request");
        assert_eq!(normalize("Request<'a>"), "Request");
        assert_eq!(normalize("&mut Request<'a, 'b>"), "&mut Request");
        // Real generic args are untouched (decoder matching must not change).
        assert_eq!(normalize("Vec<u8>"), "Vec<u8>");
        assert_eq!(normalize("&[u8]"), "&[u8]");
        // A nested lifetime-only inner list is also cleaned.
        assert_eq!(normalize("Foo<Bar<'a>>"), "Foo<Bar>");
    }

    #[test]
    fn scalar_types_decode_to_cursor_calls() {
        for (ty, expr) in [
            ("u8", "c.u8()"),
            ("i32", "c.i32()"),
            ("u64", "c.u64()"),
            ("usize", "c.usize()"),
            ("bool", "c.bool()"),
            ("f64", "c.f64()"),
            ("char", "c.char()"),
        ] {
            let e = select_rust_decoder(ty).expect(ty);
            assert_eq!(e.bounded_expr, expr);
            assert_eq!(e.by_ref, ArgPass::Move);
            assert!(!e.rest_eligible);
        }
    }

    #[test]
    fn byte_slice_is_rest_eligible_and_passed_by_ref() {
        let e = select_rust_decoder("&[u8]").unwrap();
        assert!(e.rest_eligible);
        assert_eq!(e.by_ref, ArgPass::Ref);
        assert_eq!(e.rest_expr.as_deref(), Some("c.rest_bytes()"));
        assert!(e.bounded_expr.contains("c.bytes("));
    }

    #[test]
    fn lifetime_is_erased() {
        let e = select_rust_decoder("&'a [u8]").unwrap();
        assert!(e.rest_eligible);
        assert_eq!(e.by_ref, ArgPass::Ref);
        let s = select_rust_decoder("&'a str").unwrap();
        assert_eq!(s.by_ref, ArgPass::Ref);
        assert_eq!(s.rest_expr.as_deref(), Some("c.rest_string()"));
    }

    #[test]
    fn str_and_string_decode() {
        assert!(select_rust_decoder("&str").unwrap().rest_eligible);
        assert_eq!(select_rust_decoder("String").unwrap().by_ref, ArgPass::Move);
        assert_eq!(select_rust_decoder("&String").unwrap().by_ref, ArgPass::Ref);
    }

    #[test]
    fn vec_u8_is_moved_and_rest_eligible() {
        let e = select_rust_decoder("Vec<u8>").unwrap();
        assert_eq!(e.by_ref, ArgPass::Move);
        assert!(e.rest_eligible);
    }

    #[test]
    fn mut_byte_slice_backs_a_sized_output_buffer() {
        // A `&mut [u8]` output/in-out buffer must NOT be the raw fuzz slice (an
        // empty/short slice makes every fixed-width write panic). It is backed by an
        // adequately-sized, zero-padded buffer, passed by `&mut`, and is no longer
        // the rest channel.
        let e = select_rust_decoder("&mut [u8]").unwrap();
        assert_eq!(e.by_ref, ArgPass::RefMut);
        assert!(!e.rest_eligible);
        assert!(e.rest_expr.is_none());
        assert!(
            e.bounded_expr
                .contains(&format!("resize({RUST_OUTPUT_BUF_LEN}, 0u8)")),
            "{}",
            e.bounded_expr
        );
        // The buffer must be wide enough for the widest fixed-width primitive write
        // (u128 = 16 bytes).
        const _: () = assert!(RUST_OUTPUT_BUF_LEN >= 16);
    }

    #[test]
    fn mut_pod_scalar_slice_backs_a_zero_init_scratch_vec() {
        // csv-core `read_record(&mut self, input: &[u8], output: &mut [u8],
        // ends: &mut [usize])`: the `ends: &mut [usize]` OUTPUT-scratch slice is not
        // `&mut [u8]`, so it used to hit the terminal decode error and skip the whole
        // target. Any `&mut [T]` POD-scalar slice now gets a zero-init sized Vec<T>
        // scratch passed by `&mut` (deref-coerces to `&mut [T]`).
        let e = select_rust_decoder("&mut [usize]").unwrap();
        assert_eq!(e.by_ref, ArgPass::RefMut);
        assert!(!e.rest_eligible);
        assert!(e.rest_expr.is_none());
        assert!(
            e.bounded_expr
                .contains(&format!("vec![0usize; {RUST_OUTPUT_BUF_LEN}]")),
            "{}",
            e.bounded_expr
        );
        // Other POD element types are covered too, with type-correct zero literals.
        assert!(select_rust_decoder("&mut [u32]")
            .unwrap()
            .bounded_expr
            .contains("vec![0u32;"));
        assert!(select_rust_decoder("&mut [f64]")
            .unwrap()
            .bounded_expr
            .contains("vec![0.0f64;"));
        assert!(select_rust_decoder("&mut [bool]")
            .unwrap()
            .bounded_expr
            .contains("vec![false;"));
        // A lifetime-spelled form normalizes to the same decoder.
        assert!(select_rust_decoder("&'a mut [i16]")
            .unwrap()
            .bounded_expr
            .contains("vec![0i16;"));
        // A non-POD element slice (`&mut [MyStruct]`) still rejects cleanly.
        assert!(select_rust_decoder("&mut [MyStruct]").is_err());
    }

    #[test]
    fn tuple_of_scalars_decodes_each_element_by_move() {
        let e = select_rust_decoder("(u8, u32, bool)").unwrap();
        assert_eq!(e.by_ref, ArgPass::Move);
        assert!(!e.rest_eligible);
        assert_eq!(e.bounded_expr, "(c.u8(), c.u32(), c.bool())");
        // A 1-tuple keeps its trailing comma so it stays a tuple, not a paren group.
        assert_eq!(
            select_rust_decoder("(u16,)").unwrap().bounded_expr,
            "(c.u16(),)"
        );
    }

    #[test]
    fn vec_of_decodable_element_loops_a_bounded_count() {
        let e = select_rust_decoder("Vec<u32>").unwrap();
        assert_eq!(e.by_ref, ArgPass::Move);
        assert!(e.bounded_expr.contains("c.bounded_len("));
        assert!(e.bounded_expr.contains("_gf_v.push(c.u32())"));
        // Nested: Vec<Vec<u8>> — inner Vec<u8> bottoms out at the owned byte decoder.
        let n = select_rust_decoder("Vec<Vec<u8>>").unwrap();
        assert!(n.bounded_expr.contains("c.bytes("));
    }

    #[test]
    fn smart_pointer_and_cow_wrappers_decode_owned() {
        assert_eq!(
            select_rust_decoder("Box<u64>").unwrap().bounded_expr,
            "Box::new(c.u64())"
        );
        assert!(select_rust_decoder("Arc<u8>")
            .unwrap()
            .bounded_expr
            .contains("std::sync::Arc::new(c.u8())"));
        assert!(select_rust_decoder("Cow<[u8]>")
            .unwrap()
            .bounded_expr
            .contains("Cow::<[u8]>::Owned(c.bytes("));
        assert!(select_rust_decoder("Cow<str>")
            .unwrap()
            .bounded_expr
            .contains("Cow::<str>::Owned(c.string("));
        // `Cow<T>` over any owned-decodable T is sound: every leaf this module emits
        // (scalars, Vec<u8>, String, tuples, Vec/Box/Rc/Arc) is `Clone`, and the
        // blanket `impl<T: Clone> ToOwned` makes `Cow::Owned(T)` valid — verified to
        // compile end-to-end for `Cow<u32>`, `Cow<Box<u64>>`, `Cow<Vec<u32>>`.
        assert!(select_rust_decoder("Cow<u32>")
            .unwrap()
            .bounded_expr
            .contains("Cow::Owned(c.u32())"));
        assert!(select_rust_decoder("Cow<Box<u64>>")
            .unwrap()
            .bounded_expr
            .contains("Cow::Owned(Box::new(c.u64()))"));
    }

    #[test]
    fn composite_with_undecodable_element_is_rejected() {
        // A project struct / borrow element has no owned decoder -> whole param skips.
        assert!(select_rust_decoder("Vec<MyStruct>").is_err());
        assert!(select_rust_decoder("(u8, MyStruct)").is_err());
        // A borrow inside a tuple is not move-able-owned -> reject (not silently wrong).
        assert!(select_rust_decoder("(u8, &[u8])").is_err());
    }

    #[test]
    fn ref_to_byte_slice_binds_a_slice_and_is_not_rest() {
        // memchr `find_iter` shape after monomorphizing `needle: &N` (N: AsRef<[u8]>).
        let e = select_rust_decoder("&&[u8]").unwrap();
        // Passed by `&` (so `&a` is exactly `&&[u8]`), bound as a `&[u8]` slice.
        assert_eq!(e.by_ref, ArgPass::Ref);
        assert!(e.bounded_expr.contains(".leak()"), "{}", e.bounded_expr);
        // A needle stays small: not rest-eligible, so a sibling `&[u8]` haystack
        // keeps the rest channel.
        assert!(!e.rest_eligible);
        assert!(e.rest_expr.is_none());
        // Lifetime-spelled form normalizes to the same decoder.
        assert_eq!(
            select_rust_decoder("&'n &[u8]").unwrap().by_ref,
            ArgPass::Ref
        );
    }

    #[test]
    fn unknown_type_is_rejected() {
        let err = select_rust_decoder("MyStruct").unwrap_err();
        assert!(err.to_string().contains("MyStruct"));
        assert!(select_rust_decoder("Vec<MyStruct>").is_err());
        assert!(select_rust_decoder("&Config").is_err());
    }
}
