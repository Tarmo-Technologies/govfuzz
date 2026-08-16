// SPDX-License-Identifier: Apache-2.0

//! Generate a govfuzz-native Rust fuzzing harness: a `staticlib` source file
//! exposing
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn govfuzz_run_one(data: *const u8, len: usize) -> i32 { ... }
//! ```
//!
//! which decodes the raw fuzz bytes into typed arguments via the dependency-free
//! `rust_runtime::Cursor` and calls the target. Linked with the shared C
//! fork-server driver (`c_runtime/govfuzz_driver.c`, copied beside the harness as
//! `main.c`), the result is a native sancov+ASan binary the builtin engine drives
//! persistently — the SAME execution path as C/C++, no third-party fuzzer.
//!
//! This module produces only the harness SOURCE (and the call wiring); the CLI's
//! `try_build_rust` owns the cargo/rustc invocation and the clang link.

use crate::rust_decoders::{select_rust_decoder, ArgPass, RustParamEmission};
use rust_parser::{RustFn, RustParam};

/// How a receiver constructor's return value yields the receiver instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceiverUnwrap {
    /// The ctor returns the receiver directly (`Self`).
    #[default]
    Direct,
    /// The ctor returns `Result<Self, _>` — `match { Ok(r) => r, Err(_) => return }`.
    Result,
    /// The ctor returns `Option<Self>` — `match { Some(r) => r, None => return }`.
    Option,
    /// The ctor returns `Box<Self>` — deref-move the box to the owned receiver.
    Boxed,
    /// The ctor returns `Arc<Self>` — `Arc::try_unwrap` to the owned receiver (the
    /// freshly-built value is the sole owner, so this succeeds).
    Arc,
    /// The ctor returns `Rc<Self>` — `Rc::try_unwrap` to the owned receiver.
    Rc,
}

/// What the generated harness should call, resolved from the discovered target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustCall {
    /// A free / associated function reached by a path, e.g.
    /// `["my_crate", "parser", "parse"]` -> `my_crate::parser::parse(args)`.
    Path(Vec<String>),
    /// An existing `fuzz_target!` harness file: there is no callable `pub fn`, so
    /// the generator instead wraps the target's body by `include!`-ing nothing —
    /// handled specially (see [`generate_rust_existing_fuzz_target`]).
    ExistingFuzzTarget,
}

/// Inputs to Rust harness generation for a DIRECT (single-function) target.
#[derive(Debug, Clone)]
pub struct GenerateRustDirectArgs {
    /// The fully-qualified call path, e.g. `["url", "Url", "parse"]` for
    /// `url::Url::parse`, or `["httparse", "parse_headers"]`.
    pub call_path: Vec<String>,
    /// The target function's signature (params + receiver), re-parsed from source.
    pub target: RustFn,
    /// For an instance (`&self`/`&mut self`/`self`) method, the no-arg constructor
    /// PATH used to build a receiver, e.g. `["url", "Url", "default"]` or
    /// `["url", "Url", "new"]`. The harness does `let mut recv = <ctor>();
    /// recv.method(args)` (method-call syntax auto-borrows the receiver, so the
    /// `self` kind needn't be known). `None` for a static fn, or when no usable
    /// constructor was found (the instance method is then rejected).
    pub receiver: Option<Vec<String>>,
    /// The receiver constructor's parameters, decoded from the cursor BEFORE the
    /// method args (each length-bounded, never the rest channel). Empty for a
    /// no-arg `new()`/`default()` ctor; non-empty for an arg-taking ctor like
    /// `memmem::Finder::new(&[u8])` or `Document::parse(&str)`.
    pub receiver_ctor_params: Vec<RustParam>,
    /// How the constructor's return value yields the receiver: a plain value, or
    /// an unwrapped `Result`/`Option` (a failed/`None` ctor returns from the
    /// harness rather than panicking — `Document::parse` returns `Result`).
    pub receiver_unwrap: ReceiverUnwrap,
    /// Per-parameter decode-expression OVERRIDES (parallel to `target.params`).
    /// A `Some((expr, by_ref))` entry replaces the type-based decoder for that param
    /// with `expr`, passed at the call site per `by_ref` (an enum pick like
    /// `[E::A, E::B][(c.u8() as usize) % 2]` by `Move`; a scratch slice like
    /// `[crate::EMPTY_HEADER; 16]` by `RefMut`). The param's declared type then
    /// never reaches `select_rust_decoder`, so otherwise-undecodable enum / scratch
    /// params become callable. `None` entries — and indices past the end of this vec
    /// (an empty vec means "no overrides") — fall back to the standard type decoder.
    pub param_decoders: Vec<Option<(String, ArgPass)>>,
    /// Per-parameter decode-expression OVERRIDES for the RECEIVER ctor's args
    /// (parallel to `receiver_ctor_params`). Same mechanism as `param_decoders`,
    /// applied to the ctor call — e.g. `Request::new(&mut [Header])` gets a
    /// `[httparse::EMPTY_HEADER; 16]` const-scratch by `RefMut`. Empty = no overrides.
    pub receiver_ctor_param_decoders: Vec<Option<(String, ArgPass)>>,
    /// For a STATIC trait-impl method, the reachable trait path: the call is then
    /// emitted by UFCS `<Type as Trait>::method(args)` (Type = `call_path` minus the
    /// method). `None` for a normal free/inherent/receiver call. Lets a crate whose
    /// API is trait-impl methods on marker types (byteorder) be called without a
    /// `use` of the trait.
    pub ufcs_trait: Option<Vec<String>>,
    /// For an INSTANCE method defined in a trait impl (`impl Buf for Bytes { fn
    /// remaining(&self) }`), the reachable trait path to bring into scope so the
    /// `recv.method()` call resolves. Emitted as a local `use <path> as _;` in the
    /// harness body — method-call syntax then finds the trait method without
    /// needing UFCS or knowing the `&self`/`&mut self` form. `None` for an
    /// inherent method or a prelude trait (Clone/IntoIterator — already in scope).
    pub method_trait_import: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedRustHarness {
    /// The harness `.rs` source (a `staticlib` crate root) — exposes
    /// `govfuzz_run_one`.
    pub harness_rs: String,
    /// `true` when at least one parameter was decodable and the call is real
    /// (always true on success; surfaced so callers can assert).
    pub callable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustGenerateError {
    pub reason: String,
}

impl std::fmt::Display for RustGenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// A Rust primitive scalar / `str` type name. A trait impl on one of these
/// (`impl Trait for i8`) has a bare, never-module-qualified receiver type.
fn is_rust_primitive(s: &str) -> bool {
    matches!(
        s,
        "i8" | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "f32"
            | "f64"
            | "bool"
            | "char"
            | "str"
    )
}

/// Build the body of `govfuzz_run_one` for a direct call. Decodes each parameter
/// from the cursor; the chosen rest channel (the LAST rest-eligible parameter)
/// consumes the rest of the input so the bulk of the bytes reach the parser.
#[allow(clippy::too_many_arguments)]
fn build_call_body(
    call_path: &[String],
    params: &[RustParam],
    receiver: Option<&[String]>,
    receiver_ctor_params: &[RustParam],
    receiver_unwrap: ReceiverUnwrap,
    param_decoders: &[Option<(String, ArgPass)>],
    receiver_ctor_param_decoders: &[Option<(String, ArgPass)>],
    ufcs_trait: Option<&[String]>,
    method_trait_import: Option<&[String]>,
    is_unsafe: bool,
) -> Result<String, RustGenerateError> {
    if call_path.is_empty() {
        return Err(RustGenerateError {
            reason: "empty Rust call path".to_owned(),
        });
    }

    // Per param: either a caller-supplied override expression (owned, passed by
    // move — the declared type is NOT decoded), or a type-based decoder. An
    // override lets us call targets with otherwise-undecodable params (e.g. a
    // unit enum the caller resolved variants for). Reject the candidate if any
    // non-overridden type has no decoder.
    enum Slot {
        Override(String, ArgPass),
        Decoded(RustParamEmission),
    }
    let slots: Vec<Slot> = params
        .iter()
        .enumerate()
        .map(|(i, p)| match param_decoders.get(i) {
            Some(Some((expr, by_ref))) => Ok(Slot::Override(expr.clone(), *by_ref)),
            _ => select_rust_decoder(&p.ty)
                .map(Slot::Decoded)
                .map_err(|e| RustGenerateError {
                    reason: e.to_string(),
                }),
        })
        .collect::<Result<_, _>>()?;

    // Pick the LAST rest-eligible DECODED parameter as the rest channel; every
    // other rest-eligible parameter falls back to its length-bounded form so they
    // don't all try to consume the whole input. Override slots are never the rest
    // channel.
    let rest_idx = slots
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| matches!(s, Slot::Decoded(e) if e.rest_eligible))
        .map(|(i, _)| i);

    let mut lines = Vec::new();
    let mut call_args = Vec::new();
    for (i, s) in slots.iter().enumerate() {
        let bind = format!("a{i}");
        // `let mut` unconditionally: a `&mut T` parameter needs a mutable local
        // (RC3 — else E0596), and the harness `#![allow(unused_mut)]` makes the
        // mut harmless for by-value / shared-ref params.
        match s {
            Slot::Override(expr, by_ref) => {
                lines.push(format!("    let mut {bind} = {expr};"));
                call_args.push(match by_ref {
                    ArgPass::Move => bind.clone(),
                    ArgPass::Ref => format!("&{bind}"),
                    ArgPass::RefMut => format!("&mut {bind}"),
                });
            }
            Slot::Decoded(e) => {
                let expr = if Some(i) == rest_idx {
                    e.rest_expr
                        .clone()
                        .unwrap_or_else(|| e.bounded_expr.clone())
                } else {
                    e.bounded_expr.clone()
                };
                lines.push(format!("    let mut {bind} = {expr};"));
                let arg = match e.by_ref {
                    ArgPass::Move => bind.clone(),
                    ArgPass::Ref => format!("&{bind}"),
                    ArgPass::RefMut => format!("&mut {bind}"),
                };
                call_args.push(arg);
            }
        }
    }

    let args = call_args.join(", ");
    // Receiver setup is decoded BEFORE the method args (so the method's rest
    // channel still gets the bulk of the input). For an instance method we
    // construct the receiver from its ctor — possibly decoding the ctor's own
    // args and unwrapping a fallible `Result`/`Option`.
    let mut recv_setup = Vec::new();
    // Build just the inner call expression (no `let _ =` wrapper yet); we apply
    // the `unsafe { ... }` wrapper below if the target is an `unsafe fn`.
    let call_expr = match receiver {
        Some(ctor) => {
            let method = call_path.last().cloned().unwrap_or_default();
            let ctor_path = ctor.join("::");
            let mut ctor_args = Vec::new();
            for (j, p) in receiver_ctor_params.iter().enumerate() {
                let bind = format!("rc{j}");
                // A caller-supplied override (e.g. a const-scratch `[EMPTY_HEADER; 16]`
                // for a `&mut [Header]` ctor arg) bypasses the type decoder, exactly as
                // for the method's own params; otherwise decode the ctor arg from the
                // cursor. Ctor args are always length-bounded (never the rest channel).
                match receiver_ctor_param_decoders.get(j) {
                    Some(Some((expr, by_ref))) => {
                        recv_setup.push(format!("    let mut {bind} = {expr};"));
                        ctor_args.push(match by_ref {
                            ArgPass::Move => bind.clone(),
                            ArgPass::Ref => format!("&{bind}"),
                            ArgPass::RefMut => format!("&mut {bind}"),
                        });
                    }
                    _ => {
                        let e = select_rust_decoder(&p.ty).map_err(|e| RustGenerateError {
                            reason: e.to_string(),
                        })?;
                        recv_setup.push(format!("    let mut {bind} = {};", e.bounded_expr));
                        // For `&str` / `&[u8]` params, `&bind` gives `&String` /
                        // `&Vec<u8>`. Concrete callers coerce this via Deref, but
                        // generic `From<&str>` / `From<&[u8]>` calls infer the wrong
                        // type (`&String`) and fail E0277. Use `ctor_ref_arg` to emit
                        // the exact borrowed form (`.as_str()` / `.as_slice()`).
                        ctor_args.push(match e.by_ref {
                            ArgPass::Move => bind.clone(),
                            ArgPass::Ref => ctor_ref_arg(&bind, &p.ty),
                            ArgPass::RefMut => format!("&mut {bind}"),
                        });
                    }
                }
            }
            let ctor_call = format!("{ctor_path}({})", ctor_args.join(", "));
            recv_setup.push(match receiver_unwrap {
                ReceiverUnwrap::Direct => format!("    let mut recv = {ctor_call};"),
                ReceiverUnwrap::Result => format!(
                    "    let mut recv = match {ctor_call} {{ Ok(r) => r, Err(_) => return 0 }};"
                ),
                ReceiverUnwrap::Option => format!(
                    "    let mut recv = match {ctor_call} {{ Some(r) => r, None => return 0 }};"
                ),
                // `Box<Self>`: deref-move the box to the owned receiver.
                ReceiverUnwrap::Boxed => format!("    let mut recv = *{ctor_call};"),
                // `Arc<Self>`/`Rc<Self>`: the freshly-built value is the sole owner, so
                // `try_unwrap` yields the owned receiver (Err only if the ctor itself
                // cloned the handle — then skip this input cleanly).
                ReceiverUnwrap::Arc => format!(
                    "    let mut recv = match std::sync::Arc::try_unwrap({ctor_call}) \
                     {{ Ok(r) => r, Err(_) => return 0 }};"
                ),
                ReceiverUnwrap::Rc => format!(
                    "    let mut recv = match std::rc::Rc::try_unwrap({ctor_call}) \
                     {{ Ok(r) => r, Err(_) => return 0 }};"
                ),
            });
            // method-call syntax auto-borrows &self/&mut self/self.
            format!("recv.{method}({args})")
        }
        None => match ufcs_trait {
            // A static trait-impl method: call by UFCS `<Type as Trait>::method(..)`
            // (Type = call_path minus the method) so no `use` of the trait is needed.
            Some(trait_path) if call_path.len() >= 2 => {
                let method = call_path.last().cloned().unwrap_or_default();
                let type_seg = &call_path[call_path.len() - 2];
                // A trait impl on a PRIMITIVE type (winnow `impl Int for i8`): the
                // receiver type is the BARE primitive, never module-qualified.
                // `<winnow::ascii::i8 as ..>` fails ("cannot find type i8 in module
                // winnow::ascii"); emit `<i8 as winnow::ascii::Int>::..` instead.
                let type_path = if is_rust_primitive(type_seg) {
                    type_seg.clone()
                } else {
                    call_path[..call_path.len() - 1].join("::")
                };
                let trait_path = trait_path.join("::");
                format!("<{type_path} as {trait_path}>::{method}({args})")
            }
            _ => {
                let path = call_path.join("::");
                format!("{path}({args})")
            }
        },
    };
    // Wrap in `unsafe { ... }` when the TARGET is an `unsafe fn`.  The receiver
    // / argument decoding stays OUTSIDE the block — only the actual call is unsafe.
    let call = if is_unsafe {
        format!("    let _ = unsafe {{ {call_expr} }};")
    } else {
        format!("    let _ = {call_expr};")
    };
    let mut body = String::new();
    // Bring an instance method's trait into scope so `recv.method()` resolves
    // (bytes' `Buf::remaining`, `Deref::deref`). A local `use ... as _;` is
    // anonymous so it never clashes with another name; redundant for a prelude
    // trait but harmless (`#![allow(unused_imports)]`).
    if let Some(path) = method_trait_import {
        if !path.is_empty() {
            body.push_str(&format!("    use {} as _;\n", path.join("::")));
        }
    }
    body.push_str("    let s = unsafe { core::slice::from_raw_parts(data, len) };\n");
    body.push_str("    let mut c = rust_runtime::Cursor::new(s);\n");
    for line in &recv_setup {
        body.push_str(line);
        body.push('\n');
    }
    for line in &lines {
        body.push_str(line);
        body.push('\n');
    }
    // Suppress an unused-cursor warning when there are zero parameters.
    body.push_str("    let _ = &mut c;\n");
    body.push_str("    unsafe { govfuzz_target_enter(); }\n");
    body.push_str(&call);
    body.push('\n');
    Ok(body)
}

/// Return the compact, lifetime-erased form of a reference type: `"&'a str"` →
/// `"&str"`, `"&'input [u8]"` → `"&[u8]"`. Used to match known borrowed-slice
/// types in the ctor-arg emitter without worrying about named lifetimes.
fn compact_borrow_ty(ty: &str) -> String {
    // Collapse whitespace first.
    let s = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    // Erase a named lifetime after `&`: `&'a str` → `& str` → `&str`.
    let s = if let Some(after_amp) = s.strip_prefix("&'") {
        match after_amp.find(' ') {
            Some(sp) => format!("&{}", &after_amp[sp + 1..]),
            None => s, // malformed; leave as-is
        }
    } else {
        s
    };
    s.replace(' ', "")
}

/// For `&str` / `&[u8]` receiver-ctor args: the binding owns a `String` /
/// `Vec<u8>`. In a CONCRETE function call (`fn parse(text: &str)`), `&bind`
/// coerces to `&str` via Deref. But for a GENERIC From call
/// (`fn from(value: T) where Self: From<T>`), the compiler infers `T = &String`
/// (not `T = &str`) and no coercion fires — producing E0277. Call `.as_str()` /
/// `.as_slice()` to produce the exact borrowed type the call site expects.
fn ctor_ref_arg(bind: &str, param_ty: &str) -> String {
    match compact_borrow_ty(param_ty).as_str() {
        "&str" => format!("{bind}.as_str()"),
        "&[u8]" => format!("{bind}.as_slice()"),
        _ => format!("&{bind}"),
    }
}

/// If a generic type-param bound names a byte- or str-slice conversion, the
/// concrete type to monomorphize the param to. `AsRef<[u8]>` / `Borrow<[u8]>` ->
/// `&[u8]`, `Into<Vec<u8>>` -> `Vec<u8>`, `AsRef<str>` / `Borrow<str>` -> `&str`,
/// `Into<String>` -> `String`. `None` for any other (uninferable) bound.
///
/// Also resolves OUTPUT-SINK generics — a `W: fmt::Write` / `io::Write` writer the
/// function writes INTO (pulldown-cmark-escape's `escape<W: fmt::Write>(w, s)`). A
/// concrete std sink makes the fn harnessable: `fmt::Write` -> `String`,
/// `io::Write` -> `Vec<u8>` (both impl the trait). The decoder then backs the sink
/// (an owned value by-value, or a fresh empty sink for `&mut W`).
fn monomorphize_bound(bound: &str) -> Option<&'static str> {
    let compact = bound.replace(' ', "");
    // A bound may be a sum (`AsRef<[u8]>+Send+?Sized`); any recognized clause wins.
    compact.split('+').find_map(|clause| {
        match clause {
            "AsRef<[u8]>" | "Borrow<[u8]>" | "AsRef<[u8]>+?Sized" => return Some("&[u8]"),
            "Into<Vec<u8>>" => return Some("Vec<u8>"),
            "AsRef<str>" | "Borrow<str>" => return Some("&str"),
            "Into<String>" => return Some("String"),
            _ => {}
        }
        // Output-sink writer traits, matched by their leaf path so `std::fmt::Write`,
        // `core::fmt::Write`, and `fmt::Write` all resolve. A bare `Write` is
        // ambiguous (io vs fmt) and is intentionally NOT matched.
        if clause.ends_with("fmt::Write") {
            return Some("String");
        }
        if clause.ends_with("io::Write") {
            return Some("Vec<u8>");
        }
        None
    })
}

/// Replace whole-identifier occurrences of the generic param `name` in a type
/// spelling with `concrete` (`T` -> `&[u8]`, `Vec<T>` -> `Vec<&[u8]>`). A bare
/// substring inside a longer identifier (`Threshold`) is left untouched.
fn substitute_type_param(ty: &str, name: &str, concrete: &str) -> String {
    let chars: Vec<char> = ty.chars().collect();
    let target: Vec<char> = name.chars().collect();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(ty.len());
    let mut i = 0;
    while i < chars.len() {
        let matches = i + target.len() <= chars.len() && chars[i..i + target.len()] == target[..];
        let before_ok = i == 0 || !is_ident(chars[i - 1]);
        let after_ok = i + target.len() >= chars.len() || !is_ident(chars[i + target.len()]);
        if matches && before_ok && after_ok {
            out.push_str(concrete);
            i += target.len();
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Resolve the target's parameter list to a concrete, decodable form: each generic
/// type param with a byte/str-slice bound is substituted into the param types
/// (`data: T` -> `data: &[u8]`). Errors (a clean skip) if any type param has an
/// unrecognized/absent bound, or is not used by an input param (return-only /
/// uninferable, e.g. `from_slice<T: Deserialize>() -> Result<T>`).
fn monomorphized_params(target: &RustFn) -> Result<Vec<RustParam>, RustGenerateError> {
    if target.type_params.is_empty() {
        return Ok(target.params.clone());
    }
    let mut subst: Vec<(&str, &'static str)> = Vec::new();
    for tp in &target.type_params {
        match monomorphize_bound(&tp.bound) {
            Some(concrete) => subst.push((tp.name.as_str(), concrete)),
            None => {
                return Err(RustGenerateError {
                    reason: format!(
                        "Rust target '{}' is generic over type parameter `{}`{} with no \
                         byte/str-slice bound to monomorphize (uninferable, e.g. \
                         `from_slice<T: Deserialize>`) — not auto-harnessable",
                        target.name,
                        tp.name,
                        if tp.bound.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", tp.bound)
                        },
                    ),
                })
            }
        }
    }
    let mut params = target.params.clone();
    let mut used: Vec<&str> = Vec::new();
    for p in &mut params {
        for (name, concrete) in &subst {
            let next = substitute_type_param(&p.ty, name, concrete);
            if next != p.ty {
                p.ty = next;
                if !used.contains(name) {
                    used.push(name);
                }
            }
        }
    }
    for (name, _) in &subst {
        if !used.contains(name) {
            return Err(RustGenerateError {
                reason: format!(
                    "Rust target '{}' type parameter `{name}` does not appear in any input \
                     parameter (return-only / uninferable) — not auto-harnessable",
                    target.name
                ),
            });
        }
    }
    Ok(params)
}

/// Generate a harness for a direct target. A free/associated fn is called by
/// path; an instance (`&self`/`&mut self`/`self`) method is called on a receiver
/// the caller resolved a no-arg constructor for (`args.receiver`) — without one,
/// the instance method is rejected (a clean skip).
pub fn generate_rust_direct_harness(
    args: &GenerateRustDirectArgs,
) -> Result<GeneratedRustHarness, RustGenerateError> {
    if !args.target.is_static && args.receiver.is_none() {
        return Err(RustGenerateError {
            reason: format!(
                "Rust target '{}' is a &self method and no no-arg receiver constructor \
                 (Default / new()) was found; not auto-harnessable",
                args.target.name
            ),
        });
    }
    // Monomorphize generic type params bounded by a byte/str-slice conversion
    // (`T: AsRef<[u8]>` -> `&[u8]`) so a generic-but-decodable input fn becomes
    // callable (hex::decode, encode_to_slice). Any other generic — an unrecognized
    // bound, an unbounded `<T>`, or a type used only in the return — is uninferable
    // and rejected (a clean skip), as before.
    let params = monomorphized_params(&args.target)?;
    let body = build_call_body(
        &args.call_path,
        &params,
        args.receiver.as_deref(),
        &args.receiver_ctor_params,
        args.receiver_unwrap,
        &args.param_decoders,
        &args.receiver_ctor_param_decoders,
        args.ufcs_trait.as_deref(),
        args.method_trait_import.as_deref(),
        args.target.is_unsafe,
    )?;
    let harness_rs = render_harness_rs(&body);
    Ok(GeneratedRustHarness {
        harness_rs,
        callable: true,
    })
}

/// Generate a harness that reuses an existing `fuzz_target!` body. The target
/// crate already declares a `pub fn` we can call OR a top-level entry we re-host;
/// the discovery lane points us at the *underlying* `pub fn` the macro calls when
/// one exists, so in practice the existing-harness case still resolves to a
/// `RustCall::Path`. This helper exists for the rare file with no extractable
/// `pub fn`: we wrap the canonical `&[u8]` entry by feeding the whole input.
///
/// `entry_path` is the resolved callable, e.g. `["my_crate", "parse"]`.
pub fn generate_rust_existing_fuzz_target(
    entry_path: &[String],
) -> Result<GeneratedRustHarness, RustGenerateError> {
    // Treat it as a single `&[u8]` parser fed the whole input.
    let single = RustFn {
        name: entry_path.last().cloned().unwrap_or_default(),
        line: 0,
        return_type: None,
        params: vec![RustParam {
            name: "data".to_owned(),
            ty: "&[u8]".to_owned(),
        }],
        is_static: true,
        is_unsafe: false,
        is_unsafe_fn: false,
        visibility: rust_parser::RustVisibility::Pub,
        foreign_guard: None,
        in_fuzz_target: true,
        doc_hidden: false,
        has_type_generics: false,
        type_params: Vec::new(),
        impl_trait: None,
        is_trait_method: false,
        trait_supertrait: None,
    };
    generate_rust_direct_harness(&GenerateRustDirectArgs {
        call_path: entry_path.to_vec(),
        target: single,
        receiver: None,
        receiver_ctor_params: Vec::new(),
        receiver_unwrap: ReceiverUnwrap::Direct,
        param_decoders: Vec::new(),
        receiver_ctor_param_decoders: Vec::new(),
        ufcs_trait: None,
        method_trait_import: None,
    })
}

/// Wrap a `govfuzz_run_one` body in the staticlib crate root. The `#[no_mangle]
/// extern "C"` ABI matches the C driver's `extern int govfuzz_run_one(...)`; a
/// panic in an `extern "C"` fn aborts (cannot unwind), which ASan/abort surfaces
/// to the engine as a crash — exactly like a C sanitizer abort.
fn render_harness_rs(body: &str) -> String {
    format!(
        "// SPDX-License-Identifier: Apache-2.0\n\
         //\n\
         // GENERATED by govfuzz harness_gen::rust_generate. Do not edit.\n\
         //\n\
         // A govfuzz-native Rust fuzzing harness: decodes raw fuzz bytes into\n\
         // typed arguments via `rust_runtime::Cursor` and calls the target.\n\
         // Built as a `staticlib` with rustc-nightly sancov+ASan, then linked\n\
         // with the C fork-server driver (`main.c`). The builtin engine drives it.\n\
         #![allow(unused_imports, unused_variables, unused_mut, dead_code)]\n\
         \n\
         unsafe extern \"C\" {{ fn govfuzz_target_enter(); }}\n\
         \n\
         /// Decode-and-call entry the C driver invokes once per fuzz input.\n\
         /// `data`/`len` borrow the engine's input for the duration of the call.\n\
         #[no_mangle]\n\
         pub extern \"C\" fn govfuzz_run_one(data: *const u8, len: usize) -> i32 {{\n\
         {body}    0\n\
         }}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_parser::{RustParam, RustVisibility};

    fn rust_fn(name: &str, params: &[(&str, &str)], is_static: bool) -> RustFn {
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
            is_static,
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

    #[test]
    fn generic_fn_with_unrecognized_bound_is_rejected_with_clear_reason() {
        // `from_slice<T: Deserialize>` can't be called without naming T (and T is
        // return-only); reject cleanly instead of emitting an uncompilable harness.
        let mut target = rust_fn("from_slice", &[("d", "&[u8]")], true);
        target.has_type_generics = true;
        target.type_params = vec![rust_parser::RustTypeParam {
            name: "T".to_owned(),
            bound: "Deserialize".to_owned(),
        }];
        let args = GenerateRustDirectArgs {
            call_path: vec!["toml".to_owned(), "from_slice".to_owned()],
            target,
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let err = generate_rust_direct_harness(&args).unwrap_err();
        assert!(
            err.reason.contains("byte/str-slice bound"),
            "{}",
            err.reason
        );
    }

    #[test]
    fn byte_slice_bound_generic_is_monomorphized_to_slice() {
        // `hex::decode<T: AsRef<[u8]>>(data: T)` -> call with `data: &[u8]`.
        let mut target = rust_fn("decode", &[("data", "T")], true);
        target.has_type_generics = true;
        target.type_params = vec![rust_parser::RustTypeParam {
            name: "T".to_owned(),
            bound: "AsRef<[u8]>".to_owned(),
        }];
        let args = GenerateRustDirectArgs {
            call_path: vec!["hex".to_owned(), "decode".to_owned()],
            target,
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // `T` was monomorphized to `&[u8]` -> the byte rest channel, passed by ref.
        assert!(h.harness_rs.contains("c.rest_bytes()"), "{}", h.harness_rs);
        assert!(
            h.harness_rs.contains("hex::decode(&a0)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn output_sink_generic_is_monomorphized_to_concrete_sink() {
        // pulldown-cmark-escape shape: `escape<W: fmt::Write>(w: W, s: &str)`. The
        // generic OUTPUT sink `W` was rejected as "uninferable" even though a concrete
        // std sink (String for fmt::Write, Vec<u8> for io::Write) makes it harnessable.
        // Monomorphize W -> String and feed the fuzz input through `s`.
        let mut target = rust_fn("escape", &[("w", "W"), ("s", "&str")], true);
        target.has_type_generics = true;
        target.type_params = vec![rust_parser::RustTypeParam {
            name: "W".to_owned(),
            bound: "fmt::Write".to_owned(),
        }];
        let args = GenerateRustDirectArgs {
            call_path: vec!["esc".to_owned(), "escape".to_owned()],
            target,
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // The &str input still reaches the parser as the rest channel.
        assert!(h.harness_rs.contains("c.rest_string()"), "{}", h.harness_rs);
        assert!(h.harness_rs.contains("esc::escape("), "{}", h.harness_rs);

        // io::Write -> Vec<u8> sink, and a `&mut W` sink shape monomorphizes to a
        // `&mut Vec<u8>` empty sink.
        let mut t2 = rust_fn("write_all", &[("w", "&mut W"), ("data", "&[u8]")], true);
        t2.has_type_generics = true;
        t2.type_params = vec![rust_parser::RustTypeParam {
            name: "W".to_owned(),
            bound: "io::Write".to_owned(),
        }];
        let args2 = GenerateRustDirectArgs {
            call_path: vec!["k".to_owned(), "write_all".to_owned()],
            target: t2,
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h2 = generate_rust_direct_harness(&args2).unwrap();
        assert!(
            h2.harness_rs.contains("Vec::<u8>::new()"),
            "{}",
            h2.harness_rs
        );
        assert!(
            h2.harness_rs.contains("c.rest_bytes()"),
            "{}",
            h2.harness_rs
        );
    }

    #[test]
    fn return_only_byte_slice_generic_is_rejected() {
        // A byte-slice-bounded T that appears ONLY in the return is uninferable.
        let mut target = rust_fn("make", &[("n", "usize")], true);
        target.return_type = Some("T".to_owned());
        target.has_type_generics = true;
        target.type_params = vec![rust_parser::RustTypeParam {
            name: "T".to_owned(),
            bound: "AsRef<[u8]>".to_owned(),
        }];
        let args = GenerateRustDirectArgs {
            call_path: vec!["k".to_owned(), "make".to_owned()],
            target,
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let err = generate_rust_direct_harness(&args).unwrap_err();
        assert!(
            err.reason.contains("does not appear in any input"),
            "{}",
            err.reason
        );
    }

    #[test]
    fn byte_slice_param_consumes_rest_and_is_borrowed() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["mycrate".to_owned(), "parse".to_owned()],
            target: rust_fn("parse", &[("data", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(h.harness_rs.contains("pub extern \"C\" fn govfuzz_run_one"));
        assert!(h.harness_rs.contains("rust_runtime::Cursor::new"));
        assert!(h
            .harness_rs
            .contains("unsafe extern \"C\" { fn govfuzz_target_enter(); }"));
        assert!(h
            .harness_rs
            .contains("unsafe { govfuzz_target_enter(); }\n    let _ = mycrate::parse(&a0);"));
        // The single &[u8] gets the rest of the input and is passed by reference.
        assert!(h.harness_rs.contains("c.rest_bytes()"), "{}", h.harness_rs);
        assert!(
            h.harness_rs.contains("mycrate::parse(&a0)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn mixed_params_only_last_byte_channel_takes_rest() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["c".to_owned(), "f".to_owned()],
            target: rust_fn("f", &[("a", "&[u8]"), ("n", "u32"), ("b", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // a0 is bounded (not rest), a2 is the rest channel.
        assert!(
            h.harness_rs.contains("let mut a0 = c.bytes("),
            "{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("let mut a1 = c.u32();"),
            "{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("let mut a2 = c.rest_bytes();"),
            "{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("c::f(&a0, a1, &a2)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn scalar_only_target_compiles_call() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["k".to_owned(), "g".to_owned()],
            target: rust_fn("g", &[("x", "u8"), ("y", "i64")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(h.harness_rs.contains("let mut a0 = c.u8();"));
        assert!(h.harness_rs.contains("let mut a1 = c.i64();"));
        assert!(h.harness_rs.contains("k::g(a0, a1)"));
    }

    #[test]
    fn zero_param_target_is_callable() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["z".to_owned(), "version".to_owned()],
            target: rust_fn("version", &[], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(h.harness_rs.contains("z::version()"));
    }

    #[test]
    fn method_with_self_and_no_receiver_is_rejected() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["m".to_owned(), "read".to_owned()],
            target: rust_fn("read", &[("data", "&[u8]")], false),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        assert!(generate_rust_direct_harness(&args).is_err());
    }

    #[test]
    fn instance_method_with_receiver_constructs_and_calls() {
        // `&self` method `Parser::feed(&[u8])` with a no-arg `Parser::default()`
        // receiver -> construct then method-call (auto-borrows the receiver).
        let args = GenerateRustDirectArgs {
            call_path: vec!["p".to_owned(), "Parser".to_owned(), "feed".to_owned()],
            target: rust_fn("feed", &[("data", "&[u8]")], false),
            receiver: Some(vec![
                "p".to_owned(),
                "Parser".to_owned(),
                "default".to_owned(),
            ]),
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs
                .contains("let mut recv = p::Parser::default();"),
            "{}",
            h.harness_rs
        );
        assert!(h.harness_rs.contains("recv.feed(&a0)"), "{}", h.harness_rs);
    }

    #[test]
    fn receiver_smart_pointer_ctor_unwraps_to_owned() {
        // A ctor returning Box/Arc/Rc<Self> yields the owned receiver: Box
        // deref-moves; Arc/Rc try_unwrap the freshly-built sole owner. (#452)
        let mk = |unwrap| {
            let args = GenerateRustDirectArgs {
                call_path: vec!["p".to_owned(), "Conn".to_owned(), "poll".to_owned()],
                target: rust_fn("poll", &[("n", "u32")], false),
                receiver: Some(vec!["p".to_owned(), "Conn".to_owned(), "open".to_owned()]),
                receiver_ctor_params: Vec::new(),
                receiver_unwrap: unwrap,
                param_decoders: Vec::new(),
                receiver_ctor_param_decoders: Vec::new(),
                ufcs_trait: None,
                method_trait_import: None,
            };
            generate_rust_direct_harness(&args).unwrap().harness_rs
        };
        assert!(
            mk(ReceiverUnwrap::Boxed).contains("let mut recv = *p::Conn::open();"),
            "{}",
            mk(ReceiverUnwrap::Boxed)
        );
        let arc = mk(ReceiverUnwrap::Arc);
        assert!(
            arc.contains("std::sync::Arc::try_unwrap(p::Conn::open())")
                && arc.contains("Err(_) => return 0"),
            "{arc}"
        );
        let rc = mk(ReceiverUnwrap::Rc);
        assert!(
            rc.contains("std::rc::Rc::try_unwrap(p::Conn::open())") && rc.contains("Ok(r) => r"),
            "{rc}"
        );
    }

    #[test]
    fn receiver_from_fallible_arg_ctor_decodes_args_and_unwraps_result() {
        // roxmltree shape: `Node::lookup_prefix(&self, uri: &str)` with a fallible
        // ctor `Document::parse(text: &str) -> Result<Document>`. The harness decodes
        // the ctor's `text` (bounded) into rc0, unwraps the Result, then calls the
        // method with the rest-channel `uri`.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "roxmltree".to_owned(),
                "Document".to_owned(),
                "lookup_prefix".to_owned(),
            ],
            target: rust_fn("lookup_prefix", &[("uri", "&str")], false),
            receiver: Some(vec![
                "roxmltree".to_owned(),
                "Document".to_owned(),
                "parse".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "text".to_owned(),
                ty: "&str".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Result,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // Ctor arg decoded (bounded) before the receiver is built.
        assert!(h.harness_rs.contains("let mut rc0 ="), "{}", h.harness_rs);
        // Fallible ctor is unwrapped, returning from the harness on Err.
        // `&str` ctor param: `.as_str()` so `From<&str>` calls compile (E0277 fix).
        assert!(
            h.harness_rs.contains(
                "let mut recv = match roxmltree::Document::parse(rc0.as_str()) \
                 { Ok(r) => r, Err(_) => return 0 };"
            ),
            "{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("recv.lookup_prefix(&a0)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn receiver_ctor_arg_uses_override_decoder_by_ref_mut() {
        // httparse shape: `Request::parse(&mut self, buf: &[u8])` whose receiver ctor
        // `Request::new(headers: &mut [Header])` takes a scratch slice that has no byte
        // decoder. The caller supplies a const-scratch override; the harness must build
        // the ctor arg from the override expr passed BY `&mut`, NOT via select_rust_decoder
        // (which would reject `&mut [Header]`).
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "httparse".to_owned(),
                "Request".to_owned(),
                "parse".to_owned(),
            ],
            target: rust_fn("parse", &[("buf", "&[u8]")], false),
            receiver: Some(vec![
                "httparse".to_owned(),
                "Request".to_owned(),
                "new".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "headers".to_owned(),
                ty: "&'h mut [Header<'b>]".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: vec![Some((
                "[httparse::EMPTY_HEADER; 16]".to_owned(),
                ArgPass::RefMut,
            ))],
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // Ctor arg comes from the override expr (not a byte decoder), passed by `&mut`.
        assert!(
            h.harness_rs
                .contains("let mut rc0 = [httparse::EMPTY_HEADER; 16];"),
            "{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs
                .contains("let mut recv = httparse::Request::new(&mut rc0);"),
            "{}",
            h.harness_rs
        );
        assert!(h.harness_rs.contains("recv.parse(&a0)"), "{}", h.harness_rs);
    }

    #[test]
    fn undecodable_param_rejects_candidate() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["q".to_owned(), "build".to_owned()],
            target: rust_fn("build", &[("cfg", "Config")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let err = generate_rust_direct_harness(&args).unwrap_err();
        assert!(err.to_string().contains("Config"));
    }

    #[test]
    fn str_param_uses_rest_string() {
        let args = GenerateRustDirectArgs {
            call_path: vec!["s".to_owned(), "decode".to_owned()],
            target: rust_fn("decode", &[("text", "&str")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(h.harness_rs.contains("c.rest_string()"));
        assert!(h.harness_rs.contains("s::decode(&a0)"));
    }

    #[test]
    fn static_trait_impl_method_is_called_by_ufcs() {
        // byteorder shape: `<byteorder::BigEndian as byteorder::ByteOrder>::read_u32(&a0)`
        // — calling `BigEndian::read_u32(..)` would fail without the trait in scope.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "byteorder".to_owned(),
                "BigEndian".to_owned(),
                "read_u32".to_owned(),
            ],
            target: rust_fn("read_u32", &[("buf", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: Some(vec!["byteorder".to_owned(), "ByteOrder".to_owned()]),
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs
                .contains("<byteorder::BigEndian as byteorder::ByteOrder>::read_u32(&a0)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn ufcs_write_method_backs_output_buffer_not_empty_slice() {
        // byteorder shape: `<BigEndian as ByteOrder>::write_u64(buf: &mut [u8], n: u64)`
        // writes a fixed `buf[..8]` prefix. The `&mut [u8]` output buffer MUST be a
        // sized, zero-padded backing buffer — not the raw fuzz slice, which is empty
        // for short inputs and panics ("range end index 8 out of range for slice of
        // length 0") on EVERY input.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "byteorder".to_owned(),
                "BigEndian".to_owned(),
                "write_u64".to_owned(),
            ],
            target: rust_fn("write_u64", &[("buf", "&mut [u8]"), ("n", "u64")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: Some(vec!["byteorder".to_owned(), "ByteOrder".to_owned()]),
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // The output buffer is a sized, zero-padded backing buffer passed by `&mut`.
        assert!(
            h.harness_rs.contains("_gf_buf.resize(64, 0u8); _gf_buf };"),
            "the &mut [u8] output buffer must be sized + zero-padded:\n{}",
            h.harness_rs
        );
        // It must NOT be backed by the raw fuzz slice (the empty-slice panic source).
        assert!(
            !h.harness_rs.contains("let mut a0 = c.bytes("),
            "the output buffer must not be the raw fuzz slice:\n{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs
                .contains("<byteorder::BigEndian as byteorder::ByteOrder>::write_u64(&mut a0, a1)"),
            "the write call must pass the sized buffer by &mut:\n{}",
            h.harness_rs
        );
        // The value argument still reads from the cursor.
        assert!(
            h.harness_rs.contains("let mut a1 = c.u64();"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn ufcs_on_primitive_impl_type_is_not_module_qualified() {
        // winnow `impl Int for i8` in module `winnow::ascii`: the receiver type is
        // the BARE primitive `i8`, not `winnow::ascii::i8` (which fails to compile).
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "winnow".to_owned(),
                "ascii".to_owned(),
                "i8".to_owned(),
                "try_from_dec_int".to_owned(),
            ],
            target: rust_fn("try_from_dec_int", &[("buf", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: Some(vec![
                "winnow".to_owned(),
                "ascii".to_owned(),
                "Int".to_owned(),
            ]),
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs
                .contains("<i8 as winnow::ascii::Int>::try_from_dec_int("),
            "primitive receiver must be bare `i8`, not module-qualified:\n{}",
            h.harness_rs
        );
        assert!(
            !h.harness_rs.contains("winnow::ascii::i8 as"),
            "must not module-qualify the primitive: {}",
            h.harness_rs
        );
    }

    #[test]
    fn instance_trait_method_imports_its_trait() {
        // bytes shape: `recv.remaining()` from `impl Buf for Bytes` needs `Buf`
        // in scope. The harness emits `use bytes::Buf as _;` (anonymous) so the
        // method-call resolves, then constructs the receiver and calls normally.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "bytes".to_owned(),
                "Bytes".to_owned(),
                "remaining".to_owned(),
            ],
            target: rust_fn("remaining", &[], false),
            receiver: Some(vec![
                "bytes".to_owned(),
                "Bytes".to_owned(),
                "new".to_owned(),
            ]),
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: Some(vec!["bytes".to_owned(), "Buf".to_owned()]),
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs.contains("use bytes::Buf as _;"),
            "instance trait method must bring its trait into scope:\n{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("recv.remaining()"),
            "the call stays method-call syntax:\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn reader_trait_method_uses_cursor_receiver_and_trait_import() {
        // byteorder `ReadBytesExt::read_u32<T: ByteOrder>` shape: the build lane
        // synthesises a `std::io::Cursor::new(fuzz_bytes)` receiver (the ctor arg is
        // a `c.rest_bytes()` override), imports the reader trait, and the
        // marker-turbofish is already baked onto the method segment of `call_path`.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "byteorder".to_owned(),
                "read_u32::<byteorder::BigEndian>".to_owned(),
            ],
            target: rust_fn("read_u32", &[], false),
            receiver: Some(vec![
                "std".to_owned(),
                "io".to_owned(),
                "Cursor".to_owned(),
                "new".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "_gf_reader".to_owned(),
                ty: "Vec<u8>".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: vec![Some(("c.rest_bytes()".to_owned(), ArgPass::Move))],
            ufcs_trait: None,
            method_trait_import: Some(vec!["byteorder".to_owned(), "ReadBytesExt".to_owned()]),
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // The reader is a Cursor wrapping the fuzz bytes.
        assert!(
            h.harness_rs.contains("let mut rc0 = c.rest_bytes();")
                && h.harness_rs
                    .contains("let mut recv = std::io::Cursor::new(rc0);"),
            "reader receiver must be a Cursor over the fuzz bytes:\n{}",
            h.harness_rs
        );
        // The trait is imported so the extension method resolves.
        assert!(
            h.harness_rs.contains("use byteorder::ReadBytesExt as _;"),
            "the reader trait must be brought into scope:\n{}",
            h.harness_rs
        );
        // The method is called on the receiver with its baked turbofish.
        assert!(
            h.harness_rs
                .contains("recv.read_u32::<byteorder::BigEndian>()"),
            "the turbofish method call must dispatch on the Cursor receiver:\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn enum_param_uses_override_decoder_by_move() {
        // A unit-enum param the caller resolved variants for: the override expr
        // replaces the type-based decoder and is passed BY MOVE (no `&`), and the
        // undecodable enum type `AdaStandard` never reaches `select_rust_decoder`.
        let args = GenerateRustDirectArgs {
            call_path: vec!["ada_parser".to_owned(), "lex".to_owned()],
            target: rust_fn("lex", &[("src", "&str"), ("std", "AdaStandard")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: vec![
                None,
                Some((
                    "[ada_parser::ast::AdaStandard::Ada95, \
                     ada_parser::ast::AdaStandard::Ada2012][(c.u8() as usize) % 2]"
                        .to_owned(),
                    ArgPass::Move,
                )),
            ],
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // The &str param still decodes normally (here it is the rest channel).
        assert!(
            h.harness_rs.contains("let mut a0 = c.rest_string();"),
            "{}",
            h.harness_rs
        );
        // The enum param uses the override expr verbatim.
        assert!(
            h.harness_rs
                .contains("let mut a1 = [ada_parser::ast::AdaStandard::Ada95"),
            "{}",
            h.harness_rs
        );
        // The enum value is passed by move (no leading `&`).
        assert!(
            h.harness_rs.contains("ada_parser::lex(&a0, a1)"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn existing_fuzz_target_wraps_byte_entry() {
        let h = generate_rust_existing_fuzz_target(&["fix".to_owned(), "run".to_owned()]).unwrap();
        assert!(h.harness_rs.contains("fix::run(&a0)"));
        assert!(h.harness_rs.contains("c.rest_bytes()"));
    }

    fn rust_fn_unsafe(name: &str, params: &[(&str, &str)], is_static: bool) -> RustFn {
        RustFn {
            is_unsafe: true,
            is_unsafe_fn: true,
            ..rust_fn(name, params, is_static)
        }
    }

    #[test]
    fn unsafe_fn_call_is_wrapped_in_unsafe_block() {
        // `pub unsafe fn from_slice(data: &[u8])` → call must be `unsafe { ... }`.
        let args = GenerateRustDirectArgs {
            call_path: vec![
                "json".to_owned(),
                "short".to_owned(),
                "Short".to_owned(),
                "from_slice".to_owned(),
            ],
            target: rust_fn_unsafe("from_slice", &[("data", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs.contains("unsafe {"),
            "expected `unsafe {{` in harness:\n{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs
                .contains("unsafe { json::short::Short::from_slice(&a0) }"),
            "expected wrapped call in harness:\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn safe_fn_call_has_no_unsafe_block() {
        // A normal `pub fn` must NOT gain a spurious `unsafe` block around the call.
        // (The template header always has `unsafe { core::slice::from_raw_parts }`,
        // so we look for `unsafe { mycrate::` to distinguish call-site wrapping.)
        let args = GenerateRustDirectArgs {
            call_path: vec!["mycrate".to_owned(), "parse".to_owned()],
            target: rust_fn("parse", &[("data", "&[u8]")], true),
            receiver: None,
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            !h.harness_rs.contains("unsafe { mycrate::"),
            "spurious `unsafe {{` around call in harness:\n{}",
            h.harness_rs
        );
        assert!(
            h.harness_rs.contains("let _ = mycrate::parse(&a0);"),
            "{}",
            h.harness_rs
        );
    }

    #[test]
    fn unsafe_instance_method_call_is_wrapped() {
        // `pub unsafe fn method(&self, n: u32)` on a receiver → still wraps the call.
        let args = GenerateRustDirectArgs {
            call_path: vec!["p".to_owned(), "Buf".to_owned(), "write_raw".to_owned()],
            target: rust_fn_unsafe("write_raw", &[("n", "u32")], false),
            receiver: Some(vec!["p".to_owned(), "Buf".to_owned(), "new".to_owned()]),
            receiver_ctor_params: Vec::new(),
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs.contains("unsafe { recv.write_raw(a0) }"),
            "expected wrapped method call:\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn from_str_receiver_ctor_emits_as_str_not_ref_string() {
        // json-rust shape: `impl From<&str> for JsonValue { fn from(v: &str) -> Self }`.
        // The generated ctor call must be `JsonValue::from(rc0.as_str())`, NOT
        // `JsonValue::from(&rc0)` (which passes `&String` and fails E0277 because
        // generic `From<T>` doesn't coerce `&String → &str` at the type-inference site).
        let args = GenerateRustDirectArgs {
            call_path: vec!["json".to_owned(), "JsonValue".to_owned(), "eq".to_owned()],
            target: rust_fn("eq", &[("other", "&str")], false),
            receiver: Some(vec![
                "json".to_owned(),
                "JsonValue".to_owned(),
                "from".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "v".to_owned(),
                ty: "&str".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // Ctor arg must use `.as_str()`, NOT `&rc0` (which would be `&String`).
        assert!(
            h.harness_rs.contains("json::JsonValue::from(rc0.as_str())"),
            "expected `rc0.as_str()` in ctor call:\n{}",
            h.harness_rs
        );
        assert!(
            !h.harness_rs.contains("from(&rc0)"),
            "must NOT emit `from(&rc0)` (that's `&String`, not `&str`):\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn from_bytes_receiver_ctor_emits_as_slice_not_ref_vec() {
        // Similar to the `&str` case: `impl From<&[u8]> for Foo` must emit
        // `rc0.as_slice()` so the type is `&[u8]`, not `&Vec<u8>`.
        let args = GenerateRustDirectArgs {
            call_path: vec!["crate".to_owned(), "Foo".to_owned(), "process".to_owned()],
            target: rust_fn("process", &[("n", "u32")], false),
            receiver: Some(vec![
                "crate".to_owned(),
                "Foo".to_owned(),
                "from".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "bytes".to_owned(),
                ty: "&[u8]".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        assert!(
            h.harness_rs.contains("crate::Foo::from(rc0.as_slice())"),
            "expected `rc0.as_slice()` in ctor call:\n{}",
            h.harness_rs
        );
        assert!(
            !h.harness_rs.contains("from(&rc0)"),
            "must NOT emit `from(&rc0)` (that's `&Vec<u8>`, not `&[u8]`):\n{}",
            h.harness_rs
        );
    }

    #[test]
    fn from_string_receiver_ctor_still_moves_not_as_str() {
        // `impl From<String> for JsonValue` — the param is owned `String`, passed
        // by Move. Must NOT call `.as_str()` — that changes the semantics.
        let args = GenerateRustDirectArgs {
            call_path: vec!["json".to_owned(), "JsonValue".to_owned(), "eq".to_owned()],
            target: rust_fn("eq", &[("other", "&str")], false),
            receiver: Some(vec![
                "json".to_owned(),
                "JsonValue".to_owned(),
                "from".to_owned(),
            ]),
            receiver_ctor_params: vec![RustParam {
                name: "v".to_owned(),
                ty: "String".to_owned(),
            }],
            receiver_unwrap: ReceiverUnwrap::Direct,
            param_decoders: Vec::new(),
            receiver_ctor_param_decoders: Vec::new(),
            ufcs_trait: None,
            method_trait_import: None,
        };
        let h = generate_rust_direct_harness(&args).unwrap();
        // `String` is passed by Move — the binding IS the arg.
        assert!(
            h.harness_rs.contains("json::JsonValue::from(rc0)"),
            "expected `from(rc0)` (owned String, by move):\n{}",
            h.harness_rs
        );
        assert!(
            !h.harness_rs.contains("as_str()"),
            "must NOT call `.as_str()` for an owned String ctor param:\n{}",
            h.harness_rs
        );
    }
}
