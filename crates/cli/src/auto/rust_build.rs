// SPDX-License-Identifier: Apache-2.0

//! Native Rust fuzzing lane: generate a govfuzz harness, build it as a
//! sancov+ASan `staticlib` with rustc-nightly, and clang-link it with the shared
//! C fork-server driver so the builtin engine drives it persistently — the same
//! execution path as C/C++ (M1.2).
//!
//! The pipeline, given a discovered Rust `Candidate`:
//!
//! 1. **Toolchain probe** — `cargo`/`rustc` + a working `+nightly` with the
//!    sancov/ASan flags. No nightly -> skip the lane cleanly (the GNAT-less rule).
//! 2. **Resolve the call** — re-parse the target source, find the target fn, and
//!    compute its fully-qualified path (`crate::module::fn` or
//!    `crate::Type::assoc_fn`) plus the target crate's manifest dir.
//! 3. **Emit** — a staticlib harness crate (`Cargo.toml` + `harness.rs` from
//!    `harness_gen::rust_generate`) that path-depends on the target crate and
//!    `rust_runtime`, plus a copy of `c_runtime/govfuzz_driver.c` renamed
//!    `main.c` (the engine greps the sibling source for `GOVFUZZ_FRAMED`).
//! 4. **Build** — `cargo +nightly build` the staticlib with the sancov+ASan
//!    RUSTFLAGS, then `clang` link the produced `.a` + `main.c` ->
//!    `<work>/harnesses/<id>/main`, the path the engine's `find_harness_executable`
//!    looks for.

use crate::auto::candidate::Candidate;
use build_classifier::cargo::{classify, RustBuildError};
use harness_gen::rust_generate::{
    generate_rust_direct_harness, generate_rust_existing_fuzz_target, GenerateRustDirectArgs,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Outcome of the native Rust build lane.
pub enum RustBuildResult {
    /// `<work>/harnesses/<id>/main` was produced and is ready to fuzz.
    Built,
    /// The lane could not run / the harness could not build. `reason` is a
    /// human-actionable summary; `skip` is true when the cause is a missing
    /// toolchain or an un-harnessable target (skip cleanly), false for a genuine
    /// build error worth surfacing.
    Failed { reason: String, skip: bool },
}

/// The resolved nightly toolchain channel argument (`+nightly`, or a pinned
/// nightly like `+nightly-2026-06-10`) plus the discovered `cargo` binary.
struct RustToolchain {
    cargo: PathBuf,
    /// e.g. `+nightly` — passed as the first arg to cargo/rustc.
    channel_arg: String,
    /// The host target triple (e.g. `x86_64-unknown-linux-gnu`). We build with an
    /// explicit `--target <host>` so cargo compiles build scripts + proc-macro
    /// crates (e.g. `zerofrom_derive`) for the host WITHOUT the sanitizer
    /// RUSTFLAGS — sanitizers can't be applied to host-run proc-macros. Target
    /// crates still get the sancov+ASan flags. Artifacts then live under
    /// `target/<triple>/debug/` rather than `target/debug/`.
    host_triple: String,
}

/// Parse the `host: <triple>` line out of `cargo -vV` / `rustc -vV` output.
fn parse_host_triple(version_verbose: &str) -> Option<String> {
    version_verbose
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|t| t.trim().to_owned())
}

/// Probe for a usable Rust toolchain with nightly sancov support. Returns `None`
/// (skip the lane) when cargo is absent or no nightly is installed.
fn probe_toolchain() -> Option<RustToolchain> {
    let cargo = which::which("cargo").ok()?;
    // Prefer the plain `+nightly` channel; rustup resolves it. Confirm a nightly
    // rustc actually exists by asking for its verbose version through cargo's
    // proxy — `-vV` also gives us the `host:` triple we need for `--target`.
    let probe = Command::new(&cargo)
        .arg("+nightly")
        .arg("-vV")
        .output()
        .ok()?;
    if probe.status.success() {
        let stdout = String::from_utf8_lossy(&probe.stdout);
        let host_triple = parse_host_triple(&stdout)?;
        return Some(RustToolchain {
            cargo,
            channel_arg: "+nightly".to_owned(),
            host_triple,
        });
    }
    None
}

/// RUSTFLAGS arming SanitizerCoverage (trace-pc-guard + trace-compares) and ASan
/// on the harness + target crates, matching the symbols the C driver provides.
/// VERIFIED to emit `__sanitizer_cov_trace_pc_guard{,_init}` and the `trace_cmp*`
/// references the driver defines.
fn sancov_rustflags() -> String {
    [
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=4",
        "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
        "-Zsanitizer=address",
    ]
    .join(" ")
}

/// Walk up from `source` to the nearest directory containing a `Cargo.toml`;
/// that is the target crate's manifest dir.
fn find_crate_root(source: &Path) -> Option<PathBuf> {
    let mut dir = source.parent();
    while let Some(d) = dir {
        if d.join("Cargo.toml").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

/// Extract the crate's import name from its `Cargo.toml`. Prefers an explicit
/// `[lib] name`, else `[package] name` with `-` normalized to `_` (the Rust
/// import-name rule).
fn crate_import_name(manifest_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).ok()?;
    // A crude but robust TOML scan: find `[lib]` then its `name`, else
    // `[package]` then its `name`. Avoids pulling a TOML dep into the CLI.
    let lib_name = section_value(&text, "lib", "name");
    if let Some(n) = lib_name {
        return Some(n.replace('-', "_"));
    }
    let pkg_name = section_value(&text, "package", "name")?;
    Some(pkg_name.replace('-', "_"))
}

/// The target crate's RAW `[package] name` (e.g. `data-url`, NOT normalized). Used
/// as a dependency `package = …` rename so cargo resolves a hyphenated package
/// while the harness source imports it by the `_`-normalized name. `None` if
/// unreadable.
fn crate_package_name(manifest_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).ok()?;
    section_value(&text, "package", "name")
}

/// Find `key = "value"` within the `[section]` table of a simple Cargo.toml.
fn section_value(toml: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in toml.lines() {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            in_section = l == format!("[{section}]");
            continue;
        }
        if in_section {
            if let Some(rest) = l.strip_prefix(key) {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let v = rest.trim().trim_matches('"').to_owned();
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Read the crate root source (`src/lib.rs`, else `src/main.rs`) for scanning
/// the public re-export façade. Empty string if neither is readable.
fn read_crate_root_src(manifest_dir: &Path) -> String {
    let src = manifest_dir.join("src");
    for f in ["lib.rs", "main.rs"] {
        if let Ok(t) = std::fs::read_to_string(src.join(f)) {
            return t;
        }
    }
    String::new()
}

/// True when the crate root re-exports `name` into the crate's top-level
/// namespace via a `pub use` (so it is reachable as `crate::Name`). The dominant
/// Rust facade pattern is a private `mod inner;` plus `pub use inner::Thing;` —
/// consumers must use `crate::Thing`, not `crate::inner::Thing` (a private
/// module). `pub(crate) use` / `pub(super) use` are NOT public re-exports.
fn crate_root_reexports(crate_root_src: &str, name: &str) -> bool {
    pub_use_trees(crate_root_src)
        .iter()
        .flat_map(|tree| reexported_idents(tree))
        .any(|id| id == name)
}

/// True when the crate root directly defines `name` as an externally-public
/// item: `pub struct NAME`, `pub enum NAME`, `pub trait NAME`, `pub type NAME`,
/// `pub union NAME`, or `pub fn NAME`. Handles generic parameters
/// (`pub struct Foo<'a>` → `Foo`). Excludes `pub(crate)` / `pub(super)` /
/// `pub(in …)` which are NOT externally public.
///
/// Used to detect the case where a type's `impl` block lives in a private
/// `mod` but the type itself is declared at the crate root: inherent methods
/// are reachable through the type (`crate::Foo::method`) with no `pub use`
/// re-export needed.
fn crate_root_defines_pub(crate_root_src: &str, name: &str) -> bool {
    // Track impl/trait block nesting by brace depth so an ASSOCIATED `pub fn`/`pub
    // type`/`pub const` inside an `impl`/`trait` body is NOT mistaken for a crate-root
    // item (data-url: an inherent `impl DataUrl { pub fn decode_to_vec }` must not make
    // the submodule free fn `decode_to_vec` resolve to the bare crate-root path).
    let mut block_is_impl_trait: Vec<bool> = Vec::new();
    let mut pending_impl_trait = false;
    for raw in crate_root_src.lines() {
        let line = strip_line_comment(raw);
        let l = line.trim();
        let inside_impl_trait = block_is_impl_trait.iter().any(|&b| b);

        if let Some((item_name, is_assoc_kind)) = root_pub_item(l) {
            // An associated-kind item (fn / type / const) inside an impl/trait body is
            // not reachable as a bare crate-root name — ignore it. Type-defining items
            // (struct/enum/trait/union) can't appear inside an impl, so they always count.
            if !(inside_impl_trait && is_assoc_kind) && item_name == name {
                return true;
            }
        }

        // An `impl`/`trait` declaration's body brace makes everything inside it an
        // associated context. The brace may be on this line or a following one.
        if line_starts_impl_or_trait(l) {
            pending_impl_trait = true;
        }
        for ch in l.chars() {
            match ch {
                '{' => {
                    block_is_impl_trait.push(pending_impl_trait);
                    pending_impl_trait = false;
                }
                '}' => {
                    block_is_impl_trait.pop();
                }
                _ => {}
            }
        }
    }
    false
}

/// If `l` (a trimmed source line) declares an externally-`pub` item at the start,
/// return its `(name, is_assoc_kind)` — `is_assoc_kind` is true for `fn`/`type`/
/// `const` (items that may also appear as ASSOCIATED items inside an impl/trait).
/// Excludes `pub(crate)`/`pub(super)`/`pub(in …)`.
fn root_pub_item(l: &str) -> Option<(&str, bool)> {
    let rest = l.strip_prefix("pub ")?;
    if rest.starts_with('(') {
        return None;
    }
    let (kw, after) = [
        "struct ", "enum ", "trait ", "type ", "union ", "fn ", "const ",
    ]
    .iter()
    .find_map(|kw| rest.strip_prefix(kw).map(|a| (*kw, a)))?;
    let item_name = after
        .split(|c: char| {
            c == '<'
                || c == '('
                || c == '{'
                || c == ';'
                || c == ':'
                || c == '='
                || c.is_whitespace()
        })
        .next()
        .unwrap_or("");
    if item_name.is_empty() {
        return None;
    }
    Some((item_name, matches!(kw, "fn " | "type " | "const ")))
}

/// True when a trimmed line begins an `impl` or `trait` declaration (after stripping
/// `pub`/`pub(..)`/`unsafe`/`default`/`async` modifiers). The declaration's `{` opens
/// an associated-item context.
fn line_starts_impl_or_trait(l: &str) -> bool {
    let mut s = l.trim();
    loop {
        let before = s;
        for p in ["pub ", "unsafe ", "default ", "async "] {
            if let Some(r) = s.strip_prefix(p) {
                s = r.trim_start();
            }
        }
        if let Some(rest) = s.strip_prefix("pub(") {
            if let Some(idx) = rest.find(')') {
                s = rest[idx + 1..].trim_start();
            }
        }
        if s == before {
            break;
        }
    }
    let head = s
        .split(|c: char| c.is_whitespace() || c == '<' || c == '{')
        .next()
        .unwrap_or("");
    head == "impl" || head == "trait"
}

/// Module names that the crate root re-exports via a glob `pub use <path>::*;`.
/// For `pub use crate::parse::*;` returns `"parse"`. Used to detect when a
/// type (or its impl block's source module) is made accessible at the crate
/// root through a glob without an explicit named re-export.
fn glob_reexported_modules(crate_root_src: &str) -> Vec<String> {
    pub_use_trees(crate_root_src)
        .into_iter()
        .filter_map(|tree| {
            if !tree.ends_with("::*") {
                return None;
            }
            // Strip `::*` and take the last path segment as the module name.
            let prefix = &tree[..tree.len() - 3];
            let seg = prefix.rsplit("::").next().unwrap_or(prefix).trim();
            if seg.is_empty() || seg == "crate" || seg == "self" {
                return None;
            }
            Some(seg.to_owned())
        })
        .collect()
}

/// True when `name` (a type or function identifier) is reachable at the crate
/// root — i.e. a dependent crate can use `crate::Name` without going through a
/// private module. Three sufficient conditions (any one is enough):
///
///   1. Named `pub use` re-export: `pub use <path>::Name;` in lib.rs
///   2. Type defined directly at the crate root: `pub struct Name` in lib.rs
///   3. Impl module glob-re-exported: `pub use crate::<impl_module>::*;` in
///      lib.rs, where `impl_module` is the module segment that contains the
///      function's impl block (the type itself may be defined at root, but the
///      glob also makes other pub items from that module reachable).
///
/// `impl_module` should be the first path segment of the source file's module
/// (e.g. `"parse"` for `src/parse.rs`); pass `""` to skip check (3).
///
/// `pub(crate) use` is correctly excluded by `crate_root_reexports`.
fn type_reachable_at_crate_root(crate_root_src: &str, name: &str, impl_module: &str) -> bool {
    if crate_root_reexports(crate_root_src, name) {
        return true;
    }
    if crate_root_defines_pub(crate_root_src, name) {
        return true;
    }
    if !impl_module.is_empty()
        && glob_reexported_modules(crate_root_src)
            .iter()
            .any(|m| m == impl_module)
    {
        return true;
    }
    false
}

/// Collect the use-tree text (everything between `pub use ` and `;`) of each
/// top-level `pub use` statement, joining multi-line `{ ... }` groups.
fn pub_use_trees(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc: Option<String> = None;
    for raw in src.lines() {
        let line = strip_line_comment(raw);
        let trimmed = line.trim();
        if let Some(buf) = acc.as_mut() {
            buf.push(' ');
            buf.push_str(trimmed);
            if trimmed.contains(';') {
                let stmt = acc.take().unwrap();
                out.push(stmt);
            }
            continue;
        }
        // Exactly `pub use ` — not `pub(crate) use` / `pub(super) use`.
        if let Some(rest) = trimmed.strip_prefix("pub use ") {
            let rest = rest.trim();
            if rest.contains(';') {
                out.push(rest.to_owned());
            } else {
                acc = Some(rest.to_owned());
            }
        }
    }
    out.into_iter()
        .map(|s| s.split(';').next().unwrap_or(&s).trim().to_owned())
        .collect()
}

/// Identifiers a `pub use` tree introduces at its level: `a::b::C` -> `C`,
/// `a::{C, D as E}` -> `C, E`, `x` -> `x`. Globs and `self` yield nothing.
fn reexported_idents(tree: &str) -> Vec<String> {
    let tree = tree.trim();
    if let Some(brace_open) = tree.find('{') {
        let inner_end = tree.rfind('}').unwrap_or(tree.len());
        let inner = &tree[brace_open + 1..inner_end];
        inner.split(',').filter_map(leaf_ident).collect()
    } else {
        leaf_ident(tree).into_iter().collect()
    }
}

/// The identifier a single use-tree leaf binds: the alias after `as`, else the
/// last `::` segment. `None` for `*`, empty, or `self`.
fn leaf_ident(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Some(idx) = entry.find(" as ") {
        return ident_or_none(entry[idx + 4..].trim());
    }
    let last = entry.rsplit("::").next().unwrap_or(entry).trim();
    ident_or_none(last)
}

fn ident_or_none(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s == "*" || s == "self" {
        return None;
    }
    match s.chars().next() {
        Some(c) if c.is_alphabetic() || c == '_' => Some(s.to_owned()),
        _ => None,
    }
}

/// True when the crate root declares `seg` as a PRIVATE module (`mod seg;` /
/// `mod seg {`, not `pub mod`). Used (RC5) to skip a type in a private,
/// non-re-exported module that a dependent crate cannot reach (E0603).
fn module_declared_private(crate_root_src: &str, seg: &str) -> bool {
    for raw in crate_root_src.lines() {
        let line = strip_line_comment(raw);
        let l = line.trim();
        // A `pub mod seg` / `pub(crate) mod seg` is not the private form.
        if l.starts_with("pub ") {
            continue;
        }
        if let Some(rest) = l.strip_prefix("mod ") {
            let name = rest
                .split(|c: char| c == ';' || c == '{' || c.is_whitespace())
                .next()
                .unwrap_or("");
            if name == seg {
                return true;
            }
        }
    }
    false
}

/// True when ANY module segment in the path is declared PRIVATE in its parent
/// module (`mod seg;` not `pub mod seg`). Walks the whole chain — not just the
/// first segment at the crate root — by reading each parent module's source
/// (`<prefix>/<seg>.rs` or `<prefix>/<seg>/mod.rs`). A private link anywhere makes
/// a non-re-exported type unreachable from a dependent crate (E0603). (RC fix.)
fn module_chain_has_private(manifest_dir: &Path, crate_root_src: &str, module: &[String]) -> bool {
    let mut parent_src = crate_root_src.to_owned();
    let mut prefix = manifest_dir.join("src");
    for (i, seg) in module.iter().enumerate() {
        if module_declared_private(&parent_src, seg) {
            return true;
        }
        if i + 1 < module.len() {
            let as_file = prefix.join(format!("{seg}.rs"));
            let as_mod = prefix.join(seg).join("mod.rs");
            parent_src = std::fs::read_to_string(&as_file)
                .or_else(|_| std::fs::read_to_string(&as_mod))
                .unwrap_or_default();
            prefix = prefix.join(seg);
        }
    }
    false
}

/// True when `seg` is declared a fully PUBLIC module (`pub mod seg;` / `pub mod
/// seg {`) in `parent_src` — exactly `pub`, not `pub(crate)` / `pub(super)` /
/// private. The complement of `module_declared_private`'s scope: only a `pub mod`
/// chain is reachable from a dependent crate without a re-export.
fn module_declared_pub(parent_src: &str, seg: &str) -> bool {
    for raw in parent_src.lines() {
        let line = strip_line_comment(raw);
        let l = line.trim();
        let Some(rest) = l.strip_prefix("pub mod ") else {
            continue;
        };
        let name = rest
            .split(|c: char| c == ';' || c == '{' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if name == seg {
            return true;
        }
    }
    false
}

/// True when EVERY segment of `prefix` is a `pub mod` in its parent (so the whole
/// module chain is reachable from a dependent crate). Empty prefix (the crate
/// root) is trivially public. Reads each parent module's source to walk the chain.
fn module_chain_all_pub(manifest_dir: &Path, crate_root_src: &str, prefix: &[String]) -> bool {
    let mut parent_src = crate_root_src.to_owned();
    let mut path = manifest_dir.join("src");
    for (i, seg) in prefix.iter().enumerate() {
        if !module_declared_pub(&parent_src, seg) {
            return false;
        }
        if i + 1 < prefix.len() {
            let as_file = path.join(format!("{seg}.rs"));
            let as_mod = path.join(seg).join("mod.rs");
            parent_src = std::fs::read_to_string(&as_file)
                .or_else(|_| std::fs::read_to_string(&as_mod))
                .unwrap_or_default();
            path = path.join(seg);
        }
    }
    true
}

/// Read the source of the module at `prefix` within the crate. Empty prefix ->
/// the crate root source; otherwise `src/<a>/.../<last>.rs` or
/// `src/<a>/.../<last>/mod.rs`.
fn read_module_src(manifest_dir: &Path, crate_root_src: &str, prefix: &[String]) -> String {
    let Some((last, parents)) = prefix.split_last() else {
        return crate_root_src.to_owned();
    };
    let mut path = manifest_dir.join("src");
    for seg in parents {
        path = path.join(seg);
    }
    let as_file = path.join(format!("{last}.rs"));
    let as_mod = path.join(last).join("mod.rs");
    std::fs::read_to_string(&as_file)
        .or_else(|_| std::fs::read_to_string(&as_mod))
        .unwrap_or_default()
}

/// Split a `::`-separated path into trimmed, non-empty segments.
fn split_path(s: &str) -> Vec<String> {
    s.split("::")
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect()
}

/// For a single `pub use` tree (the text between `pub use ` and `;`), return its
/// (module-prefix segments, re-exported leaf idents, is_glob). `raw::RawValue` ->
/// `(["raw"], ["RawValue"], false)`; `a::{B, C as D}` -> `(["a"], ["B", "D"],
/// false)`; `raw::*` -> `(["raw"], [], true)`.
fn pub_use_prefix_and_idents(tree: &str) -> (Vec<String>, Vec<String>, bool) {
    let tree = tree.trim();
    if let Some(brace) = tree.find('{') {
        let prefix = split_path(tree[..brace].trim().trim_end_matches("::"));
        (prefix, reexported_idents(tree), false)
    } else if let Some(stripped) = tree.strip_suffix("::*") {
        (split_path(stripped.trim()), Vec::new(), true)
    } else if tree == "*" {
        (Vec::new(), Vec::new(), true)
    } else {
        let idents = reexported_idents(tree);
        // The leaf is the last `::` segment of the path BEFORE any `as` alias.
        let before_as = tree.split(" as ").next().unwrap_or(tree).trim();
        let segs = split_path(before_as);
        let prefix = if segs.len() > 1 {
            segs[..segs.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        (prefix, idents, false)
    }
}

/// Normalize a `pub use` prefix (as written in the module at `ancestor`) to a path
/// RELATIVE to that ancestor module. A leading `self::` is stripped; `crate::` (or
/// an explicit crate-name prefix) strips the crate root + the ancestor segments; a
/// leading `super::` is ambiguous (-> `None`, skip). Anything else is already
/// ancestor-relative.
fn normalize_reexport_prefix(
    prefix: &[String],
    crate_name: &str,
    ancestor: &[String],
) -> Option<Vec<String>> {
    let Some(first) = prefix.first() else {
        return Some(Vec::new());
    };
    match first.as_str() {
        "self" => Some(prefix[1..].to_vec()),
        "super" => None,
        "crate" => strip_ancestor(&prefix[1..], ancestor),
        f if f == crate_name => strip_ancestor(&prefix[1..], ancestor),
        _ => Some(prefix.to_vec()),
    }
}

/// Strip a leading `ancestor` run from `segs`, returning the remainder; `None` when
/// `segs` doesn't begin with `ancestor`.
fn strip_ancestor(segs: &[String], ancestor: &[String]) -> Option<Vec<String>> {
    if segs.len() >= ancestor.len() && segs[..ancestor.len()] == *ancestor {
        Some(segs[ancestor.len()..].to_vec())
    } else {
        None
    }
}

/// F5: find the SHORTEST PUBLIC path to type `ty` (defined in canonical module
/// `module`) via a `pub use` re-export, for when the type's canonical module path
/// traverses a non-public (`pub(crate)` / `pub(super)` / private) module. ron
/// defines `RawValue` in `value::raw` (`pub(crate) mod raw`) and re-exports it
/// `pub use raw::RawValue;` from `value/mod.rs`, so the public path is
/// `ron::value::RawValue` (the canonical `ron::value::raw::RawValue` is E0603 —
/// the compiler itself suggests `ron::value::RawValue`). Returns the full call
/// path `[crate_name, ..ancestor.., ty]` (shortest first), or `None` when no
/// public re-export reaches `ty` (the caller then keeps the existing skip/path
/// behavior — genuine private-module types still skip cleanly).
fn resolve_public_reexport_path(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    module: &[String],
    ty: &str,
) -> Option<Vec<String>> {
    if module.is_empty() {
        return None; // already at the crate root — handled by the normal path
    }
    // Try ancestor prefixes shortest-first (k=0 is the crate root).
    for k in 0..module.len() {
        let ancestor = &module[..k];
        if !module_chain_all_pub(manifest_dir, crate_root_src, ancestor) {
            continue; // the public path through this ancestor isn't reachable
        }
        let ancestor_src = read_module_src(manifest_dir, crate_root_src, ancestor);
        let rel = &module[k..]; // path from the ancestor down to ty's defining module
        for tree in pub_use_trees(&ancestor_src) {
            let (prefix, idents, is_glob) = pub_use_prefix_and_idents(&tree);
            let Some(norm) = normalize_reexport_prefix(&prefix, crate_name, ancestor) else {
                continue;
            };
            if norm != *rel {
                continue;
            }
            // A named re-export of `ty`, or a glob over its defining module (the
            // type is public — its impl is on a pub type — so the glob exposes it).
            if is_glob || idents.iter().any(|id| id == ty) {
                let mut path = vec![crate_name.to_owned()];
                path.extend(ancestor.iter().cloned());
                path.push(ty.to_owned());
                return Some(path);
            }
        }
    }
    None
}

/// A receiver constructor resolved for an instance method: its name, the params
/// to decode, and how its return value unwraps to the receiver.
struct ReceiverCtor {
    name: String,
    params: Vec<rust_parser::RustParam>,
    unwrap: harness_gen::rust_generate::ReceiverUnwrap,
}

/// Peel a single receiver wrapper (`Result`/`Option`/`Box`/`Arc`/`Rc`, possibly
/// path-qualified like `std::sync::Arc`) off a ctor return type, returning the
/// unwrap that yields the owned receiver plus the inner type string. An
/// unwrapped or unrecognized return yields `Direct` + the whole trimmed string.
fn peel_ctor_wrapper(rt: &str) -> (harness_gen::rust_generate::ReceiverUnwrap, &str) {
    use harness_gen::rust_generate::ReceiverUnwrap;
    let rt = rt.trim();
    let Some(open) = rt.find('<') else {
        return (ReceiverUnwrap::Direct, rt);
    };
    let wrapper = rt[..open].trim();
    let wrapper = wrapper.rsplit("::").next().unwrap_or(wrapper).trim();
    let kind = match wrapper {
        "Result" => ReceiverUnwrap::Result,
        "Option" => ReceiverUnwrap::Option,
        "Box" => ReceiverUnwrap::Boxed,
        "Arc" => ReceiverUnwrap::Arc,
        "Rc" => ReceiverUnwrap::Rc,
        // A generic on the type itself (`Document<'a>`) is not a wrapper.
        _ => return (ReceiverUnwrap::Direct, rt),
    };
    let inner = rt[open + 1..]
        .trim()
        .strip_suffix('>')
        .unwrap_or(&rt[open + 1..])
        .trim();
    (kind, inner)
}

/// How a ctor's return type yields the receiver: a `Result`/`Option`/`Box`/`Arc`/
/// `Rc` unwrap, or `Direct` for a bare `Self`/`ty`.
fn ctor_unwrap(return_type: &Option<String>) -> harness_gen::rust_generate::ReceiverUnwrap {
    use harness_gen::rust_generate::ReceiverUnwrap;
    return_type
        .as_deref()
        .map(|rt| peel_ctor_wrapper(rt).0)
        .unwrap_or(ReceiverUnwrap::Direct)
}

/// True when `return_type` constructs `ty`: it is `Self` / `ty`, or a single
/// `Result`/`Option`/`Box`/`Arc`/`Rc` wrapper whose inner leading type is
/// `Self` / `ty`. This is what makes an associated fn a usable receiver ctor.
fn ctor_returns_self(return_type: &Option<String>, ty: &str) -> bool {
    let Some(rt) = return_type.as_deref() else {
        return false;
    };
    let (_, inner) = peel_ctor_wrapper(rt);
    // The leading type token (up to `<`, `,`, `>`, whitespace).
    let head = inner
        .trim_start()
        .split(|c: char| c == '<' || c == ',' || c == '>' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    // Strip a path prefix so `crate::Document` / `self::Document` match `Document`.
    let head = head.rsplit("::").next().unwrap_or(head);
    head == "Self" || head == ty
}

/// All params decode through the standard byte decoders, are scratch slices
/// fillable via a const/Default override (`Request::new(&mut [Header])` filled with
/// `[httparse::EMPTY_HEADER; 16]`), or are resolvable via a param override
/// (`is_overridable` — e.g. a reachable unit `enum` decoded as a fuzz-byte variant
/// pick), so the ctor can be driven from the cursor. Scratch args whose fill can't
/// actually be resolved are dropped later in `resolve_target` (the receiver is then
/// discarded and the method skips).
fn ctor_args_decodable(f: &rust_parser::RustFn, is_overridable: &dyn Fn(&str) -> bool) -> bool {
    f.type_params.is_empty()
        && f.params.iter().all(|p| {
            harness_gen::rust_decoders::select_rust_decoder(&p.ty).is_ok()
                || scratch_slice(&p.ty).is_some()
                || is_overridable(&p.ty)
        })
}

/// Find a receiver constructor on `ty` for an instance method. Prefers a no-arg
/// `new()` / `Default` (RC1); otherwise an ARG-TAKING associated fn that
/// constructs `ty` (`Document::parse(&str) -> Result<Document>`,
/// `Finder::new(&[u8])`) whose args are all decodable — the ctor args are decoded
/// from the cursor and a fallible `Result`/`Option` is unwrapped. `None` when no
/// usable constructor exists (the instance method is then skipped).
fn find_receiver_ctor(
    source: &str,
    fns: &[rust_parser::RustFn],
    ty: &str,
    is_overridable: &dyn Fn(&str) -> bool,
) -> Option<ReceiverCtor> {
    use harness_gen::rust_generate::ReceiverUnwrap;
    // A `pub`, static fn on `ty`, reachable from a dependent crate.
    let on_ty = |f: &&rust_parser::RustFn| {
        f.is_static
            && matches!(f.visibility, rust_parser::RustVisibility::Pub)
            && enclosing_impl_type(source, f.line).as_deref() == Some(ty)
    };

    // An `unsafe fn` constructor cannot back a receiver: the generated
    // `let recv = Type::ctor(...)` is not inside an `unsafe {}` block, so the
    // harness fails to BUILD (E0133 — json-rust's `Short::from_slice`). Skip such
    // ctors so the instance method is cleanly rejected ("could not auto-harness")
    // rather than emitting a build-breaking harness. (Wrapping the ctor call in
    // `unsafe {}` to recover coverage is a future enhancement.)
    let ctor_ok = |f: &&rust_parser::RustFn| on_ty(f) && !f.is_unsafe;
    // 1. No-arg `pub fn new()` (fast path).
    if let Some(f) = fns
        .iter()
        .find(|f| f.name == "new" && f.params.is_empty() && ctor_ok(f))
    {
        return Some(ReceiverCtor {
            name: "new".to_owned(),
            params: Vec::new(),
            unwrap: ctor_unwrap(&f.return_type),
        });
    }
    // 2. Derived / impl'd `Default`.
    if type_default_available(source, ty) {
        return Some(ReceiverCtor {
            name: "default".to_owned(),
            params: Vec::new(),
            unwrap: ReceiverUnwrap::Direct,
        });
    }
    // 3. An arg-taking constructor that returns `ty` (`Result`/`Option`-wrapped or
    //    direct) with all-decodable args. Prefer a ctor-shaped name, then fewest
    //    params (easiest to drive), then earliest line for determinism.
    fn name_rank(name: &str) -> u8 {
        match name {
            "parse" | "from_str" => 0,
            "new" | "from_slice" | "from_bytes" | "open" | "load" => 1,
            "connect" | "with_capacity" | "builder" | "from_default" => 2,
            n if n.starts_with("from_") || n.starts_with("with_") => 2,
            _ => 3,
        }
    }
    let mut candidates: Vec<&rust_parser::RustFn> = fns
        .iter()
        .filter(|f| {
            ctor_ok(f)
                && !f.params.is_empty()
                && ctor_returns_self(&f.return_type, ty)
                && ctor_args_decodable(f, is_overridable)
        })
        .collect();
    candidates.sort_by_key(|f| (name_rank(&f.name), f.params.len(), f.line));
    candidates.first().map(|f| ReceiverCtor {
        name: f.name.clone(),
        params: f.params.clone(),
        unwrap: ctor_unwrap(&f.return_type),
    })
}

/// The `Drop::drop` destructor: a no-extra-arg `&mut self` method from a `Drop`
/// impl. It cannot be called explicitly (`recv.drop()` is E0040), so targeting it
/// only ever produces a build-breaking harness. A library's own inherent `drop`
/// that takes arguments is NOT this (it has no `Drop` impl_trait), so it still
/// harnesses.
fn is_drop_destructor(f: &rust_parser::RustFn) -> bool {
    !f.is_static
        && f.name == "drop"
        && f.params.is_empty()
        && matches!(
            f.impl_trait.as_deref(),
            Some("Drop" | "ops::Drop" | "std::ops::Drop" | "core::ops::Drop")
        )
}

/// A receiver type's generic parameter, classified for monomorphization.
#[derive(Debug, PartialEq)]
enum GenericParam {
    Lifetime,
    /// A type parameter; the inner string is its name (`T`, `A`) so its trait
    /// bound can be looked up in the type's impl blocks.
    Type(String),
    /// `const N: <ty>` — the inner string is the const's type (`usize`, `bool`).
    Const(String),
}

/// For a generic receiver type whose ctor is no-arg (`SmallVec::new()`), Rust
/// cannot infer the type/const generics (E0284: `SmallVec<_, _>`). Build a
/// concrete turbofish (`::<u8, 4>`) to monomorphize the receiver so it
/// constructs and the instance method is fuzzed. Returns `None` for a
/// non-generic type or one whose declaration can't be found/parsed — the
/// receiver then constructs without a turbofish, exactly as before.
///
/// Concrete actuals: a type param -> `u8` (the natural fuzz element; satisfies
/// the common `Copy`/`Clone`/`Default`/`Ord`/`Hash`/`Eq` bounds collection
/// methods need) — UNLESS it is bound by an `Array` trait (tinyvec/heapless'
/// `impl<A: Array> ArrayVec<A>` backing-store idiom), where the actual must be an
/// array type `[u8; 4]`; a const generic -> a small literal by its type; a
/// lifetime -> `'_` (inferred). A type-param bound that `u8` cannot meet still
/// fails the build — the same outcome as the pre-fix skip, so no regression. Only
/// applied to no-arg ctors (the caller gates on empty ctor params); an arg-taking
/// ctor's generics infer from its arguments.
fn receiver_generic_turbofish(source: &str, ty: &str) -> Option<String> {
    let params = type_generic_params(source, ty)?;
    if params.is_empty() {
        return None;
    }
    let actuals: Vec<String> = params
        .iter()
        .map(|p| match p {
            GenericParam::Lifetime => "'_".to_owned(),
            GenericParam::Type(name) => {
                if type_param_bound_is_array(source, ty, name) {
                    "[u8; 4]".to_owned()
                } else {
                    "u8".to_owned()
                }
            }
            GenericParam::Const(cty) => const_generic_value(cty),
        })
        .collect();
    Some(format!("::<{}>", actuals.join(", ")))
}

/// True when type param `param_name` of `ty` is bound by an `Array` trait in one
/// of `ty`'s impl blocks (tinyvec/heapless' `impl<A: Array> ArrayVec<A>`). Such a
/// param is a backing store and must be monomorphized to an array type
/// (`[u8; 4]`), not `u8` (which does not implement the `Array` trait). The bound
/// lives on the impl, not the struct declaration, so it is looked up here by the
/// param's name (impls reuse the declaration's param letter by convention).
fn type_param_bound_is_array(source: &str, ty: &str, param_name: &str) -> bool {
    let type_ref = format!("{ty}<");
    source.lines().any(|line| {
        let l = line.trim_start();
        if !l.starts_with("impl") || !l.contains(&type_ref) {
            return false;
        }
        // Match `<A: Array`, `, A: Array`, `A : Array` etc. in the impl's generic
        // list — the bound's leading trait segment is `Array`.
        l.split(['<', ',']).any(|seg| {
            let seg = seg.trim();
            seg.strip_prefix(param_name)
                .map(str::trim_start)
                .and_then(|r| r.strip_prefix(':'))
                .map(|bound| {
                    let bound = bound.trim_start();
                    bound == "Array"
                        || bound.starts_with("Array ")
                        || bound.starts_with("Array+")
                        || bound.starts_with("Array>")
                        || bound.starts_with("Array,")
                })
                .unwrap_or(false)
        })
    })
}

/// A concrete value for a `const` generic of the given type (`const N: usize` ->
/// `4`). Defaults to a small positive integer, which is valid for every integer
/// width a backing-array/length const realistically uses.
fn const_generic_value(const_ty: &str) -> String {
    match const_ty.trim() {
        "bool" => "false".to_owned(),
        "char" => "'a'".to_owned(),
        _ => "4".to_owned(),
    }
}

/// Parse the generic parameter list of `ty`'s `struct`/`enum`/`union`
/// declaration in `source`. `Some(vec![])` when the type is declared but
/// non-generic; `None` when no declaration is found.
fn type_generic_params(source: &str, ty: &str) -> Option<Vec<GenericParam>> {
    for kw in ["struct", "enum", "union"] {
        let needle = format!("{kw} {ty}");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let start = from + rel;
            let after = &source[start + needle.len()..];
            from = start + needle.len();
            match after.chars().next() {
                // `struct SmallVec<...>` — capture the balanced generic list.
                Some('<') => return Some(parse_generic_list(&balanced_angle(after)?)),
                // `struct Foo {`/`(`/`;`/whitespace — a non-generic declaration.
                Some(c) if c.is_whitespace() || c == '{' || c == '(' || c == ';' => {
                    return Some(Vec::new());
                }
                // `struct SmallVecData...` — a different, longer type name; keep
                // scanning for the exact one.
                _ => continue,
            }
        }
    }
    None
}

/// Given a string beginning with `<`, return the content between it and its
/// matching `>` (nesting-aware), excluding the outer brackets.
fn balanced_angle(s: &str) -> Option<String> {
    let mut depth = 0i32;
    let mut inner = String::new();
    for ch in s.chars() {
        match ch {
            '<' => {
                depth += 1;
                if depth > 1 {
                    inner.push(ch);
                }
            }
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(inner);
                }
                inner.push(ch);
            }
            _ if depth >= 1 => inner.push(ch),
            _ => {}
        }
    }
    None
}

/// Classify each top-level (comma-separated) entry of a generic parameter list.
fn parse_generic_list(s: &str) -> Vec<GenericParam> {
    split_top_level_commas(s)
        .into_iter()
        .filter_map(|part| {
            let p = part.trim();
            if p.is_empty() {
                return None;
            }
            if p.starts_with('\'') {
                Some(GenericParam::Lifetime)
            } else if let Some(rest) = p.strip_prefix("const ") {
                // `const N: usize` (possibly `= default`); take the type after `:`.
                let cty = rest
                    .split(':')
                    .nth(1)
                    .map(|t| t.split('=').next().unwrap_or("").trim().to_owned())
                    .unwrap_or_default();
                Some(GenericParam::Const(cty))
            } else {
                // `T`, `T: Bound`, `T = Default` — a single type parameter; keep
                // its name (the leading ident) for impl-bound lookup.
                let name = p
                    .split(|c: char| c == ':' || c == '=' || c.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .to_owned();
                Some(GenericParam::Type(name))
            }
        })
        .collect()
}

/// Split on commas at bracket depth 0 (so `T: Foo<A, B>` stays one entry).
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '<' | '(' | '[' => {
                depth += 1;
                cur.push(ch);
            }
            '>' | ')' | ']' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// True when `ty` has a usable `Default`: an explicit `impl Default for Ty` or a
/// `#[derive(... Default ...)]` on its `struct`/`enum` declaration.
fn type_default_available(source: &str, ty: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    for (i, raw) in lines.iter().enumerate() {
        let l = strip_line_comment(raw);
        let l = l.trim();
        // Explicit `impl Default for Ty` (possibly generic `impl<..> Default for Ty`).
        if l.contains("Default for ") {
            if let Some(after) = l.split("Default for ").nth(1) {
                let name = after
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                if name == ty {
                    return true;
                }
            }
        }
        // `#[derive(.. Default ..)]` within a few lines above the type decl.
        let decl = l
            .strip_prefix("pub struct ")
            .or_else(|| l.strip_prefix("struct "))
            .or_else(|| l.strip_prefix("pub enum "))
            .or_else(|| l.strip_prefix("enum "))
            .or_else(|| l.strip_prefix("pub(crate) struct "))
            .or_else(|| l.strip_prefix("pub(crate) enum "));
        if let Some(rest) = decl {
            let name = rest
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            if name == ty {
                // The `#[derive(...)]` must be CONTIGUOUSLY attached to THIS decl:
                // walk up over only attribute / blank / doc-comment lines and stop
                // at the first real code line, so a Default-deriving DIFFERENT
                // struct above (within 6 lines) can't false-positive (else E0599).
                let mut j = i;
                while j > 0 {
                    j -= 1;
                    let prev = strip_line_comment(lines[j]);
                    let prev = prev.trim();
                    if prev.is_empty() {
                        continue; // blank line or a stripped doc/line comment
                    }
                    if prev.starts_with("#[") || prev.starts_with("#![") {
                        if prev.contains("derive(") && prev.contains("Default") {
                            return true;
                        }
                        continue; // another attribute on this decl
                    }
                    break; // a real code line — attribute attachment ends here
                }
            }
        }
    }
    false
}

/// Compute the module path segments for `source` within the crate at
/// `manifest_dir`. `src/lib.rs` / `src/main.rs` -> `[]` (crate root);
/// `src/foo.rs` -> `["foo"]`; `src/foo/mod.rs` -> `["foo"]`;
/// `src/a/b.rs` -> `["a", "b"]`. A path outside `src/` yields `[]`.
fn module_path(manifest_dir: &Path, source: &Path) -> Vec<String> {
    let src_dir = manifest_dir.join("src");
    let Ok(rel) = source.strip_prefix(&src_dir) else {
        return Vec::new();
    };
    let mut comps: Vec<String> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(str::to_owned))
        .collect();
    let Some(last) = comps.pop() else {
        return Vec::new();
    };
    match last.as_str() {
        "lib.rs" | "main.rs" | "mod.rs" => comps,
        other => {
            let stem = other.strip_suffix(".rs").unwrap_or(other).to_owned();
            comps.push(stem);
            comps
        }
    }
}

/// If `target_line` sits inside an `impl <Type> { ... }` block, return the impl's
/// type name (the leading path segment, e.g. `Url` for `impl Url`). Used so an
/// associated fn is called as `Type::fn`. A brace-depth scan: find the nearest
/// preceding `impl ... {` whose block still encloses the line.
/// Replace the CONTENT of comments and string/char literals with spaces (newlines
/// preserved, byte length unchanged) so a `{`/`}` inside them does not corrupt
/// brace-depth tracking. serde_json's de.rs has dozens of `b'{'` / `b'}'` byte-char
/// literals; counted naively they unbalance the depth and mis-attribute the free
/// `from_slice<T>` to the preceding `StreamDeserializer` impl. Handles `//`,
/// `/* */` (nested), `"…"`/`b"…"`, `'…'` chars (a lifetime `'a` is left intact),
/// and raw strings `r"…"` / `r#…"#` / `br…`.
fn mask_rust_literals(source: &str) -> String {
    let b = source.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    while i < n {
        let c = b[i];
        // Line comment.
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Block comment (Rust allows nesting).
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut depth = 1;
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < n && depth > 0 {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: optional `b`, then `r`, then `#*`, then `"`. Ends at `"` plus
        // the same number of `#`. No escape processing inside.
        let raw_start = if c == b'r' {
            Some(i)
        } else if (c == b'b') && i + 1 < n && b[i + 1] == b'r' {
            Some(i + 1)
        } else {
            None
        };
        if let Some(rs) = raw_start {
            let mut j = rs + 1;
            let mut hashes = 0;
            while j < n && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                // Emit the prefix (`r`/`br` and any `#`) and the opening quote as-is
                // structurally (they aren't braces), then blank the body.
                for &byte in &b[i..=j] {
                    blank(&mut out, byte);
                }
                i = j + 1;
                loop {
                    if i >= n {
                        break;
                    }
                    if b[i] == b'"' {
                        let mut k = i + 1;
                        let mut got = 0;
                        while k < n && got < hashes && b[k] == b'#' {
                            got += 1;
                            k += 1;
                        }
                        if got == hashes {
                            out.resize(out.len() + (k - i), b' ');
                            i = k;
                            break;
                        }
                    }
                    blank(&mut out, b[i]);
                    i += 1;
                }
                continue;
            }
        }
        // Regular / byte string.
        if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < n {
                if b[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    out.push(b' ');
                    i += 1;
                    break;
                }
                blank(&mut out, b[i]);
                i += 1;
            }
            continue;
        }
        // Char literal vs lifetime. A char is `'`(\?.)`'`; a lifetime is `'ident`
        // with no closing quote — leave it intact.
        if c == b'\'' {
            let is_char = if i + 1 < n && b[i + 1] == b'\\' {
                true // escaped char: '\n', '\'', '\x7b', ...
            } else {
                i + 2 < n && b[i + 2] == b'\''
            };
            if is_char {
                out.push(b' ');
                i += 1;
                while i < n {
                    if b[i] == b'\\' && i + 1 < n {
                        out.push(b' ');
                        out.push(b' ');
                        i += 2;
                        continue;
                    }
                    if b[i] == b'\'' {
                        out.push(b' ');
                        i += 1;
                        break;
                    }
                    blank(&mut out, b[i]);
                    i += 1;
                }
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

fn enclosing_impl_type(source: &str, target_line: u32) -> Option<String> {
    // Mask string/char/comment literals so braces inside them (serde_json's `b'{'`)
    // don't corrupt the depth tracking below and mis-attribute a free fn.
    let masked = mask_rust_literals(source);
    let source = masked.as_str();
    // Collect (line, type) for each `impl` header and track brace depth to know
    // which impl block the target line is inside.
    let lines: Vec<&str> = source.lines().collect();
    let target_idx = (target_line as usize).saturating_sub(1);
    if target_idx >= lines.len() {
        return None;
    }
    // Stack of (impl_type, depth_at_open). Process braces LEFT-TO-RIGHT so an impl
    // whose opening `{` is on a LATER line than its header (the common
    // `impl<'a> Foo<'a>\nwhere ...\n{` / `impl Foo\n{` forms) is still associated
    // with the block — a `pending` impl type is consumed by the next `{`.
    let mut depth: i32 = 0;
    let mut stack: Vec<(String, i32)> = Vec::new();
    let mut pending: Option<String> = None;
    let mut current: Option<String> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_line_comment(raw);
        if let Some(ty) = parse_impl_header(&line) {
            // An impl header: its block opens at the next `{` (this line or later).
            pending = Some(ty);
        }
        for ch in line.chars() {
            match ch {
                '{' => {
                    if let Some(ty) = pending.take() {
                        // This `{` opens the pending impl block; it sits at `depth`.
                        stack.push((ty, depth));
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    while let Some((_, open_depth)) = stack.last() {
                        if depth <= *open_depth {
                            stack.pop();
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        if i == target_idx {
            current = stack.last().map(|(ty, _)| ty.clone());
            break;
        }
    }
    current
}

fn strip_line_comment(line: &str) -> String {
    match line.find("//") {
        Some(idx) => line[..idx].to_owned(),
        None => line.to_owned(),
    }
}

/// Parse `impl <Type>` / `impl<...> <Trait> for <Type>` -> the receiver type's
/// leading identifier. Returns `None` for a trait impl's trait (we want the
/// concrete type after `for`).
fn parse_impl_header(line: &str) -> Option<String> {
    let l = line.trim_start();
    let rest = l.strip_prefix("impl")?;
    // Must be `impl` as a word (followed by space, `<`, or end), not `implements`.
    let first = rest.chars().next()?;
    if !(first.is_whitespace() || first == '<') {
        return None;
    }
    // Skip the impl's own generic params `impl<'a, T>` so the type that follows is
    // what we read (`impl<'a> Parser<'a>` -> `Parser`).
    let rest = rest.trim_start();
    let rest = if rest.starts_with('<') {
        // Balance angle brackets to find the end of the generic param list.
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => &rest[e..],
            None => rest,
        }
    } else {
        rest
    };
    // A trait impl `impl Trait for Type` -> take the type after `for`.
    let after_for = rest.split(" for ").nth(1);
    let type_part = after_for.unwrap_or(rest);
    // Strip generics/where: take up to the first `{`, `where`, or `<`.
    let type_part = type_part
        .split('{')
        .next()
        .unwrap_or(type_part)
        .split(" where ")
        .next()
        .unwrap_or(type_part);
    // The first path-ish token; strip generic args.
    let token = type_part.split_whitespace().next()?;
    let ident = token.split('<').next().unwrap_or(token).trim();
    // Take only the last path segment (`foo::Bar` -> `Bar`) for the call,
    // since the harness imports the crate and modules separately.
    let ident = ident.rsplit("::").next().unwrap_or(ident);
    if ident.is_empty() || !ident.chars().next()?.is_alphabetic() {
        return None;
    }
    Some(ident.to_owned())
}

/// If `line` is an impl header, return whether its RECEIVER type carries generic
/// ARGUMENTS (`impl FromStr for Map<String, Value>` -> `Some(true)`; `impl
/// ByteOrder for BigEndian` -> `Some(false)`). `None` when the line is not an impl
/// header. Mirrors `parse_impl_header`'s receiver-type parsing — the only added
/// signal is whether a `<...>` rides on that type.
fn impl_header_type_is_generic(line: &str) -> Option<bool> {
    let l = line.trim_start();
    let rest = l.strip_prefix("impl")?;
    let first = rest.chars().next()?;
    if !(first.is_whitespace() || first == '<') {
        return None;
    }
    // Skip the impl's own generic params `impl<'a, T>` so we read the receiver type.
    let rest = rest.trim_start();
    let rest = if rest.starts_with('<') {
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => &rest[e..],
            None => rest,
        }
    } else {
        rest
    };
    let after_for = rest.split(" for ").nth(1);
    let type_part = after_for.unwrap_or(rest);
    let type_part = type_part
        .split('{')
        .next()
        .unwrap_or(type_part)
        .split(" where ")
        .next()
        .unwrap_or(type_part);
    let token = type_part.split_whitespace().next()?;
    let ident = token.split('<').next().unwrap_or(token).trim();
    let ident = ident.rsplit("::").next().unwrap_or(ident);
    if ident.is_empty() || !ident.chars().next()?.is_alphabetic() {
        return None;
    }
    // Generic when a `<...>` rides on the receiver type (`Map<String, Value>`,
    // `Bar <'a>`). The bare type name elides it, so a UFCS call would not compile.
    Some(token.contains('<') || type_part.trim().contains('<'))
}

/// True when the impl block enclosing `target_line` has a receiver type carrying
/// generic arguments (`impl FromStr for Map<String, Value>`). The bare type name
/// used for the call path can't express such an instantiation, so F6's UFCS call
/// would not compile — callers skip these cleanly instead of emitting a
/// build-breaking harness. Mirrors `enclosing_impl_type`'s brace tracking.
fn enclosing_impl_type_is_generic(source: &str, target_line: u32) -> bool {
    let masked = mask_rust_literals(source);
    let source = masked.as_str();
    let lines: Vec<&str> = source.lines().collect();
    let target_idx = (target_line as usize).saturating_sub(1);
    if target_idx >= lines.len() {
        return false;
    }
    let mut depth: i32 = 0;
    let mut stack: Vec<(bool, i32)> = Vec::new();
    let mut pending: Option<bool> = None;
    let mut current = false;
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_line_comment(raw);
        if let Some(g) = impl_header_type_is_generic(&line) {
            pending = Some(g);
        }
        for ch in line.chars() {
            match ch {
                '{' => {
                    if let Some(g) = pending.take() {
                        stack.push((g, depth));
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    while let Some((_, open_depth)) = stack.last() {
                        if depth <= *open_depth {
                            stack.pop();
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        if i == target_idx {
            current = stack.last().map(|(g, _)| *g).unwrap_or(false);
            break;
        }
    }
    current
}

/// How the resolved harness is built (§27.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildMode {
    /// The default: a separate `staticlib` harness crate that path-depends on the
    /// target crate and calls it by its EXTERNAL name (`the_crate::Type::method`).
    /// Reaches only the target's `pub` API.
    External,
    /// IN-CRATE build: the harness is injected as a module of a COPY of the target
    /// crate and built there, so a `pub` item in a PRIVATE module
    /// (`crate::internal::Parser`) — unreachable from an external dependent crate
    /// (E0603) — is reachable by its full `crate::...` path. The `call_path`/
    /// `receiver` of an in-crate target are rooted at `crate` rather than the
    /// external crate name.
    InCrate,
}

/// Resolve the call path + target `RustFn` + crate manifest dir for a candidate.
#[derive(Debug)]
struct ResolvedTarget {
    call_path: Vec<String>,
    target: rust_parser::RustFn,
    manifest_dir: PathBuf,
    crate_name: String,
    in_fuzz_target: bool,
    /// External staticlib build (the default) or an in-crate injected-module build
    /// for a private-module target (§27.10).
    build_mode: BuildMode,
    /// For an instance method, the constructor path used to build a receiver
    /// (`<type-path>::default` / `::new` / `::parse`); `None` for a static fn or
    /// when no usable constructor was found (the instance method is then skipped).
    receiver: Option<Vec<String>>,
    /// The receiver constructor's parameters (decoded before the method args).
    /// Empty for a no-arg ctor.
    receiver_ctor_params: Vec<rust_parser::RustParam>,
    /// How the ctor's return value yields the receiver (plain / `Result` / `Option`).
    receiver_unwrap: harness_gen::rust_generate::ReceiverUnwrap,
    /// Per-parameter decode-expression overrides (parallel to `target.params`):
    /// `Some(expr)` for params whose type names a reachable unit-only `pub enum`
    /// (a fuzz-byte-indexed variant pick), `None` otherwise. Lets us call targets
    /// like `ada_parser::lex(&str, AdaStandard)` that would otherwise be skipped
    /// for an undecodable enum argument.
    param_decoders: Vec<Option<(String, harness_gen::rust_decoders::ArgPass)>>,
    /// Per-parameter decode-expression overrides for the RECEIVER ctor's args
    /// (parallel to `receiver_ctor_params`) — e.g. a const-scratch
    /// `[httparse::EMPTY_HEADER; 16]` for `Request::new(&mut [Header])`. Empty for a
    /// no-arg ctor or when no ctor arg needs an override.
    receiver_ctor_param_decoders: Vec<Option<(String, harness_gen::rust_decoders::ArgPass)>>,
    /// For a STATIC method of a trait impl (`impl ByteOrder for BigEndian { fn
    /// read_u32(..) }`), the reachable trait path (`["byteorder","ByteOrder"]`) so
    /// the call is emitted by UFCS `<byteorder::BigEndian as byteorder::ByteOrder>::
    /// read_u32(..)` — which needs no `use` of the trait. `None` for an inherent or
    /// free fn. The type path is the `call_path` minus the method.
    ufcs_trait: Option<Vec<String>>,
    /// For an INSTANCE method of a trait impl (`impl Buf for Bytes { fn
    /// remaining(&self) }`), the reachable trait path to bring into scope so
    /// `recv.remaining()` resolves (emitted as `use bytes::Buf as _;`). `None` for
    /// an inherent method, a static method (uses `ufcs_trait`), or a trait whose
    /// path can't be resolved (the call stays bare — a prelude trait like Clone
    /// already works; anything else fails as before, no regression).
    method_trait_import: Option<Vec<String>>,
}

/// How an enum-typed param is wrapped: a bare `EnumName` (passed by value) or an
/// `Option<EnumName>` (the decoder picks `None` / `Some(variant)` by a fuzz byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnumWrap {
    Bare,
    Option,
}

/// Classify a param type as an enum candidate: a plain type path (`AdaStandard`,
/// `ast::Classification`) is [`EnumWrap::Bare`]; a single `Option<…>` wrapper is
/// [`EnumWrap::Option`]. Returns the enum-name candidate (the inner type's last
/// `::` segment) plus the wrap. References, slices, tuples, pointers, lowercase
/// primitives (`u8`/`str`/`bool`), and nested generics yield `None` — they are
/// never unit enums, so the common `&[u8]` / `&str` parsers skip the crate scan.
fn enum_param_type(ty: &str) -> Option<(&str, EnumWrap)> {
    let t = ty.trim();
    if let Some(rest) = t.strip_prefix("Option<") {
        let inner = rest.strip_suffix('>')?.trim();
        return simple_type_ident(inner).map(|n| (n, EnumWrap::Option));
    }
    simple_type_ident(t).map(|n| (n, EnumWrap::Bare))
}

/// The last `::` segment of a plain PascalCase type path, or `None` for compound /
/// reference / generic / primitive types.
fn simple_type_ident(t: &str) -> Option<&str> {
    let t = t.trim();
    if t.is_empty()
        || t.contains(|c: char| {
            matches!(c, '&' | '<' | '>' | '[' | ']' | '(' | ')' | '*' | ' ' | ',')
        })
    {
        return None;
    }
    if !t
        .split("::")
        .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
    {
        return None;
    }
    let last = t.rsplit("::").next().unwrap_or(t);
    match last.chars().next() {
        // Enums are PascalCase by convention; this excludes `u8`/`bool`/`str`.
        Some(c) if c.is_ascii_uppercase() => Some(last),
        _ => None,
    }
}

/// Collect `.rs` files under `dir` (recursive, bounded) for a crate-local search.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if out.len() >= 4000 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
        if out.len() >= 4000 {
            return;
        }
    }
}

/// The fuzz-byte-indexed variant-pick expression for a unit enum, e.g.
/// `[crate::E::A, crate::E::B][(c.u8() as usize) % 2]`. `path` is the enum's
/// reachable path segments; `variants` are its unit variant names (non-empty).
/// An [`EnumWrap::Option`] param wraps the pick so the fuzzer reaches both the
/// `None` and `Some(variant)` paths.
fn build_enum_decoder_expr(path: &[String], variants: &[String], wrap: EnumWrap) -> String {
    let prefix = path.join("::");
    let arms: Vec<String> = variants.iter().map(|v| format!("{prefix}::{v}")).collect();
    let n = arms.len();
    let pick = format!("[{}][(c.u8() as usize) % {n}]", arms.join(", "));
    match wrap {
        EnumWrap::Bare => pick,
        // `Some(pick)` pins the `Option<Enum>` type so the `None` arm infers.
        EnumWrap::Option => format!("if c.u8() & 1 == 0 {{ None }} else {{ Some({pick}) }}"),
    }
}

/// Search the crate's `src/` tree for a unit-only `pub enum` named `enum_name` and
/// return its reachable path segments (`["ada_parser", "ast", "AdaStandard"]`) plus
/// its variant names. Prefers a crate-root re-export façade over the defining
/// module path (same rule as the call-path resolver); returns `None` when no such
/// enum is reachable from a dependent crate (unfound, has data variants, private,
/// or reached only through a private module).
fn find_unit_enum_path(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    enum_name: &str,
) -> Option<(Vec<String>, Vec<String>)> {
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !text.contains(enum_name) {
            continue; // cheap pre-filter before parsing
        }
        let found = rust_parser::parse_rust_enums(&text)
            .into_iter()
            .find(|e| e.name == enum_name && e.all_unit && e.is_pub && !e.unit_variants.is_empty());
        let Some(en) = found else {
            continue;
        };
        let mut path = vec![crate_name.to_owned()];
        if !crate_root_reexports(crate_root_src, enum_name) {
            let module = module_path(manifest_dir, &file);
            if module_chain_has_private(manifest_dir, crate_root_src, &module) {
                continue; // unreachable through a private module link (E0603)
            }
            path.extend(module);
        }
        path.push(enum_name.to_owned());
        return Some((path, en.unit_variants));
    }
    None
}

/// Build per-parameter decode-expression overrides (each paired with how it is
/// passed at the call site): a reachable unit `pub enum` -> a fuzz-byte variant
/// pick (by value); a non-byte scratch slice `&mut [T]` / `&[T]` -> a filled array
/// (`[crate::EMPTY_HEADER; 16]` from a public const of `T`, or — for a non-generic
/// `Default` element — a `from_fn` array) passed by `&mut` / `&`. All others get
/// `None` (the standard type decoder). Returns a vec parallel to `params`.
fn resolve_param_overrides(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    params: &[rust_parser::RustParam],
) -> Vec<Option<(String, harness_gen::rust_decoders::ArgPass)>> {
    use harness_gen::rust_decoders::ArgPass;
    params
        .iter()
        .map(|p| {
            if let Some((name, wrap)) = enum_param_type(&p.ty) {
                if let Some((path, variants)) =
                    find_unit_enum_path(manifest_dir, crate_name, crate_root_src, name)
                {
                    return Some((
                        build_enum_decoder_expr(&path, &variants, wrap),
                        ArgPass::Move,
                    ));
                }
            }
            if let Some((leaf, is_mut, is_generic)) = scratch_slice(&p.ty) {
                let by_ref = if is_mut {
                    ArgPass::RefMut
                } else {
                    ArgPass::Ref
                };
                // Prefer a public const of the element type — the only fill that
                // works for a lifetime-generic borrow element (httparse `Header`).
                if let Some(path) = find_type_const(manifest_dir, crate_name, crate_root_src, &leaf)
                {
                    return Some((format!("[{}; 16]", path.join("::")), by_ref));
                }
                // Else a NON-generic element with a usable `Default` -> a `from_fn`
                // array (element type inferred from the call site, so T isn't named).
                if !is_generic
                    && type_default_available_in_crate(manifest_dir, crate_root_src, &leaf)
                {
                    return Some((
                        "core::array::from_fn::<_, 16, _>(|_gf_idx| Default::default())".to_owned(),
                        by_ref,
                    ));
                }
            }
            // F7: a `&T` / `&mut T` reference to a reachable struct/enum with
            // `Default` -> build a throwaway `T::default()` and pass it by
            // reference, so a target with a config/context param (ron's `&Options`)
            // isn't skipped for an undecodable arg (its byte/str params still fuzz).
            if let Some((leaf, is_mut)) = ref_struct_param(&p.ty) {
                if let Some(path) =
                    find_default_type_path(manifest_dir, crate_name, crate_root_src, &leaf)
                {
                    let by_ref = if is_mut {
                        ArgPass::RefMut
                    } else {
                        ArgPass::Ref
                    };
                    return Some((format!("{}::default()", path.join("::")), by_ref));
                }
            }
            None
        })
        .collect()
}

/// #458: resolve MARKER type params (a bound naming a trait with a concrete impl
/// in the crate, used by no value parameter — e.g. byteorder's `B: ByteOrder` on
/// `read_u32::<B>()`) to a reachable concrete impl, bake a positional turbofish
/// onto the call's method segment (`read_u32::<BigEndian>(..)`), and strip the
/// resolved params from `target.type_params` so `monomorphized_params` no longer
/// rejects the candidate as having an uninferable / return-only generic.
///
/// Fires only when EVERY value-unused type param resolves to a marker impl; a
/// value-used param keeps its turbofish slot `_` (inferred from its argument). If
/// any value-unused param is unresolvable, no turbofish is applied (the candidate
/// then takes the existing monomorphize-or-skip path).
fn apply_marker_turbofish(
    call_path: &mut [String],
    target: &mut rust_parser::RustFn,
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
) {
    if target.type_params.is_empty() {
        return;
    }
    let mut slots: Vec<String> = Vec::with_capacity(target.type_params.len());
    let mut resolved: Vec<String> = Vec::new();
    for tp in &target.type_params {
        if type_param_used_in_params(&tp.name, &target.params) {
            // Inferred from a value argument — leave the turbofish slot open.
            slots.push("_".to_owned());
            continue;
        }
        // Value-unused: must resolve to a concrete impl of its bound, else we can't
        // form a valid call — abandon the turbofish entirely.
        // Prefer the crate's own `Value` for a `Deserialize` bound (a trait with
        // many impls — find_trait_impl_marker would otherwise pick an arbitrary one
        // like `Map`); fall back to marker-impl resolution for single-impl bounds
        // (byteorder's `ByteOrder` -> `BigEndian`).
        let Some(marker_path) = deserialize_value_target(&tp.bound, crate_name, crate_root_src)
            .or_else(|| {
                bound_trait_leaf(&tp.bound).and_then(|t| {
                    find_trait_impl_marker(manifest_dir, crate_name, crate_root_src, t)
                })
            })
        else {
            return;
        };
        slots.push(marker_path.join("::"));
        resolved.push(tp.name.clone());
    }
    if resolved.is_empty() {
        return; // a pure byte/str-bound generic: leave it to monomorphization
    }
    if let Some(last) = call_path.last_mut() {
        last.push_str(&format!("::<{}>", slots.join(", ")));
    }
    target.type_params.retain(|tp| !resolved.contains(&tp.name));
}

/// A RETURN-ONLY generic bound by `Deserialize`/`DeserializeOwned` (the serde
/// format crates' `from_str::<T>` / `from_slice::<T>` / `from_reader::<T>`) can't
/// be inferred from arguments — but the idiomatic dynamic fuzz target is the
/// crate's OWN `Value` type (serde_json::Value, toml::Value, ron::Value), which
/// every serde-format crate exposes and which impls Deserialize. Monomorphize the
/// param to `<crate>::Value` so the parser's PRIMARY entry point (otherwise
/// skipped as an uninferable generic) becomes fuzzable. Returns the turbofish path
/// only when the crate re-exports / defines a public `Value`.
fn deserialize_value_target(
    bound: &str,
    crate_name: &str,
    crate_root_src: &str,
) -> Option<Vec<String>> {
    let leaf = bound.rsplit("::").next().unwrap_or(bound).trim();
    let leaf = leaf.split('<').next().unwrap_or(leaf).trim();
    if !matches!(leaf, "Deserialize" | "DeserializeOwned") {
        return None;
    }
    if crate_root_reexports(crate_root_src, "Value")
        || crate_root_defines_pub(crate_root_src, "Value")
    {
        Some(vec![crate_name.to_owned(), "Value".to_owned()])
    } else {
        None
    }
}

/// The trait's leaf name from a (possibly path-qualified / generic) bound, or
/// `None` for an empty bound or a byte/str-conversion bound — those are handled by
/// value substitution in `monomorphized_params`, not by turbofish.
fn bound_trait_leaf(bound: &str) -> Option<&str> {
    let b = bound.trim();
    if b.is_empty() {
        return None;
    }
    let compact = b.replace(' ', "");
    if [
        "AsRef<[u8]>",
        "Borrow<[u8]>",
        "Into<Vec<u8>>",
        "AsRef<str>",
        "Borrow<str>",
        "Into<String>",
    ]
    .iter()
    .any(|m| compact.contains(m))
    {
        return None;
    }
    let first = b.split('+').next().unwrap_or(b).trim();
    let base = first.split('<').next().unwrap_or(first).trim();
    let leaf = base.rsplit("::").next().unwrap_or(base).trim();
    (!leaf.is_empty()).then_some(leaf)
}

/// Whether the generic type param `name` appears as a whole identifier in any of
/// `params`' types (so it's inferred from a value argument, not a phantom marker).
fn type_param_used_in_params(name: &str, params: &[rust_parser::RustParam]) -> bool {
    params.iter().any(|p| ty_mentions_ident(&p.ty, name))
}

/// Whole-identifier membership (`T` matches `Vec<T>` / `&T` but not `Threshold`).
fn ty_mentions_ident(ty: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let hay: Vec<char> = ty.chars().collect();
    let needle: Vec<char> = name.chars().collect();
    if needle.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if hay[i..i + needle.len()] == needle[..] {
            let before = i == 0 || !is_ident(hay[i - 1]);
            let after = i + needle.len() == hay.len() || !is_ident(hay[i + needle.len()]);
            if before && after {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `impl <trait_leaf> for <Marker>` -> the marker type's leading ident (PascalCase),
/// matching the trait by its leaf name (so `impl byteorder::ByteOrder for BigEndian`
/// resolves for `trait_leaf == "ByteOrder"`). Generic / blanket impls
/// (`impl<T> Foo for Bar<T>`) whose trait leaf doesn't match are skipped.
fn parse_trait_impl<'a>(line: &'a str, trait_leaf: &str) -> Option<&'a str> {
    let l = line.trim_start();
    let rest = l.strip_prefix("impl")?;
    if !matches!(rest.chars().next(), Some(' ') | Some('<')) {
        return None;
    }
    let for_pos = rest.find(" for ")?;
    let head = rest[..for_pos].trim();
    let trait_tok = head.rsplit(char::is_whitespace).next().unwrap_or(head);
    let trait_base = trait_tok.split('<').next().unwrap_or(trait_tok);
    if trait_base.rsplit("::").next().unwrap_or(trait_base) != trait_leaf {
        return None;
    }
    let after = rest[for_pos + 5..].trim_start();
    let end = after
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
        .unwrap_or(after.len());
    let marker = after[..end].rsplit("::").next().unwrap_or(&after[..end]);
    match marker.chars().next() {
        Some(c) if c.is_ascii_uppercase() => Some(marker),
        _ => None,
    }
}

/// Resolve a trait NAMED in an `impl Trait for Type` (as written, possibly a path)
/// to a reachable path from a dependent crate (`ByteOrder` -> `["byteorder",
/// "ByteOrder"]`), by finding its `pub trait <leaf>` declaration in the crate. The
/// trait must be PUBLIC and reachable (crate-root re-exported, or in a non-private
/// module) so the emitted UFCS can't fail with a privacy error. `None` when the
/// trait isn't an in-crate public trait (a std/external trait — leave the call
/// non-UFCS, so it skips/fails as before rather than emitting a wrong path).
fn resolve_in_crate_trait_path(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    trait_spelling: &str,
) -> Option<Vec<String>> {
    let leaf = trait_spelling.rsplit("::").next().unwrap_or(trait_spelling);
    let leaf = leaf.split('<').next().unwrap_or(leaf).trim();
    if leaf.is_empty() || !leaf.chars().next()?.is_ascii_uppercase() {
        return None;
    }
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        if !text.lines().any(|l| pub_trait_decl_is(l, leaf)) {
            continue;
        }
        let reexported = crate_root_reexports(crate_root_src, leaf);
        let mut path = vec![crate_name.to_owned()];
        if !reexported {
            let module = module_path(manifest_dir, file);
            if module_chain_has_private(manifest_dir, crate_root_src, &module) {
                continue;
            }
            path.extend(module);
        }
        path.push(leaf.to_owned());
        return Some(path);
    }
    None
}

/// For an INSTANCE trait-impl method (`impl Buf for Bytes { fn remaining(&self) }`),
/// the reachable trait path to `use` so a `recv.method()` call resolves. Tries an
/// in-crate `pub trait` first (bytes' `Buf`/`BufMut` — its whole API), then a map
/// of common std/core traits whose paths can't be found in the crate source.
/// `None` for an unresolvable trait — the call stays bare (a prelude trait like
/// `Clone` already works; any other unresolved trait fails as before, no
/// regression since nothing is added).
fn resolve_method_trait_import(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    trait_spelling: &str,
    method_name: &str,
) -> Option<Vec<String>> {
    resolve_in_crate_trait_path(manifest_dir, crate_name, crate_root_src, trait_spelling)
        .or_else(|| std_trait_path(trait_spelling, method_name))
}

/// Canonical module path for a common std/core trait named in an `impl Trait for
/// Type`. `Write` is ambiguous (`fmt::Write` vs `io::Write`) so it is
/// disambiguated by the method name. `None` for a trait not in the map (then no
/// `use` is emitted — a prelude trait works regardless, others fail as before).
fn std_trait_path(trait_spelling: &str, method_name: &str) -> Option<Vec<String>> {
    let leaf = trait_spelling.rsplit("::").next().unwrap_or(trait_spelling);
    let leaf = leaf.split('<').next().unwrap_or(leaf).trim();
    let path: &[&str] = match leaf {
        "Deref" => &["core", "ops", "Deref"],
        "DerefMut" => &["core", "ops", "DerefMut"],
        "Index" => &["core", "ops", "Index"],
        "IndexMut" => &["core", "ops", "IndexMut"],
        "Borrow" => &["core", "borrow", "Borrow"],
        "BorrowMut" => &["core", "borrow", "BorrowMut"],
        "AsRef" => &["core", "convert", "AsRef"],
        "AsMut" => &["core", "convert", "AsMut"],
        "PartialOrd" => &["core", "cmp", "PartialOrd"],
        "Ord" => &["core", "cmp", "Ord"],
        "PartialEq" => &["core", "cmp", "PartialEq"],
        "Hash" => &["core", "hash", "Hash"],
        // `Write`: fmt (write_str/write_char/write_fmt) vs io (write/write_all/flush).
        "Write" if matches!(method_name, "write_str" | "write_char" | "write_fmt") => {
            &["core", "fmt", "Write"]
        }
        "Write" => &["std", "io", "Write"],
        "Read" => &["std", "io", "Read"],
        "BufRead" => &["std", "io", "BufRead"],
        "Seek" => &["std", "io", "Seek"],
        _ => return None,
    };
    Some(path.iter().map(|s| (*s).to_owned()).collect())
}

/// F6: a STATIC (associated, no-`self`) method of an `impl <StdConvTrait> for T`
/// is still callable by fully-qualified UFCS (`<T as ::core::str::FromStr>::
/// from_str(s)`) even though the trait is defined in std/core — UFCS needs no
/// `use` of the trait. For the byte/str-decodable conversion traits this is an
/// IDEAL fuzz target (a raw `&str` / `&[u8]` parsed straight into a typed value).
/// Returns the fully-qualified (absolute, leading `::`) trait path when `target`
/// is one of:
///   * `impl FromStr for T      { fn from_str(s: &str) -> ... }`
///   * `impl TryFrom<&[u8]> for T { fn try_from(b: &[u8]) -> ... }`
///   * `impl TryFrom<&str> for T  { fn try_from(s: &str) -> ... }`
///
/// Gated on the method name AND its single `&str` / `&[u8]` parameter so the
/// emitted `<T as ..>::method(arg)` always type-checks. `None` for any other
/// trait/shape (a clean skip, as before). The receiver type `T`'s reachability is
/// enforced by the caller's earlier crate-root reachability gate.
fn std_ufcs_trait_path(target: &rust_parser::RustFn) -> Option<Vec<String>> {
    if !target.is_static {
        return None;
    }
    let trait_spelling = target.impl_trait.as_deref()?;
    // The trait's leaf (drop any `module::` qualifier; keep generic args).
    let leaf = trait_spelling
        .rsplit("::")
        .next()
        .unwrap_or(trait_spelling)
        .trim();
    let base = leaf.split('<').next().unwrap_or(leaf).trim();
    // `FromStr::from_str(&str)`.
    if base == "FromStr" && target.name == "from_str" && single_ref_param_is(target, "&str") {
        return Some(vec![
            "::core".to_owned(),
            "str".to_owned(),
            "FromStr".to_owned(),
        ]);
    }
    // `TryFrom<&[u8]>` / `TryFrom<&str>`::`try_from(arg)`. Extract the trait's
    // single type argument and require it (lifetime-erased) to be `&[u8]` / `&str`
    // and to match the method's lone parameter.
    if base == "TryFrom" && target.name == "try_from" {
        if let Some(arg) = leaf
            .find('<')
            .and_then(|i| leaf[i + 1..].rfind('>').map(|j| leaf[i + 1..][..j].trim()))
            .map(normalize_ref_arg)
        {
            if (arg == "&[u8]" || arg == "&str") && single_ref_param_is(target, &arg) {
                return Some(vec![format!("::core::convert::TryFrom<{arg}>")]);
            }
        }
    }
    None
}

/// True when `target` takes exactly one parameter whose (lifetime-erased,
/// whitespace-stripped) type spelling equals `expected` (e.g. `&str` / `&[u8]`).
fn single_ref_param_is(target: &rust_parser::RustFn, expected: &str) -> bool {
    target.params.len() == 1 && normalize_ref_arg(&target.params[0].ty) == expected
}

/// Lifetime-erased, whitespace-stripped form of a borrowed type spelling:
/// `&'a [u8]` -> `&[u8]`, `&'static str` -> `&str`, `& str` -> `&str`. Used to
/// match a `from_str` / `try_from` parameter (or a `TryFrom<..>` type argument)
/// against an expected `&str` / `&[u8]` shape regardless of lifetime / whitespace.
fn normalize_ref_arg(ty: &str) -> String {
    let chars: Vec<char> = ty.chars().collect();
    let mut out = String::with_capacity(ty.len());
    let mut i = 0;
    while i < chars.len() {
        // Drop a `'lifetime` token wholesale (`'a`, `'static`).
        if chars[i] == '\'' {
            i += 1;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out.split_whitespace().collect::<Vec<_>>().join("")
}

/// True when `line` declares the public trait `leaf` (`pub trait Leaf` /
/// `pub unsafe trait Leaf`), matching the whole name.
fn pub_trait_decl_is(line: &str, leaf: &str) -> bool {
    let l = line.trim_start();
    let rest = l
        .strip_prefix("pub trait ")
        .or_else(|| l.strip_prefix("pub unsafe trait "))
        .map(str::trim_start);
    match rest {
        Some(r) => {
            let name = r
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            name == leaf
        }
        None => false,
    }
}

/// `pub struct X` / `pub enum X` -> `X` (the public type's name), else `None`.
fn pub_type_decl_name(line: &str) -> Option<&str> {
    let rest = line
        .trim_start()
        .strip_prefix("pub struct ")
        .or_else(|| line.trim_start().strip_prefix("pub enum "))?;
    let name = rest
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()?;
    (!name.is_empty()).then_some(name)
}

/// Scan the crate for a reachable concrete impl `impl <trait_leaf> for <Marker>`,
/// returning the marker's reachable path (`["byteorder", "BigEndian"]`). The marker
/// must be a crate-root-reexported or public, non-private-module type (so the emitted
/// turbofish can't fail with a privacy error); multiple candidates -> the first by
/// name (deterministic). `None` when none is reachable from a dependent crate.
fn find_trait_impl_marker(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    trait_leaf: &str,
) -> Option<Vec<String>> {
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    let mut pub_types: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut impls: Vec<(String, PathBuf)> = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines() {
            if let Some(name) = pub_type_decl_name(line) {
                pub_types.insert(name.to_owned());
            }
            if let Some(marker) = parse_trait_impl(line, trait_leaf) {
                impls.push((marker.to_owned(), file.clone()));
            }
        }
    }
    impls.sort_by(|a, b| a.0.cmp(&b.0));
    for (marker, file) in impls {
        let reexported = crate_root_reexports(crate_root_src, &marker);
        if !reexported && !pub_types.contains(&marker) {
            continue; // not a public type -> emitting it would be a privacy error
        }
        let mut path = vec![crate_name.to_owned()];
        if !reexported {
            let module = module_path(manifest_dir, &file);
            if module_chain_has_private(manifest_dir, crate_root_src, &module) {
                continue;
            }
            path.extend(module);
        }
        path.push(marker);
        return Some(path);
    }
    None
}

/// If `ty` is a scratch slice of a non-byte struct/enum element (`&mut [Header]`,
/// `&[Header<'a>]`, `&mut [Header<>]`), return `(leaf_name, is_mut, is_generic)`:
/// the element's leaf type name, whether the slice is `&mut`, and whether the
/// element carried generic/lifetime args (a lifetime-generic borrow has no usable
/// `Default`, so it needs a const fill rather than `from_fn`).
fn scratch_slice(ty: &str) -> Option<(String, bool, bool)> {
    // Single-space normalize (keep spaces so an explicit reference lifetime
    // `&'h mut [..]` parses — collapsing them would fuse `'h` with `mut`).
    let t = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut s = t.strip_prefix('&')?.trim_start();
    // Optional reference lifetime `'a`.
    if let Some(after) = s.strip_prefix('\'') {
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        s = after[end..].trim_start();
    }
    let is_mut = if let Some(rest) = s.strip_prefix("mut") {
        // `mut` must be a word (so a type named `mutex` isn't mistaken for it).
        if matches!(rest.chars().next(), Some(' ') | Some('[')) {
            s = rest.trim_start();
            true
        } else {
            return None;
        }
    } else {
        false
    };
    let elem = s.strip_prefix('[')?.trim().strip_suffix(']')?.trim();
    let is_generic = elem.contains('<');
    // Drop any generic args (`Header<'a>` / `Header<>` -> `Header`).
    let elem_base = elem.split('<').next().unwrap_or(elem).trim();
    if elem_base.is_empty()
        || elem_base.contains(|c: char| {
            matches!(
                c,
                '&' | '<' | '>' | '[' | ']' | '(' | ')' | '*' | ',' | ';' | ' '
            )
        })
    {
        return None;
    }
    let leaf = elem_base.rsplit("::").next().unwrap_or(elem_base);
    match leaf.chars().next() {
        // PascalCase struct/enum element (a lowercase primitive like `u8` has its
        // own byte-slice decoder and is not a scratch slice).
        Some(c) if c.is_ascii_uppercase() => Some((leaf.to_owned(), is_mut, is_generic)),
        _ => None,
    }
}

/// Find a reachable `pub const NAME: <type_leaf>...` in the crate (httparse's
/// `pub const EMPTY_HEADER: Header<'static>`) and return its qualified path
/// segments (`["httparse", "EMPTY_HEADER"]`). Used to fill a `&mut [T]` scratch
/// slice as `[crate::EMPTY_HEADER; 16]` — the only way to build a lifetime-generic
/// borrow element that has no usable `Default`. Resolves the path via the
/// crate-root re-export façade or a non-private module chain (same rule as the
/// call-path / enum resolvers).
fn find_type_const(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    type_leaf: &str,
) -> Option<Vec<String>> {
    let mut files = Vec::new();
    collect_rs_files(&manifest_dir.join("src"), &mut files);
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !text.contains(type_leaf) {
            continue;
        }
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("pub const ") else {
                continue;
            };
            let Some((name_part, type_part)) = rest.split_once(':') else {
                continue;
            };
            let name = name_part.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            // The const's declared type leaf (before `<...>` / `=`).
            let ty = type_part.split('=').next().unwrap_or(type_part).trim();
            let ty_base = ty.split('<').next().unwrap_or(ty).trim();
            let ty_leaf = ty_base.rsplit("::").next().unwrap_or(ty_base).trim();
            if ty_leaf != type_leaf {
                continue;
            }
            let mut path = vec![crate_name.to_owned()];
            if !crate_root_reexports(crate_root_src, name) {
                let module = module_path(manifest_dir, &file);
                if module_chain_has_private(manifest_dir, crate_root_src, &module) {
                    continue;
                }
                path.extend(module);
            }
            path.push(name.to_owned());
            return Some(path);
        }
    }
    None
}

/// True when type `ty` (matched by leaf name) has a usable `Default` anywhere in
/// the crate — a `#[derive(... Default ...)]` or an `impl Default for Ty`. Used to
/// gate the `&mut [T]` scratch-slice decoder so a non-`Default` element stays a
/// clean skip rather than a build failure.
fn type_default_available_in_crate(manifest_dir: &Path, crate_root_src: &str, ty: &str) -> bool {
    let leaf = ty.rsplit("::").next().unwrap_or(ty);
    if type_default_available(crate_root_src, leaf) {
        return true;
    }
    let mut files = Vec::new();
    collect_rs_files(&manifest_dir.join("src"), &mut files);
    files.iter().any(|file| {
        std::fs::read_to_string(file)
            .ok()
            .is_some_and(|text| text.contains(leaf) && type_default_available(&text, leaf))
    })
}

/// F7: if `ty` is a SHARED/MUT reference to a single named (non-slice,
/// non-primitive) type — `&Options`, `&'a Config`, `&mut Builder` — return
/// `(leaf_name, is_mut)`. `None` for a byte/str slice (`&[u8]`, `&str`, handled by
/// the native decoders), a generic (`&Config<T>`), or a non-reference. The leaf
/// must be PascalCase (a lowercase primitive like `&u8` is rejected).
fn ref_struct_param(ty: &str) -> Option<(String, bool)> {
    let t = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut s = t.strip_prefix('&')?.trim_start();
    // Optional reference lifetime `'a`.
    if let Some(after) = s.strip_prefix('\'') {
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        s = after[end..].trim_start();
    }
    let is_mut = if let Some(rest) = s.strip_prefix("mut ") {
        s = rest.trim_start();
        true
    } else {
        false
    };
    // The remainder must be a plain type ident (PascalCase, no slice / generic /
    // tuple / nested reference). `simple_type_ident` enforces all of that.
    simple_type_ident(s).map(|leaf| (leaf.to_owned(), is_mut))
}

/// F7: for a `&T` reference param, resolve `leaf` to a publicly-reachable type
/// with a usable `Default`, returning its reachable path (`["ron", "Options"]`).
/// The harness then builds a throwaway `<path>::default()` and passes `&v`, so a
/// target with a config/context reference param (ron's `&Options`) is harnessable
/// instead of skipped — its other (byte/str) params still get fuzzed. Prefers the
/// crate-root re-export façade, then a public re-export (F5), then a non-private
/// module path. `None` when the type is unfound, non-public, private-module-only,
/// or has no `Default`.
fn find_default_type_path(
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    leaf: &str,
) -> Option<Vec<String>> {
    if !type_default_available_in_crate(manifest_dir, crate_root_src, leaf) {
        return None;
    }
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        if !text.contains(leaf) {
            continue; // cheap pre-filter
        }
        // The type must be declared `pub struct/enum <leaf>` in THIS file.
        if !text.lines().any(|l| pub_type_decl_name(l) == Some(leaf)) {
            continue;
        }
        if crate_root_reexports(crate_root_src, leaf) {
            return Some(vec![crate_name.to_owned(), leaf.to_owned()]);
        }
        let module = module_path(manifest_dir, file);
        // Prefer a public re-export over the canonical (possibly private) path.
        if let Some(rx) =
            resolve_public_reexport_path(manifest_dir, crate_name, crate_root_src, &module, leaf)
        {
            return Some(rx);
        }
        if module_chain_has_private(manifest_dir, crate_root_src, &module) {
            continue; // unreachable through a private module link (E0603)
        }
        let mut path = vec![crate_name.to_owned()];
        path.extend(module);
        path.push(leaf.to_owned());
        return Some(path);
    }
    None
}

fn resolve_target(candidate: &Candidate) -> Result<ResolvedTarget, String> {
    let source = std::fs::read_to_string(&candidate.source_path)
        .map_err(|e| format!("read Rust source {}: {e}", candidate.source_path.display()))?;
    let manifest_dir = find_crate_root(&candidate.source_path)
        .ok_or_else(|| "no Cargo.toml found above the Rust target source".to_owned())?;
    let crate_name = crate_import_name(&manifest_dir)
        .ok_or_else(|| "could not determine crate import name from Cargo.toml".to_owned())?;

    let fns = rust_parser::parse_rust_functions(&source)
        .map_err(|_| "failed to parse Rust source".to_owned())?;
    let target = fns
        .iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| fns.iter().find(|f| f.name == candidate.name))
        .cloned();

    // `Drop::drop` cannot be called explicitly — `recv.drop()` is a hard compile
    // error (E0040, "explicit use of destructor method"), so any type with a
    // `Drop` impl would only ever produce a build-breaking harness. Reject it as
    // a clean skip. Gated to the destructor's exact shape (a no-extra-arg `&mut
    // self` method from a `Drop` impl) so a library's own inherent `drop` taking
    // arguments still harnesses.
    if target.as_ref().is_some_and(is_drop_destructor) {
        return Err(
            "Rust target 'drop' is the Drop destructor — it cannot be called \
             explicitly (E0040); skipped."
                .to_owned(),
        );
    }

    // An `unsafe fn` (the modifier) carries a caller-upheld safety precondition the
    // generated harness cannot honour — json-rust's `pub unsafe fn
    // Short::from_slice(s: &str)` is contracted to `s.len() <= 30`. Fed the full fuzz
    // input it violates the precondition and fabricates a false critical GF-203/CWE-121
    // stack-buffer-overflow, attributed to the library rather than to the harness. Skip
    // it as a primary target. Gated to the `unsafe fn` MODIFIER only (`is_unsafe_fn`),
    // so a safe raw-pointer FFI signature keeps its promotion and is harnessed when its
    // params are decodable.
    if target.as_ref().is_some_and(|t| t.is_unsafe_fn) {
        return Err(format!(
            "Rust target '{}' is an `unsafe fn` with a caller-upheld safety \
             precondition the harness cannot honour; skipped (lab-only).",
            candidate.name
        ));
    }

    // An existing fuzz_target! file (the macro body is not a parseable fn): the
    // candidate's `name` is the helper the macro calls. We can't reliably call
    // into the macro, so wrap the file's first byte-channel `pub fn` if any.
    let file_is_fuzz_target = fns.iter().any(|f| f.in_fuzz_target);

    let module = module_path(&manifest_dir, &candidate.source_path);
    let crate_root_src = read_crate_root_src(&manifest_dir);

    match target {
        Some(target) => {
            // §27.1: a method DECLARED in a `pub trait` (byteorder's
            // `ReadBytesExt::read_u32`) has no enclosing concrete `impl` type — the
            // Rust lane synthesises a std-reader receiver (`std::io::Cursor`) and
            // imports the trait. Dispatched before the normal impl/free-fn path.
            if target.is_trait_method {
                return resolve_reader_trait_method(
                    target,
                    &manifest_dir,
                    &crate_name,
                    &crate_root_src,
                    file_is_fuzz_target,
                );
            }
            // Build the call path. Prefer the crate-root re-export façade over the
            // defining module path: crates routinely define a type/fn in a PRIVATE
            // `mod inner;` and surface it with `pub use inner::Thing;`, so
            // `crate::inner::Thing` fails ("module is private") while `crate::Thing`
            // works. For an associated fn we must reach the TYPE; for a free fn, the
            // fn itself. Fall back to the module path when there is no root re-export.
            let mut call_path = vec![crate_name.clone()];
            let mut receiver = None;
            let mut receiver_ctor_params = Vec::new();
            let mut receiver_unwrap = harness_gen::rust_generate::ReceiverUnwrap::Direct;
            let mut receiver_ctor_param_decoders = Vec::new();
            let impl_module = module.first().map(|s| s.as_str()).unwrap_or("");
            match enclosing_impl_type(&source, target.line) {
                Some(ty) => {
                    // Check ALL three reachability cases: named re-export, direct
                    // pub definition at root, or glob re-export of the impl's module.
                    // Inherent methods are reachable through the TYPE, not through the
                    // impl block's module, so we must not gate on the impl module's
                    // visibility when the type itself is at the crate root (E0603 fix).
                    let reachable = type_reachable_at_crate_root(&crate_root_src, &ty, impl_module);
                    if reachable {
                        call_path.push(ty.clone());
                    } else if let Some(rx) = resolve_public_reexport_path(
                        &manifest_dir,
                        &crate_name,
                        &crate_root_src,
                        &module,
                        &ty,
                    ) {
                        // F5: the type's canonical module path traverses a non-pub
                        // module, but an ancestor module re-exports it publicly — use
                        // the shortest PUBLIC re-export path (ron's `value::raw::
                        // RawValue` -> `ron::value::RawValue`) instead of the E0603
                        // private path. `rx` is already `[crate, ..ancestor.., ty]`.
                        call_path = rx;
                    } else if module_chain_has_private(&manifest_dir, &crate_root_src, &module) {
                        // RC5/§27.10: a type reached only through a PRIVATE module
                        // link (not re-exported) is unreachable from an external
                        // dependent crate (E0603). Rather than skip, build the
                        // harness IN-CRATE: a `crate::<module>::<Type>` path inside a
                        // copy of the crate reaches the private module.
                        return resolve_in_crate_target(
                            &source,
                            &fns,
                            target,
                            &manifest_dir,
                            &crate_name,
                            &crate_root_src,
                            &module,
                            file_is_fuzz_target,
                        );
                    } else {
                        call_path.extend(module.iter().cloned());
                        call_path.push(ty.clone());
                    }
                    // RC1/G1: for an instance method, find a receiver ctor on `ty` —
                    // a no-arg `new()`/`Default`, or an arg-taking/fallible ctor
                    // (`Document::parse(&str) -> Result`). The ctor path is the type
                    // path (call_path so far) + the ctor name; its params are decoded
                    // before the method args and its Result/Option is unwrapped.
                    if !target.is_static {
                        // A ctor arg that is a reachable unit `enum` is decodable via
                        // the same param-override path the target uses (a fuzz-byte
                        // variant pick), so such a ctor counts as usable.
                        let is_overridable = |arg_ty: &str| -> bool {
                            enum_param_type(arg_ty)
                                .and_then(|(name, _)| {
                                    find_unit_enum_path(
                                        &manifest_dir,
                                        &crate_name,
                                        &crate_root_src,
                                        name,
                                    )
                                })
                                .is_some()
                        };
                        if let Some(ctor) = find_receiver_ctor(&source, &fns, &ty, &is_overridable)
                        {
                            // Resolve the ctor's own arg overrides (e.g. a const-scratch
                            // `[httparse::EMPTY_HEADER; 16]` for `Request::new(&mut [Header])`).
                            let ctor_decoders = resolve_param_overrides(
                                &manifest_dir,
                                &crate_name,
                                &crate_root_src,
                                &ctor.params,
                            );
                            // A scratch-slice ctor arg with no resolvable const/Default fill
                            // can't be driven — drop the receiver so the instance method skips
                            // cleanly rather than emitting an uncompilable ctor call.
                            let unfillable = ctor
                                .params
                                .iter()
                                .zip(ctor_decoders.iter())
                                .any(|(p, d)| d.is_none() && scratch_slice(&p.ty).is_some());
                            if !unfillable {
                                let mut ctor_path = call_path.clone();
                                // Monomorphize a generic receiver type for a no-arg
                                // ctor: `SmallVec::new()` can't infer `SmallVec<T,
                                // const N>` (E0284). Inject a concrete turbofish
                                // (`SmallVec::<u8, 4>`) onto the type segment so the
                                // receiver constructs. Arg-taking ctors infer their
                                // generics from arguments, so are left alone.
                                if ctor.params.is_empty() {
                                    if let Some(tf) = receiver_generic_turbofish(&source, &ty) {
                                        if let Some(last) = ctor_path.last_mut() {
                                            last.push_str(&tf);
                                        }
                                    }
                                }
                                ctor_path.push(ctor.name);
                                receiver = Some(ctor_path);
                                receiver_ctor_params = ctor.params;
                                receiver_unwrap = ctor.unwrap;
                                receiver_ctor_param_decoders = ctor_decoders;
                            }
                        }
                    }
                }
                None => {
                    if !type_reachable_at_crate_root(&crate_root_src, &target.name, impl_module) {
                        if module_chain_has_private(&manifest_dir, &crate_root_src, &module) {
                            // §27.10: a free fn in a private module is unreachable
                            // externally (E0603) — build the harness IN-CRATE so a
                            // `crate::<module>::<fn>` path reaches it.
                            return resolve_in_crate_target(
                                &source,
                                &fns,
                                target,
                                &manifest_dir,
                                &crate_name,
                                &crate_root_src,
                                &module,
                                file_is_fuzz_target,
                            );
                        }
                        call_path.extend(module.iter().cloned());
                    }
                }
            }
            call_path.push(target.name.clone());
            // A STATIC trait-impl method (`impl ByteOrder for BigEndian { fn
            // read_u32(..) }`) must be called by UFCS — `BigEndian::read_u32(..)`
            // fails without the trait in scope. Resolve the trait to a reachable
            // path so the harness emits `<byteorder::BigEndian as
            // byteorder::ByteOrder>::read_u32(..)`. Gated to static methods (a
            // `&self` trait method needs a constructed receiver instead).
            let ufcs_trait = if target.is_static {
                target
                    .impl_trait
                    .as_deref()
                    .and_then(|tr| {
                        resolve_in_crate_trait_path(&manifest_dir, &crate_name, &crate_root_src, tr)
                    })
                    // F6: well-known std/core conversion traits (`FromStr`,
                    // `TryFrom<&[u8]>`, `TryFrom<&str>`) are UFCS-callable from a
                    // dependent crate even though they aren't in-crate traits, so the
                    // type's static `from_str` / `try_from` becomes a byte->typed
                    // fuzz target instead of being skipped. Gated to a NON-generic
                    // receiver type: `impl FromStr for Map<String, Value>` can't be
                    // called via the bare `Map` path, so it stays a clean skip.
                    .or_else(|| {
                        if enclosing_impl_type_is_generic(&source, target.line) {
                            None
                        } else {
                            std_ufcs_trait_path(&target)
                        }
                    })
            } else {
                None
            };
            // A STATIC trait-impl method is only callable by UFCS (`Type::method`
            // needs the trait in scope). If the trait isn't an in-crate, reachable
            // trait (a std/external trait like `From`/`Default`, or a private one),
            // there's no sound UFCS path — skip cleanly rather than emitting a call
            // that fails to build. Keeps the in-crate-trait win (byteorder) without
            // flooding discovery with std-conversion impls.
            if target.is_static && target.impl_trait.is_some() && ufcs_trait.is_none() {
                return Err(format!(
                    "Rust target '{}' is a static method of a non-in-crate trait impl \
                     (callable only by UFCS with an in-crate trait); not auto-harnessable",
                    target.name
                ));
            }
            // An INSTANCE trait-impl method (`recv.remaining()` from bytes' `Buf`,
            // `recv.deref()` from `Deref`) needs the trait in scope. Resolve a
            // reachable trait path to `use ... as _;` in the harness; method-call
            // syntax then finds it (no UFCS / self-kind needed). Unresolved -> no
            // import (a prelude trait still works; anything else fails as before).
            let method_trait_import = if !target.is_static {
                target.impl_trait.as_deref().and_then(|tr| {
                    resolve_method_trait_import(
                        &manifest_dir,
                        &crate_name,
                        &crate_root_src,
                        tr,
                        &target.name,
                    )
                })
            } else {
                None
            };
            // #458: resolve a marker type param (e.g. `B: ByteOrder`, used by no
            // value arg) to a concrete impl reachable in the crate and bake a
            // turbofish onto the call (`parse::<BigEndian>(..)`), stripping the
            // resolved param so monomorphization no longer rejects the candidate.
            let mut target = target;
            apply_marker_turbofish(
                &mut call_path,
                &mut target,
                &manifest_dir,
                &crate_name,
                &crate_root_src,
            );
            // Resolve unit-enum params to fuzz-byte-indexed variant picks so an
            // otherwise-undecodable enum argument (e.g. `lex(&str, AdaStandard)`)
            // doesn't get the whole candidate skipped.
            let param_decoders = resolve_param_overrides(
                &manifest_dir,
                &crate_name,
                &crate_root_src,
                &target.params,
            );
            Ok(ResolvedTarget {
                call_path,
                target,
                manifest_dir,
                crate_name,
                in_fuzz_target: file_is_fuzz_target,
                build_mode: BuildMode::External,
                receiver,
                receiver_ctor_params,
                receiver_unwrap,
                param_decoders,
                receiver_ctor_param_decoders,
                ufcs_trait,
                method_trait_import,
            })
        }
        None => Err(format!(
            "Rust target '{}' not found in {}",
            candidate.name,
            candidate.source_path.display()
        )),
    }
}

/// §27.1: resolve a method DECLARED in a `pub trait` (byteorder's
/// `ReadBytesExt::read_u32`) to a built+fuzzed harness by synthesising a std-reader
/// receiver. A reader trait (`: io::Read`/`BufRead`) gets a `std::io::Cursor`
/// receiver wrapping the fuzz bytes; the trait is imported so the extension method
/// resolves, and the existing marker-turbofish bakes any `read_u32::<BigEndian>`
/// type argument. A static trait method, or an instance method on a non-reader
/// trait, has no constructable receiver and is skipped cleanly (matching the
/// ranking demotion so it never reaches here with budget to waste).
fn resolve_reader_trait_method(
    target: rust_parser::RustFn,
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    in_fuzz_target: bool,
) -> Result<ResolvedTarget, String> {
    if target.is_static {
        return Err(format!(
            "Rust target '{}' is a static (associated) trait method — no receiver to \
             construct and not UFCS-callable without a concrete type; not auto-harnessable",
            target.name
        ));
    }
    if !trait_supertrait_is_reader(target.trait_supertrait.as_deref()) {
        return Err(format!(
            "Rust target '{}' is a trait method whose trait is not a `Read`/`BufRead` \
             reader — no constructable receiver (only a std-reader Cursor is synthesised); \
             not auto-harnessable",
            target.name
        ));
    }
    // The declaring trait must be imported so `recv.method()` resolves to the
    // extension method. Resolve a reachable path; an unresolvable trait means the
    // call can't compile, so skip cleanly.
    let trait_spelling = target.impl_trait.clone().unwrap_or_default();
    let method_trait_import = resolve_method_trait_import(
        manifest_dir,
        crate_name,
        crate_root_src,
        &trait_spelling,
        &target.name,
    );
    if method_trait_import.is_none() {
        return Err(format!(
            "Rust target '{}': could not resolve a reachable path to its reader trait \
             `{trait_spelling}` to import; not auto-harnessable",
            target.name
        ));
    }
    // For a receiver call, `build_call_body` uses only the LAST segment of
    // `call_path` (the method) — and `apply_marker_turbofish` bakes the marker type
    // argument onto it (`read_u32::<byteorder::BigEndian>`).
    let mut call_path = vec![crate_name.to_owned(), target.name.clone()];
    let mut target = target;
    apply_marker_turbofish(
        &mut call_path,
        &mut target,
        manifest_dir,
        crate_name,
        crate_root_src,
    );
    // The receiver: `std::io::Cursor::new(<Vec<u8> of the rest of the input>)`.
    // `Cursor<Vec<u8>>` implements `io::Read`, so the crate's blanket
    // `impl<R: Read + ?Sized> Trait for R {}` grants the extension method.
    let receiver = Some(vec![
        "std".to_owned(),
        "io".to_owned(),
        "Cursor".to_owned(),
        "new".to_owned(),
    ]);
    let receiver_ctor_params = vec![rust_parser::RustParam {
        name: "_gf_reader".to_owned(),
        ty: "Vec<u8>".to_owned(),
    }];
    // Feed the reader the rest of the fuzz input directly (a `Vec<u8>` by move).
    let receiver_ctor_param_decoders = vec![Some((
        "c.rest_bytes()".to_owned(),
        harness_gen::rust_decoders::ArgPass::Move,
    ))];
    // The method's OWN params (most reader methods take none) decode normally; an
    // undecodable param makes `generate_rust_direct_harness` skip cleanly.
    let param_decoders =
        resolve_param_overrides(manifest_dir, crate_name, crate_root_src, &target.params);
    Ok(ResolvedTarget {
        call_path,
        target,
        manifest_dir: manifest_dir.to_path_buf(),
        crate_name: crate_name.to_owned(),
        in_fuzz_target,
        build_mode: BuildMode::External,
        receiver,
        receiver_ctor_params,
        receiver_unwrap: harness_gen::rust_generate::ReceiverUnwrap::Direct,
        param_decoders,
        receiver_ctor_param_decoders,
        ufcs_trait: None,
        method_trait_import,
    })
}

/// True when a trait's supertrait bound spelling names a `std::io::Read` /
/// `BufRead` reader (so a `pub trait`'s instance method has a constructable
/// `std::io::Cursor` receiver). Mirrors `target_rank::rust_rank`'s reader test.
fn trait_supertrait_is_reader(supertrait: Option<&str>) -> bool {
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

/// §27.10: resolve a `pub` target in a PRIVATE module (E0603 from an external
/// dependent crate) to an IN-CRATE build. The call path is rooted at `crate` (which
/// reaches the private module from inside the crate) rather than the external crate
/// name. Supports the common shapes — a free fn, or an instance/associated method
/// on a type with a no-override-needed receiver ctor. Param/ctor-arg OVERRIDES
/// (enum picks, scratch consts) and trait-impl methods are NOT supported in-crate
/// (they would need `crate`-rooted override paths); such a target skips cleanly.
#[allow(clippy::too_many_arguments)]
fn resolve_in_crate_target(
    source: &str,
    fns: &[rust_parser::RustFn],
    target: rust_parser::RustFn,
    manifest_dir: &Path,
    crate_name: &str,
    crate_root_src: &str,
    module: &[String],
    in_fuzz_target: bool,
) -> Result<ResolvedTarget, String> {
    // A trait-impl method needs its trait in scope via a `crate`-rooted path we do
    // not yet synthesise in-crate; skip cleanly rather than emit a wrong path.
    if target.impl_trait.is_some() {
        return Err(format!(
            "Rust target '{}' is a private-module trait-impl method — in-crate trait \
             resolution is not yet supported; skipped",
            target.name
        ));
    }
    // Root the path at `crate` so the private module is reachable from inside the
    // injected harness module.
    let mut call_path = vec!["crate".to_owned()];
    call_path.extend(module.iter().cloned());
    let mut receiver = None;
    let mut receiver_ctor_params = Vec::new();
    let mut receiver_unwrap = harness_gen::rust_generate::ReceiverUnwrap::Direct;
    if let Some(ty) = enclosing_impl_type(source, target.line) {
        call_path.push(ty.clone());
        if !target.is_static {
            // A receiver ctor whose args are all natively decodable (no enum/const
            // overrides, which would need `crate`-rooted paths we skip in-crate).
            let Some(ctor) = find_receiver_ctor(source, fns, &ty, &|_| false) else {
                return Err(format!(
                    "Rust target '{}' (in-crate) is a &self method with no usable, \
                     override-free receiver constructor; skipped",
                    target.name
                ));
            };
            // A scratch-slice ctor arg can't be filled without an override -> skip.
            if ctor.params.iter().any(|p| scratch_slice(&p.ty).is_some()) {
                return Err(format!(
                    "Rust target '{}' (in-crate) needs a scratch-slice receiver ctor arg \
                     (no in-crate override); skipped",
                    target.name
                ));
            }
            let mut ctor_path = call_path.clone();
            if ctor.params.is_empty() {
                if let Some(tf) = receiver_generic_turbofish(source, &ty) {
                    if let Some(last) = ctor_path.last_mut() {
                        last.push_str(&tf);
                    }
                }
            }
            ctor_path.push(ctor.name);
            receiver = Some(ctor_path);
            receiver_ctor_params = ctor.params;
            receiver_unwrap = ctor.unwrap;
        }
    }
    call_path.push(target.name.clone());
    let mut target = target;
    apply_marker_turbofish(
        &mut call_path,
        &mut target,
        manifest_dir,
        crate_name,
        crate_root_src,
    );
    Ok(ResolvedTarget {
        call_path,
        target,
        manifest_dir: manifest_dir.to_path_buf(),
        crate_name: crate_name.to_owned(),
        in_fuzz_target,
        build_mode: BuildMode::InCrate,
        receiver,
        receiver_ctor_params,
        receiver_unwrap,
        // In-crate mode uses only native decoders (no `crate`-rooted overrides).
        param_decoders: Vec::new(),
        receiver_ctor_param_decoders: Vec::new(),
        ufcs_trait: None,
        method_trait_import: None,
    })
}

/// Locate the `c_runtime` directory (which holds `govfuzz_driver.c` +
/// `govfuzz_decode.h`). Mirrors `generate_harness::locate_c_runtime` so the Rust
/// lane finds the same driver source the C lane uses, with an executable-relative
/// fallback for an installed binary whose source tree is elsewhere.
fn locate_c_runtime_dir() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("c_runtime");
                if cand.join("govfuzz_driver.c").is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("c_runtime");
    if from_manifest.join("govfuzz_driver.c").is_file() {
        return Some(from_manifest);
    }
    None
}

/// Generate the harness crate + driver into `harness_dir` and build it to
/// `<work>/harnesses/<id>/main`. The single public entry point of the lane.
pub fn build_rust_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
) -> RustBuildResult {
    let Some(c_runtime_dir) = locate_c_runtime_dir() else {
        return RustBuildResult::Failed {
            reason: "could not locate c_runtime/govfuzz_driver.c for the Rust fork-server driver"
                .to_owned(),
            skip: false,
        };
    };
    let c_runtime_dir = c_runtime_dir.as_path();
    let Some(toolchain) = probe_toolchain() else {
        return RustBuildResult::Failed {
            reason: "no `cargo +nightly` toolchain found; install rustup nightly to fuzz Rust \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };

    let resolved = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return RustBuildResult::Failed { reason, skip: true },
    };

    // A feature-gated target (`#[cfg(feature = "X")]`) must have its feature ENABLED
    // in the harness dep, else the path resolves to nothing (E0425 false
    // failed_build). Resolve the declared features required by the candidate's cfg; a
    // gate the crate cannot satisfy (the feature isn't declared) skips cleanly.
    let target_features = match resolve_target_features(candidate, &resolved.manifest_dir) {
        Ok(f) => f,
        Err(reason) => return RustBuildResult::Failed { reason, skip: true },
    };

    // Generate the harness source.
    let harness = if resolved.in_fuzz_target && !resolved.target.is_static {
        // A non-callable existing-harness file: wrap the resolved byte entry.
        match generate_rust_existing_fuzz_target(&resolved.call_path) {
            Ok(h) => h,
            Err(e) => {
                return RustBuildResult::Failed {
                    reason: e.to_string(),
                    skip: true,
                }
            }
        }
    } else {
        match generate_rust_direct_harness(&GenerateRustDirectArgs {
            call_path: resolved.call_path.clone(),
            target: resolved.target.clone(),
            receiver: resolved.receiver.clone(),
            receiver_ctor_params: resolved.receiver_ctor_params.clone(),
            receiver_unwrap: resolved.receiver_unwrap,
            param_decoders: resolved.param_decoders.clone(),
            receiver_ctor_param_decoders: resolved.receiver_ctor_param_decoders.clone(),
            ufcs_trait: resolved.ufcs_trait.clone(),
            method_trait_import: resolved.method_trait_import.clone(),
        }) {
            Ok(h) => h,
            Err(e) => {
                return RustBuildResult::Failed {
                    reason: e.to_string(),
                    skip: true,
                }
            }
        }
    };

    // §27.10: an in-crate target builds the harness AS A MODULE of a copy of the
    // target crate (so a private-module `crate::internal::...` path is reachable),
    // not as an external staticlib that can only see the crate's `pub` API.
    if resolved.build_mode == BuildMode::InCrate {
        return build_in_crate(
            &resolved,
            &harness,
            work_dir,
            harness_id,
            &toolchain,
            c_runtime_dir,
        );
    }

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return RustBuildResult::Failed {
            reason: format!("create harness dir {}: {e}", auto_dir.display()),
            skip: false,
        };
    }

    // Emit the staticlib harness crate beside the harness dir.
    let crate_dir = auto_dir.join("rust_harness");
    if let Err(e) = emit_harness_crate(
        &crate_dir,
        &harness.harness_rs,
        &resolved.crate_name,
        &resolved.manifest_dir,
        &target_features,
    ) {
        return RustBuildResult::Failed {
            reason: e,
            skip: false,
        };
    }

    // Copy the C driver beside the binary as `main.c` (the GOVFUZZ_FRAMED marker
    // the engine greps for).
    let driver_src = c_runtime_dir.join("govfuzz_driver.c");
    let main_c = auto_dir.join("main.c");
    if let Err(e) = std::fs::copy(&driver_src, &main_c) {
        return RustBuildResult::Failed {
            reason: format!(
                "copy driver {} -> {}: {e}",
                driver_src.display(),
                main_c.display()
            ),
            skip: false,
        };
    }

    // cargo build the staticlib.
    let target_dir = crate_dir.join("target");
    let build = Command::new(&toolchain.cargo)
        .arg(&toolchain.channel_arg)
        .arg("build")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        // Explicit host `--target` so build scripts + proc-macros build for the
        // host without the sanitizer RUSTFLAGS (sanitizers can't be applied to
        // host-run proc-macros like `zerofrom_derive`); target crates still get
        // them. Output then lands in `target/<triple>/debug/`.
        .arg("--target")
        .arg(&toolchain.host_triple)
        .env("RUSTFLAGS", sancov_rustflags())
        .output();
    let build = match build {
        Ok(o) => o,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("spawn cargo: {e}"),
                skip: false,
            }
        }
    };
    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr);
        let kinds = classify(&stderr);
        let skip = kinds.iter().any(|k| {
            matches!(
                k,
                RustBuildError::ToolchainUnsupported { .. }
                    | RustBuildError::UnresolvedPath { .. }
                    | RustBuildError::SignatureMismatch { .. }
            )
        });
        return RustBuildResult::Failed {
            reason: format!("cargo build failed: {}", summarize(&kinds)),
            skip,
        };
    }

    // Locate the produced staticlib (under target/<triple>/debug/ since we built
    // with an explicit --target).
    let staticlib = match find_staticlib(&target_dir, &toolchain.host_triple) {
        Some(p) => p,
        None => {
            return RustBuildResult::Failed {
                reason: "cargo build succeeded but produced no staticlib (.a)".to_owned(),
                skip: false,
            }
        }
    };

    // clang-link: driver main.c + the Rust staticlib -> harnesses/<id>/main, with the
    // SAME sancov+ASan instrumentation on the driver so its callbacks match.
    let main_bin = auto_dir.join("main");
    let link = Command::new("clang")
        .arg("-O1")
        .arg("-g")
        .arg("-fsanitize=address")
        .arg("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        .arg("-I")
        .arg(c_runtime_dir)
        .arg("-o")
        .arg(&main_bin)
        .arg(&main_c)
        .arg(&staticlib)
        // The Rust staticlib needs libstd's transitive C deps.
        .arg("-lpthread")
        .arg("-ldl")
        .arg("-lm")
        .arg("-lrt")
        .output();
    let link = match link {
        Ok(o) => o,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("spawn clang link: {e}"),
                skip: false,
            }
        }
    };
    if !link.status.success() {
        let stderr = String::from_utf8_lossy(&link.stderr);
        return RustBuildResult::Failed {
            reason: format!(
                "clang link failed: {}",
                stderr.lines().take(8).collect::<Vec<_>>().join("\n")
            ),
            skip: false,
        };
    }
    if !main_bin.is_file() {
        return RustBuildResult::Failed {
            reason: "link reported success but no `main` binary was produced".to_owned(),
            skip: false,
        };
    }
    RustBuildResult::Built
}

/// §27.10: build an in-crate harness. Copies the target crate, injects the harness
/// as a `#[doc(hidden)] pub mod __govfuzz_harness;` of its lib root (so its
/// `crate::...` paths reach private modules), builds the copy as a `staticlib`, and
/// clang-links it with the C fork-server driver — the same execution artifact the
/// external lane produces, but reaching the crate's private API.
fn build_in_crate(
    resolved: &ResolvedTarget,
    harness: &harness_gen::rust_generate::GeneratedRustHarness,
    work_dir: &Path,
    harness_id: &str,
    toolchain: &RustToolchain,
    c_runtime_dir: &Path,
) -> RustBuildResult {
    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let crate_copy = auto_dir.join("incrate");
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return RustBuildResult::Failed {
            reason: format!("create harness dir {}: {e}", auto_dir.display()),
            skip: false,
        };
    }

    // Copy the target crate's source (excluding build/VCS dirs) into the work tree
    // so we never mutate the user's checkout.
    let _ = std::fs::remove_dir_all(&crate_copy);
    if let Err(e) = copy_dir_filtered(&resolved.manifest_dir, &crate_copy, &["target", ".git"]) {
        return RustBuildResult::Failed {
            reason: format!("copy target crate for in-crate build: {e}"),
            skip: false,
        };
    }

    // Locate the lib root in the copy (the module we inject into).
    let src = crate_copy.join("src");
    let lib_root = ["lib.rs", "main.rs"]
        .iter()
        .map(|f| src.join(f))
        .find(|p| p.is_file());
    let Some(lib_root) = lib_root else {
        return RustBuildResult::Failed {
            reason: "in-crate build: target crate has no src/lib.rs or src/main.rs to inject into"
                .to_owned(),
            skip: true,
        };
    };

    // Read the lib root once, up front, both to gate on `#![forbid(unsafe_code)]`
    // and to inject the harness module declaration below.
    let lib_text = match std::fs::read_to_string(&lib_root) {
        Ok(t) => t,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("read {} for injection: {e}", lib_root.display()),
                skip: false,
            }
        }
    };
    // A crate with a crate-level `forbid(unsafe_code)` (regex-syntax; pulldown-cmark
    // via `#![cfg_attr(not(feature = "simd"), forbid(unsafe_code))]`) can't host the
    // in-crate harness — which needs `#[no_mangle]` (now an unsafe attribute) + an
    // `unsafe` FFI block — and `forbid` is NOT overridable by an inner `#[allow]`.
    // Skip cleanly rather than inject a module that fails to compile with
    // "declaration of a `no_mangle` function" / "usage of an `unsafe` block" (the
    // external-API lane still applies).
    if forbids_unsafe_code(&lib_text) {
        return RustBuildResult::Failed {
            reason: "in-crate build: target crate forbids unsafe code \
                     (`forbid(unsafe_code)`, possibly via `cfg_attr`); the injected harness \
                     needs no_mangle + unsafe FFI which forbid disallows — skipped"
                .to_owned(),
            skip: true,
        };
    }

    // Inject the harness module: write it beside the lib root and declare it. The
    // injected module is compiled with the TARGET crate's edition, so its
    // `#[no_mangle]` export must use the `#[unsafe(no_mangle)]` form — a bare
    // `#[no_mangle]` is a HARD ERROR on edition 2024 ("unsafe attribute used without
    // unsafe"). The wrapped form is accepted on every edition (rustc ≥ 1.82).
    let harness_module = incrate_harness_with_unsafe_no_mangle(&harness.harness_rs);
    if let Err(e) = std::fs::write(src.join("__govfuzz_harness.rs"), &harness_module) {
        return RustBuildResult::Failed {
            reason: format!("write in-crate harness module: {e}"),
            skip: false,
        };
    }
    let mut text = lib_text;
    text.push_str(
        "\n// GENERATED by govfuzz — in-crate fuzz harness module (§27.10).\n\
         #[doc(hidden)]\npub mod __govfuzz_harness;\n",
    );
    if let Err(e) = std::fs::write(&lib_root, text) {
        return RustBuildResult::Failed {
            reason: format!("inject harness module into {}: {e}", lib_root.display()),
            skip: false,
        };
    }

    // Locate rust_runtime and rewrite the copy's Cargo.toml: add the rust_runtime
    // dep the harness needs, a `staticlib` crate-type, and detach from any parent
    // workspace.
    let Some(rust_runtime_dir) = locate_rust_runtime() else {
        return RustBuildResult::Failed {
            reason: "could not locate the rust_runtime crate for the in-crate harness dep"
                .to_owned(),
            skip: false,
        };
    };
    let manifest_path = crate_copy.join("Cargo.toml");
    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("read copied Cargo.toml: {e}"),
                skip: false,
            }
        }
    };
    let patched =
        match prepare_incrate_manifest(&manifest_text, &resolved.manifest_dir, &rust_runtime_dir) {
            Ok(p) => p,
            Err(reason) => return RustBuildResult::Failed { reason, skip: true },
        };
    if let Err(e) = std::fs::write(&manifest_path, patched) {
        return RustBuildResult::Failed {
            reason: format!("write patched in-crate Cargo.toml: {e}"),
            skip: false,
        };
    }

    // Copy the C driver beside the binary as `main.c`.
    let driver_src = c_runtime_dir.join("govfuzz_driver.c");
    let main_c = auto_dir.join("main.c");
    if let Err(e) = std::fs::copy(&driver_src, &main_c) {
        return RustBuildResult::Failed {
            reason: format!("copy driver to {}: {e}", main_c.display()),
            skip: false,
        };
    }

    // Build the copied crate (now a staticlib exporting `govfuzz_run_one`).
    let target_dir = crate_copy.join("target");
    let build = Command::new(&toolchain.cargo)
        .arg(&toolchain.channel_arg)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(&toolchain.host_triple)
        .env("RUSTFLAGS", sancov_rustflags())
        .output();
    let build = match build {
        Ok(o) => o,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("spawn cargo (in-crate): {e}"),
                skip: false,
            }
        }
    };
    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr);
        let kinds = classify(&stderr);
        let skip = kinds.iter().any(|k| {
            matches!(
                k,
                RustBuildError::ToolchainUnsupported { .. }
                    | RustBuildError::UnresolvedPath { .. }
                    | RustBuildError::SignatureMismatch { .. }
            )
        });
        return RustBuildResult::Failed {
            reason: format!("in-crate cargo build failed: {}", summarize(&kinds)),
            skip,
        };
    }

    // The staticlib is named after the target crate's import name (`lib<name>.a`).
    let staticlib =
        match find_incrate_staticlib(&target_dir, &toolchain.host_triple, &resolved.crate_name) {
            Some(p) => p,
            None => {
                return RustBuildResult::Failed {
                    reason: "in-crate build succeeded but produced no staticlib (.a)".to_owned(),
                    skip: false,
                }
            }
        };

    // clang-link the driver + the crate staticlib -> harnesses/<id>/main.
    let main_bin = auto_dir.join("main");
    let link = Command::new("clang")
        .arg("-O1")
        .arg("-g")
        .arg("-fsanitize=address")
        .arg("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        .arg("-I")
        .arg(c_runtime_dir)
        .arg("-o")
        .arg(&main_bin)
        .arg(&main_c)
        .arg(&staticlib)
        .arg("-lpthread")
        .arg("-ldl")
        .arg("-lm")
        .arg("-lrt")
        .output();
    let link = match link {
        Ok(o) => o,
        Err(e) => {
            return RustBuildResult::Failed {
                reason: format!("spawn clang link (in-crate): {e}"),
                skip: false,
            }
        }
    };
    if !link.status.success() {
        let stderr = String::from_utf8_lossy(&link.stderr);
        return RustBuildResult::Failed {
            reason: format!(
                "in-crate clang link failed: {}",
                stderr.lines().take(8).collect::<Vec<_>>().join("\n")
            ),
            skip: false,
        };
    }
    if !main_bin.is_file() {
        return RustBuildResult::Failed {
            reason: "in-crate link reported success but no `main` binary was produced".to_owned(),
            skip: false,
        };
    }
    RustBuildResult::Built
}

/// Recursively copy `src` into `dst`, skipping any directory whose file name is in
/// `skip_dirs` (e.g. `target`, `.git`). Files are copied verbatim.
fn copy_dir_filtered(src: &Path, dst: &Path, skip_dirs: &[&str]) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            if name.to_str().is_some_and(|n| skip_dirs.contains(&n)) {
                continue;
            }
            copy_dir_filtered(&from, &to, skip_dirs)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// True when the crate root carries a crate-level `forbid(unsafe_code)` that the
/// in-crate harness can't compile under. Covers the direct
/// `#![forbid(unsafe_code)]` (any arg order, e.g. `#![forbid(missing_docs,
/// unsafe_code)]`) AND the conditional `#![cfg_attr(<pred>, forbid(unsafe_code))]`
/// form (pulldown-cmark gates its forbid on the `simd` feature, which the in-crate
/// build never enables — so the forbid is active and the injected `#[no_mangle]`
/// harness, now an unsafe attribute, is rejected: "declaration of a `no_mangle`
/// function").
///
/// `forbid` is NOT overridable by an inner `#[allow(unsafe_code)]`, so the in-crate
/// harness module (which needs `#[no_mangle]` + an `unsafe` FFI block) can't compile
/// inside such a crate — the caller skips the in-crate lane cleanly. The cfg
/// predicate is NOT evaluated: any crate-level attribute that can activate
/// `forbid(unsafe_code)` is treated as forbidding (conservative — at worst a crate
/// that would have built is skipped and falls back to the external-API lane).
fn forbids_unsafe_code(lib_root_src: &str) -> bool {
    lib_root_src.lines().any(|raw| {
        let l = raw.trim();
        // Only a crate-level inner attribute (`#![...]`) can forbid unsafe code
        // crate-wide; an outer `#[...]`, a doc comment, or ordinary code can't.
        l.starts_with("#![") && attr_forbids_unsafe_code(l)
    })
}

/// Scan a crate-level attribute line for any `forbid(...)` whose comma-separated
/// arguments include `unsafe_code`. Handles both `#![forbid(unsafe_code)]` and a
/// nested `cfg_attr(<pred>, forbid(unsafe_code))`. (`deny(unsafe_code)` is
/// overridable and intentionally not matched; `forbid_xyz` without an immediate `(`
/// can't match the `forbid(` needle.)
fn attr_forbids_unsafe_code(line: &str) -> bool {
    let mut rest = line;
    while let Some(idx) = rest.find("forbid(") {
        let after = &rest[idx + "forbid(".len()..];
        let inner = after.split(')').next().unwrap_or("");
        if inner.split(',').any(|t| t.trim() == "unsafe_code") {
            return true;
        }
        rest = after;
    }
    false
}

/// Rewrite the injected in-crate harness module so its `#[no_mangle]` export uses
/// the `#[unsafe(no_mangle)]` form. A bare `#[no_mangle]` is a HARD ERROR when the
/// target crate is edition 2024 ("unsafe attribute used without unsafe"); the
/// wrapped form is accepted on every edition (rustc ≥ 1.82), so the injected harness
/// compiles inside edition-2024 crates too. The external lane builds its own
/// edition-2021 crate and is unaffected (it keeps using `harness_rs` verbatim).
fn incrate_harness_with_unsafe_no_mangle(harness_rs: &str) -> String {
    harness_rs.replace("#[no_mangle]", "#[unsafe(no_mangle)]")
}

/// The base field name of a workspace-INHERITED package-field line, if any: matches
/// the dotted form `key.workspace = true` and the inline-table form `key = {
/// workspace = true }`. `include.workspace = true` -> `Some("include")`. `None` for
/// any concrete field (including a non-pure inline table like
/// `key = { workspace = true, optional = true }`, which is a dependency, not a
/// package field).
fn inherited_field_key(line: &str) -> Option<String> {
    let line = line.trim();
    let (lhs, rhs) = line.split_once('=')?;
    let lhs = lhs.trim();
    // Drop a trailing comment off the value (`include.workspace = true # …`).
    let rhs = rhs.split('#').next().unwrap_or(rhs).trim();
    if let Some(base) = lhs.strip_suffix(".workspace") {
        if rhs == "true" {
            return Some(base.trim().to_owned());
        }
    }
    if rhs.starts_with('{') {
        let inner = rhs.trim_start_matches('{').trim_end_matches('}');
        if inner.replace(' ', "") == "workspace=true" {
            return Some(lhs.to_owned());
        }
    }
    None
}

/// The key (text before `=`) of a simple `key = value` line, or `None` for a blank
/// line, comment, section header, or a line without `=`.
fn toml_line_key(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    let (lhs, _) = line.split_once('=')?;
    Some(lhs.trim().to_owned())
}

/// Rewrite a copied workspace-MEMBER manifest so the DETACHED copy (govfuzz appends
/// its own `[workspace]`) still parses. A modern member inherits fields from the
/// workspace root via `field.workspace = true` (`version`/`edition`/`include`/…) and
/// points at its root with `workspace = ".."`; once detached, cargo can resolve
/// neither and HARD-FAILS ("failed to parse manifest" / "cannot configure both
/// `package.workspace` and `[workspace]`"). Resolve the two REQUIRED fields
/// (`version`, `edition`) to concrete defaults, DROP every other (optional metadata)
/// inherited field, and DROP the `package.workspace` pointer.
fn strip_workspace_inheritance(manifest: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut have_version = false;
    let mut have_edition = false;
    let mut package_header: Option<usize> = None;
    for raw in manifest.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_owned();
            if section == "package" {
                package_header = Some(lines.len());
            }
            lines.push(raw.to_owned());
            continue;
        }
        if section == "package" {
            // The `package.workspace = ".."` pointer conflicts with the detached
            // `[workspace]` govfuzz appends — drop it.
            if toml_line_key(trimmed).as_deref() == Some("workspace") {
                continue;
            }
            if let Some(base) = inherited_field_key(trimmed) {
                match base.as_str() {
                    "version" => {
                        lines.push("version = \"0.0.0\"".to_owned());
                        have_version = true;
                    }
                    "edition" => {
                        lines.push("edition = \"2021\"".to_owned());
                        have_edition = true;
                    }
                    // Every other inherited field is OPTIONAL metadata not needed to
                    // build the staticlib — drop the line.
                    _ => {}
                }
                continue;
            }
            match toml_line_key(trimmed).as_deref() {
                Some("version") => have_version = true,
                Some("edition") => have_edition = true,
                _ => {}
            }
        }
        lines.push(raw.to_owned());
    }
    // Inject concrete REQUIRED fields the package now lacks (absent, or were only
    // present as a workspace inheritance we just dropped).
    if let Some(idx) = package_header {
        if !have_edition {
            lines.insert(idx + 1, "edition = \"2021\"".to_owned());
        }
        if !have_version {
            lines.insert(idx + 1, "version = \"0.0.0\"".to_owned());
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// True when `b` can appear in a TOML bare key (so `path` inside `rustpath` is not a
/// `path` key match).
fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b == b'-' || b.is_ascii_alphanumeric()
}

/// The byte range of the double-quoted value of `key` on `line`
/// (`path = "../x"` -> the range covering `../x`), if `key` appears as a bare key
/// followed by `= "…"`. Word-boundary aware so `path` does not match `rustpath`.
fn find_quoted_value(line: &str, key: &str) -> Option<std::ops::Range<usize>> {
    let bytes = line.as_bytes();
    let mut search = 0;
    while let Some(rel) = line[search..].find(key) {
        let start = search + rel;
        let end_key = start + key.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let mut j = end_key;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if before_ok && j < bytes.len() && bytes[j] == b'=' {
            j += 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                let vstart = j + 1;
                if let Some(rel_end) = line[vstart..].find('"') {
                    return Some(vstart..vstart + rel_end);
                }
            }
        }
        search = end_key;
    }
    None
}

/// Lexically resolve `base.join(rel)` (an absolute `base`): collapse `.` and `..`
/// segments WITHOUT touching the filesystem (the path may not exist yet). `..` never
/// pops past the root. Keeps emitted manifests clean (`/a/b/../c` -> `/a/c`).
fn lexical_join(base: &Path, rel: &str) -> PathBuf {
    use std::path::Component;
    let mut comps: Vec<std::ffi::OsString> = Vec::new();
    for c in base.join(rel).components() {
        match c {
            Component::ParentDir => {
                // Don't pop the root (`/`) or a leading `..` we couldn't resolve.
                if comps.last().is_some_and(|s| s != "/") {
                    comps.pop();
                }
            }
            Component::CurDir => {}
            other => comps.push(other.as_os_str().to_owned()),
        }
    }
    comps.iter().collect()
}

/// In a single dependency line, rewrite a RELATIVE `path = "..."` to an absolute path
/// anchored at `base` (the original crate dir). Absolute/non-path lines pass through.
fn rewrite_path_value(line: &str, base: &Path) -> String {
    let Some(range) = find_quoted_value(line, "path") else {
        return line.to_owned();
    };
    let val = &line[range.clone()];
    if Path::new(val).is_absolute() {
        return line.to_owned();
    }
    let abs = lexical_join(base, val);
    let abs = abs.to_string_lossy();
    let mut out = String::with_capacity(line.len() + abs.len());
    out.push_str(&line[..range.start]);
    out.push_str(&abs);
    out.push_str(&line[range.end..]);
    out
}

/// Rewrite RELATIVE `path = "..."` dependency values to ABSOLUTE paths anchored at
/// the ORIGINAL crate dir, so a copied member's sibling path-deps (`pest = { path =
/// "../pest" }`) resolve to the real on-disk crates instead of a missing
/// `<copy>/../pest`. Only touches dependency sections (`[dependencies]`,
/// `[dev-dependencies]`, `[build-dependencies]`, `[dependencies.foo]`,
/// `[target.'cfg(..)'.dependencies]`).
fn rewrite_relative_path_deps(manifest: &str, manifest_dir: &Path) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_dep_section = false;
    for raw in manifest.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_dep_section = trimmed.contains("dependencies");
            out.push(raw.to_owned());
            continue;
        }
        if in_dep_section {
            out.push(rewrite_path_value(raw, manifest_dir));
        } else {
            out.push(raw.to_owned());
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// Names of dependencies the member INHERITS from the workspace (`serde = {
/// workspace = true }` / `serde.workspace = true` / a `[dependencies.serde]` subtable
/// with `workspace = true`). The detached copy has no parent
/// `[workspace.dependencies]` to inherit from, so such a dep can't be resolved and
/// the in-crate build must skip cleanly. (Resolving these from the parent workspace
/// is a future enhancement; today the external-API lane still covers the crate.)
fn workspace_inherited_deps(manifest: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_dep_section = false;
    let mut subtable_dep: Option<String> = None;
    for raw in manifest.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let header = trimmed.trim_start_matches('[').trim_end_matches(']');
            in_dep_section = header.contains("dependencies");
            subtable_dep = if in_dep_section {
                header
                    .rsplit_once("dependencies.")
                    .map(|(_, n)| n.trim().to_owned())
            } else {
                None
            };
            continue;
        }
        if !in_dep_section {
            continue;
        }
        let norm = trimmed
            .split('#')
            .next()
            .unwrap_or(trimmed)
            .replace(' ', "");
        if norm.contains("workspace=true") {
            let name = if let Some(sub) = &subtable_dep {
                sub.clone()
            } else if let Some((lhs, _)) = trimmed.split_once('=') {
                lhs.trim().trim_end_matches(".workspace").trim().to_owned()
            } else {
                "<dependency>".to_owned()
            };
            found.push(name);
        }
    }
    found
}

/// Rewrite a copied crate's `Cargo.toml` for the in-crate harness build: detach it
/// from its parent workspace (resolve/strip workspace-INHERITED fields, make sibling
/// path-deps absolute), then ensure a `rust_runtime` path dependency, a `staticlib`
/// (+ `rlib`) lib crate-type, and a detached `[workspace]` so cargo builds the copy
/// standalone. `Err(reason)` requests a CLEAN SKIP (an actionable reason, like the
/// private-module skips) when the copy can't be made to resolve — e.g. a dependency
/// inherited from the parent `[workspace.dependencies]`.
fn prepare_incrate_manifest(
    manifest: &str,
    manifest_dir: &Path,
    rust_runtime_dir: &Path,
) -> Result<String, String> {
    // 0. Detach from the parent workspace BEFORE any other rewrite: resolve/strip
    //    workspace-inherited package fields + the `workspace = ".."` pointer, then
    //    make sibling path-deps absolute so they still resolve from the copy.
    let stripped = strip_workspace_inheritance(manifest);
    let stripped = rewrite_relative_path_deps(&stripped, manifest_dir);
    let inherited = workspace_inherited_deps(&stripped);
    if !inherited.is_empty() {
        return Err(format!(
            "in-crate build: target crate inherits {} from the parent workspace's \
             [workspace.dependencies], which the detached copy can't resolve — skipped \
             (the external-API lane still applies)",
            inherited
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut out = stripped;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    // 1. rust_runtime dependency.
    let runtime_dep = format!("rust_runtime = {{ path = {rust_runtime_dir:?} }}");
    if !out.contains("rust_runtime") {
        if let Some(pos) = section_header_end(&out, "[dependencies]") {
            out.insert_str(pos, &format!("{runtime_dep}\n"));
        } else {
            out.push_str(&format!("\n[dependencies]\n{runtime_dep}\n"));
        }
    }
    // 2. staticlib crate-type.
    if let Some(lib_pos) = section_header_end(&out, "[lib]") {
        if let Some(ct_line) = find_line_starting_with(&out, "crate-type") {
            // Add "staticlib" to the existing array if absent.
            if !out[ct_line.0..ct_line.1].contains("staticlib") {
                if let Some(bracket) = out[ct_line.0..ct_line.1].find('[') {
                    let at = ct_line.0 + bracket + 1;
                    out.insert_str(at, "\"staticlib\", ");
                }
            }
        } else {
            out.insert_str(lib_pos, "crate-type = [\"staticlib\", \"rlib\"]\n");
        }
    } else {
        out.push_str("\n[lib]\ncrate-type = [\"staticlib\", \"rlib\"]\n");
    }
    // 3. detach from any parent workspace.
    if !out.contains("[workspace]") {
        out.push_str("\n[workspace]\n");
    }
    Ok(out)
}

/// The byte offset just past the newline ending a `[section]` header line, or
/// `None` when the section is absent. Used to insert a line as the section's first
/// entry.
fn section_header_end(toml: &str, header: &str) -> Option<usize> {
    for line in toml.lines() {
        if line.trim() == header {
            // SAFETY: `line` is a slice of `toml`, so its end offset is valid.
            let end = line.as_ptr() as usize - toml.as_ptr() as usize + line.len();
            // Step past the trailing newline if present.
            return Some(if toml.as_bytes().get(end) == Some(&b'\n') {
                end + 1
            } else {
                end
            });
        }
    }
    None
}

/// The `(start, end)` byte range (excluding the trailing newline) of the first line
/// whose trimmed text starts with `prefix`, or `None`.
fn find_line_starting_with(toml: &str, prefix: &str) -> Option<(usize, usize)> {
    for line in toml.lines() {
        if line.trim_start().starts_with(prefix) {
            let start = line.as_ptr() as usize - toml.as_ptr() as usize;
            return Some((start, start + line.len()));
        }
    }
    None
}

/// Find the in-crate staticlib `lib<crate_name>.a` under `target/<triple>/debug/`,
/// falling back to the first `.a` there.
fn find_incrate_staticlib(
    target_dir: &Path,
    host_triple: &str,
    crate_name: &str,
) -> Option<PathBuf> {
    let debug = target_dir.join(host_triple).join("debug");
    let preferred = format!("lib{crate_name}.a");
    let mut first_a = None;
    for entry in std::fs::read_dir(&debug).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("a") {
            continue;
        }
        match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if name == preferred => return Some(path),
            _ => {
                if first_a.is_none() {
                    first_a = Some(path);
                }
            }
        }
    }
    first_a
}

fn summarize(kinds: &[RustBuildError]) -> String {
    kinds
        .iter()
        .map(|k| match k {
            RustBuildError::UnresolvedPath { path } => format!("unresolved path `{path}`"),
            RustBuildError::SignatureMismatch { detail } => detail.clone(),
            RustBuildError::ToolchainUnsupported { detail } => detail.clone(),
            RustBuildError::Other { tail } => tail.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Resolve the set of target-crate features the harness must enable so a
/// `#[cfg(feature = "X")]`-gated candidate is reachable. `Ok(vec![])` when the
/// candidate has no feature gate (or only a non-feature cfg like `unix`). `Err`
/// (a clean skip) when the gate requires a feature the crate does not declare —
/// enabling a nonexistent feature is a hard cargo error, so skip instead.
fn resolve_target_features(
    candidate: &Candidate,
    manifest_dir: &Path,
) -> Result<Vec<String>, String> {
    let Some(cond) = candidate.foreign_guard.as_deref() else {
        return Ok(Vec::new());
    };
    let Some(needed) = cfg_satisfying_features(cond) else {
        // No feature predicate in the cfg (a pure target/test gate) — nothing to
        // enable; leave the build as-is.
        return Ok(Vec::new());
    };
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let available = available_features(manifest_dir);
    let missing: Vec<String> = needed
        .iter()
        .filter(|f| !available.contains(*f))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "Rust target '{}' is gated behind cfg feature(s) {:?} the target crate does \
             not declare; cannot enable -> skipped.",
            candidate.name, missing
        ));
    }
    Ok(needed)
}

/// The set of features to ENABLE so a `#[cfg(...)]` condition holds, or `None` when
/// no feature can satisfy it (a pure target/test/`not` gate). `all(...)` unions its
/// feature-bearing conjuncts (non-feature conjuncts like `unix`/`not(test)` are
/// assumed ambiently satisfied); `any(...)` takes the first feature-satisfiable
/// alternative; `not(...)` yields nothing (satisfied by leaving the feature off).
fn cfg_satisfying_features(cond: &str) -> Option<Vec<String>> {
    let c = cond.trim();
    if let Some(inner) = cfg_combinator_inner(c, "all") {
        let mut out = Vec::new();
        let mut any_feature = false;
        for p in cfg_split_top_level(inner) {
            if let Some(fs) = cfg_satisfying_features(p) {
                any_feature = true;
                for f in fs {
                    if !out.contains(&f) {
                        out.push(f);
                    }
                }
            }
        }
        return any_feature.then_some(out);
    }
    if let Some(inner) = cfg_combinator_inner(c, "any") {
        for p in cfg_split_top_level(inner) {
            if let Some(fs) = cfg_satisfying_features(p) {
                return Some(fs);
            }
        }
        return None;
    }
    if cfg_combinator_inner(c, "not").is_some() {
        return None;
    }
    parse_feature_predicate(c).map(|f| vec![f])
}

/// If `c` is `kw(...)` (optionally `kw (...)`), return the inner argument text.
fn cfg_combinator_inner<'a>(c: &'a str, kw: &str) -> Option<&'a str> {
    let rest = c.trim().strip_prefix(kw)?.trim_start();
    rest.strip_prefix('(')?.strip_suffix(')')
}

/// Split a cfg argument list on TOP-LEVEL commas (not inside nested `(...)`).
fn cfg_split_top_level(inner: &str) -> Vec<&str> {
    let mut depth = 0i32;
    let mut parts = Vec::new();
    let mut start = 0usize;
    for (i, b) in inner.char_indices() {
        match b {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
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

/// Parse a `feature = "X"` cfg predicate, returning the feature name `X`.
fn parse_feature_predicate(c: &str) -> Option<String> {
    let rest = c
        .trim()
        .strip_prefix("feature")?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    let name = rest.strip_prefix('"')?.strip_suffix('"')?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// The set of feature names the target crate DECLARES — its `[features]` table keys
/// plus optional-dependency names (which implicitly define a same-named feature).
/// Empty on a read failure (then a feature gate is treated as unsatisfiable). A
/// line-based Cargo.toml scan, consistent with `section_value`/`crate_import_name`
/// (no `toml` dependency in the CLI's link graph — it is dev-only).
fn available_features(manifest_dir: &Path) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let Ok(text) = std::fs::read_to_string(manifest_dir.join("Cargo.toml")) else {
        return set;
    };
    #[derive(PartialEq)]
    enum Section {
        Features,
        Deps(Option<String>), // an inline deps table, or a [deps.<name>] sub-table
        Other,
    }
    let is_deps_table = |inner: &str| -> bool {
        matches!(
            inner,
            "dependencies" | "build-dependencies" | "dev-dependencies"
        ) || inner.ends_with(".dependencies")
            || inner.ends_with(".build-dependencies")
            || inner.ends_with(".dev-dependencies")
    };
    let mut section = Section::Other;
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(inner) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let inner = inner.trim();
            section = if inner == "features" {
                Section::Features
            } else if let Some(name) = inner
                .strip_prefix("dependencies.")
                .or_else(|| inner.strip_prefix("dev-dependencies."))
                .or_else(|| inner.strip_prefix("build-dependencies."))
            {
                // A `[dependencies.foo]` sub-table — `foo` is the dep name.
                Section::Deps(Some(name.trim().trim_matches('"').to_owned()))
            } else if is_deps_table(inner) {
                Section::Deps(None)
            } else {
                Section::Other
            };
            continue;
        }
        match &section {
            Section::Features => {
                if let Some((key, _)) = l.split_once('=') {
                    let key = key.trim().trim_matches('"');
                    if !key.is_empty() {
                        set.insert(key.to_owned());
                    }
                }
            }
            Section::Deps(subtable) => {
                let compact = l.replace(' ', "");
                if compact.contains("optional=true") {
                    if let Some(name) = subtable {
                        set.insert(name.clone());
                    } else if let Some((key, _)) = l.split_once('=') {
                        let key = key.trim().trim_matches('"');
                        if !key.is_empty() {
                            set.insert(key.to_owned());
                        }
                    }
                }
            }
            Section::Other => {}
        }
    }
    set
}

/// Emit the staticlib harness crate: a minimal `Cargo.toml` path-depending on the
/// target crate + `rust_runtime`, and `src/lib.rs` holding `govfuzz_run_one`.
fn emit_harness_crate(
    crate_dir: &Path,
    harness_rs: &str,
    target_crate: &str,
    target_manifest_dir: &Path,
    target_features: &[String],
) -> Result<(), String> {
    let src = crate_dir.join("src");
    std::fs::create_dir_all(&src).map_err(|e| format!("mkdir {}: {e}", src.display()))?;

    // `rust_runtime` lives in this workspace; resolve it by absolute path so the
    // generated crate (built standalone, outside the workspace) can find it.
    let rust_runtime_dir = locate_rust_runtime()
        .ok_or_else(|| "could not locate the rust_runtime crate for the harness dep".to_owned())?;

    // The harness depends on the target crate by path. The dependency KEY is the
    // crate's import name (what `harness_rs` writes, `data_url::…`), but cargo
    // resolves a path dependency by its real `[package] name`, which is often
    // hyphenated (`data-url`) and does NOT match the underscore key — a bare
    // `data_url = { path }` then fails with "no matching package named data_url".
    // Emit a `package = "<real name>"` RENAME whenever the package name differs
    // from the import key so cargo resolves the hyphenated package while the source
    // keeps importing it by the normalized name.
    //
    // A feature-gated target (`#[cfg(feature = "escape-html")]` on quick-xml's
    // `resolve_html5_entity`) is unreachable unless the harness dep ENABLES the
    // feature — otherwise the path resolves to nothing (E0425 false failed_build).
    // Append a `features = [...]` to the dep table for each discovered required,
    // declared feature.
    let mut props: Vec<String> = vec![format!("path = {target_manifest_dir:?}")];
    if let Some(pkg) = crate_package_name(target_manifest_dir) {
        if pkg != target_crate {
            props.push(format!("package = {pkg:?}"));
        }
    }
    if !target_features.is_empty() {
        let feats = target_features
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        props.push(format!("features = [{feats}]"));
    }
    let target_dep = format!("{target_crate} = {{ {} }}", props.join(", "));
    let cargo_toml = format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # GENERATED by govfuzz — staticlib harness crate.\n\
         # An explicit empty [workspace] makes this crate its own workspace root so\n\
         # cargo does NOT walk up and bind it to an ancestor [workspace] — the govfuzz\n\
         # worktree (where govfuzz_work/ lives) or the target crate's own Cargo\n\
         # workspace (rust-url, tokio, …) — which fails the build with \"current\n\
         # package believes it's in a workspace when it's not\".\n\
         [workspace]\n\
         \n\
         [package]\n\
         name = \"govfuzz_rust_harness\"\n\
         version = \"0.0.0\"\n\
         edition = \"2021\"\n\
         publish = false\n\
         \n\
         [lib]\n\
         crate-type = [\"staticlib\"]\n\
         path = \"src/lib.rs\"\n\
         \n\
         [dependencies]\n\
         {target_dep}\n\
         rust_runtime = {{ path = {runtime_path:?} }}\n\
         \n\
         # A release-ish profile keeps the staticlib small without -O3 inlining\n\
         # away the comparisons the cmplog/value-profile runtime needs to see.\n\
         [profile.dev]\n\
         opt-level = 1\n",
        target_dep = target_dep,
        runtime_path = rust_runtime_dir,
    );
    std::fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("write harness Cargo.toml: {e}"))?;
    std::fs::write(src.join("lib.rs"), harness_rs)
        .map_err(|e| format!("write harness lib.rs: {e}"))?;
    Ok(())
}

/// Locate the `rust_runtime` crate dir relative to the running `govfuzz` binary
/// or the source tree. Tries, in order: a `GOVFUZZ_RUST_RUNTIME_DIR` override,
/// the workspace path relative to the executable, and a few source-tree guesses.
fn locate_rust_runtime() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("GOVFUZZ_RUST_RUNTIME_DIR") {
        let p = PathBuf::from(dir);
        if p.join("Cargo.toml").is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("crates/rust_runtime");
                if cand.join("Cargo.toml").is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    // Relative to the source tree (CARGO_MANIFEST_DIR is crates/cli at build).
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .map(|root| root.join("crates/rust_runtime"));
    if let Some(p) = from_manifest {
        if p.join("Cargo.toml").is_file() {
            return Some(p);
        }
    }
    None
}

/// Find the first `libgovfuzz_rust_harness*.a` staticlib under
/// `<target_dir>/<host_triple>/debug/` (the layout cargo uses when built with an
/// explicit `--target`).
fn find_staticlib(target_dir: &Path, host_triple: &str) -> Option<PathBuf> {
    let debug = target_dir.join(host_triple).join("debug");
    let entries = std::fs::read_dir(&debug).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("a") {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("libgovfuzz_rust_harness") {
                    return Some(path);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_harness_crate_renames_a_hyphenated_target_package() {
        // A hyphenated package (`data-url`) must be depended on with a
        // `package = "data-url"` rename keyed by the `_`-import name the harness
        // source uses — a bare `data_url = { path }` fails "no matching package".
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("data-url");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(
            target.join("Cargo.toml"),
            "[package]\nname = \"data-url\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let harness = tmp.path().join("h");
        // rust_runtime must be locatable; skip cleanly if not (CI sandbox).
        if locate_rust_runtime().is_none() {
            eprintln!("skipping: rust_runtime crate not locatable");
            return;
        }
        emit_harness_crate(&harness, "fn _x() {}", "data_url", &target, &[]).unwrap();
        let cargo = std::fs::read_to_string(harness.join("Cargo.toml")).unwrap();
        assert!(
            cargo.contains("data_url = { path =") && cargo.contains("package = \"data-url\""),
            "expected a package-rename dep, got:\n{cargo}"
        );

        // An already-underscore package needs no rename (no `package =`).
        let plain = tmp.path().join("serde_json");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::write(
            plain.join("Cargo.toml"),
            "[package]\nname = \"serde_json\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let h2 = tmp.path().join("h2");
        emit_harness_crate(&h2, "fn _x() {}", "serde_json", &plain, &[]).unwrap();
        let cargo2 = std::fs::read_to_string(h2.join("Cargo.toml")).unwrap();
        assert!(
            cargo2.contains("serde_json = { path =") && !cargo2.contains("package ="),
            "no rename needed, got:\n{cargo2}"
        );

        // A feature-gated target enables the discovered feature in the dep table.
        let h3 = tmp.path().join("h3");
        emit_harness_crate(
            &h3,
            "fn _x() {}",
            "serde_json",
            &plain,
            &["escape-html".to_owned()],
        )
        .unwrap();
        let cargo3 = std::fs::read_to_string(h3.join("Cargo.toml")).unwrap();
        assert!(
            cargo3.contains("features = [\"escape-html\"]"),
            "expected the discovered feature enabled, got:\n{cargo3}"
        );
    }

    #[test]
    fn cfg_satisfying_features_extracts_required_features() {
        // Single gate (quick-xml resolve_html5_entity shape).
        assert_eq!(
            cfg_satisfying_features("feature = \"escape-html\""),
            Some(vec!["escape-html".to_owned()])
        );
        // `all(...)` unions feature conjuncts; a non-feature conjunct is ambient.
        assert_eq!(
            cfg_satisfying_features("all(feature = \"a\", unix, feature = \"b\")"),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        // `any(...)` takes the first feature alternative.
        assert_eq!(
            cfg_satisfying_features("any(feature = \"x\", test)"),
            Some(vec!["x".to_owned()])
        );
        // A pure non-feature gate yields nothing to enable.
        assert_eq!(cfg_satisfying_features("unix"), None);
        assert_eq!(cfg_satisfying_features("not(feature = \"std\")"), None);
    }

    #[test]
    fn resolve_target_features_enables_declared_and_skips_undeclared() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"quick-xml\"\nversion = \"0.1.0\"\n\
             [features]\nescape-html = []\ndefault = []\n",
        )
        .unwrap();
        let mut cand = mk_candidate(&tmp.path().join("src/lib.rs"), "resolve_html5_entity", 1);
        cand.foreign_guard = Some("feature = \"escape-html\"".to_owned());
        assert_eq!(
            resolve_target_features(&cand, tmp.path()).unwrap(),
            vec!["escape-html".to_owned()],
            "a declared feature is enabled"
        );

        // A feature the crate does not declare -> clean skip (Err), not a guaranteed
        // E0425 false failed_build.
        let mut undeclared = cand.clone();
        undeclared.foreign_guard = Some("feature = \"nonexistent\"".to_owned());
        let err = resolve_target_features(&undeclared, tmp.path()).unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
        assert!(err.contains("skipped"), "{err}");

        // No cfg / a non-feature cfg -> nothing to enable.
        let mut plain = cand.clone();
        plain.foreign_guard = None;
        assert!(resolve_target_features(&plain, tmp.path())
            .unwrap()
            .is_empty());
        plain.foreign_guard = Some("unix".to_owned());
        assert!(resolve_target_features(&plain, tmp.path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scratch_slice_parses_lifetimed_mut_slice() {
        // httparse's `Request::new(headers: &'h mut [Header<'b>])` — the explicit
        // reference lifetime `'h` and the element generic `<'b>` must both be tolerated.
        assert_eq!(
            scratch_slice("&'h mut [Header<'b>]"),
            Some(("Header".to_owned(), true, true))
        );
        // Plain `&mut [Header]` (no lifetimes) and shared `&[Header]`.
        assert_eq!(
            scratch_slice("&mut [Header]"),
            Some(("Header".to_owned(), true, false))
        );
        assert_eq!(
            scratch_slice("&'a [Cell]"),
            Some(("Cell".to_owned(), false, false))
        );
        // A byte slice is NOT a scratch slice (it has its own decoder); neither is a
        // non-slice ref or a `mut`-prefixed type name that isn't the `mut` keyword.
        assert_eq!(scratch_slice("&'b [u8]"), None);
        assert_eq!(scratch_slice("&mut Bytes"), None);
        assert_eq!(scratch_slice("&[mutex]"), None);
    }

    #[test]
    fn module_path_for_lib_root_is_empty() {
        let root = Path::new("/c");
        assert!(module_path(root, Path::new("/c/src/lib.rs")).is_empty());
        assert!(module_path(root, Path::new("/c/src/main.rs")).is_empty());
    }

    #[test]
    fn module_path_for_file_module() {
        let root = Path::new("/c");
        assert_eq!(
            module_path(root, Path::new("/c/src/parser.rs")),
            vec!["parser"]
        );
        assert_eq!(
            module_path(root, Path::new("/c/src/a/b.rs")),
            vec!["a", "b"]
        );
        assert_eq!(module_path(root, Path::new("/c/src/a/mod.rs")), vec!["a"]);
    }

    #[test]
    fn parse_impl_header_inherent_and_trait() {
        assert_eq!(parse_impl_header("impl Url {"), Some("Url".to_owned()));
        assert_eq!(
            parse_impl_header("impl<'a> Parser<'a> {"),
            Some("Parser".to_owned())
        );
        assert_eq!(
            parse_impl_header("impl Display for Url {"),
            Some("Url".to_owned())
        );
        assert_eq!(parse_impl_header("implements()"), None);
        assert_eq!(parse_impl_header("fn impl_helper() {"), None);
    }

    #[test]
    fn enclosing_impl_type_finds_method_owner() {
        let src = "pub struct Url;\n\
                   impl Url {\n\
                   pub fn parse(s: &str) -> Url { Url }\n\
                   }\n\
                   pub fn free_fn(d: &[u8]) {}\n";
        // `parse` is on line 3 -> inside `impl Url`.
        assert_eq!(enclosing_impl_type(src, 3), Some("Url".to_owned()));
        // `free_fn` is on line 5 -> not in any impl.
        assert_eq!(enclosing_impl_type(src, 5), None);
    }

    #[test]
    fn enclosing_impl_type_handles_multiline_and_where_headers() {
        // The opening brace on its OWN line (with a where-clause / generics) — the
        // dominant real form (rust-url, tokio, serde). Must still find the type.
        let brace_own_line = "pub struct Foo;\nimpl Foo\n{\n    pub fn bar(&self) {}\n}\n";
        assert_eq!(
            enclosing_impl_type(brace_own_line, 4),
            Some("Foo".to_owned())
        );

        let where_clause = "impl<'a> Parser<'a>\nwhere\n    'a: 'static,\n{\n    pub fn feed(&mut self, d: &[u8]) {}\n}\n";
        assert_eq!(
            enclosing_impl_type(where_clause, 5),
            Some("Parser".to_owned())
        );

        // A free fn after the impl block closes is not inside it.
        let after = "impl Foo\n{\n    fn m(&self) {}\n}\npub fn free() {}\n";
        assert_eq!(enclosing_impl_type(after, 5), None);

        // serde_json shape: an impl with `b'{'` / `b'}'` byte-char literals (which
        // a NAIVE brace counter mis-counts), then a free fn after it. The free fn
        // must NOT be attributed to the impl (its call path is the free function,
        // not `Type::fn`).
        let with_char_braces = "impl StreamDeserializer {\n    fn scan(&self, c: u8) {\n        match c { b'{' => {}, b'}' => {}, _ => {} }\n    }\n}\npub fn from_slice<T>() -> T { todo!() }\n";
        assert_eq!(enclosing_impl_type(with_char_braces, 6), None);
    }

    #[test]
    fn mask_rust_literals_blanks_braces_in_literals_and_comments() {
        // Braces inside char/string/comment must be blanked so they don't count.
        let m = mask_rust_literals("fn f() { let c = b'{'; let s = \"}}}\"; /* { */ }");
        assert_eq!(m.matches('{').count(), 1, "only the real block brace: {m}");
        assert_eq!(m.matches('}').count(), 1, "only the real block brace: {m}");
        // A lifetime is NOT a char literal and is left intact.
        let life = mask_rust_literals("impl<'a> Foo<'a> { fn g(&'a self) {} }");
        assert!(life.contains("'a"), "lifetime preserved: {life}");
        // Raw-string body is blanked.
        let raw = mask_rust_literals("let x = r#\"a{b}c\"#; { }");
        assert_eq!(
            raw.matches('{').count(),
            1,
            "raw-string braces blanked: {raw}"
        );
    }

    #[test]
    fn deserialize_bound_monomorphizes_to_crate_value() {
        // serde format crates' `from_str::<T> where T: Deserialize` -> the crate's
        // own `Value` (the idiomatic dynamic deserialize target).
        let root = "pub use crate::value::Value;\n";
        assert_eq!(
            deserialize_value_target("serde::de::Deserialize<'a>", "serde_json", root),
            Some(vec!["serde_json".to_owned(), "Value".to_owned()])
        );
        assert_eq!(
            deserialize_value_target("DeserializeOwned", "toml", "pub enum Value {}\n"),
            Some(vec!["toml".to_owned(), "Value".to_owned()])
        );
        // No Deserialize bound, or no `Value` in the crate -> None.
        assert_eq!(
            deserialize_value_target("Clone", "x", "pub use crate::Value;"),
            None
        );
        assert_eq!(
            deserialize_value_target("Deserialize", "x", "// no Value here"),
            None
        );
    }

    #[test]
    fn type_default_available_requires_contiguous_derive() {
        // A Default-deriving DIFFERENT struct above must NOT make `Parser` look
        // Default-able (else `Parser::default()` -> E0599).
        let src = "#[derive(Debug, Default)]\n\
                   pub struct Config;\n\
                   \n\
                   pub struct Parser { inner: u8 }\n\
                   impl Parser { pub fn feed(&self, d: &[u8]) {} }\n";
        assert!(!type_default_available(src, "Parser"));
        assert!(type_default_available(src, "Config"));
        // Contiguous derive (with a doc comment between) still counts.
        let direct = "#[derive(Default)]\n/// doc\npub struct Thing { x: u8 }\n";
        assert!(type_default_available(direct, "Thing"));
        // Explicit impl Default for Thing.
        let explicit = "pub struct T2;\nimpl Default for T2 { fn default() -> Self { T2 } }\n";
        assert!(type_default_available(explicit, "T2"));
    }

    #[test]
    fn private_new_is_not_a_usable_receiver_ctor() {
        // A private `new()` is unreachable from the harness crate -> no ctor.
        let src = "pub struct Lexer { p: usize }\n\
                   impl Lexer { fn new() -> Self { Lexer { p: 0 } } pub fn step(&self) {} }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        assert!(find_receiver_ctor(src, &fns, "Lexer", &|_| false).is_none());
    }

    #[test]
    fn unsafe_ctor_is_not_a_usable_receiver() {
        // An `unsafe fn` ctor (json-rust's `Short::from_slice`) cannot back a
        // receiver: the generated `let recv = Short::from_slice(..)` is not in an
        // `unsafe {}` block, so the harness fails to BUILD (E0133). It must be
        // rejected so the instance method is a clean skip, not a failed build.
        let src = "pub struct Short { p: usize }\n\
                   impl Short {\n\
                   pub unsafe fn from_slice(s: &str) -> Short { Short { p: 0 } }\n\
                   pub fn eq(&self, other: &str) -> bool { false }\n\
                   }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        assert!(
            find_receiver_ctor(src, &fns, "Short", &|_| false).is_none(),
            "an unsafe ctor must not be selected as a receiver"
        );
    }

    #[test]
    fn std_trait_path_maps_common_traits_and_disambiguates_write() {
        let p = |t: &str, m: &str| std_trait_path(t, m).map(|v| v.join("::"));
        assert_eq!(p("Deref", "deref").as_deref(), Some("core::ops::Deref"));
        assert_eq!(
            p("ops::Deref", "deref").as_deref(),
            Some("core::ops::Deref")
        );
        assert_eq!(
            p("Borrow", "borrow").as_deref(),
            Some("core::borrow::Borrow")
        );
        assert_eq!(
            p("AsRef", "as_ref").as_deref(),
            Some("core::convert::AsRef")
        );
        // `Write` disambiguates by method: fmt vs io.
        assert_eq!(p("Write", "write_str").as_deref(), Some("core::fmt::Write"));
        assert_eq!(p("Write", "write").as_deref(), Some("std::io::Write"));
        assert_eq!(p("Write", "flush").as_deref(), Some("std::io::Write"));
        // A trait not in the map (a prelude or unknown trait) -> no import.
        assert_eq!(p("Clone", "clone"), None);
        assert_eq!(p("MyTrait", "foo"), None);
    }

    #[test]
    fn drop_destructor_is_rejected_but_inherent_drop_is_kept() {
        // `impl Drop for SmallVec { fn drop(&mut self) }` — uncallable (E0040).
        let src = "pub struct S;\nimpl Drop for S { fn drop(&mut self) {} }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        let drop_fn = fns.iter().find(|f| f.name == "drop").unwrap();
        assert!(is_drop_destructor(drop_fn), "Drop::drop must be rejected");

        // A library's OWN inherent `drop(&mut self, n: usize)` (args, no Drop
        // impl) is a real method and must NOT be rejected.
        let src2 = "pub struct Pool;\nimpl Pool { pub fn drop(&mut self, n: usize) {} }\n";
        let fns2 = rust_parser::parse_rust_functions(src2).unwrap();
        let inherent = fns2.iter().find(|f| f.name == "drop").unwrap();
        assert!(
            !is_drop_destructor(inherent),
            "an inherent drop(args) is not the destructor"
        );
    }

    #[test]
    fn generic_receiver_type_yields_a_concrete_turbofish() {
        // smallvec shape: `SmallVec<T, const N: usize>`. A no-arg `new()` can't
        // infer the generics (E0284 `SmallVec<_, _>`), so the receiver type must
        // be monomorphized to a concrete turbofish: type param -> u8, const -> 4.
        let src = "pub struct SmallVec<T, const N: usize> { x: [T; N] }\n";
        assert_eq!(
            receiver_generic_turbofish(src, "SmallVec").as_deref(),
            Some("::<u8, 4>")
        );
        // Lifetime + bounded type param + bool const, in order.
        let src2 = "pub struct Grid<'a, T: Clone, const FLAG: bool> { p: &'a T }\n";
        assert_eq!(
            receiver_generic_turbofish(src2, "Grid").as_deref(),
            Some("::<'_, u8, false>")
        );
        // A non-generic type gets no turbofish, and a longer-named neighbour
        // (`SmallVecData`) must not be mistaken for `SmallVec`.
        let src3 = "pub struct SmallVecData { x: usize }\npub struct Url { u: usize }\n";
        assert_eq!(receiver_generic_turbofish(src3, "Url"), None);
        // An unknown type (no declaration) yields None — no turbofish emitted.
        assert_eq!(receiver_generic_turbofish(src, "Nope"), None);

        // tinyvec idiom: `struct ArrayVec<A>` whose `A` is bound `Array` only in
        // the impl. `A` is a backing store -> `[u8; 4]`, never `u8` (which doesn't
        // implement the Array trait). A sibling SliceVec<'s, T: Default> keeps `u8`.
        let tv = "pub struct ArrayVec<A> { x: A }\n\
                  impl<A: Array> ArrayVec<A> { pub fn new() -> Self { todo!() } }\n\
                  pub struct SliceVec<'s, T> { d: &'s mut [T] }\n\
                  impl<'s, T: Default> SliceVec<'s, T> { pub fn len(&self) -> usize { 0 } }\n";
        assert_eq!(
            receiver_generic_turbofish(tv, "ArrayVec").as_deref(),
            Some("::<[u8; 4]>")
        );
        assert_eq!(
            receiver_generic_turbofish(tv, "SliceVec").as_deref(),
            Some("::<'_, u8>")
        );
    }

    #[test]
    fn arg_taking_fallible_ctor_is_resolved_as_receiver() {
        use harness_gen::rust_generate::ReceiverUnwrap;
        // roxmltree shape: a fallible string ctor builds the receiver for a method.
        let src = "pub struct Document { x: usize }\n\
                   impl Document {\n\
                   pub fn parse(text: &str) -> Result<Document, ()> { Ok(Document { x: 0 }) }\n\
                   pub fn lookup_prefix(&self, uri: &str) {}\n\
                   }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        let ctor =
            find_receiver_ctor(src, &fns, "Document", &|_| false).expect("fallible ctor resolved");
        assert_eq!(ctor.name, "parse");
        assert_eq!(ctor.params.len(), 1);
        assert_eq!(ctor.params[0].ty, "&str");
        assert_eq!(ctor.unwrap, ReceiverUnwrap::Result);
    }

    #[test]
    fn ctor_returns_self_recognizes_wrapped_and_paths() {
        assert!(ctor_returns_self(&Some("Self".to_owned()), "Document"));
        assert!(ctor_returns_self(&Some("Document".to_owned()), "Document"));
        assert!(ctor_returns_self(
            &Some("Result<Document, Error>".to_owned()),
            "Document"
        ));
        assert!(ctor_returns_self(
            &Some("Option<crate::Document>".to_owned()),
            "Document"
        ));
        // Smart-pointer-wrapped constructors (#452).
        assert!(ctor_returns_self(&Some("Box<Self>".to_owned()), "Document"));
        assert!(ctor_returns_self(
            &Some("Arc<Document>".to_owned()),
            "Document"
        ));
        assert!(ctor_returns_self(
            &Some("std::rc::Rc<Self>".to_owned()),
            "Document"
        ));
        // A ctor returning something else is not a receiver builder.
        assert!(!ctor_returns_self(
            &Some("Result<Node, Error>".to_owned()),
            "Document"
        ));
        assert!(!ctor_returns_self(
            &Some("Arc<Node>".to_owned()),
            "Document"
        ));
        assert!(!ctor_returns_self(&None, "Document"));
    }

    #[test]
    fn ctor_unwrap_classifies_smart_pointer_returns() {
        use harness_gen::rust_generate::ReceiverUnwrap;
        assert_eq!(
            ctor_unwrap(&Some("Self".to_owned())),
            ReceiverUnwrap::Direct
        );
        assert_eq!(
            ctor_unwrap(&Some("Result<Self, E>".to_owned())),
            ReceiverUnwrap::Result
        );
        assert_eq!(
            ctor_unwrap(&Some("Box<Self>".to_owned())),
            ReceiverUnwrap::Boxed
        );
        assert_eq!(
            ctor_unwrap(&Some("std::sync::Arc<Self>".to_owned())),
            ReceiverUnwrap::Arc
        );
        assert_eq!(
            ctor_unwrap(&Some("Rc<Self>".to_owned())),
            ReceiverUnwrap::Rc
        );
    }

    #[test]
    fn arc_returning_ctor_is_resolved_as_receiver() {
        use harness_gen::rust_generate::ReceiverUnwrap;
        // A ctor returning `Arc<Self>` is now a usable receiver (Arc::try_unwrap).
        let src = "pub struct Conn { fd: i32 }\n\
                   impl Conn {\n\
                   pub fn open(addr: &str) -> std::sync::Arc<Self> { unimplemented!() }\n\
                   pub fn poll(&mut self, n: u32) {}\n\
                   }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        let ctor = find_receiver_ctor(src, &fns, "Conn", &|_| false).expect("Arc ctor resolved");
        assert_eq!(ctor.name, "open");
        assert_eq!(ctor.unwrap, ReceiverUnwrap::Arc);
    }

    #[test]
    fn enum_arg_ctor_usable_only_with_override() {
        // `Parser::new(mode: Mode) -> Result<Self>` where Mode isn't a
        // standard-decodable type: usable only when the override resolver
        // recognises Mode (a unit enum -> fuzz-byte variant pick), the same path
        // the target params use.
        let src = "pub struct Parser { m: u8 }\n\
                   impl Parser {\n\
                   pub fn new(mode: Mode) -> Result<Self, ()> { Ok(Parser { m: 0 }) }\n\
                   pub fn run(&mut self, data: &[u8]) {}\n\
                   }\n";
        let fns = rust_parser::parse_rust_functions(src).unwrap();
        // Without the override the enum arg is undecodable -> no ctor.
        assert!(find_receiver_ctor(src, &fns, "Parser", &|_| false).is_none());
        // With the override (Mode recognised) the ctor resolves, Result-unwrapped.
        let ctor = find_receiver_ctor(src, &fns, "Parser", &|ty| ty == "Mode")
            .expect("enum-arg ctor resolved via override");
        assert_eq!(ctor.name, "new");
        assert_eq!(
            ctor.unwrap,
            harness_gen::rust_generate::ReceiverUnwrap::Result
        );
    }

    #[test]
    fn section_value_reads_lib_and_package_name() {
        let toml =
            "[package]\nname = \"my-crate\"\n\n[lib]\nname = \"mylib\"\npath = \"src/lib.rs\"\n";
        assert_eq!(
            section_value(toml, "package", "name"),
            Some("my-crate".to_owned())
        );
        assert_eq!(section_value(toml, "lib", "name"), Some("mylib".to_owned()));
    }

    #[test]
    fn reexported_idents_handles_plain_group_and_alias() {
        assert_eq!(reexported_idents("crate::host::Host"), vec!["Host"]);
        assert_eq!(
            reexported_idents("crate::origin::{OpaqueOrigin, Origin}"),
            vec!["OpaqueOrigin", "Origin"]
        );
        assert_eq!(
            reexported_idents("crate::host::Host as UrlHost"),
            vec!["UrlHost"]
        );
        assert_eq!(
            reexported_idents("form_urlencoded"),
            vec!["form_urlencoded"]
        );
        // Globs and self bind no specific name.
        assert!(reexported_idents("crate::host::*").is_empty());
    }

    #[test]
    fn crate_root_reexports_matches_facade_and_ignores_pub_crate() {
        // The real url lib.rs facade pattern: private `mod host;` + a root re-export.
        let src = "mod host;\n\
                   pub use crate::host::Host;\n\
                   pub use crate::origin::{OpaqueOrigin, Origin};\n\
                   pub(crate) use crate::internal::Secret;\n";
        assert!(crate_root_reexports(src, "Host"));
        assert!(crate_root_reexports(src, "Origin"));
        assert!(crate_root_reexports(src, "OpaqueOrigin"));
        // `pub(crate) use` is NOT a public re-export.
        assert!(!crate_root_reexports(src, "Secret"));
        // A type only reachable via its (private) module is not a root re-export.
        assert!(!crate_root_reexports(src, "HostInternal"));
    }

    #[test]
    fn pub_use_trees_joins_multiline_groups() {
        let src = "pub use crate::a::A;\n\
                   pub use crate::b::{\n\
                       B,\n\
                       C as D,\n\
                   };\n";
        let trees = pub_use_trees(src);
        assert_eq!(trees.len(), 2);
        // The multi-line group is joined into one tree before brace parsing.
        let idents: Vec<String> = trees.iter().flat_map(|t| reexported_idents(t)).collect();
        assert_eq!(idents, vec!["A", "B", "D"]);
    }

    #[test]
    fn parse_host_triple_reads_the_host_line() {
        let vv = "cargo 1.98.0-nightly (abc 2026-06-10)\n\
                  release: 1.98.0-nightly\n\
                  commit-hash: deadbeef\n\
                  host: x86_64-unknown-linux-gnu\n";
        assert_eq!(
            parse_host_triple(vv).as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(parse_host_triple("no host line at all\n"), None);
    }

    #[test]
    fn find_staticlib_looks_under_target_triple_debug() {
        // With an explicit --target, cargo writes artifacts to
        // target/<triple>/debug/, not target/debug/. The locator must follow.
        let tmp = tempfile::tempdir().unwrap();
        let triple = "x86_64-unknown-linux-gnu";
        let debug = tmp.path().join(triple).join("debug");
        std::fs::create_dir_all(&debug).unwrap();
        // A decoy .a that isn't ours must be ignored.
        std::fs::write(debug.join("libsomethingelse.a"), b"").unwrap();
        let ours = debug.join("libgovfuzz_rust_harness.a");
        std::fs::write(&ours, b"").unwrap();
        assert_eq!(find_staticlib(tmp.path(), triple), Some(ours));
        // Nothing under the plain target/debug/ (old layout) must NOT match.
        assert!(find_staticlib(tmp.path(), "aarch64-unknown-linux-gnu").is_none());
    }

    #[test]
    fn emitted_cargo_toml_detaches_from_ancestor_workspace() {
        // The harness crate is written under directories that frequently have an
        // ancestor `[workspace]` — the govfuzz worktree root (where `govfuzz_work/`
        // lives), or the target crate's own Cargo workspace (rust-url, tokio, …).
        // Without an explicit empty `[workspace]` table cargo walks up, finds that
        // ancestor workspace, sees the harness isn't listed as a member, and fails:
        // "current package believes it's in a workspace when it's not". The emitted
        // manifest must declare its own `[workspace]` so it is its own root.
        let tmp = tempfile::tempdir().unwrap();
        let crate_dir = tmp.path().join("rust_harness");
        emit_harness_crate(
            &crate_dir,
            "// harness\n",
            "url",
            Path::new("/tmp/some/url"),
            &[],
        )
        .expect("emit harness crate");
        let toml = std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap();
        assert!(
            toml.contains("\n[workspace]\n") || toml.starts_with("[workspace]\n"),
            "harness Cargo.toml must declare an empty [workspace] table to detach \
             from any ancestor workspace, got:\n{toml}"
        );
    }

    #[test]
    fn enum_param_type_accepts_pascal_paths_and_options_rejects_primitives_and_compounds() {
        assert_eq!(
            enum_param_type("AdaStandard"),
            Some(("AdaStandard", EnumWrap::Bare))
        );
        // A qualified path keeps only the last segment (the type name to search).
        assert_eq!(
            enum_param_type("ast::Classification"),
            Some(("Classification", EnumWrap::Bare))
        );
        // A single Option<...> wrapper is peeled and flagged.
        assert_eq!(
            enum_param_type("Option<AdaStandard>"),
            Some(("AdaStandard", EnumWrap::Option))
        );
        assert_eq!(
            enum_param_type("Option<ast::AdaStandard>"),
            Some(("AdaStandard", EnumWrap::Option))
        );
        // Primitives are lowercase-leading — never unit enums.
        assert_eq!(enum_param_type("u8"), None);
        assert_eq!(enum_param_type("bool"), None);
        assert_eq!(enum_param_type("usize"), None);
        // Compound / reference / generic types are rejected (no tree scan).
        assert_eq!(enum_param_type("&str"), None);
        assert_eq!(enum_param_type("&[u8]"), None);
        assert_eq!(enum_param_type("Vec<u8>"), None);
        assert_eq!(enum_param_type("&AdaStandard"), None);
        assert_eq!(enum_param_type("(u8, u8)"), None);
        // Nested generics inside Option are not a plain enum.
        assert_eq!(enum_param_type("Option<Vec<u8>>"), None);
    }

    #[test]
    fn build_enum_decoder_expr_indexes_variants_by_a_fuzz_byte() {
        let path = [
            "ada_parser".to_owned(),
            "ast".to_owned(),
            "AdaStandard".to_owned(),
        ];
        let variants = [
            "Ada95".to_owned(),
            "Ada2005".to_owned(),
            "Ada2012".to_owned(),
            "Ada2022".to_owned(),
        ];
        assert_eq!(
            build_enum_decoder_expr(&path, &variants, EnumWrap::Bare),
            "[ada_parser::ast::AdaStandard::Ada95, ada_parser::ast::AdaStandard::Ada2005, \
             ada_parser::ast::AdaStandard::Ada2012, ada_parser::ast::AdaStandard::Ada2022]\
             [(c.u8() as usize) % 4]"
        );
        // The Option form wraps the pick so both None and Some(variant) are reached.
        let opt = build_enum_decoder_expr(&path, &variants, EnumWrap::Option);
        assert!(
            opt.starts_with("if c.u8() & 1 == 0 { None } else { Some(["),
            "{opt}"
        );
        assert!(opt.ends_with("[(c.u8() as usize) % 4]) }"), "{opt}");
    }

    #[test]
    fn resolve_enum_decoders_finds_unit_enum_in_a_pub_module() {
        // Mirror ada_parser's layout: `pub mod ast;` in lib.rs, the unit enum in
        // src/ast.rs. The param `AdaStandard` must resolve to the byte-indexed pick;
        // the `&str` param (no decoder override) stays `None`.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"ada_parser\"\n",
        )
        .unwrap();
        std::fs::write(src.join("lib.rs"), "pub mod ast;\npub fn lex() {}\n").unwrap();
        std::fs::write(
            src.join("ast.rs"),
            "#[derive(Debug)]\npub enum AdaStandard { Ada95, Ada2005, Ada2012, Ada2022 }\n",
        )
        .unwrap();

        let crate_root_src = read_crate_root_src(tmp.path());
        let params = vec![
            rust_parser::RustParam {
                name: "src".to_owned(),
                ty: "&str".to_owned(),
            },
            rust_parser::RustParam {
                name: "std".to_owned(),
                ty: "AdaStandard".to_owned(),
            },
            rust_parser::RustParam {
                name: "hint".to_owned(),
                ty: "Option<AdaStandard>".to_owned(),
            },
        ];
        let decoders = resolve_param_overrides(tmp.path(), "ada_parser", &crate_root_src, &params);
        assert_eq!(decoders.len(), 3);
        assert_eq!(decoders[0], None, "&str param has no enum override");
        let (expr, _) = decoders[1].as_ref().expect("bare enum param resolved");
        assert!(
            expr.starts_with("[ada_parser::ast::AdaStandard::Ada95,"),
            "{expr}"
        );
        assert!(expr.ends_with("[(c.u8() as usize) % 4]"), "{expr}");
        let (opt, _) = decoders[2].as_ref().expect("Option<enum> param resolved");
        assert!(
            opt.starts_with("if c.u8() & 1 == 0 { None } else { Some("),
            "{opt}"
        );
        assert!(opt.contains("ada_parser::ast::AdaStandard::Ada95"), "{opt}");
    }

    #[test]
    fn parse_trait_impl_matches_concrete_marker_impls() {
        assert_eq!(
            parse_trait_impl("impl ByteOrder for BigEndian {", "ByteOrder"),
            Some("BigEndian")
        );
        assert_eq!(
            parse_trait_impl("impl byteorder::ByteOrder for LittleEndian {", "ByteOrder"),
            Some("LittleEndian")
        );
        // Wrong trait / blanket / inherent impls don't match.
        assert_eq!(
            parse_trait_impl("impl Display for BigEndian {", "ByteOrder"),
            None
        );
        assert_eq!(
            parse_trait_impl("impl<T> Other for Wrap<T> {", "ByteOrder"),
            None
        );
        assert_eq!(parse_trait_impl("impl BigEndian {", "ByteOrder"), None);
    }

    #[test]
    fn bound_trait_leaf_distinguishes_markers_from_byte_bounds() {
        assert_eq!(bound_trait_leaf("ByteOrder"), Some("ByteOrder"));
        assert_eq!(bound_trait_leaf("byteorder::ByteOrder"), Some("ByteOrder"));
        assert_eq!(bound_trait_leaf("Endian + Copy"), Some("Endian"));
        // Byte/str-conversion bounds are value-substituted, not turbofished.
        assert_eq!(bound_trait_leaf("AsRef<[u8]>"), None);
        assert_eq!(bound_trait_leaf("AsRef<str>"), None);
        assert_eq!(bound_trait_leaf(""), None);
    }

    #[test]
    fn ty_mentions_ident_is_whole_identifier() {
        assert!(ty_mentions_ident("Vec<B>", "B"));
        assert!(ty_mentions_ident("&mut B", "B"));
        assert!(ty_mentions_ident("B", "B"));
        assert!(!ty_mentions_ident("Threshold", "B"));
        assert!(!ty_mentions_ident("&[u8]", "B"));
    }

    fn parse_fn(src: &str, name: &str) -> rust_parser::RustFn {
        rust_parser::parse_rust_functions(src)
            .unwrap()
            .into_iter()
            .find(|f| f.name == name)
            .unwrap()
    }

    #[test]
    fn turbofish_resolves_marker_and_strips_type_param() {
        // A free fn `parse<E: Endian>(data: &[u8])` with a concrete `impl Endian for
        // Big` resolves E -> Big, bakes `::<bo::Big>` onto the call, and strips E so
        // monomorphization succeeds (#458).
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"bo\"\n").unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "pub struct Big;\npub trait Endian {}\nimpl Endian for Big {}\n\
             pub fn parse<E: Endian>(data: &[u8]) -> u32 { 0 }\n",
        )
        .unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        let mut target = parse_fn("pub fn parse<E: Endian>(data: &[u8]) -> u32 { 0 }", "parse");
        let mut call_path = vec!["bo".to_owned(), "parse".to_owned()];
        apply_marker_turbofish(
            &mut call_path,
            &mut target,
            tmp.path(),
            "bo",
            &crate_root_src,
        );
        assert_eq!(
            call_path,
            vec!["bo".to_owned(), "parse::<bo::Big>".to_owned()]
        );
        assert!(
            target.type_params.is_empty(),
            "resolved marker param stripped"
        );
    }

    #[test]
    fn turbofish_noop_when_marker_impl_absent() {
        // No `impl Endian for ...` in the crate -> no turbofish, type param kept (the
        // candidate then takes the monomorphize-or-skip path).
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"bo\"\n").unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "pub fn parse<E: Endian>(data: &[u8]) -> u32 { 0 }\n",
        )
        .unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        let mut target = parse_fn("pub fn parse<E: Endian>(data: &[u8]) -> u32 { 0 }", "parse");
        let mut call_path = vec!["bo".to_owned(), "parse".to_owned()];
        apply_marker_turbofish(
            &mut call_path,
            &mut target,
            tmp.path(),
            "bo",
            &crate_root_src,
        );
        assert_eq!(
            call_path,
            vec!["bo".to_owned(), "parse".to_owned()],
            "unchanged"
        );
        assert_eq!(target.type_params.len(), 1, "type param retained");
    }

    #[test]
    fn resolve_enum_decoders_skips_data_carrying_and_private_module_enums() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"k\"\n").unwrap();
        // `inner` is a PRIVATE module (no `pub`) and not re-exported -> unreachable.
        std::fs::write(src.join("lib.rs"), "mod inner;\n").unwrap();
        std::fs::write(
            src.join("inner.rs"),
            // `Mixed` has a data variant (not all-unit); `Hidden` is in a private mod.
            "pub enum Mixed { A, B(u8) }\npub enum Hidden { X, Y }\n",
        )
        .unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        let params = vec![
            rust_parser::RustParam {
                name: "m".to_owned(),
                ty: "Mixed".to_owned(),
            },
            rust_parser::RustParam {
                name: "h".to_owned(),
                ty: "Hidden".to_owned(),
            },
        ];
        let decoders = resolve_param_overrides(tmp.path(), "k", &crate_root_src, &params);
        assert_eq!(decoders[0], None, "data-carrying enum is not resolved");
        assert_eq!(
            decoders[1], None,
            "unit enum in a private, non-re-exported module is unreachable"
        );
    }

    #[test]
    fn crate_import_name_prefers_lib_then_normalizes_package() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"my-crate\"\n",
        )
        .unwrap();
        assert_eq!(
            crate_import_name(dir.path()).as_deref(),
            Some("my_crate"),
            "package name dashes normalize to underscores"
        );
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"my-crate\"\n[lib]\nname = \"explicit_lib\"\n",
        )
        .unwrap();
        assert_eq!(
            crate_import_name(dir.path()).as_deref(),
            Some("explicit_lib")
        );
    }

    // --- reachability helpers (E0603 false-negative fix) ---

    #[test]
    fn crate_root_defines_pub_finds_items_at_root() {
        // A struct with lifetime generics (the roxmltree `Document<'input>` pattern).
        let src = "// SPDX-License-Identifier: Apache-2.0\n\
                   mod parse;\n\
                   pub struct Document<'input> { data: &'input str }\n\
                   pub enum Color { Red, Green }\n\
                   pub trait Visitor {}\n\
                   pub type Alias = u32;\n\
                   pub fn helper() {}\n";
        assert!(crate_root_defines_pub(src, "Document"));
        assert!(crate_root_defines_pub(src, "Color"));
        assert!(crate_root_defines_pub(src, "Visitor"));
        assert!(crate_root_defines_pub(src, "Alias"));
        assert!(crate_root_defines_pub(src, "helper"));
        // An item NOT declared at root.
        assert!(!crate_root_defines_pub(src, "ParseError"));
        // `pub(crate)` / `pub(super)` are NOT externally public.
        let src2 = "pub(crate) struct Secret;\npub(super) enum Inner {}\n";
        assert!(!crate_root_defines_pub(src2, "Secret"));
        assert!(!crate_root_defines_pub(src2, "Inner"));
    }

    #[test]
    fn crate_root_defines_pub_ignores_assoc_items_inside_impl_blocks() {
        // data-url shape: the crate root has an inherent `impl` whose method is named
        // `decode_to_vec`, while the real free fn `decode_to_vec` lives in a submodule
        // (`forgiving_base64`). Matching the inherent method made the free-fn target
        // emit the bare crate-root path `data_url::decode_to_vec` -> E0425. A `pub fn`/
        // `pub type`/`pub const` INSIDE an impl/trait body is an associated item, not a
        // crate-root item, and must not satisfy `crate_root_defines_pub`.
        let src = "// SPDX-License-Identifier: Apache-2.0\n\
                   mod forgiving_base64;\n\
                   pub struct DataUrl {}\n\
                   impl DataUrl {\n\
                       pub fn decode_to_vec(&self) -> Vec<u8> { Vec::new() }\n\
                       pub type Assoc = u32;\n\
                       pub const K: u32 = 1;\n\
                   }\n\
                   pub fn top_level_helper() {}\n";
        assert!(
            !crate_root_defines_pub(src, "decode_to_vec"),
            "an inherent impl method must NOT count as a crate-root definition"
        );
        assert!(!crate_root_defines_pub(src, "Assoc"));
        assert!(!crate_root_defines_pub(src, "K"));
        // The enclosing type and a genuine top-level free fn ARE crate-root items.
        assert!(crate_root_defines_pub(src, "DataUrl"));
        assert!(crate_root_defines_pub(src, "top_level_helper"));

        // Brace-on-next-line impl form is handled too.
        let src2 = "pub struct Foo {}\n\
                    impl Foo\n\
                    {\n\
                        pub fn bar(&self) {}\n\
                    }\n\
                    pub fn bar() {}\n";
        // `bar` IS defined at root (the free fn), even though an impl method shares the
        // name — the free-fn definition must still be found.
        assert!(crate_root_defines_pub(src2, "bar"));
        // A trait DECL body's associated items are also ignored.
        let src3 = "pub trait Tr {\n    pub fn assoc_in_trait();\n}\npub fn real() {}\n";
        assert!(!crate_root_defines_pub(src3, "assoc_in_trait"));
        assert!(crate_root_defines_pub(src3, "Tr"));
        assert!(crate_root_defines_pub(src3, "real"));
    }

    #[test]
    fn glob_reexported_modules_extracts_module_names() {
        let src = "mod parse;\n\
                   mod other;\n\
                   pub use crate::parse::*;\n\
                   pub use crate::other::Named;\n\
                   pub(crate) use crate::hidden::*;\n";
        let globs = glob_reexported_modules(src);
        // Only the plain-pub glob `crate::parse::*` is a public glob re-export.
        assert!(
            globs.contains(&"parse".to_owned()),
            "parse should be in globs: {globs:?}"
        );
        // A named re-export does NOT appear in the glob list.
        assert!(
            !globs.contains(&"other".to_owned()),
            "other is a named re-export, not glob"
        );
        // `pub(crate) use …::*` is NOT a public glob re-export.
        assert!(
            !globs.contains(&"hidden".to_owned()),
            "pub(crate) glob must be excluded"
        );
    }

    #[test]
    fn type_reachable_at_crate_root_covers_all_three_cases_and_guards_genuine_private() {
        // Case (a): type defined DIRECTLY at the crate root — inherent methods are
        // reachable as `crate::Document::method` without any `pub use`.
        let lib_a = "mod parse;\n\
                     pub struct Document<'i> {}\n\
                     pub use crate::parse::*;\n"; // glob present but irrelevant here
        assert!(
            type_reachable_at_crate_root(lib_a, "Document", "parse"),
            "struct defined at root must be reachable"
        );

        // Case (b): glob `pub use crate::inner::*;` makes types defined in `inner`
        // reachable at the crate root even with no named re-export.
        let lib_b = "mod inner;\npub use crate::inner::*;\n";
        assert!(
            type_reachable_at_crate_root(lib_b, "Bar", "inner"),
            "glob-re-exported module's types must be reachable"
        );

        // Case (c): type ONLY in a private module — no root definition, no named
        // re-export, no glob — must NOT be reachable (genuine E0603).
        let lib_c = "mod secret;\n"; // nothing public
        assert!(
            !type_reachable_at_crate_root(lib_c, "Hidden", "secret"),
            "type only in private module must be unreachable"
        );

        // Case (d): `pub(crate) use` is NOT a public re-export and must stay excluded.
        let lib_d = "mod inner;\npub(crate) use crate::inner::Foo;\n";
        assert!(
            !type_reachable_at_crate_root(lib_d, "Foo", "inner"),
            "pub(crate) use must not count as public re-export"
        );

        // Sanity: existing named re-export still works (regression guard for case 1).
        let lib_e = "mod host;\npub use crate::host::Host;\n";
        assert!(
            type_reachable_at_crate_root(lib_e, "Host", "host"),
            "named pub use re-export must still be recognised"
        );
    }

    // --- F6: std/core conversion-trait UFCS resolution ---

    #[test]
    fn normalize_ref_arg_erases_lifetimes_and_whitespace() {
        assert_eq!(normalize_ref_arg("&'a [u8]"), "&[u8]");
        assert_eq!(normalize_ref_arg("&'static str"), "&str");
        assert_eq!(normalize_ref_arg("& str"), "&str");
        assert_eq!(normalize_ref_arg("&[u8]"), "&[u8]");
        assert_eq!(normalize_ref_arg("&str"), "&str");
    }

    #[test]
    fn std_ufcs_trait_path_resolves_fromstr() {
        // `impl FromStr for Version { fn from_str(text: &str) -> ... }` — the
        // semver pattern. The static method becomes a UFCS `<Version as
        // ::core::str::FromStr>::from_str(&s)` call.
        let f = parse_fn(
            "impl FromStr for Version {\n\
             fn from_str(text: &str) -> Result<Self, Error> { todo!() }\n}",
            "from_str",
        );
        assert!(f.is_static, "from_str is associated (no self)");
        assert_eq!(f.impl_trait.as_deref(), Some("FromStr"));
        assert_eq!(
            std_ufcs_trait_path(&f),
            Some(vec![
                "::core".to_owned(),
                "str".to_owned(),
                "FromStr".to_owned()
            ])
        );
    }

    #[test]
    fn std_ufcs_trait_path_resolves_tryfrom_bytes_and_str() {
        let f = parse_fn(
            "impl<'a> TryFrom<&'a [u8]> for Frame {\n\
             type Error = E;\n\
             fn try_from(b: &'a [u8]) -> Result<Self, E> { todo!() }\n}",
            "try_from",
        );
        assert_eq!(
            std_ufcs_trait_path(&f),
            Some(vec!["::core::convert::TryFrom<&[u8]>".to_owned()])
        );
        let g = parse_fn(
            "impl<'a> TryFrom<&'a str> for Tag {\n\
             type Error = E;\n\
             fn try_from(s: &'a str) -> Result<Self, E> { todo!() }\n}",
            "try_from",
        );
        assert_eq!(
            std_ufcs_trait_path(&g),
            Some(vec!["::core::convert::TryFrom<&str>".to_owned()])
        );
    }

    #[test]
    fn std_ufcs_trait_path_rejects_non_decodable_and_instance_and_other_traits() {
        // `TryFrom<u32>` is not a byte/str arg -> no native decoder -> keep skipping.
        let owned = parse_fn(
            "impl TryFrom<u32> for T {\n\
             type Error = E;\n\
             fn try_from(v: u32) -> Result<Self, E> { todo!() }\n}",
            "try_from",
        );
        assert_eq!(std_ufcs_trait_path(&owned), None);
        // `From<&str>` (infallible `from`) is not one of the handled shapes.
        let from = parse_fn(
            "impl From<&str> for T {\n\
             fn from(s: &str) -> Self { todo!() }\n}",
            "from",
        );
        assert_eq!(std_ufcs_trait_path(&from), None);
        // A FromStr with an UNEXPECTED parameter shape must not misfire.
        let weird = parse_fn(
            "impl FromStr for T {\n\
             fn from_str(a: &str, b: u8) -> Result<Self, E> { todo!() }\n}",
            "from_str",
        );
        assert_eq!(std_ufcs_trait_path(&weird), None);
        // An inherent (non-trait) static fn is not a trait-impl UFCS target.
        let inherent = parse_fn(
            "impl T { pub fn from_str(s: &str) -> Self { todo!() } }",
            "from_str",
        );
        assert_eq!(inherent.impl_trait, None);
        assert_eq!(std_ufcs_trait_path(&inherent), None);
    }

    #[test]
    fn enclosing_impl_type_is_generic_flags_instantiated_receivers() {
        // `impl FromStr for Map<String, Value>` — the bare `Map` path can't express
        // the instantiation, so F6 must treat it as generic (-> skip).
        assert!(impl_header_type_is_generic("impl FromStr for Map<String, Value> {").unwrap());
        assert!(impl_header_type_is_generic("impl<'a> Foo for Bar<'a> {").unwrap());
        // Non-generic receivers (the F6 wins).
        assert_eq!(
            impl_header_type_is_generic("impl FromStr for Version {"),
            Some(false)
        );
        assert_eq!(
            impl_header_type_is_generic("impl<'a> TryFrom<&'a [u8]> for Frame {"),
            Some(false)
        );
        // Not an impl header.
        assert_eq!(impl_header_type_is_generic("pub fn from_str() {}"), None);

        // End-to-end over a source body: the method line inside the generic impl is
        // flagged generic; one inside a plain impl is not.
        let src = "impl FromStr for Map<String, Value> {\n\
                   fn from_str(s: &str) -> Result<Self, E> { todo!() }\n}\n\
                   impl FromStr for Number {\n\
                   fn from_str(s: &str) -> Result<Self, E> { todo!() }\n}\n";
        assert!(
            enclosing_impl_type_is_generic(src, 2),
            "from_str in Map<String, Value> impl is generic"
        );
        assert!(
            !enclosing_impl_type_is_generic(src, 5),
            "from_str in Number impl is not generic"
        );
    }

    // --- F5: public re-export path resolution ---

    #[test]
    fn pub_use_prefix_and_idents_parses_named_group_glob_and_alias() {
        assert_eq!(
            pub_use_prefix_and_idents("raw::RawValue"),
            (vec!["raw".to_owned()], vec!["RawValue".to_owned()], false)
        );
        assert_eq!(
            pub_use_prefix_and_idents("crate::a::{B, C as D}"),
            (
                vec!["crate".to_owned(), "a".to_owned()],
                vec!["B".to_owned(), "D".to_owned()],
                false
            )
        );
        assert_eq!(
            pub_use_prefix_and_idents("raw::*"),
            (vec!["raw".to_owned()], Vec::<String>::new(), true)
        );
        // An alias renames the public ident; the module prefix is still `value::raw`.
        assert_eq!(
            pub_use_prefix_and_idents("value::raw::RawValue as Raw"),
            (
                vec!["value".to_owned(), "raw".to_owned()],
                vec!["Raw".to_owned()],
                false
            )
        );
    }

    #[test]
    fn normalize_reexport_prefix_handles_self_crate_and_relative() {
        let crate_name = "ron";
        let ancestor = vec!["value".to_owned()];
        // Relative `raw` (as written in value/mod.rs) -> `["raw"]`.
        assert_eq!(
            normalize_reexport_prefix(&["raw".to_owned()], crate_name, &ancestor),
            Some(vec!["raw".to_owned()])
        );
        // `self::raw` -> `["raw"]`.
        assert_eq!(
            normalize_reexport_prefix(
                &["self".to_owned(), "raw".to_owned()],
                crate_name,
                &ancestor
            ),
            Some(vec!["raw".to_owned()])
        );
        // `crate::value::raw` -> strip crate + ancestor (`value`) -> `["raw"]`.
        assert_eq!(
            normalize_reexport_prefix(
                &["crate".to_owned(), "value".to_owned(), "raw".to_owned()],
                crate_name,
                &ancestor
            ),
            Some(vec!["raw".to_owned()])
        );
        // `super::` is ambiguous -> None (skip).
        assert_eq!(
            normalize_reexport_prefix(
                &["super".to_owned(), "raw".to_owned()],
                crate_name,
                &ancestor
            ),
            None
        );
    }

    /// Build a fake crate mirroring ron's `RawValue` layout: a public `value`
    /// module that contains a `pub(crate) mod raw` plus an optional public
    /// re-export of `RawValue`.
    fn write_ron_like_crate(tmp: &Path, reexport: bool) {
        let src = tmp.join("src");
        std::fs::create_dir_all(src.join("value")).unwrap();
        std::fs::write(tmp.join("Cargo.toml"), "[package]\nname = \"ron\"\n").unwrap();
        std::fs::write(src.join("lib.rs"), "pub mod value;\n").unwrap();
        let value_mod = if reexport {
            "pub(crate) mod raw;\npub use raw::RawValue;\n"
        } else {
            "pub(crate) mod raw;\n"
        };
        std::fs::write(src.join("value").join("mod.rs"), value_mod).unwrap();
        std::fs::write(
            src.join("value").join("raw.rs"),
            "pub struct RawValue { ron: str }\n\
             impl RawValue { pub fn from_ron(ron: &str) -> Result<&Self, ()> { todo!() } }\n",
        )
        .unwrap();
    }

    #[test]
    fn resolve_public_reexport_path_prefers_public_reexport() {
        // ron's `value::raw::RawValue` (canonical, E0603 via `pub(crate) mod raw`)
        // must resolve to the public `ron::value::RawValue`.
        let tmp = tempfile::tempdir().unwrap();
        write_ron_like_crate(tmp.path(), true);
        let crate_root_src = read_crate_root_src(tmp.path());
        let module = vec!["value".to_owned(), "raw".to_owned()];
        assert_eq!(
            resolve_public_reexport_path(tmp.path(), "ron", &crate_root_src, &module, "RawValue"),
            Some(vec![
                "ron".to_owned(),
                "value".to_owned(),
                "RawValue".to_owned()
            ])
        );
    }

    #[test]
    fn resolve_public_reexport_path_none_when_not_reexported() {
        // No `pub use raw::RawValue;` anywhere -> no public path -> None, so the
        // caller keeps skipping (genuine non-re-exported case is not regressed).
        let tmp = tempfile::tempdir().unwrap();
        write_ron_like_crate(tmp.path(), false);
        let crate_root_src = read_crate_root_src(tmp.path());
        let module = vec!["value".to_owned(), "raw".to_owned()];
        assert_eq!(
            resolve_public_reexport_path(tmp.path(), "ron", &crate_root_src, &module, "RawValue"),
            None
        );
    }

    #[test]
    fn resolve_public_reexport_path_skips_non_pub_ancestor() {
        // If the ANCESTOR module is itself non-pub (here `value` is `pub(crate)`),
        // its re-export isn't reachable either -> None.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("value")).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"ron\"\n").unwrap();
        std::fs::write(src.join("lib.rs"), "pub(crate) mod value;\n").unwrap();
        std::fs::write(
            src.join("value").join("mod.rs"),
            "pub(crate) mod raw;\npub use raw::RawValue;\n",
        )
        .unwrap();
        std::fs::write(src.join("value").join("raw.rs"), "pub struct RawValue;\n").unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        let module = vec!["value".to_owned(), "raw".to_owned()];
        assert_eq!(
            resolve_public_reexport_path(tmp.path(), "ron", &crate_root_src, &module, "RawValue"),
            None,
            "a re-export inside a pub(crate) ancestor is not publicly reachable"
        );
    }

    // --- F7: `&T` struct param via Default ---

    #[test]
    fn ref_struct_param_detects_ref_struct_and_rejects_slices_primitives() {
        assert_eq!(
            ref_struct_param("&Options"),
            Some(("Options".to_owned(), false))
        );
        assert_eq!(
            ref_struct_param("&'a Config"),
            Some(("Config".to_owned(), false))
        );
        assert_eq!(
            ref_struct_param("&mut Builder"),
            Some(("Builder".to_owned(), true))
        );
        assert_eq!(
            ref_struct_param("&path::Options"),
            Some(("Options".to_owned(), false))
        );
        // Not a `&T` struct ref: byte/str slices (native decoders), primitives,
        // generics, non-references.
        assert_eq!(ref_struct_param("&[u8]"), None);
        assert_eq!(ref_struct_param("&str"), None);
        assert_eq!(ref_struct_param("&u8"), None);
        assert_eq!(ref_struct_param("&Config<T>"), None);
        assert_eq!(ref_struct_param("Options"), None);
    }

    #[test]
    fn find_default_type_path_resolves_reexported_default_struct() {
        // ron's layout: `pub use options::Options;` + `impl Default for Options`.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"ron\"\n").unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "mod options;\npub use options::Options;\n",
        )
        .unwrap();
        std::fs::write(
            src.join("options.rs"),
            "pub struct Options { depth: u8 }\n\
             impl Default for Options { fn default() -> Self { Options { depth: 0 } } }\n\
             pub struct NoDefault { x: u8 }\n",
        )
        .unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        assert_eq!(
            find_default_type_path(tmp.path(), "ron", &crate_root_src, "Options"),
            Some(vec!["ron".to_owned(), "Options".to_owned()])
        );
        // A reachable type with NO `Default` must not resolve (would fail to build).
        assert_eq!(
            find_default_type_path(tmp.path(), "ron", &crate_root_src, "NoDefault"),
            None
        );
    }

    #[test]
    fn resolve_param_overrides_fills_ref_struct_with_default() {
        // The end-to-end override: a `&Options` param resolves to a
        // `ron::Options::default()` fill passed by shared reference.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"ron\"\n").unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "mod options;\npub use options::Options;\n",
        )
        .unwrap();
        std::fs::write(
            src.join("options.rs"),
            "#[derive(Default)]\npub struct Options { depth: u8 }\n",
        )
        .unwrap();
        let crate_root_src = read_crate_root_src(tmp.path());
        let params = vec![rust_parser::RustParam {
            name: "options".to_owned(),
            ty: "&Options".to_owned(),
        }];
        let decoders = resolve_param_overrides(tmp.path(), "ron", &crate_root_src, &params);
        assert_eq!(
            decoders[0],
            Some((
                "ron::Options::default()".to_owned(),
                harness_gen::rust_decoders::ArgPass::Ref
            ))
        );
    }

    // ---- §27.1 / §27.10 helpers ----

    #[test]
    fn trait_supertrait_is_reader_matches_read_bounds() {
        assert!(trait_supertrait_is_reader(Some("io::Read")));
        assert!(trait_supertrait_is_reader(Some("std::io::Read")));
        assert!(trait_supertrait_is_reader(Some("Read")));
        assert!(trait_supertrait_is_reader(Some("BufRead")));
        // A sum bound with a reader clause still matches.
        assert!(trait_supertrait_is_reader(Some("Sized + io::Read")));
        // A non-reader supertrait (or none) does not.
        assert!(!trait_supertrait_is_reader(Some("Clone")));
        assert!(!trait_supertrait_is_reader(Some("io::Write")));
        assert!(!trait_supertrait_is_reader(None));
    }

    #[test]
    fn prepare_incrate_manifest_adds_runtime_staticlib_and_workspace() {
        // A bare package manifest gains the rust_runtime dep, a staticlib lib
        // crate-type, and a detached `[workspace]`.
        let runtime = Path::new("/tmp/rust_runtime");
        let crate_dir = Path::new("/tmp/crate");
        let out = prepare_incrate_manifest(
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            crate_dir,
            runtime,
        )
        .unwrap();
        assert!(out.contains("rust_runtime = { path ="), "{out}");
        assert!(
            out.contains("[lib]") && out.contains("crate-type = [\"staticlib\""),
            "{out}"
        );
        assert!(out.contains("[workspace]"), "{out}");

        // An existing `[lib]` (with name/path, no crate-type) gets a crate-type
        // inserted right under its header; an existing `[dependencies]` is reused;
        // an existing `[workspace]` is not duplicated.
        let with_lib = "[package]\nname = \"c\"\nversion = \"0.1.0\"\n\n\
                        [lib]\nname = \"c\"\npath = \"src/lib.rs\"\n\n\
                        [dependencies]\nserde = \"1\"\n\n[workspace]\n";
        let out2 = prepare_incrate_manifest(with_lib, crate_dir, runtime).unwrap();
        assert_eq!(
            out2.matches("[workspace]").count(),
            1,
            "no dup workspace: {out2}"
        );
        assert_eq!(
            out2.matches("[dependencies]").count(),
            1,
            "no dup deps: {out2}"
        );
        assert!(
            out2.contains("crate-type = [\"staticlib\", \"rlib\"]"),
            "{out2}"
        );
        assert!(
            out2.contains("serde = \"1\"") && out2.contains("rust_runtime ="),
            "{out2}"
        );

        // An existing `crate-type` array gains "staticlib" without duplication. (A
        // bare `[package] name` with no version/edition gets concrete ones injected.)
        let with_ct = "[package]\nname = \"c\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n";
        let out3 = prepare_incrate_manifest(with_ct, crate_dir, runtime).unwrap();
        assert!(out3.contains("\"staticlib\", \"cdylib\""), "{out3}");
        assert_eq!(out3.matches("crate-type").count(), 1, "{out3}");
        assert!(out3.contains("version = \"0.0.0\""), "{out3}");
        assert!(out3.contains("edition = \"2021\""), "{out3}");
    }

    #[test]
    fn prepare_incrate_manifest_resolves_workspace_inherited_fields() {
        // §27.10 regression (campaign: regex, pest): a workspace-MEMBER manifest that
        // inherits fields (`include.workspace = true`, a `version.workspace = true`
        // variant) and points at its root (`workspace = ".."`) must, once detached
        // (govfuzz appends its own `[workspace]`), still parse: NO `*.workspace = true`
        // lines survive, the `package.workspace` pointer is dropped, and concrete
        // version/edition are present.
        let runtime = Path::new("/tmp/rust_runtime");
        let crate_dir = Path::new("/tmp/crate");

        // (a) The exact regex-syntax shape: concrete version (kept), an
        // `include.workspace = true` (dropped), and `workspace = ".."` (dropped).
        let regex_syntax = "[package]\n\
            name = \"regex-syntax\"\n\
            version = \"0.8.11\"  #:version\n\
            license = \"MIT OR Apache-2.0\"\n\
            workspace = \"..\"\n\
            edition = \"2021\"\n\
            rust-version = \"1.65\"\n\
            include.workspace = true\n\n\
            [dependencies]\n\
            arbitrary = { version = \"1.3.0\", optional = true }\n";
        let out = prepare_incrate_manifest(regex_syntax, crate_dir, runtime).unwrap();
        assert!(
            !out.contains(".workspace = true"),
            "inherited field survived:\n{out}"
        );
        assert!(
            !out.contains("workspace = \"..\""),
            "package.workspace pointer survived:\n{out}"
        );
        assert!(
            out.contains("version = \"0.8.11\""),
            "concrete version dropped:\n{out}"
        );
        assert!(out.contains("edition = \"2021\""), "{out}");
        assert!(out.contains("[workspace]"), "{out}");
        // What would make cargo HARD-FAIL is gone (no inherited fields, and the
        // `package.workspace` + `[workspace]` conflict is resolved).
        assert!(out.contains("arbitrary ="), "concrete dep dropped:\n{out}");

        // (b) An inherited REQUIRED `version` (and a missing edition) get concrete
        // defaults injected; an inherited optional field (`authors.workspace`) is
        // dropped; the inline-table inheritance form is handled too.
        let inherited = "[package]\n\
            name = \"member\"\n\
            version.workspace = true\n\
            authors.workspace = true\n\
            license = { workspace = true }\n\
            workspace = \"..\"\n\n\
            [dependencies]\n";
        let out_b = prepare_incrate_manifest(inherited, crate_dir, runtime).unwrap();
        assert!(!out_b.contains(".workspace = true"), "{out_b}");
        assert!(
            !out_b.contains("workspace = true"),
            "inline-table inherit survived:\n{out_b}"
        );
        assert!(!out_b.contains("workspace = \"..\""), "{out_b}");
        assert!(
            out_b.contains("version = \"0.0.0\""),
            "version not resolved:\n{out_b}"
        );
        assert!(
            out_b.contains("edition = \"2021\""),
            "edition not injected:\n{out_b}"
        );
        assert!(
            !out_b.contains("authors"),
            "optional inherited field kept:\n{out_b}"
        );
    }

    #[test]
    fn prepare_incrate_manifest_makes_sibling_path_deps_absolute() {
        // pest's members path-dep their siblings (`pest = { path = "../pest" }`); the
        // copy lives elsewhere, so relative paths must be re-anchored at the ORIGINAL
        // crate dir to resolve.
        let runtime = Path::new("/tmp/rust_runtime");
        let crate_dir = Path::new("/home/u/pest/meta");
        let manifest =
            "[package]\nname = \"pest_meta\"\nversion = \"2.8.6\"\nedition = \"2021\"\n\n\
            [dependencies]\n\
            pest = { path = \"../pest\", version = \"2.8.6\" }\n";
        let out = prepare_incrate_manifest(manifest, crate_dir, runtime).unwrap();
        assert!(
            out.contains("path = \"/home/u/pest/pest\""),
            "sibling path not absolutized:\n{out}"
        );
        assert!(
            !out.contains("path = \"../pest\""),
            "relative path survived:\n{out}"
        );
    }

    #[test]
    fn prepare_incrate_manifest_skips_on_workspace_inherited_dep() {
        // A `workspace = true` dependency can't be resolved by the detached copy (no
        // parent `[workspace.dependencies]`) — request a CLEAN SKIP, not a hard error.
        let runtime = Path::new("/tmp/rust_runtime");
        let crate_dir = Path::new("/tmp/crate");
        let manifest = "[package]\nname = \"m\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
            [dependencies]\nserde = { workspace = true }\nlocal = { path = \"./x\" }\n";
        let err = prepare_incrate_manifest(manifest, crate_dir, runtime).unwrap_err();
        assert!(
            err.contains("serde"),
            "skip reason should name the dep: {err}"
        );
        assert!(err.contains("skipped"), "{err}");

        // The dotted + subtable forms are detected too.
        let dotted = "[package]\nname = \"m\"\nversion = \"1\"\nedition = \"2021\"\n\n\
            [dependencies]\ntokio.workspace = true\n";
        assert!(prepare_incrate_manifest(dotted, crate_dir, runtime).is_err());
        let subtable = "[package]\nname = \"m\"\nversion = \"1\"\nedition = \"2021\"\n\n\
            [dependencies.regex]\nworkspace = true\n";
        let e2 = prepare_incrate_manifest(subtable, crate_dir, runtime).unwrap_err();
        assert!(e2.contains("regex"), "{e2}");
    }

    #[test]
    fn forbids_unsafe_code_detects_crate_level_forbid() {
        assert!(forbids_unsafe_code(
            "#![forbid(unsafe_code)]\npub fn f() {}\n"
        ));
        assert!(forbids_unsafe_code(
            "//! docs\n#![forbid(missing_docs, unsafe_code)]\n"
        ));
        // `deny` (overridable) and an unrelated forbid do not gate the lane.
        assert!(!forbids_unsafe_code("#![deny(unsafe_code)]\n"));
        assert!(!forbids_unsafe_code("#![forbid(missing_docs)]\n"));
        assert!(!forbids_unsafe_code(
            "pub fn f() { let unsafe_code = 1; }\n"
        ));
    }

    #[test]
    fn forbids_unsafe_code_detects_cfg_attr_forbid() {
        // GAP 2 (campaign: pulldown-cmark): the forbid is conditional on the `simd`
        // feature (never enabled by the in-crate build), so it IS active and the
        // injected `#[no_mangle]` harness would be rejected — detect + skip cleanly.
        assert!(forbids_unsafe_code(
            "#![cfg_attr(not(feature = \"simd\"), forbid(unsafe_code))]\n"
        ));
        // A direct cfg_attr forbid, and one among several forbidden lints, both match.
        assert!(forbids_unsafe_code(
            "#![cfg_attr(feature = \"strict\", forbid(missing_docs, unsafe_code))]\n"
        ));
        // A cfg_attr that forbids something ELSE does not gate the lane.
        assert!(!forbids_unsafe_code(
            "#![cfg_attr(docsrs, forbid(missing_docs))]\n"
        ));
        // A cfg_attr that only `deny`s (overridable) unsafe_code does not gate it.
        assert!(!forbids_unsafe_code(
            "#![cfg_attr(test, deny(unsafe_code))]\n"
        ));
        // An identifier merely containing "forbid" is not a `forbid(` attribute.
        assert!(!forbids_unsafe_code(
            "#![allow(clippy::forbid_lint_groups)]\n"
        ));
    }

    #[test]
    fn incrate_harness_uses_unsafe_no_mangle() {
        // GAP 2: the injected in-crate harness wraps `#[no_mangle]` so it compiles
        // inside an edition-2024 target crate (bare form is a hard error there).
        let harness = "#[no_mangle]\npub extern \"C\" fn govfuzz_run_one(d: *const u8, l: usize) \
                       -> i32 { 0 }\n";
        let out = incrate_harness_with_unsafe_no_mangle(harness);
        assert!(out.contains("#[unsafe(no_mangle)]"), "{out}");
        assert!(!out.contains("\n#[no_mangle]"), "{out}");
        // The exported symbol + signature are untouched.
        assert!(out.contains("pub extern \"C\" fn govfuzz_run_one"), "{out}");
    }

    fn mk_candidate(source_path: &Path, name: &str, line: u32) -> Candidate {
        Candidate {
            harness_id: "H-R-test".to_owned(),
            lang: crate::auto::candidate::Lang::Rust,
            source_path: source_path.to_path_buf(),
            line,
            name: name.to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    #[test]
    fn resolve_target_private_module_uses_in_crate_build_mode() {
        // §27.10 detection + path emission: a `pub` type in a PRIVATE module
        // (E0603 externally) resolves to an IN-CRATE build with a `crate::`-rooted
        // path, NOT a skip.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"k\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(src.join("lib.rs"), "mod internal;\n").unwrap();
        std::fs::write(
            src.join("internal.rs"),
            "pub struct Parser { n: usize }\n\
             impl Parser {\n\
                 pub fn new() -> Self { Parser { n: 0 } }\n\
                 pub fn parse(&mut self, data: &[u8]) -> u32 { data.len() as u32 }\n\
             }\n",
        )
        .unwrap();
        let cand = mk_candidate(&src.join("internal.rs"), "parse", 4);
        let resolved = resolve_target(&cand).expect("private-module target resolves in-crate");
        assert_eq!(resolved.build_mode, BuildMode::InCrate);
        // The call path is rooted at `crate` and reaches the private module + type.
        assert_eq!(
            resolved.call_path,
            vec!["crate", "internal", "Parser", "parse"]
        );
        // The receiver ctor is the no-arg `new`, also crate-rooted.
        assert_eq!(
            resolved.receiver.as_deref(),
            Some(
                ["crate", "internal", "Parser", "new"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
    }

    #[test]
    fn resolve_target_skips_unsafe_fn_primary_target() {
        // json-rust shape: `pub unsafe fn Short::from_slice(s: &str) -> Short` is
        // documented with a `s.len() <= 30` safety precondition. Feeding it the full
        // fuzz input violates the contract and fabricates a false GF-203 stack
        // overflow, so it must be SKIPPED as a primary target (a clean Err), not
        // harnessed.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"jsonr\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "pub struct Short { p: u8 }\n\
             impl Short {\n\
                 /// Safety: `s.len()` must be <= 30.\n\
                 pub unsafe fn from_slice(s: &str) -> Short { Short { p: s.len() as u8 } }\n\
             }\n\
             pub fn safe_parse(data: &[u8]) -> u32 { data.len() as u32 }\n",
        )
        .unwrap();
        let cand = mk_candidate(&src.join("lib.rs"), "from_slice", 4);
        let err = resolve_target(&cand)
            .expect_err("an unsafe fn primary target must be skipped, not harnessed");
        assert!(err.contains("unsafe fn"), "{err}");
        assert!(err.contains("skipped"), "{err}");

        // A SAFE fn in the same crate still harnesses (the skip is gated to the
        // `unsafe` modifier, not the whole file).
        let safe = mk_candidate(&src.join("lib.rs"), "safe_parse", 6);
        assert!(
            resolve_target(&safe).is_ok(),
            "a safe sibling fn must still resolve"
        );
    }

    #[test]
    fn resolve_target_reader_trait_method_synthesises_cursor_receiver() {
        // §27.1 detection + path emission: a `pub trait`'s reader method resolves
        // to a `std::io::Cursor` receiver + a trait import, NOT a free-fn call.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"rd\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "use std::io::Read;\n\
             pub trait ReadExt: Read {\n\
                 fn read_tag(&mut self) -> std::io::Result<u8>;\n\
             }\n\
             impl<R: Read + ?Sized> ReadExt for R {}\n",
        )
        .unwrap();
        let cand = mk_candidate(&src.join("lib.rs"), "read_tag", 3);
        let resolved = resolve_target(&cand).expect("reader trait method resolves");
        assert_eq!(resolved.build_mode, BuildMode::External);
        assert_eq!(
            resolved.receiver.as_deref(),
            Some(["std", "io", "Cursor", "new"].map(str::to_owned).as_slice())
        );
        assert_eq!(
            resolved.method_trait_import.as_deref(),
            Some(["rd", "ReadExt"].map(str::to_owned).as_slice())
        );
        assert_eq!(
            resolved.call_path.last().map(String::as_str),
            Some("read_tag")
        );
    }

    #[test]
    fn resolve_target_non_reader_trait_method_skips_cleanly() {
        // A `pub trait` method whose trait is NOT a reader has no constructable
        // receiver — a clean skip, never a build-breaking harness.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"nx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "pub trait Visit {\n    fn visit(&self, data: &[u8]) -> u32;\n}\n",
        )
        .unwrap();
        let cand = mk_candidate(&src.join("lib.rs"), "visit", 2);
        let err = resolve_target(&cand).unwrap_err();
        assert!(err.contains("not auto-harnessable"), "{err}");
    }
}
