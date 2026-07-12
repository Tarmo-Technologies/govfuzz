// SPDX-License-Identifier: Apache-2.0

use crate::auto::candidate::{Candidate, Lang};
use ada_parser::ast::Visibility;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Whether to run the CPP-lite preprocessor (#460 / §27.6) over a C/C++ file
/// before parsing it for discovery. Preprocessing resolves `#ifdef`/`#if` branches
/// and expands object-like macros so tree-sitter sees the single, correct set of
/// declarations (a function compiled out under the active config is not discovered;
/// a macro-sized array is concrete). It is paired with a preprocessed->original
/// line map so reported target locations stay on the ORIGINAL source line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PreprocessMode {
    /// Preprocess only files with heavy conditional compilation (the default): the
    /// common no-`#ifdef` file is parsed raw (zero behavior change), while a file
    /// gated by many `#if`/`#ifdef` branches is resolved first.
    #[default]
    Auto,
    /// Force the preprocessor on for every C/C++ file.
    Always,
    /// Never preprocess; parse raw source (the pre-§27.6 behavior).
    Never,
}

impl std::fmt::Display for PreprocessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PreprocessMode::Auto => "auto",
            PreprocessMode::Always => "always",
            PreprocessMode::Never => "never",
        };
        f.write_str(s)
    }
}

/// The number of conditional-compilation directives at/above which the `Auto`
/// mode preprocesses a file. A handful of header guards (`#ifndef FOO_H` /
/// `#ifdef __cplusplus`) is normal and must NOT trip it; a file whose declarations
/// are genuinely gated by feature/platform `#if`s (the §27.6 motivation) clears it.
const HEAVY_CONDITIONAL_THRESHOLD: usize = 5;

/// Count conditional-compilation directives (`#if`, `#ifdef`, `#ifndef`, `#elif`)
/// in `source` — a cheap proxy for "heavy conditional compilation". `#else`/`#endif`
/// are not counted (they pair with the openers already counted).
fn conditional_directive_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix('#') else {
                return false;
            };
            let rest = rest.trim_start();
            rest == "if"
                || rest == "ifdef"
                || rest == "ifndef"
                || rest == "elif"
                || rest.starts_with("if ")
                || rest.starts_with("if(")
                || rest.starts_with("ifdef ")
                || rest.starts_with("ifndef ")
                || rest.starts_with("elif ")
                || rest.starts_with("elif(")
        })
        .count()
}

/// Whether a C/C++ `source` should be preprocessed before parsing under `mode`.
fn should_preprocess(mode: PreprocessMode, source: &str) -> bool {
    match mode {
        PreprocessMode::Always => true,
        PreprocessMode::Never => false,
        PreprocessMode::Auto => conditional_directive_count(source) >= HEAVY_CONDITIONAL_THRESHOLD,
    }
}

/// Parse `source` for C functions under `mode`, returning each function with its
/// line number translated back to the ORIGINAL source (§27.6). When preprocessing
/// is off (or the source has no heavy conditional compilation) this is exactly
/// `c_parser::parse_c_functions` on the raw text with identity line numbers.
fn parse_c_functions_preprocessed(
    source: &str,
    mode: PreprocessMode,
) -> Result<Vec<c_parser::CFunction>, c_parser::CParseError> {
    if should_preprocess(mode, source) {
        let (pp, line_map) = idl_parser::preprocess_c_like_with_line_map(source, &[]);
        let mut fns = c_parser::parse_c_functions(&pp)?;
        for f in &mut fns {
            f.line = line_map.to_original(f.line);
        }
        // Defense (#2 campaign): the CPP-lite preprocessor evaluates a whole-file
        // `#if MPACK_FEATURE` gate against an UNEXPANDED header, so a feature
        // default-defined to 1 in a header this file does not inline reads as
        // false and the ENTIRE .c API is stripped to zero functions (mpack
        // reader/node/writer/expect) — a silent false-clean. When preprocessing
        // wipes out every function a raw parse would have found, the gate
        // evaluation was wrong; fall back to the raw parse. Over-discovering a
        // genuinely-compiled-out function only costs a failed build, which is
        // honest — a hidden API is not.
        if fns.is_empty() {
            let raw = c_parser::parse_c_functions(source)?;
            if !raw.is_empty() {
                eprintln!(
                    "govfuzz auto: note: preprocessing removed all {} discoverable \
                     function(s) (likely an unexpanded #if feature gate); using the raw parse",
                    raw.len()
                );
                return Ok(raw);
            }
        }
        Ok(fns)
    } else {
        c_parser::parse_c_functions(source)
    }
}

/// C++ counterpart of [`parse_c_functions_preprocessed`].
fn parse_cpp_functions_preprocessed(
    source: &str,
    mode: PreprocessMode,
) -> Result<Vec<cpp_parser::CppFunction>, cpp_parser::CppParseError> {
    if should_preprocess(mode, source) {
        let (pp, line_map) = idl_parser::preprocess_c_like_with_line_map(source, &[]);
        let mut fns = cpp_parser::parse_cpp_functions(&pp)?;
        for f in &mut fns {
            f.line = line_map.to_original(f.line);
        }
        Ok(fns)
    } else {
        cpp_parser::parse_cpp_functions(source)
    }
}

/// An Ada subprogram is a viable direct-call fuzz target only when it has an
/// exported symbol a separately compiled harness can name.
///
/// A `Public` subprogram qualifies only when it is declared in a package *spec*
/// (`.ads`): the same `Visibility::Public` is also produced for a subprogram
/// declared in a package spec that is itself nested inside a subprogram or
/// package body (very common in large Ada bodies, e.g. `package UnZ_Meth is ...
/// end` declared inside a procedure). Those have no external symbol and only
/// ever appear in `.adb` files, so gate `Public` on the spec file.
///
/// A `LibraryLevel` subprogram in a `.ads`, or in a `.adb` with *no* sibling
/// spec, is a real standalone compilation unit and qualifies. But a
/// `LibraryLevel` in a `.adb` that *has* a sibling `.ads` is never genuinely
/// exported there: it is either a spec-completion duplicate (already found via
/// the `.ads`) or, in deeply-nested legacy bodies, a nested procedure the
/// parser mis-scoped to library level. Drop those - they only fail to link.
///
/// Abstract subprograms have no body to link against and are excluded outright.
/// Whether `subprogram`'s owning package — or any ancestor package — is a
/// private nested package, making the subprogram unreachable from a harness
/// that `with`s the root unit.
/// Whether the subprogram is a generic INSTANTIATION (`procedure Free is new
/// Ada.Unchecked_Deallocation (...);`). The structural parser models it as a
/// zero-parameter subprogram (its real profile comes from the generic it
/// instantiates), so a direct-call harness would call it with the wrong arity
/// ("missing argument for ..."); it is also never a meaningful fuzz target
/// (typically a deallocator). Detected by scanning the declaration for `is new`
/// before its terminating `;`.
fn subprogram_is_instantiation(source: &str, subprogram: &ada_parser::ast::Subprogram) -> bool {
    let start = subprogram.decl_span.start_byte as usize;
    let window_end = (start + 512).min(source.len());
    let Some(window) = source.get(start..window_end) else {
        return false;
    };
    let head = match window.find(';') {
        Some(semi) => &window[..semi],
        None => window,
    };
    let tokens: Vec<&str> = head.split_whitespace().collect();
    tokens
        .windows(2)
        .any(|w| w[0].eq_ignore_ascii_case("is") && w[1].eq_ignore_ascii_case("new"))
}

/// Score penalty for a subprogram of an un-instantiable generic package. Large
/// enough to sink it below every normally-ranked target (scores are small
/// positive i32) while preserving relative order among demoted targets.
const GENERIC_DEMOTION: i32 = 1_000_000;

/// True when `subprogram`'s owning package (or any generic ancestor) is generic
/// with at least one formal the harness generator cannot synthesize a concrete
/// actual for (a formal `type`, `with package`, or `is <>`). Such a target can
/// never be auto-instantiated.
fn subprogram_in_unsynthesizable_generic(
    ast: &ada_parser::ast::StructuralAst,
    subprogram: &ada_parser::ast::Subprogram,
    source: &str,
) -> bool {
    use ada_parser::ast::SubprogramOwner;
    let mut current = match subprogram.owner {
        SubprogramOwner::Package(id) => Some(id),
        SubprogramOwner::LibraryLevel => None,
    };
    while let Some(id) = current {
        let Some(package) = ast.packages.iter().find(|p| p.id == id) else {
            break;
        };
        // The structural AST flags `is_generic` but doesn't retain the formal
        // block, so the formals are re-parsed from the source by simple name.
        if package.is_generic
            && !harness_gen::generic_instance::generic_package_is_synthesizable(
                source,
                &package.name,
            )
        {
            return true;
        }
        current = package.parent;
    }
    false
}

fn subprogram_in_private_package(
    ast: &ada_parser::ast::StructuralAst,
    subprogram: &ada_parser::ast::Subprogram,
) -> bool {
    use ada_parser::ast::SubprogramOwner;
    let mut current = match subprogram.owner {
        SubprogramOwner::Package(id) => Some(id),
        SubprogramOwner::LibraryLevel => None,
    };
    while let Some(id) = current {
        let Some(package) = ast.packages.iter().find(|p| p.id == id) else {
            break;
        };
        if package.is_private {
            return true;
        }
        current = package.parent;
    }
    false
}

fn is_externally_callable(
    subprogram: &ada_parser::ast::Subprogram,
    is_spec_file: bool,
    body_has_sibling_spec: bool,
) -> bool {
    if subprogram.is_abstract {
        return false;
    }
    match subprogram.visibility {
        Visibility::LibraryLevel => is_spec_file || !body_has_sibling_spec,
        Visibility::Public => is_spec_file,
        Visibility::Private | Visibility::Local => false,
    }
}

/// A deterministic, BUILD-STABLE hasher (FNV-1a, 64-bit) for the discovery
/// fingerprint and harness ids.
///
/// `std::collections::hash_map::DefaultHasher` was used here originally with a
/// comment claiming it was "stable across processes" — true for one binary, but
/// Rust does NOT guarantee `DefaultHasher`'s algorithm is stable across compiler/
/// std versions. So a govfuzz rebuilt on a newer toolchain hashed byte-identical
/// TARGET source to a different digest → the discovery cache fingerprint no longer
/// matched (spurious "source changed" miss → full re-discovery) and
/// `stable_harness_id` produced different per-target dir names (orphaning the
/// prior corpus/build). The fingerprint must depend ONLY on the fuzzed code, not
/// on which govfuzz build computed it.
///
/// FNV-1a is fully specified (offset basis + prime are constants), so the digest
/// is identical on any toolchain. All integer writes use fixed little-endian
/// encoding, so the output is also independent of host endianness/word size — a
/// pure function of the logical input. Non-cryptographic, which is fine: this
/// guards a *re-run optimization*, and any real source/filter change still flips
/// the digest.
pub(crate) struct StableHasher(u64);

impl StableHasher {
    /// FNV-1a 64-bit offset basis.
    pub(crate) fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl std::hash::Hasher for StableHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a 64-bit prime
        }
    }
    // The `Hash` impls drive the hasher via these; the trait defaults use
    // `to_ne_bytes` (native-endian) which would make the digest arch-dependent.
    // Pin little-endian so the same logical value hashes identically everywhere.
    fn write_u16(&mut self, i: u16) {
        self.write(&i.to_le_bytes());
    }
    fn write_u32(&mut self, i: u32) {
        self.write(&i.to_le_bytes());
    }
    fn write_u64(&mut self, i: u64) {
        self.write(&i.to_le_bytes());
    }
    fn write_u128(&mut self, i: u128) {
        self.write(&i.to_le_bytes());
    }
    fn write_usize(&mut self, i: usize) {
        self.write(&(i as u64).to_le_bytes());
    }
    fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16);
    }
    fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32);
    }
    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }
    fn write_isize(&mut self, i: isize) {
        self.write_usize(i as usize);
    }
}

/// Build a collision-resistant harness id from `(source_path, line,
/// name)`. The visible prefix keeps the line number for at-a-glance
/// debugging; the 32-bit hash tail prevents two functions at the
/// same line in different files from clobbering each other's
/// `<work>/harnesses/<id>/` directory. Uses [`StableHasher`] so the id is identical
/// across govfuzz rebuilds (per-target corpus/build dirs survive a rebuild).
pub(crate) fn stable_harness_id(prefix: &str, source: &Path, line: u32, name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = StableHasher::new();
    source.display().to_string().hash(&mut hasher);
    line.hash(&mut hasher);
    name.hash(&mut hasher);
    let digest = hasher.finish();
    format!("{prefix}{line:04X}-{:08X}", digest as u32)
}

/// Directory-name filter applied during the discovery walk. A built-in default
/// set of non-library directories (tests, examples, vendored deps, …) is skipped
/// so their functions don't out-rank the project's real entry points; the set is
/// configurable per run (CLI `--exclude-dir` / `--include-dir`) because what counts
/// as "the library" varies by project. Build/VCS dirs are skipped unconditionally
/// (never overridable — they hold no targets).
#[derive(Debug, Default, Clone)]
pub struct DirFilter {
    /// Extra directory names to skip ON TOP of the built-in defaults.
    extra_excludes: std::collections::HashSet<String>,
    /// Directory names to KEEP even when a built-in default would skip them (so a
    /// project that legitimately ships fuzzable code under e.g. `samples/` opts in).
    keep: std::collections::HashSet<String>,
    /// The run's work directory, canonicalized, when it lives INSIDE the scanned
    /// tree. Excluded by PATH (not just by the default `govfuzz_work` name) so a
    /// custom `--work-dir` under the tree — e.g. `govfuzz auto --work-dir wd .` —
    /// doesn't have its generated harnesses/build output re-discovered as targets,
    /// which silently drops the real targets.
    work_dir: Option<std::path::PathBuf>,
}

impl DirFilter {
    /// Build from user-supplied name lists (matched case-insensitively).
    pub fn new(extra_excludes: &[String], keep: &[String]) -> Self {
        let lower = |xs: &[String]| xs.iter().map(|s| s.to_ascii_lowercase()).collect();
        Self {
            extra_excludes: lower(extra_excludes),
            keep: lower(keep),
            work_dir: None,
        }
    }

    /// Exclude `work_dir` (whatever its name) from discovery. Canonicalized so a
    /// relative path or one with `..`/symlinks still matches the walked directory.
    pub fn with_work_dir(mut self, work_dir: &Path) -> Self {
        self.work_dir = work_dir.canonicalize().ok();
        self
    }

    /// Whether `path` is the run's work directory (compared by canonical path).
    fn is_work_dir(&self, path: &Path) -> bool {
        match &self.work_dir {
            Some(wd) => path.canonicalize().ok().as_deref() == Some(wd.as_path()),
            None => false,
        }
    }

    /// Whether a directory named `name` should be skipped (non-library code).
    pub(crate) fn skips(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        if self.keep.contains(&n) {
            return false;
        }
        is_default_non_library_dir(&n) || self.extra_excludes.contains(&n)
    }

    /// Whether a directory named `name` should be skipped when inside a
    /// Maven/Gradle Java/Kotlin source root (`src/main/java`,
    /// `src/main/kotlin`). Directory names inside such a root are
    /// **package-name components** (`tools.jackson.core` → `tools/jackson/core/`),
    /// not organizational labels, so the default organizational-name exclusions
    /// (`tools/`, `vendor/`, `examples/`, `bench*`, …) are suppressed.
    /// Only user-supplied `--exclude-dir` entries still apply (the user
    /// explicitly opted in). `keep` is also respected so a user who adds a
    /// name to both lists gets the expected result.
    pub(crate) fn skips_in_java_root(&self, name: &str) -> bool {
        self.skips_user_only(name)
    }

    /// Whether a directory named `name` should be skipped when inside a C/C++
    /// header-API root (`include/`, `inc/`). Directory names there are library
    /// **namespace/module components** (CLI11's `include/CLI/`, fmt's
    /// `include/fmt/`), not organizational labels, so the default
    /// organizational-name exclusions (`cli/`, `app/`, `tools/`, `examples/`, …)
    /// are suppressed — exactly as inside a Java source root. Only user-supplied
    /// `--exclude-dir` entries still apply (`keep` is honored too).
    pub(crate) fn skips_in_header_root(&self, name: &str) -> bool {
        self.skips_user_only(name)
    }

    /// Shared body for the "namespace/module root" filters ([`skips_in_java_root`],
    /// [`skips_in_header_root`]): the default organizational-name heuristics are
    /// suppressed because directory names there are module/namespace components,
    /// so only a user-supplied `--exclude-dir` entry skips a directory (with
    /// `keep` still able to override it).
    fn skips_user_only(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        if self.keep.contains(&n) {
            return false;
        }
        self.extra_excludes.contains(&n)
    }
}

pub fn discover(root: &Path) -> Result<Vec<Candidate>> {
    discover_with_dir_filter(root, &DirFilter::default())
}

/// As [`discover`], but with a caller-supplied [`DirFilter`] so a run can add or
/// remove non-library directory exclusions from the built-in defaults. Uses the
/// default [`PreprocessMode::Auto`] (preprocess only heavy-conditional C/C++).
pub fn discover_with_dir_filter(root: &Path, filter: &DirFilter) -> Result<Vec<Candidate>> {
    discover_with_options(root, filter, PreprocessMode::Auto)
}

/// As [`discover_with_dir_filter`], but with an explicit [`PreprocessMode`] (§27.6)
/// so the CLI can force the CPP-lite preprocessor on/off for the C/C++ lane.
pub fn discover_with_options(
    root: &Path,
    filter: &DirFilter,
    preprocess: PreprocessMode,
) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    walk(root, &mut out, filter, preprocess)?;
    // Cross-file C++ visibility filter. A method DEFINED out-of-line
    // (`int Class::m(){}` in a .cpp) loses the access specifier that lives in the
    // class body (a .h), so its per-file `member_access` is None and the rank
    // filter can't drop it — a `protected`/`private` member then gets harnessed
    // and the build fails with "is a protected member" (inih's
    // `INIReader::ValueHandler`, a protected callback). Build a tree-global
    // `Class::method -> access` map from every C++ class body and drop candidates
    // that resolve to a non-public member. Only DROP on an explicit non-public
    // hit, so an unknown/free function is never over-filtered. Skipped entirely
    // when no C++ candidates exist.
    if out.iter().any(|c| matches!(c.lang, Lang::Cpp)) {
        let mut cpp_access = std::collections::BTreeMap::new();
        collect_cpp_member_access(root, filter, &mut cpp_access);
        out.retain(|c| {
            if !matches!(c.lang, Lang::Cpp) {
                return true;
            }
            // `parse_cpp_method_access` keys by `Class::method` (no namespace), but a
            // candidate name is `[ns::]Class::method` (`tinyxml2::XMLDocument::SetError`).
            // Match on the last two `::` segments so a private method of a NAMESPACED
            // class is still dropped.
            let full = c.name.split('(').next().unwrap_or(&c.name).trim();
            let segments: Vec<&str> = full.split("::").collect();
            let key = if segments.len() >= 2 {
                segments[segments.len() - 2..].join("::")
            } else {
                full.to_owned()
            };
            cpp_access.get(&key).is_none_or(|access| access == "public")
        });
    }
    // Drop fuzz-driver entry points by NAME (belt-and-suspenders to the `fuzz/`
    // dir skip): a libFuzzer/AFL harness function has the canonical fuzz
    // signature (`const uint8_t *, size_t`) so the scorer ranks it at the very
    // top, but harnessing a harness is meaningless — and govfuzz emits
    // `LLVMFuzzerTestOneInput` into its OWN generated harnesses, so a re-run over
    // a directory holding prior output would otherwise target itself.
    // C/C++ functions named exactly `main` are dropped here: the generated harness
    // defines its own `int main(...)`, so including the target's `main` always fails
    // with a duplicate-main link error (`conflicting types for 'main'` or a duplicate-
    // symbol linker error). `main` is a program entry point, not a library API — it
    // takes argc/argv, not a content buffer — and every such harness is pure waste.
    out.retain(|c| {
        // Always-drop non-library noise: a libFuzzer HOOK (Initialize / CustomMutator
        // / CustomCrossOver — never fuzzable, no `(data, size)` body to drive), or a
        // macro/template-placeholder "function" name (`FUNCNAME`,
        // `QLFC_ADAPTIVE_ENCODE_FUNCTION_NAME`) — the literal token a `*_template.h`
        // is compiled with after `#define`-ing the real name, never a callable
        // symbol (libdeflate, libbsc surfaced these at the top).
        // `main` (C/C++ program entry point, matched on the bare name so
        // `h2load::main` is also caught): the generated harness defines its own
        // `int main(...)`, causing an always-fail duplicate-main link error.
        let drop_always = is_libfuzzer_hook(&c.name)
            || (matches!(c.lang, Lang::C | Lang::Cpp) && is_macro_placeholder_name(&c.name))
            || (matches!(c.lang, Lang::C | Lang::Cpp) && bare_name(&c.name) == "main");
        !drop_always
    });
    // `LLVMFuzzerTestOneInput` is a fuzz DRIVER, not a library target. Drop it when
    // the tree ALSO has a real target — so a project's own harness can't out-rank its
    // parser (libconfig's `fuzz/` harness was ranked #1 over `__config_read`), and a
    // re-run over a directory of prior govfuzz output never targets itself. But when
    // it is the SOLE fuzzable candidate, the tree IS a project-supplied single-file
    // libFuzzer target: keep it as the PASSTHROUGH target (#408/#410) rather than
    // discovering nothing.
    if out.iter().any(|c| !is_libfuzzer_test_one_input(&c.name)) {
        out.retain(|c| !is_libfuzzer_test_one_input(&c.name));
    }
    dedup_amalgamated_single_header(&mut out);
    apply_entrypoint_callgraph(&mut out);
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// A deterministic fingerprint of the discovery-relevant source state under
/// `root` for the given `filter`. Two runs over the SAME tree (no file
/// added/removed/edited, same dir-filter config) produce the same string; any
/// content change, or a different `--exclude-dir`/`--include-dir`, changes it.
/// Used by the discovery cache (`auto --reuse-discovery`) to decide whether a
/// cached candidate list is still valid without re-parsing the tree.
///
/// Identity is the file's CONTENT, not its mtime — a `git checkout` / `cp` /
/// `rsync` that rewrites mtimes without changing bytes must NOT bust the cache.
/// It walks the same directory structure discovery does (skipping the same
/// excluded dirs so an unrelated `build/`/`tests/` change can't bust it) and
/// folds in, per targetable-extension file, the path + byte length + a content
/// hash. The hasher is `StableHasher` (FNV-1a), so the digest is build-stable and
/// stable across processes — the same property `stable_harness_id` relies on.
/// (Reading the bytes is far cheaper than the tree-sitter re-parse it avoids.)
pub fn source_fingerprint(root: &Path, filter: &DirFilter) -> String {
    use std::hash::{Hash, Hasher};

    // Collect (relative-path, len, content-hash) for every targetable file, in a
    // deterministic (sorted) order so the digest is walk-order independent.
    let mut entries: Vec<(String, u64, u64)> = Vec::new();
    fingerprint_walk(root, root, filter, &mut entries);
    entries.sort();

    let mut hasher = StableHasher::new();
    // Fold in the dir-filter config: changing it changes the discovered set even
    // when no file changed, so it must change the fingerprint too.
    let mut excludes: Vec<&String> = filter.extra_excludes.iter().collect();
    excludes.sort();
    let mut keeps: Vec<&String> = filter.keep.iter().collect();
    keeps.sort();
    "exclude".hash(&mut hasher);
    for e in excludes {
        e.hash(&mut hasher);
    }
    "keep".hash(&mut hasher);
    for k in keeps {
        k.hash(&mut hasher);
    }
    "files".hash(&mut hasher);
    entries.len().hash(&mut hasher);
    for (rel, len, content) in &entries {
        rel.hash(&mut hasher);
        len.hash(&mut hasher);
        content.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// A build-stable content hash of a file's bytes ([`StableHasher`], FNV-1a), used
/// by the discovery fingerprint so identity tracks content, not mtime, and is
/// identical across govfuzz rebuilds.
fn hash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = StableHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// Recursive helper for [`source_fingerprint`]: mirrors [`walk`]'s directory
/// pruning but records (path, len, content-hash) instead of parsing. An
/// unreadable file is recorded as zeros so a permissions hiccup degrades to a
/// stable (if coarse) fingerprint rather than panicking.
fn fingerprint_walk(
    root: &Path,
    dir: &Path,
    filter: &DirFilter,
    out: &mut Vec<(String, u64, u64)>,
) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if is_excluded_dir(&path, filter) {
                continue;
            }
            fingerprint_walk(root, &path, filter, out);
        } else if ft.is_file() && has_targetable_extension(&path) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            // Identity is CONTENT, not mtime (see `source_fingerprint`): read
            // the bytes and fold in a stable content hash. Unreadable → zeros.
            let (len, content) = match std::fs::read(&path) {
                Ok(bytes) => (bytes.len() as u64, hash_bytes(&bytes)),
                Err(_) => (0, 0),
            };
            out.push((rel, len, content));
        }
    }
}

/// The bare symbol name: strip a C++ qualifier path (`ns::fn`) and any parameter
/// signature suffix (`fn(args)`), so name matching tolerates both spellings.
fn bare_name(name: &str) -> &str {
    let bare = name.rsplit("::").next().unwrap_or(name);
    bare.split('(').next().unwrap_or(bare).trim()
}

/// A libFuzzer HOOK callback (`LLVMFuzzerInitialize` / `CustomMutator` /
/// `CustomCrossOver`) — harness glue with no fuzzable `(data, size)` body, so it
/// is never a target and is dropped from discovery unconditionally. (Distinct from
/// `LLVMFuzzerTestOneInput`, which CAN be a passthrough target — see
/// [`is_libfuzzer_test_one_input`].)
fn is_libfuzzer_hook(name: &str) -> bool {
    matches!(
        bare_name(name),
        "LLVMFuzzerInitialize" | "LLVMFuzzerCustomMutator" | "LLVMFuzzerCustomCrossOver"
    )
}

/// The libFuzzer fuzz-driver entry point `LLVMFuzzerTestOneInput`. Matched by name
/// (not only by `fuzz/` directory) because it can sit inline in a library file or
/// be govfuzz's own generated output. It is dropped when a real library target
/// coexists, but kept as the PASSTHROUGH target when it is the sole candidate
/// (#408/#410) — so the caller decides, not this predicate.
fn is_libfuzzer_test_one_input(name: &str) -> bool {
    bare_name(name) == "LLVMFuzzerTestOneInput"
}

/// A macro/template-placeholder "function" name — an ALL-UPPERCASE token a
/// `*_template.h` is compiled with after `#define`-ing the real function name
/// (`FUNCNAME`, `QLFC_ADAPTIVE_ENCODE_FUNCTION_NAME`). Real C/C++ functions are
/// lower/mixed-case; an all-caps name is never a callable symbol, so a harness
/// for it always fails to link. The length floor avoids short all-caps tokens.
fn is_macro_placeholder_name(name: &str) -> bool {
    let bare = name.rsplit("::").next().unwrap_or(name);
    let bare = bare.split('(').next().unwrap_or(bare).trim();
    let all_upper = bare.chars().any(|c| c.is_ascii_alphabetic())
        && bare
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .all(|c| c.is_ascii_uppercase());
    // Only an all-caps token that also READS like a placeholder (`FUNC`, `NAME`,
    // `IMPL`, `TEMPLATE`, `GENERIC`) — so a genuine all-caps API (`CRC32`, `MD5`)
    // is kept while `FUNCNAME` / `QLFC_..._FUNCTION_NAME` are dropped.
    all_upper
        && (bare.contains("FUNC")
            || bare.contains("NAME")
            || bare.contains("IMPL")
            || bare.contains("TEMPLATE")
            || bare.contains("GENERIC"))
}

/// Re-rank C/C++ candidates by their position in the in-tree **call graph** — a
/// documentation-independent way to tell real fuzz entry points from internal
/// helpers and example/demo code that the signature scorer alone confuses.
///
/// The insight: a genuine parse/decode entry point (`toml_parse`) is a call-graph
/// SOURCE — almost nothing in the tree calls it (only `main`/tests/the caller do),
/// and it FANS OUT into many internal functions to do the work. An internal helper
/// (`scan_digits`) is a SINK — called by many functions, fanning out into few. And
/// a one-shot demo function (`print_escape_string` in a `*2json` converter) looks
/// parser-shaped by signature but neither fans out into the library nor is reached
/// from one. This is exactly the judgement a human makes choosing what to harness,
/// and it needs no headers/docs — only the code's own structure.
///
/// For each candidate we compute `callers` (distinct in-tree functions that call
/// it) and `fan_out` (distinct in-tree functions it calls), then boost sources
/// that take untrusted input and demote heavily-called sinks. Bodies are sliced
/// from each file's source between successive function start lines (the parser
/// gives starts, not ends) — approximate but robust for call detection.
fn apply_entrypoint_callgraph(candidates: &mut [Candidate]) {
    use std::collections::{BTreeSet, HashMap, HashSet};

    // Gather every C/C++ source file that holds a candidate.
    let files: BTreeSet<std::path::PathBuf> = candidates
        .iter()
        .filter(|c| matches!(c.lang, Lang::C | Lang::Cpp))
        .map(|c| c.source_path.clone())
        .collect();
    if files.is_empty() {
        return;
    }

    // Parse ALL functions (not just candidates) per file so caller/callee counts
    // see the whole tree, and slice each function's body by start lines.
    let mut all_names: HashSet<String> = HashSet::new();
    // (path, name, start_line) -> body text
    let mut bodies: Vec<(std::path::PathBuf, String, u32, String)> = Vec::new();
    for path in &files {
        let lang = candidates
            .iter()
            .find(|c| &c.source_path == path)
            .map(|c| c.lang)
            .unwrap_or(Lang::C);
        let Ok(source) = crate::source_text::read_source_text(path) else {
            continue;
        };
        let mut fns = functions_with_lines(&source, lang);
        if fns.is_empty() {
            continue;
        }
        fns.sort_by_key(|f| f.1);
        let lines: Vec<&str> = source.lines().collect();
        for (i, (name, start)) in fns.iter().enumerate() {
            all_names.insert(name.clone());
            // Bound the body by BRACE MATCHING, not the next detected function: in a
            // big single-header (dr_libs/stb, ~9k lines) the parser detects function
            // starts sparsely, so "start..next_start" can swallow several functions
            // and count THEIR calls as this one's fan-out — wrongly promoting a
            // trivial leaf (drwav_fourcc_equal) to an orchestrator. The next start is
            // still the hard cap (a declaration-only/unmatched body can't run away).
            let cap = fns
                .get(i + 1)
                .map(|n| n.1)
                .unwrap_or(lines.len() as u32 + 1);
            let end = function_body_end(&lines, *start, cap);
            let lo = (*start as usize).saturating_sub(1).min(lines.len());
            let hi = (end as usize).saturating_sub(1).min(lines.len());
            bodies.push((path.clone(), name.clone(), *start, lines[lo..hi].join("\n")));
        }
    }

    // Build the graph: callee name -> set of distinct caller names; and
    // (path,start) -> fan-out (distinct in-tree callees).
    let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
    let mut fan_out: HashMap<(std::path::PathBuf, u32), usize> = HashMap::new();
    for (path, name, start, body) in &bodies {
        let mut callees = 0usize;
        for callee in &all_names {
            if callee == name {
                continue; // ignore self/recursion
            }
            if text_calls(body, callee) {
                callees += 1;
                callers
                    .entry(callee.clone())
                    .or_default()
                    .insert(name.clone());
            }
        }
        fan_out.insert((path.clone(), *start), callees);
    }

    for c in candidates.iter_mut() {
        if !matches!(c.lang, Lang::C | Lang::Cpp) {
            continue;
        }
        let caller_n = callers.get(&c.name).map(HashSet::len).unwrap_or(0) as i32;
        let fan = fan_out
            .get(&(c.source_path.clone(), c.line))
            .copied()
            .unwrap_or(0) as i32;
        let has_input = c
            .input_reachability
            .is_some_and(|r| r.is_attacker_reachable());

        // ORCHESTRATOR / entry point: takes untrusted input and FANS OUT into many
        // in-tree functions to do the parse (`toml_parse` -> scan/parse helpers).
        // Fan-out is the right signal, NOT caller-count: a real entry point is
        // called by main/tests/demos (consumers), so a high caller-count would
        // wrongly look like a heavily-used internal helper. Boost grows with
        // fan-out so the function that drives the whole parse out-ranks the leaves.
        // EXCEPT a function the author marked internal (`*Internal` / `*_internal`,
        // CLI/argv parsers, `main`): a deep internal worker has the highest fan-out
        // of all, so without this it is re-lifted above the public wrapper that
        // delegates to it (tinyobjloader's `ObjReader::ParseFromString` -> `LoadObj`
        // -> `LoadObjInternal`). The wrapper is the intended fuzz entry.
        if has_input && fan >= 3 && !target_rank::c_rank::name_has_helper_marker(&c.name) {
            c.score = c.score.saturating_add((fan - 2).min(12) * 3);
        }
        // LEAF UTILITY: calls nothing in-tree (fan-out 0) yet is itself called —
        // a small helper invoked to do one job (scan a number, read a `\u`
        // escape), not an entry point. Demote so a time-boxed run doesn't spend
        // its budget fuzzing leaf helpers in isolation while the real parser waits.
        if fan == 0 && caller_n >= 1 {
            c.score = c.score.saturating_sub(20);
        }
    }
}

/// All function definitions `(name, start_line)` in `source` for the language —
/// every function, not just ranked candidates, so the call graph is complete.
fn functions_with_lines(source: &str, lang: Lang) -> Vec<(String, u32)> {
    match lang {
        Lang::C => c_parser::parse_c_functions(source)
            .map(|fns| fns.into_iter().map(|f| (f.name, f.line)).collect())
            .unwrap_or_default(),
        Lang::Cpp => cpp_parser::parse_cpp_functions(source)
            .map(|fns| fns.into_iter().map(|f| (f.name, f.line)).collect())
            .unwrap_or_default(),
        Lang::Ada => Vec::new(),
        // Rust call-graph re-ranking is out of scope for M1.1 (the
        // entrypoint-callgraph boost is C/C++-gated); returning the function
        // lines is harmless and consistent with the C/C++ arms.
        Lang::Rust => rust_parser::parse_rust_functions(source)
            .map(|fns| fns.into_iter().map(|f| (f.name, f.line)).collect())
            .unwrap_or_default(),
        // Java call-graph re-ranking is out of scope for M2.1 (the
        // entrypoint-callgraph boost is C/C++-gated); returning the method lines
        // is harmless and consistent with the other non-C/C++ arms.
        Lang::Java => java_parser::parse_java_methods(source)
            .map(|ms| ms.into_iter().map(|m| (m.name, m.line)).collect())
            .unwrap_or_default(),
        // Python call-graph re-ranking is out of scope for M3.1 (the
        // entrypoint-callgraph boost is C/C++-gated); returning the function
        // lines is harmless and consistent with the other non-C/C++ arms.
        Lang::Python => python_parser::parse_python_functions(source)
            .map(|fns| fns.into_iter().map(|f| (f.qualified(), f.line)).collect())
            .unwrap_or_default(),
        // Perl call-graph re-ranking is out of scope (the entrypoint-callgraph boost
        // is C/C++-gated); returning the sub lines is harmless and consistent.
        Lang::Perl => perl_parser::parse_perl_subs(source)
            .map(|subs| subs.into_iter().map(|s| (s.qualified(), s.line)).collect())
            .unwrap_or_default(),
        Lang::Go => go_parser::parse_go_functions(source)
            .map(|fns| fns.into_iter().map(|f| (f.name, f.line)).collect())
            .unwrap_or_default(),
        // COBOL is driven through the C harness (cobc -C); no in-lane call graph.
        Lang::Cobol => Vec::new(),
        // Fortran is driven through the C harness (gfortran); no in-lane call graph.
        Lang::Fortran => Vec::new(),
        // C# call-graph re-ranking is out of scope (the entrypoint-callgraph boost is
        // C/C++-gated); returning the method lines is harmless and consistent.
        Lang::CSharp => crate::auto::csharp::parse_csharp(source)
            .into_iter()
            .map(|m| (m.qualified(), m.line))
            .collect(),
        // JS call-graph re-ranking is out of scope; returning the exported-function
        // lines is harmless and consistent with the other interpreted lanes.
        Lang::Js => crate::auto::js::parse_js(source)
            .into_iter()
            .map(|f| (f.name, f.line))
            .collect(),
    }
}

/// Whether `body` contains a CALL to `name`: the identifier bounded on the left
/// by a non-identifier char and followed (after optional whitespace) by `(`. Cheap
/// textual scan — good enough to distinguish call-graph sources from sinks.
/// The 1-based line just past a function body, found by matching `{`/`}` from the
/// first brace at/after `start`, capped by `cap` (the next detected function start
/// — so a declaration-only or brace-skewed body can never run past it). Line
/// comments are stripped; string/char braces are rare enough to tolerate. This
/// keeps the call graph from merging adjacent functions in a sparse single-header.
fn function_body_end(lines: &[&str], start: u32, cap: u32) -> u32 {
    let lo = (start as usize).saturating_sub(1);
    let hi = (cap as usize).saturating_sub(1).min(lines.len());
    if lo >= hi {
        return cap;
    }
    let mut depth: i32 = 0;
    let mut opened = false;
    for (off, line) in lines[lo..hi].iter().enumerate() {
        let code = line.split("//").next().unwrap_or(line);
        for b in code.bytes() {
            match b {
                b'{' => {
                    depth += 1;
                    opened = true;
                }
                b'}' => depth -= 1,
                _ => {}
            }
        }
        if opened && depth <= 0 {
            return start + off as u32 + 1;
        }
    }
    cap
}

fn text_calls(body: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let b = body.as_bytes();
    let nlen = name.len();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut from = 0usize;
    while let Some(rel) = body.get(from..).and_then(|s| s.find(name)) {
        let p = from + rel;
        let before_ok = p == 0 || !is_ident(b[p - 1]);
        let q = p + nlen;
        let immediate_ok = q >= b.len() || !is_ident(b[q]); // not a longer identifier
        if before_ok && immediate_ok {
            let mut j = q;
            while j < b.len() && (b[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j] == b'(' {
                return true;
            }
        }
        from = p + nlen;
    }
    false
}

/// Walk the tree collecting a `Class::method -> access` map from every C++ class
/// body, for the cross-file visibility filter. Mirrors `walk`'s directory
/// filtering but only reads C++ files; best-effort (read/parse errors are
/// skipped). A method's access is per-class consistent, so first-wins merge.
fn collect_cpp_member_access(
    dir: &Path,
    filter: &DirFilter,
    out: &mut std::collections::BTreeMap<String, String>,
) {
    if dir.is_file() {
        accumulate_cpp_member_access(dir, out);
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if !is_excluded_dir(&path, filter) {
                collect_cpp_member_access(&path, filter, out);
            }
        } else if ft.is_file() {
            accumulate_cpp_member_access(&path, out);
        }
    }
}

fn accumulate_cpp_member_access(path: &Path, out: &mut std::collections::BTreeMap<String, String>) {
    if !has_targetable_extension(path) {
        return;
    }
    let Ok(source) = std::fs::read_to_string(path) else {
        return;
    };
    if !matches!(detect_lang(path, &source), Some(Lang::Cpp)) {
        return;
    }
    for (key, access) in cpp_parser::parse_cpp_method_access(&source) {
        out.entry(key).or_insert(access);
    }
}

fn walk(
    dir: &Path,
    out: &mut Vec<Candidate>,
    filter: &DirFilter,
    preprocess: PreprocessMode,
) -> Result<()> {
    if dir.is_file() {
        return discover_file_guarded(dir, out, preprocess);
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if is_excluded_dir(&path, filter) {
                continue;
            }
            walk(&path, out, filter, preprocess)?;
        } else if ft.is_file() {
            discover_file_guarded(&path, out, preprocess)?;
        }
    }
    Ok(())
}

/// [`discover_file`] wrapped so a govfuzz-internal PANIC while parsing/ranking ONE
/// file is recorded in the bug report and skipped, instead of aborting the whole
/// discovery walk (a single malformed input used to kill the run). A normal parse
/// ERROR still propagates via `?`.
fn discover_file_guarded(
    path: &Path,
    out: &mut Vec<Candidate>,
    preprocess: PreprocessMode,
) -> Result<()> {
    let ctx = crate::auto::bug_report::IssueContext {
        phase: "discovery-parse".to_owned(),
        file: Some(path.display().to_string()),
        ..Default::default()
    };
    match crate::auto::bug_report::catch(ctx, || discover_file(path, out, preprocess)) {
        Ok(inner) => inner,
        Err(_reason) => Ok(()),
    }
}

fn discover_file(path: &Path, out: &mut Vec<Candidate>, preprocess: PreprocessMode) -> Result<()> {
    if !has_targetable_extension(path) {
        return Ok(());
    };
    // Skip test-harness / tool source FILES by name. These live in `src/` or the
    // repo root (NOT in a tests/ dir), so the directory filter misses them, yet
    // their functions — a test runner, a CLI driver — otherwise out-rank the real
    // library entry points (libxml2's `runtest.c` took the entire top 6; pcre2's
    // `pcre2test.c`, snappy's `snappy-test.cc`, aws-lc's `pkcs7_test.cc`, lua's
    // `ltests.c`, libpng's `pngtest.c` all did the same).
    if is_test_or_tool_source_file(path) {
        return Ok(());
    }
    // Latin-1 fallback: legacy Ada/C/C++ is often not UTF-8, and dropping those
    // files would silently hide real fuzzable subprograms from the sweep.
    let source = match crate::source_text::read_source_text(path) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let Some(lang) = detect_lang(path, &source) else {
        return Ok(());
    };
    // M22: tag each candidate with its detected source dialect. Only the lanes
    // whose tree-sitter grammar hides the version signal are detected here
    // (C/C++/Python/Perl); Ada/Rust/Java/Go are left `None` until their phase.
    let dialect = file_dialect(lang, &source);
    // A non-standalone C/C++ fragment header (`*-inl.h`, `*.inc.hpp`, `*.tcc`) is
    // meant to be textually included after its dependencies; a candidate generated
    // from it can only ever produce a harness that includes the fragment alone and
    // fails to build (simdjson, ctre). Don't target functions defined there.
    if matches!(lang, Lang::C | Lang::Cpp) {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if crate::generate_harness::is_partial_impl_header(name) {
                return Ok(());
            }
        }
    }
    match lang {
        Lang::Ada => {
            // A GNAT foreign-platform unit (`unit__win32.adb`) binds OS APIs the
            // host toolchain lacks, and a foreign-arch backend dir needs another
            // ISA — but both are real attack surface on their own target, so they
            // are DISCOVERED and ranked, tagged with the platform so the build
            // cross-compiles + runs them under qemu-user instead of dropping them.
            let foreign_guard =
                foreign_platform_ada_guard(path).or_else(|| foreign_platform_path_guard(path));
            let is_spec_file = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ads"));
            let body_has_sibling_spec = !is_spec_file && path.with_extension("ads").is_file();
            let ast = match ada_parser::reconcile::build_structural_ast(&source, None, path) {
                Ok(a) => a,
                Err(_) => return Ok(()),
            };
            for tgt in target_rank::rank_targets(&ast) {
                let Some(subprogram) = ast.subprograms.iter().find(|s| s.id == tgt.subprogram_id)
                else {
                    continue;
                };
                // Only externally linkable subprograms can be reached by a
                // separately compiled harness that `with`s the package. Body-
                // local helpers, private-part declarations, abstract operations,
                // and subprograms in specs nested inside a body have no exported
                // symbol, so a direct-call harness cannot name them — it just
                // fails the build with "missing Ada symbol". This mirrors the C
                // `is_static` and the C++ free-function internal-linkage gates.
                if !is_externally_callable(subprogram, is_spec_file, body_has_sibling_spec) {
                    continue;
                }
                // A subprogram in a nested package declared in its parent's
                // `private` part (zip-ada `BZip2.CRC`) is not externally
                // callable — `with BZip2` cannot name `BZip2.CRC.X`. Skip it
                // rather than emit a harness that fails with "X is not a visible
                // entity of BZip2".
                if subprogram_in_private_package(&ast, subprogram) {
                    continue;
                }
                // A generic instantiation (`procedure Free is new
                // Ada.Unchecked_Deallocation (...)`) is modelled with no
                // parameters, so a direct harness calls it with the wrong arity;
                // it is also not a fuzz target. Skip it cleanly.
                if subprogram_is_instantiation(&source, subprogram) {
                    continue;
                }
                let line = subprogram.decl_span.start_line;
                // A subprogram of a generic package whose formals can't be given
                // a concrete actual (a formal `type`, `with package`, or `is <>`
                // — libkeccak's `Keccak.Generic_Sponge`) can never be
                // auto-instantiated; it will always `blocked_by_generic` skip.
                // Demote it far below buildable concrete targets so a time-boxed
                // run spends its budget on what can actually fuzz, instead of
                // attempting-and-skipping a wall of un-instantiable generics
                // first. It stays discoverable (a targeted `--target` run still
                // reaches it) — only its priority drops.
                let score = if subprogram_in_unsynthesizable_generic(&ast, subprogram, &source) {
                    tgt.score.saturating_sub(GENERIC_DEMOTION)
                } else {
                    tgt.score
                };
                out.push(Candidate {
                    harness_id: stable_harness_id("H-A", path, line, &tgt.name),
                    lang: Lang::Ada,
                    source_path: path.to_path_buf(),
                    line,
                    name: tgt.name,
                    score,
                    is_static: false,
                    foreign_guard: foreign_guard.clone(),
                    // Ada is ranked by the structural scorer, not the C/C++
                    // byte-buffer shape classifier; no verdict computed here.
                    input_reachability: None,
                    dialect,
                });
            }
        }
        Lang::C => {
            // §27.6: parse the preprocessed text under `preprocess` so a function
            // compiled out by the active config is not discovered, with each
            // surviving function's line translated back to the ORIGINAL source.
            //
            // M22 (+campaign fix): determine the C dialect from the EXTRACTORS
            // themselves, not from the fragile source-text K&R heuristic — which
            // used to false-positive on the portable-C `#if defined(...)` +
            // file-scope `static` idiom and silently drop every function in a
            // modern file. The tolerant K&R extractor is now strict (it requires a
            // real old-style definition whose declaration block declares a
            // parameter), so it is the authority: if it finds K&R definitions the
            // file is K&R (and the extractor gets the param TYPES right from the
            // decl block); otherwise fall back to the modern tree-sitter parser.
            // This never misclassifies modern C as K&R, and never drops a modern
            // file because of a K&R false positive.
            let knr = c_parser::parse_knr_functions(&source);
            let (fns, dialect) = if !knr.is_empty() {
                (knr, Some(lang_profile::Dialect::CKAndR))
            } else {
                let Ok(modern) = parse_c_functions_preprocessed(&source, preprocess) else {
                    return Ok(());
                };
                (modern, Some(lang_profile::Dialect::C99))
            };
            let fns = dedup_c_functions(fns);
            let meta: HashMap<(&str, u32), &c_parser::CFunction> =
                fns.iter().map(|f| ((f.name.as_str(), f.line), f)).collect();
            for tgt in target_rank::rank_c_targets(&fns) {
                let (is_static, foreign_guard) = {
                    let m = meta.get(&(tgt.name.as_str(), tgt.line));
                    (
                        m.is_some_and(|f| f.is_static),
                        m.and_then(|f| f.foreign_guard.clone())
                            .or_else(|| foreign_platform_path_guard(path)),
                    )
                };
                out.push(Candidate {
                    harness_id: stable_harness_id("H-C", path, tgt.line, &tgt.name),
                    lang: Lang::C,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static,
                    foreign_guard,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Cpp => {
            // §27.6: parse the preprocessed text under `preprocess`, translating
            // each surviving function's line back to the ORIGINAL source.
            let Ok(fns) = parse_cpp_functions_preprocessed(&source, preprocess) else {
                return Ok(());
            };
            let fns = dedup_cpp_functions(fns);
            let meta: HashMap<(&str, u32), &cpp_parser::CppFunction> =
                fns.iter().map(|f| ((f.name.as_str(), f.line), f)).collect();
            for tgt in target_rank::rank_cpp_targets(&fns) {
                let (is_static, foreign_guard) = {
                    let m = meta.get(&(tgt.name.as_str(), tgt.line));
                    (
                        // Static *member* functions are linkable; only
                        // static free functions have internal linkage.
                        m.is_some_and(|f| f.is_static && !f.api.is_method),
                        m.and_then(|f| f.foreign_guard.clone())
                            .or_else(|| foreign_platform_path_guard(path))
                            .or_else(|| cpp_windows_framework_guard(&source)),
                    )
                };
                out.push(Candidate {
                    harness_id: stable_harness_id("H-X", path, tgt.line, &tgt.name),
                    lang: Lang::Cpp,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static,
                    foreign_guard,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Rust => {
            // M1.1: discover + rank Rust targets. The ranker drops private fns
            // and carries `is_static` / `foreign_guard` / reachability through,
            // so the discovery arm is a thin map (no re-parse). The attempt loop
            // pre-skips these cleanly until the harness/build/engine lane (M1.2).
            let Ok(fns) = rust_parser::parse_rust_functions(&source) else {
                return Ok(());
            };
            for tgt in target_rank::rank_rust_targets(&fns) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-R", path, tgt.line, &tgt.name),
                    lang: Lang::Rust,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static: tgt.is_static,
                    foreign_guard: tgt.foreign_guard,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Java => {
            // M2.1: discover + rank Java targets. The ranker drops non-public and
            // abstract methods, prefers security sinks + byte channels, and carries
            // `is_static`/reachability through so the discovery arm is a thin map.
            // The attempt loop pre-skips these cleanly until the build/agent/engine
            // lane (M2.1b-d) lands. Java has no `#[cfg]`-style guard -> None.
            let Ok(methods) = java_parser::parse_java_methods(&source) else {
                return Ok(());
            };
            for tgt in target_rank::rank_java_targets(&methods) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-J", path, tgt.line, &tgt.name),
                    lang: Lang::Java,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static: tgt.is_static,
                    foreign_guard: None,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Python => {
            // M3.1: discover + rank Python targets. The ranker drops private/dunder/
            // property functions, prefers byte/str channels + parse/decode names, and
            // carries `is_static` (callable without a receiver) + reachability through.
            // Python has no `#[cfg]`-style platform guard -> None.
            // M22: a Python 2 file fails the py3 grammar, so its functions are never
            // discovered. Use the tolerant line-based extractor for a detected
            // Python 2 dialect so legacy targets are still ranked + reported on
            // (report-only when no python2 interpreter, per the attempt loop).
            let functions = if dialect == Some(lang_profile::Dialect::Python2) {
                python_parser::parse_python2_functions(&source)
            } else {
                match python_parser::parse_python_functions(&source) {
                    Ok(f) => f,
                    Err(_) => return Ok(()),
                }
            };
            for tgt in target_rank::rank_python_targets(&functions) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-P", path, tgt.line, &tgt.name),
                    lang: Lang::Python,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static: tgt.is_static,
                    foreign_guard: None,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Perl => {
            // M3.2: discover + rank Perl subs. The ranker drops private/special subs,
            // prefers parse/decode names, and carries is_static (function vs OO method)
            // + reachability. Perl has no platform guard -> None.
            let Ok(subs) = perl_parser::parse_perl_subs(&source) else {
                return Ok(());
            };
            for tgt in target_rank::rank_perl_targets(&subs) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-L", path, tgt.line, &tgt.name),
                    lang: Lang::Perl,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static: tgt.is_static,
                    foreign_guard: None,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Go => {
            // M3.3: discover + rank Go funcs. `_test.go` files are the project's OWN
            // tests, not the API under test — skip them. The ranker drops unexported
            // funcs and prefers []byte/string parsers; carries is_static (free fn vs
            // method) + reachability. Go has no platform guard here -> None.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("_test.go"))
            {
                return Ok(());
            }
            let Ok(functions) = go_parser::parse_go_functions(&source) else {
                return Ok(());
            };
            for tgt in target_rank::rank_go_targets(&functions) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-G", path, tgt.line, &tgt.name),
                    lang: Lang::Go,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: tgt.score,
                    is_static: tgt.is_static,
                    foreign_guard: None,
                    input_reachability: Some(tgt.input_reachability),
                    dialect,
                });
            }
        }
        Lang::Cobol => {
            // M3.4: each COBOL PROGRAM-ID with a fuzzable LINKAGE `PIC X(N)` buffer
            // (driven via `PROCEDURE DIVISION USING`) is a candidate. It is fuzzed by
            // translating to C (`cobc -C`) and driving the entry from the fuzz bytes on
            // the C harness path — see `crate::auto::cobol` / `cobol_build`. The LINKAGE
            // buffer is the attacker-controlled input channel, so it is attacker-reachable.
            for prog in crate::auto::cobol::parse_cobol(&source) {
                if !prog.is_fuzzable() {
                    continue;
                }
                out.push(Candidate {
                    harness_id: stable_harness_id("H-B", path, prog.line, &prog.program_id),
                    lang: Lang::Cobol,
                    source_path: path.to_path_buf(),
                    line: prog.line,
                    name: prog.program_id,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
        Lang::Fortran => {
            // M3.5: each Fortran subroutine/function with a fuzzable `character`
            // argument is a candidate, driven via a gfortran C-ABI harness (see
            // `crate::auto::fortran` / `fortran_build`). The character buffer is the
            // attacker-controlled input channel.
            for proc in crate::auto::fortran::parse_fortran(&source) {
                if !proc.is_fuzzable() {
                    continue;
                }
                out.push(Candidate {
                    harness_id: stable_harness_id("H-F", path, proc.line, &proc.name),
                    lang: Lang::Fortran,
                    source_path: path.to_path_buf(),
                    line: proc.line,
                    name: proc.name,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
        Lang::CSharp => {
            // M3.6: each public method taking a byte[]/string/Stream is a candidate,
            // built + IL-instrumented (dotnet build + sharpfuzz) and driven over the
            // framed protocol (see `crate::auto::csharp` / `csharp_build`). The input
            // parameter is the attacker-controlled channel.
            for method in crate::auto::csharp::parse_csharp(&source) {
                if !method.is_fuzzable() {
                    continue;
                }
                let name = method.qualified();
                out.push(Candidate {
                    harness_id: stable_harness_id("H-S", path, method.line, &name),
                    lang: Lang::CSharp,
                    source_path: path.to_path_buf(),
                    line: method.line,
                    name,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
        Lang::Js => {
            // M3.7: each exported JS function taking ≥1 argument is a candidate,
            // driven via the Node framed driver (see `crate::auto::js` / `js_build`).
            // The first argument is the attacker-controlled input channel.
            for func in crate::auto::js::parse_js(&source) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-N", path, func.line, &func.name),
                    lang: Lang::Js,
                    source_path: path.to_path_buf(),
                    line: func.line,
                    name: func.name,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
    }
    Ok(())
}

fn c_signature(f: &c_parser::CFunction) -> String {
    let params: Vec<&str> = f.params.iter().map(|p| p.c_type.as_str()).collect();
    format!("{} ({})", f.return_type, params.join(", "))
}

/// Mutually-exclusive #ifdef ladders define the same function N
/// times with the same signature; at link time only one exists.
/// True when `path` lives in an AMALGAMATED single-header tree — a byte-identical
/// concatenation of a library's modular sources (nlohmann/json's
/// `single_include/nlohmann/json.hpp`, common `amalgamation`/`amalgamated` dirs).
/// Candidates from here duplicate the modular tree's functions, so [`discover`]
/// drops them when a modular twin exists (#28).
fn is_amalgamated_single_header_path(path: &Path) -> bool {
    path.components().any(|component| {
        let segment = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            segment.as_str(),
            "single_include" | "single-include" | "amalgamated" | "amalgamation"
        )
    })
}

/// Cross-tree dedup (#28): a project that ships BOTH a modular source tree and an
/// amalgamated single-header (nlohmann/json) surfaces every function twice — the
/// per-file dedup can't see the cross-file duplication, so `--max-targets` fuzzes
/// only a handful of distinct functions, each twice. Drop a candidate that lives in
/// an amalgamated single-header when an identical `(lang, name)` candidate exists
/// OUTSIDE it (the modular copy, which is preferred). A function that exists ONLY in
/// the single-header is kept.
fn dedup_amalgamated_single_header(out: &mut Vec<Candidate>) {
    let modular: std::collections::HashSet<(Lang, String)> = out
        .iter()
        .filter(|c| !is_amalgamated_single_header_path(&c.source_path))
        .map(|c| (c.lang, c.name.clone()))
        .collect();
    if modular.is_empty() {
        return;
    }
    out.retain(|c| {
        !(is_amalgamated_single_header_path(&c.source_path)
            && modular.contains(&(c.lang, c.name.clone())))
    });
}

/// Keep the first (lowest line) so the sweep attempts it once.
fn dedup_c_functions(fns: Vec<c_parser::CFunction>) -> Vec<c_parser::CFunction> {
    let mut seen = std::collections::HashSet::new();
    fns.into_iter()
        .filter(|f| seen.insert((f.name.clone(), c_signature(f))))
        .collect()
}

fn cpp_signature(f: &cpp_parser::CppFunction) -> String {
    let params: Vec<&str> = f.params.iter().map(|p| p.cpp_type.as_str()).collect();
    format!(
        "{} {}::{} ({})",
        f.return_type,
        f.qualifier_path.join("::"),
        f.name,
        params.join(", ")
    )
}

/// C++ overloads have differing parameter lists and survive this
/// filter; only byte-identical signature duplicates (#ifdef ladders)
/// collapse.
fn dedup_cpp_functions(fns: Vec<cpp_parser::CppFunction>) -> Vec<cpp_parser::CppFunction> {
    let mut seen = std::collections::HashSet::new();
    fns.into_iter()
        .filter(|f| seen.insert(cpp_signature(f)))
        .collect()
}

fn has_targetable_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            if ext == "C" {
                return true;
            }
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "ads"
                    | "adb"
                    | "c"
                    | "h"
                    | "cpp"
                    | "cc"
                    | "cxx"
                    | "hpp"
                    | "hh"
                    | "hxx"
                    | "rs"
                    | "java"
                    | "py"
                    | "pl"
                    | "pm"
                    | "go"
                    | "cob"
                    | "cbl"
                    | "cobol"
                    | "cble"
                    | "f90"
                    | "f95"
                    | "f03"
                    | "f08"
                    | "f"
                    | "for"
                    | "f77"
                    | "cs"
                    | "js"
                    | "mjs"
                    | "cjs"
            )
        })
}

/// M22: detect the source dialect of a file for the lanes whose tree-sitter
/// grammar hides the version signal (C/C++/Python/Perl). Ada/Rust/Java/Go return
/// `None` until their phase wires dialect detection (Ada 83 is Phase 4; Rust
/// edition and Go version flow from project metadata, not source text).
fn file_dialect(lang: Lang, source: &str) -> Option<lang_profile::Dialect> {
    match lang {
        Lang::C => Some(lang_profile::detect_c(source)),
        Lang::Cpp => Some(lang_profile::detect_cpp(source)),
        Lang::Python => Some(lang_profile::detect_python(source)),
        Lang::Perl => Some(lang_profile::detect_perl(source)),
        // M22: only an explicit `pragma Ada_83` is flagged (-> report-only); other
        // Ada standards are left to the Ada lane's own pragma/feature detection.
        Lang::Ada => lang_profile::detect_ada(source),
        Lang::Rust
        | Lang::Java
        | Lang::Go
        | Lang::Cobol
        | Lang::Fortran
        | Lang::CSharp
        | Lang::Js => None,
    }
}

fn detect_lang(path: &Path, source: &str) -> Option<Lang> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    if ext == "C" {
        return Some(Lang::Cpp);
    }
    match ext.to_ascii_lowercase().as_str() {
        "ads" | "adb" => Some(Lang::Ada),
        "c" => Some(Lang::C),
        "h" => Some(classify_c_header(source)),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some(Lang::Cpp),
        "rs" => Some(Lang::Rust),
        "java" => Some(Lang::Java),
        "py" => Some(Lang::Python),
        "pl" | "pm" => Some(Lang::Perl),
        "go" => Some(Lang::Go),
        "cob" | "cbl" | "cobol" | "cble" => Some(Lang::Cobol),
        "f90" | "f95" | "f03" | "f08" | "f" | "for" | "f77" => Some(Lang::Fortran),
        "cs" => Some(Lang::CSharp),
        "js" | "mjs" | "cjs" => Some(Lang::Js),
        _ => None,
    }
}

fn classify_c_header(source: &str) -> Lang {
    let c_count = c_parser::parse_c_functions(source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    let cpp_count = cpp_parser::parse_cpp_functions(source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    if cpp_count > c_count || header_looks_like_cpp(source) {
        Lang::Cpp
    } else {
        Lang::C
    }
}

/// Strip C/C++ comments and string/char literals from `source`, replacing each with
/// a single space. The header-classification marker scan ([`header_looks_like_cpp`])
/// must look only at real code tokens: a pure-C header like yyjson.h mentions
/// `operator` 26x and `class`/`template`/`namespace` in DOC COMMENTS, which a raw
/// substring scan misreads as C++ (#42). Operates per-byte (markers are ASCII); a
/// non-ASCII byte maps to a lone char that can never form an ASCII marker.
fn strip_c_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            out.push(' ');
            continue;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1; // closing quote (clamped by the loop guard below)
            out.push(' ');
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// True when `needle` occurs in `haystack` at a LEADING word boundary (start of
/// string or preceded by a non-identifier byte), so an identifier such as
/// `my_namespace`/`noexcept_helper` doesn't trip a keyword marker.
fn contains_token(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let before_ok = abs == 0 || {
            let b = bytes[abs - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        if before_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// True when `keyword` appears as a whole token immediately followed by whitespace
/// then an identifier start — `class Foo` / `enum class Color`, never a C field or
/// variable named `class` (`int class;`).
fn token_followed_by_identifier(code: &str, keyword: &str) -> bool {
    let bytes = code.as_bytes();
    let mut start = 0;
    while let Some(pos) = code[start..].find(keyword) {
        let abs = start + pos;
        let before_ok = abs == 0 || {
            let b = bytes[abs - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        let mut j = abs + keyword.len();
        if before_ok && j < bytes.len() && bytes[j].is_ascii_whitespace() {
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
                return true;
            }
        }
        start = abs + 1;
    }
    false
}

/// True when `code` contains a real C++ `operator` overload — the `operator` token
/// followed (after optional spaces) by an operator-punctuation char, `(`/`[`, or
/// `new`/`delete`. A C identifier like `operator_count`/`use_operator` is excluded
/// (no leading boundary or no operator symbol follows).
fn contains_operator_overload(code: &str) -> bool {
    let bytes = code.as_bytes();
    let mut start = 0;
    while let Some(pos) = code[start..].find("operator") {
        let abs = start + pos;
        let before_ok = abs == 0 || {
            let b = bytes[abs - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        if before_ok {
            let mut j = abs + "operator".len();
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() {
                if matches!(
                    bytes[j],
                    b'+' | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'^'
                        | b'&'
                        | b'|'
                        | b'~'
                        | b'!'
                        | b'='
                        | b'<'
                        | b'>'
                        | b'('
                        | b'['
                ) {
                    return true;
                }
                if code[j..].starts_with("new") || code[j..].starts_with("delete") {
                    return true;
                }
            }
        }
        start = abs + 1;
    }
    false
}

fn header_looks_like_cpp(source: &str) -> bool {
    // #42: scan only real code — comments/string literals are stripped so a
    // pure-C header (yyjson.h) that mentions C++ words in prose is not misread.
    let code = strip_c_comments_and_strings(source);
    // C++-only keyword markers, each required at a leading word boundary.
    const WORD_MARKERS: &[&str] = &[
        "namespace ",
        "template <",
        "template<",
        "typename ",
        "public:",
        "private:",
        "protected:",
        "constexpr",
        "noexcept",
    ];
    WORD_MARKERS.iter().any(|m| contains_token(&code, m))
        || token_followed_by_identifier(&code, "class")
        || contains_operator_overload(&code)
}

/// Whether `path` is a direct or transitive child of a Maven/Gradle Java or
/// Kotlin source root — i.e. whether any three consecutive path components are
/// `src` / `main` / `java` (or `kotlin`), appearing BEFORE the final component.
///
/// This matters because Java directory names ARE package-name components:
/// `tools.jackson.core` maps to `tools/jackson/core/`. Organizational heuristics
/// that make sense for C/C++ (`tools/` = CLI tools, `vendor/` = bundled deps) are
/// not valid inside a Java package tree and must not be applied there.
///
/// `src/test/java` is NOT matched (the second component must be `main`), so test
/// code stays excluded via the `test`/`tests` directory filter applied above this
/// point in the walk.
fn is_under_java_source_root(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let n = comps.len();
    // Need at least src/main/java/<something> — 4 components minimum.
    if n < 4 {
        return false;
    }
    // Slide a window of 3 over all but the last component (the last component is
    // the directory being evaluated; we are looking at its ANCESTORS).
    comps[..n - 1].windows(3).any(|w| {
        w[0].eq_ignore_ascii_case("src")
            && w[1].eq_ignore_ascii_case("main")
            && (w[2].eq_ignore_ascii_case("java") || w[2].eq_ignore_ascii_case("kotlin"))
    })
}

/// Whether `path` lies inside a conventional C/C++ header-API root — any ANCESTOR
/// directory component (case-insensitive) named `include` or `inc`. Headers under
/// such a root are the project's PUBLIC library API, and a child directory there
/// is a namespace/module name (CLI11's `include/CLI/`, fmt's `include/fmt/`), NOT
/// a "cli tools" / "app" / "bin" organizational directory. The default
/// organizational-name exclusions assume a C/C++ tool/driver layout where those
/// names mean non-library code, so they must be suppressed inside a header-API
/// root exactly as they are inside a Java source root — otherwise a library whose
/// namespace dir collides with a tool-class token (`cli`, `app`, `tool`, `bin`, …)
/// is silently dropped (CLI11's `include/CLI/` matched `cli` and discovered 0
/// targets from the tree root before this fix).
///
/// Only ANCESTORS are matched (`path.components()` minus the last component), so
/// the `include`/`inc` directory itself is not "under" a header root — it isn't an
/// organizational-exclusion name anyway, so nothing changes for it.
fn is_under_header_api_root(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let n = comps.len();
    // Need at least <root>/<dir> — the directory must have at least one ancestor.
    if n < 2 {
        return false;
    }
    comps[..n - 1]
        .iter()
        .any(|c| c.eq_ignore_ascii_case("include") || c.eq_ignore_ascii_case("inc"))
}

fn is_excluded_dir(path: &Path, filter: &DirFilter) -> bool {
    // The run's own work directory, even when custom-named and nested in the tree.
    if filter.is_work_dir(path) {
        return true;
    }
    let name = path.file_name().and_then(|n| n.to_str());
    if matches!(
        name,
        // `.govfuzz-build` = build_probe::PROBE_DIR (the --probe-build output:
        // a compile DB plus CMake's own compiler-id test files, not targets).
        // Build/VCS output: never a target, NOT overridable by the DirFilter.
        Some(
            "generated_harnesses"
                | "harnesses"
                | "govfuzz_work"
                | "target"
                | "build"
                | ".govfuzz-build"
                | "node_modules"
                | ".git"
        )
    ) {
        return true;
    }
    // Organizational-name exclusions (`tools/`, `vendor/`, `examples/`, `bench*`,
    // …) are heuristics designed for C/C++ project layouts where those names
    // reliably indicate non-library code. In Java/Kotlin they are meaningless: a
    // directory named `tools` under `src/main/java/` is the `tools` component of a
    // package name (e.g. `tools.jackson.core`) — not a CLI-tools directory.
    // Applying the heuristic there would exclude the entire library (jackson-core
    // 3.x discovers 0 targets without this fix). Inside a Maven/Gradle source root
    // (`src/main/java`, `src/main/kotlin`) suppress the default organizational
    // exclusions; only user-supplied `--exclude-dir` entries still apply.
    // Test-dir exclusion is moot here: `src/test/java` is excluded at the `test`
    // component level before we ever descend into it.
    if is_under_java_source_root(path) {
        return name.is_some_and(|n| filter.skips_in_java_root(n));
    }
    // C/C++ public header API (`include/<Name>/`, `inc/<Name>/`): the child
    // directory is a library namespace/module (CLI11's `include/CLI/`, fmt's
    // `include/fmt/`), not an organizational `cli`/`app`/`tools` directory. The
    // default name heuristics assume a tool/driver layout and would drop the whole
    // API whenever its namespace dir collides with a tool-class token — CLI11's
    // `include/CLI/` matched `cli` and discovered 0 targets from the tree root.
    // Inside a header-API root, apply only user `--exclude-dir` entries. The hard
    // build/VCS exclusions above (`.git`, `build`, `target`, …) already returned
    // for this path, so a stray `build/` or `.git/` under `include/` stays excluded.
    if is_under_header_api_root(path) {
        return name.is_some_and(|n| filter.skips_in_header_root(n));
    }
    // Non-library code that is never the project's OWN attack surface: tests and
    // the test frameworks they bundle (cjson's Unity), examples/demos, benchmarks,
    // bundled third-party/vendored deps, docs. A Unity assertion runner, an
    // example's stdin reader, or a vendored parser otherwise out-ranks the real
    // library entry points (cjson, zlib, dr_libs all had test/example code on top).
    // `fuzz`/`fuzzing` dirs hold harness driver glue (`LLVMFuzzerTestOneInput`),
    // not library code, so they are excluded too (`--include-dir fuzz` restores
    // them). The default set is configurable per run via the DirFilter
    // (--exclude-dir / --include-dir).
    if name.is_some_and(|n| filter.skips(n)) {
        return true;
    }
    // A foreign-CPU-arch SIMD backend dir (`src/arm64` on x86) is NOT excluded —
    // it is real attack surface on its own ISA, discovered + ranked and tagged
    // (see `foreign_platform_path_guard`) so the build cross-compiles + runs it
    // under qemu-user rather than dropping it.
    false
}

/// A directory whose contents are not the project's own fuzzable library code:
/// tests, examples/demos, benchmarks, bundled/vendored third-party deps, docs.
/// Matched case-insensitively on the exact path component so a legitimate module
/// (`latest`, `attestation`) is never swept up by a substring. This is the
/// built-in default set; [`DirFilter`] lets a run add to or subtract from it.
fn is_default_non_library_dir(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // Any directory whose name CONTAINS "test" is test code, even when glued into
    // a longer name (`jsontestrunner`, `test_lib_json`, `integration_tests`) that
    // an exact-match list misses. Guard the rare words that merely contain the
    // substring (`attestation`, `latest`, `contest`).
    if n.contains("test")
        && !n.contains("attest")
        && !matches!(
            n.as_str(),
            "latest" | "fastest" | "greatest" | "contest" | "protest"
        )
    {
        return true;
    }
    // Likewise any directory whose name CONTAINS "fuzz" (`bdshemu_fuzz`,
    // `fuzz_targets`, `libfuzzer`) is harness/driver code — "fuzz" has no benign
    // substring collision worth guarding (only `fuzzy`, itself fuzzing-adjacent).
    if n.contains("fuzz") {
        return true;
    }
    matches!(
        n.as_str(),
        // The Perl/CPAN `t/` convention: a one-letter directory of `*_t.c` files
        // that link against a TAP framework (libtap `plan`/`ok`/`cmp_ok`/
        // `done_testing`). C projects adopt it too (libmaxminddb), where those
        // entry points out-rank the real API and then fail to link on the missing
        // test-framework symbols. `--include-dir t` restores it.
        "t"
            | "test"
            | "tests"
            | "testing"
            | "testsuite"
            | "test-suite"
            | "unittest"
            | "unittests"
            | "gtest"
            | "googletest"
            | "example"
            | "examples"
            | "sample"
            | "samples"
            | "demo"
            | "demos"
            | "benchmark"
            | "benchmarks"
            | "bench"
            // Cargo's standard benchmark directory is the PLURAL `benches/`
            // (smallvec, most Rust crates) — criterion/bench harnesses, not the
            // library under test. `--include-dir benches` restores it.
            | "benches"
            // Fuzz-harness dirs hold driver glue (libFuzzer/AFL `LLVMFuzzerTestOneInput`
            // entry points, OSS-Fuzz build scripts), not the library under test — the
            // same category as tests/examples. `--include-dir fuzz` restores them.
            | "fuzz"
            | "fuzzing"
            | "fuzzer"
            | "fuzzers"
            | "ossfuzz"
            | "oss-fuzz"
            // Command-line tools / example programs / regression drivers — not the
            // library under test. Their `main`/CLI code otherwise out-ranks the real
            // entry points (aws's `wsdl2aws.main` #1, s2n's `bin/`, mbedtls's
            // `programs/`, harfbuzz's `util/`, brotli's `research/`, libzip's
            // `regress/`, wuffs's `snippet/`+`script/`, pcre2/zydis `tools/`).
            | "tool"
            | "tools"
            // Developer-tooling dirs (libde265 `dev-tools/` rd-curves, build/CI
            // helpers) — auxiliary code, not the library under test.
            | "dev-tools"
            | "devtools"
            | "dev_tools"
            | "program"
            | "programs"
            | "bin"
            | "cli"
            | "app"
            | "apps"
            | "regress"
            | "research"
            // Exploratory / non-stable alternative implementations the author has
            // fenced off from the shipping API (tinyobjloader's `experimental/`
            // stream + opt loaders, whose `parseObj`/`parseLine`/`LoadMtl` otherwise
            // out-rank the stable `ObjReader::ParseFromString`). Same category as
            // `research`; `--include-dir experimental` restores them.
            | "experimental"
            | "experiments"
            | "playground"
            | "sandbox"
            | "perf"
            | "script"
            | "scripts"
            | "snippet"
            | "snippets"
            | "contrib"
            | "third_party"
            | "thirdparty"
            | "third-party"
            | "3rdparty"
            | "3rd_party"
            | "vendor"
            | "vendored"
            | "extern"
            | "external"
            | "deps"
            | "dependencies"
            | "subprojects"
            | "doc"
            | "docs"
            | "documentation"
    )
}

/// A source FILE whose name marks it as a test harness or CLI/example tool rather
/// than library code — `runtest.c`, `pcre2test.c`, `xmltest.cpp`, `pngtest.c`,
/// `snappy-test.cc`, `ltests.c`, `pkcs7_test.cc`, `test_foo.c`. These sit in
/// `src/` or the repo root (outside any tests/ dir), so the directory filter
/// misses them, yet their functions (a test runner, a CLI driver) out-rank the
/// real library entry points. Matched on the file stem so the comparison is
/// independent of `.c`/`.cc`/`.cpp`/`.cxx` extension.
fn is_test_or_tool_source_file(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let s = stem.to_ascii_lowercase();
    // The "greatest" single-header C test framework (silentbicycle/greatest) is
    // header-only test scaffolding, not a library API: a `greatest.h` defines
    // `greatest_do_pass`/`greatest_usage`/runner macros that out-rank real
    // entry points and only ever fail to build alone (heatshrink ships it). It is
    // ALWAYS `greatest.h`; the canonical `.h` filename distinguishes the framework
    // from the English word "greatest" (a `greatest.c` source stays protected by
    // NOT_TEST below). Checked BEFORE NOT_TEST so the word-exception can't shield
    // the framework header.
    if s == "greatest"
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("h"))
    {
        return true;
    }
    // Common English words that merely END in "test" but are not test files.
    const NOT_TEST: &[&str] = &[
        "latest", "fastest", "greatest", "contest", "protest", "attest", "detest",
    ];
    if NOT_TEST.contains(&s.as_str()) {
        return false;
    }
    // Example/demo/benchmark FILES sitting next to library code (libpng's
    // `example.c`) — matched as exact stems so a real `sampler.c`/`demodulator.c`
    // is not swept up by a prefix.
    if matches!(
        s.as_str(),
        "example"
            | "examples"
            | "sample"
            | "samples"
            | "demo"
            | "demos"
            | "benchmark"
            | "benchmarks"
    ) {
        return true;
    }
    s.starts_with("test")        // test_foo, test-bar, testrunner, testcommon
        || s.ends_with("test")   // runtest, pcre2test, xmltest, pngtest, snappy-test, foo_test
        || s.ends_with("tests")  // ltests, runtests
        || s.contains("_test_")  // foo_test_helpers
        || s.contains("-test-")
}

/// A non-host CPU-architecture / SIMD-ISA backend source dir (simdjson `src/arm64`,
/// `src/ppc64`, `src/riscv`). Its intrinsics cannot compile on the host, so
/// discovery skips it instead of generating harnesses that always fail to build.
/// Host-architecture dirs (`src/x86_64`) and generic/portable dirs are KEPT — the
/// per-`-march` flag concern for same-arch SIMD is a build-flag matter, not here.
/// A GNAT platform-suffixed Ada source for a NON-host platform
/// (`gnatcoll-mmap-system__win32.ads`, `..__windows.adb`): its bodies bind OS
/// APIs absent on this host, so the host toolchain can't build it natively.
/// Returns the platform tag (`win32`, `darwin`, …) so the candidate is still
/// DISCOVERED and ranked — it is real attack surface on its own platform — and
/// carried as a `foreign_guard` the build resolves by cross-compiling for that
/// target (and running under qemu-user) rather than being hidden. `__` never
/// appears in a legal Ada identifier, so the suffix is unambiguous.
fn foreign_platform_ada_guard(path: &Path) -> Option<String> {
    let stem = path.file_stem().and_then(|s| s.to_str())?;
    let (_, suffix) = stem.rsplit_once("__")?;
    let suffix = suffix.to_ascii_lowercase();
    let foreign = if cfg!(windows) {
        matches!(
            suffix.as_str(),
            "unix" | "linux" | "posix" | "darwin" | "osx" | "macos"
        )
    } else {
        matches!(
            suffix.as_str(),
            "win32" | "win64" | "windows" | "win" | "nt" | "darwin" | "osx" | "macos" | "vxworks"
        )
    };
    foreign.then_some(suffix)
}

/// A foreign-CPU-architecture SIMD backend dir on this host (simdjson `src/arm64`
/// on x86, a `neon`/`altivec` backend). Like the Ada platform unit, this is real
/// attack surface on its own target, so it is DISCOVERED and ranked, then carried
/// as a `foreign_guard` so the build cross-compiles + runs it under qemu-user
/// rather than dropping it. Returns the foreign-arch path component, if any.
fn foreign_platform_path_guard(path: &Path) -> Option<String> {
    path.components().find_map(|comp| {
        let c = comp.as_os_str().to_str()?;
        is_foreign_arch_backend_dir(c).then(|| c.to_ascii_lowercase())
    })
}

/// A C++ source that `#include`s an unambiguously Windows-only framework header —
/// MFC (`afxwin.h`/`afx.h`/`afx*.h`) or ATL (`atlbase.h`/`atlstr.h`/…) — is
/// Windows-only with no portable build path, UNLIKE a bare `<windows.h>` which is
/// routinely `#ifdef _WIN32`-guarded in cross-platform code (so we deliberately do
/// NOT trigger on `windows.h`). Tag it with a `win32` foreign_guard so the attempt
/// loop routes it to the Windows strategy: a mingw+wine cross-build, or a native
/// fake-`windows.h` stub that resolves the Win32 scalar surface (`BOOL`/`DWORD`/…)
/// so those params/types are no longer "unsupported". The MFC *class* library
/// (`CString`/`CWnd`/`CDataExchange`) still isn't buildable offline, so a pure-MFC
/// target then degrades to report-only — but pure Win32 logic + the scalar
/// typedefs now type-check instead of failing the whole file natively.
fn cpp_windows_framework_guard(source: &str) -> Option<String> {
    fn is_mfc_atl_header(basename: &str) -> bool {
        let h = basename.trim().to_ascii_lowercase();
        (h.starts_with("afx") && h.ends_with(".h"))
            || matches!(
                h.as_str(),
                "atlbase.h" | "atlwin.h" | "atlcom.h" | "atlstr.h" | "atltypes.h"
            )
    }
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix('#') else {
            continue;
        };
        let Some(after) = rest.trim_start().strip_prefix("include") else {
            continue;
        };
        let after = after.trim_start();
        let header = after
            .strip_prefix('<')
            .and_then(|s| s.split('>').next())
            .or_else(|| after.strip_prefix('"').and_then(|s| s.split('"').next()));
        if let Some(header) = header {
            let base = header.rsplit(['/', '\\']).next().unwrap_or(header);
            if is_mfc_atl_header(base) {
                return Some("win32 (MFC/ATL framework header)".to_owned());
            }
        }
    }
    None
}

/// Parse every `.gpr` project file under `root` and return the set of Ada source
/// FILES declared as a project Main (`for Main use ("a.adb", ...)`), each mapped
/// to the file name of the `.gpr` that declared it (carried into the skip reason).
///
/// A unit listed as a project Main is a program ENTRY POINT — it `with`s the
/// library and runs as an executable — not a library subprogram a separately
/// compiled harness can name. A direct-call harness for it emits
/// `with Unit; ... Unit;`, which GNAT rejects ("procedure or entry name
/// expected"). The attempt loop uses this map to pre-skip such candidates with a
/// precise reason (`Outcome::UnsupportedParams`) instead of burning a build that
/// always fails — so a Main shows as `skipped`, never `failed_build`.
///
/// CONSERVATIVE + PRECISE by design: each Main entry is resolved to a real source
/// file via the gpr's `Source_Dirs` (and the gpr's own directory), and ONLY the
/// exact resolved file is recorded — never every file in a directory. A
/// subprogram is matched by the SPECIFIC source file the gpr named, so the same
/// subprogram that is a normal library unit elsewhere is unaffected. If no `.gpr`
/// is found, or none names a Main that resolves to a real file, the map is empty
/// and nothing is skipped. Keys are canonicalized absolute paths so they match a
/// candidate's canonicalized `source_path`.
pub(crate) fn gpr_main_sources(
    root: &Path,
    filter: &DirFilter,
) -> std::collections::HashMap<std::path::PathBuf, String> {
    let mut gprs = Vec::new();
    collect_gpr_files(root, filter, &mut gprs);
    let mut out = std::collections::HashMap::new();
    for gpr in gprs {
        let Ok(text) = std::fs::read_to_string(&gpr) else {
            continue;
        };
        let mains = gpr_attribute_string_list(&text, "main");
        if mains.is_empty() {
            continue;
        }
        let gpr_name = gpr
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project.gpr")
            .to_owned();
        let gpr_dir = gpr.parent().unwrap_or(root);
        let source_dirs = gpr_attribute_string_list(&text, "source_dirs");
        for main in &mains {
            // A Main entry is a bare file name or a path. Resolve it to a real
            // file by trying, in order: the entry as-given relative to the gpr
            // dir; the entry's BASENAME under each declared source dir; the
            // basename in the gpr dir (the GPR default source dir). Record only
            // the FIRST location that exists — never a speculative path.
            let basename = Path::new(main)
                .file_name()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(main));
            let mut candidates: Vec<std::path::PathBuf> = Vec::new();
            candidates.push(gpr_dir.join(main));
            for src_dir in &source_dirs {
                candidates.push(gpr_dir.join(src_dir).join(&basename));
            }
            candidates.push(gpr_dir.join(&basename));
            for cand in candidates {
                if cand.is_file() {
                    let key = cand.canonicalize().unwrap_or(cand);
                    out.entry(key).or_insert_with(|| gpr_name.clone());
                    break;
                }
            }
        }
    }
    out
}

/// Recursively collect `*.gpr` files under `dir`, skipping the same build/VCS and
/// non-library directories discovery itself prunes (so a vendored project's gpr
/// can't pull in a dependency's Main). Best-effort: unreadable dirs are skipped.
fn collect_gpr_files(dir: &Path, filter: &DirFilter, out: &mut Vec<std::path::PathBuf>) {
    let is_gpr = |p: &Path| {
        p.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("gpr"))
    };
    if dir.is_file() {
        if is_gpr(dir) {
            out.push(dir.to_path_buf());
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if !is_excluded_dir(&path, filter) {
                collect_gpr_files(&path, filter, out);
            }
        } else if ft.is_file() && is_gpr(&path) {
            out.push(path);
        }
    }
}

/// Extract the quoted string list of a GPR attribute written
/// `for <attr> use ( "a", "b", ... );`. The value list may span multiple lines
/// and use single or double quotes; the attribute-name match is case-insensitive
/// (GPR is a case-insensitive language) and whitespace-tolerant. Line comments
/// (`-- ...`) are stripped first so a commented-out attribute is ignored. Only
/// the FIRST occurrence is read (a scope declares each attribute at most once).
/// Returns the unquoted entries in declaration order, or empty if absent.
fn gpr_attribute_string_list(text: &str, attr: &str) -> Vec<String> {
    // Strip GPR/Ada line comments. ASCII lowercasing preserves byte length, so
    // offsets in the lowercased copy map 1:1 back into `decommented`.
    let mut decommented = String::with_capacity(text.len());
    for line in text.lines() {
        let code = match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        };
        decommented.push_str(code);
        decommented.push('\n');
    }
    let lc = decommented.to_ascii_lowercase();
    let pattern = format!(
        r"(?is)\bfor\s+{}\s+use\b",
        regex::escape(&attr.to_ascii_lowercase())
    );
    let Ok(re) = regex::Regex::new(&pattern) else {
        return Vec::new();
    };
    let Some(m) = re.find(&lc) else {
        return Vec::new();
    };
    // The value runs from just past `use` to its terminating `;`.
    let rest = &decommented[m.end()..];
    let segment = match rest.find(';') {
        Some(i) => &rest[..i],
        None => rest,
    };
    extract_quoted_strings(segment)
}

/// All single- or double-quoted substrings of `s`, trimmed and in order. Empty
/// quoted entries are dropped. Used to read a GPR string-list attribute value.
fn extract_quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        let Some(qpos) = rest.find(['"', '\'']) else {
            break;
        };
        let quote = rest.as_bytes()[qpos] as char;
        let after = &rest[qpos + 1..];
        let Some(epos) = after.find(quote) else {
            break;
        };
        let piece = after[..epos].trim();
        if !piece.is_empty() {
            out.push(piece.to_owned());
        }
        rest = &after[epos + 1..];
    }
    out
}

fn is_foreign_arch_backend_dir(name: &str) -> bool {
    // Only filter on the common x86/x86_64 host; on other hosts keep everything
    // (conservative — never skip the host's own architecture).
    if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    const FOREIGN_ARCH: &[&str] = &[
        "arm",
        "arm64",
        "armv7",
        "armv8",
        "aarch64",
        "ppc",
        "ppc64",
        "ppc64le",
        "powerpc",
        "powerpc64",
        "riscv",
        "riscv32",
        "riscv64",
        "mips",
        "mips64",
        "mipsel",
        "s390",
        "s390x",
        "sparc",
        "sparc64",
        "wasm",
        "wasm32",
        "wasm64",
        "wasi",
        "loongarch64",
    ];
    const FOREIGN_SIMD: &[&str] = &[
        "neon", "sve", "sve2", "altivec", "vsx", "msa", "lsx", "lasx",
    ];
    FOREIGN_ARCH.contains(&lower.as_str()) || FOREIGN_SIMD.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn cpp_windows_framework_guard_flags_mfc_atl_but_not_bare_windows_h() {
        // MFC / ATL framework headers are Windows-only -> tag win32.
        for inc in [
            "#include <afxwin.h>",
            "#include <afx.h>",
            "#include <afxext.h>",
            "#include \"stdafx.h\"\n#include <afxdisp.h>",
            "#include <atlbase.h>",
            "  #  include   <afxwin.h>",
        ] {
            let guard = cpp_windows_framework_guard(inc)
                .unwrap_or_else(|| panic!("MFC/ATL include should tag win32: {inc:?}"));
            assert!(
                guard.contains("win32"),
                "guard must match win32 needle: {guard}"
            );
        }
        // A bare <windows.h> is commonly #ifdef _WIN32-guarded cross-platform code —
        // do NOT tag it (avoids routing portable code through wine).
        assert!(cpp_windows_framework_guard("#include <windows.h>").is_none());
        assert!(cpp_windows_framework_guard("#include <string>\nint f();").is_none());
        // "afx" mentioned outside an include line must not trigger.
        assert!(cpp_windows_framework_guard("// uses afxwin.h historically").is_none());
    }

    #[test]
    fn stable_hasher_and_ids_are_pinned_build_stable_constants() {
        use std::hash::Hasher;
        // Pin the FNV-1a algorithm. The discovery cache fingerprint and the
        // per-target harness ids hash with `StableHasher`; if a future toolchain
        // bump or an accidental swap back to `DefaultHasher` changed these digests,
        // EVERY cached discovery would silently miss and EVERY per-target corpus
        // would be orphaned. This test fails loudly in that case instead.
        assert_eq!(
            StableHasher::new().finish(),
            0xcbf2_9ce4_8422_2325,
            "FNV-1a 64-bit offset basis"
        );
        let mut h = StableHasher::new();
        h.write(b"govfuzz");
        assert_eq!(h.finish(), 0x859f_9850_538e_fb06, "FNV-1a(\"govfuzz\")");
        // A harness id end-to-end (path + line + name): the `<work>/harnesses/<id>/` dir
        // name must be byte-identical across govfuzz builds so build artifacts and
        // the saved corpus are found on a re-run/rebuild.
        assert_eq!(
            stable_harness_id("H-C", Path::new("/src/foo.c"), 42, "parse"),
            "H-C002A-144FE22B"
        );
    }
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-discover-{n}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn excludes_a_custom_work_dir_nested_in_the_scanned_tree() {
        // A real library target, plus govfuzz's own work dir (a CUSTOM name, not
        // `govfuzz_work`) holding a generated harness that itself looks fuzzable.
        let root = tmpdir();
        fs::write(
            root.join("lib.c"),
            "int cfg_parse(const unsigned char *d, unsigned n){ return n ? d[0] : 0; }\n",
        )
        .unwrap();
        let wd = root.join("mywork");
        fs::create_dir_all(&wd).unwrap();
        fs::write(
            wd.join("Harness.c"),
            "int harness_entry(const unsigned char *d, unsigned n){ return n ? d[0] : 0; }\n",
        )
        .unwrap();
        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);

        // Control: without work-dir exclusion the generated harness IS re-discovered
        // (the bug — it then competes with / displaces the real targets).
        let cands = discover_with_dir_filter(&root, &DirFilter::default()).unwrap();
        assert!(
            has(&cands, "harness_entry"),
            "control: harness re-discovered without work-dir exclusion: {cands:?}"
        );

        // With the work dir excluded by PATH, the real target stays and the
        // work-dir contents are gone.
        let cands =
            discover_with_dir_filter(&root, &DirFilter::default().with_work_dir(&wd)).unwrap();
        assert!(
            has(&cands, "cfg_parse"),
            "real library target kept: {cands:?}"
        );
        assert!(
            !has(&cands, "harness_entry"),
            "work-dir contents excluded: {cands:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn source_fingerprint_is_stable_and_changes_on_edit_or_filter_change() {
        // The discovery cache (`--reuse-discovery`) trusts this fingerprint to
        // decide whether a cached candidate list is still valid, so: identical for
        // an unchanged tree; different after a file edit, a new file, or a changed
        // dir-filter. (A no-op walk over the same bytes must reproduce the digest.)
        // A collision-proof private dir (the shared `tmpdir()` keys only on nanos,
        // which two parallel tests can collide on; this test writes+rereads several
        // times so any interference would flake it).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "govfuzz-fp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.c"), "int parse(const char *p){return p[0];}\n").unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("lib/b.c"), "int f(int x){return x;}\n").unwrap();
        let filter = DirFilter::default();

        let fp1 = source_fingerprint(&root, &filter);
        // Same tree, same filter → identical.
        assert_eq!(
            fp1,
            source_fingerprint(&root, &filter),
            "stable for unchanged tree"
        );

        // Edit a file's content → its content hash changes → the fingerprint
        // differs. Identity is the content hash now, so even a same-length edit
        // is caught (this one also changes the length).
        fs::write(
            root.join("a.c"),
            "int parse(const char *p){return p[1] + p[2] + p[3];}\n",
        )
        .unwrap();
        let fp2 = source_fingerprint(&root, &filter);
        assert_ne!(fp1, fp2, "edited file changes fingerprint");

        // Add a new targetable file → different.
        fs::write(root.join("c.c"), "int g(void){return 0;}\n").unwrap();
        let fp3 = source_fingerprint(&root, &filter);
        assert_ne!(fp2, fp3, "new file changes fingerprint");

        // A non-targetable file (README) does NOT change the fingerprint.
        fs::write(root.join("README.md"), "docs\n").unwrap();
        assert_eq!(
            fp3,
            source_fingerprint(&root, &filter),
            "non-source file is ignored"
        );

        // Changing the dir-filter (excluding `lib`) changes the discovered set, so
        // it must change the fingerprint even with no file change.
        let excl = DirFilter::new(&["lib".into()], &[]);
        assert_ne!(
            fp3,
            source_fingerprint(&root, &excl),
            "dir-filter change changes fingerprint"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn source_fingerprint_ignores_mtime_but_tracks_content() {
        // Robustness: git checkout / cp / rsync rewrite mtimes without changing
        // bytes, so the fingerprint must NOT bust on an mtime-only change (else
        // --reuse-discovery misses for no reason). A same-LENGTH content edit —
        // which a size+mtime fingerprint could miss on a coarse-mtime fs — must
        // still be caught, because identity is the file's content hash.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{Duration, SystemTime};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "govfuzz-fp-mtime-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("a.c");
        let body = "int parse(const char *p){return p[0];}\n";
        fs::write(&file, body).unwrap();
        let filter = DirFilter::default();

        let fp1 = source_fingerprint(&root, &filter);

        // Bump mtime far into the future without changing a single byte.
        let handle = fs::File::options().write(true).open(&file).unwrap();
        handle
            .set_modified(SystemTime::now() + Duration::from_secs(86_400))
            .unwrap();
        drop(handle);
        assert_eq!(
            fp1,
            source_fingerprint(&root, &filter),
            "an mtime change with identical bytes must not bust the fingerprint"
        );

        // Same-length content edit (p[0] -> p[1]) must change the fingerprint.
        let edited = "int parse(const char *p){return p[1];}\n";
        assert_eq!(edited.len(), body.len(), "edit must be the same length");
        fs::write(&file, edited).unwrap();
        assert_ne!(
            fp1,
            source_fingerprint(&root, &filter),
            "a same-length content edit must change the fingerprint"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dev_tooling_dirs_are_non_library() {
        // Developer-tooling dirs hold auxiliary code, not the library under test
        // (libde265 `dev-tools/` rd-curves out-ranked real decode entries).
        assert!(is_default_non_library_dir("dev-tools"));
        assert!(is_default_non_library_dir("devtools"));
        assert!(is_default_non_library_dir("dev_tools"));
        assert!(is_default_non_library_dir("Dev-Tools"), "case-insensitive");
        // Guard: a real source dir is still kept.
        assert!(!is_default_non_library_dir("src"));
        assert!(!is_default_non_library_dir("libde265"));
    }

    #[test]
    fn cargo_benches_dir_is_non_library() {
        // Cargo's standard benchmark dir is the PLURAL `benches/` (smallvec et al.):
        // criterion/bench harnesses that use the library, not its API. The singular
        // `bench` was already excluded; `benches` must be too.
        assert!(is_default_non_library_dir("benches"));
        assert!(is_default_non_library_dir("bench"));
        assert!(is_default_non_library_dir("Benches"), "case-insensitive");
        // Guard: a real module is still kept.
        assert!(!is_default_non_library_dir("benchmark_utils_lib"));
    }

    #[test]
    fn greatest_h_framework_header_is_a_test_file() {
        // The silentbicycle/greatest single-header test framework (`greatest.h`,
        // shipped at heatshrink's repo root) is test scaffolding — its
        // `greatest_do_pass`/`greatest_usage` runner functions out-rank real
        // entry points and fail to build alone. It must be excluded even though
        // the English word "greatest" is otherwise protected from the
        // ends-with-"test" rule.
        assert!(is_test_or_tool_source_file(Path::new("/x/greatest.h")));
        assert!(is_test_or_tool_source_file(Path::new("/x/GREATEST.H")));
        // The word-exception still protects non-framework files: a hypothetical
        // `greatest.c` source and the words latest/fastest stay library code.
        assert!(!is_test_or_tool_source_file(Path::new("/x/greatest.c")));
        assert!(!is_test_or_tool_source_file(Path::new("/x/latest.c")));
        assert!(!is_test_or_tool_source_file(Path::new("/x/fastest.c")));
        // And the normal test-file patterns still fire (heatshrink's root tests).
        assert!(is_test_or_tool_source_file(Path::new(
            "/x/test_heatshrink_dynamic.c"
        )));
        assert!(is_test_or_tool_source_file(Path::new("/x/pngtest.c")));
    }

    #[test]
    fn perl_cpan_single_letter_test_dir_is_non_library() {
        // The Perl/CPAN `t/` convention (one-letter test dir holding `*_t.c` files
        // that link against a TAP framework — libtap `plan`/`ok`/`cmp_ok`/
        // `done_testing`) is widely adopted by C projects too (libmaxminddb). Those
        // entry points out-rank the real API and then fail to link on the missing
        // test-framework symbols. Treat a directory named exactly `t` as test code.
        assert!(is_default_non_library_dir("t"));
        assert!(is_default_non_library_dir("T"), "case-insensitive");
        // Guard: only the exact single letter — never a real dir that merely starts
        // with `t` (`tls`, `types`, `tcommon`) or the project itself.
        assert!(!is_default_non_library_dir("tls"));
        assert!(!is_default_non_library_dir("types"));
        assert!(!is_default_non_library_dir("transport"));
    }

    #[test]
    fn default_dir_filter_excludes_test_and_example_dirs_and_is_configurable() {
        // Test/example/vendored code is never the project's own attack surface and
        // otherwise out-ranks the real entry points (cjson's Unity, zlib's
        // examples). The default set skips them; --exclude-dir/--include-dir tune it.
        let root = tmpdir();
        fs::write(
            root.join("lib.c"),
            "int cfg_parse(char *s, char *e, int n) { return s[0] + e[0] + n; }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("tests/runner.c"),
            "int run_all_tests(const char *p, int n) { return p[0] + n; }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("examples")).unwrap();
        fs::write(
            root.join("examples/demo.c"),
            "int demo_decode(const char *p, int n) { return p[n & 7]; }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("oddball")).unwrap();
        fs::write(
            root.join("oddball/x.c"),
            "int odd_parse(const char *p, int n) { return p[1] + n; }\n",
        )
        .unwrap();

        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);

        // Default: library code discovered; tests/ and examples/ skipped.
        let cands = discover(&root).unwrap();
        assert!(has(&cands, "cfg_parse"), "library fn discovered: {cands:?}");
        assert!(!has(&cands, "run_all_tests"), "tests/ excluded by default");
        assert!(!has(&cands, "demo_decode"), "examples/ excluded by default");
        assert!(has(&cands, "odd_parse"), "non-default dir kept by default");

        // --include-dir tests re-includes the test directory.
        let kept =
            discover_with_dir_filter(&root, &DirFilter::new(&[], &["tests".into()])).unwrap();
        assert!(
            has(&kept, "run_all_tests"),
            "include-dir re-includes tests/"
        );

        // --exclude-dir adds a custom directory name to the skip set.
        let extra =
            discover_with_dir_filter(&root, &DirFilter::new(&["oddball".into()], &[])).unwrap();
        assert!(!has(&extra, "odd_parse"), "exclude-dir skips a custom dir");
        assert!(has(&extra, "cfg_parse"), "library fn still discovered");
    }

    #[test]
    fn macro_placeholder_names_are_detected_but_real_apis_are_kept() {
        // Template-expansion placeholders (libdeflate `FUNCNAME`, libbsc
        // `QLFC_ADAPTIVE_ENCODE_FUNCTION_NAME`) are dropped...
        assert!(is_macro_placeholder_name("FUNCNAME"));
        assert!(is_macro_placeholder_name(
            "QLFC_ADAPTIVE_ENCODE_FUNCTION_NAME"
        ));
        assert!(is_macro_placeholder_name("NS::FUNCNAME"));
        assert!(is_macro_placeholder_name("DECODE_TEMPLATE"));
        // ...while real functions (any lowercase) and genuine all-caps APIs are kept.
        assert!(!is_macro_placeholder_name("png_read_png"));
        assert!(!is_macro_placeholder_name("cJSON_Parse"));
        assert!(!is_macro_placeholder_name("LZ4_decompress_safe"));
        assert!(!is_macro_placeholder_name("CRC32"));
        assert!(!is_macro_placeholder_name("MD5"));
    }

    #[test]
    fn fuzz_driver_entry_points_are_never_targets() {
        // A libFuzzer/AFL harness has the canonical fuzz signature
        // (`const uint8_t *, size_t`) so the scorer ranks it #1 — but it is driver
        // glue, not a library target (libconfig's `fuzz/` harness did exactly this).
        // Excluded both by the `fuzz/` dir skip AND by NAME, so govfuzz can't target
        // its own generated `LLVMFuzzerTestOneInput` wherever a prior run wrote it.
        let root = tmpdir();
        fs::write(
            root.join("lib.c"),
            "int cfg_parse(char *s, int n) { return s[0] + n; }\n\
             /* a stray harness compiled into the library tree must still be dropped */\n\
             int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n\
             \x20  return cfg_parse((char *)data, (int)size);\n\
             }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("fuzz")).unwrap();
        fs::write(
            root.join("fuzz/harness.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n\
             \x20  return data[0] + (int)size;\n\
             }\n",
        )
        .unwrap();

        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);
        let cands = discover(&root).unwrap();
        assert!(has(&cands, "cfg_parse"), "library fn discovered: {cands:?}");
        assert!(
            !has(&cands, "LLVMFuzzerTestOneInput"),
            "fuzz-driver entry must never be a target (name + fuzz/ dir): {cands:?}"
        );
        assert_eq!(
            cands[0].name, "cfg_parse",
            "real library parser ranks #1 once the harness is dropped: {cands:?}"
        );
    }

    #[test]
    fn sole_libfuzzer_entrypoint_is_kept_as_passthrough_target() {
        // A project-supplied single-file libFuzzer target: the ONLY fuzzable
        // function is LLVMFuzzerTestOneInput. It must be KEPT as the passthrough
        // target (#408/#410) — dropping it would discover nothing and `auto` would
        // exit "no candidates". Contrast `fuzz_driver_entry_points_are_never_targets`,
        // where a real parser coexists and the harness is correctly dropped.
        let root = tmpdir();
        fs::write(
            root.join("target.cc"),
            "#include <cstdint>\n#include <cstddef>\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
             \x20  return size > 0 ? (int)data[0] : 0;\n\
             }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            cands.iter().any(|c| c.name == "LLVMFuzzerTestOneInput"),
            "a sole libFuzzer entrypoint must be kept as the passthrough target: {cands:?}"
        );
    }

    #[test]
    fn libfuzzer_hooks_are_dropped_even_when_sole() {
        // The non-TestOneInput hooks (Initialize / CustomMutator / CustomCrossOver)
        // are never fuzzable targets — they must be dropped even if nothing else is
        // discovered (they have no `(data, size)` body to drive).
        let root = tmpdir();
        fs::write(
            root.join("hooks.c"),
            "int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            !cands.iter().any(|c| c.name == "LLVMFuzzerInitialize"),
            "libFuzzer hook must never be a target: {cands:?}"
        );
    }

    #[test]
    fn test_harness_files_and_tool_dirs_are_excluded() {
        // Test-harness FILES (`runtest.c`/`pcre2test.c` in the repo root, outside
        // any tests/ dir) and CLI/tool DIRS (`tools/`, `programs/`) hold
        // non-library code whose fns otherwise out-rank the real entry points
        // (libxml2's `runtest.c` took the whole top 6). Both are skipped; the
        // library code is kept. A word that merely ends in "test" is not a test.
        let root = tmpdir();
        fs::write(
            root.join("lib.c"),
            "int cfg_parse(const char *p, int n) { return p[0] + n; }\n",
        )
        .unwrap();
        fs::write(
            root.join("runtest.c"),
            "int run_one_test(const char *p, int n) { return p[n & 7]; }\n",
        )
        .unwrap();
        fs::write(
            root.join("pcre2test.c"),
            "int do_test(const char *p, int n) { return p[1] + n; }\n",
        )
        .unwrap();
        // A library file whose name merely ends in "test" must NOT be excluded.
        fs::write(
            root.join("latest.c"),
            "int latest_value(const char *p, int n) { return p[5] + n; }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::write(
            root.join("tools/dump.c"),
            "int tool_main(const char *p, int n) { return p[2] + n; }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("programs")).unwrap();
        fs::write(
            root.join("programs/demo.c"),
            "int prog_main(const char *p, int n) { return p[3] + n; }\n",
        )
        .unwrap();

        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);
        let cands = discover(&root).unwrap();
        assert!(has(&cands, "cfg_parse"), "library fn discovered: {cands:?}");
        assert!(has(&cands, "latest_value"), "`latest.c` is not a test file");
        assert!(
            !has(&cands, "run_one_test"),
            "runtest.c excluded by file name"
        );
        assert!(!has(&cands, "do_test"), "pcre2test.c excluded by file name");
        assert!(!has(&cands, "tool_main"), "tools/ dir excluded");
        assert!(!has(&cands, "prog_main"), "programs/ dir excluded");
    }

    #[test]
    fn callgraph_ranks_orchestrator_entrypoint_above_leaf_helpers() {
        // The exact toml-c trap: internal `const char *` scan helpers score high by
        // signature (buffer + length + a parser keyword like "scan"), while the real
        // public entry takes a NON-const `char *` it tokenises in place. Without the
        // call-graph signal the leaves out-rank the entry. `config_parse` FANS OUT
        // into the scan helpers (orchestrator -> boosted); each `scan_*` calls
        // nothing in-tree and is called by the parser (leaf -> demoted). The entry
        // must end up ranked above every leaf — no headers/docs consulted.
        let root = tmpdir();
        fs::write(
            root.join("config.c"),
            "int scan_field(const char *p, int n) { return p[0] + n; }\n\
             int scan_value(const char *p, int n) { return p[1] + n; }\n\
             int scan_key(const char *p, int n) { return p[2] + n; }\n\
             int config_parse(char *input, char *errbuf, int errlen) {\n\
             \x20  int a = scan_field(input, 1);\n\
             \x20  int b = scan_value(input, 2);\n\
             \x20  int c = scan_key(input, 3);\n\
             \x20  return assemble(a, b, c, errbuf, errlen);\n\
             }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        let rank = |name: &str| cands.iter().position(|c| c.name == name);
        let parse_rank = rank("config_parse").expect("config_parse discovered");
        for leaf in ["scan_field", "scan_value", "scan_key"] {
            let leaf_rank = rank(leaf).expect("leaf discovered");
            assert!(
                parse_rank < leaf_rank,
                "orchestrator entry config_parse (#{parse_rank}) must out-rank leaf helper {leaf} (#{leaf_rank}): {:?}",
                cands.iter().map(|c| (&c.name, c.score)).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn c_main_is_excluded_from_candidates() {
        // A C/C++ function named exactly `main` is the program entry point, not a
        // library API. The generated harness defines its own `int main(...)`, so
        // compiling the target's `main` alongside it always fails with a duplicate-
        // main link error. Regression for tomlc99 / qoi / similar projects whose
        // example programs sit next to the library source.
        //
        // Rules (all verified here):
        // - `main` (C) → excluded
        // - `main` (C++) → excluded
        // - `h2load::main` (namespace-qualified C++) → excluded (bare name is `main`)
        // - `main_loop` → NOT excluded (substring, not exact match)
        // - `domain` → NOT excluded (contains "main" as substring, not at word boundary)
        // - sibling library function → kept
        let root = tmpdir();
        // A C source file with a real library function and a `main` alongside it
        // (the exact tomlc99 / qoi pattern: converter tools live next to the lib).
        fs::write(
            root.join("toml_cat.c"),
            // `main` always fails to build as a harness; `parse_buf` is the real target.
            "int parse_buf(const char *buf, int n) { return buf[0] + n; }\n\
             int main(int argc, char **argv) { return parse_buf(argv[1], argc); }\n\
             int main_loop(const char *p, int n) { return p[n & 7]; }\n\
             int domain_parse(const char *p, int n) { return p[n & 3]; }\n",
        )
        .unwrap();
        // A C++ source with a namespace-qualified `main` (same exclusion rule via
        // bare_name).
        fs::write(
            root.join("hpack.cpp"),
            "namespace h2load {\n\
             int main(int argc, char **argv) { return 0; }\n\
             }\n\
             int hpack_decode(const unsigned char *buf, int n) { return buf[0] + n; }\n",
        )
        .unwrap();

        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);
        let cands = discover(&root).unwrap();

        // Sibling library functions are discovered normally.
        assert!(has(&cands, "parse_buf"), "parse_buf kept: {cands:?}");
        assert!(has(&cands, "hpack_decode"), "hpack_decode kept: {cands:?}");

        // `main` (bare) must be absent regardless of language or namespace.
        assert!(!has(&cands, "main"), "bare `main` excluded: {cands:?}");
        assert!(
            !cands.iter().any(|c| bare_name(&c.name) == "main"),
            "any candidate with bare name `main` excluded: {cands:?}"
        );

        // `main_loop` and `domain_parse` must NOT be excluded — only the exact
        // bare identifier `main`, not substrings.
        assert!(has(&cands, "main_loop"), "main_loop kept: {cands:?}");
        assert!(has(&cands, "domain_parse"), "domain_parse kept: {cands:?}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn java_package_dirs_inside_src_main_java_are_not_excluded() {
        // Java/Kotlin directory names ARE package-name components: `tools.jackson.core`
        // lives under `tools/jackson/core/`. The organizational-name exclusions that
        // work for C/C++ projects (`tools/` = CLI tools, `vendor/` = bundled deps)
        // MUST NOT apply inside a Maven/Gradle source root (`src/main/java`,
        // `src/main/kotlin`), or the entire library is silently hidden (jackson-core
        // 3.x uses package `tools.jackson.core` and discovered 0 targets before this
        // fix).
        //
        // Rules verified here:
        // - `src/main/java/tools/…/Parser.java` is discovered (not excluded)
        // - `src/test/java/…/…` is excluded (test source root)
        // - A C `tools/` at the repo root is still excluded
        // - A sibling C library file at the root is kept
        let root = tmpdir();

        // Java source root: `tools` is a package component, not a tooling dir.
        let java_pkg = root.join("src/main/java/tools/parser");
        fs::create_dir_all(&java_pkg).unwrap();
        fs::write(
            java_pkg.join("Parser.java"),
            "package tools.parser;\n\
             /** Parses raw bytes — the canonical attacker surface. */\n\
             public class Parser {\n\
             \x20  public static Object parse(byte[] data) {\n\
             \x20    return data.length > 0 ? (int) data[0] : -1;\n\
             \x20  }\n\
             }\n",
        )
        .unwrap();

        // Test source root — excluded (src/test/ is a test dir).
        let test_pkg = root.join("src/test/java/tools/parser");
        fs::create_dir_all(&test_pkg).unwrap();
        fs::write(
            test_pkg.join("ParserTest.java"),
            "package tools.parser;\n\
             public class ParserTest {\n\
             \x20  public static Object testParse(byte[] data) { return null; }\n\
             }\n",
        )
        .unwrap();

        // C project: `tools/` at the top level is still excluded.
        let c_tools = root.join("tools");
        fs::create_dir_all(&c_tools).unwrap();
        fs::write(
            c_tools.join("dump.c"),
            "int dump_buf(const char *p, int n) { return p[0] + n; }\n",
        )
        .unwrap();

        // C library at the root: kept.
        fs::write(
            root.join("lib.c"),
            "int parse_json(const char *buf, int n) { return buf[0] + n; }\n",
        )
        .unwrap();

        let has = |cs: &[Candidate], n: &str| cs.iter().any(|c| c.name == n);
        let cands = discover(&root).unwrap();

        // Java method inside src/main/java/tools/… is discovered.
        assert!(
            has(&cands, "parse"),
            "Java method in tools package discovered: {cands:?}"
        );
        // Test source file is excluded (src/test/ hit the test-dir filter before
        // we ever reach the tools/ component inside it).
        assert!(
            !has(&cands, "testParse"),
            "Java test method excluded: {cands:?}"
        );
        // C tools/ dir at repo root is still excluded.
        assert!(
            !has(&cands, "dump_buf"),
            "C tools/ still excluded: {cands:?}"
        );
        // C library fn at root is kept.
        assert!(has(&cands, "parse_json"), "C library fn kept: {cands:?}");

        // Also verify the is_under_java_source_root helper directly.
        assert!(
            is_under_java_source_root(&root.join("src/main/java/tools")),
            "tools/ directly under src/main/java/ is a java root child"
        );
        assert!(
            is_under_java_source_root(&root.join("src/main/java/tools/jackson/core")),
            "deep nesting under src/main/java/ is also a java root child"
        );
        assert!(
            !is_under_java_source_root(&root.join("tools")),
            "top-level tools/ is NOT under a java root"
        );
        assert!(
            !is_under_java_source_root(&root.join("src/test/java/tools")),
            "src/test/java/tools is NOT under src/main/java"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn header_api_namespace_dirs_inside_include_are_not_excluded() {
        // A directory under a C/C++ header-API root (`include/`, `inc/`) is a
        // library namespace/module, not a tooling dir. The organizational-name
        // exclusions that work for tool/driver layouts (`cli/` = CLI tools,
        // `app/`, `tools/`) MUST NOT apply there, or a library whose namespace dir
        // collides with a tool-class token is silently hidden — CLI11's
        // `include/CLI/` matched the `cli` token and discovered 0 targets from the
        // tree root before this fix (262 only when `include/CLI` was the scan root,
        // i.e. not self-excluded).
        //
        // Rules verified here:
        // - `include/CLI/`, `include/app/`, `inc/tools/` namespace dirs are kept
        // - `tests/` and `examples/` at the TREE ROOT (outside include/) still go
        // - hard build/VCS exclusions (`.git/`, `build/`) under include/ still go
        let root = tmpdir();

        // include/CLI/ — CLI11's namespace dir; `CLI` collides with `cli`.
        let cli_dir = root.join("include/CLI");
        fs::create_dir_all(&cli_dir).unwrap();
        fs::write(
            cli_dir.join("App.h"),
            "#include <stddef.h>\n\
             int cli_add_flag(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // include/app/ — `app` token, under the same header-API root.
        let app_dir = root.join("include/app");
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join("Widget.h"),
            "#include <stddef.h>\n\
             int app_make_widget(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // inc/tools/ — `tools` token under the `inc` header-API root variant.
        let tools_dir = root.join("inc/tools");
        fs::create_dir_all(&tools_dir).unwrap();
        fs::write(
            tools_dir.join("Helper.h"),
            "#include <stddef.h>\n\
             int tool_help(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // tests/ at the TREE ROOT (NOT under include/) — still excluded.
        let tests_dir = root.join("tests");
        fs::create_dir_all(&tests_dir).unwrap();
        fs::write(
            tests_dir.join("Runner.h"),
            "#include <stddef.h>\n\
             int root_test_runner(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // examples/ at the tree root — still excluded.
        let examples_dir = root.join("examples");
        fs::create_dir_all(&examples_dir).unwrap();
        fs::write(
            examples_dir.join("Sample.h"),
            "#include <stddef.h>\n\
             int root_example_demo(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // .git/ under include/ — a hard VCS exclusion that MUST still fire even
        // inside a header-API root.
        let git_dir = root.join("include/.git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            git_dir.join("hook.h"),
            "#include <stddef.h>\n\
             int git_internal(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        // build/ under include/ — a hard build-output exclusion; MUST still fire.
        let build_dir = root.join("include/build");
        fs::create_dir_all(&build_dir).unwrap();
        fs::write(
            build_dir.join("gen.h"),
            "#include <stddef.h>\n\
             int build_artifact(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        let has = |n: &str| cands.iter().any(|c| c.name == n);

        // Library namespace dirs under include/ / inc/ are NOT excluded.
        assert!(
            has("cli_add_flag"),
            "include/CLI/ namespace must NOT be excluded: {cands:?}"
        );
        assert!(
            has("app_make_widget"),
            "include/app/ namespace must NOT be excluded: {cands:?}"
        );
        assert!(
            has("tool_help"),
            "inc/tools/ namespace must NOT be excluded: {cands:?}"
        );

        // Organizational dirs at the TREE ROOT (outside include/) STILL excluded.
        assert!(
            !has("root_test_runner"),
            "tests/ at the tree root must STILL be excluded: {cands:?}"
        );
        assert!(
            !has("root_example_demo"),
            "examples/ at the tree root must STILL be excluded: {cands:?}"
        );

        // Hard build/VCS exclusions STILL fire under a header-API root.
        assert!(
            !has("git_internal"),
            ".git/ under include/ must STILL be excluded: {cands:?}"
        );
        assert!(
            !has("build_artifact"),
            "build/ under include/ must STILL be excluded: {cands:?}"
        );

        // Also verify the is_under_header_api_root helper directly.
        assert!(
            is_under_header_api_root(&root.join("include/CLI")),
            "CLI/ directly under include/ is a header-root child"
        );
        assert!(
            is_under_header_api_root(&root.join("include/CLI/detail")),
            "deep nesting under include/ is also a header-root child"
        );
        assert!(
            is_under_header_api_root(&root.join("inc/tools")),
            "tools/ under the inc/ variant is a header-root child"
        );
        assert!(
            !is_under_header_api_root(&root.join("include")),
            "the include/ dir itself has no header-root ANCESTOR"
        );
        assert!(
            !is_under_header_api_root(&root.join("tests")),
            "a top-level tests/ is NOT under a header root"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn skips_unchecked_deallocation_instantiation() {
        let root = tmpdir();
        fs::write(
            root.join("buffers.ads"),
            "with Ada.Unchecked_Deallocation;\n\
             package Buffers is\n\
             \x20  type Buffer_Array is array (Natural range <>) of Integer;\n\
             \x20  type Buffer_Access is access Buffer_Array;\n\
             \x20  procedure Process (X : Integer);\n\
             \x20  procedure Unchecked_Free is new Ada.Unchecked_Deallocation\n\
             \x20    (Buffer_Array, Buffer_Access);\n\
             end Buffers;\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            cands
                .iter()
                .any(|c| c.name.to_ascii_lowercase().contains("process")),
            "the ordinary procedure should be discovered: {cands:?}"
        );
        assert!(
            !cands
                .iter()
                .any(|c| c.name.to_ascii_lowercase().contains("unchecked_free")),
            "a generic instantiation must be skipped, not emitted as a 0-arg target: {cands:?}"
        );
    }

    #[test]
    fn demotes_unsynthesizable_generic_targets_below_concrete_ones() {
        // libkeccak shape: a generic package with a formal `type` (can never be
        // auto-instantiated) and a concrete non-generic package. The concrete
        // target must rank ABOVE the generic one so a time-boxed run reaches it
        // first; the generic stays discoverable but demoted.
        let root = tmpdir();
        fs::write(
            root.join("generic_sponge.ads"),
            "generic\n\
             \x20  type State_Type is private;\n\
             \x20  with procedure Permute (S : in out State_Type);\n\
             package Generic_Sponge is\n\
             \x20  procedure Absorb (S : in out State_Type; Data : String);\n\
             end Generic_Sponge;\n",
        )
        .unwrap();
        fs::write(
            root.join("padding.ads"),
            "package Padding is\n\
             \x20  function Pad101 (Data : String) return Integer;\n\
             end Padding;\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        let concrete = cands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("Pad101"))
            .expect("concrete target discovered");
        let generic = cands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("Absorb"))
            .expect("generic target still discovered (demoted, not dropped)");
        assert!(
            concrete.score > generic.score,
            "concrete target must outrank the un-instantiable generic: concrete={} generic={}",
            concrete.score,
            generic.score
        );
        assert!(
            generic.score < 0,
            "generic target should be demoted below zero, got {}",
            generic.score
        );
    }

    #[test]
    fn discovers_c_and_cpp_targets_sorted_by_score() {
        let root = tmpdir();
        fs::write(
            root.join("a.c"),
            "int parse_a(const unsigned char *d, unsigned long n) { return (int)n; }\n",
        )
        .unwrap();
        fs::write(
            root.join("b.cpp"),
            "int parse_b(const char *s) { return s ? 0 : -1; }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(cands.iter().any(|c| c.name == "parse_a"));
        assert!(cands.iter().any(|c| c.name == "parse_b"));
        for i in 1..cands.len() {
            assert!(cands[i - 1].score >= cands[i].score);
        }
    }

    #[test]
    fn discovers_header_only_c_and_cpp_targets() {
        let root = tmpdir();
        fs::write(
            root.join("parser.h"),
            "#include <stddef.h>\nint parse_c_header(const unsigned char *d, size_t n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();
        fs::write(
            root.join("parser.hpp"),
            "#include <string_view>\nnamespace acme { inline int parse_cpp_header(std::string_view s) { return (int)s.size(); } }\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();

        assert!(
            cands.iter().any(|c| c.name == "parse_c_header"
                && c.lang == Lang::C
                && c.source_path.ends_with("parser.h")),
            "expected C header target in {cands:?}"
        );
        assert!(
            cands.iter().any(|c| c.name == "acme::parse_cpp_header"
                && c.lang == Lang::Cpp
                && c.source_path.ends_with("parser.hpp")),
            "expected C++ header target in {cands:?}"
        );
    }

    #[test]
    fn discovers_cpp_method_targets_with_qualified_overload_signatures() {
        let root = tmpdir();
        fs::write(
            root.join("parser.cpp"),
            "#include <string_view>\n\
             namespace gov { class Parser { public:\n\
             int parse(const char *d, size_t n) { return d ? (int)n : 0; }\n\
             int parse(std::string_view s) { return (int)s.size(); }\n\
             }; }\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        let names = cands
            .iter()
            .filter(|candidate| candidate.lang == Lang::Cpp)
            .map(|candidate| candidate.name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"gov::Parser::parse(const char *, size_t)"));
        assert!(names.contains(&"gov::Parser::parse(std::string_view)"));
    }

    #[test]
    fn drops_cross_file_non_public_cpp_member_definitions() {
        // The access specifier lives in the header's class body; the DEFINITION is
        // out-of-line in the .cpp (so its per-file member_access is None). The
        // cross-file filter must still drop the protected member (it can't be
        // called from the harness TU) while keeping the public one.
        let root = tmpdir();
        fs::write(
            root.join("reader.h"),
            "class Reader {\n\
             public:\n\
             int Pub(const char* d, unsigned long n);\n\
             protected:\n\
             static int Prot(const char* d, unsigned long n);\n\
             };\n",
        )
        .unwrap();
        fs::write(
            root.join("reader.cpp"),
            "#include \"reader.h\"\n\
             int Reader::Pub(const char* d, unsigned long n) { return d ? (int)n : 0; }\n\
             int Reader::Prot(const char* d, unsigned long n) { return d ? (int)n : 1; }\n",
        )
        .unwrap();

        let names = discover(&root)
            .unwrap()
            .iter()
            .map(|candidate| candidate.name.clone())
            .collect::<Vec<_>>();
        assert!(
            names.iter().any(|n| n.contains("Reader::Pub")),
            "public member kept: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("Reader::Prot")),
            "protected member must be dropped: {names:?}"
        );
    }

    #[test]
    fn drops_non_public_member_of_a_namespaced_cpp_class() {
        // The access map keys by `Class::method` (no namespace), but a candidate is
        // `ns::Class::method` (`tinyxml2::XMLDocument::SetError`). The filter must
        // match on the last two `::` segments so a private member of a NAMESPACED
        // class is still dropped.
        let root = tmpdir();
        fs::write(
            root.join("doc.h"),
            "namespace ns {\n\
             class Doc {\n\
             public:\n\
             int Parse(const char* d, unsigned long n);\n\
             private:\n\
             void SetError(int code);\n\
             };\n\
             }\n",
        )
        .unwrap();
        fs::write(
            root.join("doc.cpp"),
            "#include \"doc.h\"\n\
             namespace ns {\n\
             int Doc::Parse(const char* d, unsigned long n) { return d ? (int)n : 0; }\n\
             void Doc::SetError(int code) { (void)code; }\n\
             }\n",
        )
        .unwrap();

        let names = discover(&root)
            .unwrap()
            .iter()
            .map(|candidate| candidate.name.clone())
            .collect::<Vec<_>>();
        assert!(
            names.iter().any(|n| n.contains("Doc::Parse")),
            "public namespaced member kept: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("SetError")),
            "private namespaced member must be dropped: {names:?}"
        );
    }

    #[test]
    fn preprocess_mode_resolves_ifdef_branches_with_original_lines() {
        // §27.6: with the preprocessor on, a function compiled out by the active
        // config is NOT discovered, the active-branch one IS, and every reported
        // line is the ORIGINAL source line (the load-bearing line-map guard).
        //   1: #ifdef LEGACY
        //   2: int old_parse(const char *p, int n) { return p[0] + n; }
        //   3: #else
        //   4: int new_parse(const char *p, int n) { return p[1] + n; }
        //   5: #endif
        //   6: int common_parse(const char *p, int n) { return p[2] + n; }
        let root = tmpdir();
        fs::write(
            root.join("cond.c"),
            "#ifdef LEGACY\n\
             int old_parse(const char *p, int n) { return p[0] + n; }\n\
             #else\n\
             int new_parse(const char *p, int n) { return p[1] + n; }\n\
             #endif\n\
             int common_parse(const char *p, int n) { return p[2] + n; }\n",
        )
        .unwrap();

        // PreprocessMode::Always: inactive `old_parse` dropped; `new_parse` kept at
        // its ORIGINAL line 4; `common_parse` at its original line 6.
        let cands =
            discover_with_options(&root, &DirFilter::default(), PreprocessMode::Always).unwrap();
        let find = |n: &str| cands.iter().find(|c| c.name == n);
        assert!(
            find("old_parse").is_none(),
            "compiled-out branch must be dropped: {cands:?}"
        );
        let new_parse = find("new_parse").expect("active-branch function discovered");
        assert_eq!(new_parse.line, 4, "must report the ORIGINAL source line");
        let common = find("common_parse").expect("unconditional function discovered");
        assert_eq!(common.line, 6, "must report the ORIGINAL source line");

        // PreprocessMode::Never (the pre-§27.6 behavior): BOTH branches are parsed.
        let raw =
            discover_with_options(&root, &DirFilter::default(), PreprocessMode::Never).unwrap();
        assert!(
            raw.iter().any(|c| c.name == "old_parse") && raw.iter().any(|c| c.name == "new_parse"),
            "raw parse sees both #ifdef branches: {raw:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn auto_preprocess_fires_only_on_heavy_conditional_files() {
        // §27.6 Auto heuristic: a file gated by many `#if`s is preprocessed (the
        // inactive branch is dropped) under the default mode, while a file with a
        // lone header guard is parsed raw (zero behavior change).
        assert!(!should_preprocess(
            PreprocessMode::Auto,
            "#ifndef FOO_H\n#define FOO_H\nint parse(const char *p);\n#endif\n"
        ));
        let heavy = "#if A\nint a(void);\n#endif\n\
                     #if B\nint b(void);\n#endif\n\
                     #if C\nint c(void);\n#endif\n\
                     #ifdef D\nint d(void);\n#endif\n\
                     #ifdef E\nint e(void);\n#endif\n";
        assert!(should_preprocess(PreprocessMode::Auto, heavy));

        // End-to-end under the DEFAULT `discover` (Auto): the heavy-conditional file
        // has its inactive (undefined-macro) branches dropped.
        let root = tmpdir();
        fs::write(
            root.join("heavy.c"),
            "#ifdef HAVE_AVX2\nint avx_parse(const char *p, int n){return p[0]+n;}\n#endif\n\
             #ifdef HAVE_SSE\nint sse_parse(const char *p, int n){return p[1]+n;}\n#endif\n\
             #ifdef HAVE_NEON\nint neon_parse(const char *p, int n){return p[2]+n;}\n#endif\n\
             #ifndef NDEBUG\nint dbg_parse(const char *p, int n){return p[3]+n;}\n#endif\n\
             #if 0\nint dead_parse(const char *p, int n){return p[4]+n;}\n#endif\n\
             int scalar_parse(const char *p, int n){return p[5]+n;}\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        // The `#ifndef NDEBUG` branch IS active (NDEBUG undefined), so dbg_parse and
        // the unconditional scalar_parse are kept; the feature-gated + `#if 0`
        // branches are dropped.
        assert!(cands.iter().any(|c| c.name == "scalar_parse"), "{cands:?}");
        assert!(cands.iter().any(|c| c.name == "dbg_parse"), "{cands:?}");
        for dropped in ["avx_parse", "sse_parse", "neon_parse", "dead_parse"] {
            assert!(
                !cands.iter().any(|c| c.name == dropped),
                "{dropped} compiled out under Auto preprocessing: {cands:?}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dedupes_same_name_same_signature_definitions() {
        // #ifdef ladder: two identical-signature definitions of one
        // function in one file must yield one candidate, not two.
        let root = tmpdir();
        fs::write(
            root.join("ladder.c"),
            r#"
        #if defined(USE_FAST_PATH)
        int decode(const unsigned char *buf, unsigned long len) { return (int)len; }
        #else
        int decode(const unsigned char *buf, unsigned long len) { return buf ? 1 : (int)len; }
        #endif
        int decode_other(const unsigned char *buf, int len) { return len; }
        "#,
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        let decode_count = cands.iter().filter(|c| c.name == "decode").count();
        assert_eq!(
            decode_count, 1,
            "identical-signature ladder dedupes to one target: {cands:?}"
        );
        assert!(cands.iter().any(|c| c.name == "decode_other"));
    }

    #[test]
    fn amalgamated_single_header_dedupes_against_modular_tree() {
        // #28: nlohmann/json ships single_include/nlohmann/json.hpp — a byte-identical
        // concatenation of the modular include/nlohmann/*.hpp. Both copies surface
        // every function, so --max-targets fuzzes only a handful of distinct
        // functions, each twice. A candidate in an amalgamated single-header with a
        // modular twin is dropped (the modular copy is preferred).
        let root = tmpdir();
        fs::create_dir_all(root.join("include/lib")).unwrap();
        fs::create_dir_all(root.join("single_include/lib")).unwrap();
        let body =
            "int lib_parse(const char *data, unsigned long len) { return data ? (int)len : 0; }\n";
        fs::write(root.join("include/lib/parse.h"), body).unwrap();
        fs::write(root.join("single_include/lib/all.h"), body).unwrap();
        let cands = discover(&root).unwrap();
        let parse_cands: Vec<&Candidate> = cands.iter().filter(|c| c.name == "lib_parse").collect();
        assert_eq!(
            parse_cands.len(),
            1,
            "the amalgamated single-header copy must be deduped: {cands:?}"
        );
        assert!(
            !parse_cands[0]
                .source_path
                .components()
                .any(|c| c.as_os_str() == "single_include"),
            "the kept copy must be the modular one: {:?}",
            parse_cands[0].source_path
        );
    }

    #[test]
    fn single_header_only_function_is_kept() {
        // A function that exists ONLY in the amalgamated single-header (no modular
        // twin) must NOT be dropped.
        let root = tmpdir();
        fs::create_dir_all(root.join("single_include/lib")).unwrap();
        fs::write(
            root.join("single_include/lib/all.h"),
            "int only_here(const char *d, unsigned long n) { return d ? (int)n : 0; }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            cands.iter().any(|c| c.name == "only_here"),
            "a single-header-only function must be kept: {cands:?}"
        );
    }

    #[test]
    fn keeps_same_name_definitions_with_differing_signatures() {
        let root = tmpdir();
        fs::write(
            root.join("differs.c"),
            r#"
        #if defined(NEW_API)
        int decode(const unsigned char *buf, unsigned long len) { return (int)len; }
        #else
        int decode(const unsigned char *buf) { return buf ? 1 : 0; }
        #endif
        "#,
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        let decode_count = cands.iter().filter(|c| c.name == "decode").count();
        assert_eq!(
            decode_count, 2,
            "differing signatures are distinct targets: {cands:?}"
        );
    }

    #[test]
    fn harness_ids_do_not_collide_across_files_with_same_line() {
        let root = tmpdir();
        fs::write(
            root.join("a.c"),
            "int parse_a(const unsigned char *d, unsigned long n) { return (int)n; }\n",
        )
        .unwrap();
        fs::write(
            root.join("b.c"),
            "int parse_b(const unsigned char *d, unsigned long n) { return (int)n; }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert_eq!(cands.len(), 2);
        assert_ne!(
            cands[0].harness_id, cands[1].harness_id,
            "two functions at the same line in different files must NOT share a harness_id"
        );
    }

    #[test]
    fn skips_excluded_dirs() {
        let root = tmpdir();
        fs::create_dir_all(root.join("generated_harnesses/H-X")).unwrap();
        fs::write(
            root.join("generated_harnesses/H-X/main.c"),
            "int govfuzz_run_one(const unsigned char *d, unsigned long n) { return 0; }\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            !cands.iter().any(|c| c.name == "govfuzz_run_one"),
            "generated harnesses must be skipped: {cands:?}"
        );
    }

    #[test]
    fn skips_candidates_from_non_standalone_fragment_headers() {
        // A function defined in a `*-inl.h` / `*.inc.hpp` fragment (simdjson/ctre)
        // is not standalone-includable; don't target it (the umbrella header is
        // the real entry point).
        let root = tmpdir();
        fs::write(
            root.join("parser-inl.h"),
            "inline int frag_parse(const unsigned char *d, unsigned long n){return d&&n?d[0]:0;}\n",
        )
        .unwrap();
        fs::write(
            root.join("parser.h"),
            "int real_parse(const unsigned char *d, unsigned long n);\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            !cands.iter().any(|c| c.name == "frag_parse"),
            "fragment-header function must not be a candidate: {cands:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn tags_foreign_platform_ada_bodies_as_cross_target_not_dropped() {
        // gnatcoll's `gnatcoll-mmap-system__win32.ads` can't build natively on
        // Linux, but it is real attack surface on Windows: it stays DISCOVERED,
        // tagged with a `foreign_guard` so the build cross-compiles + qemu-runs it
        // — never hidden. The portable `__unix` variant is native here (untagged).
        let root = tmpdir();
        fs::write(
            root.join("pkg__win32.ads"),
            "package Pkg is\n   function Read_File return Integer;\nend Pkg;\n",
        )
        .unwrap();
        fs::write(
            root.join("other__unix.ads"),
            "package Other is\n   function Poll return Integer;\nend Other;\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        let win = cands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("Read_File"));
        assert!(
            win.is_some(),
            "win32 Ada body discovered, not dropped: {cands:?}"
        );
        assert_eq!(
            win.unwrap().foreign_guard.as_deref(),
            Some("win32"),
            "win32 Ada body tagged as a cross-target: {cands:?}"
        );
        let unix = cands.iter().find(|c| c.name.eq_ignore_ascii_case("Poll"));
        assert!(unix.is_some(), "unix Ada body kept on Linux: {cands:?}");
        assert_eq!(
            unix.unwrap().foreign_guard,
            None,
            "native unit is not tagged: {cands:?}"
        );
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn tags_foreign_arch_simd_backends_as_cross_target_not_dropped() {
        // simdjson's per-arch backends (src/arm64, src/ppc64) can't compile on an
        // x86 host, but they are real attack surface on those ISAs: discovered +
        // ranked + tagged so the build cross-compiles + runs them under qemu-user.
        // The host arch and the generic/portable impl are native (untagged).
        let root = tmpdir();
        for (dir, fname, fnname) in [
            ("src/generic", "compute.c", "gen_compute"),
            ("src/x86_64", "avx2.c", "x86_compute"),
            ("src/arm64", "neon.c", "arm_compute"),
            ("src/ppc64", "vsx.c", "ppc_compute"),
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
            fs::write(
                root.join(dir).join(fname),
                format!("int {fnname}(const unsigned char *d, unsigned long n) {{ return d && n ? d[0] : 0; }}\n"),
            )
            .unwrap();
        }
        let cands = discover(&root).unwrap();
        let guard = |n: &str| {
            cands
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.foreign_guard.clone())
        };
        assert_eq!(
            guard("gen_compute"),
            Some(None),
            "generic impl kept, native: {cands:?}"
        );
        assert_eq!(
            guard("x86_compute"),
            Some(None),
            "host-arch impl kept, native: {cands:?}"
        );
        assert_eq!(
            guard("arm_compute"),
            Some(Some("arm64".to_owned())),
            "arm64 backend discovered + tagged, not dropped: {cands:?}"
        );
        assert_eq!(
            guard("ppc_compute"),
            Some(Some("ppc64".to_owned())),
            "ppc64 backend discovered + tagged, not dropped: {cands:?}"
        );
    }

    #[test]
    fn skips_body_local_ada_subprograms() {
        // Body-local helpers (and nested subprograms) have no exported symbol,
        // so a direct-call harness that `with`s the package cannot name them.
        // Discovery must keep the spec-declared public op and drop the helper.
        let root = tmpdir();
        fs::write(
            root.join("pkg.ads"),
            "package Pkg is\n   procedure Public_Op (X : Integer);\nend Pkg;\n",
        )
        .unwrap();
        fs::write(
            root.join("pkg.adb"),
            "package body Pkg is\n   procedure Public_Op (X : Integer) is\n\
             \x20     procedure Local_Helper is\n      begin\n         null;\n\
             \x20     end Local_Helper;\n   begin\n      Local_Helper;\n   end Public_Op;\n\
             end Pkg;\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            cands.iter().any(|c| c.name == "public_op"),
            "spec-declared public subprogram must be discovered: {cands:?}"
        );
        assert!(
            !cands.iter().any(|c| c.name == "local_helper"),
            "body-local helper must not be a candidate: {cands:?}"
        );
    }

    #[test]
    fn skips_public_subprograms_declared_in_specs_nested_inside_a_body() {
        // `package Meth is procedure Copy_Stored; end` declared INSIDE a
        // procedure body: Copy_Stored is `Public` within that nested spec but
        // has no external symbol. Such nested specs only appear in .adb files,
        // so discovery must not offer them as direct-call candidates (otherwise
        // the harness fails to link with "missing Ada symbol").
        let root = tmpdir();
        fs::write(
            root.join("outer.adb"),
            "package body Outer is\n\
             \x20  procedure Decompress is\n\
             \x20     package Meth is\n\
             \x20        procedure Copy_Stored;\n\
             \x20     end Meth;\n\
             \x20     package body Meth is\n\
             \x20        procedure Copy_Stored is begin null; end Copy_Stored;\n\
             \x20     end Meth;\n\
             \x20  begin\n\
             \x20     null;\n\
             \x20  end Decompress;\n\
             end Outer;\n",
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(
            !cands.iter().any(|c| c.name == "copy_stored"),
            "subprogram in a spec nested inside a body must not be a candidate: {cands:?}"
        );
    }

    #[test]
    fn keeps_standalone_adb_unit_but_drops_body_with_sibling_spec() {
        // A standalone procedure body (no sibling .ads) is a real library-level
        // compilation unit and must still be discovered. The same library-level
        // shape in a .adb that *has* a sibling .ads is a spec-completion
        // duplicate (or a parser-mis-scoped nested proc) and must be dropped -
        // the callable surface comes from the .ads.
        let root = tmpdir();
        fs::write(
            root.join("standalone.adb"),
            "procedure Standalone (X : Integer) is\nbegin\n   null;\nend Standalone;\n",
        )
        .unwrap();
        // Paired unit: spec declares Paired_Op; body completes it.
        fs::write(
            root.join("paired.ads"),
            "procedure Paired_Op (X : Integer);\n",
        )
        .unwrap();
        fs::write(
            root.join("paired.adb"),
            "procedure Paired_Op (X : Integer) is\nbegin\n   null;\nend Paired_Op;\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        assert!(
            cands.iter().any(|c| c.name == "standalone"),
            "standalone .adb unit must be discovered: {cands:?}"
        );
        assert_eq!(
            cands.iter().filter(|c| c.name == "paired_op").count(),
            1,
            "paired spec/body must yield exactly one candidate (from the .ads): {cands:?}"
        );
        assert!(
            cands
                .iter()
                .find(|c| c.name == "paired_op")
                .is_some_and(|c| c.source_path.extension().is_some_and(|e| e == "ads")),
            "the surviving paired_op candidate must be the .ads one: {cands:?}"
        );
    }

    #[test]
    fn gpr_main_excludes_the_main_body_but_keeps_sibling_library_units() {
        // A `.gpr` declaring `for Main use ("tool.adb")` marks `tool.adb` as a
        // PROGRAM ENTRY POINT (it `with`s the library and runs), not a library
        // subprogram a direct-call harness can name. The gpr-Main parser must
        // resolve that specific source file (via the project's Source_Dirs) so the
        // attempt loop can pre-skip it — while a sibling library unit in the same
        // directory is NOT marked. The parser must tolerate the value list spanning
        // lines and a path-or-bare-name entry.
        let root = tmpdir();
        // Project file: source dir + a multi-line Main list with one bare name and
        // one path entry. Only `tool.adb` exists; `missing.adb` must not match.
        fs::write(
            root.join("checkers.gpr"),
            "with \"lib\";\n\
             project Checkers is\n\
             \x20  for Source_Dirs use (\"src\");\n\
             \x20  for Main use (\"tool.adb\",\n\
             \x20                 \"src/missing.adb\");\n\
             end Checkers;\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        // The Main body: a standalone procedure (the CLI entry point).
        fs::write(
            root.join("src/tool.adb"),
            "procedure Tool is\nbegin\n   null;\nend Tool;\n",
        )
        .unwrap();
        // A sibling library unit in the SAME directory — must NOT be marked.
        fs::write(
            root.join("src/lib.ads"),
            "package Lib is\n   procedure Do_It (X : Integer);\nend Lib;\n",
        )
        .unwrap();

        let mains = gpr_main_sources(&root, &DirFilter::default());
        let tool = root
            .join("src/tool.adb")
            .canonicalize()
            .expect("tool.adb exists");
        let lib = root
            .join("src/lib.ads")
            .canonicalize()
            .expect("lib.ads exists");
        assert_eq!(
            mains.get(&tool).map(String::as_str),
            Some("checkers.gpr"),
            "the Main body must be marked with the declaring gpr: {mains:?}"
        );
        assert!(
            !mains.contains_key(&lib),
            "a sibling library unit must NOT be marked as a Main: {mains:?}"
        );
        assert_eq!(
            mains.len(),
            1,
            "only the one existing Main resolves: {mains:?}"
        );

        // Discovery still surfaces BOTH as candidates (the exclusion is a precise
        // attempt-time skip, not a discovery drop), so the Main shows as `skipped`
        // rather than vanishing.
        let cands = discover(&root).unwrap();
        assert!(
            cands.iter().any(|c| c.name == "tool"),
            "the Main subprogram is still discovered (skipped later): {cands:?}"
        );
        assert!(
            cands.iter().any(|c| c.name == "do_it"),
            "the sibling library subprogram is discovered: {cands:?}"
        );

        // A tree with no Main attribute yields an empty map (changes nothing).
        let empty = tmpdir();
        fs::write(
            empty.join("lib_only.gpr"),
            "library project Lib_Only is\n   for Source_Dirs use (\"src\");\nend Lib_Only;\n",
        )
        .unwrap();
        assert!(
            gpr_main_sources(&empty, &DirFilter::default()).is_empty(),
            "no `for Main` → empty map → nothing skipped"
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn discovers_targets_in_latin1_encoded_legacy_source() {
        // Legacy Ada/C frequently ships as Latin-1 (accented author names,
        // copyright glyphs). Such files must not be silently dropped: the
        // structural code is still ASCII and contains real fuzzable targets.
        let root = tmpdir();
        let mut bytes = b"-- Auteur: Fran".to_vec();
        bytes.push(0xE7); // 'c-cedilla' in Latin-1, invalid lone byte in UTF-8
        bytes.push(0xEF); // i-diaeresis
        bytes.extend_from_slice(
            b"s\nfunction Demodulate (Sample : Integer) return Integer is\n\
              begin\n   return Sample;\nend Demodulate;\n",
        );
        let ada = root.join("radar.adb");
        fs::write(&ada, &bytes).unwrap();
        // And the same for a C file with a high byte in a comment.
        let mut cbytes = b"/* \xB0 degrees */\n".to_vec();
        cbytes.extend_from_slice(
            b"int decode_frame(const unsigned char *d, unsigned long n) { return (int)n; }\n",
        );
        fs::write(root.join("comms.c"), &cbytes).unwrap();

        let cands = discover(&root).unwrap();
        // Ada is case-insensitive; the parser normalizes subprogram names to
        // lower case.
        assert!(
            cands.iter().any(|c| c.name == "demodulate"),
            "Latin-1 Ada subprogram must still be discovered: {cands:?}"
        );
        assert!(
            cands.iter().any(|c| c.name == "decode_frame"),
            "Latin-1 C function must still be discovered: {cands:?}"
        );
    }

    #[test]
    fn pure_c_header_with_cpp_words_in_comments_is_classified_c() {
        // Campaign #42: yyjson.h is pure C but says "operator" 26x and
        // "class"/"template"/"namespace" in DOC COMMENTS. The raw-substring marker
        // scan misclassified it as C++ (then built 85 fns as C++ with fabricated
        // scope-qualified names). Comments/strings are stripped before the scan.
        let src = r#"
            /* yyjson value reader.
             * The bitwise operator | combines flags; use the >> operator to shift.
             * This is not a class, and there is no template or namespace here.
             * Even "operator==" and "class Foo" inside this comment must be ignored. */
            #ifndef YYJSON_H
            #define YYJSON_H
            const char *yyjson_get_str(void *val);  /* operator note */
            size_t yyjson_get_len(void *val);
            #endif
        "#;
        assert!(
            !header_looks_like_cpp(src),
            "pure-C header with C++ words only in comments must not look like C++"
        );
        assert_eq!(classify_c_header(src), Lang::C);
    }

    #[test]
    fn real_cpp_header_markers_still_classify_cpp() {
        assert!(header_looks_like_cpp("namespace ns { int f(); }"));
        assert!(header_looks_like_cpp("class Widget { public: int x; };"));
        assert!(header_looks_like_cpp("template <typename T> T id(T x);"));
        assert!(header_looks_like_cpp(
            "struct V { bool operator==(const V &o) const; };"
        ));
        // ...but an identifier that merely CONTAINS a keyword/`operator` is not C++.
        assert!(!header_looks_like_cpp(
            "int operator_count;\nvoid use_operator(void);\nint classid;\n"
        ));
    }

    #[test]
    fn preprocess_zeroing_out_all_functions_falls_back_to_raw_parse() {
        // #2 campaign (mpack): a whole-file `#if FEATURE` gate whose macro is
        // default-defined to 1 in a header this .c does not inline evaluates false
        // under the CPP-lite preprocessor, stripping every function to zero — a
        // silent false-clean. The fallback must re-parse raw so the real API is
        // discovered rather than the file reading as empty.
        let source = "#if MPACK_READER\n\
                      int mpack_reader_init(int x) { return x; }\n\
                      int mpack_read_u8(int x) { return x + 1; }\n\
                      #endif\n";
        let fns = parse_c_functions_preprocessed(source, PreprocessMode::Always).unwrap();
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"mpack_reader_init") && names.contains(&"mpack_read_u8"),
            "preprocessing zeroed all functions; raw fallback must recover them, got {names:?}"
        );
    }
}
