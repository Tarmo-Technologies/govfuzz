// SPDX-License-Identifier: Apache-2.0

use crate::auto::candidate::{Candidate, Lang};
use ada_parser::ast::Visibility;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
fn should_preprocess(mode: PreprocessMode, source: &str, has_project_context: bool) -> bool {
    match mode {
        PreprocessMode::Always => true,
        PreprocessMode::Never => false,
        // CPP-lite cannot follow included config headers or compiler built-ins.
        // Without an explicit per-TU project macro context it can silently choose
        // the wrong branch, so the default keeps raw discovery/generation in the
        // same world. `Always` remains an explicit best-effort override.
        PreprocessMode::Auto => {
            has_project_context
                && conditional_directive_count(source) >= HEAVY_CONDITIONAL_THRESHOLD
        }
    }
}

fn compile_database_preprocessor_defines(path: &Path) -> Vec<(String, String)> {
    let flags = crate::generate_harness::compile_database_flags_for_source(path);
    let mut defines = Vec::new();
    let mut index = 0usize;
    while index < flags.len() {
        let flag = &flags[index];
        let value = if flag == "-D" {
            index += 1;
            flags.get(index).map(String::as_str)
        } else {
            flag.strip_prefix("-D")
        };
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            let (name, replacement) = value
                .split_once('=')
                .map_or((value, "1"), |(name, replacement)| (name, replacement));
            if !name.is_empty() {
                defines.push((name.to_owned(), replacement.to_owned()));
            }
        }
        index += 1;
    }
    defines.sort();
    defines.dedup();
    defines
}

/// Parse `source` for C functions under `mode`, returning each function with its
/// line number translated back to the ORIGINAL source (§27.6). When preprocessing
/// is off (or the source has no heavy conditional compilation) this is exactly
/// `c_parser::parse_c_functions` on the raw text with identity line numbers.
fn parse_c_functions_preprocessed(
    source: &str,
    mode: PreprocessMode,
    defines: &[(String, String)],
) -> Result<Vec<c_parser::CFunction>, c_parser::CParseError> {
    if should_preprocess(mode, source, !defines.is_empty()) {
        let (pp, line_map) = idl_parser::preprocess_c_like_with_line_map(source, defines);
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
                gfeprintln!(
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
    defines: &[(String, String)],
) -> Result<Vec<cpp_parser::CppFunction>, cpp_parser::CppParseError> {
    if should_preprocess(mode, source, !defines.is_empty()) {
        let (pp, line_map) = idl_parser::preprocess_c_like_with_line_map(source, defines);
        let mut fns = cpp_parser::parse_cpp_functions(&pp)?;
        for f in &mut fns {
            f.line = line_map.to_original(f.line);
        }
        if fns.is_empty() {
            let raw = cpp_parser::parse_cpp_functions(source)?;
            if !raw.is_empty() {
                gfeprintln!(
                    "govfuzz auto: note: C++ preprocessing removed all {} discoverable \
                     function(s); using the raw parse because the conditional context is incomplete",
                    raw.len()
                );
                return Ok(raw);
            }
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
const CONCURRENCY_DEMOTION: i32 = 1_000_000;
const KNOWN_UNBUILDABLE_SIGNATURE_DEMOTION: i32 = 1_000_000;

fn ada_unit_has_concurrency(path: &Path, source: &str) -> bool {
    if crate::generate_harness::ada_concurrency_block_summary(source).is_some() {
        return true;
    }
    let sibling = match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("ads") => path.with_extension("adb"),
        Some(extension) if extension.eq_ignore_ascii_case("adb") => path.with_extension("ads"),
        _ => return false,
    };
    crate::source_text::read_source_text(&sibling)
        .ok()
        .is_some_and(|text| crate::generate_harness::ada_concurrency_block_summary(&text).is_some())
}

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

    /// The same filter with the ORGANIZATIONAL name heuristics (`app/`, `cli/`,
    /// `tools/`, `bin/`, `examples/`, ...) admitted, keeping the hard exclusions
    /// (VCS, build output, vendored code, test and fuzz directories) and every
    /// user-supplied `--exclude-dir`. `None` when the caller already opted every
    /// organizational name back in, so there is nothing to relax.
    fn without_organizational_exclusions(&self) -> Option<Self> {
        let mut keep = self.keep.clone();
        let mut added = false;
        for name in ORGANIZATIONAL_DIR_NAMES {
            if keep.insert((*name).to_owned()) {
                added = true;
            }
        }
        added.then(|| Self {
            extra_excludes: self.extra_excludes.clone(),
            keep,
            work_dir: self.work_dir.clone(),
        })
    }
}

/// Languages that discovery found NOTHING for, but whose source files sit under
/// a directory the organizational heuristic excluded. Deliberately conservative:
/// only a language with zero candidates is reconsidered, so a project with a
/// real library plus an `examples/` directory is unaffected.
fn languages_lost_to_exclusions(
    root: &Path,
    found: &[Candidate],
    relaxed: &DirFilter,
    _preprocess: PreprocessMode,
) -> std::collections::HashSet<Lang> {
    use std::collections::HashSet;
    let have: HashSet<Lang> = found.iter().map(|c| c.lang).collect();
    let mut lost: HashSet<Lang> = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut files_seen = 0usize;
    while let Some(dir) = stack.pop() {
        // A census, not a parse: bounded so this can never dominate discovery.
        if files_seen > 20_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if !is_excluded_dir(&path, relaxed) {
                    stack.push(path);
                }
                continue;
            }
            files_seen += 1;
            if !has_targetable_extension_only(&path) {
                continue;
            }
            if let Some(lang) = extension_lang_hint(&path) {
                if !have.contains(&lang) {
                    lost.insert(lang);
                }
            }
        }
    }
    lost
}

/// The lane an extension implies, without reading the file.
///
/// The single extension table: [`detect_lang`] adds only the cases that need
/// the file's contents (a `.h` can be either C or C++) or its full path (a
/// `.d.ts` declares types and has no runtime code). A bare `.h` is deliberately
/// absent here, since a header alone does not establish that C code exists.
fn extension_lang_hint(path: &Path) -> Option<Lang> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    if ext == "C" {
        return Some(Lang::Cpp);
    }
    match ext.to_ascii_lowercase().as_str() {
        "ads" | "adb" => Some(Lang::Ada),
        "c" => Some(Lang::C),
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
        "ts" | "tsx" | "mts" | "cts" => Some(Lang::Ts),
        "rb" => Some(Lang::Ruby),
        "lua" => Some(Lang::Lua),
        "php" => Some(Lang::Php),
        _ => None,
    }
}

/// Directory names excluded because of what they usually CONTAIN (driver or
/// demo code), as opposed to what they always are (VCS, build output, vendored
/// third-party code, tests). Only these are reconsidered when a language would
/// otherwise be discovered as empty.
const ORGANIZATIONAL_DIR_NAMES: &[&str] = &[
    "app",
    "apps",
    "bin",
    "cli",
    "tool",
    "tools",
    "program",
    "programs",
    "src-tauri",
    "demo",
    "demos",
    "example",
    "examples",
    "sample",
    "samples",
    "script",
    "scripts",
    "utils",
    "util",
];

/// Whether a C/C++ function NAME is really a macro invocation parsed as a
/// definition — multi-segment ALL-CAPS, the universal convention for macros.
///
/// Linux's tracepoint headers are the clearest case: `TRACE_EVENT(mcu_cmd_info,
/// TP_PROTO(...), TP_ARGS(...), TP_STRUCT__entry(...), ...)` at file scope parses
/// as a function named `TRACE_EVENT` whose parameter TYPES are the macro's
/// arguments. There is no such symbol to link, so the harness can never build —
/// lede produced two of these among ten ranked targets.
///
/// Requiring an underscore keeps single-word ALL-CAPS names that really are
/// functions: BLAS/LAPACK expose `DGEMM`/`SGEMV`, and Fortran-bound wrappers are
/// spelled that way on purpose.
fn is_macro_invocation_name(name: &str) -> bool {
    name.len() >= 3
        && name.contains('_')
        && name.chars().any(|ch| ch.is_ascii_uppercase())
        && name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

/// Source lines (1-based) that belong to a multi-line `#define` body.
///
/// A function declarator inside one is a macro TEMPLATE, not a function: BSD's
/// `<sys/tree.h>` / `<sys/queue.h>` families define whole function bodies inside
/// `RB_GENERATE_INSERT(name, type, field, cmp, attr)`, so tree-sitter sees
///
/// ```text
/// attr struct type *                                          \
/// name##_RB_INSERT(struct name *head, struct type *elm)       \
/// ```
///
/// as a function returning `attr struct type *`. It is not one — `attr`, `type`
/// and `name` are macro PARAMETERS and the symbol `name##_RB_INSERT` does not
/// exist until expansion. Harnessing it emitted `attr struct type * R = ...`,
/// which clang rejects with "cannot combine with previous 'type-name'
/// declaration specifier"; no repair can fix it, because nothing is missing.
/// tmux's compat/tree.h alone produced seven such dead targets.
fn macro_definition_body_lines(source: &str) -> std::collections::HashSet<u32> {
    let mut lines = std::collections::HashSet::new();
    let mut continuing = false;
    for (index, line) in source.lines().enumerate() {
        let number = index as u32 + 1;
        let starts_define = line.trim_start().starts_with('#')
            && line
                .trim_start()
                .trim_start_matches('#')
                .trim_start()
                .starts_with("define");
        if continuing || starts_define {
            lines.insert(number);
        }
        // A trailing backslash continues the directive onto the next line. Only
        // meaningful once we are in (or starting) a define.
        continuing = (continuing || starts_define) && line.trim_end().ends_with('\\');
    }
    lines
}

/// Temper a signature-derived reachability verdict with the target's LINKAGE.
///
/// `classify_input_reachability` reads parameter shapes and names, so a
/// file-local helper taking `const char *` looks exactly like a public parser
/// and is labelled `AttackerReachable`. It is not: a `static` function has no
/// external linkage, so nothing outside its translation unit can call it and no
/// attacker can reach it directly. It may still be reachable THROUGH a public
/// caller, which is precisely `ReachabilityUnproven`.
///
/// This changes only the claim, never the ranking — an internal helper is still
/// worth fuzzing. Measured on libexpat, where the file-local `matchkey`,
/// `xcslen` and `attlist2` were each reported `critical` and
/// `attacker_reachable`, having been driven directly by the harness with
/// fabricated arguments no public caller would pass.
fn reachability_for_linkage(
    reachability: target_rank::InputReachability,
    is_static: bool,
) -> target_rank::InputReachability {
    if is_static && reachability == target_rank::InputReachability::AttackerReachable {
        return target_rank::InputReachability::ReachabilityUnproven;
    }
    reachability
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
    // Parsing is recursive over the syntax tree, and real source contains
    // expressions deep enough to exhaust the 8 MiB a main thread gets: vllm's
    // `csrc/cpu/cpu_types_arm.hpp` aborted the whole run with "fatal runtime
    // error: stack overflow" during discovery, taking milvus with it. A tool
    // pointed at an estate has to survive every tree in it, so discovery runs on
    // a thread with room to recurse. The stack is reserved, not committed, so
    // the cost is address space rather than memory.
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .name("govfuzz-discovery".to_owned())
            .stack_size(DISCOVERY_STACK_BYTES)
            .spawn_scoped(scope, || discover_on_this_stack(root, filter, preprocess))
        {
            Ok(handle) => match handle.join() {
                Ok(result) => result,
                // A panic inside discovery is already reported by the panic hook;
                // surface it as an error rather than re-panicking the caller.
                Err(_) => Err(anyhow::anyhow!(
                    "discovery panicked while indexing {}",
                    root.display()
                )),
            },
            // If the thread cannot be spawned, index on this stack instead of
            // failing the run outright.
            Err(_) => discover_on_this_stack(root, filter, preprocess),
        }
    })
}

fn discover_on_this_stack(
    root: &Path,
    filter: &DirFilter,
    preprocess: PreprocessMode,
) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    let _tw = std::time::Instant::now();
    walk(root, &mut out, filter, preprocess)?;
    gfprof("disc:walk", _tw);
    // The organizational-directory heuristic (`app/`, `tools/`, `cli/`, `bin/`)
    // assumes the library lives elsewhere and those directories only hold demo
    // or driver code. When a project IS one of them — scrcpy keeps its entire C
    // client under `app/` — the heuristic discovers zero C candidates in a C
    // project, and the whole sweep then runs on the Android server's Java.
    // Excluding your way to nothing is never right: retry the languages that
    // came back empty with those directories admitted.
    let _tx = std::time::Instant::now();
    if let Some(relaxed) = filter.without_organizational_exclusions() {
        let empty_langs = languages_lost_to_exclusions(root, &out, &relaxed, preprocess);
        gfprof("disc:lost_langs", _tx);
        if !empty_langs.is_empty() {
            let mut recovered = Vec::new();
            walk(root, &mut recovered, &relaxed, preprocess)?;
            let before = out.len();
            out.extend(
                recovered
                    .into_iter()
                    .filter(|c| empty_langs.contains(&c.lang)),
            );
            if out.len() > before {
                let names: Vec<String> =
                    empty_langs.iter().map(|lang| format!("{lang:?}")).collect();
                gfeprintln!(
                    "govfuzz auto: {} candidate(s) recovered from organizational \
                     directories: {} code lives only there, so excluding them found nothing",
                    out.len() - before,
                    names.join("/"),
                );
            }
        }
    }
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
        let mut cpp_sig_access = std::collections::BTreeMap::new();
        let _tm = std::time::Instant::now();
        // This is a SECOND full pass over the tree — it reads and parses every
        // C++ file again — so it gets the same treatment as the main walk:
        // parallel, and bounded by the same deadline. Left sequential and
        // unbounded it was pure overshoot past the discovery ceiling.
        let mut files = Vec::new();
        let _ = collect_walk_files(root, filter, &mut files);
        let deadline = deadline();
        let per_file: Vec<(
            std::collections::BTreeMap<String, String>,
            std::collections::BTreeMap<String, String>,
        )> = discovery_pool().install(|| {
            files
                .par_iter()
                .map(|path| {
                    let mut access = std::collections::BTreeMap::new();
                    let mut sig = std::collections::BTreeMap::new();
                    if deadline.is_none_or(|deadline| std::time::Instant::now() < deadline) {
                        accumulate_cpp_member_access(path, &mut access, &mut sig);
                    }
                    (access, sig)
                })
                .collect()
        });
        // Merged in file order, so a later file overrides an earlier one exactly
        // as the sequential walk did.
        for (access, sig) in per_file {
            cpp_access.extend(access);
            cpp_sig_access.extend(sig);
        }
        gfprof("disc:cpp_access", _tm);
        out.retain(|c| {
            if !matches!(c.lang, Lang::Cpp) {
                return true;
            }
            // #98: exact-signature access first. When the candidate's full signature
            // (`Class::method(normalized params)`) resolves to a non-public overload,
            // drop it — targeting a private overload that has a public sibling is a
            // guaranteed build failure ("is a private member"). This fires ONLY on a
            // confirmed private/protected exact-signature match; any format mismatch
            // (lookup miss) falls through to the by-name check below, so it can only
            // improve, never over-filter.
            if let Some(access) = cpp_sig_access.get(&c.name) {
                if access == "private" || access == "protected" {
                    return false;
                }
            }
            // The by-name access index retains the complete namespace/class identity.
            // If overloads of the same qualified method have different access, its
            // value is deliberately `ambiguous` and discovery keeps the target;
            // generation resolves the exact parameter signature later.
            let full = c.name.split('(').next().unwrap_or(&c.name).trim();
            cpp_access
                .get(full)
                .is_none_or(|access| access == "public" || access == "ambiguous")
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
    dedup_ada_spec_body_candidates(&mut out);
    apply_entrypoint_callgraph(&mut out);
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// #92: collapse Ada candidates for the SAME subprogram of the SAME unit that were
/// discovered from BOTH a spec (`.ads`) and a body (`.adb`) in DIFFERENT
/// directories (a spec under `src/interface`, its body under `src/implementation`).
/// The per-file discovery gate only suppresses a body whose spec is a SAME-DIR
/// sibling, so a split spec/body layout otherwise yields two candidates for one
/// logical target. Keep the public SPEC candidate — it is the externally callable
/// declaration a separately compiled harness `with`s — so discovery and the build
/// share one deterministic unit closure. Ada unit identity is approximated by the
/// GNAT on-disk convention (filename stem, dashes = child-unit dots), which is
/// what `with`/source lookup already relies on.
fn dedup_ada_spec_body_candidates(candidates: &mut Vec<Candidate>) {
    use std::collections::HashSet;
    fn ada_unit(candidate: &Candidate) -> Option<String> {
        if candidate.lang != Lang::Ada {
            return None;
        }
        let stem = candidate.source_path.file_stem()?.to_str()?;
        Some(stem.to_ascii_lowercase().replace('-', "."))
    }
    fn is_spec(candidate: &Candidate) -> bool {
        candidate
            .source_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ads"))
    }
    // (unit, subprogram) pairs that already have a SPEC-derived candidate.
    let spec_keys: HashSet<(String, String)> = candidates
        .iter()
        .filter(|c| is_spec(c))
        .filter_map(|c| Some((ada_unit(c)?, c.name.to_ascii_lowercase())))
        .collect();
    if spec_keys.is_empty() {
        return;
    }
    candidates.retain(|c| {
        if c.lang != Lang::Ada || is_spec(c) {
            return true;
        }
        match ada_unit(c) {
            Some(unit) => !spec_keys.contains(&(unit, c.name.to_ascii_lowercase())),
            None => true,
        }
    });
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
    source_fingerprint_with_files(root, filter).0
}

/// The tree digest AND the per-file content hashes, from ONE walk.
///
/// `--resume` needs the per-file view because FUZZING CAN CHANGE THE TREE: a
/// target that writes or rewrites a file with a source extension (a code
/// generator, a compiler, anything emitting `.c`/`.py`/`.ts` into the checkout)
/// makes a run invalidate its OWN digest. The next `--resume` concluded "the
/// source changed", discarded every completed target and re-ran the lot; once
/// that target had run again and the file settled, the run after it matched —
/// the reported "resume only works the second time".
///
/// The per-file hashes are a by-product of the digest walk, so this costs one
/// walk, not two: the entries were being computed and thrown away already.
pub fn source_fingerprint_with_files(
    root: &Path,
    filter: &DirFilter,
) -> (String, Vec<(String, u64)>) {
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
    let digest = format!("{:016x}", hasher.finish());
    // One u64 per file: the length folded into the content hash. Cheaper to hold
    // and to persist than the triple, and enough to answer "did this file move?".
    let files = entries
        .into_iter()
        .map(|(rel, len, content)| (rel, len ^ content.rotate_left(1)))
        .collect();
    (digest, files)
}

/// #101: fingerprint the BUILD context — the files and options that change how a
/// target is BUILT, distinct from the source identity that [`source_fingerprint`]
/// covers. Editing a GPR, compile_commands.json, an IDL, or a harness-affecting
/// option changes this digest even when the targetable source (and the discovery
/// cache) is unchanged, so `--resume` re-attempts completed targets rather than
/// serving stale results. `knobs` folds in the selected project + decoder limits +
/// stubbing policy + engines/passes + sanitizer mode + harness flags. Documentation
/// (README, etc.) and excluded build artifacts are ignored (not build files).
pub fn build_context_fingerprint(root: &Path, knobs: &str) -> String {
    use std::hash::{Hash, Hasher};
    // (relative-path, content-hash) for every build-context file under `root`.
    let mut files: Vec<(String, u64)> = Vec::new();
    collect_build_context_files(root, root, 0, &mut files);
    files.sort();

    let mut hasher = StableHasher::new();
    "build_files".hash(&mut hasher);
    files.len().hash(&mut hasher);
    for (rel, content) in &files {
        rel.hash(&mut hasher);
        content.hash(&mut hasher);
    }
    // Effective build options: changing any of these changes the build even when
    // no file changed, so they must change the fingerprint too.
    "knobs".hash(&mut hasher);
    knobs.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Whether `path` is a build-context file: a compile database, GNAT project, or
/// IDL — the inputs that change how govfuzz recovers a build.
fn is_build_context_file(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) == Some("compile_commands.json") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("gpr") | Some("idl")
    )
}

/// Bounded recursive collector for [`build_context_fingerprint`]: hashes each
/// build-context file's content. Skips VCS, the govfuzz work dir, and common
/// build-output dirs so the digest stays bounded and stable.
fn collect_build_context_files(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(String, u64)>,
) {
    use std::hash::{Hash, Hasher};
    if depth > 12 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                ".git" | ".hg" | ".svn" | "govfuzz_work" | "target" | "node_modules"
            ) {
                continue;
            }
            collect_build_context_files(base, &path, depth + 1, out);
        } else if is_build_context_file(&path) {
            if let Ok(bytes) = std::fs::read(&path) {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let mut content = StableHasher::new();
                bytes.hash(&mut content);
                out.push((rel, content.finish()));
            }
        }
    }
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
            // Identity is CONTENT, not mtime (see `source_fingerprint`). Hash in
            // fixed-size chunks rather than `fs::read`-ing the whole file: the
            // fingerprint walk runs before the guarded parser read, so a single
            // giant generated source must not transiently allocate its full size.
            let (len, content) = hash_file(&path).unwrap_or((0, 0));
            out.push((rel, len, content));
        }
    }
}

fn hash_file(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::hash::{Hash, Hasher};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut hasher = StableHasher::new();
    // Match the logical shape of hashing a byte slice: length, then contents.
    (len as usize).hash(&mut hasher);
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.write(&buf[..read]);
    }
    Ok((len, hasher.finish()))
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
/// The project's OWN fuzz harnesses — the ones discovery deliberately excludes
/// from being targets.
///
/// They are excluded for a good reason (a project's harness must not out-rank
/// its parser), but excluding them also threw away the fact of their existence.
/// They are the only expert baseline there is: a govfuzz run over a tree that
/// ships them can be compared against what its own maintainers wrote, which is
/// the difference between "1,400 lines" and "1,400 of the 4,413 an expert
/// reaches".
///
/// Enumeration only. BUILDING them is deliberately not automated: each project
/// needs its own flags, generated config headers and disabled optional backends,
/// and a wrong build would silently produce a baseline that measures the build
/// rather than the harness.
pub fn existing_harness_sources(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    // Bounded like every other tree walk here: this is a reporting nicety and
    // must never dominate discovery.
    let mut budget = 20_000usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 {
                break;
            }
            let path = entry.path();
            if path.is_dir() {
                let skip = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with('.') || n == "target" || n == "node_modules")
                    .unwrap_or(false);
                if !skip {
                    stack.push(path);
                }
                continue;
            }
            budget -= 1;
            let is_source = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e, "c" | "cc" | "cpp" | "cxx" | "rs" | "java"))
                .unwrap_or(false);
            if !is_source {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            // The three entry points a project's own harness uses: libFuzzer's
            // C/C++ one, cargo-fuzz's macro, and Jazzer's JVM method.
            if text.contains("LLVMFuzzerTestOneInput")
                || text.contains("fuzz_target!")
                || text.contains("fuzzerTestOneInput")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

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
    // see the whole tree. Retain compact (name,line) metadata, not body text.
    let mut all_names: HashSet<String> = HashSet::new();
    let mut functions_by_file = Vec::new();
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
        all_names.extend(fns.iter().map(|(name, _)| name.clone()));
        functions_by_file.push((path.clone(), fns));
    }

    // Build the graph in a second streaming pass. Only one file and one joined
    // function body are resident at a time; the retained graph is names/counts.
    let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
    let mut fan_out: HashMap<(std::path::PathBuf, u32), usize> = HashMap::new();
    for (path, fns) in functions_by_file {
        let Ok(source) = crate::source_text::read_source_text(&path) else {
            continue;
        };
        let lines: Vec<&str> = source.lines().collect();
        for (i, (name, start)) in fns.iter().enumerate() {
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
            let body = lines[lo..hi].join("\n");
            let mut callees = call_names_in_text(&body, &all_names);
            callees.remove(name); // ignore self/recursion
            for callee in &callees {
                callers
                    .entry(callee.clone())
                    .or_default()
                    .insert(name.clone());
            }
            fan_out.insert((path.clone(), *start), callees.len());
        }
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
        // JS/TS call-graph re-ranking is out of scope; returning the exported-function
        // lines is harmless and consistent with the other interpreted lanes.
        Lang::Js | Lang::Ts => crate::auto::js::parse_js(source)
            .into_iter()
            .map(|f| (f.name, f.line))
            .collect(),
        // Ruby call-graph re-ranking is out of scope; returning the method lines is
        // harmless and consistent with the other interpreted lanes.
        Lang::Ruby => crate::auto::ruby::parse_ruby(source)
            .into_iter()
            .map(|m| (m.name, m.line))
            .collect(),
        Lang::Lua => crate::auto::lua::parse_lua(source)
            .into_iter()
            .map(|f| (f.name, f.line))
            .collect(),
        Lang::Php => crate::auto::php::parse_php(source)
            .into_iter()
            .map(|f| (f.name, f.line))
            .collect(),
    }
}

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

fn call_names_in_text(
    body: &str,
    all_names: &std::collections::HashSet<String>,
) -> std::collections::HashSet<String> {
    let bytes = body.as_bytes();
    let mut out = std::collections::HashSet::new();
    for (open, byte) in bytes.iter().enumerate() {
        if *byte != b'(' {
            continue;
        }
        let mut end = open;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric() || matches!(bytes[start - 1], b'_' | b':'))
        {
            start -= 1;
        }
        let token = body.get(start..end).unwrap_or_default().trim_matches(':');
        if token.is_empty() {
            continue;
        }
        if all_names.contains(token) {
            out.insert(token.to_owned());
        }
        if let Some(short) = token.rsplit("::").next() {
            if all_names.contains(short) {
                out.insert(short.to_owned());
            }
        }
    }
    out
}

fn accumulate_cpp_member_access(
    path: &Path,
    out: &mut std::collections::BTreeMap<String, String>,
    by_signature: &mut std::collections::BTreeMap<String, String>,
) {
    if !has_targetable_extension(path) {
        return;
    }
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return;
    };
    if !matches!(detect_lang(path, &source), Some(Lang::Cpp)) {
        return;
    }
    for (signature, access) in cpp_parser::parse_cpp_method_access_signatures(&source) {
        // #98: the exact overload signature (raw key) resolves to its own access,
        // so a private zero-arg overload stays distinct from a public buffer
        // overload of the same name. A genuine cross-file conflict on the exact same
        // signature is marked ambiguous (kept) like the by-name map.
        match by_signature.get(&signature) {
            Some(existing) if existing != &access => {
                by_signature.insert(signature.clone(), "ambiguous".to_owned());
            }
            Some(_) => {}
            None => {
                by_signature.insert(signature.clone(), access.clone());
            }
        }
        let key = signature
            .split_once('(')
            .map(|(qualified, _)| qualified)
            .unwrap_or(&signature)
            .to_owned();
        match out.get(&key) {
            Some(existing) if existing != &access => {
                out.insert(key, "ambiguous".to_owned());
            }
            Some(_) => {}
            None => {
                out.insert(key, access);
            }
        }
    }
}

/// Files dropped from the walk because the RSS ceiling was reached. Reported once
/// at the end of discovery so a truncated target list never reads as "this
/// project has nothing to fuzz".
static DISCOVERY_MEMORY_SKIPPED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Wall-clock ceiling for the discovery walk, in seconds. `None` = unlimited.
///
/// Discovery is deliberately NOT billed to `--campaign-time` (indexing a large
/// tree should not eat the fuzz budget), but unbilled is not the same as
/// unbounded: on Valve's Proton — 3,409 C/C++ files, 232 MB — indexing ran 447
/// seconds against a declared 240-second campaign, so the run was killed by the
/// caller's outer timeout having fuzzed nothing at all.
///
/// So when the caller has DECLARED a budget, discovery honours it too rather
/// than inventing one: past the ceiling it stops taking on new files and
/// proceeds to fuzz what it already found. A partial target list that fuzzes
/// beats a complete one that gets killed.
/// Stored as an ABSOLUTE deadline, not a duration: discovery walks the tree more
/// than once (the organizational-exclusion retry re-walks, and `list targets`
/// defers lanes to a second pass), and a per-walk duration silently granted each
/// of them a fresh budget — Proton spent 117s against a 60s ceiling. One deadline
/// for the process bounds the whole phase however many walks it takes.
static DISCOVERY_DEADLINE: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

/// Files skipped because the discovery time budget ran out.
static DISCOVERY_TIME_SKIPPED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The shared discovery deadline, for other whole-tree passes that must respect
/// the same ceiling (the declaration index is the big one).
pub(crate) fn deadline() -> Option<std::time::Instant> {
    DISCOVERY_DEADLINE.lock().ok().and_then(|slot| *slot)
}

/// Set the discovery wall-clock ceiling. `GOVFUZZ_DISCOVERY_TIME` overrides
/// (in seconds; `0` disables the ceiling entirely).
pub(crate) fn set_time_budget(budget: Option<std::time::Duration>) {
    let resolved = match std::env::var("GOVFUZZ_DISCOVERY_TIME")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(0) => None,
        Some(secs) => Some(std::time::Duration::from_secs(secs)),
        None => budget,
    };
    if let Ok(mut slot) = DISCOVERY_DEADLINE.lock() {
        *slot = resolved.map(|budget| std::time::Instant::now() + budget);
    }
}

/// Parsing recurses over the syntax tree and real source is deep enough to
/// exhaust the 8 MiB a main thread gets, so every thread that parses gets room.
/// Reserved address space, not committed memory.
const DISCOVERY_STACK_BYTES: usize = 256 * 1024 * 1024;

fn walk(
    dir: &Path,
    out: &mut Vec<Candidate>,
    filter: &DirFilter,
    preprocess: PreprocessMode,
) -> Result<()> {
    // Discovery parses every source file in the tree and holds every candidate in
    // memory, so a large C++ estate can exhaust RAM: carbon-lang was SIGKILLed
    // (exit -9) during discovery in the 500-project sweep, in BOTH `list targets`
    // and `auto` — govfuzz produced no target list at all. The static scan already
    // survives the same trees because it degrades under an RSS ceiling; discovery
    // gets the same guard, so a huge tree yields a partial target list instead of
    // nothing.
    let guard = static_analysis::MemoryGuard::start();
    let deadline = deadline();
    let result = walk_guarded(dir, out, filter, preprocess, &guard, deadline);
    let timed_out = DISCOVERY_TIME_SKIPPED.swap(0, std::sync::atomic::Ordering::Relaxed);
    if timed_out > 0 {
        gfeprintln!(
            "govfuzz auto: discovery reached its time budget and skipped {timed_out} file(s); \
             the target list is PARTIAL. Raise --campaign-time, set GOVFUZZ_DISCOVERY_TIME \
             (seconds, 0 = unlimited), or scan a subdirectory."
        );
    }
    let skipped = DISCOVERY_MEMORY_SKIPPED.swap(0, std::sync::atomic::Ordering::Relaxed);
    if skipped > 0 {
        let ceiling = static_analysis::MemoryGuard::ceiling_kb()
            .map(|kb| format!("{} MiB", kb / 1024))
            .unwrap_or_else(|| "the configured ceiling".to_owned());
        gfeprintln!(
            "govfuzz auto: discovery reached its memory ceiling ({ceiling}) and skipped \
             {skipped} file(s); the target list is PARTIAL. Raise it with \
             GOVFUZZ_MAX_MEMORY_KB, or scan a subdirectory."
        );
    }
    result
}

fn walk_guarded(
    dir: &Path,
    out: &mut Vec<Candidate>,
    filter: &DirFilter,
    preprocess: PreprocessMode,
    guard: &static_analysis::MemoryGuard,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    // Enumerate first (cheap: no file is opened), then parse in parallel.
    // Parsing IS the cost of discovery on a large tree, and it was single
    // threaded while the static scan had used a worker pool for ages. Listing a
    // 232 MB tree like Proton took ~15 minutes of one core.
    let mut files = Vec::new();
    if dir.is_file() {
        files.push(dir.to_path_buf());
    } else {
        collect_walk_files(dir, filter, &mut files)?;
    }

    // Deterministic: `collect_walk_files` visits each directory's entries sorted
    // by name, and `par_iter().collect()` preserves input order, so the candidate
    // list is byte-identical to the sequential walk's.
    let per_file: Vec<Result<Vec<Candidate>>> = discovery_pool().install(|| {
        files
            .par_iter()
            .map(|path| {
                // Past the ceiling, count the remaining files and stop parsing
                // rather than dying with nothing. Checked at a file boundary so
                // the candidate set stops growing cleanly.
                if guard.under_pressure() {
                    DISCOVERY_MEMORY_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(Vec::new());
                }
                if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                    DISCOVERY_TIME_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(Vec::new());
                }
                let mut local = Vec::new();
                discover_file_guarded(path, &mut local, preprocess)?;
                Ok(local)
            })
            .collect()
    });

    for result in per_file {
        out.extend(result?);
    }
    Ok(())
}

/// Every targetable file under `dir`, in the same order the sequential walk
/// visited them (each directory's entries sorted by name, depth first).
fn collect_walk_files(dir: &Path, filter: &DirFilter, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if is_excluded_dir(&path, filter) {
                continue;
            }
            collect_walk_files(&path, filter, files)?;
        } else if ft.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Discovery's worker pool: `cores - 1` like the static scan, and with the same
/// 256 MiB stacks the single discovery thread already used — parsing recurses
/// over the syntax tree, and real source is deep enough to blow the 2 MiB a
/// rayon worker gets by default (vllm's `cpu_types_arm.hpp` aborted a whole run
/// with "fatal runtime error: stack overflow"). The stacks are reserved address
/// space, not committed memory.
fn discovery_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::env::var("GOVFUZZ_DISCOVERY_JOBS")
            .ok()
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get().saturating_sub(1).max(1))
                    .unwrap_or(1)
            });
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(DISCOVERY_STACK_BYTES)
            .build()
            .expect("build discovery thread pool")
    })
}

/// [`discover_file`] wrapped so a govfuzz-internal PANIC while parsing/ranking ONE
/// file is recorded in the bug report and skipped, instead of aborting the whole
/// discovery walk (a single malformed input used to kill the run). A normal parse
/// ERROR still propagates via `?`.
/// #102: record that `path` was dropped from discovery because `stage` (read /
/// decode / parse) failed, then return `Ok(())` so the sweep continues. The file
/// contributes no targets, but the failure is now durable in the run's diagnostics
/// instead of looking exactly like "this file has no fuzzable endpoints" — the
/// difference between a project with nothing to fuzz and a parser regression on a
/// large legacy tree.
fn record_discovery_drop(path: &Path, language: &str, stage: &str, error: &str) -> Result<()> {
    crate::auto::bug_report::record_discovery_diagnostic(language, stage, path, error);
    Ok(())
}

/// #102: coarse language hint from a file's extension for the READ stage, which
/// runs before `detect_lang` — so a file we cannot even read still records the
/// most likely lane rather than an opaque "unknown".
fn discovery_lang_hint(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("ads" | "adb" | "ada") => "ada",
        Some("c" | "h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx") => "cpp",
        Some("rs") => "rust",
        Some("java") => "java",
        Some("py") => "python",
        Some("pl" | "pm") => "perl",
        Some("go") => "go",
        _ => "source",
    }
}

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

/// Stage timings to stderr when `GOVFUZZ_PROFILE` is set. Off by default and
/// costing one relaxed atomic load per call, so it can stay on the hot path.
///
/// Kept because guessing at this cost the work twice: a whole-registry rebuild
/// per function LOOKED like the quadratic on a 187k-line amalgamated header and
/// fixing it changed nothing, while the real costs — a per-target rescan of the
/// whole source, and a header classifier that parsed the file once with EACH
/// parser — were only visible once measured. Profile, don't guess.
pub(crate) fn gfprof(label: &str, start: std::time::Instant) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("GOVFUZZ_PROFILE").is_some()) {
        gfeprintln!("[prof] {label}: {:.3}s", start.elapsed().as_secs_f64());
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
        // #102: a file we can't read/decode is dropped, but record it so a
        // permissions/encoding regression on a legacy tree is visible.
        Err(error) => {
            return record_discovery_drop(
                path,
                discovery_lang_hint(path),
                "read",
                &error.to_string(),
            )
        }
    };
    let _tpre = std::time::Instant::now();
    let _tdl = std::time::Instant::now();
    let Some(lang) = detect_lang(path, &source) else {
        return Ok(());
    };
    // M22: tag each candidate with its detected source dialect. Only the lanes
    // whose tree-sitter grammar hides the version signal are detected here
    // (C/C++/Python/Perl); Ada/Rust/Java/Go are left `None` until their phase.
    gfprof("pre:detect_lang", _tdl);
    let _tfd = std::time::Instant::now();
    let dialect = file_dialect(lang, &source);
    gfprof("pre:file_dialect", _tfd);
    let _tcd = std::time::Instant::now();
    let preprocessor_defines = if matches!(lang, Lang::C | Lang::Cpp) {
        compile_database_preprocessor_defines(path)
    } else {
        Vec::new()
    };
    gfprof("pre:compile_db_defines", _tcd);
    gfprof("pre:lang+dialect+defines", _tpre);
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
                // #102: malformed Ada drops silently otherwise — record it.
                Err(error) => {
                    return record_discovery_drop(path, "ada", "parse", &format!("{error:?}"))
                }
            };
            let unit_has_concurrency = ada_unit_has_concurrency(path, &source);
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
                let mut score = tgt.score;
                if subprogram_in_unsynthesizable_generic(&ast, subprogram, &source) {
                    score = score.saturating_sub(GENERIC_DEMOTION);
                }
                if unit_has_concurrency {
                    score = score.saturating_sub(CONCURRENCY_DEMOTION);
                }
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
                // #5 (offline-legacy audit): a transitional 1990s TU commonly MIXES
                // a few old-style K&R helpers with ANSI-prototyped public parsers
                // (the real fuzz targets). The K&R extractor only returns old-style
                // definitions, so using it ALONE silently drops every ANSI function
                // in the file. Merge instead: keep each K&R function's
                // decl-block-derived signature (the modern parser sees old-style
                // defs as zero-param), and add the modern parser's functions that
                // the K&R parser did not recognize (by name). The dialect stays K&R
                // — the whole TU must build under a K&R-tolerant std because an
                // old-style definition is an error under C99+.
                let mut merged = knr;
                let knr_names: std::collections::HashSet<String> = merged
                    .iter()
                    .map(|function| function.name.clone())
                    .collect();
                if let Ok(modern) =
                    parse_c_functions_preprocessed(&source, preprocess, &preprocessor_defines)
                {
                    for function in modern {
                        if !knr_names.contains(&function.name) {
                            merged.push(function);
                        }
                    }
                }
                (merged, Some(lang_profile::Dialect::CKAndR))
            } else {
                let modern = match parse_c_functions_preprocessed(
                    &source,
                    preprocess,
                    &preprocessor_defines,
                ) {
                    Ok(modern) => modern,
                    // #102: record a malformed C translation unit instead of dropping it.
                    Err(error) => {
                        return record_discovery_drop(path, "c", "parse", &format!("{error:?}"))
                    }
                };
                (modern, Some(lang_profile::Dialect::C99))
            };
            let fns = dedup_c_functions(fns);
            // A function declarator inside a multi-line `#define` is a macro
            // template, not a target (BSD tree.h/queue.h `RB_GENERATE_*`).
            let _t2 = std::time::Instant::now();
            let macro_lines = macro_definition_body_lines(&source);
            gfprof("cpp:macro_lines", _t2);
            let fns: Vec<_> = fns
                .into_iter()
                .filter(|function| {
                    !macro_lines.contains(&function.line)
                        && !is_macro_invocation_name(&function.name)
                })
                .collect();
            let meta: HashMap<(&str, u32), &c_parser::CFunction> =
                fns.iter().map(|f| ((f.name.as_str(), f.line), f)).collect();
            // Loop-invariant: depends only on the path. Same hoist as the C++ arm.
            let path_guard = foreign_platform_path_guard(path);
            for tgt in target_rank::rank_c_targets(&fns) {
                let (is_static, foreign_guard) = {
                    let m = meta.get(&(tgt.name.as_str(), tgt.line));
                    (
                        m.is_some_and(|f| f.is_static),
                        m.and_then(|f| f.foreign_guard.clone())
                            .or_else(|| path_guard.clone()),
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
                    input_reachability: Some(reachability_for_linkage(
                        tgt.input_reachability,
                        is_static,
                    )),
                    dialect,
                });
            }
        }
        Lang::Cpp => {
            // §27.6: parse the preprocessed text under `preprocess`, translating
            // each surviving function's line back to the ORIGINAL source.
            let _t0 = std::time::Instant::now();
            let fns = match parse_cpp_functions_preprocessed(
                &source,
                preprocess,
                &preprocessor_defines,
            ) {
                Ok(fns) => fns,
                // #102: record a malformed C++ translation unit instead of dropping it.
                Err(error) => {
                    return record_discovery_drop(path, "cpp", "parse", &format!("{error:?}"))
                }
            };
            gfprof("cpp:parse", _t0);
            let _t1 = std::time::Instant::now();
            let fns = dedup_cpp_functions(fns);
            gfprof("cpp:dedup", _t1);
            // Same macro-template exclusion as the C lane: a C++ TU that includes
            // a BSD tree.h/queue.h header sees the identical pseudo-functions.
            let macro_lines = macro_definition_body_lines(&source);
            let fns: Vec<_> = fns
                .into_iter()
                .filter(|function| {
                    !macro_lines.contains(&function.line)
                        && !is_macro_invocation_name(&function.name)
                })
                .collect();
            let _t3 = std::time::Instant::now();
            let known_blocked = crate::generate_harness::cpp_known_blocked_signatures_for_discovery(
                path, &source, &fns,
            );
            gfprof("cpp:known_blocked", _t3);
            let meta = fns
                .iter()
                .map(|function| {
                    (
                        (function.line, target_rank::cpp_target_name(function)),
                        function,
                    )
                })
                .collect::<HashMap<_, _>>();
            let _t4 = std::time::Instant::now();
            let _ranked = target_rank::rank_cpp_targets(&fns);
            gfprof("cpp:rank", _t4);
            // Both fallback guards are loop-invariant — one depends only on the
            // PATH, the other only on the SOURCE TEXT — but being inside the
            // per-target loop meant `cpp_windows_framework_guard` rescanned the
            // whole file once per target. On simdjson's 187k-line amalgamated
            // header that is 7,264 targets x 7.7 MB = ~56 GB of scanning, and it
            // was 83 of the 99 seconds discovery spent walking that one file.
            // `.or_else` is lazy, so it only fired for targets with no parsed
            // guard of their own — which is nearly all of them.
            let path_guard = foreign_platform_path_guard(path);
            let windows_guard = cpp_windows_framework_guard(&source);
            let _t5 = std::time::Instant::now();
            for tgt in _ranked {
                let (is_static, foreign_guard, signature_known_blocked) = {
                    // Ranked C++ names are qualified (`ns::Class::method`) while
                    // `CppFunction::name` is the leaf. The old `(name,line)` map
                    // therefore missed every qualified target and silently lost
                    // its static/guard metadata. The source line is discovery's
                    // stable overload identity and is the same identity passed to
                    // generation. Keep the full ranked spelling as well as the
                    // line because legacy one-line headers can declare several
                    // overloads on one physical line.
                    let identity = (tgt.line, tgt.name.clone());
                    let m = meta.get(&identity).copied();
                    (
                        // Static *member* functions are linkable; only
                        // static free functions have internal linkage.
                        m.is_some_and(|f| f.is_static && !f.api.is_method),
                        m.and_then(|f| f.foreign_guard.clone())
                            .or_else(|| path_guard.clone())
                            .or_else(|| windows_guard.clone()),
                        known_blocked.contains(&identity),
                    )
                };
                out.push(Candidate {
                    harness_id: stable_harness_id("H-X", path, tgt.line, &tgt.name),
                    lang: Lang::Cpp,
                    source_path: path.to_path_buf(),
                    line: tgt.line,
                    name: tgt.name,
                    score: if signature_known_blocked {
                        tgt.score
                            .saturating_sub(KNOWN_UNBUILDABLE_SIGNATURE_DEMOTION)
                    } else {
                        tgt.score
                    },
                    is_static,
                    foreign_guard,
                    input_reachability: Some(reachability_for_linkage(
                        tgt.input_reachability,
                        is_static,
                    )),
                    dialect,
                });
            }
            gfprof("cpp:push_loop", _t5);
        }
        Lang::Rust => {
            // M1.1: discover + rank Rust targets. The ranker drops private fns
            // and carries `is_static` / `foreign_guard` / reachability through,
            // so the discovery arm is a thin map (no re-parse). The attempt loop
            // pre-skips these cleanly until the harness/build/engine lane (M1.2).
            let fns = match rust_parser::parse_rust_functions(&source) {
                Ok(fns) => fns,
                Err(error) => {
                    return record_discovery_drop(path, "rust", "parse", &format!("{error:?}"))
                }
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
            let methods = match java_parser::parse_java_methods(&source) {
                Ok(methods) => methods,
                Err(error) => {
                    return record_discovery_drop(path, "java", "parse", &format!("{error:?}"))
                }
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
                    Err(error) => {
                        return record_discovery_drop(
                            path,
                            "python",
                            "parse",
                            &format!("{error:?}"),
                        )
                    }
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
            let subs = match perl_parser::parse_perl_subs(&source) {
                Ok(subs) => subs,
                Err(error) => {
                    return record_discovery_drop(path, "perl", "parse", &format!("{error:?}"))
                }
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
            let functions = match go_parser::parse_go_functions(&source) {
                Ok(functions) => functions,
                Err(error) => {
                    return record_discovery_drop(path, "go", "parse", &format!("{error:?}"))
                }
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
        Lang::Js | Lang::Ts => {
            // M3.7/M3.8: each exported JS/TS function taking ≥1 argument is a
            // candidate, driven via the Node framed driver (TS is transpiled first;
            // see `crate::auto::js` / `js_build`). The first argument is the
            // attacker-controlled input channel.
            let (prefix, cand_lang) = if lang == Lang::Ts {
                ("H-T", Lang::Ts)
            } else {
                ("H-N", Lang::Js)
            };
            for func in crate::auto::js::parse_js(&source) {
                out.push(Candidate {
                    harness_id: stable_harness_id(prefix, path, func.line, &func.name),
                    lang: cand_lang,
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
        Lang::Ruby => {
            // M3.9: each callable Ruby method taking ≥1 input-channel argument is a
            // candidate, driven via the Ruby framed driver (see `crate::auto::ruby` /
            // `ruby_build`). The first argument is the attacker-controlled input.
            for m in crate::auto::ruby::parse_ruby(&source) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-U", path, m.line, &m.name),
                    lang: Lang::Ruby,
                    source_path: path.to_path_buf(),
                    line: m.line,
                    name: m.name,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
        Lang::Lua => {
            // M3.10: each callable Lua function taking ≥1 input-channel argument is a
            // candidate, driven via the Lua framed driver (see `crate::auto::lua` /
            // `lua_build`). The first argument is the attacker-controlled input.
            for f in crate::auto::lua::parse_lua(&source) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-V", path, f.line, &f.name),
                    lang: Lang::Lua,
                    source_path: path.to_path_buf(),
                    line: f.line,
                    name: f.name,
                    score: 50,
                    is_static: false,
                    foreign_guard: None,
                    input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                    dialect,
                });
            }
        }
        Lang::Php => {
            // M3.11: each PHP function / public static or instance method taking an
            // input-channel argument is a candidate, driven via the PHP framed driver
            // (see `crate::auto::php` / `php_build`).
            for f in crate::auto::php::parse_php(&source) {
                out.push(Candidate {
                    harness_id: stable_harness_id("H-W", path, f.line, &f.name),
                    lang: Lang::Php,
                    source_path: path.to_path_buf(),
                    line: f.line,
                    name: f.name,
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

/// Is this file worth parsing for targets? Extension first, then the `#!` line
/// for the extension-less scripts that carry a whole tool's code.
fn has_targetable_extension(path: &Path) -> bool {
    if path.extension().is_none() {
        return shebang_lang_of_file(path).is_some();
    }
    has_targetable_extension_only(path)
}

fn has_targetable_extension_only(path: &Path) -> bool {
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
                    | "ts"
                    | "tsx"
                    | "mts"
                    | "cts"
                    | "js"
                    | "mjs"
                    | "cjs"
                    | "rb"
                    | "lua"
                    | "php"
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
        | Lang::Js
        | Lang::Ts
        | Lang::Ruby
        | Lang::Lua
        | Lang::Php => None,
    }
}

/// The interpreter named by a `#!` line, for the scripting lanes.
///
/// Command-line tools written in a scripting language are routinely installed
/// as extension-less executables — `cloc`, `sqitch`, `ack`, most `git-*`
/// helpers — so an extension-only rule drops the whole program. cloc, for
/// example, is 20k lines of Perl in a file named `cloc`.
fn shebang_lang(first_line: &str) -> Option<Lang> {
    let line = first_line.strip_prefix("#!")?.trim();
    // `#!/usr/bin/env -S perl -w` and `#!/usr/bin/perl -w` both name the
    // interpreter in a different argument, so scan the words and take the first
    // one that IS an interpreter rather than assuming a position.
    for word in line.split_whitespace() {
        let name = word.rsplit('/').next().unwrap_or(word);
        // Strip a version suffix: python3, python3.12, lua5.4, ruby2.7.
        let stem: String = name
            .chars()
            .take_while(|c| c.is_ascii_alphabetic() || *c == '_')
            .collect();
        match stem.as_str() {
            "perl" => return Some(Lang::Perl),
            "python" => return Some(Lang::Python),
            "ruby" => return Some(Lang::Ruby),
            "php" => return Some(Lang::Php),
            "lua" | "luajit" => return Some(Lang::Lua),
            "node" | "nodejs" => return Some(Lang::Js),
            // `env` itself, and shells (`sh`, `bash`) which are not a lane.
            _ => continue,
        }
    }
    None
}

/// The `#!` lane of a file, read without pulling the whole file into memory.
/// Only extension-less files are peeked at: everything else is classified by
/// extension, and a peek per non-source file would cost a syscall per entry.
fn shebang_lang_of_file(path: &Path) -> Option<Lang> {
    use std::io::Read;
    if path.extension().is_some() {
        return None;
    }
    let mut head = [0u8; 128];
    let mut file = std::fs::File::open(path).ok()?;
    let read = file.read(&mut head).ok()?;
    let head = &head[..read];
    if !head.starts_with(b"#!") {
        return None;
    }
    let line = head.split(|b| *b == b'\n').next().unwrap_or(head);
    shebang_lang(&String::from_utf8_lossy(line))
}

fn detect_lang(path: &Path, source: &str) -> Option<Lang> {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        // No extension: an interpreter shebang is the only language signal, and
        // the source is already in hand, so no extra read is needed here.
        return shebang_lang(source.lines().next().unwrap_or_default());
    };
    match ext.to_ascii_lowercase().as_str() {
        // A header's language depends on what is IN it, and a `.d.ts` is a
        // type-declaration file with no runtime code. Everything else is decided
        // by the extension alone, from the one table.
        "h" => Some(classify_c_header(path, source)),
        "hpp" | "hh" | "hxx" => Some(Lang::Cpp),
        "ts" | "tsx" | "mts" | "cts" if path.to_string_lossy().ends_with(".d.ts") => None,
        _ => extension_lang_hint(path),
    }
}

fn classify_c_header(path: &Path, source: &str) -> Lang {
    let has_c_impl = path.with_extension("c").is_file();
    let has_cpp_impl = ["cpp", "cc", "cxx", "C"]
        .iter()
        .any(|ext| path.with_extension(ext).is_file());
    // Decide on the CHEAP evidence first. All three tests below are pure
    // predicates joined by `||`, so answering from the marker scan or the
    // sibling-implementation check gives exactly the verdict the original
    // `cpp_count > c_count || ...` chain gave — it just stops before paying for
    // two whole-file parses.
    //
    // That mattered enormously: counting functions parses the file ONCE WITH
    // EACH PARSER purely to pick a language, and the C parser over a large C++
    // header spends its time in error recovery. simdjson's 187k-line
    // `singleheader/simdjson.h` cost **33 seconds here alone** — more than the
    // real parse that follows — and the file says `namespace`, `class` and
    // `template` on nearly every page, so the marker scan answers it in
    // milliseconds.
    if header_looks_like_cpp(source) || (has_cpp_impl && !has_c_impl) {
        return Lang::Cpp;
    }
    // Genuinely ambiguous: no C++ markers and no decisive sibling. Only now is
    // the double parse worth it, and such headers are small in practice.
    let c_count = c_parser::parse_c_functions(source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    let cpp_count = cpp_parser::parse_cpp_functions(source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    if cpp_count > c_count {
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
        let Ok(text) = crate::source_text::read_source_text(&gpr) else {
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
    fn a_projects_own_harnesses_are_enumerable_even_though_they_are_not_targets() {
        // Discovery excludes them so a project's harness cannot out-rank its
        // parser — but excluding them also threw away the fact of their
        // existence, and they are the only expert baseline there is.
        let root = std::env::temp_dir().join(format!("govfuzz-experts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("fuzz")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("fuzz/xml_parse_fuzzer.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }",
        )
        .unwrap();
        fs::write(
            root.join("fuzz/rust_target.rs"),
            "fuzz_target!(|data: &[u8]| { let _ = data; });",
        )
        .unwrap();
        fs::write(
            root.join("src/lib.c"),
            "int parse(const char *s) { return 0; }",
        )
        .unwrap();

        let found = existing_harness_sources(&root);
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.contains(&"xml_parse_fuzzer.c".to_owned()),
            "{names:?}"
        );
        assert!(names.contains(&"rust_target.rs".to_owned()), "{names:?}");
        // Ordinary library source is not a harness.
        assert!(!names.contains(&"lib.c".to_owned()), "{names:?}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_local_helper_is_never_claimed_attacker_reachable() {
        use target_rank::InputReachability as R;
        // libexpat's `matchkey(const char *start, const char *end, const char *key)`
        // is `static`. Its parameter shapes read as a parser, so the signature
        // classifier says AttackerReachable — but nothing outside the TU can call
        // it, so a crash the harness drove directly is not attacker-reachable.
        assert_eq!(
            reachability_for_linkage(R::AttackerReachable, true),
            R::ReachabilityUnproven,
            "a static helper must not claim attacker reachability"
        );
        // External linkage keeps the signature verdict.
        assert_eq!(
            reachability_for_linkage(R::AttackerReachable, false),
            R::AttackerReachable
        );
        // Other verdicts are untouched in both directions — this tempers the
        // positive claim only, it does not invent one.
        for verdict in [
            R::ReachabilityUnproven,
            R::OutputSerializer,
            R::IpcChannelReachable,
        ] {
            assert_eq!(reachability_for_linkage(verdict, true), verdict);
            assert_eq!(reachability_for_linkage(verdict, false), verdict);
        }
    }

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

    #[test]
    fn all_caps_macro_invocations_are_not_targets() {
        // Linux tracepoint headers: `TRACE_EVENT(name, TP_PROTO(...), ...)` at file
        // scope parses as a function whose parameter TYPES are the macro arguments.
        // No such symbol exists, so the harness can never link.
        assert!(is_macro_invocation_name("TRACE_EVENT"));
        assert!(is_macro_invocation_name("RB_GENERATE_INSERT"));
        assert!(is_macro_invocation_name("TP_ARGS"));
        assert!(is_macro_invocation_name("MODULE_DEVICE_TABLE"));
        // tmux's `name##_RB_INSERT` loses its pasted prefix in the parse and
        // arrives as `_RB_INSERT` — macro-shaped by this rule as well as by the
        // macro-body line filter. Either one is enough to keep it out.
        assert!(is_macro_invocation_name("_RB_INSERT"));
        // Single-word ALL-CAPS names really are functions in numerical code —
        // BLAS/LAPACK and Fortran-bound wrappers are spelled this way on purpose.
        assert!(!is_macro_invocation_name("DGEMM"));
        assert!(!is_macro_invocation_name("SGEMV"));
        // Mixed-case API names (OpenSSL's `MD5_Init`, `EVP_DigestInit`) are real
        // functions and must survive.
        assert!(!is_macro_invocation_name("MD5_Init"));
        assert!(!is_macro_invocation_name("EVP_DigestInit"));
        // Ordinary C/C++ names are untouched.
        assert!(!is_macro_invocation_name("parse_header"));
        assert!(!is_macro_invocation_name("Clay__HashData"));
        assert!(!is_macro_invocation_name("session_parse"));
    }

    #[test]
    fn macro_body_functions_are_not_targets() {
        // tmux's compat/tree.h — the BSD RB_GENERATE family defines whole function
        // bodies inside a backslash-continued `#define`. tree-sitter parses them as
        // functions returning `attr struct type *`, but `attr`/`type`/`name` are
        // macro PARAMETERS: the harness emitted `attr struct type * R = ...` and
        // clang rejected it with "cannot combine with previous 'type-name'
        // declaration specifier", which no repair can fix because nothing is
        // missing. Seven dead targets from one header, each consuming a slot in the
        // ranked cap that a real function should have had.
        let source = "#define RB_GENERATE_INSERT(name, type, field, cmp, attr)\\\n\
                      attr struct type *\\\n\
                      name##_RB_INSERT(struct name *head, struct type *elm)\\\n\
                      {\\\n\
                      \treturn (NULL);\\\n\
                      }\n\
                      \n\
                      int real_parse(const char *text, size_t len)\n\
                      {\n\
                      \treturn (int)len;\n\
                      }\n";
        let macro_lines = macro_definition_body_lines(source);
        // The #define and every continued line belong to the macro body ...
        for line in 1..=6 {
            assert!(macro_lines.contains(&line), "line {line} is macro body");
        }
        // ... and the real function after it does not.
        for line in 7..=11 {
            assert!(!macro_lines.contains(&line), "line {line} is real code");
        }
    }

    #[test]
    fn a_single_line_define_does_not_swallow_the_code_after_it() {
        // Only a CONTINUED define carries a body. An ordinary one-line define must
        // not mark the following function as a macro template.
        let source = "#define MAX_LEN 4096\n\
                      #  define OTHER 1\n\
                      int parse(const char *t) { return 0; }\n";
        let macro_lines = macro_definition_body_lines(source);
        assert!(macro_lines.contains(&1));
        assert!(macro_lines.contains(&2), "indented `#  define` counts too");
        assert!(
            !macro_lines.contains(&3),
            "the function after a one-line define is real code"
        );
    }

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
    fn build_context_fingerprint_tracks_build_files_and_knobs_not_docs() {
        // #101: the build-context fingerprint busts on a GPR / compile_commands.json
        // / IDL / option change (so --resume re-attempts affected results), but NOT
        // on a README edit (docs never invalidate the build context).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "govfuzz-bctx-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("proj.gpr"), "project P is\nend P;\n").unwrap();
        fs::write(root.join("README.md"), "hello\n").unwrap();

        let fp0 = build_context_fingerprint(&root, "knobs-a");
        assert_eq!(fp0, build_context_fingerprint(&root, "knobs-a"), "stable");

        // Editing README (not a build file) does NOT change the build context.
        fs::write(root.join("README.md"), "changed docs\n").unwrap();
        assert_eq!(
            fp0,
            build_context_fingerprint(&root, "knobs-a"),
            "documentation must not invalidate the build context"
        );

        // Editing the GPR changes it.
        fs::write(
            root.join("proj.gpr"),
            "project P is\n  for Main use ();\nend P;\n",
        )
        .unwrap();
        let fp1 = build_context_fingerprint(&root, "knobs-a");
        assert_ne!(fp0, fp1, "editing a GPR must change the build context");

        // Adding a compile database changes it.
        fs::write(root.join("compile_commands.json"), "[]\n").unwrap();
        let fp2 = build_context_fingerprint(&root, "knobs-a");
        assert_ne!(fp1, fp2, "a new compile_commands.json must change it");

        // Changing a harness-affecting option (knobs) changes it with no file edit.
        assert_ne!(
            fp2,
            build_context_fingerprint(&root, "knobs-b"),
            "changing options must change the build context"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ada_spec_body_split_across_dirs_yields_one_candidate() {
        // #92: a spec under src/interface and its body under src/implementation
        // both name `Parse`. Discovery must keep ONE candidate — the public spec —
        // not two. A body-only subprogram (no spec) is retained.
        let mk = |dir: &str, ext: &str, name: &str| Candidate {
            harness_id: format!("H-{name}-{ext}"),
            lang: Lang::Ada,
            source_path: PathBuf::from(format!("/proj/{dir}/parser.{ext}")),
            line: 1,
            name: name.to_owned(),
            score: 10,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        };
        let mut candidates = vec![
            mk("src/interface", "ads", "Parse"),
            mk("src/implementation", "adb", "Parse"),
            mk("src/implementation", "adb", "Body_Only"),
        ];
        dedup_ada_spec_body_candidates(&mut candidates);
        assert_eq!(
            candidates.len(),
            2,
            "spec+body Parse collapses to one: {candidates:?}"
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.name == "Parse" && c.source_path.to_string_lossy().contains("interface")),
            "the public spec candidate is kept"
        );
        assert!(
            !candidates
                .iter()
                .any(|c| c.name == "Parse"
                    && c.source_path.to_string_lossy().contains("implementation")),
            "the redundant body candidate is dropped"
        );
        assert!(
            candidates.iter().any(|c| c.name == "Body_Only"),
            "a body-only subprogram (no spec) is retained"
        );
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
    fn extensionless_interpreter_scripts_are_discovered_by_shebang() {
        // A scripting-language tool installed as an extension-less executable is
        // still the whole program: cloc is 20k lines of Perl in a file named
        // `cloc`. Extension-only classification discovered zero targets in it.
        for (line, want) in [
            ("#!/usr/bin/perl -w", Lang::Perl),
            ("#!/usr/bin/env perl", Lang::Perl),
            ("#!/usr/bin/env -S perl -CSD", Lang::Perl),
            ("#!/usr/bin/python3", Lang::Python),
            ("#!/usr/bin/env python3.12", Lang::Python),
            ("#!/usr/bin/env ruby", Lang::Ruby),
            ("#!/usr/local/bin/php", Lang::Php),
            ("#!/usr/bin/env luajit", Lang::Lua),
            ("#!/usr/bin/env node", Lang::Js),
        ] {
            assert_eq!(shebang_lang(line), Some(want), "shebang {line:?}");
        }
        // A shell script is not one of our lanes, and a non-shebang first line
        // must never be read as one.
        assert_eq!(shebang_lang("#!/bin/sh"), None);
        assert_eq!(shebang_lang("#!/usr/bin/env bash"), None);
        assert_eq!(shebang_lang("package Foo;"), None);
        assert_eq!(shebang_lang(""), None);

        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("cloc");
        fs::write(
            &script,
            "#!/usr/bin/env perl\nsub parse_line { return 1; }\n",
        )
        .expect("write script");
        assert!(
            has_targetable_extension(&script),
            "extension-less perl script must be parsed for targets"
        );
        assert_eq!(
            detect_lang(&script, &fs::read_to_string(&script).expect("read")),
            Some(Lang::Perl)
        );
        // A README or a binary blob with no extension stays out of the sweep.
        let readme = dir.path().join("README");
        fs::write(&readme, "just words, no shebang\n").expect("write readme");
        assert!(!has_targetable_extension(&readme));
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
    fn cpp_known_unbuildable_signature_cannot_displace_viable_target() {
        let root = tmpdir();
        fs::write(
            root.join("rank.cpp"),
            "#include <string_view>\n\
             namespace gov {\n\
             class Secret { public: Secret() = delete; };\n\
             int parse_secret(Secret value) { return 0; }\n\
             int parse_bytes(std::string_view bytes) { return (int)bytes.size(); }\n\
             }\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        let viable = cands
            .iter()
            .find(|candidate| candidate.name == "gov::parse_bytes")
            .expect("byte-channel target discovered");
        let blocked = cands
            .iter()
            .find(|candidate| candidate.name == "gov::parse_secret")
            .expect("known-blocked target remains discoverable but demoted");
        assert!(
            viable.score > blocked.score,
            "a capped campaign must reach the viable target first: {cands:?}"
        );
        assert!(
            blocked.score <= -900_000,
            "declared deleted-constructor parameter should carry the conservative demotion: {blocked:?}"
        );
        assert_eq!(
            cands.first().map(|candidate| candidate.name.as_str()),
            Some("gov::parse_bytes"),
            "the first slot of even a cap=1 campaign must be viable"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cpp_qualified_metadata_identity_survives_same_line_declarations() {
        let root = tmpdir();
        // Both definitions intentionally occupy one physical line. A line-only
        // lookup chooses whichever parser record happens to appear first; the
        // full ranked identity must preserve internal linkage independently.
        fs::write(
            root.join("identity.cpp"),
            "namespace api { int parse(int x) { return x; } static int decode(int x) { return x; } }\n",
        )
        .unwrap();

        let cands = discover(&root).unwrap();
        let parse = cands
            .iter()
            .find(|candidate| candidate.name == "api::parse")
            .expect("qualified public function discovered");
        let decode = cands
            .iter()
            .find(|candidate| candidate.name == "api::decode")
            .expect("qualified static function discovered");
        assert!(!parse.is_static, "external function must remain external");
        assert!(
            decode.is_static,
            "qualified internal-linkage metadata must not be lost"
        );

        let _ = fs::remove_dir_all(&root);
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
    fn auto_preprocess_requires_heavy_conditionals_and_project_context() {
        // Default preprocessing is safe only with per-TU project macros. A lone
        // header guard is always raw, and even a heavily conditional source stays
        // raw when there is no compile database context.
        assert!(!should_preprocess(
            PreprocessMode::Auto,
            "#ifndef FOO_H\n#define FOO_H\nint parse(const char *p);\n#endif\n",
            true,
        ));
        let heavy = "#if A\nint a(void);\n#endif\n\
                     #if B\nint b(void);\n#endif\n\
                     #if C\nint c(void);\n#endif\n\
                     #ifdef D\nint d(void);\n#endif\n\
                     #ifdef E\nint e(void);\n#endif\n";
        assert!(!should_preprocess(PreprocessMode::Auto, heavy, false));
        assert!(should_preprocess(PreprocessMode::Auto, heavy, true));

        // End-to-end with an exact compile command: its `-D` context selects the
        // same active branches generation/build will use.
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
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[{{"directory":"{}","file":"heavy.c","arguments":["clang","-DHAVE_AVX2=1","-DNDEBUG=1","-c","heavy.c"]}}]"#,
                root.display()
            ),
        )
        .unwrap();
        let cands = discover(&root).unwrap();
        assert!(cands.iter().any(|c| c.name == "scalar_parse"), "{cands:?}");
        assert!(cands.iter().any(|c| c.name == "avx_parse"), "{cands:?}");
        for dropped in ["sse_parse", "neon_parse", "dbg_parse", "dead_parse"] {
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
    fn ada_concurrency_units_rank_below_ordinary_fuzzable_packages() {
        let root = tmpdir();
        fs::write(
            root.join("ordinary.ads"),
            "package Ordinary is procedure Parse (Data : String); end Ordinary;\n",
        )
        .unwrap();
        fs::write(
            root.join("concurrent.ads"),
            "package Concurrent is\n  protected Guard is\n    procedure Touch;\n  end Guard;\n  procedure Parse (Data : String);\nend Concurrent;\n",
        )
        .unwrap();
        let candidates = discover(&root).unwrap();
        let ordinary = candidates
            .iter()
            .find(|candidate| candidate.source_path.ends_with("ordinary.ads"))
            .expect("ordinary Ada target");
        let concurrent = candidates
            .iter()
            .find(|candidate| candidate.source_path.ends_with("concurrent.ads"))
            .expect("concurrent Ada target remains discoverable");
        assert!(
            ordinary.score > concurrent.score,
            "ordinary target must run first: {candidates:?}"
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
        assert_eq!(classify_c_header(Path::new("yyjson.h"), src), Lang::C);
    }

    #[test]
    fn c_like_header_with_cpp_implementation_sibling_is_classified_cpp() {
        let dir = tempfile::tempdir().unwrap();
        let header = dir.path().join("Hashes.h");
        fs::write(
            &header,
            "inline void MurmurHash1_test(const void *key) { MurmurHash1(key); }\n",
        )
        .unwrap();
        fs::write(dir.path().join("Hashes.cpp"), "#include \"Hashes.h\"\n").unwrap();

        let source = fs::read_to_string(&header).unwrap();
        assert_eq!(classify_c_header(&header, &source), Lang::Cpp);
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
        let fns = parse_c_functions_preprocessed(source, PreprocessMode::Always, &[]).unwrap();
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"mpack_reader_init") && names.contains(&"mpack_read_u8"),
            "preprocessing zeroed all functions; raw fallback must recover them, got {names:?}"
        );
    }

    #[test]
    fn cpp_preprocess_zero_result_has_the_same_raw_safety_fallback_as_c() {
        let source = "#if PROJECT_FEATURE\nnamespace Api { int parse(const char *p) { return p[0]; } }\n#endif\n";
        let fns = parse_cpp_functions_preprocessed(source, PreprocessMode::Always, &[]).unwrap();
        assert!(
            fns.iter().any(|function| function.name == "parse"),
            "{fns:?}"
        );
    }
}
