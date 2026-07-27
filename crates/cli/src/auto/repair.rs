// SPDX-License-Identifier: Apache-2.0

use build_classifier::BuildErrorKind;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Sub-directory under <harness>/repairs/ where synthesised
/// placeholder headers are written. Public so the report module
/// (Batch 5) can reference the same path without drifting.
pub const AUTO_INCLUDES_DIR: &str = "auto_includes";
pub const AUTO_STUBS_FILE: &str = "auto_stubs.c";
/// C++ stubs (qualified names, references, overloads) compiled as C++ — a C
/// stub file holding C++ definitions does not compile.
pub const AUTO_STUBS_CPP_FILE: &str = "auto_stubs.cpp";
pub const AUTO_TYPES_FILE: &str = "auto_types.h";
/// Force-included into every TU of the C/C++ build (see build.rs). Holds only
/// collision-safe content — `#include <stdlib-header>` + `using` — so that,
/// unlike `auto_types.h`'s `void *` placeholders, it can safely reach the real
/// target/library sources that define these types.
pub const AUTO_CPP_INCLUDES_FILE: &str = "auto_cpp_includes.h";
/// Force-included into every TU of the C/C++ build (see build.rs). Holds
/// `#define`s for build-config macros the project's build system would inject.
pub const AUTO_DEFINES_FILE: &str = "auto_defines.h";
pub const AUTO_ADA_STUBS_DIR: &str = "ada_stubs";
/// Directory (under a target's `repairs/`) holding synthesized stub `.gpr`
/// project files for missing external `with`ed GPR imports (force-fuzz only).
/// `prepare_layout` copies these next to the generated `govfuzz_build.gpr` so
/// gprbuild resolves the import and the project LOADS — after which the normal
/// missing-Ada-unit stubbing handles the referenced packages' used subset.
pub const AUTO_GPR_STUBS_DIR: &str = "gpr_stubs";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Repair {
    HeaderPlaceholder {
        virtual_path: String,
    },
    /// Make an installed-layout include spelling resolve to a real, uniquely
    /// named header in the checkout. Some legacy projects compile from a staged
    /// include tree (`<yajl/yajl_common.h>`) but keep that header elsewhere in
    /// source (`src/api/yajl_common.h`). The forwarding header preserves the real
    /// declarations instead of replacing them with an empty placeholder.
    HeaderForward {
        virtual_path: String,
        source_path: PathBuf,
    },
    /// A missing autoconf/cmake `config.h` for a project that ships only a
    /// `config.h.in`: write a minimal config.h (HAVE_CONFIG_H + standard feature
    /// macros) and force-define HAVE_CONFIG_H, so a TU guarded on it compiles
    /// (libarchive, tcpdump). Distinct from an empty HeaderPlaceholder.
    ConfigHeaderSynth {
        virtual_path: String,
    },
    /// Add a real in-tree directory to the include path so a `#include` resolves
    /// to the project's actual header — beats an empty `HeaderPlaceholder`, which
    /// cascades into "unknown type" errors. Used for multi-module trees (cFS)
    /// whose headers live in sibling `modules/*/fsw/inc` dirs.
    AddIncludeDir {
        dir: PathBuf,
    },
    /// Force-include the unique surviving project header that defines a type
    /// whose original include edge was lost with a damaged private header.
    IncludeTypeHeader {
        type_name: String,
        header: PathBuf,
    },
    TypePlaceholder {
        type_name: String,
    },
    /// Real typedef chain synthesised from the tree-wide type index for a type
    /// the target's include closure left undefined — e.g. an arch/config-gated
    /// scalar alias like seL4's `word_t`. Emitted into the force-included header
    /// (dependency-first) so the parameter both decodes and compiles, unlike the
    /// `void *` `TypePlaceholder` fallback.
    TypeAlias {
        type_name: String,
        decls: Vec<String>,
    },
    /// A LOWER-CONFIDENCE default-width scalar typedef for a recognised framework
    /// config-type alias (F´'s `Fw*Type` family) whose real definition lives in
    /// absent codegen (`config/*TypeAliasAc.h`) and is unresolvable from the tree.
    /// Distinct from `TypeAlias` (which carries a width recovered from a REAL
    /// in-tree typedef): this one carries the upstream DEFAULT width, which a
    /// non-default deployment can override — so the report flags any finding that
    /// touches such a target as guessed-width / path-validated, not
    /// runtime-confirmed. Only fires for the curated `c_config_type_alias` family
    /// when no real definition is reachable.
    ConfigTypeAlias {
        type_name: String,
        underlying: String,
        /// When `Some`, the missing F´ autocoder header (`config/Fw*TypeAliasAc.h`)
        /// this alias backs: the typedef is written INTO that header at the include
        /// path so one round resolves both the `#include` and the type. When
        /// `None`, the alias came from a bare `MissingType` and is force-included.
        header_path: Option<String>,
    },
    /// `#define` a build-config macro the project's build system would have
    /// injected (generated `config.h` / `-D`), so a TU referencing it compiles.
    /// `as_value` true -> `#define NAME 0` (value position); false -> `#define
    /// NAME` with no replacement (a type/specifier qualifier such as an
    /// inline/export decorator).
    MacroDefine {
        name: String,
        as_value: bool,
        /// The macro is invoked with arguments, so its replacement has to be
        /// function-like. A `#if VER >= AV_VERSION_INT(58, 9, 100)` against a
        /// library that is not installed needs `#define AV_VERSION_INT(...) 0`;
        /// the object-like `0` an ordinary value macro gets would leave the
        /// condition malformed and the translation unit unbuildable.
        #[serde(default)]
        function_like: bool,
    },
    /// Force-include a standard header for an undefined standard symbol that is a
    /// macro / needs a declaration to compile (`assert` -> `<assert.h>`), rather
    /// than stubbing the symbol with a bogus weak function.
    IncludeStdHeader {
        symbol: String,
        header: String,
    },
    /// Restore only the declaration for a real function whose definition still
    /// exists in the project. This is distinct from `StubDeclared`: it emits no
    /// body and therefore cannot replace the candidate target or inflate stub
    /// execution counts.
    DeclareFunction {
        symbol: String,
        return_type: String,
        provenance: String,
    },
    StubDeclared {
        symbol: String,
        return_type: String,
        provenance: String,
    },
    AddSource {
        symbol: String,
        source_path: PathBuf,
    },
    StubBlind {
        symbol: String,
    },
    /// `setenv()`-injected so a previously-NULL getenv call now
    /// succeeds. Synthesised value is recorded for replay.
    EnvVarInjection {
        name: String,
        value: String,
    },
    AdaPackageStub {
        unit: String,
        decls: Vec<String>,
        ops: Vec<stub_gen::StubOp>,
        synthesize_body: bool,
        provenance: String,
    },
    AdaPackageBodyStub {
        unit: String,
        ops: Vec<stub_gen::StubOp>,
        provenance: String,
    },
    /// Overwrite an uncompilable dependency body (target-specific inline asm)
    /// with a synthesised stub body from its spec, so a dependent target builds
    /// and fuzzes against the neutralised dependency.
    OverrideAdaBodyStub {
        source: PathBuf,
        unit: String,
        ops: Vec<stub_gen::StubOp>,
    },
    /// Add an Ada unit's REAL source (a sibling dir outside the scan path —
    /// adamant's `serializer_types`) to the build, resolved from the tree-wide
    /// unit index. Beats `AdaPackageStub`, which fabricates a signature-only
    /// shell that drops the unit's real enums/constants and cascades.
    AddAdaSource {
        unit: String,
        sources: Vec<PathBuf>,
    },
    /// Force-fuzz only: synthesize a minimal, empty stub `.gpr` for a missing
    /// external `with`ed project (`with "gnatcoll";` -> a `gnatcoll` the offline
    /// box doesn't have). GNAT fails at project LOAD when the imported `.gpr` is
    /// absent, before any unit compiles — so the normal missing-symbol/unit
    /// stubbing never engages. The empty stub project satisfies the import so the
    /// project loads; the packages the code actually `with`s from it are then
    /// stubbed (used subset) by the existing `MissingAdaWith` -> `AdaPackageStub`
    /// path. The stub declares no sources, so it never collides with the harness
    /// project's own units.
    StubGprImport {
        project: String,
    },
    /// Define a build-configuration macro whose ABSENCE a header turns into a
    /// `#error` — the value a real `./configure` would have written. Distinct from
    /// [`Repair::MacroDefine`], which infers its value from the TARGET's source: the
    /// requirement here is stated by the guard's own file (`#if (DEPTH != 8) && …`),
    /// so the value is resolved when the repair is planned and applied verbatim.
    ConfigGuardDefine {
        name: String,
        value: String,
    },
    /// Marker: this target was built STUB-ISOLATED for a foreign OS platform it
    /// can't be cross-compiled/emulated on — the platform guard macro was defined
    /// and fake platform headers/types were supplied so the foreign branch
    /// compiles natively. Records the platform so the report flags every finding
    /// on the target as REDUCED-FIDELITY (the platform behavior is faked). The
    /// actual header/define synthesis is done by the attempt loop; applying this
    /// repair is a no-op (it only labels).
    PlatformStub {
        platform: String,
    },
    /// Marker: under `--force`, a managed/compiled lane with no repair loop of its
    /// own (Go, C#) drove a parameter or receiver the type-directed generator
    /// REJECTS, using a synthesized zero value so the target builds instead of
    /// ending `unsupported_params`. Records what was synthesized so the report
    /// floors every finding on the target to Low with the forced caveat — a nil
    /// map, nil interface or zero-valued receiver can panic on its own account,
    /// and such a crash must never read as a confirmed defect. Applying it is a
    /// no-op (it only labels); the generator already emitted the value.
    ForcedSyntheticParams {
        detail: String,
    },
    /// Inject the synthesized Win32 `windows.h` placeholder header (the scalar +
    /// pointer typedef surface: `BOOL`, `DWORD`, `PUCHAR`, …) into the harness
    /// build, force-included so a stray Win32 name resolves to its real underlying
    /// type even where the target never `#include`d a platform header. Reuses the
    /// cross-compile stub content. Deliberately Win32-typedefs-only: an MFC *class*
    /// like `CString` is not injected — a minimal class stub can't satisfy real
    /// method calls (`GetLength`/`GetAt`), so such targets degrade to a report-only
    /// static scan instead (the graceful path).
    Win32Pack,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct RepairManifest {
    pub repairs: Vec<Repair>,
}

impl RepairManifest {
    pub fn already_attempted(&self, key: &str) -> bool {
        self.repairs.iter().any(|r| match r {
            Repair::HeaderPlaceholder { virtual_path } => virtual_path == key,
            Repair::HeaderForward { virtual_path, .. } => {
                key == format!("forward-h:{virtual_path}")
            }
            Repair::ConfigHeaderSynth { virtual_path } => key == format!("config-h:{virtual_path}"),
            Repair::AddIncludeDir { dir } => dir.display().to_string() == key,
            Repair::IncludeTypeHeader { type_name, .. } => {
                key == format!("type-header:{type_name}")
            }
            Repair::TypePlaceholder { type_name } => type_name == key,
            Repair::TypeAlias { type_name, .. } => type_name == key,
            Repair::ConfigTypeAlias { type_name, .. } => key == format!("config-alias:{type_name}"),
            Repair::MacroDefine { name, .. }
            // Same key as MacroDefine: two repairs must never both define one
            // macro, which would be a conflicting redefinition rather than a fix.
            | Repair::ConfigGuardDefine { name, .. } => key == format!("macro:{name}"),
            Repair::IncludeStdHeader { symbol, .. } => key == format!("stdhdr:{symbol}"),
            Repair::DeclareFunction { symbol, .. } => key == format!("decl:{symbol}"),
            Repair::AddSource { source_path, .. } => source_path.display().to_string() == key,
            Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => symbol == key,
            Repair::EnvVarInjection { name, .. } => name == key,
            Repair::AdaPackageStub { unit, .. } => key == format!("ada-spec:{unit}"),
            Repair::AdaPackageBodyStub { unit, .. } => key == format!("ada-body:{unit}"),
            Repair::OverrideAdaBodyStub { source, .. } => {
                key == format!("ada-override:{}", source.display())
            }
            Repair::AddAdaSource { unit, .. } => key == format!("ada-src:{unit}"),
            Repair::StubGprImport { project } => key == format!("gpr-stub:{project}"),
            Repair::PlatformStub { platform } => key == format!("platform-stub:{platform}"),
            Repair::ForcedSyntheticParams { .. } => key == "forced-synthetic-params",
            Repair::Win32Pack => key == "win32-pack",
        })
    }
}

/// Apply one Repair to the per-target repairs directory, returning the
/// extra-source / extra-include paths to thread through the rebuild.
pub struct ApplyOutcome {
    pub extra_sources: Vec<PathBuf>,
    pub extra_includes: Vec<PathBuf>,
}

/// The real in-tree source files (`.ads` + `.adb`) for an Ada unit, but only
/// when a `.ads` spec is among them: a `with` / cross-unit symbol reference needs
/// the unit's *spec* to compile against, so a body-only unit (no spec in the
/// tree) must fall through to the spec-synthesizing stub rather than have its
/// body added (which wouldn't satisfy the `with`).
/// The stub project stem for a missing GPR import path. GNAT resolves
/// `with "gnatcoll";` to a `gnatcoll.gpr` on the project path, so the stem must
/// match the imported name (extension stripped). Sanitized to a valid GPR/Ada
/// identifier — real `with` names already are, so this is a no-op for them.
fn gpr_import_stub_name(path: &str) -> String {
    let stem = std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    let mut out: String = stem
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if !out.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        out.insert_str(0, "gpr_");
    }
    out
}

/// A GPR/Ada project identifier for a stub project name. GPR names are
/// case-insensitive; capitalize the first character for the conventional form.
/// `stem` is already a valid identifier (see [`gpr_import_stub_name`]).
fn ada_project_identifier(stem: &str) -> String {
    let mut chars = stem.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => "Gpr_Stub".to_owned(),
    }
}

fn ada_real_source_with_spec(
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    unit: &str,
) -> Option<Vec<PathBuf>> {
    let sources = decl_index.ada_unit_source_files(unit);
    let has_spec = sources
        .iter()
        .any(|p| p.extension().and_then(|e| e.to_str()) == Some("ads"));
    has_spec.then_some(sources)
}

/// Whether a missing macro `name` is used *function-like* (`PX4_ERR(fmt, ...)`)
/// anywhere in the source, at a word boundary. A function-like macro needs a
/// `#define name(...) ...` stub; an object-like `#define name 0` turns
/// `name("...")` into `0("...")` (a call on an int).
/// Does `source` use `name` directly in a preprocessor VALUE context — `#if NAME`
/// or `#elif NAME`, where the macro must expand to an integer expression — rather
/// than only a definedness test (`#ifdef NAME` / `#if defined(NAME)`)? An empty
/// `#define NAME` makes such a use `#if ` → "#if with no expression"; the stub must
/// carry a value. The classic trap: a project header self-provides the macro via
/// `#ifndef NAME / #define NAME <0|1> / #endif`, a force-included empty `#define`
/// suppresses that (the `#ifndef` now skips), and the later `#if NAME` breaks
/// (yyjson's `YYJSON_U64_TO_F64_NO_IMPL`). Emitting `0` keeps the TU compiling.
fn macro_used_in_if_value_context(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        let l = line.trim_start();
        for kw in ["#if", "#elif"] {
            if let Some(rest) = l.strip_prefix(kw) {
                let rest = rest.trim_start();
                if let Some(after) = rest.strip_prefix(name) {
                    // NAME as a whole bare token (not `defined(NAME)`, not a longer
                    // identifier like `NAME_EXT`).
                    if after
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
                    {
                        return true;
                    }
                }
            }
        }
        false
    })
}

/// The macro to define so that the `#error` on (1-based) `error_line` of `source`
/// is no longer reached, or `None` when no single definition can suppress it.
///
/// A configure-style header states its requirement as a conditional whose dead
/// end is a `#error` — libssh's
///
/// ```c
/// #ifdef HAVE_STRTOULL
/// ...
/// #elif defined(HAVE___STRTOULL)
/// ...
/// #else
/// # error "no strtoull function found"
/// #endif
/// ```
///
/// or ImageMagick's `#if !defined(MAGICKCORE_QUANTUM_DEPTH) / # error "you should
/// set MAGICKCORE_QUANTUM_DEPTH" / #endif`. Nothing is MISSING from the tree in
/// either case: a real `./configure` would have defined the macro, and offline we
/// have to supply it ourselves or the translation unit never compiles.
///
/// Walks up from the `#error` through every enclosing conditional, tracking
/// nesting so an inner `#endif` cannot be mistaken for an opening directive. At
/// each level:
///
/// * error inside a NEGATIVE branch (`#ifndef X`, `#if !defined(X)`) — define `X`,
///   which makes the branch dead.
/// * error inside the `#else` of a chain — define the FIRST positively-tested
///   macro, which takes the chain's first branch and skips the else.
///
/// The OUTERMOST negative feature-test guard wins over the innermost decision,
/// because it deletes the whole fallback block rather than steering it. libssh's
/// real shape is nested:
///
/// ```c
/// #if !defined(HAVE_STRTOULL)
/// # if defined(HAVE___STRTOULL)
/// #  define strtoull __strtoull
/// # else
/// #  error "no strtoull function found"
/// # endif
/// #endif
/// ```
///
/// Taking the inner branch would define `HAVE___STRTOULL` and alias `strtoull` to
/// a symbol this host does not have — trading a `#error` for an undefined
/// reference. Defining `HAVE_STRTOULL` removes the block entirely and leaves the
/// real libc function in place, which is exactly what a configure run would do.
///
/// Anything else (a comparison, `#if 0`, a condition with no plain `defined(X)`
/// term, an error reached because a macro IS defined) returns `None` — a wrong
/// define is worse than an honest failure.
fn config_guard_macro_to_define(source: &str, error_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let error_index = (error_line as usize).checked_sub(1)?;
    if error_index >= lines.len() {
        return None;
    }
    let mut depth = 0usize;
    let mut in_else_branch = false;
    // Conditions of the chain that owns the error's branch at THIS level, opening
    // one first. Cleared on the way out to the enclosing level.
    let mut chain: Vec<&str> = Vec::new();
    let mut innermost: Option<String> = None;
    let mut outermost_negative_guard: Option<String> = None;
    for index in (0..error_index).rev() {
        let directive = lines[index].trim_start();
        let Some(rest) = directive.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("endif") {
            depth += 1;
            continue;
        }
        if depth > 0 {
            if rest.starts_with("if") {
                depth -= 1;
            }
            continue;
        }
        if let Some(condition) = rest.strip_prefix("elif") {
            chain.push(condition);
            continue;
        }
        if rest.starts_with("else") {
            in_else_branch = true;
            continue;
        }
        // An opening directive at this level: decide, then keep walking outward.
        let opening = if let Some(condition) = rest.strip_prefix("ifndef") {
            Some((condition, true))
        } else if let Some(condition) = rest.strip_prefix("ifdef") {
            Some((condition, false))
        } else {
            rest.strip_prefix("if").map(|condition| {
                let owning = {
                    chain.push(condition);
                    chain.reverse();
                    // In a negative branch, what the level tests for absence. In an
                    // else, the FIRST condition of the chain — satisfying it skips
                    // every later branch including the else.
                    if in_else_branch {
                        chain.first().copied().unwrap_or(condition)
                    } else {
                        chain.last().copied().unwrap_or(condition)
                    }
                };
                let negated = owning.trim_start().starts_with('!');
                (owning, negated)
            })
        };
        let Some((condition, negated)) = opening else {
            continue;
        };
        // A definition helps only when the error sits in the branch taken while the
        // macro is ABSENT: the true branch of a negative test, or the else of a
        // positive one. The other two shapes fire BECAUSE the macro is defined.
        if in_else_branch != negated {
            if let Some(name) = defined_macro_name(condition) {
                // NEVER the header's own include guard. `#ifndef PRIV_H / #define
                // PRIV_H` wraps the entire file, so it is always the outermost
                // negative test — and defining it does not repair the `#error`, it
                // deletes the whole header, declarations and all.
                if !is_include_guard(&lines, index, &name) {
                    if innermost.is_none() {
                        innermost = Some(name.clone());
                    }
                    // A pure `#ifndef X` / `#if !defined(X)` wrapper: defining X
                    // deletes the block the error lives in, so the outermost one is
                    // the most complete answer.
                    if negated && !in_else_branch {
                        outermost_negative_guard = Some(name);
                    }
                }
            }
        }
        chain.clear();
        in_else_branch = false;
    }
    outermost_negative_guard.or(innermost)
}

/// Whether the conditional opening at `index` is the file's include guard —
/// `#ifndef X` (or `#if !defined(X)`) whose very next directive is `#define X`.
///
/// It matters because an include guard wraps the WHOLE header and is therefore
/// always the outermost negative test around any `#error` inside it. Defining its
/// macro would not repair the guard that failed; it would preprocess the entire
/// header away, taking every declaration with it — the target then "builds" only
/// because everything it needed got stubbed.
fn is_include_guard(lines: &[&str], index: usize, name: &str) -> bool {
    lines[index + 1..]
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("/*"))
        .and_then(|line| line.strip_prefix('#'))
        .map(str::trim_start)
        .and_then(|directive| directive.strip_prefix("define"))
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|defined| defined == name)
}

/// The macro name in a `defined(X)` / `defined X` / bare `X` preprocessor
/// condition, ignoring a leading `!`. `None` for a compound condition (`&&`,
/// `||`, a comparison, an arithmetic expression) — those have no single macro
/// whose definition decides the branch.
fn defined_macro_name(condition: &str) -> Option<String> {
    let text = condition.trim();
    let text = text.strip_prefix('!').unwrap_or(text).trim();
    let text = text.trim_start_matches('(').trim_end_matches(')').trim();
    let text = match text.strip_prefix("defined") {
        Some(rest) => rest
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim(),
        None => text,
    };
    let name = text.split_whitespace().next()?;
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !name.starts_with(|ch: char| ch.is_ascii_digit());
    (plain && name == text).then(|| name.to_owned())
}

/// Recover a configuration constant from a source-level compatibility guard,
/// e.g. `#if (LIB_VERSION_MAJOR != 3)`. Defining every absent value macro as
/// zero guarantees that such guards fire even though the source states the
/// exact required value. Restrict inference to inequality comparisons in
/// preprocessor lines; ordinary runtime comparisons do not establish a build
/// configuration requirement.
fn macro_required_integer_value(source: &str, name: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("#if") && !trimmed.starts_with("#elif") {
            continue;
        }
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(name) {
            let start = from + rel;
            let end = start + name.len();
            let boundary_before = start == 0
                || !line.as_bytes()[start - 1].is_ascii_alphanumeric()
                    && line.as_bytes()[start - 1] != b'_';
            let boundary_after = end == line.len()
                || !line.as_bytes()[end].is_ascii_alphanumeric() && line.as_bytes()[end] != b'_';
            if boundary_before && boundary_after {
                let after = line[end..].trim_start();
                if let Some(value_text) = after.strip_prefix("!=") {
                    let value_text = value_text.trim_start();
                    let value_len = value_text
                        .char_indices()
                        .take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-'))
                        .map(|(i, c)| i + c.len_utf8())
                        .last()
                        .unwrap_or(0);
                    if value_len > 0 {
                        return Some(value_text[..value_len].to_owned());
                    }
                }
            }
            from = start + 1;
        }
    }
    None
}

fn calling_convention_macro_from_error(tail: &str) -> Option<String> {
    tail.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| {
            !token.is_empty()
                && token.bytes().all(|byte| !byte.is_ascii_lowercase())
                && ["CDECL", "STDCALL", "FASTCALL", "CALLCONV"]
                    .iter()
                    .any(|marker| token.contains(marker))
        })
        .map(str::to_owned)
        .next()
}

/// The macro named by clang's `function-like macro 'X' is not defined`.
///
/// The diagnostic is specific to a preprocessor condition, so the fix is
/// specific too: give it a numeric expansion. gcc words the same situation as
/// `missing binary operator before token "("`, which does not name the macro,
/// so only clang's form is recognised.
fn undefined_function_like_macro_in_condition(tail: &str) -> Option<String> {
    for line in tail.lines() {
        let Some(at) = line.find("function-like macro '") else {
            continue;
        };
        if !line.contains("is not defined") {
            continue;
        }
        let rest = &line[at + "function-like macro '".len()..];
        let name = rest.split('\'').next()?.trim();
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
        {
            return Some(name.to_owned());
        }
    }
    None
}

fn macro_used_function_like(source: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find(&needle) {
        let abs = from + rel;
        let prev_is_ident = abs > 0 && {
            let b = bytes[abs - 1];
            b.is_ascii_alphanumeric() || b == b'_'
        };
        if !prev_is_ident {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// True when a function-like macro wraps a declaration's type, for example
/// `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`. Projects commonly put
/// these API/export wrappers in the public header; if that header is damaged,
/// treating the unknown macro like a logging call (`(...) -> (0)`) corrupts the
/// declaration. An identity variadic macro preserves the type and lets the
/// surviving implementation parse.
fn macro_used_as_declaration_wrapper(source: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find(&needle) {
        let start = from + rel;
        let prev_is_ident =
            start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        if prev_is_ident {
            from = start + 1;
            continue;
        }

        let open = start + name.len();
        let mut depth = 0usize;
        let mut close = None;
        for (offset, ch) in source[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        close = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            return false;
        };
        let wrapped = source[open + 1..close].trim();
        let after = source[close + 1..].trim_start();
        let ident_len = after
            .char_indices()
            .take_while(|(i, c)| {
                (*i == 0 && (c.is_ascii_alphabetic() || *c == '_'))
                    || (*i > 0 && (c.is_ascii_alphanumeric() || *c == '_'))
            })
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .unwrap_or(0);
        let wraps_return_type = !wrapped.is_empty()
            && ident_len > 0
            && after[ident_len..].trim_start().starts_with('(');
        let wraps_function_name = !wrapped.is_empty()
            && wrapped.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            })
            && after.starts_with('(');
        // Parameter decorators such as libyaml's `SHIM(yaml_char_t **end)`
        // wrap a complete parameter declaration and are followed by the next
        // comma or the containing function's close parenthesis. Expanding them
        // to their argument preserves the declaration; a neutral `(0)` macro
        // would turn the parameter into an expression and keep the TU broken.
        let wraps_parameter = !wrapped.is_empty()
            && wrapped.split_ascii_whitespace().count() >= 2
            && (after.starts_with(',') || after.starts_with(')'));
        if wraps_return_type || wraps_function_name || wraps_parameter {
            return true;
        }
        from = start + 1;
    }
    false
}

fn declaration_wrapper_macro_at(file: &str, line: u32) -> Option<String> {
    let source = std::fs::read_to_string(file).ok()?;
    let lines: Vec<&str> = source.lines().collect();
    let index = line.checked_sub(1)? as usize;
    // Configure-generated visibility attributes also occur after an otherwise
    // complete prototype: `void f(void) FFI_HIDDEN;`. With the config header
    // absent, clang reports that declaration as body-less. Removing only a
    // macro-like attribute token is the same semantics-preserving fallback as
    // an empty PUBLIC/API wrapper; it does not invent a type or function body.
    if let Some(declaration) = lines
        .get(index)
        .map(|line| line.trim())
        .and_then(|line| line.strip_suffix(';'))
    {
        if let Some((prefix, name)) = declaration.rsplit_once(char::is_whitespace) {
            let marker = ["HIDDEN", "VISIBILITY", "EXPORT", "PUBLIC", "API", "ATTR"]
                .iter()
                .any(|value| name.contains(value));
            let macro_like = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit());
            if prefix.trim_end().ends_with(')') && marker && macro_like {
                return Some(name.to_owned());
            }
        }
    }
    // Clang points `expected function body after function declarator` at the
    // function name when an export wrapper occupies the preceding line:
    // `YAML_DECLARE(void)\nyaml_get_version(...)`. Inspect the diagnostic line
    // and the two immediately preceding lines, stopping at ordinary code.
    for source_line in (index.saturating_sub(2)..=index)
        .rev()
        .filter_map(|candidate| lines.get(candidate))
        .map(|line| line.trim_start())
    {
        if source_line.is_empty() || source_line.starts_with("/*") || source_line.starts_with('*') {
            continue;
        }
        let name_len = source_line
            .char_indices()
            .take_while(|(i, c)| {
                (*i == 0 && (c.is_ascii_alphabetic() || *c == '_'))
                    || (*i > 0 && (c.is_ascii_alphanumeric() || *c == '_'))
            })
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .unwrap_or(0);
        if name_len == 0 {
            continue;
        }
        let name = &source_line[..name_len];
        let declaration_marker = ["PUBLIC", "API", "EXPORT", "DECL"]
            .iter()
            .any(|marker| name.to_ascii_uppercase().contains(marker));
        if declaration_marker
            && source_line[name_len..].starts_with('(')
            && macro_used_as_declaration_wrapper(&source, name)
        {
            return Some(name.to_owned());
        }
    }
    None
}

/// Find a missing declaration wrapper around a function's exported name, as in
/// `const char * BZ_API(BZ2_bzlibVersion)(void)`. A call earlier in the file is
/// diagnosed as an undeclared function, but stubbing that function is the wrong
/// repair: restoring the identity wrapper makes the surviving real definition
/// parse and provides the implementation.
fn declaration_wrapper_for_symbol(file: &str, symbol: &str) -> Option<String> {
    let source = std::fs::read_to_string(file).ok()?;
    for line in source.lines() {
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(symbol) {
            let start = from + rel;
            let end = start + symbol.len();
            let before_boundary = start == 0
                || !line.as_bytes()[start - 1].is_ascii_alphanumeric()
                    && line.as_bytes()[start - 1] != b'_';
            let after_boundary = end == line.len()
                || !line.as_bytes()[end].is_ascii_alphanumeric() && line.as_bytes()[end] != b'_';
            if before_boundary && after_boundary {
                let before = line[..start].trim_end();
                let after = line[end..].trim_start();
                if before.ends_with('(') && after.starts_with(')') {
                    let wrapper_prefix = before[..before.len() - 1].trim_end();
                    let wrapper_start = wrapper_prefix
                        .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .map_or(0, |i| i + 1);
                    let wrapper = &wrapper_prefix[wrapper_start..];
                    let upper = wrapper.to_ascii_uppercase();
                    if !wrapper.is_empty()
                        && ["PUBLIC", "API", "EXPORT", "DECL"]
                            .iter()
                            .any(|marker| upper.contains(marker))
                    {
                        return Some(wrapper.to_owned());
                    }
                }
            }
            from = start + 1;
        }
    }
    None
}

/// A compile-time undeclared-call diagnostic must never be neutralized with a
/// function-like macro when the same translation unit contains a real function
/// definition. That shape means declaration visibility is broken (or another
/// syntax error prevented the compiler from seeing the definition), not that a
/// header-only assertion/logging macro was deleted.
fn source_defines_function(file: &str, symbol: &str) -> bool {
    std::fs::read_to_string(file)
        .ok()
        .and_then(|source| c_parser::parse_c_functions(&source).ok())
        .is_some_and(|functions| functions.iter().any(|function| function.name == symbol))
}

fn blind_c_return_type_from_source(source: &str, symbol: &str) -> Option<&'static str> {
    let needle = format!("{symbol}(");
    let supported = [
        "unsigned long long",
        "long long",
        "unsigned long",
        "unsigned int",
        "unsigned short",
        "signed char",
        "unsigned char",
        "long",
        "short",
        "int",
        "char",
        "bool",
        "_Bool",
        "size_t",
        "ssize_t",
    ];
    for line in source.lines() {
        let Some(call) = line.find(&needle) else {
            continue;
        };
        let before_call = &line[..call];
        let Some(assign) = before_call.rfind('=') else {
            continue;
        };
        if before_call.as_bytes().get(assign.wrapping_sub(1)) == Some(&b'=')
            || before_call.as_bytes().get(assign + 1) == Some(&b'=')
            || matches!(
                before_call.as_bytes().get(assign.wrapping_sub(1)),
                Some(b'!') | Some(b'<') | Some(b'>')
            )
        {
            continue;
        }
        let declaration = before_call[..assign].trim();
        for data_type in supported {
            if declaration.strip_prefix(data_type).is_some_and(|rest| {
                rest.chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_whitespace())
            }) {
                return Some(data_type);
            }
        }
    }
    None
}

fn blind_c_identifier(name: &str) -> Option<&str> {
    let ident = name.split('(').next().map(str::trim).unwrap_or(name);
    (!ident.is_empty()
        && ident.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        }))
    .then_some(ident)
}

fn synth_typed_blind_c_stub(name: &str, return_type: &str) -> Option<String> {
    let ident = blind_c_identifier(name)?;
    let body = c_stub_gen::stub_body_for_return_type(return_type)?;
    Some(format!(
        "/* auto-synthesised blind stub: `{name}` return inferred from its call site */\n\
         __attribute__((weak)) {return_type} {ident}(void) {{\n    {body}\n}}\n"
    ))
}

/// Crude textual check: does the target source itself define `type_name`
/// (a `typedef ... type_name;`, or a `struct/union/enum type_name {` tag)? Used
/// to decide whether force-including a placeholder is collision-safe.
fn type_defined_in_source(source: &str, type_name: &str) -> bool {
    source.lines().any(|line| {
        let l = line.trim();
        (l.contains("typedef") && l.contains(type_name))
            || l.starts_with(&format!("struct {type_name}"))
            || l.starts_with(&format!("union {type_name}"))
            || l.starts_with(&format!("enum {type_name}"))
    })
}

fn type_used_only_behind_pointers(source: &str, type_name: &str) -> bool {
    let bytes = source.as_bytes();
    let mut from = 0usize;
    let mut found = false;
    while let Some(rel) = source[from..].find(type_name) {
        let start = from + rel;
        let end = start + type_name.len();
        let before_boundary =
            start == 0 || !bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'_';
        let after_boundary =
            end == bytes.len() || !bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_';
        if before_boundary && after_boundary {
            found = true;
            let after = source[end..].trim_start();
            let pointer_use = after.starts_with('*')
                || after
                    .strip_prefix("const")
                    .is_some_and(|rest| rest.trim_start().starts_with('*'));
            if !pointer_use {
                return false;
            }
        }
        from = start + 1;
    }
    found
}

fn source_defines_named_record_tag(source: &str, type_name: &str) -> Option<&'static str> {
    for keyword in ["struct", "union"] {
        let needle = format!("{keyword} {type_name}");
        let mut from = 0usize;
        while let Some(offset) = source[from..].find(&needle) {
            let start = from + offset;
            let before_ok = start == 0
                || source.as_bytes()[start - 1].is_ascii_whitespace()
                || matches!(source.as_bytes()[start - 1], b';' | b'}');
            let after = &source[start + needle.len()..];
            let after_ok = after
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_whitespace() || ch == '{');
            if before_ok
                && after_ok
                && after
                    .find(['{', ';'])
                    .is_some_and(|delimiter| after.as_bytes()[delimiter] == b'{')
            {
                return Some(keyword);
            }
            from = start + needle.len();
        }
    }
    None
}

fn identifier_occurs(text: &str, identifier: &str) -> bool {
    text.match_indices(identifier).any(|(index, _)| {
        let before = index
            .checked_sub(1)
            .and_then(|i| text.as_bytes().get(i))
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
        let after = text
            .as_bytes()
            .get(index + identifier.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
        before && after
    })
}

fn c_type_available_in_force_header(type_name: &str, force_header: &str) -> bool {
    let ignored = [
        "const", "volatile", "restrict", "signed", "unsigned", "short", "long", "char", "int",
        "float", "double", "void", "_Bool", "struct", "union", "enum",
    ];
    let bytes = type_name.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let identifier = &type_name[start..index];
        let decoration = identifier
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch == '_')
            && ["API", "PUBLIC", "EXPORT", "IMPORT", "DECL"]
                .iter()
                .any(|marker| identifier.contains(marker));
        let supplied_by_standard_include = c_stub_gen::c_std_header(identifier)
            .is_some_and(|header| force_header.contains(&format!("#include <{header}>")));
        if !ignored.contains(&identifier)
            && !decoration
            && !supplied_by_standard_include
            && !identifier_occurs(force_header, identifier)
        {
            return false;
        }
    }
    true
}

fn c_prototype_types_available_in_force_header(
    declaration: &c_parser::CDeclaration,
    force_header: &str,
) -> bool {
    c_type_available_in_force_header(&declaration.return_type, force_header)
        && declaration
            .param_types
            .iter()
            .all(|param| c_type_available_in_force_header(param, force_header))
}

/// Synthesise a `struct` for a missing type `type_name` from the field-access
/// chains the target source uses on it. Returns None when the type is not
/// field-accessed (the caller keeps the `void *` placeholder).
///
/// If a real header already typedefs `type_name` to a struct/union *tag*
/// (cFE's `typedef struct CFE_MSG_Message CFE_MSG_Message_t;`, where the tag is
/// an incomplete generated type), complete *that tag* — a second typedef would
/// collide ("typedef redefinition"). Otherwise emit a fresh typedef.
fn synth_field_struct(
    source: &str,
    type_name: &str,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> Option<String> {
    let paths = c_parser::field_access_paths(source, type_name).ok()?;
    if paths.is_empty() {
        return None;
    }
    // Don't synthesize a struct for a type already fully defined in a compiled
    // source — force-including a synthetic one collides with the real definition
    // ("typedef/struct redefinition", libsodium/ngtcp2/blake3 `output_t`). The
    // real definition resolves once its TU compiles. (An *incomplete* tag is not
    // flagged here, so the tag-completion path below still runs for it.)
    if decl_index.type_defined_in_compiled_source(type_name) {
        return None;
    }
    let fields: Vec<c_stub_gen::FieldPath> = paths
        .into_iter()
        .map(|p| c_stub_gen::FieldPath {
            components: p.components,
            self_pointer_components: p.self_pointer_components,
            leaf_indexed: p.leaf_indexed,
            leaf_pointer: p.leaf_pointer,
            leaf_index_element_pointer: p.leaf_index_element_pointer,
            leaf_callable: p.leaf_callable,
            max_index: p.max_index,
        })
        .collect();
    if let Some(underlying) = tree_typedef_underlying(decl_index, type_name) {
        let underlying = underlying.trim();
        if let Some(tag) = underlying.strip_prefix("struct ") {
            return c_stub_gen::synth_struct_tag_from_field_paths(
                tag.trim(),
                false,
                type_name,
                &fields,
            );
        }
        if let Some(tag) = underlying.strip_prefix("union ") {
            return c_stub_gen::synth_struct_tag_from_field_paths(
                tag.trim(),
                true,
                type_name,
                &fields,
            );
        }
    }
    c_stub_gen::synth_struct_from_field_paths(type_name, &fields)
}

/// `synth_field_struct` memoized by `type_name` for one repair retry (#373):
/// `field_access_paths` reparses the whole combined source on every call, so a
/// retry that hits N type placeholders reparsed it N times. Within a retry the
/// `source` is stable, so `type_name` alone is a sufficient key; the cache is
/// created fresh each retry (the source grows between retries), so it never
/// goes stale. The memoized value — including `None` — is byte-identical to the
/// uncached `synth_field_struct` result.
fn cached_field_struct(
    cache: &mut std::collections::HashMap<String, Option<String>>,
    source: &str,
    type_name: &str,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> Option<String> {
    if let Some(cached) = cache.get(type_name) {
        return cached.clone();
    }
    let result = synth_field_struct(source, type_name, decl_index);
    cache.insert(type_name.to_owned(), result.clone());
    result
}

/// The underlying type text of a `typedef ... type_name;` found anywhere in the
/// tree. Checks the parsed-scope `c_type_defs` first; on a miss, lazily scans
/// tree headers (pre-filtered to those that textually mention `type_name`, so
/// almost none are actually parsed) — the real typedef often lives in a sibling
/// directory outside the swept subtree (cFE's `core_api/.../cfe_msg_api_typedefs.h`
/// declares `CFE_MSG_Message_t` while the sweep root is `modules/msg/fsw`).
/// Resolve a return type's typedef chain to its concrete underlying type
/// (`jx9_uint` -> `sxu32` -> `unsigned int`). The stub file only includes
/// auto_types.h, so a project typedef NAME is not in scope there — the stub must
/// name a concrete builtin. Returns the original spelling when no typedef is
/// found (already concrete, or an unknown type left for the stub to reject).
fn resolve_stub_return_type(
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    raw: &str,
) -> String {
    // Resolve the actual type inside function-like export macros. Looking up
    // `CJSON_PUBLIC(cJSON_bool)` as a typedef cannot succeed; unwrap it to
    // `cJSON_bool` first, then follow that alias to `int`.
    let mut current = c_stub_gen::unwrap_export_macro(raw);
    // Width-bearing scalar suffixes are unambiguous even when the raw header
    // index contains several preprocessor-selected typedef bodies. Libarchive,
    // for example, spells `la_int64_t` as `__int64` on Windows and `int64_t` on
    // Unix; following the first unpreprocessed branch can choose the foreign
    // spelling and make an otherwise exact header-backed stub look unsupported.
    if let Some(integer) = c_stub_gen::c_integer_alias(&current) {
        return integer.to_owned();
    }
    for _ in 0..8 {
        match tree_typedef_underlying(decl_index, &current) {
            Some(next) if next.trim() != current && !next.trim().is_empty() => {
                current = next.trim().to_owned();
            }
            _ => break,
        }
    }
    if let Some(integer) = c_stub_gen::c_integer_alias(&current) {
        return integer.to_owned();
    }
    current
}

fn synth_weak_c_data_stub(symbol: &str, data_type: &str) -> Option<String> {
    let data_type = c_stub_gen::unwrap_export_macro(data_type);
    let initializer = match c_stub_gen::stub_body_for_return_type(&data_type)? {
        "return 0;" => "0",
        "return NULL;" => "NULL",
        "return 0.0;" => "0.0",
        _ => return None,
    };
    let declaration = c_data_declaration(symbol, &data_type);
    Some(format!(
        "/* auto-synthesised weak data stub for external object `{symbol}` */\n\
         __attribute__((weak)) {declaration} = {initializer};\n"
    ))
}

fn synth_header_backed_weak_c_data_stub(symbol: &str, data_type: &str) -> String {
    let declaration = c_data_declaration(symbol, data_type);
    format!(
        "/* auto-synthesised weak data stub for external object `{symbol}` */\n\
         __attribute__((weak)) {declaration} = {{0}};\n"
    )
}

fn c_data_declaration(symbol: &str, data_type: &str) -> String {
    if data_type.contains("(*)") {
        return data_type.replacen("(*)", &format!("(*{symbol})"), 1);
    }
    data_type.find('[').map_or_else(
        || format!("{data_type} {symbol}"),
        |array_start| {
            format!(
                "{} {symbol}{}",
                data_type[..array_start].trim_end(),
                &data_type[array_start..]
            )
        },
    )
}

fn unique_definition_header_for_c_type(
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    raw: &str,
) -> Option<PathBuf> {
    let raw = c_stub_gen::unwrap_export_macro(raw);
    let ignored = [
        "const", "volatile", "restrict", "signed", "unsigned", "short", "long", "char", "int",
        "float", "double", "void", "_Bool", "struct", "union", "enum",
    ];
    let mut identifiers = Vec::new();
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let identifier = &raw[start..index];
        if !ignored.contains(&identifier) {
            identifiers.push(identifier);
        }
    }
    identifiers
        .into_iter()
        .rev()
        .find_map(|identifier| decl_index.unique_c_type_definition_header(identifier))
}

fn tree_typedef_underlying(
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    type_name: &str,
) -> Option<String> {
    if let Some(td) = decl_index
        .c_type_defs
        .typedefs
        .iter()
        .find(|t| t.name == type_name)
    {
        return Some(td.underlying.clone());
    }
    for paths in decl_index.header_paths.values() {
        for path in paths {
            let Ok(src) = crate::source_text::read_source_text(path) else {
                continue;
            };
            if !src.contains(type_name) {
                continue;
            }
            if let Ok(defs) = c_parser::parse_c_type_defs(&src) {
                if let Some(td) = defs.typedefs.iter().find(|t| t.name == type_name) {
                    return Some(td.underlying.clone());
                }
            }
        }
    }
    None
}

/// Whether a real header in the tree already declares `type_name` (as a typedef
/// or a struct tag). When true, govfuzz must not force-include a `void *` alias
/// for it — that would clash with the real declaration; the real one resolves on
/// its own once its header compiles.
fn type_known_to_tree(
    type_name: &str,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> bool {
    // The complete tree-wide type-name set (headers + .c), recorded BEFORE
    // `retain_flat_pod_structs` prunes non-flat-POD structs from `c_type_defs`.
    // Without this a `typedef struct {..} X;` header type with pointer fields
    // (jansson `strbuffer_t`, cmark `cmark_strbuf`) is pruned out, the guard
    // misses it, and repair force-includes a synthetic struct that collides with
    // the real header definition ("typedef redefinition with different types").
    decl_index.type_defined_in_compiled_source(type_name)
        || decl_index.cpp_type_name_defined_in_tree(type_name)
        || decl_index
            .c_type_defs
            .typedefs
            .iter()
            .any(|t| t.name == type_name)
        || decl_index
            .c_type_defs
            .structs
            .iter()
            .any(|s| s.name == type_name)
}

fn project_header_defining_type(
    type_name: &str,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> Option<PathBuf> {
    let header = decl_index.unique_c_type_definition_header(type_name)?;
    std::fs::read_to_string(&header)
        .ok()
        .filter(|source| !crate::generate_harness::header_rejects_direct_include(source))?;
    Some(header)
}

/// Whether a missing-header `#include` spelling is a CORBA/IDL-generated stub
/// header — either the TAO/`tao_idl` `<base>C.h`/`<base>S.h` (client-stub /
/// server-skeleton) convention recognised by [`dep_manifest::corba_generated_idl`],
/// or a header living under an `idl/`-named directory. Such a header gets CORBA
/// scaffolding typedefs instead of an empty placeholder.
fn header_is_idl_stub(virtual_path: &str) -> bool {
    if crate::auto::dep_manifest::corba_generated_idl(virtual_path).is_some() {
        return true;
    }
    // `src/idl/Foo.h`, `corba/idl/Bar.hpp`, ... — a header under an idl dir.
    virtual_path
        .split(['/', '\\'])
        .any(|seg| seg.eq_ignore_ascii_case("idl"))
}

pub fn apply_repair(
    repair: &Repair,
    repairs_dir: &Path,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> std::io::Result<ApplyOutcome> {
    apply_repair_with_source(
        repair,
        repairs_dir,
        decl_index,
        None,
        &mut std::collections::HashMap::new(),
    )
}

/// As [`apply_repair`], but with the target's own source text so a
/// `TypePlaceholder` for a missing *struct* the target field-accesses can be
/// synthesised as a real struct (see [`synth_field_struct`]) instead of a
/// `void *` alias the body can never compile against.
pub fn apply_repair_with_source(
    repair: &Repair,
    repairs_dir: &Path,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    target_source: Option<&str>,
    field_struct_cache: &mut std::collections::HashMap<String, Option<String>>,
) -> std::io::Result<ApplyOutcome> {
    let includes_dir = repairs_dir.join(AUTO_INCLUDES_DIR);
    let stubs_path = repairs_dir.join(AUTO_STUBS_FILE);
    let types_path = repairs_dir.join(AUTO_TYPES_FILE);
    let cpp_includes_path = repairs_dir.join(AUTO_CPP_INCLUDES_FILE);
    let defines_path = repairs_dir.join(AUTO_DEFINES_FILE);
    let ada_stubs_dir = repairs_dir.join(AUTO_ADA_STUBS_DIR);
    std::fs::create_dir_all(&includes_dir)?;

    match repair {
        Repair::HeaderPlaceholder { virtual_path } => {
            // `virtual_path` is the literal `#include "..."` spelling
            // from an untrusted source tree. Confine it under
            // includes_dir so a `#include "/etc/x"` or
            // `#include "../../x"` cannot escape into an arbitrary
            // file create/overwrite.
            let p = confined_join(&includes_dir, virtual_path)?;
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // A CORBA/IDL-generated stub header (`<base>C.h`/`<base>S.h`, or one
            // living under an `src/idl/`-style path) needs CORBA scaffolding
            // typedefs, not an empty `#pragma once` that leaves every IDL-defined
            // type undefined and cascades. Branch here (no enum churn) on the same
            // IDL-shape heuristic the dep manifest uses.
            let body = if header_is_idl_stub(virtual_path) {
                c_stub_gen::synth_idl_placeholder_header(virtual_path, &[])
            } else if let Some(rtos) = crate::auto::cross_target::platform_header_stub(virtual_path)
            {
                // A recognized RTOS/vendor platform header (vxWorks.h, semLib.h,
                // sys/neutrino.h, INTEGRITY.h, …) absent on this host: emit the
                // rich type surface so unguarded RTOS application code type-checks
                // and fuzzes, instead of an empty placeholder that cascades into
                // "unknown type" errors. `confined_join` above already created any
                // subdir (`sys/`) for the angled spelling to resolve under `-I`.
                rtos.to_owned()
            } else {
                c_stub_gen::synth_placeholder_header(virtual_path)
            };
            std::fs::write(&p, body)?;
            let extra_includes = relative_include_search_dirs(&includes_dir)?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes,
            })
        }
        Repair::HeaderForward {
            virtual_path,
            source_path,
        } => {
            let p = confined_join(&includes_dir, virtual_path)?;
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let source_path = source_path.canonicalize()?;
            let escaped = source_path
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            std::fs::write(
                &p,
                format!(
                    "#pragma once\n/* govfuzz: forward installed include spelling to real in-tree header */\n#include \"{escaped}\"\n"
                ),
            )?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![includes_dir],
            })
        }
        Repair::ConfigHeaderSynth { virtual_path } => {
            let p = confined_join(&includes_dir, virtual_path)?;
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, c_stub_gen::synth_minimal_config_h())?;
            // Also force-define HAVE_CONFIG_H so a TU that only checks the macro
            // (not #include "config.h") still picks up the configuration.
            append_or_create(&defines_path, "#define HAVE_CONFIG_H 1\n")?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![includes_dir],
            })
        }
        Repair::AddIncludeDir { dir } => {
            // Parent-relative missing includes can require a synthetic child search
            // directory so `-I child` plus `../header.h` reaches an exact recovered
            // sibling. This only creates the planned directory; source files remain
            // untouched and the recovered header stays in the work directory.
            if !dir.exists() {
                std::fs::create_dir_all(dir)?;
            }
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![dir.clone()],
            })
        }
        Repair::IncludeTypeHeader { type_name, header } => {
            let escaped = header
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            insert_type_header_before_consumer(
                &cpp_includes_path,
                &format!("#include \"{escaped}\"\n"),
                type_name,
            )?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::TypePlaceholder { type_name } => {
            // A tree-wide type leaf can be ambiguous while the target's own
            // include graph identifies one exact module definition. Include that
            // real umbrella and avoid a stale `void *` alias in auto_types.h: a
            // later header-backed stub would otherwise include the real typedef
            // after the placeholder and create a collision.
            if let Some(header) = target_source.and_then(|source| {
                decl_index.lookup_c_type_definition_header_near_includes(type_name, source)
            }) {
                let escaped = header
                    .to_string_lossy()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"");
                prepend_or_create(&cpp_includes_path, &format!("#include \"{escaped}\"\n"))?;
                return Ok(ApplyOutcome {
                    extra_sources: vec![],
                    extra_includes: vec![],
                });
            }
            // A recognised C standard type (uint32_t, size_t, ...) or C++ stdlib
            // type resolves to its real header, written to the force-included
            // (and collision-safe) includes file. Any other unknown type gets a
            // `void *` placeholder in auto_types.h, pulled in only via
            // auto_stubs.c — never force-included — so it cannot clash with a
            // real definition in a target source.
            if let Some(body) = c_stub_gen::synth_c_std_include(type_name) {
                append_or_create(&cpp_includes_path, &body)?;
            } else if let Some(body) = c_stub_gen::synth_c_integer_alias_typedef(type_name) {
                // OSAL / cFE / classic-flight-software integer aliases
                // (`int32`, `uint16`, ...). A sound `typedef int32_t int32;`
                // belongs in the force-included file so it reaches the real
                // target source (`auto_types.h`'s void* placeholders never do),
                // and is collision-safe because it only fires when the alias is
                // otherwise missing from the build.
                append_or_create(&cpp_includes_path, &body)?;
            } else if let Some(body) = c_stub_gen::synth_known_c_value_type(type_name) {
                append_or_create(&cpp_includes_path, &body)?;
            } else if let Some(body) = c_stub_gen::synth_cpp_stdlib_include(type_name) {
                append_or_create(&cpp_includes_path, &body)?;
            } else if let Some(record) =
                target_source.and_then(|source| source_defines_named_record_tag(source, type_name))
            {
                // The deleted public header may have carried only the opaque
                // typedef while the target source still defines the named tag
                // later (`struct mpc_parser_t { ... }`). The harness needs the
                // pointer type before that definition, but a fake complete
                // layout would collide. A forward typedef is valid in both TUs.
                append_or_create(
                    &cpp_includes_path,
                    &format!("typedef {record} {type_name} {type_name};\n"),
                )?;
            } else if let Some(body) = target_source
                // Never force-include a field-inferred struct for a type the tree
                // already DEFINES (a `typedef`/`struct` in a project header, e.g.
                // cJSON's `typedef struct cJSON {...} cJSON;`): once that header is
                // pulled in (here via an `add_source` of cJSON.c -> cJSON.h), the
                // synthetic anonymous struct collides ("redefinition of 'cJSON'").
                // `type_defined_in_compiled_source` (synth_field_struct's own guard)
                // only catches a COMPLETE struct in a then-compiled .c; the typedef
                // form lives in a header, so add the broader tree guard here.
                .filter(|_| !type_known_to_tree(type_name, decl_index))
                .and_then(|src| cached_field_struct(field_struct_cache, src, type_name, decl_index))
            {
                // A missing type the target dereferences by field (cFE's
                // `CFE_MSG_Message_t` -> `MsgPtr->CCSDS.Pri.StreamId[0]`) cannot
                // be a `void *` alias, and the `auto_types.h` placeholder is not
                // force-included so the target source never even sees it.
                // Synthesise a struct from the observed accesses and force-include
                // it so the real target source compiles and fuzzes. Collision-safe:
                // only fires when the type is otherwise missing from the build.
                append_or_create(&cpp_includes_path, &body)?;
            } else if target_source.is_some_and(|source| {
                !type_known_to_tree(type_name, decl_index)
                    && type_used_only_behind_pointers(source, type_name)
            }) {
                append_or_create(
                    &cpp_includes_path,
                    &format!(
                        "typedef struct {type_name} {type_name}; /* opaque pointer-only type */\n"
                    ),
                )?;
            } else {
                // A missing type the build references but the target source does
                // not itself define is safe to force-include as a `void *` alias,
                // so an otherwise-stubbed header prototype (`f(..., CFE_SB_MsgId_t
                // *)`) parses — the non-force-included `auto_types.h` placeholder
                // never reaches the real target source. If the target source
                // defines the type itself, keep the collision-safe
                // non-force-included placeholder.
                let alias = c_stub_gen::synth_typedef_placeholder(type_name);
                if target_source.is_some_and(|src| !type_defined_in_source(src, type_name))
                    && !type_known_to_tree(type_name, decl_index)
                {
                    append_or_create(&cpp_includes_path, &alias)?;
                } else {
                    // The target defines it, or a real header declares it (so a
                    // force-included alias would clash) — keep the collision-safe
                    // non-force-included placeholder and let the real one resolve.
                    append_or_create(&types_path, &alias)?;
                }
            }
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::TypeAlias { decls, .. } => {
            // Force-included so the synthesised aliases precede every use in the
            // harness TU. stdint/stddef cover a chain that bottoms out in a
            // standard-width spelling (uintN_t / size_t).
            let mut body = String::from("#include <stdint.h>\n#include <stddef.h>\n");
            for decl in decls {
                body.push_str(decl);
                body.push('\n');
            }
            append_or_create(&cpp_includes_path, &body)?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::ConfigTypeAlias {
            type_name,
            header_path,
            ..
        } => {
            // A curated default-width typedef for an absent-codegen config alias.
            let body = c_stub_gen::synth_c_config_type_alias_typedef(type_name)
                .unwrap_or_else(|| c_stub_gen::synth_typedef_placeholder(type_name));
            if let Some(virtual_path) = header_path {
                // Header-backed: write the typedef INTO the stubbed autocoder
                // header at the include path, so the original `#include
                // "config/Fw*TypeAliasAc.h"` resolves AND the type is defined in
                // one round. Confined under includes_dir (untrusted `#include`
                // spelling) exactly like HeaderPlaceholder.
                let p = confined_join(&includes_dir, virtual_path)?;
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&p, body)?;
                Ok(ApplyOutcome {
                    extra_sources: vec![],
                    extra_includes: vec![includes_dir],
                })
            } else {
                // Bare MissingType: route exactly like the `void *` placeholder
                // arm — force-include (so it reaches the real target source, which
                // a non-force-included `auto_types.h` placeholder never does) ONLY
                // when no real definition is reachable. If a real definition IS
                // present, keep it in non-force `auto_types.h` so a `conflicting
                // types` clash can't happen and the real one resolves.
                if target_source.is_some_and(|src| !type_defined_in_source(src, type_name))
                    && !type_known_to_tree(type_name, decl_index)
                {
                    append_or_create(&cpp_includes_path, &body)?;
                } else {
                    append_or_create(&types_path, &body)?;
                }
                Ok(ApplyOutcome {
                    extra_sources: vec![],
                    extra_includes: vec![],
                })
            }
        }
        Repair::MacroDefine {
            name,
            as_value,
            function_like,
        } => {
            // Value position -> a benign 0 (works as int, NULL, or boolean in
            // version numbers / capability flags / `#ifdef` gates). Type or
            // specifier position (an inline/export qualifier like JSON_INLINE)
            // -> define to *nothing*, so the surrounding declaration parses.
            // Force-included (build.rs) so the definition precedes every use.
            let body = if let Some(value) = decl_index
                .lookup_unique_object_macro(name)
                .or_else(|| known_project_macro_value(name))
            {
                format!("#define {name} {value}\n")
            } else if let Some(definition) = known_project_function_macro(name) {
                definition.to_owned()
            } else if target_source.is_some_and(|s| macro_used_as_declaration_wrapper(s, name)) {
                format!("#define {name}(...) __VA_ARGS__\n")
            } else if *function_like {
                // The compiler told us it is invoked with arguments (a
                // preprocessor condition against an absent library's version
                // macro), so the replacement must be function-like AND numeric.
                format!("#define {name}(...) 0\n")
            } else if target_source.is_some_and(|s| macro_used_function_like(s, name)) {
                // Function-like macro (PX4_ERR(fmt, ...), NuttX/flight-software
                // logging/assert macros). A variadic stub expanding to `(0)` works
                // as a statement (`PX4_ERR("x");` -> `(0);`) and as a value;
                // object-like `0` would make `0("x")` a call on an int.
                format!("#define {name}(...) (0)\n")
            } else if macro_requires_string_literal(name) {
                // Autoconf/CMake identity macros are concatenated with string
                // literals or passed to `%s`. Numeric `0` corrupts adjacent
                // literal syntax (`PROGRAM_PREFIX "foo"`) and caused otherwise
                // valid legacy targets to fail after config-header recovery.
                format!("#define {name} \"\"\n")
            } else if let Some(value) =
                target_source.and_then(|s| macro_required_integer_value(s, name))
            {
                format!("#define {name} {value}\n")
            } else if *as_value
                || target_source.is_some_and(|s| macro_used_in_if_value_context(s, name))
            {
                // Value position (or a `#if NAME` use the all-caps classifier missed
                // and tagged as an empty qualifier macro): a benign 0. An empty
                // `#define NAME` would break `#if NAME` ("#if with no expression").
                format!("#define {name} 0\n")
            } else {
                format!("#define {name}\n")
            };
            append_or_create(&defines_path, &body)?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::ConfigGuardDefine { name, value } => {
            // Same destination as MacroDefine: auto_defines.h, force-included ahead
            // of every TU, so the guard sees the definition before it decides.
            append_or_create(&defines_path, &format!("#define {name} {value}\n"))?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::IncludeStdHeader { symbol, header } => {
            // Force-include the standard header (build.rs precedes every TU) so a
            // standard macro/symbol is declared without a bogus stub.
            let alias = match symbol.as_str() {
                "stricmp" | "strcmpi" => "#ifndef stricmp\n#define stricmp strcasecmp\n#endif\n#ifndef strcmpi\n#define strcmpi strcasecmp\n#endif\n",
                "strnicmp" | "strncmpi" => "#ifndef strnicmp\n#define strnicmp strncasecmp\n#endif\n#ifndef strncmpi\n#define strncmpi strncasecmp\n#endif\n",
                _ => "",
            };
            prepend_or_create(&cpp_includes_path, &format!("#include <{header}>\n{alias}"))?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::DeclareFunction { symbol, .. } => {
            let declaration = decl_index.lookup_c(symbol).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("declaration for `{symbol}` vanished between classification and apply"),
                )
            })?;
            let prototype =
                c_stub_gen::synth_c_forward_declaration(declaration).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!("can't restore declaration for `{symbol}`"),
                    )
                })?;
            append_or_create(&cpp_includes_path, &prototype)?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::StubDeclared { symbol, .. } => {
            let unsupported = |symbol: &str| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("can't stub `{symbol}`: unsupported return type"),
                )
            };
            if let Some(decl) = decl_index.lookup_c(symbol) {
                let mut decl = decl.clone();
                let owning_header = decl_index.lookup_c_stub_header(symbol).filter(|header| {
                    std::fs::read_to_string(header).ok().is_some_and(|source| {
                        !crate::generate_harness::header_rejects_direct_include(&source)
                    })
                });
                // When the stub includes its real owning header, preserve that
                // header's return spelling. Configure-selected aliases can differ
                // by host (`evutil_socket_t` is `int` on Unix and `intptr_t` on
                // Windows); resolving the raw tree's first preprocessor branch
                // can silently choose the wrong ABI. If the project spelling is
                // not directly stubbable, fall back to the typedef-hidden scalar
                // resolution used for headerless declarations.
                let mut synthesized = owning_header.as_ref().and_then(|_| {
                    let resolved_return = resolve_stub_return_type(decl_index, &decl.return_type);
                    c_stub_gen::synth_header_backed_c_stub(&decl, &resolved_return)
                });
                if synthesized.is_none() {
                    decl.return_type = resolve_stub_return_type(decl_index, &decl.return_type);
                    synthesized = c_stub_gen::synth_c_stub(&decl);
                }
                let mut body = String::new();
                if let Some(header) = owning_header {
                    let header = header
                        .to_string_lossy()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    body.push_str(&format!("#include \"{header}\"\n"));
                }
                body.push_str(&synthesized.ok_or_else(|| unsupported(symbol))?);
                append_stub(&stubs_path, &types_path, &body)?;
                let prototype = c_stub_gen::synth_force_include_c_prototype(&decl).or_else(|| {
                    let force_header = std::fs::read_to_string(&cpp_includes_path).ok()?;
                    c_prototype_types_available_in_force_header(&decl, &force_header)
                        .then(|| c_stub_gen::synth_c_prototype(&decl))
                        .flatten()
                });
                if let Some(prototype) = prototype {
                    append_or_create(&cpp_includes_path, &prototype)?;
                }
                Ok(ApplyOutcome {
                    extra_sources: vec![stubs_path],
                    extra_includes: vec![],
                })
            } else if let Some(decl) = decl_index.lookup_cpp_stub_declaration(symbol) {
                // A C++ declaration: emit its stub into a .cpp compiled as C++ —
                // C++ definitions in auto_stubs.c (compiled as C) never compile.
                let mut body = String::new();
                if let Some(header) = decl_index.lookup_cpp_stub_header(symbol) {
                    let header = header
                        .to_string_lossy()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    body.push_str(&format!("#include \"{header}\"\n"));
                }
                body.push_str(&c_stub_gen::synth_c_stub(&decl).ok_or_else(|| unsupported(symbol))?);
                let cpp_stubs_path = repairs_dir.join(AUTO_STUBS_CPP_FILE);
                append_stub(&cpp_stubs_path, &types_path, &body)?;
                Ok(ApplyOutcome {
                    extra_sources: vec![cpp_stubs_path],
                    extra_includes: vec![],
                })
            } else if let Some((qualified_class, simple_class)) = cpp_destructor_class(symbol) {
                // #97: a declared-but-undefined C++ destructor — emit ONE source-level
                // definition into auto_stubs.cpp, with the class's header so the class
                // is complete. This provides the missing complete/base/deleting
                // Itanium variants from a single definition without a duplicate ABI
                // body. (Reached only when plan_repair confirmed the class header is
                // known and no in-tree definition exists.)
                let mut body = String::new();
                if let Some(header) = decl_index.lookup_cpp_stub_header(symbol) {
                    let header = header
                        .to_string_lossy()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    body.push_str(&format!("#include \"{header}\"\n"));
                }
                body.push_str(&format!("{qualified_class}::~{simple_class}() {{}}\n"));
                let cpp_stubs_path = repairs_dir.join(AUTO_STUBS_CPP_FILE);
                append_stub(&cpp_stubs_path, &types_path, &body)?;
                Ok(ApplyOutcome {
                    extra_sources: vec![cpp_stubs_path],
                    extra_includes: vec![],
                })
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("declaration for `{symbol}` vanished between classification and apply"),
                ))
            }
        }
        Repair::AddSource { source_path, .. } => Ok(ApplyOutcome {
            // Add only the symbol's defining file. Pulling its whole transitive
            // dependency closure (the old behaviour) over-includes files that
            // don't compile in isolation — a flight-software unit like cFE's
            // cfe_msg_init.c needs a full mission build, and adding it just breaks
            // the link, whereas the one file that defines the wanted symbol links
            // cleanly. Any further undefined symbols are resolved one per round
            // (AddSource the compiling files, stub the rest via the
            // AddSource->stub fallback); MAX_RETRIES is sized for that.
            extra_sources: vec![source_path.clone()],
            // A recovered implementation commonly includes private headers from
            // its own module directory. Make that directory visible to every TU
            // in the repaired link too: XZ's recovered check/check.c identifies
            // check/check.h, which the target's sibling common/index_hash.c also
            // includes as the otherwise-ambiguous "check.h".
            extra_includes: source_path
                .parent()
                .map(Path::to_path_buf)
                .into_iter()
                .collect(),
        }),
        Repair::StubBlind { symbol } => {
            let inferred_return =
                target_source.and_then(|source| blind_c_return_type_from_source(source, symbol));
            let body = if let Some(data_type) = decl_index.lookup_c_extern_data_type(symbol) {
                let header_backed = decl_index
                    .lookup_unique_c_extern_data_header(symbol)
                    .map(|(header, header_type)| (header.to_path_buf(), header_type.to_owned()))
                    .or_else(|| {
                        target_source.and_then(|source| {
                            decl_index
                                .lookup_c_extern_data_header_near_includes(symbol, source)
                                .map(|(header, header_type)| {
                                    (header.to_path_buf(), header_type.to_owned())
                                })
                        })
                    })
                    .or_else(|| {
                        unique_definition_header_for_c_type(decl_index, data_type)
                            .map(|header| (header, data_type.to_owned()))
                    })
                    .filter(|(header, _)| {
                        std::fs::read_to_string(header).ok().is_some_and(|source| {
                            !crate::generate_harness::header_rejects_direct_include(&source)
                        })
                    });
                if let Some((header, header_type)) = header_backed {
                    let header = header
                        .to_string_lossy()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    format!(
                        "#include \"{header}\"\n{}",
                        synth_header_backed_weak_c_data_stub(symbol, &header_type)
                    )
                } else {
                    let resolved_type = resolve_stub_return_type(decl_index, data_type);
                    synth_weak_c_data_stub(symbol, &resolved_type).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!(
                                "can't stub external data `{symbol}` of type `{data_type}` \
                                 (resolved as `{resolved_type}`)"
                            ),
                        )
                    })?
                }
            } else if let Some(return_type) = inferred_return {
                synth_typed_blind_c_stub(symbol, return_type).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!("can't stub `{symbol}` with inferred return `{return_type}`"),
                    )
                })?
            } else {
                c_stub_gen::synth_blind_stub(symbol)
            };
            append_stub(&stubs_path, &types_path, &body)?;
            // StubBlind is planned from a linker diagnostic, so every caller has
            // already compiled with whatever declaration its translation unit
            // needs. Force-including an old-style fallback prototype into every
            // TU is both redundant and unsafe: a later real system declaration
            // (zlib's `int deflate(z_streamp, int)`) conflicts with `void
            // *deflate()`. Keep the blind definition isolated in auto_stubs.c.
            Ok(ApplyOutcome {
                extra_sources: vec![stubs_path],
                extra_includes: vec![],
            })
        }
        Repair::EnvVarInjection { .. } => {
            // The actual setenv happens inline in
            // attempt.rs::run_fuzz_with_runtrace before pass 2.
            // This arm only exists so the manifest entry has a
            // home in the apply flow; no files are written.
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::AdaPackageStub {
            unit,
            decls,
            ops,
            synthesize_body,
            ..
        } => {
            let files = synth_ada_package_stub(unit, decls, ops, *synthesize_body, &ada_stubs_dir);
            write_stub_files(&files, &ada_stubs_dir)?;
            Ok(ApplyOutcome {
                extra_sources: files.into_iter().map(|file| file.path).collect(),
                extra_includes: vec![],
            })
        }
        Repair::AddAdaSource { sources, .. } => {
            // Copy the unit's REAL source into the Ada repair source dir (already
            // on the build's Source_Dirs), uninstrumented — it only needs to
            // compile and provide the unit, like a dependency. The build's next
            // round surfaces any unit IT in turn `with`s, and the loop adds that.
            std::fs::create_dir_all(&ada_stubs_dir)?;
            let mut copied = Vec::new();
            for src in sources {
                let Some(name) = src.file_name() else {
                    continue;
                };
                // AdaCore-style projects select files such as
                // `unit__unix.adb` through a custom GPR naming scheme. The
                // synthesized project uses GNAT's default naming, so select the
                // host variant and write it as canonical `unit.adb`, just as the
                // initial source-staging path does.
                let source_text = crate::source_text::read_source_text(src).ok();
                let dest_name = source_text
                    .as_deref()
                    .and_then(|source| super::attempt::ada_source_dest_basename(src, source))
                    .or_else(|| super::attempt::ada_variant_dest_basename(&name.to_string_lossy()));
                let Some(dest_name) = dest_name else {
                    continue;
                };
                let dest = ada_stubs_dir.join(dest_name);
                // Never clobber a real/instrumented copy already on the build
                // path (the target's own unit, or one a prior round added).
                if dest.exists() {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(src) {
                    std::fs::write(&dest, bytes)?;
                    copied.push(dest);
                }
            }
            Ok(ApplyOutcome {
                extra_sources: copied,
                extra_includes: vec![],
            })
        }
        Repair::StubGprImport { project } => {
            // Write a minimal, EMPTY stub project so gprbuild resolves the missing
            // external `with "<project>";` and the project LOADS. `prepare_layout`
            // copies these next to govfuzz_build.gpr each round so the import is on
            // the project search path. The stub declares NO sources — the packages
            // the code references from it are stubbed into the Ada stub source dir
            // by the normal MissingAdaWith path, and a source dir can't belong to
            // two projects. Not an extra_source (it's a project file, not a unit).
            let gpr_dir = repairs_dir.join(AUTO_GPR_STUBS_DIR);
            std::fs::create_dir_all(&gpr_dir)?;
            let name = ada_project_identifier(project);
            std::fs::write(
                gpr_dir.join(format!("{project}.gpr")),
                format!(
                    "--  Synthesized stub for a missing external GPR import (--force).\n\
                     abstract project {name} is\n   for Source_Dirs use ();\nend {name};\n"
                ),
            )?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::AdaPackageBodyStub { unit, ops, .. } => {
            let need = stub_gen::StubNeed {
                unit_name: unit.clone(),
                kind: stub_gen::StubNeedKind::PackageBody { ops: ops.clone() },
            };
            let files = stub_gen::synth_all(&[need], &ada_stubs_dir);
            write_stub_files(&files, &ada_stubs_dir)?;
            Ok(ApplyOutcome {
                extra_sources: files.into_iter().map(|file| file.path).collect(),
                extra_includes: vec![],
            })
        }
        Repair::OverrideAdaBodyStub { source, unit, ops } => {
            // Synthesise a stub body from the spec and overwrite the uncompilable
            // source in place, so gprbuild compiles the stub (no machine code)
            // and the dependent target builds. No extra source: the file is
            // already on the build path.
            let need = stub_gen::StubNeed {
                unit_name: unit.clone(),
                kind: stub_gen::StubNeedKind::PackageBody { ops: ops.clone() },
            };
            let files = stub_gen::synth_all(&[need], &ada_stubs_dir);
            if let Some(body) = files
                .iter()
                .find(|file| file.path.extension().and_then(|e| e.to_str()) == Some("adb"))
            {
                // GNAT may print the path relative; the file actually on the
                // build path lives under <work>/src_instrumented.
                if let Some(target) = resolve_build_source(repairs_dir, source) {
                    std::fs::write(&target, &body.content)?;
                }
            }
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::PlatformStub { .. } => {
            // Label-only marker: the attempt loop already wrote the fake platform
            // headers (beside the harness, resolved by the Makefile's `-I .`) and
            // the guard define (into auto_defines.h). Nothing to apply here.
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::ForcedSyntheticParams { .. } => {
            // Label-only marker: the lane's own generator already emitted the
            // synthesized value into the harness source. Nothing to apply here.
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![],
            })
        }
        Repair::Win32Pack => {
            // Write the synthesized windows.h into the repairs dir and force-include
            // it via auto_cpp_includes.h (build.rs force-includes that at the top of
            // EVERY TU), mirroring `apply_platform_stub`. The quote include resolves
            // via the extra `-I` we return below, so a stray Win32 typedef resolves
            // even where the target never #included a platform header.
            std::fs::write(
                repairs_dir.join("windows.h"),
                crate::auto::cross_target::WINDOWS_H_STUB,
            )?;
            let force = "#include \"windows.h\"\n";
            let mut includes = std::fs::read_to_string(&cpp_includes_path).unwrap_or_default();
            for line in force.lines() {
                let line = format!("{line}\n");
                if !includes.contains(&line) {
                    includes.push_str(&line);
                }
            }
            std::fs::write(&cpp_includes_path, includes)?;
            Ok(ApplyOutcome {
                extra_sources: vec![],
                extra_includes: vec![repairs_dir.to_path_buf()],
            })
        }
    }
}

fn macro_requires_string_literal(name: &str) -> bool {
    matches!(
        name,
        "PACKAGE_STRING"
            | "PACKAGE_NAME"
            | "PACKAGE_VERSION"
            | "PROGRAM_PREFIX"
            | "VERSION_STRING"
            | "BUILD_TAG"
    ) || name.ends_with("_VERSION_STRING")
}

/// Public ABI constants whose sole defining header is a supported damaged-file
/// target. These values are stable across cJSON 1.x/1.7 and preserve the parser's
/// lower-byte type tags plus the two ownership flags; assigning all of them zero
/// would compile but fuzz only a semantically broken parser.
fn known_project_macro_value(name: &str) -> Option<&'static str> {
    Some(match name {
        "cJSON_Invalid" => "0",
        "cJSON_False" => "(1 << 0)",
        "cJSON_True" => "(1 << 1)",
        "cJSON_NULL" => "(1 << 2)",
        "cJSON_Number" => "(1 << 3)",
        "cJSON_String" => "(1 << 4)",
        "cJSON_Array" => "(1 << 5)",
        "cJSON_Object" => "(1 << 6)",
        "cJSON_Raw" => "(1 << 7)",
        "cJSON_IsReference" => "256",
        "cJSON_StringIsConst" => "512",
        "CJSON_NESTING_LIMIT" | "CJSON_CIRCULAR_LIMIT" => "1000",
        "BZ_N_RADIX" => "2",
        "BZ_N_QSORT" => "12",
        "BZ_N_SHELL" => "18",
        "BZ_N_OVERSHOOT" => "(2 + 12 + 18 + 2)",
        "BZ_M_IDLE" => "1",
        "BZ_M_RUNNING" => "2",
        "BZ_M_FLUSHING" => "3",
        "BZ_M_FINISHING" => "4",
        "BZ_S_OUTPUT" => "1",
        "BZ_S_INPUT" => "2",
        _ => return None,
    })
}

fn known_project_function_macro(name: &str) -> Option<&'static str> {
    Some(match name {
        "cJSON_ArrayForEach" => {
            "#define cJSON_ArrayForEach(element, array) \
for ((element) = ((array) != NULL) ? (array)->child : NULL; \
     (element) != NULL; (element) = (element)->next)\n"
        }
        "BZALLOC" => "#define BZALLOC(nnn) (strm->bzalloc)(strm->opaque, (nnn), 1)\n",
        "BZFREE" => "#define BZFREE(ppp) (strm->bzfree)(strm->opaque, (ppp))\n",
        "BZ_INITIALISE_CRC" => "#define BZ_INITIALISE_CRC(crcVar) ((crcVar) = 0xffffffffL)\n",
        "BZ_FINALISE_CRC" => "#define BZ_FINALISE_CRC(crcVar) ((crcVar) = ~(crcVar))\n",
        "BZ_UPDATE_CRC" => {
            "#define BZ_UPDATE_CRC(crcVar, cha) \
((crcVar) = ((crcVar) << 8) ^ BZ2_crc32Table[((crcVar) >> 24) ^ ((UChar)(cha))])\n"
        }
        _ => return None,
    })
}

/// Join an untrusted relative path under `base`, refusing anything
/// that would escape it. Rejects absolute paths, Windows prefixes, a
/// root component, and any `..` segment. `.` segments are allowed and
/// collapsed by the join. Returns the contained path on success.
fn confined_join(base: &Path, untrusted: &str) -> std::io::Result<PathBuf> {
    use std::path::Component;
    let candidate = Path::new(untrusted);
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing path traversal in untrusted include path {untrusted:?}: \
                         must stay under {}",
                        base.display()
                    ),
                ));
            }
        }
    }
    let joined = base.join(candidate);
    // Defense in depth: even with only Normal/CurDir components the
    // result must remain prefixed by base.
    if !joined.starts_with(base) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "untrusted include path {untrusted:?} escaped {}",
                base.display()
            ),
        ));
    }
    Ok(joined)
}

/// Include roots that let a confined placeholder also satisfy quoted parent-
/// relative spellings such as `#include "../allocators.h"`. The compiler joins
/// the requested path to each `-I` root; an existing one-level child therefore
/// resolves `child/../allocators.h` back to the placeholder without writing
/// outside `base`. Four levels cover real legacy include layouts while keeping
/// every created directory confined under the repairs tree.
fn relative_include_search_dirs(base: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut dirs = vec![base.to_path_buf()];
    let mut nested = base.to_path_buf();
    for depth in 1..=4 {
        nested = nested.join(format!(".govfuzz-relative-{depth}"));
        std::fs::create_dir_all(&nested)?;
        dirs.push(nested.clone());
    }
    Ok(dirs)
}

fn append_or_create(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(body.as_bytes())?;
    Ok(())
}

/// Put prerequisite declarations/includes before previously synthesized
/// prototypes. Appending `<stddef.h>` after a prototype that already mentions
/// `size_t` does not repair that prototype because C headers are order-sensitive.
fn prepend_or_create(path: &Path, body: &str) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.contains(body) {
        return Ok(());
    }
    std::fs::write(path, format!("{body}{existing}"))
}

/// Insert a recovered project type header before the first already-recovered
/// header that uses the type. A blanket prepend reverses sibling dependencies:
/// adding `ares_threads.h` after `ares.h` produced threads -> public, although
/// the threads header itself uses `ares_status_t` from the public header.
fn insert_type_header_before_consumer(
    path: &Path,
    include_line: &str,
    _type_name: &str,
) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines = existing
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !existing.ends_with('\n') && lines.is_empty() {
        lines.push(existing);
    }
    if !lines.iter().any(|line| line.trim() == include_line.trim()) {
        lines.push(include_line.to_owned());
    }

    let mut headers = Vec::new();
    for line in &lines {
        let Some(header_path) = absolute_quoted_include_path(line) else {
            continue;
        };
        let source = std::fs::read_to_string(&header_path).unwrap_or_default();
        headers.push(RecoveredTypeHeader {
            line: format!("#include \"{header_path}\"\n"),
            path: PathBuf::from(header_path),
            defined_types: header_defined_type_names(&source),
            source,
        });
    }
    headers.sort_by(|left, right| left.line.cmp(&right.line));
    headers.dedup_by(|left, right| left.path == right.path);
    let headers = order_recovered_type_headers(headers);

    lines.retain(|line| absolute_quoted_include_path(line).is_none());
    // All recovered project headers must precede synthesized prototypes that
    // may already mention their typedefs. Keep leading standard headers first,
    // then place the dependency-ordered project headers before declarations.
    let insert_at = lines
        .iter()
        .take_while(|line| line.trim().starts_with("#include"))
        .count();
    lines.splice(
        insert_at..insert_at,
        headers.into_iter().map(|header| header.line),
    );
    std::fs::write(path, lines.concat())
}

#[derive(Debug)]
struct RecoveredTypeHeader {
    line: String,
    path: PathBuf,
    source: String,
    defined_types: Vec<String>,
}

fn absolute_quoted_include_path(line: &str) -> Option<String> {
    let header = line.trim().strip_prefix("#include \"")?.strip_suffix('"')?;
    Path::new(header).is_absolute().then(|| header.to_owned())
}

fn order_recovered_type_headers(headers: Vec<RecoveredTypeHeader>) -> Vec<RecoveredTypeHeader> {
    let count = headers.len();
    let mut edges = vec![Vec::new(); count];
    let mut indegree = vec![0usize; count];
    for prerequisite in 0..count {
        for consumer in 0..count {
            if prerequisite == consumer {
                continue;
            }
            let direct_forward = header_directly_includes(
                &headers[consumer].source,
                headers[prerequisite].path.as_path(),
            );
            let direct_reverse = header_directly_includes(
                &headers[prerequisite].source,
                headers[consumer].path.as_path(),
            );
            let type_dependency = !direct_reverse
                && headers[prerequisite]
                    .defined_types
                    .iter()
                    .filter(|name| !headers[consumer].defined_types.contains(name))
                    .any(|name| contains_identifier(&headers[consumer].source, name));
            if (direct_forward || type_dependency) && !edges[prerequisite].contains(&consumer) {
                edges[prerequisite].push(consumer);
                indegree[consumer] += 1;
            }
        }
    }

    let mut ready = (0..count)
        .filter(|index| indegree[*index] == 0)
        .collect::<Vec<_>>();
    let mut ordered = Vec::with_capacity(count);
    let mut emitted = vec![false; count];
    while !ready.is_empty() {
        ready.sort_by(|left, right| headers[*right].line.cmp(&headers[*left].line));
        let index = ready.pop().expect("non-empty ready queue");
        if emitted[index] {
            continue;
        }
        emitted[index] = true;
        ordered.push(index);
        for dependent in &edges[index] {
            indegree[*dependent] -= 1;
            if indegree[*dependent] == 0 {
                ready.push(*dependent);
            }
        }
    }
    ordered.extend((0..count).filter(|index| !emitted[*index]));

    let mut headers = headers.into_iter().map(Some).collect::<Vec<_>>();
    ordered
        .into_iter()
        .filter_map(|index| headers[index].take())
        .collect()
}

fn header_directly_includes(source: &str, candidate: &Path) -> bool {
    source.lines().any(|line| {
        let Some(include) = line
            .trim()
            .strip_prefix("#include")
            .map(str::trim)
            .and_then(|rest| rest.strip_prefix('"'))
            .and_then(|rest| rest.split_once('"').map(|(include, _)| include))
        else {
            return false;
        };
        candidate.ends_with(include)
            || candidate.file_name().and_then(|name| name.to_str())
                == Path::new(include)
                    .file_name()
                    .and_then(|name| name.to_str())
    })
}

fn header_defined_type_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(defs) = c_parser::parse_c_type_defs(source) {
        names.extend(defs.typedefs.into_iter().map(|typedef| typedef.name));
        names.extend(defs.structs.into_iter().map(|record| record.name));
        names.extend(defs.enums.into_iter().map(|enumeration| enumeration.name));
    }
    // A production header can be only partially parseable because generated
    // configuration/export macros are absent. Preserve ordering information by
    // recovering the final identifier of each textual typedef statement.
    for statement in source.split(';') {
        let Some(typedef) = statement.rsplit_once("typedef").map(|(_, tail)| tail) else {
            continue;
        };
        let bytes = typedef.as_bytes();
        let Some(end) = bytes
            .iter()
            .rposition(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .map(|index| index + 1)
        else {
            continue;
        };
        let start = bytes[..end]
            .iter()
            .rposition(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
            .map_or(0, |index| index + 1);
        let name = &typedef[start..end];
        if start < end
            && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_')
            && !matches!(
                name,
                "void"
                    | "char"
                    | "short"
                    | "int"
                    | "long"
                    | "float"
                    | "double"
                    | "signed"
                    | "unsigned"
                    | "const"
                    | "volatile"
            )
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn contains_identifier(source: &str, name: &str) -> bool {
    let bytes = source.as_bytes();
    let mut from = 0usize;
    while let Some(relative) = source[from..].find(name) {
        let start = from + relative;
        let end = start + name.len();
        let before =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let after =
            end == bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if before && after {
            return true;
        }
        from = start + 1;
    }
    false
}

fn append_stub(stubs_path: &Path, types_path: &Path, body: &str) -> std::io::Result<()> {
    if !types_path.exists() {
        std::fs::write(types_path, "")?;
    }
    let needs_preamble = stubs_path
        .metadata()
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(true);
    if needs_preamble {
        // <stdbool.h> supports synthesized boolean returns; <stdlib.h> supports
        // semantic allocator-wrapper fallbacks (malloc/calloc/free).
        append_or_create(
            stubs_path,
            "#include <stdbool.h>\n#include <stdlib.h>\n#include \"auto_types.h\"\n\n",
        )?;
    }
    // Idempotent append. A later repair round can re-plan an already-applied
    // stub: the build still fails for an unrelated reason, so the same undefined
    // symbol is re-classified and routed back here. Appending the same
    // definition a second time is a hard `redefinition` compile error *within*
    // auto_stubs.c — the `weak` attribute only reconciles duplicate strong/weak
    // definitions across translation units, never two definitions in one TU.
    // (Concretely: a harness that calls cJSON_Parse/cJSON_Print/cJSON_Delete
    // pulls in cJSON.c via AddSource for the first symbol and blind-stubs the
    // other two; re-planning across rounds emitted each blind stub twice and
    // failed the whole previously-working build.) Skip the write when this exact
    // stub is already present so the file holds at most one definition per body.
    if let Ok(existing) = std::fs::read_to_string(stubs_path) {
        if existing.contains(body) {
            return Ok(());
        }
    }
    append_or_create(stubs_path, body)
}

fn write_stub_files(files: &[stub_gen::StubFile], base: &Path) -> std::io::Result<()> {
    for file in files {
        // Ada stub filenames are derived from compiler-diagnostic unit
        // names (untrusted). Confine every write under the stubs dir so
        // a hostile unit name cannot redirect the write elsewhere.
        if !file.path.starts_with(base) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to write Ada stub outside {}: {}",
                    base.display(),
                    file.path.display()
                ),
            ));
        }
        if let Some(parent) = file.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&file.path, &file.content)?;
    }
    Ok(())
}

fn synth_ada_package_stub(
    unit: &str,
    decls: &[String],
    ops: &[stub_gen::StubOp],
    synthesize_body: bool,
    output_root: &Path,
) -> Vec<stub_gen::StubFile> {
    if ops.is_empty() {
        let need = stub_gen::StubNeed {
            unit_name: unit.to_owned(),
            kind: stub_gen::StubNeedKind::PackageSpec {
                decls: decls.to_vec(),
            },
        };
        if synthesize_body {
            stub_gen::synth_all(&[need], output_root)
        } else {
            vec![stub_gen::synth_stub(&need, output_root)]
        }
    } else {
        let mut files = vec![synth_ada_package_spec_with_ops(unit, ops, output_root)];
        if synthesize_body {
            let body_need = stub_gen::StubNeed {
                unit_name: unit.to_owned(),
                kind: stub_gen::StubNeedKind::PackageBody { ops: ops.to_vec() },
            };
            files.push(stub_gen::synth_stub(&body_need, output_root));
        }
        files
    }
}

fn synth_ada_package_spec_with_ops(
    unit: &str,
    ops: &[stub_gen::StubOp],
    output_root: &Path,
) -> stub_gen::StubFile {
    let mut content = String::new();
    content.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    content.push_str("--  Auto-stubbed by govfuzz from project/source inference.\n");
    let context_units = stub_gen::ada_context_units_for_ops(unit, ops);
    for context_unit in &context_units {
        content.push_str(&format!("with {context_unit};\n"));
    }
    if !context_units.is_empty() {
        content.push('\n');
    }
    content.push_str(&format!("package {unit} is\n"));
    content.push_str("   pragma Preelaborate;\n");
    for op in ops {
        match op.kind {
            stub_gen::StubOpKind::Procedure => {
                content.push_str(&format!(
                    "   procedure {}{};\n",
                    op.name,
                    render_ada_profile(&op.params)
                ));
            }
            stub_gen::StubOpKind::Function => {
                content.push_str(&format!(
                    "   function {}{} return {};\n",
                    op.name,
                    render_ada_profile(&op.params),
                    op.return_type.as_deref().unwrap_or("Integer")
                ));
            }
        }
    }
    content.push_str(&format!("end {unit};\n"));

    stub_gen::StubFile {
        path: output_root.join(format!("{}.ads", ada_unit_file_stem(unit))),
        content,
    }
}

fn render_ada_profile(params: &[stub_gen::StubParam]) -> String {
    if params.is_empty() {
        return String::new();
    }
    let rendered = params
        .iter()
        .map(|param| {
            let mut rendered = match param.mode.as_deref().filter(|mode| !mode.is_empty()) {
                Some(mode) => format!("{} : {mode} {}", param.name, param.type_name),
                None => format!("{} : {}", param.name, param.type_name),
            };
            if let Some(default) = param.default.as_deref() {
                rendered.push_str(" := ");
                rendered.push_str(default);
            }
            rendered
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(" ({rendered})")
}

fn ada_unit_file_stem(unit: &str) -> String {
    unit.to_ascii_lowercase().replace('.', "-")
}

/// Win32-only type spellings that show up in cross-platform sources
/// behind `#ifdef _WIN32` blocks. On non-Windows hosts these are
/// genuinely unknown — we *do* synthesise a `void *` typedef so the
/// preprocessor branch parses, but we don't want them surfacing in
/// `needed_for_build.synthesized_types` because Linux maintainers
/// shouldn't be asked to ship `WCHAR`. On Windows hosts these are
/// real, so callers should leave them in the report.
pub fn is_win32_type(name: &str) -> bool {
    matches!(
        name,
        "WCHAR"
            | "LPCWSTR"
            | "LPWSTR"
            | "HANDLE"
            | "DWORD"
            | "TCHAR"
            | "LPSTR"
            | "LPCSTR"
            | "HMODULE"
            | "HINSTANCE"
            | "HWND"
            | "HDC"
            | "HICON"
            | "HMENU"
            | "HBRUSH"
            | "HFONT"
            | "HPEN"
            | "HBITMAP"
            | "HRGN"
            | "HKEY"
            | "HRESULT"
            | "LPVOID"
            | "PVOID"
            | "LPARAM"
            | "WPARAM"
            | "BOOL"
            | "BYTE"
            | "WORD"
            | "UINT"
            | "ULONG"
            | "LPDWORD"
            | "LPCVOID"
            | "SOCKET"
    )
}

/// True when the synthesised typedef for `name` should be hidden from
/// `needed_for_build.synthesized_types` on the current host. Today
/// this only filters Win32 spellings on non-Windows builds — those
/// placeholders are required for the preprocessor branch to parse,
/// but the typedef is not something a Linux maintainer needs to ship.
pub fn is_synthesized_type_report_noise(name: &str) -> bool {
    !cfg!(windows) && is_win32_type(name)
}

/// Follow `name` through the tree-wide typedef map to a concrete C scalar leaf,
/// returning the typedef declarations needed to define it (dependency-first).
/// Returns None when `name` is not a tree typedef, is itself a standard spelling
/// (the std-include path handles those), or the chain bottoms out in something
/// other than a recognised scalar (a struct/pointer/system alias we cannot
/// safely synthesise as a flat typedef).
pub(crate) fn resolve_tree_typedef_chain(
    name: &str,
    type_defs: &[&c_parser::CTypeDefs],
) -> Option<Vec<String>> {
    if is_concrete_c_scalar_spelling(name) {
        return None;
    }
    let mut map: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut ambiguous = std::collections::HashSet::new();
    for defs in type_defs {
        for typedef in &defs.typedefs {
            match map.get(typedef.name.as_str()) {
                Some(existing) if existing.trim() != typedef.underlying.trim() => {
                    ambiguous.insert(typedef.name.as_str());
                }
                Some(_) => {}
                None => {
                    map.insert(typedef.name.as_str(), typedef.underlying.as_str());
                }
            }
        }
    }

    let mut decls = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = name;
    loop {
        if ambiguous.contains(current) {
            return None;
        }
        if !seen.insert(current) || decls.len() > 16 {
            return None; // cycle or runaway chain
        }
        let underlying = map.get(current)?.trim();
        decls.push(format!("typedef {underlying} {current};"));
        if is_concrete_c_scalar_spelling(underlying) {
            decls.reverse();
            return Some(decls);
        }
        if !map.contains_key(underlying) {
            return None; // unknown, non-scalar leaf
        }
        current = underlying;
    }
}

/// Whether `spelling` names a predefined C scalar (built-in or standard
/// fixed-width / size alias) — i.e. a safe terminal for a synthesised typedef
/// chain. Whitespace and a trailing `const`/`volatile` are tolerated.
pub(crate) fn is_concrete_c_scalar_spelling(spelling: &str) -> bool {
    let normalized = spelling.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        normalized.as_str(),
        "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "short int"
            | "unsigned short"
            | "unsigned short int"
            | "int"
            | "signed"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "long int"
            | "unsigned long"
            | "unsigned long int"
            | "long long"
            | "long long int"
            | "unsigned long long"
            | "unsigned long long int"
            | "float"
            | "double"
            | "long double"
            | "_Bool"
            | "bool"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "intptr_t"
            | "uintptr_t"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intmax_t"
            | "uintmax_t"
            | "wchar_t"
    )
}

/// Whether `name` is a C/C++ *reserved identifier* — `__`-prefixed, or `_`
/// followed by an uppercase letter. The standard reserves these for the
/// implementation, so an unknown one in macro/specifier position is always a
/// toolchain/HAL macro (never a user type), and may be defined-empty safely.
fn is_reserved_identifier(name: &str) -> bool {
    name.starts_with("__")
        || (name.starts_with('_') && name.chars().nth(1).is_some_and(|c| c.is_ascii_uppercase()))
}

/// Classify a build error and decide which Repair to attempt. Returns
/// None for errors we don't know how to repair (MissingSharedLib,
/// MissingGprImport, Other) - those flow into needed_for_build and
/// the target gets marked unrecoverable.
pub fn plan_repair(
    error: &BuildErrorKind,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
) -> Option<Repair> {
    plan_repair_with_attempts(error, decl_index, &RepairManifest::default())
}

/// As [`plan_repair`], but aware of repairs already attempted, so an undefined
/// symbol whose defining source was already `AddSource`d (and still didn't link
/// — that file doesn't compile standalone) falls back to a stub instead of
/// re-proposing the same AddSource forever.
pub fn plan_repair_with_attempts(
    error: &BuildErrorKind,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    attempted: &RepairManifest,
) -> Option<Repair> {
    plan_repair_forced(error, decl_index, attempted, false)
}

/// As [`plan_repair_with_attempts`], but with `--force` awareness. Under
/// `force`, the planner is maximally aggressive: EVERY undefined type the
/// compiler names (`MissingType`/`IncompleteType`) becomes an opaque
/// `TypePlaceholder`, and EVERY undefined symbol becomes a blind `StubBlind`,
/// so the diagnostic-driven repair loop keeps making progress until the build
/// is clean or the `--max-repair-rounds` cap — rather than stalling the moment
/// a type isn't resolvable from the tree. Non-force behaviour is byte-for-byte
/// unchanged (`force == false` is the default path).
pub fn plan_repair_forced(
    error: &BuildErrorKind,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    attempted: &RepairManifest,
    force: bool,
) -> Option<Repair> {
    plan_repair_forced_with_source_policy(error, decl_index, attempted, force, true)
}

/// Variant of [`plan_repair_forced`] used by the attempt loop after its bounded
/// real-source budget is exhausted. Disabling source additions preserves the
/// normal declared/blind stub fallbacks without pretending an application-sized
/// dependency closure was linked into the isolated harness.
pub(crate) fn plan_repair_forced_with_source_policy(
    error: &BuildErrorKind,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    attempted: &RepairManifest,
    force: bool,
    allow_source_addition: bool,
) -> Option<Repair> {
    // A stray Win32 typedef (`BOOL`, `DWORD`, `PUCHAR`, …) referenced by a file
    // that never `#include`d a platform header: inject the synthesized windows.h
    // stub (real underlying types) via the repair loop rather than fail the build.
    // Only proposed once — the `attempted` guard keeps the retry loop from
    // re-planning it forever. An MFC *class* (`CString`) is deliberately NOT routed
    // here: a minimal class stub can't satisfy real methods, so it falls through to
    // the external-class path and degrades to a report-only scan.
    if let BuildErrorKind::MissingType { name }
    | BuildErrorKind::IncompleteType { name }
    | BuildErrorKind::MissingMacro { name, .. } = error
    {
        if crate::auto::cross_target::is_win32_known_name(name) {
            if !attempted.already_attempted("win32-pack") {
                return Some(Repair::Win32Pack);
            }
            // The pack OWNS these names, and it defines them with their real
            // underlying types (`PUCHAR` is `UCHAR *`, `DWORD` is `unsigned
            // long`). Falling through to the generic placeholder would append a
            // `typedef void *PUCHAR;` to a header that already includes the
            // pack's `windows.h` — "typedef redefinition with different types",
            // which fails the build outright rather than deferring a problem.
            //
            // This is reachable whenever one round reports several Win32 names:
            // the first plans the pack, and every later one in the same round
            // sees it as already attempted. Declining is correct — a wrong
            // definition is worse than none, and the pack's force-include is what
            // actually resolves the name.
            return None;
        }
    }
    match error {
        BuildErrorKind::MissingHeader { path } => {
            // Prefer the project's real header (resolved from the tree-wide header
            // index) over an empty placeholder, which only defers the failure to
            // a cascade of "unknown type" errors.
            if let Some(dir) = decl_index.include_root_for(path) {
                Some(Repair::AddIncludeDir { dir })
            } else if c_stub_gen::is_config_header(path) {
                // A project that ships only `config.h.in` (autoconf/cmake): an
                // empty placeholder leaves `#ifdef HAVE_CONFIG_H`-guarded code
                // unconfigured. Synthesize a minimal config.h + define
                // HAVE_CONFIG_H so the build proceeds (libarchive, tcpdump).
                Some(Repair::ConfigHeaderSynth {
                    virtual_path: path.clone(),
                })
            } else if let Some((type_name, underlying)) =
                c_stub_gen::config_type_alias_from_header(path)
            {
                // A missing F´ autocoder type-alias header (`config/Fw*TypeAliasAc.h`)
                // whose real width-bearing definition is absent codegen. Write the
                // curated default typedef straight into the stubbed header so a
                // single round resolves both the `#include` and the type, instead
                // of an empty stub that defers to a per-type MissingType cascade
                // (which exhausts the repair-retry budget before it resolves).
                Some(Repair::ConfigTypeAlias {
                    type_name,
                    underlying: underlying.to_owned(),
                    header_path: Some(path.clone()),
                })
            } else if let Some(source_path) = decl_index.unique_header_for(path) {
                Some(Repair::HeaderForward {
                    virtual_path: path.clone(),
                    source_path,
                })
            } else {
                Some(Repair::HeaderPlaceholder {
                    virtual_path: path.clone(),
                })
            }
        }
        BuildErrorKind::MissingType { name } => {
            // A clang/gcc parser RECOVERY ARTIFACT (the bare `type`/`expression`
            // placeholder the frontend substitutes while recovering from a malformed
            // declaration) is never a real missing type. Synthesizing a
            // `typedef void *type;` for it doesn't help AND the placeholder then gets
            // reported as a STILL-BLOCKING synthesized_type dependency. The
            // codegen-vs-deps path already treats it as a codegen error; mirror that
            // here so no junk repair is planned (#48).
            if build_classifier::is_recovery_artifact(name) {
                return None;
            }
            // Standard typedefs missing from a generated stub TU need their real
            // SDK header, not a project `void *` placeholder. This is common
            // after a declared stub copies a signature containing `uint8_t` or
            // `size_t` (xz's check helpers).
            if let Some(header) = c_stub_gen::c_std_header(name) {
                let key = format!("stdhdr:{name}");
                return (!attempted.already_attempted(&key)).then(|| Repair::IncludeStdHeader {
                    symbol: name.clone(),
                    header: header.to_owned(),
                });
            }
            // Prefer the real typedef from the tree-wide index (resolves an
            // arch/config-gated scalar alias to its true width) over the generic
            // `void *` placeholder, which neither matches a scalar decode nor is
            // force-included where a parameter type needs it.
            let tree = [
                &*decl_index.c_type_defs,
                &*decl_index.cpp_type_defs,
                &*decl_index.c_source_scalar_type_defs,
            ];
            if let Some(decls) = resolve_tree_typedef_chain(name, &tree) {
                Some(Repair::TypeAlias {
                    type_name: name.clone(),
                    decls,
                })
            } else if let Some(header) = project_header_defining_type(name, decl_index) {
                let key = format!("type-header:{name}");
                (!attempted.already_attempted(&key)).then_some(Repair::IncludeTypeHeader {
                    type_name: name.clone(),
                    header,
                })
            } else if let Some(underlying) = c_stub_gen::c_config_type_alias(name)
                .filter(|_| !type_known_to_tree(name, decl_index))
            {
                // A recognised framework config-type alias (F´ `Fw*Type`) whose
                // real width-bearing header is absent codegen and not resolvable
                // from the tree — give it the curated upstream default width so
                // the scalar use compiles, instead of the unusable `void *`
                // placeholder. Gated on `type_known_to_tree == false` so it can
                // never shadow a real definition (resolve_tree_typedef_chain can
                // return None even for an in-tree typedef whose leaf isn't a
                // concrete scalar — type_known_to_tree is the real boundary).
                Some(Repair::ConfigTypeAlias {
                    type_name: name.clone(),
                    underlying: underlying.to_owned(),
                    header_path: None,
                })
            } else {
                Some(Repair::TypePlaceholder {
                    type_name: name.clone(),
                })
            }
        }
        BuildErrorKind::MissingMacro { name, as_value } => {
            // A surviving exact preprocessor definition proves this identifier
            // is a macro. Prefer it before the C++ type/namespace veto: parsing a
            // header with an unexpanded closing macro can otherwise record that
            // macro token as a type name and permanently block its own repair.
            if decl_index.lookup_unique_object_macro(name).is_some() {
                return Some(Repair::MacroDefine {
                    name: name.clone(),
                    as_value: *as_value,
                    function_like: false,
                });
            }
            // Clang's ALL-CAPS heuristic can classify a standard typedef such as
            // `FILE` as a missing macro after the project header that included
            // <stdio.h> is removed. Resolve the real SDK type before considering
            // a `#define FILE`, which corrupts declarations and hides every stdio
            // prototype the same header would have supplied.
            if let Some(header) =
                c_stub_gen::c_std_header(name).or_else(|| c_stub_gen::c_std_symbol_header(name))
            {
                let key = format!("stdhdr:{name}");
                return (!attempted.already_attempted(&key)).then(|| Repair::IncludeStdHeader {
                    symbol: name.clone(),
                    header: header.to_owned(),
                });
            }
            if c_stub_gen::synth_c_integer_alias_typedef(name).is_some() {
                return Some(Repair::TypePlaceholder {
                    type_name: name.clone(),
                });
            }
            let tree = [
                &*decl_index.c_type_defs,
                &*decl_index.cpp_type_defs,
                &*decl_index.c_source_scalar_type_defs,
            ];
            if let Some(decls) = resolve_tree_typedef_chain(name, &tree) {
                return Some(Repair::TypeAlias {
                    type_name: name.clone(),
                    decls,
                });
            }
            // Clang reports an unknown ALL-CAPS typedef in a generated stub TU
            // with the same shape as a missing preprocessor macro. If the tree
            // actually declares that type (Expat's PROLOG_STATE), keep a
            // collision-safe placeholder local to auto_stubs.c instead of
            // force-defining the name and corrupting the real header.
            if type_known_to_tree(name, decl_index) && !is_reserved_identifier(name) {
                if let Some(header) = project_header_defining_type(name, decl_index) {
                    return Some(Repair::IncludeTypeHeader {
                        type_name: name.clone(),
                        header,
                    });
                }
                return Some(Repair::TypePlaceholder {
                    type_name: name.clone(),
                });
            }
            // Don't `#define` a project namespace/class/type that the all-caps
            // classifier heuristic mis-read as a build-config macro: defining
            // it corrupts every use (`namespace YAML {` -> `namespace 0 {`,
            // yaml-cpp). A genuine missing build macro isn't a tree symbol —
            // EXCEPT a reserved identifier (`__EXPORT`, `_FOO`): the standard
            // reserves `__`/`_<upper>` names for the implementation, so user code
            // can't define such a type/namespace. A tree "type" sighting of one
            // is just the unexpanded linkage/visibility macro sitting in type
            // position (PX4/NuttX `__EXPORT int f(...)`), so the veto must not
            // block defining it empty.
            // Never `#define` a name the tree DEFINES AS A FUNCTION. The macro
            // rewrites that function's own definition — `int apply_config(Config
            // cfg, ...)` becomes `int (0)(Config cfg, ...)`, which fails to parse
            // — so the repair breaks the very code it was meant to unblock, and
            // the target can never build no matter what else is fixed. The
            // all-caps heuristic already vetoes tree types and namespaces for the
            // same reason; a function is the remaining case, and it is the one
            // that catches the target's own symbol.
            if decl_index.defines_function(name) && !is_reserved_identifier(name) {
                return None;
            }
            if decl_index.cpp_defines_type_or_namespace(name) && !is_reserved_identifier(name) {
                None
            } else if is_synthesized_type_report_noise(name) {
                // A Windows-only TYPE on a non-Windows host (libheif's HMODULE):
                // `#define HMODULE` to empty corrupts `HMODULE x = ...;` -> `x = ...;`.
                // Emit a `void *` typedef placeholder so the foreign declaration
                // parses instead.
                Some(Repair::TypePlaceholder {
                    type_name: name.clone(),
                })
            } else {
                Some(Repair::MacroDefine {
                    name: name.clone(),
                    as_value: *as_value,
                    function_like: false,
                })
            }
        }
        BuildErrorKind::UndeclaredFunction { name, file, .. } => {
            if let Some(header) = c_stub_gen::c_std_symbol_header(name) {
                let key = format!("stdhdr:{name}");
                return (!attempted.already_attempted(&key)).then(|| Repair::IncludeStdHeader {
                    symbol: name.clone(),
                    header: header.to_owned(),
                });
            }
            if let Some(wrapper) = declaration_wrapper_for_symbol(file, name) {
                let key = format!("macro:{wrapper}");
                if !attempted.already_attempted(&key) {
                    return Some(Repair::MacroDefine {
                        name: wrapper,
                        as_value: false,
                        function_like: false,
                    });
                }
            }
            if let Some(decl) = decl_index.lookup_c(name) {
                let key = format!("decl:{name}");
                if !attempted.already_attempted(&key) {
                    return Some(Repair::DeclareFunction {
                        symbol: name.clone(),
                        return_type: decl.return_type.clone(),
                        provenance: format!(
                            "real declaration/definition indexed at line {}; restored at call site",
                            decl.line
                        ),
                    });
                }
            }
            if source_defines_function(file, name) {
                // Static functions are intentionally absent from the tree-wide
                // declaration index. A global force-include cannot safely add a
                // `static` prototype to every translation unit, but replacing the
                // real definition with a macro would be strictly worse. Leave the
                // error for another repair round to clear any preceding syntax
                // diagnostics; if it persists, fail honestly.
                None
            } else if c_stub_gen::is_standard_libc_symbol(name) {
                // The C runtime owns this name, so the neutral macro below is not
                // an option: it is force-included ahead of EVERY translation unit,
                // and an empty object-like define ERASES the identifier — including
                // in the system header that declares it. btop's build died on
                //
                //   /usr/include/unistd.h:1091:26: error: expected identifier or '('
                //     extern long int syscall (long int __sysno, ...) __THROW;
                //
                // because GovFuzz had written `#define syscall`. That is worse than
                // the original error and unfixable by any further repair: nothing is
                // missing, and the broken declaration is inside /usr/include.
                //
                // A runtime name that reaches here has no header mapping in
                // `c_std_symbol_header` (which the arm above already tried), so the
                // honest answer is none — add the mapping there instead, and the
                // call gets its real declaration via `#include`.
                None
            } else {
                // With no declaration or definition anywhere in the offline tree,
                // a compile-time call most often came from a function-like macro
                // in the damaged header (AssertD/VPrintf/BZ_INITIALISE_CRC). A
                // neutral variadic macro fixes the calling TU without inventing an
                // ABI. If a later link-only use remains, the normal UndefinedSymbol
                // arm can still provide a recorded weak stub.
                let key = format!("macro:{name}");
                (!attempted.already_attempted(&key)).then_some(Repair::MacroDefine {
                    name: name.clone(),
                    as_value: false,
                    function_like: false,
                })
            }
        }
        BuildErrorKind::UndefinedSymbol { name } => {
            // Campaign fix: `main` is the harness entry point, never a missing
            // project dependency. An undefined `main` means the generated harness
            // failed to emit one (e.g. a C sequence harness whose entrypoint is
            // `#ifdef`-gated to AFL/libFuzzer and absent under the builtin engine).
            // Blind-stubbing it to a no-op `void *main(void)` makes the binary
            // LINK and then fuzz NOTHING — a FALSE CLEAN. Refuse: let the build
            // fail honestly so the outcome is failed_build, not built+fuzzed.
            if name == "main" {
                return None;
            }
            // A POSIX function whose prototype was hidden by the project's
            // feature/config macros must resolve from its host header before a
            // same-leaf project symbol is considered. Declaration indexes can
            // contain unrelated C++ methods such as `stream::read`; treating one
            // as the C `read(2)` implementation drags an entire contrib project
            // into the harness. Once the header is present, leave resolution to
            // the host runtime; never cross into a same-named project definition.
            if let Some(header) = c_stub_gen::c_std_symbol_header(name) {
                let key = format!("stdhdr:{name}");
                if !attempted.already_attempted(&key) {
                    return Some(Repair::IncludeStdHeader {
                        symbol: name.clone(),
                        header: header.to_owned(),
                    });
                }
                return None;
            }
            // The runtime owns these names. A tree-wide index can contain a
            // same-leaf C++ method or example helper, but it is never a valid
            // implementation of the unresolved C runtime call.
            if c_stub_gen::is_standard_libc_symbol(name) {
                return None;
            }
            // File-scope state is environment, not executable behavior. Linking
            // an entire application module merely to provide `extern int state`
            // commonly drags GUI/platform initialization into an otherwise
            // isolated target. Preserve the declaration's object ABI via
            // StubBlind's weak-data path before considering AddSource.
            if decl_index.lookup_c_extern_data_type(name).is_some() {
                return Some(Repair::StubBlind {
                    symbol: name.clone(),
                });
            }
            // Variadic logging/error callbacks are process-environment
            // boundaries. Their implementation sources frequently initialize a
            // UI, terminal, or application-wide diagnostic subsystem; the real
            // declaration gives us an exact weak ABI stub without importing that
            // dependency graph.
            if let Some(decl) = decl_index.lookup_c(name).filter(|decl| decl.variadic) {
                return Some(Repair::StubDeclared {
                    symbol: name.clone(),
                    return_type: decl.return_type.clone(),
                    provenance: format!("variadic declaration at line {}", decl.line),
                });
            }
            let definition_source = decl_index
                .lookup_c_definition_source(name)
                .or_else(|| decl_index.lookup_cpp_definition_source(name));
            // Prefer the project's real source — unless we already tried it and
            // the symbol is STILL undefined, meaning that file doesn't compile in
            // isolation (its own deps). Then stub the symbol so the link closes
            // (e.g. a harness-injected `CFE_MSG_InitDefaultHdr` lifecycle call
            // whose defining `cfe_msg_init.c` drags in the rest of the module).
            if allow_source_addition {
                if let Some(source_path) = definition_source {
                    if !attempted.already_attempted(&source_path.display().to_string()) {
                        return Some(Repair::AddSource {
                            symbol: name.clone(),
                            source_path: source_path.to_path_buf(),
                        });
                    }
                }
            }
            if let Some(decl) = decl_index.lookup_c(name) {
                Some(Repair::StubDeclared {
                    symbol: name.clone(),
                    return_type: decl.return_type.clone(),
                    provenance: format!("declared at line {}", decl.line),
                })
            } else if cpp_symbol_is_destructor(name) {
                // #97: a declared-but-undefined C++ destructor. The AddSource path
                // above already failed to find an in-tree definition, so no other TU
                // provides it — emit ONE source-level definition `Ns::Class::~Class()
                // {}` when the class's header is known (needed to make the class
                // complete). There is then no duplicate ABI body and no duplicate
                // vtable: exactly one TU (ours) defines the destructor and, if the
                // destructor is the class key function, its vtable — verified that
                // both non-virtual and virtual destructor stubs link cleanly. Without
                // the header we cannot make the class complete, so keep the honest
                // failure. The stub goes through the normal StubDeclared path, so
                // `--no-stubs` suppresses it exactly like every other stub.
                if cpp_destructor_class(name).is_some()
                    && decl_index.lookup_cpp_stub_header(name).is_some()
                {
                    Some(Repair::StubDeclared {
                        symbol: name.clone(),
                        return_type: String::new(),
                        provenance: "destructor stub (declared, no in-tree definition)".to_owned(),
                    })
                } else {
                    None
                }
            } else if let Some(decl) = decl_index.lookup_cpp(name) {
                // A C++ declaration: its stub must be a C++ definition in a .cpp
                // file (qualified names, references, overloads), not C++ text in
                // auto_stubs.c (compiled as C). apply routes it to auto_stubs.cpp.
                use c_stub_gen::DeclarationView;
                Some(Repair::StubDeclared {
                    symbol: name.clone(),
                    return_type: decl.return_type().to_owned(),
                    provenance: "C++ declared in tree".to_owned(),
                })
            } else if name.contains("::") {
                // A qualified C++ symbol (demangled link error: a constructor,
                // overload, or method) we have no usable declaration for. A blind
                // `void Ns::Type::f(void){}` is invalid C and invalid C++, and
                // pollutes auto_stubs.c — don't stub it (the real fix is linking
                // the library).
                None
            } else {
                Some(Repair::StubBlind {
                    symbol: name.clone(),
                })
            }
        }
        BuildErrorKind::MissingSharedLib { .. } => None,
        BuildErrorKind::MissingGprImport { path } => {
            // A missing external `with`ed GPR fails at project LOAD, before any
            // unit compiles. Without `--force` this is an honest missing dependency
            // (reported in the missing-deps manifest, resolvable with `--ada-deps`).
            // Under `--force` the point is to make progress anyway: synthesize an
            // empty stub project so the import resolves and the project loads —
            // then the referenced packages get stubbed by the normal
            // MissingAdaWith path. Only propose once per project.
            let project = gpr_import_stub_name(path);
            let key = format!("gpr-stub:{project}");
            (force && !project.is_empty() && !attempted.already_attempted(&key))
                .then_some(Repair::StubGprImport { project })
        }
        BuildErrorKind::Other { tail } => {
            // `error: function-like macro 'X' is not defined` is emitted ONLY for
            // a use inside a preprocessor condition, where the expansion has to
            // be a number: scrcpy's compat.h asks
            // `#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(58, 9, 100)` for an
            // FFmpeg macro that is not installed. An empty definition leaves the
            // condition malformed, so the whole translation unit — and every
            // target in it — stays unbuildable.
            if let Some(name) = undefined_function_like_macro_in_condition(tail) {
                let key = format!("macro:{name}");
                if !attempted.already_attempted(&key) {
                    return Some(Repair::MacroDefine {
                        name,
                        as_value: true,
                        function_like: true,
                    });
                }
            }
            calling_convention_macro_from_error(tail).and_then(|name| {
                let key = format!("macro:{name}");
                (!attempted.already_attempted(&key)).then_some(Repair::MacroDefine {
                    name,
                    as_value: false,
                    function_like: false,
                })
            })
        }
        // A forward-declared-but-undefined type (pimpl) must NOT be repaired: a
        // `void *` typedef would collide with its `class X;` forward declaration.
        // Leaving it unrepaired lets the post-build report-only gate recognize it
        // as an external/private definition the offline harness can't complete.
        //
        // Under `--force`, however, the point is to keep the repair loop making
        // progress on EVERY diagnostic rather than stalling: synthesize the opaque
        // placeholder so an incomplete type the tree never defines gets stubbed and
        // the build advances (failing that, the terminal report-only floor catches
        // it). The recovery-artifact guard still applies — junk placeholder names
        // never become real typedefs even under force.
        BuildErrorKind::IncompleteType { name } => {
            // A compiler may describe a missing definition for a standard/POSIX
            // struct as incomplete (`struct pollfd`, `sockaddr_storage`). These
            // are not pimpls: pull their real host header just as MissingType does.
            if let Some(header) = project_header_defining_type(name, decl_index) {
                let key = format!("type-header:{name}");
                (!attempted.already_attempted(&key)).then_some(Repair::IncludeTypeHeader {
                    type_name: name.clone(),
                    header,
                })
            } else if c_stub_gen::c_std_header(name).is_some()
                || (force && !build_classifier::is_recovery_artifact(name))
            {
                Some(Repair::TypePlaceholder {
                    type_name: name.clone(),
                })
            } else {
                None
            }
        }
        BuildErrorKind::MissingAdaWith { unit } => {
            // Prefer the unit's REAL source from a sibling dir over a
            // signature-only stub (which drops the unit's enums/constants and
            // cascades). The missing thing is the *spec*, so only add real source
            // when a `.ads` exists; a body-only unit (or one absent from the
            // tree) falls through to the spec-synthesizing stub.
            if let Some(sources) = ada_real_source_with_spec(decl_index, unit) {
                Some(Repair::AddAdaSource {
                    unit: unit.clone(),
                    sources,
                })
            } else {
                Some(Repair::AdaPackageStub {
                    unit: unit.clone(),
                    decls: Vec::new(),
                    ops: decl_index.lookup_ada_package_ops(unit),
                    synthesize_body: !decl_index.has_ada_package_body(unit),
                    provenance: "gnat missing Ada package spec".to_owned(),
                })
            }
        }
        BuildErrorKind::MissingAdaPackageBody { unit } => {
            let sources = decl_index.ada_unit_source_files(unit);
            if decl_index.has_ada_package_body(unit)
                && sources
                    .iter()
                    .any(|path| path.extension().and_then(|ext| ext.to_str()) == Some("adb"))
            {
                Some(Repair::AddAdaSource {
                    unit: unit.clone(),
                    sources,
                })
            } else {
                Some(Repair::AdaPackageBodyStub {
                    unit: unit.clone(),
                    ops: decl_index.lookup_ada_package_ops(unit),
                    provenance: "gnat missing Ada package body".to_owned(),
                })
            }
        }
        BuildErrorKind::MissingAdaSymbol { unit, symbol } => {
            if unit.is_empty() {
                None
            } else {
                let sources = decl_index.ada_unit_source_files_declaring_symbol(unit, symbol);
                if !sources.is_empty() {
                    // Add a real source only when its spec actually declares the
                    // missing symbol. A same-named but wrong-version/shadowing unit
                    // cannot repair this diagnostic and would otherwise loop.
                    Some(Repair::AddAdaSource {
                        unit: unit.clone(),
                        sources,
                    })
                } else if ada_real_source_with_spec(decl_index, unit).is_some() {
                    // The unit exists, but no indexed spec declares this symbol:
                    // retain the compiler's MissingAdaSymbol as explicit
                    // wrong-version/incomplete-binding evidence. Fabricating a
                    // declaration alongside a real package would be an illegal
                    // duplicate unit and can invent the wrong type/profile.
                    None
                } else {
                    Some(Repair::AdaPackageStub {
                        unit: unit.clone(),
                        decls: vec![symbol.clone()],
                        ops: Vec::new(),
                        synthesize_body: !decl_index.has_ada_package_body(unit),
                        provenance: "gnat missing Ada package symbol".to_owned(),
                    })
                }
            }
        }
        BuildErrorKind::UncompilableAdaBody { source } => {
            // Derive the unit from the body's filename (GNAT naming, e.g.
            // `i-arm_v7ar.adb` -> `Interfaces.ARM_V7AR`) and synthesise a stub
            // body from its spec's ops. GNAT prints this path relative, so the
            // real file is resolved (against the build's src_instrumented) at
            // apply time. Only proceed when the spec's profiles are known.
            let unit = ada_unit_from_filename(source);
            let ops = decl_index.lookup_ada_package_ops(&unit);
            if ops.is_empty() {
                return None;
            }
            Some(Repair::OverrideAdaBodyStub {
                source: PathBuf::from(source),
                unit,
                ops,
            })
        }
        BuildErrorKind::MalformedFunctionDecl { file, line } => {
            // A missing public header can erase an API/export wrapper such as
            // `CJSON_PUBLIC(type)`. Recover only that narrow identity-wrapper
            // form; arbitrary body-less generated declarators still have no safe
            // automated repair because rewriting project sources is out of scope.
            declaration_wrapper_macro_at(file, *line).and_then(|name| {
                let key = format!("macro:{name}");
                (!attempted.already_attempted(&key)).then_some(Repair::MacroDefine {
                    name,
                    as_value: false,
                    function_like: false,
                })
            })
        }
        BuildErrorKind::ConfigGuardError { file, line, .. } => {
            // A configure-style header that stops the build because its build
            // system never defined something. Read the conditional that owns the
            // `#error` and define the macro that makes the branch dead. Nothing is
            // missing from the tree, so no other repair kind applies — without this
            // the target is unbuildable however many rounds it gets.
            let source = std::fs::read_to_string(file).ok()?;
            let name = config_guard_macro_to_define(&source, *line)?;
            let key = format!("macro:{name}");
            if attempted.already_attempted(&key) {
                return None;
            }
            // A guard that compares against a value (`QUANTUM_DEPTH != 8`) states
            // the value it needs; a plain feature-test macro only has to exist, and
            // `1` is what a real configure writes (`0` would satisfy `#ifdef X` but
            // fail the equally common `#if X`).
            let value =
                macro_required_integer_value(&source, &name).unwrap_or_else(|| "1".to_owned());
            Some(Repair::ConfigGuardDefine { name, value })
        }
    }
}

fn cpp_symbol_is_destructor(symbol: &str) -> bool {
    symbol
        .split('(')
        .next()
        .and_then(|name| name.rsplit("::").next())
        .is_some_and(|member| member.starts_with('~'))
}

/// #97: split a demangled destructor symbol into (fully-qualified class, simple
/// class name) so a source-level definition can be emitted. Handles namespaced,
/// noexcept, and abi-tagged spellings by trimming to the name up to the first `(`
/// and dropping any trailing qualifiers. `tinyxml2::StrPair::~StrPair()` ->
/// (`tinyxml2::StrPair`, `StrPair`); `~Foo()` (no enclosing scope) -> None.
fn cpp_destructor_class(symbol: &str) -> Option<(String, String)> {
    let name = symbol.split('(').next()?.trim();
    // The member is the segment after the last `::` and starts with `~`.
    let (scope, member) = name.rsplit_once("::")?;
    let simple = member.strip_prefix('~')?.trim();
    if simple.is_empty() || scope.trim().is_empty() {
        return None;
    }
    Some((scope.trim().to_owned(), simple.to_owned()))
}

/// Resolve a build-error source path (which GNAT may print relative, e.g.
/// `i-aarch64.adb`) to the real file on the build path, under
/// `<work>/src_instrumented`. `repairs_dir` is `<work>/harnesses/<id>/repairs`.
fn resolve_build_source(repairs_dir: &Path, source: &Path) -> Option<PathBuf> {
    if source.is_absolute() && source.is_file() {
        return Some(source.to_path_buf());
    }
    let work = repairs_dir.parent()?.parent()?.parent()?;
    let src_instrumented = work.join("src_instrumented");
    let name = source.file_name()?;
    let direct = src_instrumented.join(name);
    if direct.is_file() {
        return Some(direct);
    }
    find_file_by_name(&src_instrumented, name)
}

/// Recursively locate a file by name under `dir` (bounded).
fn find_file_by_name(dir: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut visited = 0usize;
    while let Some(d) = stack.pop() {
        visited += 1;
        if visited > 50_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(path),
                Ok(ft) if ft.is_file() && path.file_name() == Some(name) => return Some(path),
                _ => {}
            }
        }
    }
    None
}

/// Map a GNAT source filename to its Ada unit name. The compiler krunches dots
/// to dashes and prefixes standard hierarchies (`a-`=Ada, `g-`=GNAT,
/// `i-`=Interfaces, `s-`=System): `intr.adb` -> `intr`, `i-arm_v7ar.adb` ->
/// `interfaces.arm_v7ar`. Case-insensitive lookup normalises it downstream.
fn ada_unit_from_filename(source: &str) -> String {
    let file = Path::new(source)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(source);
    let stem = file
        .strip_suffix(".adb")
        .or_else(|| file.strip_suffix(".ads"))
        .unwrap_or(file);
    let expanded = match stem.split_once('-') {
        Some(("a", rest)) => format!("ada-{rest}"),
        Some(("g", rest)) => format!("gnat-{rest}"),
        Some(("i", rest)) => format!("interfaces-{rest}"),
        Some(("s", rest)) => format!("system-{rest}"),
        _ => stem.to_owned(),
    };
    expanded.replace('-', ".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-repair-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn named_source_record_gets_an_opaque_forward_typedef() {
        let source = "struct mpc_parser_t { int state; };\n";
        assert_eq!(
            source_defines_named_record_tag(source, "mpc_parser_t"),
            Some("struct")
        );
        assert_eq!(source_defines_named_record_tag(source, "state"), None);
    }

    #[test]
    fn recovered_aliases_make_declared_stub_prototype_force_include_safe() {
        let declaration = c_parser::CDeclaration {
            name: "utf8proc_free".to_owned(),
            return_type: "void".to_owned(),
            param_types: vec!["utf8proc_uint8_t *".to_owned()],
            variadic: false,
            line: 1,
        };
        let force_header = "#include <stdint.h>\ntypedef uint8_t utf8proc_uint8_t;\n";
        assert!(c_prototype_types_available_in_force_header(
            &declaration,
            force_header
        ));
        assert!(!c_prototype_types_available_in_force_header(
            &declaration,
            ""
        ));

        let stdio_declaration = c_parser::CDeclaration {
            name: "print_error".to_owned(),
            return_type: "void".to_owned(),
            param_types: vec!["FILE *".to_owned()],
            variadic: false,
            line: 1,
        };
        assert!(c_prototype_types_available_in_force_header(
            &stdio_declaration,
            "#include <stdio.h>\n"
        ));
    }

    #[test]
    fn config_guard_error_defines_the_macro_the_guard_tests() {
        // libssh's priv.h, verbatim in shape: a feature-test chain whose dead end is
        // a `#error`. Nothing is missing from the tree — a real ./configure would
        // have defined HAVE_STRTOULL — so this is the only repair that can apply.
        let root = tmpdir();
        let header = root.join("priv.h");
        fs::write(
            &header,
            "#ifdef HAVE_STRTOULL\n\
             # define ssh_strtoull strtoull\n\
             #elif defined(HAVE___STRTOULL)\n\
             # define ssh_strtoull __strtoull\n\
             #else\n\
             # error \"no strtoull function found\"\n\
             #endif\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::ConfigGuardError {
                file: header.display().to_string(),
                line: 6,
                message: "no strtoull function found".to_owned(),
            },
            &idx,
        );
        // The FIRST branch of the chain is the one to satisfy: defining it skips
        // the else the #error lives in.
        assert!(
            matches!(&repair, Some(Repair::ConfigGuardDefine { name, value })
                if name == "HAVE_STRTOULL" && value == "1"),
            "got: {repair:?}"
        );
    }

    #[test]
    fn config_guard_error_takes_the_value_the_guard_requires() {
        // ImageMagick's magick-config.h: the macro must EXIST and then be one of a
        // listed set, so `1` would trade one #error for the next. The value the
        // guard compares against is the one to write.
        let root = tmpdir();
        let header = root.join("magick-config.h");
        fs::write(
            &header,
            "#if !defined(MAGICKCORE_QUANTUM_DEPTH)\n\
             # error \"you should set MAGICKCORE_QUANTUM_DEPTH\"\n\
             #endif\n\
             #if (MAGICKCORE_QUANTUM_DEPTH != 8)\n\
             # error \"MAGICKCORE_QUANTUM_DEPTH is not 8/16/32/64 bits\"\n\
             #endif\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::ConfigGuardError {
                file: header.display().to_string(),
                line: 2,
                message: "you should set MAGICKCORE_QUANTUM_DEPTH".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(&repair, Some(Repair::ConfigGuardDefine { name, value })
                if name == "MAGICKCORE_QUANTUM_DEPTH" && value == "8"),
            "got: {repair:?}"
        );
    }

    #[test]
    fn config_guard_prefers_the_outermost_feature_test_wrapper() {
        // libssh's real shape: the #error is in the else of an INNER chain, wrapped
        // in `#if !defined(HAVE_STRTOULL)`. Taking the inner branch would define
        // HAVE___STRTOULL and alias strtoull to a symbol this host does not have —
        // one #error traded for an undefined reference. Defining the outer guard
        // deletes the block and leaves the real libc function alone.
        let source = "#if !defined(HAVE_STRTOULL)\n\
                      # if defined(HAVE___STRTOULL)\n\
                      #  define strtoull __strtoull\n\
                      # elif defined(HAVE__STRTOUI64)\n\
                      #  define strtoull _strtoui64\n\
                      # else\n\
                      #  error \"no strtoull function found\"\n\
                      # endif\n\
                      #endif\n";
        assert_eq!(
            config_guard_macro_to_define(source, 7).as_deref(),
            Some("HAVE_STRTOULL")
        );

        // Same for the __func__ guard, whose inner branch would alias __func__ to
        // __FUNCTION__ when the C99 builtin is already right there.
        let func = "#ifndef HAVE_COMPILER__FUNC__\n\
                    # ifdef HAVE_COMPILER__FUNCTION__\n\
                    #  define __func__ __FUNCTION__\n\
                    # else\n\
                    #  error \"Your system must provide a __func__ macro\"\n\
                    # endif\n\
                    #endif\n";
        assert_eq!(
            config_guard_macro_to_define(func, 5).as_deref(),
            Some("HAVE_COMPILER__FUNC__")
        );

        // With no negative wrapper, the innermost decision still stands.
        let bare = "#ifdef HAVE_A\n\
                    # define x 1\n\
                    #else\n\
                    # error \"need A\"\n\
                    #endif\n";
        assert_eq!(
            config_guard_macro_to_define(bare, 4).as_deref(),
            Some("HAVE_A")
        );
    }

    #[test]
    fn config_guard_never_defines_the_headers_include_guard() {
        // The include guard wraps the WHOLE file, so it is always the outermost
        // negative test around any #error inside it — and defining it does not
        // repair the guard that failed, it preprocesses the entire header away,
        // declarations included. The target then "builds" only because everything
        // it needed got stubbed, which is not a repair.
        let source = "#ifndef PRIV_H\n\
                      #define PRIV_H\n\
                      \n\
                      #if !defined(HAVE_STRTOULL)\n\
                      # error \"no strtoull function found\"\n\
                      #endif\n\
                      \n\
                      int parse(const char *);\n\
                      #endif\n";
        assert_eq!(
            config_guard_macro_to_define(source, 5).as_deref(),
            Some("HAVE_STRTOULL"),
            "the feature test is the answer, never PRIV_H"
        );

        // Nothing but the include guard means there is no repair to make.
        let only_guard = "#ifndef PRIV_H\n\
                          #define PRIV_H\n\
                          # error \"needs configure\"\n\
                          #endif\n";
        assert_eq!(config_guard_macro_to_define(only_guard, 3), None);
    }

    #[test]
    fn config_guard_walk_skips_nested_conditionals_and_refuses_the_undecidable() {
        // An inner #endif must not be mistaken for the guard's own opening
        // directive, or the walk defines a macro from the wrong conditional.
        let nested = "#ifndef HAVE_ICONV\n\
                      # ifdef __linux__\n\
                      #  define X 1\n\
                      # endif\n\
                      # error \"iconv required\"\n\
                      #endif\n";
        assert_eq!(
            config_guard_macro_to_define(nested, 5).as_deref(),
            Some("HAVE_ICONV")
        );

        // Undecidable shapes: a wrong define is worse than an honest failure.
        for (source, line, why) in [
            (
                "#if VERSION > 3\n# error \"too old\"\n#endif\n",
                2,
                "a comparison has no macro whose mere definition decides it",
            ),
            (
                "#if defined(A) && defined(B)\n# error \"both\"\n#endif\n",
                2,
                "a compound condition names no single macro",
            ),
            (
                "#ifdef HAVE_BROKEN_THING\n# error \"unsupported\"\n#endif\n",
                2,
                "the error fires because the macro IS defined; defining cannot help",
            ),
            (
                "#ifndef HAVE_X\n# define X 1\n#else\n# error \"conflict\"\n#endif\n",
                4,
                "the else of an #ifndef is reached when the macro is already defined",
            ),
            ("# error \"top level\"\n", 1, "no enclosing conditional"),
        ] {
            assert_eq!(
                config_guard_macro_to_define(source, line),
                None,
                "{why}: {source}"
            );
        }
    }

    #[test]
    fn stub_return_type_resolves_typedef_hidden_scalar() {
        // unqlite/jx9 functions return project scalar typedefs (`sxu32`,
        // `jx9_int64`); the stub body must resolve them to a concrete scalar.
        let root = tmpdir();
        fs::write(
            root.join("types.h"),
            "typedef unsigned int sxu32;\ntypedef sxu32 jx9_uint;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert_eq!(resolve_stub_return_type(&idx, "sxu32"), "unsigned int");
        // Two-level chain resolves too.
        assert_eq!(resolve_stub_return_type(&idx, "jx9_uint"), "unsigned int");
        // An already-stubbable type is unchanged; an unknown one is left as-is.
        assert_eq!(resolve_stub_return_type(&idx, "int"), "int");
        assert_eq!(resolve_stub_return_type(&idx, "widget_t"), "widget_t");
        assert_eq!(
            resolve_stub_return_type(&idx, "CJSON_PUBLIC(jx9_uint)"),
            "unsigned int"
        );
        assert_eq!(
            resolve_stub_return_type(&idx, "UTF8PROC_DLLEXPORT utf8proc_ssize_t"),
            "int64_t"
        );
    }

    #[test]
    fn declared_stub_preserves_host_selected_owning_header_return_type() {
        let root = tmpdir();
        fs::write(
            root.join("event.h"),
            "#ifdef _WIN32\n\
             #define evutil_socket_t intptr_t\n\
             #else\n\
             #define evutil_socket_t int\n\
             #endif\n\
             struct event;\n\
             evutil_socket_t event_get_fd(const struct event *);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubDeclared {
                symbol: "event_get_fd".to_owned(),
                return_type: "evutil_socket_t".to_owned(),
                provenance: "event.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("evutil_socket_t event_get_fd"),
            "owning header must select the host ABI: {stubs}"
        );
        assert!(!stubs.contains("intptr_t event_get_fd"), "got: {stubs}");
    }

    #[test]
    fn declared_stub_preserves_header_backed_parameter_and_enum_types() {
        let root = tmpdir();
        fs::write(
            root.join("api.h"),
            "#include <stddef.h>\n\
             typedef struct allocator allocator_t;\n\
             enum parser_type { PARSER_REQUEST };\n\
             typedef enum token_kind { TOKEN_ERROR } token_t;\n\
             void *alloc_value(size_t, const allocator_t *);\n\
             void parser_init(void *, enum parser_type);\n\
             token_t lex_token(void *);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        for (symbol, return_type) in [
            ("alloc_value", "void *"),
            ("parser_init", "void"),
            ("lex_token", "token_t"),
        ] {
            apply_repair(
                &Repair::StubDeclared {
                    symbol: symbol.to_owned(),
                    return_type: return_type.to_owned(),
                    provenance: "api.h".to_owned(),
                },
                &repairs,
                &idx,
            )
            .unwrap();
        }

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("const allocator_t * _gf_p1"),
            "allocator type must match its included prototype: {stubs}"
        );
        assert!(
            stubs.contains("enum parser_type _gf_p1"),
            "complete enum parameter must not be demoted: {stubs}"
        );
        assert!(
            stubs.contains("token_t lex_token"),
            "typedef-hidden enum return must retain its declared spelling: {stubs}"
        );
    }

    #[test]
    fn declared_stub_strips_header_scoped_visibility_from_integer_return() {
        let root = tmpdir();
        fs::write(
            root.join("archive_entry.h"),
            "#include <stdint.h>\n\
             #if defined(_WIN32)\n\
             typedef __int64 la_int64_t;\n\
             #else\n\
             typedef int64_t la_int64_t;\n\
             #endif\n\
             #define __LA_DECL __attribute__((visibility(\"default\")))\n\
             struct archive_entry;\n\
             __LA_DECL la_int64_t archive_entry_size(struct archive_entry *);\n\
             #undef __LA_DECL\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");

        apply_repair(
            &Repair::StubDeclared {
                symbol: "archive_entry_size".to_owned(),
                return_type: "__LA_DECL la_int64_t".to_owned(),
                provenance: "test".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("la_int64_t archive_entry_size") && stubs.contains("return 0;"),
            "got: {stubs}"
        );
        assert!(!stubs.contains("__LA_DECL la_int64_t"), "got: {stubs}");
    }

    #[test]
    fn declared_stub_does_not_directly_include_umbrella_only_header() {
        let root = tmpdir();
        let header = root.join("archive_string.h");
        fs::write(
            &header,
            "#ifndef ARCHIVE_STRING_H\n#define ARCHIVE_STRING_H\n\
             #ifndef LIBRARY_BUILD\n#error This header is only for internal use\n#endif\n\
             void string_free(void *);\n#endif\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubDeclared {
                symbol: "string_free".to_owned(),
                return_type: "void".to_owned(),
                provenance: "archive_string.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            !stubs.contains(&header.to_string_lossy().to_string()),
            "got: {stubs}"
        );
        assert!(
            stubs.contains("void string_free(void * _gf_p0)"),
            "got: {stubs}"
        );
    }

    #[test]
    fn blind_repair_emits_weak_data_for_extern_object() {
        let root = tmpdir();
        fs::write(
            root.join("state.c"),
            "extern int event_debug_mode_on_;\nint use_state(void) { return event_debug_mode_on_; }\n",
        )
        .unwrap();
        fs::write(
            root.join("state_definition.c"),
            "int event_debug_mode_on_ = 1;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_extern_data_type("event_debug_mode_on_"),
            Some("int")
        );
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::UndefinedSymbol {
                    name: "event_debug_mode_on_".to_owned(),
                },
                &idx,
            ),
            Some(Repair::StubBlind { symbol }) if symbol == "event_debug_mode_on_"
        ));
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubBlind {
                symbol: "event_debug_mode_on_".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("int event_debug_mode_on_ = 0;"),
            "extern object must remain data: {stubs}"
        );
        assert!(
            !stubs.contains("event_debug_mode_on_(void)"),
            "got: {stubs}"
        );
    }

    #[test]
    fn blind_repair_uses_header_typedef_for_extern_object() {
        let root = tmpdir();
        let header = root.join("mode.h");
        fs::write(
            &header,
            "typedef enum { SKILL_EASY, SKILL_HARD } skill_t;\nextern skill_t gameskill;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubBlind {
                symbol: "gameskill".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(stubs.contains(&format!("#include \"{}\"", header.display())));
        assert!(stubs.contains("skill_t gameskill = {0};"), "got: {stubs}");
        assert!(!stubs.contains("enum skill_t"), "got: {stubs}");
    }

    #[test]
    fn blind_repair_preserves_extern_function_pointer_as_data() {
        let root = tmpdir();
        let header = root.join("monotonic.h");
        fs::write(
            &header,
            "typedef unsigned long monotime;\nextern monotime (*getMonotonicUs)(void);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubBlind {
                symbol: "getMonotonicUs".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("monotime (*getMonotonicUs)(void) = {0};"),
            "got: {stubs}"
        );
        assert!(
            !stubs.contains("monotime getMonotonicUs(void)"),
            "got: {stubs}"
        );
    }

    #[test]
    fn blind_repair_uses_unique_type_header_for_duplicate_extern_declarations() {
        let root = tmpdir();
        let type_header = root.join("mode.h");
        fs::write(
            &type_header,
            "typedef enum { SKILL_EASY, SKILL_HARD } skill_t;\n",
        )
        .unwrap();
        fs::write(
            root.join("doom.h"),
            "#include \"mode.h\"\nextern skill_t gameskill;\n",
        )
        .unwrap();
        fs::write(
            root.join("hexen.h"),
            "#include \"mode.h\"\nextern skill_t gameskill;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(idx
            .lookup_unique_c_extern_data_header("gameskill")
            .is_none());
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::StubBlind {
                symbol: "gameskill".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(stubs.contains(&format!("#include \"{}\"", type_header.display())));
        assert!(stubs.contains("skill_t gameskill = {0};"), "got: {stubs}");
    }

    #[test]
    fn blind_repair_uses_nearby_header_for_duplicate_external_array() {
        let root = tmpdir();
        for game in ["doom", "hexen"] {
            let dir = root.join(game);
            fs::create_dir_all(&dir).unwrap();
            let umbrella = if game == "hexen" {
                "h2def.h"
            } else {
                "doomdef.h"
            };
            fs::write(dir.join(umbrella), "#include \"info.h\"\n").unwrap();
            fs::write(
                dir.join("info.h"),
                "typedef struct { int value; } state_t;\n\
                 #define NUMSTATES 4\n\
                 extern state_t states[NUMSTATES]; // generated table\n",
            )
            .unwrap();
        }
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_extern_data_type("states"),
            Some("state_t [NUMSTATES]")
        );
        let repairs = root.join("repairs");
        let source = "#include \"h2def.h\"\nint save(void) { return states[0].value; }\n";
        apply_repair_with_source(
            &Repair::StubBlind {
                symbol: "states".to_owned(),
            },
            &repairs,
            &idx,
            Some(source),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains(&root.join("hexen/h2def.h").display().to_string()),
            "got: {stubs}"
        );
        assert!(
            stubs.contains("state_t states[NUMSTATES] = {0};"),
            "got: {stubs}"
        );
    }

    #[test]
    fn ambiguous_type_placeholder_uses_target_module_header() {
        let root = tmpdir();
        for game in ["doom", "hexen"] {
            let dir = root.join(game);
            fs::create_dir_all(&dir).unwrap();
            let umbrella = if game == "hexen" {
                "h2def.h"
            } else {
                "doomdef.h"
            };
            fs::write(dir.join(umbrella), "#define GAME_MODULE 1\n").unwrap();
            fs::write(
                dir.join("r_local.h"),
                "typedef struct { int value; } sector_t;\n",
            )
            .unwrap();
        }
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(idx.unique_c_type_definition_header("sector_t").is_none());
        let repairs = root.join("repairs");
        apply_repair_with_source(
            &Repair::TypePlaceholder {
                type_name: "sector_t".to_owned(),
            },
            &repairs,
            &idx,
            Some("#include \"h2def.h\"\nint save(sector_t *sector);\n"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();

        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(
            forced.contains(&root.join("hexen/r_local.h").display().to_string()),
            "got: {forced}"
        );
        let types = fs::read_to_string(repairs.join(AUTO_TYPES_FILE)).unwrap_or_default();
        assert!(!types.contains("typedef void *sector_t;"), "got: {types}");
    }

    #[test]
    fn blind_repair_infers_integral_return_from_declaration_assignment() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair_with_source(
            &Repair::StubBlind {
                symbol: "ir_target_option".to_owned(),
            },
            &repairs,
            &idx,
            Some("int res = ir_target_option(\"help\");\n"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("int ir_target_option(void)") && stubs.contains("return 0;"),
            "got: {stubs}"
        );
        assert!(!stubs.contains("void *ir_target_option"), "got: {stubs}");

        assert!(
            !repairs.join(AUTO_CPP_INCLUDES_FILE).exists(),
            "a linker-only blind stub must not inject a global prototype"
        );
    }

    #[test]
    fn blind_link_stub_does_not_conflict_with_later_system_declaration() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");

        apply_repair_with_source(
            &Repair::StubBlind {
                symbol: "deflate".to_owned(),
            },
            &repairs,
            &idx,
            Some("int call(void *stream) { return deflate(stream, 0); }\n"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(stubs.contains("void *deflate(void)"), "got: {stubs}");
        assert!(
            !repairs.join(AUTO_CPP_INCLUDES_FILE).exists(),
            "the linker repair must not place a conflicting declaration before system headers"
        );
    }

    #[test]
    fn variadic_dependency_prefers_declared_stub_over_implementation_source() {
        let root = tmpdir();
        fs::write(
            root.join("diagnostic.h"),
            "#include <stdbool.h>\nbool warningf(int kind, const char *fmt, ...);\n",
        )
        .unwrap();
        fs::write(
            root.join("diagnostic.c"),
            "#include \"diagnostic.h\"\nbool warningf(int kind, const char *fmt, ...) { return false; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "warningf".to_owned(),
            },
            &idx,
        )
        .unwrap();
        assert!(matches!(repair, Repair::StubDeclared { ref symbol, .. } if symbol == "warningf"));

        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("warningf(int _gf_p0, const char * _gf_p1, ...)"),
            "variadic ABI must be preserved: {stubs}"
        );
    }

    #[test]
    fn plan_repair_routes_known_win32_names_to_the_win32_pack() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let bool_macro = BuildErrorKind::MissingMacro {
            name: "BOOL".to_owned(),
            as_value: false,
        };
        let cstring_type = BuildErrorKind::MissingType {
            name: "CString".to_owned(),
        };
        let dword_incomplete = BuildErrorKind::IncompleteType {
            name: "DWORD".to_owned(),
        };
        assert!(
            matches!(plan_repair(&bool_macro, &idx), Some(Repair::Win32Pack)),
            "BOOL macro must route to the Win32Pack"
        );
        assert!(
            matches!(
                plan_repair(&dword_incomplete, &idx),
                Some(Repair::Win32Pack)
            ),
            "DWORD incomplete-type must route to the Win32Pack"
        );
        // An MFC *class* is NOT a Win32Pack trigger — it can't be usefully stubbed,
        // so it falls through to the external-class report-only path.
        assert!(
            !matches!(plan_repair(&cstring_type, &idx), Some(Repair::Win32Pack)),
            "CString (an MFC class) must not route to the Win32Pack"
        );
        let other = BuildErrorKind::MissingType {
            name: "widget_t".to_owned(),
        };
        assert!(
            !matches!(plan_repair(&other, &idx), Some(Repair::Win32Pack)),
            "an unknown type must not route to Win32Pack"
        );
    }

    #[test]
    fn incomplete_posix_type_includes_its_real_system_header() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::IncompleteType {
                name: "pollfd".to_owned(),
            },
            &idx,
        )
        .expect("pollfd should be repaired from the host SDK");
        assert!(matches!(
            &repair,
            Repair::TypePlaceholder { type_name } if type_name == "pollfd"
        ));

        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let include = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(include.contains("#include <poll.h>"), "got: {include}");
        assert!(!include.contains("typedef void *pollfd"), "got: {include}");
    }

    #[test]
    fn file_misclassified_as_macro_includes_stdio() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "FILE".to_owned(),
                as_value: false,
            },
            &idx,
        )
        .expect("FILE should resolve from the host SDK");
        assert!(matches!(
            &repair,
            Repair::IncludeStdHeader { symbol, header }
                if symbol == "FILE" && header == "stdio.h"
        ));

        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let include = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(include.contains("#include <stdio.h>"), "got: {include}");
        assert!(!include.contains("#define FILE"), "got: {include}");
    }

    #[test]
    fn errno_constant_misclassified_as_macro_includes_errno_header() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "ENOENT".to_owned(),
                as_value: true,
            },
            &idx,
        )
        .expect("ENOENT should resolve from the host SDK");
        assert!(
            matches!(
                &repair,
                Repair::IncludeStdHeader { symbol, header }
                    if symbol == "ENOENT" && header == "errno.h"
            ),
            "got: {repair:?}"
        );

        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let include = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(include.contains("#include <errno.h>"), "got: {include}");
        assert!(!include.contains("#define ENOENT"), "got: {include}");
    }

    #[test]
    fn force_stubs_every_undefined_type_and_symbol() {
        let idx = crate::auto::decl_index::DeclarationIndex::build(&tmpdir()).unwrap();
        let no_attempts = RepairManifest::default();

        // IncompleteType (a pimpl forward-decl) is deliberately UNREPAIRED in the
        // default path — the report-only gate recognises it as external. Under
        // force, it becomes an opaque placeholder so the loop keeps progressing.
        let incomplete = BuildErrorKind::IncompleteType {
            name: "Foo".to_owned(),
        };
        assert!(
            plan_repair_forced(&incomplete, &idx, &no_attempts, false).is_none(),
            "non-force: an incomplete type must stay unrepaired (external/pimpl)"
        );
        assert!(
            matches!(
                plan_repair_forced(&incomplete, &idx, &no_attempts, true),
                Some(Repair::TypePlaceholder { ref type_name }) if type_name == "Foo"
            ),
            "force: an incomplete type must become an opaque TypePlaceholder"
        );

        // A missing type not resolvable from the tree already becomes a placeholder
        // in BOTH paths — force does not regress it.
        let missing = BuildErrorKind::MissingType {
            name: "widget_t".to_owned(),
        };
        for force in [false, true] {
            assert!(
                matches!(
                    plan_repair_forced(&missing, &idx, &no_attempts, force),
                    Some(Repair::TypePlaceholder { ref type_name }) if type_name == "widget_t"
                ),
                "a tree-unresolvable missing type must yield a TypePlaceholder (force={force})"
            );
        }

        // An undefined non-libc, non-qualified symbol blind-stubs in both paths;
        // force must not regress that either.
        let symbol = BuildErrorKind::UndefinedSymbol {
            name: "acme_widget_init".to_owned(),
        };
        for force in [false, true] {
            assert!(
                matches!(
                    plan_repair_forced(&symbol, &idx, &no_attempts, force),
                    Some(Repair::StubBlind { ref symbol }) if symbol == "acme_widget_init"
                ),
                "an undefined project symbol must yield a StubBlind (force={force})"
            );
        }

        // Guards that must survive force: `main` (blind-stubbing it = false clean)
        // and a qualified C++ `::` symbol (invalid as a C stub) stay unrepaired.
        let main_sym = BuildErrorKind::UndefinedSymbol {
            name: "main".to_owned(),
        };
        let qualified = BuildErrorKind::UndefinedSymbol {
            name: "Ns::Type::method".to_owned(),
        };
        assert!(
            plan_repair_forced(&main_sym, &idx, &no_attempts, true).is_none(),
            "force must not blind-stub `main` (would fuzz nothing — a false clean)"
        );
        assert!(
            plan_repair_forced(&qualified, &idx, &no_attempts, true).is_none(),
            "force must not blind-stub a qualified C++ symbol (invalid C stub)"
        );
    }

    #[test]
    fn win32_pack_is_not_re_planned_once_attempted() {
        let idx = crate::auto::decl_index::DeclarationIndex::build(&tmpdir()).unwrap();
        let dword = BuildErrorKind::MissingMacro {
            name: "DWORD".to_owned(),
            as_value: false,
        };
        let bool_type = BuildErrorKind::MissingType {
            name: "BOOL".to_owned(),
        };
        // Once the Win32Pack has been attempted, a further stray Win32 name does not
        // re-plan it — the retry loop can't spin forever on the pack. (A different
        // fallback repair may still be planned; only the Win32Pack re-proposal is
        // what must not recur.)
        let attempted = RepairManifest {
            repairs: vec![Repair::Win32Pack],
        };
        assert!(!matches!(
            plan_repair_with_attempts(&dword, &idx, &attempted),
            Some(Repair::Win32Pack)
        ));
        assert!(!matches!(
            plan_repair_with_attempts(&bool_type, &idx, &attempted),
            Some(Repair::Win32Pack)
        ));
    }

    #[test]
    fn a_win32_name_never_falls_through_to_a_void_pointer_placeholder() {
        let idx = crate::auto::decl_index::DeclarationIndex::build(&tmpdir()).unwrap();
        let attempted = RepairManifest {
            repairs: vec![Repair::Win32Pack],
        };
        // The pack defines these with their real underlying types (`PUCHAR` is
        // `UCHAR *`, `DWORD` is `unsigned long`). A generic `typedef void *X`
        // appended next to the pack's own `windows.h` is a redefinition with a
        // DIFFERENT type, which fails the build outright — strictly worse than
        // planning nothing. This bit whenever one round reported several Win32
        // names: the first planned the pack, the rest fell through.
        for name in ["PUCHAR", "DWORD", "BOOL", "LPVOID"] {
            let error = BuildErrorKind::MissingType {
                name: name.to_owned(),
            };
            let planned = plan_repair_with_attempts(&error, &idx, &attempted);
            assert!(
                planned.is_none(),
                "{name} is owned by the Win32 pack; no placeholder may be \
                 synthesized for it, but got {planned:?}"
            );
        }
    }

    #[test]
    fn apply_win32_pack_writes_windows_h_and_force_includes_it() {
        let dir = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&dir).unwrap();
        let outcome = apply_repair(&Repair::Win32Pack, &dir, &idx).expect("apply Win32Pack");
        assert!(dir.join("windows.h").is_file());
        assert!(fs::read_to_string(dir.join("windows.h"))
            .unwrap()
            .contains("BOOL"));
        // Win32-typedefs-only: no MFC class stub is injected.
        assert!(!dir.join("afxwin.h").exists());
        assert!(!outcome.extra_includes.is_empty());
    }

    #[test]
    fn add_ada_source_selects_and_canonicalizes_host_platform_variant() {
        let root = tmpdir();
        let source_dir = root.join("source");
        fs::create_dir_all(&source_dir).unwrap();
        let unix = source_dir.join("widget-native__unix.adb");
        let windows = source_dir.join("widget-native__win32.adb");
        fs::write(
            &unix,
            "package body Widget.Native is -- unix\nend Widget.Native;\n",
        )
        .unwrap();
        fs::write(
            &windows,
            "package body Widget.Native is -- windows\nend Widget.Native;\n",
        )
        .unwrap();
        let repairs = root.join("repairs");
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        apply_repair(
            &Repair::AddAdaSource {
                unit: "widget.native".to_owned(),
                sources: vec![unix, windows],
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let ada_dir = repairs.join("ada_stubs");
        assert!(ada_dir.join("widget-native.adb").is_file());
        assert!(!ada_dir.join("widget-native__unix.adb").exists());
        assert!(!ada_dir.join("widget-native__win32.adb").exists());
    }

    #[test]
    fn undefined_main_is_never_stubbed() {
        // Campaign fix: an undefined `main` is a broken harness (its entrypoint
        // failed to emit), never a missing project dependency. Stubbing it would
        // make the binary link + fuzz NOTHING (a FALSE CLEAN). plan_repair must
        // return None so the build fails honestly (failed_build, not a no-op).
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "main".to_owned(),
            },
            &idx,
        );
        assert!(
            repair.is_none(),
            "main must never be stubbed; got: {repair:?}"
        );
    }

    #[test]
    fn malformed_function_decl_has_no_safe_automated_repair() {
        // #369: a body-less declarator in an in-tree C/C++ TU has no safe
        // automated repair (rewriting untrusted project source in place is out
        // of bounds). plan_repair returns None; the precise classification is
        // what surfaces in the report instead of an opaque Other cascade.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MalformedFunctionDecl {
                file: "src/gen/proto.c".to_owned(),
                line: 2,
            },
            &idx,
        );
        assert!(repair.is_none(), "got: {repair:?}");
    }

    #[test]
    fn declaration_wrapper_malformed_function_plans_identity_macro() {
        let root = tmpdir();
        let source_path = root.join("widget.c");
        fs::write(
            &source_path,
            "API_PUBLIC(const char *) widget_name(void)\n{\n return \"widget\";\n}\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MalformedFunctionDecl {
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "API_PUBLIC"
        ));

        fs::write(
            &source_path,
            "YAML_DECLARE(const char *)\nyaml_get_version_string(void)\n{\n return \"0\";\n}\n",
        )
        .unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MalformedFunctionDecl {
                file: source_path.display().to_string(),
                line: 2,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "YAML_DECLARE"
        ));
    }

    #[test]
    fn trailing_visibility_macro_plans_empty_definition() {
        let root = tmpdir();
        let source_path = root.join("ffi_common.h");
        fs::write(
            &source_path,
            "void *ffi_data_to_code_pointer(void *data) FFI_HIDDEN;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::MalformedFunctionDecl {
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );

        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "FFI_HIDDEN"
        ));
    }

    #[test]
    fn arbitrary_malformed_function_macro_is_not_an_api_wrapper() {
        let root = tmpdir();
        let source_path = root.join("generated.c");
        fs::write(&source_path, "PROTO(y)\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MalformedFunctionDecl {
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(
            repair.is_none(),
            "generic generated macro is unsafe: {repair:?}"
        );
    }

    #[test]
    fn undeclared_call_restores_wrapper_around_surviving_definition() {
        let root = tmpdir();
        let source_path = root.join("library.c");
        fs::write(
            &source_path,
            "void report(void) { LIB_version(); }\n\
             const char * LIB_API(LIB_version)(void) { return \"1\"; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "LIB_version".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "LIB_API"
        ));
    }

    #[test]
    fn undeclared_wcslen_restores_wchar_header() {
        let root = tmpdir();
        let source_path = root.join("archive.c");
        fs::write(
            &source_path,
            "int archive(void) { return (int)wcslen(0); }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "wcslen".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::IncludeStdHeader { symbol, header })
                if symbol == "wcslen" && header == "wchar.h"
        ));
    }

    #[test]
    fn undeclared_call_to_real_later_definition_restores_only_prototype() {
        let root = tmpdir();
        let source_path = root.join("library.c");
        fs::write(
            &source_path,
            "int entry(void) { return target(7); }\nint target(int value) { return value; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "target".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        )
        .expect("prototype repair");
        assert!(matches!(
            &repair,
            Repair::DeclareFunction { symbol, .. } if symbol == "target"
        ));

        let repairs = root.join("repairs");
        let outcome = apply_repair(&repair, &repairs, &idx).expect("apply prototype");
        assert!(outcome.extra_sources.is_empty());
        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(
            forced.contains("extern int target(int _gf_p0);"),
            "{forced}"
        );
        assert!(
            !repairs.join(AUTO_STUBS_FILE).exists(),
            "prototype visibility repair must not emit a stub body"
        );
    }

    #[test]
    fn attempted_wrapper_falls_through_to_real_declaration() {
        let root = tmpdir();
        let source_path = root.join("library.c");
        fs::write(
            &source_path,
            "int entry(void) { return LIB_version(); }\n\
             int LIB_API(LIB_version)(void) { return 1; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let attempted = RepairManifest {
            repairs: vec![Repair::MacroDefine {
                name: "LIB_API".to_owned(),
                as_value: false,
                function_like: false,
            }],
        };
        let repair = plan_repair_with_attempts(
            &BuildErrorKind::UndeclaredFunction {
                name: "LIB_version".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
            &attempted,
        );
        assert!(matches!(
            repair,
            Some(Repair::DeclareFunction { ref symbol, .. }) if symbol == "LIB_version"
        ));
    }

    #[test]
    fn undeclared_header_only_call_uses_neutral_function_macro() {
        let root = tmpdir();
        let source_path = root.join("library.c");
        fs::write(&source_path, "void f(void) { ProjectAssert(1, 42); }\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "ProjectAssert".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "ProjectAssert"
        ));
    }

    #[test]
    fn an_undeclared_runtime_function_is_never_erased_by_a_neutral_macro() {
        // btop: a vendored header calls `syscall(__NR_perf_event_open, …)` from a
        // `static inline` helper and leaves `<unistd.h>` to whichever .c includes
        // it first. Compiled from a TU that does not, the call is undeclared — and
        // the neutral-macro fallback wrote `#define syscall`, which is force-included
        // ahead of every TU and so erased glibc's own declaration:
        //
        //   /usr/include/unistd.h:1091:26: error: expected identifier or '('
        //     extern long int syscall (long int __sysno, ...) __THROW;
        //
        // The right repair is the declaring header.
        let root = tmpdir();
        let source_path = root.join("igt_perf.c");
        fs::write(
            &source_path,
            "int f(void) { return syscall(298, 0, 0, 0, 0, 0); }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "syscall".to_owned(),
                file: source_path.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(
            matches!(&repair, Some(Repair::IncludeStdHeader { symbol, header })
                if symbol == "syscall" && header == "unistd.h"),
            "got: {repair:?}"
        );

        // And a runtime name with NO header mapping must fail honestly rather than
        // fall through to the erasing define. `qsort` is on the runtime list and
        // routes to <stdlib.h>; `ffs` is on the list with no mapping.
        let bare = root.join("bare.c");
        fs::write(&bare, "int f(unsigned v) { return ffs(v); }\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndeclaredFunction {
                name: "ffs".to_owned(),
                file: bare.display().to_string(),
                line: 1,
            },
            &idx,
        );
        assert!(
            !matches!(&repair, Some(Repair::MacroDefine { name, .. }) if name == "ffs"),
            "a runtime name must never be defined away: {repair:?}"
        );
    }

    #[test]
    fn cached_field_struct_memoizes_per_type_name_without_changing_output() {
        // #373: a type queried twice in one retry must parse once (one cache
        // entry) and return the same body as the uncached path (caching must
        // not change results).
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let src = "void f(const Widget *w, unsigned char *v) { *v = w->hdr.id[0]; }";

        let uncached = synth_field_struct(src, "Widget", &idx);
        assert!(
            uncached.is_some(),
            "field-accessed type should synth a struct"
        );

        let mut cache = std::collections::HashMap::new();
        let first = cached_field_struct(&mut cache, src, "Widget", &idx);
        let second = cached_field_struct(&mut cache, src, "Widget", &idx);
        assert_eq!(first, uncached, "cached output must equal uncached");
        assert_eq!(second, uncached);
        assert_eq!(cache.len(), 1, "the type must be memoized once: {cache:?}");
        assert_eq!(cache.get("Widget"), Some(&uncached));
    }

    #[test]
    fn synth_field_struct_skips_type_already_defined_in_a_compiled_source() {
        // A struct fully defined in a compiled .c must not be re-synthesized and
        // force-included (that collides: "struct/typedef redefinition").
        let root = tmpdir();
        fs::write(
            root.join("core.c"),
            "struct my_ctx { int fd; char *path; };\nint use(struct my_ctx *c){return c->fd;}\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.type_defined_in_compiled_source("my_ctx"),
            "struct in a compiled .c must be known"
        );
        let target = "void fuzz(struct my_ctx *ctx){ int fd = ctx->fd; char *p = ctx->path; (void)fd;(void)p; }";
        assert!(
            synth_field_struct(target, "my_ctx", &idx).is_none(),
            "must not synthesize a struct already defined in a compiled source"
        );
    }

    fn td(name: &str, underlying: &str) -> c_parser::CTypedefDef {
        c_parser::CTypedefDef {
            name: name.to_owned(),
            underlying: underlying.to_owned(),
            line: 0,
        }
    }

    #[test]
    fn ada_unit_from_filename_decodes_gnat_naming() {
        assert_eq!(super::ada_unit_from_filename("intr.adb"), "intr");
        assert_eq!(
            super::ada_unit_from_filename("i-arm_v7ar.adb"),
            "interfaces.arm_v7ar"
        );
        assert_eq!(
            super::ada_unit_from_filename("s-bb-cpu.adb"),
            "system.bb.cpu"
        );
        assert_eq!(
            super::ada_unit_from_filename("/w/src/a-textio.ads"),
            "ada.textio"
        );
    }

    #[test]
    fn reserved_identifiers_are_recognized_for_macro_veto_bypass() {
        // Implementation-reserved names — defined-empty even if seen in the tree
        // as a "type" (an unexpanded linkage/visibility macro in type position).
        assert!(super::is_reserved_identifier("__EXPORT"));
        assert!(super::is_reserved_identifier("__BEGIN_DECLS"));
        assert!(super::is_reserved_identifier("_Bool"));
        assert!(super::is_reserved_identifier("_FOO"));
        // Real user types/namespaces, ALL-CAPS or not, keep the veto.
        assert!(!super::is_reserved_identifier("EMITTER_MANIP"));
        assert!(!super::is_reserved_identifier("YAML"));
        assert!(!super::is_reserved_identifier("widget_t"));
        assert!(!super::is_reserved_identifier("_lowercase"));
    }

    #[test]
    fn tree_typedef_chain_resolves_scalar_alias_in_dependency_order() {
        // seL4-shaped chain: word_t -> seL4_Word -> uint64_t. The synthesised
        // typedefs must be emitted dependency-first so the harness compiles.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![td("word_t", "seL4_Word"), td("seL4_Word", "uint64_t")],
            ..Default::default()
        };

        let chain = super::resolve_tree_typedef_chain("word_t", &[&defs]).unwrap();

        assert_eq!(
            chain,
            vec![
                "typedef uint64_t seL4_Word;".to_owned(),
                "typedef seL4_Word word_t;".to_owned(),
            ]
        );
    }

    #[test]
    fn tree_typedef_chain_resolves_direct_primitive() {
        let defs = c_parser::CTypeDefs {
            typedefs: vec![td("word_t", "unsigned long")],
            ..Default::default()
        };
        assert_eq!(
            super::resolve_tree_typedef_chain("word_t", &[&defs]).unwrap(),
            vec!["typedef unsigned long word_t;".to_owned()]
        );
    }

    #[test]
    fn missing_scalar_alias_recovers_from_surviving_source_definition() {
        let root = tmpdir();
        fs::write(
            root.join("compat.c"),
            "typedef unsigned char ProjectByte;\nvoid compat(void) {}\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "ProjectByte".to_owned(),
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::TypeAlias { ref type_name, ref decls })
                if type_name == "ProjectByte"
                    && decls == &["typedef unsigned char ProjectByte;".to_owned()]
        ));
    }

    #[test]
    fn conflicting_source_scalar_aliases_are_not_guessed() {
        let root = tmpdir();
        fs::write(root.join("one.c"), "typedef unsigned char Flag;\n").unwrap();
        fs::write(root.join("two.c"), "typedef int Flag;\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "Flag".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(repair, Some(Repair::TypePlaceholder { .. })),
            "ambiguous source aliases must not become a concrete typedef: {repair:?}"
        );
    }

    #[test]
    fn tree_typedef_chain_rejects_non_scalar_leaf_and_std_or_unknown_names() {
        let defs = c_parser::CTypeDefs {
            typedefs: vec![td("handle_t", "struct ctx"), td("uint32_t", "unsigned int")],
            ..Default::default()
        };
        // Non-scalar leaf (struct) is unsafe to synthesise as a flat typedef.
        assert!(super::resolve_tree_typedef_chain("handle_t", &[&defs]).is_none());
        // A standard spelling is handled by the std-include path, not synthesised.
        assert!(super::resolve_tree_typedef_chain("uint32_t", &[&defs]).is_none());
        // A name that is not a tree typedef at all.
        assert!(super::resolve_tree_typedef_chain("nope_t", &[&defs]).is_none());
    }

    #[test]
    fn tree_typedef_chain_rejects_config_conditional_ambiguity() {
        let defs = c_parser::parse_c_type_defs(
            "#if WIDE\ntypedef wchar_t XML_Char;\n#else\ntypedef char XML_Char;\n#endif\n",
        )
        .unwrap();
        assert!(
            super::resolve_tree_typedef_chain("XML_Char", &[&defs]).is_none(),
            "a raw tree parse sees both preprocessor branches and must not guess one ABI"
        );
    }

    #[test]
    fn config_alias_synthesised_for_absent_fprime_type() {
        // FwChanIdType: absent from the tree, recognised config family -> a
        // ConfigTypeAlias carrying the curated default width (uint32_t).
        let idx = crate::auto::decl_index::DeclarationIndex::default();
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "FwChanIdType".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(
                repair,
                Some(Repair::ConfigTypeAlias { ref type_name, ref underlying, header_path: None })
                    if type_name == "FwChanIdType" && underlying == "uint32_t"
            ),
            "got: {repair:?}"
        );
    }

    #[test]
    fn config_alias_loses_to_a_real_tree_typedef() {
        // When the deployment ships the real width in-tree, the existing
        // TypeAlias path wins and the synthesiser never guesses.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![td("FwChanIdType", "uint16_t")],
            ..Default::default()
        };
        let mut idx = crate::auto::decl_index::DeclarationIndex::default();
        idx.c_type_defs = std::sync::Arc::new(defs);
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "FwChanIdType".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(repair, Some(Repair::TypeAlias { .. })),
            "got: {repair:?}"
        );
    }

    #[test]
    fn config_alias_does_not_shadow_a_non_scalar_tree_typedef() {
        // resolve_tree_typedef_chain returns None for a struct leaf, but the type
        // IS known to the tree -> must NOT synthesise a guessed scalar over it.
        let defs = c_parser::CTypeDefs {
            typedefs: vec![td("FwChanIdType", "struct real_chan")],
            ..Default::default()
        };
        let mut idx = crate::auto::decl_index::DeclarationIndex::default();
        idx.c_type_defs = std::sync::Arc::new(defs);
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "FwChanIdType".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(repair, Some(Repair::TypePlaceholder { .. })),
            "got: {repair:?}"
        );
    }

    #[test]
    fn non_config_unknown_type_stays_placeholder() {
        let idx = crate::auto::decl_index::DeclarationIndex::default();
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "TotallyUnknownT".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(repair, Some(Repair::TypePlaceholder { .. })),
            "got: {repair:?}"
        );
    }

    #[test]
    fn recovery_artifact_missing_type_plans_no_repair() {
        // #48: clang's bare `type`/`expression` recovery placeholder is not a real
        // missing type — refuse to synthesize a junk `typedef void *type;` that
        // would then be reported as a still-blocking synthesized_type dependency.
        let idx = crate::auto::decl_index::DeclarationIndex::default();
        for name in ["type", "expression", "<recovery-expr>"] {
            assert!(
                plan_repair(
                    &BuildErrorKind::MissingType {
                        name: name.to_owned(),
                    },
                    &idx,
                )
                .is_none(),
                "recovery artifact {name:?} must not plan a repair"
            );
        }
        // A genuine unknown type still gets a placeholder (regression guard).
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::MissingType {
                    name: "widget_t".to_owned(),
                },
                &idx,
            ),
            Some(Repair::TypePlaceholder { .. })
        ));
    }

    #[test]
    fn config_alias_apply_force_includes_default_typedef() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        // The target source uses it but does not define it -> force-include so it
        // reaches the real target TU (a non-force auto_types.h placeholder won't).
        apply_repair_with_source(
            &Repair::ConfigTypeAlias {
                type_name: "FwEnumStoreType".to_owned(),
                underlying: "int32_t".to_owned(),
                header_path: None,
            },
            &repairs,
            &idx,
            Some("int decode(FwEnumStoreType x) { return x < 0; }"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let inc = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(
            inc.contains("typedef int32_t FwEnumStoreType;"),
            "got: {inc}"
        );
        assert!(
            inc.contains("LOWER-CONFIDENCE"),
            "must flag low confidence: {inc}"
        );
    }

    #[test]
    fn config_alias_header_plan_recognises_fprime_autocoder_header() {
        // A missing `config/Fw*TypeAliasAc.h` not resolvable from the tree -> a
        // header-backed ConfigTypeAlias carrying the derived type + curated width.
        let idx = crate::auto::decl_index::DeclarationIndex::default();
        let repair = plan_repair(
            &BuildErrorKind::MissingHeader {
                path: "config/FwTraceIdTypeAliasAc.h".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(
                repair,
                Some(Repair::ConfigTypeAlias { ref type_name, ref underlying, header_path: Some(ref h) })
                    if type_name == "FwTraceIdType" && underlying == "uint32_t"
                        && h == "config/FwTraceIdTypeAliasAc.h"
            ),
            "got: {repair:?}"
        );
        // A non-config missing header stays a plain placeholder.
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::MissingHeader {
                    path: "some/random.h".to_owned()
                },
                &idx,
            ),
            Some(Repair::HeaderPlaceholder { .. })
        ));
    }

    #[test]
    fn an_undefined_function_like_macro_in_a_condition_gets_a_numeric_expansion() {
        // scrcpy's compat.h asks
        //   #if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(58, 9, 100)
        // and FFmpeg is not installed. clang names the macro; the definition has
        // to be function-like AND numeric, or the condition stays malformed and
        // every target in the translation unit remains unbuildable.
        let tail = "/p/compat.h:24:32: error: function-like macro 'AV_VERSION_INT' \
                    is not defined\n/p/compat.h:33:32: error: function-like macro \
                    'AV_VERSION_INT' is not defined";
        assert_eq!(
            undefined_function_like_macro_in_condition(tail).as_deref(),
            Some("AV_VERSION_INT")
        );
        // An unrelated diagnostic names nothing.
        assert_eq!(
            undefined_function_like_macro_in_condition("error: expected identifier"),
            None
        );
    }

    #[test]
    fn missing_installed_layout_header_forwards_to_unique_real_header() {
        let root = tmpdir();
        let real_dir = root.join("src/api");
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("yajl_common.h");
        fs::write(&real, "typedef struct { int value; } yajl_alloc_funcs;\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::MissingHeader {
                path: "yajl/yajl_common.h".to_owned(),
            },
            &idx,
        )
        .expect("unique in-tree basename should be forwarded");
        assert!(
            matches!(&repair, Repair::HeaderForward { virtual_path, source_path }
                if virtual_path == "yajl/yajl_common.h" && source_path == &real),
            "got: {repair:?}"
        );

        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let forwarded =
            fs::read_to_string(repairs.join(AUTO_INCLUDES_DIR).join("yajl/yajl_common.h")).unwrap();
        assert!(forwarded.contains(&real.canonicalize().unwrap().display().to_string()));
        assert!(!forwarded.contains("placeholder"), "got: {forwarded}");
    }

    #[test]
    fn missing_standard_type_includes_its_real_header() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let attempted = RepairManifest::default();

        assert!(matches!(
            plan_repair_forced(
                &BuildErrorKind::MissingType {
                    name: "uint8_t".to_owned()
                },
                &idx,
                &attempted,
                false
            ),
            Some(Repair::IncludeStdHeader { ref symbol, ref header })
                if symbol == "uint8_t" && header == "stdint.h"
        ));
        assert!(matches!(
            plan_repair_forced(
                &BuildErrorKind::MissingType {
                    name: "size_t".to_owned()
                },
                &idx,
                &attempted,
                false
            ),
            Some(Repair::IncludeStdHeader { ref symbol, ref header })
                if symbol == "size_t" && header == "stddef.h"
        ));
    }

    #[test]
    fn standard_header_is_prepended_before_existing_prototype() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        fs::write(
            repairs.join(AUTO_CPP_INCLUDES_FILE),
            "extern void consume(size_t _gf_p0);\n",
        )
        .unwrap();
        apply_repair(
            &Repair::IncludeStdHeader {
                symbol: "size_t".to_owned(),
                header: "stddef.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert_eq!(
            forced,
            "#include <stddef.h>\nextern void consume(size_t _gf_p0);\n"
        );
    }

    #[test]
    fn macro_repair_prefers_exact_tree_and_known_abi_values() {
        let root = tmpdir();
        fs::write(
            root.join("compat.c"),
            "typedef unsigned char Bool;\n#define True ((Bool)1)\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        apply_repair(
            &Repair::MacroDefine {
                name: "True".to_owned(),
                as_value: true,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();
        apply_repair(
            &Repair::MacroDefine {
                name: "cJSON_Number".to_owned(),
                as_value: true,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();
        apply_repair(
            &Repair::MacroDefine {
                name: "CJSON_NESTING_LIMIT".to_owned(),
                as_value: true,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();
        apply_repair(
            &Repair::MacroDefine {
                name: "cJSON_ArrayForEach".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(defines.contains("#define True ((Bool)1)"), "{defines}");
        assert!(
            defines.contains("#define cJSON_Number (1 << 3)"),
            "{defines}"
        );
        assert!(
            defines.contains("#define CJSON_NESTING_LIMIT 1000"),
            "{defines}"
        );
        assert!(
            defines.contains("#define cJSON_ArrayForEach(element, array)"),
            "{defines}"
        );
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::MissingMacro {
                    name: "cJSON_bool".to_owned(),
                    as_value: true,
                },
                &idx,
            ),
            Some(Repair::TypePlaceholder { ref type_name }) if type_name == "cJSON_bool"
        ));
    }

    #[test]
    fn missing_non_pod_type_includes_unique_surviving_project_header() {
        let root = tmpdir();
        let header = root.join("bzlib.h");
        fs::write(
            &header,
            "typedef struct { char *next; void *(*alloc)(void *, int, int); } bz_stream;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingType {
                name: "bz_stream".to_owned(),
            },
            &idx,
        )
        .expect("real header repair");
        assert!(matches!(
            &repair,
            Repair::IncludeTypeHeader { type_name, header: found }
                if type_name == "bz_stream" && found == &header
        ));
        let repairs = root.join("repairs");
        apply_repair(&repair, &repairs, &idx).unwrap();
        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(forced.starts_with("#include \""), "{forced}");
        assert!(forced.contains("bzlib.h"), "{forced}");
        assert!(!forced.contains("typedef struct bz_stream"), "{forced}");
    }

    #[test]
    fn recovered_type_headers_are_inserted_before_their_consumers() {
        let root = tmpdir();
        let public = root.join("public.h");
        let threads = root.join("threads.h");
        let private = root.join("private.h");
        fs::write(&public, "typedef int status_t;\n").unwrap();
        fs::write(
            &threads,
            "typedef struct thread thread_t; status_t thread_start(thread_t *);\n",
        )
        .unwrap();
        fs::write(
            &private,
            "typedef struct context { thread_t *thread; status_t status; } context_t;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        for repair in [
            Repair::IncludeTypeHeader {
                type_name: "context_t".to_owned(),
                header: private.clone(),
            },
            Repair::IncludeTypeHeader {
                type_name: "status_t".to_owned(),
                header: public.clone(),
            },
            Repair::IncludeTypeHeader {
                type_name: "thread_t".to_owned(),
                header: threads.clone(),
            },
        ] {
            apply_repair(&repair, &repairs, &idx).unwrap();
        }

        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        let public_pos = forced.find(public.to_str().unwrap()).unwrap();
        let threads_pos = forced.find(threads.to_str().unwrap()).unwrap();
        let private_pos = forced.find(private.to_str().unwrap()).unwrap();
        assert!(
            public_pos < threads_pos && threads_pos < private_pos,
            "{forced}"
        );
    }

    #[test]
    fn recovered_type_header_precedes_existing_synthesized_declaration() {
        let root = tmpdir();
        let types = root.join("types.h");
        fs::write(&types, "typedef int boolean;\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        fs::write(
            repairs.join(AUTO_CPP_INCLUDES_FILE),
            "#include <stddef.h>\nextern boolean parse(const char *);\n",
        )
        .unwrap();

        apply_repair(
            &Repair::IncludeTypeHeader {
                type_name: "boolean".to_owned(),
                header: types.clone(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        let type_pos = forced.find(types.to_str().unwrap()).unwrap();
        let declaration_pos = forced.find("extern boolean parse").unwrap();
        assert!(type_pos < declaration_pos, "{forced}");
    }

    #[test]
    fn late_type_header_stays_after_its_existing_prerequisite() {
        let root = tmpdir();
        let public = root.join("public.h");
        let private = root.join("private.h");
        let table = root.join("table.h");
        fs::write(&public, "typedef int status_t;\n").unwrap();
        fs::write(&private, "typedef struct context context_t;\n").unwrap();
        fs::write(
            &table,
            "typedef struct table table_t; status_t table_insert(table_t *);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        for repair in [
            Repair::IncludeTypeHeader {
                type_name: "context_t".to_owned(),
                header: private,
            },
            Repair::IncludeTypeHeader {
                type_name: "status_t".to_owned(),
                header: public.clone(),
            },
            Repair::IncludeTypeHeader {
                type_name: "table_t".to_owned(),
                header: table.clone(),
            },
        ] {
            apply_repair(&repair, &repairs, &idx).unwrap();
        }

        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        let public_pos = forced.find(public.to_str().unwrap()).unwrap();
        let table_pos = forced.find(table.to_str().unwrap()).unwrap();
        assert!(public_pos < table_pos, "{forced}");
    }

    #[test]
    fn idl_stub_header_apply_writes_corba_typedefs_not_empty_placeholder() {
        // A missing CORBA/IDL-generated stub header (`MessageC.h`) must NOT get an
        // empty #pragma-once placeholder (which leaves every IDL-defined type and
        // CORBA scaffolding type undefined and cascades). It gets curated CORBA
        // stub typedefs so the dependent TU parses.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingHeader {
                path: "src/idl/MessageC.h".to_owned(),
            },
            &idx,
        )
        .expect("a repair");
        // Still routed through HeaderPlaceholder (no enum churn), the apply path
        // recognises the IDL shape.
        assert!(
            matches!(&repair, Repair::HeaderPlaceholder { virtual_path } if virtual_path == "src/idl/MessageC.h"),
            "got: {repair:?}"
        );
        apply_repair(&repair, &repairs, &idx).unwrap();
        let hdr =
            fs::read_to_string(repairs.join(AUTO_INCLUDES_DIR).join("src/idl/MessageC.h")).unwrap();
        assert!(hdr.contains("#pragma once"), "{hdr}");
        assert!(
            hdr.contains("typedef") && hdr.contains("CORBA_Object"),
            "IDL header must carry CORBA stub typedefs: {hdr}"
        );

        // A non-IDL internal header stays an empty placeholder (tight gate).
        let repair2 = plan_repair(
            &BuildErrorKind::MissingHeader {
                path: "internal/proprietary_alloc.h".to_owned(),
            },
            &idx,
        )
        .expect("a repair");
        apply_repair(&repair2, &repairs, &idx).unwrap();
        let hdr2 = fs::read_to_string(
            repairs
                .join(AUTO_INCLUDES_DIR)
                .join("internal/proprietary_alloc.h"),
        )
        .unwrap();
        assert!(hdr2.contains("#pragma once"), "{hdr2}");
        assert!(
            !hdr2.contains("typedef"),
            "non-IDL header must stay an empty placeholder: {hdr2}"
        );
    }

    #[test]
    fn config_alias_header_apply_writes_typedef_into_the_include() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair(
            &Repair::ConfigTypeAlias {
                type_name: "FwTraceIdType".to_owned(),
                underlying: "uint32_t".to_owned(),
                header_path: Some("config/FwTraceIdTypeAliasAc.h".to_owned()),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        // The stubbed header now resolves the `#include` AND defines the type.
        let hdr = fs::read_to_string(
            repairs
                .join(AUTO_INCLUDES_DIR)
                .join("config/FwTraceIdTypeAliasAc.h"),
        )
        .unwrap();
        assert!(
            hdr.contains("typedef uint32_t FwTraceIdType;"),
            "got: {hdr}"
        );
    }

    #[test]
    fn missing_config_h_synthesizes_minimal_config() {
        // An autoconf/cmake project shipping only config.h.in: a missing config.h
        // gets a synthesized minimal config (HAVE_CONFIG_H), not an empty stub.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        match plan_repair(
            &BuildErrorKind::MissingHeader {
                path: "config.h".to_owned(),
            },
            &idx,
        ) {
            Some(Repair::ConfigHeaderSynth { virtual_path }) => {
                assert_eq!(virtual_path, "config.h")
            }
            other => panic!("expected ConfigHeaderSynth, got {other:?}"),
        }
        // Apply writes the config + the HAVE_CONFIG_H define.
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair(
            &Repair::ConfigHeaderSynth {
                virtual_path: "config.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        let cfg = fs::read_to_string(repairs.join("auto_includes").join("config.h")).unwrap();
        assert!(cfg.contains("#define HAVE_CONFIG_H 1"), "{cfg}");
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(defines.contains("#define HAVE_CONFIG_H 1"), "{defines}");
    }

    #[test]
    fn qualified_cpp_symbol_is_not_blind_stubbed() {
        // A demangled C++ link symbol (`ns::Type::method(int)`) cannot be blind
        // stubbed into auto_stubs.c as valid code — plan must not stub it.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "eprosima::fastcdr::Cdr::Cdr(eprosima::fastcdr::FastBuffer&)".to_owned(),
            },
            &idx,
        )
        .is_none());
    }

    #[test]
    fn cpp_destructor_is_stubbed_when_the_class_header_is_known() {
        // #97: a declared-but-undefined destructor with no in-tree definition is now
        // repaired with a single source-level `Ns::Class::~Class() {}`. The
        // AddSource path already failed to find a real definition, so exactly one TU
        // (the stub) defines the destructor and — if it is the key function — its
        // vtable, so there is no duplicate ABI body or vtable (verified: both
        // non-virtual and virtual destructor stubs link cleanly). Requires the
        // class header so the class is complete.
        let root = tmpdir();
        fs::write(
            root.join("api.hh"),
            "namespace leveldb { class Comparator { public: virtual ~Comparator(); }; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "leveldb::Comparator::~Comparator()".to_owned(),
            },
            &idx,
        );
        assert!(
            matches!(
                &repair,
                Some(Repair::StubDeclared { symbol, .. })
                    if symbol == "leveldb::Comparator::~Comparator()"
            ),
            "a declared destructor with a known header is now stubbed: {repair:?}"
        );
    }

    #[test]
    fn cpp_destructor_class_splits_qualified_and_simple_name() {
        // #97: destructor symbol -> (fully-qualified class, simple class).
        assert_eq!(
            cpp_destructor_class("tinyxml2::StrPair::~StrPair()"),
            Some(("tinyxml2::StrPair".to_owned(), "StrPair".to_owned()))
        );
        assert_eq!(
            cpp_destructor_class("Foo::~Foo()"),
            Some(("Foo".to_owned(), "Foo".to_owned()))
        );
        // A bare `~Foo()` with no enclosing scope can't be defined -> None.
        assert_eq!(cpp_destructor_class("~Foo()"), None);
    }

    #[test]
    fn cpp_declared_stub_is_routed_to_cpp_file() {
        // A symbol that resolves to a C++ declaration gets a C++ stub in
        // auto_stubs.cpp (compiled as C++), not auto_stubs.c.
        let root = tmpdir();
        fs::write(root.join("api.hh"), "int gov_helper(int x);\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair(
            &Repair::StubDeclared {
                symbol: "gov_helper".to_owned(),
                return_type: "int".to_owned(),
                provenance: "C++ declared in tree".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        assert!(
            repairs.join(AUTO_STUBS_CPP_FILE).is_file(),
            "C++ stub must go to auto_stubs.cpp"
        );
        let cpp = fs::read_to_string(repairs.join(AUTO_STUBS_CPP_FILE)).unwrap();
        assert!(cpp.contains("gov_helper"), "stub body: {cpp}");
        assert!(
            !repairs.join(AUTO_STUBS_FILE).exists(),
            "no C stub file should be written for a C++ symbol"
        );
    }

    #[test]
    fn demangled_cpp_signature_uses_typed_cpp_declaration_stub() {
        let root = tmpdir();
        fs::write(
            root.join("MurmurHash1.h"),
            "unsigned int MurmurHash1(const void *, int, unsigned int);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let error = BuildErrorKind::UndefinedSymbol {
            name: "MurmurHash1(void const*, int, unsigned int)".to_owned(),
        };

        let repair = plan_repair(&error, &idx).expect("typed C++ stub repair");
        assert!(
            matches!(repair, Repair::StubDeclared { ref symbol, .. } if symbol.starts_with("MurmurHash1(")),
            "unexpected repair: {repair:?}"
        );

        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair(&repair, &repairs, &idx).unwrap();
        let stub = fs::read_to_string(repairs.join(AUTO_STUBS_CPP_FILE)).unwrap();
        assert!(stub.contains("MurmurHash1"), "{stub}");
        assert!(stub.contains("const void * _gf_p0"), "{stub}");
        assert!(!stub.contains("key _gf_p0"), "{stub}");
        assert!(!repairs.join(AUTO_STUBS_FILE).exists());
    }

    #[test]
    fn demangled_cpp_constructor_stub_keeps_class_qualification() {
        let root = tmpdir();
        fs::write(
            root.join("status.hh"),
            "namespace leveldb { class Status { public: Status(const Status &); ~Status(); }; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let repair = Repair::StubDeclared {
            symbol: "leveldb::Status::Status(leveldb::Status const&)".to_owned(),
            return_type: String::new(),
            provenance: "C++ declared in tree".to_owned(),
        };

        apply_repair(&repair, &repairs, &idx).unwrap();
        let stub = fs::read_to_string(repairs.join(AUTO_STUBS_CPP_FILE)).unwrap();
        assert!(
            stub.contains(&root.join("status.hh").display().to_string()),
            "{stub}"
        );
        assert!(stub.contains("leveldb::Status::Status("), "{stub}");
        assert!(!stub.contains("void leveldb::Status::Status"), "{stub}");
    }

    #[test]
    fn declared_stub_includes_generated_type_header() {
        let root = tmpdir();
        fs::write(root.join("vendor.h"), "int decode(widget_t *w);\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::StubDeclared {
                symbol: "decode".to_owned(),
                return_type: "int".to_owned(),
                provenance: "test".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        apply_repair(
            &Repair::TypePlaceholder {
                type_name: "widget_t".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains("#include \"auto_types.h\""),
            "stub file must include generated typedefs: {stubs}"
        );
        let types = fs::read_to_string(repairs.join(AUTO_TYPES_FILE)).unwrap();
        assert!(types.contains("typedef void *widget_t;"));
        assert!(
            !repairs.join(AUTO_CPP_INCLUDES_FILE).exists(),
            "a project-typed prototype must not precede the header that declares widget_t"
        );
    }

    #[test]
    fn fundamental_declared_stub_is_republished_to_calling_tus() {
        let root = tmpdir();
        fs::write(root.join("compat.c"), "int rand_s(unsigned int *value);\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::StubDeclared {
                symbol: "rand_s".to_owned(),
                return_type: "int".to_owned(),
                provenance: "conditional declaration".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(forced.contains("extern int rand_s(unsigned int * _gf_p0);"));
    }

    #[test]
    fn type_placeholder_routes_by_collision_safety() {
        // A non-stdlib unknown type → void* in auto_types.h (reached only via
        // auto_stubs.c, NEVER force-included — a force-included void* would
        // clash with a real typedef in the target source).
        // A C++ stdlib type → real #include in auto_cpp_includes.h, which IS
        // force-included and is collision-safe (header guards + `using`).
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::TypePlaceholder {
                type_name: "RealT".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        apply_repair(
            &Repair::TypePlaceholder {
                type_name: "ostrstream".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let types = fs::read_to_string(repairs.join(AUTO_TYPES_FILE)).unwrap();
        assert!(types.contains("typedef void *RealT;"), "{types}");
        assert!(
            !types.contains("ostrstream"),
            "stdlib type must not land in the void* file: {types}"
        );

        let cpp = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(cpp.contains("#include <strstream>"), "{cpp}");
        assert!(cpp.contains("using std::ostrstream;"), "{cpp}");
        assert!(
            !cpp.contains("typedef void *"),
            "force-included file must stay collision-safe: {cpp}"
        );
    }

    #[test]
    fn pointer_only_missing_type_gets_opaque_forward_typedef() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair_with_source(
            &Repair::TypePlaceholder {
                type_name: "CodecState".to_owned(),
            },
            &repairs,
            &idx,
            Some("int update(CodecState *state, const void *input);\n"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let forced = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap();
        assert!(
            forced.contains("typedef struct CodecState CodecState;"),
            "pointer-only type should stay one pointer wide: {forced}"
        );
        assert!(!forced.contains("typedef void *CodecState"), "{forced}");
    }

    #[test]
    fn field_struct_not_force_included_for_a_tree_known_typedef() {
        // C1: a type the tree DEFINES (via a header `typedef`, e.g. cJSON's
        // `typedef struct cJSON ... cJSON;`) must NOT be force-included as a
        // field-inferred struct — once the real header is pulled in (here it would
        // be via an add_source of cJSON.c -> cJSON.h), the synthetic anonymous
        // struct collides ("redefinition of 'cJSON'"). It must route to the
        // collision-safe non-force-included alias instead.
        let root = tmpdir();
        // A forward typedef: known to the tree as a typedef, but NOT a complete
        // struct in a compiled source — the exact gap the field-struct guard missed.
        fs::write(root.join("cjson.h"), "typedef struct cJSON cJSON;\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        // A target source that field-accesses cJSON (makes the field-struct path
        // eligible) — without the guard this synthesised + force-included a struct.
        apply_repair_with_source(
            &Repair::TypePlaceholder {
                type_name: "cJSON".to_owned(),
            },
            &repairs,
            &idx,
            Some("void f(cJSON *o) { o->next = 0; o->type = 1; }"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let cpp = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap_or_default();
        assert!(
            !cpp.contains("completion of") && !cpp.contains("struct cJSON"),
            "must NOT force-include a field-struct for a tree-known type: {cpp}"
        );
    }

    #[test]
    fn field_struct_not_force_included_for_a_tree_known_cpp_class() {
        let root = tmpdir();
        fs::write(
            root.join("status.hh"),
            "namespace leveldb { class Status { public: bool ok() const; }; }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair_with_source(
            &Repair::TypePlaceholder {
                type_name: "Status".to_owned(),
            },
            &repairs,
            &idx,
            Some("void f(Status *s) { s->ok(); }"),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let includes = fs::read_to_string(repairs.join(AUTO_CPP_INCLUDES_FILE)).unwrap_or_default();
        assert!(
            !includes.contains("auto-synthesised: struct for field-accessed type `Status`"),
            "a real C++ class must not be replaced with a field-inferred C struct: {includes}"
        );
    }

    #[test]
    fn declared_c_stub_includes_owning_header_for_real_types() {
        let root = tmpdir();
        let header = root.join("transform.h");
        fs::write(
            &header,
            "typedef struct BrotliTransforms { int count; } BrotliTransforms;\n\
             int BrotliTransformDictionaryWord(const BrotliTransforms* transforms);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::StubDeclared {
                symbol: "BrotliTransformDictionaryWord".to_owned(),
                return_type: "int".to_owned(),
                provenance: "test".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let stubs = fs::read_to_string(repairs.join(AUTO_STUBS_FILE)).unwrap();
        assert!(
            stubs.contains(&format!("#include \"{}\"", header.display())),
            "stub translation unit must use the declaration's real typedefs: {stubs}"
        );
        assert!(
            stubs.contains("BrotliTransformDictionaryWord"),
            "declared function definition must still be emitted: {stubs}"
        );
    }

    #[test]
    fn macro_define_writes_define_to_force_included_file() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::MacroDefine {
                name: "YAML_VERSION_STRING".to_owned(),
                as_value: true,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();
        // A specifier macro (type/qualifier position) defines to nothing.
        apply_repair(
            &Repair::MacroDefine {
                name: "JSON_INLINE".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define YAML_VERSION_STRING \"\"\n"),
            "{defines}"
        );
        assert!(defines.contains("#define JSON_INLINE\n"), "{defines}");
    }

    #[test]
    fn package_identity_macros_are_synthesized_as_strings() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        for name in ["PACKAGE_STRING", "PROGRAM_PREFIX"] {
            apply_repair(
                &Repair::MacroDefine {
                    name: name.to_owned(),
                    as_value: true,
                    function_like: false,
                },
                &repairs,
                &idx,
            )
            .unwrap();
        }

        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define PACKAGE_STRING \"\"\n"),
            "{defines}"
        );
        assert!(
            defines.contains("#define PROGRAM_PREFIX \"\"\n"),
            "{defines}"
        );
    }

    #[test]
    fn declaration_wrapper_macro_preserves_wrapped_return_type() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src = "API_PUBLIC(const char *) widget_name(void)\n{\n return \"widget\";\n}\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "API_PUBLIC".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define API_PUBLIC(...) __VA_ARGS__\n"),
            "declaration wrapper must preserve its type argument: {defines}"
        );
    }

    #[test]
    fn declaration_wrapper_macro_preserves_wrapped_function_name() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src = "const char * LIB_API(LIB_version)(void) { return \"1\"; }\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "LIB_API".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define LIB_API(...) __VA_ARGS__\n"),
            "function-name wrapper must preserve its identifier: {defines}"
        );
    }

    #[test]
    fn declaration_wrapper_macro_preserves_wrapped_parameter() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src = "int join(char **start, SHIM(char **end));\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "SHIM".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define SHIM(...) __VA_ARGS__\n"),
            "parameter wrapper must preserve its declaration: {defines}"
        );
    }

    #[test]
    fn non_declaration_function_macro_keeps_neutral_expansion() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src = "void f(void) { PROJECT_LOG(\"failed\"); }\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "PROJECT_LOG".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define PROJECT_LOG(...) (0)\n"),
            "{defines}"
        );
    }

    #[test]
    fn config_macro_uses_value_required_by_preprocessor_guard() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src =
            "#if (LIB_VERSION_MAJOR != 3) || (LIB_VERSION_MINOR != 17)\n#error mismatch\n#endif\n";
        for name in ["LIB_VERSION_MAJOR", "LIB_VERSION_MINOR"] {
            apply_repair_with_source(
                &Repair::MacroDefine {
                    name: name.to_owned(),
                    as_value: true,
                    function_like: false,
                },
                &repairs,
                &idx,
                Some(src),
                &mut std::collections::HashMap::new(),
            )
            .unwrap();
        }
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define LIB_VERSION_MAJOR 3\n"),
            "{defines}"
        );
        assert!(
            defines.contains("#define LIB_VERSION_MINOR 17\n"),
            "{defines}"
        );
    }

    #[test]
    fn syntax_error_calling_convention_plans_empty_macro() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::Other {
                tail: "widget.c:9: error: duplicate member 'WIDGET_CDECL'".to_owned(),
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: false, .. }) if name == "WIDGET_CDECL"
        ));
    }

    #[test]
    fn arbitrary_other_error_does_not_invent_a_macro() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::Other {
                tail: "widget.c:9: error: incompatible result type 'double'".to_owned(),
            },
            &idx,
        );
        assert!(repair.is_none(), "unrelated semantic error: {repair:?}");
    }

    #[test]
    fn macro_used_in_if_value_context_gets_a_value_not_empty() {
        // yyjson: the all-caps classifier tagged YYJSON_U64_TO_F64_NO_IMPL as an
        // empty qualifier macro (`as_value:false`), but the header self-defines it
        // via `#ifndef … #define … #endif` and later uses `#if NAME`. A force-
        // included empty `#define NAME` suppresses the real definition AND breaks
        // `#if NAME` ("#if with no expression"). When the source uses it in a value
        // context the stub must carry `0`.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let src = "#ifndef YYJSON_U64_TO_F64_NO_IMPL\n#define YYJSON_U64_TO_F64_NO_IMPL 1\n#endif\n\
                   double f(void){\n#if YYJSON_U64_TO_F64_NO_IMPL\n return 1;\n#else\n return 0;\n#endif\n}\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "YYJSON_U64_TO_F64_NO_IMPL".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define YYJSON_U64_TO_F64_NO_IMPL 0\n"),
            "value-context macro must get 0, not empty: {defines}"
        );
        // A genuine qualifier macro NOT used in #if value position stays empty.
        let src2 = "JSON_INLINE int g(void){ return 0; }\n";
        apply_repair_with_source(
            &Repair::MacroDefine {
                name: "JSON_INLINE".to_owned(),
                as_value: false,
                function_like: false,
            },
            &repairs,
            &idx,
            Some(src2),
            &mut std::collections::HashMap::new(),
        )
        .unwrap();
        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define JSON_INLINE\n"),
            "qualifier macro stays empty: {defines}"
        );
    }

    #[test]
    fn missing_macro_plans_macro_define() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "YAML_VERSION_MAJOR".to_owned(),
                as_value: true,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::MacroDefine { name, as_value: true, .. }) if name == "YAML_VERSION_MAJOR"
        ));
    }

    #[test]
    #[cfg(not(windows))]
    fn missing_win32_type_becomes_void_placeholder_not_empty_macro() {
        // On a non-Windows host a Windows-only type that the Win32Pack DOESN'T
        // model (libheif `HMODULE` — not in `win32_known_names()`) must NOT be
        // `#define`d to empty (which corrupts `HMODULE x = ...;`); it gets a
        // `void *` typedef placeholder so the foreign declaration parses.
        // Names the pack DOES model (`HWND`, `LPVOID`) now route to Win32Pack
        // instead, which resolves them to their real underlying types.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        match plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "HMODULE".to_owned(),
                as_value: false,
            },
            &idx,
        ) {
            Some(Repair::TypePlaceholder { type_name }) => assert_eq!(type_name, "HMODULE"),
            other => panic!("expected TypePlaceholder for HMODULE, got {other:?}"),
        }
        for ty in ["HWND", "LPVOID"] {
            assert!(
                matches!(
                    plan_repair(
                        &BuildErrorKind::MissingMacro {
                            name: ty.to_owned(),
                            as_value: false,
                        },
                        &idx,
                    ),
                    Some(Repair::Win32Pack)
                ),
                "a Win32Pack-modeled name ({ty}) must route to Win32Pack, not a void placeholder"
            );
        }
    }

    #[test]
    fn missing_macro_does_not_define_project_namespace() {
        // A namespace/enum that is ALL-CAPS (yaml-cpp's `namespace YAML`) is
        // mis-classified as a missing build macro; `#define`-ing it corrupts
        // every `namespace YAML {`. plan_repair must veto it.
        let root = tmpdir();
        fs::write(
            root.join("emitter.cpp"),
            "namespace YAML { int Width(int n) { return n; } }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(idx.cpp_defines_type_or_namespace("YAML"));
        let repair = plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "YAML".to_owned(),
                as_value: false,
            },
            &idx,
        );
        assert!(
            repair.is_none(),
            "must not #define the project namespace YAML, got: {repair:?}"
        );
        // A genuine build-config macro (not a tree symbol) is still defined.
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::MissingMacro { name: "BUILD_TAG".to_owned(), as_value: false },
                &idx,
            ),
            Some(Repair::MacroDefine { name, .. }) if name == "BUILD_TAG"
        ));
    }

    #[test]
    fn all_caps_tree_typedef_uses_its_surviving_header() {
        let root = tmpdir();
        fs::write(
            root.join("xmlrole.h"),
            "typedef struct prolog_state { int state; } PROLOG_STATE;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingMacro {
                name: "PROLOG_STATE".to_owned(),
                as_value: false,
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::IncludeTypeHeader { type_name, header })
                if type_name == "PROLOG_STATE" && header == root.join("xmlrole.h")
        ));
    }

    #[test]
    fn header_placeholder_writes_under_includes_dir() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        apply_repair(
            &Repair::HeaderPlaceholder {
                virtual_path: "sub/missing.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        assert!(repairs
            .join(AUTO_INCLUDES_DIR)
            .join("sub/missing.h")
            .is_file());
    }

    #[test]
    fn header_placeholder_supports_parent_relative_include_spelling() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        let outcome = apply_repair(
            &Repair::HeaderPlaceholder {
                virtual_path: "allocators.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        assert!(outcome
            .extra_includes
            .iter()
            .any(|dir| dir.join("../allocators.h").is_file()));
        assert!(outcome
            .extra_includes
            .iter()
            .all(|dir| dir.starts_with(repairs.join(AUTO_INCLUDES_DIR))));
    }

    #[test]
    fn header_placeholder_emits_rich_rtos_stub_not_empty() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        // A missing flat RTOS header gets the rich type surface, not `#pragma once`.
        apply_repair(
            &Repair::HeaderPlaceholder {
                virtual_path: "vxWorks.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        let vx = fs::read_to_string(repairs.join(AUTO_INCLUDES_DIR).join("vxWorks.h")).unwrap();
        assert!(vx.contains("STATUS") && vx.contains("SEM_ID"), "{vx}");
        // A missing subdir RTOS header is placed at its angled path so the
        // `#include <sys/neutrino.h>` resolves under the includes -I dir.
        apply_repair(
            &Repair::HeaderPlaceholder {
                virtual_path: "sys/neutrino.h".to_owned(),
            },
            &repairs,
            &idx,
        )
        .unwrap();
        let neut =
            fs::read_to_string(repairs.join(AUTO_INCLUDES_DIR).join("sys/neutrino.h")).unwrap();
        assert!(neut.contains("MsgReceive"), "{neut}");
    }

    #[test]
    fn header_placeholder_rejects_path_traversal() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();
        // Sentinel a `..`-escape would clobber if join were naive.
        let escape_target = root.join("victim.txt");
        fs::write(&escape_target, b"original").unwrap();

        for hostile in [
            "../../victim.txt",
            "/etc/cron.d/govfuzz_pwn",
            "../victim.txt",
        ] {
            let result = apply_repair(
                &Repair::HeaderPlaceholder {
                    virtual_path: hostile.to_owned(),
                },
                &repairs,
                &idx,
            );
            match result {
                Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
                Ok(_) => panic!("path traversal must be refused for {hostile:?}"),
            }
        }
        assert_eq!(
            fs::read_to_string(&escape_target).unwrap(),
            "original",
            "the file outside includes_dir must be untouched"
        );
    }

    #[test]
    fn confined_join_accepts_normal_and_curdir_components() {
        let base = Path::new("/tmp/base");
        assert_eq!(
            confined_join(base, "./a/b.h").unwrap(),
            Path::new("/tmp/base/a/b.h")
        );
        assert!(confined_join(base, "../escape").is_err());
        assert!(confined_join(base, "/abs").is_err());
        assert!(confined_join(base, "a/../../escape").is_err());
    }

    #[test]
    fn undefined_symbol_prefers_project_source_over_declared_stub() {
        let root = tmpdir();
        let helper = root.join("helper.c");
        fs::write(
            &helper,
            "int helper(const unsigned char *d, unsigned long n){return (int)n;}\n",
        )
        .unwrap();
        fs::write(
            root.join("helper.h"),
            "int helper(const unsigned char *, unsigned long);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "helper".to_owned(),
            },
            &idx,
        )
        .expect("undefined helper should be repairable");

        match repair {
            Repair::AddSource {
                symbol,
                source_path,
            } => {
                assert_eq!(symbol, "helper");
                assert_eq!(source_path, helper);
            }
            other => panic!("expected AddSource, got {other:?}"),
        }
    }

    #[test]
    fn exhausted_source_budget_falls_back_to_declared_stub() {
        let root = tmpdir();
        fs::write(
            root.join("helper.c"),
            "int helper(const unsigned char *d, unsigned long n){return d ? (int)n : 0;}\n",
        )
        .unwrap();
        fs::write(
            root.join("helper.h"),
            "int helper(const unsigned char *, unsigned long);\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair_forced_with_source_policy(
            &BuildErrorKind::UndefinedSymbol {
                name: "helper".to_owned(),
            },
            &idx,
            &RepairManifest::default(),
            false,
            false,
        )
        .expect("a declared symbol remains stub-repairable after the source budget");

        assert!(
            matches!(repair, Repair::StubDeclared { ref symbol, .. } if symbol == "helper"),
            "source-budget exhaustion must switch to the typed stub path: {repair:?}"
        );
    }

    #[test]
    fn added_source_exposes_its_private_header_directory() {
        let root = tmpdir();
        let module = root.join("src/check");
        fs::create_dir_all(&module).unwrap();
        let source = module.join("check.c");
        fs::write(&source, "int check(void) { return 0; }\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");

        let outcome = apply_repair(
            &Repair::AddSource {
                symbol: "check".to_owned(),
                source_path: source.clone(),
            },
            &repairs,
            &idx,
        )
        .unwrap();

        assert_eq!(outcome.extra_sources, vec![source]);
        assert_eq!(outcome.extra_includes, vec![module]);
    }

    #[test]
    fn posix_symbol_prefers_host_header_over_same_named_project_method() {
        let root = tmpdir();
        fs::write(root.join("stream.cpp"), "int read(int fd) { return fd; }\n").unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "read".to_owned(),
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::IncludeStdHeader { ref symbol, ref header })
                if symbol == "read" && header == "unistd.h"
        ));

        let attempted = RepairManifest {
            repairs: vec![Repair::IncludeStdHeader {
                symbol: "read".to_owned(),
                header: "unistd.h".to_owned(),
            }],
        };
        assert!(
            plan_repair_forced(
                &BuildErrorKind::UndefinedSymbol {
                    name: "read".to_owned(),
                },
                &idx,
                &attempted,
                false,
            )
            .is_none(),
            "an already-declared POSIX call must not fall through to stream.cpp"
        );
    }

    #[test]
    fn undefined_standard_libc_symbol_is_not_stubbed() {
        // POSIX declarations hidden behind feature/config guards need their real
        // header. Other libc functions already declared by the target still link
        // directly. Neither case may produce a blind `void symbol(void)` stub.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::UndefinedSymbol {
                    name: "open".to_owned()
                },
                &idx
            ),
            Some(Repair::IncludeStdHeader { ref symbol, ref header })
                if symbol == "open" && header == "fcntl.h"
        ));
        assert!(matches!(
            plan_repair(
                &BuildErrorKind::UndefinedSymbol {
                    name: "strcmp".to_owned()
                },
                &idx
            ),
            Some(Repair::IncludeStdHeader { ref symbol, ref header })
                if symbol == "strcmp" && header == "string.h"
        ));
        for sym in ["waitpid", "wctomb"] {
            assert!(
                plan_repair(
                    &BuildErrorKind::UndefinedSymbol {
                        name: sym.to_owned()
                    },
                    &idx
                )
                .is_none(),
                "{sym} should not need a repair"
            );
        }
    }

    #[test]
    fn undefined_assert_injects_its_standard_header() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        match plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "assert".to_owned(),
            },
            &idx,
        ) {
            Some(Repair::IncludeStdHeader { symbol, header }) => {
                assert_eq!(symbol, "assert");
                assert_eq!(header, "assert.h");
            }
            other => panic!("expected IncludeStdHeader, got {other:?}"),
        }
    }

    #[test]
    fn stub_preamble_includes_stdbool() {
        let dir = tmpdir();
        let stubs = dir.join("auto_stubs.c");
        let types = dir.join("auto_types.h");
        append_stub(&stubs, &types, "void s(void){return;}\n").unwrap();
        let body = std::fs::read_to_string(&stubs).unwrap();
        assert!(
            body.contains("#include <stdbool.h>"),
            "stub preamble must include <stdbool.h>: {body}"
        );
    }

    #[test]
    fn append_stub_is_idempotent_for_repeated_symbol() {
        // A later repair round can re-plan an already-applied stub (the build
        // still fails for an unrelated reason). Emitting the same definition
        // twice into auto_stubs.c is a `redefinition` compile error that fails
        // the whole build — regression: a cJSON harness (Parse via AddSource,
        // Print/Delete blind-stubbed) emitted each blind stub twice and broke a
        // previously-working target. append_stub must hold one copy per body.
        let dir = tmpdir();
        let stubs = dir.join("auto_stubs.c");
        let types = dir.join("auto_types.h");
        let print_stub = c_stub_gen::synth_blind_stub("cJSON_Print");
        let delete_stub = c_stub_gen::synth_blind_stub("cJSON_Delete");
        // Round 1 plans both; round 2 re-plans both.
        for _round in 0..2 {
            append_stub(&stubs, &types, &print_stub).unwrap();
            append_stub(&stubs, &types, &delete_stub).unwrap();
        }
        let body = std::fs::read_to_string(&stubs).unwrap();
        assert_eq!(
            body.matches("void *cJSON_Print(void)").count(),
            1,
            "cJSON_Print must be defined exactly once: {body}"
        );
        assert_eq!(
            body.matches("void *cJSON_Delete(void)").count(),
            1,
            "cJSON_Delete must be defined exactly once: {body}"
        );
        // Distinct symbols still both present.
        assert!(body.contains("void *cJSON_Print(void)"));
        assert!(body.contains("void *cJSON_Delete(void)"));
    }

    #[test]
    fn undefined_cpp_symbol_prefers_project_source() {
        let root = tmpdir();
        let helper = root.join("helper.cpp");
        fs::write(
            &helper,
            "#include <string>\n\
             namespace gov { std::string normalize(const std::string &seed) { return seed; } }\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::UndefinedSymbol {
                name: "gov::normalize[abi:cxx11](std::string const&)".to_owned(),
            },
            &idx,
        )
        .expect("undefined C++ helper should be repairable");

        match repair {
            Repair::AddSource {
                symbol,
                source_path,
            } => {
                assert!(symbol.contains("normalize"));
                assert_eq!(source_path, helper);
            }
            other => panic!("expected AddSource, got {other:?}"),
        }
    }

    #[test]
    fn ada_missing_with_is_repairable() {
        let idx = crate::auto::decl_index::DeclarationIndex::default();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaWith {
                unit: "Legacy.Io".to_owned(),
            },
            &idx,
        );

        assert!(
            repair.is_some(),
            "MissingAdaWith should synthesise an Ada package stub"
        );
    }

    #[test]
    fn repair_manifest_dedupes_ada_repairs_by_attempt_key() {
        let manifest = RepairManifest {
            repairs: vec![
                Repair::AdaPackageStub {
                    unit: "Aux_Pkg".to_owned(),
                    decls: Vec::new(),
                    ops: Vec::new(),
                    synthesize_body: false,
                    provenance: "test".to_owned(),
                },
                Repair::AdaPackageBodyStub {
                    unit: "Body_Pkg".to_owned(),
                    ops: Vec::new(),
                    provenance: "test".to_owned(),
                },
            ],
        };

        assert!(manifest.already_attempted("ada-spec:Aux_Pkg"));
        assert!(manifest.already_attempted("ada-body:Body_Pkg"));
    }

    #[test]
    fn ada_missing_package_body_is_repairable() {
        let idx = crate::auto::decl_index::DeclarationIndex::default();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaPackageBody {
                unit: "Aux_Pkg".to_owned(),
            },
            &idx,
        );

        assert!(
            repair.is_some(),
            "MissingAdaPackageBody should synthesise an Ada package body"
        );
    }

    #[test]
    fn ada_missing_package_body_prefers_indexed_real_body() {
        let root = tmpdir();
        fs::write(
            root.join("aux_pkg.ads"),
            "package Aux_Pkg is\n   function Score return Integer;\nend Aux_Pkg;\n",
        )
        .unwrap();
        fs::write(
            root.join("aux_pkg.adb"),
            "package body Aux_Pkg is\n   function Score return Integer is (1);\nend Aux_Pkg;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaPackageBody {
                unit: "Aux_Pkg".to_owned(),
            },
            &idx,
        );

        assert!(matches!(
            repair,
            Some(Repair::AddAdaSource { unit, sources })
                if unit == "Aux_Pkg"
                    && sources.iter().any(|path| path.ends_with("aux_pkg.adb"))
        ));
    }

    #[test]
    fn ada_missing_symbol_with_unit_is_repairable() {
        let idx = crate::auto::decl_index::DeclarationIndex::default();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaSymbol {
                unit: "Aux_Pkg".to_owned(),
                symbol: "Score".to_owned(),
            },
            &idx,
        );

        assert!(
            repair.is_some(),
            "qualified MissingAdaSymbol should extend a generated Ada package stub"
        );
    }

    #[test]
    fn ada_missing_symbol_adds_only_a_spec_that_declares_it() {
        let root = tmpdir();
        fs::write(
            root.join("vendor_custom_name.ads"),
            "package Aux_Pkg is function Score return Integer; end Aux_Pkg;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingAdaSymbol {
                unit: "Aux_Pkg".to_owned(),
                symbol: "Score".to_owned(),
            },
            &idx,
        );
        assert!(matches!(
            repair,
            Some(Repair::AddAdaSource { sources, .. })
                if sources.iter().any(|source| source.ends_with("vendor_custom_name.ads"))
        ));
    }

    #[test]
    fn ada_wrong_version_spec_is_not_readded_or_fabricated() {
        let root = tmpdir();
        fs::write(
            root.join("vendor_custom_name.ads"),
            "package Aux_Pkg is function Older_Api return Integer; end Aux_Pkg;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repair = plan_repair(
            &BuildErrorKind::MissingAdaSymbol {
                unit: "Aux_Pkg".to_owned(),
                symbol: "Score".to_owned(),
            },
            &idx,
        );
        assert!(
            repair.is_none(),
            "a real but incomplete/wrong-version spec cannot gain a symbol by being copied again: {repair:?}"
        );
    }

    #[test]
    fn missing_external_gpr_import_is_stubbed_only_under_force() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let manifest = RepairManifest::default();
        let err = BuildErrorKind::MissingGprImport {
            path: "gnatcoll".to_owned(),
        };
        // Without --force: an honest missing dependency — no repair (it surfaces in
        // the missing-deps manifest and is resolvable with --ada-deps).
        assert!(
            plan_repair_forced_with_source_policy(&err, &idx, &manifest, false, true).is_none(),
            "non-force must not fabricate a stub project"
        );
        // Under --force: synthesize a stub project so gprbuild can LOAD the build.
        assert!(
            matches!(
                plan_repair_forced_with_source_policy(&err, &idx, &manifest, true, true),
                Some(Repair::StubGprImport { project }) if project == "gnatcoll"
            ),
            "force must synthesize a stub GPR for the missing import"
        );
        // A pathful / `.gpr`-suffixed import reduces to the project stem.
        let err2 = BuildErrorKind::MissingGprImport {
            path: "vendor/si_units.gpr".to_owned(),
        };
        assert!(matches!(
            plan_repair_forced_with_source_policy(&err2, &idx, &manifest, true, true),
            Some(Repair::StubGprImport { project }) if project == "si_units"
        ));
        // Once attempted it is not re-proposed (avoids a stub-rewrite loop).
        let attempted = RepairManifest {
            repairs: vec![Repair::StubGprImport {
                project: "gnatcoll".to_owned(),
            }],
        };
        assert!(
            plan_repair_forced_with_source_policy(&err, &idx, &attempted, true, true).is_none(),
            "an already-stubbed import must not be re-proposed"
        );
    }

    #[test]
    fn ada_package_body_stub_uses_surviving_spec_profile() {
        let root = tmpdir();
        fs::write(
            root.join("aux_pkg.ads"),
            "package Aux_Pkg is\n   function Score (N : Natural) return Integer;\nend Aux_Pkg;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaPackageBody {
                unit: "Aux_Pkg".to_owned(),
            },
            &idx,
        )
        .expect("missing body should be repairable");
        apply_repair(&repair, &repairs, &idx).unwrap();

        let body = fs::read_to_string(repairs.join(AUTO_ADA_STUBS_DIR).join("aux_pkg.adb"))
            .expect("Ada package body stub should be written");
        assert!(
            body.contains("function Score (N : Natural) return Integer is"),
            "body stub should preserve the spec profile; got:\n{body}"
        );
    }

    #[test]
    fn ada_package_spec_stub_uses_surviving_body_profile_without_duplicate_body() {
        let root = tmpdir();
        fs::write(
            root.join("aux_pkg.adb"),
            "package body Aux_Pkg is\n   function Score (N : Natural) return Integer is\n   begin\n      return Integer (N);\n   end Score;\nend Aux_Pkg;\n",
        )
        .unwrap();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        let repair = plan_repair(
            &BuildErrorKind::MissingAdaWith {
                unit: "aux_pkg".to_owned(),
            },
            &idx,
        )
        .expect("missing spec should be repairable");
        apply_repair(&repair, &repairs, &idx).unwrap();

        let spec = fs::read_to_string(repairs.join(AUTO_ADA_STUBS_DIR).join("aux_pkg.ads"))
            .expect("Ada package spec stub should be written");
        assert!(
            spec.contains("function Score (N : Natural) return Integer;"),
            "spec stub should preserve the body profile; got:\n{spec}"
        );
        assert!(
            !repairs
                .join(AUTO_ADA_STUBS_DIR)
                .join("aux_pkg.adb")
                .exists(),
            "a deleted spec with a real body should not generate a duplicate body"
        );
    }

    #[test]
    fn inferred_ada_spec_inherits_dialect_and_imports_qualified_types() {
        let output = tmpdir();
        let stub = synth_ada_package_spec_with_ops(
            "PolyORB_HI.Output_Low_Level",
            &[stub_gen::StubOp {
                name: "C_Write".to_owned(),
                kind: stub_gen::StubOpKind::Procedure,
                return_type: None,
                params: vec![
                    stub_gen::StubParam {
                        name: "Fd".to_owned(),
                        mode: None,
                        type_name: "Interfaces.C.Int".to_owned(),
                        default: Some("2".to_owned()),
                    },
                    stub_gen::StubParam {
                        name: "P".to_owned(),
                        mode: None,
                        type_name: "System.Address".to_owned(),
                        default: None,
                    },
                ],
            }],
            &output,
        );

        assert!(!stub.content.contains("pragma Ada_"));
        assert!(stub.content.contains("with Interfaces.C;\nwith System;"));
        assert!(stub
            .content
            .contains("procedure C_Write (Fd : Interfaces.C.Int := 2; P : System.Address);"));
    }
}
