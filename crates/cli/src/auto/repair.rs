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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Repair {
    HeaderPlaceholder {
        virtual_path: String,
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
    },
    /// Force-include a standard header for an undefined standard symbol that is a
    /// macro / needs a declaration to compile (`assert` -> `<assert.h>`), rather
    /// than stubbing the symbol with a bogus weak function.
    IncludeStdHeader {
        symbol: String,
        header: String,
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
            Repair::ConfigHeaderSynth { virtual_path } => key == format!("config-h:{virtual_path}"),
            Repair::AddIncludeDir { dir } => dir.display().to_string() == key,
            Repair::TypePlaceholder { type_name } => type_name == key,
            Repair::TypeAlias { type_name, .. } => type_name == key,
            Repair::ConfigTypeAlias { type_name, .. } => key == format!("config-alias:{type_name}"),
            Repair::MacroDefine { name, .. } => key == format!("macro:{name}"),
            Repair::IncludeStdHeader { symbol, .. } => key == format!("stdhdr:{symbol}"),
            Repair::AddSource { source_path, .. } => source_path.display().to_string() == key,
            Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => symbol == key,
            Repair::EnvVarInjection { name, .. } => name == key,
            Repair::AdaPackageStub { unit, .. } => key == format!("ada-spec:{unit}"),
            Repair::AdaPackageBodyStub { unit, .. } => key == format!("ada-body:{unit}"),
            Repair::OverrideAdaBodyStub { source, .. } => {
                key == format!("ada-override:{}", source.display())
            }
            Repair::AddAdaSource { unit, .. } => key == format!("ada-src:{unit}"),
            Repair::PlatformStub { platform } => key == format!("platform-stub:{platform}"),
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
            leaf_indexed: p.leaf_indexed,
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
    let mut current = raw.trim().to_owned();
    for _ in 0..8 {
        match tree_typedef_underlying(decl_index, &current) {
            Some(next) if next.trim() != current && !next.trim().is_empty() => {
                current = next.trim().to_owned();
            }
            _ => break,
        }
    }
    current
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
        Repair::AddIncludeDir { dir } => Ok(ApplyOutcome {
            extra_sources: vec![],
            extra_includes: vec![dir.clone()],
        }),
        Repair::TypePlaceholder { type_name } => {
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
            } else if let Some(body) = c_stub_gen::synth_cpp_stdlib_include(type_name) {
                append_or_create(&cpp_includes_path, &body)?;
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
        Repair::MacroDefine { name, as_value } => {
            // Value position -> a benign 0 (works as int, NULL, or boolean in
            // version numbers / capability flags / `#ifdef` gates). Type or
            // specifier position (an inline/export qualifier like JSON_INLINE)
            // -> define to *nothing*, so the surrounding declaration parses.
            // Force-included (build.rs) so the definition precedes every use.
            let body = if target_source.is_some_and(|s| macro_used_function_like(s, name)) {
                // Function-like macro (PX4_ERR(fmt, ...), NuttX/flight-software
                // logging/assert macros). A variadic stub expanding to `(0)` works
                // as a statement (`PX4_ERR("x");` -> `(0);`) and as a value;
                // object-like `0` would make `0("x")` a call on an int.
                format!("#define {name}(...) (0)\n")
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
        Repair::IncludeStdHeader { header, .. } => {
            // Force-include the standard header (build.rs precedes every TU) so a
            // standard macro/symbol is declared without a bogus stub.
            append_or_create(&cpp_includes_path, &format!("#include <{header}>\n"))?;
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
                // Resolve a typedef-hidden scalar return (`sxu32` -> `unsigned int`,
                // unqlite/jx9) so the stub body recognises it as integral.
                let mut decl = decl.clone();
                decl.return_type = resolve_stub_return_type(decl_index, &decl.return_type);
                let body = c_stub_gen::synth_c_stub(&decl).ok_or_else(|| unsupported(symbol))?;
                append_stub(&stubs_path, &types_path, &body)?;
                Ok(ApplyOutcome {
                    extra_sources: vec![stubs_path],
                    extra_includes: vec![],
                })
            } else if let Some(decl) = decl_index.lookup_cpp(symbol) {
                // A C++ declaration: emit its stub into a .cpp compiled as C++ —
                // C++ definitions in auto_stubs.c (compiled as C) never compile.
                let body = c_stub_gen::synth_c_stub(decl).ok_or_else(|| unsupported(symbol))?;
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
            extra_includes: vec![],
        }),
        Repair::StubBlind { symbol } => {
            let body = c_stub_gen::synth_blind_stub(symbol);
            append_stub(&stubs_path, &types_path, &body)?;
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
                let dest = ada_stubs_dir.join(name);
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

fn append_or_create(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(body.as_bytes())?;
    Ok(())
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
        // <stdbool.h> so a stub returning `bool` (a synthesized C scalar return)
        // compiles; it is a standard, idempotent, collision-free header.
        append_or_create(
            stubs_path,
            "#include <stdbool.h>\n#include \"auto_types.h\"\n\n",
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
    content.push_str("pragma Ada_95;\n");
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
        .map(
            |param| match param.mode.as_deref().filter(|mode| !mode.is_empty()) {
                Some(mode) => format!("{} : {mode} {}", param.name, param.type_name),
                None => format!("{} : {}", param.name, param.type_name),
            },
        )
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
    for defs in type_defs {
        for typedef in &defs.typedefs {
            map.entry(typedef.name.as_str())
                .or_insert(typedef.underlying.as_str());
        }
    }

    let mut decls = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = name;
    loop {
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
        if crate::auto::cross_target::is_win32_known_name(name)
            && !attempted.already_attempted("win32-pack")
        {
            return Some(Repair::Win32Pack);
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
            // Prefer the real typedef from the tree-wide index (resolves an
            // arch/config-gated scalar alias to its true width) over the generic
            // `void *` placeholder, which neither matches a scalar decode nor is
            // force-included where a parameter type needs it.
            let tree = [&*decl_index.c_type_defs, &*decl_index.cpp_type_defs];
            if let Some(decls) = resolve_tree_typedef_chain(name, &tree) {
                Some(Repair::TypeAlias {
                    type_name: name.clone(),
                    decls,
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
            let definition_source = decl_index
                .lookup_c_definition_source(name)
                .or_else(|| decl_index.lookup_cpp_definition_source(name));
            // Prefer the project's real source — unless we already tried it and
            // the symbol is STILL undefined, meaning that file doesn't compile in
            // isolation (its own deps). Then stub the symbol so the link closes
            // (e.g. a harness-injected `CFE_MSG_InitDefaultHdr` lifecycle call
            // whose defining `cfe_msg_init.c` drags in the rest of the module).
            if let Some(source_path) = definition_source {
                if !attempted.already_attempted(&source_path.display().to_string()) {
                    return Some(Repair::AddSource {
                        symbol: name.clone(),
                        source_path: source_path.to_path_buf(),
                    });
                }
            }
            // A standard symbol that is a macro / needs a header (assert): inject
            // the header, never stub it.
            if let Some(header) = c_stub_gen::c_std_symbol_header(name) {
                return Some(Repair::IncludeStdHeader {
                    symbol: name.clone(),
                    header: header.to_owned(),
                });
            }
            // A standard libc FUNCTION resolves from libc at link time; a blind
            // `void name(void)` stub mismatches its real signature and breaks the
            // link, so leave it unstubbed (no repair).
            if c_stub_gen::is_standard_libc_symbol(name) {
                return None;
            }
            if let Some(decl) = decl_index.lookup_c(name) {
                Some(Repair::StubDeclared {
                    symbol: name.clone(),
                    return_type: decl.return_type.clone(),
                    provenance: format!("declared at line {}", decl.line),
                })
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
        BuildErrorKind::MissingSharedLib { .. }
        | BuildErrorKind::MissingGprImport { .. }
        | BuildErrorKind::Other { .. } => None,
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
            if force && !build_classifier::is_recovery_artifact(name) {
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
        BuildErrorKind::MissingAdaPackageBody { unit } => Some(Repair::AdaPackageBodyStub {
            unit: unit.clone(),
            ops: decl_index.lookup_ada_package_ops(unit),
            provenance: "gnat missing Ada package body".to_owned(),
        }),
        BuildErrorKind::MissingAdaSymbol { unit, symbol } => {
            if unit.is_empty() {
                None
            } else if let Some(sources) = ada_real_source_with_spec(decl_index, unit) {
                // The unit's real spec exists in the tree (a sibling dir) — add
                // its source so the symbol (and the rest of the unit) resolves.
                Some(Repair::AddAdaSource {
                    unit: unit.clone(),
                    sources,
                })
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
        BuildErrorKind::MalformedFunctionDecl { .. } => {
            // A body-less declarator from an in-tree macro/IDL-codegen line. The
            // only fix is rewriting that source line, but for C/C++ the offending
            // TU is the user's own project source (compiled in place, not copied
            // like the Ada src_instrumented tree), and rewriting untrusted
            // project source in place is out of bounds. No safe automated repair;
            // the precise classification surfaces it in the report instead of an
            // opaque `Other` cascade.
            None
        }
    }
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
    fn macro_define_writes_define_to_force_included_file() {
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        let repairs = root.join("repairs");
        fs::create_dir_all(&repairs).unwrap();

        apply_repair(
            &Repair::MacroDefine {
                name: "YAML_VERSION_STRING".to_owned(),
                as_value: true,
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
            },
            &repairs,
            &idx,
        )
        .unwrap();

        let defines = fs::read_to_string(repairs.join(AUTO_DEFINES_FILE)).unwrap();
        assert!(
            defines.contains("#define YAML_VERSION_STRING 0\n"),
            "{defines}"
        );
        assert!(defines.contains("#define JSON_INLINE\n"), "{defines}");
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
            Some(Repair::MacroDefine { name, as_value: true }) if name == "YAML_VERSION_MAJOR"
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
    fn undefined_standard_libc_symbol_is_not_stubbed() {
        // A real libc function links from libc; a blind `void open(void)` stub
        // mismatches its signature and breaks the link. Leave it unstubbed.
        let root = tmpdir();
        let idx = crate::auto::decl_index::DeclarationIndex::build(&root).unwrap();
        for sym in ["open", "strcmp", "waitpid", "wctomb"] {
            assert!(
                plan_repair(
                    &BuildErrorKind::UndefinedSymbol {
                        name: sym.to_owned()
                    },
                    &idx
                )
                .is_none(),
                "{sym} should not be stubbed"
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
}
