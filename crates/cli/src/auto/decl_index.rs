// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn include_candidate_is_host_usable(path: &Path) -> bool {
    if crate::generate_harness::source_path_is_foreign_platform(path) {
        return false;
    }

    let Ok(source) = crate::source_text::read_source_text(path) else {
        return true;
    };
    !source.lines().any(|line| {
        let directive = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .unwrap_or_default();
        let Some(message) = directive.strip_prefix("error") else {
            return false;
        };
        let message = message.to_ascii_lowercase();
        message.contains("foreign") && (message.contains("configure") || message.contains("build"))
    })
}

fn merge_vec_map<K, V>(destination: &mut HashMap<K, Vec<V>>, source: HashMap<K, Vec<V>>)
where
    K: Eq + Hash,
    V: PartialEq,
{
    for (key, values) in source {
        let existing = destination.entry(key).or_default();
        for value in values {
            if !existing.contains(&value) {
                existing.push(value);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct DeclarationIndex {
    /// Function name -> list of declarations across the tree. Multiple
    /// entries mean we found multiple incompatible declarations; the
    /// auto loop logs and picks the first by source-tree order.
    pub c: HashMap<String, Vec<c_parser::CDeclaration>>,
    pub cpp: HashMap<String, Vec<cpp_parser::CppDeclaration>>,
    /// C++ declaration leaf -> header(s) that declare it. Declared C++ stubs
    /// compile in their own translation unit and need the owning header for
    /// namespace/class-qualified definitions.
    cpp_declaration_headers: HashMap<String, Vec<PathBuf>>,
    /// C declarations originating in headers. Tree-wide lifecycle discovery uses
    /// this public surface only; source declarations include private `static`
    /// helpers whose storage class the declaration parser intentionally omits.
    c_header_declarations: Vec<c_parser::CDeclaration>,
    /// C declaration name -> header(s) that declare it. A generated C stub should
    /// include the owning header so typedef-backed parameter and return types are
    /// real, rather than cascading into incompatible opaque placeholders.
    c_declaration_headers: HashMap<String, Vec<PathBuf>>,
    /// C type name -> surviving header(s) that define the complete record or
    /// typedef. A damaged private header can remove the include edge while the
    /// real public type still exists elsewhere (bzip2's `bz_stream`); repair can
    /// force-include that unique real header instead of synthesizing a colliding
    /// layout.
    c_type_definition_headers: HashMap<String, Vec<PathBuf>>,
    /// C function name -> source file(s) that define it. Used by auto
    /// build recovery to add real project source files before falling
    /// back to generated stubs.
    c_definitions: HashMap<String, Vec<PathBuf>>,
    /// External C data symbol -> declared type. Undefined data must recover as
    /// a weak object, not a blind function with the same linker name.
    c_extern_data: HashMap<String, String>,
    /// External C data symbol -> header declarations. A weak definition should
    /// use the exact typedef spelling from its owning header when that header is
    /// unique, rather than resolving an anonymous enum/struct typedef into a
    /// nonexistent tagged type.
    c_extern_data_headers: HashMap<String, Vec<(PathBuf, String)>>,
    /// Object-like C preprocessor definitions found anywhere in the surviving
    /// tree. A deleted private header may duplicate foundational constants in a
    /// utility source (bzip2's `True`/`False`); recovery can reuse the exact
    /// replacement instead of guessing zero.
    c_object_macros: HashMap<String, Vec<String>>,
    /// C++ function name / qualified name -> source file(s) that define it.
    /// For source files that include definition-bearing implementation
    /// headers, the source file is indexed instead of the header so the
    /// repair loop adds a compilable translation unit.
    cpp_definitions: HashMap<String, Vec<PathBuf>>,
    /// Ada package unit -> public subprogram profiles from package specs.
    /// Used by auto build recovery to synthesize package bodies with
    /// signatures that match surviving `.ads` files.
    ada_package_ops: HashMap<String, Vec<stub_gen::StubOp>>,
    /// Ada package units with a real `.adb` package body in the source tree.
    ada_package_bodies: HashSet<String>,
    /// Ada unit key (`keccak.arch`) -> source file paths (`keccak-arch.ads`,
    /// `keccak-arch.adb`) anywhere in the tree. Lets a `MissingAdaSymbol` /
    /// `MissingAdaWith` be repaired by adding the unit's REAL source (a sibling
    /// dir outside the scan path — adamant's `serializer_types`) to the build,
    /// instead of stubbing it. Keyed off the GNAT filename convention, so the
    /// cross-tree walk records it without parsing.
    ada_unit_paths: HashMap<String, Vec<PathBuf>>,
    /// C++ namespace / class / type identifiers seen in the tree. Used to veto
    /// the `MissingMacro` repair: an ALL-CAPS namespace or enum type (yaml-cpp's
    /// `namespace YAML`, `EMITTER_MANIP`) is mis-read as a build-config macro by
    /// the classifier's all-caps heuristic, and `#define`-ing it corrupts every
    /// use (`namespace YAML {` -> `namespace 0 {`).
    cpp_type_names: HashSet<String>,
    /// All C typedefs/structs/enums found in header files anywhere in the tree.
    /// Used as a *fallback* type-resolution source for the harness generator:
    /// when a parameter type is left opaque by the target's own include closure
    /// (e.g. an arch/config-gated typedef like seL4's `word_t`, defined in a
    /// header reachable only via an include root the absent build would select),
    /// the tree-wide definition still resolves it. The include closure always
    /// takes priority, so this can never override a correct in-scope definition.
    /// Held behind `Arc` so the per-target harness path clones the handle, not
    /// the (potentially large) definition set.
    pub c_type_defs: std::sync::Arc<c_parser::CTypeDefs>,
    /// Tree-wide C++ type defs, used identically for the C++ harness path.
    pub cpp_type_defs: std::sync::Arc<c_parser::CTypeDefs>,
    /// Scalar typedefs recovered from implementation files. These are not used
    /// for target discovery or parameter decoding because a source-local type is
    /// not necessarily public, but the repair loop may use an unambiguous scalar
    /// definition after a damaged private header removes the same alias from a
    /// sibling TU (bzip2's `Bool`/`UChar`). Conflicting definitions are rejected
    /// by `resolve_tree_typedef_chain` rather than guessed.
    pub(crate) c_source_scalar_type_defs: std::sync::Arc<c_parser::CTypeDefs>,
    /// Header basename -> full paths of every C/C++ header in the tree. Lets a
    /// `MissingHeader` build error be repaired by adding the real header's
    /// directory to the include path (multi-module trees like cFS keep headers
    /// in sibling `modules/*/fsw/inc` dirs the auto include detection misses)
    /// instead of stubbing an empty placeholder that cascades into unknown types.
    pub(crate) header_paths: HashMap<String, Vec<PathBuf>>,
    /// Struct/union tag and typedef names defined in COMPILED source files
    /// (`.c`/`.cpp`), which `c_type_defs` (headers only) omits. Used purely for
    /// collision detection: the repair loop must not force-include a synthesized
    /// struct for a type already fully defined in a source that the build compiles
    /// (libsodium/ngtcp2/blake3 `output_t`), which would be a redefinition.
    source_type_names: HashSet<String>,
    /// Enumerator names defined anywhere in the tree, INCLUDING inside compiled
    /// `.c`/`.cpp` sources (which `c_type_defs` — headers only — omits) and
    /// including the members of anonymous enums, which have no type name to key
    /// on. Purely for collision detection, like `source_type_names`: the repair
    /// loop must never `#define` a name the project already defines as an
    /// enumerator. See `DeclIndex::defines_enumerator`.
    enumerator_names: HashSet<String>,
    /// Leaf names of C++ classes/structs/unions that appear (declared, forward-
    /// declared, or defined) in any HEADER (`.h`/`.hpp`/`.hh`/`.hxx`/…) in the
    /// tree. A member of such a class is reachable from a harness that `#include`s
    /// the header, so its methods are normal targets.
    cpp_header_class_names: HashSet<String>,
    /// Leaf names of C++ classes/structs/unions DEFINED (with a body) only inside a
    /// `.cpp`/`.cc`/`.cxx`/`.C` translation unit. When such a name is NOT in
    /// `cpp_header_class_names`, the class has no header declaration anywhere, so a
    /// generated harness (which includes the project header, not the `.cpp`) sees an
    /// undefined type — the C++ analog of Rust's "reachable only through a private
    /// module" (json11's `JsonParser`, defined in json11.cpp, absent from
    /// json11.hpp). Such members are pre-skipped instead of attempted-and-failed.
    cpp_source_class_names: HashSet<String>,
    /// Tree-wide C opaque-handle lifecycle pairs (§27.2): init/destroy pairs found
    /// by scanning public C header declarations throughout the tree (not just a
    /// target's include closure), computed ONCE here. Threaded into the
    /// per-target lifecycle table (`generate_harness::merge_tree_c_lifecycle`) so a
    /// handle whose constructor is declared in a header the target does NOT directly
    /// `#include` is still paired. Held behind `Arc` so the per-target harness path
    /// clones the handle, not the vector.
    pub c_tree_lifecycle: std::sync::Arc<Vec<harness_gen::c_generate::CHandleLifecycle>>,
}

/// The directory the cross-tree index should be built from when harnessing
/// `scan_path`. A subdir run of a larger project (cFS `modules/msg`, PX4
/// `src/lib/parameters`) needs cross-dir headers/types/definitions that live
/// elsewhere in the same project, so index from the nearest ancestor that marks
/// a project boundary (`.git`, then a top-level `CMakeLists.txt`/`Makefile`),
/// falling back to `scan_path` itself. Discovery and the attempt loop stay
/// scoped to `scan_path`; only what's *available* for resolution broadens.
pub fn project_index_root(scan_path: &Path) -> PathBuf {
    const MAX_ASCENT: usize = 24;
    let mut dir = scan_path;
    for _ in 0..MAX_ASCENT {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => dir = parent,
            _ => break,
        }
    }
    scan_path.to_path_buf()
}

impl DeclarationIndex {
    pub fn build(root: &Path) -> std::io::Result<Self> {
        Self::build_indexed(root, root)
    }

    /// Build the index, parsing files under `parse_root`, but additionally
    /// record the (cheap, parse-free) header-path index from `header_root` — the
    /// project root. A subdir run then resolves a `MissingHeader` to the real
    /// cross-dir header (PX4 `lib/perf/perf_counter.h` from `src/lib/parameters`)
    /// without paying to parse the whole project for types. The parse-based
    /// indexes (types, declarations, definitions) stay scoped to `parse_root`.
    pub fn build_indexed(parse_root: &Path, header_root: &Path) -> std::io::Result<Self> {
        let mut idx = Self::build_parsed(parse_root)?;
        if header_root != parse_root {
            idx.extend_header_paths(header_root)?;
            idx.extend_ada_unit_paths(header_root)?;
        }
        // Drop Ada units that live only in GPR scenario-excluded dirs (libkeccak's
        // SIMD `src/x86_64/AVX2`): the default build never compiles them, so the
        // cross-dir unit recovery must not re-add one — that would defeat
        // scenario-gating and resurrect the `-mavx2` build failures.
        idx.prune_scenario_excluded_ada_units(parse_root);
        Ok(idx)
    }

    /// Remove Ada unit -> source entries whose source lives under a GPR
    /// scenario-excluded directory of the project governing `gpr_root`. Keeps the
    /// unit index consistent with the source set the build actually compiles.
    fn prune_scenario_excluded_ada_units(&mut self, gpr_root: &Path) {
        let excluded = crate::auto::gpr_scenario::find_project_gpr(gpr_root)
            .map(|gpr| crate::auto::gpr_scenario::scenario_excluded_dirs(&gpr))
            .unwrap_or_default();
        if excluded.is_empty() {
            return;
        }
        for paths in self.ada_unit_paths.values_mut() {
            paths.retain(|p| {
                let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
                !excluded.iter().any(|ex| canon.starts_with(ex))
            });
        }
        self.ada_unit_paths.retain(|_, paths| !paths.is_empty());
    }

    /// Walk `header_root` recording only header basenames -> paths (no parsing),
    /// so the cross-tree header resolution covers the whole project cheaply.
    /// Capped to keep a pathological tree (millions of files) bounded.
    fn extend_header_paths(&mut self, header_root: &Path) -> std::io::Result<()> {
        const MAX_HEADER_WALK: usize = 200_000;
        let mut seen = 0usize;
        for entry in walkdir_lite(header_root)? {
            seen += 1;
            if seen > MAX_HEADER_WALK {
                break;
            }
            let Some(ext) = entry.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if matches!(ext, "h" | "hpp" | "hh" | "hxx" | "hp" | "inc") {
                if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                    let paths = self.header_paths.entry(name.to_owned()).or_default();
                    if !paths.contains(&entry) {
                        paths.push(entry.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// Walk `header_root` recording Ada unit -> source paths by GNAT filename
    /// convention (`keccak-arch.ads` -> unit `keccak.arch`), no parsing — so the
    /// cross-tree Ada unit index is as cheap as the header index. Same walk cap.
    fn extend_ada_unit_paths(&mut self, header_root: &Path) -> std::io::Result<()> {
        const MAX_ADA_WALK: usize = 200_000;
        let mut seen = 0usize;
        for entry in walkdir_lite(header_root)? {
            seen += 1;
            if seen > MAX_ADA_WALK {
                break;
            }
            let Some(ext) = entry.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if matches!(ext, "ads" | "adb") {
                self.record_ada_unit_path(&entry);
            }
        }
        Ok(())
    }

    /// Fold additional header search roots — `auto --extra-include` dependency
    /// directories that live outside the project tree — into the cross-dir
    /// header index, so a `#include "common_types.h"` from a swept header
    /// resolves to the real out-of-tree file during type modeling instead of
    /// being treated as missing.
    pub fn add_header_search_roots(&mut self, roots: &[PathBuf]) -> std::io::Result<()> {
        for root in roots {
            self.extend_header_paths(root)?;
        }
        Ok(())
    }

    /// Fold the `.c`/`.cpp` DEFINITION sources from additional roots — `auto
    /// --extra-include` dependency directories that live outside the swept tree —
    /// into the definition index. Without this, an undefined target-library symbol
    /// (cJSON's `cJSON_Parse`, declared only in an out-of-tree `cJSON.h`) has no
    /// `c_definitions` entry, so the repair planner blind-stubs it as
    /// `void cJSON_Parse(void)`; the harness then calls it through its real
    /// pointer-returning prototype, reads a garbage return register, and crashes
    /// in `free(garbage)` — the phantom #388 findings. Indexing the defining `.c`
    /// lets the existing `UndefinedSymbol -> Repair::AddSource` arm compile and
    /// link the real source instead (faithful fuzzing, zero phantom crashes).
    ///
    /// Deliberately narrow: it populates only `c_definitions` / `cpp_definitions`
    /// (the AddSource lookup) and `source_type_names` (so a struct now linkable
    /// from the added source isn't also force-included as a synthetic
    /// redefinition). It does NOT broaden the `c`/`cpp` declaration maps or the
    /// tree-wide type-def fallbacks — those drive unrelated repair arms and a huge
    /// vendored `--extra-include` SDK must not perturb them. The walk is capped in
    /// both file count and per-file size so pointing `--extra-include` at a whole
    /// sysroot stays cheap, and any translation unit that defines its own `main`
    /// is skipped wholesale (AddSource pulls the entire file, and a second `main`
    /// is a duplicate-symbol link break).
    pub fn add_definition_search_roots(&mut self, roots: &[PathBuf]) -> std::io::Result<()> {
        const MAX_DEF_WALK: usize = 50_000;
        const MAX_DEF_FILE_BYTES: u64 = 8 * 1024 * 1024;
        let mut seen = 0usize;
        for root in roots {
            for entry in walkdir_lite(root)? {
                seen += 1;
                if seen > MAX_DEF_WALK {
                    return Ok(());
                }
                let Some(ext) = entry.extension().and_then(|e| e.to_str()) else {
                    continue;
                };
                let is_c = ext == "c";
                let is_cpp = matches!(ext, "cpp" | "cc" | "cxx" | "C");
                if !is_c && !is_cpp {
                    continue;
                }
                if std::fs::metadata(&entry)
                    .map(|m| m.len())
                    .unwrap_or(u64::MAX)
                    > MAX_DEF_FILE_BYTES
                {
                    continue;
                }
                let Ok(source) = crate::source_text::read_source_text(&entry) else {
                    continue;
                };
                if is_c {
                    let Ok(functions) = c_parser::parse_c_functions(&source) else {
                        continue;
                    };
                    if functions.iter().any(|f| f.name == "main") {
                        continue;
                    }
                    for f in functions {
                        let paths = self.c_definitions.entry(f.name).or_default();
                        if !paths.contains(&entry) {
                            paths.push(entry.clone());
                        }
                    }
                    if let Ok(defs) = c_parser::parse_c_type_defs(&source) {
                        for s in defs.structs.iter().filter(|s| s.complete) {
                            self.source_type_names.insert(s.name.clone());
                        }
                        for t in &defs.typedefs {
                            self.source_type_names.insert(t.name.clone());
                        }
                        for e in &defs.enums {
                            self.enumerator_names.extend(e.members.iter().cloned());
                        }
                    }
                } else {
                    if cpp_source_uses_module_unit(&source) {
                        continue;
                    }
                    let Ok(functions) = cpp_parser::parse_cpp_functions(&source) else {
                        continue;
                    };
                    if functions.iter().any(|f| f.name == "main") {
                        continue;
                    }
                    for f in functions {
                        self.index_cpp_definition(&f, &entry);
                    }
                }
            }
        }
        Ok(())
    }

    /// Merge exact dependency files recovered into an isolated VCS shadow. This
    /// is deliberately broader than `--extra-include`: a deleted public header
    /// may carry class/type declarations, while a deleted C/C++/Ada body must be
    /// visible to the real-source repair indexes. Only files in the recovery
    /// root are parsed, so the surviving tree is not duplicated.
    pub fn add_vcs_recovery_root(&mut self, root: &Path) -> std::io::Result<()> {
        let recovered = Self::build_parsed(root)?;
        merge_vec_map(&mut self.c, recovered.c);
        merge_vec_map(&mut self.cpp, recovered.cpp);
        merge_vec_map(
            &mut self.cpp_declaration_headers,
            recovered.cpp_declaration_headers,
        );
        for declaration in recovered.c_header_declarations {
            if !self.c_header_declarations.contains(&declaration) {
                self.c_header_declarations.push(declaration);
            }
        }
        merge_vec_map(
            &mut self.c_declaration_headers,
            recovered.c_declaration_headers,
        );
        merge_vec_map(
            &mut self.c_type_definition_headers,
            recovered.c_type_definition_headers,
        );
        merge_vec_map(&mut self.c_definitions, recovered.c_definitions);
        for (name, data_type) in recovered.c_extern_data {
            self.c_extern_data.entry(name).or_insert(data_type);
        }
        merge_vec_map(
            &mut self.c_extern_data_headers,
            recovered.c_extern_data_headers,
        );
        merge_vec_map(&mut self.c_object_macros, recovered.c_object_macros);
        merge_vec_map(&mut self.cpp_definitions, recovered.cpp_definitions);
        merge_vec_map(&mut self.ada_package_ops, recovered.ada_package_ops);
        self.ada_package_bodies.extend(recovered.ada_package_bodies);
        merge_vec_map(&mut self.ada_unit_paths, recovered.ada_unit_paths);
        self.cpp_type_names.extend(recovered.cpp_type_names);
        std::sync::Arc::make_mut(&mut self.c_type_defs)
            .merge(recovered.c_type_defs.as_ref().clone());
        std::sync::Arc::make_mut(&mut self.cpp_type_defs)
            .merge(recovered.cpp_type_defs.as_ref().clone());
        std::sync::Arc::make_mut(&mut self.c_source_scalar_type_defs)
            .merge(recovered.c_source_scalar_type_defs.as_ref().clone());
        merge_vec_map(&mut self.header_paths, recovered.header_paths);
        self.source_type_names.extend(recovered.source_type_names);
        self.enumerator_names.extend(recovered.enumerator_names);
        self.cpp_header_class_names
            .extend(recovered.cpp_header_class_names);
        self.cpp_source_class_names
            .extend(recovered.cpp_source_class_names);
        self.c_tree_lifecycle = std::sync::Arc::new(self.compute_c_tree_lifecycle());
        Ok(())
    }

    /// Record an Ada source under every defensible unit identity. The parsed
    /// declaration is authoritative for custom GPR naming; the GNAT basename is
    /// retained as a fallback for compiler runtime sources the parser cannot read.
    fn record_ada_unit_path(&mut self, path: &Path) {
        let mut keys = Vec::new();
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            keys.push(ada_unit_key(strip_ada_platform_suffix(stem)));
        }
        if let Ok(source) = crate::source_text::read_source_text(path) {
            if let Ok(ast) = ada_parser::reconcile::build_structural_ast(&source, None, path) {
                if let Some(package) = ast.packages.first() {
                    keys.push(ada_unit_key(&package.name));
                } else if let Some(subprogram) = ast.subprograms.iter().find(|subprogram| {
                    matches!(
                        subprogram.owner,
                        ada_parser::ast::SubprogramOwner::LibraryLevel
                    )
                }) {
                    keys.push(ada_unit_key(&subprogram.name));
                }
            }
        }
        keys.sort();
        keys.dedup();
        for key in keys {
            let paths = self.ada_unit_paths.entry(key).or_default();
            if !paths.contains(&path.to_path_buf()) {
                paths.push(path.to_path_buf());
            }
        }
    }

    /// The real source files (`.ads` then `.adb`) for an Ada unit found anywhere
    /// in the tree, spec first. Empty when the unit isn't in the tree (genuinely
    /// model-generated or external). Used to add a cross-dir unit's real source
    /// to the build instead of stubbing it.
    pub fn ada_unit_source_files(&self, unit: &str) -> Vec<PathBuf> {
        let mut files = self
            .ada_unit_paths
            .get(&ada_unit_key(unit))
            .cloned()
            .unwrap_or_default();
        // Spec before body so the build sees the declaration first.
        files.sort_by_key(|p| {
            let is_body = p.extension().and_then(|e| e.to_str()) == Some("adb");
            (is_body, p.clone())
        });
        files
    }

    /// Real spec/body files for `unit`, but only when at least one indexed spec
    /// actually declares `symbol`. This prevents a wrong-version or shadowing
    /// spec from being "repaired" as if merely copying that unit could add a
    /// declaration it does not contain.
    pub fn ada_unit_source_files_declaring_symbol(&self, unit: &str, symbol: &str) -> Vec<PathBuf> {
        let files = self.ada_unit_source_files(unit);
        let declaring_dirs = files
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("ads"))
                    && ada_spec_declares_symbol(path, unit, symbol)
            })
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect::<HashSet<_>>();
        if declaring_dirs.is_empty() {
            return Vec::new();
        }
        files
            .into_iter()
            .filter(|path| {
                path.parent()
                    .is_some_and(|parent| declaring_dirs.contains(parent))
            })
            .collect()
    }

    fn build_parsed(root: &Path) -> std::io::Result<Self> {
        let mut idx = Self::default();
        let entries = walkdir_lite(root)?;
        // Keep only the compact facts needed by the final include-to-definition
        // join. The old implementation retained the FULL text of every C++
        // source and header until the entire tree had been parsed, making peak
        // RSS proportional to checkout bytes on large C++ systems.
        let mut cpp_headers: Vec<(PathBuf, Vec<cpp_parser::CppFunction>)> = Vec::new();
        let mut cpp_sources: Vec<(PathBuf, Vec<String>)> = Vec::new();
        let mut c_type_defs = c_parser::CTypeDefs::default();
        let mut cpp_type_defs = c_parser::CTypeDefs::default();
        let mut c_source_scalar_type_defs = c_parser::CTypeDefs::default();
        for entry in entries {
            let Some(ext) = entry.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                let indexed_name = if matches!(ext, "h" | "hpp" | "hh" | "hxx" | "hp" | "inc") {
                    Some(name)
                } else {
                    // Some source releases ship the configured public header as
                    // an explicit prebuilt fallback (libpng's
                    // `pnglibconf.h.prebuilt`). A missing `pnglibconf.h` should
                    // forward to that real feature surface, not an empty stub
                    // that compiles the API out.
                    name.strip_suffix(".prebuilt")
                        .or_else(|| name.strip_suffix(".dist"))
                        .filter(|base| {
                            Path::new(base)
                                .extension()
                                .and_then(|suffix| suffix.to_str())
                                .is_some_and(|suffix| {
                                    matches!(suffix, "h" | "hpp" | "hh" | "hxx" | "hp" | "inc")
                                })
                        })
                };
                if let Some(indexed_name) = indexed_name {
                    idx.header_paths
                        .entry(indexed_name.to_owned())
                        .or_default()
                        .push(entry.clone());
                }
            }
            // `walkdir_lite` intentionally returns paths, not contents. Reject
            // unrelated artifacts before reading them: a source tree can contain
            // multi-gigabyte firmware/images beside its code, and object-macro
            // extraction never needs to inspect those files.
            if !matches!(
                ext,
                "c" | "h"
                    | "cpp"
                    | "cc"
                    | "cxx"
                    | "C"
                    | "hpp"
                    | "hh"
                    | "hxx"
                    | "hp"
                    | "inc"
                    | "ads"
                    | "adb"
                    | "prebuilt"
                    | "dist"
            ) {
                continue;
            }
            let Ok(source) = crate::source_text::read_source_text(&entry) else {
                continue;
            };
            if !crate::generate_harness::source_path_is_foreign_platform(&entry) {
                for (name, value) in object_macro_definitions(&source) {
                    let values = idx.c_object_macros.entry(name).or_default();
                    if !values.contains(&value) {
                        values.push(value);
                    }
                }
            }
            // Record C++ class/struct/union leaf names so a member whose owning
            // class is defined only in a `.cpp` (never declared in a header) can be
            // pre-skipped. Every header extension is parsed with the C++ type-def
            // parser (a superset of C, and a `.h` is routinely a C++ header — e.g.
            // ada-url) so a forward declaration in a header still counts as
            // "declared", keeping out-of-line-defined classes harnessable.
            if matches!(ext, "h" | "hpp" | "hh" | "hxx" | "hp") {
                if let Ok(classes) = cpp_parser::parse_cpp_class_info(&source) {
                    for class in classes {
                        idx.cpp_header_class_names.insert(class.name);
                    }
                }
                if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                    for s in &defs.structs {
                        idx.cpp_header_class_names.insert(s.name.clone());
                    }
                }
            } else if matches!(ext, "cpp" | "cc" | "cxx" | "C")
                && !cpp_source_uses_module_unit(&source)
            {
                if let Ok(classes) = cpp_parser::parse_cpp_class_info(&source) {
                    for class in classes.into_iter().filter(|class| class.complete) {
                        idx.cpp_source_class_names.insert(class.name);
                    }
                }
                if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                    for s in defs.structs.iter().filter(|s| s.complete) {
                        idx.cpp_source_class_names.insert(s.name.clone());
                    }
                }
            }
            match ext {
                "c" | "h" => {
                    for (name, data_type) in c_extern_data_declarations(&source) {
                        idx.c_extern_data
                            .entry(name.clone())
                            .or_insert_with(|| data_type.clone());
                        if ext == "h" {
                            let declarations = idx.c_extern_data_headers.entry(name).or_default();
                            let declaration = (entry.clone(), data_type);
                            if !declarations.contains(&declaration) {
                                declarations.push(declaration);
                            }
                        }
                    }
                    if ext == "h" {
                        // Tree-wide type-def fallback is collected from headers
                        // (where typedefs/structs/enums live); a `.c`-local def
                        // is not a sound cross-target fallback. A `.h` is a C
                        // header that C++ TUs also include, so feed its defs into
                        // BOTH indexes — otherwise a basic alias defined in a `.h`
                        // (fprime `typedef uint8_t U8;`) is invisible to the C++
                        // fallback and a `U8` parameter is wrongly opaque.
                        if let Ok(defs) = c_parser::parse_c_type_defs(&source) {
                            // Record header type NAMES (complete structs + typedefs)
                            // so repair never force-includes a SYNTHESIZED struct
                            // that collides with the real one in this header — even
                            // after `retain_flat_pod_structs` prunes the struct from
                            // `c_type_defs` (jansson `strbuffer_t`, cmark `cmark_strbuf`
                            // are `typedef struct {..} X;` with pointer fields, pruned
                            // as non-flat-POD, so the redefinition guard lost them).
                            for s in defs.structs.iter().filter(|s| s.complete) {
                                idx.source_type_names.insert(s.name.clone());
                                let headers = idx
                                    .c_type_definition_headers
                                    .entry(s.name.clone())
                                    .or_default();
                                if !headers.contains(&entry) {
                                    headers.push(entry.clone());
                                }
                            }
                            for e in &defs.enums {
                                idx.enumerator_names.extend(e.members.iter().cloned());
                            }
                            for t in &defs.typedefs {
                                idx.source_type_names.insert(t.name.clone());
                                let headers = idx
                                    .c_type_definition_headers
                                    .entry(t.name.clone())
                                    .or_default();
                                if !headers.contains(&entry) {
                                    headers.push(entry.clone());
                                }
                            }
                            for e in &defs.enums {
                                let headers = idx
                                    .c_type_definition_headers
                                    .entry(e.name.clone())
                                    .or_default();
                                if !headers.contains(&entry) {
                                    headers.push(entry.clone());
                                }
                            }
                            c_type_defs.merge(defs.clone());
                            cpp_type_defs.merge(defs);
                        }
                        // Plain `.h` is also the dominant header convention in
                        // legacy C++ (smhasher). Index its prototypes in the C++
                        // declaration map as well, so a demangled link error with
                        // a parameter signature can synthesize a C++-linkage stub
                        // instead of falling through to an unmangled blind C stub.
                        if let Ok(decls) = cpp_parser::parse_cpp_declarations(&source) {
                            for d in decls {
                                idx.index_cpp_declaration(d, &entry, true);
                            }
                        }
                        if let Ok(functions) = cpp_parser::parse_cpp_functions(&source) {
                            cpp_headers.push((entry.clone(), functions));
                        }
                    }
                    if let Ok(decls) = c_parser::parse_c_declarations(&source) {
                        if ext == "h" {
                            idx.c_header_declarations.extend(decls.iter().cloned());
                        }
                        for d in decls {
                            if ext == "h" {
                                let headers =
                                    idx.c_declaration_headers.entry(d.name.clone()).or_default();
                                if !headers.contains(&entry) {
                                    headers.push(entry.clone());
                                }
                            }
                            idx.c.entry(d.name.clone()).or_default().push(d);
                        }
                    }
                    if ext == "c" {
                        if let Ok(functions) = c_parser::parse_c_functions(&source) {
                            for f in functions {
                                let name = f.name.clone();
                                if !f.is_static {
                                    idx.c.entry(name.clone()).or_default().push(
                                        c_parser::CDeclaration {
                                            name: name.clone(),
                                            return_type: f.return_type,
                                            param_types: f
                                                .params
                                                .into_iter()
                                                .map(|param| param.c_type)
                                                .collect(),
                                            variadic: f.variadic,
                                            line: f.line,
                                        },
                                    );
                                }
                                idx.c_definitions
                                    .entry(name)
                                    .or_default()
                                    .push(entry.clone());
                            }
                        }
                        // Record COMPLETE struct + typedef names from the .c so
                        // repair won't force-include a colliding synthetic struct.
                        if let Ok(defs) = c_parser::parse_c_type_defs(&source) {
                            for s in defs.structs.iter().filter(|s| s.complete) {
                                idx.source_type_names.insert(s.name.clone());
                            }
                            for t in &defs.typedefs {
                                idx.source_type_names.insert(t.name.clone());
                            }
                            for e in &defs.enums {
                                idx.enumerator_names.extend(e.members.iter().cloned());
                            }
                            c_source_scalar_type_defs.typedefs.extend(defs.typedefs);
                        }
                        // Also index file-scope global VARIABLE definitions so a
                        // cross-file reference to a shared global (PX4 rc parsers
                        // share `rc_decode_buf`) resolves to its defining source
                        // via AddSource instead of being blind-stubbed (which
                        // leaves the symbol undefined at link).
                        for name in extract_global_var_definitions(&source) {
                            idx.c_definitions
                                .entry(name)
                                .or_default()
                                .push(entry.clone());
                        }
                    }
                }
                "cpp" | "cc" | "cxx" | "C" | "hpp" | "hh" | "hxx" => {
                    let is_cpp_source = matches!(ext, "cpp" | "cc" | "cxx" | "C");
                    if is_cpp_source {
                        if cpp_source_uses_module_unit(&source) {
                            continue;
                        }
                        cpp_sources.push((entry.clone(), quoted_includes(&source)));
                        // Enumerators only — `cpp_type_defs` stays headers-only by
                        // design (a source-local type is not necessarily public),
                        // but the repair loop still must not `#define` over an
                        // enumerator this TU defines. See `defines_enumerator`.
                        if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                            for e in &defs.enums {
                                idx.enumerator_names.extend(e.members.iter().cloned());
                            }
                        }
                    } else {
                        if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                            cpp_type_defs.merge(defs);
                        }
                    }
                    if let Ok(decls) = cpp_parser::parse_cpp_declarations(&source) {
                        for d in decls {
                            idx.index_cpp_declaration(d, &entry, !is_cpp_source);
                        }
                    }
                    if let Ok(functions) = cpp_parser::parse_cpp_functions(&source) {
                        for f in &functions {
                            idx.collect_cpp_type_names(f);
                        }
                        if is_cpp_source {
                            for f in functions {
                                idx.index_cpp_definition(&f, &entry);
                            }
                            // Index file-scope global variable definitions too
                            // (PX4 `__EXPORT rc_decode_buf_t rc_decode_buf;` in
                            // common_rc.cpp), so a parser TU referencing the shared
                            // global links against the real source via AddSource.
                            for name in extract_global_var_definitions(&source) {
                                idx.cpp_definitions
                                    .entry(name)
                                    .or_default()
                                    .push(entry.clone());
                            }
                        } else {
                            cpp_headers.push((entry.clone(), functions));
                        }
                    }
                }
                "ads" | "adb" => {
                    idx.record_ada_unit_path(&entry);
                    idx.index_ada_package_ops(&entry, &source, ext.eq_ignore_ascii_case("adb"));
                }
                _ => {}
            }
        }
        idx.index_cpp_definition_headers(&cpp_sources, &cpp_headers);
        // Keep the scalar/enum-resolving part of the tree-wide index plus
        // *flat-POD* structs (every field resolves to a scalar or enum) — the
        // ubiquitous military "strong typedef" wrapper idiom (cFS
        // `CFE_SB_MsgId_t { CFE_SB_MsgId_Atom_t Value; }`, resource-id wrappers).
        // Structs with a pointer/union/unresolved field are dropped: an arch-gated
        // complex struct (`tcb_t`) stays an honest opaque skip rather than an
        // attempt-and-fail build, while small POD packets/ids decode and build.
        retain_flat_pod_structs(&mut c_type_defs);
        retain_flat_pod_structs(&mut cpp_type_defs);
        idx.c_type_defs = std::sync::Arc::new(c_type_defs);
        idx.cpp_type_defs = std::sync::Arc::new(cpp_type_defs);
        idx.c_source_scalar_type_defs = std::sync::Arc::new(c_source_scalar_type_defs);
        // §27.2: compute the tree-wide C opaque-handle lifecycle pairs ONCE, from
        // public declarations in every C header in the tree, so a
        // handle whose constructor/destructor lives in a header a given target does
        // not `#include` is still pairable. Reuses the exact per-target pairing
        // (`c_direct_lifecycle_table` with no same-file functions, all tree decls as
        // cross-file declarations) so the tree-wide result is consistent with what
        // the per-target path would find. The merge into each target is local-first.
        idx.c_tree_lifecycle = std::sync::Arc::new(idx.compute_c_tree_lifecycle());
        Ok(idx)
    }

    /// Build the tree-wide C lifecycle pairs from every indexed C declaration
    /// (§27.2). The registry is the tree-wide C type-def fallback, so a handle
    /// typedef/forward declaration anywhere in the tree resolves to its canonical
    /// key. Returns an empty vec when the tree declares no opaque-handle lifecycle.
    fn compute_c_tree_lifecycle(&self) -> Vec<harness_gen::c_generate::CHandleLifecycle> {
        let registry = type_model::TypeRegistry::from_defs(std::iter::once(&*self.c_type_defs));
        let tree_decls = self.c_header_declarations.clone();
        if tree_decls.is_empty() {
            return Vec::new();
        }
        crate::generate_harness::c_direct_lifecycle_table(&[], &tree_decls, &registry)
    }

    fn index_cpp_declaration(
        &mut self,
        declaration: cpp_parser::CppDeclaration,
        source_path: &Path,
        is_header: bool,
    ) {
        let name = declaration.name.clone();
        self.cpp.entry(name.clone()).or_default().push(declaration);
        if is_header {
            let headers = self.cpp_declaration_headers.entry(name).or_default();
            let path = source_path.to_path_buf();
            if !headers.contains(&path) {
                headers.push(path);
            }
        }
    }

    /// Record the namespace components, class name, and param/return type leaf
    /// identifiers of a C++ function so the repair loop can recognise project
    /// namespaces/types and refuse to `#define` them as build-config macros.
    fn collect_cpp_type_names(&mut self, f: &cpp_parser::CppFunction) {
        for ns in &f.api.namespace_path {
            self.cpp_type_names.insert(ns.clone());
        }
        if let Some(class) = &f.api.class_name {
            self.cpp_type_names.insert(class.clone());
        }
        let mut record_type = |ty: &str| {
            if let Some(leaf) = cpp_type_leaf_identifier(ty) {
                self.cpp_type_names.insert(leaf);
            }
        };
        record_type(&f.return_type);
        for p in &f.params {
            record_type(&p.cpp_type);
        }
    }

    /// Whether `name` is a C++ namespace, class, or type identifier seen in the
    /// tree — i.e. NOT a missing build-config macro, even if it is ALL-CAPS.
    pub fn cpp_defines_type_or_namespace(&self, name: &str) -> bool {
        self.cpp_type_names.contains(name)
    }

    /// Whether the tree DEFINES a function of this name, in either language.
    ///
    /// Used to veto `#define`-ing it: a macro rewrites the function's own
    /// definition (`int f(T x)` becomes `int (0)(T x)`), so the repair destroys
    /// the code it was meant to unblock — including, in the worst case, the
    /// target itself.
    pub fn defines_function(&self, name: &str) -> bool {
        self.c_definitions.contains_key(name) || self.cpp_definitions.contains_key(name)
    }

    /// Whether the tree defines `name` as an ENUMERATOR, in either language.
    ///
    /// Same hazard as [`Self::defines_function`], one construct over. A macro is
    /// force-included ahead of every translation unit, so `#define ScannerLimit 1`
    /// rewrites the enum's own definition —
    ///
    ///   enum : std::size_t { ScannerLimit = 4 };  ->  enum : std::size_t { 1 = 4 };
    ///
    /// — which fails to parse ("expected identifier"). The name was never missing
    /// from the project; it was merely not visible in the harness translation unit,
    /// and defining it destroys the real declaration for every TU that had it.
    pub fn defines_enumerator(&self, name: &str) -> bool {
        self.enumerator_names.contains(name)
            || [&self.c_type_defs, &self.cpp_type_defs].iter().any(|defs| {
                defs.enums
                    .iter()
                    .any(|def| def.members.iter().any(|member| member == name))
            })
    }

    /// Resolve a `#include` spelling (bare `cfe_error.h` or sub-pathed
    /// `osal/common_types.h`) to an include-root directory in the tree such that
    /// `root/spelling` is a real header. Used to repair a `MissingHeader` by
    /// adding the real directory to the include path instead of stubbing an
    /// empty placeholder. Returns None when no matching header exists in the tree.
    pub fn include_root_for(&self, spelling: &str) -> Option<PathBuf> {
        let spelling = spelling.trim().replace('\\', "/");
        let basename = std::path::Path::new(&spelling).file_name()?.to_str()?;
        let candidates = self.header_paths.get(basename)?;
        let needle = format!("/{spelling}");
        let mut roots: Vec<PathBuf> = candidates
            .iter()
            .filter(|path| include_candidate_is_host_usable(path))
            .filter_map(|path| {
                let path_str = path.to_string_lossy().replace('\\', "/");
                path_str
                    .strip_suffix(&needle)
                    .filter(|root| !root.is_empty())
                    .map(PathBuf::from)
            })
            .collect();
        // Prefer the shortest root (the canonical include dir over a deep copy).
        roots.sort_by_key(|root| root.as_os_str().len());
        if let Some(root) = roots.into_iter().next() {
            return Some(root);
        }

        // A surviving header can include a deleted sibling through a parent-relative
        // spelling such as `../allocators.h`. Clang searches each include directory
        // using that spelling verbatim, so the ordinary suffix calculation above
        // cannot produce a root. When exactly one usable candidate matches the
        // non-parent suffix, return a synthetic child path beneath its real parent:
        // `parent/.govfuzz-up-0/../allocators.h` then resolves to the recovered blob.
        // apply_repair creates these work-directory-only marker directories before
        // adding them to the compiler search path.
        let path = Path::new(&spelling);
        let parent_count = path
            .components()
            .take_while(|component| matches!(component, std::path::Component::ParentDir))
            .count();
        if parent_count == 0 {
            return None;
        }
        let suffix = path.components().skip(parent_count).collect::<PathBuf>();
        if suffix.as_os_str().is_empty()
            || suffix
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return None;
        }
        let suffix_components = suffix.components().count();
        let mut matches = candidates
            .iter()
            .filter(|candidate| include_candidate_is_host_usable(candidate))
            .filter(|candidate| candidate.ends_with(&suffix))
            .filter_map(|candidate| candidate.ancestors().nth(suffix_components))
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        if matches.len() != 1 {
            return None;
        }
        let mut root = matches.remove(0);
        for level in 0..parent_count {
            root.push(format!(".govfuzz-relative-include-{level}"));
        }
        Some(root)
    }

    /// Resolve an include whose directory layout differs from the checkout to a
    /// unique real header with the same basename. The caller creates a forwarding
    /// header at the requested spelling. Ambiguous basenames are intentionally
    /// refused: choosing one of several unrelated `config.h`/`types.h` files
    /// would silently corrupt the build model.
    pub fn unique_header_for(&self, spelling: &str) -> Option<PathBuf> {
        let spelling = spelling.trim().replace('\\', "/");
        let basename = std::path::Path::new(&spelling).file_name()?.to_str()?;
        let mut candidates = self.header_paths.get(basename)?.clone();
        candidates.retain(|path| include_candidate_is_host_usable(path));
        candidates.sort();
        candidates.dedup();
        (candidates.len() == 1).then(|| candidates.remove(0))
    }

    pub fn lookup_c(&self, name: &str) -> Option<&c_parser::CDeclaration> {
        self.c.get(name).and_then(|v| v.first())
    }

    pub(crate) fn unique_c_type_definition_header(&self, name: &str) -> Option<PathBuf> {
        let mut headers = self.c_type_definition_headers.get(name)?.clone();
        headers.sort();
        headers.dedup();
        (headers.len() == 1).then(|| headers.remove(0))
    }

    /// Resolve an ambiguous type name through the target's own include graph.
    /// Multi-module trees commonly define the same leaf typedef in several
    /// components. The one definition reachable from a unique direct include is
    /// the ABI the target actually uses. Return that direct include so repair
    /// preserves the component's prerequisite include order.
    pub(crate) fn lookup_c_type_definition_header_near_includes(
        &self,
        name: &str,
        source: &str,
    ) -> Option<PathBuf> {
        let definitions = self.c_type_definition_headers.get(name)?;
        let include_paths: Vec<&PathBuf> = quoted_includes(source)
            .into_iter()
            .filter_map(|include| {
                let basename = Path::new(&include).file_name()?.to_str()?;
                self.header_paths.get(basename)
            })
            .filter(|paths| paths.len() == 1)
            .flatten()
            .collect();

        let mut reachable = Vec::new();
        for (index, definition) in definitions.iter().enumerate() {
            for include in &include_paths {
                let mut seen = HashSet::new();
                if self.header_reaches_header(include, definition, 6, &mut seen) {
                    reachable.push((index, (*include).clone()));
                    break;
                }
            }
        }
        reachable.sort_by_key(|(index, _)| *index);
        reachable.dedup_by_key(|(index, _)| *index);
        if reachable.len() == 1 {
            return Some(reachable.remove(0).1);
        }

        // The target may directly include an ambiguous leaf (`p_local.h`) that
        // cannot enter `include_paths`, while another unique include in the same
        // module (`hexen/h2def.h`) still locates the correct sibling definition
        // (`hexen/r_local.h`). Require a unique longest shared path prefix; ties
        // remain unresolved rather than selecting a same-named type arbitrarily.
        let mut scored: Vec<(usize, usize)> = definitions
            .iter()
            .enumerate()
            .map(|(index, header)| {
                let shared = include_paths
                    .iter()
                    .map(|include| {
                        header
                            .components()
                            .zip(include.components())
                            .take_while(|(left, right)| left == right)
                            .count()
                    })
                    .max()
                    .unwrap_or(0);
                (shared, index)
            })
            .collect();
        scored.sort_by_key(|(shared, _)| std::cmp::Reverse(*shared));
        let (best_shared, best_index) = *scored.first()?;
        if best_shared == 0
            || scored
                .get(1)
                .is_some_and(|(shared, _)| *shared == best_shared)
        {
            return None;
        }
        Some(definitions[best_index].clone())
    }

    pub(crate) fn lookup_c_extern_data_type(&self, name: &str) -> Option<&str> {
        self.c_extern_data.get(name).map(String::as_str)
    }

    pub(crate) fn lookup_unique_c_extern_data_header(&self, name: &str) -> Option<(&Path, &str)> {
        let declarations = self.c_extern_data_headers.get(name)?;
        (declarations.len() == 1).then(|| (declarations[0].0.as_path(), declarations[0].1.as_str()))
    }

    pub(crate) fn lookup_c_extern_data_header_near_includes(
        &self,
        name: &str,
        source: &str,
    ) -> Option<(&Path, &str)> {
        let declarations = self.c_extern_data_headers.get(name)?;
        let include_paths: Vec<&PathBuf> = quoted_includes(source)
            .into_iter()
            .filter_map(|include| {
                let basename = Path::new(&include).file_name()?.to_str()?;
                self.header_paths.get(basename)
            })
            .filter(|paths| paths.len() == 1)
            .flatten()
            .collect();

        let mut reachable = Vec::new();
        for (index, (declaration, _)) in declarations.iter().enumerate() {
            for include in &include_paths {
                let mut seen = HashSet::new();
                if self.header_reaches_header(include, declaration, 6, &mut seen) {
                    reachable.push((index, include.as_path()));
                    break;
                }
            }
        }
        reachable.sort_by_key(|(index, _)| *index);
        reachable.dedup_by_key(|(index, _)| *index);
        if reachable.len() == 1 {
            let (index, include) = reachable[0];
            return Some((include, declarations[index].1.as_str()));
        }

        let mut scored: Vec<(usize, usize)> = declarations
            .iter()
            .enumerate()
            .map(|(index, (header, _))| {
                let shared = include_paths
                    .iter()
                    .map(|include| {
                        header
                            .components()
                            .zip(include.components())
                            .take_while(|(left, right)| left == right)
                            .count()
                    })
                    .max()
                    .unwrap_or(0);
                (shared, index)
            })
            .collect();
        scored.sort_by_key(|(shared, _)| std::cmp::Reverse(*shared));
        let (best_shared, best_index) = *scored.first()?;
        if best_shared == 0
            || scored
                .get(1)
                .is_some_and(|(shared, _)| *shared == best_shared)
        {
            return None;
        }
        Some((
            declarations[best_index].0.as_path(),
            declarations[best_index].1.as_str(),
        ))
    }

    fn header_reaches_header(
        &self,
        current: &Path,
        target: &Path,
        depth: usize,
        seen: &mut HashSet<PathBuf>,
    ) -> bool {
        if current == target {
            return true;
        }
        if depth == 0 || !seen.insert(current.to_path_buf()) {
            return false;
        }
        let Ok(source) = crate::source_text::read_source_text(current) else {
            return false;
        };
        quoted_includes(&source).into_iter().any(|include| {
            let local = current
                .parent()
                .map(|parent| parent.join(&include))
                .filter(|path| path.is_file());
            if let Some(local) = local {
                return self.header_reaches_header(&local, target, depth - 1, seen);
            }
            let Some(basename) = Path::new(&include)
                .file_name()
                .and_then(|name| name.to_str())
            else {
                return false;
            };
            self.header_paths.get(basename).is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| self.header_reaches_header(path, target, depth - 1, seen))
            })
        })
    }

    pub(crate) fn lookup_unique_object_macro(&self, name: &str) -> Option<&str> {
        let values = self.c_object_macros.get(name)?;
        (values.len() == 1).then(|| values[0].as_str())
    }

    /// Whether `name` is a struct/union tag or typedef already FULLY defined in a
    /// compiled translation unit (a complete struct in a header, or any
    /// struct/typedef in a `.c`/`.cpp` source). Repair uses this to avoid
    /// force-including a synthesized definition that would collide with the real
    /// one ("typedef/struct redefinition").
    pub fn type_defined_in_compiled_source(&self, name: &str) -> bool {
        self.source_type_names.contains(name)
            || self
                .c_type_defs
                .structs
                .iter()
                .any(|s| s.name == name && s.complete)
    }

    /// Test-only seam: record a type as defined in the compiled source set, so a
    /// unit test can exercise the "definition exists in the tree but is not visible
    /// to the harness TU" path without materializing a real multi-file fixture.
    #[cfg(test)]
    pub(crate) fn insert_source_type_name_for_test(&mut self, name: &str) {
        self.source_type_names.insert(name.to_owned());
    }

    pub fn lookup_cpp(&self, name: &str) -> Option<&cpp_parser::CppDeclaration> {
        let expected_arity = cpp_symbol_param_arity(name);
        let expected_const = cpp_symbol_is_const_method(name);
        let symbol_params = cpp_symbol_param_text(name).unwrap_or("");
        cpp_symbol_lookup_keys(name).into_iter().find_map(|key| {
            let declarations = self.cpp.get(&key)?;
            expected_arity
                .and_then(|arity| {
                    let mut best = None;
                    let mut best_score = 0usize;
                    for declaration in declarations.iter().filter(|declaration| {
                        declaration.param_types.len() == arity
                            && declaration
                                .function_suffix
                                .split_whitespace()
                                .any(|qualifier| qualifier == "const")
                                == expected_const
                    }) {
                        let score = cpp_declaration_param_match_score(declaration, symbol_params);
                        if best.is_none() || score > best_score {
                            best = Some(declaration);
                            best_score = score;
                        }
                    }
                    best
                })
                .or_else(|| declarations.first())
        })
    }

    pub(crate) fn lookup_c_stub_header(&self, symbol: &str) -> Option<&Path> {
        self.c_declaration_headers
            .get(symbol)
            .and_then(|paths| paths.first())
            .map(PathBuf::as_path)
    }

    /// Return a declaration prepared for an out-of-line C++ stub definition.
    /// Header declarations are indexed by their leaf name (`Status`/`ToString`),
    /// while linker diagnostics carry the namespace/class-qualified symbol. The
    /// definition must use that qualified spelling or it emits an unrelated free
    /// function and leaves the original symbol unresolved.
    pub(crate) fn lookup_cpp_stub_declaration(
        &self,
        symbol: &str,
    ) -> Option<cpp_parser::CppDeclaration> {
        let mut declaration = self.lookup_cpp(symbol)?.clone();
        declaration.name = cpp_symbol_qualified_name(symbol)?;
        Some(declaration)
    }

    pub(crate) fn lookup_cpp_stub_header(&self, symbol: &str) -> Option<&Path> {
        cpp_symbol_lookup_keys(symbol).into_iter().find_map(|key| {
            self.cpp_declaration_headers
                .get(&key)
                .and_then(|paths| paths.first())
                .map(PathBuf::as_path)
        })
    }

    /// Whether the C++ class/struct `name` (a leaf class name, no namespace) is
    /// DEFINED only inside a `.cpp` translation unit and is NEVER declared in any
    /// header in the tree. Such a class is invisible to a generated harness (which
    /// includes the project header, not the `.cpp`), so its member functions are not
    /// reachable from an external harness and must be skipped — the C++ analog of
    /// Rust's private-module skip. `false` for a class with any header declaration
    /// (the normal "declared in a header, methods defined out-of-line in a .cpp"
    /// case) and for a free function's namespace (never a recorded class name).
    pub fn cpp_class_defined_only_in_translation_unit(&self, name: &str) -> bool {
        self.cpp_source_class_names.contains(name) && !self.cpp_header_class_names.contains(name)
    }

    /// Whether a C++ type LEAF name (no namespace/template/cv/ref decoration) is
    /// DEFINED somewhere in the scanned tree — a class/struct declared in a header
    /// or defined in a `.cpp`, or a struct/typedef in any compiled source.
    /// Deliberately does NOT consult `cpp_type_names`, which records merely
    /// REFERENCED type leaves (so an undefined external `CString` used only as a
    /// parameter/return type would wrongly read as "defined"). Used to detect a
    /// target return/receiver type that is undefined-in-tree BEFORE a doomed
    /// compile (external framework types like MFC `CString`/`CWnd`).
    pub fn cpp_type_name_defined_in_tree(&self, leaf: &str) -> bool {
        self.cpp_header_class_names.contains(leaf)
            || self.cpp_source_class_names.contains(leaf)
            || self.type_defined_in_compiled_source(leaf)
            || self
                .cpp_type_defs
                .enums
                .iter()
                .any(|definition| definition.name == leaf)
            || self
                .cpp_type_defs
                .typedefs
                .iter()
                .any(|definition| definition.name == leaf)
            || self
                .cpp_type_defs
                .structs
                .iter()
                .any(|definition| definition.name == leaf)
    }

    pub fn lookup_c_definition_source(&self, name: &str) -> Option<&Path> {
        self.lookup_c_definition_source_impl(name, None)
    }

    pub fn lookup_c_definition_source_near(&self, name: &str, reference: &Path) -> Option<&Path> {
        self.lookup_c_definition_source_impl(name, Some(reference))
    }

    fn lookup_c_definition_source_impl(
        &self,
        name: &str,
        reference: Option<&Path>,
    ) -> Option<&Path> {
        self.c_definitions
            .get(name)
            .and_then(|paths| {
                paths
                    .iter()
                    .filter(|path| {
                        !crate::generate_harness::source_path_is_foreign_platform(path)
                            && !crate::generate_harness::source_path_has_unconditional_foreign_platform_include(path)
                            && !crate::generate_harness::source_path_has_missing_translation_unit_include(path)
                            && !self.source_has_unavailable_unconditional_include(path)
                    })
                    .min_by_key(|path| {
                        definition_source_repair_score_near(path, reference)
                    })
            })
            .map(PathBuf::as_path)
    }

    pub fn lookup_cpp_definition_source(&self, name: &str) -> Option<&Path> {
        self.lookup_cpp_definition_source_impl(name, None)
    }

    pub fn lookup_cpp_definition_source_near(&self, name: &str, reference: &Path) -> Option<&Path> {
        self.lookup_cpp_definition_source_impl(name, Some(reference))
    }

    fn lookup_cpp_definition_source_impl(
        &self,
        name: &str,
        reference: Option<&Path>,
    ) -> Option<&Path> {
        let mut candidates = Vec::new();
        for key in cpp_symbol_lookup_keys(name) {
            if let Some(paths) = self.cpp_definitions.get(&key) {
                candidates.extend(paths.iter());
            }
        }
        candidates
            .into_iter()
            .filter(|path| {
                !crate::generate_harness::source_path_is_foreign_platform(path)
                    && !crate::generate_harness::source_path_has_unconditional_foreign_platform_include(path)
                    && !crate::generate_harness::source_path_has_missing_translation_unit_include(
                        path,
                    )
                    && !self.source_has_unavailable_unconditional_include(path)
            })
            .min_by_key(|path| definition_source_repair_score_near(path, reference))
            .map(PathBuf::as_path)
    }

    pub fn lookup_definition_source_near(&self, name: &str, reference: &Path) -> Option<&Path> {
        self.lookup_c_definition_source_near(name, reference)
            .or_else(|| self.lookup_cpp_definition_source_near(name, reference))
    }

    fn source_has_unavailable_unconditional_include(&self, path: &Path) -> bool {
        let Ok(source) = crate::source_text::read_source_text(path) else {
            return true;
        };
        let mut conditional_depth = 0usize;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#if") {
                conditional_depth += 1;
                continue;
            }
            if trimmed.starts_with("#endif") {
                conditional_depth = conditional_depth.saturating_sub(1);
                continue;
            }
            if conditional_depth != 0 || !trimmed.starts_with("#include") {
                continue;
            }
            let spelling = trimmed["#include".len()..]
                .trim()
                .strip_prefix(['<', '"'])
                .and_then(|rest| rest.split(['>', '"']).next())
                .unwrap_or("")
                .trim();
            if spelling.is_empty() || self.include_spelling_is_available(spelling, path) {
                continue;
            }
            return true;
        }
        false
    }

    fn include_spelling_is_available(&self, spelling: &str, source_path: &Path) -> bool {
        const COMPILER_BUILTIN_HEADERS: &[&str] = &[
            "float.h",
            "iso646.h",
            "stdalign.h",
            "stdarg.h",
            "stdatomic.h",
            "stdbool.h",
            "stddef.h",
            "tgmath.h",
            "unwind.h",
            "varargs.h",
        ];
        if c_stub_gen::is_config_header(spelling)
            || (!spelling.contains('/') && !spelling.contains('.'))
            || COMPILER_BUILTIN_HEADERS.contains(&spelling)
        {
            return true;
        }
        let include_path = Path::new(spelling);
        if include_path.is_absolute() && include_path.is_file() {
            return true;
        }
        if source_path
            .parent()
            .is_some_and(|parent| parent.join(include_path).is_file())
        {
            return true;
        }
        let Some(basename) = include_path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        if self.header_paths.contains_key(basename) {
            return true;
        }
        [
            Path::new("/usr/include").join(include_path),
            Path::new("/usr/local/include").join(include_path),
            Path::new("/usr/include/x86_64-linux-gnu").join(include_path),
            Path::new("/opt/homebrew/include").join(include_path),
        ]
        .iter()
        .any(|candidate| candidate.is_file())
    }

    pub fn lookup_ada_package_ops(&self, unit: &str) -> Vec<stub_gen::StubOp> {
        self.ada_package_ops
            .get(&ada_unit_key(unit))
            .cloned()
            .unwrap_or_default()
    }

    pub fn has_ada_package_body(&self, unit: &str) -> bool {
        self.ada_package_bodies.contains(&ada_unit_key(unit))
    }

    fn index_ada_package_ops(&mut self, source_path: &Path, source: &str, is_body_source: bool) {
        let Ok(ast) = ada_parser::reconcile::build_structural_ast(source, None, source_path) else {
            return;
        };
        if is_body_source {
            for package in &ast.packages {
                self.ada_package_bodies.insert(ada_unit_key(&package.name));
            }
        }
        for subprogram in &ast.subprograms {
            if !matches!(
                &subprogram.kind,
                ada_parser::ast::SubprogramKind::Procedure
                    | ada_parser::ast::SubprogramKind::Function
            ) {
                continue;
            }
            if !is_body_source && subprogram.visibility != ada_parser::ast::Visibility::Public {
                continue;
            }
            // An expression function declared in a package spec already has its
            // body in that spec. Re-emitting it in a synthesized package body is
            // illegal ("body conflicts with expression function").
            if !is_body_source && subprogram.body_span.is_some() {
                continue;
            }
            // A renaming declaration (`function Image ... renames Value`) is a
            // complete implementation in the spec and must not be duplicated in
            // a synthesized package body.
            if !is_body_source && ada_subprogram_decl_is_renaming(source, subprogram) {
                continue;
            }
            let ada_parser::ast::SubprogramOwner::Package(package_id) = &subprogram.owner else {
                continue;
            };
            let Some(package) = ast
                .packages
                .iter()
                .find(|package| package.id == *package_id)
            else {
                continue;
            };
            let op = stub_op_from_ada_subprogram(subprogram);
            let ops = self
                .ada_package_ops
                .entry(ada_unit_key(&package.name))
                .or_default();
            if !ops.contains(&op) {
                ops.push(op);
            }
        }
    }

    fn index_cpp_definition(&mut self, function: &cpp_parser::CppFunction, source_path: &Path) {
        let path = source_path.to_path_buf();
        self.cpp_definitions
            .entry(function.name.clone())
            .or_default()
            .push(path.clone());
        if !function.qualifier_path.is_empty() {
            let qualified = format!("{}::{}", function.qualifier_path.join("::"), function.name);
            self.cpp_definitions
                .entry(qualified)
                .or_default()
                .push(path);
        }
    }

    fn index_cpp_definition_headers(
        &mut self,
        cpp_sources: &[(PathBuf, Vec<String>)],
        cpp_headers: &[(PathBuf, Vec<cpp_parser::CppFunction>)],
    ) {
        for (source_path, includes) in cpp_sources {
            for include in includes {
                for (header_path, functions) in cpp_headers {
                    if !header_matches_include(source_path, include, header_path) {
                        continue;
                    }
                    for function in functions {
                        self.index_cpp_definition(function, source_path);
                    }
                }
            }
        }
    }
}

fn c_extern_data_declarations(source: &str) -> Vec<(String, String)> {
    let mut declarations = Vec::new();
    for raw_line in source.lines() {
        let line = raw_line.split_once("//").map_or(raw_line, |(code, _)| code);
        // Headers routinely annotate extern objects after the semicolon. Keep
        // the declaration and discard the trailing C block comment; otherwise
        // `extern Type state; /* note */` misses `strip_suffix(';')` and a later
        // unresolved data reference is wrongly synthesized as a function.
        let line = line.split_once("/*").map_or(line, |(code, _)| code);
        let Some((extern_pos, _)) = line.match_indices("extern").find(|(pos, word)| {
            let before = pos
                .checked_sub(1)
                .and_then(|index| line.as_bytes().get(index))
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
            let after = line
                .as_bytes()
                .get(pos + word.len())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
            before && after
        }) else {
            continue;
        };
        let Some(statement) = line[extern_pos + "extern".len()..]
            .trim()
            .strip_suffix(';')
            .map(str::trim)
        else {
            continue;
        };
        if let Some(captures) = extern_function_pointer().captures(statement) {
            declarations.push((
                captures[2].to_owned(),
                format!("{} (*){}", captures[1].trim(), captures[3].trim()),
            ));
            continue;
        }
        if statement.contains(['(', ',', '=']) {
            continue;
        }
        let (declarator, array_suffix) = statement.find('[').map_or((statement, ""), |start| {
            (statement[..start].trim_end(), statement[start..].trim())
        });
        if !array_suffix.is_empty()
            && (!array_suffix.ends_with(']')
                || array_suffix.bytes().filter(|byte| *byte == b'[').count()
                    != array_suffix.bytes().filter(|byte| *byte == b']').count())
        {
            continue;
        }
        let bytes = declarator.as_bytes();
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
        let name = &declarator[start..end];
        let base_type = declarator[..start].trim();
        let data_type = if array_suffix.is_empty() {
            base_type.to_owned()
        } else {
            format!("{base_type} {array_suffix}")
        };
        if name.is_empty()
            || base_type.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            continue;
        }
        declarations.push((name.to_owned(), data_type));
    }
    declarations
}

fn extern_function_pointer() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^(.+?)\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)(\s*\([^;]*\))$")
            .expect("extern function-pointer regex")
    })
}

fn cpp_symbol_is_const_method(symbol: &str) -> bool {
    symbol
        .rsplit_once(')')
        .is_some_and(|(_, suffix)| suffix.split_whitespace().any(|part| part == "const"))
}

fn cpp_declaration_param_match_score(
    declaration: &cpp_parser::CppDeclaration,
    symbol_params: &str,
) -> usize {
    let symbol_tokens = symbol_params
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect::<std::collections::HashSet<_>>();
    declaration
        .param_types
        .iter()
        .flat_map(|param| param.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'))
        .filter(|token| {
            token.len() >= 3
                && !matches!(
                    *token,
                    "const" | "volatile" | "struct" | "class" | "unsigned" | "signed" | "std"
                )
        })
        .filter(|token| symbol_tokens.contains(token))
        .count()
}

fn quoted_includes(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix("#include")?.trim_start();
            let quoted = rest.strip_prefix('"')?;
            let end = quoted.find('"')?;
            Some(quoted[..end].to_owned())
        })
        .collect()
}

fn header_matches_include(source_path: &Path, include: &str, header_path: &Path) -> bool {
    if source_path
        .parent()
        .is_some_and(|parent| parent.join(include) == header_path)
    {
        return true;
    }
    let normalized_header = header_path.to_string_lossy().replace('\\', "/");
    normalized_header.ends_with(include)
}

/// The base identifier of a C++ type spelling: drop cv/ref/pointer noise and
/// template arguments, then take the segment after the last `::`
/// (`const YAML::EMITTER_MANIP &` -> `EMITTER_MANIP`). Returns None for
/// non-identifier shapes.
fn cpp_type_leaf_identifier(ty: &str) -> Option<String> {
    let base = ty.split('<').next().unwrap_or(ty).replace(['&', '*'], " ");
    let last_word = base.split_whitespace().rfind(|w| {
        !matches!(
            *w,
            "const" | "volatile" | "struct" | "class" | "enum" | "typename"
        )
    })?;
    let leaf = last_word.rsplit("::").next().unwrap_or(last_word);
    if leaf.is_empty()
        || !leaf
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !leaf.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(leaf.to_owned())
}

fn cpp_source_uses_module_unit(source: &str) -> bool {
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        return trimmed == "module;"
            || trimmed.starts_with("module ")
            || trimmed.starts_with("export module ");
    }
    false
}

fn definition_source_repair_score(path: &Path) -> (u8, usize, String) {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let is_test = path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|s| matches!(s, "test" | "tests" | "testing"))
    }) || file_name.contains("test");
    let tier = if is_test {
        2
    } else if normalized.contains("/src/") {
        0
    } else {
        1
    };
    (tier, normalized.len(), normalized)
}

fn definition_source_repair_score_near(
    path: &Path,
    reference: Option<&Path>,
) -> (u8, std::cmp::Reverse<usize>, usize, String) {
    let (tier, length, normalized) = definition_source_repair_score(path);
    let shared_components = reference.map_or(0, |reference| {
        path.components()
            .zip(reference.components())
            .take_while(|(left, right)| left == right)
            .count()
    });
    (
        tier,
        std::cmp::Reverse(shared_components),
        length,
        normalized,
    )
}

fn cpp_symbol_lookup_keys(symbol: &str) -> Vec<String> {
    let Some(qualified) = cpp_symbol_qualified_name(symbol) else {
        return Vec::new();
    };
    let mut keys = vec![qualified.clone()];
    if let Some(simple) = qualified.rsplit("::").next() {
        if simple != qualified {
            keys.push(simple.to_owned());
        }
    }
    keys
}

fn cpp_symbol_qualified_name(symbol: &str) -> Option<String> {
    let before_params = symbol.split('(').next()?.replace("[abi:cxx11]", "");
    let stripped_templates = strip_cpp_template_args(&before_params);
    stripped_templates
        .split_whitespace()
        .last()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn cpp_symbol_param_arity(symbol: &str) -> Option<usize> {
    let params = cpp_symbol_param_text(symbol)?;
    if params.is_empty() || params == "void" {
        return Some(0);
    }
    let mut nesting = 0usize;
    let mut arity = 1usize;
    for byte in params.bytes() {
        match byte {
            b'<' | b'(' | b'[' | b'{' => nesting += 1,
            b'>' | b')' | b']' | b'}' => nesting = nesting.saturating_sub(1),
            b',' if nesting == 0 => arity += 1,
            _ => {}
        }
    }
    Some(arity)
}

fn cpp_symbol_param_text(symbol: &str) -> Option<&str> {
    let bytes = symbol.as_bytes();
    let mut depth = 0usize;
    let mut open = None;
    for index in (0..bytes.len()).rev() {
        match bytes[index] {
            b')' => depth += 1,
            b'(' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    open = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    Some(symbol.get(open? + 1..symbol.rfind(')')?)?.trim())
}

fn stub_op_from_ada_subprogram(subprogram: &ada_parser::ast::Subprogram) -> stub_gen::StubOp {
    stub_gen::StubOp {
        name: ada_display_name(&subprogram.name),
        kind: match &subprogram.kind {
            ada_parser::ast::SubprogramKind::Function => stub_gen::StubOpKind::Function,
            _ => stub_gen::StubOpKind::Procedure,
        },
        return_type: subprogram
            .return_type
            .as_ref()
            .map(ada_type_ref_display_name),
        params: subprogram
            .params
            .iter()
            .map(|param| stub_gen::StubParam {
                name: ada_display_name(&param.name),
                mode: ada_param_mode_display_name(param),
                type_name: ada_type_ref_display_name(&param.type_ref),
                default: param.default.as_ref().map(|expr| expr.0.clone()),
            })
            .collect(),
    }
}

fn ada_param_mode_display_name(param: &ada_parser::ast::Parameter) -> Option<String> {
    match &param.mode {
        ada_parser::ast::ParamMode::In => None,
        ada_parser::ast::ParamMode::Out => Some("out".to_owned()),
        ada_parser::ast::ParamMode::InOut => Some("in out".to_owned()),
        ada_parser::ast::ParamMode::AccessMode => Some(
            if param
                .type_ref
                .aspects
                .0
                .iter()
                .any(|aspect| aspect == "not_null_access")
            {
                "not null access"
            } else {
                "access"
            }
            .to_owned(),
        ),
    }
}

fn ada_subprogram_decl_is_renaming(source: &str, subprogram: &ada_parser::ast::Subprogram) -> bool {
    let start = subprogram.decl_span.start_byte as usize;
    let end = subprogram.decl_span.end_byte as usize;
    source.get(start..end).is_some_and(|decl| {
        decl.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .any(|word| word.eq_ignore_ascii_case("renames"))
    })
}

fn ada_type_ref_display_name(type_ref: &ada_parser::ast::TypeRef) -> String {
    if type_ref.name_path.is_empty() && !type_ref.constraints.0.trim().is_empty() {
        return type_ref.constraints.0.trim().to_owned();
    }
    type_ref
        .name_path
        .iter()
        .map(|part| ada_display_name(part))
        .collect::<Vec<_>>()
        .join(".")
}

fn ada_unit_key(unit: &str) -> String {
    unit.replace('-', ".").to_ascii_lowercase()
}

fn ada_spec_declares_symbol(path: &Path, unit: &str, symbol: &str) -> bool {
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return false;
    };
    let Ok(ast) = ada_parser::reconcile::build_structural_ast(&source, None, path) else {
        return false;
    };
    let unit_key = ada_unit_key(unit);
    let package_ids = ast
        .packages
        .iter()
        .filter(|package| ada_unit_key(&package.name) == unit_key)
        .map(|package| package.id)
        .collect::<HashSet<_>>();
    if package_ids.is_empty() {
        return false;
    }
    if ast.subprograms.iter().any(|subprogram| {
        subprogram.name.eq_ignore_ascii_case(symbol)
            && matches!(
                subprogram.owner,
                ada_parser::ast::SubprogramOwner::Package(id) if package_ids.contains(&id)
            )
            && subprogram.visibility == ada_parser::ast::Visibility::Public
    }) {
        return true;
    }
    if ast.constants.iter().any(|constant| {
        constant.name.eq_ignore_ascii_case(symbol)
            && matches!(
                constant.owner,
                ada_parser::ast::TypeOwner::Package(id) if package_ids.contains(&id)
            )
            && constant.visibility == ada_parser::ast::Visibility::Public
    }) {
        return true;
    }
    ast.types.iter().any(|data_type| {
        let owned_here = matches!(
            data_type.owner,
            ada_parser::ast::TypeOwner::Package(id) if package_ids.contains(&id)
        );
        owned_here
            && (data_type
                .name_path
                .last()
                .is_some_and(|name| name.eq_ignore_ascii_case(symbol))
                || matches!(
                    &data_type.kind,
                    ada_parser::ast::TypeKind::Enum(literals)
                        if literals.iter().any(|literal| literal.eq_ignore_ascii_case(symbol))
                ))
    })
}

/// Strip GNAT's platform / separate-body filename suffix from a file stem so the
/// implementation is keyed under its real unit: `gnatcoll-os-fs-set...__unix`
/// (file `..__unix.adb`) belongs to unit `gnatcoll-os-fs-set...`. `__` never
/// appears inside a legal Ada identifier, so splitting on it is unambiguous.
fn strip_ada_platform_suffix(stem: &str) -> &str {
    match stem.split_once("__") {
        Some((base, _)) => base,
        None => stem,
    }
}

/// Names of file-scope (global) variable DEFINITIONS in C/C++ source — a
/// non-`extern`, non-`static`, non-function top-level `<type> <name>[ = ...];`
/// (PX4's `__EXPORT rc_decode_buf_t rc_decode_buf;`). A cross-file reference to
/// such a shared global is otherwise blind-stubbed (leaving the symbol undefined
/// at link); indexing the definition lets the repair loop AddSource the real
/// defining file. Conservative line scan: column-0 only (file scope), no `(`/`{`
/// (excludes prototypes, definitions, calls, aggregates), `;`-terminated,
/// excluding linkage/keyword-only forms.
fn extract_global_var_definitions(source: &str) -> Vec<String> {
    const SKIP_FIRST: &[&str] = &[
        "extern",
        "static",
        "typedef",
        "using",
        "namespace",
        "template",
        "return",
        "class",
        "struct",
        "enum",
        "union",
        "if",
        "else",
        "for",
        "while",
        "switch",
        "case",
        "do",
        "goto",
        "friend",
        "public",
        "private",
        "protected",
    ];
    let mut out = Vec::new();
    for line in source.lines() {
        // File scope: a definition starts at column 0 (not indented inside a
        // function/struct, not a preprocessor/comment line).
        if line.is_empty() || line.starts_with([' ', '\t', '#', '/', '*', '}', '{', ')']) {
            continue;
        }
        let l = line.trim_end();
        if !l.ends_with(';') || l.contains('(') || l.contains('{') {
            continue;
        }
        // Isolate the declarator (drop any initializer).
        let decl = l
            .split('=')
            .next()
            .unwrap_or(l)
            .trim_end_matches(';')
            .trim();
        let first = decl.split_whitespace().next().unwrap_or("");
        if first.is_empty() || SKIP_FIRST.contains(&first) {
            continue;
        }
        // Need at least a type token + a name token.
        if decl.split_whitespace().count() < 2 {
            continue;
        }
        // The variable name is the last identifier (strip pointer/array/ref noise).
        let last = decl
            .rsplit(|c: char| c.is_whitespace() || c == '*' || c == '&')
            .next()
            .unwrap_or("");
        let name: String = last
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.len() > 1
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            out.push(name);
        }
    }
    out
}

fn ada_display_name(name: &str) -> String {
    name.split('.')
        .map(|part| {
            part.split('_')
                .map(|segment| {
                    let mut chars = segment.chars();
                    let Some(first) = chars.next() else {
                        return String::new();
                    };
                    let mut out = first.to_ascii_uppercase().to_string();
                    out.push_str(&chars.as_str().to_ascii_lowercase());
                    out
                })
                .collect::<Vec<_>>()
                .join("_")
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn strip_cpp_template_args(input: &str) -> String {
    let mut out = String::new();
    let mut depth = 0_u32;
    for ch in input.chars() {
        match ch {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Minimal in-tree walker; sweeps source files only, applies the same
/// directory-exclusion list as scan.rs (govfuzz_work, target, etc.).
fn walkdir_lite(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    if dir.is_file() {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if is_excluded_dir(&path) {
                continue;
            }
            walk(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Drop every struct from `defs` that is not "flat POD" — i.e. keep only
/// complete structs whose every field resolves (within `defs`) to a scalar or
/// enum. This admits the military strong-typedef wrapper idiom (a struct around
/// one scalar id) and small POD packets into the tree-wide fallback, while
/// excluding structs with pointer/union/nested/unresolved fields whose harness
/// could only attempt-and-fail to build.
fn retain_flat_pod_structs(defs: &mut c_parser::CTypeDefs) {
    let snapshot = defs.clone();
    let enum_names: HashSet<&str> = snapshot.enums.iter().map(|e| e.name.as_str()).collect();
    defs.structs
        .retain(|s| struct_is_flat_pod(s, &snapshot, &enum_names));
}

fn object_macro_definitions(source: &str) -> Vec<(String, String)> {
    let mut definitions = Vec::new();
    let mut logical_lines = Vec::new();
    let mut logical = String::new();
    for raw in source.lines() {
        if logical.is_empty() {
            logical.push_str(raw);
        } else {
            logical.push_str(raw.trim_start());
        }
        if logical.trim_end().ends_with('\\') {
            let trimmed_len = logical.trim_end().len();
            logical.truncate(trimmed_len - 1);
            logical.truncate(logical.trim_end().len());
            logical.push(' ');
            continue;
        }
        logical_lines.push(std::mem::take(&mut logical));
    }
    if !logical.is_empty() {
        logical_lines.push(logical);
    }

    for raw in logical_lines {
        let line = raw.trim_start();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        if !rest.chars().next().is_some_and(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        let name_len = rest
            .char_indices()
            .take_while(|(index, ch)| {
                (*index == 0 && (ch.is_ascii_alphabetic() || *ch == '_'))
                    || (*index > 0 && (ch.is_ascii_alphanumeric() || *ch == '_'))
            })
            .map(|(index, ch)| index + ch.len_utf8())
            .last()
            .unwrap_or(0);
        if name_len == 0 || rest[name_len..].starts_with('(') {
            continue;
        }
        let value = rest[name_len..].trim();
        if
        // Unconfigured Autoconf/CMake templates are not C expressions.
        // Re-emitting `@PROJECT_VERSION_MAJOR@` as an "exact" value turns a
        // recoverable config gap into `expected expression` in every TU.
        value.contains('@') || value.contains("${") {
            continue;
        }
        definitions.push((rest[..name_len].to_owned(), value.to_owned()));
    }
    definitions
}

fn struct_is_flat_pod(
    def: &c_parser::CStructDef,
    defs: &c_parser::CTypeDefs,
    enum_names: &HashSet<&str>,
) -> bool {
    def.complete
        && !def.fields.is_empty()
        && def
            .fields
            .iter()
            .all(|field| field_type_is_pod(&field.c_type, defs, enum_names))
}

fn field_type_is_pod(
    spelling: &str,
    defs: &c_parser::CTypeDefs,
    enum_names: &HashSet<&str>,
) -> bool {
    // A pointer field is a graph edge, not a value to fuzz-fill — not flat POD.
    if spelling.contains('*') {
        return false;
    }
    // Strip an array suffix and cv-qualifiers to get the element/base spelling.
    let without_array = spelling.split('[').next().unwrap_or(spelling);
    let base = without_array
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile"))
        .collect::<Vec<_>>()
        .join(" ");
    if base.is_empty() {
        return false;
    }
    if crate::auto::repair::is_concrete_c_scalar_spelling(&base) {
        return true;
    }
    if base.starts_with("union ") {
        return false;
    }
    if base.starts_with("enum ") {
        return true;
    }
    let tag = base.strip_prefix("struct ").map(str::trim).unwrap_or(&base);
    if enum_names.contains(tag) {
        return true;
    }
    // A typedef/named type that bottoms out in a concrete scalar (the wrapper
    // idiom's `CFE_SB_MsgId_Atom_t` -> uint32). Nested structs are deliberately
    // not followed: a field that is itself a struct keeps the parent out of the
    // flat-POD set (conservative — avoids deep object graphs).
    crate::auto::repair::resolve_tree_typedef_chain(tag, &[defs]).is_some()
}

fn is_excluded_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        // `.govfuzz-build` = build_probe::PROBE_DIR (the --probe-build output).
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn extracts_global_variable_definitions_not_other_constructs() {
        let src = "\
#include \"common_rc.h\"
__EXPORT rc_decode_buf_t rc_decode_buf;
static uint8_t _rxlen;
extern int shared_handle;
uint8_t crc8_dvb_s2(uint8_t crc, uint8_t a) {
    int local = 0;
    return crc;
}
int g_counter = 0;
typedef struct foo bar;
";
        let names = extract_global_var_definitions(src);
        assert!(names.contains(&"rc_decode_buf".to_owned()), "{names:?}");
        assert!(names.contains(&"g_counter".to_owned()), "{names:?}");
        // static (file-local), extern (declaration), function bodies, locals,
        // typedefs, and preprocessor lines must NOT be indexed as definitions.
        assert!(!names.contains(&"_rxlen".to_owned()));
        assert!(!names.contains(&"shared_handle".to_owned()));
        assert!(!names.contains(&"local".to_owned()));
        assert!(!names.contains(&"crc".to_owned()));
        assert!(!names.contains(&"bar".to_owned()));
    }

    #[test]
    fn extracts_libcbor_data_object_allocator_pointers() {
        // #27: libcbor's allocators.c DEFINES the function-pointer-typedef DATA
        // objects `_cbor_malloc`/`_cbor_realloc`/`_cbor_free` (referenced as externs
        // from the rest of the library). They must be indexed as global-variable
        // DEFINITIONS so a referencing TU resolves them to AddSource(allocators.c)
        // instead of blind-stubbing them as weak NULL FUNCTIONS (wrong symbol kind).
        let src = "\
#include \"cbor/common.h\"
_cbor_malloc_t _cbor_malloc = malloc;
_cbor_realloc_t _cbor_realloc = realloc;
CBOR_EXPORT _cbor_free_t _cbor_free = free;
";
        let names = extract_global_var_definitions(src);
        assert!(names.contains(&"_cbor_malloc".to_owned()), "{names:?}");
        assert!(names.contains(&"_cbor_realloc".to_owned()), "{names:?}");
        assert!(names.contains(&"_cbor_free".to_owned()), "{names:?}");
    }

    fn tmpdir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-declidx-{nonce}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn resolves_cross_dir_ada_unit_to_its_real_source() {
        // adamant pattern: the scan path (`types/`) has a unit that `with`s
        // `Serializer_Types`, whose real source lives in a sibling dir
        // (`core/`). The cross-tree index must resolve the unit to that source
        // file so repair can add it instead of stubbing.
        let root = tmpdir();
        let scan = root.join("types");
        let core = root.join("core");
        fs::create_dir_all(&scan).unwrap();
        fs::create_dir_all(&core).unwrap();
        fs::write(
            scan.join("widget.ads"),
            "with Serializer_Types;\npackage Widget is\n   function F return Integer;\nend Widget;\n",
        )
        .unwrap();
        fs::write(
            core.join("serializer_types.ads"),
            "package Serializer_Types is\n   type Serialization_Status is (Success, Failure);\nend Serializer_Types;\n",
        )
        .unwrap();
        fs::write(
            core.join("serializer_types.adb"),
            "package body Serializer_Types is\nend Serializer_Types;\n",
        )
        .unwrap();

        // parse_root = scan dir; header_root = project root (git boundary).
        let idx = DeclarationIndex::build_indexed(&scan, &root).unwrap();

        let files = idx.ada_unit_source_files("Serializer_Types");
        assert_eq!(files.len(), 2, "spec + body resolved: {files:?}");
        assert!(
            files[0].file_name().unwrap() == "serializer_types.ads",
            "spec first: {files:?}"
        );
        assert!(files[1].file_name().unwrap() == "serializer_types.adb");
        // A child-unit filename convention resolves too.
        assert!(
            idx.ada_unit_source_files("Keccak.Arch").is_empty(),
            "absent unit yields empty"
        );
    }

    #[test]
    fn ada_stub_ops_preserve_qualified_classwide_and_anonymous_access_types() {
        let root = tmpdir();
        fs::write(
            root.join("callbacks.ads"),
            "package Callbacks is\n\
             \x20  function Now return Ada.Calendar.Time;\n\
             \x20  procedure Parse\n\
             \x20    (Parser : Argument_Parser'Class;\n\
             \x20     Put_Parts : not null access procedure (Text : String));\n\
             \x20  function Existing return Integer is (1);\n\
             end Callbacks;\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let ops = idx.lookup_ada_package_ops("Callbacks");
        let now = ops.iter().find(|op| op.name == "Now").expect("Now op");
        assert_eq!(now.return_type.as_deref(), Some("Ada.Calendar.Time"));
        let parse = ops.iter().find(|op| op.name == "Parse").expect("Parse op");
        assert_eq!(parse.params[0].type_name, "Argument_Parser'class");
        assert_eq!(parse.params[1].mode.as_deref(), Some("not null access"));
        assert_eq!(parse.params[1].type_name, "procedure (Text : String)");
        assert!(
            ops.iter().all(|op| op.name != "Existing"),
            "expression function must not be emitted in a package body: {ops:?}"
        );
    }

    #[test]
    fn ada_stub_ops_continue_after_generic_instantiation() {
        let root = tmpdir();
        fs::write(
            root.join("unicode-ces.ads"),
            "with Ada.Unchecked_Deallocation;\n\
             package Unicode.CES is\n\
             \x20  subtype Byte_Sequence is String;\n\
             \x20  type Byte_Sequence_Access is access all Byte_Sequence;\n\
             \x20  procedure Free is new Ada.Unchecked_Deallocation\n\
             \x20    (Byte_Sequence, Byte_Sequence_Access);\n\
             \x20  procedure Read_Bom (Str : String; Len : out Natural);\n\
             \x20  function Write_Bom (BOM : Integer) return String;\n\
             \x20  function Index_From_Offset\n\
             \x20    (Str : Byte_Sequence; Offset : Natural) return Integer;\n\
             end Unicode.CES;\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let ops = idx.lookup_ada_package_ops("Unicode.CES");
        let names = ops.iter().map(|op| op.name.as_str()).collect::<Vec<_>>();
        assert!(names.contains(&"Read_Bom"), "{names:?}");
        assert!(names.contains(&"Write_Bom"), "{names:?}");
        assert!(names.contains(&"Index_From_Offset"), "{names:?}");
        assert!(
            !names.contains(&"Free"),
            "generic instance needs no body: {names:?}"
        );
    }

    #[test]
    fn ada_stub_ops_preserve_defaults_and_skip_renamings() {
        let root = tmpdir();
        fs::write(
            root.join("defaults.ads"),
            "package Defaults is\n\
             \x20  procedure Read (Enabled : Boolean := True);\n\
             \x20  function Value return String;\n\
             \x20  function Image return String renames Value;\n\
             end Defaults;\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let ops = idx.lookup_ada_package_ops("Defaults");
        let read = ops.iter().find(|op| op.name == "Read").expect("Read op");
        assert_eq!(read.params[0].default.as_deref(), Some("True"));
        assert!(ops.iter().any(|op| op.name == "Value"), "{ops:?}");
        assert!(ops.iter().all(|op| op.name != "Image"), "{ops:?}");
    }

    #[test]
    fn ada_unit_in_gpr_scenario_excluded_dir_is_not_resolvable() {
        // Regression: the cross-dir unit recovery must not re-add a unit the
        // default GPR scenario excludes (libkeccak's SIMD `src/x86_64/AVX2`),
        // which would defeat scenario-gating and resurrect `-mavx2` failures.
        let root = tmpdir();
        let common = root.join("src/common");
        let avx2 = root.join("src/x86_64/AVX2");
        fs::create_dir_all(&common).unwrap();
        fs::create_dir_all(&avx2).unwrap();
        fs::write(
            common.join("keccak.ads"),
            "package Keccak is\nend Keccak;\n",
        )
        .unwrap();
        fs::write(
            avx2.join("keccak-arch-avx2.ads"),
            "package Keccak.Arch.AVX2 is\nend Keccak.Arch.AVX2;\n",
        )
        .unwrap();
        fs::write(
            root.join("p.gpr"),
            "project P is\n\
             \x20  SIMD : T := external (\"SIMD\", \"none\");\n\
             \x20  D := (\"src/common\");\n\
             \x20  case SIMD is\n\
             \x20     when \"none\" => D := D & (\"src/common\");\n\
             \x20     when \"AVX2\" => D := D & (\"src/x86_64/AVX2\");\n\
             \x20  end case;\n\
             \x20  for Source_Dirs use D;\n\
             end P;\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.ada_unit_source_files("Keccak.Arch.AVX2").is_empty(),
            "a scenario-excluded unit must not be resolvable for re-adding"
        );
        // A non-excluded unit still resolves.
        assert!(!idx.ada_unit_source_files("Keccak").is_empty());
    }

    #[test]
    fn resolves_ada_child_unit_by_hyphenated_filename() {
        let root = tmpdir();
        fs::write(
            root.join("keccak-arch.ads"),
            "package Keccak.Arch is\nend Keccak.Arch;\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        let files = idx.ada_unit_source_files("Keccak.Arch");
        assert_eq!(files.len(), 1, "{files:?}");
        assert!(files[0].file_name().unwrap() == "keccak-arch.ads");
    }

    #[test]
    fn resolves_ada_platform_suffixed_unit_to_base_unit() {
        // GNAT platform-suffixed bodies (`unit__unix.adb`) must be keyed under the
        // base unit so repair finds the real implementation instead of stubbing it
        // (gnatcoll gnatcoll-os-fs-set_close_on_exec__unix.adb).
        let root = tmpdir();
        fs::write(
            root.join("gnatcoll-os-fs-set_close_on_exec__unix.ads"),
            "package Gnatcoll.OS.FS.Set_Close_On_Exec is\nend;\n",
        )
        .unwrap();
        fs::write(
            root.join("gnatcoll-os-fs-set_close_on_exec__unix.adb"),
            "package body Gnatcoll.OS.FS.Set_Close_On_Exec is\nend;\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        let files = idx.ada_unit_source_files("Gnatcoll.OS.FS.Set_Close_On_Exec");
        assert_eq!(files.len(), 2, "{files:?}");
    }

    #[test]
    fn indexes_c_type_defs_from_nested_includes_dir() {
        // Regression: a public header under a nested includes/ dir is indexed
        // (ngtcp2 includes/ngtcp2.h). decl_index already walks nested dirs; this
        // guards against a future is_excluded_dir change breaking it.
        let root = tmpdir();
        fs::create_dir_all(root.join("includes")).unwrap();
        fs::write(
            root.join("includes").join("ngtcp2.h"),
            "typedef struct { int value; } ngtcp2_conn;\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.c_type_defs
                .structs
                .iter()
                .any(|s| s.name == "ngtcp2_conn"),
            "nested includes/ header must be indexed"
        );
    }

    #[test]
    fn computes_tree_wide_c_lifecycle_pairs_across_unincluded_headers() {
        // §27.2: the opaque handle's typedef, its constructor, and its destructor
        // are spread across THREE separate headers that no single target
        // `#include`s together. The once-per-tree lifecycle index must still pair
        // `widget_create` / `widget_destroy` under the canonical handle key.
        let root = tmpdir();
        fs::write(
            root.join("widget_types.h"),
            "typedef struct widget widget_t;\n",
        )
        .unwrap();
        fs::write(
            root.join("widget_ctor.h"),
            "widget_t *widget_create(void);\n",
        )
        .unwrap();
        fs::write(
            root.join("widget_dtor.h"),
            "void widget_destroy(widget_t *w);\n",
        )
        .unwrap();
        // An unrelated decode entry that takes the handle but pairs nothing itself.
        fs::write(
            root.join("decode.c"),
            "int widget_decode(widget_t *w, const char *p, unsigned long n){return (int)n;}\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let paired = idx
            .c_tree_lifecycle
            .iter()
            .find(|h| h.init.as_deref() == Some("widget_create"))
            .expect("tree-wide lifecycle pairs the cross-header constructor");
        assert_eq!(
            paired.delete.as_deref(),
            Some("widget_destroy"),
            "destructor from a different header must pair too: {:?}",
            idx.c_tree_lifecycle
        );
        assert!(
            paired.handle_type.contains("widget"),
            "handle keyed under the opaque widget type: {paired:?}"
        );
    }

    #[test]
    fn static_source_initializer_does_not_shadow_public_tree_constructor() {
        let root = tmpdir();
        fs::write(
            root.join("mimalloc.h"),
            "typedef struct mi_heap_s mi_heap_t;\n\
             mi_heap_t *mi_heap_new(void);\n\
             void mi_heap_delete(mi_heap_t *heap);\n",
        )
        .unwrap();
        fs::write(
            root.join("heap.c"),
            "#include \"mimalloc.h\"\n\
             static int _mi_heap_guarded_init(mi_heap_t *heap) { return heap != 0; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let heap = idx
            .c_tree_lifecycle
            .iter()
            .find(|entry| entry.handle_type.contains("mi_heap"))
            .expect("heap lifecycle found");
        assert_eq!(heap.init.as_deref(), Some("mi_heap_new"));
        assert!(heap.init_returns_handle);
        assert_eq!(heap.delete.as_deref(), Some("mi_heap_delete"));
    }

    #[test]
    fn cpp_enum_in_header_is_a_defined_return_type() {
        let root = tmpdir();
        fs::write(
            root.join("tinyxml2.h"),
            "namespace tinyxml2 { enum XMLError { XML_SUCCESS = 0 }; }\n",
        )
        .unwrap();
        fs::write(
            root.join("tinyxml2.cpp"),
            "#include \"tinyxml2.h\"\n\
             tinyxml2::XMLError parse() { return tinyxml2::XML_SUCCESS; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.cpp_type_name_defined_in_tree("XMLError"),
            "a header enum must not be classified as an unavailable SDK type"
        );
    }

    #[test]
    fn indexes_c_declarations_and_external_definitions_across_tree() {
        let root = tmpdir();
        fs::write(
            root.join("a.h"),
            "extern int decoder_create(void);\nextern void decoder_destroy(int);\n",
        )
        .unwrap();
        fs::write(
            root.join("b.c"),
            "extern int decoder_create(void);\nint helper(void){return 0;}\nstatic int private_helper(void){return 0;}\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(idx.lookup_c("decoder_create").is_some());
        assert!(idx.lookup_c("decoder_destroy").is_some());
        assert!(idx.lookup_c("helper").is_some());
        assert!(idx.lookup_c("private_helper").is_none());
    }

    #[test]
    fn indexes_non_pod_anonymous_struct_typedef_and_wrapped_pointer_return() {
        let root = tmpdir();
        let header = "typedef struct {\n\
                 char *next_in;\n\
                 void *(*bzalloc)(void *, int, int);\n\
                 void (*bzfree)(void *, void *);\n\
             } bz_stream;\n";
        fs::write(root.join("bzlib.h"), header).unwrap();
        fs::write(
            root.join("version.c"),
            "typedef unsigned char Bool;\n\
             #define True ((Bool)1)\n\
             #define False ((Bool)0)\n\
             const char * BZ_API(BZ2_bzlibVersion)(void) { return \"1\"; }\n",
        )
        .unwrap();
        let parsed = c_parser::parse_c_type_defs(header).unwrap();
        assert!(
            parsed
                .structs
                .iter()
                .any(|record| record.name == "bz_stream"),
            "parsed structs: {:?}; typedefs: {:?}",
            parsed.structs,
            parsed.typedefs
        );
        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.type_defined_in_compiled_source("bz_stream"),
            "a surviving public-header typedef must block a colliding synthetic struct"
        );
        assert!(
            idx.lookup_c("BZ2_bzlibVersion").is_some(),
            "the real name inside a pointer-returning declaration wrapper must be indexed"
        );
        assert_eq!(idx.lookup_unique_object_macro("True"), Some("((Bool)1)"));
        assert_eq!(idx.lookup_unique_object_macro("False"), Some("((Bool)0)"));
    }

    #[test]
    fn ignores_unresolved_config_template_macro_values() {
        let root = tmpdir();
        fs::write(
            root.join("yaml.h"),
            "#define YAML_VERSION_MAJOR @YAML_VERSION_MAJOR@\n\
             #define YAML_VERSION_STRING \"@YAML_VERSION_STRING@\"\n\
             #define YAML_READY 1\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.lookup_unique_object_macro("YAML_VERSION_MAJOR"), None);
        assert_eq!(idx.lookup_unique_object_macro("YAML_VERSION_STRING"), None);
        assert_eq!(idx.lookup_unique_object_macro("YAML_READY"), Some("1"));
    }

    #[test]
    fn ignores_object_macros_from_foreign_platform_headers() {
        let foreign_header = if cfg!(target_os = "windows") {
            "archive_linux.h"
        } else if cfg!(any(target_os = "linux", target_os = "macos")) {
            "archive_windows.h"
        } else {
            return;
        };
        let root = tmpdir();
        fs::write(
            root.join(foreign_header),
            "#define O_RDONLY _O_RDONLY\n#define HOST_ONLY_ALIAS foreign_value\n",
        )
        .unwrap();
        fs::write(root.join("portable.h"), "#define PORTABLE_LIMIT 64\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.lookup_unique_object_macro("O_RDONLY"), None);
        assert_eq!(idx.lookup_unique_object_macro("HOST_ONLY_ALIAS"), None);
        assert_eq!(idx.lookup_unique_object_macro("PORTABLE_LIMIT"), Some("64"));
    }

    #[test]
    fn indexes_multiline_object_macro_values() {
        let root = tmpdir();
        fs::write(
            root.join("base.h"),
            concat!(
                "#define FMT_BEGIN_NAMESPACE \\",
                "\n",
                "  namespace fmt { \\",
                "\n",
                "  inline namespace v12 {\n",
                "#define FMT_END_NAMESPACE \\",
                "\n",
                "  } \\",
                "\n",
                "  }\n",
            ),
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_unique_object_macro("FMT_BEGIN_NAMESPACE"),
            Some("namespace fmt { inline namespace v12 {")
        );
        assert_eq!(
            idx.lookup_unique_object_macro("FMT_END_NAMESPACE"),
            Some("} }")
        );
    }

    #[test]
    fn empty_object_macro_keeps_conditional_definition_ambiguous() {
        let root = tmpdir();
        fs::write(
            root.join("base.h"),
            "#define FMT_BEGIN_EXPORT\n#define API_ONLY\n",
        )
        .unwrap();
        fs::write(
            root.join("module.cpp"),
            "#define FMT_BEGIN_EXPORT export {\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.lookup_unique_object_macro("FMT_BEGIN_EXPORT"), None);
        assert_eq!(idx.lookup_unique_object_macro("API_ONLY"), Some(""));
    }

    #[test]
    fn indexes_external_c_definitions_as_stub_declarations() {
        let root = tmpdir();
        fs::write(
            root.join("api.c"),
            "void release_buffer(unsigned char *ptr) { (void)ptr; }\n\
             static int private_helper(int value) { return value; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let declaration = idx
            .lookup_c("release_buffer")
            .expect("external definition supplies a declaration");
        assert_eq!(declaration.return_type, "void");
        assert_eq!(declaration.param_types, vec!["unsigned char *"]);
        assert!(
            idx.lookup_c("private_helper").is_none(),
            "private definitions must not become externally linked stubs"
        );
    }

    #[test]
    fn indexes_c_type_defs_tree_wide_from_headers() {
        // seL4's `word_t` is defined in an arch-gated header reached only via an
        // arch-specific include root the build (absent here) would select. The
        // tree-wide type-def index captures it regardless of include path so it
        // can back a fallback resolution.
        let root = tmpdir();
        let arch = root.join("include/arch/arm/arch");
        fs::create_dir_all(&arch).unwrap();
        fs::write(arch.join("types.h"), "typedef unsigned long word_t;\n").unwrap();
        fs::write(
            root.join("include/basic_types.h"),
            "typedef word_t bool_t;\n\
             struct msgid { word_t value; };\n\
             struct tcb { struct tcb *next; word_t prio; };\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        let names: Vec<&str> = idx
            .c_type_defs
            .typedefs
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert!(
            names.contains(&"word_t"),
            "tree-wide word_t missing: {names:?}"
        );
        assert!(
            names.contains(&"bool_t"),
            "tree-wide bool_t missing: {names:?}"
        );
        let struct_names: Vec<&str> = idx
            .c_type_defs
            .structs
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        // A flat-POD wrapper struct (scalar field) is kept — the military strong
        // typedef idiom now resolves.
        assert!(
            struct_names.contains(&"msgid"),
            "flat-POD wrapper struct must be kept: {struct_names:?}"
        );
        // A struct with a pointer field stays out, so an arch-gated complex struct
        // remains an honest opaque skip instead of an attempt-then-fail build.
        assert!(
            !struct_names.contains(&"tcb"),
            "struct with a pointer field must be dropped: {struct_names:?}"
        );
    }

    #[test]
    fn project_index_root_climbs_to_the_git_boundary() {
        // A subdir of a git project indexes from the project root, so cross-dir
        // headers/types resolve; a plain directory indexes itself.
        let root = tmpdir();
        fs::create_dir_all(root.join(".git")).unwrap();
        let sub = root.join("src/lib/parameters");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(super::project_index_root(&sub), root);

        let plain = tmpdir();
        let inner = plain.join("a/b");
        fs::create_dir_all(&inner).unwrap();
        assert_eq!(super::project_index_root(&inner), inner);
    }

    #[test]
    fn dot_h_typedefs_feed_both_c_and_cpp_fallback_indexes() {
        // fprime defines its basic aliases in a `.h` (`typedef uint8_t U8;` in
        // Fw/Types/BasicTypes.h). A C++ TU includes that C header, so the alias
        // must reach the C++ fallback index, not only the C one — otherwise a
        // `U8` C++ parameter is wrongly opaque.
        let root = tmpdir();
        fs::write(root.join("BasicTypes.h"), "typedef unsigned char U8;\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        let in_c = idx.c_type_defs.typedefs.iter().any(|t| t.name == "U8");
        let in_cpp = idx.cpp_type_defs.typedefs.iter().any(|t| t.name == "U8");
        assert!(in_c, "U8 should be in the C fallback index");
        assert!(
            in_cpp,
            "U8 from a .h must also reach the C++ fallback index"
        );
    }

    #[test]
    fn resolves_include_root_for_header_in_sibling_module_dir() {
        // cFS keeps headers in sibling module inc dirs the auto include detection
        // misses; resolving the real dir beats stubbing an empty placeholder.
        let root = tmpdir();
        let inc = root.join("modules/core_api/fsw/inc");
        fs::create_dir_all(&inc).unwrap();
        fs::write(inc.join("cfe_error.h"), "typedef int CFE_Status_t;\n").unwrap();
        let sub = root.join("osal/inc/osal");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("common_types.h"), "typedef unsigned int uint32;\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        // Bare spelling resolves to the header's own directory.
        assert_eq!(idx.include_root_for("cfe_error.h"), Some(inc.clone()));
        // Sub-pathed spelling resolves to the root above the sub-path.
        assert_eq!(
            idx.include_root_for("osal/common_types.h"),
            Some(root.join("osal/inc"))
        );
        // A header not in the tree has no root (falls back to a placeholder).
        assert_eq!(idx.include_root_for("not_here.h"), None);
    }

    #[test]
    fn missing_host_platform_header_rejects_foreign_and_build_only_copies() {
        let root = tmpdir();
        for dir in [
            "builds/vxworks",
            "builds/qnx",
            "builds/zos",
            "builds/mingw32",
        ] {
            let dir = root.join(dir);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("platform.hpp"), "#define FOREIGN_PLATFORM 1\n").unwrap();
        }
        let gyp = root.join("builds/gyp");
        fs::create_dir_all(&gyp).unwrap();
        fs::write(
            gyp.join("platform.hpp"),
            "#ifndef ZMQ_GYP_BUILD\n# error \"foreign platform.hpp detected, please re-configure\"\n#endif\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.include_root_for("platform.hpp"), None);
        assert_eq!(idx.unique_header_for("platform.hpp"), None);
    }

    #[test]
    fn generated_host_platform_header_remains_resolvable() {
        let root = tmpdir();
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("platform.hpp"), "#define ZMQ_HAVE_LINUX 1\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.include_root_for("platform.hpp"), Some(src));
    }

    #[test]
    fn resolves_missing_header_to_explicit_prebuilt_fallback() {
        let root = tmpdir();
        let prebuilt = root.join("pnglibconf.h.prebuilt");
        fs::write(&prebuilt, "#define PNG_READ_SUPPORTED\n").unwrap();
        let dist = root.join("ares_build.h.dist");
        fs::write(&dist, "#define CARES_TYPEOF_ARES_SOCKLEN_T socklen_t\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        assert_eq!(idx.include_root_for("pnglibconf.h"), None);
        assert_eq!(idx.unique_header_for("pnglibconf.h"), Some(prebuilt));
        assert_eq!(idx.include_root_for("ares_build.h"), None);
        assert_eq!(idx.unique_header_for("ares_build.h"), Some(dist));
    }

    #[test]
    fn resolves_parent_relative_include_to_unique_recovered_header() {
        let root = tmpdir();
        let include = root.join("vcs_recovery/include/rapidjson");
        fs::create_dir_all(&include).unwrap();
        fs::write(include.join("allocators.h"), "#pragma once\n").unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.include_root_for("../allocators.h"),
            Some(include.join(".govfuzz-relative-include-0"))
        );
    }

    #[test]
    fn indexes_c_definition_source_paths_across_tree() {
        let root = tmpdir();
        let helper = root.join("helper.c");
        fs::write(
            &helper,
            "int helper(const unsigned char *d, unsigned long n){return (int)n;}\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let source = idx
            .lookup_c_definition_source("helper")
            .expect("helper definition source should be indexed");

        assert_eq!(source, helper.as_path());
    }

    #[test]
    fn c_definition_source_selection_is_deterministic_and_prefers_production() {
        let root = tmpdir();
        let src = root.join("src");
        let tests = root.join("tests");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&tests).unwrap();
        let fast = src.join("crc32_fast.c");
        fs::write(&fast, "int crc32_impl(void) { return 1; }\n").unwrap();
        fs::write(
            src.join("crc32_small.c"),
            "int crc32_impl(void) { return 2; }\n",
        )
        .unwrap();
        fs::write(
            tests.join("crc32.c"),
            "int crc32_impl(void) { return 3; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_definition_source("crc32_impl"),
            Some(fast.as_path())
        );
    }

    #[test]
    fn c_definition_source_selection_prefers_the_targets_subproject() {
        let root = tmpdir();
        let doom = root.join("src/doom");
        let hexen = root.join("src/hexen");
        fs::create_dir_all(&doom).unwrap();
        fs::create_dir_all(&hexen).unwrap();
        let doom_definition = doom.join("game.c");
        let hexen_definition = hexen.join("game.c");
        let target = hexen.join("save.c");
        fs::write(&doom_definition, "int shared_state;\n").unwrap();
        fs::write(&hexen_definition, "int shared_state;\n").unwrap();
        fs::write(
            &target,
            "extern int shared_state;\nint save(void) { return shared_state; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_definition_source_near("shared_state", &target),
            Some(hexen_definition.as_path())
        );
    }

    #[test]
    fn c_definition_source_selection_rejects_unavailable_external_header() {
        let root = tmpdir();
        let source = root.join("helper.c");
        fs::write(
            &source,
            "#include <vendor_sdk/missing.h>\nint helper(void) { return 1; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(idx.lookup_c_definition_source("helper"), None);

        fs::write(root.join("missing.h"), "#define VENDOR_READY 1\n").unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_definition_source("helper"),
            Some(source.as_path())
        );
    }

    #[test]
    fn c_definition_source_selection_accepts_compiler_builtin_header() {
        let root = tmpdir();
        let source = root.join("helper.c");
        fs::write(
            &source,
            "#include <stddef.h>\nint helper(const void *p) { return p != NULL; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_definition_source("helper"),
            Some(source.as_path())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn c_definition_source_selection_excludes_foreign_platform_directories() {
        let root = tmpdir();
        let unix = root.join("src/prim/unix");
        let wasi = root.join("src/prim/wasi");
        fs::create_dir_all(&unix).unwrap();
        fs::create_dir_all(&wasi).unwrap();
        let host_source = unix.join("prim.c");
        fs::write(&host_source, "int platform_output(void) { return 1; }\n").unwrap();
        fs::write(
            wasi.join("prim.c"),
            "int platform_output(void) { return 2; }\n\
             int foreign_only(void) { return 3; }\n",
        )
        .unwrap();
        fs::write(
            root.join("src/async.c"),
            "#include \"iocp-internal.h\"\nint async_only(void) { return 4; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_definition_source("platform_output"),
            Some(host_source.as_path())
        );
        assert!(
            idx.lookup_c_definition_source("foreign_only").is_none(),
            "a WASI implementation must not be linked into a Linux repair"
        );
        assert!(
            idx.lookup_c_definition_source("async_only").is_none(),
            "an unconditionally IOCP-backed source must not enter a Linux repair"
        );
    }

    #[test]
    fn c_definition_source_selection_excludes_missing_textual_implementation() {
        let root = tmpdir();
        fs::write(
            root.join("broken.c"),
            "#include \"deleted_impl.c\"\nint broken_helper(void) { return 1; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            idx.lookup_c_definition_source("broken_helper").is_none(),
            "a TU that textually includes a deleted implementation must not be linked as a repair"
        );
    }

    #[test]
    fn libcbor_extern_data_object_resolves_to_addsource_not_blind_stub() {
        // #27: libcbor's `_cbor_malloc`/`_cbor_realloc`/`_cbor_free` are extern DATA
        // objects (function-pointer-typedef variables) DEFINED in allocators.c. A TU
        // referencing them must resolve them to AddSource(allocators.c) — the repair
        // planner consults `lookup_c_definition_source` — instead of blind-stubbing
        // them as weak NULL FUNCTIONS (the wrong symbol kind).
        let root = tmpdir();
        fs::create_dir_all(root.join("cbor")).unwrap();
        fs::write(root.join("cbor/common.h"), "/* allocator typedefs */\n").unwrap();
        fs::write(
            root.join("allocators.c"),
            "#include \"cbor/common.h\"\n\
             _cbor_malloc_t _cbor_malloc = malloc;\n\
             _cbor_realloc_t _cbor_realloc = realloc;\n\
             _cbor_free_t _cbor_free = free;\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        for sym in ["_cbor_malloc", "_cbor_realloc", "_cbor_free"] {
            assert_eq!(
                idx.lookup_c_definition_source(sym),
                Some(root.join("allocators.c").as_path()),
                "extern data object {sym} must resolve to its defining source for AddSource",
            );
        }
    }

    #[test]
    fn extra_include_definition_sources_resolve_for_addsource() {
        // #388: a target library (cJSON) passed via --extra-include must have its
        // `.c` definition sources indexed so the repair planner AddSource-links the
        // real source instead of blind-stubbing the symbol. The swept tree holds
        // only the harness; the library lives in a separate --extra-include dir.
        let tree = tmpdir();
        fs::write(
            tree.join("harness.c"),
            "#include \"cjson_lite.h\"\nint LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){ return 0; }\n",
        )
        .unwrap();
        let dep = tmpdir();
        fs::write(
            dep.join("cjson_lite.h"),
            "void *cJSON_Parse(const char *s);\n",
        )
        .unwrap();
        fs::write(
            dep.join("cjson_lite.c"),
            "void *cJSON_Parse(const char *s){ return (void *)0; }\n",
        )
        .unwrap();
        // A demo TU with its own main() must be skipped wholesale (duplicate main).
        fs::write(
            dep.join("demo.c"),
            "int demo_helper(void){ return 1; }\nint main(void){ return 0; }\n",
        )
        .unwrap();

        let mut idx = DeclarationIndex::build(&tree).unwrap();
        // Before indexing the dep dir, the library symbol is unknown (-> StubBlind).
        assert!(idx.lookup_c_definition_source("cJSON_Parse").is_none());

        idx.add_definition_search_roots(std::slice::from_ref(&dep))
            .unwrap();

        assert_eq!(
            idx.lookup_c_definition_source("cJSON_Parse"),
            Some(dep.join("cjson_lite.c").as_path()),
            "extra-include .c definition source must be indexed for AddSource",
        );
        // The main()-bearing TU is skipped entirely, including its other defs.
        assert!(
            idx.lookup_c_definition_source("demo_helper").is_none(),
            "a TU defining main() must not be indexed (duplicate-main link break)",
        );
    }

    #[test]
    fn indexes_cpp_member_declarations() {
        let root = tmpdir();
        fs::write(
            root.join("foo.hpp"),
            "class Foo {\npublic:\n    int parse(const char *s);\n};\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(idx.lookup_cpp("parse").is_some());
    }

    #[test]
    fn indexes_owning_header_for_c_stub_declaration() {
        let root = tmpdir();
        let header = root.join("transform.h");
        fs::write(
            &header,
            "typedef struct BrotliTransforms BrotliTransforms;\n\
             int BrotliTransformDictionaryWord(const BrotliTransforms* transforms);\n\
             void mi_cdecl _mi_auto_process_done(void) mi_attr_noexcept;\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_stub_header("BrotliTransformDictionaryWord"),
            Some(header.as_path())
        );
        assert_eq!(
            idx.lookup_c("_mi_auto_process_done")
                .map(|declaration| declaration.return_type.as_str()),
            Some("void")
        );
        assert_eq!(
            idx.lookup_c_stub_header("_mi_auto_process_done"),
            Some(header.as_path())
        );
    }

    #[test]
    fn indexes_cpp_hh_declarations() {
        let root = tmpdir();
        fs::write(
            root.join("foo.hh"),
            "class Foo {\npublic:\n    int parse_hh(const char *s);\n};\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        assert!(idx.lookup_cpp("parse_hh").is_some());
    }

    #[test]
    fn demangled_cpp_lookup_selects_constructor_overload_by_arity() {
        let root = tmpdir();
        fs::write(
            root.join("status.hh"),
            "namespace leveldb { class Slice; class Status {\n\
             public: Status(const Status &);\n\
             private: enum Code { kOk }; Status(Code, const Slice &, const Slice &);\n\
             }; }\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();

        let declaration = idx
            .lookup_cpp_stub_declaration(
                "leveldb::Status::Status(leveldb::Status::Code, leveldb::Slice const&, leveldb::Slice const&)",
            )
            .expect("three-argument constructor declaration");
        assert_eq!(declaration.name, "leveldb::Status::Status");
        assert_eq!(declaration.param_types.len(), 3, "{declaration:?}");
        assert_eq!(
            idx.lookup_cpp_stub_header("leveldb::Status::Status(leveldb::Status::Code, leveldb::Slice const&, leveldb::Slice const&)"),
            Some(root.join("status.hh").as_path())
        );
    }

    #[test]
    fn demangled_cpp_lookup_selects_const_method_overload() {
        let root = tmpdir();
        fs::write(
            root.join("value.hh"),
            "namespace Json { class Value; class Iterator {\n\
             public: const Value& deref() const; Value& deref();\n\
             }; }\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();

        let const_decl = idx
            .lookup_cpp_stub_declaration("Json::Iterator::deref() const")
            .expect("const overload");
        assert_eq!(const_decl.return_type, "const Value&");
        assert_eq!(const_decl.function_suffix, "const");

        let mutable_decl = idx
            .lookup_cpp_stub_declaration("Json::Iterator::deref()")
            .expect("mutable overload");
        assert_eq!(mutable_decl.return_type, "Value&");
        assert!(mutable_decl.function_suffix.is_empty());
    }

    #[test]
    fn demangled_cpp_lookup_scores_same_arity_parameter_types() {
        let root = tmpdir();
        fs::write(
            root.join("value.hh"),
            "namespace Json { class ValueIterator; class Value {\n\
             public: struct ObjectValues { class iterator; };\n\
             }; class ValueConstIterator {\n\
             public: ValueConstIterator(const ValueIterator&);\n\
             private: explicit ValueConstIterator(const Value::ObjectValues::iterator&);\n\
             }; }\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();

        let declaration = idx
            .lookup_cpp_stub_declaration(
                "Json::ValueConstIterator::ValueConstIterator(std::_Rb_tree_iterator<std::pair<Json::Value, int> > const&)",
            )
            .expect("iterator constructor declaration");
        assert!(
            declaration.param_types[0].contains("ObjectValues"),
            "{declaration:?}"
        );
    }

    #[test]
    fn demangled_cpp_lookup_finds_default_base_constructor() {
        let root = tmpdir();
        fs::write(
            root.join("value.hh"),
            "namespace Json { class Value { public: struct ObjectValues { using iterator = int; }; };\n\
             class JSON_API ValueIteratorBase {\n\
             public: using SelfType = ValueIteratorBase;\n\
             bool operator==(const SelfType& other) const { return isEqual(other); }\n\
             bool operator!=(const ValueIteratorBase& other) const { return !isEqual(other); }\n\
             bool isEqual(const ValueIteratorBase& other) const;\n\
             JSONCPP_DEPRECATED(\"Use `key = name();` instead.\")\n\
             char const* memberName() const;\n\
             protected: void increment();\n\
             private: Value::ObjectValues::iterator current_;\n\
             bool isNull_{true};\n\
             public: ValueIteratorBase();\n\
             explicit ValueIteratorBase(const Value::ObjectValues::iterator& current);\n\
             }; }\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();

        let declaration = idx
            .lookup_cpp_stub_declaration("Json::ValueIteratorBase::ValueIteratorBase()")
            .expect("default base constructor declaration");
        assert_eq!(
            declaration.name,
            "Json::ValueIteratorBase::ValueIteratorBase"
        );
        assert!(declaration.return_type.is_empty());
        assert!(declaration.param_types.is_empty());
    }

    #[test]
    fn indexes_cpp_source_that_includes_definition_header() {
        let root = tmpdir();
        fs::create_dir_all(root.join("include/fmt")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("test")).unwrap();
        fs::write(
            root.join("include/fmt/format-inl.h"),
            "namespace fmt { namespace v12 { namespace detail {\n\
             auto allocate(unsigned long size) -> void* { return (void*)size; }\n\
             } } }\n",
        )
        .unwrap();
        let source = root.join("src/format.cc");
        fs::write(&source, "#include \"fmt/format-inl.h\"\n").unwrap();
        fs::write(
            root.join("test/format-test.cc"),
            "struct Alloc { void *allocate(unsigned long); };\n\
             void *Alloc::allocate(unsigned long size) { return (void*)size; }\n",
        )
        .unwrap();
        fs::write(
            root.join("src/module.cc"),
            "module;\nvoid *allocate(unsigned long size) { return (void*)size; }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let found = idx
            .lookup_cpp_definition_source("fmt::v12::detail::allocate(unsigned long)")
            .expect("included C++ definition header should map back to implementation source");

        assert_eq!(found, source.as_path());
    }

    #[test]
    fn indexes_cpp_definition_source_for_demangled_member_symbol() {
        let root = tmpdir();
        let helper = root.join("parser_helper.cpp");
        fs::write(
            &helper,
            "#include <string>\n\
             namespace gov { class Parser { public: std::string normalize(const std::string &); };\n\
             std::string Parser::normalize(const std::string &input) { return input; } }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        let found = idx
            .lookup_cpp_definition_source("gov::Parser::normalize[abi:cxx11](std::string const&)")
            .expect("demangled C++ member symbol should map to its source");

        assert_eq!(found, helper.as_path());
    }

    #[test]
    fn skips_cpp_module_units_for_source_repair() {
        let root = tmpdir();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/module.cc"),
            "module;\nnamespace fmt { namespace v12 { void helper() {} } }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        assert!(idx
            .lookup_cpp_definition_source("fmt::v12::helper()")
            .is_none());
    }

    /// F2: a class declared in a header (methods defined out-of-line in a .cpp) is
    /// the NORMAL case and stays harnessable; a class DEFINED only in a .cpp and
    /// never declared in any header is unreachable from a harness and is flagged.
    #[test]
    fn cpp_class_defined_only_in_cpp_is_detected_header_declared_kept() {
        let root = tmpdir();
        // Header declares `Json` (full definition) and forward-declares `JsonValue`.
        fs::write(
            root.join("json11.hpp"),
            "namespace json11 {\n\
             class JsonValue;\n\
             class Json final {\n\
             public:\n\
               static Json parse(const std::string& in);\n\
             };\n\
             }\n",
        )
        .unwrap();
        // The .cpp defines `Json::parse` out-of-line (NORMAL) and defines a brand
        // new `struct JsonParser` that appears in no header (json11's real pattern).
        fs::write(
            root.join("json11.cpp"),
            "#include \"json11.hpp\"\n\
             namespace json11 {\n\
             Json Json::parse(const std::string& in) { return Json(); }\n\
             struct JsonParser final {\n\
               bool expect(const std::string& s) { return s.empty(); }\n\
             };\n\
             }\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();

        // .cpp-only class with no header declaration anywhere -> flagged.
        assert!(
            idx.cpp_class_defined_only_in_translation_unit("JsonParser"),
            "JsonParser is defined only in json11.cpp and absent from the header"
        );
        // Header-declared class (defined in header, methods out-of-line) -> kept.
        assert!(
            !idx.cpp_class_defined_only_in_translation_unit("Json"),
            "Json is declared in the header and must remain harnessable"
        );
        // A forward-declared-only class still counts as header-declared -> kept.
        assert!(
            !idx.cpp_class_defined_only_in_translation_unit("JsonValue"),
            "a forward declaration in a header is still a declaration"
        );
        // A namespace (never a recorded class) is never flagged.
        assert!(!idx.cpp_class_defined_only_in_translation_unit("json11"));
        // An unknown name is never flagged.
        assert!(!idx.cpp_class_defined_only_in_translation_unit("Nonexistent"));
    }

    /// A `.h` extension is routinely a C++ header (ada-url): a class declared there
    /// must still count, so a class fully defined in a `.h` is not flagged even
    /// though no `.hpp` exists.
    #[test]
    fn cpp_class_in_dot_h_header_counts_as_declared() {
        let root = tmpdir();
        fs::write(
            root.join("url.h"),
            "namespace ada {\nclass url {\npublic:\n  bool parse_host(const char* in);\n};\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("url.cpp"),
            "#include \"url.h\"\nnamespace ada {\nbool url::parse_host(const char* in) { return in != nullptr; }\n}\n",
        )
        .unwrap();

        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(
            !idx.cpp_class_defined_only_in_translation_unit("url"),
            "class url is declared in url.h (a C++ .h header) and must stay harnessable"
        );
    }

    #[test]
    fn indexes_extern_data_with_trailing_block_comment() {
        let root = tmpdir();
        fs::write(
            root.join("server.h"),
            "typedef struct { int value; } BucketsType;\n\
             extern BucketsType subexpiresBucketsType; /* global expires */\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_extern_data_type("subexpiresBucketsType"),
            Some("BucketsType")
        );
    }

    #[test]
    fn indexes_extern_function_pointer_as_data() {
        let root = tmpdir();
        fs::write(
            root.join("monotonic.h"),
            "typedef unsigned long monotime;\nextern monotime (*getMonotonicUs)(void);\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert_eq!(
            idx.lookup_c_extern_data_type("getMonotonicUs"),
            Some("monotime (*)(void)")
        );
    }
}
