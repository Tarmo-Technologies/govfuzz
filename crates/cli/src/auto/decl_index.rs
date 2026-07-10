// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct DeclarationIndex {
    /// Function name -> list of declarations across the tree. Multiple
    /// entries mean we found multiple incompatible declarations; the
    /// auto loop logs and picks the first by source-tree order.
    pub c: HashMap<String, Vec<c_parser::CDeclaration>>,
    pub cpp: HashMap<String, Vec<cpp_parser::CppDeclaration>>,
    /// C function name -> source file(s) that define it. Used by auto
    /// build recovery to add real project source files before falling
    /// back to generated stubs.
    c_definitions: HashMap<String, Vec<PathBuf>>,
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
    /// by scanning the C declarations of ALL translation units in the tree (not
    /// just a target's include closure), computed ONCE here. Threaded into the
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

    /// Record an Ada source file under its unit key, derived from the file stem
    /// (GNAT crunches `Keccak.Arch` to `keccak-arch`). Deduped.
    fn record_ada_unit_path(&mut self, path: &Path) {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            return;
        };
        let key = ada_unit_key(strip_ada_platform_suffix(stem));
        let paths = self.ada_unit_paths.entry(key).or_default();
        if !paths.contains(&path.to_path_buf()) {
            paths.push(path.to_path_buf());
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

    fn build_parsed(root: &Path) -> std::io::Result<Self> {
        let mut idx = Self::default();
        let entries = walkdir_lite(root)?;
        let mut cpp_headers = Vec::new();
        let mut cpp_sources = Vec::new();
        let mut c_type_defs = c_parser::CTypeDefs::default();
        let mut cpp_type_defs = c_parser::CTypeDefs::default();
        for entry in entries {
            let Some(ext) = entry.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if matches!(ext, "h" | "hpp" | "hh" | "hxx" | "hp" | "inc") {
                if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                    idx.header_paths
                        .entry(name.to_owned())
                        .or_default()
                        .push(entry.clone());
                }
            }
            let Ok(source) = crate::source_text::read_source_text(&entry) else {
                continue;
            };
            // Record C++ class/struct/union leaf names so a member whose owning
            // class is defined only in a `.cpp` (never declared in a header) can be
            // pre-skipped. Every header extension is parsed with the C++ type-def
            // parser (a superset of C, and a `.h` is routinely a C++ header — e.g.
            // ada-url) so a forward declaration in a header still counts as
            // "declared", keeping out-of-line-defined classes harnessable.
            if matches!(ext, "h" | "hpp" | "hh" | "hxx" | "hp") {
                if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                    for s in &defs.structs {
                        idx.cpp_header_class_names.insert(s.name.clone());
                    }
                }
            } else if matches!(ext, "cpp" | "cc" | "cxx" | "C")
                && !cpp_source_uses_module_unit(&source)
            {
                if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                    for s in defs.structs.iter().filter(|s| s.complete) {
                        idx.cpp_source_class_names.insert(s.name.clone());
                    }
                }
            }
            match ext {
                "c" | "h" => {
                    if ext == "h" {
                        cpp_headers.push((entry.clone(), source.clone()));
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
                            }
                            for t in &defs.typedefs {
                                idx.source_type_names.insert(t.name.clone());
                            }
                            c_type_defs.merge(defs.clone());
                            cpp_type_defs.merge(defs);
                        }
                    }
                    if let Ok(decls) = c_parser::parse_c_declarations(&source) {
                        for d in decls {
                            idx.c.entry(d.name.clone()).or_default().push(d);
                        }
                    }
                    if ext == "c" {
                        if let Ok(functions) = c_parser::parse_c_functions(&source) {
                            for f in functions {
                                idx.c_definitions
                                    .entry(f.name)
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
                        cpp_sources.push((entry.clone(), source.clone()));
                    } else {
                        cpp_headers.push((entry.clone(), source.clone()));
                        if let Ok(defs) = cpp_parser::parse_cpp_type_defs(&source) {
                            cpp_type_defs.merge(defs);
                        }
                    }
                    if let Ok(decls) = cpp_parser::parse_cpp_declarations(&source) {
                        for d in decls {
                            idx.cpp.entry(d.name.clone()).or_default().push(d);
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
        // §27.2: compute the tree-wide C opaque-handle lifecycle pairs ONCE, from
        // the declarations of EVERY C translation unit in the tree (`idx.c`), so a
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
        let tree_decls: Vec<c_parser::CDeclaration> = self.c.values().flatten().cloned().collect();
        if tree_decls.is_empty() {
            return Vec::new();
        }
        crate::generate_harness::c_direct_lifecycle_table(&[], &tree_decls, &registry)
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
        roots.into_iter().next()
    }

    pub fn lookup_c(&self, name: &str) -> Option<&c_parser::CDeclaration> {
        self.c.get(name).and_then(|v| v.first())
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
        self.cpp.get(name).and_then(|v| v.first())
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
    }

    pub fn lookup_c_definition_source(&self, name: &str) -> Option<&Path> {
        self.c_definitions
            .get(name)
            .and_then(|v| v.first())
            .map(PathBuf::as_path)
    }

    pub fn lookup_cpp_definition_source(&self, name: &str) -> Option<&Path> {
        let mut candidates = Vec::new();
        for key in cpp_symbol_lookup_keys(name) {
            if let Some(paths) = self.cpp_definitions.get(&key) {
                candidates.extend(paths.iter());
            }
        }
        candidates
            .into_iter()
            .min_by_key(|path| cpp_source_repair_score(path))
            .map(PathBuf::as_path)
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
        cpp_sources: &[(PathBuf, String)],
        cpp_headers: &[(PathBuf, String)],
    ) {
        for (source_path, source_text) in cpp_sources {
            for include in quoted_includes(source_text) {
                for (header_path, header_text) in cpp_headers {
                    if !header_matches_include(source_path, &include, header_path) {
                        continue;
                    }
                    let Ok(functions) = cpp_parser::parse_cpp_functions(header_text) else {
                        continue;
                    };
                    for function in functions {
                        self.index_cpp_definition(&function, source_path);
                    }
                }
            }
        }
    }
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

fn cpp_source_repair_score(path: &Path) -> (u8, usize, String) {
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
                mode: ada_param_mode_display_name(&param.mode),
                type_name: ada_type_ref_display_name(&param.type_ref),
            })
            .collect(),
    }
}

fn ada_param_mode_display_name(mode: &ada_parser::ast::ParamMode) -> Option<String> {
    match mode {
        ada_parser::ast::ParamMode::In => None,
        ada_parser::ast::ParamMode::Out => Some("out".to_owned()),
        ada_parser::ast::ParamMode::InOut => Some("in out".to_owned()),
        ada_parser::ast::ParamMode::AccessMode => Some("access".to_owned()),
    }
}

fn ada_type_ref_display_name(type_ref: &ada_parser::ast::TypeRef) -> String {
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
    fn indexes_c_declarations_across_tree() {
        let root = tmpdir();
        fs::write(
            root.join("a.h"),
            "extern int decoder_create(void);\nextern void decoder_destroy(int);\n",
        )
        .unwrap();
        fs::write(
            root.join("b.c"),
            "extern int decoder_create(void);\nint helper(void){return 0;}\n",
        )
        .unwrap();
        let idx = DeclarationIndex::build(&root).unwrap();
        assert!(idx.lookup_c("decoder_create").is_some());
        assert!(idx.lookup_c("decoder_destroy").is_some());
        assert!(
            idx.lookup_c("helper").is_none(),
            "function definitions stay out of the declaration index"
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
    fn libcbor_extern_data_object_resolves_to_addsource_not_blind_stub() {
        // #27: libcbor's `_cbor_malloc`/`_cbor_realloc`/`_cbor_free` are extern DATA
        // objects (function-pointer-typedef variables) DEFINED in allocators.c. A TU
        // referencing them must resolve them to AddSource(allocators.c) — the repair
        // planner consults `lookup_c_definition_source` — instead of blind-stubbing
        // them as weak NULL FUNCTIONS (the wrong symbol kind).
        let root = tmpdir();
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
}
