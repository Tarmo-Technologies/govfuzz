// SPDX-License-Identifier: Apache-2.0

//! Offline build-probe: recover a project's real compile wiring by running its
//! own build under govfuzz, emitting a `compile_commands.json` (and, as a side
//! effect of running the build's configure/codegen step, any *generated*
//! headers) into `<tree>/.govfuzz-build/`. The existing per-target compile-flag
//! ingestion then builds each harness with the exact `-I`/`-D`/`-std` flags the
//! real translation unit uses — the general fix for project-specific build
//! wiring (cFS config dirs + generated CCSDS headers, seL4/Zephyr CMake).
//!
//! Tiers (detected by marker file at the tree root):
//! * **CMake** — configure an instrumented static build, request CMake's file-api
//!   codemodel, then build only its static-library targets. This yields the DB,
//!   generated headers, and sanitizer/coverage-compatible archives without
//!   paying to compile project tests/tools.
//! * **Meson** — `meson setup <tree>/.govfuzz-build <tree>` (configure only):
//!   Meson writes the DB into the build dir natively and runs codegen.
//! * **MSBuild** — parse `.vcxproj` XML for include dirs/defines/sources (no
//!   execution); needs no `msbuild`.
//! * **Make** — run the project's `make` with `CC`/`CXX` pointed at a generated
//!   wrapper that logs each invocation then execs the real compiler; the log is
//!   converted to a DB. Captures generated headers and even a partial build.
//! * **Ninja** — `ninja -t compdb` reads `build.ninja` and prints the DB without
//!   running the build.
//!
//! For *any other* build (custom radar/RTOS scripts, Bazel, SCons, Waf, a bare
//! `build.sh`, a vendor IDE build), `--build-command "<cmd>"` runs that command
//! under a front-of-`PATH` compiler shim — see `probe_build_command` — which
//! intercepts every `cc`/`gcc`/`clang` *and* vendor-compiler invocation into the
//! same DB. That is the universal escape hatch.
//!
//! Both **execute untrusted build scripts**, so the probe is opt-in
//! (`--probe-build`) and runs under govfuzz's sandbox when one is available,
//! degrading to a direct run otherwise (matching the auto-sandbox policy).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory under the scanned tree where the probe writes its compile database
/// and (for the Make tier) the compiler wrapper + invocation log. Mirrored by
/// `compile_database_candidates` in `generate_harness`, so the produced DB is
/// found without any extra plumbing.
pub const PROBE_DIR: &str = ".govfuzz-build";
const COVERAGE_PROBE_DIR: &str = ".govfuzz-build-cov";
const PROBE_REQUIREMENTS_FILE: &str = "missing-requirements.json";
const PROBE_ARTIFACTS_FILE: &str = "govfuzz-artifacts.json";

/// Exact native instrumentation requested for project artifacts produced by an
/// opt-in build probe. A prebuilt archive is useful for closing a link only if
/// it was compiled with the same coverage/sanitizer contract as the harness;
/// otherwise the engine sees the wrapper but not the library it is meant to
/// explore (and `--sanitizers none` can fail on stale ASan references).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProbeInstrumentation {
    cc: String,
    cxx: String,
    c_flags: Vec<String>,
    cxx_flags: Vec<String>,
    #[serde(default)]
    linker_flags: Vec<String>,
}

impl ProbeInstrumentation {
    fn for_selection(selection: &multicore_fuzz::SanitizerSelection) -> Self {
        use multicore_fuzz::{Sanitizer, SanitizerSelection};

        let sanitizer_name = |sanitizer: Sanitizer| match sanitizer {
            Sanitizer::Asan => "address",
            Sanitizer::Msan => "memory",
            Sanitizer::Ubsan => "undefined",
            Sanitizer::Tsan => "thread",
            Sanitizer::Lsan => "leak",
        };
        let selected = match selection {
            SanitizerSelection::Default => Some(vec![Sanitizer::Asan, Sanitizer::Ubsan]),
            SanitizerSelection::None => None,
            SanitizerSelection::Set(set) => Some(set.clone()),
        };
        let has_ubsan = selected
            .as_ref()
            .is_some_and(|set| set.contains(&Sanitizer::Ubsan));
        let mut common = vec![
            "-O1".to_owned(),
            "-g".to_owned(),
            "-ffunction-sections".to_owned(),
            "-fdata-sections".to_owned(),
        ];
        if let Some(set) = selected {
            if !set.is_empty() {
                common.push(format!(
                    "-fsanitize={}",
                    set.into_iter()
                        .map(sanitizer_name)
                        .collect::<Vec<_>>()
                        .join(",")
                ));
                if has_ubsan {
                    common.push("-fno-sanitize=function,vptr,alignment".to_owned());
                }
            }
        }
        common.push("-fsanitize-coverage=trace-pc-guard,trace-cmp".to_owned());
        let mut cxx_flags = common.clone();
        cxx_flags.push("-Wno-reserved-user-defined-literal".to_owned());
        cxx_flags.extend(crate::build::detect_cpp_stdlib_include_flags_for(
            "clang++", &cxx_flags,
        ));
        let linker_flags = crate::build::detect_libstdcxx_search_path()
            .map(|path| vec![format!("-L{path}")])
            .unwrap_or_default();
        Self {
            cc: "clang".to_owned(),
            cxx: "clang++".to_owned(),
            c_flags: common,
            cxx_flags,
            linker_flags,
        }
    }

    /// Source-based coverage is a separate project build. Reusing the primary
    /// ASan/UBSan archive in `make cov` does not merely omit library line data:
    /// it fails to link because that lane intentionally has no sanitizer
    /// runtime. Keeping a second archive also avoids burdening the hot fuzz
    /// binary with profile counters and `.profraw` writes.
    fn for_source_coverage() -> Self {
        let common = vec![
            "-O0".to_owned(),
            "-g".to_owned(),
            "-ffunction-sections".to_owned(),
            "-fdata-sections".to_owned(),
            "-fprofile-instr-generate".to_owned(),
            "-fcoverage-mapping".to_owned(),
        ];
        let mut cxx_flags = common.clone();
        cxx_flags.push("-Wno-reserved-user-defined-literal".to_owned());
        cxx_flags.extend(crate::build::detect_cpp_stdlib_include_flags_for(
            "clang++", &cxx_flags,
        ));
        let linker_flags = crate::build::detect_libstdcxx_search_path()
            .map(|path| vec![format!("-L{path}")])
            .unwrap_or_default();
        Self {
            cc: "clang".to_owned(),
            cxx: "clang++".to_owned(),
            c_flags: common,
            cxx_flags,
            linker_flags,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeArtifactManifest {
    schema_version: u32,
    instrumentation: ProbeInstrumentation,
    build_attempted: bool,
    build_succeeded: bool,
}

fn write_probe_artifact_manifest(
    tree: &Path,
    instrumentation: &ProbeInstrumentation,
    build_succeeded: bool,
) {
    write_artifact_manifest_at(&tree.join(PROBE_DIR), instrumentation, build_succeeded);
}

fn write_artifact_manifest_at(
    probe_dir: &Path,
    instrumentation: &ProbeInstrumentation,
    build_succeeded: bool,
) {
    let manifest = ProbeArtifactManifest {
        schema_version: 1,
        instrumentation: instrumentation.clone(),
        build_attempted: true,
        build_succeeded,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&manifest) {
        let _ = crate::auto::report::atomic_write(&probe_dir.join(PROBE_ARTIFACTS_FILE), &bytes);
    }
}

/// A precise dependency/tool failure observed while running the project's own
/// build probe. The requirements scanner folds this sidecar into the durable
/// `missing-deps.*` checkpoint immediately after the probe.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProbeRequirement {
    pub kind: crate::auto::dep_manifest::DepKind,
    pub name: String,
    pub acquisition_hint: String,
    pub evidence: String,
}

pub fn load_probe_requirements(tree: &Path) -> Vec<ProbeRequirement> {
    std::fs::read_to_string(tree.join(PROBE_DIR).join(PROBE_REQUIREMENTS_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn record_probe_requirement(tree: &Path, requirement: ProbeRequirement) {
    let path = tree.join(PROBE_DIR).join(PROBE_REQUIREMENTS_FILE);
    let mut requirements = load_probe_requirements(tree);
    if let Some(existing) = requirements
        .iter_mut()
        .find(|entry| entry.kind == requirement.kind && entry.name == requirement.name)
    {
        *existing = requirement;
    } else {
        requirements.push(requirement);
    }
    requirements.sort_by(|a, b| {
        a.kind
            .label()
            .cmp(b.kind.label())
            .then_with(|| a.name.cmp(&b.name))
    });
    if let Ok(bytes) = serde_json::to_vec_pretty(&requirements) {
        let _ = crate::auto::report::atomic_write(&path, &bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSystem {
    CMake,
    /// A Meson project (`meson.build`). `meson setup <builddir>` writes
    /// `compile_commands.json` into the build dir natively (ninja backend).
    Meson,
    /// A Visual Studio solution/project (`.sln` / `.vcxproj`), built by MSBuild.
    MSBuild,
    Make,
    /// A standalone Ninja build (`build.ninja` at the tree root, not the
    /// CMake/Meson-generated one inside a build dir). `ninja -t compdb` emits the
    /// database from the manifest without running the build.
    Ninja,
    /// A Bazel workspace (`WORKSPACE`/`MODULE.bazel`/`BUILD.bazel`). No native
    /// compile DB, so we run `bazel build` under compiler interception.
    Bazel,
    /// An SCons project (`SConstruct`). Run `scons` under compiler interception.
    SCons,
    None,
}

/// Detect the project's build system from the marker files at the tree root.
/// CMake takes precedence (it emits a DB natively and runs codegen at configure
/// time); then a Visual Studio solution/project; then Make.
pub fn detect_build_system(tree: &Path) -> BuildSystem {
    if tree.join("CMakeLists.txt").is_file() {
        return BuildSystem::CMake;
    }
    // Meson before Make: a Meson tree often also ships a convenience Makefile
    // wrapper, but `meson setup` emits a native DB and runs codegen.
    if tree.join("meson.build").is_file() {
        return BuildSystem::Meson;
    }
    if find_msbuild_project(tree).is_some() {
        return BuildSystem::MSBuild;
    }
    if ["Makefile", "makefile", "GNUmakefile", "configure"]
        .iter()
        .any(|name| tree.join(name).is_file())
    {
        return BuildSystem::Make;
    }
    // Standalone Ninja: a `build.ninja` at the tree root with no higher-level
    // generator. (CMake/Meson keep theirs inside a build dir.)
    if tree.join("build.ninja").is_file() {
        return BuildSystem::Ninja;
    }
    // Bazel / SCons have no native compile DB; we run them under interception.
    if [
        "WORKSPACE",
        "WORKSPACE.bazel",
        "MODULE.bazel",
        "BUILD.bazel",
    ]
    .iter()
    .any(|name| tree.join(name).is_file())
    {
        return BuildSystem::Bazel;
    }
    if tree.join("SConstruct").is_file() {
        return BuildSystem::SCons;
    }
    BuildSystem::None
}

/// Find a single nested project root under a packaging/wrapper directory.
/// Source drops commonly unpack as `<wrapper>/<project>/CMakeLists.txt`; probing
/// only the user-supplied wrapper silently misses the real build and degrades to
/// stubs. Ambiguous monorepos are deliberately left alone rather than choosing
/// one component arbitrarily.
fn unique_nested_build_root(tree: &Path) -> Option<PathBuf> {
    let mut stack = vec![(tree.to_path_buf(), 0usize)];
    let mut found = Vec::new();
    while let Some((dir, depth)) = stack.pop() {
        if depth >= 3 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        children.sort();
        for child in children.into_iter().rev() {
            let name = child
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "build" | "builds" | "target" | "out" | "dist" | "node_modules"
                )
            {
                continue;
            }
            if detect_build_system(&child) != BuildSystem::None {
                found.push(child);
                if found.len() > 1 {
                    return None;
                }
            } else {
                stack.push((child, depth + 1));
            }
        }
    }
    found.pop()
}

/// The build command run under compiler interception for a build system with no
/// native compile database. `None` for the systems probed natively.
fn interception_build_command(bs: BuildSystem) -> Option<&'static str> {
    match bs {
        // `--spawn_strategy=local` disables Bazel's action sandbox so our
        // PATH/LD_PRELOAD interception sees the real compiler invocations.
        BuildSystem::Bazel => Some("bazel build --spawn_strategy=local //..."),
        BuildSystem::SCons => Some("scons"),
        _ => None,
    }
}

/// Find a Visual Studio solution (preferred) or project under `tree`, scanning a
/// few directory levels (VS solutions commonly live in `projects/vstudio/`,
/// `msvc/`, `build/`, etc.). Returns the `.sln` if any, else the first `.vcxproj`.
fn find_msbuild_project(tree: &Path) -> Option<PathBuf> {
    let mut vcxproj: Option<PathBuf> = None;
    let mut stack = vec![(tree.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // Skip output/VCS dirs; bound the depth so a huge tree is cheap.
                if depth < 4 && !name.starts_with('.') && name != "target" && name != "node_modules"
                {
                    stack.push((path, depth + 1));
                }
            } else {
                match path.extension().and_then(|e| e.to_str()) {
                    Some("sln") => return Some(path),
                    Some("vcxproj") if vcxproj.is_none() => vcxproj = Some(path),
                    _ => {}
                }
            }
        }
    }
    vcxproj
}

/// MSBuild tier: recover a Visual Studio project's compile wiring by PARSING its
/// `.vcxproj` files (include dirs, preprocessor defines, source files) into a
/// `compile_commands.json`. Unlike the CMake/Make tiers this does NOT execute the
/// build — it reads the project XML — so it needs no `msbuild` on PATH and runs
/// the same on any host. govfuzz then builds each harness with the project's real
/// `-I`/`-D` flags + clang coverage. (Headers produced by a custom build step are
/// not materialized — a follow-up; most C/C++ projects declare their wiring.)
fn probe_msbuild(tree: &Path, db: &Path) -> Option<PathBuf> {
    let projects = msbuild_project_files(tree);
    let mut entries = Vec::new();
    for proj in &projects {
        entries.extend(vcxproj_entries(proj));
    }
    if entries.is_empty() {
        gfeprintln!(
            "govfuzz auto: MSBuild probe found a VS solution/project under {} but no \
             ClCompile sources to map",
            tree.display()
        );
        return None;
    }
    let json = serde_json::to_vec_pretty(&entries).ok()?;
    std::fs::write(db, json).ok()?;
    Some(db.to_path_buf())
}

/// The `.vcxproj` files of the solution: parsed from a `.sln`'s `Project(...)`
/// lines when a solution is present, else every `.vcxproj` found under the tree.
fn msbuild_project_files(tree: &Path) -> Vec<PathBuf> {
    match find_msbuild_project(tree) {
        Some(p) if p.extension().and_then(|e| e.to_str()) == Some("sln") => {
            let projects = parse_sln_projects(&p);
            if projects.is_empty() {
                collect_vcxproj(tree)
            } else {
                projects
            }
        }
        _ => collect_vcxproj(tree),
    }
}

/// Resolve the `.vcxproj` paths referenced by a `.sln`. Solution lines read:
/// `Project("{GUID}") = "Name", "rel\path\Name.vcxproj", "{GUID}"` — the path is
/// the second quoted field, relative to the solution dir, with `\` separators.
fn parse_sln_projects(sln: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(sln) else {
        return Vec::new();
    };
    let sln_dir = sln.parent().unwrap_or_else(|| Path::new("."));
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.trim_start().starts_with("Project(") {
            continue;
        }
        let quoted: Vec<&str> = line.split('"').collect();
        if let Some(rel) = quoted.get(3) {
            if rel.to_ascii_lowercase().ends_with(".vcxproj") {
                let rel_norm = rel.replace('\\', std::path::MAIN_SEPARATOR_STR);
                let abs = resolve_against(sln_dir, &rel_norm);
                if abs.is_file() {
                    out.push(abs);
                }
            }
        }
    }
    out
}

/// Every `.vcxproj` under `tree` (bounded scan), for when there is no `.sln` or
/// it lists no resolvable projects.
fn collect_vcxproj(tree: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(tree.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth < 4 {
                    stack.push((path, depth + 1));
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("vcxproj") {
                out.push(path);
            }
        }
    }
    out
}

/// Parse one `.vcxproj` into compile entries — one per `ClCompile` source, each
/// carrying the project's include dirs (`-I`) and preprocessor defines (`-D`).
/// `$(ProjectDir)`/`$(SolutionDir)`/`$(MSBuildProjectDirectory)` resolve to the
/// project directory; inherited `%(...)` placeholders and empty tokens are
/// dropped; relative paths resolve against the project dir.
fn vcxproj_entries(vcxproj: &Path) -> Vec<ProbeEntry> {
    let Ok(text) = std::fs::read_to_string(vcxproj) else {
        return Vec::new();
    };
    let proj_dir = vcxproj.parent().unwrap_or_else(|| Path::new("."));
    let proj_dir_rendered = harness_gen::build_safety::make_path(proj_dir);
    let proj_dir_slash = format!("{proj_dir_rendered}/");
    let resolve_macros = |raw: &str| -> String {
        raw.replace("$(ProjectDir)", &proj_dir_slash)
            .replace("$(MSBuildProjectDirectory)", &proj_dir_rendered)
            .replace("$(SolutionDir)", &proj_dir_slash)
    };
    // Union every declared include dir + define across the file. Over-approxing
    // is harmless — extra `-I`/`-D` never break a build — and sidesteps having to
    // model per-configuration `Condition=` selection.
    let mut include_dirs: Vec<String> = Vec::new();
    for raw in tag_values(&text, "AdditionalIncludeDirectories") {
        for piece in raw.split(';') {
            let piece = piece.trim();
            if piece.is_empty() || piece.starts_with("%(") {
                continue;
            }
            let abs = resolve_against(proj_dir, &resolve_macros(piece));
            let s = harness_gen::build_safety::make_path(&abs);
            if !include_dirs.contains(&s) {
                include_dirs.push(s);
            }
        }
    }
    // The project dir itself is always an include root (for `#include "sibling.h"`).
    let proj_dir_s = proj_dir_rendered;
    if !include_dirs.contains(&proj_dir_s) {
        include_dirs.push(proj_dir_s);
    }
    let mut defines: Vec<String> = Vec::new();
    for raw in tag_values(&text, "PreprocessorDefinitions") {
        for piece in raw.split(';') {
            let piece = piece.trim();
            if piece.is_empty() || piece.starts_with("%(") {
                continue;
            }
            if !defines.contains(&piece.to_owned()) {
                defines.push(piece.to_owned());
            }
        }
    }
    let mut base_args = vec!["clang".to_owned()];
    base_args.extend(include_dirs.iter().map(|d| format!("-I{d}")));
    base_args.extend(defines.iter().map(|d| format!("-D{d}")));
    let mut entries = Vec::new();
    for src in clcompile_sources(&text) {
        let rel = src.replace('\\', std::path::MAIN_SEPARATOR_STR);
        let file = resolve_against(proj_dir, &rel);
        if !file.is_file() {
            continue;
        }
        let mut arguments = base_args.clone();
        arguments.push("-c".to_owned());
        arguments.push(file.display().to_string());
        entries.push(ProbeEntry {
            directory: proj_dir.to_path_buf(),
            file,
            arguments,
        });
    }
    entries
}

/// Inner texts of every `<TAG ...>...</TAG>` occurrence (tolerates attributes on
/// the open tag, e.g. `<TAG Condition="...">`).
fn tag_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(o) = rest.find(&open) {
        let after_open = &rest[o + open.len()..];
        let Some(gt) = after_open.find('>') else {
            break;
        };
        let body = &after_open[gt + 1..];
        let Some(c) = body.find(&close) else {
            break;
        };
        out.push(body[..c].trim().to_owned());
        rest = &body[c + close.len()..];
    }
    out
}

/// The `Include="..."` paths of every `<ClCompile Include="...">` element.
fn clcompile_sources(xml: &str) -> Vec<String> {
    let needle = "<ClCompile Include=\"";
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i + needle.len()..];
        let Some(q) = after.find('"') else {
            break;
        };
        out.push(after[..q].to_owned());
        rest = &after[q + 1..];
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeEntry {
    directory: PathBuf,
    file: PathBuf,
    arguments: Vec<String>,
}

/// The `sh` wrapper set as `CC`/`CXX` for the Make tier. It appends a record
/// (working directory, then one `ARG` line per argument, then `ENDREC`) to the
/// log and execs the real compiler so the build still proceeds and produces its
/// generated headers/objects.
fn cc_wrapper_script() -> &'static str {
    "#!/bin/sh\n\
     {\n\
     printf '%s\\n' \"$PWD\"\n\
     for a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done\n\
     printf 'ENDREC\\n'\n\
     } >> \"$GF_CC_LOG\"\n\
     exec \"$GF_REAL_CC\" \"$@\"\n"
}

/// Whether a wrapper argument names a C/C++ translation unit (the entry's
/// `file`).
fn is_source_arg(arg: &str) -> bool {
    matches!(
        Path::new(arg).extension().and_then(|e| e.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "c++" | "C")
    )
}

/// Convert the Make-tier wrapper log into compile-database entries. `real_cc` is
/// prepended as `arguments[0]` so the entry is a complete compile command.
fn parse_cc_log(log: &str, real_cc: &str) -> Vec<ProbeEntry> {
    let mut entries = Vec::new();
    let mut directory: Option<&str> = None;
    let mut args: Vec<String> = Vec::new();
    for line in log.lines() {
        if line == "ENDREC" {
            if let (Some(dir), Some(file)) =
                (directory, args.iter().find(|a| is_source_arg(a)).cloned())
            {
                let mut arguments = Vec::with_capacity(args.len() + 1);
                arguments.push(real_cc.to_owned());
                arguments.extend(args.iter().cloned());
                let file_path = resolve_against(Path::new(dir), &file);
                entries.push(ProbeEntry {
                    directory: PathBuf::from(dir),
                    file: file_path,
                    arguments,
                });
            }
            directory = None;
            args.clear();
        } else if let Some(arg) = line.strip_prefix("ARG ") {
            args.push(arg.to_owned());
        } else {
            directory = Some(line);
        }
    }
    entries
}

fn resolve_against(dir: &Path, file: &str) -> PathBuf {
    let p = Path::new(file);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(p)
    }
}

fn find_on_path(program: &str) -> bool {
    program_on_path(program).is_some()
}

fn program_on_path(program: &str) -> Option<PathBuf> {
    let candidates = executable_candidates_for(
        program,
        cfg!(windows),
        std::env::var("PATHEXT").ok().as_deref(),
    );
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            candidates
                .iter()
                .map(|name| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    })
}

/// On-disk filenames to try for an executable named `program`, given the target
/// platform. On Windows an executable is resolved through its extension
/// (`PATHEXT`) — e.g. `cmake` lives on disk as `cmake.exe`, so a bare-name lookup
/// finds nothing — so try the bare name plus each PATHEXT suffix. On Unix the bare
/// name is the executable. Pure (platform + PATHEXT passed in) so it is
/// unit-testable off-Windows.
fn executable_candidates_for(program: &str, windows: bool, pathext: Option<&str>) -> Vec<String> {
    if !windows || std::path::Path::new(program).extension().is_some() {
        return vec![program.to_owned()];
    }
    let mut out = vec![program.to_owned()];
    for ext in pathext
        .unwrap_or(".COM;.EXE;.BAT;.CMD")
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let ext = ext.strip_prefix('.').unwrap_or(ext);
        out.push(format!("{program}.{}", ext.to_ascii_lowercase()));
    }
    out
}

/// Resolve a *working* sandbox launcher (`bwrap` preferred, then `firejail`) for
/// wrapping the build, or `None` when neither is installed or usable. The launch
/// is probed with a trivial `true` so a denied user/namespace (containers, CI)
/// degrades to a direct run instead of failing the whole probe.
pub fn resolve_sandbox_program() -> Option<PathBuf> {
    if let Some(bwrap) = program_on_path("bwrap") {
        if sandbox_launches(&bwrap, &bwrap_fs_args()) {
            return Some(bwrap);
        }
    }
    if let Some(firejail) = program_on_path("firejail") {
        if sandbox_launches(&firejail, &["--quiet".to_owned(), "--noprofile".to_owned()]) {
            return Some(firejail);
        }
    }
    None
}

/// Bubblewrap arguments for filesystem isolation (read-only system, private
/// `/proc` `/dev` `/tmp`). Network is intentionally NOT unshared — that needs a
/// network namespace many containers deny, and the build is offline regardless;
/// the security win here is the read-only root.
fn bwrap_fs_args() -> Vec<String> {
    let mut args = vec![
        "--die-with-parent".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
    ];
    for ro in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"] {
        if Path::new(ro).exists() {
            args.push("--ro-bind".to_owned());
            args.push(ro.to_owned());
            args.push(ro.to_owned());
        }
    }
    args
}

/// Whether `program` with `args` can launch a trivial `true` — i.e. the sandbox
/// is actually usable in this environment.
fn sandbox_launches(program: &Path, args: &[String]) -> bool {
    Command::new(program)
        .args(args)
        .args(["--", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Pick the real compiler the Make wrapper should exec: the first of
/// `cc`/`gcc`/`clang` found on PATH.
fn real_compiler() -> Option<String> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|c| find_on_path(c))
        .map(str::to_owned)
}

/// Run the project's own build offline to produce `<tree>/.govfuzz-build/
/// compile_commands.json`, returning its path on success. `sandbox_program` is
/// the resolved `bwrap`/`firejail` binary to wrap the build in, or `None` for a
/// direct run (caller's policy). Best-effort: any failure logs a warning and
/// returns `None` so auto proceeds with its existing detection/repair path.
pub fn probe_build(
    tree: &Path,
    sandbox_program: Option<&Path>,
    sanitizers: &multicore_fuzz::SanitizerSelection,
) -> Option<PathBuf> {
    let root_build_system = detect_build_system(tree);
    let nested_root = (root_build_system == BuildSystem::None)
        .then(|| unique_nested_build_root(tree))
        .flatten();
    let build_root = nested_root.as_deref().unwrap_or(tree);
    if build_root != tree {
        gfeprintln!(
            "govfuzz auto: --probe-build: using the sole nested project root {}",
            build_root.display()
        );
    }
    let probe_dir = build_root.join(PROBE_DIR);
    // This directory is govfuzz-owned build output. Reusing a CMakeCache or an
    // archive from a prior sanitizer selection can make configuration lie about
    // its compiler and can link ASan objects into a `--sanitizers none` harness.
    // Start each explicit probe from a clean, exact build context.
    if probe_dir.exists() && std::fs::remove_dir_all(&probe_dir).is_err() {
        return None;
    }
    if std::fs::create_dir_all(&probe_dir).is_err() {
        return None;
    }
    let _ = std::fs::remove_file(probe_dir.join(PROBE_REQUIREMENTS_FILE));
    let db = probe_dir.join("compile_commands.json");
    let instrumentation = ProbeInstrumentation::for_selection(sanitizers);
    let build_system = detect_build_system(build_root);
    if build_system == BuildSystem::CMake {
        request_cmake_file_api(&probe_dir);
    }
    let recovered = match build_system {
        BuildSystem::CMake => probe_cmake(
            build_root,
            &probe_dir,
            &db,
            sandbox_program,
            &instrumentation,
        ),
        BuildSystem::Meson => probe_meson(build_root, &probe_dir, &db, sandbox_program),
        BuildSystem::MSBuild => probe_msbuild(build_root, &db),
        BuildSystem::Make => probe_make(build_root, &probe_dir, &db, sandbox_program),
        BuildSystem::Ninja => probe_ninja(build_root, &db, sandbox_program),
        bs @ (BuildSystem::Bazel | BuildSystem::SCons) => {
            // No native compile DB: run the build's own command under compiler
            // interception (the PATH shim + LD_PRELOAD exec shim recover flags).
            let command = interception_build_command(bs).expect("bazel/scons command");
            gfeprintln!(
                "govfuzz auto: --probe-build: intercepting `{command}` to recover compile flags"
            );
            probe_build_command(build_root, command, sandbox_program, sanitizers)
        }
        BuildSystem::None => {
            gfeprintln!(
                "govfuzz auto: --probe-build found no CMake/Meson/MSBuild/Make/Ninja/Bazel/SCons \
                 build at {} (use --build-command \"<cmd>\" to intercept a custom build)",
                tree.display()
            );
            None
        }
    };
    if build_root != tree {
        // Requirements are normally recorded beside the probe output. Mirror
        // them to the scanned wrapper root so the final dependency checkpoint
        // does not lose configure/build failures from the nested project.
        for requirement in load_probe_requirements(build_root) {
            record_probe_requirement(tree, requirement);
        }
    }
    recovered
}

fn request_cmake_file_api(probe_dir: &Path) {
    let query = probe_dir.join(".cmake/api/v1/query/codemodel-v2");
    if let Some(parent) = query.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(query, b"");
}

/// Static-library target names from CMake's file-api codemodel. Building these
/// instead of `all` avoids compiling hundreds of test/tool objects after the
/// reusable library is already complete. The query is requested before
/// configure; malformed/unsupported replies simply return an empty list and the
/// caller retains its `all` fallback.
fn cmake_static_library_target_artifacts(probe_dir: &Path) -> Vec<(String, Vec<PathBuf>)> {
    let reply = probe_dir.join(".cmake/api/v1/reply");
    let mut indexes: Vec<PathBuf> = std::fs::read_dir(&reply)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("index-") && name.ends_with(".json"))
        })
        .collect();
    indexes.sort();
    let index: serde_json::Value = indexes
        .last()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    let Some(codemodel_file) = index
        .get("objects")
        .and_then(|objects| objects.as_array())
        .and_then(|objects| {
            objects.iter().find_map(|object| {
                (object.get("kind").and_then(|kind| kind.as_str()) == Some("codemodel"))
                    .then(|| object.get("jsonFile").and_then(|file| file.as_str()))
                    .flatten()
            })
        })
    else {
        return Vec::new();
    };
    let codemodel: serde_json::Value = std::fs::read(reply.join(codemodel_file))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    let mut targets = Vec::new();
    for target in codemodel
        .pointer("/configurations/0/targets")
        .and_then(|targets| targets.as_array())
        .into_iter()
        .flatten()
    {
        let Some(file) = target.get("jsonFile").and_then(|file| file.as_str()) else {
            continue;
        };
        let detail: serde_json::Value = std::fs::read(reply.join(file))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(serde_json::Value::Null);
        if detail.get("type").and_then(|kind| kind.as_str()) == Some("STATIC_LIBRARY") {
            if let Some(name) = detail.get("name").and_then(|name| name.as_str()) {
                let artifacts = detail
                    .get("artifacts")
                    .and_then(|artifacts| artifacts.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|artifact| artifact.get("path").and_then(|path| path.as_str()))
                    .map(PathBuf::from)
                    .collect();
                targets.push((name.to_owned(), artifacts));
            }
        }
    }
    targets.sort_by(|left, right| left.0.cmp(&right.0));
    targets.dedup_by(|left, right| left.0 == right.0);
    targets
}

fn cmake_static_library_targets(probe_dir: &Path) -> Vec<String> {
    cmake_static_library_target_artifacts(probe_dir)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Run the project's own Ada build (`alr build`, else `gprbuild`) so it
/// materializes generated dependencies — the Alire configuration package, any
/// `.gpr`-declared codegen — into the tree, where govfuzz's normal Ada flow then
/// picks them up. Only invoked under `--run-untrusted` (it executes the
/// project's build). Best-effort + graceful: no Ada project, or no toolchain,
/// logs and returns. `alr` is preferred because it also resolves+fetches the
/// crate's dependencies; `gprbuild` is the offline fallback.
pub fn probe_ada_build(tree: &Path, sandbox_program: Option<&Path>) {
    let has_alire = tree.join("alire.toml").is_file();
    let gpr = first_gpr(tree);
    if !has_alire && gpr.is_none() {
        gfeprintln!("govfuzz auto: --run-untrusted: no Ada project (alire.toml/.gpr) at {}; skipping Ada build probe", tree.display());
        return;
    }
    if has_alire && find_on_path("alr") {
        gfeprintln!("govfuzz auto: --run-untrusted: running `alr build` to generate Alire config + fetch deps");
        run_build(
            tree,
            &["alr".to_owned(), "-n".to_owned(), "build".to_owned()],
            &[],
            sandbox_program,
        );
        return;
    }
    if let Some(gpr) = gpr {
        if find_on_path("gprbuild") {
            gfeprintln!(
                "govfuzz auto: --run-untrusted: running `gprbuild -p -P {}` to run gpr codegen",
                gpr.display()
            );
            run_build(
                tree,
                &[
                    "gprbuild".to_owned(),
                    "-p".to_owned(),
                    "-P".to_owned(),
                    gpr.display().to_string(),
                ],
                &[],
                sandbox_program,
            );
            return;
        }
    }
    gfeprintln!(
        "govfuzz auto: --run-untrusted: no Ada build tool available (need `alr` or `gprbuild`); skipping Ada build probe"
    );
}

/// First `*.gpr` directly in `tree` (deterministic by name), if any.
fn first_gpr(tree: &Path) -> Option<PathBuf> {
    let mut gprs: Vec<PathBuf> = std::fs::read_dir(tree)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("gpr")))
        .collect();
    gprs.sort();
    gprs.into_iter().next()
}

fn probe_cmake(
    tree: &Path,
    probe_dir: &Path,
    db: &Path,
    sandbox_program: Option<&Path>,
    instrumentation: &ProbeInstrumentation,
) -> Option<PathBuf> {
    if !find_on_path("cmake") {
        gfeprintln!("govfuzz auto: --probe-build: cmake not on PATH; skipping CMake probe");
        record_probe_requirement(
            tree,
            ProbeRequirement {
                kind: crate::auto::dep_manifest::DepKind::CodegenTool,
                name: "cmake".to_owned(),
                acquisition_hint: "install a CMake version compatible with this project's CMakeLists.txt"
                    .to_owned(),
                evidence: "CMakeLists.txt is present and the requested build probe found no cmake executable on PATH"
                    .to_owned(),
            },
        );
        return None;
    }
    let cmake_source = cmake_source_with_local_dependencies(tree, probe_dir);
    let args = cmake_probe_args(
        &cmake_source,
        probe_dir,
        cfg!(windows),
        find_on_path("ninja"),
        instrumentation,
    );
    // Capture (rather than inherit) cmake's output so a missing-dependency
    // configure abort can be reported ACTIONABLY (§26.2). The output is replayed
    // to the parent streams afterwards so build progress/errors stay visible.
    let mut command = build_command(tree, &args, &[], sandbox_program);
    let output = match crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(600),
    ) {
        Ok(output) => output,
        Err(error) => {
            gfeprintln!("govfuzz auto: --probe-build: failed to run cmake: {error}");
            return None;
        }
    };
    use std::io::Write;
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    if db.is_file() {
        // Configure alone recovers flags but produces no library to reuse. Build
        // the project now, under the same opt-in sandbox and with clang's exact
        // harness instrumentation. A partial build is still valuable: library
        // targets normally precede optional tools/tests, and any archive left on
        // disk can close a stateful harness in one link instead of a 16-round
        // source-addition cascade.
        let static_targets = cmake_static_library_targets(probe_dir);
        let mut build_args = vec![
            "cmake".to_owned(),
            "--build".to_owned(),
            probe_dir.display().to_string(),
            "--parallel".to_owned(),
        ];
        if !static_targets.is_empty() {
            build_args.push("--target".to_owned());
            build_args.extend(static_targets.iter().cloned());
            gfeprintln!(
                "govfuzz auto: --probe-build: building {} static library target(s), skipping project tests/tools",
                static_targets.len()
            );
        }
        let build_succeeded = run_build(tree, &build_args, &[], sandbox_program);
        write_probe_artifact_manifest(tree, instrumentation, build_succeeded);
        return Some(db.to_path_buf());
    }
    // No database means the configure failed. The single most common — and most
    // actionable — cause is a REQUIRED external dependency `find_package` could
    // not locate (libspng's `find_package(ZLIB REQUIRED)`), which aborts the
    // configure before any compile_commands.json is written, so EVERY target
    // would otherwise fail to build with a generic "no compile_commands.json".
    // Name the missing package instead (§26.2).
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match cmake_missing_dependency(&combined) {
        Some(pkg) => {
            record_probe_requirement(
                tree,
                ProbeRequirement {
                    kind: crate::auto::dep_manifest::DepKind::SharedLibrary,
                    name: pkg.clone(),
                    acquisition_hint: format!(
                        "stage the development package/source for CMake package '{pkg}', or set {pkg}_ROOT/CMAKE_PREFIX_PATH to its offline location"
                    ),
                    evidence: format!(
                        "CMake configure reported `Could NOT find {pkg}` for a required find_package dependency"
                    ),
                },
            );
            gfeprintln!(
                "govfuzz auto: --probe-build: CMake configure FAILED — required dependency `{pkg}` was \
             not found (`find_package({pkg} REQUIRED)`). This aborted the whole probe, so no \
             compile_commands.json was produced and every target will fail to build until it is \
             resolved. Install `{pkg}` (its dev headers/library) or point CMake at it (e.g. set \
             `{pkg}_ROOT`/`CMAKE_PREFIX_PATH`), then re-run with --probe-build."
            )
        }
        None => gfeprintln!(
            "govfuzz auto: --probe-build: `cmake` configure produced no compile_commands.json at {}",
            db.display()
        ),
    }
    None
}

/// Parse a CMake configure log for a REQUIRED dependency that `find_package`
/// could not locate — the `Could NOT find <Pkg> (missing: ...)` message
/// `FindPackageHandleStandardArgs` prints right before aborting the configure.
/// Returns the package name so the probe can report which dependency blocked the
/// whole configure (§26.2) instead of a generic "no compile_commands.json". Pure
/// so it is unit-testable without running cmake.
fn cmake_missing_dependency(output: &str) -> Option<String> {
    const NEEDLE: &str = "Could NOT find ";
    for line in output.lines() {
        let Some(idx) = line.find(NEEDLE) else {
            continue;
        };
        let rest = &line[idx + NEEDLE.len()..];
        // The package name is the first token; stop at a space, `(missing: ...)`,
        // or a trailing version/colon qualifier.
        let pkg = rest.split([' ', '(', ':', ',']).next().unwrap_or("").trim();
        if !pkg.is_empty() {
            return Some(pkg.to_owned());
        }
    }
    None
}

/// Out-of-source build directories — the govfuzz probe dir plus the conventional
/// CMake/Meson ones — searched for a project's already-built static libraries
/// (§26.1) and CMake-generated headers (§26.8), relative to the scanned tree.
const RECOVERED_ARTIFACT_DIRS: &[&str] = &[
    PROBE_DIR,
    "build",
    "builddir",
    "out",
    "cmake-build-debug",
    "cmake-build-release",
];

/// Maximum recursion depth when walking a build/probe dir for recovered
/// artifacts. CMake nests archives a few levels deep (`build/lib/libfoo.a`); a
/// bound keeps a pathological tree cheap.
const RECOVERED_ARTIFACT_MAX_DEPTH: u32 = 6;

/// Discover a project's already-built static libraries (`*.a`) under the scanned
/// tree's build / probe directories, for ROADMAP §26.1 whole-library linking.
///
/// A harness for a function in a multi-TU library links only `main` + the
/// target's own source, so it fails with undefined references to every sibling
/// translation unit (zstd's `lib/common`/`lib/compress`, miniz). When the
/// project has already been built and shipped its static archive, linking that
/// whole archive resolves the library's symbols in one shot — and reaches a
/// symbol whose `.c` was never shipped in the source tree, which the
/// symbol-by-symbol `AddSource` repair cannot. Bounded recursive walk so a
/// nested `build/lib/libfoo.a` is found; deterministically sorted.
pub fn discover_static_libraries(tree: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Autotools/configure projects commonly build their reusable archive in
    // the source root even though govfuzz keeps interception metadata under
    // `.govfuzz-build` (SQLite's `libsqlite3.a` is the representative case).
    // Inspect direct children only: recursive source-tree archive discovery
    // would accidentally mix vendored/host-platform libraries into the link.
    collect_static_libraries(tree, RECOVERED_ARTIFACT_MAX_DEPTH, &mut out);
    for sub in RECOVERED_ARTIFACT_DIRS {
        collect_static_libraries(&tree.join(sub), 0, &mut out);
    }
    for probe in probe_dirs_under(tree) {
        collect_static_libraries(&probe, 0, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

/// Archives produced by THIS govfuzz probe under the exact native
/// sanitizer/coverage selection in force for the current run. These may be
/// linked proactively: unlike an arbitrary `build/libfoo.a`, their object code
/// participates in the same edge map and sanitizer runtime as the generated
/// harness. A partial project build is acceptable when it left a usable archive
/// behind; many projects build the library successfully and fail only while
/// linking optional tools/tests.
pub fn compatible_probe_static_libraries(
    tree: &Path,
    selection: &multicore_fuzz::SanitizerSelection,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let expected = ProbeInstrumentation::for_selection(selection);
    for probe in probe_dirs_under(tree) {
        let compatible = std::fs::read(probe.join(PROBE_ARTIFACTS_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ProbeArtifactManifest>(&bytes).ok())
            .is_some_and(|manifest| {
                manifest.schema_version == 1
                    && manifest.build_attempted
                    && manifest.instrumentation == expected
            });
        if compatible {
            collect_static_libraries(&probe, 0, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Govfuzz-owned primary probe directories at the scan root or beneath a
/// shallow packaging wrapper. This is intentionally much narrower than a walk
/// for arbitrary build directories: the exact directory name plus its
/// instrumentation manifest is the trust/compatibility boundary.
fn probe_dirs_under(tree: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![(tree.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let direct = dir.join(PROBE_DIR);
        if direct.is_dir() {
            found.push(direct);
        }
        if depth >= 3 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "build" | "builds" | "target" | "out" | "dist" | "node_modules"
                )
            {
                continue;
            }
            stack.push((path, depth + 1));
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Whether `path` is a static library inside govfuzz's owned primary build
/// probe. Coverage replay treats these specially: they contain the fuzz lane's
/// sanitizer/edge instrumentation and therefore cannot be passed unchanged to
/// the source-coverage link.
pub fn is_probe_static_library(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("a"))
        && owning_probe_tree_and_relative(path).is_some()
}

fn owning_probe_tree_and_relative(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    for ancestor in path.ancestors() {
        if ancestor.file_name().and_then(|name| name.to_str()) == Some(PROBE_DIR) {
            let tree = ancestor.parent()?.to_path_buf();
            let relative = path.strip_prefix(ancestor).ok()?.to_path_buf();
            return Some((tree, relative));
        }
    }
    None
}

/// Build (once per project/target) and return the source-coverage counterpart of
/// a primary CMake probe archive. The CMake file API maps the concrete archive
/// back to its target, so replay builds exactly that target rather than `all`.
///
/// Returning `None` is deliberate: linking the primary ASan archive into the
/// coverage lane is neither an equivalent program nor, in practice, linkable.
/// Coverage replay must report no measurement when an exact variant cannot be
/// produced.
pub fn coverage_variant_for_probe_archive(archive: &Path) -> Option<PathBuf> {
    let (tree, relative) = owning_probe_tree_and_relative(archive)?;
    if detect_build_system(&tree) != BuildSystem::CMake {
        return coverage_variant_for_intercept_archive(&tree, archive, &relative);
    }
    if !find_on_path("cmake") {
        return None;
    }
    let coverage_probe = tree.join(COVERAGE_PROBE_DIR);
    let instrumentation = ProbeInstrumentation::for_source_coverage();
    let compatible_configuration = std::fs::read(coverage_probe.join(PROBE_ARTIFACTS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ProbeArtifactManifest>(&bytes).ok())
        .is_some_and(|manifest| {
            manifest.schema_version == 1
                && manifest.build_attempted
                && manifest.build_succeeded
                && manifest.instrumentation == instrumentation
        });

    // A target with a large static dependency closure can build every archive
    // while resolving the first member (RE2 builds its in-tree Abseil closure
    // this way).  The remaining members already have exact, same-relative-path
    // counterparts in the compatible coverage tree.  Return those artifacts
    // directly: requiring the primary tree's optional file-API/link metadata
    // again makes a usable coverage archive disappear when CMake cleans or
    // omits metadata for just one transitive target.
    let same_relative_coverage_archive = coverage_probe.join(&relative);
    if compatible_configuration && same_relative_coverage_archive.is_file() {
        return Some(same_relative_coverage_archive);
    }

    let primary_probe = tree.join(PROBE_DIR);
    let primary_archive = primary_probe.join(&relative);
    let primary_archive = primary_archive.canonicalize().unwrap_or(primary_archive);
    let (target, artifact_relative) = cmake_static_library_target_artifacts(&primary_probe)
        .into_iter()
        .find_map(|(target, artifacts)| {
            artifacts.into_iter().find_map(|artifact| {
                let candidate = primary_probe.join(&artifact);
                let candidate = candidate.canonicalize().unwrap_or(candidate);
                (candidate == primary_archive).then_some((target.clone(), artifact))
            })
        })
        // A generated dependency-closure superproject can lose CMake's file-API
        // reply even though its ordinary Make metadata is complete.  The target
        // link script is an equally exact mapping: it names both the CMake target
        // (`CMakeFiles/<target>.dir`) and the concrete archive written by `ar`.
        .or_else(|| cmake_archive_target_from_link_script(&primary_probe, &primary_archive))?;

    if !compatible_configuration {
        if coverage_probe.exists() && std::fs::remove_dir_all(&coverage_probe).is_err() {
            return None;
        }
        std::fs::create_dir_all(&coverage_probe).ok()?;
        request_cmake_file_api(&coverage_probe);
        let cmake_source = cmake_source_with_local_dependencies(&tree, &coverage_probe);
        let configure = cmake_probe_args(
            &cmake_source,
            &coverage_probe,
            cfg!(windows),
            find_on_path("ninja"),
            &instrumentation,
        );
        let sandbox = resolve_sandbox_program();
        let configured = run_build(&tree, &configure, &[], sandbox.as_deref());
        // Some dependency superprojects generate a complete, usable build graph
        // and compile database, then return failure solely because an install()
        // export cannot include vendored targets (RE2 + in-tree Abseil).  This is
        // irrelevant to a named archive build.  Match the primary probe's
        // partial-configure policy: proceed only when CMake left concrete build
        // metadata that can execute the exact target below.
        let usable_partial_configuration = coverage_probe.join("compile_commands.json").is_file()
            && (coverage_probe.join("Makefile").is_file()
                || coverage_probe.join("build.ninja").is_file());
        if !configured && !usable_partial_configuration {
            write_artifact_manifest_at(&coverage_probe, &instrumentation, false);
            return None;
        }
        // The configuration itself is now reusable. The target build below
        // overwrites this with `false` if it fails.
        write_artifact_manifest_at(&coverage_probe, &instrumentation, true);
    }

    let coverage_archive = coverage_probe.join(artifact_relative);
    if !coverage_archive.is_file() {
        let build = vec![
            "cmake".to_owned(),
            "--build".to_owned(),
            coverage_probe.display().to_string(),
            "--parallel".to_owned(),
            "--target".to_owned(),
            target.clone(),
        ];
        gfeprintln!(
            "govfuzz auto: coverage replay: building CMake target `{target}` with source coverage"
        );
        let sandbox = resolve_sandbox_program();
        let succeeded = run_build(&tree, &build, &[], sandbox.as_deref());
        write_artifact_manifest_at(&coverage_probe, &instrumentation, succeeded);
        if !succeeded || !coverage_archive.is_file() {
            return None;
        }
    }
    Some(coverage_archive)
}

/// Recover `(target, artifact-relative-path)` from CMake's generated link.txt
/// files when its optional file-API reply is absent. Paths in link scripts are
/// interpreted relative to the sub-build directory that owns `CMakeFiles`, just
/// as generated Makefiles execute them.
fn cmake_archive_target_from_link_script(
    probe_dir: &Path,
    archive: &Path,
) -> Option<(String, PathBuf)> {
    let archive = archive
        .canonicalize()
        .unwrap_or_else(|_| archive.to_path_buf());
    let mut stack = vec![(probe_dir.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth < 12 {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some("link.txt") {
                continue;
            }
            let target_dir = path.parent()?;
            let target_component = target_dir.file_name()?.to_str()?;
            let Some(target) = target_component.strip_suffix(".dir") else {
                continue;
            };
            let cmake_files = target_dir.parent()?;
            if cmake_files.file_name().and_then(|name| name.to_str()) != Some("CMakeFiles") {
                continue;
            }
            let command_dir = cmake_files.parent()?;
            let text = std::fs::read_to_string(&path).ok()?;
            for token in split_cmake_link_command(&text) {
                let candidate = PathBuf::from(&token);
                if !candidate.extension().is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("a") || ext.eq_ignore_ascii_case("lib")
                }) {
                    continue;
                }
                let candidate = if candidate.is_absolute() {
                    candidate
                } else {
                    command_dir.join(candidate)
                };
                let candidate = candidate.canonicalize().unwrap_or(candidate);
                if candidate == archive {
                    let relative = archive.strip_prefix(probe_dir).ok()?.to_path_buf();
                    return Some((target.to_owned(), relative));
                }
            }
        }
    }
    None
}

fn split_cmake_link_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote = None;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(expected), actual) if expected == actual => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), actual) => current.push(actual),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, actual) if actual.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            (None, actual) => current.push(actual),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Rebuild the exact members of an archive produced by a compiler-intercepted
/// configure/Make build with Clang source coverage. The intercepted compile DB
/// preserves each member's real flags and working directory; matching `ar t`
/// member names to `-o` outputs avoids accidentally archiving tool/test `main`
/// objects that happened to be built by the same command.
fn coverage_variant_for_intercept_archive(
    tree: &Path,
    archive: &Path,
    relative: &Path,
) -> Option<PathBuf> {
    let coverage_probe = tree.join(COVERAGE_PROBE_DIR);
    let coverage_archive = coverage_probe.join(relative);
    let instrumentation = ProbeInstrumentation::for_source_coverage();
    let compatible = std::fs::read(coverage_probe.join(PROBE_ARTIFACTS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ProbeArtifactManifest>(&bytes).ok())
        .is_some_and(|manifest| {
            manifest.schema_version == 1
                && manifest.build_attempted
                && manifest.build_succeeded
                && manifest.instrumentation == instrumentation
        });
    if compatible && coverage_archive.is_file() {
        return Some(coverage_archive);
    }

    let ar = ["llvm-ar", "ar"]
        .into_iter()
        .find_map(|program| which::which(program).ok())?;
    let members_output = Command::new(&ar).arg("t").arg(archive).output().ok()?;
    if !members_output.status.success() {
        return None;
    }
    let members = String::from_utf8_lossy(&members_output.stdout)
        .lines()
        .filter_map(|line| Path::new(line).file_name()?.to_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    if members.is_empty() {
        return None;
    }
    let entries: Vec<ProbeEntry> =
        std::fs::read(tree.join(PROBE_DIR).join("compile_commands.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())?;
    let mut selected = BTreeMap::<String, ProbeEntry>::new();
    for entry in entries {
        if !entry.arguments.iter().any(|arg| arg == "-c") {
            continue;
        }
        let output = compile_output_name(&entry.arguments).or_else(|| {
            entry
                .file
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| format!("{stem}.o"))
        });
        let Some(output) = output else { continue };
        if members.contains(&output) {
            selected.entry(output).or_insert(entry);
        }
    }
    if selected.len() != members.len() {
        return None;
    }

    if coverage_probe.exists() && std::fs::remove_dir_all(&coverage_probe).is_err() {
        return None;
    }
    let objects = coverage_probe.join("intercept-objects");
    std::fs::create_dir_all(&objects).ok()?;
    let mut built_objects = Vec::new();
    for (index, (member, entry)) in selected.into_iter().enumerate() {
        let object = objects.join(format!("{index}-{member}"));
        let compiler = if matches!(
            entry.file.extension().and_then(|value| value.to_str()),
            Some("cc" | "cpp" | "cxx" | "c++" | "C")
        ) {
            "clang++"
        } else {
            "clang"
        };
        let mut args = Vec::new();
        let mut skip_next = false;
        for argument in entry.arguments.into_iter().skip(1) {
            if skip_next {
                skip_next = false;
                continue;
            }
            if argument == "-o" {
                skip_next = true;
                continue;
            }
            if argument.starts_with("-o")
                || argument.starts_with("-O")
                || argument.starts_with("-fsanitize")
                || argument.starts_with("-fno-sanitize")
                || argument.starts_with("-fprofile-instr")
                || argument == "-fcoverage-mapping"
            {
                continue;
            }
            args.push(argument);
        }
        args.extend(instrumentation.c_flags.iter().cloned());
        args.push("-o".to_owned());
        args.push(object.display().to_string());
        let status = Command::new(compiler)
            .args(&args)
            .current_dir(&entry.directory)
            .status()
            .ok()?;
        if !status.success() {
            write_artifact_manifest_at(&coverage_probe, &instrumentation, false);
            return None;
        }
        built_objects.push(object);
    }
    std::fs::create_dir_all(coverage_archive.parent()?).ok()?;
    let status = Command::new(ar)
        .arg("rcs")
        .arg(&coverage_archive)
        .args(&built_objects)
        .status()
        .ok()?;
    write_artifact_manifest_at(&coverage_probe, &instrumentation, status.success());
    status.success().then_some(coverage_archive)
}

fn compile_output_name(arguments: &[String]) -> Option<String> {
    for (index, argument) in arguments.iter().enumerate() {
        let output = if argument == "-o" {
            arguments.get(index + 1)?.as_str()
        } else if argument.starts_with("-o") && argument.len() > 2 {
            &argument[2..]
        } else {
            continue;
        };
        return Path::new(output)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
    }
    None
}

/// Exact library-file dependencies CMake used when linking an executable that
/// consumes `archive`. Static archives intentionally carry no transitive-link
/// metadata: linking libarchive.a without the zlib/bzip2/lzma/etc. entries from
/// CMake's link line merely trades internal undefined symbols for external ones,
/// which the repair loop then (incorrectly) stubs. Reuse the concrete resolved
/// `.so`/`.a` paths CMake already proved, in their original order.
pub fn probe_archive_link_dependencies(tree: &Path, archive: &Path) -> Vec<PathBuf> {
    let probe = owning_probe_tree_and_relative(archive)
        .map(|(owner, _)| owner.join(PROBE_DIR))
        .unwrap_or_else(|| tree.join(PROBE_DIR));
    let mut link_files = Vec::new();
    collect_named_files(&probe, 0, "link.txt", &mut link_files);
    link_files.sort();
    let mut dependencies = Vec::new();
    for link_file in link_files {
        let Ok(text) = std::fs::read_to_string(&link_file) else {
            continue;
        };
        let cwd = cmake_link_working_dir(&link_file).unwrap_or(&probe);
        dependencies.extend(libraries_from_cmake_link_text(&text, cwd, archive));
    }
    dependencies.extend(intercept_archive_link_dependencies(tree, archive));
    let archive = archive
        .canonicalize()
        .unwrap_or_else(|_| archive.to_path_buf());
    dependencies.retain(|path| path.canonicalize().unwrap_or_else(|_| path.clone()) != archive);
    let mut seen = BTreeSet::new();
    dependencies.retain(|path| seen.insert(path.clone()));
    dependencies
}

/// Library files used by a successful compiler-intercepted consumer of an
/// archive member. Autotools archives do not have CMake `link.txt` metadata;
/// the intercepted executable/shared-library command is the equivalent source
/// of truth (`sqlite3.c ... -lz` for SQLite). Resolve `-lfoo` through the same
/// compiler so the harness receives a concrete file and preserves the existing
/// extra-source/link ordering machinery.
fn intercept_archive_link_dependencies(tree: &Path, archive: &Path) -> Vec<PathBuf> {
    let ar = ["llvm-ar", "ar"]
        .into_iter()
        .find_map(|program| which::which(program).ok());
    let Some(ar) = ar else { return Vec::new() };
    let Ok(member_output) = Command::new(ar).arg("t").arg(archive).output() else {
        return Vec::new();
    };
    if !member_output.status.success() {
        return Vec::new();
    }
    let members = String::from_utf8_lossy(&member_output.stdout)
        .lines()
        .filter_map(|line| Path::new(line).file_name()?.to_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    if members.is_empty() {
        return Vec::new();
    }

    let log = tree
        .join(PROBE_DIR)
        .join("intercept")
        .join("cc-invocations.log");
    let Ok(log) = std::fs::read_to_string(log) else {
        return Vec::new();
    };
    let archive_name = archive.file_name();
    let mut dependencies = Vec::new();
    for entry in parse_intercept_log(&log) {
        if entry
            .arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-c" | "-E" | "-S"))
        {
            continue;
        }
        let uses_archive = entry.arguments.iter().any(|argument| {
            let path = Path::new(argument);
            path.file_name() == archive_name
                || (is_source_arg(argument)
                    && path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .is_some_and(|stem| members.contains(&format!("{stem}.o"))))
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| members.contains(name))
        });
        if uses_archive {
            dependencies.extend(libraries_from_intercept_arguments(&entry));
        }
    }
    dependencies
}

fn libraries_from_intercept_arguments(entry: &ProbeEntry) -> Vec<PathBuf> {
    let mut search_dirs = Vec::new();
    let mut library_names = Vec::new();
    let mut direct = Vec::new();
    let mut index = 1;
    while index < entry.arguments.len() {
        let argument = &entry.arguments[index];
        if argument == "-L" {
            if let Some(value) = entry.arguments.get(index + 1) {
                search_dirs.push(resolve_against(&entry.directory, value));
                index += 2;
                continue;
            }
        } else if let Some(value) = argument.strip_prefix("-L") {
            if !value.is_empty() {
                search_dirs.push(resolve_against(&entry.directory, value));
            }
        } else if argument == "-l" {
            if let Some(value) = entry.arguments.get(index + 1) {
                library_names.push(value.clone());
                index += 2;
                continue;
            }
        } else if let Some(value) = argument.strip_prefix("-l") {
            if !value.is_empty() && !value.starts_with(':') {
                library_names.push(value.to_owned());
            }
        } else if is_library_file_token(argument) {
            let path = resolve_against(&entry.directory, argument);
            if path.is_file() {
                direct.push(path);
            }
        }
        index += 1;
    }

    for name in library_names {
        let filenames = [
            format!("lib{name}.so"),
            format!("lib{name}.a"),
            format!("lib{name}.dylib"),
        ];
        let from_search = search_dirs
            .iter()
            .flat_map(|dir| filenames.iter().map(move |filename| dir.join(filename)))
            .find(|path| path.is_file());
        let resolved = from_search.or_else(|| {
            let compiler = entry.arguments.first()?;
            filenames.iter().find_map(|filename| {
                let output = Command::new(compiler)
                    .arg(format!("-print-file-name={filename}"))
                    .output()
                    .ok()?;
                if !output.status.success() {
                    return None;
                }
                let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                let path = PathBuf::from(value);
                (path.is_absolute() && path.is_file()).then_some(path)
            })
        });
        if let Some(path) = resolved {
            direct.push(path);
        }
    }
    direct
}

fn collect_named_files(dir: &Path, depth: u32, name: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth < RECOVERED_ARTIFACT_MAX_DEPTH + 2 {
                collect_named_files(&path, depth + 1, name, out);
            }
        } else if path.file_name().and_then(|part| part.to_str()) == Some(name) {
            out.push(path);
        }
    }
}

fn cmake_link_working_dir(link_file: &Path) -> Option<&Path> {
    let mut cursor = link_file.parent()?;
    loop {
        if cursor.file_name().and_then(|name| name.to_str()) == Some("CMakeFiles") {
            return cursor.parent();
        }
        cursor = cursor.parent()?;
    }
}

fn is_library_file_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.ends_with(".a")
        || lower.ends_with(".lib")
        || lower.ends_with(".dylib")
        || lower.contains(".so")
}

fn libraries_from_cmake_link_text(text: &str, cwd: &Path, archive: &Path) -> Vec<PathBuf> {
    let archive = archive
        .canonicalize()
        .unwrap_or_else(|_| archive.to_path_buf());
    let resolve = |token: &str| {
        let token = token.trim_matches(['\'', '"']);
        let path = PathBuf::from(token);
        let path = if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        };
        path.canonicalize().unwrap_or(path)
    };
    let mut lines_with_archive = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens
            .iter()
            .filter(|token| is_library_file_token(token))
            .map(|token| resolve(token))
            .any(|path| path == archive)
        {
            lines_with_archive.push(tokens);
        }
    }
    lines_with_archive
        .into_iter()
        .flat_map(|tokens| tokens.into_iter())
        .filter(|token| is_library_file_token(token))
        .map(resolve)
        .filter(|path| path != &archive && path.is_file())
        .collect()
}

/// Defined global symbols in each static archive, demangled when the host `nm`
/// supports it. Indexing once per target lets repair choose the ONE archive that
/// actually supplies a failed symbol instead of adding every `*.a` found under a
/// build tree (which is both slow and prone to unrelated duplicate definitions).
pub fn index_static_library_symbols(libraries: &[PathBuf]) -> BTreeMap<PathBuf, BTreeSet<String>> {
    let nm = ["llvm-nm", "nm"]
        .into_iter()
        .find_map(|program| which::which(program).ok());
    let Some(nm) = nm else {
        return BTreeMap::new();
    };
    let mut index = BTreeMap::new();
    for library in libraries {
        let output = Command::new(&nm)
            .args(["-g", "--defined-only", "-C"])
            .arg(library)
            .output();
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let symbols = parse_nm_defined_symbols(&String::from_utf8_lossy(&output.stdout));
        if !symbols.is_empty() {
            index.insert(library.clone(), symbols);
        }
    }
    index
}

fn parse_nm_defined_symbols(output: &str) -> BTreeSet<String> {
    const DEFINED_KINDS: &str = "AaBbCcDdGgIiNnPpRrSsTtVvWw";
    let mut symbols = BTreeSet::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(kind_index) = fields.iter().position(|field| {
            field.len() == 1
                && field
                    .chars()
                    .next()
                    .is_some_and(|kind| DEFINED_KINDS.contains(kind))
        }) else {
            continue;
        };
        if kind_index + 1 >= fields.len() {
            continue;
        }
        symbols.insert(fields[kind_index + 1..].join(" "));
    }
    symbols
}

fn symbol_matches(defined: &str, requested: &str) -> bool {
    let defined = defined.trim().trim_start_matches('_');
    let requested = requested.trim().trim_start_matches('_');
    defined == requested
        || defined
            .strip_prefix(requested)
            .is_some_and(|suffix| suffix.starts_with('('))
        || requested
            .strip_prefix(defined)
            .is_some_and(|suffix| suffix.starts_with('('))
}

pub fn static_libraries_defining_any(
    index: &BTreeMap<PathBuf, BTreeSet<String>>,
    requested: impl IntoIterator<Item = impl AsRef<str>>,
) -> Vec<PathBuf> {
    let requested: Vec<String> = requested
        .into_iter()
        .map(|symbol| symbol.as_ref().to_owned())
        .collect();
    index
        .iter()
        .filter(|(_, defined)| {
            requested.iter().any(|requested| {
                defined
                    .iter()
                    .any(|defined| symbol_matches(defined, requested))
            })
        })
        .map(|(path, _)| path.clone())
        .collect()
}

fn collect_static_libraries(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth >= RECOVERED_ARTIFACT_MAX_DEPTH {
                continue;
            }
            // CMakeFiles holds build bookkeeping, never a shippable archive; a
            // dotdir is VCS/editor state. Skip both to keep the walk cheap.
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name != "CMakeFiles" && !name.starts_with('.') {
                collect_static_libraries(&path, depth + 1, out);
            }
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("a"))
        {
            out.push(path);
        }
    }
}

/// Directories under the scanned tree's build / probe dirs that hold *generated*
/// headers, for ROADMAP §26.8.
///
/// A configure-only probe (`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`) runs the
/// project's codegen — CMake `generate_export_header` (miniz's `miniz_export.h`),
/// a configure-written `config.h` — but drops the header into the build dir,
/// which the per-file `compile_commands.json` `-I` set can miss, so the harness
/// build fails with `miniz_export.h: No such file or directory`. Returning the
/// build/probe dirs that actually contain a header lets the harness include path
/// pick the generated header up. A build dir holds only generated headers (no
/// hand-written source lives there), so any dir with a `.h` is a generated-header
/// dir. Bounded recursive; deterministically sorted.
pub fn generated_header_dirs(tree: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in RECOVERED_ARTIFACT_DIRS {
        collect_generated_header_dirs(&tree.join(sub), 0, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn collect_generated_header_dirs(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut has_header = false;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name != "CMakeFiles" && !name.starts_with('.') {
                subdirs.push(path);
            }
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("h"))
        {
            has_header = true;
        }
    }
    if has_header {
        out.push(dir.to_path_buf());
    }
    if depth < RECOVERED_ARTIFACT_MAX_DEPTH {
        for subdir in subdirs {
            collect_generated_header_dirs(&subdir, depth + 1, out);
        }
    }
}

/// Build a CMake project through a tiny generated superproject when it declares
/// a required package whose source is already available locally. This closes
/// the common offline monorepo/vendor-cache shape without editing the checkout
/// or fetching from the network. RE2 + Abseil is the representative case: RE2
/// explicitly accepts an existing `absl::base` target before `find_package`, so
/// adding the sibling source first is its supported integration path.
fn cmake_source_with_local_dependencies(tree: &Path, probe_dir: &Path) -> PathBuf {
    let cmake = std::fs::read_to_string(tree.join("CMakeLists.txt")).unwrap_or_default();
    if !cmake.contains("find_package(absl") {
        return tree.to_path_buf();
    }
    let Some(abseil) = local_abseil_source(tree) else {
        return tree.to_path_buf();
    };
    let wrapper = probe_dir.join("govfuzz-wrapper-src");
    if std::fs::create_dir_all(&wrapper).is_err() {
        return tree.to_path_buf();
    }
    let quote = |path: &Path| {
        path.display()
            .to_string()
            .replace('\\', "/")
            .replace('"', "\\\"")
    };
    let re2_link_probe = wrapper.join("govfuzz-re2-link-probe.cc");
    if std::fs::write(
        &re2_link_probe,
        "#include <re2/re2.h>\nint main() { re2::RE2 re(\"a\"); return re.ok() ? 0 : 1; }\n",
    )
    .is_err()
    {
        return tree.to_path_buf();
    }
    let source = format!(
        "cmake_minimum_required(VERSION 3.22)\n\
         project(govfuzz_local_dependency_closure LANGUAGES C CXX)\n\
         set(ABSL_BUILD_TESTING OFF CACHE BOOL \"\" FORCE)\n\
         set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL \"\" FORCE)\n\
         # This is an analysis build, not an install tree. RE2's install export\n\
         # cannot legally export sibling in-tree Abseil targets and otherwise\n\
         # makes CMake return failure after generating a usable build graph.\n\
         set(RE2_INSTALL OFF CACHE BOOL \"\" FORCE)\n\
         add_subdirectory(\"{}\" \"${{CMAKE_BINARY_DIR}}/govfuzz-deps/absl\")\n\
         add_subdirectory(\"{}\" \"${{CMAKE_BINARY_DIR}}/govfuzz-project\")\n\
         if(TARGET re2::re2)\n\
           # A static archive has no transitive-link metadata. Keep an excluded\n\
           # consumer in the generated build graph so its link.txt records the\n\
           # exact ordered Abseil closure CMake resolved for RE2.\n\
           add_executable(govfuzz_dependency_probe EXCLUDE_FROM_ALL \"{}\")\n\
           target_link_libraries(govfuzz_dependency_probe PRIVATE re2::re2)\n\
         endif()\n",
        quote(&abseil),
        quote(tree),
        quote(&re2_link_probe),
    );
    if std::fs::write(wrapper.join("CMakeLists.txt"), source).is_err() {
        return tree.to_path_buf();
    }
    gfeprintln!(
        "govfuzz auto: CMake dependency closure: supplying local Abseil source {}",
        abseil.display()
    );
    wrapper
}

fn local_abseil_source(tree: &Path) -> Option<PathBuf> {
    let mut candidates = ["third_party", "third-party", "vendor", "vendors", "deps"]
        .into_iter()
        .flat_map(|base| {
            ["abseil-cpp", "absl"]
                .into_iter()
                .map(move |name| tree.join(base).join(name))
        })
        .collect::<Vec<_>>();
    if let Some(parent) = tree.parent() {
        candidates.extend([parent.join("abseil-cpp"), parent.join("absl")]);
        if let Ok(entries) = std::fs::read_dir(parent) {
            candidates.extend(entries.flatten().filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                (name.starts_with("abseil-cpp-") || name.starts_with("absl-"))
                    .then_some(entry.path())
            }));
        }
    }
    if let Some(roots) = std::env::var_os("GOVFUZZ_DEPENDENCY_ROOTS") {
        for root in std::env::split_paths(&roots) {
            candidates.extend([root.join("abseil-cpp"), root.join("absl"), root]);
        }
    }
    candidates.into_iter().find(|candidate| {
        candidate.join("CMakeLists.txt").is_file() && candidate.join("absl").is_dir()
    })
}

/// CMake configure args for the compile-database probe. On Windows the default
/// generator is the Visual Studio generator, which ignores
/// `CMAKE_EXPORT_COMPILE_COMMANDS` (it never writes compile_commands.json); Ninja
/// honors it and ships with both VS Build Tools and w64devkit, so prefer Ninja
/// there and pin clang so the recovered flags are gcc-style (`-I`/`-D`) — matching
/// govfuzz's clang-based harness build — rather than MSVC `/I`/`/D`. On Unix the
/// default (Makefiles) generator already emits the database. Pure so it is
/// unit-testable off-Windows.
fn cmake_probe_args(
    tree: &Path,
    probe_dir: &Path,
    windows: bool,
    ninja: bool,
    instrumentation: &ProbeInstrumentation,
) -> Vec<String> {
    let mut args = vec![
        "cmake".to_owned(),
        "-S".to_owned(),
        tree.display().to_string(),
        "-B".to_owned(),
        probe_dir.display().to_string(),
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".to_owned(),
        "-DBUILD_SHARED_LIBS=OFF".to_owned(),
        "-DBUILD_TESTING=OFF".to_owned(),
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON".to_owned(),
        format!("-DCMAKE_C_COMPILER={}", instrumentation.cc),
        format!("-DCMAKE_CXX_COMPILER={}", instrumentation.cxx),
        format!("-DCMAKE_C_FLAGS={}", instrumentation.c_flags.join(" ")),
        format!("-DCMAKE_CXX_FLAGS={}", instrumentation.cxx_flags.join(" ")),
    ];
    if !instrumentation.linker_flags.is_empty() {
        let flags = instrumentation.linker_flags.join(" ");
        args.extend([
            format!("-DCMAKE_EXE_LINKER_FLAGS={flags}"),
            format!("-DCMAKE_SHARED_LINKER_FLAGS={flags}"),
            format!("-DCMAKE_MODULE_LINKER_FLAGS={flags}"),
        ]);
    }
    if windows && ninja {
        args.extend(["-G".to_owned(), "Ninja".to_owned()]);
    }
    args
}

/// `meson setup` arguments for the compile-database probe: configure the source
/// tree into `probe_dir`. Meson always emits `compile_commands.json` into the
/// build dir with its (default) ninja backend, and runs codegen at configure
/// time. Pure so it is unit-testable without meson installed.
fn meson_probe_args(tree: &Path, probe_dir: &Path) -> Vec<String> {
    vec![
        "meson".to_owned(),
        "setup".to_owned(),
        probe_dir.display().to_string(),
        tree.display().to_string(),
    ]
}

/// `ninja -t compdb` arguments for the compile-database probe: emit the database
/// from the manifest in `tree` to stdout without running the build. Pure so it is
/// unit-testable without ninja installed.
fn ninja_compdb_args(tree: &Path) -> Vec<String> {
    vec![
        "ninja".to_owned(),
        "-C".to_owned(),
        tree.display().to_string(),
        "-t".to_owned(),
        "compdb".to_owned(),
    ]
}

/// Meson tier: `meson setup <probe_dir> <tree>`. Meson writes
/// `compile_commands.json` directly into the build dir (= the probe dir) and runs
/// codegen during configure, so the recovered DB lands at `db` with no extra
/// plumbing.
fn probe_meson(
    tree: &Path,
    probe_dir: &Path,
    db: &Path,
    sandbox_program: Option<&Path>,
) -> Option<PathBuf> {
    if !find_on_path("meson") {
        gfeprintln!("govfuzz auto: --probe-build: meson not on PATH; skipping Meson probe");
        return None;
    }
    run_build(
        tree,
        &meson_probe_args(tree, probe_dir),
        &[],
        sandbox_program,
    );
    db.is_file().then(|| db.to_path_buf())
}

/// Ninja tier: `ninja -C <tree> -t compdb` reads the manifest and prints the
/// compile database to stdout WITHOUT running the build; we capture it into `db`.
/// (The other tiers run a build that writes the DB to disk, so they inherit
/// stdio; this one needs the captured stdout.)
fn probe_ninja(tree: &Path, db: &Path, sandbox_program: Option<&Path>) -> Option<PathBuf> {
    if !find_on_path("ninja") {
        gfeprintln!("govfuzz auto: --probe-build: ninja not on PATH; skipping Ninja probe");
        return None;
    }
    let mut command = build_command(tree, &ninja_compdb_args(tree), &[], sandbox_program);
    let db_file = std::fs::File::create(db).ok()?;
    command
        .stdout(std::process::Stdio::from(db_file))
        .stderr(std::process::Stdio::inherit());
    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            gfeprintln!("govfuzz auto: --probe-build: failed to run ninja compdb: {error}");
            return None;
        }
    };
    if !status.success() || !std::fs::metadata(db).is_ok_and(|metadata| metadata.len() > 0) {
        gfeprintln!("govfuzz auto: --probe-build: `ninja -t compdb` produced no database");
        let _ = std::fs::remove_file(db);
        return None;
    }
    Some(db.to_path_buf())
}

fn probe_make(
    tree: &Path,
    probe_dir: &Path,
    db: &Path,
    sandbox_program: Option<&Path>,
) -> Option<PathBuf> {
    if !find_on_path("make") {
        gfeprintln!("govfuzz auto: --probe-build: make not on PATH; skipping Make probe");
        return None;
    }
    let Some(real_cc) = real_compiler() else {
        gfeprintln!("govfuzz auto: --probe-build: no C compiler on PATH; skipping Make probe");
        return None;
    };
    let wrapper = probe_dir.join("gf-cc");
    let log = probe_dir.join("cc-invocations.log");
    let _ = std::fs::remove_file(&log);
    if std::fs::write(&wrapper, cc_wrapper_script()).is_err() {
        return None;
    }
    // Best-effort executable bit; the build invokes it as `$CC`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755));
    }
    let wrapper_disp = wrapper.display().to_string();
    let env = [
        ("CC".to_owned(), wrapper_disp.clone()),
        ("CXX".to_owned(), wrapper_disp),
        ("GF_REAL_CC".to_owned(), real_cc.clone()),
        ("GF_CC_LOG".to_owned(), log.display().to_string()),
    ];
    run_build(tree, &["make".to_owned()], &env, sandbox_program);

    let log_text = std::fs::read_to_string(&log).ok()?;
    let entries = parse_cc_log(&log_text, &real_cc);
    if entries.is_empty() {
        return None;
    }
    let json = serde_json::to_vec_pretty(&entries).ok()?;
    std::fs::write(db, json).ok()?;
    Some(db.to_path_buf())
}

// --- Universal interception tier (`--build-command`) ---------------------------

/// Compiler basenames the interception shim multiplexes: the standard host
/// C/C++ frontends plus the named vendor compilers common in radar/RTOS/defense
/// builds (Wind River Diab, Green Hills, QNX, Keil/ARM, IAR, TI). A shim is only
/// written for a name actually present on PATH. Cross-prefixed GNU/LLVM
/// compilers (e.g. `aarch64-linux-gnu-gcc`) are discovered separately by
/// scanning PATH — see `is_cross_compiler_name`.
const INTERCEPT_COMPILER_NAMES: &[&str] = &[
    // Standard host C/C++ frontends.
    "cc",
    "c++",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "cpp",
    "clang-cpp",
    // Wind River Diab (VxWorks safety-critical toolchain).
    "dcc",
    "dplus",
    // Green Hills (per-arch `cc<arch>`/`cx<arch>`: ARM/PPC/x86/arm64 shown).
    "ccarm",
    "cxarm",
    "ccppc",
    "cxppc",
    "ccintarm64",
    "ccx86",
    "cxx86",
    // QNX Neutrino.
    "qcc",
    "q++",
    // Keil/ARM and IAR (embedded).
    "armcc",
    "armclang",
    "iccarm",
    // TI (DSP/radar signal processing).
    "cl2000",
    "cl6x",
    "cl430",
];

fn intercept_compiler_names() -> &'static [&'static str] {
    INTERCEPT_COMPILER_NAMES
}

/// Whether `name` is a cross-prefixed GNU/LLVM compiler (a target triple/prefix
/// followed by `-gcc`/`-g++`/`-cc`/`-c++`/`-clang`/`-clang++`), e.g.
/// `aarch64-linux-gnu-gcc`, `arm-none-eabi-g++`, `ntoaarch64-gcc` (QNX). The bare
/// names (`gcc`, `g++`, ...) are handled by `INTERCEPT_COMPILER_NAMES` instead, so
/// a true prefix is required (the suffix alone does not match).
fn is_cross_compiler_name(name: &str) -> bool {
    const SUFFIXES: &[&str] = &["-gcc", "-g++", "-cc", "-c++", "-clang", "-clang++"];
    SUFFIXES
        .iter()
        .any(|s| name.len() > s.len() && name.ends_with(s))
}

/// The `sh` shim for one intercepted compiler. It appends a record (`DIR <cwd>`,
/// `CC <real>`, one `ARG` line per argument, `ENDREC`) to the shared log and then
/// execs the ABSOLUTE real compiler — no PATH re-lookup, so the shim (which lives
/// on PATH under the compiler's own name) is never re-entered. `real_abs` is
/// single-quoted so a path with spaces still execs.
#[cfg(test)]
fn intercept_wrapper_script(real_abs: &str) -> String {
    intercept_wrapper_script_with_flags(real_abs, &[])
}

fn intercept_wrapper_script_with_flags(real_abs: &str, extra_flags: &[String]) -> String {
    let flags = extra_flags
        .iter()
        .map(|flag| format!(" '{}'", flag.replace('\'', "'\\''")))
        .collect::<String>();
    format!(
        "#!/bin/sh\n\
         {{\n\
         printf 'DIR %s\\n' \"$PWD\"\n\
         printf 'CC %s\\n' '{real}'\n\
         for a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done\n\
         printf 'ENDREC\\n'\n\
         }} >> \"$GF_CC_LOG\"\n\
         exec '{real}' \"$@\"{flags}\n",
        real = real_abs,
        flags = flags
    )
}

/// Convert the interception log into compile-database entries. Unlike the
/// Make-tier `parse_cc_log`, each record carries its own real compiler (`CC`
/// line), so a mixed C/C++/vendor build records the actual frontend per TU.
fn parse_intercept_log(log: &str) -> Vec<ProbeEntry> {
    let mut entries = Vec::new();
    let mut directory: Option<String> = None;
    let mut cc: Option<String> = None;
    let mut args: Vec<String> = Vec::new();
    for line in log.lines() {
        if line == "ENDREC" {
            if let (Some(dir), Some(cc_path), Some(file)) = (
                &directory,
                &cc,
                args.iter().find(|a| is_source_arg(a)).cloned(),
            ) {
                let mut arguments = Vec::with_capacity(args.len() + 1);
                arguments.push(cc_path.clone());
                arguments.extend(args.iter().cloned());
                let file_path = resolve_against(Path::new(dir), &file);
                entries.push(ProbeEntry {
                    directory: PathBuf::from(dir),
                    file: file_path,
                    arguments,
                });
            }
            directory = None;
            cc = None;
            args.clear();
        } else if let Some(d) = line.strip_prefix("DIR ") {
            directory = Some(d.to_owned());
        } else if let Some(c) = line.strip_prefix("CC ") {
            cc = Some(c.to_owned());
        } else if let Some(a) = line.strip_prefix("ARG ") {
            args.push(a.to_owned());
        }
    }
    entries
}

/// Environment for the intercepted build: the shim dir wins at the front of
/// `PATH` (so name-based compiler lookups hit the shim), `GF_CC_LOG` points every
/// shim at the shared log, and `CC`/`CXX` are pointed at the shim too (so builds
/// that honor those env vars are caught even if they invoke `$(CC)`).
fn intercept_env(
    intercept_dir: &Path,
    log: &Path,
    cc: Option<&Path>,
    cxx: Option<&Path>,
) -> Vec<(String, String)> {
    let existing = std::env::var("PATH").unwrap_or_default();
    let path = if existing.is_empty() {
        intercept_dir.display().to_string()
    } else {
        format!("{}:{}", intercept_dir.display(), existing)
    };
    let mut env = vec![
        ("PATH".to_owned(), path),
        ("GF_CC_LOG".to_owned(), log.display().to_string()),
    ];
    if let Some(cc) = cc {
        env.push(("CC".to_owned(), cc.display().to_string()));
    }
    if let Some(cxx) = cxx {
        env.push(("CXX".to_owned(), cxx.display().to_string()));
    }
    env
}

/// Every compiler to write a shim for: the curated names present on the current
/// PATH, plus cross-prefixed GNU/LLVM compilers discovered by scanning PATH. Each
/// is paired with its resolved ABSOLUTE path (resolved before the shim dir is on
/// PATH, so the real binary — not the shim — is found).
fn collect_intercept_targets() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in intercept_compiler_names() {
        if let Some(abs) = program_on_path(name) {
            if seen.insert(name.to_string()) {
                out.push((name.to_string(), abs));
            }
        }
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return out;
    };
    for dir in std::env::split_paths(&paths) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_cross_compiler_name(&name) && seen.insert(name.clone()) {
                out.push((name, entry.path()));
            }
        }
    }
    out
}

/// Universal interception tier: run an ARBITRARY user-provided build command (a
/// custom `build.sh`, `bazel build`, `scons`, `waf`, a vendor RTOS build, ...)
/// under a front-of-`PATH` compiler shim so every `cc`/`gcc`/`clang` *and* vendor
/// compiler invocation is logged into a `compile_commands.json`. The escape hatch
/// for builds govfuzz doesn't natively probe. EXECUTES `command` (via `sh -c`),
/// so it runs under the sandbox when one is available — same policy as the other
/// tiers. Best-effort: returns `None` (after a warning) if no compiler is present
/// or the build compiled no C/C++.
pub fn probe_build_command(
    tree: &Path,
    command: &str,
    sandbox_program: Option<&Path>,
    sanitizers: &multicore_fuzz::SanitizerSelection,
) -> Option<PathBuf> {
    let probe_dir = tree.join(PROBE_DIR);
    let intercept_dir = probe_dir.join("intercept");
    if std::fs::create_dir_all(&intercept_dir).is_err() {
        return None;
    }
    let _ = std::fs::remove_file(probe_dir.join(PROBE_REQUIREMENTS_FILE));
    let log = intercept_dir.join("cc-invocations.log");
    let _ = std::fs::remove_file(&log);

    let mut wrote_any = false;
    let instrumentation = ProbeInstrumentation::for_selection(sanitizers);
    let mut cc_shim: Option<PathBuf> = None;
    let mut cxx_shim: Option<PathBuf> = None;
    for (name, real) in collect_intercept_targets() {
        let shim = intercept_dir.join(&name);
        let standard_c = matches!(name.as_str(), "cc" | "gcc" | "clang");
        let standard_cxx = matches!(name.as_str(), "c++" | "g++" | "clang++");
        let instrumented_real = if standard_c {
            which::which(&instrumentation.cc).unwrap_or_else(|_| real.clone())
        } else if standard_cxx {
            which::which(&instrumentation.cxx).unwrap_or_else(|_| real.clone())
        } else {
            real.clone()
        };
        let extra_flags = if standard_c {
            instrumentation.c_flags.as_slice()
        } else if standard_cxx {
            instrumentation.cxx_flags.as_slice()
        } else {
            &[]
        };
        if std::fs::write(
            &shim,
            intercept_wrapper_script_with_flags(
                &instrumented_real.display().to_string(),
                extra_flags,
            ),
        )
        .is_err()
        {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755));
        }
        wrote_any = true;
        if cc_shim.is_none() && matches!(name.as_str(), "cc" | "gcc" | "clang") {
            cc_shim = Some(shim.clone());
        }
        if cxx_shim.is_none() && matches!(name.as_str(), "c++" | "g++" | "clang++") {
            cxx_shim = Some(shim.clone());
        }
        // The injected instrumentation contract is Clang-specific. Prefer its
        // shim even when `/usr/bin/cc`/`c++` were encountered first.
        if name == "clang" {
            cc_shim = Some(shim.clone());
        } else if name == "clang++" {
            cxx_shim = Some(shim.clone());
        }
    }
    if !wrote_any {
        gfeprintln!(
            "govfuzz auto: --build-command: no C/C++ compiler found on PATH to intercept; skipping"
        );
        return None;
    }

    let mut env = intercept_env(
        &intercept_dir,
        &log,
        cc_shim.as_deref(),
        cxx_shim.as_deref(),
    );
    env.push(("CFLAGS".to_owned(), instrumentation.c_flags.join(" ")));
    env.push(("CXXFLAGS".to_owned(), instrumentation.cxx_flags.join(" ")));
    env.push(("LDFLAGS".to_owned(), instrumentation.linker_flags.join(" ")));
    // Also catch compilers the PATH shim cannot shadow — those invoked by
    // ABSOLUTE path (vendor RTOS toolchains, a Bazel toolchain) or via
    // `posix_spawn` (ninja/cmake) — by LD_PRELOAD-ing the exec-interposing shim.
    // Copy it into the (sandbox-bound) intercept dir so it resolves both
    // sandboxed and direct. Dedup-by-source (below) makes the two mechanisms safe
    // to run together. Best-effort: absent .so (e.g. a `-p govfuzz` build) just
    // leaves the PATH shim active.
    if let Some(so) = locate_cc_intercept_so() {
        let so_copy = intercept_dir.join("libgovfuzz_cc_intercept.so");
        if std::fs::copy(&so, &so_copy).is_ok() {
            let chained = match std::env::var("LD_PRELOAD") {
                Ok(existing) if !existing.is_empty() => {
                    format!("{}:{}", so_copy.display(), existing)
                }
                _ => so_copy.display().to_string(),
            };
            env.push(("LD_PRELOAD".to_owned(), chained));
        }
    }
    let build_succeeded = run_build(
        tree,
        &["sh".to_owned(), "-c".to_owned(), command.to_owned()],
        &env,
        sandbox_program,
    );
    mirror_root_static_libraries(tree, &probe_dir);
    write_artifact_manifest_at(&probe_dir, &instrumentation, build_succeeded);

    let log_text = std::fs::read_to_string(&log).ok()?;
    let entries = dedup_intercept_entries(parse_intercept_log(&log_text));
    if entries.is_empty() {
        gfeprintln!(
            "govfuzz auto: --build-command: intercepted no compiler invocations \
             (did `{command}` compile any C/C++?)"
        );
        return None;
    }
    let db = probe_dir.join("compile_commands.json");
    let json = serde_json::to_vec_pretty(&entries).ok()?;
    std::fs::write(&db, json).ok()?;
    Some(db)
}

/// Configure/Autotools builds often leave their archive beside `configure`
/// while govfuzz's compiler log and trust manifest live in `.govfuzz-build`.
/// Mirror only direct root archives into the owned probe directory so the
/// normal compatible-artifact path can select them proactively.
fn mirror_root_static_libraries(tree: &Path, probe_dir: &Path) {
    let artifact_dir = probe_dir.join("intercept-artifacts");
    let Ok(entries) = std::fs::read_dir(tree) else {
        return;
    };
    for entry in entries.flatten() {
        let source = entry.path();
        if !source.is_file()
            || !source
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("a"))
        {
            continue;
        }
        if std::fs::create_dir_all(&artifact_dir).is_err() {
            return;
        }
        let _ = std::fs::copy(&source, artifact_dir.join(entry.file_name()));
    }
}

/// Locate `libgovfuzz_cc_intercept.so` — `$GOVFUZZ_CC_INTERCEPT` override, else a
/// sibling of the running binary (where `cargo build --workspace` puts the
/// cdylib). `None` (graceful) when absent.
fn locate_cc_intercept_so() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("GOVFUZZ_CC_INTERCEPT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let so = exe.parent()?.join("libgovfuzz_cc_intercept.so");
    so.is_file().then_some(so)
}

/// Collapse records that refer to the same translation unit (normalized `file`).
/// Prefer a compiler DRIVER invocation over Clang's expanded `-cc1` child even
/// when the latter has more arguments: driver flags are portable/replayable and
/// its default `foo.c -> foo.o` output names correspond to archive members,
/// whereas a cc1 record commonly names an ephemeral `/tmp/foo-XXXX.o`. Among
/// records at the same layer, keep the richest. First-seen order is preserved.
fn dedup_intercept_entries(entries: Vec<ProbeEntry>) -> Vec<ProbeEntry> {
    use std::collections::HashMap;
    let mut order: Vec<String> = Vec::new();
    let mut best: HashMap<String, ProbeEntry> = HashMap::new();
    for entry in entries {
        let key = entry.file.to_string_lossy().into_owned();
        match best.get(&key) {
            Some(prev) if !intercept_entry_is_better(&entry, prev) => {}
            Some(_) => {
                best.insert(key, entry);
            }
            None => {
                order.push(key.clone());
                best.insert(key, entry);
            }
        }
    }
    order
        .into_iter()
        .filter_map(|key| best.remove(&key))
        .collect()
}

fn intercept_entry_is_better(candidate: &ProbeEntry, current: &ProbeEntry) -> bool {
    let candidate_internal = candidate
        .arguments
        .iter()
        .any(|argument| argument == "-cc1");
    let current_internal = current.arguments.iter().any(|argument| argument == "-cc1");
    match (candidate_internal, current_internal) {
        (false, true) => true,
        (true, false) => false,
        _ => candidate.arguments.len() > current.arguments.len(),
    }
}

/// Build the `Command` for a probe build in `cwd` with `env`, wrapped in the
/// sandbox when one is available. The whole tree is bind-mounted read-write (the
/// build writes objects, generated headers, and the probe dir); the rest of the
/// filesystem is read-only. Network is unshared (offline). Stdio is left at the
/// default (inherited) — callers that need stdout (`ninja -t compdb`) override it
/// before spawning.
fn build_command(
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
    sandbox_program: Option<&Path>,
) -> Command {
    match sandbox_program {
        Some(program) if program.file_name().and_then(|n| n.to_str()) == Some("bwrap") => {
            let mut c = Command::new(program);
            c.args(bwrap_fs_args());
            // The tree is the one read-write area (objects, generated headers,
            // the probe dir); everything else stays read-only.
            c.arg("--bind").arg(cwd).arg(cwd);
            c.arg("--chdir").arg(cwd);
            for (key, value) in env {
                c.arg("--setenv").arg(key).arg(value);
            }
            c.arg("--");
            c.args(args);
            c
        }
        Some(program) if program.file_name().and_then(|n| n.to_str()) == Some("firejail") => {
            let mut c = Command::new(program);
            c.args(["--quiet", "--net=none", "--private-tmp"]);
            c.arg(format!("--whitelist={}", cwd.display()));
            c.arg("--");
            c.args(args);
            c.current_dir(cwd);
            for (key, value) in env {
                c.env(key, value);
            }
            c
        }
        _ => {
            // Direct run (sandbox unavailable / disabled). The opt-in flag is the
            // user's acknowledgement that the build executes project code.
            let mut c = Command::new(&args[0]);
            c.args(&args[1..]);
            c.current_dir(cwd);
            for (key, value) in env {
                c.env(key, value);
            }
            c
        }
    }
}

/// Run a build command in `cwd` with `env`, wrapped in the sandbox when one is
/// available (see `build_command`). Output is inherited so build progress/errors
/// are visible.
fn run_build(
    cwd: &Path,
    args: &[String],
    env: &[(String, String)],
    sandbox_program: Option<&Path>,
) -> bool {
    let mut command = build_command(cwd, args, env, sandbox_program);
    match command.status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            gfeprintln!(
                "govfuzz auto: --probe-build: `{}` exited with {status} (a partial build can still yield usable compile metadata/artifacts)",
                args.join(" ")
            );
            false
        }
        Err(error) => {
            gfeprintln!(
                "govfuzz auto: --probe-build: failed to run `{}`: {error}",
                args.join(" ")
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-probe-{nonce}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_gpr_picks_deterministically_and_handles_none() {
        let root = tmpdir();
        assert!(first_gpr(&root).is_none(), "no gpr -> None");
        fs::write(root.join("zeta.gpr"), "project Zeta is end Zeta;\n").unwrap();
        fs::write(root.join("alpha.gpr"), "project Alpha is end Alpha;\n").unwrap();
        assert_eq!(
            first_gpr(&root).unwrap().file_name().unwrap(),
            "alpha.gpr",
            "lexicographically first for determinism"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_requirement_sidecar_round_trips_and_deduplicates() {
        let root = tmpdir();
        fs::create_dir_all(root.join(PROBE_DIR)).unwrap();
        let requirement = ProbeRequirement {
            kind: crate::auto::dep_manifest::DepKind::SharedLibrary,
            name: "ZLIB".to_owned(),
            acquisition_hint: "stage zlib development files".to_owned(),
            evidence: "CMake Could NOT find ZLIB".to_owned(),
        };
        record_probe_requirement(&root, requirement.clone());
        record_probe_requirement(&root, requirement);
        let loaded = load_probe_requirements(&root);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "ZLIB");
        assert!(loaded[0].evidence.contains("Could NOT find"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn probe_ada_build_is_graceful_without_an_ada_project() {
        // No alire.toml / .gpr -> must not panic, just skip.
        let root = tmpdir();
        probe_ada_build(&root, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn executable_candidates_resolve_windows_exe() {
        // Unix: the bare name is the executable.
        assert_eq!(
            executable_candidates_for("cmake", false, None),
            vec!["cmake".to_owned()]
        );
        // Windows: must also try the PATHEXT-suffixed names so `cmake.exe` resolves
        // (the old bare-name join was the native-Windows CMake/make probe bug).
        let win = executable_candidates_for("cmake", true, Some(".COM;.EXE;.BAT;.CMD"));
        assert!(win.contains(&"cmake".to_owned()));
        assert!(
            win.contains(&"cmake.exe".to_owned()),
            "windows lookup must try cmake.exe, got {win:?}"
        );
        // An already-qualified name is trusted as-is (no double extension).
        assert_eq!(
            executable_candidates_for("make.exe", true, Some(".EXE")),
            vec!["make.exe".to_owned()]
        );
    }

    #[test]
    fn cmake_probe_forces_ninja_and_clang_on_windows_only() {
        let tree = Path::new("/src");
        let probe = Path::new("/probe");
        let instrumentation =
            ProbeInstrumentation::for_selection(&multicore_fuzz::SanitizerSelection::Default);
        // Unix keeps the default (Makefiles) generator — it already emits the DB.
        let lin = cmake_probe_args(tree, probe, false, true, &instrumentation);
        assert!(lin
            .iter()
            .any(|a| a == "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"));
        assert!(lin.iter().any(|a| a == "-DBUILD_SHARED_LIBS=OFF"));
        assert!(lin.iter().any(|a| {
            a.contains("CMAKE_C_FLAGS=")
                && a.contains("-fsanitize=address,undefined")
                && a.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        }));
        assert!(
            !lin.iter().any(|a| a == "-G"),
            "unix must not pin a generator: {lin:?}"
        );
        // Windows with ninja: force Ninja + clang so the DB is actually written
        // (the VS generator ignores the export flag) with gcc-style flags.
        let win = cmake_probe_args(tree, probe, true, true, &instrumentation).join(" ");
        assert!(win.contains("-G Ninja"), "windows must pin Ninja: {win}");
        assert!(win.contains("CMAKE_C_COMPILER=clang"), "{win}");
        assert!(win.contains("CMAKE_CXX_COMPILER=clang++"), "{win}");
        // Windows without ninja: fall back to the default generator (best effort).
        let win_no_ninja = cmake_probe_args(tree, probe, true, false, &instrumentation);
        assert!(!win_no_ninja.iter().any(|a| a == "-G"));
    }

    #[test]
    fn cmake_probe_wraps_a_required_locally_available_abseil_source() {
        let root = tmpdir();
        let project = root.join("re2");
        let abseil = root.join("abseil-cpp");
        let probe = project.join(PROBE_DIR);
        fs::create_dir_all(&probe).unwrap();
        fs::create_dir_all(abseil.join("absl")).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("CMakeLists.txt"),
            "if(NOT TARGET absl::base)\nfind_package(absl REQUIRED)\nendif()\n",
        )
        .unwrap();
        fs::write(
            abseil.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.22)\n",
        )
        .unwrap();

        let source = cmake_source_with_local_dependencies(&project, &probe);
        assert_ne!(source, project);
        let wrapper = fs::read_to_string(source.join("CMakeLists.txt")).unwrap();
        assert!(wrapper.contains("add_subdirectory"), "{wrapper}");
        assert!(wrapper.contains(&abseil.display().to_string()), "{wrapper}");
        assert!(
            wrapper.contains(&project.display().to_string()),
            "{wrapper}"
        );
        assert!(wrapper.contains("re2::re2"), "{wrapper}");
        assert!(wrapper.contains("set(RE2_INSTALL OFF"), "{wrapper}");
        assert!(source.join("govfuzz-re2-link-probe.cc").is_file());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sanitizer_selection_produces_an_exact_probe_contract() {
        use multicore_fuzz::{Sanitizer, SanitizerSelection};
        let none = ProbeInstrumentation::for_selection(&SanitizerSelection::None);
        assert!(none
            .c_flags
            .iter()
            .any(|flag| flag.contains("sanitize-coverage")));
        assert!(!none
            .c_flags
            .iter()
            .any(|flag| flag.starts_with("-fsanitize=")));

        let asan =
            ProbeInstrumentation::for_selection(&SanitizerSelection::Set(vec![Sanitizer::Asan]));
        assert!(asan.c_flags.iter().any(|flag| flag == "-fsanitize=address"));
        assert!(!asan
            .c_flags
            .iter()
            .any(|flag| flag.starts_with("-fno-sanitize=")));

        let default = ProbeInstrumentation::for_selection(&SanitizerSelection::Default);
        assert!(default
            .c_flags
            .iter()
            .any(|flag| flag == "-fsanitize=address,undefined"));
        assert!(default
            .c_flags
            .iter()
            .any(|flag| flag == "-fno-sanitize=function,vptr,alignment"));
    }

    #[test]
    fn nm_parser_and_archive_selection_handle_c_and_demangled_cpp() {
        let symbols = parse_nm_defined_symbols(
            "libx.a(one.o):\n0000000000000000 T archive_read_support_format_all\n\
             0000000000000010 W YAML::Emitter::Write(char const*, unsigned long)\n\
                              U ignored_undefined\n",
        );
        assert!(symbols.contains("archive_read_support_format_all"));
        assert!(symbols.contains("YAML::Emitter::Write(char const*, unsigned long)"));
        assert!(!symbols.contains("ignored_undefined"));

        let mut index = BTreeMap::new();
        index.insert(PathBuf::from("/build/libarchive.a"), symbols);
        assert_eq!(
            static_libraries_defining_any(&index, ["archive_read_support_format_all"]),
            vec![PathBuf::from("/build/libarchive.a")]
        );
        assert_eq!(
            static_libraries_defining_any(&index, ["YAML::Emitter::Write"]),
            vec![PathBuf::from("/build/libarchive.a")]
        );
        assert!(static_libraries_defining_any(&index, ["archive_read_support_format"]).is_empty());
    }

    #[test]
    fn cmake_link_metadata_recovers_static_archive_dependencies_in_order() {
        let root = tmpdir();
        let cwd = root.join("tool");
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        let archive = root.join("lib/libparser.a");
        let zlib = root.join("lib/libz.so");
        let crypto = root.join("lib/libcrypto.so");
        fs::write(&archive, b"!<arch>\n").unwrap();
        fs::write(&zlib, b"so").unwrap();
        fs::write(&crypto, b"so").unwrap();
        let link = format!(
            "clang tool.o -o tool ../lib/libparser.a {} {}\n",
            zlib.display(),
            crypto.display()
        );
        assert_eq!(
            libraries_from_cmake_link_text(&link, &cwd, &archive),
            vec![zlib, crypto]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn compatible_probe_archives_require_the_exact_instrumentation_manifest() {
        let root = tmpdir();
        let probe = root.join(PROBE_DIR);
        fs::create_dir_all(&probe).unwrap();
        fs::write(probe.join("libparser.a"), b"!<arch>\n").unwrap();
        let default = multicore_fuzz::SanitizerSelection::Default;
        write_probe_artifact_manifest(&root, &ProbeInstrumentation::for_selection(&default), false);
        assert_eq!(
            compatible_probe_static_libraries(&root, &default),
            vec![probe.join("libparser.a")],
            "a partial build's archive is valid when its instrumentation matches"
        );
        assert!(compatible_probe_static_libraries(
            &root,
            &multicore_fuzz::SanitizerSelection::None
        )
        .is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nested_probe_archives_are_visible_from_a_wrapper_scan_root() {
        let wrapper = tmpdir();
        let probe = wrapper.join("project").join(PROBE_DIR);
        fs::create_dir_all(&probe).unwrap();
        let archive = probe.join("libnested.a");
        fs::write(&archive, b"!<arch>\n").unwrap();
        let selection = multicore_fuzz::SanitizerSelection::Default;
        write_artifact_manifest_at(
            &probe,
            &ProbeInstrumentation::for_selection(&selection),
            true,
        );

        assert_eq!(
            compatible_probe_static_libraries(&wrapper, &selection),
            vec![archive.clone()]
        );
        assert!(discover_static_libraries(&wrapper).contains(&archive));
        let _ = fs::remove_dir_all(wrapper);
    }

    #[test]
    fn cmake_probe_builds_and_indexes_an_instrumented_static_library() {
        if !find_on_path("cmake") || !find_on_path("clang") || !find_on_path("clang++") {
            eprintln!("skipping: cmake/clang toolchain unavailable");
            return;
        }
        let root = tmpdir();
        fs::write(
            root.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.16)\n\
             project(gf_probe CXX)\n\
             add_library(gf_parser STATIC parser.cpp)\n",
        )
        .unwrap();
        fs::write(
            root.join("parser.cpp"),
            "#include <string>\n\
             extern \"C\" int gf_parser_open(const unsigned char *p, unsigned long n) {\n\
                 std::string marker = \"cpp-probe\";\n\
                 return p && n ? p[0] : 0;\n\
             }\n",
        )
        .unwrap();
        let selection = multicore_fuzz::SanitizerSelection::Default;
        let db = probe_build(&root, None, &selection).expect("CMake probe");
        assert!(db.is_file());
        assert_eq!(
            cmake_static_library_targets(&root.join(PROBE_DIR)),
            vec!["gf_parser".to_owned()]
        );
        assert_eq!(
            cmake_static_library_target_artifacts(&root.join(PROBE_DIR)),
            vec![(
                "gf_parser".to_owned(),
                vec![PathBuf::from("libgf_parser.a")]
            )]
        );
        let compile_db = fs::read_to_string(db).unwrap();
        assert!(
            compile_db.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"),
            "project TU must carry engine coverage instrumentation: {compile_db}"
        );

        let archives = compatible_probe_static_libraries(&root, &selection);
        assert_eq!(archives.len(), 1, "instrumented archive: {archives:?}");
        let index = index_static_library_symbols(&archives);
        assert_eq!(
            static_libraries_defining_any(&index, ["gf_parser_open"]),
            archives,
            "the target-owning archive must be selectable without linking unrelated libraries"
        );

        let primary_archive = &archives[0];
        assert!(is_probe_static_library(primary_archive));
        // The generated link script is a complete fallback when CMake omits or
        // an external cleanup removes its optional file-API reply.
        let reply = root.join(PROBE_DIR).join(".cmake/api/v1/reply");
        let _ = fs::remove_dir_all(reply);
        let coverage_archive = coverage_variant_for_probe_archive(primary_archive)
            .expect("exact CMake source-coverage counterpart");
        assert!(coverage_archive.is_file());
        assert!(coverage_archive.starts_with(root.join(COVERAGE_PROBE_DIR)));
        let coverage_db =
            fs::read_to_string(root.join(COVERAGE_PROBE_DIR).join("compile_commands.json"))
                .unwrap();
        assert!(coverage_db.contains("-fprofile-instr-generate"));
        assert!(coverage_db.contains("-fcoverage-mapping"));
        assert!(
            !coverage_db.contains("-fsanitize=address"),
            "coverage archive must not retain the primary sanitizer lane: {coverage_db}"
        );
        // Once the exact coverage artifact exists, replay must not depend on
        // optional metadata surviving in the primary build tree.  Real CMake
        // dependency closures can omit/clean one transitive target's metadata
        // after building all of its archives.
        let _ = fs::remove_dir_all(root.join(PROBE_DIR).join("CMakeFiles"));
        assert_eq!(
            coverage_variant_for_probe_archive(primary_archive).as_deref(),
            Some(coverage_archive.as_path()),
            "the exact coverage target is cached"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn detects_cmake_over_make() {
        let root = tmpdir();
        fs::write(root.join("CMakeLists.txt"), "project(x)\n").unwrap();
        fs::write(root.join("Makefile"), "all:\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::CMake);
    }

    #[test]
    fn detects_make_when_no_cmake() {
        let root = tmpdir();
        fs::write(root.join("Makefile"), "all:\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::Make);
        let bare = tmpdir();
        assert_eq!(detect_build_system(&bare), BuildSystem::None);
    }

    #[test]
    fn detects_meson_when_no_cmake() {
        let root = tmpdir();
        fs::write(root.join("meson.build"), "project('x', 'c')\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::Meson);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn detects_standalone_ninja() {
        let root = tmpdir();
        fs::write(root.join("build.ninja"), "rule cc\n  command = cc\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::Ninja);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn detection_precedence_cmake_meson_make_ninja() {
        // CMake wins over a co-located meson.build + build.ninja.
        let root = tmpdir();
        fs::write(root.join("CMakeLists.txt"), "project(x)\n").unwrap();
        fs::write(root.join("meson.build"), "project('x','c')\n").unwrap();
        fs::write(root.join("build.ninja"), "rule cc\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::CMake);
        let _ = fs::remove_dir_all(&root);
        // Meson is preferred over a hand-written Makefile (native DB + codegen).
        let m = tmpdir();
        fs::write(m.join("meson.build"), "project('x','c')\n").unwrap();
        fs::write(m.join("Makefile"), "all:\n").unwrap();
        assert_eq!(detect_build_system(&m), BuildSystem::Meson);
        let _ = fs::remove_dir_all(&m);
        // The mature Make path wins over a (usually generated) build.ninja.
        let n = tmpdir();
        fs::write(n.join("Makefile"), "all:\n").unwrap();
        fs::write(n.join("build.ninja"), "rule cc\n").unwrap();
        assert_eq!(detect_build_system(&n), BuildSystem::Make);
        let _ = fs::remove_dir_all(&n);
    }

    #[test]
    fn meson_probe_configures_tree_into_probe_dir() {
        let args = meson_probe_args(Path::new("/src"), Path::new("/src/.govfuzz-build"));
        assert_eq!(args.first().map(String::as_str), Some("meson"));
        assert_eq!(args.get(1).map(String::as_str), Some("setup"));
        // `meson setup <builddir> <sourcedir>`: it writes compile_commands.json
        // into the build dir, which is exactly the probe dir.
        assert!(args.iter().any(|a| a == "/src/.govfuzz-build"), "{args:?}");
        assert!(args.iter().any(|a| a == "/src"), "{args:?}");
    }

    #[test]
    fn ninja_compdb_targets_the_tree() {
        assert_eq!(
            ninja_compdb_args(Path::new("/src")),
            vec!["ninja", "-C", "/src", "-t", "compdb"]
        );
    }

    #[test]
    fn detects_bazel_and_scons_and_their_interception_commands() {
        let b = tmpdir();
        fs::write(b.join("WORKSPACE"), "").unwrap();
        fs::write(b.join("BUILD.bazel"), "").unwrap();
        assert_eq!(detect_build_system(&b), BuildSystem::Bazel);
        assert_eq!(
            interception_build_command(BuildSystem::Bazel),
            Some("bazel build --spawn_strategy=local //...")
        );
        let _ = fs::remove_dir_all(&b);

        let s = tmpdir();
        fs::write(s.join("SConstruct"), "").unwrap();
        assert_eq!(detect_build_system(&s), BuildSystem::SCons);
        assert_eq!(
            interception_build_command(BuildSystem::SCons),
            Some("scons")
        );
        let _ = fs::remove_dir_all(&s);

        // A natively-probed system still wins over a co-located Bazel marker.
        let c = tmpdir();
        fs::write(c.join("CMakeLists.txt"), "project(x)\n").unwrap();
        fs::write(c.join("WORKSPACE"), "").unwrap();
        assert_eq!(detect_build_system(&c), BuildSystem::CMake);
        let _ = fs::remove_dir_all(&c);
        // Natively-probed systems return no interception command.
        assert_eq!(interception_build_command(BuildSystem::CMake), None);
    }

    #[test]
    fn sole_nested_project_root_is_found_but_monorepo_is_not_guessed() {
        let wrapper = tmpdir();
        let project = wrapper.join("expat");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("CMakeLists.txt"), "project(expat)\n").unwrap();
        assert_eq!(
            unique_nested_build_root(&wrapper).as_deref(),
            Some(project.as_path())
        );

        let second = wrapper.join("another-library");
        fs::create_dir_all(&second).unwrap();
        fs::write(second.join("meson.build"), "project('other', 'c')\n").unwrap();
        assert_eq!(
            unique_nested_build_root(&wrapper),
            None,
            "an ambiguous monorepo needs an explicit scan root"
        );
        let _ = fs::remove_dir_all(&wrapper);
    }

    #[test]
    fn intercept_names_cover_standard_and_vendor_compilers() {
        let names = intercept_compiler_names();
        for must in ["cc", "c++", "gcc", "g++", "clang", "clang++"] {
            assert!(names.contains(&must), "missing standard frontend {must}");
        }
        // Named vendor compilers for radar/RTOS/defense builds.
        for vendor in [
            "dcc", "dplus", "ccarm", "cxarm", "qcc", "q++", "iccarm", "armclang",
        ] {
            assert!(names.contains(&vendor), "missing vendor compiler {vendor}");
        }
    }

    #[test]
    fn cross_prefixed_compilers_are_recognized_bare_ones_are_not() {
        assert!(is_cross_compiler_name("aarch64-linux-gnu-gcc"));
        assert!(is_cross_compiler_name("arm-none-eabi-g++"));
        assert!(is_cross_compiler_name("x86_64-w64-mingw32-cc"));
        assert!(is_cross_compiler_name("ntoaarch64-gcc")); // QNX
                                                           // Bare names are handled by the curated list, not the prefix scanner.
        assert!(!is_cross_compiler_name("gcc"));
        assert!(!is_cross_compiler_name("g++"));
        assert!(!is_cross_compiler_name("-gcc"));
        // Non-compilers must never be shimmed.
        assert!(!is_cross_compiler_name("ld"));
        assert!(!is_cross_compiler_name("ar"));
        assert!(!is_cross_compiler_name("python3"));
    }

    #[test]
    fn intercept_wrapper_logs_then_execs_absolute_real_compiler() {
        let s = intercept_wrapper_script("/usr/bin/gcc");
        assert!(
            s.contains("GF_CC_LOG"),
            "must append to the shared log: {s}"
        );
        assert!(s.contains("ARG "), "must record each argument: {s}");
        assert!(s.contains("CC %s"), "must record the real compiler: {s}");
        // Execs the ABSOLUTE real compiler (no PATH re-lookup -> no shim loop).
        assert!(s.contains("exec '/usr/bin/gcc'"), "{s}");
    }

    #[test]
    fn parse_intercept_log_recovers_per_record_compiler_and_source() {
        let log = "DIR /proj\nCC /usr/bin/clang\nARG -I/proj/include\nARG -DFOO=1\nARG -c\nARG foo.c\nENDREC\n";
        let entries = parse_intercept_log(log);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.directory, PathBuf::from("/proj"));
        assert_eq!(e.file, PathBuf::from("/proj/foo.c"));
        // arguments[0] is the actual frontend for this TU, not a fixed default.
        assert_eq!(e.arguments[0], "/usr/bin/clang");
        assert!(e.arguments.iter().any(|a| a == "-I/proj/include"));
        assert!(e.arguments.iter().any(|a| a == "-DFOO=1"));
    }

    #[test]
    fn parse_intercept_log_skips_records_with_no_source() {
        // A link step (`cc foo.o -o foo`) has no .c/.cc source -> not a DB entry.
        let log = "DIR /p\nCC /usr/bin/cc\nARG foo.o\nARG -o\nARG foo\nENDREC\n";
        assert!(parse_intercept_log(log).is_empty());
    }

    #[test]
    fn intercept_env_prepends_shim_dir_and_sets_log() {
        let env = intercept_env(
            Path::new("/p/intercept"),
            Path::new("/p/intercept/cc-invocations.log"),
            Some(Path::new("/p/intercept/cc")),
            Some(Path::new("/p/intercept/c++")),
        );
        let path = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(
            path.split(':').next(),
            Some("/p/intercept"),
            "shim dir must be first on PATH: {path}"
        );
        assert!(env
            .iter()
            .any(|(k, v)| k == "GF_CC_LOG" && v == "/p/intercept/cc-invocations.log"));
        assert!(env.iter().any(|(k, v)| k == "CC" && v == "/p/intercept/cc"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "CXX" && v == "/p/intercept/c++"));
    }

    #[test]
    fn dedup_intercept_entries_collapses_same_source_keeps_richest() {
        let mk = |file: &str, args: &[&str]| ProbeEntry {
            directory: PathBuf::from("/p"),
            file: PathBuf::from(file),
            arguments: args.iter().map(|s| s.to_string()).collect(),
        };
        // The PATH shim and the LD_PRELOAD interposer can both log a.c (and the
        // interposer can log it via execvp + the internal execve): collapse to one.
        let entries = vec![
            mk("/p/a.c", &["cc", "-c", "a.c"]),
            mk("/p/a.c", &["/usr/bin/cc", "-Iinc", "-c", "a.c"]), // richer dup
            mk("/p/b.c", &["cc", "-c", "b.c"]),
        ];
        let out = dedup_intercept_entries(entries);
        assert_eq!(out.len(), 2, "a.c must collapse to a single entry");
        // First-seen order preserved.
        assert_eq!(out[0].file, PathBuf::from("/p/a.c"));
        assert_eq!(out[1].file, PathBuf::from("/p/b.c"));
        // The richest record (the one carrying -Iinc) wins.
        assert!(out[0].arguments.iter().any(|a| a == "-Iinc"), "{out:?}");

        let out = dedup_intercept_entries(vec![
            mk("/p/a.c", &["clang", "-c", "a.c"]),
            mk(
                "/p/a.c",
                &[
                    "clang",
                    "-cc1",
                    "-internal-isystem",
                    "/usr/include",
                    "-o",
                    "/tmp/a-random.o",
                    "a.c",
                ],
            ),
        ]);
        assert!(
            !out[0].arguments.iter().any(|argument| argument == "-cc1"),
            "the replayable driver command must beat a richer cc1 child: {out:?}"
        );
    }

    #[test]
    fn intercepts_a_real_custom_build_into_a_compile_db() {
        // Needs a host C compiler; skip cleanly when absent (matches govfuzz's
        // toolchain-gated test policy).
        if real_compiler().is_none()
            || which::which("clang").is_err()
            || (which::which("llvm-ar").is_err() && which::which("ar").is_err())
        {
            return;
        }
        let root = tmpdir();
        fs::create_dir_all(root.join("inc")).unwrap();
        fs::write(root.join("foo.c"), "int foo(int x){return x+1;}\n").unwrap();
        fs::write(
            root.join("consumer.c"),
            "int foo(int); int main(void){return foo(1) != 2;}\n",
        )
        .unwrap();
        // A custom build script that invokes the compiler BY NAME (the case
        // CC/CXX-env interception alone would miss).
        fs::write(
            root.join("build.sh"),
            "#!/bin/sh\ncc -Iinc -DFOO=1 -c foo.c -o foo.o\nar rcs libfoo.a foo.o\ncc consumer.c libfoo.a -lm -o consumer\n",
        )
        .unwrap();
        // Direct run (no sandbox) for determinism in CI.
        let db = probe_build_command(
            &root,
            "sh build.sh",
            None,
            &multicore_fuzz::SanitizerSelection::None,
        )
        .expect("interception must produce a compile database");
        let text = fs::read_to_string(&db).unwrap();
        assert!(text.contains("foo.c"), "db must reference the TU:\n{text}");
        assert!(
            text.contains("-Iinc"),
            "db must capture the include dir:\n{text}"
        );
        assert!(
            text.contains("-DFOO=1"),
            "db must capture the define:\n{text}"
        );
        let primary = root.join(PROBE_DIR).join("intercept-artifacts/libfoo.a");
        assert!(
            primary.is_file(),
            "root archive must enter owned probe storage"
        );
        assert!(
            compatible_probe_static_libraries(&root, &multicore_fuzz::SanitizerSelection::None)
                .contains(&primary),
            "mirrored archive must carry the exact instrumentation manifest"
        );
        let coverage = coverage_variant_for_probe_archive(&primary)
            .expect("intercepted archive must have a source-coverage variant");
        assert!(coverage.is_file());
        assert!(
            probe_archive_link_dependencies(&root, &primary)
                .iter()
                .any(|path| path.file_name().is_some_and(|name| name == "libm.so")),
            "intercepted consumer link must preserve the archive's -lm dependency"
        );
        assert_eq!(
            compile_output_name(&["clang".to_owned(), "-ofoo.o".to_owned()]).as_deref(),
            Some("foo.o")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn detects_msbuild_solution_then_cmake_wins() {
        let root = tmpdir();
        fs::create_dir_all(root.join("msvc")).unwrap();
        // A .sln nested a level down is still detected as MSBuild.
        fs::write(
            root.join("msvc/app.sln"),
            "Microsoft Visual Studio Solution File\n",
        )
        .unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::MSBuild);
        // CMake still takes precedence when both exist (it emits a DB natively).
        fs::write(root.join("CMakeLists.txt"), "project(x)\n").unwrap();
        assert_eq!(detect_build_system(&root), BuildSystem::CMake);
    }

    #[test]
    fn vcxproj_entries_extract_includes_defines_and_sources() {
        let root = tmpdir();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("include")).unwrap();
        fs::write(root.join("src/parser.c"), "int p(void){return 0;}\n").unwrap();
        let vcxproj = root.join("lib.vcxproj");
        fs::write(
            &vcxproj,
            r#"<?xml version="1.0"?>
<Project>
  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>$(ProjectDir)include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions Condition="'$(Config)'=='Release'">PARSERLIB_BUILD;WIN32;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="src\parser.c" />
  </ItemGroup>
</Project>"#,
        )
        .unwrap();
        let entries = vcxproj_entries(&vcxproj);
        assert_eq!(entries.len(), 1, "one ClCompile source -> one entry");
        let args = entries[0].arguments.join(" ");
        assert!(
            args.contains(&format!(
                "-I{}",
                harness_gen::build_safety::make_path(&root.join("include"))
            )),
            "include dir resolved from $(ProjectDir): {args}"
        );
        assert!(
            args.contains("-DPARSERLIB_BUILD"),
            "define extracted: {args}"
        );
        assert!(args.contains("-DWIN32"), "second define extracted: {args}");
        assert!(
            !args.contains("%("),
            "inherited %(...) placeholders dropped: {args}"
        );
        assert_eq!(entries[0].file, root.join("src").join("parser.c"));
    }

    #[test]
    fn parses_cc_log_into_compile_entries() {
        // Two recorded invocations; only the one that names a source becomes an
        // entry, with the real compiler prepended and the file path resolved.
        let log = "/work/sb\n\
                   ARG -c\n\
                   ARG -I/work/inc\n\
                   ARG -DCFG=1\n\
                   ARG cfe_msg.c\n\
                   ARG -o\n\
                   ARG cfe_msg.o\n\
                   ENDREC\n\
                   /work\n\
                   ARG --version\n\
                   ENDREC\n";
        let entries = parse_cc_log(log, "/usr/bin/cc");
        assert_eq!(entries.len(), 1, "only the compile invocation is an entry");
        let e = &entries[0];
        assert_eq!(e.directory, PathBuf::from("/work/sb"));
        assert_eq!(e.file, PathBuf::from("/work/sb/cfe_msg.c"));
        assert_eq!(e.arguments[0], "/usr/bin/cc");
        assert!(e.arguments.contains(&"-I/work/inc".to_owned()));
        assert!(e.arguments.contains(&"-DCFG=1".to_owned()));
    }

    #[test]
    fn source_arg_recognizes_c_and_cpp() {
        assert!(is_source_arg("foo.c"));
        assert!(is_source_arg("a/b/foo.cpp"));
        assert!(!is_source_arg("foo.o"));
        assert!(!is_source_arg("-I/x"));
    }

    #[test]
    fn cmake_missing_dependency_names_the_required_package() {
        // §26.2: a libspng-style `find_package(ZLIB REQUIRED)` failure must be
        // reported by package name, not as a generic "no compile_commands.json".
        let stderr = "\
-- Configuring incomplete, errors occurred!
CMake Error at /usr/share/cmake-3.28/Modules/FindPackageHandleStandardArgs.cmake:230 (message):
  Could NOT find ZLIB (missing: ZLIB_LIBRARY ZLIB_INCLUDE_DIR)
Call Stack (most recent call first):
  CMakeLists.txt:12 (find_package)
";
        assert_eq!(
            cmake_missing_dependency(stderr).as_deref(),
            Some("ZLIB"),
            "must extract the missing package name from the FindPackage error"
        );
        // A configure failure with no missing-dependency line falls back to the
        // generic path (None) so we don't fabricate a package name.
        assert!(
            cmake_missing_dependency("CMake Error: some unrelated configure failure\n").is_none()
        );
        // A version-qualified miss still names just the package.
        assert_eq!(
            cmake_missing_dependency("  Could NOT find OpenSSL: found version \"1.0\"\n")
                .as_deref(),
            Some("OpenSSL")
        );
    }

    #[test]
    fn discover_static_libraries_finds_archives_in_build_and_probe_dirs() {
        // §26.1: an already-built `*.a` under the probe dir or a conventional
        // build dir (including a nested `build/lib/`) is discovered so the harness
        // link can pull the whole library in.
        let root = tmpdir();
        fs::create_dir_all(root.join(PROBE_DIR)).unwrap();
        fs::create_dir_all(root.join("build/lib")).unwrap();
        fs::create_dir_all(root.join("build/CMakeFiles/foo.dir")).unwrap();
        fs::write(root.join(PROBE_DIR).join("libroot.a"), b"!<arch>\n").unwrap();
        fs::write(root.join("build/lib/libnested.a"), b"!<arch>\n").unwrap();
        // CMakeFiles bookkeeping is skipped, and non-archives are ignored.
        fs::write(root.join("build/CMakeFiles/foo.dir/skip.a"), b"!<arch>\n").unwrap();
        fs::write(root.join("build/foo.o"), b"obj").unwrap();

        let libs = discover_static_libraries(&root);
        assert!(
            libs.contains(&root.join(PROBE_DIR).join("libroot.a")),
            "probe-dir archive must be found: {libs:?}"
        );
        assert!(
            libs.contains(&root.join("build/lib/libnested.a")),
            "nested build archive must be found: {libs:?}"
        );
        assert!(
            !libs.iter().any(|p| p.ends_with("skip.a")),
            "CMakeFiles bookkeeping archives must be skipped: {libs:?}"
        );
        assert!(
            !libs.iter().any(|p| p.extension().is_some_and(|e| e == "o")),
            "object files are not archives: {libs:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn generated_header_dirs_returns_build_dirs_holding_headers() {
        // §26.8: a CMake-generated export/config header dropped into the build
        // (here the probe) dir must surface so the harness include path finds it.
        let root = tmpdir();
        let probe = root.join(PROBE_DIR);
        fs::create_dir_all(probe.join("gen")).unwrap();
        fs::create_dir_all(probe.join("CMakeFiles")).unwrap();
        fs::write(probe.join("miniz_export.h"), "#define MINIZ_EXPORT\n").unwrap();
        fs::write(probe.join("gen/config.h"), "#define HAVE_X 1\n").unwrap();
        // CMakeFiles internals are skipped even when they hold a .h.
        fs::write(probe.join("CMakeFiles/internal.h"), "x").unwrap();

        let dirs = generated_header_dirs(&root);
        assert!(
            dirs.contains(&probe),
            "probe dir holding miniz_export.h must be returned: {dirs:?}"
        );
        assert!(
            dirs.contains(&probe.join("gen")),
            "nested dir holding config.h must be returned: {dirs:?}"
        );
        assert!(
            !dirs.iter().any(|p| p.ends_with("CMakeFiles")),
            "CMakeFiles must be skipped: {dirs:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
