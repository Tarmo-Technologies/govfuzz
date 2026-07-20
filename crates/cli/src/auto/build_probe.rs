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
//! * **CMake** — `cmake -S <tree> -B <tree>/.govfuzz-build
//!   -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` (configure only): CMake writes the DB
//!   directly and runs codegen during configure.
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

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory under the scanned tree where the probe writes its compile database
/// and (for the Make tier) the compiler wrapper + invocation log. Mirrored by
/// `compile_database_candidates` in `generate_harness`, so the produced DB is
/// found without any extra plumbing.
pub const PROBE_DIR: &str = ".govfuzz-build";
const PROBE_REQUIREMENTS_FILE: &str = "missing-requirements.json";

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
        eprintln!(
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
    let proj_dir_slash = format!("{}/", proj_dir.display());
    let resolve_macros = |raw: &str| -> String {
        raw.replace("$(ProjectDir)", &proj_dir_slash)
            .replace(
                "$(MSBuildProjectDirectory)",
                &proj_dir.display().to_string(),
            )
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
            let s = abs.display().to_string();
            if !include_dirs.contains(&s) {
                include_dirs.push(s);
            }
        }
    }
    // The project dir itself is always an include root (for `#include "sibling.h"`).
    let proj_dir_s = proj_dir.display().to_string();
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

#[derive(Debug, Serialize)]
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
pub fn probe_build(tree: &Path, sandbox_program: Option<&Path>) -> Option<PathBuf> {
    let probe_dir = tree.join(PROBE_DIR);
    if std::fs::create_dir_all(&probe_dir).is_err() {
        return None;
    }
    let _ = std::fs::remove_file(probe_dir.join(PROBE_REQUIREMENTS_FILE));
    let db = probe_dir.join("compile_commands.json");
    match detect_build_system(tree) {
        BuildSystem::CMake => probe_cmake(tree, &probe_dir, &db, sandbox_program),
        BuildSystem::Meson => probe_meson(tree, &probe_dir, &db, sandbox_program),
        BuildSystem::MSBuild => probe_msbuild(tree, &db),
        BuildSystem::Make => probe_make(tree, &probe_dir, &db, sandbox_program),
        BuildSystem::Ninja => probe_ninja(tree, &db, sandbox_program),
        bs @ (BuildSystem::Bazel | BuildSystem::SCons) => {
            // No native compile DB: run the build's own command under compiler
            // interception (the PATH shim + LD_PRELOAD exec shim recover flags).
            let command = interception_build_command(bs).expect("bazel/scons command");
            eprintln!(
                "govfuzz auto: --probe-build: intercepting `{command}` to recover compile flags"
            );
            probe_build_command(tree, command, sandbox_program)
        }
        BuildSystem::None => {
            eprintln!(
                "govfuzz auto: --probe-build found no CMake/Meson/MSBuild/Make/Ninja/Bazel/SCons \
                 build at {} (use --build-command \"<cmd>\" to intercept a custom build)",
                tree.display()
            );
            None
        }
    }
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
        eprintln!("govfuzz auto: --run-untrusted: no Ada project (alire.toml/.gpr) at {}; skipping Ada build probe", tree.display());
        return;
    }
    if has_alire && find_on_path("alr") {
        eprintln!("govfuzz auto: --run-untrusted: running `alr build` to generate Alire config + fetch deps");
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
            eprintln!(
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
    eprintln!(
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
) -> Option<PathBuf> {
    if !find_on_path("cmake") {
        eprintln!("govfuzz auto: --probe-build: cmake not on PATH; skipping CMake probe");
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
    let args = cmake_probe_args(tree, probe_dir, cfg!(windows), find_on_path("ninja"));
    // Capture (rather than inherit) cmake's output so a missing-dependency
    // configure abort can be reported ACTIONABLY (§26.2). The output is replayed
    // to the parent streams afterwards so build progress/errors stay visible.
    let mut command = build_command(tree, &args, &[], sandbox_program);
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("govfuzz auto: --probe-build: failed to run cmake: {error}");
            return None;
        }
    };
    use std::io::Write;
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    if db.is_file() {
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
            eprintln!(
                "govfuzz auto: --probe-build: CMake configure FAILED — required dependency `{pkg}` was \
             not found (`find_package({pkg} REQUIRED)`). This aborted the whole probe, so no \
             compile_commands.json was produced and every target will fail to build until it is \
             resolved. Install `{pkg}` (its dev headers/library) or point CMake at it (e.g. set \
             `{pkg}_ROOT`/`CMAKE_PREFIX_PATH`), then re-run with --probe-build."
            )
        }
        None => eprintln!(
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
    for sub in RECOVERED_ARTIFACT_DIRS {
        collect_static_libraries(&tree.join(sub), 0, &mut out);
    }
    out.sort();
    out.dedup();
    out
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

/// CMake configure args for the compile-database probe. On Windows the default
/// generator is the Visual Studio generator, which ignores
/// `CMAKE_EXPORT_COMPILE_COMMANDS` (it never writes compile_commands.json); Ninja
/// honors it and ships with both VS Build Tools and w64devkit, so prefer Ninja
/// there and pin clang so the recovered flags are gcc-style (`-I`/`-D`) — matching
/// govfuzz's clang-based harness build — rather than MSVC `/I`/`/D`. On Unix the
/// default (Makefiles) generator already emits the database. Pure so it is
/// unit-testable off-Windows.
fn cmake_probe_args(tree: &Path, probe_dir: &Path, windows: bool, ninja: bool) -> Vec<String> {
    let mut args = vec![
        "cmake".to_owned(),
        "-S".to_owned(),
        tree.display().to_string(),
        "-B".to_owned(),
        probe_dir.display().to_string(),
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".to_owned(),
    ];
    if windows && ninja {
        args.extend([
            "-G".to_owned(),
            "Ninja".to_owned(),
            "-DCMAKE_C_COMPILER=clang".to_owned(),
            "-DCMAKE_CXX_COMPILER=clang++".to_owned(),
        ]);
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
        eprintln!("govfuzz auto: --probe-build: meson not on PATH; skipping Meson probe");
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
        eprintln!("govfuzz auto: --probe-build: ninja not on PATH; skipping Ninja probe");
        return None;
    }
    let mut command = build_command(tree, &ninja_compdb_args(tree), &[], sandbox_program);
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("govfuzz auto: --probe-build: failed to run ninja compdb: {error}");
            return None;
        }
    };
    if !output.status.success() || output.stdout.is_empty() {
        eprintln!("govfuzz auto: --probe-build: `ninja -t compdb` produced no database");
        return None;
    }
    std::fs::write(db, &output.stdout).ok()?;
    Some(db.to_path_buf())
}

fn probe_make(
    tree: &Path,
    probe_dir: &Path,
    db: &Path,
    sandbox_program: Option<&Path>,
) -> Option<PathBuf> {
    if !find_on_path("make") {
        eprintln!("govfuzz auto: --probe-build: make not on PATH; skipping Make probe");
        return None;
    }
    let Some(real_cc) = real_compiler() else {
        eprintln!("govfuzz auto: --probe-build: no C compiler on PATH; skipping Make probe");
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
fn intercept_wrapper_script(real_abs: &str) -> String {
    format!(
        "#!/bin/sh\n\
         {{\n\
         printf 'DIR %s\\n' \"$PWD\"\n\
         printf 'CC %s\\n' '{real}'\n\
         for a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done\n\
         printf 'ENDREC\\n'\n\
         }} >> \"$GF_CC_LOG\"\n\
         exec '{real}' \"$@\"\n",
        real = real_abs
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
    let mut cc_shim: Option<PathBuf> = None;
    let mut cxx_shim: Option<PathBuf> = None;
    for (name, real) in collect_intercept_targets() {
        let shim = intercept_dir.join(&name);
        if std::fs::write(&shim, intercept_wrapper_script(&real.display().to_string())).is_err() {
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
    }
    if !wrote_any {
        eprintln!(
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
    run_build(
        tree,
        &["sh".to_owned(), "-c".to_owned(), command.to_owned()],
        &env,
        sandbox_program,
    );

    let log_text = std::fs::read_to_string(&log).ok()?;
    let entries = dedup_intercept_entries(parse_intercept_log(&log_text));
    if entries.is_empty() {
        eprintln!(
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

/// Collapse records that refer to the same translation unit (normalized `file`),
/// keeping the richest (most arguments). The PATH shim and the LD_PRELOAD `exec`
/// interposer can each log the same compile — and the interposer can see one
/// name-based compile via several `exec*` variants — so this is what makes
/// running both together (and the interposer's broad hooking) safe. First-seen
/// order is preserved.
fn dedup_intercept_entries(entries: Vec<ProbeEntry>) -> Vec<ProbeEntry> {
    use std::collections::HashMap;
    let mut order: Vec<String> = Vec::new();
    let mut best: HashMap<String, ProbeEntry> = HashMap::new();
    for entry in entries {
        let key = entry.file.to_string_lossy().into_owned();
        match best.get(&key) {
            Some(prev) if prev.arguments.len() >= entry.arguments.len() => {}
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
) {
    let mut command = build_command(cwd, args, env, sandbox_program);
    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!(
            "govfuzz auto: --probe-build: `{}` exited with {status} (a partial build can still yield a usable compile database)",
            args.join(" ")
        ),
        Err(error) => eprintln!("govfuzz auto: --probe-build: failed to run `{}`: {error}", args.join(" ")),
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
        // Unix keeps the default (Makefiles) generator — it already emits the DB.
        let lin = cmake_probe_args(tree, probe, false, true);
        assert!(lin
            .iter()
            .any(|a| a == "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"));
        assert!(
            !lin.iter().any(|a| a == "-G"),
            "unix must not pin a generator: {lin:?}"
        );
        // Windows with ninja: force Ninja + clang so the DB is actually written
        // (the VS generator ignores the export flag) with gcc-style flags.
        let win = cmake_probe_args(tree, probe, true, true).join(" ");
        assert!(win.contains("-G Ninja"), "windows must pin Ninja: {win}");
        assert!(win.contains("CMAKE_C_COMPILER=clang"), "{win}");
        assert!(win.contains("CMAKE_CXX_COMPILER=clang++"), "{win}");
        // Windows without ninja: fall back to the default generator (best effort).
        let win_no_ninja = cmake_probe_args(tree, probe, true, false);
        assert!(!win_no_ninja.iter().any(|a| a == "-G"));
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
    }

    #[test]
    fn intercepts_a_real_custom_build_into_a_compile_db() {
        // Needs a host C compiler; skip cleanly when absent (matches govfuzz's
        // toolchain-gated test policy).
        if real_compiler().is_none() {
            return;
        }
        let root = tmpdir();
        fs::create_dir_all(root.join("inc")).unwrap();
        fs::write(root.join("foo.c"), "int foo(int x){return x+1;}\n").unwrap();
        // A custom build script that invokes the compiler BY NAME (the case
        // CC/CXX-env interception alone would miss).
        fs::write(
            root.join("build.sh"),
            "#!/bin/sh\ncc -Iinc -DFOO=1 -c foo.c -o foo.o\n",
        )
        .unwrap();
        // Direct run (no sandbox) for determinism in CI.
        let db = probe_build_command(&root, "sh build.sh", None)
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
            args.contains(&format!("-I{}", root.join("include").display())),
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
