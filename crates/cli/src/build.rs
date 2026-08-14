// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use compiler_adapter::{probe_compiler, BuildMode, CompilerAdapter, ToolchainConfig};
use project_synth::{write_project, ProjectSpec, SourceRoot, Switches};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::probe_backend::{materialize_runtime_sources, ProbeBackend};

/// Explicit C/C++ compiler + flag override for the harness `make` invocation.
/// `govfuzz auto` passes this ONLY for a foreign-platform/arch candidate it is
/// cross-compiling (see `auto::cross_target`); host-native builds pass `None`
/// and keep the existing clang defaults. `cflags`/`cxxflags`, when non-empty,
/// replace the Makefile's `CFLAGS ?=`/`CXXFLAGS ?=` defaults — the cross GCCs
/// reject the clang `-fsanitize-coverage=trace-pc-guard` baked into them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFamilyCompilerOverride {
    pub cc: String,
    pub cxx: String,
    pub cflags: Vec<String>,
    pub cxxflags: Vec<String>,
}

/// Activate a coverage-capable Clang from the RHEL 7 LLVM Software Collection
/// when the base-system `clang` is too old for SanitizerCoverage. The SCL ships
/// outside the normal PATH and needs its lib64 directory at compiler run time;
/// applying those variables to this process also covers every later `make`,
/// replay, and optional sanitizer build spawned by `auto`.
///
/// This is deliberately capability-based rather than version-based: a vendor
/// compiler is accepted when it compiles the exact edge+comparison coverage
/// flags govfuzz uses. Explicit CC/CXX choices remain authoritative.
pub(crate) fn activate_compatible_clang() -> bool {
    #[cfg(unix)]
    {
        if std::env::var_os("CC").is_some() || std::env::var_os("CXX").is_some() {
            return false;
        }
        if clang_supports_govfuzz_coverage("clang", None) {
            return false;
        }

        const SCL_ROOTS: [&str; 2] = [
            "/opt/rh/llvm-toolset-7.0/root/usr",
            "/opt/rh/llvm-toolset-7/root/usr",
        ];
        for root in SCL_ROOTS {
            let root = Path::new(root);
            let clang = root.join("bin/clang");
            let lib64 = root.join("lib64");
            if !clang.is_file() || !clang_supports_govfuzz_coverage(&clang, Some(&lib64)) {
                continue;
            }

            prepend_process_path("PATH", &[root.join("bin"), root.join("sbin")]);
            prepend_process_path("LD_LIBRARY_PATH", &[lib64]);
            gfeprintln!(
                "govfuzz: using RHEL 7 LLVM Toolset compiler {} (base clang lacks SanitizerCoverage)",
                clang.display()
            );
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn clang_supports_govfuzz_coverage(
    compiler: impl AsRef<std::ffi::OsStr>,
    runtime_lib: Option<&Path>,
) -> bool {
    let mut command = std::process::Command::new(compiler);
    command.args([
        "-x",
        "c",
        "-c",
        "/dev/null",
        "-o",
        "/dev/null",
        "-fsanitize-coverage=trace-pc-guard,trace-cmp",
    ]);
    if let Some(runtime_lib) = runtime_lib {
        let mut paths = vec![runtime_lib.to_path_buf()];
        if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(paths) {
            command.env("LD_LIBRARY_PATH", joined);
        }
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn prepend_process_path(key: &str, prefixes: &[PathBuf]) {
    let mut paths = prefixes.to_vec();
    if let Some(existing) = std::env::var_os(key) {
        paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var(key, joined);
    }
}

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct BuildArgs {
    /// Path to govfuzz_work directory containing src_instrumented and harnesses/generated_harnesses.
    pub work_dir: PathBuf,

    /// Governing Ada project whose evaluated build semantics the generated
    /// instrumented overlay should inherit.
    #[arg(long)]
    pub source_project: Option<PathBuf>,

    /// Harness id to build. Defaults to the only harness present (errors if multiple).
    #[arg(long)]
    pub harness: Option<String>,

    /// Target triple for cross-compilation project synthesis and default tool prefix.
    #[arg(long)]
    pub target: Option<String>,

    /// Ada runtime name to pass through the generated GPR project.
    #[arg(long)]
    pub runtime: Option<String>,

    /// Toolchain executable prefix, e.g. aarch64-linux-gnu for aarch64-linux-gnu-gprbuild.
    #[arg(long)]
    pub toolchain: Option<String>,

    /// AdaFuzz.Probe runtime backend to compile into the harness runtime.
    #[arg(long, value_enum, default_value = "host_file")]
    pub(crate) probe_backend: ProbeBackend,

    /// For C/C++ harnesses: which Makefile target to build.
    /// `libfuzzer` (default) runs `make` which produces a libFuzzer binary
    /// driven by sanitizers; `afl++` runs `make afl` which produces a
    /// persistent-mode AFL++ binary suitable for `govfuzz fuzz --engine afl++`.
    #[arg(long, value_enum, default_value = "libfuzzer")]
    pub c_engine: CEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CEngine {
    /// `make` target - libFuzzer entrypoint (default).
    Libfuzzer,
    /// `make afl` target - AFL++ persistent-mode entrypoint.
    #[value(name = "afl++")]
    AflPlusPlus,
}

pub fn run(args: BuildArgs) -> i32 {
    // Try the C / C++ make-based build path first. The generated harness
    // ships its own Makefile (Slice A / B of #286); if it's present, the
    // Ada-specific prepare_layout below would fail on the missing
    // src_instrumented dir anyway.
    if let Some(exit) = try_run_c_make_build(&args) {
        return exit;
    }

    let layout = match prepare_layout(&args) {
        Ok(layout) => layout,
        Err(error) => {
            gfeprintln!("{error}");
            return 3;
        }
    };

    let adapter = match CompilerAdapter::discover_for(toolchain_config(&args)) {
        Ok(adapter) => adapter,
        Err(error) => {
            gfeprintln!("{error}");
            return 2;
        }
    };

    if let Err(error) = probe_compiler(&adapter) {
        gfeprintln!("{error}");
        return 2;
    }

    let result = match adapter.build(&layout.project_path) {
        Ok(result) => result,
        Err(error) => {
            gfeprintln!("{error}");
            return 2;
        }
    };

    print!("{}", result.stdout);
    gfeprint!("{}", result.stderr);

    if result.exit_code == 0 {
        0
    } else {
        1
    }
}

pub(crate) struct BuildLayout {
    pub(crate) project_path: PathBuf,
}

/// Whether `dir` directly contains at least one C source file (`.c`). Used to
/// decide whether the generated Ada project must also declare the C language so
/// gprbuild compiles + links the C glue a real Ada library binds to. Non-recursive
/// because the generated project lists each source dir explicitly (no `**`).
fn dir_contains_c_source(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("c"))
            })
        })
        .unwrap_or(false)
}

/// Whether a staged source directory contains an explicit implementation of a
/// predefined Ada hierarchy. Alternate runtime projects intentionally provide
/// `Ada.*`/`System.*` units; GNAT requires implementation mode (`-gnatg`) to
/// compile those bodies. Structural parsing avoids triggering on comments or on
/// ordinary files that merely `with` a runtime unit.
fn dir_contains_in_tree_ada_runtime_unit(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let path = entry.path();
            if !path.extension().is_some_and(|extension| {
                extension.eq_ignore_ascii_case("ads") || extension.eq_ignore_ascii_case("adb")
            }) {
                return false;
            }
            let Ok(source) = crate::source_text::read_source_text(&path) else {
                return false;
            };
            let Ok(ast) = ada_parser::reconcile::build_structural_ast(&source, None, &path) else {
                return false;
            };
            ast.packages.iter().any(|package| {
                let root = package.name.split('.').next().unwrap_or(&package.name);
                matches!(
                    root.to_ascii_lowercase().as_str(),
                    "ada" | "system" | "interfaces" | "gnat"
                )
            })
        })
    })
}

/// C source *base names* in the source closure whose stem matches an Ada
/// `.ads`/`.adb` stem — these would collide on `<stem>.o`, which gprbuild rejects
/// ("... have the same object file name"). Returned for `Excluded_Source_Files`
/// so the Ada unit (the harness target) wins. Non-recursive to match the gpr's
/// literal `Source_Dirs` and the flat `src_instrumented/` layout; stems compared
/// case-insensitively (GNAT object names are the lowercased base stem).
fn colliding_c_basenames(roots: &[SourceRoot]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut ada_stems = BTreeSet::new();
    let mut c_files: Vec<(String, String)> = Vec::new(); // (stem, basename)
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root.path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let (Some(stem), Some(ext)) = (path.file_stem(), path.extension()) else {
                continue;
            };
            let stem = stem.to_string_lossy().to_ascii_lowercase();
            if ext.eq_ignore_ascii_case("ads") || ext.eq_ignore_ascii_case("adb") {
                ada_stems.insert(stem);
            } else if ext.eq_ignore_ascii_case("c") {
                if let Some(name) = path.file_name() {
                    c_files.push((stem, name.to_string_lossy().into_owned()));
                }
            }
        }
    }
    let mut out: Vec<String> = c_files
        .into_iter()
        .filter(|(stem, _)| ada_stems.contains(stem))
        .map(|(_, name)| name)
        .collect();
    out.sort();
    out.dedup();
    out
}

pub(crate) fn prepare_layout(args: &BuildArgs) -> Result<BuildLayout, String> {
    let work_dir = absolutize(&args.work_dir)?;
    if !work_dir.is_dir() {
        return Err(format!("work dir '{}' does not exist", work_dir.display()));
    }

    let source_dir = work_dir.join("src_instrumented");
    if !source_dir.is_dir() {
        return Err(format!(
            "work dir malformed: missing {}",
            source_dir.display()
        ));
    }

    let (harness_id, harness_dir) = select_harness(&work_dir, args.harness.as_deref())?;
    // Usually `main.adb` (`procedure Main`). A private-child-subprogram harness
    // (for a target whose signature uses parent-private types) is instead
    // `<parent>-gf_harness.adb`; detect it and the gpr renames its executable to
    // `main` so the rest of the pipeline finds `obj/main` unchanged.
    let main_file = detect_harness_main_file(&harness_dir).ok_or_else(|| {
        format!(
            "work dir malformed: no main.adb or *-gf_harness.adb in {}",
            harness_dir.display()
        )
    })?;

    let build_dir = work_dir.join("build").join(&harness_id);
    let ada_standard = detect_ada_standard(&source_dir, &work_dir)?;
    let obj_dir = build_dir.join("obj");
    fs::create_dir_all(&obj_dir)
        .map_err(|error| format!("create build directory '{}': {error}", obj_dir.display()))?;
    // Every harness in a sweep compiles the SAME project closure — only the main
    // and the stub set differ — so a per-harness object directory made a project
    // with N targets compile its units N times. Share one object directory across
    // the run and let gprbuild's own staleness check decide what to redo; the
    // executable stays in the per-harness `obj/` (via `Exec_Dir`) so a later
    // target's link cannot overwrite a binary an earlier finding replays against.
    let shared_obj_dir = work_dir.join(SHARED_ADA_OBJ_DIR);
    fs::create_dir_all(&shared_obj_dir).map_err(|error| {
        format!(
            "create shared object directory '{}': {error}",
            shared_obj_dir.display()
        )
    })?;

    let mut source_roots = vec![
        SourceRoot {
            path: source_dir,
            language: "Ada".to_owned(),
        },
        SourceRoot {
            path: harness_dir,
            language: "Ada".to_owned(),
        },
    ];
    let fake_corba_dir = work_dir.join("fake_corba");
    if fake_corba_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: fake_corba_dir,
            language: "Ada".to_owned(),
        });
    }
    let global_stubs_dir = work_dir.join("generated_stubs");
    if global_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: global_stubs_dir,
            language: "Ada".to_owned(),
        });
    }
    let auto_repair_stubs_dir = crate::auto::layout::harness_dir(&work_dir, &harness_id)
        .join("repairs")
        .join(crate::auto::repair::AUTO_ADA_STUBS_DIR);
    if auto_repair_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: auto_repair_stubs_dir,
            language: "Ada".to_owned(),
        });
    }
    let external_stubs_dir = work_dir.join(SHARED_ADA_STUBS_DIR);
    if external_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: external_stubs_dir,
            language: "Ada".to_owned(),
        });
    }

    let runtime_project_path = build_dir.join("adafuzz_runtime.gpr");
    write_runtime_project(&runtime_project_path, &build_dir, args.probe_backend).map_err(
        |error| {
            format!(
                "write runtime project '{}': {error}",
                runtime_project_path.display()
            )
        },
    )?;

    // Forward `with "<x>.gpr";` clauses from any user-supplied .gpr
    // files in the source root into our generated build project.
    // When a forwarded import resolves cleanly it's a no-op; when it
    // resolves to a missing path, gprbuild fails with "cannot find
    // <x>.gpr" which build_classifier maps to MissingGprImport so the
    // upstream maintainer sees the dependency they need to ship.
    let mut with_clauses = vec![PathBuf::from("adafuzz_runtime.gpr")];
    // <work_dir>/.. is the source root the auto CLI was pointed at;
    // for the standalone build path it's the project directory the
    // user invoked govfuzz against. Either way that's where the
    // user's *.gpr files live.
    let user_root = work_dir
        .parent()
        .unwrap_or(work_dir.as_path())
        .to_path_buf();
    // An extended project keeps all of its imports, and GPR has no way for the
    // child project to subtract one. Do not extend a project that imports
    // `adafuzz.gpr`: this build already supplies `adafuzz_runtime.gpr`, while a
    // stale relative AdaFuzz import either fails at the parent's original path
    // or creates duplicate runtime units. The instrumented source overlay still
    // carries the target sources, and the normal import-forwarder below keeps
    // every non-AdaFuzz dependency visible.
    // Offline-legacy audit #1/#7: never EXTEND a library, aggregate, or abstract
    // project. GNAT rejects extending a library project without `Library_Dir`
    // (and it can't hold the harness `Main`), an aggregate can't be extended at
    // all, and an abstract project has no sources — each aborts the whole build,
    // so an entire class of real Alire/GNAT library repos never fuzzes. The
    // instrumented source overlay already carries the governing project's
    // Source_Dirs, so those cases build as a standalone project with the user's
    // dependency imports forwarded below.
    let extends_project = args
        .source_project
        .as_ref()
        .filter(|project| !gpr_imports_adafuzz(project))
        .filter(|project| crate::auto::gpr_scenario::gpr_is_extendable_base(project))
        .cloned();
    if extends_project.is_none() {
        with_clauses.extend(discover_user_gpr_with_clauses(&user_root));
    }

    let project_path = build_dir.join("govfuzz_build.gpr");
    // A non-`main.adb` main (a child-subprogram harness) gets its executable
    // renamed to `main` so the downstream `obj/main` path is unchanged.
    let executable_name = (main_file != "main.adb").then(|| "main".to_owned());
    // #412: instrument the target+harness compile (NOT the uninstrumented runtime
    // project) with `-fsanitize-coverage=trace-pc` so the AdaFuzz trace-pc callback
    // records edge coverage and the engine fuzzes coverage-guided instead of blind.
    // Gated behind a cached probe of the Ada gcc: GNAT/GCC that lacks trace-pc
    // degrades to today's behavior (no flag, coverage_edges=0) rather than breaking
    // the build. A sentinel next to the build dir tells the fuzz engine the harness
    // is coverage-instrumented so it engages its CoverageTracker.
    let mut switches = Switches::default();
    let ada_cov_instrumented = ada_trace_pc_supported(&toolchain_config(args));
    if ada_cov_instrumented {
        switches.default.push(ADA_COV_TRACE_PC_FLAG.to_owned());
    }
    // Enable Ada 2012 assertion checks (-gnata): a failed precondition, postcondition,
    // type invariant, or `pragma Assert` raises Assertion_Error, which the exception
    // oracle reports as a contract violation (GF-557). This turns the target's OWN
    // specification into a fuzzing oracle — code that ships with assertions disabled
    // still gets them exercised under the fuzzer, at no cost to production behavior.
    switches.default.push("-gnata".to_owned());
    if source_roots
        .iter()
        .any(|root| dir_contains_in_tree_ada_runtime_unit(&root.path))
    {
        // `-gnatg` authorizes compilation of predefined-hierarchy units. It also
        // enables GNAT's own style profile, which is inappropriate for generated
        // harness/runtime support, so cancel style checks while retaining the
        // implementation-unit semantics.
        switches.default.push("-gnatg".to_owned());
        switches.default.push("-gnatyN".to_owned());
        switches.default.push("-gnatws".to_owned());
    }
    // Declare C in the project when any source dir carries C glue (copied in by
    // ensure_ada_src_instrumented from a real Ada library's bindings — gnatcoll's
    // gnatcoll_support.c / libc-wrappers.c). Without this gprbuild skips the .c and
    // the Ada link fails on the bound C symbols (gnatcoll_mmap, __gnatcoll_open, …).
    let compile_c = source_roots
        .iter()
        .any(|root| dir_contains_c_source(&root.path));
    // A C source that shares its stem with an Ada body/spec in the closure would
    // collide on object-file name (`sxxx.adb` + `sxxx.c` -> `sxxx.o`) and gprbuild
    // rejects the whole project. Exclude the C file — the Ada unit is the harness
    // target and must win. Only reachable when C is actually compiled.
    let excluded_source_files = if compile_c {
        colliding_c_basenames(&source_roots)
    } else {
        Vec::new()
    };
    let spec = ProjectSpec {
        project_name: "Govfuzz_Build".to_owned(),
        extends_project,
        source_roots,
        object_dir: shared_obj_dir,
        exec_dir: Some(obj_dir),
        main_adb: Some(main_file),
        ada_standard,
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        toolchain: args.toolchain.clone(),
        switches,
        with_clauses,
        executable_name,
        compile_c,
        excluded_source_files,
    };
    write_project(&spec, &project_path)
        .map_err(|error| format!("write project '{}': {error}", project_path.display()))?;

    // Force-fuzz: copy any synthesized stub `.gpr` for a missing external `with`ed
    // project (repairs/gpr_stubs/*.gpr) NEXT TO govfuzz_build.gpr, so gprbuild
    // resolves the import from the root project's directory and the project LOADS.
    // The repair loop then stubs the packages the code actually uses from it.
    // Copied every round because prepare_layout owns the build dir.
    let gpr_stubs_dir = crate::auto::layout::harness_dir(&work_dir, &harness_id)
        .join("repairs")
        .join(crate::auto::repair::AUTO_GPR_STUBS_DIR);
    if let Ok(entries) = fs::read_dir(&gpr_stubs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("gpr"))
            {
                if let Some(name) = path.file_name() {
                    let _ = fs::copy(&path, build_dir.join(name));
                }
            }
        }
    }

    // Drop / refresh the coverage sentinel to match what we actually emitted, so a
    // rebuild on a toolchain that lost trace-pc support doesn't leave a stale flag.
    let sentinel = build_dir.join(ADA_COV_SENTINEL);
    if ada_cov_instrumented {
        fs::write(&sentinel, b"trace-pc\n").map_err(|error| {
            format!("write coverage sentinel '{}': {error}", sentinel.display())
        })?;
    } else {
        let _ = fs::remove_file(&sentinel);
    }

    Ok(BuildLayout { project_path })
}

/// Walk `root` for top-level `.gpr` files and extract their
/// `with "...";` clauses to forward into the generated
/// `govfuzz_build.gpr`.
///
/// Relative imports are resolved against `root` (the directory of the
/// `.gpr` they were read from — these are top-level gprs sitting
/// directly in `root`) and lexically normalized into ABSOLUTE paths.
/// This is load-bearing: `govfuzz_build.gpr` lives at
/// `<work_dir>/build/<id>/`, a *different* directory depth than the
/// source gpr the clause came from, and gprbuild resolves a `with`
/// clause relative to the IMPORTING project's own directory. A clause
/// kept relative therefore resolves against the wrong base and the
/// `../` depth comes out wrong (work-dir-depth dependent), which is
/// the #411 bug. Absolutizing makes the forwarded clause
/// depth-independent. Already-absolute imports are normalized but
/// otherwise preserved. We deliberately do NOT `canonicalize`: a
/// genuinely-missing user dependency need not exist on disk, and we
/// still want the absolute *intended* path so the resulting
/// "imported project file not found" diagnostic names the real
/// location.
///
/// Imports of govfuzz's own bundled runtime (`ada_runtime/adafuzz.gpr`)
/// are skipped entirely: `prepare_layout` always adds the build-local
/// `adafuzz_runtime.gpr` to the with-clauses, which already provides
/// the AdaFuzz runtime units. Re-forwarding the bundled `adafuzz.gpr`
/// is redundant and is precisely the #411 trigger — depending on the
/// work-dir depth it either fails to resolve (reported as a missing
/// `adafuzz.gpr` import) or resolves and collides with
/// `adafuzz_runtime.gpr` ("unit ... cannot belong to several
/// projects"). Genuine user deps with other names are still forwarded
/// (now absolutized).
///
/// Subdirectories are skipped — we only want the project's
/// root-level user gprs, not the generated build/* gprs we created
/// ourselves.
fn discover_user_gpr_with_clauses(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let with_re = regex::Regex::new(r#"with\s+"([^"]+\.gpr)"\s*;"#).expect("regex");
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_file = path.is_file();
        let is_gpr = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("gpr"));
        if !is_file || !is_gpr {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for caps in with_re.captures_iter(&text) {
            let imported = PathBuf::from(&caps[1]);
            // Never re-forward govfuzz's bundled runtime: the build-local
            // adafuzz_runtime.gpr (added in prepare_layout) already provides
            // those units, so forwarding it is redundant and breaks the
            // build (#411 — missing-import or duplicate-unit, depending on
            // work-dir depth).
            if imported
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("adafuzz.gpr"))
            {
                continue;
            }
            // Absolutize relative imports against the source gpr's own dir so
            // the forwarded clause is depth-independent when written into
            // govfuzz_build.gpr at its deeper build/<id>/ location (#411).
            let resolved = if imported.is_absolute() {
                normalize_path_lexical(&imported)
            } else {
                normalize_path_lexical(&root.join(&imported))
            };
            out.push(resolved);
        }
    }
    out
}

fn gpr_imports_adafuzz(project: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(project) else {
        return false;
    };
    let with_re = regex::Regex::new(r#"with\s+"([^"]+\.gpr)"\s*;"#).expect("regex");
    let imports_runtime = with_re.captures_iter(&text).any(|caps| {
        Path::new(&caps[1])
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("adafuzz.gpr"))
    });
    imports_runtime
}

/// Lexically collapse `.`/`..` components of `path` without touching
/// the filesystem. Unlike `std::fs::canonicalize` this neither requires
/// the path to exist nor resolves symlinks — we want the absolute
/// *intended* path even for a dependency the user has not shipped yet.
fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Detect a C/C++ harness layout (generated by Slice A/B of #286) and run
/// the harness's Makefile directly. Returns `Some(exit_code)` when the
/// build was dispatched; `None` to fall through to the Ada path.
fn try_run_c_make_build(args: &BuildArgs) -> Option<i32> {
    let work_dir = absolutize(&args.work_dir).ok()?;
    let (harness_id, harness_dir) = select_harness(&work_dir, args.harness.as_deref()).ok()?;
    let makefile = harness_dir.join("Makefile");
    if !makefile.is_file() {
        return None;
    }
    let main_c = harness_dir.join("main.c");
    let main_cpp = harness_dir.join("main.cpp");
    if !main_c.is_file() && !main_cpp.is_file() {
        return None;
    }

    // Mirror the Ada path's `build/<harness-id>/main` layout so `govfuzz fuzz`
    // and the existing find_harness_executable helper find the binary.
    let build_dir = work_dir.join("build").join(&harness_id);
    if let Err(error) = fs::create_dir_all(&build_dir) {
        gfeprintln!("create build directory '{}': {error}", build_dir.display());
        return Some(2);
    }

    let (make_target, built_name, staged_name) = match args.c_engine {
        CEngine::Libfuzzer => (Some("main"), "main", "main"),
        CEngine::AflPlusPlus => (Some("afl"), "main_afl", "main_afl"),
    };
    gfeprintln!(
        "Building C/C++ harness '{}' via make{}",
        harness_id,
        make_target.map(|t| format!(" {t}")).unwrap_or_default()
    );
    let mut cmd = std::process::Command::new("make");
    cmd.current_dir(&harness_dir);
    if let Some(t) = make_target {
        cmd.arg(t);
    }
    let force_includes = repair_force_includes(&harness_dir);
    apply_c_family_make_env(&mut cmd, &[], &[], &force_includes, None);
    // Bounded and process-grouped: an unbounded `status()` here let one spinning
    // compile consume a whole campaign and outlive govfuzz entirely.
    let status = crate::command_output::status_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    );
    match status {
        Ok(s) if s.success() => {
            let built = harness_dir.join(built_name);
            if built.is_file() {
                let dest = build_dir.join(staged_name);
                if let Err(error) = fs::copy(&built, &dest) {
                    gfeprintln!(
                        "copy '{}' -> '{}': {error}",
                        built.display(),
                        dest.display()
                    );
                    return Some(2);
                }
                gfeprintln!("built harness binary -> {}", dest.display());
            } else {
                gfeprintln!(
                    "make reported success but did not produce expected harness binary '{}'",
                    built.display()
                );
                return Some(2);
            }
            Some(0)
        }
        Ok(s) => {
            gfeprintln!("make exited with status {:?}", s.code());
            Some(1)
        }
        Err(error) => {
            gfeprintln!("invoke make: {error}");
            Some(2)
        }
    }
}

/// Core of the auto C/C++ make build, parameterized on the make target. With
/// `make_target = None` it explicitly requests `main`; with `Some("afl")` it builds
/// the `main_afl` persistent-mode AFL binary. Explicit `main` is load-bearing:
/// an included per-TU object fragment can otherwise become GNU make's first/default
/// goal, return success, and leave no harness executable. Both targets receive the SAME
/// `AUTO_EXTRA_*` recovery env (extra sources / includes / force-includes), so the
/// AFL build sees the identical recovered context the `main` build used.
pub(crate) fn try_run_c_make_build_with_target(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
    make_target: Option<&str>,
    cxx_std: Option<&str>,
) -> std::process::Output {
    try_run_c_make_build_with_target_and_ldflags(
        work_dir,
        harness_id,
        extra_sources,
        extra_includes,
        compiler,
        make_target,
        cxx_std,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_run_c_make_build_with_target_and_ldflags(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
    make_target: Option<&str>,
    cxx_std: Option<&str>,
    extra_ldflags: Option<&str>,
) -> std::process::Output {
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let mut cmd = std::process::Command::new("make");
    cmd.current_dir(&harness_dir);
    let is_cpp = harness_dir.join("main.cpp").is_file();
    let prepared_extra_sources = match crate::generate_harness::prepare_repair_per_tu_context(
        &harness_dir,
        extra_sources,
        is_cpp,
    ) {
        Ok(sources) => sources,
        Err(error) => {
            // Make consumes this environment variable at parse time and
            // fails before compiling anything. Falling back to the shared
            // target flags here would silently recreate the context-loss
            // bug this preparation step exists to prevent.
            cmd.env(
                "GOVFUZZ_CONTEXT_PREPARE_FAILED",
                format!("could not prepare exact repair TU contexts: {error:#}"),
            );
            extra_sources.to_vec()
        }
    };
    cmd.arg(make_target.unwrap_or("main"));
    // Override the language standard for the legacy-dialect ladder. A make
    // command-line assignment wins over the Makefile's `?=` default. The two
    // Makefiles carry different variables, so route by which harness this is:
    // `CXX_STD` names a bare standard (`gnu++14`) that the C++ template splices
    // into `-std=`, and `C_STD` does the same on the C side, where it is empty by
    // default so an ordinary build carries no `-std` at all.
    if let Some(std) = cxx_std {
        cmd.arg(if is_cpp {
            format!("CXX_STD={std}")
        } else {
            format!("C_STD={std}")
        });
    }
    let force_includes = repair_force_includes(&harness_dir);
    apply_c_family_make_env(
        &mut cmd,
        &prepared_extra_sources,
        extra_includes,
        &force_includes,
        compiler,
    );
    if let Some(extra_ldflags) = extra_ldflags.filter(|value| !value.trim().is_empty()) {
        append_command_env_flags(&mut cmd, "AUTO_EXTRA_LDFLAGS", extra_ldflags);
    }
    crate::command_output::output_with_timeout(&mut cmd, std::time::Duration::from_secs(30 * 60))
        .expect("spawn make")
}

/// Append flags to an environment value already staged on a command.
///
/// Reading the parent process environment here is incorrect: C/C++ context
/// recovery may just have placed an inferred value (notably a libstdc++ `-L`)
/// directly on `cmd`. Coverage replay appends its portable system libraries
/// after that step, so it must preserve the command-local value.
fn append_command_env_flags(cmd: &mut std::process::Command, key: &str, extra: &str) {
    let current = cmd
        .get_envs()
        .find(|(candidate, _)| *candidate == std::ffi::OsStr::new(key))
        .and_then(|(_, value)| value)
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.trim().is_empty());
    let combined = current
        .map(|value| format!("{value} {extra}"))
        .unwrap_or_else(|| extra.to_owned());
    cmd.env(key, combined);
}

/// The (make target, staged artifact) for an AFL build — the Makefile's `afl`
/// target produces `main_afl` via `$(AFLPP_CC)`. A small seam so the selection is
/// unit-testable without a toolchain.
pub(crate) fn afl_make_target_and_artifact() -> (Option<&'static str>, &'static str) {
    (Some("afl"), "main_afl")
}

/// Build the AFL-instrumented `main_afl` for an auto-recovered C/C++ harness,
/// reusing the SAME recovered extras (`extra_sources` / `extra_includes` →
/// `AUTO_EXTRA_*`) so the afl build sees the identical recovery context the `main`
/// build used. No sanitizer/cross compiler override — the Makefile's `AFLPP_CC` /
/// `AFLPP_CFLAGS` defaults drive the afl target. Runs `make afl` in the harness
/// dir; the caller inspects `.status.success()`.
pub(crate) fn try_run_c_make_afl_build_with_extras(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
) -> std::process::Output {
    let (target, _staged) = afl_make_target_and_artifact();
    try_run_c_make_build_with_target(
        work_dir,
        harness_id,
        extra_sources,
        extra_includes,
        None,
        target,
        None,
    )
}

/// Synthesised repair headers that must be force-included into every TU of
/// the harness compile so their content precedes the first use in `main` and
/// in the target source: the collision-safe C++-stdlib `#include`s and the
/// build-config macro `#define`s. Never `auto_types.h`, whose `void *`
/// placeholders would clash with a real typedef in any target TU.
fn repair_force_includes(harness_dir: &Path) -> Vec<PathBuf> {
    let repairs = harness_dir.join("repairs");
    [
        crate::auto::repair::AUTO_CPP_INCLUDES_FILE,
        crate::auto::repair::AUTO_DEFINES_FILE,
    ]
    .iter()
    .map(|name| repairs.join(name))
    .filter(|path| path.is_file())
    .collect()
}

fn apply_c_family_make_env(
    cmd: &mut std::process::Command,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    force_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
) {
    // The generated Makefiles use libFuzzer sanitizer flags. GNU make's
    // built-in CC/CXX defaults are usually cc/g++, which do not support
    // -fsanitize=fuzzer on common Linux hosts. Respect explicit caller
    // choices, but provide clang defaults when no compiler was selected.
    if let Some(compiler) = compiler {
        // Foreign-target cross build: force the cross CC/CXX (and replacement
        // flags) unconditionally, overriding both the Makefile defaults and any
        // ambient CC/CXX so the candidate compiles for its real platform/arch.
        cmd.env("CC", &compiler.cc);
        cmd.env("CXX", &compiler.cxx);
        if !compiler.cflags.is_empty() {
            cmd.env("CFLAGS", compiler.cflags.join(" "));
        }
        if !compiler.cxxflags.is_empty() {
            cmd.env("CXXFLAGS", compiler.cxxflags.join(" "));
        }
    } else {
        if std::env::var_os("CC").is_none() {
            cmd.env("CC", "clang");
        }
        if std::env::var_os("CXX").is_none() {
            cmd.env("CXX", "clang++");
        }
    }

    let inherited_includes = std::env::var("AUTO_EXTRA_INCLUDES").ok();
    let inherited_ldflags = std::env::var("AUTO_EXTRA_LDFLAGS").ok();
    for (key, value) in c_family_make_env(
        extra_sources,
        extra_includes,
        inherited_includes.as_deref(),
        &detect_libstdcxx_include_flags(),
        inherited_ldflags.as_deref(),
        detect_libstdcxx_search_path(),
        force_includes,
    ) {
        cmd.env(key, value);
    }
}

#[allow(clippy::too_many_arguments)]
fn c_family_make_env(
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    inherited_extra_includes: Option<&str>,
    detected_include_flags: &[String],
    inherited_ldflags: Option<&str>,
    detected_ld_search_path: Option<String>,
    force_includes: &[PathBuf],
) -> Vec<(String, String)> {
    let mut env = Vec::new();

    if !extra_sources.is_empty() {
        env.push((
            "AUTO_EXTRA_SOURCES".to_owned(),
            extra_sources
                .iter()
                .map(|p| harness_gen::build_safety::make_path(p))
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }

    let mut include_flags = inherited_extra_includes
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect::<Vec<_>>();
    // #366: recovered project include dirs use `-iquote` (searched only for
    // quoted `#include "..."`, never for angle `#include <...>`) so a project
    // header cannot shadow a same-named system header. `-isystem` would not
    // help — those dirs still precede the built-in system dirs. Detected
    // project `-I` flags below are left as-is so project-internal angle
    // includes still resolve.
    include_flags.extend(
        extra_includes
            .iter()
            .map(|p| format!("-iquote {}", harness_gen::build_safety::make_path(p))),
    );
    // Also search the same dirs AFTER the system dirs (`-idirafter`) so a
    // synthesized placeholder for a genuinely-missing ANGLED system header (a
    // stubbed `<vxWorks.h>`/`<sys/neutrino.h>` for RTOS code, or any `<...>`
    // header the host lacks) resolves. `-idirafter` is searched last, so a real
    // same-named system header still wins — #366's no-shadow guarantee holds; this
    // only adds a fallback for headers the host genuinely does not provide.
    include_flags.extend(
        extra_includes
            .iter()
            .map(|p| format!("-idirafter {}", harness_gen::build_safety::make_path(p))),
    );
    include_flags.extend(detected_include_flags.iter().cloned());
    // Force-include synthesised repair headers (C++-stdlib includes, build-config
    // defines) into every TU so their content is seen by the harness `main` and
    // the target source, not only by `auto_stubs.c`. Prepend so each lands before
    // the first line of every source.
    // `make_path` (forward-slash, verbatim-prefix-stripped): these land in an
    // `AUTO_EXTRA_INCLUDES` make variable whose recipe runs through `sh`, which
    // eats Windows backslashes — `-include C:\...\auto_defines.h` would arrive as
    // `C:...auto_defines.h` and the repair header would never be found.
    for force in force_includes.iter().rev() {
        include_flags.insert(
            0,
            format!("-include {}", harness_gen::build_safety::make_path(force)),
        );
    }
    if !include_flags.is_empty() {
        env.push(("AUTO_EXTRA_INCLUDES".to_owned(), include_flags.join(" ")));
    }

    let mut ldflags = inherited_ldflags
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(extra) = detected_ld_search_path {
        ldflags.push(format!("-L{extra}"));
    }
    if !ldflags.is_empty() {
        env.push(("AUTO_EXTRA_LDFLAGS".to_owned(), ldflags.join(" ")));
    }

    env
}

fn detect_libstdcxx_include_flags() -> Vec<String> {
    let cxx = std::env::var("CXX").unwrap_or_else(|_| "clang++".to_owned());
    detect_cpp_stdlib_include_flags_for(&cxx, &[])
}

/// Recover C++ standard-library include paths for the exact compiler and base
/// flags used by an independent probe. Header preflights call this too so a
/// mixed GCC/Clang installation is judged under the same toolchain recovery as
/// the eventual harness build.
pub(crate) fn detect_cpp_stdlib_include_flags_for(cxx: &str, base_flags: &[String]) -> Vec<String> {
    if cxx_accepts_cpp_standard_headers(cxx, base_flags) {
        return Vec::new();
    }
    for dirs in candidate_libstdcxx_include_sets_from_root(Path::new("/usr/include")) {
        let flags = libstdcxx_include_flags(&dirs);
        let mut probe_flags = base_flags.to_vec();
        probe_flags.extend(flags.iter().cloned());
        if cxx_accepts_cpp_standard_headers(cxx, &probe_flags) {
            return flags;
        }
    }
    Vec::new()
}

fn cxx_accepts_cpp_standard_headers(cxx: &str, flags: &[String]) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = match Command::new(cxx)
        .arg("-std=c++17")
        .args(flags)
        .args(["-x", "c++", "-", "-fsyntax-only"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(stdin) = child.stdin.as_mut() else {
        return false;
    };
    if stdin
        .write_all(b"#include <string>\n#include <cstring>\nint main() { return 0; }\n")
        .is_err()
    {
        return false;
    }
    child.wait().map(|status| status.success()).unwrap_or(false)
}

fn libstdcxx_include_flags(dirs: &[PathBuf]) -> Vec<String> {
    dirs.iter()
        .flat_map(|dir| ["-isystem".to_owned(), dir.display().to_string()])
        .collect()
}

fn candidate_libstdcxx_include_sets_from_root(include_root: &Path) -> Vec<Vec<PathBuf>> {
    let cxx_root = include_root.join("c++");
    let mut versions = fs::read_dir(&cxx_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }
            let version = entry.file_name().to_string_lossy().into_owned();
            if !version.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let base = cxx_root.join(&version);
            if base.join("string").is_file() {
                Some(version)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    versions.sort_by(|left, right| {
        right
            .parse::<u32>()
            .unwrap_or(0)
            .cmp(&left.parse::<u32>().unwrap_or(0))
    });

    versions
        .into_iter()
        .map(|version| {
            let base = cxx_root.join(&version);
            let mut dirs = vec![base.clone()];
            let mut arch_dirs = fs::read_dir(include_root)
                .ok()
                .into_iter()
                .flat_map(|entries| entries.filter_map(Result::ok))
                .filter_map(|entry| {
                    let file_type = entry.file_type().ok()?;
                    if !file_type.is_dir() {
                        return None;
                    }
                    let candidate = entry.path().join("c++").join(&version);
                    if candidate.is_dir() {
                        Some(candidate)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            arch_dirs.sort();
            dirs.extend(arch_dirs);
            let backward = base.join("backward");
            if backward.is_dir() {
                dirs.push(backward);
            }
            dirs
        })
        .collect()
}

/// Probe whether the linker can find libstdc++ in clang's default
/// search path. clang's libFuzzer runtime pulls in `-lstdc++`; on
/// hosts where clang picks a gcc toolchain version that's installed
/// without the C++ runtime (common: clang-18 picks gcc-14 paths but
/// only gcc-13 libstdc++ is installed), the link fails with
/// "cannot find -lstdc++". Find the actual libstdc++.so on the
/// filesystem and return its parent directory so the Makefile can
/// pass it through `-L`. Returns `None` if libstdc++ is already on
/// the default path or genuinely missing — both cases let the build
/// proceed and the classifier surface the real diagnostic.
pub(crate) fn detect_libstdcxx_search_path() -> Option<String> {
    use std::process::Command;
    // Ask clang where it would find libstdc++ by default. If
    // -print-file-name returns the bare filename (no absolute path),
    // it's not on the default path.
    let out = Command::new(std::env::var("CC").unwrap_or_else(|_| "clang".to_owned()))
        .args(["-print-file-name=libstdc++.so"])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if path != "libstdc++.so" && std::path::Path::new(&path).is_file() && !path.ends_with(".so")
    // double-check; -print-file-name returns the canonical path
    {
        return None;
    }
    if std::path::Path::new(&path).is_file() {
        // clang already knows where it is; nothing to inject.
        return None;
    }
    // Fall back: search common gcc toolchain dirs.
    let candidates: &[&str] = &[
        "/usr/lib/gcc/x86_64-linux-gnu/13",
        "/usr/lib/gcc/x86_64-linux-gnu/14",
        "/usr/lib/gcc/x86_64-linux-gnu/12",
        "/usr/lib/gcc/aarch64-linux-gnu/13",
        "/usr/lib/gcc/aarch64-linux-gnu/14",
        "/usr/lib/gcc/aarch64-linux-gnu/12",
    ];
    for dir in candidates {
        let p = std::path::Path::new(dir).join("libstdc++.so");
        if p.is_file() {
            return Some(dir.to_string());
        }
    }
    None
}

/// Captured stdout/stderr from a programmatic gprbuild invocation,
/// used by `govfuzz auto`'s attempt loop to classify Ada build
/// failures with the build_classifier crate.
pub(crate) struct CapturedBuild {
    pub(crate) status_success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Programmatic Ada-build driver used by `govfuzz auto`'s attempt
/// loop. Mirrors the `build::run` happy path (prepare layout +
/// discover compiler + probe + build) but returns the captured
/// stdout/stderr instead of printing to the process streams so the
/// classifier can see GNAT diagnostics.
pub(crate) fn try_run_ada_build_capturing(args: &BuildArgs) -> Result<CapturedBuild, String> {
    run_ada_project(args, BuildMode::Full)
}

/// Semantic-only counterpart of [`try_run_ada_build_capturing`]: compiles no code
/// and links nothing, but reports every diagnostic the repair loop reads. A repair
/// round that is going to fail costs only this, and the expensive full build runs
/// once the closure is semantically clean.
pub(crate) fn try_run_ada_check_capturing(args: &BuildArgs) -> Result<CapturedBuild, String> {
    run_ada_project(args, BuildMode::CheckOnly)
}

fn run_ada_project(args: &BuildArgs, mode: BuildMode) -> Result<CapturedBuild, String> {
    let layout = prepare_layout(args)?;
    let adapter = CompilerAdapter::discover_for(toolchain_config(args))
        .map_err(|error| format!("{error}"))?;
    probe_compiler(&adapter).map_err(|error| format!("{error}"))?;
    let result = match mode {
        BuildMode::Full => adapter.build(&layout.project_path),
        BuildMode::CheckOnly => adapter.check(&layout.project_path),
    }
    .map_err(|error| format!("{error}"))?;
    Ok(CapturedBuild {
        status_success: result.exit_code == 0,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn toolchain_config(args: &BuildArgs) -> ToolchainConfig {
    ToolchainConfig {
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        toolchain: args.toolchain.clone(),
    }
}

/// The GCC SanitizerCoverage flag the Ada lane uses (#412). GNAT/GCC does NOT
/// accept `trace-pc-guard` (the C/C++ driver's flag); `trace-pc` emits calls to
/// the parameterless `__sanitizer_cov_trace_pc` that `ada_runtime/adafuzz_cov.c`
/// defines.
pub(crate) const ADA_COV_TRACE_PC_FLAG: &str = "-fsanitize-coverage=trace-pc";

/// Marker file written into a harness's `build/<id>` dir when its compile was
/// instrumented with [`ADA_COV_TRACE_PC_FLAG`]. The fuzz engine keys its
/// CoverageTracker on this (#412) so coverage-guided fuzzing engages for the Ada
/// lane exactly when the SHM bitmap is actually being written.
pub(crate) const ADA_COV_SENTINEL: &str = ".govfuzz_ada_cov";

/// Whether the Ada gcc accepts [`ADA_COV_TRACE_PC_FLAG`], probed once per process
/// per compiler and cached. GNAT/GCC 13.x supports `trace-pc` but earlier/odd
/// toolchains may not; a compiler that rejects it would otherwise fail every Ada
/// build the moment we add the flag, so we degrade to no-coverage instead.
///
/// Probes the same gcc gprbuild would invoke (toolchain/target-prefixed when set,
/// else host `gcc`) by compiling an empty translation unit with the flag.
fn ada_trace_pc_supported(toolchain: &ToolchainConfig) -> bool {
    use std::collections::HashMap;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let gcc = toolchain
        .compiler_prefix()
        .map(|prefix| format!("{prefix}-gcc"))
        .unwrap_or_else(|| "gcc".to_owned());

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&cached) = cache.lock().expect("trace-pc probe cache").get(&gcc) {
        return cached;
    }

    let supported = Command::new(&gcc)
        .args([
            ADA_COV_TRACE_PC_FLAG,
            "-xc",
            "-c",
            "/dev/null",
            "-o",
            "/dev/null",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    cache
        .lock()
        .expect("trace-pc probe cache")
        .insert(gcc, supported);
    supported
}

fn write_runtime_project(
    project_path: &Path,
    build_dir: &Path,
    probe_backend: ProbeBackend,
) -> Result<(), String> {
    let object_dir = build_dir.join("adafuzz_obj");
    let library_dir = build_dir.join("adafuzz_lib");
    fs::create_dir_all(&object_dir).map_err(|error| {
        format!(
            "create runtime object directory '{}': {error}",
            object_dir.display()
        )
    })?;
    fs::create_dir_all(&library_dir).map_err(|error| {
        format!(
            "create runtime library directory '{}': {error}",
            library_dir.display()
        )
    })?;

    let runtime_source_dir =
        materialize_runtime_sources(&build_dir.join("adafuzz_runtime_src"), probe_backend)?;
    let rendered = format!(
        "--  SPDX-License-Identifier: Apache-2.0\n\
project AdaFuzz_Runtime is\n\
   --  C is built alongside Ada so adafuzz_cov.c (the trace-pc edge callback,\n\
   --  #412) lands in the runtime archive. It is compiled at `-g` only (no\n\
   --  coverage instrumentation) so the callback is itself uninstrumented and\n\
   --  never recurses; the instrumented target+harness pull it in via the\n\
   --  unresolved `__sanitizer_cov_trace_pc` reference.\n\
   for Languages use (\"Ada\", \"C\");\n\
   for Source_Dirs use (\"{}\");\n\
   for Source_Files use\n\
     (\"adafuzz.ads\",\n\
      \"adafuzz-probe.ads\",\n\
      \"adafuzz-probe.adb\",\n\
      \"adafuzz-input.ads\",\n\
      \"adafuzz-input.adb\",\n\
      \"adafuzz-decode.ads\",\n\
      \"adafuzz-decode.adb\",\n\
      \"adafuzz_cov.c\");\n\
   for Object_Dir use \"adafuzz_obj\";\n\
   for Library_Name use \"adafuzz\";\n\
   for Library_Kind use \"static\";\n\
   for Library_Dir use \"adafuzz_lib\";\n\
\n\
   package Compiler is\n\
      for Default_Switches (\"Ada\") use (\"-g\");\n\
      for Default_Switches (\"C\") use (\"-g\");\n\
   end Compiler;\n\
end AdaFuzz_Runtime;\n",
        path_string(&runtime_source_dir)
    );
    fs::write(project_path, rendered)
        .map_err(|error| format!("write '{}': {error}", project_path.display()))
}

/// The harness's main source-file base name: `main.adb` when present, otherwise
/// a single `*-gf_harness.adb` (a private-child-subprogram harness). Returns
/// `None` when neither exists.
fn detect_harness_main_file(harness_dir: &Path) -> Option<String> {
    if harness_dir.join("main.adb").is_file() {
        return Some("main.adb".to_owned());
    }
    let entries = fs::read_dir(harness_dir).ok()?;
    entries.flatten().find_map(|entry| {
        let name = entry.file_name().to_string_lossy().into_owned();
        (name.ends_with("-gf_harness.adb") && entry.path().is_file()).then_some(name)
    })
}

fn select_harness(work_dir: &Path, requested: Option<&str>) -> Result<(String, PathBuf), String> {
    if let Some(harness_id) = requested {
        for harness_root in harness_roots(work_dir) {
            let harness_dir = harness_root.join(harness_id);
            if harness_dir.is_dir() {
                return Ok((harness_id.to_owned(), harness_dir));
            }
        }
        return Err(format!(
            "work dir malformed: harness '{}' not found under {} or {}",
            harness_id,
            work_dir
                .join(crate::auto::layout::GENERATED_HARNESSES_DIR)
                .display(),
            crate::auto::layout::harness_root(work_dir).display()
        ));
    }

    let mut harnesses = BTreeMap::new();
    for harness_root in harness_roots(work_dir) {
        if !harness_root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&harness_root).map_err(|error| {
            format!(
                "read harness directory '{}': {error}",
                harness_root.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "read harness directory entry under '{}': {error}",
                    harness_root.display()
                )
            })?;
            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "read harness entry type '{}': {error}",
                    entry.path().display()
                )
            })?;
            if file_type.is_dir() {
                harnesses
                    .entry(entry.file_name().to_string_lossy().into_owned())
                    .or_insert_with(|| entry.path());
            }
        }
    }

    match harnesses.len() {
        0 => Err(format!(
            "work dir malformed: no harnesses under {} or {}",
            work_dir
                .join(crate::auto::layout::GENERATED_HARNESSES_DIR)
                .display(),
            crate::auto::layout::harness_root(work_dir).display()
        )),
        1 => {
            let (id, dir) = harnesses.into_iter().next().expect("one harness");
            Ok((id, dir))
        }
        count => Err(format!(
            "work dir malformed: {count} harnesses found; pass --harness"
        )),
    }
}

fn harness_roots(work_dir: &Path) -> [PathBuf; 2] {
    [
        work_dir.join(crate::auto::layout::GENERATED_HARNESSES_DIR),
        crate::auto::layout::harness_root(work_dir),
    ]
}

/// The Ada standard the harness build compiles under. The build pulls in
/// dependency sources of mixed, often unmarked vintage, all under one
/// `-gnatXXXX`; detecting one standard from a single source and applying it
/// build-wide made an Ada 2022 dependency (SweetAda's `bits.adb`, which uses the
/// `@` target name and formal-parameter aspects) fail with "... is an Ada 2022
/// feature". `-gnat2022` is the latest supported standard and accepts older code
/// too (the harness main still carries its own `pragma Ada_2012`), so it is the
/// safe, maximally-buildable choice — squarely govfuzz's "fuzz code that doesn't
/// cleanly build" thesis. (The `@` form is not a token the standard-probe
/// recognises, so per-source detection cannot reliably pick 2022 here anyway.)
fn detect_ada_standard(_source_dir: &Path, work_dir: &Path) -> Result<AdaStandard, String> {
    // The legacy-dialect ladder (see `crate::auto::attempt`) writes the standard it
    // found buildable to this cache; honor it so the whole build (and any
    // synthesized stub bodies) compiles under the SAME `-gnatXXXX`. Absent a cache,
    // Ada 2022 is the maximally-buildable default — where the compiler HAS it.
    let chosen = read_ada_dialect_cache(work_dir).unwrap_or(AdaStandard::Ada2022);
    Ok(clamp_ada_standard_to_compiler(chosen))
}

/// Lower `-gnat2022` to `-gnat2012` on a compiler that does not know the switch.
///
/// `-gnat2022` arrived in GNAT 12. On GNAT 11 — the default on Ubuntu 22.04 and
/// every still-supported RHEL 9 derivative — `gnat1` answers `invalid switch:
/// -gnat2022` and the build dies before it reads a line of Ada, so NO Ada target
/// could be harnessed there at all. The whole GNAT 11 row of the nightly matrix
/// (all four dialects, both profiles) failed this way, and so would any user on
/// an older distribution.
///
/// Ada 2012 is the right fallback: it is fully supported on every GNAT this tool
/// targets and accepts the same older code 2022 does. The only thing lost is a
/// dependency that genuinely uses a 2022 feature, which on such a compiler could
/// not have built regardless.
fn clamp_ada_standard_to_compiler(standard: AdaStandard) -> AdaStandard {
    if standard == AdaStandard::Ada2022 && !gnat_accepts_ada2022() {
        return AdaStandard::Ada2012;
    }
    standard
}

/// Whether this host's GNAT accepts `-gnat2022`, probed once by compiling a
/// trivial unit. Probed rather than parsed from a version string because vendor
/// GNATs spell their versions freely. Any probe failure answers `true`, which is
/// the historical behaviour — this must never turn a working build into a
/// downgraded one.
fn gnat_accepts_ada2022() -> bool {
    use std::sync::OnceLock;
    static ACCEPTS: OnceLock<bool> = OnceLock::new();
    *ACCEPTS.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("govfuzz-gnat-probe-{}", std::process::id()));
        if fs::create_dir_all(&dir).is_err() {
            return true;
        }
        let src = dir.join("gf_probe.adb");
        let wrote = fs::write(&src, "procedure Gf_Probe is begin null; end Gf_Probe;\n").is_ok();
        let accepts = wrote
            && std::process::Command::new("gcc")
                .arg("-c")
                .arg("-gnat2022")
                .arg(&src)
                .current_dir(&dir)
                .output()
                .map(|out| !String::from_utf8_lossy(&out.stderr).contains("invalid switch"))
                .unwrap_or(true);
        let _ = fs::remove_dir_all(&dir);
        accepts
    })
}

/// Run-level object directory shared by every Ada harness of a sweep, so the
/// project's own closure is compiled once rather than once per target. Ada
/// attempts are serialized within a sweep (they share the staged source layout),
/// so no two gprbuild runs write here at the same time.
pub(crate) const SHARED_ADA_OBJ_DIR: &str = "ada_obj";

/// Run-level source directory holding the reconstructed external-library stubs.
/// Project-scoped for the same reason the model behind it is: the stub set is a
/// property of the project. Keeping it at a stable path also means the compiled
/// stub objects survive in [`SHARED_ADA_OBJ_DIR`] from one target to the next —
/// a per-target path would make gprbuild recompile every stub, and everything
/// depending on it, for each harness.
pub(crate) const SHARED_ADA_STUBS_DIR: &str = "ada_external_stubs";

/// Path of the Ada dialect cache written by the legacy-dialect ladder.
///
/// RUN-level, not per harness. Which `-gnatXXXX` a project's sources compile
/// under is a property of the project — one target does not use Ada 95 while its
/// neighbour uses Ada 2022 — but the cache used to sit in `build/<harness>/`, so
/// every target of a legacy project re-ran the whole ladder, paying up to three
/// extra full builds each to rediscover the same answer.
pub(crate) fn ada_dialect_cache_path(work_dir: &Path) -> PathBuf {
    work_dir.join("ada_dialect")
}

/// Read the cached Ada standard (a `-gnatXXXX` token) for this run, if any.
pub(crate) fn read_ada_dialect_cache(work_dir: &Path) -> Option<AdaStandard> {
    let raw = fs::read_to_string(ada_dialect_cache_path(work_dir)).ok()?;
    ada_standard_from_switch(raw.trim())
}

/// Map a `-gnatXXXX` dialect switch to its [`AdaStandard`].
pub(crate) fn ada_standard_from_switch(switch: &str) -> Option<AdaStandard> {
    match switch {
        "-gnat83" => Some(AdaStandard::Ada83),
        "-gnat95" => Some(AdaStandard::Ada95),
        "-gnat05" | "-gnat2005" => Some(AdaStandard::Ada2005),
        "-gnat12" | "-gnat2012" => Some(AdaStandard::Ada2012),
        "-gnat2022" => Some(AdaStandard::Ada2022),
        _ => None,
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn absolutize(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_staged_in_tree_ada_runtime_unit() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("s-valint.ads"),
            "package System.Val_Int is\nend System.Val_Int;\n",
        )
        .unwrap();
        assert!(dir_contains_in_tree_ada_runtime_unit(temp.path()));

        fs::write(
            temp.path().join("ordinary.ads"),
            "with System;\npackage Ordinary is\nend Ordinary;\n",
        )
        .unwrap();
        fs::remove_file(temp.path().join("s-valint.ads")).unwrap();
        assert!(!dir_contains_in_tree_ada_runtime_unit(temp.path()));
    }

    #[test]
    fn afl_build_uses_afl_target_and_main_afl() {
        // The AFL build must request the `afl` make target, producing `main_afl`.
        let (target, staged) = afl_make_target_and_artifact();
        assert_eq!(target, Some("afl"));
        assert_eq!(staged, "main_afl");
    }

    #[test]
    fn native_make_build_explicitly_requests_main_after_included_object_graph() {
        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_err()
        {
            gfeprintln!("skipping explicit make goal test: make not on PATH");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let harness = work.join("harnesses/H-X");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.c"), "int main(void) { return 0; }\n").unwrap();
        fs::write(
            harness.join("build_context_objects.mk"),
            "context_objs:\n\tmkdir -p context_objs\n",
        )
        .unwrap();
        fs::write(
            harness.join("Makefile"),
            "-include build_context_objects.mk\n.PHONY: all\nall: main\nmain: main.c\n\ttouch main\n",
        )
        .unwrap();

        let output = try_run_c_make_build_with_target(work, "H-X", &[], &[], None, None, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            harness.join("main").is_file(),
            "the included fragment's first target must not replace the harness goal"
        );
        assert!(
            !harness.join("context_objs").exists(),
            "make must not stop after the fragment's default-looking target"
        );
    }

    #[test]
    fn discover_user_gpr_absolutizes_relative_imports_and_skips_bundled_adafuzz() {
        // #411: forwarded `with` clauses must be depth-independent. A
        // relative import is resolved against the source gpr's own dir
        // into a normalized ABSOLUTE path (so it still resolves when
        // written into govfuzz_build.gpr at its deeper build/<id>/ dir),
        // an already-absolute import is preserved, and govfuzz's own
        // bundled adafuzz.gpr is dropped (adafuzz_runtime.gpr already
        // provides it).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("foo.gpr"),
            "with \"../sub/dep.gpr\";\n\
             with \"/opt/x.gpr\";\n\
             with \"../../whatever/adafuzz.gpr\";\n\
             project Foo is\n\
             end Foo;\n",
        )
        .unwrap();

        let clauses = discover_user_gpr_with_clauses(root);

        assert!(
            gpr_imports_adafuzz(&root.join("foo.gpr")),
            "a governing project that imports adafuzz.gpr must not be extended"
        );

        // Relative dep -> normalized ABSOLUTE path rooted at the gpr dir.
        let expected_dep = root.parent().unwrap().join("sub").join("dep.gpr");
        assert!(
            expected_dep.is_absolute(),
            "fixture root must be absolute for this assertion"
        );
        // Absolute import preserved verbatim.
        let expected_abs = PathBuf::from("/opt/x.gpr");
        assert_eq!(
            clauses,
            vec![expected_dep, expected_abs],
            "expected the relative dep absolutized and the absolute one kept, \
             with the bundled adafuzz.gpr skipped; got {clauses:?}"
        );
        // Belt-and-suspenders: the bundled runtime is never forwarded.
        assert!(
            !clauses
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n == "adafuzz.gpr")),
            "bundled adafuzz.gpr must not be forwarded: {clauses:?}"
        );
    }

    #[test]
    fn normalize_path_lexical_collapses_dot_and_dotdot_without_touching_fs() {
        assert_eq!(
            normalize_path_lexical(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        // Non-existent path is normalized lexically (no canonicalize).
        assert_eq!(
            normalize_path_lexical(Path::new("/x/y/../../nope/here.gpr")),
            PathBuf::from("/nope/here.gpr")
        );
    }

    #[test]
    fn libstdcxx_include_candidates_pair_base_arch_and_backward_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let include_root = tmp.path().join("usr/include");
        let base = include_root.join("c++/13");
        let arch = include_root.join("x86_64-linux-gnu/c++/13");
        let backward = include_root.join("c++/13/backward");
        fs::create_dir_all(&arch).unwrap();
        fs::create_dir_all(&backward).unwrap();
        fs::write(base.join("string"), "").unwrap();
        fs::create_dir_all(include_root.join("c++/v1")).unwrap();
        fs::write(include_root.join("c++/v1/string"), "").unwrap();

        let sets = candidate_libstdcxx_include_sets_from_root(&include_root);

        assert_eq!(sets, vec![vec![base, arch, backward]]);
    }

    #[test]
    fn recovered_extra_includes_use_iquote_to_avoid_system_header_shadow() {
        // #366: govfuzz's recovered project include dirs must be -iquote, not
        // -I, so a project header (e.g. capnproto's C++ endian.h) cannot shadow
        // a system header pulled in via an angle include. The project's own
        // detected -I flags pass through untouched, and the harness includes its
        // target headers via quoted `#include "..."`, which -iquote resolves.
        let env = c_family_make_env(
            &[],
            &[PathBuf::from("/proj/src/capnp")],
            None,
            &["-I/proj/build".to_owned()],
            None,
            None,
            &[],
        );
        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(
            includes.contains("-iquote /proj/src/capnp"),
            "recovered include dirs must be -iquote: {includes}"
        );
        assert!(
            !includes.contains("-I/proj/src/capnp"),
            "recovered include dirs must NOT be -I: {includes}"
        );
        assert!(
            includes.contains("-I/proj/build"),
            "detected project -I flags must pass through untouched: {includes}"
        );
    }

    #[test]
    fn recovered_extra_includes_also_idirafter_for_angled_placeholders() {
        // A synthesized placeholder for a genuinely-missing ANGLED system header
        // (a stubbed `<vxWorks.h>`/`<sys/neutrino.h>` for RTOS code) lives in the
        // repair includes dir. `-iquote` never resolves `<...>` includes, so the
        // dir must ALSO be `-idirafter`: searched AFTER the real system dirs, so a
        // real `<stdio.h>` still wins (no shadow — #366 preserved) while a header
        // the host genuinely lacks falls through to the placeholder.
        let env = c_family_make_env(
            &[],
            &[PathBuf::from("/work/repairs/auto_includes")],
            None,
            &[],
            None,
            None,
            &[],
        );
        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(
            includes.contains("-iquote /work/repairs/auto_includes"),
            "{includes}"
        );
        assert!(
            includes.contains("-idirafter /work/repairs/auto_includes"),
            "angled-include placeholders need -idirafter fallback: {includes}"
        );
    }

    #[test]
    fn c_family_make_env_threads_detected_libstdcxx_flags() {
        let env = c_family_make_env(
            &[],
            &[],
            Some("-I/custom"),
            &["-isystem".to_owned(), "/usr/include/c++/13".to_owned()],
            Some("-Wl,--as-needed"),
            Some("/usr/lib/gcc/x86_64-linux-gnu/13".to_owned()),
            &[],
        );

        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(includes.contains("-I/custom"));
        assert!(includes.contains("-isystem /usr/include/c++/13"));

        let forced = c_family_make_env(
            &[],
            &[],
            None,
            &[],
            None,
            None,
            &[
                PathBuf::from("/wk/harnesses/H/repairs/auto_cpp_includes.h"),
                PathBuf::from("/wk/harnesses/H/repairs/auto_defines.h"),
            ],
        );
        let forced_includes = forced
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("force-include sets AUTO_EXTRA_INCLUDES");
        // Both headers force-included, in order.
        assert!(
            forced_includes.starts_with(
                "-include /wk/harnesses/H/repairs/auto_cpp_includes.h \
                 -include /wk/harnesses/H/repairs/auto_defines.h"
            ),
            "{forced_includes}"
        );

        let ldflags = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_LDFLAGS")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_LDFLAGS is set");
        assert!(ldflags.contains("-Wl,--as-needed"));
        assert!(ldflags.contains("-L/usr/lib/gcc/x86_64-linux-gnu/13"));
    }

    #[test]
    fn appending_coverage_ldflags_preserves_command_local_recovery() {
        let mut command = std::process::Command::new("make");
        command.env("AUTO_EXTRA_LDFLAGS", "-L/usr/lib/gcc/x86_64-linux-gnu/13");

        append_command_env_flags(&mut command, "AUTO_EXTRA_LDFLAGS", "-lm -ldl -lpthread");

        let value = command
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new("AUTO_EXTRA_LDFLAGS"))
            .and_then(|(_, value)| value)
            .expect("command-local linker flags")
            .to_string_lossy();
        assert_eq!(
            value,
            "-L/usr/lib/gcc/x86_64-linux-gnu/13 -lm -ldl -lpthread"
        );
    }

    #[test]
    fn ada_prepare_layout_includes_auto_repair_stubs_source_root() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("govfuzz_work");
        let src = work.join("src_instrumented");
        let harness = work.join("generated_harnesses/H-A0001");
        let repair_stubs = work.join("harnesses/H-A0001/repairs/ada_stubs");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&harness).unwrap();
        fs::create_dir_all(&repair_stubs).unwrap();
        fs::write(
            src.join("pkg.adb"),
            "package body Pkg is begin null; end Pkg;\n",
        )
        .unwrap();
        fs::write(
            harness.join("main.adb"),
            "procedure Main is begin null; end Main;\n",
        )
        .unwrap();
        fs::write(
            repair_stubs.join("aux_pkg.ads"),
            "package Aux_Pkg is end Aux_Pkg;\n",
        )
        .unwrap();

        let args = BuildArgs {
            work_dir: work.clone(),
            source_project: None,
            harness: Some("H-A0001".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: ProbeBackend::HostFile,
            c_engine: CEngine::Libfuzzer,
        };

        let layout = prepare_layout(&args).unwrap();
        let project = fs::read_to_string(layout.project_path).unwrap();

        assert!(
            project.contains(&repair_stubs.to_string_lossy().to_string()),
            "generated GPR should include auto Ada stubs dir; got:\n{project}"
        );
    }

    /// `-gnat2022` arrived in GNAT 12. On GNAT 11 — Ubuntu 22.04's default —
    /// `gnat1` answers `invalid switch: -gnat2022` and the build dies before
    /// reading a line of Ada, so no Ada target could be harnessed at all. The
    /// whole GNAT 11 row of the nightly matrix failed exactly this way.
    #[test]
    fn ada_2022_is_lowered_on_a_compiler_that_lacks_the_switch() {
        // Only 2022 is clamped; a standard the ladder actually found buildable
        // is passed through untouched.
        for standard in [
            AdaStandard::Ada83,
            AdaStandard::Ada95,
            AdaStandard::Ada2005,
            AdaStandard::Ada2012,
        ] {
            assert_eq!(clamp_ada_standard_to_compiler(standard), standard);
        }
        // On THIS host the answer follows the probe, and either answer is a
        // legal Ada standard the writer can spell.
        let clamped = clamp_ada_standard_to_compiler(AdaStandard::Ada2022);
        assert!(
            clamped == AdaStandard::Ada2022 || clamped == AdaStandard::Ada2012,
            "unexpected clamp: {clamped:?}"
        );
        assert_eq!(clamped == AdaStandard::Ada2022, gnat_accepts_ada2022());
    }

    #[test]
    fn ada_overlay_build_inherits_governing_project_semantics_from_external_work_dir() {
        if std::process::Command::new("gprbuild")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let app = project_root.join("app");
        let original = app.join("original");
        let common = project_root.join("common/src");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&common).unwrap();
        fs::write(
            common.join("common.ads"),
            "package Common is X : constant Integer := 7; end Common;\n",
        )
        .unwrap();
        fs::write(
            project_root.join("common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;\n",
        )
        .unwrap();
        let package_source =
            "with Common; package Pkg is X : constant Integer := Common.X; end Pkg;\n";
        fs::write(original.join("vendor_pkg.ads"), package_source).unwrap();
        fs::write(app.join("gnat.adc"), "pragma Warnings (Off);\n").unwrap();
        let source_project = app.join("app.gpr");
        fs::write(
            &source_project,
            "with \"../common/common.gpr\";\n\
             project App is\n\
                type Mode_Type is (\"host\", \"other\");\n\
                Mode : Mode_Type := external (\"MODE\", \"host\");\n\
                for Source_Dirs use (\"original\");\n\
                package Compiler is\n\
                   for Local_Configuration_Pragmas use \"gnat.adc\";\n\
                end Compiler;\n\
                package Naming is\n\
                   case Mode is\n\
                      when \"host\" => for Spec (\"Pkg\") use \"vendor_pkg.ads\";\n\
                      when others => for Spec (\"Pkg\") use \"unselected.ads\";\n\
                   end case;\n\
                end Naming;\n\
                package Binder is for Default_Switches (\"Ada\") use (\"-E\"); end Binder;\n\
                package Linker is for Default_Switches (\"Ada\") use (\"-Wl,--as-needed\"); end Linker;\n\
             end App;\n",
        )
        .unwrap();

        // Deliberately outside the project: parent-directory inference cannot
        // find App.gpr, so only the explicit governing-project plumbing works.
        let work = temp.path().join("external-work/govfuzz_work");
        let staged = work.join("src_instrumented");
        let harness = work.join("generated_harnesses/H-GPR-OVERLAY");
        fs::create_dir_all(&staged).unwrap();
        fs::create_dir_all(&harness).unwrap();
        fs::write(staged.join("vendor_pkg.ads"), package_source).unwrap();
        fs::write(
            harness.join("main.adb"),
            "with Pkg; procedure Main is X : Integer := Pkg.X; begin X := X + 1; end Main;\n",
        )
        .unwrap();
        let args = BuildArgs {
            work_dir: work,
            source_project: Some(source_project.clone()),
            harness: Some("H-GPR-OVERLAY".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: ProbeBackend::HostFile,
            c_engine: CEngine::Libfuzzer,
        };

        let captured = try_run_ada_build_capturing(&args).unwrap();
        assert!(
            captured.status_success,
            "overlay should inherit custom Naming, scenario, config, import, binder and linker settings:\n{}\n{}",
            captured.stdout, captured.stderr
        );
        let generated =
            fs::read_to_string(args.work_dir.join("build/H-GPR-OVERLAY/govfuzz_build.gpr"))
                .unwrap();
        assert!(generated.contains(&format!("extends \"{}\"", source_project.display())));
    }

    #[test]
    fn ada_runtime_project_builds_c_and_is_never_coverage_instrumented() {
        // #412: the AdaFuzz runtime project ships the C trace-pc callback
        // (adafuzz_cov.c) but is compiled WITHOUT any coverage instrumentation, so
        // the callback never recurses into itself.
        let tmp = tempfile::tempdir().unwrap();
        let build_dir = tmp.path();
        let gpr = build_dir.join("adafuzz_runtime.gpr");
        write_runtime_project(&gpr, build_dir, ProbeBackend::HostFile).unwrap();
        let rendered = fs::read_to_string(&gpr).unwrap();
        assert!(
            rendered.contains("for Languages use (\"Ada\", \"C\")"),
            "runtime project must build C:\n{rendered}"
        );
        assert!(
            rendered.contains("\"adafuzz_cov.c\""),
            "runtime project must include the trace-pc callback source:\n{rendered}"
        );
        assert!(
            !rendered.contains("-fsanitize-coverage"),
            "runtime project must never be coverage-instrumented:\n{rendered}"
        );
    }

    #[test]
    fn govfuzz_build_renders_trace_pc_only_when_instrumented() {
        // #412: the target/harness ProjectSpec carries
        // `-fsanitize-coverage=trace-pc` in its Ada Default_Switches when
        // instrumented, and the default (uninstrumented) spec carries none — the
        // switch wiring prepare_layout toggles behind the gcc capability probe.
        let spec_with = |switches: Switches| ProjectSpec {
            project_name: "Govfuzz_Build".to_owned(),
            extends_project: None,
            source_roots: vec![SourceRoot {
                path: PathBuf::from("/tmp/src"),
                language: "Ada".to_owned(),
            }],
            object_dir: PathBuf::from("/tmp/obj"),
            exec_dir: None,
            main_adb: Some("main.adb".to_owned()),
            ada_standard: AdaStandard::Ada2012,
            target: None,
            runtime: None,
            toolchain: None,
            switches,
            with_clauses: vec![PathBuf::from("adafuzz_runtime.gpr")],
            executable_name: None,
            compile_c: false,
            excluded_source_files: Vec::new(),
        };

        let mut instrumented = Switches::default();
        instrumented.default.push(ADA_COV_TRACE_PC_FLAG.to_owned());
        let with_flag = project_synth::render_project(&spec_with(instrumented)).unwrap();
        assert!(
            with_flag.contains("-fsanitize-coverage=trace-pc"),
            "instrumented Govfuzz_Build must carry trace-pc:\n{with_flag}"
        );

        let without = project_synth::render_project(&spec_with(Switches::default())).unwrap();
        assert!(
            !without.contains("-fsanitize-coverage"),
            "default Govfuzz_Build must carry no coverage flag:\n{without}"
        );
    }

    #[test]
    fn colliding_c_basenames_flags_only_same_stem_c_sources() {
        // `sxxx.adb` + `sxxx.c` -> both `sxxx.o` -> gprbuild "same object file name".
        // Only the colliding C file is returned; a C file with no Ada twin, and the
        // Ada files themselves, are left alone.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for name in [
            "sxxx.adb",
            "sxxx.c",
            "sxxx.h",
            "other.c",
            "widget.ads",
            "widget.c",
        ] {
            fs::write(dir.join(name), "x").unwrap();
        }
        let roots = vec![SourceRoot {
            path: dir.to_path_buf(),
            language: "Ada".to_owned(),
        }];
        let collisions = colliding_c_basenames(&roots);
        assert_eq!(
            collisions,
            vec!["sxxx.c".to_owned(), "widget.c".to_owned()],
            "only the C sources sharing a stem with an Ada unit collide"
        );
        assert!(
            !collisions.iter().any(|f| f == "other.c"),
            "a C file with no Ada twin must not be excluded: {collisions:?}"
        );
    }
}
