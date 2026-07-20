// SPDX-License-Identifier: Apache-2.0

//! Fortran harness build (M3.5) — see [`crate::auto::fortran`] for the strategy.
//!
//! Step 0 for a `Lang::Fortran` candidate: compile the `.f90`/`.f` with
//! `gfortran -fsanitize=address -fsanitize-coverage=trace-pc -fcheck=all` (ASan
//! catches memory corruption with the exact `.f90:line`, `-fcheck` adds Fortran
//! runtime checks, `trace-pc` feeds a coverage hook the glue defines), generate a
//! `LLVMFuzzerTestOneInput` glue that calls the routine via the gfortran C ABI
//! (`name_`, args by reference, a hidden `size_t` length per character arg), and
//! build+link on the passthrough C fork-server path with `-lgfortran`.

use crate::auto::candidate::Candidate;
use crate::auto::fortran::{FortranArg, FortranArgKind, FortranResult};
use std::path::{Path, PathBuf};
use std::process::Command;

pub enum FortranBuildResult {
    Built,
    Skip(String),
    Failed(String),
}

/// A stable, per-project `.mod` directory under the work dir (keyed on the source
/// root), shared across every harness of the project so the module graph is built
/// once.
fn fortran_module_dir(work_dir: &Path, source_root: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source_root.hash(&mut hasher);
    work_dir.join(format!("fortran_modules_{:016x}", hasher.finish()))
}

/// Whether `path` is a Fortran source file by extension (free or fixed form).
fn is_fortran_source(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("f90" | "f95" | "f03" | "f08" | "f" | "for" | "f77" | "ftn")
    )
}

/// Cheap check that a file DEFINES at least one module (`MODULE name`, not
/// `MODULE PROCEDURE` / `USE`), so the pre-compile only spends time on module
/// providers.
fn file_defines_module(path: &Path) -> bool {
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    src.lines().any(|l| {
        let t = l.trim_start().to_ascii_lowercase();
        if let Some(rest) = t.strip_prefix("module ") {
            let next = rest.trim_start();
            !next.starts_with("procedure")
        } else {
            false
        }
    })
}

/// Collect up to `budget` module-defining Fortran files under `root`, skipping
/// build/VCS/test directories.
fn collect_module_files(root: &Path, budget: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= budget {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if !matches!(
                    name.as_str(),
                    ".git"
                        | "build"
                        | "target"
                        | "node_modules"
                        | ".fpm"
                        | "test"
                        | "tests"
                        | "example"
                        | "examples"
                        | "doc"
                        | "docs"
                        | "bench"
                ) {
                    stack.push(p);
                }
            } else if is_fortran_source(&p) && file_defines_module(&p) {
                out.push(p);
                if out.len() >= budget {
                    break;
                }
            }
        }
    }
    out
}

/// Pre-compile the project's module-defining Fortran files into a shared directory
/// so a target that `USE`s a sibling module both COMPILES (finds the `.mod`
/// interface) and LINKS (the module's `.o` provides its procedures). Modern Fortran
/// is module-heavy (fortran-lang/stdlib, fpm), so without this most real Fortran is
/// un-fuzzable. Best-effort and cached: each file is compiled to `<stem>.o` with the
/// SAME instrumentation as the target (ASan + trace-pc/cmp) so the objects link and
/// their code is covered; a fixpoint loop retries files whose USEd modules weren't
/// available yet (resolving the dependency DAG without parsing `USE` graphs),
/// stopping when a round makes no progress. Files needing external deps stay
/// unresolved — the target build then fails cleanly, as before.
fn precompile_project_modules(source_root: &Path, moddir: &Path) {
    let marker = moddir.join(".govfuzz_modules_done");
    if marker.exists() {
        return;
    }
    if std::fs::create_dir_all(moddir).is_err() {
        return;
    }
    let mut remaining = collect_module_files(source_root, 2000);
    for _ in 0..12 {
        if remaining.is_empty() {
            break;
        }
        let before = remaining.len();
        remaining.retain(|f| {
            let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("mod");
            let obj = moddir.join(format!("{stem}.o"));
            let ok = crate::command_output::output_with_timeout(
                Command::new("gfortran")
                    .args(["-O1", "-g", "-fsanitize=address"])
                    .arg("-fsanitize-coverage=trace-pc,trace-cmp")
                    .arg("-cpp")
                    .arg("-ffree-line-length-none")
                    .arg("-J")
                    .arg(moddir)
                    .arg("-I")
                    .arg(moddir)
                    .arg("-c")
                    .arg(f)
                    .arg("-o")
                    .arg(&obj),
                std::time::Duration::from_secs(30 * 60),
            )
            .map(|o| o.status.success() && obj.is_file())
            .unwrap_or(false);
            !ok // keep only the ones that still failed
        });
        if remaining.len() == before {
            break; // no progress — the rest need external deps / flags
        }
    }
    let _ = std::fs::write(&marker, "");
}

/// The pre-compiled project module objects to link into a harness, EXCLUDING the
/// one built from the target's own file (which the harness compiles separately —
/// linking both would duplicate its module's symbols).
fn project_module_objects(moddir: &Path, target_src: &Path) -> Vec<PathBuf> {
    let target_stem = target_src.file_stem().and_then(|s| s.to_str());
    let Ok(rd) = std::fs::read_dir(moddir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("o"))
        .filter(|p| p.file_stem().and_then(|s| s.to_str()) != target_stem)
        .collect()
}

fn have_gfortran() -> bool {
    Command::new("gfortran")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The directory holding `libgfortran.so`, for the harness link.
fn gfortran_libdir() -> Option<String> {
    let out = Command::new("gfortran")
        .arg("-print-file-name=libgfortran.so")
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout);
    let path = path.trim();
    Path::new(path)
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
}

/// gfortran default ABI: lowercase the name and append a trailing underscore.
/// The gfortran C-ABI symbol for a procedure. An external (top-level) procedure is
/// `name_`; a MODULE-contained procedure is `__<module>_MOD_<name>` (gfortran's
/// name mangling) — most modern Fortran procedures live in a `module … contains`
/// block, so without this they are un-callable and the whole module lane is limited.
fn abi_symbol(name: &str, module: Option<&str>) -> String {
    match module {
        Some(m) => format!(
            "__{}_MOD_{}",
            m.to_ascii_lowercase(),
            name.to_ascii_lowercase()
        ),
        None => format!("{}_", name.to_ascii_lowercase()),
    }
}

/// The glue: `LLVMFuzzerTestOneInput` drives every dummy argument, plus a
/// self-contained `__sanitizer_cov_trace_pc` hook feeding the shared edge map
/// (gfortran emits trace-pc, which the govfuzz Linux driver — trace-pc-guard —
/// does not otherwise provide).
fn glue_source(entry: &str, args: &[FortranArg], result: FortranResult) -> String {
    let primary = args
        .iter()
        .position(|a| matches!(a.kind, FortranArgKind::CharBuffer { .. }))
        .unwrap_or(0);
    // A length operand: an integer named *LEN*/*N*/*SIZE*/*COUNT*, else the integer
    // right after the primary buffer.
    let len_idx = args
        .iter()
        .position(|a| {
            matches!(a.kind, FortranArgKind::Integer) && {
                let u = a.name.to_ascii_uppercase();
                u.contains("LEN") || u == "N" || u.contains("SIZE") || u.contains("COUNT")
            }
        })
        .or_else(|| {
            let n = primary + 1;
            args.get(n)
                .filter(|a| matches!(a.kind, FortranArgKind::Integer))
                .map(|_| n)
        });

    const BUFSZ: usize = 65536;
    let mut decls = String::new();
    let mut fills = String::new();
    let mut frees = String::new();
    let mut call_args: Vec<String> = Vec::new();
    let mut hidden_lengths: Vec<String> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let var = format!("gf_a{i}");
        match a.kind {
            FortranArgKind::CharBuffer { len } => {
                if i == primary && len == 0 {
                    // Assumed-length `CHARACTER*(*)`: the hidden length IS the byte
                    // count, so heap-allocate to the EXACT input size — a real
                    // out-of-bounds access (relative to that length) lands in ASan's
                    // redzone, which a static over-allocated buffer would hide.
                    decls.push_str(&format!(
                        "    char *{var} = (char *)malloc(Size ? Size : 1);\n"
                    ));
                    fills.push_str(&format!(
                        "    if (!{var}) return 0;\n    if (Size) memcpy({var}, Data, Size);\n    gf_primary_len = Size;\n"
                    ));
                    frees.push_str(&format!("    free({var});\n"));
                    hidden_lengths.push("(size_t)gf_primary_len".to_owned());
                } else if i == primary {
                    // Fixed `CHARACTER*K`: the callee addresses `buf(1:K)`, so the
                    // buffer MUST be K bytes even when the fuzz input is shorter —
                    // allocating only `Size` and passing hidden length K overran the
                    // buffer (heap-overflow FALSE POSITIVE, NASTRAN `NASOPN` on a
                    // `CHARACTER*80` arg with a 0-byte input). Allocate exactly K
                    // (so a real `buf(K+1)` still hits the redzone), fill up to K
                    // fuzz bytes, and space-pad the rest (Fortran blank-fill).
                    decls.push_str(&format!("    char *{var} = (char *)malloc({len});\n"));
                    fills.push_str(&format!(
                        "    if (!{var}) return 0;\n    memset({var}, ' ', {len});\n    gf_primary_len = Size < {len} ? Size : {len};\n    if (gf_primary_len) memcpy({var}, Data, gf_primary_len);\n"
                    ));
                    frees.push_str(&format!("    free({var});\n"));
                    hidden_lengths.push(format!("(size_t){len}"));
                } else {
                    decls.push_str(&format!("    static char {var}[{BUFSZ}];\n"));
                    fills.push_str(&format!("    memset({var}, ' ', sizeof {var});\n"));
                    // A non-primary fixed len=K fits the large static buffer; an
                    // assumed-length one uses the primary byte count.
                    if len == 0 {
                        hidden_lengths.push("(size_t)gf_primary_len".to_owned());
                    } else {
                        hidden_lengths.push(format!("(size_t){len}"));
                    }
                }
                call_args.push(var.clone());
            }
            FortranArgKind::Integer => {
                decls.push_str(&format!("    int {var} = 0;\n"));
                if Some(i) == len_idx {
                    fills.push_str(&format!("    {var} = (int)gf_primary_len;\n"));
                }
                call_args.push(format!("&{var}"));
            }
            // A Derived arg only reaches here for a NON-primary operand of an
            // otherwise-fuzzable procedure (a Derived on the target itself makes it
            // un-fuzzable and it is never built); pass a zeroed scratch like Other.
            FortranArgKind::Other | FortranArgKind::Derived => {
                decls.push_str(&format!("    static unsigned char {var}[256];\n"));
                fills.push_str(&format!("    memset({var}, 0, sizeof {var});\n"));
                call_args.push(format!("(void *){var}"));
            }
        }
    }
    let mut all_args = call_args;
    all_args.extend(hidden_lengths);
    let extern_params: Vec<&str> = args
        .iter()
        .map(|a| match a.kind {
            FortranArgKind::CharBuffer { .. } => "char *",
            FortranArgKind::Integer => "int *",
            FortranArgKind::Other | FortranArgKind::Derived => "void *",
        })
        .collect();
    let hidden_count = args
        .iter()
        .filter(|a| matches!(a.kind, FortranArgKind::CharBuffer { .. }))
        .count();
    let mut extern_sig: Vec<String> = extern_params.iter().map(|s| s.to_string()).collect();
    for _ in 0..hidden_count {
        extern_sig.push("size_t".to_owned());
    }
    // A `character`-returning function's gfortran C ABI prepends a hidden result
    // argument the caller must supply (verified empirically). Two forms:
    match result {
        // NonChar drives the plain `void` ABI; Unsupported never reaches here (an
        // array-char result makes the procedure non-fuzzable), but is handled defensively.
        FortranResult::NonChar | FortranResult::Unsupported => {}
        FortranResult::ValueChar { fixed_len } => {
            // `void f(char* result, size_t result_len, <args…>)`. The glue allocates a
            // blank-initialised result buffer (Fortran strings are space-padded) sized
            // generously — the declared constant length, at least 4× the input (headroom
            // for a spec-expression that expands the input), floored and capped — so the
            // callee writes its result in bounds, and passes its true size as the length.
            let res_alloc = format!(
                "\x20   size_t gf_res_len = (size_t)Size * 4;\n\
                 \x20   if (gf_res_len < 4096) gf_res_len = 4096;\n\
                 \x20   if (gf_res_len < {fixed_len}u) gf_res_len = {fixed_len}u;\n\
                 \x20   gf_res_len += 256;\n\
                 \x20   if (gf_res_len > (1u << 22)) gf_res_len = (1u << 22);\n\
                 \x20   char *gf_res = (char *)malloc(gf_res_len);\n\
                 \x20   if (!gf_res) return 0;\n\
                 \x20   memset(gf_res, ' ', gf_res_len);\n"
            );
            decls.push_str(&res_alloc);
            frees.push_str("    free(gf_res);\n");
            all_args.insert(0, "gf_res_len".to_owned());
            all_args.insert(0, "gf_res".to_owned());
            extern_sig.insert(0, "size_t".to_owned());
            extern_sig.insert(0, "char *".to_owned());
        }
        FortranResult::AllocChar => {
            // `void f(char** data, size_t* len, <args…>)` — the callee `malloc`s the
            // result (deferred-length `character(len=:), allocatable`), stores the
            // pointer + length, and the glue frees it. No expansion-overflow risk.
            let res_alloc = "\x20   char *gf_res_data = 0;\n\
                 \x20   size_t gf_res_len = 0;\n";
            decls.push_str(res_alloc);
            frees.push_str("    free(gf_res_data);\n");
            all_args.insert(0, "&gf_res_len".to_owned());
            all_args.insert(0, "&gf_res_data".to_owned());
            extern_sig.insert(0, "size_t *".to_owned());
            extern_sig.insert(0, "char **".to_owned());
        }
    }
    let extern_sig = if extern_sig.is_empty() {
        "void".to_owned()
    } else {
        extern_sig.join(", ")
    };
    let call = all_args.join(", ");

    format!(
        "/* SPDX-License-Identifier: Apache-2.0 */\n\
         /* govfuzz Fortran glue: drives {entry} from fuzzer bytes. */\n\
         #include <stdint.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #include <unistd.h>\n\
         #include <fcntl.h>\n\
         #include <sys/mman.h>\n\
         extern void {entry}({extern_sig});\n\
         /* gfortran instruments with -fsanitize-coverage=trace-pc (no guard); the\n\
         \x20* govfuzz Linux driver only provides trace-pc-guard, so define the\n\
         \x20* trace-pc hook here, writing into the same shared edge map the engine\n\
         \x20* reads (GOVFUZZ_COV_SHM). ASan reports memory bugs directly, so no\n\
         \x20* exit() interposition is needed (unlike the COBOL lane). */\n\
         #define GF_COV_BITS (1u << 16)\n\
         static unsigned char *gf_cov = 0;\n\
         static int gf_cov_init = 0;\n\
         __attribute__((no_sanitize(\"coverage\"))) static void gf_cov_open(void) {{\n\
         \x20   const char *p = getenv(\"GOVFUZZ_COV_SHM\"); gf_cov_init = 1;\n\
         \x20   if (!p || !*p) return;\n\
         \x20   int fd = open(p, O_RDWR | O_CREAT, 0600); if (fd < 0) return;\n\
         \x20   if (ftruncate(fd, GF_COV_BITS) == 0) {{ void *m = mmap(0, GF_COV_BITS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); if (m != MAP_FAILED) gf_cov = (unsigned char *)m; }}\n\
         \x20   close(fd);\n\
         }}\n\
         __attribute__((no_sanitize(\"coverage\"))) void __sanitizer_cov_trace_pc(void) {{\n\
         \x20   if (!gf_cov_init) gf_cov_open();\n\
         \x20   if (!gf_cov) return;\n\
         \x20   uintptr_t pc = (uintptr_t)__builtin_return_address(0);\n\
         \x20   unsigned h = ((unsigned)(pc * 2654435761u) >> 4) & (GF_COV_BITS - 1);\n\
         \x20   gf_cov[h] = 1;\n\
         }}\n\
         int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{\n\
         \x20   size_t gf_primary_len = 0; (void)gf_primary_len; (void)Data;\n\
         {decls}\
         {fills}\
         \x20   {entry}({call});\n\
         {frees}\
         \x20   return 0;\n\
         }}\n"
    )
}

/// Build the Fortran harness for `candidate` into `harnesses/<harness_id>/`.
pub fn build_fortran_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> FortranBuildResult {
    if !have_gfortran() {
        return FortranBuildResult::Skip(
            "no `gfortran` toolchain found; install gfortran to fuzz Fortran".to_owned(),
        );
    }
    // Build the project's module graph once (cached) so a target that USEs a
    // sibling module compiles — otherwise gfortran fails with "Cannot open module
    // file 'x.mod'" and modern module-heavy Fortran is entirely un-fuzzable.
    let moddir = fortran_module_dir(work_dir, source_root);
    precompile_project_modules(source_root, &moddir);
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return FortranBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }

    let source = match crate::source_text::read_source_text(&candidate.source_path) {
        Ok(s) => s,
        Err(e) => return FortranBuildResult::Failed(format!("read Fortran source: {e}")),
    };
    let procs = crate::auto::fortran::parse_fortran(&source);
    let proc = procs
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(&candidate.name))
        .or_else(|| procs.first());
    let Some(proc) = proc.filter(|p| p.is_fuzzable()) else {
        return FortranBuildResult::Skip(format!(
            "{}: no fuzzable character argument",
            candidate.name
        ));
    };

    // Compile the Fortran to an instrumented object (ASan + trace-pc + runtime checks),
    // UNLESS the target's own file was already compiled as a project module object with
    // the SAME instrumentation — then reuse it. A large single-file library (M_strings
    // is a 12k-line file with dozens of targets) otherwise recompiles the whole file
    // once per target, which dominates the campaign wall-clock. `project_module_objects`
    // already EXCLUDES the target file's `.o`, so linking the reused object here adds no
    // duplicate symbols.
    let target_stem = candidate.source_path.file_stem().and_then(|s| s.to_str());
    let precompiled_o = target_stem.map(|s| moddir.join(format!("{s}.o")));
    let fortran_o = if let Some(reused) = precompiled_o.filter(|p| p.is_file()) {
        reused
    } else {
        let fortran_o = hdir.join("fortran_target.o");
        // ASan (not `-fcheck`) is the memory oracle: `-fcheck=all` would exit(2) on a
        // bounds error before the raw access, which govfuzz classifies as an input
        // rejection; letting the raw out-of-bounds access happen surfaces it as a genuine
        // ASan crash with the exact `.f90:line`. trace-pc/trace-cmp feed the engine.
        let compiled = crate::command_output::output_with_timeout(
            Command::new("gfortran")
                .args(["-O1", "-g", "-fsanitize=address"])
                .arg("-fsanitize-coverage=trace-pc,trace-cmp")
                .arg("-cpp")
                .arg("-ffree-line-length-none")
                // Write generated `.mod` module files into the harness dir (via -J) instead
                // of polluting the current working directory; find self-referential modules
                // (-I hdir) plus the pre-compiled PROJECT module graph (-I moddir) so a
                // target `USE`ing a sibling module builds.
                .arg("-J")
                .arg(&hdir)
                .arg("-I")
                .arg(&hdir)
                .arg("-I")
                .arg(&moddir)
                .arg("-c")
                .arg(&candidate.source_path)
                .arg("-o")
                .arg(&fortran_o),
            std::time::Duration::from_secs(30 * 60),
        );
        match compiled {
            Ok(o) if o.status.success() && fortran_o.is_file() => {}
            Ok(o) => {
                return FortranBuildResult::Failed(format!(
                    "gfortran compile failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .filter(|l| l.to_ascii_lowercase().contains("error"))
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            Err(e) => return FortranBuildResult::Failed(format!("spawn gfortran: {e}")),
        }
        fortran_o
    };

    let entry = abi_symbol(&proc.name, proc.module.as_deref());
    let glue_c = hdir.join("fortran_glue.c");
    if let Err(e) = std::fs::write(&glue_c, glue_source(&entry, &proc.args, proc.result)) {
        return FortranBuildResult::Failed(format!("write glue: {e}"));
    }

    // Link the pre-compiled project module objects so a target `USE`ing a sibling
    // module resolves that module's procedures (its `.o` provides them). The target's
    // own object is compiled above; exclude its module `.o` to avoid a duplicate.
    let mut target_sources = vec![fortran_o.clone(), glue_c.clone()];
    target_sources.extend(project_module_objects(&moddir, &candidate.source_path));

    let gen_result = harness_gen::c_generate::generate_c_direct_harness(
        harness_gen::c_generate::GenerateCDirectArgs {
            harness_id: harness_id.to_owned(),
            output_dir: hdir.clone(),
            source_path: candidate.source_path.clone(),
            target: c_parser::CFunction {
                name: "LLVMFuzzerTestOneInput".to_owned(),
                line: 0,
                return_type: "int".to_owned(),
                params: Vec::new(),
                is_static: false,
                foreign_guard: None,
                variadic: false,
            },
            params: Vec::new(),
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources,
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: crate::generate_harness::locate_c_runtime(),
            type_defs: Vec::new(),
            result_cleanup: None,
            lifecycle: Vec::new(),
            drive_plan: None,
            decoder_limits: harness_gen::c_decoders::DecoderLimits::default(),
            force: false,
        },
    );
    if let Err(e) = gen_result {
        return FortranBuildResult::Failed(format!("generate C driver: {e}"));
    }

    let mut ldflags = String::new();
    if let Some(dir) = gfortran_libdir() {
        ldflags.push_str(&format!("-L{dir} "));
    }
    ldflags.push_str("-lgfortran -lquadmath -lm");
    let built = crate::command_output::output_with_timeout(
        Command::new("make")
            .current_dir(&hdir)
            .env("AUTO_EXTRA_LDFLAGS", ldflags),
        std::time::Duration::from_secs(30 * 60),
    );
    let main_bin = hdir.join("main");
    match built {
        Ok(o) if o.status.success() && main_bin.is_file() => FortranBuildResult::Built,
        Ok(o) => FortranBuildResult::Failed(format!(
            "Fortran harness build failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .filter(|l| l.contains("error"))
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        )),
        Err(e) => FortranBuildResult::Failed(format!("spawn make: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(name: &str, kind: FortranArgKind) -> FortranArg {
        FortranArg {
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn abi_symbol_lowercases_and_underscores() {
        assert_eq!(abi_symbol("Scan", None), "scan_");
        assert_eq!(abi_symbol("COUNT_IT", None), "count_it_");
        // A module-contained procedure uses gfortran's __module_MOD_name mangling.
        assert_eq!(
            abi_symbol("count_vowels", Some("utils_mod")),
            "__utils_mod_MOD_count_vowels"
        );
    }

    #[test]
    fn glue_drives_buffer_len_and_hidden_length() {
        let args = vec![
            arg("BUF", FortranArgKind::CharBuffer { len: 0 }),
            arg("N", FortranArgKind::Integer),
        ];
        let g = glue_source("scan_", &args, FortranResult::NonChar);
        // extern has 2 explicit args + 1 hidden size_t for the character arg.
        assert!(g.contains("extern void scan_(char *, int *, size_t);"));
        // Assumed-length: hidden length is the byte count; N gets it too.
        assert!(g.contains("scan_(gf_a0, &gf_a1, (size_t)gf_primary_len);"));
        assert!(g.contains("gf_a1 = (int)gf_primary_len;"));
        assert!(g.contains("gf_primary_len = Size;"));
        assert!(g.contains("char *gf_a0 = (char *)malloc(Size ? Size : 1)"));
        // trace-pc coverage hook present.
        assert!(g.contains("void __sanitizer_cov_trace_pc(void)"));
    }

    #[test]
    fn glue_fixed_length_char_buffer_is_sized_to_the_declared_length() {
        // A fixed `CHARACTER*80` primary arg (NASTRAN `NASOPN`): the callee addresses
        // `buf(1:80)`, so the buffer MUST be 80 bytes even for a short/empty input —
        // allocating only `Size` and passing hidden length 80 overran it (ASan
        // heap-overflow FALSE POSITIVE).
        let args = vec![arg("DSN", FortranArgKind::CharBuffer { len: 80 })];
        let g = glue_source("nasopn_", &args, FortranResult::NonChar);
        assert!(g.contains("char *gf_a0 = (char *)malloc(80);"));
        assert!(g.contains("memset(gf_a0, ' ', 80);"));
        assert!(g.contains("gf_primary_len = Size < 80 ? Size : 80;"));
        // Hidden length still the declared 80, now matched by the buffer.
        assert!(g.contains("nasopn_(gf_a0, (size_t)80);"));
        assert!(!g.contains("malloc(Size ? Size : 1)"));
    }

    #[test]
    fn glue_assumed_length_uses_byte_count_as_hidden_len() {
        let args = vec![arg("S", FortranArgKind::CharBuffer { len: 0 })];
        let g = glue_source("f_", &args, FortranResult::NonChar);
        assert!(g.contains("extern void f_(char *, size_t);"));
        assert!(g.contains("f_(gf_a0, (size_t)gf_primary_len);"));
    }

    #[test]
    fn glue_value_char_function_prepends_result_buffer_pair() {
        // fortran-csv-module `lowercase_string(str) result(s)` where `s` is a
        // fixed/assumed-length CHARACTER: gfortran's ABI is `void f(char* result,
        // size_t result_len, char* str, size_t str_len)`. Without the hidden result
        // pair the fuzz buffer lands in the result slot and `str` is a garbage pointer
        // -> OOB read/SEGV false positive.
        let args = vec![arg("STR", FortranArgKind::CharBuffer { len: 0 })];
        let g = glue_source(
            "__csv_utilities_MOD_lowercase_string",
            &args,
            FortranResult::ValueChar { fixed_len: 0 },
        );
        // Hidden result pair (char*, size_t) is prepended to BOTH the extern and call.
        assert!(g.contains(
            "extern void __csv_utilities_MOD_lowercase_string(char *, size_t, char *, size_t);"
        ));
        assert!(g.contains("__csv_utilities_MOD_lowercase_string(gf_res, gf_res_len, gf_a0, (size_t)gf_primary_len);"));
        // Result buffer is allocated, blank-filled, and freed.
        assert!(g.contains("char *gf_res = (char *)malloc(gf_res_len);"));
        assert!(g.contains("memset(gf_res, ' ', gf_res_len);"));
        assert!(g.contains("free(gf_res);"));
    }

    #[test]
    fn glue_alloc_char_function_passes_and_frees_callee_allocated_result() {
        // M_strings `upper(str) result(output)` where `output` is
        // `character(len=:), allocatable`: gfortran's ABI is `void f(char** data,
        // size_t* len, char* str, size_t str_len)` — the callee mallocs the result. The
        // glue passes address-of pointers and frees the callee-allocated buffer.
        let args = vec![arg("STR", FortranArgKind::CharBuffer { len: 0 })];
        let g = glue_source("__m_strings_MOD_upper", &args, FortranResult::AllocChar);
        assert!(g.contains("extern void __m_strings_MOD_upper(char **, size_t *, char *, size_t);"));
        assert!(g.contains(
            "__m_strings_MOD_upper(&gf_res_data, &gf_res_len, gf_a0, (size_t)gf_primary_len);"
        ));
        assert!(g.contains("char *gf_res_data = 0;"));
        assert!(g.contains("free(gf_res_data);"));
        // The callee allocates; the glue must NOT pre-allocate a result buffer here.
        assert!(!g.contains("malloc(gf_res_len)"));
    }
}
