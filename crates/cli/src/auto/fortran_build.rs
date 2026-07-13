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
use crate::auto::fortran::{FortranArg, FortranArgKind};
use std::path::Path;
use std::process::Command;

pub enum FortranBuildResult {
    Built,
    Skip(String),
    Failed(String),
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
fn abi_symbol(name: &str) -> String {
    format!("{}_", name.to_ascii_lowercase())
}

/// The glue: `LLVMFuzzerTestOneInput` drives every dummy argument, plus a
/// self-contained `__sanitizer_cov_trace_pc` hook feeding the shared edge map
/// (gfortran emits trace-pc, which the govfuzz Linux driver — trace-pc-guard —
/// does not otherwise provide).
fn glue_source(entry: &str, args: &[FortranArg]) -> String {
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
            FortranArgKind::Other => {
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
            FortranArgKind::Other => "void *",
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
) -> FortranBuildResult {
    if !have_gfortran() {
        return FortranBuildResult::Skip(
            "no `gfortran` toolchain found; install gfortran to fuzz Fortran".to_owned(),
        );
    }
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return FortranBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }

    let source = match std::fs::read_to_string(&candidate.source_path) {
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

    // Compile the Fortran to an instrumented object (ASan + trace-pc + runtime checks).
    let fortran_o = hdir.join("fortran_target.o");
    // ASan (not `-fcheck`) is the memory oracle: `-fcheck=all` would exit(2) on a
    // bounds error before the raw access, which govfuzz classifies as an input
    // rejection; letting the raw out-of-bounds access happen surfaces it as a genuine
    // ASan crash with the exact `.f90:line`. trace-pc/trace-cmp feed the engine.
    let compiled = Command::new("gfortran")
        .args(["-O1", "-g", "-fsanitize=address"])
        .arg("-fsanitize-coverage=trace-pc,trace-cmp")
        // Write generated `.mod` module files into the harness dir (via -J) instead
        // of polluting the current working directory, and let a self-referential
        // module find its own .mod (-I) during the compile.
        .arg("-J")
        .arg(&hdir)
        .arg("-I")
        .arg(&hdir)
        .arg("-c")
        .arg(&candidate.source_path)
        .arg("-o")
        .arg(&fortran_o)
        .output();
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

    let entry = abi_symbol(&proc.name);
    let glue_c = hdir.join("fortran_glue.c");
    if let Err(e) = std::fs::write(&glue_c, glue_source(&entry, &proc.args)) {
        return FortranBuildResult::Failed(format!("write glue: {e}"));
    }

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
            target_sources: vec![fortran_o.clone(), glue_c.clone()],
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
    let built = Command::new("make")
        .current_dir(&hdir)
        .env("AUTO_EXTRA_LDFLAGS", ldflags)
        .output();
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
        assert_eq!(abi_symbol("Scan"), "scan_");
        assert_eq!(abi_symbol("COUNT_IT"), "count_it_");
    }

    #[test]
    fn glue_drives_buffer_len_and_hidden_length() {
        let args = vec![
            arg("BUF", FortranArgKind::CharBuffer { len: 0 }),
            arg("N", FortranArgKind::Integer),
        ];
        let g = glue_source("scan_", &args);
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
        let g = glue_source("nasopn_", &args);
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
        let g = glue_source("f_", &args);
        assert!(g.contains("extern void f_(char *, size_t);"));
        assert!(g.contains("f_(gf_a0, (size_t)gf_primary_len);"));
    }
}
