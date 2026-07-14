// SPDX-License-Identifier: Apache-2.0

//! COBOL harness build (M3.4) — see [`crate::auto::cobol`] for the strategy.
//!
//! Step 0 of the attempt loop for a `Lang::Cobol` candidate: translate the COBOL
//! subprogram to C with `cobc -C -debug -fec=all` (free/fixed format detected,
//! copybook dirs added as `-I`), generate a `LLVMFuzzerTestOneInput` glue that
//! drives the `PROCEDURE DIVISION USING` operands from the fuzz bytes, reuse the
//! passthrough C fork-server driver + coverage/cmplog runtime, and build with
//! `libcob` linked. The result at `harnesses/<id>/main` is a normal govfuzz C
//! harness the built-in engine drives unchanged.

use crate::auto::candidate::Candidate;
use crate::auto::cobol::{CobolParam, CobolParamKind};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub enum CobolBuildResult {
    Built,
    /// Not fuzzable here (no `cobc`, no byte-buffer LINKAGE operand) — skip cleanly.
    Skip(String),
    /// A genuine build failure.
    Failed(String),
}

/// `cob-config --cflags` / `--libs`, or conservative defaults when the helper is
/// absent. libcob is LGPLv3 and links into the user's harness (like the GNAT
/// runtime), never into govfuzz.
fn cob_config(flag: &str) -> Vec<String> {
    if let Ok(o) = Command::new("cob-config").arg(flag).output() {
        if o.status.success() {
            let toks: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect();
            if !toks.is_empty() {
                return toks;
            }
        }
    }
    match flag {
        "--libs" => vec!["-lcob".to_owned(), "-lm".to_owned()],
        _ => Vec::new(),
    }
}

fn have_cobc() -> bool {
    Command::new("cobc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether the source is free-format (code from column 1, `*>` comments) vs the
/// fixed 80-column format. An explicit `>>SOURCE FORMAT` directive wins.
fn is_free_format(source: &str) -> bool {
    for line in source.lines() {
        let u = line.to_ascii_uppercase();
        if u.contains(">>SOURCE FORMAT") || u.contains(">> SOURCE FORMAT") {
            if u.contains("FREE") {
                return true;
            }
            if u.contains("FIXED") {
                return false;
            }
        }
    }
    source.lines().any(|l| {
        l.contains("*>")
            || (l.starts_with(|c: char| c.is_ascii_alphabetic()) && {
                let u = l.trim_end().to_ascii_uppercase();
                u.starts_with("IDENTIFICATION DIVISION")
                    || u.starts_with("PROGRAM-ID")
                    || u.starts_with("DATA DIVISION")
                    || u.starts_with("PROCEDURE DIVISION")
                    || u.starts_with("ENVIRONMENT DIVISION")
                    || u.starts_with("WORKING-STORAGE")
            })
    })
}

/// Directories to pass to `cobc` as copybook search paths (`-I`): the source
/// file's own directory plus every directory under the project root that holds a
/// `.cpy` copybook. Bounded so a huge tree can't stall discovery.
fn copybook_includes(source_path: &Path) -> Vec<PathBuf> {
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    if let Some(d) = source_path.parent() {
        dirs.insert(d.to_path_buf());
    }
    // Walk up to a plausible project root (a `.git` dir, or up to 5 levels).
    let mut chosen = source_path.parent().map(Path::to_path_buf);
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    let mut levels = 0;
    while let Some(d) = cursor {
        chosen = Some(d.clone());
        if d.join(".git").exists() {
            break;
        }
        levels += 1;
        if levels >= 5 {
            break;
        }
        cursor = d.parent().map(Path::to_path_buf);
    }
    if let Some(root) = chosen {
        collect_cpy_dirs(&root, 0, &mut dirs);
    }
    dirs.into_iter().collect()
}

fn collect_cpy_dirs(dir: &Path, depth: usize, out: &mut BTreeSet<PathBuf>) {
    if depth > 6 || out.len() > 200 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, ".git" | "target" | "node_modules" | ".svn") {
                continue;
            }
            collect_cpy_dirs(&p, depth + 1, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case("cpy"))
            .unwrap_or(false)
        {
            if let Some(d) = p.parent() {
                out.insert(d.to_path_buf());
            }
        }
    }
}

/// Recover the C entry symbol GnuCOBOL emitted: `int   PROGID (cob_u8_t *...)`
/// (whitespace/tab-separated; the PROGRAM-ID may be mixed-case with `_` for `-`).
/// Recover the C entry symbol for the TARGET program `program_id` from cobc's
/// generated C. `cobc -C` emits a C function per `PROGRAM-ID` in the source, so a
/// multi-program file yields several `int Name(cob_u8_t *…)` entries; picking the
/// FIRST one drives the wrong program (e.g. targeting CobolCraft `Facing-FromString`
/// but calling `Facing-GetRelative` — whose numeric-first operand fuzzed to garbage
/// then indexed a stack array out of bounds: a false positive). Match the entry
/// whose de-mangled name equals `program_id` (cobc mangles `-` to `__`; normalize by
/// dropping every non-alphanumeric char and upper-casing both sides). Fall back to
/// the first entry when nothing matches (single-program files / unusual mangling).
fn recover_entry_symbol(generated_c: &str, program_id: &str) -> Option<String> {
    let normalize = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    };
    let want = normalize(program_id);
    let mut first: Option<String> = None;
    for line in generated_c.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("int") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        if !after.starts_with("(cob_u8_t") {
            continue;
        }
        if normalize(&name) == want {
            return Some(name);
        }
        first.get_or_insert(name);
    }
    first
}

/// Whether `program_id` was compiled by cobc as a NESTED program — a `static int`
/// C function whose name (de-mangled: cobc appends a `_0_`/`_0__` nesting suffix)
/// begins with the target's normalized name. Such a function has internal linkage and
/// cannot be reached from the generated harness, so the target is skipped rather than
/// reported as a failed build.
fn is_nested_static_program(generated_c: &str, program_id: &str) -> bool {
    let normalize = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    };
    let want = normalize(program_id);
    if want.is_empty() {
        return false;
    }
    for line in generated_c.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("static int") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        if !after.starts_with("(cob_u8_t") {
            continue;
        }
        // cobc mangles a nested program `getquery` to `getquery_0__`; normalized that is
        // `GETQUERY0`, which starts with the wanted `GETQUERY`.
        if normalize(&name).starts_with(&want) {
            return true;
        }
    }
    false
}

/// Pick the operand to set to the fuzz byte count: a numeric operand named
/// `*LEN*`/`*LENGTH*`/`*SIZE*`/`*COUNT*`, else the numeric operand immediately
/// after the primary buffer.
fn length_param_index(params: &[CobolParam], primary: usize) -> Option<usize> {
    let named = params.iter().position(|p| {
        matches!(p.kind, CobolParamKind::Numeric { .. }) && {
            let u = p.name.to_ascii_uppercase();
            u.contains("LEN") || u.contains("SIZE") || u.contains("COUNT")
        }
    });
    if named.is_some() {
        return named;
    }
    let next = primary + 1;
    if params
        .get(next)
        .is_some_and(|p| matches!(p.kind, CobolParamKind::Numeric { .. }))
    {
        Some(next)
    } else {
        None
    }
}

/// The `LLVMFuzzerTestOneInput` glue that drives every `USING` operand.
fn multi_param_glue(entry: &str, params: &[CobolParam]) -> String {
    let primary = params
        .iter()
        .position(|p| matches!(p.kind, CobolParamKind::Bytes { .. }))
        .unwrap_or(0);
    let len_idx = length_param_index(params, primary);

    let mut decls = String::new();
    let mut fills = String::new();
    let mut args: Vec<String> = Vec::new();
    for (i, p) in params.iter().enumerate() {
        let var = format!("gf_b{i}");
        let is_primary = i == primary;
        match p.kind {
            CobolParamKind::Bytes { len: Some(n) } if is_primary => {
                let n = n.max(1);
                decls.push_str(&format!("    static unsigned char {var}[{n}];\n"));
                fills.push_str(&format!(
                    "    memset({var}, ' ', {n});\n    {{ size_t _n = Size < {n} ? Size : (size_t){n}; if (_n) memcpy({var}, Data, _n); gf_primary_len = _n; }}\n"
                ));
            }
            CobolParamKind::Bytes { len: None } if is_primary => {
                decls.push_str(&format!("    static unsigned char {var}[65536];\n"));
                fills.push_str(&format!(
                    "    memset({var}, 0, sizeof {var});\n    {{ size_t _n = Size < sizeof {var} ? Size : sizeof {var}; if (_n) memcpy({var}, Data, _n); gf_primary_len = _n; }}\n"
                ));
            }
            CobolParamKind::Bytes { len: Some(n) } => {
                let n = n.max(1);
                decls.push_str(&format!("    static unsigned char {var}[{n}];\n"));
                fills.push_str(&format!("    memset({var}, ' ', {n});\n"));
            }
            CobolParamKind::Numeric { width } if Some(i) == len_idx => {
                let w = width.clamp(1, 8);
                decls.push_str(&format!("    unsigned char {var}[8];\n"));
                fills.push_str(&format!(
                    "    memset({var}, 0, sizeof {var});\n    {{ size_t _v = gf_primary_len; for (int _k = 0; _k < {w}; _k++) {var}[{w}-1-_k] = (unsigned char)((_v >> (8*_k)) & 0xff); }}\n"
                ));
            }
            _ => {
                // Secondary ANY-LENGTH buffers, other numerics, groups: a generous
                // zeroed scratch so the program's reads/writes stay in bounds.
                decls.push_str(&format!("    static unsigned char {var}[256];\n"));
                fills.push_str(&format!("    memset({var}, 0, sizeof {var});\n"));
            }
        }
        args.push(format!("(cob_u8_t *){var}"));
    }

    let extern_sig = if params.is_empty() {
        "void".to_owned()
    } else {
        vec!["cob_u8_t *"; params.len()].join(", ")
    };
    let call_args = args.join(", ");

    format!(
        "/* SPDX-License-Identifier: Apache-2.0 */\n\
         /* govfuzz COBOL glue: drives {entry}({n} operand(s)) from fuzzer bytes. */\n\
         #include <stdint.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #include <unistd.h>\n\
         #include <libcob.h>\n\
         extern int {entry}({extern_sig});\n\
         /* Interpose exit(): a libcob runtime check (EC-BOUND-*, EC-SIZE-*, zero\n\
         \x20* divide, ...) reports a COBOL-semantic defect via a nonzero exit, which\n\
         \x20* govfuzz would classify as an input REJECTION not a crash. ONLY while a\n\
         \x20* target call is in flight, force a genuine crash signal (SIGSEGV) so the\n\
         \x20* fuzzer records it, with the libcob + COBOL frames on the stack. A\n\
         \x20* nonzero exit outside a target call (ASan leak check on libcob's\n\
         \x20* by-design retained memory, teardown) passes through as a clean exit. */\n\
         static volatile int gf_in_target = 0;\n\
         __attribute__((noreturn)) void exit(int code) {{\n\
         \x20   if (code != 0 && gf_in_target) {{ *(volatile int *)0 = 0; }}\n\
         \x20   _exit(0);\n\
         }}\n\
         static int gf_cob_ready = 0;\n\
         int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{\n\
         \x20   if (!gf_cob_ready) {{ cob_init(0, (char **)0); gf_cob_ready = 1; }}\n\
         \x20   size_t gf_primary_len = 0; (void)gf_primary_len; (void)Data;\n\
         {decls}\
         {fills}\
         \x20   gf_in_target = 1;\n\
         \x20   int gf_rc = {entry}({call_args});\n\
         \x20   gf_in_target = 0;\n\
         \x20   return gf_rc;\n\
         }}\n",
        n = params.len()
    )
}

/// Build the COBOL harness for `candidate` into `harnesses/<harness_id>/`.
pub fn build_cobol_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
) -> CobolBuildResult {
    if !have_cobc() {
        return CobolBuildResult::Skip(
            "no `cobc` (GnuCOBOL) toolchain found; install gnucobol to fuzz COBOL".to_owned(),
        );
    }
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return CobolBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }

    let source = match std::fs::read_to_string(&candidate.source_path) {
        Ok(s) => s,
        Err(e) => return CobolBuildResult::Failed(format!("read COBOL source: {e}")),
    };
    let programs = crate::auto::cobol::parse_cobol(&source);
    let program = programs
        .iter()
        .find(|p| p.program_id == candidate.name)
        .or_else(|| programs.first());
    let Some(program) = program.filter(|p| p.is_fuzzable()) else {
        return CobolBuildResult::Skip(format!(
            "{}: no fuzzable LINKAGE byte-buffer operand (no USING PIC X input surface)",
            candidate.name
        ));
    };

    // Translate COBOL -> C with runtime bound checks (`-fec=all`); detect
    // free-format and add copybook search dirs so real projects translate.
    let target_c = hdir.join("cobol_target.c");
    let mut cmd = Command::new("cobc");
    cmd.arg("-C").arg("-debug").arg("-fec=all");
    if is_free_format(&source) {
        cmd.arg("-free");
    }
    for inc in copybook_includes(&candidate.source_path) {
        cmd.arg("-I").arg(inc);
    }
    cmd.arg("-o").arg(&target_c).arg(&candidate.source_path);
    match cmd.output() {
        Ok(o) if o.status.success() && target_c.is_file() => {}
        Ok(o) => {
            return CobolBuildResult::Failed(format!(
                "cobc -C failed: {}",
                String::from_utf8_lossy(&o.stderr)
                    .lines()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        Err(e) => return CobolBuildResult::Failed(format!("spawn cobc: {e}")),
    }

    let generated = std::fs::read_to_string(&target_c).unwrap_or_default();
    let Some(entry) = recover_entry_symbol(&generated, &program.program_id) else {
        // A NESTED (contained) COBOL program — one whose `END PROGRAM` precedes its
        // enclosing program's — is compiled by cobc as a `static` C function (mangled
        // `name_0_`, internal linkage), only callable from its parent via `CALL`. It has
        // no external entry the harness can link, so skip it cleanly (the COBOL analog of
        // a Fortran private module procedure / a C# internal-class method) rather than
        // reporting a confusing failed_build.
        if is_nested_static_program(&generated, &program.program_id) {
            return CobolBuildResult::Skip(format!(
                "{}: nested COBOL program (cobc compiles it as a static C function, not \
                 externally callable)",
                program.program_id
            ));
        }
        return CobolBuildResult::Failed(
            "could not recover the C entry symbol from cobc output".to_owned(),
        );
    };

    let glue_c = hdir.join("cobol_glue.c");
    if let Err(e) = std::fs::write(&glue_c, multi_param_glue(&entry, &program.params)) {
        return CobolBuildResult::Failed(format!("write glue: {e}"));
    }

    // Passthrough C driver (main.c) + Makefile; the COBOL C + glue are extra
    // sources, cob-config cflags let the driver see libcob headers.
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
            target_sources: vec![target_c.clone(), glue_c.clone()],
            compile_flags: cob_config("--cflags"),
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
        return CobolBuildResult::Failed(format!("generate C driver: {e}"));
    }

    let libs = cob_config("--libs").join(" ");
    let built = Command::new("make")
        .current_dir(&hdir)
        .env("AUTO_EXTRA_LDFLAGS", libs)
        .output();
    let main_bin = hdir.join("main");
    match built {
        Ok(o) if o.status.success() && main_bin.is_file() => CobolBuildResult::Built,
        Ok(o) => CobolBuildResult::Failed(format!(
            "COBOL harness build failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .filter(|l| l.contains("error"))
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        )),
        Err(e) => CobolBuildResult::Failed(format!("spawn make: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, kind: CobolParamKind) -> CobolParam {
        CobolParam {
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn recovers_mixed_case_tab_separated_entry() {
        let c = "int\t\tBlocks__Parse (cob_u8_t *, cob_u8_t *, cob_u8_t *);\n";
        assert_eq!(
            recover_entry_symbol(c, "Blocks-Parse").as_deref(),
            Some("Blocks__Parse")
        );
    }

    #[test]
    fn ignores_non_cobol_int_decls() {
        assert_eq!(
            recover_entry_symbol("int main(int argc, char **argv)", "Anything"),
            None
        );
    }

    #[test]
    fn recovers_the_targeted_entry_in_a_multi_program_file() {
        // cobc emits a C function per PROGRAM-ID; the harness must drive the TARGET,
        // not whichever appears first. Regression for CobolCraft `Facing-FromString`
        // being driven as `Facing-GetRelative` (first in the file) -> stack OOB FP.
        let c = "\
int\t\tFacing__GetRelative (cob_u8_t *, cob_u8_t *);
int\t\tFacing__ToString (cob_u8_t *, cob_u8_t *);
int\t\tFacing__FromString (cob_u8_t *, cob_u8_t *);
";
        assert_eq!(
            recover_entry_symbol(c, "Facing-FromString").as_deref(),
            Some("Facing__FromString"),
            "must match the targeted program, not the first in the file"
        );
        assert_eq!(
            recover_entry_symbol(c, "Facing-GetRelative").as_deref(),
            Some("Facing__GetRelative")
        );
        // Unknown target falls back to the first entry (single-program / odd mangling).
        assert_eq!(
            recover_entry_symbol(c, "Nonexistent").as_deref(),
            Some("Facing__GetRelative")
        );
    }

    #[test]
    fn nested_program_is_static_and_detected() {
        // cobol-on-wheelchair: `getquery`/`checkquery` are NESTED programs inside `cow`,
        // which cobc compiles as `static int getquery_0__(...)` (internal linkage) — no
        // external entry the harness can link. recover_entry_symbol finds none (the only
        // non-static entry is the parameterless main `cow`), and the target is detected
        // as nested so the build skips instead of failing.
        let c = "\
int\t\tcow (void);
static int\t\tcow_ (const int);
static int\t\tgetquery_0__ (cob_u8_t *);
static int\t\tgetquery_0_ (const int, cob_u8_t *);
static int\t\tcheckquery_0__ (cob_u8_t *, cob_u8_t *, cob_u8_t *, cob_u8_t *);
";
        // No linkable entry for the nested program.
        assert_eq!(recover_entry_symbol(c, "getquery"), None);
        // It is recognized as a nested (static) program.
        assert!(is_nested_static_program(c, "getquery"));
        assert!(is_nested_static_program(c, "checkquery"));
        // A genuinely-absent program is NOT flagged nested.
        assert!(!is_nested_static_program(c, "nonexistent"));
        // A top-level program with a real external entry is not "nested".
        let top = "int\t\tParseit (cob_u8_t *);\n";
        assert!(!is_nested_static_program(top, "Parseit"));
        assert_eq!(
            recover_entry_symbol(top, "Parseit").as_deref(),
            Some("Parseit")
        );
    }

    #[test]
    fn detects_free_vs_fixed_format() {
        assert!(is_free_format("*> a free-format comment\nPROGRAM-ID. P.\n"));
        assert!(is_free_format("IDENTIFICATION DIVISION.\nPROGRAM-ID. P.\n"));
        assert!(is_free_format(">>SOURCE FORMAT FREE\n 01 X.\n"));
        assert!(!is_free_format(
            ">>SOURCE FORMAT FIXED\n       PROGRAM-ID. P.\n"
        ));
        assert!(!is_free_format("000100 PROGRAM-ID. P.\n"));
    }

    #[test]
    fn length_param_by_name_then_position() {
        let by_name = vec![
            param("BUF", CobolParamKind::Bytes { len: None }),
            param("STATUS-X", CobolParamKind::Numeric { width: 1 }),
            param("BUF-LENGTH", CobolParamKind::Numeric { width: 4 }),
        ];
        assert_eq!(length_param_index(&by_name, 0), Some(2));
        let by_pos = vec![
            param("BUF", CobolParamKind::Bytes { len: None }),
            param("N", CobolParamKind::Numeric { width: 4 }),
        ];
        assert_eq!(length_param_index(&by_pos, 0), Some(1));
    }

    #[test]
    fn multi_param_glue_drives_all_operands() {
        let params = vec![
            param("LK-JSON", CobolParamKind::Bytes { len: None }),
            param("LK-JSON-LEN", CobolParamKind::Numeric { width: 4 }),
            param("LK-FAILURE", CobolParamKind::Numeric { width: 1 }),
        ];
        let g = multi_param_glue("JSON__PARSE", &params);
        // One extern operand per USING param; the call passes all three.
        assert!(g.contains("extern int JSON__PARSE(cob_u8_t *, cob_u8_t *, cob_u8_t *);"));
        assert!(g.contains(
            "int gf_rc = JSON__PARSE((cob_u8_t *)gf_b0, (cob_u8_t *)gf_b1, (cob_u8_t *)gf_b2);"
        ));
        // Primary ANY-LENGTH buffer filled from the input; length operand set.
        assert!(g.contains("gf_primary_len = _n;"));
        assert!(g.contains("gf_b1[4-1-_k]"));
        // in-target guard so the end-of-run leak check is not a phantom crash.
        assert!(g.contains("gf_in_target = 1;"));
    }

    #[test]
    fn single_fixed_buffer_glue() {
        let params = vec![param("BUF", CobolParamKind::Bytes { len: Some(8) })];
        let g = multi_param_glue("PARSEIT", &params);
        assert!(g.contains("extern int PARSEIT(cob_u8_t *);"));
        assert!(g.contains("static unsigned char gf_b0[8];"));
        assert!(g.contains("memset(gf_b0, ' ', 8);"));
        assert!(g.contains("int gf_rc = PARSEIT((cob_u8_t *)gf_b0);"));
    }
}
