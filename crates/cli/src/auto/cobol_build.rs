// SPDX-License-Identifier: Apache-2.0

//! COBOL harness build (M3.4) — see [`crate::auto::cobol`] for the strategy.
//!
//! Step 0 of the attempt loop for a `Lang::Cobol` candidate: translate the COBOL
//! subprogram to C with `cobc -C -debug -fec=all`, generate a `LLVMFuzzerTestOneInput`
//! glue that fills the `PIC X(N)` LINKAGE buffer from the fuzz bytes, reuse the
//! passthrough C fork-server driver + coverage/cmplog runtime, and build with
//! `libcob` linked. The result at `harnesses/<id>/main` is a normal govfuzz C
//! harness the built-in engine drives unchanged.

use crate::auto::candidate::Candidate;
use std::path::Path;
use std::process::Command;

pub enum CobolBuildResult {
    Built,
    /// Not fuzzable here (no `cobc`, no LINKAGE buffer) — skip cleanly.
    Skip(String),
    /// A genuine build failure.
    Failed(String),
}

/// `cob-config --cflags` / `--libs`, or conservative defaults when the helper is
/// absent. libcob is LGPLv3 and links into the user's harness (like the GNAT
/// runtime), never into govfuzz.
fn cob_config(flag: &str) -> Vec<String> {
    let out = Command::new("cob-config").arg(flag).output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            let toks: Vec<String> = s.split_whitespace().map(ToOwned::to_owned).collect();
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

/// Recover the C entry symbol GnuCOBOL emitted for the program from the generated
/// C: `int   PROGID (cob_u8_t *);` (whitespace/tab-separated).
fn recover_entry_symbol(generated_c: &str) -> Option<String> {
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
        if after.starts_with("(cob_u8_t") {
            return Some(name);
        }
    }
    None
}

fn glue_source(entry: &str, buf_len: usize) -> String {
    // stdlib/string BEFORE libcob.h (it uses size_t/uint8_t without including
    // stddef/stdint itself). PIC X = space-filled, truncated past N (COBOL
    // semantics), so a shorter fuzz input never under-reads the LINKAGE buffer.
    format!(
        "/* SPDX-License-Identifier: Apache-2.0 */\n\
         /* govfuzz COBOL glue: drives {entry} from fuzzer bytes. */\n\
         #include <stdint.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #include <unistd.h>\n\
         #include <libcob.h>\n\
         #define GOVFUZZ_COB_N {buf_len}\n\
         extern int {entry}(cob_u8_t *b);\n\
         /* Interpose exit(): a libcob runtime check (EC-BOUND-*, EC-SIZE-*, zero\n\
         \x20* divide, ...) reports a COBOL-semantic defect on the fuzz input via a\n\
         \x20* nonzero exit. govfuzz classifies SIGABRT / a bare nonzero exit as an\n\
         \x20* input REJECTION, not a crash, so — ONLY while a target call is in\n\
         \x20* flight — we force a genuine crash signal (SIGSEGV, a CRASH_SIGNAL)\n\
         \x20* with the libcob + COBOL frames on the stack. A nonzero exit OUTSIDE a\n\
         \x20* target call (ASan leak check on libcob's by-design retained memory,\n\
         \x20* process teardown) is not input-triggered, so it passes through as a\n\
         \x20* clean exit — otherwise the end-of-run leak check would manufacture a\n\
         \x20* phantom crash with an empty testcase. Raw memory corruption is still\n\
         \x20* caught by ASan on the generated C independently of this. */\n\
         static volatile int govfuzz_cob_in_target = 0;\n\
         __attribute__((noreturn)) void exit(int code) {{\n\
         \x20   if (code != 0 && govfuzz_cob_in_target) {{ *(volatile int *)0 = 0; }}\n\
         \x20   _exit(0);\n\
         }}\n\
         static int govfuzz_cob_ready = 0;\n\
         int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{\n\
         \x20   if (!govfuzz_cob_ready) {{ cob_init(0, (char **)0); govfuzz_cob_ready = 1; }}\n\
         \x20   unsigned char buf[GOVFUZZ_COB_N];\n\
         \x20   memset(buf, ' ', GOVFUZZ_COB_N);\n\
         \x20   size_t n = Size < GOVFUZZ_COB_N ? Size : (size_t)GOVFUZZ_COB_N;\n\
         \x20   if (n) memcpy(buf, Data, n);\n\
         \x20   govfuzz_cob_in_target = 1;\n\
         \x20   int rc = {entry}((cob_u8_t *)buf);\n\
         \x20   govfuzz_cob_in_target = 0;\n\
         \x20   return rc;\n\
         }}\n"
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

    // Recover the fuzzable LINKAGE buffer length by re-scanning the source.
    let source = match std::fs::read_to_string(&candidate.source_path) {
        Ok(s) => s,
        Err(e) => return CobolBuildResult::Failed(format!("read COBOL source: {e}")),
    };
    let programs = crate::auto::cobol::parse_cobol(&source);
    let program = programs
        .iter()
        .find(|p| p.program_id == candidate.name)
        .or_else(|| programs.first());
    let buf_len = match program.and_then(|p| p.linkage_buf.as_ref()) {
        Some(b) => b.len,
        None => {
            return CobolBuildResult::Skip(format!(
                "{}: no fuzzable LINKAGE `PIC X(N)` buffer (no USING input surface)",
                candidate.name
            ));
        }
    };

    // Translate COBOL -> C with runtime bound checks (`-fec=all`) so semantic
    // violations (out-of-range ref-mod / subscript, SIZE overflow, zero-divide)
    // abort libcob and surface as crashes, on top of ASan on the generated C.
    let target_c = hdir.join("cobol_target.c");
    let cobc = Command::new("cobc")
        .arg("-C")
        .arg("-debug")
        .arg("-fec=all")
        .arg("-o")
        .arg(&target_c)
        .arg(&candidate.source_path)
        .output();
    match cobc {
        Ok(o) if o.status.success() && target_c.is_file() => {}
        Ok(o) => {
            return CobolBuildResult::Failed(format!(
                "cobc -C failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => return CobolBuildResult::Failed(format!("spawn cobc: {e}")),
    }

    let generated = std::fs::read_to_string(&target_c).unwrap_or_default();
    let Some(entry) = recover_entry_symbol(&generated) else {
        return CobolBuildResult::Failed(
            "could not recover the C entry symbol from cobc output".to_owned(),
        );
    };

    // Glue defining LLVMFuzzerTestOneInput.
    let glue_c = hdir.join("cobol_glue.c");
    if let Err(e) = std::fs::write(&glue_c, glue_source(&entry, buf_len)) {
        return CobolBuildResult::Failed(format!("write glue: {e}"));
    }

    // Generate the passthrough C driver (main.c) + Makefile: the target IS
    // `LLVMFuzzerTestOneInput`, and the COBOL C + glue are extra sources. cob-config
    // cflags let the driver's TU see libcob headers; libs are linked at build time.
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

    // Build: `make` in the harness dir; libcob linked via AUTO_EXTRA_LDFLAGS.
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

    #[test]
    fn recovers_tab_separated_entry_symbol() {
        let c = "static void x(void);\nint\t\tPARSEIT (cob_u8_t *);\nstatic int PARSEIT_ (const int, cob_u8_t *);\n";
        assert_eq!(recover_entry_symbol(c).as_deref(), Some("PARSEIT"));
    }

    #[test]
    fn recovers_space_separated_entry_symbol() {
        assert_eq!(
            recover_entry_symbol("int MYPROG (cob_u8_t *b_9)").as_deref(),
            Some("MYPROG")
        );
    }

    #[test]
    fn ignores_non_cobol_int_decls() {
        assert_eq!(
            recover_entry_symbol("int main(int argc, char **argv)"),
            None
        );
        assert_eq!(recover_entry_symbol("integer_thing (cob_u8_t *)"), None);
    }

    #[test]
    fn glue_embeds_entry_and_buffer_len() {
        let g = glue_source("PARSEIT", 32);
        assert!(g.contains("extern int PARSEIT(cob_u8_t *b);"));
        assert!(g.contains("#define GOVFUZZ_COB_N 32"));
        assert!(g.contains("int rc = PARSEIT((cob_u8_t *)buf);"));
        assert!(g.contains("int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)"));
        // The in-target guard so an end-of-run leak check is not a phantom crash.
        assert!(g.contains("govfuzz_cob_in_target = 1;"));
    }
}
