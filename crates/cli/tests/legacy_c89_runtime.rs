// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 1a: the bundled C decode runtime must compile strict-C89 clean, so a
//! legacy C target recompiled with a modern clang in `-std=c89` mode (the hybrid
//! build strategy) builds without the runtime itself tripping the dialect. The
//! historical contradiction — `govfuzz_decode.h` advertised C89 yet used a
//! runtime-value compound initializer (a C99 extension) — is what this guards.
//!
//! Gated on `clang`: skips cleanly when the toolchain is absent, like the
//! GNAT-less Ada tests.

use std::path::PathBuf;
use std::process::Command;

fn c_runtime_dir() -> PathBuf {
    // crates/cli -> repo root -> c_runtime
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root above crates/cli")
        .join("c_runtime")
}

fn have_clang() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn decode_runtime_compiles_strict_c89() {
    if !have_clang() {
        eprintln!("clang absent; skipping strict-C89 runtime check");
        return;
    }
    let rt = c_runtime_dir();
    let header = rt.join("govfuzz_decode.h");
    assert!(
        header.is_file(),
        "c_runtime/govfuzz_decode.h must exist: {}",
        header.display()
    );

    let dir = std::env::temp_dir().join(format!("gf-c89-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tu = dir.join("c89_tu.c");
    // Exercise the decode API a real harness uses, including the cursor open that
    // used to be a non-constant compound initializer.
    std::fs::write(
        &tu,
        "#include \"govfuzz_decode.h\"\n\
         int main(void) {\n\
         \x20   unsigned char b[8];\n\
         \x20   gf_cursor c = gf_open(b, sizeof b);\n\
         \x20   (void) gf_i32(&c);\n\
         \x20   (void) gf_i64(&c);\n\
         \x20   (void) gf_bounded_i32(&c, 0, 3);\n\
         \x20   { char *s = gf_c_string(&c, 4); free(s); }\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();

    let out = Command::new("clang")
        .args(["-std=c89", "-ansi", "-pedantic-errors"])
        .arg(format!("-I{}", rt.display()))
        .arg("-c")
        .arg(&tu)
        .arg("-o")
        .arg(dir.join("c89_tu.o"))
        .output()
        .expect("run clang");
    assert!(
        out.status.success(),
        "govfuzz_decode.h must compile strict-C89 (-std=c89 -ansi -pedantic-errors):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
