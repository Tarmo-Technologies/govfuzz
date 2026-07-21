// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rerun-if-changed=src/hooks/format_hooks.c");
    println!("cargo:rerun-if-changed=src/hooks/assertion.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");

    // The runtrace shim is an LD_PRELOAD library and is only distributed on
    // Linux. cargo-dist can still compile every release package while it
    // assembles a Windows target, so keep the intentionally empty non-Linux
    // cdylib free of GNU headers and linker arguments.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set"));
    let exports = out_dir.join("format_hook_exports.map");
    std::fs::write(
        &exports,
        "{ global: printf; fprintf; dprintf; sprintf; snprintf; __assert_fail; __assert_perror_fail; };",
    )
    .expect("write format hook export map");
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
        exports.display()
    );
    cc::Build::new()
        .file("src/hooks/format_hooks.c")
        .warnings(false)
        .compile("govfuzz_format_hooks");
}
