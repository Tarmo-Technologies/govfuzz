// SPDX-License-Identifier: Apache-2.0
//! aarch64-linux never had the legacy non-`*at` syscalls (unlink, open,
//! stat, ...), so libc defines no `SYS_unlink` there: a raw-syscall
//! fallback using a legacy constant compiles on x86_64 but breaks the
//! aarch64-unknown-linux-gnu dist target at release-build time (push CI
//! is x86_64-only and never sees it). Keep raw syscall fallbacks on
//! constants that exist on every dist architecture.

use std::path::Path;

/// Syscall numbers defined by the libc crate on both x86_64 and aarch64
/// linux. Extend this list only after checking libc's aarch64 module.
const PORTABLE_SYSCALLS: &[&str] = &[
    "SYS_close",
    "SYS_openat",
    "SYS_faccessat",
    "SYS_faccessat2",
    "SYS_readlinkat",
    "SYS_unlinkat",
    "SYS_fchmodat",
    "SYS_mkdirat",
    "SYS_memfd_create",
    // SYS_mmap is defined on both x86_64 (9) and aarch64 (222) with byte-offset
    // semantics — the generic mmap, not the 32-bit-only page-offset mmap2. Used by
    // the #443 mmap interposer's raw passthrough (avoids dlsym-bootstrap recursion).
    "SYS_mmap",
    "SYS_getpid",
    "SYS_getppid",
    "SYS_getuid",
    "SYS_getgid",
];

#[test]
fn raw_syscall_constants_exist_on_all_dist_targets() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "SYS_* constants not defined on aarch64-linux (use the *at form): {offenders:?}"
    );
}

fn visit(dir: &Path, offenders: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("shim src dir is readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            visit(&path, offenders);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("source file is readable");
            for constant in syscall_constants(&text) {
                if !PORTABLE_SYSCALLS.contains(&constant.as_str()) {
                    offenders.push(format!("{}: {constant}", path.display()));
                }
            }
        }
    }
}

fn syscall_constants(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices("SYS_") {
        let identifier: String = text[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if identifier.len() > "SYS_".len() {
            found.push(identifier);
        }
    }
    found
}
