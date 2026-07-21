// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn release_workflow_disables_unavailable_github_attestations() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let cargo_toml = read(root.join("Cargo.toml"));

    assert!(cargo_toml.contains("github-attestations = false"));
    assert!(!cargo_toml.contains("github-attestations-phase"));
    assert!(!workflow.contains("\"attestations\": \"write\""));
    assert!(!workflow.contains("\"id-token\": \"write\""));
    assert!(!workflow.contains("uses: actions/attest-build-provenance@v3"));
}

#[test]
fn release_packaging_docs_explain_supported_integrity_verification() {
    let docs = read(repo_root().join("docs/release-packaging.md"));

    assert!(docs.contains("sha256sum -c <asset>.sha256"));
    assert!(docs.contains("signed content pack"));
    assert!(docs.contains("GitHub Artifact Attestations are disabled"));
    assert!(docs.contains("github-attestations = true"));
}

#[test]
fn release_packaging_includes_linux_runtrace_shim() {
    let root = repo_root();
    let shim_manifest = read(root.join("crates/govfuzz_runtrace_shim/Cargo.toml"));
    let docs = read(root.join("docs/release-packaging.md"));

    assert!(shim_manifest.contains("[package.metadata.dist]"));
    assert!(shim_manifest.contains("dist = true"));
    assert!(shim_manifest.contains("package-libraries = [\"cdylib\"]"));
    assert!(shim_manifest.contains("install-libraries = [\"cdylib\"]"));
    assert!(docs.contains("govfuzz_runtrace_shim"));
    assert!(docs.contains("virtualisation"));
}

#[test]
fn release_targets_match_supported_cross_platform_binary_matrix() {
    let root = repo_root();
    let cargo_toml = read(root.join("Cargo.toml"));
    let docs = read(root.join("docs/release-packaging.md"));

    assert!(
        cargo_toml.contains("targets = [\"x86_64-unknown-linux-gnu\", \"x86_64-pc-windows-msvc\"]")
    );
    assert!(docs.contains("The generated release workflow builds these target triples"));
    assert!(docs.contains("`x86_64-unknown-linux-gnu`"));
    assert!(docs.contains("`x86_64-pc-windows-msvc`"));
    assert!(docs.contains("preload shims remain Linux-only assets"));
}

#[test]
fn release_cli_is_self_contained_for_every_harness_runtime() {
    let root = repo_root();
    let cli_manifest = read(root.join("crates/cli/Cargo.toml"));
    let workflow = read(root.join(".github/workflows/release.yml"));

    for runtime in [
        "ada_runtime",
        "c_runtime",
        "csharp_runtime",
        "java_runtime",
        "js_runtime",
        "lua_runtime",
        "perl_runtime",
        "php_runtime",
        "python_runtime",
        "ruby_runtime",
        "rust_runtime",
    ] {
        assert!(
            cli_manifest.contains(runtime),
            "CLI dist metadata omitted {runtime}"
        );
        assert!(
            workflow.contains(runtime),
            "release archive gate omitted {runtime}"
        );
    }

    assert!(workflow.contains("Validate packaged harness runtimes (Linux)"));
    assert!(workflow.contains("Validate packaged harness runtimes (Windows)"));
    assert!(workflow.contains("archive=target/distrib/govfuzz-x86_64-unknown-linux-gnu.tar.xz"));
    assert!(
        workflow.contains("$archive = Get-Item target/distrib/govfuzz-x86_64-pc-windows-msvc.zip")
    );
    assert!(!workflow.contains("-name \"govfuzz-*.tar.xz\""));
    assert!(!workflow.contains("-Filter \"govfuzz-*.zip\""));
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
