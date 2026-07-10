// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn docs_site_workflow_builds_and_deploys_github_pages() {
    let workflow = read(repo_root().join(".github/workflows/docs-site.yml"));

    assert!(workflow.contains("name: Docs Site"));
    assert!(workflow.contains("pull_request:"));
    assert!(workflow.contains("push:"));
    assert!(workflow.contains("branches: [main]"));
    assert!(workflow.contains("python3 scripts/docs/build-site.py --out target/docs-site"));
    // Actions are pinned to a commit SHA (supply-chain hardening); Dependabot
    // bumps the pin + version comment, so assert the action is referenced rather
    // than a specific tag/SHA.
    assert!(workflow.contains("uses: actions/configure-pages@"));
    assert!(workflow.contains("uses: actions/upload-pages-artifact@"));
    assert!(workflow.contains("uses: actions/deploy-pages@"));
    assert!(workflow.contains("vars.GOVFUZZ_PAGES_ENABLED == 'true'"));
    assert!(workflow.contains("contents: read"));
    assert!(workflow.contains("pages: write"));
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains(
        "github.event_name == 'push' && github.ref == 'refs/heads/main' && vars.GOVFUZZ_PAGES_ENABLED == 'true'"
    ));
}

#[test]
fn docs_site_sources_cover_m19_topics() {
    let root = repo_root();
    let required_pages = [
        ("index", "docs.govfuzz.dev"),
        ("architecture", "hosting architecture"),
        ("instrumentation", "instrumentation"),
        ("fake-corba", "fake-CORBA"),
        ("licensing", "license audit"),
        ("cli", "govfuzz CLI"),
        ("c-cpp", "C and C++ Fuzzing"),
        ("cross-compilation", "cross-compilation"),
        ("daemon", "JSON-RPC daemon"),
    ];

    for (slug, required_text) in required_pages {
        let source = read(root.join(format!("docs/site/{slug}.md")));
        assert!(
            source.contains(required_text),
            "docs/site/{slug}.md should mention {required_text:?}"
        );
    }
}

#[test]
fn primary_product_surfaces_do_not_use_ada_first_positioning() {
    let root = repo_root();
    let checked = [
        "README.md",
        "ROADMAP.md",
        "docs/fuzzing-landscape-2026-05-20.md",
        "docs/site/index.md",
        "docs/site/architecture.md",
        "docs/site/auto.md",
        "docs/site/c-cpp.md",
        "crates/cli/src/lib.rs",
    ];

    for rel in checked {
        let source = read(root.join(rel));
        assert!(
            !source.contains("Ada-first") && !source.contains("Ada first."),
            "{rel} should position GovFuzz as a government legacy Ada/C/C++ fuzzer, not Ada-first"
        );
    }
}

#[test]
fn docs_site_generator_emits_html_pages_and_metadata() {
    let root = repo_root();
    let output_dir = root.join("target/m19-docs-site-test");
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir).unwrap_or_else(|error| {
            panic!(
                "failed to remove old docs output {}: {error}",
                output_dir.display()
            );
        });
    }

    let status = Command::new("python3")
        .arg("scripts/docs/build-site.py")
        .arg("--out")
        .arg(&output_dir)
        .current_dir(&root)
        .status()
        .expect("failed to run docs site generator");

    assert!(status.success(), "docs site generator failed: {status}");

    let index = read(output_dir.join("index.html"));
    assert!(index.contains("GovFuzz Documentation"));
    assert!(index.contains("href=\"architecture/\""));
    assert!(index.contains("href=\"instrumentation/\""));
    assert!(index.contains("href=\"fake-corba/\""));
    assert!(index.contains("href=\"licensing/\""));
    assert!(index.contains("href=\"cli/\""));
    assert!(index.contains("href=\"c-cpp/\""));
    assert!(index.contains("href=\"cross-compilation/\""));
    assert!(index.contains("href=\"daemon/\""));

    let cross_compilation = read(output_dir.join("cross-compilation/index.html"));
    assert!(cross_compilation.contains("&lt;prefix&gt;-gnat"));

    let c_cpp = read(output_dir.join("c-cpp/index.html"));
    assert!(c_cpp.contains("Supported C++ Parameter Shapes"));

    assert!(output_dir.join("CNAME").is_file());
    assert_eq!(read(output_dir.join("CNAME")).trim(), "docs.govfuzz.dev");
    assert!(read(output_dir.join("sitemap.xml")).contains("docs.govfuzz.dev"));
    assert!(read(output_dir.join("robots.txt")).contains("Sitemap:"));
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
