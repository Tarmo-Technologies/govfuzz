// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn docs_cli_flow_uses_current_command_flags() {
    let docs = read(repo_root().join("docs/site/cli.md"));

    assert!(
        docs.contains("govfuzz instrument path/to/pkg.adb --output govfuzz_work/src_instrumented")
    );
    assert!(docs.contains("govfuzz generate-harness govfuzz_work/src_instrumented/pkg.adb --target Pkg.Parse --output govfuzz_work/generated_harnesses"));
    assert!(docs.contains("govfuzz report --findings findings --out reports"));
    assert!(!docs.contains("--output govfuzz_work/harnesses"));
    assert!(!docs.contains("generate-harness path/to/project --target Pkg.Parse --out"));
    assert!(!docs.contains("instrument govfuzz_work --out"));
    assert!(!docs.contains("report findings --format markdown"));
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
