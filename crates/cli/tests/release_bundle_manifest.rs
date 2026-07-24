// SPDX-License-Identifier: Apache-2.0

//! #106: the full distribution archive is the standard release shape and must
//! always ship install.sh, INSTALL.md, LICENSE, README.md, and RELEASE_NOTES.md
//! at its root. These tests guard the packaging manifest AND the release-workflow
//! validation gate against a regression that silently drops a mandatory file — a
//! failure no ordinary build would catch. They are hermetic (read repo files
//! only, no network, no release build).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/cli
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above crates/cli")
        .to_path_buf()
}

#[test]
fn packaging_script_stages_every_mandatory_root_file() {
    let root = repo_root();
    let script = std::fs::read_to_string(root.join("scripts/package-offline-dist.sh"))
        .expect("read scripts/package-offline-dist.sh");
    // install.sh is staged from install-dist.sh; the rest are copied by name.
    assert!(
        script.contains("\"$STAGE_ROOT/install.sh\""),
        "packaging must stage install.sh at the archive root"
    );
    for file in ["INSTALL.md", "LICENSE", "README.md", "RELEASE_NOTES.md"] {
        assert!(
            script.contains(&format!("\"$STAGE_ROOT/{file}\"")),
            "packaging must stage {file} at the archive root"
        );
        // The packaging `cp` source must actually exist in the repo.
        assert!(
            root.join(file).is_file(),
            "{file} must exist at the repo root (the packaging cp source)"
        );
    }
}

#[test]
fn release_workflow_gates_on_every_mandatory_root_file() {
    let root = repo_root();
    let workflow = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read .github/workflows/release.yml");
    // The bundle-validation step must FAIL the release (`set -euo pipefail` + a
    // failing `test`) when a required file is missing from the extracted archive.
    assert!(
        workflow.contains(r#"test -x "$bundle_root/install.sh""#),
        "release must validate install.sh in the archive"
    );
    for file in ["INSTALL.md", "LICENSE", "README.md", "RELEASE_NOTES.md"] {
        assert!(
            workflow.contains(file),
            "release must validate {file} in the archive"
        );
    }
    // And it must exercise the offline installer from the extracted archive.
    assert!(
        workflow.contains("install.sh") && workflow.contains("--non-interactive"),
        "release must run the offline install.sh from the extracted archive"
    );
}
