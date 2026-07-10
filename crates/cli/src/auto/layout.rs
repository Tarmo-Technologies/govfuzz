// SPDX-License-Identifier: Apache-2.0

//! Shared work-directory layout for `govfuzz auto`.

use std::path::{Path, PathBuf};

pub(crate) const REPORTS_DIR: &str = "auto";
pub(crate) const HARNESSES_DIR: &str = "harnesses";
pub(crate) const LEGACY_AUTO_HARNESSES_DIR: &str = "auto";
pub(crate) const GENERATED_HARNESSES_DIR: &str = "generated_harnesses";

pub(crate) fn reports_dir(work_dir: &Path) -> PathBuf {
    work_dir.join(REPORTS_DIR)
}

pub(crate) fn harness_root(work_dir: &Path) -> PathBuf {
    work_dir.join(HARNESSES_DIR)
}

pub(crate) fn harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    harness_root(work_dir).join(harness_id)
}

pub(crate) fn legacy_auto_harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    work_dir.join(LEGACY_AUTO_HARNESSES_DIR).join(harness_id)
}

pub(crate) fn generated_harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    work_dir.join(GENERATED_HARNESSES_DIR).join(harness_id)
}

pub(crate) fn harness_dir_candidates(work_dir: &Path, harness_id: &str) -> Vec<PathBuf> {
    vec![
        harness_dir(work_dir, harness_id),
        legacy_auto_harness_dir(work_dir, harness_id),
        generated_harness_dir(work_dir, harness_id),
    ]
}
