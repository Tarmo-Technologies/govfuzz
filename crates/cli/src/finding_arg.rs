// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

pub fn resolve_finding_arg(positional: Option<PathBuf>, named: Option<PathBuf>) -> PathBuf {
    let raw = named
        .or(positional)
        .expect("clap enforces a finding argument");
    if raw.is_dir() || raw.is_absolute() {
        return raw;
    }

    let looks_like_id = raw.components().count() == 1;
    let under_findings = PathBuf::from("findings").join(&raw);
    if looks_like_id && under_findings.is_dir() {
        under_findings
    } else {
        raw
    }
}
