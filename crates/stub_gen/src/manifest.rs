// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::{BuildLoopOutcome, StubGenError, StubNeedKind};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StubManifest {
    pub generated_at: String,
    pub iterations: u32,
    pub outcome: BuildLoopOutcome,
    pub stubs: Vec<StubManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StubManifestEntry {
    pub unit_name: String,
    pub kind: StubNeedKind,
    pub path: PathBuf,
    pub triggered_by: Vec<String>,
    pub confidence_delta: f64,
}

pub fn write_manifest(path: &Path, manifest: &StubManifest) -> Result<(), StubGenError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encoded = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, format!("{encoded}\n"))?;
    Ok(())
}

pub fn read_manifest(path: &Path) -> Result<StubManifest, StubGenError> {
    let contents = std::fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(StubGenError::from)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{write_manifest, BuildLoopOutcome, StubManifest, StubManifestEntry, StubNeedKind};

    #[test]
    fn manifest_serde_round_trip() {
        let manifest = sample_manifest();

        let encoded = serde_json::to_string(&manifest).expect("manifest serializes");
        let decoded: StubManifest = serde_json::from_str(&encoded).expect("manifest deserializes");

        assert_eq!(decoded.generated_at, manifest.generated_at);
        assert_eq!(decoded.iterations, 2);
        assert_eq!(decoded.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(decoded.stubs.len(), 1);
    }

    #[test]
    fn write_manifest_creates_pretty_json_file() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let path = temp.path().join("generated_stubs/manifest.json");

        write_manifest(&path, &sample_manifest()).expect("manifest writes");

        let written = std::fs::read_to_string(path).expect("manifest is readable");
        assert!(written.contains("{\n  \"generated_at\""));
        assert!(written.ends_with('\n'));
    }

    #[test]
    fn manifest_entry_serializes_kind_as_snake_case() {
        let encoded = serde_json::to_string(&sample_manifest()).expect("manifest serializes");

        assert!(encoded.contains("package_spec"));
    }

    fn sample_manifest() -> StubManifest {
        StubManifest {
            generated_at: "2026-05-02T00:00:00Z".to_owned(),
            iterations: 2,
            outcome: BuildLoopOutcome::CleanBuild,
            stubs: vec![StubManifestEntry {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageSpec { decls: Vec::new() },
                path: PathBuf::from("generated_stubs/external_lib.ads"),
                triggered_by: vec!["file \"external_lib.ads\" not found".to_owned()],
                confidence_delta: 0.05,
            }],
        }
    }
}
