// SPDX-License-Identifier: Apache-2.0

use config::Profile;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

const DEFAULT_AUDIT_PACKAGE: &str = "govfuzz";
const ALLOWED_DEPENDENCY_LICENSES: &[&str] = &[
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Unicode-DFS-2016",
    "Unicode-3.0",
    "ISC",
    "Zlib",
    "CC0-1.0",
];
const ALLOWED_LICENSE_EXCEPTIONS: &[&str] = &["LLVM-exception"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("probe '{probe}' is not allowed for profile '{profile}'")]
    ProbeNotAllowed {
        profile: &'static str,
        probe: String,
    },
}

pub fn enforce(profile: Profile, probes: &[&str]) -> Result<(), PolicyError> {
    let allowed = profile.allowed_probes();

    for probe in probes {
        if !allowed.contains(probe) {
            return Err(PolicyError::ProbeNotAllowed {
                profile: profile.as_str(),
                probe: (*probe).to_owned(),
            });
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseAuditReport {
    pub profile: Profile,
    pub package: String,
    pub root: PathBuf,
    pub reachable_packages: usize,
    pub third_party_packages: usize,
    pub direct_third_party_dependencies: Vec<String>,
    pub findings: Vec<LicenseAuditFinding>,
}

impl LicenseAuditReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseAuditFinding {
    pub kind: LicenseAuditFindingKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseAuditFindingKind {
    DisallowedLicense,
    MissingLicense,
    UnsupportedSource,
    MissingThirdPartyDoc,
    MissingThirdPartyBoundary,
    VendoredLicenseMismatch,
}

#[derive(Debug, Error)]
pub enum LicenseAuditError {
    #[error("failed to run cargo metadata in '{}': {source}", root.display())]
    MetadataCommand {
        root: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cargo metadata failed in '{}': {stderr}", root.display())]
    MetadataFailed { root: PathBuf, stderr: String },
    #[error("failed to parse cargo metadata JSON: {0}")]
    MetadataJson(#[from] serde_json::Error),
    #[error("metadata does not contain package '{package}'")]
    MissingPackage { package: String },
    #[error("metadata does not contain a dependency resolve graph")]
    MissingResolveGraph,
    #[error("failed to read '{}': {source}", path.display())]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn audit_project(
    root: impl AsRef<Path>,
    profile: Profile,
) -> Result<LicenseAuditReport, LicenseAuditError> {
    audit_project_package(root, profile, DEFAULT_AUDIT_PACKAGE)
}

pub fn audit_project_package(
    root: impl AsRef<Path>,
    profile: Profile,
    package: &str,
) -> Result<LicenseAuditReport, LicenseAuditError> {
    let root = root.as_ref().to_path_buf();
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(&root)
        .output()
        .map_err(|source| LicenseAuditError::MetadataCommand {
            root: root.clone(),
            source,
        })?;

    if !output.status.success() {
        return Err(LicenseAuditError::MetadataFailed {
            root,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    audit_metadata_json(&root, profile, package, &output.stdout)
}

pub fn audit_metadata_json(
    root: impl AsRef<Path>,
    profile: Profile,
    package: &str,
    metadata_json: impl AsRef<[u8]>,
) -> Result<LicenseAuditReport, LicenseAuditError> {
    let root = root.as_ref().to_path_buf();
    let metadata: Value = serde_json::from_slice(metadata_json.as_ref())?;
    let packages = parse_packages(&metadata);
    let nodes = parse_nodes(&metadata)?;
    let root_id = packages
        .values()
        .find(|candidate| candidate.name == package && candidate.source.is_none())
        .map(|candidate| candidate.id.clone())
        .ok_or_else(|| LicenseAuditError::MissingPackage {
            package: package.to_owned(),
        })?;
    let reachable = reachable_non_dev_packages(&root_id, &nodes);

    let mut findings = Vec::new();
    let mut third_party_packages = 0;

    for id in &reachable {
        let Some(package) = packages.get(id) else {
            continue;
        };

        if package.source.is_some() {
            third_party_packages += 1;
            audit_package_source(package, &mut findings);
            audit_package_license(package, &mut findings);
        }
    }

    let direct_deps = direct_third_party_dependencies(&reachable, &packages, &nodes);
    audit_third_party_docs(&root, &direct_deps, &mut findings)?;
    audit_vendored_tree_sitter_ada(&root, &mut findings)?;

    Ok(LicenseAuditReport {
        profile,
        package: package.to_owned(),
        root,
        reachable_packages: reachable.len(),
        third_party_packages,
        direct_third_party_dependencies: direct_deps,
        findings,
    })
}

fn audit_package_source(package: &PackageSummary, findings: &mut Vec<LicenseAuditFinding>) {
    let Some(source) = &package.source else {
        return;
    };

    if source != "registry+https://github.com/rust-lang/crates.io-index" {
        findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::UnsupportedSource,
            message: format!(
                "{} {} comes from unsupported source '{}'",
                package.name, package.version, source
            ),
        });
    }
}

fn audit_package_license(package: &PackageSummary, findings: &mut Vec<LicenseAuditFinding>) {
    match package.license.as_deref() {
        Some(expression) if spdx_expression_is_allowed(expression) => {}
        Some(expression) => findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::DisallowedLicense,
            message: format!(
                "{} {} has disallowed license expression '{}'",
                package.name, package.version, expression
            ),
        }),
        None if package.license_file.is_some() => findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::MissingLicense,
            message: format!(
                "{} {} uses license-file without an auditable SPDX expression",
                package.name, package.version
            ),
        }),
        None => findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::MissingLicense,
            message: format!(
                "{} {} has no license metadata",
                package.name, package.version
            ),
        }),
    }
}

fn audit_third_party_docs(
    root: &Path,
    direct_deps: &[String],
    findings: &mut Vec<LicenseAuditFinding>,
) -> Result<(), LicenseAuditError> {
    let path = root.join("THIRD_PARTY.md");
    let text = read_to_string(&path)?;
    let components = third_party_components(&text);

    for dependency in direct_deps {
        if !components
            .iter()
            .any(|component| component_documents_dependency(component, dependency))
        {
            findings.push(LicenseAuditFinding {
                kind: LicenseAuditFindingKind::MissingThirdPartyDoc,
                message: format!(
                    "THIRD_PARTY.md does not document direct dependency '{}'",
                    dependency
                ),
            });
        }
    }

    for required in [
        "GCC Runtime Library Exception",
        "does not link GPL Ada front-end libraries",
    ] {
        if !text.contains(required) {
            findings.push(LicenseAuditFinding {
                kind: LicenseAuditFindingKind::MissingThirdPartyBoundary,
                message: format!("THIRD_PARTY.md is missing GCC RLE boundary text: '{required}'"),
            });
        }
    }

    Ok(())
}

fn audit_vendored_tree_sitter_ada(
    root: &Path,
    findings: &mut Vec<LicenseAuditFinding>,
) -> Result<(), LicenseAuditError> {
    let vendored_path = root.join("vendor/tree-sitter-ada/VENDORED.md");
    let license_path = root.join("vendor/tree-sitter-ada/LICENSE");
    let vendored = read_to_string(&vendored_path)?;
    let license = fs::read(&license_path).map_err(|source| LicenseAuditError::ReadFile {
        path: license_path.clone(),
        source,
    })?;

    let spdx = metadata_value(&vendored, "license-spdx");
    if spdx.as_deref() != Some("MIT") {
        findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::VendoredLicenseMismatch,
            message: "vendor/tree-sitter-ada/VENDORED.md must declare license-spdx: MIT".to_owned(),
        });
    }

    let expected_checksum = metadata_value(&vendored, "license-sha256");
    let actual_checksum = hex_sha256(&license);
    if expected_checksum.as_deref() != Some(actual_checksum.as_str()) {
        findings.push(LicenseAuditFinding {
            kind: LicenseAuditFindingKind::VendoredLicenseMismatch,
            message: format!(
                "vendor/tree-sitter-ada/LICENSE checksum is {actual_checksum}, expected {}",
                expected_checksum.unwrap_or_else(|| "<missing>".to_owned())
            ),
        });
    }

    Ok(())
}

fn read_to_string(path: &Path) -> Result<String, LicenseAuditError> {
    fs::read_to_string(path).map_err(|source| LicenseAuditError::ReadFile {
        path: path.to_path_buf(),
        source,
    })
}

fn metadata_value(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn third_party_components(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with('|') {
                return None;
            }
            let mut cells = line.split('|').skip(1);
            let component = cells.next()?.trim();
            if component == "Component" || component.chars().all(|ch| ch == '-') {
                return None;
            }
            Some(component.to_owned())
        })
        .collect()
}

fn component_documents_dependency(component: &str, dependency: &str) -> bool {
    let dependency = dependency.to_ascii_lowercase();

    component
        .to_ascii_lowercase()
        .split(['/', ','])
        .map(|part| part.split_once('(').map_or(part, |(before, _)| before))
        .map(str::trim)
        .any(|part| {
            part == dependency
                || part
                    .strip_prefix(&dependency)
                    .is_some_and(|rest| rest.starts_with(' ') || rest.starts_with('-'))
        })
}

fn direct_third_party_dependencies(
    reachable: &BTreeSet<String>,
    packages: &BTreeMap<String, PackageSummary>,
    nodes: &BTreeMap<String, Vec<NodeDep>>,
) -> Vec<String> {
    let mut dependencies = BTreeSet::new();

    for id in reachable {
        let Some(package) = packages.get(id) else {
            continue;
        };
        if package.source.is_some() {
            continue;
        }

        for dep in nodes.get(id).into_iter().flatten() {
            if !dep.is_non_dev() {
                continue;
            }

            let Some(dep_package) = packages.get(&dep.pkg) else {
                continue;
            };
            if dep_package.source.is_some() {
                dependencies.insert(dep_package.name.clone());
            }
        }
    }

    dependencies.into_iter().collect()
}

fn reachable_non_dev_packages(
    root_id: &str,
    nodes: &BTreeMap<String, Vec<NodeDep>>,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([root_id.to_owned()]);

    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }

        for dep in nodes.get(&id).into_iter().flatten() {
            if dep.is_non_dev() && !seen.contains(&dep.pkg) {
                queue.push_back(dep.pkg.clone());
            }
        }
    }

    seen
}

fn parse_packages(metadata: &Value) -> BTreeMap<String, PackageSummary> {
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| {
            let id = package.get("id")?.as_str()?.to_owned();
            Some((
                id.clone(),
                PackageSummary {
                    id,
                    name: package.get("name")?.as_str()?.to_owned(),
                    version: package.get("version")?.as_str()?.to_owned(),
                    source: package
                        .get("source")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    license: package
                        .get("license")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    license_file: package
                        .get("license_file")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                },
            ))
        })
        .collect()
}

fn parse_nodes(metadata: &Value) -> Result<BTreeMap<String, Vec<NodeDep>>, LicenseAuditError> {
    let nodes = metadata
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(Value::as_array)
        .ok_or(LicenseAuditError::MissingResolveGraph)?;

    Ok(nodes
        .iter()
        .filter_map(|node| {
            let id = node.get("id")?.as_str()?.to_owned();
            let deps = node
                .get("deps")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|dep| {
                    Some(NodeDep {
                        pkg: dep.get("pkg")?.as_str()?.to_owned(),
                        kinds: dep
                            .get("dep_kinds")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .map(|kind| {
                                kind.get("kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or("normal")
                                    .to_owned()
                            })
                            .collect(),
                    })
                })
                .collect();
            Some((id, deps))
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageSummary {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    license: Option<String>,
    license_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeDep {
    pkg: String,
    kinds: Vec<String>,
}

impl NodeDep {
    fn is_non_dev(&self) -> bool {
        self.kinds.iter().any(|kind| kind != "dev")
    }
}

fn spdx_expression_is_allowed(expression: &str) -> bool {
    let tokens = tokenize_spdx_expression(expression);
    if tokens.is_empty() {
        return false;
    }

    let mut parser = SpdxParser {
        tokens,
        position: 0,
    };
    let allowed = parser.parse_or();
    allowed && parser.position == parser.tokens.len()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SpdxToken {
    License(String),
    And,
    Or,
    With,
    LParen,
    RParen,
}

fn tokenize_spdx_expression(expression: &str) -> Vec<SpdxToken> {
    let normalized = expression.replace('/', " OR ");
    let mut tokens = Vec::new();
    let mut chars = normalized.chars().peekable();

    while let Some(ch) = chars.peek().copied() {
        match ch {
            ch if ch.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(SpdxToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(SpdxToken::RParen);
            }
            _ => {
                let mut token = String::new();
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || next == '(' || next == ')' {
                        break;
                    }
                    token.push(next);
                    chars.next();
                }

                match token.as_str() {
                    "AND" => tokens.push(SpdxToken::And),
                    "OR" => tokens.push(SpdxToken::Or),
                    "WITH" => tokens.push(SpdxToken::With),
                    _ => tokens.push(SpdxToken::License(token)),
                }
            }
        }
    }

    tokens
}

struct SpdxParser {
    tokens: Vec<SpdxToken>,
    position: usize,
}

impl SpdxParser {
    fn parse_or(&mut self) -> bool {
        let mut value = self.parse_and();

        while self.consume(&SpdxToken::Or) {
            value = self.parse_and() || value;
        }

        value
    }

    fn parse_and(&mut self) -> bool {
        let mut value = self.parse_with();

        while self.consume(&SpdxToken::And) {
            value = self.parse_with() && value;
        }

        value
    }

    fn parse_with(&mut self) -> bool {
        let value = self.parse_primary();

        if self.consume(&SpdxToken::With) {
            let exception_allowed = match self.tokens.get(self.position) {
                Some(SpdxToken::License(exception)) => {
                    self.position += 1;
                    ALLOWED_LICENSE_EXCEPTIONS.contains(&exception.as_str())
                }
                _ => false,
            };
            value && exception_allowed
        } else {
            value
        }
    }

    fn parse_primary(&mut self) -> bool {
        match self.tokens.get(self.position) {
            Some(SpdxToken::License(license)) => {
                self.position += 1;
                ALLOWED_DEPENDENCY_LICENSES.contains(&license.as_str())
            }
            Some(SpdxToken::LParen) => {
                self.position += 1;
                let value = self.parse_or();
                let closed = self.consume(&SpdxToken::RParen);
                value && closed
            }
            _ => false,
        }
    }

    fn consume(&mut self, token: &SpdxToken) -> bool {
        if self.tokens.get(self.position) == Some(token) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        audit_metadata_json, component_documents_dependency, enforce, spdx_expression_is_allowed,
        third_party_components, LicenseAuditFindingKind, PolicyError,
    };
    use config::Profile;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn strict_permissive_rejects_gnat_actions_probe() {
        assert_eq!(
            enforce(Profile::StrictPermissive, &["gnat_actions"]),
            Err(PolicyError::ProbeNotAllowed {
                profile: "strict-permissive",
                probe: "gnat_actions".to_owned()
            })
        );
    }

    #[test]
    fn external_tools_allows_gnat_actions_probe() {
        assert_eq!(enforce(Profile::ExternalTools, &["gnat_actions"]), Ok(()));
    }

    #[test]
    fn spdx_expression_accepts_current_permissive_forms() {
        for expression in [
            "MIT OR Apache-2.0",
            "MIT/Apache-2.0",
            "Unlicense/MIT",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "(MIT AND GPL-3.0-only) OR Apache-2.0",
            "BSD-2-Clause OR Apache-2.0 OR MIT",
        ] {
            assert!(
                spdx_expression_is_allowed(expression),
                "{expression} should be allowed"
            );
        }
    }

    #[test]
    fn spdx_expression_rejects_copyleft_only_forms() {
        for expression in ["GPL-3.0-only", "LGPL-2.1-or-later", "MIT AND GPL-3.0-only"] {
            assert!(
                !spdx_expression_is_allowed(expression),
                "{expression} should be rejected"
            );
        }
    }

    #[test]
    fn third_party_component_matching_is_token_aware() {
        assert!(component_documents_dependency(
            "serde / serde_json (Rust)",
            "serde_json"
        ));
        assert!(component_documents_dependency("tree-sitter", "tree-sitter"));
        assert!(!component_documents_dependency("FSF GNAT/GCC", "cc"));
    }

    #[test]
    fn third_party_components_extracts_first_table_column() {
        let components = third_party_components(
            "| Component | Purpose |\n|---|---|\n| serde / serde_json (Rust) | Serialization |\n",
        );

        assert_eq!(components, vec!["serde / serde_json (Rust)"]);
    }

    #[test]
    fn audit_metadata_reports_missing_third_party_matrix_entries() {
        let root = temp_dir("missing-third-party");
        write_license_vendor(&root);
        fs::write(
            root.join("THIRD_PARTY.md"),
            "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n| Component | Purpose |\n|---|---|\n| anyhow | Errors |\n\nGCC Runtime Library Exception\n\ndoes not link GPL Ada front-end libraries\n",
        )
        .unwrap();

        let report = audit_metadata_json(
            &root,
            Profile::StrictPermissive,
            "govfuzz",
            fixture_metadata(),
        )
        .unwrap();

        assert!(report.findings.iter().any(|finding| {
            finding.kind == LicenseAuditFindingKind::MissingThirdPartyDoc
                && finding.message.contains("cc")
        }));
    }

    fn fixture_metadata() -> &'static [u8] {
        br#"{
          "packages": [
            {
              "id": "path+file:///repo/crates/cli#govfuzz@0.1.0",
              "name": "govfuzz",
              "version": "0.1.0",
              "source": null,
              "license": "Apache-2.0",
              "license_file": null
            },
            {
              "id": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.0",
              "name": "anyhow",
              "version": "1.0.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index",
              "license": "MIT OR Apache-2.0",
              "license_file": null
            },
            {
              "id": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
              "name": "cc",
              "version": "1.0.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index",
              "license": "MIT OR Apache-2.0",
              "license_file": null
            }
          ],
          "resolve": {
            "nodes": [
              {
                "id": "path+file:///repo/crates/cli#govfuzz@0.1.0",
                "deps": [
                  {
                    "name": "anyhow",
                    "pkg": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.0",
                    "dep_kinds": [{"kind": null, "target": null}]
                  },
                  {
                    "name": "cc",
                    "pkg": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
                    "dep_kinds": [{"kind": "build", "target": null}]
                  }
                ]
              },
              {
                "id": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.0",
                "deps": []
              },
              {
                "id": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
                "deps": []
              }
            ]
          }
        }"#
    }

    fn write_license_vendor(root: &std::path::Path) {
        let vendor = root.join("vendor/tree-sitter-ada");
        fs::create_dir_all(&vendor).unwrap();
        fs::write(vendor.join("LICENSE"), b"MIT license fixture\n").unwrap();
        fs::write(
            vendor.join("VENDORED.md"),
            format!(
                "license-spdx: MIT\nlicense-sha256: {}\n",
                super::hex_sha256(b"MIT license fixture\n")
            ),
        )
        .unwrap();
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-license-policy-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
