// SPDX-License-Identifier: Apache-2.0

//! Build-time Java classpath cataloger — the deep build-time SCA the SBOM goal
//! calls for: catalog the JARs the build ACTUALLY links, not just what a
//! `pom.xml`/`build.gradle` *declares*.
//!
//! Syft/Trivy stop at `Declared` (parsed from a manifest). This walks the project
//! tree for `*.jar` files — the real classpath, including projects that use plain
//! `javac`/`ant` with bundled `lib/*.jar` and NO maven/gradle at all — and emits
//! each as `EvidenceKind::Linked` (a higher evidence rung: the artifact is on the
//! build path, so it is genuinely linked into the program). When a `pom.xml` is
//! also present, `merge_by_identity` collapses the declared + linked views into
//! one component whose usage climbs to `linked`.
//!
//! # Coordinates + identity
//! Two tiers, best-effort:
//!   1. **Exact** — `META-INF/maven/<group>/<artifact>/pom.properties` inside the
//!      JAR gives the authoritative `groupId:artifactId:version`, so a full
//!      `pkg:maven/<group>/<artifact>@<version>` PURL is emitted. Read with the
//!      `unzip` tool when available (offline, local); absence degrades gracefully.
//!   2. **Filename** — else parse `<artifactId>-<version>[-classifier].jar`
//!      (version starts the first digit `-`-segment). No groupId -> no PURL
//!      namespace; identity falls to `(ecosystem, name, version)`.
//!
//! Every JAR also gets its **SHA-256** (a `HashRef` + the `sha256` field) so a
//! downstream vuln DB can match by content hash. `-sources`/`-javadoc` JARs are
//! skipped (not dependencies).

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

pub struct JavaClasspathCataloger;

impl Cataloger for JavaClasspathCataloger {
    fn ecosystem(&self) -> &str {
        "maven"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_ending_with(".jar").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx.files_ending_with(".jar") {
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(from_name) = parse_jar_name(file_name) else {
                continue; // -sources / -javadoc
            };
            let rel = relative_path(&ctx.root, path);

            // SHA-256 of the JAR bytes (best-effort; absent on an unreadable path).
            let sha256 = sha256_file(path);
            // Exact coordinates from the embedded pom.properties, if readable.
            let exact = read_pom_properties(path);

            let (name, version, purl) = match &exact {
                Some(coords) => {
                    let purl = coords
                        .version
                        .as_ref()
                        .map(|v| purl::maven(&coords.group, &coords.artifact, v));
                    (coords.artifact.clone(), coords.version.clone(), purl)
                }
                // No groupId from a file name -> no PURL namespace.
                None => (from_name.artifact, from_name.version, None),
            };

            let hashes = sha256
                .as_ref()
                .map(|hex| {
                    vec![HashRef {
                        alg: "SHA-256".to_owned(),
                        value_hex: hex.clone(),
                    }]
                })
                .unwrap_or_default();

            out.push(Component {
                component_ref: String::new(),
                name,
                version,
                ecosystem: "maven".to_owned(),
                group: None,
                component_type: "library".to_owned(),
                supplier: None,
                license: None,
                purl,
                cpe: None,
                sha256,
                hashes,
                identity_confidence: if exact.is_some() { "high" } else { "medium" }.to_owned(),
                matching_method: if exact.is_some() {
                    "java_classpath_pom_properties"
                } else {
                    "java_classpath_jar_name"
                }
                .to_owned(),
                // Linked: the JAR is on the build classpath — actually linked into
                // the program, a higher evidence rung than a manifest's Declared.
                evidence: vec![Evidence::new(
                    EvidenceKind::Linked,
                    format!("classpath-jar:{rel}"),
                )],
                runtime_harnesses: Vec::new(),
            });
        }
        Ok(out)
    }
}

struct ParsedJar {
    artifact: String,
    version: Option<String>,
}

/// Parse `<artifactId>-<version>[-classifier].jar` into `(artifact, version)`.
fn parse_jar_name(file_name: &str) -> Option<ParsedJar> {
    let stem = file_name.strip_suffix(".jar")?;
    if stem.ends_with("-sources") || stem.ends_with("-javadoc") || stem.ends_with("-tests") {
        return None;
    }
    let segments: Vec<&str> = stem.split('-').collect();
    let is_version_seg = |s: &&str| s.chars().next().is_some_and(|c| c.is_ascii_digit());
    let version_start = segments.iter().position(is_version_seg);
    match version_start {
        None => Some(ParsedJar {
            artifact: stem.to_owned(),
            version: None,
        }),
        // The first segment itself is digit-leading (e.g. `3d-party-1.0`): segment 0
        // is part of the ARTIFACT name, not the version. The version is the next
        // digit-leading segment, if any. (RC review fix.)
        Some(0) => {
            let later = segments.iter().enumerate().skip(1).find_map(|(i, s)| {
                if is_version_seg(s) {
                    Some(i)
                } else {
                    None
                }
            });
            match later {
                Some(idx) => Some(ParsedJar {
                    artifact: segments[..idx].join("-"),
                    version: Some(segments[idx..].join("-")),
                }),
                None => Some(ParsedJar {
                    artifact: stem.to_owned(),
                    version: None,
                }),
            }
        }
        Some(idx) => Some(ParsedJar {
            artifact: segments[..idx].join("-"),
            version: Some(segments[idx..].join("-")),
        }),
    }
}

struct PomCoords {
    group: String,
    artifact: String,
    version: Option<String>,
}

/// Read `META-INF/maven/<g>/<a>/pom.properties` out of a JAR via the `unzip` tool
/// (offline, local). `None` when unzip is absent, the entry is missing, or the
/// path is unreadable — the caller then falls back to file-name coordinates.
fn read_pom_properties(jar: &Path) -> Option<PomCoords> {
    if !jar.is_file() {
        return None;
    }
    // List entries and find a pom.properties under META-INF/maven/.
    let listing = Command::new("unzip").arg("-Z1").arg(jar).output().ok()?;
    if !listing.status.success() {
        return None;
    }
    let entries = String::from_utf8_lossy(&listing.stdout);
    let poms: Vec<&str> = entries
        .lines()
        .map(str::trim)
        .filter(|t| t.starts_with("META-INF/maven/") && t.ends_with("pom.properties"))
        .collect();
    // Exactly ONE pom.properties => authoritative coords. A shaded/uber JAR carries
    // MANY (one per bundled dependency); picking an arbitrary one would mislabel the
    // jar (e.g. `myapp-shaded.jar` -> `org.slf4j:slf4j-api`) with false-high
    // confidence — so fall back to the file-name coords instead. (RC review fix.)
    if poms.len() != 1 {
        return None;
    }
    let content = Command::new("unzip")
        .arg("-p")
        .arg(jar)
        .arg(poms[0])
        .output()
        .ok()?;
    if !content.status.success() {
        return None;
    }
    parse_pom_properties(&String::from_utf8_lossy(&content.stdout))
}

/// Parse a Maven `pom.properties` body (`groupId=…`, `artifactId=…`, `version=…`).
fn parse_pom_properties(text: &str) -> Option<PomCoords> {
    let mut group = None;
    let mut artifact = None;
    let mut version = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("groupId=") {
            group = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("artifactId=") {
            artifact = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("version=") {
            let v = v.trim();
            if !v.is_empty() {
                version = Some(v.to_owned());
            }
        }
    }
    Some(PomCoords {
        group: group?,
        artifact: artifact?,
        version,
    })
}

/// Hex SHA-256 of a file, or `None` if unreadable.
fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Some(hex)
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(files: &[&str]) -> CatalogContext {
        CatalogContext::new(
            std::path::PathBuf::from("/proj"),
            files.iter().map(std::path::PathBuf::from).collect(),
        )
    }

    #[test]
    fn parses_standard_maven_jar_name() {
        let p = parse_jar_name("commons-codec-1.16.0.jar").unwrap();
        assert_eq!(p.artifact, "commons-codec");
        assert_eq!(p.version.as_deref(), Some("1.16.0"));
    }

    #[test]
    fn parses_classifier_into_version() {
        let p = parse_jar_name("guava-31.1-jre.jar").unwrap();
        assert_eq!(p.artifact, "guava");
        assert_eq!(p.version.as_deref(), Some("31.1-jre"));
    }

    #[test]
    fn digit_leading_artifact_keeps_its_version() {
        // RC fix: the first segment being digit-leading is part of the artifact;
        // the version is the next digit-leading segment.
        let p = parse_jar_name("3d-party-1.0.jar").unwrap();
        assert_eq!(p.artifact, "3d-party");
        assert_eq!(p.version.as_deref(), Some("1.0"));
        // Common real names still parse correctly.
        let log4j = parse_jar_name("log4j-core-2.17.1.jar").unwrap();
        assert_eq!(log4j.artifact, "log4j-core");
        assert_eq!(log4j.version.as_deref(), Some("2.17.1"));
    }

    #[test]
    fn sources_and_javadoc_jars_are_skipped() {
        assert!(parse_jar_name("commons-codec-1.16.0-sources.jar").is_none());
        assert!(parse_jar_name("guava-31.1-javadoc.jar").is_none());
    }

    #[test]
    fn parses_pom_properties_into_exact_coords() {
        let body = "#Generated by Maven\n\
                    groupId=org.apache.commons\n\
                    artifactId=commons-codec\n\
                    version=1.16.0\n";
        let c = parse_pom_properties(body).unwrap();
        assert_eq!(c.group, "org.apache.commons");
        assert_eq!(c.artifact, "commons-codec");
        assert_eq!(c.version.as_deref(), Some("1.16.0"));
    }

    #[test]
    fn catalogs_filename_jar_as_linked_when_not_readable() {
        // String paths don't exist on disk -> no SHA-256, no unzip -> filename tier.
        let c = JavaClasspathCataloger;
        let context = ctx(&["lib/commons-codec-1.16.0.jar", "src/Main.java"]);
        assert!(c.detect(&context));
        let comps = c.catalog(&context).unwrap();
        assert_eq!(comps.len(), 1);
        let comp = &comps[0];
        assert_eq!(comp.name, "commons-codec");
        assert_eq!(comp.version.as_deref(), Some("1.16.0"));
        assert_eq!(comp.evidence[0].kind, EvidenceKind::Linked);
        assert_eq!(comp.matching_method, "java_classpath_jar_name");
        assert_eq!(comp.usage(), "linked");
    }

    #[test]
    fn computes_sha256_and_exact_coords_for_a_real_jar() {
        // Build a real JAR with an embedded pom.properties using `zip`/`jar` if
        // available; otherwise self-skip (CI without zip tooling).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pom_dir = root.join("META-INF/maven/org.example/widget");
        std::fs::create_dir_all(&pom_dir).unwrap();
        std::fs::write(
            pom_dir.join("pom.properties"),
            "groupId=org.example\nartifactId=widget\nversion=2.5.0\n",
        )
        .unwrap();
        let jar = root.join("widget-2.5.0.jar");
        let zipped = std::process::Command::new("zip")
            .arg("-r")
            .arg(&jar)
            .arg("META-INF")
            .current_dir(root)
            .output();
        let made = zipped.map(|o| o.status.success()).unwrap_or(false) && jar.is_file();
        if !made {
            eprintln!("skip: no `zip` tool to build the test jar");
            return;
        }
        let context = CatalogContext::new(root.to_path_buf(), vec![jar.clone()]);
        let comps = JavaClasspathCataloger.catalog(&context).unwrap();
        assert_eq!(comps.len(), 1);
        let comp = &comps[0];
        // Exact coordinates from pom.properties (groupId recovered -> PURL).
        assert_eq!(comp.name, "widget");
        assert_eq!(comp.version.as_deref(), Some("2.5.0"));
        assert_eq!(
            comp.purl.as_deref(),
            Some("pkg:maven/org.example/widget@2.5.0")
        );
        assert_eq!(comp.matching_method, "java_classpath_pom_properties");
        assert_eq!(comp.identity_confidence, "high");
        // SHA-256 computed.
        let sha = comp.sha256.as_ref().expect("sha256");
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(comp.hashes[0].alg, "SHA-256");
        assert_eq!(comp.hashes[0].value_hex, *sha);
    }

    #[test]
    fn shaded_jar_with_many_pom_properties_falls_back_to_filename() {
        // RC fix: a shaded/uber jar embeds MANY pom.properties (one per bundled
        // dep); the cataloger must NOT mislabel the jar with one of them — it falls
        // back to the file-name coords (the real top-level artifact).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (g, a, v) in [
            ("org.slf4j", "slf4j-api", "1.7.36"),
            ("com.google.guava", "guava", "31.1"),
        ] {
            let d = root.join(format!("META-INF/maven/{g}/{a}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("pom.properties"),
                format!("groupId={g}\nartifactId={a}\nversion={v}\n"),
            )
            .unwrap();
        }
        let jar = root.join("myapp-1.0.jar");
        let made = std::process::Command::new("zip")
            .arg("-r")
            .arg(&jar)
            .arg("META-INF")
            .current_dir(root)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            && jar.is_file();
        if !made {
            eprintln!("skip: no `zip` tool");
            return;
        }
        let context = CatalogContext::new(root.to_path_buf(), vec![jar]);
        let comps = JavaClasspathCataloger.catalog(&context).unwrap();
        assert_eq!(comps.len(), 1);
        let comp = &comps[0];
        // The jar's own name wins, NOT an arbitrary embedded dependency's coords.
        assert_eq!(comp.name, "myapp");
        assert_eq!(comp.version.as_deref(), Some("1.0"));
        assert_eq!(comp.matching_method, "java_classpath_jar_name");
        assert!(comp.purl.is_none());
        // SHA-256 still computed.
        assert_eq!(comp.sha256.as_ref().map(|s| s.len()), Some(64));
    }
}
