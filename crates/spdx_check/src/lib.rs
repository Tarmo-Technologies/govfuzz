// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

const SPDX_MARKER: &str = "SPDX-License-Identifier:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    #[serde(rename = "SPDX-License-Identifier")]
    pub spdx_license_identifier: String,
    pub version: u8,
    pub files: Vec<ManifestEntry>,
}

pub fn check(root: &Path) -> Result<()> {
    let missing = missing_spdx_files(root)?;
    if !missing.is_empty() {
        for path in &missing {
            eprintln!("missing SPDX header: {}", path.display());
        }
        bail!("{} file(s) missing SPDX headers", missing.len());
    }
    Ok(())
}

pub fn generate(root: &Path) -> Result<()> {
    let manifest = build_manifest(root)?;
    let manifest_path = root.join("SPDX").join("manifest.json");
    fs::create_dir_all(
        manifest_path
            .parent()
            .context("SPDX manifest path has no parent")?,
    )
    .with_context(|| format!("creating {}", manifest_path.display()))?;

    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, format!("{json}\n"))
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    Ok(())
}

pub fn build_manifest(root: &Path) -> Result<Manifest> {
    let mut entries = Vec::new();
    for path in auditable_files(root)? {
        let license = read_spdx_license(&path)?.with_context(|| {
            format!(
                "{} is missing an SPDX license identifier in the first 10 lines",
                path.display()
            )
        })?;
        entries.push(ManifestEntry {
            path: relative_path(root, &path)?,
            license,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(Manifest {
        spdx_license_identifier: "Apache-2.0".to_owned(),
        version: 1,
        files: entries,
    })
}

fn missing_spdx_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    for path in auditable_files(root)? {
        if read_spdx_license(&path)?.is_none() {
            missing.push(path);
        }
    }
    Ok(missing)
}

fn auditable_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_auditable_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_auditable_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if entry.file_type()?.is_dir() {
            // Generated output and ignored internal design notes are not repo
            // source. They may exist in a developer checkout but not in CI, so
            // including them would make the checked-in manifest nondeterministic.
            if matches!(
                file_name.as_ref(),
                ".git" | "target" | "govfuzz_work" | "dist"
            ) || path
                .strip_prefix(root)
                .is_ok_and(|relative| relative == Path::new("docs/superpowers"))
            {
                continue;
            }
            collect_auditable_files(root, &path, files)?;
            continue;
        }

        if should_audit_file(root, &path) {
            files.push(path);
        }
    }
    Ok(())
}

/// Root-level documents that describe our licensing posture must always carry
/// an SPDX header. `LICENSE` and `NOTICE` are deliberately excluded — by
/// convention they hold verbatim license/notice text without comment headers.
const ROOT_LICENSING_FILES: &[&str] = &["THIRD_PARTY.md"];

fn should_audit_file(root: &Path, path: &Path) -> bool {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("cargo.lock"))
    {
        return false;
    }

    if let Ok(relative) = path.strip_prefix(root) {
        if let Some(name) = relative.to_str() {
            if ROOT_LICENSING_FILES.contains(&name) {
                return true;
            }
        }

        if relative
            .components()
            .next()
            .is_some_and(|component| component.as_os_str() == "vendor")
        {
            return false;
        }
    }

    let extension = path.extension().and_then(|extension| extension.to_str());
    if matches!(
        extension,
        Some("rs" | "c" | "toml" | "ada" | "adb" | "ads" | "gpr" | "tera" | "yml" | "yaml")
    ) {
        return true;
    }

    if extension != Some("md") {
        return false;
    }

    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };

    relative
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == "docs" || component.as_os_str() == "SPDX")
}

fn read_spdx_license(path: &Path) -> Result<Option<String>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in contents.lines().take(10) {
        if let Some((_, license)) = line.split_once(SPDX_MARKER) {
            let license = license
                .trim()
                .trim_end_matches("-->")
                .trim_end_matches("*/")
                .trim()
                .to_owned();
            return Ok(Some(license));
        }
    }
    Ok(None)
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::{build_manifest, check};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn check_rejects_rust_file_without_spdx_header() {
        let root = test_root("missing");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn missing() {}\n").unwrap();

        assert!(check(&root).is_err());
    }

    #[test]
    fn check_rejects_c_file_without_spdx_header() {
        let root = test_root("missing-c");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/shim.c"), "int main(void) { return 0; }\n").unwrap();

        assert!(check(&root).is_err());
    }

    #[test]
    fn check_skips_vendor_c_files() {
        let root = test_root("vendor-c");
        fs::create_dir_all(root.join("vendor/tree-sitter-ada/src")).unwrap();
        fs::write(
            root.join("vendor/tree-sitter-ada/src/parser.c"),
            "int tree_sitter_ada(void) { return 0; }\n",
        )
        .unwrap();

        check(&root).expect("vendored C is covered by vendor license checksum");
    }

    #[test]
    fn check_rejects_tera_template_without_spdx_header() {
        let root = test_root("missing-tera");
        fs::create_dir_all(root.join("templates")).unwrap();
        fs::write(
            root.join("templates/main.adb.tera"),
            "procedure Main is begin null; end Main;\n",
        )
        .unwrap();

        assert!(check(&root).is_err());
    }

    #[test]
    fn check_audits_root_third_party_md_without_header() {
        let root = test_root("third-party-root");
        fs::write(root.join("THIRD_PARTY.md"), "# Third party\n\nNo header.\n").unwrap();

        let err = check(&root).expect_err("THIRD_PARTY.md without SPDX header must fail check");
        assert!(
            err.to_string().contains("missing SPDX headers"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_skips_root_license_and_notice() {
        let root = test_root("license-notice-root");
        fs::write(root.join("LICENSE"), "Apache 2.0 verbatim text.\n").unwrap();
        fs::write(root.join("NOTICE"), "Notice without header.\n").unwrap();

        check(&root).expect("LICENSE and NOTICE follow Apache convention, no SPDX header required");
    }

    #[test]
    fn manifest_orders_paths_deterministically() {
        let root = test_root("manifest");
        fs::create_dir_all(root.join("b")).unwrap();
        fs::create_dir_all(root.join("a")).unwrap();
        fs::write(
            root.join("b/b.rs"),
            "// SPDX-License-Identifier: Apache-2.0\n",
        )
        .unwrap();
        fs::write(root.join("a/a.rs"), "// SPDX-License-Identifier: MIT\n").unwrap();

        let manifest = build_manifest(&root).unwrap();
        assert_eq!(manifest.files[0].path, "a/a.rs");
        assert_eq!(manifest.files[1].path, "b/b.rs");
    }

    #[test]
    fn manifest_trims_block_comment_suffix_from_license_expression() {
        let root = test_root("manifest-block-comment");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/shim.c"),
            "/* SPDX-License-Identifier: Apache-2.0 */\n",
        )
        .unwrap();

        let manifest = build_manifest(&root).unwrap();

        assert_eq!(manifest.files[0].license, "Apache-2.0");
    }

    #[test]
    fn manifest_skips_generated_govfuzz_work_dirs() {
        let root = test_root("manifest-generated-work");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("govfuzz_work/auto/H-C0001")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "// SPDX-License-Identifier: Apache-2.0\n",
        )
        .unwrap();
        fs::write(
            root.join("govfuzz_work/auto/H-C0001/main.c"),
            "// SPDX-License-Identifier: Apache-2.0\n",
        )
        .unwrap();

        let manifest = build_manifest(&root).unwrap();

        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "src/lib.rs");
    }

    #[test]
    fn manifest_skips_ignored_internal_design_docs() {
        let root = test_root("manifest-internal-design-docs");
        fs::create_dir_all(root.join("docs/site")).unwrap();
        fs::create_dir_all(root.join("docs/superpowers/plans")).unwrap();
        fs::write(
            root.join("docs/site/install.md"),
            "<!-- SPDX-License-Identifier: Apache-2.0 -->\n",
        )
        .unwrap();
        fs::write(
            root.join("docs/superpowers/plans/internal.md"),
            "<!-- SPDX-License-Identifier: Apache-2.0 -->\n",
        )
        .unwrap();

        let manifest = build_manifest(&root).unwrap();

        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "docs/site/install.md");
    }

    fn test_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-spdx-{name}-{unique}"));
        fs::create_dir_all(&root).unwrap();
        root
    }
}
