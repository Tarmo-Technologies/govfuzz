// SPDX-License-Identifier: Apache-2.0

//! Characterization test: locks the exact `sbom.json` / `cyclonedx.json`
//! produced for a fixed tree. Guards the Phase-1 `sbom_ingest` migration —
//! output must not change. Set `GOVFUZZ_BLESS=1` to (re)write the golden files.

use std::fs;
use std::path::Path;

fn write_fixture(root: &Path) {
    fs::create_dir_all(root.join("app")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nlicense = \"Apache-2.0\"\n",
    )
    .unwrap();
    fs::write(
        root.join("app/package.json"),
        "{\"name\":\"demo-ui\",\"version\":\"2.0.0\",\"license\":\"MIT\"}",
    )
    .unwrap();
}

/// The scanned tree lives in a fresh temp dir whose absolute path is random per
/// run. Redact that environmental prefix (and the random basename) so the golden
/// locks the *component discovery* output — the only thing the Phase-1 migration
/// touches — without flapping on the tempdir name.
fn redact_root(pretty: &str, root: &Path) -> String {
    let mut out = pretty.replace(&root.to_string_lossy().replace('\\', "/"), "<ROOT>");
    if let Some(basename) = root.file_name().and_then(|name| name.to_str()) {
        out = out.replace(&format!("\"name\": \"{basename}\""), "\"name\": \"<ROOT>\"");
    }
    // govfuzz stamps its OWN version (the workspace version) into the SBOM tool
    // metadata; that changes every release and would otherwise break this golden
    // on each version bump. Redact it so the golden locks component DISCOVERY, not
    // the tool version. The workspace version is shared, so this crate's
    // `CARGO_PKG_VERSION` is govfuzz's version. (Safe: the fixture packages are
    // demo@0.1.0 / demo-ui@2.0.0, neither equal to govfuzz's version.)
    out = out.replace(env!("CARGO_PKG_VERSION"), "<GOVFUZZ_VERSION>");
    out
}

fn assert_golden(name: &str, actual: &serde_json::Value, root: &Path) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    let pretty = redact_root(&serde_json::to_string_pretty(actual).unwrap(), root);
    if std::env::var("GOVFUZZ_BLESS").is_ok() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{pretty}\n")).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {name}; run with GOVFUZZ_BLESS=1"));
    assert_eq!(
        format!("{pretty}\n"),
        expected,
        "golden mismatch for {name}"
    );
}

#[test]
fn sbom_output_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    write_fixture(dir.path());

    let options = governance::SbomOptions {
        root: dir.path().to_path_buf(),
        out_dir: dir.path().join("out"),
        vuln_db: None,
        policy: None,
        binary_inventories: Vec::new(),
        fail_on: None,
        ..Default::default()
    };
    let summary = governance::write_sbom(&options).unwrap();

    let sbom: serde_json::Value =
        serde_json::from_slice(&fs::read(&summary.sbom_path).unwrap()).unwrap();
    let cyclonedx: serde_json::Value =
        serde_json::from_slice(&fs::read(&summary.cyclonedx_path).unwrap()).unwrap();

    assert_golden("sbom_basic.sbom.json", &sbom, dir.path());
    assert_golden("sbom_basic.cyclonedx.json", &cyclonedx, dir.path());
}
