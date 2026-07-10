// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[test]
fn offline_dist_packager_advertises_binary_only_content_pack_flow() {
    let root = repo_root();
    let script = root.join("scripts/package-offline-dist.sh");

    assert!(script.is_file(), "missing {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .arg("--help")
        .output()
        .expect("run package-offline-dist --help");

    assert_success(output, "package-offline-dist --help");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--help")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("--sbom-cve-db"));
    assert!(stdout.contains("--binary-cve-db"));
    assert!(stdout.contains("--seed-dir"));
    assert!(stdout.contains("dist/content-inputs/sbom-cves.json"));
    assert!(stdout.contains("dist/content-inputs/binary-cves.json"));
    assert!(stdout.contains("smoke"));
    assert!(stdout.contains("install.sh"));
    assert!(stdout.contains("RUN-GOVFUZZ.md"));
    assert!(stdout.contains("does not include GovFuzz source"));
}

#[test]
fn offline_dist_packager_generates_default_content_inputs_when_omitted() {
    let root = repo_root();
    let script = root.join("scripts/package-offline-dist.sh");
    let out_dir = temp_dir("dist-package-default-inputs");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--dry-run")
        .arg("--skip-build")
        .arg("--out")
        .arg(&out_dir)
        .arg("--version")
        .arg("test")
        .output()
        .expect("run package-offline-dist dry-run");

    assert_success(output, "package-offline-dist dry-run");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--dry-run")
            .arg("--skip-build")
            .arg("--out")
            .arg(&out_dir)
            .arg("--version")
            .arg("test")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("content-inputs/sbom-cves.json"));
    assert!(stdout.contains("content-inputs/binary-cves.json"));
    assert!(stdout.contains("content-inputs/seeds"));
    assert!(!stdout.contains("missing --sbom-cve-db"));
    assert!(!stdout.contains("missing --binary-cve-db"));
}

#[test]
fn offline_dist_readme_documents_install_options_without_source_tree_note() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();
    let readme = extract_readme_dist_template(&script);

    for expected in [
        "--prefix DIR",
        "--bin-dir DIR",
        "--non-interactive",
        "--languages LIST",
        "c,cpp,rust,java,python,perl,go,ada,all,none",
        "--targets LIST",
        "native,windows,aarch64,all,none",
        "--fuzzers LIST",
        "builtin,afl,all,none",
        "--extras LIST",
        "build-recovery,sandbox,archives,all,none",
        "--install-seeds",
        "--no-apt",
        "--no-rustup",
        "--no-content",
        "--no-symlink",
        "--no-smoke",
        "--smoke-work-dir DIR",
        "--dry-run",
        "-h, --help",
        "./install.sh --non-interactive",
        "--languages c,cpp,rust",
        "--targets native,aarch64",
        "--fuzzers builtin,afl",
        "--extras build-recovery,archives",
        "--languages all",
        "--targets all",
        "--fuzzers all",
        "--extras all",
    ] {
        assert!(
            readme.contains(expected),
            "README-DIST template missing {expected:?}:\n{readme}"
        );
    }
    // The binary-only dist README must not carry a build-from-source install
    // instruction (it may still discuss operating govfuzz ON a source tree, and
    // note that the dist "does not include GovFuzz source").
    let lower = readme.to_lowercase();
    assert!(!lower.contains("build from source"));
    assert!(!lower.contains("git clone"));
    assert!(!lower.contains("cargo build"));
}

#[test]
fn offline_dist_run_guide_is_packaged_and_documents_core_workflows() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();
    let readme = extract_readme_dist_template(&script);
    let run_guide = extract_run_guide_template(&script);

    assert!(
        script.contains("cat >\"$STAGE_ROOT/RUN-GOVFUZZ.md\" <<"),
        "packager must write RUN-GOVFUZZ.md into the staged tarball root"
    );
    assert!(
        readme.contains("RUN-GOVFUZZ.md"),
        "README-DIST should point installed operators at the run guide:\n{readme}"
    );

    for expected in [
        "govfuzz --help",
        "VERSION",
        "govfuzz auto",
        "--work-dir",
        "--per-target-time",
        "30 seconds",
        "auto/run.md",
        "auto/run.json",
        "govfuzz report",
        "--findings govfuzz_work/findings",
        "--csv",
        "reports/last.csv",
        "govfuzz fuzz",
        "10 minutes",
        "govfuzz replay",
        "govfuzz sbom",
        "--emit sbom,cyclonedx,vulnerabilities,openvex,csv",
        "sbom/sbom.csv",
        "sbom/vulnerabilities.csv",
        "govfuzz-daemon",
        "GOVFUZZ_RUNTRACE_SHIM",
        "/opt/govfuzz",
        "A content pack is a signed offline bundle",
        "Seeds are example input files",
    ] {
        assert!(
            run_guide.contains(expected),
            "RUN-GOVFUZZ template missing {expected:?}:\n{run_guide}"
        );
    }
}

#[test]
fn offline_dist_checksum_sidecar_uses_archive_basename() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();

    assert!(
        script.contains("sha256sum \"${NAME}.tar.gz\""),
        "checksum sidecar should record the archive basename so sha256sum -c works after transfer"
    );
    assert!(
        !script.contains("sha256sum \"$TARBALL\" >\"${TARBALL}.sha256\""),
        "checksum sidecar must not record the build host's absolute tarball path"
    );
}

#[test]
fn offline_dist_installer_supports_interactive_and_noninteractive_profiles() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");

    assert!(script.is_file(), "missing {}", script.display());

    let help = Command::new("bash")
        .arg(&script)
        .arg("--help")
        .output()
        .expect("run install-dist --help");
    assert_success(help, "install-dist --help");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--help")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("--non-interactive"));
    assert!(stdout.contains("--languages"));
    assert!(stdout.contains("--targets"));
    assert!(stdout.contains("--fuzzers"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--no-smoke"));
    assert!(stdout.contains("arrow-key checklist"));
    assert!(stdout.contains("Esc/Cancel"));
    assert!(!stdout.to_lowercase().contains("offline"));
}

#[test]
fn offline_dist_installer_dry_run_maps_choices_to_dependency_groups() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-dry-run");
    create_minimal_bundle(&bundle);

    let output = Command::new("bash")
        .arg(&script)
        .arg("--non-interactive")
        .arg("--dry-run")
        .arg("--prefix")
        .arg(bundle.join("install").to_str().unwrap())
        .arg("--languages")
        .arg("c,cpp,rust,java,python,perl,go,ada")
        .arg("--targets")
        .arg("native,windows,aarch64")
        .arg("--fuzzers")
        .arg("builtin,afl")
        .arg("--extras")
        .arg("build-recovery,sandbox,archives")
        .current_dir(&bundle)
        .output()
        .expect("run installer dry-run");

    assert_success(output, "installer dry-run");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--non-interactive")
            .arg("--dry-run")
            .arg("--prefix")
            .arg(bundle.join("install").to_str().unwrap())
            .arg("--languages")
            .arg("c,cpp,rust,java,python,perl,go,ada")
            .arg("--targets")
            .arg("native,windows,aarch64")
            .arg("--fuzzers")
            .arg("builtin,afl")
            .arg("--extras")
            .arg("build-recovery,sandbox,archives")
            .current_dir(&bundle)
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    for pkg in [
        "clang",
        "gprbuild",
        "default-jdk",
        "golang-go",
        "afl++",
        "wine64",
        "qemu-user",
        "bubblewrap",
    ] {
        assert!(
            stdout.contains(pkg),
            "dry-run did not mention {pkg}: {stdout}"
        );
    }
    assert!(stdout.contains("rustup toolchain install nightly"));
    assert!(stdout.contains("pack verify"));
    assert!(stdout.contains("govfuzz-smoke"));
    assert!(stdout.contains("auto"));
}

#[test]
fn offline_dist_installer_interactive_prompt_accepts_down_arrow_to_ok() {
    if Command::new("script").arg("--version").output().is_err()
        || Command::new("timeout").arg("--version").output().is_err()
    {
        return;
    }

    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-arrow-ok");
    create_minimal_bundle(&bundle);

    let mut keys = String::new();
    keys.push_str(&down_arrow(8));
    keys.push('\n');
    keys.push_str(&down_arrow(3));
    keys.push('\n');
    keys.push_str(&down_arrow(2));
    keys.push('\n');
    keys.push_str(&down_arrow(3));
    keys.push('\n');

    // Force the built-in arrow-key checklist (not the whiptail/dialog popup) so the
    // simulated Down-arrow + Enter keystrokes drive a deterministic fallback UI.
    let command = format!(
        "cd {} && GOVFUZZ_INSTALL_NO_GUI=1 bash {} --dry-run --no-apt --no-rustup --no-content --no-symlink --no-smoke --prefix {} --bin-dir {}",
        shell_quote(&bundle),
        shell_quote(&script),
        shell_quote(&bundle.join("install")),
        shell_quote(&bundle.join("bin")),
    );
    let mut child = Command::new("timeout")
        .arg("10")
        .arg("script")
        .arg("-qec")
        .arg(command)
        .arg("/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn installer pty");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(keys.as_bytes())
        .expect("write installer keys");
    let output = child.wait_with_output().expect("wait for installer pty");

    assert_success(output, "interactive installer down-arrow OK flow");
}

#[test]
fn readme_uses_copy_pasteable_generated_content_paths() {
    let readme = fs::read_to_string(repo_root().join("README.md")).unwrap();

    assert!(!readme.contains("/path/to/govfuzz-sbom-cves.json"));
    assert!(!readme.contains("/path/to/govfuzz-binary-cves.json"));
    assert!(!readme.contains("/path/to/seed-corpus"));
    assert!(readme.contains("scripts/package-offline-dist.sh"));
    assert!(readme.contains("dist/content-inputs/sbom-cves.json"));
    assert!(readme.contains("dist/content-inputs/binary-cves.json"));
    assert!(readme.contains("dist/content-inputs/seeds"));
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_success(output: std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn temp_dir(prefix: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn create_minimal_bundle(root: &Path) {
    fs::create_dir_all(root.join("tool")).unwrap();
    fs::create_dir_all(root.join("content/packs/current")).unwrap();
    fs::create_dir_all(root.join("smoke/c")).unwrap();
    fs::write(root.join("tool/govfuzz"), b"#!/usr/bin/env bash\nexit 0\n").unwrap();
    fs::write(root.join("content/packs/current/update-pack.json"), b"{}\n").unwrap();
    fs::write(
        root.join("smoke/c/govfuzz_smoke.c"),
        b"#include <stddef.h>\nint govfuzz_smoke_parse(const unsigned char *data, size_t len) { return len && data[0] == 'G'; }\n",
    )
    .unwrap();
}

fn down_arrow(count: usize) -> String {
    "\x1b[B".repeat(count)
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn extract_readme_dist_template(script: &str) -> &str {
    let marker = "cat >\"$STAGE_ROOT/README-DIST.md\" <<";
    let marker_start = script.find(marker).expect("README-DIST heredoc marker");
    let after_marker = &script[marker_start..];
    let content_start = after_marker.find('\n').unwrap() + 1;
    let content = &after_marker[content_start..];
    let end = content
        .find("\nEOF")
        .expect("README-DIST heredoc terminator");
    &content[..end]
}

fn extract_run_guide_template(script: &str) -> &str {
    let marker = "cat >\"$STAGE_ROOT/RUN-GOVFUZZ.md\" <<";
    let marker_start = script.find(marker).expect("RUN-GOVFUZZ heredoc marker");
    let after_marker = &script[marker_start..];
    let content_start = after_marker.find('\n').unwrap() + 1;
    let content = &after_marker[content_start..];
    let end = content
        .find("\nEOF")
        .expect("RUN-GOVFUZZ heredoc terminator");
    &content[..end]
}
