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
    assert!(stdout.contains("--artifact-dir"));
    assert!(stdout.contains("dist/content-inputs/sbom-cves.json"));
    assert!(stdout.contains("dist/content-inputs/binary-cves.json"));
    assert!(stdout.contains("smoke"));
    assert!(stdout.contains("install.sh"));
    assert!(stdout.contains("INSTALL.md"));
    assert!(stdout.contains("LICENSE"));
    assert!(stdout.contains("README.md"));
    assert!(stdout.contains("RELEASE_NOTES.md"));
    assert!(stdout.contains("RUN-GOVFUZZ.md"));
    assert!(stdout.contains("govfuzz-bug-report"));
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
        "c,cpp,rust,java,python,perl,go,ada,cobol,",
        "fortran,csharp,javascript,typescript,ruby,lua,php,all,none",
        "--targets LIST",
        "native,windows,aarch64,all,none",
        "--fuzzers LIST",
        "builtin,afl,all,none",
        "--extras LIST",
        "build-recovery,sandbox,archives,all,none",
        "--install-seeds",
        "--package-manager NAME",
        "--no-system-packages",
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
        "all-in-one Linux package",
        "both Linux preload shims",
        "INSTALL.md",
        "LICENSE",
        "README.md",
        "RELEASE_NOTES.md",
        "manually co-locate",
        "govfuzz-bug-report",
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
    assert!(
        readme.contains("AUTO-OFFLINE-RUNBOOK.md"),
        "README-DIST should point operators at the offline auto runbook:\n{readme}"
    );
    assert!(
        script.contains(
            "cp \"$REPO_ROOT/docs/site/offline-auto-runbook.md\" \"$STAGE_ROOT/AUTO-OFFLINE-RUNBOOK.md\""
        ),
        "packager must put the offline auto runbook in the distribution root"
    );
    assert!(
        script.contains(
            "cp \"$REPO_ROOT/docs/site/offline-auto-runbook.md\" \"$TOOL_DIR/docs/AUTO-OFFLINE-RUNBOOK.md\""
        ),
        "packager must install the offline auto runbook under the tool prefix"
    );
    assert!(
        run_guide.contains("AUTO-OFFLINE-RUNBOOK.md"),
        "RUN-GOVFUZZ should point operators at the detailed offline auto runbook"
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
        "govfuzz-bug-report /path/to/govfuzz_work",
    ] {
        assert!(
            run_guide.contains(expected),
            "RUN-GOVFUZZ template missing {expected:?}:\n{run_guide}"
        );
    }
}

#[test]
fn offline_auto_runbook_documents_trusted_and_forced_recovery_flows() {
    let runbook = fs::read_to_string(repo_root().join("docs/site/offline-auto-runbook.md"))
        .expect("read offline auto runbook");

    for expected in [
        "Known Build Command",
        "Unknown Build Command",
        "--run-untrusted",
        "--build-command",
        "--unsafe-search-and-run-build-commands",
        "--extra-include",
        "--extra-source",
        "--ada-deps",
        "IDL and Generated Source",
        "--force",
        "different work directory",
        "Do not use `--install-deps`",
        "positive coverage",
        "Compact Scrubbed Support Report",
        "govfuzz-bug-report /results/govfuzz-real",
    ] {
        assert!(
            runbook.contains(expected),
            "offline auto runbook missing {expected:?}:\n{runbook}"
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
    assert!(stdout.contains("--package-manager"));
    assert!(stdout.contains("--no-system-packages"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--no-smoke"));
    assert!(stdout.contains("arrow-key checklist"));
    assert!(stdout.contains("Esc/Cancel"));
    assert!(!stdout.to_lowercase().contains("offline"));
}

#[test]
fn offline_dist_installer_maps_rhel_dependencies_to_dnf_packages() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-rhel-dry-run");
    create_minimal_bundle(&bundle);

    let output = Command::new("bash")
        .arg(&script)
        .arg("--non-interactive")
        .arg("--dry-run")
        .arg("--package-manager")
        .arg("dnf")
        .arg("--no-rustup")
        .arg("--no-content")
        .arg("--no-symlink")
        .arg("--no-smoke")
        .arg("--prefix")
        .arg(bundle.join("install"))
        .arg("--languages")
        .arg("all")
        .arg("--targets")
        .arg("native,windows,aarch64")
        .arg("--fuzzers")
        .arg("builtin,afl")
        .arg("--extras")
        .arg("build-recovery,sandbox,archives")
        .current_dir(&bundle)
        .output()
        .expect("run RHEL installer dry-run");

    assert_success(output.clone(), "RHEL installer dry-run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dnf -y makecache"), "{stdout}");
    assert!(stdout.contains("dnf install -y"), "{stdout}");
    for package in [
        "gcc-c++",
        "gcc-gnat",
        "java-17-openjdk-devel",
        "golang",
        "gcc-gfortran",
        "lua",
        "aflplusplus",
        "pkgconf-pkg-config",
        "xz",
    ] {
        assert!(
            stdout.contains(package),
            "RHEL dry-run did not mention {package}: {stdout}"
        );
    }
    for debian_only in ["default-jdk", "golang-go", "lua5.4", "xz-utils"] {
        assert!(
            !stdout.contains(debian_only),
            "RHEL dry-run used Debian package {debian_only}: {stdout}"
        );
    }
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
        .arg("--package-manager")
        .arg("apt-get")
        .arg("--prefix")
        .arg(bundle.join("install").to_str().unwrap())
        .arg("--languages")
        .arg("all")
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
            .arg("--package-manager")
            .arg("apt-get")
            .arg("--prefix")
            .arg(bundle.join("install").to_str().unwrap())
            .arg("--languages")
            .arg("all")
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
        "gnucobol",
        "gfortran",
        "nodejs",
        "ruby",
        "lua5.4",
        "php-cli",
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
    assert!(stdout.contains("SharpFuzz.CommandLine"));
    assert!(stdout.contains("esbuild"));
    assert!(stdout.contains("pack verify"));
    assert!(stdout.contains("govfuzz-smoke"));
    assert!(stdout.contains("auto"));
}

#[test]
fn offline_dist_packager_stages_every_external_harness_runtime() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();

    for runtime in [
        "c_runtime",
        "ada_runtime",
        "java_runtime",
        "python_runtime",
        "perl_runtime",
        "crates/rust_runtime",
        "csharp_runtime",
        "js_runtime",
        "ruby_runtime",
        "lua_runtime",
        "php_runtime",
    ] {
        assert!(
            script.contains(&format!("$REPO_ROOT/{runtime}")),
            "packager does not stage {runtime}"
        );
    }

    assert!(
        script.contains("libgovfuzz_cc_intercept.so"),
        "all-in-one packager must stage the compiler-interception shim"
    );
    assert!(
        script.contains("cp \"$REPO_ROOT/INSTALL.md\" \"$STAGE_ROOT/INSTALL.md\""),
        "all-in-one package must carry the dual-path installation guide"
    );
    for document in ["LICENSE", "README.md", "RELEASE_NOTES.md"] {
        assert!(
            script.contains(&format!(
                "cp \"$REPO_ROOT/{document}\" \"$STAGE_ROOT/{document}\""
            )),
            "all-in-one package must carry {document}"
        );
    }
    assert!(
        script
            .contains("cp \"$SCRIPT_DIR/govfuzz-bug-report.sh\" \"$TOOL_DIR/govfuzz-bug-report\""),
        "all-in-one package must stage the scrubbed support-report wrapper"
    );
}

#[test]
fn release_matrix_keeps_windows_apps_and_linux_only_shims_separate() {
    let root = repo_root();
    let workspace = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let cli = fs::read_to_string(root.join("crates/cli/Cargo.toml")).unwrap();
    let daemon = fs::read_to_string(root.join("crates/daemon/Cargo.toml")).unwrap();
    let runtrace =
        fs::read_to_string(root.join("crates/govfuzz_runtrace_shim/Cargo.toml")).unwrap();
    let intercept =
        fs::read_to_string(root.join("crates/govfuzz_cc_intercept/Cargo.toml")).unwrap();
    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();

    assert!(workspace.contains("installers = [\"shell\", \"powershell\"]"));
    for manifest in [&workspace, &cli, &daemon] {
        assert!(manifest.contains("x86_64-unknown-linux-gnu"));
        assert!(manifest.contains("x86_64-pc-windows-msvc"));
    }
    for manifest in [&runtrace, &intercept] {
        assert!(manifest.contains("targets = [\"x86_64-unknown-linux-gnu\"]"));
        assert!(!manifest.contains("x86_64-pc-windows-msvc"));
    }
    for manifest in [&cli, &daemon, &runtrace, &intercept] {
        assert!(
            manifest.contains("../../INSTALL.md"),
            "every release component archive must include INSTALL.md"
        );
    }
    assert!(workflow.contains("if: runner.os == 'Linux'"));
    assert!(workflow.contains("if: runner.os == 'Windows'"));
    assert!(workflow.contains("scripts/check-linux-release-abi.sh"));
    assert!(workflow.contains("scripts/package-offline-dist.sh"));
    assert!(workflow.contains("govfuzz-dist-*.tar.gz.sha256"));
    assert!(workflow.contains("INSTALL.md LICENSE README.md RELEASE_NOTES.md"));
    assert!(workflow.contains("libgovfuzz_cc_intercept.so"));
    assert!(cli.contains("../../scripts/govfuzz-bug-report.sh"));
    assert!(workflow.contains("govfuzz-bug-report.sh"));
}

#[test]
fn release_archive_install_guide_documents_both_linux_layouts() {
    let guide = fs::read_to_string(repo_root().join("INSTALL.md")).unwrap();

    for expected in [
        "all-in-one `install.sh` bundle",
        "./install.sh",
        "--non-interactive",
        "manually co-locate component archives",
        "libgovfuzz_runtrace_shim.so",
        "libgovfuzz_cc_intercept.so",
        "GOVFUZZ_RUNTRACE_SHIM",
        "GOVFUZZ_CC_INTERCEPT",
        "govfuzz-daemon",
        "govfuzz-bug-report",
    ] {
        assert!(
            guide.contains(expected),
            "INSTALL.md missing {expected:?}:\n{guide}"
        );
    }
}

#[test]
fn offline_dist_installer_interactive_prompt_accepts_down_arrow_to_ok() {
    // The arrow-key checklist needs a real interactive terminal. Under a headless
    // CI pty the installer detects no controlling TTY and falls back to text-input
    // mode, so the simulated Down-arrow escape sequences become garbage input and
    // the flow is untestable there. The non-interactive installer paths (the
    // `--non-interactive` tests) are what CI exercises; skip this one cleanly.
    if std::env::var_os("CI").is_some() {
        eprintln!("skip: interactive arrow-key TUI needs a real terminal (headless CI)");
        return;
    }
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
    keys.push_str(&down_arrow(16));
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
fn offline_deployment_doc_uses_copy_pasteable_generated_content_paths() {
    // The offline binary-only packaging instructions moved out of README into the
    // dedicated offline deployment guide during the README slim-down. Wherever
    // they live, they must show real copy-pasteable generated paths, not
    // `/path/to/...` placeholders.
    let doc = fs::read_to_string(repo_root().join("docs/site/offline-deployment.md")).unwrap();

    assert!(!doc.contains("/path/to/govfuzz-sbom-cves.json"));
    assert!(!doc.contains("/path/to/govfuzz-binary-cves.json"));
    assert!(!doc.contains("/path/to/seed-corpus"));
    assert!(doc.contains("scripts/package-offline-dist.sh"));
    assert!(doc.contains("dist/content-inputs/sbom-cves.json"));
    assert!(doc.contains("dist/content-inputs/binary-cves.json"));
    assert!(doc.contains("dist/content-inputs/seeds"));
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
