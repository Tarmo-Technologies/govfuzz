// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

#[test]
fn release_workflow_disables_unavailable_github_attestations() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let cargo_toml = read(root.join("Cargo.toml"));

    assert!(cargo_toml.contains("github-attestations = false"));
    assert!(!cargo_toml.contains("github-attestations-phase"));
    assert!(!workflow.contains("\"attestations\": \"write\""));
    assert!(!workflow.contains("\"id-token\": \"write\""));
    assert!(!workflow.contains("uses: actions/attest-build-provenance@v3"));
}

#[test]
fn release_packaging_docs_explain_supported_integrity_verification() {
    let docs = read(repo_root().join("docs/release-packaging.md"));

    assert!(docs.contains("sha256sum -c <asset>.sha256"));
    assert!(docs.contains("signed content pack"));
    assert!(docs.contains("GitHub Artifact Attestations are disabled"));
    assert!(docs.contains("github-attestations = true"));
}

#[test]
fn release_packaging_includes_linux_runtrace_shim() {
    let root = repo_root();
    let shim_manifest = read(root.join("crates/govfuzz_runtrace_shim/Cargo.toml"));
    let docs = read(root.join("docs/release-packaging.md"));

    assert!(shim_manifest.contains("[package.metadata.dist]"));
    assert!(shim_manifest.contains("dist = true"));
    assert!(shim_manifest.contains("package-libraries = [\"cdylib\"]"));
    assert!(shim_manifest.contains("install-libraries = [\"cdylib\"]"));
    assert!(docs.contains("govfuzz_runtrace_shim"));
    assert!(docs.contains("virtualisation"));
}

#[test]
fn release_targets_match_supported_cross_platform_binary_matrix() {
    let root = repo_root();
    let cargo_toml = read(root.join("Cargo.toml"));
    let docs = read(root.join("docs/release-packaging.md"));

    assert!(
        cargo_toml.contains("targets = [\"x86_64-unknown-linux-gnu\", \"x86_64-pc-windows-msvc\"]")
    );
    assert!(docs.contains("The generated release workflow builds these target triples"));
    assert!(docs.contains("`x86_64-unknown-linux-gnu`"));
    assert!(docs.contains("`x86_64-pc-windows-msvc`"));
    assert!(docs.contains("preload shims remain Linux-only assets"));
}

#[test]
fn release_cli_is_self_contained_for_every_harness_runtime() {
    let root = repo_root();
    let cli_manifest = read(root.join("crates/cli/Cargo.toml"));
    let workflow = read(root.join(".github/workflows/release.yml"));

    for runtime in [
        "ada_runtime",
        "c_runtime",
        "csharp_runtime",
        "java_runtime",
        "js_runtime",
        "lua_runtime",
        "perl_runtime",
        "php_runtime",
        "python_runtime",
        "ruby_runtime",
        "rust_runtime",
    ] {
        assert!(
            cli_manifest.contains(runtime),
            "CLI dist metadata omitted {runtime}"
        );
        assert!(
            workflow.contains(runtime),
            "release archive gate omitted {runtime}"
        );
    }

    assert!(workflow.contains("Validate packaged harness runtimes (Linux)"));
    assert!(workflow.contains("Validate packaged harness runtimes (Windows)"));
    assert!(workflow.contains("archive=target/distrib/govfuzz-x86_64-unknown-linux-gnu.tar.xz"));
    assert!(
        workflow.contains("$archive = Get-Item target/distrib/govfuzz-x86_64-pc-windows-msvc.zip")
    );
    assert!(!workflow.contains("-name \"govfuzz-*.tar.xz\""));
    assert!(!workflow.contains("-Filter \"govfuzz-*.zip\""));
}

#[test]
fn release_workflow_augments_the_unix_installer_with_rhel7_guidance() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let augmenter = read(root.join("scripts/augment-release-installer.py"));
    let readme = read(root.join("README.md"));

    assert!(workflow.contains(
        "python3 scripts/augment-release-installer.py target/distrib/govfuzz-installer.sh"
    ));
    assert!(workflow.contains("GOVFUZZ_RHEL7_GUIDANCE_BEGIN"));
    assert!(augmenter.contains("GOVFUZZ_RHEL7_GUIDANCE_BEGIN"));
    for required in [
        "rhel-server-rhscl-7-rpms",
        "llvm-toolset-7.0-clang",
        "llvm-toolset-7.0-compiler-rt",
        "govfuzz_runtrace_shim-installer.sh",
        "govfuzz_cc_intercept-installer.sh",
    ] {
        assert!(augmenter.contains(required), "installer omitted {required}");
        assert!(readme.contains(required), "README omitted {required}");
    }
}

#[cfg(unix)]
#[test]
fn release_workflow_fixes_library_installer_chmod_path() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let fixer = root.join("scripts/fix-dist-library-installer.py");
    let fixer_text = read(&fixer);

    assert!(workflow.contains("python3 scripts/fix-dist-library-installer.py"));
    assert!(workflow.contains("govfuzz_runtrace_shim-installer.sh"));
    assert!(workflow.contains("govfuzz_cc_intercept-installer.sh"));
    assert!(fixer_text.contains("$_lib_install_temp/$_lib_name"));

    let tmp = std::env::temp_dir().join(format!(
        "govfuzz-library-installer-fix-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create installer test directory");
    let installer = tmp.join("library-installer.sh");
    fs::write(&installer, "chmod +x \"$_lib_install_dir/$_lib_name\"\n")
        .expect("write generated library installer fixture");

    for _ in 0..2 {
        let status = Command::new("python3")
            .arg(&fixer)
            .arg(&installer)
            .status()
            .expect("run library installer fixer");
        assert!(status.success());
    }
    let fixed = read(&installer);
    assert!(fixed.contains("chmod +x \"$_lib_install_temp/$_lib_name\""));
    assert!(!fixed.contains("chmod +x \"$_lib_install_dir/$_lib_name\""));
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[test]
fn release_workflow_makes_powershell_installers_noninteractive_safe() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let fixer = root.join("scripts/fix-dist-powershell-installer.py");

    assert!(workflow.contains("python3 scripts/fix-dist-powershell-installer.py"));
    assert!(workflow.contains("govfuzz-installer.ps1"));
    assert!(workflow.contains("govfuzz-daemon-installer.ps1"));

    let tmp = std::env::temp_dir().join(format!(
        "govfuzz-powershell-installer-fix-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create PowerShell installer test directory");
    let installer = tmp.join("installer.ps1");
    fs::write(
        &installer,
        concat!(
            "$InformationPreference = \"Continue\"\n",
            "      Expand-Archive -Path $dir_path -DestinationPath \"$tmp\";\n"
        ),
    )
    .expect("write generated PowerShell installer fixture");

    for _ in 0..2 {
        let status = Command::new("python3")
            .arg(&fixer)
            .arg(&installer)
            .status()
            .expect("run PowerShell installer fixer");
        assert!(status.success());
    }
    let fixed = read(&installer);
    assert_eq!(fixed.matches("$ProgressPreference").count(), 2);
    assert!(fixed.contains("$ProgressPreference = \"SilentlyContinue\""));
    assert!(fixed.contains("Avoid console progress-buffer access"));
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[test]
fn release_shell_installers_check_for_xz() {
    let root = repo_root();
    let workflow = read(root.join(".github/workflows/release.yml"));
    let fixer = root.join("scripts/fix-dist-shell-installer.py");

    assert!(workflow.contains("python3 scripts/fix-dist-shell-installer.py"));
    for installer in [
        "govfuzz-installer.sh",
        "govfuzz-daemon-installer.sh",
        "govfuzz_runtrace_shim-installer.sh",
        "govfuzz_cc_intercept-installer.sh",
    ] {
        assert!(workflow.contains(installer));
    }

    let tmp = std::env::temp_dir().join(format!(
        "govfuzz-shell-installer-fix-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create shell installer test directory");
    let installer = tmp.join("installer.sh");
    fs::write(&installer, "    need_cmd tar\n    need_cmd grep\n")
        .expect("write generated shell installer fixture");

    for _ in 0..2 {
        let status = Command::new("python3")
            .arg(&fixer)
            .arg(&installer)
            .status()
            .expect("run shell installer fixer");
        assert!(status.success());
    }
    let fixed = read(&installer);
    assert_eq!(fixed.matches("need_cmd xz").count(), 1);
    assert!(fixed.contains("minimal RHEL images omit xz"));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn ci_enforces_the_current_supported_os_matrix() {
    let root = repo_root();
    let ci = read(root.join(".github/workflows/ci.yml"));
    let windows_smoke = read(root.join("scripts/ci/windows-release-smoke.ps1"));
    let readme = read(root.join("README.md"));
    let install = read(root.join("docs/site/install.md"));
    let windows = read(root.join("docs/site/windows.md"));

    for required in [
        "ubuntu-22.04",
        "ubuntu-24.04",
        "ubuntu-26.04",
        "almalinux:8.10@sha256:",
        "almalinux:9.8@sha256:",
        "almalinux:10.2@sha256:",
        "windows-2022",
        "windows-2025",
    ] {
        assert!(ci.contains(required), "CI omitted {required}");
    }
    assert!(ci.contains("govfuzz-el7-release.tar.gz"));
    assert!(ci.contains("runtrace.jsonl"));
    assert!(ci.contains(r#"grep -Eq "\"built_and_fuzzed\"[[:space:]]*:[[:space:]]*1""#));
    assert!(ci.contains("scripts/ci/windows-release-smoke.ps1"));
    assert!(windows_smoke.contains("Win32_OperatingSystem"));
    assert!(windows_smoke.contains("built_and_fuzzed"));
    assert!(windows_smoke.contains("GetEnvironmentVariable(\"Path\", \"Machine\")"));
    assert!(windows_smoke.contains("GetEnvironmentVariable(\"Path\", \"User\")"));
    let supported_docs = format!("{readme}\n{install}\n{windows}");
    for required in [
        "RHEL 10",
        "26.04",
        "Windows 11 Enterprise 25H2",
        "Windows 11 Enterprise LTSC 2024",
        "Windows Server 2019",
        "Server 2025",
    ] {
        assert!(
            supported_docs.contains(required),
            "support documentation omitted {required}"
        );
    }
    assert!(windows.contains("$Version = \"v0.2.18\""));
    assert!(!windows.contains("$Version = \"v0.2.16\""));
}

#[cfg(unix)]
#[test]
fn augmented_installer_prints_actionable_rhel7_prerequisites() {
    let root = repo_root();
    let tmp = std::env::temp_dir().join(format!(
        "govfuzz-release-installer-guidance-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create installer test directory");
    let installer = tmp.join("govfuzz-installer.sh");
    let os_release = tmp.join("os-release");
    fs::write(
        &installer,
        r#"#!/bin/sh
APP_NAME="govfuzz"
APP_VERSION="0.2.18"
ARTIFACT_DOWNLOAD_URLS="https://example.invalid/v0.2.18"
PRINT_QUIET=0
INFERRED_HOME=/tmp/govfuzz-installer-test
say() { echo "$1"; }
warn() { say "WARN: $1" >&2; }
download_binary_and_run_installer() { :; }
download_binary_and_run_installer "$@" || exit 1
"#,
    )
    .expect("write generated installer fixture");
    fs::write(
        &os_release,
        "ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"7.9\"\n",
    )
    .expect("write RHEL 7 os-release fixture");

    for _ in 0..2 {
        let output = Command::new("python3")
            .arg(root.join("scripts/augment-release-installer.py"))
            .arg(&installer)
            .output()
            .expect("run installer augmenter");
        assert!(
            output.status.success(),
            "augmenter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let augmented = read(&installer);
    assert_eq!(augmented.matches("GOVFUZZ_RHEL7_GUIDANCE_BEGIN").count(), 1);

    let output = Command::new("sh")
        .arg(&installer)
        .env("GOVFUZZ_OS_RELEASE_FILE", &os_release)
        .output()
        .expect("run augmented installer fixture");
    assert!(output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for expected in [
        "installs the CLI only",
        "subscription-manager repos --enable rhel-server-rhscl-7-rpms",
        "yum install -y curl tar xz",
        "llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt",
        "govfuzz_runtrace_shim-installer.sh",
        "govfuzz_cc_intercept-installer.sh",
    ] {
        assert!(
            combined.contains(expected),
            "missing {expected} from installer output:\n{combined}"
        );
    }
    let _ = fs::remove_dir_all(&tmp);
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
