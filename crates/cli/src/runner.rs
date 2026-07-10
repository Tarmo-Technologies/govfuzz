// SPDX-License-Identifier: Apache-2.0

use clap::ValueEnum;
use replay_min::{HarnessRunner, SandboxConfig};
use std::path::{Path, PathBuf};

/// How a foreign-platform/arch harness is launched. Both variants prefix the
/// harness argv with an emulator executable (`qemu-aarch64 <harness>` /
/// `wine <harness>`), so both reuse `HarnessRunner::qemu_user` — wine takes no
/// emulator args, qemu may take a `-L <sysroot>` pair. Set by `govfuzz auto`
/// only for a cross candidate; the host-native path uses `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HarnessWrapper {
    QemuUser { exe: PathBuf, args: Vec<String> },
    Wine { exe: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SandboxModeArg {
    None,
    Auto,
    Firejail,
    Bubblewrap,
}

pub(crate) fn harness_runner(
    harness: PathBuf,
    qemu_user: Option<PathBuf>,
    qemu_args: Vec<String>,
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> HarnessRunner {
    let wrapper = qemu_user.map(|exe| HarnessWrapper::QemuUser {
        exe,
        args: qemu_args,
    });
    harness_runner_with_wrapper(harness, wrapper, sandbox, sandbox_tool, sandbox_strict)
}

/// Build a `HarnessRunner` for a harness launched directly, under qemu-user, or
/// under wine. `wrapper == None` is byte-identical to the historical
/// `HarnessRunner::direct` path; the wine variant is just a qemu-user prefix
/// with no emulator args (`wine <harness>`).
pub(crate) fn harness_runner_with_wrapper(
    harness: PathBuf,
    wrapper: Option<HarnessWrapper>,
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> HarnessRunner {
    let runner = match wrapper {
        Some(HarnessWrapper::QemuUser { exe, args }) => {
            HarnessRunner::qemu_user(exe, args, harness)
        }
        Some(HarnessWrapper::Wine { exe }) => HarnessRunner::qemu_user(exe, Vec::new(), harness),
        None => HarnessRunner::direct(harness),
    };
    let runner = runner.with_sandbox(sandbox_config(sandbox, sandbox_tool, sandbox_strict));
    // Read-only-bind the runtrace shim's directory into the sandbox so the
    // LD_PRELOAD shim still loads (and the executable oracles still fire) when
    // the harness runs sandboxed. No effect when not sandboxed or shim absent.
    match crate::auto::shim_path::locate().and_then(|shim| shim.parent().map(Path::to_path_buf)) {
        Some(shim_dir) => runner.with_ro_binds([shim_dir]),
        None => runner,
    }
}

/// Classify a built harness binary by the engine its main() expects.
/// AdaStdin is the default for native Ada harnesses (read events file
/// via env). CLibFuzzer accepts an input file via argv (libFuzzer
/// `single input` mode). CAfl reads input from stdin (AFL persistent
/// mode handshake). Detection is best-effort:
///   - filename `main_afl` is unambiguous (govfuzz build only stages
///     it for `--c-engine afl++`).
///   - libFuzzer detection probes the binary with `-help=1` and looks
///     for the libFuzzer banner in stdout/stderr. Ada harnesses
///     don't accept that flag and exit immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HarnessEngine {
    AdaStdin,
    CLibFuzzer,
    CAfl,
}

pub(crate) fn detect_harness_engine(harness: &Path) -> HarnessEngine {
    let name = harness
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name == "main_afl" || name == "main_afl.exe" {
        return HarnessEngine::CAfl;
    }
    // A govfuzz driver harness (generated C #399, or a passthrough #398) has no
    // libFuzzer banner — it ships its own `main` with the GOVFUZZ_FRAMED loop and
    // an argv[1]-file fallback. Treat it as CLibFuzzer (argv-file single-input) so
    // minimize/replay feed the testcase as a file, not on stdin.
    if is_govfuzz_driver_harness(harness) || is_libfuzzer_binary(harness) {
        return HarnessEngine::CLibFuzzer;
    }
    HarnessEngine::AdaStdin
}

/// A govfuzz driver harness carries the `GOVFUZZ_FRAMED` persistent-loop marker:
/// C/C++/Rust ship a sibling `main.c`/`main.cpp`, and the native Java lane's
/// `main` is itself a launcher script whose header carries the marker (reading the
/// real binary as text simply fails on the non-UTF-8 bytes and is ignored).
fn is_govfuzz_driver_harness(harness: &Path) -> bool {
    let Some(dir) = harness.parent() else {
        return false;
    };
    let harness_name = harness.file_name().and_then(|n| n.to_str()).unwrap_or("");
    ["main.c", "main.cpp", harness_name].iter().any(|name| {
        !name.is_empty()
            && std::fs::read_to_string(dir.join(name))
                .map(|src| src.contains("GOVFUZZ_FRAMED"))
                .unwrap_or(false)
    })
}

fn is_libfuzzer_binary(harness: &Path) -> bool {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let Ok(mut child) = Command::new(harness)
        .arg("-help=1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return false;
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return false,
        }
    }
    let _ = child.kill();
    let Ok(output) = child.wait_with_output() else {
        return false;
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr.contains("libFuzzer") || stdout.contains("libFuzzer")
}

fn sandbox_config(
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> SandboxConfig {
    match sandbox {
        SandboxModeArg::None => SandboxConfig::none(),
        SandboxModeArg::Auto => {
            if sandbox_strict {
                SandboxConfig::strict_auto()
            } else {
                SandboxConfig::auto()
            }
        }
        SandboxModeArg::Firejail => {
            SandboxConfig::firejail(sandbox_tool.unwrap_or_else(|| PathBuf::from("firejail")))
                .with_strict(sandbox_strict)
        }
        SandboxModeArg::Bubblewrap => {
            SandboxConfig::bubblewrap(sandbox_tool.unwrap_or_else(|| PathBuf::from("bwrap")))
                .with_strict(sandbox_strict)
        }
    }
}
