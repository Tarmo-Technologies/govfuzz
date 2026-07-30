// SPDX-License-Identifier: Apache-2.0

use crate::finding_arg::resolve_finding_arg;
use crate::runner::{detect_harness_engine, harness_runner, HarnessEngine, SandboxModeArg};
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct ReplayArgs {
    /// Finding directory, or finding ID under ./findings.
    #[arg(
        value_name = "FINDING_DIR",
        required_unless_present = "finding",
        conflicts_with = "finding"
    )]
    pub finding_dir: Option<PathBuf>,

    /// Finding directory, or finding ID under ./findings.
    #[arg(long, value_name = "ID_OR_DIR")]
    pub finding: Option<PathBuf>,

    /// Harness binary path. Optional: when omitted it is auto-resolved from the
    /// finding's recorded `fixture_path` / `harness_id` (`<work>/auto/<harness_id>/main`).
    /// Pass this to override the auto-resolved path.
    #[arg(long)]
    pub harness: Option<PathBuf>,

    /// qemu-user executable for ELF-Linux cross-target replay.
    #[arg(long, value_name = "QEMU")]
    pub qemu_user: Option<PathBuf>,

    /// Extra argument passed to qemu-user before the harness path.
    #[arg(
        long = "qemu-arg",
        value_name = "ARG",
        allow_hyphen_values = true,
        requires = "qemu_user"
    )]
    pub qemu_args: Vec<String>,

    /// Sandbox wrapper for harness execution.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Override sandbox wrapper executable.
    #[arg(long, value_name = "PATH", requires = "sandbox")]
    pub sandbox_tool: Option<PathBuf>,

    /// Fail if the requested sandbox tool is unavailable.
    #[arg(long)]
    pub sandbox_strict: bool,
}

pub fn run(args: ReplayArgs) -> i32 {
    let finding_dir = resolve_finding_arg(args.finding_dir, args.finding);
    // The finding already records where its harness was built; resolve it so the
    // user does not have to repeat `--harness`. An explicit `--harness` always wins.
    let harness = match resolve_harness(&finding_dir, args.harness) {
        Ok(harness) => harness,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };
    if crate::binary_fuzz::is_binary_finding(&finding_dir) {
        return crate::binary_fuzz::replay_binary_finding(&finding_dir, &harness);
    }
    // Dispatch by engine. libFuzzer harnesses get a parallel path
    // that invokes the binary with the recorded testcase as argv[1]
    // and matches the resulting sanitizer rule_id against the
    // finding's recorded rule_id. AFL is still tracked by #291.
    match detect_harness_engine(&harness) {
        HarnessEngine::CAfl => {
            return replay_c_afl(&finding_dir, &harness);
        }
        HarnessEngine::CLibFuzzer => {
            return replay_c_libfuzzer(&finding_dir, &harness);
        }
        HarnessEngine::AdaStdin => {}
    }
    let runner = harness_runner(
        harness,
        args.qemu_user,
        args.qemu_args,
        args.sandbox,
        args.sandbox_tool,
        args.sandbox_strict,
    );
    match replay_min::replay_with_runner(&finding_dir, &runner) {
        Ok(replay_min::ReplayResult::Match) => {
            println!("MATCH");
            0
        }
        Ok(replay_min::ReplayResult::Mismatch { recorded, actual }) => {
            let actual = actual
                .map(|signature| signature.hex())
                .unwrap_or_else(|| "<none>".to_owned());
            eprintln!("MISMATCH recorded={} actual={actual}", recorded.hex());
            3
        }
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}

/// Resolve the harness binary for a finding. An explicit `--harness` always
/// wins. Otherwise read the finding's `finding.json` and resolve the built
/// harness from the recorded `fixture_path` (the exact path the auto loop built
/// it at) or, failing that, from `harness_id` against the standard
/// `<work>/auto/<harness_id>/main` layout — trying a couple of work-root
/// candidates relative to the finding directory. Errors naming every path
/// tried, and telling the user to pass `--harness`, when nothing resolves.
fn resolve_harness(finding_dir: &Path, explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(harness) = explicit {
        return Ok(harness);
    }
    let finding_path = finding_dir.join("finding.json");
    let raw: serde_json::Value = std::fs::read(&finding_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| {
            format!(
                "cannot read {} to auto-resolve the harness; pass --harness <path>",
                finding_path.display()
            )
        })?;

    let mut tried: Vec<PathBuf> = Vec::new();

    // 1) `fixture_path` records the exact harness binary the auto loop built and
    // ran when the finding was observed — the most direct resolution.
    if let Some(fixture) = raw.get("fixture_path").and_then(|v| v.as_str()) {
        let candidate = PathBuf::from(fixture);
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    // 2) `harness_id` against `<work>/harnesses/<harness_id>/<leaf>` for a couple of
    // plausible work roots relative to the finding dir (standard layout is
    // `<work>/findings/<F-...>/`, so the work root is the finding dir's
    // grandparent; also try the parent in case findings sit directly under work).
    if let Some(harness_id) = raw.get("harness_id").and_then(|v| v.as_str()) {
        for work in harness_work_roots(finding_dir) {
            for harness_dir in crate::auto::layout::harness_dir_candidates(&work, harness_id) {
                for leaf in ["main", "main_afl", "main.exe", "main_afl.exe"] {
                    let candidate = harness_dir.join(leaf);
                    if candidate.is_file() {
                        return Ok(candidate);
                    }
                    tried.push(candidate);
                }
            }
        }
    }

    let looked = if tried.is_empty() {
        "no fixture_path or harness_id recorded in the finding".to_owned()
    } else {
        tried
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "could not auto-resolve the harness binary for finding {}; looked at: {looked}. \
         Pass --harness <path>.",
        finding_dir.display()
    ))
}

/// Candidate fuzz-work roots for a finding directory, most-likely first. The
/// standard layout nests findings as `<work>/findings/<F-...>/`, so the work
/// root is the finding dir's grandparent; the parent is offered as a fallback
/// for flatter layouts.
fn harness_work_roots(finding_dir: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(grandparent) = finding_dir.parent().and_then(Path::parent) {
        roots.push(grandparent.to_path_buf());
    }
    if let Some(parent) = finding_dir.parent() {
        if !roots.iter().any(|root| root == parent) {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

/// Reproduce an AFL C/C++ finding by invoking the binary with the
/// recorded testcase piped via stdin (AFL persistent-mode harnesses
/// read from \`__AFL_FUZZ_TESTCASE_BUF\` which our template falls back
/// to stdin via \`govfuzz_afl_read_stdin\`). Same MATCH/MISMATCH/error
/// exit codes as the libFuzzer path.
fn replay_c_afl(finding_dir: &Path, harness: &Path) -> i32 {
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let testcase_path = finding_dir.join("testcase.bin");
    let finding_path = finding_dir.join("finding.json");
    let recorded_rule = match fs::read(&finding_path).and_then(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(std::io::Error::other)
    }) {
        Ok(value) => value
            .get("rule_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        Err(error) => {
            eprintln!("read {}: {error}", finding_path.display());
            return 1;
        }
    };
    let Some(recorded_rule) = recorded_rule else {
        eprintln!(
            "finding {} has no rule_id; cannot replay AFL crash without a baseline",
            finding_path.display()
        );
        return 1;
    };
    let input = match fs::read(&testcase_path) {
        Ok(b) => b,
        Err(error) => {
            eprintln!("read {}: {error}", testcase_path.display());
            return 1;
        }
    };

    let mut stdin_replay = Command::new(harness);
    stdin_replay
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = match spawn_harness(&mut stdin_replay) {
        Ok(c) => c,
        Err(error) => {
            eprintln!("spawn {}: {error}", harness.display());
            return 1;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&input);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                eprintln!("poll {}: {error}", harness.display());
                return 1;
            }
        }
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(error) => {
            eprintln!("wait {}: {error}", harness.display());
            return 1;
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual_rule = corpus::parse_sanitizer_report(&stderr).map(|r| r.rule_id);
    match actual_rule {
        Some(rule) if rule == recorded_rule => {
            println!("MATCH");
            0
        }
        Some(rule) => {
            eprintln!("MISMATCH recorded={recorded_rule} actual={rule}");
            3
        }
        None => {
            eprintln!("MISMATCH recorded={recorded_rule} actual=<none>");
            3
        }
    }
}

/// Reproduce a libFuzzer C/C++ finding by invoking the binary with the
/// recorded testcase as argv[1]. Compare the resulting sanitizer
/// rule_id against finding.json's `rule_id`. Exit codes mirror the
/// Ada path: 0 = MATCH, 3 = MISMATCH, 1 = error.
fn replay_c_libfuzzer(finding_dir: &Path, harness: &Path) -> i32 {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let testcase_path = finding_dir.join("testcase.bin");
    let finding_path = finding_dir.join("finding.json");
    let parsed = match fs::read(&finding_path).and_then(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(std::io::Error::other)
    }) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("read {}: {error}", finding_path.display());
            return 1;
        }
    };
    let recorded_rule = parsed
        .get("rule_id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let Some(recorded_rule) = recorded_rule else {
        eprintln!(
            "finding {} has no rule_id; cannot replay libFuzzer crash without a baseline",
            finding_path.display()
        );
        return 1;
    };

    // Slice C: recover the runtime_mode block the auto loop stamped
    // into this finding. Pre-Slice-C findings have no such block —
    // `pass` falls back to "audit" and `env_injected` to an empty
    // map so replay still runs (just without env injection).
    let runtime_mode = parsed.get("runtime_mode").and_then(|v| v.as_object());
    let pass = runtime_mode
        .and_then(|m| m.get("pass"))
        .and_then(|v| v.as_str())
        .unwrap_or("audit");
    let env_injected: Vec<(String, String)> = runtime_mode
        .and_then(|m| m.get("env_injected"))
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();

    let mut cmd = Command::new(harness);
    cmd.arg(&testcase_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // Recreate the runtime environment the auto loop used when this
    // finding was first observed: LD_PRELOAD the runtrace shim,
    // set the same GOVFUZZ_RUNTRACE_MODE, and any env vars the
    // pre-injection phase recorded. Use Command::env (not
    // std::env::set_var) so we don't pollute the parent process
    // env between replays in a single `cargo run` session.
    let shim = crate::auto::shim_path::locate();
    if let Some(s) = &shim {
        cmd.env("LD_PRELOAD", crate::auto::shim_path::ld_preload_value(s));
    }
    cmd.env("GOVFUZZ_RUNTRACE_MODE", pass);
    for (k, v) in &env_injected {
        cmd.env(k, v);
    }

    let mut child = match spawn_harness(&mut cmd) {
        Ok(c) => c,
        Err(error) => {
            eprintln!("spawn {}: {error}", harness.display());
            return 1;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                eprintln!("poll {}: {error}", harness.display());
                return 1;
            }
        }
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(error) => {
            eprintln!("wait {}: {error}", harness.display());
            return 1;
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual_rule = corpus::parse_sanitizer_report(&stderr).map(|r| r.rule_id);
    match actual_rule {
        Some(rule) if rule == recorded_rule => {
            println!("MATCH");
            0
        }
        Some(rule) => {
            eprintln!("MISMATCH recorded={recorded_rule} actual={rule}");
            3
        }
        None => {
            eprintln!("MISMATCH recorded={recorded_rule} actual=<none>");
            3
        }
    }
}

/// Spawn a freshly-written harness, retrying the two transient failures that make
/// an `exec` of a just-created executable fail.
///
/// `ETXTBSY` is the real one: the kernel refuses to exec a file still open for
/// writing anywhere, so building (or copying) a harness and immediately replaying
/// it races the writer's descriptor being closed. It is load- and
/// filesystem-dependent, which is why it surfaced as an occasional CI failure and
/// never locally — `replay` exiting 1 with a bare "spawn ...: Text file busy",
/// which reads like a broken harness rather than a race. `EAGAIN` covers a
/// transient fork failure when the box is briefly out of process slots, which a
/// loaded sweep machine does hit.
///
/// Both mean "try again in a moment", not "this cannot run", so both are retried.
fn spawn_harness(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
    const RETRIES: usize = 40; // ~1s total, far longer than either window lasts
    for _ in 0..RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                if !transient_spawn_failure(&error) {
                    return Err(error);
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    command.spawn()
}

/// Whether a spawn failure is one of the two "try again in a moment" kinds.
///
/// Matched through `ErrorKind` rather than raw errno so this compiles on every
/// target — `libc` is not available on the MSVC build, which is how the first
/// attempt at this broke the Windows job.
fn transient_spawn_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ExecutableFileBusy | std::io::ErrorKind::WouldBlock
    )
}
