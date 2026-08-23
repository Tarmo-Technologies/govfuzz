// SPDX-License-Identifier: Apache-2.0

use corpus::{classify, compute_signature, resolve_handler, Signature};
use event_log::{group_into_testcases, EventReader};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn replay(finding_dir: &Path, harness_path: &Path) -> Result<ReplayResult, ReplayError> {
    let runner = HarnessRunner::direct(harness_path);
    replay_with_runner(finding_dir, &runner)
}

pub fn replay_with_runner(
    finding_dir: &Path,
    runner: &HarnessRunner,
) -> Result<ReplayResult, ReplayError> {
    let ReplayInput { recorded, input } = load_finding(finding_dir)?;
    let computed = signatures_for_input_with_runner(runner, &input)?;

    if computed.contains(&recorded) {
        Ok(ReplayResult::Match)
    } else {
        let actual = computed.first().copied();
        Ok(ReplayResult::Mismatch { recorded, actual })
    }
}

pub(crate) struct ReplayInput {
    pub recorded: Signature,
    pub input: Vec<u8>,
}

pub(crate) fn load_finding(finding_dir: &Path) -> Result<ReplayInput, ReplayError> {
    let finding_path = finding_dir.join("finding.json");
    if !finding_path.is_file() {
        return Err(ReplayError::MissingFinding { path: finding_path });
    }
    let testcase_path = finding_dir.join("testcase.bin");
    if !testcase_path.is_file() {
        return Err(ReplayError::MissingTestcase {
            path: testcase_path,
        });
    }

    let finding: Value = serde_json::from_slice(&fs::read(&finding_path)?)?;
    let recorded = finding
        .get("signature")
        .cloned()
        .ok_or(ReplayError::MissingFinding { path: finding_path })?;
    let recorded: Signature = serde_json::from_value(recorded)?;
    let input = fs::read(&testcase_path)?;

    Ok(ReplayInput { recorded, input })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessRunner {
    harness_path: PathBuf,
    qemu_user: Option<QemuUserRunner>,
    sandbox: SandboxConfig,
    /// Extra paths to read-only-bind into the sandbox (e.g. the LD_PRELOAD
    /// runtrace shim's directory, so the shim still loads and the executable
    /// oracles still fire when the harness runs sandboxed). No effect when the
    /// sandbox is `None`.
    extra_ro_binds: Vec<PathBuf>,
    /// Extra paths to read-write-bind into the sandbox (e.g. the directory of a
    /// runtrace log the harness writes from inside the sandbox). No effect when
    /// the sandbox is `None`.
    extra_rw_binds: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QemuUserRunner {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    mode: SandboxMode,
    strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SandboxMode {
    None,
    Auto,
    Firejail(PathBuf),
    Bubblewrap(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxMetadata {
    pub mode: String,
    pub strict: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<PathBuf>,
}

impl HarnessRunner {
    pub fn direct(harness_path: impl Into<PathBuf>) -> Self {
        Self {
            harness_path: harness_path.into(),
            qemu_user: None,
            sandbox: SandboxConfig::none(),
            extra_ro_binds: Vec::new(),
            extra_rw_binds: Vec::new(),
        }
    }

    pub fn qemu_user(
        program: impl Into<PathBuf>,
        args: Vec<String>,
        harness_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            harness_path: harness_path.into(),
            qemu_user: Some(QemuUserRunner {
                program: program.into(),
                args,
            }),
            sandbox: SandboxConfig::none(),
            extra_ro_binds: Vec::new(),
            extra_rw_binds: Vec::new(),
        }
    }

    pub fn with_sandbox(mut self, sandbox: SandboxConfig) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Add directories to read-only-bind into the sandbox (e.g. the runtrace
    /// shim's directory). Ignored when not sandboxed.
    pub fn with_ro_binds(mut self, binds: impl IntoIterator<Item = PathBuf>) -> Self {
        self.extra_ro_binds.extend(binds);
        self
    }

    /// Add directories to read-write-bind into the sandbox (e.g. the directory
    /// of a runtrace log the harness writes). Ignored when not sandboxed.
    pub fn with_rw_binds(mut self, binds: impl IntoIterator<Item = PathBuf>) -> Self {
        self.extra_rw_binds.extend(binds);
        self
    }

    pub fn harness_path(&self) -> &Path {
        &self.harness_path
    }

    /// The qemu-user / wine emulator prefix (`program`, `args`) when this runner
    /// launches the harness under emulation, or `None` for a direct host run.
    /// Lets the per-spawn (argv-file) execution path prepend the same emulator
    /// prefix the framed path already applies via [`Self::command_for_events`],
    /// so a cross-compiled foreign harness runs under emulation there too.
    pub fn qemu_prefix(&self) -> Option<(&Path, &[String])> {
        self.qemu_user
            .as_ref()
            .map(|qemu_user| (qemu_user.program.as_path(), qemu_user.args.as_slice()))
    }

    pub fn sandbox_metadata(&self) -> SandboxMetadata {
        self.sandbox.metadata()
    }

    fn executable_path(&self) -> &Path {
        match self.sandbox.resolved_tool(false) {
            Some(tool) => tool,
            None => self
                .qemu_user
                .as_ref()
                .map(|qemu_user| qemu_user.program.as_path())
                .unwrap_or(self.harness_path()),
        }
    }

    pub fn command_for_events(&self, events_path: &Path) -> Result<Command, ReplayError> {
        let sandbox = self.sandbox.resolve()?;
        if let Some(qemu_user) = &self.qemu_user {
            Ok(wrap_command(
                sandbox,
                &qemu_user.program,
                qemu_user.args.iter().map(String::as_str),
                self.harness_path.as_path(),
                events_path,
                &self.extra_ro_binds,
                &self.extra_rw_binds,
            ))
        } else {
            Ok(wrap_command(
                sandbox,
                &self.harness_path,
                std::iter::empty::<&str>(),
                self.harness_path.as_path(),
                events_path,
                &self.extra_ro_binds,
                &self.extra_rw_binds,
            ))
        }
    }
}

impl SandboxConfig {
    pub fn none() -> Self {
        Self {
            mode: SandboxMode::None,
            strict: false,
        }
    }

    pub fn auto() -> Self {
        Self {
            mode: SandboxMode::Auto,
            strict: false,
        }
    }

    pub fn strict_auto() -> Self {
        Self {
            mode: SandboxMode::Auto,
            strict: true,
        }
    }

    pub fn firejail(program: impl Into<PathBuf>) -> Self {
        Self {
            mode: SandboxMode::Firejail(program.into()),
            strict: true,
        }
    }

    pub fn bubblewrap(program: impl Into<PathBuf>) -> Self {
        Self {
            mode: SandboxMode::Bubblewrap(program.into()),
            strict: true,
        }
    }

    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    fn metadata(&self) -> SandboxMetadata {
        match &self.mode {
            SandboxMode::None => SandboxMetadata {
                mode: "none".to_owned(),
                strict: self.strict,
                tool: None,
            },
            SandboxMode::Auto => match self.resolve() {
                Ok(Some(resolved)) => resolved.metadata(self.strict),
                Ok(None) | Err(_) => SandboxMetadata {
                    mode: "none".to_owned(),
                    strict: self.strict,
                    tool: None,
                },
            },
            SandboxMode::Firejail(program) => SandboxMetadata {
                mode: "firejail".to_owned(),
                strict: self.strict,
                tool: Some(program.clone()),
            },
            SandboxMode::Bubblewrap(program) => SandboxMetadata {
                mode: "bubblewrap".to_owned(),
                strict: self.strict,
                tool: Some(program.clone()),
            },
        }
    }

    fn resolved_tool(&self, require_exists: bool) -> Option<&Path> {
        match &self.mode {
            SandboxMode::Firejail(program) | SandboxMode::Bubblewrap(program)
                if !require_exists || program.is_file() =>
            {
                Some(program)
            }
            _ => None,
        }
    }

    fn resolve(&self) -> Result<Option<ResolvedSandbox>, ReplayError> {
        match &self.mode {
            SandboxMode::None => Ok(None),
            SandboxMode::Firejail(program) => self.resolve_explicit("firejail", program),
            SandboxMode::Bubblewrap(program) => self.resolve_explicit("bubblewrap", program),
            SandboxMode::Auto => {
                if let Some(program) = find_on_path("bwrap") {
                    match probe_bwrap(&program) {
                        BwrapProbe::NetIsolated => {
                            return Ok(Some(ResolvedSandbox::Bubblewrap {
                                program,
                                unshare_net: true,
                            }));
                        }
                        BwrapProbe::FsOnly => {
                            return Ok(Some(ResolvedSandbox::Bubblewrap {
                                program,
                                unshare_net: false,
                            }));
                        }
                        // bwrap is installed but non-functional here (e.g.
                        // nested container denies user namespaces); fall
                        // through to firejail, then to graceful degradation.
                        BwrapProbe::Broken => {}
                    }
                }
                if let Some(program) = find_on_path("firejail") {
                    return Ok(Some(ResolvedSandbox::Firejail(program)));
                }
                if self.strict {
                    Err(ReplayError::SandboxUnavailable {
                        tool: PathBuf::from("bwrap/firejail"),
                        strict: true,
                    })
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn resolve_explicit(
        &self,
        mode: &'static str,
        program: &Path,
    ) -> Result<Option<ResolvedSandbox>, ReplayError> {
        if !program.is_file() {
            if self.strict {
                return Err(ReplayError::SandboxUnavailable {
                    tool: program.to_path_buf(),
                    strict: true,
                });
            }
            return Ok(None);
        }
        match mode {
            "firejail" => Ok(Some(ResolvedSandbox::Firejail(program.to_path_buf()))),
            "bubblewrap" => match probe_bwrap(program) {
                BwrapProbe::NetIsolated => Ok(Some(ResolvedSandbox::Bubblewrap {
                    program: program.to_path_buf(),
                    unshare_net: true,
                })),
                BwrapProbe::FsOnly => Ok(Some(ResolvedSandbox::Bubblewrap {
                    program: program.to_path_buf(),
                    unshare_net: false,
                })),
                // Installed but non-functional: honour strictness like an
                // absent tool rather than spawning a doomed wrapper per exec.
                BwrapProbe::Broken => {
                    if self.strict {
                        Err(ReplayError::SandboxUnavailable {
                            tool: program.to_path_buf(),
                            strict: true,
                        })
                    } else {
                        Ok(None)
                    }
                }
            },
            _ => unreachable!("known sandbox mode"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedSandbox {
    Firejail(PathBuf),
    Bubblewrap { program: PathBuf, unshare_net: bool },
}

impl ResolvedSandbox {
    fn metadata(&self, strict: bool) -> SandboxMetadata {
        match self {
            Self::Firejail(program) => SandboxMetadata {
                mode: "firejail".to_owned(),
                strict,
                tool: Some(program.clone()),
            },
            Self::Bubblewrap {
                program,
                unshare_net,
            } => SandboxMetadata {
                mode: if *unshare_net {
                    "bubblewrap".to_owned()
                } else {
                    // Filesystem isolation only — this environment denies the
                    // network namespace (loopback config), so egress is not
                    // sealed. Surfaced in metadata so reports don't overstate
                    // the containment that actually held.
                    "bubblewrap-fs-only".to_owned()
                },
                strict,
                tool: Some(program.clone()),
            },
        }
    }
}

/// Result of probing whether `bwrap` actually works in this environment.
/// Binary presence on `PATH` is not enough: nested containers commonly deny
/// unprivileged user namespaces (`setting up uid map: Permission denied`) or
/// the loopback config inside a fresh net namespace (`loopback: Failed
/// RTM_NEWADDR`). The probe runs `bwrap … /bin/true` once and caches the
/// verdict for the process lifetime (the kernel's namespace policy is stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BwrapProbe {
    /// Full isolation works, including `--unshare-net`.
    NetIsolated,
    /// User-namespace + filesystem binds work, but `--unshare-net` fails;
    /// run without it (filesystem containment only).
    FsOnly,
    /// `bwrap` cannot create even a filesystem sandbox here — degrade away.
    Broken,
}

fn probe_bwrap(program: &Path) -> BwrapProbe {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    // Keyed by program path: distinct bwrap binaries can behave differently,
    // and per-path caching keeps the verdict stable for the process while
    // staying deterministic under tests that point at fake wrappers.
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, BwrapProbe>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(verdict) = cache.lock().expect("bwrap probe cache").get(program) {
        return *verdict;
    }
    let verdict = if run_bwrap_probe(program, true) {
        BwrapProbe::NetIsolated
    } else if run_bwrap_probe(program, false) {
        BwrapProbe::FsOnly
    } else {
        BwrapProbe::Broken
    };
    cache
        .lock()
        .expect("bwrap probe cache")
        .insert(program.to_path_buf(), verdict);
    verdict
}

/// Run the static prefix of our real sandbox command against `/bin/true`,
/// optionally with `--unshare-net`. Returns whether it exited cleanly.
fn run_bwrap_probe(program: &Path, unshare_net: bool) -> bool {
    let target = find_on_path("true").unwrap_or_else(|| PathBuf::from("/bin/true"));
    let mut command = Command::new(program);
    command.arg("--die-with-parent");
    if unshare_net {
        command.arg("--unshare-net");
    }
    command.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/bin",
        "/bin",
        "--",
    ]);
    command.arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    matches!(command.status(), Ok(status) if status.success())
}

fn wrap_command<'a>(
    sandbox: Option<ResolvedSandbox>,
    program: &Path,
    args: impl IntoIterator<Item = &'a str>,
    harness_path: &Path,
    events_path: &Path,
    extra_ro_binds: &[PathBuf],
    extra_rw_binds: &[PathBuf],
) -> Command {
    let args = args.into_iter().collect::<Vec<_>>();
    match sandbox {
        Some(ResolvedSandbox::Firejail(firejail)) => {
            let mut command = Command::new(firejail);
            command.args(["--quiet", "--net=none", "--"]);
            command.arg(program);
            command.args(args);
            if program != harness_path {
                command.arg(harness_path);
            }
            command
        }
        Some(ResolvedSandbox::Bubblewrap {
            program: bubblewrap,
            unshare_net,
        }) => {
            let mut command = Command::new(bubblewrap);
            command.arg("--die-with-parent");
            if unshare_net {
                command.arg("--unshare-net");
            }
            command.args([
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/bin",
                "/bin",
            ]);
            let events_dir = events_path.parent().unwrap_or_else(|| Path::new("/tmp"));
            let harness_dir = harness_path.parent().unwrap_or_else(|| Path::new("/"));
            command
                .arg("--bind")
                .arg(events_dir)
                .arg(events_dir)
                .arg("--ro-bind")
                .arg(harness_dir)
                .arg(harness_dir);
            // Read-only-bind extra directories (e.g. the LD_PRELOAD runtrace
            // shim's directory) so the shim still loads and the executable
            // oracles still fire inside the sandbox. Skip ones already covered
            // by the system binds or the harness dir.
            for bind in extra_ro_binds {
                if bind.as_os_str().is_empty()
                    || bind.starts_with("/usr")
                    || bind.starts_with("/bin")
                    || bind == harness_dir
                {
                    continue;
                }
                command.arg("--ro-bind").arg(bind).arg(bind);
            }
            // Read-write-bind extra directories (e.g. a runtrace-log dir the
            // harness writes), unless already covered by the events dir.
            for bind in extra_rw_binds {
                if bind.as_os_str().is_empty() || bind == events_dir {
                    continue;
                }
                command.arg("--bind").arg(bind).arg(bind);
            }
            command.arg("--");
            command.arg(program);
            command.args(args);
            if program != harness_path {
                command.arg(harness_path);
            }
            command
        }
        None => {
            let mut command = Command::new(program);
            command.args(args);
            if program != harness_path {
                command.arg(harness_path);
            }
            command
        }
    }
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

/// Spawn a harness, retrying the two transient failures that make an `exec` of a
/// FRESHLY WRITTEN executable fail.
///
/// `ExecutableFileBusy` (`ETXTBSY`) is the real one: the kernel refuses to exec a
/// file that is still open for writing anywhere, so building — or copying — a
/// harness and immediately replaying it races the writer's descriptor being
/// closed. It is load- and filesystem-dependent, which is why it surfaced as an
/// intermittent CI failure and never locally: `replay` exiting 1 with "failed to
/// start harness ...", which reads like a broken harness rather than a race.
///
/// This is not a test-only concern. govfuzz BUILDS a harness and then replays it,
/// so real runs hit the same window. `WouldBlock` (`EAGAIN`) covers a transient
/// fork failure when a loaded box is briefly out of process slots.
///
/// Matched on `ErrorKind` rather than raw errno so it compiles on every target.
fn spawn_harness(command: &mut Command) -> std::io::Result<std::process::Child> {
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
    const RETRIES: usize = 40; // ~1s total, far longer than either window lasts
    for _ in 0..RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::ExecutableFileBusy | std::io::ErrorKind::WouldBlock
                ) {
                    return Err(error);
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    command.spawn()
}

#[cfg(test)]
pub(crate) fn signatures_for_input(
    harness_path: &Path,
    input: &[u8],
) -> Result<Vec<Signature>, ReplayError> {
    let runner = HarnessRunner::direct(harness_path);
    signatures_for_input_with_runner(&runner, input)
}

pub(crate) fn signatures_for_input_with_runner(
    runner: &HarnessRunner,
    input: &[u8],
) -> Result<Vec<Signature>, ReplayError> {
    let events_path = TempEventFile::new();
    let mut command = runner.command_for_events(events_path.path())?;
    command
        .env("GOVFUZZ_EVENTS_PATH", events_path.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child =
        spawn_harness(&mut command).map_err(|source| ReplayError::HarnessFailedToStart {
            path: runner.executable_path().to_path_buf(),
            source,
        })?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ReplayError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "child stdin not piped",
            ))
        })?;
        // A harness that exits before consuming the whole input closes the pipe,
        // so write_all/flush return BrokenPipe — not an error here (the process
        // ran; its exit + stderr are evaluated below). Only a genuine I/O error
        // propagates.
        for r in [stdin.write_all(input), stdin.flush()] {
            if let Err(error) = r {
                if error.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(ReplayError::Io(error));
                }
            }
        }
        drop(stdin);
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(ReplayError::HarnessNonZeroExit {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let event_bytes = fs::read(events_path.path())?;
    let testcases = group_into_testcases(EventReader::new(event_bytes.as_slice()))?;
    Ok(computed_signatures(&testcases))
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReplayResult {
    Match,
    Mismatch {
        recorded: Signature,
        actual: Option<Signature>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("I/O error during replay")]
    Io(#[from] std::io::Error),
    #[error("JSON error during replay")]
    Json(#[from] serde_json::Error),
    #[error("event log read error during replay")]
    EventLog(#[from] event_log::EventReadError),
    #[error("missing finding.json at {}", path.display())]
    MissingFinding { path: PathBuf },
    #[error("missing testcase.bin at {}", path.display())]
    MissingTestcase { path: PathBuf },
    // The source errno is part of the message, not just the `#[source]` chain: the
    // top-level `error:` line is all a CI log shows, and "failed to start harness
    // <path>" alone cannot distinguish a missing file from a permissions problem
    // from `Text file busy`. That ambiguity is exactly what made an intermittent
    // CI failure here impossible to diagnose from the log.
    #[error("failed to start harness {}: {source}", path.display())]
    HarnessFailedToStart {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sandbox tool unavailable: {} (strict={strict})", tool.display())]
    SandboxUnavailable { tool: PathBuf, strict: bool },
    #[error("harness exited non-zero ({code:?}): {stderr}")]
    HarnessNonZeroExit { code: Option<i32>, stderr: String },
}

fn computed_signatures(testcases: &[event_log::Testcase]) -> Vec<Signature> {
    let mut signatures = Vec::new();
    for testcase in testcases {
        for (handler_index, _) in classify(testcase) {
            let Some(handler) = resolve_handler(testcase, handler_index) else {
                continue;
            };
            signatures.push(compute_signature(testcase, handler.as_ref()));
        }
    }
    signatures
}

fn temp_event_path() -> PathBuf {
    let clock_reading = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    temp_event_path_from(clock_reading)
}

/// Build the event-file path for a given clock reading.
///
/// The pid and the clock alone do not make this unique. Rust runs the tests of
/// one target as threads of a single process, so the pid is shared, and two
/// threads that read the clock inside the same tick get the same path — at
/// which point one replay reads the other's events, and whichever `TempEventFile`
/// drops first deletes the file the other is still about to read. Those are
/// exactly the two shapes this has failed as on CI: a `Mismatch` carrying the
/// other test's signature, and `Io(NotFound)`.
///
/// Clock granularity is not something to rely on here — it is far coarser on
/// some virtualized hosts than the nanosecond unit suggests, which is why this
/// reproduces on CI and effectively never on a developer box. The counter makes
/// uniqueness within the process independent of the clock entirely.
///
/// Deliberately not called a nonce: it is a filename disambiguator with no
/// secrecy or unpredictability requirement, and naming it one both overstates
/// its role and trips CodeQL's `rust/hard-coded-cryptographic-value`, which
/// treats any literal reaching a value by that name as a critical finding.
fn temp_event_path_from(clock_reading: u128) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "govfuzz-replay-events-{}-{clock_reading}-{sequence}.bin",
        std::process::id()
    ))
}

struct TempEventFile {
    path: PathBuf,
}

impl TempEventFile {
    fn new() -> Self {
        Self {
            path: temp_event_path(),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempEventFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        computed_signatures, replay, signatures_for_input, signatures_for_input_with_runner,
        temp_event_path, temp_event_path_from, HarnessRunner, ReplayError, SandboxConfig,
    };
    use corpus::{compute_signature, Signature};
    use event_log::{HandlerEvent, Testcase, TopLevelEvent};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    static REPLAY_EVENT_FILE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn computed_signatures_returns_empty_for_empty_testcases() {
        assert_eq!(computed_signatures(&[]), Vec::<Signature>::new());
    }

    #[test]
    fn computed_signatures_includes_unhandled_top_level_escape() {
        // An exception that escaped the target unhandled is a genuine fault and
        // must get a signature so a real-fault finding can be replayed/matched.
        let testcase = Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs: Vec::new(),
            handlers: Vec::new(),
            raises: Vec::new(),
            top_level: Some(TopLevelEvent {
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "escaped".to_owned(),
            }),
            end: None,
            mocks: Vec::new(),
        };

        assert_eq!(computed_signatures(&[testcase]).len(), 1);
    }

    #[test]
    fn computed_signatures_returns_some_for_handler_testcase() {
        assert_eq!(computed_signatures(&[handler_testcase()]).len(), 1);
    }

    #[test]
    fn temp_event_path_uses_replay_event_name() {
        let path = temp_event_path();

        assert!(path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("govfuzz-replay-events-")));
    }

    #[test]
    fn temp_event_path_is_unique_when_the_clock_does_not_advance() {
        // Pin the clock reading rather than racing threads, so this is a
        // deterministic red before the fix instead of a flaky one: two replays
        // landing in the same tick must still get separate files, or they read
        // and delete each other's events.
        let first = temp_event_path_from(1_700_000_000_000_000_000);
        let second = temp_event_path_from(1_700_000_000_000_000_000);

        assert_ne!(
            first, second,
            "two replays reading the clock in the same tick must not share an event file"
        );
    }

    #[test]
    fn concurrent_temp_event_paths_are_all_distinct() {
        // The real shape: tests of one target are threads of one process, so
        // the pid is shared and only this function keeps them apart.
        let threads = (0..16)
            .map(|_| std::thread::spawn(temp_event_path))
            .collect::<Vec<_>>();
        let paths = threads
            .into_iter()
            .map(|handle| handle.join().expect("path thread joins"))
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(paths.len(), 16, "event paths collided across threads");
    }

    #[test]
    fn replay_pipes_testcase_bytes_to_harness_stdin() {
        let _guard = replay_event_file_lock();
        let root = temp_dir("stdin-pipe");
        let capture_path = root.join("stdin.bin");
        let harness_path = compile_stdin_capture_harness(&root, &capture_path);
        let testcase = b"govfuzz-stdin-marker\0mismatch\n".to_vec();
        let finding_dir = write_finding(&root, &testcase, canonical_signature());

        let result = replay(&finding_dir, &harness_path);

        assert!(matches!(result, Ok(super::ReplayResult::Match)));
        assert_eq!(fs::read(capture_path).unwrap(), testcase);
    }

    #[test]
    fn qemu_user_runner_wraps_harness_and_preserves_replay_contract() {
        let _guard = replay_event_file_lock();
        let root = temp_dir("qemu-user-runner");
        let capture_path = root.join("stdin.bin");
        let qemu_log_path = root.join("qemu-argv.txt");
        let harness_path = compile_stdin_capture_harness(&root, &capture_path);
        let qemu_path = compile_fake_qemu_user(&root, &qemu_log_path);
        let runner = HarnessRunner::qemu_user(
            qemu_path,
            vec!["-L".to_owned(), "/opt/aarch64-sysroot".to_owned()],
            harness_path.clone(),
        );
        let testcase = b"govfuzz-qemu-stdin-marker\n".to_vec();

        let signatures = signatures_for_input_with_runner(&runner, &testcase).unwrap();

        assert_eq!(signatures, vec![canonical_signature()]);
        assert_eq!(fs::read(capture_path).unwrap(), testcase);
        let qemu_argv = fs::read_to_string(qemu_log_path).unwrap();
        assert_eq!(
            qemu_argv,
            format!("-L\n/opt/aarch64-sysroot\n{}\n", harness_path.display())
        );
    }

    #[test]
    fn firejail_sandbox_runner_wraps_harness_and_preserves_replay_contract() {
        let _guard = replay_event_file_lock();
        let root = temp_dir("firejail-sandbox-runner");
        let capture_path = root.join("stdin.bin");
        let sandbox_log_path = root.join("sandbox-argv.txt");
        let harness_path = compile_stdin_capture_harness(&root, &capture_path);
        let firejail_path = compile_fake_sandbox_wrapper(&root, &sandbox_log_path);
        let runner = HarnessRunner::direct(harness_path.clone())
            .with_sandbox(SandboxConfig::firejail(firejail_path));
        let testcase = b"govfuzz-sandbox-stdin-marker\n".to_vec();

        let signatures = signatures_for_input_with_runner(&runner, &testcase).unwrap();

        assert_eq!(signatures, vec![canonical_signature()]);
        assert_eq!(fs::read(capture_path).unwrap(), testcase);
        let sandbox_argv = fs::read_to_string(sandbox_log_path).unwrap();
        assert!(sandbox_argv.contains("--net=none\n"));
        assert!(sandbox_argv.contains("--\n"));
        assert!(sandbox_argv.contains(&format!("{}\n", harness_path.display())));
    }

    #[test]
    fn bubblewrap_installed_but_broken_degrades_to_direct_run_when_non_strict() {
        // Regression: a bwrap that is present on PATH but non-functional here
        // (e.g. nested container denies user namespaces) must NOT fail the run
        // under non-strict auto/default sandboxing — it must degrade to a
        // direct, unsandboxed execution so fuzzing still proceeds.
        let _guard = replay_event_file_lock();
        let root = temp_dir("bwrap-broken-degrade");
        let capture_path = root.join("stdin.bin");
        let log_path = root.join("bwrap-argv.txt");
        let harness_path = compile_stdin_capture_harness(&root, &capture_path);
        let fake = compile_fake_bwrap(&root, "fake_bwrap_broken", false, true, &log_path);
        let runner = HarnessRunner::direct(harness_path.clone())
            .with_sandbox(SandboxConfig::bubblewrap(fake).with_strict(false));
        let testcase = b"govfuzz-broken-bwrap-marker\n".to_vec();

        let signatures = signatures_for_input_with_runner(&runner, &testcase).unwrap();

        assert_eq!(signatures, vec![canonical_signature()]);
        // The harness ran directly: it captured stdin even though the fake
        // wrapper never reached its exec path.
        assert_eq!(fs::read(capture_path).unwrap(), testcase);
        assert!(
            !log_path.exists(),
            "broken bwrap must never wrap the harness"
        );
    }

    #[test]
    fn bubblewrap_installed_but_broken_errors_when_strict() {
        // The strict guarantee still holds: if the user demanded isolation and
        // the tool cannot deliver it, surface the failure rather than silently
        // running unsandboxed.
        let root = temp_dir("bwrap-broken-strict");
        let log_path = root.join("bwrap-argv.txt");
        let fake = compile_fake_bwrap(&root, "fake_bwrap_broken_strict", false, true, &log_path);
        let runner = HarnessRunner::direct(root.join("harness"))
            .with_sandbox(SandboxConfig::bubblewrap(fake.clone()));

        let error = signatures_for_input_with_runner(&runner, b"candidate").unwrap_err();

        assert!(matches!(
            error,
            ReplayError::SandboxUnavailable { strict: true, .. }
        ));
    }

    #[test]
    fn bubblewrap_drops_unshare_net_when_netns_denied() {
        // Regression: when only the network namespace is denied (loopback
        // config fails) but filesystem isolation works, keep the sandbox and
        // drop --unshare-net rather than abandoning containment entirely.
        let _guard = replay_event_file_lock();
        let root = temp_dir("bwrap-fs-only");
        let capture_path = root.join("stdin.bin");
        let log_path = root.join("bwrap-argv.txt");
        let harness_path = compile_stdin_capture_harness(&root, &capture_path);
        let fake = compile_fake_bwrap(&root, "fake_bwrap_fsonly", true, false, &log_path);
        let runner = HarnessRunner::direct(harness_path.clone())
            .with_sandbox(SandboxConfig::bubblewrap(fake));
        let testcase = b"govfuzz-fs-only-marker\n".to_vec();

        let signatures = signatures_for_input_with_runner(&runner, &testcase).unwrap();

        assert_eq!(signatures, vec![canonical_signature()]);
        assert_eq!(fs::read(capture_path).unwrap(), testcase);
        // The harness DID run through the wrapper (FS isolation retained)...
        let argv = fs::read_to_string(&log_path).unwrap();
        let harness_arg = harness_path.to_str().unwrap();
        assert!(
            argv.lines().any(|line| line == harness_arg),
            "harness must be wrapped; argv:\n{argv}"
        );
        // ...but the wrapped invocation dropped the unworkable net unshare.
        assert!(
            !argv.lines().any(|line| line == "--unshare-net"),
            "wrapped run must drop --unshare-net; argv:\n{argv}"
        );
    }

    #[test]
    fn strict_sandbox_runner_reports_missing_sandbox_tool() {
        let root = temp_dir("missing-strict-sandbox");
        let runner = HarnessRunner::direct(root.join("harness"))
            .with_sandbox(SandboxConfig::firejail(root.join("missing-firejail")));

        let error = signatures_for_input_with_runner(&runner, b"candidate").unwrap_err();

        assert!(matches!(
            error,
            ReplayError::SandboxUnavailable { tool, strict: true }
                if tool == root.join("missing-firejail")
        ));
    }

    #[test]
    fn signatures_for_input_removes_event_file_on_nonzero_exit() {
        let _guard = replay_event_file_lock();
        let root = temp_dir("event-cleanup");
        let harness_path = compile_nonzero_event_harness(&root);
        let before = replay_event_files();

        let error = signatures_for_input(&harness_path, b"candidate").unwrap_err();

        assert!(matches!(error, ReplayError::HarnessNonZeroExit { .. }));
        assert_eq!(replay_event_files(), before);
    }

    fn canonical_signature() -> Signature {
        let testcase = handler_testcase();
        compute_signature(&testcase, &testcase.handlers[0])
    }

    fn write_finding(root: &Path, input: &[u8], signature: Signature) -> PathBuf {
        let finding_dir = root.join("findings/F-0000-test");
        fs::create_dir_all(&finding_dir).unwrap();
        fs::write(finding_dir.join("testcase.bin"), input).unwrap();
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({ "signature": signature })).unwrap(),
        )
        .unwrap();
        finding_dir
    }

    fn compile_stdin_capture_harness(root: &Path, capture_path: &Path) -> PathBuf {
        let source_path = root.join("stdin_capture_harness.rs");
        let harness_path = root.join("stdin_capture_harness");
        let capture_literal = serde_json::to_string(capture_path.to_str().unwrap()).unwrap();
        fs::write(
            &source_path,
            format!(
                r#"
use std::io::Read;

fn main() -> std::io::Result<()> {{
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    std::fs::write({capture_literal}, input)?;
    let event_path = std::env::var("GOVFUZZ_EVENTS_PATH").map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    push_begin(&mut bytes, 1);
    push_target(&mut bytes, 0x42);
    push_crumb(&mut bytes, 1);
    push_handler(&mut bytes);
    push_end(&mut bytes, 0);
    std::fs::write(event_path, bytes)
}}

fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {{
    bytes.push(1);
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}}

fn push_end(bytes: &mut Vec<u8>, result_class: u8) {{
    bytes.push(2);
    bytes.push(result_class);
}}

fn push_crumb(bytes: &mut Vec<u8>, id: u32) {{
    bytes.push(3);
    bytes.extend_from_slice(&id.to_le_bytes());
}}

fn push_target(bytes: &mut Vec<u8>, id: u32) {{
    bytes.push(4);
    bytes.extend_from_slice(&id.to_le_bytes());
}}

fn push_handler(bytes: &mut Vec<u8>) {{
    bytes.push(5);
    push_string(bytes, "CONSTRAINT_ERROR");
    push_string(bytes, "bad input");
    push_string(bytes, "pkg.adb");
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0x42_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
}}

fn push_string(bytes: &mut Vec<u8>, value: &str) {{
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}}
"#
            ),
        )
        .unwrap();
        let output = Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&harness_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        harness_path
    }

    fn compile_fake_qemu_user(root: &Path, qemu_log_path: &Path) -> PathBuf {
        let source_path = root.join("fake_qemu_user.rs");
        let qemu_path = root.join("fake_qemu_user");
        let log_literal = serde_json::to_string(qemu_log_path.to_str().unwrap()).unwrap();
        fs::write(
            &source_path,
            format!(
                r#"
fn main() -> std::io::Result<()> {{
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    std::fs::write({log_literal}, format!("{{}}\n", args.join("\n")))?;
    let Some(harness_path) = args.last() else {{
        std::process::exit(125);
    }};
    let status = std::process::Command::new(harness_path)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}}
"#
            ),
        )
        .unwrap();
        let output = Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&qemu_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        qemu_path
    }

    fn compile_fake_sandbox_wrapper(root: &Path, log_path: &Path) -> PathBuf {
        let source_path = root.join("fake_sandbox.rs");
        let sandbox_path = root.join("fake_firejail");
        let log_literal = serde_json::to_string(log_path.to_str().unwrap()).unwrap();
        fs::write(
            &source_path,
            format!(
                r#"
fn main() -> std::io::Result<()> {{
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    std::fs::write({log_literal}, format!("{{}}\n", args.join("\n")))?;
    let Some(separator) = args.iter().position(|arg| arg == "--") else {{
        std::process::exit(125);
    }};
    let command = args.get(separator + 1).cloned().unwrap_or_default();
    let command_args = &args[(separator + 2)..];
    let status = std::process::Command::new(command)
        .args(command_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}}
"#
            ),
        )
        .unwrap();
        let output = Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&sandbox_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        sandbox_path
    }

    /// Compile a stand-in `bwrap` that models an environment-restricted real
    /// one: `always_fail` simulates denied user namespaces (installed but
    /// non-functional); `fail_on_unshare_net` simulates a denied network
    /// namespace (loopback config). On the success path it logs its argv and
    /// execs the command after `--`, like real bwrap.
    fn compile_fake_bwrap(
        root: &Path,
        name: &str,
        fail_on_unshare_net: bool,
        always_fail: bool,
        log_path: &Path,
    ) -> PathBuf {
        let source_path = root.join(format!("{name}.rs"));
        let bin_path = root.join(name);
        let log_literal = serde_json::to_string(log_path.to_str().unwrap()).unwrap();
        fs::write(
            &source_path,
            format!(
                r#"
fn main() -> std::io::Result<()> {{
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if {always_fail} {{ std::process::exit(1); }}
    if {fail_on_unshare_net} && args.iter().any(|arg| arg == "--unshare-net") {{
        std::process::exit(1);
    }}
    std::fs::write({log_literal}, format!("{{}}\n", args.join("\n")))?;
    let Some(separator) = args.iter().position(|arg| arg == "--") else {{
        std::process::exit(125);
    }};
    let command = args.get(separator + 1).cloned().unwrap_or_default();
    let command_args = &args[(separator + 2)..];
    let status = std::process::Command::new(command)
        .args(command_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}}
"#
            ),
        )
        .unwrap();
        let output = Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&bin_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        bin_path
    }

    fn compile_nonzero_event_harness(root: &Path) -> PathBuf {
        let source_path = root.join("nonzero_event_harness.rs");
        let harness_path = root.join("nonzero_event_harness");
        fs::write(
            &source_path,
            r#"
use std::io::Read;

fn main() -> std::io::Result<()> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let event_path = std::env::var("GOVFUZZ_EVENTS_PATH").map_err(std::io::Error::other)?;
    std::fs::write(event_path, b"partial-event-log")?;
    std::process::exit(2);
}
"#,
        )
        .unwrap();
        let output = Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&harness_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        harness_path
    }

    fn replay_event_file_lock() -> MutexGuard<'static, ()> {
        REPLAY_EVENT_FILE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn replay_event_files() -> Vec<PathBuf> {
        let prefix = format!("govfuzz-replay-events-{}-", std::process::id());
        let mut paths = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-replay-unit-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn handler_testcase() -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs: vec![1],
            handlers: vec![HandlerEvent {
                sequence_index: 3,
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: 9,
                last_breadcrumb: 1,
                target_id: 0x42,
                testcase_id: 1,
            }],
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }
}
