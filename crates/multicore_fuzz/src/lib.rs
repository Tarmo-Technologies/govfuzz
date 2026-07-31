// SPDX-License-Identifier: Apache-2.0

//! Multi-core fuzzing orchestrator.
//!
//! Spawns N parallel `govfuzz fuzz` worker subprocesses, all
//! pointed at the same work directory. Each worker writes its
//! own slice of the corpus + findings; the orchestrator collates
//! findings across workers and reports an aggregate `MulticoreSummary`.
//!
//! The orchestrator seeds every worker from a central
//! `corpus/<harness>/queue`, gives each worker a private work tree,
//! then imports newly discovered queue entries back into the central
//! queue and writes a sync manifest. That is still lighter than an
//! AFL master/slave protocol, but it gives offline campaigns a real
//! shared-corpus handoff between worker runs and CI invocations.
//!
//! Tracks issue #292.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticoreConfig {
    /// Govfuzz work directory containing build/<harness_id>/.
    pub work_dir: PathBuf,
    pub harness_id: String,
    pub workers: WorkerCount,
    /// Per-worker iteration budget. None = run until time budget
    /// elapses.
    pub per_worker_iterations: Option<u64>,
    /// Wall-clock budget for the whole campaign.
    pub time_budget: Duration,
    /// Path to the govfuzz binary the orchestrator should spawn.
    /// `which` lookup is the caller's responsibility.
    pub govfuzz_bin: PathBuf,
    /// Per-worker environment overrides keyed by worker_id (e.g.
    /// `ASAN_OPTIONS` / `MSAN_OPTIONS` / `UBSAN_OPTIONS` for the
    /// sanitizer-composition flow from #296). When the per-worker
    /// map is empty the worker inherits the orchestrator's env.
    pub per_worker_env: Vec<Vec<(String, String)>>,
    /// Extra argv passed through to every `govfuzz fuzz` worker after
    /// the orchestrator-owned worker budget, seed, and harness args.
    pub extra_worker_args: Vec<String>,
    /// Grace period beyond `time_budget` before the orchestrator
    /// SIGKILLs workers that haven't exited. Only enforced when
    /// `time_budget` is non-zero — the worker is supposed to honour
    /// `--time` on its own and this is a backstop for hangs.
    /// `None` defaults to 5 seconds.
    pub kill_grace: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCount {
    /// Use `available_parallelism() - 1` workers, capped at 1+.
    Auto,
    /// Use a fixed count. Must be >= 1.
    Fixed(u32),
}

impl WorkerCount {
    pub fn resolve(self) -> Result<u32, MulticoreError> {
        match self {
            WorkerCount::Auto => {
                let cpus = std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1);
                Ok(cpus.saturating_sub(1).max(1))
            }
            WorkerCount::Fixed(0) => Err(MulticoreError::InvalidWorkerCount),
            WorkerCount::Fixed(n) => Ok(n),
        }
    }
}

/// Spawn a worker, retrying the two transient failures that make an `exec` of a
/// FRESHLY WRITTEN executable fail.
///
/// `ExecutableFileBusy` (`ETXTBSY`): the kernel refuses to exec a file that is
/// still open for writing ANYWHERE. govfuzz builds a harness and then fuzzes it,
/// and a multicore run forks several workers at once — a child forked by one
/// thread inherits a write descriptor another thread has not closed yet, so the
/// exec of that path fails. Load- and filesystem-dependent, which is why it shows
/// up as an intermittent CI failure and never locally.
///
/// `replay` was given this treatment in 0.2.27 (see `replay_min::spawn_harness`);
/// the multicore worker spawn has the same window and was missed, surfacing as
/// `worker 0 failed to spawn: Text file busy` on a loaded runner.
///
/// Matched on `ErrorKind` rather than raw errno so it compiles on every target.
fn spawn_worker(command: &mut Command) -> std::io::Result<std::process::Child> {
    const RETRY_DELAY: Duration = Duration::from_millis(25);
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

#[derive(Debug, thiserror::Error)]
pub enum MulticoreError {
    #[error("work dir does not exist: {0}")]
    WorkDirMissing(PathBuf),
    #[error("worker count must be at least 1")]
    InvalidWorkerCount,
    #[error("govfuzz binary not found: {0}")]
    BinMissing(PathBuf),
    #[error("worker {worker_id} failed to spawn: {source}")]
    WorkerSpawn {
        worker_id: u32,
        source: std::io::Error,
    },
    #[error("worker {worker_id} exited non-zero ({exit_code:?})")]
    WorkerFailed {
        worker_id: u32,
        exit_code: Option<i32>,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MulticoreSummary {
    pub harness_id: String,
    pub workers_started: u32,
    pub workers_completed: u32,
    pub total_findings: usize,
    pub unique_findings: usize,
    pub campaign_dir: PathBuf,
    pub sync_manifest_path: PathBuf,
    pub sync: CorpusSyncReport,
    pub per_worker: Vec<WorkerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReport {
    pub worker_id: u32,
    pub work_dir: PathBuf,
    pub exit_code: Option<i32>,
    pub findings_count: usize,
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSyncReport {
    pub shared_queue: PathBuf,
    pub seed_inputs_loaded: usize,
    pub imported_inputs: usize,
    pub duplicate_inputs: usize,
}

/// Spawn `workers` parallel fuzz subprocesses and wait for all of
/// them to terminate. Each worker gets its own `work_dir`/worker-N/
/// subdirectory (a copy of the base build tree); findings are
/// collated at the end.
pub fn run_multicore(config: &MulticoreConfig) -> Result<MulticoreSummary, MulticoreError> {
    if !config.work_dir.is_dir() {
        return Err(MulticoreError::WorkDirMissing(config.work_dir.clone()));
    }
    if !config.govfuzz_bin.is_file() {
        return Err(MulticoreError::BinMissing(config.govfuzz_bin.clone()));
    }
    let workers = config.workers.resolve()?;
    let campaign_dir = config
        .work_dir
        .join("fuzz_campaigns")
        .join(&config.harness_id);
    let shared_queue = config
        .work_dir
        .join("corpus")
        .join(&config.harness_id)
        .join("queue");
    std::fs::create_dir_all(&campaign_dir)?;
    std::fs::create_dir_all(&shared_queue)?;
    let shared_seed_files = queue_seed_files(&shared_queue)?;
    let mut children: Vec<(u32, PathBuf, Vec<String>, std::process::Child)> = Vec::new();
    let worker_namespace = sanitize_worker_namespace(&config.harness_id);
    for worker_id in 0..workers {
        // Namespace per harness so two campaigns sharing one work_dir (e.g.
        // fuzzing two harnesses at once) don't collide on `worker-N` dirs and
        // cross-contaminate each other's corpus/findings.
        let worker_dir = config
            .work_dir
            .join(format!("worker-{worker_namespace}-{worker_id}"));
        copy_build_tree(&config.work_dir, &worker_dir, &config.harness_id)?;
        copy_shared_queue_to_worker(&shared_queue, &worker_dir, &config.harness_id)?;
        let worker_env = env_for_worker(&config.per_worker_env, worker_id);
        let env_keys = worker_env
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut cmd = Command::new(&config.govfuzz_bin);
        cmd.arg("fuzz")
            .arg(&worker_dir)
            .arg("--harness")
            .arg(&config.harness_id)
            .arg("--rng-seed")
            .arg(format!("{}", 0x4756_4655_5a5a_u64 ^ (worker_id as u64)))
            .env("GOVFUZZ_WORKER_ID", worker_id.to_string())
            .env("GOVFUZZ_SHARED_CORPUS_DIR", &shared_queue)
            .env("GOVFUZZ_CAMPAIGN_DIR", &campaign_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(iterations) = config.per_worker_iterations {
            cmd.arg("--iterations").arg(iterations.to_string());
        }
        if !config.time_budget.is_zero() {
            cmd.arg("--time")
                .arg(format!("{}s", config.time_budget.as_secs()));
        }
        for seed_file in &shared_seed_files {
            cmd.arg("--seed-file").arg(seed_file);
        }
        for arg in &config.extra_worker_args {
            cmd.arg(arg);
        }
        for (k, v) in &worker_env {
            cmd.env(k, v);
        }
        let child = spawn_worker(&mut cmd)
            .map_err(|source| MulticoreError::WorkerSpawn { worker_id, source })?;
        children.push((worker_id, worker_dir, env_keys, child));
    }
    let workers_started = children.len() as u32;
    let mut workers_completed = 0u32;
    let mut per_worker: Vec<WorkerReport> = Vec::new();
    let start = Instant::now();
    let kill_grace = config.kill_grace.unwrap_or(Duration::from_secs(5));
    let enforce_deadline = !config.time_budget.is_zero();
    let mut pending = children;
    while !pending.is_empty() {
        let should_kill =
            enforce_deadline && start.elapsed() > config.time_budget.saturating_add(kill_grace);
        let mut still_pending = Vec::with_capacity(pending.len());
        for (worker_id, worker_dir, env_keys, mut child) in pending.drain(..) {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        workers_completed += 1;
                    }
                    let findings_count = count_findings(&worker_dir);
                    per_worker.push(WorkerReport {
                        worker_id,
                        work_dir: worker_dir,
                        exit_code: status.code(),
                        findings_count,
                        env_keys,
                    });
                }
                Ok(None) => {
                    if should_kill {
                        let _ = child.kill();
                        let _ = child.wait();
                        let findings_count = count_findings(&worker_dir);
                        per_worker.push(WorkerReport {
                            worker_id,
                            work_dir: worker_dir,
                            exit_code: None,
                            findings_count,
                            env_keys,
                        });
                    } else {
                        still_pending.push((worker_id, worker_dir, env_keys, child));
                    }
                }
                Err(error) => return Err(MulticoreError::Io(error)),
            }
        }
        pending = still_pending;
        if !pending.is_empty() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    let total_findings: usize = per_worker.iter().map(|r| r.findings_count).sum();
    let unique_findings = unique_finding_count(&per_worker);
    let sync = sync_worker_corpora(
        &config.work_dir,
        &config.harness_id,
        &per_worker,
        shared_seed_files.len(),
        &shared_queue,
    )?;
    let sync_manifest_path = config
        .work_dir
        .join("fuzz_campaigns")
        .join(format!("{}-sync-manifest.json", config.harness_id));

    let summary = MulticoreSummary {
        harness_id: config.harness_id.clone(),
        workers_started,
        workers_completed,
        total_findings,
        unique_findings,
        campaign_dir,
        sync_manifest_path,
        sync,
        per_worker,
    };
    write_campaign_artifacts(&config.work_dir, &summary)?;
    Ok(summary)
}

fn env_for_worker(envs: &[Vec<(String, String)>], worker_id: u32) -> Vec<(String, String)> {
    if envs.is_empty() {
        Vec::new()
    } else {
        envs[(worker_id as usize) % envs.len()].clone()
    }
}

fn queue_seed_files(shared_queue: &Path) -> Result<Vec<PathBuf>, MulticoreError> {
    let mut files = Vec::new();
    if !shared_queue.is_dir() {
        return Ok(files);
    }
    for entry in std::fs::read_dir(shared_queue)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn copy_shared_queue_to_worker(
    shared_queue: &Path,
    worker_dir: &Path,
    harness_id: &str,
) -> Result<(), MulticoreError> {
    if !shared_queue.is_dir() {
        return Ok(());
    }
    let worker_queue = worker_dir.join("corpus").join(harness_id).join("queue");
    std::fs::create_dir_all(&worker_queue)?;
    for seed_file in queue_seed_files(shared_queue)? {
        let Some(name) = seed_file.file_name() else {
            continue;
        };
        std::fs::copy(&seed_file, worker_queue.join(name))?;
    }
    Ok(())
}

fn sync_worker_corpora(
    work_dir: &Path,
    harness_id: &str,
    per_worker: &[WorkerReport],
    seed_inputs_loaded: usize,
    shared_queue: &Path,
) -> Result<CorpusSyncReport, MulticoreError> {
    std::fs::create_dir_all(shared_queue)?;
    let mut seen = HashSet::<Vec<u8>>::new();
    for seed_file in queue_seed_files(shared_queue)? {
        if let Ok(bytes) = std::fs::read(seed_file) {
            seen.insert(bytes);
        }
    }

    let mut imported_inputs = 0_usize;
    let mut duplicate_inputs = 0_usize;
    for worker in per_worker {
        let worker_queue = worker
            .work_dir
            .join("corpus")
            .join(harness_id)
            .join("queue");
        for queue_file in queue_seed_files(&worker_queue)? {
            let bytes = std::fs::read(&queue_file)?;
            if !seen.insert(bytes.clone()) {
                duplicate_inputs += 1;
                continue;
            }
            let Some(name) = queue_file.file_name() else {
                continue;
            };
            let mut destination = shared_queue.join(name);
            if destination.exists() {
                destination = shared_queue.join(format!(
                    "worker-{}-{}",
                    worker.worker_id,
                    name.to_string_lossy()
                ));
            }
            std::fs::write(destination, bytes)?;
            imported_inputs += 1;
        }
    }

    Ok(CorpusSyncReport {
        shared_queue: work_dir.join("corpus").join(harness_id).join("queue"),
        seed_inputs_loaded,
        imported_inputs,
        duplicate_inputs,
    })
}

fn write_campaign_artifacts(
    work_dir: &Path,
    summary: &MulticoreSummary,
) -> Result<(), MulticoreError> {
    let runs_dir = work_dir.join("fuzz_campaigns");
    std::fs::create_dir_all(&runs_dir)?;
    let latest = runs_dir.join(format!("{}-latest.json", summary.harness_id));
    std::fs::write(
        &latest,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )?;
    let manifest = serde_json::json!({
        "schema_version": 1,
        "harness_id": summary.harness_id,
        "workers_started": summary.workers_started,
        "workers_completed": summary.workers_completed,
        "total_findings": summary.total_findings,
        "unique_findings": summary.unique_findings,
        "campaign_dir": summary.campaign_dir,
        "sync": summary.sync,
        "per_worker": summary.per_worker,
    });
    std::fs::write(
        &summary.sync_manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    Ok(())
}

fn copy_build_tree(
    src_work: &Path,
    dst_work: &Path,
    harness_id: &str,
) -> Result<(), MulticoreError> {
    let dst_build = dst_work.join("build").join(harness_id);
    if dst_build.is_dir() {
        // Already prepared on a previous run; reuse.
        return Ok(());
    }
    let src_build = src_work.join("build").join(harness_id);
    if !src_build.is_dir() {
        // Caller didn't pre-stage anything; create the dst skeleton
        // and let the per-worker fuzz subcommand error out clearly.
        std::fs::create_dir_all(&dst_build).map_err(MulticoreError::Io)?;
        return Ok(());
    }
    std::fs::create_dir_all(dst_build.parent().unwrap()).map_err(MulticoreError::Io)?;
    copy_dir_recursive(&src_build, &dst_build)?;
    copy_line_map_sidecars(src_work, dst_work);
    Ok(())
}

/// Map a harness id to a filesystem-safe worker-directory namespace
/// (alphanumeric / `-` / `_` kept; anything else collapsed to `_`).
fn sanitize_worker_namespace(harness_id: &str) -> String {
    let mapped: String = harness_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() {
        "harness".to_owned()
    } else {
        mapped
    }
}

/// Copy the instrumented→original line-map sidecars into the worker tree so
/// worker-emitted findings remap exception lines to the original source just
/// like the single-process path. Best-effort: absence simply skips remapping.
fn copy_line_map_sidecars(src_work: &Path, dst_work: &Path) {
    let src_dir = src_work.join("src_instrumented");
    let dst_dir = dst_work.join("src_instrumented");
    let Ok(entries) = std::fs::read_dir(&src_dir) else {
        return;
    };
    let _ = std::fs::create_dir_all(&dst_dir);
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".govfuzz-lines.json") {
            let _ = std::fs::copy(entry.path(), dst_dir.join(&name));
        }
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), MulticoreError> {
    std::fs::create_dir_all(dst).map_err(MulticoreError::Io)?;
    for entry in std::fs::read_dir(src).map_err(MulticoreError::Io)? {
        let entry = entry.map_err(MulticoreError::Io)?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().map_err(MulticoreError::Io)?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to).map_err(MulticoreError::Io)?;
            #[cfg(unix)]
            {
                if let Ok(meta) = std::fs::metadata(&from) {
                    let perms = meta.permissions();
                    let _ = std::fs::set_permissions(&to, perms);
                }
            }
        }
    }
    Ok(())
}

/// The `<SAN>_OPTIONS` key for a sanitizer.
pub fn sanitizer_options_key(s: Sanitizer) -> &'static str {
    match s {
        Sanitizer::Asan => "ASAN_OPTIONS",
        Sanitizer::Msan => "MSAN_OPTIONS",
        Sanitizer::Ubsan => "UBSAN_OPTIONS",
        Sanitizer::Tsan => "TSAN_OPTIONS",
        Sanitizer::Lsan => "LSAN_OPTIONS",
    }
}

/// The runtime keys govfuzz must set on every armed `<SAN>_OPTIONS`:
/// `abort_on_error`/`halt_on_error` turn a sanitizer report into a fault the
/// engine saves as a finding (instead of a printed-and-ignored warning), and
/// `detect_leaks` arms LSan. These MUST win over any operator value.
///
/// `symbolize=0` deliberately does NOT belong here. AFL++ v4 refuses to start
/// when it inherits a custom `ASAN_OPTIONS` without it, so the afl-fuzz
/// invocation sets it on its own child env — but a BUILTIN-engine child must
/// keep symbolizing, because the file and line in a sanitizer report are what
/// join a crash to the static finding at the same line. Setting it globally to
/// appease AFL silently downgraded every fuzz-confirmed static finding to
/// `fuzz_exercised`, which is the one result govfuzz exists to produce.
const REQUIRED_SANITIZER_OPTIONS: &str = "abort_on_error=1:halt_on_error=1:detect_leaks=1";

/// Merge an operator-provided `<SAN>_OPTIONS` (from the inherited environment)
/// with the keys govfuzz requires (#435). govfuzz's keys go LAST so they win on
/// conflict — an operator cannot accidentally disable `abort_on_error`, which is
/// what makes a sanitizer report a saved finding — while every other operator
/// key is preserved. This is how an operator tames the RTOS / partial-build
/// false-positive storm: export e.g.
/// `ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:detect_odr_violation=0:allocator_may_return_null=1:suppressions=$PWD/asan.supp`
/// (and `LSAN_OPTIONS=suppressions=$PWD/lsan.supp`) and govfuzz keeps it. Each
/// sanitizer is merged independently, so per-sanitizer suppressions files land in
/// the right place (an LSan suppressions file never leaks into `ASAN_OPTIONS`).
pub fn merge_sanitizer_options(inherited: Option<&str>, required: &str) -> String {
    match inherited.map(str::trim).filter(|s| !s.is_empty()) {
        Some(prefix) => format!("{prefix}:{required}"),
        None => required.to_owned(),
    }
}

/// Sanitizer composition envs (#296): produce a per-worker env vector that points
/// each worker at one of ASan / MSan / UBSan / TSan / LSan via
/// `<SANITIZER>_OPTIONS`. The harness binary must already be built with the
/// relevant sanitizer flags — this only orchestrates the env-controlled runtime
/// options. Each value MERGES the operator's inherited `<SAN>_OPTIONS` (so
/// suppressions / FP-killer options survive) with govfuzz's required keys (#435).
pub fn sanitizer_envs(sanitizers: &[Sanitizer]) -> Vec<Vec<(String, String)>> {
    sanitizers
        .iter()
        .map(|s| {
            let key = sanitizer_options_key(*s);
            let value = merge_sanitizer_options(
                std::env::var(key).ok().as_deref(),
                REQUIRED_SANITIZER_OPTIONS,
            );
            vec![(key.to_owned(), value)]
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sanitizer {
    Asan,
    Msan,
    Ubsan,
    Tsan,
    Lsan,
}

impl Sanitizer {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "asan" | "address" => Some(Sanitizer::Asan),
            "msan" | "memory" => Some(Sanitizer::Msan),
            "ubsan" | "undefined" => Some(Sanitizer::Ubsan),
            "tsan" | "thread" => Some(Sanitizer::Tsan),
            "lsan" | "leak" => Some(Sanitizer::Lsan),
            _ => None,
        }
    }
}

/// What `--sanitizers` selected for a build+run (#434). Distinguishes the three
/// meaningful states that a bare `Vec<Sanitizer>` could not:
///
/// * [`SanitizerSelection::Default`] — no `--sanitizers` given. The harness
///   Makefile's baked-in `-fsanitize=address,undefined` stands; build and run
///   env are left byte-identical to the historical behavior.
/// * [`SanitizerSelection::None`] — `--sanitizers none`. The native build keeps
///   the engine's coverage instrumentation but drops the `-fsanitize=` group
///   entirely: native crash-only + coverage fuzzing with **zero** ASan/UBSan
///   false positives (the escape hatch for shared-memory / custom-allocator /
///   RTOS code that FP-storms under ASan). No runtime `<SAN>_OPTIONS`.
/// * [`SanitizerSelection::Set`] — `--sanitizers <set>`. Arm exactly this set on
///   both the build (`-fsanitize=<set>`) and the run env.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SanitizerSelection {
    #[default]
    Default,
    None,
    Set(Vec<Sanitizer>),
}

impl SanitizerSelection {
    /// The sanitizers whose runtime `<SAN>_OPTIONS` must be armed. Empty for
    /// `Default` (the Makefile bakes ASan/UBSan, but we do not override their
    /// run env) and for `None`.
    pub fn runtime_set(&self) -> &[Sanitizer] {
        match self {
            SanitizerSelection::Set(set) => set,
            SanitizerSelection::Default | SanitizerSelection::None => &[],
        }
    }

    /// True when the native build's `-fsanitize=`/coverage flags must be
    /// overridden. `Default` leaves the Makefile flags intact; `None` and `Set`
    /// both replace them.
    pub fn overrides_build(&self) -> bool {
        !matches!(self, SanitizerSelection::Default)
    }
}

fn count_findings(worker_dir: &Path) -> usize {
    let findings_dir = worker_dir.join("findings");
    let Ok(entries) = std::fs::read_dir(findings_dir) else {
        return 0;
    };
    entries.filter_map(|e| e.ok()).count()
}

fn unique_finding_count(per_worker: &[WorkerReport]) -> usize {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    for report in per_worker {
        let findings_dir = report.work_dir.join("findings");
        let Ok(entries) = std::fs::read_dir(&findings_dir) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let finding_json = entry.path().join("finding.json");
            let Ok(bytes) = std::fs::read(&finding_json) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let key = value
                .get("cluster_key")
                .and_then(|v| v.as_str())
                .or_else(|| value.get("signature").and_then(|v| v.as_str()))
                .map(str::to_owned);
            if let Some(key) = key {
                seen.insert(key);
            }
        }
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    /// The builtin engine and AFL++ want OPPOSITE symbolization, and satisfying
    /// AFL globally is what broke the product's differentiator.
    ///
    /// AFL++ v4 aborts in pre-flight on a custom `ASAN_OPTIONS` without
    /// `symbolize=0`, so the afl-fuzz spawn sets it on that child. Putting it
    /// here instead stripped file:line from every builtin child's sanitizer
    /// report — and file:line is exactly what joins a crash to the static finding
    /// on the same line, so every `fuzz_confirmed` static finding silently
    /// downgraded to `fuzz_exercised`.
    #[test]
    #[cfg(unix)]
    fn worker_spawn_retries_a_freshly_written_executable_that_is_still_open() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // ETXTBSY: the kernel refuses to exec a file that is still open for
        // WRITING anywhere. Holding the writer open reproduces deterministically
        // what a loaded CI runner hits by accident when one thread is still
        // finishing a write while another forks.
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-mc-etxtbsy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("worker.sh");
        let mut writer = std::fs::File::create(&script).unwrap();
        writer.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        writer.flush().unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Still-open writer -> a bare spawn fails.
        let bare = Command::new(&script).spawn();
        let bare_failed_busy = matches!(
            &bare,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy
        );
        if let Ok(mut child) = bare {
            let _ = child.wait();
        }

        // Release the descriptor from another thread while the retry loop runs,
        // exactly as the real race resolves itself.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            drop(writer);
        });
        let mut cmd = Command::new(&script);
        let spawned = spawn_worker(&mut cmd);
        handle.join().unwrap();
        assert!(
            spawned.is_ok(),
            "spawn_worker must ride out ETXTBSY, got {:?}",
            spawned.err()
        );
        let _ = spawned.unwrap().wait();
        // Only meaningful if the platform actually produced the race; say so
        // rather than silently passing a test that proved nothing.
        if !bare_failed_busy {
            eprintln!("note: this filesystem did not produce ETXTBSY for an open writer");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builtin_children_keep_symbolization_for_the_fuzz_confirmation_join() {
        assert!(
            !REQUIRED_SANITIZER_OPTIONS.contains("symbolize"),
            "a builtin fuzz child must symbolize so a crash carries file:line: \
             {REQUIRED_SANITIZER_OPTIONS}"
        );
        // The keys that make a sanitizer report a saved finding stay required.
        for key in ["abort_on_error=1", "halt_on_error=1", "detect_leaks=1"] {
            assert!(
                REQUIRED_SANITIZER_OPTIONS.contains(key),
                "{key} is required"
            );
        }
        // An operator asking for no symbolization is still honoured — govfuzz
        // does not force it on — and their other keys survive the merge.
        let merged = merge_sanitizer_options(
            Some("symbolize=0:suppressions=/x.supp"),
            REQUIRED_SANITIZER_OPTIONS,
        );
        assert!(merged.contains("symbolize=0"), "{merged}");
        assert!(
            merged.contains("suppressions=/x.supp"),
            "operator keys survive: {merged}"
        );
        assert!(merged.contains("abort_on_error=1"), "{merged}");
    }

    /// The AFL child's own env is built by merging `symbolize=0` LAST, so it wins
    /// over whatever the builtin path put in `extra_env`. That ordering is the
    /// whole fix: applying `extra_env` after the explicit value silently undid it
    /// and AFL went back to aborting in pre-flight.
    #[test]
    fn the_afl_child_env_forces_symbolize_off_over_an_inherited_value() {
        let builtin = merge_sanitizer_options(None, REQUIRED_SANITIZER_OPTIONS);
        let afl = merge_sanitizer_options(Some(&builtin), "symbolize=0");
        assert!(
            afl.contains("symbolize=0"),
            "AFL++ will not start without it: {afl}"
        );
        assert!(
            afl.contains("abort_on_error=1"),
            "and it must not lose the keys that save a finding: {afl}"
        );
    }

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn worker_namespace_is_harness_specific_and_path_safe() {
        // Two harnesses yield distinct namespaces (no worker-dir collision when
        // sharing a work_dir); odd chars collapse to '_'.
        assert_eq!(
            sanitize_worker_namespace("H-A0048-0B811272"),
            "H-A0048-0B811272"
        );
        assert_ne!(
            sanitize_worker_namespace("H-A0048-0B811272"),
            sanitize_worker_namespace("H-A004E-E9877A92")
        );
        assert_eq!(sanitize_worker_namespace("a/b c"), "a_b_c");
        assert_eq!(sanitize_worker_namespace(""), "harness");
    }

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-multicore-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn worker_count_auto_resolves_at_least_one() {
        let n = WorkerCount::Auto.resolve().unwrap();
        assert!(n >= 1);
    }

    #[test]
    fn worker_count_fixed_zero_is_rejected() {
        assert!(matches!(
            WorkerCount::Fixed(0).resolve(),
            Err(MulticoreError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn worker_count_fixed_n_returns_n() {
        assert_eq!(WorkerCount::Fixed(7).resolve().unwrap(), 7);
    }

    #[test]
    fn run_multicore_rejects_missing_work_dir() {
        let config = MulticoreConfig {
            work_dir: PathBuf::from("/nonexistent/work"),
            harness_id: "H".to_owned(),
            workers: WorkerCount::Auto,
            per_worker_iterations: None,
            time_budget: Duration::from_secs(1),
            govfuzz_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::WorkDirMissing(_))
        ));
    }

    #[test]
    fn run_multicore_rejects_missing_govfuzz_bin() {
        let work = tempdir("missing-bin");
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::from_secs(1),
            govfuzz_bin: PathBuf::from("/nonexistent/bin/govfuzz"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::BinMissing(_))
        ));
    }

    #[test]
    fn run_multicore_rejects_zero_workers() {
        let work = tempdir("zero");
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H".to_owned(),
            workers: WorkerCount::Fixed(0),
            per_worker_iterations: None,
            time_budget: Duration::from_secs(1),
            govfuzz_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn count_findings_returns_zero_for_missing_dir() {
        let dir = tempdir("count-zero");
        assert_eq!(count_findings(&dir), 0);
    }

    #[test]
    fn count_findings_counts_finding_subdirectories() {
        let dir = tempdir("count");
        let findings = dir.join("findings");
        std::fs::create_dir_all(findings.join("F-0001")).unwrap();
        std::fs::create_dir_all(findings.join("F-0002")).unwrap();
        assert_eq!(count_findings(&dir), 2);
    }

    #[test]
    fn unique_finding_count_dedups_across_workers_by_cluster_key() {
        let dir = tempdir("uniq");
        for worker in 0..2 {
            let worker_dir = dir.join(format!("worker-{worker}"));
            let findings_dir = worker_dir.join("findings");
            let f = findings_dir.join(format!("F-{worker:04}"));
            std::fs::create_dir_all(&f).unwrap();
            std::fs::write(
                f.join("finding.json"),
                serde_json::json!({
                    "cluster_key": "shared-cluster-key",
                    "signature": "irrelevant"
                })
                .to_string(),
            )
            .unwrap();
        }
        let reports = vec![
            WorkerReport {
                worker_id: 0,
                work_dir: dir.join("worker-0"),
                exit_code: Some(0),
                findings_count: 1,
                env_keys: Vec::new(),
            },
            WorkerReport {
                worker_id: 1,
                work_dir: dir.join("worker-1"),
                exit_code: Some(0),
                findings_count: 1,
                env_keys: Vec::new(),
            },
        ];
        // Two workers, one shared cluster_key → 1 unique.
        assert_eq!(unique_finding_count(&reports), 1);
    }

    #[test]
    fn sanitizer_parse_accepts_known_aliases() {
        assert_eq!(Sanitizer::parse("asan"), Some(Sanitizer::Asan));
        assert_eq!(Sanitizer::parse("Address"), Some(Sanitizer::Asan));
        assert_eq!(Sanitizer::parse("msan"), Some(Sanitizer::Msan));
        assert_eq!(Sanitizer::parse("memory"), Some(Sanitizer::Msan));
        assert_eq!(Sanitizer::parse("ubsan"), Some(Sanitizer::Ubsan));
        assert_eq!(Sanitizer::parse("tsan"), Some(Sanitizer::Tsan));
        assert_eq!(Sanitizer::parse("lsan"), Some(Sanitizer::Lsan));
        assert_eq!(Sanitizer::parse("garbage"), None);
    }

    #[test]
    fn sanitizer_selection_default_is_passthrough() {
        let sel = SanitizerSelection::default();
        assert_eq!(sel, SanitizerSelection::Default);
        assert!(sel.runtime_set().is_empty());
        assert!(!sel.overrides_build());
    }

    #[test]
    fn sanitizer_selection_none_overrides_build_but_arms_no_env() {
        let sel = SanitizerSelection::None;
        assert!(sel.runtime_set().is_empty());
        assert!(sel.overrides_build());
    }

    #[test]
    fn sanitizer_selection_set_exposes_runtime_set() {
        let sel = SanitizerSelection::Set(vec![Sanitizer::Asan, Sanitizer::Lsan]);
        assert_eq!(sel.runtime_set(), &[Sanitizer::Asan, Sanitizer::Lsan]);
        assert!(sel.overrides_build());
    }

    #[test]
    fn merge_sanitizer_options_without_inherited_is_just_required() {
        assert_eq!(
            merge_sanitizer_options(None, "abort_on_error=1"),
            "abort_on_error=1"
        );
        assert_eq!(
            merge_sanitizer_options(Some("   "), "abort_on_error=1"),
            "abort_on_error=1"
        );
    }

    #[test]
    fn merge_sanitizer_options_preserves_operator_keys_and_required_wins() {
        // Operator's FP-killers / suppressions survive; govfuzz's required keys
        // come LAST so they override any operator attempt to disable them (#435).
        let merged = merge_sanitizer_options(
            Some("verify_asan_link_order=0:abort_on_error=0:suppressions=/x.supp"),
            "abort_on_error=1:halt_on_error=1:detect_leaks=1",
        );
        assert_eq!(
            merged,
            "verify_asan_link_order=0:abort_on_error=0:suppressions=/x.supp:\
             abort_on_error=1:halt_on_error=1:detect_leaks=1"
        );
        // The required override is the LAST abort_on_error occurrence (ASan: last wins).
        assert!(
            merged.rfind("abort_on_error=1").unwrap() > merged.rfind("abort_on_error=0").unwrap()
        );
    }

    #[test]
    fn sanitizer_envs_one_entry_per_sanitizer() {
        let envs = sanitizer_envs(&[Sanitizer::Asan, Sanitizer::Msan, Sanitizer::Ubsan]);
        assert_eq!(envs.len(), 3);
        assert_eq!(envs[0][0].0, "ASAN_OPTIONS");
        assert_eq!(envs[1][0].0, "MSAN_OPTIONS");
        assert_eq!(envs[2][0].0, "UBSAN_OPTIONS");
        for env in &envs {
            assert!(env[0].1.contains("abort_on_error=1"));
        }
    }

    #[test]
    fn run_multicore_two_workers_with_bin_true_yields_two_started_workers() {
        // /bin/true exits 0 immediately; we just want to verify
        // orchestration scaffolding spawns + reaps the right number.
        let work = tempdir("true-bin");
        let build = work.join("build").join("H-TEST");
        std::fs::create_dir_all(&build).unwrap();
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H-TEST".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(0),
            time_budget: Duration::from_secs(0),
            govfuzz_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
        };
        let summary = run_multicore(&config).expect("run ok");
        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_multicore_syncs_worker_corpus_and_writes_manifest() {
        use std::os::unix::fs::PermissionsExt;

        let work = tempdir("sync-manifest");
        let build = work.join("build").join("H-SYNC");
        let shared_queue = work.join("corpus").join("H-SYNC").join("queue");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&shared_queue).unwrap();
        std::fs::write(shared_queue.join("seed.bin"), b"seed").unwrap();

        let script = work.join("fake-govfuzz.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
set -eu
worker_dir="$2"
harness=""
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) harness="$2"; shift 2 ;;
    *) shift ;;
  esac
done
test -f "$GOVFUZZ_SHARED_CORPUS_DIR/seed.bin"
mkdir -p "$worker_dir/corpus/$harness/queue"
printf "worker-%s" "$GOVFUZZ_WORKER_ID" > "$worker_dir/corpus/$harness/queue/worker-$GOVFUZZ_WORKER_ID.bin"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-SYNC".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            govfuzz_bin: script,
            per_worker_env: sanitizer_envs(&[Sanitizer::Asan, Sanitizer::Ubsan]),
            extra_worker_args: Vec::new(),
            kill_grace: None,
        };

        let summary = run_multicore(&config).expect("run ok");

        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 2);
        assert_eq!(summary.sync.seed_inputs_loaded, 1);
        assert_eq!(summary.sync.imported_inputs, 2);
        assert!(summary.sync_manifest_path.is_file());
        assert_eq!(
            std::fs::read(shared_queue.join("worker-0.bin")).unwrap(),
            b"worker-0"
        );
        assert_eq!(
            std::fs::read(shared_queue.join("worker-1.bin")).unwrap(),
            b"worker-1"
        );
        assert_eq!(summary.per_worker[0].env_keys, vec!["ASAN_OPTIONS"]);
        assert_eq!(summary.per_worker[1].env_keys, vec!["UBSAN_OPTIONS"]);

        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&summary.sync_manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["harness_id"], "H-SYNC");
        assert_eq!(manifest["workers_started"], 2);
        assert_eq!(manifest["sync"]["imported_inputs"], 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_multicore_kills_workers_after_time_budget_plus_grace() {
        use std::os::unix::fs::PermissionsExt;
        // A shell script that ignores its args and hangs forever.
        // We need this because /bin/sleep would error on our argv,
        // and /bin/true exits before the kill switch can trigger.
        let work = tempdir("hang");
        let build = work.join("build").join("H-HANG");
        std::fs::create_dir_all(&build).unwrap();
        let script = work.join("hang.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 300\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H-HANG".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: None,
            time_budget: Duration::from_millis(200),
            govfuzz_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: Some(Duration::from_millis(300)),
        };

        let start = std::time::Instant::now();
        let summary = run_multicore(&config).expect("run ok");
        let elapsed = start.elapsed();

        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 0); // killed, not exit 0
        assert!(
            summary.per_worker.iter().all(|r| r.exit_code.is_none()),
            "expected all workers killed (exit_code=None), got {:?}",
            summary.per_worker
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "orchestrator should have killed hanging workers within ~time_budget+grace, took {elapsed:?}"
        );
    }
}
