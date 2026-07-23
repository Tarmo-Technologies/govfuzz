// SPDX-License-Identifier: Apache-2.0

use crate::runner::{harness_runner, SandboxModeArg};
use clap::ValueEnum;
use corpus::{
    classify, compute_signature, finding_tier, resolve_handler, CorpusManager, FindingEmitter,
    FindingTier, Signature, SignatureClass,
};
use event_log::{group_into_testcases, Event, EventReader, Testcase};
use fuzz_engine_builtin::{
    generate_symbolic_seeds, Dictionary, Grammar, MutationInput, MutationRng, MutatorConfig,
    MutatorSuite, SymbolicSeedSource,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Belt-and-suspenders kernel rails on every fuzz harness spawn.
///
/// 1. On Linux, `PR_SET_PDEATHSIG(SIGKILL)` — the kernel SIGKILLs the
///    harness if our process dies, so a panicking govfuzz can't leave orphan
///    workers behind.
/// 2. `RLIMIT_CPU = 600s` — each harness gets at most 10 minutes of
///    CPU time before the kernel reaps it.
///
/// RLIMIT_AS and RLIMIT_NPROC were applied here historically but
/// were removed: AddressSanitizer reserves ~128 TiB of shadow
/// memory and libFuzzer's helper threads exhaust modest NPROC
/// caps, so any VA/thread limit that's tight enough to actually
/// brake a runaway harness also breaks every sanitizer-instrumented
/// build. The crash-rate kill-switch and absolute wall-clock cap in
/// `auto::attempt::attempt` remain the orchestrator-level guard.
///
/// All four calls are best-effort: if the syscall fails (eg. an
/// existing RLIMIT_AS is already lower) we don't propagate. The
/// crash-rate and wall-clock checks in `auto::attempt` are the
/// primary guard; these rails are the last line of defence.
#[cfg(unix)]
fn apply_runaway_rlimits(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            let cpu = libc::rlimit {
                rlim_cur: 600,
                rlim_max: 600,
            };
            libc::setrlimit(libc::RLIMIT_CPU, &cpu);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn apply_runaway_rlimits(_cmd: &mut std::process::Command) {}

/// SIGKILL a child's entire process group, then the child, for a hard timeout
/// kill. The child must have been spawned with `process_group(0)` so its PID is
/// the group id; `kill(-pid, ...)` then reaps the forked grandchildren (e.g. the
/// persistent harness afl-fuzz forks) that a plain `child.kill()` would orphan.
#[cfg(unix)]
fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    // Negative pid => the process group led by `pid`.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// SIGKILL any process still executing `exe`. AFL++'s persistent forkserver
/// `setsid()`s its worker into a fresh session, so a group kill of afl-fuzz can
/// leave that worker orphaned (reparented to init, often SIGSTOP-paused). After a
/// hard-deadline kill we reap by exe path so a hung run leaks no `main_afl`. Each
/// harness has a unique `harnesses/<id>/main_afl` path, so this only ever targets the
/// run's own binary. SIGCONT first in case the orphan is stopped.
#[cfg(target_os = "linux")]
fn kill_processes_by_exe(exe: &Path) {
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(target) = fs::read_link(entry.path().join("exe")) {
            if target == exe {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGCONT);
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn kill_processes_by_exe(_exe: &Path) {}

/// Parse AFL++'s `out/default/fuzzer_stats` for the real execution counters
/// (`execs_done`, `execs_per_sec`). Returns `(execs_done, execs_per_sec)`; either
/// is `None` when the file or key is absent (afl-fuzz never wrote stats). The file
/// is `key : value` lines.
fn parse_afl_fuzzer_stats(out_dir: &Path) -> (Option<u64>, Option<f64>) {
    let text = match fs::read_to_string(out_dir.join("default").join("fuzzer_stats")) {
        Ok(text) => text,
        Err(_) => return (None, None),
    };
    let mut execs_done = None;
    let mut execs_per_sec = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "execs_done" => execs_done = value.trim().parse::<u64>().ok(),
                "execs_per_sec" => execs_per_sec = value.trim().parse::<f64>().ok(),
                _ => {}
            }
        }
    }
    (execs_done, execs_per_sec)
}

/// A fuzzed target may create files using fuzz-controlled paths (an archive
/// extractor, a `Stream_IO`/`File_Zipstream` writer, a TOML emitter, ...). Run
/// the harness with its working directory inside the run's own work dir so
/// those files land in one clearly-named, throwaway place - `<work>/
/// fuzz_scratch/` - instead of polluting wherever govfuzz was launched. The
/// whole work dir is the user's to delete, so the junk goes with it.
fn ensure_harness_scratch(work_dir: &Path) -> Result<PathBuf, String> {
    let scratch = work_dir.join("fuzz_scratch");
    std::fs::create_dir_all(&scratch)
        .map_err(|error| format!("create fuzz scratch dir {}: {error}", scratch.display()))?;
    Ok(scratch)
}

#[derive(Debug, clap::Args)]
pub struct FuzzArgs {
    /// Path to govfuzz_work directory containing build/<harness-id>/.
    pub work_dir: PathBuf,

    /// Harness id under build/<harness-id>/.
    #[arg(long)]
    pub harness: String,

    /// Fuzz engine: the built-in coverage-guided engine (default), or AFL++ via
    /// subprocess (`afl++`, needs `afl-fuzz`/`afl-clang-fast` on PATH).
    #[arg(long, value_enum, default_value_t = FuzzEngine::Builtin)]
    pub engine: FuzzEngine,

    /// Run multiple fuzz workers. Use a number or `auto`.
    #[arg(long, value_parser = parse_worker_count)]
    pub workers: Option<FuzzWorkerCount>,

    /// Maximum number of harness executions. Defaults to 256 when neither this
    /// nor `--time` is given; when `--time` is set and this is omitted, the run
    /// is bounded only by the time budget (not silently capped at 256).
    #[arg(long)]
    pub iterations: Option<usize>,

    /// Optional wall-clock budget such as 30s, 5m, or 1h.
    #[arg(long, value_parser = parse_duration)]
    pub time: Option<Duration>,

    /// Maximum generated input length in bytes (libFuzzer's `-max_len`). The
    /// built-in mutator never produces an input longer than this. With adaptive
    /// length control on (the default) this is the *ceiling*; the effective
    /// length starts small and grows as coverage plateaus.
    #[arg(long = "max-len", default_value_t = DEFAULT_MAX_LEN)]
    pub max_len: usize,

    /// Adaptive length control (libFuzzer's `-len_control`). The effective
    /// mutation length starts small and doubles toward `--max-len` after this
    /// many executions without a new corpus signature, so early fuzzing explores
    /// shallow/fast and deepens as it plateaus. `0` disables it (always use the
    /// full `--max-len`).
    #[arg(long = "len-control", default_value_t = DEFAULT_LEN_CONTROL)]
    pub len_control: usize,

    /// Per-input timeout (libFuzzer's `-timeout`): a single C/C++ harness
    /// execution that runs longer than this is killed and skipped (the slow unit
    /// is reported). Distinct from `--time`, the whole-campaign budget. Defaults
    /// to 10s. (The Ada lane bounds runaway inputs via CPU rlimits instead.)
    #[arg(long = "timeout", value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// Print a final-stats line at the end of the run (libFuzzer's
    /// `-print_final_stats`): executions, exec/s, new vs duplicate corpus
    /// signatures, findings, and elapsed time.
    #[arg(long = "print-final-stats")]
    pub print_final_stats: bool,

    /// Resident-memory ceiling in MB for a single C/C++ harness execution
    /// (libFuzzer's `-rss_limit_mb`). An execution whose RSS exceeds this is
    /// killed and reported as an out-of-memory finding. `0` (default) disables
    /// it. (RSS is polled rather than an `RLIMIT_AS` cap, which would break
    /// ASan's large virtual-address reservation.)
    #[arg(long = "rss-limit-mb", default_value_t = 0)]
    pub rss_limit_mb: usize,

    /// Force the persistent fork-server execution mode (it is the default for
    /// the builtin engine; this only matters to override `--no-fork-server` or
    /// `GOVFUZZ_FORK_SERVER=0`). One harness process is kept alive and fed inputs
    /// over a framed protocol, amortizing fork/exec/elaboration (~38x more
    /// execs/sec) while preserving the coverage-guided feedback. Every finding is
    /// replay-validated in a fresh process, so a global-state artifact never
    /// escapes; a hard crash falls back to a per-spawn run and respawns.
    #[arg(long)]
    pub fork_server: bool,

    /// Disable the fork-server and run a fresh process per input. Use for a
    /// target that intentionally carries fuzz-relevant global state across calls
    /// (a stateful state machine), where the per-spawn dynamics are preferred.
    #[arg(long)]
    pub no_fork_server: bool,

    /// Literal seed input bytes, interpreted as UTF-8 bytes.
    #[arg(long = "seed-input")]
    pub seed_inputs: Vec<String>,

    /// File containing seed input bytes.
    #[arg(long = "seed-file")]
    pub seed_files: Vec<PathBuf>,

    /// Sanitizer campaign matrix to arm, comma-separated (asan, msan, ubsan, tsan,
    /// lsan), or the standalone value `none` (build coverage-only with no
    /// `-fsanitize=` — crash-only fuzzing without ASan/UBSan false positives).
    #[arg(long = "sanitizers", value_delimiter = ',')]
    pub sanitizers: Vec<String>,

    /// Ada source file to mine guarded literals into prototype symbolic seeds.
    #[arg(long = "symbolic-seed-source")]
    pub symbolic_seed_sources: Vec<PathBuf>,

    /// Deterministic RNG seed for built-in mutation.
    #[arg(long, default_value_t = 0x4756_4655_5a5a)]
    pub rng_seed: u64,

    /// Sandbox wrapper for harness execution.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Actionability profile to optimize for.
    #[arg(long, default_value_t = actionability::RunMode::Reporting)]
    pub mode: actionability::RunMode,

    /// Override sandbox wrapper executable.
    #[arg(long, value_name = "PATH", requires = "sandbox")]
    pub sandbox_tool: Option<PathBuf>,

    /// Fail if the requested sandbox tool is unavailable.
    #[arg(long)]
    pub sandbox_strict: bool,

    /// Extra environment variables to set on the harness Command.
    /// Populated by `govfuzz auto` to thread GOVFUZZ_RUNTRACE_MODE,
    /// LD_PRELOAD, and per-finding env injections without polluting
    /// the parent process env. Always empty for the CLI path.
    #[arg(skip)]
    pub extra_env: Vec<(String, String)>,

    /// Path to a previously captured runtrace audit log produced
    /// with `GOVFUZZ_CMPLOG=1`. When set, recovered cmplog operands
    /// seed both the mutator dictionary (positional-info-free token
    /// insert) and an offset-aware RedQueen-style splice that
    /// replaces operand_a with operand_b at the exact offset
    /// operand_a appears in the current input.
    #[arg(long, value_name = "PATH")]
    pub cmplog_log: Option<PathBuf>,

    /// Path to a JSON grammar describing the target's input format for structure-aware
    /// generation (a Nautilus-style grammar mutator). Each rule maps a non-terminal to
    /// a list of production strings where `{NAME}` references another rule; the start
    /// symbol is `START` if present, else the first rule.
    #[arg(long = "grammar", value_name = "PATH")]
    pub grammar_file: Option<PathBuf>,

    /// Structure-aware input synthesis for the built-in engine.
    #[arg(long = "structured-inputs", value_enum, default_value_t = StructuredInputMode::Auto)]
    pub structured_inputs: StructuredInputMode,

    /// Override the govfuzz worker binary used by multicore orchestration.
    #[arg(long, value_name = "PATH", hide = true)]
    pub govfuzz_bin: Option<PathBuf>,

    /// Stop this run as soon as it has emitted this many DISTINCT findings (the
    /// built-in engine's in-process loop breaks the instant the count is hit).
    /// Set programmatically by `auto`'s `--per-target-finding-count` (the count
    /// REMAINING for the current pass); `None` runs to the time/iteration budget.
    /// Not a standalone CLI flag.
    #[arg(skip)]
    pub stop_after_findings: Option<usize>,
}

impl FuzzArgs {
    /// The execution cap the fuzz loop should use. An explicit `--iterations`
    /// always wins; otherwise a `--time` budget runs unbounded (so a time-based
    /// campaign isn't silently capped at the 256 default), and with neither set
    /// we fall back to 256.
    pub(crate) fn effective_iterations(&self) -> usize {
        resolve_iterations(self.iterations, self.time.is_some())
    }
}

const DEFAULT_ITERATIONS: usize = 256;

/// Default maximum generated input length, matching the built-in mutator's
/// historical fixed cap (and libFuzzer's default).
pub(crate) const DEFAULT_MAX_LEN: usize = 4096;

/// Memory/disk retention bounds for one active target's coverage corpus. The byte
/// budget is derived from available host/cgroup memory; the entry count follows
/// from that byte budget and the configured maximum input length. Both have exact
/// operator overrides, so the OOM safeguard never imposes an unchangeable fuzzing
/// ceiling on a larger analysis host.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CorpusLimits {
    pub(crate) entries: usize,
    pub(crate) bytes: usize,
}

pub(crate) fn corpus_limits(max_len: usize) -> CorpusLimits {
    let bytes = crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_CORPUS_BYTES",
        64,
        64 * crate::resource_limits::MIB,
        128 * crate::resource_limits::MIB,
        2 * 1024 * crate::resource_limits::MIB,
    );
    let estimated_entry_bytes = max_len.clamp(1024, 64 * 1024);
    let derived_entries = (bytes / estimated_entry_bytes).clamp(4096, 262_144);
    let entries =
        crate::resource_limits::env_usize("GOVFUZZ_MAX_CORPUS_ENTRIES").unwrap_or(derived_entries);
    CorpusLimits { entries, bytes }
}

fn max_finding_record_bytes() -> u64 {
    crate::resource_limits::env_usize("GOVFUZZ_MAX_FINDING_RECORD_BYTES")
        .unwrap_or(2 * crate::resource_limits::MIB) as u64
}

fn max_finding_dedup_keys() -> usize {
    if let Some(configured) = crate::resource_limits::env_usize("GOVFUZZ_MAX_FINDING_DEDUP_KEYS") {
        return configured;
    }
    let bytes = crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_FINDING_DEDUP_BYTES",
        1024,
        32 * crate::resource_limits::MIB,
        32 * crate::resource_limits::MIB,
        512 * crate::resource_limits::MIB,
    );
    // Keys include owned signatures/paths and hash-table overhead. 512 bytes is
    // deliberately conservative; this controls retention, not finding emission.
    (bytes / 512).clamp(65_536, 1_048_576)
}
fn max_symbolic_source_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_SYMBOLIC_SOURCE_BYTES",
        256,
        16 * crate::resource_limits::MIB,
        16 * crate::resource_limits::MIB,
        256 * crate::resource_limits::MIB,
    )
}

fn max_symbolic_sources_total_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_SYMBOLIC_SOURCES_TOTAL_BYTES",
        64,
        64 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
        2 * 1024 * crate::resource_limits::MIB,
    )
}

fn max_grammar_bytes() -> usize {
    crate::resource_limits::env_usize("GOVFUZZ_MAX_GRAMMAR_BYTES")
        .unwrap_or(16 * crate::resource_limits::MIB)
}

fn max_dictionary_bytes() -> usize {
    crate::resource_limits::env_usize("GOVFUZZ_MAX_DICTIONARY_BYTES")
        .unwrap_or(16 * crate::resource_limits::MIB)
}
const GOVFUZZ_VP_BYTES: usize = 1 << 16;

/// Read at most `cap` bytes from a seed without first allocating the whole file.
/// Returns `(prefix, original_len)` so callers can report truncation honestly.
pub(crate) fn read_seed_file_prefix(path: &Path, cap: usize) -> std::io::Result<(Vec<u8>, u64)> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut bytes = Vec::with_capacity((len.min(cap as u64)) as usize);
    file.take(cap as u64).read_to_end(&mut bytes)?;
    Ok((bytes, len))
}

/// Bound both the count and aggregate bytes of initial seeds. This is applied at
/// the engine boundary as well as during CLI loading, so programmatic `auto` and
/// symbolic-seed callers cannot bypass it.
fn bound_seed_corpus(seeds: &mut Vec<Vec<u8>>, max_len: usize) {
    let limits = corpus_limits(max_len);
    let before = seeds.len();
    let mut kept = Vec::with_capacity(before.min(limits.entries));
    let mut bytes = 0usize;
    for mut seed in seeds.drain(..) {
        seed.truncate(max_len);
        if kept.len() >= limits.entries {
            continue;
        }
        // Always retain the first seed, even when an explicit --max-len larger
        // than our normal byte budget opted into one unusually large sample.
        if !kept.is_empty() && bytes.saturating_add(seed.len()) > limits.bytes {
            continue;
        }
        bytes = bytes.saturating_add(seed.len());
        kept.push(seed);
    }
    let dropped = before.saturating_sub(kept.len());
    if dropped > 0 {
        eprintln!(
            "govfuzz: seed corpus bounded to {} input(s) / {} MiB; dropped {dropped} \
             seed(s) beyond the in-memory corpus budget (override with \
             GOVFUZZ_MAX_CORPUS_ENTRIES / GOVFUZZ_MAX_CORPUS_BYTES)",
            kept.len(),
            bytes / (1024 * 1024),
        );
    }
    if kept.is_empty() {
        kept.push(Vec::new());
    }
    *seeds = kept;
}

/// Default `--len-control`: executions-without-new-coverage before the effective
/// mutation length doubles. Mirrors libFuzzer's default of 100.
pub(crate) const DEFAULT_LEN_CONTROL: usize = 100;

/// Effective mutation length the run starts at when length control is active.
pub(crate) const INITIAL_LEN_CONTROL_LEN: usize = 64;

/// Resolve the fuzz-loop execution cap. An explicit `--iterations` always wins;
/// otherwise a `--time` budget runs unbounded (`usize::MAX`) so the loop is
/// governed by wall-clock, not silently capped at 256; with neither, 256.
fn resolve_iterations(explicit: Option<usize>, has_time_budget: bool) -> usize {
    match (explicit, has_time_budget) {
        (Some(n), _) => n,
        (None, true) => usize::MAX,
        (None, false) => DEFAULT_ITERATIONS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzEngine {
    Builtin,
    #[value(name = "afl++")]
    AflPlusPlus,
}

/// Parse a comma-separated engine list (`auto --engine builtin,afl++`) into an
/// ordered, de-duplicated `Vec<FuzzEngine>`. Order is preserved as written; the
/// first occurrence of each engine wins. Whitespace around names is tolerated.
/// Empty input or an unknown name is an error. Accepted names mirror the
/// `FuzzEngine` value-enum (`builtin`, `afl++`), plus `afl`/`aflplusplus`
/// synonyms for `afl++`.
pub(crate) fn parse_engine_list(raw: &str) -> Result<Vec<FuzzEngine>, String> {
    let mut out: Vec<FuzzEngine> = Vec::new();
    for tok in raw.split(',') {
        let name = tok.trim();
        if name.is_empty() {
            continue;
        }
        let engine = match name {
            "builtin" => FuzzEngine::Builtin,
            "afl++" | "aflplusplus" | "afl" => FuzzEngine::AflPlusPlus,
            other => {
                return Err(format!(
                    "unknown fuzz engine '{other}' (expected: builtin, afl++)"
                ))
            }
        };
        if !out.contains(&engine) {
            out.push(engine);
        }
    }
    if out.is_empty() {
        return Err("no fuzz engine specified (expected: builtin, afl++)".to_owned());
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
pub enum StructuredInputMode {
    Auto,
    Off,
    Record,
    Json,
    Xml,
    #[value(name = "kv")]
    Kv,
    Url,
    Multipart,
    Csv,
    Http,
    Ini,
    Toml,
    Yaml,
    Recursive,
}

impl StructuredInputMode {
    fn structured_records_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Record)
    }

    fn structured_json_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Json)
    }

    fn structured_xml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Xml)
    }

    fn structured_key_value_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Kv)
    }

    fn structured_url_encoded_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Url)
    }

    fn structured_multipart_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Multipart)
    }

    fn structured_csv_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Csv)
    }

    fn structured_http_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Http)
    }

    fn structured_ini_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Ini)
    }

    fn structured_toml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Toml)
    }

    fn structured_yaml_enabled(self) -> bool {
        matches!(self, Self::Auto | Self::Yaml)
    }

    fn structured_chunked_enabled(self) -> bool {
        // Binary chunked/length-prefixed shape: on in the default `Auto` mode.
        matches!(self, Self::Auto)
    }

    fn structured_recursive_enabled(self) -> bool {
        // Recursive/nested-grammar shape: on in `Auto`, or selectable on its own.
        matches!(self, Self::Auto | Self::Recursive)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzWorkerCount {
    Auto,
    Fixed(u32),
}

#[derive(Debug, Serialize)]
pub(crate) struct FuzzRunSummary {
    pub(crate) schema_version: u32,
    pub(crate) harness_id: String,
    pub(crate) engine: String,
    pub(crate) mode: actionability::RunMode,
    pub(crate) harness_path: PathBuf,
    pub(crate) sandbox: replay_min::SandboxMetadata,
    pub(crate) iterations_requested: usize,
    pub(crate) executions: usize,
    /// True only when a language harness emitted its checkpoint immediately
    /// before the selected project endpoint. Driver executions and driver-only
    /// coverage do not satisfy this proof.
    #[serde(default)]
    pub(crate) target_entry_observed: bool,
    pub(crate) corpus_new: usize,
    pub(crate) corpus_duplicates: usize,
    /// #401: number of coverage-guided corpus inputs flushed to
    /// `corpus/<hid>/queue/` at the end of the run (content-hash-named, seeds
    /// included). 0 for an empty pool. Makes the explored corpus replayable for
    /// neutral coverage measurement / `corpus minimize` instead of lost on exit.
    #[serde(default)]
    pub(crate) corpus_persisted: usize,
    pub(crate) execution: ExecutionRunSummary,
    pub(crate) cmplog: CmpLogRunSummary,
    pub(crate) sanitizers: SanitizerRunSummary,
    pub(crate) coverage: CoverageRunSummary,
    pub(crate) findings: Vec<String>,
    /// #405: actual wall-clock seconds this run spent fuzzing — the engine's
    /// measured run time, NOT the requested budget (a run can finish early or
    /// lose time to setup). 0.0 only when no measurable time elapsed.
    #[serde(default)]
    pub(crate) elapsed_secs: f64,
    /// #405: built-in-engine throughput — `executions / elapsed_secs` — for
    /// head-to-head parity with libFuzzer `average_exec_per_sec` / honggfuzz
    /// `speed`. 0.0 when no measurable time elapsed, and 0.0 for the AFL++
    /// engine (whose `executions` is the saved-crash count, not target execs;
    /// its real throughput is in AFL's own `fuzzer_stats`).
    #[serde(default)]
    pub(crate) executions_per_sec: f64,
}

/// Throughput in executions/sec, guarding the zero-elapsed case (returns 0.0
/// rather than NaN/inf). Shared by every #405 emission site.
pub(crate) fn executions_per_sec(executions: usize, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        executions as f64 / elapsed_secs
    } else {
        0.0
    }
}

/// Edge-coverage measured during the run. For passthrough libFuzzer harnesses the
/// govfuzz driver carries a SanitizerCoverage (`trace-pc-guard`) runtime that sets
/// one bit per hit edge in a shared bitmap (#385); `edges` is the popcount. Zero
/// for harnesses without that runtime (Ada event-log lane, generated `-fsanitize=
/// fuzzer` wrappers) or when GOVFUZZ_COV_SHM was unset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CoverageRunSummary {
    pub(crate) edges: usize,
    pub(crate) source: String,
}

/// Read the govfuzz driver's edge-coverage bitmap (one byte per hit edge) from the
/// path in `GOVFUZZ_COV_SHM`, counting distinct edges. The bitmap is MAP_SHARED so
/// it accumulates across every per-spawn child and within a persistent process.
/// Parse the driver's value-profile token log written at `path`
/// (`[u32 cursor][ {u8 len}{len bytes} ... ]`, native-endian cursor), returning
/// the mined comparison-operand tokens for the mutator dictionary (#398).
fn read_vp_tokens(path: &Path) -> Vec<Vec<u8>> {
    let Ok((bytes, _)) = read_seed_file_prefix(path, GOVFUZZ_VP_BYTES) else {
        return Vec::new();
    };
    if bytes.len() < 4 {
        return Vec::new();
    }
    let cursor = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let end = (4 + cursor).min(bytes.len());
    let mut out = Vec::new();
    let mut i = 4usize;
    while i < end {
        let len = bytes[i] as usize;
        i += 1;
        if len == 0 || len > 8 || i + len > end {
            break;
        }
        out.push(bytes[i..i + len].to_vec());
        i += len;
    }
    out
}

fn coverage_from_env(extra_env: &[(String, String)]) -> CoverageRunSummary {
    let Some((_, path)) = extra_env.iter().find(|(k, _)| k == "GOVFUZZ_COV_SHM") else {
        return CoverageRunSummary {
            edges: 0,
            source: "none".to_owned(),
        };
    };
    let edges = read_seed_file_prefix(Path::new(path), GOVFUZZ_COV_BITS)
        .map(|(bytes, _)| bytes)
        .map(|bytes| bytes.iter().filter(|&&b| b != 0).count())
        .unwrap_or(0);
    CoverageRunSummary {
        edges,
        source: "sancov-trace-pc-guard".to_owned(),
    }
}

fn target_entry_path(extra_env: &[(String, String)]) -> Option<&Path> {
    extra_env
        .iter()
        .find(|(key, _)| key == "GOVFUZZ_TARGET_ENTRY_SHM")
        .map(|(_, value)| Path::new(value))
}

fn reset_target_entry(extra_env: &[(String, String)]) {
    if let Some(path) = target_entry_path(extra_env) {
        let _ = fs::write(path, [0u8]);
    }
}

fn target_entry_from_env(extra_env: &[(String, String)]) -> bool {
    target_entry_path(extra_env)
        .and_then(|path| read_seed_file_prefix(path, 1).ok())
        .is_some_and(|(bytes, _)| bytes.first().is_some_and(|byte| *byte != 0))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ExecutionRunSummary {
    pub(crate) harness_protocol: String,
    pub(crate) forkserver: bool,
    pub(crate) persistent: bool,
    pub(crate) persistent_iterations: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CmpLogRunSummary {
    pub(crate) enabled: bool,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) entries: usize,
    pub(crate) dictionary_tokens: usize,
    pub(crate) seed_splice_candidates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SanitizerRunSummary {
    pub(crate) requested: Vec<String>,
    pub(crate) active_env: Vec<EnvVarSummary>,
    pub(crate) composition_campaign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EnvVarSummary {
    pub(crate) key: String,
    pub(crate) value: String,
}

struct PreparedFuzzRun {
    work_dir: PathBuf,
    harness_id: String,
    harness_path: PathBuf,
    runner: replay_min::HarnessRunner,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time: Option<Duration>,
    /// Stop the in-process loop once this many distinct findings are emitted
    /// (`--per-target-finding-count`). `None` = run to the time/iteration budget.
    stop_after_findings: Option<usize>,
    rng_seed: u64,
    engine: FuzzEngine,
    mode: actionability::RunMode,
    extra_env: Vec<(String, String)>,
    cmplog_log: Option<PathBuf>,
    grammar_file: Option<PathBuf>,
    structured_inputs: StructuredInputMode,
    sanitizers: Vec<multicore_fuzz::Sanitizer>,
    sanitizer_env: Vec<(String, String)>,
    fork_server: bool,
    max_len: usize,
    len_control: usize,
    per_input_timeout: Duration,
    print_final_stats: bool,
    rss_limit_mb: usize,
}

struct HarnessRun {
    events: Vec<Event>,
    testcases: Vec<Testcase>,
    /// Populated when the harness exited non-zero AND a sanitizer report was
    /// recognized in its stderr. The C/C++ fuzz path uses this to emit
    /// findings without an Ada event log.
    sanitizer: Option<corpus::SanitizerReport>,
    /// #15: the target REJECTED this input (assert/abort or a non-zero error
    /// return on malformed bytes) — a clean no-finding run that the pass skips and
    /// continues past. Tracked so `run_builtin` can tell a target that rejected
    /// EVERY input (incl. the empty seed — a gate/seed/harness problem, reported as
    /// built-not-fuzzed) from one that genuinely fuzzed.
    rejected: bool,
}

/// Classify a non-success harness exit (called only when `!status.success()` and
/// NO sanitizer report was found): is it the target REJECTING this input, or a
/// real crash? Only the genuine memory-safety crash signals — SIGSEGV, SIGBUS,
/// SIGILL, SIGFPE — are NOT a rejection; without a sanitizer report they stay a
/// hard error so a real crash on a non-instrumented harness isn't silently
/// swallowed. Everything else is a rejection (#15: skip + continue):
///   - SIGABRT — the `assert()`/`abort()` idiom (an input rejection),
///   - a plain non-zero exit code — an error return,
///   - SIGPIPE (13) — benign plumbing: the harness wrote to a closed pipe (e.g.
///     a `--comparison-progress` / stats pipe whose reader went away). It is
///     NEVER an attacker-triggerable memory-safety bug and does not reproduce
///     standalone, so misclassifying it manufactures a phantom GF-210 "reachable
///     crash" (a valid glTF that exits 0 on replay) — exactly the false positive
///     that undermines triage,
///   - SIGTERM/SIGINT/SIGHUP/SIGALRM — external termination (timeout-kill, etc.),
///     handled by the timeout/hang path, not a code defect in the target.
///
/// Use an allow-list of the real crash signals so any other signal a runtime may
/// raise can never become a phantom finding.
///
/// EXCEPTION — the Windows (mingw + wine) path: a guest hardware fault is NOT
/// delivered as a POSIX signal; the driver's vectored exception handler reports it
/// by exiting with [`GOVFUZZ_WIN_CRASH_EXIT`]. That specific exit code is a genuine
/// crash, not a rejection — any OTHER nonzero exit stays a rejection as before.
///
/// The exit code the Windows (mingw) driver's vectored exception handler uses to
/// report a fatal hardware fault when fuzzing under wine. MUST match
/// `GOVFUZZ_WIN_CRASH_EXIT` in `c_runtime/govfuzz_driver.c` and the
/// `direct_harness.{c,cpp}.tera` templates.
const GOVFUZZ_WIN_CRASH_EXIT: i32 = 0x39;

#[cfg(unix)]
fn is_input_rejection(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    // The Windows (mingw + wine) driver's vectored exception handler reports a
    // guest hardware fault via this exit code — there is no POSIX signal for it —
    // so it is a genuine crash, not a rejection.
    if status.code() == Some(GOVFUZZ_WIN_CRASH_EXIT) {
        return false;
    }
    // SIGILL=4, SIGBUS=7, SIGFPE=8, SIGSEGV=11 — the genuine crash signals.
    const CRASH_SIGNALS: [i32; 4] = [4, 7, 8, 11];
    match status.signal() {
        Some(signal) => !CRASH_SIGNALS.contains(&signal),
        None => true,
    }
}

#[cfg(not(unix))]
fn is_input_rejection(status: &std::process::ExitStatus) -> bool {
    // Off-Unix (native Windows) there are no POSIX signals: the harness driver's
    // vectored exception handler reports a hardware fault via GOVFUZZ_WIN_CRASH_EXIT.
    // Treat that exact code as a genuine crash; any other nonzero exit is an input
    // rejection (an error return on malformed input).
    status.code() != Some(GOVFUZZ_WIN_CRASH_EXIT)
}

/// Human name for a fatal crash signal, for the GF-210 finding message.
#[cfg(unix)]
fn fatal_signal_name(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    if status.code() == Some(GOVFUZZ_WIN_CRASH_EXIT) {
        return "Windows exception (access violation / fault, via wine)".to_owned();
    }
    match status.signal() {
        Some(4) => "SIGILL".to_owned(),
        Some(6) => "SIGABRT".to_owned(),
        Some(7) => "SIGBUS".to_owned(),
        Some(8) => "SIGFPE".to_owned(),
        Some(11) => "SIGSEGV".to_owned(),
        Some(n) => format!("signal {n}"),
        None => format!("exit {:?}", status.code()),
    }
}

#[cfg(not(unix))]
fn fatal_signal_name(status: &std::process::ExitStatus) -> String {
    if status.code() == Some(GOVFUZZ_WIN_CRASH_EXIT) {
        return "Windows exception (access violation / fault)".to_owned();
    }
    format!("exit {:?}", status.code())
}

/// Synthesize the GF-210 "reachable crash (fatal signal, no sanitizer report)"
/// finding for a non-rejection crash on an input. Recording it as a finding —
/// rather than returning a hard error — lets the crash SURFACE and the fuzz
/// cascade keep exploring, instead of one early crash aborting the whole pass and
/// leaving the target reported "built, not fuzzed" with the crash lost (e.g.
/// cute_tiled, whose empty seed crashes before any real input is tried). The
/// replay re-runs the input, hits the same signal, and re-synthesizes GF-210, so
/// the finding still confirms on replay-verify.
fn fatal_signal_report(status: &std::process::ExitStatus) -> corpus::SanitizerReport {
    corpus::SanitizerReport {
        sanitizer: corpus::Sanitizer::AddressSanitizer,
        kind: "fatal-signal".to_owned(),
        rule_id: "GF-210",
        stack: Vec::new(),
        message: format!(
            "harness crashed with {} and no sanitizer report — a reachable crash",
            fatal_signal_name(status)
        ),
    }
}

pub fn run(args: FuzzArgs) -> i32 {
    if multicore_requested(&args) {
        return run_multicore_campaign(args);
    }

    let prepared = match prepare(args) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("{error}");
            return 3;
        }
    };

    let result = match prepared.engine {
        FuzzEngine::Builtin => run_builtin(prepared),
        FuzzEngine::AflPlusPlus => run_afl_plus_plus(prepared),
    };

    match result {
        Ok(summary) => {
            match serde_json::to_string_pretty(&summary) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("failed to render fuzz summary: {error}");
                    return 1;
                }
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// Programmatic fuzz entry used by `govfuzz auto`. Builds a
/// [`FuzzArgs`] for the requested harness id under `work_dir`, runs
/// [`prepare`] + [`run_builtin`], and returns the resulting summary
/// without serialising it. Errors bubble up as `String` (same shape as
/// [`prepare`] / [`run_builtin`]) so the caller can downgrade them to a
/// `Built` outcome without losing the original message.
/// Periodic live-progress callback for the builtin fuzz loop:
/// `(executions, findings_so_far, elapsed)` sampled at most every
/// 500ms so the hot loop stays hot.
pub(crate) type FuzzProgressFn<'a> = &'a dyn Fn(usize, usize, Duration);

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_one_target_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time_budget: Option<Duration>,
    stop_after_findings: Option<usize>,
    rss_limit_mb: usize,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    cmplog_log: Option<PathBuf>,
    sanitizers: &[multicore_fuzz::Sanitizer],
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    run_one_target_programmatic_with_runner(
        work_dir,
        harness_id,
        seeds,
        iterations,
        time_budget,
        stop_after_findings,
        rss_limit_mb,
        extra_env,
        mode,
        cmplog_log,
        None,
        sanitizers,
        progress,
    )
}

/// As [`run_one_target_programmatic`], but with an optional pre-built runner
/// that REPLACES the default direct/host runner — `govfuzz auto` passes a
/// qemu-user / wine runner for a foreign-platform/arch harness so the cross-built
/// binary runs under emulation. `runner == None` is identical to the host path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_one_target_programmatic_with_runner(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time_budget: Option<Duration>,
    stop_after_findings: Option<usize>,
    rss_limit_mb: usize,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    cmplog_log: Option<PathBuf>,
    runner: Option<replay_min::HarnessRunner>,
    // Sanitizers requested by `govfuzz auto --sanitizers`. The auto path builds the
    // harness with the matching `-fsanitize=` flags (attempt.rs); naming them here
    // makes `prepare` inject the run-time `<SAN>_OPTIONS` env (abort_on_error /
    // halt_on_error / detect_leaks) and record them in the run's sanitizer summary,
    // exactly as the standalone `govfuzz fuzz --sanitizers` path does. Empty for
    // every existing caller, so the run record / env are byte-identical to before.
    sanitizers: &[multicore_fuzz::Sanitizer],
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    // `auto --max-len` / `--timeout` publish their choice via env (GOVFUZZ_MAX_LEN /
    // GOVFUZZ_EXEC_TIMEOUT); resolve them here where the seed sizes are known (so a
    // large seed is never truncated). Unset (non-auto callers / tests) keeps the
    // historical defaults.
    let largest_seed = seeds.iter().map(Vec::len).max().unwrap_or(0);
    let args = FuzzArgs {
        work_dir: work_dir.to_path_buf(),
        harness: harness_id.to_owned(),
        engine: FuzzEngine::Builtin,
        workers: None,
        iterations: Some(iterations),
        time: time_budget,
        timeout: resolve_env_timeout(),
        max_len: resolve_env_max_len(largest_seed),
        len_control: DEFAULT_LEN_CONTROL,
        print_final_stats: false,
        // Per-harness memory cap so a fuzzer-controlled huge allocation is caught
        // as an OOM finding (GF-209) instead of OOM-killing the host (#386).
        rss_limit_mb,
        fork_server: false,
        no_fork_server: false,
        seed_inputs: seeds
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect(),
        seed_files: Vec::new(),
        sanitizers: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        symbolic_seed_sources: Vec::new(),
        rng_seed: 0x4756_4655_5a5a,
        sandbox: crate::runner::SandboxModeArg::Auto,
        mode,
        sandbox_tool: None,
        sandbox_strict: false,
        extra_env: extra_env.to_vec(),
        cmplog_log,
        grammar_file: None,
        structured_inputs: StructuredInputMode::Auto,
        govfuzz_bin: None,
        stop_after_findings,
    };
    let mut prepared = prepare(args)?;
    // A caller-supplied cross runner overrides the direct/host runner `prepare`
    // resolved from the harness path (qemu-user / wine emulation).
    if let Some(runner) = runner {
        prepared.runner = runner;
    }
    run_builtin_with_progress(prepared, progress)
}

/// Drive AFL++ against an already-built `main_afl` for `govfuzz auto`'s attempt
/// loop, returning the SAME [`FuzzRunSummary`] the builtin programmatic runner
/// returns so AFL crashes fold into the shared findings pipeline (GF-210 /
/// sanitizer-report / replay-verify) — no separate report path. Reuses
/// [`prepare`] (which resolves the `main_afl` path for the AFL engine, builds the
/// runner, and arms the sanitizer env) and the existing [`run_afl_plus_plus`]
/// drive + crash harvest. Errors (no `main_afl`, afl-fuzz failure) propagate to
/// the caller, which records a warning and continues — it must NOT abort the
/// target. `iterations` is unused by AFL (it runs on a wall-clock `-V` budget).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_afl_plus_plus_programmatic(
    work_dir: &Path,
    harness_id: &str,
    seeds: Vec<Vec<u8>>,
    time_budget: Option<Duration>,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    rss_limit_mb: usize,
    sanitizers: &[multicore_fuzz::Sanitizer],
) -> Result<FuzzRunSummary, String> {
    let args = FuzzArgs {
        work_dir: work_dir.to_path_buf(),
        harness: harness_id.to_owned(),
        engine: FuzzEngine::AflPlusPlus,
        workers: None,
        iterations: Some(0),
        time: time_budget,
        timeout: None,
        max_len: DEFAULT_MAX_LEN,
        len_control: DEFAULT_LEN_CONTROL,
        print_final_stats: false,
        rss_limit_mb,
        fork_server: false,
        no_fork_server: false,
        seed_inputs: seeds
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect(),
        seed_files: Vec::new(),
        sanitizers: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        symbolic_seed_sources: Vec::new(),
        rng_seed: 0x4756_4655_5a5a,
        sandbox: crate::runner::SandboxModeArg::Auto,
        mode,
        sandbox_tool: None,
        sandbox_strict: false,
        extra_env: extra_env.to_vec(),
        cmplog_log: None,
        grammar_file: None,
        structured_inputs: StructuredInputMode::Auto,
        govfuzz_bin: None,
        stop_after_findings: None,
    };
    let prepared = prepare(args)?;
    run_afl_plus_plus(prepared)
}

fn multicore_requested(args: &FuzzArgs) -> bool {
    if args.sanitizers.len() > 1 {
        return true;
    }
    matches!(args.workers, Some(FuzzWorkerCount::Auto))
        || matches!(args.workers, Some(FuzzWorkerCount::Fixed(n)) if n > 1)
}

fn run_multicore_campaign(args: FuzzArgs) -> i32 {
    let sanitizers = match parse_sanitizer_args(&args.sanitizers) {
        Ok(sanitizers) => sanitizers,
        Err(error) => {
            eprintln!("{error}");
            return 3;
        }
    };
    let min_workers = sanitizers.runtime_set().len().max(1) as u32;
    let workers = match args.workers {
        Some(FuzzWorkerCount::Auto) => multicore_fuzz::WorkerCount::Auto,
        Some(FuzzWorkerCount::Fixed(n)) => multicore_fuzz::WorkerCount::Fixed(n.max(min_workers)),
        None => multicore_fuzz::WorkerCount::Fixed(min_workers),
    };
    let govfuzz_bin = match args.govfuzz_bin.clone() {
        Some(path) => path,
        None => match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("resolve current govfuzz executable: {error}");
                return 3;
            }
        },
    };
    let config = multicore_fuzz::MulticoreConfig {
        work_dir: args.work_dir.clone(),
        harness_id: args.harness.clone(),
        workers,
        // Pass the raw Option through: an explicit cap reaches each worker as
        // `--iterations N`; when omitted under `--time`, workers receive no
        // `--iterations` and resolve to time-bounded themselves.
        per_worker_iterations: args.iterations.map(|n| n as u64),
        time_budget: args.time.unwrap_or(Duration::ZERO),
        govfuzz_bin,
        per_worker_env: multicore_fuzz::sanitizer_envs(sanitizers.runtime_set()),
        extra_worker_args: worker_passthrough_args(&args),
        kill_grace: None,
    };

    match multicore_fuzz::run_multicore(&config) {
        Ok(summary) => {
            match serde_json::to_string_pretty(&summary) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("failed to render multicore fuzz summary: {error}");
                    return 1;
                }
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            match error {
                multicore_fuzz::MulticoreError::WorkDirMissing(_)
                | multicore_fuzz::MulticoreError::BinMissing(_)
                | multicore_fuzz::MulticoreError::InvalidWorkerCount => 3,
                _ => 1,
            }
        }
    }
}

fn worker_passthrough_args(args: &FuzzArgs) -> Vec<String> {
    let mut out = vec![
        "--engine".to_owned(),
        engine_arg_name(args.engine).to_owned(),
        "--mode".to_owned(),
        args.mode.to_string(),
        "--sandbox".to_owned(),
        sandbox_arg_name(args.sandbox).to_owned(),
    ];
    if let Some(tool) = &args.sandbox_tool {
        out.push("--sandbox-tool".to_owned());
        out.push(tool.display().to_string());
    }
    if args.sandbox_strict {
        out.push("--sandbox-strict".to_owned());
    }
    for seed in &args.seed_inputs {
        out.push("--seed-input".to_owned());
        out.push(seed.clone());
    }
    for seed_file in &args.seed_files {
        out.push("--seed-file".to_owned());
        out.push(seed_file.display().to_string());
    }
    for source in &args.symbolic_seed_sources {
        out.push("--symbolic-seed-source".to_owned());
        out.push(source.display().to_string());
    }
    if let Some(cmplog_log) = &args.cmplog_log {
        out.push("--cmplog-log".to_owned());
        out.push(cmplog_log.display().to_string());
    }
    out.push("--structured-inputs".to_owned());
    out.push(structured_input_mode_arg_name(args.structured_inputs).to_owned());
    out.push("--max-len".to_owned());
    out.push(args.max_len.to_string());
    out.push("--len-control".to_owned());
    out.push(args.len_control.to_string());
    if let Some(timeout) = args.timeout {
        out.push("--timeout".to_owned());
        out.push(format!("{}s", timeout.as_secs().max(1)));
    }
    if args.rss_limit_mb > 0 {
        out.push("--rss-limit-mb".to_owned());
        out.push(args.rss_limit_mb.to_string());
    }
    out
}

fn engine_arg_name(engine: FuzzEngine) -> &'static str {
    match engine {
        FuzzEngine::Builtin => "builtin",
        FuzzEngine::AflPlusPlus => "afl++",
    }
}

fn sandbox_arg_name(sandbox: SandboxModeArg) -> &'static str {
    match sandbox {
        SandboxModeArg::None => "none",
        SandboxModeArg::Auto => "auto",
        SandboxModeArg::Firejail => "firejail",
        SandboxModeArg::Bubblewrap => "bubblewrap",
    }
}

fn structured_input_mode_arg_name(mode: StructuredInputMode) -> &'static str {
    match mode {
        StructuredInputMode::Auto => "auto",
        StructuredInputMode::Off => "off",
        StructuredInputMode::Record => "record",
        StructuredInputMode::Json => "json",
        StructuredInputMode::Xml => "xml",
        StructuredInputMode::Kv => "kv",
        StructuredInputMode::Url => "url",
        StructuredInputMode::Multipart => "multipart",
        StructuredInputMode::Csv => "csv",
        StructuredInputMode::Http => "http",
        StructuredInputMode::Ini => "ini",
        StructuredInputMode::Toml => "toml",
        StructuredInputMode::Yaml => "yaml",
        StructuredInputMode::Recursive => "recursive",
    }
}

fn prepare(args: FuzzArgs) -> Result<PreparedFuzzRun, String> {
    match args.engine {
        FuzzEngine::Builtin | FuzzEngine::AflPlusPlus => {}
    }
    let iterations = args.effective_iterations();
    let sanitizers = parse_sanitizer_args(&args.sanitizers)?
        .runtime_set()
        .to_vec();
    let sanitizer_env = sanitizer_env_for(&sanitizers);

    let work_dir = absolutize(&args.work_dir)?;
    if !work_dir.is_dir() {
        return Err(format!("work dir '{}' does not exist", work_dir.display()));
    }

    let harness_path = find_harness_executable(&work_dir, &args.harness, args.engine)?;
    let runner = harness_runner(
        harness_path.clone(),
        None,
        Vec::new(),
        args.sandbox,
        args.sandbox_tool,
        args.sandbox_strict,
    );
    let mut seeds = args
        .seed_inputs
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    for seed_file in args.seed_files {
        let (bytes, original_len) = read_seed_file_prefix(&seed_file, args.max_len.max(1))
            .map_err(|error| format!("read seed file '{}': {error}", seed_file.display()))?;
        if original_len > bytes.len() as u64 {
            eprintln!(
                "govfuzz: seed '{}' is {original_len} bytes; using its first {} bytes \
                 to honor --max-len",
                seed_file.display(),
                bytes.len()
            );
        }
        seeds.push(bytes);
    }
    let mut symbolic_sources = Vec::new();
    let mut symbolic_source_bytes = 0usize;
    let symbolic_source_limit = max_symbolic_source_bytes();
    let symbolic_sources_total_limit = max_symbolic_sources_total_bytes();
    for path in &args.symbolic_seed_sources {
        let (bytes, original_len) = read_seed_file_prefix(path, symbolic_source_limit)
            .map_err(|error| format!("read symbolic seed source '{}': {error}", path.display()))?;
        if original_len > bytes.len() as u64 {
            return Err(format!(
                "symbolic seed source '{}' is {original_len} bytes, above the {} MiB safety limit",
                path.display(),
                symbolic_source_limit / (1024 * 1024)
            ));
        }
        if symbolic_source_bytes.saturating_add(bytes.len()) > symbolic_sources_total_limit {
            return Err(format!(
                "symbolic seed sources exceed the {} MiB aggregate safety limit",
                symbolic_sources_total_limit / (1024 * 1024)
            ));
        }
        let contents = String::from_utf8(bytes).map_err(|error| {
            format!(
                "symbolic seed source '{}' is not UTF-8: {error}",
                path.display()
            )
        })?;
        symbolic_source_bytes = symbolic_source_bytes.saturating_add(contents.len());
        symbolic_sources.push((path.display().to_string(), contents));
    }
    let symbolic_sources = symbolic_sources
        .iter()
        .map(|(path, contents)| SymbolicSeedSource::new(path, contents))
        .collect::<Vec<_>>();
    seeds.extend(
        generate_symbolic_seeds(symbolic_sources)
            .into_iter()
            .map(|seed| seed.bytes),
    );
    bound_seed_corpus(&mut seeds, args.max_len.max(1));
    let mut extra_env = args.extra_env;
    extra_env.extend(sanitizer_env.clone());
    apply_fuzz_child_env_overrides(&mut extra_env);

    Ok(PreparedFuzzRun {
        work_dir,
        harness_id: args.harness,
        harness_path,
        runner,
        seeds,
        iterations,
        time: args.time,
        stop_after_findings: args.stop_after_findings,
        rng_seed: args.rng_seed,
        engine: args.engine,
        mode: args.mode,
        extra_env,
        cmplog_log: args.cmplog_log,
        grammar_file: args.grammar_file,
        structured_inputs: args.structured_inputs,
        sanitizers,
        sanitizer_env,
        fork_server: resolve_fork_server(args.fork_server, args.no_fork_server),
        max_len: args.max_len.max(1),
        len_control: args.len_control,
        per_input_timeout: args.timeout.unwrap_or(PER_INPUT_TIMEOUT),
        print_final_stats: args.print_final_stats,
        rss_limit_mb: args.rss_limit_mb,
    })
}

/// Resident set size (MB) of a running process, from `/proc/<pid>/statm`.
/// Returns `None` when unavailable (non-Linux, or the process already exited).
/// Size (bytes) of the driver's shared edge-coverage bitmap. MUST match
/// `GOVFUZZ_COV_BITS` in the passthrough harness template
/// (`crates/harness_gen/src/templates/direct_harness.c.tera`) — the driver and
/// this reader map the same file.
const GOVFUZZ_COV_BITS: usize = 1 << 16;

/// Size (bytes) of the driver's comparison-progress map (#421 laf-intel). One
/// byte per hashed compare site, holding this exec's MAX leading-byte-match count
/// for that site. MUST match `GOVFUZZ_CMPP_BITS` in BOTH
/// `direct_harness.c.tera` and `direct_harness.cpp.tera` — the driver and this
/// reader map the same file. Same size as the edge bitmap so site hashing has
/// the same collision envelope.
#[cfg(any(target_os = "linux", windows))]
const GOVFUZZ_CMPP_BITS: usize = 1 << 16;

/// Map a per-input edge hit count to an AFL-style logarithmic bucket (#420) so a
/// loop run N+1 vs N is distinguishable across a bucket boundary but identical
/// within one. REPLICATED from the canonical `count_to_bucket` in
/// `crates/fuzz_engine/builtin/src/coverage.rs` (the in-process engine's #381
/// channel) — keep the two IDENTICAL: 1->0, 2->1, 3->2, 4..=7->3, 8..=15->4,
/// 16..=31->5, 32..=127->6, 128..->7. The argument is a saturating `u8` map byte,
/// so 255 lands in the top bucket exactly like 128+.
#[cfg(any(target_os = "linux", windows))]
fn count_to_bucket(count: u8) -> u8 {
    match count {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

/// Reads the govfuzz driver's cumulative SanitizerCoverage edge bitmap so the
/// engine can tell, per exec, whether an input grew coverage and should be kept
/// in the corpus (#398). The driver writes the bitmap via a MAP_SHARED mapping of
/// `GOVFUZZ_COV_SHM`; this maps the same file read-only, so reads are pure memory
/// (no syscall per exec) and stay cheap at fork-server exec rates.
/// Minimal `kernel32` file-mapping FFI so the coverage/cmplog SHM readers work on
/// native Windows without an external crate. The driver writes these maps via the
/// same Win32 file mapping (`gf_map_shared` in the C driver), so engine + harness
/// share the bytes — the Windows analogue of the Linux `mmap(MAP_SHARED)` path.
#[cfg(windows)]
mod win_shm {
    use std::os::windows::io::AsRawHandle;
    type Handle = *mut core::ffi::c_void;
    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_ALL_ACCESS: u32 = 0x000F_001F;
    extern "system" {
        fn CreateFileMappingW(
            file: Handle,
            attrs: *mut core::ffi::c_void,
            protect: u32,
            max_hi: u32,
            max_lo: u32,
            name: *const u16,
        ) -> Handle;
        fn MapViewOfFile(
            map: Handle,
            access: u32,
            hi: u32,
            lo: u32,
            bytes: usize,
        ) -> *mut core::ffi::c_void;
        fn UnmapViewOfFile(addr: *const core::ffi::c_void) -> i32;
    }
    /// Map `len` bytes of `file` as a shared read+write view, or `None`. The
    /// section handle is intentionally leaked for the process lifetime (the view
    /// stays valid even after `file` is dropped; the OS reclaims it at exit),
    /// mirroring the Linux mmap-outlives-fd contract.
    pub fn map(file: &std::fs::File, len: usize) -> Option<*mut u8> {
        // SAFETY: `file` is a valid open handle; we map exactly `len` bytes of the
        // section it backs and never read/write beyond `len`.
        unsafe {
            let m = CreateFileMappingW(
                file.as_raw_handle() as Handle,
                core::ptr::null_mut(),
                PAGE_READWRITE,
                ((len as u64) >> 32) as u32,
                (len & 0xffff_ffff) as u32,
                core::ptr::null(),
            );
            if m.is_null() {
                return None;
            }
            let p = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, len);
            if p.is_null() {
                None
            } else {
                Some(p as *mut u8)
            }
        }
    }
    pub fn unmap(ptr: *mut u8) {
        // SAFETY: `ptr` was returned by `MapViewOfFile` for this process.
        unsafe {
            UnmapViewOfFile(ptr as *const core::ffi::c_void);
        }
    }
}

/// Open (creating + sizing) the file at `path` and map `len` bytes of it as a
/// shared read+write region the driver also maps, returning the base pointer or
/// `None`. The mapping outlives the file handle on both platforms (Linux kernel
/// keeps the mmap; Windows keeps the section). This is the one place the
/// coverage/cmplog readers touch platform shared-memory APIs.
#[cfg(any(target_os = "linux", windows))]
fn map_shared_file(path: &str, len: usize) -> Option<*mut u8> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .ok()?;
    file.set_len(len as u64).ok()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: mapping `len` bytes of a file sized to `len`; the kernel keeps
        // the mapping valid past `file`'s drop.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            None
        } else {
            Some(p as *mut u8)
        }
    }
    #[cfg(windows)]
    {
        win_shm::map(&file, len)
    }
}

/// Release a region from [`map_shared_file`].
#[cfg(any(target_os = "linux", windows))]
fn unmap_shared(ptr: *mut u8, _len: usize) {
    if ptr.is_null() {
        return;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `ptr`/`_len` are the region returned by our mmap.
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, _len);
    }
    #[cfg(windows)]
    win_shm::unmap(ptr);
}

#[cfg(any(target_os = "linux", windows))]
struct CoverageTracker {
    map: *mut u8,
    len: usize,
    last_count: usize,
    /// #420 hit-count buckets: a SEPARATE, PARALLEL channel to the presence map
    /// above. `cnt_map` is the driver's per-exec edge hit-count map
    /// (`GOVFUZZ_COV_CNT_SHM`); null when that env is unset (e.g. the Ada
    /// trace-pc path), in which case the bucket channel is inert and presence
    /// behavior is byte-for-byte unchanged. `virgin_buckets` is the engine-side
    /// cumulative per-edge bitmask of AFL log-buckets ever observed.
    cnt_map: *mut u8,
    cnt_len: usize,
    virgin_buckets: Vec<u8>,
    /// #421 laf-intel comparison-progress: a THIRD parallel channel. `cmpp_map` is
    /// the driver's per-exec map of MAX leading-byte-match per hashed compare site
    /// (`GOVFUZZ_CMP_PROGRESS_SHM`); null when that env is unset (flag off, or the
    /// Ada trace-pc path), in which case the channel is inert. `virgin_progress`
    /// is the engine-side cumulative per-site bitmask of leading-match LEVELS ever
    /// observed, so an input that matches more leading bytes of a gate than any
    /// prior input registers as new coverage — laf-intel's gradient without an
    /// LLVM split pass.
    cmpp_map: *mut u8,
    cmpp_len: usize,
    virgin_progress: Vec<u8>,
}

#[cfg(any(target_os = "linux", windows))]
impl CoverageTracker {
    fn new(extra_env: &[(String, String)]) -> Option<Self> {
        let (_, path) = extra_env.iter().find(|(k, _)| k == "GOVFUZZ_COV_SHM")?;
        // The edge bitmap, shared with the driver. Mapped read+write so
        // colorization (#400) can snapshot/zero/restore it around probe execs
        // without polluting the cumulative #398 feedback.
        let map = map_shared_file(path, GOVFUZZ_COV_BITS)?;
        // #420: optionally map the driver's per-exec hit-count map (a parallel
        // channel to the presence bitmap). Absent (null) when GOVFUZZ_COV_CNT_SHM
        // is unset — the Ada trace-pc path and any harness without the #420
        // runtime — leaving the bucket channel inert. Same GOVFUZZ_COV_BITS size,
        // one saturating byte per edge; mapped read+write so the engine can zero
        // it before each exec (the harness only ever increments it).
        let mut cnt_map: *mut u8 = std::ptr::null_mut();
        let mut cnt_len = 0usize;
        if let Some((_, cnt_path)) = extra_env.iter().find(|(k, _)| k == "GOVFUZZ_COV_CNT_SHM") {
            if let Some(m) = map_shared_file(cnt_path, GOVFUZZ_COV_BITS) {
                cnt_map = m;
                cnt_len = GOVFUZZ_COV_BITS;
            }
        }
        let virgin_buckets = if cnt_map.is_null() {
            Vec::new()
        } else {
            vec![0u8; GOVFUZZ_COV_BITS]
        };
        // #421: optionally map the driver's per-exec comparison-progress map (a
        // third parallel channel). Absent (null) when GOVFUZZ_CMP_PROGRESS_SHM is
        // unset — the flag is off, or a harness without the #421 runtime — leaving
        // the channel inert. `GOVFUZZ_CMPP_BITS`-sized, one byte per hashed site;
        // mapped read+write so the engine can zero it before each exec (the harness
        // only ever raises a site's value via a `max`-write).
        let mut cmpp_map: *mut u8 = std::ptr::null_mut();
        let mut cmpp_len = 0usize;
        if let Some((_, cmpp_path)) = extra_env
            .iter()
            .find(|(k, _)| k == "GOVFUZZ_CMP_PROGRESS_SHM")
        {
            if let Some(m) = map_shared_file(cmpp_path, GOVFUZZ_CMPP_BITS) {
                cmpp_map = m;
                cmpp_len = GOVFUZZ_CMPP_BITS;
            }
        }
        let virgin_progress = if cmpp_map.is_null() {
            Vec::new()
        } else {
            vec![0u8; GOVFUZZ_CMPP_BITS]
        };
        let mut tracker = Self {
            map,
            len: GOVFUZZ_COV_BITS,
            last_count: 0,
            cnt_map,
            cnt_len,
            virgin_buckets,
            cmpp_map,
            cmpp_len,
            virgin_progress,
        };
        // Start from whatever coverage already exists (so a later pass only counts
        // edges beyond the earlier passes' accumulated bitmap as "new").
        tracker.last_count = tracker.count();
        Some(tracker)
    }

    /// Number of distinct edges hit so far (set bytes in the bitmap). Scanned as
    /// u64 words so a mostly-empty map costs ~O(edges), not O(map size).
    fn count(&self) -> usize {
        // SAFETY: `self.map` is a valid `self.len`-byte read-only mapping for the
        // tracker's lifetime; `self.len` is a multiple of 8.
        let words = unsafe { std::slice::from_raw_parts(self.map as *const u64, self.len / 8) };
        let mut count = 0usize;
        for &w in words {
            if w != 0 {
                count += w.to_ne_bytes().iter().filter(|&&b| b != 0).count();
            }
        }
        count
    }

    /// Whether the just-executed input grew edge coverage. Stateful: updates the
    /// running maximum, so call exactly once per exec.
    fn input_increased_coverage(&mut self) -> bool {
        let now = self.count();
        let grew = now > self.last_count;
        if grew {
            self.last_count = now;
        }
        grew
    }

    /// Copy the raw edge bitmap (#400 colorization). Used to save the cumulative
    /// state before colorization probes and to compare per-exec footprints.
    fn snapshot(&self) -> Vec<u8> {
        // SAFETY: `self.map` is a valid `self.len`-byte mapping.
        unsafe { std::slice::from_raw_parts(self.map as *const u8, self.len) }.to_vec()
    }

    /// Zero the edge bitmap so the next exec records its footprint in isolation.
    fn zero(&self) {
        // SAFETY: `self.map`/`self.len` are our writable mapping.
        unsafe { std::ptr::write_bytes(self.map, 0, self.len) }
    }

    /// Restore the edge bitmap from a [`snapshot`](Self::snapshot). Called after
    /// colorization so its probe execs never alter the cumulative #398 feedback.
    fn restore(&self, snapshot: &[u8]) {
        let n = snapshot.len().min(self.len);
        // SAFETY: copying `n <= self.len` bytes into our writable mapping.
        unsafe { std::ptr::copy_nonoverlapping(snapshot.as_ptr(), self.map, n) }
    }

    /// Zero the per-exec hit-count map (#420) so the NEXT exec records its edge
    /// hit counts in isolation; the harness only ever increments it. Called
    /// before EVERY main exec. No-op when the count map is absent (Ada/legacy).
    fn zero_counts(&self) {
        if self.cnt_map.is_null() {
            return;
        }
        // SAFETY: when non-null, `self.cnt_map`/`self.cnt_len` is our writable mapping.
        unsafe { std::ptr::write_bytes(self.cnt_map, 0, self.cnt_len) }
    }

    /// Whether the just-executed input pushed any edge into an AFL hit-count
    /// BUCKET not previously seen for that edge (#420) — the loop/recursion-depth
    /// novelty that edge-presence cannot register (a loop run deeper than any
    /// prior input crosses a bucket boundary; noise WITHIN a bucket does not).
    /// Stateful: folds each newly-seen `(edge, bucket)` into `virgin_buckets`, so
    /// call exactly once per main exec, AFTER the exec and BEFORE `zero_counts`
    /// for the next one. No-op (false) when the count map is absent.
    fn input_grew_buckets(&mut self) -> bool {
        if self.cnt_map.is_null() {
            return false;
        }
        // SAFETY: when non-null, `self.cnt_map`/`self.cnt_len` is a valid mapping
        // for the tracker's lifetime; `virgin_buckets` is sized to `cnt_len`.
        let counts = unsafe { std::slice::from_raw_parts(self.cnt_map as *const u8, self.cnt_len) };
        let mut novel = false;
        for (edge, &count) in counts.iter().enumerate() {
            // count 0 == edge not hit this exec; only bucket edges actually run.
            if count == 0 {
                continue;
            }
            let bit = 1u8 << count_to_bucket(count);
            let seen = &mut self.virgin_buckets[edge];
            if *seen & bit == 0 {
                *seen |= bit;
                novel = true;
            }
        }
        novel
    }

    /// Zero the per-exec comparison-progress map (#421) so the NEXT exec records
    /// its per-site leading-byte-match in isolation; the harness only ever raises
    /// a site via a `max`-write. Called before EVERY main exec. No-op when the
    /// progress map is absent (flag off / Ada / legacy).
    fn zero_progress(&self) {
        if self.cmpp_map.is_null() {
            return;
        }
        // SAFETY: when non-null, `self.cmpp_map`/`self.cmpp_len` is our writable mapping.
        unsafe { std::ptr::write_bytes(self.cmpp_map, 0, self.cmpp_len) }
    }

    /// Whether the just-executed input matched MORE leading bytes of some compare
    /// than any prior input — laf-intel's gradient (#421). For each hashed compare
    /// site the harness recorded a per-exec MAX leading-byte-match LEVEL; the first
    /// time a site reaches a given level is novel (folded into `virgin_progress`),
    /// so an input that gets one more byte of a multi-byte gate correct is retained
    /// and energized exactly like new edge coverage. Stateful: call exactly once
    /// per main exec, AFTER the exec and BEFORE `zero_progress` for the next one.
    /// No-op (false) when the progress map is absent.
    fn input_advanced_comparisons(&mut self) -> bool {
        if self.cmpp_map.is_null() {
            return false;
        }
        // SAFETY: when non-null, `self.cmpp_map`/`self.cmpp_len` is a valid mapping
        // for the tracker's lifetime; `virgin_progress` is sized to `cmpp_len`.
        let progress =
            unsafe { std::slice::from_raw_parts(self.cmpp_map as *const u8, self.cmpp_len) };
        let mut novel = false;
        for (site, &level) in progress.iter().enumerate() {
            // level 0 == no leading-byte match (or site not hit this exec); only a
            // positive leading-match is a gradient signal.
            if level == 0 {
                continue;
            }
            // Cap at 7 so `1 << level` fits a u8 (a full 8-byte match passes the
            // gate and lights a real edge — the progress channel need not encode it).
            let bit = 1u8 << level.min(7);
            let seen = &mut self.virgin_progress[site];
            if *seen & bit == 0 {
                *seen |= bit;
                novel = true;
            }
        }
        novel
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for CoverageTracker {
    fn drop(&mut self) {
        unmap_shared(self.map, self.len);
        unmap_shared(self.cnt_map, self.cnt_len);
        unmap_shared(self.cmpp_map, self.cmpp_len);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
struct CoverageTracker;

#[cfg(not(any(target_os = "linux", windows)))]
impl CoverageTracker {
    fn new(_extra_env: &[(String, String)]) -> Option<Self> {
        None
    }
    fn input_increased_coverage(&mut self) -> bool {
        false
    }
    fn snapshot(&self) -> Vec<u8> {
        Vec::new()
    }
    fn zero(&self) {}
    fn restore(&self, _snapshot: &[u8]) {}
    fn zero_counts(&self) {}
    fn input_grew_buckets(&mut self) -> bool {
        false
    }
    fn zero_progress(&self) {}
    fn input_advanced_comparisons(&mut self) -> bool {
        false
    }
}

/// One corpus entry in the builtin engine's mutation pool. Replaces the prior
/// three length-synced `Vec`s (#382 energy/selections) so each entry can also
/// cache its per-input RedQueen cmplog (#400): the comparison operand pairs
/// captured by running this entry once with `GOVFUZZ_CMP_SHM` capture armed.
/// Cached so the capture exec is paid once per base, then reused across all the
/// children mutated from it.
struct PoolEntry {
    bytes: Vec<u8>,
    /// #382 entropic energy: coverage novelty this entry contributed.
    energy: u32,
    /// #382: how many times this entry has seeded a mutation.
    selections: u64,
    /// #400: operand pairs observed while running this entry (driver path only),
    /// `None` until it is first selected for mutation (and on non-driver paths).
    cmplog: Option<cmplog::CmpLog>,
    /// #400 colorization: a coverage-equivalent variant of `bytes` whose
    /// don't-care positions hold near-unique values, so `cmplog` operands splice
    /// at the offset they were compared instead of every occurrence of a common
    /// byte. `None` until captured; mutation draws from it when present.
    colored: Option<Vec<u8>>,
}

impl PoolEntry {
    fn seed(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            energy: 1,
            selections: 0,
            cmplog: None,
            colored: None,
        }
    }

    /// The bytes to mutate from: the colorized variant once captured, else the
    /// raw corpus bytes.
    fn mutation_base(&self) -> &[u8] {
        self.colored.as_deref().unwrap_or(&self.bytes)
    }
}

/// Shared-memory layout of the driver's per-exec cmplog ring. MUST match the
/// `GOVFUZZ_CMP_*` macros in the harness template
/// (`crates/harness_gen/src/templates/direct_harness.c.tera`): header
/// `[u32 armed][u32 count]` then `GOVFUZZ_CMP_CAP` records of
/// `[u8 len_a][u8 len_b][u8 a[OPMAX]][u8 b[OPMAX]]`.
// Used by the mmap/file-mapping CmpShmReader on linux + windows (and its tests);
// the reader is a no-op stub on other platforms, so gate these to match.
#[cfg(any(target_os = "linux", windows))]
const GOVFUZZ_CMP_CAP: usize = 2048;
#[cfg(any(target_os = "linux", windows))]
const GOVFUZZ_CMP_OPMAX: usize = 32;
#[cfg(any(target_os = "linux", windows))]
const GOVFUZZ_CMP_REC: usize = 2 + 2 * GOVFUZZ_CMP_OPMAX;
#[cfg(any(target_os = "linux", windows))]
const GOVFUZZ_CMP_BYTES: usize = 8 + GOVFUZZ_CMP_CAP * GOVFUZZ_CMP_REC;

/// Reads (and arms) the driver's per-exec cmplog operand ring (#400). RedQueen
/// input-to-state: the engine arms capture for the one corpus entry it is about
/// to mutate, runs it once (the driver records the comparison operand pairs that
/// run produced), then builds a `CmpLog` whose `splice_candidates` find those
/// operands at the offsets they were compared in *that* input. Mapped
/// `MAP_SHARED` read+write so the engine can set `armed` and zero `count`.
#[cfg(any(target_os = "linux", windows))]
struct CmpShmReader {
    map: *mut u8,
    len: usize,
}

#[cfg(any(target_os = "linux", windows))]
impl CmpShmReader {
    fn new(extra_env: &[(String, String)]) -> Option<Self> {
        let (_, path) = extra_env.iter().find(|(k, _)| k == "GOVFUZZ_CMP_SHM")?;
        let map = map_shared_file(path, GOVFUZZ_CMP_BYTES)?;
        Some(Self {
            map,
            len: GOVFUZZ_CMP_BYTES,
        })
    }

    /// Zero `count` and set `armed` so the next exec records into the ring. The
    /// driver does not reset the ring itself; pipe ordering (this store -> frame
    /// write -> child read) makes the store visible before the child appends.
    fn arm(&self) {
        // SAFETY: `self.map` is a valid `GOVFUZZ_CMP_BYTES` rw mapping; header is
        // the first 8 bytes.
        unsafe {
            std::ptr::write_volatile(self.map, 1u8);
            for i in 1..8 {
                std::ptr::write_volatile(self.map.add(i), 0u8);
            }
        }
    }

    /// Clear `armed` so subsequent (child) execs do not record.
    fn disarm(&self) {
        // SAFETY: as above.
        unsafe {
            for i in 0..4 {
                std::ptr::write_volatile(self.map.add(i), 0u8);
            }
        }
    }

    /// Build a `CmpLog` from the operand pairs recorded since the last `arm`.
    /// Deduped; `count` and operand lengths are clamped to the shared capacity so
    /// a corrupt header (untrusted child) can never drive an out-of-bounds read.
    fn read_log(&self) -> cmplog::CmpLog {
        let mut log = cmplog::CmpLog::new();
        // SAFETY: the 8-byte header is within the mapping.
        let count = unsafe {
            (std::ptr::read_volatile(self.map.add(4)) as usize)
                | ((std::ptr::read_volatile(self.map.add(5)) as usize) << 8)
                | ((std::ptr::read_volatile(self.map.add(6)) as usize) << 16)
                | ((std::ptr::read_volatile(self.map.add(7)) as usize) << 24)
        }
        .min(GOVFUZZ_CMP_CAP);
        let mut seen = HashSet::<(Vec<u8>, Vec<u8>)>::new();
        for i in 0..count {
            let off = 8 + i * GOVFUZZ_CMP_REC;
            // SAFETY: `off + GOVFUZZ_CMP_REC <= len` for every `i < GOVFUZZ_CMP_CAP`,
            // and the operand lengths are clamped to `GOVFUZZ_CMP_OPMAX`.
            let (la, lb) = unsafe {
                (
                    (*self.map.add(off) as usize).min(GOVFUZZ_CMP_OPMAX),
                    (*self.map.add(off + 1) as usize).min(GOVFUZZ_CMP_OPMAX),
                )
            };
            let a = unsafe { std::slice::from_raw_parts(self.map.add(off + 2), la) }.to_vec();
            let b = unsafe {
                std::slice::from_raw_parts(self.map.add(off + 2 + GOVFUZZ_CMP_OPMAX), lb)
            }
            .to_vec();
            if a.is_empty() && b.is_empty() {
                continue;
            }
            if seen.insert((a.clone(), b.clone())) {
                log.record(cmplog::CmpEntry {
                    site_id: i as u64,
                    operand_a: a,
                    operand_b: b,
                    kind: cmplog::CmpKind::IntegerCompare,
                });
            }
        }
        log
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for CmpShmReader {
    fn drop(&mut self) {
        unmap_shared(self.map, self.len);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
struct CmpShmReader;

#[cfg(not(any(target_os = "linux", windows)))]
impl CmpShmReader {
    fn new(_extra_env: &[(String, String)]) -> Option<Self> {
        None
    }
    fn arm(&self) {}
    fn disarm(&self) {}
    fn read_log(&self) -> cmplog::CmpLog {
        cmplog::CmpLog::new()
    }
}

#[cfg(target_os = "linux")]
fn process_rss_mb(pid: u32) -> Option<usize> {
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as usize
    } else {
        4096
    };
    Some(resident_pages.saturating_mul(page_size) / (1024 * 1024))
}

#[cfg(not(target_os = "linux"))]
fn process_rss_mb(_pid: u32) -> Option<usize> {
    None
}

/// One-line end-of-run summary for `--print-final-stats` (libFuzzer parity).
fn format_final_stats(
    executions: usize,
    corpus_new: usize,
    corpus_duplicates: usize,
    findings: usize,
    elapsed: Duration,
) -> String {
    let secs = elapsed.as_secs_f64().max(1e-9);
    let per_sec = executions as f64 / secs;
    format!(
        "govfuzz: final stats — execs: {executions} ({per_sec:.0}/s) | corpus: {corpus_new} new, \
         {corpus_duplicates} dup | findings: {findings} | elapsed: {:.1}s",
        elapsed.as_secs_f64()
    )
}

fn run_builtin(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    run_builtin_with_progress(prepared, None)
}

fn run_builtin_with_progress(
    mut prepared: PreparedFuzzRun,
    progress: Option<FuzzProgressFn<'_>>,
) -> Result<FuzzRunSummary, String> {
    reset_target_entry(&prepared.extra_env);
    bound_seed_corpus(&mut prepared.seeds, prepared.max_len);
    let corpus_limits = corpus_limits(prepared.max_len);
    let finding_dedup_limit = max_finding_dedup_keys();
    let start = Instant::now();
    let mut last_tick = Instant::now();
    let mut corpus = CorpusManager::new(prepared.work_dir.clone());
    // Interpreted lanes (Python/Perl) run the target under an interpreter whose OWN
    // file activity the shim traces; there the resource-leak oracle is taint-gated
    // to avoid flagging the interpreter's fixed env/stdlib opens as target leaks.
    // Detected once from the launcher `main` marker.
    let interpreted_lane = std::fs::read_to_string(&prepared.harness_path)
        .map(|s| {
            s.contains("GOVFUZZ_PY_LAUNCHER")
                || s.contains("GOVFUZZ_PL_LAUNCHER")
                || s.contains("GOVFUZZ_RB_LAUNCHER")
                || s.contains("GOVFUZZ_LUA_LAUNCHER")
                || s.contains("GOVFUZZ_PHP_LAUNCHER")
        })
        .unwrap_or(false);
    let sandbox_metadata = prepared.runner.sandbox_metadata();
    let emitter = FindingEmitter::with_metadata_and_sandbox(
        prepared.work_dir.clone(),
        prepared.harness_id.clone(),
        "unknown".to_owned(),
        prepared.harness_path.display().to_string(),
        serde_json::to_value(&sandbox_metadata)
            .map_err(|error| format!("serialize sandbox metadata: {error}"))?,
    )
    .with_mode(prepared.mode)
    .with_line_maps_dir(&prepared.work_dir.join("src_instrumented"));
    let mut rng = MutationRng::new(prepared.rng_seed);
    // The mutation pool. Each entry carries its #382 entropic energy + selection
    // count (selection favors high-novelty, under-explored seeds) and its #400
    // per-input RedQueen cmplog (captured lazily on first selection).
    let (cmplog_log, cmplog_summary) =
        load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    // Move (rather than clone) seeds into the pool. Large structured seeds used
    // to remain duplicated in `prepared.seeds` for the full campaign.
    let initial_seed_count = prepared.seeds.len();
    let mut pool: Vec<PoolEntry> = std::mem::take(&mut prepared.seeds)
        .into_iter()
        .map(PoolEntry::seed)
        .collect();
    let mut pool_bytes: usize = pool.iter().map(|entry| entry.bytes.len()).sum();
    // `fuzz --grammar` sets prepared.grammar_file directly; `auto --grammar` publishes
    // the path via GOVFUZZ_GRAMMAR (inherited by multicore workers), so fall back to it.
    let grammar_path = prepared.grammar_file.clone().or_else(|| {
        std::env::var_os("GOVFUZZ_GRAMMAR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    let grammar = load_grammar_for_run(grammar_path.as_deref())?;
    let mut dictionary_tokens =
        load_generated_dictionary_tokens(&prepared.work_dir, &prepared.harness_id)?;
    if let Some(log) = &cmplog_log {
        for token in log.dictionary_tokens() {
            if !dictionary_tokens.contains(&token) {
                dictionary_tokens.push(token);
            }
        }
    }
    // Value-profile (#398): the driver mines comparison operands into a shared log
    // during the run; fold newly seen tokens into the dictionary on a cadence so a
    // later input can splice the magic byte and reach gated code. Track membership
    // so re-merges stay cheap; `None` path for harnesses without the driver runtime.
    let vp_path = prepared
        .extra_env
        .iter()
        .find(|(k, _)| k == "GOVFUZZ_VP_SHM")
        .map(|(_, v)| PathBuf::from(v));
    let mut dictionary_token_set: HashSet<Vec<u8>> = dictionary_tokens.iter().cloned().collect();
    let mut dictionary = Dictionary::from_tokens(dictionary_tokens.clone());
    let mut corpus_new = 0_usize;
    let mut corpus_duplicates = 0_usize;
    let mut non_reproducible = 0_usize;
    // Sanitizer crashes dropped as libFuzzer/sanitizer driver glue (#388).
    let mut driver_glue_drops = 0_usize;
    // LSan leaks suppressed as govfuzz decode/harness scaffolding (#49): the
    // decoder buffer the harness would have freed, left dangling only because an
    // exit()/abort()-only target died before the harness's free() ran.
    let mut scaffolding_leak_drops = 0_usize;
    let mut finding_ids = Vec::new();
    // #35: pre-seed the within-pass dedup sets from findings already on disk so the
    // NEXT cascade pass (Empty/Rng/FuzzDriven) over the SAME harness does not
    // re-emit a byte-identical finding it already wrote (~2-3x inflation otherwise).
    let (seed_clusters, seed_oracles) =
        existing_finding_dedup_keys(&prepared.work_dir, &prepared.harness_id);
    let mut seen_oracle_hits = HashSet::<String>::from_iter(seed_oracles);
    // Sanitizer-crash cluster key -> hit count, for dedup (#389): one finding
    // per root cause, not one per crashing input.
    let mut seen_sanitizer_clusters = HashMap::<String, usize>::new();
    for key in seed_clusters {
        seen_sanitizer_clusters.insert(key, 1);
    }
    // Replay-verify + driver-glue filtering only apply to passthrough C/C++
    // libFuzzer harnesses (the class that crashes in driver glue); the Ada
    // event-log lane validates findings separately via per-spawn replay.
    let c_libfuzzer_harness = is_c_libfuzzer_harness(&prepared.runner, &prepared.work_dir);
    // #416: crash inputs (this run's, plus any recorded by an earlier pass) are
    // excluded from the persisted corpus so a crashing input is never left in the
    // clean coverage queue. Seeded from the durable findings dir for cross-pass
    // correctness; the C/C++ sanitizer path is the one that can mask a crash on
    // the warm fork-server, so scope the read there (Ada faults surface via the
    // event log and are validated separately).
    let mut crashing_inputs: HashSet<u64> = if c_libfuzzer_harness {
        existing_crash_testcases(&prepared.work_dir, &prepared.harness_id, prepared.max_len)
    } else {
        HashSet::new()
    };
    let mut executions = 0_usize;
    let mut target_entry_observed = false;
    // #15: count inputs the target REJECTED (assert/abort/non-zero return). If
    // EVERY executed input rejected — including the empty seed run first — the
    // harness couldn't actually fuzz (a magic/format gate with no valid seed, or a
    // broken harness), reported as built-not-fuzzed rather than silent success.
    let mut rejected_count = 0_usize;
    // Adaptive length control (libFuzzer `-len_control`): start short and double
    // the effective mutation length toward `--max-len` after a plateau of
    // executions with no new corpus signature. `len_control == 0` disables it.
    let mut effective_max_len = if prepared.len_control == 0 {
        prepared.max_len
    } else {
        INITIAL_LEN_CONTROL_LEN.min(prepared.max_len)
    };
    // Adaptive ceiling: the effective length grows toward `current_ceiling`, which
    // itself only rises past the default (4096) when the target is length-sensitive.
    // Below AUTO_SOFT_CEILING the raise is free (covers most large-object formats);
    // above it, the ceiling rises only while a prior rise produced new coverage, so a
    // small-format target is never grown into huge inputs pointlessly. When
    // `prepared.max_len == DEFAULT_MAX_LEN` (the `fuzz` default and every existing
    // test) this never triggers — behavior is identical to before.
    let mut current_ceiling = if prepared.len_control == 0 {
        prepared.max_len
    } else {
        DEFAULT_MAX_LEN.min(prepared.max_len)
    };
    let mut productive_since_ceiling_raise = false;
    let mut execs_since_new_signature = 0_usize;
    let mut runtrace_cursor = RuntraceLogCursor::from_extra_env(&prepared.extra_env);
    // #422: unified cross-execution byte-origin taint correlation for every
    // taint-confirmed sink oracle (path-open GF-405, process-exec GF-431, SSRF
    // GF-433, library-load GF-435, SQL GF-441, destructive-fs GF-440). Fed each
    // input's events below; queried once after the loop so a fuzz-controlled
    // sink is confirmed exactly once (no per-input flood) and a program constant
    // the dictionary echoed into some inputs is suppressed (no FP).
    let mut sink_taint = crate::auto::runtrace::SinkTaintTracker::default();
    // Persistent execution. The fork-server protocol is spoken by the Ada AdaFuzz
    // runtime AND by the passthrough govfuzz driver (its GOVFUZZ_FRAMED loop), so
    // either drives in one long-lived process at fork-server rates; a generated
    // `-fsanitize=fuzzer` C harness does not speak it and stays per-spawn. The
    // ForkServer::spawn handshake is the backstop — it returns Err -> None for
    // anything that doesn't complete the protocol.
    let driver_harness = is_govfuzz_driver_harness(&prepared.runner);
    let mut fork_server = if prepared.fork_server
        && (driver_harness || !is_c_libfuzzer_harness(&prepared.runner, &prepared.work_dir))
    {
        ForkServer::spawn(
            &prepared.runner,
            &prepared.work_dir,
            &prepared.extra_env,
            prepared.rss_limit_mb,
        )
        .ok()
    } else {
        None
    };

    // Coverage-guided corpus (#398, #412): a SanitizerCoverage edge bitmap is
    // shared via GOVFUZZ_COV_SHM by the C/C++ govfuzz driver (trace-pc-guard) AND,
    // since #412, by an instrumented Ada harness (trace-pc + the AdaFuzz callback).
    // Tracking it lets the engine retain only inputs that grow coverage instead of
    // pushing every exec into the pool, and makes the fuzz_driven pass coverage-
    // guided. `None` for harnesses with no edge runtime (uninstrumented Ada/legacy,
    // generated `-fsanitize=fuzzer` C), whose feedback is the event log / signatures.
    let ada_cov_harness = is_instrumented_ada_harness(&prepared.runner);
    let mut cov_tracker = if driver_harness || ada_cov_harness {
        CoverageTracker::new(&prepared.extra_env)
    } else {
        None
    };

    // RedQueen per-input cmplog capture (#400): on the driver path the harness
    // writes comparison operand pairs to GOVFUZZ_CMP_SHM. This reader arms
    // capture for the base it is about to mutate and reads the operands back.
    // `None` when the feature is disabled (GOVFUZZ_DISABLE_REDQUEEN=1, so the env
    // var is absent) or for non-driver harnesses.
    let cmp_reader = if driver_harness {
        CmpShmReader::new(&prepared.extra_env)
    } else {
        None
    };

    for iteration in 0..prepared.iterations {
        if prepared
            .time
            .is_some_and(|budget| start.elapsed() >= budget)
        {
            break;
        }

        let input = if iteration < initial_seed_count {
            pool[iteration].bytes.clone()
        } else {
            // #382: pick a base weighted by coverage energy / under-exploration.
            let base_index = choose_entropic_index_pool(&pool, &mut rng);
            if let Some(entry) = pool.get_mut(base_index) {
                entry.selections = entry.selections.saturating_add(1);
            }
            // #400 RedQueen: the first time a base is mutated, colorize it (so its
            // operands splice at the right offset), run it once with cmplog capture
            // armed, and cache the operand pairs + colorized base. The mutator then
            // biases this base's children toward CmpLogSplice, injecting the
            // captured value at the offset it was compared. Paid once per base.
            if let (Some(reader), Some(fork)) = (cmp_reader.as_ref(), fork_server.as_mut()) {
                if pool
                    .get(base_index)
                    .is_some_and(|e| e.cmplog.is_none() && !e.bytes.is_empty())
                {
                    let base_bytes = pool[base_index].bytes.clone();
                    let colored = match cov_tracker.as_mut() {
                        Some(cov) => colorize_base(cov, fork, &base_bytes, &mut rng),
                        None => base_bytes,
                    };
                    let log = capture_cmplog(reader, fork, &colored);
                    if let Some(entry) = pool.get_mut(base_index) {
                        entry.cmplog = Some(log);
                        entry.colored = Some(colored);
                    }
                }
            }
            mutate_from_pool(
                &pool,
                base_index,
                &dictionary,
                cmplog_log.as_ref(),
                grammar.as_ref(),
                mutator_config(prepared.structured_inputs, effective_max_len),
                &mut rng,
            )
        };
        // Empty inputs end the harness loop (an empty frame is the degenerate
        // "no input"), so they always go through the per-spawn path; everything
        // else uses the persistent fork-server when enabled, falling back to a
        // per-spawn run (and respawning the server) on a hard crash.
        // #420: zero the per-exec hit-count map so THIS exec's edge hit counts
        // are recorded in isolation, then read back via `input_grew_buckets()`
        // after the exec. Placed AFTER #400 colorization / cmplog capture (which
        // run their own probe execs and dirty the count map) and before BOTH the
        // fork-server and per-spawn main-exec paths below. No-op when there is no
        // count map (Ada/legacy targets). The harness only ever increments it, so
        // the post-exec read sees exactly this input's per-edge loop counts.
        if let Some(cov) = cov_tracker.as_ref() {
            cov.zero_counts();
            // #421: likewise zero the comparison-progress map so THIS exec's
            // per-site leading-byte-match is recorded in isolation (the harness
            // only ever `max`-raises it). No-op when the progress map is absent.
            cov.zero_progress();
        }
        // Whether this run came from the persistent fork-server (vs a fresh
        // per-spawn process). Fork-server findings are replay-validated below so
        // an artifact of accumulated global state never escapes as a finding.
        let mut from_fork_server = false;
        let mut run = if !input.is_empty() && fork_server.is_some() {
            match fork_server
                .as_mut()
                .expect("fork_server checked is_some")
                .run_one(&input)
            {
                ForkOutcome::Ran(run) => {
                    from_fork_server = true;
                    run
                }
                ForkOutcome::Died => {
                    // Drop (kill/reap) the dead server, isolate the crash via the
                    // proven per-spawn path, then respawn for subsequent inputs.
                    drop(fork_server.take());
                    let run = run_harness(
                        &prepared.runner,
                        &prepared.work_dir,
                        &input,
                        &prepared.extra_env,
                        prepared.per_input_timeout,
                        prepared.rss_limit_mb,
                    )?;
                    fork_server = ForkServer::spawn(
                        &prepared.runner,
                        &prepared.work_dir,
                        &prepared.extra_env,
                        prepared.rss_limit_mb,
                    )
                    .ok();
                    run
                }
            }
        } else {
            run_harness(
                &prepared.runner,
                &prepared.work_dir,
                &input,
                &prepared.extra_env,
                prepared.per_input_timeout,
                prepared.rss_limit_mb,
            )?
        };
        executions += 1;
        target_entry_observed |= run.testcases.iter().any(|testcase| testcase.target_entered);
        if run.rejected {
            rejected_count += 1;
        }
        // Did this input grow edge coverage (#398 presence) OR push an edge into a
        // new AFL hit-count bucket (#420 loop/recursion depth) OR match more leading
        // bytes of some compare than any prior input (#421 laf-intel gradient)?
        // (driver path only.) All THREE are read exactly once per main exec since
        // the tracker is stateful; call all unconditionally (no `||` short-circuit)
        // so every virgin map is folded even when an earlier channel didn't grow.
        // The three channels are OR'd into the same progress signal, so a
        // comparison-progress advance retains the input in the corpus and feeds the
        // scheduler (`input_energy`) exactly like edge novelty does.
        let input_new_coverage = cov_tracker
            .as_mut()
            .map(|t| {
                let new_edges = t.input_increased_coverage();
                let new_buckets = t.input_grew_buckets();
                let new_cmp_progress = t.input_advanced_comparisons();
                new_edges || new_buckets || new_cmp_progress
            })
            .unwrap_or(false);
        // Fold newly-mined value-profile operands into the dictionary every 2048
        // execs so the mutator can splice magic bytes it just observed (#398).
        if let Some(vp) = &vp_path {
            if executions % 2048 == 0 {
                let mut added = false;
                for token in read_vp_tokens(vp) {
                    if dictionary_token_set.insert(token.clone()) {
                        dictionary_tokens.push(token);
                        added = true;
                    }
                }
                if added {
                    dictionary = Dictionary::from_tokens(dictionary_tokens.clone());
                }
            }
        }
        let runtrace_events = runtrace_cursor.read_new_events();
        // #422: record this execution's sink taint for end-of-run correlation
        // (before the finding loop drains anything) across all sink classes.
        sink_taint.observe(&runtrace_events, &input);
        if let Some(tick) = progress {
            if last_tick.elapsed() >= Duration::from_millis(500) {
                tick(executions, finding_ids.len(), start.elapsed());
                last_tick = Instant::now();
            }
        }

        let records = corpus
            .record(&prepared.harness_id, &input, &run.events)
            .map_err(|error| format!("record corpus entry: {error}"))?;
        let mut new_signatures = HashSet::<Signature>::new();
        for record in records {
            match record.class {
                SignatureClass::New => {
                    corpus_new += 1;
                    new_signatures.insert(record.signature);
                }
                SignatureClass::Duplicate => corpus_duplicates += 1,
            }
        }
        // Edge-coverage growth is a corpus-progress signal (#398, #412): count it
        // as a new corpus entry. The C/C++ driver path produces no event
        // signatures, but an instrumented Ada harness produces both, so only count
        // coverage growth when it wasn't already counted as a new signature — one
        // retained pool entry, one increment.
        if input_new_coverage && new_signatures.is_empty() {
            corpus_new += 1;
        }
        let made_progress = !new_signatures.is_empty() || input_new_coverage;
        // #416: a persistent fork-server `Ran` cannot observe a fault that the warm
        // process masks but a fresh process aborts on — a crash gated on per-process
        // state (lazy-init globals, allocator / container-annotation state: the
        // jsoncpp container-overflow class). The server's stderr is discarded, so
        // such an input returns `Ran` with no sanitizer report and would otherwise be
        // coverage-credited and corpus-enqueued with no finding at all (the engine
        // silently misses a real memory-safety bug). Every input we are about to
        // ENQUEUE — it grew coverage, so it is the rare, worth-saving input — is
        // re-run once in a fresh per-spawn process here, so a crashing input is never
        // enqueued-without-a-finding (#416 AC2). Bounded by edge count (coverage is
        // monotonic), so this adds ~corpus-many extra spawns over a whole run, like
        // AFL++ calibrating each new corpus entry; the captured report flows into the
        // dedup / replay-verify emission path below exactly like a per-spawn crash.
        if from_fork_server
            && made_progress
            && c_libfuzzer_harness
            && run.sanitizer.is_none()
            && !input.is_empty()
        {
            let fresh = run_c_libfuzzer_single_input(
                &prepared.runner,
                &prepared.work_dir,
                &input,
                &prepared.extra_env,
                prepared.per_input_timeout,
                prepared.rss_limit_mb,
            )?;
            run.sanitizer = fresh.sanitizer;
        }
        // #382: this input's coverage novelty — new corpus signatures plus (on the
        // driver path) new edge coverage — is its scheduling energy, captured here
        // before the finding loop drains the set. Rare-coverage seeds get more
        // mutation energy.
        let input_energy = (new_signatures.len() as u32 + u32::from(input_new_coverage)).max(1);

        // New coverage found while fuzzing in the EXTENDED zone (past the default cap)
        // proves this target is length-sensitive, so the last ceiling raise paid off.
        if made_progress && effective_max_len > DEFAULT_MAX_LEN {
            productive_since_ceiling_raise = true;
        }
        // Length control: progress (a new signature or new edge coverage) resets the
        // plateau; otherwise, after `len_control` flat executions, double the effective
        // length toward the current ceiling.
        (effective_max_len, execs_since_new_signature) = len_control_step(
            effective_max_len,
            current_ceiling,
            prepared.len_control,
            execs_since_new_signature,
            made_progress,
        );
        // Adaptive ceiling: stuck at the current ceiling with room below the hard cap.
        // Raise it when still in the free zone (below AUTO_SOFT_CEILING) or when the
        // last raise produced new coverage; otherwise stay capped — the target does not
        // benefit from longer inputs.
        if prepared.len_control != 0
            && effective_max_len >= current_ceiling
            && current_ceiling < prepared.max_len
            && execs_since_new_signature >= prepared.len_control
            && (current_ceiling < AUTO_SOFT_CEILING.min(prepared.max_len)
                || productive_since_ceiling_raise)
        {
            current_ceiling = current_ceiling.saturating_mul(2).min(prepared.max_len);
            effective_max_len = current_ceiling;
            productive_since_ceiling_raise = false;
            execs_since_new_signature = 0; // fresh plateau window at the larger length
        }

        for testcase in &run.testcases {
            // Emit a finding for every classified event with a fresh signature.
            // This includes UNHANDLED_HANDLER_INDEX — an exception that escaped
            // the target to the harness top level (a real fault) — which was
            // previously dropped here, hiding genuine crashes while reporting
            // exceptions the target caught itself. `resolve_handler` yields a
            // synthetic handler for that case so it signatures like any other.
            for (handler_index, classification) in classify(testcase) {
                let Some(handler) = resolve_handler(testcase, handler_index) else {
                    continue;
                };
                // A target rejecting malformed input via its OWN declared exception
                // (e.g. XML/Ada's `XML_Fatal_Error`, caught by the harness or escaped
                // uncaught) is intended handling, not a defect — `finding_tier` marks
                // it `IntendedRejection`. Emitting one floods the findings list with a
                // false positive on every malformed input. Skip it: only real faults
                // (uncaught predefined checks) and swallowed predefined checks
                // (potential masked memory-safety bugs) are worth a finding.
                if finding_tier(classification, &handler.as_ref().exception_name)
                    == FindingTier::IntendedRejection
                {
                    continue;
                }
                let signature = compute_signature(testcase, handler.as_ref());
                if new_signatures.remove(&signature) {
                    // Safety net for the persistent fork-server: a fault could be
                    // an artifact of global state accumulated across prior inputs
                    // and so not reproduce from this testcase alone (the canonical
                    // replay). Re-run the input in a fresh process and only emit
                    // findings that reproduce, keeping every finding actionable.
                    if from_fork_server
                        && !finding_reproduces_per_spawn(&prepared, &input, &signature)?
                    {
                        non_reproducible += 1;
                        continue;
                    }
                    let id = emitter
                        .emit(&input, testcase, handler_index)
                        .map_err(|error| format!("emit finding: {error}"))?;
                    finding_ids.push(id.0);
                }
            }
        }

        if let Some(report) = &run.sanitizer {
            // (#49) An LSan leak whose entire allocation stack is govfuzz's own
            // decode/harness scaffolding (no target frame) is the decoder buffer the
            // harness would have freed — left dangling only because an exit()/abort()-
            // only target terminated before the harness free(). govfuzz manufactured
            // it, so SUPPRESS it (don't emit/count a phantom CWE-401).
            if corpus::cluster::is_harness_scaffolding_leak(report) {
                scaffolding_leak_drops += 1;
            }
            // (#388) A crash entirely in libFuzzer/sanitizer/allocator driver
            // glue with no target frame is a harness fault, not a target bug.
            else if c_libfuzzer_harness && corpus::cluster::is_driver_glue_crash(report) {
                driver_glue_drops += 1;
            } else if first_of_sanitizer_cluster(&mut seen_sanitizer_clusters, report) {
                // First sighting of this cluster (#389 dedups the rest). For a
                // passthrough libFuzzer harness, replay-verify before emitting
                // (#388): re-run in a fresh process and drop non-reproducing
                // faults (allocator-state corruption across inputs).
                if !c_libfuzzer_harness
                    || sanitizer_crash_reproduces(
                        &prepared.runner,
                        &prepared.work_dir,
                        &input,
                        report,
                        &prepared.extra_env,
                        prepared.per_input_timeout,
                        prepared.rss_limit_mb,
                    )
                {
                    let id = emitter
                        .emit_sanitizer_crash(&input, report)
                        .map_err(|error| format!("emit sanitizer finding: {error}"))?;
                    finding_ids.push(id.0);
                } else {
                    non_reproducible += 1;
                }
            }
        }

        for hit in crate::auto::runtrace::oracle_hits_from_events_for_lane(
            &runtrace_events,
            interpreted_lane,
        ) {
            let key = oracle_hit_dedupe_key(&hit);
            if !seen_oracle_hits.insert(key) {
                continue;
            }
            let id = emitter
                .emit_oracle_hit(&input, &hit)
                .map_err(|error| format!("emit oracle finding: {error}"))?;
            finding_ids.push(id.0);
        }

        // Corpus retention (#398, #412). Keep only inputs that made progress —
        // a fresh corpus signature or new edge coverage (`made_progress`, the same
        // signal that incremented `corpus_new` above) — and hard-cap the pool at
        // the derived corpus entry budget. It is the backstop for any path where coverage
        // feedback is absent or reads zero (uninstrumented Ada/legacy targets):
        // without it the gate degenerated to "keep every non-empty input" and the
        // end-of-run flush wrote ~every executed input to disk (#412: 402k files /
        // 1.6 GB). Seeds are pre-loaded into `pool` and never removed, so the seed
        // corpus is always retained regardless of this gate.
        //
        // #416: an input that produced a sanitizer crash is saved as a finding
        // testcase, never enqueued into the (clean) coverage corpus — it must not
        // sit in the queue as if it were a benign coverage seed, and mutating a
        // known crasher as a base is wasted energy. Record it so the end-of-run
        // persist also drops it when it entered the pool as a pre-loaded seed
        // (seeds bypass this `keep` gate). This is the retention half of "a
        // crashing input is never enqueued-without-a-finding": it is emitted as a
        // finding above and excluded from the corpus here.
        if run.sanitizer.is_some() && crashing_inputs.len() < finding_dedup_limit {
            crashing_inputs.insert(crash_input_key(&input));
        }
        let keep = made_progress
            && run.sanitizer.is_none()
            && pool.len() < corpus_limits.entries
            && pool_bytes.saturating_add(input.len()) <= corpus_limits.bytes;
        if !input.is_empty() && keep {
            pool_bytes = pool_bytes.saturating_add(input.len());
            pool.push(PoolEntry {
                bytes: input,
                energy: input_energy,
                selections: 0,
                cmplog: None,
                colored: None,
            });
        }

        // Per-target finding cap (`auto --per-target-finding-count`): stop this
        // run the instant it has emitted the requested number of DISTINCT findings
        // (`finding_ids` is signature/cluster-deduped above) so the cascade can
        // move on. The caller passes the count REMAINING for this pass; `None`
        // (default) never breaks early.
        if prepared
            .stop_after_findings
            .is_some_and(|cap| finding_ids.len() >= cap)
        {
            break;
        }
    }

    // #422: emit a taint-confirmed sink finding for each cross-execution-
    // confirmed fuzz-controlled sink (path-open GF-405, process-exec GF-431,
    // SSRF GF-433, library-load GF-435, SQL GF-441, destructive-fs GF-440).
    // Done at run end (not per-input) so a sink is confirmed exactly once and a
    // program constant the auto-dictionary echoed into some inputs — reached
    // untainted on other inputs — is suppressed. Distinct subjects dedupe to
    // one finding per (rule | oracle | api); the cap is a backstop against a
    // target that reaches a fresh input-derived sink every execution.
    let max_sink_taint_findings =
        crate::resource_limits::env_usize("GOVFUZZ_MAX_SINK_TAINT_FINDINGS").unwrap_or_else(|| {
            crate::resource_limits::dynamic_bytes(
                "GOVFUZZ_MAX_SINK_TAINT_FINDING_BYTES",
                2048,
                2 * crate::resource_limits::MIB,
                2 * crate::resource_limits::MIB,
                64 * crate::resource_limits::MIB,
            )
            .saturating_div(32 * 1024)
            .clamp(50, 2048)
        });
    let dropped_sink_entries = sink_taint.dropped_entries();
    let sink_taint_limit = sink_taint.entry_limit();
    let confirmed_sinks = sink_taint.into_confirmed();
    let confirmed_sinks_total = confirmed_sinks.len();
    for confirmed in confirmed_sinks.into_iter().take(max_sink_taint_findings) {
        let Some(hit) = crate::auto::runtrace::confirmed_sink_hit(&confirmed) else {
            continue;
        };
        if !seen_oracle_hits.insert(oracle_hit_dedupe_key(&hit)) {
            continue;
        }
        let id = emitter
            .emit_oracle_hit(&confirmed.input, &hit)
            .map_err(|error| format!("emit oracle finding: {error}"))?;
        finding_ids.push(id.0);
    }
    if confirmed_sinks_total > max_sink_taint_findings {
        eprintln!(
            "govfuzz fuzz: {confirmed_sinks_total} fuzz-controlled sink(s) confirmed (#422); \
             emitted the first {max_sink_taint_findings} (raise \
             GOVFUZZ_MAX_SINK_TAINT_FINDINGS if intended)"
        );
    }
    if dropped_sink_entries > 0 {
        eprintln!(
            "govfuzz fuzz: sink-taint tracking reached its {}-subject memory cap; \
             ignored {} later distinct sink observation(s) (raise \
             GOVFUZZ_MAX_SINK_SUBJECTS or GOVFUZZ_MAX_SINK_TRACKING_BYTES if intended)",
            sink_taint_limit, dropped_sink_entries
        );
    }

    if non_reproducible > 0 {
        eprintln!(
            "govfuzz fuzz: {non_reproducible} fault(s) did not reproduce in a fresh \
             process (global-state artifacts) and were not emitted"
        );
    }
    if driver_glue_drops > 0 {
        eprintln!(
            "govfuzz fuzz: {driver_glue_drops} crash(es) in libFuzzer/sanitizer driver glue \
             (no target frame) were treated as harness faults and not emitted"
        );
    }
    if scaffolding_leak_drops > 0 {
        eprintln!(
            "govfuzz fuzz: {scaffolding_leak_drops} LSan leak(s) whose entire stack was govfuzz \
             decode/harness scaffolding (no target frame) were suppressed (not target leaks)"
        );
    }

    // #401/#412: flush the coverage-guided corpus (the in-memory pool — seeds plus
    // every retained input) to `corpus/<hid>/queue/`, content-hash named, so the
    // explored corpus is replayable for neutral coverage measurement /
    // `corpus minimize` instead of lost on exit. The pool is retention-gated
    // (coverage-or-signature progress) and bounded by the derived corpus budget, so
    // `corpus_persisted` tracks `corpus_new` and stays bounded even when coverage
    // reads zero. Best-effort: a persistence I/O error must not fail an otherwise-
    // successful run.
    let corpus_persisted = match corpus.persist_coverage_corpus(
        &prepared.harness_id,
        pool.iter()
            .map(|entry| &entry.bytes)
            .filter(|bytes| !crashing_inputs.contains(&crash_input_key(bytes))),
    ) {
        Ok(count) => count,
        Err(error) => {
            eprintln!("govfuzz fuzz: warning: could not persist coverage corpus: {error}");
            0
        }
    };

    // #15: the harness REJECTED every input it executed (incl. the empty seed run
    // first) — it never actually fuzzed (an input gate with no valid seed, or a
    // broken harness). Surface a hard error so the auto loop reports it as
    // built-not-fuzzed, not a silent clean run. A target that genuinely fuzzed has
    // at least one non-rejected execution (a finding or a clean/coverage run).
    //
    // #477: but a target where EVERY input crashes (a callback struct cast from
    // raw bytes, a parser that aborts on malformed input) rejects all executions
    // AND emits real crash findings. Those findings are already persisted to the
    // findings/ tree; returning Err here would make the attempt loop discard them
    // and downgrade the target to a finding-less `Built`. A run that produced any
    // finding produced signal — return Ok so the crashes survive into the report.
    if executions > 0 && rejected_count == executions && finding_ids.is_empty() {
        return Err(format!(
            "harness rejected all {executions} executed input(s) (assert/abort/non-zero exit, \
             including the empty seed) — it cannot fuzz: it needs a valid seed past its input \
             gate, or the harness is broken"
        ));
    }

    let elapsed_secs = start.elapsed().as_secs_f64();
    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id,
        engine: "builtin".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path,
        sandbox: sandbox_metadata,
        iterations_requested: prepared.iterations,
        executions,
        target_entry_observed: target_entry_observed || target_entry_from_env(&prepared.extra_env),
        corpus_new,
        corpus_duplicates,
        corpus_persisted,
        execution: builtin_execution_summary(&prepared.runner, &prepared.work_dir),
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage: coverage_from_env(&prepared.extra_env),
        findings: finding_ids,
        elapsed_secs,
        executions_per_sec: executions_per_sec(executions, elapsed_secs),
    };
    if prepared.print_final_stats {
        eprintln!(
            "{}",
            format_final_stats(
                summary.executions,
                summary.corpus_new,
                summary.corpus_duplicates,
                summary.findings.len(),
                start.elapsed(),
            )
        );
    }
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

struct RuntraceLogCursor {
    path: Option<PathBuf>,
    offset: u64,
}

impl RuntraceLogCursor {
    fn from_extra_env(extra_env: &[(String, String)]) -> Self {
        let path = extra_env
            .iter()
            .find_map(|(key, value)| (key == "GOVFUZZ_RUNTRACE_LOG").then(|| PathBuf::from(value)));
        let offset = path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Self { path, offset }
    }

    fn read_new_events(&mut self) -> Vec<crate::auto::runtrace::RuntraceEvent> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        let Ok(mut file) = fs::File::open(path) else {
            return Vec::new();
        };
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        let len = metadata.len();
        if len < self.offset {
            self.offset = 0;
        }
        if len == self.offset {
            return Vec::new();
        }
        if len.saturating_sub(self.offset) > max_event_delta_bytes() {
            self.offset = len;
            return Vec::new();
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            self.offset = len;
            return Vec::new();
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        self.offset = len;
        crate::auto::runtrace::parse_str(&String::from_utf8_lossy(&buf))
    }
}

/// First-sighting test for sanitizer-crash deduplication (#389). Returns true
/// exactly once per distinct crash cluster (root cause), so the report carries
/// one finding per cluster with a hit count instead of one per crashing input
/// (cJSON produced 2211 findings collapsing to 3 clusters). A fallback cluster
/// (no informative target frame) is keyed by rule_id so unrelated rules still
/// separate.
fn first_of_sanitizer_cluster(
    seen: &mut HashMap<String, usize>,
    report: &corpus::SanitizerReport,
) -> bool {
    let limit = max_finding_dedup_keys();
    let cluster = corpus::cluster::cluster_for_sanitizer(report);
    let key = if cluster.fallback {
        format!("rule:{}", report.rule_id)
    } else {
        cluster.full
    };
    if let Some(count) = seen.get_mut(&key) {
        *count = count.saturating_add(1);
        return false;
    }
    if seen.len() >= limit {
        if seen.len() == limit {
            eprintln!(
                "govfuzz: sanitizer-cluster tracking reached its {limit}-key \
                 memory cap; suppressing later distinct clusters (raise \
                 GOVFUZZ_MAX_FINDING_DEDUP_KEYS if intended)"
            );
            seen.insert("__govfuzz_dedup_memory_cap__".to_owned(), 1);
        }
        return false;
    }
    seen.insert(key, 1);
    true
}

fn oracle_hit_dedupe_key(hit: &finding_rules::oracle_sdk::OracleHit) -> String {
    // Dedup at the DEFECT level: rule + oracle + dangerous API. Evidence values
    // (an opened file path / fd, an injected command, ...) are PER-INPUT, so
    // including them made every input that re-triggers the same defect a distinct
    // "finding" — a resource-leak oracle that fires on every testcase emitted 600+
    // identical findings (mpack). One defect → one finding (with its first example
    // testcase + evidence preserved on the emitted finding); a genuinely different
    // dangerous API or oracle still keys distinctly.
    format!("{}|{}|{}", hit.rule_id, hit.oracle_name, hit.api)
}

#[cfg(test)]
mod oracle_dedupe_tests {
    use super::oracle_hit_dedupe_key;
    use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

    fn hit(api: &str, resource: &str) -> OracleHit {
        OracleHit {
            oracle_name: "resource-leak-ada".into(),
            rule_id: "GF-306".into(),
            category: "logic".into(),
            api: api.into(),
            message: "leak".into(),
            evidence: vec![OracleEvidence::new("resource", resource)],
        }
    }

    #[test]
    fn same_defect_different_per_input_evidence_dedupes() {
        // A resource-leak oracle that fires on every input (a different opened
        // path/fd each time) must collapse to ONE finding, not one per input
        // (mpack emitted 600+ identical GF-306 findings before this).
        assert_eq!(
            oracle_hit_dedupe_key(&hit("open", "/tmp/gf_inAAA")),
            oracle_hit_dedupe_key(&hit("open", "/tmp/gf_inBBB"))
        );
    }

    #[test]
    fn different_dangerous_api_keys_distinctly() {
        assert_ne!(
            oracle_hit_dedupe_key(&hit("open", "/x")),
            oracle_hit_dedupe_key(&hit("openat", "/x"))
        );
    }
}

/// Run a C harness under AFL++. Expects:
///
/// - `<work_dir>/build/<harness_id>/main_afl` produced by
///   `make afl` (afl-clang-fast -DGOVFUZZ_AFL).
/// - `<work_dir>/build/<harness_id>/main` (the libFuzzer/asan/ubsan
///   build) for replaying each crash artifact so we get a sanitizer
///   report to map onto the rule catalog.
///
/// We drive `afl-fuzz -i seeds -o out -- ./main_afl` for either the
/// requested time budget or `prepared.iterations * 0.1s` (afl-fuzz
/// runs in seconds, not iterations), then walk the
/// `out/default/crashes/` directory to collect crash artifacts, replay
/// each against the libFuzzer binary, parse the resulting stderr, and
/// emit one finding per unique rule_signature.
fn run_afl_plus_plus(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    use std::process::Command;
    use std::time::Instant;

    reset_target_entry(&prepared.extra_env);
    let (_, cmplog_summary) = load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    let afl_fuzz = which_executable("afl-fuzz")?;
    let generated_dictionary = find_generated_dictionary(&prepared.work_dir, &prepared.harness_id);
    // find_harness_executable already preferred main_afl for the AFL
    // engine. If we landed on a libFuzzer `main` because main_afl was
    // missing, fail with a clear message - libFuzzer binaries don't
    // wire up afl-fuzz's persistent-mode handshake and afl-fuzz will
    // hang or behave unpredictably.
    let main_afl = prepared.harness_path.clone();
    let staged_name = main_afl
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if staged_name != "main_afl" && staged_name != "main_afl.exe" {
        return Err(format!(
            "AFL build not found at '{}'. Run `govfuzz build --c-engine afl++ ...` (or `make afl` against the harness Makefile) first.",
            main_afl.with_file_name("main_afl").display()
        ));
    }

    // Seed corpus directory required by afl-fuzz.
    let afl_out = prepared.work_dir.join("afl_out").join(&prepared.harness_id);
    let seeds_dir = afl_out.join("seeds");
    fs::create_dir_all(&seeds_dir)
        .map_err(|error| format!("create AFL seeds dir '{}': {error}", seeds_dir.display()))?;
    let out_dir = afl_out.join("out");
    let _ = fs::remove_dir_all(&out_dir);
    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("create AFL out dir '{}': {error}", out_dir.display()))?;
    // afl-fuzz's console output goes here instead of an undrained pipe (see the
    // stdout/stderr redirect below — a piped, undrained child deadlocks).
    let afl_log = afl_out.join("afl-fuzz.log");
    let afl_log_file = std::fs::File::create(&afl_log)
        .map_err(|error| format!("create afl log '{}': {error}", afl_log.display()))?;
    let mut seed_count = 0_usize;
    for (idx, seed) in prepared.seeds.iter().enumerate() {
        if seed.is_empty() {
            continue;
        }
        let seed_path = seeds_dir.join(format!("seed-{idx:04}"));
        fs::write(&seed_path, seed)
            .map_err(|error| format!("write seed '{}': {error}", seed_path.display()))?;
        seed_count += 1;
    }
    if seed_count == 0 {
        // afl-fuzz refuses to start with an empty seed dir; supply one.
        let seed_path = seeds_dir.join("seed-default");
        fs::write(&seed_path, b"AAAA").map_err(|error| format!("write default seed: {error}"))?;
    }

    let time_budget = prepared.time.unwrap_or_else(|| {
        // 100 ms per requested iteration, capped at 30s for safety.
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });

    let start = Instant::now();
    // AFL stops at the first of -V or -E; pass only the time budget so the
    // caller's `--time` (or our iterations-derived default) actually applies.
    let mut afl_cmd = Command::new(&afl_fuzz);
    afl_cmd
        .current_dir(ensure_harness_scratch(&prepared.work_dir)?)
        .arg("-i")
        .arg(&seeds_dir)
        .arg("-o")
        .arg(&out_dir)
        .arg("-V")
        .arg(time_budget.as_secs().to_string())
        // Per-exec timeout. WITHOUT this, a single fuzzed input that hangs the
        // target (e.g. parson's recursive JSON parser on a deeply-nested array)
        // wedges the whole run — afl-fuzz's internal `run_time` stays 0, its `-V`
        // budget never fires, and the run deadlocks (observed: stuck at 20 execs
        // forever; the hard-deadline kill above is only the backstop). A 1s cap is
        // ~25000x a normal parser exec, so it catches hangs without flagging
        // legitimately-fast inputs. The `+` suffix keeps initial seed calibration
        // lenient (a slow seed is skipped, not treated as a fatal hang).
        .arg("-t")
        .arg("1000+");
    if let Some(dictionary) = &generated_dictionary {
        afl_cmd.arg("-x").arg(dictionary);
    }
    afl_cmd
        .arg("--")
        .arg(&main_afl)
        .env("AFL_NO_UI", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .env("AFL_BENCH_UNTIL_CRASH", "0")
        // AFL refuses to start on hosts where /proc/sys/kernel/core_pattern
        // pipes to a userland handler (apport, systemd-coredump). Acknowledge
        // we may miss the rare crash that gets intercepted by the handler;
        // most C target crashes are SIGSEGV/SIGABRT seen via waitpid anyway.
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        // Sanitizers default to "report and continue" which hides findings
        // from AFL's exit-code-based crash detection. abort_on_error turns
        // the first sanitizer report into a SIGABRT that AFL will save.
        // symbolize=0 is required by AFL's pre-flight check so the sanitizer
        // doesn't fork llvm-symbolizer in the hot loop; we re-symbolize
        // ourselves when replaying each crash artifact against the
        // libFuzzer binary later. The operator's inherited `<SAN>_OPTIONS`
        // (suppressions / FP-killers, #435) are MERGED in first; govfuzz's
        // required keys go last so they win.
        .env(
            "ASAN_OPTIONS",
            multicore_fuzz::merge_sanitizer_options(
                std::env::var("ASAN_OPTIONS").ok().as_deref(),
                "abort_on_error=1:halt_on_error=1:symbolize=0",
            ),
        )
        .env(
            "UBSAN_OPTIONS",
            multicore_fuzz::merge_sanitizer_options(
                std::env::var("UBSAN_OPTIONS").ok().as_deref(),
                "abort_on_error=1:halt_on_error=1:symbolize=0",
            ),
        )
        .env(
            "LSAN_OPTIONS",
            multicore_fuzz::merge_sanitizer_options(
                std::env::var("LSAN_OPTIONS").ok().as_deref(),
                "abort_on_error=1:symbolize=0",
            ),
        )
        // CRITICAL: redirect afl-fuzz's stdout+stderr to a FILE, not a pipe. A
        // piped child blocks on write() once the ~64KB pipe buffer fills, and we
        // only drain it after wait() — so afl-fuzz (which keeps printing status
        // even under AFL_NO_UI) deadlocks after ~20 execs and `auto` hangs forever
        // (the original 69-min wedge). A file never blocks; we read it afterward
        // for the diagnostic hints below. stderr shares the stdout handle (a dup,
        // so they share one file offset and interleave instead of clobbering).
        .stdout(Stdio::from(
            afl_log_file
                .try_clone()
                .map_err(|error| format!("dup afl log handle: {error}"))?,
        ))
        .stderr(Stdio::from(afl_log_file));
    for (k, v) in &prepared.extra_env {
        afl_cmd.env(k, v);
    }
    apply_runaway_rlimits(&mut afl_cmd);
    // Run afl-fuzz in its own process group so a hard-deadline kill can take down
    // the WHOLE group — afl-fuzz plus the persistent harness it forked — instead
    // of orphaning the harness (`child.kill()` alone leaves `main_afl` running).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        afl_cmd.process_group(0);
    }
    let mut child = afl_cmd
        .spawn()
        .map_err(|error| format!("spawn afl-fuzz '{}': {error}", afl_fuzz.display()))?;
    // afl-fuzz is supposed to self-terminate at its `-V` budget, but a
    // fork-server / persistent-mode handshake wedge can leave its internal
    // `run_time` stuck at 0 so the `-V` check never fires and afl-fuzz hangs
    // forever (observed: 20 execs, 69 min wall). A bare `child.wait()` would then
    // block `auto` indefinitely, blowing past `--per-target-time`. Bound the wait
    // with a hard wall-clock deadline (generous margin over the budget) and kill
    // the process group if exceeded; any crashes found before the wedge are still
    // harvested from `out/default/crashes` below.
    let hard_deadline = Instant::now() + time_budget.saturating_mul(2) + Duration::from_secs(30);
    let mut timed_out = false;
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| format!("wait afl-fuzz: {error}"))?
        {
            Some(status) => break status,
            None => {
                if Instant::now() >= hard_deadline {
                    timed_out = true;
                    kill_process_group(&mut child);
                    break child
                        .wait()
                        .map_err(|error| format!("reap timed-out afl-fuzz: {error}"))?;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };
    if timed_out {
        // Reap any persistent-mode worker that setsid()'d out of the killed group.
        kill_processes_by_exe(&main_afl);
        eprintln!(
            "govfuzz: afl-fuzz exceeded its hard deadline ({:?}) and was killed — \
             likely a fork-server/persistent-mode hang; harvesting any crashes found so far",
            time_budget.saturating_mul(2) + Duration::from_secs(30)
        );
    }
    // AFL terminates itself with a signal when the -V time budget expires (or when
    // we hard-kill a hung run above), surfacing as status.code() == None. Treat
    // that as success - it's the *intended* end of a time-bounded run. Real
    // failures show up as a positive exit code.
    let exited_by_signal = status.code().is_none();
    if !status.success() && !exited_by_signal {
        // afl-fuzz's console output was redirected to a file (not an undrained
        // pipe), so read it back for the diagnostic hints.
        let afl_log_bytes =
            read_bounded_file_head_tail(&afl_log, max_captured_stderr_bytes()).unwrap_or_default();
        let buf = String::from_utf8_lossy(&afl_log_bytes);
        // Strip ANSI sequences so the error is readable on dumb stderr.
        let cleaned: String = buf
            .chars()
            .filter(|ch| {
                let c = *ch as u32;
                ch.is_ascii_graphic() || ch.is_ascii_whitespace() || c >= 0x80
            })
            .collect();
        if cleaned.contains("at least one valid input seed that does not crash") {
            // GRACEFUL SKIP, not an error: every seed aborts the harness, so
            // afl-fuzz can't start. This is a property of the TARGET (a pervasive
            // sanitizer finding that fires on every input — e.g. a UBSan
            // member-access on tinyexpr's over-allocated nodes), not a govfuzz
            // failure. afl-fuzz already skips individual crashing seeds; it only
            // aborts when ALL crash. Returning an Err here would emit a scary
            // warning and lose the target; instead fall through to an empty
            // summary. The builtin engine surfaces such crashes directly, so
            // `--engine builtin,afl++` still reports them.
            eprintln!(
                "govfuzz: afl-fuzz could not start for {} — every seed aborts the \
                 harness (a pervasive sanitizer finding that fires on all inputs); \
                 skipping AFL for this target. Use `--engine builtin,afl++` so the \
                 builtin engine surfaces the crash.",
                prepared.harness_id
            );
            // fall through: the empty crashes dir yields a 0-finding summary below.
        } else {
            let mut hint = String::new();
            if cleaned.contains("core_pattern") {
                hint.push_str(
                    "\nHint: AFL detected a host `core_pattern` that would swallow \
                     crashes. Run `sudo sysctl kernel.core_pattern=core` or set \
                     AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 (govfuzz already sets \
                     this; check the harness env).",
                );
            }
            return Err(format!(
                "afl-fuzz exited non-zero ({:?}). Output tail:\n{}{}",
                status.code(),
                cleaned
                    .lines()
                    .rev()
                    .take(10)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n"),
                hint
            ));
        }
    }
    let elapsed = start.elapsed();

    let crashes_dir = out_dir.join("default").join("crashes");
    let sandbox_metadata = prepared.runner.sandbox_metadata();
    let emitter = FindingEmitter::with_metadata_and_sandbox(
        prepared.work_dir.clone(),
        prepared.harness_id.clone(),
        "unknown".to_owned(),
        prepared.harness_path.display().to_string(),
        serde_json::to_value(&sandbox_metadata)
            .map_err(|error| format!("serialize sandbox metadata: {error}"))?,
    )
    .with_mode(prepared.mode)
    .with_line_maps_dir(&prepared.work_dir.join("src_instrumented"));

    let mut finding_ids = Vec::new();
    let mut seen_rule_sigs = HashSet::<String>::new();
    let mut crash_count = 0_usize;
    if crashes_dir.is_dir() {
        for entry in fs::read_dir(&crashes_dir)
            .map_err(|error| format!("read AFL crashes dir '{}': {error}", crashes_dir.display()))?
        {
            let entry = entry.map_err(|error| format!("read AFL crash entry: {error}"))?;
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with("id:") {
                continue;
            }
            crash_count += 1;
            let input = fs::read(&path)
                .map_err(|error| format!("read crash artifact '{}': {error}", path.display()))?;
            // AFL persistent-mode harnesses read input from stdin (via the
            // __AFL_LOOP / __AFL_FUZZ_TESTCASE_BUF macros). Piping the
            // crash bytes is the only way to reproduce; passing them as
            // argv[1] has no effect.
            let mut replay_cmd = Command::new(&prepared.harness_path);
            replay_cmd
                .current_dir(ensure_harness_scratch(&prepared.work_dir)?)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            for (k, v) in &prepared.extra_env {
                replay_cmd.env(k, v);
            }
            apply_runaway_rlimits(&mut replay_cmd);
            let mut child = replay_cmd.spawn().map_err(|error| {
                format!(
                    "spawn '{}' to replay '{}': {error}",
                    prepared.harness_path.display(),
                    path.display()
                )
            })?;
            let stderr_reader = drain_child_stderr(child.stderr.take());
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(&input);
            }
            let status = child.wait().map_err(|error| {
                format!(
                    "wait for replay of '{}' against '{}': {error}",
                    path.display(),
                    prepared.harness_path.display()
                )
            })?;
            let replay = collected_child_output(status, stderr_reader);
            let stderr = String::from_utf8_lossy(&replay.stderr);
            let Some(report) = corpus::parse_sanitizer_report(&stderr) else {
                continue;
            };
            let frame_names: Vec<&str> = report.stack.iter().map(|f| f.function.as_str()).collect();
            let sig = format!("{}|{}", report.rule_id, frame_names.join("|"));
            if !seen_rule_sigs.insert(sig) {
                continue;
            }
            let id = emitter
                .emit_sanitizer_crash(&input, &report)
                .map_err(|error| format!("emit AFL finding: {error}"))?;
            finding_ids.push(id.0);
        }
    }

    let elapsed_secs = elapsed.as_secs_f64();
    // Surface AFL's REAL throughput from its own stats file rather than reporting
    // `executions` as the crash count (which made run.json show afl++ passes as
    // `execs=1, edges=0` even on a productive run). Fall back to the crash count
    // only when afl-fuzz wrote no stats (e.g. it aborted before the first cycle).
    let (afl_execs_done, afl_execs_per_sec) = parse_afl_fuzzer_stats(&out_dir);
    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id.clone(),
        engine: "afl++".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path,
        sandbox: sandbox_metadata,
        iterations_requested: prepared.iterations,
        executions: afl_execs_done.map(|n| n as usize).unwrap_or(crash_count),
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: crash_count,
        corpus_duplicates: 0,
        // AFL++ owns its own on-disk queue/ corpus; the built-in persistence
        // path (#401) does not apply to the external-engine run.
        corpus_persisted: 0,
        execution: afl_execution_summary(),
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage: coverage_from_env(&prepared.extra_env),
        findings: finding_ids,
        elapsed_secs,
        // AFL++ owns its own loop; its real per-second throughput comes from
        // `out/default/fuzzer_stats` (`execs_per_sec`). 0.0 only when afl-fuzz
        // wrote no stats.
        executions_per_sec: afl_execs_per_sec.unwrap_or(0.0),
    };
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

/// Detect a libFuzzer-built C/C++ harness by looking for a sibling
/// `main.c` or `main.cpp` in the generated_harnesses tree. libFuzzer
/// binaries run their own fuzz engine when invoked without args - which
/// hangs the builtin engine's "stream stdin + wait" loop. For these
/// harnesses we'll write the input to a temp file and pass it as argv[1]
/// to run a single iteration.
fn is_c_libfuzzer_harness(runner: &replay_min::HarnessRunner, work_dir: &Path) -> bool {
    let harness_path = runner.harness_path();
    // Sibling layout: govfuzz auto writes to <work>/harnesses/<id>/main +
    // <work>/harnesses/<id>/main.c. Detect the C source next to the binary.
    if let Some(dir) = harness_path.parent() {
        if dir.join("main.c").is_file() || dir.join("main.cpp").is_file() {
            return true;
        }
    }
    // Legacy layout: <work>/generated_harnesses/<id>/main.c. Kept so
    // standalone `govfuzz fuzz` against a hand-built generated tree
    // still detects the libFuzzer single-input shape.
    let harness_id = harness_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str());
    let Some(id) = harness_id else { return false };
    let candidate_c = work_dir.join("generated_harnesses").join(id).join("main.c");
    let candidate_cpp = work_dir
        .join("generated_harnesses")
        .join(id)
        .join("main.cpp");
    candidate_c.is_file() || candidate_cpp.is_file()
}

/// A passthrough harness built with the govfuzz driver speaks the persistent
/// framed fork-server protocol (its `main.c` carries the `GOVFUZZ_FRAMED` loop),
/// so the engine can drive it in one long-lived process at fork-server rates
/// instead of paying an ASan-instrumented per-spawn startup for every input — the
/// difference between thousands and millions of execs in a 60s budget. Detected
/// by the marker in the sibling source. A crash still surfaces: ASan aborts the
/// whole process, the parent sees the closed pipe (`ForkOutcome::Died`) and
/// re-isolates that input via the per-spawn path that captures the report.
fn is_govfuzz_driver_harness(runner: &replay_min::HarnessRunner) -> bool {
    let harness_path = runner.harness_path();
    let Some(dir) = harness_path.parent() else {
        return false;
    };
    // C/C++/Rust ship a sibling main.c/main.cpp with the marker; the native Java
    // lane's `main` is itself a launcher script carrying it (reading a real ELF
    // binary as text fails on the non-UTF-8 bytes and is ignored).
    let harness_name = harness_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    for name in ["main.c", "main.cpp", harness_name] {
        if name.is_empty() {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(dir.join(name)) {
            if src.contains("GOVFUZZ_FRAMED") {
                return true;
            }
        }
    }
    false
}

/// Whether this is an Ada harness whose target+harness compile was instrumented
/// with `-fsanitize-coverage=trace-pc` and linked against the AdaFuzz trace-pc
/// callback (#412). `build.rs` writes a sentinel into the harness `build/<id>`
/// dir exactly when it added the flag, so this is true iff the AdaFuzz runtime is
/// actively writing the GOVFUZZ_COV_SHM edge bitmap. The harness binary lives at
/// `build/<id>/obj/main`, so the sentinel is two levels up. Keyed on the sentinel
/// (not the C-driver markers) so it can never flip C/C++ harness behavior, and so
/// a GNAT that lacks trace-pc (no sentinel) cleanly degrades to no coverage.
fn is_instrumented_ada_harness(runner: &replay_min::HarnessRunner) -> bool {
    runner
        .harness_path()
        .parent()
        .and_then(|obj_dir| obj_dir.parent())
        .map(|build_dir| build_dir.join(crate::build::ADA_COV_SENTINEL).is_file())
        .unwrap_or(false)
}

/// Hard cap on a single libFuzzer-binary invocation. A fuzz input that
/// causes the target to loop forever (algorithmic complexity, parser
/// backtracking blowup) would otherwise hang the whole \`govfuzz fuzz\`
/// run indefinitely. 10s is generous - any well-behaved input
/// completes in milliseconds, and the harness is invoked once per
/// iteration so the overall fuzz budget caps total wall time anyway.
const PER_INPUT_TIMEOUT: Duration = Duration::from_secs(10);

/// A target controls its own diagnostics. Keep enough from both ends for a
/// sanitizer header and final stack/summary, but never let a chatty execution
/// grow the parent process without bound.
fn max_captured_stderr_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_HARNESS_OUTPUT_BYTES",
        1024,
        4 * crate::resource_limits::MIB,
        4 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
    )
}

/// Maximum event-log data admitted from one execution. The event runtime is
/// normally tiny, but the scanned program is untrusted and can inherit or write
/// the advertised path itself.
fn max_event_delta_bytes() -> u64 {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_EVENT_DELTA_BYTES",
        512,
        16 * crate::resource_limits::MIB,
        16 * crate::resource_limits::MIB,
        256 * crate::resource_limits::MIB,
    ) as u64
}

fn read_bounded_head_tail(mut reader: impl Read, cap: usize) -> Vec<u8> {
    let head_cap = cap / 2;
    let tail_cap = cap.saturating_sub(head_cap);
    let mut head = Vec::with_capacity(head_cap);
    let mut tail: VecDeque<u8> = VecDeque::with_capacity(tail_cap);
    let mut truncated = false;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let Ok(read) = reader.read(&mut chunk) else {
            break;
        };
        if read == 0 {
            break;
        }
        let mut bytes = &chunk[..read];
        if head.len() < head_cap {
            let take = bytes.len().min(head_cap - head.len());
            head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if !bytes.is_empty() {
            if tail.len().saturating_add(bytes.len()) > tail_cap {
                let excess = tail
                    .len()
                    .saturating_add(bytes.len())
                    .saturating_sub(tail_cap);
                let remove = excess.min(tail.len());
                tail.drain(..remove);
                truncated = true;
                if bytes.len() > tail_cap {
                    bytes = &bytes[bytes.len() - tail_cap..];
                }
            }
            tail.extend(bytes);
        }
    }
    if truncated {
        head.extend_from_slice(b"\n[govfuzz: diagnostic output truncated]\n");
    }
    head.extend(tail);
    head
}

fn read_bounded_file_head_tail(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len <= cap as u64 {
        let mut bytes = Vec::with_capacity(len as usize);
        (&mut file).take(cap as u64).read_to_end(&mut bytes)?;
        return Ok(bytes);
    }

    let head_cap = cap / 2;
    let tail_cap = cap.saturating_sub(head_cap);
    let mut bytes = Vec::with_capacity(cap.saturating_add(48));
    (&mut file).take(head_cap as u64).read_to_end(&mut bytes)?;
    bytes.extend_from_slice(b"\n[govfuzz: AFL output truncated]\n");
    file.seek(SeekFrom::Start(len.saturating_sub(tail_cap as u64)))?;
    (&mut file).take(tail_cap as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn drain_child_stderr(
    stderr: Option<std::process::ChildStderr>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    let limit = max_captured_stderr_bytes();
    stderr.map(|pipe| std::thread::spawn(move || read_bounded_head_tail(pipe, limit)))
}

fn collected_child_output(
    status: std::process::ExitStatus,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
) -> std::process::Output {
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: stderr
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default(),
    }
}

/// Run `harness_path <input_path>` with a wall-clock timeout. On
/// timeout, kill the process and return a synthetic exit status plus
/// a marker on stderr so the caller can distinguish hang-vs-crash.
fn run_with_timeout(
    harness_path: &Path,
    input_path: &Path,
    timeout: Duration,
    extra_env: &[(String, String)],
    scratch: &Path,
    rss_limit_mb: usize,
    qemu_prefix: Option<(&Path, &[String])>,
) -> Result<std::process::Output, String> {
    // A foreign-arch harness runs under qemu-user (`qemu-aarch64 [args] harness
    // input`); the host path keeps the exact direct `harness input` invocation.
    let mut timeout_cmd = match qemu_prefix {
        Some((program, args)) => {
            let mut cmd = std::process::Command::new(program);
            cmd.args(args).arg(harness_path);
            cmd
        }
        None => std::process::Command::new(harness_path),
    };
    timeout_cmd
        .current_dir(scratch)
        .arg(input_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        timeout_cmd.env(k, v);
    }
    apply_runaway_rlimits(&mut timeout_cmd);
    let mut child = timeout_cmd.spawn().map_err(|error| {
        format!(
            "failed to start harness '{}': {error}",
            harness_path.display()
        )
    })?;
    let stderr_reader = drain_child_stderr(child.stderr.take());

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(collected_child_output(status, stderr_reader)),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let status = child.wait().map_err(|error| {
                        format!(
                            "failed to reap timed-out harness '{}': {error}",
                            harness_path.display()
                        )
                    })?;
                    let mut output = collected_child_output(status, stderr_reader);
                    let marker = format!(
                        "\ngovfuzz: harness exceeded per-input timeout of {:?} - killed\n",
                        timeout
                    );
                    output.stderr.extend_from_slice(marker.as_bytes());
                    return Ok(output);
                }
                if rss_limit_mb > 0 {
                    if let Some(rss) = process_rss_mb(child.id()) {
                        if rss > rss_limit_mb {
                            let _ = child.kill();
                            let status = child.wait().map_err(|error| {
                                format!(
                                    "failed to reap OOM harness '{}': {error}",
                                    harness_path.display()
                                )
                            })?;
                            let mut output = collected_child_output(status, stderr_reader);
                            let marker = format!(
                                "\ngovfuzz: harness exceeded RSS limit of {rss_limit_mb} MB \
                                 (used {rss} MB) - killed\n"
                            );
                            output.stderr.extend_from_slice(marker.as_bytes());
                            return Ok(output);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.and_then(|reader| reader.join().ok());
                return Err(format!(
                    "failed to poll harness '{}': {error}",
                    harness_path.display()
                ));
            }
        }
    }
}

fn run_c_libfuzzer_single_input(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
) -> Result<HarnessRun, String> {
    let tmp_dir = work_dir.join("fuzz_inputs");
    fs::create_dir_all(&tmp_dir)
        .map_err(|error| format!("create fuzz inputs dir '{}': {error}", tmp_dir.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let input_path = tmp_dir.join(format!("input-{}-{}.bin", std::process::id(), nonce));
    fs::write(&input_path, input)
        .map_err(|error| format!("write fuzz input '{}': {error}", input_path.display()))?;

    let output = run_with_timeout(
        runner.harness_path(),
        &input_path,
        per_input_timeout,
        extra_env,
        &ensure_harness_scratch(work_dir)?,
        rss_limit_mb,
        runner.qemu_prefix(),
    )?;
    let _ = fs::remove_file(&input_path);

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        if let Some(report) = corpus::parse_sanitizer_report(&stderr) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(report),
                rejected: false,
            });
        }
        // A timed-out input is not a fuzz failure - it just means this
        // particular input didn't produce a useful signal in the budget.
        // Skip it and let the next iteration mutate further. Real
        // non-zero exits without a sanitizer report still bubble up.
        // An input that blew past the RSS ceiling is a reportable out-of-memory
        // finding (libFuzzer saves OOM units), surfaced via a synthesized report.
        if stderr.contains("exceeded RSS limit") {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(corpus::SanitizerReport {
                    sanitizer: corpus::Sanitizer::AddressSanitizer,
                    kind: "out-of-memory".to_owned(),
                    // A real catalog rule (CWE-789) so the OOM classifies as a
                    // finding like any sanitizer crash, not an unmapped "oom" tag.
                    rule_id: "GF-209",
                    stack: Vec::new(),
                    message: "harness exceeded the configured RSS limit (--rss-limit-mb)"
                        .to_owned(),
                }),
                rejected: false,
            });
        }
        if stderr.contains("exceeded per-input timeout") {
            eprintln!(
                "govfuzz: input hung beyond {:?}, skipping",
                per_input_timeout
            );
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                rejected: false,
            });
        }
        // Hands-off robustness (#15): an `assert()`/`abort()` (SIGABRT) or a
        // non-zero error return with NO sanitizer report is the target REJECTING
        // this input (e.g. cute_aseprite's `assert(magic == 0xA5E0)`). Treat it
        // like a timeout — a clean no-finding run flagged `rejected` so the pass
        // keeps exploring past the bad input.
        if is_input_rejection(&output.status) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                rejected: true,
            });
        }
        // A genuine crash SIGNAL (SIGSEGV/SIGBUS/SIGILL/SIGFPE) with no sanitizer
        // report is still a reachable crash on THIS input — record it as a GF-210
        // finding so it surfaces and the cascade keeps fuzzing, rather than a hard
        // error that aborts the whole pass (which left targets whose empty/early
        // seed crashes, e.g. cute_tiled, reported "built, not fuzzed" with the
        // crash lost). A real ASan/UBSan bug is still classified precisely by its
        // report above; this is the fallback for an unlocalized signal crash.
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: Some(fatal_signal_report(&output.status)),
            rejected: false,
        });
    }
    Ok(HarnessRun {
        events: Vec::new(),
        testcases: Vec::new(),
        sanitizer: None,
        rejected: false,
    })
}

fn load_cmplog_for_run(
    path: Option<&Path>,
    seeds: &[Vec<u8>],
) -> (Option<cmplog::CmpLog>, CmpLogRunSummary) {
    let Some(path) = path else {
        return (
            None,
            CmpLogRunSummary {
                enabled: false,
                status: "disabled".to_owned(),
                log_path: None,
                entries: 0,
                dictionary_tokens: 0,
                seed_splice_candidates: 0,
            },
        );
    };
    match cmplog::ingest_from_jsonl_log(path) {
        Ok(log) => {
            let dictionary_tokens = log.dictionary_tokens().len();
            let seed_splice_candidates = seeds
                .iter()
                .map(|seed| log.splice_candidates(seed).len())
                .sum();
            let entries = log.entries.len();
            (
                Some(log),
                CmpLogRunSummary {
                    enabled: true,
                    status: "loaded".to_owned(),
                    log_path: Some(path.to_path_buf()),
                    entries,
                    dictionary_tokens,
                    seed_splice_candidates,
                },
            )
        }
        Err(error) => {
            eprintln!(
                "warning: failed to ingest cmplog log {}: {error}; falling back to empty dictionary",
                path.display()
            );
            (
                None,
                CmpLogRunSummary {
                    enabled: true,
                    status: "failed".to_owned(),
                    log_path: Some(path.to_path_buf()),
                    entries: 0,
                    dictionary_tokens: 0,
                    seed_splice_candidates: 0,
                },
            )
        }
    }
}

fn builtin_execution_summary(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
) -> ExecutionRunSummary {
    let harness_protocol = if is_c_libfuzzer_harness(runner, work_dir) {
        "libfuzzer_single_input"
    } else {
        "stdin_event_log"
    };
    ExecutionRunSummary {
        harness_protocol: harness_protocol.to_owned(),
        forkserver: false,
        persistent: false,
        persistent_iterations: None,
    }
}

fn afl_execution_summary() -> ExecutionRunSummary {
    ExecutionRunSummary {
        harness_protocol: "afl++_persistent_stdin".to_owned(),
        forkserver: true,
        persistent: true,
        persistent_iterations: Some(10_000),
    }
}

pub(crate) fn parse_sanitizer_args(
    values: &[String],
) -> Result<multicore_fuzz::SanitizerSelection, String> {
    use multicore_fuzz::SanitizerSelection;
    // `none` (#434): build native crash-only + coverage with no `-fsanitize=`.
    // It is a standalone choice — mixing it with real sanitizers is contradictory.
    if values.iter().any(|v| v.eq_ignore_ascii_case("none")) {
        if values.len() > 1 {
            return Err("`--sanitizers none` cannot be combined with other sanitizers".to_owned());
        }
        return Ok(SanitizerSelection::None);
    }
    if values.is_empty() {
        return Ok(SanitizerSelection::Default);
    }
    let mut out = Vec::new();
    for value in values {
        let Some(sanitizer) = multicore_fuzz::Sanitizer::parse(value) else {
            return Err(format!(
                "unknown sanitizer '{value}' (expected asan, msan, ubsan, tsan, lsan, or none)"
            ));
        };
        if !out.contains(&sanitizer) {
            out.push(sanitizer);
        }
    }
    Ok(SanitizerSelection::Set(out))
}

fn sanitizer_env_for(sanitizers: &[multicore_fuzz::Sanitizer]) -> Vec<(String, String)> {
    multicore_fuzz::sanitizer_envs(sanitizers)
        .into_iter()
        .flatten()
        .collect()
}

/// Environment overrides applied to EVERY builtin fuzz child, independent of
/// `--sanitizers` (the C/C++ harness is always ASan-built).
///
/// Neutralizes the network debuginfod client: on a crash ASan's in-process
/// symbolizer consults the system debuginfod server (`DEBUGINFOD_URLS`, set by
/// default on stock Ubuntu) over HTTPS. For a target where most inputs crash —
/// e.g. a callback struct cast straight from fuzz bytes, whose garbage function
/// pointer faults on the first byte — that round-trip runs on every crash, and
/// the X.509/TLS strcmp traffic libcurl→OpenSSL drives through our cmplog hooks
/// floods the runtrace; together they blow past the per-target wall cap (a 2.7s
/// run became 182s). A fuzz child never wants a network debuginfo fetch in the
/// hot loop; local symbolization still works, so finding stack frames stay
/// symbolized. An explicit caller-supplied value is respected.
fn apply_fuzz_child_env_overrides(extra_env: &mut Vec<(String, String)>) {
    if !extra_env.iter().any(|(k, _)| k == "DEBUGINFOD_URLS") {
        extra_env.push(("DEBUGINFOD_URLS".to_owned(), String::new()));
    }
}

fn sanitizer_summary(
    sanitizers: &[multicore_fuzz::Sanitizer],
    env: &[(String, String)],
    composition_campaign: bool,
) -> SanitizerRunSummary {
    SanitizerRunSummary {
        requested: sanitizers
            .iter()
            .map(|s| sanitizer_name(*s).to_owned())
            .collect(),
        active_env: env
            .iter()
            .map(|(key, value)| EnvVarSummary {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        composition_campaign,
    }
}

fn sanitizer_name(sanitizer: multicore_fuzz::Sanitizer) -> &'static str {
    match sanitizer {
        multicore_fuzz::Sanitizer::Asan => "asan",
        multicore_fuzz::Sanitizer::Msan => "msan",
        multicore_fuzz::Sanitizer::Ubsan => "ubsan",
        multicore_fuzz::Sanitizer::Tsan => "tsan",
        multicore_fuzz::Sanitizer::Lsan => "lsan",
    }
}

fn which_executable(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "'{name}' not found on PATH; install AFL++ (apt install afl++ or build from source) before using --engine afl++"
    ))
}

/// Entropic seed weight (#382): a seed's selection weight rises with the
/// coverage novelty it contributed (`energy`) and decays with how many times it
/// has already been chosen (`selections`), so the mutator pours energy into
/// high-yield, under-explored seeds and backs off ones it has already mined.
fn entropic_weight(energy: u32, selections: u64) -> u64 {
    (u64::from(energy) + 1).saturating_mul(1024) / (selections + 1)
}

/// Pick a pool index weighted by [`entropic_weight`] (#382). Falls back to
/// uniform choice when all weights are zero, and 0 for an empty pool.
fn choose_entropic_index_pool(pool: &[PoolEntry], rng: &mut MutationRng) -> usize {
    if pool.is_empty() {
        return 0;
    }
    let weights: Vec<u64> = pool
        .iter()
        .map(|entry| entropic_weight(entry.energy, entry.selections))
        .collect();
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return rng.choose_index(pool.len()).unwrap_or(0);
    }
    let mut r = rng.next_u64() % total;
    for (index, weight) in weights.iter().enumerate() {
        if r < *weight {
            return index;
        }
        r -= *weight;
    }
    pool.len() - 1
}

/// Max byte positions a colorization pass probes per base (#400). Bounds the
/// extra execs (each probe is one fork-server run) so colorization stays once-per-
/// base overhead rather than scaling with arbitrarily long inputs.
const MAX_COLORIZE_PROBES: usize = 64;
/// Don't colorize inputs shorter than this — too little to gain offset precision.
const MIN_COLORIZE_LEN: usize = 4;

/// RedQueen colorization (#400). Replace as many of `base`'s bytes as possible
/// with random values that do **not** change its edge-coverage footprint, so each
/// don't-care position holds a near-unique value. Then `cmplog`'s single-byte /
/// short operands splice at the exact offset they were compared instead of at
/// every occurrence of a common byte (0x00, ' ') — the precision fix RedQueen
/// needs on parsers full of repeated bytes (cJSON's `*c=='{'` char gates).
///
/// Coverage is measured in isolation by zeroing the shared bitmap before each
/// probe and reading the exact footprint; the cumulative #398 feedback is saved
/// up front and **restored** at the end, so colorization's probe execs never
/// leak edges into corpus retention. Returns the original base unchanged if the
/// fork-server dies mid-pass (the caller's next real run respawns it).
fn colorize_base(
    cov: &mut CoverageTracker,
    fork: &mut ForkServer,
    base: &[u8],
    rng: &mut MutationRng,
) -> Vec<u8> {
    if base.len() < MIN_COLORIZE_LEN {
        return base.to_vec();
    }
    let backup = cov.snapshot();
    cov.zero();
    if matches!(fork.run_one(base), ForkOutcome::Died) {
        cov.restore(&backup);
        return base.to_vec();
    }
    let base_cov = cov.snapshot();
    let mut colored = base.to_vec();
    let probes = base.len().min(MAX_COLORIZE_PROBES);
    for i in 0..probes {
        let original = colored[i];
        let candidate = rng.next_u8();
        if candidate == original {
            continue;
        }
        colored[i] = candidate;
        cov.zero();
        match fork.run_one(&colored) {
            ForkOutcome::Died => {
                // The probe crashed or hung; revert it and stop (the colored
                // input must stay coverage-equivalent and non-crashing).
                colored[i] = original;
                break;
            }
            ForkOutcome::Ran(_) => {
                if cov.snapshot() != base_cov {
                    // This byte affects control flow — keep the original value.
                    colored[i] = original;
                }
            }
        }
    }
    cov.restore(&backup);
    colored
}

/// Run `base` once with RedQueen cmplog capture armed and return the comparison
/// operand pairs it produced (#400). The capture exec's findings/coverage are
/// intentionally ignored — this is pure input-to-state evidence-gathering, paid
/// once per base and then cached on its [`PoolEntry`].
fn capture_cmplog(reader: &CmpShmReader, fork: &mut ForkServer, base: &[u8]) -> cmplog::CmpLog {
    reader.arm();
    // The driver fills the ring as a side effect of running `base`; whether the
    // run produced events / a crash is irrelevant to operand capture.
    let _ = fork.run_one(base);
    let log = reader.read_log();
    reader.disarm();
    log
}

/// Load a `--grammar` JSON file into a [`Grammar`]. The file is a JSON object mapping
/// each non-terminal name to a list of production strings, where `{NAME}` references
/// another rule. `None` → `Ok(None)` (no grammar in play). A malformed grammar is a
/// hard error so a typo is surfaced rather than silently fuzzing without structure.
pub(crate) fn load_grammar_for_run(path: Option<&Path>) -> Result<Option<Grammar>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let grammar_limit = max_grammar_bytes();
    let (bytes, original_len) = read_seed_file_prefix(path, grammar_limit)
        .map_err(|e| format!("read grammar {}: {e}", path.display()))?;
    if original_len > bytes.len() as u64 {
        return Err(format!(
            "grammar {} is {original_len} bytes, above the {} MiB safety limit",
            path.display(),
            grammar_limit / (1024 * 1024)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("grammar {} is not valid JSON: {e}", path.display()))?;
    let obj = value.as_object().ok_or_else(|| {
        format!(
            "grammar {} must be a JSON object of name -> productions",
            path.display()
        )
    })?;
    let mut rules: Vec<(String, Vec<String>)> = Vec::new();
    for (name, prods) in obj {
        let alts = prods.as_array().ok_or_else(|| {
            format!("grammar rule {name:?} must be a JSON array of production strings")
        })?;
        let mut productions = Vec::with_capacity(alts.len());
        for prod in alts {
            let s = prod
                .as_str()
                .ok_or_else(|| format!("a production in grammar rule {name:?} must be a string"))?;
            productions.push(s.to_owned());
        }
        rules.push((name.clone(), productions));
    }
    Grammar::from_rules(&rules, None).map(Some)
}

/// Build one mutated child from pool entry `base_index`. Prefers that entry's
/// per-input RedQueen cmplog (#400) so `CmpLogSplice` injects the operands it
/// observed at the offsets they were compared; falls back to the global
/// pre-mined log (`global_cmplog`) so non-driver paths keep their behavior.
#[allow(clippy::too_many_arguments)]
fn mutate_from_pool(
    pool: &[PoolEntry],
    base_index: usize,
    dictionary: &Dictionary,
    global_cmplog: Option<&cmplog::CmpLog>,
    grammar: Option<&Grammar>,
    config: MutatorConfig,
    rng: &mut MutationRng,
) -> Vec<u8> {
    let suite = MutatorSuite::new(config);
    let base = pool
        .get(base_index)
        .map(PoolEntry::mutation_base)
        .unwrap_or(&[]);
    let peer = pool
        .get((base_index + 1) % pool.len().max(1))
        .map(PoolEntry::mutation_base)
        .unwrap_or(&[]);
    let mut mutation_input = MutationInput::new(base, dictionary).with_peer(peer);
    let cmplog = pool
        .get(base_index)
        .and_then(|entry| entry.cmplog.as_ref())
        .or(global_cmplog);
    if let Some(log) = cmplog {
        mutation_input = mutation_input.with_cmplog(log);
    }
    if let Some(g) = grammar {
        mutation_input = mutation_input.with_grammar(g);
    }

    let bytes = suite
        .mutate(&mutation_input, rng)
        .map(|result| result.bytes)
        .unwrap_or_else(|| vec![rng.next_u8()]);
    // AdaFuzz.Input.Load_From_Stdin exits the harness loop on empty input,
    // which leaves no event log behind and breaks first-run dogfooding when
    // no --seed-input is supplied. Guarantee at least one byte every time.
    if bytes.is_empty() {
        vec![rng.next_u8()]
    } else {
        bytes
    }
}

/// One adaptive length-control update. Returns the next effective mutation
/// length and plateau counter. With `len_control == 0` (disabled) or once the
/// ceiling is reached, the length is held; a new corpus signature resets the
/// plateau; otherwise the length doubles toward `max_len` every `len_control`
/// flat executions.
/// One adaptive-length step (libFuzzer `-len_control`): after `len_control` executions
/// with no new coverage, double the effective mutation length toward `ceiling`. Unlike
/// plain libFuzzer control, when the effective length has REACHED the ceiling the
/// plateau counter is HELD at the threshold (rather than reset) so the caller can
/// detect "stuck at the ceiling" and decide whether to raise it (the adaptive ceiling).
fn len_control_step(
    effective: usize,
    ceiling: usize,
    len_control: usize,
    execs_since_new: usize,
    found_new_signature: bool,
) -> (usize, usize) {
    if len_control == 0 {
        return (effective, 0);
    }
    if found_new_signature {
        return (effective, 0);
    }
    let plateau = execs_since_new + 1;
    if plateau >= len_control && effective < ceiling {
        (effective.saturating_mul(2).min(ceiling), 0)
    } else {
        // Below threshold, or stuck at the ceiling: hold the plateau (capped at the
        // threshold) so a stuck-at-ceiling caller sees the signal and can raise it.
        (effective, plateau.min(len_control))
    }
}

fn mutator_config(structured_inputs: StructuredInputMode, max_len: usize) -> MutatorConfig {
    MutatorConfig {
        max_len,
        structured_records: structured_inputs.structured_records_enabled(),
        structured_json: structured_inputs.structured_json_enabled(),
        structured_xml: structured_inputs.structured_xml_enabled(),
        structured_key_value: structured_inputs.structured_key_value_enabled(),
        structured_url_encoded: structured_inputs.structured_url_encoded_enabled(),
        structured_multipart: structured_inputs.structured_multipart_enabled(),
        structured_csv: structured_inputs.structured_csv_enabled(),
        structured_http: structured_inputs.structured_http_enabled(),
        structured_ini: structured_inputs.structured_ini_enabled(),
        structured_toml: structured_inputs.structured_toml_enabled(),
        structured_yaml: structured_inputs.structured_yaml_enabled(),
        structured_chunked: structured_inputs.structured_chunked_enabled(),
        structured_recursive: structured_inputs.structured_recursive_enabled(),
    }
}

fn find_generated_dictionary(work_dir: &Path, harness_id: &str) -> Option<PathBuf> {
    [
        crate::auto::layout::harness_dir(work_dir, harness_id).join("dictionary.txt"),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id).join("dictionary.txt"),
        work_dir
            .join("generated_harnesses")
            .join(harness_id)
            .join("dictionary.txt"),
        work_dir
            .join("build")
            .join(harness_id)
            .join("dictionary.txt"),
        work_dir.join("fake_corba").join("dictionary.txt"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn load_generated_dictionary_tokens(
    work_dir: &Path,
    harness_id: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let Some(path) = find_generated_dictionary(work_dir, harness_id) else {
        return Ok(Vec::new());
    };
    load_afl_dictionary_tokens(&path)
}

fn load_afl_dictionary_tokens(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let dictionary_limit = max_dictionary_bytes();
    let (bytes, original_len) = read_seed_file_prefix(path, dictionary_limit)
        .map_err(|error| format!("read dictionary '{}': {error}", path.display()))?;
    if original_len > dictionary_limit as u64 {
        return Err(format!(
            "dictionary '{}' is {original_len} bytes, above the {} MiB safety limit",
            path.display(),
            dictionary_limit / (1024 * 1024)
        ));
    }
    let contents = String::from_utf8(bytes)
        .map_err(|error| format!("dictionary '{}' is not UTF-8: {error}", path.display()))?;
    let mut tokens = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        // The dictionary is a best-effort optimization. A single malformed line
        // must never abort the fuzz run — skip it with a warning and keep the
        // tokens we could parse, rather than dropping the whole campaign.
        match parse_afl_dictionary_line(line) {
            Ok(Some(token)) => {
                if !tokens.contains(&token) {
                    tokens.push(token);
                }
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!(
                    "govfuzz: warning: skipping dictionary '{}:{}': {error}",
                    path.display(),
                    index + 1
                );
            }
        }
    }
    Ok(tokens)
}

fn parse_afl_dictionary_line(line: &str) -> Result<Option<Vec<u8>>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // The token value is the quoted span. An optional AFL `name=` / `name@level=`
    // prefix may precede it, but a dictionary name never contains a quote, so the
    // value reliably begins at the first `"`. Splitting on `=` to strip the prefix
    // would corrupt any token that legitimately contains `=` — e.g. printf format
    // strings such as `"len of TF\t = %d"` lifted verbatim from the target source.
    let Some(open_quote) = trimmed.find('"') else {
        return Err("expected quoted token".to_owned());
    };
    let rest = &trimmed[open_quote + 1..];
    let mut out = Vec::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Ok(Some(out)),
            '\\' => match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('x') => {
                    let hi = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| "invalid hex escape".to_owned())?;
                    let lo = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| "invalid hex escape".to_owned())?;
                    out.push(((hi << 4) | lo) as u8);
                }
                Some(other) => {
                    let mut buf = [0; 4];
                    out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => return Err("unterminated escape".to_owned()),
            },
            other => {
                let mut buf = [0; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Err("unterminated quoted token".to_owned())
}

/// Write one framed input (`u32` little-endian length + bytes) to the harness
/// stdin, matching `AdaFuzz.Input.Load_From_Stdin`'s framing.
fn write_input_frame(stdin: &mut impl std::io::Write, input: &[u8]) -> std::io::Result<()> {
    stdin.write_all(&(input.len() as u32).to_le_bytes())?;
    stdin.write_all(input)
}

/// The directory of the `GOVFUZZ_RUNTRACE_LOG` path in `extra_env`, if set, so
/// it can be bound into the sandbox for the harness to write runtrace events.
fn runtrace_log_dir(extra_env: &[(String, String)]) -> Option<PathBuf> {
    extra_env
        .iter()
        .find(|(key, _)| key == "GOVFUZZ_RUNTRACE_LOG")
        .and_then(|(_, value)| Path::new(value).parent().map(Path::to_path_buf))
}

/// #416: inputs already recorded as crash findings, read from
/// `<work>/findings/*/testcase.bin`. A crashing input is a finding, not a clean
/// coverage seed, so it must be kept out of the persisted corpus — even when a
/// later pass re-introduces it as a built-in/reseeded seed and the cumulative,
/// pass-shared coverage map means it grows no new edges to re-trigger in-pass
/// detection. Reading the durable findings dir makes the exclusion cross-pass
/// correct without re-running every seed.
fn existing_crash_testcases(work_dir: &Path, harness_id: &str, max_len: usize) -> HashSet<u64> {
    let finding_record_limit = max_finding_record_bytes();
    let dedup_limit = max_finding_dedup_keys();
    let mut set = HashSet::new();
    let Ok(entries) = fs::read_dir(work_dir.join("findings")) else {
        return set;
    };
    for entry in entries.flatten() {
        let finding_path = entry.path().join("finding.json");
        if fs::metadata(&finding_path).is_ok_and(|metadata| metadata.len() > finding_record_limit) {
            continue;
        }
        let Ok(bytes) = fs::read(&finding_path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if record.get("harness_id").and_then(|value| value.as_str()) != Some(harness_id) {
            continue;
        }
        if set.len() >= dedup_limit {
            break;
        }
        if let Some(key) = crash_testcase_key(&entry.path().join("testcase.bin"), max_len) {
            set.insert(key);
        }
    }
    set
}

/// Compact, allocation-free identity for crash inputs retained only to keep them
/// out of the clean corpus. A collision merely drops one clean corpus entry; it
/// cannot fabricate or suppress the already-emitted crash finding.
fn crash_input_key(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn crash_testcase_key(path: &Path, max_len: usize) -> Option<u64> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > max_len as u64 {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let mut hash = 0xcbf29ce484222325_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        for byte in &buf[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Some(hash)
}

/// Pre-seed the within-pass dedup sets from findings already written to disk so a
/// later cascade pass (Empty/Rng/FuzzDriven) over the SAME harness does not
/// re-emit a finding it already produced (#35: the cascade otherwise wrote the
/// same root cause once per pass, inflating findings.csv / the findings dir /
/// summary counts ~2-3x). Returns `(sanitizer-cluster keys, oracle-hit keys)`
/// reconstructed to match the runtime keys `first_of_sanitizer_cluster` /
/// `oracle_hit_dedupe_key` compute. Mirrors `existing_crash_testcases`.
fn existing_finding_dedup_keys(work_dir: &Path, harness_id: &str) -> (Vec<String>, Vec<String>) {
    let finding_record_limit = max_finding_record_bytes();
    let dedup_limit = max_finding_dedup_keys();
    let mut clusters = Vec::new();
    let mut oracles = Vec::new();
    let Ok(entries) = fs::read_dir(work_dir.join("findings")) else {
        return (clusters, oracles);
    };
    for entry in entries.flatten() {
        if clusters.len().saturating_add(oracles.len()) >= dedup_limit {
            break;
        }
        let finding_path = entry.path().join("finding.json");
        if fs::metadata(&finding_path).is_ok_and(|metadata| metadata.len() > finding_record_limit) {
            continue;
        }
        let Ok(bytes) = fs::read(finding_path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if record.get("harness_id").and_then(|value| value.as_str()) != Some(harness_id) {
            continue;
        }
        let rule_id = record.get("rule_id").and_then(|v| v.as_str());
        // Oracle-hit finding: key = rule_id|oracle_name|api (oracle_hit_dedupe_key).
        if let (Some(rule_id), Some(oracle)) = (rule_id, record.get("oracle")) {
            if let (Some(name), Some(api)) = (
                oracle.get("name").and_then(|v| v.as_str()),
                oracle.get("api").and_then(|v| v.as_str()),
            ) {
                oracles.push(format!("{rule_id}|{name}|{api}"));
                continue;
            }
        }
        // Sanitizer-crash finding: key = cluster_key_full, or rule:<id> on fallback
        // (matches first_of_sanitizer_cluster).
        let fallback = record
            .get("cluster_fallback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if fallback {
            if let Some(rule_id) = rule_id {
                clusters.push(format!("rule:{rule_id}"));
            }
        } else if let Some(full) = record.get("cluster_key_full").and_then(|v| v.as_str()) {
            clusters.push(full.to_owned());
        }
    }
    (clusters, oracles)
}

fn run_harness(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
) -> Result<HarnessRun, String> {
    if is_c_libfuzzer_harness(runner, work_dir) {
        return run_c_libfuzzer_single_input(
            runner,
            work_dir,
            input,
            extra_env,
            per_input_timeout,
            rss_limit_mb,
        );
    }
    let events_path = temp_event_path(work_dir)?;
    let scratch = ensure_harness_scratch(work_dir)?;
    // When a runtrace log is configured (the executable oracles read it), bind
    // its directory read-write into the sandbox so the harness can write events
    // from inside it. No-op when not sandboxed or when it is the events dir.
    let runner_owned;
    let runner = match runtrace_log_dir(extra_env) {
        Some(dir) => {
            runner_owned = runner.clone().with_rw_binds([dir]);
            &runner_owned
        }
        None => runner,
    };
    let mut command = runner
        .command_for_events(&events_path)
        .map_err(|error| error.to_string())?;
    command
        .current_dir(&scratch)
        .env("GOVFUZZ_EVENTS_PATH", &events_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        command.env(k, v);
    }
    apply_runaway_rlimits(&mut command);
    let mut child = command.spawn().map_err(|error| {
        format!(
            "failed to start harness '{}': {error}",
            runner.harness_path().display()
        )
    })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open harness stdin".to_owned())?;
        // Raw input: per-spawn feeds the whole input as stdin (the AdaFuzz
        // runtime reads framed stdin only under GOVFUZZ_FRAMED, set by the
        // fork-server). Closing stdin afterwards is the harness loop's EOF.
        //
        // A harness that exits (or stops reading) before consuming the whole
        // input closes the pipe, so `write_all` returns BrokenPipe. That is NOT a
        // harness error — the process ran, and its exit code / stderr below are
        // the real signal (an immediate `exit N` rejection, or a sanitizer crash
        // on the first bytes). Swallow BrokenPipe; only a genuine I/O error aborts.
        if let Err(error) = stdin.write_all(input) {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("write harness stdin: {error}"));
            }
        }
    }
    // Signal EOF to the harness's read loop. `wait_with_output` used to drop the
    // stdin handle implicitly; we poll for exit below (to enforce a wall-clock
    // timeout), so close it explicitly here or the harness blocks awaiting EOF.
    drop(child.stdin.take());
    // Drain stderr on a thread so a chatty harness cannot fill the pipe buffer
    // and stall on write. The collector itself is bounded because target output
    // is untrusted and this path executes once per fuzz input.
    let stderr_reader = drain_child_stderr(child.stderr.take());
    // Enforce `per_input_timeout` as a WALL-CLOCK bound. A hung harness sits at
    // 0% CPU blocked on I/O, so `apply_runaway_rlimits`' RLIMIT_CPU (CPU-time)
    // never fires for it — `wait_with_output` here would block the engine
    // forever. The C/libFuzzer lane already wall-clock-bounds its wait in
    // `run_c_libfuzzer_single_input`; this is the matching guard for the
    // event-log per-spawn lane (the #412 deadlock class).
    let deadline = Instant::now() + per_input_timeout;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                return Err(format!(
                    "wait for harness '{}': {error}",
                    runner.harness_path().display()
                ));
            }
        }
    };
    let stderr_bytes = stderr_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let Some(status) = exit_status else {
        // Timed out: a hung input produces no coverage/findings. Discard any
        // partial event log and return a clean no-event run rather than
        // hanging the engine.
        let _ = fs::remove_file(&events_path);
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: None,
            rejected: false,
        });
    };
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        // C / C++ libFuzzer + AFL++ harnesses do not write an Ada event log -
        // they exit with a non-zero status and a sanitizer report in stderr.
        // Surface that as a structured HarnessRun instead of a hard error so
        // the fuzz loop can emit a finding.
        if let Some(report) = corpus::parse_sanitizer_report(&stderr) {
            let _ = fs::remove_file(&events_path);
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: Some(report),
                rejected: false,
            });
        }
        // Hands-off robustness (#15): an assert/abort (SIGABRT) or non-zero error
        // return with NO sanitizer report is the target REJECTING this input — a
        // clean no-event run flagged `rejected` so the pass CONTINUES exploring
        // past the bad input instead of aborting.
        let _ = fs::remove_file(&events_path);
        if is_input_rejection(&status) {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                rejected: true,
            });
        }
        // A genuine crash SIGNAL (SIGSEGV/SIGBUS/SIGILL/SIGFPE) with no report is a
        // reachable crash on this input — record it as a GF-210 finding (surfaces
        // it + keeps the cascade fuzzing) rather than a hard error that aborts the
        // whole pass. Precise ASan/UBSan bugs still classify via their report above.
        return Ok(HarnessRun {
            events: Vec::new(),
            testcases: Vec::new(),
            sanitizer: Some(fatal_signal_report(&status)),
            rejected: false,
        });
    }

    let event_delta_limit = max_event_delta_bytes();
    if fs::metadata(&events_path).is_ok_and(|metadata| metadata.len() > event_delta_limit) {
        let _ = fs::remove_file(&events_path);
        return Err(format!(
            "event log exceeded the {} MiB per-execution memory cap (raise \
             GOVFUZZ_MAX_EVENT_DELTA_BYTES if intended)",
            event_delta_limit / (1024 * 1024)
        ));
    }
    let event_bytes = match fs::read(&events_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The harness exited without ever calling Begin_Testcase (typical
            // when stdin was empty and the AdaFuzz.Input loop exited
            // immediately). Treat as a zero-event clean run rather than a
            // hard error.
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                rejected: false,
            });
        }
        Err(error) => {
            return Err(format!(
                "read event log '{}': {error}",
                events_path.display()
            ));
        }
    };
    let _ = fs::remove_file(&events_path);
    let events = EventReader::new(event_bytes.as_slice())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read event log '{}': {error}", events_path.display()))?;
    let testcases = group_into_testcases(EventReader::new(event_bytes.as_slice()))
        .map_err(|error| format!("group event log '{}': {error}", events_path.display()))?;

    Ok(HarnessRun {
        events,
        testcases,
        sanitizer: None,
        rejected: false,
    })
}

/// Replay a single corpus input through `runner` and return the grouped
/// testcases it produced. Used by `govfuzz corpus minimize` to compute each
/// input's coverage contribution. C/C++ libFuzzer harnesses do not emit an
/// Ada event log, so they yield an empty vector (no runtrace coverage).
pub(crate) fn replay_input_testcases(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
) -> Result<Vec<Testcase>, String> {
    let run = run_harness(runner, work_dir, input, &[], PER_INPUT_TIMEOUT, 0)?;
    Ok(run.testcases)
}

/// Replay-verify a C/C++ sanitizer crash (#388): re-run the input in a fresh
/// process and confirm it reproduces a sanitizer crash with the same `rule_id`.
/// A passthrough libFuzzer harness can corrupt allocator state across inputs
/// and crash in driver glue even on empty input; those faults do not reproduce
/// and must not be reported (libFuzzer/AFL find zero on that class).
fn sanitizer_crash_reproduces(
    runner: &replay_min::HarnessRunner,
    work_dir: &Path,
    input: &[u8],
    report: &corpus::SanitizerReport,
    extra_env: &[(String, String)],
    per_input_timeout: Duration,
    rss_limit_mb: usize,
) -> bool {
    // Replay-verify MUST reconstruct the same environment the crash occurred
    // under — the runtrace shim's LD_PRELOAD + GOVFUZZ_RUNTRACE_MODE that inject
    // env vars / fake resources. Re-running with an empty env spuriously fails to
    // reproduce env-triggered crashes (e.g. getenv-gated faults) and drops real
    // findings.
    match run_c_libfuzzer_single_input(
        runner,
        work_dir,
        input,
        extra_env,
        per_input_timeout,
        rss_limit_mb,
    ) {
        Ok(rerun) => rerun
            .sanitizer
            .as_ref()
            .map(|fresh| fresh.rule_id == report.rule_id)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Re-run `input` in a fresh per-spawn process and report whether the finding
/// `signature` reproduces. Used to validate fork-server findings so an artifact
/// of accumulated global state is never emitted as a finding (it would not
/// reproduce from the testcase alone, the canonical replay).
fn finding_reproduces_per_spawn(
    prepared: &PreparedFuzzRun,
    input: &[u8],
    signature: &Signature,
) -> Result<bool, String> {
    let run = run_harness(
        &prepared.runner,
        &prepared.work_dir,
        input,
        &prepared.extra_env,
        prepared.per_input_timeout,
        prepared.rss_limit_mb,
    )?;
    if run.sanitizer.is_some() {
        return Ok(true);
    }
    for testcase in &run.testcases {
        for (handler_index, _) in classify(testcase) {
            if let Some(handler) = resolve_handler(testcase, handler_index) {
                if compute_signature(testcase, handler.as_ref()) == *signature {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Resolve whether the persistent fork-server runs. It is the **default** (it
/// keeps the coverage-guided feedback while amortizing fork/exec/elaboration,
/// and replay-validates every finding so it is safe). `--fork-server` forces it
/// on; `--no-fork-server` or `GOVFUZZ_FORK_SERVER=0` turn it off.
fn resolve_fork_server(force_on: bool, force_off: bool) -> bool {
    if force_on {
        return true;
    }
    if force_off {
        return false;
    }
    std::env::var("GOVFUZZ_FORK_SERVER").as_deref() != Ok("0")
}

/// A persistent harness process driven one input at a time over the framed
/// stdin protocol. Used only for the common clean path; a hard crash falls back
/// to per-spawn `run_harness` (which isolates and reports it precisely) and the
/// caller respawns the server.
struct ForkServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    events_path: PathBuf,
    events_offset: u64,
    /// Per-input RSS ceiling (MB), mirrored from the run so the persistent
    /// process enforces `--rss-limit-mb` too. 0 disables. Without this the
    /// fork-server path (the common driver path since #399) silently ignored the
    /// limit — only the per-spawn fallback enforced it.
    rss_limit_mb: usize,
}

enum ForkOutcome {
    Ran(HarnessRun),
    /// The process exited/crashed/hung handling this input; respawn + re-run.
    Died,
}

/// Handshake timeout (ms): a conforming Ada harness writes its "ready" sync byte
/// at startup essentially instantly; anything not speaking the framed protocol
/// (a C/libFuzzer harness, a stale build, a test mock) never does, so spawn bails
/// to per-spawn after this.
const FORK_HANDSHAKE_TIMEOUT_MS: i32 = 2000;
/// Per-input sync timeout (ms): a backstop for a single input that hangs the
/// persistent process (where the cumulative CPU rlimit would not catch it
/// promptly). On timeout the input is isolated via the per-spawn path.
const FORK_RUN_TIMEOUT_MS: i32 = 30_000;

/// Block until `fd` is readable or `timeout_ms` elapses. Returns true if
/// readable, false on timeout/error (caller treats either as "no response").
#[cfg(unix)]
fn fd_readable_within(fd: std::os::unix::io::RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a valid initialized pollfd for the duration of the call.
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 }
}
#[cfg(not(unix))]
fn fd_readable_within(_fd: i32, _timeout_ms: i32) -> bool {
    true
}

/// The raw fd of a child's stdout for the readability poll on unix; a dummy on
/// other platforms (where `fd_readable_within` ignores it and returns `true`, so
/// the caller falls through to a blocking `read_exact`). Keeps the fork-server
/// handshake/sync code platform-agnostic without sprinkling `os::unix` imports.
#[cfg(unix)]
fn child_stdout_fd(stdout: &std::process::ChildStdout) -> std::os::unix::io::RawFd {
    use std::os::unix::io::AsRawFd;
    stdout.as_raw_fd()
}
#[cfg(not(unix))]
fn child_stdout_fd(_stdout: &std::process::ChildStdout) -> i32 {
    0
}

impl ForkServer {
    fn spawn(
        runner: &replay_min::HarnessRunner,
        work_dir: &Path,
        extra_env: &[(String, String)],
        rss_limit_mb: usize,
    ) -> Result<Self, String> {
        let events_path = temp_event_path(work_dir)?;
        // Fresh, empty events file; we read deltas from it per input.
        fs::File::create(&events_path)
            .map_err(|error| format!("create fork-server event log: {error}"))?;
        let scratch = ensure_harness_scratch(work_dir)?;
        let runner_owned;
        let runner = match runtrace_log_dir(extra_env) {
            Some(dir) => {
                runner_owned = runner.clone().with_rw_binds([dir]);
                &runner_owned
            }
            None => runner,
        };
        let mut command = runner
            .command_for_events(&events_path)
            .map_err(|error| error.to_string())?;
        command
            .current_dir(&scratch)
            .env("GOVFUZZ_EVENTS_PATH", &events_path)
            // Switch the AdaFuzz runtime into framed-stdin + sync mode.
            .env("GOVFUZZ_FRAMED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in extra_env {
            command.env(k, v);
        }
        apply_runaway_rlimits(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn fork-server harness: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "fork-server: no stdin".to_owned())?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "fork-server: no stdout".to_owned())?;
        // Handshake: a conforming harness writes a "ready" sync byte at startup.
        // No byte within the timeout means this harness does not speak the framed
        // protocol (a C/libFuzzer harness, a stale build, a test mock) -> bail so
        // the caller uses the per-spawn path.
        use std::io::Read;
        let fd = child_stdout_fd(&stdout);
        let mut ready = [0u8; 1];
        if !fd_readable_within(fd, FORK_HANDSHAKE_TIMEOUT_MS)
            || stdout.read_exact(&mut ready).is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&events_path);
            return Err("fork-server: harness did not complete the protocol handshake".to_owned());
        }
        Ok(Self {
            child,
            stdin,
            stdout,
            events_path,
            events_offset: 0,
            rss_limit_mb,
        })
    }

    /// Whether the persistent child's RSS now exceeds the configured ceiling.
    /// Polling `/proc/<pid>/statm` mirrors the per-spawn path; `false` when no
    /// limit is set or the stat is unavailable.
    fn rss_exceeded(&self) -> bool {
        self.rss_limit_mb > 0
            && process_rss_mb(self.child.id()).is_some_and(|rss| rss > self.rss_limit_mb)
    }

    fn run_one(&mut self, input: &[u8]) -> ForkOutcome {
        use std::io::Read;
        // Write the framed input, then await the harness's sync byte (sent from
        // its next Load_From_Stdin once it has flushed this input's events). A
        // broken pipe / EOF means the process died; a timeout means this input
        // hung the persistent process — both isolate via the per-spawn path.
        if write_input_frame(&mut self.stdin, input)
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            return ForkOutcome::Died;
        }
        if !self.await_sync_within_rss_limit() {
            // Either the input hung the process or it blew past the RSS ceiling;
            // kill the child and isolate via the per-spawn path, which polls RSS
            // and synthesizes the GF-209 out-of-memory finding.
            let _ = self.child.kill();
            return ForkOutcome::Died;
        }
        let mut sync = [0u8; 1];
        if self.stdout.read_exact(&mut sync).is_err() {
            return ForkOutcome::Died;
        }
        // The input may have driven RSS over the ceiling and only then sent its
        // sync byte (the harness frees nothing mid-loop); catch that too.
        if self.rss_exceeded() {
            let _ = self.child.kill();
            return ForkOutcome::Died;
        }
        match self.read_event_delta() {
            Ok(run) => ForkOutcome::Ran(run),
            Err(_) => ForkOutcome::Died,
        }
    }

    /// Wait for the harness's sync byte to become readable, returning `true` once
    /// it is. With no RSS limit this is a single bounded poll; with a limit it
    /// polls in short slices, returning `false` if the child's RSS breaches the
    /// ceiling (or the whole-input timeout elapses) so the caller can isolate it.
    fn await_sync_within_rss_limit(&self) -> bool {
        let fd = child_stdout_fd(&self.stdout);
        if self.rss_limit_mb == 0 {
            return fd_readable_within(fd, FORK_RUN_TIMEOUT_MS);
        }
        const RSS_POLL_INTERVAL_MS: i32 = 25;
        let deadline = Instant::now() + Duration::from_millis(FORK_RUN_TIMEOUT_MS as u64);
        loop {
            if fd_readable_within(fd, RSS_POLL_INTERVAL_MS) {
                return true;
            }
            if self.rss_exceeded() || Instant::now() >= deadline {
                return false;
            }
        }
    }

    fn read_event_delta(&mut self) -> Result<HarnessRun, String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(&self.events_path)
            .map_err(|error| format!("open fork-server event log: {error}"))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size <= self.events_offset {
            return Ok(HarnessRun {
                events: Vec::new(),
                testcases: Vec::new(),
                sanitizer: None,
                rejected: false,
            });
        }
        let event_delta_limit = max_event_delta_bytes();
        if size.saturating_sub(self.events_offset) > event_delta_limit {
            self.events_offset = size;
            return Err(format!(
                "fork-server event delta exceeded the {} MiB memory cap (raise \
                 GOVFUZZ_MAX_EVENT_DELTA_BYTES if intended)",
                event_delta_limit / (1024 * 1024)
            ));
        }
        file.seek(SeekFrom::Start(self.events_offset))
            .map_err(|error| format!("seek fork-server event log: {error}"))?;
        let mut bytes = Vec::with_capacity((size - self.events_offset) as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("read fork-server event log: {error}"))?;
        self.events_offset = size;
        let events = EventReader::new(bytes.as_slice())
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse fork-server events: {error}"))?;
        let testcases = group_into_testcases(EventReader::new(bytes.as_slice()))
            .map_err(|error| format!("group fork-server events: {error}"))?;
        Ok(HarnessRun {
            events,
            testcases,
            sanitizer: None,
            rejected: false,
        })
    }
}

impl Drop for ForkServer {
    fn drop(&mut self) {
        // Closing stdin is the EOF that ends the harness loop; then reap.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.events_path);
    }
}

pub(crate) fn find_harness_executable(
    work_dir: &Path,
    harness_id: &str,
    engine: FuzzEngine,
) -> Result<PathBuf, String> {
    let build_dir = work_dir.join("build").join(harness_id);
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let legacy_auto_dir = crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id);
    if !build_dir.is_dir() && !harness_dir.is_dir() && !legacy_auto_dir.is_dir() {
        return Err(format!(
            "work dir malformed: harness build directory '{}' (or harness layout '{}') not found",
            build_dir.display(),
            harness_dir.display()
        ));
    }

    // For the AFL++ engine, prefer the AFL-instrumented binary (built by
    // `govfuzz build --c-engine afl++`). Fall back to `main` so that
    // legacy workflows where the user manually copied a single binary
    // continue to work. The `<work>/harnesses/<id>/` layout is produced by
    // `govfuzz auto` (try_run_c_make_build_with_extras) which builds
    // in-place; check it as well so the auto attempt loop can locate
    // the binary it just built.
    let candidates: Vec<PathBuf> = match engine {
        FuzzEngine::AflPlusPlus => vec![
            build_dir.join("main_afl"),
            build_dir.join("main_afl.exe"),
            build_dir.join("main"),
            build_dir.join("main.exe"),
            harness_dir.join("main_afl"),
            harness_dir.join("main_afl.exe"),
            harness_dir.join("main"),
            harness_dir.join("main.exe"),
            legacy_auto_dir.join("main_afl"),
            legacy_auto_dir.join("main_afl.exe"),
            legacy_auto_dir.join("main"),
            legacy_auto_dir.join("main.exe"),
        ],
        FuzzEngine::Builtin => vec![
            build_dir.join("main"),
            build_dir.join("main.exe"),
            build_dir.join("obj").join("main"),
            build_dir.join("obj").join("main.exe"),
            harness_dir.join("main"),
            harness_dir.join("main.exe"),
            legacy_auto_dir.join("main"),
            legacy_auto_dir.join("main.exe"),
        ],
    };

    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "work dir malformed: no built harness executable found under {}, {}, or {}",
        build_dir.display(),
        harness_dir.display(),
        legacy_auto_dir.display()
    ))
}

fn write_run_summary(work_dir: &Path, summary: &FuzzRunSummary) -> Result<(), String> {
    let runs_dir = work_dir.join("fuzz_runs");
    fs::create_dir_all(&runs_dir).map_err(|error| {
        format!(
            "create fuzz run directory '{}': {error}",
            runs_dir.display()
        )
    })?;
    let json = serde_json::to_string_pretty(summary)
        .map_err(|error| format!("render fuzz run summary: {error}"))?;
    let latest = runs_dir.join(format!("{}-latest.json", summary.harness_id));
    fs::write(&latest, format!("{json}\n"))
        .map_err(|error| format!("write fuzz run summary '{}': {error}", latest.display()))
}

fn temp_event_path(work_dir: &Path) -> Result<PathBuf, String> {
    let events_dir = work_dir.join("events");
    fs::create_dir_all(&events_dir).map_err(|error| {
        format!(
            "create events directory '{}': {error}",
            events_dir.display()
        )
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Ok(events_dir.join(format!("fuzz-events-{}-{nonce}.bin", std::process::id())))
}

fn absolutize(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

/// Free-growth ceiling for the `auto` "auto" mode: adaptive length control grows the
/// effective length up to here WITHOUT needing to prove productivity (covers the vast
/// majority of "large object" formats — images, documents, configs, small firmware).
pub(crate) const AUTO_SOFT_CEILING: usize = 1024 * 1024;
/// Hard ceiling for the `auto` "auto" mode: growth PAST [`AUTO_SOFT_CEILING`] toward
/// this only continues while it keeps producing new coverage (genuinely large targets
/// like firmware/video), so a small-format target is never grown here pointlessly.
pub(crate) const AUTO_MAX_LEN_CEILING: usize = 64 * 1024 * 1024;

/// Resolve the per-target hard max input length for the `auto` path from the
/// `GOVFUZZ_MAX_LEN` env it sets: `auto` uses the adaptive ceiling (and never truncates
/// a larger seed), a number is a fixed cap, and unset keeps the fixed default (so
/// non-auto callers and tests are unchanged). `largest_seed` is the largest seed's
/// byte length, so even a huge sample is honored rather than truncated.
pub(crate) fn resolve_env_max_len(largest_seed: usize) -> usize {
    resolve_max_len_spec(
        std::env::var("GOVFUZZ_MAX_LEN").ok().as_deref(),
        largest_seed,
    )
}

/// Pure resolution of a max-len spec (`None`/`"auto"`/a number) against the largest
/// seed, split out so it is testable without touching process env.
fn resolve_max_len_spec(spec: Option<&str>, largest_seed: usize) -> usize {
    match spec {
        Some(spec) if spec.eq_ignore_ascii_case("auto") => AUTO_MAX_LEN_CEILING.max(largest_seed),
        Some(spec) => spec
            .parse::<usize>()
            .ok()
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_LEN),
        None => DEFAULT_MAX_LEN,
    }
}

/// Resolve the per-exec timeout for the `auto` path from the `GOVFUZZ_EXEC_TIMEOUT`
/// env (milliseconds) it sets; `None` keeps the engine's default (`PER_INPUT_TIMEOUT`).
pub(crate) fn resolve_env_timeout() -> Option<Duration> {
    std::env::var("GOVFUZZ_EXEC_TIMEOUT")
        .ok()
        .and_then(|ms| ms.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
}

pub(crate) fn parse_duration(value: &str) -> Result<Duration, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("duration must not be empty".to_owned());
    }
    let (number, multiplier) = match trimmed.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'm') | Some(b'M') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b'h') | Some(b'H') => (&trimmed[..trimmed.len() - 1], 60 * 60),
        Some(b'0'..=b'9') => (trimmed, 1),
        _ => return Err(format!("invalid duration '{value}'")),
    };
    let amount = number
        .parse::<u64>()
        .map_err(|error| format!("invalid duration '{value}': {error}"))?;
    Ok(Duration::from_secs(amount.saturating_mul(multiplier)))
}

fn parse_worker_count(value: &str) -> Result<FuzzWorkerCount, String> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(FuzzWorkerCount::Auto);
    }
    let workers = value
        .parse::<u32>()
        .map_err(|error| format!("invalid worker count '{value}': {error}"))?;
    if workers == 0 {
        return Err("worker count must be at least 1".to_owned());
    }
    Ok(FuzzWorkerCount::Fixed(workers))
}

#[cfg(all(test, unix))]
mod signal_classification_tests {
    use super::is_input_rejection;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn only_memory_safety_signals_are_crashes_benign_signals_are_rejections() {
        // A wait-status terminated by signal N is encoded with N in the low 7 bits.
        let by_signal = |sig: i32| ExitStatus::from_raw(sig);

        // Genuine memory-safety crash signals -> NOT a rejection (surface as GF-210).
        for sig in [
            4,  /*ILL*/
            7,  /*BUS*/
            8,  /*FPE*/
            11, /*SEGV*/
        ] {
            assert!(
                !is_input_rejection(&by_signal(sig)),
                "signal {sig} is a genuine crash and must not be treated as a rejection",
            );
        }

        // Benign / external / assert-idiom signals -> rejections (never a GF-210).
        // SIGPIPE (13) is the regression under test: a closed progress/stats pipe
        // killed the harness, govfuzz reported a phantom high-severity "reachable
        // crash" on a valid glTF that exits 0 on replay.
        for sig in [
            6,  // SIGABRT — assert()/abort() idiom
            13, // SIGPIPE — wrote to a closed pipe (plumbing, not a target bug)
            15, // SIGTERM — external termination
            2,  // SIGINT
            1,  // SIGHUP
            14, // SIGALRM — timeout path, not a code defect
        ] {
            assert!(
                is_input_rejection(&by_signal(sig)),
                "signal {sig} is benign/external and must be a rejection, not a crash",
            );
        }

        // A plain non-zero exit code (error return on malformed input) -> rejection.
        assert!(
            is_input_rejection(&ExitStatus::from_raw(1 << 8)),
            "a non-signal error exit is an input rejection",
        );
    }

    #[test]
    fn windows_crash_sentinel_exit_is_a_crash_not_a_rejection() {
        // Under wine a guest fault carries NO POSIX signal; the driver's vectored
        // exception handler reports it via the GOVFUZZ_WIN_CRASH_EXIT exit code.
        // That code must classify as a crash; any other nonzero exit stays a
        // rejection.
        let crash = ExitStatus::from_raw(super::GOVFUZZ_WIN_CRASH_EXIT << 8);
        assert_eq!(crash.code(), Some(super::GOVFUZZ_WIN_CRASH_EXIT));
        assert!(
            !is_input_rejection(&crash),
            "the Windows crash sentinel exit must be a crash, not a rejection",
        );
        assert!(
            is_input_rejection(&ExitStatus::from_raw(2 << 8)),
            "an ordinary nonzero exit remains an input rejection",
        );
    }
}

#[cfg(test)]
mod engine_list_tests {
    use super::{parse_engine_list, read_bounded_head_tail, read_seed_file_prefix, FuzzEngine};

    #[test]
    fn diagnostic_capture_keeps_both_ends_under_a_fixed_bound() {
        let input: Vec<u8> = (0_u8..100).collect();
        let output = read_bounded_head_tail(input.as_slice(), 16);
        assert!(output.starts_with(&input[..8]));
        assert!(output.ends_with(&input[92..]));
        assert!(output
            .windows("diagnostic output truncated".len())
            .any(|window| window == b"diagnostic output truncated"));
        assert!(output.len() <= 16 + 64);
    }

    #[test]
    fn seed_file_reader_never_allocates_past_requested_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-seed.bin");
        std::fs::write(&path, vec![7_u8; 4096]).unwrap();
        let (bytes, original_len) = read_seed_file_prefix(&path, 32).unwrap();
        assert_eq!(original_len, 4096);
        assert_eq!(bytes, vec![7_u8; 32]);
    }

    #[test]
    fn parse_engine_list_dedupes_and_orders() {
        assert_eq!(
            parse_engine_list("builtin").unwrap(),
            vec![FuzzEngine::Builtin]
        );
        assert_eq!(
            parse_engine_list("afl++").unwrap(),
            vec![FuzzEngine::AflPlusPlus]
        );
        // order preserved, duplicates collapsed
        assert_eq!(
            parse_engine_list("builtin,afl++,builtin").unwrap(),
            vec![FuzzEngine::Builtin, FuzzEngine::AflPlusPlus]
        );
        // whitespace tolerated, order as written
        assert_eq!(
            parse_engine_list(" afl++ , builtin ").unwrap(),
            vec![FuzzEngine::AflPlusPlus, FuzzEngine::Builtin]
        );
        // synonyms map to afl++
        assert_eq!(
            parse_engine_list("afl").unwrap(),
            vec![FuzzEngine::AflPlusPlus]
        );
        assert!(parse_engine_list("").is_err());
        assert!(parse_engine_list("honggfuzz").is_err());
    }

    #[test]
    fn parse_afl_fuzzer_stats_reads_execs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("default");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("fuzzer_stats"),
            "start_time        : 1000\n\
             execs_done        : 443314\n\
             execs_per_sec     : 73873.50\n\
             cycles_done       : 2\n",
        )
        .unwrap();
        let (execs, per_sec) = super::parse_afl_fuzzer_stats(tmp.path());
        assert_eq!(execs, Some(443314));
        assert_eq!(per_sec, Some(73873.50));
        // Missing file -> (None, None), never a panic.
        let missing = tempfile::tempdir().unwrap();
        assert_eq!(super::parse_afl_fuzzer_stats(missing.path()), (None, None));
    }

    #[test]
    fn afl_programmatic_errors_without_main_afl() {
        // No main_afl (empty work dir) -> clear error, no panic. Confirms the
        // programmatic AFL entry fails closed for the attempt loop to handle.
        let tmp = tempfile::tempdir().unwrap();
        let result = super::run_afl_plus_plus_programmatic(
            tmp.path(),
            "H-NONE",
            vec![b"seed".to_vec()],
            Some(std::time::Duration::from_secs(1)),
            &[],
            actionability::RunMode::Reporting,
            2048,
            &[],
        );
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod dedup_seed_tests {
    use super::existing_finding_dedup_keys;

    #[test]
    fn seeds_sanitizer_cluster_and_oracle_keys_from_findings_dir() {
        // #35: a later cascade pass must reconstruct the dedup keys of findings a
        // prior pass already wrote, so it does not re-emit byte-identical findings.
        let work = tempfile::tempdir().unwrap();
        let findings = work.path().join("findings");
        // A sanitizer-crash finding (clustered).
        let c = findings.join("F-0001-aaaa");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(
            c.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0001-aaaa",
                "harness_id": "H-TEST",
                "rule_id": "GF-201",
                "cluster_key_full": "deadbeef",
                "cluster_fallback": false,
            }))
            .unwrap(),
        )
        .unwrap();
        // A fallback sanitizer-crash finding (keyed by rule).
        let f = findings.join("F-0002-bbbb");
        std::fs::create_dir_all(&f).unwrap();
        std::fs::write(
            f.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0002-bbbb",
                "harness_id": "H-TEST",
                "rule_id": "GF-210",
                "cluster_fallback": true,
            }))
            .unwrap(),
        )
        .unwrap();
        // An oracle-hit finding.
        let o = findings.join("F-0003-cccc");
        std::fs::create_dir_all(&o).unwrap();
        std::fs::write(
            o.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0003-cccc",
                "harness_id": "H-TEST",
                "rule_id": "GF-405",
                "oracle": { "name": "path-traversal", "api": "open" },
            }))
            .unwrap(),
        )
        .unwrap();

        let (clusters, oracles) = existing_finding_dedup_keys(work.path(), "H-TEST");
        assert!(clusters.contains(&"deadbeef".to_owned()));
        assert!(clusters.contains(&"rule:GF-210".to_owned()));
        assert!(oracles.contains(&"GF-405|path-traversal|open".to_owned()));
    }

    #[test]
    fn missing_findings_dir_yields_empty_seeds() {
        let work = tempfile::tempdir().unwrap();
        let (clusters, oracles) = existing_finding_dedup_keys(work.path(), "H-TEST");
        assert!(clusters.is_empty() && oracles.is_empty());
    }
}

#[cfg(test)]
mod entropic_tests {
    use super::{choose_entropic_index_pool, entropic_weight, PoolEntry};
    use fuzz_engine_builtin::MutationRng;

    #[test]
    fn entropic_weight_rises_with_energy_and_decays_with_selections() {
        // Baseline: no novelty, never selected.
        assert_eq!(entropic_weight(0, 0), 1024);
        // More coverage novelty -> strictly higher weight.
        assert_eq!(entropic_weight(4, 0), 5120);
        assert!(entropic_weight(4, 0) > entropic_weight(1, 0));
        // Repeated selection decays the weight (entropic back-off): a 4-energy
        // seed picked 4 times sinks back to the unselected baseline, and a
        // fresh seed eventually outweighs an over-mined one.
        assert_eq!(entropic_weight(4, 4), 1024);
        assert!(entropic_weight(0, 0) > entropic_weight(4, 9));
    }

    #[test]
    fn choose_entropic_index_favors_high_weight_seed() {
        // A far-rarer/under-explored seed (index 1) must be picked far more
        // often than a zero-novelty, heavily-mined one (index 0).
        let mut pool = vec![PoolEntry::seed(vec![0]), PoolEntry::seed(vec![1])];
        pool[0].energy = 0;
        pool[0].selections = 50;
        pool[1].energy = 100;
        pool[1].selections = 0;
        let mut rng = MutationRng::new(0xC0FFEE);
        let mut counts = [0usize; 2];
        for _ in 0..2000 {
            counts[choose_entropic_index_pool(&pool, &mut rng)] += 1;
        }
        assert!(
            counts[1] > counts[0] * 10,
            "entropic choice should strongly favor the rare seed: {counts:?}"
        );
    }
}

#[cfg(test)]
mod vp_tokens_tests {
    use super::read_vp_tokens;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_driver_value_profile_log() {
        // Layout the driver writes: [u32 cursor][ {u8 len}{len bytes} ... ].
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-vp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vp.shm");
        let mut body = Vec::new();
        for tok in [b"{".as_slice(), b"true", &[0x50, 0x4b, 0x03, 0x04]] {
            body.push(tok.len() as u8);
            body.extend_from_slice(tok);
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(body.len() as u32).to_ne_bytes()).unwrap();
        f.write_all(&body).unwrap();
        // Trailing zeroes (the driver sizes the file past the cursor) are ignored.
        f.write_all(&[0u8; 64]).unwrap();
        drop(f);

        let tokens = read_vp_tokens(&path);
        assert_eq!(
            tokens,
            vec![
                b"{".to_vec(),
                b"true".to_vec(),
                vec![0x50, 0x4b, 0x03, 0x04],
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_empty_log_yields_no_tokens() {
        assert!(read_vp_tokens(std::path::Path::new("/nonexistent/vp.shm")).is_empty());
    }
}

#[cfg(test)]
mod resolve_iterations_tests {
    use super::resolve_iterations;

    #[test]
    fn explicit_iterations_always_win() {
        assert_eq!(resolve_iterations(Some(10), false), 10);
        assert_eq!(resolve_iterations(Some(10), true), 10);
    }

    #[test]
    fn time_budget_without_explicit_iterations_runs_unbounded() {
        // The bug: a `--time` campaign was silently capped at the 256 default.
        assert_eq!(resolve_iterations(None, true), usize::MAX);
    }

    #[test]
    fn neither_falls_back_to_default() {
        assert_eq!(resolve_iterations(None, false), 256);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod coverage_tracker_tests {
    use super::{count_to_bucket, CoverageTracker, GOVFUZZ_COV_BITS};
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Set one bitmap byte (an "edge") the way the driver's coverage runtime would.
    // A write() to the file shares the page cache with the tracker's MAP_SHARED
    // mapping, so the change is visible to the reader.
    fn set_edge(path: &std::path::Path, offset: u64) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&[1u8]).unwrap();
        f.flush().unwrap();
    }

    // Write one edge's per-exec hit COUNT into the #420 count map the way the
    // driver's saturating increment would. Shares the page cache with the
    // tracker's MAP_SHARED count mapping, so the value is visible to the reader.
    fn set_count(path: &std::path::Path, offset: u64, value: u8) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&[value]).unwrap();
        f.flush().unwrap();
    }

    #[test]
    fn coverage_tracker_keeps_only_coverage_increasing_inputs() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cov-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("coverage.shm");
        let env = vec![("GOVFUZZ_COV_SHM".to_owned(), path.display().to_string())];

        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");
        // Empty bitmap: the first exec hit nothing new.
        assert!(!tracker.input_increased_coverage());

        // An input that lights two fresh edges is interesting (retained).
        set_edge(&path, 10);
        set_edge(&path, 4096);
        assert!(tracker.input_increased_coverage());

        // A redundant input (no new edges) is not retained.
        assert!(!tracker.input_increased_coverage());

        // One more new edge is interesting again.
        set_edge(&path, GOVFUZZ_COV_BITS as u64 - 1);
        assert!(tracker.input_increased_coverage());
        assert!(!tracker.input_increased_coverage());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // #420: the engine-side bucket table MUST stay identical to the canonical
    // `count_to_bucket` in crates/fuzz_engine/builtin/src/coverage.rs. This guards
    // against the two drifting apart (the layout-sync hazard called out in #420).
    #[test]
    fn count_to_bucket_matches_afl_log_buckets() {
        assert_eq!(count_to_bucket(0), 0);
        assert_eq!(count_to_bucket(1), 0);
        assert_eq!(count_to_bucket(2), 1);
        assert_eq!(count_to_bucket(3), 2);
        assert_eq!(count_to_bucket(4), 3);
        assert_eq!(count_to_bucket(7), 3);
        assert_eq!(count_to_bucket(8), 4);
        assert_eq!(count_to_bucket(15), 4);
        assert_eq!(count_to_bucket(16), 5);
        assert_eq!(count_to_bucket(31), 5);
        assert_eq!(count_to_bucket(32), 6);
        assert_eq!(count_to_bucket(127), 6);
        assert_eq!(count_to_bucket(128), 7);
        assert_eq!(count_to_bucket(255), 7);
        // Adjacent counts straddling a boundary differ; within a bucket match.
        assert_ne!(count_to_bucket(7), count_to_bucket(8));
        assert_eq!(count_to_bucket(5), count_to_bucket(6));
    }

    // #420 AC2: a per-input hit-count crossing into a higher AFL bucket
    // (1->2->4->8 ...) registers as novelty exactly once; noise WITHIN a bucket
    // (4->5->6->7, all bucket 3) does not. This is the loop/recursion-depth signal
    // edge-presence cannot see. The engine zeroes the count map before each exec
    // (modelled by `zero_counts`), so each call observes one exec's counts.
    #[test]
    fn coverage_tracker_buckets_register_transitions_not_within_bucket_noise() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cov-cnt-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cov = dir.join("coverage.shm");
        let cnt = dir.join("coverage_cnt.shm");
        let env = vec![
            ("GOVFUZZ_COV_SHM".to_owned(), cov.display().to_string()),
            ("GOVFUZZ_COV_CNT_SHM".to_owned(), cnt.display().to_string()),
        ];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps both maps");
        let edge = 100u64; // arbitrary instrumented edge

        // The engine zeroes the count map, the harness writes this exec's counts,
        // the engine reads bucket novelty. First time edge 100 reaches each bucket
        // is novel; a repeat within the same bucket is not.
        let exec = |tracker: &mut CoverageTracker, count: u8| -> bool {
            tracker.zero_counts();
            set_count(&cnt, edge, count);
            tracker.input_grew_buckets()
        };

        // Bucket transitions 1->2->4->8 each register exactly once.
        assert!(
            exec(&mut tracker, 1),
            "count 1 (bucket 0) is novel the first time"
        );
        assert!(
            !exec(&mut tracker, 1),
            "count 1 again is within-bucket noise"
        );
        assert!(exec(&mut tracker, 2), "count 2 crosses into bucket 1");
        assert!(
            !exec(&mut tracker, 2),
            "count 2 again is within-bucket noise"
        );
        assert!(exec(&mut tracker, 4), "count 4 crosses into bucket 3");
        // Noise WITHIN bucket 3 (4..=7) does not register.
        assert!(!exec(&mut tracker, 5), "count 5 stays in bucket 3");
        assert!(!exec(&mut tracker, 6), "count 6 stays in bucket 3");
        assert!(!exec(&mut tracker, 7), "count 7 stays in bucket 3");
        // Crossing into bucket 4 (8..=15) registers again.
        assert!(exec(&mut tracker, 8), "count 8 crosses into bucket 4");
        assert!(!exec(&mut tracker, 15), "count 15 stays in bucket 4");
        // A deeper loop crossing into the top bucket registers once more.
        assert!(exec(&mut tracker, 200), "count 200 crosses into bucket 7");
        assert!(!exec(&mut tracker, 255), "count 255 stays in bucket 7");

        // Re-visiting a LOWER, already-seen bucket is not novel (virgin is a
        // per-edge bitmask of every bucket ever seen, not a high-water mark only).
        assert!(
            !exec(&mut tracker, 1),
            "bucket 0 was already seen for this edge"
        );

        // A DIFFERENT edge is tracked independently: its first hit is novel.
        tracker.zero_counts();
        set_count(&cnt, 7777, 9); // edge 7777, bucket 4
        assert!(
            tracker.input_grew_buckets(),
            "a fresh edge's first bucket is novel regardless of other edges"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Write one compare site's per-exec MAX leading-byte-match count into the #421
    // comparison-progress map the way the driver's `max`-write would. Shares the
    // page cache with the tracker's MAP_SHARED progress mapping.
    fn set_progress(path: &std::path::Path, site: u64, value: u8) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(site)).unwrap();
        f.write_all(&[value]).unwrap();
        f.flush().unwrap();
    }

    // #421 laf-intel: an input that matches MORE leading bytes of a compare than
    // any prior input (a higher progress LEVEL at that site) registers as novel
    // coverage exactly once — the gradient that lets the fuzzer hill-climb a
    // multi-byte gate one byte at a time. A re-seen level is not novel; progress 0
    // (no leading-byte match) never registers; levels cap at 7; sites are tracked
    // independently. The engine zeroes the progress map before each exec (modelled
    // by `zero_progress`), so each call observes one exec's per-site progress.
    #[test]
    fn coverage_tracker_progress_registers_new_leading_match_levels() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cmpp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cov = dir.join("coverage.shm");
        let cmpp = dir.join("cmp_progress.shm");
        let env = vec![
            ("GOVFUZZ_COV_SHM".to_owned(), cov.display().to_string()),
            (
                "GOVFUZZ_CMP_PROGRESS_SHM".to_owned(),
                cmpp.display().to_string(),
            ),
        ];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps progress map");
        let site = 100u64; // arbitrary hashed compare site

        let exec = |tracker: &mut CoverageTracker, progress: u8| -> bool {
            tracker.zero_progress();
            set_progress(&cmpp, site, progress);
            tracker.input_advanced_comparisons()
        };

        // Matching one leading byte is novel the first time; the same level again
        // is not (no new gradient).
        assert!(exec(&mut tracker, 1), "first 1-byte leading match is novel");
        assert!(
            !exec(&mut tracker, 1),
            "same match level again is not novel"
        );
        // Matching deeper (2, then 3 leading bytes) each registers once.
        assert!(exec(&mut tracker, 2), "2-byte leading match is novel");
        assert!(exec(&mut tracker, 3), "3-byte leading match is novel");
        // Re-seeing an intermediate level already observed is not novel.
        assert!(!exec(&mut tracker, 2), "level 2 was already seen");
        // Progress 0 (no leading-byte match) is indistinguishable from "site not
        // hit" and never registers novelty.
        assert!(
            !exec(&mut tracker, 0),
            "zero leading-byte match is not progress"
        );
        // Levels saturate at 7 (an 8-byte compare matching all 8 passes the gate
        // and lights a real edge): 7 is novel once, and a >7 value maps to 7.
        assert!(exec(&mut tracker, 7), "level 7 is novel the first time");
        assert!(!exec(&mut tracker, 8), "level >7 caps to 7, already seen");

        // A DIFFERENT compare site is tracked independently.
        tracker.zero_progress();
        set_progress(&cmpp, 7777, 4);
        assert!(
            tracker.input_advanced_comparisons(),
            "a fresh site's first leading match is novel regardless of other sites"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // #421: the comparison-progress channel is inert (always false) when its map
    // is absent (no GOVFUZZ_CMP_PROGRESS_SHM — the flag is off, or the Ada
    // trace-pc path), rather than fabricating novelty.
    #[test]
    fn coverage_tracker_without_progress_map_is_inert() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cmpp-absent-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cov = dir.join("coverage.shm");
        // No GOVFUZZ_CMP_PROGRESS_SHM: the progress channel must stay inert.
        let env = vec![("GOVFUZZ_COV_SHM".to_owned(), cov.display().to_string())];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");

        assert!(!tracker.input_advanced_comparisons());
        tracker.zero_progress(); // no panic, no effect
        assert!(!tracker.input_advanced_comparisons());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // #420: edge-PRESENCE behavior is byte-for-byte unchanged when the count map
    // is absent (no GOVFUZZ_COV_CNT_SHM — the Ada trace-pc path), and the bucket
    // channel is inert (always false) rather than fabricating novelty.
    #[test]
    fn coverage_tracker_without_count_map_is_presence_only() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-cov-nocnt-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cov = dir.join("coverage.shm");
        // No GOVFUZZ_COV_CNT_SHM: the bucket channel must stay inert.
        let env = vec![("GOVFUZZ_COV_SHM".to_owned(), cov.display().to_string())];
        let mut tracker = CoverageTracker::new(&env).expect("tracker maps the bitmap");

        // Bucket channel is a no-op without a count map.
        assert!(!tracker.input_grew_buckets());
        tracker.zero_counts(); // no panic, no effect

        // Presence still works exactly as before.
        set_edge(&cov, 42);
        assert!(tracker.input_increased_coverage());
        assert!(!tracker.input_increased_coverage());
        // Still inert after presence growth.
        assert!(!tracker.input_grew_buckets());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod frame_tests {
    use super::write_input_frame;

    #[test]
    fn write_input_frame_prepends_little_endian_length() {
        let mut out = Vec::new();
        write_input_frame(&mut out, b"abc").unwrap();
        assert_eq!(out, vec![3, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn write_input_frame_handles_empty() {
        let mut out = Vec::new();
        write_input_frame(&mut out, b"").unwrap();
        assert_eq!(out, vec![0, 0, 0, 0]);
    }
}

#[cfg(test)]
mod parse_sanitizer_args_tests {
    use super::parse_sanitizer_args;
    use multicore_fuzz::{Sanitizer, SanitizerSelection};

    fn parse(values: &[&str]) -> Result<SanitizerSelection, String> {
        parse_sanitizer_args(&values.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn empty_is_default() {
        assert_eq!(parse(&[]).unwrap(), SanitizerSelection::Default);
    }

    #[test]
    fn none_is_standalone_none() {
        assert_eq!(parse(&["none"]).unwrap(), SanitizerSelection::None);
        assert_eq!(parse(&["NONE"]).unwrap(), SanitizerSelection::None);
    }

    #[test]
    fn none_mixed_with_a_sanitizer_is_an_error() {
        // `none` is contradictory with a real sanitizer — reject, don't silently
        // pick one (#434).
        assert!(parse(&["none", "asan"]).is_err());
        assert!(parse(&["asan", "none"]).is_err());
    }

    #[test]
    fn set_dedups_and_preserves_order() {
        assert_eq!(
            parse(&["asan", "ubsan", "asan"]).unwrap(),
            SanitizerSelection::Set(vec![Sanitizer::Asan, Sanitizer::Ubsan])
        );
    }

    #[test]
    fn unknown_name_is_an_error_mentioning_none() {
        let err = parse(&["garbage"]).unwrap_err();
        assert!(err.contains("none"), "help should list `none`: {err}");
    }

    #[test]
    fn none_arms_no_runtime_env_and_overrides_build() {
        let sel = parse(&["none"]).unwrap();
        assert!(sel.runtime_set().is_empty());
        assert!(sel.overrides_build());
    }
}

#[cfg(test)]
mod fuzz_child_env_tests {
    use super::apply_fuzz_child_env_overrides;

    #[test]
    fn neutralizes_debuginfod_for_every_fuzz_child() {
        // A fuzz child must never make a network debuginfo fetch in the hot loop:
        // ASan's crash symbolizer would consult the system debuginfod server and
        // a crash-heavy target blows past the per-target wall cap (182s regression).
        let mut env = vec![("GOVFUZZ_COV_SHM".to_owned(), "/tmp/x".to_owned())];
        apply_fuzz_child_env_overrides(&mut env);
        assert_eq!(
            env.iter().find(|(k, _)| k == "DEBUGINFOD_URLS"),
            Some(&("DEBUGINFOD_URLS".to_owned(), String::new()))
        );
    }

    #[test]
    fn respects_an_explicit_caller_debuginfod_value() {
        let mut env = vec![("DEBUGINFOD_URLS".to_owned(), "https://example/".to_owned())];
        apply_fuzz_child_env_overrides(&mut env);
        // Exactly one entry, unchanged — no silent override of an explicit value.
        let hits: Vec<_> = env.iter().filter(|(k, _)| k == "DEBUGINFOD_URLS").collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "https://example/");
    }
}

#[cfg(test)]
mod auto_path_tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-find-{n}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn sanitizer_report(rule_id: &'static str, frames: Vec<&str>) -> corpus::SanitizerReport {
        corpus::SanitizerReport {
            sanitizer: corpus::Sanitizer::AddressSanitizer,
            kind: "heap-buffer-overflow".to_owned(),
            rule_id,
            stack: frames
                .into_iter()
                .map(|f| corpus::sanitizer::StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "boom".to_owned(),
        }
    }

    #[test]
    fn sanitizer_cluster_dedup_emits_once_per_root_cause() {
        let mut seen = HashMap::new();
        // Same target frames, different scaffolding -> one cluster.
        let a1 = sanitizer_report(
            "GF-201",
            vec!["real_parse", "real_dispatch", "LLVMFuzzerTestOneInput"],
        );
        let a2 = sanitizer_report("GF-201", vec!["real_parse", "real_dispatch", "main"]);
        // Different target frame -> a second cluster.
        let b = sanitizer_report("GF-201", vec!["other_fn", "LLVMFuzzerTestOneInput"]);

        assert!(first_of_sanitizer_cluster(&mut seen, &a1));
        assert!(!first_of_sanitizer_cluster(&mut seen, &a2));
        assert!(first_of_sanitizer_cluster(&mut seen, &b));
        // Two clusters, three total hits.
        assert_eq!(seen.len(), 2);
        assert_eq!(seen.values().sum::<usize>(), 3);
    }

    #[test]
    #[cfg(unix)]
    fn sanitizer_crash_reproduces_true_for_crashing_false_for_clean() {
        use std::os::unix::fs::PermissionsExt;
        let work = tmpdir();

        // A fake C harness that reports an ASan heap-buffer-overflow (rule_id
        // GF-201) on every input and exits non-zero — a reproducing crash.
        let crashing = work.join("crashing");
        fs::write(
            &crashing,
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&crashing, fs::Permissions::from_mode(0o755)).unwrap();

        // A clean harness that never crashes.
        let clean = work.join("clean");
        fs::write(&clean, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&clean, fs::Permissions::from_mode(0o755)).unwrap();

        let report = sanitizer_report("GF-201", vec!["real_parse"]);

        let crashing_runner = replay_min::HarnessRunner::direct(crashing);
        assert!(sanitizer_crash_reproduces(
            &crashing_runner,
            &work,
            b"x",
            &report,
            &[],
            Duration::from_secs(5),
            0,
        ));

        let clean_runner = replay_min::HarnessRunner::direct(clean);
        assert!(!sanitizer_crash_reproduces(
            &clean_runner,
            &work,
            b"x",
            &report,
            &[],
            Duration::from_secs(5),
            0,
        ));
    }

    #[cfg(unix)]
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    // #15: a non-zero exit / fatal signal with NO sanitizer report is the target
    // REJECTING the input (assert/abort/non-zero-return on malformed bytes). It
    // must be a clean no-finding run (so the fuzz pass keeps exploring), NOT a hard
    // error that aborts the whole pass.
    #[test]
    #[cfg(unix)]
    fn nonzero_exit_without_sanitizer_is_input_rejection_not_error() {
        let work = tmpdir();
        let h = write_script(&work, "reject_exit.sh", "#!/bin/sh\nexit 1\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"bad-input",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("a non-zero exit must be a rejection (Ok), not a hard error (Err)");
        assert!(run.sanitizer.is_none(), "rejection must not be a finding");
        assert!(run.testcases.is_empty());
        assert!(run.rejected, "flagged rejected for the all-reject signal");
    }

    #[test]
    #[cfg(unix)]
    fn fatal_abort_signal_without_sanitizer_is_input_rejection() {
        // The cute_aseprite case: assert() -> abort() -> SIGABRT, no ASan report.
        let work = tmpdir();
        let h = write_script(&work, "reject_abort.sh", "#!/bin/sh\nkill -ABRT $$\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("an assert/abort on bad input must be a rejection, not a pass-aborting error");
        assert!(run.sanitizer.is_none());
        assert!(run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn fatal_signal_without_sanitizer_report_is_a_gf210_crash_finding() {
        // A SIGSEGV (or SIGILL/SIGBUS/SIGFPE) with no sanitizer report is a
        // reachable crash on this input — NOT a rejection, and NOT a hard error
        // that aborts the pass. It is recorded as a GF-210 finding so it surfaces
        // and the cascade keeps fuzzing (the cute_tiled empty-seed-crash blocker).
        let work = tmpdir();
        let h = write_script(&work, "segv.sh", "#!/bin/sh\nkill -SEGV $$\n");
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("a fatal signal must be a finding (Ok), not a pass-aborting Err");
        let report = run
            .sanitizer
            .expect("fatal signal must produce a synthesized crash report");
        assert_eq!(report.rule_id, "GF-210", "fatal-signal crash is GF-210");
        assert!(!run.rejected, "a crash is not a rejection");
        assert!(
            report.message.contains("SIGSEGV"),
            "names the signal: {}",
            report.message
        );
        // SIGILL (the cute_tiled empty-seed case) is also a GF-210 finding.
        let h2 = write_script(&work, "ill.sh", "#!/bin/sh\nkill -ILL $$\n");
        let run2 = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h2),
            &work,
            b"",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("SIGILL must be a finding too");
        assert_eq!(run2.sanitizer.expect("report").rule_id, "GF-210");
    }

    #[test]
    #[cfg(unix)]
    fn run_harness_nonzero_exit_without_sanitizer_is_rejection() {
        // Exercises the event-log per-spawn path (run_harness) too.
        let work = tmpdir();
        let h = write_script(&work, "reject_harness.sh", "#!/bin/sh\nexit 3\n");
        let run = run_harness(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("run_harness must treat a non-zero exit without a sanitizer report as a rejection");
        assert!(run.sanitizer.is_none());
        assert!(run.rejected);
    }

    #[test]
    #[cfg(unix)]
    fn genuine_sanitizer_crash_still_surfaces_after_rejection_change() {
        // Real memory bugs must still become findings: an ASan report on a non-zero
        // exit yields a sanitizer HarnessRun, not a silent rejection.
        let work = tmpdir();
        let h = write_script(
            &work,
            "asan.sh",
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        );
        let run = run_c_libfuzzer_single_input(
            &replay_min::HarnessRunner::direct(h),
            &work,
            b"x",
            &[],
            Duration::from_secs(5),
            0,
        )
        .expect("ok");
        assert!(
            run.sanitizer.is_some(),
            "an ASan report must still surface as a sanitizer finding"
        );
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_rejects_every_input_is_built_not_fuzzed() {
        // #15 part B: a harness that exits non-zero on EVERY input never actually
        // fuzzed — the run must Err (so the auto loop reports built-not-fuzzed),
        // not return a clean (but empty) success that masks a gate/seed/harness
        // problem.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-ALLREJECT", "#!/bin/sh\nexit 1\n");
        let result = run_one_target_programmatic(
            &work_dir,
            "H-ALLREJECT",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        );
        let err = result.expect_err("all-reject must not report a clean fuzz");
        assert!(
            err.contains("rejected all") && err.contains("cannot fuzz"),
            "built-not-fuzzed reason must be explicit: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_crashes_on_every_input_keeps_its_findings() {
        // #477: a target where EVERY input crashes (a callback struct cast from raw
        // bytes; a parser that aborts on malformed input) rejects all executions AND
        // emits real crash findings. The reject-all guard must NOT discard them by
        // returning Err — a run that produced any finding produced signal, so it must
        // return Ok with the findings, not downgrade to a finding-less `Built`.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-ALLCRASH",
            "#!/bin/sh\n>&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1'\n\
             >&2 echo '    #0 0x1 in real_parse /src/p.c:9'\nexit 1\n",
        );
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-ALLCRASH",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a crash on every input is signal, not an all-reject failure");
        assert!(
            !summary.findings.is_empty(),
            "the crash findings must survive into the summary"
        );
    }

    #[test]
    #[cfg(unix)]
    fn harness_that_runs_clean_fuzzes_normally() {
        // Contrast to the all-reject case: a harness that exits 0 fuzzes fine.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-CLEAN15", "#!/bin/sh\nexit 0\n");
        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CLEAN15",
            vec![b"seed".to_vec()],
            5,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .expect("a clean harness must fuzz, not be flagged built-not-fuzzed");
        assert!(summary.executions > 0);
    }

    #[test]
    #[cfg(unix)]
    fn file_creating_harness_writes_into_scratch_not_launch_cwd() {
        use std::os::unix::fs::PermissionsExt;
        let work = tmpdir();
        let scratch = ensure_harness_scratch(&work).unwrap();
        // A fake harness that, like a fuzzed archive/stream writer fed fuzz
        // bytes, creates a file with a fuzz-controlled name in its CWD.
        let fake = work.join("fake_harness.sh");
        fs::write(&fake, "#!/bin/sh\ntouch 'junk-from-fuzz=0644'\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let input = work.join("in.bin");
        fs::write(&input, b"x").unwrap();
        let launch_cwd = std::env::current_dir().unwrap();

        let _ = run_with_timeout(
            &fake,
            &input,
            Duration::from_secs(5),
            &[],
            &scratch,
            0,
            None,
        );

        assert!(
            scratch.join("junk-from-fuzz=0644").is_file(),
            "a file-creating harness must write into the run's fuzz_scratch dir"
        );
        assert!(
            !launch_cwd.join("junk-from-fuzz=0644").exists(),
            "a file-creating harness must not pollute the directory govfuzz was launched from"
        );
    }

    #[test]
    #[cfg(unix)]
    fn hanging_event_log_harness_is_reaped_at_per_input_timeout() {
        use std::os::unix::fs::PermissionsExt;
        // A non-C harness (no main.c/main.cpp in the dir, so it takes the
        // event-log per-spawn lane) that hangs forever, ignoring stdin. Before
        // the fix `run_harness` blocked in `wait_with_output` indefinitely —
        // RLIMIT_CPU never fires for a 0%-CPU sleep — hanging the whole engine.
        // Now `per_input_timeout` is a wall-clock bound. `exec` so the process
        // we spawn (and kill) IS the sleep.
        let work = tmpdir();
        let hang = work.join("hang.sh");
        fs::write(&hang, "#!/bin/sh\nexec sleep 3600\n").unwrap();
        fs::set_permissions(&hang, fs::Permissions::from_mode(0o755)).unwrap();
        let runner = replay_min::HarnessRunner::direct(hang);

        let started = Instant::now();
        let run = run_harness(&runner, &work, b"input", &[], Duration::from_secs(1), 0)
            .expect("a hung harness must be reaped and return a clean run, not block or error");
        let elapsed = started.elapsed();

        // With the fix this returns in ~1s; without it the test would hang for
        // ~an hour. Generous bound to stay non-flaky under load.
        assert!(
            elapsed < Duration::from_secs(30),
            "engine must recover within the per-input timeout, took {elapsed:?}"
        );
        // A timed-out (hung) input yields no events and no finding.
        assert!(
            run.events.is_empty() && run.sanitizer.is_none(),
            "a reaped hung harness must produce a no-event run"
        );
    }

    #[test]
    fn find_harness_executable_finds_harnesses_layout_binary() {
        let root = tmpdir();
        let auto_main = root.join("harnesses/H-X/main");
        fs::create_dir_all(auto_main.parent().unwrap()).unwrap();
        fs::write(&auto_main, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::Builtin).unwrap();
        assert_eq!(p, auto_main);
    }

    #[test]
    fn find_harness_executable_finds_harnesses_layout_afl_binary() {
        let root = tmpdir();
        let auto_main = root.join("harnesses/H-X/main_afl");
        fs::create_dir_all(auto_main.parent().unwrap()).unwrap();
        fs::write(&auto_main, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::AflPlusPlus).unwrap();
        assert_eq!(p, auto_main);
    }

    #[test]
    fn find_harness_executable_still_finds_legacy_build_dir() {
        let root = tmpdir();
        let legacy = root.join("build/H-X/main");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, b"\x7fELF").unwrap();
        let p = find_harness_executable(&root, "H-X", FuzzEngine::Builtin).unwrap();
        assert_eq!(p, legacy);
    }

    #[test]
    fn generated_dictionary_loader_prefers_harnesses_layout() {
        let root = tmpdir();
        let auto_dict = root.join("harnesses/H-X/dictionary.txt");
        let generated_dict = root.join("generated_harnesses/H-X/dictionary.txt");
        fs::create_dir_all(auto_dict.parent().unwrap()).unwrap();
        fs::create_dir_all(generated_dict.parent().unwrap()).unwrap();
        fs::write(&auto_dict, "\"AUTO\\nTOKEN\"\n").unwrap();
        fs::write(&generated_dict, "\"LEGACY\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, auto_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"AUTO\nTOKEN".to_vec()]);
    }

    #[test]
    fn generated_dictionary_loader_finds_legacy_generated_harness_layout() {
        let root = tmpdir();
        let generated_dict = root.join("generated_harnesses/H-X/dictionary.txt");
        fs::create_dir_all(generated_dict.parent().unwrap()).unwrap();
        fs::write(&generated_dict, "\"GIF89a\"\n\"MODE_FAST\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, generated_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"GIF89a".to_vec(), b"MODE_FAST".to_vec()]);
    }

    #[test]
    fn generated_dictionary_loader_finds_fake_corba_idl_dictionary() {
        let root = tmpdir();
        let fake_corba_dict = root.join("fake_corba/dictionary.txt");
        fs::create_dir_all(fake_corba_dict.parent().unwrap()).unwrap();
        fs::write(&fake_corba_dict, "\"READY\"\n\"MODE_FAST\"\n").unwrap();

        let path = find_generated_dictionary(&root, "H-X").unwrap();
        assert_eq!(path, fake_corba_dict);
        let tokens = load_generated_dictionary_tokens(&root, "H-X").unwrap();
        assert_eq!(tokens, vec![b"READY".to_vec(), b"MODE_FAST".to_vec()]);
    }

    #[test]
    fn dictionary_token_may_contain_equals_sign() {
        // printf format strings lifted from real source routinely contain `=`.
        // The token value must survive verbatim and not be split on the `=`.
        let token = parse_afl_dictionary_line("\"len of TF\\t = %d\"")
            .expect("token with '=' parses")
            .expect("token is not a comment/blank");
        assert_eq!(token, b"len of TF\t = %d");
    }

    #[test]
    fn dictionary_named_token_strips_prefix_but_keeps_equals_in_value() {
        let token = parse_afl_dictionary_line("fmt@1=\"a = b\"")
            .expect("named token parses")
            .expect("token is not a comment/blank");
        assert_eq!(token, b"a = b");
    }

    #[test]
    fn malformed_dictionary_line_is_skipped_not_fatal() {
        // A generated dictionary must never abort the campaign: one bad line is
        // skipped and the valid tokens around it still load.
        let root = tmpdir();
        let dict = root.join("harnesses/H-Y/dictionary.txt");
        fs::create_dir_all(dict.parent().unwrap()).unwrap();
        fs::write(&dict, "\"good_one\"\nthis is not quoted\n\"good = two\"\n").unwrap();
        let tokens =
            load_generated_dictionary_tokens(&root, "H-Y").expect("loads despite bad line");
        assert_eq!(tokens, vec![b"good_one".to_vec(), b"good = two".to_vec()]);
    }

    #[test]
    fn len_control_grows_on_plateau_resets_on_new_and_caps_at_max() {
        // Disabled (0): never grows.
        assert_eq!(len_control_step(64, 4096, 0, 50, false), (64, 0));
        // Plateau below threshold: counter ticks, length held.
        assert_eq!(len_control_step(64, 4096, 100, 40, false), (64, 41));
        // Plateau reaches threshold: length doubles, counter resets.
        assert_eq!(len_control_step(64, 4096, 100, 99, false), (128, 0));
        // A new corpus signature resets the plateau without growing.
        assert_eq!(len_control_step(64, 4096, 100, 99, true), (64, 0));
        // Growth never exceeds the ceiling.
        assert_eq!(len_control_step(4000, 4096, 100, 99, false), (4096, 0));
    }

    #[test]
    fn resolve_max_len_spec_handles_auto_number_and_default() {
        // "auto" never truncates a larger seed and otherwise uses the adaptive ceiling.
        assert_eq!(resolve_max_len_spec(Some("auto"), 0), AUTO_MAX_LEN_CEILING);
        assert_eq!(
            resolve_max_len_spec(Some("AUTO"), 1024),
            AUTO_MAX_LEN_CEILING
        );
        let huge = AUTO_MAX_LEN_CEILING + 1;
        assert_eq!(resolve_max_len_spec(Some("auto"), huge), huge);
        // A number is a fixed cap; a bogus value falls back to the default.
        assert_eq!(resolve_max_len_spec(Some("65536"), 0), 65536);
        assert_eq!(resolve_max_len_spec(Some("0"), 0), DEFAULT_MAX_LEN);
        assert_eq!(resolve_max_len_spec(Some("nope"), 0), DEFAULT_MAX_LEN);
        // Unset keeps the historical default (no regression for non-auto callers).
        assert_eq!(resolve_max_len_spec(None, 999), DEFAULT_MAX_LEN);
    }

    #[test]
    fn len_control_holds_plateau_at_ceiling_for_the_adaptive_raise() {
        // At the ceiling the length is held, but the plateau counter is now HELD at
        // the threshold (not zeroed) so the loop can detect "stuck at ceiling" and
        // decide whether to raise it. Below the threshold it still just ticks.
        assert_eq!(len_control_step(4096, 4096, 100, 5, false), (4096, 6));
        assert_eq!(len_control_step(4096, 4096, 100, 99, false), (4096, 100));
        // Stuck at the ceiling: the counter is capped at the threshold, not unbounded.
        assert_eq!(len_control_step(4096, 4096, 100, 500, false), (4096, 100));
        // A new signature at the ceiling still clears the plateau.
        assert_eq!(len_control_step(4096, 4096, 100, 500, true), (4096, 0));
    }

    #[test]
    fn worker_passthrough_includes_rss_limit_only_when_set() {
        let mut args = fuzz_args_for_worker_passthrough(StructuredInputMode::Auto);
        args.rss_limit_mb = 0;
        assert!(!worker_passthrough_args(&args)
            .iter()
            .any(|a| a == "--rss-limit-mb"));
        args.rss_limit_mb = 2048;
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--rss-limit-mb" && pair[1] == "2048"));
    }

    #[test]
    fn worker_passthrough_includes_timeout_only_when_set() {
        let mut args = fuzz_args_for_worker_passthrough(StructuredInputMode::Auto);
        args.timeout = None;
        assert!(
            !worker_passthrough_args(&args)
                .iter()
                .any(|a| a == "--timeout"),
            "no --timeout passthrough when unset (workers use the default)"
        );
        args.timeout = Some(Duration::from_secs(30));
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--timeout" && pair[1] == "30s"));
    }

    #[test]
    fn worker_passthrough_includes_len_control() {
        let mut args = fuzz_args_for_worker_passthrough(StructuredInputMode::Auto);
        args.len_control = 7;
        let passthrough = worker_passthrough_args(&args);
        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--len-control" && pair[1] == "7"));
    }

    #[test]
    fn final_stats_line_reports_execs_rate_corpus_findings() {
        let line = format_final_stats(1000, 12, 988, 3, Duration::from_secs(2));
        assert!(line.contains("execs: 1000 (500/s)"), "{line}");
        assert!(line.contains("corpus: 12 new, 988 dup"), "{line}");
        assert!(line.contains("findings: 3"), "{line}");
        assert!(line.contains("elapsed: 2.0s"), "{line}");
    }

    #[test]
    fn mutator_config_honors_max_len() {
        assert_eq!(mutator_config(StructuredInputMode::Auto, 64).max_len, 64);
        assert_eq!(
            mutator_config(StructuredInputMode::Auto, DEFAULT_MAX_LEN).max_len,
            DEFAULT_MAX_LEN
        );
    }

    #[test]
    fn worker_passthrough_includes_max_len() {
        let mut args = fuzz_args_for_worker_passthrough(StructuredInputMode::Auto);
        args.max_len = 128;
        let passthrough = worker_passthrough_args(&args);
        assert!(
            passthrough
                .windows(2)
                .any(|pair| pair[0] == "--max-len" && pair[1] == "128"),
            "workers must inherit --max-len: {passthrough:?}"
        );
    }

    #[test]
    fn worker_passthrough_preserves_structured_input_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Record);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "record"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_json_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Json);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "json"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_xml_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Xml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "xml"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_key_value_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Kv);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "kv"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_url_encoded_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Url);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "url"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_multipart_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Multipart);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "multipart"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_csv_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Csv);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "csv"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_http_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Http);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "http"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_ini_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Ini);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "ini"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_toml_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Toml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "toml"));
    }

    #[test]
    fn worker_passthrough_preserves_structured_yaml_mode() {
        let args = fuzz_args_for_worker_passthrough(StructuredInputMode::Yaml);

        let passthrough = worker_passthrough_args(&args);

        assert!(passthrough
            .windows(2)
            .any(|pair| pair[0] == "--structured-inputs" && pair[1] == "yaml"));
    }

    #[test]
    fn runtrace_cursor_reads_only_appended_events() {
        let root = tmpdir();
        let log = root.join("runtrace.jsonl");
        fs::write(&log, "").unwrap();
        let mut cursor = RuntraceLogCursor::from_extra_env(&[(
            "GOVFUZZ_RUNTRACE_LOG".to_owned(),
            log.display().to_string(),
        )]);

        fs::write(
            &log,
            "{\"e\":\"open\",\"p\":\"../secret\",\"r\":-1,\"n\":2}\n",
        )
        .unwrap();
        let first = cursor.read_new_events();
        assert_eq!(first.len(), 1);
        assert!(matches!(
            &first[0],
            crate::auto::runtrace::RuntraceEvent::FileMissing { path, .. }
                if path == "../secret"
        ));

        assert!(cursor.read_new_events().is_empty());
        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"{\"e\":\"getenv\",\"n\":\"ACME_HOME\",\"r\":null}\n")
            .unwrap();
        let second = cursor.read_new_events();
        assert_eq!(
            second,
            vec![crate::auto::runtrace::RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            }]
        );
    }

    #[test]
    #[cfg(unix)]
    fn builtin_fuzz_emits_oracle_finding_from_runtrace_event() {
        use std::os::unix::fs::PermissionsExt;

        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        let harness_id = "H-ORACLE";
        let harness_dir = work_dir.join("build").join(harness_id);
        fs::create_dir_all(&harness_dir).unwrap();
        let harness = harness_dir.join("main");
        fs::write(
            &harness,
            "#!/bin/sh\n\
             input=$(cat)\n\
             if [ -n \"$GOVFUZZ_RUNTRACE_LOG\" ]; then\n\
               printf '{\"e\":\"open\",\"p\":\"%s\",\"r\":-1,\"n\":2}\\n' \"$input\" >> \"$GOVFUZZ_RUNTRACE_LOG\"\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&harness).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&harness, perms).unwrap();
        let runtrace_log = root.join("runtrace.jsonl");

        // The harness is a shell subprocess. Under heavy parallel test load (the
        // full `cargo test --workspace` runs ~16 test binaries at once) it can be
        // starved past the 10s per-input timeout (PER_INPUT_TIMEOUT) and get killed,
        // yielding a no-event (0-finding) run. The fuzz logic here is deterministic
        // (iterations=1 over a fixed seed), so retry the transient-starvation case
        // with generous headroom; a persistent 0 across all attempts is a real
        // regression. Each non-starved attempt returns in well under a second, so
        // the retries cost wall-clock only on the (rare) starved path.
        let do_run = || {
            fs::write(&runtrace_log, "").unwrap();
            run_one_target_programmatic(
                &work_dir,
                harness_id,
                vec![b"../secret".to_vec()],
                1,
                None,
                None,
                0,
                &[(
                    "GOVFUZZ_RUNTRACE_LOG".to_owned(),
                    runtrace_log.display().to_string(),
                )],
                actionability::RunMode::Reporting,
                None, // cmplog_log
                &[],
                None,
            )
            .unwrap()
        };
        let mut summary = do_run();
        for _ in 0..15 {
            if !summary.findings.is_empty() {
                break;
            }
            summary = do_run();
        }

        assert_eq!(
            summary.findings.len(),
            1,
            "expected exactly one oracle finding after retries (transient subprocess \
             starvation should not persist): {:?}",
            summary.findings
        );
        let finding_dir = work_dir.join("findings").join(&summary.findings[0]);
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["classification"], "oracle_hit");
        assert_eq!(finding["rule_id"], "GF-101");
        assert_eq!(finding["oracle"]["name"], "path-traversal-ada");
        assert_eq!(finding["oracle"]["api"], "open");
        assert_eq!(finding["oracle"]["evidence"][0]["value"], "../secret");
        assert_eq!(
            fs::read(finding_dir.join("testcase.bin")).unwrap(),
            b"../secret"
        );
    }

    #[cfg(unix)]
    fn write_c_libfuzzer_harness(work_dir: &Path, id: &str, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = work_dir.join("build").join(id);
        fs::create_dir_all(&dir).unwrap();
        // The sibling main.c is what is_c_libfuzzer_harness() keys on.
        fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
        let harness = dir.join("main");
        fs::write(&harness, script).unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        harness
    }

    #[test]
    #[cfg(unix)]
    fn passthrough_libfuzzer_glue_crash_is_not_reported() {
        // A passthrough libFuzzer harness that SEGVs entirely inside ASan /
        // libFuzzer driver glue (no target frame) — the cJSON class from #388.
        // Without the driver-glue filter this floods the user with phantom
        // findings; ground truth (libFuzzer/AFL) is zero.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(
            &work_dir,
            "H-GLUE",
            "#!/bin/sh\n\
             >&2 echo 'ERROR: AddressSanitizer: SEGV on unknown address 0xfffffffffffffff1'\n\
             >&2 echo '    #0 0x1 in __asan::Allocator::Deallocate /asan/a.cpp:1'\n\
             >&2 echo '    #1 0x2 in free /asan/i.cpp:2'\n\
             >&2 echo '    #2 0x3 in fuzzer::RunOneTest /fuzzer/d.cpp:3'\n\
             exit 1\n",
        );

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-GLUE",
            vec![b"seed".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(
            summary.findings.len(),
            0,
            "a crash with no target frame (driver glue) must not be reported"
        );
    }

    #[test]
    #[cfg(unix)]
    fn per_target_finding_count_stops_after_n_distinct_findings() {
        // A harness that emits TWO distinct sanitizer crash signatures keyed on
        // the first input byte ('A' -> func_a, 'B' -> func_b), each with a real
        // target frame (not driver glue). Seeded with both crashing inputs (seeds
        // run first), so uncapped the run surfaces 2 distinct findings; with
        // `stop_after_findings = Some(1)` the in-process loop breaks the instant
        // the first finding lands -> exactly 1.
        let script = "#!/bin/sh\n\
             b=$(head -c1 \"$1\")\n\
             if [ \"$b\" = A ]; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x501 at pc 0x111'\n\
               >&2 echo '    #0 0x111 in func_a /src/a.c:10'\n\
               >&2 echo '    #1 0x112 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             if [ \"$b\" = B ]; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502 at pc 0x222'\n\
               >&2 echo '    #0 0x222 in func_b /src/b.c:10'\n\
               >&2 echo '    #1 0x223 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
               exit 1\n\
             fi\n\
             exit 0\n";
        let run = |cap: Option<usize>| {
            let root = tmpdir();
            let work_dir = root.join("govfuzz_work");
            write_c_libfuzzer_harness(&work_dir, "H-FCAP", script);
            run_one_target_programmatic(
                &work_dir,
                "H-FCAP",
                vec![b"A".to_vec(), b"B".to_vec()],
                50,
                None,
                cap,
                0,
                &[],
                actionability::RunMode::Reporting,
                None,
                &[],
                None,
            )
            .unwrap()
            .findings
            .len()
        };

        assert_eq!(run(None), 2, "uncapped: both distinct findings surface");
        assert_eq!(
            run(Some(1)),
            1,
            "--per-target-finding-count 1 stops the run at the first distinct finding"
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_one_target_programmatic_honors_cmplog_log() {
        // #378: a cmplog log passed to the auto fuzz path must be ingested and
        // fed to the mutator (CmpLogRunSummary reflects it), so operands mined
        // in an earlier pass guide later passes.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-CMPLOG", "#!/bin/sh\nexit 0\n");

        // A pre-mined cmplog log with one memcmp operand pair ("MAGIC").
        let cmplog_log = root.join("cmplog.jsonl");
        let magic_hex: String = "MAGIC".bytes().map(|b| format!("{b:02x}")).collect();
        fs::write(
            &cmplog_log,
            format!("{{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"{magic_hex}\",\"b\":\"{magic_hex}\"}}\n"),
        )
        .unwrap();

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CMPLOG",
            vec![b"seed".to_vec()],
            4,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            Some(cmplog_log.clone()),
            &[],
            None,
        )
        .unwrap();

        assert!(
            summary.cmplog.enabled,
            "cmplog must be enabled: {:?}",
            summary.cmplog
        );
        assert_eq!(summary.cmplog.status, "loaded");
        assert!(
            summary.cmplog.entries >= 1,
            "cmplog entries: {:?}",
            summary.cmplog
        );
        assert!(
            summary.cmplog.dictionary_tokens >= 1,
            "cmplog dictionary tokens: {:?}",
            summary.cmplog
        );
    }

    #[test]
    #[cfg(unix)]
    fn clean_libfuzzer_harness_yields_no_findings() {
        // Acceptance regression (#388): a known-clean libFuzzer harness yields
        // zero govfuzz findings, matching libFuzzer/AFL.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-CLEAN", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CLEAN",
            vec![b"seed".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(summary.findings.len(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn clean_run_persists_coverage_corpus_even_with_no_findings() {
        // #401 regression: a clean run that raises no classified event must still
        // flush the explored corpus (seeds + coverage-increasing inputs) to
        // corpus/<hid>/queue/, instead of leaving it empty and lost on exit.
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-CORPUS", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-CORPUS",
            vec![b"seed-input".to_vec()],
            8,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        assert_eq!(summary.findings.len(), 0, "harness is clean");
        assert!(
            summary.corpus_persisted >= 1,
            "no-event run must persist >=1 corpus input, got {}",
            summary.corpus_persisted
        );
        let queue = work_dir.join("corpus/H-CORPUS/queue");
        let files: Vec<_> = fs::read_dir(&queue)
            .expect("queue dir exists")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
            .collect();
        assert!(
            !files.is_empty(),
            "corpus/<hid>/queue must be non-empty after a clean coverage-producing run"
        );
        // The seed must be among the persisted corpus.
        let contents: Vec<Vec<u8>> = files.iter().map(|e| fs::read(e.path()).unwrap()).collect();
        assert!(
            contents.iter().any(|c| c == b"seed-input"),
            "the seed must be persisted into the corpus"
        );
    }

    #[test]
    #[cfg(unix)]
    fn non_driver_zero_coverage_run_persists_bounded_corpus() {
        // #412 regression: a non-driver harness (no GOVFUZZ_FRAMED main.c — the
        // exact shape of every Ada/legacy target) has `cov_tracker == None`, so the
        // engine never sees edge coverage. Pre-fix the retention gate degenerated to
        // "keep every non-empty input" and the end-of-run flush wrote ~every
        // executed input to disk (corpus_persisted ~= iterations, e.g. ~5000 here),
        // a disk/inode-exhaustion hazard. Post-fix retention is progress-gated and
        // bounded by the memory-aware corpus limit, so a clean zero-coverage run persists
        // only the seed(s).
        let root = tmpdir();
        let work_dir = root.join("govfuzz_work");
        write_c_libfuzzer_harness(&work_dir, "H-BOUND", "#!/bin/sh\nexit 0\n");

        let summary = run_one_target_programmatic(
            &work_dir,
            "H-BOUND",
            vec![b"seed".to_vec()],
            5000,
            None,
            None,
            0,
            &[],
            actionability::RunMode::Reporting,
            None, // cmplog_log
            &[],
            None,
        )
        .unwrap();

        // No coverage feedback and no classified events => no corpus novelty.
        assert_eq!(
            summary.corpus_new, 0,
            "a clean zero-coverage harness grows no corpus signatures"
        );
        // The pool is hard-bounded regardless of the gate.
        let entry_limit = corpus_limits(DEFAULT_MAX_LEN).entries;
        assert!(
            summary.corpus_persisted <= entry_limit,
            "corpus_persisted {} must be capped at the derived entry limit {}",
            summary.corpus_persisted,
            entry_limit
        );
        assert!(
            summary.corpus_persisted < 10_000,
            "corpus_persisted {} must not blow up (pre-fix ~5000)",
            summary.corpus_persisted
        );
        // Concretely: only the seed survives retention (nothing made progress).
        assert!(
            summary.corpus_persisted <= 1,
            "only the seed should persist on a zero-coverage no-event run, got {}",
            summary.corpus_persisted
        );
    }

    #[test]
    fn afl_execution_summary_marks_forkserver_and_persistent_mode() {
        let summary = afl_execution_summary();
        assert_eq!(summary.harness_protocol, "afl++_persistent_stdin");
        assert!(summary.forkserver);
        assert!(summary.persistent);
        assert_eq!(summary.persistent_iterations, Some(10_000));
    }

    #[test]
    fn parse_worker_count_accepts_auto_and_fixed_counts() {
        assert_eq!(parse_worker_count("auto"), Ok(FuzzWorkerCount::Auto));
        assert_eq!(parse_worker_count("3"), Ok(FuzzWorkerCount::Fixed(3)));
        assert!(parse_worker_count("0").is_err());
    }

    #[test]
    fn load_grammar_for_run_parses_json_and_generates_conformant_bytes() {
        let dir = tmpdir();
        let path = dir.join("grammar.json");
        std::fs::write(
            &path,
            br#"{"START": ["{DIGIT}{DIGIT}"], "DIGIT": ["0", "1"]}"#,
        )
        .unwrap();

        let grammar = load_grammar_for_run(Some(&path))
            .unwrap()
            .expect("grammar should load");
        let mut rng = MutationRng::new(42);
        let out = grammar
            .generate(16, &mut rng)
            .expect("grammar should generate");
        assert_eq!(out.len(), 2, "START expands to two DIGITs");
        assert!(
            out.iter().all(|b| matches!(b, b'0' | b'1')),
            "only grammar terminals, got {out:?}"
        );

        // No path -> no grammar in play.
        assert!(load_grammar_for_run(None).unwrap().is_none());
        // Malformed JSON is a hard error, not a silent skip.
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_grammar_for_run(Some(&path)).is_err());
        // A reference to an undefined non-terminal is rejected.
        std::fs::write(&path, br#"{"START": ["{MISSING}"]}"#).unwrap();
        assert!(load_grammar_for_run(Some(&path)).is_err());
    }

    fn fuzz_args_for_worker_passthrough(structured_inputs: StructuredInputMode) -> FuzzArgs {
        FuzzArgs {
            work_dir: tmpdir(),
            harness: "H-X".to_owned(),
            engine: FuzzEngine::Builtin,
            workers: None,
            iterations: Some(1),
            time: None,
            timeout: None,
            max_len: DEFAULT_MAX_LEN,
            len_control: DEFAULT_LEN_CONTROL,
            print_final_stats: false,
            rss_limit_mb: 0,
            fork_server: false,
            no_fork_server: false,
            seed_inputs: Vec::new(),
            seed_files: Vec::new(),
            sanitizers: Vec::new(),
            symbolic_seed_sources: Vec::new(),
            rng_seed: 1,
            sandbox: SandboxModeArg::None,
            mode: actionability::RunMode::Reporting,
            sandbox_tool: None,
            sandbox_strict: false,
            extra_env: Vec::new(),
            cmplog_log: None,
            grammar_file: None,
            structured_inputs,
            govfuzz_bin: None,
            stop_after_findings: None,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod redqueen_cmplog_tests {
    use super::{
        CmpShmReader, CoverageTracker, GOVFUZZ_CMP_BYTES, GOVFUZZ_CMP_CAP, GOVFUZZ_CMP_OPMAX,
        GOVFUZZ_CMP_REC,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("govfuzz-rq-{tag}-{n}"))
    }

    /// Write a `GOVFUZZ_CMP_SHM` image with the given (count, records) and the
    /// usual header, then return the path + an env vec pointing `CmpShmReader` at it.
    fn write_cmp_image(
        tag: &str,
        count: u32,
        records: &[(u8, u8, Vec<u8>, Vec<u8>)],
    ) -> (std::path::PathBuf, Vec<(String, String)>) {
        let mut buf = vec![0u8; GOVFUZZ_CMP_BYTES];
        // header: [u32 armed=0][u32 count]
        buf[4..8].copy_from_slice(&count.to_le_bytes());
        for (i, (la, lb, a, b)) in records.iter().enumerate() {
            let off = 8 + i * GOVFUZZ_CMP_REC;
            buf[off] = *la;
            buf[off + 1] = *lb;
            let a_end = (a.len()).min(GOVFUZZ_CMP_OPMAX);
            buf[off + 2..off + 2 + a_end].copy_from_slice(&a[..a_end]);
            let b_end = (b.len()).min(GOVFUZZ_CMP_OPMAX);
            buf[off + 2 + GOVFUZZ_CMP_OPMAX..off + 2 + GOVFUZZ_CMP_OPMAX + b_end]
                .copy_from_slice(&b[..b_end]);
        }
        let path = tmp_path(tag);
        std::fs::write(&path, &buf).unwrap();
        let env = vec![("GOVFUZZ_CMP_SHM".to_owned(), path.display().to_string())];
        (path, env)
    }

    #[test]
    fn read_log_round_trips_planted_pairs_with_dedup_and_skips() {
        let records = vec![
            // a planted scalar pair
            (
                4u8,
                4u8,
                vec![0x44, 0x33, 0x22, 0x11],
                vec![0x88, 0x77, 0x66, 0x55],
            ),
            // an exact duplicate -> deduped away
            (
                4,
                4,
                vec![0x44, 0x33, 0x22, 0x11],
                vec![0x88, 0x77, 0x66, 0x55],
            ),
            // a distinct two-byte pair
            (2, 2, vec![0xAB, 0xCD], vec![0xEF, 0x01]),
            // both operands empty -> skipped
            (0, 0, vec![], vec![]),
        ];
        let (path, env) = write_cmp_image("roundtrip", records.len() as u32, &records);
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        let log = reader.read_log();

        // dup collapsed, empty skipped -> exactly two unique entries.
        assert_eq!(log.entries.len(), 2);
        assert!(log
            .entries
            .iter()
            .any(|e| e.operand_a == vec![0x44, 0x33, 0x22, 0x11]
                && e.operand_b == vec![0x88, 0x77, 0x66, 0x55]));
        assert!(log
            .entries
            .iter()
            .any(|e| e.operand_a == vec![0xAB, 0xCD] && e.operand_b == vec![0xEF, 0x01]));
        // splice_candidates must locate the planted operand in a matching input.
        let input = b"\x44\x33\x22\x11....".to_vec();
        let cands = log.splice_candidates(&input);
        assert!(
            cands
                .iter()
                .any(|c| c.offset == 0 && c.replacement == vec![0x88, 0x77, 0x66, 0x55]),
            "splice candidate at the planted offset must be found"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_log_clamps_corrupt_count_and_operand_lengths() {
        // A corrupt child could write count > CAP and len > OPMAX; the reader must
        // clamp both rather than read out of bounds.
        let records = vec![(
            200u8, // len_a far over OPMAX
            200u8, // len_b far over OPMAX
            vec![0x5A; GOVFUZZ_CMP_OPMAX],
            vec![0xA5; GOVFUZZ_CMP_OPMAX],
        )];
        let (path, env) = write_cmp_image("clamp", (GOVFUZZ_CMP_CAP as u32) + 9999, &records);
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        let log = reader.read_log();
        // Only one real record was written; the rest of the (clamped-to-CAP) range
        // is zeroed -> empty -> skipped. Operand lengths clamp to OPMAX.
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].operand_a.len(), GOVFUZZ_CMP_OPMAX);
        assert_eq!(log.entries[0].operand_b.len(), GOVFUZZ_CMP_OPMAX);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn arm_zeroes_count_and_sets_armed_disarm_clears() {
        let (path, env) = write_cmp_image("arm", 7, &[(2, 2, vec![1, 2], vec![3, 4])]);
        let reader = CmpShmReader::new(&env).expect("map cmp shm");
        reader.arm();
        let after_arm = std::fs::read(&path).unwrap();
        assert_ne!(after_arm[0], 0, "armed byte set");
        assert_eq!(&after_arm[4..8], &[0, 0, 0, 0], "count zeroed by arm");
        reader.disarm();
        let after_disarm = std::fs::read(&path).unwrap();
        assert_eq!(
            &after_disarm[0..4],
            &[0, 0, 0, 0],
            "armed cleared by disarm"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn coverage_tracker_snapshot_zero_restore_round_trips() {
        let path = tmp_path("cov");
        std::fs::write(&path, vec![0u8; super::GOVFUZZ_COV_BITS]).unwrap();
        let env = vec![("GOVFUZZ_COV_SHM".to_owned(), path.display().to_string())];
        let tracker = CoverageTracker::new(&env).expect("map cov shm");
        // Simulate an exec setting some edges, snapshot it.
        tracker.restore(&{
            let mut m = vec![0u8; super::GOVFUZZ_COV_BITS];
            m[10] = 1;
            m[20] = 1;
            m
        });
        assert_eq!(tracker.count(), 2);
        let snap = tracker.snapshot();
        // Zero wipes the bitmap (isolated per-probe measurement).
        tracker.zero();
        assert_eq!(tracker.count(), 0);
        // Restore brings the cumulative state back exactly -> no #398 pollution.
        tracker.restore(&snap);
        assert_eq!(tracker.count(), 2);
        let _ = std::fs::remove_file(path);
    }
}
