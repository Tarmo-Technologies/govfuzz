// SPDX-License-Identifier: Apache-2.0
//! Live run-level status: the shared truth behind the sticky progress block.
//!
//! The per-target sink in [`crate::auto::progress`] answers "what is THIS target
//! doing". It cannot answer the questions an operator actually has while a sweep
//! of 26k candidates runs for an hour:
//!
//!   * how far through the run am I, against the constraint that will actually
//!     end it (`--max-targets`, `--campaign-time`, or the candidate list)?
//!   * am I in the unforced pass or the `--force` retry pass?
//!   * is the sweep yielding anything, or am I watching 200 consecutive
//!     `failed_build`s scroll past?
//!   * what is blocking the ones that fail — right now, not at end of run?
//!   * is the box saturated, or should I raise `--jobs`?
//!
//! Every worker writes into one `RunStatus`; the renderer takes a [`Snapshot`]
//! and formats it. Rendering is a pure function of the snapshot so the layout is
//! unit-testable without a terminal, a clock, or a sweep.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auto::progress::{phase_label, Phase};

/// Which sweep pass is running. `--force` makes a run two passes over two
/// different candidate sets, and phase 2's per-target lines are otherwise
/// indistinguishable from phase 1's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseId {
    pub index: usize,
    pub total: usize,
    pub forced: bool,
}

impl PhaseId {
    pub fn label(&self) -> String {
        let kind = if self.forced { "forced" } else { "unforced" };
        format!("phase {}/{} {kind}", self.index, self.total)
    }
}

/// Outcome buckets for the running yield tally, in the order they are displayed.
/// Ordered by "how good is this result", so the line reads as a funnel.
pub const OUTCOME_BUCKETS: [&str; 9] = [
    "fuzzed",
    "stub-only",
    "not-entered",
    "built",
    "failed-build",
    "link",
    "runtime",
    "skipped",
    "report-only",
];

/// Map a finished outcome onto its tally bucket. `stub-only` and `not-entered`
/// are split out of the built/fuzzed families deliberately: both are false
/// clean-looking results (#417 / #95), and a sweep that is producing nothing but
/// those should be visibly different from one that is really fuzzing.
pub fn outcome_bucket(outcome: &crate::auto::attempt::Outcome) -> &'static str {
    use crate::auto::attempt::Outcome::*;
    match outcome {
        BuiltAndFuzzed { .. } if outcome.stub_execution().is_some_and(|se| se.stub_only) => {
            "stub-only"
        }
        BuiltAndFuzzed { .. } => "fuzzed",
        BuiltNotEntered { .. } => "not-entered",
        Built { .. } => "built",
        FailedBuild { .. } => "failed-build",
        UnrecoverableLink { .. } => "link",
        UnrecoverableRuntime { .. } => "runtime",
        UnsupportedParams { .. } => "skipped",
        ReportOnly { .. } => "report-only",
    }
}

/// Distinct findings a finished target produced. Passes share a finding-id
/// space (a crash rediscovered by a later pass is the same finding), so this
/// counts unique ids rather than summing per-pass vectors — otherwise the live
/// tally would drift above the number the report ends up publishing.
pub fn finding_count(outcome: &crate::auto::attempt::Outcome) -> usize {
    use crate::auto::attempt::Outcome::*;
    let passes = match outcome {
        BuiltAndFuzzed { passes, .. } | BuiltNotEntered { passes, .. } => passes,
        _ => return 0,
    };
    passes
        .iter()
        .flat_map(|pass| pass.findings.iter())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// One in-flight target, as the renderer needs it. Durations rather than
/// `Instant`s so a snapshot is a plain value that tests can build by hand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerView {
    pub harness_id: String,
    pub name: String,
    pub lang: String,
    pub stage: String,
    pub stage_elapsed: Duration,
    pub budget: Option<Duration>,
    pub executions: usize,
    pub execs_per_sec: u64,
    pub edges: usize,
    pub findings: usize,
    /// Time since this target last grew coverage / last produced a finding.
    /// AFL++'s `last new path` is the single most actionable field on its status
    /// screen: it is what says "this target has gone cold, the budget left on it
    /// is being wasted". `None` until the first one happens.
    pub since_new_edge: Option<Duration>,
    pub since_finding: Option<Duration>,
}

/// Host load, sampled best-effort. `None` on platforms without /proc.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadSample {
    pub cpu_percent: u32,
    pub rss_mb: usize,
    pub rss_budget_mb: usize,
}

/// An immutable view of the run at one instant. Everything the renderer needs.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub phase: Option<PhaseId>,
    pub elapsed: Duration,
    pub eta: Option<Duration>,
    pub attempts_done: usize,
    pub attempts_total: usize,
    pub fuzzed: usize,
    pub cap: Option<usize>,
    pub time_left: Option<Duration>,
    pub outcomes: Vec<(&'static str, usize)>,
    pub top_blocker: Option<(String, usize)>,
    pub findings: usize,
    pub workers: Vec<WorkerView>,
    pub jobs: usize,
    pub jobs_ceiling: usize,
    pub per_target_secs: u64,
    pub budget_locked: bool,
    pub verbose: bool,
    pub force: bool,
    pub load: Option<LoadSample>,
    pub quitting: bool,
    pub paused: bool,
    pub help_open: bool,
    /// Whether the keyboard control plane is live (drives the hint line).
    pub controls: bool,
}

#[derive(Default)]
struct Inner {
    phase_index: Option<usize>,
    phase_forced: bool,
    /// How many phases this run will have. Live, because `[f]` can add or remove
    /// the forced pass while phase 1 is still sweeping — a fixed "1/2" printed at
    /// startup would then be a lie for the rest of the run.
    phase_total: usize,
    attempts_done: usize,
    attempts_total: usize,
    fuzzed: usize,
    cap: Option<usize>,
    outcomes: BTreeMap<&'static str, usize>,
    blockers: BTreeMap<String, usize>,
    findings: usize,
    workers: BTreeMap<usize, Worker>,
    load: Option<LoadSample>,
    deadline: Option<Instant>,
    /// Successes/attempts already carried in from a `--resume`, excluded from the
    /// rate estimate: they cost this run no wall-clock, and counting them would
    /// make the ETA claim a throughput the run has not demonstrated.
    resumed_fuzzed: usize,
}

#[derive(Clone, Debug)]
struct Worker {
    harness_id: String,
    name: String,
    lang: String,
    stage: String,
    stage_started: Instant,
    /// Fuzz-pass elapsed as reported by the engine tick (the pass clock, which is
    /// not the stage clock — a pass can start late inside a stage).
    pass_elapsed: Duration,
    budget: Option<Duration>,
    executions: usize,
    edges: usize,
    findings: usize,
    last_new_edge: Option<Instant>,
    last_finding: Option<Instant>,
}

/// Shared, mutable run state. Cheap to update (a mutex taken at ~2 Hz per
/// worker); the control flags are atomics so the hot paths can poll them
/// without contending on the mutex.
pub struct RunStatus {
    started: Instant,
    inner: Mutex<Inner>,
    jobs: AtomicUsize,
    jobs_ceiling: usize,
    quit: AtomicBool,
    paused: AtomicBool,
    help_open: AtomicBool,
    verbose: AtomicBool,
    force: AtomicBool,
    per_target_secs: std::sync::atomic::AtomicU64,
    budget_locked: AtomicBool,
    controls: AtomicBool,
    rss_budget_mb: AtomicUsize,
}

impl RunStatus {
    pub fn new(jobs: usize, jobs_ceiling: usize) -> Self {
        Self {
            started: Instant::now(),
            inner: Mutex::new(Inner::default()),
            jobs: AtomicUsize::new(jobs.max(1)),
            jobs_ceiling: jobs_ceiling.max(jobs).max(1),
            quit: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            help_open: AtomicBool::new(false),
            verbose: AtomicBool::new(false),
            force: AtomicBool::new(false),
            per_target_secs: std::sync::atomic::AtomicU64::new(60),
            budget_locked: AtomicBool::new(false),
            controls: AtomicBool::new(false),
            rss_budget_mb: AtomicUsize::new(0),
        }
    }

    pub fn set_rss_budget_mb(&self, mb: usize) {
        self.rss_budget_mb.store(mb, Ordering::Relaxed);
    }

    pub fn set_controls_live(&self, live: bool) {
        self.controls.store(live, Ordering::Relaxed);
    }

    pub fn controls_live(&self) -> bool {
        self.controls.load(Ordering::Relaxed)
    }

    /// Begin a sweep phase. Per-phase counters reset (phase 2 sweeps a different,
    /// smaller candidate set); cumulative ones — fuzzed, tallies, blockers — do
    /// not, because they describe the run, not the pass.
    pub fn begin_phase(&self, index: usize, forced: bool, attempts_total: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.phase_index = Some(index);
        inner.phase_forced = forced;
        inner.attempts_done = 0;
        inner.attempts_total = attempts_total;
        inner.workers.clear();
    }

    pub fn set_cap(&self, cap: Option<usize>) {
        self.inner.lock().unwrap().cap = cap;
    }

    /// The live `--max-targets` cap. Read once per candidate by both sweeps, so
    /// raising it mid-run simply lets the sweep keep going.
    pub fn cap(&self) -> Option<usize> {
        self.inner.lock().unwrap().cap
    }

    /// Move the cap by `delta` steps of its own size. An uncapped run can be
    /// capped downward (stop after a few more) but not "raised" — it is already
    /// unlimited, and inventing a ceiling there would be a silent restriction.
    /// Returns `(new_cap, changed)`.
    pub fn adjust_cap(&self, delta: i64) -> (Option<usize>, bool) {
        let mut inner = self.inner.lock().unwrap();
        match inner.cap {
            Some(cap) => {
                let step = (cap / 10).max(1) as i64;
                let want = (cap as i64 + delta * step).max(1) as usize;
                // Never below what has already been fuzzed: the sweep would stop
                // instantly and the bar would read as over-full.
                let want = want.max(inner.fuzzed.max(1));
                inner.cap = Some(want);
                (Some(want), want != cap)
            }
            None if delta < 0 => {
                let want = inner.fuzzed + 10;
                inner.cap = Some(want);
                (Some(want), true)
            }
            None => (None, false),
        }
    }

    /// Live per-target fuzz budget, applied from the NEXT target onward (the
    /// in-flight one has already planned its pass cascade).
    pub fn per_target_time(&self) -> Duration {
        Duration::from_secs(self.per_target_secs.load(Ordering::SeqCst))
    }

    pub fn set_per_target_time(&self, budget: Duration) {
        self.per_target_secs
            .store(budget.as_secs().max(1), Ordering::SeqCst);
    }

    /// Move the per-target budget by a quarter of itself, floored at 1s.
    pub fn adjust_per_target_time(&self, delta: i64) -> u64 {
        let mut current = self.per_target_secs.load(Ordering::SeqCst);
        loop {
            let step = (current / 4).max(1) as i64;
            let want = (current as i64 + delta * step).max(1) as u64;
            match self.per_target_secs.compare_exchange(
                current,
                want,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return want,
                Err(actual) => current = actual,
            }
        }
    }

    /// `--campaign-time` split mode owns the per-target budget (it divides the
    /// campaign across the targets it kept), so the control must refuse rather
    /// than fight it.
    pub fn set_budget_locked(&self, locked: bool) {
        self.budget_locked.store(locked, Ordering::Relaxed);
    }

    pub fn budget_locked(&self) -> bool {
        self.budget_locked.load(Ordering::Relaxed)
    }

    /// Stop starting new targets, without ending the run. In-flight targets
    /// finish; workers park until unpaused. The reason this is worth a key: the
    /// alternative for "I need this box for ten minutes" was killing the run.
    pub fn toggle_pause(&self) -> bool {
        let now = !self.paused.load(Ordering::SeqCst);
        self.paused.store(now, Ordering::SeqCst);
        now
    }

    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn help_open(&self) -> bool {
        self.help_open.load(Ordering::Relaxed)
    }

    pub fn toggle_help(&self) -> bool {
        let now = !self.help_open.load(Ordering::Relaxed);
        self.help_open.store(now, Ordering::Relaxed);
        now
    }

    /// Any key that DOES something dismisses the list: the operator found what
    /// they were looking for, and the panel is covering the run.
    pub fn close_help(&self) {
        self.help_open.store(false, Ordering::Relaxed);
    }

    pub fn set_verbose(&self, verbose: bool) {
        self.verbose.store(verbose, Ordering::Relaxed);
    }

    pub fn verbose(&self) -> bool {
        self.verbose.load(Ordering::Relaxed)
    }

    pub fn toggle_verbose(&self) -> bool {
        let now = !self.verbose.load(Ordering::Relaxed);
        self.verbose.store(now, Ordering::Relaxed);
        now
    }

    /// Whether a forced phase 2 will run. Read at the phase boundary, so it can
    /// be turned on or off for the whole of phase 1.
    pub fn set_force(&self, force: bool) {
        self.force.store(force, Ordering::SeqCst);
        self.inner.lock().unwrap().phase_total = if force { 2 } else { 1 };
    }

    pub fn force(&self) -> bool {
        self.force.load(Ordering::SeqCst)
    }

    pub fn toggle_force(&self) -> bool {
        let now = !self.force.load(Ordering::SeqCst);
        self.set_force(now);
        now
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) {
        self.inner.lock().unwrap().deadline = deadline;
    }

    /// Seed the fuzzed count from a `--resume` reload so `fuzzed N/cap` counts the
    /// same successes the cap does.
    pub fn seed_resumed(&self, fuzzed: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.fuzzed = fuzzed;
        inner.resumed_fuzzed = fuzzed;
    }

    pub fn jobs(&self) -> usize {
        self.jobs.load(Ordering::SeqCst)
    }

    pub fn jobs_ceiling(&self) -> usize {
        self.jobs_ceiling
    }

    /// Apply a live `--jobs` change, clamped to `1..=ceiling`. Returns the new
    /// value so the caller can report what actually happened — asking for 40 on a
    /// 16-core box must not silently look like it worked.
    pub fn adjust_jobs(&self, delta: i64) -> usize {
        let mut current = self.jobs.load(Ordering::SeqCst);
        loop {
            let want = (current as i64 + delta).clamp(1, self.jobs_ceiling as i64) as usize;
            match self
                .jobs
                .compare_exchange(current, want, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return want,
                Err(actual) => current = actual,
            }
        }
    }

    /// Operator asked to stop. In-flight targets finish and are reported; nothing
    /// new is handed out. This is the difference between a run that ends with a
    /// report and one that Ctrl-C leaves half-written.
    pub fn request_quit(&self) {
        self.quit.store(true, Ordering::SeqCst);
    }

    pub fn quitting(&self) -> bool {
        self.quit.load(Ordering::SeqCst)
    }

    pub fn set_load(&self, load: Option<LoadSample>) {
        self.inner.lock().unwrap().load = load;
    }

    /// Register a target as in-flight on `slot` (one slot per worker thread).
    pub fn worker_begin(&self, slot: usize, harness_id: &str, name: &str, lang: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.workers.insert(
            slot,
            Worker {
                harness_id: harness_id.to_owned(),
                name: name.to_owned(),
                lang: lang.to_owned(),
                stage: "starting".to_owned(),
                stage_started: Instant::now(),
                pass_elapsed: Duration::ZERO,
                budget: None,
                executions: 0,
                edges: 0,
                findings: 0,
                last_new_edge: None,
                last_finding: None,
            },
        );
    }

    /// Fold one progress tick into the worker's slot. Coverage and finding growth
    /// is detected here, by comparison against the slot's previous values, rather
    /// than plumbed as an event out of the fuzz loop.
    pub fn worker_update(&self, slot: usize, update: &crate::auto::progress::ProgressUpdate) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let Some(worker) = inner.workers.get_mut(&slot) else {
            return;
        };
        let stage = phase_label(&update.phase);
        if worker.stage != stage {
            worker.stage = stage;
            worker.stage_started = now;
            // A new stage is a new pass: counters restart, but the coldness
            // clocks do not — "nothing new for 4 minutes" is a property of the
            // target, and resetting it at every pass boundary would hide exactly
            // the case it exists to show.
            worker.executions = 0;
            worker.edges = 0;
            worker.pass_elapsed = Duration::ZERO;
        }
        if matches!(update.phase, Phase::Fuzz { .. }) {
            if update.edges > worker.edges {
                worker.last_new_edge = Some(now);
            }
            if update.findings > worker.findings {
                worker.last_finding = Some(now);
            }
            worker.pass_elapsed = update.elapsed;
            worker.budget = update.budget;
            worker.executions = update.executions;
            worker.edges = update.edges;
            worker.findings = update.findings;
        }
    }

    /// Record a finished target: clears its slot and folds it into the tallies.
    pub fn worker_finish(&self, slot: usize, result: &crate::auto::attempt::AttemptResult) {
        let bucket = outcome_bucket(&result.outcome);
        let blocker = crate::auto::blocker_histogram::blocker_for(result);
        let findings = finding_count(&result.outcome);
        let mut inner = self.inner.lock().unwrap();
        inner.workers.remove(&slot);
        inner.attempts_done += 1;
        *inner.outcomes.entry(bucket).or_insert(0) += 1;
        inner.findings += findings;
        if bucket == "fuzzed" || bucket == "stub-only" {
            inner.fuzzed += 1;
        }
        if let Some(key) = blocker {
            *inner
                .blockers
                .entry(format!("{} ({})", key.detail, key.language))
                .or_insert(0) += 1;
        }
    }

    /// A target that ended in an error rather than an outcome still advanced the
    /// sweep; count it so the position and ETA stay honest.
    pub fn worker_failed(&self, slot: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.workers.remove(&slot);
        inner.attempts_done += 1;
        *inner.outcomes.entry("runtime").or_insert(0) += 1;
    }

    pub fn fuzzed(&self) -> usize {
        self.inner.lock().unwrap().fuzzed
    }

    pub fn snapshot(&self) -> Snapshot {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        let elapsed = now.saturating_duration_since(self.started);
        let workers = inner
            .workers
            .values()
            .map(|w| {
                let pass_secs = w.pass_elapsed.as_secs_f64();
                WorkerView {
                    harness_id: w.harness_id.clone(),
                    name: w.name.clone(),
                    lang: w.lang.clone(),
                    stage: w.stage.clone(),
                    stage_elapsed: now.saturating_duration_since(w.stage_started),
                    budget: w.budget,
                    executions: w.executions,
                    execs_per_sec: if pass_secs > 0.0 {
                        (w.executions as f64 / pass_secs) as u64
                    } else {
                        0
                    },
                    edges: w.edges,
                    findings: w.findings,
                    since_new_edge: w.last_new_edge.map(|t| now.saturating_duration_since(t)),
                    since_finding: w.last_finding.map(|t| now.saturating_duration_since(t)),
                }
            })
            .collect();
        let top_blocker = inner
            .blockers
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(detail, count)| (detail.clone(), *count));
        let outcomes = OUTCOME_BUCKETS
            .iter()
            .filter_map(|bucket| inner.outcomes.get(bucket).map(|n| (*bucket, *n)))
            .collect();
        let time_left = inner
            .deadline
            .map(|deadline| deadline.saturating_duration_since(now));
        Snapshot {
            phase: inner.phase_index.map(|index| PhaseId {
                index,
                total: inner.phase_total.max(index),
                forced: inner.phase_forced,
            }),
            elapsed,
            eta: estimate_eta(&inner, elapsed, time_left),
            attempts_done: inner.attempts_done,
            attempts_total: inner.attempts_total,
            fuzzed: inner.fuzzed,
            cap: inner.cap,
            time_left,
            outcomes,
            top_blocker,
            findings: inner.findings,
            workers,
            jobs: self.jobs(),
            jobs_ceiling: self.jobs_ceiling,
            per_target_secs: self.per_target_secs.load(Ordering::SeqCst),
            budget_locked: self.budget_locked(),
            verbose: self.verbose(),
            force: self.force(),
            load: inner.load.map(|mut load| {
                load.rss_budget_mb = self.rss_budget_mb.load(Ordering::Relaxed);
                load
            }),
            quitting: self.quitting(),
            paused: self.paused(),
            help_open: self.help_open(),
            controls: self.controls_live(),
        }
    }
}

/// Below this many completed attempts the measured rate is noise — a sweep whose
/// first two targets happened to be quick would advertise an ETA off by an order
/// of magnitude, which is worse than showing none.
const MIN_ETA_SAMPLES: usize = 5;

/// Time to the end of the run, estimated from the constraint that will actually
/// stop it. With `--max-targets` that is the success rate (most candidates never
/// fuzz, so the attempt rate would badly under-estimate); without it, the attempt
/// rate over the remaining candidates. A `--campaign-time` deadline caps both —
/// it is a hard stop, so no estimate may exceed it.
fn estimate_eta(inner: &Inner, elapsed: Duration, time_left: Option<Duration>) -> Option<Duration> {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return time_left;
    }
    let by_attempts = (inner.attempts_done >= MIN_ETA_SAMPLES).then(|| {
        let remaining = inner.attempts_total.saturating_sub(inner.attempts_done) as f64;
        Duration::from_secs_f64(remaining / (inner.attempts_done as f64 / secs))
    });
    // Successes earned in THIS run: a resumed run's reloaded successes cost it no
    // time, so including them would inflate the rate.
    let earned = inner.fuzzed.saturating_sub(inner.resumed_fuzzed);
    let by_cap = inner.cap.and_then(|cap| {
        if earned < MIN_ETA_SAMPLES {
            return None;
        }
        let remaining = cap.saturating_sub(inner.fuzzed) as f64;
        Some(Duration::from_secs_f64(remaining / (earned as f64 / secs)))
    });
    // Whichever constraint binds first ends the run.
    [by_attempts, by_cap, time_left].into_iter().flatten().min()
}

/// `6m12s`, `1h04m`, `43s` — fixed-ish width, no decimals, readable at a glance.
pub fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// `812`, `8.1k`, `1.2M` — execution counts get large enough that raw digits stop
/// being comparable at a glance between redraws.
pub fn human_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// `412 MB`, `7.2 GB`. A sweep that has not yet started a compiler sits in the
/// hundreds of megabytes, and rendering that as `0.0 GB` reads as "nothing is
/// running" next to a multi-gigabyte budget.
pub fn human_mb(mb: usize) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

/// Shorten to `width` characters with a trailing ellipsis. Target names in
/// generated harnesses can be long enough (namespaced C++ / Ada child units) to
/// push the stage off the right edge of the block.
fn elide(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn bar(done: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return "─".repeat(width);
    }
    let filled = ((done.min(total) as f64 / total as f64) * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

const BAR_WIDTH: usize = 14;

/// The headline: where the run is against the constraint that will end it. The
/// bar tracks that constraint — with `--max-targets` the run ends at N fuzzed, so
/// filling a bar with candidate position (which may reach 213/26409 while the cap
/// is nearly met) would point at the wrong finish line.
pub fn headline(s: &Snapshot) -> String {
    let mut out = String::new();
    if let Some(phase) = s.phase {
        out.push_str(&phase.label());
        out.push_str("   ");
    }
    match s.cap {
        Some(cap) => {
            out.push_str(&format!(
                "fuzzed {:>width$}/{cap} {}  attempts {}/{}",
                s.fuzzed,
                bar(s.fuzzed, cap, BAR_WIDTH),
                s.attempts_done,
                s.attempts_total,
                width = cap.to_string().len(),
            ));
        }
        None => {
            out.push_str(&format!(
                "attempts {}/{} {}  {} fuzzed",
                s.attempts_done,
                s.attempts_total,
                bar(s.attempts_done, s.attempts_total, BAR_WIDTH),
                s.fuzzed,
            ));
        }
    }
    out.push_str(&format!("   {}", human_duration(s.elapsed)));
    match s.eta {
        Some(eta) => out.push_str(&format!(" · eta ~{}", human_duration(eta))),
        None => out.push_str(" · eta —"),
    }
    if s.quitting {
        out.push_str("  [STOPPING]");
    } else if s.paused {
        // Distinct from stopping: the run is alive and will continue on a key.
        out.push_str("  [PAUSED]");
    }
    out
}

/// The yield line: is this sweep producing anything, and what is stopping the
/// rest. A position counter alone cannot answer either.
pub fn tally_line(s: &Snapshot) -> String {
    let tally = if s.outcomes.is_empty() {
        "no results yet".to_owned()
    } else {
        s.outcomes
            .iter()
            .map(|(bucket, count)| format!("{count} {bucket}"))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let mut out = format!("{tally}   {} finding(s)", s.findings);
    if let Some((detail, count)) = &s.top_blocker {
        out.push_str(&format!("   top blocker: {detail} ({count})"));
    }
    out
}

/// Load + the control hints. Printed together because they answer one question:
/// "should I change something about this run, and how".
pub fn control_line(s: &Snapshot) -> String {
    let mut out = format!("jobs {}/{}", s.jobs, s.jobs_ceiling);
    out.push_str(&match s.cap {
        Some(cap) => format!(" · cap {cap}"),
        None => " · cap none".to_owned(),
    });
    out.push_str(&format!(
        " · target-time {}{}",
        human_duration(Duration::from_secs(s.per_target_secs)),
        if s.budget_locked { " (split)" } else { "" }
    ));
    out.push_str(&format!(
        " · force {} · verbose {}",
        if s.force { "on" } else { "off" },
        if s.verbose { "on" } else { "off" }
    ));
    if let Some(load) = s.load {
        out.push_str(&format!("   cpu {}%", load.cpu_percent));
        if load.rss_budget_mb > 0 {
            out.push_str(&format!(
                "   rss {}/{}",
                human_mb(load.rss_mb),
                human_mb(load.rss_budget_mb)
            ));
        } else {
            out.push_str(&format!("   rss {}", human_mb(load.rss_mb)));
        }
    }
    out
}

/// The key legend, sized to the terminal.
///
/// Three widths rather than one truncated string. A legend cut off mid-way is
/// worse than a short one: the operator cannot tell whether the missing keys
/// exist, and a control nobody knows about may as well not be implemented. Every
/// tier keeps `[?]`, which opens the full list.
pub fn key_line(s: &Snapshot, width: usize) -> String {
    if !s.controls {
        return String::new();
    }
    let pause = if s.paused { "resume" } else { "pause" };
    let close = if s.help_open { "close help" } else { "help" };
    let full = format!(
        "keys: [q] stop & report · [p] {pause} · [+/-] jobs · [{{/}}] cap · [</>] target-time · [f] force · [v] verbose · [?] {close}"
    );
    if full.chars().count() <= width {
        return full;
    }
    let medium =
        format!("keys: q stop · p {pause} · +/- jobs · {{/}} cap · </> time · f force · v verbose · ? {close}");
    if medium.chars().count() <= width {
        return medium;
    }
    "keys: [?] help · [q] stop".to_owned()
}

/// The expanded key list, shown while `[?]` is toggled on.
///
/// The one-line legend names the keys; this says what each one DOES, which is
/// what decides whether to press it. It lives inside the block rather than
/// scrolling past as a printed line, so it can be dismissed — and so reading it
/// never costs the operator the live numbers they were watching.
pub fn help_panel(s: &Snapshot) -> Vec<String> {
    if !s.help_open {
        return Vec::new();
    }
    let pause = if s.paused {
        "resume the sweep".to_owned()
    } else {
        "pause: in-flight targets finish, nothing new starts, the run stays alive".to_owned()
    };
    let cap = match s.cap {
        Some(cap) => format!("--max-targets (now {cap}), by a tenth — never below what has fuzzed"),
        None => "--max-targets: [ caps this uncapped run, ] has nothing to raise".to_owned(),
    };
    let time = if s.budget_locked {
        "--per-target-time — fixed by this run's --campaign-time split".to_owned()
    } else {
        format!(
            "--per-target-time (now {}), by a quarter — applies from the NEXT target",
            human_duration(Duration::from_secs(s.per_target_secs))
        )
    };
    vec![
        "  ── controls ──────────────────────────────────────────────────────".to_owned(),
        "  q      stop cleanly: finish in-flight targets, then write the report".to_owned(),
        format!("  p      {pause}"),
        format!(
            "  + -    --jobs (now {}/{}), applied as workers free up",
            s.jobs, s.jobs_ceiling
        ),
        format!("  ] [    {cap}"),
        format!("  > <    {time}"),
        format!(
            "  f      forced phase 2 (now {}) — retries what this pass could not fuzz",
            if s.force { "on" } else { "off" }
        ),
        format!(
            "  v      per-target detail lines (now {})",
            if s.verbose { "on" } else { "off" }
        ),
        "  ?      close this list · Ctrl-C still aborts, without a report".to_owned(),
        "  ──────────────────────────────────────────────────────────────────".to_owned(),
    ]
}

/// One line per in-flight target. `+`/`-` can leave fewer workers busy than
/// `jobs`, so this renders what is actually running, not what was configured.
pub fn worker_lines(s: &Snapshot) -> Vec<String> {
    s.workers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let lead = if i == 0 { "now " } else { "    " };
            // Pad the identity columns so the stage and its clock line up across
            // workers: the scan an operator actually does is vertical ("is any of
            // these stuck?"), and ragged columns defeat it.
            let mut line = format!(
                "{lead} {:<18} {:<22} {:<6} {}",
                w.harness_id,
                elide(&w.name, 22),
                w.lang,
                w.stage
            );
            match w.budget {
                Some(budget) => line.push_str(&format!(
                    " {}/{}",
                    human_duration(w.stage_elapsed),
                    human_duration(budget)
                )),
                None => line.push_str(&format!(" {}", human_duration(w.stage_elapsed))),
            }
            if w.executions > 0 {
                line.push_str(&format!(
                    "  {} execs {}/s",
                    human_count(w.executions),
                    human_count(w.execs_per_sec as usize)
                ));
            }
            if w.edges > 0 {
                line.push_str(&format!("  {} edges", human_count(w.edges)));
            }
            if w.findings > 0 {
                line.push_str(&format!("  {} finding(s)", w.findings));
            }
            // Coldness, only once there is something to be cold since.
            if let Some(since) = w.since_new_edge {
                line.push_str(&format!("  last edge {}", human_duration(since)));
            }
            if let Some(since) = w.since_finding {
                line.push_str(&format!("  last find {}", human_duration(since)));
            }
            line
        })
        .collect()
}

/// The whole sticky block, top to bottom.
pub fn render_block(s: &Snapshot, width: usize) -> Vec<String> {
    let mut lines = vec![headline(s), tally_line(s), control_line(s)];
    let keys = key_line(s, width);
    if !keys.is_empty() {
        lines.push(keys);
    }
    lines.extend(help_panel(s));
    lines.extend(worker_lines(s));
    // A paused run has no in-flight workers to list once they drain, and an empty
    // tail would read as "stuck". Say what is actually true.
    if s.paused && s.workers.is_empty() {
        lines.push("now  paused — no targets running; press [p] to resume".to_owned());
    }
    lines
}

/// Fit the block into `rows`, saying how much was hidden rather than silently
/// dropping it. A block taller than the screen also breaks the erase — the cursor
/// cannot walk up past the top of the terminal — so this is a correctness bound,
/// not only tidiness. `--jobs 16` plus the help panel exceeds a 24-row window.
pub fn fit_block(mut lines: Vec<String>, rows: usize) -> Vec<String> {
    let max = rows.saturating_sub(2).max(3);
    if lines.len() <= max {
        return lines;
    }
    let hidden = lines.len() - (max - 1);
    lines.truncate(max - 1);
    lines.push(format!(
        "… +{hidden} more line(s) — taller terminal or lower --jobs to see them"
    ));
    lines
}

/// The non-TTY heartbeat: the same facts on one line, for CI logs where a
/// redrawn block is meaningless but "where did the last 20 minutes go" is still
/// the question being asked.
pub fn heartbeat_line(s: &Snapshot) -> String {
    let phase = s
        .phase
        .map(|p| format!("{} ", p.label()))
        .unwrap_or_default();
    let cap = s
        .cap
        .map(|cap| format!("fuzzed {}/{cap} ", s.fuzzed))
        .unwrap_or_else(|| format!("fuzzed {} ", s.fuzzed));
    let eta = s
        .eta
        .map(|eta| format!(" eta ~{}", human_duration(eta)))
        .unwrap_or_default();
    let busy = s
        .workers
        .iter()
        .map(|w| format!("{} {}", w.harness_id, w.stage))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "govfuzz auto: {phase}{cap}attempts {}/{} elapsed {}{eta} | {busy}",
        s.attempts_done,
        s.attempts_total,
        human_duration(s.elapsed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot {
            phase: Some(PhaseId {
                index: 1,
                total: 2,
                forced: false,
            }),
            elapsed: Duration::from_secs(372),
            eta: Some(Duration::from_secs(2280)),
            attempts_done: 213,
            attempts_total: 26409,
            fuzzed: 7,
            cap: Some(50),
            outcomes: vec![("fuzzed", 7), ("failed-build", 118), ("skipped", 88)],
            top_blocker: Some(("missing header X (c)".to_owned(), 61)),
            findings: 2,
            jobs: 3,
            jobs_ceiling: 16,
            controls: true,
            ..Snapshot::default()
        }
    }

    #[test]
    fn headline_bars_the_cap_not_the_candidate_position() {
        let line = headline(&snap());
        // The cap is the finish line, so the bar is ~7/50 filled (2 of 14 cells),
        // NOT ~213/26409 (which would render as an empty bar and imply the run
        // has barely started when it is nearly done).
        assert!(line.contains("fuzzed  7/50 ██░░░░░░░░░░░░"), "{line}");
        assert!(line.contains("attempts 213/26409"), "{line}");
        assert!(line.contains("phase 1/2 unforced"), "{line}");
        assert!(line.contains("6m12s · eta ~38m00s"), "{line}");
    }

    #[test]
    fn uncapped_run_bars_the_candidate_sweep_instead() {
        let line = headline(&Snapshot {
            cap: None,
            ..snap()
        });
        assert!(line.contains("attempts 213/26409 ░░░░░░░░░░░░░░"), "{line}");
        assert!(line.contains("7 fuzzed"), "{line}");
    }

    #[test]
    fn forced_phase_is_named_in_the_headline() {
        let line = headline(&Snapshot {
            phase: Some(PhaseId {
                index: 2,
                total: 2,
                forced: true,
            }),
            ..snap()
        });
        assert!(line.starts_with("phase 2/2 forced"), "{line}");
    }

    #[test]
    fn quitting_is_visible_while_in_flight_targets_finish() {
        let line = headline(&Snapshot {
            quitting: true,
            ..snap()
        });
        assert!(line.ends_with("[STOPPING]"), "{line}");
    }

    #[test]
    fn tally_line_carries_yield_and_the_top_blocker() {
        let line = tally_line(&snap());
        assert!(
            line.contains("7 fuzzed · 118 failed-build · 88 skipped"),
            "{line}"
        );
        assert!(line.contains("2 finding(s)"), "{line}");
        assert!(
            line.contains("top blocker: missing header X (c) (61)"),
            "{line}"
        );
    }

    #[test]
    fn control_line_shows_every_live_tunable_and_the_load() {
        let line = control_line(&Snapshot {
            per_target_secs: 60,
            load: Some(LoadSample {
                cpu_percent: 42,
                rss_mb: 1228,
                rss_budget_mb: 9168,
            }),
            ..snap()
        });
        // Each of these is adjustable from the keyboard, so each must be visible:
        // a control whose current value is off screen cannot be used deliberately.
        assert!(line.contains("jobs 3/16"), "{line}");
        assert!(line.contains("cap 50"), "{line}");
        assert!(line.contains("target-time 1m00s"), "{line}");
        assert!(line.contains("force off"), "{line}");
        assert!(line.contains("verbose off"), "{line}");
        assert!(line.contains("cpu 42%"), "{line}");
        assert!(line.contains("rss 1.2 GB/9.0 GB"), "{line}");
    }

    #[test]
    fn a_split_owned_budget_is_marked_so_the_key_refusal_is_not_a_surprise() {
        let line = control_line(&Snapshot {
            per_target_secs: 37,
            budget_locked: true,
            ..snap()
        });
        assert!(line.contains("target-time 37s (split)"), "{line}");
    }

    #[test]
    fn the_key_line_names_the_controls_and_tracks_the_pause_state() {
        let line = key_line(&snap(), 200);
        assert!(line.contains("[q] stop & report"), "{line}");
        assert!(line.contains("[p] pause"), "{line}");
        assert!(line.contains("[+/-] jobs"), "{line}");
        assert!(line.contains("[?] help"), "{line}");
        // The label flips so the key never reads as a no-op while paused.
        let paused = key_line(
            &Snapshot {
                paused: true,
                ..snap()
            },
            200,
        );
        assert!(paused.contains("[p] resume"), "{paused}");
        // No controls (piped run): no legend to offer.
        assert_eq!(
            key_line(
                &Snapshot {
                    controls: false,
                    ..snap()
                },
                200
            ),
            ""
        );
    }

    #[test]
    fn the_legend_has_no_stray_whitespace() {
        // `cargo fmt` joined a line-continuation literal here once and kept the
        // source indentation INSIDE the string, so the rendered legend carried a
        // ten-space gap. Source-level review did not catch it; this does.
        for width in [200, 90, 20] {
            let line = key_line(&snap(), width);
            assert!(
                !line.contains("  "),
                "double space at width {width}: {line}"
            );
        }
    }

    #[test]
    fn the_legend_degrades_by_width_instead_of_being_cut_off() {
        // A legend truncated mid-way hides that the remaining keys exist at all,
        // so each tier must FIT rather than overflow — and must keep [?], the way
        // back to the full list.
        for width in [200, 120, 100, 80, 60, 40, 26] {
            let line = key_line(&snap(), width);
            assert!(
                line.chars().count() <= width.max(25),
                "width {width} overflowed: {line}"
            );
            assert!(
                line.contains('?'),
                "width {width} lost the help key: {line}"
            );
            assert!(
                line.contains('q'),
                "width {width} lost the stop key: {line}"
            );
        }
    }

    #[test]
    fn the_help_panel_explains_what_each_key_does_with_its_current_value() {
        let closed = help_panel(&snap());
        assert!(closed.is_empty(), "panel must be off until [?] is pressed");
        let panel = help_panel(&Snapshot {
            help_open: true,
            per_target_secs: 60,
            ..snap()
        })
        .join("\n");
        // Naming the key is not enough — the panel exists to say what pressing it
        // does, and what the value is NOW.
        assert!(panel.contains("q      stop cleanly"), "{panel}");
        assert!(panel.contains("nothing new starts"), "{panel}");
        assert!(panel.contains("--jobs (now 3/16)"), "{panel}");
        assert!(panel.contains("--max-targets (now 50)"), "{panel}");
        assert!(panel.contains("--per-target-time (now 1m00s)"), "{panel}");
        assert!(panel.contains("applies from the NEXT target"), "{panel}");
        assert!(panel.contains("Ctrl-C still aborts"), "{panel}");
    }

    #[test]
    fn the_help_panel_states_the_limits_that_apply_to_this_run() {
        // An uncapped run and a split-owned budget behave differently under the
        // same keys; the panel says so rather than describing a generic run.
        let panel = help_panel(&Snapshot {
            help_open: true,
            cap: None,
            budget_locked: true,
            ..snap()
        })
        .join("\n");
        assert!(panel.contains("] has nothing to raise"), "{panel}");
        assert!(
            panel.contains("fixed by this run's --campaign-time split"),
            "{panel}"
        );
    }

    #[test]
    fn a_block_taller_than_the_terminal_is_capped_and_says_what_it_hid() {
        // --jobs 16 plus the help panel overflows a 24-row window, and a block
        // taller than the screen breaks the erase (the cursor cannot walk up past
        // the top), so the cap is a correctness bound.
        let lines: Vec<String> = (0..40).map(|i| format!("line {i}")).collect();
        let fitted = fit_block(lines, 24);
        assert_eq!(fitted.len(), 22);
        assert!(
            fitted.last().unwrap().contains("+19 more line(s)"),
            "{fitted:?}"
        );
        // A block that already fits is returned untouched.
        let short = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(fit_block(short.clone(), 24), short);
    }

    #[test]
    fn a_paused_run_with_no_workers_says_so_instead_of_showing_an_empty_tail() {
        let lines = render_block(
            &Snapshot {
                paused: true,
                workers: vec![],
                ..snap()
            },
            200,
        );
        assert!(lines[0].contains("[PAUSED]"), "{:?}", lines[0]);
        assert!(
            lines.last().unwrap().contains("press [p] to resume"),
            "{lines:?}"
        );
    }

    #[test]
    fn stopping_outranks_paused_in_the_headline() {
        // A run that is both paused and quitting is ENDING; saying "paused" would
        // suggest it could still be resumed.
        let line = headline(&Snapshot {
            paused: true,
            quitting: true,
            ..snap()
        });
        assert!(line.contains("[STOPPING]"), "{line}");
        assert!(!line.contains("[PAUSED]"), "{line}");
    }

    #[test]
    fn a_long_target_name_cannot_push_the_stage_off_the_block() {
        assert_eq!(elide("short", 22), "short");
        let long = elide("Ada.Strings.Unbounded.Parse_Everything", 22);
        assert_eq!(long.chars().count(), 22);
        assert!(long.ends_with('…'), "{long}");
    }

    #[test]
    fn sub_gigabyte_memory_is_reported_in_megabytes() {
        // A run that has not spawned a compiler yet still uses real memory;
        // `0.0 GB` next to a 9 GB budget reads as "idle" when it is not.
        assert_eq!(human_mb(412), "412 MB");
        assert_eq!(human_mb(9168), "9.0 GB");
    }

    #[test]
    fn worker_line_reports_coldness_and_live_counters() {
        let lines = worker_lines(&Snapshot {
            workers: vec![WorkerView {
                harness_id: "H-C0051".to_owned(),
                name: "mz_crc32".to_owned(),
                lang: "C".to_owned(),
                stage: "fuzz:cmplog".to_owned(),
                stage_elapsed: Duration::from_secs(14),
                budget: Some(Duration::from_secs(60)),
                executions: 8123,
                execs_per_sec: 512,
                edges: 318,
                findings: 1,
                since_new_edge: Some(Duration::from_secs(4)),
                since_finding: Some(Duration::from_secs(63)),
            }],
            ..snap()
        });
        let line = &lines[0];
        assert!(
            line.contains(
                "now  H-C0051            mz_crc32               C      fuzz:cmplog 14s/1m00s"
            ),
            "{line}"
        );
        assert!(line.contains("8.1k execs 512/s"), "{line}");
        assert!(line.contains("318 edges"), "{line}");
        assert!(line.contains("1 finding(s)"), "{line}");
        // Coldness clocks: the reason to cut this target's budget short.
        assert!(line.contains("last edge 4s"), "{line}");
        assert!(line.contains("last find 1m03s"), "{line}");
    }

    #[test]
    fn eta_needs_samples_before_it_claims_a_rate() {
        let mut inner = Inner {
            attempts_done: 2,
            attempts_total: 100,
            ..Inner::default()
        };
        assert_eq!(estimate_eta(&inner, Duration::from_secs(10), None), None);
        inner.attempts_done = 10;
        // 10 attempts in 10s → 1/s → 90 remaining → 90s.
        assert_eq!(
            estimate_eta(&inner, Duration::from_secs(10), None),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn capped_eta_uses_the_success_rate_and_the_deadline_caps_it() {
        let inner = Inner {
            attempts_done: 100,
            attempts_total: 10_000,
            fuzzed: 10,
            cap: Some(50),
            ..Inner::default()
        };
        // 10 successes in 100s → 0.1/s → 40 remaining → 400s, which beats the
        // attempt-rate estimate (9900 remaining at 1/s = 9900s).
        assert_eq!(
            estimate_eta(&inner, Duration::from_secs(100), None),
            Some(Duration::from_secs(400))
        );
        // A campaign deadline is a hard stop: no estimate may exceed it.
        assert_eq!(
            estimate_eta(
                &inner,
                Duration::from_secs(100),
                Some(Duration::from_secs(60))
            ),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn resumed_successes_do_not_inflate_the_success_rate() {
        // 15 fuzzed of which 10 were reloaded from a prior run: only the 5 earned
        // in this run's 100s may set the rate, so the ETA for the remaining 35 is
        // 700s — not the 233s that counting all 15 as this run's work would claim.
        let inner = Inner {
            attempts_done: 100,
            attempts_total: 10_000,
            fuzzed: 15,
            resumed_fuzzed: 10,
            cap: Some(50),
            ..Inner::default()
        };
        assert_eq!(
            estimate_eta(&inner, Duration::from_secs(100), None),
            Some(Duration::from_secs(700))
        );
    }

    #[test]
    fn jobs_adjustment_clamps_to_one_and_the_ceiling() {
        let status = RunStatus::new(3, 8);
        assert_eq!(status.adjust_jobs(1), 4);
        assert_eq!(status.adjust_jobs(100), 8);
        assert_eq!(status.adjust_jobs(-100), 1);
    }

    #[test]
    fn heartbeat_carries_the_same_facts_on_one_line() {
        let line = heartbeat_line(&snap());
        assert!(line.contains("phase 1/2 unforced"), "{line}");
        assert!(line.contains("fuzzed 7/50"), "{line}");
        assert!(line.contains("attempts 213/26409"), "{line}");
        assert!(line.contains("eta ~38m00s"), "{line}");
    }
}
