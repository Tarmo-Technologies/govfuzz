// SPDX-License-Identifier: Apache-2.0

//! Continuous-fuzzing on-prem daemon.
//!
//! In-process scheduler that accepts fuzz-job submissions, queues
//! them, and dispatches them to a worker pool that spawns the
//! configured `govfuzz fuzz` command per job. Jobs are persisted
//! to `<data_dir>/jobs.jsonl` so a daemon restart can recover the
//! known job set (state is reset to Queued for jobs that were
//! Running at shutdown — in-flight work is assumed lost).
//!
//! Tracks issue #303. The HTTP/JSON-RPC front end + web UI from
//! the original issue body are deliberately out of scope for v0.1
//! — the focus here is the scheduler + job model the
//! `crates/daemon` JSON-RPC server (or any other front end) plugs
//! into via the `Scheduler::submit` / `Scheduler::list_jobs`
//! surface.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzJob {
    pub job_id: String,
    pub project_dir: PathBuf,
    pub harness_id: String,
    pub time_budget_secs: u64,
    pub state: JobState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub max_concurrent_jobs: u32,
    pub govfuzz_bin: PathBuf,
    pub webhook_url: Option<String>,
    pub poll_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("data dir does not exist: {0}")]
    DataDirMissing(PathBuf),
    #[error("govfuzz binary not found: {0}")]
    BinMissing(PathBuf),
    #[error("scheduler already shut down")]
    Shutdown,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Scheduler handle. Construction spawns a background worker
/// thread that drains the queue. Drop the scheduler to stop the
/// thread (Drop sends a shutdown signal and joins).
pub struct Scheduler {
    state: Arc<SharedState>,
    workers: Vec<JoinHandle<()>>,
    data_dir: PathBuf,
}

struct SharedState {
    inner: Mutex<InnerState>,
    cv: Condvar,
}

struct InnerState {
    queue: VecDeque<FuzzJob>,
    seen: Vec<FuzzJob>,
    shutdown: bool,
    next_id: u64,
}

impl Scheduler {
    pub fn start(config: &DaemonConfig) -> Result<Self, DaemonError> {
        if !config.data_dir.is_dir() {
            return Err(DaemonError::DataDirMissing(config.data_dir.clone()));
        }
        if !config.govfuzz_bin.is_file() {
            return Err(DaemonError::BinMissing(config.govfuzz_bin.clone()));
        }
        let state = Arc::new(SharedState {
            inner: Mutex::new(InnerState {
                queue: VecDeque::new(),
                seen: Vec::new(),
                shutdown: false,
                next_id: 0,
            }),
            cv: Condvar::new(),
        });

        // Restore from disk if the previous run persisted any jobs.
        let jobs_path = config.data_dir.join("jobs.jsonl");
        if jobs_path.is_file() {
            let bytes = std::fs::read(&jobs_path).unwrap_or_default();
            let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            for line in bytes.split(|b| *b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let Ok(mut job) = serde_json::from_slice::<FuzzJob>(line) else {
                    continue;
                };
                if matches!(job.state, JobState::Running) {
                    job.state = JobState::Queued;
                }
                let needs_requeue = matches!(job.state, JobState::Queued);
                guard.seen.push(job.clone());
                if needs_requeue {
                    guard.queue.push_back(job);
                }
            }
        }

        let mut workers = Vec::new();
        for _ in 0..config.max_concurrent_jobs.max(1) {
            let state_ref = Arc::clone(&state);
            let data_dir = config.data_dir.clone();
            let bin = config.govfuzz_bin.clone();
            let poll = config.poll_interval;
            let webhook = config.webhook_url.clone();
            workers.push(std::thread::spawn(move || {
                worker_loop(state_ref, data_dir, bin, poll, webhook);
            }));
        }
        Ok(Self {
            state,
            workers,
            data_dir: config.data_dir.clone(),
        })
    }

    /// Queue a fuzz job. Returns the assigned job_id. The job will
    /// be picked up by a worker thread on the next poll cycle.
    pub fn submit(
        &self,
        project_dir: PathBuf,
        harness_id: String,
        time_budget: Duration,
    ) -> Result<String, DaemonError> {
        let mut guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        if guard.shutdown {
            return Err(DaemonError::Shutdown);
        }
        let job_id = format!("J-{:06}", guard.next_id);
        guard.next_id += 1;
        let job = FuzzJob {
            job_id: job_id.clone(),
            project_dir,
            harness_id,
            time_budget_secs: time_budget.as_secs(),
            state: JobState::Queued,
        };
        guard.queue.push_back(job.clone());
        guard.seen.push(job);
        self.state.cv.notify_one();
        drop(guard);
        self.persist();
        Ok(job_id)
    }

    pub fn list_jobs(&self) -> Result<Vec<FuzzJob>, DaemonError> {
        let guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(guard.seen.clone())
    }

    fn persist(&self) {
        let guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = String::new();
        for job in &guard.seen {
            if let Ok(line) = serde_json::to_string(job) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        let _ = std::fs::write(self.data_dir.join("jobs.jsonl"), out);
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        {
            let mut guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.shutdown = true;
            self.state.cv.notify_all();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

fn worker_loop(
    state: Arc<SharedState>,
    data_dir: PathBuf,
    bin: PathBuf,
    poll: Duration,
    webhook: Option<String>,
) {
    loop {
        let job = {
            let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if guard.shutdown {
                    return;
                }
                if let Some(job) = guard.queue.pop_front() {
                    let job_id = job.job_id.clone();
                    for seen in guard.seen.iter_mut() {
                        if seen.job_id == job_id {
                            seen.state = JobState::Running;
                            break;
                        }
                    }
                    break job;
                }
                guard = match state.cv.wait_timeout(guard, poll) {
                    Ok((g, _)) => g,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
        };
        persist_locked(&data_dir, &state);
        let final_state = run_one_job(&bin, &job);
        {
            let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            for seen in guard.seen.iter_mut() {
                if seen.job_id == job.job_id {
                    seen.state = final_state;
                    break;
                }
            }
        }
        persist_locked(&data_dir, &state);
        if let Some(url) = &webhook {
            let payload = serde_json::json!({
                "job_id": job.job_id,
                "harness_id": job.harness_id,
                "state": final_state,
            });
            let _ = post_webhook(url, &payload.to_string());
        }
    }
}

fn run_one_job(bin: &Path, job: &FuzzJob) -> JobState {
    let mut cmd = Command::new(bin);
    cmd.arg("fuzz")
        .arg(&job.project_dir)
        .arg("--harness")
        .arg(&job.harness_id);
    if job.time_budget_secs > 0 {
        cmd.arg("--time").arg(format!("{}s", job.time_budget_secs));
    }
    match cmd.status() {
        Ok(status) if status.success() => JobState::Complete,
        _ => JobState::Failed,
    }
}

/// Best-effort webhook POST. Used by the scheduler to notify a
/// configured webhook URL of job state transitions. Returns
/// Ok(()) on 2xx, Err otherwise. The implementation is a hand-rolled
/// minimal HTTP/1.1 client to avoid pulling in a TLS+reqwest stack
/// — the v0.1 audience is on-prem (likely plain HTTP webhook to a
/// chatops bot or local notification proxy).
///
/// All socket operations (connect, write, read) carry a 10-second
/// timeout so a misbehaving webhook server can't stall the worker
/// thread that called us.
pub fn post_webhook(url: &str, payload: &str) -> Result<(), DaemonError> {
    post_webhook_with_timeout(url, payload, Duration::from_secs(10))
}

/// As [`post_webhook`] but with a caller-supplied per-operation
/// socket timeout. Mainly exposed for tests that need a tight
/// timeout to keep the suite fast.
pub fn post_webhook_with_timeout(
    url: &str,
    payload: &str,
    timeout: Duration,
) -> Result<(), DaemonError> {
    let parsed = parse_http_url(url).ok_or_else(|| {
        DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid webhook url: {url}"),
        ))
    })?;
    if parsed.scheme != "http" {
        return Err(DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http:// webhooks are supported in v0.1; use a TLS-terminating proxy for https",
        )));
    }
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .collect();
    let addr = addrs.first().ok_or_else(|| {
        DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("could not resolve {}:{}", parsed.host, parsed.port),
        ))
    })?;
    let mut stream = std::net::TcpStream::connect_timeout(addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        parsed.path,
        parsed.host,
        payload.len(),
        payload
    );
    stream.write_all(request.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let status = parse_http_status(&buf)
        .ok_or_else(|| DaemonError::Io(std::io::Error::other("malformed webhook response")))?;
    if !(200..300).contains(&status) {
        return Err(DaemonError::Io(std::io::Error::other(format!(
            "webhook returned {status}"
        ))));
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().ok()?),
        None => (
            host_port.to_owned(),
            if scheme == "https" { 443u16 } else { 80u16 },
        ),
    };
    Some(ParsedUrl {
        scheme: scheme.to_owned(),
        host,
        port,
        path: path.to_owned(),
    })
}

fn parse_http_status(response: &[u8]) -> Option<u16> {
    let line = response.split(|b| *b == b'\n').next()?;
    let mut tokens = line.splitn(3, |b| *b == b' ');
    let _http = tokens.next()?;
    let status = std::str::from_utf8(tokens.next()?).ok()?;
    status.trim().parse().ok()
}

fn persist_locked(data_dir: &Path, state: &SharedState) {
    let guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
    let mut out = String::new();
    for job in &guard.seen {
        if let Ok(line) = serde_json::to_string(job) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    let _ = std::fs::write(data_dir.join("jobs.jsonl"), out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cd-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ok_config(dir: PathBuf, bin: PathBuf) -> DaemonConfig {
        DaemonConfig {
            data_dir: dir,
            max_concurrent_jobs: 2,
            govfuzz_bin: bin,
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        }
    }

    #[test]
    fn start_rejects_missing_data_dir() {
        let config = DaemonConfig {
            data_dir: PathBuf::from("/nonexistent"),
            max_concurrent_jobs: 1,
            govfuzz_bin: PathBuf::from("/bin/true"),
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        };
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::DataDirMissing(_))
        ));
    }

    #[test]
    fn start_rejects_missing_bin() {
        let dir = tempdir("missing-bin");
        let config = DaemonConfig {
            data_dir: dir,
            max_concurrent_jobs: 1,
            govfuzz_bin: PathBuf::from("/nonexistent/govfuzz"),
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        };
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::BinMissing(_))
        ));
    }

    #[test]
    fn submit_and_list_returns_queued_job() {
        let dir = tempdir("submit");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        assert!(id.starts_with("J-"));
        let jobs = scheduler.list_jobs().unwrap();
        assert!(jobs.iter().any(|j| j.job_id == id));
    }

    #[test]
    fn worker_runs_submitted_job_to_completion_against_bin_true() {
        let dir = tempdir("run-complete");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let jobs = scheduler.list_jobs().unwrap();
            let job = jobs.iter().find(|j| j.job_id == id).expect("job present");
            if matches!(job.state, JobState::Complete | JobState::Failed) {
                assert_eq!(job.state, JobState::Complete);
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("job did not finish within 3s: {job:?}");
            }
        }
    }

    #[test]
    fn worker_marks_failure_when_bin_exits_nonzero() {
        let dir = tempdir("run-fail");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/false"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let jobs = scheduler.list_jobs().unwrap();
            let job = jobs.iter().find(|j| j.job_id == id).expect("job present");
            if matches!(job.state, JobState::Complete | JobState::Failed) {
                assert_eq!(job.state, JobState::Failed);
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("job did not finish within 3s: {job:?}");
            }
        }
    }

    #[test]
    fn parse_http_url_handles_explicit_port() {
        let parsed = super::parse_http_url("http://localhost:9090/notify").unwrap();
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 9090);
        assert_eq!(parsed.path, "/notify");
    }

    #[test]
    fn parse_http_url_defaults_port_80() {
        let parsed = super::parse_http_url("http://example.com/").unwrap();
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/");
    }

    #[test]
    fn parse_http_url_defaults_port_443_for_https() {
        let parsed = super::parse_http_url("https://example.com/x").unwrap();
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn parse_http_status_picks_status_code() {
        let response = b"HTTP/1.1 204 No Content\r\nFoo: bar\r\n\r\n";
        assert_eq!(super::parse_http_status(response), Some(204));
    }

    #[test]
    fn post_webhook_rejects_invalid_url() {
        let result = post_webhook("not-a-url", "{}");
        assert!(result.is_err());
    }

    #[test]
    fn post_webhook_rejects_https_v0_1() {
        let result = post_webhook("https://example.com/notify", "{}");
        assert!(result.is_err());
    }

    #[test]
    fn post_webhook_with_timeout_fires_on_silent_server() {
        // Bind a listener that accepts then never responds. The
        // webhook client should give up within ~timeout instead of
        // hanging the worker thread.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _acceptor = std::thread::spawn(move || {
            // Accept one connection and immediately drop it from
            // this scope — but keep the stream alive in the closure's
            // local so it doesn't close, simulating a server that
            // never writes a response.
            let held: Vec<std::net::TcpStream> =
                listener.incoming().take(1).filter_map(Result::ok).collect();
            std::thread::sleep(std::time::Duration::from_secs(2));
            drop(held);
        });
        let url = format!("http://127.0.0.1:{port}/hook");
        let start = std::time::Instant::now();
        let result = post_webhook_with_timeout(&url, "{}", std::time::Duration::from_millis(250));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "should error on silent server");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "client should give up within ~timeout, took {elapsed:?}"
        );
    }

    #[test]
    fn restart_recovers_queued_jobs_from_disk() {
        let dir = tempdir("restart");
        {
            let scheduler =
                Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/sleep"))).unwrap();
            scheduler
                .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
                .unwrap();
            // Drop scheduler — workers may have started but with
            // /bin/sleep + no args sleep exits 1; we don't care
            // about completion here, only that disk persistence ran.
        }
        // Inspect the persisted file directly to confirm something
        // landed; a fresh scheduler should also see at least one job.
        let jobs_file = std::fs::read(dir.join("jobs.jsonl")).unwrap();
        assert!(!jobs_file.is_empty());
        let scheduler = Scheduler::start(&ok_config(dir, PathBuf::from("/bin/true"))).unwrap();
        let jobs = scheduler.list_jobs().unwrap();
        assert!(!jobs.is_empty());
    }
}
