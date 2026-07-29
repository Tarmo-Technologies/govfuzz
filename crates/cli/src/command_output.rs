// SPDX-License-Identifier: Apache-2.0

//! Bounded subprocess capture for build/smoke-test commands that must inspect
//! stdout or stderr. Source-controlled build/import code can print forever, so
//! `Command::output` is not safe at this trust boundary.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn max_stream_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_SUBPROCESS_OUTPUT_BYTES",
        1024,
        4 * crate::resource_limits::MIB,
        4 * crate::resource_limits::MIB,
        64 * crate::resource_limits::MIB,
    )
}

pub(crate) struct BoundedOutput {
    pub(crate) output: Output,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) timed_out: bool,
}

#[cfg(unix)]
fn prepare_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child(_command: &mut Command) {}

#[cfg(unix)]
fn kill_child_tree(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn read_head_tail(mut reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
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
                tail.drain(..excess.min(tail.len()));
                truncated = true;
                if bytes.len() > tail_cap {
                    bytes = &bytes[bytes.len() - tail_cap..];
                }
            }
            tail.extend(bytes);
        }
    }
    if truncated {
        head.extend_from_slice(b"\n[govfuzz: subprocess output truncated]\n");
    }
    head.extend(tail);
    (head, truncated)
}

/// A whole-run deadline that every subprocess is clamped to.
///
/// Build steps carry generous individual timeouts (30 minutes for a compile),
/// which is right for one target and wrong for a bounded sweep: a single slow
/// build outlasted a `--campaign-time 150` run by minutes, so the budget the
/// operator set did not describe the run. Setting this makes every child
/// inherit "whatever is left", so the campaign ends when it was asked to.
static CAMPAIGN_DEADLINE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Work already in flight when the budget runs out gets this much longer to
/// finish, so the last target is cut off cleanly rather than mid-link.
///
/// A QUARTER of the campaign, capped at two minutes and floored at ten seconds
/// — not a flat two minutes. A round may start moments before the deadline and
/// its compile then runs for the whole grace, so a flat grace is added to every
/// campaign no matter how small: with `--campaign-time 120` it DOUBLED the
/// phase, and Proton's run came to 84s discovery + 120s campaign + 120s grace
/// against a 510s allowance. Scaling keeps the overshoot proportional to the
/// budget the operator actually set.
static CAMPAIGN_GRACE: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

/// The operator's whole campaign budget, used to size the grace and the
/// per-subprocess ceiling.
static CAMPAIGN_TOTAL: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

fn campaign_grace() -> Duration {
    *CAMPAIGN_GRACE.get().unwrap_or(&Duration::from_secs(120))
}

/// Bound every subsequent subprocess by `deadline`. Idempotent: the first
/// deadline set for a process wins, so nested code cannot extend it.
///
/// `campaign` is the operator's total budget, used to size the grace.
pub(crate) fn set_campaign_deadline(deadline: Instant, campaign: Option<Duration>) {
    let _ = CAMPAIGN_DEADLINE.set(deadline);
    if let Some(campaign) = campaign {
        let _ = CAMPAIGN_TOTAL.set(campaign);
        // Publish the same ceiling to crates that spawn compilers themselves and
        // cannot depend on this module (compiler_adapter runs gprbuild).
        std::env::set_var(
            "GOVFUZZ_SUBPROCESS_TIMEOUT_SECS",
            (campaign / 4)
                .max(Duration::from_secs(15))
                .as_secs()
                .to_string(),
        );
        let _ = CAMPAIGN_GRACE
            .set((campaign / 4).clamp(Duration::from_secs(10), Duration::from_secs(120)));
    }
}

/// Has the operator's budget passed? Callers use this to stop starting work
/// that cannot finish, and to report an honest "budget exhausted" instead of a
/// mystery build failure. Deliberately the REAL deadline, not the grace-padded
/// one the subprocess clamp uses: work already running gets the grace, new
/// rounds do not.
pub(crate) fn campaign_budget_exhausted() -> bool {
    CAMPAIGN_DEADLINE
        .get()
        .is_some_and(|deadline| Instant::now() >= *deadline)
}

/// The effective timeout: the caller's, or the time left in the campaign (plus
/// the grace) when that is shorter. A floor keeps a nearly-expired budget from
/// spawning processes that are killed before they can do anything.
fn clamp_to_campaign(timeout: Duration) -> Duration {
    let Some(deadline) = CAMPAIGN_DEADLINE.get() else {
        return timeout;
    };
    let remaining = (*deadline + campaign_grace())
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(5));
    // No SINGLE subprocess may take more than a quarter of the campaign, even
    // while the whole budget is still unspent. Remaining-time alone does not stop
    // the FIRST build from eating everything: on AdaCore/gnat-llvm one generated
    // harness sent `gnat1` into a spin and, because the budget was untouched, the
    // clamp allowed it the entire campaign — one target consumed the run and it
    // was killed with nothing to show. A build that cannot finish in a quarter of
    // the budget leaves no time to fuzz what it produces.
    timeout.min(remaining).min(per_call_ceiling())
}

/// The most any one subprocess may take: a quarter of the campaign, floored at
/// 15s so a small budget can still run a compiler. Unbounded with no campaign.
fn per_call_ceiling() -> Duration {
    CAMPAIGN_TOTAL
        .get()
        .map(|total| (*total / 4).max(Duration::from_secs(15)))
        .unwrap_or(Duration::MAX)
}

/// Run a command to completion with INHERITED stdio (so compiler output still
/// streams to the terminal), bounded by the same campaign clamp as
/// [`output_with_timeout`], in its own process group so a timeout kills the
/// whole tree.
///
/// `Command::status()` does none of that. A generated Ada harness that sent
/// `gnat1` into a spin ran `gprbuild` for the entire campaign on
/// AdaCore/gnat-llvm, and because the child was neither grouped nor
/// death-signalled it SURVIVED govfuzz being killed: orphaned `gprbuild`/`gcc`/
/// `gnat1` processes were found still running 39 hours after their sweep,
/// stealing CPU from every later run on the machine.
pub(crate) fn status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<std::process::ExitStatus> {
    prepare_child(command);
    let mut child = command.spawn()?;
    let deadline = Instant::now() + clamp_to_campaign(timeout);
    loop {
        match child.try_wait() {
            Err(error) => {
                kill_child_tree(&mut child);
                let _ = child.wait();
                return Err(error);
            }
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_child_tree(&mut child);
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out (campaign budget)",
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Run a command with bounded stdout/stderr and a wall-clock timeout. Both pipes
/// are drained concurrently so a noisy child cannot deadlock on a full pipe.
pub(crate) fn output_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    capture_with_timeout(command, clamp_to_campaign(timeout), max_stream_bytes())
        .map(|captured| captured.output)
}

/// Variant for consumers (notably external analyzer JSON) that need to reject a
/// truncated stream rather than treating the bounded head/tail as complete data.
pub(crate) fn capture_with_timeout(
    command: &mut Command,
    timeout: Duration,
    max_stream_bytes: usize,
) -> io::Result<BoundedOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    prepare_child(command);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || read_head_tail(pipe, max_stream_bytes)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || read_head_tail(pipe, max_stream_bytes)));
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Err(error) => {
                kill_child_tree(&mut child);
                let _ = child.wait();
                // Reaping closes the pipes so the readers cannot remain blocked.
                let _ = stdout.and_then(|reader| reader.join().ok());
                let _ = stderr.and_then(|reader| reader.join().ok());
                return Err(error);
            }
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() >= deadline => {
                kill_child_tree(&mut child);
                break (child.wait()?, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let (stdout, stdout_truncated) = stdout
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let (mut stderr, stderr_truncated) = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    if timed_out {
        stderr.extend_from_slice(b"\ngovfuzz: subprocess exceeded its wall-clock timeout\n");
    }
    Ok(BoundedOutput {
        output: Output {
            status,
            stdout,
            stderr,
        },
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn captures_both_streams() {
        let output = output_with_timeout(
            Command::new("sh")
                .arg("-c")
                .arg("printf out; printf err >&2"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    #[cfg(unix)]
    fn timeout_reaps_descendants_holding_capture_pipes() {
        let start = Instant::now();
        let output = output_with_timeout(
            Command::new("sh").arg("-c").arg("sleep 30 & wait"),
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(!output.status.success());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("wall-clock timeout"));
    }

    #[test]
    fn bounded_capture_reports_truncation() {
        let (bytes, truncated) = read_head_tail(&b"0123456789abcdef"[..], 8);
        assert!(truncated);
        assert!(bytes.starts_with(b"0123"));
        assert!(bytes.ends_with(b"cdef"));
    }

    #[test]
    fn a_campaign_deadline_clamps_subprocess_timeouts_but_grants_a_grace() {
        // Without a deadline the caller's timeout is used verbatim.
        assert_eq!(
            clamp_to_campaign(Duration::from_secs(1800)),
            Duration::from_secs(1800)
        );

        // With one, a generous build timeout is cut to what is left plus the
        // grace: a 30-minute compile must not outlive a two-minute campaign.
        set_campaign_deadline(
            Instant::now() + Duration::from_secs(60),
            Some(Duration::from_secs(60)),
        );
        let clamped = clamp_to_campaign(Duration::from_secs(1800));
        // The grace is a quarter of the campaign (15s here), not a flat two
        // minutes, so a small budget is not doubled by the margin.
        assert!(
            clamped <= Duration::from_secs(60) + campaign_grace(),
            "clamped to {clamped:?}"
        );
        assert_eq!(campaign_grace(), Duration::from_secs(15));
        assert!(
            clamped >= Duration::from_secs(5),
            "a floor keeps work possible"
        );
        // A timeout shorter than the remaining budget is left alone.
        assert_eq!(
            clamp_to_campaign(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        // The budget itself has not passed yet, so new work may still start.
        assert!(!campaign_budget_exhausted());
    }
}
