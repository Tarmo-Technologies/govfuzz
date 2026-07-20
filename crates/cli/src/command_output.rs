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

/// Run a command with bounded stdout/stderr and a wall-clock timeout. Both pipes
/// are drained concurrently so a noisy child cannot deadlock on a full pipe.
pub(crate) fn output_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    capture_with_timeout(command, timeout, max_stream_bytes()).map(|captured| captured.output)
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
}
