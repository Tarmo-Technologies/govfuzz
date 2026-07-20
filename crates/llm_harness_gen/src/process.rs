// SPDX-License-Identifier: Apache-2.0

use crate::LlmError;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;

fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn host_available_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let value = line.strip_prefix("MemAvailable:")?;
        value
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
            .map(|kb| kb.saturating_mul(1024))
    })
}

#[cfg(target_os = "linux")]
fn cgroup_available_bytes() -> Option<u64> {
    fn remaining(limit_path: &str, usage_path: &str) -> Option<u64> {
        let limit = std::fs::read_to_string(limit_path).ok()?;
        let limit = limit.trim();
        if limit == "max" {
            return None;
        }
        let limit = limit.parse::<u64>().ok()?;
        if limit >= (1_u64 << 60) {
            return None;
        }
        Some(limit.saturating_sub(read_u64(usage_path).unwrap_or(0)))
    }

    remaining("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current").or_else(|| {
        remaining(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        )
    })
}

/// Memory currently available to this process, respecting the Linux cgroup
/// when one is present. Other platforms use the documented fallback.
pub fn available_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        match (host_available_bytes(), cgroup_available_bytes()) {
            (Some(host), Some(cgroup)) => Some(host.min(cgroup)),
            (host, cgroup) => host.or(cgroup),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Resolve an LLM transport/message budget. An exact positive byte count in
/// `env_name` wins; otherwise the default scales with currently available RAM.
pub fn memory_aware_byte_limit(env_name: &str) -> usize {
    if let Some(value) = std::env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
    {
        return value;
    }
    available_memory_bytes()
        .map(|available| {
            usize::try_from(available / 512)
                .unwrap_or(usize::MAX)
                .clamp(MIB, 64 * MIB)
        })
        .unwrap_or(8 * MIB)
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
        head.extend_from_slice(b"\n[govfuzz: provider output truncated]\n");
    }
    head.extend(tail);
    (head, truncated)
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
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

pub(crate) fn run_bounded_command(
    bin: &Path,
    args: &[String],
    input: String,
    timeout: Option<Duration>,
) -> Result<String, LlmError> {
    let cap = memory_aware_byte_limit("GOVFUZZ_LLM_MAX_RESPONSE_BYTES");
    let mut command = Command::new(bin);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare_child(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| LlmError::Provider(format!("spawn {}: {error}", bin.display())))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| LlmError::Provider("provider stdin unavailable".to_owned()))?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        stdin.write_all(input.as_bytes())?;
        drop(stdin);
        Ok(())
    });
    let stdout = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || read_head_tail(pipe, cap)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || read_head_tail(pipe, cap)));

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if timeout.is_some_and(|limit| started.elapsed() >= limit) => {
                kill_child_tree(&mut child);
                break (
                    child.wait().map_err(|error| {
                        LlmError::Provider(format!("wait {}: {error}", bin.display()))
                    })?,
                    true,
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                kill_child_tree(&mut child);
                let _ = child.wait();
                return Err(LlmError::Provider(format!(
                    "wait {}: {error}",
                    bin.display()
                )));
            }
        }
    };
    let _ = writer.join();
    let (stdout, stdout_truncated) = stdout
        .and_then(|thread| thread.join().ok())
        .unwrap_or_default();
    let (stderr, stderr_truncated) = stderr
        .and_then(|thread| thread.join().ok())
        .unwrap_or_default();

    if timed_out {
        return Err(LlmError::Provider(format!(
            "{} timed out after {:?}",
            bin.display(),
            timeout.unwrap_or_default()
        )));
    }
    if stdout_truncated {
        return Err(LlmError::ResponseTooLarge { limit: cap });
    }
    if !status.success() {
        let suffix = if stderr_truncated { " (truncated)" } else { "" };
        return Err(LlmError::Provider(format!(
            "{} exit={:?} stderr={}{}",
            bin.display(),
            status.code(),
            String::from_utf8_lossy(&stderr),
            suffix
        )));
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCli {
    Codex,
    Claude,
}

/// Uses an already-authenticated coding-agent CLI. It reuses the CLI's cached
/// account login, but intentionally starts an ephemeral non-interactive child
/// session with no write-capable tools.
pub struct SessionCliProvider {
    pub kind: SessionCli,
    pub bin: PathBuf,
    pub model: Option<String>,
    pub working_dir: Option<PathBuf>,
    pub timeout: Option<Duration>,
}

impl crate::LlmProvider for SessionCliProvider {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let mut args = Vec::new();
        let input = match self.kind {
            SessionCli::Codex => {
                args.extend([
                    "exec".to_owned(),
                    "--ephemeral".to_owned(),
                    "--sandbox".to_owned(),
                    "read-only".to_owned(),
                    "--skip-git-repo-check".to_owned(),
                    "--color".to_owned(),
                    "never".to_owned(),
                ]);
                if let Some(dir) = &self.working_dir {
                    args.push("-C".to_owned());
                    args.push(dir.to_string_lossy().into_owned());
                }
                if let Some(model) = &self.model {
                    args.push("--model".to_owned());
                    args.push(model.clone());
                }
                args.push("-".to_owned());
                format!("SYSTEM INSTRUCTIONS:\n{system_prompt}\n\nUSER REQUEST:\n{user_prompt}")
            }
            SessionCli::Claude => {
                args.extend([
                    "-p".to_owned(),
                    "--no-session-persistence".to_owned(),
                    "--permission-mode".to_owned(),
                    "plan".to_owned(),
                    "--tools".to_owned(),
                    String::new(),
                    "--output-format".to_owned(),
                    "text".to_owned(),
                    "--system-prompt".to_owned(),
                    system_prompt.to_owned(),
                ]);
                if let Some(model) = &self.model {
                    args.push("--model".to_owned());
                    args.push(model.clone());
                }
                user_prompt.to_owned()
            }
        };
        run_bounded_command(&self.bin, &args, input, self.timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_limit_is_bounded_or_explicit() {
        let value = memory_aware_byte_limit("GOVFUZZ_TEST_MISSING_LLM_LIMIT");
        assert!((MIB..=64 * MIB).contains(&value));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_reaps_a_descendant_that_holds_the_pipe() {
        let started = Instant::now();
        let result = run_bounded_command(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "sleep 30 & wait".to_owned()],
            String::new(),
            Some(Duration::from_millis(50)),
        );
        assert!(matches!(result, Err(LlmError::Provider(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
