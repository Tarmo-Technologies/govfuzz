// SPDX-License-Identifier: Apache-2.0

//! Fuzz-driven capability profiling — what can attacker input make the program DO?
//!
//! Crash-only fuzzers report where the program *breaks*. govfuzz's runtrace shim
//! also records what the program *does*: every process exec, filesystem open,
//! network connect, dlopen, and format-string call, with byte-origin taint (#422).
//! This pass turns that stream into a security signal by DIFFING two populations:
//! a set of baseline (empty / unstructured) inputs vs the coverage-guided corpus.
//! A capability the target exercises ONLY once structured input drives its parser
//! deep enough — but never on baseline input — is INPUT-TRIGGERED attack surface
//! (CWE-668, and per-kind CWE-77 exec / CWE-22 path / CWE-134 format): a map of the
//! sphere-of-control an attacker who owns the input can reach, which no crash-only
//! fuzzer produces.
//!
//! Post-campaign and best-effort: it replays each population through the harness's
//! `main` under the shim (fresh process each, so the runtrace log is per-input),
//! folds events into `(kind, operand)` capability sets, and emits ONE clustered
//! GF-668 finding per `(harness, kind)` whose input-triggered operand set is
//! non-empty, plus an `auto/capabilities.json` profile. Native lanes (C/C++/Rust)
//! only — the interpreted/JVM lanes run without the shim. A missing shim, an empty
//! corpus, or a non-native harness all skip cleanly.

use crate::auto::runtrace::{self, RuntraceEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Cap corpus replays per harness so a huge queue can't stall the run.
const MAX_CORPUS: usize = 400;
const PROFILE_BUDGET: Duration = Duration::from_secs(30);

/// Profile every native harness's capabilities and emit GF-668 findings for the
/// input-triggered ones. Returns the number of findings written.
pub fn run_capability_profile(work_dir: &Path) -> usize {
    let Some(shim) = crate::auto::shim_path::locate() else {
        return 0; // no shim -> no runtrace -> nothing to profile.
    };
    let ld_preload = crate::auto::shim_path::ld_preload_value_with(
        &shim,
        std::env::var("LD_PRELOAD").ok().as_deref(),
    );
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut profiles = Vec::new();
    let mut written = 0usize;
    let mut index = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if let Some(profile) = profile_one(work_dir, &hdir, &harness_id, &ld_preload, &mut index) {
            written += profile.findings_written;
            profiles.push(profile.json);
        }
    }
    if !profiles.is_empty() {
        let out = json!({ "schema": "govfuzz.capabilities/v1", "harnesses": profiles });
        let dir = work_dir.join("auto");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(
            dir.join("capabilities.json"),
            serde_json::to_vec_pretty(&out).unwrap_or_default(),
        );
    }
    written
}

/// A capability: an OS action keyed by kind + normalized operand.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Capability {
    kind: &'static str,
    operand: String,
    /// Any input byte offset that flowed into the operand (path taint / controlled
    /// format), when the shim recorded it.
    tainted: bool,
}

struct HarnessProfile {
    json: serde_json::Value,
    findings_written: usize,
}

fn profile_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    ld_preload: &str,
    index: &mut usize,
) -> Option<HarnessProfile> {
    let bin = hdir.join("main");
    if !bin.is_file() || !is_native_harness(hdir, harness_id) {
        return None;
    }
    let deadline = Instant::now() + PROFILE_BUDGET;
    // Baseline: empty + deterministic unstructured buffers (no magic-gate structure).
    let baseline = baseline_inputs();
    let mut baseline_caps: BTreeSet<Capability> = BTreeSet::new();
    let scratch = hdir.join("cap_scratch");
    let _ = std::fs::create_dir_all(&scratch);
    for (i, input) in baseline.iter().enumerate() {
        if Instant::now() >= deadline {
            let _ = std::fs::remove_dir_all(&scratch);
            return None;
        }
        let path = scratch.join(format!("base_{i}.bin"));
        if std::fs::write(&path, input).is_ok() {
            if !replay_into(&bin, &path, ld_preload, hdir, &mut baseline_caps) {
                let _ = std::fs::remove_dir_all(&scratch);
                return None;
            }
        }
    }

    // Fuzz population: the coverage-guided corpus queue.
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let mut fuzz_caps: BTreeSet<Capability> = BTreeSet::new();
    let mut replayed = 0usize;
    if let Ok(inputs) = std::fs::read_dir(&queue) {
        for input in inputs.flatten() {
            if replayed >= MAX_CORPUS || Instant::now() >= deadline {
                break;
            }
            let p = input.path();
            if p.is_file() {
                replayed += 1;
                if !replay_into(&bin, &p, ld_preload, hdir, &mut fuzz_caps) {
                    let _ = std::fs::remove_dir_all(&scratch);
                    return None;
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);

    // Input-triggered = exercised by the corpus, never by any baseline input.
    let baseline_keys: BTreeSet<(&str, &str)> = baseline_caps
        .iter()
        .map(|c| (c.kind, c.operand.as_str()))
        .collect();
    let input_triggered: Vec<&Capability> = fuzz_caps
        .iter()
        .filter(|c| !baseline_keys.contains(&(c.kind, c.operand.as_str())))
        .collect();

    // Group the input-triggered capabilities by kind and emit one finding per kind.
    let mut by_kind: BTreeMap<&'static str, Vec<&Capability>> = BTreeMap::new();
    for cap in &input_triggered {
        by_kind.entry(cap.kind).or_default().push(cap);
    }
    let mut findings_written = 0usize;
    for (kind, caps) in &by_kind {
        if !kind_is_reportable(kind) {
            continue;
        }
        let id = format!("F-CAP-{:04}", *index);
        *index += 1;
        if write_capability_finding(work_dir, &id, hdir, harness_id, kind, caps) {
            findings_written += 1;
        }
    }

    let profile = json!({
        "harness_id": harness_id,
        "baseline_inputs": baseline.len(),
        "corpus_inputs": replayed,
        "baseline_capabilities": baseline_caps.iter().map(cap_json).collect::<Vec<_>>(),
        "input_triggered_capabilities": input_triggered.iter().map(|c| cap_json(c)).collect::<Vec<_>>(),
    });
    Some(HarnessProfile {
        json: profile,
        findings_written,
    })
}

/// Replay one input through the harness under the shim, folding its runtrace into
/// the capability set.
fn replay_into(
    bin: &Path,
    input: &Path,
    ld_preload: &str,
    hdir: &Path,
    caps: &mut BTreeSet<Capability>,
) -> bool {
    let log = hdir.join("cap_runtrace.jsonl");
    let _ = std::fs::write(&log, "");
    let mut command = replay_command(bin);
    command
        .arg(input)
        .env("LD_PRELOAD", ld_preload)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "reporting")
        // Don't let a crashing corpus input abort the profiling replay noisily; ASan
        // still records what ran before the fault. `symbolize=0` is load-bearing: the
        // coverage-instrumented `main` otherwise HANGS in the ASan crash symbolizer
        // (run without the shim's symbolizer scoping in this post-hoc replay), which
        // would wedge the whole capability pass on the first crashing input.
        .env("ASAN_OPTIONS", "abort_on_error=0:exitcode=0:symbolize=0");
    let completed = crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(15),
    )
    .map(|output| !matches!(output.status.code(), Some(124 | 137)))
    .unwrap_or(false);
    let mut events = runtrace::parse_log(&log).unwrap_or_default();
    runtrace::dedupe_in_place(&mut events);
    let _ = std::fs::remove_file(&log);
    for ev in &events {
        if let Some(cap) = classify(ev) {
            caps.insert(cap);
        }
    }
    completed
}

/// Build the replay command, wrapping in `timeout` when available so a
/// pathological corpus input can never wedge the profiling pass.
fn replay_command(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut cmd = Command::new("timeout");
        cmd.arg("-s").arg("KILL").arg("10").arg(bin);
        cmd
    } else {
        Command::new(bin)
    }
}

/// Map a runtrace event to a security-relevant capability, or `None` for noise.
fn classify(ev: &RuntraceEvent) -> Option<Capability> {
    let cap = match ev {
        RuntraceEvent::CommandExecuted { command, .. } => Capability {
            kind: "process-exec",
            operand: command.clone(),
            tainted: false,
        },
        RuntraceEvent::FileOpened {
            path, taint_offset, ..
        }
        | RuntraceEvent::FileMissing {
            path, taint_offset, ..
        } => Capability {
            kind: "filesystem-path",
            operand: path.clone(),
            tainted: taint_offset.is_some(),
        },
        RuntraceEvent::PathChecked { path, .. } => Capability {
            kind: "filesystem-path",
            operand: path.clone(),
            tainted: false,
        },
        RuntraceEvent::FileDeleted { path, .. } => Capability {
            kind: "filesystem-delete",
            operand: path.clone(),
            tainted: false,
        },
        RuntraceEvent::NetworkUnreachable { address, .. } => Capability {
            kind: "network-connect",
            operand: address.clone(),
            tainted: false,
        },
        RuntraceEvent::DlopenFailed { library } => Capability {
            kind: "dynamic-load",
            operand: library.clone(),
            tainted: false,
        },
        RuntraceEvent::FormatString {
            format, controlled, ..
        } => Capability {
            kind: "format-string",
            operand: format.clone(),
            tainted: *controlled,
        },
        RuntraceEvent::InsecureTempFile { path, .. } => Capability {
            kind: "insecure-temp",
            operand: path.clone(),
            tainted: false,
        },
        RuntraceEvent::EnvVarAccess { name, .. } | RuntraceEvent::EnvVarMissing { name, .. } => {
            Capability {
                kind: "env-read",
                operand: name.clone(),
                tainted: false,
            }
        }
        _ => return None,
    };
    Some(cap)
}

/// Whether a capability kind is worth a finding (high-signal attack surface). The
/// full set — including `env-read` — is always recorded in the JSON profile.
fn kind_is_reportable(kind: &str) -> bool {
    matches!(
        kind,
        "process-exec"
            | "filesystem-path"
            | "filesystem-delete"
            | "network-connect"
            | "dynamic-load"
            | "format-string"
            | "insecure-temp"
            | "env-read"
    )
}

/// The most-specific CWE for a capability kind.
fn cwe_for(kind: &str) -> &'static str {
    match kind {
        "process-exec" => "CWE-77",
        "filesystem-path" | "filesystem-delete" => "CWE-22",
        "network-connect" => "CWE-668",
        "dynamic-load" => "CWE-114",
        "format-string" => "CWE-134",
        "insecure-temp" => "CWE-377",
        _ => "CWE-668",
    }
}

fn human_kind(kind: &str) -> &'static str {
    match kind {
        "process-exec" => "execute a process",
        "filesystem-path" => "open a filesystem path",
        "filesystem-delete" => "delete a file",
        "network-connect" => "open a network connection",
        "dynamic-load" => "dynamically load a library",
        "format-string" => "evaluate a format string",
        "insecure-temp" => "create an insecure temp file",
        "env-read" => "read an environment variable",
        _ => "exercise an OS capability",
    }
}

/// Write one clustered GF-668 finding for a `(harness, kind)` with a non-empty
/// input-triggered operand set. Deliberately carries NO `actionability.sink` so the
/// fuzz-confirmation join does not index it as a crash site.
fn write_capability_finding(
    work: &Path,
    id: &str,
    hdir: &Path,
    harness_id: &str,
    kind: &str,
    caps: &[&Capability],
) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let (name, source_path, line) = candidate_site(hdir);
    let cwe = cwe_for(kind);
    let tainted = caps.iter().any(|c| c.tainted);
    let mut operands: Vec<String> = caps.iter().map(|c| c.operand.clone()).collect();
    operands.sort();
    operands.dedup();
    let examples: Vec<String> = operands.iter().take(8).cloned().collect();
    let cluster_key_full = hex(&Sha256::digest(
        format!("GF-668:{harness_id}:{kind}").as_bytes(),
    ));
    let taint_note = if tainted {
        " At least one operand is directly controlled by an input byte (byte-origin taint)."
    } else {
        ""
    };
    let message = format!(
        "Attacker input can make {name} {} — this capability is exercised by the fuzz corpus but by no baseline input, so it is input-triggered attack surface.{taint_note}",
        human_kind(kind)
    );
    let record = json!({
        "id": id,
        "rule_id": "GF-668",
        "classification": "capability",
        "severity": if tainted { "high" } else { "medium" },
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": source_path, "line": line },
        "exception": { "name": "INPUT_TRIGGERED_CAPABILITY", "message": message },
        "capability": {
            "kind": kind,
            "input_triggered": true,
            "input_controlled": tainted,
            "operand_count": operands.len(),
            "examples": examples,
        },
        "oracle": { "evidence": [ { "key": "source", "value": format!("{source_path}:{line}") } ] },
        "analysis": { "engine": "govfuzz.dynamic.capability.diff" },
        "actionability": {
            "cwe": [cwe],
            "verdict": "likely_reachable",
            "confidence": if tainted { "high" } else { "medium" }
        },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

/// The `(name, source_path, line)` of the harness's candidate, from `result.json`.
fn candidate_site(hdir: &Path) -> (String, String, u64) {
    let default = (
        hdir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("target")
            .to_owned(),
        String::new(),
        0,
    );
    let Some(raw) = read_json(&hdir.join("result.json")) else {
        return default;
    };
    let name = raw
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&default.0)
        .to_owned();
    let source_path = raw
        .get("source_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let line = raw.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
    (name, source_path, line)
}

/// Native lanes carry the runtrace shim; the JVM lane and interpreted lanes do not.
/// The harness id prefix encodes the lane (`H-C` C, `H-X` C++, `H-R` Rust).
fn is_native_harness(hdir: &Path, harness_id: &str) -> bool {
    if !(harness_id.starts_with("H-C")
        || harness_id.starts_with("H-X")
        || harness_id.starts_with("H-R"))
    {
        return false;
    }
    // A JVM launcher script masquerades as `main`; never a native ELF.
    !std::fs::read_to_string(hdir.join("main"))
        .map(|s| s.contains("GOVFUZZ_JVM_LAUNCHER"))
        .unwrap_or(false)
}

/// Deterministic baseline inputs: empty, all-zero, all-one, and a couple of
/// fixed-pattern buffers at several sizes. Deliberately unstructured so a magic /
/// length gate is NOT satisfied by chance.
fn baseline_inputs() -> Vec<Vec<u8>> {
    let mut out = vec![Vec::new()];
    for &size in &[1usize, 4, 16, 64, 256] {
        out.push(vec![0x00; size]);
        out.push(vec![0xff; size]);
        out.push(
            (0..size)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect(),
        );
    }
    out
}

fn cap_json(c: &Capability) -> serde_json::Value {
    json!({ "kind": c.kind, "operand": c.operand, "input_controlled": c.tainted })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_exec_and_taints_path() {
        let exec = classify(&RuntraceEvent::CommandExecuted {
            api: "system".into(),
            command: "/bin/sh -c ls".into(),
            taint_offset: None,
        })
        .unwrap();
        assert_eq!(exec.kind, "process-exec");
        assert_eq!(cwe_for(exec.kind), "CWE-77");

        let open = classify(&RuntraceEvent::FileOpened {
            syscall: "open".into(),
            fd: 3,
            path: "/tmp/../etc/passwd".into(),
            taint_offset: Some(2),
        })
        .unwrap();
        assert_eq!(open.kind, "filesystem-path");
        assert!(open.tainted);
        assert_eq!(cwe_for(open.kind), "CWE-22");
    }

    #[test]
    fn baseline_inputs_are_deterministic_and_unstructured() {
        let a = baseline_inputs();
        let b = baseline_inputs();
        assert_eq!(a, b, "baseline generation must be deterministic");
        assert!(a[0].is_empty(), "first baseline is the empty input");
        assert!(a.len() >= 10);
    }

    #[test]
    fn input_triggered_diff_excludes_baseline_capabilities() {
        // Baseline reads env LOCALE; fuzz reads LOCALE + execs a command.
        let baseline: BTreeSet<Capability> = [Capability {
            kind: "env-read",
            operand: "LOCALE".into(),
            tainted: false,
        }]
        .into_iter()
        .collect();
        let fuzz: BTreeSet<Capability> = [
            Capability {
                kind: "env-read",
                operand: "LOCALE".into(),
                tainted: false,
            },
            Capability {
                kind: "process-exec",
                operand: "/bin/sh".into(),
                tainted: false,
            },
        ]
        .into_iter()
        .collect();
        let baseline_keys: BTreeSet<(&str, &str)> = baseline
            .iter()
            .map(|c| (c.kind, c.operand.as_str()))
            .collect();
        let triggered: Vec<&Capability> = fuzz
            .iter()
            .filter(|c| !baseline_keys.contains(&(c.kind, c.operand.as_str())))
            .collect();
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].kind, "process-exec");
    }

    #[test]
    fn write_finding_has_no_sink_and_carries_cwe() {
        let work = std::env::temp_dir().join(format!("gf-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        let hdir = work.join("harnesses").join("H-C0001");
        std::fs::create_dir_all(&hdir).unwrap();
        std::fs::write(
            hdir.join("result.json"),
            serde_json::to_vec(&json!({ "name": "parse", "source_path": "/p/x.c", "line": 12 }))
                .unwrap(),
        )
        .unwrap();
        let cap = Capability {
            kind: "process-exec",
            operand: "/bin/sh -c id".into(),
            tainted: true,
        };
        assert!(write_capability_finding(
            &work,
            "F-CAP-0000",
            &hdir,
            "H-C0001",
            "process-exec",
            &[&cap]
        ));
        let raw = read_json(&work.join("findings/F-CAP-0000/finding.json")).unwrap();
        assert_eq!(raw["rule_id"], "GF-668");
        assert_eq!(raw["actionability"]["cwe"][0], "CWE-77");
        assert_eq!(raw["severity"], "high"); // tainted -> high
        assert!(
            raw.pointer("/actionability/sink").is_none(),
            "must not carry a sink"
        );
        assert_eq!(raw["capability"]["kind"], "process-exec");
        let _ = std::fs::remove_dir_all(&work);
    }
}
