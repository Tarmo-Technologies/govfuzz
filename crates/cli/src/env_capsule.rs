// SPDX-License-Identifier: Apache-2.0

//! `govfuzz env-capsule` — record + replay the shim-served virtualized world for a
//! crash that depends on the ENVIRONMENT, not (only) the fuzz input.
//!
//! govfuzz fuzzes the content of "trusted" external resources — a config file, a
//! socket peer, a shared-memory partition — by faking them and serving fuzz-driven
//! bytes on reads (environment-response fuzzing, #7). A crash found that way is
//! driven by the SERVED bytes, so the minimized primary input is often empty and
//! replaying it alone does not reproduce: the reproducer lives in the faked world,
//! which a plain corpus file cannot carry.
//!
//! This subcommand captures that world. It replays a crashing input under the shim
//! with `GOVFUZZ_ENVCAP_RECORD`, so the shim logs the exact bytes it served each
//! faked resource, and bundles the log (`env-world.jsonl`) with the harness binary,
//! the shim, the input, and a `replay.sh`. On replay the shim serves those exact
//! bytes back (`GOVFUZZ_ENVCAP_REPLAY`), so the crash reproduces DETERMINISTICALLY
//! — even from an empty input — because the environment is pinned. Each capsule is
//! verified to reproduce before it is finalized.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_CANDIDATES: usize = 64;

/// `govfuzz env-capsule` — bundle a replayable faked-environment reproducer.
#[derive(Debug, clap::Args)]
pub struct EnvCapsuleArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Capture only this finding id (default: every C crash).
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,

    /// Directory to write capsules under. Default `<work-dir>/env-capsules`.
    #[arg(long, short = 'o', value_name = "DIR")]
    pub out: Option<PathBuf>,
}

pub fn run(args: EnvCapsuleArgs) -> i32 {
    let Some(shim) = crate::auto::shim_path::locate() else {
        eprintln!(
            "govfuzz env-capsule: the runtrace shim (libgovfuzz_runtrace.so) was not found; \
             it is required to record/replay the faked environment"
        );
        return 1;
    };
    let ld_preload = crate::auto::shim_path::ld_preload_value_with(&shim, None);
    let out_root = args
        .out
        .clone()
        .unwrap_or_else(|| args.work_dir.join("env-capsules"));
    if std::fs::create_dir_all(&out_root).is_err() {
        eprintln!("error: cannot create {}", out_root.display());
        return 1;
    }
    let findings = match collect(&args.work_dir, args.finding_id.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if findings.is_empty() {
        eprintln!(
            "govfuzz env-capsule: no C crash findings in {}",
            args.work_dir.display()
        );
        return 0;
    }
    let mut made = 0usize;
    let mut reproduced = 0usize;
    for f in &findings {
        match build_env_capsule(&args.work_dir, f, &out_root, &shim, &ld_preload) {
            Some(rep) => {
                made += 1;
                if rep.reproduced {
                    reproduced += 1;
                }
                println!(
                    "  {} {}  ({})",
                    f.id,
                    rep.path.display(),
                    if rep.reproduced {
                        "✓ replays"
                    } else {
                        "⚠ not reproduced"
                    }
                );
            }
            None => {
                println!("  {} skipped (no faked-environment crash to capture)", f.id);
            }
        }
    }
    println!(
        "govfuzz env-capsule: {made} capsule(s) in {} ({reproduced} verified to replay)",
        out_root.display()
    );
    0
}

struct FindingRef {
    id: String,
    dir: PathBuf,
    harness_id: String,
}

fn collect(work_dir: &Path, only: Option<&str>) -> anyhow::Result<Vec<FindingRef>> {
    let dir = work_dir.join("findings");
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fdir = entry.path();
        let Some(raw) = read_json(&fdir.join("finding.json")) else {
            continue;
        };
        if raw.get("classification").and_then(Value::as_str) != Some("unhandled") {
            continue;
        }
        let harness_id = match raw.get("harness_id").and_then(Value::as_str) {
            Some(h) if h.starts_with("H-C") => h.to_owned(),
            _ => continue,
        };
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(want) = only {
            if id != want {
                continue;
            }
        }
        out.push(FindingRef {
            id,
            dir: fdir,
            harness_id,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

struct EnvReport {
    path: PathBuf,
    reproduced: bool,
}

fn build_env_capsule(
    work_dir: &Path,
    f: &FindingRef,
    out_root: &Path,
    shim: &Path,
    ld_preload: &str,
) -> Option<EnvReport> {
    let bin = crate::auto::layout::harness_dir(work_dir, &f.harness_id).join("main");
    if !bin.is_file() {
        return None;
    }
    // Find an input that crashes under a faking pass AND records a non-empty served
    // world (the finding's min input is often empty — the crash lives in the faked
    // environment, so we drive it with the corpus inputs that still carry bytes).
    let world_tmp = out_root.join(format!(".world-{}.jsonl", f.id));
    let mut candidates: Vec<PathBuf> = Vec::new();
    let min_input = f.dir.join("testcase.bin");
    if min_input.is_file() {
        candidates.push(min_input.clone());
    }
    candidates.extend(corpus_inputs(work_dir, &f.harness_id));
    let mut recorded: Option<PathBuf> = None;
    for cand in candidates.iter().take(MAX_CANDIDATES) {
        let _ = std::fs::remove_file(&world_tmp);
        if replay_crashes(&bin, cand, ld_preload, Some(&world_tmp), None)
            && world_tmp.is_file()
            && std::fs::metadata(&world_tmp)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        {
            recorded = Some(cand.clone());
            break;
        }
    }
    let crashing_input = recorded?;

    // Assemble the capsule.
    let cap = out_root.join(format!("env_capsule_{}", f.id));
    let _ = std::fs::remove_dir_all(&cap);
    std::fs::create_dir_all(&cap).ok()?;
    std::fs::rename(&world_tmp, cap.join("env-world.jsonl"))
        .or_else(|_| std::fs::copy(&world_tmp, cap.join("env-world.jsonl")).map(|_| ()))
        .ok()?;
    let _ = std::fs::remove_file(&world_tmp);
    // Prefer the finding's min input for the shipped reproducer (it proves the world
    // alone reproduces); fall back to the crashing candidate.
    let input_for_capsule = if min_input.is_file() {
        &min_input
    } else {
        &crashing_input
    };
    std::fs::copy(input_for_capsule, cap.join("input.bin")).ok()?;
    std::fs::copy(&bin, cap.join("main")).ok()?;
    set_executable(&cap.join("main"));
    std::fs::copy(shim, cap.join("libgovfuzz_runtrace.so")).ok()?;

    // Verify: replay the recorded world with the shipped input; it must crash.
    let world_path = cap.join("env-world.jsonl");
    let reproduced = replay_crashes(
        &cap.join("main"),
        &cap.join("input.bin"),
        "./libgovfuzz_runtrace.so",
        None,
        Some(&world_path),
    );

    std::fs::write(cap.join("replay.sh"), replay_script()).ok()?;
    set_executable(&cap.join("replay.sh"));
    write_manifest(&cap, f, reproduced);
    std::fs::write(cap.join("README.md"), readme(&f.id)).ok()?;

    Some(EnvReport {
        path: cap,
        reproduced,
    })
}

/// Replay `input` through `bin` under the shim in a faking pass. `record` pins a
/// `GOVFUZZ_ENVCAP_RECORD` log; `replay` pins a `GOVFUZZ_ENVCAP_REPLAY` world.
/// Returns whether a sanitizer crash was observed.
fn replay_crashes(
    bin: &Path,
    input: &Path,
    ld_preload: &str,
    record: Option<&Path>,
    replay: Option<&Path>,
) -> bool {
    let dir = bin.parent().unwrap_or(Path::new("."));
    let mut cmd = timeout_wrap(bin);
    cmd.arg(input)
        .current_dir(dir)
        .env("LD_PRELOAD", ld_preload)
        .env("GOVFUZZ_RUNTRACE_MODE", "fuzz_driven")
        .env(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=0:detect_leaks=0",
        );
    if let Some(rec) = record {
        cmd.env("GOVFUZZ_ENVCAP_RECORD", rec);
    }
    if let Some(rep) = replay {
        cmd.env("GOVFUZZ_ENVCAP_REPLAY", rep);
    }
    let Ok(out) = cmd.output() else {
        return false;
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    stderr.contains("AddressSanitizer")
        || stderr.contains("UndefinedBehaviorSanitizer")
        || stderr.contains("runtime error:")
}

fn timeout_wrap(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut cmd = Command::new("timeout");
        cmd.arg("-s").arg("KILL").arg("10").arg(bin);
        cmd
    } else {
        Command::new(bin)
    }
}

/// The corpus queue inputs for a harness (bounded).
fn corpus_inputs(work_dir: &Path, harness_id: &str) -> Vec<PathBuf> {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(entries) = std::fs::read_dir(&queue) else {
        return Vec::new();
    };
    let mut inputs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // Larger inputs are likelier to carry the bytes the faked resource consumes.
    inputs.sort_by_key(|p| std::cmp::Reverse(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)));
    inputs
}

fn write_manifest(cap: &Path, f: &FindingRef, reproduced: bool) {
    let world_resources = count_world_resources(&cap.join("env-world.jsonl"));
    let manifest = json!({
        "schema": "govfuzz.env-capsule/v1",
        "govfuzz_version": env!("GOVFUZZ_VERSION_FULL"),
        "finding_id": f.id,
        "harness_id": f.harness_id,
        "world": "env-world.jsonl",
        "recorded_resources": world_resources,
        "input": "input.bin",
        "replay": "sh replay.sh",
        "reproduced": reproduced,
        "note": "the shim serves the recorded bytes for each faked resource, so the crash \
                 reproduces deterministically from the pinned environment even when the primary \
                 input is empty",
    });
    let _ = std::fs::write(
        cap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    );
}

fn count_world_resources(world: &Path) -> usize {
    std::fs::read_to_string(world)
        .map(|t| t.lines().filter(|l| l.contains(':')).count())
        .unwrap_or(0)
}

fn replay_script() -> &'static str {
    "#!/bin/sh\n\
     # Reproduce the crash by replaying the recorded faked environment.\n\
     cd \"$(dirname \"$0\")\"\n\
     LD_PRELOAD=./libgovfuzz_runtrace.so \\\n\
     \x20 GOVFUZZ_RUNTRACE_MODE=fuzz_driven \\\n\
     \x20 GOVFUZZ_ENVCAP_REPLAY=env-world.jsonl \\\n\
     \x20 ASAN_OPTIONS=abort_on_error=1:symbolize=0 \\\n\
     \x20 ./main input.bin\n"
}

fn readme(id: &str) -> String {
    format!(
        "# GovFuzz environment capsule — {id}\n\n\
         Reproduces a crash driven by the shim-served (fuzzed) content of a \"trusted\"\n\
         external resource. The reproducer is the recorded ENVIRONMENT, not the input.\n\n\
         ## Reproduce\n\n\
         ```sh\n\
         sh replay.sh\n\
         ```\n\n\
         The shim (`libgovfuzz_runtrace.so`) serves each faked resource the exact bytes\n\
         in `env-world.jsonl`, so the crash fires even though `input.bin` may be empty.\n\n\
         ## Layout\n\n\
         - `main` — the fuzz harness binary\n\
         - `libgovfuzz_runtrace.so` — the resource-virtualization shim\n\
         - `env-world.jsonl` — the recorded served bytes, per faked resource\n\
         - `input.bin` — the primary fuzz input (often empty for env-driven crashes)\n\
         - `manifest.json` — finding metadata\n"
    )
}

fn set_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_world_resources() {
        let dir = std::env::temp_dir().join(format!("gf-envcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let w = dir.join("w.jsonl");
        std::fs::write(&w, "6161:4142\n6262:4344\ngarbage\n").unwrap();
        assert_eq!(count_world_resources(&w), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_script_pins_replay_env() {
        let s = replay_script();
        assert!(s.contains("GOVFUZZ_ENVCAP_REPLAY=env-world.jsonl"));
        assert!(s.contains("LD_PRELOAD=./libgovfuzz_runtrace.so"));
    }
}
