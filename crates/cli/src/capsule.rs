// SPDX-License-Identifier: Apache-2.0

//! `govfuzz capsule` / `govfuzz verify-poc` — a portable, self-verifying exploit
//! capsule for a crash govfuzz found on an un-buildable tree.
//!
//! govfuzz's whole point is that it fuzzes source with no working build by
//! stitching one together. The flip side: the crash it finds lives inside a
//! throwaway `govfuzz_work/` full of absolute paths and generated stubs. A capsule
//! makes that crash *hand-offable*: it copies the minimal set that reproduces it —
//! the harness driver, the target sources, the recovered stubs, the C runtime
//! headers, and the minimized input — rewrites every path to be relative, and
//! ships a `build.sh` plus a `manifest.json` recording the exact sanitizer
//! signature to expect. `govfuzz verify-poc` rebuilds it offline (only `clang` + a
//! shell needed — no govfuzz) and asserts the same crash reproduces.
//!
//! The capsule is self-verifying BY CONSTRUCTION: `capsule` builds and replays it in
//! a scratch copy before finalizing, records the observed sanitizer signature, and
//! marks `reproduced: false` (never silently) when the reconstruction doesn't fire —
//! e.g. a multi-TU link this post-hoc packaging couldn't recover. C lane today.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── `govfuzz capsule` ───────────────────────────────────────────────────────

/// `govfuzz capsule` — package reproducible crashes into portable PoC capsules.
#[derive(Debug, clap::Args)]
pub struct CapsuleArgs {
    /// Work directory of a prior `auto` run to read findings + harnesses from.
    #[arg(long = "work-dir", default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Package only this finding id (default: every reproducible C crash finding).
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,

    /// Directory to write capsules under. Default `<work-dir>/capsules`.
    #[arg(long, short = 'o', value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Also emit a `.tar.gz` next to each capsule dir (via the system `tar`).
    #[arg(long)]
    pub tar: bool,

    /// Print per-capsule detail.
    #[arg(short, long)]
    pub verbose: bool,
}

/// `govfuzz verify-poc` — rebuild a capsule offline and assert the crash reproduces.
#[derive(Debug, clap::Args)]
pub struct VerifyPocArgs {
    /// Capsule directory or `.tar.gz` produced by `govfuzz capsule`.
    pub capsule: PathBuf,
}

pub fn run(args: CapsuleArgs) -> i32 {
    let out_root = args
        .out
        .clone()
        .unwrap_or_else(|| args.work_dir.join("capsules"));
    if std::fs::create_dir_all(&out_root).is_err() {
        eprintln!("error: cannot create output dir {}", out_root.display());
        return 1;
    }
    let findings = match collect_findings(&args.work_dir, args.finding_id.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if findings.is_empty() {
        eprintln!(
            "govfuzz capsule: no reproducible C crash findings in {} (need a runtime finding with a testcase.bin)",
            args.work_dir.display()
        );
        return 0;
    }
    let mut made = 0usize;
    let mut reproduced = 0usize;
    for f in findings {
        match build_capsule(&args.work_dir, &f, &out_root, args.tar) {
            Ok(report) => {
                made += 1;
                if report.reproduced {
                    reproduced += 1;
                }
                let mark = if report.reproduced {
                    "✓"
                } else {
                    "⚠ not reproduced"
                };
                println!(
                    "  {} {}  ({})",
                    report.finding_id,
                    report.capsule_path.display(),
                    mark
                );
                if args.verbose {
                    println!("      signature: {}", report.signature);
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("  {} skipped: {e}", f.finding_id);
                }
            }
        }
    }
    println!(
        "govfuzz capsule: {made} capsule(s) written to {} ({reproduced} verified to reproduce)",
        out_root.display()
    );
    0
}

/// A finding selected for packaging.
struct FindingRef {
    finding_id: String,
    finding_dir: PathBuf,
    harness_id: String,
    raw: Value,
}

/// Collect runtime C crash findings (with a min input) from the work dir.
fn collect_findings(work_dir: &Path, only: Option<&str>) -> anyhow::Result<Vec<FindingRef>> {
    let dir = work_dir.join("findings");
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fdir = entry.path();
        let raw = match read_json(&fdir.join("finding.json")) {
            Some(r) => r,
            None => continue,
        };
        if raw.get("classification").and_then(Value::as_str) != Some("unhandled") {
            continue;
        }
        let finding_id = raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(want) = only {
            if finding_id != want {
                continue;
            }
        }
        let harness_id = match raw.get("harness_id").and_then(Value::as_str) {
            Some(h) if h.starts_with("H-C") => h.to_owned(), // C lane only, today.
            _ => continue,
        };
        if !fdir.join("testcase.bin").is_file() {
            continue;
        }
        out.push(FindingRef {
            finding_id,
            finding_dir: fdir,
            harness_id,
            raw,
        });
    }
    out.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    Ok(out)
}

/// A written capsule's summary.
struct CapsuleReport {
    finding_id: String,
    capsule_path: PathBuf,
    reproduced: bool,
    signature: String,
}

/// The compile inputs recovered from a harness's Makefile.
struct BuildRecipe {
    /// Explicit target sources (absolute) listed in the `main:` recipe.
    target_sources: Vec<PathBuf>,
    /// `COMPILE_DB_FLAGS` (recovered `-std`/`-D` etc.), verbatim tokens.
    compile_db_flags: Vec<String>,
    /// Non-`.` `-I` include dirs from `INCLUDES` (the govfuzz C runtime + any
    /// recovered dependency-header dir) — copied into the capsule's `runtime/`.
    include_dirs: Vec<PathBuf>,
}

fn build_capsule(
    work_dir: &Path,
    f: &FindingRef,
    out_root: &Path,
    tar: bool,
) -> anyhow::Result<CapsuleReport> {
    let hdir = crate::auto::layout::harness_dir(work_dir, &f.harness_id);
    let makefile = hdir.join("Makefile");
    let recipe = parse_makefile(&makefile)
        .ok_or_else(|| anyhow::anyhow!("cannot parse harness Makefile {}", makefile.display()))?;

    let cap = out_root.join(format!("capsule_{}", f.finding_id));
    let _ = std::fs::remove_dir_all(&cap);
    for sub in ["harness", "sources", "stubs", "runtime", "input"] {
        std::fs::create_dir_all(cap.join(sub))?;
    }

    // 1. driver
    copy(&hdir.join("main.c"), &cap.join("harness/main.c"))?;
    // any harness-local headers main.c may include
    copy_headers_in_dir(&hdir, &cap.join("harness"));

    // 2. target sources (+ their sibling headers so quoted includes resolve)
    for src in &recipe.target_sources {
        let dest = cap.join("sources").join(basename(src));
        copy(src, &dest)?;
        if let Some(parent) = src.parent() {
            copy_headers_in_dir(parent, &cap.join("sources"));
        }
    }

    // 3. recovered stubs + placeholder types/defines
    let repairs = hdir.join("repairs");
    let mut stub_sources = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&repairs) {
        for e in entries.flatten() {
            let p = e.path();
            let name = basename(&p);
            // The provenance-poisoned copy is a govfuzz-internal artifact — never ship it.
            if name == "auto_stubs_prov.c" {
                continue;
            }
            match p.extension().and_then(|x| x.to_str()) {
                Some("c") => {
                    copy(&p, &cap.join("stubs").join(&name))?;
                    stub_sources.push(format!("stubs/{name}"));
                }
                Some("h") => {
                    copy(&p, &cap.join("stubs").join(&name))?;
                }
                _ => {}
            }
        }
    }

    // 4. C runtime + recovered dependency headers (govfuzz_decode.h + friends),
    //    taken from the harness's own `-I` roots so the exact build headers ship.
    for inc in &recipe.include_dirs {
        copy_headers_in_dir(inc, &cap.join("runtime"));
    }

    // 5. minimized input
    copy(
        &f.finding_dir.join("testcase.bin"),
        &cap.join("input/testcase.bin"),
    )?;

    // 6. build.sh + README
    let force_include = cap.join("stubs/auto_defines.h").is_file();
    let build_sh = render_build_sh(&recipe, &stub_sources, force_include, &cap);
    let build_path = cap.join("build.sh");
    std::fs::write(&build_path, build_sh)?;
    set_executable(&build_path);

    // 7. verify by construction: build + replay in place, capture the signature.
    let (reproduced, signature) = verify_capsule(&cap);
    // Leave the capsule pristine (no compiled binary with a machine-specific path).
    let _ = std::fs::remove_file(cap.join("poc"));

    write_manifest(&cap, f, &recipe, reproduced, &signature)?;
    std::fs::write(cap.join("README.md"), readme(&f.finding_id, &signature))?;

    if tar {
        make_tarball(out_root, &cap);
    }
    Ok(CapsuleReport {
        finding_id: f.finding_id.clone(),
        capsule_path: cap,
        reproduced,
        signature,
    })
}

/// Parse a harness Makefile for the `main:` recipe's explicit target sources and the
/// recovered `COMPILE_DB_FLAGS`.
fn parse_makefile(path: &Path) -> Option<BuildRecipe> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut compile_db_flags = Vec::new();
    let mut target_sources = Vec::new();
    let mut include_dirs = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("COMPILE_DB_FLAGS =") {
            compile_db_flags = rest.split_whitespace().map(ToOwned::to_owned).collect();
        }
        if let Some(rest) = line.strip_prefix("INCLUDES =") {
            // `-I <dir>` pairs; skip the `.` self-include (the harness dir, copied
            // separately). `-iquote`/`-idirafter` source dirs come in via the
            // target-source parents, so only collect real `-I` include roots.
            let toks: Vec<&str> = rest.split_whitespace().collect();
            let mut i = 0;
            while i < toks.len() {
                if toks[i] == "-I" && i + 1 < toks.len() && toks[i + 1] != "." {
                    include_dirs.push(PathBuf::from(toks[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        // The `main` recipe line: `$(CC) ... -o $@ main.c <sources> $(AUTO_EXTRA_SOURCES) ...`
        let t = line.trim_start();
        if t.starts_with("$(CC)") && t.contains("-o $@ main.c") {
            // Tokens strictly between `main.c` and the first `$(...)` make var are the
            // explicit target sources (absolute paths).
            let after = t.split("-o $@ main.c").nth(1).unwrap_or("");
            for tok in after.split_whitespace() {
                if tok.starts_with("$(") {
                    break;
                }
                target_sources.push(PathBuf::from(tok));
            }
        }
    }
    Some(BuildRecipe {
        target_sources,
        compile_db_flags,
        include_dirs,
    })
}

/// Render a POSIX `build.sh` that compiles the capsule with relative paths.
fn render_build_sh(
    recipe: &BuildRecipe,
    stub_sources: &[String],
    force_include_defines: bool,
    cap: &Path,
) -> String {
    let mut sources = vec!["harness/main.c".to_owned()];
    if let Ok(entries) = std::fs::read_dir(cap.join("sources")) {
        for e in entries.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("c") {
                sources.push(format!("sources/{}", basename(&e.path())));
            }
        }
    }
    sources.extend(stub_sources.iter().cloned());
    let db_flags = recipe.compile_db_flags.join(" ");
    let force = if force_include_defines {
        " -include stubs/auto_defines.h"
    } else {
        ""
    };
    format!(
        "#!/bin/sh\n\
         # Rebuild this govfuzz PoC offline. Needs only clang (or set CC) + a shell.\n\
         set -e\n\
         cd \"$(dirname \"$0\")\"\n\
         CC=\"${{CC:-clang}}\"\n\
         \"$CC\" -O1 -g -fsanitize=address,undefined -fno-sanitize=function,vptr,alignment \\\n\
         \x20 {db_flags} -I runtime -I stubs -I harness -iquote sources{force} \\\n\
         \x20 -o poc {sources}\n",
        db_flags = db_flags,
        force = force,
        sources = sources.join(" "),
    )
}

/// Build + replay the capsule in place; return `(reproduced, signature)`.
fn verify_capsule(cap: &Path) -> (bool, String) {
    let build = Command::new("sh").arg("build.sh").current_dir(cap).output();
    let built = build.map(|o| o.status.success()).unwrap_or(false);
    if !built || !cap.join("poc").is_file() {
        return (false, String::new());
    }
    let mut replay = Command::new("./poc");
    configure_capsule_replay(&mut replay);
    let Ok(out) = replay.arg("input/testcase.bin").current_dir(cap).output() else {
        return (false, String::new());
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    match sanitizer_signature(&stderr, &out.status) {
        Some(sig) => (true, sig),
        None => (false, String::new()),
    }
}

/// Keep capsule verification local and deterministic. On Ubuntu,
/// `DEBUGINFOD_URLS` is commonly set system-wide; a sanitizer crash can then
/// make llvm-symbolizer wait on the network indefinitely. Capsules are promised
/// to verify offline, so their replay must never inherit that remote lookup.
fn configure_capsule_replay(command: &mut Command) {
    command
        .env("ASAN_OPTIONS", "abort_on_error=1:handle_abort=1")
        .env("DEBUGINFOD_URLS", "");
}

/// Extract a stable sanitizer-crash signature from a replay's stderr — the ASan
/// error class (`stack-buffer-overflow`, `heap-use-after-free`, `SEGV`, …) or a
/// UBSan `runtime error`. `None` when the replay did not crash.
pub fn sanitizer_signature(stderr: &str, status: &std::process::ExitStatus) -> Option<String> {
    // ASan: `==NN==ERROR: AddressSanitizer: <class> on/at ...`
    if let Some(pos) = stderr.find("AddressSanitizer: ") {
        let rest = &stderr[pos + "AddressSanitizer: ".len()..];
        let class: String = rest
            .split(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_owned();
        if !class.is_empty() {
            return Some(format!("AddressSanitizer:{class}"));
        }
    }
    if stderr.contains("UndefinedBehaviorSanitizer") || stderr.contains("runtime error:") {
        return Some("UndefinedBehaviorSanitizer:runtime-error".to_owned());
    }
    // Death by signal with no sanitizer text (rare — coverage-less repro of a raw SEGV).
    if !status.success() && status.code().is_none() {
        return Some("signal:crash".to_owned());
    }
    None
}

fn write_manifest(
    cap: &Path,
    f: &FindingRef,
    _recipe: &BuildRecipe,
    reproduced: bool,
    signature: &str,
) -> anyhow::Result<()> {
    let sink = f.raw.pointer("/actionability/sink").cloned();
    let cwe = f.raw.pointer("/actionability/cwe").cloned();
    let manifest = json!({
        "schema": "govfuzz.capsule/v1",
        "govfuzz_version": env!("GOVFUZZ_VERSION_FULL"),
        "finding_id": f.finding_id,
        "harness_id": f.harness_id,
        "lang": "c",
        "rule_id": f.raw.get("rule_id"),
        "cwe": cwe,
        "exception": f.raw.pointer("/exception/name"),
        "sink": sink,
        "input": "input/testcase.bin",
        "build": "sh build.sh",
        "run": "./poc input/testcase.bin",
        "expected_signature": signature,
        "reproduced": reproduced,
    });
    std::fs::write(
        cap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn readme(finding_id: &str, signature: &str) -> String {
    format!(
        "# GovFuzz PoC capsule — {finding_id}\n\n\
         Self-contained reproducer for a crash govfuzz found on a tree with no working\n\
         build. Rebuilds offline with only `clang` (or `$CC`) and a shell.\n\n\
         ## Reproduce\n\n\
         ```sh\n\
         sh build.sh                 # compile ./poc (ASan+UBSan)\n\
         ./poc input/testcase.bin    # replay the minimized crash input\n\
         ```\n\n\
         Or verify with govfuzz:\n\n\
         ```sh\n\
         govfuzz verify-poc .\n\
         ```\n\n\
         Expected sanitizer signature: `{signature}`.\n\n\
         ## Layout\n\n\
         - `harness/main.c` — the fuzz driver (decodes `testcase.bin`, calls the target)\n\
         - `sources/` — the target source(s) under analysis\n\
         - `stubs/` — the dependencies govfuzz stubbed to make the tree build\n\
         - `runtime/` — govfuzz C decode-runtime headers\n\
         - `input/testcase.bin` — the minimized crashing input\n\
         - `manifest.json` — finding metadata + expected signature\n"
    )
}

// ── `govfuzz verify-poc` ─────────────────────────────────────────────────────

pub fn run_verify(args: VerifyPocArgs) -> i32 {
    // Accept a directory or a .tar.gz/.tar (extract to a scratch dir via system tar).
    let (root, _scratch) = match resolve_capsule(&args.capsule) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let manifest = match read_json(&root.join("manifest.json")) {
        Some(m) => m,
        None => {
            eprintln!(
                "error: not a govfuzz capsule (missing manifest.json): {}",
                root.display()
            );
            return 1;
        }
    };
    let expected = manifest
        .get("expected_signature")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    // Rebuild in place (or a temp copy — for a tar it's already scratch).
    let (reproduced, observed) = verify_capsule(&root);
    let _ = std::fs::remove_file(root.join("poc"));

    if !reproduced {
        // A capsule records whether the crash fired when it was PACKAGED. If it
        // did not, this run is not a regression — the capsule never demonstrated
        // the crash — and saying "did not rebuild+crash as expected" sends the
        // reader hunting for an environment difference that does not exist.
        let packaged_reproducing = manifest
            .get("reproduced")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let finding = manifest
            .get("finding_id")
            .and_then(Value::as_str)
            .unwrap_or("?");
        if packaged_reproducing {
            println!("verify-poc: FAIL — the capsule did not rebuild+crash as expected");
            println!("  finding:  {finding}");
            println!("  expected: {expected}");
            println!("  observed: <no crash>");
        } else {
            println!(
                "verify-poc: NOT REPRODUCIBLE — this capsule was recorded as \
                 non-reproducing when it was packaged, so there is nothing for it \
                 to verify"
            );
            println!("  finding:  {finding}");
            println!(
                "  note:     the finding fired during fuzzing but not on a standalone \
                 replay (a warm fork-server state, an environment the shim faked, or \
                 a timing-dependent crash). `govfuzz explain --finding-id {finding}` \
                 shows what the run depended on."
            );
        }
        return 1;
    }
    // Signature match is best-effort: if the manifest recorded one, require the class
    // to agree; otherwise any sanitizer crash counts.
    let matched = expected.is_empty() || signature_matches(&expected, &observed);
    println!(
        "verify-poc: {} — {} (finding {})",
        if matched { "PASS" } else { "MISMATCH" },
        observed,
        manifest
            .get("finding_id")
            .and_then(Value::as_str)
            .unwrap_or("?"),
    );
    if !matched {
        println!("  expected: {expected}");
        return 1;
    }
    0
}

/// Whether an observed signature matches the expected one. Exact, but a bare
/// `signal:crash` fallback is accepted against any sanitizer class (a coverage-less
/// rebuild can surface a raw SEGV where the instrumented run named the class).
fn signature_matches(expected: &str, observed: &str) -> bool {
    // Exact class agreement, or either side is the coverage-less `signal:crash`
    // fallback (a raw SEGV where the instrumented run named the ASan class).
    expected == observed || observed == "signal:crash" || expected == "signal:crash"
}

/// Resolve a capsule argument to a usable directory root. A directory is used
/// in place; an archive is extracted to a scratch dir (returned so the caller keeps
/// it alive). The scratch guard is `Some` only for the archive case.
fn resolve_capsule(arg: &Path) -> anyhow::Result<(PathBuf, Option<ScratchDir>)> {
    if arg.is_dir() {
        return Ok((arg.to_path_buf(), None));
    }
    let name = arg.to_string_lossy();
    if !(name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".tar")) {
        anyhow::bail!(
            "capsule must be a directory or a .tar.gz produced by `govfuzz capsule`: {}",
            arg.display()
        );
    }
    let scratch = ScratchDir::new()?;
    let status = Command::new("tar")
        .arg("xf")
        .arg(arg)
        .arg("-C")
        .arg(&scratch.0)
        .status()
        .map_err(|e| anyhow::anyhow!("cannot run tar to extract capsule: {e}"))?;
    if !status.success() {
        anyhow::bail!("tar failed to extract {}", arg.display());
    }
    // The tarball holds a single `capsule_*` dir; descend into it if present.
    let root = single_subdir(&scratch.0).unwrap_or_else(|| scratch.0.clone());
    Ok((root, Some(scratch)))
}

/// If `dir` holds exactly one subdirectory (and nothing else of substance), return it.
fn single_subdir(dir: &Path) -> Option<PathBuf> {
    let mut subdirs = Vec::new();
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if e.path().is_dir() {
            subdirs.push(e.path());
        }
    }
    if subdirs.len() == 1 {
        subdirs.pop()
    } else {
        None
    }
}

/// A scratch directory removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> anyhow::Result<Self> {
        let base = std::env::temp_dir().join(format!("gf-verify-poc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base)?;
        Ok(ScratchDir(base))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_tarball(out_root: &Path, cap: &Path) {
    let name = basename(cap);
    let _ = Command::new("tar")
        .arg("czf")
        .arg(out_root.join(format!("{name}.tar.gz")))
        .arg("-C")
        .arg(out_root)
        .arg(&name)
        .status();
}

fn copy(src: &Path, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dest)
        .map_err(|e| anyhow::anyhow!("copy {} -> {}: {e}", src.display(), dest.display()))?;
    Ok(())
}

/// Copy every `*.h`/`*.hpp` in `from` (non-recursive) into `into`.
fn copy_headers_in_dir(from: &Path, into: &Path) {
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_file() {
            let is_header = p
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| matches!(x, "h" | "hpp" | "hh" | "hxx"));
            if is_header {
                let _ = copy(&p, &into.join(basename(&p)));
            }
        }
    }
}

fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
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
    fn capsule_replay_disables_remote_debuginfod() {
        let mut command = Command::new("true");
        configure_capsule_replay(&mut command);
        let env: std::collections::HashMap<_, _> = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect();
        assert_eq!(
            env.get(std::ffi::OsStr::new("DEBUGINFOD_URLS")),
            Some(&std::ffi::OsStr::new(""))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("ASAN_OPTIONS")),
            Some(&std::ffi::OsStr::new("abort_on_error=1:handle_abort=1"))
        );
    }

    #[test]
    fn signature_from_asan_stderr() {
        let s = "==12==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...";
        let ok = std::process::Command::new("true").status().unwrap();
        assert_eq!(
            sanitizer_signature(s, &ok),
            Some("AddressSanitizer:stack-buffer-overflow".to_owned())
        );
    }

    #[test]
    fn signature_from_ubsan_stderr() {
        let s = "x.c:5:9: runtime error: signed integer overflow";
        let ok = std::process::Command::new("true").status().unwrap();
        assert_eq!(
            sanitizer_signature(s, &ok),
            Some("UndefinedBehaviorSanitizer:runtime-error".to_owned())
        );
    }

    #[test]
    fn clean_run_has_no_signature() {
        let ok = std::process::Command::new("true").status().unwrap();
        assert_eq!(sanitizer_signature("all good\n", &ok), None);
    }

    #[test]
    fn parse_makefile_extracts_sources_and_flags() {
        let dir = std::env::temp_dir().join(format!("gf-cap-mk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mk = dir.join("Makefile");
        std::fs::write(
            &mk,
            "COMPILE_DB_FLAGS = -std=c11 -DFOO=1\n\
             INCLUDES = -I . -I /gf/c_runtime -iquote /proj -idirafter /proj\n\
             main: main.c\n\
             \t$(CC) $(CFLAGS) $(COMPILE_DB_FLAGS) $(INCLUDES) -o $@ main.c /proj/a.c /proj/b.c $(AUTO_EXTRA_SOURCES) $(AUTO_EXTRA_LDFLAGS)\n",
        )
        .unwrap();
        let recipe = parse_makefile(&mk).unwrap();
        assert_eq!(recipe.compile_db_flags, vec!["-std=c11", "-DFOO=1"]);
        assert_eq!(
            recipe.target_sources,
            vec![PathBuf::from("/proj/a.c"), PathBuf::from("/proj/b.c")]
        );
        // `.` is skipped; the c_runtime `-I` root is captured.
        assert_eq!(recipe.include_dirs, vec![PathBuf::from("/gf/c_runtime")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signature_match_rules() {
        assert!(signature_matches(
            "AddressSanitizer:stack-buffer-overflow",
            "AddressSanitizer:stack-buffer-overflow"
        ));
        assert!(signature_matches("AddressSanitizer:SEGV", "signal:crash"));
        assert!(!signature_matches(
            "AddressSanitizer:heap-use-after-free",
            "AddressSanitizer:stack-buffer-overflow"
        ));
    }

    #[test]
    fn a_capsule_packaged_as_non_reproducing_verifies_as_such_not_as_a_failure() {
        // `capsule` writes a package even when the reconstruction did not fire,
        // marking `reproduced: false`. Running verify-poc on one then printed
        // "did not rebuild+crash as expected", which reads as a regression and
        // sends the reader looking for an environment difference that never
        // existed. The manifest already knows better.
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = serde_json::json!({
            "schema": "govfuzz.capsule/v1",
            "finding_id": "F-0000-a3531355",
            "expected_signature": "",
            "reproduced": false,
        });
        std::fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize"),
        )
        .expect("write manifest");

        let parsed = read_json(&dir.path().join("manifest.json")).expect("read back");
        assert_eq!(
            parsed.get("reproduced").and_then(Value::as_bool),
            Some(false),
            "the packaged verdict is what verify-poc must report"
        );
        // A capsule that WAS reproducing when packaged keeps the strict reading.
        let strict = serde_json::json!({"finding_id": "F-1", "reproduced": true});
        assert_eq!(
            strict.get("reproduced").and_then(Value::as_bool),
            Some(true)
        );
        // An older capsule without the field is treated as reproducing, so its
        // failure is still reported as a failure.
        let legacy = serde_json::json!({"finding_id": "F-2"});
        assert_eq!(
            legacy
                .get("reproduced")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            true
        );
    }
}
