// SPDX-License-Identifier: Apache-2.0

//! JavaScript / Node.js harness build (M3.7) — see [`crate::auto::js`] for strategy.
//!
//! Step 0 of the attempt loop for a `Lang::Js` candidate: resolve the target
//! module, syntax-check it with `node -c`, copy the bundled framed driver next to
//! the harness, and emit a launcher `main` that execs
//! `node js_runtime/govfuzz_driver.js` with the target module + export path + arg
//! kind in the environment. The engine sets `GOVFUZZ_FRAMED` + `GOVFUZZ_COV_SHM`
//! across the exec and drives the warm Node process over the framed fork-server
//! protocol — same path as Python/Perl. Interpreted: there is no native binary.

use crate::auto::candidate::Candidate;
use crate::auto::js::{parse_js, JsFunction};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub enum JsBuildResult {
    Built,
    /// Not fuzzable here (no `node`, target no longer present) — skip cleanly.
    Skip(String),
    /// A genuine failure (missing runtime, unwritable work dir).
    Failed(String),
}

fn have_node() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Locate the bundled `js_runtime/govfuzz_driver.js`, relative to the source tree
/// (dev) or the installed binary (release) — mirrors `locate_python_runtime`.
fn locate_js_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("js_runtime", "govfuzz_driver.js")
}

/// Re-parse the source and find the discovered function by (name, line).
fn resolve_target(candidate: &Candidate) -> Result<JsFunction, String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let fns = parse_js(&source);
    fns.iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| fns.iter().find(|f| f.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("JS target `{}` no longer present in source", candidate.name))
}

/// The single public entry point of the lane.
pub fn build_js_harness(candidate: &Candidate, work_dir: &Path, harness_id: &str) -> JsBuildResult {
    if !have_node() {
        return JsBuildResult::Skip(
            "no `node` runtime found; install Node.js to fuzz JavaScript (the lane \
             skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
        );
    }
    let Some(runtime) = locate_js_runtime() else {
        return JsBuildResult::Failed(
            "could not locate the bundled js_runtime/govfuzz_driver.js".to_owned(),
        );
    };
    let func = match resolve_target(candidate) {
        Ok(f) => f,
        Err(reason) => return JsBuildResult::Skip(reason),
    };

    let module_abs = match candidate.source_path.canonicalize() {
        Ok(p) => p,
        Err(_) => candidate.source_path.clone(),
    };

    // Syntax + load smoke-test: the module must parse AND `require` at runtime.
    // `node -c` only checks syntax; a module whose `require('...')` cannot resolve
    // (an npm dependency not installed — `side-channel`, etc.) parses fine but dies
    // at startup, which would silently fuzz 0 inputs. Skip it cleanly with the
    // reason (mirrors the Python lane's import check).
    if let Some(reason) = js_module_load_error(&module_abs) {
        return JsBuildResult::Skip(reason);
    }

    emit_js_harness(work_dir, harness_id, &runtime, &module_abs, &func)
}

/// `None` if the module parses and `require`s cleanly, else a skip reason. Catches
/// both syntax errors and unresolved runtime `require`s (missing npm dependencies).
fn js_module_load_error(module_abs: &Path) -> Option<String> {
    // `node -c` first (cheap, no side effects) for a precise syntax message.
    if let Ok(out) = Command::new("node").arg("-c").arg(module_abs).output() {
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            return Some(format!(
                "`node -c` rejected {}: {}",
                module_abs.display(),
                msg.lines().next().unwrap_or("").trim()
            ));
        }
    }
    // Then require it in a throwaway process to confirm the dependency graph resolves.
    let out = crate::command_output::output_with_timeout(
        Command::new("node")
            .arg("-e")
            .arg("require(process.argv[1])")
            .arg(module_abs),
        Duration::from_secs(30),
    )
    .ok()?;
    if out.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Shared wording so the uninstalled npm package is recorded as a named
    // requirement: the prose form said `npm install` but carried no marker, so
    // the run reported "no dependencies were missing" for a tree where every
    // target skipped on one.
    Some(crate::auto::script_load_roots::unloadable_reason(
        &module_abs.display().to_string(),
        &stderr,
    ))
}

/// Copy the driver and emit the `node` launcher pointing at `module_abs` (the target
/// module for JS, or the transpiled `.js` for TS). Shared by both lanes.
fn emit_js_harness(
    work_dir: &Path,
    harness_id: &str,
    runtime: &Path,
    module_abs: &Path,
    func: &JsFunction,
) -> JsBuildResult {
    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return JsBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }
    let driver = hdir.join("govfuzz_driver.js");
    if let Err(e) = std::fs::copy(runtime.join("govfuzz_driver.js"), &driver) {
        return JsBuildResult::Failed(format!("copy driver: {e}"));
    }

    // Emit the launcher `main`. Carries the GOVFUZZ_FRAMED marker the engine greps
    // for; node inherits GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM across the exec.
    let main_path = hdir.join("main");
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_JS_LAUNCHER govfuzz Node.js driver launcher.\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM in the environment; node\n\
         # inherits them across this exec. The driver records V8 precise block coverage\n\
         # into the file-backed GOVFUZZ_COV_SHM map and speaks the framed protocol.\n\
         # GOVFUZZ_JS_MODULE = the target module; GOVFUZZ_JS_EXPORT = the export path;\n\
         # GOVFUZZ_JS_ARG = buffer|string (how the fuzz bytes reach the first param).\n\
         GOVFUZZ_JS_MODULE=\"{module}\" \\\n\
         GOVFUZZ_JS_EXPORT=\"{export_path}\" \\\n\
         GOVFUZZ_JS_ARG=\"{arg}\" \\\n\
         exec node \"{driver}\" \"$@\"\n",
        module = module_abs.display(),
        export_path = func.export_path,
        arg = func.arg_kind.as_env(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return JsBuildResult::Failed(format!("write launcher {}: {e}", main_path.display()));
    }
    if let Err(e) = make_executable(&main_path) {
        return JsBuildResult::Failed(format!("chmod +x {}: {e}", main_path.display()));
    }
    JsBuildResult::Built
}

/// Resolve the TypeScript transpiler: `esbuild` on PATH (preferred — a single fast
/// binary that strips types), else the local `npx esbuild`. Returns the argv prefix.
fn locate_esbuild() -> Option<Vec<String>> {
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            if dir.join("esbuild").is_file() {
                return Some(vec![dir.join("esbuild").to_string_lossy().into_owned()]);
            }
        }
    }
    // `npx --no-install esbuild` uses a project-local esbuild if present.
    if Command::new("npx")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success()
    {
        return Some(vec![
            "npx".to_owned(),
            "--no-install".to_owned(),
            "esbuild".to_owned(),
        ]);
    }
    None
}

/// The TypeScript lane's build (M3.8). Transpile the `.ts` target to CommonJS `.js`
/// with esbuild (bundling local imports, leaving `node_modules` external), then
/// reuse the JS driver on the transpiled module. A missing node/esbuild, or a
/// transpile/load failure, skips cleanly.
pub fn build_ts_harness(candidate: &Candidate, work_dir: &Path, harness_id: &str) -> JsBuildResult {
    if !have_node() {
        return JsBuildResult::Skip(
            "no `node` runtime found; install Node.js to fuzz TypeScript (skips cleanly)"
                .to_owned(),
        );
    }
    let Some(runtime) = locate_js_runtime() else {
        return JsBuildResult::Failed(
            "could not locate the bundled js_runtime/govfuzz_driver.js".to_owned(),
        );
    };
    let func = match resolve_target(candidate) {
        Ok(f) => f,
        Err(reason) => return JsBuildResult::Skip(reason),
    };
    let Some(esbuild) = locate_esbuild() else {
        return JsBuildResult::Skip(
            "no TypeScript transpiler found (install esbuild: `npm i -g esbuild`); the \
             TS lane skips cleanly"
                .to_owned(),
        );
    };
    let src_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());

    let hdir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&hdir) {
        return JsBuildResult::Failed(format!("create {}: {e}", hdir.display()));
    }
    let out_js = hdir.join("target.js");

    // Transpile: bundle local TS imports + strip types, keep node_modules external.
    let mut cmd = Command::new(&esbuild[0]);
    cmd.args(&esbuild[1..])
        .arg(&src_abs)
        .arg("--bundle")
        .arg("--packages=external")
        .arg("--format=cjs")
        .arg("--platform=node")
        .arg(format!("--outfile={}", out_js.display()));
    match crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    ) {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            return JsBuildResult::Skip(format!(
                "esbuild could not transpile {}: {}",
                src_abs.display(),
                msg.lines().next().unwrap_or("").trim()
            ));
        }
        Err(e) => return JsBuildResult::Skip(format!("spawn esbuild: {e}")),
    }
    // Smoke-test the transpiled module parses AND loads (external node_modules
    // requires resolvable) — else it would fuzz 0 inputs. Skip cleanly otherwise.
    if let Some(reason) = js_module_load_error(&out_js) {
        return JsBuildResult::Skip(reason);
    }
    emit_js_harness(work_dir, harness_id, &runtime, &out_js, &func)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
