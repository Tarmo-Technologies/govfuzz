// SPDX-License-Identifier: Apache-2.0

//! Native Lua fuzzing lane (M3.10): generate a govfuzz harness, copy the
//! `lua_runtime` driver, and emit a `harnesses/<id>/main` launcher that runs the
//! target under `lua` speaking the `GOVFUZZ_FRAMED` fork-server protocol with a
//! `debug.sethook` line-hook edge coverage into the shared map — the SAME
//! builtin-engine execution path as the other interpreted lanes (Ruby/Perl/Python),
//! no third-party fuzzer.
//!
//! Interpreted, like Ruby/Perl: there is no native binary. "Build" is a `luac -p`
//! (or `lua` load) syntax gate plus a `dofile` smoke-test (so an un-loadable target —
//! a missing module, a load-time error — is a clean skip, not a silent zero-exec
//! run). The repair loop is a pass-through.

use crate::auto::candidate::Candidate;
use crate::auto::lua::{parse_lua, LuaFunction};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub enum LuaBuildResult {
    Built,
    Failed { reason: String, skip: bool },
}

/// Locate a Lua interpreter (`lua`, then versioned fallbacks).
fn probe_lua() -> Option<PathBuf> {
    for name in ["lua", "lua5.4", "lua5.3", "luajit"] {
        if let Ok(p) = which::which(name) {
            return Some(p);
        }
    }
    None
}

/// Locate the bundled `lua_runtime/` (the driver).
fn locate_lua_runtime() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("lua_runtime");
                if cand.join("govfuzz_driver.lua").is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("lua_runtime"));
    if let Some(p) = &from_manifest {
        if p.join("govfuzz_driver.lua").is_file() {
            return from_manifest;
        }
    }
    None
}

pub fn build_lua_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> LuaBuildResult {
    let Some(lua) = probe_lua() else {
        return LuaBuildResult::Failed {
            reason: "no `lua` interpreter found; install Lua 5.3+ to fuzz Lua \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };
    let Some(runtime) = locate_lua_runtime() else {
        return LuaBuildResult::Failed {
            reason: "could not locate the bundled lua_runtime/ (driver)".to_owned(),
            skip: false,
        };
    };

    let (func, call) = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return LuaBuildResult::Failed { reason, skip: true },
    };

    let target_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());
    let target_dir = target_abs
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return LuaBuildResult::Failed {
            reason: format!("create {}: {e}", auto_dir.display()),
            skip: false,
        };
    }
    if let Err(e) = std::fs::copy(
        runtime.join("govfuzz_driver.lua"),
        auto_dir.join("govfuzz_driver.lua"),
    ) {
        return LuaBuildResult::Failed {
            reason: format!("copy driver: {e}"),
            skip: false,
        };
    }

    let harness_src = generate_harness(&target_abs, &target_dir, source_root, &call);
    let harness_path = auto_dir.join("govfuzzgen.lua");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return LuaBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate: load the harness (a `dofile` of the target) so a syntax error or an
    // un-loadable target (missing module, load-time error) is a CLEAN SKIP, not a
    // silent zero-exec run. `-e "assert(loadfile(...))"` checks syntax; then actually
    // running it loads the target.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&lua).arg("-e").arg(format!(
            "local f=assert(loadfile('{}')); f()",
            harness_path.display()
        )),
        Duration::from_secs(30),
    );
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return LuaBuildResult::Failed {
                reason: format!(
                    "target `{}` is not loadable (skipped cleanly): {}",
                    candidate.name,
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("load error")
                ),
                skip: true,
            };
        }
        Err(e) => {
            return LuaBuildResult::Failed {
                reason: format!("could not run lua smoke-test: {e}"),
                skip: false,
            };
        }
    }

    // Emit the launcher. Carries the GOVFUZZ_FRAMED + GOVFUZZ_LUA_LAUNCHER markers.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("govfuzz_driver.lua");
    let _ = &func;
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_LUA_LAUNCHER govfuzz Lua driver launcher (native Lua lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM; lua inherits them. A\n\
         # debug.sethook line hook records edge coverage into the shared map.\n\
         GOVFUZZ_HARNESS=\"{harness}\" \\\n\
         GOVFUZZ_TRACE_PREFIX=\"{trace}\" \\\n\
         GOVFUZZ_COVERED_LINES=\"{covered}\" \\\n\
         exec \"{lua}\" \"{driver}\" \"$@\"\n",
        harness = harness_path.display(),
        trace = source_root.display(),
        covered = auto_dir.join("covered-lines.txt").display(),
        lua = lua.display(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return LuaBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return LuaBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    LuaBuildResult::Built
}

/// Resolve the target function + the Lua call expression against the dofile'd module
/// (`mod`) or the global env (`_G`).
fn resolve_target(candidate: &Candidate) -> Result<(LuaFunction, String), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let funcs = parse_lua(&source);
    let f = funcs
        .iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| funcs.iter().find(|f| f.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let field = &f.field;
    let call = if f.is_global {
        // A global function the target defined; resolve from the global env, falling
        // back to the returned module table.
        format!("return (_G['{field}'] or (mod and mod['{field}']))(data)")
    } else if f.is_method {
        format!("return mod['{field}'](mod, data)")
    } else {
        format!("return mod['{field}'](data)")
    };
    Ok((f, call))
}

/// Emit `govfuzzgen.lua` returning a `run_one(data)` closure that `dofile`s the target
/// and calls the function.
fn generate_harness(
    target_abs: &Path,
    target_dir: &Path,
    source_root: &Path,
    call: &str,
) -> String {
    format!(
        "-- SPDX-License-Identifier: Apache-2.0\n\
         -- Generated by govfuzz (native Lua lane). Loads the target and passes the\n\
         -- fuzz bytes as a string. Do not edit.\n\
         package.path = '{dir}/?.lua;{root}/?.lua;' .. package.path\n\
         local mod = dofile('{target}')\n\
         return function(data)\n\
         \x20 {call}\n\
         end\n",
        dir = target_dir.display(),
        root = source_root.display(),
        target = target_abs.display(),
        call = call,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_returns_run_one_closure() {
        let h = generate_harness(
            Path::new("/proj/lib/toml.lua"),
            Path::new("/proj/lib"),
            Path::new("/proj"),
            "return mod['parse'](data)",
        );
        assert!(h.contains("local mod = dofile('/proj/lib/toml.lua')"));
        assert!(h.contains("return mod['parse'](data)"));
        assert!(h.contains("return function(data)"));
        assert!(h.contains("package.path = '/proj/lib/?.lua"));
    }

    #[test]
    fn bundled_driver_is_locatable_in_tree() {
        let runtime = locate_lua_runtime().expect("lua_runtime locatable in-tree");
        assert!(runtime.join("govfuzz_driver.lua").is_file());
    }
}
