// SPDX-License-Identifier: Apache-2.0

//! Native PHP fuzzing lane (M3.11): generate a govfuzz harness, copy the
//! `php_runtime` driver, and emit a `harnesses/<id>/main` launcher that runs the
//! target under `php` (with the `pcov` extension for coverage) speaking the
//! `GOVFUZZ_FRAMED` fork-server protocol — the SAME builtin-engine execution path as
//! the other interpreted lanes (Ruby/Lua/Perl), no third-party fuzzer.
//!
//! Interpreted, like Ruby/Lua: there is no native binary. "Build" is a `php -l`
//! (lint) syntax gate plus a `require` smoke-test (so an un-loadable target — a
//! missing composer dependency, a load-time error — is a clean skip, not a silent
//! zero-exec run). The repair loop is a pass-through.

use crate::auto::candidate::Candidate;
use crate::auto::php::{parse_php, PhpFunction};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub enum PhpBuildResult {
    Built,
    Failed { reason: String, skip: bool },
}

fn probe_php() -> Option<PathBuf> {
    which::which("php").ok()
}

/// Locate the bundled `php_runtime/` (the driver).
fn locate_php_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("php_runtime", "govfuzz_driver.php")
}

pub fn build_php_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> PhpBuildResult {
    let Some(php) = probe_php() else {
        return PhpBuildResult::Failed {
            reason: "no `php` interpreter found; install PHP 8.0+ to fuzz PHP \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };
    let Some(runtime) = locate_php_runtime() else {
        return PhpBuildResult::Failed {
            reason: "could not locate the bundled php_runtime/ (driver)".to_owned(),
            skip: false,
        };
    };

    let (func, call) = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return PhpBuildResult::Failed { reason, skip: true },
    };

    let target_abs = candidate
        .source_path
        .canonicalize()
        .unwrap_or_else(|_| candidate.source_path.clone());

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    if let Err(e) = std::fs::create_dir_all(&auto_dir) {
        return PhpBuildResult::Failed {
            reason: format!("create {}: {e}", auto_dir.display()),
            skip: false,
        };
    }
    if let Err(e) = std::fs::copy(
        runtime.join("govfuzz_driver.php"),
        auto_dir.join("govfuzz_driver.php"),
    ) {
        return PhpBuildResult::Failed {
            reason: format!("copy driver: {e}"),
            skip: false,
        };
    }

    let harness_src = generate_harness(&target_abs, &call);
    let harness_path = auto_dir.join("govfuzzgen.php");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return PhpBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate 1: `php -l` lint (syntax only).
    match Command::new(&php).arg("-l").arg(&harness_path).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PhpBuildResult::Failed {
                reason: format!(
                    "php -l of generated harness failed: {}",
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .last()
                        .unwrap_or("")
                ),
                skip: false,
            };
        }
        Err(e) => {
            return PhpBuildResult::Failed {
                reason: format!("could not run php -l: {e}"),
                skip: false,
            };
        }
    }

    // Build gate 2: require smoke-test — actually load the harness (which requires the
    // target) so an un-loadable target (missing dependency, load-time error) is a
    // CLEAN SKIP, not a silent zero-exec run.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&php)
            .arg("-r")
            .arg(format!("require '{}';", harness_path.display())),
        Duration::from_secs(30),
    );
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PhpBuildResult::Failed {
                reason: crate::auto::script_load_roots::unloadable_reason(
                    &candidate.name,
                    &String::from_utf8_lossy(&out.stderr),
                ),
                skip: true,
            };
        }
        Err(e) => {
            return PhpBuildResult::Failed {
                reason: format!("could not run require smoke-test: {e}"),
                skip: false,
            };
        }
    }

    // Emit the launcher. Enables pcov (scoped to the source root) for coverage and
    // carries the GOVFUZZ_FRAMED + GOVFUZZ_PHP_LAUNCHER markers.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("govfuzz_driver.php");
    // The declared-rejection namespace: an exception whose class is in the target's own
    // top namespace is that library's rejection.
    let target_ns = func.name.split('\\').next().unwrap_or("").to_owned();
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_PHP_LAUNCHER govfuzz PHP driver launcher (native PHP lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM; php inherits them. pcov (scoped\n\
         # to the source root) records per-line coverage into the shared map.\n\
         GOVFUZZ_HARNESS=\"{harness}\" \\\n\
         GOVFUZZ_TARGET_NS=\"{ns}\" \\\n\
         GOVFUZZ_TRACE_PREFIX=\"{trace}\" \\\n\
         GOVFUZZ_COVERED_LINES=\"{covered}\" \\\n\
         exec \"{php}\" -d pcov.enabled=1 -d 'pcov.directory={trace}' -d memory_limit=512M \\\n\
         \x20   \"{driver}\" \"$@\"\n",
        harness = harness_path.display(),
        ns = target_ns,
        trace = source_root.display(),
        covered = auto_dir.join("covered-lines.txt").display(),
        php = php.display(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return PhpBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return PhpBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    PhpBuildResult::Built
}

/// Resolve the target function + the PHP call expression. A free function or a
/// `static` method is called directly; an instance method constructs a no-arg
/// receiver (`(new Class())->method(...)`).
fn resolve_target(candidate: &Candidate) -> Result<(PhpFunction, String), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let funcs = parse_php(&source);
    let f = funcs
        .iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| funcs.iter().find(|f| f.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let call = if f.class.is_empty() {
        // A free function; `f.name` is the (possibly namespaced) name.
        format!("return \\{}($data);", f.name)
    } else if f.is_static {
        format!("return {}::{}($data);", f.class, f.func)
    } else {
        format!("return (new {}())->{}($data);", f.class, f.func)
    };
    Ok((f, call))
}

/// Emit `govfuzzgen.php` returning a `run_one($data)` closure that `require`s the
/// target and calls the function.
fn generate_harness(target_abs: &Path, call: &str) -> String {
    format!(
        "<?php\n\
         // SPDX-License-Identifier: Apache-2.0\n\
         // Generated by govfuzz (native PHP lane). Loads the target and passes the\n\
         // fuzz bytes as a string. Do not edit.\n\
         require_once '{target}';\n\
         return function(string $data) {{\n\
         \x20   {call}\n\
         }};\n",
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
    fn harness_requires_target_and_returns_closure() {
        let h = generate_harness(
            Path::new("/proj/src/Toml.php"),
            "return \\Toml\\parse($data);",
        );
        assert!(h.contains("require_once '/proj/src/Toml.php'"));
        assert!(h.contains("return \\Toml\\parse($data);"));
        assert!(h.contains("return function(string $data)"));
    }

    #[test]
    fn bundled_driver_is_locatable_in_tree() {
        let runtime = locate_php_runtime().expect("php_runtime locatable in-tree");
        assert!(runtime.join("govfuzz_driver.php").is_file());
    }
}
