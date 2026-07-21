// SPDX-License-Identifier: Apache-2.0

//! Native Ruby fuzzing lane (M3.9): generate a govfuzz harness, copy the
//! `ruby_runtime` driver, and emit a `harnesses/<id>/main` launcher that runs the
//! target under `ruby` speaking the `GOVFUZZ_FRAMED` fork-server protocol with
//! `TracePoint` edge coverage into the shared map — the SAME builtin-engine
//! execution path as the other interpreted lanes (Python/Perl), no third-party
//! fuzzer.
//!
//! Interpreted, like Python/Perl: there is no native binary. "Build" is a `ruby -c`
//! syntax gate plus a `require` smoke-test (so an un-loadable target — a missing gem,
//! a load-time error — is a clean skip, not a silent zero-exec run). The repair loop
//! is a pass-through.

use crate::auto::candidate::Candidate;
use crate::auto::ruby::{parse_ruby, RubyMethod};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub enum RubyBuildResult {
    Built,
    Failed { reason: String, skip: bool },
}

fn probe_ruby() -> Option<PathBuf> {
    which::which("ruby").ok()
}

/// `(major, minor)` of a Ruby interpreter from `RUBY_VERSION`, or `None`. The driver
/// uses `TracePoint` (Ruby 2.0+); older interpreters skip with a clear reason.
fn ruby_version(ruby: &Path) -> Option<(u32, u32)> {
    let out = Command::new(ruby)
        .arg("-e")
        .arg("print RUBY_VERSION")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout);
    let mut it = v.trim().split('.');
    let major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// Locate the bundled `ruby_runtime/` (the driver + coverage).
fn locate_ruby_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("ruby_runtime", "govfuzz_driver.rb")
}

pub fn build_ruby_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> RubyBuildResult {
    let Some(ruby) = probe_ruby() else {
        return RubyBuildResult::Failed {
            reason: "no `ruby` interpreter found; install Ruby 2.0+ to fuzz Ruby \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };
    if let Some((major, minor)) = ruby_version(&ruby) {
        if (major, minor) < (2, 0) {
            return RubyBuildResult::Failed {
                reason: format!(
                    "interpreter at {} is Ruby {major}.{minor}; the Ruby fuzzing lane \
                     requires Ruby 2.0+ (TracePoint coverage)",
                    ruby.display()
                ),
                skip: true,
            };
        }
    }
    let Some(runtime) = locate_ruby_runtime() else {
        return RubyBuildResult::Failed {
            reason: "could not locate the bundled ruby_runtime/ (driver)".to_owned(),
            skip: false,
        };
    };

    let (method, call) = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return RubyBuildResult::Failed { reason, skip: true },
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
        return RubyBuildResult::Failed {
            reason: format!("create {}: {e}", auto_dir.display()),
            skip: false,
        };
    }
    if let Err(e) = std::fs::copy(
        runtime.join("govfuzz_driver.rb"),
        auto_dir.join("govfuzz_driver.rb"),
    ) {
        return RubyBuildResult::Failed {
            reason: format!("copy driver: {e}"),
            skip: false,
        };
    }

    // The target's own `require_relative`/`require` resolve from its directory and the
    // project root, added to `$LOAD_PATH` INSIDE the generated harness (see
    // `generate_harness`) — after ruby startup, so the gem prelude never scans them.
    // Used here only for the build-time `require` smoke test.
    let load_paths = format!("{}:{}", target_dir.display(), source_root.display());
    let harness_src = generate_harness(&target_abs, &target_dir, source_root, &call);
    let harness_path = auto_dir.join("govfuzzgen.rb");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return RubyBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate 1: `ruby -c` syntax check of the generated harness (the `require`
    // inside is a runtime op, so this does not execute the target).
    match Command::new(&ruby).arg("-c").arg(&harness_path).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return RubyBuildResult::Failed {
                reason: format!(
                    "ruby -c of generated harness failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("")
                ),
                skip: false,
            };
        }
        Err(e) => {
            return RubyBuildResult::Failed {
                reason: format!("could not run ruby -c: {e}"),
                skip: false,
            };
        }
    }

    // Build gate 2: require smoke-test — actually load the harness (which requires
    // the target) so an un-loadable target (missing gem, load-time error) is a CLEAN
    // SKIP, not a silent zero-exec run.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&ruby)
            .arg("-e")
            .arg(format!("require '{}'", harness_path.display()))
            .env("RUBYLIB", &load_paths),
        Duration::from_secs(30),
    );
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return RubyBuildResult::Failed {
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
            return RubyBuildResult::Failed {
                reason: format!("could not run require smoke-test: {e}"),
                skip: false,
            };
        }
    }

    // Emit the launcher. Carries the GOVFUZZ_FRAMED + GOVFUZZ_RB_LAUNCHER markers the
    // engine greps for.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("govfuzz_driver.rb");
    // The declared-rejection namespace: an exception whose class is defined in the
    // target's own top module is that library's rejection, not a finding.
    let top_module = method
        .receiver_path
        .split("::")
        .next()
        .unwrap_or("")
        .to_owned();
    // `--disable-gems` skips Ruby's gem_prelude, which `require 'rubygems'` at startup
    // and `rb_check_realpath`s every $LOAD_PATH entry — a hard ENOENT under the fuzz
    // sandbox that would abort ruby before the driver runs. RUBYLIB is likewise NOT set
    // on the launcher (it feeds the prelude scan); the target's own $LOAD_PATH additions
    // are made INSIDE the generated harness (after startup, see `generate_harness`), so
    // they never reach the prelude. Pure parsers do not need rubygems.
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_RB_LAUNCHER govfuzz Ruby driver launcher (native Ruby lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM; ruby inherits them. TracePoint\n\
         # records per-line edge coverage into the shared map.\n\
         GOVFUZZ_HARNESS=\"{harness}\" \\\n\
         GOVFUZZ_TARGET_MODULE=\"{module}\" \\\n\
         GOVFUZZ_TRACE_PREFIX=\"{trace}\" \\\n\
         GOVFUZZ_COVERED_LINES=\"{covered}\" \\\n\
         exec \"{ruby}\" --disable-gems \"{driver}\" \"$@\"\n",
        harness = harness_path.display(),
        module = top_module,
        trace = source_root.display(),
        covered = auto_dir.join("covered-lines.txt").display(),
        ruby = ruby.display(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return RubyBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return RubyBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    RubyBuildResult::Built
}

/// Resolve the target method + the Ruby call expression. A top-level or module
/// (`self.`) method is called directly; an instance method constructs a no-arg
/// receiver (`Klass.new.method`).
fn resolve_target(candidate: &Candidate) -> Result<(RubyMethod, String), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let methods = parse_ruby(&source);
    let m = methods
        .iter()
        .find(|m| m.name == candidate.name && m.line == candidate.line)
        .or_else(|| methods.iter().find(|m| m.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let call = if m.receiver_path.is_empty() {
        // Top-level method (a private method on Object) — callable directly.
        format!("{}(data)", m.method)
    } else if m.needs_instance {
        format!("{}.new.{}(data)", m.receiver_path, m.method)
    } else {
        format!("{}.{}(data)", m.receiver_path, m.method)
    };
    Ok((m, call))
}

/// Emit `govfuzzgen.rb` defining a global `govfuzz_run_one(data)` that loads the
/// target and passes the fuzz bytes as a `String`.
fn generate_harness(
    target_abs: &Path,
    target_dir: &Path,
    source_root: &Path,
    call: &str,
) -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # Generated by govfuzz (native Ruby lane). Loads the target and passes the\n\
         # fuzz bytes as a String. Do not edit.\n\
         $LOAD_PATH.unshift('{dir}') unless $LOAD_PATH.include?('{dir}')\n\
         $LOAD_PATH.unshift('{root}') unless $LOAD_PATH.include?('{root}')\n\
         require '{target}'\n\
         \n\
         def govfuzz_run_one(data)\n\
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
    fn harness_loads_target_and_defines_run_one() {
        let h = generate_harness(
            Path::new("/proj/lib/toml.rb"),
            Path::new("/proj/lib"),
            Path::new("/proj"),
            "Toml.parse(data)",
        );
        assert!(h.contains("require '/proj/lib/toml.rb'"));
        assert!(h.contains("Toml.parse(data)"));
        assert!(h.contains("def govfuzz_run_one(data)"));
        assert!(h.contains("$LOAD_PATH.unshift('/proj/lib')"));
    }

    #[test]
    fn ruby_version_parses_installed_interpreter() {
        let Some(ruby) = probe_ruby() else {
            return; // no interpreter installed -> skip
        };
        let v = ruby_version(&ruby).expect("ruby_version should parse a real interpreter");
        assert!(v.0 >= 2, "modern ruby is >= 2.x: {v:?}");
    }

    #[test]
    fn bundled_driver_is_locatable_in_tree() {
        let runtime = locate_ruby_runtime().expect("ruby_runtime locatable in-tree");
        assert!(runtime.join("govfuzz_driver.rb").is_file());
    }
}
