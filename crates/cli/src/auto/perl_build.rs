// SPDX-License-Identifier: Apache-2.0

//! Native Perl fuzzing lane (M3.2): generate a govfuzz harness module, copy the
//! `perl_runtime` (driver + Devel::GovfuzzCov), and emit a `harnesses/<id>/main`
//! launcher that runs the target under `perl -d:GovfuzzCov` speaking the
//! `GOVFUZZ_FRAMED` fork-server protocol with DB::DB edge coverage into the shared
//! map — the SAME builtin-engine execution path as the other lanes, no third-party
//! fuzzer.
//!
//! Interpreted, like Python: there is no native binary. "Build" is a `perl -c`
//! syntax gate plus a `require` smoke-test (so an un-loadable target is a clean
//! skip, not a silent zero-exec run). The repair loop is a pass-through.

use crate::auto::candidate::Candidate;
use perl_parser::{parse_perl_subs, PerlSub};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub enum PerlBuildResult {
    Built,
    Failed { reason: String, skip: bool },
}

fn probe_perl() -> Option<PathBuf> {
    which::which("perl").ok()
}

/// M22: detected `(major, minor)` of a Perl interpreter from `$]` (e.g.
/// `5.036000` -> `(5, 36)`), or `None` if it could not be run/parsed. The driver
/// is written to run on Perl 5.6+; older interpreters skip with a clear reason.
fn perl_version(perl: &Path) -> Option<(u32, u32)> {
    let out = std::process::Command::new(perl)
        .arg("-e")
        .arg("print $]")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: f64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    let major = v.trunc() as u32;
    // The fractional part encodes minor.patch as .MMMPPP (5.036000 -> minor 36).
    let minor = (v.fract() * 1000.0).round() as u32;
    Some((major, minor))
}

/// Locate the bundled `perl_runtime/` (driver + Devel/GovfuzzCov.pm).
fn locate_perl_runtime() -> Option<PathBuf> {
    crate::runtime_assets::locate("perl_runtime", "govfuzz_driver.pl")
}

pub fn build_perl_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    _source_root: &Path,
) -> PerlBuildResult {
    let Some(perl) = probe_perl() else {
        return PerlBuildResult::Failed {
            reason: "no `perl` interpreter found; install Perl 5 to fuzz Perl \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };
    // M22: the driver is written to run on Perl 5.6+ (no `//` defined-or). An
    // older interpreter (Perl 4 / 5.0-5.5) skips with an actionable reason; the
    // Perl 4 lane is M22 Phase 5.
    if let Some((major, minor)) = perl_version(&perl) {
        if (major, minor) < (5, 6) {
            return PerlBuildResult::Failed {
                reason: format!(
                    "interpreter at {} is Perl {major}.{minor}; the Perl fuzzing lane \
                     requires Perl 5.6+ (Perl 4 is M22 Phase 5)",
                    perl.display()
                ),
                skip: true,
            };
        }
    }
    let Some(runtime) = locate_perl_runtime() else {
        return PerlBuildResult::Failed {
            reason: "could not locate the bundled perl_runtime/ (driver + Devel::GovfuzzCov)"
                .to_owned(),
            skip: false,
        };
    };

    let (sub, call) = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return PerlBuildResult::Failed { reason, skip: true },
    };

    let target_abs = match candidate.source_path.canonicalize() {
        Ok(p) => p,
        Err(_) => candidate.source_path.clone(),
    };
    let (module_root, _) = resolve_module_root(&target_abs, &sub.package);

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let devel_dir = auto_dir.join("Devel");
    if let Err(e) = std::fs::create_dir_all(&devel_dir) {
        return PerlBuildResult::Failed {
            reason: format!("create {}: {e}", devel_dir.display()),
            skip: false,
        };
    }
    if let Err(e) = std::fs::copy(
        runtime.join("govfuzz_driver.pl"),
        auto_dir.join("govfuzz_driver.pl"),
    ) {
        return PerlBuildResult::Failed {
            reason: format!("copy driver: {e}"),
            skip: false,
        };
    }
    if let Err(e) = std::fs::copy(
        runtime.join("Devel/GovfuzzCov.pm"),
        devel_dir.join("GovfuzzCov.pm"),
    ) {
        return PerlBuildResult::Failed {
            reason: format!("copy coverage module: {e}"),
            skip: false,
        };
    }

    let harness_src = generate_harness(
        &target_abs,
        &call,
        &format!("{}::{}", sub.package, sub.name),
    );
    let harness_path = auto_dir.join("govfuzzgen.pm");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return PerlBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate 1: `perl -c` the harness (syntax only; the `require` inside is a
    // runtime op, so this does not execute the target).
    let perl5lib = format!(
        "{}:{}:{}",
        auto_dir.display(),
        module_root.display(),
        target_abs
            .parent()
            .map(Path::display)
            .map(|d| d.to_string())
            .unwrap_or_default()
    );
    let compile = crate::command_output::output_with_timeout(
        Command::new(&perl)
            .arg("-c")
            .arg(&harness_path)
            .env("PERL5LIB", &perl5lib),
        Duration::from_secs(30),
    );
    match compile {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PerlBuildResult::Failed {
                reason: format!(
                    "perl -c of generated harness failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("")
                ),
                skip: false,
            };
        }
        Err(e) => {
            return PerlBuildResult::Failed {
                reason: format!("could not run perl -c: {e}"),
                skip: false,
            };
        }
    }

    // Build gate 2: require smoke-test — actually load the harness (which requires
    // the target) so an un-loadable target (missing CPAN dep, compile error in the
    // module) is a CLEAN SKIP, not a silent zero-exec run.
    let smoke = crate::command_output::output_with_timeout(
        Command::new(&perl)
            .arg("-e")
            .arg(format!("require q{{{}}}; 1", harness_path.display()))
            .env("PERL5LIB", &perl5lib),
        Duration::from_secs(30),
    );
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let reason = crate::auto::script_load_roots::unloadable_reason(
                &sub.package,
                &String::from_utf8_lossy(&out.stderr),
            );
            return PerlBuildResult::Failed { reason, skip: true };
        }
        Err(e) => {
            return PerlBuildResult::Failed {
                reason: format!("could not run require smoke-test: {e}"),
                skip: false,
            };
        }
    }

    // Emit the launcher. Carries the GOVFUZZ_FRAMED marker the engine greps for.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("govfuzz_driver.pl");
    let top_pkg = sub.package.split("::").next().unwrap_or(&sub.package);
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_PL_LAUNCHER govfuzz Perl driver launcher (native Perl lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM; perl inherits them. Run under\n\
         # `perl -d:GovfuzzCov` so DB::DB records edge coverage into the shared map.\n\
         GOVFUZZ_HARNESS=\"{harness}\" \\\n\
         GOVFUZZ_TARGET_PACKAGE=\"{pkg}\" \\\n\
         GOVFUZZ_TRACE_PREFIX=\"{trace}\" \\\n\
         GOVFUZZ_COVERED_LINES=\"{covered}\" \\\n\
         PERL5LIB=\"{perl5lib}:${{PERL5LIB}}\" \\\n\
         exec \"{perl}\" -d:GovfuzzCov \"{driver}\" \"$@\"\n",
        harness = harness_path.display(),
        pkg = top_pkg,
        trace = module_root.display(),
        covered = auto_dir.join("covered-lines.txt").display(),
        perl5lib = perl5lib,
        perl = perl.display(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return PerlBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return PerlBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    PerlBuildResult::Built
}

/// Resolve the target sub + the Perl call expression. For an OO method, construct
/// the receiver via `Package->new` IFF the package defines a `new` sub; otherwise
/// skip cleanly (no-arg-ctor first cut, like the other lanes).
fn resolve_target(candidate: &Candidate) -> Result<(PerlSub, String), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let subs = parse_perl_subs(&source).map_err(|_| "failed to parse Perl source".to_owned())?;
    let sub = subs
        .iter()
        .find(|s| s.qualified() == candidate.name && s.line == candidate.line)
        .or_else(|| subs.iter().find(|s| s.qualified() == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let call = if sub.is_method {
        let has_new = subs
            .iter()
            .any(|s| s.package == sub.package && s.name == "new");
        if !has_new {
            return Err(format!(
                "OO method `{}` needs a receiver, but `{}` has no `new` constructor; \
                 only no-arg-constructible receivers are supported (skipped cleanly)",
                sub.qualified(),
                sub.package
            ));
        }
        format!("{}->new->{}($data)", sub.package, sub.name)
    } else {
        format!("{}::{}($data)", sub.package, sub.name)
    };
    Ok((sub, call))
}

/// Compute the `@INC` root for a Perl module so its own `use`/`require` resolve:
/// strip the `Package/Path.pm` suffix from the file path. Falls back to the file's
/// directory for a `package main` script or a path/package mismatch.
fn resolve_module_root(target_abs: &Path, package: &str) -> (PathBuf, ()) {
    let dir = target_abs
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if package == "main" || package.is_empty() {
        return (dir, ());
    }
    let rel = format!("{}.pm", package.replace("::", "/"));
    let path_str = target_abs.to_string_lossy();
    if let Some(stripped) = path_str.strip_suffix(&rel) {
        let root = stripped.trim_end_matches('/');
        if !root.is_empty() {
            return (PathBuf::from(root), ());
        }
    }
    (dir, ())
}

/// Emit `govfuzzgen.pm` exposing `govfuzzgen::govfuzz_run_one($bytes)`.
fn generate_harness(target_abs: &Path, call: &str, sub_name: &str) -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # Generated by govfuzz (native Perl lane). Loads the target and passes the\n\
         # fuzz bytes as a string scalar. Do not edit.\n\
         package govfuzzgen;\n\
         use strict;\n\
         use warnings;\n\
         # A standalone script (cloc, sqitch, any `#!perl` tool) RUNS its main body\n\
         # on require, prints usage for an empty @ARGV, and exits — which aborts the\n\
         # load even though perl has already compiled the file and defined every\n\
         # named sub. Neutralise the exit, silence the body's output, and judge the\n\
         # load by whether the target sub exists rather than by how the body ended.\n\
         BEGIN {{ *CORE::GLOBAL::exit = sub {{ die \"govfuzz_load_exit\\n\" }}; }}\n\
         {{\n\
         \x20   # `require FILE` compiles into the CALLER's package, so a script\n\
         \x20   # whose subs are implicitly `main::` would land in this harness's\n\
         \x20   # package and appear undefined. Load it as main.\n\
         \x20   package main;\n\
         \x20   local @ARGV = ();\n\
         \x20   open(my $govfuzz_devnull, '>', '/dev/null');\n\
         \x20   my $govfuzz_saved;\n\
         \x20   $govfuzz_saved = select($govfuzz_devnull) if $govfuzz_devnull;\n\
         \x20   eval {{ require q{{{target}}}; 1 }};\n\
         \x20   my $govfuzz_err = $@;\n\
         \x20   select($govfuzz_saved) if defined $govfuzz_saved;\n\
         \x20   unless (defined &{{'{sub_name}'}}) {{\n\
         \x20       die $govfuzz_err || \"govfuzz: `{sub_name}` undefined after load\\n\";\n\
         \x20   }}\n\
         }}\n\
         \n\
         sub govfuzz_run_one {{\n\
         \x20   my ($data) = @_;\n\
         \x20   {call};\n\
         }}\n\
         1;\n",
        target = target_abs.display(),
        call = call,
        sub_name = sub_name,
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
    fn harness_loads_target_and_calls_function() {
        let h = generate_harness(
            Path::new("/proj/lib/My/P.pm"),
            "My::P::parse($data)",
            "My::P::parse",
        );
        assert!(h.contains("require q{/proj/lib/My/P.pm}"));
        assert!(h.contains("My::P::parse($data)"));
        assert!(h.contains("sub govfuzz_run_one"));
    }

    #[test]
    fn a_standalone_script_survives_its_own_exit_during_load() {
        // cloc is 20k lines of Perl in an extension-less file whose main body
        // prints usage and exits when @ARGV is empty. perl has already compiled
        // and defined every sub by then, so the load must be judged by whether
        // the target sub exists, not by how the body ended.
        let h = generate_harness(
            Path::new("/proj/cloc"),
            "main::parse_line($data)",
            "main::parse_line",
        );
        assert!(
            h.contains("*CORE::GLOBAL::exit"),
            "exit must be neutralised"
        );
        assert!(
            h.contains("local @ARGV = ()"),
            "a script must not see arguments"
        );
        assert!(
            h.contains("package main;"),
            "a script's subs are main::, so it must be required as main: {h}"
        );
        assert!(
            h.contains("defined &{'main::parse_line'}"),
            "the load verdict is whether the sub exists: {h}"
        );
    }

    #[test]
    fn module_root_strips_package_path() {
        let (root, _) = resolve_module_root(Path::new("/proj/lib/My/Parser.pm"), "My::Parser");
        assert_eq!(root, Path::new("/proj/lib"));
    }

    #[test]
    fn module_root_falls_back_to_dir_for_main() {
        let (root, _) = resolve_module_root(Path::new("/proj/script.pl"), "main");
        assert_eq!(root, Path::new("/proj"));
    }

    #[test]
    fn bundled_driver_runs_on_perl_5_6_no_defined_or() {
        // M22 Phase 1b: the driver must run on Perl 5.6-5.9 (legacy gov/mil), so
        // it must not use the `//` defined-or operator (5.10+). A regex delimiter
        // (`s/.../...//`) never has whitespace around `//`, so requiring spaces
        // distinguishes the operator from a regex.
        let runtime = locate_perl_runtime().expect("perl_runtime locatable in-tree");
        let driver = std::fs::read_to_string(runtime.join("govfuzz_driver.pl")).unwrap();
        for (i, line) in driver.lines().enumerate() {
            let code = line.split('#').next().unwrap_or("");
            assert!(
                !code.contains(" // "),
                "`//` defined-or at line {} breaks Perl <5.10: {line}",
                i + 1
            );
        }
    }

    #[test]
    fn perl_version_parses_installed_interpreter() {
        let Some(perl) = probe_perl() else {
            return; // no interpreter installed -> skip
        };
        let v = perl_version(&perl).expect("perl_version should parse a real interpreter");
        assert_eq!(v.0, 5, "modern perl is 5.x: {v:?}");
    }
}
