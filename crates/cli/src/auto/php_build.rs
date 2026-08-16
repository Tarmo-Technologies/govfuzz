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

struct PhpCall {
    setup: String,
    invocation: String,
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
    let target_dir = target_abs
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let load_roots = crate::auto::script_load_roots::module_load_roots(source_root, &target_dir);

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

    let harness_src = generate_harness(&target_abs, &load_roots, &call);
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
            .arg(format!("require '{}';", harness_path.display()))
            .current_dir(&auto_dir),
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

    if func.needs_instance {
        let code = format!(
            "require '{}'; $r = new \\ReflectionClass('{}'); \
             if (!$r->isInstantiable()) {{ fwrite(STDERR, 'receiver class is not instantiable'); exit(2); }} \
             $c = $r->getConstructor(); \
             if ($c && $c->getNumberOfRequiredParameters() > 0) {{ \
                 fwrite(STDERR, 'receiver constructor requires ' . $c->getNumberOfRequiredParameters() . ' argument(s)'); exit(2); \
             }}",
            harness_path.display(),
            func.class
        );
        match crate::command_output::output_with_timeout(
            Command::new(&php)
                .arg("-r")
                .arg(code)
                .current_dir(&auto_dir),
            Duration::from_secs(30),
        ) {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                return PhpBuildResult::Failed {
                    reason: format!(
                        "target `{}` has no safe default receiver: {}",
                        candidate.name,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                    skip: true,
                };
            }
            Err(error) => {
                return PhpBuildResult::Failed {
                    reason: format!("could not inspect PHP receiver: {error}"),
                    skip: false,
                };
            }
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
fn resolve_target(candidate: &Candidate) -> Result<(PhpFunction, PhpCall), String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let funcs = parse_php(&source);
    let f = funcs
        .iter()
        .find(|f| f.name == candidate.name && f.line == candidate.line)
        .or_else(|| funcs.iter().find(|f| f.name == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let argument = php_input_expression(&f.first_param_type).ok_or_else(|| {
        format!(
            "target `{}` has unsupported input type `{}`",
            candidate.name, f.first_param_type
        )
    })?;

    let mut setup = format!("$govfuzz_arg = {argument};");
    let invocation = if f.class.is_empty() {
        // A free function; `f.name` is the (possibly namespaced) name.
        format!("return \\{}($govfuzz_arg);", f.name)
    } else if f.is_static {
        format!("return {}::{}($govfuzz_arg);", f.class, f.func)
    } else {
        setup.push_str(&format!("\n    $govfuzz_receiver = new {}();", f.class));
        format!("return $govfuzz_receiver->{}($govfuzz_arg);", f.func)
    };
    Ok((f, PhpCall { setup, invocation }))
}

fn php_input_expression(ty: &str) -> Option<String> {
    let mut types = ty
        .trim_start_matches('?')
        .split('|')
        .map(|part| part.trim().to_ascii_lowercase());
    if ty.is_empty()
        || types
            .clone()
            .any(|part| part == "mixed" || part == "string")
    {
        return Some("$data".to_owned());
    }
    if types.clone().any(|part| part == "int" || part == "integer") {
        return Some("unpack('q', str_pad(substr($data, 0, 8), 8, \"\\0\"))[1]".to_owned());
    }
    if types
        .clone()
        .any(|part| part == "bool" || part == "boolean")
    {
        return Some("$data !== '' && (ord($data[0]) & 1) !== 0".to_owned());
    }
    if types
        .clone()
        .any(|part| part == "float" || part == "double")
    {
        return Some("unpack('e', str_pad(substr($data, 0, 8), 8, \"\\0\"))[1]".to_owned());
    }
    if types.any(|part| part == "array") {
        return Some("array_values(unpack('C*', $data))".to_owned());
    }
    let class = ty
        .trim_start_matches('?')
        .split('|')
        .map(str::trim)
        .find(|part| {
            let lower = part.to_ascii_lowercase();
            !matches!(
                lower.as_str(),
                "mixed"
                    | "string"
                    | "int"
                    | "integer"
                    | "bool"
                    | "boolean"
                    | "float"
                    | "double"
                    | "array"
                    | "null"
            )
        })?;
    Some(format!(
        "$govfuzz_make_value('{}', $data)",
        class.replace('\'', "\\\\'")
    ))
}

/// Emit `govfuzzgen.php` returning a `run_one($data)` closure that `require`s the
/// target and calls the function.
fn generate_harness(target_abs: &Path, load_roots: &[PathBuf], call: &PhpCall) -> String {
    let roots = load_roots
        .iter()
        .map(|root| format!("'{}'", root.display()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "<?php\n\
         // SPDX-License-Identifier: Apache-2.0\n\
         // Generated by govfuzz (native PHP lane). Loads the target and passes the\n\
         // fuzz bytes as a string. Do not edit.\n\
         $govfuzz_roots = [{roots}];\n\
         foreach ($govfuzz_roots as $govfuzz_root) {{\n\
         \x20   $autoload = $govfuzz_root . '/vendor/autoload.php';\n\
         \x20   if (is_file($autoload)) {{ require_once $autoload; break; }}\n\
         }}\n\
         spl_autoload_register(function(string $class) use ($govfuzz_roots): void {{\n\
         \x20   $parts = explode('\\\\', ltrim($class, '\\\\'));\n\
         \x20   foreach ($govfuzz_roots as $root) {{\n\
         \x20       for ($drop = 0; $drop < count($parts); $drop++) {{\n\
         \x20           $candidate = $root . '/' . implode('/', array_slice($parts, $drop)) . '.php';\n\
         \x20           if (is_file($candidate)) {{ require_once $candidate; return; }}\n\
         \x20       }}\n\
         \x20   }}\n\
         }});\n\
         require_once '{target}';\n\
         $govfuzz_make_value = function(string $type, string $data, int $depth = 0) use (&$govfuzz_make_value) {{\n\
         \x20   if ($depth > 4) throw new \\TypeError('constructor graph is too deep');\n\
         \x20   $lower = strtolower(ltrim($type, '\\\\'));\n\
         \x20   if ($lower === 'string' || $lower === 'mixed') return $data;\n\
         \x20   if ($lower === 'int' || $lower === 'integer') return unpack('q', str_pad(substr($data, 0, 8), 8, \"\\0\"))[1];\n\
         \x20   if ($lower === 'bool' || $lower === 'boolean') return $data !== '' && (ord($data[0]) & 1) !== 0;\n\
         \x20   if ($lower === 'float' || $lower === 'double') return unpack('e', str_pad(substr($data, 0, 8), 8, \"\\0\"))[1];\n\
         \x20   if ($lower === 'array') return array_values(unpack('C*', $data));\n\
         \x20   if (is_a($type, \\DateTimeInterface::class, true)) return new \\DateTimeImmutable();\n\
         \x20   if (enum_exists($type)) {{\n\
         \x20       $cases = $type::cases();\n\
         \x20       if (!$cases) throw new \\TypeError('enum has no cases');\n\
         \x20       return $cases[$data === '' ? 0 : ord($data[0]) % count($cases)];\n\
         \x20   }}\n\
         \x20   $reflection = new \\ReflectionClass($type);\n\
         \x20   if (!$reflection->isInstantiable()) throw new \\TypeError(\"type $type is not instantiable\");\n\
         \x20   $constructor = $reflection->getConstructor();\n\
         \x20   if (!$constructor) return $reflection->newInstance();\n\
         \x20   $arguments = [];\n\
         \x20   foreach ($constructor->getParameters() as $parameter) {{\n\
         \x20       if ($parameter->isDefaultValueAvailable()) break;\n\
         \x20       $parameter_type = $parameter->getType();\n\
         \x20       if ($parameter_type instanceof \\ReflectionUnionType) {{\n\
         \x20           $named = array_values(array_filter($parameter_type->getTypes(), fn($candidate) => $candidate->getName() !== 'null'))[0] ?? null;\n\
         \x20       }} else {{ $named = $parameter_type; }}\n\
         \x20       if (!$named instanceof \\ReflectionNamedType) throw new \\TypeError('unsupported constructor parameter');\n\
         \x20       $arguments[] = $govfuzz_make_value($named->getName(), $data, $depth + 1);\n\
         \x20   }}\n\
         \x20   return $reflection->newInstanceArgs($arguments);\n\
         }};\n\
         $govfuzz_target_entered = false;\n\
         $govfuzz_mark_target_entry = function() use (&$govfuzz_target_entered): void {{\n\
         \x20   if ($govfuzz_target_entered) return;\n\
         \x20   $path = getenv('GOVFUZZ_TARGET_ENTRY_SHM');\n\
         \x20   if (!$path) return;\n\
         \x20   if (@file_put_contents($path, \"\\x01\", LOCK_EX) !== false) {{\n\
         \x20       $govfuzz_target_entered = true;\n\
         \x20   }}\n\
         }};\n\
         return function(string $data) use ($govfuzz_mark_target_entry, $govfuzz_make_value) {{\n\
         \x20   {setup}\n\
         \x20   $govfuzz_mark_target_entry();\n\
         \x20   {invocation}\n\
         }};\n",
        target = target_abs.display(),
        roots = roots,
        setup = call.setup,
        invocation = call.invocation,
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
            &[PathBuf::from("/proj/src"), PathBuf::from("/proj")],
            &PhpCall {
                setup: "$govfuzz_arg = $data;".to_owned(),
                invocation: "return \\Toml\\parse($govfuzz_arg);".to_owned(),
            },
        );
        assert!(h.contains("require_once '/proj/src/Toml.php'"));
        assert!(h.contains("$govfuzz_arg = $data;"));
        assert!(h.contains("return \\Toml\\parse($govfuzz_arg);"));
        assert!(h.contains("return function(string $data)"));
        assert!(h.contains("spl_autoload_register"));
        assert!(h.contains("'/proj/src', '/proj'"));
        assert!(
            h.contains("$govfuzz_mark_target_entry();\n    return \\Toml\\parse($govfuzz_arg);"),
            "entry checkpoint must immediately precede the selected call: {h}"
        );
    }

    #[test]
    fn object_argument_is_constructed_before_entry_checkpoint() {
        let expression = php_input_expression("\\Monolog\\LogRecord").unwrap();
        assert!(expression.contains("$govfuzz_make_value('\\Monolog\\LogRecord'"));
        let call = PhpCall {
            setup: format!("$govfuzz_arg = {expression};"),
            invocation: "return $receiver->format($govfuzz_arg);".to_owned(),
        };
        let harness = generate_harness(Path::new("/tmp/Formatter.php"), &[], &call);
        let argument = harness.find("$govfuzz_arg =").unwrap();
        let checkpoint = harness.find("$govfuzz_mark_target_entry();").unwrap();
        assert!(argument < checkpoint, "{harness}");
    }

    #[test]
    fn bundled_driver_is_locatable_in_tree() {
        let runtime = locate_php_runtime().expect("php_runtime locatable in-tree");
        assert!(runtime.join("govfuzz_driver.php").is_file());
    }
}
