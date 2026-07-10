// SPDX-License-Identifier: Apache-2.0

//! Native Python fuzzing lane (M3.1): generate a govfuzz harness module, copy the
//! `python_runtime` (decode/cov/driver), and emit a `harnesses/<id>/main` launcher that
//! runs the target under a persistent CPython speaking the `GOVFUZZ_FRAMED`
//! fork-server protocol with `sys.monitoring`/`sys.settrace` edge coverage into the
//! shared map — the SAME builtin-engine execution path as C/C++/Rust/Java, no
//! Atheris, no libFuzzer.
//!
//! Python is interpreted, so there is no native binary: the launcher execs the
//! interpreter on the generated driver. "Build" is a `py_compile` syntax gate; the
//! repair loop is a pass-through (the launcher already exists). A missing `python3`
//! or an un-harnessable target (currently: an instance method needing a constructed
//! receiver) skips cleanly — the GNAT-less rule.

use crate::auto::candidate::Candidate;
use python_parser::{parse_python_functions, PyFunction};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Outcome of the native Python build lane (parallels `JavaBuildResult`).
pub enum PythonBuildResult {
    /// `<work>/harnesses/<id>/main` was produced and is ready to fuzz.
    Built,
    /// The lane could not run / the harness could not build. `skip` is true for a
    /// missing toolchain or an un-harnessable target (skip cleanly), false for a
    /// genuine build error worth surfacing.
    Failed { reason: String, skip: bool },
}

fn probe_python() -> Option<PathBuf> {
    which::which("python3")
        .or_else(|_| which::which("python"))
        .ok()
}

/// M22: detected `(major, minor)` of a Python interpreter, or `None` if it could
/// not be run/parsed. Used to detect a Python 2 interpreter up front so the lane
/// skips with an actionable reason instead of letting the Python 3 driver fail
/// later with an opaque import-time `SyntaxError`.
fn python_version(python: &Path) -> Option<(u32, u32)> {
    let out = std::process::Command::new(python)
        .arg("-c")
        .arg("import sys; sys.stdout.write('%d.%d' % sys.version_info[:2])")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.trim().split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

/// Locate the bundled `python_runtime/` directory (decode/cov/driver), relative to
/// the source tree (dev) or the installed binary (release) — mirrors
/// `locate_build_agent_script` for the Java agent.
fn locate_python_runtime() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("python_runtime");
                if cand.join("govfuzz_driver.py").is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("python_runtime"));
    if let Some(p) = &from_manifest {
        if p.join("govfuzz_driver.py").is_file() {
            return from_manifest;
        }
    }
    None
}

/// The single public entry point of the lane.
pub fn build_python_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> PythonBuildResult {
    let Some(python) = probe_python() else {
        return PythonBuildResult::Failed {
            reason: "no `python3` interpreter found; install Python 3 to fuzz Python \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };
    // M22: a Python 2 interpreter (the only `python` on some legacy hosts) cannot
    // run the Python 3 driver. Detect it up front and skip with an actionable
    // reason rather than letting the import smoke-test fail with an opaque
    // SyntaxError. The Python 2 fuzzing lane is M22 Phase 2.
    if let Some((major, minor)) = python_version(&python) {
        if major < 3 {
            return PythonBuildResult::Failed {
                reason: format!(
                    "interpreter at {} is Python {major}.{minor}; the Python-2 fuzzing \
                     lane is not yet available (M22 Phase 2) — install python3 to fuzz \
                     this target",
                    python.display()
                ),
                skip: true,
            };
        }
    }
    let Some(runtime) = locate_python_runtime() else {
        return PythonBuildResult::Failed {
            reason: "could not locate the bundled python_runtime/ (decode/cov/driver)".to_owned(),
            skip: false,
        };
    };

    // Resolve the target function by re-parsing the source and matching (name, line).
    let resolved = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return PythonBuildResult::Failed { reason, skip: true },
    };
    let func = &resolved.func;

    // Compute the importable module path + the directory to put on PYTHONPATH.
    let (import_root, module) = resolve_module(&candidate.source_path, source_root);

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let gen_pkg = auto_dir.join("govfuzzgen");
    if let Err(e) = std::fs::create_dir_all(&gen_pkg) {
        return PythonBuildResult::Failed {
            reason: format!("create {}: {e}", gen_pkg.display()),
            skip: false,
        };
    }

    // Copy the runtime modules next to the harness so they are importable.
    for f in ["govfuzz_decode.py", "govfuzz_cov.py", "govfuzz_driver.py"] {
        if let Err(e) = std::fs::copy(runtime.join(f), auto_dir.join(f)) {
            return PythonBuildResult::Failed {
                reason: format!("copy runtime {f}: {e}", f = f),
                skip: false,
            };
        }
    }
    let _ = std::fs::write(
        gen_pkg.join("__init__.py"),
        "# SPDX-License-Identifier: Apache-2.0\n",
    );

    // Generate the harness module.
    let harness_src = generate_harness(&module, func, resolved.receiver.as_deref());
    let harness_path = gen_pkg.join("harness.py");
    if let Err(e) = std::fs::write(&harness_path, &harness_src) {
        return PythonBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_path.display()),
            skip: false,
        };
    }

    // Build gate: py_compile the generated harness (syntax only; no target execution).
    let compile = Command::new(&python)
        .arg("-m")
        .arg("py_compile")
        .arg(&harness_path)
        .output();
    match compile {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PythonBuildResult::Failed {
                reason: format!(
                    "py_compile of generated harness failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                skip: false,
            };
        }
        Err(e) => {
            return PythonBuildResult::Failed {
                reason: format!("could not run py_compile: {e}"),
                skip: false,
            };
        }
    }

    let pythonpath = format!("{}:{}", auto_dir.display(), import_root.display());

    // Import smoke-test: actually import the harness (which imports the target
    // module) so a target that isn't importable under this interpreter — a missing
    // third-party dependency, a newer-Python syntax, an import-time error — is a
    // CLEAN SKIP instead of a silent "built, 0 executions" run. This executes the
    // module's import-time code, the same exposure as the fuzz step (which runs the
    // target); bounded by a timeout. Run without the shim so import-time mkdir of
    // caches can't trip a behavioral oracle.
    let smoke = Command::new(&python)
        .arg("-B")
        .arg("-c")
        .arg("import govfuzzgen.harness")
        .env("PYTHONPATH", &pythonpath)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(&auto_dir)
        .output();
    match smoke {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return PythonBuildResult::Failed {
                reason: format!(
                    "target module `{module}` is not importable under this interpreter \
                     (skipped cleanly): {}",
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("import error")
                ),
                skip: true,
            };
        }
        Err(e) => {
            return PythonBuildResult::Failed {
                reason: format!("could not run import smoke-test: {e}"),
                skip: false,
            };
        }
    }

    // Emit the launcher `main`. Carries the GOVFUZZ_FRAMED marker the engine greps
    // for; the interpreter inherits GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM across the exec.
    let main_path = auto_dir.join("main");
    let driver = auto_dir.join("govfuzz_driver.py");
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_PY_LAUNCHER govfuzz CPython driver launcher (native Python lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM in the environment; the\n\
         # interpreter inherits them across this exec. govfuzz_cov joins the file-backed\n\
         # GOVFUZZ_COV_SHM map; govfuzz_driver speaks the framed fork-server protocol.\n\
         # PYTHONDONTWRITEBYTECODE: don't write __pycache__ at import time — its mkdir\n\
         # would otherwise trip the insecure-permissions behavioral oracle (GF-416) on\n\
         # the interpreter's own bytecode cache, a false positive unrelated to the target.\n\
         GOVFUZZ_HARNESS_MODULE=\"govfuzzgen.harness\" \\\n\
         GOVFUZZ_TRACE_PREFIX=\"{trace}\" \\\n\
         GOVFUZZ_TARGET_PACKAGE=\"{pkg}\" \\\n\
         GOVFUZZ_COVERED_LINES=\"{covered}\" \\\n\
         PYTHONDONTWRITEBYTECODE=1 \\\n\
         PYTHONPATH=\"{pythonpath}:${{PYTHONPATH}}\" \\\n\
         exec \"{python}\" -B \"{driver}\" \"$@\"\n",
        trace = import_root.display(),
        pkg = module.split('.').next().unwrap_or(&module),
        covered = auto_dir.join("covered-lines.txt").display(),
        pythonpath = pythonpath,
        python = python.display(),
        driver = driver.display(),
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return PythonBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return PythonBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    PythonBuildResult::Built
}

/// A resolved target: the matched function plus, for an instance method, the
/// receiver-construction expression (`_t.Class()`).
struct ResolvedTarget {
    func: PyFunction,
    /// Construction expression for an instance method's receiver, or `None` for a
    /// module-level function / `@staticmethod` / `@classmethod`.
    receiver: Option<String>,
}

/// Re-parse the candidate source, find the function by (qualified name, line), and
/// resolve the receiver for an instance method (no-arg constructor only — if the
/// class's `__init__` needs arguments we skip cleanly, mirroring the Rust/Java
/// no-arg-ctor first cut).
fn resolve_target(candidate: &Candidate) -> Result<ResolvedTarget, String> {
    let source = std::fs::read_to_string(&candidate.source_path)
        .map_err(|e| format!("read {}: {e}", candidate.source_path.display()))?;
    let functions =
        parse_python_functions(&source).map_err(|_| "failed to parse Python source".to_owned())?;
    let func = functions
        .iter()
        .find(|f| f.qualified() == candidate.name && f.line == candidate.line)
        .or_else(|| functions.iter().find(|f| f.qualified() == candidate.name))
        .cloned()
        .ok_or_else(|| format!("target `{}` no longer present in source", candidate.name))?;

    let receiver = resolve_receiver(&func, &functions)?;
    Ok(ResolvedTarget { func, receiver })
}

/// Resolve an instance method's receiver. `None` for module fns / static / class
/// methods. For an instance method, synthesize `_t.Class()` IFF the class's
/// `__init__` (if defined in this file) takes no required arguments; otherwise
/// return an `Err` so the target skips cleanly.
fn resolve_receiver(func: &PyFunction, all: &[PyFunction]) -> Result<Option<String>, String> {
    if !func.is_method || func.is_staticmethod || func.is_classmethod {
        return Ok(None);
    }
    let Some(class) = func.class_name.as_deref() else {
        return Ok(None);
    };
    // The parser already drops the implicit `self`, so a non-default, non-varargs
    // param of `__init__` is a REQUIRED constructor argument.
    if let Some(init) = all
        .iter()
        .find(|f| f.class_name.as_deref() == Some(class) && f.name == "__init__")
    {
        let required = init
            .params
            .iter()
            .filter(|p| !p.is_varargs && !p.has_default)
            .count();
        if required > 0 {
            return Err(format!(
                "instance method `{}` needs a receiver, but `{class}.__init__` takes \
                 {required} required argument(s); only no-arg-constructible receivers \
                 are supported (skipped cleanly)",
                func.qualified()
            ));
        }
    }
    // No __init__ in this file (inherited / default) or a no-arg __init__.
    Ok(Some(format!("_t.{class}()")))
}

/// Map a source file to `(import_root_dir, dotted_module)`. Walks up through
/// directories that contain `__init__.py` to find the package root; the directory
/// ABOVE the top package goes on PYTHONPATH and the module is the dotted path from
/// there. A file with no package ancestry imports as its bare stem from its own dir.
fn resolve_module(source_path: &Path, source_root: &Path) -> (PathBuf, String) {
    let stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_owned();
    let Some(mut dir) = source_path.parent().map(Path::to_path_buf) else {
        return (source_root.to_path_buf(), stem);
    };
    let mut parts = vec![stem];
    // Walk up while the directory is a package (has __init__.py).
    while dir.join("__init__.py").is_file() {
        let pkg = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        if pkg.is_empty() {
            break;
        }
        parts.push(pkg);
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => break,
        }
    }
    parts.reverse();
    (dir, parts.join("."))
}

/// Decide how to decode one parameter from the fuzz cursor, by annotation then
/// name heuristic. `last` controls whether a byte/str param drains the rest.
fn decode_expr(p: &python_parser::PyParam, last: bool) -> String {
    let ann = p.annotation.as_deref().unwrap_or("").trim();
    let name = p.name.to_ascii_lowercase();
    // A file-like param (`fp`/`file`/`stream` or an IO annotation) must NOT get raw
    // bytes — `bytes` has no `.read()`, which would manufacture an AttributeError
    // false positive (plistlib.load(fp)). Wrap the fuzz bytes in a real stream.
    let is_text_file = ann.contains("TextIO") || ann.contains("StringIO");
    let is_file = is_text_file
        || ann.contains("BinaryIO")
        || ann.contains("BytesIO")
        || ann.contains("IO[")
        || ann == "IO"
        || ann.contains("BufferedReader")
        || ann.contains("BufferedIOBase")
        || matches!(
            name.as_str(),
            "fp" | "file" | "fileobj" | "fobj" | "infile" | "stream" | "f" | "readable"
        );
    if is_file {
        let bytes_expr = if last {
            "_c.rest()"
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))"
        };
        return if is_text_file {
            format!("io.StringIO({bytes_expr}.decode('utf-8', 'replace'))")
        } else {
            format!("io.BytesIO({bytes_expr})")
        };
    }
    // Container params: synthesize an empty container rather than raw bytes, so an
    // internal function with an output `kwds: dict` / `out: list` (e.g.
    // email DateHeader.parse(value, kwds)) is fuzzed sensibly instead of raising a
    // wrong-type error on `bytes['key']=...`. Keyword-ish names map to dict too.
    let is_dict = ann.starts_with("dict")
        || ann.starts_with("Dict")
        || ann.contains("Mapping")
        || matches!(
            name.as_str(),
            "kwds" | "kw" | "kwargs" | "options" | "opts" | "params" | "attrs" | "headers"
        );
    let is_list = ann.starts_with("list")
        || ann.starts_with("List")
        || ann.starts_with("Sequence")
        || ann.starts_with("Iterable")
        || matches!(name.as_str(), "items" | "elements" | "rows" | "args");
    let is_set = ann.starts_with("set") || ann.starts_with("Set") || ann.starts_with("frozenset");
    if is_dict {
        return "{}".to_owned();
    }
    if is_list {
        return "[]".to_owned();
    }
    if is_set {
        return "set()".to_owned();
    }
    let is_bytes = ann.starts_with("bytes")
        || ann.starts_with("bytearray")
        || ann.starts_with("memoryview")
        || matches!(
            name.as_str(),
            "data" | "buf" | "buffer" | "payload" | "raw" | "blob" | "b" | "bytes_" | "chunk"
        );
    let is_str = ann.starts_with("str")
        || matches!(
            name.as_str(),
            "text" | "s" | "string" | "content" | "src" | "source" | "line" | "msg" | "message"
        );
    let is_int = ann == "int" || matches!(name.as_str(), "n" | "size" | "length" | "count" | "i");
    let is_float = ann == "float";
    let is_bool = ann == "bool" || ann == "boolean";
    if is_int {
        "_c.i32()".to_owned()
    } else if is_float {
        "_c.f64()".to_owned()
    } else if is_bool {
        "_c.boolean()".to_owned()
    } else if is_str {
        if last {
            "_c.rest().decode('utf-8', 'replace')".to_owned()
        } else {
            "_c.text()".to_owned()
        }
    } else if is_bytes {
        if last {
            "_c.rest()".to_owned()
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))".to_owned()
        }
    } else {
        // Unknown/unannotated -> hand it raw bytes (the most fuzzable default).
        if last {
            "_c.rest()".to_owned()
        } else {
            "_c.take_bytes(_c.bounded_length(0, _c.remaining()))".to_owned()
        }
    }
}

/// Emit `govfuzzgen/harness.py` exposing `govfuzz_run_one(data: bytes)`. Decodes
/// only the REQUIRED parameters (skip defaulted + `*args`/`**kwargs`) so we never
/// pass a keyword-only-with-default param positionally (e.g. `loads(s, *,
/// parse_float=...)` -> `loads(a0)`). For an instance method, construct a fresh
/// receiver per input so each input starts from clean state.
fn generate_harness(module: &str, func: &PyFunction, receiver: Option<&str>) -> String {
    let decodable: Vec<&python_parser::PyParam> = func
        .params
        .iter()
        .filter(|p| !p.is_varargs && !p.has_default)
        .collect();
    let n = decodable.len();
    let mut lines = String::new();
    let mut args = Vec::new();
    for (i, p) in decodable.iter().enumerate() {
        let last = i + 1 == n;
        lines.push_str(&format!("    a{i} = {}\n", decode_expr(p, last)));
        args.push(format!("a{i}"));
    }
    let arglist = args.join(", ");
    let call = match receiver {
        // Instance method: fresh receiver per input, then call the bare method name.
        Some(recv) => format!(
            "    _recv = {recv}\n    _recv.{method}({arglist})\n",
            recv = recv,
            method = func.name,
            arglist = arglist,
        ),
        // Module fn / @staticmethod / @classmethod: an attribute path on the module.
        None => format!(
            "    _t.{}({arglist})\n",
            func.qualified(),
            arglist = arglist
        ),
    };
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # Generated by govfuzz (native Python lane). Decodes fuzz bytes into typed\n\
         # arguments and calls the target. Do not edit.\n\
         import io\n\
         import govfuzz_decode\n\
         import {module} as _t\n\
         \n\
         \n\
         def govfuzz_run_one(data):\n\
         \x20   _c = govfuzz_decode.open_cursor(data)\n\
         {lines}{call}",
        module = module,
        lines = lines,
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

    fn func(name: &str, params: &[(&str, Option<&str>)], method: bool) -> PyFunction {
        PyFunction {
            name: name.to_owned(),
            line: 1,
            params: params
                .iter()
                .map(|(n, a)| python_parser::PyParam {
                    name: (*n).to_owned(),
                    annotation: a.map(|s| s.to_owned()),
                    is_varargs: false,
                    has_default: false,
                })
                .collect(),
            decorators: Vec::new(),
            return_annotation: None,
            is_method: method,
            class_name: if method { Some("C".to_owned()) } else { None },
            is_staticmethod: false,
            is_classmethod: false,
            is_property: false,
            is_async: false,
            is_private: false,
            is_dunder: false,
        }
    }

    #[test]
    fn single_bytes_param_gets_whole_input() {
        let h = generate_harness(
            "pkg.mod",
            &func("parse", &[("data", Some("bytes"))], false),
            None,
        );
        assert!(h.contains("import pkg.mod as _t"));
        assert!(h.contains("a0 = _c.rest()"));
        assert!(h.contains("_t.parse(a0)"));
        assert!(h.contains("def govfuzz_run_one(data):"));
    }

    #[test]
    fn typed_params_decode_by_annotation() {
        let h = generate_harness(
            "m",
            &func(
                "f",
                &[("s", Some("str")), ("n", Some("int")), ("b", Some("bytes"))],
                false,
            ),
            None,
        );
        assert!(h.contains("a0 = _c.text()")); // str, not last
        assert!(h.contains("a1 = _c.i32()"));
        assert!(h.contains("a2 = _c.rest()")); // bytes, last
        assert!(h.contains("_t.f(a0, a1, a2)"));
    }

    #[test]
    fn staticmethod_call_uses_qualified_path() {
        let mut m = func("decode", &[("data", Some("bytes"))], true);
        m.is_staticmethod = true;
        let h = generate_harness("m", &m, None);
        assert!(h.contains("_t.C.decode(a0)"));
    }

    #[test]
    fn instance_method_constructs_receiver_and_skips_defaulted_params() {
        let mut m = func("feed", &[("chunk", Some("bytes"))], true);
        // Add a defaulted param that must NOT be decoded/passed.
        m.params.push(python_parser::PyParam {
            name: "strict".to_owned(),
            annotation: Some("bool".to_owned()),
            is_varargs: false,
            has_default: true,
        });
        let h = generate_harness("m", &m, Some("_t.C()"));
        assert!(h.contains("_recv = _t.C()"), "constructs receiver:\n{h}");
        assert!(
            h.contains("_recv.feed(a0)"),
            "calls bare method on receiver:\n{h}"
        );
        assert!(!h.contains("a1"), "defaulted param must be skipped:\n{h}");
    }

    fn param(name: &str, ann: Option<&str>) -> python_parser::PyParam {
        python_parser::PyParam {
            name: name.to_owned(),
            annotation: ann.map(|s| s.to_owned()),
            is_varargs: false,
            has_default: false,
        }
    }

    #[test]
    fn file_param_wrapped_in_stream_not_raw_bytes() {
        // `fp` by name -> BytesIO (binary); avoids the `bytes has no .read()` FP.
        assert!(decode_expr(&param("fp", None), true).contains("io.BytesIO"));
        // An IO annotation -> BytesIO.
        assert!(decode_expr(&param("x", Some("BinaryIO")), true).contains("io.BytesIO"));
        // A text IO annotation -> StringIO.
        assert!(decode_expr(&param("x", Some("TextIO")), true).contains("io.StringIO"));
    }

    #[test]
    fn container_params_synthesize_empty_containers() {
        assert_eq!(decode_expr(&param("kwds", None), true), "{}");
        assert_eq!(decode_expr(&param("x", Some("dict")), true), "{}");
        assert_eq!(decode_expr(&param("items", None), true), "[]");
        assert_eq!(decode_expr(&param("x", Some("set")), true), "set()");
    }

    #[test]
    fn harness_imports_io_for_file_params() {
        let mut f = func("load", &[("fp", None)], false);
        f.params = vec![param("fp", None)];
        let h = generate_harness("plistlib", &f, None);
        assert!(h.contains("import io"));
        assert!(h.contains("io.BytesIO"));
        assert!(h.contains("_t.load(a0)"));
    }

    #[test]
    fn resolve_module_walks_packages() {
        // Build a temp tree: root/pkg/sub/mod.py with __init__.py in pkg and sub.
        let tmp = std::env::temp_dir().join(format!("gfpytest_{}", std::process::id()));
        let sub = tmp.join("pkg").join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(tmp.join("pkg").join("__init__.py"), "").unwrap();
        std::fs::write(sub.join("__init__.py"), "").unwrap();
        let modf = sub.join("mod.py");
        std::fs::write(&modf, "def f(): pass\n").unwrap();
        let (root, module) = resolve_module(&modf, &tmp);
        assert_eq!(root, tmp);
        assert_eq!(module, "pkg.sub.mod");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// True if `code` contains an f-string prefix at a token boundary (so we do
    /// not misflag `stuff"` as an f-string).
    fn has_fstring(code: &str) -> bool {
        let b = code.as_bytes();
        for i in 0..b.len() {
            if b[i] == b'f' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'\'') {
                let boundary = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                if boundary {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn bundled_driver_imports_on_python_3_0_no_fstrings() {
        // M22 Phase 1b: the driver must import on Python 3.0-3.5 (legacy gov/mil
        // interpreters), so it must contain no f-strings (a SyntaxError <3.6).
        let runtime = locate_python_runtime().expect("python_runtime locatable in-tree");
        let driver = std::fs::read_to_string(runtime.join("govfuzz_driver.py")).unwrap();
        for (i, line) in driver.lines().enumerate() {
            let code = line.split('#').next().unwrap_or("");
            assert!(
                !has_fstring(code),
                "f-string at line {} breaks Python <3.6 import: {line}",
                i + 1
            );
        }
    }

    #[test]
    fn python_version_parses_installed_interpreter() {
        let Some(py) = probe_python() else {
            return; // no interpreter installed -> skip, like a GNAT-less Ada skip
        };
        let v = python_version(&py).expect("python_version should parse a real interpreter");
        assert!(v.0 >= 2, "major version is sane: {v:?}");
    }
}
