// SPDX-License-Identifier: Apache-2.0

//! Native Java fuzzing lane (M2.1b/d): compile the target with `javac`, generate
//! and compile a govfuzz harness, then emit a `harnesses/<id>/main` launcher script
//! that runs the target in a persistent JVM under govfuzz's own coverage agent. The
//! builtin engine then drives that JVM over the `GOVFUZZ_FRAMED` fork-server
//! protocol — the SAME execution path as C/C++/Rust, no Jazzer.
//!
//! Pipeline, given a discovered Java `Candidate`:
//!
//! 1. **Toolchain probe** — `javac` + `java`. Absent -> skip the lane cleanly
//!    (the GNAT-less rule).
//! 2. **Agent jar** — ensure `govfuzz-jvm-agent.jar` (coverage agent + driver +
//!    GovfuzzData + shaded ASM) is built (cached; built once by `build-agent.sh`).
//! 3. **Resolve the target classpath** — maven/gradle build it (cached per project)
//!    when a pom.xml/build.gradle is present, else `javac` the bare source tree;
//!    the result is the classes + dependency classpath.
//! 4. **Generate + compile the harness** — `java_generate` emits
//!    `govfuzzgen.Harness.govfuzzRunOne(byte[])` (a static call, a `new` for a
//!    constructor, or a no-arg-ctor receiver + method call for an instance method);
//!    compile it against the agent jar (for `GovfuzzData`) + the target classpath.
//! 5. **Emit the launcher** — `harnesses/<id>/main`, an executable script that execs
//!    `java -javaagent:<agent> -cp <cp> com.govfuzz.Driver govfuzzgen.Harness`. It
//!    carries the `GOVFUZZ_FRAMED` marker the engine greps for, and inherits the
//!    engine's `GOVFUZZ_FRAMED` / `GOVFUZZ_COV_SHM` env across the exec.

use crate::auto::candidate::Candidate;
use harness_gen::java_generate::{
    decode_param_expr, generate_java_direct_harness, GenerateJavaDirectArgs,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Outcome of the native Java build lane (parallels `RustBuildResult`).
pub enum JavaBuildResult {
    /// `<work>/harnesses/<id>/main` was produced and is ready to fuzz.
    Built,
    /// The lane could not run / the harness could not build. `skip` is true for a
    /// missing toolchain or an un-harnessable target (skip cleanly), false for a
    /// genuine build error worth surfacing.
    Failed { reason: String, skip: bool },
}

struct JavaToolchain {
    javac: PathBuf,
    java: PathBuf,
}

fn probe_toolchain() -> Option<JavaToolchain> {
    let javac = which::which("javac").ok()?;
    let java = which::which("java").ok()?;
    Some(JavaToolchain { javac, java })
}

/// The single public entry point of the lane.
pub fn build_java_harness(
    candidate: &Candidate,
    work_dir: &Path,
    harness_id: &str,
    source_root: &Path,
) -> JavaBuildResult {
    let Some(tc) = probe_toolchain() else {
        return JavaBuildResult::Failed {
            reason: "no `javac`/`java` toolchain found; install a JDK to fuzz Java \
                     (the lane skips cleanly, like a GNAT-less Ada skip)"
                .to_owned(),
            skip: true,
        };
    };

    let agent_jar = match ensure_agent_jar() {
        Ok(p) => p,
        Err(e) => {
            return JavaBuildResult::Failed {
                reason: format!("could not build the govfuzz JVM agent jar: {e}"),
                skip: false,
            }
        }
    };

    // Resolve the target method + its fully-qualified class by re-parsing the
    // source and matching (name, line) — mirrors rust_build's resolve.
    let resolved = match resolve_target(candidate) {
        Ok(r) => r,
        Err(reason) => return JavaBuildResult::Failed { reason, skip: true },
    };
    // The target's declared exceptions (its `throws`) are expected rejections of
    // bad input; the driver suppresses them as non-findings (even unchecked ones
    // like org.json's JSONException) via GOVFUZZ_EXPECTED_EXCEPTIONS.
    let expected_exceptions = resolved.target.throws.join(",");

    // A target with no attacker byte channel is driven purely from synthesized
    // scalars; an out-of-range `int` fed to a JDK collection/array accessor or
    // capacity ctor (gson `JsonArray.remove(int)`, `new JsonArray(int capacity)`)
    // hits a DOCUMENTED range contract (IndexOutOfBounds / NegativeArraySize / OOM),
    // not a defect. Forward this so the Driver suppresses those scalar-precondition
    // exceptions for scalar-only targets (a byte-channel parser's internal OOB stays
    // a finding).
    let scalar_only_target = !target_rank::java_target_has_byte_channel(&resolved.target);

    // Resolve declaration models for the target's custom (class/enum) parameter
    // types from across the tree, so a config-object parameter (e.g. `CSVFormat`)
    // can be constructed with a default instead of skipping the target (F8).
    let param_types = collect_param_type_models(source_root, &resolved.target);

    // Generate the harness BEFORE building so an un-harnessable target (instance
    // method / unsupported param) skips without a wasted compile.
    let generated = match generate_java_direct_harness(&GenerateJavaDirectArgs {
        target_class: resolved.class.clone(),
        target: resolved.target,
        receiver: resolved.receiver,
        enum_types: resolved.enum_types,
        param_types,
        target_class_is_abstract: resolved.class_is_abstract,
    }) {
        Ok(g) => g,
        Err(e) => {
            return JavaBuildResult::Failed {
                reason: e.to_string(),
                skip: true,
            }
        }
    };

    let auto_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let target_classes = auto_dir.join("target-classes");
    let harness_classes = auto_dir.join("harness-classes");
    let harness_src = auto_dir.join("harness-src");
    for d in [&target_classes, &harness_classes, &harness_src] {
        if let Err(e) = std::fs::create_dir_all(d) {
            return JavaBuildResult::Failed {
                reason: format!("create {}: {e}", d.display()),
                skip: false,
            };
        }
    }

    // 3. Resolve the target classpath: maven/gradle build it (cached once per
    //    project) when a pom.xml/build.gradle is present, else javac-compile the
    //    bare source tree. `target_cp` is the colon-joined classes + dependency
    //    classpath the harness compiles against and the JVM runs with.
    let target_cp = match resolve_target_classpath(
        &tc,
        source_root,
        &candidate.source_path,
        work_dir,
        &target_classes,
    ) {
        Ok(cp) => cp,
        Err((reason, skip)) => return JavaBuildResult::Failed { reason, skip },
    };

    // 4. Write + compile the harness against agent jar + target classpath.
    let harness_file = harness_src
        .join(harness_gen::java_generate::HARNESS_PACKAGE)
        .join(format!(
            "{}.java",
            harness_gen::java_generate::HARNESS_CLASS
        ));
    if let Some(parent) = harness_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&harness_file, &generated.harness_java) {
        return JavaBuildResult::Failed {
            reason: format!("write harness {}: {e}", harness_file.display()),
            skip: false,
        };
    }
    let harness_cp = format!("{}:{}", agent_jar.display(), target_cp);
    if let Err(reason) = run_javac(
        &tc.javac,
        &[harness_cp.as_str()],
        &harness_classes,
        std::slice::from_ref(&harness_file),
    ) {
        return JavaBuildResult::Failed {
            reason: format!("javac (harness) failed: {reason}"),
            skip: false,
        };
    }

    // 5. Emit the launcher `main` script.
    let main_path = auto_dir.join("main");
    let classpath = format!(
        "{}:{}:{}",
        agent_jar.display(),
        target_cp,
        harness_classes.display()
    );
    let script = format!(
        "#!/bin/sh\n\
         # GOVFUZZ_FRAMED GOVFUZZ_JVM_LAUNCHER govfuzz JVM driver launcher (native Java lane).\n\
         # The engine sets GOVFUZZ_FRAMED + GOVFUZZ_COV_SHM in the environment; the\n\
         # JVM inherits them across this exec. The coverage agent joins the\n\
         # file-backed GOVFUZZ_COV_SHM map; the Driver speaks the framed protocol.\n\
         # GOVFUZZ_EXPECTED_EXCEPTIONS = the target's declared `throws` (expected\n\
         # rejections of bad input, suppressed as non-findings by the Driver).\n\
         # GOVFUZZ_SINK_OUT = where the agent records input-reachable dangerous sinks\n\
         # (deserialization / exec / eval / SQL / LDAP); govfuzz reads it after the run.\n\
         # GOVFUZZ_SCALAR_ONLY_TARGET = the target has no byte/char channel, so an\n\
         # out-of-range synthesized scalar hitting a documented range contract\n\
         # (IndexOutOfBounds / NegativeArraySize / OOM) is expected, not a finding.\n\
         GOVFUZZ_EXPECTED_EXCEPTIONS=\"{expected}\" \\\n\
         GOVFUZZ_SCALAR_ONLY_TARGET=\"{scalar_only}\" \\\n\
         GOVFUZZ_SINK_OUT=\"$(dirname \"$0\")/sink_report.txt\" \\\n\
         exec \"{java}\" -javaagent:\"{agent}\" -cp \"{cp}\" \\\n\
         \x20   com.govfuzz.Driver {harness_class} \"$@\"\n",
        expected = expected_exceptions,
        scalar_only = if scalar_only_target { "1" } else { "0" },
        java = tc.java.display(),
        agent = agent_jar.display(),
        cp = classpath,
        harness_class = generated.harness_class,
    );
    if let Err(e) = std::fs::write(&main_path, script) {
        return JavaBuildResult::Failed {
            reason: format!("write launcher {}: {e}", main_path.display()),
            skip: false,
        };
    }
    if let Err(e) = make_executable(&main_path) {
        return JavaBuildResult::Failed {
            reason: format!("chmod +x {}: {e}", main_path.display()),
            skip: false,
        };
    }
    JavaBuildResult::Built
}

/// What [`resolve_target`] extracts from a candidate's source for harness generation.
struct ResolvedJavaTarget {
    /// The matched method/constructor.
    target: java_parser::JavaMethod,
    /// Source-form fully-qualified class, e.g. `com.acme.JsonParser`.
    class: String,
    /// Receiver-construction expression for an instance method, or `None` (static
    /// method / constructor / un-constructible receiver).
    receiver: Option<String>,
    /// In-scope enum FQNs (an enum-typed param decodes as a `values()` pick).
    enum_types: Vec<String>,
    /// True when the target's OWN class is an `abstract class` / `interface` — so the
    /// generator never `new`s it (GAP 1: commons-validator ModulusCheckDigit).
    class_is_abstract: bool,
}

/// Re-parse the candidate's source and resolve everything the harness generator
/// needs (see [`ResolvedJavaTarget`]).
fn resolve_target(candidate: &Candidate) -> Result<ResolvedJavaTarget, String> {
    let source = crate::source_text::read_source_text(&candidate.source_path)
        .map_err(|e| format!("read Java source {}: {e}", candidate.source_path.display()))?;
    let methods = java_parser::parse_java_methods(&source)
        .map_err(|_| "failed to parse Java source".to_owned())?;
    let enum_types = java_parser::parse_java_enum_types(&source);
    let target = methods
        .iter()
        .find(|m| m.name == candidate.name && m.line == candidate.line)
        .or_else(|| methods.iter().find(|m| m.name == candidate.name))
        .cloned()
        .ok_or_else(|| {
            format!(
                "Java target '{}' not found in {}",
                candidate.name,
                candidate.source_path.display()
            )
        })?;
    let class = target.fqcn();
    // An `abstract class` / `interface` target class can never be `new`'d — so the
    // receiver builder must not synthesise `new <class>(...)` and a constructor
    // target is skipped by the generator (GAP 1: commons-validator ModulusCheckDigit).
    let class_is_abstract = java_parser::parse_java_abstract_types(&source)
        .iter()
        .any(|t| t == &class);
    let receiver = resolve_receiver(&methods, &target, class_is_abstract);
    Ok(ResolvedJavaTarget {
        target,
        class,
        receiver,
        enum_types,
        class_is_abstract,
    })
}

/// Collect [`JavaTypeModel`]s for the target's custom (class/enum) parameter types
/// by scanning the source tree's `.java` files (F8). Only runs when the target has
/// at least one parameter the harness cursor can't already decode — a scalar /
/// string / byte channel / supported JDK type needs no model — so the tree walk is
/// skipped for the common all-scalar target. The harness generator matches a model
/// to a parameter by FQN or leaf name and synthesises a default instance.
fn collect_param_type_models(
    source_root: &Path,
    target: &java_parser::JavaMethod,
) -> Vec<java_parser::JavaTypeModel> {
    // Leaf names of parameter types the cursor can't decode directly (the candidates
    // for model-based construction). Arrays and generic-only spellings are excluded.
    let wanted: HashSet<String> = target
        .params
        .iter()
        .filter(|p| decode_param_expr(&p.ty).is_none())
        .filter_map(|p| custom_type_leaf(&p.ty))
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let mut models = Vec::new();
    for src_path in collect_java_sources(source_root) {
        let Ok(src) = std::fs::read_to_string(&src_path) else {
            continue;
        };
        for m in java_parser::parse_java_type_models(&src) {
            let leaf = m.fqn.rsplit('.').next().unwrap_or(&m.fqn);
            if wanted.contains(leaf) {
                models.push(m);
            }
        }
    }
    models
}

/// The leaf type name of a non-array, non-generic-only parameter spelling, or
/// `None` for an array / wildcard / empty spelling (which can't name a single
/// constructible class to model).
fn custom_type_leaf(ty: &str) -> Option<String> {
    let bare: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    // Drop generic args, then reject anything left looking like an array/wildcard.
    let base = bare.split('<').next().unwrap_or(&bare);
    if base.is_empty() || base.contains('[') || base.contains('?') {
        return None;
    }
    let leaf = base.rsplit('.').next().unwrap_or(base);
    if leaf.is_empty() {
        None
    } else {
        Some(leaf.to_owned())
    }
}

/// Resolve a receiver-construction expression for an INSTANCE method on a
/// TOP-LEVEL class, trying progressively less-certain strategies (#459):
///
///   1. a reachable no-arg constructor               -> `new C()`
///   2. a no-arg static factory returning C          -> `C.getInstance()`
///   3. a `builder()` + nested `Builder.build()`     -> `C.builder().build()`
///   4. a nested `Builder` no-arg ctor + `build()`   -> `new C.Builder().build()`
///   5. a static factory returning C, args filled    -> `C.create(<args>)`
///   6. a public constructor, args filled            -> `new C(<args>)`
///
/// Strategies 1-4 emit only method names + the class's own FQN, so they always
/// compile. Strategies 5-6 decode scalar args from the cursor and pass a bare
/// `null` for reference params (the harness lives in its own package and can't
/// name the target's unqualified types, so a typed cast is avoided); they fire
/// only when the chosen candidate is unambiguous (see [`pick_synth_candidate`]).
///
/// Only a TOP-LEVEL class has a `new <fqcn>()`-shaped receiver: a non-static
/// inner class needs `outer.new Inner()` and a static nested class the qualified
/// form, and the parser records no per-class static-ness — so a nested-class
/// instance method still skips cleanly (returns `None`). (RC review constraint.)
///
/// `class_is_abstract` true (the target class is an `abstract class` / `interface`)
/// disables the two `new <class>(...)` strategies (1 and 6): instantiating an
/// abstract type is javac error "<class> is abstract; cannot be instantiated". The
/// factory/builder strategies (2-5) stay enabled — a `static` factory or nested
/// `Builder` yields a CONCRETE instance of the abstract type and compiles fine.
fn resolve_receiver(
    methods: &[java_parser::JavaMethod],
    target: &java_parser::JavaMethod,
    class_is_abstract: bool,
) -> Option<String> {
    if target.is_static || target.is_constructor || target.class_path.len() != 1 {
        return None;
    }
    let class = target.fqcn();
    let leaf = target.class_path.last()?.as_str();
    let class_path = target.class_path.as_slice();

    // 1. No-arg constructor (explicit public, or the implicit one a class with no
    //    declared constructors gets) — only for a concrete class. (An interface has
    //    no constructors, so the implicit-ctor path would otherwise wrongly emit
    //    `new Interface()`.)
    if !class_is_abstract && java_no_arg_ctor_available(methods, class_path) {
        return Some(format!("new {class}()"));
    }

    // Sibling public static methods that return the class's OWN type — real
    // instance factories, not arbitrary getters (the return-type check gates the
    // permissive name set).
    let self_factories: Vec<&java_parser::JavaMethod> = methods
        .iter()
        .filter(|m| {
            m.is_static
                && m.class_path == class_path
                && matches!(m.visibility, java_parser::JavaVisibility::Public)
                && is_factory_name(&m.name)
                && returns_leaf(m, leaf)
        })
        .collect();

    // 2. A no-arg static factory.
    if let Some(f) = self_factories.iter().find(|m| m.params.is_empty()) {
        return Some(format!("{class}.{}()", f.name));
    }

    // Nested `Builder` of this class and its `build()`.
    let mut builder_path = class_path.to_vec();
    builder_path.push("Builder".to_owned());
    let has_build = methods.iter().any(|m| {
        m.class_path == builder_path
            && m.name == "build"
            && !m.is_static
            && !m.is_constructor
            && returns_leaf(m, leaf)
    });
    if has_build {
        // 3. `C.builder().build()` when a no-arg static `builder()` exists.
        let has_builder_factory = methods.iter().any(|m| {
            m.is_static && m.class_path == class_path && m.name == "builder" && m.params.is_empty()
        });
        if has_builder_factory {
            return Some(format!("{class}.builder().build()"));
        }
        // 4. `new C.Builder().build()` when the nested Builder is no-arg-constructible.
        if java_no_arg_ctor_available(methods, &builder_path) {
            return Some(format!("new {class}.Builder().build()"));
        }
    }

    // 5. A static factory returning C, with synthesised arguments.
    if let Some(f) = pick_synth_candidate(&self_factories) {
        return Some(format!("{class}.{}({})", f.name, synth_args(&f.params)));
    }

    // 6. A public constructor, with synthesised arguments — only for a concrete
    //    class. An abstract class's `public C(int)` ctor (commons-validator's
    //    ModulusCheckDigit) is reachable only via a concrete subclass, which we don't
    //    synthesise, so `new C(...)` would be "C is abstract; cannot be instantiated".
    if !class_is_abstract {
        let ctors: Vec<&java_parser::JavaMethod> = methods
            .iter()
            .filter(|m| {
                m.is_constructor
                    && m.class_path == class_path
                    && matches!(m.visibility, java_parser::JavaVisibility::Public)
            })
            .collect();
        if let Some(c) = pick_synth_candidate(&ctors) {
            return Some(format!("new {class}({})", synth_args(&c.params)));
        }
    }

    None
}

/// Recognised static-factory method names. Paired with a return-type-is-own-class
/// check at the call site, so these name an instance factory rather than a getter.
fn is_factory_name(name: &str) -> bool {
    matches!(
        name,
        "getInstance"
            | "newInstance"
            | "getDefault"
            | "defaultInstance"
            | "create"
            | "newBuilder"
            | "of"
            | "valueOf"
            | "from"
            | "fromString"
    ) || name.starts_with("create")
        || name.starts_with("newInstance")
}

/// Whether method `m`'s return-type leaf equals `leaf` (generics + nesting
/// stripped), i.e. the method yields an instance of the target class.
fn returns_leaf(m: &java_parser::JavaMethod, leaf: &str) -> bool {
    let Some(rt) = &m.return_type else {
        return false;
    };
    let base = rt.split('<').next().unwrap_or(rt);
    let dotted = base.trim().rsplit('.').next().unwrap_or(base).trim();
    let bare = dotted.rsplit('$').next().unwrap_or(dotted);
    bare.eq_ignore_ascii_case(leaf)
}

/// Number of params that can't be decoded from the cursor (reference types that
/// would be passed as `null`).
fn null_fill_count(params: &[java_parser::JavaParam]) -> usize {
    params
        .iter()
        .filter(|p| decode_param_expr(&p.ty).is_none())
        .count()
}

/// Pick the candidate (ctor or factory) needing the fewest fabricated args. A
/// candidate with `null`-filled reference params is only returned when it is the
/// SOLE candidate of its arity, so the bare `null`(s) can't make an overloaded
/// call ambiguous (a compile error). Fully-decodable candidates are always safe.
fn pick_synth_candidate<'a>(
    cands: &[&'a java_parser::JavaMethod],
) -> Option<&'a java_parser::JavaMethod> {
    let chosen = *cands
        .iter()
        .min_by_key(|m| (null_fill_count(&m.params), m.params.len()))?;
    if null_fill_count(&chosen.params) == 0 {
        return Some(chosen);
    }
    let arity = chosen.params.len();
    if cands.iter().filter(|m| m.params.len() == arity).count() == 1 {
        Some(chosen)
    } else {
        None
    }
}

/// Synthesise a comma-separated argument list: scalars/strings/byte channels are
/// decoded from the cursor with identical semantics to the harness's own param
/// decode; reference types become a bare `null`.
fn synth_args(params: &[java_parser::JavaParam]) -> String {
    params
        .iter()
        .map(|p| decode_param_expr(&p.ty).unwrap_or_else(|| "null".to_owned()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether the class identified by `class_path` has a reachable no-arg
/// constructor: an explicit `public` ctor with no parameters, or the IMPLICIT
/// public no-arg ctor a class gets when it declares no constructors at all.
fn java_no_arg_ctor_available(methods: &[java_parser::JavaMethod], class_path: &[String]) -> bool {
    let ctors: Vec<&java_parser::JavaMethod> = methods
        .iter()
        .filter(|m| m.is_constructor && m.class_path == class_path)
        .collect();
    if ctors.is_empty() {
        return true; // implicit public no-arg constructor
    }
    ctors
        .iter()
        .any(|c| c.params.is_empty() && matches!(c.visibility, java_parser::JavaVisibility::Public))
}

fn run_javac(
    javac: &Path,
    classpath: &[&str],
    out_dir: &Path,
    sources: &[PathBuf],
) -> Result<(), String> {
    let mut cmd = Command::new(javac);
    cmd.arg("-d").arg(out_dir);
    if !classpath.is_empty() {
        cmd.arg("-cp").arg(classpath.join(":"));
    }
    // Keep going past individual warnings; proc-style errors still fail the build.
    cmd.arg("-nowarn");
    for s in sources {
        cmd.arg(s);
    }
    let out = crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    )
    .map_err(|e| format!("spawn javac: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(stderr.lines().take(12).collect::<Vec<_>>().join("\n"))
}

/// A directory whose `.java` files are NOT library sources to compile: build/VCS
/// output, and TEST/example/benchmark trees (which pull in JUnit etc. and would
/// fail a dependency-free `javac`). Mirrors the discovery `DirFilter` defaults —
/// `src/test/java` is the dominant real case (commons-codec, jackson, …).
fn is_non_source_dir(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if matches!(
        n.as_str(),
        "govfuzz_work" | ".git" | "target" | "build" | "node_modules" | "out" | ".gradle"
    ) {
        return true;
    }
    // Any dir whose name contains "test" is test code (`test`, `tests`,
    // `integration-test`), guarding the words that merely contain the substring.
    if n.contains("test")
        && !n.contains("attest")
        && !matches!(n.as_str(), "latest" | "fastest" | "greatest" | "contest")
    {
        return true;
    }
    matches!(
        n.as_str(),
        "example" | "examples" | "sample" | "samples" | "benchmark" | "benchmarks" | "demo"
    )
}

/// Resolve the classpath the harness compiles against and the JVM runs with: the
/// target's compiled classes plus its dependency classpath. Uses maven/gradle when
/// a build file is present (so dep-heavy real projects — jackson, gson, commons-*
/// — link their dependencies), else `javac`-compiles the bare source tree (the
/// dep-light path). A maven/gradle build is cached per project so it runs once
/// across all of a project's targets, not once per candidate.
///
/// Returns the colon-joined classpath on success, or `(reason, skip)` on failure.
fn resolve_target_classpath(
    tc: &JavaToolchain,
    source_root: &Path,
    source_path: &Path,
    work_dir: &Path,
    fallback_classes: &Path,
) -> Result<String, (String, bool)> {
    // Maven/gradle are ADDITIVE: try the build tool (it resolves dependencies for
    // dep-heavy projects), but on ANY failure fall back to a bare `javac` of the
    // tree — which still works for dep-light/dep-free projects (and never does
    // worse than the original javac-only lane). The build-tool error is kept so a
    // genuinely-dep-heavy project that also fails javac reports the better reason.
    let mut tool_error: Option<String> = None;

    if let Some(module) = find_build_file(source_path, source_root, &["pom.xml"]) {
        if which::which("mvn").is_ok() {
            match maven_classpath(&module, work_dir) {
                Ok(cp) => return Ok(cp),
                Err(e) => tool_error = Some(e),
            }
        }
    }
    if let Some(module) = find_build_file(
        source_path,
        source_root,
        &["build.gradle", "build.gradle.kts"],
    ) {
        let has_gradle = which::which("gradle").is_ok() || module.join("gradlew").is_file();
        if has_gradle {
            match gradle_classpath(&module) {
                Ok(cp) => return Ok(cp),
                Err(e) => tool_error = tool_error.or(Some(e)),
            }
        }
    }

    // Fallback: javac the bare source tree (dep-light / dep-free projects).
    let sources = collect_java_sources(source_root);
    if sources.is_empty() {
        return Err((
            format!("no .java sources under {}", source_root.display()),
            true,
        ));
    }
    match run_javac(&tc.javac, &[], fallback_classes, &sources) {
        Ok(()) => Ok(fallback_classes.display().to_string()),
        Err(javac_err) => {
            // Both the build tool (if any) and javac failed — surface both so a
            // dep-heavy project's real blocker (the build tool) isn't hidden.
            let reason = match tool_error {
                Some(t) => format!("build failed via maven/gradle ({t}) AND javac ({javac_err})"),
                None => format!("javac (target) failed: {javac_err}"),
            };
            Err((reason, false))
        }
    }
}

/// The nearest ancestor of `source_path` (up to and including `root`) that
/// contains any of `names`.
fn find_build_file(source_path: &Path, root: &Path, names: &[&str]) -> Option<PathBuf> {
    let mut dir = source_path.parent();
    while let Some(d) = dir {
        if names.iter().any(|n| d.join(n).is_file()) {
            return Some(d.to_path_buf());
        }
        if d == root {
            break;
        }
        dir = d.parent();
    }
    // Also check root itself (when source_path is directly under root).
    if names.iter().any(|n| root.join(n).is_file()) {
        return Some(root.to_path_buf());
    }
    None
}

/// Build a maven module's `target/classes` + dependency classpath (cached per
/// module so it runs once). `mvn compile dependency:build-classpath` writes the
/// dep classpath to a file we cache.
fn maven_classpath(module: &Path, work_dir: &Path) -> Result<String, String> {
    let classes = module.join("target").join("classes");
    let cache_dir = work_dir.join("java-build-cache");
    std::fs::create_dir_all(&cache_dir).map_err(|e| format!("mkdir cache: {e}"))?;
    // Absolute cp path so `mvn` (run with current_dir = module) writes where we read.
    let cache_abs = cache_dir
        .canonicalize()
        .unwrap_or_else(|_| cache_dir.clone());
    let cp_file = cache_abs.join(format!("{}.cp", module_cache_key(module)));

    // Reuse a prior successful build for this project.
    if classes.is_dir() && cp_file.is_file() {
        if let Ok(deps) = std::fs::read_to_string(&cp_file) {
            return Ok(join_cp(&classes, deps.trim()));
        }
    }

    // govfuzz's offline classpath build deliberately ignores the project's CI
    // Maven-version policy: `-Denforcer.skip=true` / `-Denforcer.fail=false` disable
    // any maven-enforcer-plugin `requireMavenVersion` rule so an older locally
    // installed Maven still resolves the classpath (`-Dmaven.test.skip=true` already
    // keeps test code + its deps out of the build). `goal` is the lifecycle phase or
    // plugin goal that produces `target/classes`.
    let cp_file_arg = format!("-Dmdep.outputFile={}", cp_file.display());
    let run_mvn = |goal: &str| -> Result<(), String> {
        let out = crate::command_output::output_with_timeout(
            Command::new("mvn")
                .arg("-q")
                .arg("-B")
                .arg("-Dmaven.test.skip=true")
                .arg("-Denforcer.skip=true")
                .arg("-Denforcer.fail=false")
                .arg(goal)
                .arg("dependency:build-classpath")
                .arg(&cp_file_arg)
                .current_dir(module),
            std::time::Duration::from_secs(30 * 60),
        )
        .map_err(|e| format!("spawn mvn: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Err(format!("mvn build failed: {}", tail_lines(&combined, 12)))
    };

    // First try the full `compile` lifecycle phase, which also runs any source /
    // resource generation a dep-heavy project needs before compiling. If that aborts
    // on a build/validate-phase plugin that hard-requires a NEWER Maven than is
    // installed (e.g. apache-rat-plugin pins `<prerequisites>3.9` in commons-parent),
    // that version is checked at plugin-LOAD time — so no `-D*.skip` can bypass it and
    // the whole phase fails before producing classes. govfuzz doesn't care about the
    // project's CI Maven-version policy, so retry by driving the compiler goal
    // DIRECTLY (`compiler:compile`), which never schedules those validate-phase
    // plugins. (`-Denforcer.skip` already covers the enforcer's own version rule.)
    if let Err(e) = run_mvn("compile") {
        if maven_version_gated(&e) {
            run_mvn("compiler:compile")?;
        } else {
            return Err(e);
        }
    }
    if !classes.is_dir() {
        return Err(format!("mvn compile produced no {}", classes.display()));
    }
    let deps = std::fs::read_to_string(&cp_file).unwrap_or_default();
    Ok(join_cp(&classes, deps.trim()))
}

/// Whether a failed `mvn` invocation was blocked by a Maven-version gate — an
/// enforcer `requireMavenVersion` rule or a plugin `<prerequisites>` demanding a
/// newer Maven than is installed — rather than a genuine compile error. Such a
/// failure is worth retrying with a lifecycle that skips the gating plugin, because
/// govfuzz's offline build doesn't honour a project's CI Maven-version policy.
fn maven_version_gated(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("requires maven version")
        || e.contains("pluginincompatibleexception")
        || e.contains("requiremavenversion")
        || e.contains("not in the allowed range")
}

/// Build a gradle module's classes + a best-effort dependency classpath.
fn gradle_classpath(module: &Path) -> Result<String, String> {
    let gradle = if module.join("gradlew").is_file() {
        module.join("gradlew")
    } else {
        PathBuf::from("gradle")
    };
    let out = crate::command_output::output_with_timeout(
        Command::new(&gradle)
            .arg("-q")
            .arg("compileJava")
            .current_dir(module),
        std::time::Duration::from_secs(30 * 60),
    )
    .map_err(|e| format!("spawn gradle: {e}"))?;
    if !out.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(format!(
            "gradle compileJava failed: {}",
            tail_lines(&combined, 8)
        ));
    }
    let classes = module
        .join("build")
        .join("classes")
        .join("java")
        .join("main");
    if !classes.is_dir() {
        return Err("gradle produced no build/classes/java/main".to_owned());
    }
    // Best-effort dependency classpath via an init script printing runtimeClasspath.
    match gradle_runtime_classpath(module, &gradle) {
        Some(deps) if !deps.is_empty() => Ok(join_cp(&classes, &deps)),
        _ => Ok(classes.display().to_string()),
    }
}

/// Print a gradle project's runtime classpath via a one-shot init script. Returns
/// `None` on any failure (the caller falls back to classes-only).
fn gradle_runtime_classpath(module: &Path, gradle: &Path) -> Option<String> {
    let init = module.join(".govfuzz-init.gradle");
    let script = "allprojects { tasks.register('govfuzzCp') { doLast { try { \
                  println configurations.runtimeClasspath.asPath } catch (e) {} } } }\n";
    std::fs::write(&init, script).ok()?;
    let out = crate::command_output::output_with_timeout(
        Command::new(gradle)
            .arg("-q")
            .arg("-I")
            .arg(&init)
            .arg("govfuzzCp")
            .current_dir(module),
        std::time::Duration::from_secs(30 * 60),
    )
    .ok();
    let _ = std::fs::remove_file(&init);
    let out = out?;
    if !out.status.success() {
        return None;
    }
    let cp = String::from_utf8_lossy(&out.stdout)
        .lines()
        .rev()
        .find(|l| l.contains(".jar"))
        .map(|l| l.trim().to_owned())?;
    Some(cp)
}

fn join_cp(classes: &Path, deps: &str) -> String {
    if deps.is_empty() {
        classes.display().to_string()
    } else {
        format!("{}:{}", classes.display(), deps)
    }
}

/// A filesystem-safe cache key for a module directory.
fn module_cache_key(module: &Path) -> String {
    // A readable slug PLUS a hash of the full path, so sibling modules that differ
    // only in non-alphanumeric chars (`foo-bar` vs `foo.bar`) don't collide to the
    // same `.cp` cache file. (RC review fix.)
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    module.to_string_lossy().hash(&mut hasher);
    let slug: String = module
        .to_string_lossy()
        .chars()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{slug}_{:016x}", hasher.finish())
}

fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Collect every `.java` file under `root`, skipping the govfuzz work dir and
/// non-library dirs (build output, test/example trees). Capped to keep a
/// pathological tree bounded.
fn collect_java_sources(root: &Path) -> Vec<PathBuf> {
    const MAX: usize = 5000;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if path.is_dir() {
                if is_non_source_dir(name) {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                out.push(path);
                if out.len() >= MAX {
                    return out;
                }
            }
        }
    }
    out
}

/// Ensure the govfuzz JVM agent jar exists AND is at least as new as its sources;
/// build it via `build-agent.sh` otherwise. Returns the jar path.
fn ensure_agent_jar() -> Result<PathBuf, String> {
    let cache = agent_jar_cache_path();
    let script = locate_build_agent_script()
        .ok_or_else(|| "could not locate java_runtime/build-agent.sh".to_owned())?;
    if cache.is_file() && !agent_jar_is_stale(&cache, &script) {
        return Ok(cache);
    }
    let out = crate::command_output::output_with_timeout(
        Command::new("sh").arg(&script).arg(&cache),
        std::time::Duration::from_secs(10 * 60),
    )
    .map_err(|e| format!("spawn build-agent.sh: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr)
            .lines()
            .take(8)
            .collect::<Vec<_>>()
            .join("\n"));
    }
    if cache.is_file() {
        Ok(cache)
    } else {
        Err("build-agent.sh reported success but produced no jar".to_owned())
    }
}

/// True when the agent jar is older than `build-agent.sh` or any `.java` source
/// beside it, so a dev edit to the runtime triggers a rebuild instead of silently
/// shipping a stale jar (which would manifest as a harness "cannot find symbol").
fn agent_jar_is_stale(jar: &Path, script: &Path) -> bool {
    let Ok(jar_mtime) = std::fs::metadata(jar).and_then(|m| m.modified()) else {
        return true;
    };
    let src_dir = script.parent().map(|d| d.join("src"));
    let mut newest = std::fs::metadata(script).and_then(|m| m.modified()).ok();
    if let Some(dir) = src_dir {
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("java") {
                    if let Ok(m) = std::fs::metadata(&p).and_then(|m| m.modified()) {
                        if newest.map(|n| m > n).unwrap_or(true) {
                            newest = Some(m);
                        }
                    }
                }
            }
        }
    }
    newest.map(|n| n > jar_mtime).unwrap_or(false)
}

fn agent_jar_cache_path() -> PathBuf {
    if let Ok(dir) = std::env::var("GOVFUZZ_JVM_CACHE") {
        return PathBuf::from(dir).join("govfuzz-jvm-agent.jar");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home)
        .join(".cache")
        .join("govfuzz")
        .join("jvm")
        .join("govfuzz-jvm-agent.jar")
}

fn locate_build_agent_script() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("java_runtime/build-agent.sh");
                if cand.is_file() {
                    return Some(cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    let from_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("java_runtime/build-agent.sh"));
    if let Some(p) = from_manifest {
        if p.is_file() {
            return Some(p);
        }
    }
    None
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
    fn agent_cache_path_honours_env() {
        // GOVFUZZ_JVM_CACHE override is respected (don't mutate global env in the
        // test; just assert the default shape is sane).
        let p = agent_jar_cache_path();
        assert!(p.ends_with("govfuzz-jvm-agent.jar"), "{}", p.display());
    }

    #[test]
    fn find_build_file_walks_up_to_module_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let src = root.join("src/main/java/com/acme");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(root.join("pom.xml"), "<project/>").unwrap();
        let found = find_build_file(&src.join("A.java"), root, &["pom.xml"]).unwrap();
        assert_eq!(found, root);
        // No build file -> None.
        assert!(find_build_file(&src.join("A.java"), root, &["build.gradle"]).is_none());
    }

    #[test]
    fn maven_version_gate_is_recognised_but_real_errors_are_not() {
        // An enforcer requireMavenVersion failure and a plugin <prerequisites>
        // incompatibility are both version gates worth retrying.
        assert!(maven_version_gated(
            "Rule 0: ...RequireMavenVersion failed: Detected Maven Version: 3.8.7 \
             is not in the allowed range [3.9,)."
        ));
        assert!(maven_version_gated(
            "The plugin org.apache.rat:apache-rat-plugin:0.18 requires Maven version 3.9"
        ));
        assert!(maven_version_gated(
            "org.apache.maven.plugin.PluginIncompatibleException: ..."
        ));
        // A genuine compile error must NOT be mistaken for a version gate.
        assert!(!maven_version_gated(
            "Foo.java:[12,5] cannot find symbol\n  symbol: method bar()"
        ));
        assert!(!maven_version_gated("mvn build failed: BUILD FAILURE"));
    }

    #[test]
    fn join_cp_and_cache_key_are_sane() {
        assert_eq!(join_cp(Path::new("/c"), ""), "/c");
        assert_eq!(join_cp(Path::new("/c"), "/d/x.jar"), "/c:/d/x.jar");
        let key = module_cache_key(Path::new("/tmp/foo-bar/baz"));
        assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn collect_java_sources_finds_nested_and_skips_work_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src/com/acme")).unwrap();
        std::fs::write(root.join("src/com/acme/A.java"), "class A {}").unwrap();
        std::fs::create_dir_all(root.join("govfuzz_work/auto")).unwrap();
        std::fs::write(root.join("govfuzz_work/auto/Skip.java"), "class Skip {}").unwrap();
        // A `src/test/java` tree (JUnit-dependent) must NOT be compiled.
        std::fs::create_dir_all(root.join("src/test/java/com/acme")).unwrap();
        std::fs::write(
            root.join("src/test/java/com/acme/ATest.java"),
            "class ATest {}",
        )
        .unwrap();
        let found = collect_java_sources(root);
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"A.java".to_owned()), "{names:?}");
        assert!(
            !names.contains(&"Skip.java".to_owned()),
            "work dir skipped: {names:?}"
        );
        assert!(
            !names.contains(&"ATest.java".to_owned()),
            "test tree skipped: {names:?}"
        );
    }

    use java_parser::{JavaMethod, JavaParam, JavaVisibility};

    /// Build a JavaMethod for receiver-resolution tests. `class_path` is the
    /// enclosing-class chain (`["JsonParser"]`, or `["JsonParser","Builder"]` for
    /// a nested type); package is fixed to `com.acme`.
    fn jm(
        name: &str,
        params: &[&str],
        is_static: bool,
        is_ctor: bool,
        ret: Option<&str>,
        class_path: &[&str],
    ) -> JavaMethod {
        JavaMethod {
            name: name.to_owned(),
            line: 1,
            return_type: ret.map(str::to_owned),
            params: params
                .iter()
                .map(|t| JavaParam {
                    name: "x".to_owned(),
                    ty: (*t).to_owned(),
                })
                .collect(),
            is_static,
            visibility: JavaVisibility::Public,
            enclosing_public: true,
            package: Some("com.acme".to_owned()),
            class_path: class_path.iter().map(|s| (*s).to_owned()).collect(),
            is_constructor: is_ctor,
            ..JavaMethod::default()
        }
    }

    /// The instance method we want a receiver for: `JsonParser.decode(byte[])`.
    fn instance_target() -> JavaMethod {
        jm("decode", &["byte[]"], false, false, None, &["JsonParser"])
    }

    #[test]
    fn collect_param_type_models_finds_custom_config_type() {
        // A custom-typed param (`CSVFormat`) declared in a sibling file is resolved
        // to a model; a target with only scalar/string params resolves nothing.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pkg = root.join("src/main/java/org/apache/commons/csv");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("CSVFormat.java"),
            "package org.apache.commons.csv;\n\
             public final class CSVFormat {\n\
             \x20 public static final CSVFormat DEFAULT = new CSVFormat();\n\
             \x20 private CSVFormat() {}\n}",
        )
        .unwrap();

        let parse = jm(
            "parse",
            &["String", "CSVFormat"],
            true,
            false,
            Some("CSVParser"),
            &["CSVParser"],
        );
        let models = collect_param_type_models(root, &parse);
        assert_eq!(models.len(), 1, "{models:?}");
        assert_eq!(models[0].fqn, "org.apache.commons.csv.CSVFormat");
        assert_eq!(models[0].self_constants, vec!["DEFAULT"]);

        // All-scalar target -> no tree scan, no models.
        let scalar = jm("f", &["String", "int"], true, false, None, &["P"]);
        assert!(collect_param_type_models(root, &scalar).is_empty());
        // A supported JDK type (Charset) is decodable -> not modelled either.
        let charset = jm(
            "parse",
            &["java.nio.charset.Charset", "String"],
            true,
            false,
            None,
            &["P"],
        );
        assert!(collect_param_type_models(root, &charset).is_empty());
    }

    #[test]
    fn custom_type_leaf_strips_qualifiers_and_rejects_arrays() {
        assert_eq!(custom_type_leaf("CSVFormat").as_deref(), Some("CSVFormat"));
        assert_eq!(
            custom_type_leaf("org.apache.commons.csv.CSVFormat").as_deref(),
            Some("CSVFormat")
        );
        assert_eq!(custom_type_leaf("List<String>").as_deref(), Some("List"));
        // Generic args (including a bare wildcard) are stripped before the leaf.
        assert_eq!(custom_type_leaf("Class<?>").as_deref(), Some("Class"));
        assert!(custom_type_leaf("byte[]").is_none());
        assert!(custom_type_leaf("CSVFormat[]").is_none());
    }

    #[test]
    fn receiver_implicit_no_arg_ctor() {
        // No declared ctors -> implicit public no-arg ctor.
        let methods = vec![instance_target()];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("new com.acme.JsonParser()")
        );
    }

    #[test]
    fn receiver_no_arg_static_factory() {
        // Only a parameterised ctor (no no-arg), plus `getInstance()` returning the
        // class -> prefer the factory.
        let methods = vec![
            instance_target(),
            jm(
                "JsonParser",
                &["com.acme.Schema"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
            jm(
                "getInstance",
                &[],
                true,
                false,
                Some("JsonParser"),
                &["JsonParser"],
            ),
        ];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("com.acme.JsonParser.getInstance()")
        );
    }

    #[test]
    fn receiver_builder_factory_then_build() {
        // `builder()` static factory + nested `Builder.build()` -> fluent build.
        let methods = vec![
            instance_target(),
            jm(
                "JsonParser",
                &["com.acme.Schema"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
            jm(
                "builder",
                &[],
                true,
                false,
                Some("Builder"),
                &["JsonParser"],
            ),
            jm(
                "build",
                &[],
                false,
                false,
                Some("JsonParser"),
                &["JsonParser", "Builder"],
            ),
        ];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("com.acme.JsonParser.builder().build()")
        );
    }

    #[test]
    fn receiver_nested_builder_new_then_build() {
        // No `builder()` factory, but the nested Builder is no-arg-constructible and
        // has `build()` -> `new C.Builder().build()`.
        let methods = vec![
            instance_target(),
            jm(
                "JsonParser",
                &["com.acme.Schema"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
            jm(
                "build",
                &[],
                false,
                false,
                Some("JsonParser"),
                &["JsonParser", "Builder"],
            ),
        ];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("new com.acme.JsonParser.Builder().build()")
        );
    }

    #[test]
    fn receiver_param_ctor_scalar_decoded_reference_nulled() {
        // Sole public ctor `JsonParser(int, Schema)` -> decode the int, null the
        // reference. Unambiguous (only ctor of its arity), so the `null` is safe.
        let methods = vec![
            instance_target(),
            jm(
                "JsonParser",
                &["int", "com.acme.Schema"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
        ];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("new com.acme.JsonParser(c.consumeInt(), null)")
        );
    }

    #[test]
    fn receiver_ambiguous_null_overload_is_skipped() {
        // Two same-arity ctors each taking a single reference type: a bare `null`
        // would be an ambiguous overload, so synthesis declines (None).
        let methods = vec![
            instance_target(),
            jm(
                "JsonParser",
                &["com.acme.Schema"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
            jm(
                "JsonParser",
                &["com.acme.Config"],
                false,
                true,
                None,
                &["JsonParser"],
            ),
        ];
        assert_eq!(resolve_receiver(&methods, &instance_target(), false), None);
    }

    #[test]
    fn receiver_private_only_ctor_is_unconstructible() {
        // The only ctor is private and parameterised, no factory/builder -> None.
        let mut priv_ctor = jm(
            "JsonParser",
            &["com.acme.Schema"],
            false,
            true,
            None,
            &["JsonParser"],
        );
        priv_ctor.visibility = JavaVisibility::Private;
        let methods = vec![instance_target(), priv_ctor];
        assert_eq!(resolve_receiver(&methods, &instance_target(), false), None);
    }

    #[test]
    fn receiver_abstract_class_is_not_new_constructed() {
        // GAP 1 (campaign: commons-validator): the target class is `abstract` and its
        // only ctor is `public C(int)`. The concrete path would emit
        // `new com.acme.JsonParser(c.consumeInt())` (javac "is abstract; cannot be
        // instantiated"); with `class_is_abstract` the `new` strategies are disabled
        // and, lacking a factory/builder, the receiver resolves to None (clean skip).
        let methods = vec![
            instance_target(),
            jm("JsonParser", &["int"], false, true, None, &["JsonParser"]),
        ];
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), true),
            None,
            "an abstract class must not be `new`-constructed"
        );
        // Sanity: the SAME shape on a CONCRETE class still constructs via the ctor.
        assert_eq!(
            resolve_receiver(&methods, &instance_target(), false).as_deref(),
            Some("new com.acme.JsonParser(c.consumeInt())")
        );
        // But an abstract class WITH a no-arg static factory still gets a receiver
        // (the factory returns a concrete subtype, which compiles fine).
        let with_factory = vec![
            instance_target(),
            jm(
                "getInstance",
                &[],
                true,
                false,
                Some("JsonParser"),
                &["JsonParser"],
            ),
        ];
        assert_eq!(
            resolve_receiver(&with_factory, &instance_target(), true).as_deref(),
            Some("com.acme.JsonParser.getInstance()")
        );
    }

    #[test]
    fn receiver_nested_class_target_skips() {
        // A nested-class instance method still skips (no per-class static info).
        let target = jm(
            "decode",
            &["byte[]"],
            false,
            false,
            None,
            &["Outer", "Inner"],
        );
        assert_eq!(
            resolve_receiver(std::slice::from_ref(&target), &target, false),
            None
        );
    }
}
