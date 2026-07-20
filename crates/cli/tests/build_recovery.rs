// SPDX-License-Identifier: Apache-2.0

//! Build-recovery harness: TOML-declared scenarios that delete pieces
//! from a vendored upstream codebase, run `govfuzz auto`, and assert
//! each removal surfaces in the right `run.json::needed_for_build`
//! bucket. See docs/superpowers/specs/2026-05-14-build-recovery-
//! harness-design.md for the design.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Directory under the repo root that holds fixtures and scenarios.
/// Cargo runs integration tests with CWD == crate root
/// (`crates/cli/`), so we walk two levels up to reach the workspace
/// root, then into tests/fixtures/build_recovery/.
fn harness_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/cli")
        .join("tests/fixtures/build_recovery")
}

#[derive(Debug, Deserialize)]
struct Scenario {
    fixture: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    must_build_after_repair: bool,
    #[serde(default)]
    missing: Vec<Missing>,
    /// Optional exact target-name filters passed through to
    /// `govfuzz auto --target`. This keeps real-code fixtures from
    /// attempting every vendored support function when the scenario
    /// is specifically about the wrapper target.
    #[serde(default)]
    targets: Vec<String>,
    /// Optional top-level [scenario] table for assertions that don't
    /// fit the per-`[[missing]]` shape (e.g. discovery-only scenarios
    /// that assert auto found N candidates without removing anything).
    #[serde(default)]
    scenario: ScenarioConfig,
}

#[derive(Debug, Default, Deserialize)]
struct ScenarioConfig {
    /// If set, scenario asserts `run.json.summary.discovered >= N`.
    /// Default 0 means no assertion — existing scenarios remain
    /// unaffected.
    #[serde(default)]
    min_discovered: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Missing {
    File {
        path: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    Directory {
        path: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    EnvVar {
        name: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    SystemLib {
        name: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    GprImport {
        path: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    RuntimeFile {
        path: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    RuntimeEndpoint {
        address: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    RuntimeDlopen {
        path: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    /// Declarative kind: the fixture's harness references an unknown
    /// C type whose typedef nobody ships. Auto's repair planner emits
    /// a `Repair::TypePlaceholder` which lands in
    /// `needed_for_build.synthesized_types`. No tempdir action — the
    /// gap is baked into the fixture's source.
    UnknownType {
        name: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
    /// Declarative kind: source calls a symbol whose declaration disappeared
    /// with another removed artifact. No linker flag or tempdir action is needed.
    UnknownSymbol {
        name: String,
        expect_surfaced: Option<String>,
        #[serde(default)]
        locator_override: Option<String>,
    },
}

fn discover_scenarios() -> Vec<PathBuf> {
    let scenarios_dir = harness_root().join("scenarios");
    if !scenarios_dir.is_dir() {
        return Vec::new();
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(&scenarios_dir)
        .expect("read scenarios dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    out.sort();
    out
}

fn parse_scenario(path: &Path) -> Result<Scenario, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str::<Scenario>(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[test]
fn scenario_toml_round_trips() {
    let mut failures: Vec<String> = Vec::new();
    for path in discover_scenarios() {
        match parse_scenario(&path) {
            Ok(scenario) => {
                let fixture_dir = harness_root().join("fixtures").join(&scenario.fixture);
                if !fixture_dir.is_dir() {
                    failures.push(format!(
                        "{}: fixture '{}' not found at {}",
                        path.display(),
                        scenario.fixture,
                        fixture_dir.display()
                    ));
                }
            }
            Err(e) => failures.push(e),
        }
    }
    assert!(
        failures.is_empty(),
        "scenario TOML round-trip failed:\n{}",
        failures.join("\n")
    );
}

/// Field names of the `NeededForBuild` struct in
/// `crates/cli/src/auto/report.rs`. Kept in sync by hand; the
/// `bucket_names_match_run_json_schema` self-test enforces that
/// every `expect_surfaced` in every scenario references one of these.
const KNOWN_BUCKETS: &[&str] = &[
    "synthesized_headers",
    "synthesized_types",
    "synthesized_macros",
    "stubbed_symbols_declared",
    "stubbed_symbols_blind",
    "stubbed_ada_units",
    "stubbed_ada_symbols",
    "missing_libraries",
    "missing_gpr_imports",
    "environment_variables_faked",
    "missing_files",
    "network_endpoints",
    "dlopen_failures",
    "missing_ada_units",
];

#[test]
fn bucket_names_match_run_json_schema() {
    let mut failures: Vec<String> = Vec::new();
    for path in discover_scenarios() {
        let Ok(scenario) = parse_scenario(&path) else {
            continue; // covered by scenario_toml_round_trips
        };
        for entry in &scenario.missing {
            let expected = expect_surfaced_of(entry);
            if let Some(bucket) = expected {
                if !KNOWN_BUCKETS.contains(&bucket.as_str()) {
                    failures.push(format!(
                        "{}: expect_surfaced = {:?} is not a NeededForBuild field name",
                        path.display(),
                        bucket
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "scenarios reference unknown buckets:\n{}",
        failures.join("\n")
    );
}

fn expect_surfaced_of(entry: &Missing) -> Option<&String> {
    match entry {
        Missing::File {
            expect_surfaced, ..
        }
        | Missing::Directory {
            expect_surfaced, ..
        }
        | Missing::EnvVar {
            expect_surfaced, ..
        }
        | Missing::SystemLib {
            expect_surfaced, ..
        }
        | Missing::GprImport {
            expect_surfaced, ..
        }
        | Missing::RuntimeFile {
            expect_surfaced, ..
        }
        | Missing::RuntimeEndpoint {
            expect_surfaced, ..
        }
        | Missing::RuntimeDlopen {
            expect_surfaced, ..
        }
        | Missing::UnknownType {
            expect_surfaced, ..
        }
        | Missing::UnknownSymbol {
            expect_surfaced, ..
        } => expect_surfaced.as_ref(),
    }
}

fn locator_of(entry: &Missing) -> &str {
    if let Some(override_) = locator_override_of(entry) {
        return override_;
    }
    match entry {
        Missing::File { path, .. }
        | Missing::Directory { path, .. }
        | Missing::GprImport { path, .. }
        | Missing::RuntimeFile { path, .. }
        | Missing::RuntimeDlopen { path, .. } => path,
        Missing::EnvVar { name, .. }
        | Missing::SystemLib { name, .. }
        | Missing::UnknownType { name, .. }
        | Missing::UnknownSymbol { name, .. } => name,
        Missing::RuntimeEndpoint { address, .. } => address,
    }
}

fn locator_override_of(entry: &Missing) -> Option<&str> {
    let override_ = match entry {
        Missing::File {
            locator_override, ..
        }
        | Missing::Directory {
            locator_override, ..
        }
        | Missing::EnvVar {
            locator_override, ..
        }
        | Missing::SystemLib {
            locator_override, ..
        }
        | Missing::GprImport {
            locator_override, ..
        }
        | Missing::RuntimeFile {
            locator_override, ..
        }
        | Missing::RuntimeEndpoint {
            locator_override, ..
        }
        | Missing::RuntimeDlopen {
            locator_override, ..
        }
        | Missing::UnknownType {
            locator_override, ..
        }
        | Missing::UnknownSymbol {
            locator_override, ..
        } => locator_override,
    };
    override_.as_deref()
}

/// Skip the whole #[test] when the host toolchain doesn't have what
/// the scenarios need. Govfuzz auto itself decides whether each
/// scenario applies; here we just gate the test runner.
fn skip_if_no_toolchain() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping build_recovery: clang not on PATH");
        return true;
    }
    if which::which("gnatmake").is_err() {
        eprintln!(
            "skipping build_recovery: gnatmake not on PATH \
             (only Ada scenarios will be skipped)"
        );
        // We don't return true here — C scenarios should still run.
        // Per-scenario skipping happens in run_one when an Ada
        // fixture is named.
    }
    false
}

fn skip_scenario_for_toolchain(scenario: &Scenario) -> Option<&'static str> {
    // Every `ada_*` fixture (ada_basic, ada_basic_gpr, …) drives gnatmake /
    // gprbuild to produce the build diagnostics each scenario asserts on, so
    // gate them all — not just the bare `ada_basic` name — when the Ada
    // toolchain is absent (e.g. the default CI runner, which ships clang/gcc
    // but no GNAT; the GNAT Matrix workflow covers these instead).
    if scenario.fixture.starts_with("ada_") && which::which("gnatmake").is_err() {
        return Some("gnatmake not on PATH");
    }
    None
}

#[test]
fn build_recovery_scenarios() {
    if skip_if_no_toolchain() {
        return;
    }
    let scenarios = discover_scenarios();
    assert!(
        !scenarios.is_empty(),
        "no scenarios discovered under {}",
        harness_root().join("scenarios").display()
    );
    let mut failures: Vec<String> = Vec::new();
    for path in &scenarios {
        let scenario = match parse_scenario(path) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if let Some(reason) = skip_scenario_for_toolchain(&scenario) {
            eprintln!("{}: skipped ({reason})", path.display());
            continue;
        }
        if let Err(e) = run_one(path) {
            failures.push(format!("{}: {e}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "build-recovery scenarios failed ({} of {}):\n{}",
        failures.len(),
        scenarios.len(),
        failures.join("\n\n")
    );
}

fn run_one(scenario_path: &Path) -> Result<(), String> {
    let scenario = parse_scenario(scenario_path)?;
    let fixture_dir = harness_root().join("fixtures").join(&scenario.fixture);
    if !fixture_dir.is_dir() {
        return Err(format!(
            "fixture '{}' not found at {}",
            scenario.fixture,
            fixture_dir.display()
        ));
    }

    let work = tempfile::Builder::new()
        .prefix("govfuzz-build-recovery-")
        .tempdir()
        .map_err(|e| format!("create tempdir: {e}"))?;
    let project_dir = work.path().join("project");
    copy_dir_recursive(&fixture_dir, &project_dir).map_err(|e| format!("copy fixture: {e}"))?;

    // Apply operational [[missing]] entries.
    let mut env_strip: Vec<String> = Vec::new();
    let mut extra_ldflags: Vec<String> = Vec::new();
    for entry in &scenario.missing {
        match entry {
            Missing::File { path, .. } => {
                let target = project_dir.join(path);
                if !target.exists() {
                    return Err(format!(
                        "authoring error: file kind targets {} which does not exist in fixture",
                        path
                    ));
                }
                std::fs::remove_file(&target)
                    .map_err(|e| format!("rm {}: {e}", target.display()))?;
            }
            Missing::Directory { path, .. } => {
                let target = project_dir.join(path);
                if !target.exists() {
                    return Err(format!(
                        "authoring error: directory kind targets {} which does not exist in fixture",
                        path
                    ));
                }
                std::fs::remove_dir_all(&target)
                    .map_err(|e| format!("rm -r {}: {e}", target.display()))?;
            }
            Missing::EnvVar { name, .. } => env_strip.push(name.clone()),
            Missing::SystemLib { name, .. } => extra_ldflags.push(format!("-l{name}")),
            Missing::GprImport { .. }
            | Missing::RuntimeFile { .. }
            | Missing::RuntimeEndpoint { .. }
            | Missing::RuntimeDlopen { .. }
            | Missing::UnknownType { .. }
            | Missing::UnknownSymbol { .. } => {
                // declarative kinds — no tempdir action
            }
        }
    }

    let auto_output =
        invoke_govfuzz_auto(&project_dir, &env_strip, &extra_ldflags, &scenario.targets)?;

    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json_bytes = match std::fs::read(&run_json_path) {
        Ok(b) => b,
        Err(e) => {
            return Err(format!(
                "read {}: {e}; govfuzz auto exit={:?} stderr=\n{}",
                run_json_path.display(),
                auto_output.status.code(),
                String::from_utf8_lossy(&auto_output.stderr),
            ));
        }
    };
    let run_json: serde_json::Value =
        serde_json::from_slice(&run_json_bytes).map_err(|e| format!("parse run.json: {e}"))?;

    for entry in &scenario.missing {
        check_expectation(entry, &run_json)?;
    }
    if scenario.must_build_after_repair {
        let built = run_json["summary"]["built"].as_u64().unwrap_or(0);
        if built == 0 {
            return Err("must_build_after_repair = true but summary.built == 0".into());
        }
    }
    if scenario.scenario.min_discovered > 0 {
        let discovered = run_json["summary"]["discovered"].as_u64().unwrap_or(0);
        if discovered < scenario.scenario.min_discovered {
            return Err(format!(
                "min_discovered = {} but summary.discovered = {discovered}",
                scenario.scenario.min_discovered
            ));
        }
    }
    let _ = scenario.description; // silence unused-field warning
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if kind.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if kind.is_file() {
            std::fs::copy(&from, &to)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "unsupported file type for {}: only regular files and \
                     directories are accepted in fixtures",
                    from.display()
                ),
            ));
        }
    }
    Ok(())
}

fn invoke_govfuzz_auto(
    project_dir: &Path,
    env_strip: &[String],
    extra_ldflags: &[String],
    targets: &[String],
) -> Result<std::process::Output, String> {
    let work_dir = project_dir.join("govfuzz_work");
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.args(["run", "--quiet", "--release", "-p", "govfuzz", "--", "auto"])
        .arg(project_dir)
        .arg("--work-dir")
        .arg(&work_dir)
        // 3-second per-target TOTAL fuzz budget (--per-target-time), split
        // evenly across the ~3 passes (empty/rng/fuzz_driven) under one shared
        // deadline, so each target costs ~3s of fuzz wall-clock — enough for the
        // runtrace shim to record the locators each scenario asserts against,
        // without ballooning the suite beyond a few minutes for a dozen scenarios.
        .arg("--per-target-time")
        .arg("3");
    for target in targets {
        cmd.arg("--target").arg(target);
    }
    for name in env_strip {
        cmd.env_remove(name);
    }
    if !extra_ldflags.is_empty() {
        cmd.env("AUTO_EXTRA_LDFLAGS", extra_ldflags.join(" "));
    }
    // Auto returns 1 when some targets failed but the run.json still
    // exists, so we don't gate on exit status here. Capturing output
    // lets run_one surface stderr if run.json ends up missing (e.g.
    // because govfuzz itself failed to compile).
    cmd.output().map_err(|e| format!("spawn cargo run: {e}"))
}

fn check_expectation(entry: &Missing, run_json: &serde_json::Value) -> Result<(), String> {
    let locator = locator_of(entry);
    let expected = expect_surfaced_of(entry);
    let needed = &run_json["needed_for_build"];
    let all_buckets_with_locator: Vec<&'static str> = KNOWN_BUCKETS
        .iter()
        .copied()
        .filter(|bucket| bucket_contains(needed, bucket, locator))
        .collect();
    match expected {
        Some(bucket) => {
            if all_buckets_with_locator.contains(&bucket.as_str()) {
                Ok(())
            } else {
                Err(format!(
                    "locator {locator:?} expected in needed_for_build.{bucket}; \
                     not found there (found in: {all_buckets_with_locator:?})"
                ))
            }
        }
        None => {
            if all_buckets_with_locator.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "locator {locator:?} marked expect_surfaced=null but auto \
                     now surfaces it in {all_buckets_with_locator:?} — \
                     bump the scenario's expect_surfaced to the matching bucket"
                ))
            }
        }
    }
}

fn bucket_contains(needed: &serde_json::Value, bucket: &str, locator: &str) -> bool {
    let Some(arr) = needed.get(bucket).and_then(|v| v.as_array()) else {
        return false;
    };
    arr.iter().any(|entry| {
        entry
            .get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|name| name_matches_locator(name, locator))
    })
}

/// Match a reported `needed_for_build` entry name against a scenario
/// locator. Exact match, or — for forwarded gpr imports, which #411
/// absolutized against the source gpr's dir (e.g. a scenario locator
/// `missing.gpr` is now reported as `/tmp/.../project/missing.gpr`) —
/// the reported name ends with `/{locator}`. The suffix is anchored on
/// a path separator so `missing.gpr` cannot match `not-missing.gpr`.
fn name_matches_locator(name: &str, locator: &str) -> bool {
    name == locator || name.ends_with(&format!("{}{}", std::path::MAIN_SEPARATOR, locator))
}

#[test]
fn smoke_extract_fixture_compiles() {
    if skip_if_no_toolchain() {
        return;
    }
    let fixture = harness_root().join("fixtures/miniz");
    let work = tempfile::Builder::new()
        .prefix("govfuzz-build-recovery-smoke-")
        .tempdir()
        .expect("create tempdir for smoke_extract_fixture_compiles");
    let project_dir = work.path().join("project");
    copy_dir_recursive(&fixture, &project_dir).unwrap_or_else(|e| {
        panic!(
            "copy fixture {} -> {}: {e}",
            fixture.display(),
            project_dir.display()
        )
    });

    let out = std::process::Command::new("clang")
        .args(["-O0", "-Wno-error", "-c"])
        .arg(project_dir.join("harness.c"))
        .arg(project_dir.join("miniz.c"))
        .current_dir(&project_dir)
        .output()
        .expect("clang invocation");
    assert!(
        out.status.success(),
        "smoke build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn smoke_no_removals_does_not_fail_build() {
    if skip_if_no_toolchain() {
        return;
    }
    let fixture = harness_root().join("fixtures/miniz");
    let work = tempfile::Builder::new()
        .prefix("govfuzz-build-recovery-no-removals-")
        .tempdir()
        .expect("create tempdir for smoke_no_removals_does_not_fail_build");
    let project_dir = work.path().join("project");
    copy_dir_recursive(&fixture, &project_dir).unwrap_or_else(|e| {
        panic!(
            "copy fixture {} -> {}: {e}",
            fixture.display(),
            project_dir.display()
        )
    });

    invoke_govfuzz_auto(&project_dir, &[], &[], &["miniz_inflate_fuzz".to_owned()])
        .expect("invoke govfuzz auto in smoke test");

    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json_bytes = std::fs::read(&run_json_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", run_json_path.display()));
    let run_json: serde_json::Value = serde_json::from_slice(&run_json_bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", run_json_path.display()));
    let summary = &run_json["summary"];
    let discovered = summary["discovered"].as_u64().unwrap_or(0);
    assert!(
        discovered > 0,
        "summary.discovered = 0; auto found no candidates in the fixture: {}",
        serde_json::to_string_pretty(summary).expect("serialize summary for failure message")
    );

    // Baseline-clean signal: with no removals, auto must not synthesise any
    // placeholder headers — otherwise the miniz_delete_internal_header
    // scenario's positive surface signal is contaminated.
    //
    // This smoke check is about the build-recovery surface itself: an
    // unmodified fixture should not populate needed_for_build before any
    // scenario deletes or withholds inputs.
    let synth_headers = run_json["needed_for_build"]["synthesized_headers"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(
        synth_headers,
        0,
        "unmodified fixture surfaced synthesized_headers entries — \
         scenario surface is contaminated: {}",
        serde_json::to_string_pretty(&run_json["needed_for_build"]["synthesized_headers"])
            .expect("serialize synthesized_headers for failure message")
    );
}

/// Regression: a C++ harness that sees a bare C++ standard-library type
/// (`streamoff`, declared in the included header) must build. The repair
/// planner recognises the stdlib spelling and injects `#include <ios>`
/// (force-included into the compile), rather than aliasing it to `void*`
/// — which would link but corrupt value semantics — or leaving the build
/// failing because `auto_types.h` was never seen by `main`.
#[test]
fn cpp_stdlib_type_resolves_via_real_include() {
    if skip_if_no_toolchain() {
        return;
    }
    let work = tempfile::Builder::new()
        .prefix("govfuzz-cpp-stdlib-")
        .tempdir()
        .expect("create tempdir for cpp_stdlib_type_resolves_via_real_include");
    let project_dir = work.path().join("lib");
    std::fs::create_dir_all(&project_dir).expect("create fixture dir");
    // `process(int)` is harnessable; the sibling `streamoff current_offset()`
    // forces a bare-stdlib MissingType the harness `main` compile must satisfy.
    std::fs::write(
        project_dir.join("proc.hpp"),
        "streamoff current_offset();\nint process(int n);\n",
    )
    .expect("write proc.hpp");
    std::fs::write(
        project_dir.join("proc.cpp"),
        "#include <ios>\n\
         using std::streamoff;\n\
         #include \"proc.hpp\"\n\
         streamoff current_offset() { return 42; }\n\
         int process(int n) { return n * 3 + static_cast<int>(current_offset()); }\n",
    )
    .expect("write proc.cpp");

    let out = invoke_govfuzz_auto(&project_dir, &[], &[], &[]).expect("invoke govfuzz auto");
    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&run_json_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}\nstdout:\n{}\nstderr:\n{}",
                run_json_path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }))
        .unwrap_or_else(|e| panic!("parse {}: {e}", run_json_path.display()));

    let summary = &run_json["summary"];
    assert_eq!(
        summary["failed_build"].as_u64(),
        Some(0),
        "C++ stdlib type left a failed build (force-include / header mapping regressed):\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
    assert!(
        summary["built"].as_u64().unwrap_or(0) >= 1,
        "expected the streamoff C++ target to build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
}

/// Regression: a target source that references an ALL-CAPS build-config macro
/// the build system would have injected (generated `config.h` / `-D`) must
/// build — the classifier flags `use of undeclared identifier 'FOO'`, the
/// repair `#define`s it to a benign value (force-included), and the macro is
/// surfaced in `needed_for_build.synthesized_macros` so the maintainer knows
/// to supply a real value.
#[test]
fn missing_build_config_macro_is_defined_and_surfaced() {
    if skip_if_no_toolchain() {
        return;
    }
    let work = tempfile::Builder::new()
        .prefix("govfuzz-macro-")
        .tempdir()
        .expect("create tempdir for missing_build_config_macro");
    let project_dir = work.path().join("lib");
    std::fs::create_dir_all(&project_dir).expect("create fixture dir");
    std::fs::write(
        project_dir.join("ver.c"),
        // BUILD_TAG / BUILD_LEVEL are undefined (normally -D injected).
        "const char *banner(void) { return BUILD_TAG; }\n\
         int compute(int n) { return n + BUILD_LEVEL; }\n",
    )
    .expect("write ver.c");

    let out = invoke_govfuzz_auto(&project_dir, &[], &[], &[]).expect("invoke govfuzz auto");
    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&run_json_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}\nstdout:\n{}\nstderr:\n{}",
                run_json_path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }))
        .unwrap_or_else(|e| panic!("parse {}: {e}", run_json_path.display()));

    let summary = &run_json["summary"];
    assert_eq!(
        summary["failed_build"].as_u64(),
        Some(0),
        "undefined build-config macro left a failed build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
    assert!(
        summary["built"].as_u64().unwrap_or(0) >= 1,
        "expected the macro-referencing target to build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
    // The faked macros must be surfaced so the maintainer supplies real values.
    let macros = run_json["needed_for_build"]["synthesized_macros"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["name"].as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        macros.contains(&"BUILD_TAG") || macros.contains(&"BUILD_LEVEL"),
        "synthesized_macros should list the faked macro(s): {macros:?}"
    );
}

/// Regression: a `static` target lives in a `.c` the harness must `#include`
/// to reach it. That source already `#include`s its own headers, so the
/// harness must NOT separately re-include them — doing so double-includes any
/// header without an include guard (jansson's `lookup3.h` ->
/// "redefinition of 'hashlittle'"). The header set is still used for type
/// resolution; only the harness `#include` list collapses to the source.
#[test]
fn static_target_does_not_double_include_guardless_header() {
    if skip_if_no_toolchain() {
        return;
    }
    let work = tempfile::Builder::new()
        .prefix("govfuzz-guardless-")
        .tempdir()
        .expect("create tempdir for static_target_does_not_double_include_guardless_header");
    let project_dir = work.path().join("lib");
    std::fs::create_dir_all(&project_dir).expect("create fixture dir");
    // No include guard, defines a function: including it twice in one TU is a
    // hard "redefinition" error.
    std::fs::write(
        project_dir.join("gl.h"),
        "static int gl_helper(int x) { return x + 1; }\n",
    )
    .expect("write gl.h");
    // `secret` is static, so the harness reaches it by `#include`ing mod.c —
    // which already pulls in gl.h. A re-include of gl.h would redefine
    // gl_helper.
    std::fs::write(
        project_dir.join("mod.c"),
        "#include \"gl.h\"\n\
         static int secret(int n) { return gl_helper(n) * 2; }\n",
    )
    .expect("write mod.c");

    let out = invoke_govfuzz_auto(&project_dir, &[], &[], &[]).expect("invoke govfuzz auto");
    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&run_json_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}\nstdout:\n{}\nstderr:\n{}",
                run_json_path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }))
        .unwrap_or_else(|e| panic!("parse {}: {e}", run_json_path.display()));

    let summary = &run_json["summary"];
    assert_eq!(
        summary["failed_build"].as_u64(),
        Some(0),
        "guard-less header was double-included for the static target:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
    assert!(
        summary["built"].as_u64().unwrap_or(0) >= 1,
        "expected the static target to build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
}

/// Regression: a non-static function whose parameter is a struct defined only
/// in the `.c` (never exported in a header — tinyexpr's lexer `state`) must be
/// skipped, not emit a harness that names a type it cannot see. The harness
/// `#include`s only headers, so resolving the param against the `.c`-local
/// struct produced `state _gf_value_s;` → "missing_type: state". A clean
/// `process(int)` sibling proves the rest of the tree still harnesses.
#[test]
fn non_static_target_with_source_only_struct_param_is_skipped_not_failed() {
    if skip_if_no_toolchain() {
        return;
    }
    let work = tempfile::Builder::new()
        .prefix("govfuzz-source-only-type-")
        .tempdir()
        .expect("create tempdir for non_static_target_with_source_only_struct_param");
    let project_dir = work.path().join("lib");
    std::fs::create_dir_all(&project_dir).expect("create fixture dir");
    std::fs::write(project_dir.join("lib.h"), "int process(int n);\n").expect("write lib.h");
    // `struct lexer_state` exists only here; `scan` is non-static so the harness
    // links it but compiles against lib.h, which never declares the struct.
    std::fs::write(
        project_dir.join("lib.c"),
        "#include \"lib.h\"\n\
         struct lexer_state { const char *cur; int depth; };\n\
         void scan(struct lexer_state *s) { if (s) s->depth++; }\n\
         int process(int n) { return n * 2; }\n",
    )
    .expect("write lib.c");

    let out = invoke_govfuzz_auto(&project_dir, &[], &[], &[]).expect("invoke govfuzz auto");
    let run_json_path = project_dir.join("govfuzz_work/auto/run.json");
    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&run_json_path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}\nstdout:\n{}\nstderr:\n{}",
                run_json_path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }))
        .unwrap_or_else(|e| panic!("parse {}: {e}", run_json_path.display()));

    let summary = &run_json["summary"];
    assert_eq!(
        summary["failed_build"].as_u64(),
        Some(0),
        "source-only struct param should skip, not fail the build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
    assert!(
        summary["built"].as_u64().unwrap_or(0) >= 1,
        "expected the clean `process(int)` sibling to build:\n{}",
        serde_json::to_string_pretty(summary).expect("serialize summary")
    );
}
