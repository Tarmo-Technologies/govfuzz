// SPDX-License-Identifier: Apache-2.0

use corpus::FindingEmitter;
use event_log::{group_into_testcases, EventReader, Testcase};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn full_ci_fixture_pipelines_cover_active_matrix_cell() {
    if std::env::var_os("GOVFUZZ_M19_FULL_CI").is_none() {
        eprintln!("skipping: GOVFUZZ_M19_FULL_CI is not set");
        return;
    }
    assert!(
        which::which("gprbuild").is_ok(),
        "M19 full CI requires gprbuild on PATH"
    );

    let cell = MatrixCell::from_env();
    assert_eq!(cli::run_from(["govfuzz", "--profile", cell.profile()]), 0);

    run_swallowed_constraint_error_pipeline(&cell);
    run_access_param_pipeline(&cell);
    run_private_state_pipeline(&cell);
    run_missing_dependency_pipeline(&cell);
    run_fake_corba_servant_pipeline(&cell);
}

#[test]
fn ci_workflow_defines_gnat_dialect_profile_matrix() {
    let workflow = read_repo_file(".github/workflows/gnat-matrix.yml");
    let runner = read_repo_file("scripts/ci/run-gnat-fixture-matrix.sh");

    assert!(workflow.contains("name: GNAT Matrix"));
    assert!(workflow.contains("workflow_dispatch:"));
    assert!(workflow.contains("schedule:"));
    assert!(workflow.contains("ubuntu-24.04"));
    for version in ["11", "12", "13", "14"] {
        assert!(
            workflow.contains(version),
            "workflow matrix should include GNAT {version}"
        );
    }
    assert!(runner.contains("gnatmake-${GOVFUZZ_GNAT_VERSION}"));
    // The generated config is force-fed to every gprbuild in the cell, and the
    // Ada runtime project builds `adafuzz_cov.c` — so an Ada-only config has no
    // C DRIVER and every cell dies on `no compiler for language "C"`. That is
    // what this matrix did on every nightly run between 2026-07-23 and
    // 2026-07-28. Both halves are required: the config must ASK for C, and the
    // workflow must install a C compiler of the matching major for it to find.
    assert!(
        runner.contains("--config=C,,,,gcc-${GOVFUZZ_GNAT_VERSION}"),
        "the gprconfig config must include a C compiler:\n{runner}"
    );
    assert!(
        workflow.contains("gcc-${{ matrix.gnat }}"),
        "the workflow must install a version-matched C compiler:\n{workflow}"
    );
    for dialect in ["ada95", "ada2005", "ada2012", "ada2022"] {
        assert!(
            workflow.contains(dialect),
            "workflow matrix should include {dialect}"
        );
    }
    for profile in ["strict-permissive", "external-tools"] {
        assert!(
            workflow.contains(profile),
            "workflow matrix should include {profile}"
        );
    }
    for fixture in [
        "swallowed_constraint_error",
        "access_param",
        "private_state",
        "missing_dependency",
        "fake_corba_servant",
    ] {
        assert!(
            runner.contains(fixture),
            "runner should document the {fixture} fixture pipeline"
        );
    }
}

fn read_repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

struct MatrixCell {
    dialect: AdaDialect,
    profile: String,
}

impl MatrixCell {
    fn from_env() -> Self {
        let dialect = AdaDialect::parse(&required_env("GOVFUZZ_ADA_DIALECT"));
        let profile = required_env("GOVFUZZ_PROFILE");
        assert!(
            matches!(profile.as_str(), "strict-permissive" | "external-tools"),
            "unsupported GOVFUZZ_PROFILE={profile}"
        );

        Self { dialect, profile }
    }

    fn profile(&self) -> &str {
        &self.profile
    }
}

#[derive(Clone, Copy)]
enum AdaDialect {
    Ada95,
    Ada2005,
    Ada2012,
    Ada2022,
}

impl AdaDialect {
    fn parse(value: &str) -> Self {
        match value {
            "ada95" => Self::Ada95,
            "ada2005" => Self::Ada2005,
            "ada2012" => Self::Ada2012,
            "ada2022" => Self::Ada2022,
            other => panic!("unsupported GOVFUZZ_ADA_DIALECT={other}"),
        }
    }

    fn env_value(self) -> &'static str {
        match self {
            Self::Ada95 => "ada95",
            Self::Ada2005 => "ada2005",
            Self::Ada2012 => "ada2012",
            Self::Ada2022 => "ada2022",
        }
    }

    fn pragma(self) -> &'static str {
        match self {
            Self::Ada95 => "pragma Ada_95;",
            Self::Ada2005 => "pragma Ada_2005;",
            Self::Ada2012 => "pragma Ada_2012;",
            Self::Ada2022 => "pragma Ada_2022;",
        }
    }
}

fn run_swallowed_constraint_error_pipeline(cell: &MatrixCell) {
    let temp = temp_dir("swallowed-constraint-error", cell);
    let variant_dir = temp.join("variant");
    let fixture = repo_root().join("examples/swallowed_constraint_error");
    copy_rewritten_ada(
        &fixture.join("pkg.ads"),
        &variant_dir.join("pkg.ads"),
        cell.dialect,
    );
    copy_rewritten_ada(
        &fixture.join("pkg.adb"),
        &variant_dir.join("pkg.adb"),
        cell.dialect,
    );

    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("instrument"),
            variant_dir.join("pkg.adb").into_os_string(),
            OsString::from("--output"),
            instrumented_dir.as_os_str().to_owned(),
        ],
    );
    fs::copy(
        variant_dir.join("pkg.ads"),
        instrumented_dir.join("pkg.ads"),
    )
    .expect("fixture spec is copied");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("generate-harness"),
            instrumented_dir.join("pkg.adb").into_os_string(),
            OsString::from("--target"),
            OsString::from("Parse"),
            OsString::from("--output"),
            harness_root.as_os_str().to_owned(),
            OsString::from("--id"),
            OsString::from("H-M19-SWALLOWED"),
        ],
    );
    build_harness(cell.profile(), &work_dir, "H-M19-SWALLOWED");

    let input = swallowed_constraint_input();
    let exe = find_built_executable(&work_dir, "H-M19-SWALLOWED");
    let testcase = run_harness_once(&exe, &input, &temp.join("swallowed-events.bin"));
    let finding = emit_finding(
        &temp.join("swallowed-corpus"),
        &input,
        &testcase,
        "H-M19-SWALLOWED",
        cell.dialect.env_value(),
        "examples/swallowed_constraint_error/pkg.adb",
        0,
    );

    assert_eq!(finding["classification"], "swallowed_predefined");
    assert_eq!(finding["dialect"], cell.dialect.env_value());
}

fn run_access_param_pipeline(cell: &MatrixCell) {
    let temp = temp_dir("access-param", cell);
    let variant_dir = temp.join("variant");
    let fixture = repo_root().join("examples/access_param");
    copy_rewritten_ada(
        &fixture.join("access_param.ads"),
        &variant_dir.join("access_param.ads"),
        cell.dialect,
    );
    copy_rewritten_ada(
        &fixture.join("access_param.adb"),
        &variant_dir.join("access_param.adb"),
        cell.dialect,
    );

    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("instrument"),
            variant_dir.join("access_param.adb").into_os_string(),
            OsString::from("--output"),
            instrumented_dir.as_os_str().to_owned(),
        ],
    );
    fs::copy(
        variant_dir.join("access_param.ads"),
        instrumented_dir.join("access_param.ads"),
    )
    .expect("fixture spec is copied");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("generate-harness"),
            instrumented_dir.join("access_param.adb").into_os_string(),
            OsString::from("--target"),
            OsString::from("Process"),
            OsString::from("--output"),
            harness_root.as_os_str().to_owned(),
            OsString::from("--id"),
            OsString::from("H-M19-ACCESS"),
        ],
    );
    build_harness(cell.profile(), &work_dir, "H-M19-ACCESS");

    let exe = find_built_executable(&work_dir, "H-M19-ACCESS");
    let testcase = run_harness_once(&exe, &slot_index_input(0), &temp.join("access-events.bin"));
    assert_eq!(testcase.handlers.len(), 0);
}

fn run_private_state_pipeline(cell: &MatrixCell) {
    let temp = temp_dir("private-state", cell);
    let variant_dir = temp.join("variant");
    let fixture = repo_root().join("examples/private_state");
    copy_rewritten_ada(
        &fixture.join("state.ads"),
        &variant_dir.join("state.ads"),
        cell.dialect,
    );
    copy_rewritten_ada(
        &fixture.join("state.adb"),
        &variant_dir.join("state.adb"),
        cell.dialect,
    );

    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("instrument"),
            variant_dir.join("state.adb").into_os_string(),
            OsString::from("--output"),
            instrumented_dir.as_os_str().to_owned(),
        ],
    );
    fs::copy(
        variant_dir.join("state.ads"),
        instrumented_dir.join("state.ads"),
    )
    .expect("fixture spec is copied");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("generate-harness"),
            instrumented_dir.join("state.adb").into_os_string(),
            OsString::from("--target"),
            OsString::from("State"),
            OsString::from("--kind"),
            OsString::from("sequence"),
            OsString::from("--output"),
            harness_root.as_os_str().to_owned(),
            OsString::from("--id"),
            OsString::from("H-M19-PRIVATE"),
        ],
    );
    build_harness(cell.profile(), &work_dir, "H-M19-PRIVATE");

    let exe = find_built_executable(&work_dir, "H-M19-PRIVATE");
    let testcase = run_harness_once(
        &exe,
        &private_state_push_pop_pop_input(),
        &temp.join("private-events.bin"),
    );
    assert!(testcase.handlers.iter().any(|handler| {
        handler.exception_name.contains("CONSTRAINT_ERROR")
            && handler.handler_file.contains("state.adb")
    }));
}

fn run_missing_dependency_pipeline(cell: &MatrixCell) {
    let temp = temp_dir("missing-dependency", cell);
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-M19-MISSING");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");

    copy_rewritten_ada(
        &repo_root().join("examples/missing_dependency/src.adb"),
        &source_dir.join("demo.adb"),
        cell.dialect,
    );
    fs::write(
        harness_dir.join("main.adb"),
        format!(
            "--  SPDX-License-Identifier: Apache-2.0\n{}\nwith Demo;\nprocedure Main is\nbegin\n   Demo;\nend Main;\n",
            cell.dialect.pragma()
        ),
    )
    .expect("missing dependency harness is written");

    run_govfuzz(
        cell.profile(),
        [
            OsString::from("stub"),
            work_dir.as_os_str().to_owned(),
            OsString::from("--harness"),
            OsString::from("H-M19-MISSING"),
        ],
    );

    assert!(work_dir.join("generated_stubs/external_lib.ads").is_file());
    assert!(work_dir.join("generated_stubs/external_lib.adb").is_file());
    assert!(work_dir.join("generated_stubs/manifest.json").is_file());
}

fn run_fake_corba_servant_pipeline(cell: &MatrixCell) {
    let temp = temp_dir("fake-corba-servant", cell);
    let variant_dir = temp.join("variant");
    let fixture = repo_root().join("examples/fake_corba_servant");
    copy_rewritten_ada(
        &fixture.join("bar_impl.ads"),
        &variant_dir.join("bar_impl.ads"),
        cell.dialect,
    );
    copy_rewritten_ada(
        &fixture.join("bar_impl.adb"),
        &variant_dir.join("bar_impl.adb"),
        cell.dialect,
    );

    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("instrument"),
            variant_dir.join("bar_impl.adb").into_os_string(),
            OsString::from("--output"),
            instrumented_dir.as_os_str().to_owned(),
        ],
    );
    fs::copy(
        variant_dir.join("bar_impl.ads"),
        instrumented_dir.join("bar_impl.ads"),
    )
    .expect("fixture spec is copied");
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("fake-corba"),
            work_dir.as_os_str().to_owned(),
        ],
    );
    run_govfuzz(
        cell.profile(),
        [
            OsString::from("generate-harness"),
            instrumented_dir.join("bar_impl.adb").into_os_string(),
            OsString::from("--target"),
            OsString::from("Compute"),
            OsString::from("--kind"),
            OsString::from("servant_direct"),
            OsString::from("--output"),
            harness_root.as_os_str().to_owned(),
            OsString::from("--id"),
            OsString::from("H-M19-CORBA"),
        ],
    );
    build_harness(cell.profile(), &work_dir, "H-M19-CORBA");

    let input = fake_corba_bad_input_bytes();
    let exe = find_built_executable(&work_dir, "H-M19-CORBA");
    let testcase = run_harness_once(&exe, &input, &temp.join("fake-corba-events.bin"));
    let handler_idx = testcase
        .handlers
        .iter()
        .position(|handler| handler.exception_name.eq_ignore_ascii_case("Foo.BadInput"))
        .expect("Foo.BadInput handler is recorded");
    let finding = emit_finding(
        &temp.join("fake-corba-corpus"),
        &input,
        &testcase,
        "H-M19-CORBA",
        cell.dialect.env_value(),
        "examples/fake_corba_servant/bar_impl.adb",
        handler_idx,
    );

    assert_eq!(finding["classification"], "explicit_raise");
    assert_eq!(
        finding["handler"]["exception_name"]
            .as_str()
            .expect("handler exception is a string")
            .to_ascii_uppercase(),
        "FOO.BADINPUT"
    );
}

fn run_govfuzz<I>(profile: &str, args: I)
where
    I: IntoIterator<Item = OsString>,
{
    let mut argv = vec![
        OsString::from("govfuzz"),
        OsString::from("--profile"),
        OsString::from(profile),
    ];
    argv.extend(args);

    assert_eq!(cli::run_from(argv), 0);
}

fn build_harness(profile: &str, work_dir: &Path, harness_id: &str) {
    run_govfuzz(
        profile,
        [
            OsString::from("build"),
            work_dir.as_os_str().to_owned(),
            OsString::from("--harness"),
            OsString::from(harness_id),
        ],
    );
}

fn copy_rewritten_ada(source_path: &Path, dest_path: &Path, dialect: AdaDialect) {
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).expect("destination parent is created");
    }

    let mut source = fs::read_to_string(source_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
    let mut replaced = false;
    for pragma in [
        "pragma Ada_95;",
        "pragma Ada_2005;",
        "pragma Ada_2012;",
        "pragma Ada_2022;",
    ] {
        if source.contains(pragma) {
            source = source.replacen(pragma, dialect.pragma(), 1);
            replaced = true;
            break;
        }
    }
    if !replaced {
        source = format!("{}\n{source}", dialect.pragma());
    }
    if matches!(dialect, AdaDialect::Ada95) {
        source = source.replace("raise Foo.BadInput with \"neg\";", "raise Foo.BadInput;");
    }

    fs::write(dest_path, source)
        .unwrap_or_else(|error| panic!("write {}: {error}", dest_path.display()));
}

fn run_harness_once(exe: &Path, input: &[u8], events_path: &Path) -> Testcase {
    let mut child = Command::new(exe)
        .env("GOVFUZZ_EVENTS_PATH", events_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("start {}: {error}", exe.display()));
    {
        let mut stdin = child.stdin.take().expect("harness stdin is piped");
        stdin.write_all(input).expect("harness input is written");
    }

    let output = child.wait_with_output().expect("harness exits");
    assert!(
        output.status.success(),
        "harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_single_testcase(events_path)
}

fn read_single_testcase(events_path: &Path) -> Testcase {
    let events = fs::File::open(events_path).expect("events file exists");
    let testcases = group_into_testcases(EventReader::new(events)).expect("events parse");
    assert_eq!(testcases.len(), 1);
    testcases.into_iter().next().unwrap()
}

fn emit_finding(
    root: &Path,
    input: &[u8],
    testcase: &Testcase,
    harness_id: &str,
    dialect: &str,
    fixture_path: &str,
    handler_idx: usize,
) -> serde_json::Value {
    let emitter = FindingEmitter::with_metadata(
        root.to_path_buf(),
        harness_id.to_owned(),
        dialect.to_owned(),
        fixture_path.to_owned(),
    );
    let id = emitter
        .emit(input, testcase, handler_idx)
        .expect("finding is emitted");
    let finding_dir = root.join("findings").join(id.0);
    serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap()
}

fn find_built_executable(work_dir: &Path, harness_id: &str) -> PathBuf {
    let build_dir = work_dir.join("build").join(harness_id);
    let candidates = [
        build_dir.join("main"),
        build_dir.join("obj").join("main"),
        build_dir.join("obj").join("main.exe"),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("built executable not found under {}", build_dir.display()))
}

fn swallowed_constraint_input() -> Vec<u8> {
    let mut input = vec![1];
    input.extend_from_slice(&14_u32.to_le_bytes());
    input.extend_from_slice(b"not-an-integer");
    input
}

fn private_state_push_pop_pop_input() -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bounded_range(&mut bytes, 2);
    push_bounded_range(&mut bytes, 0);
    bytes.extend_from_slice(&7_i32.to_le_bytes());
    push_bounded_range(&mut bytes, 1);
    push_bounded_range(&mut bytes, 1);
    bytes
}

fn fake_corba_bad_input_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(b"neg");
    bytes
}

fn slot_index_input(raw: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bounded_range(&mut bytes, raw);
    bytes
}

fn push_bounded_range(bytes: &mut Vec<u8>, raw: u32) {
    bytes.push(1);
    bytes.extend_from_slice(&raw.to_le_bytes());
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn temp_dir(name: &str, cell: &MatrixCell) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "govfuzz-m19-{}-{}-{}-{nonce}",
        name,
        cell.dialect.env_value(),
        cell.profile().replace('-', "_")
    ));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}
