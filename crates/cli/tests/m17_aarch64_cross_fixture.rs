// SPDX-License-Identifier: Apache-2.0

use corpus::FindingEmitter;
use event_log::{group_into_testcases, EventReader, Testcase};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const HARNESS_ID: &str = "H-M17-AARCH64";
const FIXTURE_PATH: &str = "examples/swallowed_constraint_error/pkg.adb";

#[test]
fn swallowed_constraint_error_fixture_is_present_and_parses() {
    let spec_path = fixture_root().join("pkg.ads");
    let body_path = fixture_root().join("pkg.adb");
    let spec = fs::read_to_string(&spec_path).expect("fixture spec is readable");
    let body = fs::read_to_string(&body_path).expect("fixture body is readable");
    let spec_ast = ada_parser::reconcile::build_structural_ast(&spec, None, &spec_path)
        .expect("fixture spec parses");
    let body_ast = ada_parser::reconcile::build_structural_ast(&body, None, &body_path)
        .expect("fixture body parses");

    assert!(fixture_root().join("manifest.toml").is_file());
    assert!(fixture_root().join("README.md").is_file());
    assert!(spec_ast
        .packages
        .iter()
        .any(|package| package.name.eq_ignore_ascii_case("Pkg")));
    assert!(body_ast
        .subprograms
        .iter()
        .any(|subprogram| subprogram.name.eq_ignore_ascii_case("Parse")));
}

#[test]
fn swallowed_constraint_error_direct_harness_generates_without_gnat() {
    let temp = temp_dir("m17-swallowed-generate");
    let (work_dir, main_adb) = generate_swallowed_constraint_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/pkg.ads").is_file());
    assert!(work_dir.join("src_instrumented/pkg.adb").is_file());
    assert!(main_text.contains("Pkg.Parse"));
    assert!(main_text.contains("AdaFuzz.Decode.Ada_String"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated direct harness parses");
}

#[test]
fn swallowed_constraint_error_host_run_emits_expected_finding_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m17-swallowed-host-run");
    let (work_dir, _main_adb) = generate_swallowed_constraint_harness(&temp);
    build_harness(&work_dir, &[]);

    let input = swallowed_constraint_input();
    let exe = find_built_executable(&work_dir, HARNESS_ID);
    let testcase = run_harness_direct(&exe, &input, &temp.join("host-events.bin"));
    let (_finding_dir, finding) = emit_finding(&temp.join("host-corpus"), &input, &testcase);

    let signature = finding["signature"]
        .as_str()
        .expect("finding has a signature");
    assert_eq!(signature.len(), 64);
    assert_eq!(finding["classification"], "swallowed_predefined");
    assert_eq!(finding["handler"]["handler_file"], "pkg.adb");
    assert_eq!(finding["handler"]["handler_line"], 12);
    assert_eq!(finding["last_breadcrumb"], 1);
    assert_eq!(finding["fixture_path"], FIXTURE_PATH);
    assert_eq!(finding["harness_id"], HARNESS_ID);
    assert_eq!(finding["dialect"], "ada95");
}

#[test]
fn swallowed_constraint_error_aarch64_qemu_run_matches_host_finding_when_tools_available() {
    let Some(tools) = Aarch64Tools::discover() else {
        eprintln!(
            "skipping: requires gprbuild, aarch64-linux-gnu-gprbuild, \
             aarch64-linux-gnu-gnat, and qemu-aarch64"
        );
        return;
    };

    let temp = temp_dir("m17-swallowed-aarch64-qemu");
    let (work_dir, _main_adb) = generate_swallowed_constraint_harness(&temp);
    let input = swallowed_constraint_input();

    build_harness(&work_dir, &[]);
    let host_exe = find_built_executable(&work_dir, HARNESS_ID);
    let host_testcase = run_harness_direct(&host_exe, &input, &temp.join("host-events.bin"));
    let (host_finding_dir, host_finding) =
        emit_finding(&temp.join("host-corpus"), &input, &host_testcase);

    build_harness(
        &work_dir,
        &[
            "--target",
            "aarch64-linux-gnu",
            "--toolchain",
            "aarch64-linux-gnu",
        ],
    );
    let cross_exe = find_built_executable(&work_dir, HARNESS_ID);

    let mut replay_args = vec![
        OsString::from("govfuzz"),
        OsString::from("replay"),
        OsString::from("--finding"),
        host_finding_dir.as_os_str().to_owned(),
        OsString::from("--harness"),
        cross_exe.as_os_str().to_owned(),
        OsString::from("--qemu-user"),
        tools.qemu.as_os_str().to_owned(),
    ];
    for arg in tools.qemu_args() {
        replay_args.push(OsString::from("--qemu-arg"));
        replay_args.push(arg);
    }
    assert_eq!(cli::run_from(replay_args), 0);

    let cross_testcase =
        run_harness_qemu(&tools, &cross_exe, &input, &temp.join("cross-events.bin"));
    let (_cross_finding_dir, cross_finding) =
        emit_finding(&temp.join("cross-corpus"), &input, &cross_testcase);

    assert_eq!(cross_finding, host_finding);
}

fn generate_swallowed_constraint_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    let source = fixture_root().join("pkg.adb");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source.to_str().expect("fixture source path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::copy(
        fixture_root().join("pkg.ads"),
        instrumented_dir.join("pkg.ads"),
    )
    .expect("fixture spec is copied");

    let instrumented_source = instrumented_dir.join("pkg.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Parse",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            HARNESS_ID,
        ]),
        0
    );

    (work_dir, harness_root.join(HARNESS_ID).join("main.adb"))
}

fn build_harness(work_dir: &Path, extra_args: &[&str]) {
    let mut args = vec![
        OsString::from("govfuzz"),
        OsString::from("build"),
        work_dir.as_os_str().to_owned(),
        OsString::from("--harness"),
        OsString::from(HARNESS_ID),
    ];
    args.extend(extra_args.iter().map(OsString::from));

    assert_eq!(cli::run_from(args), 0);
}

fn run_harness_direct(exe: &Path, input: &[u8], events_path: &Path) -> Testcase {
    let mut child = Command::new(exe)
        .env("GOVFUZZ_EVENTS_PATH", events_path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("harness starts");
    write_stdin_and_wait(&mut child, input);
    read_single_testcase(events_path)
}

fn run_harness_qemu(
    tools: &Aarch64Tools,
    exe: &Path,
    input: &[u8],
    events_path: &Path,
) -> Testcase {
    let mut command = Command::new(&tools.qemu);
    command.args(tools.qemu_args()).arg(exe);
    let mut child = command
        .env("GOVFUZZ_EVENTS_PATH", events_path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("qemu-user harness starts");
    write_stdin_and_wait(&mut child, input);
    read_single_testcase(events_path)
}

fn write_stdin_and_wait(child: &mut std::process::Child, input: &[u8]) {
    {
        let mut stdin = child.stdin.take().expect("harness stdin is piped");
        stdin.write_all(input).expect("input is written");
    }

    let status = child.wait().expect("harness exits");
    assert!(status.success(), "harness failed with status {status}");
}

fn read_single_testcase(events_path: &Path) -> Testcase {
    let events = fs::File::open(events_path).expect("events file exists");
    let testcases = group_into_testcases(EventReader::new(events)).expect("events parse");
    assert_eq!(testcases.len(), 1);
    testcases.into_iter().next().unwrap()
}

fn emit_finding(root: &Path, input: &[u8], testcase: &Testcase) -> (PathBuf, serde_json::Value) {
    let emitter = FindingEmitter::with_metadata(
        root.to_path_buf(),
        HARNESS_ID.to_owned(),
        "ada95".to_owned(),
        FIXTURE_PATH.to_owned(),
    );
    let id = emitter
        .emit(input, testcase, 0)
        .expect("finding is emitted");
    let finding_dir = root.join("findings").join(id.0);
    let finding =
        serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    (finding_dir, finding)
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

fn fixture_root() -> PathBuf {
    repo_root().join("examples/swallowed_constraint_error")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}

struct Aarch64Tools {
    qemu: PathBuf,
    sysroot: Option<PathBuf>,
}

impl Aarch64Tools {
    fn discover() -> Option<Self> {
        if which::which("gprbuild").is_err()
            || which::which("aarch64-linux-gnu-gprbuild").is_err()
            || which::which("aarch64-linux-gnu-gnat").is_err()
        {
            return None;
        }

        let qemu = std::env::var_os("GOVFUZZ_AARCH64_QEMU_USER")
            .map(PathBuf::from)
            .or_else(|| which::which("qemu-aarch64").ok())
            .or_else(|| which::which("qemu-aarch64-static").ok())?;
        let sysroot = std::env::var_os("GOVFUZZ_AARCH64_SYSROOT")
            .map(PathBuf::from)
            .or_else(|| {
                let default = PathBuf::from("/usr/aarch64-linux-gnu");
                default.is_dir().then_some(default)
            });

        Some(Self { qemu, sysroot })
    }

    fn qemu_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(sysroot) = &self.sysroot {
            args.push(OsString::from("-L"));
            args.push(sysroot.as_os_str().to_owned());
        }
        args
    }
}
