// SPDX-License-Identifier: Apache-2.0

//! Fresh-work-directory acceptance campaigns for the zero-fuzz remediation
//! ledger. These fixtures intentionally combine boundaries that previously
//! passed in isolation but failed when old Ada/C++ projects exercised them
//! together.

use std::path::Path;
use std::process::{Command, Output};

fn run_auto(root: &Path, work: &Path, extra: &[&str]) -> (serde_json::Value, Output) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    command
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass");
    command.args(extra);
    let output = command.output().expect("spawn govfuzz auto");
    let run_path = work.join("auto/run.json");
    let bytes = std::fs::read(&run_path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; status={:?}\nstderr:\n{}",
            run_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let run = serde_json::from_slice(&bytes).expect("parse run.json");
    (run, output)
}

fn assert_target_entered_and_fuzzed(target: &serde_json::Value, stderr: &[u8]) {
    assert_eq!(
        target["outcome"]["outcome"],
        "built_and_fuzzed",
        "target did not build and fuzz: {}\nstderr:\n{}",
        target["outcome"],
        String::from_utf8_lossy(stderr)
    );
    let passes = target["outcome"]["passes"]
        .as_array()
        .expect("built_and_fuzzed passes");
    assert!(
        passes
            .iter()
            .any(|pass| pass["target_entry_observed"] == true),
        "no endpoint-entry proof: {passes:?}"
    );
    assert!(
        passes
            .iter()
            .filter_map(|pass| pass["executions"].as_u64())
            .sum::<u64>()
            > 0,
        "no fuzz input executions: {passes:?}"
    );
}

fn have_ada_toolchain() -> bool {
    which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok()
}

#[test]
fn ada_overloads_each_build_enter_and_fuzz_their_exact_profile() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-ada-overloads-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    std::fs::write(
        root.join("integer_dep.ads"),
        "package Integer_Dep is procedure Touch (V : Integer); end Integer_Dep;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("integer_dep.adb"),
        "package body Integer_Dep is procedure Touch (V : Integer) is begin if V = Integer'First then null; end if; end Touch; end Integer_Dep;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("string_dep.ads"),
        "package String_Dep is procedure Touch (V : String); end String_Dep;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("string_dep.adb"),
        "package body String_Dep is procedure Touch (V : String) is begin if V'Length = 99 then null; end if; end Touch; end String_Dep;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("endpoints.ads"),
        "package Endpoints is\n   procedure Parse (Value : Integer);\n   procedure Parse (Value : String);\nend Endpoints;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("endpoints.adb"),
        "with Integer_Dep; with String_Dep;\npackage body Endpoints is\n   procedure Parse (Value : Integer) is begin Integer_Dep.Touch (Value); end Parse;\n   procedure Parse (Value : String) is begin String_Dep.Touch (Value); end Parse;\nend Endpoints;\n",
    )
    .unwrap();

    let work = root.join("work");
    let (run, output) = run_auto(root, &work, &["--target-file", "endpoints.ads"]);
    let targets = run["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2, "expected both overloads: {run}");
    let mut lines = targets
        .iter()
        .filter_map(|target| target["line"].as_u64())
        .collect::<Vec<_>>();
    lines.sort_unstable();
    lines.dedup();
    assert_eq!(
        lines.len(),
        2,
        "overloads must retain distinct lines: {targets:?}"
    );

    let mut saw_integer = false;
    let mut saw_string = false;
    for target in targets {
        assert_target_entered_and_fuzzed(target, &output.stderr);
        let id = target["harness_id"].as_str().expect("harness id");
        let main = std::fs::read_to_string(work.join("harnesses").join(id).join("main.adb"))
            .expect("read generated Ada harness");
        saw_integer |= main.contains("Integer (AdaFuzz.Decode.I32");
        saw_string |= main.contains("AdaFuzz.Decode.Ada_String");
    }
    assert!(
        saw_integer && saw_string,
        "each overload needs its own decoder profile"
    );
}

#[test]
fn multi_idl_checked_in_servant_reopens_modules_without_collisions_and_fuzzes() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-multi-idl-servant-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    let idl = root.join("idl");
    std::fs::create_dir_all(&idl).unwrap();

    // A real parent package deliberately collides with the generated fake-CORBA
    // base. It is complete for this fixture, so collision pruning must retain it
    // while keeping the genuinely missing CORBA.Object/PortableServer children.
    std::fs::write(
        root.join("corba.ads"),
        "package CORBA is\n   pragma Pure;\n   type Long is new Integer;\n   type Unsigned_Long is mod 2 ** 32;\n   type Short is range -2 ** 15 .. 2 ** 15 - 1;\n   type Unsigned_Short is mod 2 ** 16;\n   subtype Boolean is Standard.Boolean;\n   subtype Float is Standard.Float;\n   subtype Double is Standard.Long_Float;\n   subtype String is Standard.String;\n   type Octet is mod 2 ** 8;\n   type Octet_Array is array (Positive range <>) of Octet;\nend CORBA;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("bar_impl.ads"),
        "with CORBA.Object; with PortableServer;\npackage Bar_Impl is\n   type Servant is new PortableServer.Servant_Base with null record;\n   function Compute (Self : Servant; S : String) return Integer;\nend Bar_Impl;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("bar_impl.adb"),
        "package body Bar_Impl is\n   function Compute (Self : Servant; S : String) return Integer is\n      pragma Unreferenced (Self);\n   begin\n      if S'Length = 17 then return 17; else return S'Length; end if;\n   end Compute;\nend Bar_Impl;\n",
    )
    .unwrap();
    std::fs::write(
        idl.join("common.idl"),
        "#ifndef SHARED_COMMON_IDL\n#define SHARED_COMMON_IDL\nmodule Shared { struct Common { long id; }; const string COMMON_TOKEN = \"COMMON\"; };\n#endif\n",
    )
    .unwrap();
    std::fs::write(
        idl.join("first.idl"),
        "#include \"common.idl\"\nmodule Shared { struct First { long first_value; }; const string FIRST_TOKEN = \"FIRST\"; };\n",
    )
    .unwrap();
    std::fs::write(
        idl.join("second.idl"),
        "#include \"common.idl\"\nmodule Shared { struct Second { long second_value; }; const string SECOND_TOKEN = \"SECOND\"; };\n",
    )
    .unwrap();

    let work = root.join("work");
    let (run, output) = run_auto(root, &work, &["--target", "Compute"]);
    let targets = run["targets"].as_array().expect("targets array");
    let discovery_cache =
        std::fs::read_to_string(work.join("discovery-cache.json")).unwrap_or_default();
    assert_eq!(
        targets.len(),
        1,
        "expected checked-in servant target: {run}\ndiscovery cache:\n{discovery_cache}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    if targets[0]["outcome"]["outcome"] != "built_and_fuzzed" {
        let id = targets[0]["harness_id"].as_str().unwrap();
        let main = std::fs::read_to_string(work.join("harnesses").join(id).join("main.adb"))
            .unwrap_or_default();
        let metadata = std::fs::read_to_string(
            work.join("harnesses")
                .join(id)
                .join("generation-metadata.json"),
        )
        .unwrap_or_default();
        panic!(
            "multi-IDL servant failed before fuzzing: {}\nmetadata: {metadata}\nmain:\n{main}\nstderr:\n{}",
            targets[0]["outcome"],
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_target_entered_and_fuzzed(&targets[0], &output.stderr);

    let mapping = work.join("fake_corba");
    let shared = std::fs::read_to_string(mapping.join("shared.ads"))
        .expect("read aggregate reopened-module mapping");
    for declaration in [
        "type Common is record",
        "type First is record",
        "type Second is record",
    ] {
        assert!(
            shared.contains(declaration),
            "missing {declaration}:\n{shared}"
        );
    }
    assert_eq!(
        shared.matches("type Common is record").count(),
        1,
        "multiply included IDL declaration was duplicated: {shared}"
    );
    let dictionary = std::fs::read_to_string(mapping.join("dictionary.txt"))
        .expect("read aggregate IDL dictionary");
    for token in ["COMMON", "FIRST", "SECOND"] {
        assert!(dictionary.contains(token), "missing IDL token {token}");
    }
    let recovery: serde_json::Value =
        serde_json::from_slice(&std::fs::read(mapping.join("idl_recovery_report.json")).unwrap())
            .unwrap();
    assert_eq!(recovery["status"], "complete", "{recovery}");
    assert_eq!(recovery["files_seen"], 3, "{recovery}");
    assert_eq!(recovery["files_parsed"], 3, "{recovery}");
    assert!(
        recovery["reopened_modules"].as_u64().unwrap_or(0) >= 2,
        "{recovery}"
    );
    assert_eq!(recovery["generated_unit_collisions"], 0, "{recovery}");
    assert!(
        recovery["real_fake_collisions_pruned"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "checked-in CORBA binding did not win: {recovery}"
    );

    let report_path = root.join("multi-idl-support.txt");
    let report_output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("bug-report")
        .arg(&work)
        .arg("--output")
        .arg(&report_path)
        .arg("--max-bytes")
        .arg("4000")
        .output()
        .expect("collect multi-IDL support report");
    assert!(report_output.status.success());
    let support = std::fs::read_to_string(&report_path).unwrap();
    for fact in [
        "schema=govfuzz.support.v3",
        "target_entry_observed:1",
        "ada_idl=files_seen:3 files_parsed:3 partial:no",
        "generated_unit_collisions:0",
        "real_fake_collisions_pruned:1",
        "campaign=version:",
        "discovery_semantics:",
        "generated_state_semantics:",
        "work_state:new",
    ] {
        assert!(support.contains(fact), "missing {fact}:\n{support}");
    }
    let root_text = root.to_string_lossy().into_owned();
    for secret in ["Shared", "Bar_Impl", "Compute", root_text.as_str()] {
        assert!(
            !support.contains(secret),
            "support report leaked {secret}:\n{support}"
        );
    }
    assert!(support.len() <= 4_000);
    assert_eq!(
        std::fs::read_to_string(root.join("corba.ads")).unwrap(),
        "package CORBA is\n   pragma Pure;\n   type Long is new Integer;\n   type Unsigned_Long is mod 2 ** 32;\n   type Short is range -2 ** 15 .. 2 ** 15 - 1;\n   type Unsigned_Short is mod 2 ** 16;\n   subtype Boolean is Standard.Boolean;\n   subtype Float is Standard.Float;\n   subtype Double is Standard.Long_Float;\n   subtype String is Standard.String;\n   type Octet is mod 2 ** 8;\n   type Octet_Array is array (Positive range <>) of Octet;\nend CORBA;\n"
    );
}

#[test]
fn legacy_cpp_lifecycle_namespace_and_default_parameter_campaign_fuzzes() {
    if which::which("g++").is_err() {
        eprintln!("SKIP: g++ not installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-cpp-lifecycle-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    let config = root.join("config.hpp");
    let header = root.join("api.hpp");
    let source = root.join("api.cpp");
    std::fs::write(&config, "#pragma once\n#define LEGACY_API_READY 1\n").unwrap();
    std::fs::write(
        &header,
        r#"#pragma once
#ifndef LEGACY_API_READY
#error include config.hpp before api.hpp
#endif
#include <cstddef>
namespace CORBA { struct Environment { int marker; Environment() : marker(0) {} }; }
namespace real { struct Options { unsigned mode; Options() : mode(0) {} }; }
namespace decoy { struct Options { Options() = delete; }; }
namespace legacy {
class Parser {
public:
    Parser() : ready_(false) {}
    void setup(const real::Options &options) { ready_ = options.mode <= 255; }
    int parse(const unsigned char *data, std::size_t size, const real::Options &options, CORBA::Environment &_env);
private:
    Parser(int) = delete;
    bool ready_;
};
}
"#,
    )
    .unwrap();
    std::fs::write(
        &source,
        "#include \"config.hpp\"\n#include \"api.hpp\"\nint legacy::Parser::parse(const unsigned char *data, std::size_t size, const real::Options &options, CORBA::Environment &_env) { return data && size && ready_ ? data[0] + (int)options.mode + _env.marker : 0; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec_pretty(&serde_json::json!([{
            "directory": root,
            "file": source,
            "arguments": ["g++", "-I", root, "-std=gnu++14", "-c", source]
        }]))
        .unwrap(),
    )
    .unwrap();

    let work = root.join("work");
    let (run, output) = run_auto(root, &work, &["--target", "parse"]);
    let targets = run["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1, "expected exact method target: {run}");
    assert_target_entered_and_fuzzed(&targets[0], &output.stderr);
    let id = targets[0]["harness_id"].as_str().unwrap();
    let main = std::fs::read_to_string(work.join("harnesses").join(id).join("main.cpp"))
        .expect("read generated C++ harness");
    let config_pos = main.find("config.hpp").expect("config include");
    let api_pos = main.find("api.hpp").expect("API include");
    assert!(
        config_pos < api_pos,
        "source include order was not preserved: {main}"
    );
    assert!(
        main.contains("real::Options"),
        "defaultable parameter missing: {main}"
    );
    assert!(
        !main.contains("decoy::Options _gf"),
        "namespace decoy was selected: {main}"
    );
    assert!(
        main.contains("CORBA::Environment _env;") && main.contains("_env)"),
        "legacy CORBA call context was not neutralized: {main}"
    );
}

#[test]
fn empty_cpp_lifecycle_records_direct_fallback_and_fuzzes() {
    if which::which("g++").is_err() {
        eprintln!("SKIP: g++ not installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-empty-lifecycle-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    let header = root.join("parser.hpp");
    let source = root.join("parser.cpp");
    std::fs::write(
        &header,
        "#pragma once\n#include <string_view>\nclass Parser {\npublic:\n  Parser();\n  int parse(std::string_view input);\nprivate:\n  void reset();\n  int state_;\n};\n",
    )
    .unwrap();
    std::fs::write(
        &source,
        "#include \"parser.hpp\"\nParser::Parser() : state_(1) {}\nint Parser::parse(std::string_view input) { return state_ + (int)input.size(); }\nvoid Parser::reset() { state_ = 0; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec_pretty(&serde_json::json!([{
            "directory": root,
            "file": source,
            "arguments": ["g++", "-I", root, "-std=gnu++17", "-c", source]
        }]))
        .unwrap(),
    )
    .unwrap();

    let work = root.join("work");
    let (run, output) = run_auto(
        root,
        &work,
        &["--target", "parse", "--target-file", "parser.cpp"],
    );
    let targets = run["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1, "{run}");
    assert_target_entered_and_fuzzed(&targets[0], &output.stderr);
    let chain = targets[0]["attempt_trace"]["fallback_chain"]
        .as_array()
        .expect("fallback chain")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        &chain[..2],
        ["sequence_generation_failed", "direct_fallback"],
        "empty lifecycle fallback was not checkpointed: {targets:?}"
    );
    let id = targets[0]["harness_id"].as_str().unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            work.join("harnesses")
                .join(id)
                .join("generation-metadata.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["requested_kind"], "direct");
    assert_eq!(metadata["emitted_path"], "constructed_receiver");
}

#[test]
fn header_compile_database_context_fuzzes_and_support_report_is_private() {
    if which::which("g++").is_err() {
        eprintln!("SKIP: g++ not installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-header-context-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    let forced = root.join("forced_private.hpp");
    let header = root.join("private_api_name.hpp");
    let owner = root.join("private_owner_name.cpp");
    let support = root.join("private_support_name.cpp");
    std::fs::write(&forced, "#pragma once\n#define FORCED_MODE 1\n").unwrap();
    std::fs::write(
        &header,
        "#pragma once\n#ifndef FORCED_MODE\n#error forced include lost\n#endif\n#ifndef OWNER_MODE\n#error owner define lost\n#endif\nunsigned support_value(unsigned);\ninline int parse_private_header(const unsigned char *data, unsigned size) { return data && size ? (int)support_value(data[0]) : 0; }\n",
    )
    .unwrap();
    std::fs::write(&owner, "#include \"private_api_name.hpp\"\n").unwrap();
    std::fs::write(
        &support,
        "#ifndef SUPPORT_TU\n#error support TU context lost\n#endif\nunsigned support_value(unsigned value) { return value + 1; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec_pretty(&serde_json::json!([
            {
                "directory": root,
                "file": owner,
                "arguments": ["g++", "-I", root, "-include", forced, "-DOWNER_MODE=1", "-fpack-struct=1", "-std=gnu++14", "-c", owner]
            },
            {
                "directory": root,
                "file": support,
                "arguments": ["g++", "-I", root, "-DSUPPORT_TU=1", "-std=gnu++17", "-c", support]
            }
        ]))
        .unwrap(),
    )
    .unwrap();

    let work = root.join("work");
    let (run, output) = run_auto(
        root,
        &work,
        &[
            "--target",
            "parse_private_header",
            "--target-file",
            "private_api_name.hpp",
        ],
    );
    let targets = run["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1, "expected header target: {run}");
    assert_target_entered_and_fuzzed(&targets[0], &output.stderr);

    let report_path = root.join("support.txt");
    let report_output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("bug-report")
        .arg(&work)
        .arg("--output")
        .arg(&report_path)
        .arg("--stdout")
        .arg("--examples")
        .arg("6")
        .arg("--max-bytes")
        .arg("4000")
        .output()
        .expect("run support collector");
    assert!(
        report_output.status.success(),
        "collector failed: {}",
        String::from_utf8_lossy(&report_output.stderr)
    );
    let report = std::fs::read_to_string(&report_path).expect("read support report");
    assert!(report.len() <= 4_000, "support report exceeded cap");
    for fact in [
        "schema=govfuzz.support.v3",
        "attempts=terminal_stages:",
        "target_entry_observed:1",
        "associated_header_compile_database",
        "compiler_families:cpp/gcc:1",
        "per_tu_object_graphs:1",
        "repair_per_tu_object_graphs:1",
        "tu_context=rows:0 repair_rows:1",
        "standards:cpp/gnu++17:1",
        "discovery_cache_producer_match:yes",
    ] {
        assert!(report.contains(fact), "missing {fact}:\n{report}");
    }
    let root_text = root.to_string_lossy().into_owned();
    for secret in [
        "private_api_name",
        "private_owner_name",
        "private_support_name",
        "parse_private_header",
        root_text.as_str(),
    ] {
        assert!(
            !report.contains(secret),
            "support report leaked {secret}:\n{report}"
        );
    }
}

#[test]
fn incompatible_resume_and_clean_all_cannot_reuse_stale_generated_state() {
    if which::which("clang").is_err() && which::which("gcc").is_err() {
        eprintln!("SKIP: no C compiler installed");
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-zero-work-state-")
        .tempdir()
        .unwrap();
    let root = temp.path();
    let source = root.join("parser.c");
    std::fs::write(
        &source,
        "int parse(const unsigned char *data, unsigned size) { return data && size ? data[0] : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");

    let (first, first_output) = run_auto(root, &work, &["--target", "parse"]);
    let first_targets = first["targets"].as_array().expect("first targets");
    assert_eq!(first_targets.len(), 1, "{first}");
    assert_target_entered_and_fuzzed(&first_targets[0], &first_output.stderr);

    // Simulate artifacts left by an older release, including an otherwise
    // compatible-looking explicit resume. Corpus/findings are durable evidence;
    // every other sentinel is regenerable and must disappear on migration.
    for directory in [
        "harnesses/H-STALE",
        "generated_harnesses/H-STALE",
        "fake_corba",
        "src_instrumented",
        "cxx_dialects",
        "corpus/KEEP",
        "findings/KEEP",
    ] {
        std::fs::create_dir_all(work.join(directory)).unwrap();
    }
    std::fs::write(work.join("harnesses/H-STALE/main.c"), "stale").unwrap();
    std::fs::write(work.join("generated_harnesses/H-STALE/main.c"), "stale").unwrap();
    std::fs::write(work.join("fake_corba/stale.ads"), "stale").unwrap();
    std::fs::write(work.join("src_instrumented/stale.adb"), "stale").unwrap();
    std::fs::write(work.join("cxx_dialects/stale.txt"), "gnu++03").unwrap();
    std::fs::write(work.join("c_compat.mk"), "C_COMPAT_FLAGS := -fcommon\n").unwrap();
    std::fs::write(work.join("corpus/KEEP/seed.bin"), b"durable seed").unwrap();
    std::fs::write(work.join("findings/KEEP/record"), b"durable finding").unwrap();

    let state_path = work.join("auto/work-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["generated_state_semantic_version"] = serde_json::json!(999);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let cache_path = work.join("discovery-cache.json");
    let mut cache: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    cache["producer_version"] = serde_json::json!("obsolete-release");
    std::fs::write(&cache_path, serde_json::to_vec(&cache).unwrap()).unwrap();

    let (resumed, resumed_output) = run_auto(root, &work, &["--target", "parse", "--resume"]);
    let resumed_targets = resumed["targets"].as_array().expect("resumed targets");
    assert_eq!(resumed_targets.len(), 1, "{resumed}");
    assert_target_entered_and_fuzzed(&resumed_targets[0], &resumed_output.stderr);
    let migrated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(migrated["disposition"], "incompatible_migration");
    for stale in [
        "harnesses/H-STALE",
        "generated_harnesses/H-STALE",
        "fake_corba/stale.ads",
        "src_instrumented/stale.adb",
        "cxx_dialects/stale.txt",
        "c_compat.mk",
    ] {
        assert!(
            !work.join(stale).exists(),
            "stale artifact survived: {stale}"
        );
    }
    assert!(work.join("corpus/KEEP/seed.bin").is_file());
    assert!(work.join("findings/KEEP/record").is_file());
    let refreshed_cache: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    assert_ne!(refreshed_cache["producer_version"], "obsolete-release");

    let migration_report = root.join("migration-support.txt");
    let migration_report_output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("bug-report")
        .arg(&work)
        .arg("--output")
        .arg(&migration_report)
        .arg("--max-bytes")
        .arg("4000")
        .output()
        .expect("collect migration support report");
    assert!(migration_report_output.status.success());
    let migration_support = std::fs::read_to_string(&migration_report).unwrap();
    for fact in [
        "work_state:incompatible_migration",
        "discovery_cache_hit:no",
        "discovery_cache_producer_match:yes",
    ] {
        assert!(
            migration_support.contains(fact),
            "missing migration fact {fact}:\n{migration_support}"
        );
    }

    let clean = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("clean")
        .arg(&work)
        .arg("--all")
        .output()
        .expect("run clean --all");
    assert!(
        clean.status.success(),
        "clean --all failed: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    for owned in [
        "auto",
        "harnesses",
        "generated_harnesses",
        "corpus",
        "findings",
        "discovery-cache.json",
    ] {
        assert!(
            !work.join(owned).exists(),
            "clean retained owned path {owned}"
        );
    }
    assert!(source.is_file(), "clean escaped the work directory");

    let (fresh, fresh_output) = run_auto(root, &work, &["--target", "parse"]);
    let fresh_targets = fresh["targets"].as_array().expect("fresh targets");
    assert_eq!(fresh_targets.len(), 1, "{fresh}");
    assert_target_entered_and_fuzzed(&fresh_targets[0], &fresh_output.stderr);
    let fresh_state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(fresh_state["disposition"], "new");
}
