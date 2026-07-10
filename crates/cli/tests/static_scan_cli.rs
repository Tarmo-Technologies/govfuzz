// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn static_scan_since_scopes_to_changed_files() {
    use std::process::Command;
    let git = |dir: &std::path::Path, args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git")
    };
    if !git(&std::env::temp_dir(), &["--version"]).status.success() {
        return; // git not available
    }
    let root = temp_dir("since-scope");
    fs::create_dir_all(&root).unwrap();
    // A committed vulnerable file, then a second added afterwards.
    fs::write(
        root.join("old.py"),
        "import os\ndef h(user):\n    os.system('echo ' + user)\n",
    )
    .unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "base"]);
    fs::write(
        root.join("new.py"),
        "import os\ndef g(user):\n    os.system('echo ' + user)\n",
    )
    .unwrap();

    // Full scan sees both files' command-injection findings.
    let out_full = root.join("full");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            root.to_str().unwrap(),
            "--out",
            out_full.to_str().unwrap(),
        ]),
        0
    );
    let full: serde_json::Value =
        serde_json::from_slice(&fs::read(out_full.join("static-report.json")).unwrap()).unwrap();
    let full_paths: std::collections::BTreeSet<String> = full["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"]["path"].as_str().unwrap().to_owned())
        .collect();
    assert!(full_paths.iter().any(|p| p.ends_with("old.py")));
    assert!(full_paths.iter().any(|p| p.ends_with("new.py")));

    // `--since HEAD` scans only the newly-added file.
    let out_inc = root.join("inc");
    std::env::set_var("GOVFUZZ_SINCE_REV", "HEAD");
    let exit = cli::run_from([
        "govfuzz",
        "static-scan",
        root.to_str().unwrap(),
        "--out",
        out_inc.to_str().unwrap(),
        "--since",
        "HEAD",
    ]);
    std::env::remove_var("GOVFUZZ_SINCE_REV");
    assert_eq!(exit, 0);
    let inc: serde_json::Value =
        serde_json::from_slice(&fs::read(out_inc.join("static-report.json")).unwrap()).unwrap();
    let inc_paths: std::collections::BTreeSet<String> = inc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"]["path"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        inc_paths.iter().any(|p| p.ends_with("new.py")),
        "since scan must include the changed file: {inc_paths:?}"
    );
    assert!(
        !inc_paths.iter().any(|p| p.ends_with("old.py")),
        "since scan must skip the unchanged file: {inc_paths:?}"
    );
}

#[test]
fn static_scan_reports_ada_c_and_cpp_findings_with_sarif() {
    let root = temp_dir("multi-language");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("legacy.c"),
        "#include <string.h>\nvoid copy(char *dst, const char *src) { strcpy(dst, src); }\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy.cpp"),
        "#include <cstring>\nnamespace Legacy { void copy(char *d, const char *s) { std::strcpy(d, s); } }\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy.adb"),
        "procedure Legacy is\nbegin\n   null;\nexception\n   when others => null;\nend Legacy;\n",
    )
    .unwrap();

    let out = root.join("static");
    let exit = cli::run_from([
        "govfuzz",
        "static-scan",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--sarif",
    ]);

    assert_eq!(exit, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "govfuzz.static.v1");
    assert_eq!(report["counts"]["findings"], 3);
    assert_eq!(report["counts"]["by_language"]["ada"], 1);
    assert_eq!(report["counts"]["by_language"]["c"], 1);
    assert_eq!(report["counts"]["by_language"]["cpp"], 1);
    assert!(finding(&report, "GF-401", "legacy.c").is_some());
    assert!(finding(&report, "GF-401", "legacy.cpp").is_some());
    assert!(finding(&report, "GF-402", "legacy.adb").is_some());

    let c_finding = finding(&report, "GF-401", "legacy.c").unwrap();
    assert_eq!(c_finding["baseline_status"], "new");
    assert!(c_finding["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("GF-401:"));

    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 3);
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["findingKind"],
        "static"
    );
}

#[test]
fn static_scan_applies_suppressions_and_marks_baseline_status() {
    let root = temp_dir("suppressions-baseline");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("legacy.c"),
        "#include <string.h>\nvoid copy(char *dst, const char *src) { strcpy(dst, src); }\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy.cpp"),
        "#include <cstring>\nvoid copy(char *d, const char *s) { std::strcpy(d, s); }\n",
    )
    .unwrap();

    let suppressions = root.join("suppressions.json");
    fs::write(
        &suppressions,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.static.suppressions.v1",
            "suppressions": [{
                "rule_id": "GF-401",
                "path": "legacy.c",
                "line": 2,
                "reason": "tracked legacy wrapper",
                "triage_state": "false_positive"
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let baseline = root.join("baseline.json");
    fs::write(
        &baseline,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.static.v1",
            "findings": [
                {
                    "fingerprint": "GF-401:legacy.cpp:2:unsafe-string-copy",
                    "rule_id": "GF-401",
                    "path": "legacy.cpp"
                },
                {
                    "fingerprint": "GF-999:old.adb:1:retired",
                    "rule_id": "GF-999",
                    "path": "old.adb"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("static");
    let exit = cli::run_from([
        "govfuzz",
        "static-scan",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--suppressions",
        suppressions.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);

    assert_eq!(exit, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    assert_eq!(report["counts"]["findings"], 1);
    assert_eq!(report["counts"]["suppressed"], 1);
    assert_eq!(report["counts"]["new"], 0);
    assert_eq!(report["counts"]["unchanged"], 1);
    assert_eq!(report["counts"]["resolved"], 1);

    assert!(finding(&report, "GF-401", "legacy.c").is_none());
    let cpp_finding = finding(&report, "GF-401", "legacy.cpp").unwrap();
    assert_eq!(cpp_finding["baseline_status"], "unchanged");
    assert_eq!(
        report["baseline"]["resolved"][0]["fingerprint"],
        "GF-999:old.adb:1:retired"
    );
    assert_eq!(report["suppressed"][0]["reason"], "tracked legacy wrapper");
    assert_eq!(
        report["suppressed"][0]["finding"]["triage"]["state"],
        "false_positive"
    );
}

#[test]
fn static_scan_emits_interprocedural_taint_traces_and_gaps() {
    let root = temp_dir("taint");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("chain.c"),
        "#include <stdlib.h>\nvoid entry(char *input) { stage(input); missing_vendor(input); }\nvoid stage(char *cmd) { system(cmd); }\n",
    )
    .unwrap();
    fs::write(
        src.join("chain.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid stage(std::string cmd) { std::system(cmd.c_str()); }\nvoid entry(std::string input) { stage(input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("chain.adb"),
        "with GNAT.OS_Lib;\nprocedure Chain is\n   procedure Stage (Cmd : String) is\n   begin\n      GNAT.OS_Lib.Spawn (Cmd);\n   end Stage;\n   procedure Entry (Input : String) is\n   begin\n      Stage (Input);\n   end Entry;\nbegin\n   null;\nend Chain;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let command_findings = findings_by_rule(&report, "GF-304");
    assert_eq!(command_findings.len(), 3);
    for finding in command_findings {
        assert!(
            finding["analysis"]["trace"].as_array().unwrap().len() >= 2,
            "taint finding should carry source-to-sink trace: {finding:#}"
        );
        assert_eq!(finding["analysis"]["gaps"].as_array().unwrap().len(), 0);
        assert_eq!(
            finding["analysis"]["actionability"]["verdict"],
            "likely_reachable"
        );
    }

    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|gap| gap["callee"] == "missing_vendor"
            && gap["reason"] == "unresolved_project_local_call"),
        "expected explicit unresolved-call gap, got {gaps:#?}"
    );
}

#[test]
fn static_scan_resolves_cross_file_taint_calls_for_ada_c_and_cpp() {
    let root = temp_dir("cross-file-taint");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("entry.c"),
        "void stage(char *cmd);\nvoid entry(char *input) {\n  stage(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("stage.c"),
        "#include <stdlib.h>\nvoid stage(char *cmd) {\n  system(cmd);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("entry.cpp"),
        "#include <string>\nvoid stage_cpp(std::string cmd);\nvoid entry_cpp(std::string input) {\n  stage_cpp(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("stage.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid stage_cpp(std::string cmd) {\n  std::system(cmd.c_str());\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("entry.adb"),
        "procedure Entry (Input : String) is\nbegin\n   Stage (Input);\nend Entry;\n",
    )
    .unwrap();
    fs::write(
        src.join("stage.adb"),
        "with GNAT.OS_Lib;\nprocedure Stage (Cmd : String) is\nbegin\n   GNAT.OS_Lib.Spawn (Cmd);\nend Stage;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        3,
        "cross-file Ada/C/C++ taint calls should resolve to sink findings: {findings:#?}"
    );
    for (entry, stage) in [
        ("entry.c", "stage.c"),
        ("entry.cpp", "stage.cpp"),
        ("entry.adb", "stage.adb"),
    ] {
        let finding = finding(&report, "GF-304", stage).unwrap();
        let trace = finding["analysis"]["trace"].as_array().unwrap();
        assert!(
            trace
                .iter()
                .any(|step| step["kind"] == "call"
                    && step["path"].as_str().unwrap().ends_with(entry)),
            "{stage} finding should include cross-file call from {entry}: {finding:#}"
        );
        assert!(
            trace
                .iter()
                .any(|step| step["kind"] == "sink"
                    && step["path"].as_str().unwrap().ends_with(stage)),
            "{stage} finding should include sink in callee file: {finding:#}"
        );
    }
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps.iter().any(|gap| {
            ["stage", "stage_cpp", "Stage"]
                .iter()
                .any(|callee| gap["callee"] == *callee)
        }),
        "resolved cross-file calls should not remain as analysis gaps: {gaps:#?}"
    );
}

#[test]
fn static_scan_prefers_same_file_taint_callees_when_function_names_collide() {
    let root = temp_dir("same-file-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("a_entry.c"),
        "void stage(char *cmd) { (void)cmd; }\nvoid entry(char *input) {\n  stage(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("z_vendor.c"),
        "#include <stdlib.h>\nvoid stage(char *cmd) {\n  system(cmd);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("a_entry.cpp"),
        "#include <string>\nvoid stage_cpp(std::string cmd) { (void)cmd; }\nvoid entry_cpp(std::string input) {\n  stage_cpp(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("z_vendor.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid stage_cpp(std::string cmd) {\n  std::system(cmd.c_str());\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert!(
        findings.is_empty(),
        "same-file safe helpers should not resolve to same-name sink helpers in later files: {findings:#?}"
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "stage" || gap["callee"] == "stage_cpp"),
        "same-file resolved helper calls should not be reported as unresolved: {gaps:#?}"
    );
}

#[test]
fn static_scan_preserves_cpp_qualified_taint_callees() {
    let root = temp_dir("cpp-qualified-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("qualified.cpp"),
        "#include <cstdlib>\n#include <string>\nnamespace Safe { void stage(std::string cmd); }\nnamespace Danger { void stage(std::string cmd); }\nvoid Safe::stage(std::string cmd) { (void)cmd; }\nvoid Danger::stage(std::string cmd) { std::system(cmd.c_str()); }\nvoid entry_cpp(std::string input) {\n  Safe::stage(input);\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert!(
        findings.is_empty(),
        "Safe::stage(input) must not resolve to same-leaf Danger::stage sink: {findings:#?}"
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "stage" || gap["callee"] == "Safe::stage"),
        "qualified local call should be resolved without unqualified gap noise: {gaps:#?}"
    );
}

#[test]
fn static_scan_prefers_cpp_namespace_scope_for_unqualified_calls() {
    let root = temp_dir("cpp-namespace-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("namespaced.cpp"),
        "#include <cstdlib>\n#include <string>\nnamespace Safe {\nvoid stage(std::string cmd) { (void)cmd; }\nvoid entry_cpp(std::string input) {\n  stage(input);\n}\n}\nnamespace Danger {\nvoid stage(std::string cmd) { std::system(cmd.c_str()); }\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert!(
        findings.is_empty(),
        "unqualified calls inside Safe namespace must not resolve to Danger::stage: {findings:#?}"
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "stage" || gap["callee"] == "Safe::stage"),
        "namespace-local helper call should resolve without gap noise: {gaps:#?}"
    );
}

#[test]
fn static_scan_prefers_cpp_class_scope_for_unqualified_member_calls() {
    let root = temp_dir("cpp-class-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("member.cpp"),
        "#include <cstdlib>\n#include <string>\nclass Gateway {\npublic:\n  void stage(std::string cmd) { (void)cmd; }\n  void entry_cpp(std::string input) { stage(input); }\n};\nvoid stage(std::string cmd) { std::system(cmd.c_str()); }\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert!(
        findings.is_empty(),
        "unqualified member calls inside Gateway must not resolve to global stage sink: {findings:#?}"
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "stage" || gap["callee"] == "Gateway::stage"),
        "class-local member call should resolve without gap noise: {gaps:#?}"
    );
}

#[test]
fn static_scan_resolves_cpp_object_member_taint_calls_without_global_leaf_fallback() {
    let root = temp_dir("cpp-object-member-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("object_member.cpp"),
        "#include <cstdlib>\n#include <string>\nclass Safe {\npublic:\n  void stage(std::string cmd) { (void)cmd; }\n};\nclass Dangerous {\npublic:\n  void stage(std::string cmd) { std::system(cmd.c_str()); }\n  void run_this(std::string cmd) { std::system(cmd.c_str()); }\n  void entry_this(std::string input) { this->run_this(input); }\n};\nvoid stage(std::string cmd) { std::system(cmd.c_str()); }\nvoid entry_safe(std::string input) {\n  Safe safe;\n  safe.stage(input);\n}\nvoid entry_object(std::string input) {\n  Dangerous dangerous;\n  dangerous.stage(input);\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        2,
        "only Dangerous object and this member calls should be reachable: {findings:#?}"
    );
    assert!(
        findings.iter().any(|finding| finding["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["callee"] == "Dangerous::stage")),
        "object member taint trace should resolve to Dangerous::stage: {findings:#?}"
    );
    assert!(
        findings.iter().any(|finding| finding["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["callee"] == "Dangerous::run_this")),
        "this member taint trace should resolve to Dangerous::run_this: {findings:#?}"
    );
    for finding in &findings {
        let trace = finding["analysis"]["trace"].as_array().unwrap();
        assert!(
            !trace.iter().any(|step| step["callee"] == "stage"),
            "object member calls must not fall back to the global same-leaf stage sink: {finding:#}"
        );
    }

    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps.iter().any(|gap| gap["callee"] == "safe.stage"
            || gap["callee"] == "dangerous.stage"
            || gap["callee"] == "stage"),
        "typed member calls should resolve without unresolved-call gap noise: {gaps:#?}"
    );
}

#[test]
fn static_scan_resolves_cpp_overload_taint_calls_by_arity() {
    let root = temp_dir("cpp-overload-arity");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("overload.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid stage(std::string cmd, int mode) { (void)cmd; (void)mode; }\nvoid stage(std::string cmd) { std::system(cmd.c_str()); }\nclass Worker {\npublic:\n  void run(std::string cmd, int mode) { (void)cmd; (void)mode; }\n  void run(std::string cmd) { std::system(cmd.c_str()); }\n};\nvoid entry_a_safe(std::string input) {\n  stage(input, 0);\n}\nvoid entry_z_danger(std::string input) {\n  stage(input);\n}\nvoid member_a_safe(std::string input) {\n  Worker worker;\n  worker.run(input, 0);\n}\nvoid member_z_danger(std::string input) {\n  Worker worker;\n  worker.run(input);\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        2,
        "only the one-argument free-function and member overloads should be reachable from taint: {findings:#?}"
    );
    assert!(
        findings.iter().any(|finding| finding["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["kind"] == "call" && step["caller"] == "entry_z_danger")),
        "dangerous free-function overload trace should originate at entry_z_danger: {findings:#?}"
    );
    assert!(
        findings.iter().any(|finding| finding["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["kind"] == "call" && step["caller"] == "member_z_danger")),
        "dangerous member overload trace should originate at member_z_danger: {findings:#?}"
    );
    assert!(
        !findings.iter().any(|finding| finding["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["kind"] == "call"
                && matches!(
                    step["caller"].as_str(),
                    Some("entry_a_safe" | "member_a_safe")
                ))),
        "two-argument safe overloads must not flow into one-argument sinks: {findings:#?}"
    );
}

#[test]
fn static_scan_resolves_cpp_auto_constructed_member_taint_calls() {
    let root = temp_dir("cpp-auto-member-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("auto_member.cpp"),
        "#include <cstdlib>\n#include <string>\nclass Safe {\npublic:\n  void stage(std::string cmd) { (void)cmd; }\n};\nclass Dangerous {\npublic:\n  void stage(std::string cmd) { std::system(cmd.c_str()); }\n};\nvoid entry_safe(std::string input) {\n  auto safe = Safe{};\n  safe.stage(input);\n}\nvoid entry_danger(std::string input) {\n  auto dangerous = Dangerous{};\n  dangerous.stage(input);\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        1,
        "only auto-constructed Dangerous should be reachable: {findings:#?}"
    );
    let trace = findings[0]["analysis"]["trace"].as_array().unwrap();
    assert!(
        trace.iter().any(|step| {
            step["kind"] == "call"
                && step["caller"] == "entry_danger"
                && step["callee"] == "Dangerous::stage"
        }),
        "auto receiver should resolve to Dangerous::stage: {:#}",
        findings[0]
    );
    assert!(
        !trace
            .iter()
            .any(|step| step["kind"] == "call" && step["caller"] == "entry_safe"),
        "auto-constructed Safe must not flow into Dangerous::stage: {:#}",
        findings[0]
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "safe.stage" || gap["callee"] == "dangerous.stage"),
        "auto-constructed receivers should resolve without unresolved-call gaps: {gaps:#?}"
    );
}

#[test]
fn static_scan_resolves_cpp_initialized_object_member_taint_calls() {
    let root = temp_dir("cpp-initialized-member-callee");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("initialized_member.cpp"),
        "#include <cstdlib>\n#include <string>\nclass Safe {\npublic:\n  explicit Safe(int mode) { (void)mode; }\n  void stage(std::string cmd) { (void)cmd; }\n};\nclass Dangerous {\npublic:\n  Dangerous() = default;\n  void stage(std::string cmd) { std::system(cmd.c_str()); }\n};\nvoid entry_safe(std::string input) {\n  Safe safe(1);\n  safe.stage(input);\n}\nvoid entry_danger(std::string input) {\n  Dangerous dangerous{};\n  dangerous.stage(input);\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        1,
        "only initialized Dangerous should be reachable: {findings:#?}"
    );
    let trace = findings[0]["analysis"]["trace"].as_array().unwrap();
    assert!(
        trace.iter().any(|step| {
            step["kind"] == "call"
                && step["caller"] == "entry_danger"
                && step["callee"] == "Dangerous::stage"
        }),
        "initialized receiver should resolve to Dangerous::stage: {:#}",
        findings[0]
    );
    assert!(
        !trace
            .iter()
            .any(|step| step["kind"] == "call" && step["caller"] == "entry_safe"),
        "initialized Safe must not flow into Dangerous::stage: {:#}",
        findings[0]
    );
    let gaps = report["analysis_gaps"].as_array().unwrap();
    assert!(
        !gaps
            .iter()
            .any(|gap| gap["callee"] == "safe.stage" || gap["callee"] == "dangerous.stage"),
        "initialized receivers should resolve without unresolved-call gaps: {gaps:#?}"
    );
}

#[test]
fn static_scan_rule_pack_reports_seeded_findings_and_honors_policy() {
    let root = temp_dir("rule-pack");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("rules.c"),
        "#include <stdio.h>\n#include <stdlib.h>\nvoid path_rule(char *path) { fopen(path, \"r\"); }\nvoid env_rule(void) { getenv(\"HOME\"); }\nvoid int_rule(char *input) { atoi(input); }\nvoid fmt_rule(char *input) { printf(input); }\nvoid safe_fmt(char *input) { printf(\"%s\", input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("rules.cpp"),
        "#include <cstdio>\n#include <cstdlib>\nvoid fmt_rule(char *input) { std::printf(input); }\n",
    )
    .unwrap();
    // Seed the Ada hazard SITES (instantiations + a spawn), not the bare `with`
    // context clauses — an import is not a hazard and is no longer flagged.
    fs::write(
        src.join("rules.adb"),
        "with Ada.Command_Line;\nwith Ada.Unchecked_Conversion;\nwith Ada.Unchecked_Deallocation;\nwith GNAT.OS_Lib;\nprocedure Rules is\n   type Obj is null record;\n   type Obj_Access is access Obj;\n   function Conv is new Ada.Unchecked_Conversion (Integer, Float);\n   procedure Free is new Ada.Unchecked_Deallocation (Obj, Obj_Access);\n   task type Worker;\n   task body Worker is\n   begin\n      null;\n   end Worker;\nbegin\n   GNAT.OS_Lib.Spawn (Command);\nend Rules;\n",
    )
    .unwrap();
    fs::write(
        src.join("safe.adb"),
        "procedure Safe is\nbegin\n   null;\nend Safe;\n",
    )
    .unwrap();
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.policy.v1",
            "policy_id": "static-rules",
            "rules": {
                "disabled": ["GF-406"]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    for rule_id in [
        "GF-405", "GF-407", "GF-408", "GF-409", "GF-410", "GF-411", "GF-412",
    ] {
        assert!(
            !findings_by_rule(&report, rule_id).is_empty(),
            "expected seeded finding for {rule_id}: {report:#}"
        );
    }
    assert!(
        findings_by_rule(&report, "GF-406").is_empty(),
        "policy should disable environment rule GF-406"
    );
    assert_eq!(
        findings_by_rule(&report, "GF-408")
            .iter()
            .filter(|finding| finding["location"]["path"]
                .as_str()
                .unwrap()
                .ends_with("rules.c"))
            .count(),
        1,
        "safe printf with literal format must not be reported"
    );
    assert!(finding(&report, "GF-411", "safe.adb").is_none());
    assert!(finding(&report, "GF-412", "safe.adb").is_none());
}

#[test]
fn static_scan_reduces_format_and_taint_false_positives() {
    let root = temp_dir("precision");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("format.c"),
        "#include <stdio.h>\nvoid bad_fprintf(char *input) { fprintf(stderr, input); }\nvoid bad_snprintf(char *input, char *buf, unsigned long n) { snprintf(buf, n, input); }\nvoid safe_fprintf(char *input) { fprintf(stderr, \"%s\", input); }\nvoid safe_snprintf(char *input, char *buf, unsigned long n) { snprintf(buf, n, \"%s\", input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("taint.c"),
        "#include <stdlib.h>\nvoid stage(char *cmd) { system(cmd); }\nvoid literal(char *input) { system(\"date\"); }\nvoid wrapper(char *input) { stage(input); }\nvoid helper(const char *cmd) { system(cmd); }\nvoid unrelated(char *input) { helper(\"date\"); }\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let format_findings = findings_by_rule(&report, "GF-408");
    assert_eq!(
        format_findings.len(),
        2,
        "only nonliteral fprintf/snprintf format arguments should be reported: {format_findings:#?}"
    );
    assert!(format_findings
        .iter()
        .any(|finding| finding["evidence"][0]["snippet"]
            .as_str()
            .unwrap()
            .contains("bad_fprintf")));
    assert!(format_findings
        .iter()
        .any(|finding| finding["evidence"][0]["snippet"]
            .as_str()
            .unwrap()
            .contains("bad_snprintf")));

    let taint_findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        taint_findings.len(),
        1,
        "literal command sinks and unrelated constant calls should not be tainted: {taint_findings:#?}"
    );
    assert!(
        taint_findings[0]["analysis"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["callee"] == "stage"),
        "wrapper(input) -> stage(cmd) trace should be retained: {:#}",
        taint_findings[0]
    );
}

#[test]
fn static_scan_ignores_commented_out_rule_matches() {
    let root = temp_dir("commented-out-matches");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("comments.c"),
        "#include <stdlib.h>\nvoid c_safe(char *input, char *dst, char *src) {\n  // system(input);\n  /* strcpy(dst, src); */\n  /*\n    system(input);\n  */\n}\nvoid c_bad(char *input) { system(input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("comments.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid cpp_safe(std::string input) {\n  // std::system(input.c_str());\n  /* std::system(input.c_str()); */\n}\nvoid cpp_bad(std::string input) { std::system(input.c_str()); }\n",
    )
    .unwrap();
    fs::write(
        src.join("comments.adb"),
        "with GNAT.OS_Lib;\nprocedure Comments is\n   procedure Entry (Input : String) is\n   begin\n      -- GNAT.OS_Lib.Spawn (Input);\n      GNAT.OS_Lib.Spawn (Input);\n   end Entry;\nbegin\n   -- when others => null;\n   null;\nend Comments;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let taint_findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        taint_findings.len(),
        3,
        "only real C/C++/Ada command sinks should be reported: {taint_findings:#?}"
    );
    for finding in taint_findings {
        assert!(
            !finding["evidence"][0]["snippet"]
                .as_str()
                .unwrap()
                .trim_start()
                .starts_with("//")
                && !finding["evidence"][0]["snippet"]
                    .as_str()
                    .unwrap()
                    .contains("/*")
                && !finding["evidence"][0]["snippet"]
                    .as_str()
                    .unwrap()
                    .trim_start()
                    .starts_with("--"),
            "commented-out sinks must not appear as evidence: {finding:#}"
        );
    }
    assert!(
        findings_by_rule(&report, "GF-401").is_empty(),
        "commented-out unsafe string copies should be ignored: {report:#}"
    );
    assert!(
        findings_by_rule(&report, "GF-402").is_empty(),
        "commented-out Ada exception handlers should be ignored: {report:#}"
    );
}

#[test]
fn static_scan_preserves_matches_after_comment_tokens_inside_strings() {
    let root = temp_dir("comment-tokens-in-strings");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("strings.c"),
        "#include <stdlib.h>\nvoid c_bad(char *input) { const char *url = \"http://legacy.local\"; system(input); }\n",
    )
    .unwrap();
    fs::write(
        src.join("strings.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid cpp_bad(std::string input) { const char *url = \"http://legacy.local\"; std::system(input.c_str()); }\n",
    )
    .unwrap();
    fs::write(
        src.join("strings.adb"),
        "with GNAT.OS_Lib;\nprocedure Strings is\n   procedure Entry (Input : String) is\n   begin\n      declare S : constant String := \"--not-a-comment\"; begin GNAT.OS_Lib.Spawn (Input); end;\n   end Entry;\nbegin\n   null;\nend Strings;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        3,
        "comment-like tokens inside strings must not hide active Ada/C/C++ sinks: {findings:#?}"
    );
    for expected in ["strings.c", "strings.cpp", "strings.adb"] {
        assert!(
            findings.iter().any(|finding| finding["location"]["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(expected))),
            "missing active sink from {expected}: {findings:#?}"
        );
    }
}

#[test]
fn static_scan_preserves_triage_and_ci_gates_path_sensitive_findings() {
    let root = temp_dir("triage");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("blocked.c"),
        "#include <stdlib.h>\nvoid entry(char *input) {\n  if (0) system(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("unsafe.c"),
        "#include <string.h>\nvoid copy(char *dst, const char *src) { strcpy(dst, src); }\n",
    )
    .unwrap();
    let baseline = root.join("baseline.json");
    fs::write(
        &baseline,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.static.v1",
            "findings": [
                {
                    "fingerprint": "GF-304:blocked.c:3:command-injection",
                    "rule_id": "GF-304",
                    "path": "blocked.c",
                    "triage_state": "accepted_risk"
                },
                {
                    "fingerprint": "GF-401:old.c:1:unsafe-string-copy",
                    "rule_id": "GF-401",
                    "path": "old.c",
                    "triage_state": "fixed"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("static");
    let exit = cli::run_from([
        "govfuzz",
        "static-scan",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--sarif",
        "--fail-on",
        "high",
    ]);

    assert_eq!(
        exit, 1,
        "--fail-on high should trip on active high findings"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let blocked = finding(&report, "GF-304", "blocked.c").unwrap();
    assert_eq!(blocked["baseline_status"], "unchanged");
    assert_eq!(blocked["triage"]["state"], "accepted_risk");
    assert_eq!(blocked["confidence"], "low");
    assert_eq!(blocked["analysis"]["path"]["blocked"], true);
    assert_eq!(blocked["analysis"]["actionability"]["verdict"], "blocked");
    assert_eq!(report["baseline"]["resolved"][0]["triage_state"], "fixed");

    let markdown = fs::read_to_string(out.join("static-report.md")).unwrap();
    assert!(markdown.contains("# GovFuzz Static Scan"));
    assert!(markdown.contains("accepted_risk"));

    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.sarif")).unwrap()).unwrap();
    let result = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["ruleId"] == "GF-304")
        .unwrap();
    assert!(!result["relatedLocations"].as_array().unwrap().is_empty());
    assert_eq!(result["properties"]["triageState"], "accepted_risk");
}

#[test]
fn static_scan_maps_taint_to_callee_arguments_for_precision() {
    let root = temp_dir("arg-mapping");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("mapping.c"),
        "#include <stdlib.h>\nvoid stage(char *cmd, char *safe) { system(safe); }\nvoid run(char *cmd) { system(cmd); }\nvoid entry(char *input) { stage(input, \"date\"); run(input); }\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--sarif",
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        1,
        "stage(input, literal) must not taint stage.safe and report system(safe): {findings:#?}"
    );
    let finding = findings[0];
    assert_eq!(finding["analysis"]["precision"]["sink"], "system");
    assert_eq!(
        finding["analysis"]["precision"]["tainted_parameters"][0],
        "cmd"
    );
    assert_eq!(finding["analysis"]["precision"]["interprocedural_depth"], 1);
    assert_eq!(finding["analysis"]["precision"]["complete_trace"], true);

    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.sarif")).unwrap()).unwrap();
    let result = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["ruleId"] == "GF-304")
        .unwrap();
    assert_eq!(
        result["properties"]["analysis"]["precision"]["tainted_parameters"][0],
        "cmd"
    );
}

#[test]
fn static_scan_tracks_local_taint_aliases_across_ada_c_and_cpp() {
    let root = temp_dir("local-taint-aliases");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("alias.c"),
        "#include <stdlib.h>\nvoid entry(char *input) {\n  char *cmd = input;\n  system(cmd);\n  cmd = \"date\";\n  system(cmd);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("alias.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid entry(std::string input) {\n  std::string cmd = input;\n  std::system(cmd.c_str());\n  std::string safe = sanitize(input);\n  std::system(safe.c_str());\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("alias.adb"),
        "with GNAT.OS_Lib;\nprocedure Alias is\n   procedure Entry (Input : String) is\n      Cmd : String := Input;\n      Safe : String := \"date\";\n   begin\n      GNAT.OS_Lib.Spawn (Cmd);\n      GNAT.OS_Lib.Spawn (Safe);\n   end Entry;\nbegin\n   null;\nend Alias;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let findings = findings_by_rule(&report, "GF-304");
    assert_eq!(
        findings.len(),
        3,
        "local taint aliases should be reported once per language while constant/sanitized aliases stay quiet: {findings:#?}"
    );
    for path in ["alias.c", "alias.cpp", "alias.adb"] {
        let finding = finding(&report, "GF-304", path).unwrap();
        assert!(
            finding["analysis"]["trace"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["kind"] == "assignment" && step["callee"] == "cmd"),
            "{path} finding should include assignment trace: {finding:#}"
        );
        assert!(
            finding["analysis"]["precision"]["tainted_parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|param| param == "cmd"),
            "{path} finding should preserve local alias in precision metadata: {finding:#}"
        );
    }
}

#[test]
fn static_scan_does_not_report_call_arguments_as_unresolved_callees() {
    let root = temp_dir("unresolved-argument-noise");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("noise.c"),
        "#include <stdlib.h>\nvoid stage(char *cmd) { system(cmd); }\nvoid entry(char *input) {\n  stage(input);\n  missing_vendor(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("noise.cpp"),
        "#include <cstdlib>\n#include <string>\nvoid stage_cpp(std::string cmd) { std::system(cmd.c_str()); }\nvoid entry_cpp(std::string input) {\n  stage_cpp(input);\n  missing_cpp(input);\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("noise.adb"),
        "with GNAT.OS_Lib;\nprocedure Noise is\n   procedure Stage (Cmd : String) is\n   begin\n      GNAT.OS_Lib.Spawn (Cmd);\n   end Stage;\n   procedure Entry (Input : String) is\n   begin\n      Stage (Input);\n      Missing_Ada (Input);\n   end Entry;\nbegin\n   null;\nend Noise;\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let gaps = report["analysis_gaps"].as_array().unwrap();
    for expected in ["missing_vendor", "missing_cpp", "Missing_Ada"] {
        assert!(
            gaps.iter().any(|gap| gap["callee"] == expected),
            "expected real unresolved callee {expected}: {gaps:#?}"
        );
    }
    assert!(
        !gaps.iter().any(|gap| matches!(
            gap["callee"].as_str(),
            Some("input" | "Input" | "cmd" | "Cmd")
        )),
        "argument names should not be reported as unresolved callees: {gaps:#?}"
    );
}

#[test]
fn static_scan_marks_multiline_impossible_guarded_taint_as_blocked() {
    let root = temp_dir("multiline-guard");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("guard.c"),
        "#include <stdlib.h>\nvoid run(char *cmd) { system(cmd); }\nvoid blocked(char *input) {\n  if (false) {\n    run(input);\n  }\n}\n",
    )
    .unwrap();

    let out = root.join("static");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]),
        0
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("static-report.json")).unwrap()).unwrap();
    let finding = finding(&report, "GF-304", "guard.c").unwrap();
    assert_eq!(finding["confidence"], "low");
    assert_eq!(finding["analysis"]["path"]["blocked"], true);
    assert_eq!(
        finding["analysis"]["path"]["predicates"][0]["expression"],
        "if (false) {"
    );
    assert_eq!(finding["analysis"]["actionability"]["verdict"], "blocked");
}

fn finding<'a>(
    report: &'a serde_json::Value,
    rule_id: &str,
    path_suffix: &str,
) -> Option<&'a serde_json::Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| {
            finding["rule_id"] == rule_id
                && finding["location"]["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(path_suffix))
        })
}

fn findings_by_rule<'a>(
    report: &'a serde_json::Value,
    rule_id: &str,
) -> Vec<&'a serde_json::Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["rule_id"] == rule_id)
        .collect()
}

#[test]
fn static_scan_sloc_writes_text_table_and_json() {
    let root = temp_dir("sloc-flag");
    fs::write(root.join("a.py"), "def f():\n    # c\n    return 1\n\n").unwrap();
    fs::write(
        root.join("b.c"),
        "// hdr\nint main(void){\n    return 0;\n}\n",
    )
    .unwrap();
    // A dependency tree that must be excluded from the count.
    let dep = root.join("node_modules").join("pkg");
    fs::create_dir_all(&dep).unwrap();
    fs::write(dep.join("d.py"), "import sys\nx = 1\n").unwrap();

    // Text table.
    let table_path = root.join("sloc.txt");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            root.to_str().unwrap(),
            "--out",
            root.join("out").to_str().unwrap(),
            "--sloc",
            table_path.to_str().unwrap(),
        ]),
        0
    );
    let table = fs::read_to_string(&table_path).unwrap();
    assert!(table.contains("LANGUAGE"), "header: {table}");
    assert!(table.contains("SLOC"), "header: {table}");
    assert!(
        table.lines().last().unwrap().starts_with("TOTAL"),
        "totals row: {table}"
    );
    assert!(!table.contains("node_modules"));

    // JSON form, keyed off the .json extension.
    let json_path = root.join("sloc.json");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            root.to_str().unwrap(),
            "--out",
            root.join("out2").to_str().unwrap(),
            "--sloc",
            json_path.to_str().unwrap(),
        ]),
        0
    );
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "govfuzz.static.sloc.v1");
    let py = report["languages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["language"] == "python")
        .expect("python row");
    // Only the two project files, not the excluded dependency file.
    assert_eq!(py["files"], json!(1));
    assert_eq!(py["comment_lines"], json!(1));
    assert_eq!(py["blank_lines"], json!(1));
    assert_eq!(py["code_lines"], json!(2));
    assert_eq!(report["total"]["files"], json!(2));
}

#[test]
fn static_scan_relative_sloc_lands_in_out_dir_not_cwd() {
    let root = temp_dir("sloc-relative");
    fs::write(root.join("a.py"), "x = 1\n").unwrap();
    let out = root.join("report-out");
    // A bare, relative --sloc filename must resolve under --out, not the process
    // CWD (the bug: it was written relative to where the command was invoked).
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "static-scan",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--sloc",
            "sloc-file.txt",
        ]),
        0
    );
    assert!(
        out.join("sloc-file.txt").is_file(),
        "relative --sloc must land in --out"
    );
    assert!(
        !PathBuf::from("sloc-file.txt").exists(),
        "relative --sloc must not be written to CWD"
    );
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-static-scan-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
