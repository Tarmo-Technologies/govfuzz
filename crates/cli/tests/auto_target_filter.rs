// SPDX-License-Identifier: Apache-2.0

use cli::run_from;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn tempdir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-auto-target-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn read_run_json(work_dir: &Path) -> serde_json::Value {
    let run_json = work_dir.join("auto/run.json");
    let bytes = fs::read(&run_json).unwrap_or_else(|e| panic!("read {}: {e}", run_json.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {} as json: {e}", run_json.display()))
}

#[test]
fn auto_target_filter_attempts_only_matching_target_names() {
    let root = tempdir("filter");
    fs::write(
        root.join("targets.c"),
        r#"
int wrapper_target(const unsigned char *data, unsigned long len) {
    return data && len > 0 ? 1 : 0;
}

int support_target(const unsigned char *data, unsigned long len) {
    return data && len > 1 ? 1 : 0;
}
"#,
    )
    .expect("write C source");
    let work_dir = root.join("work");

    let exit = run_from([
        "govfuzz",
        "auto",
        root.to_str().expect("root path utf-8"),
        "--work-dir",
        work_dir.to_str().expect("work path utf-8"),
        "--per-target-time",
        "1",
        "--target",
        "wrapper_target",
    ]);

    assert_eq!(exit, 0);
    let run_json = read_run_json(&work_dir);
    assert_eq!(run_json["summary"]["discovered"], 1);
    let targets = run_json["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["name"], "wrapper_target");
}

#[test]
fn auto_target_file_filter_disambiguates_duplicate_names() {
    let root = tempdir("file-filter");
    fs::write(
        root.join("one.c"),
        r#"
int parse_packet(const unsigned char *data, unsigned long len) {
    return data && len > 0 ? 1 : 0;
}
"#,
    )
    .expect("write first C source");
    fs::write(
        root.join("two.c"),
        r#"
int parse_packet(const unsigned char *data, unsigned long len) {
    return data && len > 1 ? 2 : 0;
}
"#,
    )
    .expect("write second C source");
    let work_dir = root.join("work");

    let exit = run_from([
        "govfuzz",
        "auto",
        root.to_str().expect("root path utf-8"),
        "--work-dir",
        work_dir.to_str().expect("work path utf-8"),
        "--per-target-time",
        "1",
        "--target",
        "parse_packet",
        "--target-file",
        "one.c",
    ]);

    assert_eq!(exit, 0);
    let run_json = read_run_json(&work_dir);
    assert_eq!(run_json["summary"]["discovered"], 1);
    let targets = run_json["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["name"], "parse_packet");
    assert!(targets[0]["source"].as_str().unwrap().ends_with("/one.c"));
}

#[test]
fn auto_harness_id_filter_reruns_exact_candidate() {
    let root = tempdir("id-filter");
    fs::write(
        root.join("targets.c"),
        r#"
int first_target(const unsigned char *data, unsigned long len) {
    return data && len > 0 ? 1 : 0;
}

int second_target(const unsigned char *data, unsigned long len) {
    return data && len > 1 ? 2 : 0;
}
"#,
    )
    .expect("write C source");
    let selected = cli::auto::discovery::discover(&root)
        .expect("discover fixture targets")
        .into_iter()
        .find(|candidate| candidate.name == "second_target")
        .expect("second target discovered");
    let work_dir = root.join("work");

    let exit = run_from([
        "govfuzz",
        "auto",
        root.to_str().expect("root path utf-8"),
        "--work-dir",
        work_dir.to_str().expect("work path utf-8"),
        "--per-target-time",
        "1",
        "--harness-id",
        selected.harness_id.as_str(),
    ]);

    assert_eq!(exit, 0);
    let run_json = read_run_json(&work_dir);
    assert_eq!(run_json["summary"]["discovered"], 1);
    let targets = run_json["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["name"], "second_target");
    assert_eq!(targets[0]["harness_id"], selected.harness_id);
}

#[test]
fn auto_exclude_path_filters_candidates_before_attempts() {
    let root = tempdir("exclude-path");
    fs::create_dir(root.join("src")).expect("create src");
    fs::create_dir(root.join("tests")).expect("create tests");
    fs::write(
        root.join("src").join("packet.c"),
        r#"
int production_target(const unsigned char *data, unsigned long len) {
    return data && len > 0 ? 1 : 0;
}
"#,
    )
    .expect("write production C source");
    fs::write(
        root.join("tests").join("packet_test.c"),
        r#"
int test_only_target(const unsigned char *data, unsigned long len) {
    return data && len > 1 ? 2 : 0;
}
"#,
    )
    .expect("write test C source");
    let work_dir = root.join("work");

    let exit = run_from([
        "govfuzz",
        "auto",
        root.to_str().expect("root path utf-8"),
        "--work-dir",
        work_dir.to_str().expect("work path utf-8"),
        "--per-target-time",
        "1",
        "--exclude-path",
        "tests",
    ]);

    assert_eq!(exit, 0);
    let run_json = read_run_json(&work_dir);
    assert_eq!(run_json["summary"]["discovered"], 1);
    let targets = run_json["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["name"], "production_target");
    assert!(targets[0]["source"]
        .as_str()
        .unwrap()
        .ends_with("/src/packet.c"));
}

#[test]
fn auto_exclude_category_filters_common_project_areas() {
    let root = tempdir("exclude-category");
    for child in ["src", "tools", "examples"] {
        fs::create_dir(root.join(child)).unwrap_or_else(|e| panic!("create {child}: {e}"));
    }
    fs::write(
        root.join("src").join("packet.c"),
        r#"
int production_target(const unsigned char *data, unsigned long len) {
    return data && len > 0 ? 1 : 0;
}
"#,
    )
    .expect("write production C source");
    fs::write(
        root.join("tools").join("tool.c"),
        r#"
int tool_target(const unsigned char *data, unsigned long len) {
    return data && len > 1 ? 2 : 0;
}
"#,
    )
    .expect("write tool C source");
    fs::write(
        root.join("examples").join("demo.c"),
        r#"
int example_target(const unsigned char *data, unsigned long len) {
    return data && len > 2 ? 3 : 0;
}
"#,
    )
    .expect("write example C source");
    let work_dir = root.join("work");

    let exit = run_from([
        "govfuzz",
        "auto",
        root.to_str().expect("root path utf-8"),
        "--work-dir",
        work_dir.to_str().expect("work path utf-8"),
        "--per-target-time",
        "1",
        "--exclude",
        "tools,examples",
    ]);

    assert_eq!(exit, 0);
    let run_json = read_run_json(&work_dir);
    assert_eq!(run_json["summary"]["discovered"], 1);
    let targets = run_json["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["name"], "production_target");
    assert!(targets[0]["source"]
        .as_str()
        .unwrap()
        .ends_with("/src/packet.c"));
}
