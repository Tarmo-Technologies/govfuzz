// SPDX-License-Identifier: Apache-2.0

//! A class with no usable public constructor and no zero-argument factory is an
//! unbuildable parameter, and the target is skipped. But the project's own tests
//! usually show how to build it, and those directories are skipped as fuzz
//! TARGETS — not as evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-mined-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// `Config`'s constructor is private and its factory takes an ARGUMENT, so
/// neither existing strategy applies: the constructor recipe needs a public
/// constructor, and the factory recipe only accepts a zero-argument one. The
/// only way to learn how to build this is to read code that already does.
const LIB: &str = "\
class Config {
public:
    static Config make(int scale) { return Config(scale); }
    int scale() const { return scale_; }
private:
    explicit Config(int scale) : scale_(scale) {}
    int scale_;
};

int apply_config(Config cfg, const unsigned char *d, unsigned long n) {
    int total = 0;
    for (unsigned long i = 0; i < n; i++) { total += d[i] * cfg.scale(); }
    return total;
}
";

fn setup(prefix: &str, with_example: bool) -> (PathBuf, PathBuf, PathBuf) {
    let root = tmpdir(prefix);
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("lib.cpp"), LIB).unwrap();
    if with_example {
        let tests = src.join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("config_test.cpp"),
            "void check() {\n\
             \x20   Config cfg = Config::make(3);\n\
             \x20   (void)cfg;\n\
             }\n",
        )
        .unwrap();
    }
    let work = root.join("work");
    (root, src, work)
}

fn run(root: &Path, src: &Path, work: &Path) -> String {
    let output = support::govfuzz_cargo_command()
        .current_dir(root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            "--languages",
            "cpp",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn outcome_of(work: &Path, name: &str) -> String {
    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|target| target["name"].as_str().is_some_and(|n| n.contains(name)))
        .map(|target| {
            target["outcome"]["outcome"]
                .as_str()
                .unwrap_or("<none>")
                .to_owned()
        })
        .unwrap_or_else(|| format!("<no target named {name}>"))
}

#[test]
fn with_no_example_anywhere_the_parameter_is_genuinely_unbuildable() {
    if !support::libfuzzer_toolchain_available("mined-none") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    let (root, src, work) = setup("no-example", false);
    let stderr = run(&root, &src, &work);

    assert_eq!(
        outcome_of(&work, "apply_config"),
        "unsupported_params",
        "nothing in the project says how to build a Config, so the parameter \
         cannot be driven; stderr=\n{stderr}"
    );
}

#[test]
fn a_construction_written_in_the_projects_tests_is_used_to_build_the_parameter() {
    if !support::libfuzzer_toolchain_available("mined-recipe") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    let (root, src, work) = setup("with-example", true);
    let stderr = run(&root, &src, &work);

    // The parameter is no longer skipped as undriveable — the difference from
    // the test above is only the example file.
    assert_ne!(
        outcome_of(&work, "apply_config"),
        "unsupported_params",
        "the test tree shows how to build a Config, so the parameter must no \
         longer be treated as undriveable; stderr=\n{stderr}"
    );

    // And the mined construction is what the harness actually emits.
    let harness = fs::read_dir(work.join("harnesses"))
        .expect("harnesses dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("main.cpp"))
        .filter_map(|main| fs::read_to_string(main).ok())
        .find(|text| text.contains("apply_config("))
        .expect("a harness was generated for the target");
    assert!(
        harness.contains("Config::make(3)"),
        "the harness must build the parameter the way the project's own example \
         does:\n{harness}"
    );

    // The example file is evidence, never a target.
    let run_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(work.join("auto/run.json")).unwrap()).unwrap();
    let sources: Vec<String> = run_json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["source"].as_str().map(str::to_owned))
        .collect();
    assert!(
        !sources.iter().any(|s| s.contains("config_test.cpp")),
        "a recipe source must never become a fuzz target: {sources:?}"
    );
}
