// SPDX-License-Identifier: Apache-2.0

//! Construction recipes used to be resolved one level deep: a constructor was
//! usable only when EVERY argument could be decoded straight from fuzz bytes. So
//! `Parser(Config)` was rejected however buildable a `Config` was, because a
//! `Config` is not a byte-decodable type.
//!
//! The decoder always knew how to recurse; what was missing was a recipe for
//! anything but the target's direct parameters, so the recursion had nothing to
//! find.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-producer-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// `Parser` needs a `Config`, and a `Config` needs an `int`. Only the innermost
/// value comes from bytes; the two objects above it have to be produced.
const CHAINED: &str = "\
class Config {
public:
    explicit Config(int scale) : scale_(scale) {}
    int scale() const { return scale_; }
private:
    int scale_;
};

class Parser {
public:
    explicit Parser(Config cfg) : cfg_(cfg) {}
    int run(const unsigned char *d, unsigned long n) const {
        int total = 0;
        for (unsigned long i = 0; i < n; i++) { total += d[i] * cfg_.scale(); }
        return total;
    }
private:
    Config cfg_;
};

int parse_with(Parser p, const unsigned char *d, unsigned long n) { return p.run(d, n); }
";

/// The same shape, except the innermost type cannot be obtained at all: its
/// constructor is private and there is no factory. The chain must not be
/// completed by inventing something.
const UNREACHABLE: &str = "\
class Secret {
public:
    int scale() const { return scale_; }
private:
    explicit Secret(int scale) : scale_(scale) {}
    int scale_;
};

class Parser {
public:
    explicit Parser(Secret s) : s_(s) {}
    int run(const unsigned char *d, unsigned long n) const {
        int total = 0;
        for (unsigned long i = 0; i < n; i++) { total += d[i] * s_.scale(); }
        return total;
    }
private:
    Secret s_;
};

int parse_with(Parser p, const unsigned char *d, unsigned long n) { return p.run(d, n); }
";

fn run_fixture(prefix: &str, lib: &str) -> (String, String) {
    let root = tmpdir(prefix);
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("lib.cpp"), lib).unwrap();
    let work = root.join("work");

    let output = support::govfuzz_cargo_command()
        .current_dir(&root)
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
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let outcome = outcome_of(&work, "parse_with");
    let harness = harness_containing(&work, "parse_with").unwrap_or_default();
    (format!("{outcome}\u{1}{harness}"), stderr)
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

fn harness_containing(work: &Path, needle: &str) -> Option<String> {
    fs::read_dir(work.join("harnesses"))
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("main.cpp"))
        .filter_map(|main| fs::read_to_string(main).ok())
        .find(|text| text.contains(needle))
}

#[test]
fn a_parameter_reachable_only_through_another_object_is_built() {
    if !support::libfuzzer_toolchain_available("producer-chain") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    let (result, stderr) = run_fixture("chain", CHAINED);
    let (outcome, harness) = result.split_once('\u{1}').unwrap();

    assert_ne!(
        outcome, "unsupported_params",
        "Parser is reachable via Config, which is reachable from bytes; \
         stderr=\n{stderr}"
    );
    assert!(
        harness.contains("Parser p("),
        "the harness must construct the parameter:\n{harness}"
    );
    assert!(
        harness.contains("Config "),
        "and it must construct the intermediate object the constructor needs:\n{harness}"
    );
    // The innermost value comes from the fuzzer, not from a constant: a chain
    // built entirely out of hardcoded values would fuzz nothing.
    assert!(
        harness.contains("gf_i32("),
        "the leaf of the chain must still be decoded from input bytes:\n{harness}"
    );
}

#[test]
fn a_chain_whose_leaf_cannot_be_obtained_is_still_refused() {
    if !support::libfuzzer_toolchain_available("producer-unreachable") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    let (result, stderr) = run_fixture("unreachable", UNREACHABLE);
    let (outcome, _) = result.split_once('\u{1}').unwrap();

    assert_eq!(
        outcome, "unsupported_params",
        "nothing can produce a Secret, so the chain above it must not be \
         reported as buildable; stderr=\n{stderr}"
    );
}
