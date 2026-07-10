// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for the C++ harness-generation gaps closed in ROADMAP
//! §26.6 / §27.4 / §27.5: a float/double method, an abstract receiver built via a
//! ctor-arg subclass, an abstract receiver built via a factory, and an
//! instantiated template function. Each fixture plants a reachable ASan
//! buffer-overflow that is ONLY reachable through the newly-supported construction
//! path, so a `built_and_fuzzed` outcome + a finding proves the emitted harness
//! both COMPILES with clang++ and actually drives the target.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

/// True when this host can build a C++ sanitizer target the way `govfuzz auto`
/// does (clang++ + a discoverable libstdc++). Mirrors the amalgamation suite:
/// when true, a failed build is a real regression, not a toolchain gap.
fn cpp_toolchain_capable() -> bool {
    let clang = Command::new("clang++")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let libstdcxx = support::libstdcxx_search_path_from_dirs(
        [
            "/usr/lib/gcc/x86_64-linux-gnu/14",
            "/usr/lib/gcc/x86_64-linux-gnu/13",
            "/usr/lib/gcc/x86_64-linux-gnu/12",
            "/usr/lib/gcc/aarch64-linux-gnu/14",
            "/usr/lib/gcc/aarch64-linux-gnu/13",
            "/usr/lib/gcc/aarch64-linux-gnu/12",
        ]
        .into_iter()
        .map(Path::new),
    )
    .is_some();
    clang && libstdcxx
}

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-cpp-gap-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn run_auto(root: &Path, per_target_time: &str) -> std::process::ExitStatus {
    support::govfuzz_cargo_command()
        .current_dir(root)
        .args(["auto", "src", "--per-target-time", per_target_time])
        .status()
        .expect("run govfuzz auto")
}

fn read_run_json(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap()).unwrap()
}

/// A `built_and_fuzzed` target whose `name` contains `needle`, or a panic listing
/// every target so a regression names what actually happened.
fn built_target_named(run_json: &serde_json::Value, needle: &str) -> serde_json::Value {
    let targets = run_json["targets"].as_array().expect("targets array");
    targets
        .iter()
        .find(|t| {
            t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")
                && t["name"].as_str().is_some_and(|n| n.contains(needle))
        })
        .cloned()
        .unwrap_or_else(|| {
            let summary: Vec<String> = targets
                .iter()
                .map(|t| {
                    format!(
                        "{}={}",
                        t["name"].as_str().unwrap_or("?"),
                        t["outcome"]["outcome"].as_str().unwrap_or("?")
                    )
                })
                .collect();
            panic!("no built_and_fuzzed target matching '{needle}'; targets: {summary:?}");
        })
}

fn write_src(root: &Path, file: &str, body: &str) {
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join(file), body).unwrap();
}

// §26.6: a class method taking `double` + `float` (plus a string the OOB rides on)
// — both were skipped "unsupported parameter type" before the decode fix.
const FLOAT_DOUBLE_METHOD: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <cstddef>
class Meter {
public:
    int last = 0;
    int record(double value, float weight, const std::string &tag) {
        char buf[4];
        for (std::size_t i = 0; i < tag.size(); ++i) buf[i] = tag[i]; // OOB when tag.size() > 4
        last = (int)value + (int)weight + buf[0];
        return last;
    }
};
"#;

// §27.4a: a method on an abstract `Reader` whose only concrete subclass needs a
// CONSTRUCTOR ARGUMENT (no default ctor) — resolved + constructed with a decoded
// arg, so the virtual call dispatches to the override.
const ABSTRACT_CTOR_ARGS: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <cstddef>
class Reader {
public:
    virtual ~Reader() {}
    virtual int decode(const std::string &s) = 0;
    int decode_checked(const std::string &s) {
        return s.empty() ? -1 : decode(s);
    }
};
class BufferReader : public Reader {
public:
    explicit BufferReader(int base) : base_(base) {}
    int decode(const std::string &s) override {
        char buf[4];
        for (std::size_t i = 0; i < s.size(); ++i) buf[i] = s[i]; // OOB when s.size() > 4
        return base_ + buf[0];
    }
private:
    int base_;
};
"#;

// §27.4b: a method on an abstract `Codec` with NO constructible subclass (the
// concrete impl has a private ctor) — built through a FACTORY returning `Codec *`.
const ABSTRACT_FACTORY: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <cstddef>
class Codec {
public:
    virtual ~Codec() {}
    virtual int run(const std::string &s) = 0;
    int run_checked(const std::string &s) {
        return s.empty() ? -1 : run(s);
    }
};
class RealCodec : public Codec {
    explicit RealCodec(int variant) : variant_(variant) {} // private: not constructible directly
    int variant_;
public:
    int run(const std::string &s) override {
        char buf[4];
        for (std::size_t i = 0; i < s.size(); ++i) buf[i] = s[i]; // OOB when s.size() > 4
        return variant_ + buf[0];
    }
    friend Codec *make_codec(int);
};
Codec *make_codec(int variant) {
    static RealCodec instance(0); // function-static: no per-input leak
    (void)variant;
    return &instance;
}
"#;

// §27.5: a free templated function with a SAME-FILE call-site instantiation
// (`fold_as<int>`) — surfaced and harnessed with a turbofish call.
const TEMPLATE_INSTANTIATION: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <vector>
#include <cstddef>
template <typename T>
T fold_as(const std::vector<unsigned char> &data) {
    char buf[4];
    for (std::size_t i = 0; i < data.size(); ++i) buf[i] = (char)data[i]; // OOB when size > 4
    T acc = T();
    for (std::size_t i = 0; i < data.size(); ++i) acc = (T)(acc + data[i]);
    return (T)(acc + buf[0]);
}
int force_instantiation(const std::vector<unsigned char> &d) { return fold_as<int>(d); }
"#;

// Campaign (cpptoml): a header-only library whose header uses
// `std::numeric_limits<long>` / `std::size_t` at file scope WITHOUT including its
// own `<limits>`/`<cstddef>` — it relies on a transitive standard include a
// normal consumer happens to have pulled in first (exactly cpptoml.h:344). The
// generated harness compiles this header in a minimal translation unit, so
// before the defensive C++ stdlib prelude every target failed to build with
// "implicit instantiation of undefined template 'std::numeric_limits<long>'".
// The prelude restores the build, so the planted stack overflow in `parse_value`
// becomes reachable — `built_and_fuzzed` + a finding proves the fix.
const HEADER_ONLY_NUMERIC_LIMITS: &str = r#"// SPDX-License-Identifier: Apache-2.0
#ifndef CPPTOML_LIKE_HPP
#define CPPTOML_LIKE_HPP
#include <string>

namespace cpptoml_like {

// File-scope numeric_limits use — the shape of cpptoml.h:344. Needs <limits>,
// which this header deliberately does NOT include.
inline long clamp_long(long v) {
    const long hi = std::numeric_limits<long>::max();
    const long lo = std::numeric_limits<long>::min();
    return v > hi ? hi : (v < lo ? lo : v);
}

// Fuzz target: copies the untrusted string into a fixed 4-byte buffer (a planted
// stack overflow when the input exceeds 4 bytes) and folds in the
// numeric_limits-derived bound so the header genuinely requires <limits>. The
// std::size_t loop index relies on a transitive <cstddef> the header also omits.
inline long parse_value(const std::string &s) {
    char buf[4];
    for (std::size_t i = 0; i < s.size(); ++i) buf[i] = s[i]; // OOB when s.size() > 4
    return clamp_long((long)buf[0]);
}

} // namespace cpptoml_like
#endif
"#;

// Campaign (taocpp-json): a method taking const-qualified BY-VALUE scalars
// (`const bool`, `const double`, `const int`, `const std::size_t`). Each was
// reported "unsupported parameter type 'const bool'/'const double'" and the
// target was skipped, because the decoder did not strip a top-level const from a
// by-value param. A const on a by-value parameter is meaningless to the caller —
// it must decode exactly like its bare base type — so the target now builds and
// fuzzes. The planted stack overflow rides on the `const std::string &` tag, so a
// `built_and_fuzzed` outcome + a finding proves the harness COMPILED with clang++
// (all params decoded) AND drove the target.
const CONST_BY_VALUE_SCALARS: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <cstddef>
class Config {
public:
    int total = 0;
    int apply(const bool enabled, const double weight, const int count,
              const std::size_t limit, const std::string &tag) {
        char buf[4];
        for (std::size_t i = 0; i < tag.size(); ++i) buf[i] = tag[i]; // OOB when tag.size() > 4
        total = (enabled ? 1 : 0) + (int)weight + count + (int)limit + buf[0];
        return total;
    }
};
"#;

fn assert_built_and_found(root: &Path, target_needle: &str) {
    let status = run_auto(root, "8");
    assert!(status.success() || status.code() == Some(1));
    let run_json = read_run_json(root);
    let built = built_target_named(&run_json, target_needle);
    let passes = built["outcome"]["passes"].as_array().expect("passes array");
    let executed = passes
        .iter()
        .filter_map(|p| p["executions"].as_u64())
        .sum::<u64>();
    assert!(
        executed > 0,
        "target '{target_needle}' must actually execute: {built}"
    );
    let findings = run_json["summary"]["findings"].as_u64().unwrap_or(0);
    assert!(
        findings > 0,
        "the planted OOB reachable only through '{target_needle}' must be found: {run_json}"
    );
}

#[test]
fn cpp_float_double_method_builds_and_fuzzes() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("floatdouble");
    write_src(&root, "meter.cpp", FLOAT_DOUBLE_METHOD);
    assert_built_and_found(&root, "record");
}

#[test]
fn cpp_abstract_receiver_via_ctor_arg_subclass_builds_and_fuzzes() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("ctorargs");
    write_src(&root, "reader.cpp", ABSTRACT_CTOR_ARGS);
    assert_built_and_found(&root, "decode_checked");
}

#[test]
fn cpp_abstract_receiver_via_factory_builds_and_fuzzes() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("factory");
    write_src(&root, "codec.cpp", ABSTRACT_FACTORY);
    assert_built_and_found(&root, "run_checked");
}

#[test]
fn cpp_template_instantiation_builds_and_fuzzes() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("template");
    write_src(&root, "tmpl.cpp", TEMPLATE_INSTANTIATION);
    assert_built_and_found(&root, "fold_as");
}

// Campaign (cpptoml): the defensive C++ stdlib prelude lets a header-only library
// that reaches for `std::numeric_limits` / `std::size_t` without its own
// `<limits>`/`<cstddef>` compile in the harness's minimal translation unit.
#[test]
fn cpp_header_only_numeric_limits_builds_and_fuzzes() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("numlimits");
    write_src(&root, "cpptoml_like.hpp", HEADER_ONLY_NUMERIC_LIMITS);
    assert_built_and_found(&root, "parse_value");
}

// Campaign (taocpp-json): const-qualified BY-VALUE scalar params (`const bool`,
// `const double`, `const int`, `const std::size_t`) must decode like their bare
// base types instead of being skipped "unsupported parameter type".
#[test]
fn cpp_const_by_value_scalar_params_build_and_fuzz() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("constbyval");
    write_src(&root, "config.cpp", CONST_BY_VALUE_SCALARS);
    assert_built_and_found(&root, "apply");
}

// §27.5 phase 3: `--template-instantiate` steers a templated target that has NO
// observed call-site instantiation. This is a codegen assertion (no toolchain):
// the emitted harness must carry the turbofish call with the supplied type arg.
#[test]
fn template_instantiate_flag_steers_codegen() {
    let dir = tmpdir("flag");
    // An implementation file holding ONLY the template definition, with no call
    // site — so the parser resolves no instantiation and the flag must steer it.
    let src = dir.join("convert.cpp");
    fs::write(
        &src,
        "// SPDX-License-Identifier: Apache-2.0\n\
         #include <string>\n\
         template <typename T> T convert(const std::string &s) { (void)s; return T(); }\n",
    )
    .unwrap();
    let out = dir.join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args([
            "generate-harness",
            "--target",
            "convert",
            "--template-instantiate",
            "int",
            "--output",
            out.to_str().unwrap(),
            "--id",
            "H-TPLFLAG",
            src.to_str().unwrap(),
        ])
        .status()
        .expect("run generate-harness");
    assert!(
        status.success(),
        "generate-harness with --template-instantiate must succeed"
    );
    let main_cpp = fs::read_to_string(out.join("H-TPLFLAG/main.cpp")).expect("main.cpp emitted");
    assert!(
        main_cpp.contains("convert<int>("),
        "flag-steered template must emit a turbofish call:\n{main_cpp}"
    );
    assert!(
        main_cpp.contains("int R = convert<int>("),
        "the `T` result type must be specialised to `int`:\n{main_cpp}"
    );
}
