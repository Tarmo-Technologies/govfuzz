// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz: a missing external Ada library whose GENERIC is instantiated by the
//! project. `Genapp.Options` instantiates `Vendorgen.Opt.Parse_Option` twice with
//! different `Arg_Type` actuals, and `Genapp.Score` reads a value back through each
//! instance.
//!
//! A generic cannot be stubbed like a plain package: Ada checks the actual list
//! against the formal part, so every formal's KIND has to match (a type actual needs
//! a formal type, `Convert => Genapp.To_Label` needs a formal subprogram, and
//! `Short => "-l"` needs a formal object). The stub model infers the formal names
//! from the named associations and the kinds from the client's own declarations,
//! widens the formal type when GNAT rejects an indefinite actual, and types the
//! entity reached through the instances by the FORMAL — which is the only thing that
//! satisfies both instantiations at once.
//!
//! Without `--force` the missing library cannot be stubbed at all. With it, the
//! driveable `Score (String)` target reaches `built_and_fuzzed`.
//!
//! Gated on the Ada toolchain; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn have_ada_toolchain() -> bool {
    which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok()
}

fn walk(dir: &Path) -> String {
    let mut out = String::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            out.push_str(&format!("{}\n", p.display()));
            if p.is_dir() {
                out.push_str(&walk(&p));
            }
        }
    }
    out
}

fn run_auto(force: bool) -> serde_json::Value {
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_generic_lib");

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-ada-generic-")
        .tempdir()
        .expect("tempdir");
    let work_dir = tmp.path().join("auto_work");

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    cmd.arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(&work_dir);
    if force {
        cmd.arg("--force");
    }
    cmd.arg("--languages")
        .arg("ada")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache");

    let output = cmd.output().expect("spawn govfuzz auto");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        let listing = walk(&work_dir);
        panic!(
            "read {}: {e}; work_dir tree:\n{listing}\nstdout=\n{stdout}\nstderr=\n{stderr}",
            run_json.display()
        )
    });
    serde_json::from_str(&raw).expect("parse run.json")
}

/// The outcome of the driveable `Score` target.
fn score_outcome(doc: &serde_json::Value) -> String {
    let targets = doc["targets"].as_array().expect("targets array");
    let target = targets
        .iter()
        .find(|t| {
            t["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case("Score"))
        })
        .unwrap_or_else(|| panic!("no Score target discovered; run.json=\n{doc}"));
    target["outcome"]["outcome"]
        .as_str()
        .expect("outcome tag")
        .to_owned()
}

#[test]
fn an_instantiated_missing_generic_does_not_build_fuzz_without_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(false);
    assert_ne!(
        score_outcome(&doc),
        "built_and_fuzzed",
        "without --force the missing external library must NOT build+fuzz; \
         run.json=\n{doc}"
    );
}

#[test]
fn an_instantiated_missing_generic_builds_and_fuzzes_under_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(true);
    assert_eq!(
        score_outcome(&doc),
        "built_and_fuzzed",
        "with --force the stub model must synthesize the missing generic (formals \
         inferred from the actuals) and type the instance-reached entity by the \
         formal so BOTH instantiations compile; run.json=\n{doc}"
    );
}
