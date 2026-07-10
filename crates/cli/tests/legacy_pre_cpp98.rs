// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 5: pre-C++98 / cfront-ARM "C with classes" — code using the
//! pre-standard `.h` iostream headers (`<iostream.h>`, `<strstream>`) that no
//! modern compiler accepts. It cannot be fuzzed end-to-end, so it is flagged
//! with the pre-C++98 dialect and reported on (discovered + statically analyzed
//! with CWE findings) rather than silently dropped.
//!
//! (Perl 4 is handled by the existing Perl 5 lane — Perl 5 is backward-compatible
//! and runs most Perl 4 — so it fuzzes there rather than taking this path.)

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use cli::auto::report_only::emit_report_only;
use std::fs;
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("govfuzz-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

const PRE98_SRC: &str = "\
#include <iostream.h>   // pre-standard: removed in C++98
#include <string.h>

int parse_buffer(const char* data, int len)
{
    char tmp[64];
    strcpy(tmp, data);   // GF-401: unbounded copy
    cout << tmp << endl; // pre-standard unqualified cout
    return len;
}
";

#[test]
fn pre_cpp98_file_is_discovered_with_pre98_dialect() {
    let dir = tmp("pre98-disc");
    fs::write(dir.join("legacy.cpp"), PRE98_SRC).unwrap();

    let candidates = discover(&dir).expect("discover pre-C++98 tree");
    let cpp = candidates
        .iter()
        .find(|c| c.lang == Lang::Cpp && c.name == "parse_buffer")
        .expect("the pre-C++98 function must be discovered");
    assert_eq!(
        cpp.dialect.map(|d| d.as_str()),
        Some("cpp_pre98"),
        "pre-standard iostream header must flag the pre-C++98 dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn pre_cpp98_report_only_emits_cwe_finding() {
    let dir = tmp("pre98-ro");
    fs::write(dir.join("legacy.cpp"), PRE98_SRC).unwrap();

    let candidates = discover(&dir).expect("discover pre-C++98 tree");
    let cpp = candidates
        .iter()
        .find(|c| c.lang == Lang::Cpp && c.name == "parse_buffer")
        .expect("pre-C++98 function discovered");

    let work = tmp("pre98-work");
    let outcome = emit_report_only(cpp, "pre-C++98 (test)".to_owned(), &work);
    let count = match &outcome {
        cli::auto::attempt::Outcome::ReportOnly {
            static_findings, ..
        } => *static_findings,
        other => panic!("expected ReportOnly, got {other:?}"),
    };
    assert!(count >= 1, "GF-401 strcpy must produce a static finding");

    let mut saw_cwe = false;
    for entry in fs::read_dir(work.join("findings")).unwrap() {
        let fj = entry.unwrap().path().join("finding.json");
        if !fj.exists() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&fj).unwrap()).unwrap();
        assert!(
            !v["actionability"]["cwe"].as_array().unwrap().is_empty(),
            "report-only pre-C++98 finding must carry a CWE"
        );
        saw_cwe = true;
    }
    assert!(saw_cwe);

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&work);
}
