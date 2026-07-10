// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 3: K&R / pre-ANSI C is discovered via the tolerant extractor
//! (the modern tree-sitter-c grammar cannot represent old-style untyped
//! parameter lists), tagged with the K&R dialect, and — having no fuzzing lane
//! that auto-builds it yet — reported on: discovered + statically analyzed with
//! CWE-tagged findings, instead of silently dropped.

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

const KNR_SRC: &str = "\
/* legacy K&R / pre-ANSI C */
int copy_into(dst, src)
    char *dst;
    char *src;
{
    strcpy(dst, src);   /* GF-401: unbounded copy */
    return 0;
}
";

#[test]
fn knr_function_is_discovered_with_knr_dialect() {
    let dir = tmp("knr-disc");
    fs::write(dir.join("legacy.c"), KNR_SRC).unwrap();

    let candidates = discover(&dir).expect("discover K&R tree");
    let knr = candidates
        .iter()
        .find(|c| c.lang == Lang::C && c.name == "copy_into")
        .expect("the K&R function must be discovered by the tolerant extractor");
    assert_eq!(
        knr.dialect.map(|d| d.as_str()),
        Some("c_knr"),
        "discovered K&R target must carry the K&R dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn knr_target_report_only_emits_cwe_finding() {
    let dir = tmp("knr-ro");
    fs::write(dir.join("legacy.c"), KNR_SRC).unwrap();

    let candidates = discover(&dir).expect("discover K&R tree");
    let knr = candidates
        .iter()
        .find(|c| c.lang == Lang::C && c.name == "copy_into")
        .expect("K&R function discovered");

    let work = tmp("knr-work");
    let outcome = emit_report_only(knr, "K&R C (test)".to_owned(), &work);
    let count = match &outcome {
        cli::auto::attempt::Outcome::ReportOnly {
            static_findings, ..
        } => *static_findings,
        other => panic!("expected ReportOnly, got {other:?}"),
    };
    // GF-401 (strcpy) is a substring rule, so it fires even on K&R source.
    assert!(count >= 1, "expected >=1 static finding on the K&R source");

    let mut saw_cwe = false;
    for entry in fs::read_dir(work.join("findings")).unwrap() {
        let fj = entry.unwrap().path().join("finding.json");
        if !fj.exists() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&fj).unwrap()).unwrap();
        let cwe = v["actionability"]["cwe"].as_array().unwrap();
        assert!(!cwe.is_empty(), "report-only K&R finding must carry a CWE");
        saw_cwe = true;
    }
    assert!(saw_cwe, "expected a finding.json on disk");

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&work);
}
