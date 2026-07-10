// SPDX-License-Identifier: Apache-2.0
//! M23 static-scanner precision benchmark (#485).
//!
//! Scores the static ruleset against a labeled corpus (`benchmarks/static/`):
//! each corpus line carries an inline `EXPECT GF-NNN` annotation where a finding
//! is expected; every other line must stay clean. Computes precision / recall /
//! false-positive count per rule and per language, writes `results.tsv`, and
//! GATES the suite on an overall precision floor — a new/edited rule that drops
//! precision below the floor fails CI. This is the number that makes "best" a
//! measurable claim rather than a marketing line. Seed corpus is govfuzz-authored
//! (license-clean); expanding it with a permissive Juliet subset is future work.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Precision floor the whole ruleset must hold. The curated corpus is tuned to
/// zero false positives, so this leaves headroom for real-world corpus additions.
const PRECISION_FLOOR: f64 = 0.90;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// (line 1-based) -> expected rule id, parsed from `EXPECT GF-NNN` annotations.
fn expected_labels(source: &str) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for (i, line) in source.lines().enumerate() {
        if let Some(pos) = line.find("EXPECT ") {
            let rule: String = line[pos + 7..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_owned();
            if rule.starts_with("GF-") {
                out.insert(i as u32 + 1, rule);
            }
        }
    }
    out
}

fn language_of(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => "python",
        Some("pl" | "pm") => "perl",
        Some("go") => "go",
        Some("rs") => "rust",
        Some("java") => "java",
        Some("c" | "h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx") => "cpp",
        Some("adb" | "ads") => "ada",
        _ => "other",
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_tree(&src_path, &dst_path);
        } else {
            std::fs::copy(&src_path, &dst_path).unwrap();
        }
    }
}

#[derive(Default, Clone)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
}

#[test]
fn static_ruleset_meets_precision_floor() {
    let source_corpus = repo_root().join("benchmarks/static/corpus");
    if !source_corpus.is_dir() {
        eprintln!("SKIP: {} not present", source_corpus.display());
        return;
    }

    let work = std::env::temp_dir().join(format!(
        "gf-static-bench-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let corpus = work.join("corpus");
    copy_tree(&source_corpus, &corpus);

    // Scan the whole corpus once. The release corpus is copied out of the repo
    // so production fixture/test/benchmark path suppressions do not hide rules
    // that intentionally suppress findings in real benchmark directories.
    let options = static_analysis::StaticScanOptions {
        root: corpus.clone(),
        out_dir: work.join("out"),
        suppressions_path: None,
        baseline_path: None,
        policy_path: None,
        enabled_rules: Default::default(),
        disabled_rules: Default::default(),
        emit_sarif: false,
    };
    let report = static_analysis::scan(&options).expect("scan corpus");

    // Group findings by absolute file path.
    let mut by_file: BTreeMap<PathBuf, Vec<(u32, String)>> = BTreeMap::new();
    for f in &report.findings {
        by_file
            .entry(corpus.join(&f.location.path))
            .or_default()
            .push((f.location.line, f.rule_id.clone()));
    }

    let mut per_rule: BTreeMap<String, Counts> = BTreeMap::new();
    let mut per_lang: BTreeMap<&str, Counts> = BTreeMap::new();
    let mut walk = vec![corpus.clone()];
    let mut fp_details: Vec<String> = Vec::new();
    while let Some(dir) = walk.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk.push(path);
                continue;
            }
            let lang = language_of(&path);
            if lang == "other" {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let expected = expected_labels(&source);
            let found: Vec<(u32, String)> = by_file.get(&path).cloned().unwrap_or_default();
            // True positives + false positives.
            for (line, rule) in &found {
                let hit = expected.get(line) == Some(rule);
                let e = per_rule.entry(rule.clone()).or_default();
                let el = per_lang.entry(lang).or_default();
                if hit {
                    e.tp += 1;
                    el.tp += 1;
                } else {
                    e.fp += 1;
                    el.fp += 1;
                    fp_details.push(format!(
                        "{}:{} unexpected {}",
                        path.strip_prefix(&corpus).unwrap().display(),
                        line,
                        rule
                    ));
                }
            }
            // False negatives: an EXPECT with no matching finding.
            for (line, rule) in &expected {
                if !found.iter().any(|(l, r)| l == line && r == rule) {
                    per_rule.entry(rule.clone()).or_default().fn_ += 1;
                    per_lang.entry(lang).or_default().fn_ += 1;
                }
            }
        }
    }

    // Write results.tsv + compute overall precision/recall.
    let mut tsv = String::from("scope\tid\ttp\tfp\tfn\tprecision\trecall\n");
    let (mut ttp, mut tfp, mut tfn) = (0u32, 0u32, 0u32);
    let pr = |c: &Counts| {
        if c.tp + c.fp == 0 {
            1.0
        } else {
            c.tp as f64 / (c.tp + c.fp) as f64
        }
    };
    let rc = |c: &Counts| {
        if c.tp + c.fn_ == 0 {
            1.0
        } else {
            c.tp as f64 / (c.tp + c.fn_) as f64
        }
    };
    for (lang, c) in &per_lang {
        tsv.push_str(&format!(
            "language\t{lang}\t{}\t{}\t{}\t{:.3}\t{:.3}\n",
            c.tp,
            c.fp,
            c.fn_,
            pr(c),
            rc(c)
        ));
    }
    for (rule, c) in &per_rule {
        tsv.push_str(&format!(
            "rule\t{rule}\t{}\t{}\t{}\t{:.3}\t{:.3}\n",
            c.tp,
            c.fp,
            c.fn_,
            pr(c),
            rc(c)
        ));
        ttp += c.tp;
        tfp += c.fp;
        tfn += c.fn_;
    }
    let overall_p = if ttp + tfp == 0 {
        1.0
    } else {
        ttp as f64 / (ttp + tfp) as f64
    };
    let overall_r = if ttp + tfn == 0 {
        1.0
    } else {
        ttp as f64 / (ttp + tfn) as f64
    };
    tsv.push_str(&format!(
        "overall\tALL\t{ttp}\t{tfp}\t{tfn}\t{overall_p:.3}\t{overall_r:.3}\n"
    ));
    let _ = std::fs::write(repo_root().join("benchmarks/static/results.tsv"), &tsv);
    let _ = std::fs::remove_dir_all(&work);

    eprintln!(
        "static precision benchmark: TP={ttp} FP={tfp} FN={tfn} precision={overall_p:.3} recall={overall_r:.3}"
    );
    assert!(
        overall_p >= PRECISION_FLOOR,
        "static ruleset precision {overall_p:.3} is below the floor {PRECISION_FLOOR}. False positives:\n{}",
        fp_details.join("\n")
    );
    // The curated corpus must also achieve full recall (no rule silently stops firing).
    assert_eq!(
        tfn, 0,
        "static ruleset missed expected findings (recall < 1.0)"
    );
}
