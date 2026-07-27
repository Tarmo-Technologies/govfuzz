// SPDX-License-Identifier: Apache-2.0
//! `auto --static`: run a whole-tree static scan IN ADDITION to fuzzing (not only
//! as a fallback when a target can't be fuzzed). The scan's findings
//! (classification `static_scan`, `F-STATIC-*`) merge into the unified report next
//! to the fuzz findings — so a target that built+fuzzed still gets static coverage.
//!
//! Gated on the C toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
fn static_flag_runs_tree_scan_and_merges_findings() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang/make not installed — C lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-static-scan-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        srcroot.join("weak.c"),
    )
    .expect("copy fixture");

    let work_dir = srcroot.join("govfuzz_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg("--static")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn govfuzz auto --static");

    // The static scan must have produced at least one F-STATIC finding, written
    // straight into the findings dir alongside any fuzz findings.
    let findings_dir = work_dir.join("findings");
    let static_findings: Vec<_> = std::fs::read_dir(&findings_dir)
        .expect("findings dir exists")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("F-STATIC-"))
        .collect();
    assert!(
        !static_findings.is_empty(),
        "--static must write at least one F-STATIC finding; stderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Each static finding is tagged classification `static_scan` and carries a CWE.
    let first = static_findings[0].path().join("finding.json");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&first).expect("read finding.json"))
            .expect("parse finding.json");
    assert_eq!(record["classification"].as_str(), Some("static_scan"));
    assert!(
        record["actionability"]["cwe"]
            .as_array()
            .is_some_and(|c| !c.is_empty()),
        "static finding must carry a CWE: {record}"
    );

    // #484 (fuzz-confirmation join): the `strcpy(buf, name)` at weak.c:9 is a
    // static CWE-120 finding AND a trivially fuzz-reachable stack overflow. The
    // fuzzer crashes ASan at the SAME line the static rule flagged, so the join
    // must (a) upgrade the static finding to `fuzz_confirmed` on disk, and (b)
    // CLUSTER it with the crash so the report renders ONE issue row (the crash as
    // representative, the static finding a member) — not two orphaned rows.
    let static_id = static_findings[0]
        .file_name()
        .to_string_lossy()
        .into_owned();
    let confirmed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(static_findings[0].path().join("finding.json")).expect("read finding.json"),
    )
    .expect("parse confirmed finding.json");
    assert_eq!(confirmed["confirmation"].as_str(), Some("fuzz_confirmed"));
    assert!(
        confirmed["confirmed_by"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "confirmed finding must name its confirming runtime finding(s): {confirmed}"
    );

    // The merged issue row (identified by the static id in its member_finding_ids)
    // must carry provenance `fuzz_confirmed` (column 8) and resolve to weak.c:9
    // (sink_file/sink_line, columns 14,15 — a `source` column sits at 13 now).
    // govfuzz's OWN generated harness under the work-dir must NOT appear as static
    // findings (no `main.c` FP rows).
    let csv =
        std::fs::read_to_string(work_dir.join("auto/findings.csv")).expect("read findings.csv");
    assert!(
        !csv.contains("harnesses/"),
        "the work-dir's generated harness must be excluded from --static:\n{csv}"
    );
    let merged_row = csv
        .lines()
        .find(|l| l.contains(&static_id))
        .unwrap_or_else(|| panic!("findings.csv must merge the confirmed static finding:\n{csv}"));
    let cols: Vec<&str> = merged_row.split(',').collect();
    assert_eq!(
        cols.get(8).copied(),
        Some("fuzz_confirmed"),
        "the fuzz-reachable static finding must be fuzz_confirmed: {merged_row}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        cols.get(15).is_some_and(|c| c.ends_with("weak.c")),
        "confirmed issue must resolve its sink file: {merged_row}"
    );
    assert!(
        cols.get(16)
            .is_some_and(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit())),
        "confirmed issue must resolve a numeric sink line: {merged_row}"
    );
    // The static finding must name WHAT it is, not just a CWE: its rule_id (col 3)
    // and a human-readable message (col 4) must be populated.
    assert!(
        cols.get(3).is_some_and(|c| c.starts_with("GF-")),
        "static issue must surface its finding-rule id: {merged_row}"
    );
    assert!(
        cols.get(4).is_some_and(|c| !c.is_empty()),
        "static issue must surface a human-readable message: {merged_row}"
    );
    // sink_function (col 17) must be the ENCLOSING FUNCTION, not the file name —
    // the static analyzer resolves `handle_request`, and the emitter passes it
    // through so the column no longer falls back to the file basename.
    assert!(
        cols.get(17)
            .is_some_and(|c| !c.is_empty() && !c.ends_with(".c") && *c != "weak.c"),
        "sink_function must be the enclosing function, not the file: {merged_row}"
    );
    // remediation (col 19, after the inserted data_flow col 14 and entity col 18)
    // carries an actionable one-line fix, not a location.
    assert!(
        cols.get(19).is_some_and(|c| !c.is_empty()),
        "confirmed issue must carry remediation guidance: {merged_row}"
    );

    let run_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work_dir.join("auto/run.json")).expect("read run.json"),
    )
    .expect("parse run.json");
    assert!(
        run_json["summary"]["fuzz_confirmed"].as_u64().unwrap_or(0) >= 1,
        "run.json summary must count the confirmed finding: {}",
        run_json["summary"]
    );
}

/// `--static-dynamic` appends a `scan_type` column to findings.csv: `static-dynamic`
/// for a static-scan result, `dynamic` for a fuzzed result. Off by default (no
/// column). Gated on the C toolchain.
#[test]
fn static_dynamic_flag_adds_scan_type_column() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang/make not installed — C lane unavailable");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-scan-type-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        srcroot.join("weak.c"),
    )
    .expect("copy fixture");
    let work_dir = srcroot.join("govfuzz_work");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args(["auto", "--static", "--static-dynamic"])
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .args(["--per-target-time", "1"])
        .status()
        .expect("spawn govfuzz auto --static --static-dynamic");
    assert!(status.success());

    let csv =
        std::fs::read_to_string(work_dir.join("auto/findings.csv")).expect("read findings.csv");
    let header = csv.lines().next().expect("header");
    // `scan_type` sits between the base columns and the stub-accounting block,
    // which is where `render_issue_row` writes it. (It used to be asserted as the
    // LAST column, which is what let the header and the rows disagree.)
    let columns: Vec<&str> = header.split(',').collect();
    let scan_type = columns
        .iter()
        .position(|c| *c == "scan_type")
        .unwrap_or_else(|| panic!("--static-dynamic must add a scan_type column: {header}"));
    assert_eq!(
        columns.get(scan_type + 1).copied(),
        Some("stub_total"),
        "scan_type must precede the stub block: {header}"
    );
    // The weak.c static finding (fuzz-confirmed, clustered under the crash) is a
    // static-scan result, so its row's scan_type is `static-dynamic`. (The row is
    // keyed by the static id appearing in member_finding_ids.)
    let static_row = csv
        .lines()
        .skip(1)
        .find(|l| l.contains("F-STATIC-"))
        .expect("a row referencing the static finding");
    assert_eq!(
        static_row.split(',').nth(scan_type),
        Some("static-dynamic"),
        "a static-scan result's scan_type must be static-dynamic: {static_row}"
    );
}
