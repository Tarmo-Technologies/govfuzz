// SPDX-License-Identifier: Apache-2.0

//! JVM sink-reachability oracle — input-reachable dangerous sinks (behavioral
//! findings the crash-only JVM lane never reports).
//!
//! govfuzz's coverage agent instruments the target's bytecode so each call site of a
//! dangerous sink (untrusted deserialization, process execution, dynamic code
//! evaluation, dynamic SQL, an LDAP search) records the reach into a per-harness
//! `sink_report.txt` (see `java_runtime/com/govfuzz/Sink`). A sink reached while the
//! fuzzer drives the input is input-reachable attack surface — the JVM analog of the
//! native runtrace shim's behavioral oracles (which are native-only). This pass reads
//! that report after the run and emits one finding per reached sink kind, mapping the
//! kind to its existing CWE/rule.
//!
//! Reachability, not full taint: it reports that fuzzer-driven execution reached the
//! sink, the same signal Jazzer's autofuzz detectors surface. A missing report (no
//! sink reached, or a non-JVM harness) skips cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// Map a `Sink` kind integer (must match `com.govfuzz.Sink`) to its rule id, CWE, and
/// a short human label.
fn kind_to_rule(kind: u32) -> Option<(&'static str, &'static str, &'static str)> {
    match kind {
        1 => Some(("GF-421", "CWE-502", "untrusted deserialization")),
        2 => Some(("GF-404", "CWE-78", "process execution")),
        3 => Some(("GF-420", "CWE-94", "dynamic code evaluation")),
        4 => Some(("GF-419", "CWE-89", "dynamic SQL execution")),
        5 => Some(("GF-432", "CWE-90", "LDAP directory search")),
        _ => None,
    }
}

/// Read the reached sink kinds from a `sink_report.txt` (one integer per line,
/// possibly repeated across JVM spawns), deduped.
fn read_reached_kinds(report: &Path) -> BTreeSet<u32> {
    let mut kinds = BTreeSet::new();
    if let Ok(text) = std::fs::read_to_string(report) {
        for line in text.lines() {
            if let Ok(kind) = line.trim().parse::<u32>() {
                kinds.insert(kind);
            }
        }
    }
    kinds
}

/// For every Java harness, turn its recorded reachable sinks into findings. Returns
/// the number of findings written.
pub fn run_sink_oracle(work_dir: &Path) -> usize {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut written = 0usize;
    let mut index = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let report = hdir.join("sink_report.txt");
        for kind in read_reached_kinds(&report) {
            let Some((rule_id, cwe, label)) = kind_to_rule(kind) else {
                continue;
            };
            let id = format!("F-JSINK-{index:04}");
            index += 1;
            if write_sink_finding(work_dir, &id, &harness_id, rule_id, cwe, label) {
                written += 1;
            }
        }
    }
    written
}

fn write_sink_finding(
    work: &Path,
    id: &str,
    harness_id: &str,
    rule_id: &str,
    cwe: &str,
    label: &str,
) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    // One issue per (harness, sink rule), stable 64-hex cluster key.
    let cluster_key_full = hex(&Sha256::digest(
        format!("{rule_id}:{harness_id}").as_bytes(),
    ));
    let record = json!({
        "id": id,
        "rule_id": rule_id,
        "confirmation": "fuzz_confirmed",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "exception": {
            "name": "SinkReached",
            "message": format!("fuzzer-driven execution reached a {label} sink — input-reachable attack surface"),
        },
        "oracle": { "evidence": [ { "key": "sink", "value": label.to_owned() } ] },
        "analysis": { "engine": "govfuzz.dynamic.jvm.sink" },
        "actionability": { "cwe": [cwe], "verdict": "likely_reachable", "confidence": "high" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_mapping_covers_the_agent_sink_kinds() {
        // Must stay in lockstep with com.govfuzz.Sink's constants.
        assert_eq!(kind_to_rule(1).unwrap().0, "GF-421");
        assert_eq!(kind_to_rule(2).unwrap().0, "GF-404");
        assert_eq!(kind_to_rule(3).unwrap().0, "GF-420");
        assert_eq!(kind_to_rule(4).unwrap().0, "GF-419");
        assert_eq!(kind_to_rule(5).unwrap().0, "GF-432");
        assert!(kind_to_rule(99).is_none());
    }

    #[test]
    fn read_reached_kinds_dedupes_across_spawns() {
        let tmp = std::env::temp_dir().join(format!("govfuzz-sink-read-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let report = tmp.join("sink_report.txt");
        // Appended by three JVM spawns; kind 1 seen twice.
        std::fs::write(&report, "1\n4\n1\n").unwrap();
        assert_eq!(
            read_reached_kinds(&report),
            BTreeSet::from([1, 4]),
            "deduped kinds"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn run_sink_oracle_emits_one_finding_per_reached_kind() {
        let tmp = std::env::temp_dir().join(format!("govfuzz-sink-oracle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let hdir = tmp.join("harnesses").join("H-J0001");
        std::fs::create_dir_all(&hdir).unwrap();
        // Deserialization (1) and SQL (4) reached.
        std::fs::write(hdir.join("sink_report.txt"), "1\n4\n1\n").unwrap();

        let written = run_sink_oracle(&tmp);
        assert_eq!(written, 2, "one finding per distinct reached sink kind");

        let findings: Vec<String> = std::fs::read_dir(tmp.join("findings"))
            .unwrap()
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.path().join("finding.json")).ok())
            .collect();
        let joined = findings.join("\n");
        assert!(
            joined.contains("GF-421"),
            "deserialization finding:\n{joined}"
        );
        assert!(joined.contains("GF-419"), "SQL finding:\n{joined}");
        assert!(joined.contains("fuzz_confirmed"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
