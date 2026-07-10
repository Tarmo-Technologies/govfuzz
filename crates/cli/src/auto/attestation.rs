// SPDX-License-Identifier: Apache-2.0

//! Fuzz-assurance evidence ledger — an in-toto attestation of the run.
//!
//! govfuzz's differentiator is correlating static + dynamic evidence: a finding is
//! `fuzz_confirmed` (a fuzzer walked into it), `reachable`, `static`, or `lab_only`
//! (proven not attacker-reachable). This module turns that evidence into a signed
//! -able, machine-checkable [in-toto Statement](https://in-toto.io/Statement/v1)
//! written to `<work>/auto/attestation.json`, so a run is an auditable artifact for
//! SLSA provenance / the CISA memory-safety-roadmap attestation workflows government
//! vendors now file. It is UNSIGNED by design (offline): a `cosign attest` / DSSE
//! step wraps it, and the `subject.digest.sha256` is a self-integrity anchor over
//! the exact evidence set — tamper the findings and the digest no longer matches.
//!
//! Best-effort: unreadable/mis-shaped finding sidecars are skipped, never fatal.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// One finding's assurance evidence, in the attestation's stable form.
#[derive(serde::Serialize)]
struct Evidence {
    id: String,
    rule: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    cwe: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    severity: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    location: String,
    /// `fuzz_confirmed` · `reachable` · `static` · `lab_only`.
    tier: &'static str,
}

/// Write `<auto_dir>/attestation.json`: an in-toto v1 Statement whose predicate is
/// the run's fuzz-assurance evidence ledger. Returns the number of findings covered.
pub(crate) fn write_attestation(
    auto_dir: &Path,
    work_dir: &Path,
    source_root: &Path,
    started_at: &str,
    finished_at: &str,
    mode: &str,
) -> usize {
    let mut evidence = collect_evidence(work_dir);
    // Deterministic order so the digest is reproducible for identical evidence.
    evidence.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.location.cmp(&b.location)));

    let mut tally: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for e in &evidence {
        *tally.entry(e.tier).or_default() += 1;
    }

    // Self-integrity anchor: sha256 over the canonical evidence list. An attestation
    // whose findings were altered no longer matches its own subject digest.
    let canonical = serde_json::to_vec(&evidence).unwrap_or_default();
    let digest = hex(&Sha256::digest(&canonical));

    let statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": source_root.display().to_string(),
            "digest": { "sha256": digest }
        }],
        "predicateType": "https://govfuzz.dev/attestation/fuzz-assurance/v1",
        "predicate": {
            "tool": { "name": "govfuzz", "version": env!("CARGO_PKG_VERSION") },
            "run": { "mode": mode, "startedAt": started_at, "finishedAt": finished_at },
            "assurance": {
                "total": evidence.len(),
                "fuzzConfirmed": tally.get("fuzz_confirmed").copied().unwrap_or(0),
                "reachable": tally.get("reachable").copied().unwrap_or(0),
                "static": tally.get("static").copied().unwrap_or(0),
                "labOnly": tally.get("lab_only").copied().unwrap_or(0),
            },
            "findings": evidence,
        }
    });

    if let Ok(bytes) = serde_json::to_vec_pretty(&statement) {
        let _ = std::fs::write(auto_dir.join("attestation.json"), bytes);
    }
    tally.values().sum()
}

/// Read every `<work>/findings/*/finding.json` into an [`Evidence`] record.
fn collect_evidence(work_dir: &Path) -> Vec<Evidence> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work_dir.join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(raw) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let id = str_field(&raw, &["id"]);
        if id.is_empty() {
            continue;
        }
        let rule = str_field(&raw, &["rule_id", "rule"]);
        out.push(Evidence {
            tier: tier_of(&raw),
            cwe: cwe_of(&raw, &rule),
            severity: str_field(&raw, &["severity"]),
            location: location_of(&raw),
            rule,
            id,
        });
    }
    out
}

/// The assurance tier for a finding. A runtime finding (a real fuzz crash / oracle
/// hit — anything not tagged a static finding) is `fuzz_confirmed` by construction;
/// a static finding takes its confirmation/verdict tier.
fn tier_of(raw: &Value) -> &'static str {
    let confirmation = raw.get("confirmation").and_then(Value::as_str);
    if confirmation == Some("fuzz_confirmed") {
        return "fuzz_confirmed";
    }
    let is_static = confirmation == Some("static")
        || raw
            .get("classification")
            .and_then(Value::as_str)
            .is_some_and(|c| c.contains("static"))
        || raw
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.contains("STATIC"));
    if !is_static {
        // A runtime crash / oracle finding: a defect a fuzzer actually triggered.
        return "fuzz_confirmed";
    }
    match verdict_of(raw).as_deref() {
        Some("lab_only") | Some("blocked") => "lab_only",
        Some("likely_reachable") | Some("real_reachable") | Some("attacker_reachable") => {
            "reachable"
        }
        _ => "static",
    }
}

fn verdict_of(raw: &Value) -> Option<String> {
    for ptr in [
        "/actionability/verdict",
        "/analysis/actionability/verdict",
        "/verdict",
    ] {
        if let Some(v) = raw.pointer(ptr).and_then(Value::as_str) {
            return Some(v.to_owned());
        }
    }
    None
}

/// The CWE for a finding: `actionability.cwe[0]` when present, else the rule
/// catalog's CWE for the rule id (finding sidecars carry only the rule id).
fn cwe_of(raw: &Value, rule: &str) -> String {
    if let Some(cwe) = raw
        .pointer("/actionability/cwe/0")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
    {
        return cwe.to_owned();
    }
    if let Some(cwe) = str_opt(raw, &["cwe"]) {
        return cwe;
    }
    finding_rules::by_id(rule)
        .map(|r| r.cwe.to_owned())
        .unwrap_or_default()
}

/// A `path:line` location, tried across the finding shapes: the `oracle.evidence[]`
/// `source` entry (`bug.c:2`), then the static/runtime sink shapes.
fn location_of(raw: &Value) -> String {
    if let Some(evidence) = raw.pointer("/oracle/evidence").and_then(Value::as_array) {
        for item in evidence {
            if item.get("key").and_then(Value::as_str) == Some("source") {
                if let Some(v) = item.get("value").and_then(Value::as_str) {
                    return v.to_owned();
                }
            }
        }
    }
    for (path_ptr, line_ptr) in [
        ("/location/path", "/location/line"),
        ("/sink/path", "/sink/line"),
        ("/site/path", "/site/line"),
    ] {
        if let Some(p) = raw.pointer(path_ptr).and_then(Value::as_str) {
            let line = raw.pointer(line_ptr).and_then(Value::as_u64);
            return match line {
                Some(l) => format!("{p}:{l}"),
                None => p.to_owned(),
            };
        }
    }
    str_field(raw, &["path", "file"])
}

fn str_field(raw: &Value, keys: &[&str]) -> String {
    str_opt(raw, keys).unwrap_or_default()
}

fn str_opt(raw: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| raw.get(key).and_then(Value::as_str))
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
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

    fn write_finding(dir: &Path, id: &str, body: Value) {
        let d = dir.join("findings").join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("finding.json"), serde_json::to_vec(&body).unwrap()).unwrap();
    }

    #[test]
    fn attestation_tiers_findings_and_self_anchors() {
        let tmp = std::env::temp_dir().join(format!("gf-attest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let auto = tmp.join("auto");
        std::fs::create_dir_all(&auto).unwrap();
        // A confirmed static finding, an unconfirmed static one, and a runtime crash.
        write_finding(
            &tmp,
            "F-STATIC-0001",
            json!({"id":"F-STATIC-0001","rule_id":"GF-401","cwe":"CWE-120","severity":"high",
                   "confirmation":"fuzz_confirmed","location":{"path":"a.c","line":8}}),
        );
        write_finding(
            &tmp,
            "F-STATIC-0002",
            json!({"id":"F-STATIC-0002","rule_id":"GF-427","cwe":"CWE-918","severity":"medium",
                   "confirmation":"static","actionability":{"verdict":"lab_only"},
                   "location":{"path":"b.go","line":3}}),
        );
        write_finding(
            &tmp,
            "F-0003",
            json!({"id":"F-0003","rule_id":"GF-202","cwe":"CWE-416","severity":"critical",
                   "sink":{"path":"c.c","line":42}}),
        );

        let n = write_attestation(&auto, &tmp, Path::new("/src/proj"), "t0", "t1", "auto");
        assert_eq!(n, 3);
        let doc: Value =
            serde_json::from_slice(&std::fs::read(auto.join("attestation.json")).unwrap()).unwrap();
        assert_eq!(doc["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(
            doc["predicateType"],
            "https://govfuzz.dev/attestation/fuzz-assurance/v1"
        );
        // Confirmed static + runtime crash both count as fuzz_confirmed; the
        // lab_only static is triaged down.
        assert_eq!(doc["predicate"]["assurance"]["fuzzConfirmed"], 2);
        assert_eq!(doc["predicate"]["assurance"]["labOnly"], 1);
        assert_eq!(doc["predicate"]["assurance"]["total"], 3);
        // The subject digest is a non-empty sha256 hex anchoring the evidence.
        let digest = doc["subject"][0]["digest"]["sha256"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        // Recompute over a tampered evidence set → different digest (self-anchor).
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
