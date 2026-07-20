// SPDX-License-Identifier: Apache-2.0

//! M23 Phase 3 (#486): external static-analysis tool adapters.
//!
//! govfuzz's own rules are deliberately thin in some languages (Rust especially).
//! Rather than reimplement clippy/gosec/Bandit/SpotBugs/GNATcheck, this runs them
//! as **subprocesses** — never linked — parses their SARIF/JSON output into the
//! same `finding.json` format `--static` uses, and lets the fuzz-confirmation join
//! confirm/downgrade THEIR findings too. The tools are the operator's own installs.
//!
//! **License gate (load-bearing):** an adapter runs ONLY when its tool's
//! subprocess id is allowed by the active [`config::Profile`]. `strict-permissive`
//! allows none — so the default profile never invokes a GPL tool like GNATcheck.
//! `external-tools` / `research-lab` opt in. This is a runtime mirror of the
//! build-time `cargo deny` / license-audit guarantee: the govfuzz binary links
//! nothing GPL; a subprocess is not a derivative work; and the profile still gates
//! whether it is invoked at all.
//!
//! Missing tools are skipped (like a missing toolchain), never fatal.

use config::Profile;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn max_external_tool_output_bytes() -> usize {
    crate::resource_limits::dynamic_bytes(
        "GOVFUZZ_MAX_EXTERNAL_TOOL_OUTPUT_BYTES",
        256,
        32 * crate::resource_limits::MIB,
        32 * crate::resource_limits::MIB,
        512 * crate::resource_limits::MIB,
    )
}

/// One external analyzer govfuzz can drive.
struct Adapter {
    /// Display / finding-source name (e.g. `gosec`).
    tool: &'static str,
    /// The binary to invoke (via `which`), if different from `tool`.
    binary: &'static str,
    /// Profile subprocess-id gating this tool (see `Profile::allowed_subprocesses`).
    subprocess_id: &'static str,
    /// Arguments; `{root}` is replaced with the scan root. Output goes to stdout.
    args: &'static [&'static str],
    /// How to parse the tool's stdout into findings.
    format: OutputFormat,
    /// Prefix→CWE fallback for tools that don't tag CWE in their output.
    rule_cwe: &'static [(&'static str, &'static str)],
}

#[derive(Clone, Copy)]
enum OutputFormat {
    /// SARIF 2.1.0 (`runs[].results[]`).
    Sarif,
}

/// The adapter registry. Permissive-licensed tools (gosec/Bandit/clippy/semgrep,
/// all Apache-2.0 or MIT) and the GPL GNATcheck are all gated by profile; the
/// distinction that matters for the product guarantee is the profile gate, not the
/// tool's own license, because govfuzz never links any of them.
const ADAPTERS: &[Adapter] = &[
    Adapter {
        tool: "gosec",
        binary: "gosec",
        subprocess_id: "gosec",
        args: &["-quiet", "-fmt=sarif", "{root}/..."],
        format: OutputFormat::Sarif,
        rule_cwe: &[
            ("G204", "CWE-78"),
            ("G201", "CWE-89"),
            ("G202", "CWE-89"),
            ("G203", "CWE-79"), // unescaped data into an HTML template (XSS)
            ("G304", "CWE-22"),
            ("G401", "CWE-327"),
            ("G501", "CWE-327"),
            ("G101", "CWE-798"),
        ],
    },
    Adapter {
        tool: "bandit",
        binary: "bandit",
        subprocess_id: "bandit",
        args: &["-r", "-q", "-f", "sarif", "{root}"],
        format: OutputFormat::Sarif,
        rule_cwe: &[
            ("B602", "CWE-78"),
            ("B605", "CWE-78"),
            ("B608", "CWE-89"),
            ("B307", "CWE-94"),
            ("B301", "CWE-502"),
            ("B303", "CWE-327"),
            ("B105", "CWE-798"),
            ("B701", "CWE-79"),  // jinja2 autoescape disabled (XSS)
            ("B702", "CWE-79"),  // mako templates (no autoescape → XSS)
            ("B703", "CWE-79"),  // django mark_safe on untrusted data (XSS)
            ("B308", "CWE-79"),  // mark_safe (XSS)
            ("B323", "CWE-295"), // unverified HTTPS context
        ],
    },
    Adapter {
        tool: "semgrep",
        binary: "semgrep",
        subprocess_id: "semgrep",
        args: &["--sarif", "--quiet", "--config", "auto", "{root}"],
        format: OutputFormat::Sarif,
        rule_cwe: &[],
    },
    Adapter {
        tool: "gnatcheck",
        binary: "gnatcheck",
        subprocess_id: "gnatcheck",
        args: &["-P", "{root}", "--show-rule"],
        format: OutputFormat::Sarif,
        rule_cwe: &[],
    },
];

/// Run every profile-allowed, installed external adapter over `root`, writing
/// their findings under `work/findings/` (classification `static_scan`, ids
/// `F-EXT-*`) so they merge into the report and the fuzz-confirmation join. Returns
/// the number of findings written. Best-effort throughout.
pub fn run_external_adapters(root: &Path, work: &Path, profile: Profile) -> usize {
    let mut written = 0usize;
    for (index, finding) in collect_external_findings(root, profile).iter().enumerate() {
        let id = format!("F-EXT-{index:04}");
        if write_finding(work, &id, &finding.tool, finding) {
            written += 1;
        }
    }
    written
}

/// Run every profile-allowed, installed external adapter over `root` and return the
/// normalized findings — without writing them anywhere. This is the "breadth without
/// fuzzing" entry point: `static-scan --external-tools` folds these into its report
/// so a tree that can't be fuzzed still gets the adapters' coverage (XSS/CSRF and the
/// rest). `run_external_adapters` writes them for the `auto` fuzz-confirmation join.
pub fn collect_external_findings(root: &Path, profile: Profile) -> Vec<ExtFinding> {
    let allowed = profile.allowed_subprocesses();
    let mut findings = Vec::new();
    for adapter in ADAPTERS {
        if !subprocess_allowed(allowed, adapter.subprocess_id) {
            continue;
        }
        if which::which(adapter.binary).is_err() {
            continue; // tool not installed — skip like a missing toolchain.
        }
        let Some(output) = run_tool(adapter, root) else {
            continue;
        };
        match adapter.format {
            OutputFormat::Sarif => findings.extend(parse_sarif(&output, adapter)),
        }
    }
    findings
}

/// Whether the active profile permits this tool's subprocess (`"*"` = any).
fn subprocess_allowed(allowed: &[&str], subprocess_id: &str) -> bool {
    allowed.contains(&"*") || allowed.contains(&subprocess_id)
}

fn run_tool(adapter: &Adapter, root: &Path) -> Option<String> {
    let root_str = root.to_string_lossy();
    let args: Vec<String> = adapter
        .args
        .iter()
        .map(|arg| arg.replace("{root}", &root_str))
        .collect();
    let output_limit = max_external_tool_output_bytes();
    let captured = crate::command_output::capture_with_timeout(
        Command::new(adapter.binary).args(&args),
        Duration::from_secs(30 * 60),
        output_limit,
    )
    .ok()?;
    if captured.timed_out {
        eprintln!(
            "govfuzz: external analyzer '{}' exceeded its 30-minute timeout; skipping its output",
            adapter.binary
        );
        return None;
    }
    if captured.stdout_truncated {
        eprintln!(
            "govfuzz: external analyzer '{}' exceeded the {} MiB output cap; skipping its \
             incomplete report (raise GOVFUZZ_MAX_EXTERNAL_TOOL_OUTPUT_BYTES if needed)",
            adapter.binary,
            output_limit / (1024 * 1024)
        );
        return None;
    }
    if captured.stderr_truncated {
        eprintln!(
            "govfuzz: external analyzer '{}' stderr exceeded the bounded capture; diagnostics were truncated",
            adapter.binary
        );
    }
    // Tools exit non-zero when they find issues; take stdout regardless.
    Some(String::from_utf8_lossy(&captured.output.stdout).into_owned())
}

/// One normalized finding parsed from a tool's output.
pub struct ExtFinding {
    /// The originating analyzer (`semgrep`, `gosec`, `bandit`, `gnatcheck`).
    pub tool: String,
    pub rule: String,
    pub message: String,
    pub path: String,
    pub line: u32,
    pub severity: String,
    pub cwe: Option<String>,
}

/// Parse SARIF 2.1.0 stdout into findings, pulling `path:line`, the rule id, the
/// message, the level→severity, and a CWE (from the result/rule `tags`, else the
/// adapter's rule→CWE fallback).
fn parse_sarif(output: &str, adapter: &Adapter) -> Vec<ExtFinding> {
    let Ok(doc) = serde_json::from_str::<Value>(output) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let runs = doc.get("runs").and_then(Value::as_array);
    for run in runs.into_iter().flatten() {
        // Semgrep (and many SARIF producers) put the CWE on the RULE definition
        // (`tool.driver.rules[]`), not on each result — so build a ruleId→CWE map
        // and consult it when the result itself carries no CWE. Without this the
        // whole XSS/CSRF/framework catalog folds in with a null CWE.
        let rule_cwe_map = sarif_rule_cwe_map(run);
        let results = run.get("results").and_then(Value::as_array);
        for result in results.into_iter().flatten() {
            let rule = result
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("external")
                .to_owned();
            let message = result
                .pointer("/message/text")
                .and_then(Value::as_str)
                .unwrap_or("external finding")
                .to_owned();
            let severity = sarif_level_to_severity(
                result
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("warning"),
            );
            let loc = result.pointer("/locations/0/physicalLocation");
            let Some(path) = loc
                .and_then(|l| l.pointer("/artifactLocation/uri"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let line = loc
                .and_then(|l| l.pointer("/region/startLine"))
                .and_then(Value::as_u64)
                .unwrap_or(1) as u32;
            let cwe = sarif_cwe(result)
                .or_else(|| rule_cwe_map.get(&rule).cloned())
                .or_else(|| {
                    adapter
                        .rule_cwe
                        .iter()
                        .find(|(prefix, _)| rule.starts_with(prefix))
                        .map(|(_, cwe)| (*cwe).to_owned())
                });
            findings.push(ExtFinding {
                tool: adapter.tool.to_owned(),
                rule,
                message,
                path: path.to_owned(),
                line,
                severity,
                cwe,
            });
        }
    }
    findings
}

/// Build a `ruleId → CWE` map from a SARIF run's rule definitions
/// (`tool.driver.rules[]`, plus any `tool.extensions[].rules[]`), reading each
/// rule's `properties.cwe` / `properties.tags`. This is where semgrep and friends
/// record the CWE, keyed by the same `ruleId` the results reference.
fn sarif_rule_cwe_map(run: &Value) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    let mut rule_arrays: Vec<&Vec<Value>> = Vec::new();
    if let Some(rules) = run.pointer("/tool/driver/rules").and_then(Value::as_array) {
        rule_arrays.push(rules);
    }
    if let Some(extensions) = run.pointer("/tool/extensions").and_then(Value::as_array) {
        for ext in extensions {
            if let Some(rules) = ext.get("rules").and_then(Value::as_array) {
                rule_arrays.push(rules);
            }
        }
    }
    for rules in rule_arrays {
        for rule in rules {
            let Some(id) = rule.get("id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(cwe) = sarif_cwe(rule) {
                map.insert(id.to_owned(), cwe);
            }
        }
    }
    map
}

/// A CWE from a SARIF result's OR rule's `properties.cwe` / `properties.tags`
/// (`CWE-78`, `external/cwe/cwe-78`, `cwe-78`, or a `"CWE-79: …"` tag).
fn sarif_cwe(result: &Value) -> Option<String> {
    if let Some(cwe) = result
        .pointer("/properties/cwe")
        .and_then(Value::as_str)
        .map(normalize_cwe)
    {
        return cwe;
    }
    let tags = result
        .pointer("/properties/tags")
        .and_then(Value::as_array)?;
    tags.iter()
        .filter_map(Value::as_str)
        .find_map(normalize_cwe)
}

/// Normalize a CWE-bearing tag to `CWE-NNN` (handles `cwe-78`, `external/cwe/cwe-78`).
fn normalize_cwe(tag: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let idx = lower.find("cwe-")?;
    let digits: String = lower[idx + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    (!digits.is_empty()).then(|| format!("CWE-{digits}"))
}

fn sarif_level_to_severity(level: &str) -> String {
    match level {
        "error" => "high",
        "warning" => "medium",
        "note" => "low",
        _ => "medium",
    }
    .to_owned()
}

/// Write one external finding as a corpus-format `finding.json` (classification
/// `static_scan`, so the fuzz-confirmation join and report treat it like any other
/// static hit), tagged with the originating tool.
fn write_finding(work: &Path, id: &str, tool: &str, finding: &ExtFinding) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let target_name = Path::new(&finding.path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "external".to_owned());
    let source_line = format!("{}:{}", finding.path, finding.line);
    let cwe: Vec<String> = finding.cwe.iter().cloned().collect();
    let record = json!({
        "id": id,
        "rule_id": finding.rule,
        "classification": "static_scan",
        "severity": finding.severity,
        "report_only": true,
        "confirmation": "static",
        "harness_id": "external-scan",
        "external_tool": tool,
        "target": {
            "name": target_name,
            "source_path": finding.path,
            "line": finding.line,
            "location": { "path": finding.path, "line": finding.line },
        },
        "oracle": { "evidence": [ { "key": "source", "value": source_line } ] },
        "exception": { "message": finding.message },
        "analysis": { "engine": format!("govfuzz.static.external.{tool}") },
        "actionability": { "cwe": cwe, "verdict": "static_only", "confidence": "medium" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sarif(rule: &str, cwe_tag: Option<&str>) -> String {
        let props = cwe_tag
            .map(|t| json!({ "tags": [t] }))
            .unwrap_or_else(|| json!({}));
        json!({
            "version": "2.1.0",
            "runs": [ { "results": [ {
                "ruleId": rule,
                "level": "error",
                "message": { "text": "external issue" },
                "properties": props,
                "locations": [ { "physicalLocation": {
                    "artifactLocation": { "uri": "src/app.go" },
                    "region": { "startLine": 12 }
                } } ]
            } ] } ]
        })
        .to_string()
    }

    #[test]
    fn parse_sarif_extracts_location_and_cwe_from_tag() {
        let gosec = &ADAPTERS[0];
        let out = parse_sarif(&sarif("G204", Some("external/cwe/cwe-78")), gosec);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "src/app.go");
        assert_eq!(out[0].line, 12);
        assert_eq!(out[0].severity, "high");
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn parse_sarif_falls_back_to_rule_cwe_map() {
        let gosec = &ADAPTERS[0];
        // No CWE tag -> fall back to the adapter's G204 -> CWE-78 map.
        let out = parse_sarif(&sarif("G204", None), gosec);
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn parse_sarif_reads_cwe_from_rule_metadata() {
        // Semgrep-style: the CWE is on the RULE definition (tool.driver.rules[]),
        // not the result. Without the rule→CWE map the whole XSS catalog is null-CWE.
        let doc = json!({
            "version": "2.1.0",
            "runs": [ {
                "tool": { "driver": { "rules": [ {
                    "id": "python.flask.security.xss.audit.direct-use-of-jinja2",
                    "properties": { "tags": ["CWE-79: Cross-site Scripting (XSS)", "security"] }
                } ] } },
                "results": [ {
                    "ruleId": "python.flask.security.xss.audit.direct-use-of-jinja2",
                    "level": "warning",
                    "message": { "text": "XSS" },
                    "locations": [ { "physicalLocation": {
                        "artifactLocation": { "uri": "app.py" },
                        "region": { "startLine": 6 }
                    } } ]
                } ]
            } ]
        })
        .to_string();
        let semgrep = ADAPTERS.iter().find(|a| a.tool == "semgrep").unwrap();
        let out = parse_sarif(&doc, semgrep);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-79"));
        assert_eq!(out[0].tool, "semgrep");
    }

    #[test]
    fn bandit_and_gosec_map_xss_rule_ids_to_cwe_79() {
        let gosec = ADAPTERS.iter().find(|a| a.tool == "gosec").unwrap();
        let bandit = ADAPTERS.iter().find(|a| a.tool == "bandit").unwrap();
        // gosec G203 (template XSS) and bandit B701/B308 (jinja2/mark_safe) -> CWE-79.
        assert_eq!(
            parse_sarif(&sarif("G203", None), gosec)[0].cwe.as_deref(),
            Some("CWE-79")
        );
        assert_eq!(
            parse_sarif(&sarif("B701", None), bandit)[0].cwe.as_deref(),
            Some("CWE-79")
        );
        assert_eq!(
            parse_sarif(&sarif("B308", None), bandit)[0].cwe.as_deref(),
            Some("CWE-79")
        );
    }

    #[test]
    fn normalize_cwe_handles_variants() {
        assert_eq!(normalize_cwe("CWE-78").as_deref(), Some("CWE-78"));
        assert_eq!(
            normalize_cwe("external/cwe/cwe-89").as_deref(),
            Some("CWE-89")
        );
        assert_eq!(normalize_cwe("not-a-cwe"), None);
    }

    /// The load-bearing gate: strict-permissive permits NO external subprocess, so
    /// a GPL tool like GNATcheck is never invoked in the strict-permissive profile.
    #[test]
    fn strict_permissive_allows_no_external_tool() {
        let allowed = Profile::StrictPermissive.allowed_subprocesses();
        for adapter in ADAPTERS {
            assert!(
                !subprocess_allowed(allowed, adapter.subprocess_id),
                "{} must be gated out of strict-permissive",
                adapter.tool
            );
        }
        // external-tools opts in.
        assert!(subprocess_allowed(
            Profile::ExternalTools.allowed_subprocesses(),
            "gosec"
        ));
    }

    /// Writing an external finding produces a static-classified record the report
    /// and the fuzz-confirmation join accept, tagged with the tool + CWE.
    #[test]
    fn write_finding_emits_static_record_with_tool_and_cwe() {
        let work = std::env::temp_dir().join(format!("gf-ext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        let finding = ExtFinding {
            tool: "gosec".to_owned(),
            rule: "G204".to_owned(),
            message: "subprocess launched with a variable".to_owned(),
            path: "src/app.go".to_owned(),
            line: 12,
            severity: "high".to_owned(),
            cwe: Some("CWE-78".to_owned()),
        };
        assert!(write_finding(&work, "F-EXT-0000", "gosec", &finding));
        let v: Value = serde_json::from_slice(
            &std::fs::read(work.join("findings/F-EXT-0000/finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["classification"], "static_scan");
        assert_eq!(v["external_tool"], "gosec");
        assert_eq!(v["confirmation"], "static");
        assert_eq!(v["actionability"]["cwe"][0], "CWE-78");
        let _ = std::fs::remove_dir_all(&work);
    }
}
