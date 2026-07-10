// SPDX-License-Identifier: Apache-2.0

//! Offline enterprise governance primitives for GovFuzz.

mod vex;

use sbom_ingest::{Component, Evidence, EvidenceKind};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const POLICY_VALIDATION_SCHEMA_VERSION: &str = "govfuzz.policy.validation.v1";
pub const RUNNERS_VALIDATION_SCHEMA_VERSION: &str = "govfuzz.runners.validation.v1";
pub const UPDATE_PACK_VERIFICATION_SCHEMA_VERSION: &str = "govfuzz.update_pack.verification.v1";
pub const UPDATE_PACK_INSPECTION_SCHEMA_VERSION: &str = "govfuzz.update_pack.inspection.v1";
pub const UPDATE_PACK_INSTALL_SCHEMA_VERSION: &str = "govfuzz.update_pack.install.v1";
pub const EXPORT_SCHEMA_VERSION: &str = "govfuzz.export.v1";
pub const POLICY_EXPLAIN_SCHEMA_VERSION: &str = "govfuzz.policy.explain.v1";
pub const POLICY_DRY_RUN_SCHEMA_VERSION: &str = "govfuzz.policy.dry_run.v1";
pub const RUNNER_SELECTION_SCHEMA_VERSION: &str = "govfuzz.runners.selection.v1";
pub const RUNNER_HANDOFF_SCHEMA_VERSION: &str = "govfuzz.runners.handoff.v1";
pub const RUNNER_LEASE_SCHEMA_VERSION: &str = "govfuzz.runners.lease.v1";
pub const RUNNER_COMPLETION_SCHEMA_VERSION: &str = "govfuzz.runners.completion.v1";
pub const RUNNER_PLAN_SCHEMA_VERSION: &str = "govfuzz.runners.plan.v1";
pub const AUDIT_EVENT_SCHEMA_VERSION: &str = "govfuzz.audit.event.v1";
pub const AUDIT_LOG_SCHEMA_VERSION: &str = "govfuzz.audit.log.v1";
pub const DASHBOARD_SCHEMA_VERSION: &str = "govfuzz.dashboard.v1";
pub const CI_DASHBOARD_SCHEMA_VERSION: &str = "govfuzz.ci.dashboard.v1";
pub const SBOM_SCHEMA_VERSION: &str = "govfuzz.sbom.v1";
pub const VULNERABILITY_SCHEMA_VERSION: &str = "govfuzz.vulnerabilities.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    pub work_dir: PathBuf,
    pub out: PathBuf,
    pub bundle_dir: Option<PathBuf>,
    pub policy: Option<PathBuf>,
    pub update_packs: Vec<PathBuf>,
    pub audit_log: Option<PathBuf>,
    pub runner_manifest: Option<PathBuf>,
    pub runner_plan: Option<PathBuf>,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomOptions {
    pub root: PathBuf,
    pub out_dir: PathBuf,
    pub vuln_db: Option<PathBuf>,
    pub policy: Option<PathBuf>,
    pub binary_inventories: Vec<PathBuf>,
    pub fail_on: Option<String>,
    /// Which artifacts `write_sbom` emits. Defaults to all of them (the VEX
    /// outputs are part of the default differentiator).
    pub emit: EmitSet,
    /// Restrict discovery to these `Cataloger::ecosystem()` labels. `None`
    /// runs every cataloger that `detect()`s the tree (the prior behavior).
    pub ecosystems: Option<Vec<String>>,
    /// Explicit `auto/run.json` for runtime/fuzz enrich evidence. When set it is
    /// consulted IN ADDITION to the auto-detected conventional locations.
    pub run_json: Option<PathBuf>,
}

impl Default for SbomOptions {
    fn default() -> Self {
        SbomOptions {
            root: PathBuf::new(),
            out_dir: PathBuf::new(),
            vuln_db: None,
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            emit: EmitSet::all(),
            ecosystems: None,
            run_json: None,
        }
    }
}

/// One emittable SBOM artifact. `CyclonedxVex` is the CycloneDX `analysis`
/// (VEX) embedding rather than a separate file — it modulates `cyclonedx.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EmitKind {
    /// `sbom.json` — the native GovFuzz component inventory.
    Sbom,
    /// `cyclonedx.json` — the CycloneDX SBOM (with base vulnerabilities).
    Cyclonedx,
    /// `vulnerabilities.json` — the offline CVE match report.
    Vulnerabilities,
    /// `openvex.json` — the OpenVEX assessment document.
    Openvex,
    /// CSV outputs for spreadsheet / procurement / vuln-triage ingestion:
    /// `sbom.csv` (a flat one-row-per-component inventory) AND
    /// `vulnerabilities.csv` (one row per CVE match, carrying the `cwe` column).
    Csv,
    /// Embed the per-vulnerability CycloneDX `analysis` (VEX) into `cyclonedx.json`.
    CyclonedxVex,
    /// `sbom.spdx.json` — an SPDX-2.3 JSON document (procurement mandate format).
    /// Opt-in (not in the default `all()` set) so existing consumers are
    /// unchanged; select via `--emit spdx-json` or the `--format spdx-json` alias.
    SpdxJson,
}

impl EmitKind {
    /// The hyphenated CLI/spec name for this artifact.
    pub fn as_str(self) -> &'static str {
        match self {
            EmitKind::Sbom => "sbom",
            EmitKind::Cyclonedx => "cyclonedx",
            EmitKind::Vulnerabilities => "vulnerabilities",
            EmitKind::Openvex => "openvex",
            EmitKind::Csv => "csv",
            EmitKind::CyclonedxVex => "cyclonedx-vex",
            EmitKind::SpdxJson => "spdx-json",
        }
    }

    /// Parse a single emit name. Unknown names are rejected (typo safety).
    pub fn parse(name: &str) -> Result<Self, GovernanceError> {
        match name.trim() {
            "sbom" => Ok(EmitKind::Sbom),
            "cyclonedx" => Ok(EmitKind::Cyclonedx),
            "vulnerabilities" => Ok(EmitKind::Vulnerabilities),
            "openvex" => Ok(EmitKind::Openvex),
            "csv" => Ok(EmitKind::Csv),
            "cyclonedx-vex" => Ok(EmitKind::CyclonedxVex),
            "spdx-json" => Ok(EmitKind::SpdxJson),
            other => Err(GovernanceError::InvalidInput {
                message: format!(
                    "unknown --emit value '{other}' (expected one of: \
                     cyclonedx, sbom, vulnerabilities, openvex, csv, cyclonedx-vex, spdx-json)"
                ),
            }),
        }
    }
}

/// The set of artifacts to emit. Ordered/deduped for determinism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitSet {
    kinds: std::collections::BTreeSet<EmitKind>,
}

impl EmitSet {
    /// Every artifact, including the VEX differentiator. The default.
    pub fn all() -> Self {
        EmitSet {
            kinds: [
                EmitKind::Sbom,
                EmitKind::Cyclonedx,
                EmitKind::Vulnerabilities,
                EmitKind::Openvex,
                EmitKind::Csv,
                EmitKind::CyclonedxVex,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Build from an explicit selection. Empty input is rejected.
    pub fn from_kinds(kinds: impl IntoIterator<Item = EmitKind>) -> Result<Self, GovernanceError> {
        let kinds: std::collections::BTreeSet<EmitKind> = kinds.into_iter().collect();
        if kinds.is_empty() {
            return Err(GovernanceError::InvalidInput {
                message: "--emit selection must name at least one artifact".to_owned(),
            });
        }
        Ok(EmitSet { kinds })
    }

    /// Parse a comma-separated emit list (e.g. `"sbom,openvex"`). Whitespace and
    /// empty segments are ignored; an unknown name is a hard error.
    pub fn parse_list(list: &str) -> Result<Self, GovernanceError> {
        let mut kinds = Vec::new();
        for segment in list.split(',') {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                continue;
            }
            kinds.push(EmitKind::parse(trimmed)?);
        }
        Self::from_kinds(kinds)
    }

    /// Fold additional emit kinds into the set (additive; order-independent).
    pub fn with_kinds(mut self, kinds: impl IntoIterator<Item = EmitKind>) -> Self {
        self.kinds.extend(kinds);
        self
    }

    /// Force the two VEX outputs into the set (the `--vex` convenience alias).
    pub fn with_vex(mut self) -> Self {
        self.kinds.insert(EmitKind::Openvex);
        self.kinds.insert(EmitKind::CyclonedxVex);
        self
    }

    /// Is this artifact selected?
    pub fn contains(&self, kind: EmitKind) -> bool {
        self.kinds.contains(&kind)
    }
}

impl Default for EmitSet {
    fn default() -> Self {
        EmitSet::all()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomSummary {
    pub sbom_path: PathBuf,
    pub cyclonedx_path: PathBuf,
    pub vulnerability_path: PathBuf,
    pub openvex_path: PathBuf,
    pub csv_path: PathBuf,
    /// `vulnerabilities.csv` — the CVE matches as flat CSV (with a `cwe` column),
    /// written alongside `sbom.csv` under the `csv` emit kind.
    pub vulnerability_csv_path: PathBuf,
    /// `sbom.spdx.json` — the SPDX-2.3 document, written under `spdx-json`.
    pub spdx_path: PathBuf,
    /// Absolute paths of the artifacts actually written, in `EmitKind` order.
    /// `cyclonedx-vex` is reflected as an attribute of `cyclonedx.json`, not its
    /// own entry, so it never appears here.
    pub written: Vec<PathBuf>,
    pub components: usize,
    pub matches: usize,
    pub gate_failed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
    #[error("{message}")]
    InvalidInput { message: String },
    #[error("missing required field `{field}` in {path}", path = path.display())]
    MissingField { path: PathBuf, field: &'static str },
}

impl From<sbom_ingest::CatalogError> for GovernanceError {
    fn from(error: sbom_ingest::CatalogError) -> Self {
        match error {
            sbom_ingest::CatalogError::Io { source, .. } => GovernanceError::Io(source),
            sbom_ingest::CatalogError::Malformed { kind, path, detail } => {
                GovernanceError::InvalidInput {
                    message: format!(
                        "malformed {kind} manifest at {path}: {detail}",
                        path = path.display()
                    ),
                }
            }
        }
    }
}

pub fn validate_policy_file(path: &Path) -> Result<Value, GovernanceError> {
    let value = read_json(path)?;
    let policy_id = string_field(&value, "policy_id")
        .ok_or_else(|| missing(path, "policy_id"))?
        .to_owned();
    let languages = string_array(value.get("languages"));
    let enabled_rules = string_array(value.pointer("/rules/enabled"));
    let disabled_rules = string_array(value.pointer("/rules/disabled"));
    let allowed_runners = string_array(value.pointer("/runners/allowed"));
    let require_sandbox = value
        .pointer("/runners/require_sandbox")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let allowed_pack_kinds = string_array(value.pointer("/update_packs/allowed_kinds"));
    let require_pack_signature = value
        .pointer("/update_packs/require_signature")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let trusted_pack_keys = string_array(value.pointer("/update_packs/trusted_keys"));
    let fail_on_severity = value
        .pointer("/ci/fail_on_severity")
        .and_then(Value::as_str)
        .unwrap_or("any");
    let fail_on_actionability = value
        .pointer("/ci/fail_on_actionability")
        .and_then(Value::as_str)
        .unwrap_or("any");
    let required_artifacts = string_array(value.pointer("/ci/require_artifacts"));
    let waiver_ids = value
        .pointer("/ci/waivers")
        .and_then(Value::as_array)
        .map(|waivers| {
            waivers
                .iter()
                .filter_map(|waiver| waiver.get("id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let baseline_findings = string_array(value.pointer("/ci/baseline_findings"));

    Ok(json!({
        "schema_version": POLICY_VALIDATION_SCHEMA_VERSION,
        "valid": true,
        "policy_id": policy_id,
        "source": path_string(path),
        "languages": languages,
        "rules": {
            "enabled": enabled_rules.len(),
            "disabled": disabled_rules.len(),
            "enabled_ids": enabled_rules,
            "disabled_ids": disabled_rules
        },
        "runners": {
            "allowed": allowed_runners.len(),
            "allowed_ids": allowed_runners,
            "require_sandbox": require_sandbox
        },
        "ci": {
            "fail_on_severity": fail_on_severity,
            "fail_on_actionability": fail_on_actionability,
            "require_artifacts": required_artifacts,
            "waivers": waiver_ids.len(),
            "waiver_ids": waiver_ids,
            "baseline_findings": baseline_findings
        },
        "update_packs": {
            "allowed_kinds": allowed_pack_kinds,
            "require_signature": require_pack_signature,
            "trusted_keys": trusted_pack_keys
        }
    }))
}

pub fn explain_policy_file(path: &Path) -> Result<Value, GovernanceError> {
    let bytes = fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let summary = validate_policy_file(path)?;
    Ok(json!({
        "schema_version": POLICY_EXPLAIN_SCHEMA_VERSION,
        "policy_id": value.get("policy_id").and_then(Value::as_str).unwrap_or("unknown"),
        "version": value.get("version").and_then(Value::as_str),
        "source": path_string(path),
        "policy_hash": sha256_hex(&bytes),
        "summary": summary,
        "decisions": {
            "disabled_rules": string_array(value.pointer("/rules/disabled")),
            "denied_external_tools": string_array(value.pointer("/external_tools/denied")),
            "allowed_runners": string_array(value.pointer("/runners/allowed")),
            "require_sandbox": value.pointer("/runners/require_sandbox").and_then(Value::as_bool).unwrap_or(false),
            "ci": value.get("ci").cloned().unwrap_or_else(|| json!({}))
        }
    }))
}

pub fn policy_dry_run_file(policy: &Path, finding: &Path) -> Result<Value, GovernanceError> {
    let policy_value = read_json(policy)?;
    let finding_value = read_json(finding)?;
    let policy_id = policy_value
        .get("policy_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let disabled_rules = string_array(policy_value.pointer("/rules/disabled"));
    let denied_tools = string_array(policy_value.pointer("/external_tools/denied"));
    let allowed_runners = string_array(policy_value.pointer("/runners/allowed"));
    let require_sandbox = policy_value
        .pointer("/runners/require_sandbox")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rule_id = finding_value
        .get("rule_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let runner_id = finding_value
        .pointer("/runner/profile_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let runner_caps = string_array(finding_value.pointer("/runner/capabilities"));
    let severity = finding_value
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let finding_id = finding_identifier(&finding_value).unwrap_or_default();
    let waiver = matching_policy_waiver(&policy_value, &finding_value);
    let waived = waiver.is_some();
    let waiver_id = waiver
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let fail_on = policy_value
        .pointer("/ci/fail_on_severity")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let rule_enabled = !disabled_rules.iter().any(|disabled| disabled == rule_id);
    let runner_allowed =
        allowed_runners.is_empty() || allowed_runners.iter().any(|allowed| allowed == runner_id);
    let sandbox_ok = !require_sandbox || runner_caps.iter().any(|cap| cap == "sandbox");
    let ci_gate = if waived {
        "pass"
    } else if severity_rank(severity) >= severity_rank(fail_on) && fail_on != "none" {
        "fail"
    } else {
        "pass"
    };
    Ok(json!({
        "schema_version": POLICY_DRY_RUN_SCHEMA_VERSION,
        "policy": {
            "policy_id": policy_id,
            "source": path_string(policy)
        },
        "finding": {
            "source": path_string(finding),
            "id": finding_id,
            "rule_id": rule_id,
            "severity": severity
        },
        "decisions": {
            "rule_enabled": rule_enabled,
            "runner_allowed": runner_allowed,
            "sandbox_ok": sandbox_ok,
            "waived": waived,
            "waiver_id": waiver_id,
            "ci_gate": ci_gate,
            "denied_external_tools": denied_tools
        }
    }))
}

pub fn validate_runners_file(path: &Path) -> Result<Value, GovernanceError> {
    let value = read_json(path)?;
    let runners = value
        .get("runners")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let diagnostics = runner_diagnostics(&runners);
    let valid = diagnostics.is_empty();

    Ok(json!({
        "schema_version": RUNNERS_VALIDATION_SCHEMA_VERSION,
        "valid": valid,
        "source": path_string(path),
        "counts": {
            "runners": runners.len()
        },
        "runners": runners,
        "diagnostics": diagnostics
    }))
}

pub fn runner_list_file(path: &Path) -> Result<Value, GovernanceError> {
    let summary = validate_runners_file(path)?;
    let mut by_kind = BTreeMap::<String, usize>::new();
    for runner in summary
        .get("runners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = runner
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *by_kind.entry(kind.to_owned()).or_insert(0) += 1;
    }
    Ok(json!({
        "schema_version": RUNNERS_VALIDATION_SCHEMA_VERSION,
        "valid": summary.get("valid").and_then(Value::as_bool).unwrap_or(false),
        "source": path_string(path),
        "counts": {
            "runners": summary.pointer("/counts/runners").and_then(Value::as_u64).unwrap_or(0),
            "by_kind": by_kind
        },
        "runners": summary.get("runners").cloned().unwrap_or_else(|| json!([])),
        "diagnostics": summary.get("diagnostics").cloned().unwrap_or_else(|| json!([]))
    }))
}

pub fn runner_select_file(path: &Path, runner_id: &str) -> Result<Value, GovernanceError> {
    let value = read_json(path)?;
    let runner = find_runner(&value, runner_id)
        .cloned()
        .unwrap_or(Value::Null);
    let valid = !runner.is_null();
    Ok(json!({
        "schema_version": RUNNER_SELECTION_SCHEMA_VERSION,
        "valid": valid,
        "source": path_string(path),
        "runner": runner,
        "capability_evidence": runner_capability_evidence(&runner),
        "diagnostics": if valid { json!([]) } else { json!([{"path": "/runners", "message": format!("runner '{runner_id}' not found")}]) }
    }))
}

pub fn runner_handoff_file(
    manifest: &Path,
    runner_id: &str,
    work_dir: &Path,
    out: &Path,
) -> Result<Value, GovernanceError> {
    let selected = runner_select_file(manifest, runner_id)?;
    let runner = selected.get("runner").cloned().unwrap_or(Value::Null);
    let mut artifacts = Vec::new();
    collect_artifacts_by_prefix(work_dir, "findings", "finding", &mut artifacts)?;
    collect_artifacts_by_prefix(work_dir, "reports", "report", &mut artifacts)?;
    artifacts.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });
    let handoff = json!({
        "schema_version": RUNNER_HANDOFF_SCHEMA_VERSION,
        "valid": selected.get("valid").and_then(Value::as_bool).unwrap_or(false),
        "work_dir": path_string(work_dir),
        "runner_manifest": path_string(manifest),
        "selected_runner": runner,
        "capability_evidence": selected.get("capability_evidence").cloned().unwrap_or_else(|| json!({})),
        "artifacts": artifacts
    });
    write_json(out, &handoff)?;
    Ok(handoff)
}

pub fn runner_lease_file(
    handoff: &Path,
    runner_id: &str,
    lease_id: &str,
    out: &Path,
) -> Result<Value, GovernanceError> {
    let value = read_json(handoff)?;
    let selected_runner = value.get("selected_runner").cloned().unwrap_or(Value::Null);
    let selected_id = selected_runner
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut diagnostics = Vec::new();
    if selected_id != runner_id {
        diagnostics.push(json!({
            "path": "/selected_runner/id",
            "message": format!("handoff runner '{selected_id}' does not match requested runner '{runner_id}'")
        }));
    }
    if lease_id.trim().is_empty() {
        diagnostics.push(json!({
            "path": "/lease/id",
            "message": "missing lease id"
        }));
    }
    let valid =
        value.get("valid").and_then(Value::as_bool).unwrap_or(false) && diagnostics.is_empty();
    let artifacts = value
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let jobs = artifacts
        .iter()
        .enumerate()
        .map(|(index, artifact)| {
            json!({
                "id": format!("{lease_id}-job-{index:04}", index = index + 1),
                "state": "leased",
                "artifact": artifact
            })
        })
        .collect::<Vec<_>>();
    let lease = json!({
        "schema_version": RUNNER_LEASE_SCHEMA_VERSION,
        "valid": valid,
        "source": path_string(handoff),
        "work_dir": value.get("work_dir").cloned().unwrap_or(Value::Null),
        "runner_manifest": value.get("runner_manifest").cloned().unwrap_or(Value::Null),
        "runner": selected_runner,
        "lease": {
            "id": lease_id,
            "status": if valid { "leased" } else { "invalid" },
            "heartbeat_required": true
        },
        "jobs": jobs,
        "diagnostics": diagnostics
    });
    write_json(out, &lease)?;
    Ok(lease)
}

pub fn runner_complete_file(
    lease: &Path,
    artifact_paths: &[PathBuf],
    out: &Path,
) -> Result<Value, GovernanceError> {
    let lease_value = read_json(lease)?;
    let lease_id = lease_value
        .pointer("/lease/id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut artifacts = Vec::new();
    for path in artifact_paths {
        if path.is_file() {
            artifacts.push(artifact("runner_result", &path_string(path), path)?);
        }
    }
    let valid = lease_value
        .get("valid")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let completion = json!({
        "schema_version": RUNNER_COMPLETION_SCHEMA_VERSION,
        "valid": valid,
        "status": if valid { "completed" } else { "invalid" },
        "source": path_string(lease),
        "lease": {
            "id": lease_id,
            "source": path_string(lease)
        },
        "runner": lease_value.get("runner").cloned().unwrap_or(Value::Null),
        "jobs_completed": lease_value
            .get("jobs")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        "artifacts": artifacts
    });
    write_json(out, &completion)?;
    Ok(completion)
}

pub fn runner_plan_file(
    manifest: &Path,
    queue: &Path,
    policy: Option<&Path>,
    out: &Path,
) -> Result<Value, GovernanceError> {
    let manifest_value = read_json(manifest)?;
    let queue_value = read_json(queue)?;
    let policy_value = policy.map(read_json).transpose()?;
    let runners = manifest_value
        .get("runners")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let manifest_diagnostics = runner_diagnostics(&runners);
    let jobs = queue_value
        .get("jobs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let policy_summary = runner_plan_policy_summary(policy_value.as_ref());
    let allowed_runners = string_array(policy_value.as_ref().and_then(|value| {
        value
            .pointer("/runners/allowed")
            .or_else(|| value.get("allowed_runners"))
    }));
    let require_sandbox = policy_value
        .as_ref()
        .and_then(|value| value.pointer("/runners/require_sandbox"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let denied_external_tools = string_array(policy_value.as_ref().and_then(|value| {
        value
            .pointer("/external_tools/denied")
            .or_else(|| value.pointer("/runners/denied_required_tools"))
    }));
    let mut runner_states = runners
        .into_iter()
        .map(RunnerPlanState::new)
        .collect::<Vec<_>>();
    let mut assignments = Vec::new();
    let mut unassigned = Vec::new();
    let mut diagnostics = manifest_diagnostics.clone();

    for (index, job) in jobs.iter().enumerate() {
        let job_id = job_id(job, index);
        if let Some(tool) = denied_job_tool(job, &denied_external_tools) {
            let reason = "denied_external_tool";
            let diagnostic = json!({
                "path": format!("/jobs/{index}/required_tools"),
                "job_id": job_id,
                "reason": reason,
                "message": format!("job requires denied external tool '{tool}'")
            });
            diagnostics.push(diagnostic.clone());
            unassigned.push(json!({
                "job_id": job_id,
                "reason": reason,
                "job": job,
                "diagnostics": [diagnostic]
            }));
            continue;
        }

        let mut blocked_by_capacity = false;
        let mut rejected_candidates = Vec::new();
        let mut selected = None;
        for (runner_index, state) in runner_states.iter().enumerate() {
            match runner_job_compatibility(&state.runner, job, &allowed_runners, require_sandbox) {
                RunnerCompatibility::Compatible => {
                    if state.has_capacity_for(job) {
                        selected = Some(runner_index);
                        break;
                    }
                    blocked_by_capacity = true;
                    rejected_candidates.push(json!({
                        "runner_id": state.id,
                        "reason": "capacity_exhausted"
                    }));
                }
                RunnerCompatibility::Rejected(reason) => {
                    rejected_candidates.push(json!({
                        "runner_id": state.id,
                        "reason": reason
                    }));
                }
            }
        }

        if let Some(runner_index) = selected {
            let state = &mut runner_states[runner_index];
            state.assign(job);
            assignments.push(json!({
                "job_id": job_id,
                "runner_id": state.id,
                "lease_hint": format!("{}-job-{:04}", state.id, state.assigned_jobs),
                "estimated_seconds": estimated_seconds(job),
                "job": job,
                "runner": {
                    "id": state.id,
                    "kind": state.runner.get("kind").and_then(Value::as_str),
                    "target": state.runner.get("target").and_then(Value::as_str)
                },
                "policy": {
                    "runner_allowed": runner_allowed(&allowed_runners, &state.id),
                    "sandbox_required": require_sandbox
                }
            }));
        } else {
            let reason = if blocked_by_capacity {
                "capacity_exhausted"
            } else {
                "no_compatible_runner"
            };
            let diagnostic = json!({
                "path": format!("/jobs/{index}"),
                "job_id": job_id,
                "reason": reason,
                "message": "job could not be assigned to an allowed compatible runner"
            });
            diagnostics.push(diagnostic.clone());
            unassigned.push(json!({
                "job_id": job_id,
                "reason": reason,
                "job": job,
                "diagnostics": [diagnostic],
                "rejected_candidates": rejected_candidates
            }));
        }
    }

    let plan = json!({
        "schema_version": RUNNER_PLAN_SCHEMA_VERSION,
        "valid": manifest_diagnostics.is_empty() && unassigned.is_empty(),
        "source": {
            "runner_manifest": path_string(manifest),
            "queue": path_string(queue),
            "policy": policy.map(path_string)
        },
        "counts": {
            "jobs": jobs.len(),
            "assigned": assignments.len(),
            "unassigned": unassigned.len(),
            "runners_considered": runner_states.len()
        },
        "policy": policy_summary,
        "assignments": assignments,
        "unassigned": unassigned,
        "runners": runner_states
            .iter()
            .map(RunnerPlanState::summary)
            .collect::<Vec<_>>(),
        "diagnostics": diagnostics
    });
    write_json(out, &plan)?;
    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
pub fn create_update_pack_file(
    root: &Path,
    pack_id: &str,
    version: Option<&str>,
    item_specs: &[String],
    license: Option<&str>,
    required_tools: &[String],
    sign_key: Option<&str>,
    out: &Path,
) -> Result<Value, GovernanceError> {
    if pack_id.trim().is_empty() {
        return Err(GovernanceError::InvalidInput {
            message: "pack id must not be empty".to_owned(),
        });
    }
    if item_specs.is_empty() {
        return Err(GovernanceError::InvalidInput {
            message: "at least one --item kind:path entry is required".to_owned(),
        });
    }

    let mut items = Vec::new();
    for spec in item_specs {
        let (kind, rel_path) = parse_pack_item_spec(spec)?;
        let absolute = root.join(&rel_path);
        let bytes = fs::read(&absolute).map_err(|error| GovernanceError::InvalidInput {
            message: format!("pack item '{}' could not be read: {error}", rel_path),
        })?;
        let mut item = json!({
            "kind": kind,
            "path": rel_path,
            "sha256": sha256_hex(&bytes)
        });
        if let Some(license) = license {
            item["license"] = json!(license);
        }
        if !required_tools.is_empty() {
            item["required_tools"] = json!(required_tools);
        }
        items.push(item);
    }
    items.sort_by(|left, right| {
        left.get("kind")
            .and_then(Value::as_str)
            .cmp(&right.get("kind").and_then(Value::as_str))
            .then_with(|| {
                left.get("path")
                    .and_then(Value::as_str)
                    .cmp(&right.get("path").and_then(Value::as_str))
            })
    });

    let mut manifest = json!({
        "schema_version": "govfuzz.update_pack.v1",
        "pack_id": pack_id,
        "version": version.unwrap_or("unknown"),
        "root": path_string(root),
        "items": items
    });
    if let Some(sign_key) = sign_key {
        let digest = pack_items_signature_digest(
            manifest
                .get("items")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        manifest["signature"] = json!({
            "algorithm": "sha256-items-v1",
            "key_id": sign_key,
            "digest": digest
        });
    }
    write_json(out, &manifest)?;
    Ok(manifest)
}

pub fn verify_update_pack_file(manifest: &Path, root: &Path) -> Result<Value, GovernanceError> {
    verify_update_pack_file_with_policy(manifest, root, None)
}

pub fn verify_update_pack_file_with_policy(
    manifest: &Path,
    root: &Path,
    policy: Option<&Path>,
) -> Result<Value, GovernanceError> {
    let value = read_json(manifest)?;
    let pack_id = string_field(&value, "pack_id")
        .ok_or_else(|| missing(manifest, "pack_id"))?
        .to_owned();
    let version = string_field(&value, "version")
        .unwrap_or("unknown")
        .to_owned();
    let mut valid = true;
    let policy_value = policy.map(read_json).transpose()?;
    let mut items = Vec::new();
    let mut diagnostics = Vec::new();

    for item in value
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let rel_path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let expected = item.get("sha256").and_then(Value::as_str).unwrap_or("");
        let absolute = root.join(rel_path);
        let (status, actual) = match fs::read(&absolute) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual == expected {
                    ("verified", actual)
                } else {
                    valid = false;
                    ("mismatch", actual)
                }
            }
            Err(_) => {
                valid = false;
                ("missing", String::new())
            }
        };
        let policy_decisions = pack_item_policy_decisions(item, policy_value.as_ref());
        for decision in &policy_decisions {
            if decision
                .get("allowed")
                .and_then(Value::as_bool)
                .is_some_and(|allowed| !allowed)
            {
                valid = false;
                diagnostics.push(decision.clone());
            }
        }
        items.push(json!({
            "kind": kind,
            "path": rel_path,
            "status": status,
            "sha256": actual,
            "expected_sha256": expected,
            "license": item.get("license").and_then(Value::as_str),
            "required_tools": string_array(item.get("required_tools")),
            "policy_decisions": policy_decisions
        }));
    }
    let (signature, signature_diagnostics, signature_valid) =
        update_pack_signature_summary(&value, policy_value.as_ref());
    if !signature_valid {
        valid = false;
    }
    diagnostics.extend(signature_diagnostics);

    Ok(json!({
        "schema_version": UPDATE_PACK_VERIFICATION_SCHEMA_VERSION,
        "valid": valid,
        "pack_id": pack_id,
        "version": version,
        "manifest": path_string(manifest),
        "root": path_string(root),
        "policy": policy.map(path_string),
        "signature": signature,
        "items": items,
        "diagnostics": diagnostics
    }))
}

pub fn inspect_update_pack_file(manifest: &Path) -> Result<Value, GovernanceError> {
    let value = read_json(manifest)?;
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by_kind = BTreeMap::new();
    for item in &items {
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *by_kind.entry(kind.to_owned()).or_insert(0usize) += 1;
    }
    Ok(json!({
        "schema_version": UPDATE_PACK_INSPECTION_SCHEMA_VERSION,
        "pack_id": value.get("pack_id").and_then(Value::as_str).unwrap_or("unknown"),
        "version": value.get("version").and_then(Value::as_str).unwrap_or("unknown"),
        "manifest": path_string(manifest),
        "counts": {
            "items": items.len(),
            "by_kind": by_kind
        },
        "items": items
    }))
}

pub fn install_update_pack_file(
    manifest: &Path,
    root: &Path,
    install_dir: &Path,
    policy: Option<&Path>,
) -> Result<Value, GovernanceError> {
    let verified = verify_update_pack_file_with_policy(manifest, root, policy)?;
    if verified.get("valid").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "schema_version": UPDATE_PACK_INSTALL_SCHEMA_VERSION,
            "valid": false,
            "verified": verified
        }));
    }
    let pack_id = verified
        .get("pack_id")
        .and_then(Value::as_str)
        .unwrap_or("pack");
    // pack_id and every item path come from the untrusted manifest.
    // Reject any that could escape install_dir (absolute, root,
    // prefix, or `..`) so a hostile pack cannot zip-slip arbitrary
    // file writes outside the install directory.
    if path_escapes_root(pack_id) {
        return Err(GovernanceError::InvalidInput {
            message: format!(
                "update-pack pack_id '{pack_id}' must be a relative path under the install dir"
            ),
        });
    }
    let target = install_dir.join(pack_id);
    fs::create_dir_all(&target)?;
    fs::copy(manifest, target.join("pack.json"))?;
    for item in verified
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let rel = item.get("path").and_then(Value::as_str).unwrap_or("");
        if rel.is_empty() {
            continue;
        }
        if path_escapes_root(rel) {
            return Err(GovernanceError::InvalidInput {
                message: format!("update-pack item path '{rel}' must be relative to the pack root"),
            });
        }
        let src = root.join(rel);
        let dst = target.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    let installed = json!({
        "schema_version": UPDATE_PACK_INSTALL_SCHEMA_VERSION,
        "valid": true,
        "pack_id": pack_id,
        "install_dir": path_string(&target),
        "verified": verified
    });
    fs::write(
        target.join("install.json"),
        serde_json::to_vec_pretty(&installed)?,
    )?;
    Ok(installed)
}

pub fn write_export_manifest(options: &ExportOptions) -> Result<Value, GovernanceError> {
    let mut artifacts = Vec::new();
    collect_work_artifact(
        &options.work_dir,
        "reports/run-last.json",
        "report_json",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "reports/run-last.md",
        "report_markdown",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "reports/run-last.sarif",
        "sarif",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "reports/run-last.junit.xml",
        "junit",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "static/static-report.json",
        "static_report",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "static/static-report.sarif",
        "static_sarif",
        &mut artifacts,
    )?;
    collect_work_artifact(&options.work_dir, "sbom/sbom.json", "sbom", &mut artifacts)?;
    collect_work_artifact(
        &options.work_dir,
        "sbom/cyclonedx.json",
        "cyclonedx_sbom",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "sbom/vulnerabilities.json",
        "vulnerability_report",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "auto/run.json",
        "auto_run",
        &mut artifacts,
    )?;
    collect_work_artifact(
        &options.work_dir,
        "auto/run.md",
        "auto_markdown",
        &mut artifacts,
    )?;
    collect_artifacts_by_name(
        &options.work_dir,
        "findings",
        "testcase.bin",
        "replay_input",
        &mut artifacts,
    )?;
    collect_artifacts_by_prefix(
        &options.work_dir,
        "evidence",
        "validation_evidence",
        &mut artifacts,
    )?;

    if let Some(policy) = &options.policy {
        collect_external_artifact(policy, "policy", &mut artifacts)?;
    }
    for pack in &options.update_packs {
        collect_external_artifact(pack, "update_pack", &mut artifacts)?;
    }
    if let Some(audit_log) = &options.audit_log {
        collect_external_artifact(audit_log, "audit_log", &mut artifacts)?;
    }
    if let Some(runner_manifest) = &options.runner_manifest {
        collect_external_artifact(runner_manifest, "runner_manifest", &mut artifacts)?;
    }
    if let Some(runner_plan) = &options.runner_plan {
        collect_external_artifact(runner_plan, "runner_plan", &mut artifacts)?;
    }
    artifacts.sort_by(|left, right| {
        left.get("kind")
            .and_then(Value::as_str)
            .cmp(&right.get("kind").and_then(Value::as_str))
            .then_with(|| {
                left.get("path")
                    .and_then(Value::as_str)
                    .cmp(&right.get("path").and_then(Value::as_str))
            })
    });
    let missing_required = missing_required_artifacts(&artifacts, &options.required_artifacts);
    let governance = export_governance_summary(options)?;
    let bundle = if let Some(bundle_dir) = &options.bundle_dir {
        materialize_export_bundle(bundle_dir, &mut artifacts)?
    } else {
        json!({
            "materialized": false,
            "path": Value::Null,
            "manifest_path": Value::Null
        })
    };
    let public_artifacts = artifacts.iter().map(public_artifact).collect::<Vec<_>>();

    let manifest = json!({
        "schema_version": EXPORT_SCHEMA_VERSION,
        "work_dir": path_string(&options.work_dir),
        "counts": {
            "artifacts": public_artifacts.len()
        },
        "artifacts": public_artifacts,
        "governance": governance,
        "bundle": bundle,
        "required_artifacts": {
            "requested": options.required_artifacts,
            "missing": missing_required
        }
    });

    if let Some(parent) = options.out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.out, serde_json::to_vec_pretty(&manifest)?)?;
    if let Some(bundle_dir) = &options.bundle_dir {
        fs::write(
            bundle_dir.join("export-manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
    }
    Ok(manifest)
}

fn export_governance_summary(options: &ExportOptions) -> Result<Value, GovernanceError> {
    let policy_bytes = options.policy.as_ref().map(fs::read).transpose()?;
    let policy_hash = policy_bytes.as_ref().map(|bytes| sha256_hex(bytes));
    let policy_value = policy_bytes
        .as_ref()
        .map(|bytes| serde_json::from_slice::<Value>(bytes))
        .transpose()?;
    let mut update_packs = Vec::new();
    for pack in &options.update_packs {
        let value = read_json(pack)?;
        let (signature, _, _) = update_pack_signature_summary(&value, policy_value.as_ref());
        update_packs.push(json!({
            "path": path_string(pack),
            "pack_id": value.get("pack_id").and_then(Value::as_str).unwrap_or("unknown"),
            "version": value.get("version").and_then(Value::as_str).unwrap_or("unknown"),
            "signature": signature
        }));
    }
    let audit_events = options
        .audit_log
        .as_ref()
        .map(|path| {
            read_audit_log(path).map(|value| {
                value
                    .pointer("/counts/events")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
        })
        .transpose()?;
    let runner_count = options
        .runner_manifest
        .as_ref()
        .map(|path| {
            runner_list_file(path).map(|value| {
                value
                    .pointer("/counts/runners")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
        })
        .transpose()?;
    let runner_plan = options
        .runner_plan
        .as_ref()
        .map(|path| runner_plan_budget_summary(path))
        .transpose()?;

    Ok(json!({
        "policy_hash": policy_hash,
        "update_packs": update_packs,
        "audit_events": audit_events,
        "runners": {
            "count": runner_count
        },
        "runner_plan": runner_plan
    }))
}

pub fn write_sbom(options: &SbomOptions) -> Result<SbomSummary, GovernanceError> {
    let emit = &options.emit;
    let components = discover_components(options)?;
    let sbom = render_sbom(&options.root, &components);
    let vulnerabilities = match_vulnerabilities(options, &components)?;
    let mut cyclonedx = render_cyclonedx_sbom(&options.root, &components);
    // The base CycloneDX `vulnerabilities` array belongs to `cyclonedx`; the
    // per-vuln `analysis` (VEX) embedding is gated on `cyclonedx-vex`.
    if emit.contains(EmitKind::Cyclonedx) {
        attach_cyclonedx_vulnerabilities(&mut cyclonedx, &vulnerabilities);
        if !emit.contains(EmitKind::CyclonedxVex) {
            strip_cyclonedx_vex_analysis(&mut cyclonedx);
        }
    }
    let openvex = render_openvex_document(&vulnerabilities);

    fs::create_dir_all(&options.out_dir)?;
    let sbom_path = options.out_dir.join("sbom.json");
    let cyclonedx_path = options.out_dir.join("cyclonedx.json");
    let vulnerability_path = options.out_dir.join("vulnerabilities.json");
    let openvex_path = options.out_dir.join("openvex.json");
    let csv_path = options.out_dir.join("sbom.csv");
    let vulnerability_csv_path = options.out_dir.join("vulnerabilities.csv");
    let spdx_path = options.out_dir.join("sbom.spdx.json");

    let mut written = Vec::new();
    if emit.contains(EmitKind::Sbom) {
        fs::write(&sbom_path, serde_json::to_vec_pretty(&sbom)?)?;
        written.push(sbom_path.clone());
    }
    if emit.contains(EmitKind::Cyclonedx) {
        fs::write(&cyclonedx_path, serde_json::to_vec_pretty(&cyclonedx)?)?;
        written.push(cyclonedx_path.clone());
    }
    if emit.contains(EmitKind::Vulnerabilities) {
        fs::write(
            &vulnerability_path,
            serde_json::to_vec_pretty(&vulnerabilities)?,
        )?;
        written.push(vulnerability_path.clone());
    }
    if emit.contains(EmitKind::Openvex) {
        fs::write(&openvex_path, serde_json::to_vec_pretty(&openvex)?)?;
        written.push(openvex_path.clone());
    }
    if emit.contains(EmitKind::Csv) {
        // The `csv` kind emits BOTH the component inventory and the CVE matches as
        // flat CSV, so a spreadsheet / SCA pipeline gets the vulnerabilities (with
        // their CWE column) alongside the inventory.
        fs::write(&csv_path, render_sbom_csv(&components))?;
        written.push(csv_path.clone());
        fs::write(
            &vulnerability_csv_path,
            render_vulnerabilities_csv(&vulnerabilities),
        )?;
        written.push(vulnerability_csv_path.clone());
    }
    if emit.contains(EmitKind::SpdxJson) {
        let spdx = render_spdx_document(&options.root, &components);
        fs::write(&spdx_path, serde_json::to_vec_pretty(&spdx)?)?;
        written.push(spdx_path.clone());
    }

    Ok(SbomSummary {
        sbom_path,
        cyclonedx_path,
        vulnerability_path,
        openvex_path,
        csv_path,
        vulnerability_csv_path,
        spdx_path,
        written,
        components: components.len(),
        matches: vulnerabilities
            .get("matches")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        gate_failed: vulnerabilities
            .pointer("/gate/failed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Drop the per-vulnerability CycloneDX `analysis` (VEX) blocks when
/// `cyclonedx-vex` is not selected — the base CycloneDX SBOM still carries the
/// vulnerabilities, just without the VEX assessment.
fn strip_cyclonedx_vex_analysis(cyclonedx: &mut Value) {
    if let Some(vulns) = cyclonedx
        .get_mut("vulnerabilities")
        .and_then(Value::as_array_mut)
    {
        for vuln in vulns {
            if let Some(object) = vuln.as_object_mut() {
                object.remove("analysis");
            }
        }
    }
}

pub fn write_json(path: &Path, value: &Value) -> Result<(), GovernanceError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn append_audit_event(
    log: &Path,
    event: &str,
    actor: &str,
    role: &str,
    project: Option<&str>,
) -> Result<Value, GovernanceError> {
    let record = json!({
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "event": event,
        "actor": actor,
        "role": role,
        "project": project,
        "sequence": audit_next_sequence(log)?,
    });
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new().create(true).append(true).open(log)?;
    writeln!(file, "{}", serde_json::to_string(&record)?)?;
    Ok(record)
}

pub fn read_audit_log(log: &Path) -> Result<Value, GovernanceError> {
    let mut events = Vec::new();
    if log.is_file() {
        let text = fs::read_to_string(log)?;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            events.push(serde_json::from_str::<Value>(line)?);
        }
    }
    Ok(json!({
        "schema_version": AUDIT_LOG_SCHEMA_VERSION,
        "log": path_string(log),
        "counts": { "events": events.len() },
        "events": events
    }))
}

pub fn dashboard_data(
    work_dir: &Path,
    audit_log: Option<&Path>,
    policy: Option<&Path>,
    runner_manifest: Option<&Path>,
) -> Result<Value, GovernanceError> {
    let audit_events = match audit_log {
        Some(path) => read_audit_log(path)?
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let policy_summary = policy.map(validate_policy_file).transpose()?;
    let runner_summary = runner_manifest.map(runner_list_file).transpose()?;
    let finding_count = count_finding_json(work_dir)?;
    Ok(json!({
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "work_dir": path_string(work_dir),
        "counts": {
            "findings": finding_count,
            "audit_events": audit_events.len(),
            "runners": runner_summary.as_ref().and_then(|value| value.pointer("/counts/runners")).and_then(Value::as_u64).unwrap_or(0)
        },
        "rbac": {
            "roles": ["reader", "operator", "policy-admin", "auditor"],
            "permissions": {
                "reader": ["view_dashboard", "view_findings"],
                "operator": ["start_scan", "use_runner", "export_bundle"],
                "policy-admin": ["validate_policy", "change_policy", "approve_waiver"],
                "auditor": ["read_audit_log", "export_evidence"]
            }
        },
        "policy": policy_summary,
        "runners": runner_summary,
        "audit": audit_events
    }))
}

pub fn ci_dashboard_data(
    work_dir: &Path,
    policy: Option<&Path>,
    runner_plan: Option<&Path>,
    findings: &BTreeMap<String, usize>,
    gate_failed: bool,
) -> Result<Value, GovernanceError> {
    let policy_summary = policy.map(validate_policy_file).transpose()?;
    let policy_gate = policy
        .map(|path| ci_policy_gate_with_runner_plan(work_dir, path, runner_plan))
        .transpose()?;
    let runner_plan_summary = runner_plan.map(runner_plan_budget_summary).transpose()?;
    let policy_id = policy_summary
        .as_ref()
        .and_then(|value| value.get("policy_id"))
        .and_then(Value::as_str)
        .unwrap_or("none");
    let effective_gate_failed = policy_gate
        .as_ref()
        .and_then(|value| value.pointer("/gate/failed"))
        .and_then(Value::as_bool)
        .unwrap_or(gate_failed);
    let gate_reason = policy_gate
        .as_ref()
        .and_then(|value| value.pointer("/gate/reason"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if gate_failed {
                "policy_threshold".to_owned()
            } else {
                "none".to_owned()
            }
        });
    let decisions = policy_gate
        .as_ref()
        .and_then(|value| value.get("decisions"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "baseline": "not_configured",
                "baseline_findings": [],
                "waived_findings": [],
                "flake_quarantine": "disabled",
                "missing_evidence": []
            })
        });
    Ok(json!({
        "schema_version": CI_DASHBOARD_SCHEMA_VERSION,
        "work_dir": path_string(work_dir),
        "policy": {
            "policy_id": policy_id,
            "summary": policy_summary
        },
        "findings": {
            "by_severity": findings,
            "effective_by_severity": policy_gate
                .as_ref()
                .and_then(|value| value.pointer("/effective_findings/by_severity"))
                .cloned()
                .unwrap_or_else(|| json!(findings))
        },
        "gate": {
            "failed": effective_gate_failed,
            "reason": gate_reason,
            "reasons": policy_gate
                .as_ref()
                .and_then(|value| value.pointer("/gate/reasons"))
                .cloned()
                .unwrap_or_else(|| json!([]))
        },
        "budget": {
            "strategy": "deterministic-risk",
            "inputs": ["changed_files", "target_risk", "prior_findings", "runner_capacity"],
            "allocated_targets": runner_plan_summary
                .as_ref()
                .and_then(|value| value.get("assigned"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            "runner_plan": runner_plan_summary.unwrap_or_else(|| json!({
                "source": Value::Null,
                "jobs": 0,
                "assigned": 0,
                "unassigned": 0,
                "valid": Value::Null
            }))
        },
        "decisions": decisions
    }))
}

pub fn ci_policy_gate(work_dir: &Path, policy: &Path) -> Result<Value, GovernanceError> {
    ci_policy_gate_with_runner_plan(work_dir, policy, None)
}

pub fn ci_policy_gate_with_runner_plan(
    work_dir: &Path,
    policy: &Path,
    runner_plan: Option<&Path>,
) -> Result<Value, GovernanceError> {
    let policy_value = read_json(policy)?;
    let required_artifacts = string_array(policy_value.pointer("/ci/require_artifacts"));
    let missing_evidence = missing_required_work_artifacts(work_dir, &required_artifacts)?;
    let require_runner_plan = policy_value
        .pointer("/ci/require_runner_plan")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let require_full_runner_assignment = policy_value
        .pointer("/ci/require_full_runner_assignment")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let runner_plan_summary = runner_plan.map(runner_plan_budget_summary).transpose()?;
    let runner_plan_status = match runner_plan_summary.as_ref() {
        Some(summary)
            if summary
                .get("valid")
                .and_then(Value::as_bool)
                .is_some_and(|valid| !valid)
                && summary
                    .get("unassigned")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    == 0 =>
        {
            "invalid"
        }
        Some(summary)
            if summary
                .get("unassigned")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == 0 =>
        {
            "complete"
        }
        Some(_) => "incomplete",
        None => "missing",
    };
    let fail_on = policy_value
        .pointer("/ci/fail_on_severity")
        .and_then(Value::as_str)
        .unwrap_or("any");
    let findings = finding_records(work_dir)?;
    let mut active_findings = Vec::new();
    let mut waived_findings = Vec::new();
    let mut baseline_findings = Vec::new();
    let mut active_by_severity = BTreeMap::<String, usize>::new();
    let mut threshold_failed = false;

    for finding in findings {
        let finding_id = finding_identifier(&finding).unwrap_or_else(|| "unknown".to_owned());
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Some(waiver) = matching_policy_waiver(&policy_value, &finding) {
            waived_findings.push(json!({
                "finding_id": finding_id,
                "severity": severity,
                "waiver_id": waiver.get("id").and_then(Value::as_str).unwrap_or("unknown"),
                "reason": waiver.get("reason").and_then(Value::as_str)
            }));
            continue;
        }
        if matching_policy_baseline(&policy_value, &finding) {
            baseline_findings.push(json!({
                "finding_id": finding_id,
                "severity": severity
            }));
            continue;
        }
        *active_by_severity.entry(severity.to_owned()).or_insert(0) += 1;
        if fail_on != "none" && severity_rank(severity) >= severity_rank(fail_on) {
            threshold_failed = true;
        }
        active_findings.push(json!({
            "finding_id": finding_id,
            "severity": severity
        }));
    }

    let mut reasons = Vec::new();
    if !missing_evidence.is_empty() {
        reasons.push("missing_required_artifacts");
    }
    if threshold_failed {
        reasons.push("policy_threshold");
    }
    if require_runner_plan && runner_plan_summary.is_none() {
        reasons.push("missing_runner_plan");
    }
    if require_full_runner_assignment {
        match runner_plan_summary.as_ref() {
            Some(summary)
                if summary
                    .get("unassigned")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    > 0 =>
            {
                reasons.push("runner_plan_unassigned");
            }
            Some(summary)
                if summary
                    .get("valid")
                    .and_then(Value::as_bool)
                    .is_some_and(|valid| !valid) =>
            {
                reasons.push("runner_plan_invalid");
            }
            None if !require_runner_plan => reasons.push("missing_runner_plan"),
            _ => {}
        }
    }
    let reason = match reasons.as_slice() {
        [] => "none",
        [single] => single,
        _ => "multiple",
    };

    Ok(json!({
        "schema_version": CI_DASHBOARD_SCHEMA_VERSION,
        "work_dir": path_string(work_dir),
        "policy": path_string(policy),
        "gate": {
            "failed": !reasons.is_empty(),
            "reason": reason,
            "reasons": reasons
        },
        "effective_findings": {
            "count": active_findings.len(),
            "by_severity": active_by_severity,
            "findings": active_findings
        },
        "decisions": {
            "baseline": if baseline_findings.is_empty() { "not_configured" } else { "configured" },
            "baseline_findings": baseline_findings,
            "waived_findings": waived_findings,
            "flake_quarantine": "disabled",
            "required_artifacts": required_artifacts,
            "missing_evidence": missing_evidence,
            "runner_plan": {
                "required": require_runner_plan,
                "full_assignment_required": require_full_runner_assignment,
                "status": runner_plan_status,
                "summary": runner_plan_summary
            }
        }
    }))
}

fn audit_next_sequence(log: &Path) -> Result<u64, GovernanceError> {
    Ok(read_audit_log(log)?
        .get("counts")
        .and_then(|value| value.get("events"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1)
}

fn count_finding_json(work_dir: &Path) -> Result<usize, GovernanceError> {
    let findings = work_dir.join("findings");
    if !findings.is_dir() {
        return Ok(0);
    }
    Ok(walk_all_files(&findings)?
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("finding.json"))
        .count())
}

fn finding_records(work_dir: &Path) -> Result<Vec<Value>, GovernanceError> {
    let findings = work_dir.join("findings");
    if !findings.is_dir() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for path in walk_all_files(&findings)? {
        if path.file_name().and_then(|name| name.to_str()) == Some("finding.json") {
            records.push(read_json(&path)?);
        }
    }
    Ok(records)
}

fn missing_required_work_artifacts(
    work_dir: &Path,
    required: &[String],
) -> Result<Vec<String>, GovernanceError> {
    let mut artifacts = Vec::new();
    collect_work_artifact(
        work_dir,
        "reports/run-last.json",
        "report_json",
        &mut artifacts,
    )?;
    collect_work_artifact(
        work_dir,
        "reports/run-last.md",
        "report_markdown",
        &mut artifacts,
    )?;
    collect_work_artifact(work_dir, "reports/run-last.sarif", "sarif", &mut artifacts)?;
    collect_work_artifact(
        work_dir,
        "reports/run-last.junit.xml",
        "junit",
        &mut artifacts,
    )?;
    collect_work_artifact(
        work_dir,
        "static/static-report.json",
        "static_report",
        &mut artifacts,
    )?;
    collect_work_artifact(
        work_dir,
        "static/static-report.sarif",
        "static_sarif",
        &mut artifacts,
    )?;
    collect_work_artifact(work_dir, "sbom/sbom.json", "sbom", &mut artifacts)?;
    collect_work_artifact(
        work_dir,
        "sbom/cyclonedx.json",
        "cyclonedx_sbom",
        &mut artifacts,
    )?;
    collect_work_artifact(
        work_dir,
        "sbom/vulnerabilities.json",
        "vulnerability_report",
        &mut artifacts,
    )?;
    collect_artifacts_by_name(
        work_dir,
        "findings",
        "testcase.bin",
        "replay_input",
        &mut artifacts,
    )?;
    collect_artifacts_by_prefix(work_dir, "evidence", "validation_evidence", &mut artifacts)?;
    Ok(missing_required_artifacts(&artifacts, required))
}

fn materialize_export_bundle(
    bundle_dir: &Path,
    artifacts: &mut [Value],
) -> Result<Value, GovernanceError> {
    fs::create_dir_all(bundle_dir.join("artifacts"))?;
    for artifact in artifacts {
        let Some(source) = artifact.get("_source_path").and_then(Value::as_str) else {
            continue;
        };
        let bundle_path = bundle_artifact_path(artifact);
        let destination = bundle_dir.join(&bundle_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, &destination)?;
        artifact["bundle_path"] = json!(path_string(&bundle_path));
    }
    Ok(json!({
        "materialized": true,
        "path": path_string(bundle_dir),
        "manifest_path": "export-manifest.json"
    }))
}

fn bundle_artifact_path(artifact: &Value) -> PathBuf {
    let kind = artifact
        .get("kind")
        .and_then(Value::as_str)
        .map(sanitize_path_segment)
        .unwrap_or_else(|| "artifact".to_owned());
    let display_path = artifact
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("artifact");
    let mut out = PathBuf::from("artifacts").join(kind);
    let mut had_segment = false;
    for segment in display_path.split('/') {
        let sanitized = sanitize_path_segment(segment);
        if sanitized.is_empty() {
            continue;
        }
        out.push(sanitized);
        had_segment = true;
    }
    if !had_segment {
        out.push("artifact");
    }
    out
}

fn sanitize_path_segment(segment: &str) -> String {
    let sanitized = segment
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let trimmed = sanitized.trim_matches('.');
    if trimmed.is_empty() {
        "_".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn public_artifact(artifact: &Value) -> Value {
    let mut public = artifact.as_object().cloned().unwrap_or_default();
    public.remove("_source_path");
    Value::Object(public)
}

/// SBOM component pipeline: discover (catalogers) → merge_by_identity → ENRICH
/// → ref. `write_sbom` matches vulns + renders over this result.
///
/// The enrich pass climbs the evidence ladder to its dynamic, fuzz-confirmed
/// rungs (`Linked` / `RuntimeLoaded` / `FuzzReached`). It prefers to ANNOTATE an
/// already-discovered component and only creates a new one when nothing matches,
/// so a library declared in a manifest and seen again as a linked `.so` stays a
/// single component carrying both rungs.
fn discover_components(options: &SbomOptions) -> Result<Vec<Component>, GovernanceError> {
    let files = walk_all_files(&options.root)?;
    let ctx = sbom_ingest::CatalogContext::new(options.root.clone(), files);
    if let Some(filter) = &options.ecosystems {
        validate_ecosystem_filter(filter)?;
    }
    let mut components = Vec::new();
    for cataloger in sbom_ingest::registry() {
        // --ecosystems restricts which catalogers run, by their declared
        // `Cataloger::ecosystem()` label. Default (no filter) runs every
        // cataloger that detects the tree, exactly as before.
        if let Some(filter) = &options.ecosystems {
            if !filter.iter().any(|name| name == cataloger.ecosystem()) {
                continue;
            }
        }
        if cataloger.detect(&ctx) {
            components.extend(cataloger.catalog(&ctx).map_err(GovernanceError::from)?);
        }
    }

    let mut components = sbom_ingest::merge_by_identity(components);
    enrich_components(&mut components, options)?;
    // Re-merge: collapses any newly-created duplicates and re-establishes the
    // deterministic sort. Idempotent when enrich added nothing, so the no-enrich
    // path (no inventory / run.json / reachability) is byte-stable.
    let mut components = sbom_ingest::merge_by_identity(components);
    // Post-merge (so it can't perturb identity-key dedup): give any component that
    // still lacks a purl — a range-declared dep with no lockfile pin — a
    // VERSIONLESS name-only purl for its ecosystem, so downstream SCA can match it
    // by name (without this, range-declared pypi/npm/go deps carry no purl at all).
    for component in &mut components {
        if component.purl.is_none() {
            component.purl = sbom_ingest::purl::name_only(&component.ecosystem, &component.name);
        }
    }
    for component in &mut components {
        component.component_ref = component_ref(component);
    }
    Ok(components)
}

/// Every `Cataloger::ecosystem()` label the built-in registry can emit, sorted
/// and deduplicated. Exposed so the CLI can validate `--ecosystems` up front and
/// list the valid choices in an error message.
pub fn known_ecosystems() -> Vec<String> {
    let mut names: Vec<String> = sbom_ingest::registry()
        .iter()
        .map(|cataloger| cataloger.ecosystem().to_owned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Reject an `--ecosystems` entry that no cataloger emits (typo safety).
fn validate_ecosystem_filter(filter: &[String]) -> Result<(), GovernanceError> {
    let known = known_ecosystems();
    for name in filter {
        if !known.iter().any(|candidate| candidate == name) {
            return Err(GovernanceError::InvalidInput {
                message: format!(
                    "unknown --ecosystems value '{name}' (known: {})",
                    known.join(", ")
                ),
            });
        }
    }
    Ok(())
}

/// Annotate merged components with the dynamic evidence rungs, creating a new
/// component only when no confident identity match exists. Pure over the inputs;
/// all source JSON is untrusted (bounded read, tolerate malformed, never panic).
fn enrich_components(
    components: &mut Vec<Component>,
    options: &SbomOptions,
) -> Result<(), GovernanceError> {
    // 1. Linked — DT_NEEDED / linked-library sonames from each binary inventory.
    for inventory in &options.binary_inventories {
        let value = read_json(inventory)?;
        enrich_linked_from_inventory(components, &path_string(inventory), &value);
    }

    // 2. RuntimeLoaded — dlopen/exec libraries observed in auto/run.json.
    let by_library = collect_dlopen_libraries(options)?;
    enrich_runtime_from_dlopen(components, by_library);

    // 3. FuzzReached — components a fuzzed harness actually drove.
    let reachability = load_sbom_reachability(options)?;
    enrich_fuzz_reached(components, &reachability);

    // 4. SourceObserved — a manifest dependency actually imported in source
    //    (#07-lite SCA reachability). A dep in go.mod/Cargo.toml but never imported
    //    stays merely `Resolved`, so the VEX ladder keeps its CVEs out of the
    //    execute path; an imported one is promoted so its CVEs surface.
    enrich_source_imports(components, &options.root)?;

    Ok(())
}

/// Per-source-file read cap for import scanning — skip pathological/generated blobs
/// without touching the rest of the tree.
const IMPORT_SCAN_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// #07-lite (SCA reachability): promote a manifest dependency to `SourceObserved`
/// when the source actually imports it, so the VEX evidence ladder separates USED
/// dependencies from dead manifest entries — the govulncheck/Snyk "reachability"
/// story, at import granularity. Go and Rust have an EXACT import→component mapping
/// (a Go import path equals or extends the module path; a Rust `use`/`extern crate`
/// names the crate with `-`↔`_`), so a match is precise. Strictly additive and
/// conservative: it only ever APPENDS a `SourceObserved` rung to a still-`Resolved`
/// go/cargo component — an unmatched dep is left declared (quiet, never a false
/// promotion), and a component already at a higher rung is untouched (byte-stable).
fn enrich_source_imports(components: &mut [Component], root: &Path) -> Result<(), GovernanceError> {
    let want_go = components.iter().any(|c| c.ecosystem == "golang");
    let want_rust = components.iter().any(|c| c.ecosystem == "cargo");
    if !want_go && !want_rust {
        return Ok(());
    }
    // import path / normalized crate name -> first source locator that used it.
    let mut go_imports: BTreeMap<String, String> = BTreeMap::new();
    let mut rust_crates: BTreeMap<String, String> = BTreeMap::new();
    for path in walk_all_files(root)? {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let scan_go = want_go && ext == "go";
        let scan_rust = want_rust && ext == "rs";
        if !scan_go && !scan_rust {
            continue;
        }
        let Some(source) = read_source_bounded(&path) else {
            continue;
        };
        let rel = relative_path(root, &path);
        if scan_go {
            for import_path in scan_go_imports(&source) {
                go_imports.entry(import_path).or_insert_with(|| rel.clone());
            }
        } else if scan_rust {
            for krate in scan_rust_crates(&source) {
                rust_crates.entry(krate).or_insert_with(|| rel.clone());
            }
        }
    }
    for component in components.iter_mut() {
        // Never perturb a component already at or above SourceObserved.
        if component
            .evidence
            .iter()
            .map(|e| e.kind)
            .max()
            .is_some_and(|rung| rung >= EvidenceKind::SourceObserved)
        {
            continue;
        }
        let hit = match component.ecosystem.as_str() {
            "golang" => go_imports
                .iter()
                .find(|(import_path, _)| {
                    import_path.as_str() == component.name
                        || import_path.starts_with(&format!("{}/", component.name))
                })
                .map(|(_, locator)| locator.clone()),
            "cargo" => {
                let normalized = component.name.replace('-', "_").to_ascii_lowercase();
                rust_crates.get(&normalized).cloned()
            }
            _ => None,
        };
        if let Some(locator) = hit {
            component.evidence.push(Evidence::new(
                EvidenceKind::SourceObserved,
                format!("{locator}: import {}", component.name),
            ));
        }
    }
    Ok(())
}

/// Read a source file, bounded, tolerating any error (untrusted tree): `None` on a
/// read error, a non-UTF-8 blob, or a file over the size cap.
fn read_source_bounded(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > IMPORT_SCAN_MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Go import paths from a source file — both `import "path"` and the block form
/// `import ( "a"; alias "b"; _ "c" )`. Returns the quoted paths (the alias, `_`,
/// and `.` prefixes are ignored). Non-dependency stdlib paths simply never match a
/// component, so they need no filtering.
fn scan_go_imports(source: &str) -> Vec<String> {
    let mut imports = Vec::new();
    let mut in_block = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if in_block {
            if trimmed.starts_with(')') {
                in_block = false;
                continue;
            }
            if let Some(path) = quoted_string(trimmed) {
                imports.push(path);
            }
            continue;
        }
        if trimmed.starts_with("import (") {
            in_block = true;
            // An `import ( "path"` on the same line is unusual but tolerated.
            if let Some(path) = quoted_string(trimmed) {
                imports.push(path);
            }
            continue;
        }
        if trimmed.starts_with("import ") {
            if let Some(path) = quoted_string(trimmed) {
                imports.push(path);
            }
        }
    }
    imports
}

/// The last double-quoted substring on a line (so `alias "path"` yields `path`).
fn quoted_string(line: &str) -> Option<String> {
    let close = line.rfind('"')?;
    let open = line[..close].rfind('"')?;
    let inner = &line[open + 1..close];
    (!inner.is_empty()).then(|| inner.to_owned())
}

/// Rust crate roots referenced by `use`/`pub use`/`extern crate`. Returns the first
/// path segment (already `_`-normalized as Cargo imports it), skipping the language
/// roots (`crate`/`self`/`super`/`std`/`core`/`alloc`). A crate never imported is
/// simply absent, so its manifest entry stays `Resolved`.
fn scan_rust_crates(source: &str) -> Vec<String> {
    const ROOTS: &[&str] = &["crate", "self", "super", "std", "core", "alloc"];
    let mut crates = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        let rest = trimmed
            .strip_prefix("pub use ")
            .or_else(|| trimmed.strip_prefix("use "))
            .or_else(|| trimmed.strip_prefix("extern crate "));
        let Some(rest) = rest else {
            continue;
        };
        let segment: String = rest
            .trim_start()
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        if segment.is_empty() || ROOTS.contains(&segment.as_str()) {
            continue;
        }
        crates.push(segment.to_ascii_lowercase());
    }
    crates
}

/// Linked lane: the binary record itself stays a component (binary-only libs
/// must still appear), and every DT_NEEDED soname annotates a matching
/// component or, absent a confident match, becomes a `linked-library` component.
fn enrich_linked_from_inventory(components: &mut Vec<Component>, source: &str, value: &Value) {
    for binary in value
        .get("binaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = binary.get("path").and_then(Value::as_str) {
            // The binary executable/object record. No discovered source
            // component shares this path identity, so this is always create.
            components.push(Component {
                component_ref: String::new(),
                name: name.to_owned(),
                version: None,
                ecosystem: "binary".to_owned(),
                group: None,
                component_type: "binary".to_owned(),
                supplier: None,
                license: None,
                purl: None,
                cpe: None,
                sha256: binary
                    .get("sha256")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                hashes: Vec::new(),
                identity_confidence: "low".to_owned(),
                matching_method: "binary_inventory".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Linked, source.to_owned())],
                runtime_harnesses: Vec::new(),
            });
        }

        for soname in string_array(binary.pointer("/dependencies/libraries")) {
            if soname.trim().is_empty() {
                continue;
            }
            let evidence = Evidence::new(EvidenceKind::Linked, format!("{source}:{soname}"));
            if let Some(target) = components
                .iter_mut()
                .find(|c| soname_matches_component(&soname, c))
            {
                push_evidence_once(target, evidence);
            } else {
                // No discovered component matched: create one named by the
                // stripped base (`libz.so.1` → `z`) with the SONAME version.
                let name = soname_base(&soname);
                let version = soname_version(&soname);
                components.push(Component {
                    component_ref: String::new(),
                    name,
                    version,
                    ecosystem: "linked-library".to_owned(),
                    group: None,
                    component_type: "library".to_owned(),
                    supplier: None,
                    license: None,
                    purl: None,
                    cpe: None,
                    sha256: None,
                    hashes: Vec::new(),
                    identity_confidence: "low".to_owned(),
                    matching_method: "binary_inventory".to_owned(),
                    evidence: vec![evidence],
                    runtime_harnesses: Vec::new(),
                });
            }
        }
    }
}

/// Gather dlopen/exec libraries from every `auto/run.json`, unioning the
/// harness ids that referenced each one. Bounded, malformed-tolerant.
fn collect_dlopen_libraries(
    options: &SbomOptions,
) -> Result<BTreeMap<String, Vec<String>>, GovernanceError> {
    let mut by_library = BTreeMap::<String, Vec<String>>::new();
    for path in auto_run_json_paths(options) {
        if !path.is_file() {
            continue;
        }
        let value = read_json(&path)?;
        for entry in value
            .pointer("/needed_for_build/dlopen_failures")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(library) = entry.get("name").and_then(Value::as_str) else {
                continue;
            };
            if library.trim().is_empty() {
                continue;
            }
            let harnesses = string_array(entry.get("referenced_by_targets"));
            let bucket = by_library.entry(library.to_owned()).or_default();
            for harness in harnesses {
                if !bucket.iter().any(|existing| existing == &harness) {
                    bucket.push(harness);
                }
            }
        }
    }
    Ok(by_library)
}

/// RuntimeLoaded lane: each dlopen'd library annotates a matching component or,
/// absent a confident match, becomes a `runtime-dlopen` component (legacy shape).
fn enrich_runtime_from_dlopen(
    components: &mut Vec<Component>,
    by_library: BTreeMap<String, Vec<String>>,
) {
    for (library, mut harnesses) in by_library {
        harnesses.sort();
        let evidence_source = if harnesses.is_empty() {
            format!("auto/run.json:dlopen:{library}")
        } else {
            format!(
                "auto/run.json:dlopen:{library}:targets:{}",
                harnesses.join(",")
            )
        };
        let evidence = Evidence::new(EvidenceKind::RuntimeLoaded, evidence_source);
        if let Some(target) = components
            .iter_mut()
            .find(|c| soname_matches_component(&library, c))
        {
            push_evidence_once(target, evidence);
            for harness in &harnesses {
                if !target.runtime_harnesses.contains(harness) {
                    target.runtime_harnesses.push(harness.clone());
                }
            }
        } else {
            let (name, version) = runtime_library_name_version(&library);
            components.push(Component {
                component_ref: String::new(),
                name,
                version,
                ecosystem: "runtime-dlopen".to_owned(),
                group: None,
                component_type: "runtime_library".to_owned(),
                supplier: None,
                license: None,
                purl: None,
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "low".to_owned(),
                matching_method: "runtime_dlopen".to_owned(),
                evidence: vec![evidence],
                runtime_harnesses: harnesses,
            });
        }
    }
}

/// FuzzReached lane: push a `FuzzReached` rung on every component a fuzzed
/// harness actually drove, reusing the per-VULN reachability matching keys.
fn enrich_fuzz_reached(components: &mut [Component], reachability: &SbomReachability) {
    for component in components.iter_mut() {
        let hits = reachability.hits_for_component(component);
        if hits.is_empty() {
            continue;
        }
        let source = hits
            .iter()
            .map(|hit| format!("harness:{}:{}", hit.harness_id, hit.target_name))
            .collect::<Vec<_>>()
            .join(",");
        push_evidence_once(
            component,
            Evidence::new(
                EvidenceKind::FuzzReached,
                format!("auto/run.json:fuzz_reached:{source}"),
            ),
        );
    }
}

/// Append `evidence` unless an identical entry already exists (idempotent enrich).
fn push_evidence_once(component: &mut Component, evidence: Evidence) {
    if !component.evidence.contains(&evidence) {
        component.evidence.push(evidence);
    }
}

/// Does `soname` identify `component`? Two confident signals, in order: (1) the
/// Phase-3 KB maps the soname to a canonical library name that equals the
/// component name (`libz.so.1` → `zlib`); or (2) the soname's stripped base name
/// (no `lib` prefix, no `.so[.N]*` suffix) equals the component name
/// case-insensitively (`libz.so.1` ↔ `z`). Conservative: a confident identity
/// match only, else the caller creates.
fn soname_matches_component(soname: &str, component: &Component) -> bool {
    if let Some(kb_name) = sbom_ingest::soname_to_library_name(soname) {
        if component.name.eq_ignore_ascii_case(kb_name) {
            return true;
        }
    }
    let base = soname_base(soname);
    if base.is_empty() {
        return false;
    }
    component.name.eq_ignore_ascii_case(&base)
}

/// Strip a shared-object name to its base library name: drop any directory, the
/// leading `lib`, and a trailing `.so` plus version digits (`libz.so.1` → `z`,
/// `libssl.so.1.1` → `ssl`, `libpng16.so.16` → `png16`). Lowercased.
fn soname_base(soname: &str) -> String {
    let leaf = Path::new(soname)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(soname)
        .trim()
        .to_ascii_lowercase();
    // Strip `.so` and everything after it (the SONAME version chain).
    let stem = match leaf.find(".so") {
        Some(idx) => &leaf[..idx],
        None => leaf.as_str(),
    };
    stem.strip_prefix("lib").unwrap_or(stem).to_owned()
}

/// The SONAME version chain after `.so.` (`libz.so.1` → `Some("1")`,
/// `libssl.so.1.1` → `Some("1.1")`, `libcrypto.so` → `None`).
fn soname_version(soname: &str) -> Option<String> {
    let leaf = Path::new(soname)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(soname)
        .trim();
    let (_, version) = leaf.split_once(".so.")?;
    if version.is_empty() {
        None
    } else {
        Some(version.to_owned())
    }
}

/// Split a shared-object name into a `(name, version)` for a CREATED component.
/// The `lib` prefix is intentionally retained here (e.g. `libssl.so.1.1` →
/// `("libssl", "1.1")`) — that is the established runtime-dlopen / binary
/// component shape; identity matching against discovered components uses the
/// stripped `soname_base` instead.
fn runtime_library_name_version(library: &str) -> (String, Option<String>) {
    let basename = Path::new(library)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(library)
        .trim();
    if let Some((name, version)) = basename.split_once(".so.") {
        if !name.is_empty() && !version.is_empty() {
            return (name.to_owned(), Some(version.to_owned()));
        }
    }
    if let Some(name) = basename.strip_suffix(".so") {
        if !name.is_empty() {
            return (name.to_owned(), None);
        }
    }
    (basename.to_owned(), None)
}

fn render_sbom(root: &Path, components: &[Component]) -> Value {
    let mut by_ecosystem = BTreeMap::new();
    for component in components {
        *by_ecosystem
            .entry(component.ecosystem.clone())
            .or_insert(0usize) += 1;
    }
    json!({
        "schema_version": SBOM_SCHEMA_VERSION,
        "root": path_string(root),
        "counts": {
            "components": components.len(),
            "by_ecosystem": by_ecosystem
        },
        "components": components.iter().map(component_json).collect::<Vec<_>>()
    })
}

/// The column header of the SBOM CSV inventory. One row per catalogued
/// component; field order is stable so downstream diffs/spreadsheets are byte
/// reproducible.
const SBOM_CSV_HEADER: &str = "name,version,ecosystem,type,supplier,license,purl,cpe,sha256,\
identity_confidence,matching_method,usage,runtime_harnesses,evidence";

/// Render the catalogued components as a flat RFC-4180 CSV (one row per
/// component, deterministic component order). This is the SBOM rendered for
/// spreadsheet / procurement / vuln-triage ingestion — the same component set
/// as `sbom.json`, projected onto the columns most consumers ask for. Mirrors
/// the CSV inventories `syft -o csv` and CycloneDX tooling emit.
fn render_sbom_csv(components: &[Component]) -> String {
    let mut out = String::with_capacity(SBOM_CSV_HEADER.len() + components.len() * 64);
    out.push_str(SBOM_CSV_HEADER);
    out.push('\n');
    for component in components {
        let cols = [
            component.name.as_str(),
            component.version.as_deref().unwrap_or(""),
            component.ecosystem.as_str(),
            component.component_type.as_str(),
            component.supplier.as_deref().unwrap_or(""),
            component.license.as_deref().unwrap_or(""),
            component.purl.as_deref().unwrap_or(""),
            component.cpe.as_deref().unwrap_or(""),
            component.sha256.as_deref().unwrap_or(""),
            component.identity_confidence.as_str(),
            component.matching_method.as_str(),
            component.usage(),
            &component.runtime_harnesses.join(";"),
            &component.evidence_summary(),
        ];
        let row = cols
            .iter()
            .map(|c| sbom_csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// RFC-4180 field escaping: a field containing a comma, double-quote, CR, or LF
/// is wrapped in double quotes with embedded quotes doubled.
fn sbom_csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

const VULNERABILITY_CSV_HEADER: &str =
    "component,version,purl,cve,severity,cvss_score,cwe,kev,reachability,advisory";

/// Render the offline CVE matches as a flat RFC-4180 CSV — one row per CVE match,
/// in the same deterministic order as `vulnerabilities.json`. The `cwe` column is
/// pulled from the SAME `normalized_cwe` field that flows into
/// `vulnerabilities.json` and CycloneDX, so every emitted format agrees on the
/// weakness mapping. Written alongside `sbom.csv` under the `csv` emit kind so a
/// spreadsheet / SCA pipeline gets both the inventory and its vulnerabilities.
///
/// Each row stays ACTIONABLE: `reachability` tells the dev whether a fuzz
/// campaign actually drove the vulnerable component, and `advisory` is the
/// upstream link to follow to remediate the CVE (the SBOM-side analog of a
/// finding's reproducer / fix location).
fn render_vulnerabilities_csv(vulnerabilities: &Value) -> String {
    let matches = vulnerabilities
        .get("matches")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut out = String::with_capacity(VULNERABILITY_CSV_HEADER.len() + matches.len() * 96);
    out.push_str(VULNERABILITY_CSV_HEADER);
    out.push('\n');
    for finding in matches {
        let str_at = |pointer: &str| {
            finding
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let component = str_at("/component/name");
        let version = str_at("/component/version");
        let purl = str_at("/component/purl");
        let cve = finding
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Print the CVSS score from its canonical JSON number form ("9.8"),
        // avoiding float-formatting artifacts.
        let cvss_score = match finding.pointer("/cvss/score") {
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        };
        let cwe = finding
            .get("cwe")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(";")
            })
            .unwrap_or_default();
        let kev = if finding
            .pointer("/kev/known_exploited")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "true"
        } else {
            "false"
        };
        let reachability = str_at("/reachability/status");
        let advisory = finding
            .pointer("/references/0/url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let cols = [
            component.as_str(),
            version.as_str(),
            purl.as_str(),
            cve.as_str(),
            severity.as_str(),
            cvss_score.as_str(),
            cwe.as_str(),
            kev,
            reachability.as_str(),
            advisory.as_str(),
        ];
        let row = cols
            .iter()
            .map(|c| sbom_csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// The single deterministic timestamp used across the SBOM body (CycloneDX
/// `metadata.timestamp` and the OpenVEX `timestamp`). Never a wall-clock call —
/// keeps outputs byte-reproducible for diffing and attestation.
const SBOM_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

/// The scanned project's OWN component — the BOM's primary subject — among the
/// catalogued components, or `None` for a tree with no root-level self-manifest
/// (e.g. a pure-C source drop). A self-component is the one its native-manifest
/// cataloger tagged `component_type == "source"` (dependencies are `"library"`)
/// whose manifest sits DIRECTLY at the scan root — a `Declared` evidence source
/// with no path separator (`Cargo.toml`, `package.json`, `pom.xml`), not a
/// nested workspace member / reactor submodule. When several qualify (e.g. a
/// Cargo.toml and a package.json both at the root) the first in the deterministic
/// component order wins, so the choice is byte-stable.
fn primary_self_component(components: &[Component]) -> Option<&Component> {
    components.iter().find(|component| {
        component.component_type == "source"
            && component.evidence.iter().any(|evidence| {
                evidence.kind == EvidenceKind::Declared && is_root_level_manifest(&evidence.source)
            })
    })
}

/// A manifest evidence source that points DIRECTLY at the scan root: a bare
/// filename with no path separator (`Cargo.toml`, not `crates/x/Cargo.toml`).
fn is_root_level_manifest(source: &str) -> bool {
    !source.is_empty() && !source.contains('/')
}

/// The CycloneDX `metadata.component` (the BOM's primary subject). When a
/// root-level project-self component is identified, adopt its real identity
/// (name / version / purl / licenses / supplier) so the BOM is no longer
/// anonymous — matching how syft et al. populate the primary from the root
/// manifest. The `bom-ref` stays `govfuzz:scanned-root` and the `govfuzz:root`
/// property is preserved so the dependency graph is unchanged. With no root
/// self-manifest, fall back to the scan dir name + `unknown`.
fn metadata_component_json(root: &Path, root_ref: &str, primary: Option<&Component>) -> Value {
    let dir_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("scanned-tree");
    let mut component = json!({
        "type": "application",
        "bom-ref": root_ref,
        "name": primary.map_or(dir_name, |c| c.name.as_str()),
        "version": primary.and_then(|c| c.version.as_deref()).unwrap_or("unknown"),
        "supplier": {
            "name": primary.and_then(|c| c.supplier.as_deref()).unwrap_or("unknown")
        },
        "licenses": [cyclonedx_license_json(primary.and_then(|c| c.license.as_deref()))],
        "properties": [{
            "name": "govfuzz:root",
            "value": path_string(root)
        }]
    });
    if let Some(group) = primary
        .and_then(|c| c.group.as_deref())
        .filter(|g| !g.is_empty())
    {
        component["group"] = json!(group);
    }
    if let Some(purl) = primary.and_then(|c| c.purl.as_deref()) {
        component["purl"] = json!(purl);
    }
    component
}

fn render_cyclonedx_sbom(root: &Path, components: &[Component]) -> Value {
    let root_ref = "govfuzz:scanned-root";
    let govfuzz_tool_ref = format!("pkg:cargo/govfuzz@{}", env!("CARGO_PKG_VERSION"));
    let component_refs = components
        .iter()
        .map(|component| component.component_ref.clone())
        .collect::<Vec<_>>();
    let metadata_component =
        metadata_component_json(root, root_ref, primary_self_component(components));
    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": SBOM_TIMESTAMP,
            "supplier": {
                "name": "Tarmo Technologies"
            },
            "tools": {
                "components": [{
                    "type": "application",
                    "bom-ref": govfuzz_tool_ref.clone(),
                    "name": "govfuzz",
                    "version": env!("CARGO_PKG_VERSION"),
                    "supplier": {
                        "name": "Tarmo Technologies"
                    },
                    "purl": govfuzz_tool_ref,
                    "licenses": [{
                        "license": {
                            "id": "Apache-2.0"
                        }
                    }],
                    "properties": [{
                        "name": "govfuzz:component_role",
                        "value": "scanner"
                    }]
                }]
            },
            "component": metadata_component,
            "properties": [{
                "name": "govfuzz:generation_context",
                "value": "offline-sbom"
            }]
        },
        "components": components
            .iter()
            .map(cyclonedx_component_json)
            .collect::<Vec<_>>(),
        "dependencies": std::iter::once(json!({
            "ref": root_ref,
            "dependsOn": component_refs
        }))
        .chain(components.iter().map(|component| json!({
            "ref": component.component_ref,
            "dependsOn": []
        })))
        .collect::<Vec<_>>()
    })
}

/// Build an SPDX-2.3 JSON document from the catalogued components.
///
/// SPDX is a common procurement mandate (many US-government / enterprise intakes
/// accept SPDX but not CycloneDX). This emits the minimal-but-valid SPDX-2.3
/// shape: the document header (`spdxVersion`/`dataLicense`/`SPDXID`/`name`/
/// `documentNamespace`/`creationInfo`), one `packages[]` entry per component
/// (with `SPDXID`/`name`/`versionInfo`/`downloadLocation`/`licenseConcluded`,
/// plus a PACKAGE-MANAGER `purl` externalRef and checksums where known), and a
/// `DESCRIBES` relationship from the document to each package.
///
/// Offline and deterministic: `documentNamespace` is derived from the document
/// name (no UUID/timestamp entropy) and the created time is the fixed
/// `SBOM_TIMESTAMP`, so the output is byte-stable for golden diffing.
fn render_spdx_document(root: &Path, components: &[Component]) -> Value {
    let dir_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("scanned-tree");
    let doc_name = format!("{dir_name}-sbom");
    let namespace = format!("https://govfuzz.dev/spdx/{doc_name}");

    let mut packages = Vec::with_capacity(components.len());
    let mut relationships = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        let spdx_id = format!(
            "SPDXRef-Package-{index}-{}",
            spdx_id_sanitize(&component.name)
        );
        packages.push(spdx_package_json(&spdx_id, component));
        relationships.push(json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id
        }));
    }

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": SBOM_TIMESTAMP,
            "creators": [
                format!("Tool: govfuzz-{}", env!("CARGO_PKG_VERSION")),
                "Organization: Tarmo Technologies"
            ]
        },
        "packages": packages,
        "relationships": relationships
    })
}

/// One SPDX `packages[]` entry. Absent fields use the SPDX `NOASSERTION`
/// sentinel (never a null), which is what SPDX consumers expect.
fn spdx_package_json(spdx_id: &str, component: &Component) -> Value {
    let version = component.version.as_deref().unwrap_or("NOASSERTION");
    let license = component
        .license
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .unwrap_or("NOASSERTION");
    let mut package = json!({
        "SPDXID": spdx_id,
        "name": component.name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": license,
        "licenseDeclared": license,
        "copyrightText": "NOASSERTION"
    });
    if let Some(supplier) = component
        .supplier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        package["supplier"] = json!(format!("Organization: {supplier}"));
    }

    let mut external_refs = Vec::new();
    if let Some(purl) = &component.purl {
        external_refs.push(json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl
        }));
    }
    if let Some(cpe) = &component.cpe {
        external_refs.push(json!({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": cpe
        }));
    }
    if !external_refs.is_empty() {
        package["externalRefs"] = json!(external_refs);
    }

    let mut checksums = Vec::new();
    for hash in &component.hashes {
        checksums.push(json!({
            "algorithm": spdx_checksum_algorithm(&hash.alg),
            "checksumValue": hash.value_hex
        }));
    }
    if component.hashes.is_empty() {
        if let Some(sha256) = &component.sha256 {
            checksums.push(json!({
                "algorithm": "SHA256",
                "checksumValue": sha256
            }));
        }
    }
    if !checksums.is_empty() {
        package["checksums"] = json!(checksums);
    }
    package
}

/// Map a CycloneDX hash alg id (`SHA-256`) to the SPDX ChecksumAlgorithm enum
/// (`SHA256`). Unknown algorithms pass through uppercased-and-dehyphenated.
fn spdx_checksum_algorithm(alg: &str) -> String {
    alg.replace('-', "").to_ascii_uppercase()
}

/// Sanitize a component name into the SPDX idstring charset (letters, digits,
/// `.`, `-`). Everything else becomes `-`, so `SPDXID` values are always valid.
fn spdx_id_sanitize(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "component".to_owned()
    } else {
        sanitized
    }
}

/// Build the standalone OpenVEX document from the matched vulnerabilities. One
/// statement per `(vuln, component)` match, carrying the assessment computed in
/// `vex_assessment`. With no vuln-db (no matches) the `statements` array is
/// empty — a valid, honest empty VEX.
fn render_openvex_document(vulnerability_report: &Value) -> Value {
    let statements = vulnerability_report
        .get("matches")
        .and_then(Value::as_array)
        .map(|matches| {
            matches
                .iter()
                .filter_map(openvex_statement_from_match)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    vex::render_openvex("govfuzz:vex", SBOM_TIMESTAMP, statements)
}

/// One OpenVEX statement from a vulnerability match, reusing the embedded VEX
/// assessment built in `vex_assessment`. Returns `None` if the match lacks the
/// statement (defensive — never panic on a malformed report).
fn openvex_statement_from_match(finding: &Value) -> Option<Value> {
    finding.pointer("/vex/openvex_statement").cloned()
}

fn attach_cyclonedx_vulnerabilities(cyclonedx: &mut Value, vulnerability_report: &Value) {
    let entries = vulnerability_report
        .get("matches")
        .and_then(Value::as_array)
        .map(|matches| {
            matches
                .iter()
                .map(cyclonedx_vulnerability_json)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !entries.is_empty() {
        cyclonedx["vulnerabilities"] = json!(entries);
    }
}

fn cyclonedx_vulnerability_json(finding: &Value) -> Value {
    let id = finding
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let component_ref = finding
        .get("component_ref")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let severity = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut item = json!({
        "bom-ref": format!("govfuzz:vulnerability:{id}:{component_ref}"),
        "id": id,
        "source": {
            "name": "GovFuzz offline vulnerability database"
        },
        "ratings": [cyclonedx_vulnerability_rating(finding, severity)],
        "affects": [{
            "ref": component_ref
        }],
        "properties": cyclonedx_vulnerability_properties(finding)
    });
    if let Some(summary) = finding.get("summary").and_then(Value::as_str) {
        item["description"] = json!(summary);
    }
    let cwes = cyclonedx_cwe_numbers(finding);
    if !cwes.is_empty() {
        item["cwes"] = json!(cwes);
    }
    let advisories = cyclonedx_vulnerability_advisories(finding);
    if !advisories.is_empty() {
        item["advisories"] = json!(advisories);
    }
    // CycloneDX-VEX: embed the analysis (state + justification? + detail) the
    // match carries. Built once in `vex_assessment`; consumed verbatim here.
    if let Some(analysis) = finding.pointer("/vex/cyclonedx_analysis") {
        if analysis.is_object() {
            item["analysis"] = analysis.clone();
        }
    }
    item
}

fn cyclonedx_vulnerability_rating(finding: &Value, severity: &str) -> Value {
    let cvss = finding.get("cvss").unwrap_or(&Value::Null);
    let mut rating = json!({
        "severity": severity,
        "method": cvss
            .get("version")
            .and_then(Value::as_str)
            .map(cyclonedx_cvss_method)
            .unwrap_or("other")
    });
    if let Some(score) = cvss.get("score").and_then(Value::as_f64) {
        rating["score"] = json!(score);
    }
    if let Some(vector) = cvss.get("vector").and_then(Value::as_str) {
        rating["vector"] = json!(vector);
    }
    rating
}

fn cyclonedx_cvss_method(version: &str) -> &'static str {
    match version.trim() {
        "2" | "2.0" => "CVSSv2",
        "3" | "3.0" => "CVSSv3",
        "3.1" => "CVSSv31",
        "4" | "4.0" => "CVSSv4",
        _ => "other",
    }
}

fn cyclonedx_cwe_numbers(finding: &Value) -> Vec<u64> {
    finding
        .get("cwe")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(parse_cwe_number))
        })
        .collect()
}

fn parse_cwe_number(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let number = trimmed
        .strip_prefix("CWE-")
        .or_else(|| trimmed.strip_prefix("cwe-"))
        .unwrap_or(trimmed);
    number.parse::<u64>().ok()
}

fn cyclonedx_vulnerability_properties(finding: &Value) -> Vec<Value> {
    let mut properties = Vec::new();
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:matching_method",
        finding.get("matching_method").and_then(Value::as_str),
    );
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:match_confidence",
        finding.get("match_confidence").and_then(Value::as_str),
    );
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:reachability_status",
        finding
            .pointer("/reachability/status")
            .and_then(Value::as_str),
    );
    if let Some(known_exploited) = finding
        .pointer("/kev/known_exploited")
        .and_then(Value::as_bool)
    {
        properties.push(json!({
            "name": "govfuzz:kev_known_exploited",
            "value": known_exploited.to_string()
        }));
    }
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:kev_date_added",
        finding.pointer("/kev/date_added").and_then(Value::as_str),
    );
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:kev_due_date",
        finding.pointer("/kev/due_date").and_then(Value::as_str),
    );
    push_cyclonedx_property(
        &mut properties,
        "govfuzz:kev_required_action",
        finding
            .pointer("/kev/required_action")
            .and_then(Value::as_str),
    );
    properties
}

fn cyclonedx_vulnerability_advisories(finding: &Value) -> Vec<Value> {
    finding
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            let url = reference
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|url| !url.is_empty())?;
            let mut advisory = json!({ "url": url });
            if let Some(title) = reference
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|title| !title.is_empty())
            {
                advisory["title"] = json!(title);
            }
            Some(advisory)
        })
        .collect()
}

fn push_cyclonedx_property(properties: &mut Vec<Value>, name: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        properties.push(json!({
            "name": name,
            "value": value
        }));
    }
}

fn component_json(component: &Component) -> Value {
    let hashes: Vec<Value> = if !component.hashes.is_empty() {
        component
            .hashes
            .iter()
            .map(|h| json!({"alg": h.alg, "value_hex": h.value_hex}))
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "component_ref": component.component_ref,
        "name": component.name,
        "group": component.group,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "type": component.component_type,
        "supplier": component.supplier,
        "license": component.license,
        "purl": component.purl,
        "cpe": component.cpe,
        "sha256": component.sha256,
        "hashes": hashes,
        "identity_confidence": component.identity_confidence,
        "matching_method": component.matching_method,
        "evidence": component.evidence_summary(),
        "runtime_harnesses": component.runtime_harnesses
    })
}

fn cyclonedx_component_json(component: &Component) -> Value {
    let mut item = json!({
        "type": cyclonedx_component_type(&component.component_type),
        "bom-ref": component.component_ref,
        "name": component.name,
        "supplier": {
            "name": component.supplier.as_deref().unwrap_or("unknown")
        },
        "licenses": [cyclonedx_license_json(component.license.as_deref())],
        "properties": [
            {
                "name": "govfuzz:ecosystem",
                "value": component.ecosystem
            },
            {
                "name": "govfuzz:component_type",
                "value": component.component_type
            },
            {
                "name": "govfuzz:identity_confidence",
                "value": component.identity_confidence
            },
            {
                "name": "govfuzz:matching_method",
                "value": component.matching_method
            },
            {
                "name": "govfuzz:evidence",
                "value": component.evidence_summary()
            },
            {
                "name": "govfuzz:runtime_harnesses",
                "value": component.runtime_harnesses.join(",")
            }
        ]
    });
    if let Some(group) = component.group.as_deref().filter(|g| !g.is_empty()) {
        item["group"] = json!(group);
    }
    if let Some(version) = &component.version {
        item["version"] = json!(version);
    }
    if let Some(purl) = &component.purl {
        item["purl"] = json!(purl);
    }
    if let Some(cpe) = &component.cpe {
        item["cpe"] = json!(cpe);
    }
    if !component.hashes.is_empty() {
        item["hashes"] = Value::Array(
            component
                .hashes
                .iter()
                .map(|h| json!({"alg": h.alg, "content": h.value_hex}))
                .collect(),
        );
    } else if let Some(sha256) = &component.sha256 {
        item["hashes"] = json!([{
            "alg": "SHA-256",
            "content": sha256
        }]);
    }
    item
}

fn cyclonedx_license_json(license: Option<&str>) -> Value {
    let Some(license) = license.map(str::trim).filter(|license| !license.is_empty()) else {
        return json!({
            "license": {
                "name": "unknown"
            }
        });
    };
    if license.contains(' ') {
        json!({
            "expression": license
        })
    } else {
        json!({
            "license": {
                "id": license
            }
        })
    }
}

fn cyclonedx_component_type(component_type: &str) -> &'static str {
    match component_type {
        "binary" => "file",
        "source" | "vendored" | "runtime_library" => "library",
        _ => "library",
    }
}

fn match_vulnerabilities(
    options: &SbomOptions,
    components: &[Component],
) -> Result<Value, GovernanceError> {
    let fail_on = sbom_gate_threshold(options)?;
    let reachability = load_sbom_reachability(options)?;
    let campaign_ran = reachability.campaign_ran();
    let mut matches = Vec::new();
    if let Some(vuln_db) = &options.vuln_db {
        let db = read_json(vuln_db)?;
        for vuln in db
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let package = vuln.get("package").unwrap_or(&Value::Null);
            let ecosystem = package
                .get("ecosystem")
                .and_then(Value::as_str)
                .unwrap_or("");
            let name = package.get("name").and_then(Value::as_str).unwrap_or("");
            let package_cpe = vulnerability_cpe(vuln, package);
            let package_purl = vulnerability_purl(vuln, package);
            let affected = string_array(vuln.get("affected_versions"));
            for component in components {
                if !version_is_affected(component.version.as_deref(), &affected) {
                    continue;
                }
                let cpe_matches = package_cpe.is_some_and(|cpe| {
                    component
                        .cpe
                        .as_deref()
                        .is_some_and(|component_cpe| cpe_compatible(component_cpe, cpe))
                });
                let purl_matches = package_purl.is_some_and(|purl| {
                    component
                        .purl
                        .as_deref()
                        .is_some_and(|component_purl| purl_compatible(component_purl, purl))
                });
                let package_matches = component.ecosystem == ecosystem && component.name == name;
                let cpe_mismatch = package_cpe.is_some() && component.cpe.is_some() && !cpe_matches;
                let purl_mismatch =
                    package_purl.is_some() && component.purl.is_some() && !purl_matches;
                if cpe_mismatch || purl_mismatch {
                    continue;
                }
                if !cpe_matches && !purl_matches && !package_matches {
                    continue;
                }
                let matching_method =
                    vulnerability_matching_method(component, cpe_matches, purl_matches);
                let reached = reachability.hits_for_component(component);
                matches.push(vulnerability_match(
                    vuln,
                    component,
                    &reached,
                    matching_method,
                    campaign_ran,
                ));
            }
        }
    }
    matches.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    let gate_failed = fail_on.as_deref().is_some_and(|threshold| {
        matches.iter().any(|finding| {
            finding
                .get("severity")
                .and_then(Value::as_str)
                .is_some_and(|severity| severity_rank(severity) >= severity_rank(threshold))
        })
    });
    let kev_matches = matches
        .iter()
        .filter(|finding| {
            finding
                .pointer("/kev/known_exploited")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let reached_matches = matches
        .iter()
        .filter(|finding| {
            finding
                .pointer("/reachability/status")
                .and_then(Value::as_str)
                == Some("reached_by_fuzz")
        })
        .count();
    Ok(json!({
        "schema_version": VULNERABILITY_SCHEMA_VERSION,
        "counts": {
            "matches": matches.len(),
            "kev_matches": kev_matches,
            "reached_matches": reached_matches
        },
        "gate": {
            "fail_on": fail_on,
            "failed": gate_failed
        },
        "matches": matches
    }))
}

fn sbom_gate_threshold(options: &SbomOptions) -> Result<Option<String>, GovernanceError> {
    if options.fail_on.is_some() {
        return Ok(options.fail_on.clone());
    }
    let Some(policy) = &options.policy else {
        return Ok(None);
    };
    let value = read_json(policy)?;
    Ok(value
        .pointer("/ci/fail_on_vulnerability_severity")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

/// Structural purl comparison. Advisory purls routinely omit the version
/// (OSV pins versions in `affected_versions` instead) or differ in case
/// and qualifiers, so exact string equality would veto real matches.
/// Compare type/namespace/name case-insensitively and let versions
/// disagree only when both sides pin one.
fn purl_compatible(left: &str, right: &str) -> bool {
    match (parse_purl(left), parse_purl(right)) {
        (Some(left), Some(right)) => {
            left.base == right.base
                && match (&left.version, &right.version) {
                    (Some(left_version), Some(right_version)) => left_version == right_version,
                    _ => true,
                }
        }
        _ => left.trim() == right.trim(),
    }
}

struct ParsedPurl {
    base: String,
    version: Option<String>,
}

fn parse_purl(raw: &str) -> Option<ParsedPurl> {
    let rest = raw.trim().strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (base, version) = match rest.rsplit_once('@') {
        Some((base, version)) if !version.is_empty() => (base, Some(version.to_ascii_lowercase())),
        _ => (rest, None),
    };
    let base = base.trim_matches('/').to_ascii_lowercase();
    if base.is_empty() {
        return None;
    }
    Some(ParsedPurl { base, version })
}

/// Field-wise CPE comparison covering both 2.3 formatted strings and 2.2
/// URIs. `*` (and a missing trailing field) is ANY on either side; all
/// other fields compare case-insensitively.
fn cpe_compatible(left: &str, right: &str) -> bool {
    let (Some(left_fields), Some(right_fields)) = (cpe_fields(left), cpe_fields(right)) else {
        return left.trim().eq_ignore_ascii_case(right.trim());
    };
    let len = left_fields.len().max(right_fields.len());
    (0..len).all(|index| {
        let left_field = left_fields.get(index).map(String::as_str).unwrap_or("*");
        let right_field = right_fields.get(index).map(String::as_str).unwrap_or("*");
        left_field == "*" || right_field == "*" || left_field == right_field
    })
}

fn cpe_fields(raw: &str) -> Option<Vec<String>> {
    let raw = raw.trim();
    let rest = raw
        .strip_prefix("cpe:2.3:")
        .or_else(|| raw.strip_prefix("cpe:/"))?;
    Some(
        rest.split(':')
            .map(|field| field.trim().to_ascii_lowercase())
            .collect(),
    )
}

fn vulnerability_cpe<'a>(vuln: &'a Value, package: &'a Value) -> Option<&'a str> {
    package
        .get("cpe")
        .and_then(Value::as_str)
        .or_else(|| vuln.get("cpe").and_then(Value::as_str))
        .map(str::trim)
        .filter(|cpe| !cpe.is_empty())
}

fn vulnerability_purl<'a>(vuln: &'a Value, package: &'a Value) -> Option<&'a str> {
    package
        .get("purl")
        .and_then(Value::as_str)
        .or_else(|| vuln.get("purl").and_then(Value::as_str))
        .map(str::trim)
        .filter(|purl| !purl.is_empty())
}

fn vulnerability_matching_method(
    component: &Component,
    cpe_matches: bool,
    purl_matches: bool,
) -> &'static str {
    if cpe_matches {
        "cpe"
    } else if purl_matches {
        "purl"
    } else if component.identity_confidence == "high" {
        "package_name_version"
    } else {
        "ambiguous_name_version"
    }
}

fn vulnerability_match(
    vuln: &Value,
    component: &Component,
    reachability: &[ReachabilityHit],
    matching_method: &str,
    campaign_ran: bool,
) -> Value {
    let mut finding = json!({
        "id": vuln.get("id").and_then(Value::as_str).unwrap_or("unknown"),
        "severity": vuln.get("severity").and_then(Value::as_str).unwrap_or("unknown"),
        "summary": vuln.get("summary").and_then(Value::as_str),
        "component_ref": component.component_ref,
        "component": {
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "purl": component.purl,
            "cpe": component.cpe,
            "sha256": component.sha256
        },
        "match_confidence": if matches!(matching_method, "cpe" | "purl") { "high" } else { component.identity_confidence.as_str() },
        "matching_method": matching_method,
        "evidence": component.evidence_summary()
    });
    if let Some(kev) = normalized_kev(vuln) {
        finding["kev"] = kev;
    }
    if let Some(cvss) = vuln.get("cvss") {
        finding["cvss"] = cvss.clone();
    }
    if let Some(cwe) = normalized_cwe(vuln) {
        finding["cwe"] = cwe;
    } else {
        // Campaign fix: a CVE/VEX advisory lacking a CWE must still carry one so
        // the "every vulnerability row carries a CWE" contract holds in
        // vulnerabilities.csv / .json / CycloneDX. CWE-1395 (Dependency on a
        // Vulnerable Third-Party Component) is a defensible leaf last resort
        // (CWE-noinfo is rejected as a non-leaf category). Mirrors the fuzz
        // path's last-resort CWE backfill.
        finding["cwe"] = json!(["CWE-1395"]);
    }
    if let Some(references) = normalized_vulnerability_references(vuln) {
        finding["references"] = references;
    }
    if reachability.is_empty() {
        finding["reachability"] = json!({
            "status": "not_observed",
            "source": "auto_run"
        });
    } else {
        finding["reachability"] = json!({
            "status": "reached_by_fuzz",
            "source": "auto_run",
            "harnesses": reachability.iter().map(ReachabilityHit::to_json).collect::<Vec<_>>()
        });
    }
    finding["vex"] = vex_assessment(vuln, component, reachability, campaign_ran);
    finding
}

/// Compute the conservative VEX assessment for this `(vuln, component)` match
/// and serialize it. Driven by the matched component's top usage rung, whether
/// a campaign ran (validated reachability present), and whether the vuln's
/// fixed version is at or below the resolved version.
fn vex_assessment(
    vuln: &Value,
    component: &Component,
    reachability: &[ReachabilityHit],
    campaign_ran: bool,
) -> Value {
    // Effective top rung: the component's evidence ladder, lifted to FuzzReached
    // when this specific match has validated reachability hits. Both are derived
    // from the same validated reachability map (never raw fork-server signals).
    let mut top_rung = sbom_ingest::top_rung(&component.evidence);
    if !reachability.is_empty() {
        top_rung = Some(top_rung.map_or(EvidenceKind::FuzzReached, |rung| {
            rung.max(EvidenceKind::FuzzReached)
        }));
    }

    // Fixed-version dominance: only when the vuln pins a fixed/patched version
    // at or below the component's resolved version (conservative comparison).
    let (fixed_applies, fixed_version) =
        vulnerability_fixed_state(vuln, component.version.as_deref());

    let harnesses: Vec<String> = reachability
        .iter()
        .map(|hit| hit.harness_id.clone())
        .collect();
    let product_id = component
        .purl
        .as_deref()
        .filter(|purl| !purl.is_empty())
        .unwrap_or(component.component_ref.as_str());
    let evidence_summary = component.evidence_summary();

    let ctx = vex::AssessmentContext {
        top_rung,
        campaign_ran,
        fixed_applies,
        fixed_version: fixed_version.as_deref(),
        resolved_version: component.version.as_deref(),
        product_id,
        evidence_summary: &evidence_summary,
        harnesses: &harnesses,
    };
    let assessment = vex::assess(&ctx);
    let cve = vuln.get("id").and_then(Value::as_str).unwrap_or("unknown");
    json!({
        "status": assessment.status.openvex(),
        "justification": assessment.justification,
        "impact_statement": assessment.impact_statement,
        "product_id": product_id,
        "openvex_statement": vex::openvex_statement(cve, product_id, &assessment),
        "cyclonedx_analysis": vex::cyclonedx_analysis(&assessment)
    })
}

/// Extract the vuln's fixed/patched version (if any) and decide whether the
/// resolved component version is at or above it. Recognizes `fixed_versions`
/// (array) and `fixed_version` / `patched_version` (string). Never panics.
fn vulnerability_fixed_state(vuln: &Value, resolved: Option<&str>) -> (bool, Option<String>) {
    let mut fixed_versions = string_array(vuln.get("fixed_versions"));
    for key in ["fixed_version", "patched_version"] {
        if let Some(value) = vuln.get(key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                fixed_versions.push(trimmed.to_owned());
            }
        }
    }
    let Some(resolved) = resolved else {
        return (false, None);
    };
    for fixed in &fixed_versions {
        if vex::resolved_at_or_above_fixed(resolved, fixed) {
            return (true, Some(fixed.clone()));
        }
    }
    (false, None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReachabilityHit {
    harness_id: String,
    source_path: String,
    target_name: String,
    executions: u64,
}

impl ReachabilityHit {
    fn to_json(&self) -> Value {
        json!({
            "harness_id": self.harness_id,
            "source_path": self.source_path,
            "target_name": self.target_name,
            "executions": self.executions
        })
    }
}

#[derive(Debug, Clone, Default)]
struct SbomReachability {
    hits: Vec<ReachabilityHit>,
}

impl SbomReachability {
    /// A fuzz campaign "ran" for this SBOM iff the validated reachability map is
    /// non-empty. This single signal gates the dynamic VEX `not_affected`.
    fn campaign_ran(&self) -> bool {
        !self.hits.is_empty()
    }

    fn hits_for_component(&self, component: &Component) -> Vec<ReachabilityHit> {
        if !component.runtime_harnesses.is_empty() {
            return self
                .hits
                .iter()
                .filter(|hit| {
                    component
                        .runtime_harnesses
                        .iter()
                        .any(|harness| harness == &hit.harness_id)
                })
                .cloned()
                .collect();
        }
        self.hits
            .iter()
            .filter(|hit| component_path_overlaps_hit(component, hit))
            .cloned()
            .collect()
    }
}

fn load_sbom_reachability(options: &SbomOptions) -> Result<SbomReachability, GovernanceError> {
    let mut hits = Vec::new();
    for path in auto_run_json_paths(options) {
        if !path.is_file() {
            continue;
        }
        let value = read_json(&path)?;
        hits.extend(reachability_hits_from_auto_run(&options.root, &value));
    }
    hits.sort_by(|left, right| {
        left.source_path
            .cmp(&right.source_path)
            .then_with(|| left.harness_id.cmp(&right.harness_id))
    });
    hits.dedup();
    Ok(SbomReachability { hits })
}

fn auto_run_json_paths(options: &SbomOptions) -> Vec<PathBuf> {
    let mut run_jsons = Vec::new();
    // An explicit --run-json is consulted in addition to the conventional
    // auto-detected locations under the tree / work dir.
    if let Some(run_json) = &options.run_json {
        run_jsons.push(run_json.clone());
    }
    run_jsons.push(options.root.join("auto/run.json"));
    if let Some(parent) = options.out_dir.parent() {
        run_jsons.push(parent.join("auto/run.json"));
    }
    run_jsons.sort();
    run_jsons.dedup();
    run_jsons
}

fn reachability_hits_from_auto_run(root: &Path, run: &Value) -> Vec<ReachabilityHit> {
    run.get("targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|target| {
            target.pointer("/outcome/outcome").and_then(Value::as_str) == Some("built_and_fuzzed")
        })
        .filter_map(|target| {
            let source_path = target
                .get("source")
                .or_else(|| target.get("source_path"))
                .and_then(Value::as_str)?;
            Some(ReachabilityHit {
                harness_id: target
                    .get("harness_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                source_path: normalize_evidence_path(root, source_path),
                target_name: target
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                executions: target
                    .pointer("/outcome/passes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|pass| pass.get("executions").and_then(Value::as_u64))
                    .sum(),
            })
        })
        .collect()
}

fn component_path_overlaps_hit(component: &Component, hit: &ReachabilityHit) -> bool {
    component_path_candidates(component)
        .into_iter()
        .any(|candidate| evidence_paths_overlap(&candidate, &hit.source_path))
}

fn component_path_candidates(component: &Component) -> Vec<String> {
    // Only the static rungs carry real source paths; the dynamic rungs
    // (`Linked` / `RuntimeLoaded` / `FuzzReached`) carry synthetic locator
    // strings (`source:…`, `auto/run.json:…`) that must not be treated as
    // filesystem paths. Consider each path-bearing evidence source on its own so
    // an added dynamic rung never corrupts the path-overlap match.
    let mut candidates: Vec<String> = component
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EvidenceKind::Declared | EvidenceKind::Resolved | EvidenceKind::SourceObserved
            )
        })
        .map(|e| normalize_relative_path(&e.source))
        .collect();
    if component.component_type == "binary" {
        candidates.push(normalize_relative_path(&component.name));
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn evidence_paths_overlap(left: &str, right: &str) -> bool {
    let left = component_scope_path(left);
    let right = normalize_relative_path(right);
    left == right || path_is_within(&right, &left) || path_is_within(&left, &right)
}

fn component_scope_path(path: &str) -> String {
    let normalized = normalize_relative_path(path);
    if normalized.rsplit('/').next().is_some_and(|name| {
        matches!(
            name,
            "Cargo.toml" | "package.json" | "component.json" | "govfuzz-component.json" | "VERSION"
        )
    }) {
        normalized
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_owned())
            .unwrap_or(normalized)
    } else {
        normalized
    }
}

fn path_is_within(path: &str, parent: &str) -> bool {
    !parent.is_empty()
        && path.len() > parent.len()
        && path.starts_with(parent)
        && path.as_bytes().get(parent.len()) == Some(&b'/')
}

fn normalize_evidence_path(root: &Path, path: &str) -> String {
    let raw = Path::new(path);
    if raw.is_absolute() {
        normalize_relative_path(&relative_path(root, raw))
    } else {
        normalize_relative_path(path)
    }
}

fn normalize_relative_path(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_owned();
    }
    normalized.trim_matches('/').to_owned()
}

fn normalized_kev(vuln: &Value) -> Option<Value> {
    let kev = vuln.get("kev")?;
    match kev {
        Value::Bool(true) => Some(json!({
            "known_exploited": true
        })),
        Value::Object(_) => {
            let known = kev
                .get("known_exploited")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if !known {
                return None;
            }
            Some(json!({
                "known_exploited": true,
                "date_added": kev.get("date_added").and_then(Value::as_str),
                "due_date": kev.get("due_date").and_then(Value::as_str),
                "required_action": kev.get("required_action").and_then(Value::as_str),
                "source": kev.get("source").and_then(Value::as_str).unwrap_or("CISA KEV")
            }))
        }
        _ => None,
    }
}

fn normalized_cwe(vuln: &Value) -> Option<Value> {
    let cwe = vuln.get("cwe").or_else(|| vuln.get("cwes"))?;
    let mut values = Vec::new();
    match cwe {
        Value::String(value) => push_normalized_cwe(&mut values, value),
        Value::Number(number) => push_normalized_cwe(&mut values, &number.to_string()),
        Value::Array(items) => {
            for item in items {
                if let Some(value) = item.as_str() {
                    push_normalized_cwe(&mut values, value);
                } else if let Some(number) = item.as_u64() {
                    push_normalized_cwe(&mut values, &number.to_string());
                }
            }
        }
        _ => {}
    }
    if values.is_empty() {
        None
    } else {
        Some(json!(values))
    }
}

fn normalized_vulnerability_references(vuln: &Value) -> Option<Value> {
    let references = vuln.get("references").or_else(|| vuln.get("advisories"))?;
    let mut normalized = Vec::<Value>::new();
    match references {
        Value::String(url) => {
            push_normalized_vulnerability_reference(
                &mut normalized,
                url,
                None,
                vuln.get("id").and_then(Value::as_str),
            );
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(url) => {
                        push_normalized_vulnerability_reference(
                            &mut normalized,
                            url,
                            None,
                            vuln.get("id").and_then(Value::as_str),
                        );
                    }
                    Value::Object(_) => {
                        if let Some(url) = item.get("url").and_then(Value::as_str) {
                            push_normalized_vulnerability_reference(
                                &mut normalized,
                                url,
                                item.get("title").and_then(Value::as_str),
                                vuln.get("id").and_then(Value::as_str),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    if normalized.is_empty() {
        None
    } else {
        Some(json!(normalized))
    }
}

fn push_normalized_vulnerability_reference(
    references: &mut Vec<Value>,
    url: &str,
    title: Option<&str>,
    vuln_id: Option<&str>,
) {
    let url = url.trim();
    if url.is_empty() || references.iter().any(|reference| reference["url"] == url) {
        return;
    }
    let title = title
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_owned)
        .or_else(|| vuln_id.map(|id| format!("{id} advisory")))
        .unwrap_or_else(|| "vulnerability advisory".to_owned());
    references.push(json!({
        "title": title,
        "url": url
    }));
}

fn push_normalized_cwe(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let normalized = if parse_cwe_number(value).is_some()
        && !value
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CWE-"))
    {
        format!("CWE-{value}")
    } else {
        value.to_owned()
    };
    if !values.iter().any(|existing| existing == &normalized) {
        values.push(normalized);
    }
}

fn version_is_affected(version: Option<&str>, affected: &[String]) -> bool {
    affected.iter().any(|entry| entry == "*")
        || version.is_some_and(|version| affected.iter().any(|entry| entry == version))
}

fn component_ref(component: &Component) -> String {
    let identity = component
        .version
        .as_deref()
        .or(component.sha256.as_deref())
        .or(component.cpe.as_deref())
        .unwrap_or("unknown");
    // Fold the namespace/group into the name segment so two artifacts that share
    // an artifactId across different groupIds (Maven) get distinct bom-refs.
    match &component.group {
        Some(group) if !group.is_empty() => {
            format!(
                "{}:{group}/{}:{identity}",
                component.ecosystem, component.name
            )
        }
        _ => format!("{}:{}:{identity}", component.ecosystem, component.name),
    }
}

fn finding_identifier(finding: &Value) -> Option<String> {
    finding
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| finding.get("fingerprint").and_then(Value::as_str))
        .map(str::to_owned)
}

fn finding_identifiers(finding: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(id) = finding.get("id").and_then(Value::as_str) {
        ids.push(id.to_owned());
    }
    if let Some(fingerprint) = finding.get("fingerprint").and_then(Value::as_str) {
        ids.push(fingerprint.to_owned());
    }
    ids
}

fn matching_policy_waiver(policy: &Value, finding: &Value) -> Option<Value> {
    let identifiers = finding_identifiers(finding);
    policy
        .pointer("/ci/waivers")
        .and_then(Value::as_array)?
        .iter()
        .find(|waiver| {
            waiver_identifier_matches(waiver.get("finding_id"), &identifiers)
                || waiver_identifier_matches(waiver.get("fingerprint"), &identifiers)
                || waiver_identifier_matches(waiver.get("finding_ids"), &identifiers)
        })
        .cloned()
}

fn matching_policy_baseline(policy: &Value, finding: &Value) -> bool {
    let identifiers = finding_identifiers(finding);
    waiver_identifier_matches(policy.pointer("/ci/baseline_findings"), &identifiers)
        || waiver_identifier_matches(policy.pointer("/ci/baseline/findings"), &identifiers)
}

fn waiver_identifier_matches(value: Option<&Value>, identifiers: &[String]) -> bool {
    match value {
        Some(Value::String(candidate)) => identifiers.iter().any(|id| id == candidate),
        Some(Value::Array(candidates)) => candidates.iter().any(|candidate| {
            candidate
                .as_str()
                .is_some_and(|candidate| identifiers.iter().any(|id| id == candidate))
        }),
        _ => false,
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn walk_all_files(root: &Path) -> Result<Vec<PathBuf>, GovernanceError> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    let mut out = Vec::new();
    collect_all_files(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_all_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), GovernanceError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if !dir_is_excluded(&child) {
                collect_all_files(&child, out)?;
            }
        } else if ty.is_file() {
            out.push(child);
        }
    }
    Ok(())
}

fn dir_is_excluded(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "target" | "govfuzz_work" | "build"))
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(path_string)
        .unwrap_or_else(|_| path_string(path))
}

fn collect_work_artifact(
    work_dir: &Path,
    rel_path: &str,
    kind: &str,
    artifacts: &mut Vec<Value>,
) -> Result<(), GovernanceError> {
    let absolute = work_dir.join(rel_path);
    if absolute.is_file() {
        artifacts.push(export_artifact(kind, rel_path, &absolute)?);
    }
    Ok(())
}

fn collect_artifacts_by_prefix(
    work_dir: &Path,
    rel_prefix: &str,
    kind: &str,
    artifacts: &mut Vec<Value>,
) -> Result<(), GovernanceError> {
    let root = work_dir.join(rel_prefix);
    if !root.is_dir() {
        return Ok(());
    }
    for path in walk_all_files(&root)? {
        let rel_path = relative_path(work_dir, &path);
        artifacts.push(export_artifact(kind, &rel_path, &path)?);
    }
    Ok(())
}

fn collect_artifacts_by_name(
    work_dir: &Path,
    rel_prefix: &str,
    file_name: &str,
    kind: &str,
    artifacts: &mut Vec<Value>,
) -> Result<(), GovernanceError> {
    let root = work_dir.join(rel_prefix);
    if !root.is_dir() {
        return Ok(());
    }
    for path in walk_all_files(&root)? {
        if path.file_name().and_then(|name| name.to_str()) == Some(file_name) {
            let rel_path = relative_path(work_dir, &path);
            artifacts.push(export_artifact(kind, &rel_path, &path)?);
        }
    }
    Ok(())
}

fn missing_required_artifacts(artifacts: &[Value], required: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|kind| {
            !artifacts
                .iter()
                .any(|artifact| artifact.get("kind").and_then(Value::as_str) == Some(kind.as_str()))
        })
        .cloned()
        .collect()
}

fn runner_diagnostics(runners: &[Value]) -> Vec<Value> {
    let mut diagnostics = Vec::new();
    for (index, runner) in runners.iter().enumerate() {
        let base = format!("/runners/{index}");
        if runner
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            diagnostics.push(json!({"path": base, "message": "missing id"}));
        }
        let kind = runner.get("kind").and_then(Value::as_str).unwrap_or("");
        if kind.is_empty() {
            diagnostics.push(json!({"path": base, "message": "missing kind"}));
        } else if !matches!(
            kind,
            "host" | "sandboxed" | "qemu-user" | "cross" | "binary" | "distributed"
        ) {
            diagnostics.push(json!({"path": format!("{base}/kind"), "message": format!("unsupported runner kind '{kind}'")}));
        }
        if string_array(runner.get("languages")).is_empty() {
            diagnostics
                .push(json!({"path": format!("{base}/languages"), "message": "missing languages"}));
        }
        if string_array(runner.get("engines")).is_empty() {
            diagnostics
                .push(json!({"path": format!("{base}/engines"), "message": "missing engines"}));
        }
    }
    diagnostics
}

fn find_runner<'a>(manifest: &'a Value, runner_id: &str) -> Option<&'a Value> {
    manifest
        .get("runners")
        .and_then(Value::as_array)?
        .iter()
        .find(|runner| runner.get("id").and_then(Value::as_str) == Some(runner_id))
}

fn runner_capability_evidence(runner: &Value) -> Value {
    let capabilities = string_array(runner.get("capabilities"));
    let sandbox_required = runner
        .pointer("/sandbox/required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || capabilities
            .iter()
            .any(|capability| capability == "sandbox");
    json!({
        "kind": runner.get("kind").and_then(Value::as_str),
        "languages": string_array(runner.get("languages")),
        "engines": string_array(runner.get("engines")),
        "capabilities": capabilities,
        "sandbox_required": sandbox_required,
        "target": runner.get("target").and_then(Value::as_str)
    })
}

#[derive(Debug, Clone)]
struct RunnerPlanState {
    runner: Value,
    id: String,
    max_jobs: Option<usize>,
    max_seconds: Option<u64>,
    assigned_jobs: usize,
    assigned_seconds: u64,
    job_ids: Vec<String>,
}

impl RunnerPlanState {
    fn new(runner: Value) -> Self {
        let id = runner
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        Self {
            max_jobs: runner
                .pointer("/capacity/max_jobs")
                .and_then(Value::as_u64)
                .map(|value| value as usize),
            max_seconds: runner
                .pointer("/capacity/max_seconds")
                .and_then(Value::as_u64),
            runner,
            id,
            assigned_jobs: 0,
            assigned_seconds: 0,
            job_ids: Vec::new(),
        }
    }

    fn has_capacity_for(&self, job: &Value) -> bool {
        let seconds = estimated_seconds(job);
        self.max_jobs
            .is_none_or(|max_jobs| self.assigned_jobs < max_jobs)
            && self.max_seconds.is_none_or(|max_seconds| {
                self.assigned_seconds.saturating_add(seconds) <= max_seconds
            })
    }

    fn assign(&mut self, job: &Value) {
        let next_index = self.job_ids.len();
        self.assigned_jobs += 1;
        self.assigned_seconds = self.assigned_seconds.saturating_add(estimated_seconds(job));
        self.job_ids.push(job_id(job, next_index));
    }

    fn summary(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.runner.get("kind").and_then(Value::as_str),
            "target": self.runner.get("target").and_then(Value::as_str),
            "capacity": {
                "jobs": self.max_jobs,
                "seconds": self.max_seconds
            },
            "assigned": {
                "jobs": self.assigned_jobs,
                "seconds": self.assigned_seconds,
                "job_ids": self.job_ids
            },
            "remaining_capacity": {
                "jobs": self.max_jobs.map(|max_jobs| max_jobs.saturating_sub(self.assigned_jobs)),
                "seconds": self.max_seconds.map(|max_seconds| max_seconds.saturating_sub(self.assigned_seconds))
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerCompatibility {
    Compatible,
    Rejected(&'static str),
}

fn runner_job_compatibility(
    runner: &Value,
    job: &Value,
    allowed_runners: &[String],
    require_sandbox: bool,
) -> RunnerCompatibility {
    let runner_id = runner.get("id").and_then(Value::as_str).unwrap_or("");
    if !runner_allowed(allowed_runners, runner_id) {
        return RunnerCompatibility::Rejected("runner_not_allowed");
    }
    let runner_caps = string_array(runner.get("capabilities"));
    if require_sandbox && !runner_has_sandbox(runner, &runner_caps) {
        return RunnerCompatibility::Rejected("sandbox_required");
    }
    let language = job.get("language").and_then(Value::as_str).unwrap_or("");
    if !language.is_empty()
        && !string_array(runner.get("languages"))
            .iter()
            .any(|candidate| candidate == language)
    {
        return RunnerCompatibility::Rejected("language_mismatch");
    }
    let engine = job.get("engine").and_then(Value::as_str).unwrap_or("");
    if !engine.is_empty()
        && !string_array(runner.get("engines"))
            .iter()
            .any(|candidate| candidate == engine)
    {
        return RunnerCompatibility::Rejected("engine_mismatch");
    }
    let target = job.get("target").and_then(Value::as_str).unwrap_or("");
    if !target.is_empty() && runner.get("target").and_then(Value::as_str) != Some(target) {
        return RunnerCompatibility::Rejected("target_mismatch");
    }
    let required_caps = string_array(job.get("required_capabilities"));
    if !required_caps
        .iter()
        .all(|required| runner_caps.iter().any(|capability| capability == required))
    {
        return RunnerCompatibility::Rejected("capability_mismatch");
    }
    RunnerCompatibility::Compatible
}

fn runner_allowed(allowed_runners: &[String], runner_id: &str) -> bool {
    allowed_runners.is_empty() || allowed_runners.iter().any(|allowed| allowed == runner_id)
}

fn runner_has_sandbox(runner: &Value, capabilities: &[String]) -> bool {
    runner
        .pointer("/sandbox/required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || capabilities
            .iter()
            .any(|capability| capability == "sandbox")
}

fn job_id(job: &Value, index: usize) -> String {
    job.get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("job-{index:04}", index = index + 1))
}

fn estimated_seconds(job: &Value) -> u64 {
    job.get("estimated_seconds")
        .and_then(Value::as_u64)
        .or_else(|| job.get("timeout_seconds").and_then(Value::as_u64))
        .unwrap_or(0)
}

fn denied_job_tool(job: &Value, denied_external_tools: &[String]) -> Option<String> {
    if denied_external_tools.is_empty() {
        return None;
    }
    string_array(job.get("required_tools"))
        .into_iter()
        .find(|tool| denied_external_tools.iter().any(|denied| denied == tool))
}

fn runner_plan_policy_summary(policy: Option<&Value>) -> Value {
    json!({
        "policy_id": policy
            .and_then(|value| value.get("policy_id"))
            .and_then(Value::as_str)
            .unwrap_or("none"),
        "allowed_runners": string_array(policy.and_then(|value| {
            value
                .pointer("/runners/allowed")
                .or_else(|| value.get("allowed_runners"))
        })),
        "require_sandbox": policy
            .and_then(|value| value.pointer("/runners/require_sandbox"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "denied_external_tools": string_array(policy.and_then(|value| {
            value
                .pointer("/external_tools/denied")
                .or_else(|| value.pointer("/runners/denied_required_tools"))
        }))
    })
}

fn runner_plan_budget_summary(path: &Path) -> Result<Value, GovernanceError> {
    let value = read_json(path)?;
    let assigned = value
        .pointer("/counts/assigned")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            value
                .get("assignments")
                .and_then(Value::as_array)
                .map_or(0, |assignments| assignments.len() as u64)
        });
    let unassigned = value
        .pointer("/counts/unassigned")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            value
                .get("unassigned")
                .and_then(Value::as_array)
                .map_or(0, |unassigned| unassigned.len() as u64)
        });
    let jobs = value
        .pointer("/counts/jobs")
        .and_then(Value::as_u64)
        .unwrap_or(assigned + unassigned);
    Ok(json!({
        "source": path_string(path),
        "valid": value.get("valid").and_then(Value::as_bool),
        "jobs": jobs,
        "assigned": assigned,
        "unassigned": unassigned
    }))
}

fn update_pack_signature_summary(
    manifest: &Value,
    policy: Option<&Value>,
) -> (Value, Vec<Value>, bool) {
    let require_signature = policy
        .and_then(|value| value.pointer("/update_packs/require_signature"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let trusted_keys =
        string_array(policy.and_then(|value| value.pointer("/update_packs/trusted_keys")));
    let items = manifest
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let expected_digest = pack_items_signature_digest(&items);
    let mut diagnostics = Vec::new();

    let Some(signature) = manifest.get("signature") else {
        if require_signature {
            diagnostics.push(json!({
                "decision": "require_signature",
                "allowed": false,
                "message": "update pack signature is required by policy"
            }));
        }
        return (
            json!({
                "required": require_signature,
                "status": "missing",
                "algorithm": Value::Null,
                "key_id": Value::Null,
                "trusted": false,
                "digest_match": false,
                "expected_digest": expected_digest
            }),
            diagnostics,
            !require_signature,
        );
    };

    let algorithm = signature
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("");
    let key_id = signature
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let digest = signature
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or("");
    let algorithm_ok = algorithm == "sha256-items-v1";
    let digest_match = digest == expected_digest;
    let trusted = !key_id.is_empty()
        && (trusted_keys.is_empty() || trusted_keys.iter().any(|trusted| trusted == key_id));
    let status = if !algorithm_ok {
        "unsupported_algorithm"
    } else if !digest_match {
        "mismatch"
    } else if !trusted {
        "untrusted"
    } else {
        "verified"
    };
    if status != "verified" {
        diagnostics.push(json!({
            "decision": "verify_signature",
            "allowed": false,
            "status": status,
            "message": "update pack signature could not be verified against policy"
        }));
    }

    (
        json!({
            "required": require_signature,
            "status": status,
            "algorithm": algorithm,
            "key_id": key_id,
            "trusted": trusted,
            "digest": digest,
            "expected_digest": expected_digest,
            "digest_match": digest_match
        }),
        diagnostics,
        status == "verified",
    )
}

fn pack_items_signature_digest(items: &[Value]) -> String {
    let mut hasher = Sha256::new();
    for item in items {
        for key in ["kind", "path", "sha256"] {
            hasher.update(
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
            hasher.update(b"\t");
        }
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn parse_pack_item_spec(spec: &str) -> Result<(String, String), GovernanceError> {
    let Some((kind, path)) = spec.split_once(':') else {
        return Err(GovernanceError::InvalidInput {
            message: format!("pack item '{spec}' must use kind:path syntax"),
        });
    };
    let kind = kind.trim();
    let path = path.trim();
    if kind.is_empty() || path.is_empty() {
        return Err(GovernanceError::InvalidInput {
            message: format!("pack item '{spec}' must include both kind and path"),
        });
    }
    if path_escapes_root(path) {
        return Err(GovernanceError::InvalidInput {
            message: format!("pack item path '{path}' must be relative to the pack root"),
        });
    }
    Ok((kind.to_owned(), path.to_owned()))
}

/// True when a path could escape the directory it is joined under:
/// it is absolute, names a Windows prefix/root, or contains a `..`
/// segment. Used to confine update-pack writes (pack_id and item
/// paths) at install time, not just at pack-create time.
fn path_escapes_root(path: &str) -> bool {
    Path::new(path).components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    })
}

fn pack_item_policy_decisions(item: &Value, policy: Option<&Value>) -> Vec<Value> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let kind = item
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let license = item.get("license").and_then(Value::as_str).unwrap_or("");
    let required_tools = string_array(item.get("required_tools"));
    let allowed_kinds = string_array(policy.pointer("/update_packs/allowed_kinds"));
    let denied_licenses = string_array(policy.pointer("/update_packs/denied_licenses"));
    let denied_tools = string_array(policy.pointer("/update_packs/denied_required_tools"));
    let mut decisions = Vec::new();
    if !allowed_kinds.is_empty() && !allowed_kinds.iter().any(|allowed| allowed == kind) {
        decisions.push(json!({
            "decision": "deny_kind",
            "allowed": false,
            "kind": kind,
            "message": format!("pack item kind '{kind}' is not allowed by policy")
        }));
    }
    if denied_licenses.iter().any(|denied| denied == license) {
        decisions.push(json!({
            "decision": "deny_license",
            "allowed": false,
            "license": license,
            "message": format!("pack item license '{license}' is denied by policy")
        }));
    }
    for tool in required_tools {
        if denied_tools.iter().any(|denied| denied == &tool) {
            decisions.push(json!({
                "decision": "deny_required_tool",
                "allowed": false,
                "tool": tool,
                "message": "pack item requires an external tool denied by policy"
            }));
        }
    }
    decisions
}

fn collect_external_artifact(
    path: &Path,
    kind: &str,
    artifacts: &mut Vec<Value>,
) -> Result<(), GovernanceError> {
    if path.is_file() {
        let display = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| path_string(path));
        artifacts.push(export_artifact(kind, &display, path)?);
    }
    Ok(())
}

fn export_artifact(
    kind: &str,
    display_path: &str,
    absolute: &Path,
) -> Result<Value, GovernanceError> {
    let mut value = artifact(kind, display_path, absolute)?;
    value["_source_path"] = json!(path_string(absolute));
    Ok(value)
}

fn artifact(kind: &str, display_path: &str, absolute: &Path) -> Result<Value, GovernanceError> {
    let bytes = fs::read(absolute)?;
    Ok(json!({
        "kind": kind,
        "path": display_path,
        "sha256": sha256_hex(&bytes),
        "bytes": bytes.len()
    }))
}

fn read_json(path: &Path) -> Result<Value, GovernanceError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn missing(path: &Path, field: &'static str) -> GovernanceError {
    GovernanceError::MissingField {
        path: path.to_path_buf(),
        field,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod install_security_tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn cyclonedx_sbom_renders_components_hashes_purls_and_dependencies() {
        let root = PathBuf::from("/workspace/legacy");
        let components = vec![
            Component {
                component_ref: "cargo:legacy-lib:1.2.3".to_owned(),
                name: "legacy-lib".to_owned(),
                version: Some("1.2.3".to_owned()),
                ecosystem: "cargo".to_owned(),
                group: None,
                component_type: "source".to_owned(),
                supplier: None,
                license: None,
                purl: Some("pkg:cargo/legacy-lib@1.2.3".to_owned()),
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "high".to_owned(),
                matching_method: "cargo_manifest".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml")],
                runtime_harnesses: Vec::new(),
            },
            Component {
                component_ref: "binary:build/legacyd:aaaaaaaa".to_owned(),
                name: "build/legacyd".to_owned(),
                version: None,
                ecosystem: "binary".to_owned(),
                group: None,
                component_type: "binary".to_owned(),
                supplier: None,
                license: None,
                purl: None,
                cpe: None,
                sha256: Some("aaaaaaaa".to_owned()),
                hashes: Vec::new(),
                identity_confidence: "low".to_owned(),
                matching_method: "binary_inventory".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Linked, "inventory.json")],
                runtime_harnesses: Vec::new(),
            },
        ];

        let sbom = render_cyclonedx_sbom(&root, &components);

        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.6");
        let tool = &sbom["metadata"]["tools"]["components"][0];
        assert_eq!(tool["name"], "govfuzz");
        assert_eq!(tool["supplier"]["name"], "Tarmo Technologies");
        assert_eq!(
            tool["purl"],
            format!("pkg:cargo/govfuzz@{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(tool["bom-ref"], tool["purl"]);
        assert_eq!(
            sbom["dependencies"][0]["dependsOn"],
            json!(["cargo:legacy-lib:1.2.3", "binary:build/legacyd:aaaaaaaa"])
        );
        let binary = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "build/legacyd")
            .unwrap();
        assert_eq!(binary["type"], "file");
        assert_eq!(binary["hashes"][0]["alg"], "SHA-256");
        assert_eq!(binary["hashes"][0]["content"], "aaaaaaaa");
    }

    #[test]
    fn metadata_component_adopts_root_self_manifest_identity() {
        // A `source` component whose manifest sits at the scan root (a bare
        // filename) IS the BOM's primary subject: metadata.component must adopt
        // its name/version/purl/licenses, keeping bom-ref + govfuzz:root.
        let root = PathBuf::from("/workspace/myproj");
        let components = vec![
            Component {
                component_ref: "cargo:myproj:1.2.0".to_owned(),
                name: "myproj".to_owned(),
                version: Some("1.2.0".to_owned()),
                ecosystem: "cargo".to_owned(),
                group: None,
                component_type: "source".to_owned(),
                supplier: None,
                license: Some("Apache-2.0".to_owned()),
                purl: Some("pkg:cargo/myproj@1.2.0".to_owned()),
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "high".to_owned(),
                matching_method: "cargo_manifest".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml")],
                runtime_harnesses: Vec::new(),
            },
            // A nested workspace member (NOT root-level) must NOT be adopted.
            Component {
                component_ref: "cargo:inner:0.1.0".to_owned(),
                name: "inner".to_owned(),
                version: Some("0.1.0".to_owned()),
                ecosystem: "cargo".to_owned(),
                group: None,
                component_type: "source".to_owned(),
                supplier: None,
                license: None,
                purl: Some("pkg:cargo/inner@0.1.0".to_owned()),
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "high".to_owned(),
                matching_method: "cargo_manifest".to_owned(),
                evidence: vec![Evidence::new(
                    EvidenceKind::Declared,
                    "crates/inner/Cargo.toml",
                )],
                runtime_harnesses: Vec::new(),
            },
        ];

        let sbom = render_cyclonedx_sbom(&root, &components);
        let meta = &sbom["metadata"]["component"];
        assert_eq!(meta["name"], "myproj");
        assert_eq!(meta["version"], "1.2.0");
        assert_eq!(meta["purl"], "pkg:cargo/myproj@1.2.0");
        assert_eq!(meta["licenses"][0]["license"]["id"], "Apache-2.0");
        // Graph identity is preserved.
        assert_eq!(meta["bom-ref"], "govfuzz:scanned-root");
        assert_eq!(meta["properties"][0]["name"], "govfuzz:root");
    }

    #[test]
    fn metadata_component_falls_back_to_dir_name_without_root_manifest() {
        // A pure-C tree (no manifest at root) keeps the dir-name + "unknown"
        // fallback. The lone component is a vendored lib, not a project-self.
        let root = PathBuf::from("/workspace/lua");
        let components = vec![Component {
            component_ref: "generic:zlib:1.3".to_owned(),
            name: "zlib".to_owned(),
            version: Some("1.3".to_owned()),
            ecosystem: "generic".to_owned(),
            group: None,
            component_type: "vendored".to_owned(),
            supplier: None,
            license: None,
            purl: None,
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "low".to_owned(),
            matching_method: "directory_version".to_owned(),
            evidence: vec![Evidence::new(
                EvidenceKind::Declared,
                "vendor/zlib-1.3/VERSION",
            )],
            runtime_harnesses: Vec::new(),
        }];

        let sbom = render_cyclonedx_sbom(&root, &components);
        let meta = &sbom["metadata"]["component"];
        assert_eq!(meta["name"], "lua");
        assert_eq!(meta["version"], "unknown");
        assert!(
            meta.get("purl").is_none(),
            "no purl without a self-manifest"
        );
        assert_eq!(meta["licenses"][0]["license"]["name"], "unknown");
        assert_eq!(meta["supplier"]["name"], "unknown");
    }

    fn maven_component_with_group() -> Component {
        Component {
            component_ref: String::new(),
            name: "spring-core".to_owned(),
            group: Some("org.springframework".to_owned()),
            version: Some("6.1.0".to_owned()),
            ecosystem: "maven".to_owned(),
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: Some("pkg:maven/org.springframework/spring-core@6.1.0".to_owned()),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "pom_xml".to_owned(),
            evidence: vec![Evidence::new(
                EvidenceKind::Declared,
                "pom.xml:org.springframework:spring-core",
            )],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn component_ref_folds_group_into_namespace() {
        // A Maven component's bom-ref must include the groupId so two artifacts
        // sharing an artifactId across groupIds do not collide.
        let c = maven_component_with_group();
        assert_eq!(
            component_ref(&c),
            "maven:org.springframework/spring-core:6.1.0"
        );
        // A component without a group keeps the flat ecosystem:name:version form.
        let mut flat = maven_component_with_group();
        flat.group = None;
        flat.ecosystem = "cargo".to_owned();
        flat.name = "serde".to_owned();
        assert_eq!(component_ref(&flat), "cargo:serde:6.1.0");
    }

    #[test]
    fn cyclonedx_component_emits_group_field() {
        let c = maven_component_with_group();
        let json = cyclonedx_component_json(&c);
        assert_eq!(json["group"], "org.springframework");
        assert_eq!(json["name"], "spring-core");
        // A group-less component omits the field entirely.
        let mut flat = maven_component_with_group();
        flat.group = None;
        assert!(cyclonedx_component_json(&flat).get("group").is_none());
    }

    #[test]
    fn sbom_reachability_matches_manifest_and_vendored_component_paths() {
        let cargo = Component {
            component_ref: "cargo:legacy-lib:1.2.3".to_owned(),
            name: "legacy-lib".to_owned(),
            version: Some("1.2.3".to_owned()),
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "source".to_owned(),
            supplier: None,
            license: None,
            purl: Some("pkg:cargo/legacy-lib@1.2.3".to_owned()),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence: vec![Evidence::new(
                EvidenceKind::Declared,
                "crates/legacy-lib/Cargo.toml",
            )],
            runtime_harnesses: Vec::new(),
        };
        let vendored = Component {
            component_ref: "generic:ambiguous-lib:1.0.0".to_owned(),
            name: "ambiguous-lib".to_owned(),
            version: Some("1.0.0".to_owned()),
            ecosystem: "generic".to_owned(),
            group: None,
            component_type: "vendored".to_owned(),
            supplier: None,
            license: None,
            purl: None,
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "low".to_owned(),
            matching_method: "directory_version".to_owned(),
            evidence: vec![Evidence::new(
                EvidenceKind::Declared,
                "vendor/ambiguous-lib-1.0.0/VERSION",
            )],
            runtime_harnesses: Vec::new(),
        };
        let cargo_hit = ReachabilityHit {
            harness_id: "H-CARGO".to_owned(),
            source_path: "crates/legacy-lib/src/parser.c".to_owned(),
            target_name: "parse".to_owned(),
            executions: 128,
        };
        let vendor_hit = ReachabilityHit {
            harness_id: "H-VENDOR".to_owned(),
            source_path: "vendor/ambiguous-lib-1.0.0/src/read.c".to_owned(),
            target_name: "read_record".to_owned(),
            executions: 64,
        };

        assert!(component_path_overlaps_hit(&cargo, &cargo_hit));
        assert!(component_path_overlaps_hit(&vendored, &vendor_hit));
        assert!(!component_path_overlaps_hit(&cargo, &vendor_hit));
    }

    fn resolved_component(ecosystem: &str, name: &str, version: &str) -> Component {
        Component {
            component_ref: format!("{ecosystem}:{name}:{version}"),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            ecosystem: ecosystem.to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: Some(format!("pkg:{ecosystem}/{name}@{version}")),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "manifest".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Resolved, "manifest")],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn import_observation_promotes_only_imported_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write(
            &root.join("main.go"),
            "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/used/mod/sub\"\n)\n\nfunc main() { fmt.Println(sub.X) }\n",
        );
        write(
            &root.join("app.rs"),
            "use serde_json::Value;\nuse std::io::Read;\nfn main() {}\n",
        );

        let mut components = vec![
            resolved_component("golang", "github.com/used/mod", "1.0.0"),
            resolved_component("golang", "github.com/unused/mod", "2.0.0"),
            resolved_component("cargo", "serde-json", "1.0.0"),
            resolved_component("cargo", "unused-crate", "3.0.0"),
        ];
        enrich_source_imports(&mut components, &root).unwrap();

        let top = |name: &str| {
            components
                .iter()
                .find(|c| c.name == name)
                .and_then(|c| c.evidence.iter().map(|e| e.kind).max())
        };
        assert_eq!(
            top("github.com/used/mod"),
            Some(EvidenceKind::SourceObserved),
            "an imported Go module is promoted to source-observed",
        );
        assert_eq!(
            top("github.com/unused/mod"),
            Some(EvidenceKind::Resolved),
            "a Go module never imported stays merely resolved",
        );
        assert_eq!(
            top("serde-json"),
            Some(EvidenceKind::SourceObserved),
            "an imported crate (dash→underscore) is promoted",
        );
        assert_eq!(
            top("unused-crate"),
            Some(EvidenceKind::Resolved),
            "a crate never used stays merely resolved",
        );
    }

    #[test]
    fn sbom_includes_runtime_dlopen_components_with_reachability() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(root.join("auto")).unwrap();
        write(
            &root.join("auto/run.json"),
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.auto.v1",
                "needed_for_build": {
                    "dlopen_failures": [{
                        "name": "libssl.so.1.1",
                        "referenced_by_targets": ["H-SSL"]
                    }]
                },
                "targets": [{
                    "harness_id": "H-SSL",
                    "source": root.join("src/tls.c"),
                    "name": "parse_tls",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "passes": [{ "executions": 77 }]
                    }
                }]
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-4242",
                    "severity": "high",
                    "summary": "runtime OpenSSL fixture",
                    "package": {
                        "ecosystem": "runtime-dlopen",
                        "name": "libssl"
                    },
                    "affected_versions": ["1.1"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let component = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libssl")
            .expect("runtime dlopen component present");
        assert_eq!(component["ecosystem"], "runtime-dlopen");
        assert_eq!(component["version"], "1.1");
        assert_eq!(component["matching_method"], "runtime_dlopen");
        assert_eq!(component["runtime_harnesses"], json!(["H-SSL"]));

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let runtime_component = cyclonedx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libssl")
            .expect("runtime component present in CycloneDX");
        assert!(runtime_component["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property["name"] == "govfuzz:matching_method"
                && property["value"] == "runtime_dlopen"));

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 1);
        assert_eq!(vulns["counts"]["reached_matches"], 1);
        assert_eq!(
            vulns["matches"][0]["reachability"]["status"],
            "reached_by_fuzz"
        );
        assert_eq!(
            vulns["matches"][0]["reachability"]["harnesses"][0]["harness_id"],
            "H-SSL"
        );
    }

    #[test]
    fn sbom_matches_declared_component_by_cpe() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        let openssl_cpe = "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*";
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "openssl",
                "version": "3.0.13",
                "ecosystem": "generic",
                "type": "vendored",
                "cpe": openssl_cpe
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-CPE",
                    "severity": "high",
                    "summary": "CPE-only OpenSSL fixture",
                    "package": {
                        "cpe": openssl_cpe
                    },
                    "affected_versions": ["3.0.13"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let component = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "openssl")
            .expect("declared OpenSSL component present");
        assert_eq!(component["cpe"], openssl_cpe);

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let cyclonedx_component = cyclonedx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "openssl")
            .expect("declared OpenSSL component present in CycloneDX");
        assert_eq!(cyclonedx_component["cpe"], openssl_cpe);

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 1);
        assert_eq!(vulns["matches"][0]["id"], "CVE-2026-CPE");
        assert_eq!(vulns["matches"][0]["matching_method"], "cpe");
        assert_eq!(vulns["matches"][0]["match_confidence"], "high");
        assert_eq!(vulns["matches"][0]["component"]["cpe"], openssl_cpe);
    }

    #[test]
    fn sbom_preserves_declared_component_supplier_and_license() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "libaudit",
                "version": "2.8.5",
                "ecosystem": "generic",
                "type": "vendored",
                "supplier": "Linux Audit Project",
                "license": "GPL-2.0-or-later"
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let component = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libaudit")
            .expect("declared component present");
        assert_eq!(component["supplier"], "Linux Audit Project");
        assert_eq!(component["license"], "GPL-2.0-or-later");

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let cyclonedx_component = cyclonedx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libaudit")
            .expect("declared component present in CycloneDX");
        assert_eq!(
            cyclonedx_component["supplier"]["name"],
            "Linux Audit Project"
        );
        assert_eq!(
            cyclonedx_component["licenses"][0]["license"]["id"],
            "GPL-2.0-or-later"
        );
    }

    #[test]
    fn sbom_preserves_declared_component_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "libcrypto",
                "version": "3.0.13",
                "ecosystem": "generic",
                "type": "vendored",
                "sha256": sha256
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let component = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libcrypto")
            .expect("declared component present");
        assert_eq!(component["sha256"], sha256);

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let cyclonedx_component = cyclonedx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "libcrypto")
            .expect("declared component present in CycloneDX");
        assert_eq!(cyclonedx_component["hashes"][0]["alg"], "SHA-256");
        assert_eq!(cyclonedx_component["hashes"][0]["content"], sha256);
    }

    #[test]
    fn sbom_matches_cargo_component_by_purl() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-PURL",
                    "severity": "critical",
                    "summary": "PURL-only Cargo fixture",
                    "package": {
                        "purl": "pkg:cargo/legacy-lib@1.2.3"
                    },
                    "affected_versions": ["1.2.3"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 1);
        assert_eq!(vulns["matches"][0]["id"], "CVE-2026-PURL");
        assert_eq!(vulns["matches"][0]["matching_method"], "purl");
        assert_eq!(vulns["matches"][0]["match_confidence"], "high");
        assert_eq!(
            vulns["matches"][0]["component"]["purl"],
            "pkg:cargo/legacy-lib@1.2.3"
        );
    }

    #[test]
    fn sbom_matches_when_advisory_purl_lacks_version() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-NOVER",
                    "severity": "critical",
                    "summary": "advisory purl without a pinned version",
                    "package": {
                        "ecosystem": "cargo",
                        "name": "legacy-lib",
                        "purl": "pkg:cargo/legacy-lib"
                    },
                    "affected_versions": ["1.2.3"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 1);
        assert_eq!(vulns["matches"][0]["id"], "CVE-2026-NOVER");
    }

    #[test]
    fn sbom_matches_when_advisory_cpe_version_is_wildcard() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "openssl",
                "version": "3.0.13",
                "ecosystem": "generic",
                "type": "vendored",
                "cpe": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-WILDCPE",
                    "severity": "high",
                    "summary": "advisory CPE with wildcard version",
                    "package": {
                        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
                    },
                    "affected_versions": ["3.0.13"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 1);
        assert_eq!(vulns["matches"][0]["id"], "CVE-2026-WILDCPE");
        assert_eq!(vulns["matches"][0]["matching_method"], "cpe");
    }

    #[test]
    fn sbom_vetoes_component_with_contradictory_purl() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-OTHERPKG",
                    "severity": "critical",
                    "summary": "advisory purl names a different package",
                    "package": {
                        "ecosystem": "cargo",
                        "name": "legacy-lib",
                        "purl": "pkg:cargo/other-lib@1.2.3"
                    },
                    "affected_versions": ["1.2.3"]
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["counts"]["matches"], 0);
    }

    #[test]
    fn cyclonedx_sbom_includes_offline_vulnerability_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-7777",
                    "severity": "critical",
                    "summary": "legacy-lib critical parser issue",
                    "cvss": {
                        "version": "3.1",
                        "score": 9.8,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    },
                    "cwe": ["CWE-787"],
                    "package": {
                        "purl": "pkg:cargo/legacy-lib@1.2.3"
                    },
                    "affected_versions": ["1.2.3"],
                    "references": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-7777",
                        {
                            "title": "CISA KEV catalog entry",
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        }
                    ],
                    "kev": {
                        "known_exploited": true,
                        "date_added": "2026-01-15",
                        "required_action": "Apply vendor update"
                    }
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let vulns = read_json(&out.join("vulnerabilities.json")).unwrap();
        assert_eq!(vulns["matches"][0]["cvss"]["score"], 9.8);
        assert_eq!(
            vulns["matches"][0]["cvss"]["vector"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        assert_eq!(vulns["matches"][0]["cwe"], json!(["CWE-787"]));
        assert_eq!(
            vulns["matches"][0]["references"],
            json!([
                {
                    "title": "CVE-2026-7777 advisory",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7777"
                },
                {
                    "title": "CISA KEV catalog entry",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                }
            ])
        );

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let vulnerabilities = cyclonedx["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        let vulnerability = &vulnerabilities[0];
        assert_eq!(vulnerability["id"], "CVE-2026-7777");
        assert_eq!(vulnerability["ratings"][0]["severity"], "critical");
        assert_eq!(vulnerability["ratings"][0]["score"], 9.8);
        assert_eq!(
            vulnerability["ratings"][0]["vector"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        assert_eq!(vulnerability["ratings"][0]["method"], "CVSSv31");
        assert_eq!(vulnerability["cwes"], json!([787]));
        assert_eq!(vulnerability["affects"][0]["ref"], "cargo:legacy-lib:1.2.3");
        assert_eq!(
            vulnerability["advisories"],
            json!([
                {
                    "title": "CVE-2026-7777 advisory",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7777"
                },
                {
                    "title": "CISA KEV catalog entry",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                }
            ])
        );
        assert!(vulnerability["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property["name"] == "govfuzz:matching_method"
                && property["value"] == "purl"));
        assert!(vulnerability["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property["name"] == "govfuzz:kev_known_exploited"
                && property["value"] == "true"));
    }

    /// Build a valid (hash-matching, unsigned) manifest, then overwrite
    /// its pack_id with a hostile value to exercise the install-time
    /// containment check directly.
    fn manifest_with_pack_id(root: &Path, out: &Path, pack_id: &str) {
        write(&root.join("rules.json"), "{\"rule\":1}");
        create_update_pack_file(
            root,
            "benign",
            Some("1"),
            &["rules:rules.json".to_owned()],
            None,
            &[],
            None,
            out,
        )
        .unwrap();
        let mut value = read_json(out).unwrap();
        value["pack_id"] = json!(pack_id);
        write_json(out, &value).unwrap();
    }

    #[test]
    fn install_rejects_pack_id_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let manifest = tmp.path().join("pack.json");
        let install_dir = tmp.path().join("install");
        fs::create_dir_all(&install_dir).unwrap();

        // A sentinel directory a `..` escape would target.
        let escape_marker = tmp.path().join("escape_zone");

        for hostile in [
            "../escape_zone",
            "/tmp/govfuzz-zipslip",
            "../../escape_zone",
        ] {
            manifest_with_pack_id(&root, &manifest, hostile);
            let result = install_update_pack_file(&manifest, &root, &install_dir, None);
            assert!(
                matches!(result, Err(GovernanceError::InvalidInput { .. })),
                "hostile pack_id {hostile:?} must be rejected, got {result:?}"
            );
        }
        assert!(
            !escape_marker.exists(),
            "no files should be written outside the install dir"
        );
    }

    #[test]
    fn install_rejects_item_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let manifest = tmp.path().join("pack.json");
        let install_dir = tmp.path().join("install");
        fs::create_dir_all(&install_dir).unwrap();

        write(&root.join("rules.json"), "{\"rule\":1}");
        create_update_pack_file(
            &root,
            "benign",
            Some("1"),
            &["rules:rules.json".to_owned()],
            None,
            &[],
            None,
            &manifest,
        )
        .unwrap();
        // Hand-craft a hostile item path (parse_pack_item_spec blocks
        // this at create time, so inject it post-hoc) while keeping the
        // sha256 so verification stays valid.
        let mut value = read_json(&manifest).unwrap();
        let sha = value["items"][0]["sha256"].clone();
        // Place a matching source at the escaped relative location so
        // the hash check would otherwise pass.
        write(&root.join("../escape_item.json"), "{\"rule\":1}");
        value["items"] = json!([{ "kind": "rules", "path": "../escape_item.json", "sha256": sha }]);
        write_json(&manifest, &value).unwrap();

        let result = install_update_pack_file(&manifest, &root, &install_dir, None);
        assert!(
            matches!(result, Err(GovernanceError::InvalidInput { .. })),
            "hostile item path must be rejected, got {result:?}"
        );
    }

    #[test]
    fn install_accepts_benign_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let manifest = tmp.path().join("pack.json");
        let install_dir = tmp.path().join("install");
        fs::create_dir_all(&install_dir).unwrap();

        write(&root.join("rules.json"), "{\"rule\":1}");
        create_update_pack_file(
            &root,
            "rules-2026",
            Some("1"),
            &["rules:rules.json".to_owned()],
            None,
            &[],
            None,
            &manifest,
        )
        .unwrap();
        let installed = install_update_pack_file(&manifest, &root, &install_dir, None).unwrap();
        assert_eq!(installed["valid"], json!(true));
        assert!(install_dir.join("rules-2026/rules.json").is_file());
    }

    // ------------------------------------------------------------------
    // Enrich pass (Phase 4): annotate-or-create Linked / RuntimeLoaded /
    // FuzzReached evidence on already-discovered components.
    // ------------------------------------------------------------------

    /// A minimal source-discovered component with a single `Declared` rung.
    fn declared(name: &str, version: &str, ecosystem: &str) -> Component {
        Component {
            component_ref: String::new(),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            ecosystem: ecosystem.to_owned(),
            group: None,
            component_type: "source".to_owned(),
            supplier: None,
            license: None,
            purl: Some(format!("pkg:{ecosystem}/{name}@{version}")),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "manifest".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, "manifest")],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn soname_base_strips_lib_prefix_and_so_versions() {
        assert_eq!(soname_base("libz.so.1"), "z");
        assert_eq!(soname_base("libssl.so.1.1"), "ssl");
        assert_eq!(soname_base("libpng16.so.16"), "png16");
        assert_eq!(soname_base("libcrypto.so"), "crypto");
        assert_eq!(soname_base("/usr/lib/libz.so.1"), "z");
        assert_eq!(soname_base("LIBZ.SO.1"), "z");
        // Non-library leaf still normalizes to a lowercased basename.
        assert_eq!(soname_base("zlib"), "zlib");
    }

    #[test]
    fn soname_matches_component_by_base_name_case_insensitively() {
        // `libz.so.1` → base `z`, which matches a component literally named `z`.
        let z = declared("z", "1.3.1", "c");
        assert!(soname_matches_component("libz.so.1", &z));
        // `libzlib.so` → base `zlib`, matching the conventional zlib name.
        let zlib = declared("zlib", "1.3.1", "c");
        assert!(soname_matches_component("libzlib.so", &zlib));
        assert!(soname_matches_component("ZLIB.SO", &zlib));
        // Non-matching base must not annotate.
        assert!(!soname_matches_component("libssl.so.3", &zlib));
    }

    #[test]
    fn enrich_linked_annotates_existing_component_not_create() {
        let mut components = vec![declared("zlib", "1.3.1", "c")];
        let inventory = json!({
            "binaries": [{
                "path": "build/app",
                "sha256": "deadbeef",
                "dependencies": { "libraries": ["libz.so.1"] }
            }]
        });
        enrich_linked_from_inventory(&mut components, "inventory.json", &inventory);

        // The binary record is a new component; zlib gains Linked, stays one entry.
        let zlib = components
            .iter()
            .find(|c| c.name == "zlib")
            .expect("zlib retained");
        assert_eq!(
            components.iter().filter(|c| c.name == "zlib").count(),
            1,
            "annotated, not duplicated"
        );
        assert!(zlib
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(zlib
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Linked && e.source == "inventory.json:libz.so.1"));
        assert_eq!(zlib.usage(), "linked");

        // The binary itself still appears (binary-only record).
        assert!(components.iter().any(|c| c.name == "build/app"
            && c.ecosystem == "binary"
            && c.evidence.iter().any(|e| e.kind == EvidenceKind::Linked)));
    }

    #[test]
    fn enrich_linked_creates_component_when_no_match() {
        let mut components = vec![declared("openssl", "3.0", "c")];
        let inventory = json!({
            "binaries": [{
                "path": "build/app",
                "dependencies": { "libraries": ["libfoobar.so.2"] }
            }]
        });
        enrich_linked_from_inventory(&mut components, "inventory.json", &inventory);
        let created = components
            .iter()
            .find(|c| c.name == "foobar")
            .expect("unmatched linked lib created");
        assert_eq!(created.ecosystem, "linked-library");
        assert_eq!(created.version.as_deref(), Some("2"));
        assert_eq!(created.usage(), "linked");
        assert!(!components.iter().any(|c| c.name == "libfoobar.so.2"));
    }

    #[test]
    fn enrich_runtime_annotates_matching_component_else_creates() {
        // A discovered `ssl` should absorb the dlopen of libssl.so.1.1.
        let mut components = vec![declared("ssl", "1.1", "c")];
        let mut by_library = BTreeMap::new();
        by_library.insert("libssl.so.1.1".to_owned(), vec!["H-SSL".to_owned()]);
        by_library.insert("libwidget.so.3".to_owned(), vec!["H-W".to_owned()]);
        enrich_runtime_from_dlopen(&mut components, by_library);

        let ssl = components.iter().find(|c| c.name == "ssl").unwrap();
        assert_eq!(
            components.iter().filter(|c| c.name == "ssl").count(),
            1,
            "annotated not duplicated"
        );
        assert!(ssl
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::RuntimeLoaded));
        assert!(ssl.runtime_harnesses.contains(&"H-SSL".to_owned()));
        assert_eq!(ssl.usage(), "loaded");

        // Unmatched dlopen creates a runtime-dlopen component (legacy shape:
        // the `lib` prefix is retained, e.g. `libwidget`).
        let widget = components
            .iter()
            .find(|c| c.name == "libwidget")
            .expect("unmatched dlopen created");
        assert_eq!(widget.ecosystem, "runtime-dlopen");
        assert_eq!(widget.matching_method, "runtime_dlopen");
        assert_eq!(widget.version.as_deref(), Some("3"));
        assert_eq!(widget.runtime_harnesses, vec!["H-W".to_owned()]);
    }

    #[test]
    fn enrich_fuzz_reached_marks_component_exercised() {
        let mut components = vec![declared("legacy-lib", "1.2.3", "cargo")];
        components[0].evidence = vec![Evidence::new(
            EvidenceKind::Declared,
            "crates/legacy-lib/Cargo.toml",
        )];
        let reachability = SbomReachability {
            hits: vec![ReachabilityHit {
                harness_id: "H1".to_owned(),
                source_path: "crates/legacy-lib/src/parser.c".to_owned(),
                target_name: "parse".to_owned(),
                executions: 99,
            }],
        };
        enrich_fuzz_reached(&mut components, &reachability);
        let c = &components[0];
        assert!(c
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::FuzzReached));
        assert_eq!(c.usage(), "exercised");
    }

    #[test]
    fn enrich_full_pipeline_e2e_linked_then_one_component() {
        // A manifest-declared zlib + a binary inventory listing libz.so.1
        // produces ONE component carrying both Declared and Linked evidence.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "zlib",
                "version": "1.3.1",
                "ecosystem": "generic",
                "type": "vendored"
            }))
            .unwrap(),
        );
        let inventory = tmp.path().join("inventory.json");
        write(
            &inventory,
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.binary.v1",
                "binaries": [{
                    "path": "build/app",
                    "sha256": "aa",
                    "dependencies": { "libraries": ["libz.so.1"] }
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: vec![inventory],
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let zlibs: Vec<_> = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["name"] == "zlib")
            .collect();
        assert_eq!(zlibs.len(), 1, "annotated, not duplicated");
        let evidence = zlibs[0]["evidence"].as_str().unwrap();
        assert!(
            evidence.contains("inventory.json:libz.so.1"),
            "evidence={evidence}"
        );
        // Binary-only record still present.
        assert!(sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "build/app"));
    }

    #[test]
    fn enrich_binary_only_lib_still_appears_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        let inventory = tmp.path().join("inventory.json");
        write(
            &inventory,
            &serde_json::to_string_pretty(&json!({
                "binaries": [{
                    "path": "build/app",
                    "dependencies": { "libraries": ["libz.so.1"] }
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: vec![inventory],
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let z = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "z")
            .expect("binary-only linked lib appears");
        assert_eq!(z["ecosystem"], "linked-library");
        assert_eq!(z["matching_method"], "binary_inventory");
    }

    #[test]
    fn enrich_fuzz_reached_e2e_marks_exercised() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(root.join("crates/legacy-lib/src")).unwrap();
        fs::create_dir_all(root.join("auto")).unwrap();
        write(
            &root.join("crates/legacy-lib/component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "legacy-lib",
                "version": "1.2.3",
                "ecosystem": "generic",
                "type": "vendored"
            }))
            .unwrap(),
        );
        write(
            &root.join("auto/run.json"),
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.auto.v1",
                "targets": [{
                    "harness_id": "H1",
                    "source": root.join("crates/legacy-lib/src/parser.c"),
                    "name": "parse",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "passes": [{ "executions": 99 }]
                    }
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let c = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "legacy-lib")
            .expect("declared component present");
        let evidence = c["evidence"].as_str().unwrap();
        assert!(evidence.contains("fuzz"), "evidence={evidence}");
    }
}

/// End-to-end VEX wiring through `write_sbom`: a tiny vuln-db + a component +
/// (optionally) a fuzz campaign produce `openvex.json` and a CycloneDX
/// `analysis` whose state/justification follow the conservative mapping table.
#[cfg(test)]
mod vex_e2e_tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn write_vuln_db(path: &Path, vuln: Value) {
        write(
            path,
            &serde_json::to_string_pretty(&json!({ "vulnerabilities": [vuln] })).unwrap(),
        );
    }

    /// A campaign that ran but whose single harness lives at `src/other.c` —
    /// disjoint from any library component, so reachability is present (campaign
    /// ran) yet the matched component is never reached.
    fn write_disjoint_campaign(root: &Path) {
        write(
            &root.join("auto/run.json"),
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.auto.v1",
                "targets": [{
                    "harness_id": "H-OTHER",
                    "source": root.join("src/other.c"),
                    "name": "parse_other",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "passes": [{ "executions": 11 }]
                    }
                }]
            }))
            .unwrap(),
        );
    }

    fn openvex_statement_for<'a>(openvex: &'a Value, cve: &str) -> &'a Value {
        openvex["statements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["vulnerability"]["name"] == cve)
            .unwrap_or_else(|| panic!("no openvex statement for {cve}"))
    }

    fn cyclonedx_vuln_for<'a>(cyclonedx: &'a Value, id: &str) -> &'a Value {
        cyclonedx["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no cyclonedx vulnerability for {id}"))
    }

    fn run(root: &Path, out: &Path, vuln_db: &Path, inventories: Vec<PathBuf>) {
        write_sbom(&SbomOptions {
            root: root.to_path_buf(),
            out_dir: out.to_path_buf(),
            vuln_db: Some(vuln_db.to_path_buf()),
            policy: None,
            binary_inventories: inventories,
            fail_on: None,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn declared_only_component_yields_not_affected_vex() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        // Declared component, no source/link evidence, NO campaign.
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "leftpad",
                "version": "1.0.0",
                "ecosystem": "npm",
                "type": "library",
                "purl": "pkg:npm/leftpad@1.0.0"
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_db(
            &vuln_db,
            json!({
                "id": "CVE-2026-DECL",
                "severity": "high",
                "summary": "declared dependency, never built in",
                "package": { "ecosystem": "npm", "name": "leftpad", "purl": "pkg:npm/leftpad@1.0.0" },
                "affected_versions": ["1.0.0"]
            }),
        );

        run(&root, &out, &vuln_db, Vec::new());

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        assert_eq!(openvex["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(openvex["author"], "govfuzz");
        assert_eq!(openvex["timestamp"], SBOM_TIMESTAMP);
        let stmt = openvex_statement_for(&openvex, "CVE-2026-DECL");
        assert_eq!(stmt["status"], "not_affected");
        assert_eq!(stmt["justification"], "vulnerable_code_not_in_execute_path");
        assert_eq!(stmt["products"][0]["@id"], "pkg:npm/leftpad@1.0.0");
        assert!(!stmt["impact_statement"].as_str().unwrap().is_empty());

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let analysis = &cyclonedx_vuln_for(&cyclonedx, "CVE-2026-DECL")["analysis"];
        assert_eq!(analysis["state"], "not_affected");
        assert_eq!(analysis["justification"], "code_not_reachable");
        assert!(!analysis["detail"].as_str().unwrap().is_empty());
    }

    #[test]
    fn linked_with_campaign_and_not_reached_yields_not_affected_citing_campaign() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        // A real (but disjoint) campaign ran.
        write_disjoint_campaign(&root);
        // Binary inventory → a `linked-library` component `vexlib@2.5.0`.
        let inventory = tmp.path().join("inventory.json");
        write(
            &inventory,
            &serde_json::to_string_pretty(&json!({
                "binaries": [{
                    "path": "build/app",
                    "dependencies": { "libraries": ["libvexlib.so.2.5.0"] }
                }]
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_db(
            &vuln_db,
            json!({
                "id": "CVE-2026-LINK",
                "severity": "high",
                "summary": "linked but not reached",
                "package": { "ecosystem": "linked-library", "name": "vexlib" },
                "affected_versions": ["2.5.0"]
            }),
        );

        run(&root, &out, &vuln_db, vec![inventory]);

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        let stmt = openvex_statement_for(&openvex, "CVE-2026-LINK");
        assert_eq!(stmt["status"], "not_affected");
        assert_eq!(stmt["justification"], "vulnerable_code_not_in_execute_path");
        // The dynamic claim MUST cite the campaign as its backing evidence.
        let impact = stmt["impact_statement"].as_str().unwrap();
        assert!(
            impact.contains("fuzz campaign ran"),
            "dynamic not_affected must cite the campaign: {impact}"
        );

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let analysis = &cyclonedx_vuln_for(&cyclonedx, "CVE-2026-LINK")["analysis"];
        assert_eq!(analysis["state"], "not_affected");
        assert_eq!(analysis["justification"], "code_not_reachable");
    }

    #[test]
    fn linked_without_campaign_is_under_investigation_never_not_affected() {
        // THE GUARDRAIL. Same linked component, but NO campaign ran.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        let inventory = tmp.path().join("inventory.json");
        write(
            &inventory,
            &serde_json::to_string_pretty(&json!({
                "binaries": [{
                    "path": "build/app",
                    "dependencies": { "libraries": ["libvexlib.so.2.5.0"] }
                }]
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_db(
            &vuln_db,
            json!({
                "id": "CVE-2026-NOCAMP",
                "severity": "high",
                "summary": "linked, no campaign ran",
                "package": { "ecosystem": "linked-library", "name": "vexlib" },
                "affected_versions": ["2.5.0"]
            }),
        );

        run(&root, &out, &vuln_db, vec![inventory]);

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        let stmt = openvex_statement_for(&openvex, "CVE-2026-NOCAMP");
        assert_eq!(
            stmt["status"], "under_investigation",
            "no campaign must NOT yield not_affected"
        );
        assert_ne!(stmt["status"], "not_affected");
        assert!(stmt.get("justification").is_none());
        let impact = stmt["impact_statement"].as_str().unwrap();
        assert!(impact.contains("no fuzz campaign ran"), "{impact}");

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let analysis = &cyclonedx_vuln_for(&cyclonedx, "CVE-2026-NOCAMP")["analysis"];
        assert_eq!(analysis["state"], "in_triage");
        assert!(analysis.get("justification").is_none());
    }

    #[test]
    fn reached_component_yields_affected_vex() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        // Runtime-dlopen component reached by harness H-SSL (FuzzReached path).
        write(
            &root.join("auto/run.json"),
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.auto.v1",
                "needed_for_build": {
                    "dlopen_failures": [{
                        "name": "libssl.so.1.1",
                        "referenced_by_targets": ["H-SSL"]
                    }]
                },
                "targets": [{
                    "harness_id": "H-SSL",
                    "source": root.join("src/tls.c"),
                    "name": "parse_tls",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "passes": [{ "executions": 77 }]
                    }
                }]
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_db(
            &vuln_db,
            json!({
                "id": "CVE-2026-REACH",
                "severity": "critical",
                "summary": "reached at runtime",
                "package": { "ecosystem": "runtime-dlopen", "name": "libssl" },
                "affected_versions": ["1.1"]
            }),
        );

        run(&root, &out, &vuln_db, Vec::new());

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        let stmt = openvex_statement_for(&openvex, "CVE-2026-REACH");
        assert_eq!(stmt["status"], "affected");
        assert!(stmt.get("justification").is_none());
        let impact = stmt["impact_statement"].as_str().unwrap();
        assert!(impact.contains("executed under fuzzing"), "{impact}");

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let analysis = &cyclonedx_vuln_for(&cyclonedx, "CVE-2026-REACH")["analysis"];
        assert_eq!(analysis["state"], "exploitable");
        assert!(analysis.get("justification").is_none());
    }

    #[test]
    fn patched_resolved_version_yields_fixed_vex() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "openssl",
                "version": "3.0.14",
                "ecosystem": "generic",
                "type": "vendored",
                "purl": "pkg:generic/openssl@3.0.14"
            }))
            .unwrap(),
        );
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_db(
            &vuln_db,
            json!({
                "id": "CVE-2026-FIXED",
                "severity": "high",
                "summary": "patched in 3.0.13; resolved is 3.0.14",
                "package": { "ecosystem": "generic", "name": "openssl", "purl": "pkg:generic/openssl@3.0.14" },
                "affected_versions": ["3.0.14"],
                "fixed_versions": ["3.0.13"]
            }),
        );

        run(&root, &out, &vuln_db, Vec::new());

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        let stmt = openvex_statement_for(&openvex, "CVE-2026-FIXED");
        assert_eq!(stmt["status"], "fixed");
        assert!(stmt.get("justification").is_none());
        let impact = stmt["impact_statement"].as_str().unwrap();
        assert!(impact.contains("patched version 3.0.13"), "{impact}");

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let analysis = &cyclonedx_vuln_for(&cyclonedx, "CVE-2026-FIXED")["analysis"];
        assert_eq!(analysis["state"], "resolved");
    }

    #[test]
    fn no_vuln_db_writes_empty_openvex_and_no_cyclonedx_analysis() {
        // The no-vuln path the golden guards: openvex is written but empty, and
        // CycloneDX gains no vulnerabilities/analysis.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "leftpad",
                "version": "1.0.0",
                "ecosystem": "npm",
                "type": "library"
            }))
            .unwrap(),
        );

        let summary = write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: None,
            policy: None,
            binary_inventories: Vec::new(),
            fail_on: None,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(summary.openvex_path, out.join("openvex.json"));

        let openvex = read_json(&out.join("openvex.json")).unwrap();
        assert_eq!(openvex["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(openvex["statements"].as_array().unwrap().len(), 0);

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        assert!(cyclonedx.get("vulnerabilities").is_none());
    }

    fn write_vuln_component(root: &Path, vuln_db: &Path) {
        write(
            &root.join("component.json"),
            &serde_json::to_string_pretty(&json!({
                "name": "leftpad",
                "version": "1.0.0",
                "ecosystem": "npm",
                "type": "library",
                "purl": "pkg:npm/leftpad@1.0.0"
            }))
            .unwrap(),
        );
        write_vuln_db(
            vuln_db,
            json!({
                "id": "CVE-2026-EMIT",
                "severity": "high",
                "summary": "for emit-selection tests",
                "package": { "ecosystem": "npm", "name": "leftpad", "purl": "pkg:npm/leftpad@1.0.0" },
                "affected_versions": ["1.0.0"]
            }),
        );
    }

    #[test]
    fn default_emit_writes_all_artifacts_including_openvex() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_component(&root, &vuln_db);

        let summary = write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            ..Default::default()
        })
        .unwrap();

        for name in [
            "sbom.json",
            "cyclonedx.json",
            "vulnerabilities.json",
            "openvex.json",
            "sbom.csv",
            "vulnerabilities.csv",
        ] {
            assert!(out.join(name).is_file(), "default emit should write {name}");
        }
        assert_eq!(summary.written.len(), 6);
        // CycloneDX-VEX is on by default: the analysis is embedded.
        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        assert!(cyclonedx_vuln_for(&cyclonedx, "CVE-2026-EMIT")
            .get("analysis")
            .is_some());
    }

    #[test]
    fn emit_sbom_only_writes_sbom_json_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_component(&root, &vuln_db);

        let summary = write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            emit: EmitSet::from_kinds([EmitKind::Sbom]).unwrap(),
            ..Default::default()
        })
        .unwrap();

        assert!(out.join("sbom.json").is_file());
        assert!(!out.join("cyclonedx.json").exists());
        assert!(!out.join("vulnerabilities.json").exists());
        assert!(!out.join("openvex.json").exists());
        assert!(!out.join("sbom.csv").exists());
        assert!(!out.join("vulnerabilities.csv").exists());
        assert_eq!(summary.written, vec![out.join("sbom.json")]);
    }

    #[test]
    fn render_sbom_csv_emits_header_and_one_row_per_component_escaped() {
        let component = Component {
            component_ref: "ref-1".to_owned(),
            name: "lib, special".to_owned(),
            version: Some("1.2.3".to_owned()),
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: Some("Acme \"Corp\"".to_owned()),
            license: Some("MIT".to_owned()),
            purl: Some("pkg:cargo/lib@1.2.3".to_owned()),
            cpe: None,
            sha256: Some("deadbeef".to_owned()),
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence: vec![sbom_ingest::Evidence::new(
                sbom_ingest::EvidenceKind::Declared,
                "Cargo.toml",
            )],
            runtime_harnesses: Vec::new(),
        };
        let csv = render_sbom_csv(std::slice::from_ref(&component));
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), SBOM_CSV_HEADER);
        let row = lines.next().unwrap();
        // Comma-bearing name and quote-bearing supplier are RFC-4180 escaped.
        assert!(row.starts_with("\"lib, special\",1.2.3,cargo,library,\"Acme \"\"Corp\"\"\","));
        assert!(row.contains(",MIT,pkg:cargo/lib@1.2.3,,deadbeef,high,cargo_manifest,"));
        // Exactly one data row.
        assert!(lines.next().is_none());
    }

    #[test]
    fn emit_csv_writes_sbom_csv() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_component(&root, &vuln_db);

        let summary = write_sbom(&SbomOptions {
            root,
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            emit: EmitSet::from_kinds([EmitKind::Csv]).unwrap(),
            ..Default::default()
        })
        .unwrap();

        let csv_path = out.join("sbom.csv");
        let vuln_csv_path = out.join("vulnerabilities.csv");
        assert!(csv_path.is_file());
        assert!(vuln_csv_path.is_file());
        // The `csv` kind writes BOTH the inventory and the CVE-match CSVs.
        assert_eq!(
            summary.written,
            vec![csv_path.clone(), vuln_csv_path.clone()]
        );
        assert_eq!(summary.csv_path, csv_path);
        assert_eq!(summary.vulnerability_csv_path, vuln_csv_path);
        let body = fs::read_to_string(&csv_path).unwrap();
        assert!(body.starts_with(SBOM_CSV_HEADER));
        // Header + at least one component row.
        assert!(body.lines().count() >= 2);
        let vuln_body = fs::read_to_string(&vuln_csv_path).unwrap();
        assert!(vuln_body.starts_with(VULNERABILITY_CSV_HEADER));
    }

    #[test]
    fn emit_spdx_json_writes_valid_spdx_2_3_document() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_component(&root, &vuln_db);

        let summary = write_sbom(&SbomOptions {
            root,
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            emit: EmitSet::from_kinds([EmitKind::SpdxJson]).unwrap(),
            ..Default::default()
        })
        .unwrap();

        let spdx_path = out.join("sbom.spdx.json");
        assert!(spdx_path.is_file(), "spdx-json must write sbom.spdx.json");
        assert_eq!(summary.written, vec![spdx_path.clone()]);
        // Nothing else is written under this emit selection.
        assert!(!out.join("cyclonedx.json").exists());

        let doc = read_json(&spdx_path).unwrap();
        // Required SPDX-2.3 document header fields.
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["dataLicense"], "CC0-1.0");
        assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(doc["name"].is_string());
        assert!(doc["documentNamespace"].is_string());
        assert!(doc["creationInfo"]["creators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str().unwrap().contains("govfuzz")));

        // At least the leftpad package with a versionInfo and required fields.
        let packages = doc["packages"].as_array().unwrap();
        let leftpad = packages
            .iter()
            .find(|p| p["name"] == "leftpad")
            .expect("leftpad package present");
        assert_eq!(leftpad["versionInfo"], "1.0.0");
        assert!(leftpad["SPDXID"].as_str().unwrap().starts_with("SPDXRef-"));
        assert!(leftpad["downloadLocation"].is_string());
        assert!(leftpad["licenseConcluded"].is_string());
        // purl surfaces as an externalRef (PACKAGE-MANAGER / purl).
        let refs = leftpad["externalRefs"].as_array().unwrap();
        assert!(refs
            .iter()
            .any(|r| r["referenceType"] == "purl"
                && r["referenceLocator"] == "pkg:npm/leftpad@1.0.0"));
        // SPDXID values must be unique across packages.
        let mut ids: Vec<&str> = packages
            .iter()
            .map(|p| p["SPDXID"].as_str().unwrap())
            .collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "SPDXIDs must be unique");
    }

    #[test]
    fn emit_csv_writes_vulnerabilities_csv_with_cwe() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"legacy-lib\"\nversion = \"1.2.3\"\n",
        );
        let vuln_db = tmp.path().join("vulns.json");
        write(
            &vuln_db,
            &serde_json::to_string_pretty(&json!({
                "vulnerabilities": [{
                    "id": "CVE-2026-7777",
                    "severity": "critical",
                    "summary": "legacy-lib critical parser issue",
                    "cvss": { "version": "3.1", "score": 9.8 },
                    "cwe": ["CWE-787"],
                    "package": { "purl": "pkg:cargo/legacy-lib@1.2.3" },
                    "affected_versions": ["1.2.3"],
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-7777"],
                    "kev": { "known_exploited": true }
                }]
            }))
            .unwrap(),
        );

        let summary = write_sbom(&SbomOptions {
            root,
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            emit: EmitSet::from_kinds([EmitKind::Csv]).unwrap(),
            ..Default::default()
        })
        .unwrap();

        let vuln_csv = fs::read_to_string(&summary.vulnerability_csv_path).unwrap();
        let mut lines = vuln_csv.lines();
        assert_eq!(lines.next().unwrap(), VULNERABILITY_CSV_HEADER);
        let row = lines.next().expect("one CVE match row");
        let cols: Vec<&str> = row.split(',').collect();
        // component,version,purl,cve,severity,cvss_score,cwe,kev,reachability,advisory
        assert_eq!(cols[0], "legacy-lib");
        assert_eq!(cols[1], "1.2.3");
        assert_eq!(cols[3], "CVE-2026-7777");
        assert_eq!(cols[4], "critical");
        assert_eq!(cols[5], "9.8");
        // The CWE column is pulled from the same normalized field as JSON/CDX.
        assert_eq!(cols[6], "CWE-787");
        assert_eq!(cols[7], "true");
        assert_eq!(cols[8], "not_observed");
        assert_eq!(cols[9], "https://nvd.nist.gov/vuln/detail/CVE-2026-7777");
    }

    #[test]
    fn emit_cyclonedx_without_vex_omits_analysis_but_keeps_vulnerabilities() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        let vuln_db = tmp.path().join("vulns.json");
        write_vuln_component(&root, &vuln_db);

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            vuln_db: Some(vuln_db),
            emit: EmitSet::from_kinds([EmitKind::Cyclonedx]).unwrap(),
            ..Default::default()
        })
        .unwrap();

        let cyclonedx = read_json(&out.join("cyclonedx.json")).unwrap();
        let vuln = cyclonedx_vuln_for(&cyclonedx, "CVE-2026-EMIT");
        // The base CycloneDX vulnerability is present, but the VEX analysis is not.
        assert_eq!(vuln["id"], "CVE-2026-EMIT");
        assert!(
            vuln.get("analysis").is_none(),
            "cyclonedx (no cyclonedx-vex) must omit the VEX analysis"
        );
        assert!(!out.join("openvex.json").exists());
    }

    #[test]
    fn emit_set_parse_list_rejects_unknown_name() {
        assert!(EmitSet::parse_list("sbom,zzz").is_err());
        let set = EmitSet::parse_list("sbom, openvex ").unwrap();
        assert!(set.contains(EmitKind::Sbom));
        assert!(set.contains(EmitKind::Openvex));
        assert!(!set.contains(EmitKind::Cyclonedx));
    }

    #[test]
    fn emit_set_with_vex_forces_the_two_vex_outputs() {
        let set = EmitSet::from_kinds([EmitKind::Sbom]).unwrap().with_vex();
        assert!(set.contains(EmitKind::Openvex));
        assert!(set.contains(EmitKind::CyclonedxVex));
        assert!(set.contains(EmitKind::Sbom));
    }

    #[test]
    fn ecosystems_filter_restricts_catalogers_to_named_ecosystem() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        // A tree with both a cargo and an npm manifest.
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nlicense = \"Apache-2.0\"\n",
        );
        write(
            &root.join("package.json"),
            "{\"name\":\"demo-ui\",\"version\":\"2.0.0\",\"license\":\"MIT\"}",
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            ecosystems: Some(vec!["cargo".to_owned()]),
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        let ecosystems: Vec<String> = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["ecosystem"].as_str().map(str::to_owned))
            .collect();
        assert!(
            ecosystems.iter().all(|e| e == "cargo"),
            "only cargo components expected, got {ecosystems:?}"
        );
        assert!(
            ecosystems.iter().any(|e| e == "cargo"),
            "cargo component must still be discovered"
        );
    }

    #[test]
    fn ecosystems_filter_rejects_unknown_ecosystem() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        write(&root.join("Cargo.toml"), "[package]\nname=\"x\"\n");
        let err = write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: tmp.path().join("sbom"),
            ecosystems: Some(vec!["not-a-real-ecosystem".to_owned()]),
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(err, GovernanceError::InvalidInput { .. }));
        // `known_ecosystems` exposes the registry's `Cataloger::ecosystem()` set.
        assert!(known_ecosystems().contains(&"cargo".to_owned()));
    }

    #[test]
    fn explicit_run_json_supplies_fuzz_reached_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let out = tmp.path().join("sbom");
        // A campaign whose run.json lives at a NON-conventional path (not
        // `<root>/auto/run.json`, not under the out dir) supplied explicitly via
        // --run-json. The dlopen failure creates a runtime component that the
        // FuzzReached pass then annotates — proving the explicit path was read.
        fs::create_dir_all(&root).unwrap();
        let run_json = tmp.path().join("elsewhere/run.json");
        write(
            &run_json,
            &serde_json::to_string_pretty(&json!({
                "schema_version": "govfuzz.auto.v1",
                "needed_for_build": {
                    "dlopen_failures": [{
                        "name": "libssl.so.1.1",
                        "referenced_by_targets": ["H-SSL"]
                    }]
                },
                "targets": [{
                    "harness_id": "H-SSL",
                    "source": root.join("src/tls.c"),
                    "name": "parse_tls",
                    "outcome": {
                        "outcome": "built_and_fuzzed",
                        "passes": [{ "executions": 99 }]
                    }
                }]
            }))
            .unwrap(),
        );

        write_sbom(&SbomOptions {
            root: root.clone(),
            out_dir: out.clone(),
            run_json: Some(run_json),
            ..Default::default()
        })
        .unwrap();

        let sbom = read_json(&out.join("sbom.json")).unwrap();
        // The evidence summary is a `;`-joined list of source locators; a
        // FuzzReached rung contributes an `auto/run.json:fuzz_reached:…` locator.
        let reached = sbom["components"].as_array().unwrap().iter().any(|c| {
            c["evidence"]
                .as_str()
                .is_some_and(|summary| summary.contains("fuzz_reached"))
        });
        assert!(
            reached,
            "explicit --run-json should add FuzzReached evidence: {sbom:#}"
        );
    }
}
