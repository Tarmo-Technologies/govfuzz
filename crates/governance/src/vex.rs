// SPDX-License-Identifier: Apache-2.0

//! VEX (Vulnerability Exploitability eXchange) generation.
//!
//! Turns govfuzz's evidence ladder + fuzz-confirmed reachability into a
//! conservative, auditable exploitability statement per `(vuln, component)`
//! pair. Over-claiming `not_affected` is the cardinal sin, so the dynamic
//! `not_affected` ruling is gated on a campaign actually having run (validated
//! reachability data present for this run).
//!
//! The decision is pure and table-driven (`vex_status_for`) so every row of the
//! mapping table is independently unit-testable. Rendering produces both an
//! OpenVEX statement and a CycloneDX `analysis` object from the same assessment.

use sbom_ingest::EvidenceKind;
use serde_json::{json, Value};

/// OpenVEX statuses we emit. Conservative subset of the OpenVEX vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl VexStatus {
    /// OpenVEX status label.
    pub fn openvex(self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }

    /// CycloneDX `analysis.state` label.
    pub fn cyclonedx_state(self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "exploitable",
            VexStatus::Fixed => "resolved",
            VexStatus::UnderInvestigation => "in_triage",
        }
    }
}

/// The one justification we ever assert: the vulnerable code is not in the
/// fuzzed target's execute path. OpenVEX wording.
pub const JUSTIFICATION_NOT_IN_EXECUTE_PATH: &str = "vulnerable_code_not_in_execute_path";
/// CycloneDX `analysis.justification` for the same claim.
pub const CYCLONEDX_JUSTIFICATION_NOT_REACHABLE: &str = "code_not_reachable";

/// A fully-resolved exploitability assessment for one `(vuln, component)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexAssessment {
    pub status: VexStatus,
    /// `Some` only when we assert `not_affected` with a justification; otherwise
    /// `None` (CycloneDX/OpenVEX omit the field).
    pub justification: Option<&'static str>,
    /// Human-auditable evidence trail. Never empty — a reviewer must be able to
    /// audit every claim.
    pub impact_statement: String,
}

/// The conservative mapping table, as a pure function of the three signals.
///
/// * `top_rung` — the matched component's highest evidence rung (`None` = no
///   evidence at all, treated as Declared/Resolved-level, i.e. not built in).
/// * `campaign_ran` — did a real fuzz campaign run for this SBOM (validated
///   reachability data present)? The dynamic `not_affected` is gated on this.
/// * `fixed_applies` — the vuln carries a fixed/patched version `<=` the
///   resolved component version.
///
/// | Top rung | campaign | fixed | → status |
/// |---|---|---|---|
/// | (any) | — | yes | `Fixed` |
/// | Declared / Resolved / none | — | no | `NotAffected` (in deps, not built in) |
/// | SourceObserved / Linked | ran | no | `NotAffected` (campaign cited) |
/// | SourceObserved / Linked | not ran | no | `UnderInvestigation` |
/// | RuntimeLoaded / FuzzReached | — | no | `Affected` |
pub fn vex_status_for(
    top_rung: Option<EvidenceKind>,
    campaign_ran: bool,
    fixed_applies: bool,
) -> VexStatus {
    // A patched resolved version dominates: it is exploitable-irrelevant
    // regardless of reachability.
    if fixed_applies {
        return VexStatus::Fixed;
    }
    match top_rung {
        // Never source-observed or linked into the fuzzed target: the
        // vulnerable code was not built in. Static, always defensible.
        None | Some(EvidenceKind::Declared) | Some(EvidenceKind::Resolved) => {
            VexStatus::NotAffected
        }
        // Built into the target but never observed loaded/reached. The DYNAMIC
        // not_affected — only defensible if a campaign actually ran.
        Some(EvidenceKind::SourceObserved) | Some(EvidenceKind::Linked) => {
            if campaign_ran {
                VexStatus::NotAffected
            } else {
                VexStatus::UnderInvestigation
            }
        }
        // Code in the component was executed under fuzzing.
        Some(EvidenceKind::RuntimeLoaded) | Some(EvidenceKind::FuzzReached) => VexStatus::Affected,
    }
}

/// Evidence-trail inputs for the audit string. All optional context so the
/// statement remains honest about what backed the ruling.
pub struct AssessmentContext<'a> {
    pub top_rung: Option<EvidenceKind>,
    pub campaign_ran: bool,
    pub fixed_applies: bool,
    pub fixed_version: Option<&'a str>,
    pub resolved_version: Option<&'a str>,
    /// The component purl (or fallback ref) — identifies the product.
    pub product_id: &'a str,
    /// Evidence sources that produced the component's rungs (`evidence_summary`).
    pub evidence_summary: &'a str,
    /// Harness ids / run sources that drove (or could have driven) the
    /// component, when reachability was observed.
    pub harnesses: &'a [String],
}

/// Build the full assessment (status + justification + auditable impact string).
pub fn assess(ctx: &AssessmentContext<'_>) -> VexAssessment {
    let status = vex_status_for(ctx.top_rung, ctx.campaign_ran, ctx.fixed_applies);
    let justification = match status {
        VexStatus::NotAffected => Some(JUSTIFICATION_NOT_IN_EXECUTE_PATH),
        _ => None,
    };
    VexAssessment {
        status,
        justification,
        impact_statement: impact_statement(status, ctx),
    }
}

fn rung_label(top: Option<EvidenceKind>) -> &'static str {
    match top {
        None => "no-evidence",
        Some(kind) => kind.as_str(),
    }
}

/// The auditable evidence trail. Always non-empty; cites the rung, the run
/// status, the component purl, and the harnesses/inventory when present.
fn impact_statement(status: VexStatus, ctx: &AssessmentContext<'_>) -> String {
    let rung = rung_label(ctx.top_rung);
    let campaign = if ctx.campaign_ran {
        "fuzz campaign ran (validated reachability present)"
    } else {
        "no fuzz campaign ran (no reachability data)"
    };
    let harness_trail = if ctx.harnesses.is_empty() {
        String::new()
    } else {
        format!("; harnesses: {}", ctx.harnesses.join(", "))
    };
    let evidence_trail = if ctx.evidence_summary.is_empty() {
        String::new()
    } else {
        format!("; evidence: {}", ctx.evidence_summary)
    };
    match status {
        VexStatus::Fixed => format!(
            "resolved version {} is at or above the patched version {} for {}; {}{}{}",
            ctx.resolved_version.unwrap_or("unknown"),
            ctx.fixed_version.unwrap_or("unknown"),
            ctx.product_id,
            campaign,
            evidence_trail,
            harness_trail,
        ),
        VexStatus::Affected => format!(
            "component {} reached during fuzzing (top rung {}); code in the component was executed under fuzzing; {}{}{}",
            ctx.product_id, rung, campaign, evidence_trail, harness_trail,
        ),
        VexStatus::NotAffected => match ctx.top_rung {
            Some(EvidenceKind::SourceObserved) | Some(EvidenceKind::Linked) => format!(
                "component {} is built into the fuzzed target (top rung {}) but was never observed loaded or reached; {} — vulnerable code not in execute path{}{}",
                ctx.product_id, rung, campaign, evidence_trail, harness_trail,
            ),
            _ => format!(
                "component {} is a dependency (top rung {}) never source-observed or linked into the fuzzed target; vulnerable code not built into the target{}{}",
                ctx.product_id, rung, evidence_trail, harness_trail,
            ),
        },
        VexStatus::UnderInvestigation => format!(
            "component {} is source-observed in the target (top rung {}) but {} — insufficient evidence to assert exploitability either way{}{}",
            ctx.product_id, rung, campaign, evidence_trail, harness_trail,
        ),
    }
}

/// One OpenVEX statement: `{ vulnerability, products, status, justification?,
/// impact_statement }`.
pub fn openvex_statement(cve: &str, product_id: &str, assessment: &VexAssessment) -> Value {
    let mut statement = json!({
        "vulnerability": { "name": cve },
        "products": [ { "@id": product_id } ],
        "status": assessment.status.openvex(),
        "impact_statement": assessment.impact_statement,
    });
    if let Some(justification) = assessment.justification {
        statement["justification"] = json!(justification);
    }
    statement
}

/// The full standalone OpenVEX document. `timestamp` mirrors the CycloneDX
/// `metadata.timestamp` constant — never a wall-clock call.
pub fn render_openvex(id: &str, timestamp: &str, statements: Vec<Value>) -> Value {
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": id,
        "author": "govfuzz",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    })
}

/// The CycloneDX `analysis` object embedded under a `vulnerabilities[]` entry.
pub fn cyclonedx_analysis(assessment: &VexAssessment) -> Value {
    let mut analysis = json!({
        "state": assessment.status.cyclonedx_state(),
        "detail": assessment.impact_statement,
    });
    // Only our not-in-execute-path justification maps to a CycloneDX
    // justification; everything else omits the field.
    if assessment.justification == Some(JUSTIFICATION_NOT_IN_EXECUTE_PATH) {
        analysis["justification"] = json!(CYCLONEDX_JUSTIFICATION_NOT_REACHABLE);
    }
    analysis
}

/// Conservative version comparison for the `fixed` ruling. Returns `true` only
/// when both versions are dotted-numeric-comparable AND `resolved >= fixed`.
/// Anything we cannot confidently compare yields `false` (never over-claim
/// `fixed`). Never panics on malformed input.
pub fn resolved_at_or_above_fixed(resolved: &str, fixed: &str) -> bool {
    match (numeric_version(resolved), numeric_version(fixed)) {
        (Some(resolved), Some(fixed)) => resolved >= fixed,
        _ => false,
    }
}

/// Parse a leading dotted-numeric version (e.g. `1.2.3`, `3.0.13-rc1` → first
/// three numeric components). Returns `None` if there is no numeric prefix, so
/// non-comparable versions degrade to "cannot assert fixed".
fn numeric_version(raw: &str) -> Option<Vec<u64>> {
    let core = raw.trim().trim_start_matches('v');
    let mut parts = Vec::new();
    for segment in core.split(['.', '-', '+', '_']) {
        // Stop at the first non-numeric segment (pre-release / build metadata).
        let digits: String = segment.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse::<u64>().ok()?);
        if digits.len() != segment.len() {
            break;
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- The mapping table, one row per test -----

    #[test]
    fn declared_only_component_is_not_affected() {
        // Row 1: never source-observed/linked → static not_affected.
        let status = vex_status_for(Some(EvidenceKind::Declared), false, false);
        assert_eq!(status, VexStatus::NotAffected);
        let status = vex_status_for(Some(EvidenceKind::Resolved), true, false);
        assert_eq!(status, VexStatus::NotAffected);
    }

    #[test]
    fn no_evidence_component_is_not_affected() {
        // No evidence at all is treated as "not built into the target".
        assert_eq!(vex_status_for(None, false, false), VexStatus::NotAffected);
    }

    #[test]
    fn source_observed_with_campaign_and_not_reached_is_not_affected() {
        // Row 2: built in, campaign ran, never reached → dynamic not_affected.
        assert_eq!(
            vex_status_for(Some(EvidenceKind::SourceObserved), true, false),
            VexStatus::NotAffected
        );
        assert_eq!(
            vex_status_for(Some(EvidenceKind::Linked), true, false),
            VexStatus::NotAffected
        );
    }

    #[test]
    fn source_observed_without_campaign_is_under_investigation_not_not_affected() {
        // GUARDRAIL: the dynamic not_affected requires a real campaign.
        let source = vex_status_for(Some(EvidenceKind::SourceObserved), false, false);
        assert_eq!(source, VexStatus::UnderInvestigation);
        assert_ne!(source, VexStatus::NotAffected);

        let linked = vex_status_for(Some(EvidenceKind::Linked), false, false);
        assert_eq!(linked, VexStatus::UnderInvestigation);
        assert_ne!(linked, VexStatus::NotAffected);
    }

    #[test]
    fn runtime_loaded_or_fuzz_reached_is_affected() {
        // Row 3.
        assert_eq!(
            vex_status_for(Some(EvidenceKind::RuntimeLoaded), true, false),
            VexStatus::Affected
        );
        assert_eq!(
            vex_status_for(Some(EvidenceKind::FuzzReached), true, false),
            VexStatus::Affected
        );
        // Reached even when campaign_ran flag is incidentally false (the rung
        // itself is reachability evidence).
        assert_eq!(
            vex_status_for(Some(EvidenceKind::FuzzReached), false, false),
            VexStatus::Affected
        );
    }

    #[test]
    fn fixed_version_dominates_every_rung() {
        // Row 5: a patched resolved version is fixed regardless of reachability.
        for rung in [
            None,
            Some(EvidenceKind::Declared),
            Some(EvidenceKind::SourceObserved),
            Some(EvidenceKind::FuzzReached),
        ] {
            assert_eq!(vex_status_for(rung, true, true), VexStatus::Fixed);
            assert_eq!(vex_status_for(rung, false, true), VexStatus::Fixed);
        }
    }

    // ----- Assessment: justification + non-empty impact statement -----

    fn ctx<'a>(
        top: Option<EvidenceKind>,
        campaign: bool,
        fixed: bool,
        harnesses: &'a [String],
    ) -> AssessmentContext<'a> {
        AssessmentContext {
            top_rung: top,
            campaign_ran: campaign,
            fixed_applies: fixed,
            fixed_version: if fixed { Some("1.2.4") } else { None },
            resolved_version: Some("1.2.5"),
            product_id: "pkg:generic/zlib@1.2.5",
            evidence_summary: "src/zip.c:7 #include <zlib.h>",
            harnesses,
        }
    }

    #[test]
    fn every_assessment_has_a_non_empty_impact_statement() {
        for (top, campaign, fixed) in [
            (Some(EvidenceKind::Declared), false, false),
            (Some(EvidenceKind::SourceObserved), true, false),
            (Some(EvidenceKind::SourceObserved), false, false),
            (Some(EvidenceKind::FuzzReached), true, false),
            (Some(EvidenceKind::Resolved), false, true),
            (None, false, false),
        ] {
            let assessment = assess(&ctx(top, campaign, fixed, &[]));
            assert!(
                !assessment.impact_statement.trim().is_empty(),
                "empty impact statement for {top:?}/{campaign}/{fixed}"
            );
            // The purl is always cited so the claim is auditable.
            assert!(
                assessment
                    .impact_statement
                    .contains("pkg:generic/zlib@1.2.5"),
                "impact statement must cite the product: {}",
                assessment.impact_statement
            );
        }
    }

    #[test]
    fn not_affected_carries_justification_others_do_not() {
        let na = assess(&ctx(Some(EvidenceKind::SourceObserved), true, false, &[]));
        assert_eq!(na.status, VexStatus::NotAffected);
        assert_eq!(na.justification, Some(JUSTIFICATION_NOT_IN_EXECUTE_PATH));

        let affected = assess(&ctx(Some(EvidenceKind::FuzzReached), true, false, &[]));
        assert_eq!(affected.justification, None);

        let triage = assess(&ctx(Some(EvidenceKind::SourceObserved), false, false, &[]));
        assert_eq!(triage.status, VexStatus::UnderInvestigation);
        assert_eq!(triage.justification, None);
    }

    #[test]
    fn dynamic_not_affected_cites_the_campaign() {
        let harnesses = vec!["zip_open".to_owned()];
        let na = assess(&ctx(
            Some(EvidenceKind::SourceObserved),
            true,
            false,
            &harnesses,
        ));
        assert_eq!(na.status, VexStatus::NotAffected);
        assert!(
            na.impact_statement.contains("fuzz campaign ran"),
            "dynamic not_affected must cite the campaign: {}",
            na.impact_statement
        );
        assert!(na.impact_statement.contains("zip_open"));
    }

    #[test]
    fn no_campaign_under_investigation_says_no_campaign_ran() {
        let triage = assess(&ctx(Some(EvidenceKind::SourceObserved), false, false, &[]));
        assert!(triage.impact_statement.contains("no fuzz campaign ran"));
        assert!(triage.impact_statement.contains("insufficient evidence"));
    }

    // ----- Rendering shapes -----

    #[test]
    fn openvex_statement_shape_with_justification() {
        let assessment = assess(&ctx(Some(EvidenceKind::SourceObserved), true, false, &[]));
        let statement = openvex_statement("CVE-2026-0001", "pkg:generic/zlib@1.2.5", &assessment);
        assert_eq!(statement["vulnerability"]["name"], "CVE-2026-0001");
        assert_eq!(statement["products"][0]["@id"], "pkg:generic/zlib@1.2.5");
        assert_eq!(statement["status"], "not_affected");
        assert_eq!(
            statement["justification"],
            JUSTIFICATION_NOT_IN_EXECUTE_PATH
        );
        assert!(!statement["impact_statement"].as_str().unwrap().is_empty());
    }

    #[test]
    fn openvex_statement_omits_justification_when_absent() {
        let assessment = assess(&ctx(Some(EvidenceKind::FuzzReached), true, false, &[]));
        let statement = openvex_statement("CVE-2026-0002", "pkg:x", &assessment);
        assert_eq!(statement["status"], "affected");
        assert!(statement.get("justification").is_none());
    }

    #[test]
    fn render_openvex_document_shape() {
        let stmt = openvex_statement(
            "CVE-2026-0003",
            "pkg:x",
            &assess(&ctx(Some(EvidenceKind::Declared), false, false, &[])),
        );
        let doc = render_openvex("govfuzz:vex:test", "1970-01-01T00:00:00Z", vec![stmt]);
        assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(doc["@id"], "govfuzz:vex:test");
        assert_eq!(doc["author"], "govfuzz");
        assert_eq!(doc["timestamp"], "1970-01-01T00:00:00Z");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn cyclonedx_analysis_state_and_justification_mapping() {
        let na = cyclonedx_analysis(&assess(&ctx(
            Some(EvidenceKind::SourceObserved),
            true,
            false,
            &[],
        )));
        assert_eq!(na["state"], "not_affected");
        assert_eq!(na["justification"], CYCLONEDX_JUSTIFICATION_NOT_REACHABLE);
        assert!(!na["detail"].as_str().unwrap().is_empty());

        let affected = cyclonedx_analysis(&assess(&ctx(
            Some(EvidenceKind::FuzzReached),
            true,
            false,
            &[],
        )));
        assert_eq!(affected["state"], "exploitable");
        assert!(affected.get("justification").is_none());

        let fixed = cyclonedx_analysis(&assess(&ctx(
            Some(EvidenceKind::Resolved),
            false,
            true,
            &[],
        )));
        assert_eq!(fixed["state"], "resolved");
        assert!(fixed.get("justification").is_none());

        let triage = cyclonedx_analysis(&assess(&ctx(
            Some(EvidenceKind::SourceObserved),
            false,
            false,
            &[],
        )));
        assert_eq!(triage["state"], "in_triage");
        assert!(triage.get("justification").is_none());
    }

    // ----- fixed-version comparison -----

    #[test]
    fn resolved_at_or_above_fixed_is_conservative() {
        assert!(resolved_at_or_above_fixed("1.2.5", "1.2.4"));
        assert!(resolved_at_or_above_fixed("1.2.4", "1.2.4"));
        assert!(resolved_at_or_above_fixed("2.0.0", "1.9.9"));
        assert!(!resolved_at_or_above_fixed("1.2.3", "1.2.4"));
        // Non-numeric / non-comparable → never claim fixed.
        assert!(!resolved_at_or_above_fixed("abc", "1.2.4"));
        assert!(!resolved_at_or_above_fixed("1.2.4", "latest"));
        assert!(!resolved_at_or_above_fixed("", ""));
    }

    #[test]
    fn numeric_version_handles_prefixes_and_prerelease() {
        assert_eq!(numeric_version("v1.2.3"), Some(vec![1, 2, 3]));
        assert_eq!(numeric_version("3.0.13-rc1"), Some(vec![3, 0, 13]));
        assert_eq!(numeric_version("1"), Some(vec![1]));
        assert_eq!(numeric_version("abc"), None);
        assert_eq!(numeric_version(""), None);
    }

    #[test]
    fn does_not_panic_on_malformed_versions() {
        // Exercise the untrusted-input guardrail: garbage never panics.
        for raw in ["", "....", "v", "1.2.999999999999999999999999", "🦀.1.2"] {
            let _ = resolved_at_or_above_fixed(raw, "1.0.0");
            let _ = resolved_at_or_above_fixed("1.0.0", raw);
        }
    }
}
