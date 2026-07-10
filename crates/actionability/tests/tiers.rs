// SPDX-License-Identifier: Apache-2.0
//
// Tier-driven actionability: an Ada exception finding's triage tier (set by the
// corpus finding emitter) governs how loud it reads. A genuine uncaught fault
// is high impact; a predefined runtime check the target caught is a low-impact
// "review for masked vuln"; the target rejecting input via its own declared
// exception is the quietest.

use actionability::{value_for_finding, RunMode};
use serde_json::json;

fn actionability(tier: &str, classification: &str, rule_id: &str, exc: &str) -> serde_json::Value {
    let raw = json!({
        "tier": tier,
        "classification": classification,
        "rule_id": rule_id,
        "exception": { "name": exc },
    });
    value_for_finding(RunMode::Reporting, &raw, None)
}

#[test]
fn real_fault_tier_is_high_impact() {
    let v = actionability("real_fault", "unhandled", "GF-101", "CONSTRAINT_ERROR");
    assert_eq!(v["impact"], "high");
}

#[test]
fn swallowed_check_tier_is_low_impact_and_low_confidence() {
    // A swallowed predefined runtime check must NOT read as a confirmed high
    // vuln (the old GF-102 = High behaviour), but stays visible for review.
    let v = actionability(
        "swallowed_check",
        "swallowed_predefined",
        "GF-102",
        "CONSTRAINT_ERROR",
    );
    assert_eq!(v["impact"], "low");
    assert_eq!(v["confidence"], "low");
}

#[test]
fn intended_rejection_tier_is_info_impact() {
    // The library rejecting malformed input via its own declared exception is
    // not a defect — informational only, distinct from a low-priority real bug.
    let v = actionability(
        "intended_rejection",
        "swallowed_user",
        "GF-105",
        "UNZIP.CRC_ERROR",
    );
    assert_eq!(v["impact"], "info");
    assert_eq!(v["confidence"], "low");
}

#[test]
fn swallowed_check_next_steps_flag_masked_vuln_review() {
    let v = actionability(
        "swallowed_check",
        "swallowed_predefined",
        "GF-102",
        "CONSTRAINT_ERROR",
    );
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        steps.iter().any(|s| s.as_str().is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("masked") || s.contains("checks suppressed") || s.contains("review")
        })),
        "swallowed_check should advise reviewing for a masked vuln, got {steps:?}"
    );
}

#[test]
fn intended_rejection_next_steps_mark_not_a_finding() {
    let v = actionability(
        "intended_rejection",
        "swallowed_user",
        "GF-105",
        "UNZIP.CRC_ERROR",
    );
    let steps = v["next_steps"].as_array().expect("next_steps array");
    assert!(
        steps.iter().any(|s| s.as_str().is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("intended") || s.contains("not a finding") || s.contains("rejected")
        })),
        "intended_rejection should be marked as deliberate rejection, got {steps:?}"
    );
}
