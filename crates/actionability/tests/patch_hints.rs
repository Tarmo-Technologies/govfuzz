// SPDX-License-Identifier: Apache-2.0

use actionability::patch_hints_for_finding;
use serde_json::json;

#[test]
fn command_injection_gets_conservative_argv_guidance() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "GF-304" }));

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].rule_id, "GF-304");
    assert!(hints[0].guidance.contains("argv"));
    assert!(hints[0].diff.is_none());
}

#[test]
fn integer_overflow_gets_bounds_guidance() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "GF-205" }));

    assert_eq!(hints[0].rule_id, "GF-205");
    assert!(hints[0].guidance.contains("bounds"));
}

#[test]
fn unknown_rule_gets_no_patch_hint() {
    let hints = patch_hints_for_finding(&json!({ "rule_id": "GF-999" }));

    assert!(hints.is_empty());
}
