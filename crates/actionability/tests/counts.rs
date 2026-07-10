// SPDX-License-Identifier: Apache-2.0

use actionability::{
    aggregate_counts, attacking_target_score, finding_sort_key, ActionabilityConfidence,
    ActionabilityRecord, Impact, Prosthetics, RunMode, Verdict,
};

fn record(
    verdict: Verdict,
    impact: Impact,
    confidence: ActionabilityConfidence,
) -> ActionabilityRecord {
    ActionabilityRecord {
        mode: RunMode::Reporting,
        verdict,
        impact,
        confidence,
        entry_path: None,
        fix_location: None,
        source: None,
        sink: None,
        explanation: None,
        cwe: Vec::new(),
        cwe_name: None,
        replay: None,
        prosthetics: Prosthetics::default(),
        patch_hints: Vec::new(),
        next_steps: Vec::new(),
    }
}

#[test]
fn counts_group_by_verdict_and_impact() {
    let records = [
        record(
            Verdict::RealReachable,
            Impact::Critical,
            ActionabilityConfidence::High,
        ),
        record(
            Verdict::LabOnly,
            Impact::High,
            ActionabilityConfidence::Medium,
        ),
        record(
            Verdict::RealReachable,
            Impact::High,
            ActionabilityConfidence::High,
        ),
    ];

    let counts = aggregate_counts(records.iter());

    assert_eq!(counts.by_actionability_verdict["real_reachable"], 2);
    assert_eq!(counts.by_actionability_verdict["lab_only"], 1);
    assert_eq!(counts.by_impact["critical"], 1);
    assert_eq!(counts.by_impact["high"], 2);
}

#[test]
fn sort_key_prefers_real_high_confidence_high_impact() {
    let lab = record(
        Verdict::LabOnly,
        Impact::Critical,
        ActionabilityConfidence::High,
    );
    let real = record(
        Verdict::RealReachable,
        Impact::High,
        ActionabilityConfidence::High,
    );

    assert!(finding_sort_key(&real) < finding_sort_key(&lab));
}

#[test]
fn attacking_target_score_prioritizes_real_input_and_dangerous_api_cues() {
    let base = attacking_target_score(10, "int helper(void) { return 0; }", "helper");
    let parse = attacking_target_score(10, "int parse_packet(void) { return 0; }", "parse_packet");
    let danger = attacking_target_score(
        10,
        "procedure Run is begin GNAT.OS_Lib.Spawn (Cmd, Args); end Run;",
        "run_user_command",
    );

    assert!(parse > base);
    assert!(danger > parse);
}
