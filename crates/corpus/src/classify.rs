// SPDX-License-Identifier: Apache-2.0

use event_log::{HandlerEvent, Testcase, TopLevelEvent};
use std::borrow::Cow;

pub const UNHANDLED_HANDLER_INDEX: usize = usize::MAX;

/// Resolve the [`HandlerEvent`] that a `(handler_index, classification)` pair
/// from [`classify`] refers to. Real in-target handlers come straight from
/// `testcase.handlers`; [`UNHANDLED_HANDLER_INDEX`] resolves to a handler
/// synthesized from the top-level (escaped) exception so that a genuine
/// uncaught fault is signatured, deduped, and reported like any other event
/// rather than being silently dropped.
pub fn resolve_handler(testcase: &Testcase, handler_index: usize) -> Option<Cow<'_, HandlerEvent>> {
    if handler_index == UNHANDLED_HANDLER_INDEX {
        testcase
            .top_level
            .as_ref()
            .map(|top| Cow::Owned(synthetic_top_level_handler(testcase, top)))
    } else {
        testcase.handlers.get(handler_index).map(Cow::Borrowed)
    }
}

/// Build a [`HandlerEvent`] standing in for an exception that escaped the
/// target unhandled to the harness top level, so it shares the signature /
/// cluster / finding machinery with caught exceptions.
fn synthetic_top_level_handler(testcase: &Testcase, top: &TopLevelEvent) -> HandlerEvent {
    HandlerEvent {
        sequence_index: usize::MAX,
        exception_name: top.exception_name.clone(),
        exception_message: top.exception_message.clone(),
        handler_file: "<unhandled>".to_owned(),
        handler_line: 0,
        last_breadcrumb: testcase.crumbs.last().copied().unwrap_or(0),
        target_id: testcase.target_id,
        testcase_id: testcase.testcase_id,
    }
}

/// Whether `name` is the Ada assertion/contract exception. A failed Ada 2012
/// precondition, postcondition, type invariant, or `pragma Assert` under -gnata
/// raises `Ada.Assertions.Assertion_Error` (GNAT names the underlying exception
/// `System.Assertions.Assert_Failure`). Unlike a routine raising its OWN declared
/// exception — deliberate input rejection — a violated contract is a genuine defect
/// (the target's specification did not hold), so an escaped one is a real fault.
pub fn is_assertion_exception(name: &str) -> bool {
    let simple = name.rsplit('.').next().unwrap_or(name);
    simple.eq_ignore_ascii_case("ASSERTION_ERROR") || simple.eq_ignore_ascii_case("ASSERT_FAILURE")
}

/// Whether `name` is an Ada predefined (language-defined) exception — i.e. one
/// raised by a runtime check rather than a user/library `raise`. Matches the
/// trailing segment so a qualified form (`Standard.Constraint_Error`) is
/// recognised too.
pub fn is_predefined_exception(name: &str) -> bool {
    const PREDEFINED: [&str; 5] = [
        "CONSTRAINT_ERROR",
        "PROGRAM_ERROR",
        "STORAGE_ERROR",
        "TASKING_ERROR",
        "NUMERIC_ERROR",
    ];
    let simple = name.rsplit('.').next().unwrap_or(name);
    PREDEFINED
        .iter()
        .any(|predefined| predefined.eq_ignore_ascii_case(simple))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Unhandled,
    SwallowedPredefined,
    SwallowedUser,
    ExplicitRaise,
}

/// Triage tier for an Ada exception finding. Separates a genuine uncaught
/// fault (a real crash) from an exception the target caught itself, and — among
/// the caught ones — a swallowed predefined runtime check (a *potential* masked
/// memory-safety / DoS bug) from the target deliberately rejecting bad input
/// via its own declared exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTier {
    /// Exception escaped the target unhandled to the harness top level.
    RealFault,
    /// A predefined runtime check (Constraint/Storage/Program/Tasking/Numeric)
    /// was raised and caught inside the target. Review for a masked vuln.
    SwallowedCheck,
    /// The target raised/caught its own declared exception — deliberate
    /// rejection of malformed input, not a finding.
    IntendedRejection,
}

impl FindingTier {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingTier::RealFault => "real_fault",
            FindingTier::SwallowedCheck => "swallowed_check",
            FindingTier::IntendedRejection => "intended_rejection",
        }
    }
}

/// Map a `(classification, exception)` pair to its triage [`FindingTier`].
///
/// An escaped (unhandled) exception is a real fault only when it is a predefined
/// runtime check (`Constraint_Error`, `Storage_Error`, ...). A target raising
/// its own declared exception (e.g. `bad_data_descriptor`) is that routine's
/// documented contract — even when it escapes a direct harness that does not
/// catch it — so it is intended rejection, not a crash.
pub fn finding_tier(classification: Classification, exception_name: &str) -> FindingTier {
    match classification {
        Classification::Unhandled => {
            // A predefined runtime check OR a violated Ada 2012 contract (assertion)
            // that escapes the target is a genuine fault. A routine raising its own
            // declared exception, by contrast, is documented input rejection.
            if is_predefined_exception(exception_name) || is_assertion_exception(exception_name) {
                FindingTier::RealFault
            } else {
                FindingTier::IntendedRejection
            }
        }
        Classification::SwallowedPredefined => FindingTier::SwallowedCheck,
        Classification::SwallowedUser | Classification::ExplicitRaise => {
            FindingTier::IntendedRejection
        }
    }
}

pub fn classify(testcase: &Testcase) -> Vec<(usize, Classification)> {
    let mut classifications = testcase
        .handlers
        .iter()
        .enumerate()
        .map(|(handler_index, handler)| (handler_index, classify_handler(testcase, handler)))
        .collect::<Vec<_>>();

    if let Some(top_level) = &testcase.top_level {
        let handled_before_top_level = testcase.handlers.iter().any(|handler| {
            handler
                .exception_name
                .eq_ignore_ascii_case(&top_level.exception_name)
        });
        if !handled_before_top_level {
            classifications.push((UNHANDLED_HANDLER_INDEX, Classification::Unhandled));
        }
    }

    classifications
}

fn classify_handler(testcase: &Testcase, handler: &HandlerEvent) -> Classification {
    if has_preceding_matching_raise(testcase, handler) {
        return Classification::ExplicitRaise;
    }

    if is_predefined_exception(&handler.exception_name) {
        Classification::SwallowedPredefined
    } else {
        Classification::SwallowedUser
    }
}

fn has_preceding_matching_raise(testcase: &Testcase, handler: &HandlerEvent) -> bool {
    testcase.raises.iter().any(|raise| {
        raise.sequence_index < handler.sequence_index
            && raise
                .exception_name
                .eq_ignore_ascii_case(&handler.exception_name)
    })
}

#[cfg(test)]
mod tests {
    use super::{classify, finding_tier, Classification, FindingTier, UNHANDLED_HANDLER_INDEX};
    use event_log::{HandlerEvent, RaiseEvent, Testcase, TopLevelEvent};

    #[test]
    fn escaped_predefined_exception_is_real_fault_tier() {
        // A predefined runtime check that escaped the target unhandled is a
        // genuine crash/robustness fault.
        assert_eq!(
            finding_tier(Classification::Unhandled, "CONSTRAINT_ERROR"),
            FindingTier::RealFault
        );
    }

    #[test]
    fn escaped_ada_contract_assertion_is_real_fault_tier() {
        // A violated Pre/Post/Type_Invariant raises Assertion_Error under -gnata; when
        // it escapes the target it is a genuine defect (the spec did not hold), NOT
        // intended input rejection like a user-declared exception.
        assert_eq!(
            finding_tier(Classification::Unhandled, "ADA.ASSERTIONS.ASSERTION_ERROR"),
            FindingTier::RealFault
        );
        assert_eq!(
            finding_tier(
                Classification::Unhandled,
                "System.Assertions.Assert_Failure"
            ),
            FindingTier::RealFault
        );
    }

    #[test]
    fn escaped_declared_exception_is_intended_rejection() {
        // A routine raising its own declared exception (e.g. bad_data_descriptor)
        // is its documented contract, even when it escapes a direct harness — so
        // it must not read as a high-impact crash.
        assert_eq!(
            finding_tier(Classification::Unhandled, "Zip.Headers.Bad_Data_Descriptor"),
            FindingTier::IntendedRejection
        );
        // A standard-library exception (End_Error on truncated input) is
        // likewise the routine reacting to malformed input, not a crash.
        assert_eq!(
            finding_tier(Classification::Unhandled, "Ada.IO_Exceptions.End_Error"),
            FindingTier::IntendedRejection
        );
    }

    #[test]
    fn swallowed_predefined_is_swallowed_check_tier() {
        // A predefined runtime check (Constraint/Storage/...) caught inside the
        // target: not a confirmed crash, but a *potential masked* memory-safety
        // / DoS issue worth reviewing — its own tier, distinct from the noise.
        assert_eq!(
            finding_tier(Classification::SwallowedPredefined, "CONSTRAINT_ERROR"),
            FindingTier::SwallowedCheck
        );
    }

    #[test]
    fn swallowed_user_and_explicit_raise_are_intended_rejection() {
        // The target raising/catching its own declared exception (CRC error,
        // Archive_corrupted, ...) is deliberate input rejection, not a finding.
        assert_eq!(
            finding_tier(Classification::SwallowedUser, "UNZIP.CRC_ERROR"),
            FindingTier::IntendedRejection
        );
        assert_eq!(
            finding_tier(Classification::ExplicitRaise, "ZIP.ARCHIVE_CORRUPTED"),
            FindingTier::IntendedRejection
        );
    }

    #[test]
    fn classify_unhandled_when_top_level_only() {
        let mut testcase = empty_testcase();
        testcase.top_level = Some(TopLevelEvent {
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "escaped".to_owned(),
        });

        assert_eq!(
            classify(&testcase),
            vec![(UNHANDLED_HANDLER_INDEX, Classification::Unhandled)]
        );
    }

    #[test]
    fn classify_explicit_raise_when_raise_precedes_handler_with_same_name() {
        let mut testcase = empty_testcase();
        testcase.raises.push(raise(1, "BadInput"));
        testcase.handlers.push(handler(2, "BadInput"));

        assert_eq!(
            classify(&testcase),
            vec![(0, Classification::ExplicitRaise)]
        );
    }

    #[test]
    fn classify_swallowed_predefined_when_handler_for_constraint_error_no_preceding_raise() {
        let mut testcase = empty_testcase();
        testcase.handlers.push(handler(1, "CONSTRAINT_ERROR"));

        assert_eq!(
            classify(&testcase),
            vec![(0, Classification::SwallowedPredefined)]
        );
    }

    #[test]
    fn classify_swallowed_user_when_handler_for_user_exception() {
        let mut testcase = empty_testcase();
        testcase.handlers.push(handler(1, "BadInput"));

        assert_eq!(
            classify(&testcase),
            vec![(0, Classification::SwallowedUser)]
        );
    }

    #[test]
    fn classify_returns_one_per_handler_event() {
        let mut testcase = empty_testcase();
        testcase.handlers.push(handler(1, "CONSTRAINT_ERROR"));
        testcase.handlers.push(handler(2, "BadInput"));

        assert_eq!(
            classify(&testcase),
            vec![
                (0, Classification::SwallowedPredefined),
                (1, Classification::SwallowedUser),
            ]
        );
    }

    #[test]
    fn classify_does_not_treat_raise_after_handler_as_explicit() {
        let mut testcase = empty_testcase();
        testcase.handlers.push(handler(1, "BadInput"));
        testcase.raises.push(raise(2, "BadInput"));

        assert_eq!(
            classify(&testcase),
            vec![(0, Classification::SwallowedUser)]
        );
    }

    fn empty_testcase() -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            crumbs: Vec::new(),
            handlers: Vec::new(),
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    fn handler(sequence_index: usize, exception_name: &str) -> HandlerEvent {
        HandlerEvent {
            sequence_index,
            exception_name: exception_name.to_owned(),
            exception_message: String::new(),
            handler_file: "pkg.adb".to_owned(),
            handler_line: 9,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        }
    }

    fn raise(sequence_index: usize, exception_name: &str) -> RaiseEvent {
        RaiseEvent {
            sequence_index,
            exception_name: exception_name.to_owned(),
            file: "pkg.adb".to_owned(),
            line: 8,
            breadcrumb: 1,
        }
    }
}
