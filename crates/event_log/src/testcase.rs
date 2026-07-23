// SPDX-License-Identifier: Apache-2.0

use crate::{Event, EventReadError, EventReader};
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Testcase {
    pub testcase_id: u64,
    pub target_id: u32,
    /// True only when decoding completed and the generated harness reached the
    /// checkpoint immediately before its selected project endpoint.
    #[serde(default)]
    pub target_entered: bool,
    pub crumbs: Vec<u32>,
    pub handlers: Vec<HandlerEvent>,
    pub raises: Vec<RaiseEvent>,
    pub top_level: Option<TopLevelEvent>,
    pub end: Option<EndEvent>,
    pub mocks: Vec<MockEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HandlerEvent {
    pub sequence_index: usize,
    pub exception_name: String,
    pub exception_message: String,
    pub handler_file: String,
    pub handler_line: u32,
    pub last_breadcrumb: u32,
    pub target_id: u32,
    pub testcase_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RaiseEvent {
    pub sequence_index: usize,
    pub exception_name: String,
    pub file: String,
    pub line: u32,
    pub breadcrumb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TopLevelEvent {
    pub exception_name: String,
    pub exception_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EndEvent {
    pub result_class: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MockEvent {
    pub symbol: String,
}

impl Testcase {
    fn new(testcase_id: u64) -> Self {
        Self {
            testcase_id,
            target_id: 0,
            target_entered: false,
            crumbs: Vec::new(),
            handlers: Vec::new(),
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }
}

/// Groups probe events into testcase windows.
///
/// M5 drops events before the first `Begin` and after a completed `End` because
/// those events cannot be attributed to a concrete input.
pub fn group_into_testcases<R: Read>(
    mut reader: EventReader<R>,
) -> Result<Vec<Testcase>, EventReadError> {
    let mut testcases = Vec::new();
    let mut current: Option<Testcase> = None;
    let mut sequence_index = 0_usize;

    while let Some(event) = reader.next_event()? {
        let current_index = sequence_index;
        sequence_index += 1;

        match event {
            Event::Begin { testcase_id } => {
                if let Some(open) = current.replace(Testcase::new(testcase_id)) {
                    testcases.push(open);
                }
            }
            Event::End { result_class } => {
                if let Some(mut testcase) = current.take() {
                    testcase.end = Some(EndEvent { result_class });
                    testcases.push(testcase);
                }
            }
            Event::Crumb { id } => {
                if let Some(testcase) = &mut current {
                    testcase.crumbs.push(id);
                }
            }
            Event::Target { id } => {
                if let Some(testcase) = &mut current {
                    testcase.target_id = id;
                }
            }
            Event::TargetEntry => {
                if let Some(testcase) = &mut current {
                    testcase.target_entered = true;
                }
            }
            Event::Handler {
                exception_name,
                exception_message,
                handler_file,
                handler_line,
                last_breadcrumb,
                target_id,
                testcase_id,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.handlers.push(HandlerEvent {
                        sequence_index: current_index,
                        exception_name,
                        exception_message,
                        handler_file,
                        handler_line,
                        last_breadcrumb,
                        target_id,
                        testcase_id,
                    });
                }
            }
            Event::Raise {
                exception_name,
                file,
                line,
                breadcrumb,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.raises.push(RaiseEvent {
                        sequence_index: current_index,
                        exception_name,
                        file,
                        line,
                        breadcrumb,
                    });
                }
            }
            Event::Mock { symbol } => {
                if let Some(testcase) = &mut current {
                    testcase.mocks.push(MockEvent { symbol });
                }
            }
            Event::TopLevel {
                exception_name,
                exception_message,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.top_level = Some(TopLevelEvent {
                        exception_name,
                        exception_message,
                    });
                }
            }
        }
    }

    if let Some(testcase) = current {
        testcases.push(testcase);
    }

    Ok(testcases)
}

#[cfg(test)]
mod tests {
    use super::group_into_testcases;
    use crate::{EventReader, EventTag};
    use std::io::Cursor;

    #[test]
    fn single_testcase_groups_all_events_between_begin_and_end() {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_target(&mut bytes, 0x42);
        push_crumb(&mut bytes, 1);
        push_raise(&mut bytes, "CONSTRAINT_ERROR", "pkg.adb", 8, 1);
        push_handler(
            &mut bytes,
            "CONSTRAINT_ERROR",
            "bad",
            "pkg.adb",
            9,
            1,
            0x42,
            7,
        );
        push_mock(&mut bytes, "External.Lookup", 1, 0x42, 7);
        push_top_level(&mut bytes, "PROGRAM_ERROR", "escaped", 1, 0x42, 7);
        push_end(&mut bytes, 0);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert_eq!(testcases.len(), 1);
        let testcase = &testcases[0];
        assert_eq!(testcase.testcase_id, 7);
        assert_eq!(testcase.target_id, 0x42);
        assert_eq!(testcase.crumbs, vec![1]);
        assert_eq!(testcase.raises[0].exception_name, "CONSTRAINT_ERROR");
        assert_eq!(testcase.handlers[0].handler_file, "pkg.adb");
        assert_eq!(testcase.mocks[0].symbol, "External.Lookup");
        assert_eq!(
            testcase.top_level.as_ref().unwrap().exception_name,
            "PROGRAM_ERROR"
        );
        assert_eq!(testcase.end.as_ref().unwrap().result_class, 0);
    }

    #[test]
    fn two_testcases_separate_event_streams() {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 1);
        push_target(&mut bytes, 0x41);
        push_end(&mut bytes, 0);
        push_begin(&mut bytes, 2);
        push_target(&mut bytes, 0x42);
        push_end(&mut bytes, 1);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert_eq!(testcases.len(), 2);
        assert_eq!(testcases[0].testcase_id, 1);
        assert_eq!(testcases[0].target_id, 0x41);
        assert_eq!(testcases[1].testcase_id, 2);
        assert_eq!(testcases[1].target_id, 0x42);
    }

    #[test]
    fn events_before_begin_are_dropped() {
        let mut bytes = Vec::new();
        push_target(&mut bytes, 0x99);
        push_crumb(&mut bytes, 99);
        push_begin(&mut bytes, 1);
        push_target(&mut bytes, 0x42);
        push_end(&mut bytes, 0);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert_eq!(testcases.len(), 1);
        assert_eq!(testcases[0].target_id, 0x42);
        assert!(testcases[0].crumbs.is_empty());
    }

    #[test]
    fn testcase_without_end_returns_with_end_none() {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 1);
        push_target(&mut bytes, 0x42);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert_eq!(testcases.len(), 1);
        assert_eq!(testcases[0].testcase_id, 1);
        assert_eq!(testcases[0].target_id, 0x42);
        assert_eq!(testcases[0].end, None);
    }

    #[test]
    fn crumbs_preserve_order() {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 1);
        push_crumb(&mut bytes, 3);
        push_crumb(&mut bytes, 1);
        push_crumb(&mut bytes, 2);
        push_end(&mut bytes, 0);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert_eq!(testcases[0].crumbs, vec![3, 1, 2]);
    }

    #[test]
    fn handler_and_raise_sequence_indices_follow_event_order() {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 1);
        push_raise(&mut bytes, "BadInput", "pkg.adb", 7, 11);
        push_handler(&mut bytes, "BadInput", "bad", "pkg.adb", 9, 12, 0x42, 1);
        push_end(&mut bytes, 0);

        let testcases = group_into_testcases(EventReader::new(Cursor::new(bytes))).unwrap();

        assert!(testcases[0].raises[0].sequence_index < testcases[0].handlers[0].sequence_index);
    }

    fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {
        bytes.push(EventTag::Begin as u8);
        bytes.extend_from_slice(&testcase_id.to_le_bytes());
    }

    fn push_end(bytes: &mut Vec<u8>, result_class: u8) {
        bytes.push(EventTag::End as u8);
        bytes.push(result_class);
    }

    fn push_crumb(bytes: &mut Vec<u8>, id: u32) {
        bytes.push(EventTag::Crumb as u8);
        bytes.extend_from_slice(&id.to_le_bytes());
    }

    fn push_target(bytes: &mut Vec<u8>, id: u32) {
        bytes.push(EventTag::Target as u8);
        bytes.extend_from_slice(&id.to_le_bytes());
    }

    fn push_string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn push_handler(
        bytes: &mut Vec<u8>,
        exception_name: &str,
        exception_message: &str,
        handler_file: &str,
        handler_line: u32,
        last_breadcrumb: u32,
        target_id: u32,
        testcase_id: u64,
    ) {
        bytes.push(EventTag::Handler as u8);
        push_string(bytes, exception_name);
        push_string(bytes, exception_message);
        push_string(bytes, handler_file);
        bytes.extend_from_slice(&handler_line.to_le_bytes());
        bytes.extend_from_slice(&last_breadcrumb.to_le_bytes());
        bytes.extend_from_slice(&target_id.to_le_bytes());
        bytes.extend_from_slice(&testcase_id.to_le_bytes());
    }

    fn push_raise(
        bytes: &mut Vec<u8>,
        exception_name: &str,
        file: &str,
        line: u32,
        breadcrumb: u32,
    ) {
        bytes.push(EventTag::Raise as u8);
        push_string(bytes, exception_name);
        push_string(bytes, file);
        bytes.extend_from_slice(&line.to_le_bytes());
        bytes.extend_from_slice(&breadcrumb.to_le_bytes());
    }

    fn push_mock(
        bytes: &mut Vec<u8>,
        symbol: &str,
        last_breadcrumb: u32,
        target_id: u32,
        testcase_id: u64,
    ) {
        bytes.push(EventTag::Mock as u8);
        push_string(bytes, symbol);
        bytes.extend_from_slice(&last_breadcrumb.to_le_bytes());
        bytes.extend_from_slice(&target_id.to_le_bytes());
        bytes.extend_from_slice(&testcase_id.to_le_bytes());
    }

    fn push_top_level(
        bytes: &mut Vec<u8>,
        exception_name: &str,
        exception_message: &str,
        last_breadcrumb: u32,
        target_id: u32,
        testcase_id: u64,
    ) {
        bytes.push(EventTag::TopLevel as u8);
        push_string(bytes, exception_name);
        push_string(bytes, exception_message);
        bytes.extend_from_slice(&last_breadcrumb.to_le_bytes());
        bytes.extend_from_slice(&target_id.to_le_bytes());
        bytes.extend_from_slice(&testcase_id.to_le_bytes());
    }
}
