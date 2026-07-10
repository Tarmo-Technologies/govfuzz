// SPDX-License-Identifier: Apache-2.0

//! Coverage feedback for the built-in engine.
//!
//! Granularity (matching AFL/libFuzzer's edge + hit-count model):
//! - **Edge coverage** — consecutive `(prev -> cur)` breadcrumb transitions,
//!   not just the set of blocks. This distinguishes execution *orderings* that
//!   reach the same blocks in a different sequence.
//! - **Hit-count buckets** — each block's per-input execution count is mapped
//!   to an AFL-style logarithmic bucket (`count_to_bucket`) and folded into the
//!   block's coverage key. A loop run N+1 times vs N registers as new coverage
//!   across a bucket boundary (the per-byte state-machine case), while noise
//!   within a bucket does not. Both feed `CoverageFeedback::new_bitmap_bits`,
//!   so they drive corpus growth like every other channel.

use std::collections::HashSet;

use crate::scheduler::ScheduleFeedback;
use event_log::Testcase;

/// Map a per-input edge/block hit count to an AFL-style logarithmic bucket so
/// "looped N times" and "looped N+1 times" are distinguishable across a bucket
/// boundary but identical within one (the st24 per-byte state-machine case).
/// Buckets: 1->0, 2->1, 3->2, 4..=7->3, 8..=15->4, 16..=31->5, 32..=127->6,
/// 128..->7.
pub fn count_to_bucket(n: u32) -> u8 {
    match n {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoverageSignature([u8; 32]);

impl CoverageSignature {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CoverageInput<'a> {
    pub testcase: &'a Testcase,
    pub exception_signatures: &'a [CoverageSignature],
}

impl<'a> CoverageInput<'a> {
    pub fn new(testcase: &'a Testcase, exception_signatures: &'a [CoverageSignature]) -> Self {
        Self {
            testcase,
            exception_signatures,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageFeedback {
    pub new_exception_signatures: u32,
    pub new_breadcrumb_bits: u32,
    pub new_edge_bits: u32,
    pub new_handler_bits: u32,
    pub new_raise_bits: u32,
    pub new_top_level_bits: u32,
    pub new_return_class_bits: u32,
    pub new_mock_call_bits: u32,
}

impl CoverageFeedback {
    pub fn is_empty(self) -> bool {
        self.new_exception_signatures == 0 && self.new_bitmap_bits() == 0
    }

    pub fn new_bitmap_bits(self) -> u32 {
        self.new_breadcrumb_bits
            .saturating_add(self.new_edge_bits)
            .saturating_add(self.new_handler_bits)
            .saturating_add(self.new_raise_bits)
            .saturating_add(self.new_top_level_bits)
            .saturating_add(self.new_return_class_bits)
            .saturating_add(self.new_mock_call_bits)
    }

    pub fn to_schedule_feedback(self) -> ScheduleFeedback {
        ScheduleFeedback {
            new_exception_signatures: self.new_exception_signatures,
            new_breadcrumb_bits: self.new_bitmap_bits(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageSnapshot {
    pub exception_signatures: usize,
    pub breadcrumb_bits: usize,
    pub edge_bits: usize,
    pub handler_bits: usize,
    pub raise_bits: usize,
    pub top_level_bits: usize,
    pub return_class_bits: usize,
    pub mock_call_bits: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CoverageProxy {
    exception_signatures: HashSet<CoverageSignature>,
    breadcrumb_bits: HashSet<u64>,
    edge_bits: HashSet<u64>,
    handler_bits: HashSet<u64>,
    raise_bits: HashSet<u64>,
    top_level_bits: HashSet<u64>,
    return_class_bits: HashSet<u64>,
    mock_call_bits: HashSet<u64>,
}

impl CoverageProxy {
    pub fn record(&mut self, input: CoverageInput<'_>) -> CoverageFeedback {
        let mut feedback = CoverageFeedback::default();

        for signature in input.exception_signatures {
            if self.exception_signatures.insert(*signature) {
                feedback.new_exception_signatures =
                    feedback.new_exception_signatures.saturating_add(1);
            }
        }

        // Per-input block hit counts -> AFL-bucketed breadcrumb keys, so a
        // block executed more times (a loop run N+1 vs N) registers as new
        // coverage across a bucket boundary (#381).
        let mut hits: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        for crumb in &input.testcase.crumbs {
            *hits.entry(*crumb).or_insert(0) += 1;
        }
        for (crumb, count) in &hits {
            let key = breadcrumb_bucket_bit(*crumb, count_to_bucket(*count));
            if self.breadcrumb_bits.insert(key) {
                feedback.new_breadcrumb_bits = feedback.new_breadcrumb_bits.saturating_add(1);
            }
        }
        // Edge coverage: consecutive (prev -> cur) block transitions, the
        // signal that distinguishes orderings the block set alone cannot.
        for window in input.testcase.crumbs.windows(2) {
            let key = edge_bit(window[0], window[1]);
            if self.edge_bits.insert(key) {
                feedback.new_edge_bits = feedback.new_edge_bits.saturating_add(1);
            }
        }

        for handler in &input.testcase.handlers {
            if self.handler_bits.insert(handler_bit(handler)) {
                feedback.new_handler_bits = feedback.new_handler_bits.saturating_add(1);
            }
        }

        for raise in &input.testcase.raises {
            if self.raise_bits.insert(raise_bit(raise)) {
                feedback.new_raise_bits = feedback.new_raise_bits.saturating_add(1);
            }
        }

        if let Some(top_level) = &input.testcase.top_level {
            if self.top_level_bits.insert(top_level_bit(top_level)) {
                feedback.new_top_level_bits = feedback.new_top_level_bits.saturating_add(1);
            }
        }

        if let Some(end) = &input.testcase.end {
            if self.return_class_bits.insert(u64::from(end.result_class)) {
                feedback.new_return_class_bits = feedback.new_return_class_bits.saturating_add(1);
            }
        }

        for mock in &input.testcase.mocks {
            if self
                .mock_call_bits
                .insert(stable_hash_bytes(mock.symbol.as_bytes()))
            {
                feedback.new_mock_call_bits = feedback.new_mock_call_bits.saturating_add(1);
            }
        }

        feedback
    }

    pub fn snapshot(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            exception_signatures: self.exception_signatures.len(),
            breadcrumb_bits: self.breadcrumb_bits.len(),
            edge_bits: self.edge_bits.len(),
            handler_bits: self.handler_bits.len(),
            raise_bits: self.raise_bits.len(),
            top_level_bits: self.top_level_bits.len(),
            return_class_bits: self.return_class_bits.len(),
            mock_call_bits: self.mock_call_bits.len(),
        }
    }
}

/// Stable global key for a (block, hit-count-bucket) pair (#381). Tagged so it
/// can't collide with a raw block id or an edge key.
fn breadcrumb_bucket_bit(crumb: u32, bucket: u8) -> u64 {
    let mut hash = StableHash::new();
    hash.write_bytes(b"block");
    hash.write_u32(crumb);
    hash.write_bytes(&[bucket]);
    hash.finish()
}

/// Stable global key for a (prev -> cur) block transition (#381).
fn edge_bit(prev: u32, cur: u32) -> u64 {
    let mut hash = StableHash::new();
    hash.write_bytes(b"edge");
    hash.write_u32(prev);
    hash.write_u32(cur);
    hash.finish()
}

fn handler_bit(handler: &event_log::HandlerEvent) -> u64 {
    let mut hash = StableHash::new();
    hash.write_u32(handler.target_id);
    hash.write_str(&handler.handler_file);
    hash.write_u32(handler.handler_line);
    hash.write_u32(handler.last_breadcrumb);
    hash.write_str(&handler.exception_name.to_ascii_lowercase());
    hash.finish()
}

fn raise_bit(raise: &event_log::RaiseEvent) -> u64 {
    let mut hash = StableHash::new();
    hash.write_str(&raise.exception_name.to_ascii_lowercase());
    hash.write_str(&raise.file);
    hash.write_u32(raise.line);
    hash.write_u32(raise.breadcrumb);
    hash.finish()
}

fn top_level_bit(top_level: &event_log::TopLevelEvent) -> u64 {
    let mut hash = StableHash::new();
    hash.write_str(&top_level.exception_name.to_ascii_lowercase());
    hash.write_str(&top_level.exception_message);
    hash.finish()
}

fn stable_hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = StableHash::new();
    hash.write_bytes(bytes);
    hash.finish()
}

struct StableHash {
    value: u64,
}

impl StableHash {
    fn new() -> Self {
        Self {
            value: 0xcbf2_9ce4_8422_2325,
        }
    }

    fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_str(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
        self.write_bytes(&[0]);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= u64::from(*byte);
            self.value = self.value.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn finish(self) -> u64 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_log::{EndEvent, HandlerEvent, MockEvent, RaiseEvent, Testcase, TopLevelEvent};

    #[test]
    fn coverage_proxy_counts_new_exception_signatures_once() {
        let mut proxy = CoverageProxy::default();
        let testcase = empty_testcase();
        let signature = CoverageSignature::from_bytes([1; 32]);

        let first = proxy.record(CoverageInput::new(&testcase, &[signature]));
        let second = proxy.record(CoverageInput::new(&testcase, &[signature]));

        assert_eq!(first.new_exception_signatures, 1);
        assert_eq!(second.new_exception_signatures, 0);
    }

    #[test]
    fn count_to_bucket_maps_afl_log_buckets() {
        assert_eq!(count_to_bucket(1), 0);
        assert_eq!(count_to_bucket(2), 1);
        assert_eq!(count_to_bucket(3), 2);
        assert_eq!(count_to_bucket(4), 3);
        assert_eq!(count_to_bucket(7), 3);
        assert_eq!(count_to_bucket(8), 4);
        assert_eq!(count_to_bucket(15), 4);
        assert_eq!(count_to_bucket(16), 5);
        assert_eq!(count_to_bucket(31), 5);
        assert_eq!(count_to_bucket(32), 6);
        assert_eq!(count_to_bucket(127), 6);
        assert_eq!(count_to_bucket(128), 7);
        assert_eq!(count_to_bucket(1_000_000), 7);
        // Adjacent counts straddling a boundary differ; within a bucket match.
        assert_ne!(count_to_bucket(7), count_to_bucket(8));
        assert_eq!(count_to_bucket(5), count_to_bucket(6));
    }

    #[test]
    fn coverage_proxy_records_edge_transitions_and_hit_count_buckets() {
        let mut proxy = CoverageProxy::default();
        let mut a = empty_testcase();
        a.crumbs = vec![1, 2, 1, 2]; // edges 1->2, 2->1, 1->2 ; crumb hit counts 1:2, 2:2
        let first = proxy.record(CoverageInput::new(&a, &[]));
        // Two distinct edges (1->2, 2->1).
        assert_eq!(first.new_edge_bits, 2, "{first:?}");
        let repeat = proxy.record(CoverageInput::new(&a, &[]));
        assert_eq!(repeat.new_edge_bits, 0);

        // Same blocks, but looped more times -> different hit-count bucket ->
        // counts as new breadcrumb coverage (this is the whole point of #381).
        let mut b = empty_testcase();
        b.crumbs = vec![1; 8]; // crumb 1 hit 8 times -> bucket 4 (vs 2 -> bucket 1)
        let looped = proxy.record(CoverageInput::new(&b, &[]));
        assert!(
            looped.new_breadcrumb_bits >= 1,
            "a higher loop count must register as new coverage: {looped:?}"
        );
    }

    #[test]
    fn coverage_proxy_counts_new_breadcrumb_bits_once() {
        let mut proxy = CoverageProxy::default();
        let mut testcase = empty_testcase();
        testcase.crumbs = vec![7, 8, 7];

        let first = proxy.record(CoverageInput::new(&testcase, &[]));
        let second = proxy.record(CoverageInput::new(&testcase, &[]));

        assert_eq!(first.new_breadcrumb_bits, 2);
        assert_eq!(second.new_breadcrumb_bits, 0);
    }

    #[test]
    fn coverage_proxy_counts_handler_return_and_mock_bits() {
        let mut proxy = CoverageProxy::default();
        let mut testcase = empty_testcase();
        testcase
            .handlers
            .push(handler("CONSTRAINT_ERROR", 0x42, 99));
        testcase.end = Some(EndEvent { result_class: 2 });
        testcase.mocks.push(MockEvent {
            symbol: "External.Lookup".to_owned(),
        });

        let first = proxy.record(CoverageInput::new(&testcase, &[]));
        let second = proxy.record(CoverageInput::new(&testcase, &[]));

        assert_eq!(first.new_handler_bits, 1);
        assert_eq!(first.new_return_class_bits, 1);
        assert_eq!(first.new_mock_call_bits, 1);
        assert_eq!(second.new_handler_bits, 0);
        assert_eq!(second.new_return_class_bits, 0);
        assert_eq!(second.new_mock_call_bits, 0);
    }

    #[test]
    fn coverage_proxy_counts_raise_and_top_level_bits() {
        let mut proxy = CoverageProxy::default();
        let mut testcase = empty_testcase();
        testcase.raises.push(RaiseEvent {
            sequence_index: 1,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            file: "pkg.adb".to_owned(),
            line: 17,
            breadcrumb: 7,
        });
        testcase.top_level = Some(TopLevelEvent {
            exception_name: "PROGRAM_ERROR".to_owned(),
            exception_message: "escaped".to_owned(),
        });

        let first = proxy.record(CoverageInput::new(&testcase, &[]));
        let second = proxy.record(CoverageInput::new(&testcase, &[]));

        assert_eq!(first.new_raise_bits, 1);
        assert_eq!(first.new_top_level_bits, 1);
        assert_eq!(second.new_raise_bits, 0);
        assert_eq!(second.new_top_level_bits, 0);
    }

    #[test]
    fn coverage_feedback_maps_all_bitmap_channels_to_scheduler_feedback() {
        let feedback = CoverageFeedback {
            new_exception_signatures: 2,
            new_breadcrumb_bits: 3,
            new_edge_bits: 19,
            new_handler_bits: 5,
            new_raise_bits: 13,
            new_top_level_bits: 17,
            new_return_class_bits: 7,
            new_mock_call_bits: 11,
        };

        let schedule = feedback.to_schedule_feedback();

        assert_eq!(schedule.new_exception_signatures, 2);
        // 3 + 19 + 5 + 13 + 17 + 7 + 11
        assert_eq!(schedule.new_breadcrumb_bits, 75);
    }

    #[test]
    fn coverage_proxy_handles_empty_testcase_without_novelty() {
        let mut proxy = CoverageProxy::default();

        assert_eq!(
            proxy.record(CoverageInput::new(&empty_testcase(), &[])),
            CoverageFeedback::default()
        );
    }

    #[test]
    fn coverage_snapshot_reports_seen_channel_counts() {
        let mut proxy = CoverageProxy::default();
        let mut testcase = empty_testcase();
        testcase.crumbs = vec![1, 2];
        testcase
            .handlers
            .push(handler("CONSTRAINT_ERROR", 0x42, 99));
        testcase.end = Some(EndEvent { result_class: 2 });
        testcase.mocks.push(MockEvent {
            symbol: "External.Lookup".to_owned(),
        });

        proxy.record(CoverageInput::new(
            &testcase,
            &[CoverageSignature::from_bytes([9; 32])],
        ));

        assert_eq!(
            proxy.snapshot(),
            CoverageSnapshot {
                exception_signatures: 1,
                breadcrumb_bits: 2,
                edge_bits: 1,
                handler_bits: 1,
                raise_bits: 0,
                top_level_bits: 0,
                return_class_bits: 1,
                mock_call_bits: 1,
            }
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

    fn handler(exception_name: &str, target_id: u32, last_breadcrumb: u32) -> HandlerEvent {
        HandlerEvent {
            sequence_index: 1,
            exception_name: exception_name.to_owned(),
            exception_message: String::new(),
            handler_file: "pkg.adb".to_owned(),
            handler_line: 17,
            last_breadcrumb,
            target_id,
            testcase_id: 1,
        }
    }
}
