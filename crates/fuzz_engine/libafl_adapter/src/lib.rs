// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use corpus::compute_signature;
use event_log::{
    group_into_testcases, EventReadError, EventReader, HandlerEvent, RaiseEvent, Testcase,
    TopLevelEvent,
};
use fuzz_engine_builtin::{
    CoverageFeedback, CoverageInput, CoverageProxy, CoverageSignature, CoverageSnapshot,
    EngineFeedback, EngineFeedbackTranslator,
};

pub const LIBAFL_ENGINE_FEATURE: &str = "libafl-engine";
pub const DEFAULT_EVENT_MAP_SIZE: usize = 65_536;
pub const DEFAULT_EVENT_OBSERVER_NAME: &str = "govfuzz-events";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibAflEngineConfig {
    pub event_map_size: usize,
    pub observer_name: String,
}

impl Default for LibAflEngineConfig {
    fn default() -> Self {
        Self {
            event_map_size: DEFAULT_EVENT_MAP_SIZE,
            observer_name: DEFAULT_EVENT_OBSERVER_NAME.to_owned(),
        }
    }
}

impl LibAflEngineConfig {
    pub fn with_event_map_size(mut self, event_map_size: usize) -> Self {
        self.event_map_size = event_map_size.max(1);
        self
    }

    pub fn with_observer_name(mut self, observer_name: impl Into<String>) -> Self {
        self.observer_name = observer_name.into();
        self
    }

    pub fn plan(&self) -> LibAflEnginePlan {
        LibAflEnginePlan {
            feature: LIBAFL_ENGINE_FEATURE,
            input_type: "libafl::inputs::BytesInput",
            state_type: "libafl::state::StdState",
            scheduler_type: "libafl::schedulers::IndexesLenTimeMinimizerScheduler",
            observer_name: self.observer_name.clone(),
            event_map_size: self.event_map_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibAflEnginePlan {
    pub feature: &'static str,
    pub input_type: &'static str,
    pub state_type: &'static str,
    pub scheduler_type: &'static str,
    pub observer_name: String,
    pub event_map_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventStreamObservation {
    pub testcases: usize,
    pub feedback: CoverageFeedback,
    pub engine_feedback: EngineFeedback,
    pub snapshot: CoverageSnapshot,
    pub set_map_bits: usize,
}

#[derive(Debug, Clone)]
pub struct EventStreamObserver {
    map: Vec<u8>,
    coverage: CoverageProxy,
}

impl EventStreamObserver {
    pub fn new(map_size: usize) -> Self {
        Self {
            map: vec![0; map_size.max(1)],
            coverage: CoverageProxy::default(),
        }
    }

    pub fn from_config(config: &LibAflEngineConfig) -> Self {
        Self::new(config.event_map_size)
    }

    pub fn map(&self) -> &[u8] {
        &self.map
    }

    pub fn into_map(self) -> Vec<u8> {
        self.map
    }

    pub fn reset_coverage(&mut self) {
        self.coverage = CoverageProxy::default();
    }

    pub fn observe_reader<R: Read>(
        &mut self,
        reader: R,
    ) -> Result<EventStreamObservation, EventReadError> {
        let mut map = std::mem::take(&mut self.map);
        let result = self.observe_reader_into_slice(reader, &mut map);
        self.map = map;
        result
    }

    pub fn observe_reader_into_slice<R: Read>(
        &mut self,
        reader: R,
        map: &mut [u8],
    ) -> Result<EventStreamObservation, EventReadError> {
        map.fill(0);
        let testcases = group_into_testcases(EventReader::new(reader))?;
        let mut aggregate = CoverageFeedback::default();
        let mut writer = EventBitmapWriter { map };

        for testcase in &testcases {
            writer.mark_testcase(testcase);
            let signatures = testcase_signatures(testcase);
            let feedback = self
                .coverage
                .record(CoverageInput::new(testcase, &signatures));
            merge_feedback(&mut aggregate, feedback);
        }

        Ok(EventStreamObservation {
            testcases: testcases.len(),
            feedback: aggregate,
            engine_feedback: EngineFeedbackTranslator::default().translate_coverage(aggregate),
            snapshot: self.coverage.snapshot(),
            set_map_bits: writer.map.iter().filter(|value| **value != 0).count(),
        })
    }
}

struct EventBitmapWriter<'a> {
    map: &'a mut [u8],
}

impl EventBitmapWriter<'_> {
    fn mark_testcase(&mut self, testcase: &Testcase) {
        for signature in testcase_signatures(testcase) {
            self.mark_bytes(0x01, &signature.bytes());
        }
        for crumb in &testcase.crumbs {
            self.mark_u64(0x02, u64::from(*crumb));
        }
        for handler in &testcase.handlers {
            self.mark_handler(handler);
        }
        for raise in &testcase.raises {
            self.mark_raise(raise);
        }
        if let Some(top_level) = &testcase.top_level {
            self.mark_top_level(top_level);
        }
        if let Some(end) = &testcase.end {
            self.mark_u64(0x04, u64::from(end.result_class));
        }
        for mock in &testcase.mocks {
            self.mark_bytes(0x05, mock.symbol.as_bytes());
        }
    }

    fn mark_handler(&mut self, handler: &HandlerEvent) {
        let mut hash = StableHash::new(0x03);
        hash.write_u32(handler.target_id);
        hash.write_str(&handler.handler_file);
        hash.write_u32(handler.handler_line);
        hash.write_u32(handler.last_breadcrumb);
        hash.write_str(&handler.exception_name.to_ascii_lowercase());
        self.mark_hash(hash.finish());
    }

    fn mark_raise(&mut self, raise: &RaiseEvent) {
        let mut hash = StableHash::new(0x06);
        hash.write_str(&raise.exception_name.to_ascii_lowercase());
        hash.write_str(&raise.file);
        hash.write_u32(raise.line);
        hash.write_u32(raise.breadcrumb);
        self.mark_hash(hash.finish());
    }

    fn mark_top_level(&mut self, top_level: &TopLevelEvent) {
        let mut hash = StableHash::new(0x07);
        hash.write_str(&top_level.exception_name.to_ascii_lowercase());
        hash.write_str(&top_level.exception_message);
        self.mark_hash(hash.finish());
    }

    fn mark_u64(&mut self, channel: u8, value: u64) {
        let mut hash = StableHash::new(channel);
        hash.write_bytes(&value.to_le_bytes());
        self.mark_hash(hash.finish());
    }

    fn mark_bytes(&mut self, channel: u8, bytes: &[u8]) {
        let mut hash = StableHash::new(channel);
        hash.write_bytes(bytes);
        self.mark_hash(hash.finish());
    }

    fn mark_hash(&mut self, hash: u64) {
        if self.map.is_empty() {
            return;
        }
        let index = (hash as usize) % self.map.len();
        self.map[index] = self.map[index].saturating_add(1);
    }
}

#[cfg(feature = "libafl-engine")]
pub mod libafl_engine {
    use super::LibAflEngineConfig;
    use libafl::{
        corpus::InMemoryCorpus,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::{CanTrack, ExplicitTracking, StdMapObserver},
        schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
        state::StdState,
    };
    use libafl_bolts::rands::StdRand;
    use std::ops::DerefMut;

    pub type GovfuzzInput = BytesInput;
    pub type GovfuzzCorpus = InMemoryCorpus<GovfuzzInput>;
    // libafl 0.16 reordered these parameters: 0.13's `StdState<I, C, R, SC>`
    // became `StdState<C, I, R, SC>`, corpus first. The argument order of
    // `StdState::new` is unchanged, so only the alias moves.
    pub type GovfuzzState = StdState<GovfuzzCorpus, GovfuzzInput, StdRand, GovfuzzCorpus>;
    pub type GovfuzzEventObserver =
        ExplicitTracking<StdMapObserver<'static, u8, false>, true, false>;
    // Also 0.16: the minimizer alias gained an input parameter
    // (`<CS, I, O>`), and `QueueScheduler` dropped its own — it is now generic
    // over `(I, S)` at the impl rather than the type.
    pub type GovfuzzScheduler =
        IndexesLenTimeMinimizerScheduler<QueueScheduler, GovfuzzInput, GovfuzzEventObserver>;

    pub fn new_event_observer(config: &LibAflEngineConfig) -> GovfuzzEventObserver {
        StdMapObserver::owned(
            config.observer_name.clone(),
            vec![0_u8; config.event_map_size.max(1)],
        )
        .track_indices()
    }

    pub fn new_scheduler(observer: &GovfuzzEventObserver) -> GovfuzzScheduler {
        IndexesLenTimeMinimizerScheduler::new(observer, QueueScheduler::new())
    }

    pub fn observe_reader_into_observer<R: std::io::Read>(
        event_stream: &mut super::EventStreamObserver,
        reader: R,
        observer: &mut GovfuzzEventObserver,
    ) -> Result<super::EventStreamObservation, event_log::EventReadError> {
        event_stream.observe_reader_into_slice(reader, observer.as_mut().deref_mut())
    }

    pub fn observer_set_bits(observer: &GovfuzzEventObserver) -> usize {
        observer
            .as_ref()
            .iter()
            .filter(|value| **value != 0)
            .count()
    }

    pub fn new_state(seed: u64) -> Result<GovfuzzState, libafl::Error> {
        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        StdState::new(
            StdRand::with_seed(seed),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
    }
}

pub fn crate_name() -> &'static str {
    "fuzz_engine_libafl_adapter"
}

fn testcase_signatures(testcase: &Testcase) -> Vec<CoverageSignature> {
    testcase
        .handlers
        .iter()
        .map(|handler| CoverageSignature::from_bytes(compute_signature(testcase, handler).0))
        .collect()
}

fn merge_feedback(total: &mut CoverageFeedback, next: CoverageFeedback) {
    total.new_exception_signatures = total
        .new_exception_signatures
        .saturating_add(next.new_exception_signatures);
    total.new_breadcrumb_bits = total
        .new_breadcrumb_bits
        .saturating_add(next.new_breadcrumb_bits);
    total.new_edge_bits = total.new_edge_bits.saturating_add(next.new_edge_bits);
    total.new_handler_bits = total.new_handler_bits.saturating_add(next.new_handler_bits);
    total.new_raise_bits = total.new_raise_bits.saturating_add(next.new_raise_bits);
    total.new_top_level_bits = total
        .new_top_level_bits
        .saturating_add(next.new_top_level_bits);
    total.new_return_class_bits = total
        .new_return_class_bits
        .saturating_add(next.new_return_class_bits);
    total.new_mock_call_bits = total
        .new_mock_call_bits
        .saturating_add(next.new_mock_call_bits);
}

struct StableHash {
    value: u64,
}

impl StableHash {
    fn new(channel: u8) -> Self {
        let mut hash = Self {
            value: 0xcbf2_9ce4_8422_2325,
        };
        hash.write_bytes(&[channel]);
        hash
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
    use event_log::EventTag;
    use std::io::Cursor;

    #[test]
    fn engine_plan_names_optional_feature_and_libafl_types() {
        let plan = LibAflEngineConfig::default()
            .with_event_map_size(128)
            .with_observer_name("events")
            .plan();

        assert_eq!(plan.feature, "libafl-engine");
        assert_eq!(plan.observer_name, "events");
        assert_eq!(plan.event_map_size, 128);
        assert!(plan.state_type.contains("StdState"));
        assert!(plan
            .scheduler_type
            .contains("IndexesLenTimeMinimizerScheduler"));
    }

    #[test]
    fn event_stream_map_records_signature_and_bitmap_feedback() {
        let stream = fixture_event_stream();
        let mut observer = EventStreamObserver::new(256);

        let first = observer
            .observe_reader(Cursor::new(&stream))
            .expect("event stream is valid");
        let second = observer
            .observe_reader(Cursor::new(&stream))
            .expect("event stream can be observed again");

        assert_eq!(first.testcases, 1);
        assert_eq!(first.feedback.new_exception_signatures, 1);
        assert_eq!(first.feedback.new_breadcrumb_bits, 1);
        assert_eq!(first.feedback.new_handler_bits, 1);
        assert_eq!(first.feedback.new_return_class_bits, 1);
        assert!(first.engine_feedback.libafl.is_interesting);
        assert!(first.engine_feedback.libafl.is_objective);
        assert!(first.engine_feedback.afl.queue_get);
        assert!(first.set_map_bits >= 4);
        assert!(observer.map().iter().any(|value| *value != 0));

        assert_eq!(second.testcases, 1);
        assert!(second.feedback.is_empty());
        assert!(!second.engine_feedback.libafl.is_interesting);
        assert!(second.set_map_bits >= 4);
        assert_eq!(second.snapshot.exception_signatures, 1);
    }

    #[test]
    fn event_stream_map_hashes_raise_and_top_level_channels() {
        let mut observer = EventStreamObserver::new(4096);

        let raise_constraint =
            observer_map_for(&mut observer, raise_only_stream("CONSTRAINT_ERROR"));
        let raise_program = observer_map_for(&mut observer, raise_only_stream("PROGRAM_ERROR"));
        let top_level_constraint = observer_map_for(
            &mut observer,
            top_level_only_stream("CONSTRAINT_ERROR", "bad input"),
        );
        let top_level_program = observer_map_for(
            &mut observer,
            top_level_only_stream("PROGRAM_ERROR", "bad input"),
        );

        assert_ne!(raise_constraint, raise_program);
        assert_ne!(top_level_constraint, top_level_program);
    }

    #[test]
    fn event_stream_observation_reports_raise_and_top_level_feedback() {
        let mut observer = EventStreamObserver::new(4096);
        observer
            .observe_reader(Cursor::new(empty_result_stream()))
            .expect("baseline event stream is valid");

        let raise = observer
            .observe_reader(Cursor::new(raise_only_stream("CONSTRAINT_ERROR")))
            .expect("raise stream is valid");

        assert_eq!(raise.feedback.new_raise_bits, 1);
        assert_eq!(raise.feedback.new_top_level_bits, 0);
        assert_eq!(raise.feedback.new_return_class_bits, 0);
        assert!(!raise.feedback.is_empty());
        assert!(raise.engine_feedback.libafl.is_interesting);
        assert!(!raise.engine_feedback.libafl.is_objective);

        let top_level = observer
            .observe_reader(Cursor::new(top_level_without_crumb_stream(
                "PROGRAM_ERROR",
                "escaped",
            )))
            .expect("top-level stream is valid");

        assert_eq!(top_level.feedback.new_raise_bits, 0);
        assert_eq!(top_level.feedback.new_top_level_bits, 1);
        assert_eq!(top_level.feedback.new_breadcrumb_bits, 0);
        assert_eq!(top_level.feedback.new_return_class_bits, 0);
        assert!(!top_level.feedback.is_empty());
        assert!(top_level.engine_feedback.libafl.is_interesting);
        assert!(!top_level.engine_feedback.libafl.is_objective);
    }

    #[cfg(feature = "libafl-engine")]
    #[test]
    fn libafl_feature_constructs_state_scheduler_and_updates_tracked_observer() {
        let config = LibAflEngineConfig::default().with_event_map_size(128);
        let mut observer = libafl_engine::new_event_observer(&config);
        let mut stream_observer = EventStreamObserver::from_config(&config);
        let observation = libafl_engine::observe_reader_into_observer(
            &mut stream_observer,
            Cursor::new(fixture_event_stream()),
            &mut observer,
        )
        .expect("event stream updates the live LibAFL observer");
        let _scheduler = libafl_engine::new_scheduler(&observer);
        let _state = libafl_engine::new_state(0).expect("LibAFL state is constructed");

        assert!(observation.set_map_bits > 0);
        assert!(observation.engine_feedback.libafl.is_interesting);
        assert_eq!(
            libafl_engine::observer_set_bits(&observer),
            observation.set_map_bits
        );
    }

    fn observer_map_for(observer: &mut EventStreamObserver, stream: Vec<u8>) -> Vec<u8> {
        let observation = observer
            .observe_reader(Cursor::new(stream))
            .expect("event stream is valid");
        assert!(observation.set_map_bits > 0);
        observer.map().to_vec()
    }

    fn fixture_event_stream() -> Vec<u8> {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_target(&mut bytes, 0x42);
        push_crumb(&mut bytes, 9);
        push_handler(
            &mut bytes,
            "CONSTRAINT_ERROR",
            "bad",
            "pkg.adb",
            11,
            9,
            0x42,
            7,
        );
        push_end(&mut bytes, 0);
        bytes
    }

    fn empty_result_stream() -> Vec<u8> {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_end(&mut bytes, 0);
        bytes
    }

    fn raise_only_stream(exception_name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_raise(&mut bytes, exception_name, "pkg.adb", 11, 9);
        push_end(&mut bytes, 0);
        bytes
    }

    fn top_level_only_stream(exception_name: &str, exception_message: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_crumb(&mut bytes, 9);
        push_top_level(&mut bytes, exception_name, exception_message, 9, 0x42, 7);
        push_end(&mut bytes, 0);
        bytes
    }

    fn top_level_without_crumb_stream(exception_name: &str, exception_message: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_begin(&mut bytes, 7);
        push_top_level(&mut bytes, exception_name, exception_message, 9, 0x42, 7);
        push_end(&mut bytes, 0);
        bytes
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

    fn push_string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
}
