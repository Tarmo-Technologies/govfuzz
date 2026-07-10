// SPDX-License-Identifier: Apache-2.0

pub mod coverage;
pub mod dictionary;
pub mod engine_feedback;
pub mod grammar;
pub mod mutator;
pub mod persistent;
pub mod rng;
pub mod scheduler;
pub mod symbolic_seed;
pub mod typed;

pub use coverage::{
    CoverageFeedback, CoverageInput, CoverageProxy, CoverageSignature, CoverageSnapshot,
};
pub use dictionary::{
    Dictionary, DictionaryBucket, DictionaryCurationConfig, DictionaryCurator, DictionaryEntry,
    DictionaryProvenance, DictionaryProximity, DictionarySource, DictionarySpan,
};
pub use engine_feedback::{
    AflCustomMutatorFeedback, EngineFeedback, EngineFeedbackReason, EngineFeedbackTranslator,
    EngineFeedbackTranslatorConfig, LibAflFeedback,
};
pub use grammar::Grammar;
pub use mutator::{
    MutationInput, MutationKind, MutationResult, MutatorConfig, MutatorSuite,
    OperationSequenceLayout, OperationSequenceLayoutError, OperationStepSpan,
};
pub use persistent::{
    read_queue_file, run_persistent_queue, write_queue_file, PersistentChildError,
    PersistentHarnessChild, PersistentLoopConfig, PersistentLoopError, PersistentQueueEntry,
    PersistentRunSummary,
};
pub use rng::MutationRng;
pub use scheduler::{PowerScheduleConfig, PowerScheduler, ScheduleFeedback, ScheduledSeed, SeedId};
pub use symbolic_seed::{
    generate_symbolic_seeds, SymbolicSeed, SymbolicSeedKind, SymbolicSeedSource,
};
pub use typed::{typed_candidates, TypedSpan, TypedValueKind};

pub fn crate_name() -> &'static str {
    "fuzz_engine_builtin"
}
