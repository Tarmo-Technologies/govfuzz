// SPDX-License-Identifier: Apache-2.0

pub mod bridge;
pub mod classify;
pub mod cluster;
pub mod finding;
pub mod line_remap;
pub mod manager;
pub mod sanitizer;
pub mod signature;

pub use classify::{
    classify, finding_tier, is_predefined_exception, resolve_handler, Classification, FindingTier,
    UNHANDLED_HANDLER_INDEX,
};
pub use finding::{FindingEmitter, FindingId};
pub use line_remap::{ResolvedLocation, SourceLineMaps};
pub use manager::{CorpusError, CorpusManager, SignatureClass, SignatureRecord};
pub use sanitizer::{parse_sanitizer_report, Sanitizer, SanitizerReport};
pub use signature::{compute_signature, Signature};
