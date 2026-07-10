// SPDX-License-Identifier: Apache-2.0

use crate::replay::{load_finding, signatures_for_input_with_runner, HarnessRunner, ReplayInput};
use crate::ReplayError;
use corpus::Signature;
use fuzz_engine_builtin::{typed_candidates, Dictionary, TypedSpan, TypedValueKind};
use std::ops::Range;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteMinimization {
    pub original_len: usize,
    pub minimized: Vec<u8>,
    pub predicate_runs: usize,
}

impl ByteMinimization {
    pub fn minimized_len(&self) -> usize {
        self.minimized.len()
    }

    pub fn removed_bytes(&self) -> usize {
        self.original_len.saturating_sub(self.minimized.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedValueMinimization {
    pub original_len: usize,
    pub minimized: Vec<u8>,
    pub attempted_replacements: usize,
    pub accepted_replacements: usize,
}

impl TypedValueMinimization {
    pub fn minimized_len(&self) -> usize {
        self.minimized.len()
    }

    pub fn removed_bytes(&self) -> usize {
        self.original_len.saturating_sub(self.minimized.len())
    }
}

pub fn ddmin_bytes<E>(
    input: &[u8],
    mut predicate: impl FnMut(&[u8]) -> Result<bool, E>,
) -> Result<ByteMinimization, E> {
    let original_len = input.len();
    let mut current = input.to_vec();
    let mut n = 2_usize;
    let mut predicate_runs = 0_usize;

    while !current.is_empty() {
        let split_count = n.min(current.len());
        let chunks = split_ranges(current.len(), split_count);
        let mut changed = false;

        for chunk in &chunks {
            let candidate = remove_range(&current, chunk.clone());
            predicate_runs = predicate_runs.saturating_add(1);
            if predicate(&candidate)? {
                current = candidate;
                n = split_count.saturating_sub(1).max(2);
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        for chunk in &chunks {
            if chunk.len() == current.len() {
                continue;
            }
            let candidate = current[chunk.clone()].to_vec();
            predicate_runs = predicate_runs.saturating_add(1);
            if predicate(&candidate)? {
                current = candidate;
                n = 2;
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        if split_count >= current.len() {
            break;
        }
        n = split_count.saturating_mul(2).min(current.len());
    }

    Ok(ByteMinimization {
        original_len,
        minimized: current,
        predicate_runs,
    })
}

pub fn minimize_finding_bytes(
    finding_dir: &Path,
    harness_path: &Path,
) -> Result<ByteMinimization, MinimizeError> {
    let runner = HarnessRunner::direct(harness_path);
    minimize_finding_bytes_with_runner(finding_dir, &runner)
}

pub fn minimize_finding_bytes_with_runner(
    finding_dir: &Path,
    runner: &HarnessRunner,
) -> Result<ByteMinimization, MinimizeError> {
    let (recorded, input) = load_reproducing_input_with_runner(finding_dir, runner)?;

    ddmin_bytes(&input, |candidate| {
        candidate_preserves_signature_with_runner(runner, candidate, recorded)
    })
}

pub fn minimize_typed_values<E>(
    input: &[u8],
    typed_spans: &[TypedSpan],
    mut predicate: impl FnMut(&[u8]) -> Result<bool, E>,
) -> Result<TypedValueMinimization, E> {
    let original_len = input.len();
    let mut current = input.to_vec();
    let mut offset = 0_isize;
    let mut attempted_replacements = 0_usize;
    let mut accepted_replacements = 0_usize;
    let spans = sorted_non_overlapping_spans(typed_spans, input.len());

    for span in spans {
        let Some(range) = adjusted_range(&span.range, offset, current.len()) else {
            continue;
        };
        let current_value = current[range.clone()].to_vec();

        for replacement in typed_minimizer_candidates(span.kind) {
            if replacement == current_value {
                continue;
            }

            attempted_replacements = attempted_replacements.saturating_add(1);
            let candidate = replace_range(&current, range.clone(), &replacement);
            if predicate(&candidate)? {
                offset += replacement.len() as isize - range.len() as isize;
                current = candidate;
                accepted_replacements = accepted_replacements.saturating_add(1);
                break;
            }
        }
    }

    Ok(TypedValueMinimization {
        original_len,
        minimized: current,
        attempted_replacements,
        accepted_replacements,
    })
}

pub fn minimize_finding_typed_values(
    finding_dir: &Path,
    harness_path: &Path,
) -> Result<TypedValueMinimization, MinimizeError> {
    let typed_spans = load_decoded_typed_spans(finding_dir)?;
    let runner = HarnessRunner::direct(harness_path);
    minimize_finding_typed_values_with_runner_and_spans(finding_dir, &runner, &typed_spans)
}

pub fn minimize_finding_typed_values_with_spans(
    finding_dir: &Path,
    harness_path: &Path,
    typed_spans: &[TypedSpan],
) -> Result<TypedValueMinimization, MinimizeError> {
    let runner = HarnessRunner::direct(harness_path);
    minimize_finding_typed_values_with_runner_and_spans(finding_dir, &runner, typed_spans)
}

pub fn minimize_finding_typed_values_with_runner(
    finding_dir: &Path,
    runner: &HarnessRunner,
) -> Result<TypedValueMinimization, MinimizeError> {
    let typed_spans = load_decoded_typed_spans(finding_dir)?;
    minimize_finding_typed_values_with_runner_and_spans(finding_dir, runner, &typed_spans)
}

pub fn minimize_finding_typed_values_with_runner_and_spans(
    finding_dir: &Path,
    runner: &HarnessRunner,
    typed_spans: &[TypedSpan],
) -> Result<TypedValueMinimization, MinimizeError> {
    let (recorded, input) = load_reproducing_input_with_runner(finding_dir, runner)?;

    minimize_typed_values(&input, typed_spans, |candidate| {
        candidate_preserves_signature_with_runner(runner, candidate, recorded)
    })
}

pub fn load_decoded_typed_spans(finding_dir: &Path) -> Result<Vec<TypedSpan>, MinimizeError> {
    let path = finding_dir.join("decoded.json");
    if !path.is_file() {
        return Ok(Vec::new());
    }

    let decoded: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let Some(spans) = decoded.get("typed_spans") else {
        return Ok(Vec::new());
    };
    let Some(spans) = spans.as_array() else {
        return Err(MinimizeError::InvalidDecodedMetadata {
            path,
            reason: "typed_spans must be an array".to_owned(),
        });
    };

    let spans = spans
        .iter()
        .enumerate()
        .map(|(index, value)| decoded_typed_span(&path, index, value))
        .collect::<Result<Vec<_>, _>>()?;
    validate_decoded_typed_spans(&path, &spans)?;
    Ok(spans)
}

#[derive(Debug, thiserror::Error)]
pub enum MinimizeError {
    #[error(transparent)]
    Replay(#[from] crate::ReplayError),
    #[error("I/O error while reading decoded metadata")]
    Io(#[from] std::io::Error),
    #[error("JSON error while reading decoded metadata")]
    Json(#[from] serde_json::Error),
    #[error("invalid decoded metadata at {}: {reason}", path.display())]
    InvalidDecodedMetadata { path: PathBuf, reason: String },
    #[error(
        "original testcase does not reproduce recorded signature {recorded:?}; actual {actual:?}"
    )]
    OriginalMismatch {
        recorded: Signature,
        actual: Option<Signature>,
    },
}

fn load_reproducing_input_with_runner(
    finding_dir: &Path,
    runner: &HarnessRunner,
) -> Result<(Signature, Vec<u8>), MinimizeError> {
    let ReplayInput { recorded, input } = load_finding(finding_dir)?;
    let original = signatures_for_input_with_runner(runner, &input)?;
    if !original.contains(&recorded) {
        return Err(MinimizeError::OriginalMismatch {
            recorded,
            actual: original.first().copied(),
        });
    }

    Ok((recorded, input))
}

fn candidate_preserves_signature_with_runner(
    runner: &HarnessRunner,
    candidate: &[u8],
    recorded: Signature,
) -> Result<bool, MinimizeError> {
    match signatures_for_input_with_runner(runner, candidate) {
        Ok(signatures) => Ok(signatures.contains(&recorded)),
        Err(error @ ReplayError::HarnessFailedToStart { .. }) => Err(error.into()),
        Err(_) => Ok(false),
    }
}

fn decoded_typed_span(
    path: &Path,
    index: usize,
    value: &serde_json::Value,
) -> Result<TypedSpan, MinimizeError> {
    let Some(start) = value.get("start").and_then(serde_json::Value::as_u64) else {
        return invalid_decoded_span(path, index, "missing numeric start");
    };
    let Some(end) = value.get("end").and_then(serde_json::Value::as_u64) else {
        return invalid_decoded_span(path, index, "missing numeric end");
    };
    let Some(kind) = value.get("kind").and_then(serde_json::Value::as_str) else {
        return invalid_decoded_span(path, index, "missing string kind");
    };
    let Some(kind) = typed_value_kind(kind) else {
        return invalid_decoded_span(path, index, "unknown kind");
    };

    let Ok(start) = usize::try_from(start) else {
        return invalid_decoded_span(path, index, "start is too large");
    };
    let Ok(end) = usize::try_from(end) else {
        return invalid_decoded_span(path, index, "end is too large");
    };
    if start >= end {
        return invalid_decoded_span(path, index, "range must be non-empty");
    }

    Ok(TypedSpan::new(start..end, kind))
}

fn invalid_decoded_span<T>(path: &Path, index: usize, reason: &str) -> Result<T, MinimizeError> {
    Err(MinimizeError::InvalidDecodedMetadata {
        path: path.to_path_buf(),
        reason: format!("typed_spans[{index}]: {reason}"),
    })
}

fn typed_value_kind(kind: &str) -> Option<TypedValueKind> {
    match kind {
        "boolean" | "bool" => Some(TypedValueKind::Boolean),
        "signed_integer" | "signed-integer" | "i32" => Some(TypedValueKind::SignedInteger),
        "unsigned_integer" | "unsigned-integer" | "u32" => Some(TypedValueKind::UnsignedInteger),
        "float64" | "float" | "f64" => Some(TypedValueKind::Float64),
        "bytes" => Some(TypedValueKind::Bytes),
        "string" => Some(TypedValueKind::String),
        _ => None,
    }
}

fn typed_minimizer_candidates(kind: TypedValueKind) -> Vec<Vec<u8>> {
    typed_candidates(kind, &Dictionary::default())
}

fn validate_decoded_typed_spans(path: &Path, spans: &[TypedSpan]) -> Result<(), MinimizeError> {
    let mut indexed = spans.iter().enumerate().collect::<Vec<_>>();
    indexed.sort_by_key(|(_, span)| (span.range.start, span.range.end));

    let mut previous_end = 0_usize;
    for (index, span) in indexed {
        if span.range.start < previous_end {
            return invalid_decoded_span(path, index, "overlaps another typed span");
        }
        previous_end = span.range.end;
    }

    Ok(())
}

fn sorted_non_overlapping_spans(typed_spans: &[TypedSpan], input_len: usize) -> Vec<TypedSpan> {
    let mut spans = typed_spans
        .iter()
        .filter(|span| span.valid_for(input_len))
        .cloned()
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| (span.range.start, span.range.end));

    let mut previous_end = 0_usize;
    spans
        .into_iter()
        .filter(|span| {
            if span.range.start < previous_end {
                return false;
            }
            previous_end = span.range.end;
            true
        })
        .collect()
}

fn adjusted_range(range: &Range<usize>, offset: isize, len: usize) -> Option<Range<usize>> {
    let start = range.start.checked_add_signed(offset)?;
    let end = range.end.checked_add_signed(offset)?;
    if start < end && end <= len {
        Some(start..end)
    } else {
        None
    }
}

fn replace_range(input: &[u8], range: Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut candidate = Vec::with_capacity(input.len() - range.len() + replacement.len());
    candidate.extend_from_slice(&input[..range.start]);
    candidate.extend_from_slice(replacement);
    candidate.extend_from_slice(&input[range.end..]);
    candidate
}

fn split_ranges(len: usize, count: usize) -> Vec<Range<usize>> {
    let count = count.min(len).max(1);
    let base = len / count;
    let remainder = len % count;
    let mut start = 0_usize;
    let mut ranges = Vec::with_capacity(count);

    for index in 0..count {
        let extra = usize::from(index < remainder);
        let end = start + base + extra;
        ranges.push(start..end);
        start = end;
    }

    ranges
}

fn remove_range(input: &[u8], range: Range<usize>) -> Vec<u8> {
    let mut candidate = Vec::with_capacity(input.len().saturating_sub(range.len()));
    candidate.extend_from_slice(&input[..range.start]);
    candidate.extend_from_slice(&input[range.end..]);
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddmin_removes_irrelevant_prefix_and_suffix() {
        let result = ddmin_bytes(b"prefix-crash-suffix", |candidate| {
            Ok::<_, ()>(contains_bytes(candidate, b"crash"))
        })
        .unwrap();

        assert_eq!(result.minimized, b"crash");
        assert_eq!(result.original_len, b"prefix-crash-suffix".len());
        assert_eq!(result.minimized_len(), 5);
        assert_eq!(result.removed_bytes(), b"prefix--suffix".len());
        assert!(result.predicate_runs > 0);
    }

    #[test]
    fn ddmin_can_keep_a_single_required_byte() {
        let result =
            ddmin_bytes(b"abc", |candidate| Ok::<_, ()>(candidate.contains(&b'b'))).unwrap();

        assert_eq!(result.minimized, b"b");
    }

    #[test]
    fn ddmin_stops_when_no_smaller_candidate_satisfies_predicate() {
        let result = ddmin_bytes(b"abc", |candidate| Ok::<_, ()>(candidate == b"abc")).unwrap();

        assert_eq!(result.minimized, b"abc");
    }

    #[test]
    fn ddmin_propagates_predicate_errors() {
        let error = ddmin_bytes(b"abc", |_candidate| Err::<bool, _>("stop")).unwrap_err();

        assert_eq!(error, "stop");
    }

    #[test]
    fn typed_value_minimizer_collapses_spans_in_order() {
        let spans = vec![
            TypedSpan::new(0..4, TypedValueKind::String),
            TypedSpan::new(9..13, TypedValueKind::Bytes),
        ];
        let result = minimize_typed_values(b"AAAACRASHBBBB", &spans, |candidate| {
            Ok::<_, ()>(contains_bytes(candidate, b"CRASH"))
        })
        .unwrap();

        assert_eq!(result.minimized, b"CRASH");
        assert_eq!(result.original_len, 13);
        assert_eq!(result.minimized_len(), 5);
        assert_eq!(result.removed_bytes(), 8);
        assert_eq!(result.accepted_replacements, 2);
    }

    #[test]
    fn typed_value_minimizer_ignores_invalid_spans() {
        let spans = vec![TypedSpan::new(10..12, TypedValueKind::String)];
        let result = minimize_typed_values(b"abc", &spans, |_candidate| Ok::<_, ()>(true)).unwrap();

        assert_eq!(result.minimized, b"abc");
        assert_eq!(result.attempted_replacements, 0);
        assert_eq!(result.accepted_replacements, 0);
    }

    #[test]
    fn typed_value_minimizer_skips_overlapping_spans() {
        let spans = vec![
            TypedSpan::new(0..6, TypedValueKind::Bytes),
            TypedSpan::new(2..4, TypedValueKind::String),
        ];
        let result = minimize_typed_values(b"prefix-crash", &spans, |candidate| {
            Ok::<_, ()>(contains_bytes(candidate, b"crash"))
        })
        .unwrap();

        assert_eq!(result.minimized, b"-crash");
        assert_eq!(result.attempted_replacements, 1);
        assert_eq!(result.accepted_replacements, 1);
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
