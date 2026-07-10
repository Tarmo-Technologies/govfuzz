// SPDX-License-Identifier: Apache-2.0

use std::{fmt, ops::Range};

use crate::dictionary::Dictionary;
use crate::rng::MutationRng;
use crate::typed::{typed_candidates, TypedSpan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    BitFlip,
    ByteFlip,
    Arithmetic,
    Interesting,
    Splice,
    DictionaryInsert,
    StructuredRecord,
    StructuredJson,
    StructuredXml,
    StructuredKeyValue,
    StructuredUrlEncoded,
    StructuredMultipart,
    StructuredCsv,
    StructuredHttp,
    StructuredIni,
    StructuredToml,
    StructuredYaml,
    /// A binary chunked/length-prefixed shape: a magic header (a mined
    /// signature token) followed by repeated `[u32 length][payload]` chunks.
    /// Models PNG/RIFF/ZIP-style and network-framing binary formats — the
    /// dominant structure of the legacy binary parsers govfuzz targets.
    StructuredChunked,
    /// A recursively-nested structure drawn from a small context-free grammar:
    /// balanced delimiter pairs (`()`, `[]`, `{}`, `<e>..</e>`) nested to a
    /// random depth, optionally mixing delimiters per level, with an innermost
    /// terminal mined from the dictionary. Models the nested grammars of legacy
    /// recursive-descent parsers (S-expressions, nested JSON/XML, block scopes)
    /// and is the lever for recursion-limit / stack-exhaustion defects that the
    /// flat structured mutators cannot reach.
    StructuredRecursive,
    /// A fresh derivation from a user-supplied context-free grammar (`--grammar`).
    /// Unlike the fixed structured mutators, this generates deeply-valid inputs for a
    /// bespoke format the operator describes, reaching parser code past surface checks
    /// that reject random bytes.
    StructuredGrammar,
    TypedValue,
    OpSequence,
    /// Offset-aware splice driven by runtime cmplog evidence.
    /// When the recorded operand_a appears at offset N of the
    /// current input, replace it with operand_b at exactly that
    /// offset. This is the RedQueen-style mutation that recovers
    /// magic-byte expectations from a single observed comparison
    /// without paying the dictionary-token loss of positional
    /// information.
    CmpLogSplice,
}

impl MutationKind {
    const ALL: [Self; 23] = [
        Self::BitFlip,
        Self::ByteFlip,
        Self::Arithmetic,
        Self::Interesting,
        Self::Splice,
        Self::DictionaryInsert,
        Self::StructuredRecord,
        Self::StructuredJson,
        Self::StructuredXml,
        Self::StructuredKeyValue,
        Self::StructuredUrlEncoded,
        Self::StructuredMultipart,
        Self::StructuredCsv,
        Self::StructuredHttp,
        Self::StructuredIni,
        Self::StructuredToml,
        Self::StructuredYaml,
        Self::StructuredChunked,
        Self::StructuredRecursive,
        Self::StructuredGrammar,
        Self::TypedValue,
        Self::OpSequence,
        Self::CmpLogSplice,
    ];
}

/// How many extra times `CmpLogSplice` is entered into the per-mutation
/// selection pool when the base carries per-input RedQueen evidence (#400). The
/// uniform scheduler then picks the offset-aware splice for the large majority
/// of that base's children — input-to-state injection clears a hard equality
/// gate in one mutation where blind mutation needs exponentially many tries.
const CMPLOG_SPLICE_EXTRA_WEIGHT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationResult {
    pub bytes: Vec<u8>,
    pub kind: MutationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutatorConfig {
    pub max_len: usize,
    pub structured_records: bool,
    pub structured_json: bool,
    pub structured_xml: bool,
    pub structured_key_value: bool,
    pub structured_url_encoded: bool,
    pub structured_multipart: bool,
    pub structured_csv: bool,
    pub structured_http: bool,
    pub structured_ini: bool,
    pub structured_toml: bool,
    pub structured_yaml: bool,
    pub structured_chunked: bool,
    pub structured_recursive: bool,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            max_len: 4096,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationStepSpan {
    pub range: Range<usize>,
    pub op_index_range: Range<usize>,
}

impl OperationStepSpan {
    pub fn new(range: Range<usize>, op_index_range: Range<usize>) -> Self {
        Self {
            range,
            op_index_range,
        }
    }

    fn valid_for(&self, len: usize) -> bool {
        self.range.start < self.range.end
            && self.range.end <= len
            && self.op_index_range.start < self.op_index_range.end
            && self.op_index_range.start >= self.range.start
            && self.op_index_range.end <= self.range.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationSequenceLayoutError {
    InvalidStepBounds {
        min_steps: usize,
        max_steps: usize,
    },
    EmptyOperationSet,
    InvalidStepCountRange {
        range: Range<usize>,
    },
    InvalidStepSpan {
        index: usize,
        range: Range<usize>,
        op_index_range: Range<usize>,
    },
    OverlappingStepSpan {
        previous: usize,
        current: usize,
    },
    StepCountMismatch {
        decoded: usize,
        actual: usize,
    },
    InvalidOperationSelector {
        index: usize,
        range: Range<usize>,
    },
}

impl fmt::Display for OperationSequenceLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStepBounds {
                min_steps,
                max_steps,
            } => write!(
                formatter,
                "operation sequence step bounds are invalid: min {min_steps}, max {max_steps}"
            ),
            Self::EmptyOperationSet => {
                formatter.write_str("operation sequence has no selectable operations")
            }
            Self::InvalidStepCountRange { range } => write!(
                formatter,
                "operation sequence step-count range {range:?} is not decodable for this input"
            ),
            Self::InvalidStepSpan {
                index,
                range,
                op_index_range,
            } => write!(
                formatter,
                "operation sequence step {index} has invalid range {range:?} or selector range {op_index_range:?}"
            ),
            Self::OverlappingStepSpan { previous, current } => write!(
                formatter,
                "operation sequence step {current} overlaps previous step {previous}"
            ),
            Self::StepCountMismatch { decoded, actual } => write!(
                formatter,
                "operation sequence decoded {decoded} steps but layout contains {actual}"
            ),
            Self::InvalidOperationSelector { index, range } => write!(
                formatter,
                "operation sequence step {index} selector range {range:?} is not decodable for this input"
            ),
        }
    }
}

impl std::error::Error for OperationSequenceLayoutError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSequenceLayout {
    pub step_count_range: Option<Range<usize>>,
    pub min_steps: usize,
    pub max_steps: usize,
    pub operation_count: usize,
    pub steps: Vec<OperationStepSpan>,
}

impl OperationSequenceLayout {
    pub fn new(
        step_count_range: Option<Range<usize>>,
        min_steps: usize,
        max_steps: usize,
        operation_count: usize,
        steps: Vec<OperationStepSpan>,
    ) -> Self {
        Self {
            step_count_range,
            min_steps,
            max_steps,
            operation_count,
            steps,
        }
    }

    pub fn validate_for_input(&self, bytes: &[u8]) -> Result<(), OperationSequenceLayoutError> {
        if self.min_steps > self.max_steps {
            return Err(OperationSequenceLayoutError::InvalidStepBounds {
                min_steps: self.min_steps,
                max_steps: self.max_steps,
            });
        }

        if self.operation_count == 0 {
            return Err(OperationSequenceLayoutError::EmptyOperationSet);
        }

        let decoded_step_count = if let Some(range) = self.step_count_range.as_ref() {
            Some(
                decode_bounded_range(bytes, range, self.min_steps, self.max_steps).ok_or_else(
                    || OperationSequenceLayoutError::InvalidStepCountRange {
                        range: range.clone(),
                    },
                )?,
            )
        } else {
            None
        };

        let mut previous_end = 0;
        for (index, step) in self.steps.iter().enumerate() {
            if !step.valid_for(bytes.len()) {
                return Err(OperationSequenceLayoutError::InvalidStepSpan {
                    index,
                    range: step.range.clone(),
                    op_index_range: step.op_index_range.clone(),
                });
            }

            if step.range.start < previous_end {
                return Err(OperationSequenceLayoutError::OverlappingStepSpan {
                    previous: index.saturating_sub(1),
                    current: index,
                });
            }
            previous_end = step.range.end;

            if decode_bounded_range(
                bytes,
                &step.op_index_range,
                0,
                self.operation_count.saturating_sub(1),
            )
            .is_none()
            {
                return Err(OperationSequenceLayoutError::InvalidOperationSelector {
                    index,
                    range: step.op_index_range.clone(),
                });
            }
        }

        if let Some(decoded) = decoded_step_count {
            if decoded != self.steps.len() {
                return Err(OperationSequenceLayoutError::StepCountMismatch {
                    decoded,
                    actual: self.steps.len(),
                });
            }
        }

        Ok(())
    }

    fn decoded_step_count(&self, bytes: &[u8]) -> Option<usize> {
        let range = self.step_count_range.as_ref()?;
        decode_bounded_range(bytes, range, self.min_steps, self.max_steps)
    }

    fn valid_steps(&self, len: usize) -> Vec<&OperationStepSpan> {
        let mut steps: Vec<&OperationStepSpan> = self
            .steps
            .iter()
            .filter(|step| step.valid_for(len))
            .collect();
        steps.sort_by_key(|step| (step.range.start, step.range.end));

        let mut previous_end = 0;
        steps
            .into_iter()
            .filter(|step| {
                if step.range.start < previous_end {
                    false
                } else {
                    previous_end = step.range.end;
                    true
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MutationInput<'a> {
    pub bytes: &'a [u8],
    pub peer: Option<&'a [u8]>,
    pub dictionary: &'a Dictionary,
    pub typed_spans: &'a [TypedSpan],
    pub operation_sequence: Option<&'a OperationSequenceLayout>,
    pub cmplog: Option<&'a cmplog::CmpLog>,
    pub grammar: Option<&'a crate::grammar::Grammar>,
}

impl<'a> MutationInput<'a> {
    pub fn new(bytes: &'a [u8], dictionary: &'a Dictionary) -> Self {
        Self {
            bytes,
            peer: None,
            dictionary,
            typed_spans: &[],
            operation_sequence: None,
            cmplog: None,
            grammar: None,
        }
    }

    pub fn with_peer(mut self, peer: &'a [u8]) -> Self {
        self.peer = Some(peer);
        self
    }

    pub fn with_typed_spans(mut self, typed_spans: &'a [TypedSpan]) -> Self {
        self.typed_spans = typed_spans;
        self
    }

    pub fn with_operation_sequence(mut self, layout: &'a OperationSequenceLayout) -> Self {
        self.operation_sequence = Some(layout);
        self
    }

    pub fn with_cmplog(mut self, cmplog: &'a cmplog::CmpLog) -> Self {
        self.cmplog = Some(cmplog);
        self
    }

    pub fn with_grammar(mut self, grammar: &'a crate::grammar::Grammar) -> Self {
        self.grammar = Some(grammar);
        self
    }
}

#[derive(Debug, Clone)]
pub struct MutatorSuite {
    config: MutatorConfig,
}

impl Default for MutatorSuite {
    fn default() -> Self {
        Self::new(MutatorConfig::default())
    }
}

impl MutatorSuite {
    pub fn new(config: MutatorConfig) -> Self {
        Self { config }
    }

    pub fn mutate(
        &self,
        input: &MutationInput<'_>,
        rng: &mut MutationRng,
    ) -> Option<MutationResult> {
        let mut available: Vec<MutationKind> = MutationKind::ALL
            .into_iter()
            .filter(|kind| self.kind_available(input, *kind))
            .collect();

        // #400: when the base carries per-input cmplog evidence, bias selection
        // heavily toward CmpLogSplice. `kind_available` only admits CmpLogSplice
        // when the captured operand actually occurs in this input, so the boost
        // never wastes the schedule on an inapplicable splice.
        if input.cmplog.is_some() && available.contains(&MutationKind::CmpLogSplice) {
            for _ in 0..CMPLOG_SPLICE_EXTRA_WEIGHT {
                available.push(MutationKind::CmpLogSplice);
            }
        }

        while !available.is_empty() {
            let index = rng.choose_index(available.len())?;
            let kind = available.swap_remove(index);
            if let Some(result) = self.try_mutate_with_kind(input, kind, rng) {
                return Some(result);
            }
        }

        None
    }

    pub fn try_mutate_with_kind(
        &self,
        input: &MutationInput<'_>,
        kind: MutationKind,
        rng: &mut MutationRng,
    ) -> Option<MutationResult> {
        let bytes = match kind {
            MutationKind::BitFlip => bit_flip(input.bytes, rng),
            MutationKind::ByteFlip => byte_flip(input.bytes, rng),
            MutationKind::Arithmetic => arithmetic(input.bytes, rng),
            MutationKind::Interesting => interesting(input.bytes, rng),
            MutationKind::Splice => self.splice(input.bytes, input.peer?, rng),
            MutationKind::DictionaryInsert => {
                self.dictionary_insert(input.bytes, input.dictionary, rng)
            }
            MutationKind::StructuredRecord => self.structured_record(input.dictionary, rng),
            MutationKind::StructuredJson => self.structured_json(input.dictionary, rng),
            MutationKind::StructuredXml => self.structured_xml(input.dictionary, rng),
            MutationKind::StructuredKeyValue => self.structured_key_value(input.dictionary, rng),
            MutationKind::StructuredUrlEncoded => {
                self.structured_url_encoded(input.dictionary, rng)
            }
            MutationKind::StructuredMultipart => self.structured_multipart(input.dictionary, rng),
            MutationKind::StructuredCsv => self.structured_csv(input.dictionary, rng),
            MutationKind::StructuredHttp => self.structured_http(input.dictionary, rng),
            MutationKind::StructuredIni => self.structured_ini(input.dictionary, rng),
            MutationKind::StructuredToml => self.structured_toml(input.dictionary, rng),
            MutationKind::StructuredYaml => self.structured_yaml(input.dictionary, rng),
            MutationKind::StructuredChunked => self.structured_chunked(input.dictionary, rng),
            MutationKind::StructuredRecursive => self.structured_recursive(input.dictionary, rng),
            MutationKind::StructuredGrammar => input.grammar?.generate(self.config.max_len, rng),
            MutationKind::TypedValue => {
                self.typed_value(input.bytes, input.dictionary, input.typed_spans, rng)
            }
            MutationKind::OpSequence => {
                self.operation_sequence(input.bytes, input.operation_sequence?, rng)
            }
            MutationKind::CmpLogSplice => self.cmplog_splice(input.bytes, input.cmplog?, rng),
        }?;

        Some(MutationResult { bytes, kind })
    }

    fn kind_available(&self, input: &MutationInput<'_>, kind: MutationKind) -> bool {
        match kind {
            MutationKind::BitFlip | MutationKind::ByteFlip | MutationKind::Arithmetic => {
                !input.bytes.is_empty()
            }
            MutationKind::Interesting => !interesting_placements(input.bytes).is_empty(),
            MutationKind::Splice => {
                self.config.max_len > 0
                    && !input.bytes.is_empty()
                    && input.peer.is_some_and(|peer| !peer.is_empty())
            }
            MutationKind::DictionaryInsert => {
                !input.dictionary.is_empty() && input.bytes.len() < self.config.max_len
            }
            MutationKind::StructuredRecord => {
                self.config.structured_records
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_RECORD_LEN
            }
            MutationKind::StructuredJson => {
                self.config.structured_json
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_JSON_LEN
            }
            MutationKind::StructuredXml => {
                self.config.structured_xml
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_XML_LEN
            }
            MutationKind::StructuredKeyValue => {
                self.config.structured_key_value
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_KEY_VALUE_LEN
            }
            MutationKind::StructuredUrlEncoded => {
                self.config.structured_url_encoded
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_URL_ENCODED_LEN
            }
            MutationKind::StructuredMultipart => {
                self.config.structured_multipart
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_MULTIPART_LEN
            }
            MutationKind::StructuredCsv => {
                self.config.structured_csv
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_CSV_LEN
            }
            MutationKind::StructuredHttp => {
                self.config.structured_http
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_HTTP_LEN
            }
            MutationKind::StructuredIni => {
                self.config.structured_ini
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_INI_LEN
            }
            MutationKind::StructuredToml => {
                self.config.structured_toml
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_TOML_LEN
            }
            MutationKind::StructuredYaml => {
                self.config.structured_yaml
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_YAML_LEN
            }
            MutationKind::StructuredChunked => {
                self.config.structured_chunked
                    && !input.dictionary.is_empty()
                    && self.config.max_len >= MIN_STRUCTURED_CHUNKED_LEN
            }
            // No dictionary requirement: deep delimiter nesting is valuable on
            // its own (the innermost terminal is an optional embellishment).
            MutationKind::StructuredRecursive => {
                self.config.structured_recursive
                    && self.config.max_len >= MIN_STRUCTURED_RECURSIVE_LEN
            }
            // Available whenever a grammar is supplied; generation ignores the input
            // bytes (it synthesizes a fresh derivation), so no length/dictionary gate.
            MutationKind::StructuredGrammar => input.grammar.is_some() && self.config.max_len > 0,
            MutationKind::TypedValue => !self
                .typed_span_candidates(input.bytes, input.dictionary, input.typed_spans)
                .is_empty(),
            MutationKind::OpSequence => input.operation_sequence.is_some_and(|layout| {
                !self
                    .operation_sequence_actions(input.bytes, layout)
                    .is_empty()
            }),
            MutationKind::CmpLogSplice => input.cmplog.is_some_and(|log| {
                !input.bytes.is_empty() && !cmplog_splice_candidates(log, input.bytes).is_empty()
            }),
        }
    }

    fn operation_sequence(
        &self,
        bytes: &[u8],
        layout: &OperationSequenceLayout,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        let mut actions = self.operation_sequence_actions(bytes, layout);

        while !actions.is_empty() {
            let index = rng.choose_index(actions.len())?;
            let action = actions.swap_remove(index);
            let result = match action {
                OperationSequenceAction::ChangeOp => change_operation_selector(bytes, layout, rng),
                OperationSequenceAction::Insert => {
                    insert_operation_step(bytes, layout, self.config.max_len, rng)
                }
                OperationSequenceAction::Remove => remove_operation_step(bytes, layout, rng),
                OperationSequenceAction::Swap => swap_operation_steps(bytes, layout, rng),
            };
            if let Some(result) = result {
                if result != bytes {
                    return Some(result);
                }
            }
        }

        None
    }

    fn operation_sequence_actions(
        &self,
        bytes: &[u8],
        layout: &OperationSequenceLayout,
    ) -> Vec<OperationSequenceAction> {
        let steps = layout.valid_steps(bytes.len());
        let mut actions = Vec::new();

        if layout.operation_count > 1
            && steps
                .iter()
                .any(|step| alternative_op_indices(bytes, layout, step).next().is_some())
        {
            actions.push(OperationSequenceAction::ChangeOp);
        }

        if count_field_precedes_steps(layout, &steps) {
            if let Some(count) = layout.decoded_step_count(bytes) {
                if count < layout.max_steps
                    && !steps.is_empty()
                    && steps
                        .iter()
                        .any(|step| bytes.len() + step.range.len() <= self.config.max_len)
                    && can_encode_bounded_range(
                        layout.step_count_range.as_ref().unwrap(),
                        layout.min_steps,
                        layout.max_steps,
                        count + 1,
                    )
                {
                    actions.push(OperationSequenceAction::Insert);
                }

                if count > layout.min_steps
                    && !steps.is_empty()
                    && can_encode_bounded_range(
                        layout.step_count_range.as_ref().unwrap(),
                        layout.min_steps,
                        layout.max_steps,
                        count - 1,
                    )
                {
                    actions.push(OperationSequenceAction::Remove);
                }
            }
        }

        if steps.len() >= 2 {
            actions.push(OperationSequenceAction::Swap);
        }

        actions
    }

    fn splice(&self, bytes: &[u8], peer: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
        if bytes.is_empty() || peer.is_empty() || self.config.max_len == 0 {
            return None;
        }

        let current_cut = rng.choose_index(bytes.len())? + 1;
        let peer_cut = rng.choose_index(peer.len())?;
        let mut output = Vec::with_capacity(current_cut + peer.len() - peer_cut);
        output.extend_from_slice(&bytes[..current_cut]);
        output.extend_from_slice(&peer[peer_cut..]);
        output.truncate(self.config.max_len);

        if output.is_empty() {
            None
        } else {
            Some(output)
        }
    }

    fn cmplog_splice(
        &self,
        bytes: &[u8],
        log: &cmplog::CmpLog,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        let mut candidates = cmplog_splice_candidates(log, bytes);
        while !candidates.is_empty() {
            let index = rng.choose_index(candidates.len())?;
            let candidate = candidates.swap_remove(index);
            let new_len = bytes
                .len()
                .checked_sub(candidate.original_len)?
                .checked_add(candidate.replacement.len())?;
            if new_len > self.config.max_len {
                continue;
            }
            let end = candidate.offset.checked_add(candidate.original_len)?;
            if end > bytes.len() {
                continue;
            }
            if bytes[candidate.offset..end] == candidate.replacement[..] {
                continue;
            }
            let mut output = Vec::with_capacity(new_len);
            output.extend_from_slice(&bytes[..candidate.offset]);
            output.extend_from_slice(&candidate.replacement);
            output.extend_from_slice(&bytes[end..]);
            return Some(output);
        }
        None
    }

    fn dictionary_insert(
        &self,
        bytes: &[u8],
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        let remaining = self.config.max_len.checked_sub(bytes.len())?;
        if remaining == 0 {
            return None;
        }

        let token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let token_len = token.len().min(remaining);
        if token_len == 0 {
            return None;
        }

        let insert_at = rng.choose_index(bytes.len() + 1)?;
        let mut output = Vec::with_capacity(bytes.len() + token_len);
        output.extend_from_slice(&bytes[..insert_at]);
        output.extend_from_slice(&token[..token_len]);
        output.extend_from_slice(&bytes[insert_at..]);
        Some(output)
    }

    fn structured_record(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_records
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_RECORD_LEN
        {
            return None;
        }

        let requested_records = 1 + rng.choose_index(MAX_STRUCTURED_RECORDS)?;
        let mut output = vec![0];
        let mut record_count = 0_u8;

        for _ in 0..requested_records {
            if output.len() + MIN_STRUCTURED_RECORD_FIELD_LEN > self.config.max_len {
                break;
            }

            let tag = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let available = self.config.max_len.checked_sub(output.len())?;
            let payload_budget = available.checked_sub(STRUCTURED_RECORD_OVERHEAD)?;
            if payload_budget < 2 {
                break;
            }

            let tag_budget = (payload_budget / 2).clamp(1, u8::MAX as usize);
            let tag_len = tag.len().min(tag_budget);
            let value_budget = payload_budget.checked_sub(tag_len)?;
            let value_len = value.len().min(value_budget).min(u16::MAX as usize);
            if tag_len == 0 || value_len == 0 {
                break;
            }

            output.push(tag_len as u8);
            output.extend_from_slice(&tag[..tag_len]);
            output.extend_from_slice(&(value_len as u16).to_le_bytes());
            output.extend_from_slice(&value[..value_len]);
            record_count = record_count.saturating_add(1);

            if record_count as usize == MAX_STRUCTURED_RECORDS {
                break;
            }
        }

        if record_count == 0 {
            None
        } else {
            output[0] = record_count;
            Some(output)
        }
    }

    /// A binary chunked/length-prefixed shape: a magic header (a mined signature
    /// token) followed by repeated `[u32 length][payload]` chunks. The endianness
    /// of the length is chosen per call so both little-endian (ZIP) and
    /// big-endian (PNG/RIFF/network) framings are exercised. This models the
    /// dominant structure of legacy binary parsers (archive/codec/protocol),
    /// letting the fuzzer get past the magic check and reach chunk-parsing code.
    fn structured_chunked(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if !self.config.structured_chunked
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_CHUNKED_LEN
        {
            return None;
        }

        // Magic header: a mined signature token (the parser's expected magic).
        let magic = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let magic_len = magic
            .len()
            .min(STRUCTURED_CHUNKED_MAX_MAGIC)
            .min(self.config.max_len);
        if magic_len == 0 {
            return None;
        }
        let big_endian = rng.choose_index(2)? == 1;
        let mut output = Vec::with_capacity(self.config.max_len.min(256));
        output.extend_from_slice(&magic[..magic_len]);

        let requested_chunks = 1 + rng.choose_index(MAX_STRUCTURED_CHUNKS)?;
        for _ in 0..requested_chunks {
            // Each chunk needs a 4-byte length plus at least one payload byte.
            if output.len() + STRUCTURED_CHUNK_OVERHEAD + 1 > self.config.max_len {
                break;
            }
            let payload = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let available = self
                .config
                .max_len
                .checked_sub(output.len() + STRUCTURED_CHUNK_OVERHEAD)?;
            let payload_len = payload.len().min(available).min(u32::MAX as usize);
            if payload_len == 0 {
                break;
            }
            let len_bytes = if big_endian {
                (payload_len as u32).to_be_bytes()
            } else {
                (payload_len as u32).to_le_bytes()
            };
            output.extend_from_slice(&len_bytes);
            output.extend_from_slice(&payload[..payload_len]);
        }

        // Require at least one chunk beyond the bare magic.
        if output.len() <= magic_len {
            None
        } else {
            Some(output)
        }
    }

    /// Generate a recursively-nested structure from the delimiter grammar.
    /// Opens a random number of balanced delimiter levels (optionally mixing
    /// the delimiter per level so the parser must track a heterogeneous stack),
    /// drops an optional dictionary terminal at the centre, then closes every
    /// level in reverse. Bounded by `max_len` and a hard depth cap so the
    /// output stays within the corpus size budget while nesting deep enough to
    /// stress recursive-descent parsers (stack exhaustion, recursion limits).
    fn structured_recursive(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if !self.config.structured_recursive || self.config.max_len < MIN_STRUCTURED_RECURSIVE_LEN {
            return None;
        }

        let pairs = STRUCTURED_RECURSIVE_DELIMITERS;
        let (primary_open, primary_close) = pairs[rng.choose_index(pairs.len())?];
        let mixed = rng.choose_index(2)? == 1;

        // Upper bound on depth from the size budget: every level costs at least
        // its open+close bytes. Pick a random depth in 1..=budget.
        let min_unit = primary_open.len() + primary_close.len();
        let depth_budget =
            (self.config.max_len / min_unit).clamp(1, MAX_STRUCTURED_RECURSIVE_DEPTH);
        let depth = 1 + rng.choose_index(depth_budget)?;

        let mut output = Vec::with_capacity((depth * min_unit + 16).min(self.config.max_len));
        // Pending close delimiters, innermost last.
        let mut closes: Vec<&[u8]> = Vec::with_capacity(depth);
        let mut close_reserve = 0usize;
        for _ in 0..depth {
            let (open, close) = if mixed {
                pairs[rng.choose_index(pairs.len())?]
            } else {
                (primary_open, primary_close)
            };
            // Keep room for this level's close plus every already-pending close.
            if output.len() + open.len() + close_reserve + close.len() > self.config.max_len {
                break;
            }
            output.extend_from_slice(open);
            closes.push(close);
            close_reserve += close.len();
        }
        if closes.is_empty() {
            return None;
        }

        // Optional innermost terminal mined from the dictionary, sized to leave
        // room for every pending close and stripped of delimiter bytes so it
        // cannot unbalance the structure.
        if !dictionary.is_empty() {
            if let Some(token) = dictionary.get(rng.choose_index(dictionary.len())?) {
                let room = self
                    .config
                    .max_len
                    .saturating_sub(output.len() + close_reserve);
                let take = token.len().min(room).min(STRUCTURED_RECURSIVE_TERMINAL_MAX);
                output.extend(
                    token[..take]
                        .iter()
                        .copied()
                        .filter(|byte| !is_recursive_delimiter_byte(*byte)),
                );
            }
        }

        while let Some(close) = closes.pop() {
            output.extend_from_slice(close);
        }
        Some(output)
    }

    fn structured_json(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_json
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_JSON_LEN
        {
            return None;
        }

        if rng.choose_index(2)? == 0 {
            self.structured_json_object(dictionary, rng)
                .or_else(|| self.structured_json_array(dictionary, rng))
        } else {
            self.structured_json_array(dictionary, rng)
                .or_else(|| self.structured_json_object(dictionary, rng))
        }
    }

    fn structured_json_object(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if self.config.max_len < MIN_STRUCTURED_JSON_OBJECT_LEN {
            return None;
        }

        let key = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let value = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let escaped_budget = self
            .config
            .max_len
            .checked_sub(MIN_STRUCTURED_JSON_OBJECT_LEN)?;
        let key_budget = escaped_budget / 2;
        let value_budget = escaped_budget - key_budget;
        let key = json_escaped_fragment(key, key_budget);
        let value = json_escaped_fragment(value, value_budget);

        let mut output =
            Vec::with_capacity(MIN_STRUCTURED_JSON_OBJECT_LEN + key.len() + value.len());
        output.extend_from_slice(b"{\"");
        output.extend_from_slice(key.as_bytes());
        output.extend_from_slice(b"\":\"");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\"}");

        if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_json_array(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if self.config.max_len < MIN_STRUCTURED_JSON_LEN {
            return None;
        }

        let requested_items = 1 + rng.choose_index(MAX_STRUCTURED_JSON_ITEMS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(32));
        output.push(b'[');

        for item_count in 0..requested_items {
            let available = self
                .config
                .max_len
                .checked_sub(output.len())?
                .checked_sub(1)?;
            let item_overhead = if item_count == 0 { 2 } else { 3 };
            if available < item_overhead {
                break;
            }

            let token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let token = json_escaped_fragment(token, available - item_overhead);
            if item_count > 0 {
                output.push(b',');
            }
            output.push(b'"');
            output.extend_from_slice(token.as_bytes());
            output.push(b'"');
        }

        output.push(b']');
        Some(output)
    }

    fn structured_xml(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_xml
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_XML_LEN
        {
            return None;
        }

        let tag_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let max_tag_len = self
            .config
            .max_len
            .checked_sub(6)
            .map(|budget| (budget / 2).clamp(1, 32))?;
        let tag = xml_name_fragment(tag_token, max_tag_len)?;
        let value_budget = self.config.max_len.checked_sub(5 + (2 * tag.len()))?;
        if value_budget == 0 {
            return None;
        }
        let value = xml_text_fragment(value_token, value_budget)?;

        let mut output = Vec::with_capacity(5 + (2 * tag.len()) + value.len());
        output.push(b'<');
        output.extend_from_slice(&tag);
        output.push(b'>');
        output.extend_from_slice(&value);
        output.extend_from_slice(b"</");
        output.extend_from_slice(&tag);
        output.push(b'>');

        if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_key_value(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if !self.config.structured_key_value
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_KEY_VALUE_LEN
        {
            return None;
        }

        let requested_pairs = 1 + rng.choose_index(MAX_STRUCTURED_KEY_VALUE_PAIRS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(64));
        let mut pair_count = 0_usize;

        for _ in 0..requested_pairs {
            let available = self.config.max_len.checked_sub(output.len())?;
            if available < MIN_STRUCTURED_KEY_VALUE_LEN {
                break;
            }

            let key_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = available.checked_sub(STRUCTURED_KEY_VALUE_OVERHEAD)?;
            let key_budget = (payload_budget / 2).max(1);
            let key = key_value_fragment(key_token, key_budget, KeyValueFragmentRole::Key)?;
            let value_budget = payload_budget.checked_sub(key.len())?;
            if value_budget == 0 {
                break;
            }
            let value = key_value_fragment(value_token, value_budget, KeyValueFragmentRole::Value)?;
            let separator = if rng.choose_index(2)? == 0 {
                b'='
            } else {
                b':'
            };

            output.extend_from_slice(&key);
            output.push(separator);
            output.extend_from_slice(&value);
            output.push(b'\n');
            pair_count += 1;

            if pair_count == MAX_STRUCTURED_KEY_VALUE_PAIRS {
                break;
            }
        }

        if pair_count == 0 {
            None
        } else {
            Some(output)
        }
    }

    fn structured_url_encoded(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if !self.config.structured_url_encoded
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_URL_ENCODED_LEN
        {
            return None;
        }

        let requested_pairs = 1 + rng.choose_index(MAX_STRUCTURED_URL_ENCODED_PAIRS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(64));
        let mut pair_count = 0_usize;

        for _ in 0..requested_pairs {
            let available = self.config.max_len.checked_sub(output.len())?;
            let pair_overhead = if pair_count == 0 {
                STRUCTURED_URL_ENCODED_OVERHEAD
            } else {
                STRUCTURED_URL_ENCODED_OVERHEAD + 1
            };
            if available < pair_overhead + 2 {
                break;
            }

            let key_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = available.checked_sub(pair_overhead)?;
            let key_budget = (payload_budget / 2).max(1);
            let key = url_encoded_fragment(key_token, key_budget)?;
            let value_budget = payload_budget.checked_sub(key.len())?;
            if value_budget == 0 {
                break;
            }
            let value = url_encoded_fragment(value_token, value_budget)?;

            if pair_count > 0 {
                output.push(b'&');
            }
            output.extend_from_slice(&key);
            output.push(b'=');
            output.extend_from_slice(&value);
            pair_count += 1;

            if pair_count == MAX_STRUCTURED_URL_ENCODED_PAIRS {
                break;
            }
        }

        if pair_count == 0 {
            None
        } else {
            Some(output)
        }
    }

    fn structured_multipart(
        &self,
        dictionary: &Dictionary,
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        if !self.config.structured_multipart
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_MULTIPART_LEN
        {
            return None;
        }

        let requested_parts = 1 + rng.choose_index(MAX_STRUCTURED_MULTIPART_PARTS)?;
        let boundary = b"gf";
        let delimiter_len = 2 + boundary.len() + 2;
        let closing_len = 2 + boundary.len() + 4;
        let header_prefix = b"Content-Disposition: form-data; name=\"";
        let header_suffix = b"\"\r\n\r\n";
        let mut output = Vec::with_capacity(self.config.max_len.min(96));
        let mut part_count = 0_usize;

        for _ in 0..requested_parts {
            let remaining = self
                .config
                .max_len
                .checked_sub(output.len())?
                .checked_sub(closing_len)?;
            let part_overhead =
                delimiter_len + header_prefix.len() + header_suffix.len() + b"\r\n".len();
            if remaining < part_overhead + 2 {
                break;
            }

            let name_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = remaining.checked_sub(part_overhead)?;
            let name_budget = 1;
            let name = multipart_name_fragment(name_token, name_budget)?;
            let value_budget = payload_budget.checked_sub(name.len())?;
            if value_budget == 0 {
                break;
            }
            let value = multipart_value_fragment(value_token, value_budget)?;

            output.extend_from_slice(b"--");
            output.extend_from_slice(boundary);
            output.extend_from_slice(b"\r\n");
            output.extend_from_slice(header_prefix);
            output.extend_from_slice(&name);
            output.extend_from_slice(header_suffix);
            output.extend_from_slice(&value);
            output.extend_from_slice(b"\r\n");
            part_count += 1;

            if part_count == MAX_STRUCTURED_MULTIPART_PARTS {
                break;
            }
        }

        if part_count == 0 {
            return None;
        }

        output.extend_from_slice(b"--");
        output.extend_from_slice(boundary);
        output.extend_from_slice(b"--\r\n");
        if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_csv(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_csv
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_CSV_LEN
        {
            return None;
        }

        let requested_rows = 1 + rng.choose_index(MAX_STRUCTURED_CSV_ROWS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(64));
        let mut row_count = 0_usize;

        for _ in 0..requested_rows {
            let row_prefix = usize::from(!output.is_empty());
            if output.len() + row_prefix >= self.config.max_len {
                break;
            }
            let row_budget = self.config.max_len - output.len() - row_prefix;
            let requested_cols = 1 + rng.choose_index(MAX_STRUCTURED_CSV_COLUMNS)?;
            let row = structured_csv_row(dictionary, rng, row_budget, requested_cols)?;
            if row.is_empty() {
                break;
            }
            if !output.is_empty() {
                output.push(b'\n');
            }
            output.extend_from_slice(&row);
            row_count += 1;

            if row_count == MAX_STRUCTURED_CSV_ROWS {
                break;
            }
        }

        if row_count == 0 {
            None
        } else {
            Some(output)
        }
    }

    fn structured_http(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_http
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_HTTP_LEN
        {
            return None;
        }

        let method = HTTP_METHODS[rng.choose_index(HTTP_METHODS.len())?];
        let path_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let host_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let body_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let fixed_len =
            method.len() + b" /".len() + b" HTTP/1.1\r\nHost: ".len() + b"\r\n\r\n".len();
        let payload_budget = self.config.max_len.checked_sub(fixed_len)?;
        let path_budget = (payload_budget / 3).clamp(1, 32);
        let path = http_path_fragment(path_token, path_budget)?;
        let remaining = payload_budget.checked_sub(path.len())?;
        if remaining == 0 {
            return None;
        }
        let host_budget = (remaining / 2).max(1);
        let host = http_header_value_fragment(host_token, host_budget)?;
        let body_budget = remaining.checked_sub(host.len())?;
        let body = http_body_fragment(body_token, body_budget);

        let mut output = Vec::with_capacity(fixed_len + path.len() + host.len() + body.len());
        output.extend_from_slice(method);
        output.extend_from_slice(b" /");
        output.extend_from_slice(&path);
        output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        output.extend_from_slice(&host);
        output.extend_from_slice(b"\r\n\r\n");
        output.extend_from_slice(&body);

        if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_ini(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_ini
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_INI_LEN
        {
            return None;
        }

        let requested_sections = 1 + rng.choose_index(MAX_STRUCTURED_INI_SECTIONS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(96));
        let mut section_count = 0_usize;

        for _ in 0..requested_sections {
            let available = self.config.max_len.checked_sub(output.len())?;
            if available < MIN_STRUCTURED_INI_LEN {
                break;
            }

            let section_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let key_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = available.checked_sub(STRUCTURED_INI_OVERHEAD)?;
            let section_budget = (payload_budget / 3).clamp(1, 32);
            let section = ini_name_fragment(section_token, section_budget)?;
            let remaining = payload_budget.checked_sub(section.len())?;
            let key_budget = (remaining / 2).max(1);
            let key = ini_name_fragment(key_token, key_budget)?;
            let value_budget = remaining.checked_sub(key.len())?;
            if value_budget == 0 {
                break;
            }
            let value = ini_value_fragment(value_token, value_budget)?;

            output.push(b'[');
            output.extend_from_slice(&section);
            output.extend_from_slice(b"]\n");
            output.extend_from_slice(&key);
            output.push(b'=');
            output.extend_from_slice(&value);
            output.push(b'\n');
            section_count += 1;

            if section_count == MAX_STRUCTURED_INI_SECTIONS {
                break;
            }
        }

        if section_count == 0 {
            None
        } else if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_toml(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_toml
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_TOML_LEN
        {
            return None;
        }

        let requested_tables = 1 + rng.choose_index(MAX_STRUCTURED_TOML_TABLES)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(96));
        let mut table_count = 0_usize;

        for _ in 0..requested_tables {
            let available = self.config.max_len.checked_sub(output.len())?;
            if available < MIN_STRUCTURED_TOML_LEN {
                break;
            }

            let table_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let key_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = available.checked_sub(STRUCTURED_TOML_OVERHEAD)?;
            let table_budget = (payload_budget / 3).clamp(1, 32);
            let table = toml_bare_key_fragment(table_token, table_budget)?;
            let remaining = payload_budget.checked_sub(table.len())?;
            let key_budget = (remaining / 2).max(1);
            let key = toml_bare_key_fragment(key_token, key_budget)?;
            let value_budget = remaining.checked_sub(key.len())?;
            if value_budget < 2 {
                break;
            }
            let value = toml_basic_string_fragment(value_token, value_budget)?;

            output.push(b'[');
            output.extend_from_slice(&table);
            output.extend_from_slice(b"]\n");
            output.extend_from_slice(&key);
            output.extend_from_slice(b" = ");
            output.extend_from_slice(&value);
            output.push(b'\n');
            table_count += 1;

            if table_count == MAX_STRUCTURED_TOML_TABLES {
                break;
            }
        }

        if table_count == 0 {
            None
        } else if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn structured_yaml(&self, dictionary: &Dictionary, rng: &mut MutationRng) -> Option<Vec<u8>> {
        if !self.config.structured_yaml
            || dictionary.is_empty()
            || self.config.max_len < MIN_STRUCTURED_YAML_LEN
        {
            return None;
        }

        let requested_documents = 1 + rng.choose_index(MAX_STRUCTURED_YAML_DOCUMENTS)?;
        let mut output = Vec::with_capacity(self.config.max_len.min(96));
        let mut document_count = 0_usize;

        for _ in 0..requested_documents {
            let available = self.config.max_len.checked_sub(output.len())?;
            if available < MIN_STRUCTURED_YAML_LEN {
                break;
            }

            let section_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let key_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let value_token = dictionary.get(rng.choose_index(dictionary.len())?)?;
            let payload_budget = available.checked_sub(STRUCTURED_YAML_OVERHEAD)?;
            let section_budget = (payload_budget / 3).clamp(1, 32);
            let section = toml_bare_key_fragment(section_token, section_budget)?;
            let remaining = payload_budget.checked_sub(section.len())?;
            let key_budget = (remaining / 2).max(1);
            let key = toml_bare_key_fragment(key_token, key_budget)?;
            let value_budget = remaining.checked_sub(key.len())?;
            if value_budget < 2 {
                break;
            }
            let value = toml_basic_string_fragment(value_token, value_budget)?;

            output.extend_from_slice(&section);
            output.extend_from_slice(b":\n  ");
            output.extend_from_slice(&key);
            output.extend_from_slice(b": ");
            output.extend_from_slice(&value);
            output.push(b'\n');
            document_count += 1;

            if document_count == MAX_STRUCTURED_YAML_DOCUMENTS {
                break;
            }
        }

        if document_count == 0 {
            None
        } else if output.len() <= self.config.max_len {
            Some(output)
        } else {
            None
        }
    }

    fn typed_value(
        &self,
        bytes: &[u8],
        dictionary: &Dictionary,
        typed_spans: &[TypedSpan],
        rng: &mut MutationRng,
    ) -> Option<Vec<u8>> {
        let span_candidates = self.typed_span_candidates(bytes, dictionary, typed_spans);
        let (span, candidates) = span_candidates.get(rng.choose_index(span_candidates.len())?)?;
        let candidate = candidates.get(rng.choose_index(candidates.len())?)?;

        let mut output =
            Vec::with_capacity(bytes.len() - (span.range.end - span.range.start) + candidate.len());
        output.extend_from_slice(&bytes[..span.range.start]);
        output.extend_from_slice(candidate);
        output.extend_from_slice(&bytes[span.range.end..]);
        Some(output)
    }

    fn typed_span_candidates<'a>(
        &self,
        bytes: &'a [u8],
        dictionary: &Dictionary,
        typed_spans: &'a [TypedSpan],
    ) -> Vec<(&'a TypedSpan, Vec<Vec<u8>>)> {
        typed_spans
            .iter()
            .filter_map(|span| {
                if !span.valid_for(bytes.len()) {
                    return None;
                }

                let current = &bytes[span.range.clone()];
                let candidates: Vec<Vec<u8>> = typed_candidates(span.kind, dictionary)
                    .into_iter()
                    .filter(|candidate| candidate.as_slice() != current)
                    .filter(|candidate| {
                        bytes.len() - current.len() + candidate.len() <= self.config.max_len
                    })
                    .collect();

                if candidates.is_empty() {
                    None
                } else {
                    Some((span, candidates))
                }
            })
            .collect()
    }
}

const MAX_STRUCTURED_RECORDS: usize = 4;
const STRUCTURED_RECORD_OVERHEAD: usize = 3;
/// Chunked binary shape: max chunks, per-chunk length-field width, max magic
/// header length, and the minimum total length to bother emitting one.
const MAX_STRUCTURED_CHUNKS: usize = 6;
const STRUCTURED_CHUNK_OVERHEAD: usize = 4;
const STRUCTURED_CHUNKED_MAX_MAGIC: usize = 16;
const MIN_STRUCTURED_CHUNKED_LEN: usize = 6;
/// Smallest output that fits one nested delimiter pair plus a byte of slack.
const MIN_STRUCTURED_RECURSIVE_LEN: usize = 2;
/// Hard cap on nesting depth so a single mutation cannot expand without bound;
/// still far past the recursion limits of typical recursive-descent parsers.
const MAX_STRUCTURED_RECURSIVE_DEPTH: usize = 512;
/// Cap on the innermost dictionary terminal copied into the nest.
const STRUCTURED_RECURSIVE_TERMINAL_MAX: usize = 32;
/// Balanced (open, close) delimiter pairs the recursive grammar nests with.
const STRUCTURED_RECURSIVE_DELIMITERS: &[(&[u8], &[u8])] =
    &[(b"(", b")"), (b"[", b"]"), (b"{", b"}"), (b"<e>", b"</e>")];

/// Bytes that open or close a recursive-grammar delimiter; stripped from mined
/// terminals so an embedded token cannot unbalance the generated structure.
fn is_recursive_delimiter_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b'/'
    )
}
const MIN_STRUCTURED_RECORD_FIELD_LEN: usize = STRUCTURED_RECORD_OVERHEAD + 2;
const MIN_STRUCTURED_RECORD_LEN: usize = 1 + MIN_STRUCTURED_RECORD_FIELD_LEN;
const MAX_STRUCTURED_JSON_ITEMS: usize = 3;
const MIN_STRUCTURED_JSON_LEN: usize = 2;
const MIN_STRUCTURED_JSON_OBJECT_LEN: usize = 7;
const MIN_STRUCTURED_XML_LEN: usize = 8;
const MAX_STRUCTURED_KEY_VALUE_PAIRS: usize = 4;
const STRUCTURED_KEY_VALUE_OVERHEAD: usize = 2;
const MIN_STRUCTURED_KEY_VALUE_LEN: usize = 4;
const MAX_STRUCTURED_URL_ENCODED_PAIRS: usize = 4;
const STRUCTURED_URL_ENCODED_OVERHEAD: usize = 1;
const MIN_STRUCTURED_URL_ENCODED_LEN: usize = 3;
const MAX_STRUCTURED_MULTIPART_PARTS: usize = 3;
const MIN_STRUCTURED_MULTIPART_LEN: usize = 61;
const MAX_STRUCTURED_CSV_ROWS: usize = 4;
const MAX_STRUCTURED_CSV_COLUMNS: usize = 3;
const MIN_STRUCTURED_CSV_LEN: usize = 1;
const HTTP_METHODS: [&[u8]; 4] = [b"GET", b"POST", b"PUT", b"DELETE"];
const MIN_STRUCTURED_HTTP_LEN: usize = 28;
const MAX_STRUCTURED_INI_SECTIONS: usize = 3;
const STRUCTURED_INI_OVERHEAD: usize = 5; // '[' + "]\n" + '=' + '\n'
const MIN_STRUCTURED_INI_LEN: usize = STRUCTURED_INI_OVERHEAD + 3;
const MAX_STRUCTURED_TOML_TABLES: usize = 3;
const STRUCTURED_TOML_OVERHEAD: usize = 8; // '[' + "]\n" + " = " + quoted value + '\n'
const MIN_STRUCTURED_TOML_LEN: usize = STRUCTURED_TOML_OVERHEAD + 3;
const MAX_STRUCTURED_YAML_DOCUMENTS: usize = 3;
const STRUCTURED_YAML_OVERHEAD: usize = 9; // ":\n  " + ": " + quoted value + '\n'
const MIN_STRUCTURED_YAML_LEN: usize = STRUCTURED_YAML_OVERHEAD + 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationSequenceAction {
    ChangeOp,
    Insert,
    Remove,
    Swap,
}

fn change_operation_selector(
    bytes: &[u8],
    layout: &OperationSequenceLayout,
    rng: &mut MutationRng,
) -> Option<Vec<u8>> {
    let steps: Vec<&OperationStepSpan> = layout
        .valid_steps(bytes.len())
        .into_iter()
        .filter(|step| alternative_op_indices(bytes, layout, step).next().is_some())
        .collect();
    let step = steps.get(rng.choose_index(steps.len())?)?;
    let alternatives: Vec<usize> = alternative_op_indices(bytes, layout, step).collect();
    let op_index = *alternatives.get(rng.choose_index(alternatives.len())?)?;

    let mut output = bytes.to_vec();
    encode_bounded_range(
        &mut output,
        &step.op_index_range,
        0,
        layout.operation_count.saturating_sub(1),
        op_index,
    )?;
    Some(output)
}

fn insert_operation_step(
    bytes: &[u8],
    layout: &OperationSequenceLayout,
    max_len: usize,
    rng: &mut MutationRng,
) -> Option<Vec<u8>> {
    let steps: Vec<&OperationStepSpan> = layout
        .valid_steps(bytes.len())
        .into_iter()
        .filter(|step| bytes.len() + step.range.len() <= max_len)
        .collect();
    let count = layout.decoded_step_count(bytes)?;
    if count >= layout.max_steps || steps.is_empty() || !count_field_precedes_steps(layout, &steps)
    {
        return None;
    }

    let source = steps.get(rng.choose_index(steps.len())?)?;
    let insert_slot = rng.choose_index(steps.len() + 1)?;
    let insert_at = if insert_slot == steps.len() {
        steps.last()?.range.end
    } else {
        steps[insert_slot].range.start
    };

    let mut output = Vec::with_capacity(bytes.len() + source.range.len());
    output.extend_from_slice(&bytes[..insert_at]);
    output.extend_from_slice(&bytes[source.range.clone()]);
    output.extend_from_slice(&bytes[insert_at..]);
    encode_bounded_range(
        &mut output,
        layout.step_count_range.as_ref()?,
        layout.min_steps,
        layout.max_steps,
        count + 1,
    )?;
    Some(output)
}

fn remove_operation_step(
    bytes: &[u8],
    layout: &OperationSequenceLayout,
    rng: &mut MutationRng,
) -> Option<Vec<u8>> {
    let steps = layout.valid_steps(bytes.len());
    let count = layout.decoded_step_count(bytes)?;
    if count <= layout.min_steps || steps.is_empty() || !count_field_precedes_steps(layout, &steps)
    {
        return None;
    }

    let step = steps.get(rng.choose_index(steps.len())?)?;
    let mut output = Vec::with_capacity(bytes.len() - step.range.len());
    output.extend_from_slice(&bytes[..step.range.start]);
    output.extend_from_slice(&bytes[step.range.end..]);
    encode_bounded_range(
        &mut output,
        layout.step_count_range.as_ref()?,
        layout.min_steps,
        layout.max_steps,
        count - 1,
    )?;
    Some(output)
}

fn swap_operation_steps(
    bytes: &[u8],
    layout: &OperationSequenceLayout,
    rng: &mut MutationRng,
) -> Option<Vec<u8>> {
    let steps = layout.valid_steps(bytes.len());
    if steps.len() < 2 {
        return None;
    }

    let left_index = rng.choose_index(steps.len())?;
    let mut right_index = rng.choose_index(steps.len() - 1)?;
    if right_index >= left_index {
        right_index += 1;
    }

    let (left, right) = if left_index < right_index {
        (steps[left_index], steps[right_index])
    } else {
        (steps[right_index], steps[left_index])
    };

    let mut output = Vec::with_capacity(bytes.len());
    output.extend_from_slice(&bytes[..left.range.start]);
    output.extend_from_slice(&bytes[right.range.clone()]);
    output.extend_from_slice(&bytes[left.range.end..right.range.start]);
    output.extend_from_slice(&bytes[left.range.clone()]);
    output.extend_from_slice(&bytes[right.range.end..]);
    Some(output)
}

fn alternative_op_indices<'a>(
    bytes: &'a [u8],
    layout: &'a OperationSequenceLayout,
    step: &'a OperationStepSpan,
) -> impl Iterator<Item = usize> + 'a {
    let current = decode_bounded_range(
        bytes,
        &step.op_index_range,
        0,
        layout.operation_count.saturating_sub(1),
    );

    (0..layout.operation_count)
        .filter(move |op_index| Some(*op_index) != current)
        .filter(move |op_index| {
            can_encode_bounded_range(
                &step.op_index_range,
                0,
                layout.operation_count.saturating_sub(1),
                *op_index,
            )
        })
}

fn count_field_precedes_steps(
    layout: &OperationSequenceLayout,
    steps: &[&OperationStepSpan],
) -> bool {
    let Some(range) = layout.step_count_range.as_ref() else {
        return false;
    };

    range.start < range.end
        && layout.min_steps <= layout.max_steps
        && steps.iter().all(|step| range.end <= step.range.start)
}

fn decode_bounded_range(
    bytes: &[u8],
    range: &Range<usize>,
    min: usize,
    max: usize,
) -> Option<usize> {
    if min > max || range.start >= range.end || range.end > bytes.len() {
        return None;
    }

    if max <= min {
        return Some(min);
    }

    let selector = bytes[range.start];
    if selector % 4 == 0 {
        return Some(selector_bounded_value(selector, min, max));
    }

    if range.len() < 5 {
        return None;
    }

    let raw = u32::from_le_bytes(bytes[range.start + 1..range.start + 5].try_into().ok()?);
    Some(min + raw as usize % (max - min + 1))
}

fn encode_bounded_range(
    bytes: &mut [u8],
    range: &Range<usize>,
    min: usize,
    max: usize,
    value: usize,
) -> Option<()> {
    if value < min || value > max || range.start >= range.end || range.end > bytes.len() {
        return None;
    }

    if range.len() >= 5 {
        bytes[range.start] = 1;
        bytes[range.start + 1..range.start + 5]
            .copy_from_slice(&((value - min) as u32).to_le_bytes());
        return Some(());
    }

    bytes[range.start] = one_byte_selector_for_value(min, max, value)?;
    Some(())
}

fn can_encode_bounded_range(range: &Range<usize>, min: usize, max: usize, value: usize) -> bool {
    value >= min
        && value <= max
        && range.start < range.end
        && (range.len() >= 5 || one_byte_selector_for_value(min, max, value).is_some())
}

fn one_byte_selector_for_value(min: usize, max: usize, value: usize) -> Option<u8> {
    (0..=u8::MAX)
        .find(|selector| selector % 4 == 0 && selector_bounded_value(*selector, min, max) == value)
}

fn selector_bounded_value(selector: u8, min: usize, max: usize) -> usize {
    let raw = match selector % 6 {
        0 => min,
        1 => min.saturating_add(1),
        2 => max.saturating_sub(1),
        3 => max,
        4 => 0,
        _ => usize::MAX,
    };

    raw.clamp(min, max)
}

fn bit_flip(bytes: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
    let index = rng.choose_index(bytes.len())?;
    let bit = rng.choose_index(8)? as u8;
    let mut output = bytes.to_vec();
    output[index] ^= 1_u8 << bit;
    Some(output)
}

fn byte_flip(bytes: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
    let index = rng.choose_index(bytes.len())?;
    let mut replacement = rng.next_u8();
    if replacement == bytes[index] {
        replacement = replacement.wrapping_add(1);
    }

    let mut output = bytes.to_vec();
    output[index] = replacement;
    Some(output)
}

fn arithmetic(bytes: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
    let index = rng.choose_index(bytes.len())?;
    let mut output = bytes.to_vec();
    output[index] = output[index].wrapping_add(1);
    Some(output)
}

fn interesting(bytes: &[u8], rng: &mut MutationRng) -> Option<Vec<u8>> {
    let placements = interesting_placements(bytes);
    let (start, candidate) = placements.get(rng.choose_index(placements.len())?)?;

    let mut output = bytes.to_vec();
    output[*start..*start + candidate.len()].copy_from_slice(candidate);
    Some(output)
}

fn interesting_placements(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
    interesting_candidates(bytes.len())
        .into_iter()
        .flat_map(|candidate| {
            (0..=bytes.len() - candidate.len()).filter_map(move |start| {
                if candidate.as_slice() == &bytes[start..start + candidate.len()] {
                    None
                } else {
                    Some((start, candidate.clone()))
                }
            })
        })
        .collect()
}

/// Filter the cmplog's splice candidates against the current input
/// to keep only those that (a) sit in-bounds, (b) actually change a
/// byte, and (c) the operand was found in the input. Used both by
/// `kind_available` and `cmplog_splice` so the availability gate and
/// the mutation see the same set.
fn cmplog_splice_candidates(log: &cmplog::CmpLog, bytes: &[u8]) -> Vec<cmplog::SpliceCandidate> {
    log.splice_candidates(bytes)
        .into_iter()
        .filter(|candidate| {
            let Some(end) = candidate.offset.checked_add(candidate.original_len) else {
                return false;
            };
            if end > bytes.len() {
                return false;
            }
            bytes[candidate.offset..end] != candidate.replacement[..]
        })
        .collect()
}

fn json_escaped_fragment(token: &[u8], max_len: usize) -> String {
    let mut escaped = String::new();
    for byte in token {
        let fragment = match *byte {
            b'"' => "\\\"".to_owned(),
            b'\\' => "\\\\".to_owned(),
            b'\n' => "\\n".to_owned(),
            b'\r' => "\\r".to_owned(),
            b'\t' => "\\t".to_owned(),
            0x08 => "\\b".to_owned(),
            0x0c => "\\f".to_owned(),
            0x20..=0x7e => (*byte as char).to_string(),
            _ => format!("\\u00{byte:02x}"),
        };
        if escaped.len() + fragment.len() > max_len {
            break;
        }
        escaped.push_str(&fragment);
    }
    escaped
}

fn xml_name_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        let is_first = output.is_empty();
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => output.push(*byte),
            b'0'..=b'9' | b'-' | b'.' if !is_first => output.push(*byte),
            b' ' | b'\t' if !is_first => output.push(b'_'),
            _ if is_first => output.push(b'x'),
            _ => output.push(b'_'),
        }
    }

    if output.is_empty() {
        output.push(b'x');
    }

    Some(output)
}

fn xml_text_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        let fragment: &[u8] = match *byte {
            b'&' => b"&amp;",
            b'<' => b"&lt;",
            b'>' => b"&gt;",
            b'"' => b"&quot;",
            b'\'' => b"&apos;",
            b'\n' | b'\r' | b'\t' => b" ",
            0x20..=0x7e => std::slice::from_ref(byte),
            _ => b"_",
        };
        if output.len() + fragment.len() > max_len {
            break;
        }
        output.extend_from_slice(fragment);
    }

    if output.is_empty() {
        output.push(b'x');
    }

    Some(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyValueFragmentRole {
    Key,
    Value,
}

fn key_value_fragment(token: &[u8], max_len: usize, role: KeyValueFragmentRole) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match (*byte, role) {
            (b'\n' | b'\r', _) => push_key_value_byte(&mut output, b'_', max_len),
            (b'=' | b':', KeyValueFragmentRole::Key) => {
                push_key_value_byte(&mut output, b'_', max_len)
            }
            (b' ' | b'\t', KeyValueFragmentRole::Key) => {
                push_key_value_byte(&mut output, b'_', max_len)
            }
            (0x21..=0x7e, KeyValueFragmentRole::Key)
            | (0x20..=0x7e, KeyValueFragmentRole::Value) => {
                push_key_value_byte(&mut output, *byte, max_len)
            }
            _ => push_percent_encoded(&mut output, *byte, max_len),
        }
    }

    if output.is_empty() {
        output.push(match role {
            KeyValueFragmentRole::Key => b'k',
            KeyValueFragmentRole::Value => b'v',
        });
    }

    Some(output)
}

fn url_encoded_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                push_key_value_byte(&mut output, *byte, max_len)
            }
            b' ' | b'\t' => push_key_value_byte(&mut output, b'+', max_len),
            _ => push_percent_encoded(&mut output, *byte, max_len),
        }
    }

    if output.is_empty() {
        output.push(b'x');
    }

    Some(output)
}

fn multipart_name_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'~' => {
                push_key_value_byte(&mut output, *byte, max_len)
            }
            b' ' | b'\t' => push_key_value_byte(&mut output, b'_', max_len),
            _ => push_percent_encoded(&mut output, *byte, max_len),
        }
    }

    if output.is_empty() {
        output.push(b'f');
    }

    Some(output)
}

fn multipart_value_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    key_value_fragment(token, max_len, KeyValueFragmentRole::Value)
}

fn structured_csv_row(
    dictionary: &Dictionary,
    rng: &mut MutationRng,
    max_len: usize,
    requested_cols: usize,
) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::with_capacity(max_len.min(32));
    let mut col_count = 0_usize;
    for _ in 0..requested_cols {
        let prefix = usize::from(col_count > 0);
        if output.len() + prefix >= max_len {
            break;
        }
        let cell_budget = max_len - output.len() - prefix;
        let token = dictionary.get(rng.choose_index(dictionary.len())?)?;
        let cell = csv_cell_fragment(token, cell_budget)?;
        if cell.is_empty() {
            break;
        }
        if col_count > 0 {
            output.push(b',');
        }
        output.extend_from_slice(&cell);
        col_count += 1;

        if col_count == MAX_STRUCTURED_CSV_COLUMNS {
            break;
        }
    }

    if col_count == 0 {
        None
    } else {
        Some(output)
    }
}

fn csv_cell_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let needs_quotes = token
        .iter()
        .any(|byte| matches!(*byte, b',' | b'"' | b'\n' | b'\r'));
    if needs_quotes && max_len >= 3 {
        let mut output = Vec::with_capacity(max_len.min(token.len() + 2));
        output.push(b'"');
        for byte in token {
            let fragment: &[u8] = match *byte {
                b'"' => b"\"\"",
                b'\n' | b'\r' => b" ",
                0x20..=0x7e => std::slice::from_ref(byte),
                _ => b"_",
            };
            if output.len() + fragment.len() + 1 > max_len {
                break;
            }
            output.extend_from_slice(fragment);
        }
        if output.len() == 1 && output.len() + 2 <= max_len {
            output.push(b'x');
        }
        output.push(b'"');
        return Some(output);
    }

    let mut output = Vec::with_capacity(max_len.min(token.len()));
    for byte in token {
        if output.len() >= max_len {
            break;
        }
        match *byte {
            b',' | b'"' | b'\n' | b'\r' | b'\t' => output.push(b'_'),
            0x20..=0x7e => output.push(*byte),
            _ => output.push(b'_'),
        }
    }
    if output.is_empty() {
        output.push(b'x');
    }
    Some(output)
}

fn http_path_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    url_encoded_fragment(token, max_len)
}

fn http_header_value_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'\r' | b'\n' | b'\t' => output.push(b'_'),
            0x20..=0x7e => output.push(*byte),
            _ => output.push(b'_'),
        }
    }

    if output.is_empty() {
        output.push(b'h');
    }
    Some(output)
}

fn http_body_fragment(token: &[u8], max_len: usize) -> Vec<u8> {
    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'\r' | b'\n' => output.push(b' '),
            0x20..=0x7e => output.push(*byte),
            _ => output.push(b'_'),
        }
    }
    output
}

fn ini_name_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => output.push(*byte),
            b' ' | b'\t' => output.push(b'_'),
            _ if output.is_empty() => output.push(b'x'),
            _ => output.push(b'_'),
        }
    }

    if output.is_empty() {
        output.push(b'x');
    }
    Some(output)
}

fn ini_value_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    key_value_fragment(token, max_len, KeyValueFragmentRole::Value)
}

fn toml_bare_key_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len == 0 {
        return None;
    }

    let mut output = Vec::new();
    for byte in token {
        if output.len() >= max_len {
            break;
        }

        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' => output.push(*byte),
            b' ' | b'\t' | b'.' => output.push(b'_'),
            _ if output.is_empty() => output.push(b'x'),
            _ => output.push(b'_'),
        }
    }

    if output.is_empty() {
        output.push(b'x');
    }
    Some(output)
}

fn toml_basic_string_fragment(token: &[u8], max_len: usize) -> Option<Vec<u8>> {
    if max_len < 2 {
        return None;
    }

    let mut output = Vec::with_capacity(max_len.min(token.len().saturating_add(2)));
    output.push(b'"');
    for byte in token {
        if output.len() + 1 >= max_len {
            break;
        }

        match *byte {
            b'"' | b'\\' if output.len() + 3 <= max_len => {
                output.push(b'\\');
                output.push(*byte);
            }
            b'\n' if output.len() + 3 <= max_len => {
                output.push(b'\\');
                output.push(b'n');
            }
            b'\r' if output.len() + 3 <= max_len => {
                output.push(b'\\');
                output.push(b'r');
            }
            b'\t' if output.len() + 3 <= max_len => {
                output.push(b'\\');
                output.push(b't');
            }
            0x20..=0x7e => output.push(*byte),
            _ => output.push(b'_'),
        }
    }
    if output.len() == 1 && output.len() + 2 <= max_len {
        output.push(b'x');
    }
    output.push(b'"');
    Some(output)
}

fn push_key_value_byte(output: &mut Vec<u8>, byte: u8, max_len: usize) {
    if output.len() < max_len {
        output.push(byte);
    }
}

fn push_percent_encoded(output: &mut Vec<u8>, byte: u8, max_len: usize) {
    if output.len() + 3 > max_len {
        return;
    }

    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push(b'%');
    output.push(HEX[(byte >> 4) as usize]);
    output.push(HEX[(byte & 0x0f) as usize]);
}

fn interesting_candidates(max_len: usize) -> Vec<Vec<u8>> {
    let mut candidates = vec![vec![0], vec![1], vec![0xff], vec![0x7f], vec![0x80]];
    candidates.extend(
        [
            i16::MIN.to_le_bytes().to_vec(),
            i16::MAX.to_le_bytes().to_vec(),
            i32::MIN.to_le_bytes().to_vec(),
            i32::MAX.to_le_bytes().to_vec(),
        ]
        .into_iter()
        .filter(|candidate| candidate.len() <= max_len),
    );
    candidates
        .into_iter()
        .filter(|candidate| candidate.len() <= max_len)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::Dictionary;
    use crate::rng::MutationRng;
    use crate::typed::{TypedSpan, TypedValueKind};

    fn suite() -> MutatorSuite {
        MutatorSuite::new(MutatorConfig {
            max_len: 64,
            ..MutatorConfig::default()
        })
    }

    #[test]
    fn bit_flip_changes_exactly_one_bit() {
        let dictionary = Dictionary::default();
        let input = MutationInput::new(&[0b1010_1010], &dictionary);
        let mut rng = MutationRng::new(1);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::BitFlip, &mut rng)
            .expect("bit flip should apply");

        assert_eq!(result.kind, MutationKind::BitFlip);
        assert_eq!(result.bytes.len(), 1);
        assert!((result.bytes[0] ^ 0b1010_1010).is_power_of_two());
    }

    #[test]
    fn byte_flip_replaces_one_byte() {
        let dictionary = Dictionary::default();
        let original = b"abcd";
        let input = MutationInput::new(original, &dictionary);
        let mut rng = MutationRng::new(2);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::ByteFlip, &mut rng)
            .expect("byte flip should apply");

        assert_eq!(result.kind, MutationKind::ByteFlip);
        assert_eq!(result.bytes.len(), original.len());
        assert_eq!(
            result
                .bytes
                .iter()
                .zip(original)
                .filter(|(left, right)| left != right)
                .count(),
            1
        );
    }

    #[test]
    fn arithmetic_wraps_one_byte() {
        let dictionary = Dictionary::default();
        let input = MutationInput::new(&[u8::MAX], &dictionary);
        let mut rng = MutationRng::new(3);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::Arithmetic, &mut rng)
            .expect("arithmetic should apply");

        assert_eq!(result.kind, MutationKind::Arithmetic);
        assert_eq!(result.bytes, vec![0]);
    }

    #[test]
    fn interesting_overwrites_existing_bytes() {
        let dictionary = Dictionary::default();
        let original = b"aaaaaa";
        let input = MutationInput::new(original, &dictionary);
        let mut rng = MutationRng::new(4);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::Interesting, &mut rng)
            .expect("interesting overwrite should apply");

        assert_eq!(result.kind, MutationKind::Interesting);
        assert_eq!(result.bytes.len(), original.len());
        assert_ne!(result.bytes, original);
    }

    #[test]
    fn interesting_overwrite_does_not_return_original_anchor_byte() {
        let dictionary = Dictionary::default();
        let input = MutationInput::new(&[0], &dictionary);
        let mut rng = MutationRng::new(0);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::Interesting, &mut rng)
            .expect("interesting overwrite should apply");

        assert_eq!(result.kind, MutationKind::Interesting);
        assert_ne!(result.bytes, vec![0]);
    }

    #[test]
    fn splice_combines_current_prefix_with_peer_suffix() {
        let dictionary = Dictionary::default();
        let current = [1, 2, 3, 4];
        let peer = [9, 8, 7, 6];
        let input = MutationInput::new(&current, &dictionary).with_peer(&peer);
        let mut rng = MutationRng::new(5);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::Splice, &mut rng)
            .expect("splice should apply");

        assert_eq!(result.kind, MutationKind::Splice);
        assert_eq!(result.bytes[0], current[0]);
        assert!(result.bytes.iter().any(|byte| peer.contains(byte)));
    }

    #[test]
    fn dictionary_insert_inserts_token() {
        let dictionary = Dictionary::from_tokens([&[2, 3][..]]);
        let input = MutationInput::new(&[1, 4], &dictionary);
        let mut rng = MutationRng::new(6);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::DictionaryInsert, &mut rng)
            .expect("dictionary insert should apply");

        assert_eq!(result.kind, MutationKind::DictionaryInsert);
        assert_eq!(result.bytes.len(), 4);
        assert!(result.bytes.windows(2).any(|window| window == [2, 3]));
    }

    #[test]
    fn structured_record_builds_tlv_records_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"TYPE"[..], &b"MAGIC"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(16);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredRecord, &mut rng)
            .expect("structured record mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredRecord);
        let records =
            decode_structured_records(&result.bytes).expect("structured output should parse");
        assert!((1..=4).contains(&records.len()));
        assert!(records
            .iter()
            .all(|(tag, value)| !tag.is_empty() && !value.is_empty()));
        assert!(records
            .iter()
            .any(|(tag, value)| tag == b"TYPE" || value == b"MAGIC" || value == b"READY"));
    }

    #[test]
    fn structured_record_respects_max_len_and_remains_parseable() {
        let long_token = vec![b'A'; 128];
        let dictionary = Dictionary::from_tokens([long_token.as_slice()]);
        let input = MutationInput::new(&[], &dictionary);
        let tiny = MutatorSuite::new(MutatorConfig {
            max_len: 16,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(17);

        let result = tiny
            .try_mutate_with_kind(&input, MutationKind::StructuredRecord, &mut rng)
            .expect("structured record mutation should apply with truncated tokens");

        assert_eq!(result.kind, MutationKind::StructuredRecord);
        assert!(result.bytes.len() <= 16);
        let records =
            decode_structured_records(&result.bytes).expect("truncated output should parse");
        assert_eq!(records.len(), 1);
        assert!(records[0].0.iter().all(|byte| *byte == b'A'));
        assert!(records[0].1.iter().all(|byte| *byte == b'A'));
    }

    #[test]
    fn structured_record_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"TYPE"[..], &b"MAGIC"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: false,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(18);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredRecord, &mut rng),
            None
        );
    }

    #[test]
    fn structured_json_builds_valid_json_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"TYPE"[..], &b"MAGIC"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(19);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredJson, &mut rng)
            .expect("structured JSON mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredJson);
        assert!(result.bytes.len() <= 64);
        let value: serde_json::Value =
            serde_json::from_slice(&result.bytes).expect("structured output should parse as JSON");
        let rendered = value.to_string();
        assert!(
            ["TYPE", "MAGIC", "READY"]
                .iter()
                .any(|token| rendered.contains(token)),
            "JSON output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_json_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"TYPE"[..], &b"MAGIC"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: true,
            structured_json: false,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(20);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredJson, &mut rng),
            None
        );
    }

    #[test]
    fn structured_xml_builds_parseable_element_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(21);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredXml, &mut rng)
            .expect("structured XML mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredXml);
        assert!(result.bytes.len() <= 64);
        let (tag, value) = parse_simple_xml_element(&result.bytes).expect("XML should parse");
        assert!(!tag.is_empty());
        assert!(!value.is_empty());
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["HOST", "READY"]
                .iter()
                .any(|token| rendered.contains(token)),
            "XML output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_xml_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: true,
            structured_json: true,
            structured_xml: false,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(22);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredXml, &mut rng),
            None
        );
    }

    #[test]
    fn structured_key_value_builds_parseable_pairs_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(21);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredKeyValue, &mut rng)
            .expect("structured key/value mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredKeyValue);
        assert!(result.bytes.len() <= 64);
        let pairs = parse_key_value_lines(&result.bytes).expect("key/value output should parse");
        assert!((1..=4).contains(&pairs.len()));
        assert!(pairs
            .iter()
            .all(|(key, _separator, value)| !key.is_empty() && !value.is_empty()));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["HOST", "PORT", "READY"]
                .iter()
                .any(|token| rendered.contains(token)),
            "key/value output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_key_value_respects_max_len_and_remains_parseable() {
        let long_token = vec![b'A'; 128];
        let dictionary = Dictionary::from_tokens([long_token.as_slice()]);
        let input = MutationInput::new(&[], &dictionary);
        let tiny = MutatorSuite::new(MutatorConfig {
            max_len: 12,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(22);

        let result = tiny
            .try_mutate_with_kind(&input, MutationKind::StructuredKeyValue, &mut rng)
            .expect("structured key/value mutation should apply with truncated tokens");

        assert_eq!(result.kind, MutationKind::StructuredKeyValue);
        assert!(result.bytes.len() <= 12);
        let pairs =
            parse_key_value_lines(&result.bytes).expect("truncated key/value output should parse");
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].0.iter().all(|byte| *byte == b'A'));
        assert!(pairs[0].2.iter().all(|byte| *byte == b'A'));
    }

    #[test]
    fn structured_key_value_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: false,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(23);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredKeyValue, &mut rng),
            None
        );
    }

    #[test]
    fn structured_ini_builds_parseable_sections_from_dictionary_tokens() {
        let dictionary =
            Dictionary::from_tokens([&b"network"[..], &b"host name"[..], &b"ready=true"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(52);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredIni, &mut rng)
            .expect("structured INI mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredIni);
        assert!(result.bytes.len() <= 64);
        let sections = parse_ini_sections(&result.bytes).expect("INI output should parse");
        assert!((1..=3).contains(&sections.len()));
        assert!(sections.iter().all(|(section, pairs)| !section.is_empty()
            && !pairs.is_empty()
            && pairs
                .iter()
                .all(|(key, value)| !key.is_empty() && !value.is_empty())));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["network", "host", "ready"]
                .iter()
                .any(|token| rendered.contains(token)),
            "INI output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_ini_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"section"[..], &b"value"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: false,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(53);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredIni, &mut rng),
            None
        );
    }

    #[test]
    fn structured_toml_builds_parseable_tables_from_dictionary_tokens() {
        let dictionary =
            Dictionary::from_tokens([&b"network"[..], &b"host name"[..], &b"ready=true"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(54);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredToml, &mut rng)
            .expect("structured TOML mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredToml);
        assert!(result.bytes.len() <= 64);
        let tables = parse_toml_tables(&result.bytes).expect("TOML output should parse");
        assert!((1..=3).contains(&tables.len()));
        assert!(tables.iter().all(|(table, pairs)| !table.is_empty()
            && !pairs.is_empty()
            && pairs
                .iter()
                .all(|(key, value)| !key.is_empty() && value.len() >= 2)));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["network", "host", "ready"]
                .iter()
                .any(|token| rendered.contains(token)),
            "TOML output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_toml_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"table"[..], &b"value"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: false,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(55);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredToml, &mut rng),
            None
        );
    }

    #[test]
    fn structured_yaml_builds_parseable_documents_from_dictionary_tokens() {
        let dictionary =
            Dictionary::from_tokens([&b"network"[..], &b"host name"[..], &b"ready: true"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(56);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredYaml, &mut rng)
            .expect("structured YAML mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredYaml);
        assert!(result.bytes.len() <= 64);
        let documents = parse_yaml_documents(&result.bytes).expect("YAML output should parse");
        assert!((1..=3).contains(&documents.len()));
        assert!(documents.iter().all(|(section, pairs)| !section.is_empty()
            && !pairs.is_empty()
            && pairs
                .iter()
                .all(|(key, value)| !key.is_empty() && value.len() >= 2)));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["network", "host", "ready"]
                .iter()
                .any(|token| rendered.contains(token)),
            "YAML output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_yaml_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"section"[..], &b"value"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: false,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(57);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredYaml, &mut rng),
            None
        );
    }

    #[test]
    fn structured_url_encoded_builds_parseable_query_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..], &b"READY"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(24);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredUrlEncoded, &mut rng)
            .expect("structured URL-encoded mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredUrlEncoded);
        assert!(result.bytes.len() <= 64);
        let pairs = parse_url_encoded_pairs(&result.bytes).expect("query output should parse");
        assert!((1..=4).contains(&pairs.len()));
        assert!(pairs
            .iter()
            .all(|(key, value)| !key.is_empty() && !value.is_empty()));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["HOST", "PORT", "READY"]
                .iter()
                .any(|token| rendered.contains(token)),
            "URL-encoded output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_url_encoded_respects_max_len_and_remains_parseable() {
        let long_token = vec![b'A'; 128];
        let dictionary = Dictionary::from_tokens([long_token.as_slice()]);
        let input = MutationInput::new(&[], &dictionary);
        let tiny = MutatorSuite::new(MutatorConfig {
            max_len: 11,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(25);

        let result = tiny
            .try_mutate_with_kind(&input, MutationKind::StructuredUrlEncoded, &mut rng)
            .expect("structured URL-encoded mutation should apply with truncated tokens");

        assert_eq!(result.kind, MutationKind::StructuredUrlEncoded);
        assert!(result.bytes.len() <= 11);
        let pairs =
            parse_url_encoded_pairs(&result.bytes).expect("truncated query output should parse");
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].0.iter().all(|byte| *byte == b'A'));
        assert!(pairs[0].1.iter().all(|byte| *byte == b'A'));
    }

    #[test]
    fn structured_url_encoded_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: false,
            structured_multipart: true,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(26);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredUrlEncoded, &mut rng),
            None
        );
    }

    #[test]
    fn structured_multipart_builds_parseable_form_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let mut rng = MutationRng::new(27);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredMultipart, &mut rng)
            .expect("structured multipart mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredMultipart);
        assert!(result.bytes.len() <= 64);
        let parts = parse_multipart_form_data(&result.bytes).expect("multipart body should parse");
        assert!((1..=3).contains(&parts.len()));
        assert!(parts
            .iter()
            .all(|(name, value)| !name.is_empty() && !value.is_empty()));
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["HOST", "PORT"]
                .iter()
                .any(|token| rendered.contains(token)),
            "multipart output should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_multipart_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"HOST"[..], &b"PORT"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: false,
            structured_csv: true,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(28);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredMultipart, &mut rng),
            None
        );
    }

    #[test]
    fn structured_csv_builds_parseable_rows_from_dictionary_tokens() {
        let dictionary =
            Dictionary::from_tokens([&b"name"[..], &b"alice,bob"[..], &b"quoted\"value"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(47);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredCsv, &mut rng)
            .expect("structured CSV mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredCsv);
        let rows = parse_csv_rows(&result.bytes).expect("CSV output should parse");
        assert!((1..=4).contains(&rows.len()));
        assert!(rows.iter().all(|row| (1..=3).contains(&row.len())));
        let cells = rows.into_iter().flatten().collect::<Vec<_>>();
        assert!(
            cells.iter().any(|cell| cell == b"name")
                || cells.iter().any(|cell| cell == b"alice,bob")
                || cells.iter().any(|cell| cell == b"quoted\"value")
        );
    }

    #[test]
    fn structured_csv_respects_max_len_and_remains_parseable() {
        let dictionary = Dictionary::from_tokens([&b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 10,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(48);

        let result = suite
            .try_mutate_with_kind(&input, MutationKind::StructuredCsv, &mut rng)
            .expect("structured CSV mutation should apply with truncated tokens");

        assert_eq!(result.kind, MutationKind::StructuredCsv);
        assert!(result.bytes.len() <= 10);
        let rows = parse_csv_rows(&result.bytes).expect("truncated CSV output should parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 1);
        assert!(rows[0][0].iter().all(u8::is_ascii_uppercase));
    }

    #[test]
    fn structured_csv_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"field"[..], &b"value"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: false,
            structured_http: true,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(49);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredCsv, &mut rng),
            None
        );
    }

    #[test]
    fn structured_http_request_builds_parseable_request_from_dictionary_tokens() {
        let dictionary = Dictionary::from_tokens([&b"api"[..], &b"READY"[..], &b"MAGIC"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(50);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredHttp, &mut rng)
            .expect("structured HTTP mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredHttp);
        assert!(result.bytes.len() <= 128);
        parse_http_request(&result.bytes).expect("HTTP request should parse");
        let rendered = String::from_utf8_lossy(&result.bytes);
        assert!(
            ["api", "READY", "MAGIC"]
                .iter()
                .any(|token| rendered.contains(token)),
            "HTTP request should contain at least one dictionary token: {rendered}"
        );
    }

    #[test]
    fn structured_http_request_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"api"[..], &b"Host"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_records: true,
            structured_json: true,
            structured_xml: true,
            structured_key_value: true,
            structured_url_encoded: true,
            structured_multipart: true,
            structured_csv: true,
            structured_http: false,
            structured_ini: true,
            structured_toml: true,
            structured_yaml: true,
            structured_chunked: true,
            structured_recursive: true,
        });
        let mut rng = MutationRng::new(51);

        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredHttp, &mut rng),
            None
        );
    }

    #[test]
    fn structured_chunked_builds_magic_plus_length_prefixed_chunks() {
        let dictionary = Dictionary::from_tokens([&b"PKZIP"[..], &b"DATA"[..], &b"HDRPAYLOAD"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut rng = MutationRng::new(7);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::StructuredChunked, &mut rng)
            .expect("chunked mutation should apply");

        assert_eq!(result.kind, MutationKind::StructuredChunked);
        let tokens: [&[u8]; 3] = [b"PKZIP", b"DATA", b"HDRPAYLOAD"];
        let magic = tokens
            .iter()
            .find(|t| {
                result
                    .bytes
                    .starts_with(&t[..t.len().min(STRUCTURED_CHUNKED_MAX_MAGIC)])
            })
            .expect("output must start with a dictionary magic token");
        assert!(
            result.bytes.len() > magic.len(),
            "output {:?} must have chunks beyond the magic",
            result.bytes
        );
        assert!(result.bytes.len() <= suite().config.max_len);

        // The first chunk's u32 length (LE or BE) points within the buffer.
        let pos = magic.len();
        assert!(pos + STRUCTURED_CHUNK_OVERHEAD <= result.bytes.len());
        let raw: [u8; 4] = result.bytes[pos..pos + 4].try_into().unwrap();
        let le = u32::from_le_bytes(raw) as usize;
        let be = u32::from_be_bytes(raw) as usize;
        let body = result.bytes.len() - pos - STRUCTURED_CHUNK_OVERHEAD;
        assert!(
            le <= body || be <= body,
            "first chunk length must point within the buffer (le={le}, be={be}, body={body})"
        );
    }

    #[test]
    fn structured_chunked_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"PKZIP"[..], &b"DATA"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 128,
            structured_chunked: false,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(8);
        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredChunked, &mut rng),
            None
        );
    }

    /// Maximum nesting depth of a recursive-grammar output, or `None` if the
    /// delimiters are not well-balanced (running balance goes negative, or does
    /// not return to zero). Tokenises `<e>`/`</e>` as units; single-char pairs
    /// otherwise.
    fn nesting_depth(bytes: &[u8]) -> Option<usize> {
        let mut i = 0;
        let mut balance: i64 = 0;
        let mut max: i64 = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"</e>") {
                balance -= 1;
                i += 4;
            } else if bytes[i..].starts_with(b"<e>") {
                balance += 1;
                i += 3;
            } else {
                match bytes[i] {
                    b'(' | b'[' | b'{' => balance += 1,
                    b')' | b']' | b'}' => balance -= 1,
                    _ => {}
                }
                i += 1;
            }
            if balance < 0 {
                return None;
            }
            max = max.max(balance);
        }
        (balance == 0).then_some(max as usize)
    }

    #[test]
    fn structured_recursive_builds_balanced_nested_delimiters() {
        let dictionary = Dictionary::from_tokens([&b"NODE"[..], &b"LEAF"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let mut applied = 0;
        for seed in 0..32u64 {
            let mut rng = MutationRng::new(seed);
            if let Some(result) =
                suite().try_mutate_with_kind(&input, MutationKind::StructuredRecursive, &mut rng)
            {
                applied += 1;
                assert_eq!(result.kind, MutationKind::StructuredRecursive);
                assert!(result.bytes.len() <= suite().config.max_len);
                assert!(
                    nesting_depth(&result.bytes).is_some(),
                    "output must be balanced: {:?}",
                    String::from_utf8_lossy(&result.bytes)
                );
            }
        }
        assert!(applied > 0, "recursive mutator never applied");
    }

    #[test]
    fn structured_recursive_reaches_deep_nesting() {
        // No dictionary: deep delimiter nesting must be reachable on its own.
        let dictionary = Dictionary::default();
        let input = MutationInput::new(b"", &dictionary);
        let mut deepest = 0;
        for seed in 0..64u64 {
            let mut rng = MutationRng::new(seed);
            if let Some(result) =
                suite().try_mutate_with_kind(&input, MutationKind::StructuredRecursive, &mut rng)
            {
                deepest = deepest.max(nesting_depth(&result.bytes).expect("balanced"));
            }
        }
        assert!(
            deepest >= 4,
            "recursive mutator must reach deep nesting (max depth {deepest})"
        );
    }

    #[test]
    fn structured_recursive_respects_max_len_and_balance() {
        let dictionary = Dictionary::from_tokens([&b"NODE"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 16,
            ..MutatorConfig::default()
        });
        for seed in 0..32u64 {
            let mut rng = MutationRng::new(seed);
            if let Some(result) =
                suite.try_mutate_with_kind(&input, MutationKind::StructuredRecursive, &mut rng)
            {
                assert!(result.bytes.len() <= 16, "len {} > 16", result.bytes.len());
                assert!(nesting_depth(&result.bytes).is_some());
            }
        }
    }

    #[test]
    fn structured_recursive_can_be_disabled_by_config() {
        let dictionary = Dictionary::from_tokens([&b"NODE"[..]]);
        let input = MutationInput::new(b"seed", &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            structured_recursive: false,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(8);
        assert_eq!(
            suite.try_mutate_with_kind(&input, MutationKind::StructuredRecursive, &mut rng),
            None
        );
    }

    #[test]
    fn cmplog_splice_replaces_operand_at_observed_offset() {
        let dictionary = Dictionary::default();
        let mut log = cmplog::CmpLog::new();
        log.record(cmplog::CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: cmplog::CmpKind::BufferEquality,
        });
        let bytes = b"xxabcdyy";
        let input = MutationInput::new(bytes, &dictionary).with_cmplog(&log);
        let mut rng = MutationRng::new(13);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::CmpLogSplice, &mut rng)
            .expect("cmplog splice should apply");

        assert_eq!(result.kind, MutationKind::CmpLogSplice);
        // Either direction is valid (operand_a→b or b→a) but only b is
        // present in the input, so we must see MAGIC spliced at offset 2.
        assert_eq!(&result.bytes[..2], b"xx");
        assert_eq!(&result.bytes[2..7], b"MAGIC");
        assert_eq!(&result.bytes[7..], b"yy");
    }

    #[test]
    fn cmplog_splice_unavailable_when_operands_absent_from_input() {
        let dictionary = Dictionary::default();
        let mut log = cmplog::CmpLog::new();
        log.record(cmplog::CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: cmplog::CmpKind::BufferEquality,
        });
        let input = MutationInput::new(b"unrelated", &dictionary).with_cmplog(&log);
        let mut rng = MutationRng::new(14);

        assert_eq!(
            suite().try_mutate_with_kind(&input, MutationKind::CmpLogSplice, &mut rng),
            None
        );
    }

    #[test]
    fn cmplog_splice_respects_max_len() {
        let dictionary = Dictionary::default();
        let mut log = cmplog::CmpLog::new();
        log.record(cmplog::CmpEntry {
            site_id: 1,
            operand_a: b"ab".to_vec(),
            operand_b: vec![0xCC; 256],
            kind: cmplog::CmpKind::BufferEquality,
        });
        let input = MutationInput::new(b"ab", &dictionary).with_cmplog(&log);
        let tiny = MutatorSuite::new(MutatorConfig {
            max_len: 8,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(15);

        assert_eq!(
            tiny.try_mutate_with_kind(&input, MutationKind::CmpLogSplice, &mut rng),
            None
        );
    }

    #[test]
    fn mutate_biases_toward_cmplog_splice_when_base_has_evidence() {
        // #400: when the base carries per-input cmplog evidence whose operand
        // occurs in the input, the uniform scheduler must pick CmpLogSplice for
        // the large majority of children (the boost), so one capture run yields
        // many input-to-state children. Without the boost it would be ~1/N.
        let dictionary = Dictionary::default();
        let mut log = cmplog::CmpLog::new();
        log.record(cmplog::CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"WXYZ".to_vec(),
            kind: cmplog::CmpKind::IntegerCompare,
        });
        let bytes = b"--abcd--";
        let input = MutationInput::new(bytes, &dictionary).with_cmplog(&log);
        let suite = suite();

        let mut splices = 0usize;
        let trials = 2000usize;
        for seed in 0..trials as u64 {
            let mut rng = MutationRng::new(seed);
            if let Some(result) = suite.mutate(&input, &mut rng) {
                if result.kind == MutationKind::CmpLogSplice {
                    splices += 1;
                }
            }
        }
        // The boost (CMPLOG_SPLICE_EXTRA_WEIGHT extra entries) makes the splice
        // dominate; a generous floor keeps the test robust to the exact ratio.
        assert!(
            splices * 2 > trials,
            "expected CmpLogSplice to dominate when evidence present, got {splices}/{trials}"
        );
    }

    #[test]
    fn mutate_never_splices_without_cmplog_evidence() {
        // The boost keys off `input.cmplog`; with no evidence, CmpLogSplice is
        // unavailable and never selected.
        let dictionary = Dictionary::default();
        let input = MutationInput::new(b"--abcd--", &dictionary);
        let suite = suite();
        for seed in 0..500u64 {
            let mut rng = MutationRng::new(seed);
            if let Some(result) = suite.mutate(&input, &mut rng) {
                assert_ne!(result.kind, MutationKind::CmpLogSplice);
            }
        }
    }

    #[test]
    fn typed_value_replaces_valid_typed_span() {
        let dictionary = Dictionary::default();
        let spans = [TypedSpan::new(1..2, TypedValueKind::Boolean)];
        let input = MutationInput::new(&[9, 9, 9], &dictionary).with_typed_spans(&spans);
        let mut rng = MutationRng::new(7);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::TypedValue, &mut rng)
            .expect("typed replacement should apply");

        assert_eq!(result.kind, MutationKind::TypedValue);
        assert_eq!(result.bytes.len(), 3);
        assert!(matches!(result.bytes[1], 0 | 1));
    }

    #[test]
    fn typed_value_ignores_invalid_typed_span() {
        let dictionary = Dictionary::default();
        let spans = [TypedSpan::new(2..5, TypedValueKind::Boolean)];
        let input = MutationInput::new(&[9, 9, 9], &dictionary).with_typed_spans(&spans);
        let mut rng = MutationRng::new(8);

        assert_eq!(
            suite().try_mutate_with_kind(&input, MutationKind::TypedValue, &mut rng),
            None
        );
    }

    #[test]
    fn op_sequence_inserts_step_and_updates_count() {
        let dictionary = Dictionary::default();
        let bytes = encoded_sequence(1, [encoded_step(0, &[0xaa])]);
        let layout = OperationSequenceLayout::new(
            Some(0..5),
            1,
            4,
            1,
            vec![OperationStepSpan::new(5..11, 5..10)],
        );
        let input = MutationInput::new(&bytes, &dictionary).with_operation_sequence(&layout);
        let mut rng = MutationRng::new(11);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::OpSequence, &mut rng)
            .expect("op-sequence insert should apply");

        assert_eq!(result.kind, MutationKind::OpSequence);
        assert_eq!(decode_count(&result.bytes[0..5], 1, 4), 2);
        assert_eq!(&result.bytes[5..11], &result.bytes[11..17]);
    }

    #[test]
    fn op_sequence_removes_step_and_updates_count() {
        let dictionary = Dictionary::default();
        let bytes = encoded_sequence(2, [encoded_step(0, &[0xaa])]);
        let layout = OperationSequenceLayout::new(
            Some(0..5),
            1,
            2,
            1,
            vec![OperationStepSpan::new(5..11, 5..10)],
        );
        let input = MutationInput::new(&bytes, &dictionary).with_operation_sequence(&layout);
        let mut rng = MutationRng::new(12);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::OpSequence, &mut rng)
            .expect("op-sequence remove should apply");

        assert_eq!(result.kind, MutationKind::OpSequence);
        assert_eq!(decode_count(&result.bytes[0..5], 1, 2), 1);
        assert_eq!(result.bytes.len(), 5);
    }

    #[test]
    fn op_sequence_swaps_steps_without_rewriting_count() {
        let dictionary = Dictionary::default();
        let first = encoded_step(0, &[0xaa]);
        let second = encoded_step(0, &[0xbb]);
        let bytes = encoded_sequence(2, [first.clone(), second.clone()]);
        let layout = OperationSequenceLayout::new(
            None,
            1,
            8,
            1,
            vec![
                OperationStepSpan::new(5..11, 5..10),
                OperationStepSpan::new(11..17, 11..16),
            ],
        );
        let input = MutationInput::new(&bytes, &dictionary).with_operation_sequence(&layout);
        let mut rng = MutationRng::new(13);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::OpSequence, &mut rng)
            .expect("op-sequence swap should apply");

        assert_eq!(result.kind, MutationKind::OpSequence);
        assert_eq!(&result.bytes[0..5], &bytes[0..5]);
        assert_eq!(&result.bytes[5..11], second.as_slice());
        assert_eq!(&result.bytes[11..17], first.as_slice());
    }

    #[test]
    fn op_sequence_changes_operation_selector() {
        let dictionary = Dictionary::default();
        let bytes = encoded_sequence(1, [encoded_step(0, &[0xaa])]);
        let layout =
            OperationSequenceLayout::new(None, 1, 8, 4, vec![OperationStepSpan::new(5..11, 5..10)]);
        let input = MutationInput::new(&bytes, &dictionary).with_operation_sequence(&layout);
        let mut rng = MutationRng::new(14);

        let result = suite()
            .try_mutate_with_kind(&input, MutationKind::OpSequence, &mut rng)
            .expect("op-selector mutation should apply");

        assert_eq!(result.kind, MutationKind::OpSequence);
        assert_eq!(&result.bytes[0..5], &bytes[0..5]);
        assert_ne!(decode_count(&result.bytes[5..10], 0, 3), 0);
    }

    #[test]
    fn op_sequence_layout_validation_accepts_matching_decoded_steps() {
        let bytes = encoded_sequence(2, [encoded_step(0, &[0xaa]), encoded_step(1, &[0xbb])]);
        let layout = OperationSequenceLayout::new(
            Some(0..5),
            1,
            4,
            2,
            vec![
                OperationStepSpan::new(5..11, 5..10),
                OperationStepSpan::new(11..17, 11..16),
            ],
        );

        assert_eq!(layout.validate_for_input(&bytes), Ok(()));
    }

    #[test]
    fn op_sequence_layout_validation_rejects_step_count_mismatch() {
        let bytes = encoded_sequence(2, [encoded_step(0, &[0xaa])]);
        let layout = OperationSequenceLayout::new(
            Some(0..5),
            1,
            4,
            1,
            vec![OperationStepSpan::new(5..11, 5..10)],
        );

        assert_eq!(
            layout.validate_for_input(&bytes),
            Err(OperationSequenceLayoutError::StepCountMismatch {
                decoded: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn op_sequence_layout_validation_rejects_empty_operation_set() {
        let bytes = encoded_sequence(1, [encoded_step(0, &[0xaa])]);
        let layout = OperationSequenceLayout::new(
            Some(0..5),
            1,
            4,
            0,
            vec![OperationStepSpan::new(5..11, 5..10)],
        );

        assert_eq!(
            layout.validate_for_input(&bytes),
            Err(OperationSequenceLayoutError::EmptyOperationSet)
        );
    }

    #[test]
    fn op_sequence_layout_validation_rejects_invalid_selector_span() {
        let bytes = [0, 1, 0xaa];
        let layout =
            OperationSequenceLayout::new(None, 1, 4, 2, vec![OperationStepSpan::new(1..3, 1..2)]);

        assert_eq!(
            layout.validate_for_input(&bytes),
            Err(OperationSequenceLayoutError::InvalidOperationSelector {
                index: 0,
                range: 1..2
            })
        );
    }

    #[test]
    fn general_mutation_filters_unavailable_kinds() {
        let dictionary = Dictionary::from_tokens([&b"x"[..]]);
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            max_len: 64,
            structured_records: false,
            structured_json: false,
            structured_xml: false,
            structured_key_value: false,
            structured_url_encoded: false,
            structured_multipart: false,
            structured_csv: false,
            structured_http: false,
            structured_ini: false,
            structured_toml: false,
            structured_yaml: false,
            structured_chunked: true,
            // Disabled here so the only generative kinds left for empty input
            // are the dictionary-backed ones (the recursive nester is exercised
            // by its own tests and is always applicable).
            structured_recursive: false,
        });
        let mut rng = MutationRng::new(9);

        let result = suite
            .mutate(&input, &mut rng)
            .expect("dictionary insert remains available for empty input");

        assert_eq!(result.kind, MutationKind::DictionaryInsert);
        assert_eq!(result.bytes, b"x");
    }

    #[test]
    fn general_mutation_returns_none_when_no_kind_can_apply() {
        // Empty input + empty dictionary starves every seed/dictionary-driven
        // kind. The recursive nester is generative (needs neither), so it must
        // also be off for "nothing applies" to hold.
        let dictionary = Dictionary::default();
        let input = MutationInput::new(&[], &dictionary);
        let suite = MutatorSuite::new(MutatorConfig {
            structured_recursive: false,
            ..MutatorConfig::default()
        });
        let mut rng = MutationRng::new(10);

        assert_eq!(suite.mutate(&input, &mut rng), None);
    }

    fn encoded_sequence<const N: usize>(count: usize, steps: [Vec<u8>; N]) -> Vec<u8> {
        let mut bytes = encode_bounded_with_min(count, 1);
        for step in steps {
            bytes.extend(step);
        }
        bytes
    }

    fn encoded_step(op_index: usize, args: &[u8]) -> Vec<u8> {
        let mut bytes = encode_bounded(op_index);
        bytes.extend_from_slice(args);
        bytes
    }

    fn encode_bounded(value: usize) -> Vec<u8> {
        encode_bounded_with_min(value, 0)
    }

    fn encode_bounded_with_min(value: usize, min: usize) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((value - min) as u32).to_le_bytes());
        bytes
    }

    fn decode_count(bytes: &[u8], min: usize, max: usize) -> usize {
        let raw = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        min + raw % (max - min + 1)
    }

    fn decode_structured_records(bytes: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        let count = *bytes.first()? as usize;
        if !(1..=4).contains(&count) {
            return None;
        }

        let mut offset = 1;
        let mut records = Vec::new();
        for _ in 0..count {
            let tag_len = *bytes.get(offset)? as usize;
            offset += 1;
            if tag_len == 0 {
                return None;
            }
            let tag = bytes.get(offset..offset + tag_len)?.to_vec();
            offset += tag_len;

            let value_len =
                u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?) as usize;
            offset += 2;
            if value_len == 0 {
                return None;
            }
            let value = bytes.get(offset..offset + value_len)?.to_vec();
            offset += value_len;

            records.push((tag, value));
        }

        if offset == bytes.len() {
            Some(records)
        } else {
            None
        }
    }

    type KeyValueLine<'a> = (&'a [u8], u8, &'a [u8]);
    type BytePair<'a> = (&'a [u8], &'a [u8]);
    type BytePairs<'a> = Vec<BytePair<'a>>;
    type NamedSection<'a> = (&'a [u8], BytePairs<'a>);
    type HttpRequest<'a> = (&'a [u8], &'a [u8], BytePairs<'a>, &'a [u8]);

    fn parse_key_value_lines(bytes: &[u8]) -> Option<Vec<KeyValueLine<'_>>> {
        let mut pairs = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let separator_index = line.iter().position(|byte| matches!(*byte, b'=' | b':'))?;
            let (key, rest) = line.split_at(separator_index);
            let separator = *rest.first()?;
            let value = &rest[1..];
            if key.is_empty() || value.is_empty() {
                return None;
            }
            pairs.push((key, separator, value));
        }
        if pairs.is_empty() {
            None
        } else {
            Some(pairs)
        }
    }

    fn parse_url_encoded_pairs(bytes: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
        let mut pairs = Vec::new();
        for pair in bytes.split(|byte| *byte == b'&') {
            if pair.is_empty() {
                return None;
            }
            let pos = pair.iter().position(|byte| *byte == b'=')?;
            if pos == 0 || pos + 1 >= pair.len() {
                return None;
            }
            if !url_component_is_valid(&pair[..pos]) || !url_component_is_valid(&pair[pos + 1..]) {
                return None;
            }
            pairs.push((&pair[..pos], &pair[pos + 1..]));
        }
        if pairs.is_empty() {
            None
        } else {
            Some(pairs)
        }
    }

    fn parse_ini_sections(bytes: &[u8]) -> Option<Vec<NamedSection<'_>>> {
        let mut sections = Vec::<NamedSection<'_>>::new();
        let mut current: Option<NamedSection<'_>> = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(b"[") {
                if let Some(section) = current.take() {
                    if section.1.is_empty() {
                        return None;
                    }
                    sections.push(section);
                }
                if !line.ends_with(b"]") || line.len() <= 2 {
                    return None;
                }
                let name = &line[1..line.len() - 1];
                if name.is_empty()
                    || !name.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.')
                    })
                {
                    return None;
                }
                current = Some((name, Vec::new()));
                continue;
            }
            let section = current.as_mut()?;
            let separator = line.iter().position(|byte| *byte == b'=')?;
            let key = &line[..separator];
            let value = &line[separator + 1..];
            if key.is_empty()
                || value.is_empty()
                || !key
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
                || value.iter().any(|byte| matches!(*byte, b'\r' | b'\n'))
            {
                return None;
            }
            section.1.push((key, value));
        }
        if let Some(section) = current {
            if section.1.is_empty() {
                return None;
            }
            sections.push(section);
        }
        if sections.is_empty() {
            None
        } else {
            Some(sections)
        }
    }

    fn parse_toml_tables(bytes: &[u8]) -> Option<Vec<NamedSection<'_>>> {
        let mut tables = Vec::<NamedSection<'_>>::new();
        let mut current: Option<NamedSection<'_>> = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(b"[") {
                if let Some(table) = current.take() {
                    if table.1.is_empty() {
                        return None;
                    }
                    tables.push(table);
                }
                if !line.ends_with(b"]") || line.len() <= 2 {
                    return None;
                }
                let name = &line[1..line.len() - 1];
                if !toml_bare_key_is_valid(name) {
                    return None;
                }
                current = Some((name, Vec::new()));
                continue;
            }
            let table = current.as_mut()?;
            let separator = line.windows(3).position(|window| window == b" = ")?;
            let key = &line[..separator];
            let value = &line[separator + 3..];
            if !toml_bare_key_is_valid(key) || !toml_basic_string_is_valid(value) {
                return None;
            }
            table.1.push((key, value));
        }
        if let Some(table) = current {
            if table.1.is_empty() {
                return None;
            }
            tables.push(table);
        }
        if tables.is_empty() {
            None
        } else {
            Some(tables)
        }
    }

    fn toml_bare_key_is_valid(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    }

    fn toml_basic_string_is_valid(bytes: &[u8]) -> bool {
        bytes.len() >= 2
            && bytes.first() == Some(&b'"')
            && bytes.last() == Some(&b'"')
            && bytes[1..bytes.len() - 1]
                .iter()
                .all(|byte| !matches!(*byte, b'\r' | b'\n'))
    }

    fn parse_yaml_documents(bytes: &[u8]) -> Option<Vec<NamedSection<'_>>> {
        let mut documents = Vec::<NamedSection<'_>>::new();
        let mut current: Option<NamedSection<'_>> = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if !line.starts_with(b" ") {
                if let Some(document) = current.take() {
                    if document.1.is_empty() {
                        return None;
                    }
                    documents.push(document);
                }
                if !line.ends_with(b":") || line.len() <= 1 {
                    return None;
                }
                let section = &line[..line.len() - 1];
                if !toml_bare_key_is_valid(section) {
                    return None;
                }
                current = Some((section, Vec::new()));
                continue;
            }
            let document = current.as_mut()?;
            let line = line.strip_prefix(b"  ")?;
            let separator = line.windows(2).position(|window| window == b": ")?;
            let key = &line[..separator];
            let value = &line[separator + 2..];
            if !toml_bare_key_is_valid(key) || !toml_basic_string_is_valid(value) {
                return None;
            }
            document.1.push((key, value));
        }
        if let Some(document) = current {
            if document.1.is_empty() {
                return None;
            }
            documents.push(document);
        }
        if documents.is_empty() {
            None
        } else {
            Some(documents)
        }
    }

    fn parse_csv_rows(bytes: &[u8]) -> Option<Vec<Vec<Vec<u8>>>> {
        let mut rows = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let mut row = Vec::new();
            let mut cell = Vec::new();
            let mut index = 0;
            let mut quoted = false;
            let mut cell_started = false;
            while index < line.len() {
                let byte = line[index];
                if quoted {
                    match byte {
                        b'"' if line.get(index + 1) == Some(&b'"') => {
                            cell.push(b'"');
                            index += 2;
                            continue;
                        }
                        b'"' => {
                            quoted = false;
                            index += 1;
                            continue;
                        }
                        _ => cell.push(byte),
                    }
                } else {
                    match byte {
                        b',' => {
                            if cell.is_empty() {
                                return None;
                            }
                            row.push(std::mem::take(&mut cell));
                            cell_started = false;
                        }
                        b'"' if !cell_started => {
                            quoted = true;
                            cell_started = true;
                        }
                        b'"' => return None,
                        _ => {
                            cell.push(byte);
                            cell_started = true;
                        }
                    }
                }
                index += 1;
            }
            if quoted || cell.is_empty() {
                return None;
            }
            row.push(cell);
            rows.push(row);
        }
        if rows.is_empty() {
            None
        } else {
            Some(rows)
        }
    }

    fn url_component_is_valid(bytes: &[u8]) -> bool {
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    if index + 2 >= bytes.len()
                        || !bytes[index + 1].is_ascii_hexdigit()
                        || !bytes[index + 2].is_ascii_hexdigit()
                    {
                        return false;
                    }
                    index += 3;
                }
                b'&' | b'=' => return false,
                0x21..=0x7e => index += 1,
                _ => return false,
            }
        }
        true
    }

    fn parse_simple_xml_element(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        if !bytes.starts_with(b"<") {
            return None;
        }
        let tag_end = bytes.iter().position(|byte| *byte == b'>')?;
        let tag = &bytes[1..tag_end];
        if tag.is_empty() || !xml_name_is_valid(tag) {
            return None;
        }
        let closing = [b"</", tag, b">"].concat();
        if !bytes.ends_with(&closing) {
            return None;
        }
        let value_end = bytes.len().checked_sub(closing.len())?;
        let value = &bytes[tag_end + 1..value_end];
        if value.is_empty() {
            return None;
        }
        Some((tag, value))
    }

    fn xml_name_is_valid(bytes: &[u8]) -> bool {
        let Some(first) = bytes.first() else {
            return false;
        };
        if !first.is_ascii_alphabetic() && *first != b'_' {
            return false;
        }
        bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
    }

    fn parse_multipart_form_data(bytes: &[u8]) -> Option<BytePairs<'_>> {
        let boundary_end = bytes.windows(2).position(|window| window == b"\r\n")?;
        let first_line = bytes.get(..boundary_end)?;
        if !first_line.starts_with(b"--") || first_line.len() <= 2 {
            return None;
        }
        let boundary = &first_line[2..];
        let mut offset = boundary_end + 2;
        let mut parts = Vec::new();

        loop {
            let header = b"Content-Disposition: form-data; name=\"";
            if !bytes.get(offset..)?.starts_with(header) {
                return None;
            }
            offset += header.len();
            let name_end = bytes[offset..]
                .windows(3)
                .position(|window| window == b"\"\r\n")?;
            let name = &bytes[offset..offset + name_end];
            offset += name_end + 3;
            if !bytes.get(offset..)?.starts_with(b"\r\n") {
                return None;
            }
            offset += 2;
            let value_end = bytes[offset..]
                .windows(2)
                .position(|window| window == b"\r\n")?;
            let value = &bytes[offset..offset + value_end];
            offset += value_end + 2;
            if name.is_empty() || value.is_empty() {
                return None;
            }
            parts.push((name, value));

            if !bytes.get(offset..)?.starts_with(b"--") {
                return None;
            }
            offset += 2;
            if bytes.get(offset..offset + boundary.len())? != boundary {
                return None;
            }
            offset += boundary.len();
            if bytes.get(offset..)?.starts_with(b"--\r\n") {
                offset += 4;
                break;
            }
            if bytes.get(offset..)?.starts_with(b"\r\n") {
                offset += 2;
                continue;
            }
            return None;
        }

        if offset == bytes.len() && !parts.is_empty() {
            Some(parts)
        } else {
            None
        }
    }

    fn parse_http_request(bytes: &[u8]) -> Option<HttpRequest<'_>> {
        let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
        let header_block = &bytes[..header_end];
        let body = &bytes[header_end + 4..];
        let mut lines = header_block.split(|byte| *byte == b'\n');
        let request_line = lines.next()?.strip_suffix(b"\r")?;
        let mut parts = request_line.split(|byte| *byte == b' ');
        let method = parts.next()?;
        let path = parts.next()?;
        let version = parts.next()?;
        if parts.next().is_some()
            || !matches!(method, b"GET" | b"POST" | b"PUT" | b"DELETE")
            || !path.starts_with(b"/")
            || path.len() < 2
            || path.iter().any(|byte| byte.is_ascii_whitespace())
            || version != b"HTTP/1.1"
        {
            return None;
        }

        let mut headers = Vec::new();
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let separator = line.windows(2).position(|window| window == b": ")?;
            let name = &line[..separator];
            let value = &line[separator + 2..];
            if name.is_empty()
                || value.is_empty()
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
                || value.iter().any(|byte| matches!(*byte, b'\r' | b'\n'))
            {
                return None;
            }
            headers.push((name, value));
        }

        if headers.is_empty() {
            return None;
        }

        Some((method, path, headers, body))
    }
}
