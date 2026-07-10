// SPDX-License-Identifier: Apache-2.0

use std::ops::Range;

use crate::dictionary::{Dictionary, DictionaryBucket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedValueKind {
    Boolean,
    SignedInteger,
    UnsignedInteger,
    Float64,
    Bytes,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSpan {
    pub range: Range<usize>,
    pub kind: TypedValueKind,
}

impl TypedSpan {
    pub fn new(range: Range<usize>, kind: TypedValueKind) -> Self {
        Self { range, kind }
    }

    pub fn valid_for(&self, len: usize) -> bool {
        self.range.start < self.range.end && self.range.end <= len
    }
}

pub fn typed_candidates(kind: TypedValueKind, dictionary: &Dictionary) -> Vec<Vec<u8>> {
    match kind {
        TypedValueKind::Boolean => vec![vec![0], vec![1]],
        TypedValueKind::SignedInteger => [
            0_i32.to_le_bytes(),
            1_i32.to_le_bytes(),
            (-1_i32).to_le_bytes(),
            i32::MIN.to_le_bytes(),
            i32::MAX.to_le_bytes(),
        ]
        .into_iter()
        .map(Vec::from)
        .collect(),
        TypedValueKind::UnsignedInteger => [
            0_u32.to_le_bytes(),
            1_u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
        ]
        .into_iter()
        .map(Vec::from)
        .collect(),
        TypedValueKind::Float64 => [
            0.0_f64.to_le_bytes(),
            (-0.0_f64).to_le_bytes(),
            f64::NAN.to_le_bytes(),
            f64::INFINITY.to_le_bytes(),
            f64::NEG_INFINITY.to_le_bytes(),
        ]
        .into_iter()
        .map(Vec::from)
        .collect(),
        TypedValueKind::Bytes | TypedValueKind::String => {
            let tokens: Vec<Vec<u8>> =
                if kind == TypedValueKind::String && dictionary.has_curated_entries() {
                    dictionary
                        .tokens_for_bucket(&DictionaryBucket::String)
                        .map(Vec::from)
                        .collect()
                } else {
                    dictionary.tokens().map(Vec::from).collect()
                };
            if tokens.is_empty() {
                vec![Vec::new()]
            } else {
                tokens
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::Dictionary;

    #[test]
    fn typed_span_rejects_out_of_bounds_range() {
        let span = TypedSpan::new(1..4, TypedValueKind::Bytes);

        assert!(span.valid_for(4));
        assert!(!span.valid_for(3));
        assert!(!TypedSpan::new(2..2, TypedValueKind::Bytes).valid_for(4));
    }

    #[test]
    fn boolean_candidates_are_single_byte_anchors() {
        let candidates = typed_candidates(TypedValueKind::Boolean, &Dictionary::default());

        assert_eq!(candidates, vec![vec![0], vec![1]]);
    }

    #[test]
    fn signed_integer_candidates_are_little_endian_i32() {
        let candidates = typed_candidates(TypedValueKind::SignedInteger, &Dictionary::default());

        assert!(candidates.contains(&0_i32.to_le_bytes().to_vec()));
        assert!(candidates.contains(&1_i32.to_le_bytes().to_vec()));
        assert!(candidates.contains(&(-1_i32).to_le_bytes().to_vec()));
        assert!(candidates.contains(&i32::MIN.to_le_bytes().to_vec()));
        assert!(candidates.contains(&i32::MAX.to_le_bytes().to_vec()));
    }

    #[test]
    fn string_candidates_use_dictionary_when_available() {
        let dictionary = Dictionary::from_tokens([&b"alpha"[..], &b"beta"[..]]);

        assert_eq!(
            typed_candidates(TypedValueKind::String, &dictionary),
            vec![b"alpha".to_vec(), b"beta".to_vec()]
        );
    }
}
