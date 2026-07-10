// SPDX-License-Identifier: Apache-2.0

use crate::CoverageFeedback;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineFeedbackTranslatorConfig {
    pub base_fuzz_count: u32,
    pub exception_signature_bonus: u32,
    pub bitmap_bit_bonus: u32,
    pub max_fuzz_count: u32,
}

impl Default for EngineFeedbackTranslatorConfig {
    fn default() -> Self {
        Self {
            base_fuzz_count: 1,
            exception_signature_bonus: 16,
            bitmap_bit_bonus: 1,
            max_fuzz_count: 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineFeedbackTranslator {
    config: EngineFeedbackTranslatorConfig,
}

impl Default for EngineFeedbackTranslator {
    fn default() -> Self {
        Self::new(EngineFeedbackTranslatorConfig::default())
    }
}

impl EngineFeedbackTranslator {
    pub fn new(config: EngineFeedbackTranslatorConfig) -> Self {
        Self { config }
    }

    pub fn translate_coverage(self, feedback: CoverageFeedback) -> EngineFeedback {
        self.translate_counts(
            feedback.new_exception_signatures,
            feedback.new_bitmap_bits(),
        )
    }

    pub fn translate_counts(
        self,
        new_exception_signatures: u32,
        new_bitmap_bits: u32,
    ) -> EngineFeedback {
        let reason = EngineFeedbackReason::from_counts(new_exception_signatures, new_bitmap_bits);
        let interesting = reason != EngineFeedbackReason::None;
        let fuzz_count = if interesting {
            self.config
                .base_fuzz_count
                .saturating_add(
                    self.config
                        .exception_signature_bonus
                        .saturating_mul(new_exception_signatures),
                )
                .saturating_add(self.config.bitmap_bit_bonus.saturating_mul(new_bitmap_bits))
                .min(self.config.max_fuzz_count.max(1))
        } else {
            0
        };

        EngineFeedback {
            reason,
            new_exception_signatures,
            new_bitmap_bits,
            afl: AflCustomMutatorFeedback {
                queue_get: interesting,
                fuzz_count,
                describe: reason.describe(),
            },
            libafl: LibAflFeedback {
                is_interesting: interesting,
                is_objective: new_exception_signatures > 0,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineFeedback {
    pub reason: EngineFeedbackReason,
    pub new_exception_signatures: u32,
    pub new_bitmap_bits: u32,
    pub afl: AflCustomMutatorFeedback,
    pub libafl: LibAflFeedback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AflCustomMutatorFeedback {
    pub queue_get: bool,
    pub fuzz_count: u32,
    pub describe: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibAflFeedback {
    pub is_interesting: bool,
    pub is_objective: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EngineFeedbackReason {
    #[default]
    None,
    ExceptionSignature,
    BitmapNovelty,
    ExceptionSignatureAndBitmap,
}

impl EngineFeedbackReason {
    fn from_counts(new_exception_signatures: u32, new_bitmap_bits: u32) -> Self {
        match (new_exception_signatures > 0, new_bitmap_bits > 0) {
            (false, false) => Self::None,
            (true, false) => Self::ExceptionSignature,
            (false, true) => Self::BitmapNovelty,
            (true, true) => Self::ExceptionSignatureAndBitmap,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::None => "govfuzz:none",
            Self::ExceptionSignature => "govfuzz:exception-signature",
            Self::BitmapNovelty => "govfuzz:bitmap-novelty",
            Self::ExceptionSignatureAndBitmap => "govfuzz:exception-signature+bitmap",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_signature_feedback_maps_to_afl_and_libafl_objective() {
        let translated = EngineFeedbackTranslator::default().translate_coverage(CoverageFeedback {
            new_exception_signatures: 2,
            ..CoverageFeedback::default()
        });

        assert_eq!(translated.reason, EngineFeedbackReason::ExceptionSignature);
        assert_eq!(translated.new_exception_signatures, 2);
        assert_eq!(translated.new_bitmap_bits, 0);
        assert!(translated.afl.queue_get);
        assert_eq!(translated.afl.fuzz_count, 33);
        assert_eq!(translated.afl.describe, "govfuzz:exception-signature");
        assert!(translated.libafl.is_interesting);
        assert!(translated.libafl.is_objective);
    }

    #[test]
    fn bitmap_feedback_maps_to_corpus_feedback_without_objective() {
        let translated = EngineFeedbackTranslator::default().translate_coverage(CoverageFeedback {
            new_breadcrumb_bits: 3,
            new_handler_bits: 5,
            ..CoverageFeedback::default()
        });

        assert_eq!(translated.reason, EngineFeedbackReason::BitmapNovelty);
        assert_eq!(translated.new_exception_signatures, 0);
        assert_eq!(translated.new_bitmap_bits, 8);
        assert!(translated.afl.queue_get);
        assert_eq!(translated.afl.fuzz_count, 9);
        assert!(translated.libafl.is_interesting);
        assert!(!translated.libafl.is_objective);
    }

    #[test]
    fn empty_feedback_disables_afl_queue_and_libafl_interest() {
        let translated =
            EngineFeedbackTranslator::default().translate_coverage(CoverageFeedback::default());

        assert_eq!(translated.reason, EngineFeedbackReason::None);
        assert!(!translated.afl.queue_get);
        assert_eq!(translated.afl.fuzz_count, 0);
        assert!(!translated.libafl.is_interesting);
        assert!(!translated.libafl.is_objective);
    }

    #[test]
    fn fuzz_count_is_clamped() {
        let config = EngineFeedbackTranslatorConfig {
            max_fuzz_count: 10,
            ..EngineFeedbackTranslatorConfig::default()
        };
        let translated = EngineFeedbackTranslator::new(config).translate_counts(10, 1000);

        assert_eq!(translated.afl.fuzz_count, 10);
    }
}
