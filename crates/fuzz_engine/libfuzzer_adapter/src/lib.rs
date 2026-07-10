// SPDX-License-Identifier: Apache-2.0

pub const LIBFUZZER_ENTRYPOINT_SYMBOL: &str = "LLVMFuzzerTestOneInput";
pub const LIBFUZZER_HARNESS_ARGUMENT: &str = "stdin bytes";
pub const LIBFUZZER_DEFERRED_REASON: &str =
    "libFuzzer adapter deferred until a viable user-supplied Ada/LLVM toolchain exists";

pub fn crate_name() -> &'static str {
    "fuzz_engine_libfuzzer_adapter"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibFuzzerAdapterStatus {
    Deferred,
    Available,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibFuzzerAdapterPlan {
    pub entrypoint_symbol: &'static str,
    pub harness_argument: &'static str,
    pub status: LibFuzzerAdapterStatus,
    pub required_toolchain: &'static str,
    pub strict_permissive_safe: bool,
    pub note: &'static str,
}

impl LibFuzzerAdapterPlan {
    pub fn deferred() -> Self {
        Self {
            entrypoint_symbol: LIBFUZZER_ENTRYPOINT_SYMBOL,
            harness_argument: LIBFUZZER_HARNESS_ARGUMENT,
            status: LibFuzzerAdapterStatus::Deferred,
            required_toolchain:
                "user-supplied LLVM/libFuzzer plus a production-viable Ada frontend",
            strict_permissive_safe: true,
            note: LIBFUZZER_DEFERRED_REASON,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibFuzzerAvailability {
    pub available: bool,
    pub toolchain: Option<String>,
    skip_reason: Option<&'static str>,
}

impl LibFuzzerAvailability {
    pub fn from_toolchain(toolchain: Option<&str>) -> Self {
        let toolchain = toolchain.map(str::to_owned);
        let available = toolchain
            .as_deref()
            .map(has_viable_ada_llvm_toolchain)
            .unwrap_or(false);

        Self {
            available,
            toolchain,
            skip_reason: (!available).then_some(LIBFUZZER_DEFERRED_REASON),
        }
    }

    pub fn skip_reason(&self) -> &str {
        self.skip_reason.unwrap_or("")
    }
}

fn has_viable_ada_llvm_toolchain(toolchain: &str) -> bool {
    let normalized = toolchain.to_ascii_lowercase();
    normalized.contains("llvm") && normalized.contains("ada")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_documents_required_entrypoint_and_user_toolchain() {
        let plan = LibFuzzerAdapterPlan::deferred();

        assert_eq!(plan.entrypoint_symbol, "LLVMFuzzerTestOneInput");
        assert_eq!(plan.harness_argument, "stdin bytes");
        assert_eq!(plan.status, LibFuzzerAdapterStatus::Deferred);
        assert!(plan.required_toolchain.contains("LLVM"));
        assert!(plan.required_toolchain.contains("Ada"));
        assert!(plan.strict_permissive_safe);
    }

    #[test]
    fn unavailable_adapter_reports_skippable_reason() {
        let availability = LibFuzzerAvailability::from_toolchain(None);

        assert!(!availability.available);
        assert!(availability.skip_reason().contains("Ada/LLVM"));
    }

    #[test]
    fn availability_requires_both_ada_and_llvm_markers() {
        assert!(!LibFuzzerAvailability::from_toolchain(Some("LLVM C/C++")).available);
        assert!(!LibFuzzerAvailability::from_toolchain(Some("Ada compiler")).available);
        assert!(LibFuzzerAvailability::from_toolchain(Some("LLVM Ada frontend")).available);
    }
}
