// SPDX-License-Identifier: Apache-2.0

pub use build_loop::{run_build_loop, BuildLoopOutcome, BuildLoopResult};
pub use diagnostics::{parse_json, parse_text, Diagnostic, DiagnosticKind, Severity};
pub use error::StubGenError;
pub use manifest::{read_manifest, write_manifest, StubManifest, StubManifestEntry};
pub use needs::{derive_stub_needs, StubNeed, StubNeedKind, StubOp, StubOpKind, StubParam};
pub use synth::{synth_all, synth_stub, StubFile};

pub mod build_loop;
pub mod diagnostics;
pub mod error;
pub mod manifest;
pub mod needs;
pub mod synth;

pub fn crate_name() -> &'static str {
    "stub_gen"
}

#[cfg(test)]
mod tests {
    use crate::{StubGenError, StubNeed, StubNeedKind};

    #[test]
    fn error_display_for_max_iterations_includes_count() {
        let error = StubGenError::MaxIterations {
            max: 8,
            needs: vec![StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageSpec { decls: Vec::new() },
            }],
        };

        let rendered = error.to_string();

        assert!(rendered.contains("max iterations (8) exceeded"));
        assert!(rendered.contains("External_Lib"));
    }

    #[test]
    fn error_compiler_adapter_wraps() {
        let error = StubGenError::from(compiler_adapter::CompilerError::NoCompilerFound);

        assert!(error.to_string().contains("no Ada compiler found"));
    }

    #[test]
    fn error_json_malformed_wraps_serde_error() {
        let source = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let error = StubGenError::from(source);

        assert!(error.to_string().contains("diagnostic JSON malformed"));
    }
}
