// SPDX-License-Identifier: Apache-2.0

use crate::StubNeed;

#[derive(Debug, thiserror::Error)]
pub enum StubGenError {
    #[error("diagnostic JSON malformed: {0}")]
    JsonMalformed(#[from] serde_json::Error),
    #[error("compiler adapter error: {0}")]
    CompilerAdapter(#[from] compiler_adapter::CompilerError),
    #[error("project synthesis error: {0}")]
    ProjectSynth(#[from] project_synth::ProjectSynthError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("max iterations ({max}) exceeded; last needs: {needs:?}")]
    MaxIterations { max: u32, needs: Vec<StubNeed> },
}
