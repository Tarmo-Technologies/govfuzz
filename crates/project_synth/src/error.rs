// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum ProjectSynthError {
    #[error("invalid project name '{name}': must be a valid Ada identifier")]
    InvalidProjectName { name: String },
    #[error("source root '{path}' does not exist")]
    MissingSourceRoot { path: std::path::PathBuf },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
