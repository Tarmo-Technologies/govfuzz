// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum CompilerError {
    #[error("no Ada compiler found on PATH (looked for gprbuild, gnatmake)")]
    NoCompilerFound,
    #[error("which lookup failed: {0}")]
    Which(#[from] which::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("compiler version output unparseable: {raw}")]
    UnparseableVersion { raw: String },
    #[error("compiler canary failed: {stderr}")]
    CanaryFailed { stderr: String },
    #[error("host toolchain {toolchain} for target {target} not found: missing {missing} on PATH")]
    TargetToolchainNotFound {
        toolchain: String,
        target: String,
        missing: String,
    },
    #[error("project-based build requires gprbuild, but only gnatmake was discovered")]
    ProjectBuildRequiresGprbuild,
}
