// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum HarnessGenError {
    #[error("target subprogram '{0}' not found in AST")]
    TargetNotFound(String),
    // The message is supplied verbatim by the caller (each call site
    // builds a complete, human-readable sentence); the variant does not
    // wrap it, so reasons don't end up doubly-prefixed when surfaced in
    // `govfuzz auto --verbose` and `run.json`.
    #[error("{0}")]
    UnsupportedParamType(String),
    /// An untrusted build input (a compile flag, source path, or
    /// include directory from a scanned tree / compile_commands.json)
    /// contained a shell/make metacharacter and was refused before it
    /// could reach a generated Makefile recipe. Prevents command
    /// injection at `make` time.
    #[error("{0}")]
    UnsafeBuildInput(String),
    #[error("template render failure: {0}")]
    TemplateRender(#[from] tera::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}
