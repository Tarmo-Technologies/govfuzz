// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum InstrumenterError {
    #[error("source path is not utf-8: {0:?}")]
    NonUtf8Path(PathBuf),
    #[error("ast and source disagree on subprogram '{0}' span")]
    AstSourceMismatch(String),
    #[error("overlapping rewrites at byte ranges {first_start}..{first_end} and {second_start}..{second_end}")]
    OverlappingRewrites {
        first_start: u32,
        first_end: u32,
        second_start: u32,
        second_end: u32,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde_json error: {0}")]
    Json(#[from] serde_json::Error),
}
