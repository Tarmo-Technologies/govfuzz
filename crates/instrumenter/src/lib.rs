// SPDX-License-Identifier: Apache-2.0

pub use breadcrumbs::Breadcrumb;
pub use error::InstrumenterError;
pub use instrument::{
    breadcrumbs_sidecar_json, instrument_unit, line_map_sidecar_json,
    parse_breadcrumbs_sidecar_json, BreadcrumbSidecar, InstrumentArgs, InstrumentedFile,
    LineMapSidecar,
};
pub use rewriter::LineMap;

pub mod breadcrumbs;
pub mod context_clauses;
pub mod edge_cases;
pub mod error;
pub mod handlers;
pub mod instrument;
pub mod raises;
pub mod rewriter;

#[cfg(test)]
mod tests {
    use crate::InstrumenterError;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn error_display_for_non_utf8_path() {
        let error = InstrumenterError::NonUtf8Path(PathBuf::from("src.adb"));

        assert!(error.to_string().contains("source path is not utf-8"));
        assert!(error.to_string().contains("src.adb"));
    }

    #[test]
    fn error_display_for_ast_source_mismatch_includes_name() {
        let error = InstrumenterError::AstSourceMismatch("Parse".to_owned());

        assert!(error.to_string().contains("Parse"));
        assert!(error.to_string().contains("ast and source disagree"));
    }

    #[test]
    fn error_io_wraps_std_io() {
        let error = InstrumenterError::from(io::Error::new(io::ErrorKind::NotFound, "missing"));

        assert!(error.to_string().contains("io error"));
        assert!(error.to_string().contains("missing"));
    }
}
