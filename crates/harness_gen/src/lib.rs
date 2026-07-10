// SPDX-License-Identifier: Apache-2.0

pub use error::HarnessGenError;
pub use generate::{
    generate_direct_harness, generate_sequence_harness, generate_servant_direct_harness,
    GenerateDirectArgs, GenerateSequenceArgs, GenerateServantDirectArgs, GeneratedFiles,
};

pub mod build_safety;
pub mod c_decoders;
pub mod c_generate;
pub mod cpp_decoders;
pub mod cpp_generate;
pub mod decoders;
pub mod error;
pub mod generate;
pub mod generic_instance;
pub mod java_generate;
pub mod registry;
pub mod rust_decoders;
pub mod rust_generate;
pub mod stream_init;
pub mod templates;

#[cfg(test)]
mod tests {
    use super::HarnessGenError;

    #[test]
    fn error_display_for_target_not_found_includes_name() {
        let error = HarnessGenError::TargetNotFound("Parse".to_owned());

        assert!(error.to_string().contains("Parse"));
    }

    #[test]
    fn error_display_for_unsupported_param_type_includes_type_name() {
        let error = HarnessGenError::UnsupportedParamType("Root_Record".to_owned());

        assert!(error.to_string().contains("Root_Record"));
    }

    #[test]
    fn error_io_wraps_std_io_error() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "missing harness");
        let error = HarnessGenError::from(source);

        assert!(error.to_string().contains("missing harness"));
    }
}
