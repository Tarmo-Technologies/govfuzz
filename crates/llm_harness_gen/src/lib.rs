// SPDX-License-Identifier: Apache-2.0

//! LLM-assisted harness generation scaffold.
//!
//! Tracks issue #301. v0.1 ships the LlmProvider trait and the
//! HarnessSuggestion data model. Real network-backed providers
//! (OpenAI, local Ollama, and other providers) land under the
//! `llm-runtime` feature in a follow-up.
//!
//! Strategic note: OSS-Fuzz-Gen and HarnessAgent document the
//! recurring failure where LLMs emit harnesses that compile but
//! don't link to the target. This crate establishes the
//! build-graph-validation hook (`HarnessValidator`) that surrounds
//! every suggestion before it's returned to the caller.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessSuggestion {
    pub target_symbol: String,
    pub language: Language,
    pub source: String,
    pub system_prompt: String,
    pub user_prompt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Ada,
    C,
    Cpp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub compiles: bool,
    pub target_reachable_from_main: bool,
    pub coverage_observed: bool,
    pub diagnostic_messages: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error(
        "LLM harness gen built without the `llm-runtime` feature; rebuild with `--features llm-runtime` once an LlmProvider implementation lands"
    )]
    NotImplemented,
    #[error("provider returned an empty completion")]
    EmptyCompletion,
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

/// An LLM backend that produces a single harness suggestion given
/// the target metadata + prompt. Implementations live in
/// downstream crates (e.g. a feature-gated remote-API provider).
pub trait LlmProvider: Send + Sync {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError>;
}

/// Validates that a candidate harness actually links to the target
/// symbol and exercises its coverage counters. Implementations live
/// in `harness_gen` once this scaffold matures.
pub trait HarnessValidator {
    fn validate(&self, suggestion: &HarnessSuggestion) -> Result<ValidationReport, LlmError>;
}

/// Generate a harness suggestion via LLM and validate it survives
/// build-graph reachability. Retries up to `max_attempts` times
/// when validation fails (e.g. the LLM produced a harness that
/// doesn't link to the target symbol).
pub fn suggest_and_validate(
    provider: &dyn LlmProvider,
    validator: &dyn HarnessValidator,
    target_symbol: &str,
    language: Language,
) -> Result<HarnessSuggestion, LlmError> {
    suggest_and_validate_with(provider, validator, target_symbol, language, 3)
}

/// Same as `suggest_and_validate` but takes an explicit retry
/// budget. Useful for tests and callers who want different
/// retry semantics.
pub fn suggest_and_validate_with(
    provider: &dyn LlmProvider,
    validator: &dyn HarnessValidator,
    target_symbol: &str,
    language: Language,
    max_attempts: u32,
) -> Result<HarnessSuggestion, LlmError> {
    if max_attempts == 0 {
        return Err(LlmError::ValidationFailed(
            "max_attempts must be at least 1".to_owned(),
        ));
    }
    let system_prompt = default_system_prompt().to_owned();
    let mut last_diagnostics: Vec<String> = Vec::new();
    for attempt in 0..max_attempts {
        let user_prompt = render_user_prompt(target_symbol, language, attempt, &last_diagnostics);
        let source = provider.complete(&system_prompt, &user_prompt)?;
        if source.trim().is_empty() {
            return Err(LlmError::EmptyCompletion);
        }
        let suggestion = HarnessSuggestion {
            target_symbol: target_symbol.to_owned(),
            language,
            source,
            system_prompt: system_prompt.clone(),
            user_prompt,
        };
        let report = validator.validate(&suggestion)?;
        if report.compiles && report.target_reachable_from_main && report.coverage_observed {
            return Ok(suggestion);
        }
        last_diagnostics = report.diagnostic_messages;
        last_diagnostics.push(format!(
            "compiles={} reachable={} coverage={}",
            report.compiles, report.target_reachable_from_main, report.coverage_observed
        ));
    }
    Err(LlmError::ValidationFailed(format!(
        "all {max_attempts} attempts failed; last diagnostics: {last_diagnostics:?}"
    )))
}

fn render_user_prompt(
    target_symbol: &str,
    language: Language,
    attempt: u32,
    prior_diagnostics: &[String],
) -> String {
    let lang_name = match language {
        Language::Ada => "Ada",
        Language::C => "C",
        Language::Cpp => "C++",
    };
    let mut out = format!(
        "Write a fuzz harness in {lang_name} that calls the function `{target_symbol}` \
         with a byte buffer derived from the fuzzer input. \
         Produce only the source code with no commentary.",
    );
    if attempt > 0 && !prior_diagnostics.is_empty() {
        out.push_str(&format!(
            "\n\nThis is retry attempt {attempt}. Previous attempts failed with: {prior_diagnostics:?}.\n\
             Fix those issues."
        ));
    }
    out
}

/// Deterministic offline provider for tests and CI: returns the
/// same supplied response regardless of prompt. Useful for unit
/// testing `suggest_and_validate` orchestration without making
/// real LLM calls.
pub struct FixedProvider {
    pub response: String,
}

impl LlmProvider for FixedProvider {
    fn complete(&self, _system_prompt: &str, _user_prompt: &str) -> Result<String, LlmError> {
        Ok(self.response.clone())
    }
}

/// Provider that shells out to a local command, passing the
/// system prompt + user prompt on stdin (separated by a `\n---\n`
/// marker) and reading the completion from stdout. Useful for
/// wrapping a local LLM CLI (e.g. `ollama run <model>`) that
/// reads stdin + writes a completion to stdout — no HTTP client
/// or API-key plumbing required in this crate.
///
/// `timeout` SIGKILLs the child if it hasn't exited within the
/// supplied wall-clock budget. `None` keeps the legacy behaviour of
/// blocking indefinitely. Pick a value when wrapping a remote-backed
/// CLI (e.g. ollama against a slow model) since the retry loop in
/// `suggest_and_validate` can't recover from a hang otherwise.
pub struct LocalCommandProvider {
    pub bin: std::path::PathBuf,
    pub args: Vec<String>,
    pub timeout: Option<std::time::Duration>,
}

impl LlmProvider for LocalCommandProvider {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut cmd = Command::new(&self.bin);
        cmd.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            LlmError::ValidationFailed(format!("spawn {}: {e}", self.bin.display()))
        })?;

        let payload = format!("{system_prompt}\n---\n{user_prompt}");
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| LlmError::ValidationFailed("provider stdin unavailable".to_owned()))?;
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            stdin.write_all(payload.as_bytes())?;
            drop(stdin);
            Ok(())
        });

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| LlmError::ValidationFailed("provider stdout unavailable".to_owned()))?;
        let stdout_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        });
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| LlmError::ValidationFailed("provider stderr unavailable".to_owned()))?;
        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            buf
        });

        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if let Some(t) = self.timeout {
                        if start.elapsed() >= t {
                            let _ = child.kill();
                            timed_out = true;
                            break child
                                .wait()
                                .map_err(|e| LlmError::ValidationFailed(format!("wait: {e}")))?;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(LlmError::ValidationFailed(format!(
                        "wait {}: {e}",
                        self.bin.display()
                    )))
                }
            }
        };
        let _ = writer.join();
        let stdout_bytes = stdout_thread.join().unwrap_or_default();
        let stderr_bytes = stderr_thread.join().unwrap_or_default();

        if timed_out {
            return Err(LlmError::ValidationFailed(format!(
                "{} timed out after {:?}",
                self.bin.display(),
                self.timeout.unwrap_or_default()
            )));
        }
        if !status.success() {
            return Err(LlmError::ValidationFailed(format!(
                "{} exit={:?} stderr={}",
                self.bin.display(),
                status.code(),
                String::from_utf8_lossy(&stderr_bytes)
            )));
        }
        Ok(String::from_utf8_lossy(&stdout_bytes).into_owned())
    }
}

/// Default system prompt for harness generation. Useful for
/// callers that want to pre-render the prompt before backing into
/// a provider.
pub fn default_system_prompt() -> &'static str {
    "You are generating a fuzz harness for govfuzz. Produce a single \
     compilation unit that defines exactly one entry point, accepts a \
     byte buffer, and calls the target function. Do not redefine the \
     target. The harness must compile against the project's existing \
     build configuration."
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysEmptyProvider;
    impl LlmProvider for AlwaysEmptyProvider {
        fn complete(&self, _system: &str, _user: &str) -> Result<String, LlmError> {
            Err(LlmError::EmptyCompletion)
        }
    }

    struct AlwaysOkValidator;
    impl HarnessValidator for AlwaysOkValidator {
        fn validate(&self, _: &HarnessSuggestion) -> Result<ValidationReport, LlmError> {
            Ok(ValidationReport {
                compiles: true,
                target_reachable_from_main: true,
                coverage_observed: true,
                diagnostic_messages: Vec::new(),
            })
        }
    }

    #[test]
    fn suggest_and_validate_returns_empty_completion_error_for_empty_provider() {
        struct EmptyProvider;
        impl LlmProvider for EmptyProvider {
            fn complete(&self, _: &str, _: &str) -> Result<String, LlmError> {
                Ok(String::new())
            }
        }
        let v = AlwaysOkValidator;
        let result = suggest_and_validate(&EmptyProvider, &v, "target_parse", Language::C);
        assert!(matches!(result, Err(LlmError::EmptyCompletion)));
    }

    #[test]
    fn suggest_and_validate_returns_suggestion_when_validator_accepts() {
        let provider = FixedProvider {
            response: "int main() { return 0; }".to_owned(),
        };
        let validator = AlwaysOkValidator;
        let suggestion =
            suggest_and_validate(&provider, &validator, "parse_target", Language::C).unwrap();
        assert_eq!(suggestion.target_symbol, "parse_target");
        assert_eq!(suggestion.language, Language::C);
        assert!(suggestion.source.contains("int main"));
        assert!(suggestion.user_prompt.contains("parse_target"));
    }

    #[test]
    fn suggest_and_validate_propagates_provider_errors() {
        let p = AlwaysEmptyProvider;
        let v = AlwaysOkValidator;
        let result = suggest_and_validate(&p, &v, "target_parse", Language::C);
        assert!(matches!(result, Err(LlmError::EmptyCompletion)));
    }

    #[test]
    fn suggest_and_validate_retries_on_validation_failure_then_returns_validation_error() {
        struct FailingValidator;
        impl HarnessValidator for FailingValidator {
            fn validate(&self, _: &HarnessSuggestion) -> Result<ValidationReport, LlmError> {
                Ok(ValidationReport {
                    compiles: false,
                    target_reachable_from_main: false,
                    coverage_observed: false,
                    diagnostic_messages: vec!["target symbol not linked".to_owned()],
                })
            }
        }
        let provider = FixedProvider {
            response: "harness body".to_owned(),
        };
        let result = suggest_and_validate_with(&provider, &FailingValidator, "x", Language::C, 2);
        assert!(matches!(result, Err(LlmError::ValidationFailed(_))));
    }

    #[test]
    fn suggest_and_validate_max_attempts_zero_is_rejected() {
        let provider = FixedProvider {
            response: "x".to_owned(),
        };
        let validator = AlwaysOkValidator;
        let result = suggest_and_validate_with(&provider, &validator, "x", Language::C, 0);
        assert!(matches!(result, Err(LlmError::ValidationFailed(_))));
    }

    #[test]
    fn render_user_prompt_mentions_target_symbol_and_language() {
        let prompt = super::render_user_prompt("parse_thing", Language::Ada, 0, &[]);
        assert!(prompt.contains("parse_thing"));
        assert!(prompt.contains("Ada"));
        assert!(!prompt.contains("retry"));
    }

    #[test]
    fn render_user_prompt_includes_diagnostics_on_retry() {
        let diagnostics = vec!["target not linked".to_owned()];
        let prompt = super::render_user_prompt("parse_thing", Language::C, 1, &diagnostics);
        assert!(prompt.contains("retry"));
        assert!(prompt.contains("target not linked"));
    }

    #[test]
    fn default_system_prompt_mentions_harness_generation() {
        let p = default_system_prompt();
        assert!(p.contains("fuzz harness"));
        assert!(p.contains("govfuzz"));
    }

    #[test]
    fn harness_suggestion_serializes() {
        let suggestion = HarnessSuggestion {
            target_symbol: "parse".to_owned(),
            language: Language::C,
            source: "int main() { return 0; }".to_owned(),
            system_prompt: "system".to_owned(),
            user_prompt: "user".to_owned(),
        };
        let s = serde_json::to_string(&suggestion).unwrap();
        assert!(s.contains("\"target_symbol\":\"parse\""));
    }

    #[cfg(unix)]
    #[test]
    fn local_command_provider_invokes_external_binary() {
        let provider = LocalCommandProvider {
            bin: std::path::PathBuf::from("/bin/cat"),
            args: Vec::new(),
            timeout: None,
        };
        let out = provider.complete("system-line", "user-line").unwrap();
        assert!(out.contains("system-line"));
        assert!(out.contains("user-line"));
        assert!(out.contains("---"));
    }

    #[cfg(unix)]
    #[test]
    fn local_command_provider_reports_nonzero_exit_as_validation_failed() {
        let provider = LocalCommandProvider {
            bin: std::path::PathBuf::from("/bin/false"),
            args: Vec::new(),
            timeout: None,
        };
        let result = provider.complete("system", "user");
        assert!(matches!(result, Err(LlmError::ValidationFailed(_))));
    }

    #[cfg(unix)]
    #[test]
    fn local_command_provider_times_out_on_hanging_child() {
        let provider = LocalCommandProvider {
            bin: std::path::PathBuf::from("/bin/sleep"),
            args: vec!["60".to_owned()],
            timeout: Some(std::time::Duration::from_millis(250)),
        };
        let start = std::time::Instant::now();
        let result = provider.complete("system", "user");
        let elapsed = start.elapsed();
        assert!(matches!(result, Err(LlmError::ValidationFailed(_))));
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "provider should have killed child within ~timeout, took {elapsed:?}"
        );
    }
}
