// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand, ValueEnum};
use llm_harness_gen::{
    memory_aware_byte_limit, prepare_assistance, AnthropicMessagesProvider, AssistanceKind,
    AssistanceRequest, Evidence, Language, LlmProvider, OpenAiCompatibleProvider,
    OpenAiResponsesProvider, SessionCli, SessionCliProvider,
};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Args)]
pub struct LlmArgs {
    #[command(subcommand)]
    command: LlmCommand,
}

#[derive(Debug, Subcommand)]
enum LlmCommand {
    /// Show installed session CLIs and configured API credentials without making a model call
    Status(StatusArgs),
    /// Make a small live request and verify that a provider connection responds
    Test(TestArgs),
    /// Render a workflow-specific prompt for use in the current session or another client
    Prompt(AssistanceArgs),
    /// Send a workflow-specific, evidence-grounded request to a configured provider
    Assist(AssistArgs),
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct TestArgs {
    #[command(flatten)]
    provider: ProviderArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AssistArgs {
    #[command(flatten)]
    request: AssistanceArgs,
    #[command(flatten)]
    provider: ProviderArgs,
    /// Wrap the completion and provider metadata in JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AssistanceArgs {
    /// Assistance workflow; this changes the grounding and verification instructions.
    #[arg(long, value_enum)]
    task: TaskName,
    /// The question to answer. Evidence files are optional when this is supplied.
    #[arg(long)]
    question: Option<String>,
    /// Bounded evidence file to include (repeatable): source, logs, run.json, or finding JSON.
    #[arg(long = "input", value_name = "FILE")]
    inputs: Vec<PathBuf>,
    /// Target symbol, required for generate-harness.
    #[arg(long)]
    target_symbol: Option<String>,
    /// Target language when known.
    #[arg(long, value_enum)]
    language: Option<LanguageName>,
}

#[derive(Debug, Clone, Args)]
struct ProviderArgs {
    /// Backend: cached Codex/Claude login, OpenAI/Anthropic API, or local OpenAI-compatible server.
    #[arg(long, value_enum, default_value = "codex")]
    provider: ProviderName,
    /// Model identifier. API/local providers require this; session CLIs use their configured default when omitted.
    #[arg(long)]
    model: Option<String>,
    /// Override the provider base URL (for gateways and local servers).
    #[arg(long)]
    base_url: Option<String>,
    /// Environment variable containing the API key. Keys are never accepted as command-line values.
    #[arg(long)]
    api_key_env: Option<String>,
    /// Provider wall-clock timeout.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
    /// Maximum output tokens requested from HTTP providers.
    #[arg(long, default_value_t = 4096)]
    max_output_tokens: u32,
    /// Override the Codex or Claude executable path.
    #[arg(long)]
    bin: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderName {
    Codex,
    Claude,
    Openai,
    Anthropic,
    Local,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TaskName {
    PlanRun,
    GenerateHarness,
    AnalyzeFindings,
    ExplainCode,
    DiagnoseError,
}

impl From<TaskName> for AssistanceKind {
    fn from(value: TaskName) -> Self {
        match value {
            TaskName::PlanRun => Self::PlanRun,
            TaskName::GenerateHarness => Self::GenerateHarness,
            TaskName::AnalyzeFindings => Self::AnalyzeFindings,
            TaskName::ExplainCode => Self::ExplainCode,
            TaskName::DiagnoseError => Self::DiagnoseError,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LanguageName {
    Ada,
    C,
    Cpp,
}

impl From<LanguageName> for Language {
    fn from(value: LanguageName) -> Self {
        match value {
            LanguageName::Ada => Self::Ada,
            LanguageName::C => Self::C,
            LanguageName::Cpp => Self::Cpp,
        }
    }
}

#[derive(Serialize)]
struct StatusReport {
    codex_cli: ExecutableStatus,
    claude_cli: ExecutableStatus,
    openai_api_key: bool,
    anthropic_api_key: bool,
    local_default_url: &'static str,
    response_byte_limit: usize,
    note: &'static str,
}

#[derive(Serialize)]
struct ExecutableStatus {
    installed: bool,
    path: Option<PathBuf>,
}

#[derive(Serialize)]
struct TestReport {
    provider: ProviderName,
    model: Option<String>,
    connected: bool,
    elapsed_ms: u128,
    response_bytes: usize,
}

#[derive(Serialize)]
struct AssistReport<'a> {
    provider: ProviderName,
    model: Option<&'a str>,
    completion: &'a str,
}

pub fn run(args: LlmArgs) -> i32 {
    match args.command {
        LlmCommand::Status(args) => status(args),
        LlmCommand::Test(args) => test_provider(args),
        LlmCommand::Prompt(args) => prompt(args),
        LlmCommand::Assist(args) => assist(args),
    }
}

fn status(args: StatusArgs) -> i32 {
    let executable = |name: &str| match which::which(name) {
        Ok(path) => ExecutableStatus {
            installed: true,
            path: Some(path),
        },
        Err(_) => ExecutableStatus {
            installed: false,
            path: None,
        },
    };
    let report = StatusReport {
        codex_cli: executable("codex"),
        claude_cli: executable("claude"),
        openai_api_key: env_has_value("OPENAI_API_KEY"),
        anthropic_api_key: env_has_value("ANTHROPIC_API_KEY"),
        local_default_url: "http://127.0.0.1:11434/v1",
        response_byte_limit: memory_aware_byte_limit("GOVFUZZ_LLM_MAX_RESPONSE_BYTES"),
        note: "installed does not prove authentication; use `govfuzz llm test`. MCP mode needs no GovFuzz API token.",
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!(
            "codex={} claude={} openai_key={} anthropic_key={} response_limit_bytes={}",
            report.codex_cli.installed,
            report.claude_cli.installed,
            report.openai_api_key,
            report.anthropic_api_key,
            report.response_byte_limit
        );
        println!("{}", report.note);
    }
    0
}

fn test_provider(args: TestArgs) -> i32 {
    let provider = match build_provider(&args.provider) {
        Ok(provider) => provider,
        Err(error) => {
            gfeprintln!("{error}");
            return 2;
        }
    };
    let started = Instant::now();
    let completion = match provider.complete(
        "This is a GovFuzz provider connectivity test. Follow the requested exact output.",
        "Reply with exactly GOVFUZZ_LLM_OK and no other text.",
    ) {
        Ok(completion) => completion,
        Err(error) => {
            gfeprintln!("LLM connection failed: {error}");
            return 1;
        }
    };
    if !completion.contains("GOVFUZZ_LLM_OK") {
        gfeprintln!("LLM connection responded but did not return the verification marker");
        return 1;
    }
    let report = TestReport {
        provider: args.provider.provider,
        model: args.provider.model,
        connected: true,
        elapsed_ms: started.elapsed().as_millis(),
        response_bytes: completion.len(),
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!(
            "provider={:?} connected=true elapsed_ms={} response_bytes={}",
            report.provider, report.elapsed_ms, report.response_bytes
        );
    }
    0
}

fn prompt(args: AssistanceArgs) -> i32 {
    match build_prompt(args) {
        Ok(prompt) => {
            println!("{}", serde_json::to_string_pretty(&prompt).unwrap());
            0
        }
        Err(error) => {
            gfeprintln!("{error}");
            2
        }
    }
}

fn assist(args: AssistArgs) -> i32 {
    let prompt = match build_prompt(args.request) {
        Ok(prompt) => prompt,
        Err(error) => {
            gfeprintln!("{error}");
            return 2;
        }
    };
    let provider = match build_provider(&args.provider) {
        Ok(provider) => provider,
        Err(error) => {
            gfeprintln!("{error}");
            return 2;
        }
    };
    match provider.complete(&prompt.system_prompt, &prompt.user_prompt) {
        Ok(completion) if args.json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&AssistReport {
                    provider: args.provider.provider,
                    model: args.provider.model.as_deref(),
                    completion: &completion,
                })
                .unwrap()
            );
            0
        }
        Ok(completion) => {
            println!("{completion}");
            0
        }
        Err(error) => {
            gfeprintln!("LLM assistance failed: {error}");
            1
        }
    }
}

fn build_prompt(args: AssistanceArgs) -> Result<llm_harness_gen::PreparedPrompt, String> {
    let budget = memory_aware_byte_limit("GOVFUZZ_LLM_MAX_EVIDENCE_BYTES");
    let mut remaining = budget;
    let mut evidence = Vec::new();
    for path in args.inputs {
        let bytes = read_bounded(&path, remaining)?;
        let text = decode_bounded_lossy(&bytes, remaining).map_err(|()| {
            format!(
                "decoded evidence {} exceeds the memory-aware {remaining}-byte remaining budget; set GOVFUZZ_LLM_MAX_EVIDENCE_BYTES to override",
                path.display()
            )
        })?;
        remaining = remaining.saturating_sub(text.len());
        evidence.push(Evidence {
            label: path.display().to_string(),
            text,
        });
    }
    prepare_assistance(&AssistanceRequest {
        kind: args.task.into(),
        question: args.question,
        target_symbol: args.target_symbol,
        language: args.language.map(Into::into),
        evidence,
    })
    .map_err(|error| error.to_string())
}

fn read_bounded(path: &Path, remaining: usize) -> Result<Vec<u8>, String> {
    if remaining == 0 {
        return Err(
            "LLM evidence budget exhausted; set GOVFUZZ_LLM_MAX_EVIDENCE_BYTES to override"
                .to_owned(),
        );
    }
    let file = std::fs::File::open(path)
        .map_err(|error| format!("read evidence {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((remaining as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read evidence {}: {error}", path.display()))?;
    if bytes.len() > remaining {
        return Err(format!(
            "evidence exceeds the memory-aware {remaining}-byte remaining budget; set GOVFUZZ_LLM_MAX_EVIDENCE_BYTES to override"
        ));
    }
    Ok(bytes)
}

fn decode_bounded_lossy(mut bytes: &[u8], limit: usize) -> Result<String, ()> {
    let mut text = String::with_capacity(bytes.len().min(limit));
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                if valid.len() > limit.saturating_sub(text.len()) {
                    return Err(());
                }
                text.push_str(valid);
                return Ok(text);
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len > limit.saturating_sub(text.len()) {
                    return Err(());
                }
                text.push_str(std::str::from_utf8(&bytes[..valid_len]).map_err(|_| ())?);
                if '\u{fffd}'.len_utf8() > limit.saturating_sub(text.len()) {
                    return Err(());
                }
                text.push('\u{fffd}');
                let Some(error_len) = error.error_len() else {
                    return Ok(text);
                };
                bytes = &bytes[valid_len + error_len..];
            }
        }
    }
}

fn build_provider(args: &ProviderArgs) -> Result<Box<dyn LlmProvider>, String> {
    let timeout = Duration::from_secs(args.timeout_secs);
    let working_dir = std::env::current_dir().ok();
    match args.provider {
        ProviderName::Codex | ProviderName::Claude => {
            if args.base_url.is_some() || args.api_key_env.is_some() {
                return Err(
                    "--base-url and --api-key-env do not apply to session CLI providers".to_owned(),
                );
            }
            let (kind, default_bin) = match args.provider {
                ProviderName::Codex => (SessionCli::Codex, "codex"),
                ProviderName::Claude => (SessionCli::Claude, "claude"),
                _ => unreachable!(),
            };
            Ok(Box::new(SessionCliProvider {
                kind,
                bin: args
                    .bin
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(default_bin)),
                model: args.model.clone(),
                working_dir,
                timeout: Some(timeout),
            }))
        }
        ProviderName::Openai => {
            reject_bin(args)?;
            let model = required_model(args)?;
            let key = read_api_key(args.api_key_env.as_deref().unwrap_or("OPENAI_API_KEY"))?;
            let mut provider = OpenAiResponsesProvider::new(model, key);
            if let Some(base_url) = &args.base_url {
                provider.base_url = base_url.clone();
            }
            provider.timeout = timeout;
            provider.max_output_tokens = args.max_output_tokens;
            Ok(Box::new(provider))
        }
        ProviderName::Anthropic => {
            reject_bin(args)?;
            let model = required_model(args)?;
            let key = read_api_key(args.api_key_env.as_deref().unwrap_or("ANTHROPIC_API_KEY"))?;
            let mut provider = AnthropicMessagesProvider::new(model, key);
            if let Some(base_url) = &args.base_url {
                provider.base_url = base_url.clone();
            }
            provider.timeout = timeout;
            provider.max_output_tokens = args.max_output_tokens;
            Ok(Box::new(provider))
        }
        ProviderName::Local => {
            reject_bin(args)?;
            let model = required_model(args)?;
            let mut provider = OpenAiCompatibleProvider::new(model);
            if let Some(base_url) = &args.base_url {
                provider.base_url = base_url.clone();
            }
            if let Some(name) = &args.api_key_env {
                provider.api_key = Some(read_api_key(name)?);
            }
            provider.timeout = timeout;
            provider.max_output_tokens = args.max_output_tokens;
            Ok(Box::new(provider))
        }
    }
}

fn required_model(args: &ProviderArgs) -> Result<String, String> {
    args.model.clone().ok_or_else(|| {
        format!(
            "--model is required for {:?}; model defaults change, so GovFuzz does not silently select one",
            args.provider
        )
    })
}

fn reject_bin(args: &ProviderArgs) -> Result<(), String> {
    if args.bin.is_some() {
        Err("--bin only applies to codex and claude session CLI providers".to_owned())
    } else {
        Ok(())
    }
}

fn read_api_key(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("environment variable {name} is not set or is empty"))
}

fn env_has_value(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_provider_requires_explicit_model() {
        let args = ProviderArgs {
            provider: ProviderName::Openai,
            model: None,
            base_url: None,
            api_key_env: None,
            timeout_secs: 1,
            max_output_tokens: 1,
            bin: None,
        };
        assert!(build_provider(&args).err().unwrap().contains("--model"));
    }

    #[test]
    fn prompt_builder_reads_bounded_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("link.log");
        std::fs::write(&path, "undefined reference to parse_packet").unwrap();
        let prompt = build_prompt(AssistanceArgs {
            task: TaskName::DiagnoseError,
            question: None,
            inputs: vec![path],
            target_symbol: None,
            language: Some(LanguageName::Cpp),
        })
        .unwrap();
        assert!(prompt.user_prompt.contains("undefined reference"));
    }

    #[test]
    fn lossy_evidence_decoding_never_exceeds_its_budget() {
        assert_eq!(decode_bounded_lossy(b"a\xffb", 5).unwrap(), "a\u{fffd}b");
        assert!(decode_bounded_lossy(b"a\xffb", 4).is_err());
    }
}
