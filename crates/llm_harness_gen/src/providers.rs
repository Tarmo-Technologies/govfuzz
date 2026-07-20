// SPDX-License-Identifier: Apache-2.0

use crate::process::memory_aware_byte_limit;
use crate::{LlmError, LlmProvider};
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4096;

fn endpoint(base: &str, suffix: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

fn response_json(response: ureq::Response) -> Result<Value, LlmError> {
    let limit = memory_aware_byte_limit("GOVFUZZ_LLM_MAX_RESPONSE_BYTES");
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| LlmError::Provider(format!("read provider response: {error}")))?;
    if bytes.len() > limit {
        return Err(LlmError::ResponseTooLarge { limit });
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LlmError::Provider(format!("decode provider JSON: {error}")))
}

fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    body: Value,
    timeout: Duration,
) -> Result<Value, LlmError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();
    let mut request = agent.post(url).set("content-type", "application/json");
    for (name, value) in headers {
        request = request.set(name, value);
    }
    match request.send_json(body) {
        Ok(response) => response_json(response),
        Err(ureq::Error::Status(code, response)) => {
            let detail = response_json(response)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/error/message")
                        .or_else(|| value.pointer("/error/error/message"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "provider returned an error".to_owned());
            Err(LlmError::Provider(format!("HTTP {code}: {detail}")))
        }
        Err(ureq::Error::Transport(error)) => {
            Err(LlmError::Provider(format!("request {url}: {error}")))
        }
    }
}

fn nonempty(text: String) -> Result<String, LlmError> {
    if text.trim().is_empty() {
        Err(LlmError::EmptyCompletion)
    } else {
        Ok(text)
    }
}

pub struct OpenAiResponsesProvider {
    pub base_url: String,
    pub model: String,
    api_key: String,
    pub max_output_tokens: u32,
    pub timeout: Duration,
}

impl OpenAiResponsesProvider {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: "https://api.openai.com/v1".to_owned(),
            model: model.into(),
            api_key: api_key.into(),
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            timeout: Duration::from_secs(180),
        }
    }
}

impl LlmProvider for OpenAiResponsesProvider {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let authorization = format!("Bearer {}", self.api_key);
        let response = post_json(
            &endpoint(&self.base_url, "responses"),
            &[("authorization", authorization.as_str())],
            json!({
                "model": self.model,
                "instructions": system_prompt,
                "input": user_prompt,
                "max_output_tokens": self.max_output_tokens,
            }),
            self.timeout,
        )?;
        if let Some(text) = response.get("output_text").and_then(Value::as_str) {
            return nonempty(text.to_owned());
        }
        let text = response
            .get("output")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("content").and_then(Value::as_array))
            .flatten()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("output_text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        nonempty(text)
    }
}

pub struct AnthropicMessagesProvider {
    pub base_url: String,
    pub model: String,
    api_key: String,
    pub max_output_tokens: u32,
    pub timeout: Duration,
}

impl AnthropicMessagesProvider {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: "https://api.anthropic.com/v1".to_owned(),
            model: model.into(),
            api_key: api_key.into(),
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            timeout: Duration::from_secs(180),
        }
    }
}

impl LlmProvider for AnthropicMessagesProvider {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let response = post_json(
            &endpoint(&self.base_url, "messages"),
            &[
                ("x-api-key", self.api_key.as_str()),
                ("anthropic-version", "2023-06-01"),
            ],
            json!({
                "model": self.model,
                "system": system_prompt,
                "max_tokens": self.max_output_tokens,
                "messages": [{"role": "user", "content": user_prompt}],
            }),
            self.timeout,
        )?;
        let text = response
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        nonempty(text)
    }
}

/// OpenAI-compatible Chat Completions transport for Ollama, llama.cpp,
/// LM Studio, and compatible self-hosted gateways.
pub struct OpenAiCompatibleProvider {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub max_output_tokens: u32,
    pub timeout: Duration,
}

impl OpenAiCompatibleProvider {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            base_url: "http://127.0.0.1:11434/v1".to_owned(),
            model: model.into(),
            api_key: None,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            timeout: Duration::from_secs(180),
        }
    }
}

impl LlmProvider for OpenAiCompatibleProvider {
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let authorization = self.api_key.as_ref().map(|key| format!("Bearer {key}"));
        let headers = authorization
            .as_deref()
            .map(|value| vec![("authorization", value)])
            .unwrap_or_default();
        let response = post_json(
            &endpoint(&self.base_url, "chat/completions"),
            &headers,
            json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": self.max_output_tokens,
                "stream": false,
            }),
            self.timeout,
        )?;
        let text = response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        nonempty(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn mock_json(response_body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                {
                    content_length = value.parse().unwrap();
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
            format!("{request_line}{}", String::from_utf8_lossy(&body))
        });
        (url, thread)
    }

    #[test]
    fn openai_responses_request_and_response_match_protocol() {
        let (base_url, server) = mock_json(
            r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"OPENAI_OK"}]}]}"#,
        );
        let mut provider = OpenAiResponsesProvider::new("test-model", "test-key");
        provider.base_url = base_url;
        let output = provider.complete("system", "user").unwrap();
        assert_eq!(output, "OPENAI_OK");
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /responses HTTP/1.1"));
        assert!(request.contains("\"instructions\":\"system\""));
        assert!(request.contains("\"input\":\"user\""));
    }

    #[test]
    fn anthropic_messages_request_and_response_match_protocol() {
        let (base_url, server) = mock_json(r#"{"content":[{"type":"text","text":"CLAUDE_OK"}]}"#);
        let mut provider = AnthropicMessagesProvider::new("test-model", "test-key");
        provider.base_url = base_url;
        let output = provider.complete("system", "user").unwrap();
        assert_eq!(output, "CLAUDE_OK");
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /messages HTTP/1.1"));
        assert!(request.contains("\"system\":\"system\""));
        assert!(request.contains("\"messages\":[{\"content\":\"user\",\"role\":\"user\"}]"));
    }

    #[test]
    fn compatible_chat_request_and_response_match_protocol() {
        let (base_url, server) = mock_json(r#"{"choices":[{"message":{"content":"LOCAL_OK"}}]}"#);
        let mut provider = OpenAiCompatibleProvider::new("local-model");
        provider.base_url = base_url;
        let output = provider.complete("system", "user").unwrap();
        assert_eq!(output, "LOCAL_OK");
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /chat/completions HTTP/1.1"));
        assert!(request.contains("\"model\":\"local-model\""));
    }
}
