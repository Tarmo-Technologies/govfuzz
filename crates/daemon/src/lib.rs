// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{AdaStandard, Span, StructuralAst, SubprogramId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

pub fn crate_name() -> &'static str {
    "govfuzz-daemon"
}

pub fn run_json_rpc<R: BufRead, W: Write>(reader: R, writer: W) -> Result<(), JsonRpcServerError> {
    run_json_rpc_with_security(reader, writer, DaemonSecurityConfig::local_single_user())
}

pub fn run_json_rpc_with_security<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    security: DaemonSecurityConfig,
) -> Result<(), JsonRpcServerError> {
    while let Some(frame) = read_frame(&mut reader)? {
        let response = match serde_json::from_slice::<JsonRpcRequest>(&frame) {
            Ok(request) => handle_json_rpc_request(request, &security),
            Err(error) => Some(error_response(
                Value::Null,
                RpcFailure::invalid_request(format!("invalid JSON-RPC request: {error}")),
            )),
        };

        if let Some(response) = response {
            write_frame(&mut writer, &serde_json::to_vec(&response)?)?;
        }
    }

    Ok(())
}

/// Run a Model Context Protocol server over newline-delimited stdio. In this
/// mode the host Codex/Claude session does the reasoning; GovFuzz exposes
/// deterministic analysis and prompt/preflight tools, so no API token is
/// required by the server.
pub fn run_mcp<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
) -> Result<(), JsonRpcServerError> {
    let limit = llm_harness_gen::memory_aware_byte_limit("GOVFUZZ_MCP_MAX_MESSAGE_BYTES");
    while let Some(line) = read_mcp_line(&mut reader, limit)? {
        if line.is_empty() {
            continue;
        }
        let response = match serde_json::from_slice::<McpRequest>(&line) {
            Ok(request) => handle_mcp_request(request),
            Err(error) => Some(error_response(
                Value::Null,
                RpcFailure::invalid_request(format!("invalid MCP JSON-RPC request: {error}")),
            )),
        };
        if let Some(response) = response {
            write_mcp_message(&mut writer, &response, limit)?;
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

fn handle_mcp_request(request: McpRequest) -> Option<Value> {
    let Some(id) = request.id else {
        // MCP notifications (notably notifications/initialized) do not receive
        // responses. Unknown notifications are also safely ignored.
        return None;
    };
    if request.jsonrpc != "2.0" {
        return Some(error_response(
            id,
            RpcFailure::invalid_request("jsonrpc must be \"2.0\""),
        ));
    }
    let result = match request.method.as_str() {
        "initialize" => initialize_mcp(request.params),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": mcp_tools()})),
        "tools/call" => call_mcp_tool(request.params),
        _ => Err(RpcFailure::method_not_found()),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => error_response(id, error),
    })
}

fn initialize_mcp(params: Option<Value>) -> Result<Value, RpcFailure> {
    const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
    let requested = params
        .as_ref()
        .and_then(|value| value.get("protocolVersion"))
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFailure::invalid_params("initialize requires protocolVersion"))?;
    let protocol = if SUPPORTED.contains(&requested) {
        requested
    } else {
        SUPPORTED[0]
    };
    Ok(json!({
        "protocolVersion": protocol,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {
            "name": "govfuzz",
            "title": "GovFuzz",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Deterministic fuzzing evidence and LLM-assistance tools"
        },
        "instructions": "Use GovFuzz tools for observed facts. The current host model may reason over their output without giving GovFuzz an API token. Treat prepared prompts and preflight results as advisory; build, replay, and fuzz results are authoritative."
    }))
}

fn mcp_tools() -> Vec<Value> {
    let default_target_limit = mcp_default_target_limit();
    let default_findings_limit = mcp_default_findings_limit();
    let read_only_annotations = || {
        json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        })
    };
    vec![
        json!({
            "name": "govfuzz_scan",
            "description": "Deterministically summarize Ada source structure under a repository path. Read-only; no LLM call.",
            "annotations": read_only_annotations(),
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "govfuzz_list_targets",
            "description": "Deterministically discover and rank Ada/C/C++ fuzz targets. Read-only; top defaults from the current MCP message budget and can be set explicitly.",
            "annotations": read_only_annotations(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "top": {"type": "integer", "minimum": 1, "default": default_target_limit}
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "govfuzz_load_findings",
            "description": "Load normalized GovFuzz findings for evidence-grounded triage. Read-only; top defaults from the current MCP message budget and can be set explicitly.",
            "annotations": read_only_annotations(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "findings": {"type": "string"},
                    "top": {"type": "integer", "minimum": 1, "default": default_findings_limit}
                },
                "required": ["findings"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "govfuzz_prepare_assistance",
            "description": "Prepare an injection-aware, evidence-grounded prompt for run planning, harness generation, finding analysis, code explanation, or error diagnosis. The current MCP host session supplies the model reasoning; GovFuzz uses no API token.",
            "annotations": read_only_annotations(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["plan_run", "generate_harness", "analyze_findings", "explain_code", "diagnose_error"]},
                    "question": {"type": "string"},
                    "target_symbol": {"type": "string"},
                    "language": {"type": "string", "enum": ["ada", "c", "cpp"]},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"label": {"type": "string"}, "text": {"type": "string"}},
                            "required": ["label", "text"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["kind"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "govfuzz_preflight_harness",
            "description": "Perform a cheap structural check of an LLM-produced harness candidate. This never claims compilation, linking, reachability, or coverage; follow with deterministic GovFuzz build/fuzz validation.",
            "annotations": read_only_annotations(),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_symbol": {"type": "string"},
                    "language": {"type": "string", "enum": ["ada", "c", "cpp"]},
                    "source": {"type": "string"}
                },
                "required": ["target_symbol", "language", "source"],
                "additionalProperties": false
            }
        }),
    ]
}

fn mcp_default_target_limit() -> usize {
    // Reserve ample space for paths, score breakdowns, spans, and protocol
    // framing. This is a dynamic output budget, not a discovery ceiling:
    // callers can still request an explicit positive `top` value.
    (llm_harness_gen::memory_aware_byte_limit("GOVFUZZ_MCP_MAX_MESSAGE_BYTES") / 4096).max(1)
}

fn mcp_default_findings_limit() -> usize {
    (llm_harness_gen::memory_aware_byte_limit("GOVFUZZ_MCP_MAX_MESSAGE_BYTES") / (16 * 1024)).max(1)
}

#[derive(Debug, Deserialize)]
struct McpCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct McpAssistanceParams {
    kind: String,
    #[serde(default)]
    question: Option<String>,
    #[serde(default)]
    target_symbol: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    evidence: Vec<llm_harness_gen::Evidence>,
}

#[derive(Debug, Deserialize)]
struct McpHarnessParams {
    target_symbol: String,
    language: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct McpFindingsParams {
    findings: PathBuf,
    #[serde(default)]
    top: Option<usize>,
}

fn call_mcp_tool(params: Option<Value>) -> Result<Value, RpcFailure> {
    let params = parse_params::<McpCallParams>(params)?;
    let result = match params.name.as_str() {
        "govfuzz_scan" => {
            dispatch_json_rpc_method("scan", Some(params.arguments), &AuthorizedIdentity::Local)
        }
        "govfuzz_list_targets" => {
            let mut parsed: ListTargetsRpcParams = serde_json::from_value(params.arguments)
                .map_err(|error| RpcFailure::invalid_params(error.to_string()))?;
            parsed.top = Some(parsed.top.unwrap_or_else(mcp_default_target_limit));
            to_result(list_targets(parsed.path, parsed.top))
        }
        "govfuzz_load_findings" => {
            let parsed: McpFindingsParams = serde_json::from_value(params.arguments)
                .map_err(|error| RpcFailure::invalid_params(error.to_string()))?;
            to_result(load_findings_limited(
                parsed.findings,
                parsed.top.unwrap_or_else(mcp_default_findings_limit),
            ))
        }
        "govfuzz_prepare_assistance" => {
            let params: McpAssistanceParams = serde_json::from_value(params.arguments)
                .map_err(|error| RpcFailure::invalid_params(error.to_string()))?;
            let kind = params
                .kind
                .parse()
                .map_err(|error: llm_harness_gen::LlmError| {
                    RpcFailure::invalid_params(error.to_string())
                })?;
            let language = params
                .language
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|error: llm_harness_gen::LlmError| {
                    RpcFailure::invalid_params(error.to_string())
                })?;
            llm_harness_gen::prepare_assistance(&llm_harness_gen::AssistanceRequest {
                kind,
                question: params.question,
                target_symbol: params.target_symbol,
                language,
                evidence: params.evidence,
            })
            .and_then(|prompt| {
                serde_json::to_value(prompt)
                    .map_err(|error| llm_harness_gen::LlmError::Provider(error.to_string()))
            })
            .map_err(|error| RpcFailure::invalid_params(error.to_string()))
        }
        "govfuzz_preflight_harness" => {
            let params: McpHarnessParams = serde_json::from_value(params.arguments)
                .map_err(|error| RpcFailure::invalid_params(error.to_string()))?;
            let language =
                params
                    .language
                    .parse()
                    .map_err(|error: llm_harness_gen::LlmError| {
                        RpcFailure::invalid_params(error.to_string())
                    })?;
            serde_json::to_value(llm_harness_gen::preflight_harness(
                &params.target_symbol,
                language,
                &params.source,
            ))
            .map_err(|error| RpcFailure::server_error(error.to_string()))
        }
        _ => Err(RpcFailure::invalid_params(format!(
            "unknown MCP tool `{}`",
            params.name
        ))),
    };
    match result {
        Ok(value) => Ok(mcp_tool_result(value, false)),
        Err(error) => Ok(mcp_tool_result(
            json!({"error": error.message, "code": error.code}),
            true,
        )),
    }
}

fn mcp_tool_result(value: Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|error| format!("serialize GovFuzz MCP result: {error}"));
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error
    })
}

fn read_mcp_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, JsonRpcServerError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index);
        if line.len().saturating_add(take) > limit {
            return Err(JsonRpcServerError::InvalidFrame(format!(
                "MCP message exceeds the memory-aware {limit}-byte limit; set GOVFUZZ_MCP_MAX_MESSAGE_BYTES to override"
            )));
        }
        line.extend_from_slice(&available[..take]);
        let consumed = take + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

fn write_mcp_message<W: Write>(
    writer: &mut W,
    response: &Value,
    limit: usize,
) -> Result<(), JsonRpcServerError> {
    let bytes = serde_json::to_vec(response)?;
    if bytes.len() > limit {
        return Err(JsonRpcServerError::InvalidFrame(format!(
            "MCP response exceeds the memory-aware {limit}-byte limit; narrow the request or set GOVFUZZ_MCP_MAX_MESSAGE_BYTES"
        )));
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonSecurityConfig {
    LocalSingleUser,
    WorkspaceShared(TenantConfig),
    MultiTenant(Vec<TenantConfig>),
}

impl DaemonSecurityConfig {
    pub fn local_single_user() -> Self {
        Self::LocalSingleUser
    }

    pub fn workspace_shared(tenant: TenantConfig) -> Self {
        Self::WorkspaceShared(tenant)
    }

    pub fn multi_tenant(tenants: Vec<TenantConfig>) -> Self {
        Self::MultiTenant(tenants)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantConfig {
    pub tenant: String,
    pub token: String,
    pub workspace_root: PathBuf,
    pub role: DaemonRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRole {
    Viewer,
    Operator,
    WorkspaceAdmin,
}

#[derive(Clone, Debug, Serialize)]
struct AuditMetadata {
    tenant: Option<String>,
    role: DaemonRole,
    method: String,
    workspace_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
enum AuthorizedIdentity {
    Local,
    Tenant(TenantConfig),
}

impl AuthorizedIdentity {
    fn audit_metadata(&self, method: &str) -> Option<AuditMetadata> {
        match self {
            Self::Local => None,
            Self::Tenant(tenant) => Some(AuditMetadata {
                tenant: Some(tenant.tenant.clone()),
                role: tenant.role,
                method: method.to_owned(),
                workspace_root: Some(tenant.workspace_root.clone()),
            }),
        }
    }
}

#[derive(Debug)]
pub enum JsonRpcServerError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidFrame(String),
}

impl fmt::Display for JsonRpcServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error in JSON-RPC server: {error}"),
            Self::Json(error) => write!(formatter, "JSON error in JSON-RPC server: {error}"),
            Self::InvalidFrame(message) => write!(formatter, "invalid JSON-RPC frame: {message}"),
        }
    }
}

impl std::error::Error for JsonRpcServerError {}

impl From<std::io::Error> for JsonRpcServerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for JsonRpcServerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    auth: Option<JsonRpcAuth>,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcAuth {
    #[serde(default)]
    tenant: Option<String>,
    token: String,
}

#[derive(Debug)]
struct RpcFailure {
    code: i32,
    message: String,
}

impl RpcFailure {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    fn method_not_found() -> Self {
        Self {
            code: -32601,
            message: "method not found".to_owned(),
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn server_error(message: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: message.into(),
        }
    }

    fn authentication_required() -> Self {
        Self {
            code: -32001,
            message: "authentication required".to_owned(),
        }
    }

    fn permission_denied(message: impl Into<String>) -> Self {
        Self {
            code: -32002,
            message: message.into(),
        }
    }

    fn workspace_denied(message: impl Into<String>) -> Self {
        Self {
            code: -32003,
            message: message.into(),
        }
    }
}

fn handle_json_rpc_request(
    request: JsonRpcRequest,
    security: &DaemonSecurityConfig,
) -> Option<Value> {
    let id = request.id;
    let Some(response_id) = id.clone() else {
        let _ = authorize_request(security, request.auth.as_ref()).and_then(|identity| {
            dispatch_json_rpc_method(&request.method, request.params, &identity)
        });
        return None;
    };

    if request.jsonrpc != "2.0" {
        return Some(error_response(
            response_id,
            RpcFailure::invalid_request("jsonrpc must be \"2.0\""),
        ));
    }

    Some(
        match authorize_request(security, request.auth.as_ref()).and_then(|identity| {
            dispatch_json_rpc_method(&request.method, request.params, &identity)
                .map(|result| (result, identity))
        }) {
            Ok((result, identity)) => {
                let mut response = json!({
                    "jsonrpc": "2.0",
                    "id": response_id,
                    "result": result,
                });
                if let Some(audit) = identity.audit_metadata(&request.method) {
                    response["govfuzzAudit"] = serde_json::to_value(audit)
                        .unwrap_or_else(|error| json!({ "error": error.to_string() }));
                }
                response
            }
            Err(error) => error_response(response_id, error),
        },
    )
}

fn dispatch_json_rpc_method(
    method: &str,
    params: Option<Value>,
    identity: &AuthorizedIdentity,
) -> Result<Value, RpcFailure> {
    match method {
        "scan" => {
            let params = parse_params::<PathParams>(params)?;
            authorize_method(identity, MethodAccess::ReadWorkspace)?;
            authorize_path(identity, &params.path)?;
            to_result(scan(params.path))
        }
        "listTargets" => {
            let params = parse_params::<ListTargetsRpcParams>(params)?;
            authorize_method(identity, MethodAccess::ReadWorkspace)?;
            authorize_path(identity, &params.path)?;
            to_result(list_targets(params.path, params.top))
        }
        "findings" => {
            let params = parse_params::<FindingsParams>(params)?;
            authorize_method(identity, MethodAccess::ReadWorkspace)?;
            authorize_path(identity, &params.findings)?;
            to_result(load_findings(params.findings))
        }
        "rankAt" => {
            let params = parse_params::<RankAtParams>(params)?;
            authorize_method(identity, MethodAccess::ReadWorkspace)?;
            authorize_path(identity, &params.path)?;
            to_result(rank_at(params))
        }
        "instrumentPreview" => {
            let params = parse_params::<PathParams>(params)?;
            authorize_method(identity, MethodAccess::OperateWorkspace)?;
            authorize_path(identity, &params.path)?;
            to_result(instrument_preview(params.path))
        }
        "staticScan" => {
            let params = parse_params::<StaticScanParams>(params)?;
            authorize_method(identity, MethodAccess::OperateWorkspace)?;
            authorize_path(identity, &params.path)?;
            authorize_optional_path(identity, params.suppressions.as_deref())?;
            authorize_optional_path(identity, params.baseline.as_deref())?;
            authorize_optional_path(identity, params.policy.as_deref())?;
            if let Some(out) = params.out.as_deref() {
                authorize_output_path(identity, out)?;
            }
            to_result(static_scan(params))
        }
        _ => Err(RpcFailure::method_not_found()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MethodAccess {
    ReadWorkspace,
    OperateWorkspace,
}

fn authorize_request(
    security: &DaemonSecurityConfig,
    auth: Option<&JsonRpcAuth>,
) -> Result<AuthorizedIdentity, RpcFailure> {
    match security {
        DaemonSecurityConfig::LocalSingleUser => Ok(AuthorizedIdentity::Local),
        DaemonSecurityConfig::WorkspaceShared(tenant) => {
            authorize_tenant(std::slice::from_ref(tenant), auth)
        }
        DaemonSecurityConfig::MultiTenant(tenants) => authorize_tenant(tenants, auth),
    }
}

fn authorize_tenant(
    tenants: &[TenantConfig],
    auth: Option<&JsonRpcAuth>,
) -> Result<AuthorizedIdentity, RpcFailure> {
    let Some(auth) = auth else {
        return Err(RpcFailure::authentication_required());
    };
    tenants
        .iter()
        .find(|tenant| {
            auth.tenant
                .as_deref()
                .is_none_or(|requested| requested == tenant.tenant)
                && auth.token == tenant.token
        })
        .cloned()
        .map(AuthorizedIdentity::Tenant)
        .ok_or_else(RpcFailure::authentication_required)
}

fn authorize_method(identity: &AuthorizedIdentity, access: MethodAccess) -> Result<(), RpcFailure> {
    let AuthorizedIdentity::Tenant(tenant) = identity else {
        return Ok(());
    };
    match (tenant.role, access) {
        (DaemonRole::Viewer, MethodAccess::OperateWorkspace) => Err(RpcFailure::permission_denied(
            "role viewer cannot perform workspace operations",
        )),
        _ => Ok(()),
    }
}

fn authorize_path(identity: &AuthorizedIdentity, path: &Path) -> Result<(), RpcFailure> {
    let AuthorizedIdentity::Tenant(tenant) = identity else {
        return Ok(());
    };
    let root = canonicalize_for_auth(&tenant.workspace_root)?;
    let target = canonicalize_for_auth(path)?;
    if target.starts_with(&root) {
        Ok(())
    } else {
        Err(RpcFailure::workspace_denied(format!(
            "path {} is outside authorized workspace {}",
            path.display(),
            tenant.workspace_root.display()
        )))
    }
}

fn authorize_optional_path(
    identity: &AuthorizedIdentity,
    path: Option<&Path>,
) -> Result<(), RpcFailure> {
    if let Some(path) = path {
        authorize_path(identity, path)?;
    }
    Ok(())
}

fn authorize_output_path(identity: &AuthorizedIdentity, path: &Path) -> Result<(), RpcFailure> {
    let AuthorizedIdentity::Tenant(_) = identity else {
        return Ok(());
    };
    if path.exists() {
        return authorize_path(identity, path);
    }
    let mut current = path.parent();
    while let Some(parent) = current {
        if parent.exists() {
            return authorize_path(identity, parent);
        }
        current = parent.parent();
    }
    authorize_path(identity, path)
}

fn canonicalize_for_auth(path: &Path) -> Result<PathBuf, RpcFailure> {
    path.canonicalize().map_err(|error| {
        RpcFailure::workspace_denied(format!("authorize path {}: {error}", path.display()))
    })
}

fn to_result<T: Serialize>(result: Result<T, String>) -> Result<Value, RpcFailure> {
    let value = result.map_err(RpcFailure::server_error)?;
    serde_json::to_value(value).map_err(|error| RpcFailure::server_error(error.to_string()))
}

fn parse_params<T: DeserializeOwned>(params: Option<Value>) -> Result<T, RpcFailure> {
    serde_json::from_value(params.unwrap_or_else(|| json!({})))
        .map_err(|error| RpcFailure::invalid_params(error.to_string()))
}

fn error_response(id: Value, error: RpcFailure) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
        },
    })
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, JsonRpcServerError> {
    let limit = llm_harness_gen::memory_aware_byte_limit("GOVFUZZ_DAEMON_MAX_MESSAGE_BYTES");
    read_frame_with_limit(reader, limit)
}

fn read_frame_with_limit<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, JsonRpcServerError> {
    let mut content_length = None;
    let mut saw_header = false;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader
            .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_line(&mut line)?;
        if bytes > limit || (bytes > 0 && !line.ends_with('\n')) {
            return Err(JsonRpcServerError::InvalidFrame(format!(
                "JSON-RPC header line exceeds the memory-aware {limit}-byte limit; set GOVFUZZ_DAEMON_MAX_MESSAGE_BYTES to override"
            )));
        }
        if bytes == 0 {
            if saw_header {
                return Err(JsonRpcServerError::InvalidFrame(
                    "unexpected EOF while reading JSON-RPC headers".to_owned(),
                ));
            }
            return Ok(None);
        }

        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        saw_header = true;

        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = Some(value.trim().parse::<usize>().map_err(|error| {
                    JsonRpcServerError::InvalidFrame(format!("invalid Content-Length: {error}"))
                })?);
            }
        }
    }

    let length = content_length.ok_or_else(|| {
        JsonRpcServerError::InvalidFrame("missing Content-Length header".to_owned())
    })?;
    if length > limit {
        return Err(JsonRpcServerError::InvalidFrame(format!(
            "JSON-RPC frame exceeds the memory-aware {limit}-byte limit; set GOVFUZZ_DAEMON_MAX_MESSAGE_BYTES to override"
        )));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> Result<(), std::io::Error> {
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(body)?;
    writer.flush()
}

#[derive(Debug, Deserialize)]
struct PathParams {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ListTargetsRpcParams {
    path: PathBuf,
    #[serde(default)]
    top: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaticScanFailOn {
    Low,
    Medium,
    High,
    Critical,
}

impl StaticScanFailOn {
    fn as_cli(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Deserialize)]
struct StaticScanParams {
    path: PathBuf,
    #[serde(default)]
    out: Option<PathBuf>,
    #[serde(default)]
    suppressions: Option<PathBuf>,
    #[serde(default)]
    baseline: Option<PathBuf>,
    #[serde(default)]
    policy: Option<PathBuf>,
    #[serde(default, alias = "enabledRules", alias = "enable_rule")]
    enabled_rules: Vec<String>,
    #[serde(default, alias = "disabledRules", alias = "disable_rule")]
    disabled_rules: Vec<String>,
    #[serde(default)]
    sarif: bool,
    #[serde(default)]
    fail_on: Option<StaticScanFailOn>,
}

#[derive(Debug, Deserialize)]
struct FindingsParams {
    #[serde(default = "default_findings_dir")]
    findings: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RankAtParams {
    path: PathBuf,
    line: u32,
    #[serde(default)]
    column: Option<u32>,
}

fn default_findings_dir() -> PathBuf {
    PathBuf::from("findings")
}

#[derive(Debug, Serialize)]
struct ScanResult {
    files: Vec<ScannedFile>,
    total_files: usize,
    total_units: usize,
    total_packages: usize,
    total_subprograms: usize,
    total_handlers: usize,
    total_raises: usize,
}

#[derive(Debug, Serialize)]
struct ScannedFile {
    path: PathBuf,
    ada_standard: Option<AdaStandard>,
    units: usize,
    packages: usize,
    subprograms: usize,
    handlers: usize,
    raises: usize,
}

#[derive(Debug, Serialize)]
struct ListTargetsResult {
    targets: Vec<RpcTarget>,
    total_candidates: usize,
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct RpcTarget {
    file: PathBuf,
    language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subprogram_id: Option<u32>,
    name: String,
    score: i32,
    breakdown: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    decl_span: Option<Span>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_span: Option<Span>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
struct FindingsResult {
    findings: Vec<govfuzz_report::FindingReport>,
    total_findings: usize,
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct RankAtResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<RpcTarget>,
}

#[derive(Debug, Serialize)]
struct InstrumentPreviewResult {
    path: PathBuf,
    rewritten_source: String,
    breadcrumbs: Vec<instrumenter::Breadcrumb>,
}

fn static_scan(params: StaticScanParams) -> Result<Value, String> {
    let out_dir = params
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from("govfuzz_work/static"));
    let options = static_analysis::StaticScanOptions {
        root: params.path,
        out_dir,
        suppressions_path: params.suppressions,
        baseline_path: params.baseline,
        policy_path: params.policy,
        enabled_rules: params.enabled_rules.into_iter().collect::<BTreeSet<_>>(),
        disabled_rules: params.disabled_rules.into_iter().collect::<BTreeSet<_>>(),
        emit_sarif: params.sarif,
    };
    let fail_on = params.fail_on;
    let summary = static_analysis::write_static_scan(&options)
        .map_err(|error| format!("static scan: {error:#}"))?;
    let report: Value = serde_json::from_slice(
        &fs::read(&summary.json_path)
            .map_err(|error| format!("read {}: {error}", summary.json_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", summary.json_path.display()))?;
    let exit_code = if fail_on
        .is_some_and(|threshold| static_severity_gate_trips(&summary.by_severity, threshold))
    {
        1
    } else {
        0
    };

    Ok(json!({
        "exit_code": exit_code,
        "summary": {
            "json_path": display_path(&summary.json_path),
            "markdown_path": display_path(&summary.markdown_path),
            "sarif_path": summary.sarif_path.as_deref().map(display_path),
            "findings_count": summary.findings_count,
            "suppressed_count": summary.suppressed_count,
            "resolved_count": summary.resolved_count,
            "by_severity": summary.by_severity,
        },
        "report": report,
    }))
}

fn static_severity_gate_trips(
    buckets: &std::collections::BTreeMap<String, usize>,
    threshold: StaticScanFailOn,
) -> bool {
    buckets.iter().any(|(severity, count)| {
        *count > 0 && static_severity_rank(severity) >= static_severity_threshold_rank(threshold)
    })
}

fn static_severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn static_severity_threshold_rank(threshold: StaticScanFailOn) -> u8 {
    match threshold {
        StaticScanFailOn::Low => 1,
        StaticScanFailOn::Medium => 2,
        StaticScanFailOn::High => 3,
        StaticScanFailOn::Critical => 4,
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn scan(path: PathBuf) -> Result<ScanResult, String> {
    let mut files = Vec::new();
    for file_path in walk_ada_files(&path)? {
        let (_source, ast) = parse_ada_file(&file_path)?;
        files.push(ScannedFile {
            path: file_path,
            ada_standard: ast.units.first().map(|unit| unit.ada_standard),
            units: ast.units.len(),
            packages: ast.packages.len(),
            subprograms: ast.subprograms.len(),
            handlers: ast.handlers.len(),
            raises: ast.raises.len(),
        });
    }

    Ok(ScanResult {
        total_files: files.len(),
        total_units: files.iter().map(|file| file.units).sum(),
        total_packages: files.iter().map(|file| file.packages).sum(),
        total_subprograms: files.iter().map(|file| file.subprograms).sum(),
        total_handlers: files.iter().map(|file| file.handlers).sum(),
        total_raises: files.iter().map(|file| file.raises).sum(),
        files,
    })
}

fn list_targets(path: PathBuf, top: Option<usize>) -> Result<ListTargetsResult, String> {
    let mut targets = Vec::new();
    let mut total_candidates = 0_usize;
    for file_path in walk_targetable_files(&path)? {
        let mut file_targets = match detect_source_language(&file_path)? {
            Some(SourceLanguage::Ada) => {
                let (_source, ast) = parse_ada_file(&file_path)?;
                ranked_targets_for_ast(&file_path, &ast)
            }
            Some(SourceLanguage::C) => {
                let source = read_source_file(&file_path)?;
                let functions = c_parser::parse_c_functions(&source)
                    .map_err(|error| format!("scan C source {}: {error}", file_path.display()))?;
                ranked_c_targets(&file_path, &functions)
            }
            Some(SourceLanguage::Cpp) => {
                let source = read_source_file(&file_path)?;
                let functions = cpp_parser::parse_cpp_functions(&source)
                    .map_err(|error| format!("scan C++ source {}: {error}", file_path.display()))?;
                ranked_cpp_targets(&file_path, &functions)
            }
            None => Vec::new(),
        };
        total_candidates = total_candidates.saturating_add(file_targets.len());
        targets.append(&mut file_targets);
        if let Some(top) = top {
            let compact_at = top.saturating_mul(2).max(top.saturating_add(1));
            if targets.len() >= compact_at {
                sort_rpc_targets(&mut targets);
                targets.truncate(top);
            }
        }
    }
    sort_rpc_targets(&mut targets);
    if let Some(top) = top {
        targets.truncate(top);
    }

    Ok(ListTargetsResult {
        targets,
        total_candidates,
        truncated: top.is_some_and(|top| total_candidates > top),
    })
}

fn sort_rpc_targets(targets: &mut [RpcTarget]) {
    targets.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.file.cmp(&right.file))
    });
}

fn load_findings(findings: PathBuf) -> Result<FindingsResult, String> {
    let findings = govfuzz_report::load_findings(&findings).map_err(|error| error.to_string())?;
    let total_findings = findings.len();
    Ok(FindingsResult {
        findings,
        total_findings,
        truncated: false,
    })
}

fn load_findings_limited(findings: PathBuf, top: usize) -> Result<FindingsResult, String> {
    let mut result = load_findings(findings)?;
    result.findings.truncate(top);
    result.truncated = result.total_findings > top;
    Ok(result)
}

fn rank_at(params: RankAtParams) -> Result<RankAtResult, String> {
    let (source, ast) = parse_ada_file(&params.path)?;
    let Some(byte_offset) = line_col_to_byte(&source, params.line, params.column.unwrap_or(1))
    else {
        return Ok(RankAtResult { target: None });
    };
    let targets = ranked_targets_for_ast(&params.path, &ast);
    let target = targets.into_iter().find(|target| {
        target
            .body_span
            .or(target.decl_span)
            .is_some_and(|span| span_contains_byte(span, byte_offset))
    });

    Ok(RankAtResult { target })
}

fn instrument_preview(path: PathBuf) -> Result<InstrumentPreviewResult, String> {
    let (source, ast) = parse_ada_file(&path)?;
    let result = instrumenter::instrument_unit(instrumenter::InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &path,
    })
    .map_err(|error| error.to_string())?;

    Ok(InstrumentPreviewResult {
        path,
        rewritten_source: result.rewritten_source,
        breadcrumbs: result.breadcrumbs,
    })
}

fn ranked_targets_for_ast(file: &Path, ast: &StructuralAst) -> Vec<RpcTarget> {
    target_rank::rank_targets(ast)
        .into_iter()
        .filter_map(|target| {
            let subprogram = ast
                .subprograms
                .iter()
                .find(|subprogram| subprogram.id == target.subprogram_id)?;
            Some(RpcTarget {
                file: file.to_path_buf(),
                language: "ada".to_owned(),
                subprogram_id: Some(subprogram_id_value(target.subprogram_id)),
                name: target.name,
                score: target.score,
                breakdown: serde_json::to_value(target.breakdown).unwrap_or(Value::Null),
                decl_span: Some(subprogram.decl_span),
                body_span: subprogram.body_span,
                line: Some(subprogram.decl_span.start_line),
                metadata: None,
            })
        })
        .collect()
}

fn ranked_c_targets(file: &Path, functions: &[c_parser::CFunction]) -> Vec<RpcTarget> {
    target_rank::rank_c_targets(functions)
        .into_iter()
        .map(|target| RpcTarget {
            file: file.to_path_buf(),
            language: "c".to_owned(),
            subprogram_id: None,
            name: target.name,
            score: target.score,
            breakdown: serde_json::to_value(target.breakdown).unwrap_or(Value::Null),
            decl_span: None,
            body_span: None,
            line: Some(target.line),
            metadata: None,
        })
        .collect()
}

fn ranked_cpp_targets(file: &Path, functions: &[cpp_parser::CppFunction]) -> Vec<RpcTarget> {
    target_rank::rank_cpp_targets(functions)
        .into_iter()
        .map(|target| {
            let metadata = functions
                .iter()
                .find(|function| {
                    cpp_rpc_target_name(function) == target.name && function.line == target.line
                })
                .and_then(|function| serde_json::to_value(&function.api).ok());
            RpcTarget {
                file: file.to_path_buf(),
                language: "cpp".to_owned(),
                subprogram_id: None,
                name: target.name,
                score: target.score,
                breakdown: serde_json::to_value(target.breakdown).unwrap_or(Value::Null),
                decl_span: None,
                body_span: None,
                line: Some(target.line),
                metadata,
            }
        })
        .collect()
}

fn cpp_rpc_target_name(function: &cpp_parser::CppFunction) -> String {
    let qualified = if function.qualifier_path.is_empty() {
        function.name.clone()
    } else {
        format!("{}::{}", function.qualifier_path.join("::"), function.name)
    };
    if function
        .api
        .unsupported
        .iter()
        .any(|item| item == "overload_set")
    {
        format!(
            "{}({})",
            qualified,
            function
                .params
                .iter()
                .map(|param| param.cpp_type.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        qualified
    }
}

fn subprogram_id_value(id: SubprogramId) -> u32 {
    id.0
}

fn parse_ada_file(path: &Path) -> Result<(String, StructuralAst), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read Ada source {}: {error}", path.display()))?;
    let ast = ada_parser::reconcile::build_structural_ast(&source, None, path)
        .map_err(|error| format!("scan Ada source {}: {error}", path.display()))?;
    Ok((source, ast))
}

fn walk_ada_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        if is_ada_file(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        return Err(format!(
            "path is not an Ada source file: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "path is neither file nor directory: {}",
            path.display()
        ));
    }

    let mut files = Vec::new();
    collect_ada_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_ada_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|error| format!("read directory {}: {error}", path.display()))?
    {
        let entry = entry
            .map_err(|error| format!("read directory entry in {}: {error}", path.display()))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type for {}: {error}", entry_path.display()))?;
        if file_type.is_dir() {
            collect_ada_files(&entry_path, files)?;
        } else if file_type.is_file() && is_ada_file(&entry_path) {
            files.push(entry_path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceLanguage {
    Ada,
    C,
    Cpp,
}

fn walk_targetable_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        if detect_source_language(path)?.is_some() {
            return Ok(vec![path.to_path_buf()]);
        }
        return Err(format!(
            "path is not a supported Ada/C/C++ source file: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "path is neither file nor directory: {}",
            path.display()
        ));
    }

    let mut files = Vec::new();
    collect_targetable_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_targetable_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|error| format!("read directory {}: {error}", path.display()))?
    {
        let entry = entry
            .map_err(|error| format!("read directory entry in {}: {error}", path.display()))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type for {}: {error}", entry_path.display()))?;
        if file_type.is_dir() {
            collect_targetable_files(&entry_path, files)?;
        } else if file_type.is_file() && detect_source_language(&entry_path)?.is_some() {
            files.push(entry_path);
        }
    }
    Ok(())
}

fn detect_source_language(path: &Path) -> Result<Option<SourceLanguage>, String> {
    if is_ada_file(path) {
        return Ok(Some(SourceLanguage::Ada));
    }
    if is_cpp_file(path) {
        return Ok(Some(SourceLanguage::Cpp));
    }
    if is_c_source_file(path) {
        return Ok(Some(SourceLanguage::C));
    }
    if is_c_header_file(path) {
        return Ok(classify_c_header(path));
    }
    Ok(None)
}

fn classify_c_header(path: &Path) -> Option<SourceLanguage> {
    let source = fs::read_to_string(path).ok()?;
    let c_count = c_parser::parse_c_functions(&source)
        .map(|functions| functions.len())
        .unwrap_or(0);
    let cpp_count = cpp_parser::parse_cpp_functions(&source)
        .map(|functions| functions.len())
        .unwrap_or(0);
    if cpp_count > c_count || header_looks_like_cpp(&source) {
        Some(SourceLanguage::Cpp)
    } else {
        Some(SourceLanguage::C)
    }
}

fn header_looks_like_cpp(source: &str) -> bool {
    [
        "namespace ",
        "template <",
        "template<",
        "class ",
        "typename ",
        "public:",
        "private:",
        "protected:",
        "constexpr",
        "noexcept",
        "operator",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn is_ada_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("adb") || extension.eq_ignore_ascii_case("ads")
        })
}

fn is_c_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "c")
}

fn is_c_header_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("h"))
}

fn is_cpp_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            if extension == "C" {
                return true;
            }
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx"
            )
        })
}

fn read_source_file(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("read source {}: {error}", path.display()))
}

fn line_col_to_byte(source: &str, line: u32, column: u32) -> Option<u32> {
    if line == 0 || column == 0 {
        return None;
    }

    let mut offset = 0usize;
    for (index, line_text) in source.split_inclusive('\n').enumerate() {
        if index + 1 == line as usize {
            let line_without_newline = line_text.trim_end_matches('\n').trim_end_matches('\r');
            let col_offset = (column as usize)
                .saturating_sub(1)
                .min(line_without_newline.len());
            return u32::try_from(offset + col_offset).ok();
        }
        offset += line_text.len();
    }

    if line as usize == source.lines().count() + usize::from(!source.ends_with('\n')) {
        return u32::try_from(source.len()).ok();
    }
    None
}

fn span_contains_byte(span: Span, byte: u32) -> bool {
    span.start_byte <= byte && byte < span.end_byte
}

pub trait GovfuzzRpc {
    fn build(&self, request: BuildRequest) -> RpcCommandResult;
    fn fake_corba(&self, request: FakeCorbaRequest) -> RpcCommandResult;
    fn generate_harness(&self, request: GenerateHarnessRequest) -> RpcCommandResult;
    fn instrument(&self, request: InstrumentRequest) -> RpcCommandResult;
    fn list_targets(&self, request: ListTargetsRequest) -> RpcCommandResult;
    fn minimize(&self, request: MinimizeRequest) -> RpcCommandResult;
    fn model_train(&self, request: ModelTrainRequest) -> RpcCommandResult;
    fn replay(&self, request: ReplayRequest) -> RpcCommandResult;
    fn report(&self, request: ReportRequest) -> RpcCommandResult;
    fn static_scan(&self, request: StaticScanRequest) -> RpcCommandResult;
    fn stub(&self, request: StubRequest) -> RpcCommandResult;
}

pub trait CliRunner {
    fn run(&self, argv: Vec<OsString>) -> i32;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GovfuzzCliRunner;

impl CliRunner for GovfuzzCliRunner {
    fn run(&self, argv: Vec<OsString>) -> i32 {
        cli::run_from(argv)
    }
}

#[derive(Debug, Clone)]
pub struct CliRpcService<R = GovfuzzCliRunner> {
    runner: R,
}

impl Default for CliRpcService<GovfuzzCliRunner> {
    fn default() -> Self {
        Self {
            runner: GovfuzzCliRunner,
        }
    }
}

impl<R> CliRpcService<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: CliRunner> GovfuzzRpc for CliRpcService<R> {
    fn build(&self, request: BuildRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "build");
        argv.push(request.work_dir.into());
        push_optional_flag(&mut argv, "--harness", request.harness);
        push_optional_flag(&mut argv, "--target", request.target);
        push_optional_flag(&mut argv, "--runtime", request.runtime);
        push_optional_flag(&mut argv, "--toolchain", request.toolchain);
        push_optional_flag(&mut argv, "--probe-backend", request.probe_backend);
        self.execute("build", argv)
    }

    fn fake_corba(&self, request: FakeCorbaRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "fake-corba");
        argv.push(request.work_dir.into());
        push_optional_flag(&mut argv, "--source-dir", request.source_dir);
        push_optional_flag(&mut argv, "--idl", request.idl);
        self.execute("fake-corba", argv)
    }

    fn generate_harness(&self, request: GenerateHarnessRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "generate-harness");
        argv.push(request.source.into());
        push_optional_flag(&mut argv, "--target", request.target);
        push_optional_flag(&mut argv, "--output", request.output);
        push_optional_flag(&mut argv, "--id", request.id);
        if let Some(kind) = request.kind {
            argv.push("--kind".into());
            argv.push(kind.as_cli().into());
        }
        self.execute("generate-harness", argv)
    }

    fn instrument(&self, request: InstrumentRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "instrument");
        argv.push(request.source.into());
        push_optional_flag(&mut argv, "--output", request.output);
        self.execute("instrument", argv)
    }

    fn list_targets(&self, request: ListTargetsRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "list-targets");
        argv.push(request.path.into());
        push_optional_flag(&mut argv, "--top", request.top.map(|top| top.to_string()));
        if let Some(format) = request.format {
            argv.push("--format".into());
            argv.push(format.as_cli().into());
        }
        self.execute("list-targets", argv)
    }

    fn minimize(&self, request: MinimizeRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "minimize");
        push_finding_arg(&mut argv, request.finding_dir, request.finding);
        argv.push("--harness".into());
        argv.push(request.harness.into());
        if let Some(strategy) = request.strategy {
            argv.push("--strategy".into());
            argv.push(strategy.as_cli().into());
        }
        self.execute("minimize", argv)
    }

    fn model_train(&self, request: ModelTrainRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "model");
        argv.push("train".into());
        argv.push("--labels".into());
        argv.push(request.labels.into());
        argv.push("--out".into());
        argv.push(request.out.into());
        self.execute("model.train", argv)
    }

    fn replay(&self, request: ReplayRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "replay");
        push_finding_arg(&mut argv, request.finding_dir, request.finding);
        argv.push("--harness".into());
        argv.push(request.harness.into());
        self.execute("replay", argv)
    }

    fn report(&self, request: ReportRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "report");
        push_optional_flag(&mut argv, "--run", request.run);
        push_optional_flag(&mut argv, "--findings", request.findings);
        push_optional_flag(&mut argv, "--out", request.out);
        push_optional_flag(&mut argv, "--model", request.model);
        push_bool_flag(&mut argv, "--sarif", request.sarif);
        push_bool_flag(&mut argv, "--junit", request.junit);
        self.execute("report", argv)
    }

    fn static_scan(&self, request: StaticScanRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "static-scan");
        argv.push(request.path.into());
        push_optional_flag(&mut argv, "--out", request.out);
        push_optional_flag(&mut argv, "--suppressions", request.suppressions);
        push_optional_flag(&mut argv, "--baseline", request.baseline);
        push_optional_flag(&mut argv, "--policy", request.policy);
        for rule in request.enabled_rules {
            argv.push("--enable-rule".into());
            argv.push(rule.into());
        }
        for rule in request.disabled_rules {
            argv.push("--disable-rule".into());
            argv.push(rule.into());
        }
        push_bool_flag(&mut argv, "--sarif", request.sarif);
        if let Some(threshold) = request.fail_on {
            argv.push("--fail-on".into());
            argv.push(threshold.as_cli().into());
        }
        self.execute("static-scan", argv)
    }

    fn stub(&self, request: StubRequest) -> RpcCommandResult {
        let mut argv = command_argv(&request.options, "stub");
        argv.push(request.work_dir.into());
        push_optional_flag(&mut argv, "--harness", request.harness);
        push_optional_flag(&mut argv, "--target", request.target);
        push_optional_flag(&mut argv, "--runtime", request.runtime);
        push_optional_flag(&mut argv, "--toolchain", request.toolchain);
        push_optional_flag(&mut argv, "--probe-backend", request.probe_backend);
        self.execute("stub", argv)
    }
}

impl<R: CliRunner> CliRpcService<R> {
    fn execute(&self, command: &'static str, argv: Vec<OsString>) -> RpcCommandResult {
        let display_argv = display_argv(&argv);
        let exit_code = self.runner.run(argv);
        RpcCommandResult {
            command: command.to_owned(),
            argv: display_argv,
            exit_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpcOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCommandResult {
    pub command: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub work_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_backend: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StubRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub work_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_backend: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeCorbaRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub work_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idl: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateHarnessRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub source: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<HarnessKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessKind {
    Direct,
    Sequence,
    ServantDirect,
}

impl HarnessKind {
    fn as_cli(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Sequence => "sequence",
            Self::ServantDirect => "servant_direct",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrumentRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub source: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTargetsRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<ListTargetsFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListTargetsFormat {
    Table,
    Json,
}

impl ListTargetsFormat {
    fn as_cli(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRequest {
    #[serde(default)]
    pub options: RpcOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<PathBuf>,
    pub harness: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizeRequest {
    #[serde(default)]
    pub options: RpcOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<PathBuf>,
    pub harness: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MinimizeStrategy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimizeStrategy {
    Bytes,
    Typed,
}

impl MinimizeStrategy {
    fn as_cli(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Typed => "typed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    #[serde(default)]
    pub options: RpcOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<PathBuf>,
    #[serde(default)]
    pub sarif: bool,
    #[serde(default)]
    pub junit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticScanRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressions: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_rules: Vec<String>,
    #[serde(default)]
    pub sarif: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<StaticScanFailOn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelTrainRequest {
    #[serde(default)]
    pub options: RpcOptions,
    pub labels: PathBuf,
    pub out: PathBuf,
}

fn command_argv(options: &RpcOptions, command: &'static str) -> Vec<OsString> {
    let mut argv = vec![OsString::from("govfuzz")];
    if let Some(profile) = &options.profile {
        argv.push("--profile".into());
        argv.push(profile.into());
    }
    for probe in &options.probes {
        argv.push("--probe".into());
        argv.push(probe.into());
    }
    argv.push(command.into());
    argv
}

fn push_optional_flag<T: Into<OsString>>(argv: &mut Vec<OsString>, flag: &str, value: Option<T>) {
    if let Some(value) = value {
        argv.push(flag.into());
        argv.push(value.into());
    }
}

fn push_bool_flag(argv: &mut Vec<OsString>, flag: &str, enabled: bool) {
    if enabled {
        argv.push(flag.into());
    }
}

fn push_finding_arg(
    argv: &mut Vec<OsString>,
    finding_dir: Option<PathBuf>,
    finding: Option<PathBuf>,
) {
    if let Some(finding_dir) = finding_dir {
        argv.push(finding_dir.into());
    }
    if let Some(finding) = finding {
        argv.push("--finding".into());
        argv.push(finding.into());
    }
}

fn display_argv(argv: &[OsString]) -> Vec<String> {
    argv.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        BuildRequest, CliRpcService, CliRunner, FakeCorbaRequest, GenerateHarnessRequest,
        GovfuzzRpc, HarnessKind, InstrumentRequest, ListTargetsFormat, ListTargetsRequest,
        MinimizeRequest, MinimizeStrategy, ModelTrainRequest, ReplayRequest, ReportRequest,
        RpcOptions, StaticScanFailOn, StaticScanRequest, StubRequest,
    };
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{BufReader, Write};
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct RecordingRunner {
        calls: Rc<RefCell<Vec<Vec<String>>>>,
        exit_code: i32,
    }

    impl RecordingRunner {
        fn new(exit_code: i32) -> Self {
            Self {
                calls: Rc::new(RefCell::new(Vec::new())),
                exit_code,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
    }

    impl CliRunner for RecordingRunner {
        fn run(&self, argv: Vec<OsString>) -> i32 {
            self.calls.borrow_mut().push(super::display_argv(&argv));
            self.exit_code
        }
    }

    #[test]
    fn list_targets_rpc_delegates_global_options_and_format_to_cli_argv() {
        let runner = RecordingRunner::new(0);
        let service = CliRpcService::new(runner.clone());

        let result = service.list_targets(ListTargetsRequest {
            options: RpcOptions {
                profile: Some("external-tools".to_owned()),
                probes: vec!["gnat_actions".to_owned()],
            },
            path: PathBuf::from("src"),
            top: Some(5),
            format: Some(ListTargetsFormat::Json),
        });

        assert_eq!(result.command, "list-targets");
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            runner.calls()[0],
            [
                "govfuzz",
                "--profile",
                "external-tools",
                "--probe",
                "gnat_actions",
                "list-targets",
                "src",
                "--top",
                "5",
                "--format",
                "json"
            ]
        );
    }

    #[test]
    fn report_rpc_delegates_all_report_flags_to_cli_argv() {
        let runner = RecordingRunner::new(0);
        let service = CliRpcService::new(runner.clone());

        let result = service.report(ReportRequest {
            options: RpcOptions::default(),
            run: Some("ci".to_owned()),
            findings: Some(PathBuf::from("findings")),
            out: Some(PathBuf::from("reports")),
            model: Some(PathBuf::from("model.bin")),
            sarif: true,
            junit: true,
        });

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            result.argv,
            [
                "govfuzz",
                "report",
                "--run",
                "ci",
                "--findings",
                "findings",
                "--out",
                "reports",
                "--model",
                "model.bin",
                "--sarif",
                "--junit"
            ]
        );
        assert_eq!(runner.calls()[0], result.argv);
    }

    #[test]
    fn static_scan_rpc_delegates_policy_triage_and_ci_flags_to_cli_argv() {
        let runner = RecordingRunner::new(0);
        let service = CliRpcService::new(runner.clone());

        let result = service.static_scan(StaticScanRequest {
            options: RpcOptions::default(),
            path: PathBuf::from("src"),
            out: Some(PathBuf::from("work/static")),
            suppressions: Some(PathBuf::from("suppressions.json")),
            baseline: Some(PathBuf::from("baseline.json")),
            policy: Some(PathBuf::from("policy.json")),
            enabled_rules: vec!["GF-408".to_owned()],
            disabled_rules: vec!["GF-406".to_owned()],
            sarif: true,
            fail_on: Some(StaticScanFailOn::High),
        });

        assert_eq!(result.command, "static-scan");
        assert_eq!(
            result.argv,
            [
                "govfuzz",
                "static-scan",
                "src",
                "--out",
                "work/static",
                "--suppressions",
                "suppressions.json",
                "--baseline",
                "baseline.json",
                "--policy",
                "policy.json",
                "--enable-rule",
                "GF-408",
                "--disable-rule",
                "GF-406",
                "--sarif",
                "--fail-on",
                "high"
            ]
        );
        assert_eq!(runner.calls()[0], result.argv);
    }

    #[test]
    fn model_train_rpc_delegates_to_cli_argv() {
        let runner = RecordingRunner::new(0);
        let service = CliRpcService::new(runner.clone());

        let result = service.model_train(ModelTrainRequest {
            options: RpcOptions::default(),
            labels: PathBuf::from("labels.json"),
            out: PathBuf::from("model.bin"),
        });

        assert_eq!(result.command, "model.train");
        assert_eq!(
            runner.calls()[0],
            [
                "govfuzz",
                "model",
                "train",
                "--labels",
                "labels.json",
                "--out",
                "model.bin"
            ]
        );
    }

    #[test]
    fn build_and_stub_rpc_delegate_cross_toolchain_flags_to_cli_argv() {
        let runner = RecordingRunner::new(0);
        let service = CliRpcService::new(runner.clone());

        service.build(BuildRequest {
            options: RpcOptions::default(),
            work_dir: "work".into(),
            harness: Some("H-test".to_owned()),
            target: Some("aarch64-linux-gnu".to_owned()),
            runtime: Some("ravenscar-full".to_owned()),
            toolchain: Some("aarch64-linux-gnu".to_owned()),
            probe_backend: Some("memory_buffer".to_owned()),
        });
        service.stub(StubRequest {
            options: RpcOptions::default(),
            work_dir: "work".into(),
            harness: None,
            target: Some("arm-eabi".to_owned()),
            runtime: Some("light-cortex-m3".to_owned()),
            toolchain: Some("arm-eabi".to_owned()),
            probe_backend: Some("memory_buffer".to_owned()),
        });

        let calls = runner.calls();
        assert_eq!(
            calls[0],
            [
                "govfuzz",
                "build",
                "work",
                "--harness",
                "H-test",
                "--target",
                "aarch64-linux-gnu",
                "--runtime",
                "ravenscar-full",
                "--toolchain",
                "aarch64-linux-gnu",
                "--probe-backend",
                "memory_buffer"
            ]
        );
        assert_eq!(
            calls[1],
            [
                "govfuzz",
                "stub",
                "work",
                "--target",
                "arm-eabi",
                "--runtime",
                "light-cortex-m3",
                "--toolchain",
                "arm-eabi",
                "--probe-backend",
                "memory_buffer"
            ]
        );
    }

    #[test]
    fn current_cli_commands_have_rpc_wrappers() {
        let runner = RecordingRunner::new(7);
        let service = CliRpcService::new(runner.clone());
        let options = RpcOptions::default();

        service.build(BuildRequest {
            options: options.clone(),
            work_dir: "work".into(),
            harness: Some("H-test".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: None,
        });
        assert_eq!(
            service
                .fake_corba(FakeCorbaRequest {
                    options: options.clone(),
                    work_dir: "work".into(),
                    source_dir: Some("src".into()),
                    idl: Some("api.idl".into()),
                })
                .exit_code,
            7
        );
        service.generate_harness(GenerateHarnessRequest {
            options: options.clone(),
            source: "pkg.adb".into(),
            target: Some("Parse".to_owned()),
            output: Some("generated_harnesses".into()),
            id: Some("H-test".to_owned()),
            kind: Some(HarnessKind::ServantDirect),
        });
        service.instrument(InstrumentRequest {
            options: options.clone(),
            source: "pkg.adb".into(),
            output: Some("work/src_instrumented".into()),
        });
        service.minimize(MinimizeRequest {
            options: options.clone(),
            finding_dir: None,
            finding: Some("F-0001".into()),
            harness: "main".into(),
            strategy: Some(MinimizeStrategy::Typed),
        });
        service.replay(ReplayRequest {
            options: options.clone(),
            finding_dir: Some("findings/F-0001".into()),
            finding: None,
            harness: "main".into(),
        });
        service.static_scan(StaticScanRequest {
            options: options.clone(),
            path: "src".into(),
            out: Some("work/static".into()),
            suppressions: None,
            baseline: None,
            policy: None,
            enabled_rules: Vec::new(),
            disabled_rules: Vec::new(),
            sarif: false,
            fail_on: None,
        });
        service.stub(StubRequest {
            options,
            work_dir: "work".into(),
            harness: Some("H-test".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: None,
        });

        let calls = runner.calls();
        assert_eq!(calls[0][1], "build");
        assert_eq!(calls[1][1], "fake-corba");
        assert_eq!(calls[2][1], "generate-harness");
        assert_eq!(calls[2].last().map(String::as_str), Some("servant_direct"));
        assert_eq!(calls[3][1], "instrument");
        assert_eq!(calls[4][1], "minimize");
        assert!(calls[4].contains(&"--finding".to_owned()));
        assert!(calls[4].contains(&"typed".to_owned()));
        assert_eq!(calls[5][1], "replay");
        assert_eq!(calls[6][1], "static-scan");
        assert_eq!(calls[7][1], "stub");
    }

    #[test]
    fn json_rpc_server_handles_scan_and_list_targets_over_lsp_framing() {
        let root = temp_dir("json-rpc-scan-targets");
        let source = root.join("pkg.adb");
        fs::write(
            &source,
            "package body Pkg is\n   procedure Run is begin null; end Run;\nend Pkg;\n",
        )
        .unwrap();
        let request_stream = format!(
            "{}{}",
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "scan",
                "params": { "path": root }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "listTargets",
                "params": { "path": source, "top": 1 }
            }))
        );
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["jsonrpc"], "2.0");
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["total_files"], 1);
        assert_eq!(responses[0]["result"]["total_subprograms"], 1);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["targets"][0]["name"], "run");
        assert_eq!(responses[1]["result"]["total_candidates"], 1);
        assert_eq!(responses[1]["result"]["truncated"], false);
        assert_eq!(
            responses[1]["result"]["targets"][0]["file"].as_str(),
            Some(source.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn json_rpc_server_list_targets_exposes_cpp_api_metadata() {
        let root = temp_dir("json-rpc-cpp-targets");
        let source = root.join("api.cpp");
        fs::write(
            &source,
            r#"
            namespace gov {
            class Parser {
            public:
                int parse(const char *input, std::size_t len) { return 0; }
            };
            }
            "#,
        )
        .unwrap();
        let request_stream = frame(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "listTargets",
            "params": { "path": source, "top": 1 }
        }));
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 1);
        let target = &responses[0]["result"]["targets"][0];
        assert_eq!(target["name"], "gov::Parser::parse");
        assert_eq!(target["language"], "cpp");
        assert_eq!(target["metadata"]["api_kind"], "method");
        assert_eq!(target["metadata"]["class_name"], "Parser");
        assert_eq!(target["metadata"]["namespace_path"][0], "gov");
    }

    #[test]
    fn json_rpc_server_handles_static_scan_over_lsp_framing() {
        let root = temp_dir("json-rpc-static-scan");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("legacy.c"),
            "#include <stdio.h>\nvoid log_line(char *input) { printf(input); }\n",
        )
        .unwrap();
        let out = root.join("static");
        let request_stream = frame(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "static",
            "method": "staticScan",
            "params": {
                "path": src,
                "out": out,
                "sarif": true,
                "fail_on": "high"
            }
        }));
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], "static");
        assert_eq!(responses[0]["result"]["exit_code"], 1);
        assert_eq!(responses[0]["result"]["report"]["counts"]["findings"], 1);
        assert_eq!(
            responses[0]["result"]["report"]["findings"][0]["rule_id"],
            "GF-408"
        );
        assert!(responses[0]["result"]["summary"]["sarif_path"]
            .as_str()
            .unwrap()
            .ends_with("static-report.sarif"));
    }

    #[test]
    fn json_rpc_server_handles_findings_rank_at_and_instrument_preview() {
        let root = temp_dir("json-rpc-ide-methods");
        let source = root.join("pkg.adb");
        fs::write(
            &source,
            "package body Pkg is\n   procedure Parse is\n   begin\n      raise Constraint_Error;\n   exception\n      when Constraint_Error => null;\n   end Parse;\nend Pkg;\n",
        )
        .unwrap();
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-alpha"),
            serde_json::json!({
                "id": "F-0001-alpha",
                "severity": "high",
                "classification": "swallowed_predefined",
                "signature": "abcd",
                "target": { "subprogram": "Parse" }
            }),
        );
        let request_stream = format!(
            "{}{}{}",
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "findings",
                "method": "findings",
                "params": { "findings": findings }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "rank",
                "method": "rankAt",
                "params": { "path": source, "line": 2, "column": 14 }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "preview",
                "method": "instrumentPreview",
                "params": { "path": source }
            }))
        );
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["result"]["findings"][0]["id"], "F-0001-alpha");
        assert_eq!(responses[1]["result"]["target"]["name"], "parse");
        assert!(responses[2]["result"]["rewritten_source"]
            .as_str()
            .unwrap()
            .contains("AdaFuzz.Probe.Breadcrumb"));
        assert!(!responses[2]["result"]["breadcrumbs"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn json_rpc_findings_backfills_actionability_for_older_records() {
        let root = temp_dir("json-rpc-actionability");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-old"),
            serde_json::json!({
                "id": "F-0001-old",
                "severity": "high",
                "classification": "explicit_raise",
                "signature": "abcd",
                "target": { "harness_id": "H-old" },
                "exception": { "handler": { "file": "src/pkg.adb", "line": 9 } }
            }),
        );
        let request_stream = frame(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "findings",
            "method": "findings",
            "params": { "findings": findings }
        }));
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(
            responses[0]["result"]["findings"][0]["actionability"]["verdict"],
            "likely_reachable"
        );
        assert_eq!(
            responses[0]["result"]["findings"][0]["actionability"]["fix_location"]["path"],
            "src/pkg.adb"
        );
    }

    #[test]
    fn json_rpc_server_reports_unknown_method_as_json_rpc_error() {
        let request_stream = frame(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "missingMethod"
        }));
        let mut output = Vec::new();

        super::run_json_rpc(BufReader::new(request_stream.as_bytes()), &mut output).unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], 99);
        assert_eq!(responses[0]["error"]["code"], -32601);
        assert_eq!(responses[0]["error"]["message"], "method not found");
    }

    #[test]
    fn json_rpc_multi_tenant_mode_requires_auth_and_blocks_cross_workspace_paths() {
        let allowed = temp_dir("json-rpc-auth-allowed");
        let denied = temp_dir("json-rpc-auth-denied");
        let allowed_source = allowed.join("pkg.adb");
        let denied_source = denied.join("pkg.adb");
        fs::write(
            &allowed_source,
            "package body Pkg is\n   procedure Run is begin null; end Run;\nend Pkg;\n",
        )
        .unwrap();
        fs::write(
            &denied_source,
            "package body Other is\n   procedure Run is begin null; end Run;\nend Other;\n",
        )
        .unwrap();
        let security = super::DaemonSecurityConfig::multi_tenant(vec![super::TenantConfig {
            tenant: "alpha".to_owned(),
            token: "token-alpha".to_owned(),
            workspace_root: allowed.clone(),
            role: super::DaemonRole::WorkspaceAdmin,
        }]);
        let request_stream = format!(
            "{}{}{}",
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "missing-auth",
                "method": "rankAt",
                "params": { "path": allowed_source, "line": 1 }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "cross-workspace",
                "method": "rankAt",
                "auth": { "tenant": "alpha", "token": "token-alpha" },
                "params": { "path": denied_source, "line": 1 }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "allowed",
                "method": "rankAt",
                "auth": { "tenant": "alpha", "token": "token-alpha" },
                "params": { "path": allowed_source, "line": 1 }
            }))
        );
        let mut output = Vec::new();

        super::run_json_rpc_with_security(
            BufReader::new(request_stream.as_bytes()),
            &mut output,
            security,
        )
        .unwrap();

        let responses = parse_frames(&output);
        assert_eq!(responses[0]["error"]["code"], -32001);
        assert_eq!(responses[1]["error"]["code"], -32003);
        assert_eq!(responses[2]["id"], "allowed");
        assert!(responses[2].get("result").is_some());
    }

    #[test]
    fn json_rpc_multi_tenant_mode_enforces_roles_and_records_audit_metadata() {
        let workspace = temp_dir("json-rpc-rbac");
        let source = workspace.join("pkg.adb");
        fs::write(
            &source,
            "package body Pkg is\n   procedure Run is begin null; end Run;\nend Pkg;\n",
        )
        .unwrap();
        let security = super::DaemonSecurityConfig::multi_tenant(vec![super::TenantConfig {
            tenant: "viewer".to_owned(),
            token: "token-viewer".to_owned(),
            workspace_root: workspace.clone(),
            role: super::DaemonRole::Viewer,
        }]);
        let request_stream = format!(
            "{}{}",
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "read",
                "method": "rankAt",
                "auth": { "tenant": "viewer", "token": "token-viewer" },
                "params": { "path": source, "line": 1 }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "operate",
                "method": "instrumentPreview",
                "auth": { "tenant": "viewer", "token": "token-viewer" },
                "params": { "path": source }
            }))
        );
        let mut output = Vec::new();

        super::run_json_rpc_with_security(
            BufReader::new(request_stream.as_bytes()),
            &mut output,
            security,
        )
        .unwrap();

        let responses = parse_frames(&output);
        assert!(responses[0].get("result").is_some());
        assert_eq!(responses[0]["govfuzzAudit"]["tenant"], "viewer");
        assert_eq!(responses[0]["govfuzzAudit"]["role"], "viewer");
        assert_eq!(responses[0]["govfuzzAudit"]["method"], "rankAt");
        assert_eq!(responses[1]["error"]["code"], -32002);
    }

    #[test]
    fn write_frame_flushes_after_response_body() {
        let mut output = RecordingWriter::default();

        super::write_frame(&mut output, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).unwrap();

        assert_eq!(output.flushes, 1);
        assert!(output
            .bytes
            .ends_with(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#));
    }

    #[test]
    fn json_rpc_reader_rejects_an_oversized_header_before_body_allocation() {
        let input = format!("X-Test: {}\n", "x".repeat(64));
        let error =
            super::read_frame_with_limit(&mut BufReader::new(input.as_bytes()), 32).unwrap_err();
        assert!(error.to_string().contains("header line exceeds"));
    }

    #[test]
    fn mcp_negotiates_lists_tools_and_prepares_session_prompt() {
        let messages = [
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}
                }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "govfuzz_prepare_assistance",
                    "arguments": {
                        "kind": "diagnose_error",
                        "question": "Why did linking fail?",
                        "language": "cpp",
                        "evidence": [{
                            "label": "linker.log",
                            "text": "undefined reference to parse_packet"
                        }]
                    }
                }
            }),
        ];
        let input = messages
            .iter()
            .map(|message| serde_json::to_string(message).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();

        super::run_mcp(BufReader::new(input.as_bytes()), &mut output).unwrap();

        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            responses.len(),
            3,
            "notification must not receive a response"
        );
        assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
        let tools = responses[1]["result"]["tools"].as_array().unwrap();
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "govfuzz_prepare_assistance"));
        assert!(tools
            .iter()
            .find(|tool| tool["name"] == "govfuzz_list_targets")
            .and_then(|tool| tool["inputSchema"]["properties"]["top"]["default"].as_u64())
            .is_some_and(|top| top > 0));
        assert!(tools
            .iter()
            .find(|tool| tool["name"] == "govfuzz_load_findings")
            .and_then(|tool| tool["inputSchema"]["properties"]["top"]["default"].as_u64())
            .is_some_and(|top| top > 0));
        assert!(tools.iter().all(|tool| {
            tool["annotations"]["readOnlyHint"] == true
                && tool["annotations"]["destructiveHint"] == false
                && tool["annotations"]["idempotentHint"] == true
                && tool["annotations"]["openWorldHint"] == false
        }));
        let prepared = responses[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(prepared.contains("undefined reference"));
        assert!(prepared.contains("untrusted data"));
        assert_eq!(responses[2]["result"]["isError"], false);
    }

    #[test]
    fn mcp_harness_preflight_does_not_claim_build_success() {
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "govfuzz_preflight_harness",
                "arguments": {
                    "target_symbol": "parse_packet",
                    "language": "c",
                    "source": "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { parse_packet(d, n); return 0; }"
                }
            }
        });
        let input = serde_json::to_string(&message).unwrap() + "\n";
        let mut output = Vec::new();

        super::run_mcp(BufReader::new(input.as_bytes()), &mut output).unwrap();

        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("requires_build_validation"));
        assert!(text.contains("cannot prove compilation"));
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn frame(value: serde_json::Value) -> String {
        let body = serde_json::to_string(&value).unwrap();
        format!("Content-Length: {}\r\n\r\n{body}", body.len())
    }

    fn parse_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let mut frames = Vec::new();
        let mut rest = text.as_str();
        while !rest.is_empty() {
            let (headers, after_headers) = rest.split_once("\r\n\r\n").unwrap();
            let len = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let (body, remaining) = after_headers.split_at(len);
            frames.push(serde_json::from_str(body).unwrap());
            rest = remaining;
        }
        frames
    }

    fn write_finding(dir: &std::path::Path, finding: serde_json::Value) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&finding).unwrap(),
        )
        .unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-daemon-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
