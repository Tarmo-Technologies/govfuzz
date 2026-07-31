// SPDX-License-Identifier: Apache-2.0

use config::Profile;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const ADAPTER_SCHEMA_VERSION: &str = "govfuzz.binary.adapter.v1";

#[derive(Debug, clap::Args)]
pub struct BinaryAdapterArgs {
    /// Binary artifact to analyze.
    pub target: PathBuf,

    /// Adapter kind to run.
    #[arg(long, value_enum)]
    pub adapter: AdapterKind,

    /// Output directory for binary-adapter-report.json.
    #[arg(long)]
    pub out: PathBuf,

    /// Mock adapter JSON output for deterministic contract tests.
    #[arg(long)]
    pub mock_output: Option<PathBuf>,

    /// Local adapter executable. Missing tools are reported as skipped.
    #[arg(long)]
    pub tool: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AdapterKind {
    Mock,
    Rizin,
    Ghidra,
    Angr,
}

impl AdapterKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Rizin => "rizin",
            Self::Ghidra => "ghidra",
            Self::Angr => "angr",
        }
    }

    fn default_tool(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Rizin => "rizin",
            Self::Ghidra => "analyzeHeadless",
            Self::Angr => "python3",
        }
    }

    fn is_external(self) -> bool {
        !matches!(self, Self::Mock)
    }
}

pub fn run(args: BinaryAdapterArgs, profile: Profile) -> i32 {
    if !adapter_allowed(profile, args.adapter) {
        gfeprintln!(
            "binary adapter '{}' is not allowed for profile '{}'",
            args.adapter.as_str(),
            profile.as_str()
        );
        return 2;
    }

    let result = match args.adapter {
        AdapterKind::Mock => run_mock(&args),
        AdapterKind::Rizin | AdapterKind::Ghidra | AdapterKind::Angr => run_real_smoke(&args),
    };
    match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            gfeprintln!("{error}");
            1
        }
    }
}

fn adapter_allowed(profile: Profile, adapter: AdapterKind) -> bool {
    if !adapter.is_external() {
        return true;
    }
    let allowed = profile.allowed_subprocesses();
    allowed.contains(&"*") || allowed.contains(&adapter.as_str())
}

fn run_mock(args: &BinaryAdapterArgs) -> Result<i32, String> {
    let Some(mock_output) = args.mock_output.as_deref() else {
        return Err("--mock-output is required for the mock adapter".to_owned());
    };
    let value: Value = serde_json::from_slice(
        &fs::read(mock_output)
            .map_err(|error| format!("read {}: {error}", mock_output.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", mock_output.display()))?;
    let status = value.get("status").and_then(Value::as_str).unwrap_or("ok");
    let report = if status == "error" {
        base_report(args, "error", "mock_fixture")
            .with_arrays(&value)
            .with_error(
                "adapter_error",
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("mock adapter error"),
            )
            .finish()
    } else {
        base_report(args, "ok", "mock_fixture")
            .with_arrays(&value)
            .finish()
    };
    write_report(&args.out, &report)?;
    Ok(if status == "error" { 1 } else { 0 })
}

fn run_real_smoke(args: &BinaryAdapterArgs) -> Result<i32, String> {
    let tool = args
        .tool
        .clone()
        .unwrap_or_else(|| PathBuf::from(args.adapter.default_tool()));
    match Command::new(&tool).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_owned();
            let mut report = base_report(args, "smoke_tested", "external_subprocess").finish();
            report["tool"] = json!({
                "path": tool.to_string_lossy(),
                "version": version
            });
            write_report(&args.out, &report)?;
            Ok(0)
        }
        Ok(output) => {
            let mut report = base_report(args, "error", "external_subprocess")
                .with_error("tool_error", String::from_utf8_lossy(&output.stderr).trim())
                .finish();
            report["tool"] = json!({ "path": tool.to_string_lossy() });
            write_report(&args.out, &report)?;
            Ok(1)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut report = base_report(args, "skipped", "external_subprocess")
                .with_error("tool_not_found", "adapter executable was not found")
                .finish();
            report["tool"] = json!({ "path": tool.to_string_lossy() });
            write_report(&args.out, &report)?;
            Ok(0)
        }
        Err(error) => Err(format!("run {}: {error}", tool.display())),
    }
}

struct ReportBuilder {
    value: Value,
}

fn base_report(args: &BinaryAdapterArgs, status: &str, trust_boundary: &str) -> ReportBuilder {
    ReportBuilder {
        value: json!({
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "target": args.target.to_string_lossy(),
            "status": status,
            "evidence_kind": "adapter_derived",
            "adapter": {
                "kind": args.adapter.as_str(),
                "trust_boundary": trust_boundary,
                "linked_into_govfuzz": false
            },
            "functions": [],
            "call_graph": [],
            "strings": [],
            "xrefs": [],
            "errors": []
        }),
    }
}

impl ReportBuilder {
    fn with_arrays(mut self, value: &Value) -> Self {
        for key in ["functions", "call_graph", "strings", "xrefs"] {
            if let Some(items) = value.get(key).and_then(Value::as_array) {
                self.value[key] = Value::Array(items.clone());
            }
        }
        self
    }

    fn with_error(mut self, reason: &str, message: &str) -> Self {
        self.value["errors"] = json!([{
            "reason": reason,
            "message": message
        }]);
        self
    }

    fn finish(self) -> Value {
        self.value
    }
}

fn write_report(out_dir: &PathBuf, report: &Value) -> Result<(), String> {
    fs::create_dir_all(out_dir)
        .map_err(|error| format!("create {}: {error}", out_dir.display()))?;
    let path = out_dir.join("binary-adapter-report.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write {}: {error}", path.display()))
}
