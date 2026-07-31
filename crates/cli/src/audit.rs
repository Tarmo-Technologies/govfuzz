// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Append one audit event to a JSONL audit log.
    Append(AppendArgs),
    /// Read and summarize a JSONL audit log.
    Read(ReadArgs),
}

#[derive(Debug, Args)]
pub struct AppendArgs {
    #[arg(long)]
    pub log: PathBuf,
    #[arg(long)]
    pub event: String,
    #[arg(long)]
    pub actor: String,
    #[arg(long)]
    pub role: String,
    #[arg(long)]
    pub project: Option<String>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    #[arg(long)]
    pub log: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: AuditArgs) -> i32 {
    match args.command {
        AuditCommand::Append(args) => {
            let event = governance::append_audit_event(
                &args.log,
                &args.event,
                &args.actor,
                &args.role,
                args.project.as_deref(),
            );
            write_summary(event, args.out)
        }
        AuditCommand::Read(args) => write_summary(governance::read_audit_log(&args.log), args.out),
    }
}

fn write_summary(
    summary: Result<serde_json::Value, governance::GovernanceError>,
    out: Option<PathBuf>,
) -> i32 {
    match summary {
        Ok(summary) => {
            if let Some(out) = out {
                if let Err(error) = governance::write_json(&out, &summary) {
                    gfeprintln!("{error:#}");
                    return 1;
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            }
            0
        }
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
    }
}
