// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Explain effective policy decisions and policy hash.
    Explain(ExplainArgs),
    /// Evaluate policy decisions against a finding record without running scans.
    DryRun(DryRunArgs),
    /// Validate a GovFuzz policy-as-code document.
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DryRunArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub finding: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Policy JSON file.
    pub path: PathBuf,

    /// Write validation summary JSON to this path.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: PolicyArgs) -> i32 {
    match args.command {
        PolicyCommand::Explain(args) => {
            write_summary(governance::explain_policy_file(&args.path), args.out)
        }
        PolicyCommand::DryRun(args) => write_summary(
            governance::policy_dry_run_file(&args.path, &args.finding),
            args.out,
        ),
        PolicyCommand::Validate(args) => validate(args),
    }
}

fn validate(args: ValidateArgs) -> i32 {
    match governance::validate_policy_file(&args.path) {
        Ok(summary) => {
            if let Some(out) = args.out {
                if let Err(error) = governance::write_json(&out, &summary) {
                    gfeprintln!("{error:#}");
                    return 1;
                }
            } else {
                match serde_json::to_string_pretty(&summary) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        gfeprintln!("serialize policy validation: {error}");
                        return 1;
                    }
                }
            }
            0
        }
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
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
