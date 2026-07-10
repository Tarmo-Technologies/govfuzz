// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct RunnersArgs {
    #[command(subcommand)]
    pub command: RunnersCommand,
}

#[derive(Debug, Subcommand)]
pub enum RunnersCommand {
    /// List runner profiles and capability counts.
    List(ListArgs),
    /// Select one runner profile and emit capability evidence.
    Select(SelectArgs),
    /// Create a local offline handoff manifest for a distributed runner.
    Handoff(HandoffArgs),
    /// Lease jobs from a handoff manifest for a distributed runner.
    Lease(LeaseArgs),
    /// Complete a distributed runner lease and attach result artifacts.
    Complete(CompleteArgs),
    /// Plan an offline runner assignment queue under policy and capacity limits.
    Plan(PlanArgs),
    /// Validate an offline runner capability manifest.
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
pub struct ListArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SelectArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub runner: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct HandoffArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub runner: String,
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct LeaseArgs {
    pub handoff: PathBuf,
    #[arg(long)]
    pub runner: String,
    #[arg(long)]
    pub lease_id: String,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct CompleteArgs {
    pub lease: PathBuf,
    #[arg(long)]
    pub artifact: Vec<PathBuf>,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub queue: PathBuf,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Runner manifest JSON file.
    pub path: PathBuf,

    /// Write validation summary JSON to this path.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: RunnersArgs) -> i32 {
    match args.command {
        RunnersCommand::List(args) => {
            write_summary(governance::runner_list_file(&args.path), args.out)
        }
        RunnersCommand::Select(args) => write_summary(
            governance::runner_select_file(&args.path, &args.runner),
            args.out,
        ),
        RunnersCommand::Handoff(args) => match governance::runner_handoff_file(
            &args.path,
            &args.runner,
            &args.work_dir,
            &args.out,
        ) {
            Ok(summary) => {
                if summary.get("valid").and_then(|value| value.as_bool()) == Some(true) {
                    0
                } else {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&summary).unwrap_or_default()
                    );
                    1
                }
            }
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        RunnersCommand::Lease(args) => write_summary(
            governance::runner_lease_file(&args.handoff, &args.runner, &args.lease_id, &args.out),
            None,
        ),
        RunnersCommand::Complete(args) => write_summary(
            governance::runner_complete_file(&args.lease, &args.artifact, &args.out),
            None,
        ),
        RunnersCommand::Plan(args) => match governance::runner_plan_file(
            &args.path,
            &args.queue,
            args.policy.as_deref(),
            &args.out,
        ) {
            Ok(summary) => {
                if summary.get("valid").and_then(|value| value.as_bool()) == Some(true) {
                    0
                } else {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&summary).unwrap_or_default()
                    );
                    1
                }
            }
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        RunnersCommand::Validate(args) => validate(args),
    }
}

fn validate(args: ValidateArgs) -> i32 {
    match governance::validate_runners_file(&args.path) {
        Ok(summary) => {
            if let Some(out) = args.out {
                if let Err(error) = governance::write_json(&out, &summary) {
                    eprintln!("{error:#}");
                    return 1;
                }
            } else {
                match serde_json::to_string_pretty(&summary) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        eprintln!("serialize runner validation: {error}");
                        return 1;
                    }
                }
            }
            if summary.get("valid").and_then(|value| value.as_bool()) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("{error:#}");
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
                    eprintln!("{error:#}");
                    return 1;
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            }
            if summary
                .get("valid")
                .and_then(|value| value.as_bool())
                .unwrap_or(true)
            {
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}
