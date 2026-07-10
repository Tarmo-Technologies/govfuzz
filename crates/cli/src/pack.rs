// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(subcommand)]
    pub command: PackCommand,
}

#[derive(Debug, Subcommand)]
pub enum PackCommand {
    /// Create a deterministic air-gapped update pack manifest.
    Create(CreateArgs),
    /// Inspect an air-gapped update pack manifest without installing it.
    Inspect(InspectArgs),
    /// Install a verified update pack into a local offline directory.
    Install(InstallArgs),
    /// Verify an air-gapped update pack manifest.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub pack_id: String,
    #[arg(long)]
    pub version: Option<String>,
    /// Pack item in kind:path form. Repeat for each item.
    #[arg(long = "item")]
    pub items: Vec<String>,
    #[arg(long)]
    pub license: Option<String>,
    /// External tool required by every item in this pack. Repeatable.
    #[arg(long = "required-tool")]
    pub required_tools: Vec<String>,
    /// Offline signing key identifier for the deterministic sha256-items-v1 digest.
    #[arg(long = "sign-key")]
    pub sign_key: Option<String>,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    pub manifest: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    pub manifest: PathBuf,
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub install_dir: PathBuf,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Update pack manifest JSON file.
    pub manifest: PathBuf,

    /// Root directory used to resolve manifest item paths.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Write verification summary JSON to this path.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Optional policy file used to deny pack kinds, licenses, or required tools.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

pub fn run(args: PackArgs) -> i32 {
    match args.command {
        PackCommand::Create(args) => create(args),
        PackCommand::Inspect(args) => write_summary(
            governance::inspect_update_pack_file(&args.manifest),
            args.out,
        ),
        PackCommand::Install(args) => {
            let summary = governance::install_update_pack_file(
                &args.manifest,
                &args.root,
                &args.install_dir,
                args.policy.as_deref(),
            );
            write_summary(summary, args.out)
        }
        PackCommand::Verify(args) => verify(args),
    }
}

fn create(args: CreateArgs) -> i32 {
    match governance::create_update_pack_file(
        &args.root,
        &args.pack_id,
        args.version.as_deref(),
        &args.items,
        args.license.as_deref(),
        &args.required_tools,
        args.sign_key.as_deref(),
        &args.out,
    ) {
        Ok(manifest) => {
            let items = manifest
                .get("items")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len);
            println!("update pack manifest: {items} items");
            0
        }
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}

fn verify(args: VerifyArgs) -> i32 {
    match governance::verify_update_pack_file_with_policy(
        &args.manifest,
        &args.root,
        args.policy.as_deref(),
    ) {
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
                        eprintln!("serialize update pack verification: {error}");
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
