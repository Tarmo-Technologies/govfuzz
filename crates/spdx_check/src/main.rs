// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "spdx_check")]
#[command(about = "Check and generate govfuzz SPDX metadata")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check,
    Generate,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = PathBuf::from(".");

    match args.command {
        Command::Check => spdx_check::check(&root),
        Command::Generate => spdx_check::generate(&root),
    }
}
