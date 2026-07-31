// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct DashboardArgs {
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,
    #[arg(long)]
    pub audit_log: Option<PathBuf>,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    #[arg(long)]
    pub runner_manifest: Option<PathBuf>,
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(args: DashboardArgs) -> i32 {
    match governance::dashboard_data(
        &args.work_dir,
        args.audit_log.as_deref(),
        args.policy.as_deref(),
        args.runner_manifest.as_deref(),
    ) {
        Ok(dashboard) => match governance::write_json(&args.out, &dashboard) {
            Ok(()) => 0,
            Err(error) => {
                gfeprintln!("{error:#}");
                1
            }
        },
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
    }
}
