// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// GovFuzz work directory to inventory.
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Output manifest path.
    #[arg(long)]
    pub out: PathBuf,

    /// Optional directory to materialize copied export artifacts for air-gapped handoff.
    #[arg(long)]
    pub bundle_dir: Option<PathBuf>,

    /// Policy file to include in the bundle manifest.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Update pack manifest to include. Repeat for multiple packs.
    #[arg(long = "update-pack")]
    pub update_packs: Vec<PathBuf>,

    /// Audit JSONL log to include.
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Runner manifest to include.
    #[arg(long)]
    pub runner_manifest: Option<PathBuf>,

    /// Runner assignment plan to include.
    #[arg(long)]
    pub runner_plan: Option<PathBuf>,

    /// Required artifact kind. Repeatable.
    #[arg(long = "require-artifact")]
    pub required_artifacts: Vec<String>,
}

pub fn run(args: ExportArgs) -> i32 {
    let options = governance::ExportOptions {
        work_dir: args.work_dir,
        out: args.out,
        bundle_dir: args.bundle_dir,
        policy: args.policy,
        update_packs: args.update_packs,
        audit_log: args.audit_log,
        runner_manifest: args.runner_manifest,
        runner_plan: args.runner_plan,
        required_artifacts: args.required_artifacts,
    };

    match governance::write_export_manifest(&options) {
        Ok(manifest) => {
            let artifacts = manifest
                .pointer("/counts/artifacts")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            println!("export manifest: {artifacts} artifacts");
            if manifest
                .pointer("/required_artifacts/missing")
                .and_then(|value| value.as_array())
                .is_some_and(|missing| !missing.is_empty())
            {
                1
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}
