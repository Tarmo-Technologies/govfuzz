// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use config::Profile;
use license_policy::{audit_project_package, LicenseAuditError};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct LicenseAuditArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,

    #[arg(long, default_value = "govfuzz")]
    package: String,
}

pub fn run(args: LicenseAuditArgs, profile: Profile) -> i32 {
    match audit_project_package(&args.root, profile, &args.package) {
        Ok(report) if report.is_clean() => {
            println!(
                "license audit ok: {} reachable packages, {} third-party packages, {} direct third-party dependencies",
                report.reachable_packages,
                report.third_party_packages,
                report.direct_third_party_dependencies.len()
            );
            0
        }
        Ok(report) => {
            for finding in report.findings {
                eprintln!("license audit: {}", finding.message);
            }
            2
        }
        Err(error) => {
            eprintln!("{error}");
            operational_exit_code(&error)
        }
    }
}

fn operational_exit_code(error: &LicenseAuditError) -> i32 {
    match error {
        LicenseAuditError::MetadataFailed { .. }
        | LicenseAuditError::MetadataCommand { .. }
        | LicenseAuditError::MetadataJson(_)
        | LicenseAuditError::MissingPackage { .. }
        | LicenseAuditError::MissingResolveGraph
        | LicenseAuditError::ReadFile { .. } => 1,
    }
}
