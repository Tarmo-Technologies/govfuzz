// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct BinaryScanArgs {
    /// Binary file, firmware blob, or directory tree to inventory.
    pub path: PathBuf,

    /// Output directory for binary-inventory.json.
    #[arg(long, default_value = "govfuzz_work/binary")]
    pub out: PathBuf,

    /// Skip individual files or archive members larger than this byte count.
    #[arg(long)]
    pub max_bytes: Option<u64>,

    /// Offline CVE component database for SBOM/SCA matching.
    #[arg(long)]
    pub cve_db: Option<PathBuf>,
}

pub fn run(args: BinaryScanArgs) -> i32 {
    let options = binary_analysis::BinaryScanOptions {
        root: args.path,
        out_dir: args.out,
        max_bytes: args.max_bytes,
        cve_db_path: args.cve_db,
    };
    match binary_analysis::write_inventory(&options) {
        Ok(summary) => {
            println!(
                "binary scan: {} files inventoried, {} skipped, {} containers",
                summary.files, summary.skipped, summary.containers,
            );
            if summary.secret_count > 0 {
                println!(
                    "  ! {} hardcoded secret(s) across {} binaries",
                    summary.secret_count, summary.binaries_with_secrets,
                );
            }
            if summary.malware_indicator_count > 0 {
                println!(
                    "  !! {} malware indicator(s) (credential-store / exfiltration strings)",
                    summary.malware_indicator_count,
                );
            }
            if summary.high_priority > 0 {
                println!(
                    "  ! {} high-priority binaries (secrets / risky imports / CVEs)",
                    summary.high_priority,
                );
            }
            println!("json: {}", summary.json_path.display());
            0
        }
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}
