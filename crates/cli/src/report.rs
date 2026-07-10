// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Run identifier used for output file names.
    #[arg(long, default_value = "last")]
    pub run: String,

    /// Findings root containing one subdirectory per finding.
    #[arg(long, default_value = "findings")]
    pub findings: PathBuf,

    /// Report output directory.
    #[arg(long, default_value = "reports")]
    pub out: PathBuf,

    /// Learned confidence model produced by govfuzz model train.
    #[arg(long)]
    pub model: Option<PathBuf>,

    /// Also emit a SARIF 2.1.0 report.
    #[arg(long)]
    pub sarif: bool,

    /// Also emit a JUnit-style XML report.
    #[arg(long)]
    pub junit: bool,

    /// Also emit a CSV report (one row per finding) for spreadsheets / SCA.
    #[arg(long)]
    pub csv: bool,

    /// Collapse non-representative findings inside each cluster under
    /// their representative in the Markdown report.
    #[arg(long)]
    pub collapse_clusters: bool,
}

pub fn run(args: ReportArgs) -> i32 {
    let options = govfuzz_report::ReportOptions::new(args.findings, args.out)
        .with_run_id(args.run)
        .with_sarif(args.sarif)
        .with_junit(args.junit)
        .with_csv(args.csv)
        .with_collapse_clusters(args.collapse_clusters);
    let options = if let Some(model) = args.model {
        options.with_confidence_model_path(model)
    } else {
        options
    };
    match govfuzz_report::write_reports(options) {
        Ok(summary) => {
            println!(
                "REPORT run={} findings={} json={} markdown={}",
                summary.run_id,
                summary.findings_count,
                summary.json_path.display(),
                summary.markdown_path.display()
            );
            if let Some(path) = summary.sarif_path {
                println!("SARIF {}", path.display());
            }
            if let Some(path) = summary.junit_path {
                println!("JUNIT {}", path.display());
            }
            if let Some(path) = summary.csv_path {
                println!("CSV {}", path.display());
            }
            0
        }
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}
