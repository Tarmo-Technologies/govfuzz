// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct SbomArgs {
    /// Source tree, work directory, or component manifest to inventory.
    pub path: PathBuf,

    /// Output directory for the emitted artifacts (sbom.json, cyclonedx.json,
    /// vulnerabilities.json, openvex.json, sbom.csv — see `--emit` to select a
    /// subset).
    #[arg(long, default_value = "govfuzz_work/sbom")]
    pub out: PathBuf,

    /// Comma-separated subset of artifacts to emit: `cyclonedx`, `sbom`,
    /// `vulnerabilities`, `openvex`, `csv`, `cyclonedx-vex`. Default emits all of
    /// them (the VEX outputs are on by default). An unknown name is rejected.
    #[arg(long, value_name = "LIST")]
    pub emit: Option<String>,

    /// Convenience alias: force the two VEX outputs (`openvex`,`cyclonedx-vex`)
    /// into the emit set, in addition to whatever `--emit` selects.
    #[arg(long)]
    pub vex: bool,

    /// Convenience alias for a single output format, added to the emit set:
    /// `spdx-json` writes `sbom.spdx.json` (SPDX-2.3). Equivalent to
    /// `--emit spdx-json`; combine with `--emit` to add it to a wider selection.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,

    /// Comma-separated cataloger ecosystems to run (e.g. `cargo,npm`). Default
    /// runs every cataloger that detects the tree. An unknown name is rejected.
    #[arg(long, value_name = "LIST")]
    pub ecosystems: Option<String>,

    /// Explicit `auto/run.json` for runtime/fuzz reachability evidence. When
    /// unset the conventional `<root>/auto/run.json` locations are auto-detected.
    #[arg(long = "run-json", value_name = "PATH")]
    pub run_json: Option<PathBuf>,

    /// Offline CVE database JSON supplied by an update pack.
    #[arg(long = "vuln-db")]
    pub vuln_db: Option<PathBuf>,

    /// Policy-as-code JSON; /ci/fail_on_vulnerability_severity supplies the gate.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Binary inventory JSON to include as binary component evidence.
    #[arg(long = "binary-inventory")]
    pub binary_inventories: Vec<PathBuf>,

    /// Exit non-zero when a matched vulnerability meets or exceeds this severity.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnSeverity>,
}

impl SbomArgs {
    /// Resolve the `--emit`/`--vex` flags into an `EmitSet`. `--emit` absent
    /// keeps the all-artifacts default; `--vex` then forces the VEX outputs in.
    fn emit_set(&self) -> Result<governance::EmitSet, governance::GovernanceError> {
        // A bare `--format` with no `--emit` means "emit only that format" (so a
        // procurement pipeline can ask for SPDX alone); when `--emit` is also
        // given, `--format` is additive.
        let mut set = match (&self.emit, &self.format) {
            (Some(list), _) => governance::EmitSet::parse_list(list)?,
            (None, Some(format)) => governance::EmitSet::parse_list(format)?,
            (None, None) => governance::EmitSet::all(),
        };
        if let (Some(_), Some(format)) = (&self.emit, &self.format) {
            let mut kinds: Vec<governance::EmitKind> = Vec::new();
            for segment in format.split(',') {
                let trimmed = segment.trim();
                if !trimmed.is_empty() {
                    kinds.push(governance::EmitKind::parse(trimmed)?);
                }
            }
            set = set.with_kinds(kinds);
        }
        if self.vex {
            set = set.with_vex();
        }
        Ok(set)
    }

    fn ecosystem_filter(&self) -> Option<Vec<String>> {
        self.ecosystems.as_ref().map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect()
        })
    }
}

pub fn run(args: SbomArgs) -> i32 {
    let emit = match args.emit_set() {
        Ok(emit) => emit,
        Err(error) => {
            gfeprintln!("{error:#}");
            return 1;
        }
    };
    let ecosystems = args.ecosystem_filter();
    let options = governance::SbomOptions {
        root: args.path,
        out_dir: args.out,
        vuln_db: args.vuln_db,
        policy: args.policy,
        binary_inventories: args.binary_inventories,
        fail_on: args.fail_on.map(|severity| severity.as_str().to_owned()),
        emit,
        ecosystems,
        run_json: args.run_json,
    };

    match governance::write_sbom(&options) {
        Ok(summary) => {
            println!(
                "sbom: {} components, {} vulnerability matches",
                summary.components, summary.matches
            );
            for path in &summary.written {
                println!("sbom: wrote {}", path.display());
            }
            if summary.gate_failed {
                1
            } else {
                0
            }
        }
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use governance::EmitKind;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(flatten)]
        sbom: SbomArgs,
    }

    fn parse(args: &[&str]) -> SbomArgs {
        let mut argv = vec!["govfuzz", "tree"];
        argv.extend_from_slice(args);
        TestCli::try_parse_from(argv).expect("parses").sbom
    }

    #[test]
    fn emit_flag_parses_to_the_named_subset() {
        let set = parse(&["--emit", "sbom,openvex"]).emit_set().unwrap();
        assert!(set.contains(EmitKind::Sbom));
        assert!(set.contains(EmitKind::Openvex));
        assert!(!set.contains(EmitKind::Cyclonedx));
        assert!(!set.contains(EmitKind::Vulnerabilities));
    }

    #[test]
    fn default_emit_is_all_artifacts_including_vex() {
        let set = parse(&[]).emit_set().unwrap();
        for kind in [
            EmitKind::Sbom,
            EmitKind::Cyclonedx,
            EmitKind::Vulnerabilities,
            EmitKind::Openvex,
            EmitKind::Csv,
            EmitKind::CyclonedxVex,
        ] {
            assert!(set.contains(kind), "default should contain {kind:?}");
        }
    }

    #[test]
    fn vex_alias_forces_the_two_vex_outputs() {
        let set = parse(&["--emit", "sbom", "--vex"]).emit_set().unwrap();
        assert!(set.contains(EmitKind::Sbom));
        assert!(set.contains(EmitKind::Openvex));
        assert!(set.contains(EmitKind::CyclonedxVex));
        // --vex did NOT pull in cyclonedx or vulnerabilities.
        assert!(!set.contains(EmitKind::Cyclonedx));
        assert!(!set.contains(EmitKind::Vulnerabilities));
    }

    #[test]
    fn unknown_emit_value_is_a_hard_error() {
        assert!(parse(&["--emit", "zzz"]).emit_set().is_err());
    }

    #[test]
    fn format_spdx_json_alone_emits_only_spdx() {
        let set = parse(&["--format", "spdx-json"]).emit_set().unwrap();
        assert!(set.contains(EmitKind::SpdxJson));
        assert!(!set.contains(EmitKind::Cyclonedx));
        assert!(!set.contains(EmitKind::Sbom));
    }

    #[test]
    fn format_is_additive_to_explicit_emit() {
        let set = parse(&["--emit", "cyclonedx", "--format", "spdx-json"])
            .emit_set()
            .unwrap();
        assert!(set.contains(EmitKind::Cyclonedx));
        assert!(set.contains(EmitKind::SpdxJson));
    }

    #[test]
    fn unknown_format_value_is_a_hard_error() {
        assert!(parse(&["--format", "zzz"]).emit_set().is_err());
    }

    #[test]
    fn ecosystem_filter_threads_through_and_splits_on_comma() {
        let filter = parse(&["--ecosystems", "cargo, npm"]).ecosystem_filter();
        assert_eq!(filter, Some(vec!["cargo".to_owned(), "npm".to_owned()]));
        // Absent flag means no restriction.
        assert_eq!(parse(&[]).ecosystem_filter(), None);
    }

    #[test]
    fn run_json_threads_through() {
        let args = parse(&["--run-json", "/tmp/run.json"]);
        assert_eq!(args.run_json, Some(PathBuf::from("/tmp/run.json")));
        assert_eq!(parse(&[]).run_json, None);
    }

    #[test]
    fn existing_flags_still_parse() {
        let args = parse(&[
            "--out",
            "/tmp/out",
            "--vuln-db",
            "/tmp/vulns.json",
            "--binary-inventory",
            "/tmp/inv.json",
            "--fail-on",
            "high",
        ]);
        assert_eq!(args.out, PathBuf::from("/tmp/out"));
        assert_eq!(args.vuln_db, Some(PathBuf::from("/tmp/vulns.json")));
        assert_eq!(
            args.binary_inventories,
            vec![PathBuf::from("/tmp/inv.json")]
        );
        assert_eq!(args.fail_on, Some(FailOnSeverity::High));
    }
}
