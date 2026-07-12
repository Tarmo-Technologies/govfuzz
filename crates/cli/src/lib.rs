// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use config::Profile;
use license_policy::enforce;

mod ada_bridge;
mod audit;
pub mod auto;
mod benchmark;
mod binary_adapter;
mod binary_fuzz;
mod binary_scan;
mod build;
mod capsule;
mod cartography;
pub mod ci;
mod clean;
mod cmplog_cli;
mod corpus;
mod dashboard;
mod differential;
mod env_capsule;
mod explain;
mod export_bundle;
mod extract_state_machines;
mod fake_corba;
mod finding_arg;
mod fuzz;
mod generate_harness;
mod git_diff;
mod instrument;
mod introspect;
mod license_audit;
pub mod list_fakes;
pub mod list_oracles;
mod list_targets;
mod minimize;
mod model;
mod pack;
mod policy;
mod probe_backend;
mod readiness;
mod replay;
mod report;
mod rules;
mod runner;
mod runners;
mod sbom;
mod scan;
mod sloc;
mod snippet;
mod source_text;
mod static_scan;
mod stub;
mod target_filter;

#[derive(Debug, Parser)]
#[command(name = "govfuzz")]
#[command(version = env!("GOVFUZZ_VERSION_FULL"))]
#[command(about = "Offline fuzz lab generator for legacy Ada, C, and C++ software")]
#[command(long_about = "\
Offline fuzz lab generator for legacy Ada, C, and C++ software.

Scan untrusted source (or binaries), rank fuzzable subprograms, generate typed
harnesses + stubs, build with your installed toolchains, fuzz with a builtin
engine or external adapters (AFL++, libFuzzer, LibAFL, Nyx), and emit
JSON/Markdown/SARIF/JUnit/CSV findings — fully offline.

Most users want `govfuzz auto <source-dir>`, which runs the whole pipeline.

COMMANDS BY AREA (run `govfuzz <command> --help` for details):
  Pipeline      auto, scan, list, generate-harness, build, fuzz, report
  Build support stub, instrument, fake-corba
  Crash triage  corpus, minimize, replay, differential, cmplog
  Binaries      binary (scan, adapter, fuzz — no source)
  Supply chain  sbom, license-audit, static-scan, extract-state-machines
  Reference     rules, list oracles
  Governance    policy, audit, pack, export
  Ops & CI      ci, runners, clean, introspect

`list` and `binary` group related subcommands (`govfuzz list targets`,
`govfuzz binary scan`). TIP: the list is greppable — `govfuzz --help | grep -i sarif`.")]
struct Args {
    /// License/capability profile gating which tools may run. `strict-permissive`
    /// (default) links only Apache-2.0/MIT/BSD code; `external-tools`
    /// also permits GPL tools (GNAT, GPRbuild) as subprocesses.
    #[arg(long, default_value = "strict-permissive", value_parser = parse_profile, global = true)]
    profile: Profile,

    /// Capability probe(s) to enforce against the profile (repeatable); the run
    /// is rejected if a probe is forbidden by the active profile.
    #[arg(long = "probe", value_name = "PROBE")]
    probes: Vec<String>,

    /// Debug mode: capture a backtrace for any govfuzz-internal panic (sets
    /// RUST_BACKTRACE), keep going past a file that crashes govfuzz, and enrich
    /// the generated bug-report.json. Use this when govfuzz itself errors on your
    /// tree so the report has enough to fix the bug offline.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

// Variants are ordered by area (clap lists subcommands in declaration order)
// and each carries a keyword-dense one-line description. The first doc-comment
// line becomes the `about` shown in the command list and is intentionally
// written so `govfuzz --help | grep -i <keyword>` surfaces the right command
// (engine names, formats, standards, and synonyms appear inline).
// `AutoArgs` is by far the largest variant (the flagship command carries many
// sweep/budget/build flags). The enum is parsed exactly once at startup and
// never stored in bulk, so its size is irrelevant — and clap's `Subcommand`
// derive can't take a `Box<Args>`, so boxing isn't an option here anyway.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    // ── Pipeline: the source -> findings flow ───────────────────────────────
    /// End-to-end pipeline: discover targets, generate harnesses, auto-repair the build, fuzz, and report (flagship command)
    Auto(auto::cli::AutoArgs),
    /// Fuzz ONE pasted function with no project/build/deps — detect language, synthesize a one-file project, run the auto pipeline
    Snippet(snippet::SnippetArgs),
    /// Index an Ada/C/C++ source tree into scan_index.json (units, fuzzable targets, handler counts)
    Scan(scan::ScanArgs),
    /// List fuzzable targets in a source tree, or the bug-oracle inventory (`list targets` / `list oracles`)
    List(ListArgs),
    /// Generate an Ada/C/C++ fuzzing harness for one subprogram, with build-context recovery
    GenerateHarness(generate_harness::GenerateHarnessArgs),
    /// Compile a generated harness (toolchain auto-detect, cross-compile, GNAT/GPRbuild/clang, probe backend)
    Build(build::BuildArgs),
    /// Fuzz a built harness with the built-in coverage-guided engine (default) or AFL++ (`--engine afl++`)
    Fuzz(fuzz::FuzzArgs),
    /// Render findings to Markdown, SARIF 2.1.0, JUnit XML, and CSV with crash clustering and dedupe
    Report(report::ReportArgs),

    // ── Build support: unblock a harness that won't compile ─────────────────
    /// Synthesize missing type/function stubs from build-loop diagnostics to unblock a harness (Ada/C/C++)
    Stub(stub::StubArgs),
    /// Rewrite Ada source to capture runtrace events (probe points, breadcrumb sidecar)
    Instrument(instrument::InstrumentArgs),
    /// Generate fake CORBA Helper/Skel/Stub Ada packages from IDL or ROS interfaces
    FakeCorba(fake_corba::FakeCorbaArgs),

    // ── Crash triage: corpora, reduction, reproduction ──────────────────────
    /// Import, export, and merge corpora across AFL++, libFuzzer, Honggfuzz, and govfuzz layouts
    Corpus(corpus::CorpusArgs),
    /// Shrink a crashing input by binary search while preserving the crash (testcase reduction)
    Minimize(minimize::MinimizeArgs),
    /// Re-run a finding's crash input through a harness to reproduce it (sandbox / qemu-user)
    Replay(replay::ReplayArgs),
    /// Package a crash into a portable, self-verifying PoC capsule (min input + harness + recovered build + stubs)
    Capsule(capsule::CapsuleArgs),
    /// Rebuild a PoC capsule offline and assert the crash reproduces (only clang + a shell needed)
    VerifyPoc(capsule::VerifyPocArgs),
    /// Record + replay the shim-served faked environment so an environment-driven crash reproduces deterministically
    EnvCapsule(env_capsule::EnvCapsuleArgs),
    /// Replay inputs through two harnesses or metamorphic variants and flag divergences (GF-301 oracle)
    Differential(differential::DifferentialArgs),
    /// Recover comparison operands (cmplog / RedQueen) from a runtrace log into a fuzzing dictionary
    Cmplog(cmplog_cli::CmplogArgs),
    /// Explain, offline and deterministically (no LLM), WHY a crash fired: input, gate constants, faked env, dataflow
    Explain(explain::ExplainArgs),
    /// Map which input bytes control which sink operand (offset/size/index) via perturbation — the exploit primitive
    Cartography(cartography::CartographyArgs),

    // ── Binaries: no-source / firmware analysis ─────────────────────────────
    /// No-source analysis of compiled binaries & firmware: scan, adapter, fuzz (CVE/SBOM, Rizin/Ghidra/angr, black-box)
    Binary(BinaryArgs),

    // ── Supply chain & static analysis ──────────────────────────────────────
    /// Generate an SBOM from source/manifest/binaries with CVE matching and vulnerability gating
    Sbom(sbom::SbomArgs),
    /// Verify reachable dependencies against the Apache-2.0/MIT/BSD license policy (SLSA/compliance)
    LicenseAudit(license_audit::LicenseAuditArgs),
    /// Run static-analysis rules (MISRA, CWE) over source to a report/SARIF with baseline diff (SAST)
    StaticScan(static_scan::StaticScanArgs),
    /// Fast per-language SLOC counting over one or more roots — tree walk only, NO rule scanning (much faster than `static-scan --sloc`)
    Sloc(sloc::SlocArgs),
    /// Infer Ada protected/task types from source as JSON state machines (protocol analysis)
    ExtractStateMachines(extract_state_machines::ExtractStateMachinesArgs),

    // ── Reference data ──────────────────────────────────────────────────────
    /// Browse the rule catalog: GF-NNNN ids, CWE/CERT/MISRA mappings, severity
    Rules(rules::RulesArgs),

    // ── Governance & air-gapped distribution ────────────────────────────────
    /// Explain, validate, or dry-run GovFuzz policy-as-code governance rules
    Policy(policy::PolicyArgs),
    /// Append to or read the JSONL compliance/audit log
    Audit(audit::AuditArgs),
    /// Create, inspect, verify, or install signed air-gapped update packs (offline distribution)
    Pack(pack::PackArgs),
    /// Bundle a work directory (policy, packs, audit) into a manifest/tarball for air-gapped handoff
    Export(export_bundle::ExportArgs),

    // ── Ops, CI & diagnostics ───────────────────────────────────────────────
    /// Run auto for CI: write a Markdown summary to GITHUB_STEP_SUMMARY and gate on a severity threshold
    Ci(ci::CiArgs),
    /// Manage distributed runner profiles (list/select/handoff/lease/plan/validate)
    Runners(runners::RunnersArgs),
    /// Remove selected work-directory subdirectories (build, corpus, reports, findings)
    Clean(clean::CleanArgs),
    /// Compare discovered targets against a prior auto/run.json to surface coverage blockers (diagnostics)
    Introspect(introspect::IntrospectArgs),

    // ── Internal / metrics: hidden from the default menu, still runnable ─────
    /// Emit governance dashboard data (audit, policy, runner manifest) as JSON
    #[command(hide = true)]
    Dashboard(dashboard::DashboardArgs),
    /// Score fuzzing-effort readiness against validation/benchmark/pattern claims (maturity scorecard)
    #[command(hide = true)]
    Readiness(readiness::ReadinessArgs),
    /// Measure fuzz performance — seeded metrics or pattern coverage — against a manifest
    #[command(hide = true)]
    Benchmark(benchmark::BenchmarkArgs),
    /// Train a confidence/severity model from labeled findings to improve signal-to-noise
    #[command(hide = true)]
    Model(model::ModelArgs),

    // ── Deprecated flat aliases (hidden): superseded by `binary`/`list` ──────
    // Kept so existing scripts and IDE integrations keep working.
    /// Deprecated alias for `govfuzz binary scan`.
    #[command(name = "binary-scan", hide = true)]
    BinaryScan(binary_scan::BinaryScanArgs),
    /// Deprecated alias for `govfuzz binary adapter`.
    #[command(name = "binary-adapter", hide = true)]
    BinaryAdapter(binary_adapter::BinaryAdapterArgs),
    /// Deprecated alias for `govfuzz binary fuzz`.
    #[command(name = "binary-fuzz", hide = true)]
    BinaryFuzz(binary_fuzz::BinaryFuzzArgs),
    /// Deprecated alias for `govfuzz list targets`.
    #[command(name = "list-targets", hide = true)]
    ListTargets(list_targets::ListTargetsArgs),
    /// Deprecated alias for `govfuzz list oracles`.
    #[command(name = "list-oracles", hide = true)]
    ListOracles(list_oracles::ListOraclesArgs),
}

/// `govfuzz binary <scan|adapter|fuzz>` — no-source analysis of compiled
/// artifacts. Groups the former `binary-*` top-level commands.
#[derive(Debug, clap::Args)]
struct BinaryArgs {
    #[command(subcommand)]
    command: BinaryCommand,
}

#[derive(Debug, Subcommand)]
enum BinaryCommand {
    /// Inventory binaries and firmware, extract archives, match CVE components for SBOM/SCA
    Scan(binary_scan::BinaryScanArgs),
    /// Analyze a binary via external adapters (Rizin, Ghidra, angr) into a JSON report
    Adapter(binary_adapter::BinaryAdapterArgs),
    /// Fuzz a standalone executable with no source (stdin/seed inputs, sandbox, timeouts, black-box)
    Fuzz(binary_fuzz::BinaryFuzzArgs),
}

/// `govfuzz list <targets|oracles>` — enumerate discovered fuzzable targets or
/// the bug-oracle inventory.
#[derive(Debug, clap::Args)]
struct ListArgs {
    #[command(subcommand)]
    command: ListCommand,
}

#[derive(Debug, Subcommand)]
enum ListCommand {
    /// List fuzzable subprograms in a source tree, ranked, as a table or JSON
    Targets(list_targets::ListTargetsArgs),
    /// List the bug-oracle plugin inventory (threat-detection rules by API/category)
    Oracles(list_oracles::ListOraclesArgs),
}

pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = match Args::try_parse_from(args) {
        Ok(args) => args,
        Err(error) => {
            let _ = error.print();
            return error.exit_code();
        }
    };

    // Install the self-diagnostics panic hook up front so an internal panic in
    // ANY subcommand is captured (with a backtrace under `--debug`) rather than
    // just aborting. The `auto` sweep additionally catches per-target panics and
    // writes a bug-report.
    auto::bug_report::init(args.debug);

    let profile = args.profile;
    let probe_refs = args.probes.iter().map(String::as_str).collect::<Vec<_>>();
    if let Err(error) = enforce(profile, &probe_refs) {
        eprintln!("{error}");
        return 2;
    }

    match args.command {
        Some(Command::Auto(auto_args)) => auto::cli::run(auto_args),
        // Nested parents. The flat BinaryScan/.../ListOracles arms below are
        // retained for the hidden back-compat aliases.
        Some(Command::Binary(binary)) => match binary.command {
            BinaryCommand::Scan(args) => binary_scan::run(args),
            BinaryCommand::Adapter(args) => binary_adapter::run(args, profile),
            BinaryCommand::Fuzz(args) => binary_fuzz::run(args),
        },
        Some(Command::List(list)) => match list.command {
            ListCommand::Targets(args) => match list_targets::run(args) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("{error:#}");
                    1
                }
            },
            ListCommand::Oracles(args) => list_oracles::run(args),
        },
        Some(Command::Audit(args)) => audit::run(args),
        Some(Command::Benchmark(args)) => benchmark::run(args),
        Some(Command::BinaryAdapter(args)) => binary_adapter::run(args, profile),
        Some(Command::BinaryFuzz(args)) => binary_fuzz::run(args),
        Some(Command::BinaryScan(args)) => binary_scan::run(args),
        Some(Command::Build(build_args)) => build::run(build_args),
        Some(Command::Capsule(args)) => capsule::run(args),
        Some(Command::VerifyPoc(args)) => capsule::run_verify(args),
        Some(Command::EnvCapsule(args)) => env_capsule::run(args),
        Some(Command::Ci(ci_args)) => ci::run(ci_args),
        Some(Command::Clean(clean_args)) => clean::run(clean_args),
        Some(Command::Cmplog(args)) => cmplog_cli::run(args),
        Some(Command::Corpus(corpus_args)) => corpus::run(corpus_args),
        Some(Command::Dashboard(args)) => dashboard::run(args),
        Some(Command::Differential(diff_args)) => differential::run(diff_args),
        Some(Command::Explain(args)) => explain::run(args),
        Some(Command::Cartography(args)) => cartography::run(args),
        Some(Command::ExtractStateMachines(args)) => extract_state_machines::run(args),
        Some(Command::FakeCorba(fake_corba_args)) => fake_corba::run(fake_corba_args),
        Some(Command::Export(args)) => export_bundle::run(args),
        Some(Command::Fuzz(fuzz_args)) => fuzz::run(fuzz_args),
        Some(Command::LicenseAudit(license_audit_args)) => {
            license_audit::run(license_audit_args, profile)
        }
        Some(Command::ListOracles(args)) => list_oracles::run(args),
        Some(Command::ListTargets(list_args)) => match list_targets::run(list_args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        Some(Command::GenerateHarness(generate_args)) => match generate_harness::run(generate_args)
        {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        Some(Command::Instrument(instrument_args)) => match instrument::run(instrument_args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        Some(Command::Introspect(introspect_args)) => match introspect::run(introspect_args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error:#}");
                1
            }
        },
        Some(Command::Minimize(minimize_args)) => minimize::run(minimize_args),
        Some(Command::Model(model_args)) => model::run(model_args),
        Some(Command::Pack(args)) => pack::run(args),
        Some(Command::Policy(args)) => policy::run(args),
        Some(Command::Readiness(args)) => readiness::run(args),
        Some(Command::Report(report_args)) => report::run(report_args),
        Some(Command::Replay(replay_args)) => replay::run(replay_args),
        Some(Command::Rules(rules_args)) => rules::run(rules_args),
        Some(Command::Runners(args)) => runners::run(args),
        Some(Command::Scan(scan_args)) => scan::run(scan_args),
        Some(Command::Snippet(snippet_args)) => snippet::run(snippet_args),
        Some(Command::Sbom(args)) => sbom::run(args),
        Some(Command::StaticScan(args)) => static_scan::run(args),
        Some(Command::Sloc(args)) => sloc::run(args),
        Some(Command::Stub(stub_args)) => stub::run(stub_args),
        None => 0,
    }
}

fn parse_profile(value: &str) -> Result<Profile, String> {
    value.parse::<Profile>().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{run_from, Args};
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn every_subcommand_has_a_description() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let missing: Vec<String> = cmd
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .filter(|c| c.get_about().is_none())
            .map(|c| c.get_name().to_owned())
            .collect();
        assert!(
            missing.is_empty(),
            "every command needs a `--help` description; missing: {missing:?}"
        );
    }

    #[test]
    fn help_descriptions_are_greppable_by_keyword() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let about_of = |name: &str| -> String {
            cmd.get_subcommands()
                .find(|c| c.get_name() == name)
                .and_then(|c| c.get_about())
                .map(|s| s.to_string().to_lowercase())
                .unwrap_or_default()
        };
        // Users grep the command list by domain keyword; the description must
        // carry the term even when it isn't in the command name.
        for (command, keyword) in [
            ("report", "sarif"),
            ("fuzz", "afl"),
            ("sbom", "cve"),
            ("static-scan", "misra"),
            ("minimize", "crash"),
            ("cmplog", "redqueen"),
            ("replay", "qemu"),
            ("fake-corba", "idl"),
        ] {
            assert!(
                about_of(command).contains(keyword),
                "`{command}` description should be grep-able by '{keyword}', got: {:?}",
                about_of(command)
            );
        }
    }

    #[test]
    fn binary_and_list_nest_with_hidden_backcompat_aliases() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let sub = |name: &str| {
            cmd.get_subcommands()
                .find(|c| c.get_name() == name)
                .cloned()
        };

        let binary = sub("binary").expect("`binary` parent exists");
        let bsubs: Vec<&str> = binary.get_subcommands().map(|c| c.get_name()).collect();
        for expected in ["scan", "adapter", "fuzz"] {
            assert!(
                bsubs.contains(&expected),
                "binary missing `{expected}`: {bsubs:?}"
            );
        }
        let list = sub("list").expect("`list` parent exists");
        let lsubs: Vec<&str> = list.get_subcommands().map(|c| c.get_name()).collect();
        for expected in ["targets", "oracles"] {
            assert!(
                lsubs.contains(&expected),
                "list missing `{expected}`: {lsubs:?}"
            );
        }

        // Old flat names still parse, but are hidden from the menu.
        for alias in [
            "binary-scan",
            "binary-adapter",
            "binary-fuzz",
            "list-targets",
            "list-oracles",
        ] {
            let c = sub(alias).unwrap_or_else(|| panic!("back-compat alias `{alias}` missing"));
            assert!(c.is_hide_set(), "`{alias}` should be hidden");
        }

        // Internal/metrics commands are runnable but hidden.
        for dev in ["benchmark", "model", "dashboard", "readiness"] {
            let c = sub(dev).unwrap_or_else(|| panic!("`{dev}` missing"));
            assert!(c.is_hide_set(), "`{dev}` should be hidden");
        }
    }

    #[test]
    fn strict_permissive_gnat_actions_exits_two() {
        assert_eq!(
            run_from([
                "govfuzz",
                "--profile",
                "strict-permissive",
                "--probe",
                "gnat_actions"
            ]),
            2
        );
    }

    #[test]
    fn external_tools_gnat_actions_exits_zero() {
        assert_eq!(
            run_from([
                "govfuzz",
                "--profile",
                "external-tools",
                "--probe",
                "gnat_actions"
            ]),
            0
        );
    }

    #[test]
    fn strict_permissive_without_probe_exits_zero() {
        assert_eq!(run_from(["govfuzz", "--profile", "strict-permissive"]), 0);
    }

    #[test]
    fn rules_list_exits_zero() {
        assert_eq!(run_from(["govfuzz", "rules", "list"]), 0);
    }

    #[test]
    fn rules_show_known_id_exits_zero() {
        assert_eq!(run_from(["govfuzz", "rules", "show", "GF-201"]), 0);
    }

    #[test]
    fn rules_show_unknown_id_exits_two() {
        assert_eq!(run_from(["govfuzz", "rules", "show", "GF-999-unknown"]), 2);
    }

    #[test]
    fn license_audit_subcommand_exits_zero_for_current_repo() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(
            run_from(vec![
                OsString::from("govfuzz"),
                OsString::from("license-audit"),
                OsString::from("--profile"),
                OsString::from("strict-permissive"),
                OsString::from("--root"),
                root.into_os_string(),
            ]),
            0
        );
    }

    #[test]
    fn generate_harness_wrong_kind_reaches_subcommand_handler() {
        assert_eq!(
            run_from([
                "govfuzz",
                "generate-harness",
                "src/pkg.adb",
                "--kind",
                "servant_direct"
            ]),
            1
        );
    }

    #[test]
    fn fake_corba_subcommand_writes_generated_files() {
        let temp = temp_dir("fake-corba-success");
        let work_dir = create_minimal_work_dir(&temp);
        fs::write(
            work_dir.join("src_instrumented/bar_impl.adb"),
            "with PortableServer;\npackage body Bar_Impl is\nbegin\n   raise Foo.BadInput;\nexception\n   when Foo.BadInput => null;\nend Bar_Impl;\n",
        )
        .expect("CORBA-like source is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("fake_corba/corba.ads").is_file());
        assert!(work_dir.join("fake_corba/portableserver.ads").is_file());
        assert!(work_dir.join("fake_corba/foo.ads").is_file());
    }

    #[test]
    fn fake_corba_subcommand_writes_idl_mapping_files() {
        let temp = temp_dir("fake-corba-idl");
        let work_dir = create_minimal_work_dir(&temp);
        let idl_path = temp.join("demo.idl");
        fs::write(
            &idl_path,
            "module Demo { interface Calculator { long Add(in long Left, in long Right); }; };",
        )
        .expect("IDL fixture is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("fake_corba/corba.ads").is_file());
        assert!(work_dir.join("fake_corba/corba-any.ads").is_file());
        assert!(work_dir
            .join("fake_corba/demo-calculator-helper.ads")
            .is_file());
        assert!(work_dir
            .join("fake_corba/demo-calculator-skel.ads")
            .is_file());
        assert!(work_dir
            .join("fake_corba/demo-calculator-stub.ads")
            .is_file());
    }

    #[test]
    fn fake_corba_subcommand_passes_idl_defines_to_preprocessor() {
        let temp = temp_dir("fake-corba-idl-define");
        let work_dir = create_minimal_work_dir(&temp);
        let idl_path = temp.join("cyclone_style.idl");
        fs::write(
            &idl_path,
            "#if defined(__IDLC__)\nmodule Demo { interface Chosen {}; };\n#else\n#define C_HELPER(x) x\n#endif\n",
        )
        .expect("IDL fixture is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
            "--idl-define",
            "__IDLC__",
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("fake_corba/demo-chosen-helper.ads").is_file());
    }

    #[test]
    fn fake_corba_subcommand_writes_idl_mapping_without_src_instrumented() {
        let temp = temp_dir("fake-corba-idl-only");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&work_dir).expect("work dir is created");
        let idl_path = temp.join("demo.idl");
        fs::write(
            &idl_path,
            "module Demo { interface Calculator { long Add(in long Left, in long Right); }; };",
        )
        .expect("IDL fixture is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("fake_corba/corba.ads").is_file());
        assert!(work_dir.join("fake_corba/corba-any.ads").is_file());
        assert!(work_dir
            .join("fake_corba/demo-calculator-helper.ads")
            .is_file());
    }

    #[test]
    fn fake_corba_subcommand_passes_idl_include_dirs() {
        let temp = temp_dir("fake-corba-idl-include-dir");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&work_dir).expect("work dir is created");
        let include_dir = temp.join("idl/includes");
        fs::create_dir_all(&include_dir).expect("include dir is created");
        fs::write(
            include_dir.join("shared.idl"),
            "module Shared { interface Service {}; };",
        )
        .expect("included IDL is written");
        let idl_path = temp.join("root.idl");
        fs::write(
            &idl_path,
            "#include \"shared.idl\"\nmodule Demo { interface Calculator {}; };",
        )
        .expect("root IDL is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
            "--idl-include-dir",
            include_dir.to_str().expect("include dir path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir
            .join("fake_corba/shared-service-helper.ads")
            .is_file());
        assert!(work_dir
            .join("fake_corba/demo-calculator-helper.ads")
            .is_file());
    }

    #[test]
    fn fake_corba_subcommand_recovers_from_missing_idl_include() {
        let temp = temp_dir("fake-corba-idl-missing-include");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&work_dir).expect("work dir is created");
        let idl_path = temp.join("root.idl");
        fs::write(
            &idl_path,
            "#include \"external/missing.idl\"\nmodule Demo { interface Calculator {}; };",
        )
        .expect("root IDL is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir
            .join("fake_corba/demo-calculator-helper.ads")
            .is_file());
    }

    #[test]
    fn fake_corba_subcommand_recovers_from_unsupported_idl_if_expression() {
        let temp = temp_dir("fake-corba-idl-unsupported-if");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&work_dir).expect("work dir is created");
        let idl_path = temp.join("root.idl");
        fs::write(
            &idl_path,
            "#if VENDOR_FLAG(1)\nmodule Disabled { interface Hidden {}; };\n#endif\nmodule Demo { interface Calculator {}; };",
        )
        .expect("root IDL is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir
            .join("fake_corba/demo-calculator-helper.ads")
            .is_file());
        assert!(!work_dir
            .join("fake_corba/disabled-hidden-helper.ads")
            .is_file());
    }

    #[test]
    fn fake_corba_subcommand_preserves_scanned_any_operations_with_idl_mapping() {
        let temp = temp_dir("fake-corba-idl-any");
        let work_dir = create_minimal_work_dir(&temp);
        fs::write(
            work_dir.join("src_instrumented/any_client.adb"),
            "with CORBA.Any;\npackage body Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value) is\n      TC : CORBA.Any.TypeCode := CORBA.Any.Get_Type (A);\n   begin\n      CORBA.Any.Set_Type (A, TC);\n   end Touch;\nend Any_Client;\n",
        )
        .expect("Any client source is written");
        let idl_path = temp.join("demo.idl");
        fs::write(&idl_path, "module Demo { interface Calculator {}; };")
            .expect("IDL fixture is written");

        let exit = run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]);

        let any_ads = fs::read_to_string(work_dir.join("fake_corba/corba-any.ads"))
            .expect("CORBA Any spec is readable");
        assert_eq!(exit, 0);
        assert!(any_ads.contains("function Get_Type"));
        assert!(any_ads.contains("procedure Set_Type"));
        assert!(work_dir.join("fake_corba/corba-any.adb").is_file());
    }

    #[test]
    fn build_subcommand_discovers_compiler_and_invokes_build() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-success");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let log_path = temp.join("build-args.log");
        let _path = PathEnvGuard::set(&bin_dir);
        let _log = EnvVarGuard::set("GOVFUZZ_BUILD_LOG", log_path.as_os_str());

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("utf-8 work dir"),
        ]);

        let argv = fs::read_to_string(log_path).expect("build argv log is readable");
        assert_eq!(exit, 0);
        assert!(argv.contains("-P"));
        assert!(argv.contains("govfuzz_build.gpr"));
        assert!(work_dir.join("build/H-TEST/govfuzz_build.gpr").is_file());
    }

    #[test]
    fn build_subcommand_includes_fake_corba_source_root_when_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-fake-corba-root");
        let work_dir = create_minimal_work_dir(&temp);
        let fake_dir = work_dir.join("fake_corba");
        fs::create_dir_all(&fake_dir).expect("fake CORBA directory is created");
        fs::write(fake_dir.join("corba.ads"), "package CORBA is end CORBA;\n")
            .expect("fake CORBA source is written");
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        let project = fs::read_to_string(work_dir.join("build/H-TEST/govfuzz_build.gpr"))
            .expect("project file is readable");
        assert!(project.contains("fake_corba"));
    }

    #[test]
    fn build_subcommand_writes_build_local_runtime_project() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-local-runtime");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        assert_eq!(exit, 0);
        let build_dir = work_dir.join("build/H-TEST");
        let project = fs::read_to_string(build_dir.join("govfuzz_build.gpr"))
            .expect("project file is readable");
        let runtime_project = fs::read_to_string(build_dir.join("adafuzz_runtime.gpr"))
            .expect("build-local runtime project is readable");
        assert!(project.contains("with \"adafuzz_runtime.gpr\";"));
        assert!(!project.contains("ada_runtime/adafuzz.gpr"));
        assert!(runtime_project.contains("for Object_Dir use \"adafuzz_obj\";"));
        assert!(runtime_project.contains("for Library_Dir use \"adafuzz_lib\";"));
        assert!(build_dir
            .join("adafuzz_runtime_src/adafuzz-probe.adb")
            .is_file());
    }

    #[test]
    fn build_instruments_target_with_trace_pc_but_not_runtime() {
        // #412: a real `govfuzz build` must produce a self-consistent coverage
        // wiring — the runtime project is NEVER coverage-instrumented (that would
        // make the trace-pc callback recurse) yet DOES build C (so adafuzz_cov.c
        // ships in the archive), and the target compile carries
        // `-fsanitize-coverage=trace-pc` EXACTLY when the coverage sentinel is
        // written (both derive from the same capability decision). Asserting the
        // invariant — rather than re-probing the host gcc, which races with this
        // test's restricted PATH and the build's cached probe — keeps the test
        // deterministic regardless of whether the host gcc supports trace-pc.
        // Deterministic positive/negative rendering is covered by build.rs unit
        // tests; coverage_edges>0 end-to-end by tests/auto_ada_coverage.rs.
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-trace-pc-instrumentation");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);
        assert_eq!(exit, 0);

        let build_dir = work_dir.join("build/H-TEST");
        let project = fs::read_to_string(build_dir.join("govfuzz_build.gpr"))
            .expect("project file is readable");
        let runtime_project = fs::read_to_string(build_dir.join("adafuzz_runtime.gpr"))
            .expect("build-local runtime project is readable");
        let sentinel = build_dir.join(".govfuzz_ada_cov");

        // The runtime project must never carry a coverage flag (the comment is
        // worded to avoid the literal token, so this match is unambiguous) and
        // must build C for the callback.
        assert!(
            !runtime_project.contains("-fsanitize-coverage"),
            "runtime project must never be coverage-instrumented:\n{runtime_project}"
        );
        assert!(
            runtime_project.contains("for Languages use (\"Ada\", \"C\")"),
            "runtime project must build C for the trace-pc callback:\n{runtime_project}"
        );

        // The Ada lane only ever uses trace-pc, never the unsupported guard form.
        assert!(
            !project.contains("trace-pc-guard"),
            "Ada must use trace-pc, not trace-pc-guard:\n{project}"
        );
        // The target's trace-pc flag and the coverage sentinel are written from
        // the same decision, so they must always agree.
        assert_eq!(
            project.contains("-fsanitize-coverage=trace-pc"),
            sentinel.is_file(),
            "trace-pc flag in Govfuzz_Build must match the coverage sentinel:\n{project}"
        );
    }

    #[test]
    fn build_subcommand_writes_cross_attributes_and_uses_prefixed_probe() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-cross-toolchain");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(
            &bin_dir.join("aarch64-linux-gnu-gprbuild"),
            fake_build_compiler_script(),
        );
        write_executable(
            &bin_dir.join("aarch64-linux-gnu-gnat"),
            fake_raw_gnat_canary_script(),
        );
        let build_log_path = temp.join("build-args.log");
        let gnat_log_path = temp.join("raw-gnat.log");
        let _path = PathEnvGuard::set(&bin_dir);
        let _build_log = EnvVarGuard::set("GOVFUZZ_BUILD_LOG", build_log_path.as_os_str());
        let _gnat_log = EnvVarGuard::set("GOVFUZZ_RAW_GNAT_LOG", gnat_log_path.as_os_str());

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--target",
            "aarch64-linux-gnu",
            "--runtime",
            "ravenscar-full",
            "--toolchain",
            "aarch64-linux-gnu",
        ]);

        let project = fs::read_to_string(work_dir.join("build/H-TEST/govfuzz_build.gpr"))
            .expect("project file is readable");
        let build_argv = fs::read_to_string(build_log_path).expect("build argv log is readable");
        let gnat_argv = fs::read_to_string(gnat_log_path).expect("raw gnat log is readable");
        assert_eq!(exit, 0);
        assert!(project.contains("for Target use \"aarch64-linux-gnu\";"));
        assert!(project.contains("for Runtime (\"Ada\") use \"ravenscar-full\";"));
        assert!(project.contains("for Toolchain_Name (\"Ada\") use \"aarch64-linux-gnu\";"));
        assert!(build_argv.contains("govfuzz_build.gpr"));
        assert!(gnat_argv.contains("aarch64-linux-gnu-gnat"));
        assert!(gnat_argv.contains("-gnatc"));
    }

    #[test]
    fn build_subcommand_writes_memory_buffer_probe_backend() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-memory-buffer-probe");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--probe-backend",
            "memory_buffer",
        ]);

        assert_eq!(exit, 0);
        let build_dir = work_dir.join("build/H-TEST");
        let runtime_project = fs::read_to_string(build_dir.join("adafuzz_runtime.gpr"))
            .expect("runtime project is readable");
        let probe_body =
            fs::read_to_string(build_dir.join("adafuzz_runtime_src/adafuzz-probe.adb"))
                .expect("selected probe body is readable");
        assert!(runtime_project.contains("adafuzz_runtime_src"));
        assert!(probe_body.contains("adafuzz_probe_memory_buffer"));
        assert!(!probe_body.contains("Ada.Streams.Stream_IO"));
        assert!(!probe_body.contains("Ada.Environment_Variables"));
    }

    #[test]
    fn build_subcommand_writes_semihosting_probe_backend() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-semihosting-probe");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--probe-backend",
            "semihosting",
        ]);

        assert_eq!(exit, 0);
        let build_dir = work_dir.join("build/H-TEST");
        let probe_body =
            fs::read_to_string(build_dir.join("adafuzz_runtime_src/adafuzz-probe.adb"))
                .expect("selected probe body is readable");
        assert!(probe_body.contains("adafuzz_semihosting_write"));
        assert!(probe_body.contains("Semihosting_File_Descriptor"));
        assert!(!probe_body.contains("Ada.Streams.Stream_IO"));
        assert!(!probe_body.contains("Ada.Environment_Variables"));
    }

    #[test]
    fn build_subcommand_writes_stub_probe_backend() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-stub-probe");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--probe-backend",
            "stub",
        ]);

        assert_eq!(exit, 0);
        let build_dir = work_dir.join("build/H-TEST");
        let probe_body =
            fs::read_to_string(build_dir.join("adafuzz_runtime_src/adafuzz-probe.adb"))
                .expect("selected probe body is readable");
        assert!(probe_body.contains("Ada.Command_Line.Set_Exit_Status"));
        assert!(probe_body.contains("Exit_Result_Class"));
        assert!(!probe_body.contains("Ada.Streams.Stream_IO"));
        assert!(!probe_body.contains("Ada.Environment_Variables"));
        assert!(!probe_body.contains("adafuzz_semihosting_write"));
        assert!(!probe_body.contains("adafuzz_probe_memory_buffer"));
    }

    #[test]
    fn build_subcommand_returns_two_when_no_compiler_present() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-no-compiler");
        let work_dir = create_minimal_work_dir(&temp);
        let empty_path = temp.join("empty-path");
        fs::create_dir_all(&empty_path).expect("empty PATH directory is created");
        let _path = PathEnvGuard::set(&empty_path);

        let exit = run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("utf-8 work dir"),
        ]);

        assert_eq!(exit, 2);
    }

    #[test]
    fn build_subcommand_returns_three_when_work_dir_missing() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("build-missing-work");
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let missing = temp.join("missing-work");
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "build",
            missing.to_str().expect("utf-8 work dir"),
        ]);

        assert_eq!(exit, 3);
    }

    #[test]
    fn stub_subcommand_returns_two_when_no_compiler() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("stub-no-compiler");
        let empty_path = temp.join("empty-path");
        fs::create_dir_all(&empty_path).expect("empty PATH directory is created");
        let _path = PathEnvGuard::set(&empty_path);

        let exit = run_from(["govfuzz", "stub", "/tmp/govfuzz-missing-work"]);

        assert_eq!(exit, 2);
    }

    #[test]
    fn stub_subcommand_returns_three_when_work_dir_missing() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("stub-missing-work");
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let missing = temp.join("missing-work");
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from(["govfuzz", "stub", missing.to_str().expect("utf-8 work dir")]);

        assert_eq!(exit, 3);
    }

    #[test]
    fn stub_subcommand_writes_manifest_on_success() {
        let _lock = PATH_LOCK.lock().expect("path lock is acquired");
        let temp = temp_dir("stub-success");
        let work_dir = create_minimal_work_dir(&temp);
        let bin_dir = temp.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake compiler bin directory is created");
        write_executable(&bin_dir.join("gprbuild"), fake_build_compiler_script());
        let _path = PathEnvGuard::set(&bin_dir);

        let exit = run_from([
            "govfuzz",
            "stub",
            work_dir.to_str().expect("utf-8 work dir"),
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("generated_stubs/manifest.json").is_file());
    }

    #[test]
    fn clean_subcommand_deletes_selected_owned_subtrees() {
        let temp = temp_dir("clean-selected");
        let work_dir = temp.join("govfuzz_work");
        for name in ["build", "corpus", "queue", "reports", "findings"] {
            fs::create_dir_all(work_dir.join(name)).expect("owned subtree is created");
        }
        fs::write(work_dir.join("notes.txt"), "keep").expect("unowned file is written");

        let exit = run_from([
            "govfuzz",
            "clean",
            work_dir.to_str().expect("work dir is utf-8"),
            "--build",
            "--corpus",
            "--reports",
        ]);

        assert_eq!(exit, 0);
        assert!(!work_dir.join("build").exists());
        assert!(!work_dir.join("corpus").exists());
        assert!(!work_dir.join("queue").exists());
        assert!(!work_dir.join("reports").exists());
        assert!(work_dir.join("findings").is_dir());
        assert!(work_dir.join("notes.txt").is_file());
    }

    #[test]
    fn clean_subcommand_all_deletes_findings_and_generated_subtrees() {
        let temp = temp_dir("clean-all");
        let work_dir = temp.join("govfuzz_work");
        for name in [
            "build",
            "corpus",
            "queue",
            "reports",
            "harnesses",
            "generated_harnesses",
            "generated_stubs",
            "fake_corba",
            "src_instrumented",
            "findings",
        ] {
            fs::create_dir_all(work_dir.join(name)).expect("owned subtree is created");
        }
        fs::write(work_dir.join("notes.txt"), "keep").expect("unowned file is written");

        let exit = run_from([
            "govfuzz",
            "clean",
            work_dir.to_str().expect("work dir is utf-8"),
            "--all",
        ]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("notes.txt").is_file());
        assert_eq!(
            fs::read_dir(&work_dir).expect("work dir remains").count(),
            1
        );
    }

    #[test]
    fn clean_subcommand_without_scope_is_noop() {
        let temp = temp_dir("clean-noop");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(work_dir.join("build")).expect("build subtree is created");

        let exit = run_from(["govfuzz", "clean", work_dir.to_str().expect("utf-8")]);

        assert_eq!(exit, 0);
        assert!(work_dir.join("build").is_dir());
    }

    #[test]
    fn clean_subcommand_missing_workdir_returns_three() {
        let temp = temp_dir("clean-missing");
        let missing = temp.join("missing-work");

        let exit = run_from(["govfuzz", "clean", missing.to_str().expect("utf-8")]);

        assert_eq!(exit, 3);
    }

    #[test]
    fn scan_subcommand_writes_scan_index_json() {
        let temp = temp_dir("scan-index");
        let source_dir = temp.join("src");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&source_dir).expect("source directory is created");
        fs::write(
            source_dir.join("demo.adb"),
            "procedure Demo (Input : in String) is\nbegin\n   raise Constraint_Error;\nend Demo;\n",
        )
        .expect("Ada source is written");

        let exit = run_from([
            "govfuzz",
            "scan",
            source_dir.to_str().expect("source dir path is utf-8"),
            "--work-dir",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        let index = fs::read_to_string(work_dir.join("scan_index.json"))
            .expect("scan index JSON is written");
        let json: serde_json::Value = serde_json::from_str(&index).expect("scan index is JSON");
        assert_eq!(exit, 0);
        assert_eq!(json["schema_version"], 3);
        assert_eq!(json["total_files"], 1);
        assert_eq!(json["total_subprograms"], 1);
        assert_eq!(json["total_raises"], 1);
        assert_eq!(json["skipped"].as_array().expect("skipped array").len(), 0);
        assert!(json["files"][0]["path"]
            .as_str()
            .expect("file path is a string")
            .ends_with("demo.adb"));
        assert_eq!(json["files"][0]["language"], "ada");
        assert_eq!(json["files"][0]["target_details"][0]["name"], "demo");
        assert_eq!(json["files"][0]["target_details"][0]["line"], 1);
        assert!(json["files"][0]["target_details"][0]["score"].is_number());
    }

    #[test]
    fn scan_subcommand_transcodes_non_utf8_ada_files() {
        let temp = temp_dir("scan-transcodes-non-utf8");
        let source_dir = temp.join("src");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&source_dir).expect("source directory is created");
        fs::write(
            source_dir.join("good.adb"),
            "procedure Good is begin null; end Good;\n",
        )
        .expect("Ada source is written");
        // A Latin-1 byte (0xFF) in a comment must not drop the whole file:
        // legacy Ada is routinely non-UTF-8, and `Legacy` is a real target.
        fs::write(
            source_dir.join("legacy.adb"),
            b"procedure Legacy is\n-- \xFF\nbegin\n   null;\nend Legacy;\n",
        )
        .expect("legacy source is written");

        let exit = run_from([
            "govfuzz",
            "scan",
            source_dir.to_str().expect("source dir path is utf-8"),
            "--work-dir",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        let index = fs::read_to_string(work_dir.join("scan_index.json"))
            .expect("scan index JSON is written");
        let json: serde_json::Value = serde_json::from_str(&index).expect("scan index is JSON");
        assert_eq!(exit, 0);
        // Both files are scanned and nothing is skipped for encoding.
        assert_eq!(json["total_files"], 2);
        assert_eq!(json["skipped"].as_array().expect("skipped array").len(), 0);
        let scanned_legacy = json["files"]
            .as_array()
            .expect("files array")
            .iter()
            .any(|f| {
                f["path"]
                    .as_str()
                    .map(|p| p.ends_with("legacy.adb"))
                    .unwrap_or(false)
            });
        assert!(
            scanned_legacy,
            "transcoded legacy.adb should be scanned: {json}"
        );
    }

    #[test]
    fn scan_subcommand_returns_one_when_nothing_parseable() {
        let temp = temp_dir("scan-empty");
        let source_dir = temp.join("src");
        let work_dir = temp.join("govfuzz_work");
        fs::create_dir_all(&source_dir).expect("source directory is created");
        fs::write(source_dir.join("README.md"), "not Ada").expect("non-Ada file is written");

        let exit = run_from([
            "govfuzz",
            "scan",
            source_dir.to_str().expect("source dir path is utf-8"),
            "--work-dir",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]);

        let index = fs::read_to_string(work_dir.join("scan_index.json"))
            .expect("scan index JSON is written");
        let json: serde_json::Value = serde_json::from_str(&index).expect("scan index is JSON");
        assert_eq!(exit, 1);
        assert_eq!(json["total_files"], 0);
        assert_eq!(json["files"].as_array().expect("files array").len(), 0);
    }

    fn create_minimal_work_dir(parent: &Path) -> PathBuf {
        let work_dir = parent.join("govfuzz_work");
        let source_dir = work_dir.join("src_instrumented");
        let harness_dir = work_dir.join("generated_harnesses/H-TEST");
        fs::create_dir_all(&source_dir).expect("instrumented source directory is created");
        fs::create_dir_all(&harness_dir).expect("harness directory is created");
        fs::write(
            source_dir.join("pkg.adb"),
            "procedure Pkg is begin null; end Pkg;\n",
        )
        .expect("instrumented source is written");
        fs::write(
            harness_dir.join("main.adb"),
            "procedure Main is begin null; end Main;\n",
        )
        .expect("harness main is written");
        work_dir
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("temporary directory is created");
        dir
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("fake compiler is written");
        make_executable(path);
    }

    fn fake_build_compiler_script() -> &'static str {
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'GNATMAKE 13.2.0 20240106 (experimental)' 'Target: x86_64-pc-linux-gnu' 'Runtime: default'
  exit 0
fi

if [ "$1" = "-P" ]; then
  if [ -n "$GOVFUZZ_BUILD_LOG" ]; then
    printf '%s\n' "$@" > "$GOVFUZZ_BUILD_LOG"
  fi
  printf '%s\n' 'build ok'
  exit 0
fi

exit 0
"#
    }

    fn fake_raw_gnat_canary_script() -> &'static str {
        r#"#!/bin/sh
if [ -n "$GOVFUZZ_RAW_GNAT_LOG" ]; then
  printf '%s\n' "$0" "$@" > "$GOVFUZZ_RAW_GNAT_LOG"
fi

if [ "$#" -eq 4 ] &&
   [ "$1" = "-c" ] &&
   [ "$2" = "-gnatc" ]; then
  exit 0
fi

printf 'unexpected raw gnat argv:' >&2
for arg in "$@"; do
  printf ' <%s>' "$arg" >&2
done
printf '\n' >&2
exit 1
"#
    }

    struct PathEnvGuard {
        original: Option<OsString>,
    }

    impl PathEnvGuard {
        fn set(path: &Path) -> Self {
            let original = std::env::var_os("PATH");
            std::env::set_var("PATH", path);
            Self { original }
        }
    }

    impl Drop for PathEnvGuard {
        fn drop(&mut self) {
            if let Some(original) = &self.original {
                std::env::set_var("PATH", original);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set<V>(key: &'static str, value: V) -> Self
        where
            V: AsRef<std::ffi::OsStr>,
        {
            let original = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(original) = &self.original {
                std::env::set_var(self.key, original);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .expect("fake compiler metadata is readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake compiler is executable");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
