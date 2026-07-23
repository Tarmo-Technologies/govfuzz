// SPDX-License-Identifier: Apache-2.0

//! `govfuzz corpus` subcommand: import/export/merge corpora across
//! AFL, libFuzzer, Honggfuzz, and govfuzz directory layouts.

use corpus::bridge::{
    detect_format, export_dir, import_dir, merge_dirs, BridgeError, Format, ImportSummary,
};
use corpus::compute_signature;
use event_log::Testcase;
use fuzz_engine_builtin::{CoverageInput, CoverageProxy, CoverageSignature};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct CorpusArgs {
    #[command(subcommand)]
    pub command: CorpusCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum CorpusCommand {
    /// Import a foreign corpus into a govfuzz-layout directory.
    Import(ImportArgs),
    /// Export a govfuzz corpus to another fuzzer's layout.
    Export(ExportArgs),
    /// Merge multiple corpus directories, deduplicating by content.
    Merge(MergeArgs),
    /// Produce a coverage-minimal corpus: replay each input through a harness
    /// and keep only those that add new coverage (libFuzzer `-merge=1`).
    Minimize(MinimizeCorpusArgs),
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Source format. `auto` (default) detects from filename
    /// patterns; pass an explicit value for mixed-format dirs.
    #[arg(long, default_value = "auto")]
    pub from: String,

    /// Source directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Target directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// Target format.
    #[arg(long, default_value = "libfuzzer")]
    pub to: String,

    /// Source directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Target directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct MergeArgs {
    /// Output directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,

    /// One or more input directories to merge.
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct MinimizeCorpusArgs {
    /// Harness binary to replay corpus inputs through.
    #[arg(long)]
    pub harness: PathBuf,

    /// Input corpus directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Output directory for the coverage-minimal corpus (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

pub fn run(args: CorpusArgs) -> i32 {
    match args.command {
        CorpusCommand::Import(import_args) => run_import(import_args),
        CorpusCommand::Export(export_args) => run_export(export_args),
        CorpusCommand::Merge(merge_args) => run_merge(merge_args),
        CorpusCommand::Minimize(minimize_args) => run_minimize(minimize_args),
    }
}

fn run_import(args: ImportArgs) -> i32 {
    let from_explicit = Format::parse(&args.from);
    let source_format = match from_explicit {
        Some(Format::Unknown) | None => match detect_format(&args.input) {
            Ok(format) => format,
            Err(error) => return fail(error),
        },
        Some(explicit) => explicit,
    };
    match import_dir(&args.input, &args.output, source_format) {
        Ok(summary) => {
            print_summary("imported", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_export(args: ExportArgs) -> i32 {
    let Some(target) = Format::parse(&args.to) else {
        eprintln!("error: unknown target format: {}", args.to);
        return 2;
    };
    if matches!(target, Format::Unknown) {
        eprintln!("error: target format must be one of govfuzz, libfuzzer, afl, honggfuzz");
        return 2;
    }
    match export_dir(&args.input, &args.output, target) {
        Ok(summary) => {
            print_summary("exported", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_merge(args: MergeArgs) -> i32 {
    match merge_dirs(&args.inputs, &args.output) {
        Ok(summary) => {
            print_summary("merged", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_minimize(args: MinimizeCorpusArgs) -> i32 {
    let inputs = match read_corpus_inputs(&args.input) {
        Ok(inputs) => inputs,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };
    if inputs.is_empty() {
        eprintln!("error: no corpus files found in {}", args.input.display());
        return 1;
    }

    let runner = crate::runner::harness_runner(
        args.harness.clone(),
        None,
        Vec::new(),
        crate::runner::SandboxModeArg::Auto,
        None,
        false,
    );
    let work_dir = match scratch_work_dir() {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };

    let mut saw_coverage = false;
    let total = inputs.len();
    let selection = select_coverage_minimal(&inputs, |bytes| {
        match crate::fuzz::replay_input_testcases(&runner, &work_dir, bytes) {
            Ok(testcases) => {
                if !testcases.is_empty() {
                    saw_coverage = true;
                }
                Ok(testcases)
            }
            // One unreplayable input must not abort the whole minimize: warn,
            // treat it as contributing no coverage, and keep going.
            Err(error) => {
                eprintln!("warning: skipping input (replay failed): {error}");
                Ok(Vec::new())
            }
        }
    });
    let _ = std::fs::remove_dir_all(&work_dir);

    let kept = match selection {
        Ok(kept) => kept,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };

    if !saw_coverage {
        eprintln!(
            "warning: harness produced no runtrace coverage for any input; \
             C/C++ libFuzzer harnesses are not supported for coverage-minimal \
             merge — use `govfuzz corpus merge` for content deduplication"
        );
    }

    if let Err(error) = copy_selected(&args.input, &args.output, &kept) {
        eprintln!("error: {error}");
        return 1;
    }

    println!(
        "minimized {total} inputs -> {} coverage-minimal ({} dropped)",
        kept.len(),
        total - kept.len(),
    );
    0
}

/// Read every regular file in `dir` as `(file_name, bytes)`, sorted by file
/// name so the coverage-minimal selection is deterministic across runs.
fn read_corpus_inputs(dir: &std::path::Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut inputs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        inputs.push((name, bytes));
    }
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(inputs)
}

fn copy_selected(
    input: &std::path::Path,
    output: &std::path::Path,
    kept: &[String],
) -> Result<(), String> {
    std::fs::create_dir_all(output).map_err(|e| format!("create {}: {e}", output.display()))?;
    for name in kept {
        let src = input.join(name);
        let dst = output.join(name);
        std::fs::copy(&src, &dst)
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
    }
    Ok(())
}

fn scratch_work_dir() -> Result<PathBuf, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "govfuzz-corpus-minimize-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create work dir {}: {e}", dir.display()))?;
    Ok(dir)
}

fn print_summary(verb: &str, summary: &ImportSummary) {
    println!(
        "{verb} {} unique files, {} duplicates skipped ({} -> {})",
        summary.unique,
        summary.duplicates,
        summary.source_format.as_str(),
        summary.target_format.as_str(),
    );
}

fn fail(error: BridgeError) -> i32 {
    eprintln!("error: {error}");
    1
}

/// Exception-handler coverage signatures for a single replayed testcase, in
/// the same form the built-in engine feeds its `CoverageProxy`.
fn testcase_signatures(testcase: &Testcase) -> Vec<CoverageSignature> {
    testcase
        .handlers
        .iter()
        .map(|handler| CoverageSignature::from_bytes(compute_signature(testcase, handler).0))
        .collect()
}

/// Greedily select a coverage-minimal subset of `inputs` (libFuzzer `-merge`
/// semantics): replay each input in order through `replay`, feed the resulting
/// testcases into a running `CoverageProxy`, and keep an input only when it
/// contributes at least one new coverage feature (breadcrumb, handler, raise,
/// top-level, return class, mock call, or exception signature). Inputs that
/// reproduce only already-seen coverage — or no coverage at all — are dropped.
fn select_coverage_minimal<F>(
    inputs: &[(String, Vec<u8>)],
    mut replay: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&[u8]) -> Result<Vec<Testcase>, String>,
{
    let mut proxy = CoverageProxy::default();
    let mut kept = Vec::new();
    for (name, input) in inputs {
        let testcases = replay(input)?;
        let mut added = false;
        for testcase in &testcases {
            let signatures = testcase_signatures(testcase);
            if !proxy
                .record(CoverageInput::new(testcase, &signatures))
                .is_empty()
            {
                added = true;
            }
        }
        if added {
            kept.push(name.clone());
        }
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testcase_with_crumbs(crumbs: Vec<u32>) -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs,
            handlers: Vec::new(),
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    #[test]
    fn select_coverage_minimal_keeps_only_coverage_adding_inputs() {
        let inputs = vec![
            ("a".to_owned(), b"a".to_vec()),
            ("b".to_owned(), b"b".to_vec()),
            ("c".to_owned(), b"c".to_vec()),
            ("d".to_owned(), b"d".to_vec()),
        ];

        let kept = select_coverage_minimal(&inputs, |input| {
            Ok(match input {
                // distinct breadcrumb -> novel coverage
                b"a" => vec![testcase_with_crumbs(vec![1])],
                // same breadcrumb as "a" -> no new coverage
                b"b" => vec![testcase_with_crumbs(vec![1])],
                // fresh breadcrumb -> novel coverage
                b"c" => vec![testcase_with_crumbs(vec![2])],
                // no events at all -> nothing to add
                _ => Vec::new(),
            })
        })
        .unwrap();

        assert_eq!(kept, vec!["a".to_owned(), "c".to_owned()]);
    }
}
