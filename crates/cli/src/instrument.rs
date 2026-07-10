// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct InstrumentArgs {
    /// Ada source file to instrument.
    pub source: PathBuf,

    /// Output directory. Default: govfuzz_work/src_instrumented/.
    #[arg(long, default_value = "govfuzz_work/src_instrumented")]
    pub output: PathBuf,
}

pub fn run(args: InstrumentArgs) -> Result<()> {
    let source = std::fs::read_to_string(&args.source)
        .with_context(|| format!("read Ada source {}", args.source.display()))?;
    let ast = ada_parser::reconcile::build_structural_ast(&source, None, &args.source)
        .with_context(|| format!("scan Ada source {}", args.source.display()))?;
    let result = instrumenter::instrument_unit(instrumenter::InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &args.source,
    })?;

    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("create output directory {}", args.output.display()))?;
    let basename = args.source.file_name().ok_or_else(|| {
        anyhow::anyhow!("source path has no file name: {}", args.source.display())
    })?;
    let dest = args.output.join(basename);
    std::fs::write(&dest, &result.rewritten_source)
        .with_context(|| format!("write instrumented source {}", dest.display()))?;
    let sidecar = args.output.join("breadcrumbs.json");
    std::fs::write(
        &sidecar,
        instrumenter::breadcrumbs_sidecar_json(&result.breadcrumbs)?,
    )
    .with_context(|| format!("write breadcrumb sidecar {}", sidecar.display()))?;

    println!("Instrumented: {}", dest.display());
    println!("Sidecar:      {}", sidecar.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run, InstrumentArgs};
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Parser)]
    struct InstrumentOnly {
        #[command(flatten)]
        args: InstrumentArgs,
    }

    #[test]
    fn instrument_subcommand_writes_to_default_output_dir() {
        let temp = temp_dir("default-output");
        let source = write_source(&temp);
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();

        let args = InstrumentOnly::try_parse_from(["instrument", source.to_str().unwrap()])
            .unwrap()
            .args;
        run(args).unwrap();

        assert!(temp.join("govfuzz_work/src_instrumented/src.adb").is_file());
        std::env::set_current_dir(cwd).unwrap();
    }

    #[test]
    fn instrument_subcommand_writes_to_custom_output_dir() {
        let temp = temp_dir("custom-output");
        let source = write_source(&temp);
        let output = temp.join("out");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        assert!(output.join("src.adb").is_file());
    }

    #[test]
    fn instrument_subcommand_creates_output_dir_if_missing() {
        let temp = temp_dir("creates-output");
        let source = write_source(&temp);
        let output = temp.join("missing/nested");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        assert!(output.is_dir());
    }

    #[test]
    fn instrument_subcommand_writes_breadcrumbs_json_sidecar() {
        let temp = temp_dir("sidecar");
        let source = write_source(&temp);
        let output = temp.join("out");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        let sidecar = fs::read_to_string(output.join("breadcrumbs.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sidecar).unwrap();
        assert!(value.get("1").is_some());
    }

    fn write_source(dir: &Path) -> PathBuf {
        let source = dir.join("src.adb");
        fs::write(&source, "procedure P is begin A; end P;").unwrap();
        source
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cli-instrument-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
