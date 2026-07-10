// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use confidence_model::{ConfidenceLabel, TrainingSample};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct ModelArgs {
    #[command(subcommand)]
    pub command: ModelCommand,
}

#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    Train(TrainArgs),
}

#[derive(Debug, clap::Args)]
pub struct TrainArgs {
    /// Labeled findings JSON file.
    #[arg(long)]
    pub labels: PathBuf,

    /// Output model path.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LabelInput {
    Object { labels: Vec<LabelRecord> },
    Array(Vec<LabelRecord>),
}

#[derive(Debug, Deserialize)]
struct LabelRecord {
    label: ConfidenceLabel,
    #[serde(default)]
    finding: Option<Value>,
    #[serde(default)]
    finding_path: Option<PathBuf>,
}

pub fn run(args: ModelArgs) -> i32 {
    match run_result(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    }
}

fn run_result(args: ModelArgs) -> Result<()> {
    match args.command {
        ModelCommand::Train(args) => train(args),
    }
}

fn train(args: TrainArgs) -> Result<()> {
    let samples = load_training_samples(&args.labels)?;
    let model = confidence_model::train_model(&samples);

    if let Some(parent) = args
        .out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create model output directory {}", parent.display()))?;
    }
    fs::write(&args.out, serde_json::to_vec_pretty(&model)?)
        .with_context(|| format!("write model {}", args.out.display()))?;

    println!(
        "MODEL path={} labels={} model_id={} warm={}",
        args.out.display(),
        model.label_count,
        model.model_id,
        model.is_warm()
    );
    Ok(())
}

fn load_training_samples(labels_path: &Path) -> Result<Vec<TrainingSample>> {
    let value: Value = serde_json::from_slice(
        &fs::read(labels_path).with_context(|| format!("read {}", labels_path.display()))?,
    )
    .with_context(|| format!("parse {}", labels_path.display()))?;
    let input = serde_json::from_value::<LabelInput>(value)
        .with_context(|| format!("decode {}", labels_path.display()))?;
    let records = match input {
        LabelInput::Object { labels } => labels,
        LabelInput::Array(labels) => labels,
    };
    let base_dir = labels_path.parent().unwrap_or_else(|| Path::new("."));

    records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let finding = match (record.finding, record.finding_path) {
                (Some(finding), _) => finding,
                (None, Some(path)) => read_finding_path(base_dir, &path)
                    .with_context(|| format!("load label record {index} finding_path"))?,
                (None, None) => {
                    return Err(anyhow!(
                        "label record {index} must include finding or finding_path"
                    ));
                }
            };
            if !finding.is_object() {
                return Err(anyhow!(
                    "label record {index} finding must be a JSON object"
                ));
            }
            Ok(TrainingSample::new(record.label, finding))
        })
        .collect()
}

fn read_finding_path(base_dir: &Path, path: &Path) -> Result<Value> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    serde_json::from_slice(
        &fs::read(&resolved).with_context(|| format!("read {}", resolved.display()))?,
    )
    .with_context(|| format!("parse {}", resolved.display()))
}
