// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CALIBRATION_ID: &str = "govfuzz.calibrated.v1";
pub const MODEL_SCHEMA_VERSION: &str = "govfuzz.confidence_model.v1";
pub const LEARNED_MODEL_ID_PREFIX: &str = "govfuzz.learned.v1";
pub const DEFAULT_STUB_WEIGHT: f64 = 0.05;
pub const FAKE_CORBA_PENALTY: f64 = 0.10;
pub const UNKNOWN_HANDLER_PENALTY: f64 = 0.05;
/// Hard ceiling on confidence for a finding whose fuzzed entry is NOT a proven
/// attacker-controlled input channel (the harness drove an internal function /
/// output serializer directly; public-API reachability is UNPROVEN). Applied to
/// both the calibrated score and the learned blend so "the harness reached it"
/// can never read as "an attacker can reach it" (≈1.00). Applied as a flat cap
/// — like the `FAKE_CORBA_PENALTY` / `UNKNOWN_HANDLER_PENALTY` constants — and
/// NOT as a learned feature, so the trained weight vector is unchanged.
pub const UNPROVEN_REACHABILITY_CAP: f64 = 0.5;
pub const MIN_CONFIDENCE: f64 = 0.05;
/// Human-readable note attached to a finding produced under `auto --force` whose
/// forced build fuzzed synthesized STUBS (opaque params / blind-stubbed symbols).
/// A crash there may be a stub artifact, not a real defect — so the finding's
/// confidence is floored (see [`forced_floor`]) and this note surfaced.
pub const FORCED_STUB_NOTE: &str =
    "forced: ran against synthesized stubs; a crash may be a stub artifact, not a real defect.";

/// Floor a finding's numeric confidence for a forced/stub-heavy run: a forced
/// crash must never read as a confirmed bug, so its score is pinned to the model
/// floor ([`MIN_CONFIDENCE`]). Idempotent — a value already at/under the floor is
/// returned as the floor.
#[must_use]
pub fn forced_floor(_confidence: f64) -> f64 {
    MIN_CONFIDENCE
}
pub const COLD_START_MIN_LABELS: usize = 100;
pub const LEARNED_HEAVY_MIN_LABELS: usize = 1_000;
pub const TRAINING_EPOCHS: u32 = 600;
pub const TRAINING_LEARNING_RATE: f64 = 0.05;
pub const ONLINE_LEARNING_RATE: f64 = 0.02;

const FEATURE_NAMES: [&str; 16] = [
    "stub_count",
    "stubbed_call_depth",
    "fake_corba_used",
    "signature_age",
    "breadcrumb_density",
    "handler_explicit_raise",
    "handler_swallowed_predefined",
    "handler_swallowed_user",
    "handler_top_level",
    "handler_unknown",
    "return_normal",
    "return_failure",
    "return_timeout",
    "return_unknown",
    "param_shape_complexity",
    "target_score",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfidenceReport {
    pub calibrated: f64,
    pub learned: Option<f64>,
    pub blend: f64,
    pub model_id: Option<String>,
    pub calibration_id: &'static str,
    pub features: ConfidenceFeatures,
    pub terms: Vec<ConfidenceTerm>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceFeatures {
    pub stub_count: u32,
    pub calls_through_stub: u32,
    pub stubbed_call_depth: u32,
    pub fake_corba_used: bool,
    pub signature_age: u32,
    pub handler_kind: HandlerKind,
    pub return_class: ReturnClass,
    pub breadcrumb_density: f64,
    pub target_score: Option<f64>,
    pub param_shape_complexity: u32,
    /// NON-learned input: the fuzzed entry's parameters are NOT a proven
    /// attacker-controlled input channel (the harness drove an internal function
    /// directly; public-API reachability is UNPROVEN). Consumed ONLY by the
    /// calibration cap (`UNPROVEN_REACHABILITY_CAP`); it is deliberately excluded
    /// from `FEATURE_NAMES` / the learned feature vector so the trained model is
    /// unaffected.
    #[serde(default)]
    pub entry_reachability_unproven: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerKind {
    ExplicitRaise,
    SwallowedPredefined,
    SwallowedUser,
    TopLevel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnClass {
    Normal,
    Failure,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfidenceTerm {
    pub name: &'static str,
    pub value: f64,
    pub weight: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearnedConfidenceModel {
    pub schema_version: String,
    pub model_id: String,
    pub label_count: usize,
    pub feature_names: Vec<String>,
    pub weights: Vec<f64>,
    pub bias: f64,
    pub training: TrainingMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingMetadata {
    pub algorithm: String,
    pub epochs: u32,
    pub learning_rate: f64,
    pub online_learning_rate: f64,
    pub cold_start_min_labels: usize,
    pub learned_heavy_min_labels: usize,
}

impl Default for TrainingMetadata {
    fn default() -> Self {
        Self {
            algorithm: "logistic_regression_sgd_v1".to_owned(),
            epochs: TRAINING_EPOCHS,
            learning_rate: TRAINING_LEARNING_RATE,
            online_learning_rate: ONLINE_LEARNING_RATE,
            cold_start_min_labels: COLD_START_MIN_LABELS,
            learned_heavy_min_labels: LEARNED_HEAVY_MIN_LABELS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLabel {
    TruePositive,
    FalsePositive,
    LowValue,
}

impl ConfidenceLabel {
    pub fn target_value(self) -> f64 {
        match self {
            Self::TruePositive => 1.0,
            Self::FalsePositive => 0.0,
            Self::LowValue => 0.25,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrainingSample {
    pub label: ConfidenceLabel,
    pub finding: Value,
}

impl TrainingSample {
    pub fn new(label: ConfidenceLabel, finding: Value) -> Self {
        Self { label, finding }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TrainingDataError {
    #[error("invalid label data: {0}")]
    Json(#[from] serde_json::Error),
    #[error("label record {index} must include a finding object")]
    MissingFinding { index: usize },
    #[error("label record {index} finding must be a JSON object")]
    FindingNotObject { index: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ModelLoadError {
    #[error("invalid model JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid learned confidence model: {0}")]
    Validation(#[from] ModelValidationError),
}

#[derive(Debug, thiserror::Error)]
pub enum ModelValidationError {
    #[error("schema_version must be {expected}, got {actual}")]
    SchemaVersion { expected: String, actual: String },
    #[error("feature_names do not match the v1 feature layout")]
    FeatureLayout,
    #[error("weights length must be {expected}, got {actual}")]
    WeightCount { expected: usize, actual: usize },
    #[error("weight at index {index} is not finite")]
    NonFiniteWeight { index: usize },
    #[error("bias is not finite")]
    NonFiniteBias,
    #[error("training metadata is incompatible with v1 defaults: {field}")]
    TrainingMetadata { field: &'static str },
    #[error("model_id mismatch: expected {expected}, got {actual}")]
    ModelId { expected: String, actual: String },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawTrainingInput {
    Object { labels: Vec<RawTrainingRecord> },
    Array(Vec<RawTrainingRecord>),
}

#[derive(Debug, Deserialize)]
struct RawTrainingRecord {
    label: ConfidenceLabel,
    #[serde(default)]
    finding: Option<Value>,
}

impl LearnedConfidenceModel {
    pub fn new() -> Self {
        let mut model = Self {
            schema_version: MODEL_SCHEMA_VERSION.to_owned(),
            model_id: String::new(),
            label_count: 0,
            feature_names: feature_names(),
            weights: vec![0.0; FEATURE_NAMES.len()],
            bias: 0.0,
            training: TrainingMetadata::default(),
        };
        model.refresh_model_id();
        model
    }

    pub fn is_warm(&self) -> bool {
        self.label_count >= COLD_START_MIN_LABELS && self.is_compatible()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ModelLoadError> {
        let model: Self = serde_json::from_slice(bytes)?;
        model.validate()?;
        Ok(model)
    }

    pub fn validate(&self) -> Result<(), ModelValidationError> {
        if self.schema_version != MODEL_SCHEMA_VERSION {
            return Err(ModelValidationError::SchemaVersion {
                expected: MODEL_SCHEMA_VERSION.to_owned(),
                actual: self.schema_version.clone(),
            });
        }
        if self.feature_names != feature_names() {
            return Err(ModelValidationError::FeatureLayout);
        }
        if self.weights.len() != FEATURE_NAMES.len() {
            return Err(ModelValidationError::WeightCount {
                expected: FEATURE_NAMES.len(),
                actual: self.weights.len(),
            });
        }
        for (index, weight) in self.weights.iter().enumerate() {
            if !weight.is_finite() {
                return Err(ModelValidationError::NonFiniteWeight { index });
            }
        }
        if !self.bias.is_finite() {
            return Err(ModelValidationError::NonFiniteBias);
        }
        self.validate_training_metadata()?;
        let expected = self.expected_model_id();
        if self.model_id != expected {
            return Err(ModelValidationError::ModelId {
                expected,
                actual: self.model_id.clone(),
            });
        }
        Ok(())
    }

    pub fn expected_model_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.as_bytes());
        hasher.update([0]);
        hasher.update((self.label_count as u64).to_le_bytes());
        hasher.update([0]);
        for name in &self.feature_names {
            hasher.update(name.as_bytes());
            hasher.update([0]);
        }
        for weight in &self.weights {
            hasher.update(weight.to_le_bytes());
        }
        hasher.update(self.bias.to_le_bytes());
        hasher.update(self.training.algorithm.as_bytes());
        hasher.update([0]);
        hasher.update(self.training.epochs.to_le_bytes());
        hasher.update(self.training.learning_rate.to_le_bytes());
        hasher.update(self.training.online_learning_rate.to_le_bytes());
        hasher.update((self.training.cold_start_min_labels as u64).to_le_bytes());
        hasher.update((self.training.learned_heavy_min_labels as u64).to_le_bytes());
        let digest = hasher.finalize();
        format!(
            "{LEARNED_MODEL_ID_PREFIX}.{}",
            hex_prefix(digest.as_slice(), 12)
        )
    }

    pub fn predict_finding(&self, finding: &Value) -> Option<f64> {
        let features = extract_features(finding);
        self.predict_features(&features)
    }

    pub fn predict_features(&self, features: &ConfidenceFeatures) -> Option<f64> {
        if !self.is_warm() {
            return None;
        }
        Some(round3(self.raw_predict_features(features)))
    }

    pub fn update(&mut self, sample: &TrainingSample) {
        self.update_with_learning_rate(sample, self.training.online_learning_rate);
    }

    pub fn update_with_learning_rate(&mut self, sample: &TrainingSample, learning_rate: f64) {
        self.ensure_layout();
        let vector = feature_vector(&extract_features(&sample.finding));
        apply_gradient(
            &mut self.weights,
            &mut self.bias,
            &vector,
            sample.label.target_value(),
            learning_rate,
        );
        self.label_count = self.label_count.saturating_add(1);
        self.round_parameters();
        self.refresh_model_id();
    }

    fn raw_predict_features(&self, features: &ConfidenceFeatures) -> f64 {
        sigmoid(dot(&self.weights, &feature_vector(features)) + self.bias)
    }

    fn is_compatible(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_training_metadata(&self) -> Result<(), ModelValidationError> {
        let defaults = TrainingMetadata::default();
        if self.training.algorithm != defaults.algorithm {
            return Err(ModelValidationError::TrainingMetadata { field: "algorithm" });
        }
        if self.training.epochs != defaults.epochs {
            return Err(ModelValidationError::TrainingMetadata { field: "epochs" });
        }
        if self.training.learning_rate != defaults.learning_rate {
            return Err(ModelValidationError::TrainingMetadata {
                field: "learning_rate",
            });
        }
        if self.training.online_learning_rate != defaults.online_learning_rate {
            return Err(ModelValidationError::TrainingMetadata {
                field: "online_learning_rate",
            });
        }
        if self.training.cold_start_min_labels != defaults.cold_start_min_labels {
            return Err(ModelValidationError::TrainingMetadata {
                field: "cold_start_min_labels",
            });
        }
        if self.training.learned_heavy_min_labels != defaults.learned_heavy_min_labels {
            return Err(ModelValidationError::TrainingMetadata {
                field: "learned_heavy_min_labels",
            });
        }
        Ok(())
    }

    fn ensure_layout(&mut self) {
        if self.feature_names != feature_names() {
            self.feature_names = feature_names();
            self.weights = vec![0.0; FEATURE_NAMES.len()];
        }
        if self.weights.len() != FEATURE_NAMES.len() {
            self.weights.resize(FEATURE_NAMES.len(), 0.0);
        }
        if self.schema_version != MODEL_SCHEMA_VERSION {
            self.schema_version = MODEL_SCHEMA_VERSION.to_owned();
        }
    }

    fn round_parameters(&mut self) {
        for weight in &mut self.weights {
            *weight = round6(*weight);
        }
        self.bias = round6(self.bias);
    }

    fn refresh_model_id(&mut self) {
        self.model_id = self.expected_model_id();
    }
}

impl Default for LearnedConfidenceModel {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crate_name() -> &'static str {
    "confidence_model"
}

pub fn learned_feature_names() -> Vec<String> {
    feature_names()
}

pub fn calibrated_confidence(finding: &Value) -> ConfidenceReport {
    confidence_with_model(finding, None)
}

pub fn confidence_with_model(
    finding: &Value,
    model: Option<&LearnedConfidenceModel>,
) -> ConfidenceReport {
    let features = extract_features(finding);
    let mut report = calibrated_confidence_for_features(features);

    if let Some(model) = model {
        if let Some(learned) = model.predict_features(&report.features) {
            report.learned = Some(learned);
            let mut blend = blend_confidence(report.calibrated, learned, model.label_count);
            // The learned model could pull the blend back up; re-apply the
            // unproven-reachability ceiling so the cap holds on `blend` too.
            if report.features.entry_reachability_unproven {
                blend = round3(blend.min(UNPROVEN_REACHABILITY_CAP));
            }
            report.blend = blend;
            report.model_id = Some(model.model_id.clone());
        }
    }

    report
}

pub fn calibrated_confidence_for_features(features: ConfidenceFeatures) -> ConfidenceReport {
    let stub_penalty = DEFAULT_STUB_WEIGHT * f64::from(features.calls_through_stub);
    let fake_corba_penalty = if features.fake_corba_used {
        FAKE_CORBA_PENALTY
    } else {
        0.0
    };
    let handler_penalty = if features.handler_kind == HandlerKind::Unknown {
        UNKNOWN_HANDLER_PENALTY
    } else {
        0.0
    };

    let raw = 1.0 - stub_penalty - fake_corba_penalty - handler_penalty;
    let uncapped = raw.clamp(MIN_CONFIDENCE, 1.0);
    // Hard cap when the fuzzed entry's reachability is unproven, so a clean
    // reproduce on an internal function can never blend to ~1.00.
    let calibrated = if features.entry_reachability_unproven {
        uncapped.min(UNPROVEN_REACHABILITY_CAP)
    } else {
        uncapped
    };
    let reachability_contribution = round3(calibrated - uncapped);
    let calibrated = round3(calibrated);

    ConfidenceReport {
        calibrated,
        learned: None,
        blend: calibrated,
        model_id: None,
        calibration_id: CALIBRATION_ID,
        terms: vec![
            ConfidenceTerm {
                name: "base",
                value: 1.0,
                weight: 1.0,
                contribution: 1.0,
            },
            ConfidenceTerm {
                name: "calls_through_stub",
                value: f64::from(features.calls_through_stub),
                weight: -DEFAULT_STUB_WEIGHT,
                contribution: round3(-stub_penalty),
            },
            ConfidenceTerm {
                name: "fake_corba_used",
                value: if features.fake_corba_used { 1.0 } else { 0.0 },
                weight: -FAKE_CORBA_PENALTY,
                contribution: round3(-fake_corba_penalty),
            },
            ConfidenceTerm {
                name: "unknown_handler_kind",
                value: if features.handler_kind == HandlerKind::Unknown {
                    1.0
                } else {
                    0.0
                },
                weight: -UNKNOWN_HANDLER_PENALTY,
                contribution: round3(-handler_penalty),
            },
            ConfidenceTerm {
                name: "reachability_unproven_cap",
                value: if features.entry_reachability_unproven {
                    1.0
                } else {
                    0.0
                },
                weight: UNPROVEN_REACHABILITY_CAP,
                // The reduction the cap actually applied (≤ 0); 0 when the entry
                // is attacker-reachable / unassessed or already below the cap.
                contribution: reachability_contribution,
            },
        ],
        features,
    }
}

pub fn train_model(samples: &[TrainingSample]) -> LearnedConfidenceModel {
    let mut weights = vec![0.0; FEATURE_NAMES.len()];
    let mut bias = 0.0;
    let vectors = samples
        .iter()
        .map(|sample| {
            (
                feature_vector(&extract_features(&sample.finding)),
                sample.label.target_value(),
            )
        })
        .collect::<Vec<_>>();

    for _ in 0..TRAINING_EPOCHS {
        for (vector, target) in &vectors {
            apply_gradient(
                &mut weights,
                &mut bias,
                vector,
                *target,
                TRAINING_LEARNING_RATE,
            );
        }
    }

    let mut model = LearnedConfidenceModel::new();
    model.label_count = samples.len();
    model.weights = weights;
    model.bias = bias;
    model.round_parameters();
    model.refresh_model_id();
    model
}

pub fn training_samples_from_value(value: Value) -> Result<Vec<TrainingSample>, TrainingDataError> {
    let input = serde_json::from_value::<RawTrainingInput>(value)?;
    let records = match input {
        RawTrainingInput::Object { labels } => labels,
        RawTrainingInput::Array(labels) => labels,
    };

    records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let finding = record
                .finding
                .ok_or(TrainingDataError::MissingFinding { index })?;
            if !finding.is_object() {
                return Err(TrainingDataError::FindingNotObject { index });
            }
            Ok(TrainingSample::new(record.label, finding))
        })
        .collect()
}

pub fn extract_features(finding: &Value) -> ConfidenceFeatures {
    let stub_count = array_len_at(finding, &["build", "deps", "stubbed"])
        .or_else(|| array_len_at(finding, &["deps", "stubbed"]))
        .unwrap_or(0);
    let calls_through_stub = number_at(finding, &["confidence", "features", "calls_through_stub"])
        .or_else(|| number_at(finding, &["build", "deps", "calls_through_stub"]))
        .or_else(|| number_at(finding, &["deps", "calls_through_stub"]))
        .or_else(|| array_len_at(finding, &["build", "deps", "stubbed_calls"]))
        .unwrap_or(stub_count);
    let stubbed_call_depth = number_at(finding, &["confidence", "features", "stubbed_call_depth"])
        .or_else(|| number_at(finding, &["build", "deps", "stubbed_call_depth"]))
        .or_else(|| number_at(finding, &["deps", "stubbed_call_depth"]))
        .unwrap_or(calls_through_stub);

    ConfidenceFeatures {
        stub_count,
        calls_through_stub,
        stubbed_call_depth,
        fake_corba_used: fake_corba_used(finding),
        signature_age: signature_age(finding),
        handler_kind: handler_kind(finding),
        return_class: return_class(finding),
        breadcrumb_density: breadcrumb_density(finding),
        target_score: f64_at(finding, &["target", "score"])
            .or_else(|| f64_at(finding, &["target_score"])),
        param_shape_complexity: number_at(finding, &["target", "param_shape_complexity"])
            .or_else(|| number_at(finding, &["param_shape_complexity"]))
            .unwrap_or(0),
        entry_reachability_unproven: entry_reachability_unproven(finding),
    }
}

/// True only when the finding carries POSITIVE evidence that its fuzzed entry is
/// not an attacker-controlled input channel: `actionability.entry_path
/// .attacker_reachable == false`. Absent (Ada / legacy findings, reachability
/// not assessed) or `true` → `false` (no cap), so the change only penalizes
/// entries known to be unproven, never merely unassessed ones.
fn entry_reachability_unproven(finding: &Value) -> bool {
    finding
        .pointer("/actionability/entry_path/attacker_reachable")
        .and_then(Value::as_bool)
        == Some(false)
}

pub fn blend_confidence(calibrated: f64, learned: f64, label_count: usize) -> f64 {
    if label_count >= LEARNED_HEAVY_MIN_LABELS {
        round3((0.2 * calibrated) + (0.8 * learned))
    } else {
        round3((0.5 * calibrated) + (0.5 * learned))
    }
}

fn feature_names() -> Vec<String> {
    FEATURE_NAMES.iter().map(ToString::to_string).collect()
}

fn feature_vector(features: &ConfidenceFeatures) -> Vec<f64> {
    vec![
        scaled_count(features.stub_count, 10),
        scaled_count(features.stubbed_call_depth, 10),
        if features.fake_corba_used { 1.0 } else { 0.0 },
        scaled_count(features.signature_age, 100),
        features.breadcrumb_density.clamp(0.0, 1.0),
        handler_flag(features.handler_kind, HandlerKind::ExplicitRaise),
        handler_flag(features.handler_kind, HandlerKind::SwallowedPredefined),
        handler_flag(features.handler_kind, HandlerKind::SwallowedUser),
        handler_flag(features.handler_kind, HandlerKind::TopLevel),
        handler_flag(features.handler_kind, HandlerKind::Unknown),
        return_flag(features.return_class, ReturnClass::Normal),
        return_flag(features.return_class, ReturnClass::Failure),
        return_flag(features.return_class, ReturnClass::Timeout),
        return_flag(features.return_class, ReturnClass::Unknown),
        scaled_count(features.param_shape_complexity, 20),
        features.target_score.unwrap_or(0.0).clamp(0.0, 100.0) / 100.0,
    ]
}

fn handler_flag(actual: HandlerKind, expected: HandlerKind) -> f64 {
    if actual == expected {
        1.0
    } else {
        0.0
    }
}

fn return_flag(actual: ReturnClass, expected: ReturnClass) -> f64 {
    if actual == expected {
        1.0
    } else {
        0.0
    }
}

fn scaled_count(value: u32, max: u32) -> f64 {
    (f64::from(value) / f64::from(max)).clamp(0.0, 1.0)
}

fn apply_gradient(
    weights: &mut [f64],
    bias: &mut f64,
    vector: &[f64],
    target: f64,
    learning_rate: f64,
) {
    let prediction = sigmoid(dot(weights, vector) + *bias);
    let error = prediction - target;
    for (weight, feature) in weights.iter_mut().zip(vector) {
        *weight -= learning_rate * error * *feature;
    }
    *bias -= learning_rate * error;
}

fn dot(weights: &[f64], vector: &[f64]) -> f64 {
    weights
        .iter()
        .zip(vector)
        .map(|(weight, feature)| weight * feature)
        .sum()
}

fn sigmoid(logit: f64) -> f64 {
    if logit >= 0.0 {
        1.0 / (1.0 + (-logit).exp())
    } else {
        let exp = logit.exp();
        exp / (1.0 + exp)
    }
}

fn fake_corba_used(finding: &Value) -> bool {
    bool_at(finding, &["fake_corba_used"])
        || bool_at(finding, &["build", "deps", "fake_corba_used"])
        || array_len_at(finding, &["build", "deps", "fake_corba"]).unwrap_or(0) > 0
        || string_at(finding, &["fixture_path"])
            .is_some_and(|path| path.to_ascii_lowercase().contains("fake_corba"))
}

fn signature_age(finding: &Value) -> u32 {
    number_at(finding, &["confidence", "features", "signature_age"])
        .or_else(|| number_at(finding, &["exception", "signature_age"]))
        .or_else(|| number_at(finding, &["signature", "age"]))
        .or_else(|| number_at(finding, &["signature_age"]))
        .unwrap_or(0)
}

fn handler_kind(finding: &Value) -> HandlerKind {
    let classification = string_at(finding, &["classification"])
        .or_else(|| string_at(finding, &["exception", "classification"]))
        .or_else(|| string_at(finding, &["result", "kind"]))
        .map(|value| normalized_token(&value));

    match classification.as_deref() {
        Some("explicit_raise") => HandlerKind::ExplicitRaise,
        Some("swallowed_predefined") => HandlerKind::SwallowedPredefined,
        Some("swallowed_user") => HandlerKind::SwallowedUser,
        Some("top_level") | Some("unhandled") | Some("top_level_unhandled") => {
            HandlerKind::TopLevel
        }
        _ => HandlerKind::Unknown,
    }
}

fn return_class(finding: &Value) -> ReturnClass {
    let value = string_at(finding, &["return_class"])
        .or_else(|| string_at(finding, &["result", "return_class"]))
        .or_else(|| string_at(finding, &["result", "class"]))
        .or_else(|| string_at(finding, &["result", "kind"]))
        .or_else(|| string_at(finding, &["classification"]))
        .map(|value| normalized_token(&value));

    match value.as_deref() {
        Some("normal") | Some("ok") | Some("success") | Some("pass") | Some("passed") => {
            ReturnClass::Normal
        }
        Some("timeout") | Some("timed_out") | Some("hang") => ReturnClass::Timeout,
        Some("failure")
        | Some("fail")
        | Some("failed")
        | Some("exception")
        | Some("raise")
        | Some("explicit_raise")
        | Some("swallowed_predefined")
        | Some("swallowed_user")
        | Some("top_level")
        | Some("unhandled")
        | Some("top_level_unhandled") => ReturnClass::Failure,
        _ => ReturnClass::Unknown,
    }
}

fn breadcrumb_density(finding: &Value) -> f64 {
    let breadcrumb_count = array_len_at(finding, &["breadcrumbs"])
        .or_else(|| array_len_at(finding, &["crumbs"]))
        .unwrap_or_else(|| {
            if finding.get("last_breadcrumb").is_some()
                || finding
                    .get("handler")
                    .and_then(|handler| handler.get("last_breadcrumb"))
                    .is_some()
                || finding
                    .get("exception")
                    .and_then(|exception| exception.get("last_breadcrumb"))
                    .is_some()
            {
                1
            } else {
                0
            }
        });
    let event_count = array_len_at(finding, &["raises"])
        .unwrap_or(0)
        .saturating_add(1);

    round3((f64::from(breadcrumb_count) / f64::from(event_count)).clamp(0.0, 1.0))
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    Some(current)
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    value_at(value, path)?.as_str().map(ToOwned::to_owned)
}

fn number_at(value: &Value, path: &[&str]) -> Option<u32> {
    let number = value_at(value, path)?.as_u64()?;
    u32::try_from(number).ok()
}

fn f64_at(value: &Value, path: &[&str]) -> Option<f64> {
    value_at(value, path)?.as_f64()
}

fn bool_at(value: &Value, path: &[&str]) -> bool {
    value_at(value, path)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn array_len_at(value: &Value, path: &[&str]) -> Option<u32> {
    let len = value_at(value, path)?.as_array()?.len();
    u32::try_from(len).ok()
}

fn normalized_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(len);
    for byte in bytes {
        if out.len() >= len {
            break;
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() >= len {
            break;
        }
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::{
        blend_confidence, calibrated_confidence, confidence_with_model, extract_features,
        forced_floor, train_model, training_samples_from_value, ConfidenceLabel, HandlerKind,
        LearnedConfidenceModel, ReturnClass, TrainingSample, CALIBRATION_ID, COLD_START_MIN_LABELS,
        FAKE_CORBA_PENALTY, FORCED_STUB_NOTE, LEARNED_MODEL_ID_PREFIX, MIN_CONFIDENCE,
        UNPROVEN_REACHABILITY_CAP,
    };
    use serde_json::json;

    #[test]
    fn forced_floor_pins_confidence_to_model_floor() {
        // A forced/stub-heavy finding that would otherwise score a perfect 1.00.
        let report = calibrated_confidence(&json!({
            "classification": "explicit_raise",
            "handler": { "last_breadcrumb": 7 },
            "build": { "deps": { "real": ["pkg.adb"], "stubbed": [], "fake_corba": [] } }
        }));
        assert_eq!(report.calibrated, 1.0);
        // Floored to the model floor regardless of the pre-floor value.
        assert_eq!(forced_floor(report.calibrated), MIN_CONFIDENCE);
        // Idempotent: a value already at the floor stays at the floor.
        assert_eq!(forced_floor(MIN_CONFIDENCE), MIN_CONFIDENCE);
        assert_eq!(forced_floor(0.0), MIN_CONFIDENCE);
        // The note names the stub-artifact caveat.
        assert!(FORCED_STUB_NOTE.contains("stub artifact"));
    }

    #[test]
    fn real_explicit_raise_scores_full_confidence() {
        let confidence = calibrated_confidence(&json!({
            "classification": "explicit_raise",
            "handler": { "last_breadcrumb": 7 },
            "build": { "deps": { "real": ["pkg.adb"], "stubbed": [], "fake_corba": [] } }
        }));

        assert_eq!(confidence.calibrated, 1.0);
        assert_eq!(confidence.blend, 1.0);
        assert_eq!(confidence.learned, None);
        assert_eq!(confidence.model_id, None);
        assert_eq!(confidence.calibration_id, CALIBRATION_ID);
        assert_eq!(confidence.features.handler_kind, HandlerKind::ExplicitRaise);
        assert_eq!(confidence.features.return_class, ReturnClass::Failure);
    }

    #[test]
    fn stubbed_dependencies_reduce_confidence_by_default_weight() {
        let confidence = calibrated_confidence(&json!({
            "classification": "swallowed_predefined",
            "build": {
                "deps": {
                    "stubbed": ["external_lib.ads", "external_lib.adb"],
                    "calls_through_stub": 3
                }
            }
        }));

        assert_eq!(confidence.features.stub_count, 2);
        assert_eq!(confidence.features.calls_through_stub, 3);
        assert_eq!(confidence.features.stubbed_call_depth, 3);
        assert_eq!(confidence.calibrated, 0.85);
        assert!(confidence
            .terms
            .iter()
            .any(|term| { term.name == "calls_through_stub" && term.contribution == -0.15 }));
    }

    #[test]
    fn fake_corba_fixture_applies_fake_corba_penalty() {
        let confidence = calibrated_confidence(&json!({
            "classification": "swallowed_user",
            "fixture_path": "examples/fake_corba_servant/bar_impl.adb",
            "build": { "deps": { "stubbed": ["foo.ads"] } }
        }));

        assert!(confidence.features.fake_corba_used);
        assert_eq!(confidence.features.calls_through_stub, 1);
        assert_eq!(confidence.calibrated, 0.85);
        assert!(confidence.terms.iter().any(|term| {
            term.name == "fake_corba_used" && term.contribution == -FAKE_CORBA_PENALTY
        }));
    }

    #[test]
    fn unknown_handler_kind_gets_small_penalty() {
        let confidence = calibrated_confidence(&json!({
            "classification": "unknown",
            "build": { "deps": { "stubbed": [] } }
        }));

        assert_eq!(confidence.features.handler_kind, HandlerKind::Unknown);
        assert_eq!(confidence.calibrated, 0.95);
    }

    #[test]
    fn confidence_is_clamped_to_floor() {
        let confidence = calibrated_confidence(&json!({
            "classification": "unknown",
            "build": { "deps": { "calls_through_stub": 40 } },
            "fake_corba_used": true
        }));

        assert_eq!(confidence.calibrated, 0.05);
    }

    #[test]
    fn unproven_reachability_caps_calibrated_and_blend() {
        // A finding that would otherwise score a perfect 1.00, but whose fuzzed
        // entry is NOT a proven attacker-controlled input channel.
        let unproven = json!({
            "classification": "explicit_raise",
            "handler": { "last_breadcrumb": 7 },
            "build": { "deps": { "real": ["pkg.adb"], "stubbed": [], "fake_corba": [] } },
            "actionability": { "entry_path": { "attacker_reachable": false } }
        });
        let report = calibrated_confidence(&unproven);
        assert!(report.features.entry_reachability_unproven);
        assert_eq!(report.calibrated, UNPROVEN_REACHABILITY_CAP);
        assert_eq!(report.blend, UNPROVEN_REACHABILITY_CAP);
        assert!(report.calibrated <= 0.5 && report.blend <= 0.5);
        // The cap is reported as an auditable term carrying the reduction it made.
        assert!(report
            .terms
            .iter()
            .any(|term| term.name == "reachability_unproven_cap" && term.contribution < 0.0));
    }

    #[test]
    fn attacker_reachable_entry_is_not_capped() {
        let reachable = json!({
            "classification": "explicit_raise",
            "handler": { "last_breadcrumb": 7 },
            "build": { "deps": { "real": ["pkg.adb"], "stubbed": [], "fake_corba": [] } },
            "actionability": { "entry_path": { "attacker_reachable": true } }
        });
        let report = calibrated_confidence(&reachable);
        assert!(!report.features.entry_reachability_unproven);
        assert_eq!(report.calibrated, 1.0);
        assert_eq!(report.blend, 1.0);
    }

    #[test]
    fn unassessed_reachability_is_not_capped() {
        // No entry_path.attacker_reachable signal (Ada / legacy finding): the cap
        // must NOT fire, preserving prior behavior.
        let report = calibrated_confidence(&json!({
            "classification": "explicit_raise",
            "handler": { "last_breadcrumb": 7 },
            "build": { "deps": { "real": ["pkg.adb"], "stubbed": [], "fake_corba": [] } }
        }));
        assert!(!report.features.entry_reachability_unproven);
        assert_eq!(report.calibrated, 1.0);
    }

    #[test]
    fn unproven_reachability_caps_blend_even_with_warm_learned_model() {
        // A warm model would otherwise pull the blend back above the cap; the
        // ceiling must still hold on `blend`.
        let model = train_model(&repeated_samples(COLD_START_MIN_LABELS));
        assert!(model.is_warm());
        let mut finding = true_positive_finding();
        finding["actionability"] = json!({ "entry_path": { "attacker_reachable": false } });
        let report = confidence_with_model(&finding, Some(&model));
        let learned = report.learned.expect("warm model predicts a learned score");
        assert!(
            report.blend <= UNPROVEN_REACHABILITY_CAP,
            "blend {} (learned {}) must respect the unproven cap",
            report.blend,
            learned
        );
    }

    #[test]
    fn extracts_auditable_feature_vector() {
        let features = extract_features(&json!({
            "classification": "swallowed_predefined",
            "breadcrumbs": [1, 2],
            "raises": [{}, {}, {}],
            "result": { "return_class": "timeout" },
            "signature_age": 12,
            "build": { "deps": { "stubbed_call_depth": 4 } },
            "target": { "score": 42.0, "param_shape_complexity": 3 }
        }));

        assert_eq!(features.handler_kind, HandlerKind::SwallowedPredefined);
        assert_eq!(features.return_class, ReturnClass::Timeout);
        assert_eq!(features.breadcrumb_density, 0.5);
        assert_eq!(features.stubbed_call_depth, 4);
        assert_eq!(features.signature_age, 12);
        assert_eq!(features.target_score, Some(42.0));
        assert_eq!(features.param_shape_complexity, 3);
    }

    #[test]
    fn parses_label_data_from_array_and_object() {
        let array = training_samples_from_value(json!([
            { "label": "true_positive", "finding": { "classification": "explicit_raise" } },
            { "label": "low_value", "finding": { "classification": "swallowed_user" } }
        ]))
        .unwrap();
        let object = training_samples_from_value(json!({
            "labels": [
                { "label": "false_positive", "finding": { "classification": "unknown" } }
            ]
        }))
        .unwrap();

        assert_eq!(array.len(), 2);
        assert_eq!(array[0].label, ConfidenceLabel::TruePositive);
        assert_eq!(array[1].label, ConfidenceLabel::LowValue);
        assert_eq!(object.len(), 1);
        assert_eq!(object[0].label, ConfidenceLabel::FalsePositive);
    }

    #[test]
    fn cold_model_keeps_learned_null_until_100_labels() {
        let samples = repeated_samples(COLD_START_MIN_LABELS - 1);
        let model = train_model(&samples);
        let report = confidence_with_model(&true_positive_finding(), Some(&model));

        assert!(!model.is_warm());
        assert_eq!(report.learned, None);
        assert_eq!(report.model_id, None);
        assert_eq!(report.blend, report.calibrated);
    }

    #[test]
    fn warm_model_blends_learned_confidence() {
        let samples = repeated_samples(COLD_START_MIN_LABELS);
        let model = train_model(&samples);
        let report = confidence_with_model(&true_positive_finding(), Some(&model));
        let learned = report.learned.expect("warm model predicts learned score");

        assert!(model.is_warm());
        assert!(model.model_id.starts_with(LEARNED_MODEL_ID_PREFIX));
        assert_eq!(report.model_id.as_deref(), Some(model.model_id.as_str()));
        assert_eq!(
            report.blend,
            blend_confidence(report.calibrated, learned, model.label_count)
        );
    }

    #[test]
    fn training_separates_true_positive_and_false_positive_features() {
        let samples = repeated_samples(120);
        let model = train_model(&samples);

        let true_score = model.predict_finding(&true_positive_finding()).unwrap();
        let false_score = model.predict_finding(&false_positive_finding()).unwrap();

        assert!(true_score > false_score);
    }

    #[test]
    fn online_update_changes_weights_and_label_count() {
        let mut model = LearnedConfidenceModel::new();
        let old_weights = model.weights.clone();
        let old_id = model.model_id.clone();

        model.update(&TrainingSample::new(
            ConfidenceLabel::TruePositive,
            true_positive_finding(),
        ));

        assert_eq!(model.label_count, 1);
        assert_ne!(model.weights, old_weights);
        assert_ne!(model.model_id, old_id);
    }

    #[test]
    fn model_json_round_trip_preserves_prediction() {
        let model = train_model(&repeated_samples(COLD_START_MIN_LABELS));
        let encoded = serde_json::to_string(&model).unwrap();
        let decoded: LearnedConfidenceModel = serde_json::from_str(&encoded).unwrap();

        decoded.validate().unwrap();
        assert_eq!(decoded.model_id, model.model_id);
        assert_eq!(
            decoded.predict_finding(&true_positive_finding()),
            model.predict_finding(&true_positive_finding())
        );
    }

    #[test]
    fn model_validation_rejects_tampered_model_id() {
        let mut model = train_model(&repeated_samples(COLD_START_MIN_LABELS));
        model.model_id = "govfuzz.learned.v1.tampered".to_owned();

        let error = model.validate().unwrap_err();

        assert!(error.to_string().contains("model_id mismatch"));
    }

    #[test]
    fn model_load_rejects_incompatible_feature_layout() {
        let model = train_model(&repeated_samples(COLD_START_MIN_LABELS));
        let mut value = serde_json::to_value(&model).unwrap();
        value["feature_names"] = json!(["stub_count"]);
        value["model_id"] = json!("govfuzz.learned.v1.tampered");
        let bytes = serde_json::to_vec(&value).unwrap();

        let error = LearnedConfidenceModel::from_slice(&bytes).unwrap_err();

        assert!(error.to_string().contains("feature_names"));
    }

    fn repeated_samples(count: usize) -> Vec<TrainingSample> {
        (0..count)
            .map(|index| {
                if index % 2 == 0 {
                    TrainingSample::new(ConfidenceLabel::TruePositive, true_positive_finding())
                } else {
                    TrainingSample::new(ConfidenceLabel::FalsePositive, false_positive_finding())
                }
            })
            .collect()
    }

    fn true_positive_finding() -> serde_json::Value {
        json!({
            "classification": "explicit_raise",
            "return_class": "failure",
            "breadcrumbs": [1, 2, 3],
            "raises": [{}],
            "signature_age": 1,
            "target": { "score": 95.0, "param_shape_complexity": 1 },
            "build": { "deps": { "stubbed": [], "fake_corba": [] } }
        })
    }

    fn false_positive_finding() -> serde_json::Value {
        json!({
            "classification": "unknown",
            "return_class": "normal",
            "signature_age": 80,
            "target": { "score": 5.0, "param_shape_complexity": 14 },
            "build": {
                "deps": {
                    "stubbed": ["external.ads", "external.adb"],
                    "stubbed_call_depth": 5,
                    "calls_through_stub": 5,
                    "fake_corba": ["corba.ads"]
                }
            }
        })
    }
}
