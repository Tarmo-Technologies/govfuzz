// SPDX-License-Identifier: Apache-2.0

use crate::{
    classify, compute_signature, finding_tier, resolve_handler, Classification, CorpusError,
    UNHANDLED_HANDLER_INDEX,
};
use event_log::{HandlerEvent, Testcase};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

pub struct FindingEmitter {
    root: PathBuf,
    metadata: FindingMetadata,
    line_maps: crate::line_remap::SourceLineMaps,
}

impl FindingEmitter {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            metadata: FindingMetadata::default(),
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    /// Load instrumented→original line-map sidecars from `dir` (the
    /// `src_instrumented` directory) so emitted findings report the developer's
    /// original source lines instead of the instrumented copy's shifted lines.
    pub fn with_line_maps_dir(mut self, dir: &std::path::Path) -> Self {
        self.line_maps = crate::line_remap::SourceLineMaps::load(dir);
        self
    }

    pub fn with_metadata(
        root: PathBuf,
        harness_id: String,
        dialect: String,
        fixture_path: String,
    ) -> Self {
        Self {
            root,
            metadata: FindingMetadata {
                harness_id,
                dialect,
                fixture_path,
                sandbox: None,
                mode: actionability::RunMode::Reporting,
            },
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    pub fn with_metadata_and_sandbox(
        root: PathBuf,
        harness_id: String,
        dialect: String,
        fixture_path: String,
        sandbox: serde_json::Value,
    ) -> Self {
        Self {
            root,
            metadata: FindingMetadata {
                harness_id,
                dialect,
                fixture_path,
                sandbox: Some(sandbox),
                mode: actionability::RunMode::Reporting,
            },
            line_maps: crate::line_remap::SourceLineMaps::default(),
        }
    }

    pub fn with_mode(mut self, mode: actionability::RunMode) -> Self {
        self.metadata.mode = mode;
        self
    }

    /// Emit a finding for a libFuzzer/AFL++ C/C++ crash captured via stderr.
    /// Unlike `emit`, there's no event log and no Ada Testcase; the sanitizer
    /// report already carries everything we need.
    pub fn emit_sanitizer_crash(
        &self,
        input: &[u8],
        report: &crate::sanitizer::SanitizerReport,
    ) -> Result<FindingId, CorpusError> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(report.rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(report.kind.as_bytes());
        for frame in &report.stack {
            hasher.update(b"|");
            hasher.update(frame.function.as_bytes());
        }
        let signature_hex = format!("{:x}", hasher.finalize());
        let cluster = crate::cluster::cluster_for_sanitizer(report);
        let (cluster_short, cluster_full, cluster_fallback) = if cluster.fallback {
            (
                signature_hex.chars().take(16).collect::<String>(),
                signature_hex.clone(),
                true,
            )
        } else {
            (cluster.short.clone(), cluster.full.clone(), false)
        };
        let id = FindingId(format!(
            "F-{ordinal:04}-{short}",
            ordinal = self.next_ordinal()?,
            short = signature_hex.chars().take(8).collect::<String>()
        ));
        let finding_dir = self.root.join("findings").join(&id.0);
        fs::create_dir_all(&finding_dir)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;

        let mut record = json!({
            "id": id.0,
            "signature": signature_hex,
            "cluster_key": cluster_short,
            "cluster_key_full": cluster_full,
            "cluster_normalized_frames": cluster.frames,
            "cluster_fallback": cluster_fallback,
            "rule_id": report.rule_id,
            "classification": "unhandled",
            "harness_id": self.metadata.harness_id,
            "dialect": self.metadata.dialect,
            "fixture_path": self.metadata.fixture_path,
            "exception": {
                "name": format!("{}_{}", report.sanitizer.as_str().to_uppercase(), report.kind.to_uppercase().replace('-', "_")),
                "message": report.message,
                "sanitizer": report.sanitizer.as_str(),
                "stack": report.stack,
            },
            "paths": {
                "testcase": "testcase.bin",
                "decoded": "decoded.json",
                "finding": "finding.json",
            },
        });
        if let Some(sandbox) = &self.metadata.sandbox {
            record["sandbox"] = sandbox.clone();
            record["build"] = json!({ "sandbox": sandbox });
        }
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );

        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    /// Emit a finding for an executable oracle hit captured from
    /// runtime instrumentation, such as a path traversal signal from
    /// the runtrace shim. These findings are not crashes; the oracle
    /// evidence is the behavioral signal.
    pub fn emit_oracle_hit(
        &self,
        input: &[u8],
        hit: &finding_rules::oracle_sdk::OracleHit,
    ) -> Result<FindingId, CorpusError> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(hit.rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(hit.oracle_name.as_bytes());
        hasher.update(b"|");
        hasher.update(hit.api.as_bytes());
        for evidence in &hit.evidence {
            hasher.update(b"|");
            hasher.update(evidence.key.as_bytes());
            hasher.update(b"=");
            hasher.update(evidence.value.as_bytes());
        }
        let signature_hex = format!("{:x}", hasher.finalize());
        // The cluster key is DEFECT-level (rule | oracle | dangerous API) and
        // EXCLUDES per-input evidence (the opened path/fd, injected command, ...).
        // The `signature` above keeps the evidence so each finding ID stays unique,
        // but clustering must collapse repeated hits of the SAME defect — a
        // resource-leak oracle re-triggered every pass otherwise produced a new
        // cluster per finding (mpack), defeating report dedup.
        let mut cluster_hasher = sha2::Sha256::new();
        cluster_hasher.update(hit.rule_id.as_bytes());
        cluster_hasher.update(b"|");
        cluster_hasher.update(hit.oracle_name.as_bytes());
        cluster_hasher.update(b"|");
        cluster_hasher.update(hit.api.as_bytes());
        // Site-stable discriminators (oracle-declared) so two distinct sites of
        // the same defect — e.g. two native-assertion sites that share the
        // `__assert_fail` API — do not over-merge into one cluster with an empty
        // sink. Per-input evidence stays excluded (the allowlist names only
        // site-stable keys like the assertion source location/expression).
        let mut cluster_frames = vec![hit.oracle_name.clone(), hit.api.clone()];
        for key in finding_rules::oracle_manifest::site_keys_for(&hit.oracle_name) {
            if let Some(value) = hit.evidence_value(key) {
                cluster_hasher.update(b"|");
                cluster_hasher.update(key.as_bytes());
                cluster_hasher.update(b"=");
                cluster_hasher.update(value.as_bytes());
                cluster_frames.push(format!("{key}={value}"));
            }
        }
        let cluster_full = format!("{:x}", cluster_hasher.finalize());
        let cluster_short = cluster_full.chars().take(16).collect::<String>();
        let id = FindingId(format!(
            "F-{ordinal:04}-{short}",
            ordinal = self.next_ordinal()?,
            short = signature_hex.chars().take(8).collect::<String>()
        ));
        let finding_dir = self.root.join("findings").join(&id.0);
        fs::create_dir_all(&finding_dir)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;

        let mut record = json!({
            "id": id.0,
            "signature": signature_hex,
            "cluster_key": cluster_short,
            "cluster_key_full": cluster_full,
            "cluster_normalized_frames": cluster_frames,
            "cluster_fallback": false,
            "rule_id": hit.rule_id,
            "classification": "oracle_hit",
            // #422: an oracle hit is dynamic, runtime-confirmed evidence — the
            // graduation of a static candidate (e.g. GF-405/GF-408) from
            // "candidate" to runtime-confirmed. Static-scan findings carry no
            // such marker, so consumers can distinguish the two.
            "confirmation": "runtime",
            "harness_id": self.metadata.harness_id,
            "dialect": self.metadata.dialect,
            "fixture_path": self.metadata.fixture_path,
            "oracle": {
                "name": hit.oracle_name,
                "category": hit.category,
                "api": hit.api,
                "message": hit.message,
                "evidence": hit.evidence,
            },
            "exception": {
                "name": oracle_exception_name(&hit.oracle_name),
                "message": hit.message,
            },
            "paths": {
                "testcase": "testcase.bin",
                "decoded": "decoded.json",
                "finding": "finding.json",
            },
        });
        if let Some(sandbox) = &self.metadata.sandbox {
            record["sandbox"] = sandbox.clone();
            record["build"] = json!({ "sandbox": sandbox });
        }
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );

        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    pub fn emit(
        &self,
        input: &[u8],
        testcase: &Testcase,
        handler_idx: usize,
    ) -> Result<FindingId, CorpusError> {
        let handler = resolve_handler(testcase, handler_idx)
            .ok_or(CorpusError::InvalidHandlerIndex { index: handler_idx })?;
        let handler = handler.as_ref();
        let classification = if handler_idx == UNHANDLED_HANDLER_INDEX {
            Classification::Unhandled
        } else {
            classify(testcase)
                .into_iter()
                .find_map(|(index, classification)| {
                    if index == handler_idx {
                        Some(classification)
                    } else {
                        None
                    }
                })
                .ok_or(CorpusError::InvalidHandlerIndex { index: handler_idx })?
        };
        let signature = compute_signature(testcase, handler);
        let signature_hex = signature.hex();
        let cluster = crate::cluster::cluster_for_ada(testcase, handler);
        let (cluster_short, cluster_full, cluster_fallback) = if cluster.fallback {
            (
                signature_hex.chars().take(16).collect::<String>(),
                signature_hex.clone(),
                true,
            )
        } else {
            (cluster.short.clone(), cluster.full.clone(), false)
        };
        let cluster_frames = cluster.frames.clone();
        let id = FindingId(format!(
            "F-{ordinal:04}-{short}",
            ordinal = self.next_ordinal()?,
            short = signature_hex.chars().take(8).collect::<String>()
        ));
        let finding_dir = self.root.join("findings").join(&id.0);
        fs::create_dir_all(&finding_dir)?;

        fs::write(finding_dir.join("testcase.bin"), input)?;
        fs::write(
            finding_dir.join("decoded.json"),
            serde_json::to_vec_pretty(&decoded_placeholder(input))?,
        )?;
        let mut record = finding_record(
            &id.0,
            &signature_hex,
            classification,
            testcase,
            handler,
            &self.metadata,
            &cluster_short,
            &cluster_full,
            &cluster_frames,
            cluster_fallback,
        );
        self.remap_exception_lines(&mut record);
        record["actionability"] = actionability::value_for_finding(
            self.metadata.mode,
            &record,
            Some(&finding_dir.join("finding.json")),
        );
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&record)?,
        )?;

        Ok(id)
    }

    /// Rewrite instrumented-copy `<file>:<line>` references in the finding's
    /// exception message to the developer's original source lines, and record
    /// the resolved original location under `exception.source_file` /
    /// `exception.source_line`. No-op when no line maps were loaded.
    fn remap_exception_lines(&self, record: &mut serde_json::Value) {
        if self.line_maps.is_empty() {
            return;
        }
        let Some(message) = record
            .get("exception")
            .and_then(|exc| exc.get("message"))
            .and_then(|msg| msg.as_str())
        else {
            return;
        };
        let (rewritten, resolved) = self.line_maps.remap_message(message);
        if let Some(exc) = record.get_mut("exception") {
            exc["message"] = json!(rewritten);
            if let Some(location) = resolved {
                exc["source_file"] = json!(location.source_path);
                exc["source_line"] = json!(location.original_line);
            }
        }
    }

    fn next_ordinal(&self) -> Result<u32, CorpusError> {
        let findings_root = self.root.join("findings");
        fs::create_dir_all(&findings_root)?;
        let mut next = 0_u32;
        for entry in fs::read_dir(findings_root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix("F-") else {
                continue;
            };
            let digits = rest.chars().take(4).collect::<String>();
            let Some(ordinal) = digits.parse::<u32>().ok() else {
                continue;
            };
            next = next.max(ordinal.saturating_add(1));
        }
        Ok(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingMetadata {
    harness_id: String,
    dialect: String,
    fixture_path: String,
    sandbox: Option<serde_json::Value>,
    mode: actionability::RunMode,
}

impl Default for FindingMetadata {
    fn default() -> Self {
        Self {
            harness_id: String::new(),
            dialect: String::new(),
            fixture_path: String::new(),
            sandbox: None,
            mode: actionability::RunMode::Reporting,
        }
    }
}

fn decoded_placeholder(input: &[u8]) -> serde_json::Value {
    json!({
        "input_size": input.len(),
        "preview_hex": preview_hex(input),
        "provenance": [{
            "kind": "raw_bytes",
            "source": "testcase.bin",
            "byte_range": { "start": 0, "end": input.len() }
        }]
    })
}

#[allow(clippy::too_many_arguments)]
fn finding_record(
    id: &str,
    signature_hex: &str,
    classification: Classification,
    testcase: &Testcase,
    handler: &HandlerEvent,
    metadata: &FindingMetadata,
    cluster_short: &str,
    cluster_full: &str,
    cluster_frames: &[String],
    cluster_fallback: bool,
) -> serde_json::Value {
    let classification_str = classification_label(classification);
    let rule_id = finding_rules::derive_rule_id(
        Some(classification_str),
        Some(handler.exception_name.as_str()),
    );
    let mut record = json!({
        "id": id,
        "signature": signature_hex,
        "cluster_key": cluster_short,
        "cluster_key_full": cluster_full,
        "cluster_normalized_frames": cluster_frames,
        "cluster_fallback": cluster_fallback,
        "classification": classification,
        "tier": finding_tier(classification, &handler.exception_name).as_str(),
        "handler": handler,
        "last_breadcrumb": handler.last_breadcrumb,
        "raises": testcase.raises,
        "mocks": testcase.mocks,
        "harness_id": metadata.harness_id,
        "dialect": metadata.dialect,
        "fixture_path": metadata.fixture_path,
        "exception": {
            "name": handler.exception_name,
            "message": handler.exception_message,
        },
        "paths": {
            "testcase": "testcase.bin",
            "decoded": "decoded.json",
            "finding": "finding.json",
        },
    });
    if let Some(rule_id) = rule_id {
        record["rule_id"] = json!(rule_id);
    }
    if let Some(sandbox) = &metadata.sandbox {
        record["sandbox"] = sandbox.clone();
        record["build"] = json!({ "sandbox": sandbox });
    }
    record
}

fn classification_label(classification: Classification) -> &'static str {
    match classification {
        Classification::Unhandled => "unhandled",
        Classification::SwallowedPredefined => "swallowed_predefined",
        Classification::SwallowedUser => "swallowed_user",
        Classification::ExplicitRaise => "explicit_raise",
    }
}

fn preview_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len().min(32) * 2);
    for byte in input.iter().take(32) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn oracle_exception_name(name: &str) -> String {
    let mut out = String::from("ORACLE_");
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::FindingEmitter;
    use crate::compute_signature;
    use event_log::{HandlerEvent, Testcase};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn emit_creates_finding_directory() {
        let root = temp_dir("directory");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"input", &testcase(), 0).unwrap();

        assert!(root.join("findings").join(id.0).is_dir());
    }

    #[test]
    fn emit_writes_testcase_bin_with_exact_input_bytes() {
        let root = temp_dir("testcase-bin");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"\x00\x01bad", &testcase(), 0).unwrap();

        assert_eq!(
            fs::read(root.join("findings").join(id.0).join("testcase.bin")).unwrap(),
            b"\x00\x01bad"
        );
    }

    #[test]
    fn emit_writes_decoded_json_with_input_size() {
        let root = temp_dir("decoded");
        let emitter = FindingEmitter::new(root.clone());

        let id = emitter.emit(b"abcdef", &testcase(), 0).unwrap();
        let decoded =
            fs::read_to_string(root.join("findings").join(id.0).join("decoded.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(value["input_size"], 6);
        assert_eq!(value["preview_hex"], "616263646566");
    }

    #[test]
    fn emit_writes_lightweight_input_provenance() {
        let root = temp_dir("decoded-provenance");
        let emitter = FindingEmitter::new(root.clone());
        let input = b"\x00\x01bad";

        let id = emitter.emit(input, &testcase(), 0).unwrap();
        let decoded =
            fs::read_to_string(root.join("findings").join(id.0).join("decoded.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&decoded).unwrap();

        assert_eq!(value["provenance"][0]["kind"], "raw_bytes");
        assert_eq!(value["provenance"][0]["source"], "testcase.bin");
        assert_eq!(value["provenance"][0]["byte_range"]["end"], input.len());
    }

    #[test]
    fn emit_writes_finding_json_with_signature_hex() {
        let root = temp_dir("finding-json");
        let emitter = FindingEmitter::new(root.clone());
        let testcase = testcase();
        let expected = compute_signature(&testcase, &testcase.handlers[0]).hex();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding =
            fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["signature"], expected);
        assert_eq!(value["classification"], "swallowed_predefined");
        assert_eq!(value["handler"]["handler_line"], 9);
    }

    #[test]
    fn emit_populates_rule_id_and_exception_block_from_classification() {
        let root = temp_dir("rule-id-and-exception");
        let emitter = FindingEmitter::new(root.clone());
        let testcase = testcase();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding =
            fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["rule_id"], "GF-102");
        assert_eq!(value["exception"]["name"], "CONSTRAINT_ERROR");
        assert_eq!(value["exception"]["message"], "bad input");
    }

    #[test]
    fn emit_marks_mock_based_ada_finding_lab_only() {
        let root = temp_dir("ada-mock-actionability");
        let emitter =
            FindingEmitter::new(root.clone()).with_mode(actionability::RunMode::Attacking);
        let mut testcase = testcase();
        testcase.mocks = vec![event_log::MockEvent {
            symbol: "Missing_Service".to_owned(),
        }];

        let id = emitter.emit(b"input", &testcase, 0).unwrap();
        let finding =
            fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["mocks"][0]["symbol"], "Missing_Service");
        assert_eq!(value["actionability"]["verdict"], "lab_only");
        assert_eq!(value["actionability"]["prosthetics"]["used"], true);
    }

    #[test]
    fn emit_tags_swallowed_predefined_with_swallowed_check_tier() {
        let root = temp_dir("tier-swallowed-check");
        let emitter = FindingEmitter::new(root.clone());
        let id = emitter.emit(b"input", &testcase(), 0).unwrap();
        let value: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(value["tier"], "swallowed_check");
    }

    #[test]
    fn emit_records_unhandled_top_level_as_real_fault() {
        let root = temp_dir("tier-real-fault");
        let emitter = FindingEmitter::new(root.clone());
        let mut testcase = testcase();
        // An exception that escaped the target unhandled to the harness top
        // level, with no in-target handler that caught it.
        testcase.handlers.clear();
        testcase.top_level = Some(event_log::TopLevelEvent {
            exception_name: "PROGRAM_ERROR".to_owned(),
            exception_message: "escaped to harness".to_owned(),
        });

        let id = emitter
            .emit(b"input", &testcase, crate::UNHANDLED_HANDLER_INDEX)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(value["tier"], "real_fault");
        assert_eq!(value["classification"], "unhandled");
        assert_eq!(value["exception"]["name"], "PROGRAM_ERROR");
        assert_eq!(value["rule_id"], "GF-101");
    }

    #[test]
    fn emit_returns_finding_id_with_short_sig_prefix() {
        let root = temp_dir("id");
        let emitter = FindingEmitter::new(root);
        let testcase = testcase();
        let signature = compute_signature(&testcase, &testcase.handlers[0]).hex();

        let id = emitter.emit(b"input", &testcase, 0).unwrap();

        assert_eq!(id.0, format!("F-0000-{}", &signature[..8]));
    }

    fn testcase() -> Testcase {
        let handler = HandlerEvent {
            sequence_index: 3,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "bad input".to_owned(),
            handler_file: "pkg.adb".to_owned(),
            handler_line: 9,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        };

        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            crumbs: vec![1],
            handlers: vec![handler],
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-finding-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn testcase_with_message(message: &str) -> Testcase {
        let mut tc = testcase();
        tc.handlers[0].exception_message = message.to_owned();
        tc
    }

    #[test]
    fn emit_remaps_exception_line_to_original_source() {
        let root = temp_dir("remap");
        let instr = root.join("src_instrumented");
        fs::create_dir_all(&instr).unwrap();
        // Anchor (62 -> 56): an instrumented line 646 maps to 56 + (646-62) = 640.
        fs::write(
            instr.join("bzip2-decoding.adb.govfuzz-lines.json"),
            r#"{"source_path":"/src/bzip2-decoding.adb","anchors":[[1,1],[62,56]]}"#,
        )
        .unwrap();
        let emitter = FindingEmitter::new(root.clone()).with_line_maps_dir(&instr);

        let id = emitter
            .emit(
                b"crash",
                &testcase_with_message("bzip2-decoding.adb:646 index check failed"),
                0,
            )
            .unwrap();
        let finding: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(&id.0).join("finding.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(
            finding["exception"]["message"],
            "bzip2-decoding.adb:640 index check failed"
        );
        assert_eq!(
            finding["exception"]["source_file"],
            "/src/bzip2-decoding.adb"
        );
        assert_eq!(finding["exception"]["source_line"], 640);
    }

    #[test]
    fn emit_without_line_maps_leaves_message_unchanged() {
        let root = temp_dir("no-remap");
        let emitter = FindingEmitter::new(root.clone());
        let id = emitter
            .emit(
                b"crash",
                &testcase_with_message("bzip2-decoding.adb:646 boom"),
                0,
            )
            .unwrap();
        let finding: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(&id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            finding["exception"]["message"],
            "bzip2-decoding.adb:646 boom"
        );
        assert!(finding["exception"].get("source_line").is_none());
    }

    #[test]
    fn emit_sanitizer_crash_writes_cluster_fields() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("cluster-sanitizer");
        let emitter = super::FindingEmitter::new(root.clone());
        let report = SanitizerReport {
            sanitizer: Sanitizer::AddressSanitizer,
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "GF-201",
            stack: vec![
                StackFrame {
                    function: "__asan_memcpy".to_owned(),
                    file: None,
                    line: None,
                },
                StackFrame {
                    function: "real_parse".to_owned(),
                    file: Some("/src/p.c".to_owned()),
                    line: Some(9),
                },
                StackFrame {
                    function: "LLVMFuzzerTestOneInput".to_owned(),
                    file: None,
                    line: None,
                },
            ],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
        };
        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_normalized_frames"][0], "real_parse");
        let short = v["cluster_key"].as_str().unwrap();
        assert_eq!(short.len(), 16);
        assert_eq!(v["cluster_fallback"], false);
        assert_eq!(v["cluster_key_full"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn emit_sanitizer_crash_writes_actionability_object() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("sanitizer-actionability");
        let emitter =
            super::FindingEmitter::new(root.clone()).with_mode(actionability::RunMode::Attacking);
        let report = SanitizerReport {
            sanitizer: Sanitizer::AddressSanitizer,
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "GF-201",
            stack: vec![StackFrame {
                function: "parse_packet".to_owned(),
                file: Some("src/packet.c".to_owned()),
                line: Some(27),
            }],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
        };

        let id = emitter.emit_sanitizer_crash(b"in", &report).unwrap();
        let finding =
            fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["actionability"]["mode"], "attacking");
        assert_eq!(
            value["actionability"]["fix_location"]["path"],
            "src/packet.c"
        );
        assert_eq!(value["actionability"]["impact"], "critical");
    }

    #[test]
    fn emit_oracle_hit_writes_runtime_evidence() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-hit");
        let emitter = super::FindingEmitter::with_metadata(
            root.clone(),
            "H-path".to_owned(),
            "c".to_owned(),
            "/tmp/harness/main.c".to_owned(),
        );
        let hit = OracleHit {
            oracle_name: "path-traversal-ada".to_owned(),
            rule_id: "GF-101".to_owned(),
            category: "logic-bug".to_owned(),
            api: "open".to_owned(),
            message: "filesystem path contains a parent-directory component".to_owned(),
            evidence: vec![OracleEvidence {
                key: "path".to_owned(),
                value: "../../etc/passwd".to_owned(),
            }],
        };

        let id = emitter.emit_oracle_hit(b"../../etc/passwd", &hit).unwrap();
        let finding =
            fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&finding).unwrap();

        assert_eq!(value["rule_id"], "GF-101");
        assert_eq!(value["classification"], "oracle_hit");
        assert_eq!(value["harness_id"], "H-path");
        assert_eq!(value["oracle"]["name"], "path-traversal-ada");
        assert_eq!(value["oracle"]["category"], "logic-bug");
        assert_eq!(value["oracle"]["evidence"][0]["key"], "path");
        assert_eq!(value["oracle"]["evidence"][0]["value"], "../../etc/passwd");
        assert_eq!(
            fs::read(
                root.join("findings")
                    .join(value["id"].as_str().unwrap())
                    .join("testcase.bin")
            )
            .unwrap(),
            b"../../etc/passwd"
        );
    }

    #[test]
    fn emit_oracle_hit_distinct_assert_sites_cluster_separately_and_populate_sink() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-assert-sites");
        let emitter = super::FindingEmitter::with_metadata(
            root.clone(),
            "H-assert".to_owned(),
            "c".to_owned(),
            "/tmp/harness/main.c".to_owned(),
        );
        let hit_at = |source: &str, expr: &str| OracleHit {
            oracle_name: "native-assertion-contract".to_owned(),
            rule_id: "GF-415".to_owned(),
            category: "logic-bug".to_owned(),
            api: "__assert_fail".to_owned(),
            message: "native assertion contract failed during fuzz execution".to_owned(),
            evidence: vec![
                OracleEvidence::new("exception", "AssertionFailure"),
                OracleEvidence::new("check", "assertion"),
                OracleEvidence::new("expression", expr),
                OracleEvidence::new("source", source),
            ],
        };

        let id_a = emitter
            .emit_oracle_hit(b"a", &hit_at("parser.c:42:parse_frame", "len < cap"))
            .unwrap();
        let id_b = emitter
            .emit_oracle_hit(b"b", &hit_at("writer.c:99:flush_buf", "n > 0"))
            .unwrap();

        let read = |id: &super::FindingId| -> serde_json::Value {
            serde_json::from_str(
                &fs::read_to_string(root.join("findings").join(&id.0).join("finding.json"))
                    .unwrap(),
            )
            .unwrap()
        };
        let a = read(&id_a);
        let b = read(&id_b);

        // Two distinct assert sites → two distinct clusters (no over-merge).
        assert_ne!(a["cluster_key"], b["cluster_key"]);
        assert_ne!(a["cluster_key_full"], b["cluster_key_full"]);

        // The source location populates the actionability sink (report CSV cols).
        assert_eq!(a["actionability"]["sink"]["function"], "parse_frame");
        assert_eq!(a["actionability"]["sink"]["file"], "parser.c");
        assert_eq!(a["actionability"]["sink"]["line"], 42);
    }

    #[test]
    fn emit_oracle_hit_same_assert_site_clusters_together() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};

        let root = temp_dir("oracle-assert-same");
        let emitter = super::FindingEmitter::new(root.clone());
        let hit = OracleHit {
            oracle_name: "native-assertion-contract".to_owned(),
            rule_id: "GF-415".to_owned(),
            category: "logic-bug".to_owned(),
            api: "__assert_fail".to_owned(),
            message: "native assertion contract failed during fuzz execution".to_owned(),
            evidence: vec![
                OracleEvidence::new("expression", "len < cap"),
                OracleEvidence::new("source", "parser.c:42:parse_frame"),
            ],
        };
        // Same site, two different inputs → same cluster (the per-input bytes are
        // not part of the cluster key).
        let id_a = emitter.emit_oracle_hit(b"input-one", &hit).unwrap();
        let id_b = emitter
            .emit_oracle_hit(b"input-two-different", &hit)
            .unwrap();
        let read = |id: &super::FindingId| -> serde_json::Value {
            serde_json::from_str(
                &fs::read_to_string(root.join("findings").join(&id.0).join("finding.json"))
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(read(&id_a)["cluster_key"], read(&id_b)["cluster_key"]);
    }

    #[test]
    fn emit_writes_cluster_fields_for_ada_path() {
        let root = temp_dir("cluster-ada");
        let emitter = super::FindingEmitter::new(root.clone());
        let id = emitter.emit(b"input", &testcase(), 0).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_normalized_frames"][0], "CONSTRAINT_ERROR");
        assert_eq!(v["cluster_normalized_frames"][1], "pkg.adb:9");
        assert_eq!(v["cluster_fallback"], false);
        assert_eq!(v["cluster_key"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn emit_sanitizer_crash_falls_back_when_only_noise() {
        use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
        let root = temp_dir("cluster-fallback");
        let emitter = super::FindingEmitter::new(root.clone());
        let report = SanitizerReport {
            sanitizer: Sanitizer::AddressSanitizer,
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "GF-201",
            stack: vec![StackFrame {
                function: "__asan_memcpy".to_owned(),
                file: None,
                line: None,
            }],
            message: "ERROR: ASan: heap-buffer-overflow".to_owned(),
        };
        let id = emitter.emit_sanitizer_crash(b"x", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("findings").join(id.0).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["cluster_fallback"], true);
        let signature = v["signature"].as_str().unwrap();
        assert_eq!(v["cluster_key"], signature[..16]);
    }
}
