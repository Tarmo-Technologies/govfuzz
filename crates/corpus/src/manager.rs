// SPDX-License-Identifier: Apache-2.0

use crate::{classify, compute_signature, resolve_handler, Classification, Signature};
use event_log::{EndEvent, Event, HandlerEvent, MockEvent, RaiseEvent, Testcase, TopLevelEvent};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

pub struct CorpusManager {
    root: PathBuf,
}

impl CorpusManager {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn record(
        &mut self,
        harness_id: &str,
        input: &[u8],
        events: &[Event],
    ) -> Result<Vec<SignatureRecord>, CorpusError> {
        let harness_root = self.root.join("corpus").join(harness_id);
        let sigs_dir = harness_root.join("sigs");
        let queue_dir = harness_root.join("queue");
        let swallowed_dir = harness_root.join("swallowed");
        fs::create_dir_all(&sigs_dir)?;
        fs::create_dir_all(&queue_dir)?;
        fs::create_dir_all(&swallowed_dir)?;

        let mut records = Vec::new();
        for testcase in group_events(events) {
            for (handler_index, classification) in classify(&testcase) {
                let Some(handler) = resolve_handler(&testcase, handler_index) else {
                    continue;
                };
                let signature = compute_signature(&testcase, handler.as_ref());
                let sig_hex = signature.hex();
                let sig_path = sigs_dir.join(&sig_hex);
                let class = if sig_path.exists() {
                    SignatureClass::Duplicate
                } else {
                    fs::write(&sig_path, &sig_hex)?;
                    fs::write(queue_dir.join(format!("{sig_hex}.bin")), input)?;
                    if is_swallowed(classification) {
                        fs::write(swallowed_dir.join(format!("{sig_hex}.bin")), input)?;
                    }
                    SignatureClass::New
                };

                records.push(SignatureRecord {
                    signature,
                    class,
                    classification,
                });
            }
        }

        Ok(records)
    }

    /// Persist the engine's coverage-guided corpus (#401): write each input to
    /// `corpus/<hid>/queue/<sha256>.bin`, content-hash-named and deduplicated by
    /// hash. Returns the number of NEW files written.
    ///
    /// Unlike [`record`](Self::record), this does not require a classified event:
    /// a plain coverage-increasing input (the #398 pool) IS the corpus, and was
    /// previously held only in memory and lost on exit, leaving `queue/` empty
    /// after a clean run. Seeds passed here are included so the on-disk corpus
    /// fully explains the run's reported coverage and is replayable through a
    /// neutral coverage build / `corpus minimize`.
    pub fn persist_coverage_corpus<I, B>(
        &self,
        harness_id: &str,
        inputs: I,
    ) -> Result<usize, CorpusError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let queue_dir = self.root.join("corpus").join(harness_id).join("queue");
        fs::create_dir_all(&queue_dir)?;
        let mut written = 0usize;
        for input in inputs {
            let bytes = input.as_ref();
            if bytes.is_empty() {
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let name = content_hex(&hasher.finalize());
            let path = queue_dir.join(format!("{name}.bin"));
            if path.exists() {
                continue;
            }
            fs::write(&path, bytes)?;
            written += 1;
        }
        Ok(written)
    }
}

/// Lowercase-hex of a digest, for content-hash corpus filenames.
fn content_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRecord {
    pub signature: Signature,
    pub class: SignatureClass,
    pub classification: Classification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureClass {
    New,
    Duplicate,
}

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("I/O error while updating corpus")]
    Io(#[from] std::io::Error),
    #[error("JSON error while updating corpus")]
    Json(#[from] serde_json::Error),
    #[error("handler index {index} is not present in testcase")]
    InvalidHandlerIndex { index: usize },
}

fn is_swallowed(classification: Classification) -> bool {
    matches!(
        classification,
        Classification::SwallowedPredefined | Classification::SwallowedUser
    )
}

fn group_events(events: &[Event]) -> Vec<Testcase> {
    let mut testcases = Vec::new();
    let mut current: Option<Testcase> = None;

    for (sequence_index, event) in events.iter().enumerate() {
        match event {
            Event::Begin { testcase_id } => {
                if let Some(open) = current.replace(Testcase {
                    testcase_id: *testcase_id,
                    target_id: 0,
                    target_entered: false,
                    crumbs: Vec::new(),
                    handlers: Vec::new(),
                    raises: Vec::new(),
                    top_level: None,
                    end: None,
                    mocks: Vec::new(),
                }) {
                    testcases.push(open);
                }
            }
            Event::End { result_class } => {
                if let Some(mut testcase) = current.take() {
                    testcase.end = Some(EndEvent {
                        result_class: *result_class,
                    });
                    testcases.push(testcase);
                }
            }
            Event::Crumb { id } => {
                if let Some(testcase) = &mut current {
                    testcase.crumbs.push(*id);
                }
            }
            Event::Target { id } => {
                if let Some(testcase) = &mut current {
                    testcase.target_id = *id;
                }
            }
            Event::TargetEntry => {
                if let Some(testcase) = &mut current {
                    testcase.target_entered = true;
                }
            }
            Event::Handler {
                exception_name,
                exception_message,
                handler_file,
                handler_line,
                last_breadcrumb,
                target_id,
                testcase_id,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.handlers.push(HandlerEvent {
                        sequence_index,
                        exception_name: exception_name.clone(),
                        exception_message: exception_message.clone(),
                        handler_file: handler_file.clone(),
                        handler_line: *handler_line,
                        last_breadcrumb: *last_breadcrumb,
                        target_id: *target_id,
                        testcase_id: *testcase_id,
                    });
                }
            }
            Event::Raise {
                exception_name,
                file,
                line,
                breadcrumb,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.raises.push(RaiseEvent {
                        sequence_index,
                        exception_name: exception_name.clone(),
                        file: file.clone(),
                        line: *line,
                        breadcrumb: *breadcrumb,
                    });
                }
            }
            Event::Mock { symbol } => {
                if let Some(testcase) = &mut current {
                    testcase.mocks.push(MockEvent {
                        symbol: symbol.clone(),
                    });
                }
            }
            Event::TopLevel {
                exception_name,
                exception_message,
            } => {
                if let Some(testcase) = &mut current {
                    testcase.top_level = Some(TopLevelEvent {
                        exception_name: exception_name.clone(),
                        exception_message: exception_message.clone(),
                    });
                }
            }
        }
    }

    if let Some(testcase) = current {
        testcases.push(testcase);
    }

    testcases
}

#[cfg(test)]
mod tests {
    use super::{CorpusManager, SignatureClass};
    use event_log::Event;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn record_new_signature_returns_new_class() {
        let root = temp_dir("new-class");
        let mut manager = CorpusManager::new(root);

        let records = manager
            .record("harness", b"input", &swallowed_events(1))
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class, SignatureClass::New);
    }

    #[test]
    fn record_duplicate_signature_returns_duplicate_class() {
        let root = temp_dir("duplicate-class");
        let mut manager = CorpusManager::new(root);
        let events = swallowed_events(1);

        manager.record("harness", b"input", &events).unwrap();
        let records = manager.record("harness", b"input", &events).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class, SignatureClass::Duplicate);
    }

    #[test]
    fn record_writes_input_to_queue_directory() {
        let root = temp_dir("queue");
        let mut manager = CorpusManager::new(root.clone());

        let records = manager
            .record("harness", b"input-bytes", &swallowed_events(1))
            .unwrap();
        let queue_path = root
            .join("corpus/harness/queue")
            .join(format!("{}.bin", records[0].signature.hex()));

        assert_eq!(fs::read(queue_path).unwrap(), b"input-bytes");
    }

    #[test]
    fn record_swallowed_classification_also_writes_swallowed_directory() {
        let root = temp_dir("swallowed");
        let mut manager = CorpusManager::new(root.clone());

        let records = manager
            .record("harness", b"input", &swallowed_events(1))
            .unwrap();
        let swallowed_path = root
            .join("corpus/harness/swallowed")
            .join(format!("{}.bin", records[0].signature.hex()));

        assert_eq!(fs::read(swallowed_path).unwrap(), b"input");
    }

    #[test]
    fn record_explicit_raise_classification_does_not_write_swallowed() {
        let root = temp_dir("explicit");
        let mut manager = CorpusManager::new(root.clone());

        let records = manager
            .record("harness", b"input", &explicit_raise_events())
            .unwrap();
        let swallowed_path = root
            .join("corpus/harness/swallowed")
            .join(format!("{}.bin", records[0].signature.hex()));

        assert!(!swallowed_path.exists());
    }

    #[test]
    fn record_creates_directory_tree_if_missing() {
        let root = temp_dir("dirs");
        let mut manager = CorpusManager::new(root.clone());

        manager
            .record("harness", b"input", &swallowed_events(1))
            .unwrap();

        assert!(root.join("corpus/harness/sigs").is_dir());
        assert!(root.join("corpus/harness/queue").is_dir());
        assert!(root.join("corpus/harness/swallowed").is_dir());
    }

    #[test]
    fn persist_coverage_corpus_writes_content_hashed_dedups_and_skips_empty() {
        let root = temp_dir("persist");
        let manager = CorpusManager::new(root.clone());

        // Two distinct inputs + a duplicate of the first + an empty input.
        let written = manager
            .persist_coverage_corpus(
                "harness",
                vec![
                    b"alpha".to_vec(),
                    b"beta".to_vec(),
                    b"alpha".to_vec(),
                    Vec::new(),
                ],
            )
            .unwrap();
        assert_eq!(written, 2, "duplicate and empty inputs must not add files");

        let queue = root.join("corpus/harness/queue");
        let files: Vec<_> = fs::read_dir(&queue)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 2, "two unique inputs -> two files");
        // Content-hash-named (.bin), and the bytes round-trip.
        let contents: Vec<Vec<u8>> = files.iter().map(|p| fs::read(p).unwrap()).collect();
        assert!(contents.iter().any(|c| c == b"alpha"));
        assert!(contents.iter().any(|c| c == b"beta"));
        for p in &files {
            let name = p.file_name().unwrap().to_str().unwrap();
            assert!(name.ends_with(".bin"));
            assert!(name
                .trim_end_matches(".bin")
                .chars()
                .all(|c| c.is_ascii_hexdigit()));
        }

        // A second call with an already-persisted input writes nothing new.
        let again = manager
            .persist_coverage_corpus("harness", vec![b"alpha".to_vec()])
            .unwrap();
        assert_eq!(again, 0, "re-persisting an existing input is a no-op");
    }

    #[test]
    fn record_includes_unhandled_top_level_escape_as_new_signature() {
        let root = temp_dir("unhandled");
        let mut manager = CorpusManager::new(root.clone());

        let records = manager
            .record("harness", b"input", &unhandled_events())
            .unwrap();

        // The escaped (uncaught) exception must be recorded as a distinct
        // corpus signature so the fuzz gate can surface it as a real finding.
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class, SignatureClass::New);
        assert_eq!(records[0].classification, crate::Classification::Unhandled);
        // It is not a swallowed exception, so no swallowed/ entry.
        let swallowed_path = root
            .join("corpus/harness/swallowed")
            .join(format!("{}.bin", records[0].signature.hex()));
        assert!(!swallowed_path.exists());
    }

    fn unhandled_events() -> Vec<Event> {
        vec![
            Event::Begin { testcase_id: 1 },
            Event::Target { id: 0x42 },
            Event::Crumb { id: 7 },
            Event::TopLevel {
                exception_name: "PROGRAM_ERROR".to_owned(),
                exception_message: "escaped to harness".to_owned(),
            },
            Event::End { result_class: 1 },
        ]
    }

    fn swallowed_events(last_breadcrumb: u32) -> Vec<Event> {
        vec![
            Event::Begin { testcase_id: 1 },
            Event::Target { id: 0x42 },
            Event::Crumb {
                id: last_breadcrumb,
            },
            Event::Handler {
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: 9,
                last_breadcrumb,
                target_id: 0x42,
                testcase_id: 1,
            },
            Event::End { result_class: 0 },
        ]
    }

    fn explicit_raise_events() -> Vec<Event> {
        vec![
            Event::Begin { testcase_id: 1 },
            Event::Target { id: 0x42 },
            Event::Raise {
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                file: "pkg.adb".to_owned(),
                line: 8,
                breadcrumb: 1,
            },
            Event::Handler {
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: 9,
                last_breadcrumb: 1,
                target_id: 0x42,
                testcase_id: 1,
            },
            Event::End { result_class: 0 },
        ]
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-corpus-manager-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
