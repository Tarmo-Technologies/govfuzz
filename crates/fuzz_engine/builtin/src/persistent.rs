// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const QUEUE_MAGIC: &[u8; 6] = b"GVFQ1\0";
const FRAME_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentQueueEntry {
    pub testcase_id: u64,
    pub bytes: Vec<u8>,
}

impl PersistentQueueEntry {
    pub fn new(testcase_id: u64, bytes: Vec<u8>) -> Self {
        Self { testcase_id, bytes }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentLoopConfig {
    pub max_testcase_len: usize,
    pub max_testcases: usize,
}

impl Default for PersistentLoopConfig {
    fn default() -> Self {
        Self {
            max_testcase_len: 1024 * 1024,
            max_testcases: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentRunSummary {
    pub testcases: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentChildError {
    message: String,
}

impl PersistentChildError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PersistentChildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PersistentChildError {}

#[derive(Debug)]
pub enum PersistentLoopError {
    Io(io::Error),
    BadMagic,
    TruncatedFrame {
        offset: usize,
        expected: usize,
        remaining: usize,
    },
    TestcaseTooLarge {
        len: usize,
        max: usize,
    },
    TooManyTestcases {
        count: usize,
        max: usize,
    },
    Child(PersistentChildError),
}

impl fmt::Display for PersistentLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "persistent queue I/O error: {error}"),
            Self::BadMagic => formatter.write_str("persistent queue has invalid magic header"),
            Self::TruncatedFrame {
                offset,
                expected,
                remaining,
            } => write!(
                formatter,
                "persistent queue frame at offset {offset} is truncated: expected {expected} bytes, remaining {remaining}"
            ),
            Self::TestcaseTooLarge { len, max } => {
                write!(formatter, "persistent testcase length {len} exceeds maximum {max}")
            }
            Self::TooManyTestcases { count, max } => {
                write!(formatter, "persistent queue has {count} testcases, maximum is {max}")
            }
            Self::Child(error) => write!(formatter, "persistent child error: {error}"),
        }
    }
}

impl std::error::Error for PersistentLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Child(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PersistentLoopError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PersistentChildError> for PersistentLoopError {
    fn from(error: PersistentChildError) -> Self {
        Self::Child(error)
    }
}

pub trait PersistentHarnessChild {
    fn start(&mut self) -> Result<(), PersistentChildError>;
    fn run_testcase(&mut self, testcase: &PersistentQueueEntry)
        -> Result<(), PersistentChildError>;
}

pub fn write_queue_file(
    path: &Path,
    entries: &[PersistentQueueEntry],
) -> Result<(), PersistentLoopError> {
    let mut file = fs::File::create(path)?;
    file.write_all(QUEUE_MAGIC)?;

    for entry in entries {
        let len = u32::try_from(entry.bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "testcase {} length {} exceeds u32 queue frame limit",
                    entry.testcase_id,
                    entry.bytes.len()
                ),
            )
        })?;

        file.write_all(&entry.testcase_id.to_le_bytes())?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&entry.bytes)?;
    }

    Ok(())
}

pub fn read_queue_file(
    path: &Path,
    config: PersistentLoopConfig,
) -> Result<Vec<PersistentQueueEntry>, PersistentLoopError> {
    let bytes = fs::read(path)?;
    if bytes.len() < QUEUE_MAGIC.len() || &bytes[..QUEUE_MAGIC.len()] != QUEUE_MAGIC {
        return Err(PersistentLoopError::BadMagic);
    }

    let mut entries = Vec::new();
    let mut offset = QUEUE_MAGIC.len();
    while offset < bytes.len() {
        if entries.len() == config.max_testcases {
            return Err(PersistentLoopError::TooManyTestcases {
                count: entries.len() + 1,
                max: config.max_testcases,
            });
        }

        ensure_remaining(&bytes, offset, FRAME_HEADER_LEN)?;

        let testcase_id = read_u64_le(&bytes[offset..offset + 8]);
        offset += 8;
        let len = read_u32_le(&bytes[offset..offset + 4]) as usize;
        offset += 4;

        if len > config.max_testcase_len {
            return Err(PersistentLoopError::TestcaseTooLarge {
                len,
                max: config.max_testcase_len,
            });
        }

        ensure_remaining(&bytes, offset, len)?;
        entries.push(PersistentQueueEntry {
            testcase_id,
            bytes: bytes[offset..offset + len].to_vec(),
        });
        offset += len;
    }

    Ok(entries)
}

pub fn run_persistent_queue<C: PersistentHarnessChild>(
    path: &Path,
    config: PersistentLoopConfig,
    child: &mut C,
) -> Result<PersistentRunSummary, PersistentLoopError> {
    let entries = read_queue_file(path, config)?;
    if entries.is_empty() {
        return Ok(PersistentRunSummary {
            testcases: 0,
            bytes: 0,
        });
    }

    child.start()?;
    let mut summary = PersistentRunSummary {
        testcases: 0,
        bytes: 0,
    };

    for entry in entries {
        child.run_testcase(&entry)?;
        summary.testcases += 1;
        summary.bytes += entry.bytes.len();
    }

    Ok(summary)
}

fn ensure_remaining(
    bytes: &[u8],
    offset: usize,
    expected: usize,
) -> Result<(), PersistentLoopError> {
    let remaining = bytes.len().saturating_sub(offset);
    if remaining < expected {
        Err(PersistentLoopError::TruncatedFrame {
            offset,
            expected,
            remaining,
        })
    } else {
        Ok(())
    }
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut output = [0_u8; 8];
    output.copy_from_slice(bytes);
    u64::from_le_bytes(output)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let mut output = [0_u8; 4];
    output.copy_from_slice(bytes);
    u32::from_le_bytes(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn queue_file_round_trips_ordered_testcases() {
        let path = temp_dir("queue-round-trip").join("queue.gvfq");
        let entries = vec![
            PersistentQueueEntry::new(7, b"alpha".to_vec()),
            PersistentQueueEntry::new(8, vec![0, 1, 2, 3]),
        ];

        write_queue_file(&path, &entries).expect("queue file is written");

        assert_eq!(
            read_queue_file(&path, PersistentLoopConfig::default()).expect("queue file is read"),
            entries
        );
    }

    #[test]
    fn queue_reader_rejects_bad_magic() {
        let path = temp_dir("queue-bad-magic").join("queue.gvfq");
        fs::write(&path, b"not-a-govfuzz-queue").unwrap();

        assert!(matches!(
            read_queue_file(&path, PersistentLoopConfig::default()),
            Err(PersistentLoopError::BadMagic)
        ));
    }

    #[test]
    fn queue_reader_rejects_truncated_frame() {
        let path = temp_dir("queue-truncated").join("queue.gvfq");
        let mut bytes = b"GVFQ1\0".to_vec();
        bytes.extend_from_slice(&7_u64.to_le_bytes());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(b"ab");
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            read_queue_file(&path, PersistentLoopConfig::default()),
            Err(PersistentLoopError::TruncatedFrame { .. })
        ));
    }

    #[test]
    fn queue_reader_rejects_oversized_testcase() {
        let path = temp_dir("queue-oversized").join("queue.gvfq");
        let entries = [PersistentQueueEntry::new(1, b"abcd".to_vec())];
        let config = PersistentLoopConfig {
            max_testcase_len: 3,
            max_testcases: 16,
        };

        write_queue_file(&path, &entries).expect("queue file is written");

        assert!(matches!(
            read_queue_file(&path, config),
            Err(PersistentLoopError::TestcaseTooLarge { len: 4, max: 3 })
        ));
    }

    #[test]
    fn persistent_loop_runs_all_entries_on_one_child() {
        let path = temp_dir("persistent-loop-all").join("queue.gvfq");
        let entries = vec![
            PersistentQueueEntry::new(1, b"a".to_vec()),
            PersistentQueueEntry::new(2, b"bb".to_vec()),
            PersistentQueueEntry::new(3, b"ccc".to_vec()),
        ];
        write_queue_file(&path, &entries).expect("queue file is written");
        let mut child = RecordingChild::default();

        let summary = run_persistent_queue(&path, PersistentLoopConfig::default(), &mut child)
            .expect("persistent loop runs");

        assert_eq!(child.starts.get(), 1);
        assert_eq!(child.seen, entries);
        assert_eq!(
            summary,
            PersistentRunSummary {
                testcases: 3,
                bytes: 6,
            }
        );
    }

    #[test]
    fn persistent_loop_stops_on_child_failure() {
        let path = temp_dir("persistent-loop-failure").join("queue.gvfq");
        let entries = vec![
            PersistentQueueEntry::new(1, b"a".to_vec()),
            PersistentQueueEntry::new(2, b"bb".to_vec()),
        ];
        write_queue_file(&path, &entries).expect("queue file is written");
        let mut child = RecordingChild {
            fail_on: Some(2),
            ..RecordingChild::default()
        };

        assert!(matches!(
            run_persistent_queue(&path, PersistentLoopConfig::default(), &mut child),
            Err(PersistentLoopError::Child(PersistentChildError { .. }))
        ));
        assert_eq!(child.seen, vec![entries[0].clone()]);
    }

    #[derive(Default)]
    struct RecordingChild {
        starts: Cell<usize>,
        seen: Vec<PersistentQueueEntry>,
        fail_on: Option<u64>,
    }

    impl PersistentHarnessChild for RecordingChild {
        fn start(&mut self) -> Result<(), PersistentChildError> {
            self.starts.set(self.starts.get() + 1);
            Ok(())
        }

        fn run_testcase(
            &mut self,
            testcase: &PersistentQueueEntry,
        ) -> Result<(), PersistentChildError> {
            if Some(testcase.testcase_id) == self.fail_on {
                return Err(PersistentChildError::new("child rejected testcase"));
            }
            self.seen.push(testcase.clone());
            Ok(())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-persistent-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir is created");
        dir
    }
}
