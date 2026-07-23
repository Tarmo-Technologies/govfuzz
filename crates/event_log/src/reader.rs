// SPDX-License-Identifier: Apache-2.0

//! Reader for `AdaFuzz.Probe` binary event streams.
//!
//! The Ada body `ada_runtime/adafuzz-probe.adb` is the wire-format source of
//! truth. Each record starts with a one-byte tag. Integers are little-endian
//! `u8`, `u32`, or `u64`. Strings are a four-byte little-endian `u32` byte
//! length followed by that many bytes. `TopLevel` and `Mock` records carry
//! trailing breadcrumb/target/testcase context in the current probe body; M5
//! consumes those fields to stay aligned but does not retain them in `Event`.

use crate::{Event, EventTag};
use std::io::{self, Read};

pub struct EventReader<R: Read> {
    inner: R,
}

impl<R: Read> EventReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn next_event(&mut self) -> Result<Option<Event>, EventReadError> {
        let mut tag = [0_u8; 1];
        let bytes_read = self.inner.read(&mut tag)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let tag = EventTag::try_from_byte(tag[0]).ok_or(EventReadError::UnknownTag(tag[0]))?;
        let event = match tag {
            EventTag::Begin => Event::Begin {
                testcase_id: self.read_u64()?,
            },
            EventTag::End => Event::End {
                result_class: self.read_array::<1>()?[0],
            },
            EventTag::Crumb => Event::Crumb {
                id: self.read_u32()?,
            },
            EventTag::Target => Event::Target {
                id: self.read_u32()?,
            },
            EventTag::TargetEntry => Event::TargetEntry,
            EventTag::Handler => Event::Handler {
                exception_name: self.read_string()?,
                exception_message: self.read_string()?,
                handler_file: self.read_string()?,
                handler_line: self.read_u32()?,
                last_breadcrumb: self.read_u32()?,
                target_id: self.read_u32()?,
                testcase_id: self.read_u64()?,
            },
            EventTag::Raise => Event::Raise {
                exception_name: self.read_string()?,
                file: self.read_string()?,
                line: self.read_u32()?,
                breadcrumb: self.read_u32()?,
            },
            EventTag::Mock => {
                let symbol = self.read_string()?;
                let _last_breadcrumb = self.read_u32()?;
                let _target_id = self.read_u32()?;
                let _testcase_id = self.read_u64()?;
                Event::Mock { symbol }
            }
            EventTag::TopLevel => {
                let exception_name = self.read_string()?;
                let exception_message = self.read_string()?;
                let _last_breadcrumb = self.read_u32()?;
                let _target_id = self.read_u32()?;
                let _testcase_id = self.read_u64()?;
                Event::TopLevel {
                    exception_name,
                    exception_message,
                }
            }
        };

        Ok(Some(event))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], EventReadError> {
        let mut bytes = [0_u8; N];
        self.inner
            .read_exact(&mut bytes)
            .map_err(EventReadError::from_payload_read)?;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> Result<u32, EventReadError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, EventReadError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Upper bound on a length-prefixed string. The 4-byte length is only
    /// indirectly attacker-influenced (it comes from govfuzz's own harness
    /// runtime), but a corrupt or oversized header must not drive a multi-gigabyte
    /// allocation before the payload is even read (security review, LOW).
    const MAX_STRING_LEN: usize = 16 * 1024 * 1024;

    fn read_string(&mut self) -> Result<String, EventReadError> {
        let len = self.read_u32()? as usize;
        if len > Self::MAX_STRING_LEN {
            return Err(EventReadError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "event-log string length {len} exceeds cap {}",
                    Self::MAX_STRING_LEN
                ),
            )));
        }
        let mut bytes = vec![0_u8; len];
        self.inner
            .read_exact(&mut bytes)
            .map_err(EventReadError::from_payload_read)?;
        String::from_utf8(bytes)
            .map_err(|error| EventReadError::Io(io::Error::new(io::ErrorKind::InvalidData, error)))
    }
}

pub struct EventReaderIter<R: Read> {
    reader: EventReader<R>,
}

impl<R: Read> IntoIterator for EventReader<R> {
    type Item = Result<Event, EventReadError>;
    type IntoIter = EventReaderIter<R>;

    fn into_iter(self) -> Self::IntoIter {
        EventReaderIter { reader: self }
    }
}

impl<R: Read> Iterator for EventReaderIter<R> {
    type Item = Result<Event, EventReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_event() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventReadError {
    #[error("end of event stream")]
    Eof,
    #[error("unknown event tag {0}")]
    UnknownTag(u8),
    #[error("I/O error while reading event stream")]
    Io(#[from] io::Error),
    #[error("truncated event payload")]
    Truncated,
}

impl EventReadError {
    fn from_payload_read(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Self::Truncated
        } else {
            Self::Io(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventReadError, EventReader};
    use crate::{Event, EventTag};
    use std::io::Cursor;

    #[test]
    fn read_begin_event_decodes_testcase_id() {
        let mut bytes = vec![EventTag::Begin as u8];
        bytes.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Begin {
                testcase_id: 0x0102_0304_0506_0708
            })
        );
    }

    #[test]
    fn read_end_event_decodes_result_class() {
        let mut reader = EventReader::new(Cursor::new(vec![EventTag::End as u8, 7]));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::End { result_class: 7 })
        );
    }

    #[test]
    fn read_crumb_event_decodes_id() {
        let mut bytes = vec![EventTag::Crumb as u8];
        bytes.extend_from_slice(&0xAABB_CCDD_u32.to_le_bytes());
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Crumb { id: 0xAABB_CCDD })
        );
    }

    #[test]
    fn read_target_event_decodes_id() {
        let mut bytes = vec![EventTag::Target as u8];
        bytes.extend_from_slice(&0x0000_0042_u32.to_le_bytes());
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Target { id: 0x42 })
        );
    }

    #[test]
    fn read_target_entry_event_has_no_identifier_payload() {
        let mut reader = EventReader::new([EventTag::TargetEntry as u8].as_slice());
        assert_eq!(reader.next_event().unwrap(), Some(Event::TargetEntry));
        assert_eq!(reader.next_event().unwrap(), None);
    }

    #[test]
    fn read_returns_eof_when_stream_exhausted() {
        let mut reader = EventReader::new(Cursor::new(Vec::<u8>::new()));

        assert_eq!(reader.next_event().unwrap(), None);
    }

    #[test]
    fn read_returns_unknown_tag_for_invalid_byte() {
        let mut reader = EventReader::new(Cursor::new(vec![99]));

        assert!(matches!(
            reader.next_event(),
            Err(EventReadError::UnknownTag(99))
        ));
    }

    #[test]
    fn read_returns_truncated_when_payload_short() {
        let mut reader = EventReader::new(Cursor::new(vec![EventTag::Begin as u8, 1, 2]));

        assert!(matches!(
            reader.next_event(),
            Err(EventReadError::Truncated)
        ));
    }

    #[test]
    fn read_handler_event_decodes_all_fields() {
        let bytes = vec![
            EventTag::Handler as u8,
            16,
            0,
            0,
            0,
            b'C',
            b'O',
            b'N',
            b'S',
            b'T',
            b'R',
            b'A',
            b'I',
            b'N',
            b'T',
            b'_',
            b'E',
            b'R',
            b'R',
            b'O',
            b'R',
            9,
            0,
            0,
            0,
            b'b',
            b'a',
            b'd',
            b' ',
            b'i',
            b'n',
            b'p',
            b'u',
            b't',
            7,
            0,
            0,
            0,
            b'p',
            b'k',
            b'g',
            b'.',
            b'a',
            b'd',
            b'b',
            9,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0x42,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Handler {
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "bad input".to_owned(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: 9,
                last_breadcrumb: 1,
                target_id: 0x42,
                testcase_id: 1,
            })
        );
    }

    #[test]
    fn read_raise_event_decodes_all_fields() {
        let bytes = vec![
            EventTag::Raise as u8,
            8,
            0,
            0,
            0,
            b'B',
            b'a',
            b'd',
            b'I',
            b'n',
            b'p',
            b'u',
            b't',
            7,
            0,
            0,
            0,
            b'p',
            b'k',
            b'g',
            b'.',
            b'a',
            b'd',
            b'b',
            23,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Raise {
                exception_name: "BadInput".to_owned(),
                file: "pkg.adb".to_owned(),
                line: 23,
                breadcrumb: 2,
            })
        );
    }

    #[test]
    fn read_mock_event_decodes_symbol() {
        let bytes = vec![
            EventTag::Mock as u8,
            19,
            0,
            0,
            0,
            b'E',
            b'x',
            b't',
            b'e',
            b'r',
            b'n',
            b'a',
            b'l',
            b'_',
            b'L',
            b'i',
            b'b',
            b'.',
            b'L',
            b'o',
            b'o',
            b'k',
            b'u',
            b'p',
            3,
            0,
            0,
            0,
            0x42,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Mock {
                symbol: "External_Lib.Lookup".to_owned()
            })
        );
    }

    #[test]
    fn read_top_level_event_decodes_name_and_message() {
        let bytes = vec![
            EventTag::TopLevel as u8,
            13,
            0,
            0,
            0,
            b'P',
            b'R',
            b'O',
            b'G',
            b'R',
            b'A',
            b'M',
            b'_',
            b'E',
            b'R',
            b'R',
            b'O',
            b'R',
            7,
            0,
            0,
            0,
            b'e',
            b's',
            b'c',
            b'a',
            b'p',
            b'e',
            b'd',
            4,
            0,
            0,
            0,
            0x42,
            0,
            0,
            0,
            9,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::TopLevel {
                exception_name: "PROGRAM_ERROR".to_owned(),
                exception_message: "escaped".to_owned(),
            })
        );
    }

    #[test]
    fn read_handler_with_empty_message_is_ok() {
        let bytes = vec![
            EventTag::Handler as u8,
            13,
            0,
            0,
            0,
            b'T',
            b'A',
            b'S',
            b'K',
            b'I',
            b'N',
            b'G',
            b'_',
            b'E',
            b'R',
            b'R',
            b'O',
            b'R',
            0,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            b'p',
            b'k',
            b'g',
            b'.',
            b'a',
            b'd',
            b'b',
            10,
            0,
            0,
            0,
            5,
            0,
            0,
            0,
            0x42,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Handler {
                exception_name: "TASKING_ERROR".to_owned(),
                exception_message: String::new(),
                handler_file: "pkg.adb".to_owned(),
                handler_line: 10,
                last_breadcrumb: 5,
                target_id: 0x42,
                testcase_id: 2,
            })
        );
    }

    #[test]
    fn read_raise_with_empty_name_is_ok() {
        let bytes = vec![
            EventTag::Raise as u8,
            0,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            b'p',
            b'k',
            b'g',
            b'.',
            b'a',
            b'd',
            b'b',
            31,
            0,
            0,
            0,
            6,
            0,
            0,
            0,
        ];
        let mut reader = EventReader::new(Cursor::new(bytes));

        assert_eq!(
            reader.next_event().unwrap(),
            Some(Event::Raise {
                exception_name: String::new(),
                file: "pkg.adb".to_owned(),
                line: 31,
                breadcrumb: 6,
            })
        );
    }
}
