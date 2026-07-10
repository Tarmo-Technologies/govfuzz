// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::str::Utf8Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endianness {
    Big,
    Little,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CdrError {
    UnexpectedEof {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    InvalidBoolean {
        offset: usize,
        value: u8,
    },
    InvalidStringTerminator {
        offset: usize,
    },
    InvalidUtf8 {
        offset: usize,
    },
    SequenceLengthExceedsRemaining {
        offset: usize,
        declared: u32,
        remaining: usize,
        element_min_size: usize,
    },
}

impl fmt::Display for CdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected EOF at offset {offset}: needed {needed} byte(s), had {remaining}"
            ),
            Self::InvalidBoolean { offset, value } => {
                write!(f, "invalid CDR boolean value {value} at offset {offset}")
            }
            Self::InvalidStringTerminator { offset } => {
                write!(f, "CDR string missing NUL terminator at offset {offset}")
            }
            Self::InvalidUtf8 { offset } => write!(f, "CDR string is not valid UTF-8 at {offset}"),
            Self::SequenceLengthExceedsRemaining {
                offset,
                declared,
                remaining,
                element_min_size,
            } => write!(
                f,
                "sequence length {declared} at offset {offset} cannot fit in {remaining} remaining byte(s) with {element_min_size}-byte minimum elements"
            ),
        }
    }
}

impl std::error::Error for CdrError {}

#[derive(Clone, Debug)]
pub struct CdrReader<'a> {
    input: &'a [u8],
    offset: usize,
    alignment_base: usize,
    endian: Endianness,
}

impl<'a> CdrReader<'a> {
    pub fn new(input: &'a [u8], endian: Endianness) -> Self {
        Self {
            input,
            offset: 0,
            alignment_base: 0,
            endian,
        }
    }

    pub fn with_alignment_base(input: &'a [u8], endian: Endianness, alignment_base: usize) -> Self {
        Self {
            input,
            offset: 0,
            alignment_base,
            endian,
        }
    }

    pub fn from_encapsulation(input: &'a [u8]) -> Result<Self, CdrError> {
        let mut byte_order = Self::new(input, Endianness::Big);
        let is_little_endian = byte_order.read_bool()?;
        let endian = if is_little_endian {
            Endianness::Little
        } else {
            Endianness::Big
        };

        Ok(Self::with_alignment_base(&input[1..], endian, 1))
    }

    pub fn position(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    pub fn align_to(&mut self, alignment: usize) -> Result<(), CdrError> {
        let start = self.offset;
        let Some(aligned) = align_offset(start, alignment, self.alignment_base) else {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: alignment,
                remaining: self.remaining(),
            });
        };
        if aligned > self.input.len() {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: aligned - start,
                remaining: self.remaining(),
            });
        }

        self.offset = aligned;
        Ok(())
    }

    pub fn read_octet(&mut self) -> Result<u8, CdrError> {
        Ok(self.take_aligned(1, 1)?[0])
    }

    pub fn read_bool(&mut self) -> Result<bool, CdrError> {
        let offset = self.offset;
        match self.read_octet()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(CdrError::InvalidBoolean { offset, value }),
        }
    }

    pub fn read_u16(&mut self) -> Result<u16, CdrError> {
        let endian = self.endian;
        let bytes = self.take_aligned(2, 2)?;
        Ok(match endian {
            Endianness::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
            Endianness::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
        })
    }

    pub fn read_i16(&mut self) -> Result<i16, CdrError> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_u32(&mut self) -> Result<u32, CdrError> {
        let endian = self.endian;
        let bytes = self.take_aligned(4, 4)?;
        Ok(match endian {
            Endianness::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endianness::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    pub fn read_i32(&mut self) -> Result<i32, CdrError> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_u64(&mut self) -> Result<u64, CdrError> {
        let endian = self.endian;
        let bytes = self.take_aligned(8, 8)?;
        Ok(match endian {
            Endianness::Big => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            Endianness::Little => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        })
    }

    pub fn read_i64(&mut self) -> Result<i64, CdrError> {
        Ok(self.read_u64()? as i64)
    }

    pub fn read_f32(&mut self) -> Result<f32, CdrError> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    pub fn read_f64(&mut self) -> Result<f64, CdrError> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    pub fn read_string(&mut self) -> Result<String, CdrError> {
        let start = self.offset;
        let len = self.read_u32()? as usize;
        if len == 0 {
            return Err(CdrError::InvalidStringTerminator { offset: start + 4 });
        }

        let bytes = self.take_unaligned(len)?;
        let terminator_offset = self.offset - 1;
        if bytes[len - 1] != 0 {
            return Err(CdrError::InvalidStringTerminator {
                offset: terminator_offset,
            });
        }

        std::str::from_utf8(&bytes[..len - 1])
            .map(|value| value.to_owned())
            .map_err(|_err: Utf8Error| CdrError::InvalidUtf8 { offset: start + 4 })
    }

    pub fn read_octet_sequence(&mut self) -> Result<&'a [u8], CdrError> {
        let len = self.read_u32()? as usize;
        self.take_unaligned(len)
    }

    fn take_aligned(&mut self, alignment: usize, len: usize) -> Result<&'a [u8], CdrError> {
        let start = self.offset;
        let Some(aligned) = align_offset(start, alignment, self.alignment_base) else {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: len,
                remaining: self.remaining(),
            });
        };
        let Some(end) = aligned.checked_add(len) else {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: len,
                remaining: self.remaining(),
            });
        };
        if end > self.input.len() {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: len,
                remaining: self.remaining(),
            });
        }

        self.offset = aligned + len;
        Ok(&self.input[aligned..aligned + len])
    }

    fn take_unaligned(&mut self, len: usize) -> Result<&'a [u8], CdrError> {
        let start = self.offset;
        let Some(end) = start.checked_add(len) else {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: len,
                remaining: self.remaining(),
            });
        };
        if end > self.input.len() {
            return Err(CdrError::UnexpectedEof {
                offset: start,
                needed: len,
                remaining: self.remaining(),
            });
        }

        self.offset = end;
        Ok(&self.input[start..end])
    }
}

fn align_offset(offset: usize, alignment: usize, alignment_base: usize) -> Option<usize> {
    debug_assert!(alignment.is_power_of_two());
    let absolute = alignment_base.checked_add(offset)?;
    let mask = alignment - 1;
    let aligned_absolute = absolute.checked_add(mask)? & !mask;
    aligned_absolute.checked_sub(alignment_base)
}
