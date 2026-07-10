// SPDX-License-Identifier: Apache-2.0
//
// §27.1 native Rust reader-trait fixture (the byteorder `ReadBytesExt` class). The
// crate's public API is `pub trait` methods on an extension trait over any
// `io::Read`, plus a marker byte-order trait with concrete `BigEndian` /
// `LittleEndian` impls. A trait method has no enclosing concrete `impl` type, so
// the Rust lane must synthesise a `std::io::Cursor` receiver from the fuzz bytes,
// import the trait (`use ... ReadNumExt;`), and bake the marker turbofish
// (`read_num::<BigEndian>()`). `read_tag` hides a planted panic reachable through
// the synthesised Cursor receiver so the native engine demonstrably FINDS a crash.

use std::io::Read;

/// A marker byte-order trait (the `ByteOrder` / `BigEndian` shape). Used only as a
/// type-parameter bound, so the build lane resolves it to a concrete-impl turbofish
/// rather than trying to decode a value of it.
pub trait Endian {
    /// `true` for big-endian.
    const BIG: bool;
}

/// Big-endian marker.
pub enum BigEndian {}
impl Endian for BigEndian {
    const BIG: bool = true;
}

/// Little-endian marker.
pub enum LittleEndian {}
impl Endian for LittleEndian {
    const BIG: bool = false;
}

/// An extension trait over any `io::Read` (the `ReadBytesExt: io::Read` shape). Its
/// instance methods read typed values from the underlying reader.
pub trait ReadNumExt: Read {
    /// Read a 4-byte unsigned integer in the byte order named by the marker `T`.
    /// The generic `T: Endian` is used by no value argument, so the build lane
    /// resolves it to `BigEndian` via the marker turbofish.
    fn read_num<T: Endian>(&mut self) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        let v = if T::BIG {
            u32::from_be_bytes(buf)
        } else {
            u32::from_le_bytes(buf)
        };
        Ok(v)
    }

    /// Read a one-byte tag. PLANTED BUG: tag `0x7e` panics — reachable through the
    /// synthesised `std::io::Cursor` receiver fed the fuzz bytes, so the native
    /// engine finds the crash within a handful of executions.
    fn read_tag(&mut self) -> std::io::Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        if buf[0] == 0x7e {
            panic!("planted reader-trait crash (GF-201)");
        }
        Ok(buf[0])
    }
}

/// Every `io::Read` gets the extension methods (byteorder's blanket-impl idiom).
impl<R: Read + ?Sized> ReadNumExt for R {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_num_big_endian() {
        let mut c = Cursor::new(vec![0x00, 0x00, 0x01, 0x00]);
        assert_eq!(c.read_num::<BigEndian>().unwrap(), 256);
    }

    #[test]
    fn read_tag_passes_non_magic() {
        let mut c = Cursor::new(vec![0x01]);
        assert_eq!(c.read_tag().unwrap(), 1);
    }
}
