# SPDX-License-Identifier: Apache-2.0
"""govfuzz Python decode runtime — the Python analog of c_runtime/govfuzz_decode.h.

A cursor over the raw fuzz input that decodes typed values left-to-right, drained
deterministically and zero-filling on exhaustion (so a short input still produces
a valid, stable call). Mirrors the C decoder's primitives so the same byte layout
decodes consistently across lanes.
"""
import struct


class Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos if self.pos < len(self.data) else 0

    def u8(self) -> int:
        if self.remaining() == 0:
            return 0
        v = self.data[self.pos]
        self.pos += 1
        return v

    def _take(self, n: int) -> bytes:
        avail = min(n, self.remaining())
        b = self.data[self.pos:self.pos + avail]
        self.pos += avail
        if avail < n:
            b = b + b"\x00" * (n - avail)
        return b

    def i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self._take(8))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self._take(8))[0]

    def boolean(self) -> bool:
        return (self.u8() & 1) == 1

    def bounded_i32(self, lo: int, hi: int) -> int:
        if hi <= lo:
            return lo
        return lo + (self.u32() % (hi - lo + 1))

    def bounded_length(self, lo: int, hi: int) -> int:
        return self.bounded_i32(lo, hi)

    def take_bytes(self, n: int) -> bytes:
        return self._take(n)

    def rest(self) -> bytes:
        b = self.data[self.pos:]
        self.pos = len(self.data)
        return b

    def text(self, max_len: int = 4096) -> str:
        """A length-prefixed-ish string: one length byte scaled into [0, min(max_len, remaining)]."""
        n = self.bounded_length(0, min(max_len, max(self.remaining(), 0)))
        return self._take(n).decode("utf-8", "replace")


def open_cursor(data: bytes) -> Cursor:
    return Cursor(data)
