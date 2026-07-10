# SPDX-License-Identifier: Apache-2.0
"""govfuzz Python coverage agent — the Python analog of java_runtime Coverage.java.

Joins govfuzz's file-backed edge map (path in GOVFUZZ_COV_SHM, mmap MAP_SHARED,
GOVFUZZ_COV_BITS = 1<<16) and records AFL-style edge hits into it from the
interpreter, using sys.monitoring (PEP 669, 3.12+) where available, else
sys.settrace. Pure stdlib — no coverage.py, no Atheris, no native helper.

Edge hash MUST match the C driver / Coverage.java:
    idx = (prev ^ block) & MASK ; map[idx]++ (saturating 0xff) ; prev = block >> 1
prev is reset to 0 at the start of each input so identical inputs hash to
identical edges (deterministic coverage).
"""
import mmap
import os
import sys

COV_BITS = 1 << 16
COV_MASK = COV_BITS - 1

_map = None
_prev = 0
_traced_prefix = None
_tool_id = 1

# Covered (file:line) set for negative fuzz-confirmation: a static finding whose
# line the fuzzer EXECUTED without a crash/finding is exercised-and-survived (weak
# evidence of a false positive), distinct from a line never reached. Captured only
# when GOVFUZZ_COVERED_LINES names a sidecar; dumped periodically by the driver.
_covered = set()
_covered_dumped = 0


def note_line(filename, lineno):
    _covered.add("{0}:{1}".format(filename, lineno))


def dump_covered_lines():
    """Write the covered (file:line) set to GOVFUZZ_COVERED_LINES when it grew.
    Cheap + best-effort: skipped if unset, no-op if nothing new since last dump."""
    global _covered_dumped
    path = os.environ.get("GOVFUZZ_COVERED_LINES")
    if not path or len(_covered) == _covered_dumped:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write("\n".join(sorted(_covered)))
        os.replace(tmp, path)
        _covered_dumped = len(_covered)
    except Exception:
        pass


def _open():
    global _map
    path = os.environ.get("GOVFUZZ_COV_SHM")
    if not path:
        return None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        if os.fstat(fd).st_size < COV_BITS:
            os.ftruncate(fd, COV_BITS)
        m = mmap.mmap(fd, COV_BITS, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        os.close(fd)
        return m
    except Exception:
        return None


def enabled() -> bool:
    return _map is not None


def reset_prev():
    global _prev
    _prev = 0


def _record(block: int):
    global _prev
    m = _map
    if m is None:
        return
    idx = (_prev ^ block) & COV_MASK
    v = m[idx]
    if v != 0xFF:
        m[idx] = v + 1
    _prev = (block >> 1) & COV_MASK


def _block_id(filename: str, lineno: int) -> int:
    # Stable per (file,line). hash() is salted per-process for str, so use a
    # deterministic FNV-1a over the bytes instead — coverage must be reproducible.
    h = 0xCBF29CE484222325
    for byte in filename.encode("utf-8", "replace"):
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    h = ((h ^ (lineno & 0xFF)) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    h = ((h ^ ((lineno >> 8) & 0xFF)) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & COV_MASK


# ---- sys.monitoring backend (3.12+) ----

def _install_monitoring(prefix):
    mon = sys.monitoring
    mon.use_tool_id(_tool_id, "govfuzz")
    E = mon.events

    def on_line(code, line_number):
        fn = code.co_filename
        if prefix is None or fn.startswith(prefix):
            _record(_block_id(fn, line_number))
            note_line(fn, line_number)
        return mon.DISABLE if False else None

    mon.register_callback(_tool_id, E.LINE, on_line)
    mon.set_events(_tool_id, E.LINE)


# ---- settrace backend (fallback) ----

def _install_settrace(prefix):
    def tracer(frame, event, arg):
        if event == "line":
            fn = frame.f_code.co_filename
            if prefix is None or fn.startswith(prefix):
                _record(_block_id(fn, frame.f_lineno))
                note_line(fn, frame.f_lineno)
        return tracer
    sys.settrace(tracer)
    # settrace only applies to frames entered after the call; threads need
    # settrace too, but the harness is single-threaded per input.


def install(traced_prefix=None):
    """Arm coverage. traced_prefix limits instrumentation to files under that path
    (the target/harness source root) so stdlib/driver noise is excluded."""
    global _map, _traced_prefix
    _map = _open()
    _traced_prefix = traced_prefix
    if _map is None:
        return False
    if hasattr(sys, "monitoring"):
        try:
            _install_monitoring(traced_prefix)
            return True
        except Exception:
            pass
    _install_settrace(traced_prefix)
    return True
