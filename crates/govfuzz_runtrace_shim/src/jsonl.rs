// SPDX-License-Identifier: Apache-2.0

//! Fixed-buffer JSONL emitter. Each event is formatted into a 4 KiB
//! stack buffer and emitted via libc::write(2) to a per-process log
//! fd opened on first use. No heap allocations — the host process
//! may be inside its own allocator on the path we're called from.
//!
//! The output fd path comes from the `GOVFUZZ_RUNTRACE_LOG` env var.
//! When that var is unset (host is not running under govfuzz auto),
//! every emit() is a no-op.

use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Sentinel: fd not yet opened. -2 instead of -1 because some
/// system calls genuinely return -1 as a valid (just-failed) fd.
const FD_UNINITIALIZED: i32 = -2;
const FD_DISABLED: i32 = -1;

static LOG_FD: AtomicI32 = AtomicI32::new(FD_UNINITIALIZED);

/// Bytes written to the log so far. Once this exceeds
/// `MAX_LOG_BYTES` the shim stops appending — fuzz campaigns can
/// otherwise produce multi-GiB runtrace files that DoS the parent
/// process trying to parse them. Unique locators are deduplicated
/// at aggregation time, so dropping repeated events past the cap
/// loses no information the report would have used.
static LOG_BYTES: AtomicU64 = AtomicU64::new(0);

const EVENT_BUFFER_SIZE: usize = 4096;

/// Cap each runtrace log at 16 MiB. Anything past that is dropped
/// silently. Sized to hold ~300k events at the average event width.
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

/// Append a pre-formatted JSON line (newline-terminated) to the
/// runtrace log. Silent when no log is configured or the per-log
/// byte cap has been reached.
pub fn emit_raw(line: &[u8]) {
    let fd = ensure_fd();
    if fd < 0 {
        return;
    }
    let new_total = LOG_BYTES.fetch_add(line.len() as u64, Ordering::Relaxed) + line.len() as u64;
    if new_total > MAX_LOG_BYTES {
        return;
    }
    // Atomic write: a single write(2) under PIPE_BUF (4096) is
    // guaranteed atomic vs. other writers on POSIX. The buffer here
    // is exactly EVENT_BUFFER_SIZE, so we never exceed.
    unsafe {
        let _ = libc::write(fd, line.as_ptr().cast(), line.len());
    }
}

fn ensure_fd() -> i32 {
    let cached = LOG_FD.load(Ordering::Relaxed);
    if cached != FD_UNINITIALIZED {
        return cached;
    }
    // Open the log file. Use libc directly so we don't accidentally
    // wind up inside our own hooked open() (which would recurse).
    let path = match std::env::var_os("GOVFUZZ_RUNTRACE_LOG") {
        Some(p) => p,
        None => {
            LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
            return FD_DISABLED;
        }
    };
    // Process-scope the shim: a crash makes the statically linked sanitizer
    // spawn an external symbolizer (llvm-symbolizer / addr2line) which inherits
    // our LD_PRELOAD *and* the shared GOVFUZZ_RUNTRACE_LOG path. Without this
    // gate the symbolizer's own getenv/open probes (OPENSSL_*, LLVM_*,
    // ~/.cache/llvm-debuginfod, ...) would be appended to the TARGET's runtrace
    // and misreported as the target's faked env vars / missing deps. Detected
    // once, at first log-open, so the whole non-target child stays silent — and
    // the very event that triggered detection is dropped (this runs before the
    // write in `emit_raw`).
    if process_is_symbolizer() {
        LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
        return FD_DISABLED;
    }
    let path_cstr = match CString::new(path.as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => {
            LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
            return FD_DISABLED;
        }
    };
    // O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC; mode 0644
    let fd = unsafe {
        libc::open(
            path_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
        return FD_DISABLED;
    }
    LOG_FD.store(fd, Ordering::Relaxed);
    fd
}

/// True when THIS process is a crash-symbolizer helper the sanitizer spawned
/// (llvm-symbolizer / addr2line / …), read once from `/proc/self/cmdline`.
/// Signal-safe: a single stack buffer and three raw libc syscalls, no heap.
/// `libc::open` here either binds to our own `open` hook — which short-circuits
/// without logging because a hook is already active when `ensure_fd` runs — or
/// to the real `open`; either way the probe is never itself recorded.
fn process_is_symbolizer() -> bool {
    let fd = unsafe {
        libc::open(
            c"/proc/self/cmdline".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe {
        libc::close(fd);
    }
    if n <= 0 {
        return false;
    }
    let n = n as usize;
    // argv[0] is the first NUL-delimited field of /proc/self/cmdline.
    let arg0 = match buf[..n].iter().position(|&b| b == 0) {
        Some(i) => &buf[..i],
        None => &buf[..n],
    };
    let base = match arg0.iter().rposition(|&b| b == b'/') {
        Some(i) => &arg0[i + 1..],
        None => arg0,
    };
    basename_is_symbolizer(base)
}

/// Whether a process basename is one of the sanitizer's symbolization helpers.
/// Versioned forms (`llvm-symbolizer-17`) match via the `llvm-` prefixes.
fn basename_is_symbolizer(base: &[u8]) -> bool {
    base == b"addr2line"
        || base == b"atos"
        || base.starts_with(b"llvm-symbolizer")
        || base.starts_with(b"llvm-addr2line")
}

/// Stack-allocated JSON line builder. Use `Builder::new(b"open")` to
/// start, then `.field_str` / `.field_i64` / `.field_null`, finally
/// `.emit()` to flush. Truncates silently when the buffer fills.
pub struct Builder {
    buf: [u8; EVENT_BUFFER_SIZE],
    len: usize,
    truncated: bool,
}

impl Builder {
    pub fn new(event_name: &[u8]) -> Self {
        let mut b = Self {
            buf: [0u8; EVENT_BUFFER_SIZE],
            len: 0,
            truncated: false,
        };
        b.write_byte(b'{');
        b.write_kv_open(b"e");
        b.write_str_quoted(event_name);
        b
    }

    /// Add a `"key":"value"` pair.
    pub fn field_str(&mut self, key: &[u8], value: &[u8]) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_str_quoted(value);
    }

    /// Add a `"key":<integer>` pair.
    pub fn field_i64(&mut self, key: &[u8], value: i64) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_i64(value);
    }

    pub fn field_null(&mut self, key: &[u8]) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_bytes(b"null");
    }

    pub fn emit(mut self) {
        self.write_byte(b'}');
        self.write_byte(b'\n');
        emit_raw(&self.buf[..self.len]);
    }

    fn write_byte(&mut self, b: u8) {
        if self.len >= self.buf.len() {
            self.truncated = true;
            return;
        }
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn write_bytes(&mut self, bs: &[u8]) {
        for b in bs {
            self.write_byte(*b);
        }
    }

    fn write_kv_open(&mut self, key: &[u8]) {
        self.write_byte(b'"');
        self.write_bytes(key);
        self.write_bytes(b"\":");
    }

    fn write_str_quoted(&mut self, value: &[u8]) {
        self.write_byte(b'"');
        for &b in value {
            match b {
                b'"' => self.write_bytes(b"\\\""),
                b'\\' => self.write_bytes(b"\\\\"),
                b'\n' => self.write_bytes(b"\\n"),
                b'\r' => self.write_bytes(b"\\r"),
                b'\t' => self.write_bytes(b"\\t"),
                0x20..=0x7e => self.write_byte(b),
                // Non-ASCII / control bytes: render as \uXXXX
                _ => {
                    let hi = (b >> 4) & 0xf;
                    let lo = b & 0xf;
                    self.write_bytes(b"\\u00");
                    self.write_byte(hex_digit(hi));
                    self.write_byte(hex_digit(lo));
                }
            }
        }
        self.write_byte(b'"');
    }

    fn write_i64(&mut self, value: i64) {
        if value == 0 {
            self.write_byte(b'0');
            return;
        }
        let mut tmp = [0u8; 20];
        let mut n = value;
        let mut neg = false;
        if n < 0 {
            neg = true;
            // Avoid overflow on i64::MIN.
            n = n.wrapping_neg();
        }
        let mut idx = tmp.len();
        let mut u = n as u64;
        while u > 0 {
            idx -= 1;
            tmp[idx] = b'0' + (u % 10) as u8;
            u /= 10;
        }
        if neg {
            self.write_byte(b'-');
        }
        self.write_bytes(&tmp[idx..]);
    }
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_renders_simple_event() {
        let mut b = Builder::new(b"getenv");
        b.field_str(b"n", b"FOO_HOME");
        b.field_null(b"r");
        // We can't directly call emit() in a test because it writes
        // to the log fd. Instead, finalize manually and read buf.
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert_eq!(out, r#"{"e":"getenv","n":"FOO_HOME","r":null}"#);
    }

    #[test]
    fn builder_renders_integer() {
        let mut b = Builder::new(b"open");
        b.field_str(b"p", b"/etc/foo");
        b.field_i64(b"r", -1);
        b.field_i64(b"n", 2);
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert_eq!(out, r#"{"e":"open","p":"/etc/foo","r":-1,"n":2}"#);
    }

    #[test]
    fn builder_escapes_quotes_and_backslashes() {
        let mut b = Builder::new(b"open");
        b.field_str(b"p", b"/etc/\"weird\"/path");
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert!(out.contains(r#"\"weird\""#), "got {out}");
    }

    #[test]
    fn symbolizer_basenames_are_recognized() {
        assert!(basename_is_symbolizer(b"llvm-symbolizer"));
        assert!(basename_is_symbolizer(b"llvm-symbolizer-17"));
        assert!(basename_is_symbolizer(b"addr2line"));
        assert!(basename_is_symbolizer(b"llvm-addr2line"));
        assert!(basename_is_symbolizer(b"atos"));
        // A genuine fuzz target binary is not a symbolizer.
        assert!(!basename_is_symbolizer(b"my_target_fuzzer"));
        assert!(!basename_is_symbolizer(b"parse"));
        assert!(!basename_is_symbolizer(b""));
    }

    #[test]
    fn builder_truncates_at_buffer_size() {
        let big: Vec<u8> = vec![b'a'; EVENT_BUFFER_SIZE * 2];
        let mut b = Builder::new(b"open");
        b.field_str(b"p", &big);
        // No panic, no oob write.
        assert!(b.len <= EVENT_BUFFER_SIZE);
    }
}
