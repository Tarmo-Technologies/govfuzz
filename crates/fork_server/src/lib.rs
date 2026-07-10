// SPDX-License-Identifier: Apache-2.0

//! AFL fork-server wire-protocol implementation.
//!
//! The fork-server protocol is how AFL drives a target without
//! re-execing the whole binary per input: the parent (fuzzer)
//! and child (target) communicate over two pipes — a "control"
//! pipe (parent -> child) and a "status" pipe (child -> parent).
//! Each iteration the parent writes a 4-byte ping to the control
//! pipe; the child forks a worker, reads the input, runs one
//! iteration, and writes the worker pid + exit status back to the
//! status pipe.
//!
//! AFL hard-codes fds 198 (control read by child) and 199 (status
//! write by child) so the target's child process can rely on them
//! without negotiation. govfuzz's parent-side allocator follows
//! the same convention by default but `Server::new_with_fds`
//! accepts arbitrary fds for testing.
//!
//! Tracks issue #293. The C harness template needs to call
//! `child_handshake` + `child_loop` for this to be useful end-to-end;
//! that template change is intentionally out of scope for this
//! crate (it ships under harness_gen + a follow-up linker hook
//! in fuzz_engine_builtin).

use std::io::{Read, Write};

pub const DEFAULT_CTRL_FD: i32 = 198;
pub const DEFAULT_STATUS_FD: i32 = 199;
pub const HELLO: [u8; 4] = [b'F', b'O', b'R', b'K'];

#[derive(Debug, thiserror::Error)]
pub enum ForkServerError {
    #[error("I/O error in fork-server protocol: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake byte mismatch: expected {expected:?} got {actual:?}")]
    HandshakeMismatch { expected: [u8; 4], actual: [u8; 4] },
    #[error("child exited without status")]
    NoStatus,
}

/// Parent-side handle. Use `parent_handshake` to bring the
/// fork-server online (it reads the child's HELLO from the status
/// pipe), then call `request_iteration` per fuzz input. The
/// returned `IterationResult` carries the worker pid and exit
/// status — the fuzzer maps that onto its own crash detection.
#[derive(Debug)]
pub struct Parent<R: Read, W: Write> {
    status: R,
    ctrl: W,
}

impl<R: Read, W: Write> Parent<R, W> {
    pub fn new(status: R, ctrl: W) -> Self {
        Self { status, ctrl }
    }

    /// Read the HELLO bytes the child wrote when its fork-server
    /// loop started. Returns OK once the child is ready to accept
    /// the first ping.
    pub fn handshake(&mut self) -> Result<(), ForkServerError> {
        let mut buf = [0u8; 4];
        self.status.read_exact(&mut buf)?;
        if buf != HELLO {
            return Err(ForkServerError::HandshakeMismatch {
                expected: HELLO,
                actual: buf,
            });
        }
        Ok(())
    }

    /// Request a single iteration. Writes a 4-byte ping to the
    /// control pipe; reads back the worker pid (4 bytes LE) and the
    /// worker exit status (4 bytes LE) from the status pipe.
    pub fn request_iteration(&mut self) -> Result<IterationResult, ForkServerError> {
        self.ctrl.write_all(&[0, 0, 0, 0])?;
        self.ctrl.flush()?;
        let mut pid_bytes = [0u8; 4];
        self.status.read_exact(&mut pid_bytes)?;
        let mut status_bytes = [0u8; 4];
        self.status.read_exact(&mut status_bytes)?;
        Ok(IterationResult {
            worker_pid: i32::from_le_bytes(pid_bytes),
            exit_status: i32::from_le_bytes(status_bytes),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterationResult {
    pub worker_pid: i32,
    pub exit_status: i32,
}

/// Child-side helper. The C harness compiled with the
/// fork-server preamble calls `child_handshake` once on startup
/// (writes HELLO), then enters its iteration loop: read a ping,
/// fork, child runs the target, parent waits, parent writes pid +
/// status back to the status pipe.
///
/// For test purposes (or for a future pure-Rust harness),
/// `Child::run_loop` accepts a closure that simulates the fork +
/// run + exit cycle and writes the expected wire bytes.
#[derive(Debug)]
pub struct Child<R: Read, W: Write> {
    ctrl: R,
    status: W,
}

impl<R: Read, W: Write> Child<R, W> {
    pub fn new(ctrl: R, status: W) -> Self {
        Self { ctrl, status }
    }

    pub fn handshake(&mut self) -> Result<(), ForkServerError> {
        self.status.write_all(&HELLO)?;
        self.status.flush()?;
        Ok(())
    }

    /// Wait for one ping from the parent, then write back the
    /// worker pid + exit status the caller supplied. Returns false
    /// when the control pipe closes (parent shut down).
    pub fn serve_one<F>(&mut self, run: F) -> Result<bool, ForkServerError>
    where
        F: FnOnce() -> IterationResult,
    {
        let mut buf = [0u8; 4];
        match self.ctrl.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        let result = run();
        self.status.write_all(&result.worker_pid.to_le_bytes())?;
        self.status.write_all(&result.exit_status.to_le_bytes())?;
        self.status.flush()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parent_handshake_accepts_correct_hello() {
        let status = Cursor::new(HELLO.to_vec());
        let ctrl: Vec<u8> = Vec::new();
        let mut parent = Parent::new(status, ctrl);
        assert!(parent.handshake().is_ok());
    }

    #[test]
    fn parent_handshake_rejects_wrong_hello() {
        let status = Cursor::new(b"XXXX".to_vec());
        let ctrl: Vec<u8> = Vec::new();
        let mut parent = Parent::new(status, ctrl);
        assert!(matches!(
            parent.handshake(),
            Err(ForkServerError::HandshakeMismatch { .. })
        ));
    }

    #[test]
    fn child_handshake_writes_hello() {
        let ctrl: &[u8] = &[];
        let mut status: Vec<u8> = Vec::new();
        let mut child = Child::new(ctrl, &mut status);
        child.handshake().unwrap();
        assert_eq!(status, HELLO);
    }

    #[test]
    fn round_trip_one_iteration_parent_reads_pid_and_status() {
        // Simulate parent + child wired together with two
        // back-to-back Vec/Cursor channels in memory.
        //
        // Sequence:
        //   1. child writes HELLO to status.
        //   2. parent.handshake() consumes HELLO.
        //   3. parent.request_iteration() writes ping to ctrl.
        //   4. child.serve_one(...) reads ping, writes pid+status.
        //   5. parent.request_iteration() reads pid+status, returns.
        //
        // We arrange this by running child first, dumping bytes
        // into a shared buffer, then parent consumes them.
        let mut child_status_buf: Vec<u8> = Vec::new();
        let mut child_ctrl_buf: Vec<u8> = Vec::new();
        {
            let mut c = Child::new(&[][..], &mut child_status_buf);
            c.handshake().unwrap();
        }
        // Pretend parent writes a ping (just append 4 bytes).
        child_ctrl_buf.extend_from_slice(&[0, 0, 0, 0]);
        {
            let mut c = Child::new(&child_ctrl_buf[..], &mut child_status_buf);
            let ok = c
                .serve_one(|| IterationResult {
                    worker_pid: 4242,
                    exit_status: 0,
                })
                .unwrap();
            assert!(ok);
        }
        // Now drive the parent over what the child wrote.
        let status = Cursor::new(child_status_buf);
        let mut parent_ctrl_sink: Vec<u8> = Vec::new();
        let mut parent = Parent::new(status, &mut parent_ctrl_sink);
        parent.handshake().unwrap();
        let result = parent.request_iteration().unwrap();
        assert_eq!(result.worker_pid, 4242);
        assert_eq!(result.exit_status, 0);
    }

    #[test]
    fn child_serve_one_returns_false_when_ctrl_pipe_closes() {
        let ctrl: &[u8] = &[];
        let mut status: Vec<u8> = Vec::new();
        let mut child = Child::new(ctrl, &mut status);
        let result = child
            .serve_one(|| IterationResult {
                worker_pid: 0,
                exit_status: 0,
            })
            .unwrap();
        assert!(!result);
    }

    #[cfg(unix)]
    #[test]
    fn pipe_round_trip_with_real_unix_pipes() {
        use std::os::unix::io::FromRawFd;
        // Build two pipes: ctrl (parent->child) and status
        // (child->parent).
        let mut ctrl_pipe = [-1i32; 2];
        let mut status_pipe = [-1i32; 2];
        unsafe {
            libc::pipe(ctrl_pipe.as_mut_ptr());
            libc::pipe(status_pipe.as_mut_ptr());
        }
        let ctrl_read = unsafe { std::fs::File::from_raw_fd(ctrl_pipe[0]) };
        let ctrl_write = unsafe { std::fs::File::from_raw_fd(ctrl_pipe[1]) };
        let status_read = unsafe { std::fs::File::from_raw_fd(status_pipe[0]) };
        let status_write = unsafe { std::fs::File::from_raw_fd(status_pipe[1]) };

        // Spawn a child-side thread.
        let child_thread = std::thread::spawn(move || {
            let mut child = Child::new(ctrl_read, status_write);
            child.handshake().unwrap();
            let _ = child
                .serve_one(|| IterationResult {
                    worker_pid: 9999,
                    exit_status: 7,
                })
                .unwrap();
        });

        let mut parent = Parent::new(status_read, ctrl_write);
        parent.handshake().unwrap();
        let result = parent.request_iteration().unwrap();
        assert_eq!(result.worker_pid, 9999);
        assert_eq!(result.exit_status, 7);
        child_thread.join().unwrap();
    }
}
