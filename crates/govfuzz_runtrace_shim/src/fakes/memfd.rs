// SPDX-License-Identifier: Apache-2.0

//! Create a memfd-backed fake fd, pre-filled with up to
//! FAKE_FD_CAPACITY bytes from fakes::data. Used by the fs hooks to
//! substitute on open()/openat() ENOENT.

use crate::fakes::data::fill_bytes;

/// Max bytes we'll pre-fill into a fake fd. Big enough for most
/// config files / etc-style content; small enough that even a
/// pathological fuzz harness with thousands of fake fds doesn't
/// exhaust process memory. 16 KiB per fd.
const FAKE_FD_CAPACITY: usize = 16 * 1024;

/// Create a memfd whose contents are the appropriate Mode-driven
/// fake bytes for `resource_name`. The fd has its read offset at 0;
/// the caller hands it back to the target as the return value of
/// the original open() so subsequent read()s see EOF (Empty mode),
/// pseudo-random bytes (Rng), or fuzz-driven bytes (FuzzDriven).
///
/// Returns -1 on any failure; caller falls back to the original
/// ENOENT return.
///
/// # Safety
///
/// Invokes libc syscalls directly (memfd_create, write, lseek,
/// close). The caller is responsible for closing the returned fd
/// when it's no longer needed.
pub unsafe fn create_fake_file_fd(resource_name: &[u8]) -> i32 {
    // memfd_create has the signature:
    //   int memfd_create(const char *name, unsigned int flags)
    // We pass MFD_CLOEXEC so the fd doesn't leak into spawned
    // children.
    let raw_name = b"govfuzz_fake\0";
    let fd = libc::syscall(
        libc::SYS_memfd_create,
        raw_name.as_ptr() as *const libc::c_char,
        libc::MFD_CLOEXEC as libc::c_uint,
    ) as i32;
    if fd < 0 {
        return -1;
    }
    let mut buf = [0u8; FAKE_FD_CAPACITY];
    let n = fill_bytes(resource_name, &mut buf);
    if n > 0 {
        let mut written = 0;
        while written < n {
            let w = libc::write(
                fd,
                buf[written..n].as_ptr() as *const libc::c_void,
                n - written,
            );
            if w <= 0 {
                let _ = libc::close(fd);
                return -1;
            }
            written += w as usize;
        }
    }
    // Reset offset so read() starts at byte 0.
    let _ = libc::lseek(fd, 0, libc::SEEK_SET);
    fd
}

/// Default sparse size for a fake POSIX shared-memory object (#438). A caller
/// that opens an "existing" object (`shm_open` without `O_CREAT`) often mmaps it
/// WITHOUT first `ftruncate`-ing, expecting the size to already exist; backing it
/// with a zero-length memfd would then SIGBUS on first access. memfd `ftruncate`
/// is sparse — only touched pages consume RAM — so a generous default is cheap
/// and lets virtually any real shm mapping succeed. The target may still
/// `ftruncate` it smaller or larger.
const FAKE_SHM_CAPACITY: libc::off_t = 64 * 1024 * 1024;

/// Bytes of mode-driven content pre-filled at the base of a fake shared-memory
/// object so a target that READS the region (expecting a peer partition to have
/// written it) gets fuzz/rng/zero values — the fuzzer drives shared-memory
/// content, reaching content-dependent handlers, exactly as it does for files and
/// MMIO. Empty mode fills nothing (the region reads as zero).
const FAKE_SHM_FILL: usize = 64 * 1024;

/// Create a private, anonymous memfd to stand in for a POSIX shared-memory
/// object (#438). Returns a harness-PRIVATE fd: two `shm_open`s of the same name
/// under the shim get distinct memfds, so there is no foreign writer — runs are
/// deterministic and the MSan-uninitialized / TSan-race false-positive classes
/// from cross-partition shared memory disappear. The head is pre-filled with
/// mode-driven bytes for `resource_name` so a reader of the region is driven by
/// the fuzz input (still private and, being written by us, "initialized" to MSan).
/// Pre-sized to [`FAKE_SHM_CAPACITY`] (sparse) so a later mmap succeeds without an
/// intervening ftruncate.
///
/// Returns -1 on failure; the caller then falls back to the real shm_open.
///
/// # Safety
///
/// Invokes libc syscalls directly (memfd_create, write, ftruncate, lseek). The
/// caller owns the returned fd and must close it.
pub unsafe fn create_fake_shm_fd(resource_name: &[u8]) -> i32 {
    let raw_name = b"govfuzz_fake_shm\0";
    let fd = libc::syscall(
        libc::SYS_memfd_create,
        raw_name.as_ptr() as *const libc::c_char,
        libc::MFD_CLOEXEC as libc::c_uint,
    ) as i32;
    if fd < 0 {
        return -1;
    }
    let mut buf = [0u8; FAKE_SHM_FILL];
    let n = fill_bytes(resource_name, &mut buf);
    let mut written = 0;
    while written < n {
        let w = libc::write(
            fd,
            buf[written..n].as_ptr() as *const libc::c_void,
            n - written,
        );
        if w <= 0 {
            break;
        }
        written += w as usize;
    }
    // Extend (sparse) so a wide mmap succeeds; bytes past the filled head are zero.
    let _ = libc::ftruncate(fd, FAKE_SHM_CAPACITY);
    let _ = libc::lseek(fd, 0, libc::SEEK_SET);
    fd
}

/// Fill an already-mapped region (e.g. a System V segment's private backing) with
/// mode-driven bytes for `resource_name`, up to `len`. A no-op in Empty mode
/// (region stays zero). Used so a target reading a virtualized SysV segment is
/// driven by the fuzz input.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes (it is the base of the caller's
/// just-`mmap`ed segment of that size).
pub unsafe fn fill_region(resource_name: &[u8], ptr: *mut u8, len: usize) {
    let cap = len.min(FAKE_SHM_FILL);
    let mut buf = [0u8; FAKE_SHM_FILL];
    let n = fill_bytes(resource_name, &mut buf[..cap]);
    if n > 0 {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, n.min(len));
    }
}

/// Bytes of mode-driven content pre-filled at the base of a fake MMIO window so
/// `mmap`-ed register reads near the device base return fuzz/rng/zero values.
const FAKE_MMIO_FILL: usize = 64 * 1024;
/// Sparse size of a fake MMIO window so a wide `mmap` of the device succeeds
/// (bytes past the filled head read as zero).
const FAKE_MMIO_CAPACITY: libc::off_t = 16 * 1024 * 1024;

/// Create a private memfd standing in for a memory-mapped device (#441). The
/// head is pre-filled with mode-driven bytes (Empty → zeros, Rng → pseudo-random,
/// FuzzDriven → the fuzz input) so a driver that `mmap`s the fd and reads device
/// registers gets fuzz-controlled values instead of touching real hardware, and
/// the unprivileged open of `/dev/mem` that would otherwise fail now succeeds.
///
/// Returns -1 on failure.
///
/// # Safety
///
/// Invokes libc syscalls directly (memfd_create, write, ftruncate, lseek). The
/// caller owns the returned fd and must close it.
pub unsafe fn create_fake_mmio_fd(resource_name: &[u8]) -> i32 {
    let raw_name = b"govfuzz_fake_mmio\0";
    let fd = libc::syscall(
        libc::SYS_memfd_create,
        raw_name.as_ptr() as *const libc::c_char,
        libc::MFD_CLOEXEC as libc::c_uint,
    ) as i32;
    if fd < 0 {
        return -1;
    }
    let mut buf = [0u8; FAKE_MMIO_FILL];
    let n = fill_bytes(resource_name, &mut buf);
    let mut written = 0;
    while written < n {
        let w = libc::write(
            fd,
            buf[written..n].as_ptr() as *const libc::c_void,
            n - written,
        );
        if w <= 0 {
            break;
        }
        written += w as usize;
    }
    // Extend (sparse) so a wide device mmap succeeds; reads past the filled head
    // return zero.
    let _ = libc::ftruncate(fd, FAKE_MMIO_CAPACITY);
    let _ = libc::lseek(fd, 0, libc::SEEK_SET);
    fd
}
