// SPDX-License-Identifier: Apache-2.0

//! Device control plane.
//!
//! The MMIO fake (#441) redirects a device open to a private memfd, so a
//! driver's register reads hit fuzz-controlled memory. But a memfd answers
//! `ioctl` with `ENOTTY`, and real Linux drivers and userspace HALs — V4L2, UIO,
//! i2c `I2C_RDWR`, SPI `SPI_IOC_MESSAGE`, hidraw, CAN — negotiate capabilities
//! by ioctl BEFORE they touch a register. The negotiation failed, the driver
//! bailed out, and the register window the fake had prepared was never read.
//! Half a device is not a device.
//!
//! What makes this safe to answer is that Linux encodes the direction and the
//! payload SIZE in the request number itself:
//!
//!     bits 30..32 direction (none / write / read)
//!     bits 16..30 payload size
//!
//! So a read-direction request states exactly how many bytes it expects, and the
//! fake can fill precisely that many. Filling an untyped `void *` by guesswork
//! would be a buffer overflow the HARNESS commits — the same class of
//! manufactured finding the decoder contracts exist to prevent — so a request
//! that does not state a size gets a bare success and no write.
//!
//! Only a FAKING pass answers, and only after the real `ioctl` has declined: a
//! device that genuinely implements the request keeps its real behaviour.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

static REAL_IOCTL: ResolvedFn = ResolvedFn::new(b"ioctl\0");

/// Direction is the top two bits of the request; size is the 14 below it.
/// Matches asm-generic's `_IOC_*` layout, which every mainstream Linux arch
/// uses (the exceptions — powerpc/mips/sparc — reorder the direction bits, so
/// there the size simply reads as 0 and the hook degrades to a bare success).
const IOC_DIRSHIFT: u32 = 30;
const IOC_SIZESHIFT: u32 = 16;
const IOC_SIZEMASK: u32 = 0x3fff;
const IOC_READ: u32 = 2;

fn ioc_dir(request: u32) -> u32 {
    (request >> IOC_DIRSHIFT) & 0x3
}

fn ioc_size(request: u32) -> usize {
    ((request >> IOC_SIZESHIFT) & IOC_SIZEMASK) as usize
}

/// Whether the caller is asking the driver to WRITE into its buffer, and how
/// much. `None` when the request states no readable payload, in which case
/// nothing may be written.
fn readable_payload(request: u32) -> Option<usize> {
    let size = ioc_size(request);
    (ioc_dir(request) & IOC_READ != 0 && size > 0).then_some(size)
}

fn log_ioctl(request: libc::c_ulong, filled: usize, faked: bool) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"ioctl");
        b.field_i64(b"req", request as i64);
        b.field_i64(b"fill", filled as i64);
        b.field_i64(b"fake", i64::from(faked));
        b.emit();
    }
}

pub struct Ioctl;

impl FakeResource for Ioctl {
    fn name(&self) -> &'static str {
        "ioctl"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"ioctl\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "answer device capability ioctls so a driver reaches the virtualized register window"
    }
}

#[no_mangle]
pub unsafe extern "C" fn ioctl(
    fd: libc::c_int,
    request: libc::c_ulong,
    arg: *mut libc::c_void,
) -> libc::c_int {
    let real = REAL_IOCTL.ptr() as *const ();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(libc::c_int, libc::c_ulong, *mut libc::c_void) -> libc::c_int =
        std::mem::transmute(real);
    let result = real(fd, request, arg);
    if result >= 0 {
        // A device that really implements this request keeps its real answer.
        return result;
    }
    if !crate::fakes::mode::current().is_faking() {
        return result;
    }
    // The real call declined. Under a faking pass the fd is typically the
    // memfd standing in for a device, which answers every ioctl with ENOTTY —
    // so the driver's capability negotiation would fail before it ever reads a
    // register.
    let errno = *libc::__errno_location();
    if errno != libc::ENOTTY && errno != libc::EINVAL {
        return result;
    }
    // Answer ONLY a request that states what it wants back. Two reasons, and
    // the second is the load-bearing one.
    //
    // The payload size is what bounds the fill, so without it there is nothing
    // safe to write. And a request with no _IOC-encoded readable payload is
    // usually not a device query at all but a legacy terminal ioctl: `isatty`
    // asks TCGETS (0x5401, no encoded direction) and treats success as "this is
    // a tty". Answering that made EVERY descriptor look like a terminal, which
    // changed stdio buffering and broke the harness's own framed protocol —
    // measured as targets that built and then were never entered.
    let Some(size) = readable_payload(request as u32) else {
        return result;
    };
    if arg.is_null() {
        return result;
    }
    // Exactly the byte count the request itself declares — never a guess at the
    // shape of an untyped `void *`.
    crate::fakes::memfd::fill_region(b"ioctl", arg as *mut u8, size);
    log_ioctl(request, size, true);
    *libc::__errno_location() = 0;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a request the way Linux's `_IOR`/`_IOW` macros do.
    fn ioc(dir: u32, size: usize) -> u32 {
        (dir << IOC_DIRSHIFT) | ((size as u32 & IOC_SIZEMASK) << IOC_SIZESHIFT)
    }

    #[test]
    fn a_read_request_declares_exactly_how_much_may_be_written() {
        // The size comes from the request itself, so the fill can never run past
        // the caller's buffer — writing by guesswork would be an overflow the
        // shim commits on the target's behalf.
        assert_eq!(readable_payload(ioc(IOC_READ, 64)), Some(64));
        assert_eq!(readable_payload(ioc(IOC_READ | 1, 16)), Some(16));
    }

    #[test]
    fn nothing_is_written_without_a_stated_readable_payload() {
        // Write-only and size-less requests get a bare success: the driver's
        // negotiation proceeds, but no byte of the caller's memory is touched.
        assert_eq!(readable_payload(ioc(1, 64)), None, "write-only direction");
        assert_eq!(readable_payload(ioc(0, 64)), None, "no direction");
        assert_eq!(readable_payload(ioc(IOC_READ, 0)), None, "no size");
    }

    #[test]
    fn a_legacy_terminal_ioctl_is_never_answered() {
        // TCGETS is 0x5401: a legacy number with no _IOC-encoded direction, so
        // it declares no readable payload. `isatty` asks it and reads success as
        // "this is a tty"; answering it made every descriptor look like a
        // terminal, changed stdio buffering, and broke the harness's framed
        // protocol — targets built and were then never entered.
        assert_eq!(readable_payload(0x5401), None);
        assert_eq!(readable_payload(0x5402), None, "TCSETS");
        assert_eq!(readable_payload(0x5413), None, "TIOCGWINSZ");
    }
}
