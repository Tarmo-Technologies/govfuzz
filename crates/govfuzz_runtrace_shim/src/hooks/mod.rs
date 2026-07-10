// SPDX-License-Identifier: Apache-2.0

//! Per-category hook modules. Each #[no_mangle] extern "C" fn in
//! these modules overrides the matching libc symbol when this
//! cdylib is loaded via LD_PRELOAD.

pub mod assertion;
pub mod cmplog;
pub mod dl;
pub mod dlsym;
pub mod env;
pub mod format;
pub mod fs;
pub mod identity;
pub mod mem;
pub mod mqueue;
pub mod net;
pub mod proc;
pub mod sql;
