// SPDX-License-Identifier: Apache-2.0

//! Runtime-virtualisation layer: when the auto loop runs a faking
//! pass, these modules substitute fake fds / socket peers / dlopen
//! handles for the missing real resources so the target keeps
//! executing against a synthesised environment.

pub mod data;
pub mod dl_handle;
pub mod envcap;
pub mod fuzz_input;
pub mod memfd;
pub mod mode;
pub mod peer;
