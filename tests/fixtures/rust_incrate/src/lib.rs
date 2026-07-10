// SPDX-License-Identifier: Apache-2.0
//
// §27.10 in-crate-build fixture. The parser lives in a PRIVATE module
// (`mod internal;`, not `pub mod`, and not re-exported), so `internal::Parser` is
// `pub` yet unreachable from an external dependent crate (E0603). An external
// staticlib harness can only see this crate's `pub` API (`version`); only the
// IN-CRATE build mode — which injects the harness as a module of a copy of this
// crate — can reach `crate::internal::Parser` to fuzz it.

mod internal;

/// A public free function (reachable externally) so the crate has a normal public
/// surface alongside the private-module parser.
pub fn version() -> u32 {
    1
}
