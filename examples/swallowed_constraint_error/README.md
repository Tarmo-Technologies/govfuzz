<!-- SPDX-License-Identifier: Apache-2.0 -->

# Swallowed Constraint Error

This fixture exercises the M17 cross-compilation acceptance path. `Pkg.Parse`
converts an input string with `Integer'Value` and swallows `Constraint_Error`,
which should produce the same GovFuzz finding when the generated harness runs
as a host binary or as an `aarch64-linux-gnu` binary through qemu-user.

The acceptance test uses user-installed tools and skips when the host does not
provide `gprbuild`, `aarch64-linux-gnu-gprbuild`, `aarch64-linux-gnu-gnat`, and
`qemu-aarch64` or `qemu-aarch64-static`.
