<!-- SPDX-License-Identifier: Apache-2.0 -->

# RHEL 9 compatibility validation on Proxmox (2026-07-20)

> Follow-up (2026-07-21): the release baseline was subsequently lowered to
> glibc 2.17 and validated on an EL7 guest. See
> `2026-07-21-rhel7-proxmox.md`. The AlmaLinux 9 results below remain the
> original RHEL 9 validation record.

## Environment

- Proxmox node: `ms01`, PVE 9.1.6
- VM: `108` (`govfuzz-rhel9-test`), 4 vCPU, 3 GiB maximum / 2 GiB
  ballooned memory, 40 GiB disk, and 8 GiB temporary swap
- Guest: AlmaLinux 9.8, used because licensed RHEL media was not available on
  the Proxmox host
- Kernel: `5.14.0-611.54.3.el9_7.x86_64`
- glibc: 2.34
- SELinux: enforcing
- Toolchain: Rust 1.97.1, GCC 11.5.0, Clang 21.1.8

AlmaLinux is used here as the closest available RHEL-compatible guest. This run
validates the RHEL 9 userspace ABI and `dnf` behavior; it is not represented as
a licensed Red Hat certification run.

## Compatibility failure reproduced

The existing release-mode binary built on the Ubuntu 24.04 development host
failed immediately in the guest:

```text
/tmp/govfuzz-ubuntu-build: /lib64/libc.so.6: version `GLIBC_2.39' not found
```

This proved that adding only `dnf` package mappings would not make the shipped
binary usable on RHEL 9. At the time of this run, the release workflow was
changed to build GNU/Linux artifacts in an AlmaLinux 9 container; the follow-up
EL7 work lowered that baseline further.

## Results

1. `cargo build --release --workspace` completed in the guest in 3m36s.
2. The RHEL installer regression suite passed: 12 passed, 0 failed (the
   interactive TTY-only check skipped under the CI marker).
3. `scripts/package-offline-dist.sh --skip-build` produced and verified a
   signed binary-only distribution in the guest.
4. The packaged `install.sh` auto-detected `dnf`, installed the RHEL package
   names, verified and installed the content pack, and completed its C smoke
   target: 8 executions and 20 coverage edges.
5. The installed binary fuzzed the real miniz fixture: one ranked target built
   and fuzzed for 32 executions and 72 coverage edges, with no blocking
   dependencies.
6. The guest-built `govfuzz`, `govfuzz-daemon`, and runtrace shim all loaded on
   glibc 2.34. Their highest required symbol version was `GLIBC_2.34`.

The VM is retained on Proxmox for inspection and can be restarted by VM ID 108.
The installed validation artifact and reports are under:

```text
/home/govfuzz/govfuzz-install/
/home/govfuzz/govfuzz-smoke/auto/run.json
/home/govfuzz/miniz-smoke/auto/run.json
/home/govfuzz/rhel-dist/
```
