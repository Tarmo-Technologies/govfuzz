<!-- SPDX-License-Identifier: Apache-2.0 -->

# RHEL 7 compatibility validation on Proxmox (2026-07-21)

## Environment

- Proxmox node: `ms01`, PVE 9.1.6
- VM: `109`, CentOS Linux 7.9.2009, 64-bit x86
- Guest address during validation: `192.168.48.28`
- glibc: 2.17
- SELinux: enforcing
- Compiler used by GovFuzz: Red Hat Developer Toolset
  `llvm-toolset-7.0-clang` 7.0.1

CentOS 7.9 is the closest freely obtainable RHEL 7-compatible guest used for
this run because licensed RHEL 7 media was not available. The official CentOS
GenericCloud image was verified against its published SHA-256 checksum before
import. This validates the EL7 userspace ABI and package behavior; it is not a
Red Hat certification claim.

CentOS 7 is end-of-life, so its base and Software Collections repositories had
to be redirected to the CentOS vault. Packages retained their normal RPM
signature checks.

## Compatibility work validated

1. Linux release binaries were built in the pinned manylinux2014 image
   `quay.io/pypa/manylinux2014_x86_64@sha256:0d25b049964b2549b83384036abdff06789a8c0b1e9ff003ec80f0d531f79e50`.
2. The release ABI gate reported maximum required versions of `GLIBC_2.16` for
   `govfuzz` and `govfuzz-daemon`, and `GLIBC_2.14` for the runtrace shim. All
   are below the EL7 `GLIBC_2.17` ceiling.
3. The Bash 4.2-compatible offline installer detected EL7 and installed the
   signed Software Collections LLVM packages needed for sanitizer coverage.
4. The stock CentOS 7 Clang 3.4 was tested with every supported sanitizer
   coverage spelling and correctly rejected because it provides none. GovFuzz
   then found and activated `/opt/rh/llvm-toolset-7.0/root/usr` automatically.
5. The packaged content signature and SHA-256 manifest were verified before
   installation with SELinux still enforcing.

The final offline bundle was rebuilt after all source and test fixes, passed
the same ABI gate, and was checksum-verified, installed, content-verified, and
smoke-tested on VM 109:

```text
govfuzz-dist-rhel7-final-20260721.tar.gz
SHA256 d908f84876166b7e6cfb5ee3c0989c45f52411cea40f95148504b7f8fe115f0a
```

## Results

- The package's C post-install smoke target built and fuzzed: 8 executions and
  10 coverage edges.
- The final package found a planted C stack-buffer overflow after 89 executions,
  created a portable PoC capsule and tarball, and self-verified the capsule's
  `AddressSanitizer:stack-buffer-overflow` signature on EL7.
- A generated C++ fixture built and fuzzed: 16 executions and 12 coverage
  edges.
- miniz 3.1.2 at commit `77d0dce` was tested as a real project. Its
  top three targets all built and fuzzed, totaling 96 executions and 239
  coverage edges.
- The miniz run reported one reproducible LeakSanitizer finding in the selected
  target/harness path; it did not block compilation, execution, coverage, or
  EL7 compatibility.

The installed trees and retained reports are under:

```text
/home/govfuzz/govfuzz-install-el7-final/
/home/govfuzz/govfuzz-smoke-final/
/home/govfuzz/capsule-el7-final-work/
/home/govfuzz/govfuzz-install-el7/
/home/govfuzz/govfuzz-smoke/
/home/govfuzz/cpp-smoke/
/home/govfuzz/miniz-smoke/
```

VM 109 is retained on Proxmox for inspection and repeat runs.
