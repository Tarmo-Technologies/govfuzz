<!-- SPDX-License-Identifier: Apache-2.0 -->

# Current Linux and Windows platform validation (2026-07-21)

This record extends the RHEL 7 compatibility work through the current RHEL,
Ubuntu LTS, Windows client, and Windows Server generations. The tested support
matrix is RHEL 7–10, Ubuntu 22.04/24.04/26.04 LTS, Windows 11 Enterprise 25H2,
Windows 11 Enterprise LTSC 2024 (24H2 codebase), and Windows Server
2019/2022/2025. Windows 10 and Server 2016 are outside this matrix because their
normal Microsoft support has ended.

The Linux tests used the published v0.2.18 release installers and the same
EL7-baseline artifacts delivered to users. Windows tests used the published
native MSVC release executables. Each behavioral smoke covered `--version`, the
daemon, `scan`, `auto --list-targets`, native C harness compilation, and a real
fuzz run whose JSON report had one `built_and_fuzzed` target. Linux sanitizer
runs also required ASan+UBSan success and a nonempty per-harness runtrace.

## Proxmox and official Red Hat validation

| Environment | VM / runtime | Security state | Native result |
|---|---|---|---|
| CentOS 7.9 (EL7-compatible) | Proxmox VM 109; kernel 3.10.0-1160.el7 | SELinux-enforcing guest from the retained EL7 validation | PASS: LLVM Toolset 7 auto-selection; 32 iterations without sanitizers; 16 with ASan+UBSan |
| AlmaLinux 8.10 | Proxmox VM 111; kernel 4.18.0-553.146.1.el8_10 | SELinux enforcing | PASS: install, ABI/load checks, scan, discovery, 32 iterations, ASan+UBSan, runtrace, and post-update reboot smoke |
| AlmaLinux 9.8 | Proxmox VM 108; kernel 5.14.0-687.26.1.el9_8 | SELinux enforcing | PASS: install, ABI/load checks, scan, discovery, 32 iterations, ASan+UBSan, and runtrace |
| AlmaLinux 10.2 | Proxmox VM 112; kernel 6.12.0-211.34.1.el10_2 | SELinux enforcing | PASS: install, ABI/load checks, scan, discovery, 32 iterations, ASan+UBSan, runtrace, and post-update reboot smoke |
| Red Hat UBI 10.2 | Official `registry.access.redhat.com/ubi10/ubi:10.2` userspace | Container isolation on the validation host | PASS: release installers plus native 32-iteration and 16-iteration ASan+UBSan fuzz runs |
| Ubuntu 26.04 LTS | Proxmox VM 113; kernel 7.0.0-28-generic | AppArmor enabled | PASS: install, ABI/load checks, scan, discovery, 32 iterations, ASan+UBSan, and runtrace |
| Windows 11 Enterprise 25H2 Evaluation | Proxmox VM 115; build 26200.6584 | UEFI Secure Boot and TPM 2.0 | PASS: CLI and daemon PowerShell installers, scan, discovery, LLVM 22 + VS 2022 native build, and 32-iteration fuzz run |
| Windows 11 Enterprise LTSC 2024 Evaluation | Proxmox VM 116; build 26100.1742 (24H2 codebase) | UEFI Secure Boot and TPM 2.0 | PASS: official hash-verified Microsoft evaluation media, CLI and daemon PowerShell installers, scan, discovery, LLVM 22 + VS 2022 native build, and 32-iteration fuzz run |
| Windows Server 2019 Standard Evaluation | Proxmox VM 114; build 17763 | Native x64 guest | PASS: CLI and daemon PowerShell installers over OpenSSH; scan, discovery, LLVM 22 + VS 2022 native build, and 32-iteration fuzz run |

Licensed RHEL installation media was not available. AlmaLinux guests therefore
provide full-system RHEL-compatible VM evidence, while Red Hat's official UBI
10.2 image provides an actual current RHEL 10.2 userspace check. This supports a
compatibility statement, not Red Hat certification.

## Continuous matrix

The CI workflow has persistent behavioral jobs for the release artifact on:

- AlmaLinux 8.10, 9.8, and 10.2 containers, in addition to the EL7 ABI build
  and retained CentOS 7.9 VM result;
- Ubuntu 22.04, 24.04, and 26.04 LTS runners; and
- Windows Server 2022 and 2025 runners using the native MSVC release pair.

The Windows jobs share `scripts/ci/windows-release-smoke.ps1`, so both lanes
must perform a real native C compile and fuzz rather than a startup-only smoke.

## Defects found and fixed

Clean-host validation found three distribution defects and one diagnostic bug:

1. Cargo-dist 0.31's generated preload-library installers applied `chmod` to a
   final path before moving the library from its temporary directory. Both
   Linux shim installers are now corrected and release-gated.
2. Cargo-dist's PowerShell `Expand-Archive` progress display attempted to read a
   console buffer in non-interactive Windows OpenSSH sessions. Both Windows
   installers now disable archive progress in that scope.
3. Minimal RHEL images can omit the external `xz` helper required by `.tar.xz`
   release archives. RHEL prerequisites now install it, and every generated
   Unix installer checks for it before downloading an archive.
4. Missing Windows C/C++ prerequisites incorrectly suggested `apt-get`, while
   Linux hints did not distinguish RHEL from Ubuntu. Windows diagnostics now
   name LLVM, VS 2022 Build Tools/Windows SDK, and GNU make; Linux diagnostics
   distinguish RHEL 7 LLVM Toolset 7, RHEL 8+ `dnf`, and Ubuntu `apt-get`.

The broader functional result remains the
[53-project post-update sweep](./2026-07-21-major-updates-sweep.md): 106 clean
and damaged project runs, 47/47 in-scope successes in both populations, followed
by the complete workspace regression suite.
