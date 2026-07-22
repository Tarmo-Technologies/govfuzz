<!-- SPDX-License-Identifier: Apache-2.0 -->
# Installing govfuzz

govfuzz is a Rust workspace. Building it also produces the runtime
virtualisation shim (`libgovfuzz_runtrace_shim.so`) and the build-time compiler
interception shim (`libgovfuzz_cc_intercept.so`) next to the binaries, where
`govfuzz auto` locates them automatically.

## From source (recommended)

Prerequisites:

- **Rust** stable toolchain, 1.83 or newer (pinned via `rust-toolchain.toml`, so
  `rustup` selects it for you).
- **`make`** and **`clang`/`clang++`** with SanitizerCoverage plus ASan/UBSan
  support — required to build and fuzz C/C++ with the built-in engine.

```sh
git clone https://github.com/Tarmo-Technologies/govfuzz.git
cd govfuzz
cargo build --release --workspace
./target/release/govfuzz --help
```

The binaries land in `target/release/` (`govfuzz`, `govfuzz-daemon`) alongside
`libgovfuzz_runtrace_shim.so` and `libgovfuzz_cc_intercept.so`. Put `govfuzz` on
your `PATH`, or `cargo install --path crates/cli` (then also build the shims with
`cargo build --release -p govfuzz_runtrace_shim -p govfuzz_cc_intercept` and set
`GOVFUZZ_RUNTRACE_SHIM` / `GOVFUZZ_CC_INTERCEPT` to their paths — `cargo install`
does not stage them beside the binary).

### Supported OS matrices

The published GNU/Linux release target is x86_64 and supports RHEL 7, 8, 9, and 10.
“Supported” here means that the release binaries are held to the EL7 glibc 2.17
ABI, the installer handles the applicable `yum`/`dnf` family, and GovFuzz can
select a compiler with the required sanitizer-coverage capabilities. It is not
a Red Hat certification claim.

| Version | Release status | Package manager | C/C++ compiler | Validation evidence |
|---|---|---|---|---|
| RHEL 7 | Supported by the prebuilt x86_64 release | `yum` | Software Collections `llvm-toolset-7.0-clang`; stock Clang 3.4 is insufficient | CentOS 7.9 EL7-compatible Proxmox guest, glibc 2.17, SELinux enforcing |
| RHEL 8 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 8.10 RHEL-compatible Proxmox guest, SELinux enforcing |
| RHEL 9 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 9.8 RHEL-compatible Proxmox guest, SELinux enforcing |
| RHEL 10 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 10.2 RHEL-compatible Proxmox guest, SELinux enforcing |

The guest records use freely available, binary-compatible distributions because
licensed Red Hat media was unavailable. See the
[EL7 validation record](https://github.com/Tarmo-Technologies/govfuzz/blob/main/docs/validation/2026-07-21-rhel7-proxmox.md)
and
[EL9 validation record](https://github.com/Tarmo-Technologies/govfuzz/blob/main/docs/validation/2026-07-20-rhel9-proxmox.md)
as well as the
[current-platform validation record](https://github.com/Tarmo-Technologies/govfuzz/blob/main/docs/validation/2026-07-21-current-platform-matrix.md)
for the exact VMs and results. Other architectures can be built from source,
but they are not covered by this x86_64 release claim.

The tested Ubuntu and Windows matrix is deliberately explicit; “latest” does
not silently float to an untested future release:

| Family | Supported x86_64 versions | Notes |
|---|---|---|
| Ubuntu LTS | 22.04, 24.04, 26.04 | The same EL7-baseline Linux artifact is scan/build/fuzz tested on every listed LTS. |
| Windows client | Windows 11 Enterprise 25H2; Windows 11 Enterprise LTSC 2024 (24H2 codebase) | Native `x86_64-pc-windows-msvc` CLI and daemon; C/C++ fuzzing also needs LLVM, VS Build Tools/Windows SDK, and GNU make. |
| Windows Server | Windows Server 2019, Windows Server 2022, Windows Server 2025 | Windows Server 2019 is the oldest supported Windows baseline; Windows Server 2022 and Windows Server 2025 are persistent CI environments. |

Windows 10 and Windows Server 2016 are outside this tested support matrix. See
[Running govfuzz on Windows](./windows.md) for setup and native-Windows feature
limits.

### Per-language toolchains

govfuzz fuzzes sixteen languages; each lane needs its own toolchain, installed
only if you fuzz that language (a target whose toolchain is absent skips
cleanly). On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y make clang llvm                 # C/C++ (required to build/fuzz)
sudo apt-get install -y gnat gprbuild                   # Ada
sudo apt-get install -y default-jdk maven gradle        # Java
sudo apt-get install -y python3                         # Python (3.12+ for sys.monitoring coverage)
sudo apt-get install -y perl                            # Perl
sudo apt-get install -y golang-go                       # Go
rustup toolchain install nightly                        # Rust (sancov + ASan staticlib)
sudo apt-get install -y gfortran                        # Fortran
sudo apt-get install -y gnucobol                        # COBOL (GnuCOBOL cobc)
sudo apt-get install -y nodejs npm                      # JavaScript / TypeScript (TS via esbuild)
sudo apt-get install -y ruby                            # Ruby
sudo apt-get install -y lua5.4                          # Lua
sudo apt-get install -y php-cli                         # PHP
# C#: install a .NET 8 SDK, then stage the instrumentation CLI (and its NuGet package offline if needed)
dotnet tool install --global SharpFuzz.CommandLine
sudo apt-get install -y afl++                           # optional: AFL++ engine (C/C++ only)
```

On RHEL 8, 9, or 10 and compatible distributions (AlmaLinux/Rocky Linux), the base
and AppStream repositories provide the core build and most language toolchains:

```sh
sudo dnf install -y curl tar xz                         # release installer prerequisites
sudo dnf install -y gcc gcc-c++ make clang llvm lld    # source build + C/C++ fuzzing
sudo dnf install -y java-17-openjdk-devel maven        # Java
sudo dnf install -y python3 perl golang                # Python / Perl / Go
sudo dnf install -y gcc-gfortran                       # Fortran
sudo dnf install -y nodejs npm ruby lua php-cli        # interpreter lanes
rustup toolchain install nightly                       # Rust fuzzing lane
```

On RHEL 7, the released GovFuzz binaries run against the system glibc 2.17.
The stock Clang 3.4 cannot instrument GovFuzz harnesses, so enable the Red Hat
Software Collections repository approved for the host and install LLVM 7.0:

> The lightweight `govfuzz-installer.sh` release asset installs only the CLI.
> It does not enable repositories, install the packages below, or install the
> separate Linux runtime shims. Prepare the host first, then run the component
> installers shown under [Prebuilt release binaries](#prebuilt-release-binaries).

```sh
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
sudo yum install -y curl tar xz gcc gcc-c++ make \
  llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
```

GovFuzz discovers and activates `/opt/rh/llvm-toolset-7.0/root/usr`
automatically; an interactive `scl enable` shell is not required.

RHEL 7 hosts need an active vendor/organization package source, and CentOS 7
test hosts need an archive mirror because the original mirrorlist is retired.
The stock EL7 linker is too old to link the current preload shim from source;
use the prebuilt release, or reproduce the release build in the pinned
manylinux2014 image from `.github/workflows/release.yml`.

GNAT/GPRbuild, GnuCOBOL, Gradle, AFL++, Wine/mingw, and foreign-architecture
cross compilers are not consistently present in the standard RHEL repositories.
Enable an organization-approved supplemental repository or stage those tools
separately when their lanes are needed. The binary distribution installer uses
`dnf` automatically on RHEL and installs every available selected dependency
without allowing an absent optional package to block the core C/C++ setup.

The full per-lane matrix lives in
[offline-deployment.md](./offline-deployment.md#toolchains-on-the-offline-host).
For Windows-native cross-fuzzing (mingw + wine) and foreign-arch fuzzing
(qemu-user), see [cross-compilation.md](./cross-compilation.md).

### Optional LLM and agent integration

No model, API key, or network connection is required for GovFuzz. Optional
assistance needs one of the following:

- the `govfuzz-daemon` release component plus an MCP-capable Codex or Claude
  host for the recommended current-session workflow;
- an already installed and authenticated `codex` or `claude` executable for a
  separate ephemeral CLI-provider request;
- an OpenAI or Anthropic API credential injected through an environment
  variable and an explicit model id; or
- a locally served OpenAI-compatible model endpoint.

Run `govfuzz llm status --json` to inspect non-secret availability and
`govfuzz llm test --provider <name>` to make a live connection check. The status
command does not prove CLI authentication and does not print credential values.
See [LLM Assistance](./llm.md) before registering MCP or transmitting source and
findings to any provider.

## Prebuilt release binaries

GNU/Linux release artifacts are built in a pinned manylinux2014 / CentOS 7
userspace. CI rejects an artifact that requires a symbol newer than glibc 2.17,
so the published binaries are compatible with RHEL 7, 8, 9, and 10. A binary built
locally on a newer distribution may not be portable to RHEL; use the published
artifact or the same pinned build image if the loader reports
`GLIBC_2.xx not found`.

GitHub releases ship per-component archives and shell installers (one component
at a time). You do **not** need every asset for every install.

The CLI archive carries every harness-runtime source tree. The CLI executable
also embeds the same sources and stages a private copy automatically when it was
installed by the shell or PowerShell installer, so prebuilt installs do not
need a govfuzz source checkout.

### Choose release assets by task

An installer downloads and installs its matching archive. Use the installer for
a connected, conventional installation; use the archive plus its `.sha256`
sidecar for manual or offline installation. Do not download both forms of the
same component.

| Task | Required assets | Optional additions |
|---|---|---|
| Windows CLI | `govfuzz-installer.ps1`, or `govfuzz-x86_64-pc-windows-msvc.zip` and its sidecar | `govfuzz-daemon-installer.ps1` or the daemon ZIP only for IDE/JSON-RPC/MCP use |
| Basic Linux CLI, scan, build, and fuzz | `govfuzz-installer.sh`, or `govfuzz-x86_64-unknown-linux-gnu.tar.xz` and its sidecar | Add the two Linux shims below for full runtime behavior and complex C/C++ build recovery |
| Full Linux `govfuzz auto` | The Linux CLI plus `govfuzz_runtrace_shim-installer.sh` (or its archive and sidecar) | Add `govfuzz_cc_intercept` when testing C/C++ projects with real build systems |
| Complex C/C++ `--probe-build` / `--build-command` recovery | Linux CLI plus `govfuzz_cc_intercept-installer.sh` (or its archive and sidecar) | Add the runtrace shim for runtime audit/fake-resource coverage too |
| Linux IDE/JSON-RPC/MCP service | The required Linux CLI/shims for the intended workload, plus `govfuzz-daemon-installer.sh` or its archive | None |
| Source audit or rebuild | `source.tar.gz` and `source.tar.gz.sha256` | Prebuilt runtime assets are not required unless you also want to run them |
| Automated release processing | `dist-manifest.json`; use `sha256.sum` to verify all archives or the matching `*.sha256` file for one archive | None |

What each optional component changes:

- `govfuzz_runtrace_shim` is Linux-only. It enables runtime environment auditing,
  behavioral/taint oracles, and fake files, sockets, and environment resources.
  Without it, GovFuzz still scans, builds, and fuzzes, but warns and runs without
  those runtime features.
- `govfuzz_cc_intercept` is Linux-only. It lets C/C++ build recovery observe
  compilers launched by absolute path or through `posix_spawn`. Most direct
  harness builds do not need it; complex `--probe-build` and `--build-command`
  workflows often do.
- `govfuzz-daemon` provides JSON-RPC and read-only MCP. The CLI does not use or
  require the daemon for ordinary terminal runs.
- `source.tar.gz`, `dist-manifest.json`, and checksum files are not executable
  components. Do not install them into `PATH`.

In short: the recommended full Linux set is the CLI plus both shims. The normal
Windows set is the CLI alone, with the daemon added only for IDE/MCP use. Windows
users should ignore the two Linux-only shim assets.

### Connected Linux installation

```sh
VERSION=<latest release tag>
BASE="https://github.com/Tarmo-Technologies/govfuzz/releases/download/${VERSION}"

curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz_runtrace_shim-installer.sh" | sh
# Optional, recommended for C/C++ build recovery on real projects:
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz_cc_intercept-installer.sh" | sh
```

For archive installs, verify the `.sha256` sidecars, extract the component
archives, and keep the shim archives beside the `govfuzz-*` directory or set
`GOVFUZZ_RUNTRACE_SHIM` / `GOVFUZZ_CC_INTERCEPT` to the extracted library paths.

## Native Windows release or build

Releases include `govfuzz-x86_64-pc-windows-msvc.zip`,
`govfuzz-daemon-x86_64-pc-windows-msvc.zip`, their SHA-256 sidecars, and native
PowerShell installers. For example:

```powershell
$Version = "v0.2.18"
irm "https://github.com/Tarmo-Technologies/govfuzz/releases/download/$Version/govfuzz-installer.ps1" | iex
govfuzz.exe --version
```

The release executables do not require Rust. LLVM, Visual Studio Build Tools,
and GNU make are still required to compile and fuzz native C/C++ targets; see
[windows.md](./windows.md).

To build from source instead:

```sh
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p govfuzz
# -> target/x86_64-pc-windows-msvc/release/govfuzz.exe
```

`govfuzz.exe` runs the full pipeline on Windows — discovery, clang harness builds
(edge coverage + cmplog + ASan), coverage-guided fuzzing, crash detection —
including Visual Studio solutions (`.sln`/`.vcxproj`) via `--probe-build`. See
[windows.md](./windows.md) for the full guide.

## Offline / air-gapped install

govfuzz runs with no network access and never auto-updates. To install or update
on a disconnected machine, build a binary-only offline tarball
(`scripts/package-offline-dist.sh`), transfer published/source-built binaries, or
transfer the source and build on the offline host — plus stage the harness
build/fuzz toolchains and signed content packs.
[offline-deployment.md](./offline-deployment.md) is the full operational guide:
the binary-only package flow, the build-vs-transfer decision, exactly which
artifacts to move, glibc/arch matching for the runtrace shim, the `cargo vendor`
offline-build flow, toolchain staging, staging harness dependencies across the
air gap (`--deps-only` / `--install-deps`), and rules/CVE/corpus pack updates.

## Verify the install

Run `auto` against a source tree that ships with the repo. The C example needs
only `clang`; the Ada example also needs the optional GNAT/GPRbuild toolchain.
`--per-target-time` is the **total** per-target fuzz budget in **seconds**.

```sh
# Real C library (miniz)
govfuzz auto tests/fixtures/build_recovery/fixtures/miniz --work-dir /tmp/gf-miniz --per-target-time 10

# Ada example (needs the Ada toolchain)
govfuzz auto examples/swallowed_constraint_error --work-dir /tmp/gf-ada --per-target-time 10
```

When the sweep finishes it prints a summary — duration, outcome breakdown, file/
language counts, findings, executions, throughput, coverage edges, and where every
output landed — and writes it to `<work-dir>/auto/summary.txt`. Detailed reports
are at `<work-dir>/auto/run.md` and `run.json`. If the summary ends in a
`⚠ WARNING: N target(s) fuzzed STUB-ONLY` line, those targets fuzzed blind stubs
rather than real library code, so a clean result there is a **false clean** —
inspect the `stub_execution` block in `run.json` before trusting it.

See [auto.md](./auto.md) for the full `govfuzz auto` reference, including scaling
to large trees, force-fuzz mode, and static-analysis integration.
