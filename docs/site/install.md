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
- **`make`** and **`clang`/`clang++`** with libFuzzer sanitizer support
  (`-fsanitize=fuzzer,address,undefined`) — required to build and fuzz C/C++.

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

### Per-language toolchains

govfuzz fuzzes eight languages; each lane needs its own toolchain, installed only
if you fuzz that language (a target whose toolchain is absent skips cleanly). On
Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y make clang llvm                 # C/C++ (required to build/fuzz)
sudo apt-get install -y gnat gprbuild                   # Ada
sudo apt-get install -y default-jdk maven gradle        # Java
sudo apt-get install -y python3                         # Python (3.12+ for sys.monitoring coverage)
sudo apt-get install -y perl                            # Perl
sudo apt-get install -y golang-go                       # Go
rustup toolchain install nightly                        # Rust (sancov + ASan staticlib)
sudo apt-get install -y afl++                           # optional: AFL++ engine (C/C++ only)
```

The full per-lane matrix lives in
[offline-deployment.md](./offline-deployment.md#toolchains-on-the-offline-host).
For Windows-native cross-fuzzing (mingw + wine) and foreign-arch fuzzing
(qemu-user), see [cross-compilation.md](./cross-compilation.md).

## Prebuilt release binaries

GitHub releases ship per-component archives and shell installers (one component
at a time). You do **not** need every asset for every install:

| Asset | Purpose | Needed when |
|---|---|---|
| `govfuzz-*` | Main CLI | Always |
| `govfuzz_runtrace_shim-*` | Linux `LD_PRELOAD` runtime virtualisation shim | Full `govfuzz auto` coverage |
| `govfuzz_cc_intercept-*` | Linux build-time compiler interception shim | C/C++ `--probe-build` / `--build-command` recovery |
| `govfuzz-daemon-*` | JSON-RPC daemon | IDE/editor integrations only |
| `source.tar.gz` | Release source snapshot | Rebuilding or auditing source |
| `dist-manifest.json`, `sha256.sum`, `*.sha256` | Release metadata and integrity checks | Automation / checksum verification |

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

## Native Windows build

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p govfuzz
# -> target/x86_64-pc-windows-gnu/release/govfuzz.exe
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
