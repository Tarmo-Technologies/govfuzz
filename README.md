# govfuzz

<div align="center">
  <em><strong>THE POINT-AND-CLICK FUZZER.</strong></em>
  <br><br>
  <a href="https://github.com/Tarmo-Technologies/govfuzz/security/code-scanning"><img src="https://github.com/Tarmo-Technologies/govfuzz/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.83%2B-blue" alt="Rust 1.83+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License: Apache-2.0"></a>
</div>

<p align="center">
An automated fuzzer and harness generator for Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP —
including the legacy language versions and hard-to-build codebases common in government and
military systems. Point it at a source tree; it finds the fuzzable functions, writes the
harnesses, recovers the build, and fuzzes — no test harness and no working build required.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#resource-requirements">Resources</a> ·
  <a href="#why-govfuzz">Why govfuzz?</a> ·
  <a href="#what-it-does">What It Does</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

## Quick Start

Build from source (Rust 1.83+, plus `make` + `clang` for the C/C++ lane):

```sh
git clone https://github.com/Tarmo-Technologies/govfuzz.git && cd govfuzz
cargo build --release --workspace
```

Point `auto` at a source tree — including code that does not build:

```sh
./target/release/govfuzz auto path/to/src --work-dir govfuzz_work --per-target-time 60
```

That discovers and ranks fuzzable functions, generates typed harnesses and stubs, recovers the
build context (`compile_commands.json`, CMake/Meson/Ninja/Visual Studio, or any
`--build-command`), fuzzes each target with a coverage-guided engine, and writes findings
(JSON/Markdown/SARIF/JUnit/CSV) under `govfuzz_work/auto/`.

### Resume an interrupted `auto` campaign

`govfuzz auto` checkpoints every completed target atomically. After a process
kill, power loss, or reboot, repeat the original command with the same source
tree and `--work-dir`, adding `--resume`:

```sh
./target/release/govfuzz auto path/to/src \
  --work-dir govfuzz_work \
  --per-target-time 60 \
  --resume
```

Use the same campaign options as the original run. Completed targets are loaded
from `harnesses/<id>/result.json`, included in the new report, and skipped; the
first target that did not finish is retried, followed by the remaining targets.
Existing findings and persisted corpus data remain on disk. Resume is
target-granular: only atomically completed result markers are reused, and an
interrupted target restarts its attempt rather than continuing the exact
mutation, elapsed-time budget, or in-memory fuzzer state.

**What a resume reuses, and what invalidates it.** Completed results are reused
only when BOTH identities are unchanged:

- **Source identity** — the content of every targetable source file plus the
  directory filter (the discovery cache). Editing, adding, or removing source, or
  changing the filter, is a discovery-cache miss and re-attempts all targets.
- **Build context** — the content of every `compile_commands.json`, GNAT project
  (`.gpr`), and IDL (`.idl`) under the tree, plus the harness-affecting options
  (the selected `--project`, decoder limits, stubbing policy, engines/passes, and
  sanitizer mode). If any of these change, the prior results were built under a
  different context and are re-attempted.

Editing documentation (README, comments in non-source files) changes neither
identity and does not invalidate a resume. A work directory written by an older
GovFuzz that predates the build-context fingerprint is treated conservatively as
changed and re-attempted. Do not combine `--resume` with `--fresh-discovery` or
`--no-discovery-cache`; a discovery-cache miss deliberately re-attempts all
targets rather than trusting stale results, and a compatible GovFuzz build is
required.

See the [installation guide](docs/site/install.md) for prebuilt binaries, per-language
toolchains, offline/air-gapped install, and Windows.

### Which release files do I need?

Linux has two complete installation styles. The all-in-one `govfuzz-dist-*.tar.gz`
contains `install.sh`, the CLI, daemon, both Linux shims, harness runtimes, and a
signed content pack. Every full bundle also contains `INSTALL.md`, `LICENSE`,
`README.md`, and `RELEASE_NOTES.md`. The component installers/archives let you
install only selected pieces. An individual component installer downloads its
matching archive automatically, so choose the installer **or** that archive—not
both.

| What you want to do | Install or download |
|---|---|
| Install complete GovFuzz on Linux with one `install.sh` | `govfuzz-dist-v0.2.19-x86_64-unknown-linux-gnu.tar.gz` plus its `.sha256` file |
| Run the CLI on Windows | `govfuzz-installer.ps1`, or `govfuzz-x86_64-pc-windows-msvc.zip` plus its `.sha256` file for a manual/offline install |
| Run basic CLI workflows on Linux | `govfuzz-installer.sh`, or `govfuzz-x86_64-unknown-linux-gnu.tar.xz` plus its `.sha256` file |
| Get the full Linux `govfuzz auto` runtime audit and fake-resource support | Add `govfuzz_runtrace_shim-installer.sh`, or its matching `govfuzz_runtrace_shim-*.tar.xz` archive |
| Recover complex C/C++ builds that use `--probe-build` or `--build-command` | Add `govfuzz_cc_intercept-installer.sh`, or its matching `govfuzz_cc_intercept-*.tar.xz` archive |
| Use the IDE, JSON-RPC, or read-only MCP service | Add the OS-appropriate `govfuzz-daemon-installer.sh` / `.ps1`, or the matching daemon archive |
| Audit or rebuild the release source | `source.tar.gz` plus `source.tar.gz.sha256`; this is not needed to run a prebuilt release |
| Automate or verify downloads | The archive's `*.sha256` sidecar, or `sha256.sum` for all archives; `dist-manifest.json` is machine-readable component-release metadata |

For a normal **full Linux installation**, use the all-in-one bundle, or manually
co-locate `govfuzz`, `libgovfuzz_runtrace_shim.so`, and
`libgovfuzz_cc_intercept.so`. For a normal **Windows CLI installation**, install
only `govfuzz`; add `govfuzz-daemon` only for IDE/MCP use. The two shims are
Linux-only and should not be downloaded on Windows. Every component archive now
contains `INSTALL.md`; see [INSTALL.md](INSTALL.md) for exact `install.sh` and
manual co-location commands.

#### Complete Linux install with `install.sh`

```sh
VERSION=v0.2.19
BASE="https://github.com/Tarmo-Technologies/govfuzz/releases/download/${VERSION}"
ARCHIVE="govfuzz-dist-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sha256"
sha256sum -c "$ARCHIVE.sha256"
tar xzf "$ARCHIVE"
cd "${ARCHIVE%.tar.gz}"
./install.sh
```

The installer prompts for language toolchains, targets, fuzzers, and optional
extras. Run `./install.sh --help` for non-interactive, custom-prefix, offline,
and smoke-test controls.

#### Manual Linux component co-location

After verifying and extracting the three matching Linux `.tar.xz` archives,
copy both shims beside the CLI:

```sh
CLI_DIR=govfuzz-x86_64-unknown-linux-gnu

install -m 0755 \
  govfuzz_runtrace_shim-x86_64-unknown-linux-gnu/libgovfuzz_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  govfuzz_cc_intercept-x86_64-unknown-linux-gnu/libgovfuzz_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/govfuzz" --version
```

Run from that directory or copy it intact to a permanent prefix. If the shims
must remain elsewhere, set `GOVFUZZ_RUNTRACE_SHIM` and
`GOVFUZZ_CC_INTERCEPT` to their absolute paths. The complete download,
checksum, optional-daemon, and user-local prefix commands are in
[INSTALL.md](INSTALL.md).

### Supported release platforms

Releases publish the CLI and daemon for **64-bit Windows** and **64-bit
GNU/Linux**. The supported and continuously exercised release matrix is:

| Family | Supported versions | Validation |
|---|---|---|
| RHEL | 7, 8, 9, and 10 | EL7 ABI gate plus native C scan/build/fuzz runs on CentOS 7.9 and AlmaLinux 8.10, 9.8, and 10.2 |
| Ubuntu LTS | 22.04, 24.04, and 26.04 | Native release-binary scan/build/fuzz jobs on every listed LTS |
| Windows x64 | Windows 11 Enterprise 25H2; Windows 11 Enterprise LTSC 2024 (24H2 codebase); Windows Server 2019, Windows Server 2022, and Windows Server 2025 | Native MSVC binaries plus real C scan/build/fuzz runs |

The Linux artifact is built in a pinned manylinux2014 environment and
CI-enforced to require no newer than glibc 2.17. RHEL-compatible guests are used
when licensed Red Hat media is unavailable; this is a compatibility claim, not
Red Hat certification. RHEL 7 needs Software Collections LLVM 7.0 for the C/C++
fuzzing lane because its stock Clang 3.4 lacks the required SanitizerCoverage;
GovFuzz detects and activates that toolset automatically. See the
[installation guide](docs/site/install.md) for the full OS matrices and
prerequisites.

#### RHEL 7 quick install

The lightweight GitHub Release installer installs the GovFuzz executable only:
it does not enable Red Hat repositories, install compiler packages, or install
the Linux preload shims. For C/C++ fuzzing on RHEL 7, prepare the host first:

```sh
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
sudo yum install -y curl tar xz gcc gcc-c++ make \
  llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
```

Then use the all-in-one bundle above. It installs the CLI, daemon, both shims,
harness runtimes, and signed content together. The separate component
installers remain available when you deliberately want a smaller install:

```sh
VERSION=v0.2.19
BASE="https://github.com/Tarmo-Technologies/govfuzz/releases/download/${VERSION}"

curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz_runtrace_shim-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/govfuzz_cc_intercept-installer.sh" | sh
```

GovFuzz discovers and activates LLVM Toolset 7 automatically; no interactive
`scl enable` shell is needed. Other language lanes need their corresponding
toolchains from an organization-approved repository or offline package mirror.

#### Windows 11 / Windows Server quick install

The PowerShell release installers install the native x64 CLI and daemon only.
For C/C++ fuzzing on Windows 11 Enterprise 25H2, Windows 11 Enterprise LTSC
2024, Windows Server 2019, Windows Server 2022, or Windows Server 2025, first
install LLVM, VS 2022 Build Tools/Windows SDK, and GNU make from
an elevated PowerShell. One Chocolatey-based setup is:

```powershell
choco install llvm make visualstudio2022buildtools `
  visualstudio2022-workload-vctools -y

$Version = "v0.2.19"
$Base = "https://github.com/Tarmo-Technologies/govfuzz/releases/download/$Version"
irm "$Base/govfuzz-installer.ps1" | iex
irm "$Base/govfuzz-daemon-installer.ps1" | iex       # optional: RPC/MCP service
```

Start a new **x64 Developer PowerShell for VS 2022** after tool installation.
See the [Windows guide](docs/site/windows.md) for `winget`/w64devkit alternatives,
Visual Studio environment initialization, and native-Windows lane limits.

## Resource Requirements

There is no single RAM minimum because the target program, sanitizers, input-size
limit, and concurrency all contribute. These are practical starting points:

| Workload | RAM | Suggested settings |
|---|---:|---|
| Small repository or PR/diff-scoped run | 4 GiB minimum | `--jobs 1`; keep the default harness RSS cap |
| Whole-tree run on a large repository | 8 GiB practical minimum | `--jobs 1 --rss-limit-mb 1536`; static `--jobs 2 --max-memory-mb 4096` |
| 10M+ SLOC with static analysis/build recovery | 16 GiB recommended | Start with `--jobs 2`; increase only after measuring peak RSS |
| Parallel sanitizer campaigns | 32 GiB+ recommended | Size from measured target RSS and leave parent/OS headroom |

`--rss-limit-mb` caps each fuzz child, not the whole run. Budget at least
`jobs × rss-limit-mb` for children **plus** GovFuzz's discovery/index/report data,
compiler processes, and the OS. On an 8 GiB machine, use a serial bounded sweep:

```sh
GOVFUZZ_STATIC_JOBS=2 GOVFUZZ_MAX_MEMORY_KB=4194304 \
  govfuzz auto path/to/10m-sloc-tree \
  --jobs 1 --rss-limit-mb 1536 --max-targets 500 \
  --single-pass --campaign-time 3600
```

For `govfuzz static-scan`, the equivalent controls are `--jobs 2
--max-memory-mb 4096`. Linux static scans also respect cgroup memory limits and
record an analysis gap when the RSS ceiling is reached. These are protective
thresholds, not hardcoded analysis limits: without an explicit flag, the static
ceiling is the smaller of 80% of host-available RAM and 70% of the cgroup limit;
`auto` derives its per-harness RSS allowance from available memory as well.

Retention and parsing budgets scale with available host/cgroup memory. The
per-target mutation corpus defaults to 1/64 of available RAM (64 MiB..2 GiB),
and its entry allowance is derived from that byte budget and `--max-len`.
Static-analysis source size defaults to 1/64 of its scan ceiling (16..256 MiB;
standalone SLOC has a 64 MiB floor), while auto-discovery uses 1/32 of available
RAM (64 MiB..1 GiB). Exact overrides are available through
`GOVFUZZ_MAX_CORPUS_BYTES`, `GOVFUZZ_MAX_CORPUS_ENTRIES`,
`GOVFUZZ_MAX_FILE_BYTES`, and `GOVFUZZ_MAX_SOURCE_FILE_BYTES`. Captured
subprocess, harness, runtrace, and external-analyzer output budgets are also
memory-scaled and have `GOVFUZZ_MAX_*_BYTES` overrides; see the
[auto scaling guide](docs/site/auto.md#scaling-to-large-trees) for the named controls.
On a constrained host, omit `--sarif` on the first pass because SARIF construction
needs additional report-sized memory.

## LLM Assistance (Optional)

GovFuzz can use an authenticated Codex or Claude CLI, the OpenAI Responses API,
the Anthropic Messages API, or a local OpenAI-compatible server. For interactive
work, the recommended mode is `govfuzz-daemon --mcp`: the Codex/Claude session
you are already in performs the reasoning and calls deterministic GovFuzz tools,
so GovFuzz needs no API token. Direct CLI-provider calls start a separate,
ephemeral child session using the CLI's cached login.

```sh
govfuzz llm status --json
govfuzz llm test --provider codex
govfuzz llm test --provider claude
govfuzz llm prompt --task diagnose-error --input govfuzz_work/auto/run.json
```

LLM output is advisory: normal build, target-reachability, coverage, replay, and
minimization results remain authoritative. API keys are read only from
environment variables, and all evidence/provider/MCP buffers have memory-aware,
overrideable limits. See the [LLM assistance guide](docs/site/llm.md) for MCP
registration, local models, API providers, privacy boundaries, and the audited
workflow for run planning, harnesses, findings, code explanations, and root-
cause analysis.

### Run govfuzz on every pull request

Fuzz only the code each PR changes — inline annotations, one `uses:` line, no config file:

```yaml
# .github/workflows/govfuzz-pr.yml
name: govfuzz PR
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  govfuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: Tarmo-Technologies/govfuzz/.github/actions/govfuzz-pr@main
        with: { path: ., campaign-time: "180" }
```

The action diff-scopes the run to changed files, uploads SARIF for inline code-scanning
annotations, posts a sticky summary comment, and fails only on a fuzz-confirmed finding. See
[docs/site/ci.md](docs/site/ci.md).

## Why govfuzz?

- **No harness to write.** `govfuzz auto` discovers fuzzable subprograms, generates typed
  harnesses and stubs, and drives them — you point, it fuzzes.
- **Works on trees that don't build.** It recovers the build context and repairs missing
  headers, types, and undefined symbols; unbuildable code still gets static + taint coverage
  instead of a hard failure.
- **Sixteen languages, one engine.** Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran,
  C#, JavaScript, TypeScript, Ruby, Lua, and PHP are peer first-class lanes over a shared
  coverage-guided fork-server engine — no cargo-fuzz, Jazzer, Atheris, jsfuzz, or
  `go test -fuzz` runner is required (AFL++ is an optional adapter for native C/C++). COBOL is fuzzed via
  GnuCOBOL (`cobc -C`, the first turnkey COBOL fuzzer → [cobol.md](docs/site/cobol.md)); Fortran
  via gfortran with ASan (→ [fortran.md](docs/site/fortran.md)); C# via `dotnet` + SharpFuzz IL
  instrumentation, warm-CLR and zero-harness (→ [csharp.md](docs/site/csharp.md)); JavaScript and
  TypeScript via a warm Node process with real V8 block coverage (TS transpiled with esbuild)
  (→ [javascript.md](docs/site/javascript.md)); Ruby, Lua, and PHP run under their own
  interpreters with in-process edge coverage.
- **Legacy-first.** Legacy dialects (e.g. Ada 83, K&R C, pre-C++98) and non-UTF-8
  (Latin-1/Windows-1252) sources are transcoded and fuzzed, not skipped.
- **Runs air-gapped.** No network access, no telemetry, no auto-update — built for
  disconnected review of untrusted code.
- **Permissive-license core** (Apache-2.0 / MIT / BSD only), built from scratch where
  licensing is unclear.

## What It Does

- **Fuzzing** — `govfuzz auto` across all sixteen lanes, with build recovery, typed harness/stub
  generation, a coverage-guided engine (edge coverage + CmpLog/RedQueen), and an optional
  AFL++ adapter for native C/C++. → [auto.md](docs/site/auto.md)
- **Static analysis (SAST)** — `govfuzz static-scan` (or `auto --static`) runs an offline rule
  pack across eight of those languages (Ada, C, C++, Rust, Java, Python, Perl, Go) plus
  JavaScript/TypeScript, QML, and config/IaC, with taint traces and SARIF codeFlows; fuzzing
  then confirms static findings. → [static CWE coverage](docs/site/static-cwe-coverage.md)
- **SBOM / SCA** — multi-language SBOMs across 12 ecosystems (CycloneDX + OpenVEX) with
  offline CVE/VEX correlation.
- **Binary triage** — `govfuzz binary scan` / `binary fuzz` over ELF, PE, Mach-O, and raw
  firmware blobs, with source-unavailable crash replay.

Behavioral / taint oracles (path control, command injection, insecure temp, sensitive env) run
under the Linux runtime virtualisation shim on native C/C++/Ada/Rust/Go/COBOL/Fortran
targets and the Python/Perl/Ruby/Lua/PHP interpreters. The shim is deliberately
off for Java, C#, JavaScript/TypeScript, and cross/emulated targets.

## Commands

| Command | What it does |
|---|---|
| `govfuzz auto <src>` | Discover, harness, build, and fuzz a whole tree |
| `govfuzz auto <src> --static` | Fold a whole-tree SAST pass into the run |
| `govfuzz auto <src> --engine afl++` | Fuzz recovered native C/C++ targets with AFL++ |
| `govfuzz auto <src> --force` | Best-effort fuzz every C/C++/Ada function (stub-heavy; Low-confidence findings) |
| `govfuzz auto <src> --differential clang:gcc` | Two-compiler differential (C/C++): flag inputs where the clang and gcc builds diverge (GF-301) |
| `govfuzz ci <src> --changed-since <ref>` | PR-native: fuzz only the diff, emit SARIF, gate on confirmed findings |
| `govfuzz static-scan <src> --sarif` | Offline SAST only (JSON/Markdown/SARIF) |
| `govfuzz sbom <src> --vuln-db <db>` | SBOM + offline CVE/VEX correlation |
| `govfuzz binary scan <bin>` | Inventory + hardening triage for ELF/PE/Mach-O/firmware |
| `govfuzz binary fuzz <bin>` | Fuzz a source-unavailable executable |
| `govfuzz sloc <src>` | Fast per-language SLOC count |
| `govfuzz generate-harness <file> --target <fn>` | Generate one harness by hand |
| `govfuzz llm status\|test\|prompt\|assist` | Optional bounded LLM assistance; MCP is served by `govfuzz-daemon --mcp` |

Every subcommand is documented in [docs/site/cli.md](docs/site/cli.md); `govfuzz --help` lists
them all.

## Documentation

- [Installation](docs/site/install.md) — from source, prebuilt binaries, offline, Windows.
- [`govfuzz auto`](docs/site/auto.md) — end-to-end, scaling to large trees, force-fuzz, static integration.
- [PR-native CI](docs/site/ci.md) — the GitHub Action, diff-scoping, and the confirmed-findings gate.
- [C/C++ guide](docs/site/c-cpp.md) — prerequisites, supported parameter shapes, limits.
- [COBOL guide](docs/site/cobol.md) and [Fortran guide](docs/site/fortran.md) — translated/compiler lanes, coverage, oracles, and limits.
- [C# / .NET guide](docs/site/csharp.md) — dotnet + SharpFuzz, coverage bridge, vs the field.
- [JavaScript / Node.js guide](docs/site/javascript.md) — warm Node, V8 block coverage, vs Jazzer.js.
- [CLI reference](docs/site/cli.md) — every subcommand.
- [Architecture](docs/site/architecture.md) — pipeline and crate boundaries.
- [Runtime virtualisation](docs/site/runtime-virtualisation.md) — the LD_PRELOAD shim and replay envelope.
- [Cross-compilation](docs/site/cross-compilation.md) — qemu-user / wine backends and sandboxes.
- [Windows](docs/site/windows.md) — native install + Visual Studio solution fuzzing.
- [Offline deployment](docs/site/offline-deployment.md) — air-gapped install and content packs.
- [Offline Ada/C/C++ `auto` runbook](docs/site/offline-auto-runbook.md) — strongest known-build and unknown-build commands, dependency staging, IDL codegen, and the separate forced fallback.
- [LLM and MCP assistance](docs/site/llm.md) — current-session agents, CLI/API/local providers, harness help, findings, diagnostics, privacy, and validation boundaries.
- [Licensing](docs/site/licensing.md) — policy profiles and audits.
- Validation: [DoD-domain recovery](docs/validation/2026-06-15-dod-domain-recovery.md), [real code / broken builds](docs/validation/2026-06-08-real-code-broken-builds.md), [memory scaling](docs/validation/2026-07-20-memory-scaling-benchmarks.md), and [LLM/MCP paths](docs/validation/2026-07-20-llm-mcp-validation.md).

The engineering roadmap is in [ROADMAP.md](ROADMAP.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the build, test, and
formatting/lint/SPDX gates, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities **privately** via the repository's
[Security tab](https://github.com/Tarmo-Technologies/govfuzz/security/advisories/new), not a
public issue — see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The core links only Apache-2.0 / MIT /
BSD dependencies; user-installed GPL tools (FSF GNAT, GPRbuild, AFL++) may be driven as optional
subprocesses, never linked. See the [licensing matrix](ROADMAP.md#1-licensing-and-dependency-policy).
