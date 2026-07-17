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

See the [installation guide](docs/site/install.md) for prebuilt binaries, per-language
toolchains, offline/air-gapped install, and Windows.

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
  coverage-guided fork-server engine — no cargo-fuzz, Jazzer, Atheris, SharpFuzz, jsfuzz, or
  `go test -fuzz` required (AFL++ is an optional adapter for native C/C++). COBOL is fuzzed via
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
under the runtime virtualisation shim on native C/C++/Ada/Rust/Go targets and the Python/Perl
interpreters.

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

Every subcommand is documented in [docs/site/cli.md](docs/site/cli.md); `govfuzz --help` lists
them all.

## Documentation

- [Installation](docs/site/install.md) — from source, prebuilt binaries, offline, Windows.
- [`govfuzz auto`](docs/site/auto.md) — end-to-end, scaling to large trees, force-fuzz, static integration.
- [PR-native CI](docs/site/ci.md) — the GitHub Action, diff-scoping, and the confirmed-findings gate.
- [C/C++ guide](docs/site/c-cpp.md) — prerequisites, supported parameter shapes, limits.
- [C# / .NET guide](docs/site/csharp.md) — dotnet + SharpFuzz, coverage bridge, vs the field.
- [JavaScript / Node.js guide](docs/site/javascript.md) — warm Node, V8 block coverage, vs Jazzer.js.
- [CLI reference](docs/site/cli.md) — every subcommand.
- [Architecture](docs/site/architecture.md) — pipeline and crate boundaries.
- [Runtime virtualisation](docs/site/runtime-virtualisation.md) — the LD_PRELOAD shim and replay envelope.
- [Cross-compilation](docs/site/cross-compilation.md) — qemu-user / wine backends and sandboxes.
- [Windows](docs/site/windows.md) — native install + Visual Studio solution fuzzing.
- [Offline deployment](docs/site/offline-deployment.md) — air-gapped install and content packs.
- [Licensing](docs/site/licensing.md) — policy profiles and audits.
- Validation: [DoD-domain recovery](docs/validation/2026-06-15-dod-domain-recovery.md), [real code / broken builds](docs/validation/2026-06-08-real-code-broken-builds.md).

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
