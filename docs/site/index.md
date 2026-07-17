<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz Documentation

`docs.govfuzz.dev` is the public documentation site for GovFuzz operators,
release engineers, and IDE integrators. GovFuzz is an offline fuzz lab
generator for sixteen languages — Ada, C, C++, Rust, Java, Python, Perl, Go,
COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP — with
source-generated harnesses and a permissively licensed core.

## Start Here

- [Comparison](./comparison/) — govfuzz measured head-to-head against the most
  popular fuzzer for each language (AFL++, libFuzzer, cargo-fuzz, Jazzer):
  harness effort, bug-finding, breadth, and a reproducible benchmark suite.
- [White Paper](./whitepaper/) — *One fuzzer for the whole codebase*: the case
  for automated, multi-language fuzzing of legacy and mission-critical software.
- [Vulnerability Coverage](./vulnerability-coverage/) — measured CWE-class
  coverage vs the crash-only fuzzers: the behavioral bugs (path traversal,
  insecure temp, sensitive-env) they run right past, plus first/second-run timing.
- [Static CWE Coverage Matrix](./static-cwe-coverage/) — what the static analyzer
  detects per language and CWE, the fuzz-confirmation differentiator, and the
  web-only CWEs it deliberately declines (with rationale).
- [SAST Comparison](./sast-comparison/) — govfuzz's static scanner measured on 50
  GitHub projects against the leading open-source SAST tool for each language
  (bandit, semgrep, gosec, flawfinder, cppcheck, perlcritic, clippy): same
  security classes, far less noise, more usable output.
- [White Paper: Bugs Your Fuzzer Can't See](./whitepaper-coverage/) — why a crash
  is only the beginning; runtime taint + behavioral oracles find the rest.
- [Taint-Confirmed Sink Oracles](./sink-oracles/) — how govfuzz confirms that a
  fuzz input *provably controls* a dangerous sink (command exec, path traversal,
  SSRF, library load, SQL, destructive fs) with byte-origin taint, the full sink
  matrix with CWEs, and the honest boundary of what it deliberately declines.
- [Architecture](./architecture/) — pipeline overview and the crates that
  make it up.
- [CLI](./cli/) — the stable `govfuzz` operator surface.
- [Auto](./auto/) — `govfuzz auto <PATH>` sweeps a source tree in any of the
  sixteen supported languages (including code that does not build) and produces a
  fuzz lab plus a findings report without manual harnessing.
- [C and C++ Fuzzing](./c-cpp/) — C/C++ prerequisites, manual commands,
  supported API shapes, engine modes, and current limits.
- [Sanitizers](./sanitizers/) — the `--sanitizers` matrix, what the default
  build already arms, and when to add LSan/MSan/TSan.
- [Run Modes](./run-modes/) — `--mode reporting|attacking`: how each schedules
  targets and foregrounds findings, and the shared verdict ladder.
- [libFuzzer Parity](./libfuzzer-parity/) — how the built-in engine's flags
  map to libFuzzer's (`--max-len`, `--len-control`, `--timeout`,
  `--rss-limit-mb`, ...), and cmplog/RedQueen as the value-profile equivalent.
- [Engine Parity Benchmark](./engine-parity-benchmark/) — the planted-bug
  time-to-first-crash suite for cold magic-byte / gated-parser solving, and the
  current baseline.
- [Runtime Virtualisation](./runtime-virtualisation/) — the LD_PRELOAD shim
  that fakes the missing environment around a fuzz target, plus the
  three-pass cascade and replay envelope.
- [Instrumentation](./instrumentation/) — source rewriting and probe
  backends.
- [Fake-CORBA](./fake-corba/) — IDL scaffolding for legacy Ada servants.
- [Cross-Compilation](./cross-compilation/) — target toolchains, probe
  backends, qemu-user replay, and sandboxing.
- [Daemon](./daemon/) — JSON-RPC service that powers the VS Code and GNAT
  Studio integrations.
- [Licensing](./licensing/) — policy profiles, SPDX metadata, and audits.
- [Release Packaging](./release-packaging/) — distributed archives,
  checksums, and signed content packs.
- [Offline / Air-Gapped Deployment](./offline-deployment/) — installing and
  updating GovFuzz on a disconnected host: build-vs-transfer, the artifact set,
  offline source builds, toolchain staging, and content packs.

## Local Build

```sh
python3 scripts/docs/build-site.py --out target/docs-site
```

Open `target/docs-site/index.html` to inspect the generated site locally.
