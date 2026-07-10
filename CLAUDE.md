# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Offline fuzz lab generator for government legacy Ada, C, C++, Rust, Java, Python, Perl, and Go software (eight first-party fuzzing lanes — all driven by govfuzz's own engine, no third-party fuzzer). It scans untrusted source trees (with or without a working build), ranks fuzzable subprograms, generates typed harnesses + stubs + fake CORBA scaffolding, builds them with user-installed toolchains (GNAT/GPRbuild, clang, cargo, javac, python3, perl, go), fuzzes with a built-in coverage-guided engine (or, for native C/C++, the optional AFL++ adapter), and emits JSON/Markdown/SARIF/JUnit/CSV findings. The interpreted lanes (Python, Perl) drive a persistent interpreter over the framed fork-server protocol with tracer-based edge coverage (`sys.monitoring`/`DB::DB`) into the shared map; Go compiles a native framed harness built `-cover -covermode=atomic` with real edge coverage (per-input executed-block sets from `runtime/coverage`, count-ignoring so loop trip-counts aren't false novelty, folded into the shared map). It also produces multi-language SBOMs (12 ecosystems) with offline CVE/VEX correlation — SBOM ingestion is broader than the eight fuzzing lanes. Treat scanned trees, manifests, `compile_commands.json`, corpus files, and child-process output as untrusted input.

## Commands

```sh
cargo build --workspace                  # also produces libgovfuzz_runtrace_shim.so next to binaries
cargo test --workspace                   # full suite (~3850 tests)
cargo test -p c_parser                   # one crate
cargo test -p govfuzz --test auto_attempt        # one CLI integration test file
cargo test -p govfuzz --test auto_attempt name_substring   # one test
cargo fmt --all && cargo clippy --workspace --all-targets  # required clean before push (deny-level lints fail CI)
```

The CLI binary is `govfuzz` (crate name `govfuzz` in `crates/cli`); the daemon is `govfuzz-daemon`. Quick E2E smoke against a bundled real library:

```sh
target/debug/govfuzz auto --per-target-time 1 --verbose tests/fixtures/build_recovery/fixtures/miniz
```

Ada lanes need FSF GNAT + GPRbuild installed (`apt-get install gnat gprbuild`); C/C++ lanes need `make` + `clang`; the Rust lane needs a nightly toolchain (sancov+ASan staticlib); the Java lane needs a JDK (+ maven/gradle for those projects); the Python lane needs `python3` (3.12+ for `sys.monitoring` coverage); the Perl lane needs `perl`; the Go lane needs `go` (module-based targets; `GOTOOLCHAIN=local`). Tests that require missing toolchains skip themselves — don't mistake a missing-toolchain skip for a pass when touching that lane's codegen.

## CI

CI runs on every push (ci.yml: VS Code extension tests, GNAT Studio plugin unittests, workspace build + tests, clippy; license-audit.yml; gnat-matrix.yml exercises Ada fixtures across GNAT versions; docs-site.yml publishes `docs/site/` to docs.govfuzz.dev). Always verify locally before pushing — and watch all workflows after a push.

## License Policy (load-bearing — permissive-linking guarantee)

The default `strict-permissive` profile may link **only** Apache-2.0/MIT/BSD code. GNAT, GPRbuild, Libadalang, PolyORB, GNATcoverage are GPL: subprocess-only (`external-tools` profile) or forbidden outright — never linked, never bundled. `cargo deny` + `crates/license_policy` + the License Audit workflow gate this; adding any dependency without a ROADMAP §1.2 matrix entry fails the build. Generated artifacts (harnesses, `adafuzz-*` runtime copies, stubs) carry Apache-2.0 SPDX headers. **When adding any source or docs file**: give it an SPDX header (`// SPDX-License-Identifier: Apache-2.0` in code, `<!-- ... -->` in docs/ markdown) and re-run `cargo run -p spdx_check -- generate` to update `SPDX/manifest.json` — License Audit diffs the manifest and fails on unrecorded files. tree-sitter-ada is vendored at a pinned commit in `vendor/` for license re-verification per upgrade. When adding a dependency, update the matrix and `deny.toml` in the same change.

## Architecture

Rust workspace of ~40 crates orchestrated by `crates/cli`. The flagship path is `govfuzz auto` (`crates/cli/src/auto/`): discovery → decl index → per-target attempt loop → report.

- **Parsing/discovery:** `ada_parser` (from-scratch lexer + structural parser reconciled with vendored tree-sitter-ada), `c_parser`/`cpp_parser`/`rust_parser`/`java_parser`/`python_parser`/`perl_parser`/`go_parser` (tree-sitter), `idl_parser` (CORBA IDL subset). `crates/cli/src/auto/discovery.rs` walks the tree, parses per file, ranks via `target_rank`, and produces `Candidate`s. `decl_index.rs` indexes declarations across the tree for stubbing and signature lookup.
- **Attempt loop:** `crates/cli/src/auto/attempt.rs` runs one candidate end-to-end: harness generation (`generate_harness.rs` → `harness_gen` crate), build (`build.rs`, subprocess `make`/`gprbuild`), diagnostic-driven repair (`auto/repair.rs` + `build_classifier` — header/type placeholders, stubs, env injection), then a cascade of fuzz passes (Empty, Rng, FuzzDriven) with the runtrace shim. Outcomes are the `Outcome` enum; per-pass exec/finding counts live in `PassRun`.
- **Fuzzing:** `crates/cli/src/fuzz.rs` drives the in-process builtin engine (`fuzz_engine/builtin`); adapters for AFL++/libFuzzer/LibAFL/Nyx live under `crates/fuzz_engine/*` (only builtin + AFL++ participate in the `auto` cascade; AFL++ is native C/C++ only; libFuzzer is deferred; Nyx is a stub). `fork_server`, `multicore_fuzz`, `cmplog`, `corpus` support it.
- **Runtime virtualisation:** `govfuzz_runtrace_shim` is an LD_PRELOAD shim (unsafe libc interposition — review changes there with signal-safety in mind) that fakes resources and records runtrace events consumed by `auto`.
- **Generated-code runtimes:** `ada_runtime/` (Ada decode packages copied beside generated harnesses), `c_runtime/govfuzz_decode.h` (C89-compatible on purpose — legacy targets), the `rust_runtime` crate, `java_runtime/` (`com.govfuzz.GovfuzzData` + the ASM bytecode coverage agent — govfuzz's own, not Jazzer), `python_runtime/` (`govfuzz_decode.py` + `govfuzz_cov.py` `sys.monitoring` tracer + framed `govfuzz_driver.py`), and `perl_runtime/` (`govfuzz_driver.pl` + `Devel::GovfuzzCov` DB::DB tracer) decode raw fuzz bytes into typed values. The interpreted lanes (Python/Perl) are emitted by `crates/cli/src/auto/{python,perl}_build.rs`; the Go lane's harness is generated inline by `go_build.rs` and `go build`-compiled.
- **Reporting:** `report` (JSON/Markdown/SARIF 2.1.0/JUnit), `finding_rules`, `actionability`, `confidence_model`, `event_log`. `governance`/`license_policy`/`spdx_check` gate distribution.
- **Services:** `daemon` (JSON-RPC for IDE thin clients — VS Code extension and GNAT Studio plugin under `editors/`), `continuous_daemon`, `replay_min`.
- **Stubs (intentional):** `crates/{type_model,semantic,discovery}` are ~8-line placeholders reserved by the roadmap — don't "fix" them in passing.

Cross-cutting rule: anything emitted into a user's workspace (harness source, `.gpr`, Makefiles, stubs) comes from `harness_gen`/`stub_gen`/`project_synth` templates; codegen changes need a fixture under `examples/` or `tests/fixtures/` proving the emitted source compiles.

## Conventions

- Library crates test in-file (`#[cfg(test)]` at the bottom of `src/lib.rs`); CLI integration tests live in `crates/cli/tests/` and shell the binary or call `auto` internals against `tests/fixtures/`.
- Every source file starts with `// SPDX-License-Identifier: Apache-2.0`.
- ROADMAP.md is the engineering source of truth (license matrix, milestone acceptance criteria); user-facing behavior docs live in `docs/site/`. Keep both honest when behavior changes — README/docs drift is treated as a bug.
- Supported Ada standards: 95/2005/2012/2022 (full fuzzing). Ada 83 is supported best-effort (M22): parsed with the reduced 83 keyword set, built `-gnat83`, discovered + statically analyzed (report-only).
- `.claude/issue-drafts.md` holds pre-approved GitHub issue drafts; repo labels follow `area:*` / `type:*` taxonomy.
