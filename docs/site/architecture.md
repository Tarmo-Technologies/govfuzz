<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

GovFuzz is an offline fuzzing toolchain for government legacy Ada, C, C++,
Java, Rust, Python, Perl, and Go software. The product core is permissive-licensed end-to-end (Apache-2.0 / MIT /
BSD) and never links against GPL or LGPL libraries. External tools — FSF GNAT,
GPRbuild, clang, clang++, AFL++, LibAFL — may be invoked as subprocesses.

## Pipeline

1. **Parse** Ada, C, C++, Java, Rust, Python, Perl, and Go sources with
   permissive parser front ends.
2. **Rank** fuzz targets from subprograms, exception handlers, type
   information, and call relationships.
3. **Generate** direct-call harnesses and partial-build projects around
   selected targets. Auto-stub missing headers, types, and undefined symbols.
4. **Instrument** sources with probe breadcrumbs and testcase boundaries.
5. **Build and run** harnesses through host, cross-compiled, or qemu-user
   runners. Optionally wrap execution in a sandbox.
6. **Virtualise the runtime** via an LD_PRELOAD shim — fake missing files,
   sockets, env vars, and `dlopen` chains so the harness reaches the target
   code. The shim and its behavioral/taint oracles run natively for
   C / C++ / Ada / Rust / Go and are armed for the interpreted Python and
   Perl lanes (the shim interposes the CPython / `perl` process); they are
   not armed during Java fuzzing or under cross/emulated (qemu/wine) runs.
7. **Normalize findings** into JSON, Markdown, SARIF, JUnit, and IDE-facing
   daemon responses.

`govfuzz auto` runs steps 1–7 in one shot. Ada, C, and C++ targets are
harnessed and built inside an iterative repair loop; Rust and Java targets are
prebuilt before that loop and skip diagnostic-driven repair, then join the same
fuzzing cascade. The interpreted Python and Perl lanes substitute a
compile/import smoke-test (`py_compile` / `perl -c`) for the repair loop and run
the harness under a persistent interpreter; Go targets compile with `go build`
into a native fork-server binary. Every lane drives govfuzz's own builtin engine
over the framed fork-server protocol — no third-party fuzzer. The individual
subcommands
(`scan`, `list-targets`, `generate-harness`, `build`, `fuzz`, `replay`,
`minimize`, `report`) expose the same pipeline for manual use.

## Crate Boundaries

Parsers and rankers:

- `crates/ada_parser` — Ada syntax and source ranges.
- `crates/c_parser` — C syntax, functions, declarations.
- `crates/cpp_parser` — C++ syntax, functions, declarations.
- `crates/idl_parser` — CORBA IDL subset.
- `crates/target_rank` — score candidate fuzz entry points across Ada, C, C++,
  Java, Rust, Python, Perl, and Go. The parity program is moving C/C++ from
  signature heuristics toward build-context and lifecycle-aware ranking.

Harness and project synthesis:

- `crates/harness_gen` — emits Ada, C, C++, Java, and Rust harnesses plus
  build-local support files. The Python, Perl, and Go harnesses are emitted by the
  CLI lane builders (`crates/cli/src/auto/{python,perl,go}_build.rs`) against the
  `python_runtime`/`perl_runtime` decode runtimes / inline Go decode.
- `crates/project_synth` — Ada partial-build `.gpr` generation.
- `crates/stub_gen` — Ada package / identifier / visibility stubs.
- `crates/c_stub_gen` — C placeholder headers, typedef placeholders,
  declared and blind function stubs.
- `crates/probe_gnat_actions` — opt-in GNAT compiler-action probes.

Build / fuzz / replay:

- `crates/build_classifier` — maps gcc / clang / ld / GNAT diagnostics into
  the `BuildErrorKind` enum that drives repair planning.
- `crates/compiler_adapter` — discovers and invokes user-installed
  toolchains.
- `crates/instrumenter` — rewrites Ada source for probe events.
- `crates/fuzz_engine` — built-in deterministic engine.
- `crates/govfuzz_runtrace_shim` — LD_PRELOAD shim
  (`libgovfuzz_runtrace.so`) that audits and fakes the runtime
  environment around a fuzz target. Native for C / C++ / Ada / Rust / Go and
  armed for the interpreted Python and Perl lanes (it interposes the
  interpreter process); not armed during Java fuzzing or under cross/emulated
  targets.
- `crates/replay_min` — replay and delta-debug minimization.

Output and policy:

- `crates/report` — JSON, Markdown, SARIF, JUnit, and CSV emitters.
- `crates/confidence_model` — calibrated finding confidence.
- `crates/finding_rules` — finding-class registry (GF-101…GF-541 across
  logic, memory, injection, and static classes for Ada, C, C++, Rust, Java,
  Python, Perl, and Go) plus the executable-oracle registry that emits
  runtime-confirmed
  (`confirmation: "runtime"`) hits during fuzzing.
- `crates/license_policy` — profile-driven probe and dependency gates.
- `crates/spdx_check` — SPDX metadata audit.

IDE and orchestration:

- `crates/daemon` — JSON-RPC service for editor clients.
- `crates/cli` — the `govfuzz` command-line entry point. Houses the
  `auto` module that drives the point-and-shoot sweep.

## Docs Hosting Architecture

The docs hosting architecture is intentionally small: Markdown sources live in `docs/site`,
`scripts/docs/build-site.py` renders static HTML into `target/docs-site`,
and GitHub Pages serves the generated artifact at `docs.govfuzz.dev` when
Pages is enabled for the repository. The docs workflow validates and
uploads the Pages artifact on every push. The deploy job is gated by the
`GOVFUZZ_PAGES_ENABLED` repository variable so the workflow stays green
in repositories or plans where Pages is not available yet.
