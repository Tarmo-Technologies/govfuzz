<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

GovFuzz is an offline fuzzing toolchain for sixteen languages — Ada, C, C++,
Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby,
Lua, and PHP — with a focus on the legacy and mission-critical code common in
government systems. The product core is permissive-licensed end-to-end
(Apache-2.0 / MIT / BSD) and never links against GPL or LGPL libraries. External
tools — FSF GNAT, GPRbuild, clang, clang++, AFL++, LibAFL — may be invoked as
subprocesses.

## Pipeline

1. **Parse** sources across all sixteen supported languages with permissive
   parser front ends.
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
fuzzing cascade. The remaining lanes substitute a compile/import/interpreter
smoke-test for the repair loop and run under a persistent interpreter or native
binary: Python (`py_compile`), Perl (`perl -c`), Go (`go build`), COBOL
(GnuCOBOL `cobc`), Fortran (`gfortran`), C# (`dotnet` + SharpFuzz),
JavaScript/TypeScript (a warm Node process; TS via esbuild), and Ruby, Lua, and
PHP under their own interpreters. Every lane drives govfuzz's own builtin engine
over the framed fork-server protocol — no third-party fuzzer. The individual
subcommands
(`scan`, `list targets`, `generate-harness`, `build`, `fuzz`, `replay`,
`minimize`, `report`) expose the same pipeline for manual use.

## Crate Boundaries

Parsers and rankers:

- `crates/ada_parser` — Ada syntax and source ranges.
- `crates/c_parser` — C syntax, functions, declarations.
- `crates/cpp_parser` — C++ syntax, functions, declarations.
- `crates/{go,java,perl,python,rust}_parser` — dedicated front ends for the Go,
  Java, Perl, Python, and Rust lanes (the remaining lanes discover via
  tree-sitter or lane-specific parsing in the CLI lane builders).
- `crates/idl_parser` — CORBA IDL subset.
- `crates/target_rank` — score candidate fuzz entry points across the supported
  languages. The parity program is moving C/C++ from signature heuristics toward
  build-context and lifecycle-aware ranking.

Harness and project synthesis:

- `crates/harness_gen` — emits Ada, C, C++, Java, and Rust harnesses plus
  build-local support files. The remaining lanes emit their harnesses from the
  CLI lane builders (`crates/cli/src/auto/{python,perl,go,cobol,fortran,csharp,js,ruby,lua,php}_build.rs`)
  against the matching `*_runtime/` decode runtimes (or inline decode for Go).
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
- `crates/finding_rules` — finding-class registry (GF-101…GF-563, plus GF-668,
  across logic, memory, injection, and static classes for the supported
  languages) plus the executable-oracle registry that emits runtime-confirmed
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
