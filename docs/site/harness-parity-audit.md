<!-- SPDX-License-Identifier: Apache-2.0 -->

# 200-project expert harness parity audit

GovFuzz's auto-harnessing is measured against real, independently written expert
drivers rather than only against generated fixtures. The audit pins 200 projects
across all sixteen supported languages (12 or 13 per lane), permits the normal
ten-candidate backfill, and requires an exact target-entry checkpoint. A separate
expert set contains one reviewed driver per language at the identical project
revision. Repository-owned fuzz drivers are hidden from automatic selection so
the comparison does not leak the answer into GovFuzz.

## Measured result

The clean durable 200-project rerun completed every row without an interrupted or
negative-exit record. It proved 118 selected calls entered and 105 produced
dynamic project coverage, up from 93 body-covered projects in the initial pass.
Focused final-binary reruns closed a Go coverage-scope defect and a C++ MSBuild
context defect; substituting only those measured lane results yields an explicit
cross-run composite of 113/200 body-covered projects. That composite is not
represented as a second monolithic 200-project run.

Against the independent all-language expert set, the final binary entered and
dynamically covered the selected endpoint in 16/16 projects. Auto selected the
same normalized semantic entrypoint in 13/16 lanes, up from 6/16 before the audit.
The three conservative selection differences were:

- Rust/zoxide, where the expert uses a private in-package database method that a
  separate public harness crate cannot see;
- COBOL/webbol, where auto and the expert select two different viable deep
  surfaces and both file-resource setup and target entry are supported;
- PHP/Monolog, where auto and the expert select different viable formatters, but
  auto now constructs the required typed `LogRecord` object.

The existing blind 30-project C/C++ line comparison remains the deeper native
coverage control: all 30 pairs were comparable, 19 had no expert-only
implementation lines, and 25 were within seven expert-only lines. Auto covered
50,340 implementation lines versus 48,742 for the independent experts, with 123
expert-only lines in total. Aggregate line count and semantic target equality are
reported separately because neither substitutes for the other.

## Expert levers now automated

| Lever | Automatic behavior |
|---|---|
| Honest execution proof | Every lane checkpoints immediately before the selected call; decode/setup-only execution is demoted. |
| Semantic selection | Identifier-token scoring prioritizes public parsers, decoders, whole-artifact entrypoints, and stateful surfaces while penalizing debug/report/inspection helpers. |
| File-backed input | JavaScript, Ruby, and COBOL materialize fuzz bytes for path/file operands and clean them after the call. JavaScript awaits returned promises before cleanup. |
| Stateful APIs | Go mines a bounded one-input feeder plus zero-argument terminal, including Cobra `SetArgs` → `Execute`. |
| Typed objects | PHP resolves imports and recursively constructs bounded scalar, array, enum, date, and constructor graphs. |
| C++ templates and defaults | Public member templates, defaulted parameters, common rvalue byte strings, and default-template aliases produce legal calls. |
| ABI-specific arrays | Fortran assumed-shape character arrays receive the required descriptor and full input extent. |
| Managed instrumentation | C# compiles project code into a separate target library and instruments only project IL. |
| Coverage fallback | Go retries instrumentation for the exact selected package before falling back from a failed module-wide build. |
| Build context | Static MSBuild paths retain resolved project properties but reject unresolved configuration variables instead of inventing include paths. |

## Remaining expert-parity gaps

1. **Private Rust and resource recipes.** A controlled in-crate test/fuzz module
   is needed for private targets, followed by nearby-call-site inference for
   path-backed constructors and openers.
2. **Build-graph fidelity.** Generated files, features, platform SDKs, and full
   project artifacts still defeat reduced source closures in some large Ada,
   C++, C#, Fortran, Java, and Rust projects.
3. **Framework bootstrapping.** Missing packages and browser, Neovim, Android, or
   Windows hosts remain distinct from generator defects. Local lockfile caches
   and narrow, disclosed host stubs are the next leverage points.
4. **Structured scientific data.** Fortran scientific APIs need coherent bounded
   vectors/matrices plus coupled dimensions, leading dimensions, and alias/intent
   constraints rather than only character control inputs.
5. **General state/resource sequences.** The narrow Go feeder-terminal rule
   should grow into provenance-bearing constructor → setter/feed → parse/execute
   → cleanup recipe mining across native and managed lanes.

The checked-in reproducibility kit lives in
`benchmarks/harness-parity-200/`: pinned project manifests, one expert harness per
language, durable/resumable runners, comparison scripts, and the exact residual
classification. The benchmark distinguishes discovery, build, target entry,
dynamic body coverage, and exact semantic selection so a shallow or setup-only
success cannot be promoted silently.
