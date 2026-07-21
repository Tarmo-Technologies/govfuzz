# govfuzz — Engineering Roadmap

This is a historical engineering plan as well as a forward roadmap. Dated
milestones, command sketches, agent instructions, and acceptance criteria below
record what was proposed at the time; they are not the operator reference. Use
[`docs/site/`](docs/site/) and live `govfuzz <command> --help` output for current
behavior. Current optional LLM/MCP workflows are documented in
[`docs/site/llm.md`](docs/site/llm.md).

GovFuzz currently fuzzes sixteen languages: Ada, C, C++, Rust, Java, Python,
Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP.
Permissive core, partial-build aware, sanitizer and swallowed-exception aware,
CORBA-friendly without a real ORB.

Supported Ada standards: **95, 2005, 2012, 2022** (full fuzzing). **Ada 83** is
supported best-effort as a legacy dialect (M22 §29): it parses (reduced 83
keyword set, built with `-gnat83`) and is discovered + statically analyzed
(report-only), rather than being rejected.

---

## Current implementation snapshot

The user-facing current behavior is documented under `docs/site/`. In brief:

- `govfuzz auto` is the complete sixteen-lane entry point. The narrower manual
  commands intentionally differ: `scan` and `generate-harness` cover Ada/C/C++,
  while `list targets` covers Ada/C/C++/Java/Rust. Source reading transcodes
  non-UTF-8 legacy files
  (Latin-1/Windows-1252) instead of skipping them, so older government Ada/C is
  not silently dropped.
- The Ada lane includes source instrumentation, handler and breadcrumb events,
  typed harness generation, GNAT/GPRbuild project synthesis, fake CORBA/IDL
  scaffolding, and stateful package harnessing.
- The C/C++ lane includes direct-call harnesses for common byte-oriented APIs,
  compile database flag ingestion, sanitizer findings, build repair, runtime
  audit, and optional AFL++ targets through `govfuzz build --c-engine afl++`
  (the AFL++ adapter is native C/C++ only; every lane uses the built-in engine
  by default).
- The Rust and Java lanes are native fuzzing lanes (not SBOM-only). Both are
  built before the repair loop and share the built-in cascade with direct-only
  harnesses (no public sequence harness). Rust compiles a staticlib with
  sancov + ASan coverage linked to the C fork-server driver; Java uses
  govfuzz's own ASM bytecode JVM coverage agent (not Jazzer) over
  javac/maven/gradle builds. The behavioral/taint runtrace shim is deliberately
  not armed for Java, C#, JavaScript/TypeScript, or cross/emulated targets.
- The Python, Perl, and Go lanes (M3.1–M3.3) are native fuzzing lanes driven by
  govfuzz's own built-in engine over the framed fork-server protocol — no
  third-party fuzzer (no Atheris, no `go test -fuzz`, no libFuzzer). Python
  (`.py`) and Perl (`.pl`/`.pm`) are interpreted lanes with real coverage
  feedback: a persistent CPython driver records `sys.monitoring` (3.12+) /
  `sys.settrace` edge counts and Perl runs under `perl -d:GovfuzzCov` with
  `DB::DB` per-statement edges, both into the shared `GOVFUZZ_COV_SHM` map; their
  "build" is `py_compile`/`perl -c` plus an import/`require` smoke-test (an
  un-importable target or missing CPAN dep skips cleanly). Go (`.go`, skipping
  `_test.go`) is the compiled, fastest lane: the generated `main` imports the
  target package via a module `replace`, is built with `go build` to a native
  framed fork-server binary, and recovers panics into findings. Go now has real
  edge coverage (not black-box): it is built with `go build -cover
  -covermode=atomic`, and per input the harness clears Go's atomic counters, runs
  the target, then folds the SET of executed blocks (via
  `runtime/coverage.WriteCounters`, ignoring the count value so a single
  execution maps to one edge set) into the shared `GOVFUZZ_COV_SHM` edge map —
  the same coverage-guided feedback the other lanes get. All three map outcomes to CWE
  and suppress input-rejection exceptions to avoid untyped-lane false positives.
  The behavioral/taint runtrace oracles ARE armed for these lanes (the
  LD_PRELOAD shim interposes the CPython and Perl interpreter processes and the
  native Go binary), unlike Java.
- COBOL and Fortran compile through GnuCOBOL/gfortran into the native C driver;
  C# uses SharpFuzz IL coverage in a warm CLR; JavaScript/TypeScript use V8 block
  coverage in warm Node; and Ruby, Lua, and PHP use interpreter coverage. The
  Linux runtrace shim also covers native COBOL/Fortran and the Ruby/Lua/PHP
  interpreter processes.
- The parity program closes the remaining C/C++ gaps: richer build-system
  ingestion, C++ lifecycle/sequence harnesses, and IDE/daemon parity.
- The §25 top-of-class gap program (#341–#345) is **delivered** (2026-06-19):
  coverage-blocker introspection, structure-aware input + dictionary mining,
  the executable oracle SDK, CycloneDX SBOM + offline CVE correlation, and
  generalized C/C++ + Ada lifecycle/output harnessing all ship and are
  regression-tested. Post-1.0 continuous-improvement items are tracked in §24.

The rest of this file is an engineering roadmap. Sections written as future
milestones may describe planned work or historical acceptance criteria rather
than the exact current CLI surface.

---

## 0. MVP definition

**Strict-permissive MVP** ships when the following work end-to-end against `examples/swallowed_constraint_error/`, plus one fixture per supported dialect (95/2005/2012/2022):

1. `govfuzz scan` finds the target package and its public subprograms using a from-scratch lexer plus tree-sitter-ada.
2. `govfuzz instrument` rewrites a copy of the source so every executable statement leaves a breadcrumb and every `when ... =>` handler logs a structured event before running its original body.
3. `govfuzz generate-harness` emits a standalone Ada main that decodes stdin bytes into the target's parameter types and calls it.
4. `govfuzz build` produces a synthetic `.gpr`, calls user-installed FSF GNAT/GPRbuild as a subprocess, and parses diagnostics.
5. `govfuzz fuzz` runs the built harness using a built-from-scratch mutational engine, retains testcases by exception signature, and writes JSON findings.
6. `govfuzz replay` and `govfuzz report` reproduce and explain a finding.

Anything that requires Libadalang, GNATfuzz, GNATcoverage, AFL++, LibAFL, libFuzzer, PolyORB, or any LGPL/GPL-linked component is out of scope for the MVP and lives behind plug-in adapters.

---

## 1. Licensing and dependency policy

### 1.1 Build profiles

| Profile | Intent | Linked deps | Subprocess deps | Plug-ins allowed |
|---|---|---|---|---|
| `strict-permissive` | Permissive-only distribution | Apache-2.0 / MIT / BSD only | None required | None |
| `external-tools` | Permissive core + user-installed GPL tools at runtime | Same as strict-permissive | FSF GNAT, GPRbuild, AFL++ | `gnat_actions` probe |
| `research-lab` | Internal R&D and benchmarks; never shipped | Same as above | Anything | Libadalang, GNATfuzz, GNATcoverage, PolyORB |

The license-policy gate refuses to build a `strict-permissive` artifact if the resolved dependency graph contains a non-allow-listed license. CI fails the build.

### 1.2 Dependency matrix

| Component | Purpose | License | Tier | Risk | Recommendation |
|---|---|---|---|---|---|
| From-scratch scanner (govfuzz) | Permissive Ada lexer + structural parser | Apache-2.0 (ours) | **Core** | Grammar drift | Author in-house. Only path to true permissive guarantee. |
| tree-sitter | Generic incremental parser engine | MIT | **Core** | Low | Link directly. |
| tree-sitter-ada | Ada grammar for tree-sitter | MIT (verify per release) | **Core** (after license re-verification per upgrade) | License churn, grammar coverage gaps | Vendor at a pinned commit; CI license-audit job. |
| tree-sitter-rust | Rust grammar for tree-sitter (native Rust discovery lane, M1.1) | MIT | **Core** | Low (same `tree-sitter-language` ABI as tree-sitter-c/-cpp) | Link directly via `[workspace.dependencies]`; permissive, strict-permissive clean. |
| tree-sitter-java | Java grammar for tree-sitter (native Java discovery lane, M2.1) | MIT | **Core** | Low (same `tree-sitter-language` ABI as tree-sitter-rust/-c/-cpp) | Link directly via `[workspace.dependencies]`; permissive, strict-permissive clean. |
| tree-sitter-python | Python grammar for tree-sitter (native Python discovery lane, M3.1) | MIT | **Core** | Low (same `tree-sitter-language` ABI as the other grammars) | Link directly via `[workspace.dependencies]`; permissive, strict-permissive clean. |
| tree-sitter-perl | Perl grammar for tree-sitter (native Perl discovery lane, M3.2) | MIT | **Core** | Low (same `tree-sitter-language` ABI) | Link directly via `[workspace.dependencies]`; permissive, strict-permissive clean. |
| tree-sitter-go | Go grammar for tree-sitter (native Go discovery lane, M3.3) | MIT | **Core** | Low (same `tree-sitter-language` ABI as the other grammars) | Link directly via `[workspace.dependencies]`; permissive, strict-permissive clean. |
| ASM (org.ow2.asm) | JVM bytecode instrumentation for govfuzz's own coverage agent (native Java fuzzing, M2.1) | BSD-3-Clause | **Core (agent runtime, NOT linked)** | Low (permissive, strict-permissive clean) | Bundled only into the standalone `govfuzz-jvm-agent.jar` (`-javaagent` for the user's JVM — agent/subprocess posture, never linked into the Rust binary). Built from `java_runtime/` by `build-agent.sh`; ASM fetched to a cache or pre-staged for air-gapped builds. |
| GPR2 library | Programmatic .gpr parsing | GPLv3 (with RLE for runtime, not for tooling linkage) | **Forbidden** (linked); **External-only** via `gprbuild --print-*` parsing | Copyleft contamination if linked | Do not link. Parse `.gpr` ourselves; shell out to `gprbuild` for builds. |
| GPRbuild | Project build driver | GPLv3 | **External-only** | None when invoked as subprocess | Allowed as user-installed subprocess in `external-tools`; not bundled. |
| FSF GNAT/GCC | Ada compiler | GPLv3 + GCC Runtime Library Exception | **External-only** | The GCC RLE permits compiled-program redistribution but does not let us link Ada front-end libraries | Subprocess only. Document RLE boundary in `THIRD_PARTY.md`. Generated Ada code that links GNAT runtime is fine for end users compiling their own harnesses. |
| GNAT.Exception_Actions | Global raise hook | GPLv3 + GCC RLE | **Optional plug-in** (day-one in `external-tools`) | Same RLE caveat as runtime; implementation-defined unit | Source-instrumentation default. `--probe gnat_actions` available on day one in `external-tools`; refused in `strict-permissive`. |
| GNAT.Exception_Traces | Symbolic backtrace | GPLv3 + GCC RLE | **Optional plug-in** | Same | Opt-in. |
| GNATfuzz | AdaCore fuzzing tool | Proprietary / non-free distribution | **Forbidden** | Direct competitor; license incompatible | Never depend on. |
| GNATcoverage | Coverage tool | GPLv3 | **Forbidden** in core | Subprocess use still pulls in copyleft tooling expectations and doesn't fit MVP | `research-lab` only. |
| AFL++ | Coverage-guided fuzzer | Apache-2.0 | **Optional adapter** | Low | Adapter in `crates/fuzz_engine/afl_adapter`. Not bundled binary; user-installed. |
| LibAFL | Embeddable fuzzing library | MIT/Apache-2.0 dual | **Optional embedded** | Low | Optional Cargo feature `libafl-engine`. |
| LLVM / libFuzzer | LLVM compiler infra and in-process fuzzer | Apache-2.0 with LLVM exceptions | **Optional adapter** | LLVM/Ada front end is not production-grade | Adapter only. Never required. |
| PolyORB | Free Ada ORB | GPLv3 | **Forbidden** as core dep | Copyleft | `research-lab` only. |
| TAO | C++ ORB | DOC license (BSD-ish but unusual) | **Forbidden** in core | Audit cost | `research-lab` only. |
| omniORB | C++ ORB | LGPL/GPL | **Forbidden** | Copyleft on linkage | `research-lab` only. |
| JacORB | Java ORB | LGPL | **Forbidden** | Copyleft | `research-lab` only. |
| Libadalang | Semantic Ada front end | GPLv3 with runtime exception | **Optional plug-in only** | Linkage and audit risk | Out-of-process plug-in via JSON-RPC / subprocess. Never linked into core. |
| Alire | Ada package manager | Apache-2.0 | **Optional external** | Low | Used to fetch user dependencies in `external-tools`. |
| Langkit | Front-end generator | GPLv3 | **Forbidden** | Copyleft | Not used. |
| ASIS | Compiler-vendor semantic API | Vendor-dependent | **Forbidden** | Vendor lock | Not used. |
| serde / serde_json (Rust) | Serialization | MIT/Apache-2.0 | **Core** | Low | Allow. |
| clap (Rust) | CLI parsing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| anyhow / thiserror | Error types | MIT/Apache-2.0 | **Core** | Low | Allow. |
| tokio | Async runtime (only if needed) | MIT | **Core** | Low | Allow if used. |
| nom / chumsky | Parser combinators (IDL) | MIT/Apache-2.0 | **Core** | Low | Use for IDL subset parser. |
| zstd / lz4 | Corpus compression | BSD-3 / BSD-2 | **Optional** | Low | Allow. |
| sha2 / blake3 | Hashing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| regex | Diagnostic parsing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| rayon (Rust) | Data-parallel static-scan file pipeline (10M-SLOC scale) | MIT OR Apache-2.0 | **Core** | Low | Allow. Bounded work-stealing pool sized to cores-1; deterministic order-preserving collect. |
| criterion | Bench (dev-only) | Apache-2.0/MIT | **Core dev** | Low | Allow. |
| toml / toml_edit / winnow (Rust) | TOML manifest + lockfile parsing (sbom_ingest Cargo cataloger) | MIT OR Apache-2.0 | **Core** | Low | Allow. Transitive via toml 0.8 workspace dep. |

CI enforces this with `cargo deny` + a custom `license-policy` step. Adding any dep without a matrix entry fails the build.

### 1.3 Generated artifacts

The Ada files we emit (`adafuzz-*.ad?`, harnesses, fake-CORBA, stubs) are **Apache-2.0** with an SPDX header. The user compiles them against their own GNAT runtime; the GCC RLE handles redistribution of the resulting binary.

The native Rust lane (Phase 1) emits a `fuzz/` cargo-fuzz crate whose generated harness depends on `libfuzzer-sys` and `arbitrary` (both **MIT OR Apache-2.0**). These live in the *generated* `fuzz/Cargo.toml`, not the govfuzz workspace — they are linked only into the user-compiled harness, never into the govfuzz binary, so they need no `deny.toml` workspace entry (same posture as the `adafuzz-*` runtime copies above). The libFuzzer runtime cargo-fuzz links is **Apache-2.0-with-LLVM-exception**, also permissive. Generated `fuzz_targets/*.rs` carry the Apache-2.0 SPDX header.

---

## 2. Product goal and non-goals

**Goals**: scan with or without `.gpr`; partial sources OK; identify fuzzable subprograms, tagged ops, private-state wrappers, CORBA servants, IDL artifacts, and exception-heavy code; synthesize harnesses, stubs, and fake CORBA; fuzz subprograms and stateful sequences; **detect swallowed exceptions and attribute them to inputs, handler sites, and call sequences**; replay and minimize; emit JSON, Markdown, SARIF 2.1.0, JUnit; reproducible artifacts; cross-compilation as first-class.

**Non-goals**: no paid Ada compiler, no GNATfuzz/GNATcoverage/PolyORB requirement, no full-build requirement, no live ORB, crashes are not the only bug class, raw IIOP fuzzing is not first-class.

---

## 3. High-level architecture

### 3.1 ASCII diagram

```
              ┌──────────────────────────────────────────────────────────────┐
              │                            CLI                               │
              └─────────────┬──────────────────────────────────┬─────────────┘
                            │ commands                         │ config
              ┌─────────────▼──────────┐         ┌─────────────▼─────────────┐
              │ License-Policy Gate    │         │ Configuration System      │
              └─────────────┬──────────┘         └─────────────┬─────────────┘
                            │                                  │
              ┌─────────────▼───────────────────────────────────▼────────────┐
              │                   Source Discovery Engine                    │
              └─────────────┬─────────────────────────────────┬──────────────┘
                            │                                 │
              ┌─────────────▼──────────┐        ┌─────────────▼────────────┐
              │ Ada Syntax Scanner     │        │ CORBA / IDL Scanner      │
              │ (from-scratch + ts)    │        │ (full IDL → Ada mapping) │
              └─────────────┬──────────┘        └─────────────┬────────────┘
                            │                                 │
              ┌─────────────▼──────────┐        ┌─────────────▼────────────┐
              │ Lightweight Semantic   │        │ Fake-CORBA Synthesizer   │
              │ Model (Tier 1)         │        └─────────────┬────────────┘
              └─────────┬──────────────┘                      │
                        │ (optional plug-in)                  │
              ┌─────────▼──────────┐                          │
              │ Semantic Plug-in   │                          │
              │ (Libadalang RPC)   │                          │
              └─────────┬──────────┘                          │
                        │                                     │
              ┌─────────▼─────────────────────────────────────▼───────────┐
              │                Type Model (unified)                       │
              └─────────┬─────────────────────────────────────────────────┘
                        │
              ┌─────────▼────────────┐  ┌──────────────────────┐
              │ Target Ranking       │◄─┤ Heuristic library    │
              └─────────┬────────────┘  └──────────────────────┘
                        │
        ┌───────────────┴───────────────────────────────┐
        │                                               │
┌───────▼────────────┐  ┌───────────────────┐ ┌─────────▼────────────┐
│ Source Instrumenter │  │ Stub/Mock Gen     │ │ Harness Generator    │
└───────┬────────────┘  └─────────┬─────────┘ └─────────┬────────────┘
        │                         │                     │
        └────────────┬────────────┴─────────────────────┘
                     │
        ┌────────────▼────────────────┐
        │ Synthetic Build Project Gen │
        └────────────┬────────────────┘
                     │
        ┌────────────▼────────────────┐
        │ Compiler Adapter (subproc)  │──► gnatmake / gprbuild / gcc
        │ version-agnostic, cross-tc  │     (host or cross toolchain)
        └────────────┬────────────────┘
                     │
        ┌────────────▼────────────────┐    ┌──────────────────────┐
        │ Fuzz Engine Adapter         │◄──►│ Built-in mutator     │
        │   (built-in / AFL++ / LibAFL│    │ AFL++ adapter (opt)  │
        │    / libFuzzer)             │    │ LibAFL adapter (opt) │
        └────────────┬────────────────┘    └──────────────────────┘
                     │
              [executes harness — host or qemu/embedded]
                     │
        ┌────────────▼─────────────────┐
        │ AdaFuzz.Probe runtime (Ada)  │   (linked into harness only;
        │  breadcrumbs, handler hits   │    multiple backends:
        │  explicit-raise probes       │    host_file / memory_buffer /
        │  optional gnat_actions hook  │    semihosting / stub)
        └────────────┬─────────────────┘
                     │ binary event stream / JSON-lines
        ┌────────────▼────────────────┐
        │ Corpus Manager + Replay +   │
        │ Minimizer                   │
        └────────────┬────────────────┘
                     │
        ┌────────────▼────────────────┐
        │ Report Generator            │ ──► JSON / Markdown / SARIF 2.1 / JUnit
        └────────────┬────────────────┘     + standalone Ada repro.adb
                     │
        ┌────────────▼────────────────┐
        │ JSON-RPC Daemon (M18)       │ ──► VS Code / GNAT Studio plug-ins
        └─────────────────────────────┘
```

### 3.2 Module table

| Module | Inputs | Outputs | Core algorithm | License | MVP | Advanced | Risks |
|---|---|---|---|---|---|---|---|
| CLI | argv, config | dispatched commands | clap-style command tree | Apache-2.0 | All §15 commands | shell completions, daemon mode | scope creep |
| Config | YAML/TOML | `Config` struct | merge defaults < project < CLI | Apache-2.0 | profile, paths, engine choice | profile inheritance | drift |
| License-Policy Gate | resolved deps | pass/fail | SPDX allow-list | Apache-2.0 | Cargo deps | Ada/IDL deps too | false negatives |
| Source Discovery | path, glob, .gpr | unit list | walk + .gpr soft-parse + extension | Apache-2.0 | `*.ads`/`*.adb`/`*.idl` | follow `with` graph | symlink loops |
| Syntax Scanner Tier 1 | source bytes | structural AST | from-scratch lexer + ts-ada | Apache-2.0/MIT | specs/bodies/handlers/with/use/types/raises | preprocessor, gnatprep | grammar gaps |
| Lightweight Semantic | structural AST | resolved names where possible | scope walk, with-closure | Apache-2.0 | name binding within unit | cross-unit type unify | overconfidence |
| Semantic Plug-in API | structural AST + source | refined types | JSON-RPC subprocess | Apache-2.0 (interface) | stub | Libadalang impl out-of-tree | plug-in decay |
| CORBA/IDL Scanner | IDL files, Ada bodies | CORBA model | full IDL→Ada mapping subset | Apache-2.0 | scan IDL, detect servant base, op enumeration | typecode/Any expansion | vendor variants |
| Type Model | scanner output | unified `TypeRef` graph | normalize Ada + IDL types | Apache-2.0 | scalar/string/array/record/enum | tagged/discriminated/private/access | Ada type system depth |
| Target Ranking | type model + heuristics | ranked targets | score function (§5) | Apache-2.0 | implemented | learned weights from prior runs | local minima |
| Byte→Value Decoder | seed bytes, type | typed value | recursive consumer of byte stream | Apache-2.0 | scalars/strings/arrays/records/enums | tagged/discriminated/access via slot table | encoding drift |
| Harness Generator | target + types | `.adb` main | template + type model | Apache-2.0 | direct + sequence | tagged/generic/CORBA | template explosion |
| Source Instrumenter | unit AST + spans | rewritten copy | textual edits guided by AST spans | Apache-2.0 | breadcrumbs + handlers + explicit raises | binary-search expr instr | source fidelity |
| Dependency Closure | unit, with graph | needed-but-missing list | BFS over with clauses | Apache-2.0 | strict | weak resolution | cycles |
| Stub/Mock Gen | missing decls | synthetic specs/bodies | infer from references | Apache-2.0 | spec stubs | discriminants/tagged | hidden bugs |
| Fake CORBA Gen | IDL/heuristics | Ada packages | full mapping (Helper/Skel/Stub) | Apache-2.0 | minimal CORBA, PortableServer | TypeCode/Any helpers | ORB fidelity |
| Synthetic Project Gen | harness + deps | `.gpr` | template, per-unit Ada std switches | Apache-2.0 | works with gprbuild | multi-language, cross-tc | gprbuild quirks |
| Compiler Adapter | `.gpr` | object files / diags | spawn gprbuild/gnatmake; capability probe | Apache-2.0 | parse `.../foo.ads:LINE:COL: <msg>`, `-gnatdJ` JSON | colorized variants | locale/version |
| Fuzz Engine | harness | corpus + findings | shm/files + mutators | Apache-2.0 | built-in | AFL++/LibAFL adapters | feedback fidelity |
| Probe Runtime (Ada 95) | harness | event stream | per-task ring buffer + binary log | Apache-2.0 | events for handlers/raises/breadcrumbs | resource counters | non-reentrancy |
| Corpus Manager | inputs + sigs | dedup'd corpus | hashed + signature-tagged | Apache-2.0 | retain by exception signature | LRU + minimization | disk growth |
| Replay/Minimize | finding | minimal repro | ddmin over byte input | Apache-2.0 | byte-level ddmin | typed-value minimize | local minima |
| Report Generator | findings | JSON/MD/SARIF 2.1/JUnit | template engine | Apache-2.0 | JSON+MD | SARIF+JUnit+repro Ada | drift |
| Daemon (M18) | JSON-RPC | findings/scan results | LSP-flavored JSON-RPC | Apache-2.0 | — | continuous fuzz, IDE plug-ins | sync with CLI |

---

## 4. Source scanning strategy without Libadalang

### 4.1 Tier 1 — permissive structural scanner

Two paths share the same `StructuralAst`:

1. **From-scratch lexer** (Apache-2.0). A hand-written DFA recognizes Ada 95/2005/2012/2022 reserved words, numeric and based literals (with `'`-style attribute disambiguation), strings, character literals, identifiers, and punctuation. Reserved-word sets are dialect-parameterized: `interface`/`overriding`/`synchronized` reserved at ≥2005, `some` (context-dependent) at ≥2012, `parallel` (block) at ≥2022. The lexer emits tokens with byte offsets and line/column.
2. **tree-sitter-ada** (MIT) for structural parses; we use it as a second opinion and primary structure provider when present.

A shim layer fuses them: tree-sitter gives node spans; the from-scratch lexer gives token text and authoritative offsets when ts-ada disagrees.

Tier 1 extracts: compilation units (spec/body/subunit), packages (incl. child and generic), subprogram specs and bodies, parameter lists with mode (`in`/`out`/`in out`/`access`), exception handlers, explicit `raise` statements, `with`/`use`/`use type`/`use all type` clauses, type declarations (scalar/enum/array/record/discriminated/access/derived/tagged/abstract/interface/private/generic-formal), representation clauses, aspect specifications, pragmas.

It does **not** require legality. A unit that fails type-checking still parses to a usable `StructuralAst`.

### 4.2 Tier 2 — build-assisted refinement

When the user has a compiler:

1. Generate a probe project: minimal `.gpr` compiling `target.adb` plus its `with` closure.
2. Invoke `gprbuild -c -gnatc -f -p -P probe.gpr` (syntax+semantic check, no link).
3. Parse diagnostics with a **version-agnostic** regex grammar covering FSF GNAT 11..14+; second pass parses `-gnatdJ` JSON output when available.
4. Refine `StructuralAst`: resolve type aliases, mark missing dependencies for stub generation, promote inferred types.

We never link compiler libraries.

### 4.3 Optional Libadalang plug-in

Out-of-process JSON-RPC; never linked. Reference implementation lives in a separate repo `govfuzz-lal-plugin` under GPLv3 (matching Libadalang). The `strict-permissive` build never invokes it.

```
Request:  { "method": "resolve_unit", "unit_path": "...", "with_closure": [...], "limits": { "time_ms": 5000 } }
Response: { "types": [...], "subprograms": [...], "diagnostics": [...] }
```

### 4.4 Scanner data model

```rust
struct Unit { id, path, kind: Spec|Body|Subunit, ada_standard: Ada95|Ada2005|Ada2012|Ada2022,
              withs: Vec<UnitRef>, pragmas: Vec<Pragma>, packages: Vec<PackageId>, ... }
struct Pragma { name, args }
struct Package { id, name, parent: Option<PackageId>, is_generic, formals, decls }
struct Subprogram {
    id, owner: SubprogramOwner, name, kind: Procedure|Function|Entry|Operation,
    params: Vec<Parameter>, return_type: Option<TypeRef>,
    is_abstract, is_dispatching, is_overriding,
    body_span: Option<Span>, decl_span: Span,
    handlers: Vec<HandlerId>, raises: Vec<RaiseSiteId>,
    visibility: Public|Private|LibraryLevel|Local,
}
struct SubprogramOwner = LibraryLevel | Package(PackageId)
struct Parameter { name, mode: In|Out|InOut|AccessMode, type_ref: TypeRef, default: Option<Expr> }
struct TypeRef { id, name_path,
    visibility: Public|Private|LibraryLevel|Local,
    owner: TypeOwner,
    kind: Scalar(ScalarKind) | Enum(Vec<Lit>) | Array(IdxTypes,ElemType,Bounds)
        | Record(Fields) | Discriminated(...) | Tagged(...) | Derived(Base)
        | Interface { parents: Vec<Name>, kind: InterfaceKind } | Access(Target)
        | Private | Generic(FormalKind) | Unknown,
    constraints: Constraints, aspects: Aspects }
struct TypeOwner = LibraryLevel | Package(PackageId) | Subprogram(SubprogramId)
enum InterfaceKind { Plain, Limited, Synchronized, Task, Protected }
struct ExceptionHandler { id, owner: HandlerOwner, choices: Vec<Choice>, binds: Option<Identifier>,
                          span: Span, body_span: Span }
struct HandlerOwner = Subprogram(SubprogramId) | PackageBody(PackageId)
struct RaiseSite { id, kind: Explicit|Reraise, exception: Option<Name>, message: Option<Expr>, span: Span }
struct StatementSpan { id, owner: StatementOwner, file_byte_offset, end_byte_offset,
                       line, col, depth, index_in_block }
struct StatementOwner = Subprogram(SubprogramId) | PackageBody(PackageId)
struct Dependency { id, kind: Real|Stubbed|Fake, real_path: Option<Path>, generated_path: Option<Path> }
struct BuildArtifact { id, source_unit, instrumented_path, object_path, ... }
struct CorbaArtifact { id, idl_path: Option<Path>, package_name, op_list,
                       kind: Idl|GeneratedAda|ServantImpl|Helper|Skel|Stub }
```

`Derived` and `Interface` are modeled separately because tagged, derived,
interface, and generic-formal types drive different downstream harness choices.
Conflating them would discard information before the Type Model and Byte→Value
Decoder can make a safe decision.

---

## 5. Entry-point discovery and ranking

### 5.1 Candidate categories

Public package procedures/functions, library-level subprograms, tagged-type primitive ops, factories/constructors, parsers (params include strings/streams/arrays), range-constrained scalar consumers, anything using slices/discriminants/variants/`Unchecked_Conversion`/access types/`Unchecked_Deallocation`/tasking/protected objects, ops adjacent to handlers, ops that call or are called by exception-heavy code, CORBA servant impls, generated skeleton dispatch, IDL operation impls, package-level workflows that imply a state machine.

### 5.2 Score function

```
score(t) =
    20 * is_public(t)
  + 15 * has_swallowed_when_others_in_pkg(t)
  + 10 * count_explicit_raises_in_or_below(t)
  +  8 * count_handlers_in_or_below(t)
  +  5 * count_fuzzable_params(t)
  +  5 * has_range_constrained_scalar(t)
  +  4 * has_array_index_or_slice(t)
  +  4 * has_discriminant_or_variant(t)
  +  4 * uses_unchecked_conversion(t)
  +  4 * has_access_param(t)
  +  3 * has_tagged_dispatch(t)
  +  3 * is_corba_servant_op(t)
  +  3 * is_idl_op_impl(t)
  +  2 * uses_protected_or_task(t)
  -  3 * is_trivial_getter_setter(t)
  - 10 * unconstructible_limited_private(t)
  + 10 * adjacent_to_handler(t)
```

Trivial accessors that participate in state transitions get re-promoted at the *sequence* layer.

---

## 6. Automatic harness generation

### 6.1 Harness types

| Type | When chosen |
|---|---|
| Direct subprogram | Public sub, fuzzable params, no awkward deps |
| Package-level | All public ops over a shared state; sequences |
| Stateful sequence | Detected mutators + observers in same package |
| Private-state wrapper | Private types reachable via constructor + observers |
| Access-type wrapper | Access params reachable from harness-owned storage |
| Tagged-type dispatch | Class-wide param dispatch over known concretes |
| Generic instantiation | Generic packages + plausible actuals |
| Exception-heavy block | Specific block known to swallow |
| CORBA servant-direct | Servant impl callable by Ada method invocation |
| Fake-CORBA servant | Skeleton dispatch through synthesized fake CORBA |
| Differential | direct vs wrapper, returns compared |
| Build-probe | Detect missing deps without fuzzing |

Stateful sequence harnesses are Ada/C/C++ only; package-level and
servant-direct (CORBA) harnesses are Ada-only. The Rust, Java, Python, Perl, and
Go lanes emit direct harnesses only (no public sequence harness).

### 6.2 Required harness behavior

- Compiles standalone where the call surface allows it.
- Reads bytes from stdin (built-in engine), file (replay), or shared memory (AFL++/LibAFL).
- Decodes deterministically into Ada values via `AdaFuzz.Decode`.
- Calls target.
- Logs pre/post telemetry via `AdaFuzz.Probe`.
- Top-level safety net catches everything *only* to record final state — never to swallow bugs invisibly.
- Saves new exception signatures.
- Replay reads same bytes from a file; identical output expected.
- Minimize uses ddmin on bytes, then on decoded fields.
- Original sources are never modified; instrumented copies live in `govfuzz_work/src_instrumented/`.

### 6.3 Working tree layout

```
govfuzz_work/
  config.snapshot.json
  scan_index.bin
  src_instrumented/
  generated_runtime/
  generated_harnesses/<harness_id>/main.adb
  generated_stubs/<unit>/...
  fake_corba/
  build/<harness_id>/
  corpus/<harness_id>/{queue, crashes, swallowed, sigs}
  findings/<finding_id>/{testcase.bin, decoded.json, finding.json, repro.adb}
  reports/{run-<ts>.json, run-<ts>.md, run-<ts>.sarif}
```

---

## 7. Swallowed-exception detection

This is the load-bearing section. Two complementary paths:

- **Default — source instrumentation.** Available in all profiles, no GNAT-specific hooks.
- **Day-one optional — `--probe gnat_actions`.** `external-tools` only; uses `GNAT.Exception_Actions.Register_Global_Action` to capture every raise before any handler runs.

The Ada 95 baseline guarantees `Ada.Exceptions` is available, so handler probes always carry both name and message.

### 7.1 The instrumentation contract

We rewrite a copy of every implementation file selected as a target or in-target's elaboration closure. Each rewrite is span-precise: tokens inserted only at well-defined points (statement boundaries, handler heads, explicit raise sites). Executable order is never changed.

Three rewrites:

1. **Statement breadcrumb** before every statement in a sequence_of_statements: insert `AdaFuzz.Probe.Breadcrumb (<ID>);`. Sidecar `breadcrumbs.json` maps ID → `{file, line, col, subprogram, depth, idx}`.
2. **Handler entry** for every `when <choices> =>`: bind the occurrence (reuse user binding if present, else introduce `AdaFuzz_E`) and prepend an `On_Handler_Entry` call.
3. **Explicit raise probe** before every `raise X [with M];` or bare `raise;` insert `On_Explicit_Raise(...)`.

### 7.2 Examples

**Original (handler with no binding):**

```ada
exception
   when others =>
      Cleanup;
      return Default;
```

**Instrumented:**

```ada
exception
   when AdaFuzz_E : others =>
      AdaFuzz.Probe.On_Handler_Entry
        (Exception_Name    => Ada.Exceptions.Exception_Name (AdaFuzz_E),
         Exception_Message => Ada.Exceptions.Exception_Message (AdaFuzz_E),
         Handler_File      => "foo.adb",
         Handler_Line      => 123,
         Last_Breadcrumb   => AdaFuzz.Probe.Last_Breadcrumb,
         Target_Id         => AdaFuzz.Probe.Current_Target,
         Testcase_Id       => AdaFuzz.Probe.Current_Testcase);
      Cleanup;
      return Default;
```

**Original (specific handler):**

```ada
exception
   when Constraint_Error =>
      return 0;
```

**Instrumented:**

```ada
exception
   when AdaFuzz_E : Constraint_Error =>
      AdaFuzz.Probe.On_Handler_Entry
        (Exception_Name    => "CONSTRAINT_ERROR",
         Exception_Message => Ada.Exceptions.Exception_Message (AdaFuzz_E),
         Handler_File      => "foo.adb",
         Handler_Line      => 87,
         Last_Breadcrumb   => AdaFuzz.Probe.Last_Breadcrumb,
         Target_Id         => AdaFuzz.Probe.Current_Target,
         Testcase_Id       => AdaFuzz.Probe.Current_Testcase);
      return 0;
```

**Original (explicit raise; Ada 2005+ form):**

```ada
raise Constraint_Error with "bad length";
```

**Instrumented:**

```ada
AdaFuzz.Probe.On_Explicit_Raise
  (Exception_Name => "Constraint_Error",
   File           => "foo.adb",
   Line           => 88,
   Breadcrumb     => AdaFuzz.Probe.Last_Breadcrumb);
raise Constraint_Error with "bad length";
```

For Ada 95 sources (no `with M`), the explicit-raise probe omits the message but is otherwise identical.

### 7.3 Correctness rules

- Never inject inside a single expression; only between statements.
- Never inject between a label and its statement; emit before the label.
- Never inject inside a `pragma` argument list, between `if`/`elsif` conditions and the `then`, or inside a `case` selector.
- Inserting before `accept`, `select`, `delay`, `requeue` is allowed; the probe call cannot block.
- Renames-as-body and **expression functions** (Ada 2012+) are skipped by default; `--instrument-expr-fns` opts in to a body-conversion rewrite.
- For `extended_return_statement`, insert the breadcrumb before the `return ... do` and on each statement inside the `do ... end return`.
- Re-raise (`raise;`): we insert the explicit-raise probe with `<reraise>` as name; the `Last_Breadcrumb` carries source attribution.
- The handler body retains its original control flow including `goto`, `exit`, `return`, re-raise. The probe is the *first* statement in the handler.
- Ada 2022 declare expressions, parallel blocks, `@` target name: parallel-block bodies are sequence_of_statements; breadcrumbs go in. Probe runtime is reentrant per task.

### 7.4 Breadcrumb ID strategy

- 32-bit IDs assigned in unit-then-source-order.
- Cheap: `Breadcrumb` writes one 32-bit value into a per-task ring slot; no heap, no system call.
- Ring keeps the last N IDs (N=16 default).
- Sidecar `breadcrumbs.json` maps ID → source span.
- Optional finer-grained instrumentation (off by default): split a complex right-hand side into temporaries with a probe between, used only for binary-search instrumentation on an active finding.

### 7.5 Exception classification

| Class | How detected |
|---|---|
| Unhandled | Top-level `when others =>` in harness fires |
| Swallowed predefined | Handler probe with `is_predefined(name)` and original handler returns/continues |
| Swallowed user | Handler probe with name resolving to a user exception decl |
| Explicit raise | `On_Explicit_Raise` precedes the same `On_Handler_Entry` |
| Implicit runtime check | Handler entry without preceding explicit raise of same name |
| Translated | Handler entry of name X *and* explicit raise of Y in same call |
| CORBA-style wrapper | Handler entry whose name resolves to a fake-CORBA exception |
| Exception storm | More than K handler entries per testcase |
| Timeout/deadlock after exception | No `End_Testcase` within deadline; last event is a handler entry |

### 7.6 `--probe gnat_actions` (day one, `external-tools` only)

Crate `crates/probe_gnat_actions/` (Apache-2.0 wrapper code only). Generates an additional Ada package `AdaFuzz.Probe.Gnat_Actions` that calls `GNAT.Exception_Actions.Register_Global_Action (On_Raise'Access)` from elaboration. Captures every raise (including ones consumed by handlers we did not rewrite — third-party closed-source code in particular).

`THIRD_PARTY.md` documents the GCC RLE boundary: the user's compiled binary uses GNAT.Exception_Actions through the same RLE that covers any GNAT-compiled program; we ship no GNAT runtime source ourselves.

`strict-permissive` build refuses to enable this probe; CI test asserts it.

### 7.7 Exception signature

```
sha256(
  target_id || "\0" ||
  exception_name || "\0" ||
  handler_file || ":" || handler_line || "\0" ||
  last_breadcrumb_id || "\0" ||
  explicit_raise_id_or_blank || "\0" ||
  call_seq_index_zero_padded || "\0" ||
  param_shape_hash || "\0" ||
  return_class || "\0" ||
  resource_signal
)
```

Every new signature is corpus-promoting feedback.

---

## 8. Exception telemetry runtime

All Apache-2.0. Compiled into the harness, not user production code. Implemented in **Ada 95** and compiled with `pragma Ada_95`; links cleanly against units compiled at 95/2005/2012/2022. Single API surface — `On_Handler_Entry` and `On_Explicit_Raise` carry both name and message because the Ada 95 baseline guarantees `Ada.Exceptions` is available.

### 8.1 `adafuzz-probe.ads`

```ada
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Interfaces;

package AdaFuzz.Probe is

   pragma Preelaborate;

   subtype Crumb_Id    is Interfaces.Unsigned_32;
   subtype Target_Id   is Interfaces.Unsigned_32;
   subtype Testcase_Id is Interfaces.Unsigned_64;

   procedure Begin_Testcase (TC : Testcase_Id);
   procedure End_Testcase   (Result_Class : Interfaces.Unsigned_8 := 0);
   procedure Set_Target     (T : Target_Id);
   procedure Flush;

   procedure Breadcrumb (Id : Crumb_Id);
   pragma Inline (Breadcrumb);

   function Last_Breadcrumb return Crumb_Id;
   function Current_Target  return Target_Id;
   function Current_Testcase return Testcase_Id;

   procedure On_Handler_Entry
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id);

   procedure On_Explicit_Raise
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : Crumb_Id);

   procedure On_Top_Level_Catch
     (Exception_Name    : String;
      Exception_Message : String);

   procedure Mock_Call (Symbol : String);

end AdaFuzz.Probe;
```

### 8.2 `adafuzz-probe.adb` (sketch)

```ada
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams.Stream_IO;
with Interfaces; use Interfaces;

package body AdaFuzz.Probe is

   Ring_Size : constant := 16;
   type Ring is array (0 .. Ring_Size - 1) of Crumb_Id;

   Crumbs   : Ring := (others => 0);
   Cursor   : Natural := 0;
   Cur_Tgt  : Target_Id := 0;
   Cur_TC   : Testcase_Id := 0;
   Buf      : Ada.Streams.Stream_IO.File_Type;
   Buf_Open : Boolean := False;

   procedure Open_If_Needed is
   begin
      if not Buf_Open then
         Ada.Streams.Stream_IO.Create
           (Buf, Ada.Streams.Stream_IO.Append_File, Name => Get_Event_Path);
         Buf_Open := True;
      end if;
   exception
      when others => null;  --  probes never raise
   end Open_If_Needed;

   procedure Begin_Testcase (TC : Testcase_Id) is
   begin
      Cur_TC := TC;
      Cursor := 0;
      Crumbs := (others => 0);
      Open_If_Needed;
      Write_Event (Tag => Tag_Begin, U64 => Unsigned_64 (TC));
   exception
      when others => null;
   end Begin_Testcase;

   procedure Set_Target (T : Target_Id) is
   begin
      Cur_Tgt := T;
      Write_Event (Tag => Tag_Target, U32 => Unsigned_32 (T));
   exception
      when others => null;
   end Set_Target;

   procedure Breadcrumb (Id : Crumb_Id) is
   begin
      Crumbs (Cursor) := Id;
      Cursor := (Cursor + 1) mod Ring_Size;
      Write_Event (Tag => Tag_Crumb, U32 => Id);
   exception
      when others => null;
   end Breadcrumb;

   function Last_Breadcrumb return Crumb_Id is
     (Crumbs ((Cursor + Ring_Size - 1) mod Ring_Size));

   function Current_Target  return Target_Id   is (Cur_Tgt);
   function Current_Testcase return Testcase_Id is (Cur_TC);

   procedure On_Handler_Entry
     (Exception_Name    : String;
      Exception_Message : String;
      Handler_File      : String;
      Handler_Line      : Natural;
      Last_Breadcrumb   : Crumb_Id;
      Target_Id         : AdaFuzz.Probe.Target_Id;
      Testcase_Id       : AdaFuzz.Probe.Testcase_Id) is
   begin
      Write_Handler_Event (Exception_Name, Exception_Message,
                           Handler_File, Handler_Line,
                           Last_Breadcrumb, Target_Id, Testcase_Id);
   exception
      when others => null;
   end On_Handler_Entry;

   procedure On_Explicit_Raise
     (Exception_Name : String; File : String; Line : Natural; Breadcrumb : Crumb_Id) is
   begin
      Write_Explicit_Raise_Event (Exception_Name, File, Line, Breadcrumb);
   exception
      when others => null;
   end On_Explicit_Raise;

   procedure End_Testcase (Result_Class : Interfaces.Unsigned_8 := 0) is
   begin
      Write_Event (Tag => Tag_End, U8 => Result_Class);
      Flush;
   exception
      when others => null;
   end End_Testcase;

   procedure Flush is
   begin
      if Buf_Open then
         Ada.Streams.Stream_IO.Flush (Buf);
      end if;
   exception
      when others => null;
   end Flush;

end AdaFuzz.Probe;
```

`Write_Event`, `Write_Handler_Event`, `Write_Explicit_Raise_Event`, `Get_Event_Path`, and tag constants are private helpers: a fixed-size `Stream_Element_Array` writer with a 1-byte tag plus typed payload. JSON-lines variant is selectable via build flag.

### 8.3 Probe runtime backends

For cross-compilation (§13.5) the runtime is parameterized at build time by backend:

| Backend | Use | Notes |
|---|---|---|
| `host_file` | Default; host fuzzing | `Ada.Streams.Stream_IO`. |
| `memory_buffer` | Embedded with no FS | Fixed-size in-RAM ring; runner drains via emulator/JTAG/serial. |
| `semihosting` | ARM/RISC-V semihosting | Writes to host fd; gated on runtime support. |
| `stub` | ROM-only smoke runs | No output; signature counted via return code. |

### 8.4 `AdaFuzz.Input` / `AdaFuzz.Decode` (signatures)

```ada
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams; use Ada.Streams;
package AdaFuzz.Input is
   procedure Load_From_Stdin (Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
   procedure Load_From_File  (Path : String; Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
   procedure Load_From_Shared_Memory (Buf : out Stream_Element_Array; Last : out Stream_Element_Offset);
end AdaFuzz.Input;
```

```ada
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_95;
with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
package AdaFuzz.Decode is
   type Cursor is private;
   function Open (Buf : Stream_Element_Array; Last : Stream_Element_Offset) return Cursor;
   function U8  (C : in out Cursor) return Unsigned_8;
   function U16 (C : in out Cursor) return Unsigned_16;
   function U32 (C : in out Cursor) return Unsigned_32;
   function U64 (C : in out Cursor) return Unsigned_64;
   function I32 (C : in out Cursor) return Integer_32;
   function F64 (C : in out Cursor) return Long_Float;
   function Bool (C : in out Cursor) return Boolean;
   function Bounded_Range (C : in out Cursor; Lo, Hi : Integer) return Integer;
   function Bytes (C : in out Cursor; Min, Max : Natural) return Stream_Element_Array;
   function Ada_String (C : in out Cursor; Min, Max : Natural) return String;
   --  Wide_String / Wide_Wide_String decoders only emitted at ≥2005.
private
   type Cursor is record
      Data : access constant Stream_Element_Array;
      Pos  : Stream_Element_Offset;
      Last : Stream_Element_Offset;
   end record;
end AdaFuzz.Decode;
```

---

## 9. Multi-version Ada support (95, 2005, 2012, 2022)

### 9.1 Capability matrix

| Feature | 95 | 2005 | 2012 | 2022 |
|---|---|---|---|---|
| `Ada.Exceptions` (occurrence type, name, message) | ✓ | ✓ | ✓ | ✓ |
| `when X : E =>` occurrence binding | ✓ | ✓ | ✓ | ✓ |
| `raise X with "msg"` | — | ✓ | ✓ | ✓ |
| Child packages, tagged types, protected types | ✓ | ✓ | ✓ | ✓ |
| Interfaces, anonymous access, `not null`, `limited with` | — | ✓ | ✓ | ✓ |
| Aspects, expression functions, `if`/`case`/quantified expressions | — | — | ✓ | ✓ |
| `'Image` for non-scalar, declare expressions, `@`, `'Reduce`, parallel blocks | — | — | — | ✓ |
| Reserved-word delta vs prior | baseline | +`interface`,`overriding`,`synchronized` | +`some` (context) | +`parallel` (block) |

### 9.2 Detection (per unit)

1. `pragma Ada_95` / `Ada_05` / `Ada_2005` / `Ada_12` / `Ada_2012` / `Ada_2022`.
2. `.gpr` `Default_Switches ("Ada")` containing `-gnat95/05/12/2022`.
3. CLI `--ada-standard <ver>`.
4. Heuristic feature promotion (e.g., `interface` keyword → ≥2005; aspect spec → ≥2012; declare expression → ≥2022).
5. Default: `2012`.

A unit declaring `pragma Ada_83` is accepted as the `Ada83` dialect (M22 §29):
it is lexed with the reduced Ada 83 keyword set (post-83 reserved words are
ordinary identifiers), parsed best-effort, and routed to the report-only path
(discovered + statically analyzed, built with `-gnat83`) rather than rejected.

`scan_index.bin` records `ada_standard` per unit.

### 9.3 Lexer & parser dialect handling

Reserved-word sets parameterized by detected standard. Tokens emitted with both `kind` and `effective_kind_in_unit_standard`. The from-scratch parser has a `dialect` parameter; production rules are gated:

- 95: tagged/protected/child/`Ada.Exceptions`-aware patterns enabled.
- 2005: enables `interface`, anonymous access in profiles, `not null`, `limited with`, `raise X with M`.
- 2012: enables aspect specifications, expression functions, `if`/`case` expressions, quantified expressions.
- 2022: enables `@`, declare expressions, parallel blocks, `'Image` for non-scalars.

On dialect mismatch (user-claimed Ada 95 but source uses aspects), we re-parse with the next-higher dialect and emit a warning; we do not refuse to scan.

### 9.4 Probe runtime portability

- Implemented in **Ada 95**, compiled with `pragma Ada_95`. Links cleanly against units compiled at 95/2005/2012/2022.
- Single API surface; uses `Ada.Exceptions` unconditionally.
- No conditional compilation needed in the runtime body.

### 9.5 Synthetic project & compiler flags

`.gpr` includes `for Source_Dirs use (...)`; `package Compiler` sets per-unit `-gnat95/05/12/2022` driven by the unit's detected standard. Cross-dialect projects work; each unit compiles in its own standard, the runtime in 95.

### 9.6 Tests per dialect

`tests/dialect/`:

- `ada95/swallowed_when_others/`
- `ada2005/raise_with_message/`
- `ada2012/expression_function_handler/`
- `ada2022/parallel_block_breadcrumb/`

CI matrix: FSF GNAT 11/12/13/14 × dialects 95/2005/2012/2022.

---

## 10. Partial-build and dependency stub generation

### 10.1 Algorithm

```
fn build_for_target(t):
    work = init_workdir()
    closure = compute_with_closure(t)
    copy_real_units(closure, work.src_instrumented)
    instrument(closure ∩ instrumentation_set, work.src_instrumented)
    write_runtime(work.generated_runtime)
    write_harness(t, work.generated_harnesses)
    needed = scan_unresolved_refs(work.src_instrumented ∪ work.generated_harnesses)
    iter = 0
    loop:
        iter += 1
        if iter > MAX_ITER: classify_blocked(t); return Err
        gpr = synth_project(work, needed_stubs, fake_corba_for(t))
        diags = run_compiler(gpr, mode=check_only)
        if diags.is_clean(): break
        new_needed = derive_stub_needs(diags)
        if new_needed ⊆ needed:
            classify_blocked(t, diags); return Err
        needed = needed ∪ new_needed
        regenerate_stubs(needed, work.generated_stubs)
    final = run_compiler(gpr, mode=full_build)
    return final
```

### 10.2 Stub generation rules

- **Missing package spec** — generate `<Pkg>.ads` with `pragma Preelaborate` and only the visible declarations referenced from real code: types as opaque private with discriminants inferred when used, subprograms with mode-correct profiles, exception declarations.
- **Missing package body** — return neutral values: `0`, `False`, `""`, default-aggregate records, `null` access values. For `out`/`in out`, emit `<Param> := (others => <neutral>);` or skip if type is private.
- **Missing function** — option A: deterministic from input via `AdaFuzz.Decode` (when on the call path of a fuzz target). Option B: neutral default.
- **Missing procedure** — log call via `AdaFuzz.Probe.Mock_Call`, optionally write a deterministic value into out/in-out parameters.
- **Missing tasks/protected objects** — generate non-task replacement with the same operation set; mark fidelity-impacting in the report.
- **Missing files/network/database** — generated mock with a mode flag: `success`, `fail`, `random` (driven by fuzz input).
- **Missing CORBA** — see §11.

The report records, per finding: real, instrumented, stubbed, fake-CORBA, plus a confidence number derived from `1 - stub_weight × calls_through_stub`.

---

## 11. Fake CORBA strategy from scratch — full Ada language mapping

### 11.1 Modes

| Mode | Trigger | Output |
|---|---|---|
| IDL-only schema | `*.idl` exists | Fake CORBA + IDL→Ada packages + servant skeletons |
| Generated-Ada scan | `*.ads` looks generated | Adopt those packages; fill missing pieces |
| Servant-direct | Only servant `.adb` available | Reflect ops from impl, generate fake parent + ref types |
| Fake-ORB compile | Anything above | Synthesize enough surface for `gprbuild` to succeed |
| External real-ORB adapter | User opts in, `external-tools` | Replace fakes with real ORB packages at link time |
| Raw IIOP | `research-lab` only | Out of scope for v1 |

### 11.2 Detection heuristics

IDL files; package names containing `CORBA`, `PortableServer`, `POA`, `Skeleton`, `Impl`, `IDL`, `Any`, `Helper`, `Stub`; servant base type inheritance like `PortableServer.Servant_Base`; operation names matching IDL operation list; user exception-mapping packages (`Foo_Exceptions`); sequence helper patterns (`Sequence_Of_<X>`); object-reference types ending `_Ref`; subprogram parameter modes consistent with IDL `in`/`out`/`inout`.

### 11.3 Full IDL→Ada mapping (M11 contract)

- Modules → hierarchical packages.
- Interfaces → tagged-type `Ref` + `Object` impl base + `Skel` dispatcher + `Stub` placeholder.
- `Helper` packages with `From_Any` / `To_Any` / `TC_*` typecode constants.
- `sequence<T>`, `sequence<T,N>` → bounded/unbounded array packages with `Sequence_Of_*` helpers.
- `struct`, `enum`, `union` (full discriminator semantics), `typedef`, `const`, `exception` with member fields.
- `attribute` (read/write subprograms), `oneway`, `readonly`.
- Inheritance (single + multiple-of-abstract), `valuetype` and `eventtype` if encountered.
- `wstring`, `wchar`, `fixed<digits,scale>`.
- `Any` and `TypeCode` packages emitted with operations the target actually uses (lazy expansion driven by reference scanner).
- IDL preprocessor: support `#include`, `#ifdef`, `#define` via a vendored from-scratch CPP-lite (Apache-2.0, ~600 LOC) — no dependency on a host C preprocessor.
- Vendor pragmas: `#pragma prefix`, `#pragma version` parsed and honored; unknown pragmas tolerated and recorded.

Goal: a real-world IDL file from a representative legacy project compiles to Ada that builds against fake CORBA without manual edits.

### 11.4 Fake CORBA package surface (samples)

`fake_corba/corba.ads`:

```ada
--  SPDX-License-Identifier: Apache-2.0
package CORBA is
   pragma Pure;
   type Long is new Integer;
   type Unsigned_Long is mod 2**32;
   type Short is range -2**15 .. 2**15 - 1;
   type Unsigned_Short is mod 2**16;
   type Boolean is new Standard.Boolean;
   type Float is new Standard.Float;
   type Double is new Standard.Long_Float;
   type String is new Standard.String;
   type Octet is mod 2**8;
   type Octet_Array is array (Positive range <>) of Octet;
end CORBA;
```

`fake_corba/corba-object.ads`:

```ada
--  SPDX-License-Identifier: Apache-2.0
package CORBA.Object is
   type Ref is tagged null record;
   function Is_Nil (R : Ref) return Boolean is (True);
end CORBA.Object;
```

`fake_corba/portableserver.ads`:

```ada
--  SPDX-License-Identifier: Apache-2.0
package PortableServer is
   pragma Preelaborate;
   type Servant_Base is abstract tagged null record;
   type Servant is access all Servant_Base'Class;
end PortableServer;
```

### 11.5 Fuzzing priorities

1. Direct servant method calls — bypass everything else.
2. Wrapped calls when the wrapper still builds.
3. Fake object refs as `null`/factory-fake — observe servant code path.
4. Fake `Any`/`TypeCode` only if the target operation actually inspects them.
5. IDL-driven type generation when IDL exists.
6. Stateful sequences from IDL operation sets per interface.
7. Optional external real-ORB adapter for users who have one.

---

## 12. Type-aware input generation

### 12.1 Decoder (general shape)

`AdaFuzz.Decode` consumes a typed sequence: 1 byte → bias selector (boundary / mostly-valid / dictionary / random); N bytes → typed payload according to decode rule; recurse for compound types.

### 12.2 Rules per type kind

- **Boolean**: 1 byte; bias false/true.
- **Integer ranges**: 4 bytes; with 25% probability return one of `Lo`, `Lo+1`, `Hi-1`, `Hi`, `0`, `-1`; else clamp `value mod (Hi-Lo+1) + Lo`.
- **Modular**: same minus negative anchors.
- **Float**: bias to `+0`, `-0`, `NaN`, `+∞`, `-∞`, denormals; otherwise interpret as F64.
- **Fixed point**: integer encoding × delta; verify range.
- **Enumerations**: byte mod N.
- **Characters**: ASCII 7-bit + curated dictionary (NUL, `'`, `"`, `\\`, high-bit, etc.).
- **Strings**: length from `Bounded_Range(Min, Max)`; bytes from byte stream; with 10% probability draw from string dictionary.
- **Wide / Wide_Wide strings** (≥2005): UTF-16/UTF-32 code unit streams.
- **Arrays**: length encoded if unconstrained; elements recurse.
- **Records**: fields recurse in declaration order.
- **Discriminated records**: pick discriminant first; fields follow chosen variant.
- **Access types**: harness owns a slot table; decoder picks slot index, may pick null.
- **Tagged types**: pick concrete from a constructor registry discovered by the scanner.
- **Limited types**: only via wrapper subprograms identified as constructors.
- **Private types**: only via visible constructors or generated child packages; otherwise skip target.
- **Containers**: only when concrete instantiations are visible.
- **CORBA sequences/structs/unions/enums**: as Ada array/record/discriminated/enum.
- **Object references**: null / harness-fake / IDL-typed factory.
- **In/out/inout**: out/inout begin at deterministic neutral; we also re-feed inout with input bytes for diversity.

### 12.3 Dictionary curation (noise reduction)

Mining rules (from §6 answer):

- **Source-only**: never mine from system Ada units (`Ada.*`, `System.*`, `Interfaces.*`, `GNAT.*`) or `fake_corba/`.
- **Length cap**: 4..256 bytes for strings; 1..32 for identifiers.
- **Per-type buckets**: separate dictionaries for `String`, `Wide_String`, `Wide_Wide_String`, enumeration literal sets per enum type, exception-name set, IDL operation-name set, integer constants per scalar type. A target-`String` parameter never gets fed enum literals.
- **Proximity weighting**: per-target dictionary scored by callgraph distance from target — full weight in/one-hop from target body, exponential decay further out, floor weight in leaf utilities.
- **Dedup**: case-folded, whitespace-normalized; near-duplicates collapsed via 4-gram Jaccard ≥ 0.9.
- **Boilerplate filter**: drop SPDX/copyright/URL patterns; drop pure-punctuation or single-token English filler.
- **Frequency cap**: top-K by occurrence per bucket per target (K=64; `--dict-top` configurable).
- **Provenance**: each retained entry carries `(source_unit, span)` for replay traceability.

### 12.4 Testcase format (engine-independent)

```
Header (16B)  : magic "GFZC", version, flags
TLV block 0   : raw_input_bytes
TLV block 1   : decoded_typed_values (CBOR)
TLV block 2   : harness_id, target_id, build_context_id, stub_context_id
TLV block 3   : call_sequence (ordered op list)
TLV block 4   : exception_signature
TLV block 5   : replay_metadata (cwd, env subset, time, seeds, target/runtime/toolchain)
```

---

## 13. Fuzz engines

### 13.1 Built-in (MVP, mandatory)

- Mutators: bit-flip, byte-flip, arithmetic, interesting values, splice, dictionary insert, structure-aware (typed-value mutation when decode succeeded).
- Coverage proxy: exception signatures + breadcrumb bitmap + handler bitmap + return-class bitmap + mock-call trace bitmap.
- Scheduler: power-schedule favoring inputs that unlock new bits.
- Persistent harness mode: forked-child loop reading testcases from a queue file.
- Deterministic replay from a saved testcase.

### 13.2 AFL++ adapter

- Persistent mode (`__AFL_LOOP`).
- Thin C shim under `crates/fuzz_engine/afl_adapter/` (Apache-2.0).
- Forks the harness binary; maps shared memory.
- Translates exception signatures into AFL++ feedback via custom-mutator hook.
- Native C/C++ targets only; Ada, Rust, Java, Python, Perl, and Go use the built-in engine.
- User-installed; not bundled.

### 13.3 LibAFL adapter

- Optional Cargo feature `libafl-engine`.
- Embed `StdState`, `IndexesLenTimeMinimizerScheduler`, custom observer reading our event stream.
- Single-binary fuzzer driver.

### 13.4 libFuzzer adapter

- Only when an LLVM/Ada path exists in the user's toolchain.
- Wrap our harness behind `LLVMFuzzerTestOneInput`.

### 13.5 Cross-compilation (first-class)

- **Project synthesis** honors `Target`, `Runtime`, `Toolchain` attributes; CLI flags `--target <triple>`, `--runtime <name>`, `--toolchain <prefix>`.
- **Compiler adapter** invokes `<triple>-gnat`/`<triple>-gprbuild` when `--toolchain` is set. Detection probe runs the cross-compiler in `-gnatc` mode against a canary; failure surfaces a clear "host toolchain X for target Y not found" error.
- **Probe backends** per §8.3 (host_file / memory_buffer / semihosting / stub).
- **Built-in engine cross-mode**:
  - `qemu-user` (Linux user-mode emulation) for ELF-Linux targets — invoked as a subprocess; no linking; not bundled.
  - Embedded mode: engine writes test cases to a file; user-scripted runner flashes/loads to target; results return via the chosen probe backend.
- **AFL++/LibAFL/libFuzzer in cross mode** only when the user already has working qemu-mode AFL++; not a v1 promise. Built-in engine is the cross-target contract.
- **Behavioral/taint oracles** (the LD_PRELOAD runtrace shim) are native-host-only and are not armed under cross/emulated (qemu-user/wine) targets.
- **Findings** include `target`, `runtime`, `toolchain`, probe backend so a host repro vs target repro is unambiguous.

### 13.6 Engine feedback channels

Exception signatures, handler bitmap, breadcrumb bitmap, return-class bitmap, timeout/deadlock flag, resource growth signal, mock-call trace, stateful-transition trace, build-success bit (for build-probe harnesses).

---

## 14. Coverage without GNATcoverage

Default coverage = source-inserted breadcrumbs.

| Channel | Measures |
|---|---|
| Statement breadcrumb bitmap | Statements visited |
| Subprogram entry/exit | Call graph nodes touched |
| Handler probe | Handlers fired |
| Exception signature set | Distinct anomalies |
| Mock-call trace | External-surface coverage (fidelity-aware) |
| Return-class bitmap | Outcome diversity |

Optional plug-ins: GNATcoverage subprocess (research-lab), gcov on user's compiler (external-tools), kcov for any C side (external-tools).

---

## 15. Reporting and triage

### 15.1 Finding record

```json
{
  "id": "F-2026-04-30-0001",
  "severity": "high",
  "confidence": {
    "calibrated": 0.78,
    "learned": 0.81,
    "blend": 0.79,
    "model_id": null
  },
  "target": { "package": "Pkg.Sub", "subprogram": "Parse", "harness_id": "H-0042" },
  "build": {
    "profile": "strict-permissive",
    "compiler": { "id": "gnat", "version": "13.2", "ada_standard": "2012" },
    "target_triple": "x86_64-linux-gnu",
    "runtime": "default",
    "toolchain": null,
    "deps": { "real": [...], "instrumented": [...], "stubbed": [...], "fake_corba": [...] }
  },
  "input": { "bytes_path": "findings/.../testcase.bin", "decoded": { ... } },
  "call_sequence": [ { "op": "Init", "args": {...} }, { "op": "Parse", "args": {...} } ],
  "exception": {
    "name": "CONSTRAINT_ERROR",
    "message": "bad length",
    "explicit_raise": { "file": "foo.adb", "line": 88 },
    "handler": { "file": "foo.adb", "line": 123 },
    "last_breadcrumb": { "file": "foo.adb", "line": 87, "col": 7, "subprogram": "Parse" },
    "preceding_breadcrumbs": [ ... ],
    "returned_normally": true,
    "novelty": "new"
  },
  "replay": { "command": "govfuzz replay --finding F-2026-04-30-0001" },
  "minimal_reproducer": "findings/.../min_testcase.bin",
  "generated_repro_ada": "findings/.../repro.adb",
  "investigation_steps": [
    "Inspect handler at foo.adb:123 — confirm intentional swallow",
    "Re-evaluate range constraint at foo.adb:87",
    "Add upstream input validation"
  ]
}
```

### 15.2 Confidence — calibrated + learned

- **`calibrated`**: formula from §10 reports — transparent and reproducible. Weights tuned against the fixture set; the fixtures act as the regression suite for confidence.
- **`learned`**: small online model. Features: `stub_count`, `stubbed_call_depth`, `fake_corba_used`, `signature_age`, `breadcrumb_density`, `handler_kind`, `return_class`, `param_shape_complexity`, `target_score`. Logistic regression trained on labeled findings (`true_positive` / `false_positive` / `low_value`).
- **`blend`**: `0.5 * calibrated + 0.5 * learned` until ≥1k labeled findings; weight shifts toward `learned` afterward.
- **Cold start**: `learned` is `null` until the model has ≥100 labels.
- **Per-tenant retraining**: enterprise users retrain locally via `govfuzz model train --labels labels.json --out model.bin` without sharing data.
- **Auditable**: every learned score ships with `model_id` and feature vector for the finding.

### 15.3 Output formats

JSON (always), Markdown (always), **SARIF 2.1.0** when `--sarif`, JUnit XML when `--junit`, seed file, optional standalone Ada reproducer (`repro.adb`). Findings include `result.kind = "fail"`, `properties.govfuzzExceptionSignature`, `locations[]` for handler site + last breadcrumb + explicit raise, `relatedLocations[]` for stubs/fake CORBA used. SARIF schema validation is a CI gate.

---

## 16. Historical CLI design

This section preserves the original command design. Several names and scopes
changed during implementation; use `docs/site/cli.md` and live `--help`, not the
sketches below, for current automation.

Each command: `inputs`, `outputs`, `example`, `failure behavior`.

- **`govfuzz license-audit`** — In: project + manifests. Out: pass/fail. `govfuzz license-audit --profile strict-permissive`. Fail: exit 2 on any disallowed SPDX.
- **`govfuzz scan <path>`** — In: Ada/C/C++/Rust/Java/Python/Perl/Go file or directory tree. Out:
  `govfuzz_work/scan_index.json` plus JSON summary on stdout. Fail: exit 1
  when no supported source file was scanned.
- **`govfuzz list-targets <path>`** — In: Ada/C/C++/Rust/Java/Python/Perl/Go file or directory tree.
  Out: ranked targets, stable harness ids, and JSON/table output. `--top 20
  --format json`.
- **`govfuzz instrument --target <id>`** — In: target id. Out: rewritten files in `src_instrumented/`, `breadcrumbs.json`. Fail: prior instrumentation intact; exit 1 on any rewrite failure.
- **`govfuzz generate-harness <source> --target <name>`** — In: source file,
  target name, harness kind. Out: Ada `main.adb` + `.gpr`, or C/C++ `main.c`
  / `main.cpp` + `Makefile`. `--kind direct|sequence|servant_direct`.
- **`govfuzz generate-stubs --target <id>`** — In: target id. Out: `generated_stubs/...`.
- **`govfuzz fake-corba --idl <file>`** — In: IDL file (or scan-detected CORBA artifacts). Out: `fake_corba/...`.
- **`govfuzz build <work-dir> --harness <id>`** — In: harness id. Out: built
  binary in `build/<id>/`. Ada builds use GNAT/GPRbuild; C/C++ builds use the
  generated Makefile. `--target`, `--runtime`, `--toolchain` apply to the Ada
  path; `--c-engine libfuzzer|afl++` selects the C/C++ Makefile target.
- **`govfuzz fuzz <work-dir> --harness <id>`** — In: harness id, engine,
  time/iter budget. Out: corpus, findings. Current engines:
  `--engine builtin|afl++`.
- **`govfuzz replay --finding <id>`** — In: finding id (or testcase file). Out: stdout exception classification, identical signature. Fail: exit 3 on signature mismatch.
- **`govfuzz minimize --finding <id>`** — In: finding id. Out: `min_testcase.bin`, updated finding record.
- **`govfuzz report`** — In: optional run id. Out: JSON+MD+SARIF+JUnit. `--run last`.
- **`govfuzz model train`** — In: labeled findings. Out: per-tenant learned-confidence model. `--labels labels.json --out model.bin`.
- **`govfuzz daemon`** (M18) — In: `--listen 127.0.0.1:port`. Out: JSON-RPC service.
- **`govfuzz clean`** — `--all`/`--build`/`--corpus`.

---

## 17. Repository layout

```
govfuzz/
  LICENSE                       # Apache-2.0
  NOTICE
  THIRD_PARTY.md                # license matrix mirrored from §1.2
  SPDX/                         # per-file SPDX manifest
  Cargo.toml                    # workspace
  rust-toolchain.toml
  deny.toml                     # cargo-deny allow-list
  .github/workflows/
    ci.yml
    license-audit.yml
    nightly.yml
  crates/
    cli/
    config/
    license_policy/
    discovery/
    ada_parser/                 # from-scratch + ts-ada wrapper
    semantic/
    type_model/
    target_rank/
    instrumenter/
    harness_gen/
    stub_gen/
    fake_corba/
    idl_parser/
    project_synth/
    compiler_adapter/
    probe_gnat_actions/         # external-tools only; day-one
    fuzz_engine/
      builtin/
      afl_adapter/
      libafl_adapter/
      libfuzzer_adapter/
    corpus/
    replay_min/
    confidence_model/           # calibrated + learned
    report/
    daemon/                     # M18
  ada_runtime/                  # SPDX: Apache-2.0; pragma Ada_95
    adafuzz-probe.ads
    adafuzz-probe.adb
    adafuzz-probe-gnat_actions.ads
    adafuzz-probe-gnat_actions.adb
    adafuzz-input.ads
    adafuzz-input.adb
    adafuzz-decode.ads
    adafuzz-decode.adb
    adafuzz-corpus.ads
    adafuzz-corpus.adb
    adafuzz-fake_corba.ads
  examples/
    swallowed_constraint_error/
    swallowed_when_others/
    private_state/
    access_param/
    missing_dependency/
    fake_corba_servant/
  tests/
    unit/
    integration/
    e2e/
    license/
    dialect/
      ada95/
      ada2005/
      ada2012/
      ada2022/
  docs/
    architecture.md
    instrumentation.md
    fake-corba.md
    licensing.md
    cli.md
    cross-compilation.md
    daemon.md
```

CI: `license-audit.yml` runs `cargo deny`, the SPDX manifest check, and the policy-gate test against every PR.

---

## 18. Implementation milestones

Each milestone: goal, deliverables, tasks, acceptance, example, risks, deferrables.

### M0 — License-safe architecture and dependency audit
- **Goal**: zero copyleft in core graph, working policy gate, day-one `gnat_actions` plug-in scaffolding.
- **Deliverables**: `deny.toml`, `license-audit.yml`, `THIRD_PARTY.md`, `SPDX/` manifest, build profiles defined, `crates/probe_gnat_actions/` skeleton refusing to enable in `strict-permissive`.
- **Acceptance**: PR adding GPL dep fails CI; `--profile strict-permissive --probe gnat_actions` exits 2.
- **Example**: scaffold repo with a single Apache-2.0 noop crate.
- **Risks**: drifting tree-sitter-ada license.

### M1 — Permissive Ada syntax scanner (95/2005/2012/2022)
- **Goal**: Tier 1 scanner covers all four supported Ada standards.
- **Deliverables**: `crates/ada_parser`, vendored ts-ada at pinned commit, golden-file tests over ≥50 Ada files spread across dialects.
- **Acceptance**: scanner extracts ≥95% of subprograms and ≥99% of handlers/raises in fixture corpus per dialect.
- **Risks**: grammar gaps for representation clauses; mitigate with permissive recovery.

### M2 — Target discovery and ranking
- **Goal**: ranked targets per project.
- **Deliverables**: `crates/target_rank` with §5.2 scoring, `govfuzz list-targets`.
- **Acceptance**: ranking puts swallowed-handler ops in top 10% on fixtures.

### M3 — Direct-call harness for scalar/string params
- **Goal**: end-to-end on a trivial target.
- **Deliverables**: harness templates; `AdaFuzz.Input`/`AdaFuzz.Decode`.
- **Acceptance**: `govfuzz generate-harness && govfuzz build && govfuzz fuzz` runs.

### M4 — Source instrumentation: handlers, breadcrumbs, explicit raises
- **Goal**: instrumented copies compile and emit events on all four dialects.
- **Deliverables**: `crates/instrumenter`, `breadcrumbs.json`, `AdaFuzz.Probe` runtime; expression-function and parallel-block correctness tests.
- **Acceptance**: instrumented builds compile clean against FSF GNAT 11..14.

### M5 — Prove swallowed-exception detection
- **Goal**: produce a finding with handler file/line + last breadcrumb on a swallowed CE.
- **Deliverables**: corpus retention by signature; finding record; `govfuzz replay`.
- **Acceptance**: deterministic finding from `swallowed_constraint_error` per dialect.

### M6 — Partial-build project synthesis
- **Goal**: synthetic `.gpr` builds harness against partial code.
- **Deliverables**: `crates/project_synth`, `crates/compiler_adapter` (version-agnostic).
- **Acceptance**: builds succeed on `examples/missing_dependency` after stubs.

### M7 — Diagnostic-driven stub generation
- **Goal**: missing decls auto-stubbed from compiler diagnostics.
- **Deliverables**: `crates/stub_gen`, diagnostic regex grammar across GNAT 11..14.
- **Acceptance**: `examples/missing_dependency` builds without manual stubs.

### M8 — Type-aware generator: records/enums/arrays/access wrappers
- **Goal**: harness covers compound types.
- **Deliverables**: per-type decoders; access-slot table; tagged constructor registry.
- **Acceptance**: `examples/access_param` reaches handler with non-trivial input.

### M9 — Stateful sequence harnesses
- **Goal**: package-level harness drives op sequences.
- **Deliverables**: sequence harness template; mutator over op sequences.
- **Acceptance**: `examples/private_state` finds state-dependent swallow.

### M10 — Fake CORBA package generator
- **Goal**: minimal CORBA surface compiles servant in isolation.
- **Deliverables**: `crates/fake_corba`, generated `corba.ads`, `portableserver.ads`, etc.
- **Acceptance**: `examples/fake_corba_servant` builds without a real ORB.

### M11 — Full IDL→Ada mapping
- **Goal**: parse common IDL into our type model with the full mapping (§11.3).
- **Deliverables**: `crates/idl_parser` incl. CPP-lite preprocessor; full mapping emitter; vendor-pragma adoption.
- **Acceptance**: a representative legacy-project IDL file compiles to Ada that builds against fake CORBA without manual edits.

### M12 — CORBA servant-direct harnessing
- **Goal**: fuzz servant ops directly through fake-CORBA-typed parameters.
- **Deliverables**: harness type for servants; object-ref fakes; in/out/inout handling.
- **Acceptance**: finding produced for `fake_corba_servant` swallowed user exception.

### M13 — Built-in mutational engine
- **Goal**: replace random with coverage-lite mutator.
- **Deliverables**: scheduler; mutator suite; persistent harness loop.
- **Acceptance**: swallow-rate ≥ baseline x3 within 60s per fixture.

### M14 — Optional AFL++ / LibAFL adapters
- **Goal**: optional engine swap.
- **Deliverables**: AFL++ persistent shim; LibAFL crate feature.
- **Acceptance**: identical findings via AFL++ on at least one fixture.

### M15 — Minimization and replay
- **Goal**: ddmin over bytes; typed-value minimization; deterministic replay.
- **Deliverables**: `crates/replay_min`.
- **Acceptance**: minimal repro for each fixture < 10% of original input.

### M16 — Reporting, confidence, daemon scaffolding
- **Goal**: JSON + Markdown + SARIF 2.1.0 + JUnit; standalone Ada reproducer; calibrated + learned confidence; JSON-RPC trait.
- **Deliverables**: `crates/report`; templates; SARIF 2.1.0 validator; `crates/confidence_model` (calibrated formula + logistic regression with online update); JSON-RPC trait wrapping the CLI library entry points (no daemon process yet).
- **Acceptance**: SARIF validates; Markdown renders; `repro.adb` builds with FSF GNAT; `govfuzz model train` produces a model file used by subsequent `report` runs.

### M17 — Cross-compilation
- **Goal**: cross-compile harnesses for at least one ELF-Linux target via `qemu-user` and one bare-metal target via `memory_buffer` backend.
- **Deliverables**: `--target/--runtime/--toolchain`; probe backends; qemu-user runner integration; documentation.
- **Acceptance**: `examples/swallowed_constraint_error` runs on `aarch64-linux-gnu` via qemu-user and produces an identical finding to the host run.

### M17.1 — Windows-native fuzzing + native Windows build ✅
- **Goal**: fuzz Windows-native (`_WIN32`) C/C++ targets as real PEs, and build
  govfuzz itself to run natively on Windows (in addition to Linux).
- **Deliverables**:
  - Cross-fuzz path (Linux host): the generated fork-server driver
    (`c_runtime/govfuzz_driver.c` + `direct_harness.{c,cpp}.tera`) is
    Windows-buildable — Win32 file-mapping SHM, `_setmode` binary stdio,
    `__sanitizer_cov_trace_pc` coverage (mingw has no `trace-pc-guard`), and a
    vectored exception handler for crash detection (no ASan on mingw). A Windows
    foreign-guard now resolves to `Cross(x86_64-w64-mingw32 + wine)` PRIMARY (real
    PE, real coverage + cmplog), with the native fake-`windows.h` stub as fallback
    when mingw/wine is absent. `-static` link so the PE has no DLL deps under wine.
  - Native build: `cargo build --target x86_64-pc-windows-gnu -p govfuzz` →
    `govfuzz.exe`; crash classification recognizes the driver's `0x39` fault
    sentinel off-Unix.
- **Acceptance**: `govfuzz auto` on a `_WIN32`-guarded C and C++ fixture
  cross-builds a PE, fuzzes it under wine with real edge coverage, and reports the
  planted crash (`crates/cli/tests/windows_cross_fixture.rs`); `govfuzz.exe` builds
  clean and, under wine, runs the CLI + fuzzes a harness + detects a crash.
- **Follow-ups**: coverage-guided feedback + persistent fork-server on the
  *native-Windows* build (Win32 SHM readers + a Windows handshake timeout);
  general `govfuzz auto` multi-file-library build-context (project include-dir
  discovery + library source linking) for real OSS libraries.

### M18 — Daemon and IDE plug-ins (stretch)
- **Goal**: long-running JSON-RPC daemon + thin VS Code client.
- **Deliverables**: `crates/daemon`; VS Code extension; GNAT Studio plug-in.
- **Acceptance**: editor surfaces findings inline, "Replay this finding" / "Minimize" / "Open repro.adb" code-lens actions.

### M19 — Hardening, CI, packaging, license audit
- **Goal**: shippable.
- **Deliverables**: `cargo dist` packaging; `govfuzz license-audit` exit codes; signed releases; docs site; full CI matrix (GNAT 11..14 × dialects 95/2005/2012/2022 × profiles).
- **Acceptance**: end-to-end demo on all five fixtures × four dialects in CI nightly.

---

## 19. Proof-of-concept examples

### 19.1 `examples/swallowed_constraint_error/`

```ada
--  pkg.ads
package Pkg is
   function Parse (S : String) return Integer;
end Pkg;
```

```ada
--  pkg.adb
package body Pkg is
   function Parse (S : String) return Integer is
      Tmp : Integer;
   begin
      Tmp := Integer'Value (S);
      return Tmp;
   exception
      when Constraint_Error =>
         return 0;   -- swallowed
   end Parse;
end Pkg;
```

Expected: finding with `exception=CONSTRAINT_ERROR`, handler at `pkg.adb:9`, last breadcrumb at the `Tmp := ...` line, decoded input string.

### 19.2 `examples/swallowed_when_others/`

A procedure with `when others => null;`. The instrumenter binds `AdaFuzz_E`, the runtime captures name and message via `Ada.Exceptions`. Expected: name (e.g., `PROGRAM_ERROR` or user exception) plus message and breadcrumb.

### 19.3 `examples/private_state/`

```ada
package State is
   procedure Push (X : Integer);
   procedure Pop;
   function Top return Integer;
end State;
```

Body uses an internal counter that underflows after specific sequences. Fuzzer picks ops + scalar args, finds `Constraint_Error` only after a `Pop` on empty.

### 19.4 `examples/missing_dependency/`

`Pkg.Parse` with-clauses `External_Lib`. The repo doesn't include `External_Lib`. Stub generator infers spec from references, generates body returning neutral values, build succeeds. Report flags `confidence < 1` with `stubbed: [external_lib.ads, external_lib.adb]`.

### 19.5 `examples/fake_corba_servant/`

```idl
// foo.idl
module Foo {
  exception BadInput { string reason; };
  interface Bar {
    long compute(in string s) raises(BadInput);
  };
};
```

`bar_impl.adb` implements `compute` and `raise Foo.BadInput with "neg"` for negative input but **catches it** in the body. Fake CORBA generator produces `Foo` and `PortableServer` shims (full mapping incl. `Helper`/`Skel`/`Stub`); servant-direct harness calls `Compute` with fuzzed strings. Expected finding: swallowed `Foo.BadInput`.

---

## 20. Algorithms and pseudocode

### 20.1 Dependency license audit

```
fn audit(profile, deps):
    allow = profile.allow_list_spdx()
    for d in deps:
        if d.spdx not in allow: fail(d)
    for d in deps:
        if d.transitive_pulls_in(any spdx not in allow): fail(d)
    if profile == strict_permissive:
        forbid_runtime_link(GNAT_RUNTIME_OTHER_THAN_GENERATED_USER_BINARY)
        forbid_probe(gnat_actions)
    pass
```

### 20.2 Source discovery

```
fn discover(root, gpr_opt):
    units = []
    if gpr_opt: units += parse_gpr_soft(gpr_opt)
    for f in walk(root, ext in {ads, adb, idl, gpr}): units += classify(f)
    dedup_by_canonical_path(units)
    return units
```

### 20.3 Ada syntax extraction

```
fn extract(unit, dialect):
    toks = lex(unit.bytes, dialect)
    ts_tree = ts_parse(unit.bytes)
    ast = StructuralAst::new(dialect)
    walk_top_level(ts_tree.root, push_to ast)
    reconcile_spans(ast, toks)
    extract_handlers_and_raises(ast)
    extract_with_use(ast)
    extract_types(ast)
    return ast
```

### 20.4 Target ranking

```
fn rank(units):
    candidates = []
    for u in units:
        for s in u.subprograms:
            score = score_function(s)
            candidates.push((score, s))
    candidates.sort_desc()
    return candidates
```

### 20.5 Handler instrumentation

```
fn instrument_handlers(ast, source):
    edits = []
    for h in ast.handlers:
        bind = h.binding or "AdaFuzz_E"
        if h.binding is None:
            edits.push(insert_before(h.choices_token, bind & " : "))
        probe = render(probe_template, h, file=ast.path, line=h.line)
        edits.push(insert_at(h.body_first_stmt_offset, probe))
    return apply_edits(source, edits)
```

### 20.6 Breadcrumb insertion

```
fn instrument_breadcrumbs(ast, source):
    edits = []
    next_id = global_counter
    map = {}
    for s in ast.statements_in_sequences:
        if not_safe_to_inject_at(s): continue
        id = next_id; next_id += 1
        map[id] = source_span(s)
        call = "AdaFuzz.Probe.Breadcrumb(" & id & ");"
        edits.push(insert_before_statement(s, call))
    write(map → breadcrumbs.json)
    return apply_edits(source, edits)
```

### 20.7 Explicit raise-site instrumentation

```
fn instrument_raises(ast, source):
    edits = []
    for r in ast.raise_sites:
        name = r.exception_name or "<reraise>"
        call = render(raise_probe_template, name, file=ast.path, line=r.line)
        edits.push(insert_before_statement(r, call))
    return apply_edits(source, edits)
```

### 20.8 Byte-to-value decoding

```
fn decode(type_ref, cursor):
    match type_ref.kind:
        Scalar(IntRange(lo,hi)):
            if biased(cursor): return choose_anchor(lo, hi)
            return lo + (cursor.u32() mod (hi-lo+1))
        Enum(lits): return lits[cursor.u8() mod |lits|]
        Array(idx, elem, bounds):
            n = decode_len(cursor, bounds)
            return [decode(elem, cursor) for _ in 0..n]
        Record(fields):
            return { f.name: decode(f.type, cursor) for f in fields }
        Discriminated(disc, variants):
            d = decode(disc, cursor)
            return mix(d, decode(variants[d], cursor))
        Tagged(concretes):
            t = concretes[cursor.u8() mod |concretes|]
            return construct(t, decode_payload(t, cursor))
        Access(target):
            return slot_table.choose(cursor.u8(), target)
        Unknown: return neutral(type_ref)
```

### 20.9 Partial dependency closure

```
fn closure(target_unit):
    seen = {}; queue = [target_unit]; missing = {}
    while queue not empty:
        u = queue.pop()
        if u in seen: continue
        seen.add(u)
        for w in u.with_clauses:
            r = resolve(w)
            if r.exists: queue.push(r)
            else: missing.add(w)
    return seen, missing
```

### 20.10 Stub synthesis from compiler diagnostics

```
fn synthesize_from_diags(diags):
    needs = []
    for d in diags:
        match d:
            MissingWith(pkg): needs.push(StubPackageSpec(pkg))
            UnknownIdentifier(scope, ident, used_as): needs.push(StubDecl(scope, ident, used_as))
            TypeMismatch(expected, actual_loc): needs.push(InferType(expected, actual_loc))
            VisibilityError(...): needs.push(PromoteVisibility(...))
    coalesce(needs)
    return needs
```

### 20.11 Fake CORBA package synthesis

```
fn synth_fake_corba(idl_or_heur):
    if idl_or_heur.kind == IDL: ast = idl_parse(idl_or_heur.path)
    else: ast = infer_idl_from_ada(scan_index)
    emit corba.ads, corba-object.ads, portableserver.ads, corba-any.ads (as needed)
    for module in ast.modules:
        emit_pkg(module)
        for iface in module.interfaces:
            emit_iface_types(iface)
            emit_servant_base(iface)
            emit_helper(iface)
            emit_skel(iface)
            emit_stub(iface)
    emit_exception_packages(ast.exceptions)
```

### 20.12 Harness generation

```
fn gen_harness(target):
    h = HarnessTemplate.pick(target.kind)
    decoders = render_decoders(target.params)
    body = h.render(target, decoders, probes=true)
    write generated_harnesses/<id>/main.adb = body
    write generated_harnesses/<id>.gpr = render_gpr(target, instrumented_dirs, runtime_dir,
                                                    ada_standard, target_triple, runtime, toolchain)
```

### 20.13 Exception signature hashing

See §7.7.

### 20.14 Corpus retention

```
fn retain(input, sig):
    if sig in seen_signatures: return drop
    seen_signatures.add(sig)
    save(input → corpus/queue/<sig_short>.bin)
    save(sig → corpus/sigs/<sig>.json)
    if classify(sig) ∈ {swallowed, explicit_raise, unhandled}:
        save(input → corpus/swallowed/<sig_short>.bin)
```

### 20.15 Replay

```
fn replay(finding):
    load testcase.bin
    spawn harness with INPUT_FILE=testcase.bin, MODE=replay
    consume event stream
    compare exception signature
    if mismatch: exit 3
```

### 20.16 Minimization (ddmin)

```
fn minimize(input, predicate):
    n = 2
    while len(input) > 0:
        chunks = split(input, n)
        for i in 0..n:
            cand = remove(input, chunks[i])
            if predicate(cand): input = cand; n = max(n-1, 2); break
        else:
            for i in 0..n:
                cand = chunks[i]
                if predicate(cand): input = cand; n = 2; break
            else:
                if n >= len(input): break
                n = min(2*n, len(input))
    return input
```

### 20.17 Confidence model update

```
fn update_confidence(finding, model):
    f = features(finding)   // §15.2
    p_calibrated = formula(finding)
    p_learned = sigmoid(model.weights ⋅ f) if model.is_warm() else null
    p_blend = blend(p_calibrated, p_learned, model.label_count)
    return { calibrated: p_calibrated, learned: p_learned, blend: p_blend, model_id: model.id }
```

### 20.18 Report generation

```
fn report(run):
    findings = load(run.findings_dir)
    write json(run, findings)
    write md(run, findings)
    if --sarif: write sarif(run, findings, schema="2.1.0")
    if --junit: write junit(run, findings)
    write repro.adb for each finding
```

---

## 21. Example generated code

### 21.1 Direct harness

```ada
--  generated_harnesses/H-0042/main.adb
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Ada.Exceptions;
with AdaFuzz.Input;
with AdaFuzz.Decode;
with AdaFuzz.Probe;
with Pkg;

procedure Main is
   Buf  : Stream_Element_Array (1 .. 1 * 1024 * 1024);
   Last : Stream_Element_Offset;
   TC   : AdaFuzz.Probe.Testcase_Id := 0;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buf, Last);
      exit when Last < Buf'First;
      TC := TC + 1;
      AdaFuzz.Probe.Begin_Testcase (TC);
      AdaFuzz.Probe.Set_Target (16#0042#);
      declare
         Cur : AdaFuzz.Decode.Cursor := AdaFuzz.Decode.Open (Buf, Last);
         S   : constant String := AdaFuzz.Decode.Ada_String (Cur, 0, 1024);
         R   : Integer;
         pragma Unreferenced (R);
      begin
         R := Pkg.Parse (S);
      exception
         when AdaFuzz_E : others =>
            AdaFuzz.Probe.On_Top_Level_Catch
              (Ada.Exceptions.Exception_Name (AdaFuzz_E),
               Ada.Exceptions.Exception_Message (AdaFuzz_E));
      end;
      AdaFuzz.Probe.End_Testcase;
      AdaFuzz.Probe.Flush;
   end loop;
end Main;
```

### 21.2 Stubbed missing dependency

```ada
--  generated_stubs/external_lib.ads
--  SPDX-License-Identifier: Apache-2.0
package External_Lib is
   type Token is private;
   function Lookup (Key : String) return Token;
   procedure Configure (Flag : Boolean);
private
   type Token is new Integer;
end External_Lib;
```

```ada
--  generated_stubs/external_lib.adb
--  SPDX-License-Identifier: Apache-2.0
with AdaFuzz.Probe;
package body External_Lib is
   function Lookup (Key : String) return Token is
      pragma Unreferenced (Key);
   begin
      AdaFuzz.Probe.Mock_Call ("External_Lib.Lookup");
      return 0;
   end Lookup;

   procedure Configure (Flag : Boolean) is
      pragma Unreferenced (Flag);
   begin
      AdaFuzz.Probe.Mock_Call ("External_Lib.Configure");
   end Configure;
end External_Lib;
```

### 21.3 Fake CORBA object reference

```ada
--  fake_corba/foo-bar_ref.ads
--  SPDX-License-Identifier: Apache-2.0
with CORBA.Object;
package Foo.Bar_Ref is
   type Ref is new CORBA.Object.Ref with null record;
   function Nil return Ref is ((null record));
   function Fake (Tag : Natural) return Ref;
end Foo.Bar_Ref;
```

### 21.4 CORBA servant-direct harness

```ada
--  generated_harnesses/H-0099/main.adb
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Ada.Exceptions;
with AdaFuzz.Input;
with AdaFuzz.Decode;
with AdaFuzz.Probe;
with Foo;
with Foo.Bar_Impl;
procedure Main is
   Buf     : Stream_Element_Array (1 .. 1 * 1024 * 1024);
   Last    : Stream_Element_Offset;
   TC      : AdaFuzz.Probe.Testcase_Id := 0;
   Servant : aliased Foo.Bar_Impl.Object;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buf, Last);
      exit when Last < Buf'First;
      TC := TC + 1;
      AdaFuzz.Probe.Begin_Testcase (TC);
      AdaFuzz.Probe.Set_Target (16#0099#);
      declare
         Cur : AdaFuzz.Decode.Cursor := AdaFuzz.Decode.Open (Buf, Last);
         S   : constant String := AdaFuzz.Decode.Ada_String (Cur, 0, 4096);
         R   : Foo.Long;
         pragma Unreferenced (R);
      begin
         R := Foo.Bar_Impl.Compute (Servant, S);
      exception
         when AdaFuzz_E : others =>
            AdaFuzz.Probe.On_Top_Level_Catch
              (Ada.Exceptions.Exception_Name (AdaFuzz_E),
               Ada.Exceptions.Exception_Message (AdaFuzz_E));
      end;
      AdaFuzz.Probe.End_Testcase;
      AdaFuzz.Probe.Flush;
   end loop;
end Main;
```

---

## 22. Key tradeoffs

- **Tree-sitter / from-scratch vs Libadalang plug-in**: ts-ada + handwritten lexer wins on licensing and audit risk; loses on semantic depth (overload resolution, generics). Mitigated by Tier 2 build-assisted refinement and an out-of-process Libadalang plug-in for users who accept GPL.
- **Source instrumentation vs `GNAT.Exception_Actions`**: source instrumentation is portable, deterministic, profile-agnostic. Day-one `gnat_actions` plug-in offers the global-raise hook for `external-tools` users; never enabled in `strict-permissive`.
- **Fake CORBA vs real ORB**: fake CORBA delivers exception detection in servant logic without GPL ORBs and live network plumbing. Loses fidelity for marshalling bugs; mitigated by raw-IIOP mode much later in `research-lab`.
- **Direct servant fuzzing vs IIOP fuzzing**: direct first; IIOP later.
- **Partial vs full builds**: partial first because real Ada projects rarely build cleanly outside their original environment.
- **Generated mocks vs fidelity**: per-finding `stubbed`/`fake_corba` markers + dual-component confidence number (calibrated + learned).
- **Exception signatures vs traditional coverage**: signatures are the explicit coverage proxy; breadcrumb bitmap complements.
- **Built-in engine vs AFL++/LibAFL**: built-in is the contract; the others are upgrades.
- **Permissive-only core vs broader research-lab**: keeps the permissive-licensing boundary clean while staying competitive.
- **Calibrated vs learned confidence**: ship both. Calibrated is auditable; learned adapts; blend balances.

---

## 23. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Ada grammar incompleteness in Tier 1 | Vendor ts-ada at pinned commit, golden corpus regression tests, permissive recovery, fall back to Tier 2 diagnostics |
| No full semantic model | Tier 2 build-assisted refinement; isolate optional Libadalang plug-in |
| Instrumentation changes program behavior | Probes are no-raise, no-block, no-allocation in hot path; integration tests assert identical control flow on benchmarks; opt-out per file |
| Ada elaboration order | Probe runtime is `Preelaborate`; explicit `Preelaborate` checks in CI |
| Handler rewrite correctness | Span-precise edits; AST-driven; negative-test fixtures (extended return, expression functions, parallel blocks, labels, pragmas) |
| Generated stubs hide bugs | `confidence` (calibrated + learned); finding metadata lists stubbed deps; `--no-stubs` mode for fidelity runs |
| False positives from fake deps | Same; differential harness comparing real vs stubbed where both exist |
| False negatives bypassing ORB unmarshalling | Servant-direct as the v1 contract; raw IIOP only in research-lab |
| Vendor-specific CORBA generated code | Detection heuristics + adopt-existing-packages mode |
| Private/limited/tagged construction | Concrete-constructor registry; skip targets with no construction path; sequence harnesses can still drive state |
| Access type ownership | Harness-owned slot table; null permitted; no `Unchecked_Deallocation` from harness |
| Tasking / protected objects | Inert replacements for missing tasks; fairness-blind scheduler in harness; document complexity |
| Compiler-specific behavior | Version-agnostic diagnostic parser (GNAT 11..14+); record compiler banner in finding metadata |
| Licensing drift | License-policy gate + nightly audit; pin versions; review PRs that modify `THIRD_PARTY.md` |
| ts-ada license change | Mirror at pinned commit; CI fails on mirror drift; fallback to from-scratch parser path |
| Cross-compile environment fragmentation | Probe-backend matrix; explicit `target/runtime/toolchain` capability probe with clear failures |
| Learned-confidence drift | Auditable model id and feature vector per finding; per-tenant retraining; calibrated baseline always present |

---

## 24. Open items for v1.1+

1. Raw IIOP mode (research-lab graduation).
   - Foundation started: `iiop` crate for GIOP message headers, whole-message framing, service contexts, GIOP 1.2 request headers, and CDR primitive/string decoding. This does not add live ORB or network fuzzing yet.
2. Daemon multi-tenant authentication and RBAC.
3. GNAT Studio plug-in feature parity with VS Code plug-in.
4. Container/sandbox harness execution (firejail/bwrap) by default.
   - **Delivered (2026-06-19).** `--sandbox` defaults to `Auto` across the auto
     loop, binary-fuzz, minimize, and replay; Auto prefers bwrap then firejail.
     A cached 3-state bwrap probe degrades robustly when the environment denies
     user/network namespaces (FS-only without `--unshare-net`, or full
     degradation to a direct run when non-strict / `SandboxUnavailable` when
     strict). The runtrace shim dir is ro-bound and the runtrace-log dir
     rw-bound so the executable oracles still fire under the sandbox.
5. Symbolic-execution-assisted seed generation for deeply guarded paths.
6. Differential fuzzing across Ada compilers (FSF GNAT vs another open-source Ada front end if one matures).
7. Broader Ada semantic call resolution (reclassified from §25 #341): follow
   subprogram renamings through to their target, resolve dispatching/tagged
   calls, and expand generic instantiations. Full resolution needs
   Libadalang-level analysis, which is GPL and outside the from-scratch /
   strict-permissive thesis.
8. Grammar-recursive / stateful structured-input mutators (reclassified from
   §25 #342): full context-free-grammar–driven generation beyond the current
   text + binary structured-shape families.
   - **Advanced (2026-06-19).** Added the `StructuredRecursive` mutator:
     bounded-depth recursively-nested balanced-delimiter generation (mixed
     `()`/`[]`/`{}`/`<e>..</e>`), iterative (no mutator-side recursion) and
     capped at depth 512, exposed via `--structured-inputs recursive`. This is
     the recursion-limit / stack-exhaustion lever the flat structured mutators
     lacked. **Delivered further.** User-supplied grammars ship: `fuzz --grammar
     <file>` loads a JSON grammar object (rule name → production alternatives) and
     generates conformant inputs from it (`load_grammar_for_run` in
     `crates/cli/src/fuzz.rs`). **Remaining:** arbitrary `.g`/EBNF grammar-file
     ingestion (only the JSON grammar format is accepted today) and
     stateful/protocol mutators.
9. Additional executable-oracle classes (reclassified from §25 #343) and deeper
   C/C++ recursive object graphs + full C++ template/parity harnessing
   (reclassified from §25 #345).
   - **Advanced (2026-06-19).** Added GF-417 insecure-temporary-file oracle
     (CWE-377, CERT FIO21-C): `open`/`openat` creating a file in a
     world-writable dir without `O_EXCL` (18 registered oracles now).
     **Advanced further.** The TOCTOU runtime oracle shipped (GF-418
     `ToctouRuntime`, CWE-367): the runtrace shim logs the time-of-check path
     probe and correlates it with a later tainted open (`log_path_check` in
     `crates/govfuzz_runtrace_shim/src/hooks/fs.rs`). **Remaining:**
     weak-randomness (CWE-338) and integer-overflow-via-instrumentation oracle
     classes, deeper C/C++ recursive object graphs, and full C++ template/parity
     harnessing.

---

## 25. Top-of-class scanner gap program (2026-06-11)

A 151-agent deep review plus competitive research (AdaCore GNATfuzz/SAS,
Mayhem, Code Intelligence, OSS-Fuzz/OSS-Fuzz-Gen, AIxCC CRSs, and the
SAST incumbents) found govfuzz already ahead of the field on its core
thesis — offline/air-gapped operation, build-repair of trees that don't
compile, unified Ada+C/C++ on FSF GNAT, swallowed-exception and CORBA/IDL
awareness — with engine internals at or above the AFL++/GNATfuzz bar.
Five decisive gaps separate "impressive lab tool" from "scanner a DoD
program office adopts". Each is tracked as a GitHub issue:

1. **Coverage-blocker introspection** — join static reachability against
   dynamic coverage; surface unreached code and recommend targets.
   First slices now report direct and transitive static callee gaps,
   unresolved static calls, and CmpLog comparison gates with seed/dictionary
   recommendations. Static reachability blockers now carry depth and call-chain
   evidence for the concrete route from the fuzzed target to the blocked
   callee, and the top-level blocker list is priority-sorted so direct static
   callee gaps rank ahead of deeper paths, unresolved calls, comparison gates,
   and orphan public targets. The first Ada reachability slice now resolves
   simple local calls, including parameterless procedure statements,
   package-qualified package-body calls, grouped formal parameter lists,
   defaulted formal parameters, multi-line subprogram body headers, and
   parenthesized calls with matching accepted arity, into the same
   `static_reachability_gap` blockers.
   The static taint tracer also maps reordered Ada named-argument associations
   back to the correct callee formal. The introspector reports not-run public
   targets outside any fuzzed static call chain as `unreached_public_target`
   blockers and missing or arity-mismatched Ada calls as
   `unresolved_static_call` blockers, and now also records Ada subprogram
   **renaming** declarations (`function Q (...) renames P;`) as reachable nodes
   so a call to a renaming resolves instead of being mis-reported as unresolved.
   **Delivered.** Full semantic resolution that follows a renaming through to its
   target, resolves dispatching (tagged) calls, and expands generic
   instantiations needs Libadalang-level analysis — GPL, and outside the
   from-scratch / strict-permissive thesis — so it is tracked as continuous
   improvement in §24 (v1.1+), not a blocking gap.
   (#341)
2. **Structure-aware input layer + automatic dictionary generation** from
   the enums/macros/IDL constants we already parse. The first slice now mines
   Ada, C/C++, and IDL harness dictionaries, including C/C++ inline switch
   case labels and C++ namespaced `enum class` members, and uses them for
   token insertion,
   record/TLV-shaped inputs, JSON grammar-shaped object/array inputs,
   XML element inputs, key/value text inputs, URL-encoded query-string inputs,
   compact multipart/form-data bodies, CSV/table-row inputs, raw HTTP
   request inputs, INI-style section/key configuration inputs, TOML-style
   table/key configuration inputs, YAML-style section/key configuration
   inputs, and a binary chunked/length-prefixed shape (a mined magic header
   followed by `[u32 length][payload]` chunks, little- and big-endian — the
   PNG/RIFF/ZIP/network-framing structure of the legacy binary parsers govfuzz
   targets). **Delivered** across the text and binary structured families;
   grammar-recursive/stateful mutators (full context-free grammars) are
   continuous improvement in §24 (v1.1+).
   (#342)
3. **Executable oracle SDK** beyond crashes — runtime-check promotion,
   differential, path-traversal/format-string/resource-leak oracles on
   the runtrace shim. First runtime slices now cover path traversal, SSRF,
   sensitive environment variable access with redacted present/missing
   `getenv`/`secure_getenv` evidence, command injection, controlled
   printf-style format strings, audited file-descriptor leaks, destructive
   parent-directory file deletion, handled Ada `Constraint_Error` range/index,
   `Storage_Error`, `Tasking_Error`, and user-defined exception runtime-check
   promotion, native C/C++ assertion contract promotion, unsafe dynamic
   library load promotion, SDK-backed differential output-divergence findings,
   first-pass metamorphic relation violation findings, and runtime
   insecure-file-permission assignment (setuid/setgid/world-writable `chmod`,
   CWE-732 — e.g. an archive extractor honoring an attacker-controlled entry
   mode). **Delivered** (17 registered oracles spanning the OWASP/CWE logic-bug
   classes); additional oracle classes are continuous improvement. The
   behavioral/taint oracles run on the Linux LD_PRELOAD runtrace shim. The
   current shim scope is native C/C++/Ada/Rust/Go/COBOL/Fortran plus the
   Python/Perl/Ruby/Lua/PHP interpreter processes; it is off for Java, C#,
   JavaScript/TypeScript, and cross/emulated targets. (#343)
4. **CycloneDX SBOM (CISA 2025 minimum elements) + offline NVD/KEV CVE
   correlation** — CycloneDX, KEV metadata, and first-pass reached-CVE
   ranking now land in offline reports; runtime `dlopen` evidence from
   fuzzed harnesses is folded into dynamic SBOM components, and the CycloneDX
   document identifies GovFuzz itself as a supplier/purl-addressable tool
   component. Declared components can now carry CycloneDX supplier, license,
   SHA-256, and CPE identity, and offline vulnerability DB entries can match
   by `package.purl` or `package.cpe` with high-confidence precise-identity
   findings that are emitted both in `vulnerabilities.json` and CycloneDX
   `vulnerabilities` entries with CVSS, CWE, KEV, advisory URLs, and
   reachability properties. SBOM/SCA ingestion spans 12 ecosystems, including
   Node.js, Ruby, PHP, .NET, and the `cpan` cataloger for Perl. SBOM ecosystem
   count is independent of the current sixteen fuzzing lanes.
   (#344)
5. **Generalized C/C++ lifecycle & stateful-sequence harnesses** —
   struct/opaque-handle/callback APIs (the 170/185 miniz skip bucket).
   Phase A/B plus first C and C++ lifecycle sequence slices landed, including
   auto sequence preference with direct fallback. A fresh miniz sweep reaches
   115 built+fuzzed targets, 1 built target, and 69 precise static-linkage
   skips. Follow-up fixes keep generic `void *` buffer APIs on the direct
   harness path instead of misclassifying them as lifecycle handles;
   scalar/enum output-pointer typedefs now stack-allocate safely and turn
   representative miniz `pIndex`/`pErr` targets into built+fuzzed harnesses.
   Const byte-pointer typedefs now borrow the current fuzz input and
   registry-aware byte/length pair detection turns miniz `mz_crc32`,
   `mz_uncompress2`, and `tinfl_decompress` into built+fuzzed harnesses; miniz
   `MZ_FILE *` and `MZ_TIME_T` macro aliases now drive the cfile API cluster,
   including `mz_zip_writer_add_cfile`. Top-level `void **` output slots now
   stack-allocate nullable pointer slots and convert
   `mz_zip_writer_finalize_heap_archive`; mutable `void *` output buffers with
   scalar capacities now heap-allocate safely and convert
   `tdefl_compress_mem_to_mem`; the same output-length-pointer and
   scalar-capacity/input-pair handling now covers C++ direct harnesses, and
   standalone C/C++ `bool` and 16-bit scalar spellings plus C++ standard
   scalar aliases such as `std::size_t` and `std::uint32_t` decode through the
	   direct harness path. Visible C++ enums and `enum class` parameters now
	   decode through the shared type registry with scoped `Enum::Member`
	   or `namespace::Enum::Member` alternatives, including source-only
	   namespaced implementation files and fully-qualified C++ parameter
	   spellings whose decoded parameter types resolve through visible leaf
	   definitions. Simple visible C++ aggregate `struct`/public-field `class`
	   parameters by value or reference now decode through the same registry,
	   including source-only implementation-file inclusion when no project
	   header exposes the aggregate definition. C++ `FILE *` parameters now
	   reuse the POSIX `fmemopen` input stream decoder with cleanup.
   C++ typedef function-pointer callbacks now emit the
   same no-op trampoline support used by C harnesses, `std::function`
   callback parameters now receive generated no-op lambdas, and
   `std::optional<T>` / `std::pair<T, U>` / `std::tuple<T...>` /
	   `std::vector<T>` / `std::variant<T...>` / `std::deque<T>` /
	   `std::list<T>` / `std::forward_list<T>` / `std::set<T>` /
	   `std::map<K, V>` / `std::unordered_set<T>` /
	   `std::unordered_map<K, V>` / `std::array<T, N>` /
	   `std::bitset<N>` / `std::unique_ptr<T>` / `std::shared_ptr<T>` now reuse
	   supported owned C++ value decoders, including visible aggregate
	   vector/array/sequence-container elements, span-backed aggregate ranges,
	   pair/tuple/variant components including `std::monostate`, map mapped
	   values, optional values, and smart-pointer pointee types. Common
	   `std::chrono` duration aliases also decode from bounded integer values. The
   C++ parser now annotates straightforward member access, so sequence
   harnesses and auto sequence preference skip known `private`/`protected`
   lifecycle helpers.
   Constructor selection also ignores known non-public constructors and blocks
   classes that cannot be externally constructed with wrapper/factory guidance
   instead of emitting invalid receiver construction. Manual and auto C direct
   harnesses for `static` functions, plus C++ direct harnesses for `static`
   free functions, now include the defining source file into `main.c` or
   `main.cpp`, making internal-linkage helpers callable without a separate
   object link. C sequence harnesses and auto sequence preference also include
   the defining source when static init/end lifecycle helpers are needed.
   The Ada lane now reaches output-buffer parity with the C lane's
   output-pointer handling: an access-to-array out parameter (the canonical
   `decode (Dst : out p_Buffer; ...)` idiom, e.g. zip-ada `output_memory_access
   : out p_Stream_Element_Array`) gets a real bounded heap backing buffer
   allocated once at the harness level (leak-freed after the input loop); an
   access-to-stream out parameter (`output_stream_access`) gets a generated
   discard-stream sink for the standard `Root_Stream_Type'Class` or a concrete
   in-memory derivation for a custom class-wide stream root (zip-ada
   `Zipstream_Class_Access` → `new Memory_Zipstream`), instead of a null pointer.
   This removes the null-dereference false-positive class (the previous
   `unzip-decompress.adb:351`/`:346` artifacts) and turns output-buffer overflows
   into findable CWE-787 writes at the original source line. Record parameters
   now fuzz their fields AST-aware (enums via `'Val`, Unbounded_String, scalars;
   unresolved fields default), Unbounded_String input parameters fuzz instead of
   defaulting to empty, and every private-child target builds via the
   private-child-subprogram harness (zip-ada reaches 0 failed builds).
   **Delivered.** Deeper recursive object graphs and full C++ template/parity
   coverage are continuous improvement in §24 (v1.1+).
   (#345, #340)

The engine-parity backlog (Honggfuzz/Centipede, finishing LibAFL/Nyx
scaffolds) is the least urgent: govfuzz's own thesis correctly says
engines are not its identity.

**Gap-program status (2026-06-19): the five §25 deliverables are complete.**
Each gap's core capability ships and is regression-tested; what remains under
each is open-ended continuous improvement (broader semantic resolution that
would require Libadalang, recursive grammars, additional oracle classes, deeper
object graphs, full C++ template parity), reclassified into §24 (v1.1+). Together
with the MVP (§0) and milestones M0–M19 (§18), the roadmap's planned scope is
delivered; §24 tracks the post-1.0 backlog.

## 26. Pre-existing general gaps surfaced by native-Windows dogfooding (2026-06-25)

A native-Windows `govfuzz auto` campaign (run on a real Win10 host against a
variety of GitHub C/C++ projects — header-only, CMake, Visual Studio `.sln`, and
plain single-file) found and fixed five **Windows-specific** build/path gaps
(CMake probe detection + generator; export-macro return types; MSVC CRT-model
defines; MSVC-STL/clang version mismatch; make-env path separators — all shipped).
The targets below also exposed gaps that are **general, not Windows-specific** —
each reproduces on Linux and belongs to the C/C++ discovery/build-context/
harness-gen backlog (§24). They are recorded here for tracking; none is filed as a
GitHub issue yet (campaign workflow fixes Windows gaps directly), so each is a
candidate to promote to an issue / §24 item when scheduled.

1. **Whole-library linking for multi-TU targets.** A harness for a function in a
   multi-file library compiles but fails to link (undefined externals): the
   compile database recovers per-file `-I`/`-D`, but the harness links only
   `main` + the target's own source, not the rest of the library's translation
   units. Seen: zstd (`lib/common`,`lib/compress`,… — 4 link failures), miniz.
   Fix direction: link the project's built static library, or compile+link the
   library's full TU/object set from the compile DB. Area: `build.rs` harness
   build + compile-DB ingestion.

2. **A missing external dependency aborts the CMake probe with no fallback.**
   libspng's `find_package(ZLIB REQUIRED)` fails `cmake` configure → no
   `compile_commands.json` → every target fails to build. Fix direction: detect
   the failed-dependency configure error and report the missing package
   actionably; optionally retry a degraded configure or stub the dependency.
   Area: `auto/build_probe.rs`.

3. **Ranking attempts non-public / internal symbols.** `auto` ranks and tries
   `static` or non-header-declared functions that cannot be harnessed from a
   separate TU: cJSON `detach_path` (static), stb `readdir_raw` (internal), stb
   `stb__threadq_*` internals. Fix direction: down-rank/skip symbols that are
   `static`, absent from a public header, or match internal-naming conventions.
   Area: `target_rank` / discovery. (Same family as §24 ranking work.)
   **SHIPPED 2026-06-28**: `name_has_helper_marker` (target_rank/c_rank) now also
   marks the C reserved / library-internal naming conventions — a leading
   underscore on the leaf, an interior double underscore (stb's `stb__threadq_*`,
   C-reserved), and an `_impl` suffix — so such a symbol is demoted below the real
   public entry and excluded from the call-graph fan-out boost. `static` linkage was
   already soft-demoted (not skipped, since govfuzz reaches a static target via
   source-inclusion into main.c). Tested `reserved_and_internal_naming_conventions_are_demoted`.

4. **Targets with an incomplete (opaque) result/receiver type are attempted.**
   stb `stb_cfg` (aka `stb_cfg_st`), `stb_threadqueue` are forward-declared
   incomplete types; the harness emits `<IncompleteType> R;` →
   `error: variable has incomplete type`. Fix direction: skip a target whose
   result/receiver type is incomplete in the harness TU. Area: `harness_gen`.
   **SHIPPED 2026-06-28**: `TypeRegistry::resolves_to_incomplete_aggregate`
   (type_model) flags a result type that resolves BY VALUE (never through a pointer)
   to a struct/union present in the harness TU only as a forward declaration;
   `build_c_context` (harness_gen/c_generate) skips such a target with a precise
   `UnsupportedParamType` reason instead of emitting an uncompilable result capture.
   A POINTER result, a complete aggregate, or a type the registry never modeled is
   left alone (never skip on ignorance). Tested
   `resolves_to_incomplete_aggregate_flags_forward_declared_by_value_only` (type_model)
   + `incomplete_by_value_result_type_is_skipped_cleanly` / `pointer_to_incomplete_result_type_still_builds` (c_generate).

5. **Function-pointer typedef parameters block harness generation.** miniz
   `mz_alloc_func` / `mz_free_func` (fn-ptr typedefs) are unsatisfiable params, so
   the target is skipped/failed. Fix direction: pass `NULL` (or a generated no-op
   stub) for function-pointer parameters. Area: `harness_gen/c_decoders`.

6. **`double` / `float` parameters are reported "unsupported" in the C++ lifecycle
   path.** tinyxml2 skipped `DoubleAttribute`/`FloatAttribute` with
   `unsupported parameter type 'double' / 'float'`, though both are decodable
   scalars. Fix direction: decode `float`/`double` like the other scalar kinds in
   the C++ lifecycle-step decoder. Area: `harness_gen/cpp_generate`.
   **SHIPPED 2026-06-28**: by-value `float`/`double`/`long double` decode through
   `legacy_select_c_decoder` (`gf_i32`/`gf_i64` reinterpreted), so the registry-less
   lifecycle gate `cpp_parameter_type_supported` now accepts them. Regression
   `cpp_parameter_type_supported_accepts_floating_point_scalars` (harness_gen) pins
   the gate; the `cpp_float_double_method_builds_and_fuzzes` e2e fixture proves a
   `record(double, float, const std::string&)` method builds+fuzzes under clang++.
   (By-REFERENCE scalars — `const double &` — remain a separate pre-existing
   limitation shared with `const int &`.)

7. **Heavy C++ template / overloaded APIs are largely skipped.** tomlplusplus:
   most discovered signatures (the template-heavy `toml::parse` family) are
   skipped because args can't be synthesized. Fix direction: synthesize args for
   common template/overload shapes, or select the simplest viable overload. Area:
   `harness_gen/cpp_generate` (overlaps the §24 C++ template-parity backlog).
   **PARTIAL 2026-06-28**: the TEMPLATE half is addressed by the §27.5 instantiation
   lane (a free `generic<T>` function with a resolved specialization is now surfaced
   and harnessed with a turbofish call, where it was filtered outright before).
   OVERLOAD sets are already surfaced with disambiguated `Class::method(types)`
   names and `pick_cpp_target` harnesses the first viable (lowest-line) overload; a
   dedicated "rank overloads by argument simplicity" selector is still future work.

8. **CMake-generated export/config headers are not materialized by the
   configure-only probe.** miniz `miniz_export.h` (from `generate_export_header`)
   is not found at harness-build time. The probe runs `cmake` configure, but the
   generated header lands in the build dir and the harness include path misses it.
   Fix direction: add the probe build dir to the harness include search path, or
   copy generated headers beside the recovered DB. Area: `auto/build_probe.rs` +
   `generate_harness` include resolution. (Same "generated header" follow-up noted
   for the MSBuild `.sln` tier.)

Environment note (not a govfuzz defect): one pugixml target failed with
`clang++: error: unable to make temporary file: The file or directory is corrupted
and unreadable` — a transient Windows FS/clang temp-file error (the host had 36 GB
free). Optional robustness idea: retry a build once when it fails with a transient
temp-file/FS error rather than recording it as a missing dependency.

## 27. Auto-harness follow-ons (2026-06-25 issue sweep)

1. **Std reader-receiver + trait-method lane (Cursor/BufReader) — #458 (deferred
   half) + #462.** These are the SAME lane (byteorder `ReadBytesExt` class); #462
   is #458's deferred half filed as its own issue. The turbofish piece shipped in
   #458 (a marker type param like `B: ByteOrder`, used by no value argument,
   resolves to a reachable concrete `impl ByteOrder for BigEndian` and bakes a
   `read_u32::<BigEndian>(..)` call; `apply_marker_turbofish` in
   `auto/rust_build.rs`). The remaining FOUR pieces MUST LAND TOGETHER — parsing
   trait methods alone is net-negative (it adds skip-noise candidates with zero new
   builds unless paired with the ranking demotion + a constructible receiver):
   (1) `rust_parser::collect_functions` — collect bodyless `function_signature`
   nodes inside a `pub trait` (add `is_trait_method` to `RustFn`);
   (2) receiver synthesis for std reader traits — `let mut r =
   std::io::Cursor::new(a0);` from a decoded `&[u8]`, whitelist `Cursor`/`BufReader`,
   and emit the trait import (`use byteorder::ReadBytesExt;`) since a trait method
   has no enclosing concrete `impl` type (a `find_receiver_ctor` reader branch
   without the import emits non-compiling harnesses);
   (3) turbofish — DONE in #458;
   (4) ranking — demote un-constructable trait-method receivers so they don't waste
   budget when they can't build.
   Own design cycle. Area: `rust_parser` + `target_rank/rust_rank` + `auto/rust_build`
   + `harness_gen/rust_generate`. **SHIPPED 2026-06-28** (all four pieces):
   `rust_parser` collects `pub trait` methods (default + bodyless signatures) with
   an `is_trait_method` flag + `trait_supertrait` spelling; `rust_rank` treats a
   `: Read`/`BufRead` instance trait method as attacker-reachable (the synthesised
   receiver IS the channel) and DEMOTES every un-constructable trait method
   (static, or non-reader instance) by -60; `auto/rust_build::resolve_reader_trait_method`
   synthesises `std::io::Cursor::new(c.rest_bytes())` + `use <crate>::<Trait> as _;`
   and reuses `apply_marker_turbofish` to bake `read_u32::<BigEndian>()`. Verified
   build+fuzz against the cloned `byteorder` crate and a committed
   `tests/fixtures/rust_reader_trait` fixture (planted crash FOUND).

2. **Tree-wide (all-TU) C lifecycle discovery — #453, deferred sub-item.** The
   opaque-handle lifecycle table now keys typedef aliases to a canonical base
   (`struct widget *` ↔ a `widget_t` alias), keys an opaque `typedef void`
   handle by its typedef name (libde265 `de265_decoder_context`), and infers
   init/destroy by whole-token name patterns — all from the target's own file +
   its INCLUDED headers (`collect_c_declarations_for_harness` →
   `c_direct_lifecycle_table` in `generate_harness.rs`). The remaining sub-item
   is scanning ALL translation units in the tree (not just the target's
   includes) for init/destroy pairs, so a handle whose constructor is declared
   in a header the target does not directly `#include` is still paired. This
   belongs in the once-per-tree `decl_index` (the discovery layer), not the
   per-target harness path where an all-headers rescan would repeat for every
   candidate. Area: `auto` decl_index → threaded into the lifecycle table.
   **SHIPPED 2026-06-28**: `decl_index` computes `c_tree_lifecycle` ONCE from the C
   declarations of every TU in the tree (`compute_c_tree_lifecycle`, reusing
   `c_direct_lifecycle_table` over all tree decls), carried on `TreeTypeDefs`
   into the harness path; `merge_tree_c_lifecycle` (generate_harness) folds the
   tree-wide pairs into the per-target table local-first (fills a missing
   init/delete, or adds a handle the local pass never saw). Tested
   `computes_tree_wide_c_lifecycle_pairs_across_unincluded_headers` (decl_index) +
   the `attempt_pairs_tree_wide_c_lifecycle_from_unincluded_header` e2e (a handle
   whose ctor/dtor live in a transitively-included header the per-target scan does
   not follow now pairs and builds under clang).

3. **Callback arrays + variadic callbacks — #454, deferred slices.** A typedef'd
   function-pointer STRUCT FIELD now gets a callback trampoline assigned at
   struct-decode time (`DecodeContext` carries the registry + a file-scope
   `support` accumulator; `build_callback_trampoline` in `c_decoders.rs`) — the
   cJSON_Hooks / libxml2-SAX-handler idiom. Two slices remain: (a) a callback
   ARRAY field `void (*h[N])(...)` should allocate `N` trampolines and fill the
   array (needs funcptr-element handling in `emit_array_decode`); (b) a VARIADIC
   callback needs a `va_list` trampoline stub consuming a fixed cursor-byte arg
   budget. Inline (non-typedef) function-pointer fields also stay zeroed until the
   C parser emits the inline funcptr type intact. Area: `harness_gen/c_decoders`.

4. **C++ abstract-receiver substitution — #456, deferred phases.** A method on an
   abstract class now harnesses through a concrete, default-constructible DIRECT
   subclass — found ACROSS THE INCLUDE CLOSURE (the abstract base + its concrete
   impl commonly live in headers the target only `#include`s — libE57Format's
   Reader): `parse_cpp_subclasses` (cpp_parser) + `resolve_concrete_subclass`
   (generate_harness, now over `collect_cpp_inheritance_texts`) pick it (a header
   subclass with only a parameterised/private ctor is correctly NOT taken), and a
   `receiver_class_override` threaded into `cpp_generate` emits
   `<Subclass> _gf_receiver; _gf_receiver.method(..)` (the virtual call dispatches
   polymorphically). Remaining: (a) a subclass that needs constructor ARGS (not just
   a default ctor) — resolve its ctor like the base's; (b) Phase 3: a FACTORY
   function (`create_*`/`new_*` returning the base) as a fallback when no
   constructible subclass exists. Area: `cpp_parser` + `generate_harness` +
   `harness_gen`. **SHIPPED 2026-06-28**: both remaining phases landed. (a)
   `resolve_subclass_with_ctor` (generate_harness) finds the first concrete subclass
   whose public ctor has all-decodable args and constructs it with decoded
   arguments (`<Subclass> _gf_receiver(args); _gf_receiver.method(..)`). (b) when no
   constructible subclass exists, the abstract branch falls back to
   `find_cpp_factory_for_class`, accepting only a POINTER/reference-returning factory
   for the abstract base (`Base *make()` -> null-guarded `_gf_receiver->method(..)`).
   Unit tests `resolve_subclass_with_ctor_constructs_a_ctor_arg_subclass` /
   `find_cpp_factory_resolves_free_function_returning_base_pointer` pin the
   resolution; the `cpp_abstract_receiver_via_ctor_arg_subclass_*` /
   `cpp_abstract_receiver_via_factory_*` e2e fixtures prove both compile+fuzz under
   clang++ (planted OOB found).

5. **C++ template-function instantiation lane — #455, Phases 2+3 (own cycle).**
   Phase 1 shipped: `parse_cpp_template_instantiations` (cpp_parser) records the
   concrete instantiations seen at call sites (`parse<int>(buf)` ->
   `("parse", ["int"])`, including qualified `ns::convert<std::string,double>`).
   All `generic<T>` functions are still filtered at ranking
   (`cpp_api_is_unsupported_target` in `target_rank/c_rank.rs`), so the remaining
   lane is: (2) surface a templated target that has a detected instantiation as a
   candidate carrying its type args, and synthesise one instantiated harness per
   specialization — substitute the type args into the parameter types for
   decoding and emit a turbofish call (`ns::process<int>(args)`); (3) a
   `--template-instantiate int,std::string` flag to steer types for templates
   with no observed call-site instantiation. This needs a CppFunction
   instantiation-args field threaded parser -> ranker -> codegen, plus
   type-param substitution in `cpp_generate` — a real instantiation pipeline, its
   own design cycle. Area: `cpp_parser` (done) + `target_rank` + `generate_harness`
   + `harness_gen/cpp_generate`. **SHIPPED 2026-06-28 (phases 2+3, single-TU)**:
   `CppFunction` now carries `template_type_params` (the `template<typename T>`
   names) + `instantiation_args`; `parse_cpp_functions` resolves ONE specialization
   per free template from same-TU call sites (`annotate_template_instantiations`).
   The ranker (`cpp_api_is_unsupported_target`) surfaces a template once
   `instantiation_args` is non-empty; `cpp_generate` substitutes the type args into
   the parameter / result types (`substitute_template_type_params`) and emits a
   turbofish call (`fold_as<int>(..)`), force-including the defining `.cpp` so the
   template body is visible. Phase 3 flag `--template-instantiate int,std::string`
   steers a template with no observed call site. Tested:
   `template_function_records_type_params_and_call_site_instantiation` (parser),
   `cpp_ranker_surfaces_templated_function_with_resolved_instantiation` (ranker),
   `generate_cpp_direct_harness_instantiates_template_with_turbofish` +
   `substitute_template_type_params_*` (codegen), and the
   `cpp_template_instantiation_builds_and_fuzzes` /
   `template_instantiate_flag_steers_codegen` e2e fixtures. **Remaining**:
   cross-file instantiation aggregation (the template DEF in a header, the call site
   in a different TU) — a discovery-layer increment, since detection is per-file;
   and member-template (`obj.m<T>()`) call sites, which the parser does not yet
   collect.

6. **C/C++ preprocessor pre-parse — #460, discovery wiring (own cycle).** A
   reusable, recovering CPP-lite entry now exists: `preprocess_c_like(source,
   defines)` (idl_parser) applies object-like `#define` expansion and
   `#ifdef`/`#ifndef`/`#if` guard resolution before tree-sitter, passing through
   unknown/function-like directives and falling back to the raw source on error.
   The remaining work is wiring it into the C/C++ discovery lane (the ~6
   `c_parser::parse_c_functions` / `cpp_parser::parse_cpp_functions` call sites in
   `auto/discovery.rs`), behind a `--preprocess` flag (default-on for files with
   heavy conditional compilation) threaded through `discover_file`, AND — the
   load-bearing part — preserving a preprocessed-line -> original-line MAP so
   finding locations stay accurate (the preprocessor currently drops/expands lines
   without a source map; wiring it on without one would shift every reported
   location). `#include` expansion of in-tree headers is a further increment.
   Area: `idl_parser` (entry done) + `auto/discovery`.
   **SHIPPED 2026-06-28**: `preprocess_c_like_with_line_map` (idl_parser) returns the
   preprocessed text plus a `LineMap` (one entry per output line — exact by
   construction, since each source logical line emits exactly one output line — with
   `to_original` translating a preprocessed line back to its original, folds
   corrected; `#include` is now passed through verbatim so an active include no
   longer aborts preprocessing). `auto/discovery` parses C/C++ through
   `parse_{c,cpp}_functions_preprocessed`, translating every discovered function's
   line back to the ORIGINAL source, behind a `--preprocess auto|always|never` flag
   (`auto` = on only for files with ≥5 conditional directives) threaded through
   `discover_file`; the mode is folded into the discovery-cache fingerprint. The
   call-graph/visibility/header-classify sites stay on raw source (they parse the
   ORIGINAL TU, whose lines already align with the translated candidate lines).
   `#include` EXPANSION of in-tree headers remains the further increment. Tested
   `line_map_translates_preprocessed_line_back_to_original` /
   `line_map_corrects_for_backslash_continued_macro_fold` /
   `line_map_passes_includes_through_and_stays_one_to_one` (idl_parser) +
   `preprocess_mode_resolves_ifdef_branches_with_original_lines` /
   `auto_preprocess_fires_only_on_heavy_conditional_files` (discovery).

7. **Ada cross-package `.gpr` Source_Dirs — #450, increment 2 (SHIPPED).**
   Increment 1 shipped: `active_source_dirs(gpr_path)` (auto/gpr_scenario) returns
   the governing project file's default-scenario Source_Dirs (Ada-source dirs
   only), and `ensure_ada_src_instrumented` (auto/attempt) adds them to the
   instrumented set, so a target scanned in a subdir (ada-util `src/sys/encoders`)
   pulls in `src/core` + `src/sys` instead of failing `missing_ada_symbol`.
   Increment 2 shipped: (a) scenario/OS-variant gating now resolves a single
   coherent variant — `scenario_defaults` captures a literal-default selector
   (`OS : OS_Kind := "linux"`, not only `external(...)`), and `classify_dir_literals`
   precomputes each case's selected branch (value-match → `others` → first branch)
   so a unit defined under multiple OS variants pulls exactly one variant's dirs,
   never all (conflicting) nor none (under-included); (b) `walk_to_common_src_root`
   (auto/attempt) adds the nearest source-root-like ancestor (`src`) that roots a
   sibling Ada module when no `.gpr` governs, bounded so it never crosses into an
   unrelated parent; (c) the `ada_multidir_gpr` GNAT e2e fixture +
   `auto_ada_multidir_gpr` test exercise the built-target delta (a `src/parser`
   target whose dependency in the sibling `src/core` is pulled in and built).
   Area: `auto/gpr_scenario` + `auto/attempt`.

8. **Ada access-type opaque-handle lifecycle — #457, emission (SHIPPED).** The
   Ada-side registry plumbing: `discover_access_lifecycles` (harness_gen/registry)
   finds Init/Create + Delete/Free subprograms keyed by the access type they operate
   on (`is_ada_lifecycle_init`/`is_ada_lifecycle_delete` name patterns, the Ada
   analog of the C `is_c_lifecycle_*`), now resolving a subprogram's return/parameter
   type to an access type via the tree's `is access` declarations (the structural
   parser leaves them unresolved) and recording the constructor shape
   (`init_returns_handle`, `init_param_count`, `delete_param_count`) plus the
   designated base. The EMISSION shipped: `access_lifecycle_sink` (harness_gen/
   generate) declares the handle bare and emits a setup/call/cleanup SEQUENCE
   (`H := Create; target (H, ..); Destroy (H);`, via a new per-input
   `post_call_lines` template slot) instead of the null/slot decoder, like the C
   opaque-handle path. Designated-base resolution pairs a target spelled with a
   different access ALIAS to the same base. The `ada_access_lifecycle` GNAT e2e
   fixture + `auto_ada_access_lifecycle` test prove the emitted sequence compiles and
   fuzzes. Constructors needing config arguments (a non-nullary returning function)
   stay on the null decoder — a follow-up. Area: `harness_gen/registry` +
   `harness_gen/generate`.

9. **Inline function-pointer C parameters — #466, parser fix (deferred).** The C
   decoder now skips a malformed (unbalanced-paren) parameter type cleanly instead
   of scalar-decoding a split inline-funcptr fragment into a build-breaking
   `gf_i32` harness (the part-3 safety net). The deeper fix is upstream: keep an
   inline `int (*cb)(int, int)` parameter's type intact through the C parser's
   declaration path (`function_param_types` collapses it to `int` + stars, unlike
   the definition path `function_params` which already reconstructs `RET (*)(args)`
   — align them), then synthesise a `_gf_cb_<name>` typedef + trampoline in
   `build_callback_trampoline` to actually DRIVE the callback (it currently rejects
   inline funcptrs). Area: `c_parser` + `harness_gen/c_decoders`.

10. **In-crate Rust harness build mode — #463, deferred.** The external-crate
    private-module skip now gives an actionable reason ("make it `pub` and
    re-export with `pub use`, or build the harness in-crate") instead of a bare
    "not reachable". The real value is an IN-CRATE build mode: build the harness as
    an integration test / example INSIDE the target crate so a private-module type
    (`crate::internal::Parser`) is reachable by its full path, instead of as an
    external staticlib that genuinely can't see private items. Needs build-mode
    detection + emitting the full `crate::internal::...` path + the in-crate cargo
    wiring. Area: `auto/rust_build`. **SHIPPED 2026-06-28**: a private-module `pub`
    target (E0603 externally) is now detected in `resolve_target` (the two
    private-module skip sites dispatch to `resolve_in_crate_target` -> `BuildMode::InCrate`),
    its path is rooted at `crate::<module>::...`, and `build_in_crate` COPIES the
    target crate, injects the harness as a `#[doc(hidden)] pub mod __govfuzz_harness;`
    of its lib root, patches the copy's `Cargo.toml` (rust_runtime dep + `staticlib`
    crate-type + detached `[workspace]`), builds it with the sancov+ASan RUSTFLAGS,
    and clang-links the crate staticlib with the C driver. Verified build+fuzz of a
    private-module `Parser::parse` (planted crash FOUND) via
    `tests/fixtures/rust_incrate`. Known limitations (documented, not yet handled):
    a target crate with RELATIVE path-deps to siblings won't resolve from the copy
    (the copy needs path-dep rewriting); workspace-inherited manifest fields
    (`version.workspace = true`) and an edition-2015 crate (needs `extern crate`)
    are out of scope; in-crate param/ctor-arg OVERRIDES (enum picks, scratch consts)
    and in-crate trait-impl methods skip cleanly (they would need `crate`-rooted
    override/trait paths).

11. **Configurable decoder caps via CLI flags — #464 (C) / #465 (C++). DELIVERED.**
    A large over-cap fixed scalar array fuzzes its fill count (`0..cap`) instead of a
    fixed-prefix truncate, so inputs cover different slots (#464, `emit_array_decode`).
    The caps are now CONFIGURABLE: a `DecoderLimits {depth, array_elems, decl_bytes}`
    (C, threaded through `DecodeContext`) and a `CppDecoderLimits {container_size_max,
    bitset_max_size, array_max_size}` (C++, threaded through `CppContextInput` to the
    genuine cap usages — not every literal `16`) are driven by the
    `--max-decode-depth` / `--max-array-elems` / `--max-decl-bytes` (C) and
    `--container-size-max` / `--bitset-max-size` / `--array-max-size` (C++) flags,
    flattened (`DecoderLimitArgs`) into both `govfuzz auto` and
    `govfuzz generate-harness`. Defaults reproduce the historical hardcoded caps
    byte-for-byte (regression-tested). A per-parameter `len * sizeof(element) > ~1 MiB`
    OOM guard (`MAX_PARAM_BYTES`) clamps a dynamic container's element count and skips
    an over-budget fixed `std::array`, so a hand-cranked huge cap can't blow memory.
    Area: `harness_gen/c_decoders` + `harness_gen/cpp_decoders` + `harness_gen/{c,cpp}_generate`
    + `cli/generate_harness` (`DecoderLimitArgs`) + `auto/cli` (flags).

## 28. Campaign-discovered fixes (2026-06-28 session 2 — 19-project dogfood)

A two-wave campaign (byteorder, cpptoml, yaml-cpp, inih, tomlc99, jansson,
utf8proc, rust-csv, gson, commons-codec, parse_args, json-ada; then fmt,
cpp-peglib, libyaml, md4c, pest, regex, commons-lang) on the improved tool found
**zero govfuzz panics** across ~6000 candidates and shipped the following fixes.
All are regression-tested; the full suite stays green.

1. **Reporting: CWE on EVERY finding + group findings to one row per root-cause
   issue.** Every finding (fuzz crash, oracle, AND SBOM CVE) now carries a CWE in
   all reports including the CSVs — backfilled in priority order (explicit →
   `finding_rules` catalog by `rule_id` → bug-class map, extended to
   SIGABRT→CWE-617 / SIGFPE→CWE-369 / stack-exhaustion→CWE-674 /
   uncaught-exception→CWE-248 / Rust index-panic→CWE-125/787 → documented
   last-resort). The findings CSV/JUnit/markdown collapse to one row per
   *issue* (cluster key, else finding id) with a member count, the `fix_file`/
   `fix_line`, `member_finding_ids`, and per-member `reproducers`, plus a
   "Fix once" line and rendered patch diffs; SARIF stays one-result-per-occurrence
   (idiomatic) with a cluster `govfuzzIssueKey` fingerprint, CWE properties, and
   `result.fixes` from patch diffs. Area: `report` + `actionability`.
2. **SBOM CSV.** `sbom.csv` (flat one-row-per-component inventory) and
   `vulnerabilities.csv` (one row per CVE match with CWE/CVSS/KEV/reachability)
   now emit under `--emit csv`. Area: `governance`.
3. **Repair self-target livelock.** A refused self-target repair (a sibling
   symbol mis-attributed to the target's own TU) was re-proposed every iteration,
   burning the whole budget on one target; refused repairs are now deduped. Area:
   `auto/attempt`.
4. **Rust `&mut [u8]` output buffers.** A trait write method
   (`ByteOrder::write_u64(buf, n)`) was harnessed with an empty slice → guaranteed
   index-OOB panic FP storm; the harness now backs it with a sized scratch buffer.
   Area: `harness_gen/rust_decoders`.
5. **C++ defensive stdlib include prelude** (`<limits>` et al.) so a header that
   relies on a transitive include compiles in the minimal harness TU (cpptoml's
   `std::numeric_limits`). Area: `harness_gen` C++ template.
6. **C weak-stub incomplete-enum parameter** demoted to `int` (an incomplete
   `enum` by-value parameter/return is illegal in the stub TU; jansson). Area:
   `c_stub_gen`.
7. **Ada generic-package constructors** named through the synthesised instance,
   not the uninstantiated generic (`Json.Types.Create_Null` →
   `Govfuzz_Generic_Instance.Create_Null`; json-ada). Area: `harness_gen/generate`.
8. **Harness-incompatible compile flags filtered** from the recovered build
   context (`-fmodules-ts` / `-fmodule-*` / PCH flags; fmt). Area:
   `cli/generate_harness`.
9. **Full-TU-set link fallback** for a multi-TU library with no prebuilt archive:
   compile+link the whole library's translation units (from `compile_commands.json`
   or the sibling `src/` set) with the harness when an undefined-symbol link
   failure remains (yaml-cpp 0→4 built). The §26.1 secondary fallback. Area:
   `cli/generate_harness` + `auto/attempt`.
10. **In-crate build manifest** resolves/strips workspace-inherited fields
    (`include.workspace = true`, `version.workspace`, …) and re-anchors sibling
    `path` deps so the detached crate copy parses; a `#![forbid(unsafe_code)]`
    target crate (regex-syntax) or an unresolvable `workspace = true` dependency
    now skips cleanly with a reason instead of a hard `failed to parse manifest`.
    Area: `auto/rust_build`.

11. **C++ const-qualified by-value scalars** (`const bool`, `const double`,
    `const std::size_t`, …) now decode — a top-level `const`/`volatile` on a
    by-value parameter is stripped before the supported-type check (taocpp-json).
    Reference/pointer-to-const cases are unchanged. Area: `harness_gen/cpp_decoders`.
12. **Restrict-qualifier macros stripped from C/C++ parameter types.** A
    `restrict`-style macro (`restrict`/`__restrict`, or an unknown identifier in
    the qualifier position like xxHash's `XXH_RESTRICT`) was mis-parsed as the
    parameter NAME and stubbed, colliding with the real macro at build time. The
    C/C++ parsers now strip it. Area: `c_parser` + `cpp_parser` + `harness_gen/c_decoders`.
13. **C++ `#if`-in-struct-body recovery + never-emit-uncompilable-code.** A
    preprocessor `#if` inside a class member-initializer/body derailed
    tree-sitter ERROR recovery so the struct never closed, swallowing sibling
    free functions / other classes / a namespace as bogus members — the sequence
    harness then emitted `receiver.<non-member>()` (tinyobjloader `MappedFile`,
    uncompilable). A conditional-blanked re-parse now provides the authoritative
    member set and evicts bogus members; the C++ generator validates every
    emitted call/return and SKIPS cleanly rather than emit uncompilable code.
    Area: `cpp_parser` (`reconcile_recovered_scope`) + `harness_gen/cpp_generate`.
14. **Header-API roots suppress tool/test dir-name exclusions.** The
    organizational dir-exclusion set (`cli`/`app`/`tool(s)`/`test`/`example`/…,
    matched case-insensitively, for command-line-tool & test directories) wrongly
    dropped a library's own namespace directory under `include/` — CLI11's
    `include/CLI/` matched `cli`, so `auto <root>` discovered 0 targets (vs 262
    pointing at `include/CLI` directly). A dir under an `include/`/`inc/`
    ancestor now suppresses the DEFAULT name-heuristics (user `--exclude-dir` and
    the hard `.git`/`build`/`target` exclusions still apply), mirroring the
    existing `src/main/java` exception. Area: `auto/discovery`.
15. **Never instantiate an abstract Java class.** govfuzz emitted
    `new AbstractType(...)` (commons-validator `ModulusCheckDigit`) →
    uncompilable. The Java parser now collects abstract-class/interface types and
    the harness gates receiver/constructor strategies on non-abstract, skipping
    cleanly otherwise. Area: `java_parser` + `auto/java_build` + `harness_gen/java_generate`.
16. **In-crate Rust `#[no_mangle]` under a conditional unsafe-forbid.** The
    in-crate build's injected `#[no_mangle]` harness was rejected by a target
    crate forbidding unsafe code via `cfg_attr(<pred>, forbid(unsafe_code))`
    (pulldown-cmark) and on edition 2024 (bare `#[no_mangle]` is an error). The
    in-crate path now detects the `cfg_attr` forbid form (skip cleanly) and emits
    `#[unsafe(no_mangle)]` so 2024-edition crates build. Area: `auto/rust_build`.
17. **Calling-convention macros in function-pointer declarators.** A convention
    macro in the declarator — cJSON's `void *(CJSON_CDECL *allocate)(size_t)`
    (`CJSON_CDECL` = `__stdcall`/empty), or `__cdecl`/`WINAPI`/`CALLBACK`/… — was
    mis-parsed as the field/param NAME, so the harness emitted `.CJSON_CDECL = …`
    which after the empty macro expansion became `. = …` → "expected identifier".
    The C parser now reads the name from the `*name` pointer declarator, skipping a
    leading convention keyword or unknown all-caps macro (the same qualifier-macro
    family as item 12's `restrict`); the decoder also skips any field whose name
    isn't a valid C identifier. Area: `c_parser` + `harness_gen/c_decoders`.

The full-TU-set link (item 9) is gated to a genuine library-wide failure
(`WHOLE_LIBRARY_TU_MIN_UNDEFINED` undefined externals); a single resolvable
helper stays on the precise per-symbol `AddSource` path. The flaky
builtin-fuzz runtrace-oracle test was hardened against parallel-load starvation.

Documented residuals (separate lanes / niche, not blocking): abstract-receiver
construction that needs constructor ARGS (§27.4 phase; tinyobjloader
`StreamReader`); fmt's template-metaprogramming + user-defined-literal operators;
cpptoml `shared_ptr<base>` receiver construction; json-ada
`Ada.Iterator_Interfaces` instance member visibility through the synthesised
instance; libexpat referencing Windows-only `rand_s`/`GetLastError` on Linux (the
stub mechanism handles most externals; these few stay "blocking" — a niche
platform-config case); xxHash `static`-internal-function reachability + incomplete
`XXH3_state_t`; a multi-parameter function-pointer typedef
(`yaml_read_handler_t`) on the inline-funcptr path; Java offline Maven transitive
dependencies (correct offline behavior, not a defect).

## 29. Legacy / pre-modern language dialect support (M22, 2026-06-29)

Government and military code runs on language dialects that predate the versions
the lanes targeted: original **Ada 83**, **K&R / pre-C99 C**, **pre-C++98**
"C with classes", **Python 2**, and **Perl 4 / early Perl 5**. Before M22 every
non-Ada lane hardcoded the *modern* dialect at three layers (the tree-sitter
grammar, the generated harness, the runtime/coverage tracer), so legacy targets
were silently dropped at discovery or failed late with opaque build errors, and
there was no version-detection layer anywhere.

Epic #469. Strategy: **hybrid** build (use the modern toolchain's legacy flags
where they exist — `gnatmake -gnat83`, `clang -std=c89`, Perl 5 runs Perl 4; a
real legacy interpreter only where unavoidable — Python 2.7; transpile only as a
last resort — pre-C++98). **Report-only fallback**: legacy code that cannot build
or execute is still discovered + statically analyzed (each finding carries a CWE)
with a `not fuzzed: <reason>` status, never silently dropped.

### Phase 0 — version spine + report-only outcome (#470)

- New leaf crate `lang_profile`: `Dialect` (the detected source dialect),
  per-lane source-text detection, `HarnessProfile::for_dialect` (modern floors
  reproduce today's behavior exactly), and `Dialect::fuzz_support` (legacy
  dialects with no lane yet → report-only).
- `Candidate.dialect` (detected in discovery, round-tripped through the discovery
  cache); `Outcome::ReportOnly { reason, dialect, static_findings }` wired through
  the summary, labels, and reports.
- `auto::report_only::emit_report_only` runs the existing `static_analysis`
  scanner over a report-only target and writes CWE-tagged findings into the same
  findings tree the fuzz path uses, so they appear in every report format. The
  attempt loop routes a candidate whose dialect has no fuzzing lane there.

### Phase 1 — Tier-1 floor-lowering (no new parsers)

- **1a (#471):** `c_runtime/govfuzz_decode.h` is genuinely C89-clean (the
  runtime-value compound initializer became field assignment), verified under
  `-std=c89/c90/gnu89 -ansi -pedantic-errors`. Under the hybrid strategy the C
  harness builds with a modern `clang -std=c89` and C++11/14 targets build via
  the deliberate `gnu++20` superset.
- **1b (#472):** the Python driver dropped its lone f-string (`.format()` → imports
  on 3.0–3.5) and the Perl driver dropped the `//` defined-or (`defined(..) ? ..`
  → runs on 5.6–5.9); interpreter version probes skip too-old interpreters with an
  actionable reason.

### Phase 2 — Python 2 (#473)

`python_parser::parse_python2_functions`, a tolerant line-based extractor (the
tree-sitter grammar is Python 3 only), discovers Python 2 functions so they are
ranked and reported on instead of dropped. Where a `python2` interpreter is
present a later increment fuzzes them; absent, report-only is the fallback.

### Phase 3 — legacy C / K&R (#474)

`c_parser::parse_knr_functions` recognizes old-style definitions (bare-identifier
parameter lists + a separate declaration block) and synthesizes the ANSI
prototype as a `CFunction`, so K&R targets are discovered + reported on (the
substring C rules, e.g. GF-401 strcpy, fire on K&R source → CWE findings).

### Phase 4 — Ada 83 (#475)

`AdaStandard::Ada83` (the smallest `Ord` value, so post-83 reserved words lex as
identifiers — the reduced 83 keyword set); `pragma Ada_83` is accepted instead of
rejected, parsed best-effort, built `-gnat83`, and reported on.

### Phase 5 — pre-C++98 + Perl 4 (#476)

Pre-standard `.h` iostream headers flag the `cpp_pre98` dialect → report-only (no
modern compiler accepts cfront/ARM C++). Perl 4 is handled by the existing Perl 5
lane (Perl 5 is backward-compatible and runs most Perl 4), so it fuzzes there
rather than degrading.

### Deferred / honest limits

- Interpreter-level **Python 2** fuzzing needs a `python2` install (EOL); absent,
  report-only is the fallback. A py2-compatible runtime + lane is the increment.
- Compile-level **K&R** fuzzing (building the recovered prototype under `-std=c89`
  via an `AUTO_EXTRA_CFLAGS` injection) is the richer follow-up; the runtime is
  already C89-clean and the extractor recovers the signatures.
- Genuinely **cfront** pre-C++98 code that the permissive tree-sitter-cpp grammar
  cannot parse at all yields no candidate (documented limitation); modern-C++-
  with-pre-standard-headers is the common, handled case.

---

## 30. v1.1 development program (2026-07-11)

This dated program is now substantially delivered: the product has sixteen
fuzzing lanes, PR-native CI, differential fuzzing, and the COBOL, Fortran,
JavaScript/TypeScript, and C# paths described below. The original sequencing is
preserved as the implementation record.

### 30.1 PR-native incremental CI + GitHub Action — usability is the acceptance bar

**Goal:** running govfuzz on every pull request must take one `uses:` line and zero
configuration. The design bar is *extreme usability*, not just capability.

- **`govfuzz ci` mode** — diff-scoped. Given a base ref (`--diff <ref>`, defaulting
  to the PR base / `merge-base`), discover only the changed functions/files and
  their reachable closure and fuzz/scan just those; the rest is skipped.
- **Incremental cache** — persist `scan_index` + corpus across runs keyed by content
  hash; unchanged targets are not re-fuzzed. A warm cache makes repeat PR runs fast.
- **Action** — `Tarmo-Technologies/govfuzz-action` (composite/Docker): one `uses:`
  line, sensible defaults, triggers on `pull_request`. Auto-detects languages and
  build; no config file required.
- **Output where reviewers already are** — inline PR review comments on the changed
  lines for each finding; SARIF upload to the GitHub code-scanning tab; and one
  concise PR summary comment (counts, confirmed-vs-static, CWE breakdown, wall-time).
- **Sane exit semantics** — non-zero exit only on *new confirmed* findings by
  default (configurable: `all` / `confirmed` / `never`); a PR that touches nothing
  fuzzable reports "nothing to do" and passes.
- **Usability guardrails** — bounded default wall-time budget; clear line-accurate
  annotations; a `--dry-run`/preview; helpful failure messages when a toolchain is
  missing (never a silent skip).

**Acceptance:** adding ~3 lines of YAML to any supported-language repo produces
line-level PR annotations on the next PR with no further setup, and repeat runs are
fast on a warm cache.

**Shipped 2026-07-12.** `govfuzz ci --changed-since <ref>` (+ `--changed-paths-from`,
`--sarif`, `--ci-json`, `--pr-gate {off,confirmed,all,never}`), a shared `git_diff`
module (merge-base aware) reused by `list-targets`, and the composite Action
`.github/actions/govfuzz-pr/` (base-ref resolve, release-binary install with source
fallback, SARIF upload, sticky comment) with a copy-paste example workflow and
`docs/site/ci.md`. Scoping reuses the post-discovery `target_files` filter + the
discovery cache. Remaining follow-up: true incremental baseline delta (fuzz base vs
head, report only newly-introduced findings) — diff-scoping covers the common case.

### 30.2 Differential fuzzing — a new confirmed-bug class

**Goal:** feed identical inputs to two implementations (or two versions of one API)
and flag behavioral divergence — a bug class neither crash-only fuzzers nor
syntactic SAST catch.

- **Foundation present:** the `DifferentialOutputRuntime` oracle already detects
  output divergence; design doc at `docs/differential-fuzzing.md`.
- **`govfuzz auto --differential <a>:<b>`** — two targets (two libraries, or old vs
  new of the same API). A shared corpus and shared typed decoder guarantee both
  sides see the identical input; divergence in return value, output bytes,
  exception/panic, or exit is recorded as a finding (CWE-440 / CWE-697 family) with
  both observed outputs captured for the report.
- **Headline use case:** same source at two git refs — behavioral regression
  detection. Native lanes first (C/C++/Rust).

**Shipped 2026-07-12 (two-compiler variant).** The standalone `govfuzz differential`
subcommand (arbitrary two-harness + metamorphic, stdout compare) already existed; the
new piece is auto-integration: `govfuzz auto --differential clang:gcc` rebuilds each
C/C++ harness under both compilers (a portable `make diff` target) and replays the
fuzz corpus through both, flagging **exit/crash divergence** as a GF-301 finding in
the normal report (govfuzz harnesses suppress target stdout, so exit status is the
signal). Remaining: two-source-tree / two-git-ref differential (build the same API
from two trees and compare) and richer semantic comparators.

### 30.3 New language lanes — COBOL, Fortran, JavaScript, C#

Each follows the established lane recipe: tree-sitter discovery + ranking → harness
gen → build → framed fork-server + coverage → CWE mapping + static rules. Discovery
+ static rules (report-only) land first, then the native fuzzing lane, so partial
coverage ships incrementally. Legacy-government languages first (on-thesis), then
mainstream.

- **COBOL** — **Shipped 2026-07-12** (the first turnkey COBOL fuzzer). Rather than a
  separate lane, COBOL reuses the C engine: a `PROGRAM-ID` with a fuzzable `LINKAGE`
  `PIC X` operand is translated to C with `cobc -C -debug -fec=all` (free/fixed format
  detected, copybook `-I` dirs collected), wrapped in a generated driver that drives
  the primary buffer + a length operand + zeroed rest, and fuzzed on the C fork-server
  path (edge coverage, CmpLog, ASan). Two crash oracles (ASan + libcob `-fec` runtime
  checks) with `.cob:line` + CWE attribution, plus the taint-confirmed sink oracles
  (command/SQL/path injection) apply. From-scratch scanner (no tree-sitter-cobol
  needed). cobc is GPLv3 (subprocess-only), libcob LGPLv3 (links into the user
  harness, like the GNAT runtime). Validated on a 23-project / 2925-file campaign:
  0 panics, 30/38 build+fuzz, 0 crash-FPs, 2 real command-injection findings. See
  `docs/site/cobol.md`. **Remaining:** `ACCEPT`/file-`READ` input surfaces, linking
  sibling `CALL`ed programs, embedded `EXEC SQL`/`CICS`.
- **Fortran** — **Shipped 2026-07-12.** Like COBOL, reuses the C engine: a
  `subroutine`/`function` with a `character` byte-buffer argument is compiled with
  `gfortran -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp` and driven by
  a generated glue calling it via the gfortran C ABI (args by reference, a hidden
  length per character arg; primary buffer heap-allocated to the input size so a
  real OOB hits ASan's redzone). ASan is the memory oracle with native `.f90:line` +
  CWE attribution — no exit-interposition needed. From-scratch scanner. libgfortran
  (LGPLv3) links into the user harness like the C runtime. Campaign: 20 projects /
  40,367 files, 0 panics, 13,406 fuzzable procedures, 6,500+ exec/s, 0 FP. See
  `docs/site/fortran.md`. **Remaining:** numeric-array / Fortran-`READ` surfaces,
  module `use`-dependency compilation, full fixed-form (.f77) column parsing.
- **JavaScript / Node.js** — **Shipped 2026-07-12.** Node interpreted lane (like
  Python/Perl): an exported function (CommonJS + ESM) taking a `Buffer`/`string` is
  discovered and fuzzed by the builtin engine driving one warm Node process over the
  framed protocol. Coverage is **real V8 precise block coverage** (inspector
  Profiler, no source rewrite) folded per input — keyed on `(script, block span,
  taken-bit)` — into the shared `GOVFUZZ_COV_SHM` map, so the engine gets genuine
  branch feedback. An uncaught non-rejection exception hard-halts (exit 86); stack
  overflow → GF-207, resource `RangeError`/OOM → GF-209, else GF-210. `TypeError`
  (+ `SyntaxError`/`URIError`) is input rejection (the untyped-lane policy), and a
  first-argument name filter drops internal array/options helpers. Validated on a
  30-project / 2,018-file campaign: 0 panics, 531 fuzzable functions, 0 false
  positives; finds an uncontrolled-recursion crash end-to-end. Post-launch: a mined
  literal **dictionary** (past `==` gates), **class instance + static methods**, and
  a taint-confirmed **command-injection detector** (GF-431/CWE-78). See
  `docs/site/javascript.md`. **Remaining:** multi-argument synthesis; more sink
  detectors (path traversal, prototype pollution).
- **TypeScript** — **Shipped 2026-07-12.** Reuses the JS parser + Node framed
  driver: the `.ts`/`.tsx` source is discovered directly (the name-extracting
  parser strips type annotations; interfaces/type aliases/`private`/`abstract`
  members excluded), transpiled to CommonJS with esbuild (local imports bundled,
  `node_modules` external), and fuzzed by the same warm-Node driver. `.d.ts` skipped.
  See `docs/site/javascript.md#typescript`.
- **C#** — **Shipped 2026-07-12.** .NET lane over the shared fork-server engine: a
  `public` method taking a `byte[]`/`string`/`Stream` is discovered, the target is
  built via `dotnet` through a project reference (the reference pinned to the best
  framework the installed SDK supports), its IL is instrumented with SharpFuzz
  (`sharpfuzz <dll>`, Apache-2.0 — subprocess + user-harness-linked, never linked
  into govfuzz), and the driver `mmap`s `GOVFUZZ_COV_SHM` into
  `SharpFuzz.Common.Trace.SharedMem` (the AFL 64 KB map == `GOVFUZZ_COV_BITS`) to
  bridge real edge coverage. A warm CLR is kept alive over the framed protocol; an
  uncaught non-rejection exception hard-halts (exit 86) and maps to a GF rule + CWE.
  Like the JVM lane it runs without the LD_PRELOAD shim (the .NET host's own
  startup I/O would trip the TOCTOU/open oracles). Validated on a 25-project /
  69,608-file campaign: 0 panics, 3,113 fuzzable methods discovered; end-to-end on
  YamlDotNet at ~15k exec/s with 2,304 edges and 8 fuzz-confirmed
  `IndexOutOfRangeException` findings (a real empty-string edge case). See
  `docs/site/csharp.md`. **Remaining:** widen beyond a single input parameter
  (constructed options/context objects, generic methods), and a dictionary miner.

### 30.4 Sequencing and honesty

- **Order:** (1) PR-native CI + Action, (2) differential fuzzing, (3) COBOL,
  Fortran, JavaScript, C# lanes.
- **Strict-permissive thesis holds:** any GPL compiler (GnuCOBOL, gfortran) is
  subprocess-only, never linked; every new tree-sitter grammar is re-verified
  MIT/permissive per §1.2 before vendoring.
- **Coverage-guided where the runtime allows.** Shipped: JS/TS use V8 coverage,
  C# uses SharpFuzz IL coverage, and COBOL/Fortran use compiler edge/compare
  coverage on the generated/native C path.
