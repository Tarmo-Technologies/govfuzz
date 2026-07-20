<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Licensing

GovFuzz fuzzes sixteen languages — **Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP**. SBOM/SCA ingestion spans a broader set of ecosystems still (Cargo, npm, PyPI, Go modules, Maven/Gradle, NuGet, RubyGems, Packagist, CPAN, Conan/vcpkg/CMake/Meson, and Alire), scanned for supply-chain findings whether or not the language is a fuzzing lane. This document covers the licensing of govfuzz's core dependencies.

## Dependency matrix

| Component | Purpose | License | Tier | Risk | Recommendation |
|---|---|---|---|---|---|
| From-scratch scanner (govfuzz) | Permissive Ada lexer + structural parser | Apache-2.0 (ours) | **Core** | Grammar drift | Author in-house. Only path to true permissive guarantee. |
| tree-sitter | Generic incremental parser engine | MIT | **Core** | Low | Link directly. |
| tree-sitter-ada | Ada grammar for tree-sitter | MIT (verify per release) | **Core** (after license re-verification per upgrade) | License churn, grammar coverage gaps | Vendor at a pinned commit; CI license-audit job. |
| tree-sitter-c | C grammar for tree-sitter | MIT | **Core** | Low | Link directly for C source scanning. |
| tree-sitter-cpp | C++ grammar for tree-sitter | MIT | **Core** | Low | Link directly for C++ source scanning. |
| tree-sitter-rust | Rust grammar for tree-sitter | MIT | **Core** | Low | Link directly for Rust source scanning (native Rust discovery lane). |
| tree-sitter-java | Java grammar for tree-sitter | MIT | **Core** | Low | Link directly for Java source scanning (native Java discovery lane). |
| tree-sitter-python | Python grammar for tree-sitter | MIT | **Core** | Low | Link directly for Python source scanning (native Python discovery lane). |
| tree-sitter-perl | Perl grammar for tree-sitter | MIT | **Core** | Low | Link directly for Perl source scanning (native Perl discovery lane). |
| tree-sitter-go | Go grammar for tree-sitter | MIT | **Core** | Low | Link directly for Go source scanning (native Go discovery lane). |
| ASM (org.ow2.asm) | JVM bytecode instrumentation for govfuzz's own coverage agent | BSD-3-Clause | **Core (subprocess/agent runtime)** | Low (permissive, strict-permissive clean) | NOT linked into the govfuzz Rust binary. Bundled into the standalone `govfuzz-jvm-agent.jar` (a `-javaagent` for the user's JVM, like GNAT subprocess use); built from `java_runtime/` by `build-agent.sh`, ASM fetched into a cache (or pre-staged for air-gap). |
| cc (Rust) | Build helper for vendored parser C sources | MIT/Apache-2.0 | **Core build** | Low | Build-time only; covered by `govfuzz license-audit` and `cargo deny`. |
| GPR2 library | Programmatic .gpr parsing | GPLv3 (with RLE for runtime, not for tooling linkage) | **Forbidden** (linked); **External-only** via `gprbuild --print-*` parsing | Copyleft contamination if linked | Do not link. Parse `.gpr` ourselves; shell out to `gprbuild` for builds. |
| GPRbuild | Project build driver | GPLv3 | **External-only** | None when invoked as subprocess | Allowed as user-installed subprocess in `external-tools`; not bundled. |
| FSF GNAT/GCC | Ada compiler | GPLv3 + GCC Runtime Library Exception | **External-only** | The GCC RLE permits compiled-program redistribution but does not let us link Ada front-end libraries | Subprocess only. Document RLE boundary in `THIRD_PARTY.md`. Generated Ada code that links GNAT runtime is fine for end users compiling their own harnesses. |
| GNAT.Exception_Actions | Global raise hook | GPLv3 + GCC RLE | **Optional plug-in** (day-one in `external-tools`) | Same RLE caveat as runtime; implementation-defined unit | Source-instrumentation default. `--probe gnat_actions` available on day one in `external-tools`; refused in `strict-permissive`. |
| GNAT.Exception_Traces | Symbolic backtrace | GPLv3 + GCC RLE | **Optional plug-in** | Same | Opt-in. |
| GNATfuzz | AdaCore fuzzing tool | Proprietary / non-free distribution | **Forbidden** | Direct competitor; license incompatible | Never depend on. |
| GNATcoverage | Coverage tool | GPLv3 | **Forbidden** in core | Subprocess use still pulls in copyleft tooling expectations and doesn't fit MVP | `research-lab` only. |
| AFL++ | Coverage-guided fuzzer | Apache-2.0 | **Optional adapter** | Low | Adapter in `crates/fuzz_engine/afl_adapter`. Not bundled binary; user-installed. **Native C/C++ targets only** — not Ada, Rust, Java, or cross-compiled/emulated targets. |
| LibAFL | Embeddable fuzzing library | MIT/Apache-2.0 dual | **Optional embedded** | Low | Optional Cargo feature `libafl-engine`. |
| LLVM / libFuzzer | LLVM compiler infra and in-process fuzzer | Apache-2.0 with LLVM exceptions | **Deferred** | LLVM/Ada front end is not production-grade | Deferred — not yet implemented (awaiting Ada/LLVM toolchain). Only the builtin engine and AFL++ participate in the auto cascade. |
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
| tempfile (Rust) | RAII cleanup for compiler capability canary files | MIT/Apache-2.0 | **Core** | Low | Allow. |
| tera (Rust) | Harness template engine | MIT | **Core** | Low | Allow. |
| tokio | Async runtime | MIT | **Candidate** (not in `Cargo.lock`) | Low | Pre-cleared to allow if a future async need arises; not currently linked. |
| nom / chumsky | Parser combinators (IDL) | MIT/Apache-2.0 | **Not used** | Low | The IDL subset parser (`crates/idl_parser`) is hand-rolled; neither crate is linked. |
| zstd / lz4 | Corpus compression | BSD-3 / BSD-2 | **Candidate** (not in `Cargo.lock`) | Low | Pre-cleared; corpus storage is currently uncompressed. |
| sha2 | Hashing | MIT/Apache-2.0 | **Core** | Low | Allow. `blake3` is pre-cleared (BSD/CC0/Apache-2.0) but not currently linked. |
| regex | Diagnostic parsing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| num_cpus (Rust) | Detect host CPU count for `govfuzz auto` worker pool | MIT/Apache-2.0 | **Core** | Low | Allow. |
| rayon (Rust) | Data-parallel static-scan file pipeline (10M-SLOC scale) | MIT/Apache-2.0 | **Core** | Low | Allow. Work-stealing pool bounded to cores-1; deterministic order-preserving collect. |
| chrono (Rust) | RFC3339 timestamps in `govfuzz auto` reports | MIT/Apache-2.0 | **Core** | Low | `default-features = false` + `clock` only; no serde / windows-bindings pull-in. |
| which (Rust) | Compiler binary discovery on PATH | MIT | **Core** | Low | Allow. |
| libc (Rust) | Unix `prctl` / `setrlimit` safety rails on spawned fuzz harnesses | MIT/Apache-2.0 | **Core** | Low | Allow. |
| ureq + rustls/webpki roots (Rust) | Bounded synchronous HTTPS for optional OpenAI/Anthropic LLM providers | MIT/Apache-2.0; certificate trust-anchor data is CDLA-Permissive-2.0 | **Core (optional network path at runtime)** | Remote data disclosure if explicitly selected; certificate data has a permissive attribution license | No request occurs by default. API keys are environment-only, response sizes/timeouts are bounded, and local/MCP modes remain token-free. |
| criterion | Bench (dev-only) | Apache-2.0/MIT | **Candidate** dev (not in `Cargo.lock`) | Low | Pre-cleared for benchmarking; not currently a dev-dependency. |
| toml (Rust) | Golden-file manifest parsing in tests | MIT/Apache-2.0 | **Core dev** | Low | Dev-only dependency for hand-written corpus manifests. |

CI enforces the SPDX allow-list with `cargo deny`, the per-file SPDX header check (`crates/spdx_check`), and `govfuzz license-audit` for the resolved core dependency graph plus this matrix. Reviewers are responsible for keeping this matrix in sync with `Cargo.lock` when adding dependencies.

GovFuzz's CORBA support is self-contained: it generates its own fake-CORBA scaffolding and IDL-to-Ada mapping, so the ORB libraries above (PolyORB, TAO, omniORB, JacORB) are listed only to document why they remain forbidden or `research-lab`-only — they are never linked dependencies. The LD_PRELOAD runtrace shim that supplies govfuzz's behavioral/taint oracles (GF-405 path control, GF-304 command injection, GF-417 insecure temp, GF-305 sensitive env) is native-only (C/C++/Ada/Rust); it is not armed during Java fuzzing or under cross-compiled/emulated (qemu/wine) targets, where those oracle classes are unavailable.

## Test fixtures

- **miniz 3.0.2** — vendored under
  `tests/fixtures/build_recovery/fixtures/miniz/` (test-only;
  not redistributed in the govfuzz binary). License: MIT.
  Upstream: <https://github.com/richgel999/miniz>. Release zip
  sha256 `ada38db0b703a56d3dd6d57bf84a9c5d664921d870d8fea4db153979fb5332c5`.

## GCC RLE boundary

Generated Ada files (`adafuzz-*.ad?`, harnesses, fake-CORBA, and stubs) are Apache-2.0 and include SPDX headers. End users compile those generated files against their own GNAT runtime. The GCC Runtime Library Exception applies to redistribution of binaries produced by that compilation, but govfuzz does not link GPL Ada front-end libraries into the core Rust graph.
