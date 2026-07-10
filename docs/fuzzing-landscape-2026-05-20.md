<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fuzzing Landscape Research - 2026-05-20

This memo summarizes current fuzzing tool capabilities, recurring user pain
points, and feature opportunities for GovFuzz. Scope is Ada and C/C++ first.
Other languages should stay behind this backlog until GovFuzz is clearly
feature-rich in those three languages.

## Sources Reviewed

Primary tool and platform sources:

- AFL++ features and mutator documentation:
  https://aflplus.plus/docs/features/ and
  https://aflplus.plus/docs/custom_mutators/
- AFL++ grammar mutator:
  https://github.com/AFLplusplus/Grammar-Mutator
- AFL++ status and stability guidance:
  https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/afl-fuzz_approach.md
- LLVM libFuzzer:
  https://llvm.org/docs/LibFuzzer.html
- Google FuzzTest:
  https://github.com/google/fuzztest
- Google Honggfuzz:
  https://github.com/google/honggfuzz
- Google Centipede:
  https://chromium.googlesource.com/external/github.com/google/fuzztest.git/+/refs/heads/cl/540577910/centipede/README.md
- OSS-Fuzz and Fuzz Introspector:
  https://google.github.io/oss-fuzz/faq/ and
  https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/
- Fuzz Introspector blocker guide:
  https://fuzz-introspector.readthedocs.io/en/latest/user-guides/analyse-fuzz-blocker.html
- ClusterFuzzLite:
  https://github.com/google/clusterfuzzlite and
  https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/
- FuzzBench:
  https://github.com/google/fuzzbench
- GNATfuzz:
  https://docs.adacore.com/live/wave/gnatdas/html/gnatdas_ug/gnatfuzz/gnatfuzz_part.html

Research and community signals:

- "The Human Side of Fuzzing":
  https://binlin.info/downloads/Nourry2023a.pdf
- "An Empirical Study of OSS-Fuzz Bugs":
  https://arxiv.org/abs/2103.11518
- "Evaluating Fuzz Testing":
  https://arxiv.org/abs/1808.09700
- "SoK: Prudent Evaluation Practices for Fuzzing":
  https://arxiv.org/abs/2405.10220
- "Beyond the Coverage Plateau":
  https://thuanpv.github.io/publications/Fuzzing23_FuzzBlockers.pdf
- Firefox fuzzing oracle guidance:
  https://firefox-source-docs.mozilla.org/tools/fuzzing/index.html
- Mutation-fuzzing limitations discussion:
  https://www.trust-in-soft.com/resources/blogs/why-mutation-based-fuzzing-misses-bugs
- C++ community discussion:
  https://www.reddit.com/r/cpp/comments/1npke3t/fuzzing_at_boost/
- DevSecOps adoption discussion:
  https://www.reddit.com/r/devsecops/comments/1ins3xq/why_arent_coverageguided_fuzzers_more_widely_used/
- Hacker News discussion on fuzzing ergonomics and results triage:
  https://news.ycombinator.com/item?id=26731751
- OSS-Fuzz examples of practical pain:
  https://github.com/google/oss-fuzz/issues/3629,
  https://github.com/google/oss-fuzz/issues/4497,
  https://github.com/google/oss-fuzz/issues/13975, and
  https://github.com/google/oss-fuzz/issues/11094
- AFL++ persistent-mode support discussion:
  https://github.com/AFLplusplus/AFLplusplus/discussions/1871

Community sources are anecdotal. They are useful for product direction, not as
population-level evidence.

## Current GovFuzz Baseline

GovFuzz already has a differentiated base:

- Ada, C, and C++ source discovery and harness generation, with C/C++
  direct-call support for common byte-oriented API shapes.
- Partial-build recovery through generated Ada specs/bodies and C/C++ headers,
  typedefs, and stubs.
- Runtime virtualisation for missing environment dependencies.
- Fake CORBA and IDL-aware scaffolding for legacy Ada systems.
- Built-in fuzzing, C/C++ libFuzzer-style sanitizer harnesses, optional C/C++
  AFL++ mode, replay, minimization, reporting, SARIF/JUnit output, corpus
  import/export, CI command, differential replay, cmplog ingestion, and oracle
  metadata.

The strongest current discriminator is not "another fuzzer engine." It is the
ability to create a fuzz lab for code that does not build cleanly and does not
have its real runtime environment available.

## Ecosystem Pattern

Mature fuzzing stacks cluster around five capabilities:

1. Multiple engines and corpus exchange.
   OSS-Fuzz runs libFuzzer, AFL++, Honggfuzz, and Centipede. FuzzBench exists
   because engine performance is target-dependent and must be measured.

2. Comparison and dictionary guidance.
   AFL++ has CmpLog, LAF/CompCov, persistent mode, shared-memory testcase
   delivery, automatic dictionary extraction, custom mutators, and grammar
   mutators. These features exist because random byte mutation stalls on
   magic values, string compares, checksums, and structured formats.

3. Property and oracle ergonomics.
   FuzzTest moves C++ fuzzing toward property-based tests. Firefox's fuzzing
   docs emphasize defect oracles because crashes are only one failure class.

4. Introspection.
   Fuzz Introspector compares static reachability with dynamic coverage and
   reports blockers. OSS-Fuzz's FAQ explicitly recommends adding targets,
   better seeds, disabling crypto/CRC gates in fuzzing mode, or using Fuzz
   Introspector when coverage plateaus.

5. CI and triage.
   ClusterFuzzLite focuses on pull-request fuzzing, longer batch fuzzing,
   crash testcase download, and coverage reports. The developer pain is not
   only finding a crash; it is reproducing, deduplicating, interpreting, and
   deciding whether it matters.

## Recurring Pain Points

The same problems show up across papers, project issues, and forum threads:

- Harness creation and instrumentation are adoption blockers. Engineers have
  to pick entry points, make code build with instrumentation, write glue code,
  and reason about fuzzer-specific semantics.
- Builds and dependencies fail often. The human-side study calls out compiler,
  build-tool, external-dependency, corpus, and reproducibility issues as common
  developer challenges.
- Coverage plateaus are normal. Magic values, crypto, checksums, highly
  structured formats, and stateful protocols can stop byte mutation from
  reaching important code.
- Crashes are an incomplete oracle. Semantic, authorization, parsing,
  canonicalization, resource-leak, race, and business-logic bugs often need
  assertions, differential checks, or model-based properties.
- Persistent mode is fast but fragile. AFL++ guidance and user discussions
  show state leakage, threads, randomness, and incomplete reinitialization can
  waste most fuzzing effort.
- Reproduction and triage are not reliable enough. OSS-Fuzz issues show
  timeout confusion, non-reproducible AFL crashes, leak-detection surprises,
  and fuzz targets that time out during build checks.
- CI fuzzing needs budget allocation. Short PR fuzzing is useful, but deeper
  bugs need long-running jobs and a reusable corpus. Users need help deciding
  what to fuzz first after a code change.
- Tooling fragmentation matters. LibFuzzer has a low barrier to entry but is
  not where major new feature work is expected; AFL++ is powerful but has more
  setup friction; FuzzTest is active but C++-only and integration details still
  matter for CMake/OSS-Fuzz users.
- Evaluation claims are hard to trust. Fuzzing is stochastic and sensitive to
  environment, target, seeds, time budget, and instrumentation. GovFuzz needs
  internal benchmarking discipline before claiming superiority.

## Feature Opportunities

### P0: Differentiators To Build Next

1. Fuzz introspection for Ada and C/C++.

   Add `govfuzz introspect` and integrate it into `auto` reports. Inputs:
   discovered targets, static call graph, existing coverage/event traces,
   runtrace events, cmplog events, and build-recovery ledger. Outputs:
   uncovered high-risk functions, first red branch/callsite blockers, "add a
   target here" suggestions, missing seed/dictionary hints, and a per-target
   harness quality score.

   Why this matters: Fuzz Introspector is one of the clearest mature-platform
   gaps GovFuzz does not yet close, and Ada has no comparable open tooling.

2. Structure-aware input layer.

   Add schemas and mutators for binary records, TLV/protocol messages, line
   grammars, delimiter formats, Ada record/enumeration values, C structs, and
   C++ class/API domains. Generate dictionaries from enums, string literals,
   switch labels, comparison operands, IDL constants, and C/C++ macros. Add
   length/checksum repair hooks so inputs can pass common parser gates.

   Why this matters: AFL++ grammar mutators and CmpLog exist because raw byte
   mutation is not enough for structured formats. GovFuzz can make this
   automatic from Ada/C/C++ source models.

3. Oracle SDK v0.2 with executable oracles.

   The current oracle metadata should become runtime-checking capability. Start
   with:

   - Ada path traversal and unsafe file APIs.
   - C/C++ file path, environment, socket, format-string, integer-conversion,
     and allocator misuse hooks.
   - Differential output comparators for two harnesses.
   - Metamorphic checks such as parse/serialize/parse, normalize/idempotence,
     encode/decode, and optimized-vs-reference equivalence.
   - Contract/assertion promotion for Ada exceptions, SPARK-like pre/post
     expectations when visible, C assertions, and C++ invariants.

   Why this matters: "does not crash" misses many real bugs. Oracles are the
   path to security-relevant and correctness-relevant findings.

4. Reproducibility and flake control.

   Add deterministic replay bundles that capture argv, env, fake resources,
   sanitizer options, engine, seed, timeout, architecture, tool versions, and
   all prosthetics. Add a flake classifier that reruns findings, labels
   deterministic vs flaky, and quarantines unstable findings from CI failure
   unless policy opts in.

   Why this matters: Reproduction failures and unclear crash implications are
   among the most common adoption complaints.

5. CI budget optimizer.

   Extend `govfuzz ci` beyond "run auto." Use changed files, call graph
   impact, historical coverage, target risk score, prior findings, and corpus
   novelty to allocate a short PR budget. Always replay known regression corpus
   first, then fuzz impacted high-value targets, then spend spare time on
   coverage blockers.

   Why this matters: ClusterFuzzLite proves PR fuzzing is valuable, but GovFuzz
   can specialize it for partial Ada/C/C++ codebases and generated harnesses.

### P1: Parity And Power Features

6. Multi-engine backend parity.

   Provide first-class runner/export paths for built-in, libFuzzer, AFL++,
   Honggfuzz, and eventually Centipede/FuzzTest-style C++ entry points where
   licensing and toolchain availability permit. Preserve corpus interchange.
   Treat engines as comparable backends, not as the product identity.

7. Hybrid fuzzing bridge.

   Add optional SymCC/QSYM/KLEE-style or concolic assistance for hard
   comparisons, checksum gates, and path constraints. Keep it external-tools
   or research-lab because toolchain and license surfaces will vary.

8. Stateful/API sequence fuzzing.

   For Ada packages, infer package-state sequences from public subprograms,
   protected types, task entries, and reset candidates. For C++, infer
   constructor/method/destructor sequences. For C APIs, infer init/use/free
   sequences from naming and dataflow. Emit reset diagnostics when persistent
   mode would be unsafe.

9. Sanitizer and runtime-check matrix.

   C/C++: ASan, UBSan, MSan, TSan, LSan, fortify, integer, bounds, and
   allocator-specific checks where supported. Ada: runtime checks,
   Constraint_Error, Program_Error, Storage_Error, assertion/contract checks,
   tasking exceptions, and swallowed-exception breadcrumbs. Report which bug
   classes were not observable in a given run.

10. Local benchmark harness.

   Add a small FuzzBench-like local benchmark mode for GovFuzz changes:
   repeated trials, fixed budgets, seeds recorded, statistical summary, and
   target-specific result breakdown. This is needed before making performance
   claims about new mutators or schedulers.

### P2: Later Enhancements

11. LLM-assisted harness proposals with validation.

   Use LLM-generated harnesses only as candidates. Accept only if they compile,
   reach the target, improve coverage, and preserve deterministic replay.

12. Team triage dashboard.

   Layer on top of SARIF/JUnit/Markdown: owner routing, duplicate clustering,
   finding age, repro status, sanitizer class, oracle class, and "what changed"
   links.

13. Language expansion.

   Rust, Go, Java, and Python should wait until Ada and C/C++ have the
   introspection, structure-aware input, oracle, CI, and multi-engine story
   above.

## Ada-Specific Backlog

- Open legacy-code fuzz introspection: static reachability and dynamic coverage
  without GNATcoverage or Libadalang in the core.
- Contract and exception oracles: promote Ada assertions, preconditions,
  postconditions, `Constraint_Error`, `Program_Error`, `Storage_Error`, and
  swallowed exceptions into first-class findings.
- Package-state sequence harnesses: fuzz ordered calls, not only direct
  subprogram calls.
- Tasking/protected-object stress: deterministic scheduling envelopes where
  possible; deadlock and race-like symptom detection where practical.
- Generic package instantiation strategies for fuzzable formal types.
- Better support for C-through-Ada bindings, matching GNATfuzz's documented
  use case but without requiring GNATfuzz.
- Ravenscar/embedded profiles: semihosting, qemu-user/system replay envelopes,
  target memory limits, and no-filesystem/no-network assumptions.
- Fake CORBA oracles: servant method invariants, IDL enum/range validity,
  object reference misuse, Any/TypeCode edge cases, and request sequencing.

## C/C++-Specific Backlog

- Stronger build-system ingestion: `compile_commands.json`, CMake, Make,
  Meson, Autotools, and Bazel extraction where available.
- Stronger harness generation for C++ constructors, method sequences,
  overload disambiguation, templates, exceptions, RAII cleanup, and reset
  safety. Current C++ method support is limited to heuristic
  default-constructed receivers.
- Broader native engine support beyond the current C/C++ libFuzzer-style
  Makefile harnesses and AFL++ mode, including Honggfuzz and richer corpus
  exchange.
- Automatic dictionary generation from macros, enums, string literals,
  comparisons, parser keywords, and cmplog operands.
- Structure-aware C structs and C++ domain mutators.
- Sanitizer matrix management with explicit unsupported-class reporting.
- Differential ABI and compiler-flag fuzzing: same C/C++ API under two
  implementations, optimization levels, or compilers.
- Persistent-mode safety analysis: global state writes, thread use, randomness,
  files, sockets, and allocator state.

## Recommended Implementation Order

1. Build `govfuzz introspect` v0.1.
   It is the highest-leverage feature because it turns existing GovFuzz runs
   into actionable "what is missing" guidance and gives Ada users something
   the mainstream stack does not provide.

2. Implement executable Oracle SDK v0.2.
   Start with path traversal/file/network/env oracles and differential oracles.
   This directly addresses the "fuzzers only find crashes" complaint.

3. Add structure-aware inputs and checksum/length repair.
   This attacks coverage plateaus and improves both built-in and external
   engine performance.

4. Expand CI to budgeted, changed-code fuzzing.
   This turns GovFuzz from a lab tool into a daily development tool.

5. Add multi-engine parity after the above.
   External engines are valuable, but they should consume better harnesses,
   corpora, oracles, and introspection rather than define the product.

## Product Thesis

GovFuzz should not compete by being a faster clone of AFL++ or libFuzzer. It
should compete by fuzzing code those tools do not reach without expert setup:
partial Ada/C/C++ trees, missing runtime environments, legacy CORBA, generated
harnesses, build-recovered projects, stateful package APIs, and semantic
oracles. The technical discriminator is an Ada/C/C++ fuzz lab generator with
coverage-blocker introspection, structure-aware inputs, executable oracles, and
reproducible CI triage.
