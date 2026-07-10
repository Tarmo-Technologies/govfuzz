<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fuzzer Research And GovFuzz Dogfood - 2026-07-01

This memo records a July 2026 ecosystem review plus a broad GovFuzz dogfood
campaign. It complements the May 2026 landscape memo by validating current
GovFuzz behavior across fuzzing, SBOM/vulnerability matching, reporting, static
scan, and binary fuzzing.

Artifacts from this run are intentionally outside the repository:

- Broad campaign root: `/tmp/govfuzz-dogfood-2026-07-01`
- Extended soak root: `/tmp/govfuzz-dogfood-long-2026-07-01`

## Sources Reviewed

Primary tool/platform sources:

- AFL++ feature matrix and integrated feature list:
  https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/features.md
- LLVM libFuzzer manual:
  https://llvm.org/docs/LibFuzzer.html
- OSS-Fuzz overview:
  https://google.github.io/oss-fuzz/
- syzkaller project overview:
  https://github.com/google/syzkaller
- FuzzBench overview:
  https://google.github.io/fuzzbench/
- Jazzer project and practical-use notes:
  https://github.com/CodeIntelligenceTesting/jazzer and
  https://securitylab.servicenow.com/research/2024-10-28-jazzer-practical-tips/

Community and issue-tracker signals:

- Reddit discussion from a new user comparing libFuzzer, AFL++, and FuzzTest:
  https://www.reddit.com/r/fuzzing/comments/1b3kcf8/whats_the_difference_between_libfuzzerafl_and/
- Reddit discussion on approaching network protocol fuzzing:
  https://www.reddit.com/r/fuzzing/comments/1iqya3m/how_to_approach_network_protocol_fuzzing/
- Hacker News discussion on fuzzing ergonomics and running multiple fuzzers:
  https://news.ycombinator.com/item?id=26436520
- Hacker News discussion on structure-aware fuzzing:
  https://news.ycombinator.com/item?id=38916257
- AFL++ issue showing stall/progress confusion:
  https://github.com/AFLplusplus/AFLplusplus/issues/2127
- AFL++ discussion showing persistent-mode instability confusion:
  https://github.com/AFLplusplus/AFLplusplus/discussions/2082
- cargo-fuzz issue showing minimization/reproducer confusion:
  https://github.com/rust-fuzz/cargo-fuzz/issues/166
- Jazzer discussion on seed corpus importance and non-byte-array target docs:
  https://github.com/CodeIntelligenceTesting/jazzer/discussions/881

Community sources are anecdotal and should be treated as product-direction
signals, not population-level evidence. I did not use X/Twitter claims because
the available public results were not reliable enough to cite.

## Ecosystem Baseline

The best fuzzing systems cluster around these feature families:

| Area | Mature examples | GovFuzz implication |
|---|---|---|
| Multi-engine execution | OSS-Fuzz supports libFuzzer, AFL++, Honggfuzz, and Centipede. FuzzBench exists because fuzzer performance is target-dependent. | Keep engine adapters first-class and make comparison output easier to interpret. |
| Comparison guidance | AFL++ has CmpLog/RedQueen, LAF/CompCov, auto dictionaries, context/NGRAM coverage, persistent mode, shared-memory testcases, and custom/grammar mutators. libFuzzer has trace-cmp/value-profile/dictionaries/custom mutators. | Invest in automatic dictionary, typed-input, and comparison-blocker visibility. |
| Corpus lifecycle | Distributed fuzzing writeups emphasize saving corpora, merging findings back, and restoring the latest corpus in CI. | GovFuzz should make corpus persistence/merge/reuse explicit in `auto` and CI reports. |
| Structure-aware fuzzing | Community discussions repeatedly note that raw byte mutation stalls on JSON/protobuf-like and protocol inputs. | GovFuzz should grow schema/grammar/message-sequence lanes, especially for protocol and legacy record formats. |
| Triage/reproduction | Community issues show pain around minimization, non-reproducible findings, timeouts, and unclear progress/stalls. | Reporting is a GovFuzz strength, but progress health and replay bundle quality need continued work. |
| Language/runtime coverage | OSS-Fuzz covers C/C++, Rust, Go, Python, Java/JVM, JavaScript, Lua; syzkaller handles OS kernels; Jazzer covers JVM code and bug detectors. | GovFuzz's broad language discovery is useful, but non-C reporting and SBOM mapping need polish. |

## Local Campaigns

Toolchain inventory on the build VM included `clang`, `clang++`, `make`,
`gnat`, `gprbuild`, `javac`, `java`, `go`, `python3`, `perl`, `cargo`, `rustc`,
`afl-fuzz`, and `afl-clang-fast`.

The broad campaign ran 10 suites, all with exit status 0:

| Suite | Targets | Built/fuzzed | Skipped | Findings | Executions | Max edges |
|---|---:|---:|---:|---:|---:|---:|
| `ada-multidir` | 2 | 2 | 0 | 0 | 685,821 | 351 |
| `afl-c` | 3 | 3 | 0 | 3 | 1,228,920 | 22 |
| `benchmarks-all` | 6 | 6 | 0 | 5 | 485,725 | 431 |
| `cwe-mixed` | 11 | 11 | 0 | 9 | 544,352 | 30 |
| `go-lane` | 1 | 1 | 0 | 1 | 127,917 | 0 |
| `java-discovery` | 5 | 4 | 1 | 0 | 1,792,604 | 5 |
| `legacy-patterns` | 4 | 4 | 0 | 1 | 988,868 | 59 |
| `perl-lane` | 1 | 1 | 0 | 1 | 787 | 11 |
| `python-lane` | 1 | 1 | 0 | 1 | 273 | 13 |
| `rust-discovery` | 6 | 5 | 1 | 0 | 2,041,004 | 44 |

Broad campaign total: 40 discovered target instances, 21 findings, and
7,896,271 executions.

The extended soak reran the mixed benchmark/CWE suites and AFL++ C lane with
90-second per-target budgets:

| Suite | Targets | Built/fuzzed | Skipped | Findings | Executions | Max edges |
|---|---:|---:|---:|---:|---:|---:|
| `extended-benchmarks` | 6 | 6 | 0 | 6 | 2,001,252 | 431 |
| `extended-cwe` | 11 | 11 | 0 | 9 | 2,613,622 | 30 |
| `extended-afl-c` | 3 | 3 | 0 | 4 | 4,234,043 | 23 |

Extended campaign total: 20 discovered target instances, 19 findings, and
8,848,917 executions.

Combined total across broad plus extended campaigns: 60 discovered target
instances, 40 findings, and 16,745,188 executions.

## Additional Validation

Standalone reporting:

- `govfuzz report` over the CWE findings emitted Markdown, JSON, SARIF, JUnit,
  and CSV.
- SARIF contained 9 results: 2 critical, 4 high, and 3 medium.
- The Markdown report included issue tables, severity breakdowns, clusters,
  fix locations, suggested fixes, and replay commands.

Standalone SBOM/vulnerability matching:

- `govfuzz sbom tests/fixtures/rust_discovery` emitted GovFuzz SBOM JSON,
  CycloneDX JSON, vulnerability JSON/CSV, OpenVEX, and CSV SBOM output.
- A local test advisory for `pkg:cargo/rust_discovery_fixture@0.1.0` matched
  with high confidence.
- `--fail-on high` exited 1 after writing artifacts, as expected.

Standalone static scan:

- `govfuzz static-scan benchmarks/cwe/targets --sarif` emitted JSON, Markdown,
  and SARIF.
- It found one medium-confidence `GF-406` environment-dependent configuration
  issue at `c/libcwe.c:52`.
- `--fail-on medium` exited 1 after writing artifacts, as expected.

Binary surface:

- `govfuzz binary scan target/release/govfuzz` emitted a binary inventory for
  the GovFuzz ELF.
- A tiny compiled crashing fixture passed to `govfuzz binary fuzz` produced
  `BF-0001` with rule `GF-501`, severity high, and a testcase artifact.

## What Worked

- The `auto` pipeline handled C, C++, Ada, Rust, Java, Go, Python, Perl, and
  legacy/IDL/CORBA-pattern fixtures in one validation pass.
- External AFL++ execution worked and reached much higher throughput than the
  built-in engine on the C benchmark lane.
- Ada multi-directory/GPR workflows built and fuzzed successfully.
- Java and Rust unsupported-target skips were understandable:
  an unsafe Rust function requiring caller-upheld safety, and a Java instance
  method without a no-arg constructor.
- The reporting surface is useful. Generated Markdown, SARIF, JUnit, CSV, and
  replay commands were enough to triage the seeded CWE findings.
- Static scan, SBOM gating, and binary fuzzing all produced actionable artifacts
  and correct nonzero gate behavior.

## Gaps Found

### P1: Dependency Reporting Must Filter Fuzz-Generated Runtime Paths

The CWE file-open target produced thousands of fuzz-controlled path names.
GovFuzz reported these as external dependencies:

- Broad CWE: `28,444 external dependencies needed`, with `28,443 still
  blocking`.
- Extended CWE: `83,956 external dependencies needed`, with `83,955 still
  blocking`.
- The generated `missing-deps.txt` files contained control characters and
  newline-bearing fuzz inputs; `wc -l` saw 132,202 and 404,057 physical lines.

This makes the "bring missing dependencies" workflow unusable for fuzzed file
paths. Runtime fuzz-controlled paths should be separated from build/runtime
environment dependencies, escaped safely, capped, and summarized once per target.

### P1: Non-C Language Rollups Are Incomplete

Mixed runs built and fuzzed Rust and Java targets, but the console summary only
listed Ada/C or C:

- `benchmarks-all` and `extended-benchmarks` fuzzed Java and Rust but reported
  `Languages: Ada 1 (1 built), C 3 (3 built)`.
- `cwe-mixed` and `extended-cwe` fuzzed C, Rust, and Java but reported only
  `Languages: C 5 (5 built)`.
- Rust-only and Java-only discovery runs did not print a language rollup line.

The per-target rows are correct; the aggregate summary is not.

### P1: Multi-Engine Summaries Need Engine Labels

The AFL++ comparison lane prints duplicate pass names:

```text
fuzz_driven=995ex/1f fuzz_driven=4231257ex/0f
```

The underlying JSON has engine labels. Console and Markdown summaries should
print labels such as `builtin:fuzz_driven` and `afl++:fuzz_driven`.

### P1: Python/Perl Fuzz-Driven Passes Report Zero Executions

The Python and Perl lanes built, ran empty/rng passes, and found seeded issues,
but `fuzz_driven` reported 0 executions:

- Python: empty 156, rng 117, fuzz_driven 0.
- Perl: empty 483, rng 304, fuzz_driven 0.

This may be a pass-selection issue or an accounting issue. Either way, `auto`
should warn when a selected pass consumes budget but records zero executions.

### P1: SBOM Reachability Can Be Misleading For Source Packages

The Rust fixture SBOM matched a local advisory for
`pkg:cargo/rust_discovery_fixture@0.1.0`, but the vulnerability report marked
reachability `not_observed` and OpenVEX `not_affected/code_not_reachable`, even
when supplied the `auto/run.json` from fuzzing that source package.

For source packages under test, GovFuzz should map fuzzed harness/source paths
back to SBOM components before issuing "not reachable" VEX statements.

### P2: `govfuzz --version` Is Missing

`target/release/govfuzz --version` exits with an unexpected-argument error.
The CLI should expose `-V/--version` for installer validation, release
diagnostics, and support tickets.

### P2: Java Instance-Method Construction Is A Coverage Opportunity

Java discovery skipped an instance method because no no-arg constructor was
found. GovFuzz can improve Java depth by synthesizing object construction from
simple constructors, factory methods, or fixture hints.

### P2: Corpus Lifecycle UX Should Be More Explicit

The ecosystem strongly values persistent corpora, distributed corpus merge, and
reuse across CI. GovFuzz has corpus artifacts, but `auto` reports should make
the lifecycle obvious: where the corpus lives, what was imported, what changed,
how to merge it, and the exact command to reuse it.

### P2: Add Protocol/Stateful And Structure-Aware Lanes

Community pain around network protocols and structured formats maps directly to
GovFuzz opportunities:

- protocol/message-sequence harness generation;
- dictionaries from string literals, enums, constants, and comparisons;
- schema/grammar input layers for JSON, binary records, TLV, and delimiter
  formats;
- checksum/length repair hooks.

### P2: Add Health/Stall Diagnostics

Community issues show users struggle with stalled campaigns, persistent-mode
instability, and confusing minimization/replay behavior. GovFuzz should surface
per-target health warnings for zero-exec passes, no-new-coverage windows,
engine stalls, flaky findings, and timeout-heavy targets.

## Commands Used

Broad campaign examples:

```sh
target/release/govfuzz auto benchmarks/targets \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-2026-07-01/work/benchmarks-all \
  --per-target-time 20 \
  --max-repair-rounds 6 \
  --jobs 2 \
  --no-discovery-cache \
  --include-dir benchmarks \
  --languages c,ada,rust,java \
  --sbom \
  --verbose

target/release/govfuzz auto benchmarks/cwe/targets \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-2026-07-01/work/cwe-mixed \
  --per-target-time 20 \
  --max-repair-rounds 6 \
  --jobs 2 \
  --no-discovery-cache \
  --include-dir benchmarks \
  --languages c,rust,java \
  --sbom \
  --verbose \
  --comparison-progress

target/release/govfuzz auto benchmarks/targets/c \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-2026-07-01/work/afl-c \
  --per-target-time 24 \
  --max-targets 3 \
  --single-pass \
  --engine builtin,afl++ \
  --comparison-progress
```

Extended soak examples:

```sh
target/release/govfuzz auto benchmarks/targets \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-long-2026-07-01/work/extended-benchmarks \
  --per-target-time 90 \
  --max-repair-rounds 6 \
  --jobs 3 \
  --no-discovery-cache \
  --include-dir benchmarks \
  --languages c,ada,rust,java \
  --sbom \
  --verbose

target/release/govfuzz auto benchmarks/cwe/targets \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-long-2026-07-01/work/extended-cwe \
  --per-target-time 90 \
  --max-repair-rounds 6 \
  --jobs 3 \
  --no-discovery-cache \
  --include-dir benchmarks \
  --languages c,rust,java \
  --sbom \
  --verbose \
  --comparison-progress

target/release/govfuzz auto benchmarks/targets/c \
  --profile external-tools \
  --work-dir /tmp/govfuzz-dogfood-long-2026-07-01/work/extended-afl-c \
  --per-target-time 90 \
  --max-targets 3 \
  --jobs 2 \
  --single-pass \
  --engine builtin,afl++ \
  --no-discovery-cache \
  --include-dir benchmarks \
  --languages c \
  --verbose \
  --comparison-progress
```

Reporting, SBOM, static, and binary checks:

```sh
target/release/govfuzz report \
  --findings /tmp/govfuzz-dogfood-2026-07-01/work/cwe-mixed/findings \
  --out /tmp/govfuzz-dogfood-2026-07-01/reports/cwe \
  --run cwe-mixed \
  --sarif \
  --junit \
  --csv

target/release/govfuzz sbom tests/fixtures/rust_discovery \
  --out /tmp/govfuzz-dogfood-2026-07-01/sbom/rust-vuln \
  --run-json /tmp/govfuzz-dogfood-2026-07-01/work/rust-discovery/auto/run.json \
  --vuln-db /tmp/govfuzz-dogfood-2026-07-01/vulns-rust.json

target/release/govfuzz sbom tests/fixtures/rust_discovery \
  --out /tmp/govfuzz-dogfood-2026-07-01/sbom/rust-vuln-fail \
  --run-json /tmp/govfuzz-dogfood-2026-07-01/work/rust-discovery/auto/run.json \
  --vuln-db /tmp/govfuzz-dogfood-2026-07-01/vulns-rust.json \
  --fail-on high

target/release/govfuzz static-scan benchmarks/cwe/targets \
  --out /tmp/govfuzz-dogfood-2026-07-01/static/cwe \
  --sarif

target/release/govfuzz static-scan benchmarks/cwe/targets \
  --out /tmp/govfuzz-dogfood-2026-07-01/static/cwe-fail \
  --sarif \
  --fail-on medium

target/release/govfuzz binary scan target/release/govfuzz \
  --out /tmp/govfuzz-dogfood-2026-07-01/binary/scan-govfuzz

target/release/govfuzz binary fuzz /tmp/govfuzz-dogfood-2026-07-01/binary/crasher \
  --work-dir /tmp/govfuzz-dogfood-2026-07-01/binary/fuzz-crasher \
  --engine builtin \
  --iterations 3 \
  --seed-input ok \
  --seed-input 'GFZ!' \
  --timeout-ms 1000
```
