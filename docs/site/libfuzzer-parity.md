<!-- SPDX-License-Identifier: Apache-2.0 -->

# libFuzzer feature parity (built-in engine)

GovFuzz's built-in engine is coverage-guided and runs offline with no libFuzzer
in-process runtime. C/C++ harnesses are compiled with the system clang's
sanitizer instrumentation (sancov for coverage, ASan for memory errors), but
GovFuzz supplies its own mutator and coverage feedback instead of libFuzzer's.
This page maps the familiar libFuzzer knobs to their GovFuzz equivalents so users
coming from `clang -fsanitize=fuzzer` know what to reach for.

## Flag mapping

| libFuzzer | GovFuzz | Notes |
|---|---|---|
| `-max_len=N` | `--max-len N` | Maximum generated input length. Default 4096. |
| `-len_control=N` | `--len-control N` | Adaptive length growth: the effective mutation length starts at 64 and doubles toward `--max-len` after `N` executions without a new corpus signature. `0` disables it. Default 100. |
| `-timeout=N` | `--timeout 10s` | Per-input timeout for C/C++ harnesses; the slow unit is killed and skipped. Distinct from `--time` (the whole-campaign budget). The Ada lane bounds runaway inputs via CPU rlimits. |
| `-rss_limit_mb=N` | `--rss-limit-mb N` | Per-input RSS ceiling. RSS is polled from `/proc/<pid>/statm`; a breach is reported as an `out-of-memory` finding. `0` (default) disables it. RSS polling is used instead of an `RLIMIT_AS` cap, which would break ASan's large virtual-address reservation. |
| `-print_final_stats=1` | `--print-final-stats` | End-of-run summary: executions, exec/s, new vs duplicate corpus signatures, findings, elapsed. |
| `-runs=N` | `--iterations N` | Execution cap (defaults to 256 with no `--time`). |
| `-max_total_time=N` | `--time 30s` (manual `fuzz`); `auto --per-target-time N` | Whole-campaign budget for a single manual `fuzz` run. Under `govfuzz auto`, `--per-target-time` (default 60s) is the per-target TOTAL fuzz wall, split evenly across the three passes (empty/rng/fuzz_driven) under one shared deadline — so the per-target wall ≈ this value, **not** × pass count. This is the per-target `-max_total_time` / AFL `-V` parity knob. |
| stop-on-first-crash | `auto --per-target-finding-count 1` | Stop a target the instant it produces N distinct crash signatures (checked mid-pass; remaining passes skipped), or when its `--per-target-time` is spent. `1` ≈ libFuzzer stop-on-first-crash; unset (default) collects every finding within the budget. |
| (whole-run wall cap) | `auto --campaign-time S` [+ `--min-target-time M`] | Outer wall-clock cap across ALL targets; with `--min-target-time` it instead splits the budget evenly across targets with a per-target floor. |
| `-jobs=N` / `-workers=N` / `-fork=N` | `--workers N\|auto` | Multicore campaign; per-input length/timeout/RSS limits are passed through to every worker. |
| `-dict=FILE` | auto dictionary + `--cmplog-log` | A dictionary is mined automatically (string/byte literals) and from recovered comparison operands. |
| `-use_value_profile=1` | cmplog / RedQueen (`--cmplog-log`) | See below. |
| `inline-8bit-counters` / AFL `COUNT` buckets | always on (C/C++ driver) | Edge hit counts are bucketed (`1, 2, 3, 4-7, 8-15, …`) so a deeper loop or recursion is new coverage, not just edge presence (#420). |
| laf-intel comparison split | `--comparison-progress` | Opt-in leading-byte-match gradient on multi-byte gates (#421). See below. |
| `-merge=1` | `govfuzz corpus merge` (content dedup) / `govfuzz corpus minimize --harness` (coverage-minimal) | `merge` deduplicates by content; `minimize` replays each input and keeps only those that add a new corpus signature. |
| `-minimize_crash=1` | `govfuzz minimize` | Shrink a crashing input by binary search while preserving the finding. |
| `-seed_inputs` / corpus dir | `--seed-input` / `--seed-file` | Seed corpus. |
| `-detect_leaks=1` | `--sanitizers lsan` | Part of the sanitizer matrix (asan/msan/ubsan/tsan/lsan). C/C++-native harnesses only; Ada/Rust/Java ignore the user-selected matrix and the build wires in their own instrumentation automatically. Cross-compiled/emulated targets run with no sanitizer instrumentation at all (ASan's shadow memory does not survive qemu-user/wine), so the matrix is ignored and the run uses builtin/event-log coverage only. |

## Coverage granularity

The C/C++ driver tracks three coverage channels, not just edge presence: edge
presence (`trace-pc-guard`), AFL-style logarithmic hit-count buckets (#420, the
equivalent of libFuzzer's `inline-8bit-counters`), and the opt-in laf-intel
comparison-progress gradient (#421, `--comparison-progress`). An input is
retained in the corpus if it advances **any** of the three.

The Ada lane is also coverage-guided: since #412 an instrumented Ada harness is
compiled with `-fsanitize-coverage=trace-pc` (GNAT/GCC rejects `trace-pc-guard`)
feeding the same edge bitmap and a bounded persisted corpus, and the source is
rewritten with breadcrumb probes at exception handlers and `raise` statements
that feed an exception-signature signal alongside edge presence. Ada coverage is
**presence-only** — the hit-count-bucket and comparison-progress channels are
C/C++-only.

## Rust and Java coverage

Rust and Java are also first-class fuzzing lanes that share the same built-in
engine and corpus machinery. Rust harnesses are built as `sancov`+ASan
staticlibs linked to the same C fork-server driver, so they get the same edge,
hit-count-bucket, and comparison-progress channels as C/C++. Java bytecode is
instrumented by GovFuzz's own ASM agent (not Jazzer), feeding edge coverage into
the same engine; the opt-in comparison-progress channel is not available in the
Java lane.

## Value profile vs. cmplog/RedQueen

libFuzzer's `-use_value_profile` turns each comparison into an approximate
coverage signal: an input that makes a comparison's operands *closer* is rewarded
even when it never satisfies the branch, which helps the mutator hill-climb past
multi-byte comparisons and checksums.

GovFuzz reaches the same goal through **cmplog/RedQueen** rather than a distance
coverage signal. Comparison operands are captured two ways and fed to the mutator:

- **String / buffer gates** (`memcmp`, `strcmp`, `strncmp`, …): the generated
  driver defines the ASan `__sanitizer_weak_hook_*` family, which ASan's
  interceptors call with both operands (no libFuzzer runtime required); the
  LD_PRELOAD runtrace shim records the same under `GOVFUZZ_CMPLOG=1`.
- **Scalar / character gates** (`*c == '{'`, integer `==`, `switch`): the driver
  is compiled with `-fsanitize-coverage=trace-cmp` and its `trace_cmp*` /
  `trace_switch` callbacks record the integer operand pairs.

Both feed a per-exec operand ring (`GOVFUZZ_CMP_SHM`). The engine arms capture for
the one corpus entry it is about to mutate, runs it once, and turns the operands
it observed into mutations two ways:

- a **dictionary insert** of each operand (position-independent), and
- an **offset-aware RedQueen splice** that replaces `operand_a` with `operand_b`
  at the exact offset `operand_a` appears **in that input** — input-to-state.

Capturing operands **per input** (against the entry being mutated, not a global
pre-mined pool) is what lets the splice find `operand_a` at the offset the parser
compared it, so one mutation passes one gate deterministically. Before capturing,
the entry is **colorized** — its coverage-irrelevant bytes are randomized to
near-unique values while preserving the edge footprint — so single-byte / short
operands splice at the right offset instead of every occurrence of a common byte.

This is primarily operand-level rather than gradient-level feedback: instead of
nudging an input toward a comparison value over many generations, GovFuzz injects
the observed value directly, which clears the dominant magic-byte / header /
keyword / checksum cases libFuzzer's value profile targets — often in a single
mutation. For the cases where a gradient still helps, the opt-in
`--comparison-progress` flag (#421) adds a laf-intel-style channel on the C/C++
driver: the driver records, per compare site, the longest leading-byte prefix an
input matched, and the engine rewards an input that matches one more byte of a
multi-byte gate — the distance-coverage signal noted below, partially shipped.

The remaining value-profile-only case is a **transformed** comparison — the magic
is a function of the input that never surfaces verbatim as an operand
(`crc32(buf) == K`, `a == (b ^ K)` where the compiler folds the operand into a
derived form, length/hash math). Neither input-to-state nor leading-byte
comparison-progress can synthesize those; a future enhancement is hybrid concolic
via optional symbolic-execution adapters (SymCC/KLEE, deferred post-1.0) on
branches that stay cold, fed back as seeds. A full per-site distance metric over arbitrary transforms would be a
further future addition, requiring comparison-distance instrumentation.
