<!-- SPDX-License-Identifier: Apache-2.0 -->
# govfuzz comparison benchmarks

Reproducible head-to-head measurements behind `docs/site/comparison.md` and the
white paper. Every number in those documents is produced by the scripts here on
the toolchains listed below — nothing is hand-edited.

## What is measured

For each language we compare **govfuzz** against the most widely used fuzzer for
that language, on a target with a planted, gate-guarded bug (the canonical
fuzzing benchmark shape — a bug reachable only past a magic/length/input-to-state
gate, so the engine's feedback actually matters).

| Language | govfuzz | Compared against |
|---|---|---|
| C / C++ | builtin engine + `--engine afl++` | AFL++ (cmplog), libFuzzer (value-profile) |
| Rust | builtin Rust lane | cargo-fuzz (libFuzzer) |
| Java | Jazzer engine (auto-harnessed) | Jazzer (hand-harnessed) |
| Ada | builtin engine | — (no off-the-shelf Ada fuzzer exists) |

Metrics, per (tool, target):

- **human-authored harness LOC** — lines of fuzz-harness code a person must write
  before fuzzing can start. govfuzz needs **zero**; the others need a harness per
  entry point.
- **crash found** within a fixed wall budget.
- **TTFC** — wall-clock time to first crash. For govfuzz this is *end-to-end*
  (raw source → discovery → build → crash); for the competitors it is fuzz-only,
  on a human-written, pre-built harness (their harness-authoring time is **not**
  counted against them).
- **executions** and **executions/sec** over the run (engine throughput).

## Fairness

Each competitor runs in its **best documented configuration**, not a hobbled one:
AFL++ with a CMPLOG (RedQueen) instrumented binary (`-c`), libFuzzer with
`-use_value_profile=1`. The seed is a benign 8-byte zero input that triggers none
of the gates (so no tool gets a free crash, and AFL++ does not abort on a
crashing seed). govfuzz is run with no flags beyond `--per-target-time`.

## Toolchains

clang/libFuzzer 18, AFL++ (afl-clang-fast/afl-fuzz), cargo-fuzz 0.13 on Rust
nightly, Jazzer (standalone) on JDK 17+, GNAT/gprbuild. 6 vCPU, 13 GB RAM.

## Reproduce

```sh
cargo build --workspace                 # builds govfuzz + the cc-intercept shim
BUDGET=15 bash benchmarks/run_c.sh      # C head-to-head -> results/c.tsv
bash benchmarks/run_rust.sh             # Rust  -> results/rust.tsv
bash benchmarks/run_java.sh             # Java  -> results/java.tsv
bash benchmarks/run_ada.sh              # Ada   -> results/ada.tsv
```

The planted-bug targets live under `targets/<lang>/` with a uniform entry point
`target_one_input(bytes)`; the competitor harnesses are under `harnesses/`.
