<!-- SPDX-License-Identifier: Apache-2.0 -->
# CWE-coverage benchmarks

Reproducible measurements behind `docs/site/vulnerability-coverage.md` and the
"Bugs Your Fuzzer Can't See" white paper. Every number there is produced by these
scripts; nothing is hand-edited.

## What is measured

A library per language with **one CWE per function** — a mix of crash-detectable
bugs and bugs that produce **no crash** — fuzzed by govfuzz vs the most popular
fuzzer for that language.

| script | comparison | what it shows |
|---|---|---|
| `run_c.sh` | govfuzz vs libFuzzer + AFL++ | **detection**: behavioral CWEs (path traversal / insecure-temp / sensitive-env) that crash-only fuzzers miss even with a per-function harness |
| `run_rust.sh` | govfuzz vs cargo-fuzz | **coverage**: bugs in 3 functions; one hand-written harness reaches 1, govfuzz auto-harnesses all 3 |
| `run_java.sh` | govfuzz vs Jazzer | **coverage**: same, for Java |
| `run_ada.sh` | govfuzz vs — | Ada: no other fuzzer exists |
| `run_timing.sh` | first run (cold) vs second run (warm) | harness-build amortization + the behavioral-CWE clock win |

## Fairness and honest notes

- Competitors run in their **best** config (AFL++ CMPLOG, libFuzzer
  value-profile) and are handed a harness for **each** vulnerable function in the
  C suite — so the C result is a pure *detection* comparison, not a coverage one.
- Each tool gets the same small seed corpus (`seeds_*/`) so coverage is measured
  without engine-to-engine gate-cracking variance; govfuzz also cracks the gates
  itself given more budget.
- Behavioral sinks are **safe**: read-only `open`, `/tmp` create, `getenv` — no
  command execution, file deletion, or network — so they run under every fuzzer.
- **TOCTOU (CWE-367) is intentionally not in the suite**: it needs the checked
  path to *exist*, which blind fuzzing rarely produces, so no fuzzer finds it
  reliably from random input.
- **Run the work dir OUTSIDE the scanned tree** (the runners do). A `--work-dir`
  *inside* the tree contaminates the per-target build with govfuzz's own
  generated harnesses; discovery now excludes a custom work-dir by path, and the
  Java build's tree-walk is a known follow-up.

## Reproduce

```sh
cargo build --workspace
BUDGET=12 bash benchmarks/cwe/run_c.sh
BUDGET=15 bash benchmarks/cwe/run_rust.sh
BUDGET=15 bash benchmarks/cwe/run_java.sh
BUDGET=15 bash benchmarks/cwe/run_ada.sh
bash benchmarks/cwe/run_timing.sh
```

Toolchains: clang/libFuzzer 18, AFL++, cargo-fuzz 0.13 (Rust nightly), Jazzer,
GNAT; 6 vCPU / 13 GB.
