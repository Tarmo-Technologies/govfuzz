<!-- SPDX-License-Identifier: Apache-2.0 -->
# 200-project multilingual harness-parity audit

This audit measures govfuzz auto-harnessing against independent expert drivers
across all sixteen supported languages. It is deliberately distinct from both
the 500-project estate sweep and the 30-project native line-coverage suite:

- the estate sweep asks whether any generated target builds and executes;
- the native suite deeply compares C/C++ implementation-line sets;
- this audit takes a balanced 200-project sample and records the strongest
  comparable evidence available for every lane.

The sample contains 12 projects from each language plus one extra project from
each of the eight core lanes, for exactly 200. Within every language it includes
up to four projects where the 2026-07-27 sweep did not reach a target; the
remainder previously fuzzed. PHP has only three such rows in the source result
set, so its twelfth slot remains in the reached stratum. Selection stays in
star-rank order within those two strata and prefers repositories below 50 MiB
so the audit can be repeated on one host. Every repository and revision is
pinned in `projects.tsv`.

Evidence is reported in three tiers and is never silently promoted:

1. discovery/build/target-entry for every project;
2. semantic parity against an independently reviewed expert driver;
3. source-line parity only when both harnesses expose compatible covered-line
   coordinates.

Generate the pinned manifest from the checked 500-project corpus:

```sh
python3 benchmarks/harness-parity-200/select.py
```

Run one project per language as a toolchain and runner pilot. The broad audit
uses the normal ten-candidate backfill policy; `--max-attempts 1` is available
as a separate target-ranking stress test and must not be conflated with general
auto-harnessability.

```sh
cargo build --release -p govfuzz
python3 benchmarks/harness-parity-200/run.py --limit-per-language 1 \
  --keep-sources --output /tmp/govfuzz-harness-parity-200-pilot
```

Run or resume the complete auto baseline:

```sh
python3 benchmarks/harness-parity-200/run.py --jobs 4
python3 benchmarks/harness-parity-200/run.py --jobs 4 --resume
```

After an implementation change that affects only selected lanes, rerun those
projects into the same output with `--include-existing`. Fresh rows replace the
old rows while the final report continues to cover the full audit:

```sh
python3 benchmarks/harness-parity-200/run.py --jobs 4 \
  --only-language rust --only-language java --include-existing
```

The auto runner writes one durable JSON row per project before removing its
temporary clone, so an interrupted audit resumes without redoing completed
projects. Every row records the exact GovFuzz version and SHA-256 of the binary;
the summary surfaces multiple hashes so a mixed incremental rerun cannot be
mistaken for a clean single-build result. Generate a deterministic residual-gap
matrix at any checkpoint with:

```sh
python3 benchmarks/harness-parity-200/analyze.py
```

Compare the durable broad rows to the independently designed all-language expert
set (one pinned real project and checked-in driver per lane):

```sh
python3 benchmarks/harness-parity-200/compare.py
```

The comparison fails closed if any supported lane or expert file is absent. It
separates dynamic target-entry/body proof from target-selection parity and lists
the state, resource, dependency, object, or ABI lever used by each expert driver.
The checked-in `expert/` directory contains one real driver for every supported
language; its files are hashed into `expert-harnesses.tsv` on every comparison.
The measured baseline, final focused controls, closed levers, and remaining
expert-parity paths are summarized in [`FINDINGS.md`](FINDINGS.md).
