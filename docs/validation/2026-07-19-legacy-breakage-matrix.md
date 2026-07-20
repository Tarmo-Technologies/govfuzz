<!-- SPDX-License-Identifier: Apache-2.0 -->

# Legacy Dependency Breakage Matrix - 2026-07-19

GovFuzz passed 12 of 13 destructive legacy-project scenarios: **92.3%**
against a required **90%** gate.

This is a measured compatibility gate, not a claim that every possible damaged
source tree is recoverable. The matrix deliberately deletes a required source,
header, or Ada child-unit body from pinned real repositories and then requires
the surviving real target to build and execute under fuzzing.

## Reproduction

The pinned revisions, mutation proofs, target selections, and gate settings are
in `tests/fixtures/legacy_breakage_validation/manifest.toml`. With those
repositories already materialized by the offline legacy campaign, the final run
used:

```sh
cargo build --release -p govfuzz
python3 scripts/validation/legacy-breakage-matrix.py \
  --materialized-root /tmp/govfuzz-legacy-campaign-2026-07-19/repos \
  --offline \
  --workspace /tmp/govfuzz-legacy-breakage-final-2026-07-19 \
  --jobs 3 \
  --json-out /tmp/govfuzz-legacy-breakage-final-2026-07-19/summary.json \
  --markdown-out /tmp/govfuzz-legacy-breakage-final-2026-07-19/summary.md
```

For every scenario, the runner exports a clean pinned tree, verifies that the
removed artifact originally supplies a dependency used by the surviving target
closure, deletes it, and verifies its absence. A pass requires all of the
following:

- outcome `built_and_fuzzed` with at least one fuzz execution;
- at least one recorded build repair;
- no `fuzzed_stub_only` downgrade;
- the selected target itself was not stubbed.

Scenario timeouts kill the complete process session, including harness and
sanitizer descendants, so a timed-out run is recorded as a failure rather than
wedging the matrix.

## Results

| Scenario | Language | Deleted dependency class | Repairs | Executions | Edges | Result |
|---|---|---|---:|---:|---:|---|
| Ada Crypto | Ada | child-unit body | 2 | 8 | 137 | Pass |
| cJSON | C | dependency source | 24 | 8 | 44 | Pass |
| Expat | C | dependency source | 15 | 8 | 129 | Pass |
| GNATCOLL Core | Ada | child-unit body | 3 | 8 | 2,096 | Pass |
| jsoncpp | C++ | public header | 6 | 8 | 15 | Pass |
| LevelDB | C++ | private header | 2 | 8 | 24 | Pass |
| libarchive | C | dependency source | 29 | 8 | 27 | Pass |
| Loki | C++ | transitive header | 2 | 8 | 18 | Pass |
| Parse Args | Ada | child-unit body | 2 | 8 | 1,378 | Pass |
| TinyXML2 | C++ | dependency source | 0 | 0 | 0 | **Fail: failed build** |
| XMLAda | Ada | child-unit body | 3 | 8 | 1,932 | Pass |
| YAJL | C | dependency source | 17 | 8 | 35 | Pass |
| zlib | C | dependency source | 4 | 1 | 11 | Pass |

Totals for passing scenarios: 109 recorded repairs, 89 fuzz executions, and
5,846 coverage edges. Language rates were Ada 4/4, C 5/5, and C++ 3/4.

TinyXML2 remains an explicit unsupported recovery shape: deleting its only
implementation translation unit leaves the selected header-declared method
without enough surviving implementation structure for the current C++ repair
path. It is counted in the denominator and remains available as the next
regression target.
