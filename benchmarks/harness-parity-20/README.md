# Blind 30-project harness parity suite

This suite compares a govfuzz-generated harness with a small, reviewed expert
harness for the same API. Projects and revisions are pinned in `projects.tsv`.
The runner sets `GOVFUZZ_BLIND_EXPERT_HARNESSES=1`, so maintained fuzz
entrypoints are excluded from recipe mining, and sets `GOVFUZZ_EXPERT_HARNESS`
to the exact baseline file used by the coverage oracle.

Run a short reproducible sweep:

```sh
cargo build --release -p govfuzz
python3 benchmarks/harness-parity-20/run.py --seconds 15 --jobs 2
```

Clones, work directories, logs, raw JSON, `results.tsv`, and `summary.md` are
written below the selected `--output` directory (default:
`/tmp/govfuzz-harness-parity-20`). A project counts as measured only when both
harnesses build and the oracle reports comparable implementation files.

The directory name is retained for compatibility with the original 20-project
suite; `projects.tsv` and the checked 2026-08-14 results now contain 30 pinned
projects. The ten-project expansion adds libxml2, PCRE2, libwebp, Snappy,
msgpack-c, Lua, cmark, libucl, tomlc99, and libcsv. `ANALYSIS.md` records the
methodology, conclusions, and next gaps.
