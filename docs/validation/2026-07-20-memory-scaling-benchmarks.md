# Memory-scaling benchmarks (2026-07-20)

This validation exercises the memory-safety changes against real repositories,
including a source tree well above the 10M-SLOC target. It measures both
whole-tree indexing/static analysis and repeated build/fuzz target turnover.

## Environment

- Linux host: 6 logical CPUs, 13 GiB RAM, 8 GiB swap
- Binary: optimized `cargo build --release -p govfuzz`
- Measurement: `/usr/bin/time -v`; peak values below are its maximum resident
  set size for the GovFuzz command
- Large-tree concurrency: `--jobs 1` for auto, `--jobs 2` for static analysis
- SARIF omitted from the constrained first pass, as recommended in the README

Pinned repositories:

| Repository | Revision | Recognized files | SLOC |
|---|---|---:|---:|
| cJSON | `fb16e5cf358798aabb049655975cde8427101056` | 124 | 18,740 |
| TinyXML2 | `8224e427b655b83dae5e2298f1e6919523a78737` | 70 | 7,552 |
| Linux | `adc218676eef25575469234709c2d87185ca223a` (v6.12 checkout) | 64,556 | 26,523,136 |
| Combined SLOC pass | all three above | 64,750 | 26,549,428 |

Linux contains a real 23,949,786-byte generated register-mask header. This was
useful for validating that the dynamic per-file allowance admits it when the
machine has room.

## Results

| Workload | Wall time | Peak RSS | Result |
|---|---:|---:|---|
| Combined SLOC | 3.67s | 90.6 MiB | 26,549,428 SLOC counted |
| cJSON static scan | 0.09s | 12.9 MiB | 40 findings, 6 unresolved-call gaps |
| TinyXML2 static scan | 0.67s | 13.4 MiB | 10 findings, no gaps |
| Linux static scan, dynamic defaults, 2 jobs | 2m13s | 301.4 MiB | 13,417 findings; all 64,556 files admitted; 550 unresolved-call gaps and no memory/file-size gap |
| Linux fresh auto discovery + rank | 22m42s | 558.1 MiB | 586,513 candidates; 585,911 after C/C++ filter; 158 MiB streamed cache |
| Linux cached discovery + `--dry-run --max-targets 5` | 4.95s | 424.2 MiB | Cache reused; five targets printed (730-byte stdout) |
| cJSON auto, 5 targets | 25.48s | 117.8 MiB | 5/5 built+fuzzed; 320 executions, 191 edges |
| cJSON auto, 50 targets | 3m46s | 122.6 MiB | 49 built+fuzzed, 1 skipped; 2,958 executions, 14 findings |
| TinyXML2 auto, 5 targets | 22.84s | 138.0 MiB | 5/5 built+fuzzed; 640 executions, 3 findings, 453 edges |

The 50-target cJSON run used only 4.8 MiB more peak RSS than the five-target run
despite processing ten times as many targets. That is the retention-oriented
check: target-local corpus, diagnostics, harness, and finding state did not grow
linearly across the sweep.

TinyXML2 produced more than 1,000 distinct sink observations in the earlier
fixed-cap experiment. With the final memory-derived sink budget, the same
five-target run completed with no retention warning and the same three emitted
defects, demonstrating that available memory is used to preserve evidence rather
than imposing a machine-independent cutoff.

## Deliberate low-memory fault injection

One additional Linux static scan explicitly passed `--max-memory-mb 128`. This
is **not** a default or recommended setting; it is a fault-injection test of the
graceful-degradation path.

| Wall time | Peak RSS | Result |
|---:|---:|---|
| 55.52s | 155.7 MiB | Valid partial report with 4,598 findings; 35,468 files recorded as skipped for memory pressure; interprocedural passes recorded explicit pressure gaps; exit 0; no swap |

The overshoot above 128 MiB reflects two already-active workers, allocator
overhead, and watchdog sampling. `--max-memory-mb` is an admission threshold,
not an OS-enforced hard quota; use a cgroup/container boundary when a strict hard
limit is required.

## Issues found by benchmarking

1. Standalone SLOC initially inherited a fixed 16 MiB static source cap and
   aborted on Linux's 23 MiB generated header. Static and SLOC file admission is
   now memory-derived and operator-overridable; the final full scan has no
   file-size gap.
2. `auto --dry-run --max-targets 5` initially printed all 585,911 filtered Linux
   candidates (about 16 million output tokens). Dry-run now honors the sweep cap,
   while the intentionally exhaustive `--list-targets` mode remains unchanged.
3. Fixed corpus and sink-evidence constants could unnecessarily discard useful
   state on larger hosts. Corpus, source, event, diagnostic, external-tool, and
   sink tracking budgets now scale from available host/cgroup memory and retain
   exact `GOVFUZZ_MAX_*` overrides.

## Verification

- `cargo test -p govfuzz --lib`: 1,233 passed
- `cargo test -p static_analysis --lib`: 317 passed
- Release build completed successfully
