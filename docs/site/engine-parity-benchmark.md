<!-- SPDX-License-Identifier: Apache-2.0 -->

# Engine parity benchmark (time-to-first-crash)

The parity benchmark measures how fast GovFuzz's **built-in** engine finds a
planted bug **cold** — with no trigger seed — on a corpus of gated-parser gap
classes, the metric that matters for [#376](https://github.com/Tarmo-Technologies/govfuzz/issues/376)
(libFuzzer parity).

## Fixtures

One tiny, self-contained C harness per gap class lives under
`tests/fixtures/engine_parity/`:

| Fixture | Gate | Crash |
|---|---|---|
| `magic_byte` | `buf[0]==0x55 && buf[1]==0x55` then a length byte in {0,1,2} | stack OOB write (PX4 st24-style) |
| `const_gate` | first 4 bytes == `0xDEADBEEF` | OOB write |
| `len_field` | a 1-byte length field > 8 | OOB read |
| `redqueen_int` | first 4 bytes == a per-input, length-derived `u32` magic — reachable only by capturing the compare operand via trace-cmp | stack OOB write |

### RedQueen discriminator (#400)

`redqueen_int` is gated by an **integer** comparison against a per-input,
length-derived magic, so its crash is reachable only by capturing the compare
operand via SanitizerCoverage trace-cmp and splicing it in at the offset it was
compared. The mem/str-only shim cmplog, the static dictionary, and blind or
structured mutation cannot reach it. Because it exercises a different path it has
its own gate test
([#400](https://github.com/Tarmo-Technologies/govfuzz/issues/400)):

```sh
cargo test -p govfuzz --test redqueen_cmplog -- --ignored --nocapture
```

It asserts the gate is solved cold with per-input capture **on** and **not** with
it disabled (`GOVFUZZ_DISABLE_REDQUEEN=1`, the dictionary-only path).

## Running it

```sh
cargo test -p govfuzz --test engine_parity -- --ignored --nocapture
```

It needs `clang` + `make`, runs each fixture cold, prints a time-to-first-crash
(TTFC) table (executions, findings, solved/unsolved), and **asserts each case is
solved cold** — the parity gate. The `GOVFUZZ_PARITY_SECS` env var sets the
per-target *total* fuzz budget (default 8s), split across the passes under one
shared deadline — directly comparable to a libFuzzer `-max_total_time=8`
campaign. The sweep is `#[ignore]`d so it runs on demand / nightly rather than
per-commit.

## Baseline (2026-06-21)

All three sweep gap classes are **solved cold** (no trigger seed):

| Case | Cold result (8s total) |
|---|---|
| `magic_byte` | solved — ~28k execs |
| `const_gate` | solved — ~626k execs (~78k execs/s) |
| `len_field` | solved — tens of execs |

This required two pieces working together. The feedback was already complete —
the generated `dictionary.txt` carries the magic bytes as raw values (e.g.
`"U"` = `0x55`, `"\x03"`) via the static comparison-operand dictionary
([#379](https://github.com/Tarmo-Technologies/govfuzz/issues/379)), with cmplog
([#378](https://github.com/Tarmo-Technologies/govfuzz/issues/378)), edge
coverage ([#381](https://github.com/Tarmo-Technologies/govfuzz/issues/381)),
and the entropic schedule
([#382](https://github.com/Tarmo-Technologies/govfuzz/issues/382)). The missing
piece was **throughput**: generated C direct harnesses used to run per-spawn
(~tens of execs/s). [#399](https://github.com/Tarmo-Technologies/govfuzz/issues/399)
gave them the persistent fork-server driver (now tens of thousands of execs/s),
which is what lets dictionary insertion land the gate cold. The
libFuzzer-reference side-by-side comparison remains a deferred follow-up.
