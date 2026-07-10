<!-- SPDX-License-Identifier: Apache-2.0 -->
# Engine-parity benchmark fixtures (#384)

Planted-bug C harnesses, one per gated-parser gap class, each crashing **only**
past its gate. They measure the built-in engine's time-to-first-crash (TTFC)
**cold** — no trigger seed — versus libFuzzer, per #376.

| Fixture | Gate | Crash |
|---|---|---|
| `magic_byte/` | `buf[0]==0x55 && buf[1]==0x55` then length byte in {0,1,2} | stack OOB write (st24-style) |
| `const_gate/` | first 4 bytes == `0xDEADBEEF` | OOB write |
| `len_field/` | 1-byte length field > 8 | OOB read |

Run the sweep with `cargo test -p govfuzz --test engine_parity -- --ignored --nocapture`
(needs clang+make). It prints a TTFC table and asserts each fixture is solved cold.

## RedQueen discriminator (#400)

`redqueen_int/` is a separate fixture for the input-to-state cmplog mutator. Its
crash is gated behind an **integer** comparison against a per-input, len-derived
magic — reachable only by capturing the comparison operand via trace-cmp and
splicing it in at the offset it was compared. The mem/str-only shim cmplog, the
static dictionary, and blind/structured mutation cannot reach it. The gate test
`redqueen_cmplog.rs` asserts it is solved cold with per-input capture **on** and
**not** with it disabled (`GOVFUZZ_DISABLE_REDQUEEN=1`, the dictionary-only path):

```
cargo test -p govfuzz --test redqueen_cmplog -- --ignored --nocapture
```

## Baseline (2026-06-21)
All gap classes are **solved cold**. The feedback was already complete (cmplog
#378, raw-byte dictionary #379 — the generated `dictionary.txt` carries the
magic bytes, edge coverage #381, entropic schedule #382); the missing piece was
throughput. #399 gave generated C direct harnesses a persistent fork-server
driver (per-spawn ~tens of execs/s -> tens of thousands), which lets dictionary
insertion land the gate cold. The libFuzzer-reference comparison is a deferred
follow-up.
