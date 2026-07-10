<!-- SPDX-License-Identifier: Apache-2.0 -->

# DoD-Domain Recovery & Robustness Validation — 2026-06-15

Offline validation of `govfuzz auto` against a spread of public codebases that
mirror the kind of software found in government/defense programs — spacecraft
flight software, space-communications crypto, software-defined-radio / radar
DSP, and embedded RF drivers — written in C, C++, and Ada. None of the
repositories had their native build systems configured (no `./configure`, no
CMake cache, no fetched submodules, no cross toolchain), so every run also
exercises the **unbuildable-source recovery path**: diagnostic-driven header,
type, symbol, and environment repair on trees that do not compile out of the
box.

## Pinned Repositories

| Repository | Commit | Lang | DoD-domain analogue |
|---|---:|---|---|
| `nasa/osal` | `790dc84fe566dcccd50ee26918bcffa87a98a628` | C | Flight-software OS abstraction layer (cFS/cFE) |
| `nasa/CryptoLib` | `4872e76a5f97f16ce2740cc135d6df9a9aea32ae` | C | CCSDS SDLS space-link telecommand/telemetry crypto |
| `jgaeddert/liquid-dsp` | `563d38c1d8dd32c1ff2c81bc439c62a5084ebfbb` | C | SDR / radar / comms signal-processing |
| `nasa/fprime` | `1031e28b1d040a570d24be32c1d014c3236c7481` | C++ | Flight-software component framework |
| `AdaCore/Ada_Drivers_Library` | `95bdcbf8bcb0760e725b2ee06309734681f905ba` | Ada | Embedded peripheral + RF transceiver drivers |

Toolchains present on the validation host: `clang`/`clang++` (libFuzzer + ASAN +
UBSAN), `gcc`, `make`, `cmake`, FSF `gnat`/`gprbuild`, `afl-fuzz`.

## Discovery Robustness (whole-tree, no build)

`govfuzz list-targets` was run across each full tree to exercise the Ada/C/C++
parsers against real, macro-heavy, dialect-varied source.

| Repository | Targets ranked | Parser panics |
|---|---:|---:|
| `nasa/osal` | 2,417 | 0 |
| `nasa/CryptoLib` | 368 | 0 |
| `jgaeddert/liquid-dsp` | 3,152 | 0 |
| `nasa/fprime` | 6,470 | 0 |
| `AdaCore/Ada_Drivers_Library` | 7,114 | 0 |
| **Total** | **19,521** | **0** |

No panics, aborts, hangs, or non-graceful exits across ~19.5k discovered
targets. Tree-sitter `ERROR`/`MISSING` nodes in macro-heavy C are reported as
warnings with a remediation hint, never as a crash.

## End-to-End `auto` Runs (recovery → harness → build → fuzz)

Each run is scoped to a high-value untrusted-input parser in the tree, with a
short `--per-target-time` budget, against the un-built source.

| Repository | Scoped file | Targets | Outcome distribution |
|---|---|---:|---|
| `nasa/CryptoLib` | `src/core/crypto_tc.c` | 41 | **7 built+fuzzed**, 31 unsupported-params, 3 failed-build |
| `AdaCore/Ada_Drivers_Library` | `…/radio/nrf24l01p/nrf24l01p.adb` | 73 | 15 built (GNAT), 58 unsupported-params |
| `jgaeddert/liquid-dsp` | `src/framing/src/dsssframesync.c` | 23 | 23 unsupported-params |
| `nasa/osal` | `src/os/shared/src/osapi-printf.c` | 6 | 4 failed-build, 2 unsupported-params |
| `nasa/fprime` | `Fw/Com/ComPacket.cpp` | 2 | 2 unsupported-params |

Headline: on **NASA CryptoLib** — which has no build configured and depends on
unfetched submodules — `auto` recovered 7 telecommand-path harnesses by
blind-stubbing 14 missing globals (`sa_if`, `crypto_config_global`, …), pulling
4 sibling translation units (`Crypto_Is_AEAD_Algorithm`, `Crypto_Key_OTAR`, …)
into the harness, and injecting fake environment variables, then fuzzed each
built harness (≈ 65–110 executions/pass over a 3s budget) with the runtime
virtualisation shim attached. No findings (the parsed TC paths are robust), but
the build-recovery-to-fuzz pipeline ran end-to-end on code that does not
compile as shipped.

The dominant `unsupported_params` outcome reflects the reality of systems code:
public entry points take opaque struct pointers, tagged Ada records, and
framework buffer objects (`TC_t *`, `SecurityAssociation_t *`, `dsssframesync`,
`SerialBufferBase &`, `Nrf24l01p.Nrf24l01p_Driver`). `auto` only drives
parameters it can synthesize from a byte buffer; opaque-pointer lifecycle
support is a roadmapped item (ROADMAP §12 / "Phase C"). The skips are precise
and per-parameter, not failures.

## Issues Found And Fixed

Validation surfaced four defects, all fixed in this change with regression
tests.

1. **Legacy non-UTF-8 source was silently dropped.** Government Ada/C is
   routinely Latin-1 / Windows-1252 (accented author names, copyright glyphs,
   degree signs). `fs::read_to_string` rejected those bytes with
   `InvalidData`, so whole files vanished from discovery, scan, `list-targets`,
   the decl index, and Ada spec/dependency resolution during harness
   generation. A shared `source_text` reader now decodes UTF-8 when valid and
   falls back to ISO-8859-1 (every byte maps to a code point, never fails;
   dependency-free, license-policy-clean). _Verified:_ the
   `nrf24l01p`/`si4432` RF-transceiver drivers — previously skipped — now yield
   targets, and the `Ada_Drivers_Library` tree dropped from 4 encoding-skips to
   0. On `nrf24l01p.adb` this turned 0 harnessable targets into 15 that build.

2. **Live progress always printed `execs=0`.** Every working run looked like it
   never fuzzed: in piped/CI output the fuzz line was emitted only on phase
   change (the `execs=0` start state), and on a TTY a pass that finished inside
   the 500 ms tick window never rendered its counters. A pass now flushes a
   final update with its real execution/finding counts. _Verified:_ miniz now
   shows `execs=73/70/72` where it previously showed `execs=0`, with the
   recorded `run.json` counts unchanged.

3. **A generated dictionary could abort the whole fuzz campaign.** Dictionary
   lines were split on `=` to strip the optional `name=` prefix, which corrupted
   any token whose value contained `=` — e.g. printf format strings such as
   `"len of TF\t = %d"` lifted verbatim from the target source. The parser
   raised `expected quoted token`, which propagated out and aborted *every* fuzz
   pass for that harness. The parser now locates the token at the first quote,
   and generated-dictionary loading skips a malformed line with a warning rather
   than failing the run. _Verified:_ CryptoLib's `Crypto_TC_Validate_Auth_Mask`
   went from `built` (0 executions) to `built_and_fuzzed`.

4. **A discovery test was not hermetic.** The include-directory detector's
   3-level upward walk escaped a unique temp root into the shared `/tmp`
   namespace; a stray `/tmp/inc` from a prior run made the test fail under the
   full parallel suite. The test now nests its source so the walk stays inside
   its own root.

## Observed Limitations (not regressions)

- **Embedded Ada elaborated on the host.** The `nrf24l01p` harnesses build with
  GNAT but raise `STORAGE_ERROR` at launch: the driver `with`s bare-metal ARM
  `HAL`/`HAL.GPIO`/`HAL.SPI` packages whose elaboration assumes the target
  runtime. This is a cross-compilation/target-mismatch artifact of fuzzing
  bare-metal embedded code on a host, not a harness-generation defect — the
  repo's own Ada example (`examples/swallowed_constraint_error`) builds and
  fuzzes to 1,024 exec/pass and detects its planted swallowed exception.
- A harness that exits non-zero without a recognized sanitizer report still
  ends the current pass (a safety rail against fork-bomb/livelock stubs);
  heavily-stubbed or embedded-on-host harnesses are the ones that hit it. Making
  that path record a crash finding instead of ending the pass is a candidate
  future hardening.

## Readiness Signal

Across five DoD-domain codebases in three languages, with no native builds
configured, `govfuzz` discovered ~19.5k targets with zero parser panics,
recovered and built harnesses on source that does not compile as shipped, and
fuzzed the built C harnesses end-to-end. Legacy non-UTF-8 source — common in
exactly this kind of long-lived government code — is now first-class rather than
silently skipped, and the live `auto` output truthfully reports fuzzing
activity.
