<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing JavaScript / Node.js with govfuzz

govfuzz fuzzes JavaScript with **no harness to write** — point it at a Node source
tree and it discovers exported functions, generates the harness, and fuzzes them
coverage-guided with **real V8 block coverage**, on a warm Node process.

```sh
govfuzz auto path/to/js-src --languages javascript
```

## How it works

An **exported** function taking at least one argument is the fuzzable unit. govfuzz:

1. **Discovers** each exported function across both module systems — CommonJS
   (`module.exports = { parse }`, `exports.parse = …`, `module.exports = fn`) and
   ESM (`export function parse`, `export const parse = …`, `export default`) — plus
   the **public instance methods of exported classes** (`class Parser { parse(x) }`;
   the driver `new`s a no-argument-constructible class and calls the method). The
   first argument is inferred as a `Buffer` or UTF-8 `string` from its name
   (`buf`/`data`/`bytes` → Buffer; `str`/`text`/`source`/`html` → string).
2. **"Builds"** it with a `node -c` syntax check (interpreted — there is no native
   binary) and emits a launcher.
3. **Fuzzes** it on govfuzz's builtin fork-server engine driving **one warm Node
   process** over the framed protocol (amortizing interpreter + `require` startup).
   Per input the driver records **real V8 precise block coverage** via the inspector
   Profiler and folds it — keyed on `(script, block span, taken/not-taken)` — into
   govfuzz's cumulative `GOVFUZZ_COV_SHM` edge bitmap, so the engine gets genuine
   branch feedback, not black-box guessing.

### Oracle

An **uncaught exception** that is not input rejection is the finding signal (the
driver hard-halts with exit 86). The error is classified into a GF rule + CWE:

| Error | Rule | CWE |
|---|---|---|
| `RangeError: Maximum call stack size exceeded` | GF-207 | CWE-674 (uncontrolled recursion) |
| `RangeError: Invalid array/string length`, out-of-memory | GF-209 | CWE-789 (resource exhaustion) |
| `ReferenceError`, `AssertionError`, an explicit `throw`, any other `Error` | GF-210 | reachable crash |

Beyond uncaught exceptions, the driver runs a **taint-confirmed command-injection
detector** (the JS analog of govfuzz's native GF-431 oracle, and of Jazzer.js's
bug detectors): it hooks `child_process.exec`/`execSync` and reports **GF-431 /
CWE-78** when a shell-metacharacter-bearing substring of the fuzz input reaches the
command — i.e. the input controls shell *syntax*, not just data. The command is
**never executed** (a benign stub is returned), so the fuzzer can't run arbitrary
shell, and an input whose metacharacters never reach a command is not flagged.

`TypeError`, `SyntaxError`, `URIError`, and a validating `RangeError` are treated as
intended input rejection and swallowed. This mirrors the Python lane, which
suppresses the exact analogs (`TypeError`/`AttributeError`): in an untyped lane
govfuzz synthesizes only the *first* argument, so a `TypeError` ("Cannot read
properties of undefined", "x is not a function") is dominated by us calling a
function with a missing later argument or the wrong first shape — our fault, not a
target defect. A 30-project campaign confirmed every `TypeError` was such an
artifact, so suppressing the class is the key to a low false-positive rate. Real
memory-safety / injection classes are caught by the behavioral oracles, not this
exception policy.

## Where govfuzz stands vs the field

JavaScript has two notable fuzzers, both of which govfuzz's zero-harness,
auto-discovery model improves on:

- **[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js)** (Code
  Intelligence) — the strongest JS fuzzer. It instruments source with a Babel/hook
  plug-in and drives libFuzzer, but you write a `fuzz(data)` entry per target, wire
  it into a Jest/standalone runner, and manage the toolchain.
- **[jsfuzz](https://github.com/fuzzitdev/jsfuzz)** — Istanbul-coverage,
  coverage-guided, but likewise one hand-written `fuzz(buf)` function per target and
  now largely unmaintained.

On the static side, ESLint, SonarJS, and CodeQL flag candidate issues but don't
confirm them with real input. Jazzer.js additionally ships *bug detectors*
(command injection, path traversal, prototype pollution); govfuzz's JS driver
carries the first of these — a taint-confirmed **command-injection** detector (see
the oracle section) — in the same fuzz-confirming style as its native lanes.

| | Jazzer.js / jsfuzz | **govfuzz `auto --languages javascript`** |
|---|---|---|
| Fuzz entry to write | one per target | **none — auto-discovered** |
| Coverage | Babel/Istanbul instrumentation | **V8 precise block coverage (no source rewrite)** |
| Multi-target sweep | scripted by hand | **one command over the whole tree** |
| Warm process reuse | per-runner | **framed fork-server (one warm V8)** |
| Findings → CWE / SARIF / CSV | — | built-in |

govfuzz is the only tool that fuzzes JavaScript from source with **zero harness**,
using the V8 engine's own coverage (no Babel/Istanbul source transform) folded into
a shared edge map.

## Validation (campaign)

A 30-project campaign over the most-depended-on npm libraries — express, lodash,
axios, moment, validator.js, node-semver, marked, joi, qs, node-fetch, and more:

- **2,018 JS files scanned, 531 fuzzable functions discovered, 0 govfuzz panics** —
  discovery is robust across CommonJS and ESM, minified and hand-written code
  (validator.js alone → 111 targets, moment → 162). The first-argument name filter
  keeps internal array/options helpers (`multilineRegexp(parts)`) out of the fuzz
  set.
- **End-to-end** on a parser: real V8 branch coverage drove the engine to an
  uncontrolled-recursion crash (`RangeError: Maximum call stack size exceeded`,
  GF-207 / CWE-674) with the V8 stack, from **zero hand-written harness** — and with
  the `TypeError` suppression policy, **0 false positives** across the campaign's
  built-and-fuzzed validators.

## Requirements & licensing

- **Node.js** on the host — no npm packages are installed for the lane itself; the
  target is `require`d as-is. Absent `node`, the lane skips cleanly (the
  GNAT-less rule).
- The driver uses only Node built-ins (`inspector`, `fs`) — no third-party fuzzing
  dependency, nothing linked into govfuzz.

## Limits (honest)

- The fuzzable surface is the **first argument** (Buffer/string); a function whose
  behavior needs a second structured argument (an options object) is driven with
  the first arg only, so govfuzz feeds the primitive it can and relies on the
  rejection policy to suppress our-fault `TypeError`s.
- CommonJS/ESM modules that require a bundler/transpile step (TypeScript source,
  `import`-only ESM without a `.mjs`/`package.json type`) may not `require` as-is —
  point govfuzz at the built/published `lib/` in that case.
- One function is fuzzed at a time; the target's own `require`d dependencies load
  but coverage is scoped to the module under test.
