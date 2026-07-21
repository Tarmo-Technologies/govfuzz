<!-- SPDX-License-Identifier: Apache-2.0 -->
# The bugs your fuzzer can't see

### A white paper on vulnerability-class coverage — why a crash is only the beginning

---

## Executive summary

Every popular fuzzer — libFuzzer, AFL++, cargo-fuzz — decides it found a bug the
same way: the program **crashed**. That catches memory corruption and aborts, and
it is blind to the much larger world of vulnerabilities that do not crash: path
traversal, command injection, insecure temporary files, secret exposure, SSRF.
Those bugs execute cleanly, the fuzzer sees no signal, and it moves on.

**govfuzz sees them.** On top of the same coverage-guided engine it runs byte-origin
**taint** and a library of **behavioral oracles**, so it reports CWE-tagged
findings for the dangerous *behaviors* a program performs on attacker-controlled
input — not only the crashes. And because it auto-harnesses functions across a
tree instead of the one a human wrote a harness for, it fuzzes the whole
sixteen-language product surface. The behavioral oracles arm on native
C/C++/Ada/Rust/Go/COBOL/Fortran harnesses and the Python/Perl/Ruby/Lua/PHP
interpreters. Java, C#, and JavaScript/TypeScript retain their managed-runtime
coverage and crash/exception signals without this LD_PRELOAD oracle layer.

In a measured head-to-head on a library with one CWE per function, govfuzz found
**5 of 5** vulnerability classes where libFuzzer and AFL++ — handed a harness for
each exact function — found **2**. Across Rust and Java it found bugs in **3 of 3**
functions where the competitor's single harness found **1**. In Ada it found
both planted bugs; no other tool can fuzz Ada at all. Numbers and a reproducible
suite are in the companion [coverage comparison](vulnerability-coverage.md).

---

## A fuzzer is only as good as its oracle

A fuzzer has two halves. The **engine** drives execution into new code with
coverage feedback — and the engines are excellent and largely interchangeable.
The **oracle** decides whether an execution is a bug. This is where the popular
tools are thin: their oracle is a sanitizer crash or a process signal. So they
find:

- **CWE-787 / CWE-125** out-of-bounds write/read (AddressSanitizer)
- **CWE-617** reachable assertions / aborts
- a handful of other memory-safety classes

…and they are structurally blind to everything that is dangerous but does not
crash:

- **CWE-22 / CWE-73** an attacker-controlled path reaching `open()` — a traversal
- **CWE-78** input flowing into `system()` — command injection
- **CWE-377** a predictable temp file opened without `O_EXCL` — a symlink race
- **CWE-522** reading a secret from the environment on an input-driven path
- **CWE-134** a fuzz-controlled `printf` format string
- **CWE-918** input steering an outbound `connect()` — SSRF

These are not exotic. They are the daily bread of a security review. A crash-only
fuzzer runs every one of them, observes no crash, and reports nothing.

---

## What govfuzz adds

**Runtime taint.** govfuzz's `LD_PRELOAD` instrumentation records the byte origin
of the arguments a program passes to sensitive syscalls. When fuzz-input bytes
reach the path argument of `open()`, the format argument of `printf()`, or the
command of `system()`, it knows — and confirms it across executions to rule out
the program's own constants.

**Behavioral oracles.** A library of CWE-tagged oracles turns those runtime
events into findings: path-controlled open (`GF-405`/CWE-22), command injection
(`GF-304`/CWE-78), insecure temp file (`GF-417`/CWE-377), sensitive-environment
access (`GF-305`/CWE-522), format string (`GF-408`/CWE-134), SSRF
(`GF-303`/CWE-918), and more — each with a severity, a confidence, a sink
location, and the tainted byte range as evidence.

**Oracle-enabled lanes.** The `LD_PRELOAD` taint and behavioral oracles attach
to native C/C++/Ada/Rust/Go/COBOL/Fortran harnesses and interpose the
Python/Perl/Ruby/Lua/PHP interpreters. Java, C#, and JavaScript/TypeScript use
managed runtimes whose own startup activity would create false positives, so
the shim is deliberately off there; it is also off for cross-compiled or
emulated targets (qemu-user, wine). Those configurations still auto-harness and
fuzz with their managed-runtime coverage and crash/exception signals.

**Whole-tree harnessing.** A hand-written harness covers exactly one entry point.
govfuzz discovers and harnesses *every* fuzzable function, so a bug anywhere in
the library is reachable from one command, not one harness per function.

---

## The evidence

We planted one CWE per function and measured each tool. Competitors ran in their
best configuration; the behavioral sinks are safe (read-only `open`, `/tmp`
create, `getenv` — no command execution) so they run under every fuzzer. Full
method in the [comparison](vulnerability-coverage.md).

**Detection (C).** Handed a libFuzzer *and* an AFL++ harness for each exact
vulnerable function, the crash-only tools still found only the two crashing CWEs:

| | **govfuzz** | libFuzzer | AFL++ |
|---|:--:|:--:|:--:|
| CWE-121 out-of-bounds write | ✅ | ✅ | ✅ |
| CWE-617 reachable assertion | ✅ | ✅ | ✅ |
| **CWE-22** path traversal | ✅ | ❌ | ❌ |
| **CWE-377** insecure temp file | ✅ | ❌ | ❌ |
| **CWE-522** sensitive-env access | ✅ | ❌ | ❌ |
| **vulnerability classes found** | **5 / 5** | 2 / 5 | 2 / 5 |

**Coverage (Rust, Java).** One bug per function; the competitor's single harness
reaches one, govfuzz auto-harnesses all — with zero hand-written harness code:

| language | **govfuzz** (0 harnesses) | competitor (1 harness) |
|---|:--:|:--:|
| Rust vs cargo-fuzz | **3 / 3** | 1 / 3 |
| Java vs Jazzer | **3 / 3** | 1 / 3 |

**Ada.** govfuzz found both planted `CONSTRAINT_ERROR`s; no other fuzzer supports
Ada.

**Timing.** govfuzz writes the harness on the first run and reuses it on the
second. On these targets its build is fast enough that run 1 ≈ run 2 (1.16 s vs
1.12 s to the memory bug). On the shared memory bug libFuzzer's in-process engine
is quicker in raw wall-clock (0.69 s) — but it reaches that crash in a comparable
number of executions, and the **same** govfuzz run also reports three behavioral
CWEs libFuzzer finds in *no* amount of time. On a behavioral CWE, govfuzz wins the
clock by definition: it finds it in seconds; the crash-only fuzzer never does.

---

## Why it matters

The vulnerabilities that breach real systems are rarely just a heap overflow.
They are a traversal that reads `/etc/shadow`, an injection that runs a command,
a temp-file race that escalates privilege, a logged secret. A fuzzer whose only
oracle is "did it crash" cannot find these no matter how long it runs or how good
its mutator is. For legacy, defense, and mission-critical software — where the
bugs are old, the languages are mixed, and the stakes are high — that blind spot
is the difference between a clean report and a missed CVE.

govfuzz fuzzes the whole tree across sixteen current lanes and adds runtime
behavioral oracles on the twelve lanes named above. The measured suite on this
page predates the eight newer lanes; its detection counts are not claims about
those unmeasured languages.

---

*Reproduce every figure: `benchmarks/cwe/` in the govfuzz repository. clang/
libFuzzer 18, AFL++, cargo-fuzz 0.13 (Rust nightly), Jazzer, GNAT; 6 vCPU / 13 GB.*
