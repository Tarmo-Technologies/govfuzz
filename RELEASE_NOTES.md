<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz v0.2.20 release notes

Released 2026-07-24.

GovFuzz v0.2.20 is an audit-driven reliability release for offline legacy Ada,
C, and C++ fuzzing. A focused review of the discover → generate → build → fuzz
path found several defects that each *silently* stopped a class of real targets
from being fuzzed, and each is now fixed and covered by regressions and a
20-project real-code sweep.

## Highlights

- **Library-project Ada repos build.** The synthesized build project no longer
  extends a library project — GNAT rejects `extends "lib.gpr"` without
  `Library_Dir`, and a library project cannot carry the harness main. It now
  builds a standalone project over the instrumented source overlay, so an entire
  class of real Alire/GNAT library repositories (AdaYaml, Ada-Crypto-Library,
  ada-toml) that previously failed at project load now build, enter the target,
  and fuzz. Aggregate and abstract governing projects are handled the same way,
  and project selection prefers a concrete component over an aggregate umbrella.
- **GCC builds are coverage-guided, not blind.** A GCC-instrumented harness uses
  `-fsanitize-coverage=trace-pc`, which has no guard-init to open the
  coverage/cmplog shared-memory maps. The driver now opens them unconditionally
  in `main()` (idempotent, a no-op on the clang path), so a GCC build records
  edges and steers mutation instead of fuzzing blind.
- **UBSan-class bugs are caught by default.** The default harness is
  ASan+UBSan-built, but UBSan defaults to print-and-continue with a zero exit, so
  signed overflow, out-of-bounds indexing, shift errors, and null dereferences
  were reported to stderr and then missed. The builtin fuzz child now arms
  `UBSAN_OPTIONS`/`ASAN_OPTIONS` halt-on-error (respecting an explicit
  `--sanitizers`/`--env` value), matching the AFL path.
- **The framed fork-server stays aligned on large inputs.** An input larger than
  the harness's fixed 1 MiB buffer used to leave a tail in the pipe and desync
  the protocol — corrupting coverage or deadlocking the server until the run
  timeout. The engine now clamps each frame to the harness buffer.
- **Mixed K&R + ANSI C keeps its real targets.** A translation unit that mixes a
  few old-style K&R helpers with ANSI-prototyped parsers no longer drops the
  ANSI functions from discovery, and `list`/`scan` recover the correct K&R
  signatures instead of showing zero-parameter functions.
- **C++ rvalue-reference parameters build.** A `T&&` sink is moved into the call
  (`std::move`) instead of being passed as an uncompilable lvalue.
- **Response-file compile context is preserved.** `@flags.rsp` arguments in the
  compile database are expanded, keeping the `-I`/`-D` context they carried.

## Honest outcomes

- An `--engine afl++` run that executed zero inputs is recorded as built, not
  fuzzed.
- A native target that was entered and executed but produced zero coverage edges
  is flagged as having fuzzed blind (findings remain valid; absence of findings
  does not imply coverage-guided depth).
- A legacy C++ target whose older-dialect build ties the default's error count
  adopts the repairable older-dialect errors and converges instead of failing.

## Dependencies

- Upgraded the Tera template engine from 1.x to 2.x, with the corresponding
  harness-template test-syntax update, plus a refresh of the Cargo minor/patch
  dependency set and the pinned GitHub Actions.

## Validation

- 20-project offline real-code sweep across C, C++, and Ada: zero GovFuzz panics;
  18 of 19 cloned projects built, fuzzed, and entered targets (the one exception
  is a large Ada application that needs Alire dependencies unavailable offline
  and degraded gracefully to a categorized failed build); 17 findings surfaced.
- Workspace library tests pass — 1,322 GovFuzz CLI tests and 560
  harness-generator tests — alongside focused and end-to-end regressions for
  every fix above.
- Formatting, workspace compilation, `--locked` build, and the SPDX manifest
  check pass on the release tree.

See `CHANGELOG.md` for the cumulative project history.
