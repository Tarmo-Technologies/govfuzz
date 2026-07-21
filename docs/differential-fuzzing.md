<!-- SPDX-License-Identifier: Apache-2.0 -->

# Differential Fuzzing

GovFuzz ships a `govfuzz differential` subcommand: it replays each input
through two already-built harness executables (or one harness under a metamorphic
transform) and flags behavioural divergences. It is language-agnostic — the
executables can come from any of the sixteen current lanes as long as they obey
the normal one-input harness contract; the language is fixed by the target
source, not by this tool.

Automated comparison *across Ada compilers* — toolchain discovery and
multi-compiler matrix orchestration — remains a v1.1+ research boundary.
GovFuzz does not bundle compilers and does not depend on proprietary or
copyleft-linked compiler libraries in the strict-permissive core profile.

Run it over a directory of inputs:

```sh
# two compilers / two harness builds
govfuzz differential --harness-a ./harness_a --harness-b ./harness_b \
  --inputs ./corpus --out ./findings_differential

# one harness, metamorphic transform
govfuzz differential --harness ./harness --metamorphic-transform append-newline \
  --inputs ./corpus --out ./findings_differential
```

The CLI compares observable behaviour — stdout bytes and exit code/timeout —
and emits findings on divergence:

- `GF-301` (differential output divergence) when two harnesses disagree on the
  same input;
- `GF-307` (metamorphic relation violation) when one harness disagrees with
  itself across a metamorphic transform (currently `append-newline`).

Each divergence is written under `--out` as a JSON finding with stdout/exit-code
previews and oracle metadata (`--timeout-secs` bounds each side, default 5).

The internal `replay_min` library offers a narrower, signature-based path for
control-flow diagnostics:

- each side is tagged with a `CompilerIdentity`;
- `replay_min::run_differential_harnesses` executes the same input through both
  harness runners;
- event streams are reduced to GovFuzz exception signatures;
- differing signature sets produce a serializable `DifferentialMismatch` that
  carries both compiler identities and both signature lists.

The comparison itself is language- and compiler-agnostic; what limits *Ada
compiler* matrices specifically is which compilers users can install and
license:

| Pair | Boundary | Status |
| --- | --- | --- |
| FSF GNAT version A vs FSF GNAT version B | external user-installed subprocesses | Feasible for validation and nightly matrices. |
| FSF GNAT vs AdaCore GNAT Pro | user/customer environment only | Product can compare outputs, but cannot require or redistribute GNAT Pro. |
| FSF GNAT vs another open Ada frontend | external subprocesses | Deferred until another frontend can compile generated harnesses. |
| Compiler libraries or front-end APIs linked into GovFuzz | not allowed in core | Keep behind research-lab boundaries if ever explored. |

The subcommand intentionally starts from built harnesses. Toolchain discovery,
multi-compiler project synthesis, and automated matrix orchestration can layer on
top without changing the comparison contract.
