<!-- SPDX-License-Identifier: Apache-2.0 -->
# Open defects: `--force` reach, and the targets govfuzz still cannot fuzz

Handoff document. Everything here was found by measuring `--force` over 126 real
projects and then reading the residual blockers. Each item states the symptom,
the root cause, the exact place to change, how to verify, and — where it
matters — what has already been **ruled out**, so nobody re-derives it.

Read "Context" first: three fixes landed recently and an item below can look
wrong if you do not know what changed.

---

## Context: what `--force` is now

`--force` used to apply to the whole sweep. Measured over the 126 corpus
projects that had at least one undrivable target, that **cost 13 fuzzed targets**
(214 → 201) and bought one extra fuzz finding: a forced attempt costs ~36% more
(7.8s → 10.6s per attempt), so inside a fixed `--campaign-time` fewer candidates
were attempted at all. `git/git` went from 10 attempted / 5 fuzzed to **1
attempted / 0 fuzzed**.

It is now **two phases**:

1. Phase 1 is always unforced — bit-for-bit the run you would get without the
   flag. No target that would have fuzzed can be starved by work spent forcing
   another one.
2. Phase 2 retries **only** the targets phase 1 could not fuzz, forced.
3. The forced outcome wins for every retried target. That is safe precisely
   because phase 1's fuzzed targets are never retried, so `--force` cannot lower
   the fuzzed count.

Same corpus, after: **211 → 221 (+10)**. Per lane C +7, Go +3, Rust +1, C# 0,
C++ −1. **The noise floor is ±3** (re-running the unforced arm alone gave
214 → 211), so only C and Go are signal.

`--resume --force` over a finished campaign keeps every target that already
fuzzed and sends only the rest to phase 2 — skipping phase 1 for them, since
their unforced answer is already on disk.

Relevant commits: `6667f72` (two phases + resume), `f295d8c` (header gate honours
force; phase 2 prints its own blocker histogram), `b36be2d` (forced outcome wins
for retried targets), `9e70582` + `d9c180d` (C dialect ladder), `6c32307`
(per-finding stub accounting).

**Do not "simplify" phase 1 back into a single forced pass.** That is the
regression the +10 measures against.

---

## 1. `--force` cannot stub a function that returns a struct by value

**Contained change. Start here.**

### Symptom

A link error survives `--force`, which is supposed to stub whatever the compiler
reports undefined. On `nicbarker/clay`:

```
Clay_Raylib_Initialize -> failed_build
  {"kind": "undefined_symbol", "name": "LoadShaderFromMemory"}
```

### Root cause

Twenty other raylib symbols in the same harness **were** blind-stubbed into
`repairs/auto_stubs.c` (all `weak`). Exactly one stayed undefined, and the
discriminator is its return type:

```c
/* clay/renderers/raylib/raylib.h:1052 */
RLAPI Shader LoadShaderFromMemory(const char *vsCode, const char *fsCode);
```

The others return `void` or scalars. A stub for an aggregate-by-value return has
to construct a return value, and the generator declines to — it emits no repair
at all, so the link stays broken.

`crates/c_stub_gen/src/lib.rs:8`, `stub_body_for_return_type()`, says so itself:

> Returns `None` for struct/union by value — the caller marks the containing
> target `failed_build` because we have no safe default.

### Ruled out

- **Not a repair budget problem.** `--max-repair-rounds 30` behaves identically
  to `4` and prints no "repair cap reached". The planner returns no repair; it
  does not run out of rounds.
- **Not the `main`/libc refusal guards** earlier in the `UndefinedSymbol` arm of
  `plan_repair_forced_with_source_policy` (`crates/cli/src/auto/repair.rs`
  ~2862) — the symbol is neither.
- The final `else` of that arm **does** return `Repair::StubBlind`, so the
  refusal is downstream, in body synthesis.

### Fix

`stub_body_for_return_type` returns `Option<&'static str>`, so an aggregate case
cannot live there — it needs the type name. Put it in the `String`-returning
path, `stub_body_for_declaration` (same file, ~line 25; it already does
`stub_body_for_return_type(rt).map(str::to_owned)` at ~line 130).

Emit:

```c
<Type> gf_stub_ret = {0}; return gf_stub_ret;
```

`{0}` zero-initializes any **complete** aggregate in both C and C++ and needs no
`<string.h>`. Run the spelling through `unwrap_export_macro()` (same file, ~line
249) first, or `RLAPI Shader` will be used as a type name.

If the type is incomplete the stub will not compile — that is no worse than
today's outright refusal, and it surfaces as a real build error rather than
silence. Consider gating on force only if it proves noisy unforced.

### Verify

```
git clone --depth 1 https://github.com/nicbarker/clay
govfuzz auto clay --work-dir wk --per-target-time 1 --single-pass --jobs 1 \
  --max-attempts 6 --max-repair-rounds 6 --force
```

`Clay_Raylib_Initialize` must stop reporting
`{"kind":"undefined_symbol","name":"LoadShaderFromMemory"}`. Today that tree
reaches 3 built+fuzzed of 6 attempted; this should make it 4.

---

## 2. 297 targets end `unbuildable after N repair rounds`

### Symptom

Across the 126-project forced arm, 297 targets end with a `report_only` blocker
reading `forced: unbuildable after N repair round(s) (N residual build error(s)
the diagnostic-driven stubbing could not resolve)`. By lane: **c 125, cpp 76,
go 47, csharp 25, rust 24**.

These are the targets `--force` is supposed to convert into fuzzing and instead
converts into static analysis. That is the headline complaint about the flag and
it is not yet answered.

### What is known

This is a **class, not a defect** — it is whatever the repair loop could not fix.
Two members have been identified and one is fixed:

- **Fixed (`9e70582`)**: the C dialect ladder adopted the rung with the fewest
  *errors* without checking whether that rung **manufactured** an error the
  baseline never had. On clay it settled on a pre-C11 rung where `U'▀'` (a C11
  UTF-32 literal) tokenizes as the identifier `U`, giving `use of undeclared
  identifier 'U'` — unfixable by repair, because nothing is missing.
  `output_requires_newer_c_standard` now rejects such a rung.
- **Open**: item 1 above (struct-by-value return).

The rest are **unenumerated**. Nobody has read them.

### Suggested approach

Do not guess. Enumerate first — the same loop that produced every other fix in
this campaign:

1. Re-run the forced arm (see "Re-measuring" below).
2. Phase 2 now prints its own blocker histogram — the forced reasons, not the
   unforced ones. That output is the worklist.
3. For each residual class, open one exemplar's
   `<work>/harnesses/<id>/repairs/c_build_output.log` and read the actual
   compiler errors. The normalized histogram text is for grouping, not
   diagnosis.
4. Fix the largest class, re-measure, repeat.

The histogram exists because doing this by hand is what produced every lever
that ever moved the built count; the ones adopted because they seemed obviously
right, without measuring, are the ones that turned out wrong.

---

## 3. `--force` has no path outside C/C++/Ada (~211 targets)

### Symptom

`unsupported_params` **survives** forcing on four lanes. From the forced arm's
residual blockers:

| Lane | Targets | Shape |
|---|---:|---|
| Go | 116 | 58 undrivable param types, 23 methods, plus go-version / no-`go.mod` |
| Rust | 64 | 37 no byte decoder, 16 target-kind, 11 private-module trait-impl |
| C# | 31 | unconstructible receivers (instance method, no usable constructor) |

Go's undrivable count is **unchanged** at 219 between arms, which is the tell:
nothing even attempted it. `--force` is documented as C/C++/Ada only.

Note the Go +3 in the measured result is **not** a Go force path — it is C/C++
files inside Go repositories.

### Fix direction

`crates/harness_gen/src/c_decoders.rs` ~2530, `best_effort_param_emission()`, is
the working C-family analogue to copy. Its contract is the right one and the
doc comment states it plainly: the goal is a driver that **compiles**, value
correctness is explicitly not a goal, force mode accepts false positives. It
handles function pointers (NULL of the exact type), any pointer (input-filled
heap buffer cast to the parameter type), and non-pointer aggregates (zeroed
stack object).

Each lane needs its own equivalent, and they are not equally tractable:

- **C#** is probably the most tractable: an unconstructible receiver could be
  obtained via `FormatterServices.GetUninitializedObject` / `RuntimeHelpers`
  rather than a constructor, which is a bounded change.
- **Rust** is the hardest — no byte decoder for a type is a type-system fact,
  and private-module trait-impl resolution is a known separate gap.
- **Go**'s `no go.mod` and "requires go >= X" entries are **not** parameter
  problems and will not yield to a force path at all; they need a toolchain or a
  synthesized module. Count them separately before claiming a target number.

### Honest scoping

This is three lane-sized projects, not one fix. Do not start it as "add force to
the remaining lanes" — pick one lane, measure its residual blockers first, and
check how many of its targets are actually undrivable-parameter problems versus
environment problems that forcing cannot touch.

---

## Re-measuring

Harness lives in `benchmarks/campaign-2026-07-25/`.

```
# The forced arm, restricted to the projects a force flag can move.
sh launch_force_ab3.sh                       # writes results-force3/
python3 force_delta.py --baseline results-plain2 --forced results-force3
```

`force_delta.py` splits **real fuzz reach from stub-only** and **fuzz findings
from static findings**. That split is load-bearing: `summary.findings` counts
report-only static findings alongside runtime crashes, and reading the total
made the global-force arm look like "+376 findings" when its fuzz findings were
unchanged. Do not report a findings delta that has not been split.

### Rules that cost time when broken

- **Both A/B arms must run the same binary.** Otherwise the delta folds in
  unrelated changes. Pinned copies live in `/home/ubuntu/govfuzz-sweep-bin/`.
- **`govfuzz --version` is identical across rebuilds** (`v0.2.20-18-g893b68c-dirty`).
  Distinguish binaries by `md5sum`, never by version string.
- **`--repos <file>`** restricts a wave to the projects a flag can move (126 of
  226 here). Do **not** combine it with `--corpus-only` — that drops pool
  replacements and silently shrinks the set to 124.
- **`--results-dir`** keeps an A/B from overwriting the baseline it is compared
  against.
- **Never edit source while `cargo test --workspace` is running.** The suite
  reports a fake failure from the transient compile error.
- **Use `--no-fail-fast`.** Fail-fast aborted at binary 92 of 317 and reported
  one failure where there were six.

---

## Verification state

Full workspace suite after the changes described in Context: **317/317 binaries,
5,159 passed, 0 failed**; clippy, fmt and SPDX clean.

One caution worth inheriting: the two-phase merge rule was got wrong once. An
earlier version kept phase 1's outcome unless forcing *fuzzed*, reasoning that a
forced `report_only` says less than an unforced `failed_build` that names a real
error. That reasoning is fine about diagnostics and wrong as a mechanism — it
suppressed the result the operator explicitly asked for and broke two documented
contracts (`force_bypasses_cpp_only_class_pre_skip_gate`,
`unbuildable_target_degrades_to_report_only_under_force`). Every targeted run of
the force tests passed; only the full suite caught it. The diagnostic concern is
met instead by phase 2 printing its own blocker histogram.
