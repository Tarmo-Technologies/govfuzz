<!-- SPDX-License-Identifier: Apache-2.0 -->
# `--force` reach: what was fixed, and what govfuzz still cannot fuzz

Handoff document. Everything here was found by measuring `--force` over 126 real
projects and then reading the residual blockers. Each item states the symptom,
the root cause, what changed, how to verify, and — where it matters — what has
been **ruled out**, so nobody re-derives it.

Read "Context" first: several fixes landed recently and an item below can look
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

**Do not "simplify" phase 1 back into a single forced pass.** That is the
regression the +10 measures against.

---

## 1. `--force` could not stub a function returning a struct by value — FIXED

### Symptom

A link error survived `--force`, which is supposed to stub whatever the compiler
reports undefined. On `nicbarker/clay`:

```
Clay_Raylib_Initialize -> failed_build
  {"kind": "undefined_symbol", "name": "LoadShaderFromMemory"}
```

### Root cause

Twenty other raylib symbols in the same harness **were** stubbed into
`repairs/auto_stubs.c` (all `weak`). Exactly one stayed undefined, and the
discriminator was its return type:

```c
/* clay/renderers/raylib/raylib.h:1052 */
RLAPI Shader LoadShaderFromMemory(const char *vsCode, const char *fsCode);
```

The others return `void` or scalars. `stub_body_for_return_type` hands back a
`&'static str`, so it cannot name a type, and it declined — emitting no repair
at all, so the link stayed broken.

### Fix

`stub_aggregate_value_return_body` (`crates/c_stub_gen/src/lib.rs`) constructs
the value: `<Type> _gf_ret = {0}; return _gf_ret;`. `{0}` zero-initializes any
**complete** aggregate in C without `<string.h>`, and zero is the same neutral
answer every other stub gives.

Reached only from the **header-backed** path, where the declaration's own header
is included in the stub TU and the type is therefore complete. In the isolated
TU (which sees only `auto_types.h`) a definition with an incomplete result type
is invalid C whatever its body — C11 6.9.1p3 — so refusing there stays correct,
and `isolated_stub_still_refuses_an_aggregate_return` pins that.

### Ruled out

- **Not a repair budget problem.** `--max-repair-rounds 30` behaved identically
  to `4` and printed no "repair cap reached". The planner returned no repair; it
  did not run out of rounds.
- **Not the `main`/libc refusal guards** in the `UndefinedSymbol` arm of
  `plan_repair_forced_with_source_policy` — the symbol is neither.

### Verify

```
git clone --depth 1 https://github.com/nicbarker/clay
govfuzz auto clay --work-dir wk --per-target-time 1 --single-pass --jobs 1 \
  --max-attempts 6 --max-repair-rounds 6 --force
```

Measured: 3 built+fuzzed of 6 attempted → **4**, `Clay_Raylib_Initialize` among
them, and no `{"kind":"undefined_symbol","name":"LoadShaderFromMemory"}`.

---

## 2. 297 targets end `unbuildable after N repair rounds` — enumerated, one class fixed

### Symptom

Across the 126-project forced arm, 297 targets end with a `report_only` blocker
reading `forced: unbuildable after N repair round(s) (N residual build error(s)
the diagnostic-driven stubbing could not resolve)`. By lane: **c 125, cpp 76,
go 47, csharp 25, rust 24**.

This is a **class, not a defect** — it is whatever the repair loop could not fix.
It cannot be worked from the blocker histogram, which normalizes for grouping and
says nothing about cause. The answer only exists in each harness's
`repairs/*_build_output.log`.

### The enumeration

`benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the corpus forced,
harvests the actual `error:` lines out of every harness GovFuzz GAVE UP on, and
deletes the clone and work dir immediately, so peak disk stays at one project.

**The first cut of that filter was wrong, and it inverted the ranking.** It read
a `status` key that does not exist on `result.json` (the outcome is nested), so
every harness with an error in its last build log was harvested — including ones
that ended `built_and_fuzzed`. The repair loop reaches the LINK stage with
symbols still undefined *on its way to resolving them*, so a successful C harness
routinely leaves `undefined reference to …` behind. That put "undefined
reference" and "linker command failed" at the top, 25 and 24 of 104, when btop's
four exemplars all ended `built_and_fuzzed` with `retries=1,
repairs=[add_source]`. If a class looks huge, check the outcome before the log.

Filtered to terminal outcomes, over 55 unbuilt harnesses in 26 c/cpp projects:

```
   17  [c:11 cpp:6]  unknown type name '<id>'
   15  [cpp:8 c:7]   use of undeclared identifier '<id>'
    8  [c:5 cpp:3]   expected expression
    8  [c:5 cpp:3]   undefined reference to '<id>' / linker command failed
    7  [c:5 cpp:2]   field has incomplete type '<id>'
    7  [c:7]         cannot combine with previous '<id>' declaration specifier
    5  [c:3 cpp:2]   redefinition of '<id>'
```

Re-run it (`--report <jsonl>` histograms an existing capture without sweeping).
The normalized text is for GROUPING; always open an exemplar's raw log — the
capture keeps the first six verbatim lines per harness for exactly that.

### Fixed from that list: the configure-style `#error` guard

Ten of the 104 died on a header's own `#error`, and nothing was missing from the
tree at all:

```
/libssh/include/libssh/priv.h:45:4:   error: "no strtoull function found"
/libssh/include/libssh/priv.h:198:4:  error: "Your system must provide a __func__ macro"
/MagickCore/magick-config.h:70:3:     error: "you should set MAGICKCORE_QUANTUM_DEPTH"
```

A real `./configure` would have defined the macro the guard tests. No
header/type/symbol repair can apply — there is nothing to synthesize — so those
targets burned every repair round and ended report-only. `ConfigGuardError` now
classifies the diagnostic (both the gcc `error: #error "..."` and clang
`error: "..."` spellings), and the planner walks up to the conditional owning the
`#error` and defines the macro that makes the branch dead, with the value the
guard itself requires. The **outermost** negative feature-test wrapper wins over
the innermost decision: libssh's real shape nests the chain inside
`#if !defined(HAVE_STRTOULL)`, and taking the inner branch defines
`HAVE___STRTOULL`, which aliases `strtoull` to a symbol this host does not have —
one `#error` traded for an undefined reference. Undecidable guards are refused,
not guessed.

**Measured** (`config_guard_ab.sh`, pinned binaries, the two corpus projects that
carry the class): the guard diagnostics are gone from every build log, and
report-only targets rise — WindTerm 3 → 6, ImageMagick 1 → 4 — so more targets
reach the degradation floor. **Neither converts a target to fuzzing** inside a
90-second campaign: what sits behind the guard is a different class (absent
crypto libraries on WindTerm, a missing generated `magick-baseconfig.h` on
ImageMagick). Do not restate this as a fuzz-count win.

Note also that WindTerm's downstream `unknown type name 'bignum'` / `'MD5CTX'`
errors are NOT consequences of the guard — they are `#ifdef
HAVE_LIBGCRYPT`/`HAVE_LIBCRYPTO` blocks over genuinely absent libraries, which is
a missing-dependency problem, not a config-guard one.

### What is left

The rest is unenumerated only in the sense that nobody has read the exemplars
yet. Re-run the capture — it takes about an hour for 53 projects and keeps six
verbatim compiler lines per harness — then work it the way this campaign worked:
fix the largest class, re-measure, repeat. The levers adopted because they seemed
obviously right, without measuring, are the ones that turned out wrong.

The capture itself is deliberately not committed: it is a measurement of one
binary at one moment, and a stale one invites exactly the mistake of reading a
fixed class as still open.

### Worked from that list

Five more defects came out of reading the exemplars, and four of the five were
GovFuzz's own errors rather than project limitations:

- **`--force` emptied the missing-dependency manifest.** The forced degradation
  to report-only replaced the diagnostics with a count, and a report-only outcome
  has no `last_errors` for the manifest to mine. tmux reported "4 still blocking"
  unforced and "No external dependencies were missing" forced. Fixed by carrying
  the unresolved type names across the degradation; pinned by
  `auto_force_keeps_manifest.rs`.
- **Macro templates discovered as targets.** BSD `<sys/tree.h>`'s
  `RB_GENERATE_INSERT` defines a function body inside a continued `#define`;
  `attr`/`type`/`name` are macro parameters. Seven dead targets in tmux, each
  ending `cannot combine with previous 'type-name' declaration specifier` — the
  whole of that histogram row.
- **Macro invocations discovered as targets.** Linux's `TRACE_EVENT(...)`. Two in
  lede; together with the above, 139 pseudo-targets left the ranked list.
- **The Win32 pack redefining the tree's own typedefs.** lede's MediaTek Linux
  driver owns `CHAR` and `_LARGE_INTEGER`; the force-included pack redefined
  them. That was the whole `redefinition of` / `typedef redefinition` row.
- **A CamelCase export macro leaking into the C harness** (`ModuleExport`), the C
  twin of the C++ decoration leak.

What remains in `unknown type name` after those is dominated by genuinely absent
SDKs — libevent, Qt, protobuf, JNI, Win32 — which is a manifest problem, not a
repair one, and the manifest now reports them under `--force` too.

Three observations to start from:

- **`unknown type name` (17) is the largest, and it splits.** Roughly half is a
  type gated behind an absent third-party SDK — libssh's `MD5CTX`/`SHACTX`/
  `bignum` behind `HAVE_LIBGCRYPT`, Qt's `QRect`, protobuf's `Message`, Win32's
  `LONG`/`UINT32`/`HRESULT`. Those are missing dependencies, and the honest fix is
  the manifest, not a repair. The other half is govfuzz's own: an export
  decoration macro leaking into the GENERATED harness (ImageMagick's
  `ModuleExport` at `main.c:49`), which also produces the follow-on `expected ';'
  after top level declarator` rows. That C-side leak is the obvious next lever —
  the C++ side of exactly this shape was fixed in 0.2.21.
- **`use of undeclared identifier` (15) is the same family**, sharing its
  exemplar with the above (QtScrcpy `H-X0038`).
- `cannot combine with previous declaration specifier` (7, all C, all tmux)
  smells like a synthesized typedef colliding with a real one, i.e. a govfuzz
  codegen defect rather than a project limitation. Cheap to confirm from one log.

---

## 3. `--force` outside C/C++/Ada — Go and C# done, Rust open

### Symptom

`unsupported_params` **survived** forcing on four lanes. From the forced arm's
residual blockers:

| Lane | Targets | Shape |
|---|---:|---|
| Go | 116 | 58 undrivable param types, 23 methods, plus go-version / no-`go.mod` |
| Rust | 64 | 37 no byte decoder, 16 target-kind, 11 private-module trait-impl |
| C# | 31 | unconstructible receivers (instance method, no usable constructor) |

Go's undrivable count was **unchanged** at 219 between arms, which was the tell:
nothing even attempted it.

### Go and C# — done

Both lanes now have the C-family analogue of
`crates/harness_gen/src/c_decoders.rs::best_effort_param_emission`, whose
contract is the right one: a driver that **compiles**, with value correctness
explicitly not a goal.

- **Go** (`crates/cli/src/auto/go_build.rs`): an undrivable parameter becomes its
  type's zero value. Every Go type has one, so the only thing that can fail is
  NAMING the type from the harness package — an exported target type gains the
  `tgt.` qualifier, a predeclared name and a qualifier into a package the harness
  already imports are kept, and an unexported / generic / variadic /
  inline-literal spelling is refused rather than guessed. A method is called on a
  zero receiver via `(&recv).M(...)`, valid for both a pointer and a value
  receiver — deliberately **not** a nil `*T`, which would panic the moment the
  method touched a field, and that panic would be govfuzz's fault, not the
  target's.
- **C#** (`crates/cli/src/auto/csharp_build.rs`): a receiver type whose only
  constructors are parameterized or private is allocated without running one, via
  the runtime's `GetUninitializedObject`. Resolved by reflection so the shim
  compiles on any TFM (the primitive changed namespace in .NET 5). An abstract
  type or interface is still refused — there is no instance to allocate by any
  route.

A fabricated value can panic on its own account, so a target built this way
records a `ForcedSyntheticParams` repair naming exactly what was synthesized. The
report floors its findings to Low with the forced caveat and counts it in
`summary.forced`, the same treatment a stub-only C build gets. **Keep that
coupling**: without it a forced nil-map panic reads as a confirmed CWE-476.

### Rust — open, and hard

Left deliberately. The three shapes are not one problem:

- **"no byte decoder for T" (37)** is a type-system fact. The Go trick does not
  transfer: Rust has no universal zero value, and `T::default()` only compiles if
  `T: Default`, which cannot be tested at codegen time without type resolution.
  Emitting it speculatively trades a clean skip for a `failed_build` plus the
  wasted build — measure before assuming that is an improvement.
- **target-kind (16)** and **private-module trait-impl (11)** are separate known
  gaps, not parameter problems.

### Go's environment blockers are not force-able

"no `go.mod`" and "requires go >= X" are toolchain problems. A force path cannot
touch them, and they are counted inside that 116 — subtract them before claiming
a target number.

---

## Re-measuring

Harness lives in `benchmarks/campaign-2026-07-25/`.

```
# The forced arm, restricted to the projects a force flag can move.
sh launch_force_ab3.sh                       # writes results-force3/
python3 force_delta.py --baseline results-plain2 --forced results-force3

# What the forced arm could not build, by compiler diagnostic.
python3 residual_errors.py --lanes c,cpp --limit 40 --out residual-c-cpp.jsonl
python3 residual_errors.py --report residual-c-cpp.jsonl

# A/B a fix whose class is already identified, on the projects that carry it.
sh config_guard_ab.sh
```

`force_delta.py` splits **real fuzz reach from stub-only** and **fuzz findings
from static findings**. That split is load-bearing: `summary.findings` counts
report-only static findings alongside runtime crashes, and reading the total
made the global-force arm look like "+376 findings" when its fuzz findings were
unchanged. Do not report a findings delta that has not been split.

### Rules that cost time when broken

- **Both A/B arms must run the same binary**, and the sweep must not point at
  `target/release/govfuzz` while you are still building into it — an enumeration
  run that way silently changes binary mid-sweep and is not an A/B at all. Copy
  the binary to `/home/ubuntu/govfuzz-sweep-bin/` first and pass it explicitly.
- **`govfuzz --version` is identical across rebuilds** (`v0.2.20-18-g893b68c-dirty`).
  Distinguish binaries by `md5sum`, never by version string.
- **Match the instrument to the claim.** A whole-corpus A/B costs an hour and has
  a ±3 noise floor; for a class as specific as the `#error` guard, running the
  two projects that exhibit it under two pinned binaries answers the question
  exactly and takes minutes.
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

One caution worth inheriting: the two-phase merge rule was got wrong once. An
earlier version kept phase 1's outcome unless forcing *fuzzed*, reasoning that a
forced `report_only` says less than an unforced `failed_build` that names a real
error. That reasoning is fine about diagnostics and wrong as a mechanism — it
suppressed the result the operator explicitly asked for and broke two documented
contracts (`force_bypasses_cpp_only_class_pre_skip_gate`,
`unbuildable_target_degrades_to_report_only_under_force`). Every targeted run of
the force tests passed; only the full suite caught it. The diagnostic concern is
met instead by phase 2 printing its own blocker histogram.
