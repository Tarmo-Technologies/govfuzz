<!-- SPDX-License-Identifier: Apache-2.0 -->
# What GovFuzz still misses, and why

An honest inventory of every class of target GovFuzz does **not** fuzz, sized from
the 500-project sweep (`benchmarks/campaign-2026-07-25/results-0727/`: 463
projects measured, 3,594 targets attempted, 1,057 built and fuzzed).

Counts are targets, from the sweep's own residual-blocker histogram. They were
produced by the binary **before** the 2026-07-27 fix wave, so a class fixed since
is marked **[FIXED]** and its count is what it used to cost. Everything else is
live.

Each class carries a verdict:

- **GAP** — GovFuzz's own limitation. Fixable here. This is the work list.
- **DEPENDENCY** — the code needed is genuinely not in the tree. The honest
  answer is the missing-dependency manifest, not a repair; installing the
  dependency fixes it.
- **ENVIRONMENT** — a toolchain fact about this host. Not GovFuzz's decision.
- **BY DESIGN** — a deliberate refusal, documented, with the reason.

---

## The shape of the loss

Of 3,594 attempted targets, 2,537 did not fuzz. Roughly:

| | targets | share |
|---|---:|---:|
| DEPENDENCY — a package/header/SDK that is not in the tree | ~1,050 | 41% |
| GAP — GovFuzz cannot drive or build it yet | ~1,180 | 47% |
| ENVIRONMENT — toolchain version, SDK ceiling | ~110 | 4% |
| BY DESIGN — legacy dialect, report-only | ~45 | 2% |
| Fixed since this measurement | ~150 | 6% |

**The single largest fixable mass is undrivable parameters, not failed builds.**

---

## C

### C-1. Opaque type needs lifecycle support — 86 — **GAP**

The biggest single C gap. Sub-shapes:

| | count | what it is |
|---|---:|---|
| `opaque type X for parameter X` | 31 | a by-value type the tree never defines |
| `opaque type X for pointer parameter X` | 28 | pointer to same |
| `opaque handle X … incomplete in the harness's included headers` | 13 | **the full definition IS in the tree, in a non-included `.c`** |
| `pointer parameter X … not safely drivable after struct synthesis` | 7 | synthesis produced something unsafe to point at |
| `decoder … exceeds 65536 bytes after struct synthesis` | 6 | a legitimately huge aggregate |

The 13 "incomplete in the harness's included headers" cases look like the
tractable ones, but **check the plumbing before believing that**. The refusal
message describes the situation ("its full definition is visible only in a
non-included source"); it does NOT mean GovFuzz is holding that definition. The
harness's `type_defs` are deliberately "the INCLUDED headers + the tree-wide
flat-POD fallback — never the target `.c`'s own body"
(`header_complete_aggregate_spellings`), so at the point of refusal the complete
struct is not in the registry at all.

Replicating a private struct into the harness translation unit is still the right
idea — completing an incomplete type is legal C, and the layout matches because
the text is the project's own — but it needs the tree-wide struct definitions
plumbed down to the decoder first. That is a real feature, not a small fix.

`git`'s `struct repository`, timescaledb's `CompressionSettings` and antirez/ds4's
`ds4_session` are the worked examples.

### C-2. `missing header` (26) / `missing type` (31) / `undeclared function` (20) — **mostly DEPENDENCY**

After the repair loop exhausts itself. Spot-reading these in the previous
campaign found them dominated by genuinely absent SDKs — libevent, Qt, protobuf,
JNI, Win32. The manifest reports them. A minority are GovFuzz's own and worth
re-reading the exemplars for; that method has produced a fix every time it was
run.

### C-3. K&R C — 21 — **BY DESIGN**

Discovered and statically analyzed, not fuzzed (M22). Fuzzing a K&R definition
means synthesizing a prototype from the parameter declaration list; the
discovery side already recovers the true signature, so this is closer than the
count suggests.

### C-4. `build abandoned after N repair rounds: --campaign-time exhausted` — 10 — **ENVIRONMENT**

A cut-off, not a diagnosis. Correctly reported as such. Raise the budget.

---

## C++

### C++-1. `blocked_by_non_self_contained_header` — 49 report-only + 10 in C — **GAP**

A header that cannot be included by an independent translation unit. `--force`
already bypasses this gate and it works — clay went 0 → 3 fuzzed that way. The
gap is that the **unforced** default refuses without trying, so a plain
`govfuzz auto` never sees them.

Worth measuring: attempt-then-fail costs a build; the current refusal costs a
target. Do not change it without an A/B.

### C++-2. Unconstructible class — 30 — **GAP**

"no public default constructor, no supported public constructor, and no
factory". The producer graph resolves constructor arguments to a fixed point
already; these are what it still cannot reach.

### C++-3. No byte-buffer decoder — 33 — **GAP**

The auto-harness drives scalars, strings and visible aggregates. What is left is
templates, non-visible aggregates and library types.

### C++-4. Return type undefined in the scanned tree — 16 — **DEPENDENCY**

An external SDK/framework type (MFC, a vendor CORBA IDL). Correctly report-only.

### C++-5. Member of a class defined only in a `.cpp` — 4 — **GAP**

Same shape as C-1's "definition is in a non-included source", in C++.

### C++-6. `compile flag contains a shell/make metacharacter` — 6 — **[FIXED]**

A flag that is safe once single-quoted is now quoted rather than refused; `$`, a
single quote and a newline are still refused, and paths/include names stay
strict.

### C++-7. `linker command failed` — 10 — **GAP or DEPENDENCY**, unsplit

Needs the exemplars read. Terminal link failures after repair.

---

## Ada

### Ada-1. `1 undefined symbol(s) after repair` — 33 — **GAP**

The largest Ada class. The repair loop stubs Ada units and C symbols but ends
with one symbol unresolved.

### Ada-2. `missing Ada symbol` — 19 — **GAP**

### Ada-3. `unit X cannot belong to several projects` — 9 — **GAP, mechanism known**

GovFuzz's own project synthesis, not the target's. Reproduced on
mk270/whitakers-words (4 targets attempted, 3 die this way).

The synthesized project is `project Govfuzz_Build extends "<tree>/commands.gpr"`
with `Source_Dirs` pointing at `<work>/src_instrumented`. That work dir holds
INSTRUMENTED COPIES of the tree's units. `commands.gpr` `with`s sibling library
projects (`support_utils.gpr`, `latin_utils.gpr`, …) that own `src/<Name>`, so
`support_utils.uniques_package` is owned by both `govfuzz_build` (the copy) and
`support_utils` (the original), and gprbuild refuses.

**`extends all` does NOT fix it — tested.** The obvious GPR answer for overriding
units across a withed closure leaves the identical diagnostic on this project.
Do not spend the experiment again.

What is left to try: build purely from the staged sources without `extends`
(losing the user project's compiler settings and link flags), or drop from
`src_instrumented` any unit the extended closure already owns (losing coverage
instrumentation on exactly those units). Both are trade-offs, so measure the
built count before choosing.

### Ada-4. `predefined unit depends on itself` — 9 — **GAP**

Same family: a staged copy of a predefined unit shadows the real one.

### Ada-5. `named type X is not declared in the parsed source set` — ~10 — **GAP**

`Char_Array`, `Lsp.Json_Streams.Json_Stream`, `St7735r_Bitmap_Buffer`. A type
whose declaration is outside the parsed set and which has no synthesizable
constructor.

### Ada-6. `blocked_by_generic` — 1 — **GAP**

A generic subprogram with a parameter that has no default.

---

## Go

### Go-1. Undrivable parameter type — 58 — **GAP**

`*protocol.RequestHeader`, `*pflag.FlagSet`, `DecodeOptions`, `context.Context`,
`*zap.Logger`. Under `--force` these become zero values; unforced they skip.
**`context.Context` is [FIXED]** — it is call context, not fuzz input, and now
decodes to `context.Background()` (never nil, which would panic the callee). The
rest are genuine project/library types.

### Go-2. Method needs a receiver — 24 — **GAP (partly by design)**

Says "pass `--force`". The forced path exists and works; the gap is that a
no-arg-constructible receiver is not attempted unforced.

### Go-3. `not inside a Go module (no go.mod)` — 17 — **GAP**

A GOPATH-era or vendored tree. Synthesizing a `go.mod` for such a tree is the
same trick the harness module already uses.

### Go-4. `requires go >= X` — 13+ — **ENVIRONMENT**

Under `GOTOOLCHAIN=local`. There is already an overlay that lowers the directive
and retries; these are the ones where that is not enough.

---

## Rust

### Rust-1. No native byte decoder — 42 — **GAP**

A type-system fact: Rust has no universal zero value, and `T::default()` only
compiles if `T: Default`, which cannot be tested at codegen time without type
resolution. Emitting it speculatively trades a clean skip for a failed build —
**measure before assuming that is an improvement**.

### Rust-2. Private-module trait-impl method — 17 — **GAP**

In-crate trait resolution is not implemented.

### Rust-3. `unsafe fn` with a caller-upheld precondition — 16 — **BY DESIGN**

Driving it from fuzz bytes means violating the contract, and the resulting crash
is GovFuzz's fault, not a finding. Correct to refuse.

### Rust-4. Static method of a non-in-crate trait impl — 11 — **GAP**

---

## Java

### Java-1. Unsupported parameter type — 75 — **partly GAP, partly DEPENDENCY**

`Context` (15, Android — not resolvable offline), `RequestHttp<…>` (6, generic),
`ListNode`/`TreeNode` (4, project types), `Map<String,Object>` (3),
`File`/`Writer` **[FIXED]**. The remainder is generics: an empty `List<T>` cannot
be spelled without resolving `T`, and the harness declares locals with `var`,
which infers the wrong type. Resolving that needs the declared type, not `var`.

### Java-2. Instance method, no no-arg constructor — 12 — **GAP**

The builder/factory receiver synthesis (#459) covers some; these are the rest.

### Java-3. Constructor of an abstract class/interface — 8 — **BY DESIGN**

### Java-4. Maven `DependencyResolutionException` — 20 — **DEPENDENCY**

Offline. Correct.

---

## C#

### C#-1. Unconstructible receiver — 26 — **[PARTLY FIXED]**

`GetUninitializedObject` covers the forced path. Unforced, an instance method
whose type has no accessible parameterless constructor still skips.

### C#-2. Abstract/interface receiver — 13 — **BY DESIGN**

No instance to allocate by any route.

### C#-3. `CS0246: type or namespace not found` — 32 — **DEPENDENCY**

### C#-4. `NETSDK1045` / `NU1010` — 15 — **ENVIRONMENT**

SDK ceiling and central package management.

---

## Python

### Py-1. `ModuleNotFoundError` — 266 — **DEPENDENCY**

The largest single class in the whole sweep. Correctly named in the manifest with
the package; `--install-deps` fixes it where the network allows.

### Py-2. Instance method needs constructor arguments — 25 — **GAP**

Only no-arg-constructible receivers are supported.

### Py-3. `type X is not subscriptable` — 10 — **DEPENDENCY**

Checked, and it is not ours: the project's OWN module fails to import because it
subscripts a class that is not generic on the installed library version
(spec-kit's `Choice[...]`). Correctly reported as "not loadable (skipped
cleanly)" with the interpreter's real message. I had this filed as a loader gap
from inspection; reading an exemplar corrected it.

### Py-4. Python 2 — 20 — **BY DESIGN**

---

## JavaScript / TypeScript

### JS-1. Missing npm package — ~225 — **DEPENDENCY**

### JS-2. Browser globals: `window is not defined` (23), `navigator is not defined` (5) — **GAP**

A DOM-targeting module loaded under bare Node. A minimal global shim would make
these loadable; whether the resulting fuzz is meaningful needs judgement, and a
shim that lies about the environment can manufacture findings.

### TS-1. `No loader is configured for ".png"/".svg"/".yaml"/".vue"` — 18 — **[FIXED]**

The transpile now declares loaders for the usual non-code assets: inert text for
markup and config, a data URL for binaries.

### JS-3. Unconstructible receiver — 58 — **[FIXED]**

---

## Ruby / PHP / Lua / Perl

Dominated by **DEPENDENCY** (missing gems, Composer `vendor/`, luarocks, CPAN):
roughly 140 targets. The remainder are real load-time preconditions in the target
(`private method called`, `Trait not found`, `attempt to index a nil value`) —
each is the project telling you it needs an environment. Correctly skipped and
named.

---

## Fortran

### For-1. `Cannot open module file` / `Cannot open included file` — ~10 — **DEPENDENCY**

`stdlib_kinds.mod`, `fpm_environment.mod`, `SIZE`. A Fortran `.mod` is a build
artifact, so an unbuilt dependency has none.

### For-2. Unresolved external symbols — 3 — **DEPENDENCY**

---

## Ranked work list

By fixable targets, highest first:

1. **C opaque-type lifecycle** (86) — the 13 "incomplete in headers" cases need
   the tree-wide struct definitions plumbed to the decoder first; see C-1.
2. **Java generic/collection parameters** (~40 of the 75) — needs declared-type
   locals instead of `var`.
3. **C++ non-self-contained header, unforced** (49) — measure attempt-vs-refuse.
4. **Go undrivable parameters** (58) — `context.Context` alone is worth doing.
5. **Rust decoders** (42) + trait-impl resolution (28).
6. **C++ unconstructible class** (30) + no-decoder (33).
7. **Ada link/symbol residue** (52 across Ada-1/2) and **GPR structure** (18).
8. **Python receiver-with-arguments** (25) and C# unforced receiver (26).
9. **TS asset loaders** (12) and **JS browser globals** (28) — cheap, but the
   second risks manufacturing findings.
10. **C++ compile-flag quoting** (6) — smallest, purely mechanical.

## Method

Do not work this list from the histogram alone. It normalizes for grouping and
says nothing about cause; every fix in the last two waves came from opening an
exemplar's raw build log, and twice the obvious-looking diagnosis was wrong.
`benchmarks/campaign-2026-07-25/residual_errors.py` harvests those logs.
