<!-- SPDX-License-Identifier: Apache-2.0 -->
# What GovFuzz still misses, and why

An honest inventory of every class of target GovFuzz does **not** fuzz, sized from
the 500-project sweep (`benchmarks/campaign-2026-07-25/results-0727/`: 463
projects measured, 3,594 targets attempted, 1,057 built and fuzzed).

**Re-measured 2026-07-28** over a full 500-project sweep
(`results-0728/`: 482 projects measured, 1,212,086 targets discovered, 3,638
attempted, **1,069 built and fuzzed — 29.4%**, 366 findings, all 16 lanes). The
class shape below is unchanged; see [What the 2026-07-28 sweep
changed](#what-the-2026-07-28-sweep-changed) for what it added and closed.

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

### Go-2. Method needs a receiver — 24 — **GAP, blocked on the parser**

Says "pass `--force`". The forced path exists and works (a zero receiver, taken
by address so `(&r).M()` is valid for both value and pointer receivers); the gap
is that a REAL receiver from a sibling `func NewT() *T` is not attempted
unforced, which is what a human would write.

**The blocker is `go_parser::GoFunc`, which does not capture a return type** —
so a constructor cannot be told from any other no-arg function. Add
`returns: Option<String>` there first; `receiver_synthesis` is then a small
change, and it needs to emit `recv.M(…)` for a `*T` constructor versus
`(&recv).M(…)` for a `T` one.

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

## What the 2026-07-28 sweep changed

The re-run was measured on a binary pinned before that day's fixes, so it is a
clean read of the previous release.

**Found and fixed — a crash, not a gap.** `carbon-language/carbon-lang` was
SIGKILLed (`exit -9`) during discovery in BOTH `list targets` and `auto`.
GovFuzz produced *no target list at all*, which is worse than any residual
class here: a hard kill leaves nothing to act on and looks exactly like a hang.

Root cause was in type resolution, not discovery. `MAX_RESOLVE_DEPTH` bounds
recursion depth but not breadth, so a self-referential C++ type unrolled to the
16-deep limit materialized on the order of F^16 field vectors. One 1205-line
header cost **13.0 GiB and 88s**. Fixed by memoizing on (spelling, depth) and
stopping at a cycle — a type that transitively contains itself now resolves to
`Opaque` at the recurrence rather than unrolling, which loses nothing because a
decoder cannot build an infinitely nested value either way.

| carbon-lang | before | after |
|---|---:|---:|
| whole tree, `list targets` | SIGKILL at 12.9 GiB, 0 targets | exit 0, **52 MiB**, 5,092 targets |
| whole tree, `auto` | SIGKILL, 0 targets | 4,040 fuzzable targets |
| the single header | 13.0 GiB / 88s | **77 MiB / 1.2s** |

The same fix took `simdjson` from a 900s `list targets` timeout to completing in
481s with 14,690 targets. Seven other C/C++ projects still time out
(`sumatrapdf`, `Proton`, `emscripten`, `serenity`, `rocksdb`, `envoy`,
`whisper.cpp`) — those are tree size, not this bug.

Discovery also gained the RSS ceiling the static scan already had, on both
surfaces (`list targets` parses five lanes itself and defers eleven, so guarding
only the shared walk would have left C++ unguarded). It degrades to a partial
target list and says so. Note it did **not** save carbon-lang on its own: one
file crossed the ceiling and blew past it between two 500ms samples, which is
why the type-resolution fix was the real one. The guard is the backstop for
trees that grow past memory gradually.

**Closed since the measurement.** `blocked_by_non_self_contained_header`
(49 C++ targets, the largest C++ residual class) now falls back to the header's
owner translation unit, adopted only when it preflight-compiles. A repair that
`#define`d over an enumerator the project itself defines — corrupting
`enum { X = 4 }` into `enum { 1 = 4 }` and breaking a source that compiled fine
— is vetoed the same way tree functions and types already were.

**Still open, unchanged by this sweep.** The dominant residual mass is still
missing modules/packages (Python 273, TypeScript 174, JavaScript 95, Ruby 42,
Lua 39, PHP 36) — DEPENDENCY, answered by the missing-dependency manifest, not
by a repair. The largest remaining GAP classes are undrivable parameters and
unconstructible receivers, as below.

---

## Performance: the static scanner

`static-scan` was the last measured outlier after the timeout sweep, and it is
now **13.6x faster on Java** with byte-identical output.

| tree | lane | before | after |
|---|---|---:|---:|
| elasticsearch (4.99M SLOC) | Java | 616.6 s | **45.4 s** (13.6x) |
| kubernetes | Go | 59.2 s | **15.4 s** (3.8x) |
| Proton | C/C++ | 10.6 s | 10.4 s (unchanged) |

8.1k -> 110k SLOC/s on Java. Every number above was gated on
`scripts/validation/finding-parity.py`: identical findings, identical
`analysis_gaps`, per rule, severity and CWE. Speed is easy to measure and easy to
fool yourself about; losing a finding looks exactly like a faster scan, and gaps
are where the engine admits it stopped, so exploring less shows up as MORE gaps
even when the finding count holds.

**The earlier entry here blamed the wrong pass.** It named the interprocedural
taint worklist, on the strength of reading the code. Measurement put 24 of a
28-second Java scan in `annotate_reachability` — the call-graph BFS that LABELS
findings — and only 1.3 s in taint. Both real causes were in that BFS:

- **`reachable` was a `BTreeSet<FunctionKey>`, and a key holds a `PathBuf`.** Every
  probe cost ~17 comparisons of long path strings, and the BFS probes once per
  candidate target per call site. It is membership-only, never iterated, so it is
  now a hash set: **3.1x** on its own, and it helped Go as much as Java.
- **Each call site walked EVERY function in the tree sharing that name**, and that
  list grows with the tree — the actual source of the O(n^1.6). A name whose whole
  candidate set is already reachable can never contribute again, whichever subset
  the preference rules pick, so such names are retired. The reachable set only
  grows, so that is monotonic and cannot go stale: a further **2.7x**, and the BFS
  went from 79.1 s to 2.0 s on the full tree.

**The residual is lane-specific, and it is the Java call graph.** Measured phase
shares on comparable trees:

| lane | per-file | taint | reachability |
|---|---:|---:|---:|
| Go (kubernetes) | 15.3 s | **2.1 s** | 1.9 s |
| C++ (Proton) | 13.0 s | **0.04 s** | 0.09 s |
| Python (django) | 5.1 s | **0.6 s** | 0.3 s |
| Java (elasticsearch) | 23.5 s | **15.9 s** | 4.2 s |

Measuring the call graph itself says what the cause is
(`GOVFUZZ_PROFILE=1` prints these):

| lane | call sites | edges walked | fan-out |
|---|---:|---:|---:|
| Java (elasticsearch) | 175,297 | 436,984 | **2.49** |
| Go (kubernetes) | 17,690 | 14,112 | **0.80** |

Counted AFTER the self-call and duplicate drops, so these are edges the taint pass
actually walks. (A first version counted raw candidate visits and reported 3.21 /
0.91 — about 22% too high, because `local_calls` discards duplicates and
self-calls further down. The ratio survived the correction; the absolute number
did not.)

**Java carries roughly 3.1x the edges per call site that Go does.** Calls are
`obj.method(...)`, and the index keys on name plus arity, so `get()` resolves to
every zero-argument `get` in the tree. Each spurious edge is both extra taint
work and a spurious flow, which is why elasticsearch also emits 43,660
`unresolved_project_local_call` gaps for the names that match nothing at all.

So this is one defect with two symptoms, not a density fact about Java. A
receiver-type-aware index would make the lane **faster AND more precise** —
narrowing 562k edges toward Go's ~1:1 removes work and removes spurious flows.

**Do not "fix" this by enabling the C++ receiver path for Java.** The machinery
looks one language gate away —

    if language == "cpp" {
        for (name, type_name) in cpp_local_object_declarations(&line.text) { ... }
    }

— and it is a trap. `cpp_member_targets` resolves `ReceiverType::member` against
`by_name` with **no inheritance walk**: when the method is declared on a base
class or interface, the lookup misses and it returns NO targets. Java dispatch is
virtual and elasticsearch is interface-heavy, so most call sites would resolve to
nothing at all — turning a 2.49x over-approximation into near-total
UNDER-approximation and silently gutting taint propagation.

It would present as a large speedup with fewer findings, which is exactly what a
real precision win also looks like. Anyone taking this must build an
inheritance-aware index first (declared type -> supertypes -> declaring class),
and treat the resulting finding delta as the deliverable.

**Step one is a PARSER change, and it does not exist yet.** `JavaTypeModel`
carries `fqn`, `is_enum`, `self_constants`, `has_public_no_arg_ctor` and
`no_arg_self_factories` — there is no `extends`/`implements`, and `JavaMethod`
records no declaring hierarchy. So the supertype closure the narrowing depends on
cannot be computed from what `java_parser` produces today. The order of work is:

1. ~~`java_parser`: extract `extends` / `implements` per type.~~ **DONE** —
   `JavaTypeModel::supertypes` carries them (leaf-reduced, so `java.io.Closeable`
   is usable as an index key). Inert: nothing consumes it, behaviour unchanged.
   Note for whoever continues: a class exposes `superclass`/`interfaces` as named
   tree-sitter FIELDS, but an interface's own `extends` list is an unnamed child
   node — a field-only lookup silently returns nothing for
   `interface A extends B, C`, which is the case that matters most.
2. `static_analysis`: build declared-type -> supertype-closure, and resolve a
   member against the closure rather than the declared type alone.
3. Gate it opt-in, measure the finding delta with `finding-parity.py`, and review
   what disappears BEFORE it becomes the default.

Skipping (1) is what makes the language-gate shortcut above look plausible and
makes it destructive.

It is not taken here because it is a PRECISION change: `finding-parity.py` should
be expected to show findings CHANGE, most likely decrease as spurious flows
disappear, and each disappearance needs looking at rather than waving through.
That is a deliberate piece of work with a review step, not an optimisation.

The rest is inherent work, and that is now a measured claim rather than an
assumption. Two further optimisations were tried on the taint worklist and BOTH
measured as no gain:

- Hashing its membership sets (`enqueued`, `fn_states`, `truncated`) — the change
  that was worth 3.1x in the reachability BFS — moved nothing. The BFS probed once
  per candidate per LINE; the worklist probes once per enqueue and per pop, orders
  of magnitude fewer, so long-path comparisons never dominated here. Kept anyway
  for consistency, and labelled as a no-op in the code.
- Making the per-line arity resolution allocation-free took the phase from 15.9 s
  to 16.9 s: avoiding the two intermediate `Vec`s meant walking the candidate list
  up to three times instead of once. Reverted.

So the remaining 16.0 s is the per-line call resolution itself — candidate
extraction, call-shape gating, arity matching — not a data-structure or allocation
problem. The only structural lever left is running it on more than one core:
`scan_taint_project` parallelizes across LANGUAGES, so a mono-language tree uses
one. That means decomposing shared mutable state (`enqueued`, `fn_states`,
`truncated`, the findings sink) in the one pass that can silently change findings,
which is a redesign rather than a `par_iter` swap. `finding-parity.py` is the gate
it would need.

Per-file rule packs (23.6 s) are already parallel at cores-1.

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
