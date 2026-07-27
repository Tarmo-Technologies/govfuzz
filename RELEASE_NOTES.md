<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz v0.2.21 release notes

Released 2026-07-27.

GovFuzz v0.2.21 is a reach release. v0.2.20 made `--force` a second phase that
retries only what the first phase could not fuzz, which was worth +10 fuzzed
targets over a 126-project corpus. This release goes after the targets that
phase still could not rescue, working from the residual blockers rather than
from intuition.

## `--force` now works outside C/C++/Ada

The forced sweep's residual blockers showed 116 Go targets and 31 C# targets
ending `unsupported_params` however hard you forced them. Go's undrivable count
was *identical* between the forced and unforced arms — the tell that nothing had
even attempted it. Both lanes now have the C family's best-effort driver, whose
contract is a driver that compiles, with value correctness explicitly not a goal.

- **Go.** An undrivable parameter becomes its type's zero value — every Go type
  has one, so the only thing that can fail is naming the type from the harness
  package. An exported target type gains the package qualifier; a predeclared
  name and a qualifier into a package the harness already imports are kept; an
  unexported, generic, variadic, or inline-literal spelling is refused rather
  than guessed. A method is called on an addressable zero receiver, valid for
  both pointer and value receivers — deliberately not a nil pointer, which would
  panic the moment the method touched a field.
- **C#.** A receiver whose type has no accessible parameterless constructor is
  allocated without running one, via the runtime's own `GetUninitializedObject`,
  resolved by reflection so the shim compiles against any target framework. An
  abstract type or an interface is still refused: there is no instance to
  allocate by any route.

A fabricated value can panic on its own account, so a target built this way is
recorded as such. Its findings are floored to Low with the forced caveat and
counted separately in the summary — the same treatment a stub-only C build
already gets, so a forced nil-map panic never reads as a confirmed defect.

## A function returning a struct by value can be stubbed

Twenty raylib symbols in one clay harness stubbed cleanly and exactly one did
not, because it returns an aggregate by value and the stub generator had no way
to name the type — so it emitted no repair at all and the link stayed broken.
GovFuzz now constructs a zeroed return value wherever the type is complete (the
header-backed path), which is exactly as neutral as the `return 0;` its siblings
get. Where the type is incomplete the honest refusal stays: a C definition with
an incomplete result type is invalid whatever its body.

clay goes from 3 of 6 attempted targets fuzzed to 4.

## A configure-style `#error` guard no longer ends the build

Sweeping what `--force` still cannot build turned up a class where nothing is
missing from the tree at all — the header stops the build itself:

```
/libssh/include/libssh/priv.h:45:4:  error: "no strtoull function found"
/MagickCore/magick-config.h:70:3:    error: "you should set MAGICKCORE_QUANTUM_DEPTH"
```

A real `./configure` would have defined the macro the guard tests. No
header/type/symbol repair could apply, so those targets burned every repair
round and ended report-only — ten of 104 sampled unbuilt harnesses. GovFuzz now
reads the conditional that owns the `#error` and defines the macro that makes
its branch dead, with the value the guard itself requires (a comparison against
`8` gets `8`; a plain feature test gets `1`, not `0`, which satisfies `#ifdef X`
but fails the equally common `#if X`).

Undecidable guards are refused rather than guessed: a comparison, a compound
condition, an error that fires *because* a macro is defined, or the `#else` of
an `#ifndef`. A wrong define is worse than an honest failure.

## Report correctness

`findings.csv` writes the optional `scan_type` and `forced` columns before the
stub-accounting block, but their names were appended after it. Under `--force`
or `--static-dynamic` every stub column therefore carried its left neighbour's
value, and `forced` — the column that delivers the low-confidence caveat — read
out `linked_real`. The header is now composed in the order the rows are written
and pinned by a test that matches cells to names by position. With neither flag
set the header is byte-identical to before, so nothing already parsing the file
moves.

## Two more build recoveries, found by reading the residual blockers

- **A libc function is never defined away.** btop's build died *inside glibc* —
  `/usr/include/unistd.h:1091: error: expected identifier or '('` on glibc's own
  declaration of `syscall`. A vendored header calls `syscall()` from a
  `static inline` and leaves `<unistd.h>` to whichever `.c` includes it first;
  compiled from a TU that does not, the call is undeclared, and the neutral-macro
  repair answered with `#define syscall`. That define is force-included ahead of
  every translation unit, so it erased the declaration too — a worse error than
  the original, in a file no repair can reach, where nothing was ever missing.
  Such names now route to their declaring header, and the fallback refuses
  outright for anything the C runtime owns. btop: 4 of 10 attempted targets
  built+fuzzed → 5, and zero unbuilt harnesses across the sweep.
- **A C++ free function no header declares now gets declared.** The forward-
  declaration gate asked "does the target have any includes at all"; a
  header-less `.cpp` still pulls in whatever headers the file includes, none of
  which need declare the target, so the harness called a name nothing had
  declared. It now searches those headers for a real declarator — and strips
  export / constant-evaluation decoration macros (`JNIEXPORT jstring`,
  `utf8_constexpr14_impl int`) from what it emits, so the fix cannot manufacture
  an `unknown type name` the target never had. Both of those manufactured-error
  cases were caught by re-measuring and by the test suite, not by inspection.

## Honest reporting: `--force` kept a missing dependency to itself

Forcing degrades a residual failed build to a report-only static scan, which is
the right floor. But a report-only outcome carries no diagnostics for the
missing-dependency manifest to mine, and the degradation replaced them with a
bare COUNT of residual errors — so the evidence vanished, on the run that most
needs it. Measured on tmux, whose every target embeds libevent's `struct event`
by value:

```
unforced:  4 external dependencies needed: 4 still blocking   (naming `event`)
forced:    No external dependencies were missing — the tree built against
           its own sources.
```

The second line is simply false. The degradation now carries the unresolved type
names across, and a regression test pins that forcing can never empty the
manifest.

## Three sources of dead targets removed

Each of these consumed slots in the ranked cap that real functions should have
had, and none could ever build.

- **Macro templates.** BSD `<sys/tree.h>`'s `RB_GENERATE_INSERT(name, type,
  field, cmp, attr)` defines a whole function body inside a backslash-continued
  `#define`. It parses as a function returning `attr struct type *` — but
  `attr`, `type` and `name` are macro PARAMETERS, and the symbol does not exist
  until expansion. tmux's compat/tree.h produced seven of them.
- **Macro invocations.** Linux's `TRACE_EVENT(mcu_cmd_info, TP_PROTO(...), ...)`
  parses as a function whose parameter *types* are the macro's arguments.
  Single-word ALL-CAPS names are kept — BLAS/LAPACK really do export `DGEMM`.
- On lede the two rules together removed 139 pseudo-targets from the ranked
  list, and the freed slots went to real functions.

## Two more self-inflicted build errors

- **The Win32 pack redefining the tree's own types.** Win32-style scalar names
  are not exclusive to Windows: lede's MediaTek mt7603 *Linux* driver declares
  `typedef signed char CHAR;` and its own `union _LARGE_INTEGER`. GovFuzz
  force-included its `windows.h` placeholder over them, producing `typedef
  redefinition with different types ('signed char' vs 'char')`. When the tree
  owns the name, the ordinary type repairs run instead.
- **A CamelCase export macro in the generated C harness.** The decoration
  stripper knew the ALL-CAPS convention (`WREN_API`, `STBIDEF`) but not the
  CamelCase one, so ImageMagick's `ModuleExport size_t f()` reached the harness
  as `extern ModuleExport size_t f(...)` — the C twin of the C++ leak above.

## Getting started

`docs/recommended-sweep.md` is the one command to start from — work dir, jobs,
per-target and campaign budgets, target cap, build-command recovery, `--force`,
static, SBOM, SLOC, debug — with what each flag buys and how to size it.
`govfuzz auto --help` prints the same command at the end, and a distribution
ships it as `RECOMMENDED-SWEEP.md`.

## Tooling

`benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the corpus forced and
histograms the actual compiler errors behind every harness that did not fuzz,
deleting each clone and work dir immediately so peak disk stays at one project.
It counts only harnesses GovFuzz gave up on. The first cut did not: the repair
loop reaches the link stage with symbols still undefined *on its way to
resolving them*, so harvesting every harness ranked the loop working as designed
as the largest defect class, at 25 of 104.
The blocker histogram groups those targets; only this says *why*. It produced
the `#error`-guard fix and leaves the remaining classes on record as the next
worklist — see `docs/open-defects-force-and-reach.md`.

## Honest scope

- **Rust's 64 residual targets are untouched, deliberately.** "No byte decoder
  for T" is a type-system fact: Rust has no universal zero value, and
  `T::default()` only compiles if `T: Default`, which cannot be tested at codegen
  time without type resolution. Emitting it speculatively would trade a clean
  skip for a failed build. Target-kind and private-module trait-impl resolution
  are separate known gaps.
- **Go's "no `go.mod`" and "requires go >= X" blockers are environment, not
  parameters.** No force path can touch them, and they are counted inside that
  116 — subtract them before reading it as a target number.
- **The `#error`-guard recovery removes that diagnostic, not every blocker
  behind it.** A/B'd under pinned binaries on the two corpus projects that carry
  the class: on WindTerm both guard errors disappear and report-only targets go
  3 → 6; on ImageMagick all three disappear (`MAGICKCORE_QUANTUM_DEPTH 8`,
  `MAGICKCORE_HDRI_ENABLE 1`) and report-only goes 1 → 4. In both cases more
  targets reach the degradation floor, and in neither does one reach the fuzzer
  inside a 90-second campaign — what remains is a different class (absent crypto
  libraries on WindTerm, a missing generated `magick-baseconfig.h` on
  ImageMagick). Reported as measured, not as a fuzz-count win.

## Validation

- Full workspace suite green with `--no-fail-fast`: 1,477 GovFuzz CLI tests, 564
  harness-generator tests, 77 C-stub-generator tests, and every end-to-end
  regression binary, including new fixtures for the Go force path and the
  `#error`-guard recovery.
- The suite is what caught the sharpest defect in this release: the rule that
  prefers the outermost feature-test wrapper was, on its first cut, defining the
  header's own INCLUDE GUARD — which does not repair the failed guard, it
  preprocesses the whole header away. Two other fixtures had quietly stopped
  being negative controls because GovFuzz now repairs the shape they relied on.
- `cargo clippy --workspace --all-targets`, `cargo fmt --check`, and the SPDX
  header check pass on the release tree.

See `CHANGELOG.md` for the cumulative project history.
